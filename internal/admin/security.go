// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/network"
	P "github.com/cloudwego/hertz/pkg/protocol"
)

type principal struct {
	account model.AdminAccount
	session model.AdminSession
	token   string
}
type identityKey struct{}
type requestIDKey struct{}
type sourceKey struct{}
type attemptBucket struct {
	since time.Time
	count int
}
type attemptLimiter struct {
	mu     sync.Mutex
	global attemptBucket
	peers  map[string]attemptBucket
}

func (l *attemptLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.global.since) >= time.Minute {
		l.global = attemptBucket{since: now}
	}
	if l.global.count >= 30 {
		return false
	}
	if l.peers == nil {
		l.peers = make(map[string]attemptBucket)
	}
	for k, v := range l.peers {
		if now.Sub(v.since) >= time.Minute {
			delete(l.peers, k)
		}
	}
	b := l.peers[key]
	if b.since.IsZero() {
		if len(l.peers) >= 1024 {
			return false
		}
		b.since = now
	}
	if b.count >= 5 {
		return false
	}
	b.count++
	l.peers[key] = b
	l.global.count++
	return true
}
func (a *API) cookieName() string {
	if a.secure {
		return "__Host-lunaris_session"
	}
	return "lunaris_session"
}
func (a *API) setCookie(c *app.RequestContext, token string, expires time.Time) {
	cookie := P.AcquireCookie()
	defer P.ReleaseCookie(cookie)
	cookie.SetKey(a.cookieName())
	cookie.SetValue(token)
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSecure(a.secure)
	cookie.SetSameSite(P.CookieSameSiteStrictMode)
	if token == "" {
		cookie.SetMaxAge(-1)
		cookie.SetExpire(time.Unix(1, 0))
	} else {
		cookie.SetMaxAge(int(time.Until(expires).Seconds()))
		cookie.SetExpire(expires)
	}
	c.Response.Header.SetCookie(cookie)
}
func (a *API) token(c *app.RequestContext) (string, bool) {
	var token string
	count := 0
	c.VisitAllCookie(func(k, v []byte) {
		if string(k) == a.cookieName() {
			count++
			token = string(v)
		}
	})
	return token, count == 1 && len(token) == 43
}
func remoteIP(c *app.RequestContext) netip.Addr {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}
func (a *API) trusted(ip netip.Addr) bool {
	for _, prefix := range a.proxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func (a *API) source(c *app.RequestContext) (string, bool) {
	if a.nativeTLS {
		if _, ok := c.GetConn().(network.ConnTLSer); !ok {
			return "", false
		}
	}
	ip := remoteIP(c)
	host := string(c.Request.Host())
	if len(a.proxies) > 0 {
		if !a.trusted(ip) || string(c.Request.Header.Peek("X-Forwarded-Proto")) != "https" {
			return "", false
		}
		if h := string(c.Request.Header.Peek("X-Forwarded-Host")); h != "" {
			if strings.Contains(h, ",") {
				return "", false
			}
			host = h
		}
		if forwarded := string(c.Request.Header.Peek("X-Forwarded-For")); forwarded != "" {
			addresses := strings.Split(forwarded, ",")
			if len(addresses) > 8 {
				return "", false
			}
			for i := len(addresses) - 1; i >= 0 && a.trusted(ip); i-- {
				next, err := netip.ParseAddr(strings.TrimSpace(addresses[i]))
				if err != nil {
					return "", false
				}
				ip = next.Unmap()
			}
		}
	}
	origin, err := config.CanonicalOrigin(a.scheme + "://" + host)
	return ip.String(), err == nil && origin == a.origin
}
func (a *API) middleware(ctx context.Context, c *app.RequestContext) {
	id := "req_" + auth.Token()
	defer func() {
		if recover() != nil {
			a.logs.Add("error", "management request failed", id)
			a.fail(c, 500, 50000, "Internal management error", nil)
		}
	}()
	c.Header("X-Request-ID", id)
	ctx = context.WithValue(ctx, requestIDKey{}, id)
	source, valid := a.source(c)
	if !valid {
		a.fail(c, 403, 40300, "Invalid management host or proxy", nil)
		return
	}
	ctx = context.WithValue(ctx, sourceKey{}, source)
	if a.secure {
		c.Header("Strict-Transport-Security", "max-age=31536000")
	}
	select {
	case a.requests <- struct{}{}:
		defer func() { <-a.requests }()
	default:
		a.fail(c, 429, 42900, "Management request limit reached", nil)
		return
	}
	method, path := string(c.Method()), string(c.Path())
	write := method != "GET" && method != "HEAD" && method != "OPTIONS"
	if write {
		origin, err := config.CanonicalOrigin(string(c.Request.Header.Peek("Origin")))
		if err != nil || origin != a.origin {
			a.fail(c, 403, 40300, "Invalid request origin", nil)
			return
		}
		if site := string(c.Request.Header.Peek("Sec-Fetch-Site")); site != "" && site != "same-origin" && site != "none" {
			a.fail(c, 403, 40300, "Cross-site write rejected", nil)
			return
		}
	}
	public := method == "GET" && path == "/api/v1/setup/status" || method == "POST" && (path == "/api/v1/setup" || path == "/api/v1/auth/login")
	if !public {
		token, ok := a.token(c)
		if !ok {
			a.fail(c, 401, 40100, "Authentication required", nil)
			return
		}
		account, session, err := a.auth.Session(ctx, token)
		if err != nil {
			a.error(c, err, false)
			return
		}
		if write && !auth.ValidCSRF(string(c.Request.Header.Peek("X-CSRF-Token")), session.CSRFToken) {
			a.fail(c, 403, 40300, "Invalid CSRF token", nil)
			return
		}
		ctx = context.WithValue(ctx, identityKey{}, principal{account: account, session: session, token: token})
	}
	work, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c.Next(work)
}
func (a *API) authAttempt(ctx context.Context, c *app.RequestContext, kind string) bool {
	source, _ := ctx.Value(sourceKey{}).(string)
	if !a.attempts.allow(kind + ":" + source) {
		c.Header("Retry-After", "60")
		a.fail(c, 429, 42900, "Authentication rate limit exceeded", nil)
		return false
	}
	return true
}
func principalFrom(ctx context.Context) principal {
	p, _ := ctx.Value(identityKey{}).(principal)
	return p
}
func originScheme(origin string) string { u, _ := url.Parse(origin); return u.Scheme }

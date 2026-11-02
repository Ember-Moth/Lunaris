// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"crypto/tls"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/adaptor"
	"github.com/cloudwego/hertz/pkg/network/standard"
)

type Options struct {
	Listener net.Listener
	Assets   fs.FS
	Ready    func(context.Context) error
	API      *API
	TLS      *tls.Config
}

func New(options Options) *server.Hertz {
	h := server.New(
		server.WithListener(options.Listener),
		server.WithTransport(standard.NewTransporter),
		server.WithHandleMethodNotAllowed(true),
		server.WithMaxRequestBodySize(8192),
		server.WithMaxHeaderBytes(16<<10),
		server.WithStreamBody(true),
		server.WithDisablePreParseMultipartForm(true),
		server.WithTLS(options.TLS),
		server.WithSenseClientDisconnection(true),
		server.WithMaxKeepBodySize(64<<10),
		server.WithReadTimeout(5*time.Second),
		server.WithWriteTimeout(10*time.Second),
		server.WithIdleTimeout(2*time.Second),
		server.WithExitWaitTime(5*time.Second),
	)
	h.Use(func(ctx context.Context, c *app.RequestContext) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Content-Security-Policy", "default-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")
		c.Header("Cache-Control", "no-store")
		defer func() {
			// Streaming avoids allocating attacker-declared bodies before authentication.
			// Do not let HTTP/1 drain an unbounded remainder after an early rejection.
			if c.Request.IsBodyStream() {
				c.SetConnectionClose()
				_ = c.GetConn().SetReadTimeout(time.Nanosecond)
			}
		}()
		if options.API != nil && strings.HasPrefix(string(c.Path()), "/api/") {
			options.API.middleware(ctx, c)
		} else {
			c.Next(ctx)
		}
	})
	health := func(ctx context.Context, c *app.RequestContext) {
		checkCtx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if options.Ready != nil && options.Ready(checkCtx) != nil {
			reply(c, http.StatusServiceUnavailable, CodeUnavailable, "Service unavailable", nil)
			return
		}
		reply(c, http.StatusOK, CodeOK, "ok", map[string]string{"status": "ok"})
	}
	if options.API != nil {
		options.API.Register(h)
	}
	h.GET("/healthz", health)
	h.HEAD("/healthz", health)
	if options.Assets != nil {
		files := adaptor.HertzHandler(http.FileServer(http.FS(options.Assets)))
		index := adaptor.HertzHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			file, err := options.Assets.Open("index.html")
			if err != nil {
				http.Error(w, "frontend unavailable", http.StatusServiceUnavailable)
				return
			}
			file.Close()
			// FileServer serves /index.html through / without redirecting SPA routes.
			cloned := r.Clone(r.Context())
			cloned.URL.Path = "/"
			http.FileServer(http.FS(options.Assets)).ServeHTTP(w, cloned)
		}))
		for _, path := range []string{"/", "/about"} {
			h.GET(path, index)
			h.HEAD(path, index)
		}
		h.GET("/assets/*filepath", files)
		h.HEAD("/assets/*filepath", files)
		h.GET("/favicon.svg", files)
		h.HEAD("/favicon.svg", files)
	}
	h.NoRoute(func(_ context.Context, c *app.RequestContext) {
		reply(c, http.StatusNotFound, CodeNotFound, "Resource not found", nil)
	})
	h.NoMethod(func(_ context.Context, c *app.RequestContext) {
		reply(c, http.StatusMethodNotAllowed, CodeMethodNotAllowed, "Method not allowed", nil)
	})
	return h
}

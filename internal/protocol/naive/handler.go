// SPDX-License-Identifier: GPL-3.0-only
package naive

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	sHTTP "github.com/sagernet/sing/protocol/http"
)

type handler struct {
	auth    *auth.Authenticator
	next    transport.RelayHandler
	timeout time.Duration
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reject := func(code int) {
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		w.WriteHeader(code)
	}
	if r.Method != "CONNECT" || r.Header.Get("Padding") == "" {
		reject(http.StatusBadRequest)
		return
	}
	username, password, ok := sHTTP.ParseBasicAuth(r.Header.Get("Proxy-Authorization"))
	if !ok || !h.auth.Verify(username, password) {
		reject(http.StatusProxyAuthRequired)
		return
	}
	authority := r.Host
	if r.URL.Host != "" {
		authority = r.URL.Host
	}
	// The compatibility authority header is used by some HTTP/2 Naive clients.
	if value := r.Header.Get("-connect-authority"); value != "" {
		authority = value
	}
	host, port, err := net.SplitHostPort(authority)
	dst := M.ParseSocksaddr(authority).Unwrap()
	if err != nil || host == "" || port == "" || !dst.IsValid() || (dst.Port == 0 && dst.Fqdn != uot.MagicAddress && dst.Fqdn != uot.LegacyMagicAddress) || strings.ContainsAny(host, "/\\\r\n\x00") {
		reject(http.StatusBadRequest)
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Now().Add(h.timeout))
	w.Header().Set("Padding", paddingHeader())
	w.WriteHeader(http.StatusOK)
	if err = controller.Flush(); err != nil {
		return
	}
	var base net.Conn
	if r.ProtoMajor == 1 {
		conn, rw, err := controller.Hijack()
		if err != nil {
			return
		}
		base = &cachedConn{Conn: conn, reader: rw.Reader}
	} else {
		base = newHTTPStream(w, r)
	}
	c := &paddingConn{Conn: base}
	defer c.Close()
	_ = c.SetDeadline(time.Time{})
	ctx := auth.ContextWithUser(r.Context(), username)
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	done := make(chan struct{})
	close := N.OnceClose(func(error) { c.Close(); close(done) })
	h.next.NewConnectionEx(ctx, c, M.ParseSocksaddr(r.RemoteAddr), dst, close)
	<-done
}

type cachedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *cachedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// A response writer cannot be used after ServeHTTP returns. Close interrupts
// flow-control blocked I/O, then joins it before the handler is released.
type httpStream struct {
	body            io.ReadCloser
	controller      *http.ResponseController
	writer          http.ResponseWriter
	local, remote   net.Addr
	readMu, writeMu sync.Mutex
	once            sync.Once
	closed          atomic.Bool
}

func newHTTPStream(w http.ResponseWriter, r *http.Request) *httpStream {
	return &httpStream{body: r.Body, controller: http.NewResponseController(w), writer: w, local: M.Socksaddr{}, remote: M.ParseSocksaddr(r.RemoteAddr)}
}
func (c *httpStream) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.body.Read(p)
}
func (c *httpStream) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.writer.Write(p)
	if err == nil {
		err = c.controller.Flush()
	}
	return n, err
}
func (c *httpStream) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		_ = c.controller.SetReadDeadline(time.Now())
		_ = c.controller.SetWriteDeadline(time.Now())
		_ = c.body.Close()
		c.readMu.Lock()
		c.readMu.Unlock()
		c.writeMu.Lock()
		c.writeMu.Unlock()
	})
	return nil
}
func (c *httpStream) LocalAddr() net.Addr                { return c.local }
func (c *httpStream) RemoteAddr() net.Addr               { return c.remote }
func (c *httpStream) SetReadDeadline(t time.Time) error  { return c.controller.SetReadDeadline(t) }
func (c *httpStream) SetWriteDeadline(t time.Time) error { return c.controller.SetWriteDeadline(t) }
func (c *httpStream) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

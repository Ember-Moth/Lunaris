// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/coder/websocket"
)

type TCPFactory struct{}
type WebSocketFactory struct{}
type HTTPUpgradeFactory struct{}
type NativeFactory struct{}

func (TCPFactory) Capabilities() Capabilities { return Capabilities{Type: "tcp", TCP: true, TLS: true} }
func (WebSocketFactory) Capabilities() Capabilities {
	return Capabilities{Type: "ws", TCP: true, TLS: true}
}
func (HTTPUpgradeFactory) Capabilities() Capabilities {
	return Capabilities{Type: "httpupgrade", TCP: true, TLS: true}
}
func (NativeFactory) Capabilities() Capabilities {
	return Capabilities{Type: "native", TCP: true, UDP: true}
}
func field(path, msg string) []model.FieldError {
	return []model.FieldError{{Path: path, Code: "invalid", Message: msg}}
}
func validatePlain(s model.ListenerSpec) []model.FieldError {
	if s.Transport.XHTTP != nil {
		return field("transport.xhttp", "XHTTP settings require the xhttp transport")
	}
	if s.Transport.Reality != nil {
		return field("transport.reality", "REALITY settings require the reality transport")
	}
	if s.Transport.Path != "" || s.Transport.Host != "" {
		return field("transport", "this transport does not accept path or host")
	}
	return nil
}
func (TCPFactory) Validate(s model.ListenerSpec) []model.FieldError { return validatePlain(s) }
func (NativeFactory) Validate(s model.ListenerSpec) []model.FieldError {
	if s.CertificateRef != "" {
		return field("certificate_ref", "native TCP/UDP does not support TLS")
	}
	return validatePlain(s)
}
func validateHTTP(s model.ListenerSpec) []model.FieldError {
	if s.Transport.XHTTP != nil {
		return field("transport.xhttp", "XHTTP settings require the xhttp transport")
	}
	if s.Transport.Reality != nil {
		return field("transport.reality", "REALITY settings require the reality transport")
	}
	t := s.Transport
	u, err := url.ParseRequestURI(t.Path)
	if err != nil || !strings.HasPrefix(t.Path, "/") || strings.HasPrefix(t.Path, "//") || u.RawQuery != "" || u.Fragment != "" || u.EscapedPath() != t.Path || len(t.Path) > 1024 {
		return field("transport.path", "an escaped absolute path without query or fragment is required")
	}
	if strings.ContainsAny(t.Host, "\r\n\t /\\") {
		return field("transport.host", "invalid HTTP host")
	}
	return nil
}
func (WebSocketFactory) Validate(s model.ListenerSpec) []model.FieldError   { return validateHTTP(s) }
func (HTTPUpgradeFactory) Validate(s model.ListenerSpec) []model.FieldError { return validateHTTP(s) }
func (TCPFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	return newSocketServer(r, b, nil)
}
func (WebSocketFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	return newSocketServer(r, b, websocketUpgrade)
}
func (HTTPUpgradeFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	return newSocketServer(r, b, httpUpgrade)
}
func (NativeFactory) Build(r ResolvedSpec, b Binding) (Instance, error) {
	if len(r.Certificate) > 0 || len(r.PrivateKey) > 0 {
		return nil, errors.New("native TCP/UDP does not support TLS")
	}
	if len(r.Network) == 0 {
		r.Network = []string{"tcp", "udp"}
	}
	return newSocketServer(r, b, nil)
}

// Each HTTP carrier owns its upgrade, framing and cleanup implementation.
func websocketUpgrade(s *socketServer, w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	c := websocket.NetConn(s.ctx, ws, websocket.MessageBinary)
	ws.SetReadLimit(1 << 20)
	s.serve(r.Context(), c)
}
func httpUpgrade(s *socketServer, w http.ResponseWriter, r *http.Request) {
	if !headerToken(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w.Header().Set("Connection", "close")
		http.Error(w, "invalid upgrade", http.StatusBadRequest)
		return
	}
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	carrier := r.Context().Value(carrierKey{}).(*trackedConn)
	// Hijack clears deadlines; even the response must stay inside the budget.
	_ = carrier.SetDeadline(carrier.deadline)
	if _, err = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"); err == nil {
		err = rw.Flush()
	}
	if err != nil {
		carrier.Close()
		return
	}
	s.serve(r.Context(), &readerConn{Conn: c, reader: rw.Reader})
}
func serverTLSConfig(r ResolvedSpec, alpn []string) (*tls.Config, error) {
	if len(r.Certificate) == 0 && len(r.PrivateKey) == 0 {
		return nil, nil
	}
	cert, err := tls.X509KeyPair(r.Certificate, r.PrivateKey)
	if err != nil {
		return nil, errors.New("invalid TLS key pair")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: alpn}, nil
}

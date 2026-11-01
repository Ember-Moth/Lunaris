// SPDX-License-Identifier: GPL-3.0-only
package snell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	upstream "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Factory struct{}
type Options struct {
	Version int    `json:"version,omitempty"`
	Obfs    string `json:"obfs,omitempty"`
	Mode    string `json:"mode,omitempty"`
}

func (Factory) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "snell", TCP: true, TCPRelay: true, UDPRelay: true, UDPOverTCP: true, Multiplex: true, Transports: []string{"tcp"}}
}
func parse(s model.ListenerSpec) (Options, error) {
	var o Options
	d := json.NewDecoder(bytes.NewReader(s.Options))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return o, errors.New("invalid Snell options")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return o, errors.New("trailing Snell options")
	}
	if o.Version == 0 {
		o.Version = 5
	}
	if o.Version != 5 && o.Version != 6 {
		return o, errors.New("Snell server version must be 5 or 6 (v5 accepts v4 clients)")
	}
	if o.Version == 5 {
		if o.Mode != "" {
			return o, errors.New("mode is only valid for Snell v6")
		}
		if _, err := upstream.ParseObfsMode(o.Obfs); err != nil {
			return o, errors.New("invalid Snell v5 obfs")
		}
	} else {
		if o.Obfs != "" && o.Obfs != "none" {
			return o, errors.New("Snell v6 does not use v5 obfs")
		}
		if _, err := snellv6.ParseMode(o.Mode); err != nil {
			return o, errors.New("invalid Snell v6 mode")
		}
	}
	if len(s.CredentialRefs) != 1 {
		return o, errors.New("Snell requires exactly one PSK credential per listener")
	}
	return o, nil
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError {
	if _, err := parse(s); err != nil {
		return []model.FieldError{{Path: "options", Code: "invalid", Message: err.Error()}}
	}
	return nil
}
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	o, err := parse(r.Spec)
	if err != nil {
		return err
	}
	length := len(r.Credentials[r.Spec.CredentialRefs[0]])
	minimum := 1
	if o.Version == 6 {
		minimum = 12
	}
	if length < minimum || length > 255 {
		return errors.New("Snell PSK length is invalid: v5 requires 1..255 bytes, v6 requires 12..255 bytes")
	}
	return nil
}
func (f Factory) Build(r protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	if d.Handler == nil {
		return transport.Binding{}, errors.New("Snell handler required")
	}
	o, err := parse(r.Spec)
	if err != nil {
		return transport.Binding{}, err
	}
	if err = f.ValidateAssets(r); err != nil {
		return transport.Binding{}, err
	}
	handler := streamBoundary{next: d.Handler}
	psk := bytes.Clone(r.Credentials[r.Spec.CredentialRefs[0]])
	var service upstream.Service
	if o.Version == 6 {
		mode, _ := snellv6.ParseMode(o.Mode)
		service, err = snellv6.NewService(snellv6.ServerOptions{PSK: psk, Mode: mode, Handler: handler})
	} else {
		obfs, _ := upstream.ParseObfsMode(o.Obfs)
		service, err = snellv5.NewService(snellv5.ServiceOptions{PSK: psk, ObfsMode: obfs, Handler: handler})
	}
	if err != nil {
		return transport.Binding{}, err
	}
	return transport.Binding{Stream: &transport.StreamHandler{Serve: service.NewConnection}}, nil
}

// sing-snell's buffer/vector writer expects caller-owned headroom, including
// on small protocol-generated headers. Standard net.Conn writes allocate their
// own framing, so expose that boundary to UoT/mux and the shared relay.
type streamBoundary struct{ next protocol.RelayHandler }

func (h streamBoundary) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, close N.CloseHandlerFunc) {
	h.next.NewConnectionEx(ctx, &streamConn{Conn: c}, src, dst, close)
}
func (h streamBoundary) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, close N.CloseHandlerFunc) {
	h.next.NewPacketConnectionEx(ctx, c, src, dst, close)
}

type streamConn struct{ net.Conn }

func (c *streamConn) CloseRead() error  { return N.CloseRead(c.Conn) }
func (c *streamConn) CloseWrite() error { return N.CloseWrite(c.Conn) }
func (c *streamConn) ReaderMTU() int    { return N.CalculateMTU(c.Conn, nil) }
func (c *streamConn) WriterMTU() int    { return N.CalculateMTU(nil, c.Conn) }

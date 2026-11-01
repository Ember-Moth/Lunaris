// SPDX-License-Identifier: GPL-3.0-only
package inbound_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/inbound"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type probeProtocol struct {
	target      M.Socksaddr
	built       int
	carriers    []string
	tls, sawTLS bool
}

func (p *probeProtocol) Capabilities() protocol.Capabilities {
	return protocol.Capabilities{Type: "probe", TCP: true, UDP: true, TCPRelay: true, TLS: p.tls, Transports: p.carriers}
}
func (*probeProtocol) Validate(model.ListenerSpec) []model.FieldError { return nil }
func (p *probeProtocol) Build(resolved protocol.ResolvedListenerSpec, d protocol.Dependencies) (transport.Binding, error) {
	p.built++
	p.sawTLS = p.sawTLS || len(resolved.Certificate) > 0 || len(resolved.PrivateKey) > 0
	return transport.Binding{Stream: &transport.StreamHandler{Serve: func(ctx context.Context, c net.Conn, src M.Socksaddr, close N.CloseHandlerFunc) error {
		d.Handler.NewConnectionEx(ctx, c, src, p.target, close)
		return nil
	}}}, nil
}

type probeTransport struct {
	built       int
	rejected    bool
	tls, sawTLS bool
}

func (p *probeTransport) Capabilities() transport.Capabilities {
	return transport.Capabilities{Type: "custom-carrier", TCP: true, TLS: p.tls}
}
func (p *probeTransport) Validate(model.ListenerSpec) []model.FieldError {
	if p.rejected {
		return []model.FieldError{{Path: "transport", Message: "test rejection"}}
	}
	return nil
}
func (p *probeTransport) Build(r transport.ResolvedSpec, b transport.Binding) (transport.Instance, error) {
	p.built++
	p.sawTLS = len(r.Certificate) > 0 && len(r.PrivateKey) > 0
	return (transport.TCPFactory{}).Build(r, b)
}
func compose(t *testing.T, p *probeProtocol, tr *probeTransport) *inbound.Registry {
	t.Helper()
	ps, err := protocol.NewRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := transport.NewRegistry(tr)
	if err != nil {
		t.Fatal(err)
	}
	r, err := inbound.NewRegistry(ps, ts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func probeConfig() *model.RuntimeConfig {
	return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "probe", Enabled: true, Protocol: "probe", Address: "127.0.0.1", Port: 12345, Options: []byte("{}")}}}}
}
func TestIndependentFactoriesCanExtendBothRegistries(t *testing.T) {
	p := &probeProtocol{target: M.SocksaddrFromNet(testutil.TCPEcho(t)), carriers: []string{"custom-carrier"}}
	tr := &probeTransport{}
	r := compose(t, p, tr)
	// A protocol supporting both socket networks defaults to the selected
	// carrier's intersection, rather than enabling unsupported UDP sockets.
	normalized, err := r.Normalize(probeConfig())
	if err != nil {
		t.Fatal(err)
	}
	spec := normalized.Config.Listeners[0]
	if len(spec.Network) != 1 || spec.Network[0] != "tcp" || spec.Transport.Type != "custom-carrier" {
		t.Fatalf("incorrect transport defaults: %+v", spec)
	}
	caps := r.Protocols().Capabilities()
	caps[0].Transports[0] = "mutated"
	if r.Protocols().Capabilities()[0].Transports[0] != "custom-carrier" {
		t.Fatal("capability slice aliases registry factory")
	}
	ctx := testutil.Context(t)
	flow := relay.New(ctx, &egress.Direct{}, normalized.Config.Limits)
	defer flow.Close(ctx)
	spec.Port = 0
	instance, err := r.Build(protocol.ResolvedListenerSpec{Spec: spec, Limits: normalized.Config.Limits}, protocol.Dependencies{Handler: flow})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Stop(ctx)
	if p.built != 1 || tr.built != 1 {
		t.Fatal("both selected factories must build exactly once")
	}
	if err = instance.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr := instance.(interface{ Addr() net.Addr }).Addr()
	c, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("independent registries")
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("factory composition changed payload")
	}
}
func TestCompositionRejectsBeforeConstructing(t *testing.T) {
	for name, edit := range map[string]func(*model.RuntimeConfig, *probeTransport){
		"unregistered":         func(c *model.RuntimeConfig, _ *probeTransport) { c.Config.Listeners[0].Transport.Type = "missing" },
		"wrong network":        func(c *model.RuntimeConfig, _ *probeTransport) { c.Config.Listeners[0].Network = []string{"udp"} },
		"transport validation": func(_ *model.RuntimeConfig, tr *probeTransport) { tr.rejected = true },
		"TLS policy":           func(c *model.RuntimeConfig, _ *probeTransport) { c.Config.Listeners[0].CertificateRef = "unexpected" },
	} {
		t.Run(name, func(t *testing.T) {
			p := &probeProtocol{carriers: []string{"custom-carrier"}}
			tr := &probeTransport{}
			r := compose(t, p, tr)
			c := probeConfig()
			edit(c, tr)
			if _, err := r.Normalize(c); err == nil {
				t.Fatal("invalid combination normalized")
			}
			ctx := testutil.Context(t)
			h := relay.New(ctx, &egress.Direct{}, c.Config.Limits)
			defer h.Close(ctx)
			if _, err := r.Build(protocol.ResolvedListenerSpec{Spec: c.Config.Listeners[0], Limits: c.Config.Limits}, protocol.Dependencies{Handler: h}); err == nil {
				t.Fatal("invalid combination built")
			}
			if p.built != 0 || tr.built != 0 {
				t.Fatal("rejected combination reached constructor")
			}
		})
	}
}
func TestRegistryRegistrationFailures(t *testing.T) {
	var nilProtocol *probeProtocol
	var nilTransport *probeTransport
	for _, factories := range [][]protocol.Factory{{nil}, {nilProtocol}, {&probeProtocol{}, &probeProtocol{}}} {
		if _, err := protocol.NewRegistry(factories...); err == nil {
			t.Fatal("invalid protocol registration accepted")
		}
	}
	for _, factories := range [][]transport.Factory{{nil}, {nilTransport}, {&probeTransport{}, &probeTransport{}}} {
		if _, err := transport.NewRegistry(factories...); err == nil {
			t.Fatal("invalid transport registration accepted")
		}
	}
	ps, _ := protocol.NewRegistry(&probeProtocol{carriers: []string{"missing"}})
	ts, _ := transport.NewRegistry(&probeTransport{})
	if _, err := inbound.NewRegistry(ps, ts); err == nil {
		t.Fatal("missing declared transport accepted")
	}
	if _, err := inbound.NewRegistry(nil, ts); err == nil {
		t.Fatal("nil registry accepted")
	}
	if _, err := inbound.NewRegistry(ps, nil); err == nil {
		t.Fatal("nil registry accepted")
	}
}

func (p *probeProtocol) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	p.sawTLS = p.sawTLS || len(r.Certificate) > 0 || len(r.PrivateKey) > 0
	return nil
}
func TestCertificateMaterialOnlyReachesTransport(t *testing.T) {
	cert, _ := testutil.Certificate(t)
	p := &probeProtocol{carriers: []string{"custom-carrier"}, tls: true}
	tr := &probeTransport{tls: true}
	r := compose(t, p, tr)
	c := probeConfig()
	c.Config.Listeners[0].CertificateRef = "cert"
	c.Certificates = map[string]model.Certificate{"cert": cert}
	normalized, err := r.Normalize(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testutil.Context(t)
	h := relay.New(ctx, &egress.Direct{}, c.Config.Limits)
	defer h.Close(ctx)
	instance, err := r.Build(protocol.ResolvedListenerSpec{Spec: normalized.Config.Listeners[0], Limits: c.Config.Limits, Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}, protocol.Dependencies{Handler: h})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Stop(ctx)
	if p.sawTLS || !tr.sawTLS {
		t.Fatal("TLS material crossed the wrong factory boundary")
	}
}

// SPDX-License-Identifier: GPL-3.0-only
package policy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/outbound"
	"github.com/Ember-Moth/Lunaris/internal/route"
	M "github.com/sagernet/sing/common/metadata"
)

func outboundSnapshot() *model.RuntimeConfig {
	return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Outbounds: []model.OutboundSpec{{ID: "upstream", Protocol: "socks5", Address: "127.0.0.1", Port: 1, CredentialRef: "password", Options: []byte(`{"username":"alice"}`)}}, Route: &model.RouteConfig{Final: "upstream"}}, Credentials: map[string][]byte{"password": []byte("old-password")}}
}

func TestProxyServerUsesGenerationDNSAndIngressSource(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var source netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Is4() && !prefix.Addr().IsLoopback() && !prefix.Addr().IsLinkLocalUnicast() {
			source = prefix.Addr()
			break
		}
	}
	if !source.IsValid() {
		t.Skip("no assigned non-loopback IPv4 address")
	}
	proxy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	observed := make(chan string, 1)
	go func() {
		conn, err := proxy.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		if request.Host != "remote-only.invalid:443" {
			return
		}
		observed <- M.SocksaddrFromNet(conn.RemoteAddr()).AddrString()
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}()
	dnsAddress, queries := dnsPeer(t)
	snapshot := outboundSnapshot()
	snapshot.Config.Outbounds[0].Protocol = "http"
	snapshot.Config.Outbounds[0].Address = "proxy.test"
	snapshot.Config.Outbounds[0].Port = M.SocksaddrFromNet(proxy.Addr()).Port
	snapshot.Config.DNS = &model.DNSConfig{Strategy: "only_ipv4", Servers: []model.DNSServer{{Proto: "udp", Address: dnsAddress}}}
	lease := leaseFor(t, snapshot)
	ctx, cancel := context.WithTimeout(ingress.WithLocalIP(context.Background(), source), time.Second)
	defer cancel()
	connection, err := lease.DialContext(ctx, "tcp", M.ParseSocksaddr("remote-only.invalid:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case got := <-observed:
		if got != source.String() {
			t.Fatal("proxy socket lost ingress source", got)
		}
	case <-ctx.Done():
		t.Fatal("proxy received no request")
	}
	select {
	case <-queries:
	default:
		t.Fatal("proxy endpoint skipped configured DNS")
	}
}
func TestOutboundGenerationRotationIncludesCredentialsAndTimeouts(t *testing.T) {
	m := NewManager(context.Background())
	first := outboundSnapshot()
	if err := Normalize(first); err != nil {
		t.Fatal(err)
	}
	one, err := m.Acquire(first)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close(context.Background())
	label := outboundSnapshot()
	label.Config.Outbounds[0].Name = "renamed"
	if err := Normalize(label); err != nil {
		t.Fatal(err)
	}
	two, err := m.Acquire(label)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close(context.Background())
	if one.generation != two.generation {
		t.Fatal("label change replaced clients")
	}
	rotated := outboundSnapshot()
	rotated.Credentials["password"] = []byte("new-password")
	if err := Normalize(rotated); err != nil {
		t.Fatal(err)
	}
	three, err := m.Acquire(rotated)
	if err != nil {
		t.Fatal(err)
	}
	defer three.Close(context.Background())
	if one.generation == three.generation {
		t.Fatal("credential rotation reused old client")
	}
	rotated.Config.Limits.HandshakeTimeout += time.Second
	four, err := m.Acquire(rotated)
	if err != nil {
		t.Fatal(err)
	}
	defer four.Close(context.Background())
	if three.generation == four.generation {
		t.Fatal("new handshake timeout reused old client")
	}
	if err := one.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := one.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:80")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("released lease remained usable", err)
	}
	if two.generation.ctx.Err() != nil {
		t.Fatal("released lease closed shared generation")
	}
}

type observingClient struct{ destination M.Socksaddr }

func (c *observingClient) DialContext(_ context.Context, _ string, dst M.Socksaddr) (net.Conn, error) {
	c.destination = dst
	return nil, errors.New("observed dial")
}
func (c *observingClient) ListenPacket(_ context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	c.destination = dst
	return nil, outbound.ErrUnsupportedNetwork
}
func (c *observingClient) Close(context.Context) error { return nil }

func TestProxyPreservesRemoteDomainUnlessIPRulesResolvedIt(t *testing.T) {
	server, _ := dnsPeer(t)
	for _, ipRules := range []bool{false, true} {
		snapshot := outboundSnapshot()
		snapshot.Config.DNS = &model.DNSConfig{Servers: []model.DNSServer{{Proto: "udp", Address: server}}, Strategy: "only_ipv4"}
		if ipRules {
			snapshot.Config.Route.Rules = []model.RouteRule{{Action: "block", Match: []string{"ip:198.18.0.99"}}}
		}
		lease := leaseFor(t, snapshot)
		old := lease.generation.outbounds[route.Target("upstream")]
		old.Close(context.Background())
		observed := &observingClient{}
		lease.generation.outbounds[route.Target("upstream")] = observed
		_, _ = lease.DialContext(context.Background(), "tcp", M.ParseSocksaddr("remote-only.invalid:443"))
		if ipRules {
			if observed.destination.AddrString() != "127.0.0.1" {
				t.Fatal("remote DNS could bypass the IP rule", observed.destination)
			}
		} else if observed.destination.Fqdn != "remote-only.invalid" {
			t.Fatal("unnecessary local resolution", observed.destination)
		}
		packet, err := lease.ListenPacket(context.Background(), M.ParseSocksaddr("remote-only.invalid:443"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = packet.WriteTo([]byte("test"), M.ParseSocksaddr("remote-only.invalid:443"))
		packet.Close()
		if !errors.Is(err, outbound.ErrUnsupportedNetwork) {
			t.Fatal("missing fake UDP error", err)
		}
		if ipRules {
			if observed.destination.AddrString() != "127.0.0.1" {
				t.Fatal("UDP remote DNS bypassed resolved policy", observed.destination)
			}
		} else if observed.destination.Fqdn != "remote-only.invalid" {
			t.Fatal("UDP domain was resolved locally", observed.destination)
		}
	}
}

func TestOutboundReferencesAreStrict(t *testing.T) {
	for _, change := range []func(*model.RuntimeConfig){
		func(s *model.RuntimeConfig) { s.Config.Route.Final = "missing" },
		func(s *model.RuntimeConfig) {
			s.Config.Route.Rules = []model.RouteRule{{Action: "route", Outbound: "missing", Match: []string{"suffix:example"}}}
		},
		func(s *model.RuntimeConfig) {
			s.Config.Route.Rules = []model.RouteRule{{Action: "direct", Outbound: "upstream", Match: []string{"suffix:example"}}}
		},
		func(s *model.RuntimeConfig) { s.Config.Outbounds = append(s.Config.Outbounds, s.Config.Outbounds[0]) },
		func(s *model.RuntimeConfig) { delete(s.Credentials, "password") },
	} {
		snapshot := outboundSnapshot()
		change(snapshot)
		if err := Normalize(snapshot); err == nil {
			t.Fatal("invalid outbound reference accepted")
		}
	}
}

func TestSelectedProxyFailureNeverFallsBackToDirect(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	lease := leaseFor(t, outboundSnapshot())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := lease.DialContext(ctx, "tcp", M.SocksaddrFromNet(listener.Addr())); err == nil {
		c.Close()
		t.Fatal("failed proxy fell back to destination")
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	if c, err := listener.Accept(); err == nil {
		c.Close()
		t.Fatal("destination received bypass traffic")
	}
}

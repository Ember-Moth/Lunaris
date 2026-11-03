// SPDX-License-Identifier: GPL-3.0-only
package policy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsPeer(t *testing.T) (string, chan struct{}) {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	queries := make(chan struct{}, 32)
	go func() {
		defer close(done)
		var b [4096]byte
		for {
			n, peer, err := socket.ReadFrom(b[:])
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if request.Unpack(b[:n]) != nil {
				continue
			}
			select {
			case queries <- struct{}{}:
			default:
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true}, Questions: request.Questions}
			for _, q := range request.Questions {
				if q.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			raw, err := response.Pack()
			if err == nil {
				socket.WriteTo(raw, peer)
			}
		}
	}()
	t.Cleanup(func() { socket.Close(); <-done })
	return socket.LocalAddr().String(), queries
}
func snapshotWithDNS(server string) *model.RuntimeConfig {
	return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), DNS: &model.DNSConfig{Servers: []model.DNSServer{{Proto: "udp", Address: server}}, Strategy: "only_ipv4"}}}
}
func leaseFor(t *testing.T, snapshot *model.RuntimeConfig) *Lease {
	t.Helper()
	if err := Normalize(snapshot); err != nil {
		t.Fatal(err)
	}
	lease, err := NewManager(context.Background()).Acquire(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := lease.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return lease
}
func TestConfiguredDNSAndRoutePrecedence(t *testing.T) {
	server, queries := dnsPeer(t)
	snapshot := snapshotWithDNS(server)
	snapshot.Config.Route = &model.RouteConfig{Rules: []model.RouteRule{{Action: "direct", Match: []string{"full:allowed.test"}}, {Action: "block", Match: []string{"geoip:private"}}}}
	lease := leaseFor(t, snapshot)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := M.SocksaddrFromNet(listener.Addr()).Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := lease.DialContext(ctx, "tcp", M.Socksaddr{Fqdn: "allowed.test", Port: port})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	accepted.Close()
	select {
	case <-queries:
	default:
		t.Fatal("configured DNS was not used")
	}
	if c, err := lease.DialContext(ctx, "tcp", M.Socksaddr{Fqdn: "blocked.test", Port: port}); !errors.Is(err, ErrBlocked) {
		if c != nil {
			c.Close()
		}
		t.Fatal("resolved IP rule did not block", err)
	}
}
func TestUDPChecksEveryDestinationAndHijacksOnlyDNS(t *testing.T) {
	server, _ := dnsPeer(t)
	snapshot := snapshotWithDNS(server)
	snapshot.Config.DNS.HijackUDP53 = true
	snapshot.Config.Route = &model.RouteConfig{Block: []string{"ip:127.0.0.2", "full:blocked.test"}}
	lease := leaseFor(t, snapshot)
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dnsDestination := M.ParseSocksaddr("198.18.0.10:53")
	socket, err := lease.ListenPacket(ctx, dnsDestination)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	query, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 123, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("query.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if _, err := socket.WriteTo(query, dnsDestination); err != nil {
		t.Fatal(err)
	}
	socket.SetReadDeadline(time.Now().Add(time.Second))
	var b [4096]byte
	n, source, err := socket.ReadFrom(b[:])
	if err != nil {
		t.Fatal(err)
	}
	var response dnsmessage.Message
	if response.Unpack(b[:n]) != nil || response.ID != 123 || source.String() != dnsDestination.String() {
		t.Fatal("DNS interception changed the client identity", response, source)
	}
	if _, err := socket.WriteTo([]byte("ordinary UDP"), echo.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	echo.SetReadDeadline(time.Now().Add(time.Second))
	n, source, err = echo.ReadFrom(b[:])
	if err != nil {
		t.Fatal(err)
	}
	echo.WriteTo(b[:n], source)
	if _, _, err := socket.ReadFrom(b[:]); err != nil {
		t.Fatal("non-DNS packet was intercepted", err)
	}
	blocked := M.ParseSocksaddr("127.0.0.2:9999")
	if _, err := socket.WriteTo([]byte("blocked"), blocked); !errors.Is(err, ErrBlocked) {
		t.Fatal("later UDP destination bypassed routing", err)
	}
	if _, err := socket.WriteTo([]byte("blocked"), M.ParseSocksaddr("blocked.test:9999")); !errors.Is(err, ErrBlocked) {
		t.Fatal("UDP domain was resolved before routing", err)
	}
}
func TestGenerationLeaseSharingAndClosure(t *testing.T) {
	server, _ := dnsPeer(t)
	snapshot := snapshotWithDNS(server)
	if err := Normalize(snapshot); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(context.Background())
	first, err := manager.Acquire(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Acquire(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if first.generation != second.generation {
		t.Fatal("same generation did not share DNS state")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.generation.done:
		t.Fatal("one listener closed a shared resolver")
	default:
	}
	if _, err := second.generation.resolver.LookupIP(ctx, "query.test"); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := second.generation.resolver.LookupIP(ctx, "query.test"); err == nil {
		t.Fatal("closed resolver served requests")
	}
	fresh, err := manager.Acquire(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close(ctx)
	if fresh.generation == second.generation {
		t.Fatal("retired generation reused")
	}
}
func TestRouteDNSNormalizationOwnsInput(t *testing.T) {
	server, _ := dnsPeer(t)
	snapshot := snapshotWithDNS(server)
	snapshot.Config.Route = &model.RouteConfig{Block: []string{"full:blocked.test"}}
	original := snapshot.Config.Route
	servers := snapshot.Config.DNS.Servers
	if err := Normalize(snapshot); err != nil {
		t.Fatal(err)
	}
	digest := snapshot.PolicyDigest
	original.Block[0] = "full:changed.test"
	servers[0].Address = "invalid"
	if snapshot.Config.Route.Block[0] != "full:blocked.test" || snapshot.Config.DNS.Servers[0].Address != server || digest == "" {
		t.Fatal("normalized configuration retained mutable input")
	}
}

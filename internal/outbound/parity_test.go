// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestPolarisProtocolKindsAndAliases(t *testing.T) {
	var got []string
	for _, caps := range NewRegistry().Capabilities() {
		got = append(got, caps.Protocol)
	}
	want := []string{"socks4", "socks4a", "socks5", "http", "shadowsocks", "vmess", "vless", "trojan", "anytls", "hysteria2", "tuic"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	for alias, canonical := range map[string]string{"socks": "socks5", "hysteria": "hysteria2"} {
		spec := model.OutboundSpec{ID: "proxy", Protocol: alias, Address: "127.0.0.1", Port: 443, Options: []byte(`{}`)}
		if canonical == "hysteria2" {
			spec.CredentialRef = "password"
		}
		normalized, err := NewRegistry().Normalize(spec, map[string][]byte{"password": []byte("test-password")})
		if err != nil || normalized.Protocol != canonical {
			t.Fatal(alias, err)
		}
	}
}

type emptyProtocol struct {
	N.Dialer
	closed bool
}

func (c *emptyProtocol) Close() error { c.closed = true; return nil }
func TestStatefulPoolSeparatesSourceBindingsAndBoundsGrowth(t *testing.T) {
	var roots []netip.Addr
	var clients []*emptyProtocol
	pool := newSourcePool(context.Background(), &egress.Direct{}, time.Second, func(ctx context.Context, d N.Dialer) (ProtocolClient, error) {
		source, _ := ingress.BindingIP(ctx)
		roots = append(roots, source)
		client := &emptyProtocol{Dialer: d}
		clients = append(clients, client)
		return client, nil
	})
	defer pool.Close()
	firstContext := ingress.WithLocalIP(context.Background(), netip.MustParseAddr("198.18.0.1"))
	first, err := pool.get(firstContext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := pool.get(firstContext)
	if err != nil || first != second {
		t.Fatal("same source did not share client", err)
	}
	other, err := pool.get(ingress.WithLocalIP(context.Background(), netip.MustParseAddr("198.18.0.2")))
	if err != nil || other == first {
		t.Fatal("different sources shared a client", err)
	}
	if roots[0] == roots[1] {
		t.Fatal("background clients lost the captured ingress source")
	}
	for i := 3; i <= maxSourceClients; i++ {
		ip := netip.AddrFrom4([4]byte{198, 18, 0, byte(i)})
		if _, err := pool.get(ingress.WithLocalIP(context.Background(), ip)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.get(context.Background()); err == nil {
		t.Fatal("unbounded source-client allocation")
	}
	pool.Close()
	for _, client := range clients {
		if !client.closed {
			t.Fatal("unclosed pooled client")
		}
	}
	if _, err := pool.get(firstContext); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed pool reopened", err)
	}
}

type trackedDialer struct {
	N.Dialer
	opened chan *closeObserved
}

func (d trackedDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	c, err := d.Dialer.DialContext(ctx, network, dst)
	if err != nil {
		return nil, err
	}
	wrapped := &closeObserved{Conn: c, closed: make(chan struct{})}
	d.opened <- wrapped
	return wrapped, nil
}

type closeObserved struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeObserved) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestQUICRetirementClosesAnOfferAfterItsCallerCanceled(t *testing.T) {
	for _, protocol := range []string{"hysteria2", "tuic"} {
		t.Run(protocol, func(t *testing.T) {
			silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer silent.Close()
			server := M.SocksaddrFromNet(silent.LocalAddr())
			options := map[string]any{"tls": map[string]any{"enabled": true, "insecure": true}}
			if protocol == "tuic" {
				options["uuid"] = "e3add7a8-6e5c-4c41-bcce-0d5015e79002"
			}
			raw, _ := json.Marshal(options)
			opened := make(chan *closeObserved, 1)
			limits := model.DefaultLimits()
			limits.DialTimeout = 5 * time.Second
			limits.HandshakeTimeout = 5 * time.Second
			client, err := NewRegistry().Build(context.Background(), model.OutboundSpec{ID: "proxy", Protocol: protocol, Address: server.AddrString(), Port: server.Port, CredentialRef: "key", Options: raw}, map[string][]byte{"key": []byte("password")}, trackedDialer{Dialer: &egress.Direct{}, opened: opened}, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close(context.Background())
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() {
				conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("remote.invalid:80"))
				if conn != nil {
					conn.Close()
				}
				result <- err
			}()
			var physical *closeObserved
			select {
			case physical = <-opened:
			case <-time.After(time.Second):
				cancel()
				t.Fatal("QUIC offer did not open a socket")
			}
			cancel()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("canceled offer succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("caller cancellation blocked")
			}
			closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := client.Close(closeCtx); err != nil {
				t.Fatal("retirement waited for background offer timeout", err)
			}
			select {
			case <-physical.closed:
			default:
				t.Fatal("unpublished QUIC socket survived retirement")
			}
		})
	}
}

type pipeDialer struct {
	config      *tls.Config
	application chan struct{}
	done        chan struct{}
	release     chan struct{}
}

func (d pipeDialer) DialContext(_ context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer close(d.done)
		defer server.Close()
		secure := tls.Server(server, d.config)
		if secure.Handshake() != nil {
			return
		}
		<-d.release
	}()
	return &applicationObserved{Conn: client, application: d.application}, nil
}

func TestAnyTLSCancellationInterruptsAuthenticationWrite(t *testing.T) {
	asset, _ := testutil.Certificate(t)
	certificate, err := tls.X509KeyPair(asset.Certificate, asset.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	application, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	dialer := pipeDialer{config: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, application: application, release: release, done: done}
	t.Cleanup(func() {
		close(release)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("TLS fixture did not exit")
		}
	})
	options, _ := json.Marshal(tlsOnlyOptions{TLS: &TLSOptions{Enabled: true, ServerName: "localhost", CAPEM: string(asset.Certificate)}})
	limits := model.DefaultLimits()
	limits.DialTimeout = 10 * time.Second
	client, err := NewRegistry().Build(context.Background(), model.OutboundSpec{ID: "proxy", Protocol: "anytls", Address: "127.0.0.1", Port: 443, CredentialRef: "key", Options: options}, map[string][]byte{"key": []byte("password")}, dialer, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("remote.invalid:80"))
		if conn != nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case <-application:
	case <-time.After(time.Second):
		t.Fatal("AnyTLS authentication write did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for the write deadline")
	}
}
func (pipeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, ErrUnsupportedNetwork
}

type applicationObserved struct {
	net.Conn
	application chan struct{}
	once        sync.Once
}

func (c *applicationObserved) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == 23 {
		c.once.Do(func() { close(c.application) })
	}
	return c.Conn.Write(p)
}

func TestTLSOptionsRejectBadTrustAndUnsupportedFields(t *testing.T) {
	for _, options := range []string{`{"tls":{"enabled":false}}`, `{"tls":{"enabled":true,"ca_pem":"bad"}}`, `{"tls":{"enabled":true,"insecure":true,"ca_pem":"bad"}}`, `{"transport":"ws"}`, `{"tls":{"enabled":true,"alpn":[""]}}`} {
		_, err := NewRegistry().Normalize(model.OutboundSpec{ID: "proxy", Protocol: "trojan", Address: "localhost", Port: 443, CredentialRef: "key", Options: []byte(options)}, map[string][]byte{"key": []byte("password")})
		if err == nil {
			t.Fatal("invalid TLS configuration accepted", options)
		}
	}
	asset, _ := testutil.Certificate(t)
	options, _ := json.Marshal(tlsOnlyOptions{TLS: &TLSOptions{Enabled: true, ServerName: "localhost", CAPEM: string(asset.Certificate)}})
	if _, err := NewRegistry().Normalize(model.OutboundSpec{ID: "proxy", Protocol: "trojan", Address: "127.0.0.1", Port: 443, CredentialRef: "key", Options: options}, map[string][]byte{"key": []byte("password")}); err != nil {
		t.Fatal(err)
	}
}

func TestTLSCarrierRejectsUntrustedPeerBeforeSendingCredentials(t *testing.T) {
	asset, _ := testutil.Certificate(t)
	certificate, err := tls.X509KeyPair(asset.Certificate, asset.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"vmess", "vless", "trojan", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			application := make(chan int, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					application <- 0
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				var b [1024]byte
				n, _ := conn.Read(b[:])
				application <- n
			}()
			server := M.SocksaddrFromNet(listener.Addr())
			secret := "password"
			if protocol == "vmess" || protocol == "vless" {
				secret = "e3add7a8-6e5c-4c41-bcce-0d5015e79002"
			}
			client, err := NewRegistry().Build(context.Background(), model.OutboundSpec{ID: "proxy", Protocol: protocol, Address: server.AddrString(), Port: server.Port, CredentialRef: "key", Options: []byte(`{"tls":{"enabled":true}}`)}, map[string][]byte{"key": []byte(secret)}, &egress.Direct{}, model.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("target.invalid:443")); err == nil {
				conn.Close()
				t.Fatal("untrusted certificate accepted")
			}
			select {
			case count := <-application:
				if count > 0 {
					t.Fatal("credentials sent to untrusted peer")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("untrusted TLS socket left open")
			}
		})
	}
}

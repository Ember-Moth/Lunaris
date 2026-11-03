// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/gofrs/uuid/v5"
	mux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/tuic"
	SS "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

func originIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		p, e := netip.ParsePrefix(address.String())
		if e == nil && p.Addr().Is4() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
			return p.Addr()
		}
	}
	t.Skip("no local non-loopback IPv4 address")
	return netip.Addr{}
}
func sourceTarget(t *testing.T) (net.Addr, <-chan netip.Addr) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan netip.Addr, 32)
	var active sync.Map
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			active.Store(c, true)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer active.Delete(c)
				seen <- ingress.AddressIP(c.RemoteAddr())
				c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
		active.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		wg.Wait()
	})
	return listener.Addr(), seen
}
func expectOrigin(t *testing.T, seen <-chan netip.Addr, want netip.Addr) {
	t.Helper()
	select {
	case got := <-seen:
		if got != want {
			t.Fatal("wrong outbound source", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no outbound connection")
	}
}
func proxyFront(t *testing.T, target net.Addr, local netip.Addr, version byte) net.Addr {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var active sync.Map
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, e := listener.Accept()
			if e != nil {
				return
			}
			active.Store(client, true)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer client.Close()
				defer active.Delete(client)
				server, e := net.DialTimeout("tcp", target.String(), time.Second)
				if e != nil {
					return
				}
				defer server.Close()
				active.Store(server, true)
				defer active.Delete(server)
				var header []byte
				if version == 1 {
					header = []byte(fmt.Sprintf("PROXY TCP4 198.18.0.10 %s 12345 443\r\n", local))
				} else {
					header = []byte("\r\n\r\n\x00\r\nQUIT\n")
					header = append(header, 0x21, 0x11, 0, 12)
					header = append(header, 198, 18, 0, 10)
					bytes := local.As4()
					header = append(header, bytes[:]...)
					header = binary.BigEndian.AppendUint16(header, 12345)
					header = binary.BigEndian.AppendUint16(header, 443)
				}
				// Fragment the preface independently of TLS / protocol traffic.
				for _, b := range header {
					if _, e = server.Write([]byte{b}); e != nil {
						return
					}
				}
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(server, client); server.Close(); close(copied) }()
				_, _ = io.Copy(client, server)
				client.Close()
				server.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
		active.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		wg.Wait()
	})
	return listener.Addr()
}
func TestProxyProtocolBeforeTLSAndHTTPCarriers(t *testing.T) {
	local := originIPv4(t)
	for _, carrier := range []string{"tcp", "ws", "httpupgrade"} {
		for _, secure := range []bool{false, true} {
			for _, version := range []byte{1, 2} {
				t.Run(fmt.Sprintf("%s/tls=%v/v%d", carrier, secure, version), func(t *testing.T) {
					server := start(t, "vless", carrier, secure, model.DefaultLimits())
					// Physical connection enters loopback; the preface identifies a different
					// assigned local address. The target must observe that reported source.
					server.addr = proxyFront(t, server.addr, local, version)
					target, seen := sourceTarget(t)
					raw := carrierDial(t, server, carrier, secure)
					client := streamClient(t, "vless", raw, M.SocksaddrFromNet(target))
					defer client.Close()
					echo(t, client)
					expectOrigin(t, seen, local)
				})
			}
		}
	}
}
func TestPlainWildcardTCPOrigin(t *testing.T) {
	local := originIPv4(t)
	server := startConfigured(t, "vless", "tcp", false, model.DefaultLimits(), func(s *model.ListenerSpec) { s.Address = "0.0.0.0" })
	server.addr = &net.TCPAddr{IP: net.IP(local.AsSlice()), Port: server.addr.(*net.TCPAddr).Port}
	target, seen := sourceTarget(t)
	client := streamClient(t, "vless", carrierDial(t, server, "tcp", false), M.SocksaddrFromNet(target))
	defer client.Close()
	echo(t, client)
	expectOrigin(t, seen, local)
}
func TestQUICStreamsPreserveIngressOrigin(t *testing.T) {
	local := originIPv4(t)
	for _, kind := range []string{"hysteria2", "tuic"} {
		t.Run(kind, func(t *testing.T) {
			server := startConfigured(t, kind, "quic", true, model.DefaultLimits(), func(s *model.ListenerSpec) { s.Address = "0.0.0.0" })
			server.addr = &net.UDPAddr{IP: net.IP(local.AsSlice()), Port: server.addr.(*net.UDPAddr).Port}
			ctx := testutil.Context(t)
			tls := &transport.TLS{Config: server.tls, Timeout: time.Second}
			tls.SetNextProtos([]string{"h3"})
			var dial func(context.Context, M.Socksaddr) (net.Conn, error)
			var packets func(context.Context) (net.PacketConn, error)
			if kind == "hysteria2" {
				client, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: &egress.Direct{}, Logger: logger.NOP(), ServerAddress: M.SocksaddrFromNet(server.addr), Password: password, TLSConfig: tls})
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseWithError(io.EOF)
				dial = client.DialConn
				packets = client.ListenPacket
			} else {
				client, err := tuic.NewClient(tuic.ClientOptions{Context: ctx, Dialer: &egress.Direct{}, ServerAddress: M.SocksaddrFromNet(server.addr), UUID: [16]byte(uuid.FromStringOrNil(userID)), Password: password, TLSConfig: tls})
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseWithError(io.EOF)
				dial = client.DialConn
				packets = client.ListenPacket
			}
			target, seen := sourceTarget(t)
			c, err := dial(ctx, M.SocksaddrFromNet(target))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			echo(t, c)
			expectOrigin(t, seen, local)
			targetUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer targetUDP.Close()
			packet, err := packets(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			if _, err := packet.WriteTo([]byte("origin"), targetUDP.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			targetUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
			var data [32]byte
			n, source, err := targetUDP.ReadFrom(data[:])
			if err != nil {
				t.Fatal(err)
			}
			if ingress.AddressIP(source) != local {
				t.Fatal("QUIC UDP origin lost", source, local)
			}
			targetUDP.WriteTo(data[:n], source)
			packet.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := packet.ReadFrom(data[:]); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeShadowsocksUDPOrigin(t *testing.T) {
	local := originIPv4(t)
	for _, mode := range []string{"classic", "2022"} {
		t.Run(mode, func(t *testing.T) {
			var server running
			var method SS.Method
			if mode == "classic" {
				server = startConfigured(t, "shadowsocks", "native", false, model.DefaultLimits(), func(s *model.ListenerSpec) {
					s.Address = "0.0.0.0"
					s.Network = []string{"udp"}
					s.CredentialRefs = []string{"one"}
					s.Options = []byte(`{"method":"aes-128-gcm"}`)
				})
				method, _ = shadowaead.New("aes-128-gcm", nil, password)
			} else {
				var clients []SS.Method
				server, clients = start2022(t, "2022-blake3-aes-128-gcm", false, model.DefaultLimits(), "0.0.0.0")
				method = clients[0]
			}
			endpoint := M.SocksaddrFromNet(server.addr)
			endpoint.Addr = local
			raw, err := net.Dial("udp", endpoint.String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			client := method.DialPacketConn(raw)
			target, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if _, err := client.WriteTo([]byte("native origin"), target.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			target.SetReadDeadline(time.Now().Add(2 * time.Second))
			var b [128]byte
			n, peer, err := target.ReadFrom(b[:])
			if err != nil {
				t.Fatal(err)
			}
			if ingress.AddressIP(peer) != local {
				t.Fatal("native UDP outbound source lost", peer, local)
			}
			target.WriteTo(b[:n], peer)
			client.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, _, err := client.ReadFrom(b[:]); err != nil {
				t.Fatal("native UDP reply did not use the entry address", err)
			}
		})
	}
}
func TestMuxSubstreamsPreserveIngress(t *testing.T) {
	local := originIPv4(t)
	for _, mode := range []string{"smux", "yamux", "h2mux"} {
		t.Run(mode, func(t *testing.T) {
			server := startConfigured(t, "vless", "tcp", false, model.DefaultLimits(), func(s *model.ListenerSpec) { s.Multiplex.Enabled = true })
			server.addr = proxyFront(t, server.addr, local, 2)
			dialer := streamDialer{dial: func(dst M.Socksaddr) (net.Conn, error) {
				return streamClient(t, "vless", carrierDial(t, server, "tcp", false), dst), nil
			}}
			client, err := mux.NewClient(mux.Options{Dialer: dialer, Logger: logger.NOP(), Protocol: mode, MaxConnections: 1, MaxStreams: 4})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			target, seen := sourceTarget(t)
			for range 2 {
				c, err := client.DialContext(testutil.Context(t), "tcp", M.SocksaddrFromNet(target))
				if err != nil {
					t.Fatal(err)
				}
				echo(t, c)
				expectOrigin(t, seen, local)
				c.Close()
			}
		})
	}
}
func TestNaiveHTTPOrigins(t *testing.T) {
	local := originIPv4(t)
	for _, version := range []string{"h1", "h2", "h3"} {
		t.Run(version, func(t *testing.T) {
			carrier := "http"
			if version == "h3" {
				carrier = "quic"
			}
			server := startConfigured(t, "naive", carrier, true, model.DefaultLimits(), func(s *model.ListenerSpec) {
				s.Address = "0.0.0.0"
				s.Options = []byte(`{"users":[{"username":"alice","credential_ref":"one"},{"username":"bob","credential_ref":"two"}]}`)
			})
			endpoint := M.SocksaddrFromNet(server.addr)
			endpoint.Addr = local
			if version == "h3" {
				server.addr = endpoint.UDPAddr()
			} else {
				server.addr = endpoint.TCPAddr()
			}
			target, seen := sourceTarget(t)
			c, status := naiveDial(t, server, version, M.SocksaddrFromNet(target), "alice", password)
			if status != 200 {
				t.Fatal(status)
			}
			defer c.Close()
			echo(t, c)
			expectOrigin(t, seen, local)
		})
	}
}
func TestXHTTPReconstructedStreamOrigin(t *testing.T) {
	local := originIPv4(t)
	for _, version := range []string{"h1", "h2", "h3"} {
		t.Run(version, func(t *testing.T) {
			server := startConfigured(t, "vless", "xhttp", true, model.DefaultLimits(), func(s *model.ListenerSpec) {
				s.Address = "0.0.0.0"
				s.Transport.Path = "/xhttp"
				s.Transport.Host = "localhost"
				s.Transport.XHTTP = &model.XHTTP{Mode: "packet-up", HTTPVersion: version, Extra: []byte(xhttpExtra)}
			})
			endpoint := M.SocksaddrFromNet(server.addr)
			endpoint.Addr = local
			if version == "h3" {
				server.addr = endpoint.UDPAddr()
			} else {
				server.addr = endpoint.TCPAddr()
			}
			client := xhttpClient(t, server, version, "packet-up", true)
			raw, err := client.DialContext(testutil.Context(t))
			if err != nil {
				t.Fatal(err)
			}
			target, seen := sourceTarget(t)
			c := streamClient(t, "vless", raw, M.SocksaddrFromNet(target))
			defer c.Close()
			echo(t, c)
			expectOrigin(t, seen, local)
		})
	}
}

func TestShadowTLSCamouflageUsesReportedIngress(t *testing.T) {
	local := originIPv4(t)
	target, seen := sourceTarget(t)
	server := startSSPlugin(t, "shadow-tls", map[string]any{"version": 1, "handshake": target.String()}, model.DefaultLimits())
	server.addr = proxyFront(t, server.addr, local, 1)
	c := carrierDial(t, server, "tcp", false)
	defer c.Close()
	if _, err := c.Write([]byte{22}); err != nil {
		t.Fatal(err)
	}
	expectOrigin(t, seen, local)
}

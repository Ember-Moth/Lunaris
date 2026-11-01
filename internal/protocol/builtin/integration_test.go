// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/coder/websocket"
	"github.com/gofrs/uuid/v5"
	anytls "github.com/sagernet/sing-anytls"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-quic/tuic"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const userID = "c8820ed3-e4ee-47ad-a5bd-ece70763e32c"
const password = "lunaris-test-password"

type running struct {
	instance protocol.Instance
	addr     net.Addr
	tls      *tls.Config
	flow     *relay.Handler
}

func start(t *testing.T, kind, carrier string, secure bool, limits model.Limits) running {
	t.Helper()
	ctx := testutil.Context(t)
	cert, tlsConfig := testutil.Certificate(t)
	registry, _ := builtin.NewRegistry()
	secret := password
	if kind == "vless" || kind == "vmess" {
		secret = userID
	}
	spec := model.ListenerSpec{ID: "test", Protocol: model.ProtocolType(kind), Address: "127.0.0.1", Enabled: true, Options: []byte("{}"), CredentialRefs: []string{"one", "two"}, Transport: model.Transport{Type: carrier}}
	second := "another-password"
	if kind == "vless" || kind == "vmess" {
		second = "ab20e8ef-131d-448d-a58d-b6d81e25073b"
	}
	if carrier == "ws" || carrier == "httpupgrade" {
		spec.Transport.Path = "/proxy"
		spec.Transport.Host = "localhost"
	}
	if secure {
		spec.CertificateRef = "cert"
	}
	if kind == "tuic" {
		spec.Options = []byte(`{"users":[{"uuid":"` + userID + `","credential_ref":"one"},{"uuid":"ab20e8ef-131d-448d-a58d-b6d81e25073b","credential_ref":"two"}]}`)
	}
	flow := relay.New(ctx, &egress.Direct{}, limits)
	instance, err := registry.Build(protocol.ResolvedListenerSpec{Spec: spec, Limits: limits, Credentials: map[string][]byte{"one": []byte(secret), "two": []byte(second)}, Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}, protocol.Dependencies{Handler: flow, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := instance.Stop(ctx); err != nil {
			t.Error(err)
		}
		if err := flow.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if err := instance.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return running{instance: instance, addr: instance.(interface{ Addr() net.Addr }).Addr(), tls: tlsConfig, flow: flow}
}
func carrierDial(t *testing.T, server running, carrier string, secure bool) net.Conn {
	t.Helper()
	ctx := testutil.Context(t)
	if carrier == "ws" {
		scheme := "ws"
		if secure {
			scheme = "wss"
		}
		tr := &http.Transport{TLSClientConfig: server.tls}
		t.Cleanup(tr.CloseIdleConnections)
		ws, _, err := websocket.Dial(ctx, scheme+"://"+server.addr.String()+"/proxy", &websocket.DialOptions{HTTPClient: &http.Client{Transport: tr}, Host: "localhost"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ws.CloseNow() })
		return websocket.NetConn(ctx, ws, websocket.MessageBinary)
	}
	var c net.Conn
	var err error
	if secure {
		c, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", server.addr.String(), server.tls)
	} else {
		c, err = net.DialTimeout("tcp", server.addr.String(), time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if carrier == "httpupgrade" {
		_, err = fmt.Fprintf(c, "GET /proxy HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		if err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(c)
		response, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 101 {
			t.Fatal(response.Status)
		}
		return &readConn{Conn: c, r: r}
	}
	return c
}

type readConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type fragmentConn struct{ net.Conn }

func (c fragmentConn) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		m, err := c.Conn.Write(p[:1])
		n += m
		p = p[m:]
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
func streamClient(t *testing.T, kind string, c net.Conn, dst M.Socksaddr) net.Conn {
	t.Helper()
	switch kind {
	case "vless":
		client, err := vless.NewClient(userID, "", logger.NOP())
		if err != nil {
			t.Fatal(err)
		}
		conn, err := client.DialConn(c, dst)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	case "vmess":
		client, err := vmess.NewClient(userID, "aes-128-gcm", 0)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := client.DialConn(c, dst)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	case "trojan":
		trojanHeader(t, c, password, 1, dst)
		return c
	case "anytls":
		client, err := anytls.NewClient(anytls.ClientOptions{Password: password, DialOut: func(context.Context) (net.Conn, error) { return c, nil }})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		conn, err := client.DialContext(testutil.Context(t), dst)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	panic("unknown protocol")
}
func trojanHeader(t *testing.T, c net.Conn, secret string, command byte, dst M.Socksaddr) {
	t.Helper()
	sum := sha256.Sum224([]byte(secret))
	b := bytes.NewBufferString(hex.EncodeToString(sum[:]) + "\r\n")
	b.WriteByte(command)
	if err := M.SocksaddrSerializer.WriteAddrPort(b, dst); err != nil {
		t.Fatal(err)
	}
	b.WriteString("\r\n")
	if _, err := c.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}
}
func echo(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("Lunaris payload"), 1024)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("payload changed")
	}
}
func TestStreamProtocolTransportMatrix(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan", "anytls"} {
		for _, carrier := range []string{"tcp", "ws", "httpupgrade"} {
			if kind == "anytls" && carrier != "tcp" {
				continue
			}
			for _, secure := range []bool{false, true} {
				if !secure && (kind == "trojan" || kind == "anytls") {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/tls=%v", kind, carrier, secure), func(t *testing.T) {
					target := testutil.TCPEcho(t)
					s := start(t, kind, carrier, secure, model.DefaultLimits())
					raw := carrierDial(t, s, carrier, secure)
					c := streamClient(t, kind, raw, M.SocksaddrFromNet(target))
					echo(t, c)
					// Stop must revoke an established stream, including hijacked transports.
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					if err := s.instance.Stop(ctx); err != nil {
						t.Fatal(err)
					}
					_ = c.SetReadDeadline(time.Now().Add(time.Second))
					if _, err := c.Read(make([]byte, 1)); err == nil {
						t.Fatal("old stream survived Stop")
					}
				})
			}
		}
	}
}
func TestFragmentedStreamHandshakes(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan", "anytls"} {
		t.Run(kind, func(t *testing.T) {
			s := start(t, kind, "tcp", true, model.DefaultLimits())
			c := streamClient(t, kind, fragmentConn{carrierDial(t, s, "tcp", true)}, M.SocksaddrFromNet(testutil.TCPEcho(t)))
			echo(t, c)
			c.Close()
		})
	}
}
func TestStreamUDPMatrix(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		for _, carrier := range []string{"tcp", "ws", "httpupgrade"} {
			t.Run(kind+"/"+carrier, func(t *testing.T) {
				target := testutil.UDPEcho(t)
				dst := M.SocksaddrFromNet(target)
				s := start(t, kind, carrier, true, model.DefaultLimits())
				raw := carrierDial(t, s, carrier, true)
				var p net.PacketConn
				switch kind {
				case "vless":
					c, _ := vless.NewClient(userID, "", logger.NOP())
					// DialPacketConn emits an empty datagram before the first write.
					pc, err := c.DialEarlyPacketConn(raw, dst)
					if err != nil {
						t.Fatal(err)
					}
					p = pc
				case "vmess":
					c, _ := vmess.NewClient(userID, "aes-128-gcm", 0)
					pc, err := c.DialPacketConn(raw, dst)
					if err != nil {
						t.Fatal(err)
					}
					p = pc
				case "trojan":
					trojanHeader(t, raw, password, 3, dst)
					p = &trojanPackets{Conn: raw}
				}
				packetEcho(t, p, target)
				p.Close()
			})
		}
	}
}

type trojanPackets struct{ net.Conn }

func (c *trojanPackets) WriteTo(p []byte, a net.Addr) (int, error) {
	b := new(bytes.Buffer)
	if err := M.SocksaddrSerializer.WriteAddrPort(b, M.SocksaddrFromNet(a)); err != nil {
		return 0, err
	}
	binary.Write(b, binary.BigEndian, uint16(len(p)))
	b.WriteString("\r\n")
	b.Write(p)
	_, err := c.Write(b.Bytes())
	return len(p), err
}
func (c *trojanPackets) ReadFrom(p []byte) (int, net.Addr, error) {
	dst, err := M.SocksaddrSerializer.ReadAddrPort(c)
	if err != nil {
		return 0, nil, err
	}
	var n uint16
	if err = binary.Read(c, binary.BigEndian, &n); err != nil {
		return 0, nil, err
	}
	var sep [2]byte
	if _, err = io.ReadFull(c, sep[:]); err != nil {
		return 0, nil, err
	}
	if sep != [2]byte{'\r', '\n'} {
		return 0, nil, fmt.Errorf("bad delimiter")
	}
	read, err := io.ReadFull(c, p[:n])
	return read, dst.UDPAddr(), err
}
func packetEcho(t *testing.T, c net.PacketConn, dst net.Addr) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	p := bytes.Repeat([]byte("udp"), 1000)
	if _, err := c.WriteTo(p, dst); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 65535)
	n, _, err := c.ReadFrom(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:n], p) {
		t.Fatal("UDP payload changed")
	}
}
func TestQUICProtocols(t *testing.T) {
	for _, kind := range []string{"hysteria2", "tuic"} {
		for _, udpStream := range []bool{false, true} {
			if kind == "hysteria2" && udpStream {
				continue
			}
			t.Run(fmt.Sprintf("%s/udpStream=%v", kind, udpStream), func(t *testing.T) {
				limits := model.DefaultLimits()
				limits.MaxConnections, limits.MaxUDPSessions, limits.MaxPendingHandshakes = 1, 1, 1
				s := start(t, kind, "quic", true, limits)
				ctx := testutil.Context(t)
				tlsConfig := &transport.TLS{Config: s.tls, Timeout: time.Second}
				tlsConfig.SetNextProtos([]string{"h3"})
				var dial func(context.Context, M.Socksaddr) (net.Conn, error)
				var packet func(context.Context) (net.PacketConn, error)
				if kind == "hysteria2" {
					c, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: &egress.Direct{}, Logger: logger.NOP(), ServerAddress: M.SocksaddrFromNet(s.addr), Password: password, TLSConfig: tlsConfig})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { c.CloseWithError(io.EOF) })
					dial = c.DialConn
					packet = c.ListenPacket
				} else {
					c, err := tuic.NewClient(tuic.ClientOptions{Context: ctx, Dialer: &egress.Direct{}, ServerAddress: M.SocksaddrFromNet(s.addr), UUID: [16]byte(uuid.FromStringOrNil(userID)), Password: password, TLSConfig: tlsConfig, UDPStream: udpStream})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { c.CloseWithError(io.EOF) })
					dial = c.DialConn
					packet = c.ListenPacket
				}
				c, err := dial(ctx, M.SocksaddrFromNet(testutil.TCPEcho(t)))
				if err != nil {
					t.Fatal(err)
				}
				echo(t, c)
				p, err := packet(ctx)
				if err != nil {
					t.Fatal(err)
				}
				packetEcho(t, p, testutil.UDPEcho(t))
				p.Close()
				stop, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := s.instance.Stop(stop); err != nil {
					t.Fatal(err)
				}
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := c.Read(make([]byte, 1)); err == nil {
					t.Fatal("QUIC session survived stop")
				}
				c.Close()
			})
		}
	}
}

func TestStreamRejectsUnknownCredentials(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan", "anytls"} {
		t.Run(kind, func(t *testing.T) {
			s := start(t, kind, "tcp", true, model.DefaultLimits())
			raw := carrierDial(t, s, "tcp", true)
			dst := M.SocksaddrFromNet(testutil.TCPEcho(t))
			var c net.Conn
			var err error
			switch kind {
			case "vless":
				client, _ := vless.NewClient("dde462a4-b900-43dc-acd4-5358b19a4b74", "", logger.NOP())
				c, err = client.DialConn(raw, dst)
			case "vmess":
				client, _ := vmess.NewClient("dde462a4-b900-43dc-acd4-5358b19a4b74", "aes-128-gcm", 0)
				c, err = client.DialConn(raw, dst)
			case "trojan":
				trojanHeader(t, raw, "wrong-password", 1, dst)
				c = raw
			case "anytls":
				client, e := anytls.NewClient(anytls.ClientOptions{Password: "wrong-password", DialOut: func(context.Context) (net.Conn, error) { return raw, nil }})
				if e != nil {
					t.Fatal(e)
				}
				defer client.Close()
				c, err = client.DialContext(testutil.Context(t), dst)
			}
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			if _, err = c.Write([]byte("must not forward")); err != nil {
				return
			}
			if _, err = c.Read(make([]byte, 32)); err == nil {
				t.Fatal("unauthenticated client received data")
			}
		})
	}
}
func TestUpgradedHandshakeTimeout(t *testing.T) {
	for _, carrier := range []string{"tcp", "ws", "httpupgrade"} {
		t.Run(carrier, func(t *testing.T) {
			limits := model.DefaultLimits()
			limits.HandshakeTimeout = 150 * time.Millisecond
			limits.MaxPendingHandshakes = 1
			s := start(t, "vless", carrier, false, limits)
			c := carrierDial(t, s, carrier, false)
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			begin := time.Now()
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("silent client was not closed")
			}
			if time.Since(begin) > 800*time.Millisecond {
				t.Fatal("server handshake deadline was lost during upgrade")
			}
		})
	}
}
func TestQUICRejectsUnknownCredentials(t *testing.T) {
	for _, kind := range []string{"hysteria2", "tuic"} {
		t.Run(kind, func(t *testing.T) {
			limits := model.DefaultLimits()
			limits.HandshakeTimeout = time.Second
			s := start(t, kind, "quic", true, limits)
			ctx := testutil.Context(t)
			tlsConfig := &transport.TLS{Config: s.tls, Timeout: time.Second}
			tlsConfig.SetNextProtos([]string{"h3"})
			var dial func(context.Context, M.Socksaddr) (net.Conn, error)
			if kind == "hysteria2" {
				c, err := hysteria2.NewClient(hysteria2.ClientOptions{Context: ctx, Dialer: &egress.Direct{}, Logger: logger.NOP(), ServerAddress: M.SocksaddrFromNet(s.addr), Password: "wrong-password", TLSConfig: tlsConfig})
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseWithError(io.EOF)
				dial = c.DialConn
			} else {
				c, err := tuic.NewClient(tuic.ClientOptions{Context: ctx, Dialer: &egress.Direct{}, ServerAddress: M.SocksaddrFromNet(s.addr), UUID: [16]byte(uuid.FromStringOrNil(userID)), Password: "wrong-password", TLSConfig: tlsConfig})
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseWithError(io.EOF)
				dial = c.DialConn
			}
			c, err := dial(ctx, M.SocksaddrFromNet(testutil.TCPEcho(t)))
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = c.Write([]byte("unauthenticated")); err != nil {
				return
			}
			if _, err = c.Read(make([]byte, 32)); err == nil {
				t.Fatal("QUIC auth failure forwarded traffic")
			}
		})
	}
}

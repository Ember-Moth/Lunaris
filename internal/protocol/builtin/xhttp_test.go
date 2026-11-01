// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	X "github.com/Ember-Moth/Lunaris/internal/transport/xhttp"
	mux "github.com/sagernet/sing-mux"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"golang.org/x/net/http2"
)

const xhttpExtra = `{"xPaddingBytes":100,"scMaxEachPostBytes":1024,"scStreamUpServerSecs":-1}`

func startXHTTP(t *testing.T, kind, version, mode string, secure bool, limits model.Limits, extensions bool) (running, *X.Client) {
	t.Helper()
	s := startConfigured(t, kind, "xhttp", secure, limits, func(spec *model.ListenerSpec) {
		spec.Transport.Path = "/xhttp"
		spec.Transport.Host = "localhost"
		spec.Transport.XHTTP = &model.XHTTP{Mode: mode, HTTPVersion: version, Extra: []byte(xhttpExtra)}
		if extensions {
			spec.UDPOverTCP = true
			spec.Multiplex.Enabled = true
		}
	})
	client := xhttpClient(t, s, version, mode, secure)
	return s, client
}
func xhttpClient(t *testing.T, s running, version, mode string, secure bool) *X.Client {
	t.Helper()
	cfg, err := X.Parse("localhost", "/xhttp", mode, xhttpExtra)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ScMinPostsIntervalMs = X.Range{From: 1, To: 1}
	var tlsConfig *tls.Config
	if secure {
		tlsConfig = s.tls.Clone()
		alpn := version
		if alpn == "h1" {
			alpn = "http/1.1"
		}
		tlsConfig.NextProtos = []string{alpn}
	}
	client := X.NewClient(X.ClientOptions{Context: testutil.Context(t), Config: cfg, Server: s.addr.String(), TLSConfig: tlsConfig, Dial: func(ctx context.Context, address string, cfg *tls.Config) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil || cfg == nil {
			return c, err
		}
		secure := tls.Client(c, cfg)
		if err = secure.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return secure, nil
	}})
	t.Cleanup(func() { client.Close() })
	return client
}
func TestXHTTPProtocolMatrix(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		for _, version := range []string{"h1", "h2", "h3"} {
			for _, mode := range []string{X.ModePacketUp, X.ModeStreamUp, X.ModeStreamOne, X.ModeAuto} {
				t.Run(kind+"/"+version+"/"+mode, func(t *testing.T) {
					s, client := startXHTTP(t, kind, version, mode, true, model.DefaultLimits(), false)
					raw, err := client.DialContext(testutil.Context(t))
					if err != nil {
						t.Fatal(err)
					}
					tcp := streamClient(t, kind, raw, M.SocksaddrFromNet(testutil.TCPEcho(t)))
					defer tcp.Close()
					echo(t, tcp)
					udpRaw, err := client.DialContext(testutil.Context(t))
					if err != nil {
						t.Fatal(err)
					}
					defer udpRaw.Close()
					target := testutil.UDPEcho(t)
					dst := M.SocksaddrFromNet(target)
					var pc net.PacketConn
					switch kind {
					case "vless":
						c, _ := vless.NewClient(userID, "", logger.NOP())
						pc, err = c.DialEarlyPacketConn(udpRaw, dst)
					case "vmess":
						c, _ := vmess.NewClient(userID, "aes-128-gcm", 0)
						pc, err = c.DialPacketConn(udpRaw, dst)
					case "trojan":
						trojanHeader(t, udpRaw, password, 3, dst)
						pc = &trojanPackets{Conn: udpRaw}
					}
					if err != nil {
						t.Fatal(err)
					}
					packetEcho(t, pc, target)
					pc.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					if err = s.instance.Stop(ctx); err != nil {
						t.Fatal(err)
					}
					_ = tcp.SetReadDeadline(time.Now().Add(time.Second))
					if _, err = tcp.Read(make([]byte, 1)); err == nil {
						t.Fatal("XHTTP flow survived Stop")
					}
				})
			}
		}
	}
}
func TestXHTTPPlainHTTP1(t *testing.T) {
	for _, kind := range []string{"vless", "vmess"} {
		for _, mode := range []string{X.ModePacketUp, X.ModeStreamUp, X.ModeStreamOne} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				_, client := startXHTTP(t, kind, "h1", mode, false, model.DefaultLimits(), false)
				raw, err := client.DialContext(testutil.Context(t))
				if err != nil {
					t.Fatal(err)
				}
				c := streamClient(t, kind, raw, M.SocksaddrFromNet(testutil.TCPEcho(t)))
				defer c.Close()
				echo(t, c)
			})
		}
	}
}
func TestXHTTPExtensions(t *testing.T) {
	for _, version := range []string{"h2", "h3"} {
		t.Run(version, func(t *testing.T) {
			_, client := startXHTTP(t, "vless", version, X.ModeAuto, true, model.DefaultLimits(), true)
			d := streamDialer{dial: func(dst M.Socksaddr) (net.Conn, error) {
				raw, err := client.DialContext(testutil.Context(t))
				if err != nil {
					return nil, err
				}
				return streamClient(t, "vless", raw, dst), nil
			}}
			target := testutil.UDPEcho(t)
			for _, v := range []uint8{1, 2} {
				u := uot.Client{Dialer: d, Version: v}
				pc, err := u.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(target))
				if err != nil {
					t.Fatal(err)
				}
				packetEcho(t, pc, target)
				pc.Close()
			}
			for _, mode := range []string{"smux", "yamux", "h2mux"} {
				mc, err := mux.NewClient(mux.Options{Dialer: d, Logger: logger.NOP(), Protocol: mode, MaxConnections: 1, MaxStreams: 8})
				if err != nil {
					t.Fatal(err)
				}
				pc, err := mc.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(target))
				if err != nil {
					t.Fatal(err)
				}
				packetEcho(t, pc, target)
				pc.Close()
				mc.Close()
			}
		})
	}
}
func TestXHTTPIncompleteProtocolExpires(t *testing.T) {
	limits := model.DefaultLimits()
	limits.HandshakeTimeout = 70 * time.Millisecond
	limits.MaxPendingHandshakes = 1
	limits.MaxConnections = 1
	limits.MaxUDPSessions = 1
	for _, mode := range []string{X.ModePacketUp, X.ModeStreamUp, X.ModeStreamOne} {
		t.Run(mode, func(t *testing.T) {
			s, client := startXHTTP(t, "vless", "h2", mode, true, limits, false)
			stalled, err := client.DialContext(testutil.Context(t))
			if err != nil {
				t.Fatal(err)
			}
			defer stalled.Close()
			// Force a body-bearing request onto the wire without a complete VLESS header.
			_, _ = stalled.Write([]byte{0})
			_ = stalled.SetReadDeadline(time.Now().Add(time.Second))
			if _, err = stalled.Read(make([]byte, 1)); err == nil {
				t.Fatal("incomplete protocol survived handshake timeout")
			}
			stalled.Close()
			fresh := xhttpClient(t, s, "h2", mode, true)
			raw, err := fresh.DialContext(testutil.Context(t))
			if err != nil {
				t.Fatal(err)
			}
			c := streamClient(t, "vless", raw, M.SocksaddrFromNet(testutil.TCPEcho(t)))
			defer c.Close()
			echo(t, c)
		})
	}
}

func TestXHTTPCleartextHTTP2(t *testing.T) {
	s, _ := startXHTTP(t, "vless", "h2", X.ModeStreamOne, false, model.DefaultLimits(), false)
	tr := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+s.addr.String()+"/xhttp/?x_padding="+strings.Repeat("X", 100), reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "localhost"
	response, err := tr.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatal(response.Status)
	}
	carrier := &requestConn{reader: response.Body, writer: writer, cancel: cancel}
	defer carrier.Close()
	c := streamClient(t, "vless", carrier, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	echo(t, c)
}

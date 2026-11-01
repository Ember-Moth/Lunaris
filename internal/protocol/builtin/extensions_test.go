// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	mux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

type streamDialer struct {
	dial func(M.Socksaddr) (net.Conn, error)
}

func (d streamDialer) DialContext(_ context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("TCP carrier required")
	}
	return d.dial(dst)
}
func (d streamDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("use UoT or mux for UDP")
}
func extensionDialer(t *testing.T, kind, carrier string, secure bool, configure func(*model.ListenerSpec)) (running, streamDialer) {
	t.Helper()
	wireCarrier := carrier
	if kind == "shadowsocks" {
		carrier = "native"
		secure = false
	}
	s := startConfigured(t, kind, carrier, secure, model.DefaultLimits(), func(spec *model.ListenerSpec) {
		if kind == "shadowsocks" {
			spec.CredentialRefs = []string{"one"}
			spec.Options = []byte(`{"method":"aes-128-gcm"}`)
		}
		configure(spec)
	})
	return s, streamDialer{dial: func(dst M.Socksaddr) (net.Conn, error) {
		raw := carrierDial(t, s, wireCarrier, secure)
		if kind == "shadowsocks" {
			cipher, err := shadowaead.New("aes-128-gcm", nil, password)
			if err != nil {
				return nil, err
			}
			return cipher.DialConn(raw, dst)
		}
		return streamClient(t, kind, raw, dst), nil
	}}
}
func TestUOTProtocolMatrix(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "vless", "vmess", "trojan", "anytls"} {
		for _, version := range []uint8{1, 2} {
			if kind == "anytls" && version != 2 {
				continue
			}
			t.Run(fmt.Sprintf("%s/v%d", kind, version), func(t *testing.T) {
				s, d := extensionDialer(t, kind, "tcp", true, func(spec *model.ListenerSpec) {
					if kind != "anytls" {
						spec.UDPOverTCP = true
					}
				})
				client := uot.Client{Dialer: d, Version: version}
				target := testutil.UDPEcho(t)
				pc, err := client.ListenPacket(testutil.Context(t), M.ParseSocksaddr("0.0.0.0:0"))
				if err != nil {
					t.Fatal(err)
				}
				defer pc.Close()
				packetEcho(t, pc, target)
				// Preserve empty datagrams and subsequent packets on the same association.
				if _, err = pc.WriteTo(nil, target); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 64)
				n, _, err := pc.ReadFrom(b)
				if err != nil || n != 0 {
					t.Fatalf("empty UoT datagram: %d %v", n, err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err = s.instance.Stop(ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func TestMuxProtocolAndCarrierMatrix(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "vless", "vmess", "trojan"} {
		for _, mode := range []string{"smux", "yamux", "h2mux"} {
			for _, carrier := range []string{"tcp", "ws", "httpupgrade"} {
				if kind == "shadowsocks" && carrier != "tcp" {
					continue
				}
				t.Run(kind+"/"+mode+"/"+carrier, func(t *testing.T) {
					s, d := extensionDialer(t, kind, carrier, true, func(spec *model.ListenerSpec) {
						spec.Multiplex.Enabled = true
						spec.Multiplex.Padding = true
						spec.UDPOverTCP = true
					})
					client, err := mux.NewClient(mux.Options{Dialer: d, Logger: logger.NOP(), Protocol: mode, MaxConnections: 1, MaxStreams: 8, Padding: true})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					dst := M.SocksaddrFromNet(testutil.TCPEcho(t))
					ctx := testutil.Context(t)
					first, err := client.DialContext(ctx, "tcp", dst)
					if err != nil {
						t.Fatal(err)
					}
					defer first.Close()
					echo(t, first)
					second, err := client.DialContext(ctx, "tcp", dst)
					if err != nil {
						t.Fatal(err)
					}
					echo(t, second)
					second.Close()
					udpTarget := testutil.UDPEcho(t)
					pc, err := client.ListenPacket(ctx, mux.Destination)
					if err != nil {
						t.Fatal(err)
					}
					packetEcho(t, pc, udpTarget)
					pc.Close()
					// This server accepts both formats. The SDK can nest them, although
					// sing-box Shadowsocks outbound selects UoT instead of mux.
					uc := uot.Client{Dialer: client, Version: 2}
					up, err := uc.ListenPacket(ctx, M.ParseSocksaddr("0.0.0.0:0"))
					if err != nil {
						t.Fatal(err)
					}
					packetEcho(t, up, testutil.UDPEcho(t))
					up.Close()
					stop, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					if err = s.instance.Stop(stop); err != nil {
						t.Fatal(err)
					}
					_ = first.SetReadDeadline(time.Now().Add(time.Second))
					if _, err = first.Read(make([]byte, 1)); err == nil {
						t.Fatal("mux stream survived listener stop")
					}
				})
			}
		}
	}
}
func TestUOTConnectMode(t *testing.T) {
	_, d := extensionDialer(t, "anytls", "tcp", true, func(*model.ListenerSpec) {})
	client := uot.Client{Dialer: d, Version: 2}
	c, err := client.DialContext(testutil.Context(t), "udp", M.SocksaddrFromNet(testutil.UDPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("connected datagram")
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(payload))
	if _, err = io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, payload) {
		t.Fatal("connected payload changed")
	}
}

func TestShadowsocksNativeUOTAndMuxShareListener(t *testing.T) {
	s, d := extensionDialer(t, "shadowsocks", "tcp", false, func(spec *model.ListenerSpec) {
		spec.Network = []string{"tcp", "udp"}
		spec.UDPOverTCP = true
		spec.Multiplex = model.Multiplex{Enabled: true, Padding: true}
	})
	target := testutil.UDPEcho(t)
	raw, err := net.Dial("udp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cipher, err := shadowaead.New("aes-128-gcm", nil, password)
	if err != nil {
		t.Fatal(err)
	}
	native := cipher.DialPacketConn(raw)
	uc := uot.Client{Dialer: d, Version: 2}
	overTCP, err := uc.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(target))
	if err != nil {
		t.Fatal(err)
	}
	defer overTCP.Close()
	packetEcho(t, native, target)
	packetEcho(t, overTCP, target)
	for _, mode := range []string{"smux", "yamux", "h2mux"} {
		client, err := mux.NewClient(mux.Options{Dialer: d, Logger: logger.NOP(), Protocol: mode, Padding: true, MaxConnections: 1, MaxStreams: 8})
		if err != nil {
			t.Fatal(err)
		}
		packet, err := client.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(target))
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		packetEcho(t, packet, target)
		// Different client modes remain live together on the same SS endpoint.
		packetEcho(t, native, target)
		packetEcho(t, overTCP, target)
		packet.Close()
		client.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = s.instance.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAnyTLSRejectsUOTV1(t *testing.T) {
	_, d := extensionDialer(t, "anytls", "tcp", true, func(*model.ListenerSpec) {})
	client := uot.Client{Dialer: d, Version: 1}
	pc, err := client.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(testutil.UDPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(time.Second))
	if _, err = pc.WriteTo([]byte("legacy must be rejected"), testutil.UDPEcho(t)); err != nil {
		return
	}
	if _, _, err = pc.ReadFrom(make([]byte, 256)); err == nil {
		t.Fatal("AnyTLS accepted UoT v1")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("AnyTLS silently retained a rejected UoT v1 stream")
	}
}

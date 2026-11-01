// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	mux "github.com/sagernet/sing-mux"
	upstream "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type snellTestClient interface {
	upstream.Method
	DialContext(context.Context, M.Socksaddr) (net.Conn, error)
	Close() error
}

func snellClient(t *testing.T, s running, version int, obfs, mode string, psk []byte, reuse bool) snellTestClient {
	t.Helper()
	var c snellTestClient
	var err error
	if version == 5 {
		m, _ := upstream.ParseObfsMode(obfs)
		c, err = snellv4.NewClient(snellv4.ClientOptions{PSK: psk, ObfsMode: m, Reuse: reuse, Dialer: &egress.Direct{}, Server: M.SocksaddrFromNet(s.addr)})
	} else {
		m, _ := snellv6.ParseMode(mode)
		c, err = snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: m, Reuse: reuse, Dialer: &egress.Direct{}, Server: M.SocksaddrFromNet(s.addr)})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func TestSnellVersionsTCPUDPAndReuse(t *testing.T) {
	cases := []struct {
		name       string
		version    int
		obfs, mode string
	}{{"v5", 5, "none", ""}, {"v5-http", 5, "http", ""}, {"v5-tls-obfs", 5, "tls", ""}, {"v6", 6, "", "default"}, {"v6-unshaped", 6, "", "unshaped"}, {"v6-unsafe-raw", 6, "", "unsafe-raw"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options, _ := json.Marshal(map[string]any{"version": tc.version, "obfs": tc.obfs, "mode": tc.mode})
			s := startConfigured(t, "snell", "tcp", false, model.DefaultLimits(), func(spec *model.ListenerSpec) { spec.CredentialRefs = []string{"one"}; spec.Options = options })
			client := snellClient(t, s, tc.version, tc.obfs, tc.mode, []byte(password), true)
			for i := 0; i < 3; i++ {
				c, err := client.DialContext(testutil.Context(t), M.SocksaddrFromNet(testutil.TCPEcho(t)))
				if err != nil {
					t.Fatal(err)
				}
				echo(t, c)
				if err = N.CloseWrite(c); err != nil {
					t.Fatal(err)
				}
				if _, err = io.Copy(io.Discard, c); err != nil {
					t.Fatal(err)
				}
				c.Close()
			}
			raw, err := net.Dial("tcp", s.addr.String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			pc, err := client.DialPacketConn(raw)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			target := testutil.UDPEcho(t)
			payload := bytes.Repeat([]byte("snell-udp"), 100)
			_ = pc.SetDeadline(time.Now().Add(time.Second))
			if _, err = pc.WriteTo(payload, target); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 4096)
			n, _, err := pc.ReadFrom(buffer)
			if err != nil || !bytes.Equal(buffer[:n], payload) {
				t.Fatal("Snell UDP echo", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err = s.instance.Stop(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestSnellRejectsWrongPSK(t *testing.T) {
	s := startConfigured(t, "snell", "tcp", false, model.DefaultLimits(), func(spec *model.ListenerSpec) {
		spec.CredentialRefs = []string{"one"}
		spec.Options = []byte(`{"version":6}`)
	})
	client := snellClient(t, s, 6, "", "default", []byte("wrong-password-credential"), false)
	raw, err := net.Dial("tcp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(time.Second))
	c, err := client.DialConn(raw, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	if err != nil {
		return
	}
	defer c.Close()
	_, _ = c.Write([]byte("reject"))
	if _, err = c.Read(make([]byte, 128)); err == nil {
		t.Fatal("wrong PSK accepted")
	}
}

func TestSnellConnectionExtensions(t *testing.T) {
	s := startConfigured(t, "snell", "tcp", false, model.DefaultLimits(), func(spec *model.ListenerSpec) {
		spec.CredentialRefs = []string{"one"}
		spec.Options = []byte(`{"version":6}`)
		spec.UDPOverTCP = true
		spec.Multiplex.Enabled = true
	})
	client := snellClient(t, s, 6, "", "default", []byte(password), false)
	d := streamDialer{dial: func(dst M.Socksaddr) (net.Conn, error) {
		raw, err := net.Dial("tcp", s.addr.String())
		if err != nil {
			return nil, err
		}
		c, err := client.DialConn(raw, dst)
		if err != nil {
			raw.Close()
			return nil, err
		}
		return &struct{ net.Conn }{c}, nil
	}}
	target := testutil.UDPEcho(t)
	u := uot.Client{Dialer: d, Version: 2}
	p, err := u.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(target))
	if err != nil {
		t.Fatal(err)
	}
	packetEcho(t, p, target)
	p.Close()
	for _, mode := range []string{"smux", "yamux", "h2mux"} {
		c, err := mux.NewClient(mux.Options{Dialer: d, Logger: logger.NOP(), Protocol: mode, MaxConnections: 1, MaxStreams: 8})
		if err != nil {
			t.Fatal(err)
		}
		p, err := c.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(target))
		if err != nil {
			t.Fatal(err)
		}
		packetEcho(t, p, target)
		p.Close()
		c.Close()
	}
}

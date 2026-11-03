// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	Q "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	mux "github.com/sagernet/sing-mux"
	SS "github.com/sagernet/sing-shadowsocks"
	ss2022 "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"golang.org/x/net/http2"
)

func start2022(t *testing.T, method string, multi bool, limits model.Limits, addresses ...string) (running, []SS.Method) {
	t.Helper()
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, size)) }
	refs := []string{"one"}
	options := map[string]any{"method": method}
	passwords := []string{key(1)}
	if multi {
		refs = append(refs, "two")
		options["server_key_ref"] = "server"
		passwords = []string{key(3) + ":" + key(1), key(3) + ":" + key(2)}
	}
	rawOptions, _ := json.Marshal(options)
	spec := model.ListenerSpec{ID: "ss2022", Protocol: "shadowsocks", Address: "127.0.0.1", Enabled: true, Network: []string{"tcp", "udp"}, CredentialRefs: refs, Options: rawOptions, UDPOverTCP: true, Multiplex: model.Multiplex{Enabled: true}}
	if len(addresses) > 0 {
		spec.Address = addresses[0]
	}
	credentials := map[string][]byte{"one": []byte(key(1)), "two": []byte(key(2)), "server": []byte(key(3))}
	ctx := testutil.Context(t)
	flow := relay.New(ctx, &egress.Direct{}, limits)
	r, _ := builtin.NewRegistry()
	instance, err := r.Build(protocol.ResolvedListenerSpec{Spec: spec, Limits: limits, Credentials: credentials}, protocol.Dependencies{Handler: flow, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := instance.Stop(ctx); err != nil {
			t.Error(err)
		}
		if err := flow.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if err = instance.Start(ctx); err != nil {
		t.Fatal(err)
	}
	clients := make([]SS.Method, len(passwords))
	for i, p := range passwords {
		clients[i], err = ss2022.NewWithPassword(method, p, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	return running{instance: instance, addr: instance.(interface{ Addr() net.Addr }).Addr(), flow: flow}, clients
}
func TestShadowsocks2022Modes(t *testing.T) {
	for _, method := range ss2022.List {
		for _, multi := range []bool{false, true} {
			if multi && method == "2022-blake3-chacha20-poly1305" {
				continue
			}
			t.Run(fmt.Sprintf("%s/multi=%v", method, multi), func(t *testing.T) {
				s, clients := start2022(t, method, multi, model.DefaultLimits())
				tcpTarget := M.SocksaddrFromNet(testutil.TCPEcho(t))
				udpTarget := testutil.UDPEcho(t)
				for _, client := range clients {
					d := streamDialer{dial: func(dst M.Socksaddr) (net.Conn, error) {
						raw, err := net.Dial("tcp", s.addr.String())
						if err != nil {
							return nil, err
						}
						return client.DialConn(raw, dst)
					}}
					c, err := d.dial(tcpTarget)
					if err != nil {
						t.Fatal(err)
					}
					echo(t, c)
					c.Close()
					raw, err := net.Dial("udp", s.addr.String())
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					pc := client.DialPacketConn(raw)
					packetEcho(t, pc, udpTarget)
					uc := uot.Client{Dialer: d, Version: 2}
					u, err := uc.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(udpTarget))
					if err != nil {
						t.Fatal(err)
					}
					packetEcho(t, u, udpTarget)
					u.Close()
					for _, mode := range []string{"smux", "yamux", "h2mux"} {
						t.Log("mux", mode)
						mc, err := mux.NewClient(mux.Options{Dialer: d, Logger: logger.NOP(), Protocol: mode, MaxConnections: 1, MaxStreams: 8})
						if err != nil {
							t.Fatal(err)
						}
						c, err := mc.DialContext(testutil.Context(t), "tcp", tcpTarget)
						if err != nil {
							t.Fatal(err)
						}
						echo(t, c)
						c.Close()
						mp, err := mc.ListenPacket(testutil.Context(t), M.SocksaddrFromNet(udpTarget))
						if err != nil {
							t.Fatal(err)
						}
						packetEcho(t, mp, udpTarget)
						mp.Close()
						mc.Close()
					}
					packetEcho(t, pc, udpTarget)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				if err := s.instance.Stop(ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Independent Naive client fixture: fixed padding bytes and full-frame reads.
// It deliberately does not reuse the server's framing code.
type naivePeer struct {
	net.Conn
	reader      io.Reader
	writer      io.Writer
	read, write int
	pending     []byte
}

func (c *naivePeer) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		size := min(len(p), 60000)
		if c.write < 8 {
			frame := []byte{byte(size >> 8), byte(size), 5}
			frame = append(frame, p[:size]...)
			frame = append(frame, 1, 2, 3, 4, 5)
			_, err = c.writer.Write(frame)
		} else {
			_, err = c.writer.Write(p[:size])
		}
		if err != nil {
			return n, err
		}
		c.write++
		n += size
		p = p[size:]
	}
	return
}
func (c *naivePeer) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.read >= 8 {
		return c.reader.Read(p)
	}
	var h [3]byte
	if _, err := io.ReadFull(c.reader, h[:]); err != nil {
		return 0, err
	}
	data := make([]byte, int(binary.BigEndian.Uint16(h[:2]))+int(h[2]))
	if _, err := io.ReadFull(c.reader, data); err != nil {
		return 0, err
	}
	c.read++
	c.pending = data[:len(data)-int(h[2])]
	return c.Read(p)
}

type requestConn struct {
	reader io.ReadCloser
	writer *io.PipeWriter
	cancel context.CancelFunc
}

func (c *requestConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (c *requestConn) Write(p []byte) (int, error)    { return c.writer.Write(p) }
func (c *requestConn) Close() error                   { c.cancel(); c.writer.Close(); return c.reader.Close() }
func (*requestConn) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (*requestConn) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (*requestConn) SetDeadline(time.Time) error      { return nil }
func (*requestConn) SetReadDeadline(time.Time) error  { return nil }
func (*requestConn) SetWriteDeadline(time.Time) error { return nil }
func naiveDial(t *testing.T, s running, version string, dst M.Socksaddr, username, secret string) (net.Conn, int) {
	t.Helper()
	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+secret))
	if version == "h1" {
		cfg := s.tls.Clone()
		cfg.NextProtos = []string{"http/1.1"}
		raw, err := tls.Dial("tcp", s.addr.String(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\nPadding: ~~~~\r\n\r\n", dst, dst, authorization)
		reader := bufio.NewReader(raw)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			raw.Close()
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			raw.Close()
			return nil, response.StatusCode
		}
		return &naivePeer{Conn: raw, reader: reader, writer: raw}, 200
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	var rt http.RoundTripper
	if version == "h2" {
		tr := &http2.Transport{TLSClientConfig: s.tls, DialTLSContext: func(ctx context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
			return (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", s.addr.String())
		}}
		rt = tr
		t.Cleanup(tr.CloseIdleConnections)
	} else {
		tr := &http3.Transport{TLSClientConfig: s.tls, Dial: func(ctx context.Context, _ string, cfg *tls.Config, qcfg *Q.Config) (*Q.Conn, error) {
			return Q.DialAddr(ctx, s.addr.String(), cfg, qcfg)
		}}
		rt = tr
		t.Cleanup(func() { tr.Close() })
	}
	pr, pw := io.Pipe()
	req := &http.Request{Method: "CONNECT", URL: &url.URL{Scheme: "https", Host: dst.String()}, Host: dst.String(), Header: http.Header{"Proxy-Authorization": []string{authorization}, "Padding": []string{"~~~~"}}, Body: pr}
	response, err := rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		pw.Close()
		cancel()
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		pw.Close()
		cancel()
		return nil, response.StatusCode
	}
	base := &requestConn{reader: response.Body, writer: pw, cancel: cancel}
	return &naivePeer{Conn: base, reader: base, writer: base}, 200
}
func TestNaiveHTTPVersions(t *testing.T) {
	for _, version := range []string{"h1", "h2", "h3"} {
		t.Run(version, func(t *testing.T) {
			carrier := "http"
			if version == "h3" {
				carrier = "quic"
			}
			s := startConfigured(t, "naive", carrier, true, model.DefaultLimits(), func(spec *model.ListenerSpec) {
				spec.Options = []byte(`{"users":[{"username":"alice","credential_ref":"one"},{"username":"bob","credential_ref":"two"}]}`)
			})
			dst := M.SocksaddrFromNet(testutil.TCPEcho(t))
			c, status := naiveDial(t, s, version, dst, "alice", password)
			if status != 200 {
				t.Fatal(status)
			}
			defer c.Close()
			for i := 0; i < 12; i++ {
				echo(t, c)
			}
			if rejected, status := naiveDial(t, s, version, dst, "alice", "wrong"); rejected != nil || status != 407 {
				t.Fatal("wrong password accepted", status)
			}
			d := streamDialer{dial: func(dst M.Socksaddr) (net.Conn, error) {
				c, status := naiveDial(t, s, version, dst, "bob", "another-password")
				if status != 200 {
					return nil, fmt.Errorf("CONNECT: %d", status)
				}
				return c, nil
			}}
			uc := uot.Client{Dialer: d, Version: 2}
			pc, err := uc.ListenPacket(testutil.Context(t), M.ParseSocksaddr("0.0.0.0:0"))
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			packetEcho(t, pc, testutil.UDPEcho(t))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err = s.instance.Stop(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = c.Read(make([]byte, 1)); err == nil {
				t.Fatal("Naive stream survived listener stop")
			}
		})
	}
}

type recordingConn struct {
	net.Conn
	packet []byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.packet = bytes.Clone(p)
	return c.Conn.Write(p)
}
func TestSS2022ReplayAndSessionLimit(t *testing.T) {
	limits := model.DefaultLimits()
	limits.MaxUDPSessions = 1
	limits.UDPQueueSize = 1
	s, clients := start2022(t, "2022-blake3-aes-128-gcm", true, limits)
	target := testutil.UDPEcho(t)
	raw, err := net.Dial("udp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	record := &recordingConn{Conn: raw}
	pc := clients[0].DialPacketConn(record)
	packetEcho(t, pc, target)
	replay := bytes.Clone(record.packet)
	if _, err = raw.Write(replay); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err = pc.ReadFrom(make([]byte, 4096)); err == nil {
		t.Fatal("replayed packet accepted")
	}
	packetEcho(t, pc, target)
	// Saturate a second authenticated identity while the sole association is live.
	rejectedRaw, err := net.Dial("udp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rejectedRaw.Close()
	rejected := clients[1].DialPacketConn(rejectedRaw)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 512; i++ {
			_, _ = rejected.WriteTo([]byte("over budget"), target)
		}
	}()
	<-done
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = s.instance.Stop(ctx); err != nil {
		t.Fatal("shutdown blocked behind rejected UDP queue", err)
	}
}

func TestSS2022UDPResumesAfterIdleWithoutSessionChurn(t *testing.T) {
	limits := model.DefaultLimits()
	limits.UDPIdleTimeout = 25 * time.Millisecond
	limits.MaxUDPSessions = 1
	s, clients := start2022(t, "2022-blake3-aes-256-gcm", true, limits)
	raw, err := net.Dial("udp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	pc := clients[0].DialPacketConn(raw)
	target := testutil.UDPEcho(t)
	for i := 0; i < 4; i++ {
		packetEcho(t, pc, target)
		deadline := time.Now().Add(time.Second)
		for {
			_, active := s.flow.Active()
			if active == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("idle relay did not release its slot")
			}
			time.Sleep(time.Millisecond)
		}
	}
}

type firstFragmentConn struct {
	net.Conn
	written bool
}

func (c *firstFragmentConn) Write(p []byte) (int, error) {
	if c.written {
		return c.Conn.Write(p)
	}
	c.written = true
	return (fragmentConn{Conn: c.Conn}).Write(p)
}
func TestSS2022FragmentedHandshakeAndInvalidPackets(t *testing.T) {
	s, clients := start2022(t, "2022-blake3-aes-128-gcm", false, model.DefaultLimits())
	raw, err := net.Dial("tcp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c, err := clients[0].DialConn(&firstFragmentConn{Conn: raw}, M.SocksaddrFromNet(testutil.TCPEcho(t)))
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c)
	c.Close()
	udp, err := net.Dial("udp", s.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	for size := 0; size < 80; size++ {
		_, _ = udp.Write(bytes.Repeat([]byte{byte(size)}, size))
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	expired, err := ss2022.NewWithPassword("2022-blake3-aes-128-gcm", key, func() time.Time { return time.Now().Add(-time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	old := expired.DialPacketConn(udp)
	target := testutil.UDPEcho(t)
	_, _ = old.WriteTo([]byte("expired"), target)
	_ = old.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err = old.ReadFrom(make([]byte, 4096)); err == nil {
		t.Fatal("stale timestamp accepted")
	}
	packetEcho(t, clients[0].DialPacketConn(udp), target)
}

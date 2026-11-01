// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/relay"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const testPassword = "lunaris-integration-test-password"

func startServer(t *testing.T, method string, limits model.Limits, dialer N.Dialer) (*Server, *relay.Handler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	flow := relay.New(ctx, dialer, limits)
	options, _ := json.Marshal(Options{Method: method})
	instance, err := (Factory{}).Build(protocol.ResolvedListenerSpec{Spec: model.ListenerSpec{ID: "test", Protocol: "shadowsocks", Address: "127.0.0.1", Network: []string{"tcp", "udp"}, Options: options, CredentialRefs: []string{"personal"}}, Limits: limits, Credentials: map[string][]byte{"personal": []byte(testPassword)}}, protocol.Dependencies{Handler: flow})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	server := instance.(*Server)
	t.Cleanup(func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := server.Stop(cleanup); err != nil {
			t.Error(err)
		}
		if err := flow.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return server, flow
}

func tcpEcho(t *testing.T) net.Addr {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; wg.Wait() })
	return listener.Addr()
}

func udpEcho(t *testing.T) net.Addr {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, addr, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = listener.WriteTo(buffer[:n], addr)
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.LocalAddr()
}

func TestAEADTCPAndUDP(t *testing.T) {
	for _, method := range Methods {
		t.Run(method, func(t *testing.T) {
			targetTCP, targetUDP := tcpEcho(t), udpEcho(t)
			server, _ := startServer(t, method, model.DefaultLimits(), &egress.Direct{})
			cipher, err := shadowaead.New(method, nil, testPassword)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := net.DialTimeout("tcp", server.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			client, err := cipher.DialConn(raw, M.SocksaddrFromNet(targetTCP))
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("lunaris"), 9000)
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			// The proxy must preserve a half-close so the response can still arrive.
			if err := raw.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			response, err := io.ReadAll(client)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(response, payload) {
				t.Fatalf("TCP response size %d, expected %d", len(response), len(payload))
			}
			udp, err := net.Dial("udp", server.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			udp.SetDeadline(time.Now().Add(3 * time.Second))
			packet := cipher.DialPacketConn(udp)
			for _, destination := range []net.Addr{targetUDP, M.Socksaddr{Fqdn: "localhost", Port: uint16(targetUDP.(*net.UDPAddr).Port)}} {
				// Stay below macOS' UDP socket datagram ceiling; Linux interop
				// validation can exercise larger datagrams separately.
				payload := bytes.Repeat([]byte("udp"), 1200)
				if _, err := packet.WriteTo(payload, destination); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 65535)
				n, address, err := packet.ReadFrom(buffer)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buffer[:n], payload) || address.String() != targetUDP.String() {
					t.Fatalf("unexpected UDP reply: size=%d source=%v", n, address)
				}
			}
		})
	}
}

func TestRejectWrongPasswordAndUDPReplay(t *testing.T) {
	target := udpEcho(t)
	server, _ := startServer(t, "aes-128-gcm", model.DefaultLimits(), &egress.Direct{})
	raw, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(time.Second))
	wrong, _ := shadowaead.New("aes-128-gcm", nil, "wrong-password")
	client, err := wrong.DialConn(raw, M.Socksaddr{Addr: M.AddrFromNet(target), Port: uint16(target.(*net.UDPAddr).Port)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("wrong password accepted")
	}
	cipher, _ := shadowaead.New("aes-128-gcm", nil, testPassword)
	var wire []byte
	encoder := cipher.DialPacketConn(&datagramConn{write: func(p []byte) (int, error) { wire = bytes.Clone(p); return len(p), nil }})
	if _, err := encoder.WriteTo([]byte("single-use"), target); err != nil {
		t.Fatal(err)
	}
	udp, err := net.Dial("udp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(time.Second))
	if _, err := udp.Write(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Read(make([]byte, 1500)); err != nil {
		t.Fatal(err)
	}
	udp.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	if _, err := udp.Write(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Read(make([]byte, 1500)); err == nil {
		t.Fatal("replayed UDP packet accepted")
	}
}

func TestUDPIdleReclaimsSession(t *testing.T) {
	target := udpEcho(t)
	limits := model.DefaultLimits()
	limits.UDPIdleTimeout = 100 * time.Millisecond
	server, flow := startServer(t, "aes-128-gcm", limits, &egress.Direct{})
	udp, err := net.Dial("udp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(time.Second))
	cipher, _ := shadowaead.New("aes-128-gcm", nil, testPassword)
	client := cipher.DialPacketConn(udp)
	if _, err := client.WriteTo([]byte("idle"), target); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.ReadFrom(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, active := flow.Active()
		server.mu.Lock()
		sessions := len(server.sessions)
		server.mu.Unlock()
		if active == 0 && sessions == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle session was not reclaimed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type blockedDialer struct {
	started chan struct{}
	once    sync.Once
}

func (d *blockedDialer) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}
func (d *blockedDialer) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestStopWithFullUDPQueueAndPendingDial(t *testing.T) {
	limits := model.DefaultLimits()
	limits.UDPQueueSize = 2
	blocked := &blockedDialer{started: make(chan struct{})}
	server, _ := startServer(t, "aes-128-gcm", limits, blocked)
	udp, err := net.Dial("udp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	cipher, _ := shadowaead.New("aes-128-gcm", nil, testPassword)
	client := cipher.DialPacketConn(udp)
	for i := 0; i < 100; i++ {
		if _, err := client.WriteTo([]byte(strings.Repeat("x", 100)), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("dial not reached")
	}
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Stop(cleanup); err != nil {
		t.Fatalf("queue prevented shutdown: %v", err)
	}
}

func TestUDPBindFailureReleasesTCPPort(t *testing.T) {
	occupied, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	limits := model.DefaultLimits()
	flow := relay.New(context.Background(), &egress.Direct{}, limits)
	options, _ := json.Marshal(Options{Method: "aes-128-gcm"})
	instance, err := (Factory{}).Build(protocol.ResolvedListenerSpec{Spec: model.ListenerSpec{ID: "bind", Address: "127.0.0.1", Port: uint16(occupied.LocalAddr().(*net.UDPAddr).Port), Options: options, CredentialRefs: []string{"test"}}, Limits: limits, Credentials: map[string][]byte{"test": []byte(testPassword)}}, protocol.Dependencies{Handler: flow})
	if err != nil {
		t.Fatal(err)
	}
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer flow.Close(cleanup)
	defer instance.Stop(cleanup)
	if err := instance.Start(context.Background()); err == nil {
		t.Fatal("occupied UDP port accepted")
	}
	listener, err := net.Listen("tcp", occupied.LocalAddr().String())
	if err != nil {
		t.Fatalf("TCP port leaked after UDP failure: %v", err)
	}
	listener.Close()
}

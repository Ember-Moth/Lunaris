// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func buildClient(t *testing.T, protocol, address string) Client {
	t.Helper()
	server := M.ParseSocksaddr(address)
	c, err := NewRegistry().Build(context.Background(), model.OutboundSpec{ID: "proxy", Protocol: protocol, Address: server.AddrString(), Port: server.Port, CredentialRef: "password", Options: []byte(`{"username":"alice"}`)}, map[string][]byte{"password": []byte("secret")}, &egress.Direct{}, model.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return c
}

func tcpFixture(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				serve(c)
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; workers.Wait() })
	return listener.Addr().String()
}

func TestHTTPConnectAuthenticationDomainAndBufferedPayload(t *testing.T) {
	observed := make(chan *http.Request, 1)
	address := tcpFixture(t, func(c net.Conn) {
		reader := bufio.NewReader(c)
		request, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		observed <- request
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\nready")
		io.Copy(c, reader)
	})
	client := buildClient(t, "http", address)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	connection, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("remote-only.invalid:443"))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request := <-observed
	if request.Method != "CONNECT" || request.Host != "remote-only.invalid:443" || request.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")) {
		t.Fatal("invalid CONNECT request")
	}
	connection.SetDeadline(time.Now().Add(time.Second))
	var ready [5]byte
	if _, err := io.ReadFull(connection, ready[:]); err != nil || string(ready[:]) != "ready" {
		t.Fatal("buffered proxy payload lost", err)
	}
	if _, err := connection.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(connection, ready[:]); err != nil || string(ready[:]) != "hello" {
		t.Fatal("successful dial remained attached to canceled request", err)
	}
	if _, err := client.ListenPacket(context.Background(), M.ParseSocksaddr("127.0.0.1:53")); !errors.Is(err, ErrUnsupportedNetwork) {
		t.Fatal("HTTP accepted UDP", err)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Read(ready[:]); err == nil {
		t.Fatal("retirement left connection alive")
	}
}

func readSocksRequest(c net.Conn) (byte, string, error) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:2]); err != nil {
		return 0, "", err
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return 0, "", err
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return 0, "", err
	}
	if _, err := io.ReadFull(c, head[:2]); err != nil {
		return 0, "", err
	}
	user := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return 0, "", err
	}
	if _, err := io.ReadFull(c, head[:1]); err != nil {
		return 0, "", err
	}
	password := make([]byte, int(head[0]))
	if _, err := io.ReadFull(c, password); err != nil {
		return 0, "", err
	}
	if string(user) != "alice" || string(password) != "secret" {
		return 0, "", errors.New("wrong credentials")
	}
	c.Write([]byte{1, 0})
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return 0, "", err
	}
	command := head[1]
	var destination string
	switch head[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return 0, "", err
		}
		destination = net.IP(ip[:]).String()
	case 3:
		if _, err := io.ReadFull(c, head[:1]); err != nil {
			return 0, "", err
		}
		name := make([]byte, int(head[0]))
		if _, err := io.ReadFull(c, name); err != nil {
			return 0, "", err
		}
		destination = string(name)
	case 4:
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return 0, "", err
		}
		destination = net.IP(ip[:]).String()
	default:
		return 0, "", errors.New("unexpected address type")
	}
	_, err := io.ReadFull(c, head[:2])
	return command, destination, err
}

func TestSOCKS5UDPControlLifetimeAndUnspecifiedRelay(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	release, accepted := make(chan struct{}), make(chan struct{})
	address := tcpFixture(t, func(c net.Conn) {
		command, _, err := readSocksRequest(c)
		if err != nil || command != 3 {
			return
		}
		reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint16(reply[8:], uint16(udp.LocalAddr().(*net.UDPAddr).Port))
		c.Write(reply)
		close(accepted)
		<-release
	})
	client := buildClient(t, "socks5", address)
	socket, err := client.ListenPacket(context.Background(), M.ParseSocksaddr("remote-only.invalid:53"))
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer socket.Close()
	<-accepted
	socket.SetDeadline(time.Now().Add(time.Second))
	if _, err := socket.WriteTo([]byte("hello"), M.ParseSocksaddr("remote-only.invalid:53")); err != nil {
		close(release)
		t.Fatal(err)
	}
	udp.SetDeadline(time.Now().Add(time.Second))
	var b [512]byte
	n, peer, err := udp.ReadFrom(b[:])
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	if n < 4 || b[3] != 3 {
		close(release)
		t.Fatal("domain was resolved before SOCKS UDP")
	}
	udp.WriteTo(b[:n], peer)
	buffer := make([]byte, 512)
	n, _, err = socket.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "hello" {
		close(release)
		t.Fatal("SOCKS UDP round trip failed", err)
	}
	close(release)
	if _, _, err := socket.ReadFrom(buffer); err == nil {
		t.Fatal("closed control connection left UDP alive")
	}
}

func TestSOCKS5TCPPreservesDestination(t *testing.T) {
	observed := make(chan string, 1)
	address := tcpFixture(t, func(c net.Conn) {
		command, dst, err := readSocksRequest(c)
		if err != nil || command != 1 {
			return
		}
		observed <- dst
		c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
		io.Copy(c, c)
	})
	client := buildClient(t, "socks5", address)
	connection, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("remote-only.invalid:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if <-observed != "remote-only.invalid" {
		t.Fatal("SOCKS destination lost")
	}
	connection.SetDeadline(time.Now().Add(time.Second))
	connection.Write([]byte("hello"))
	var data [5]byte
	if _, err := io.ReadFull(connection, data[:]); err != nil || string(data[:]) != "hello" {
		t.Fatal(err)
	}
}

func TestCloseCancelsPendingHandshake(t *testing.T) {
	for _, protocol := range []string{"http", "socks5"} {
		t.Run(protocol, func(t *testing.T) {
			entered := make(chan struct{})
			address := tcpFixture(t, func(c net.Conn) {
				var b [1]byte
				if _, err := c.Read(b[:]); err == nil {
					close(entered)
					io.Copy(io.Discard, c)
				}
			})
			client := buildClient(t, protocol, address)
			result := make(chan error, 1)
			go func() {
				c, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("remote-only.invalid:443"))
				if c != nil {
					c.Close()
				}
				result <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("handshake did not start")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := client.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil {
				t.Fatal("canceled handshake succeeded")
			}
		})
	}
}

type stalledClient struct {
	N.Dialer
	release chan struct{}
	closed  chan struct{}
}

func (c *stalledClient) Close() error {
	close(c.closed)
	<-c.release
	return errors.New("cleanup failed")
}
func TestCloseCanBeWaitedAgain(t *testing.T) {
	raw := &stalledClient{release: make(chan struct{}), closed: make(chan struct{})}
	c := newClient(context.Background(), raw, Capabilities{}, model.DefaultLimits())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-raw.closed
	close(raw.release)
	if err := c.Close(context.Background()); err == nil || err.Error() != "cleanup failed" {
		t.Fatal("cleanup result lost", err)
	}
}

func TestInvalidOutboundConfiguration(t *testing.T) {
	base := model.OutboundSpec{ID: "proxy", Protocol: "socks5", Address: "proxy.example", Port: 1080, CredentialRef: "password", Options: []byte(`{"username":"alice"}`)}
	for _, change := range []func(*model.OutboundSpec){
		func(s *model.OutboundSpec) { s.ID = "direct" }, func(s *model.OutboundSpec) { s.Protocol = "socks4" }, func(s *model.OutboundSpec) { s.Address = "https://proxy.example" }, func(s *model.OutboundSpec) { s.Address = "0.0.0.0" }, func(s *model.OutboundSpec) { s.Port = 0 }, func(s *model.OutboundSpec) { s.CredentialRef = "missing" }, func(s *model.OutboundSpec) { s.Options = []byte(`{"username":"alice","password":"inline-secret"}`) }, func(s *model.OutboundSpec) { s.Options = []byte(`null`) },
	} {
		s := base
		change(&s)
		if _, err := NewRegistry().Normalize(s, map[string][]byte{"password": []byte("secret")}); err == nil {
			t.Fatalf("accepted invalid config: %s/%s", s.ID, s.Protocol)
		}
	}
}

func TestSOCKS5RejectsUnsupportedDatagramHeaders(t *testing.T) {
	for _, wire := range [][]byte{{0, 0}, {0, 1, 0, 1}, {0, 0, 1, 1}} {
		reader, writer := net.Pipe()
		go func() { defer writer.Close(); writer.Write(wire) }()
		var b [32]byte
		_, err := (socksDatagram{reader}).Read(b[:])
		reader.Close()
		if err == nil {
			t.Fatal("invalid SOCKS datagram accepted", wire)
		}
	}
}

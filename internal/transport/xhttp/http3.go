// Derived from XTLS/Xray-core transport/internet/splithttp at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

type h3ServerState struct {
	mu       sync.Mutex
	packet   net.PacketConn
	listener *quic.EarlyListener
	server   *http3.Server
}

func isHTTP3(config *tls.Config) bool {
	return config != nil && len(config.NextProtos) == 1 && config.NextProtos[0] == http3.NextProtoH3
}

func (server *Server) serveH3(listener net.Listener) error {
	listenConfig := net.ListenConfig{}
	packet, err := listenConfig.ListenPacket(server.ctx, "udp", listener.Addr().String())
	if err != nil {
		return err
	}
	return server.ServePacket(packet)
}

// ServePacket serves HTTP/3 on the UDP socket until it closes; it closes the
// socket when the configuration is not HTTP/3.
func (server *Server) ServePacket(packet net.PacketConn) error {
	if !server.PacketBased() {
		_ = packet.Close()
		return errors.New("xhttp: HTTP/3 requires TLS ALPN h3")
	}
	tlsConfig := http3.ConfigureTLSConfig(server.tlsConfig.Clone())
	quicListener, err := quic.ListenEarly(packet, tlsConfig, h3QUICConfig(server.config, true))
	if err != nil {
		_ = packet.Close()
		return err
	}
	server.localAddr = packet.LocalAddr()
	httpServer := &http3.Server{
		Handler: server, MaxHeaderBytes: server.config.ServerMaxHeaderBytes,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			enableH3BBR(conn)
			return context.WithValue(ctx, http.LocalAddrContextKey, conn.LocalAddr())
		},
	}
	server.h3.mu.Lock()
	server.h3.packet, server.h3.listener, server.h3.server = packet, quicListener, httpServer
	server.h3.mu.Unlock()
	select {
	case <-server.closed:
		_ = server.closeH3()
		return nil
	default:
	}
	err = httpServer.ServeListener(quicListener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (server *Server) closeH3() error {
	server.h3.mu.Lock()
	httpServer, listener, packet := server.h3.server, server.h3.listener, server.h3.packet
	server.h3.server, server.h3.listener, server.h3.packet = nil, nil, nil
	server.h3.mu.Unlock()
	var result error
	if httpServer != nil {
		result = errors.Join(result, httpServer.Close())
	}
	if listener != nil {
		result = errors.Join(result, listener.Close())
	}
	if packet != nil {
		result = errors.Join(result, packet.Close())
	}
	return result
}

// h3PacketTransport owns the QUIC transport of each live HTTP/3 connection.
type h3PacketTransport struct {
	mu         sync.Mutex
	transports map[*quic.Transport]struct{}
	closed     bool
}

func newH3DialerClient(
	config Config,
	address string,
	tlsConfig *tls.Config,
	dialPacket DialPacketFunc,
) *defaultDialerClient {
	if dialPacket == nil {
		dialPacket = defaultPacketDialer
	}
	owned := new(h3PacketTransport)
	transport := &http3.Transport{
		TLSClientConfig: http3.ConfigureTLSConfig(tlsConfig.Clone()), DisableCompression: true,
		QUICConfig: h3QUICConfig(config, false),
		Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			packet, remote, err := dialPacket(ctx, address)
			if err != nil {
				return nil, err
			}
			quicTransport := &quic.Transport{Conn: packet}
			conn, err := quicTransport.DialEarly(ctx, remote, tlsConfig, quicConfig)
			if err != nil {
				_ = closeQUICTransport(quicTransport)
				return nil, err
			}
			enableH3BBR(conn)
			if !owned.add(quicTransport, conn) {
				_ = closeQUICTransport(quicTransport)
				return nil, net.ErrClosed
			}
			return conn, nil
		},
	}
	client := &defaultDialerClient{
		config: config, client: &http.Client{Transport: transport}, transport: transport,
		http2: true, closeExtra: owned.Close,
	}
	return client
}

func h3KeepaliveDuration(seconds int64) time.Duration {
	if seconds < 0 {
		return 0
	}
	if seconds == 0 {
		return 10 * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func defaultPacketDialer(ctx context.Context, address string) (net.PacketConn, net.Addr, error) {
	remote, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, nil, err
	}
	network := "udp6"
	if remote.IP.To4() != nil {
		network = "udp4"
	}
	packet, err := (&net.ListenConfig{}).ListenPacket(ctx, network, "")
	return packet, remote, err
}

// add keeps the transport until its connection ends or the client closes. A
// transport the caller created outlives its connections, so http3.Transport
// redialing after a lost connection would otherwise leave the old one reading
// from its socket.
func (owned *h3PacketTransport) add(transport *quic.Transport, conn *quic.Conn) bool {
	owned.mu.Lock()
	defer owned.mu.Unlock()
	if owned.closed {
		return false
	}
	if owned.transports == nil {
		owned.transports = make(map[*quic.Transport]struct{})
	}
	owned.transports[transport] = struct{}{}
	context.AfterFunc(conn.Context(), func() { owned.release(transport) })
	return true
}

// release closes the transport while holding the lock, so a concurrent Close
// returns only after it is closed.
func (owned *h3PacketTransport) release(transport *quic.Transport) {
	owned.mu.Lock()
	defer owned.mu.Unlock()
	if _, tracked := owned.transports[transport]; tracked {
		delete(owned.transports, transport)
		_ = closeQUICTransport(transport)
	}
}

func (owned *h3PacketTransport) Close() error {
	owned.mu.Lock()
	transports := owned.transports
	owned.transports = nil
	owned.closed = true
	owned.mu.Unlock()
	var result error
	for transport := range transports {
		result = errors.Join(result, closeQUICTransport(transport))
	}
	return result
}

// closeQUICTransport closes the transport and then its UDP socket, which
// Transport.Close leaves open because the dialer supplied it.
func closeQUICTransport(transport *quic.Transport) error {
	return errors.Join(transport.Close(), transport.Conn.Close())
}

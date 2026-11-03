// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/route"
	M "github.com/sagernet/sing/common/metadata"
)

var dnsUDPBufferPool = sync.Pool{
	New: func() any { return new([maxDNSMessage]byte) },
}

func (resolver *Resolver) exchange(ctx context.Context, server server, query []byte) ([]byte, error) {
	switch server.transport {
	case transportUDP:
		return resolver.exchangeUDP(ctx, server.address, query)
	case transportTCP:
		return resolver.exchangeStream(ctx, "tcp", server.address, query, nil)
	case transportTLS:
		return resolver.exchangeStream(
			ctx,
			"tcp",
			server.address,
			query,
			&tls.Config{MinVersion: tls.VersionTLS12, ServerName: server.serverName},
		)
	case transportHTTPS:
		return resolver.exchangeHTTPS(ctx, server, query)
	default:
		return nil, ErrNoConfiguredResolver
	}
}

func (resolver *Resolver) exchangeUDP(ctx context.Context, address string, query []byte) ([]byte, error) {
	connection, err := resolver.bootstrapDial(ctx, "udp", address)
	if err != nil {
		return nil, fmt.Errorf("dns: dial UDP: %w", err)
	}
	defer func() { _ = connection.Close() }()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	if err := connection.SetDeadline(deadline(ctx)); err != nil {
		return nil, fmt.Errorf("dns: set UDP deadline: %w", err)
	}
	if _, err := connection.Write(query); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("dns: write UDP query: %w", err)
	}
	buffer := dnsUDPBufferPool.Get().(*[maxDNSMessage]byte)
	defer dnsUDPBufferPool.Put(buffer)
	count, err := connection.Read(buffer[:])
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("dns: read UDP response: %w", err)
	}
	return append([]byte(nil), buffer[:count]...), nil
}

func (resolver *Resolver) exchangeStream(
	ctx context.Context,
	network, address string,
	query []byte,
	tlsConfig *tls.Config,
) ([]byte, error) {
	connection, err := resolver.bootstrapDial(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dns: dial %s: %w", network, err)
	}
	defer func() { _ = connection.Close() }()
	stopClose := context.AfterFunc(ctx, func() { connection.Close() })
	defer stopClose()
	if err := connection.SetDeadline(deadline(ctx)); err != nil {
		return nil, fmt.Errorf("dns: set stream deadline: %w", err)
	}
	stream := connection
	if tlsConfig != nil {
		tlsConnection := tls.Client(connection, tlsConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("dns: TLS handshake: %w", err)
		}
		stream = tlsConnection
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := stream.Write(framed); err != nil {
		return nil, fmt.Errorf("dns: write stream query: %w", err)
	}
	var size [2]byte
	if _, err := io.ReadFull(stream, size[:]); err != nil {
		return nil, fmt.Errorf("dns: read stream response size: %w", err)
	}
	response := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(stream, response); err != nil {
		return nil, fmt.Errorf("dns: read stream response: %w", err)
	}
	return response, nil
}

func (resolver *Resolver) exchangeHTTPS(ctx context.Context, server server, query []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.address, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("dns: create HTTPS request: %w", err)
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	client := resolver.dohClient(server)
	if _, preserve := ingress.BindingIP(ctx); preserve {
		client = resolver.newDoHClient(server, true)
		defer client.CloseIdleConnections()
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("dns: HTTPS exchange: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dns: HTTPS response status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessage+1))
	if err != nil {
		return nil, fmt.Errorf("dns: read HTTPS response: %w", err)
	}
	if len(body) > maxDNSMessage {
		return nil, fmt.Errorf("dns: response exceeds %d bytes", maxDNSMessage)
	}
	return body, nil
}

func (resolver *Resolver) dohClient(server server) *http.Client {
	if server.serverName == "" {
		return resolver.client
	}
	key := server.address + "\x00" + server.serverName
	if existing, loaded := resolver.dohClients.Load(key); loaded {
		return existing.(*http.Client)
	}
	client := resolver.newDoHClient(server, false)
	transport := client.Transport.(*http.Transport)
	actual, _ := resolver.dohClients.LoadOrStore(key, client)
	if actual != client {
		transport.CloseIdleConnections()
	}
	return actual.(*http.Client)
}

func (r *Resolver) bootstrapDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&egress.Direct{Dialer: r.dialer}).DialContext(route.WithoutNameResolver(ctx), network, M.ParseSocksaddr(address))
}
func (r *Resolver) newDoHClient(server server, singleRequest bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if base, ok := r.client.Transport.(*http.Transport); ok {
		transport = base.Clone()
	}
	transport.Proxy = nil
	transport.MaxConnsPerHost = 32
	transport.DialContext = r.bootstrapDial
	transport.DisableKeepAlives = singleRequest
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	if server.serverName != "" {
		transport.TLSClientConfig.ServerName = server.serverName
	}
	return &http.Client{Timeout: r.timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

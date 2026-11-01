// Derived from XTLS/Xray-core transport/internet/splithttp/dialer.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DialFunc dials the server, terminating TLS when a configuration is given.
type DialFunc func(context.Context, string, *tls.Config) (net.Conn, error)

// ClientOptions contains the dependencies of one XHTTP carrier client.
type ClientOptions struct {
	Context    context.Context
	Config     Config
	Server     string
	TLSConfig  *tls.Config
	Dial       DialFunc
	DialPacket DialPacketFunc
}

// Client opens XHTTP carriers to one server, multiplexing them over pooled HTTP
// connections.
type Client struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     Config
	server     string
	tlsConfig  *tls.Config
	dial       DialFunc
	dialPacket DialPacketFunc
	manager    *xmuxManager
	download   *xmuxManager
	closeOnce  sync.Once
	closed     atomic.Bool
	closeErr   error
}

// NewClient prepares the connection pools for the configured mode.
func NewClient(options ClientOptions) *Client {
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		ctx:        ctx,
		cancel:     cancel,
		config:     options.Config,
		server:     options.Server,
		tlsConfig:  options.TLSConfig,
		dial:       options.Dial,
		dialPacket: options.DialPacket,
	}
	client.manager = newXMUXManager(
		options.Config.XMUX,
		func() xmuxConn { return client.newHTTPClient(options.Server, options.TLSConfig, options.Config) },
	)
	if download := options.Config.Download; download != nil {
		client.download = newXMUXManager(
			download.Transport.XMUX,
			func() xmuxConn { return client.newHTTPClient(download.Address, download.TLSConfig, download.Transport) },
		)
	}
	return client
}

// DialContext opens one XHTTP session and returns it as a stream.
func (client *Client) DialContext(ctx context.Context) (net.Conn, error) {
	if client.closed.Load() {
		return nil, net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	mode := client.config.Mode
	if mode == ModeAuto {
		mode = ModePacketUp
	}
	connCtx, innerCancel := context.WithCancel(context.WithoutCancel(ctx))
	stopClientCancel := context.AfterFunc(client.ctx, innerCancel)
	stopDialCancel := context.AfterFunc(ctx, innerCancel)
	defer stopDialCancel()
	cancel := func() {
		stopClientCancel()
		innerCancel()
	}
	uploadClient := client.manager.get()
	if uploadClient == nil {
		cancel()
		return nil, net.ErrClosed
	}
	downloadClient := uploadClient
	if mode == ModeStreamOne {
		var err error
		uploadClient, err = acquireXMUXRequest(client.manager, uploadClient)
		if err != nil {
			cancel()
			return nil, err
		}
		downloadClient = uploadClient
	} else if client.download != nil {
		downloadClient = client.download.get()
		if downloadClient == nil {
			cancel()
			return nil, net.ErrClosed
		}
	}
	if mode != ModeStreamOne {
		downloadManager := client.manager
		if client.download != nil {
			downloadManager = client.download
		}
		var err error
		downloadClient, err = acquireXMUXRequest(downloadManager, downloadClient)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	lease := newXMUXLease(uploadClient, downloadClient)
	var closed atomic.Bool
	onClose := func() {
		if closed.Swap(true) {
			return
		}
		lease.Close()
	}
	if mode == ModeStreamOne {
		return client.dialStreamOne(connCtx, cancel, uploadClient, onClose)
	}
	return client.dialSplit(connCtx, cancel, mode, uploadClient, downloadClient, lease, onClose)
}

func (client *Client) dialStreamOne(
	ctx context.Context,
	cancel context.CancelFunc,
	selected *xmuxClient,
	onClose func(),
) (net.Conn, error) {
	reader, writer := io.Pipe()
	response, remote, local, err := selected.conn.(dialerClient).openStream(
		ctx,
		client.targetURL(client.config, client.server, client.tlsConfig),
		"",
		reader,
		false,
	)
	if err != nil {
		cancel()
		onClose()
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	return &splitConn{
		writer:     writer,
		reader:     response,
		remoteAddr: remote,
		localAddr:  local,
		cancel:     cancel,
		onClose:    onClose,
	}, nil
}

func (client *Client) dialSplit(
	ctx context.Context,
	cancel context.CancelFunc,
	mode string,
	upload, download *xmuxClient,
	lease *xmuxLease,
	onClose func(),
) (net.Conn, error) {
	sessionID := client.config.generateSessionID()
	downloadConfig, downloadAddress, downloadTLS := client.config, client.server, client.tlsConfig
	if client.config.Download != nil {
		downloadConfig, downloadAddress, downloadTLS = client.config.Download.Transport,
			client.config.Download.Address, client.config.Download.TLSConfig
	}
	response, remote, local, err := download.conn.(dialerClient).openStream(
		ctx,
		client.targetURL(downloadConfig, downloadAddress, downloadTLS),
		sessionID,
		nil,
		false,
	)
	if err != nil {
		cancel()
		onClose()
		return nil, err
	}
	if mode == ModeStreamUp {
		reader, writer := io.Pipe()
		for !upload.takeRequest(time.Now()) {
			next := client.manager.get()
			if next == nil || !lease.replaceUpload(next) {
				cancel()
				onClose()
				_ = response.Close()
				_ = reader.Close()
				_ = writer.Close()
				return nil, errors.New("xhttp: XMUX upload request budget exhausted")
			}
			upload = next
		}
		_, _, _, err = upload.conn.(dialerClient).openStream(
			ctx,
			client.targetURL(client.config, client.server, client.tlsConfig),
			sessionID,
			reader,
			true,
		)
		if err != nil {
			cancel()
			onClose()
			_ = response.Close()
			_ = reader.Close()
			_ = writer.Close()
			return nil, err
		}
		return &splitConn{
			writer:     writer,
			reader:     response,
			remoteAddr: remote,
			localAddr:  local,
			cancel:     cancel,
			onClose:    onClose,
		}, nil
	}
	pipe := newUploadPipe(max(1, int(client.config.ScMaxEachPostBytes.To)))
	go client.uploadPackets(ctx, pipe, sessionID, upload, lease)
	return &splitConn{
		writer:     pipe,
		reader:     response,
		remoteAddr: remote,
		localAddr:  local,
		cancel:     cancel,
		onClose:    onClose,
	}, nil
}

func acquireXMUXRequest(manager *xmuxManager, selected *xmuxClient) (*xmuxClient, error) {
	for selected != nil {
		if selected.takeRequest(time.Now()) {
			return selected, nil
		}
		selected = manager.get()
	}
	return nil, net.ErrClosed
}

func (client *Client) newHTTPClient(address string, tlsConfig *tls.Config, config Config) dialerClient {
	secure := tlsConfig != nil
	if secure && len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "h3" {
		return newH3DialerClient(config, address, tlsConfig, client.dialPacket)
	}
	useHTTP2 := secure && (len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "http/1.1")
	return newDefaultDialerClient(config, secure, useHTTP2, func(ctx context.Context) (net.Conn, error) {
		var connectionConfig *tls.Config
		if tlsConfig != nil {
			connectionConfig = tlsConfig.Clone()
			if useHTTP2 {
				connectionConfig.NextProtos = []string{"h2"}
			} else {
				connectionConfig.NextProtos = []string{"http/1.1"}
			}
		}
		return client.dial(ctx, address, connectionConfig)
	})
}

func (client *Client) targetURL(config Config, address string, tlsConfig *tls.Config) string {
	return config.requestURL(address, tlsConfig).String()
}

// Close cancels the client's context and force-closes its pooled connections
// exactly once.
func (client *Client) Close() error {
	client.closeOnce.Do(func() {
		client.closed.Store(true)
		client.cancel()
		client.closeErr = client.manager.forceClose()
		if client.download != nil {
			client.closeErr = errors.Join(client.closeErr, client.download.forceClose())
		}
	})
	return client.closeErr
}

func (client *Client) String() string { return "xhttp:" + client.server }

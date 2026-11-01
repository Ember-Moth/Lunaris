// Derived from XTLS/Xray-core transport/internet/splithttp/client.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go/http3"
)

type dialerClient interface {
	xmuxConn
	openStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)
	postPacket(context.Context, string, string, string, []byte, func()) error
}

type defaultDialerClient struct {
	config     Config
	client     *http.Client
	transport  http.RoundTripper
	closed     atomic.Bool
	http2      bool
	upload     *h1ConnPool
	h1Buffers  *byteBufferPool
	dial       func(context.Context) (net.Conn, error)
	closeExtra func() error
}

func newDefaultDialerClient(
	config Config,
	secure, useHTTP2 bool,
	dial func(context.Context) (net.Conn, error),
) *defaultDialerClient {
	client := &defaultDialerClient{config: config, http2: useHTTP2, dial: dial}
	if useHTTP2 {
		protocols := new(http.Protocols)
		protocols.SetHTTP2(true)
		client.transport = &http.Transport{
			DialTLSContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
			DisableCompression: true,
			IdleConnTimeout:    connectionIdleTimeout,
			Protocols:          protocols,
			HTTP2: &http.HTTP2Config{
				SendPingTimeout: keepaliveDuration(config.XMUX.HKeepAlivePeriod),
			},
		}
	} else {
		client.upload = newH1ConnPool(max(1, config.ScMaxBufferedPosts))
		client.h1Buffers = newByteBufferPool(2 * (int(config.ScMaxEachPostBytes.To) + 64*1024))
		transport := &http.Transport{
			DisableKeepAlives: true, DisableCompression: true,
			IdleConnTimeout: connectionIdleTimeout,
		}
		if secure {
			transport.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }
		} else {
			transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }
		}
		client.transport = transport
	}
	client.client = &http.Client{Transport: client.transport}
	return client
}

func (client *defaultDialerClient) IsClosed() bool { return client.closed.Load() }

func (client *defaultDialerClient) openStream(
	ctx context.Context,
	target, sessionID string,
	body io.Reader,
	uploadOnly bool,
) (io.ReadCloser, net.Addr, net.Addr, error) {
	var remote, local net.Addr
	connected := make(chan error, 1)
	var connectedOnce sync.Once
	signalConnected := func(err error) { connectedOnce.Do(func() { connected <- err }) }
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		remote, local = info.Conn.RemoteAddr(), info.Conn.LocalAddr()
		signalConnected(nil)
	}}
	ctx = httptrace.WithClientTrace(ctx, trace)
	method := http.MethodGet
	if body != nil {
		method = client.config.UplinkHTTPMethod
	}
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, nil, nil, err
	}
	client.config.fillStreamRequest(request, sessionID)
	reader := newWaitReadCloser()
	go func() {
		response, requestErr := client.client.Do(request)
		if requestErr != nil {
			signalConnected(requestErr)
			if closer, ok := body.(io.Closer); ok {
				_ = closer.Close()
			}
			reader.fail(requestErr)
			return
		}
		signalConnected(nil)
		if response.StatusCode != http.StatusOK {
			statusErr := fmt.Errorf("xhttp: stream request rejected with HTTP status %d", response.StatusCode)
			_ = response.Body.Close()
			if closer, ok := body.(io.Closer); ok {
				_ = closer.Close()
			}
			reader.fail(statusErr)
			return
		}
		if uploadOnly {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if closer, ok := body.(io.Closer); ok {
				_ = closer.Close()
			}
			_ = reader.Close()
			return
		}
		reader.set(response.Body)
	}()
	if body == nil {
		select {
		case <-reader.ready:
			if err = reader.wait(); err != nil {
				return nil, nil, nil, err
			}
			return reader, remote, local, nil
		case <-ctx.Done():
			_ = reader.Close()
			return nil, nil, nil, ctx.Err()
		}
	}
	select {
	case connectErr := <-connected:
		if connectErr != nil {
			_ = reader.Close()
			return nil, nil, nil, connectErr
		}
		return reader, remote, local, nil
	case <-ctx.Done():
		_ = reader.Close()
		return nil, nil, nil, ctx.Err()
	}
}

func (client *defaultDialerClient) postPacket(
	ctx context.Context,
	target, sessionID, sequence string,
	payload []byte,
	onWritten func(),
) error {
	var written sync.Once
	markWritten := func() { written.Do(onWritten) }
	defer markWritten()
	ctx = httptrace.WithClientTrace(
		ctx,
		&httptrace.ClientTrace{WroteRequest: func(httptrace.WroteRequestInfo) { markWritten() }},
	)
	request, err := http.NewRequestWithContext(ctx, client.config.UplinkHTTPMethod, target, nil)
	if err != nil {
		return err
	}
	client.config.fillPacketRequest(request, sessionID, sequence, payload)
	if client.http2 {
		response, err := client.client.Do(request)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return errors.New("xhttp: packet upload rejected")
		}
		return nil
	}
	return client.postPacketH1(ctx, request, markWritten)
}

func (client *defaultDialerClient) postPacketH1(ctx context.Context, request *http.Request, onWritten func()) error {
	owner := client.h1Buffers.take(0)
	encoded := bytes.NewBuffer(owner.data)
	defer func() {
		owner.data = encoded.Bytes()
		client.h1Buffers.put(owner)
	}()
	encoded.Grow(512 + int(request.ContentLength))
	if err := request.Write(encoded); err != nil {
		return err
	}
	for {
		conn := client.upload.Get()
		fresh := conn == nil
		if fresh {
			raw, err := client.dial(ctx)
			if err != nil {
				return err
			}
			conn = &h1Conn{Conn: raw, reader: bufio.NewReader(raw)}
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		stopContext := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
		discard := func() { stopContext(); _ = conn.Close() }
		if _, err := conn.Write(encoded.Bytes()); err != nil {
			discard()
			if fresh {
				return err
			}
			continue
		}
		onWritten()
		response, err := http.ReadResponse(conn.reader, request)
		if err != nil {
			discard()
			return err
		}
		_, copyErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if copyErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
			discard()
			if response.StatusCode != http.StatusOK {
				return errors.New("xhttp: packet upload rejected")
			}
			return errors.Join(copyErr, closeErr)
		}
		if stopContext() && ctx.Err() == nil {
			_ = conn.SetDeadline(time.Time{})
			client.upload.Put(conn)
		} else {
			_ = conn.Close()
		}
		return nil
	}
}

func (client *defaultDialerClient) Close() error {
	client.closed.Store(true)
	var result error
	if client.upload != nil {
		result = client.upload.Close()
	}
	switch transport := client.transport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
	case *http3.Transport:
		result = errors.Join(result, transport.Close())
	}
	if client.closeExtra != nil {
		result = errors.Join(result, client.closeExtra())
	}
	return result
}

type h1Conn struct {
	net.Conn
	reader *bufio.Reader
}

func keepaliveDuration(seconds int64) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

const connectionIdleTimeout = 300 * time.Second

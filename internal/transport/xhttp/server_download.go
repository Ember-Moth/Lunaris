// Derived from XTLS/Xray-core transport/internet/splithttp/hub.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"context"
	"io"
	"net"
	"net/http"

	M "github.com/sagernet/sing/common/metadata"
)

func (server *Server) serveDownload(
	writer http.ResponseWriter,
	request *http.Request,
	sessionID string,
	session *serverSession,
) {
	if sessionID != "" {
		if !session.attachDownload() {
			writer.WriteHeader(http.StatusConflict)
			return
		}
		defer func() { _ = server.removeSession(sessionID, session) }()
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.Header().Set("Cache-Control", "no-store")
	if !server.config.NoSSEHeader {
		writer.Header().Set("Content-Type", "text/event-stream")
	}
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	body := request.Body
	var failed <-chan struct{}
	if request.ProtoMajor == 1 && sessionID == "" {
		watched := watchBody(body)
		body = watched
		failed = watched.failed
	}
	stream := newServerStream(body, flushWriter{ResponseWriter: writer, Flusher: flusher})
	reader := io.ReadCloser(stream)
	if session != nil {
		reader = session.upload
	}
	remote := remoteAddress(request)
	flowContext, local := server.requestFlow(request)
	flowContext, cancel := context.WithCancel(flowContext)
	conn := &splitConn{cancel: cancel, writer: stream, reader: reader, remoteAddr: remote, localAddr: local}
	done := make(chan struct{})
	server.handler.NewConnectionEx(
		flowContext,
		conn,
		sourceAddress(request),
		M.Socksaddr{},
		func(error) { closeOnce(done); _ = conn.Close() },
	)
	select {
	case <-done:
	case <-failed:
	case <-request.Context().Done():
	case <-stream.wait():
	case <-server.closed:
	}
	_ = conn.Close()
}

func remoteAddress(request *http.Request) net.Addr {
	address, err := net.ResolveTCPAddr("tcp", request.RemoteAddr)
	if err == nil {
		if request.ProtoMajor == 3 {
			return &net.UDPAddr{IP: address.IP, Port: address.Port, Zone: address.Zone}
		}
		return address
	}
	return &net.TCPAddr{}
}

func closeOnce(channel chan struct{}) {
	defer func() { _ = recover() }()
	close(channel)
}

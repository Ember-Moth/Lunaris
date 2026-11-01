// Derived from XTLS/Xray-core transport/internet/splithttp/hub.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Server accepts XHTTP sessions over HTTP/1.1, HTTP/2 or HTTP/3 and hands each
// to the connection handler.
type Server struct {
	ctx          context.Context
	cancel       context.CancelFunc
	lifecycle    sync.Mutex
	closing      bool
	requests     sync.WaitGroup
	config       Config
	tlsConfig    *tls.Config
	handler      N.TCPConnectionHandlerEx
	http         *http.Server
	sessions     sync.Map
	closed       chan struct{}
	closeOnce    sync.Once
	localAddr    net.Addr
	h3           h3ServerState
	payloads     *byteBufferPool
	uploadBudget *byteBudget
	sessionSlots chan struct{}
	requestSlots chan struct{}
}

type serverSession struct {
	upload           *uploadQueue
	mu               sync.Mutex
	timer            *time.Timer
	connected        bool
	downloadAttached bool
	closed           bool
	closeOnce        sync.Once
	closeErr         error
}

const (
	defaultMaxActiveSessions     = 16_384
	maximumActiveSessions        = 1 << 20
	defaultMaxConcurrentRequests = 16_384
	maximumConcurrentRequests    = 1 << 20
	maxSessionIDBytes            = 4096
	uploadSessionTTL             = 30 * time.Second
)

var errSessionLimit = errors.New("xhttp: active session limit reached")

// NewServer builds the HTTP server and session table for the configured mode.
func NewServer(ctx context.Context, config Config, tlsConfig *tls.Config, handler N.TCPConnectionHandlerEx) *Server {
	ctx, cancel := context.WithCancel(ctx)
	maxPayload := int(config.ScMaxEachPostBytes.To)
	maxSessions := config.ScMaxActiveSessions
	if maxSessions <= 0 {
		maxSessions = defaultMaxActiveSessions
	}
	maxSessions = min(maxSessions, maximumActiveSessions)
	maxRequests := config.ScMaxConcurrentRequests
	if maxRequests <= 0 {
		maxRequests = defaultMaxConcurrentRequests
	}
	maxRequests = min(maxRequests, maximumConcurrentRequests)
	server := &Server{
		ctx: ctx, cancel: cancel, config: config, tlsConfig: tlsConfig, handler: handler, closed: make(chan struct{}),
		payloads:     newByteBufferPool(2 * maxPayload),
		uploadBudget: newByteBudget(config.ScMaxTotalBufferedBytes, int64(maxPayload)),
		sessionSlots: make(chan struct{}, maxSessions),
		requestSlots: make(chan struct{}, maxRequests),
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	server.http = &http.Server{
		Handler: server, ReadHeaderTimeout: 4 * time.Second, MaxHeaderBytes: config.ServerMaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context { return ctx }, Protocols: protocols,
		HTTP2: &http.HTTP2Config{
			MaxReadFrameSize:              httpRelayMTU,
			MaxReceiveBufferPerConnection: 1 << 20,
			MaxReceiveBufferPerStream:     1 << 20,
		},
	}
	return server
}

// Serve accepts connections on the listener, terminating TLS when configured,
// until the listener closes.
func (server *Server) Serve(listener net.Listener) error {
	server.localAddr = listener.Addr()
	if isHTTP3(server.tlsConfig) {
		return server.serveH3(listener)
	}
	if server.tlsConfig != nil {
		config := server.tlsConfig.Clone()
		config.NextProtos = []string{"h2", "http/1.1"}
		listener = tls.NewListener(listener, config)
	}
	err := server.http.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// PacketBased reports whether the configuration selects HTTP/3 and therefore a
// UDP socket.
func (server *Server) PacketBased() bool { return isHTTP3(server.tlsConfig) }

// Close removes every session and stops the HTTP and HTTP/3 servers.
func (server *Server) Close() error {
	server.closeOnce.Do(func() {
		server.lifecycle.Lock()
		server.closing = true
		close(server.closed)
		server.lifecycle.Unlock()
		server.cancel()
		server.sessions.Range(func(key, value any) bool {
			_ = server.removeSession(key.(string), value.(*serverSession))
			return true
		})
	})
	err := errors.Join(server.http.Close(), server.closeH3())
	server.requests.Wait()
	return err
}

func (server *Server) session(id string) (*serverSession, error) {
	for {
		select {
		case <-server.closed:
			return nil, net.ErrClosed
		default:
		}
		if current, loaded := server.sessions.Load(id); loaded {
			session := current.(*serverSession)
			if !session.isClosed() {
				return session, nil
			}
			_ = server.removeSession(id, session)
			continue
		}
		select {
		case server.sessionSlots <- struct{}{}:
		default:
			if current, loaded := server.sessions.Load(id); loaded && !current.(*serverSession).isClosed() {
				return current.(*serverSession), nil
			}
			return nil, errSessionLimit
		}
		candidate := &serverSession{upload: newUploadQueue(
			server.config.ScMaxBufferedPosts, int(server.config.ScMaxEachPostBytes.To),
			server.config.ScMaxBufferedBytes, server.uploadBudget, server.payloads,
		)}
		current, loaded := server.sessions.LoadOrStore(id, candidate)
		if loaded {
			<-server.sessionSlots
			_ = candidate.close()
			session := current.(*serverSession)
			if !session.isClosed() {
				return session, nil
			}
			continue
		}
		select {
		case <-server.closed:
			_ = server.removeSession(id, candidate)
			return nil, net.ErrClosed
		default:
		}
		timeout := server.config.PendingTimeout
		if timeout <= 0 {
			timeout = uploadSessionTTL
		}
		candidate.setTimer(time.AfterFunc(timeout, func() {
			if candidate.expire() {
				_ = server.removeSession(id, candidate)
			}
		}))
		return candidate, nil
	}
}

func (server *Server) removeSession(id string, session *serverSession) error {
	if server.sessions.CompareAndDelete(id, session) {
		<-server.sessionSlots
	}
	return session.close()
}

func (session *serverSession) attachDownload() bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.downloadAttached {
		return false
	}
	session.downloadAttached = true
	session.connected = true
	if session.timer != nil {
		session.timer.Stop()
		session.timer = nil
	}
	return true
}

func (session *serverSession) close() error {
	session.mu.Lock()
	session.closed = true
	if session.timer != nil {
		session.timer.Stop()
		session.timer = nil
	}
	session.mu.Unlock()
	session.closeOnce.Do(func() { session.closeErr = session.upload.Close() })
	return session.closeErr
}

func (session *serverSession) setTimer(timer *time.Timer) {
	session.mu.Lock()
	if session.connected || session.closed {
		timer.Stop()
	} else {
		session.timer = timer
	}
	session.mu.Unlock()
}

func (session *serverSession) expire() bool {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.connected || session.closed {
		return false
	}
	session.closed = true
	session.timer = nil
	return true
}

func (session *serverSession) isClosed() bool {
	session.mu.Lock()
	closed := session.closed
	session.mu.Unlock()
	return closed
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.lifecycle.Lock()
	if server.closing {
		server.lifecycle.Unlock()
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	server.requests.Add(1)
	server.lifecycle.Unlock()
	defer server.requests.Done()
	// Close must interrupt bodies and blocked flow-control writes before joining
	// handlers; no response writer may be used after its ServeHTTP returns.
	cancelled := make(chan struct{})
	stop := context.AfterFunc(server.ctx, func() {
		defer close(cancelled)
		controller := http.NewResponseController(writer)
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
		if request.Body != nil {
			_ = request.Body.Close()
		}
	})
	defer func() {
		if !stop() {
			<-cancelled
		}
	}()

	if request.ProtoMajor == 1 {
		_ = http.NewResponseController(writer).EnableFullDuplex()
	}
	if !server.match(request) {
		http.NotFound(writer, request)
		return
	}
	server.writeResponseHeaders(writer, request)
	if request.Method == http.MethodOptions {
		writer.WriteHeader(http.StatusOK)
		return
	}
	if !server.config.validPadding(server.config.requestPadding(request)) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionID, sequence := server.config.extractMeta(request)
	if len(sessionID) > maxSessionIDBytes || len(sequence) > 20 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	if sessionID == "" && !oneOf(server.config.Mode, ModeAuto, ModeStreamOne, ModeStreamUp) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	var parsedSequence uint64
	if sequence != "" {
		var err error
		parsedSequence, err = strconv.ParseUint(sequence, 10, 64)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	isUpload := request.Method != http.MethodGet || sequence != ""
	if isUpload && sessionID != "" {
		if sequence == "" && !oneOf(server.config.Mode, ModeAuto, ModeStreamUp) ||
			sequence != "" && !oneOf(server.config.Mode, ModeAuto, ModePacketUp) {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	if isUpload || sessionID == "" {
		select {
		case server.requestSlots <- struct{}{}:
			defer func() { <-server.requestSlots }()
		default:
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	var session *serverSession
	if sessionID != "" {
		var err error
		session, err = server.session(sessionID)
		if err != nil {
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	if isUpload && sessionID != "" {
		server.serveUpload(writer, request, session, sequence, parsedSequence)
		return
	}
	if request.Method == http.MethodGet || sessionID == "" {
		server.serveDownload(writer, request, sessionID, session)
		return
	}
	writer.WriteHeader(http.StatusMethodNotAllowed)
}

func (server *Server) match(request *http.Request) bool {
	if !strings.HasPrefix(request.URL.Path, server.config.normalizedPath()) {
		return false
	}
	if server.config.Host == "" {
		return true
	}
	host := request.Host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.EqualFold(host, server.config.Host)
}

func (server *Server) writeResponseHeaders(writer http.ResponseWriter, request *http.Request) {
	origin := request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	writer.Header().Set("Access-Control-Allow-Origin", origin)
	if oneOf(server.config.SessionIDPlacement, PlacementCookie) || oneOf(server.config.SeqPlacement, PlacementCookie) ||
		server.config.XPaddingPlacement == PlacementCookie || server.config.UplinkDataPlacement == PlacementCookie {
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	if request.Method == http.MethodOptions {
		methods := request.Header.Get("Access-Control-Request-Method")
		if methods == "" {
			methods = "*"
		}
		headers := request.Header.Get("Access-Control-Request-Headers")
		if headers == "" {
			headers = "*"
		}
		writer.Header().Set("Access-Control-Allow-Methods", methods)
		writer.Header().Set("Access-Control-Allow-Headers", headers)
	}
	server.config.applyPaddingResponse(writer)
}

func sourceAddress(request *http.Request) M.Socksaddr {
	// Lunaris has no trusted-proxy configuration: peer headers cannot replace
	// the source address used by protocol authentication and accounting.
	return M.ParseSocksaddr(request.RemoteAddr).Unwrap()
}

func (server *Server) requestFlow(request *http.Request) (context.Context, net.Addr) {
	local := server.localAddr
	if value, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		local = value
	}
	if local == nil {
		local = M.Socksaddr{}
	}
	return server.ctx, local
}

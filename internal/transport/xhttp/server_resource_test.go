// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServerLimitsActiveSessionsAndDeletesByIdentity(t *testing.T) {
	config := Config{
		ScMaxEachPostBytes:      Range{From: 4, To: 4},
		ScMaxBufferedPosts:      1,
		ScMaxBufferedBytes:      8,
		ScMaxTotalBufferedBytes: 8,
		ScMaxActiveSessions:     1,
		ScMaxConcurrentRequests: 1,
	}
	server := NewServer(context.Background(), config, nil, nil)
	t.Cleanup(func() { _ = server.Close() })
	server.requestSlots <- struct{}{}
	select {
	case server.requestSlots <- struct{}{}:
		t.Fatal("concurrent request limit admitted an extra handler")
	default:
	}
	<-server.requestSlots

	first, err := server.session("same")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.session("other"); !errors.Is(err, errSessionLimit) {
		t.Fatalf("second session error = %v, want active-session limit", err)
	}
	if !first.attachDownload() {
		t.Fatal("first download was rejected")
	}
	if first.attachDownload() {
		t.Fatal("duplicate download was accepted")
	}
	if first.expire() {
		t.Fatal("connected session expired")
	}
	if err = server.removeSession("same", first); err != nil {
		t.Fatal(err)
	}

	replacement, err := server.session("same")
	if err != nil {
		t.Fatal(err)
	}
	// A stale handler must not delete a replacement that reused the same ID.
	if err = server.removeSession("same", first); err != nil {
		t.Fatal(err)
	}
	loaded, ok := server.sessions.Load("same")
	if !ok || loaded != replacement {
		t.Fatal("stale session cleanup deleted its replacement")
	}
}

func TestServerRejectsUploadBeforeCreatingSessionAtRequestLimit(t *testing.T) {
	config, err := Parse("", "/x", ModePacketUp, `{
		"xPaddingBytes":100,"scMaxEachPostBytes":4,"scMaxConcurrentRequests":1
	}`)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(context.Background(), config, nil, nil)
	t.Cleanup(func() { _ = server.Close() })
	server.requestSlots <- struct{}{}
	request := httptest.NewRequest(http.MethodPost, "/x/session/0?x_padding="+strings.Repeat("X", 100), strings.NewReader("x"))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	<-server.requestSlots
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if _, loaded := server.sessions.Load("session"); loaded {
		t.Fatal("request rejected by the concurrency limit created a session")
	}
}

type observedReader struct {
	once sync.Once
	read chan struct{}
	data *bytes.Reader
}

func (reader *observedReader) Read(output []byte) (int, error) {
	reader.once.Do(func() { close(reader.read) })
	return reader.data.Read(output)
}

func TestPacketBodyWaitsForBudgetBeforeReading(t *testing.T) {
	budget := newByteBudget(8, 4)
	pool := newByteBufferPool(8)
	first := newUploadQueue(4, 4, 8, budget, pool)
	second := newUploadQueue(4, 4, 8, budget, pool)
	t.Cleanup(func() { _ = first.Close(); _ = second.Close() })
	if err := first.push(context.Background(), uploadPacket{payload: []byte("hold"), sequence: 1}); err != nil {
		t.Fatal(err)
	}

	reader := &observedReader{read: make(chan struct{}), data: bytes.NewReader([]byte("data"))}
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.test", io.NopCloser(reader))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = 4
	server := &Server{config: Config{UplinkDataPlacement: PlacementBody, ScMaxEachPostBytes: Range{From: 4, To: 4}}}
	result := make(chan error, 1)
	go func() {
		_, readErr := server.readPacketPayload(request, second, 1)
		result <- readErr
	}()

	select {
	case <-reader.read:
		t.Fatal("request body was read before shared buffer space was reserved")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err = <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("readPacketPayload error = %v, want context canceled", err)
	}
	if used := budget.Used(); used != 4 {
		t.Fatalf("budget after canceled waiter = %d, want 4", used)
	}
}

func TestUnknownPacketBodyShrinksReservation(t *testing.T) {
	budget := newByteBudget(8, 4)
	queue := newUploadQueue(4, 4, 8, budget, newByteBufferPool(8))
	t.Cleanup(func() { _ = queue.Close() })
	request, err := http.NewRequest(http.MethodPost, "http://example.test", io.NopCloser(bytes.NewReader([]byte("abc"))))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = -1
	server := &Server{config: Config{UplinkDataPlacement: PlacementBody, ScMaxEachPostBytes: Range{From: 4, To: 4}}}
	packet, err := server.readPacketPayload(request, queue, 0)
	if err != nil {
		t.Fatal(err)
	}
	if packet.reserved != 3 || budget.Used() != 3 {
		t.Fatalf("reservation = %d, budget = %d, want 3", packet.reserved, budget.Used())
	}
	if err = queue.push(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	output := make([]byte, 3)
	if _, err = io.ReadFull(queue, output); err != nil {
		t.Fatal(err)
	}
	if string(output) != "abc" || budget.Used() != 0 {
		t.Fatalf("payload = %q, remaining budget = %d", output, budget.Used())
	}
}

type abortableResponse struct {
	entered chan struct{}
	aborted chan struct{}
	once    sync.Once
}

func (w *abortableResponse) Write([]byte) (int, error) {
	close(w.entered)
	<-w.aborted
	return 0, io.ErrClosedPipe
}
func (*abortableResponse) Flush()   {}
func (w *abortableResponse) Abort() { w.once.Do(func() { close(w.aborted) }) }
func TestServerStreamCloseInterruptsBlockedWriter(t *testing.T) {
	writer := &abortableResponse{entered: make(chan struct{}), aborted: make(chan struct{})}
	stream := newServerStream(strings.NewReader(""), writer)
	wrote := make(chan struct{})
	go func() { defer close(wrote); _, _ = stream.Write([]byte("blocked")) }()
	<-writer.entered
	done := make(chan struct{})
	go func() { stream.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close waited for flow-control blocked write")
	}
	<-wrote
	if _, err := stream.Write([]byte("after handler")); err == nil {
		t.Fatal("response writer remained usable after Close")
	}
}

type observedBody struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (b *observedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	return b.ReadCloser.Read(p)
}
func TestServerCloseInterruptsPartialUploadBody(t *testing.T) {
	cfg, err := Parse("", "/x", ModePacketUp, `{"xPaddingBytes":100,"scMaxEachPostBytes":64}`)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(context.Background(), cfg, nil, echoHandler{})
	reader, writer := io.Pipe()
	defer writer.Close()
	body := &observedBody{ReadCloser: reader, started: make(chan struct{})}
	request := httptest.NewRequest(http.MethodPost, "/x/session/0?x_padding="+strings.Repeat("X", 100), body)
	request.ContentLength = 64
	done := make(chan struct{})
	go func() { server.ServeHTTP(httptest.NewRecorder(), request); close(done) }()
	<-body.started
	closed := make(chan struct{})
	go func() { server.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("partial packet upload blocked Close")
	}
	<-done
	if used := server.uploadBudget.Used(); used != 0 {
		t.Fatalf("upload reservation leaked: %d", used)
	}
}

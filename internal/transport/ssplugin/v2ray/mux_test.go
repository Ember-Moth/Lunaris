// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from Polaris; see THIRD_PARTY_NOTICES.md.
package v2ray

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type blockingService struct {
	started chan struct{}
	once    sync.Once
}

func (service *blockingService) NewConnection(ctx context.Context, _ net.Conn, _ M.Metadata) error {
	service.once.Do(func() { close(service.started) })
	<-ctx.Done()
	return ctx.Err()
}

type returnService struct{}

func (returnService) NewConnection(context.Context, net.Conn, M.Metadata) error { return nil }

type writeCountingConn struct {
	bytes.Buffer
	writes int
}

func (*writeCountingConn) Read([]byte) (int, error) { return 0, io.EOF }
func (conn *writeCountingConn) Write(payload []byte) (int, error) {
	conn.writes++
	return conn.Buffer.Write(payload)
}
func (*writeCountingConn) Close() error                     { return nil }
func (*writeCountingConn) LocalAddr() net.Addr              { return nil }
func (*writeCountingConn) RemoteAddr() net.Addr             { return nil }
func (*writeCountingConn) SetDeadline(time.Time) error      { return nil }
func (*writeCountingConn) SetReadDeadline(time.Time) error  { return nil }
func (*writeCountingConn) SetWriteDeadline(time.Time) error { return nil }

type echoService struct{}

type deadlineTrackingConn struct {
	net.Conn
	cleared chan struct{}
	once    sync.Once
}

func (conn *deadlineTrackingConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		conn.once.Do(func() { close(conn.cleared) })
	}
	return conn.Conn.SetReadDeadline(deadline)
}

func (echoService) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	defer func() { _ = conn.Close() }()
	payload := make([]byte, 4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	_, err := conn.Write([]byte(strings.ToUpper(string(payload))))
	return err
}

func TestServiceMultiplexesV2RaySessions(t *testing.T) {
	serverRaw, client := net.Pipe()
	if err := serverRaw.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	tracked := &deadlineTrackingConn{Conn: serverRaw, cleared: make(chan struct{})}
	service := NewService(Config{Mux: true}, echoService{}, nil)
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(context.Background(), tracked, M.Metadata{}) }()
	select {
	case <-tracked.cleared:
	case <-time.After(time.Second):
		t.Fatal("service did not clear the carrier read deadline")
	}

	for id, input := range map[uint16]string{1: "ping", 2: "pong"} {
		if err := writeNewFrame(client, id); err != nil {
			t.Fatal(err)
		}
		if err := writeDataFrame(client, id, []byte(input)); err != nil {
			t.Fatal(err)
		}
	}
	responses := make(map[uint16]string, 2)
	for len(responses) < 2 {
		id, payload, err := readDataFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		if payload != nil {
			responses[id] = string(payload)
		}
	}
	if responses[1] != "PING" || responses[2] != "PONG" {
		t.Fatalf("responses = %#v", responses)
	}
	_ = client.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}

func TestServiceLimitsV2RaySessions(t *testing.T) {
	serverRaw, client := net.Pipe()
	blocking := &blockingService{started: make(chan struct{})}
	service := NewService(Config{Mux: true, MaxSessions: 1, MaxActiveStreams: 1}, blocking, nil)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(ctx, serverRaw, M.Metadata{}) }()
	if err := writeNewFrame(client, 1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("first virtual session did not start")
	}
	if err := writeNewFrame(client, 2); err != nil {
		t.Fatal(err)
	}
	id, status, err := readControlFrame(client)
	if err != nil || id != 2 || status != statusEnd {
		t.Fatalf("limit response = id %d status %d error %v", id, status, err)
	}
	cancel()
	_ = client.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}

func TestServiceBoundsV2RayQueuedBytes(t *testing.T) {
	serverRaw, client := net.Pipe()
	blocking := &blockingService{started: make(chan struct{})}
	service := NewService(Config{
		Mux: true, MaxSessions: 1, MaxActiveStreams: 1,
		MaxSessionQueuedBytes: 4, MaxQueuedBytes: 16,
	}, blocking, nil)
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(context.Background(), serverRaw, M.Metadata{}) }()
	if err := writeNewFrame(client, 1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("virtual session did not start")
	}
	if err := writeDataFrame(client, 1, []byte("too-large")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, errQueueLimit) {
			t.Fatalf("service error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("service did not enforce queue limit")
	}
	_ = client.Close()
}

func TestServiceClosesV2RaySessionAfterCleanReturn(t *testing.T) {
	serverRaw, client := net.Pipe()
	service := NewService(Config{Mux: true}, returnService{}, nil)
	result := make(chan error, 1)
	go func() { result <- service.NewConnection(context.Background(), serverRaw, M.Metadata{}) }()
	if err := writeNewFrame(client, 7); err != nil {
		t.Fatal(err)
	}
	id, status, err := readControlFrame(client)
	if err != nil || id != 7 || status != statusEnd {
		t.Fatalf("close response = id %d status %d error %v", id, status, err)
	}
	_ = client.Close()
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("service did not stop")
	}
}

func TestMuxWriteDataUsesSingleCarrierWrite(t *testing.T) {
	carrier := &writeCountingConn{}
	server := &muxServer{conn: carrier}
	frame := make([]byte, 8+len("payload"))
	copy(frame[8:], "payload")
	if err := server.writeData(7, frame[:8], frame); err != nil {
		t.Fatal(err)
	}
	if carrier.writes != 1 {
		t.Fatalf("carrier writes = %d, want 1", carrier.writes)
	}
	if !bytes.Equal(carrier.Bytes(), frame) {
		t.Fatalf("carrier frame = %x, want %x", carrier.Bytes(), frame)
	}
}

func writeNewFrame(conn net.Conn, id uint16) error {
	frame := []byte{
		0, 12, byte(id >> 8), byte(id), statusNew, 0,
		0x01, 0, 0, 0x01, 127, 0, 0, 1,
	}
	return writeAll(conn, frame)
}

func writeDataFrame(conn net.Conn, id uint16, payload []byte) error {
	frame := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], 4)
	binary.BigEndian.PutUint16(frame[2:4], id)
	frame[4], frame[5] = statusKeep, optionData
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)
	return writeAll(conn, frame)
}

func readDataFrame(conn net.Conn) (uint16, []byte, error) {
	for {
		var lengthBytes [2]byte
		if _, err := io.ReadFull(conn, lengthBytes[:]); err != nil {
			return 0, nil, err
		}
		metadataLength := int(binary.BigEndian.Uint16(lengthBytes[:]))
		metadata := make([]byte, metadataLength)
		if _, err := io.ReadFull(conn, metadata); err != nil {
			return 0, nil, err
		}
		id := binary.BigEndian.Uint16(metadata[:2])
		if metadata[3]&optionData == 0 {
			continue
		}
		if _, err := io.ReadFull(conn, lengthBytes[:]); err != nil {
			return 0, nil, err
		}
		payload := make([]byte, binary.BigEndian.Uint16(lengthBytes[:]))
		_, err := io.ReadFull(conn, payload)
		return id, payload, err
	}
}

func readControlFrame(conn net.Conn) (uint16, byte, error) {
	var lengthBytes [2]byte
	if _, err := io.ReadFull(conn, lengthBytes[:]); err != nil {
		return 0, 0, err
	}
	metadataLength := int(binary.BigEndian.Uint16(lengthBytes[:]))
	metadata := make([]byte, metadataLength)
	if _, err := io.ReadFull(conn, metadata); err != nil {
		return 0, 0, err
	}
	if len(metadata) < 3 {
		return 0, 0, errInvalidFrame
	}
	return binary.BigEndian.Uint16(metadata[:2]), metadata[2], nil
}

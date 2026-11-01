// Derived from XTLS/Xray-core transport/internet/splithttp/connection.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const httpRelayMTU = 16 << 10

type splitConn struct {
	writer      io.WriteCloser
	reader      io.ReadCloser
	remoteAddr  net.Addr
	localAddr   net.Addr
	cancel      func()
	onClose     func()
	once        sync.Once
	closed      atomic.Bool
	deadlineMu  sync.Mutex
	readTimer   *time.Timer
	writeTimer  *time.Timer
	readAt      time.Time
	writeAt     time.Time
	readGen     uint64
	writeGen    uint64
	readExpiry  atomic.Bool
	writeExpiry atomic.Bool
}

func (conn *splitConn) Write(payload []byte) (int, error) {
	if conn.writeExpiry.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := conn.writer.Write(payload)
	if err != nil && conn.writeExpiry.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (conn *splitConn) Read(payload []byte) (int, error) {
	if conn.readExpiry.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := conn.reader.Read(payload)
	if err != nil && conn.readExpiry.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (conn *splitConn) Close() error {
	var err error
	conn.once.Do(func() {
		conn.closed.Store(true)
		conn.stopDeadlineTimers()
		if conn.cancel != nil {
			conn.cancel()
		}
		if conn.onClose != nil {
			conn.onClose()
		}
		err = errors.Join(conn.writer.Close(), conn.reader.Close())
	})
	return err
}

func (conn *splitConn) LocalAddr() net.Addr  { return conn.localAddr }
func (conn *splitConn) RemoteAddr() net.Addr { return conn.remoteAddr }
func (conn *splitConn) ReaderMTU() int       { return httpRelayMTU }
func (conn *splitConn) WriterMTU() int       { return httpRelayMTU }
func (conn *splitConn) SetDeadline(deadline time.Time) error {
	return conn.setDeadlines(deadline, true, true)
}

func (conn *splitConn) SetReadDeadline(deadline time.Time) error {
	return conn.setDeadlines(deadline, true, false)
}

func (conn *splitConn) SetWriteDeadline(deadline time.Time) error {
	return conn.setDeadlines(deadline, false, true)
}

func (conn *splitConn) setDeadlines(deadline time.Time, read, write bool) error {
	conn.deadlineMu.Lock()
	if conn.closed.Load() {
		conn.deadlineMu.Unlock()
		return net.ErrClosed
	}
	if read {
		conn.readGen++
		if conn.readTimer != nil {
			conn.readTimer.Stop()
			conn.readTimer = nil
		}
		conn.readAt = deadline
		conn.readExpiry.Store(false)
		if !deadline.IsZero() {
			generation := conn.readGen
			conn.readTimer = time.AfterFunc(
				max(time.Until(deadline), 0),
				func() { conn.expireDeadline(true, generation) },
			)
		}
	}
	if write {
		conn.writeGen++
		if conn.writeTimer != nil {
			conn.writeTimer.Stop()
			conn.writeTimer = nil
		}
		conn.writeAt = deadline
		conn.writeExpiry.Store(false)
		if !deadline.IsZero() {
			generation := conn.writeGen
			conn.writeTimer = time.AfterFunc(
				max(time.Until(deadline), 0),
				func() { conn.expireDeadline(false, generation) },
			)
		}
	}
	conn.deadlineMu.Unlock()
	return nil
}

func (conn *splitConn) expireDeadline(read bool, generation uint64) {
	conn.deadlineMu.Lock()
	if conn.closed.Load() || read && generation != conn.readGen || !read && generation != conn.writeGen {
		conn.deadlineMu.Unlock()
		return
	}
	now := time.Now()
	if !conn.readAt.IsZero() && !now.Before(conn.readAt) {
		conn.readExpiry.Store(true)
	}
	if !conn.writeAt.IsZero() && !now.Before(conn.writeAt) {
		conn.writeExpiry.Store(true)
	}
	conn.deadlineMu.Unlock()
	_ = conn.Close()
}

func (conn *splitConn) stopDeadlineTimers() {
	conn.deadlineMu.Lock()
	conn.readGen++
	conn.writeGen++
	if conn.readTimer != nil {
		conn.readTimer.Stop()
		conn.readTimer = nil
	}
	if conn.writeTimer != nil {
		conn.writeTimer.Stop()
		conn.writeTimer = nil
	}
	conn.deadlineMu.Unlock()
}

type waitReadCloser struct {
	ready  chan struct{}
	once   sync.Once
	mu     sync.Mutex
	inner  io.ReadCloser
	err    error
	closed bool
}

func newWaitReadCloser() *waitReadCloser { return &waitReadCloser{ready: make(chan struct{})} }

func (reader *waitReadCloser) set(inner io.ReadCloser) {
	reader.mu.Lock()
	if reader.closed {
		reader.mu.Unlock()
		_ = inner.Close()
		reader.once.Do(func() { close(reader.ready) })
		return
	}
	reader.inner = inner
	reader.mu.Unlock()
	reader.once.Do(func() { close(reader.ready) })
}

func (reader *waitReadCloser) fail(err error) {
	reader.mu.Lock()
	if reader.inner == nil && reader.err == nil {
		reader.err = err
	}
	reader.mu.Unlock()
	reader.once.Do(func() { close(reader.ready) })
}

func (reader *waitReadCloser) wait() error {
	<-reader.ready
	reader.mu.Lock()
	err := reader.err
	reader.mu.Unlock()
	return err
}

func (reader *waitReadCloser) Read(payload []byte) (int, error) {
	<-reader.ready
	reader.mu.Lock()
	inner, err := reader.inner, reader.err
	reader.mu.Unlock()
	if inner == nil {
		if err != nil {
			return 0, err
		}
		return 0, io.ErrClosedPipe
	}
	return inner.Read(payload)
}

func (reader *waitReadCloser) Close() error {
	reader.mu.Lock()
	reader.closed = true
	inner := reader.inner
	reader.mu.Unlock()
	reader.once.Do(func() { close(reader.ready) })
	if inner != nil {
		return inner.Close()
	}
	return nil
}

type serverStream struct {
	readMu sync.Mutex
	closed atomic.Bool
	mu     sync.Mutex
	done   chan struct{}
	once   sync.Once
	reader io.Reader
	writer httpResponseWriter
}

type httpResponseWriter interface {
	Write([]byte) (int, error)
	Flush()
}

func newServerStream(reader io.Reader, writer httpResponseWriter) *serverStream {
	return &serverStream{done: make(chan struct{}), reader: reader, writer: writer}
}

func (stream *serverStream) Read(payload []byte) (int, error) {
	stream.readMu.Lock()
	defer stream.readMu.Unlock()
	if stream.closed.Load() {
		return 0, net.ErrClosed
	}
	return stream.reader.Read(payload)
}

func (stream *serverStream) Write(payload []byte) (int, error) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	select {
	case <-stream.done:
		return 0, io.ErrClosedPipe
	default:
	}
	n, err := stream.writer.Write(payload)
	if err == nil {
		stream.writer.Flush()
	}
	return n, err
}

func (stream *serverStream) Close() error {
	stream.once.Do(func() {
		stream.closed.Store(true)
		if abort, ok := stream.writer.(interface{ Abort() }); ok {
			abort.Abort()
		}
		if closer, ok := stream.reader.(io.Closer); ok {
			_ = closer.Close()
		}
		stream.mu.Lock()
		defer stream.mu.Unlock()
		stream.readMu.Lock()
		defer stream.readMu.Unlock()
		close(stream.done)
	})
	return nil
}

func (stream *serverStream) wait() <-chan struct{} { return stream.done }

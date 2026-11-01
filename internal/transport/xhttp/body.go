// SPDX-License-Identifier: GPL-3.0-only
package xhttp

import (
	"errors"
	"io"
	"net"
	"sync"
)

// A full-duplex HTTP/1 request has no independent reset signal while its body
// is idle. Read ahead by at most two relay chunks so a truncated body cancels
// a pending protocol/egress operation even when that operation is not reading.
// Clean EOF remains a read result; it does not abort the download direction.
type watchedBody struct {
	body         io.ReadCloser
	packets      chan bodyPacket
	failed       chan struct{}
	done, exited chan struct{}
	once         sync.Once
	current      []byte
	currentErr   error
}
type bodyPacket struct {
	data []byte
	err  error
}

func watchBody(body io.ReadCloser) *watchedBody {
	b := &watchedBody{body: body, packets: make(chan bodyPacket, 1), failed: make(chan struct{}), done: make(chan struct{}), exited: make(chan struct{})}
	go func() {
		defer close(b.exited)
		defer close(b.packets)
		for {
			data := make([]byte, httpRelayMTU)
			n, err := body.Read(data)
			if err != nil && !errors.Is(err, io.EOF) {
				close(b.failed)
			}
			select {
			case b.packets <- bodyPacket{data[:n], err}:
			case <-b.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return b
}
func (b *watchedBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(b.current) == 0 {
		if b.currentErr != nil {
			return 0, b.currentErr
		}
		select {
		case packet, ok := <-b.packets:
			if !ok {
				return 0, io.EOF
			}
			b.current, b.currentErr = packet.data, packet.err
		case <-b.done:
			return 0, net.ErrClosed
		}
	}
	n := copy(p, b.current)
	b.current = b.current[n:]
	if len(b.current) == 0 {
		return n, b.currentErr
	}
	return n, nil
}
func (b *watchedBody) Close() error {
	var err error
	b.once.Do(func() { close(b.done); err = b.body.Close(); <-b.exited })
	return err
}

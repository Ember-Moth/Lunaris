// Derived from XTLS/Xray-core transport/internet/splithttp/dialer.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"context"
	"net"
	"strconv"
	"time"
)

func (client *Client) uploadPackets(
	ctx context.Context,
	pipe *uploadPipe,
	sessionID string,
	selected *xmuxClient,
	lease *xmuxLease,
) {
	var sequence uint64
	var lastWrite time.Time
	var timer *time.Timer
	defer func() { stopTimer(timer) }()
	target := client.targetURL(client.config, client.server, client.tlsConfig)
	slots := make(chan struct{}, max(1, client.config.ScMaxBufferedPosts))
	written := make(chan struct{}, 1)
	onWritten := func() {
		select {
		case written <- struct{}{}:
		default:
		}
	}
	current := selected
	for {
		payload, err := pipe.readChunk(client.config.ScMaxEachPostBytes.random(), uploadCoalesceDelay)
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			pipe.release(payload)
			return
		}
		interval := time.Duration(client.config.ScMinPostsIntervalMs.random()) * time.Millisecond
		delay := time.Duration(0)
		if interval > 0 && !lastWrite.IsZero() {
			delay = interval - time.Since(lastWrite)
		}
		if !waitPostInterval(ctx, &timer, delay) {
			<-slots
			pipe.release(payload)
			return
		}
		lastWrite = time.Now()
		for !current.takeRequest(lastWrite) {
			next := client.manager.get()
			if next == nil || !lease.replaceUpload(next) {
				<-slots
				pipe.release(payload)
				pipe.interrupt(net.ErrClosed)
				return
			}
			current = next
		}
		seq := strconv.FormatUint(sequence, 10)
		sequence++
		current.addRequest()
		go client.postUpload(ctx, pipe, slots, current, target, sessionID, seq, payload, onWritten)
		select {
		case <-written:
		case <-ctx.Done():
			return
		}
	}
}

func (client *Client) postUpload(
	ctx context.Context,
	pipe *uploadPipe,
	slots chan struct{},
	selected *xmuxClient,
	target, sessionID, sequence string,
	payload *byteBuffer,
	onWritten func(),
) {
	defer func() {
		selected.doneRequest()
		pipe.release(payload)
		<-slots
	}()
	if err := selected.conn.(dialerClient).postPacket(ctx, target, sessionID, sequence, payload.data,
		onWritten); err != nil {
		pipe.interrupt(err)
	}
}

func waitPostInterval(ctx context.Context, timer **time.Timer, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	if *timer == nil {
		*timer = time.NewTimer(delay)
	} else {
		(*timer).Reset(delay)
	}
	select {
	case <-(*timer).C:
		return true
	case <-ctx.Done():
		return false
	}
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

// SPDX-License-Identifier: GPL-3.0-only
package native

import (
	"context"
	"testing"
	"time"
)

func TestPayloadBudgetAndClosedQueueRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{ctx: ctx, option: ServerOptions{MaxSessions: 1, QueueSize: 2}}
	if !s.reserveBytes(maxBufferedPayload) || s.reserveBytes(1) {
		t.Fatal("aggregate payload budget not enforced")
	}
	blocked := make(chan bool, 1)
	wait, cancelWait := context.WithCancel(ctx)
	go func() { blocked <- s.waitBytes(wait, 1) }()
	cancelWait()
	if <-blocked {
		t.Fatal("canceled producer reserved a full budget")
	}
	s.releaseBytes(maxBufferedPayload)
	u := &streamUnderlay{server: s, ctx: ctx, done: make(chan struct{})}
	session := newStreamSession(1, "alice", u)
	if !session.deliver([]byte("one")) || !session.deliver([]byte("two")) {
		t.Fatal("queue rejected valid payload")
	}
	go func() { blocked <- session.deliver([]byte("three")) }()
	session.closeRemote()
	select {
	case accepted := <-blocked:
		if accepted {
			t.Fatal("closed queue accepted payload")
		}
	case <-time.After(time.Second):
		t.Fatal("closed queue retained producer")
	}
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	if s.buffered != 0 {
		t.Fatalf("buffer budget leaked: %d", s.buffered)
	}
}
func TestSessionAdmissionLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ctx: ctx, option: ServerOptions{MaxSessions: 1}}
	if !s.reserveSession() || s.reserveSession() {
		t.Fatal("session limit not enforced")
	}
	s.releaseSession()
	if !s.reserveSession() {
		t.Fatal("slot was not reusable")
	}
	cancel()
	s.releaseSession()
	if s.reserveSession() {
		t.Fatal("closed service admitted session")
	}
}

func TestSessionDeadlineUpdatesPendingRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{ctx: ctx, option: ServerOptions{QueueSize: 1}}
	session := newStreamSession(1, "alice", &streamUnderlay{server: server, ctx: ctx, done: make(chan struct{})})
	defer session.closeRemote()
	read := make(chan error, 1)
	go func() { _, err := session.Read(make([]byte, 1)); read <- err }()
	time.Sleep(10 * time.Millisecond)
	_ = session.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("deadline returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("SetReadDeadline did not interrupt pending read")
	}
}

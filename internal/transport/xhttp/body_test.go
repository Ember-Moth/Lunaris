// SPDX-License-Identifier: GPL-3.0-only
package xhttp

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestWatchedBodyKeepsCleanEOF(t *testing.T) {
	b := watchBody(io.NopCloser(strings.NewReader("complete")))
	defer b.Close()
	data, err := io.ReadAll(b)
	if err != nil || string(data) != "complete" {
		t.Fatal(string(data), err)
	}
	select {
	case <-b.failed:
		t.Fatal("clean upload EOF aborted download")
	default:
	}
}
func TestWatchedBodyCloseInterruptsRead(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	b := watchBody(r)
	done := make(chan struct{})
	go func() { b.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("body pump survived Close")
	}
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package xhttp

import (
	"bytes"
	"testing"
	"time"
)

func TestUploadPipeCoalescesBurst(t *testing.T) {
	const chunkSize = 32 * 1024
	pipe := newUploadPipe(2 * chunkSize)
	first := bytes.Repeat([]byte{1}, chunkSize)
	second := bytes.Repeat([]byte{2}, chunkSize)
	if _, err := pipe.Write(first); err != nil {
		t.Fatal(err)
	}
	result := make(chan *byteBuffer, 1)
	go func() {
		payload, _ := pipe.readChunk(2*chunkSize, 25*time.Millisecond)
		result <- payload
	}()
	time.Sleep(5 * time.Millisecond)
	if _, err := pipe.Write(second); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-result:
		if !bytes.Equal(payload.data, append(first, second...)) {
			t.Fatalf("coalesced payload length = %d", len(payload.data))
		}
		pipe.release(payload)
	case <-time.After(time.Second):
		t.Fatal("coalesced read timed out")
	}
}

func TestUploadPipeCompactsPartialChunks(t *testing.T) {
	pipe := newUploadPipe(8)
	if _, err := pipe.Write([]byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	first, err := pipe.readChunk(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.data) != "abc" {
		t.Fatalf("first chunk = %q", first.data)
	}
	pipe.release(first)
	if _, err = pipe.Write([]byte("XYZ")); err != nil {
		t.Fatal(err)
	}
	second, err := pipe.readChunk(8, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(second.data) != "defghXYZ" {
		t.Fatalf("second chunk = %q", second.data)
	}
	pipe.release(second)
}

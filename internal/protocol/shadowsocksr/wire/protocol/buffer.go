// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package protocol

import (
	"math/bits"

	"github.com/sagernet/sing/common/buf"
)

// receiveBuffer borrows complete input and only owns storage when a frame is
// fragmented across reads.
type receiveBuffer struct {
	data []byte
}

func (b *receiveBuffer) feed(input []byte) ([]byte, bool) {
	if len(b.data) == 0 {
		return input, true
	}
	b.grow(len(b.data) + len(input))
	b.data = append(b.data, input...)
	return b.data, false
}

func (b *receiveBuffer) commit(remaining []byte, borrowed bool) {
	if borrowed {
		if len(remaining) == 0 {
			return
		}
		b.grow(len(remaining))
		b.data = append(b.data[:0], remaining...)
		return
	}
	if len(remaining) == 0 {
		b.release()
		return
	}
	consumed := len(b.data) - len(remaining)
	if consumed > 0 {
		copy(b.data, remaining)
		b.data = b.data[:len(remaining)]
	}
}

func (b *receiveBuffer) grow(required int) {
	if cap(b.data) >= required {
		return
	}
	size := max(512, required)
	if size&(size-1) != 0 {
		size = 1 << bits.Len(uint(size))
	}
	storage := buf.Get(size)
	if storage == nil {
		storage = make([]byte, size)
	} else {
		storage = storage[:cap(storage)]
	}
	length := copy(storage, b.data)
	if b.data != nil {
		_ = buf.Put(b.data[:cap(b.data)])
	}
	b.data = storage[:length]
}

func (b *receiveBuffer) release() {
	if b.data != nil {
		_ = buf.Put(b.data[:cap(b.data)])
		b.data = nil
	}
}

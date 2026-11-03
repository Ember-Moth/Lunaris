// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2022 nekohasekai.
// Adapted from sing-snell bc5a12ac736f; see MODIFICATIONS.md.
package reuse

import (
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

const (
	WaitingDiscardLimit = 0x80001
	RemoteEOFCode       = 0x65
	RemoteEOFMessage    = "Remote EOF"
)

type RecordReader interface {
	N.ExtendedReader
	N.ReadWaiter
	ReadRecord() (*buf.Buffer, error)
	NextRecord() (*buf.Buffer, error)
	SetCache(*buf.Buffer)
	ReleaseCache()
}

type RecordWriter interface {
	N.ExtendedWriter
	N.VectorisedWriteCreator
	CreateVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter
	CreatePacketVectorisedWriterFor(upstream N.VectorisedWriter) N.VectorisedWriter
	WritePacketBuffer(buffer *buf.Buffer) error
	WriteZeroChunk() error
	FrontHeadroom() int
	RearHeadroom() int
	WriterMTU() int
	Upstream() any
}

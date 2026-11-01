// SPDX-License-Identifier: GPL-3.0-or-later

package xhttp

import (
	"bytes"
	"io"
)

type bytesReadCloser struct{ *bytes.Reader }

func newBytesReadCloser(payload []byte) io.ReadCloser {
	return &bytesReadCloser{Reader: bytes.NewReader(payload)}
}

func (*bytesReadCloser) Close() error { return nil }

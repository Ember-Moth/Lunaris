// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	"bytes"

	"github.com/sagernet/sing/common/buf"
)

var (
	tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	tlsApplicationDataStart = []byte{0x17, 0x03, 0x03}
)

const (
	commandPaddingContinue byte = iota
	commandPaddingEnd
	commandPaddingDirect
)

func reshapeBuffer(b []byte) []*buf.Buffer {
	const bufferLimit = 8192 - 21
	if len(b) < bufferLimit {
		return []*buf.Buffer{buf.As(b)}
	}
	index := int32(bytes.LastIndex(b, tlsApplicationDataStart))
	if index <= 0 {
		index = 8192 / 2
	}
	return []*buf.Buffer{buf.As(b[:index]), buf.As(b[index:])}
}

// Derived from XTLS/Xray-core proxy/vless/encryption at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"sync"

	"lukechampine.com/blake3"
)

const xorRecordBufferSize = 16640

var xorRecordPool = sync.Pool{
	New: func() any {
		return new([xorRecordBufferSize]byte)
	},
}

func NewCTR(key, iv []byte) cipher.Stream {
	k := make([]byte, 32)
	blake3.DeriveKey(k, "VLESS", key) // avoids using key directly
	block, _ := aes.NewCipher(k)
	return cipher.NewCTR(block, iv)
	//chacha20.NewUnauthenticatedCipher()
}

type XorConn struct {
	net.Conn
	CTR         cipher.Stream
	PeerCTR     cipher.Stream
	OutSkip     int
	OutHeader   []byte
	InSkip      int
	InHeader    []byte
	readAccess  sync.Mutex
	writeAccess sync.Mutex
}

func NewXorConn(conn net.Conn, ctr, peerCTR cipher.Stream, outSkip, inSkip int) *XorConn {
	return &XorConn{
		Conn:      conn,
		CTR:       ctr,
		PeerCTR:   peerCTR,
		OutSkip:   outSkip,
		OutHeader: make([]byte, 0, 5), // important
		InSkip:    inSkip,
		InHeader:  make([]byte, 0, 5), // important
	}
}

func (c *XorConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	var (
		wire    []byte
		storage *[xorRecordBufferSize]byte
	)
	if len(b) <= xorRecordBufferSize {
		storage = xorRecordPool.Get().(*[xorRecordBufferSize]byte)
		wire = storage[:len(b)]
	} else {
		wire = make([]byte, len(b))
	}
	copy(wire, b)
	for p := wire; ; {
		if len(p) <= c.OutSkip {
			c.OutSkip -= len(p)
			break
		}
		p = p[c.OutSkip:]
		c.OutSkip = 0
		need := 5 - len(c.OutHeader)
		if len(p) < need {
			c.OutHeader = append(c.OutHeader, p...)
			c.CTR.XORKeyStream(p, p)
			break
		}
		c.OutSkip, _ = DecodeHeader(append(c.OutHeader, p[:need]...))
		c.OutHeader = c.OutHeader[:0]
		c.CTR.XORKeyStream(p[:need], p[:need])
		p = p[need:]
	}
	err := writeAll(c.Conn, wire)
	if storage != nil {
		xorRecordPool.Put(storage)
	}
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *XorConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	n, err := c.Conn.Read(b)
	for p := b[:n]; ; {
		if len(p) <= c.InSkip {
			c.InSkip -= len(p)
			break
		}
		p = p[c.InSkip:]
		c.InSkip = 0
		need := 5 - len(c.InHeader)
		if len(p) < need {
			c.PeerCTR.XORKeyStream(p, p)
			c.InHeader = append(c.InHeader, p...)
			break
		}
		c.PeerCTR.XORKeyStream(p[:need], p[:need])
		c.InSkip, _ = DecodeHeader(append(c.InHeader, p[:need]...))
		c.InHeader = c.InHeader[:0]
		p = p[need:]
	}
	return n, err
}

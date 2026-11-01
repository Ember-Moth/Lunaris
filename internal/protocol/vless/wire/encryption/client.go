// Derived from XTLS/Xray-core proxy/vless/encryption at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.
package encryption

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

type ClientInstance struct {
	NfsPKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][32]byte
	RelaysLength  int
	XorMode       uint32
	Seconds       uint32
	PaddingLens   [][3]int
	PaddingGaps   [][3]int

	RWLock sync.RWMutex
	Expire time.Time
	PfsKey []byte
	Ticket []byte
}

func (i *ClientInstance) Init(nfsPKeysBytes [][]byte, xorMode, seconds uint32, padding string) (err error) {
	if i.NfsPKeys != nil {
		return errors.New("already initialized")
	}
	l := len(nfsPKeysBytes)
	if l == 0 || l > 8 {
		return errors.New("invalid nfsPKeysBytes count")
	}
	if xorMode > 2 || seconds > 1 {
		return errors.New("invalid client encryption options")
	}
	i.NfsPKeys = make([]any, l)
	i.NfsPKeysBytes = nfsPKeysBytes
	i.Hash32s = make([][32]byte, l)
	for j, k := range nfsPKeysBytes {
		if len(k) == 32 {
			if i.NfsPKeys[j], err = ecdh.X25519().NewPublicKey(k); err != nil {
				return
			}
			i.RelaysLength += 32 + 32
		} else {
			if i.NfsPKeys[j], err = mlkem.NewEncapsulationKey768(k); err != nil {
				return
			}
			i.RelaysLength += 1088 + 32
		}
		i.Hash32s[j] = blake3.Sum256(k)
	}
	i.RelaysLength -= 32
	i.XorMode = xorMode
	i.Seconds = seconds
	return ParsePadding(padding, &i.PaddingLens, &i.PaddingGaps)
}

func (i *ClientInstance) Handshake(conn net.Conn) (*CommonConn, error) {
	if i.NfsPKeys == nil {
		return nil, errors.New("uninitialized")
	}
	c := NewCommonConn(conn, hasAESGCMHardwareSupport)

	ivAndRealysLength := 16 + i.RelaysLength
	pfsKeyExchangeLength := 18 + 1184 + 32 + 16
	var resumePfsKey [64]byte
	var resumeTicket [16]byte
	resume := false
	if i.Seconds > 0 {
		i.RWLock.RLock()
		if time.Now().Before(i.Expire) && len(i.PfsKey) == len(resumePfsKey) && len(i.Ticket) >= len(resumeTicket) {
			copy(resumePfsKey[:], i.PfsKey)
			copy(resumeTicket[:], i.Ticket)
			resume = true
		}
		i.RWLock.RUnlock()
	}
	var (
		paddingLength int
		paddingLens   []int
		paddingGaps   []time.Duration
	)
	clientHelloLength := ivAndRealysLength + 18 + 32
	if !resume {
		paddingLength, paddingLens, paddingGaps = CreatPadding(i.PaddingLens, i.PaddingGaps)
		clientHelloLength = ivAndRealysLength + pfsKeyExchangeLength + paddingLength
	}
	clientHello := make([]byte, clientHelloLength)

	iv := clientHello[:16]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	relays := clientHello[16:ivAndRealysLength]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.NfsPKeys {
		index := 32
		if k, ok := k.(*ecdh.PublicKey); ok {
			privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			copy(relays, privateKey.PublicKey().Bytes())
			nfsKey, err = privateKey.ECDH(k)
			if err != nil {
				return nil, err
			}
		}
		if k, ok := k.(*mlkem.EncapsulationKey768); ok {
			var ciphertext []byte
			nfsKey, ciphertext = k.Encapsulate()
			copy(relays, ciphertext)
			index = 1088
		}
		if i.XorMode > 0 { // this xor can (others can't) be recovered by client's config, revealing an X25519 public key / ML-KEM-768 ciphertext, that's why "native" values
			NewCTR(i.NfsPKeysBytes[j], iv).XORKeyStream(relays, relays[:index]) // make X25519 public key / ML-KEM-768 ciphertext distinguishable from random bytes
		}
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:32]) // make this relay irreplaceable
		}
		if j == len(i.NfsPKeys)-1 {
			break
		}
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays[index:], i.Hash32s[j+1][:])
		relays = relays[index+32:]
	}
	nfsAEAD := NewAEAD(iv, nfsKey, c.UseAES)

	if resume {
		c.Client = i
		c.UnitedKey = make([]byte, len(resumePfsKey)+len(nfsKey))
		copy(c.UnitedKey, resumePfsKey[:])
		copy(c.UnitedKey[len(resumePfsKey):], nfsKey)
		nfsAEAD.Seal(clientHello[:ivAndRealysLength], nil, EncodeLength(32), nil)
		nfsAEAD.Seal(clientHello[:ivAndRealysLength+18], nil, resumeTicket[:], nil)
		c.PreWrite = clientHello
		c.AEAD = NewAEAD(clientHello[ivAndRealysLength+18:], c.UnitedKey, c.UseAES)
		if i.XorMode == 2 {
			c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, iv), nil, len(c.PreWrite), 16)
		}
		return c, nil
	}

	pfsKeyExchange := clientHello[ivAndRealysLength : ivAndRealysLength+pfsKeyExchangeLength]
	nfsAEAD.Seal(pfsKeyExchange[:0], nil, EncodeLength(pfsKeyExchangeLength-18), nil)
	mlkem768DKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	x25519SKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pfsPublicKey := append(mlkem768DKey.EncapsulationKey().Bytes(), x25519SKey.PublicKey().Bytes()...)
	nfsAEAD.Seal(pfsKeyExchange[:18], nil, pfsPublicKey, nil)

	padding := clientHello[ivAndRealysLength+pfsKeyExchangeLength:]
	nfsAEAD.Seal(padding[:0], nil, EncodeLength(paddingLength-18), nil)
	nfsAEAD.Seal(padding[:18], nil, padding[18:paddingLength-16], nil)

	paddingLens[0] = ivAndRealysLength + pfsKeyExchangeLength + paddingLens[0]
	for i, l := range paddingLens { // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control
		if l > 0 {
			if err := writeAll(conn, clientHello[:l]); err != nil {
				return nil, err
			}
			clientHello = clientHello[l:]
		}
		if len(paddingGaps) > i {
			time.Sleep(paddingGaps[i])
		}
	}

	encryptedPfsPublicKey := make([]byte, 1088+32+16)
	if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
		return nil, err
	}
	if _, err := nfsAEAD.Open(encryptedPfsPublicKey[:0], MaxNonce, encryptedPfsPublicKey, nil); err != nil {
		return nil, err
	}
	mlkem768Key, err := mlkem768DKey.Decapsulate(encryptedPfsPublicKey[:1088])
	if err != nil {
		return nil, err
	}
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[1088 : 1088+32])
	if err != nil {
		return nil, err
	}
	x25519Key, err := x25519SKey.ECDH(peerX25519PKey)
	if err != nil {
		return nil, err
	}
	pfsKey := make([]byte, 32+32) // no more capacity
	copy(pfsKey, mlkem768Key)
	copy(pfsKey[32:], x25519Key)
	c.UnitedKey = append(pfsKey, nfsKey...)
	c.AEAD = NewAEAD(pfsPublicKey, c.UnitedKey, c.UseAES)
	c.PeerAEAD = NewAEAD(encryptedPfsPublicKey[:1088+32], c.UnitedKey, c.UseAES)

	encryptedTicket := make([]byte, 32)
	if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
		return nil, err
	}
	if _, err := c.PeerAEAD.Open(encryptedTicket[:0], nil, encryptedTicket, nil); err != nil {
		return nil, err
	}
	seconds := DecodeLength(encryptedTicket)

	if i.Seconds > 0 && seconds > 0 {
		i.RWLock.Lock()
		i.Expire = time.Now().Add(time.Duration(seconds) * time.Second)
		i.PfsKey = pfsKey
		i.Ticket = encryptedTicket[:16]
		i.RWLock.Unlock()
	}

	encryptedLength := make([]byte, 18)
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if _, err := c.PeerAEAD.Open(encryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	length := DecodeLength(encryptedLength[:2])
	c.PeerPadding = make([]byte, length) // important: allows server sends padding slowly, eliminating 1-RTT's traffic pattern

	if i.XorMode == 2 {
		c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, iv), NewCTR(c.UnitedKey, encryptedTicket[:16]), 0, length)
	}
	return c, nil
}

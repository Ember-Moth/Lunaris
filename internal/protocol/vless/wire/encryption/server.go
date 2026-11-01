// Derived from XTLS/Xray-core proxy/vless/encryption at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.
package encryption

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"lukechampine.com/blake3"
)

type ServerSession struct {
	PfsKey   []byte
	NfsKeys  map[[32]byte]struct{}
	replayMu sync.Mutex
}

const maxSessionReplays = 256
const defaultMaxSessions = 4096

type ServerInstance struct {
	// MaxSessions bounds retained tickets. A full cache still permits 1-RTT.
	MaxSessions   int
	NfsSKeys      []any
	NfsPKeysBytes [][]byte
	Hash32s       [][32]byte
	RelaysLength  int
	XorMode       uint32
	SecondsFrom   int64
	SecondsTo     int64
	PaddingLens   [][3]int
	PaddingGaps   [][3]int

	RWLock   sync.RWMutex
	Closed   bool
	Lasts    map[int64][16]byte
	Tickets  [][16]byte
	Sessions map[[16]byte]*ServerSession
	stop     chan struct{}
	close    sync.Once
	wait     sync.WaitGroup
}

func (i *ServerInstance) Init(nfsSKeysBytes [][]byte, xorMode uint32, secondsFrom, secondsTo int64, padding string) (err error) {
	if i.NfsSKeys != nil {
		return errors.New("already initialized")
	}
	l := len(nfsSKeysBytes)
	if l == 0 || l > 8 {
		return errors.New("invalid nfsSKeysBytes count")
	}
	if xorMode > 2 || secondsFrom < 0 || secondsFrom > 65535 || secondsTo < 0 || secondsTo > 65535 ||
		secondsTo > 0 && secondsTo < secondsFrom {
		return errors.New("invalid server encryption options")
	}
	if i.MaxSessions <= 0 {
		i.MaxSessions = defaultMaxSessions
	}
	i.NfsSKeys = make([]any, l)
	i.NfsPKeysBytes = make([][]byte, l)
	i.Hash32s = make([][32]byte, l)
	for j, k := range nfsSKeysBytes {
		if len(k) == 32 {
			if i.NfsSKeys[j], err = ecdh.X25519().NewPrivateKey(k); err != nil {
				return
			}
			i.NfsPKeysBytes[j] = i.NfsSKeys[j].(*ecdh.PrivateKey).PublicKey().Bytes()
			i.RelaysLength += 32 + 32
		} else {
			if i.NfsSKeys[j], err = mlkem.NewDecapsulationKey768(k); err != nil {
				return
			}
			i.NfsPKeysBytes[j] = i.NfsSKeys[j].(*mlkem.DecapsulationKey768).EncapsulationKey().Bytes()
			i.RelaysLength += 1088 + 32
		}
		i.Hash32s[j] = blake3.Sum256(i.NfsPKeysBytes[j])
	}
	i.RelaysLength -= 32
	i.XorMode = xorMode
	i.SecondsFrom = secondsFrom
	i.SecondsTo = secondsTo
	err = ParsePadding(padding, &i.PaddingLens, &i.PaddingGaps)
	if err != nil {
		return
	}
	if i.SecondsFrom > 0 || i.SecondsTo > 0 {
		i.Lasts = make(map[int64][16]byte)
		i.Tickets = make([][16]byte, 0, 1024)
		i.Sessions = make(map[[16]byte]*ServerSession)
		i.stop = make(chan struct{})
		i.wait.Add(1)
		go func() {
			defer i.wait.Done()
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-i.stop:
					return
				case <-ticker.C:
				}
				i.expireSessions(time.Now().Unix() / 60)
			}
		}()
	}
	return
}

func (i *ServerInstance) expireSessions(currentMinute int64) {
	i.RWLock.Lock()
	defer i.RWLock.Unlock()
	var (
		lastMinute int64 = -1
		lastTicket [16]byte
	)
	for minute, ticket := range i.Lasts {
		if minute <= currentMinute {
			delete(i.Lasts, minute)
			if minute > lastMinute {
				lastMinute = minute
				lastTicket = ticket
			}
		}
	}
	if lastMinute < 0 {
		return
	}
	cutoff := -1
	for index, ticket := range i.Tickets {
		if ticket == lastTicket {
			cutoff = index
			break
		}
	}
	if cutoff < 0 {
		return
	}
	for _, ticket := range i.Tickets[:cutoff+1] {
		delete(i.Sessions, ticket)
	}
	remaining := len(i.Tickets) - cutoff - 1
	copy(i.Tickets, i.Tickets[cutoff+1:])
	clear(i.Tickets[remaining:])
	i.Tickets = i.Tickets[:remaining]
}

func (i *ServerInstance) Close() (err error) {
	i.close.Do(func() {
		i.RWLock.Lock()
		i.Closed = true
		clear(i.Sessions)
		clear(i.Lasts)
		clear(i.Tickets)
		i.Tickets = nil
		i.RWLock.Unlock()
		if i.stop != nil {
			close(i.stop)
			i.wait.Wait()
		}
	})
	return
}

func (i *ServerInstance) Handshake(conn net.Conn, fallback *[]byte) (*CommonConn, error) {
	return i.HandshakeContext(context.Background(), conn, fallback)
}

// HandshakeContext keeps padding delays and blocked I/O within the admission lifetime.
func (i *ServerInstance) HandshakeContext(ctx context.Context, conn net.Conn, fallback *[]byte) (*CommonConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if i.NfsSKeys == nil {
		return nil, errors.New("uninitialized")
	}
	i.RWLock.RLock()
	closed := i.Closed
	i.RWLock.RUnlock()
	if closed {
		return nil, net.ErrClosed
	}
	c := NewCommonConn(conn, true)

	ivAndRelays := make([]byte, 16+i.RelaysLength)
	if _, err := io.ReadFull(conn, ivAndRelays); err != nil {
		return nil, err
	}
	if fallback != nil {
		*fallback = append(*fallback, ivAndRelays...)
	}
	iv := ivAndRelays[:16]
	relays := ivAndRelays[16:]
	var nfsKey []byte
	var lastCTR cipher.Stream
	for j, k := range i.NfsSKeys {
		if lastCTR != nil {
			lastCTR.XORKeyStream(relays, relays[:32]) // recover this relay
		}
		index := 32
		if _, ok := k.(*mlkem.DecapsulationKey768); ok {
			index = 1088
		}
		if i.XorMode > 0 {
			NewCTR(i.NfsPKeysBytes[j], iv).XORKeyStream(relays, relays[:index]) // we don't use buggy elligator2, because we have PSK :)
		}
		if k, ok := k.(*ecdh.PrivateKey); ok {
			publicKey, err := ecdh.X25519().NewPublicKey(relays[:index])
			if err != nil {
				return nil, err
			}
			if publicKey.Bytes()[31] > 127 { // we just don't want the observer can change even one bit without breaking the connection, though it has nothing to do with security
				return nil, errors.New("the highest bit of the last byte of the peer-sent X25519 public key is not 0")
			}
			nfsKey, err = k.ECDH(publicKey)
			if err != nil {
				return nil, err
			}
		}
		if k, ok := k.(*mlkem.DecapsulationKey768); ok {
			var err error
			nfsKey, err = k.Decapsulate(relays[:index])
			if err != nil {
				return nil, err
			}
		}
		if j == len(i.NfsSKeys)-1 {
			break
		}
		relays = relays[index:]
		lastCTR = NewCTR(nfsKey, iv)
		lastCTR.XORKeyStream(relays, relays[:32])
		if !bytes.Equal(relays[:32], i.Hash32s[j+1][:]) {
			return nil, fmt.Errorf("unexpected hash32: %v", relays[:32])
		}
		relays = relays[32:]
	}
	nfsAEAD := NewAEAD(iv, nfsKey, c.UseAES)

	encryptedLength := make([]byte, 18)
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if fallback != nil {
		*fallback = append(*fallback, encryptedLength...)
	}
	decryptedLength := make([]byte, 2)
	if _, err := nfsAEAD.Open(decryptedLength[:0], nil, encryptedLength, nil); err != nil {
		c.UseAES = !c.UseAES
		nfsAEAD = NewAEAD(iv, nfsKey, c.UseAES)
		if _, err := nfsAEAD.Open(decryptedLength[:0], nil, encryptedLength, nil); err != nil {
			return nil, err
		}
	}
	if fallback != nil {
		*fallback = nil
	}
	length := DecodeLength(decryptedLength)

	if length == 32 {
		if i.SecondsFrom == 0 && i.SecondsTo == 0 {
			return nil, errors.New("0-RTT is not allowed")
		}
		encryptedTicket := make([]byte, 32)
		if _, err := io.ReadFull(conn, encryptedTicket); err != nil {
			return nil, err
		}
		ticket, err := nfsAEAD.Open(nil, nil, encryptedTicket, nil)
		if err != nil {
			return nil, err
		}
		i.RWLock.RLock()
		s := i.Sessions[[16]byte(ticket)]
		i.RWLock.RUnlock()
		if s == nil {
			noises := make([]byte, randBetween(1279, 2279)) // matches 1-RTT's server hello length for "random"
			var err error
			for err == nil {
				if _, err = io.ReadFull(rand.Reader, noises); err != nil {
					return nil, err
				}
				_, err = DecodeHeader(noises)
			}
			_ = writeAll(conn, noises) // make client do new handshake
			return nil, errors.New("expired ticket")
		}
		if err := s.acceptReplayKey([32]byte(nfsKey)); err != nil {
			return nil, err
		}
		c.UnitedKey = append(s.PfsKey, nfsKey...) // the same nfsKey links the upload & download (prevents server -> client's another request)
		c.PreWrite = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, c.PreWrite); err != nil {
			return nil, err
		}
		c.AEAD = NewAEAD(c.PreWrite, c.UnitedKey, c.UseAES)
		c.PeerAEAD = NewAEAD(encryptedTicket, c.UnitedKey, c.UseAES) // unchangeable ctx (prevents server -> server), and different ctx length for upload / download (prevents client -> client)
		if i.XorMode == 2 {
			c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, c.PreWrite), NewCTR(c.UnitedKey, iv), 16, 0) // it doesn't matter if the attacker sends client's iv back to the client
		}
		return c, nil
	}

	if length < 1184+32+16 { // client may send more public keys in the future's version
		return nil, errors.New("too short length")
	}
	encryptedPfsPublicKey := make([]byte, length)
	if _, err := io.ReadFull(conn, encryptedPfsPublicKey); err != nil {
		return nil, err
	}
	if _, err := nfsAEAD.Open(encryptedPfsPublicKey[:0], nil, encryptedPfsPublicKey, nil); err != nil {
		return nil, err
	}
	mlkem768EKey, err := mlkem.NewEncapsulationKey768(encryptedPfsPublicKey[:1184])
	if err != nil {
		return nil, err
	}
	mlkem768Key, encapsulatedPfsKey := mlkem768EKey.Encapsulate()
	peerX25519PKey, err := ecdh.X25519().NewPublicKey(encryptedPfsPublicKey[1184 : 1184+32])
	if err != nil {
		return nil, err
	}
	x25519SKey, err := ecdh.X25519().GenerateKey(rand.Reader)
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
	pfsPublicKey := append(encapsulatedPfsKey, x25519SKey.PublicKey().Bytes()...)
	c.UnitedKey = append(pfsKey, nfsKey...)
	c.AEAD = NewAEAD(pfsPublicKey, c.UnitedKey, c.UseAES)
	c.PeerAEAD = NewAEAD(encryptedPfsPublicKey[:1184+32], c.UnitedKey, c.UseAES)

	ticket := [16]byte{}
	if _, err := io.ReadFull(rand.Reader, ticket[:]); err != nil {
		return nil, err
	}
	var seconds int64
	if i.SecondsTo == 0 {
		seconds = i.SecondsFrom * randBetween(50, 100) / 100
	} else {
		seconds = randBetween(i.SecondsFrom, i.SecondsTo)
	}
	i.RWLock.Lock()
	if i.Closed {
		i.RWLock.Unlock()
		return nil, net.ErrClosed
	}
	if len(i.Sessions) >= i.MaxSessions {
		seconds = 0
	}
	copy(ticket[:], EncodeLength(int(seconds)))
	if seconds > 0 {
		i.Lasts[(time.Now().Unix()+maximum64(i.SecondsFrom, i.SecondsTo))/60+2] = ticket
		i.Tickets = append(i.Tickets, ticket)
		i.Sessions[ticket] = &ServerSession{PfsKey: pfsKey}
	}
	i.RWLock.Unlock()

	pfsKeyExchangeLength := 1088 + 32 + 16
	encryptedTicketLength := 32
	paddingLength, paddingLens, paddingGaps := CreatPadding(i.PaddingLens, i.PaddingGaps)
	serverHello := make([]byte, pfsKeyExchangeLength+encryptedTicketLength+paddingLength)
	nfsAEAD.Seal(serverHello[:0], MaxNonce, pfsPublicKey, nil)
	c.AEAD.Seal(serverHello[:pfsKeyExchangeLength], nil, ticket[:], nil)
	padding := serverHello[pfsKeyExchangeLength+encryptedTicketLength:]
	c.AEAD.Seal(padding[:0], nil, EncodeLength(paddingLength-18), nil)
	c.AEAD.Seal(padding[:18], nil, padding[18:paddingLength-16], nil)

	paddingLens[0] = pfsKeyExchangeLength + encryptedTicketLength + paddingLens[0]
	for i, l := range paddingLens { // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS flow takes control
		if l > 0 {
			if err := writeAll(conn, serverHello[:l]); err != nil {
				return nil, err
			}
			serverHello = serverHello[l:]
		}
		if len(paddingGaps) > i {
			timer := time.NewTimer(paddingGaps[i])
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
	}

	// important: allows client sends padding slowly, eliminating 1-RTT's traffic pattern
	if _, err := io.ReadFull(conn, encryptedLength); err != nil {
		return nil, err
	}
	if _, err := nfsAEAD.Open(encryptedLength[:0], nil, encryptedLength, nil); err != nil {
		return nil, err
	}
	encryptedPadding := make([]byte, DecodeLength(encryptedLength[:2]))
	if _, err := io.ReadFull(conn, encryptedPadding); err != nil {
		return nil, err
	}
	if _, err := nfsAEAD.Open(encryptedPadding[:0], nil, encryptedPadding, nil); err != nil {
		return nil, err
	}

	if i.XorMode == 2 {
		c.Conn = NewXorConn(conn, NewCTR(c.UnitedKey, ticket[:]), NewCTR(c.UnitedKey, iv), 0, 0)
	}
	return c, nil
}

func (s *ServerSession) acceptReplayKey(key [32]byte) error {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	if _, exists := s.NfsKeys[key]; exists {
		return errors.New("replay detected")
	}
	if len(s.NfsKeys) >= maxSessionReplays {
		return errors.New("ticket replay budget exceeded")
	}
	if s.NfsKeys == nil {
		s.NfsKeys = make(map[[32]byte]struct{})
	}
	s.NfsKeys[key] = struct{}{}
	return nil
}

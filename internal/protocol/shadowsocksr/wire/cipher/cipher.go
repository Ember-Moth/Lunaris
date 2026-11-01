// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

// Package cipher implements classic Shadowsocks streams and SIP004 AEAD records
// for ShadowsocksR. It intentionally contains no registries or application state.
package cipher

import (
	"crypto/aes"
	stdcipher "crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
)

var ErrUnsupportedMethod = errors.New("shadowsocksr: unsupported cipher method")

var ErrCipherMode = errors.New("shadowsocksr: cipher method uses a different transport mode")

type streamFactory func(key, iv []byte) (stdcipher.Stream, error)

// Suite is immutable password-derived cipher material. It is safe to share
// between connections and packet workers.
type Suite struct {
	name    string
	key     []byte
	ivLen   int
	encrypt streamFactory
	decrypt streamFactory
	aead    aeadFactory
}

func NewSuite(method, password string) (*Suite, error) {
	method = normalizeMethod(method)
	if keyLen, factory, loaded := aeadMethodSpec(method); loaded {
		return &Suite{
			name:  method,
			key:   deriveKey(password, keyLen),
			ivLen: keyLen,
			aead:  factory,
		}, nil
	}
	keyLen, ivLen, encrypt, decrypt, err := methodSpec(method)
	if err != nil {
		return nil, err
	}
	return &Suite{
		name:    method,
		key:     deriveKey(password, keyLen),
		ivLen:   ivLen,
		encrypt: encrypt,
		decrypt: decrypt,
	}, nil
}

func (s *Suite) Name() string { return s.name }

func (s *Suite) IVLen() int { return s.ivLen }

// IsAEAD reports whether the suite uses SIP004 authenticated records rather
// than the classic Shadowsocks byte stream.
func (s *Suite) IsAEAD() bool { return s.aead != nil }

// PacketOverhead is the number of bytes added by the cipher layer to one UDP
// packet. SSR protocol framing overhead is intentionally not included.
func (s *Suite) PacketOverhead() int {
	overhead := s.ivLen
	if s.IsAEAD() {
		overhead += aeadTagSize
	}
	return overhead
}

// Key returns the immutable password-derived key. Callers must not modify it.
func (s *Suite) Key() []byte { return s.key }

// DeriveKey applies the classic Shadowsocks EVP_BytesToKey construction.
// It is exposed for SSR protocol header keys, not for general-purpose KDF use.
func DeriveKey(password string, length int) []byte { return deriveKey(password, length) }

func (s *Suite) NewEncryptStream(iv []byte) (stdcipher.Stream, error) {
	if s.IsAEAD() {
		return nil, fmt.Errorf("%w: %q requires SIP004 records", ErrCipherMode, s.name)
	}
	if len(iv) != s.ivLen {
		return nil, fmt.Errorf("shadowsocksr: cipher IV length %d, want %d", len(iv), s.ivLen)
	}
	return s.encrypt(s.key, iv)
}

func (s *Suite) NewDecryptStream(iv []byte) (stdcipher.Stream, error) {
	if s.IsAEAD() {
		return nil, fmt.Errorf("%w: %q requires SIP004 records", ErrCipherMode, s.name)
	}
	if len(iv) != s.ivLen {
		return nil, fmt.Errorf("shadowsocksr: cipher IV length %d, want %d", len(iv), s.ivLen)
	}
	return s.decrypt(s.key, iv)
}

func (s *Suite) RandomIV(storage []byte) ([]byte, error) {
	if cap(storage) < s.ivLen {
		storage = make([]byte, s.ivLen)
	} else {
		storage = storage[:s.ivLen]
	}
	if s.ivLen == 0 {
		return storage, nil
	}
	_, err := io.ReadFull(rand.Reader, storage)
	return storage, err
}

// SealPacket appends IV || ciphertext to dst. dst and plaintext must not
// overlap. The operation allocates only inside the selected cipher primitive.
func (s *Suite) SealPacket(dst, plaintext, iv []byte) ([]byte, error) {
	if s.IsAEAD() {
		if len(iv) != s.ivLen {
			return nil, fmt.Errorf("shadowsocksr: cipher salt length %d, want %d", len(iv), s.ivLen)
		}
		aead, err := s.newAEAD(iv)
		if err != nil {
			return nil, err
		}
		start := len(dst)
		dst = append(dst, iv...)
		var zeroNonce [24]byte
		dst = aead.Seal(dst, zeroNonce[:aead.NonceSize()], plaintext, nil)
		if len(dst) != start+s.ivLen+len(plaintext)+aead.Overhead() {
			panic("shadowsocksr: unexpected AEAD packet size")
		}
		return dst, nil
	}
	stream, err := s.NewEncryptStream(iv)
	if err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, iv...)
	dst = append(dst, plaintext...)
	stream.XORKeyStream(dst[start+s.ivLen:], plaintext)
	return dst, nil
}

// OpenPacket decrypts IV || ciphertext in place and returns the plaintext and
// IV slices backed by packet.
func (s *Suite) OpenPacket(packet []byte) (plaintext, iv []byte, err error) {
	if len(packet) < s.PacketOverhead() {
		return nil, nil, io.ErrUnexpectedEOF
	}
	iv = packet[:s.ivLen]
	if s.IsAEAD() {
		aead, aeadErr := s.newAEAD(iv)
		if aeadErr != nil {
			return nil, nil, aeadErr
		}
		ciphertext := packet[s.ivLen:]
		var zeroNonce [24]byte
		plaintext, aeadErr = aead.Open(ciphertext[:0], zeroNonce[:aead.NonceSize()], ciphertext, nil)
		if aeadErr != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrAuthentication, aeadErr)
		}
		return plaintext, iv, nil
	}
	stream, err := s.NewDecryptStream(iv)
	if err != nil {
		return nil, nil, err
	}
	plaintext = packet[s.ivLen:]
	stream.XORKeyStream(plaintext, plaintext)
	return plaintext, iv, nil
}

func normalizeMethod(method string) string {
	if method == "chacha20-poly1305" {
		return "chacha20-ietf-poly1305"
	}
	return method
}

func methodSpec(method string) (keyLen, ivLen int, encrypt, decrypt streamFactory, err error) {
	switch method {
	case "none":
		factory := func(_, _ []byte) (stdcipher.Stream, error) { return identityStream{}, nil }
		return 16, 0, factory, factory, nil
	case "aes-128-ctr":
		factory := aesStream(stdcipher.NewCTR)
		return 16, aes.BlockSize, factory, factory, nil
	case "aes-192-ctr":
		factory := aesStream(stdcipher.NewCTR)
		return 24, aes.BlockSize, factory, factory, nil
	case "aes-256-ctr":
		factory := aesStream(stdcipher.NewCTR)
		return 32, aes.BlockSize, factory, factory, nil
	case "aes-128-cfb":
		return 16, aes.BlockSize, aesStream(stdcipher.NewCFBEncrypter), aesStream(stdcipher.NewCFBDecrypter), nil
	case "aes-192-cfb":
		return 24, aes.BlockSize, aesStream(stdcipher.NewCFBEncrypter), aesStream(stdcipher.NewCFBDecrypter), nil
	case "aes-256-cfb":
		return 32, aes.BlockSize, aesStream(stdcipher.NewCFBEncrypter), aesStream(stdcipher.NewCFBDecrypter), nil
	case "rc4-md5":
		return 16, 16, rc4MD5Stream, rc4MD5Stream, nil
	case "chacha20":
		return chacha20.KeySize, 8, legacyChaCha20Stream, legacyChaCha20Stream, nil
	case "chacha20-ietf":
		return chacha20.KeySize, chacha20.NonceSize, chacha20Stream, chacha20Stream, nil
	default:
		return 0, 0, nil, nil, fmt.Errorf("%w %q", ErrUnsupportedMethod, method)
	}
}

func aesStream(newStream func(stdcipher.Block, []byte) stdcipher.Stream) streamFactory {
	return func(key, iv []byte) (stdcipher.Stream, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return newStream(block, iv), nil
	}
}

func rc4MD5Stream(key, iv []byte) (stdcipher.Stream, error) {
	hash := md5.New()
	_, _ = hash.Write(key)
	_, _ = hash.Write(iv)
	return rc4.NewCipher(hash.Sum(nil))
}

func chacha20Stream(key, iv []byte) (stdcipher.Stream, error) {
	return chacha20.NewUnauthenticatedCipher(key, iv)
}

// The original ChaCha20 construction places a 64-bit block counter before an
// 8-byte nonce. The IETF construction with a zero high counter word and
// 0 || nonce has the same initial state until the 2^32-block limit, far beyond
// an SSR stream's practical lifetime.
func legacyChaCha20Stream(key, iv []byte) (stdcipher.Stream, error) {
	var nonce [chacha20.NonceSize]byte
	copy(nonce[4:], iv)
	return chacha20.NewUnauthenticatedCipher(key, nonce[:])
}

type identityStream struct{}

func (identityStream) XORKeyStream(dst, src []byte) { copy(dst, src) }

func deriveKey(password string, length int) []byte {
	key := make([]byte, length)
	var previous [md5.Size]byte
	written := 0
	for written < length {
		hash := md5.New()
		if written != 0 {
			_, _ = hash.Write(previous[:])
		}
		_, _ = hash.Write([]byte(password))
		copy(previous[:], hash.Sum(previous[:0]))
		written += copy(key[written:], previous[:])
	}
	return key
}

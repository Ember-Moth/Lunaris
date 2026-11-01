// SPDX-License-Identifier: GPL-3.0-only
package testutil

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// RealityClient is a minimal authenticated test peer. It follows XTLS's public
// ClientHello/session-ID construction and requires the authenticated temporary
// certificate; fallback certificates are never accepted as proxy success.
func RealityClient(ctx context.Context, raw net.Conn, publicKey, shortID []byte, serverName string) (net.Conn, error) {
	return realityClient(ctx, raw, publicKey, shortID, serverName, false)
}
func LegacyRealityClient(ctx context.Context, raw net.Conn, publicKey, shortID []byte, serverName string) (net.Conn, error) {
	return realityClient(ctx, raw, publicKey, shortID, serverName, true)
}
func realityClient(ctx context.Context, raw net.Conn, publicKey, shortID []byte, serverName string, legacy bool) (net.Conn, error) {
	var authKey []byte
	cfg := &utls.Config{ServerName: serverName, InsecureSkipVerify: true, SessionTicketsDisabled: true, VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("missing REALITY certificate")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		key, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("received fallback certificate")
		}
		mac := hmac.New(sha512.New, authKey)
		mac.Write(key)
		if !hmac.Equal(mac.Sum(nil), cert.Signature) {
			return errors.New("invalid REALITY certificate authentication")
		}
		return nil
	}}
	c := utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	if err := c.BuildHandshakeState(); err != nil {
		return nil, err
	}
	if legacy {
		for _, extension := range c.Extensions {
			if e, ok := extension.(*utls.SupportedCurvesExtension); ok {
				var curves []utls.CurveID
				for _, curve := range e.Curves {
					if curve != utls.X25519MLKEM768 {
						curves = append(curves, curve)
					}
				}
				e.Curves = curves
			}
			if e, ok := extension.(*utls.KeyShareExtension); ok {
				var shares []utls.KeyShare
				for _, share := range e.KeyShares {
					if share.Group != utls.X25519MLKEM768 {
						shares = append(shares, share)
					}
				}
				e.KeyShares = shares
			}
		}
		if err := c.BuildHandshakeState(); err != nil {
			return nil, err
		}
	}
	hello := c.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2] = 26, 11, 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID)
	pub, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	key := c.HandshakeState.State13.KeyShareKeys.Ecdhe
	if key == nil {
		key = c.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if key == nil {
		return nil, errors.New("missing TLS 1.3 key share")
	}
	shared, err := key.ECDH(pub)
	if err != nil {
		return nil, err
	}
	authKey, err = hkdf.Key(sha256.New, shared, hello.Random[:20], "REALITY", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if err = c.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

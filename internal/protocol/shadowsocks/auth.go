// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	SS "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	"github.com/sagernet/sing/common/buf"
	"golang.org/x/crypto/chacha20poly1305"
)

type compiledUser struct {
	ref     string
	key     []byte
	method  *shadowaead.Method
	service SS.Service
}

func (s *Server) initUsers(r protocol.ResolvedListenerSpec, methodName string) error {
	s.tcpScan = authscan.NewSelector(authscan.HashAddr, authscan.GuardOptions{})
	s.udpScan = authscan.NewSelector(authscan.HashAddrPort, authscan.GuardOptions{})
	for _, ref := range r.Spec.CredentialRefs {
		secret := r.Credentials[ref]
		method, err := shadowaead.New(methodName, nil, string(secret))
		if err != nil {
			return err
		}
		service, err := shadowaead.NewService(methodName, nil, string(secret), int64(s.limits.UDPIdleTimeout.Seconds()), s)
		if err != nil {
			return err
		}
		s.users = append(s.users, compiledUser{ref: ref, key: SS.Key(secret, s.saltSize), method: method, service: service})
	}
	s.method = s.users[0].method
	return nil
}
func (u *compiledUser) checkHeader(salt, encrypted []byte) bool {
	key := buf.NewSize(len(u.key))
	defer key.Release()
	shadowaead.Kdf(u.key, salt, key)
	var aead cipher.AEAD
	if u.method.Name() == "chacha20-ietf-poly1305" {
		aead, _ = chacha20poly1305.New(key.Bytes())
	} else {
		block, _ := aes.NewCipher(key.Bytes())
		aead, _ = cipher.NewGCM(block)
	}
	var nonce [12]byte
	var plain [2]byte
	_, err := aead.Open(plain[:0], nonce[:], encrypted, nil)
	return err == nil
}
func (s *Server) replayKey(user int, salt []byte) []byte {
	key := make([]byte, 4+len(salt))
	binary.BigEndian.PutUint32(key, uint32(user))
	copy(key[4:], salt)
	return key
}

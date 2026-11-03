// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/authscan"
	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	keyRefreshInterval = 2 * time.Minute
	keyIterations      = 64
)

type epochKeys struct {
	epoch int64
	aead  [3]cipherAEAD
}

type cipherAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

type compiledUser struct {
	id         uint32
	name       string
	credential [32]byte
	keyMu      sync.Mutex
	keys       atomic.Pointer[epochKeys]
}

type userSnapshot struct {
	users     []*compiledUser
	mandatory bool
	scan      *authscan.Selector[netip.Addr]
}

func (s *userSnapshot) active(user *compiledUser) bool {
	if s == nil || user == nil {
		return false
	}
	index := sort.Search(len(s.users), func(index int) bool { return s.users[index].name >= user.name })
	return index < len(s.users) && s.users[index].name == user.name && s.users[index].credential == user.credential
}

func PrepareUsers(users []User) (*PreparedUsers, error) {
	if len(users) == 0 {
		return nil, ErrInvalidOptions
	}
	byName := make(map[string]User, len(users))
	for _, user := range users {
		if user.Name == "" || user.Password == "" {
			return nil, ErrInvalidOptions
		}
		byName[user.Name] = user
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	snapshot := &userSnapshot{users: make([]*compiledUser, 0, len(names)), scan: newAuthSelector()}
	for index, name := range names {
		credential := hashPassword([]byte(byName[name].Password), []byte(name))
		user := &compiledUser{id: uint32(index + 1), name: name, credential: credential}
		if _, err := user.keysAt(time.Now()); err != nil {
			return nil, err
		}
		snapshot.users = append(snapshot.users, user)
	}
	return &PreparedUsers{snapshot: snapshot}, nil
}

func hashPassword(password, unique []byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write(password)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(unique)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (u *compiledUser) keysAt(now time.Time) (*epochKeys, error) {
	epoch := now.Round(keyRefreshInterval).Unix()
	if current := u.keys.Load(); current != nil && current.epoch == epoch {
		return current, nil
	}
	u.keyMu.Lock()
	defer u.keyMu.Unlock()
	if current := u.keys.Load(); current != nil && current.epoch == epoch {
		return current, nil
	}
	set := &epochKeys{epoch: epoch}
	for index, offset := range [...]int64{-1, 0, 1} {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], uint64(epoch+offset*int64(keyRefreshInterval/time.Second)))
		salt := sha256.Sum256(encoded[:])
		key := pbkdf2.Key(u.credential[:], salt[:], keyIterations, chacha20poly1305.KeySize, sha256.New)
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		set.aead[index] = aead
	}
	u.keys.Store(set)
	return set, nil
}

func hintMatches(name string, nonce []byte) bool {
	if len(nonce) < nonceSize {
		return false
	}
	input := append([]byte(name), nonce[:16]...)
	value := sha256.Sum256(input)
	return bytes.Equal(value[:4], nonce[nonceSize-4:])
}

func applyHint(name string, nonce []byte) {
	value := userHintDigest(name, nonce)
	copy(nonce[nonceSize-4:], value[:4])
}

func userHintDigest(name string, nonce []byte) [32]byte {
	if len(name) <= 48 {
		var local [64]byte
		copy(local[:], name)
		copy(local[len(name):], nonce[:16])
		return sha256.Sum256(local[:len(name)+16])
	}
	if len(name) <= 112 {
		var local [128]byte
		copy(local[:], name)
		copy(local[len(name):], nonce[:16])
		return sha256.Sum256(local[:len(name)+16])
	}
	if len(name) <= 240 {
		var local [256]byte
		copy(local[:], name)
		copy(local[len(name):], nonce[:16])
		return sha256.Sum256(local[:len(name)+16])
	}
	input := make([]byte, len(name)+16)
	copy(input, name)
	copy(input[len(name):], nonce[:16])
	return sha256.Sum256(input)
}

type userMatch struct {
	epoch   int64
	verdict *authscan.Match[netip.Addr]
	user    *compiledUser
	aead    cipherAEAD
	text    []byte
}

func (s *userSnapshot) discover(ciphertext, dst []byte, source net.Addr) (userMatch, error) {
	if s == nil || len(ciphertext) < nonceSize+authTagSize {
		return userMatch{}, errors.New("mieru: invalid encrypted metadata")
	}
	nonce := ciphertext[:nonceSize]
	var selected userMatch
	attempt := func(hinted bool) func(int) bool {
		return func(index int) bool {
			user := s.users[index]
			if hintMatches(user.name, nonce) != hinted {
				return false
			}
			var ok bool
			selected, ok = tryUser(user, ciphertext, dst)
			return ok
		}
	}
	phases := []func(int) bool{attempt(true)}
	if !s.mandatory {
		phases = append(phases, attempt(false))
	}
	verdict, err := s.scan.FindPhased(ingress.AddressIP(source), len(s.users), phases...)
	if err != nil {
		return userMatch{}, err
	}
	selected.verdict = verdict
	return selected, nil
}

func newAuthSelector() *authscan.Selector[netip.Addr] {
	return authscan.NewSelector(authscan.HashAddr, authscan.GuardOptions{WorkRate: 1 << 18})
}

func tryUser(user *compiledUser, ciphertext, dst []byte) (userMatch, bool) {
	keys, err := user.keysAt(time.Now())
	if err != nil {
		return userMatch{}, false
	}
	nonce := ciphertext[:nonceSize]
	body := ciphertext[nonceSize:]
	for index, aead := range keys.aead {
		plaintext, openErr := aead.Open(dst, nonce, body, nil)
		if openErr == nil {
			return userMatch{user: user, aead: aead, text: plaintext, epoch: keys.epoch + int64(index-1)*int64(keyRefreshInterval/time.Second)}, true
		}
	}
	return userMatch{}, false
}

type streamCipher struct {
	aead  cipherAEAD
	nonce [nonceSize]byte
	set   bool
}

func (c *streamCipher) decrypt(dst, ciphertext []byte) ([]byte, error) {
	body := ciphertext
	if !c.set {
		if len(ciphertext) < nonceSize+authTagSize {
			return nil, errors.New("mieru: short stream ciphertext")
		}
		copy(c.nonce[:], ciphertext[:nonceSize])
		body = ciphertext[nonceSize:]
		c.set = true
	} else {
		incrementNonce(c.nonce[:])
	}
	return c.aead.Open(dst, c.nonce[:], body, nil)
}

func (c *streamCipher) encrypt(dst, plaintext []byte, userName string, pattern *trafficPattern) ([]byte, error) {
	if !c.set {
		if _, err := rand.Read(c.nonce[:]); err != nil {
			return nil, err
		}
		pattern.rewriteNonce(c.nonce[:])
		applyHint(userName, c.nonce[:])
		dst = append(dst, c.nonce[:]...)
		c.set = true
	} else {
		incrementNonce(c.nonce[:])
	}
	return c.aead.Seal(dst, c.nonce[:], plaintext, nil), nil
}

func incrementNonce(nonce []byte) {
	for index := len(nonce) - 1; index >= 0; index-- {
		nonce[index]++
		if nonce[index] != 0 {
			return
		}
	}
}

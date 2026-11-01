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
	cache     *sourceCache
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
	snapshot := &userSnapshot{users: make([]*compiledUser, 0, len(names)), cache: newSourceCache()}
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
	user *compiledUser
	aead cipherAEAD
	text []byte
}

func (s *userSnapshot) discover(ciphertext, dst []byte, source net.Addr) (userMatch, error) {
	if s == nil || len(ciphertext) < nonceSize+authTagSize {
		return userMatch{}, errors.New("mieru: invalid encrypted metadata")
	}
	nonce := ciphertext[:nonceSize]
	candidates, candidateCount := s.cache.lookup(source)
	var attempted [sourceCacheUsers]uint32
	attemptedCount := 0
	for _, hinted := range []bool{true, false} {
		if !hinted && s.mandatory {
			break
		}
		for index := 0; index < candidateCount; index++ {
			user := candidates[index]
			if user == nil || hintMatches(user.name, nonce) != hinted {
				continue
			}
			if attemptedCount < len(attempted) {
				attempted[attemptedCount] = user.id
				attemptedCount++
			}
			if match, ok := tryUser(user, ciphertext, dst); ok {
				s.cache.record(source, user)
				return match, nil
			}
		}
		for _, user := range s.users {
			seen := false
			for index := 0; index < attemptedCount; index++ {
				if attempted[index] == user.id {
					seen = true
					break
				}
			}
			if seen || hintMatches(user.name, nonce) != hinted {
				continue
			}
			if match, ok := tryUser(user, ciphertext, dst); ok {
				s.cache.record(source, user)
				return match, nil
			}
		}
	}
	return userMatch{}, errors.New("mieru: authentication failed")
}

func tryUser(user *compiledUser, ciphertext, dst []byte) (userMatch, bool) {
	keys, err := user.keysAt(time.Now())
	if err != nil {
		return userMatch{}, false
	}
	nonce := ciphertext[:nonceSize]
	body := ciphertext[nonceSize:]
	for _, aead := range keys.aead {
		plaintext, openErr := aead.Open(dst, nonce, body, nil)
		if openErr == nil {
			return userMatch{user: user, aead: aead, text: plaintext}, true
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

const (
	sourceCacheSize     = 8192
	sourceCacheUsers    = 8
	sourceCacheLifetime = 10 * time.Minute
)

type sourceCache struct {
	table atomic.Pointer[sourceCacheTable]
}

type sourceCacheTable [sourceCacheSize]atomic.Pointer[sourceCacheEntry]

type sourceCacheEntry struct {
	key     [16]byte
	expires int64
	users   [sourceCacheUsers]*compiledUser
	count   uint8
}

func newSourceCache() *sourceCache { return new(sourceCache) }

func sourceKey(address net.Addr) ([16]byte, bool) {
	var ip net.IP
	switch value := address.(type) {
	case *net.TCPAddr:
		ip = value.IP
	case *net.UDPAddr:
		ip = value.IP
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return [16]byte{}, false
	}
	return parsed.Unmap().As16(), true
}

func (c *sourceCache) lookup(address net.Addr) ([sourceCacheUsers]*compiledUser, int) {
	var empty [sourceCacheUsers]*compiledUser
	key, ok := sourceKey(address)
	if c == nil || !ok {
		return empty, 0
	}
	table := c.table.Load()
	if table == nil {
		return empty, 0
	}
	entry := table[sourceCacheIndex(key)].Load()
	if entry == nil || entry.key != key || time.Now().UnixNano() >= entry.expires {
		return empty, 0
	}
	return entry.users, int(entry.count)
}

func (c *sourceCache) record(address net.Addr, user *compiledUser) {
	key, ok := sourceKey(address)
	if c == nil || !ok || user == nil {
		return
	}
	table := c.table.Load()
	if table == nil {
		fresh := new(sourceCacheTable)
		if c.table.CompareAndSwap(nil, fresh) {
			table = fresh
		} else {
			table = c.table.Load()
		}
	}
	slot := &table[sourceCacheIndex(key)]
	for {
		current := slot.Load()
		now := time.Now()
		if current != nil && current.key == key && current.count != 0 && current.users[0] == user &&
			current.expires-now.UnixNano() > int64(sourceCacheLifetime/2) {
			return
		}
		next := &sourceCacheEntry{key: key, expires: now.Add(sourceCacheLifetime).UnixNano(), count: 1}
		next.users[0] = user
		if current != nil && current.key == key && now.UnixNano() < current.expires {
			for index := 0; index < int(current.count) && int(next.count) < len(next.users); index++ {
				if current.users[index] == user {
					continue
				}
				next.users[next.count] = current.users[index]
				next.count++
			}
		}
		if slot.CompareAndSwap(current, next) {
			return
		}
	}
}

func sourceCacheIndex(key [16]byte) int {
	value := uint32(2166136261)
	for _, part := range key {
		value = (value ^ uint32(part)) * 16777619
	}
	return int(value & (sourceCacheSize - 1))
}

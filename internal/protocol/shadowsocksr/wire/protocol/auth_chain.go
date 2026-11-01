// Copyright 2015-2016 Break Wa11 and ShadowsocksR contributors
// SPDX-License-Identifier: GPL-3.0-only
//
// The auth_chain_c-f salts, generated length tables and padding choices derive
// from ShadowsocksR-Live/shadowsocksr-native src/obfs/auth_chain.c at
// 227127c4bc5a6555e0556693d084c96860e75b5e (tag 0.9.4).
// Modified by Polaris contributors, 2026-07-31 to 2026-08-28: adapted onto the
// local auth_chain_a core and rewritten for this module; see MODIFICATIONS.md.

package protocol

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/replay"
)

const defaultChainFInterval = int64(24 * 60 * 60)

type authChainDefinition struct {
	name              string
	serverKey         []byte
	users             map[[4]byte]Credential
	now               func() time.Time
	sessions          *replay.Sessions
	param             string
	transportOverhead int
	maxClients        int
	dummy             Credential
	workPool          sync.Pool
	profileMu         sync.Mutex
	profiles          atomic.Pointer[chainProfiles]
	fInterval         int64
}

func newAuthChainDefinition(config Config) *authChainDefinition {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	definition := &authChainDefinition{name: config.Name, serverKey: config.ServerKey, users: config.Users,
		now: now, sessions: config.Sessions, param: config.ProtocolParam, transportOverhead: config.TransportOverhead,
		maxClients: parseMaxClients(config.ProtocolParam)}
	definition.dummy = Credential{Key: make([]byte, md5.Size), HeaderKey: make([]byte, 16)}
	definition.workPool.New = func() any { return newChainWork() }
	if definition.name == "auth_chain_f" {
		definition.fInterval = parseChainFInterval(definition.param)
	}
	definition.profiles.Store(definition.buildProfiles(now()))
	return definition
}

func (*authChainDefinition) Metadata() Metadata { return Metadata{UserFromWire: true} }

func (*authChainDefinition) Overhead() int { return 4 }

func (d *authChainDefinition) NewStream(_ []byte) Stream {
	return &authChainStream{
		definition: d,
		profile:    d.paddingProfile(false),
		work:       d.workPool.Get().(*chainWork),
		packID:     1,
		receiveID:  1,
		unitLength: 2800,
	}
}

func (d *authChainDefinition) DecodePacket(_ []byte, packet, _ []byte) ([]byte, [4]byte, error) {
	if len(packet) <= 8 {
		return nil, [4]byte{}, ErrAuthentication
	}
	authData := packet[len(packet)-8 : len(packet)-5]
	work := d.workPool.Get().(*chainWork)
	defer d.workPool.Put(work)
	var headerHash [md5.Size]byte
	copy(headerHash[:], work.mac.sum(d.serverKey, authData))
	encodedID := binary.LittleEndian.Uint32(packet[len(packet)-5 : len(packet)-1])
	var userID [4]byte
	binary.LittleEndian.PutUint32(userID[:], encodedID^binary.LittleEndian.Uint32(headerHash[:4]))
	credential, loaded := d.users[userID]
	if !loaded {
		credential = d.dummy
	}
	valid := validLegacyMAC(work.mac.sum(credential.Key, packet[:len(packet)-1]), packet[len(packet)-1:], 1)
	if !loaded {
		return nil, [4]byte{}, ErrUnknownUser
	}
	if !valid {
		return nil, [4]byte{}, ErrAuthentication
	}
	var random xorshift128Plus
	paddingLength := d.paddingProfile(true).udpLength(headerHash[:], &random)
	if paddingLength > len(packet)-8 {
		return nil, [4]byte{}, ErrAuthentication
	}
	payload := packet[:len(packet)-8-paddingLength]
	stream, err := work.newRC4(credential.Key, headerHash[:])
	if err != nil {
		return nil, [4]byte{}, err
	}
	stream.XORKeyStream(payload, payload)
	return payload, userID, nil
}

func (d *authChainDefinition) EncodePacket(dst, payload []byte, userID [4]byte, _ []byte) ([]byte, error) {
	credential, loaded := d.users[userID]
	if !loaded {
		return nil, ErrUnknownUser
	}
	var authData [7]byte
	if _, err := io.ReadFull(rand.Reader, authData[:]); err != nil {
		return nil, err
	}
	work := d.workPool.Get().(*chainWork)
	defer d.workPool.Put(work)
	var headerHash [md5.Size]byte
	copy(headerHash[:], work.mac.sum(d.serverKey, authData[:]))
	var random xorshift128Plus
	paddingLength := d.paddingProfile(true).udpLength(headerHash[:], &random)
	stream, err := work.newRC4(credential.Key, headerHash[:])
	if err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, payload...)
	stream.XORKeyStream(dst[start:], payload)
	paddingStart := len(dst)
	dst = append(dst, make([]byte, paddingLength)...)
	if _, err = io.ReadFull(rand.Reader, dst[paddingStart:]); err != nil {
		return nil, err
	}
	dst = append(dst, authData[:]...)
	return append(dst, work.mac.sum(credential.Key, dst[start:])[0]), nil
}

type chainProfiles struct {
	epoch  int64
	packet chainPadding
	stream chainPadding
}

func (d *authChainDefinition) buildProfiles(now time.Time) *chainProfiles {
	epoch := int64(0)
	if d.name == "auth_chain_f" {
		epoch = now.Unix() / d.fInterval
	}
	return &chainProfiles{
		epoch:  epoch,
		packet: newChainPadding(d.name, d.serverKey, d.param, now, 4),
		stream: newChainPadding(d.name, d.serverKey, d.param, now, 4+d.transportOverhead),
	}
}

func (d *authChainDefinition) paddingProfile(packet bool) chainPadding {
	profiles := d.profiles.Load()
	if d.name == "auth_chain_f" {
		now := d.now()
		epoch := now.Unix() / d.fInterval
		if profiles.epoch != epoch {
			d.profileMu.Lock()
			profiles = d.profiles.Load()
			if profiles.epoch != epoch {
				profiles = d.buildProfiles(now)
				d.profiles.Store(profiles)
			}
			d.profileMu.Unlock()
		}
	}
	if packet {
		return profiles.packet
	}
	return profiles.stream
}

type authChainStream struct {
	definition     *authChainDefinition
	profile        chainPadding
	work           *chainWork
	readIV         []byte
	receive        receiveBuffer
	userID         [4]byte
	userKey        []byte
	clientID       uint32
	lastClient     [md5.Size]byte
	lastServer     [md5.Size]byte
	clientRandom   xorshift128Plus
	serverRandom   xorshift128Plus
	readCipher     *rc4.Cipher
	writeCipher    *rc4.Cipher
	packID         uint32
	receiveID      uint32
	unitLength     int
	clientOverhead int
	sessionActive  bool
	authenticated  bool
	receivedHead   bool
	wroteHead      bool
}

func (s *authChainStream) SetReadIV(iv []byte) { s.readIV = append(s.readIV[:0], iv...) }

func (s *authChainStream) Decode(dst, input []byte) (result []byte, borrowed, reply bool, err error) {
	received, inputBorrowed := s.receive.feed(input)
	defer func() { s.receive.commit(received, inputBorrowed) }()
	result = dst
	if !s.receivedHead {
		if len(received) < 12 {
			return result, false, false, nil
		}
		clientHash := s.work.mac.sumJoined(s.readIV, s.definition.serverKey, received[:4])
		if !validLegacyMAC(clientHash, received[4:12], 8) {
			return nil, false, false, ErrAuthentication
		}
		if len(received) < 36 {
			return result, false, false, nil
		}
		copy(s.lastClient[:], clientHash)
		encodedID := binary.LittleEndian.Uint32(received[12:16])
		binary.LittleEndian.PutUint32(s.userID[:], encodedID^binary.LittleEndian.Uint32(clientHash[8:12]))
		credential, loaded := s.definition.users[s.userID]
		if !loaded {
			credential = s.definition.dummy
		}
		serverHash := s.work.mac.sum(credential.Key, received[12:32])
		serverValid := validLegacyMAC(serverHash, received[32:36], 4)
		copy(s.lastServer[:], serverHash)
		header, decryptErr := decryptAESHeader(credential.HeaderKey, received[16:32])
		if decryptErr != nil {
			return nil, false, false, decryptErr
		}
		if !loaded {
			return nil, false, false, ErrUnknownUser
		}
		if !serverValid {
			return nil, false, false, ErrAuthentication
		}
		s.clientOverhead = int(binary.LittleEndian.Uint16(header[12:14]))
		if s.clientOverhead >= 1460 {
			return nil, false, false, ErrAuthentication
		}
		timestamp := binary.LittleEndian.Uint32(header[:4])
		if absoluteInt32(int32(timestamp-uint32(s.definition.now().Unix()))) > 24*60*60 {
			return nil, false, false, ErrAuthentication
		}
		clientID := binary.LittleEndian.Uint32(header[4:8])
		connectionID := binary.LittleEndian.Uint32(header[8:12])
		if s.definition.sessions == nil || !s.definition.sessions.Accept(s.userID, clientID, connectionID, s.definition.maxClients) {
			return nil, false, false, ErrAuthentication
		}
		s.clientID = clientID
		s.sessionActive = true
		s.userKey = credential.Key
		var cipherKey [md5.Size]byte
		s.work.rc4Key(cipherKey[:], s.userKey, s.lastClient[:])
		s.readCipher, err = rc4.NewCipher(cipherKey[:])
		if err != nil {
			return nil, false, false, err
		}
		s.writeCipher, err = rc4.NewCipher(cipherKey[:])
		if err != nil {
			return nil, false, false, err
		}
		received = received[36:]
		s.receivedHead = true
		s.authenticated = true
		reply = true
	}
	for len(received) > 4 {
		dataLength := int(binary.LittleEndian.Uint16(received[:2]) ^ binary.LittleEndian.Uint16(s.lastClient[14:16]))
		paddingLength := s.profile.dataLength(dataLength, s.lastClient[:], &s.clientRandom)
		bodyLength := dataLength + paddingLength
		if bodyLength >= 4096 {
			return nil, false, false, ErrAuthentication
		}
		if bodyLength+4 > len(received) {
			break
		}
		clientHash := s.work.mac.sumSequence(s.userKey, s.receiveID, received[:bodyLength+2])
		if !validLegacyMAC(clientHash, received[bodyLength+2:bodyLength+4], 2) {
			return nil, false, false, ErrAuthentication
		}
		position := 2
		if dataLength > 0 && paddingLength > 0 {
			position += s.clientRandom.startPosition(paddingLength)
		}
		if position < 2 || position+dataLength > bodyLength+2 {
			return nil, false, false, ErrAuthentication
		}
		ciphertext := received[position : position+dataLength]
		s.readCipher.XORKeyStream(ciphertext, ciphertext)
		result = append(result, ciphertext...)
		copy(s.lastClient[:], clientHash)
		received = received[bodyLength+4:]
		s.receiveID++
		reply = reply || dataLength == 0
	}
	return result, false, reply, nil
}

func (s *authChainStream) Encode(dst, payload []byte) ([]byte, error) {
	if s.writeCipher == nil {
		return nil, ErrAuthentication
	}
	if !s.wroteHead {
		const tcpMSS = 1460
		var mss [2]byte
		binary.LittleEndian.PutUint16(mss[:], tcpMSS)
		payload = append(mss[:], payload...)
		s.unitLength = tcpMSS - s.clientOverhead
		s.wroteHead = true
	}
	for len(payload) > s.unitLength {
		var err error
		dst, err = s.appendFrame(dst, payload[:s.unitLength])
		if err != nil {
			return nil, err
		}
		payload = payload[s.unitLength:]
	}
	return s.appendFrame(dst, payload)
}

func (s *authChainStream) appendFrame(dst, payload []byte) ([]byte, error) {
	paddingLength := s.profile.dataLength(len(payload), s.lastServer[:], &s.serverRandom)
	bodyLength := len(payload) + paddingLength
	start := len(dst)
	dst = append(dst, make([]byte, bodyLength+4)...)
	frame := dst[start:]
	binary.LittleEndian.PutUint16(frame[:2], uint16(len(payload))^binary.LittleEndian.Uint16(s.lastServer[14:16]))
	position := 2
	if len(payload) > 0 && paddingLength > 0 {
		position += s.serverRandom.startPosition(paddingLength)
	}
	if _, err := io.ReadFull(rand.Reader, frame[2:2+paddingLength]); err != nil {
		return nil, err
	}
	copy(frame[position:], payload)
	s.writeCipher.XORKeyStream(frame[position:position+len(payload)], payload)
	serverHash := s.work.mac.sumSequence(s.userKey, s.packID, frame[:bodyLength+2])
	copy(frame[bodyLength+2:], serverHash[:2])
	copy(s.lastServer[:], serverHash)
	s.packID++
	return dst, nil
}

func (s *authChainStream) UserID() ([4]byte, bool) { return s.userID, s.authenticated }

func (s *authChainStream) Close() {
	s.receive.release()
	if s.work != nil {
		s.definition.workPool.Put(s.work)
		s.work = nil
	}
	if s.sessionActive {
		s.definition.sessions.Release(s.userID, s.clientID)
		s.sessionActive = false
	}
}

type chainWork struct {
	mac      *legacyMAC
	password []byte
}

func newChainWork() *chainWork {
	return &chainWork{mac: newLegacyMAC(md5.New)}
}

func (w *chainWork) rc4Key(dst, userKey, hashValue []byte) {
	userEncoded := base64.StdEncoding.EncodedLen(len(userKey))
	hashEncoded := base64.StdEncoding.EncodedLen(len(hashValue))
	required := userEncoded + hashEncoded
	if cap(w.password) < required {
		w.password = make([]byte, required)
	} else {
		w.password = w.password[:required]
	}
	base64.StdEncoding.Encode(w.password[:userEncoded], userKey)
	base64.StdEncoding.Encode(w.password[userEncoded:], hashValue)
	copy(dst, w.mac.digestParts(w.password, nil))
}

func (w *chainWork) newRC4(userKey, hashValue []byte) (*rc4.Cipher, error) {
	var key [md5.Size]byte
	w.rc4Key(key[:], userKey, hashValue)
	return rc4.NewCipher(key[:])
}

type xorshift128Plus struct {
	v0 uint64
	v1 uint64
}

func (x *xorshift128Plus) next() uint64 {
	left, right := x.v0, x.v1
	x.v0 = right
	left ^= (left & ((uint64(1) << 41) - 1)) << 23
	left ^= right ^ (left >> 17) ^ (right >> 26)
	x.v1 = left
	return left + right
}

func (x *xorshift128Plus) init(hashValue []byte) {
	var seed [16]byte
	copy(seed[:], hashValue)
	x.v0 = binary.LittleEndian.Uint64(seed[:8])
	x.v1 = binary.LittleEndian.Uint64(seed[8:])
}

func (x *xorshift128Plus) initLength(hashValue []byte, length int) {
	var seed [16]byte
	copy(seed[:], hashValue)
	binary.LittleEndian.PutUint16(seed[:2], uint16(length))
	x.v0 = binary.LittleEndian.Uint64(seed[:8])
	x.v1 = binary.LittleEndian.Uint64(seed[8:])
	for range 4 {
		x.next()
	}
}

func (x *xorshift128Plus) startPosition(paddingLength int) int {
	if paddingLength <= 0 {
		return 0
	}
	return int(x.next() % 8589934609 % uint64(paddingLength))
}

type chainPadding struct {
	method   string
	first    []int
	second   []int
	overhead int
}

func newChainPadding(method string, serverKey []byte, param string, now time.Time, overhead int) chainPadding {
	profile := chainPadding{method: method, overhead: overhead}
	if method == "auth_chain_a" {
		return profile
	}
	key := slices.Clone(serverKey)
	if method == "auth_chain_f" {
		interval := parseChainFInterval(param)
		if len(key) < 8 {
			key = append(key, make([]byte, 8-len(key))...)
		}
		var epoch [8]byte
		binary.BigEndian.PutUint64(epoch[:], uint64(now.Unix()/interval))
		for index := range epoch {
			key[index] ^= epoch[index]
		}
	}
	var random xorshift128Plus
	random.init(key)
	if method == "auth_chain_b" {
		profile.first = make([]int, int(random.next()%8+4))
		for index := range profile.first {
			profile.first[index] = int(random.next() % 2340 % 2040 % 1440)
		}
		sort.Ints(profile.first)
		profile.second = make([]int, int(random.next()%16+8))
		for index := range profile.second {
			profile.second[index] = int(random.next() % 2340 % 2040 % 1440)
		}
		sort.Ints(profile.second)
		return profile
	}
	profile.first = make([]int, int(random.next()%24+12), 64)
	for index := range profile.first {
		profile.first[index] = int(random.next() % 2340 % 2040 % 1440)
	}
	sort.Ints(profile.first)
	if method == "auth_chain_c" {
		return profile
	}
	for len(profile.first) < 64 && profile.first[len(profile.first)-1] < 1300 {
		profile.first = append(profile.first, int(random.next()%2340%2040%1440))
	}
	sort.Ints(profile.first)
	return profile
}

func (p chainPadding) dataLength(payloadLength int, lastHash []byte, random *xorshift128Plus) int {
	switch p.method {
	case "auth_chain_b":
		return p.lengthB(payloadLength, lastHash, random)
	case "auth_chain_c":
		return p.lengthC(payloadLength, lastHash, random)
	case "auth_chain_d":
		return p.lengthD(payloadLength, lastHash, random)
	case "auth_chain_e", "auth_chain_f":
		return p.lengthE(payloadLength, lastHash, random)
	}
	if payloadLength > 1440 {
		return 0
	}
	random.initLength(lastHash, payloadLength)
	return fallbackChainLength(payloadLength, random)
}

func (p chainPadding) udpLength(lastHash []byte, random *xorshift128Plus) int {
	random.init(lastHash)
	return int(random.next() % 127)
}

func (p chainPadding) lengthB(size int, lastHash []byte, random *xorshift128Plus) int {
	if size >= 1440 {
		return 0
	}
	random.initLength(lastHash, size)
	position := sort.SearchInts(p.first, size+p.overhead)
	final := position + int(random.next()%uint64(len(p.first)))
	if final < len(p.first) {
		return p.first[final] - size - p.overhead
	}
	position = sort.SearchInts(p.second, size+p.overhead)
	final = position + int(random.next()%uint64(len(p.second)))
	if final < len(p.second) {
		return p.second[final] - size - p.overhead
	}
	if final < position+len(p.second)-1 {
		return 0
	}
	return fallbackChainLength(size, random)
}

func (p chainPadding) lengthC(size int, lastHash []byte, random *xorshift128Plus) int {
	random.initLength(lastHash, size)
	other := size + p.overhead
	if other >= p.first[len(p.first)-1] {
		return fallbackChainLength(size, random)
	}
	position := sort.SearchInts(p.first, other)
	position += int(random.next() % uint64(len(p.first)-position))
	return p.first[position] - other
}

func (p chainPadding) lengthD(size int, lastHash []byte, random *xorshift128Plus) int {
	other := size + p.overhead
	if other >= p.first[len(p.first)-1] {
		return 0
	}
	random.initLength(lastHash, size)
	position := sort.SearchInts(p.first, other)
	position += int(random.next() % uint64(len(p.first)-position))
	return p.first[position] - other
}

func (p chainPadding) lengthE(size int, lastHash []byte, random *xorshift128Plus) int {
	random.initLength(lastHash, size)
	other := size + p.overhead
	if other >= p.first[len(p.first)-1] {
		return 0
	}
	return p.first[sort.SearchInts(p.first, other)] - other
}

func fallbackChainLength(size int, random *xorshift128Plus) int {
	switch {
	case size > 1440:
		return 0
	case size > 1300:
		return int(random.next() % 31)
	case size > 900:
		return int(random.next() % 127)
	case size > 400:
		return int(random.next() % 521)
	default:
		return int(random.next() % 1021)
	}
}

func parseChainFInterval(param string) int64 {
	_, value, found := strings.Cut(param, "#")
	if !found || len(value) <= 2 {
		return defaultChainFInterval
	}
	if end := strings.IndexByte(value, '#'); end >= 0 {
		value = value[:end]
	}
	value = strings.TrimLeft(value, " \t\n\v\f\r")
	if value == "" || value[0] == '-' {
		return defaultChainFInterval
	}
	if value[0] == '+' {
		value = value[1:]
		if value == "" {
			return defaultChainFInterval
		}
	}
	base := 10
	digits := value
	if len(value) >= 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') {
		base = 16
		digits = value[2:]
	} else if value[0] == '0' {
		base = 8
	}
	length := 0
	for length < len(digits) {
		digit := chainDigit(digits[length])
		if digit < 0 || digit >= base {
			break
		}
		length++
	}
	if length == 0 {
		return defaultChainFInterval
	}
	parsed, err := strconv.ParseUint(digits[:length], base, 64)
	if err != nil || parsed == 0 || parsed >= uint64(math.MaxInt64) {
		return defaultChainFInterval
	}
	return int64(parsed)
}

func chainDigit(value byte) int {
	switch {
	case value >= '0' && value <= '9':
		return int(value - '0')
	case value >= 'a' && value <= 'z':
		return int(value-'a') + 10
	case value >= 'A' && value <= 'Z':
		return int(value-'A') + 10
	default:
		return -1
	}
}

func parseMaxClients(param string) int {
	prefix, _, _ := strings.Cut(param, "#")
	parsed, err := strconv.ParseInt(strings.TrimSpace(prefix), 10, strconv.IntSize)
	if err != nil || parsed <= 0 {
		return 64
	}
	return int(parsed)
}

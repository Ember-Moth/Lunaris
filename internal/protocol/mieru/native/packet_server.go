// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

type packetSessionKey struct {
	remote packetRemoteKey
	id     uint32
}

type packetRemoteKey struct {
	address  netip.AddrPort
	zone     string
	fallback string
}

type packetNonceKey struct {
	remote packetRemoteKey
	user   string
}

func remoteKeyFrom(address net.Addr) packetRemoteKey {
	if udpAddress, ok := address.(*net.UDPAddr); ok {
		if parsed, valid := netip.AddrFromSlice(udpAddress.IP); valid && udpAddress.Port >= 0 && udpAddress.Port <= 65535 {
			return packetRemoteKey{address: netip.AddrPortFrom(parsed.Unmap(), uint16(udpAddress.Port)), zone: udpAddress.Zone}
		}
	}
	if address == nil {
		return packetRemoteKey{}
	}
	return packetRemoteKey{fallback: address.Network() + "\x00" + address.String()}
}

type remoteCipher struct {
	user     *compiledUser
	aead     cipherAEAD
	key      packetRemoteKey
	sessions atomic.Int64
}

type localPacketConn interface {
	ReadFromWithLocal([]byte) (int, net.Addr, net.Addr, error)
	WriteToWithLocal([]byte, net.Addr, net.Addr) (int, error)
}

func (s *Server) listenPacket() {
	defer s.wg.Done()
	buffer := make([]byte, 65535)
	for {
		var n int
		var remote, local net.Addr
		var err error
		if source, ok := s.packet.(localPacketConn); ok {
			n, remote, local, err = source.ReadFromWithLocal(buffer)
		} else {
			n, remote, err = s.packet.ReadFrom(buffer)
			local = s.packet.LocalAddr()
		}
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.report(err)
			}
			return
		}
		if n < packetHeaderSize || remote == nil {
			continue
		}
		packet := buffer[:n]
		seg, match, parseErr := s.parsePacket(packet, remote)
		if parseErr != nil {
			continue
		}
		remoteKey := remoteKeyFrom(remote)
		key := packetSessionKey{remote: remoteKey, id: seg.meta.sessionID}
		value, loaded := s.packetSessions.Load(key)
		if !loaded {
			if seg.meta.protocol != openSessionRequest || seg.meta.sessionID == 0 || match.user == nil {
				continue
			}
			if !s.users.Load().active(match.user) {
				continue
			}
			if s.replay.seen(packet[:nonceSize], remote) {
				continue
			}
			if !s.reserveSession() {
				continue
			}
			mtu := s.option.MTU
			if mtu <= 0 {
				mtu = defaultMTU
			}
			state := &remoteCipher{user: match.user, aead: match.aead, key: remoteKey}
			if existing, present := s.remoteCiphers.LoadOrStore(remoteKey, state); present {
				candidate := existing.(*remoteCipher)
				if candidate.user == match.user {
					state = candidate
				} else {
					s.remoteCiphers.Store(remoteKey, state)
				}
			}
			state.sessions.Add(1)
			created := newPacketSession(seg.meta.sessionID, match, s, remote, local, mtu, state)
			created.slot = true
			value, loaded = s.packetSessions.LoadOrStore(key, created)
			if !loaded {
				value = created
				if s.ctx.Err() != nil {
					created.closeRemote()
					return
				}
				created.accept(seg)
				response := created.nextOutbound(openSessionResponse, 0)
				if err = created.sendReliable(response, nil); err != nil {
					created.closeRemote()
					continue
				}
				select {
				case s.accepted <- created:
				case <-s.ctx.Done():
					return
				}
				continue
			}
			created.releaseRemoteState()
			s.releaseSession()
		}
		session := value.(*packetSession)
		if match.user != session.user {
			continue
		}
		if seg.meta.protocol == closeSessionRequest {
			_ = s.writePacket(metadata{protocol: closeSessionResponse, sessionID: session.id, seq: seg.meta.seq}, nil,
				session.aead, session.userName, remote, local)
			session.closeRemote()
			continue
		}
		if seg.meta.protocol == closeSessionResponse {
			session.closeRemote()
			continue
		}
		session.accept(seg)
	}
}

func (s *Server) parsePacket(packet []byte, remote net.Addr) (segment, userMatch, error) {
	encryptedMeta := packet[:packetHeaderSize]
	var match userMatch
	if cached, ok := s.remoteCiphers.Load(remoteKeyFrom(remote)); ok {
		known := cached.(*remoteCipher)
		plain, err := known.aead.Open(s.packetMetaScratch[:0], encryptedMeta[:nonceSize], encryptedMeta[nonceSize:], nil)
		if err == nil {
			match = userMatch{user: known.user, aead: known.aead, text: plain}
		}
	}
	if match.user == nil {
		var err error
		match, err = s.users.Load().discover(encryptedMeta, s.packetMetaScratch[:0], remote)
		if err != nil {
			return segment{}, userMatch{}, err
		}
	}
	meta, err := parseMetadata(match.text, time.Now())
	if err != nil {
		return segment{}, userMatch{}, err
	}
	remaining := packet[packetHeaderSize:]
	if int(meta.prefixLen) > len(remaining) {
		return segment{}, userMatch{}, errors.New("mieru: invalid packet prefix")
	}
	remaining = remaining[meta.prefixLen:]
	var payload []byte
	if meta.payloadLen != 0 {
		length := int(meta.payloadLen) + authTagSize
		if len(remaining) < length {
			return segment{}, userMatch{}, errors.New("mieru: incomplete packet payload")
		}
		payload, err = match.aead.Open(make([]byte, 0, meta.payloadLen), packet[:nonceSize], remaining[:length], nil)
		if err != nil {
			return segment{}, userMatch{}, err
		}
		remaining = remaining[length:]
	}
	if len(remaining) != int(meta.suffixLen) {
		return segment{}, userMatch{}, errors.New("mieru: invalid packet suffix")
	}
	return segment{meta: meta, payload: payload}, match, nil
}

func (s *Server) writePacket(meta metadata, payload []byte, aead cipherAEAD, userName string, remote, local net.Addr) error {
	if aead == nil || remote == nil {
		return ErrInvalidOptions
	}
	rewriteNonce := s.pattern.nonce.applyAll
	if !rewriteNonce {
		_, alreadyApplied := s.nonceApplied.LoadOrStore(packetNonceKey{remote: remoteKeyFrom(remote), user: userName}, struct{}{})
		rewriteNonce = !alreadyApplied
	}
	mtu := s.option.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}
	buffer := s.packetBuffers.Get().(*[]byte)
	output, err := sealPacketPattern((*buffer)[:0], meta, payload, aead, userName, s.pattern, rewriteNonce, mtu)
	if err != nil {
		s.packetBuffers.Put(buffer)
		return err
	}
	s.packetWrite.Lock()
	defer s.packetWrite.Unlock()
	if err = s.packet.SetWriteDeadline(time.Now().Add(s.option.WriteTimeout)); err != nil {
		s.packetBuffers.Put(buffer)
		return err
	}
	if source, ok := s.packet.(localPacketConn); ok && local != nil {
		_, err = source.WriteToWithLocal(output, remote, local)
	} else {
		_, err = s.packet.WriteTo(output, remote)
	}
	*buffer = output[:0]
	s.packetBuffers.Put(buffer)
	return err
}

func sealPacket(dst []byte, meta metadata, payload []byte, aead cipherAEAD, userName string) ([]byte, error) {
	return sealPacketPattern(dst, meta, payload, aead, userName, nil, false, 0)
}

func sealPacketPattern(dst []byte, meta metadata, payload []byte, aead cipherAEAD, userName string,
	pattern *trafficPattern, rewriteNonce bool, mtu int,
) ([]byte, error) {
	meta.payloadLen = uint16(len(payload))
	middleLength, endLength := 0, 0
	if pattern != nil {
		available := max(0, mtu-packetOverhead-len(payload))
		if meta.dataProtocol() {
			middleLength = pattern.paddingLength(min(pattern.middlePad, available))
			meta.prefixLen = byte(middleLength)
			available -= middleLength
		}
		endLength = pattern.paddingLength(min(pattern.endPad, available))
		meta.suffixLen = byte(endLength)
	}
	required := packetHeaderSize
	if len(payload) != 0 {
		required += len(payload) + authTagSize
	}
	required += middleLength + endLength
	start := len(dst)
	if cap(dst)-start < required {
		grown := make([]byte, start, start+required)
		copy(grown, dst)
		dst = grown
	}
	dst = dst[:start+nonceSize+metadataLength]
	nonce := dst[start : start+nonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if rewriteNonce {
		pattern.rewriteNonce(nonce)
	}
	applyHint(userName, nonce)
	plain := meta.marshal(dst[start+nonceSize:start+nonceSize], time.Now())
	dst = aead.Seal(dst[:start+nonceSize], nonce, plain, nil)
	var err error
	dst, err = appendRandom(dst, middleLength)
	if err != nil {
		return nil, err
	}
	if len(payload) != 0 {
		dst = aead.Seal(dst, nonce, payload, nil)
	}
	dst, err = appendRandom(dst, endLength)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func (s *Server) maintainPackets() {
	defer s.wg.Done()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			s.packetSessions.Range(func(_, value any) bool {
				value.(*packetSession).maintain(now)
				return true
			})
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Server) scheduleAck(session *packetSession) {
	if session == nil || !session.ackQueued.CompareAndSwap(false, true) {
		return
	}
	select {
	case s.ackQueue <- session:
	case <-s.ctx.Done():
		session.ackQueued.Store(false)
	}
}

func (s *Server) ackPackets() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	pending := make(map[*packetSession]struct{})
	for {
		select {
		case session := <-s.ackQueue:
			pending[session] = struct{}{}
		case <-ticker.C:
			for session := range pending {
				delete(pending, session)
				session.ackQueued.Store(false)
				select {
				case <-session.closed:
				default:
					session.sendAck()
				}
			}
		case <-s.ctx.Done():
			return
		}
	}
}

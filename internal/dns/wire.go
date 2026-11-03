// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

func makeQuery(name string, qType uint16) ([]byte, error) {
	encoded, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	message := make([]byte, 12+len(encoded)+4)
	if _, err := rand.Read(message[:2]); err != nil {
		return nil, fmt.Errorf("dns: random query ID: %w", err)
	}
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	copy(message[12:], encoded)
	binary.BigEndian.PutUint16(message[12+len(encoded):], qType)
	binary.BigEndian.PutUint16(message[14+len(encoded):], 1)
	return message, nil
}

func validateResponse(query, response []byte) error {
	if len(query) < 12 || len(response) < 12 || response[0] != query[0] || response[1] != query[1] {
		return errMalformedMessage
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 || flags&0x7800 != 0 {
		return errMalformedMessage
	}
	if flags&0x0200 != 0 {
		return ErrTruncatedResponse
	}
	switch flags & 0x000f {
	case 0, 3:
	case 2:
		return ErrServerFailure
	default:
		return fmt.Errorf("dns: response code %d", flags&0x000f)
	}
	queryName, queryType, queryClass, err := queryNameAndType(query)
	if err != nil {
		return err
	}
	responseName, responseType, responseClass, err := queryNameAndType(response)
	if err != nil || !strings.EqualFold(queryName, responseName) || queryType != responseType || queryClass != responseClass {
		return errMalformedMessage
	}
	return nil
}

func queryNameAndType(message []byte) (string, uint16, uint16, error) {
	if len(message) < 17 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return "", 0, 0, errMalformedMessage
	}
	name, offset, err := decodeName(message, 12)
	if err != nil || offset+4 > len(message) {
		return "", 0, 0, errMalformedMessage
	}
	return name, binary.BigEndian.Uint16(
			message[offset : offset+2],
		), binary.BigEndian.Uint16(
			message[offset+2 : offset+4],
		), nil
}

func parseAddresses(message []byte, qType uint16) ([]netip.Addr, error) {
	if len(message) < 12 || binary.BigEndian.Uint16(message[2:4])&0x8000 == 0 {
		return nil, errMalformedMessage
	}
	if binary.BigEndian.Uint16(message[2:4])&15 == 3 {
		return nil, nil
	}
	name, questionType, class, err := queryNameAndType(message)
	if err != nil || questionType != qType || class != 1 {
		return nil, errMalformedMessage
	}
	_, offset, err := decodeName(message, 12)
	if err != nil {
		return nil, err
	}
	offset += 4
	type record struct {
		owner   string
		address netip.Addr
	}
	var records []record
	aliases := map[string]string{}
	answers := int(binary.BigEndian.Uint16(message[6:8]))
	for range answers {
		owner, next, err := decodeName(message, offset)
		if err != nil || next+10 > len(message) {
			return nil, errMalformedMessage
		}
		kind, rrclass := binary.BigEndian.Uint16(message[next:]), binary.BigEndian.Uint16(message[next+2:])
		length := int(binary.BigEndian.Uint16(message[next+8:]))
		offset = next + 10
		end := offset + length
		if end > len(message) {
			return nil, errMalformedMessage
		}
		owner = strings.ToLower(owner)
		if rrclass == 1 {
			if kind == 5 {
				target, consumed, err := decodeName(message, offset)
				if err != nil || consumed != end {
					return nil, errMalformedMessage
				}
				aliases[owner] = strings.ToLower(target)
			}
			if kind == qType {
				var ip netip.Addr
				switch {
				case kind == dnsTypeA && length == 4:
					ip = netip.AddrFrom4([4]byte(message[offset:end]))
				case kind == dnsTypeAAAA && length == 16:
					ip = netip.AddrFrom16([16]byte(message[offset:end]))
				default:
					return nil, errMalformedMessage
				}
				records = append(records, record{owner: owner, address: ip})
			}
		}
		offset = end
	}
	allowed := map[string]bool{}
	current := strings.ToLower(name)
	for range 128 {
		if allowed[current] {
			return nil, errMalformedMessage
		}
		allowed[current] = true
		next, ok := aliases[current]
		if !ok {
			break
		}
		current = next
	}
	if !allowed[current] {
		return nil, errMalformedMessage
	}
	addresses := make([]netip.Addr, 0, len(records))
	for _, record := range records {
		if allowed[record.owner] {
			addresses = append(addresses, record.address)
		}
	}
	return addresses, nil
}

func responseTTL(message []byte) (time.Duration, error) {
	if len(message) < 12 {
		return 0, errMalformedMessage
	}
	questions, answers, offset := int(
		binary.BigEndian.Uint16(message[4:6]),
	), int(
		binary.BigEndian.Uint16(message[6:8]),
	), 12
	for range questions {
		_, next, err := decodeName(message, offset)
		if err != nil || next+4 > len(message) {
			return 0, errMalformedMessage
		}
		offset = next + 4
	}
	var lowest uint32
	found := false
	for range answers {
		_, next, err := decodeName(message, offset)
		if err != nil || next+10 > len(message) {
			return 0, errMalformedMessage
		}
		ttl, length := binary.BigEndian.Uint32(
			message[next+4:next+8],
		), int(
			binary.BigEndian.Uint16(message[next+8:next+10]),
		)
		offset = next + 10 + length
		if offset > len(message) {
			return 0, errMalformedMessage
		}
		if !found || ttl < lowest {
			found = true
			lowest = ttl
		}
	}
	return time.Duration(lowest) * time.Second, nil
}

func cacheTTL(message []byte) (time.Duration, error) {
	ttl, err := responseTTL(message)
	if err != nil {
		return 0, err
	}
	if binary.BigEndian.Uint16(message[2:4])&0x000f == 3 || binary.BigEndian.Uint16(message[6:8]) == 0 {
		return minTTL, nil
	}
	return ttl, nil
}

func encodeName(name string) ([]byte, error) {
	if len(strings.TrimSuffix(name, ".")) > 253 {
		return nil, errMalformedMessage
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	encoded := make([]byte, 0, len(name)+2)
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("dns: invalid name %q", name)
		}
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0), nil
}

func decodeName(message []byte, start int) (string, int, error) {
	labels := make([]string, 0, 4)
	if start < 0 {
		return "", 0, errMalformedMessage
	}
	offset, next, jumped := start, start, false
	expanded, jumps := 1, 0
	for range message {
		if offset >= len(message) {
			return "", 0, errMalformedMessage
		}
		length := int(message[offset])
		if length&0xc0 == 0xc0 {
			jumps++
			if jumps > 128 {
				return "", 0, errMalformedMessage
			}
			if offset+1 >= len(message) {
				return "", 0, errMalformedMessage
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = ((length & 0x3f) << 8) | int(message[offset+1])
			continue
		}
		if length&0xc0 != 0 || offset+1+length > len(message) {
			return "", 0, errMalformedMessage
		}
		if length == 0 {
			if !jumped {
				next = offset + 1
			}
			return strings.Join(labels, "."), next, nil
		}
		expanded += length + 1
		if expanded > 255 {
			return "", 0, errMalformedMessage
		}
		labels = append(labels, string(message[offset+1:offset+1+length]))
		offset += length + 1
	}
	return "", 0, errMalformedMessage
}

// ValidatePacketResponse also protects the direct fallback for proxied DNS.
func ValidatePacketResponse(query, response []byte) error { return validateResponse(query, response) }

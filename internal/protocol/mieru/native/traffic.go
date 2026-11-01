// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	mrand "math/rand"
	"os"
	"strconv"

	"google.golang.org/protobuf/encoding/protowire"
)

const commonNonceCharacters = "!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz<>"

type trafficPattern struct {
	tcpFragment bool
	tcpMaxSleep int
	nonce       noncePattern
	middlePad   int
	endPad      int
}

type noncePattern struct {
	kind     int
	applyAll bool
	minLen   int
	maxLen   int
	fixed    [][]byte
}

type decodedTraffic struct {
	seed, unlock              *int64
	tcpEnable, tcpSleep       *int64
	nonceKind, nonceAll       *int64
	nonceMin, nonceMax        *int64
	nonceFixed                []string
	paddingMiddle, paddingEnd *int64
}

func ValidateTrafficPattern(encoded string) error {
	_, err := decodeTrafficPattern(encoded)
	return err
}

func decodeTrafficPattern(encoded string) (*trafficPattern, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("sing-mieru: decode traffic pattern: %w", err)
	}
	decoded := new(decodedTraffic)
	if err = consumeTraffic(raw, decoded); err != nil {
		return nil, err
	}
	seed := int64(0)
	if decoded.seed != nil {
		seed = *decoded.seed
	} else {
		host, _ := os.Hostname()
		seed = int64(fixedInt(math.MaxInt32, host+" 3.34.0"))
	}
	seedText := strconv.FormatInt(seed, 10)
	unlock := decoded.unlock != nil && *decoded.unlock != 0
	pattern := &trafficPattern{}
	if decoded.tcpEnable != nil {
		pattern.tcpFragment = *decoded.tcpEnable != 0
	} else if unlock {
		pattern.tcpFragment = fixedInt(2, seedText+":tcpFragment.enable") == 1
	}
	if decoded.tcpSleep != nil {
		pattern.tcpMaxSleep = int(*decoded.tcpSleep)
	} else if unlock {
		pattern.tcpMaxSleep = fixedInt(100, seedText+":tcpFragment.maxSleepMs") + 1
	}
	if pattern.tcpMaxSleep < 0 || pattern.tcpMaxSleep > 100 {
		return nil, fmt.Errorf("sing-mieru: TCP fragment sleep %d is outside [0,100]", pattern.tcpMaxSleep)
	}
	if decoded.nonceKind != nil {
		pattern.nonce.kind = int(*decoded.nonceKind)
	} else if unlock {
		pattern.nonce.kind = fixedInt(3, seedText+":nonce.type")
	} else {
		pattern.nonce.kind = fixedInt(2, seedText+":nonce.type") + 1
	}
	if pattern.nonce.kind < 0 || pattern.nonce.kind > 3 {
		return nil, fmt.Errorf("sing-mieru: invalid nonce pattern %d", pattern.nonce.kind)
	}
	if decoded.nonceAll != nil {
		pattern.nonce.applyAll = *decoded.nonceAll != 0
	} else {
		pattern.nonce.applyAll = fixedInt(2, seedText+":nonce.applyToAllUDPPacket") == 1
	}
	if decoded.nonceMin != nil {
		pattern.nonce.minLen = int(*decoded.nonceMin)
	} else if unlock {
		pattern.nonce.minLen = fixedInt(13, seedText+":nonce.minLen")
	} else {
		pattern.nonce.minLen = fixedInt(7, seedText+":nonce.minLen") + 6
	}
	if decoded.nonceMax != nil {
		pattern.nonce.maxLen = int(*decoded.nonceMax)
	} else {
		pattern.nonce.maxLen = pattern.nonce.minLen + fixedInt(13-pattern.nonce.minLen, seedText+":nonce.maxLen")
	}
	if pattern.nonce.minLen < 0 || pattern.nonce.maxLen < pattern.nonce.minLen || pattern.nonce.maxLen > 12 {
		return nil, fmt.Errorf("sing-mieru: invalid nonce length range [%d,%d]", pattern.nonce.minLen, pattern.nonce.maxLen)
	}
	for index, value := range decoded.nonceFixed {
		prefix, decodeErr := hex.DecodeString(value)
		if decodeErr != nil || len(prefix) > 12 {
			return nil, fmt.Errorf("sing-mieru: invalid fixed nonce prefix %d", index)
		}
		pattern.nonce.fixed = append(pattern.nonce.fixed, prefix)
	}
	if decoded.paddingMiddle != nil {
		pattern.middlePad = int(*decoded.paddingMiddle)
	} else {
		pattern.middlePad = max(0, fixedInt(256, seedText+":padding.maxMiddlePaddingLen")-128)
	}
	if decoded.paddingEnd != nil {
		pattern.endPad = int(*decoded.paddingEnd)
	} else if unlock {
		pattern.endPad = fixedInt(256, seedText+":padding.maxEndPaddingLen")
	} else {
		pattern.endPad = 255
	}
	if pattern.middlePad < 0 || pattern.middlePad > 255 || pattern.endPad < 0 || pattern.endPad > 255 {
		return nil, fmt.Errorf("sing-mieru: invalid padding range")
	}
	return pattern, nil
}

func consumeTraffic(raw []byte, decoded *decodedTraffic) error {
	for len(raw) != 0 {
		number, kind, consumed := protowire.ConsumeTag(raw)
		if consumed < 0 {
			return fmt.Errorf("sing-mieru: invalid traffic pattern protobuf")
		}
		raw = raw[consumed:]
		switch number {
		case 1, 2:
			value, size := protowire.ConsumeVarint(raw)
			if kind != protowire.VarintType || size < 0 {
				return fmt.Errorf("sing-mieru: invalid traffic scalar")
			}
			parsed := int64(value)
			if number == 1 {
				decoded.seed = &parsed
			} else {
				decoded.unlock = &parsed
			}
			raw = raw[size:]
		case 3, 4, 5:
			value, size := protowire.ConsumeBytes(raw)
			if kind != protowire.BytesType || size < 0 {
				return fmt.Errorf("sing-mieru: invalid traffic message")
			}
			var decodeErr error
			switch number {
			case 3:
				decodeErr = consumeTCP(value, decoded)
			case 4:
				decodeErr = consumeNonce(value, decoded)
			case 5:
				decodeErr = consumePadding(value, decoded)
			}
			if decodeErr != nil {
				return decodeErr
			}
			raw = raw[size:]
		default:
			size := protowire.ConsumeFieldValue(number, kind, raw)
			if size < 0 {
				return fmt.Errorf("sing-mieru: invalid traffic field")
			}
			raw = raw[size:]
		}
	}
	return nil
}

func consumeTCP(raw []byte, decoded *decodedTraffic) error {
	return consumeVarintMessage(raw, func(number protowire.Number, value int64) {
		switch number {
		case 1:
			decoded.tcpEnable = pointer(value)
		case 2:
			decoded.tcpSleep = pointer(value)
		}
	})
}

func consumePadding(raw []byte, decoded *decodedTraffic) error {
	return consumeVarintMessage(raw, func(number protowire.Number, value int64) {
		switch number {
		case 1:
			decoded.paddingMiddle = pointer(value)
		case 2:
			decoded.paddingEnd = pointer(value)
		}
	})
}

func consumeNonce(raw []byte, decoded *decodedTraffic) error {
	for len(raw) != 0 {
		number, kind, consumed := protowire.ConsumeTag(raw)
		if consumed < 0 {
			return fmt.Errorf("sing-mieru: invalid nonce pattern")
		}
		raw = raw[consumed:]
		if number == 5 {
			value, size := protowire.ConsumeBytes(raw)
			if kind != protowire.BytesType || size < 0 {
				return fmt.Errorf("sing-mieru: invalid nonce prefix")
			}
			decoded.nonceFixed = append(decoded.nonceFixed, string(value))
			raw = raw[size:]
			continue
		}
		if number >= 1 && number <= 4 {
			value, size := protowire.ConsumeVarint(raw)
			if kind != protowire.VarintType || size < 0 {
				return fmt.Errorf("sing-mieru: invalid nonce scalar")
			}
			parsed := int64(value)
			switch number {
			case 1:
				decoded.nonceKind = &parsed
			case 2:
				decoded.nonceAll = &parsed
			case 3:
				decoded.nonceMin = &parsed
			case 4:
				decoded.nonceMax = &parsed
			}
			raw = raw[size:]
			continue
		}
		size := protowire.ConsumeFieldValue(number, kind, raw)
		if size < 0 {
			return fmt.Errorf("sing-mieru: invalid nonce field")
		}
		raw = raw[size:]
	}
	return nil
}

func consumeVarintMessage(raw []byte, set func(protowire.Number, int64)) error {
	for len(raw) != 0 {
		number, kind, consumed := protowire.ConsumeTag(raw)
		if consumed < 0 {
			return fmt.Errorf("sing-mieru: invalid traffic submessage")
		}
		raw = raw[consumed:]
		if kind == protowire.VarintType {
			value, size := protowire.ConsumeVarint(raw)
			if size < 0 {
				return fmt.Errorf("sing-mieru: invalid traffic scalar")
			}
			set(number, int64(value))
			raw = raw[size:]
		} else {
			size := protowire.ConsumeFieldValue(number, kind, raw)
			if size < 0 {
				return fmt.Errorf("sing-mieru: invalid traffic field")
			}
			raw = raw[size:]
		}
	}
	return nil
}

func pointer(value int64) *int64 { return &value }

func fixedInt(limit int, hint string) int {
	if limit <= 0 {
		return 0
	}
	digest := sha256.Sum256([]byte(hint))
	digest[0] &= 0x7f
	return int(binary.BigEndian.Uint32(digest[:4])) % limit
}

func (p *trafficPattern) rewriteNonce(nonce []byte) {
	if p == nil || len(nonce) < nonceSize {
		return
	}
	pattern := p.nonce
	switch pattern.kind {
	case 1, 2:
		length := pattern.minLen + randomInt(pattern.maxLen-pattern.minLen+1)
		for index := 0; index < length; index++ {
			if pattern.kind == 1 {
				nonce[index] = 0x20 + nonce[index]%95
			} else {
				nonce[index] = commonNonceCharacters[int(nonce[index])&63]
			}
		}
	case 3:
		if len(pattern.fixed) != 0 {
			prefix := pattern.fixed[randomInt(len(pattern.fixed))]
			copy(nonce, prefix)
		}
	}
}

func (p *trafficPattern) paddingLength(maximum int) int {
	maximum = min(maximum, 255)
	if maximum <= 0 {
		return 0
	}
	return randomInt(maximum + 1)
}

func appendRandom(dst []byte, length int) ([]byte, error) {
	if length <= 0 {
		return dst, nil
	}
	start := len(dst)
	dst = append(dst, make([]byte, length)...)
	if _, err := rand.Read(dst[start:]); err != nil {
		return nil, err
	}
	return dst, nil
}

func randomInt(limit int) int {
	if limit <= 1 {
		return 0
	}
	return mrand.Intn(limit)
}

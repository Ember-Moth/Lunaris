// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

// Package protocol implements the server side of the ShadowsocksR protocol
// transforms. Client behavior and transport obfuscation are deliberately kept
// out of these interfaces.
package protocol

import (
	"errors"
	"fmt"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/replay"
)

var (
	ErrAuthentication = errors.New("shadowsocksr: protocol authentication failed")
	ErrUnsupported    = errors.New("shadowsocksr: unsupported protocol")
	ErrUnknownUser    = errors.New("shadowsocksr: unknown user")
)

type Metadata struct {
	UserFromWire bool
	SingleUser   bool
}

type Config struct {
	Name              string
	ServerKey         []byte
	SingleUserID      [4]byte
	Now               func() time.Time
	Replay            *replay.Cache
	Sessions          *replay.Sessions
	Users             map[[4]byte]Credential
	ProtocolParam     string
	TransportOverhead int
}

type Credential struct {
	Key       []byte
	HeaderKey []byte
}

// Definition is immutable and safe to share between connections and packet
// workers.
type Definition interface {
	Metadata() Metadata
	Overhead() int
	NewStream(writeIV []byte) Stream
	DecodePacket(dst, packet, iv []byte) ([]byte, [4]byte, error)
	EncodePacket(dst, payload []byte, userID [4]byte, iv []byte) ([]byte, error)
}

// Stream owns the incremental state for one TCP connection.
type Stream interface {
	SetReadIV(iv []byte)
	Decode(dst, input []byte) (data []byte, borrowed, reply bool, err error)
	Encode(dst, payload []byte) ([]byte, error)
	UserID() ([4]byte, bool)
	Close()
}

func Info(name string) (Metadata, bool) {
	switch name {
	case "origin", "verify_simple", "verify_sha1", "auth_simple", "auth_sha1", "auth_sha1_v2", "auth_sha1_v4":
		return Metadata{SingleUser: true}, true
	case "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f":
		return Metadata{UserFromWire: true}, true
	default:
		return Metadata{}, false
	}
}

func New(config Config) (Definition, error) {
	metadata, loaded := Info(config.Name)
	if !loaded {
		return nil, fmt.Errorf("%w %q", ErrUnsupported, config.Name)
	}
	if metadata.SingleUser && config.SingleUserID == [4]byte{} {
		return nil, ErrUnknownUser
	}
	switch config.Name {
	case "origin":
		return &originDefinition{userID: config.SingleUserID}, nil
	case "verify_simple":
		return &verifySimpleDefinition{userID: config.SingleUserID}, nil
	case "verify_sha1":
		return &verifySHA1Definition{userID: config.SingleUserID, serverKey: config.ServerKey}, nil
	case "auth_simple", "auth_sha1", "auth_sha1_v2", "auth_sha1_v4":
		return newLegacyAuthDefinition(config), nil
	case "auth_aes128_md5", "auth_aes128_sha1":
		return newAuthAESDefinition(config), nil
	case "auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f":
		return newAuthChainDefinition(config), nil
	default:
		return nil, fmt.Errorf("%w %q is not implemented yet", ErrUnsupported, config.Name)
	}
}

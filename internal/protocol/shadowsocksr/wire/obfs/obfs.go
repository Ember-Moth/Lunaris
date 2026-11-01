// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

// Package obfs implements the server side of ShadowsocksR transport
// obfuscation. It is independent from protocol authentication and ciphers.
package obfs

import (
	"errors"
	"fmt"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/replay"
)

var (
	ErrAuthentication = errors.New("shadowsocksr: obfs authentication failed")
	ErrUnsupported    = errors.New("shadowsocksr: unsupported obfs")
)

type Config struct {
	Name      string
	Host      string
	Port      int
	Param     string
	ServerKey []byte
	Now       func() time.Time
	Replay    *replay.Cache
}

type Definition interface {
	Overhead() int
	NewStream() Stream
}

type Stream interface {
	Decode(input []byte) (data []byte, decrypt, reply bool, err error)
	Encode(dst, input []byte) ([]byte, error)
	Close()
}

func New(config Config) (Definition, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	switch config.Name {
	case "plain":
		return plainDefinition{}, nil
	case "http_simple", "http_post":
		return newHTTPDefinition(config), nil
	case "tls1.0_session_auth":
		return newTLS10Definition(config), nil
	case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
		return newTLSTicketDefinition(config), nil
	default:
		return nil, fmt.Errorf("%w %q", ErrUnsupported, config.Name)
	}
}

type plainDefinition struct{}

func (plainDefinition) Overhead() int { return 0 }

func (plainDefinition) NewStream() Stream { return plainStream{} }

type plainStream struct{}

func (plainStream) Decode(input []byte) ([]byte, bool, bool, error) {
	return input, true, false, nil
}

func (plainStream) Encode(_ []byte, input []byte) ([]byte, error) { return input, nil }

func (plainStream) Close() {}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package shadowsocksr

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	ssrcipher "github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/cipher"
	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/obfs"
	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/shadowsocksr/wire/replay"
)

var (
	ErrInvalidConfig = errors.New("shadowsocksr: invalid server config")
	ErrUnknownUser   = protocol.ErrUnknownUser
)

type ServerConfig struct {
	Method        string
	Password      string
	Protocol      string
	ProtocolParam string
	Obfs          string
	ObfsParam     string
	Host          string
	Port          int
	TimeFunc      func() time.Time
	ReplayState   *ReplayState
}

type ReplayState struct {
	legacy   *replay.Cache
	sessions *replay.Sessions
	salts    *replay.Cache
}

func NewReplayState(timeFunc func() time.Time) *ReplayState {
	return NewReplayStateWithCapacity(timeFunc, replay.DefaultCapacity)
}

// NewReplayStateWithCapacity allows deployments to size exact replay history
// for their authenticated handshake rate and longest configured replay TTL.
func NewReplayStateWithCapacity(timeFunc func() time.Time, capacity int) *ReplayState {
	return &ReplayState{
		legacy: replay.NewCache(timeFunc, capacity), sessions: replay.NewSessions(timeFunc),
		salts: replay.NewCache(timeFunc, capacity),
	}
}

type Server struct {
	config   ServerConfig
	cipher   *ssrcipher.Suite
	protocol protocol.Definition
	obfs     obfs.Definition
	replay   *ReplayState
}

var shadowsocks2022OnlyMethods = map[string]struct{}{
	"2022-blake3-aes-128-gcm": {}, "2022-blake3-aes-256-gcm": {}, "2022-blake3-chacha20-poly1305": {},
}

func NewServer(config ServerConfig, users map[[4]byte]string) (*Server, error) {
	config.Method = strings.ToLower(strings.TrimSpace(config.Method))
	if config.Method == "dummy" {
		config.Method = "none"
	}
	config.Protocol = strings.ToLower(strings.TrimSpace(config.Protocol))
	config.Obfs = strings.ToLower(strings.TrimSpace(config.Obfs))
	if config.Obfs == "" {
		config.Obfs = "plain"
	}
	if config.TimeFunc == nil {
		config.TimeFunc = time.Now
	}
	if config.Password == "" || config.Port < 1 || config.Port > 65535 || len(users) == 0 {
		return nil, ErrInvalidConfig
	}
	metadata, loaded := protocol.Info(config.Protocol)
	if !loaded {
		return nil, fmt.Errorf("%w: unsupported protocol %q", ErrInvalidConfig, config.Protocol)
	}
	if metadata.SingleUser && len(users) != 1 {
		return nil, fmt.Errorf("%w: protocol %q requires exactly one active user", ErrInvalidConfig, config.Protocol)
	}
	suite, err := ssrcipher.NewSuite(config.Method, config.Password)
	if err != nil {
		if _, shadowsocksOnly := shadowsocks2022OnlyMethods[config.Method]; shadowsocksOnly {
			return nil, fmt.Errorf("%w: method %q is a Shadowsocks 2022 method; use type=shadowsocks", ErrInvalidConfig, config.Method)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	config.Method = suite.Name()
	var singleUserID [4]byte
	if metadata.SingleUser {
		for userID, password := range users {
			if password == "" {
				return nil, fmt.Errorf("%w: empty user password", ErrInvalidConfig)
			}
			singleUserID = userID
		}
	} else {
		for _, password := range users {
			if password == "" {
				return nil, fmt.Errorf("%w: empty user password", ErrInvalidConfig)
			}
		}
	}
	credentials := compileCredentials(config.Protocol, users)
	replayState := config.ReplayState
	if replayState == nil {
		replayState = NewReplayState(config.TimeFunc)
	} else {
		// Keep the zero value usable for callers that embed ReplayState rather
		// than constructing it explicitly.
		if replayState.legacy == nil {
			replayState.legacy = replay.NewCache(config.TimeFunc, replay.DefaultCapacity)
		}
		if replayState.sessions == nil {
			replayState.sessions = replay.NewSessions(config.TimeFunc)
		}
		if replayState.salts == nil {
			replayState.salts = replay.NewCache(config.TimeFunc, replay.DefaultCapacity)
		}
	}
	obfsDefinition, err := obfs.New(obfs.Config{Name: config.Obfs, Host: config.Host, Port: config.Port,
		Param: config.ObfsParam, ServerKey: suite.Key(), Now: config.TimeFunc, Replay: replayState.legacy})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	definition, err := protocol.New(protocol.Config{Name: config.Protocol, ServerKey: suite.Key(), SingleUserID: singleUserID,
		Now: config.TimeFunc, Replay: replayState.legacy, Sessions: replayState.sessions, Users: credentials, ProtocolParam: config.ProtocolParam,
		TransportOverhead: obfsDefinition.Overhead()})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return &Server{config: config, cipher: suite, protocol: definition, obfs: obfsDefinition, replay: replayState}, nil
}

func (s *Server) checkCipherReplay(salt []byte) bool {
	return s.replay.salts.CheckAndInsert("sip004", salt, time.Minute)
}

func compileCredentials(protocolName string, users map[[4]byte]string) map[[4]byte]protocol.Credential {
	if protocolName != "auth_aes128_md5" && protocolName != "auth_aes128_sha1" && !strings.HasPrefix(protocolName, "auth_chain_") {
		return nil
	}
	result := make(map[[4]byte]protocol.Credential, len(users))
	for userID, password := range users {
		var userKey []byte
		switch protocolName {
		case "auth_aes128_md5":
			digest := md5.Sum([]byte(password))
			userKey = append([]byte(nil), digest[:]...)
		case "auth_aes128_sha1":
			digest := sha1.Sum([]byte(password))
			userKey = append([]byte(nil), digest[:]...)
		default:
			userKey = []byte(password)
		}
		headerPassword := base64.StdEncoding.EncodeToString(userKey) + protocolName
		result[userID] = protocol.Credential{Key: userKey, HeaderKey: ssrcipher.DeriveKey(headerPassword, 16)}
	}
	return result
}

func ProtocolInfo(name string) (protocol.Metadata, bool) {
	return protocol.Info(strings.ToLower(strings.TrimSpace(name)))
}

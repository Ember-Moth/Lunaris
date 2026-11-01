// SPDX-License-Identifier: GPL-3.0-only
package model

import (
	"encoding/json"
	"time"
)

const ConfigSchemaVersion = 1

type ProtocolType string

type ListenerSpec struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Enabled        bool            `json:"enabled"`
	Protocol       ProtocolType    `json:"protocol"`
	Address        string          `json:"address"`
	Port           uint16          `json:"port"`
	Network        []string        `json:"network,omitempty"`
	Options        json.RawMessage `json:"options"`
	CredentialRefs []string        `json:"credential_refs"`
	CertificateRef string          `json:"certificate_ref,omitempty"`
	Transport      Transport       `json:"transport,omitempty"`
}

// Transport describes the carrier; Network describes the listening sockets.
type Transport struct {
	Type string `json:"type,omitempty" yaml:"type"`
	Path string `json:"path,omitempty" yaml:"path"`
	Host string `json:"host,omitempty" yaml:"host"`
}

type Certificate struct {
	Certificate []byte `json:"-" yaml:"-"`
	PrivateKey  []byte `json:"-" yaml:"-"`
}

type NodeConfig struct {
	SchemaVersion int            `json:"schema_version"`
	Listeners     []ListenerSpec `json:"listeners"`
	Limits        Limits         `json:"limits"`
}

// RuntimeConfig includes resolved assets and must not be serialized to an API.
type RuntimeConfig struct {
	Config       NodeConfig
	Credentials  map[string][]byte      `json:"-" yaml:"-"`
	Certificates map[string]Certificate `json:"-" yaml:"-"`
}

// Limits bounds resources owned by each listener. All durations are normalized.
type Limits struct {
	DialTimeout          time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	HandshakeTimeout     time.Duration `json:"handshake_timeout" yaml:"handshake_timeout"`
	UDPIdleTimeout       time.Duration `json:"udp_idle_timeout" yaml:"udp_idle_timeout"`
	ShutdownTimeout      time.Duration `json:"shutdown_timeout" yaml:"shutdown_timeout"`
	MaxConnections       int           `json:"max_connections" yaml:"max_connections"`
	MaxPendingHandshakes int           `json:"max_pending_handshakes" yaml:"max_pending_handshakes"`
	MaxUDPSessions       int           `json:"max_udp_sessions" yaml:"max_udp_sessions"`
	UDPQueueSize         int           `json:"udp_queue_size" yaml:"udp_queue_size"`
	MaxUDPDestinations   int           `json:"max_udp_destinations" yaml:"max_udp_destinations"`
}

func DefaultLimits() Limits {
	return Limits{
		DialTimeout: 10 * time.Second, HandshakeTimeout: 10 * time.Second,
		UDPIdleTimeout: time.Minute, ShutdownTimeout: 5 * time.Second,
		MaxConnections: 1024, MaxPendingHandshakes: 128,
		MaxUDPSessions: 256, UDPQueueSize: 64, MaxUDPDestinations: 64,
	}
}

type ConfigHeads struct {
	DraftRevision     string `json:"draft_revision"`
	CommittedRevision string `json:"committed_revision"`
}

type FieldError struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

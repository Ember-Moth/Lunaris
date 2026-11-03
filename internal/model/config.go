// SPDX-License-Identifier: GPL-3.0-only
package model

import (
	"bytes"
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
	UDPOverTCP     bool            `json:"udp_over_tcp,omitempty"`
	Multiplex      Multiplex       `json:"multiplex,omitempty"`
}

type Multiplex struct {
	Enabled bool `json:"enabled,omitempty"`
	Padding bool `json:"padding,omitempty"`
}

// Transport describes the carrier; Network describes the listening sockets.
type Transport struct {
	Plugin  json.RawMessage `json:"plugin,omitempty" yaml:"-"`
	Type    string          `json:"type,omitempty"`
	Path    string          `json:"path,omitempty"`
	Host    string          `json:"host,omitempty"`
	Reality *Reality        `json:"reality,omitempty"`
	XHTTP   *XHTTP          `json:"xhttp,omitempty" yaml:"-"`
}

type XHTTP struct {
	Mode        string          `json:"mode,omitempty"`
	HTTPVersion string          `json:"http_version,omitempty"`
	Extra       json.RawMessage `json:"extra,omitempty"`
}

type Reality struct {
	AllowLegacyClients bool          `json:"allow_legacy_clients,omitempty"`
	Target             string        `json:"target"`
	ServerNames        []string      `json:"server_names"`
	PrivateKeyRef      string        `json:"private_key_ref"`
	ShortIDs           []string      `json:"short_ids"`
	MaxTimeDifference  time.Duration `json:"max_time_difference,omitempty"`
}

func (t Transport) Clone() Transport {
	t.Plugin = bytes.Clone(t.Plugin)
	if t.XHTTP != nil {
		x := *t.XHTTP
		x.Extra = bytes.Clone(x.Extra)
		t.XHTTP = &x
	}
	if t.Reality != nil {
		r := *t.Reality
		r.ServerNames = append([]string(nil), r.ServerNames...)
		r.ShortIDs = append([]string(nil), r.ShortIDs...)
		t.Reality = &r
	}
	return t
}

type Certificate struct {
	Certificate []byte `json:"-" yaml:"-"`
	PrivateKey  []byte `json:"-" yaml:"-"`
}

type NodeConfig struct {
	SchemaVersion int               `json:"schema_version"`
	Listeners     []ListenerSpec    `json:"listeners"`
	Outbounds     []OutboundSpec    `json:"outbounds,omitempty"`
	Limits        Limits            `json:"limits"`
	Route         *RouteConfig      `json:"route,omitempty"`
	DNS           *DNSConfig        `json:"dns,omitempty"`
	GeoData       map[string]string `json:"geodata,omitempty"`
}

// RuntimeConfig includes resolved assets and must not be serialized to an API.
type RuntimeConfig struct {
	PolicyDigest string `json:"-" yaml:"-"`
	Config       NodeConfig
	Credentials  map[string][]byte           `json:"-" yaml:"-"`
	Certificates map[string]Certificate      `json:"-" yaml:"-"`
	GeoData      map[string]*GeoDataMaterial `json:"-" yaml:"-"`
}

// Limits bounds resources owned by each listener. All durations are normalized.
type Limits struct {
	DialTimeout          time.Duration `json:"dial_timeout"`
	HandshakeTimeout     time.Duration `json:"handshake_timeout"`
	UDPIdleTimeout       time.Duration `json:"udp_idle_timeout"`
	ShutdownTimeout      time.Duration `json:"shutdown_timeout"`
	MaxConnections       int           `json:"max_connections"`
	MaxPendingHandshakes int           `json:"max_pending_handshakes"`
	MaxUDPSessions       int           `json:"max_udp_sessions"`
	UDPQueueSize         int           `json:"udp_queue_size"`
	MaxUDPDestinations   int           `json:"max_udp_destinations"`
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

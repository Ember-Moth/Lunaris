// SPDX-License-Identifier: GPL-3.0-only
package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"time"
)

// Rules are ordered after Block. Matches within a rule are OR conditions.
type RouteConfig struct {
	Block []string    `json:"block,omitempty"`
	Rules []RouteRule `json:"rules,omitempty"`
	Final string      `json:"final,omitempty"`
}
type RouteRule struct {
	Action   string   `json:"action"`
	Outbound string   `json:"outbound,omitempty"`
	Match    []string `json:"match"`
}
type DNSConfig struct {
	Servers        []DNSServer   `json:"servers,omitempty"`
	Strategy       string        `json:"strategy,omitempty"`
	Timeout        time.Duration `json:"timeout,omitempty"`
	SystemCacheTTL time.Duration `json:"system_cache_ttl,omitempty"`
	HijackUDP53    bool          `json:"hijack_udp53,omitempty"`
}
type DNSServer struct {
	Proto      string   `json:"protocol"`
	Address    string   `json:"address"`
	ServerName string   `json:"server_name,omitempty"`
	Domains    []string `json:"domains,omitempty"`
}

const MaxGeoDataSize = 128 << 20

// GeoDataMaterial owns an immutable byte snapshot. Normalized configurations
// can share this object without copying a large public dataset for every layer.
type GeoDataMaterial struct {
	data   []byte
	digest string
}

func NewGeoDataMaterial(data []byte) *GeoDataMaterial {
	owned := bytes.Clone(data)
	sum := sha256.Sum256(owned)
	return &GeoDataMaterial{data: owned, digest: hex.EncodeToString(sum[:])}
}
func (g *GeoDataMaterial) Open() io.Reader { return bytes.NewReader(g.data) }
func (g *GeoDataMaterial) Size() int       { return len(g.data) }
func (g *GeoDataMaterial) Digest() string  { return g.digest }

type GeoDataAsset struct {
	ID                  string           `json:"id"`
	Kind                string           `json:"kind"`
	Label               string           `json:"label"`
	SHA256              string           `json:"sha256"`
	Size                int              `json:"size"`
	CreatedAt           string           `json:"created_at"`
	ReferenceCount      int              `json:"reference_count"`
	ReferencesTruncated bool             `json:"references_truncated"`
	References          []AssetReference `json:"references"`
}

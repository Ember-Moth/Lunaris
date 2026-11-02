// SPDX-License-Identifier: GPL-3.0-only
package model

import "time"

type AdminAccount struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Version      int64  `json:"-"`
}
type AdminSession struct {
	TokenHash      string    `json:"-"`
	AccountID      string    `json:"-"`
	AccountVersion int64     `json:"-"`
	CSRFToken      string    `json:"-"`
	ExpiresAt      time.Time `json:"expires_at"`
	ReauthUntil    time.Time `json:"-"`
	CreatedAt      time.Time `json:"-"`
}
type AssetReference struct {
	Revision  string `json:"revision"`
	LogicalID string `json:"logical_id"`
}
type CredentialAsset struct {
	ID                  string           `json:"id"`
	Kind                string           `json:"kind"`
	Label               string           `json:"label"`
	CreatedAt           string           `json:"created_at"`
	References          []AssetReference `json:"references"`
	ReferenceCount      int              `json:"reference_count"`
	ReferencesTruncated bool             `json:"references_truncated"`
}
type CertificateAsset struct {
	ID                  string           `json:"id"`
	Label               string           `json:"label"`
	Subject             string           `json:"subject"`
	DNSNames            []string         `json:"dns_names"`
	Fingerprint         string           `json:"fingerprint"`
	NotBefore           time.Time        `json:"not_before"`
	NotAfter            time.Time        `json:"not_after"`
	CreatedAt           string           `json:"created_at"`
	References          []AssetReference `json:"references"`
	ReferenceCount      int              `json:"reference_count"`
	ReferencesTruncated bool             `json:"references_truncated"`
}

// DraftInput keeps stable logical names in NodeConfig and binds them to
// immutable asset IDs. It never accepts raw secret material or local file paths.
type DraftInput struct {
	Config            NodeConfig        `json:"config"`
	CredentialAssets  map[string]string `json:"credential_assets"`
	CertificateAssets map[string]string `json:"certificate_assets"`
}

// SPDX-License-Identifier: GPL-3.0-only
package model

type ConfigRevision struct {
	ID                string            `json:"id"`
	ParentID          string            `json:"parent_id,omitempty"`
	CreatedAt         string            `json:"created_at"`
	Config            NodeConfig        `json:"config"`
	CredentialAssets  map[string]string `json:"credential_assets"`
	CertificateAssets map[string]string `json:"certificate_assets"`
}

type ApplyOperation struct {
	ID             string `json:"id"`
	RequestKey     string `json:"request_key"`
	RequestDigest  string `json:"-"`
	ExpectedBase   string `json:"expected_base,omitempty"`
	TargetRevision string `json:"target_revision"`
	BaseRevision   string `json:"base_revision"`
	Status         string `json:"status"`
	Phase          string `json:"phase"`
	Error          string `json:"error,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

func (o ApplyOperation) Terminal() bool {
	switch o.Status {
	case "succeeded", "failed", "failed_rolled_back", "degraded", "interrupted":
		return true
	default:
		return false
	}
}

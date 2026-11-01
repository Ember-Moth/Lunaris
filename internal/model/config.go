// SPDX-License-Identifier: GPL-3.0-only
package model

import "encoding/json"

const ConfigSchemaVersion = 1

type ProtocolType string

type ListenerSpec struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Enabled        bool            `json:"enabled"`
	Protocol       ProtocolType    `json:"protocol"`
	Address        string          `json:"address"`
	Port           uint16          `json:"port"`
	Options        json.RawMessage `json:"options"`
	CredentialRefs []string        `json:"credential_refs"`
	CertificateRef string          `json:"certificate_ref,omitempty"`
}

type NodeConfig struct {
	SchemaVersion int            `json:"schema_version"`
	Listeners     []ListenerSpec `json:"listeners"`
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

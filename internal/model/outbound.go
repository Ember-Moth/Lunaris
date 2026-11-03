// SPDX-License-Identifier: GPL-3.0-only
package model

import "encoding/json"

// OutboundSpec contains public settings and a logical reference to an immutable
// credential asset. Passwords must never be embedded in Options.
type OutboundSpec struct {
	ID            string          `json:"id"`
	Name          string          `json:"name,omitempty"`
	Protocol      string          `json:"protocol"`
	Address       string          `json:"address"`
	Port          uint16          `json:"port"`
	CredentialRef string          `json:"credential_ref,omitempty"`
	Options       json.RawMessage `json:"options"`
}

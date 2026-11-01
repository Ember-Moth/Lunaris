// SPDX-License-Identifier: GPL-3.0-only
// Package stream contains shared credential validation for stream protocols.
// Transport selection and HTTP/TLS validation belong to the transport registry.
package stream

import (
	"bytes"
	"errors"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/gofrs/uuid/v5"
)

func Validate(s model.ListenerSpec) []model.FieldError {
	raw := bytes.TrimSpace(s.Options)
	if len(raw) != 0 && !bytes.Equal(raw, []byte("{}")) && !bytes.Equal(raw, []byte("null")) {
		return []model.FieldError{{Path: "options", Code: "invalid", Message: "this protocol has no configurable options"}}
	}
	if len(s.CredentialRefs) == 0 {
		return []model.FieldError{{Path: "credential_refs", Code: "invalid", Message: "at least one credential is required"}}
	}
	return nil
}
func ValidateAssets(r protocol.ResolvedListenerSpec, requireUUID bool) error {
	seen := make(map[string]bool)
	for _, ref := range r.Spec.CredentialRefs {
		secret := string(r.Credentials[ref])
		if secret == "" {
			return errors.New("empty protocol credential")
		}
		if requireUUID {
			u, err := uuid.FromString(secret)
			if err != nil || u == uuid.Nil {
				return errors.New("credential must be a nonzero UUID")
			}
			secret = u.String()
		}
		if seen[secret] {
			return errors.New("duplicate protocol credential")
		}
		seen[secret] = true
	}
	return nil
}
func Passwords(r protocol.ResolvedListenerSpec) []string {
	out := make([]string, len(r.Spec.CredentialRefs))
	for i, ref := range r.Spec.CredentialRefs {
		out[i] = string(r.Credentials[ref])
	}
	return out
}

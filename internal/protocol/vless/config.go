// SPDX-License-Identifier: GPL-3.0-only
package vless

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/stream"
	wire "github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire"
	"github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire/encryption"
)

type options struct {
	Flow          string `json:"flow,omitempty"`
	DecryptionRef string `json:"decryption_ref,omitempty"`
}

func parseOptions(s model.ListenerSpec) (options, error) {
	var o options
	if len(bytes.TrimSpace(s.Options)) == 0 {
		return o, nil
	}
	d := json.NewDecoder(bytes.NewReader(s.Options))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return o, errors.New("invalid VLESS options")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return o, errors.New("invalid VLESS options")
	}
	return o, nil
}
func (Factory) Validate(s model.ListenerSpec) []model.FieldError {
	field := func(path, message string) []model.FieldError {
		return []model.FieldError{{Path: path, Code: "invalid", Message: message}}
	}
	o, err := parseOptions(s)
	if err != nil {
		return field("options", err.Error())
	}
	if len(s.CredentialRefs) == 0 {
		return field("credential_refs", "at least one credential is required")
	}
	if o.Flow != "" && o.Flow != wire.FlowVision {
		return field("options.flow", "flow must be empty or xtls-rprx-vision")
	}
	if o.DecryptionRef != "" && slices.Contains(s.CredentialRefs, o.DecryptionRef) {
		return field("options.decryption_ref", "decryption configuration must be separate from user credentials")
	}
	if o.Flow == wire.FlowVision {
		if s.Multiplex.Enabled {
			return field("multiplex", "Vision uses XUDP for UDP and does not support sing-mux")
		}
		carrier := s.Transport.Type
		if carrier == "" {
			carrier = "tcp"
		}
		if o.DecryptionRef == "" && !(carrier == "reality" || carrier == "tcp" && s.CertificateRef != "") {
			return field("options.flow", "Vision requires TCP with TLS/REALITY or VLESS Encryption")
		}
	}
	return nil
}
func (Factory) CredentialRefs(s model.ListenerSpec) []string {
	o, err := parseOptions(s)
	if err != nil || o.DecryptionRef == "" {
		return nil
	}
	return []string{o.DecryptionRef}
}
func decryptionConfig(r protocol.ResolvedListenerSpec) (*encryption.ServerConfig, error) {
	o, err := parseOptions(r.Spec)
	if err != nil {
		return nil, err
	}
	if o.DecryptionRef == "" {
		return nil, nil
	}
	raw := r.Credentials[o.DecryptionRef]
	if len(raw) == 0 || len(raw) > 4096 {
		return nil, errors.New("invalid VLESS decryption credential")
	}
	cfg, err := encryption.ParseServerConfig(string(raw))
	if err != nil || cfg == nil {
		return nil, errors.New("invalid VLESS decryption credential")
	}
	return cfg, nil
}
func (Factory) ValidateAssets(r protocol.ResolvedListenerSpec) error {
	if err := stream.ValidateAssets(r, true); err != nil {
		return err
	}
	_, err := decryptionConfig(r)
	return err
}

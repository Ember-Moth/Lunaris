// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
)

// Examples are JSON API requests with illustrative asset IDs, never node files.
// Bind real disposable assets and validate the published requests through HTTP.
func TestJSONExamplesValidateWithAssetBindings(t *testing.T) {
	m := startManagement(t, false, nil)
	m.initialize(t)
	m.login(t, adminPassword)
	paths, err := filepath.Glob("../../examples/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatal("example requests missing", err)
	}
	certificate, _ := testutil.Certificate(t)
	r, e, _ := m.request(t, "POST", "/api/v1/certificates", map[string]string{"label": "examples", "certificate": string(certificate.Certificate), "private_key": string(certificate.PrivateKey)}, nil)
	expectStatus(t, r, 201, e)
	cert := dataAs[model.CertificateAsset](t, e)
	uuid := "c8820ed3-e4ee-47ad-a5bd-ece70763e32c"
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			input := newDraftInput()
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&input); err != nil {
				t.Fatal("example is not a JSON draft request", err)
			}
			for logical := range input.CredentialAssets {
				kind, secret := "generic", "disposable-example-password-"+logical
				switch logical {
				case "uuid", "user", "device":
					secret = uuid
				case "reality-key":
					kind = "x25519"
				case "vless-decryption":
					kind = "vless-encryption"
				case "ss-server":
					secret = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
				case "ss-alice":
					secret = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
				case "ss-bob":
					secret = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16))
				}
				request := map[string]any{"kind": kind, "secret": secret}
				if kind != "generic" {
					delete(request, "secret")
					request["generate"] = true
				}
				r, e, _ := m.request(t, "POST", "/api/v1/credentials", request, nil)
				expectStatus(t, r, 201, e)
				input.CredentialAssets[logical] = dataAs[model.CredentialAsset](t, e).ID
			}
			for logical := range input.CertificateAssets {
				input.CertificateAssets[logical] = cert.ID
			}
			for _, listener := range input.Config.Listeners {
				if !listener.Enabled {
					t.Fatal("example listener is accidentally disabled", listener.ID)
				}
			}
			r, e, _ := m.request(t, "POST", "/api/v1/config/validate", input, nil)
			expectStatus(t, r, 200, e)
		})
	}
}

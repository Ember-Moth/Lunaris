// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	vless "github.com/Ember-Moth/Lunaris/internal/protocol/vless"
)

func TestVLESSOptionsAndCredentialBoundary(t *testing.T) {
	f := vless.Factory{}
	for _, tc := range []struct {
		options, carrier string
		tls, mux, valid  bool
	}{
		{`{}`, "tcp", false, false, true},
		{`{"flow":"xtls-rprx-vision"}`, "tcp", true, false, true},
		{`{"flow":"xtls-rprx-vision"}`, "reality", false, false, true},
		{`{"flow":"xtls-rprx-vision"}`, "tcp", false, false, false},
		{`{"flow":"xtls-rprx-vision"}`, "ws", true, false, false},
		{`{"flow":"xtls-rprx-vision","decryption_ref":"enc"}`, "ws", false, false, true},
		{`{"flow":"xtls-rprx-vision","decryption_ref":"enc"}`, "xhttp", true, false, true},
		{`{"flow":"xtls-rprx-vision"}`, "tcp", true, true, false},
		{`{"flow":"xtls-rprx-direct"}`, "tcp", true, false, false},
		{`{"decryption":"secret"}`, "tcp", false, false, false},
		{`{"decryption_ref":"user"}`, "tcp", false, false, false},
	} {
		s := model.ListenerSpec{Protocol: "vless", Options: []byte(tc.options), CredentialRefs: []string{"user"}, Transport: model.Transport{Type: tc.carrier}, Multiplex: model.Multiplex{Enabled: tc.mux}}
		if tc.tls {
			s.CertificateRef = "tls"
		}
		if got := len(f.Validate(s)) == 0; got != tc.valid {
			t.Errorf("%s/%s valid=%v", tc.carrier, tc.options, got)
		}
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	raw := "mlkem768x25519plus.native.600s." + base64.RawURLEncoding.EncodeToString(key.Bytes())
	s := model.ListenerSpec{Protocol: "vless", Options: []byte(`{"decryption_ref":"enc"}`), CredentialRefs: []string{"user"}}
	registry, _ := builtin.NewRegistry()
	if refs := registry.CredentialRefs(s); !slices.Contains(refs, "enc") || !slices.Contains(refs, "user") {
		t.Fatal("missing secret dependency", refs)
	}
	r := protocol.ResolvedListenerSpec{Spec: s, Credentials: map[string][]byte{"user": []byte(userID), "enc": []byte(raw)}}
	if err := f.ValidateAssets(r); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"", "none", "mlkem768x25519plus.native.600s.private-secret", strings.Repeat("x", 4097)} {
		r.Credentials["enc"] = []byte(secret)
		err := f.ValidateAssets(r)
		if err == nil || secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatal("missing or unsafe credential error", err)
		}
	}
}

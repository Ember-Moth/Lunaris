// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
)

func TestConnectionInfoNeverExportsServerPrivateKeys(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	private := base64.RawURLEncoding.EncodeToString(key.Bytes())
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	snapshot := &model.RuntimeConfig{Credentials: map[string][]byte{"user": []byte("c8820ed3-e4ee-47ad-a5bd-ece70763e32c"), "reality": []byte(private), "encryption": []byte("mlkem768x25519plus.native.600s." + private)}}
	spec := model.ListenerSpec{ID: "vless", Protocol: "vless", CredentialRefs: []string{"user"}, Port: 443, Network: []string{"tcp"}, Options: []byte(`{"flow":"xtls-rprx-vision","decryption_ref":"encryption"}`), Transport: model.Transport{Type: "reality", Reality: &model.Reality{PrivateKeyRef: "reality", ServerNames: []string{"example.com"}, ShortIDs: []string{"0123"}}}}
	info, err := connectionParameters(snapshot, spec, connectionRequest{Revision: "r1", Host: "proxy.example.com"}, "digest")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(info)
	if bytes.Contains(encoded, []byte(private)) || bytes.Contains(encoded, []byte("decryption_ref")) || !bytes.Contains(encoded, []byte(public)) {
		t.Fatal("server encryption keys were not converted to public material")
	}
	cert, _ := testutil.Certificate(t)
	snapshot.Certificates = map[string]model.Certificate{"cert": cert}
	snapshot.Credentials["user"] = []byte("selected-password")
	snapshot.Credentials["other"] = []byte("unselected-password")
	spec = model.ListenerSpec{ID: "naive", Protocol: "naive", CredentialRefs: []string{"user", "other"}, CertificateRef: "cert", Port: 443, Options: []byte(`{"users":[{"username":"one","credential_ref":"user"},{"username":"two","credential_ref":"other"}]}`), Transport: model.Transport{Type: "http"}}
	info, err = connectionParameters(snapshot, spec, connectionRequest{Revision: "r1", Host: "localhost", CredentialRef: "user"}, "digest")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(info)
	if bytes.Contains(encoded, cert.PrivateKey) || bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("unselected-password")) || !bytes.Contains(encoded, []byte("selected-password")) {
		t.Fatal("export boundary violated")
	}
	if _, err := connectionParameters(snapshot, spec, connectionRequest{Revision: "r1", Host: "localhost"}, "digest"); err == nil {
		t.Fatal("ambiguous multi-user export accepted")
	}
}

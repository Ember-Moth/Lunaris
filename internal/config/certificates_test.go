// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"bytes"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCertificateFilesAndRotation(t *testing.T) {
	dir := t.TempDir()
	cert, _ := testutil.Certificate(t)
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("cert.pem", cert.Certificate)
	write("key.pem", cert.PrivateKey)
	config := []byte("schema_version: 1\ncertificates:\n  - id: tls\n    certificate_file: cert.pem\n    private_key_file: key.pem\ncredentials:\n  - id: user\n    secret: test-password\nlisteners:\n  - id: proxy\n    protocol: trojan\n    port: 443\n    certificate_ref: tls\n    credential_refs: [user]\n    transport: {type: ws, path: /proxy}\n")
	write("node.yaml", config)
	registry, _ := builtin.NewRegistry()
	first, err := LoadNode(filepath.Join(dir, "node.yaml"), registry)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := testutil.Certificate(t)
	write("cert.pem", second.Certificate)
	write("key.pem", second.PrivateKey)
	updated, err := LoadNode(filepath.Join(dir, "node.yaml"), registry)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificates["tls"].Certificate, updated.Certificates["tls"].Certificate) {
		t.Fatal("file rotation ignored")
	}
	write("key.pem", cert.PrivateKey)
	if _, err = LoadNode(filepath.Join(dir, "node.yaml"), registry); err == nil {
		t.Fatal("mismatched key pair accepted")
	}
}

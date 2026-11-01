// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
)

const validNode = `schema_version: 1
credentials:
  - id: personal
    secret_env: LUNARIS_TEST_SECRET
listeners:
  - id: ss
    protocol: shadowsocks
    address: 127.0.0.1
    port: 8388
    credential_refs: [personal]
    options:
      method: aes-128-gcm
limits:
  udp_idle_timeout: 30s
`

func nodeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNodeFileDefaultsAndSecretReferences(t *testing.T) {
	t.Setenv("LUNARIS_TEST_SECRET", "private-test-secret")
	registry, _ := builtin.NewRegistry()
	snapshot, err := LoadNode(nodeFile(t, validNode), registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Config.Listeners) != 1 || !snapshot.Config.Listeners[0].Enabled {
		t.Fatalf("unexpected listener: %+v", snapshot.Config.Listeners)
	}
	if snapshot.Config.Limits.UDPIdleTimeout != 30*time.Second || snapshot.Config.Limits.MaxConnections != 1024 {
		t.Fatalf("limits not normalized: %+v", snapshot.Config.Limits)
	}
	if string(snapshot.Credentials["personal"]) != "private-test-secret" {
		t.Fatal("secret not resolved")
	}
	if strings.Contains(string(snapshot.Config.Listeners[0].Options), "private-test-secret") {
		t.Fatal("secret escaped into protocol options")
	}
}

func TestNodeFileRejectsInvalidConfigWithoutLeakingSecrets(t *testing.T) {
	t.Setenv("LUNARIS_TEST_SECRET", "never-print-this-secret")
	registry, _ := builtin.NewRegistry()
	cases := map[string]string{
		"missing listeners":    "schema_version: 1\n",
		"null listeners":       "listeners: null\n",
		"unknown field":        validNode + "unexpected: never-print-this-secret\n",
		"bad protocol options": strings.Replace(validNode, "method: aes-128-gcm", "method: aes-128-gcm\n      unknown: never-print-this-secret", 1),
		"unknown protocol":     strings.Replace(validNode, "protocol: shadowsocks", "protocol: unsupported", 1),
		"empty credential":     strings.Replace(validNode, "LUNARIS_TEST_SECRET", "LUNARIS_TEST_MISSING_SECRET", 1),
		"invalid duration":     strings.Replace(validNode, "30s", "-1s", 1),
		"zero port":            strings.Replace(validNode, "8388", "0", 1),
		"unknown credential":   strings.Replace(validNode, "credential_refs: [personal]", "credential_refs: [missing]", 1),
		"duplicate field":      validNode + "schema_version: 1\n",
		"multiple documents":   validNode + "---\nschema_version: 1\n",
		"null":                 "null\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadNode(nodeFile(t, content), registry)
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error(), "never-print-this-secret") {
				t.Fatal("error exposed a secret")
			}
		})
	}
}

func TestSecretFilePathIsRelativeToNodeFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "credential"), []byte("password-with-newline\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "node.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(validNode, "secret_env: LUNARIS_TEST_SECRET", "secret_file: credential", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	registry, _ := builtin.NewRegistry()
	snapshot, err := LoadNode(path, registry)
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Credentials["personal"]) != "password-with-newline" {
		t.Fatal("secret file not loaded correctly")
	}
}

func TestNodeFileAllowsExplicitEmptyListeners(t *testing.T) {
	registry, _ := builtin.NewRegistry()
	snapshot, err := LoadNode(nodeFile(t, "schema_version: 1\nlisteners: []\n"), registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Config.Listeners) != 0 {
		t.Fatal("explicit empty node created listeners")
	}
}

func TestXHTTPYAMLAndSnapshotIsolation(t *testing.T) {
	registry, _ := builtin.NewRegistry()
	document := `schema_version: 1
credentials:
  - id: user
    secret: c8820ed3-e4ee-47ad-a5bd-ece70763e32c
listeners:
  - id: xhttp
    protocol: vless
    port: 8080
    credential_refs: [user]
    transport:
      type: xhttp
      path: /proxy
      xhttp:
        mode: packet-up
        http_version: h1
        extra:
          xPaddingBytes: "100-200"
          scMaxBufferedBytes: 2097152
`
	snapshot, err := LoadNode(nodeFile(t, document), registry)
	if err != nil {
		t.Fatal(err)
	}
	spec := snapshot.Config.Listeners[0]
	if len(spec.Network) != 1 || spec.Network[0] != "tcp" || spec.Transport.XHTTP == nil {
		t.Fatal("XHTTP config was lost")
	}
	normalized, err := registry.Normalize(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Config.Listeners[0].Transport.XHTTP.Extra[0] = '!'
	if normalized.Config.Listeners[0].Transport.XHTTP.Extra[0] != '{' {
		t.Fatal("XHTTP extra aliases source snapshot")
	}
	for _, content := range []string{strings.Replace(document, "http_version: h1", "unknown: yes", 1), strings.Replace(document, "xPaddingBytes:", "unknownPadding:", 1), strings.Replace(document, "type: xhttp", "type: tcp", 1), strings.Replace(document, "http_version: h1", "http_version: h3", 1)} {
		if _, err := LoadNode(nodeFile(t, content), registry); err == nil {
			t.Fatal("invalid XHTTP configuration accepted")
		}
	}
}

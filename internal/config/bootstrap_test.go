// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadYAMLAndResolveDataDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bootstrap.yaml")
	if err := os.WriteFile(path, []byte("data_dir: state\nadmin:\n  listen: '[::1]:9081'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.DataDir != filepath.Join(dir, "state") || got.Admin.Listen != "[::1]:9081" {
		t.Fatalf("unexpected config: %+v", got)
	}
}

func TestRejectInvalidBootstrap(t *testing.T) {
	cases := map[string]string{
		"unknown field":      "admin:\n  adress: 127.0.0.1:9080\n",
		"node configuration": "schema_version: 1\nlisteners: []\n",
		"multiple documents": "data_dir: one\n---\ndata_dir: two\n",
		"empty":              "",
		"null":               "null\n",
		"duplicate key":      "data_dir: one\ndata_dir: two\n",
		"public listener":    "admin:\n  listen: 0.0.0.0:9080\n",
		"oversized":          "data_dir: state\n" + strings.Repeat(" ", 64*1024),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bootstrap.yaml")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestManagementOriginAndTransportModes(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"https://EXAMPLE.com:443/", "https://example.com"},
		{"http://127.0.0.1:09080", "http://127.0.0.1:9080"},
		{"https://例子.com", "https://xn--fsqu00a.com"},
	}
	for _, tc := range cases {
		got, err := CanonicalOrigin(tc.raw)
		if err != nil || got != tc.want {
			t.Fatal(tc.raw, got, err)
		}
	}
	for _, raw := range []string{"null", "https://example.com/other", "https://user@example.com", "https://example.com?x=1", "https://0.0.0.0:9080", "https://*.example.com", "https://example.com\\@other"} {
		if _, err := CanonicalOrigin(raw); err == nil {
			t.Fatal("invalid origin accepted", raw)
		}
	}
	native := Defaults()
	native.Admin.Listen = "0.0.0.0:9080"
	native.Admin.PublicURL = "https://node.example.com:9080"
	native.Admin.TLS = &AdminTLS{CertificateFile: "cert.pem", PrivateKeyFile: "key.pem"}
	if err := native.Validate(); err != nil {
		t.Fatal(err)
	}
	native.Admin.TrustedProxies = []string{"127.0.0.1/32"}
	if err := native.Validate(); err == nil {
		t.Fatal("combined proxy/native modes accepted")
	}
	proxy := Defaults()
	proxy.Admin.PublicURL = "https://node.example.com"
	proxy.Admin.TrustedProxies = []string{"127.0.0.1/32"}
	if err := proxy.Validate(); err != nil {
		t.Fatal(err)
	}
	proxy.Admin.TrustedProxies = []string{"0.0.0.0/0"}
	if err := proxy.Validate(); err == nil {
		t.Fatal("universal trusted proxy range accepted")
	}
}

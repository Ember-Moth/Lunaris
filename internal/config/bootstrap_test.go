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

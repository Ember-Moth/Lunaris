// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"

	"go.yaml.in/yaml/v3"
)

type Admin struct {
	Listen string `yaml:"listen"`
}

// Bootstrap contains deployment settings, not managed proxy configuration.
type Bootstrap struct {
	DataDir string `yaml:"data_dir"`
	Admin   Admin  `yaml:"admin"`
}

func Defaults() Bootstrap {
	return Bootstrap{DataDir: "./data", Admin: Admin{Listen: "127.0.0.1:9080"}}
}

// Load resolves relative data paths against the configuration file directory.
func Load(path string) (Bootstrap, error) {
	options := Defaults()
	file, err := os.Open(path)
	if err != nil {
		return options, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil {
		return options, err
	}
	if len(content) > 64*1024 {
		return options, errors.New("bootstrap exceeds 64 KiB")
	}
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return options, fmt.Errorf("decode bootstrap: %w", err)
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return options, errors.New("bootstrap must be a YAML mapping")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&options); err != nil {
		return options, fmt.Errorf("decode bootstrap: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return options, errors.New("bootstrap must contain exactly one YAML document")
	}
	if options.DataDir != "" && !filepath.IsAbs(options.DataDir) {
		options.DataDir = filepath.Join(filepath.Dir(path), options.DataDir)
	}
	return options, options.Validate()
}

func (b Bootstrap) Validate() error {
	if b.DataDir == "" {
		return errors.New("data_dir must not be empty")
	}
	host, port, err := net.SplitHostPort(b.Admin.Listen)
	if err != nil {
		return fmt.Errorf("invalid admin listen address: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return errors.New("admin listen must use a literal loopback address until authentication and HTTPS are implemented")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return errors.New("admin listen port must be between 1 and 65535")
	}
	return nil
}

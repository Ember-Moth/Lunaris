// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Ember-Moth/Lunaris/internal/inbound"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"go.yaml.in/yaml/v3"
)

// Snapshot is the resolved input of file mode, never an API response or log value.
type Snapshot = model.RuntimeConfig

type nodeDocument struct {
	SchemaVersion int                   `yaml:"schema_version"`
	Limits        model.Limits          `yaml:"limits"`
	Credentials   []credentialDocument  `yaml:"credentials"`
	Certificates  []certificateDocument `yaml:"certificates"`
	Listeners     *[]listenerDocument   `yaml:"listeners"`
}

type certificateDocument struct {
	ID              string `yaml:"id"`
	CertificateFile string `yaml:"certificate_file"`
	PrivateKeyFile  string `yaml:"private_key_file"`
}

type credentialDocument struct {
	ID         string `yaml:"id"`
	Secret     string `yaml:"secret"`
	SecretEnv  string `yaml:"secret_env"`
	SecretFile string `yaml:"secret_file"`
}

type listenerDocument struct {
	ID             string             `yaml:"id"`
	Name           string             `yaml:"name"`
	Enabled        *bool              `yaml:"enabled"`
	Protocol       model.ProtocolType `yaml:"protocol"`
	Address        string             `yaml:"address"`
	Port           uint16             `yaml:"port"`
	Network        []string           `yaml:"network"`
	Options        map[string]any     `yaml:"options"`
	CredentialRefs []string           `yaml:"credential_refs"`
	CertificateRef string             `yaml:"certificate_ref"`
	Transport      model.Transport    `yaml:"transport"`
}

func LoadNode(path string, registry *inbound.Registry) (*Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open node configuration: %w", err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(content) > 1<<20 {
		return nil, errors.New("node configuration exceeds 1 MiB")
	}
	var tree yaml.Node
	if err := yaml.Unmarshal(content, &tree); err != nil {
		return nil, errors.New("invalid node YAML syntax")
	}
	if tree.Kind != yaml.DocumentNode || len(tree.Content) != 1 || tree.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("node configuration must be a YAML mapping")
	}
	doc := nodeDocument{SchemaVersion: model.ConfigSchemaVersion, Limits: model.DefaultLimits()}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		// YAML decoder errors can contain the offending credential value.
		return nil, errors.New("invalid node YAML fields or types (unknown and duplicate fields are rejected)")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("node configuration must contain one YAML document")
	}
	if doc.SchemaVersion != model.ConfigSchemaVersion {
		return nil, errors.New("unsupported node schema_version")
	}
	if err := model.ValidateLimits(doc.Limits); err != nil {
		return nil, err
	}
	if doc.Listeners == nil {
		return nil, errors.New("listeners must be explicitly specified; use [] for an empty node")
	}
	snapshot := &Snapshot{Config: model.NodeConfig{SchemaVersion: doc.SchemaVersion, Limits: doc.Limits, Listeners: make([]model.ListenerSpec, 0, len(*doc.Listeners))}, Credentials: make(map[string][]byte)}
	for _, credential := range doc.Credentials {
		if credential.ID == "" {
			return nil, errors.New("credential id is required")
		}
		if _, exists := snapshot.Credentials[credential.ID]; exists {
			return nil, fmt.Errorf("duplicate credential id %q", credential.ID)
		}
		secret, err := resolveSecret(credential, filepath.Dir(path))
		if err != nil {
			return nil, fmt.Errorf("credential %q: %w", credential.ID, err)
		}
		snapshot.Credentials[credential.ID] = secret
	}
	for _, listener := range *doc.Listeners {
		options, err := json.Marshal(listener.Options)
		if err != nil {
			return nil, fmt.Errorf("listener %q: options must contain JSON-compatible YAML values", listener.ID)
		}
		spec := model.ListenerSpec{ID: listener.ID, Name: listener.Name, Enabled: listener.Enabled == nil || *listener.Enabled, Protocol: listener.Protocol,
			Address: listener.Address, Port: listener.Port, Network: listener.Network, Options: options,
			CredentialRefs: listener.CredentialRefs, CertificateRef: listener.CertificateRef, Transport: listener.Transport}
		snapshot.Config.Listeners = append(snapshot.Config.Listeners, spec)
	}
	snapshot.Certificates = make(map[string]model.Certificate)
	for _, asset := range doc.Certificates {
		if asset.ID == "" {
			return nil, errors.New("certificate id is required")
		}
		if _, exists := snapshot.Certificates[asset.ID]; exists {
			return nil, errors.New("duplicate certificate id")
		}
		cert, err := readAssetFile(filepath.Dir(path), asset.CertificateFile)
		if err != nil {
			return nil, errors.New("cannot read certificate_file")
		}
		key, err := readAssetFile(filepath.Dir(path), asset.PrivateKeyFile)
		if err != nil {
			return nil, errors.New("cannot read private_key_file")
		}
		snapshot.Certificates[asset.ID] = model.Certificate{Certificate: cert, PrivateKey: key}
	}
	return registry.Normalize(snapshot)
}

func readAssetFile(base, path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("asset path required")
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(b) == 0 || len(b) > 1<<20 {
		return nil, errors.New("asset must contain 1 byte to 1 MiB")
	}
	return b, nil
}

func resolveSecret(c credentialDocument, base string) ([]byte, error) {
	count := 0
	for _, value := range []string{c.Secret, c.SecretEnv, c.SecretFile} {
		if value != "" {
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("set exactly one of secret, secret_env, secret_file")
	}
	secret := []byte(c.Secret)
	if c.SecretEnv != "" {
		secret = []byte(os.Getenv(c.SecretEnv))
	}
	if c.SecretFile != "" {
		path := c.SecretFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(base, path)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, errors.New("cannot open secret_file")
		}
		defer file.Close()
		secret, err = io.ReadAll(io.LimitReader(file, 4097))
		if err != nil {
			return nil, errors.New("cannot read secret_file")
		}
		if len(secret) > 4096 {
			return nil, errors.New("secret_file exceeds 4096 bytes")
		}
		secret = bytes.TrimSuffix(bytes.TrimSuffix(secret, []byte("\n")), []byte("\r"))
	}
	if len(secret) == 0 || len(secret) > 4096 {
		return nil, errors.New("secret must contain 1 to 4096 bytes")
	}
	return secret, nil
}

// SPDX-License-Identifier: GPL-3.0-only
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol"
	"go.yaml.in/yaml/v3"
)

// Snapshot is the resolved input of file mode, never an API response or log value.
type Snapshot = model.RuntimeConfig

type nodeDocument struct {
	SchemaVersion int                  `yaml:"schema_version"`
	Limits        model.Limits         `yaml:"limits"`
	Credentials   []credentialDocument `yaml:"credentials"`
	Listeners     []listenerDocument   `yaml:"listeners"`
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
}

func LoadNode(path string, registry *protocol.Registry) (*Snapshot, error) {
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
	if err := validateLimits(doc.Limits); err != nil {
		return nil, err
	}
	snapshot := &Snapshot{Config: model.NodeConfig{SchemaVersion: doc.SchemaVersion, Limits: doc.Limits, Listeners: make([]model.ListenerSpec, 0, len(doc.Listeners))}, Credentials: make(map[string][]byte)}
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
	ids := make(map[string]bool)
	for _, listener := range doc.Listeners {
		if listener.ID == "" || ids[listener.ID] {
			return nil, errors.New("listener ids must be non-empty and unique")
		}
		ids[listener.ID] = true
		if listener.Address == "" {
			listener.Address = "127.0.0.1"
		}
		if _, err := netip.ParseAddr(listener.Address); err != nil {
			return nil, fmt.Errorf("listener %q: address must be a literal IP", listener.ID)
		}
		if listener.Port == 0 {
			return nil, fmt.Errorf("listener %q: port must be between 1 and 65535", listener.ID)
		}
		if len(listener.Network) == 0 {
			listener.Network = []string{"tcp", "udp"}
		}
		networks := make(map[string]bool)
		for _, network := range listener.Network {
			if (network != "tcp" && network != "udp") || networks[network] {
				return nil, fmt.Errorf("listener %q: network must contain unique tcp/udp entries", listener.ID)
			}
			networks[network] = true
		}
		factory, ok := registry.Lookup(listener.Protocol)
		if !ok {
			return nil, fmt.Errorf("listener %q: unsupported protocol %q", listener.ID, listener.Protocol)
		}
		for _, ref := range listener.CredentialRefs {
			if _, exists := snapshot.Credentials[ref]; !exists {
				return nil, fmt.Errorf("listener %q: unknown credential reference", listener.ID)
			}
		}
		options, err := json.Marshal(listener.Options)
		if err != nil {
			return nil, fmt.Errorf("listener %q: options must contain JSON-compatible YAML values", listener.ID)
		}
		spec := model.ListenerSpec{ID: listener.ID, Name: listener.Name, Enabled: listener.Enabled == nil || *listener.Enabled, Protocol: listener.Protocol,
			Address: listener.Address, Port: listener.Port, Network: listener.Network, Options: options,
			CredentialRefs: listener.CredentialRefs, CertificateRef: listener.CertificateRef}
		if fields := factory.Validate(spec); len(fields) != 0 {
			return nil, fmt.Errorf("listener %q: %s: %s", spec.ID, fields[0].Path, fields[0].Message)
		}
		snapshot.Config.Listeners = append(snapshot.Config.Listeners, spec)
	}
	if err := checkEndpoints(snapshot.Config.Listeners); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func validateLimits(l model.Limits) error {
	for name, duration := range map[string]time.Duration{"dial_timeout": l.DialTimeout, "handshake_timeout": l.HandshakeTimeout, "udp_idle_timeout": l.UDPIdleTimeout, "shutdown_timeout": l.ShutdownTimeout} {
		if duration <= 0 || duration > 24*time.Hour {
			return fmt.Errorf("%s must be positive and no greater than 24h", name)
		}
	}
	for name, count := range map[string]int{"max_connections": l.MaxConnections, "max_pending_handshakes": l.MaxPendingHandshakes, "max_udp_sessions": l.MaxUDPSessions, "max_udp_destinations": l.MaxUDPDestinations} {
		if count <= 0 || count > 65536 {
			return fmt.Errorf("%s must be between 1 and 65536", name)
		}
	}
	if l.UDPQueueSize <= 0 || l.UDPQueueSize > 1024 {
		return errors.New("udp_queue_size must be between 1 and 1024")
	}
	return nil
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

func checkEndpoints(listeners []model.ListenerSpec) error {
	for i, a := range listeners {
		if !a.Enabled {
			continue
		}
		for _, b := range listeners[:i] {
			if !b.Enabled || a.Port != b.Port {
				continue
			}
			for _, network := range a.Network {
				if !strings.Contains(" "+strings.Join(b.Network, " ")+" ", " "+network+" ") {
					continue
				}
				ipA, ipB := netip.MustParseAddr(a.Address).Unmap(), netip.MustParseAddr(b.Address).Unmap()
				if ipA == ipB || ipA.IsUnspecified() || ipB.IsUnspecified() {
					return fmt.Errorf("listeners %q and %q have overlapping %s endpoints", a.ID, b.ID, network)
				}
			}
		}
	}
	return nil
}

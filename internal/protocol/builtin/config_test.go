// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	"testing"
)

func TestProtocolValidation(t *testing.T) {
	cert, _ := testutil.Certificate(t)
	registry, _ := builtin.NewRegistry()
	base := func() *model.RuntimeConfig {
		return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "a", Enabled: true, Protocol: "vless", Address: "127.0.0.1", Port: 12345, CredentialRefs: []string{"user"}, Options: []byte("{}")}}}, Credentials: map[string][]byte{"user": []byte(userID)}, Certificates: map[string]model.Certificate{"tls": cert}}
	}
	for name, change := range map[string]func(*model.RuntimeConfig){
		"bad UUID": func(c *model.RuntimeConfig) { c.Credentials["user"] = []byte("not-uuid") },
		"duplicate UUID": func(c *model.RuntimeConfig) {
			c.Credentials["other"] = []byte("C8820ED3-E4EE-47AD-A5BD-ECE70763E32C")
			c.Config.Listeners[0].CredentialRefs = append(c.Config.Listeners[0].CredentialRefs, "other")
		},
		"udp socket for vless": func(c *model.RuntimeConfig) { c.Config.Listeners[0].Network = []string{"udp"} },
		"unknown transport":    func(c *model.RuntimeConfig) { c.Config.Listeners[0].Transport.Type = "grpc" },
		"missing ws path":      func(c *model.RuntimeConfig) { c.Config.Listeners[0].Transport.Type = "ws" },
		"missing TLS":          func(c *model.RuntimeConfig) { c.Config.Listeners[0].Protocol = "trojan" },
		"missing certificate":  func(c *model.RuntimeConfig) { c.Config.Listeners[0].CertificateRef = "missing" },
		"invalid pair": func(c *model.RuntimeConfig) {
			v := c.Certificates["tls"]
			v.PrivateKey = []byte("bad-secret-key")
			c.Certificates["tls"] = v
		},
		"vision unsupported": func(c *model.RuntimeConfig) { c.Config.Listeners[0].Options = []byte(`{"flow":"xtls-rprx-vision"}`) },
		"tuic missing user mapping": func(c *model.RuntimeConfig) {
			c.Config.Listeners[0].Protocol = "tuic"
			c.Config.Listeners[0].CertificateRef = "tls"
		},
		"quic tcp socket": func(c *model.RuntimeConfig) {
			c.Config.Listeners[0].Protocol = "hysteria2"
			c.Config.Listeners[0].CertificateRef = "tls"
			c.Config.Listeners[0].Network = []string{"tcp"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			change(c)
			if _, err := registry.Normalize(c); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	normalized, err := registry.Normalize(base())
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Config.Listeners[0].Network[0] != "tcp" || normalized.Config.Listeners[0].Transport.Type != "tcp" {
		t.Fatal("stream socket default incorrect")
	}
	c := base()
	c.Config.Listeners[0].Protocol = "hysteria2"
	c.Config.Listeners[0].CertificateRef = "tls"
	normalized, err = registry.Normalize(c)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Config.Listeners[0].Network[0] != "udp" || normalized.Config.Listeners[0].Transport.Type != "quic" {
		t.Fatal("QUIC socket default incorrect")
	}
	c.Certificates["tls"].PrivateKey[0] = '!'
	if normalized.Certificates["tls"].PrivateKey[0] == '!' {
		t.Fatal("certificate snapshot aliases source")
	}
}

func TestAnyTLSAlwaysUsesUOTV2(t *testing.T) {
	cert, _ := testutil.Certificate(t)
	registry, err := builtin.NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	input := &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "anytls", Protocol: "anytls", Enabled: true, Address: "127.0.0.1", Port: 8443, CertificateRef: "cert", CredentialRefs: []string{"user"}, Options: []byte("{}")}}}, Credentials: map[string][]byte{"user": []byte(password)}, Certificates: map[string]model.Certificate{"cert": cert}}
	normalized, err := registry.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if !normalized.Config.Listeners[0].UDPOverTCP {
		t.Fatal("AnyTLS UoT v2 is not enabled by default")
	}
	factory, _ := registry.Protocols().Lookup("anytls")
	caps := factory.Capabilities()
	if !caps.UDPRelay || !caps.UDPOverTCPRequired || caps.UDPOverTCPVersion != 2 {
		t.Fatal("AnyTLS UDP capabilities do not reflect its fixed UoT v2 path")
	}
}

func TestNewProtocolConfiguration(t *testing.T) {
	cert, _ := testutil.Certificate(t)
	registry, _ := builtin.NewRegistry()
	key := "AQEBAQEBAQEBAQEBAQEBAQ=="
	serverKey := "AwMDAwMDAwMDAwMDAwMDAw=="
	base := func() *model.RuntimeConfig {
		return &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "test", Enabled: true, Protocol: "shadowsocks", Address: "127.0.0.1", Port: 8443, CredentialRefs: []string{"user"}, Options: []byte(`{"method":"2022-blake3-aes-128-gcm","server_key_ref":"server"}`)}}}, Credentials: map[string][]byte{"user": []byte(key), "server": []byte(serverKey)}, Certificates: map[string]model.Certificate{"tls": cert}}
	}
	good, err := registry.Normalize(base())
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.CredentialRefs(good.Config.Listeners[0])) != 2 {
		t.Fatal("missing server key asset")
	}
	for name, change := range map[string]func(*model.RuntimeConfig){
		"missing server key": func(c *model.RuntimeConfig) { delete(c.Credentials, "server") },
		"short key":          func(c *model.RuntimeConfig) { c.Credentials["user"] = []byte("eA==") },
		"long key": func(c *model.RuntimeConfig) {
			c.Credentials["user"] = []byte("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
		},
		"noncanonical key":  func(c *model.RuntimeConfig) { c.Credentials["user"] = []byte(key + "\n") },
		"duplicate keys":    func(c *model.RuntimeConfig) { c.Credentials["server"] = c.Credentials["user"] },
		"key chain in user": func(c *model.RuntimeConfig) { c.Credentials["user"] = []byte(serverKey + ":" + key) },
		"chacha multi": func(c *model.RuntimeConfig) {
			c.Config.Listeners[0].Options = []byte(`{"method":"2022-blake3-chacha20-poly1305","server_key_ref":"server"}`)
		},
		"classic multi": func(c *model.RuntimeConfig) {
			c.Config.Listeners[0].Options = []byte(`{"method":"aes-128-gcm","server_key_ref":"server"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			change(c)
			if _, err := registry.Normalize(c); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	c := base()
	s := &c.Config.Listeners[0]
	s.Protocol = "naive"
	s.CertificateRef = "tls"
	s.Options = []byte(`{"users":[{"username":"alice","credential_ref":"user"}]}`)
	for _, kind := range []string{"http", "quic"} {
		s.Transport.Type = kind
		result, err := registry.Normalize(c)
		if err != nil {
			t.Fatal(err)
		}
		network := "tcp"
		if kind == "quic" {
			network = "udp"
		}
		if result.Config.Listeners[0].Network[0] != network || !result.Config.Listeners[0].UDPOverTCP {
			t.Fatal("invalid Naive default network or UoT policy")
		}
	}
	for _, options := range []string{`{}`, `{"users":[{"username":"a:b","credential_ref":"user"}]}`, `{"users":[{"username":"alice","credential_ref":"missing"}]}`, `{"users":[{"username":"alice","credential_ref":"user"}],"unknown":true}`} {
		s.Options = []byte(options)
		if _, err := registry.Normalize(c); err == nil {
			t.Fatal("invalid Naive user options accepted")
		}
	}
}

// Keep the registry's snapshot ownership coverage independent of file parsing.
func TestXHTTPConfigurationSnapshotIsolation(t *testing.T) {
	registry, _ := builtin.NewRegistry()
	input := &model.RuntimeConfig{
		Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{
			ID: "xhttp", Enabled: true, Protocol: "vless", Address: "127.0.0.1", Port: 8080, CredentialRefs: []string{"user"}, Options: []byte(`{}`),
			Transport: model.Transport{Type: "xhttp", Path: "/proxy", XHTTP: &model.XHTTP{Mode: "packet-up", HTTPVersion: "h1", Extra: []byte(`{"xPaddingBytes":"100-200","scMaxBufferedBytes":2097152}`)}},
		}}}, Credentials: map[string][]byte{"user": []byte(userID)},
	}
	normalized, err := registry.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Config.Listeners[0].Network) != 1 || normalized.Config.Listeners[0].Network[0] != "tcp" {
		t.Fatal("XHTTP network default missing")
	}
	input.Config.Listeners[0].Transport.XHTTP.Extra[0] = '!'
	if normalized.Config.Listeners[0].Transport.XHTTP.Extra[0] != '{' {
		t.Fatal("XHTTP options alias the caller's snapshot")
	}
	normalized.Config.Listeners[0].Transport.XHTTP.Extra = []byte(`{"unknownPadding":"100-200"}`)
	if _, err := registry.Normalize(normalized); err == nil {
		t.Fatal("unknown XHTTP option accepted")
	}
}

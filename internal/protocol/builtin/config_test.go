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

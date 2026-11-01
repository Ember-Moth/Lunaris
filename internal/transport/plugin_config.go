// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	P "github.com/Ember-Moth/Lunaris/internal/transport/ssplugin"
	engine "github.com/metacubex/restls-client-go"
)

// PluginFactory registers one built-in Shadowsocks carrier without owning protocol logic.
type PluginFactory struct{ Kind string }

func (f PluginFactory) Capabilities() Capabilities {
	if f.Kind == "kcptun" {
		return Capabilities{Type: f.Kind, UDP: true, UDPStreams: true}
	}
	return Capabilities{Type: f.Kind, TCP: true, TLS: f.Kind == "v2ray-plugin" || f.Kind == "gost-plugin"}
}
func (f PluginFactory) Validate(s model.ListenerSpec) []model.FieldError {
	if s.Transport.Reality != nil || s.Transport.XHTTP != nil {
		return field("transport", "plugin carriers cannot combine with REALITY or XHTTP")
	}
	if !f.Capabilities().TLS && (s.CertificateRef != "" || s.Transport.Path != "" || s.Transport.Host != "") {
		return field("transport", "this plugin does not use certificate_ref, path or host")
	}
	cfg, _, err := parsePlugin(f.Kind, s, nil, false)
	if err != nil {
		return field("transport.plugin", err.Error())
	}
	if cfg.V2Ray.WebSocket.HTTPUpgrade && cfg.V2Ray.WebSocket.MaxEarlyData > 0 {
		return field("transport.plugin", "HTTPUpgrade does not accept WebSocket early data")
	}
	return nil
}
func (f PluginFactory) CredentialRefs(s model.ListenerSpec) []string {
	_, ref, err := parsePlugin(f.Kind, s, nil, false)
	if err != nil || ref == "" {
		return nil
	}
	return []string{ref}
}
func (f PluginFactory) ValidateAssets(r ResolvedSpec) error {
	_, _, err := parsePlugin(f.Kind, model.ListenerSpec{Transport: r.Transport}, r.Secrets, true)
	return err
}
func parsePlugin(kind string, s model.ListenerSpec, secrets map[string][]byte, resolve bool) (*P.Config, string, error) {
	values := make(map[string]any)
	if len(s.Transport.Plugin) > 0 {
		d := json.NewDecoder(bytes.NewReader(s.Transport.Plugin))
		d.UseNumber()
		if err := d.Decode(&values); err != nil {
			return nil, "", errors.New("invalid plugin options")
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return nil, "", errors.New("invalid plugin options")
		}
		if values == nil {
			return nil, "", errors.New("plugin options must be an object")
		}
	}
	for _, name := range []string{"password", "key", "host", "path", "tls"} {
		if _, ok := values[name]; ok {
			return nil, "", errors.New("use credential references and the transport host/path/certificate fields")
		}
	}
	for _, name := range []string{"handshake-timeout", "handshake_timeout"} {
		if _, ok := values[name]; ok {
			return nil, "", errors.New("configure handshake_timeout in node limits")
		}
	}
	var ref, secretField string
	switch kind {
	case "shadow-tls", "restls":
		secretField = "password"
	case "kcptun":
		for _, field := range []string{"conn", "autoexpire", "scavengettl"} {
			if _, ok := values[field]; ok {
				return nil, "", errors.New("kcptun connection pool settings belong to the client")
			}
		}
		secretField = "key"
	case "v2ray-plugin", "gost-plugin":
		if _, ok := values["mode"]; !ok {
			values["mode"] = "websocket"
		}
		values["host"] = s.Transport.Host
		path := s.Transport.Path
		if path == "" {
			path = "/"
		}
		values["path"] = path
		values["tls"] = s.CertificateRef != ""
	}
	if secretField != "" {
		value, exists := values[secretField+"_ref"]
		if exists {
			var ok bool
			ref, ok = value.(string)
			if !ok || strings.TrimSpace(ref) == "" {
				return nil, "", errors.New("invalid plugin secret reference")
			}
			delete(values, secretField+"_ref")
			if resolve {
				secret := secrets[ref]
				if len(secret) == 0 || len(secret) > 4096 {
					return nil, "", errors.New("invalid resolved plugin secret")
				}
				values[secretField] = string(secret)
			} else {
				values[secretField] = "resolved-plugin-secret"
			}
		}
	}
	cfg, err := P.Parse(kind, values)
	if err != nil {
		return nil, "", err
	}
	if cfg.Name == P.NameRestls && (cfg.Restls.MinRecordLen > 16384 || len(cfg.Restls.Script) > 4096) {
		return nil, "", errors.New("Restls record or script exceeds limit")
	}
	if cfg.Name == P.NameRestls {
		if _, err := engine.NewRestlsConfig("localhost", "validation", "tls13", cfg.Restls.Script, "chrome"); err != nil {
			return nil, "", errors.New("invalid Restls script")
		}
	}
	if cfg.Name == P.NameKcptun {
		c := cfg.Kcptun
		if c.MTU > 1500 || c.SndWnd > 65535 || c.RcvWnd > 65535 || c.DataShard > 256 || c.ParityShard > 256 || c.DataShard+c.ParityShard > 256 || c.SockBuf > 64<<20 || c.SmuxBuf > 64<<20 || c.StreamBuf > c.SmuxBuf || c.StreamBuf > 64<<20 || c.KeepAlive > 300 || c.RateLimit > 1<<30 || c.Interval > 5000 || c.Resend > 2 || c.NoDelay > 1 || c.NoCongestion > 1 {
			return nil, "", errors.New("kcptun option exceeds supported bounds")
		}
	}
	return cfg, ref, nil
}

// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/cloudwego/hertz/pkg/app"
)

type connectionRequest struct {
	Revision      string `json:"committed_revision"`
	Host          string `json:"host"`
	Port          uint16 `json:"port,omitempty"`
	CredentialRef string `json:"credential_ref,omitempty"`
	ServerName    string `json:"server_name,omitempty"`
}

func validPublicHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && ip.Zone() == ""
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func (a *API) connectionInfo(ctx context.Context, c *app.RequestContext) {
	p := principalFrom(ctx)
	if !p.session.ReauthUntil.After(time.Now()) {
		a.fail(c, 403, 40301, "Recent administrator authentication is required", nil)
		return
	}
	var request connectionRequest
	if !a.decode(ctx, c, &request, 4096, false) {
		return
	}
	if request.Revision == "" || !validPublicHost(request.Host) || request.ServerName != "" && !validPublicHost(request.ServerName) {
		a.fail(c, 422, 42200, "Supply a committed revision and explicit client host", nil)
		return
	}
	id := strings.Clone(c.Param("id"))
	snapshot, spec, digest, err := a.service.CommittedListener(ctx, request.Revision, id)
	if err != nil {
		a.error(c, err, false)
		return
	}
	info, err := connectionParameters(snapshot, spec, request, digest)
	if err != nil {
		a.fail(c, 422, 42200, "Select a valid listener credential and client server name", nil)
		return
	}
	// Recheck both authorization and committed/runtime identity after preparing
	// secret-bearing data. Nothing sensitive is emitted before these checks pass.
	_, session, err := a.auth.Session(ctx, p.token)
	if err != nil {
		a.error(c, err, false)
		return
	}
	if !session.ReauthUntil.After(time.Now()) {
		a.fail(c, 403, 40301, "Recent authentication expired", nil)
		return
	}
	_, _, current, err := a.service.CommittedListener(ctx, request.Revision, id)
	if err != nil {
		a.error(c, err, false)
		return
	}
	if current != digest {
		a.fail(c, 409, 40900, "Listener changed during export", nil)
		return
	}
	a.audit(ctx, "client connection parameters exported")
	reply(c, 200, 0, "ok", info)
}
func connectionParameters(snapshot *model.RuntimeConfig, s model.ListenerSpec, r connectionRequest, digest string) (map[string]any, error) {
	ref := r.CredentialRef
	if ref == "" && len(s.CredentialRefs) == 1 {
		ref = s.CredentialRefs[0]
	}
	if !slices.Contains(s.CredentialRefs, ref) {
		return nil, errors.New("credential selection required")
	}
	secret := string(snapshot.Credentials[ref])
	if secret == "" {
		return nil, errors.New("missing credential")
	}
	port := r.Port
	if port == 0 {
		port = s.Port
	}
	options := map[string]any{}
	if len(s.Options) > 0 {
		if err := json.Unmarshal(s.Options, &options); err != nil {
			return nil, err
		}
	}
	if options == nil {
		options = map[string]any{}
	}
	authentication := map[string]any{"credential_ref": ref, "password": secret}
	for _, user := range userMappings(options) {
		if user["credential_ref"] == ref {
			for _, field := range []string{"username", "uuid", "id"} {
				if value, ok := user[field]; ok {
					authentication[field] = value
				}
			}
		}
	}
	switch s.Protocol {
	case "vless", "vmess":
		delete(authentication, "password")
		authentication["uuid"] = secret
	case "shadowsocks":
		if key, ok := options["server_key_ref"].(string); ok && key != "" {
			authentication["password"] = string(snapshot.Credentials[key]) + ":" + secret
		}
	case "shadowsocksr":
		if _, ok := authentication["id"]; !ok {
			authentication["id"] = 1
		}
		if key, ok := options["server_key_ref"].(string); ok && key != "" {
			authentication["cipher_password"] = string(snapshot.Credentials[key])
		}
	}
	if ref, ok := options["decryption_ref"].(string); ok && ref != "" {
		value, err := publicVLESS(string(snapshot.Credentials[ref]))
		if err != nil {
			return nil, err
		}
		options["encryption"] = value
	}
	delete(options, "users")
	delete(options, "server_key_ref")
	delete(options, "decryption_ref")
	transport := map[string]any{"type": s.Transport.Type}
	if s.Transport.Path != "" {
		transport["path"] = s.Transport.Path
	}
	if s.Transport.Host != "" {
		transport["host"] = s.Transport.Host
	}
	serverName := r.ServerName
	if serverName == "" {
		serverName = r.Host
	}
	if s.Transport.Reality != nil {
		reality := s.Transport.Reality
		key, err := base64.RawURLEncoding.Strict().DecodeString(string(snapshot.Credentials[reality.PrivateKeyRef]))
		if err != nil {
			return nil, err
		}
		private, err := ecdh.X25519().NewPrivateKey(key)
		if err != nil {
			return nil, err
		}
		if r.ServerName == "" {
			serverName = reality.ServerNames[0]
		}
		if !slices.Contains(reality.ServerNames, serverName) {
			return nil, errors.New("server name not configured")
		}
		transport["reality"] = map[string]any{"public_key": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "server_name": serverName, "short_id": reality.ShortIDs[0]}
	}
	if s.Transport.XHTTP != nil {
		transport["xhttp"] = s.Transport.XHTTP
	}
	if len(s.Transport.Plugin) > 0 {
		var plugin map[string]any
		if err := json.Unmarshal(s.Transport.Plugin, &plugin); err != nil {
			return nil, err
		}
		for _, field := range []string{"password", "key"} {
			if ref, ok := plugin[field+"_ref"].(string); ok {
				plugin[field] = string(snapshot.Credentials[ref])
				delete(plugin, field+"_ref")
			}
		}
		if s.Transport.Type == "restls" || s.Transport.Type == "shadow-tls" {
			if r.ServerName == "" {
				target, _ := plugin["handshake"].(string)
				if target == "" {
					target, _ = plugin["dest"].(string)
				}
				if host, _, err := net.SplitHostPort(target); err == nil {
					serverName = host
				}
			}
			plugin["server_name"] = serverName
		}
		for _, field := range []string{"dest", "handshake", "strict-mode", "strict_mode", "strict", "max-sessions", "max_sessions", "max-streams", "max_streams", "max-active-streams", "max_active_streams", "max-session-queued-bytes", "max_session_queued_bytes", "max-queued-bytes", "max_queued_bytes", "allow-insecure", "allow_insecure"} {
			delete(plugin, field)
		}
		transport["plugin"] = plugin
	}
	if s.CertificateRef != "" {
		certificate := snapshot.Certificates[s.CertificateRef]
		pair, err := tls.X509KeyPair(certificate.Certificate, certificate.PrivateKey)
		if err != nil || len(pair.Certificate) == 0 {
			return nil, errors.New("certificate unavailable")
		}
		sum := sha256.Sum256(pair.Certificate[0])
		transport["tls"] = map[string]any{"server_name": serverName, "certificate_sha256": hex.EncodeToString(sum[:]), "verify_certificate": true}
	}
	return map[string]any{"format": "parameters-v1", "committed_revision": r.Revision, "listener_id": s.ID, "spec_digest": digest, "protocol": s.Protocol, "listen_network": s.Network, "endpoint": map[string]any{"host": r.Host, "port": port}, "authentication": authentication, "protocol_options": options, "transport": transport, "udp_over_tcp": s.UDPOverTCP, "multiplex": s.Multiplex}, nil
}
func userMappings(options map[string]any) []map[string]any {
	var out []map[string]any
	if users, ok := options["users"].([]any); ok {
		for _, value := range users {
			if user, ok := value.(map[string]any); ok {
				out = append(out, user)
			}
		}
	}
	return out
}
func publicVLESS(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" {
		return "", errors.New("invalid encryption configuration")
	}
	parts[2] = "1rtt"
	found := false
	for i := 3; i < len(parts); i++ {
		key, err := base64.RawURLEncoding.Strict().DecodeString(parts[i])
		if err != nil {
			continue
		}
		switch len(key) {
		case 32:
			private, err := ecdh.X25519().NewPrivateKey(key)
			if err != nil {
				return "", err
			}
			parts[i] = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
			found = true
		case 64:
			private, err := mlkem.NewDecapsulationKey768(key)
			if err != nil {
				return "", err
			}
			parts[i] = base64.RawURLEncoding.EncodeToString(private.EncapsulationKey().Bytes())
			found = true
		}
	}
	if !found {
		return "", errors.New("missing encryption key")
	}
	return strings.Join(parts, "."), nil
}

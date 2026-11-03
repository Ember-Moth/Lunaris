// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"encoding/json"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/builtin"
	"testing"
)

func TestSnellMieruSSRConfiguration(t *testing.T) {
	registry, _ := builtin.NewRegistry()
	cases := []struct {
		name, kind, options string
		refs                []string
		valid               bool
	}{
		{"snell-default", "snell", `{}`, []string{"one"}, true},
		{"snell-v6", "snell", `{"version":6}`, []string{"one"}, true},
		{"snell-invalid-version", "snell", `{"version":3}`, []string{"one"}, false},
		{"snell-v6-obfs", "snell", `{"version":6,"obfs":"http"}`, []string{"one"}, false},
		{"snell-v5-mode", "snell", `{"version":5,"mode":"unshaped"}`, []string{"one"}, false},
		{"snell-multiple-psk", "snell", `{}`, []string{"one", "two"}, true},
		{"snell-raw-multiple-psk", "snell", `{"version":6,"mode":"unsafe-raw"}`, []string{"one", "two"}, false},
		{"mieru", "mieru", `{"users":[{"username":"alice","credential_ref":"one"}]}`, []string{"one"}, true},
		{"mieru-missing-users", "mieru", `{}`, []string{"one"}, false},
		{"mieru-duplicate-users", "mieru", `{"users":[{"username":"alice","credential_ref":"one"},{"username":"alice","credential_ref":"two"}]}`, []string{"one", "two"}, false},
		{"mieru-bad-mtu", "mieru", `{"users":[{"username":"alice","credential_ref":"one"}],"mtu":1}`, []string{"one"}, false},
		{"mieru-bad-pattern", "mieru", `{"users":[{"username":"alice","credential_ref":"one"}],"traffic_pattern":"!"}`, []string{"one"}, false},
		{"ssr-single", "shadowsocksr", `{"method":"aes-128-cfb","protocol":"origin"}`, []string{"one"}, true},
		{"ssr-multi", "shadowsocksr", `{"method":"aes-128-cfb","protocol":"auth_aes128_sha1","server_key_ref":"server","users":[{"id":1,"credential_ref":"one"},{"id":2,"credential_ref":"two"}]}`, []string{"one", "two"}, true},
		{"ssr-duplicate-id", "shadowsocksr", `{"method":"aes-128-cfb","protocol":"auth_aes128_sha1","server_key_ref":"server","users":[{"id":1,"credential_ref":"one"},{"id":1,"credential_ref":"two"}]}`, []string{"one", "two"}, false},
		{"ssr-zero-id", "shadowsocksr", `{"method":"aes-128-cfb","protocol":"auth_aes128_sha1","users":[{"id":0,"credential_ref":"one"}]}`, []string{"one"}, false},
		{"ssr-origin-multi", "shadowsocksr", `{"method":"aes-128-cfb","protocol":"origin"}`, []string{"one", "two"}, false},
		{"ssr-2022", "shadowsocksr", `{"method":"2022-blake3-aes-128-gcm","protocol":"origin"}`, []string{"one"}, false},
		{"ssr-unknown-option", "shadowsocksr", `{"method":"aes-128-cfb","protocol":"origin","mystery":true}`, []string{"one"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := &model.RuntimeConfig{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits(), Listeners: []model.ListenerSpec{{ID: "test", Enabled: true, Protocol: model.ProtocolType(tc.kind), Port: 8388, CredentialRefs: tc.refs, Options: json.RawMessage(tc.options)}}}, Credentials: map[string][]byte{"one": []byte(password), "two": []byte("second-user-password"), "server": []byte("server-key")}}
			_, err := registry.Normalize(input)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if tc.name == "ssr-multi" {
				delete(input.Credentials, "server")
				if _, err = registry.Normalize(input); err == nil {
					t.Fatal("missing server key accepted")
				}
			}
			if tc.name == "snell-v6" {
				input.Credentials["one"] = []byte("short")
				if _, err = registry.Normalize(input); err == nil {
					t.Fatal("short v6 PSK accepted")
				}
			}
		})
	}
}

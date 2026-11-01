// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"encoding/json"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"strings"
	"testing"
)

func TestPluginConfigurationFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		kind string
		opts string
		path string
		want bool
	}{
		{"obfs", `{"mode":"tls"}`, "", true},
		{"obfs", `{"mode":"http","typo":true}`, "", false},
		{"shadow-tls", `{"version":3,"handshake":"localhost:443","password_ref":"key"}`, "", true},
		{"shadow-tls", `{"version":3,"handshake":"localhost:443","password":"secret"}`, "", false},
		{"shadow-tls", `{"version":3,"handshake":"localhost:443"}`, "", false},
		{"restls", `{"dest":"localhost:443","password_ref":"key","restls-script":"invalid"}`, "", false},
		{"v2ray-plugin", `{"mux":true}`, "/proxy?ed=2048", true},
		{"v2ray-plugin", `{"mode":"quic"}`, "/proxy", false},
		{"v2ray-plugin", `{"handshake-timeout":1}`, "/proxy", false},
		{"v2ray-plugin", `{"v2ray-http-upgrade":true}`, "/proxy?ed=2048", false},
		{"v2ray-plugin", `{}`, "/proxy?foo=x", false},
		{"v2ray-plugin", `{}`, "/proxy?ed=", false},
		{"v2ray-plugin", `{"mux":true,"host":"secret"}`, "/proxy", false},
		{"kcptun", `{"key_ref":"key"}`, "", true},
		{"kcptun", `{"key_ref":"key","crypt":"none"}`, "", false},
		{"kcptun", `{"key_ref":"key","datashard":9223372036854775807,"parityshard":9223372036854775807}`, "", false},
		{"kcptun", `{"key_ref":"key","smuxver":3}`, "", false},
		{"kcptun", `{"key_ref":"key","conn":4}`, "", false},
	} {
		s := model.ListenerSpec{Transport: model.Transport{Type: tc.kind, Plugin: json.RawMessage(tc.opts), Path: tc.path}}
		f := PluginFactory{Kind: tc.kind}
		if ok := len(f.Validate(s)) == 0; ok != tc.want {
			t.Errorf("%s %s: valid=%v", tc.kind, tc.opts, ok)
		}
	}
	f := PluginFactory{Kind: "shadow-tls"}
	s := model.ListenerSpec{Transport: model.Transport{Type: "shadow-tls", Plugin: []byte(`{"version":3,"handshake":"localhost:443","password_ref":"key"}`)}}
	if refs := f.CredentialRefs(s); len(refs) != 1 || refs[0] != "key" {
		t.Fatal(refs)
	}
	err := f.ValidateAssets(ResolvedSpec{Transport: s.Transport, Secrets: map[string][]byte{}})
	if err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatal(err)
	}
	if err := f.ValidateAssets(ResolvedSpec{Transport: s.Transport, Secrets: map[string][]byte{"key": []byte("secret-value")}}); err != nil {
		t.Fatal(err)
	}
	for _, factory := range []Factory{NativeFactory{}, TCPFactory{}, WebSocketFactory{}, RealityFactory{}, XHTTPFactory{}, QUICFactory{}} {
		if len(factory.Validate(model.ListenerSpec{Transport: model.Transport{Plugin: []byte(`{}`)}})) == 0 {
			t.Fatalf("%T ignored plugin options", factory)
		}
	}
}

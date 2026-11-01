// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"github.com/Ember-Moth/Lunaris/internal/model"
	"testing"
)

func TestXHTTPStrictServerOptions(t *testing.T) {
	for _, extra := range []string{` `, `[]`, `null`, `{"unknown":true}`, `{"downloadSettings":{}}`, `{"xmux":{"maxConnections":3}}`, `{"scMinPostsIntervalMs":1}`, `{"xPaddingBytes":"4294967297"}`, `{"xPaddingBytes":-1}`, `{"scMaxEachPostBytes":-1}`, `{"scMaxBufferedBytes":-1}`, `{"h3InitialStreamReceiveWindow":8388608,"h3MaxStreamReceiveWindow":1048576}`} {
		if _, err := parseXHTTP(model.Transport{Type: "xhttp", XHTTP: &model.XHTTP{Extra: []byte(extra)}}); err == nil {
			t.Errorf("invalid server options accepted: %s", extra)
		}
	}
	for _, path := range []string{"relative", "//path", "/a%2fb", "/path#fragment"} {
		if _, err := parseXHTTP(model.Transport{Type: "xhttp", Path: path}); err == nil {
			t.Errorf("invalid path %q", path)
		}
	}
	for _, version := range []string{"", "auto", "h1", "h2", "h3"} {
		spec := model.ListenerSpec{Transport: model.Transport{Type: "xhttp", XHTTP: &model.XHTTP{HTTPVersion: version}}, CertificateRef: "tls"}
		if fields := (XHTTPFactory{}).Validate(spec); len(fields) > 0 {
			t.Fatal(fields)
		}
		caps := CapabilitiesFor(XHTTPFactory{}, spec)
		if caps.UDP != (version == "h3") || caps.TCP == (version == "h3") {
			t.Fatal("wrong socket capabilities", version)
		}
	}
}

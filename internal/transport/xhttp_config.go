// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	X "github.com/Ember-Moth/Lunaris/internal/transport/xhttp"
)

type XHTTPFactory struct{}

func (XHTTPFactory) Capabilities() Capabilities {
	return Capabilities{Type: "xhttp", TCP: true, UDP: true, TLS: true, UDPStreams: true}
}
func (f XHTTPFactory) CapabilitiesFor(s model.ListenerSpec) Capabilities {
	c := f.Capabilities()
	h3 := s.Transport.XHTTP != nil && s.Transport.XHTTP.HTTPVersion == "h3"
	c.TCP = !h3
	c.UDP = h3
	return c
}
func (f XHTTPFactory) Validate(s model.ListenerSpec) []model.FieldError {
	if s.Transport.Reality != nil {
		return field("transport.reality", "XHTTP does not combine with the REALITY transport")
	}
	if _, err := parseXHTTP(s.Transport); err != nil {
		return field("transport.xhttp", err.Error())
	}
	if f.CapabilitiesFor(s).UDP && s.CertificateRef == "" {
		return field("certificate_ref", "XHTTP HTTP/3 requires TLS")
	}
	return nil
}
func parseXHTTP(t model.Transport) (X.Config, error) {
	options := t.XHTTP
	if options == nil {
		options = &model.XHTTP{}
	}
	if !slices.Contains([]string{"", "auto", "h1", "h2", "h3"}, options.HTTPVersion) {
		return X.Config{}, errors.New("http_version must be auto, h1, h2 or h3")
	}
	path := t.Path
	if path == "" {
		path = "/"
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || u.Fragment != "" || u.EscapedPath() != u.Path || len(path) > 1024 {
		return X.Config{}, errors.New("path must be an unescaped absolute HTTP path, optionally with a query")
	}
	if strings.ContainsAny(t.Host, "\r\n\t /\\[]") {
		return X.Config{}, errors.New("invalid XHTTP host")
	}
	if strings.Contains(t.Host, ":") {
		if _, err := netip.ParseAddr(t.Host); err != nil {
			return X.Config{}, errors.New("XHTTP host must not include a port")
		}
	}
	// Keep server controls in Xray's original spelling, but reject outbound-only
	// options instead of storing settings that cannot affect a node listener.
	allowed := map[string]bool{}
	for _, key := range strings.Fields("xPaddingBytes xPaddingObfsMode xPaddingKey xPaddingHeader xPaddingPlacement xPaddingMethod sessionIDPlacement sessionIDKey seqPlacement seqKey uplinkDataPlacement uplinkDataKey noSSEHeader scMaxEachPostBytes scMaxBufferedPosts scMaxBufferedBytes scMaxTotalBufferedBytes scMaxActiveSessions scMaxConcurrentRequests scStreamUpServerSecs serverMaxHeaderBytes h3InitialStreamReceiveWindow h3MaxStreamReceiveWindow h3InitialConnectionReceiveWindow h3MaxConnectionReceiveWindow") {
		allowed[key] = true
	}
	if len(options.Extra) > 64<<10 {
		return X.Config{}, errors.New("extra exceeds 64 KiB")
	}
	if len(options.Extra) > 0 {
		if len(bytes.TrimSpace(options.Extra)) == 0 || bytes.TrimSpace(options.Extra)[0] != '{' {
			return X.Config{}, errors.New("extra must be a JSON object")
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal(options.Extra, &values); err != nil {
			return X.Config{}, errors.New("invalid extra JSON")
		}
		for key := range values {
			if !allowed[key] {
				return X.Config{}, fmt.Errorf("unsupported server extra field %q", key)
			}
		}
	}
	cfg, err := X.Parse(t.Host, path, options.Mode, string(options.Extra))
	if err != nil {
		return cfg, err
	}
	if cfg.ScMaxEachPostBytes.To > 16<<20 || cfg.XPaddingBytes.To > 65536 {
		return cfg, errors.New("post payload exceeds 16 MiB or padding exceeds 64 KiB")
	}
	if cfg.ScMaxTotalBufferedBytes > 1<<30 || cfg.ScMaxBufferedBytes > 64<<20 {
		return cfg, errors.New("upload buffer limits exceed 1 GiB total or 64 MiB per session")
	}
	if cfg.H3MaxConnectionReceiveWindow > 1<<30 || cfg.H3MaxStreamReceiveWindow > 64<<20 {
		return cfg, errors.New("HTTP/3 receive windows exceed configured safety bounds")
	}
	return cfg, nil
}

// SPDX-License-Identifier: GPL-3.0-only
package outbound

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	singhttp "github.com/sagernet/sing/protocol/http"
)

type authOptions struct {
	Username string `json:"username,omitempty"`
}

func normalizeAuth(spec model.OutboundSpec, secret []byte, socks bool) (json.RawMessage, error) {
	var options authOptions
	if err := decodeOptions(spec.Options, &options); err != nil {
		return nil, err
	}
	if (options.Username == "") != (len(secret) == 0) || len(options.Username) > 255 || strings.ContainsAny(options.Username, "\x00\r\n:") || socks && len(secret) > 255 {
		return nil, errors.New("authentication requires a valid username and credential reference")
	}
	return json.Marshal(options)
}

type httpFactory struct{}

func (httpFactory) Capabilities() Capabilities { return Capabilities{Protocol: "http", TCP: true} }
func (httpFactory) Normalize(s model.OutboundSpec, secret []byte) (json.RawMessage, error) {
	return normalizeAuth(s, secret, false)
}
func (httpFactory) Build(s model.OutboundSpec, secret []byte, d N.Dialer) (ProtocolClient, error) {
	var options authOptions
	_ = json.Unmarshal(s.Options, &options)
	return &httpClient{singhttp.NewClient(singhttp.Options{Dialer: d, Server: M.ParseSocksaddrHostPort(s.Address, s.Port), Username: options.Username, Password: string(secret)})}, nil
}

type httpClient struct{ *singhttp.Client }

func (*httpClient) Close() error { return nil }

// Package xhttp implements the Xray XHTTP/SplitHTTP transport.
// Derived from XTLS/Xray-core transport/internet/splithttp at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.
package xhttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"time"
)

// Mode names, the supported server backend, field placements and padding schemes
// accepted in the extra configuration.
const (
	ModeAuto      = "auto"
	ModePacketUp  = "packet-up"
	ModeStreamUp  = "stream-up"
	ModeStreamOne = "stream-one"

	ServerBackendNetHTTP = "net/http"

	PlacementQueryInHeader = "queryInHeader"
	PlacementCookie        = "cookie"
	PlacementHeader        = "header"
	PlacementQuery         = "query"
	PlacementPath          = "path"
	PlacementBody          = "body"
	PlacementAuto          = "auto"

	PaddingRepeatX  = "repeat-x"
	PaddingTokenish = "tokenish"
)

// Config is the validated XHTTP configuration in the upstream option names.
type Config struct {
	// PendingTimeout is a runtime admission budget, not an Xray wire option.
	PendingTimeout time.Duration
	Host           string
	Path           string
	Mode           string
	// ServerBackend is retained only so a configured value can be rejected
	// explicitly; net/http is the sole supported backend.
	ServerBackend                    string
	Headers                          map[string]string
	XPaddingBytes                    Range
	XPaddingObfsMode                 bool
	XPaddingKey                      string
	XPaddingHeader                   string
	XPaddingPlacement                string
	XPaddingMethod                   string
	UplinkHTTPMethod                 string
	SessionIDPlacement               string
	SessionIDKey                     string
	SessionIDTable                   string
	SessionIDLength                  Range
	SeqPlacement                     string
	SeqKey                           string
	UplinkDataPlacement              string
	UplinkDataKey                    string
	UplinkChunkSize                  Range
	NoGRPCHeader                     bool
	NoSSEHeader                      bool
	ScMaxEachPostBytes               Range
	ScMinPostsIntervalMs             Range
	ScMaxBufferedPosts               int
	ScMaxBufferedBytes               int64
	ScMaxTotalBufferedBytes          int64
	ScMaxActiveSessions              int
	ScMaxConcurrentRequests          int
	ScStreamUpServerSecs             Range
	ServerMaxHeaderBytes             int
	H3InitialStreamReceiveWindow     int64
	H3MaxStreamReceiveWindow         int64
	H3InitialConnectionReceiveWindow int64
	H3MaxConnectionReceiveWindow     int64
	XMUX                             XMUXConfig
	Download                         *DownloadConfig
}

// XMUXConfig bounds how sessions share the client's pooled HTTP connections.
type XMUXConfig struct {
	MaxConcurrency   Range `json:"maxConcurrency"`
	MaxConnections   Range `json:"maxConnections"`
	CMaxReuseTimes   Range `json:"cMaxReuseTimes"`
	HMaxRequestTimes Range `json:"hMaxRequestTimes"`
	HMaxReusableSecs Range `json:"hMaxReusableSecs"`
	HKeepAlivePeriod int64 `json:"hKeepAlivePeriod"`
}

// DownloadConfig selects a separate server and transport for the download half
// of a session.
type DownloadConfig struct {
	Address   string
	TLSConfig *tls.Config
	Transport Config
}

// DialPacketFunc opens the UDP socket an HTTP/3 client uses and resolves the
// server address.
type DialPacketFunc func(context.Context, string) (net.PacketConn, net.Addr, error)

type rawConfig struct {
	Host                             string            `json:"host"`
	Path                             string            `json:"path"`
	Mode                             string            `json:"mode"`
	ServerBackend                    string            `json:"serverBackend"`
	Headers                          map[string]string `json:"headers"`
	XPaddingBytes                    Range             `json:"xPaddingBytes"`
	XPaddingObfsMode                 bool              `json:"xPaddingObfsMode"`
	XPaddingKey                      string            `json:"xPaddingKey"`
	XPaddingHeader                   string            `json:"xPaddingHeader"`
	XPaddingPlacement                string            `json:"xPaddingPlacement"`
	XPaddingMethod                   string            `json:"xPaddingMethod"`
	UplinkHTTPMethod                 string            `json:"uplinkHTTPMethod"`
	SessionIDPlacement               string            `json:"sessionIDPlacement"`
	SessionIDKey                     string            `json:"sessionIDKey"`
	SessionIDTable                   string            `json:"sessionIDTable"`
	SessionIDLength                  Range             `json:"sessionIDLength"`
	SeqPlacement                     string            `json:"seqPlacement"`
	SeqKey                           string            `json:"seqKey"`
	UplinkDataPlacement              string            `json:"uplinkDataPlacement"`
	UplinkDataKey                    string            `json:"uplinkDataKey"`
	UplinkChunkSize                  Range             `json:"uplinkChunkSize"`
	NoGRPCHeader                     bool              `json:"noGRPCHeader"`
	NoSSEHeader                      bool              `json:"noSSEHeader"`
	ScMaxEachPostBytes               Range             `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs             Range             `json:"scMinPostsIntervalMs"`
	ScMaxBufferedPosts               int64             `json:"scMaxBufferedPosts"`
	ScMaxBufferedBytes               int64             `json:"scMaxBufferedBytes"`
	ScMaxTotalBufferedBytes          int64             `json:"scMaxTotalBufferedBytes"`
	ScMaxActiveSessions              int64             `json:"scMaxActiveSessions"`
	ScMaxConcurrentRequests          int64             `json:"scMaxConcurrentRequests"`
	ScStreamUpServerSecs             Range             `json:"scStreamUpServerSecs"`
	ServerMaxHeaderBytes             int32             `json:"serverMaxHeaderBytes"`
	H3InitialStreamReceiveWindow     int64             `json:"h3InitialStreamReceiveWindow"`
	H3MaxStreamReceiveWindow         int64             `json:"h3MaxStreamReceiveWindow"`
	H3InitialConnectionReceiveWindow int64             `json:"h3InitialConnectionReceiveWindow"`
	H3MaxConnectionReceiveWindow     int64             `json:"h3MaxConnectionReceiveWindow"`
	XMUX                             XMUXConfig        `json:"xmux"`
	DownloadSettings                 *rawStreamConfig  `json:"downloadSettings"`
	Extra                            json.RawMessage   `json:"extra"`
}

type rawStreamConfig struct {
	Address           string     `json:"address"`
	Port              uint16     `json:"port"`
	Method            string     `json:"method"`
	Network           string     `json:"network"`
	Security          string     `json:"security"`
	TLSSettings       rawTLS     `json:"tlsSettings"`
	XHTTPSettings     *rawConfig `json:"xhttpSettings"`
	SplitHTTPSettings *rawConfig `json:"splithttpSettings"`
}

type rawTLS struct {
	ServerName    string   `json:"serverName"`
	AllowInsecure bool     `json:"allowInsecure"`
	ALPN          []string `json:"alpn"`
}

// Derived from XTLS/Xray-core transport/internet/splithttp/config.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func (config Config) normalizedPath() string {
	path := strings.SplitN(config.Path, "?", 2)[0]
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if config.SessionIDPlacement == PlacementPath || config.SeqPlacement == PlacementPath {
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
	}
	return path
}

func (config Config) normalizedQuery() string {
	parts := strings.SplitN(config.Path, "?", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func (config Config) requestHeader() http.Header {
	header := make(http.Header, len(config.Headers)+8)
	for key, value := range config.Headers {
		header.Add(key, value)
	}
	applyDefaultFetchHeaders(header)
	return header
}

func applyDefaultFetchHeaders(header http.Header) {
	if header.Get("User-Agent") == "golang" {
		header.Del("User-Agent")
		return
	}
	if header.Get("User-Agent") == "" {
		header.Set(
			"User-Agent",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "+
				"Chrome/149.0.0.0 Safari/537.36",
		)
		header.Set("Accept-Language", "en-US,en;q=0.9")
		header.Set("DNT", "1")
	}
	header.Set("Sec-Fetch-Mode", "cors")
	header.Set("Sec-Fetch-Dest", "empty")
	header.Set("Sec-Fetch-Site", "same-origin")
	if header.Get("Priority") == "" {
		header.Set("Priority", "u=1, i")
	}
	if header.Get("Cache-Control") == "" {
		header.Set("Cache-Control", "no-cache")
	}
	if header.Get("Pragma") == "" {
		header.Set("Pragma", "no-cache")
	}
	if header.Get("Accept") == "" {
		header.Set("Accept", "*/*")
	}
}

func (config Config) fillStreamRequest(request *http.Request, sessionID string) {
	request.Header = config.requestHeader()
	config.applyPaddingRequest(request)
	config.applyMeta(request, sessionID, "")
	if request.Body != nil && !config.NoGRPCHeader {
		request.Header.Set("Content-Type", "application/grpc")
	}
}

func (config Config) fillPacketRequest(request *http.Request, sessionID, sequence string, payload []byte) {
	switch config.UplinkDataPlacement {
	case PlacementHeader:
		request.Header = config.requestHeader()
		config.payloadHeaders(request.Header, payload)
	case PlacementCookie:
		request.Header = config.requestHeader()
		config.payloadCookies(request, payload)
	default:
		request.Header = config.requestHeader()
		request.Body = newBytesReadCloser(payload)
		request.ContentLength = int64(len(payload))
	}
	config.applyPaddingRequest(request)
	config.applyMeta(request, sessionID, sequence)
}

func (config Config) payloadHeaders(header http.Header, payload []byte) {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	for index := 0; len(encoded) > 0; index++ {
		size := min(config.UplinkChunkSize.random(), len(encoded))
		header.Set(fmt.Sprintf("%s-%d", config.UplinkDataKey, index), encoded[:size])
		encoded = encoded[size:]
	}
}

func (config Config) payloadCookies(request *http.Request, payload []byte) {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	for index := 0; len(encoded) > 0; index++ {
		size := min(config.UplinkChunkSize.random(), len(encoded))
		//nolint:gosec // XHTTP cookies carry protocol fields, not browser credentials
		request.AddCookie(&http.Cookie{Name: fmt.Sprintf("%s_%d", config.UplinkDataKey, index), Value: encoded[:size]})
		encoded = encoded[size:]
	}
}

func (config Config) applyMeta(request *http.Request, sessionID, sequence string) {
	applyMetaValue(request, config.SessionIDPlacement, config.SessionIDKey, sessionID)
	applyMetaValue(request, config.SeqPlacement, config.SeqKey, sequence)
}

func applyMetaValue(request *http.Request, placement, key, value string) {
	if value == "" {
		return
	}
	switch placement {
	case PlacementPath:
		request.URL.Path = appendPath(request.URL.Path, value)
	case PlacementQuery:
		query := request.URL.Query()
		query.Set(key, value)
		request.URL.RawQuery = query.Encode()
	case PlacementHeader:
		request.Header.Set(key, value)
	case PlacementCookie:
		//nolint:gosec // XHTTP cookies carry protocol fields, not browser credentials
		request.AddCookie(&http.Cookie{Name: key, Value: value})
	}
}

func (config Config) extractMeta(request *http.Request) (string, string) {
	path := config.normalizedPath()
	suffix := ""
	if len(request.URL.Path) >= len(path) {
		suffix = request.URL.Path[len(path):]
	}
	parts := strings.Split(suffix, "/")
	position := 0
	sessionID := extractMetaValue(request, config.SessionIDPlacement, config.SessionIDKey, parts, &position)
	sequence := extractMetaValue(request, config.SeqPlacement, config.SeqKey, parts, &position)
	return sessionID, sequence
}

func extractMetaValue(request *http.Request, placement, key string, path []string, position *int) string {
	switch placement {
	case PlacementPath:
		if *position < len(path) {
			value := path[*position]
			*position++
			return value
		}
	case PlacementQuery:
		return request.URL.Query().Get(key)
	case PlacementHeader:
		return request.Header.Get(key)
	case PlacementCookie:
		if cookie, err := request.Cookie(key); err == nil {
			return cookie.Value
		}
	}
	return ""
}

func (config Config) generateSessionID() string {
	table := config.SessionIDTable
	length := config.SessionIDLength.random()
	if table != "" && length > 0 {
		output := make([]byte, length)
		random := make([]byte, length)
		if _, err := rand.Read(random); err == nil {
			for index := range output {
				output[index] = table[int(random[index])%len(table)]
			}
			return string(output)
		}
	}
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	random[6] = random[6]&0x0f | 0x40
	random[8] = random[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", random[0:4], random[4:6], random[6:8], random[8:10], random[10:16])
}

func appendPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}

func (config Config) requestURL(address string, tlsConfig *tls.Config) *url.URL {
	scheme := "http"
	if tlsConfig != nil {
		scheme = "https"
	}
	host := config.Host
	if host == "" && tlsConfig != nil {
		host = tlsConfig.ServerName
	}
	if host == "" {
		host, _, _ = net.SplitHostPort(address)
		if host == "" {
			host = address
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return &url.URL{Scheme: scheme, Host: host, Path: config.normalizedPath(), RawQuery: config.normalizedQuery()}
}

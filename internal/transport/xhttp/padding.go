// Derived from XTLS/Xray-core transport/internet/splithttp/xpadding.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"crypto/rand"
	"math"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const (
	base62                     = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	averageHuffmanBytes        = 0.8
	paddingValidationTolerance = 2
)

var cachedRepeatX = strings.Repeat("X", 8192)

type paddingPlacement struct {
	placement string
	key       string
	header    string
	rawURL    string
}

func generatePadding(method string, length int) string {
	if length <= 0 {
		return ""
	}
	if method != PaddingTokenish {
		if length <= len(cachedRepeatX) {
			return cachedRepeatX[:length]
		}
		return strings.Repeat("X", length)
	}
	count := max(1, int(math.Ceil(float64(length)/averageHuffmanBytes)))
	value := randomString(count, base62)
	adjust := byte('X')
	for range 150 {
		difference := int(hpack.HuffmanEncodeLength(value)) - length
		if abs(difference) <= paddingValidationTolerance {
			return value
		}
		if difference < 0 {
			value += string(adjust)
			if adjust == 'X' {
				adjust = 'Z'
			} else {
				adjust = 'X'
			}
		} else if len(value) > 1 {
			value = value[:len(value)-1]
		}
	}
	return value
}

func randomString(length int, table string) string {
	if length <= 0 || table == "" {
		return ""
	}
	output := make([]byte, length)
	buffer := make([]byte, 256)
	limit := 256 - 256%len(table)
	for position := 0; position < length; {
		if _, err := rand.Read(buffer); err != nil {
			return strings.Repeat("X", length)
		}
		for _, value := range buffer {
			if int(value) >= limit {
				continue
			}
			output[position] = table[int(value)%len(table)]
			position++
			if position == length {
				break
			}
		}
	}
	return string(output)
}

func (config Config) clientPadding(request *http.Request) paddingPlacement {
	if config.XPaddingObfsMode {
		return paddingPlacement{
			placement: config.XPaddingPlacement,
			key:       config.XPaddingKey,
			header:    config.XPaddingHeader,
			rawURL:    request.URL.String(),
		}
	}
	return paddingPlacement{
		placement: PlacementQueryInHeader,
		key:       "x_padding",
		header:    "Referer",
		rawURL:    request.URL.String(),
	}
}

func (config Config) applyPaddingRequest(request *http.Request) {
	placement := config.clientPadding(request)
	value := generatePadding(config.XPaddingMethod, config.XPaddingBytes.random())
	switch placement.placement {
	case PlacementHeader:
		request.Header.Set(placement.header, value)
	case PlacementQueryInHeader:
		target, err := url.Parse(placement.rawURL)
		if err == nil {
			target.RawQuery = placement.key + "=" + value
			request.Header.Set(placement.header, target.String())
		}
	case PlacementCookie:
		//nolint:gosec // XHTTP cookies carry protocol fields, not browser credentials
		request.AddCookie(&http.Cookie{Name: placement.key, Value: value, Path: "/"})
	case PlacementQuery:
		query := request.URL.Query()
		query.Set(placement.key, value)
		request.URL.RawQuery = query.Encode()
	}
}

func (config Config) applyPaddingResponse(writer http.ResponseWriter) {
	value := generatePadding(config.XPaddingMethod, config.XPaddingBytes.random())
	if config.XPaddingObfsMode {
		switch config.XPaddingPlacement {
		case PlacementHeader:
			writer.Header().Set(config.XPaddingHeader, value)
		case PlacementQueryInHeader:
			writer.Header().Set(config.XPaddingHeader, "?"+config.XPaddingKey+"="+value)
		case PlacementCookie:
			//nolint:gosec // XHTTP cookies carry protocol fields, not browser credentials
			http.SetCookie(writer, &http.Cookie{Name: config.XPaddingKey, Value: value, Path: "/"})
		}
		return
	}
	writer.Header().Set("X-Padding", value)
}

func (config Config) requestPadding(request *http.Request) string {
	if !config.XPaddingObfsMode {
		if referer := request.Header.Get("Referer"); referer != "" {
			if parsed, err := url.Parse(referer); err == nil {
				return parsed.Query().Get("x_padding")
			}
		}
		return request.URL.Query().Get("x_padding")
	}
	if cookie, err := request.Cookie(config.XPaddingKey); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	if header := request.Header.Get(config.XPaddingHeader); header != "" {
		if config.XPaddingPlacement == PlacementHeader {
			return header
		}
		if parsed, err := url.Parse(header); err == nil {
			return parsed.Query().Get(config.XPaddingKey)
		}
	}
	return request.URL.Query().Get(config.XPaddingKey)
}

func (config Config) validPadding(value string) bool {
	if value == "" {
		return false
	}
	length := len(value)
	if config.XPaddingMethod == PaddingTokenish {
		length = int(hpack.HuffmanEncodeLength(value))
	}
	tolerance := 0
	if config.XPaddingMethod == PaddingTokenish {
		tolerance = paddingValidationTolerance
	}
	return length >= int(config.XPaddingBytes.From)-tolerance && length <= int(config.XPaddingBytes.To)+tolerance
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

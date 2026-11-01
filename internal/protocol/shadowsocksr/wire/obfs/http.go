// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package obfs

import (
	"bytes"
	"net/http"
	"strings"
)

const maxHTTPHeader = 64 * 1024

var (
	httpHeaderEnd      = []byte("\r\n\r\n")
	httpLineEnd        = []byte("\r\n")
	httpHostPrefix     = []byte("Host: ")
	httpResponsePrefix = []byte("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Encoding: gzip\r\nContent-Type: text/html\r\nDate: ")
	httpResponseSuffix = []byte("\r\nServer: nginx\r\nVary: Accept-Encoding\r\n\r\n")
)

type httpDefinition struct {
	config Config
	hosts  [][]byte
}

func newHTTPDefinition(config Config) *httpDefinition {
	definition := &httpDefinition{config: config}
	if config.Param != "" {
		values := strings.Split(strings.SplitN(config.Param, "#", 2)[0], ",")
		definition.hosts = make([][]byte, len(values))
		for index, value := range values {
			definition.hosts[index] = []byte(value)
		}
	}
	return definition
}

func (*httpDefinition) Overhead() int { return 0 }

func (d *httpDefinition) NewStream() Stream { return &httpStream{config: d.config, hosts: d.hosts} }

type httpStream struct {
	config       Config
	hosts        [][]byte
	receive      []byte
	headerScan   int
	receivedHead bool
	wroteHead    bool
}

func (s *httpStream) Decode(input []byte) ([]byte, bool, bool, error) {
	if s.receivedHead {
		return input, true, false, nil
	}
	if len(s.receive)+len(input) > maxHTTPHeader {
		return nil, false, false, ErrAuthentication
	}
	s.receive = append(s.receive, input...)
	if len(s.receive) >= 5 && !bytes.HasPrefix(s.receive, []byte("GET ")) && !bytes.HasPrefix(s.receive, []byte("POST ")) {
		return nil, false, false, ErrAuthentication
	}
	headerEnd := bytes.Index(s.receive[s.headerScan:], httpHeaderEnd)
	if headerEnd < 0 {
		s.headerScan = max(0, len(s.receive)-len(httpHeaderEnd)+1)
		return nil, false, false, nil
	}
	headerEnd += s.headerScan
	header := s.receive[:headerEnd]
	firstLineEnd := bytes.Index(header, httpLineEnd)
	if firstLineEnd < 0 {
		return nil, false, false, ErrAuthentication
	}
	firstLine := header[:firstLineEnd]
	pathStart := bytes.IndexByte(firstLine, '/')
	pathEnd := bytes.LastIndex(firstLine, []byte(" HTTP/"))
	if pathStart < 0 || pathEnd <= pathStart {
		return nil, false, false, ErrAuthentication
	}
	encoded := firstLine[pathStart+1 : pathEnd]
	if len(encoded)%3 != 0 {
		return nil, false, false, ErrAuthentication
	}
	decodedLength := len(encoded) / 3
	for index := 0; index < decodedLength; index++ {
		position := index * 3
		if encoded[position] != '%' {
			return nil, false, false, ErrAuthentication
		}
		high, highValid := httpHexNibble(encoded[position+1])
		low, lowValid := httpHexNibble(encoded[position+2])
		if !highValid || !lowValid {
			return nil, false, false, ErrAuthentication
		}
		s.receive[index] = high<<4 | low
	}
	if decodedLength < 4 {
		return nil, false, false, ErrAuthentication
	}
	if len(s.hosts) > 0 {
		host := httpHostValue(header[firstLineEnd+2:])
		if colon := bytes.LastIndexByte(host, ':'); colon >= 0 {
			host = host[:colon]
		}
		valid := false
		for _, candidate := range s.hosts {
			if bytes.Equal(host, candidate) {
				valid = true
				break
			}
		}
		if !valid {
			return nil, false, false, ErrAuthentication
		}
	}
	payload := s.receive[headerEnd+len(httpHeaderEnd):]
	copy(s.receive[decodedLength:], payload)
	decoded := s.receive[:decodedLength+len(payload)]
	s.receive = nil
	s.receivedHead = true
	return decoded, true, false, nil
}

func httpHostValue(header []byte) []byte {
	for len(header) > 0 {
		end := bytes.Index(header, httpLineEnd)
		if end < 0 {
			end = len(header)
		}
		if bytes.HasPrefix(header[:end], httpHostPrefix) {
			return header[len(httpHostPrefix):end]
		}
		if end == len(header) {
			break
		}
		header = header[end+len(httpLineEnd):]
	}
	return nil
}

func httpHexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func (s *httpStream) Encode(dst, input []byte) ([]byte, error) {
	if !s.wroteHead {
		s.wroteHead = true
		dst = append(dst, httpResponsePrefix...)
		dst = s.config.Now().AppendFormat(dst, http.TimeFormat)
		dst = append(dst, httpResponseSuffix...)
	}
	return append(dst, input...), nil
}

func (s *httpStream) Close() { s.receive = nil }

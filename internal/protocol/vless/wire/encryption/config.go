// Configuration grammar follows XTLS/Xray-core infra/conf/vless.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.
package encryption

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const Method = "mlkem768x25519plus"

type ServerConfig struct {
	keys        [][]byte
	xorMode     uint32
	secondsFrom int64
	secondsTo   int64
	padding     string
}

type ClientConfig struct {
	keys    [][]byte
	xorMode uint32
	seconds uint32
	padding string
}

func ParseServerConfig(raw string) (*ServerConfig, error) {
	if raw == "" || raw == "none" {
		return nil, nil
	}
	fields := strings.Split(raw, ".")
	if len(fields) < 4 || fields[0] != Method {
		return nil, fmt.Errorf("unsupported VLESS decryption")
	}
	xorMode, err := parseMode(fields[1])
	if err != nil {
		return nil, err
	}
	secondsFrom, secondsTo, err := parseTicket(fields[2])
	if err != nil {
		return nil, err
	}
	padding, keys, err := splitPaddingAndKeys(fields[3:], 32, 64)
	if err != nil {
		return nil, err
	}
	config := &ServerConfig{keys: keys, xorMode: xorMode, secondsFrom: secondsFrom, secondsTo: secondsTo, padding: padding}
	instance, err := config.NewInstance()
	if err != nil {
		return nil, err
	}
	_ = instance.Close()
	return config, nil
}

func ParseClientConfig(raw string) (*ClientConfig, error) {
	if raw == "" || raw == "none" {
		return nil, nil
	}
	fields := strings.Split(raw, ".")
	if len(fields) < 4 || fields[0] != Method {
		return nil, fmt.Errorf("unsupported VLESS encryption")
	}
	xorMode, err := parseMode(fields[1])
	if err != nil {
		return nil, err
	}
	var seconds uint32
	switch fields[2] {
	case "1rtt":
	case "0rtt":
		seconds = 1
	default:
		return nil, fmt.Errorf("invalid VLESS encryption RTT")
	}
	padding, keys, err := splitPaddingAndKeys(fields[3:], 32, 1184)
	if err != nil {
		return nil, err
	}
	config := &ClientConfig{keys: keys, xorMode: xorMode, seconds: seconds, padding: padding}
	if _, err := config.NewInstance(); err != nil {
		return nil, err
	}
	return config, nil
}

func (c *ServerConfig) NewInstance() (*ServerInstance, error) {
	return c.NewInstanceWithLimit(defaultMaxSessions)
}

func (c *ServerConfig) NewInstanceWithLimit(maxSessions int) (*ServerInstance, error) {
	instance := &ServerInstance{MaxSessions: maxSessions}
	if err := instance.Init(cloneKeys(c.keys), c.xorMode, c.secondsFrom, c.secondsTo, c.padding); err != nil {
		return nil, err
	}
	return instance, nil
}

func (c *ClientConfig) NewInstance() (*ClientInstance, error) {
	instance := new(ClientInstance)
	if err := instance.Init(cloneKeys(c.keys), c.xorMode, c.seconds, c.padding); err != nil {
		return nil, err
	}
	return instance, nil
}

func parseMode(mode string) (uint32, error) {
	switch mode {
	case "native":
		return 0, nil
	case "xorpub":
		return 1, nil
	case "random":
		return 2, nil
	default:
		return 0, fmt.Errorf("invalid VLESS encryption mode")
	}
}

func parseTicket(raw string) (int64, int64, error) {
	raw = strings.TrimSuffix(raw, "s")
	parts := strings.SplitN(raw, "-", 2)
	from, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || from < 0 || from > 65535 {
		return 0, 0, fmt.Errorf("invalid VLESS encryption ticket")
	}
	if len(parts) == 1 {
		return from, 0, nil
	}
	to, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || to < from || to > 65535 {
		return 0, 0, fmt.Errorf("invalid VLESS encryption ticket range")
	}
	return from, to, nil
}

func splitPaddingAndKeys(fields []string, keyLengths ...int) (string, [][]byte, error) {
	firstKey := -1
	var keys [][]byte
	for index, field := range fields {
		decoded, err := base64.RawURLEncoding.DecodeString(field)
		if err == nil && validLength(len(decoded), keyLengths) {
			if firstKey < 0 {
				firstKey = index
			}
			keys = append(keys, decoded)
			continue
		}
		if firstKey >= 0 {
			return "", nil, errors.New("invalid VLESS encryption key chain")
		}
	}
	if firstKey < 0 || len(keys) == 0 {
		return "", nil, errors.New("missing VLESS encryption key")
	}
	if len(keys) > 8 {
		return "", nil, errors.New("too many VLESS encryption keys")
	}
	padding := strings.Join(fields[:firstKey], ".")
	var paddingLens, paddingGaps [][3]int
	if err := ParsePadding(padding, &paddingLens, &paddingGaps); err != nil {
		return "", nil, err
	}
	return padding, keys, nil
}

func validLength(length int, accepted []int) bool {
	for _, candidate := range accepted {
		if length == candidate {
			return true
		}
	}
	return false
}

func cloneKeys(keys [][]byte) [][]byte {
	cloned := make([][]byte, len(keys))
	for index := range keys {
		cloned[index] = append([]byte(nil), keys[index]...)
	}
	return cloned
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

func indexGeoDataEntries(data []byte, kind geoDataKind) (map[string][][]byte, error) {
	entries, err := bytesFields(data, 1)
	if err != nil {
		return nil, err
	}
	if len(entries) > 16384 {
		return nil, errors.New("route: too many geodata entries")
	}
	indexed := make(map[string][][]byte, len(entries))
	for _, entry := range entries {
		code, found, parseErr := stringField(entry, 1)
		if parseErr != nil {
			return nil, parseErr
		}
		code = strings.ToUpper(strings.TrimSpace(code))
		if !found || code == "" {
			return nil, errors.New("route: geodata category code missing")
		}
		if _, exists := indexed[code]; exists && kind != geoDataIP {
			return nil, fmt.Errorf("route: duplicate geodata category %q", code)
		}
		indexed[code] = append(indexed[code], entry)
	}
	return indexed, nil
}

func parseGeoSiteEntry(entry []byte, attributes []string) ([]Selector, error) {
	domains, err := bytesFields(entry, 2)
	if err != nil {
		return nil, err
	}
	selectors := make([]Selector, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		matches, matchErr := geoSiteDomainHasAttributes(domain, attributes)
		if matchErr != nil {
			return nil, matchErr
		}
		if !matches {
			continue
		}
		typeValue, parseErr := varintField(domain, 1)
		if parseErr != nil {
			return nil, parseErr
		}
		value, found, parseErr := stringField(domain, 2)
		if parseErr != nil {
			return nil, parseErr
		}
		if !found || value == "" || typeValue > 3 {
			return nil, errors.New("route: invalid geosite domain")
		}
		prefix := "keyword:"
		switch typeValue {
		case 1:
			prefix = "regex:"
		case 2:
			prefix = "suffix:"
		case 3:
			prefix = "full:"
		}
		selector, _, selectorErr := parseSelector(prefix + value)
		if selectorErr != nil {
			return nil, selectorErr
		}
		key := selector.Key()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		selectors = append(selectors, selector)
	}
	return selectors, nil
}

func parseGeoIPEntry(entry []byte) ([]netip.Prefix, error) {
	inverse, err := varintField(entry, 3)
	if err != nil {
		return nil, err
	}
	if inverse != 0 {
		return nil, errors.New("route: inverse GeoIP categories are unsupported")
	}
	cidrs, err := bytesFields(entry, 2)
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	seen := make(map[netip.Prefix]struct{}, len(cidrs))
	for _, cidr := range cidrs {
		rawIP, found, parseErr := rawBytesField(cidr, 1)
		if parseErr != nil {
			return nil, parseErr
		}
		bits, parseErr := varintField(cidr, 2)
		if parseErr != nil {
			return nil, parseErr
		}
		if !found {
			return nil, errors.New("route: geoip address missing")
		}
		address, ok := netip.AddrFromSlice(rawIP)
		if !ok || bits > uint64(address.BitLen()) {
			return nil, errors.New("route: invalid geoip prefix")
		}
		if address.Is4In6() {
			if bits < 96 {
				return nil, errors.New("route: invalid mapped IPv4 prefix")
			}
			bits -= 96
		}
		prefix := netip.PrefixFrom(address.Unmap(), int(bits)).Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func geoSiteDomainHasAttributes(domain []byte, wanted []string) (bool, error) {
	if len(wanted) == 0 {
		return true, nil
	}
	attributeMessages, err := bytesFields(domain, 3)
	if err != nil {
		return false, err
	}
	found := make(map[string]struct{}, len(attributeMessages))
	for _, attribute := range attributeMessages {
		key, loaded, parseErr := stringField(attribute, 1)
		if parseErr != nil {
			return false, parseErr
		}
		if loaded {
			found[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
		}
	}
	for _, attribute := range wanted {
		if _, loaded := found[attribute]; !loaded {
			return false, nil
		}
	}
	return true, nil
}

func bytesFields(data []byte, wanted protowire.Number) ([][]byte, error) {
	values := make([][]byte, 0)
	for len(data) > 0 {
		number, wireType, tagLength := protowire.ConsumeTag(data)
		if tagLength < 0 {
			return nil, protowire.ParseError(tagLength)
		}
		data = data[tagLength:]
		if number == wanted && wireType != protowire.BytesType {
			return nil, errors.New("route: invalid protobuf field type")
		}
		if number == wanted && wireType == protowire.BytesType {
			value, length := protowire.ConsumeBytes(data)
			if length < 0 {
				return nil, protowire.ParseError(length)
			}
			if len(values) >= maxExpandedSelectors {
				return nil, errors.New("route: geodata field budget exceeded")
			}
			values = append(values, value)
			data = data[length:]
			continue
		}
		length := protowire.ConsumeFieldValue(number, wireType, data)
		if length < 0 {
			return nil, protowire.ParseError(length)
		}
		data = data[length:]
	}
	return values, nil
}

func stringField(data []byte, wanted protowire.Number) (string, bool, error) {
	value, found, err := rawBytesField(data, wanted)
	return string(value), found, err
}

func rawBytesField(data []byte, wanted protowire.Number) ([]byte, bool, error) {
	for len(data) > 0 {
		number, wireType, tagLength := protowire.ConsumeTag(data)
		if tagLength < 0 {
			return nil, false, protowire.ParseError(tagLength)
		}
		data = data[tagLength:]
		if number == wanted && wireType != protowire.BytesType {
			return nil, false, errors.New("route: invalid protobuf field type")
		}
		if number == wanted && wireType == protowire.BytesType {
			value, length := protowire.ConsumeBytes(data)
			if length < 0 {
				return nil, false, protowire.ParseError(length)
			}
			return value, true, nil
		}
		length := protowire.ConsumeFieldValue(number, wireType, data)
		if length < 0 {
			return nil, false, protowire.ParseError(length)
		}
		data = data[length:]
	}
	return nil, false, nil
}

func varintField(data []byte, wanted protowire.Number) (uint64, error) {
	for len(data) > 0 {
		number, wireType, tagLength := protowire.ConsumeTag(data)
		if tagLength < 0 {
			return 0, protowire.ParseError(tagLength)
		}
		data = data[tagLength:]
		if number == wanted && wireType != protowire.VarintType {
			return 0, errors.New("route: invalid protobuf field type")
		}
		if number == wanted && wireType == protowire.VarintType {
			value, length := protowire.ConsumeVarint(data)
			if length < 0 {
				return 0, protowire.ParseError(length)
			}
			return value, nil
		}
		length := protowire.ConsumeFieldValue(number, wireType, data)
		if length < 0 {
			return 0, protowire.ParseError(length)
		}
		data = data[length:]
	}
	return 0, nil
}

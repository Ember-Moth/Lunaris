// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Fixture payloads preserved from Polaris differential tests.
package route

import (
	"net/netip"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"google.golang.org/protobuf/encoding/protowire"
)

func appendBytesField(dst []byte, n protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(dst, n, protowire.BytesType), value)
}
func appendVarintField(dst []byte, n protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(dst, n, protowire.VarintType), value)
}
func encodeGeoSiteDomainEntry(typeValue uint64, value string, attributes ...string) []byte {
	entry := appendVarintField(nil, 1, typeValue)
	entry = appendBytesField(entry, 2, []byte(value))
	for _, attribute := range attributes {
		attributeEntry := appendBytesField(nil, 1, []byte(attribute))
		attributeEntry = appendVarintField(attributeEntry, 2, 1)
		entry = appendBytesField(entry, 3, attributeEntry)
	}
	return entry
}

func buildGeoSiteCategory(code string, domains ...[]byte) []byte {
	category := appendBytesField(nil, 1, []byte(code))
	for _, domain := range domains {
		category = appendBytesField(category, 2, domain)
	}
	return category
}

func buildGeoIPCategory(code string, prefixes ...netip.Prefix) []byte {
	category := appendBytesField(nil, 1, []byte(code))
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		cidr := appendBytesField(nil, 1, prefix.Addr().AsSlice())
		cidr = appendVarintField(cidr, 2, uint64(prefix.Bits()))
		category = appendBytesField(category, 2, cidr)
	}
	return category
}

func buildGeoDataFile(categories ...[]byte) []byte {
	var data []byte
	for _, category := range categories {
		data = appendBytesField(data, 1, category)
	}
	return data
}

func writeDiffFixture(tb testing.TB) *Catalog {
	tb.Helper()
	siteAlpha := buildGeoSiteCategory("SITE-ALPHA",
		encodeGeoSiteDomainEntry(3, "fx-full-a.example"),
		encodeGeoSiteDomainEntry(3, "shared.example"),
		encodeGeoSiteDomainEntry(2, "fx-suffix-a.test"),
		encodeGeoSiteDomainEntry(2, "shared-suffix.test"),
		encodeGeoSiteDomainEntry(0, "fxkwalpha"),
		encodeGeoSiteDomainEntry(1, `^fxre-[a-z]+\.example$`),
		encodeGeoSiteDomainEntry(2, "fx-attr-a.cn", "cn"),
		encodeGeoSiteDomainEntry(3, "attr-full-a.cn", "cn"),
	)
	siteBeta := buildGeoSiteCategory("SITE-BETA",
		encodeGeoSiteDomainEntry(3, "fx-full-b.example"),
		encodeGeoSiteDomainEntry(2, "fx-suffix-b.test"),
		encodeGeoSiteDomainEntry(2, "shared.example"),
		encodeGeoSiteDomainEntry(0, "fxkwbeta"),
	)
	geoAlpha := buildGeoIPCategory("GEO-ALPHA",
		netip.MustParsePrefix("198.51.100.0/25"),
		netip.MustParsePrefix("2001:db8:f1::/48"),
	)
	geoBeta := buildGeoIPCategory("GEO-BETA",
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:f2::/48"),
	)
	c, err := NewCatalog(map[string]*model.GeoDataMaterial{"geosite": model.NewGeoDataMaterial(buildGeoDataFile(siteAlpha, siteBeta)), "geoip": model.NewGeoDataMaterial(buildGeoDataFile(geoAlpha, geoBeta))})
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

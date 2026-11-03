// SPDX-License-Identifier: GPL-3.0-only
package dns

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestResponseIdentityLengthAndZeroTTL(t *testing.T) {
	query, _ := makeQuery("example.test", dnsTypeA)
	if err := validateResponse(nil, makeResponse(query, nil)); err == nil {
		t.Fatal("short query accepted")
	}
	name := dnsmessage.MustNewName("example.test.")
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(query), Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 600}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 2}}},
	}}
	raw, _ := response.Pack()
	if ttl, err := cacheTTL(raw); err != nil || ttl != 0 {
		t.Fatal("zero TTL was replaced by a later answer", ttl, err)
	}
	response.Questions[0].Name = dnsmessage.MustNewName("EXAMPLE.TEST.")
	raw, _ = response.Pack()
	if err := validateResponse(query, raw); err != nil {
		t.Fatal("DNS question case changed identity", err)
	}
	// A record encoded with an AAAA body must not become an IPv6 result for A.
	response.Answers = response.Answers[:1]
	response.Answers[0].Header.Type = dnsmessage.TypeAAAA
	response.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: [16]byte{15: 1}}
	raw, _ = response.Pack()
	_, offset, _ := decodeName(raw, 12)
	offset += 4
	_, header, _ := decodeName(raw, offset)
	binary.BigEndian.PutUint16(raw[header:], dnsTypeA)
	if _, err := parseAddresses(raw, dnsTypeA); err == nil {
		t.Fatal("invalid A payload length accepted")
	}
}
func TestAddressAnswersFollowOnlyQueryAndCNAMEChain(t *testing.T) {
	query, _ := makeQuery("example.test", dnsTypeA)
	name, alias, unrelated := dnsmessage.MustNewName("example.test."), dnsmessage.MustNewName("alias.test."), dnsmessage.MustNewName("other.test.")
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(query), Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: unrelated, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 2}}},
		{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: alias}},
	}}
	raw, _ := response.Pack()
	addresses, err := parseAddresses(raw, dnsTypeA)
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatal("unrelated answer used for dialing", addresses, err)
	}
	response.Header.RCode = dnsmessage.RCodeNameError
	raw, _ = response.Pack()
	addresses, err = parseAddresses(raw, dnsTypeA)
	if err != nil || len(addresses) != 0 {
		t.Fatal("NXDOMAIN supplied an address", addresses, err)
	}
}
func TestDNSNameExpansionIsBounded(t *testing.T) {
	if _, err := encodeName(strings.Repeat("a.", 128)); err == nil {
		t.Fatal("oversized wire name accepted")
	}
	if _, _, err := decodeName([]byte{0xc0, 0}, 0); err == nil {
		t.Fatal("compression loop accepted")
	}
}
func FuzzDNSWireBounds(f *testing.F) {
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65535 {
			return
		}
		_, _, _, _ = queryNameAndType(data)
		_, _ = parseAddresses(data, dnsTypeA)
		_, _ = cacheTTL(data)
		_ = validateResponse(data, data)
	})
}

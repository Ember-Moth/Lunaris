// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package dns

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func makeResponse(query []byte, addresses []netip.Addr) []byte {
	const qType = dnsTypeA
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	answers := 0
	for _, address := range addresses {
		if (qType == dnsTypeA && !address.Is4()) || (qType == dnsTypeAAAA && !address.Is6()) {
			continue
		}
		record := []byte{0xc0, 0x0c, 0, byte(qType), 0, 1, 0, 0, 0, 30}
		if address.Is4() {
			record = append(record, 0, 4)
			value := address.As4()
			record = append(record, value[:]...)
		} else {
			record = append(record, 0, 16)
			value := address.As16()
			record = append(record, value[:]...)
		}
		response = append(response, record...)
		answers++
	}
	binary.BigEndian.PutUint16(response[6:8], uint16(answers))
	return response
}

func TestValidateResponse_rejects_mismatched_query(t *testing.T) {
	// Given
	query, err := makeQuery("example.com", dnsTypeA)
	if err != nil {
		t.Fatalf("make query: %v", err)
	}
	response := makeResponse(query, nil)
	response[1]++

	// When
	err = validateResponse(query, response)

	// Then
	if err == nil {
		t.Fatal("expected mismatched DNS response rejection")
	}
}

func TestValidateResponse_rejects_mismatched_question_class(t *testing.T) {
	// Given
	query, err := makeQuery("example.com", dnsTypeA)
	if err != nil {
		t.Fatalf("make query: %v", err)
	}
	response := makeResponse(query, nil)
	response[len(response)-1] = 2

	// When
	err = validateResponse(query, response)

	// Then
	if err == nil {
		t.Fatal("expected mismatched DNS question class rejection")
	}
}

func TestValidateResponse_accepts_NXDOMAIN_and_rejects_SERVFAIL(t *testing.T) {
	// Given
	query, err := makeQuery("example.com", dnsTypeA)
	if err != nil {
		t.Fatalf("make query: %v", err)
	}
	nxDomain := makeResponse(query, nil)
	nxDomain[3] = 3
	serverFailure := makeResponse(query, nil)
	serverFailure[3] = 2

	// When
	nxDomainErr := validateResponse(query, nxDomain)
	serverFailureErr := validateResponse(query, serverFailure)

	// Then
	if nxDomainErr != nil {
		t.Fatalf("validate NXDOMAIN: %v", nxDomainErr)
	}
	if serverFailureErr == nil {
		t.Fatal("expected SERVFAIL rejection")
	}
}

func TestCache_bounds_entries(t *testing.T) {
	// Given
	cache := newCache()

	// When
	for index := 0; index <= maxCacheEntries; index++ {
		cache.put(cacheKey{name: string(rune(index)), qType: dnsTypeA}, []byte{1}, time.Now().Add(time.Hour))
	}

	// Then
	if len(cache.entries) != maxCacheEntries {
		t.Fatalf("cache entries = %d, want %d", len(cache.entries), maxCacheEntries)
	}
}

// Eviction clears every expired entry rather than the first one it happens to
// walk, so a cache full of stale names does not start dropping live ones.
func TestCache_evicts_all_expired_before_live_entries(t *testing.T) {
	// Given
	cache := newCache()
	expired := time.Now().Add(-time.Minute)
	for index := range maxCacheEntries - 1 {
		cache.entries[cacheKey{name: "stale" + string(rune(index)), qType: dnsTypeA}] = cacheEntry{response: []byte{1}, expires: expired}
	}
	live := cacheKey{name: "live.example", qType: dnsTypeA}
	cache.entries[live] = cacheEntry{response: []byte{2}, expires: time.Now().Add(time.Hour)}

	// When
	cache.put(cacheKey{name: "fresh.example", qType: dnsTypeA}, []byte{3}, time.Now().Add(time.Hour))

	// Then
	if len(cache.entries) != 2 {
		t.Fatalf("cache entries = %d, want 2 (both live names)", len(cache.entries))
	}
	if _, found := cache.entries[live]; !found {
		t.Fatal("the live entry was evicted while expired entries remained")
	}
}

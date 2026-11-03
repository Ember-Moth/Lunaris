// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"net/netip"
	"unsafe"
)

// prefixRuleIndex merges ordinary CIDR and GeoIP rules into one pointer-free
// trie (design: docs/route-index-redesign.md, D4). Each terminal stores the
// earliest (rule, rank) referencing that network, packed as
// rulePlusOne<<2|rank with rank 0 = CIDR and rank 1 = GeoIP; packing preserves
// the earliest-rule-wins order and the CIDR-over-GeoIP same-rule tie-break.
// The rank field uses two bits so domain matchers can share the packing.
type prefixRuleIndex struct {
	nodes    []prefixRuleNode
	ipv4Root uint32
	ipv6Root uint32
}

type prefixRuleNode struct {
	next   [2]uint32
	packed uint32
}

func newPrefixRuleIndex() *prefixRuleIndex {
	return &prefixRuleIndex{nodes: make([]prefixRuleNode, 2), ipv4Root: 0, ipv6Root: 1}
}

// The packed indexes size their words to configuration scale: rule indexes,
// entry counts, and table capacities are bounded by process memory and stay
// far below 2^32, and hash truncation deliberately keeps the low word for slot
// indexing. The helpers below centralize those reviewed conversions.
//
//nolint:gosec // G115: bounded by configuration scale
func u32(value int) uint32 { return uint32(value) }

//nolint:gosec // G115: deliberate low-word truncation
func low32(value uint64) uint32 { return uint32(value) }

//nolint:gosec // G115: bounded by configuration scale
func asInt(value uint32) int { return int(value) }

func packRule(ruleIndex int, rank uint32) uint32 {
	return u32(ruleIndex+1)<<2 | rank&3
}

func (index *prefixRuleIndex) insert(prefix netip.Prefix, ruleIndex int, rank uint32) {
	canonical := canonicalIPPrefixes([]netip.Prefix{prefix})
	if len(canonical) == 0 {
		return
	}
	prefix = canonical[0]
	root, raw := index.ipv6Root, prefix.Addr().As16()
	if prefix.Addr().Is4() {
		root, raw = index.ipv4Root, [16]byte{}
		address := prefix.Addr().As4()
		copy(raw[:4], address[:])
	}
	nodeIndex := root
	for bitIndex := range prefix.Bits() {
		bit := raw[bitIndex/8] >> (7 - uint(bitIndex%8)) & 1
		child := index.nodes[nodeIndex].next[bit]
		if child == 0 {
			index.nodes = append(index.nodes, prefixRuleNode{})
			child = u32(len(index.nodes))
			index.nodes[nodeIndex].next[bit] = child
		}
		nodeIndex = child - 1
	}
	packed := packRule(ruleIndex, rank)
	if current := index.nodes[nodeIndex].packed; current == 0 || packed < current {
		index.nodes[nodeIndex].packed = packed
	}
}

// lookup returns the packed (rule, rank) of the earliest rule below limit
// containing the address, or 0 when nothing qualifies.
func (index *prefixRuleIndex) lookup(address netip.Addr, limit int) uint32 {
	if index == nil || !address.IsValid() {
		return 0
	}
	address = address.Unmap()
	root, raw, bits := index.ipv6Root, address.As16(), 128
	if address.Is4() {
		root, raw, bits = index.ipv4Root, [16]byte{}, 32
		ipv4 := address.As4()
		copy(raw[:4], ipv4[:])
	}
	nodeIndex := root
	best := uint32(0)
	consider := func(packed uint32) {
		if packed != 0 && asInt(packed>>2) <= limit && (best == 0 || packed < best) {
			best = packed
		}
	}
	consider(index.nodes[nodeIndex].packed)
	for bitIndex := range bits {
		bit := raw[bitIndex/8] >> (7 - uint(bitIndex%8)) & 1
		child := index.nodes[nodeIndex].next[bit]
		if child == 0 {
			break
		}
		nodeIndex = child - 1
		consider(index.nodes[nodeIndex].packed)
	}
	return best
}

func (index *prefixRuleIndex) estimatedBytes() uint64 {
	if index == nil {
		return 0
	}
	return uint64(len(index.nodes)) * uint64(unsafe.Sizeof(prefixRuleNode{}))
}

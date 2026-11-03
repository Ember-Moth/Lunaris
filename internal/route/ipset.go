// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"unsafe"
)

// prefixSet is a pointer-free binary trie. Child values are node indexes plus
// one, leaving zero as the missing-child sentinel. Keeping every node in one
// slice substantially reduces allocator and GC pressure for large GeoIP sets.
// list retains the canonical accepted prefixes so snapshot compilation can
// merge them into the shared prefixRuleIndex without walking the trie.
type prefixSet struct {
	nodes    []prefixNode
	ipv4Root uint32
	ipv6Root uint32
	count    uint32
	hash     string
	source   geoDataVersion
	list     []netip.Prefix
}

type prefixNode struct {
	next     [2]uint32
	terminal bool
}

func newPrefixSet(prefixes []netip.Prefix) *prefixSet {
	set, _ := newPrefixSetBounded(prefixes, 0)
	return set
}
func newPrefixSetBounded(prefixes []netip.Prefix, limit int) (*prefixSet, error) {
	prefixes = canonicalIPPrefixes(prefixes)
	if len(prefixes) == 0 {
		return nil, nil
	}
	set := &prefixSet{nodes: make([]prefixNode, 2), ipv4Root: 0, ipv6Root: 1}
	accepted := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if limit > 0 && len(set.nodes)+prefix.Bits() > limit {
			return nil, errors.New("route: prefix index budget exceeded")
		}
		if set.insert(prefix) {
			accepted = append(accepted, prefix)
		}
	}
	set.count = uint32(len(accepted))
	set.hash = hashIPPrefixes(accepted)
	set.nodes = slices.Clip(set.nodes)
	set.list = slices.Clip(accepted)
	return set, nil
}

func canonicalIPPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	canonical := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		canonical = append(canonical, prefix)
	}
	slices.SortFunc(canonical, func(left, right netip.Prefix) int {
		left4, right4 := left.Addr().Is4(), right.Addr().Is4()
		if left4 != right4 {
			if left4 {
				return -1
			}
			return 1
		}
		if left.Bits() < right.Bits() {
			return -1
		}
		if left.Bits() > right.Bits() {
			return 1
		}
		return left.Addr().Compare(right.Addr())
	})
	return slices.Compact(canonical)
}

func (set *prefixSet) insert(prefix netip.Prefix) bool {
	root, raw := set.ipv6Root, prefix.Addr().As16()
	if prefix.Addr().Is4() {
		root, raw = set.ipv4Root, [16]byte{}
		address := prefix.Addr().As4()
		copy(raw[:4], address[:])
	}
	nodeIndex := root
	if set.nodes[nodeIndex].terminal {
		return false
	}
	for index := range prefix.Bits() {
		bit := raw[index/8] >> (7 - uint(index%8)) & 1
		child := set.nodes[nodeIndex].next[bit]
		if child == 0 {
			set.nodes = append(set.nodes, prefixNode{})
			child = uint32(len(set.nodes))
			set.nodes[nodeIndex].next[bit] = child
		}
		nodeIndex = child - 1
		if set.nodes[nodeIndex].terminal {
			return false
		}
	}
	set.nodes[nodeIndex].terminal = true
	return true
}

func hashIPPrefixes(prefixes []netip.Prefix) string {
	hash := sha256.New()
	for _, prefix := range prefixes {
		_, _ = hash.Write([]byte(prefix.String()))
		_, _ = hash.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (set *prefixSet) Contains(address netip.Addr) bool {
	if set == nil || !address.IsValid() {
		return false
	}
	address = address.Unmap()
	root, raw, bits := set.ipv6Root, address.As16(), 128
	if address.Is4() {
		root, raw, bits = set.ipv4Root, [16]byte{}, 32
		ipv4 := address.As4()
		copy(raw[:4], ipv4[:])
	}
	nodeIndex := root
	if set.nodes[nodeIndex].terminal {
		return true
	}
	for index := range bits {
		bit := raw[index/8] >> (7 - uint(index%8)) & 1
		child := set.nodes[nodeIndex].next[bit]
		if child == 0 {
			return false
		}
		nodeIndex = child - 1
		if set.nodes[nodeIndex].terminal {
			return true
		}
	}
	return false
}

func (set *prefixSet) estimatedBytes() uint64 {
	if set == nil {
		return 0
	}
	return uint64(len(set.nodes))*uint64(unsafe.Sizeof(prefixNode{})) + uint64(len(set.list))*16
}

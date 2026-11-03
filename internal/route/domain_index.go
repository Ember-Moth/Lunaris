// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

// domainIndex is the merged full/suffix domain matcher for one snapshot
// (design: docs/route-index-redesign.md, D1). All rules' ordinary and GeoSite
// full/suffix selectors compile into a single frozen open-addressing hash
// table. Because earliest-rule-wins distributes over dimensions, each key
// stores only the earliest (rule, rank) referencing it; rank breaks same-rule
// ties so ordinary selectors report MatchDomain ahead of GeoSite ones.
//
// Slots embed their string header, referencing the shared GeoData category
// arenas or rule selector strings without copying. Nothing is mutated after
// build, so concurrent Route calls need no synchronization.

const (
	domainHashOffset = 14695981039346656037
	domainHashPrime  = 1099511628211
	domainSuffixMix  = 0x9e3779b97f4a7c15

	domainFlagSuffix  = 1 << 0
	domainFlagGeoSite = 1 << 1

	domainMaxLoadNumerator   = 3
	domainMaxLoadDenominator = 4
)

type domainSlot struct {
	value       string
	hash        uint64 // full key hash, kept so rehash never recomputes it
	flags       uint32
	rulePlusOne uint32 // 0 marks an empty slot
}

type domainIndex struct {
	slots  []domainSlot
	mask   uint32
	exact  int
	suffix int
}

// hashDomainKey is a backward FNV-1a pass: processing bytes from the end of
// the string forward means the state at position i is the hash of the suffix
// value[i:], which lets match reuse one rolling pass for every candidate.
func hashDomainKey(value string) uint64 {
	hash := uint64(domainHashOffset)
	for index := len(value) - 1; index >= 0; index-- {
		hash = (hash ^ uint64(value[index])) * domainHashPrime
	}
	return hash
}

func (slot domainSlot) isSuffix() bool  { return slot.flags&domainFlagSuffix != 0 }
func (slot domainSlot) isGeoSite() bool { return slot.flags&domainFlagGeoSite != 0 }

// lookup probes one candidate. hash must be hashDomainKey(key) before the
// suffix perturbation.
func (index *domainIndex) lookup(key string, suffix bool, hash uint64) (rulePlusOne uint32, geoSite bool, found bool) {
	if suffix {
		hash ^= domainSuffixMix
	}
	slotIndex := low32(hash) & index.mask
	for {
		slot := &index.slots[slotIndex]
		if slot.rulePlusOne == 0 {
			return 0, false, false
		}
		if low32(slot.hash>>32) == low32(hash>>32) && slot.isSuffix() == suffix && slot.value == key {
			return slot.rulePlusOne, slot.isGeoSite(), true
		}
		slotIndex = (slotIndex + 1) & index.mask
	}
}

// matchPacked returns the packed (rule, rank) of the earliest domain match,
// or 0 when nothing below limitPacked matches. One backward pass produces
// every candidate hash; each label boundary probes the suffix table and
// position zero additionally probes the full table.
func (index *domainIndex) matchPacked(domain string, limitPacked uint32) uint32 {
	if len(index.slots) == 0 || domain == "" {
		return 0
	}
	best := uint32(0)
	hash := uint64(domainHashOffset)
	for position := len(domain) - 1; position >= 0; position-- {
		hash = (hash ^ uint64(domain[position])) * domainHashPrime
		if boundary := position == 0 || domain[position-1] == '.'; !boundary {
			continue
		}
		candidate := domain[position:]
		if rulePlusOne, geoSite, found := index.lookup(candidate, true, hash); found {
			packed := packRule(asInt(rulePlusOne)-1, rankOf(geoSite))
			if packed < limitPacked && (best == 0 || packed < best) {
				best = packed
			}
		}
		if position == 0 {
			if rulePlusOne, geoSite, found := index.lookup(candidate, false, hash); found {
				packed := packRule(asInt(rulePlusOne)-1, rankOf(geoSite))
				if packed < limitPacked && (best == 0 || packed < best) {
					best = packed
				}
			}
		}
	}
	return best
}

func rankOf(geoSite bool) uint32 {
	if geoSite {
		return 1
	}
	return 0
}

// domainKindOfRank maps a domain-side rank back to its diagnostic kind:
// ordinary full/suffix and keyword/regex report MatchDomain, GeoSite matchers
// report MatchGeoSite.
func domainKindOfRank(rank uint32) MatchKind {
	if rank == 1 {
		return MatchGeoSite
	}
	return MatchDomain
}

func (index *domainIndex) estimatedBytes() uint64 {
	return uint64(cap(index.slots)) * 32
}

// domainIndexBuilder deduplicates (value, suffix) keys directly inside the
// open-addressing table, keeping the earliest (rule, rank) per key. The table
// grows by rehashing during compile; no per-key map is involved.
type domainIndexBuilder struct {
	slots  []domainSlot
	mask   uint32
	count  int
	exact  int
	suffix int
}

func newDomainIndexBuilder() *domainIndexBuilder {
	return &domainIndexBuilder{}
}

// reserve pre-sizes the table for the expected number of (value, suffix) keys,
// keeping inserts single-pass; duplicate keys only lower the final load.
func (builder *domainIndexBuilder) reserve(entries int) {
	capacity := uint32(8)
	for asInt(capacity)*domainMaxLoadNumerator < entries*domainMaxLoadDenominator {
		capacity *= 2
	}
	builder.rehash(capacity)
}

func (builder *domainIndexBuilder) insert(value string, suffix bool, ruleIndex int, rank uint32) {
	packed := packRule(ruleIndex, rank)
	if builder.slots == nil {
		builder.rehash(8)
	}
	hash := hashDomainKey(value)
	if suffix {
		hash ^= domainSuffixMix
	}
	slotIndex := low32(hash) & builder.mask
	for {
		slot := &builder.slots[slotIndex]
		if slot.rulePlusOne == 0 {
			builder.occupy(slot, value, hash, suffix, ruleIndex, packed)
			return
		}
		if low32(slot.hash>>32) == low32(hash>>32) && slot.isSuffix() == suffix && slot.value == value {
			if current := packRule(asInt(slot.rulePlusOne)-1, slot.flags>>1&1); packed < current {
				slot.rulePlusOne = u32(ruleIndex) + 1
				slot.flags = slot.flags&domainFlagSuffix | (rank&1)<<1
			}
			return
		}
		slotIndex = (slotIndex + 1) & builder.mask
	}
}

// occupy fills an empty slot and grows the table past its load bound. hash is
// the caller's already-perturbed key hash.
func (builder *domainIndexBuilder) occupy(slot *domainSlot, value string, hash uint64, suffix bool,
	ruleIndex int, packed uint32,
) {
	flags := uint32(0)
	if suffix {
		flags |= domainFlagSuffix
		builder.suffix++
	} else {
		builder.exact++
	}
	if packed&1 != 0 {
		flags |= domainFlagGeoSite
	}
	*slot = domainSlot{value: value, hash: hash, flags: flags, rulePlusOne: u32(ruleIndex) + 1}
	builder.count++
	if builder.count*domainMaxLoadDenominator >= len(builder.slots)*domainMaxLoadNumerator {
		builder.rehash(builder.mask*2 + 2)
	}
}

func (builder *domainIndexBuilder) rehash(capacity uint32) {
	rehashed := make([]domainSlot, capacity)
	mask := capacity - 1
	for _, slot := range builder.slots {
		if slot.rulePlusOne == 0 {
			continue
		}
		slotIndex := low32(slot.hash) & mask
		for rehashed[slotIndex].rulePlusOne != 0 {
			slotIndex = (slotIndex + 1) & mask
		}
		rehashed[slotIndex] = slot
	}
	builder.slots = rehashed
	builder.mask = mask
}

func (builder *domainIndexBuilder) build() domainIndex {
	// reserve() sees per-rule references, so duplicate-heavy configs leave the
	// table oversized; shrink once using the stored hashes (no rehashing of
	// strings) to restore the load-factor bound.
	capacity := uint32(8)
	for asInt(capacity)*domainMaxLoadNumerator < builder.count*domainMaxLoadDenominator {
		capacity *= 2
	}
	if asInt(capacity) < len(builder.slots) {
		builder.rehash(capacity)
	}
	return domainIndex{
		slots: builder.slots, mask: builder.mask,
		exact: builder.exact, suffix: builder.suffix,
	}
}

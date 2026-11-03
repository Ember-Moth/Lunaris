// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"sort"
	"strings"
)

const smallDomainTableLimit = 32

// domainTable uses a map for small rule-local sets and a sorted string arena
// for large GeoSite categories. The latter avoids one allocation and map bucket
// overhead per domain while retaining logarithmic lookup.
type domainTable struct {
	small   map[string]struct{}
	arena   string
	offsets []uint32
}

func newDomainTable(values []string) domainTable {
	if len(values) == 0 {
		return domainTable{}
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	values = compactStrings(values)
	if len(values) <= smallDomainTableLimit {
		table := domainTable{small: make(map[string]struct{}, len(values))}
		for _, value := range values {
			table.small[value] = struct{}{}
		}
		return table
	}
	var builder strings.Builder
	total := 0
	for _, value := range values {
		total += len(value)
	}
	builder.Grow(total)
	offsets := make([]uint32, 1, len(values)+1)
	for _, value := range values {
		builder.WriteString(value)
		offsets = append(offsets, uint32(builder.Len()))
	}
	return domainTable{arena: builder.String(), offsets: offsets}
}

func compactStrings(values []string) []string {
	output := values[:0]
	for _, value := range values {
		if value == "" || len(output) > 0 && output[len(output)-1] == value {
			continue
		}
		output = append(output, value)
	}
	return output
}

func (table domainTable) contains(value string) bool {
	if table.small != nil {
		_, found := table.small[value]
		return found
	}
	count := table.len()
	index := sort.Search(count, func(index int) bool {
		return table.value(index) >= value
	})
	return index < count && table.value(index) == value
}

func (table domainTable) len() int {
	if table.small != nil {
		return len(table.small)
	}
	if len(table.offsets) == 0 {
		return 0
	}
	return len(table.offsets) - 1
}

func (table domainTable) value(index int) string {
	start, end := table.offsets[index], table.offsets[index+1]
	return table.arena[start:end]
}

func (table domainTable) each(yield func(string)) {
	if table.small != nil {
		for value := range table.small {
			yield(value)
		}
		return
	}
	for index := range table.len() {
		yield(table.value(index))
	}
}

func (table domainTable) estimatedBytes() uint64 {
	if table.small != nil {
		var size uint64
		for value := range table.small {
			size += uint64(len(value) + 24)
		}
		return size
	}
	return uint64(len(table.arena) + len(table.offsets)*4)
}

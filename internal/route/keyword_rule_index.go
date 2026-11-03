// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"slices"
	"sort"
	"unsafe"
)

// keywordRuleIndex merges every rule's keyword selectors (ordinary and
// GeoSite) into one Aho-Corasick automaton (design:
// docs/route-index-redesign.md, D2). Each terminal stores the earliest packed
// (rule, rank) of the patterns ending there, and failure links propagate the
// minimum downward, so a node's output is the earliest rule among all patterns
// ending at or above it. One pass over the domain then yields the keyword
// dimension's earliest match directly.
type keywordRuleIndex struct {
	nodes      []keywordRuleNode
	edgeValues []byte
	edgeNext   []uint32
	// minOutput is the smallest packed output in the automaton; reaching it
	// proves no later position can improve the match, enabling early exit.
	minOutput uint32
}

type keywordRuleNode struct {
	failure   uint32
	edgeStart uint32
	edgeCount uint32
	output    uint32 // packed (rule, rank); 0 = none
}

type keywordRuleBuildNode struct {
	edges   map[byte]uint32
	failure uint32
	output  uint32
}

func minPacked(left, right uint32) uint32 {
	if left == 0 {
		return right
	}
	if right == 0 || left < right {
		return left
	}
	return right
}

// keywordRuleBuilder deduplicates keywords by their earliest packed
// (rule, rank) before constructing the automaton, so categories shared by many
// rules are built once per distinct keyword.
type keywordRuleBuilder struct {
	packed map[string]uint32
}

func (builder *keywordRuleBuilder) insert(keyword string, ruleIndex int, rank uint32) {
	packed := packRule(ruleIndex, rank)
	if builder.packed == nil {
		builder.packed = make(map[string]uint32)
	}
	if current, exists := builder.packed[keyword]; exists && current <= packed {
		return
	}
	builder.packed[keyword] = packed
}

func (builder *keywordRuleBuilder) build() keywordRuleIndex {
	if len(builder.packed) == 0 {
		return keywordRuleIndex{}
	}
	patterns := make([]string, 0, len(builder.packed))
	minOutput := uint32(0)
	for pattern, packed := range builder.packed {
		patterns = append(patterns, pattern)
		minOutput = minPacked(minOutput, packed)
	}
	slices.Sort(patterns)
	build := []keywordRuleBuildNode{{edges: make(map[byte]uint32)}}
	for _, pattern := range patterns {
		state := uint32(0)
		for position := range len(pattern) {
			value := pattern[position]
			next, found := build[state].edges[value]
			if !found {
				next = u32(len(build))
				build = append(build, keywordRuleBuildNode{edges: make(map[byte]uint32)})
				build[state].edges[value] = next
			}
			state = next
		}
		build[state].output = minPacked(build[state].output, builder.packed[pattern])
	}
	queue := make([]uint32, 0, len(build))
	for _, child := range build[0].edges {
		queue = append(queue, child)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		for value, next := range build[state].edges {
			failure := build[state].failure
			candidate, found := build[failure].edges[value]
			for !found && failure != 0 {
				failure = build[failure].failure
				candidate, found = build[failure].edges[value]
			}
			if found {
				build[next].failure = candidate
			}
			// The failure target is strictly shallower, so its output is already
			// final: propagate the earliest packed rule downward.
			build[next].output = minPacked(build[next].output, build[build[next].failure].output)
			queue = append(queue, next)
		}
	}

	matcher := keywordRuleIndex{nodes: make([]keywordRuleNode, len(build))}
	for index := range build {
		values := make([]byte, 0, len(build[index].edges))
		for value := range build[index].edges {
			values = append(values, value)
		}
		slices.Sort(values)
		matcher.nodes[index] = keywordRuleNode{
			failure: build[index].failure, edgeStart: u32(len(matcher.edgeValues)),
			edgeCount: u32(len(values)), output: build[index].output,
		}
		for _, value := range values {
			matcher.edgeValues = append(matcher.edgeValues, value)
			matcher.edgeNext = append(matcher.edgeNext, build[index].edges[value])
		}
	}
	matcher.nodes = slices.Clip(matcher.nodes)
	matcher.edgeValues = slices.Clip(matcher.edgeValues)
	matcher.edgeNext = slices.Clip(matcher.edgeNext)
	matcher.minOutput = minOutput
	return matcher
}

// matchPacked walks value once, returning the earliest packed (rule, rank)
// among all keyword patterns it contains, never worse than the incoming best
// (pass the packed limit when nothing matched yet).
func (matcher keywordRuleIndex) matchPacked(value string, best uint32) uint32 {
	if len(matcher.nodes) == 0 || best == matcher.minOutput {
		return best
	}
	state := uint32(0)
	for index := range len(value) {
		next, found := matcher.next(state, value[index])
		for !found && state != 0 {
			state = matcher.nodes[state].failure
			next, found = matcher.next(state, value[index])
		}
		if found {
			state = next
		} else {
			state = 0
		}
		if output := matcher.nodes[state].output; output != 0 && output < best {
			best = output
			if best == matcher.minOutput {
				return best
			}
		}
	}
	return best
}

func (matcher keywordRuleIndex) next(state uint32, value byte) (uint32, bool) {
	node := matcher.nodes[state]
	start, end := int(node.edgeStart), int(node.edgeStart+node.edgeCount)
	offset := sort.Search(end-start, func(index int) bool {
		return matcher.edgeValues[start+index] >= value
	})
	position := start + offset
	if position >= end || matcher.edgeValues[position] != value {
		return 0, false
	}
	return matcher.edgeNext[position], true
}

func (matcher keywordRuleIndex) estimatedBytes() uint64 {
	return uint64(len(matcher.nodes))*uint64(unsafe.Sizeof(keywordRuleNode{})) +
		uint64(len(matcher.edgeValues)) + uint64(len(matcher.edgeNext))*4
}

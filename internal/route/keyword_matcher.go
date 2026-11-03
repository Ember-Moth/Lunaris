// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors
// Adapted from Polaris 56d52fb44958ef3cc2a7fb841cd240f8206234b2.
package route

import (
	"slices"
	"sort"
	"unsafe"
)

type keywordMatcher struct {
	nodes      []keywordNode
	edgeValues []byte
	edgeNext   []uint32
	// list retains the canonical keyword set so snapshot compilation can merge
	// them into the shared keywordRuleIndex without walking the automaton.
	list []string
}

type keywordNode struct {
	failure   uint32
	edgeStart uint32
	edgeCount uint32
	terminal  bool
}

type keywordBuildNode struct {
	failure  uint32
	edges    map[byte]uint32
	terminal bool
}

func newKeywordMatcher(keywords []string) keywordMatcher {
	if len(keywords) == 0 {
		return keywordMatcher{}
	}
	keywords = append([]string(nil), keywords...)
	sort.Strings(keywords)
	keywords = compactStrings(keywords)
	build := []keywordBuildNode{{edges: make(map[byte]uint32)}}
	for _, keyword := range keywords {
		state := uint32(0)
		for index := range len(keyword) {
			value := keyword[index]
			next, found := build[state].edges[value]
			if !found {
				next = uint32(len(build))
				build = append(build, keywordBuildNode{edges: make(map[byte]uint32)})
				build[state].edges[value] = next
			}
			state = next
		}
		build[state].terminal = true
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
			build[next].terminal = build[next].terminal || build[build[next].failure].terminal
			queue = append(queue, next)
		}
	}

	matcher := keywordMatcher{nodes: make([]keywordNode, len(build)), list: slices.Clip(keywords)}
	for index := range build {
		values := make([]byte, 0, len(build[index].edges))
		for value := range build[index].edges {
			values = append(values, value)
		}
		slices.Sort(values)
		matcher.nodes[index] = keywordNode{
			failure: build[index].failure, edgeStart: uint32(len(matcher.edgeValues)),
			edgeCount: uint32(len(values)), terminal: build[index].terminal,
		}
		for _, value := range values {
			matcher.edgeValues = append(matcher.edgeValues, value)
			matcher.edgeNext = append(matcher.edgeNext, build[index].edges[value])
		}
	}
	matcher.nodes = slices.Clip(matcher.nodes)
	matcher.edgeValues = slices.Clip(matcher.edgeValues)
	matcher.edgeNext = slices.Clip(matcher.edgeNext)
	return matcher
}

func (matcher keywordMatcher) empty() bool { return len(matcher.nodes) == 0 }

func (matcher keywordMatcher) match(value string) bool {
	if matcher.empty() {
		return false
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
		if matcher.nodes[state].terminal {
			return true
		}
	}
	return false
}

func (matcher keywordMatcher) next(state uint32, value byte) (uint32, bool) {
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

func (matcher keywordMatcher) estimatedBytes() uint64 {
	size := uint64(len(matcher.nodes))*uint64(unsafe.Sizeof(keywordNode{})) +
		uint64(len(matcher.edgeValues)) + uint64(len(matcher.edgeNext))*4
	for _, keyword := range matcher.list {
		size += uint64(len(keyword) + 16)
	}
	return size
}

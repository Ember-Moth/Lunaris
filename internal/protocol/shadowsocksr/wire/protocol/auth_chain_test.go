// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package protocol

import (
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthChainPaddingVectors(t *testing.T) {
	tests := []struct {
		method string
		first  []int
		second []int
		pads   []int
	}{
		{"auth_chain_b", []int{69, 143, 787, 861, 1319}, []int{43, 51, 79, 110, 114, 118, 130, 231, 242, 297, 318, 367, 413, 534, 624, 674, 827, 832, 862, 1218, 1226, 1315, 1319}, []int{39, 0, 0, 0}},
		{"auth_chain_c", []int{51, 69, 79, 110, 118, 130, 143, 231, 297, 367, 413, 511, 534, 624, 787, 861, 862, 1226, 1315, 1319, 1319}, nil, []int{127, 815, 311, 30}},
		{"auth_chain_d", []int{51, 69, 79, 110, 118, 130, 143, 231, 297, 367, 413, 511, 534, 624, 787, 861, 862, 1226, 1315, 1319, 1319}, nil, []int{127, 815, 311, 0}},
		{"auth_chain_e", []int{51, 69, 79, 110, 118, 130, 143, 231, 297, 367, 413, 511, 534, 624, 787, 861, 862, 1226, 1315, 1319, 1319}, nil, []int{6, 7, 222, 0}},
		{"auth_chain_f", []int{49, 73, 125, 144, 203, 222, 265, 351, 354, 367, 381, 407, 415, 511, 523, 549, 576, 578, 596, 673, 701, 756, 895, 1166, 1184, 1216, 1222, 1340, 1342}, nil, []int{21, 7, 162, 0}},
	}
	now := time.Unix(1700000000, 0)
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			profile := newChainPadding(test.method, []byte("0123456789abcdef"), "#86400", now, 4)
			if !reflect.DeepEqual(profile.first, test.first) || !reflect.DeepEqual(profile.second, test.second) {
				t.Fatalf("tables = %v / %v", profile.first, profile.second)
			}
			hash := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
			for index, size := range []int{100, 500, 1000, 1350} {
				var random xorshift128Plus
				if actual := profile.dataLength(size, hash, &random); actual != test.pads[index] {
					t.Fatalf("size %d padding = %d, want %d", size, actual, test.pads[index])
				}
			}
		})
	}
}

func TestAuthChainProfileCacheRefreshesOncePerEpoch(t *testing.T) {
	var unix atomic.Int64
	unix.Store(100)
	definition := newAuthChainDefinition(Config{
		Name: "auth_chain_f", ServerKey: []byte("0123456789abcdef"), ProtocolParam: "#86400",
		Now: func() time.Time { return time.Unix(unix.Load(), 0) },
	})
	initial := definition.profiles.Load()
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() { _ = definition.paddingProfile(true) })
	}
	workers.Wait()
	if current := definition.profiles.Load(); current != initial {
		t.Fatal("profile was rebuilt inside one epoch")
	}

	unix.Store(86400)
	workers = sync.WaitGroup{}
	for range 64 {
		workers.Go(func() { _ = definition.paddingProfile(false) })
	}
	workers.Wait()
	current := definition.profiles.Load()
	if current == initial || current.epoch != 1 {
		t.Fatalf("profile epoch = %d, want refreshed epoch 1", current.epoch)
	}
}

func TestAuthChainFIntervalVectors(t *testing.T) {
	tests := []struct {
		param string
		want  int64
	}{
		{"", 86400}, {"#1", 86400}, {"#01", 86400}, {"#001", 1}, {"#010", 8},
		{"#0x15180", 86400}, {"128#0X15180", 86400}, {"#123suffix", 123}, {"#0", 86400},
		{"#-100", 86400}, {"#9223372036854775807", 86400}, {"#9223372036854775808", 86400},
	}
	for _, test := range tests {
		if actual := parseChainFInterval(test.param); actual != test.want {
			t.Fatalf("parseChainFInterval(%q) = %d, want %d", test.param, actual, test.want)
		}
	}
	before := newChainPadding("auth_chain_f", []byte("0123456789abcdef"), "#86400", time.Unix(172799, 0), 4)
	same := newChainPadding("auth_chain_f", []byte("0123456789abcdef"), "#86400", time.Unix(172799, 999), 4)
	after := newChainPadding("auth_chain_f", []byte("0123456789abcdef"), "#86400", time.Unix(172800, 0), 4)
	if !reflect.DeepEqual(before.first, same.first) || reflect.DeepEqual(before.first, after.first) {
		t.Fatal("auth_chain_f epoch boundary differs")
	}
}

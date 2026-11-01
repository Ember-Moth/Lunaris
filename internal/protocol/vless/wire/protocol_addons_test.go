// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestReadAddonsRejectsLengthsPastInput(t *testing.T) {
	for _, header := range []byte{(1 << 3) | 2, (2 << 3) | 2} {
		// A field length near 2^63 used to be passed straight to make.
		addons := binary.AppendUvarint([]byte{header}, 1<<63)
		addons = append(addons, "xtls-rprx-vision"...)
		if _, err := readAddons(bytes.NewReader(addons)); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("field %#x: err = %v, want ErrUnexpectedEOF", header, err)
		}
	}
}

func TestReadAddonsFlowAndSeed(t *testing.T) {
	addons := binary.AppendUvarint([]byte{(1 << 3) | 2}, uint64(len(FlowVision)))
	addons = append(addons, FlowVision...)
	addons = binary.AppendUvarint(append(addons, (2<<3)|2), 4)
	addons = append(addons, "seed"...)
	result, err := readAddons(bytes.NewReader(addons))
	if err != nil {
		t.Fatal(err)
	}
	if result.Flow != FlowVision || result.Seed != "seed" {
		t.Fatalf("addons = %+v", result)
	}
}

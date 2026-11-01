// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Polaris contributors
package restls

import (
	"strconv"
	"testing"
)

func TestRecordTrackingRecognizesCloseNotifyShapes(t *testing.T) {
	for _, size := range []int{18, 19, 26, 32, 48, 64, 80} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			tracker := &recordTrackingConn{}
			record := make([]byte, tlsRecordHeaderLen+size)
			record[0], record[1], record[2] = tlsApplicationData, 3, 3
			record[3], record[4] = byte(size>>8), byte(size)
			tracker.track(record[:2])
			tracker.track(record[2:7])
			tracker.track(record[7:])
			if !tracker.lastRecordIsCloseNotify() {
				t.Fatalf("record length %d was not recognized", size)
			}
		})
	}
}

func TestRecordTrackingKeepsRESTLSDataDistinct(t *testing.T) {
	tracker := &recordTrackingConn{}
	size := 250
	record := make([]byte, tlsRecordHeaderLen+size)
	record[0], record[1], record[2] = tlsApplicationData, 3, 3
	record[3], record[4] = byte(size>>8), byte(size)
	tracker.track(record)
	if tracker.lastRecordIsCloseNotify() {
		t.Fatal("RESTLS application record was classified as close-notify")
	}
}

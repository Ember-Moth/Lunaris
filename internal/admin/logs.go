// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
)

type LogEntry struct {
	Sequence    uint64    `json:"sequence"`
	Time        time.Time `json:"time"`
	Level       string    `json:"level"`
	Message     string    `json:"message"`
	RequestID   string    `json:"request_id,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
}
type LogPage struct {
	BootID     string     `json:"boot_id"`
	Entries    []LogEntry `json:"entries"`
	NextCursor string     `json:"next_cursor"`
	Truncated  bool       `json:"truncated"`
	Restarted  bool       `json:"restarted"`
}
type Logs struct {
	mu      sync.Mutex
	boot    string
	next    uint64
	entries []LogEntry
}

func NewLogs(boot string) *Logs { return &Logs{boot: boot} }

// Add accepts only server-owned messages; request bodies, headers and raw errors
// are intentionally not routed into the management log API.
func (l *Logs) Add(level, message, requestID string) {
	l.add(level, message, requestID, "")
}
func (l *Logs) add(level, message, requestID, operationID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.next++
	l.entries = append(l.entries, LogEntry{Sequence: l.next, Time: time.Now().UTC(), Level: level, Message: message, RequestID: requestID, OperationID: operationID})
	if len(l.entries) > 512 {
		copy(l.entries, l.entries[len(l.entries)-512:])
		l.entries = l.entries[:512]
	}
}
func (l *Logs) Page(cursor string, limit int) (LogPage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	page := LogPage{BootID: l.boot, Entries: []LogEntry{}}
	if limit < 1 || limit > 100 || len(cursor) > 256 {
		return page, errors.New("invalid log pagination")
	}
	var after uint64
	if cursor != "" {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
		if err != nil {
			return page, err
		}
		var parts []string
		if json.Unmarshal(raw, &parts) != nil || len(parts) != 2 {
			return page, errors.New("invalid log cursor")
		}
		after, err = strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return page, err
		}
		if parts[0] != l.boot {
			after = 0
			page.Restarted = true
			page.Truncated = true
		} else if after > l.next {
			return page, errors.New("invalid future log cursor")
		}
	}
	if len(l.entries) > 0 && after+1 < l.entries[0].Sequence {
		page.Truncated = true
	}
	for _, entry := range l.entries {
		if entry.Sequence > after {
			page.Entries = append(page.Entries, entry)
			after = entry.Sequence
			if len(page.Entries) == limit {
				break
			}
		}
	}
	raw, _ := json.Marshal([]string{l.boot, strconv.FormatUint(after, 10)})
	page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	return page, nil
}

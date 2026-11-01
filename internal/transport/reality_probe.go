// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	reality "github.com/xtls/reality"
)

// Upstream's DetectPostHandshakeRecordsLens starts unowned net.Dial goroutines.
// Use its exported detector connections with bounded, cancellable sockets instead.
// Cache leases keep entries present until every owning listener has stopped.
var realityRecords = struct {
	sync.Mutex
	entries map[string]*recordProbe
}{entries: make(map[string]*recordProbe)}

type recordProbe struct {
	refs  int
	ready chan struct{}
	err   error
}

func acquireRealityRecords(ctx context.Context, cfg *reality.Config, timeout time.Duration) ([]string, error) {
	var keys []string
	var probes []*recordProbe
	var owned []bool
	for name := range cfg.ServerNames {
		for alpn := range 3 {
			key := cfg.Dest + " " + name + " " + strconv.Itoa(alpn)
			realityRecords.Lock()
			p := realityRecords.entries[key]
			created := p == nil
			if p == nil {
				p = &recordProbe{ready: make(chan struct{})}
				realityRecords.entries[key] = p
				reality.GlobalPostHandshakeRecordsLens.Store(key, false)
				go func() { p.err = probeRealityTarget(ctx, cfg.Dest, name, key, alpn, timeout); close(p.ready) }()
			}
			p.refs++
			realityRecords.Unlock()
			keys = append(keys, key)
			probes = append(probes, p)
			owned = append(owned, created)
		}
	}
	var result error
	// Join probes created by this startup before releasing their leases. A
	// cancelled waiter must not wait on another listener's longer probe context.
	for i, p := range probes {
		if owned[i] {
			<-p.ready
			result = errors.Join(result, p.err)
			continue
		}
		select {
		case <-p.ready:
			result = errors.Join(result, p.err)
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		}
	}
	if result != nil || ctx.Err() != nil {
		releaseRealityRecords(keys)
		return nil, errors.New("REALITY target probe failed or timed out")
	}
	return keys, nil
}
func releaseRealityRecords(keys []string) {
	realityRecords.Lock()
	defer realityRecords.Unlock()
	for _, key := range keys {
		p := realityRecords.entries[key]
		if p == nil {
			continue
		}
		p.refs--
		if p.refs == 0 {
			delete(realityRecords.entries, key)
			reality.GlobalPostHandshakeRecordsLens.Delete(key)
			reality.GlobalMaxCSSMsgCount.Delete(key)
		}
	}
}
func probeRealityTarget(ctx context.Context, target, name, key string, alpn int, timeout time.Duration) error {
	probe := func(ccs bool) error {
		raw, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", target)
		if err != nil {
			return err
		}
		defer raw.Close()
		stop := context.AfterFunc(ctx, func() { raw.Close() })
		defer stop()
		if deadline, ok := ctx.Deadline(); ok {
			_ = raw.SetDeadline(deadline)
		}
		var conn net.Conn = &reality.PostHandshakeRecordDetectConn{Conn: raw, Key: key}
		if ccs {
			conn = &reality.CCSDetectConn{Conn: raw, Key: key}
		}
		fingerprint := utls.HelloChrome_Auto
		protos := []string{"h2", "http/1.1"}
		if alpn != 2 {
			fingerprint = utls.HelloGolang
		}
		if alpn == 1 {
			protos = []string{"http/1.1"}
		}
		if alpn == 0 {
			protos = nil
		}
		// This probe records TLS framing, not target identity. REALITY authenticates
		// clients using its X25519 key; no target certificate is trusted by the proxy.
		client := utls.UClient(conn, &utls.Config{ServerName: name, NextProtos: protos, InsecureSkipVerify: true}, fingerprint)
		err = client.HandshakeContext(ctx)
		if err == nil && !ccs {
			_, err = io.Copy(io.Discard, client)
		}
		return err
	}
	done := make(chan struct{})
	go func() { _ = probe(true); close(done) }()
	_ = probe(false)
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	value, _ := reality.GlobalPostHandshakeRecordsLens.Load(key)
	if _, ok := value.([]int); !ok {
		return errors.New("target did not complete TLS record detection")
	}
	return nil
}

// Derived from XTLS/Xray-core transport/internet/splithttp/mux.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"errors"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

type xmuxConn interface {
	IsClosed() bool
	Close() error
}

type xmuxClient struct {
	conn         xmuxConn
	running      atomic.Int32
	requests     atomic.Int32
	leftUsage    int32
	leftRequests atomic.Int32
	unreusableAt time.Time
	notUsed      atomic.Bool
}

func (client *xmuxClient) addRunning()  { client.running.Add(1) }
func (client *xmuxClient) doneRunning() { client.running.Add(-1); client.maybeClose() }
func (client *xmuxClient) addRequest()  { client.requests.Add(1) }
func (client *xmuxClient) doneRequest() { client.requests.Add(-1); client.maybeClose() }
func (client *xmuxClient) maybeClose() {
	if client.notUsed.Load() && client.running.Load() <= 0 && client.requests.Load() <= 0 {
		_ = client.conn.Close()
	}
}

func (client *xmuxClient) takeRequest(now time.Time) bool {
	if !client.unreusableAt.IsZero() && now.After(client.unreusableAt) {
		return false
	}
	for {
		left := client.leftRequests.Load()
		if left <= 0 {
			return false
		}
		if client.leftRequests.CompareAndSwap(left, left-1) {
			return true
		}
	}
}

type xmuxLease struct {
	mu       sync.Mutex
	upload   *xmuxClient
	download *xmuxClient
	closed   bool
}

func newXMUXLease(upload, download *xmuxClient) *xmuxLease {
	lease := &xmuxLease{upload: upload, download: download}
	upload.addRunning()
	if download != upload {
		download.addRunning()
	}
	return lease
}

func (lease *xmuxLease) replaceUpload(next *xmuxClient) bool {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.closed {
		return false
	}
	previous := lease.upload
	if previous == next {
		return true
	}
	if next != lease.download {
		next.addRunning()
	}
	lease.upload = next
	if previous != lease.download {
		previous.doneRunning()
	}
	return true
}

func (lease *xmuxLease) Close() {
	lease.mu.Lock()
	if lease.closed {
		lease.mu.Unlock()
		return
	}
	lease.closed = true
	upload, download := lease.upload, lease.download
	lease.mu.Unlock()
	upload.doneRunning()
	if download != upload {
		download.doneRunning()
	}
}

type xmuxManager struct {
	mu          sync.Mutex
	config      XMUXConfig
	concurrency int32
	connections int32
	newConn     func() xmuxConn
	clients     []*xmuxClient
	closed      bool
}

func newXMUXManager(config XMUXConfig, newConn func() xmuxConn) *xmuxManager {
	return &xmuxManager{
		config:      config,
		concurrency: int32(config.MaxConcurrency.random()),
		connections: int32(config.MaxConnections.random()),
		newConn:     newConn,
	}
}

func (manager *xmuxManager) get() *xmuxClient {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return nil
	}
	for index := 0; index < len(manager.clients); {
		client := manager.clients[index]
		if client.conn.IsClosed() || client.leftUsage == 0 || client.leftRequests.Load() <= 0 ||
			(!client.unreusableAt.IsZero() && time.Now().After(client.unreusableAt)) {
			client.notUsed.Store(true)
			client.maybeClose()
			manager.clients = append(manager.clients[:index], manager.clients[index+1:]...)
			continue
		}
		index++
	}
	if len(manager.clients) == 0 || manager.connections > 0 && len(manager.clients) < int(manager.connections) {
		return manager.create()
	}
	eligible := len(manager.clients)
	if manager.concurrency > 0 {
		eligible = 0
		for _, client := range manager.clients {
			if client.running.Load() < manager.concurrency {
				eligible++
			}
		}
	}
	if eligible == 0 {
		return manager.create()
	}
	selected := 0
	if eligible > 1 {
		selected = rand.N(eligible) //nolint:gosec // spreading sessions over connections needs no secrecy
	}
	var client *xmuxClient
	for _, candidate := range manager.clients {
		if manager.concurrency > 0 && candidate.running.Load() >= manager.concurrency {
			continue
		}
		if selected == 0 {
			client = candidate
			break
		}
		selected--
	}
	if client.leftUsage > 0 {
		client.leftUsage--
	}
	return client
}

func (manager *xmuxManager) create() *xmuxClient {
	client := &xmuxClient{conn: manager.newConn(), leftUsage: -1}
	if value := manager.config.CMaxReuseTimes.random(); value > 0 {
		client.leftUsage = int32(value - 1)
	}
	client.leftRequests.Store(math.MaxInt32)
	if value := manager.config.HMaxRequestTimes.random(); value > 0 {
		client.leftRequests.Store(int32(value))
	}
	if value := manager.config.HMaxReusableSecs.random(); value > 0 {
		client.unreusableAt = time.Now().Add(time.Duration(value) * time.Second)
	}
	manager.clients = append(manager.clients, client)
	return client
}

func (manager *xmuxManager) Close() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.closed = true
	for _, client := range manager.clients {
		client.notUsed.Store(true)
		client.maybeClose()
	}
	manager.clients = nil
	return nil
}

func (manager *xmuxManager) forceClose() error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.closed = true
	var result error
	for _, client := range manager.clients {
		client.notUsed.Store(true)
		result = errors.Join(result, client.conn.Close())
	}
	manager.clients = nil
	return result
}

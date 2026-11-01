// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package replay

import (
	"encoding/binary"
	"sync"
	"time"
)

const (
	defaultMaxClients     = 64
	minimumTrackedClients = 1024
	connectionWindowSize  = 4096
	clientIdleTimeout     = 10 * time.Minute
	userSweepInterval     = 30 * time.Second
	sessionShardCount     = 64
)

// Sessions tracks authenticated SSR client and connection identifiers. State
// is sharded by user so unrelated users do not contend on a process-wide lock.
// maxClients limits active client IDs; inactive replay history is retained for
// clientIdleTimeout inside a separately bounded tracking set.
type Sessions struct {
	now    func() time.Time
	shards [sessionShardCount]sessionShard
}

type sessionShard struct {
	mu        sync.Mutex
	users     map[[4]byte]*userSessions
	lastSweep int64
}

type userSessions struct {
	clients       map[uint32]*clientSession
	activeClients int
}

type clientSession struct {
	lastSeen    int64
	references  int
	connections map[uint32]struct{}
}

func NewSessions(now func() time.Time) *Sessions {
	if now == nil {
		now = time.Now
	}
	return &Sessions{now: now}
}

// Accept records a fresh connection identifier and acquires one active
// reference for clientID. Callers must pair every successful Accept with
// Release when the authenticated stream closes.
func (s *Sessions) Accept(userID [4]byte, clientID, connectionID uint32, maxClients int) bool {
	if s == nil || userID == [4]byte{} {
		return false
	}
	if maxClients <= 0 {
		maxClients = defaultMaxClients
	}
	shard := s.shard(userID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	now := s.now().UnixNano()
	if shard.users == nil {
		shard.users = make(map[[4]byte]*userSessions)
	}
	if now-shard.lastSweep >= int64(userSweepInterval) || now < shard.lastSweep {
		shard.sweep(now)
		shard.lastSweep = now
	}
	user := shard.users[userID]
	if user == nil {
		user = &userSessions{clients: make(map[uint32]*clientSession, min(maxClients, defaultMaxClients))}
		shard.users[userID] = user
	}
	client := user.clients[clientID]
	if client != nil && client.references == 0 &&
		(now-client.lastSeen >= int64(clientIdleTimeout) || now < client.lastSeen) {
		clear(client.connections)
	}
	if client != nil {
		if _, duplicate := client.connections[connectionID]; duplicate {
			return false
		}
		if client.references == 0 && user.activeClients >= maxClients {
			return false
		}
	} else {
		if user.activeClients >= maxClients {
			return false
		}
		trackedLimit := max(maxClients, minimumTrackedClients)
		if len(user.clients) >= trackedLimit && !user.evictOldestInactive() {
			return false
		}
		client = &clientSession{connections: make(map[uint32]struct{}, 4)}
		user.clients[clientID] = client
	}
	if len(client.connections) >= connectionWindowSize {
		for existing := range client.connections {
			if int32(connectionID-existing) >= connectionWindowSize {
				delete(client.connections, existing)
			}
		}
		if len(client.connections) >= connectionWindowSize {
			return false
		}
	}
	client.connections[connectionID] = struct{}{}
	client.lastSeen = now
	if client.references == 0 {
		user.activeClients++
	}
	client.references++
	return true
}

// Release drops one active reference acquired by Accept while preserving the
// connection-ID replay history until the idle timeout expires.
func (s *Sessions) Release(userID [4]byte, clientID uint32) {
	if s == nil || userID == [4]byte{} {
		return
	}
	shard := s.shard(userID)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	user := shard.users[userID]
	if user == nil {
		return
	}
	client := user.clients[clientID]
	if client == nil || client.references == 0 {
		return
	}
	client.references--
	if client.references == 0 {
		user.activeClients--
		client.lastSeen = s.now().UnixNano()
	}
}

func (s *Sessions) shard(userID [4]byte) *sessionShard {
	value := binary.LittleEndian.Uint32(userID[:]) * 0x9e3779b1
	return &s.shards[value>>(32-6)]
}

func (s *sessionShard) sweep(now int64) {
	for userID, user := range s.users {
		for clientID, client := range user.clients {
			if client.references == 0 &&
				(now-client.lastSeen >= int64(clientIdleTimeout) || now < client.lastSeen) {
				delete(user.clients, clientID)
			}
		}
		if len(user.clients) == 0 {
			delete(s.users, userID)
		}
	}
}

func (u *userSessions) evictOldestInactive() bool {
	var oldestID uint32
	oldestSeen := int64(0)
	found := false
	for clientID, client := range u.clients {
		if client.references != 0 || found && client.lastSeen >= oldestSeen {
			continue
		}
		oldestID = clientID
		oldestSeen = client.lastSeen
		found = true
	}
	if found {
		delete(u.clients, oldestID)
	}
	return found
}

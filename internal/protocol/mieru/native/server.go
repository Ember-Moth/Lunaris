// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Polaris contributors

package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type Server struct {
	managed       bool
	budgetMu      sync.Mutex
	buffered      int64
	budgetChanged chan struct{}
	lifecycle     sync.Mutex
	sessionCount  atomic.Int64
	pending       chan struct{}
	packetWrite   sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	option        ServerOptions
	log           logger.ContextLogger

	users             atomic.Pointer[userSnapshot]
	accepted          chan net.Conn
	listener          net.Listener
	packet            net.PacketConn
	streams           sync.Map
	packetSessions    sync.Map
	remoteCipherMu    sync.Mutex
	remoteCiphers     map[packetRemoteKey]*remoteCipherSet
	ackQueue          chan *packetSession
	replay            *replayCache
	packetMetaScratch [metadataLength]byte
	pattern           *trafficPattern
	nonceApplied      sync.Map
	packetBuffers     sync.Pool

	startOnce sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup
	startErr  error
	closeErr  error
}

func NewServer(options ServerOptions) (*Server, error) {
	if options.Context == nil || options.ListenAddress == "" || options.TCPHandler == nil ||
		(options.Transport != TransportTCP && options.Transport != TransportUDP) {
		return nil, ErrInvalidOptions
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	var prepared *PreparedUsers
	var err error
	if options.PreparedUsers != nil {
		prepared = options.PreparedUsers
	} else {
		prepared, err = PrepareUsers(options.Users)
		if err != nil {
			return nil, err
		}
	}
	if prepared == nil || prepared.snapshot == nil || len(prepared.snapshot.users) == 0 {
		return nil, ErrInvalidOptions
	}
	options.Users = nil
	options.PreparedUsers = nil
	pattern, err := decodeTrafficPattern(options.TrafficPattern)
	if err != nil {
		return nil, err
	}
	if options.MaxPending <= 0 {
		options.MaxPending = 256
	}
	if options.MaxSessions <= 0 {
		options.MaxSessions = 4096
	}
	if options.QueueSize <= 0 {
		options.QueueSize = 256
	}
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = 10 * time.Second
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = 2 * time.Minute
	}
	if options.WriteTimeout <= 0 {
		options.WriteTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(options.Context))
	server := &Server{ctx: ctx, cancel: cancel, option: options, log: options.Logger, accepted: make(chan net.Conn, 256),
		pending: make(chan struct{}, options.MaxPending), ackQueue: make(chan *packetSession, 4096), replay: newReplayCache(256*1024, 3*keyRefreshInterval), pattern: pattern}
	packetCapacity := max(defaultMTU, options.MTU)
	server.packetBuffers.New = func() any {
		buffer := make([]byte, 0, packetCapacity)
		return &buffer
	}
	snapshot := *prepared.snapshot
	snapshot.mandatory = options.UserHintIsMandatory
	snapshot.scan = newAuthSelector()
	server.users.Store(&snapshot)
	return server, nil
}

func (s *Server) Start() error {
	s.startOnce.Do(func() {
		switch s.option.Transport {
		case TransportTCP:
			if s.option.StreamFactory != nil {
				s.listener, s.startErr = s.option.StreamFactory.Listen(s.ctx, "tcp", s.option.ListenAddress)
			} else {
				var config net.ListenConfig
				s.listener, s.startErr = config.Listen(s.ctx, "tcp", s.option.ListenAddress)
			}
			if s.startErr == nil {
				s.wg.Add(2)
				go s.listenStream()
				go s.acceptSessions()
			}
		case TransportUDP:
			if s.option.PacketFactory != nil {
				s.packet, s.startErr = s.option.PacketFactory.ListenPacket(s.ctx, "udp", s.option.ListenAddress)
			} else {
				var config net.ListenConfig
				s.packet, s.startErr = config.ListenPacket(s.ctx, "udp", s.option.ListenAddress)
			}
			if s.startErr == nil {
				s.wg.Add(3)
				go s.listenPacket()
				go s.maintainPackets()
				go s.ackPackets()
				s.wg.Add(1)
				go s.acceptSessions()
			}
		}
	})
	return s.startErr
}

func (s *Server) UpdateUsers(users []User) error {
	prepared, err := PrepareUsers(users)
	if err != nil {
		return err
	}
	return s.UpdatePreparedUsers(prepared)
}

func (s *Server) UpdatePreparedUsers(prepared *PreparedUsers) error {
	if prepared == nil || prepared.snapshot == nil || len(prepared.snapshot.users) == 0 {
		return ErrInvalidOptions
	}
	snapshot := *prepared.snapshot
	snapshot.mandatory = s.option.UserHintIsMandatory
	snapshot.scan = newAuthSelector()
	s.users.Store(&snapshot)
	return nil
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.lifecycle.Lock()
		s.cancel()
		s.lifecycle.Unlock()
		if s.listener != nil {
			s.closeErr = s.listener.Close()
		}
		if s.packet != nil {
			if s.managed {
				_ = s.packet.SetReadDeadline(time.Now())
			} else {
				s.closeErr = errors.Join(s.closeErr, s.packet.Close())
			}
		}
		s.streams.Range(func(_, value any) bool {
			value.(*streamUnderlay).close()
			return true
		})
		s.packetSessions.Range(func(_, value any) bool {
			value.(*packetSession).closeRemote()
			return true
		})
		s.wg.Wait()
	})
	return s.closeErr
}

func (s *Server) listenStream() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() == nil {
				s.report(fmt.Errorf("sing-mieru: accept underlay: %w", err))
			}
			return
		}
		ctx, cancel := context.WithCancel(s.ctx)
		underlay := &streamUnderlay{server: s, conn: conn, done: make(chan struct{}), ctx: ctx, cancel: cancel, handshakeDeadline: time.Now().Add(s.option.HandshakeTimeout)}
		s.streams.Store(underlay, underlay)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.streams.Delete(underlay)
			if runErr := underlay.run(); runErr != nil && s.ctx.Err() == nil &&
				!errors.Is(runErr, io.EOF) && !errors.Is(runErr, net.ErrClosed) {
				s.report(fmt.Errorf("sing-mieru: stream underlay: %w", runErr))
			}
		}()
	}
}

func (s *Server) acceptSessions() {
	defer s.wg.Done()
	for {
		select {
		case conn := <-s.accepted:
			select {
			case s.pending <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { <-s.pending }()
				s.handle(conn)
			}()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Server) report(err error) {
	s.log.ErrorContext(s.ctx, err)
	if s.option.OnError != nil {
		s.option.OnError(s.ctx, err)
	}
}

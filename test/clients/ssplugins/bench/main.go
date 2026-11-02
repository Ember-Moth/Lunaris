// SPDX-License-Identifier: GPL-3.0-only
// Separate-process loopback benchmark peer and unmodified Mihomo client.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

const blockSize = 64 * 1024

func emit(v any) {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		panic(err)
	}
}
func processCPU() float64 {
	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) != nil {
		return 0
	}
	return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
}

func writeAll(c net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := c.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type config struct {
	Server, Method, Password, Plugin, Target, Direction string
	PluginOpts                                          map[string]any
	Connections                                         int
	WarmupSeconds, Seconds                              float64
}
type streamResult struct {
	bytes uint64
	err   error
}

func main() {
	mode := flag.String("mode", "client", "client or peer")
	file := flag.String("config", "", "client JSON config")
	cert := flag.String("cert", "", "peer TLS certificate")
	key := flag.String("key", "", "peer TLS private key")
	flag.Parse()
	var err error
	if *mode == "peer" {
		err = peer(*cert, *key)
	} else {
		raw, e := os.ReadFile(*file)
		err = e
		if err == nil {
			var c config
			err = json.Unmarshal(raw, &c)
			if err == nil {
				err = run(c)
			}
		}
	}
	if err != nil {
		emit(map[string]any{"event": "error", "error": err.Error()})
		os.Exit(1)
	}
}

func peer(certFile, keyFile string) error {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	payload := make([]byte, blockSize)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	var listeners []net.Listener
	var connections sync.Map
	var wg sync.WaitGroup
	defer func() {
		cancel()
		for _, l := range listeners {
			l.Close()
		}
		connections.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		wg.Wait()
	}()
	addresses := map[string]any{"event": "ready", "pid": os.Getpid(), "go": runtime.Version()}
	for _, kind := range []string{"data", "tls12", "tls13"} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		if kind != "data" {
			version := uint16(tls.VersionTLS13)
			if kind == "tls12" {
				version = tls.VersionTLS12
			}
			listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: version, MaxVersion: version})
		}
		listeners = append(listeners, listener)
		addresses[kind] = listener.Addr().String()
		wg.Go(func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				connections.Store(c, true)
				wg.Go(func() {
					defer c.Close()
					defer connections.Delete(c)
					stop := context.AfterFunc(ctx, func() { c.Close() })
					defer stop()
					_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
					if kind == "data" {
						serveData(c, payload)
					} else {
						_, _ = io.Copy(c, c)
					}
				})
			}
		})
	}
	emit(addresses)
	<-ctx.Done()
	return nil
}
func serveData(c net.Conn, payload []byte) {
	var mode [1]byte
	if _, err := io.ReadFull(c, mode[:]); err != nil {
		return
	}
	if err := writeAll(c, []byte{'K'}); err != nil {
		return
	}
	switch mode[0] {
	case 'H':
		_, _ = io.Copy(io.Discard, c)
	case 'D':
		var start [1]byte
		if _, err := io.ReadFull(c, start[:]); err != nil {
			return
		}
		for {
			if err := writeAll(c, payload); err != nil {
				return
			}
		}
	case 'U':
		var total uint64
		var length [4]byte
		for {
			if _, err := io.ReadFull(c, length[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(length[:])
			if n == ^uint32(0) {
				total = 0
				continue
			}
			if n == 0 {
				var ack [8]byte
				binary.BigEndian.PutUint64(ack[:], total)
				_ = writeAll(c, ack[:])
				return
			}
			if n > blockSize {
				return
			}
			if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
				return
			}
			total += uint64(n)
		}
	}
}

func run(c config) error {
	if c.Connections < 1 || c.Connections > 1024 || c.Seconds < 1 || c.Seconds > 120 || c.WarmupSeconds < 0 || c.WarmupSeconds > 10 {
		return errors.New("invalid benchmark limits")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Seconds+c.WarmupSeconds+40)*time.Second)
	defer cancel()
	var proxy *outbound.ShadowSocks
	var err error
	if c.Plugin != "direct" {
		host, port, e := net.SplitHostPort(c.Server)
		if e != nil {
			return e
		}
		p, e := strconv.Atoi(port)
		if e != nil {
			return e
		}
		proxy, err = outbound.NewShadowSocks(outbound.ShadowSocksOption{Name: "benchmark", Server: host, Port: p, Password: c.Password, Cipher: c.Method, Plugin: c.Plugin, PluginOpts: c.PluginOpts, ClientFingerprint: "chrome"})
		if err != nil {
			return err
		}
		defer proxy.Close()
	}
	address, err := netip.ParseAddrPort(c.Target)
	if err != nil {
		return err
	}
	metadata := &C.Metadata{DstIP: address.Addr(), DstPort: address.Port(), NetWork: C.TCP}
	connections := make([]net.Conn, c.Connections)
	var live sync.Map
	cleanup := func() { live.Range(func(k, v any) bool { k.(net.Conn).Close(); return true }) }
	stop := context.AfterFunc(ctx, cleanup)
	defer stop()
	defer cleanup()
	var wg sync.WaitGroup
	var firstErr error
	var mu sync.Mutex
	gate := make(chan struct{}, 16)
	for i := range c.Connections {
		wg.Go(func() {
			select {
			case gate <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-gate }()
			var conn net.Conn
			var err error
			if proxy == nil {
				conn, err = (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", c.Target)
			} else {
				conn, err = proxy.DialContext(ctx, metadata)
			}
			if err == nil {
				live.Store(conn, true)
				if ctx.Err() != nil {
					conn.Close()
				}
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				mode := byte('D')
				if c.Direction == "upload" {
					mode = 'U'
				}
				if c.Direction == "hold" {
					mode = 'H'
				}
				err = writeAll(conn, []byte{mode})
				if err == nil {
					var ack [1]byte
					_, err = io.ReadFull(conn, ack[:])
					if err == nil && ack[0] != 'K' {
						err = errors.New("invalid peer acknowledgement")
					}
				}
				if err == nil {
					_ = conn.SetDeadline(time.Time{})
					connections[i] = conn
				} else {
					conn.Close()
					live.Delete(conn)
				}
			}
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if firstErr != nil {
		return fmt.Errorf("setup: %w", firstErr)
	}
	for _, conn := range connections {
		if conn == nil {
			return errors.New("setup cancelled")
		}
	}
	emit(map[string]any{"event": "ready", "connections": len(connections), "pid": os.Getpid(), "direction": c.Direction})
	if c.Direction == "hold" {
		select {
		case <-time.After(time.Duration(c.Seconds * float64(time.Second))):
		case <-ctx.Done():
			return ctx.Err()
		}
		emit(map[string]any{"event": "measure_end"})
		cleanup()
		emit(map[string]any{"event": "result", "direction": "hold", "connections": len(connections)})
		return nil
	}
	if c.Direction != "download" && c.Direction != "upload" {
		return errors.New("unknown direction")
	}
	var count atomic.Uint64
	var ending atomic.Bool
	startMeasure := make(chan struct{})
	endMeasure := make(chan struct{})
	results := make(chan streamResult, len(connections))
	for _, conn := range connections {
		go func() {
			if c.Direction == "download" {
				if err := writeAll(conn, []byte{'G'}); err != nil {
					results <- streamResult{err: err}
					return
				}
				buffer := make([]byte, blockSize)
				for {
					n, err := conn.Read(buffer)
					count.Add(uint64(n))
					if err != nil {
						if ending.Load() {
							err = nil
						}
						results <- streamResult{err: err}
						return
					}
				}
			}
			frame := make([]byte, 4+blockSize)
			binary.BigEndian.PutUint32(frame[:4], blockSize)
			_, _ = rand.Read(frame[4:])
			measured := false
			for {
				if !measured {
					select {
					case <-startMeasure:
						if err := writeAll(conn, []byte{255, 255, 255, 255}); err != nil {
							results <- streamResult{err: err}
							return
						}
						measured = true
					default:
					}
				}
				if measured {
					select {
					case <-endMeasure:
						if err := writeAll(conn, []byte{0, 0, 0, 0}); err != nil {
							results <- streamResult{err: err}
							return
						}
						var ack [8]byte
						_, err := io.ReadFull(conn, ack[:])
						results <- streamResult{bytes: binary.BigEndian.Uint64(ack[:]), err: err}
						return
					default:
					}
				}
				if err := writeAll(conn, frame); err != nil {
					results <- streamResult{err: err}
					return
				}
			}
		}()
	}
	wait := func(d time.Duration) error {
		select {
		case <-time.After(d):
			return nil
		case r := <-results:
			if r.err != nil {
				return r.err
			}
			return errors.New("stream ended before measurement")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := wait(time.Duration(c.WarmupSeconds * float64(time.Second))); err != nil {
		return fmt.Errorf("warmup: %w", err)
	}
	baseline := count.Load()
	cpuStart := processCPU()
	began := time.Now()
	close(startMeasure)
	emit(map[string]any{"event": "measure_start"})
	if err := wait(time.Duration(c.Seconds * float64(time.Second))); err != nil {
		return fmt.Errorf("measurement: %w", err)
	}
	var bytes uint64
	if c.Direction == "download" {
		bytes = count.Load() - baseline
		ending.Store(true)
	} else {
		close(endMeasure)
	}
	elapsed := time.Since(began).Seconds()
	cpuEnd := processCPU()
	if c.Direction == "download" {
		emit(map[string]any{"event": "measure_end"})
		cleanup()
	}
	for range connections {
		select {
		case r := <-results:
			if r.err != nil {
				return r.err
			}
			if c.Direction == "upload" {
				bytes += r.bytes
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if c.Direction == "upload" {
		elapsed = time.Since(began).Seconds()
		cpuEnd = processCPU()
		emit(map[string]any{"event": "measure_end"})
		cleanup()
	}
	if bytes == 0 {
		return errors.New("no delivered data")
	}
	emit(map[string]any{"event": "result", "direction": c.Direction, "connections": c.Connections, "bytes": bytes, "seconds": elapsed, "gbps": float64(bytes) * 8 / elapsed / 1e9, "client_cpu_percent": (cpuEnd - cpuStart) / elapsed * 100})
	return nil
}

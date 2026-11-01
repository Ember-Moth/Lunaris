// SPDX-License-Identifier: GPL-3.0-only
// Independently exercises the unmodified Mihomo Shadowsocks/plugin client stack.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime/pprof"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

type config struct {
	Server, Method, Password, Plugin, TCPTarget, UDPTarget string
	PluginOpts                                             map[string]any
	ExpectFailure                                          bool
}

func metadata(raw string, network C.NetWork) (*C.Metadata, error) {
	address, err := netip.ParseAddrPort(raw)
	if err != nil {
		return nil, err
	}
	return &C.Metadata{DstIP: address.Addr(), DstPort: address.Port(), NetWork: network}, nil
}
func main() {
	// Keep a broken third-party deadline implementation from hanging the harness.
	watchdog := time.AfterFunc(25*time.Second, func() { _ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 2); os.Exit(2) })
	defer watchdog.Stop()
	path := flag.String("config", "", "loopback test config")
	flag.Parse()
	data, err := os.ReadFile(*path)
	if err != nil {
		panic(err)
	}
	var cfg config
	if err = json.Unmarshal(data, &cfg); err == nil {
		err = run(cfg)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(c config) error {
	host, port, err := net.SplitHostPort(c.Server)
	if err != nil {
		return err
	}
	p, _ := strconv.Atoi(port)
	client, err := outbound.NewShadowSocks(outbound.ShadowSocksOption{Name: "loopback", Server: host, Port: p, Password: c.Password, Cipher: c.Method, Plugin: c.Plugin, PluginOpts: c.PluginOpts, UDP: true, UDPOverTCP: true, UDPOverTCPVersion: 2, ClientFingerprint: "chrome"})
	if err != nil {
		return err
	}
	defer client.Close()
	target, err := metadata(c.TCPTarget, C.TCP)
	if err != nil {
		return err
	}
	exchange := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx, target)
		if err != nil {
			return err
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
		for _, size := range []int{29, 131072, 17} {
			payload := bytes.Repeat([]byte{byte(size)}, size)
			write := make(chan error, 1)
			go func() { _, err := conn.Write(payload); write <- err }()
			got := make([]byte, size)
			_, err = io.ReadFull(conn, got)
			if err != nil {
				conn.Close()
				<-write
				return err
			}
			if err = <-write; err != nil {
				return err
			}
			if !bytes.Equal(got, payload) {
				return fmt.Errorf("TCP payload mismatch")
			}
		}
		return nil
	}
	if c.ExpectFailure {
		if err := exchange(); err == nil {
			return fmt.Errorf("invalid credential accepted")
		}
		fmt.Println("PASS rejection")
		return nil
	}
	var wg sync.WaitGroup
	results := make(chan error, 3)
	for range 3 {
		wg.Go(func() { results <- exchange() })
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			return fmt.Errorf("TCP: %w", err)
		}
	}
	udpTarget, err := metadata(c.UDPTarget, C.UDP)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	pc, err := client.ListenPacketContext(ctx, udpTarget)
	if err != nil {
		return err
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	_ = pc.SetDeadline(time.Now().Add(7 * time.Second))
	dst, err := net.ResolveUDPAddr("udp", c.UDPTarget)
	if err != nil {
		return err
	}
	for _, size := range []int{1, 4096, 8192} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if _, err = pc.WriteTo(payload, dst); err != nil {
			return err
		}
		got := make([]byte, 65535)
		n, _, err := pc.ReadFrom(got)
		if err != nil {
			return fmt.Errorf("UoT size=%d: %w", size, err)
		}
		if !bytes.Equal(got[:n], payload) {
			return fmt.Errorf("UoT payload mismatch")
		}
	}
	fmt.Printf("PASS %s/%s: concurrent TCP + UoT\n", c.Plugin, c.Method)
	return nil
}

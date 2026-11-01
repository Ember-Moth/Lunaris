// SPDX-License-Identifier: GPL-3.0-only
// Uses unmodified Mihomo wire codecs, independently from the node's SSR port.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/shadowsocks/core"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowstream"
	"github.com/metacubex/mihomo/transport/ssr/obfs"
	"github.com/metacubex/mihomo/transport/ssr/protocol"
	"io"
	"net"
	"os"
	"strconv"
	"time"
)

type config struct {
	Server, Method, Password, Protocol, ProtocolParam, Obfs, ObfsParam, TCPTarget, UDPTarget string
	ConcurrentStartup                                                                        bool
}

func main() {
	file := flag.String("config", "", "loopback test config")
	flag.Parse()
	data, err := os.ReadFile(*file)
	if err != nil {
		panic(err)
	}
	var c config
	if err = json.Unmarshal(data, &c); err == nil {
		err = run(c)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func address(raw string) ([]byte, error) {
	host, p, err := net.SplitHostPort(raw)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv4 loopback target required")
	}
	b := append([]byte{1}, ip...)
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}
func run(c config) error {
	method := c.Method
	if method == "none" {
		method = "dummy"
	}
	cipher, err := core.PickCipher(method, nil, c.Password)
	if err != nil {
		return err
	}
	var key []byte
	var ivLen int
	if method == "dummy" {
		key = core.Kdf(c.Password, 16)
	} else {
		stream, ok := cipher.(*core.StreamCipher)
		if !ok {
			return fmt.Errorf("Mihomo SSR does not support this cipher")
		}
		key = stream.Key
		ivLen = stream.IVSize()
	}
	host, p, _ := net.SplitHostPort(c.Server)
	port, _ := strconv.Atoi(p)
	obfuscator, overhead, err := obfs.PickObfs(c.Obfs, &obfs.Base{Host: host, Port: port, Key: key, IVSize: ivLen, Param: c.ObfsParam})
	if err != nil {
		return err
	}
	transform, err := protocol.PickProtocol(c.Protocol, &protocol.Base{Key: key, Overhead: overhead, Param: c.ProtocolParam})
	if err != nil {
		return err
	}
	target, err := address(c.TCPTarget)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		raw, err := net.DialTimeout("tcp", c.Server, 3*time.Second)
		if err != nil {
			return err
		}
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		encrypted := cipher.StreamConn(obfuscator.StreamConn(raw))
		var iv []byte
		if stream, ok := encrypted.(*shadowstream.Conn); ok {
			iv, err = stream.ObtainWriteIV()
			if err != nil {
				raw.Close()
				return err
			}
		}
		conn := transform.StreamConn(encrypted, iv)
		if _, err = conn.Write(bytes.Clone(target)); err != nil {
			conn.Close()
			return err
		}
		payload := bytes.Repeat([]byte("independent-ssr-wire"), 3000)
		got := make([]byte, len(payload))
		if c.ConcurrentStartup {
			done := make(chan error, 1)
			go func() { _, err := conn.Write(bytes.Clone(payload)); done <- err }()
			_, err = io.ReadFull(conn, got)
			writeErr := <-done
			if err == nil {
				err = writeErr
			}
		} else {
			_, err = conn.Write(bytes.Clone(payload))
			if err == nil {
				_, err = io.ReadFull(conn, got)
			}
		}
		conn.Close()
		if err != nil {
			return fmt.Errorf("TCP: %w", err)
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("TCP payload mismatch")
		}
	}
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer raw.Close()
	packet := transform.PacketConn(cipher.PacketConn(N.NewEnhancePacketConn(raw)))
	dst, err := net.ResolveUDPAddr("udp", c.Server)
	if err != nil {
		return err
	}
	header, err := address(c.UDPTarget)
	if err != nil {
		return err
	}
	payload := bytes.Repeat([]byte("udp"), 300)
	_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = packet.WriteTo(append(header, payload...), dst); err != nil {
		return err
	}
	out := make([]byte, 65535)
	n, _, err := packet.ReadFrom(out)
	if err != nil {
		return fmt.Errorf("UDP: %w", err)
	}
	if n < 7 || !bytes.Equal(out[7:n], payload) {
		return fmt.Errorf("UDP payload mismatch")
	}
	fmt.Printf("PASS SSR %s/%s/%s: TCP + UDP\n", c.Method, c.Protocol, c.Obfs)
	return nil
}

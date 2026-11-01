// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

func TestRealitySelectorPreservesFragmentedClientHello(t *testing.T) {
	for _, compat := range []bool{false, true} {
		name := "modern"
		if compat {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			dummy, peer := net.Pipe()
			defer dummy.Close()
			defer peer.Close()
			client := utls.UClient(dummy, &utls.Config{ServerName: "localhost"}, utls.HelloChrome_Auto)
			if err := client.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			if compat {
				for _, extension := range client.Extensions {
					if shares, ok := extension.(*utls.KeyShareExtension); ok {
						var filtered []utls.KeyShare
						for _, share := range shares.KeyShares {
							if share.Group != utls.X25519MLKEM768 {
								filtered = append(filtered, share)
							}
						}
						shares.KeyShares = filtered
					}
				}
				if err := client.BuildHandshakeState(); err != nil {
					t.Fatal(err)
				}
			}
			hello := client.HandshakeState.Hello.Raw
			var wire []byte
			// ClientHello spans several TLS records and arbitrary TCP writes.
			for len(hello) > 0 {
				n := min(137, len(hello))
				header := []byte{22, 3, 1, 0, 0}
				binary.BigEndian.PutUint16(header[3:], uint16(n))
				wire = append(wire, header...)
				wire = append(wire, hello[:n]...)
				hello = hello[n:]
			}
			send, receive := net.Pipe()
			defer send.Close()
			defer receive.Close()
			_ = receive.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() {
				for _, b := range wire {
					if _, err := send.Write([]byte{b}); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			replay, legacy, err := selectRealityBackend(receive)
			if err != nil {
				t.Fatal(err)
			}
			if legacy != compat {
				t.Fatalf("wrong handshake backend: %v", legacy)
			}
			got := make([]byte, len(wire))
			if _, err = io.ReadFull(replay, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, wire) {
				t.Fatal("ClientHello transcript was modified")
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

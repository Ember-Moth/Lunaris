// SPDX-License-Identifier: GPL-3.0-only
package shadowsocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/egress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/hkdf"
)

// A SIP004 AES-128-GCM wire probe independent of sing's packet encoder/parser.
// This is a protocol fixture, not a claim of third-party client validation.
func fixtureAEAD(t *testing.T, salt []byte) cipher.AEAD {
	t.Helper()
	master := md5.Sum([]byte(testPassword))
	subkey := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.New(sha1.New, master[:], salt, []byte("ss-subkey")), subkey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(subkey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func TestIndependentUDPAEADWire(t *testing.T) {
	target := udpEcho(t)
	server, _ := startServer(t, "aes-128-gcm", model.DefaultLimits(), &egress.Direct{})
	plain := []byte{1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(plain[5:7], uint16(target.(*net.UDPAddr).Port))
	plain = append(plain, []byte("independent UDP wire probe")...)
	salt := bytes.Repeat([]byte{0x7c}, 16)
	packet := append(bytes.Clone(salt), fixtureAEAD(t, salt).Seal(nil, make([]byte, 12), plain, nil)...)
	conn, err := net.Dial("udp", server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 1500)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	if n < 32 {
		t.Fatal("short AEAD response")
	}
	decoded, err := fixtureAEAD(t, response[:16]).Open(nil, make([]byte, 12), response[16:n], nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, plain) {
		t.Fatalf("incorrect packet address or payload: %x", decoded)
	}
}

func TestPacketQueueBudgetAndRelease(t *testing.T) {
	server := &Server{limits: model.DefaultLimits(), sessions: make(map[packetSessionKey]*packetSession)}
	sessions := make([]*packetSession, 5)
	for i := range sessions {
		sessions[i] = newPacketSession(server, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(10000+i)))
	}
	for i := 0; i < 256; i++ {
		packet := buf.NewSize(65536)
		packet.Truncate(65536)
		sessions[i/64].offer(packet, M.Socksaddr{})
	}
	packet := buf.NewSize(1)
	packet.Truncate(1)
	sessions[4].offer(packet, M.Socksaddr{})
	if len(sessions[4].queue) != 0 || server.queuedBytes != maxQueuedPayloadBytes {
		t.Fatal("aggregate packet queue limit was not enforced")
	}
	for _, session := range sessions {
		session.Close()
	}
	if server.queuedBytes != 0 {
		t.Fatalf("queue budget leaked: %d", server.queuedBytes)
	}
}

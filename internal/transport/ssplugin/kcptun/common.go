// SPDX-License-Identifier: MIT
// Derived and modified from github.com/MetaCubeX/mihomo transport/kcptun.

package kcptun

import (
	"crypto/sha1" //nolint:gosec // kcptun derives its key with PBKDF2-SHA1 for wire compatibility
	"errors"
	"net"
	"time"

	"github.com/golang/snappy"
	"github.com/metacubex/kcp-go"
	"github.com/sagernet/smux"
	"golang.org/x/crypto/pbkdf2"
)

// Config is the kcptun plugin configuration in the upstream tool's option names.
type Config struct {
	HandshakeTimeout   time.Duration
	MaxPendingSessions int
	Key                string
	Crypt              string
	Mode               string
	Conn               int
	AutoExpire         int
	ScavengeTTL        int
	MTU                int
	RateLimit          int
	SndWnd             int
	RcvWnd             int
	DataShard          int
	ParityShard        int
	DSCP               int
	NoDelay            int
	Interval           int
	Resend             int
	NoCongestion       int
	SockBuf            int
	SmuxVer            int
	SmuxBuf            int
	FrameSize          int
	StreamBuf          int
	KeepAlive          int
	NoComp             bool
	AckNodelay         bool
	AllowInsecure      bool
	MaxSessions        int
	MaxStreams         int
	MaxActiveStreams   int
}

func insecureCrypt(crypt string) bool {
	switch crypt {
	case "null", "none", "xor", "tea", "3des":
		return true
	default:
		return false
	}
}

func newBlock(config Config) (kcp.BlockCrypt, error) {
	key := pbkdf2.Key([]byte(config.Key), []byte("kcp-go"), 4096, 32, sha1.New)
	switch config.Crypt {
	case "null":
		return nil, nil
	case "tea":
		return kcp.NewTEABlockCrypt(key[:16])
	case "xor":
		return kcp.NewSimpleXORBlockCrypt(key)
	case "none":
		return kcp.NewNoneBlockCrypt(key)
	case "aes-128":
		return kcp.NewAESBlockCrypt(key[:16])
	case "aes-192":
		return kcp.NewAESBlockCrypt(key[:24])
	case "blowfish":
		return kcp.NewBlowfishBlockCrypt(key)
	case "twofish":
		return kcp.NewTwofishBlockCrypt(key)
	case "cast5":
		return kcp.NewCast5BlockCrypt(key[:16])
	case "3des":
		return kcp.NewTripleDESBlockCrypt(key[:24])
	case "xtea":
		return kcp.NewXTEABlockCrypt(key[:16])
	case "salsa20":
		return kcp.NewSalsa20BlockCrypt(key)
	case "aes-128-gcm":
		return kcp.NewAESGCMCrypt(key[:16])
	case "aes-192-gcm":
		return kcp.NewAESGCMCrypt(key[:24])
	case "aes-256-gcm":
		return kcp.NewAESGCMCrypt(key)
	case "aes", "":
		return kcp.NewAESBlockCrypt(key)
	default:
		return nil, errors.New("shadowsocks: unsupported kcptun crypt")
	}
}

func configureKCP(conn *kcp.UDPSession, config Config) {
	conn.SetStreamMode(true)
	conn.SetWriteDelay(false)
	conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	conn.SetWindowSize(config.SndWnd, config.RcvWnd)
	_ = conn.SetMtu(config.MTU)
	conn.SetACKNoDelay(config.AckNodelay)
	conn.SetRateLimit(uint32(config.RateLimit))
	_ = conn.SetDSCP(config.DSCP)
	_ = conn.SetReadBuffer(config.SockBuf)
	_ = conn.SetWriteBuffer(config.SockBuf)
}

func smuxConfig(config Config) *smux.Config {
	created := smux.DefaultConfig()
	created.Version = config.SmuxVer
	created.MaxReceiveBuffer = config.SmuxBuf
	created.MaxStreamBuffer = config.StreamBuf
	created.MaxFrameSize = config.FrameSize

	created.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second
	if created.KeepAliveInterval >= created.KeepAliveTimeout {
		created.KeepAliveTimeout = 3 * created.KeepAliveInterval
	}
	return created
}

type kcptunCompConn struct {
	net.Conn
	writer *snappy.Writer
	reader *snappy.Reader
}

func newCompConn(conn net.Conn) net.Conn {
	return &kcptunCompConn{Conn: conn, writer: snappy.NewBufferedWriter(conn), reader: snappy.NewReader(conn)}
}

func (conn *kcptunCompConn) Read(payload []byte) (int, error) { return conn.reader.Read(payload) }

func (conn *kcptunCompConn) Write(payload []byte) (int, error) {
	if _, err := conn.writer.Write(payload); err != nil {
		return 0, err
	}
	if err := conn.writer.Flush(); err != nil {
		return 0, err
	}
	return len(payload), nil
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SagerNet/sing-vmess and Polaris; see THIRD_PARTY_NOTICES.md.
package vless

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"unsafe"

	"github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire/encryption"
	legacy "github.com/metacubex/utls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	reality "github.com/xtls/reality"
)

var visionCarrierRegistry []func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer)

type visionTLSConnection interface {
	VisionTLSConnection() (net.Conn, reflect.Type, unsafe.Pointer)
}

func init() {
	visionCarrierRegistry = append(visionCarrierRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		provider, loaded := conn.(visionTLSConnection)
		if !loaded {
			return false, nil, nil, nil
		}
		netConn, reflectType, reflectPointer = provider.VisionTLSConnection()
		return true, netConn, reflectType, reflectPointer
	})
	visionCarrierRegistry = append(visionCarrierRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		encryptedConn, loaded := conn.(*encryption.CommonConn)
		if !loaded {
			return false, nil, nil, nil
		}
		return true, encryptedConn.Conn, reflect.TypeOf(encryptedConn).Elem(), unsafe.Pointer(encryptedConn)
	})
	visionCarrierRegistry = append(visionCarrierRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer unsafe.Pointer) {
		tlsConn, loaded := N.CastReader[*tls.Conn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), unsafe.Pointer(tlsConn)
	})
	visionCarrierRegistry = append(visionCarrierRegistry, func(conn net.Conn) (bool, net.Conn, reflect.Type, unsafe.Pointer) {
		switch c := conn.(type) {
		case *reality.Conn:
			return true, c.NetConn(), reflect.TypeOf(c).Elem(), unsafe.Pointer(c)
		case *legacy.Conn:
			return true, c.NetConn(), reflect.TypeOf(c).Elem(), unsafe.Pointer(c)
		case *legacy.UConn:
			return true, c.NetConn(), reflect.TypeOf(c.Conn).Elem(), unsafe.Pointer(c.Conn)
		default:
			return false, nil, nil, nil
		}
	})
}

const xrayChunkSize = 8192

type VisionConn struct {
	net.Conn
	reader       *bufio.ChunkReader
	writer       N.VectorisedWriter
	writeAccess  sync.Mutex
	filterAccess sync.Mutex
	input        *bytes.Reader
	rawInput     *bytes.Buffer
	rawInputRef  **bytes.Buffer
	netConn      net.Conn
	logger       logger.Logger

	userUUID               [16]byte
	isTLS                  bool
	numberOfPacketToFilter int
	isTLS12orAbove         bool
	remainingServerHello   int32
	cipher                 uint16
	enableXTLS             bool
	isPadding              bool
	directWrite            bool
	writeUUID              bool
	withinPaddingBuffers   bool
	remainingContent       int
	remainingPadding       int
	currentCommand         byte
	initialPadding         [21]byte
	initialPaddingLength   int
	initialPaddingChecked  bool
	paddingHeader          [5]byte
	paddingHeaderLength    int
	directRead             bool
	remainingBuffers       []*buf.Buffer
	readFilter             visionTLSFilter
	writeFilter            visionTLSFilter
}

type visionTLSFilter struct {
	header          [6]byte
	headerLength    int
	prefix          [78]byte
	prefixLength    int
	recordRemaining int
	versionMatch    int
	serverHello     bool
	stopped         bool
}

func NewVisionConn(conn net.Conn, carrierConn net.Conn, userUUID [16]byte, logger logger.Logger) (*VisionConn, error) {
	var (
		loaded         bool
		reflectType    reflect.Type
		reflectPointer unsafe.Pointer
		netConn        net.Conn
	)
	// Only explicit record carriers may be unwrapped. HTTP stream framing and
	// encryption must remain intact when Vision switches to direct mode.
	if provider, ok := carrierConn.(interface{ TLSRecordConn() net.Conn }); ok {
		carrierConn = provider.TLSRecordConn()
	}
	for _, carrierCreator := range visionCarrierRegistry {
		loaded, netConn, reflectType, reflectPointer = carrierCreator(carrierConn)
		if loaded {
			break
		}
	}
	if !loaded {
		return nil, E.New("vision: not a valid supported carrier connection: ", reflect.TypeOf(carrierConn))
	}
	input, inputLoaded := reflectType.FieldByName("input")
	rawInput, rawInputLoaded := reflectType.FieldByName("rawInput")
	if !inputLoaded || !rawInputLoaded || input.Type != reflect.TypeOf(bytes.Reader{}) || (rawInput.Type != reflect.TypeOf(bytes.Buffer{}) && rawInput.Type != reflect.TypeOf((*bytes.Buffer)(nil))) {
		return nil, E.New("vision: incompatible TLS connection layout: ", reflectType)
	}
	var buffer *bytes.Buffer
	var bufferRef **bytes.Buffer
	if rawInput.Type == reflect.TypeOf(bytes.Buffer{}) {
		buffer = (*bytes.Buffer)(unsafe.Add(reflectPointer, rawInput.Offset))
	} else {
		// Newer REALITY record layers replace/return this buffer to a pool.
		// Keep the slot, not a snapshot of its current pointer.
		bufferRef = (**bytes.Buffer)(unsafe.Add(reflectPointer, rawInput.Offset))
	}
	return &VisionConn{
		rawInputRef: bufferRef,
		Conn:        conn,
		reader:      bufio.NewChunkReader(conn, xrayChunkSize),
		writer:      bufio.NewVectorisedWriter(conn),
		input:       (*bytes.Reader)(unsafe.Add(reflectPointer, input.Offset)),
		rawInput:    buffer,
		netConn:     netConn,
		logger:      logger,

		userUUID:               userUUID,
		numberOfPacketToFilter: 8,
		remainingServerHello:   -1,
		isPadding:              true,
		writeUUID:              true,
		withinPaddingBuffers:   true,
		remainingContent:       -1,
		remainingPadding:       -1,
	}, nil
}

func (c *VisionConn) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		for len(c.remainingBuffers) > 0 {
			newN, _ := c.remainingBuffers[0].Read(p[n:])
			if c.remainingBuffers[0].IsEmpty() {
				c.remainingBuffers[0].Release()
				c.remainingBuffers = c.remainingBuffers[1:]
			}
			n += newN
			if n == len(p) {
				return n, nil
			}
		}
		if n > 0 {
			return n, nil
		}
		if c.directRead {
			return c.netConn.Read(p)
		}

		var bufferBytes []byte
		var chunkBuffer *buf.Buffer
		if len(p) > xrayChunkSize {
			n, err = c.Conn.Read(p)
			if err != nil {
				return n, err
			}
			bufferBytes = p[:n]
		} else {
			chunkBuffer, err = c.reader.ReadChunk()
			if err != nil {
				return 0, err
			}
			bufferBytes = chunkBuffer.Bytes()
		}
		if c.withinPaddingBuffers {
			buffers := c.unPadding(bufferBytes)
			n = 0
			if chunkBuffer != nil {
				chunkBuffer.Reset()
			}
			if c.remainingContent == 0 && c.remainingPadding == 0 {
				switch c.currentCommand {
				case commandPaddingEnd:
					c.withinPaddingBuffers = false
					c.remainingContent = -1
					c.remainingPadding = -1
				case commandPaddingDirect:
					c.withinPaddingBuffers = false
					c.directRead = true
					inputBuffer, readErr := readBuffered(c.input, c.input.Len())
					if readErr != nil {
						buf.ReleaseMulti(buffers)
						return 0, readErr
					}
					if inputBuffer != nil {
						buffers = append(buffers, inputBuffer)
					}
					rawInput := c.rawInput
					if c.rawInputRef != nil {
						rawInput = *c.rawInputRef
					}
					var rawInputBuffer *buf.Buffer
					if rawInput != nil {
						rawInputBuffer, readErr = readBuffered(rawInput, rawInput.Len())
					}
					if readErr != nil {
						buf.ReleaseMulti(buffers)
						return 0, readErr
					}
					if rawInputBuffer != nil {
						buffers = append(buffers, rawInputBuffer)
					}
					c.logger.Trace("XtlsRead readV")
				case commandPaddingContinue:
					c.withinPaddingBuffers = true
				default:
					return 0, E.New("unknown command ", c.currentCommand)
				}
			} else if c.remainingContent > 0 || c.remainingPadding > 0 {
				c.withinPaddingBuffers = true
			} else if c.initialPaddingChecked {
				c.withinPaddingBuffers = false
			}
			c.filterTLSRead(buf.ToSliceMulti(buffers))
			c.remainingBuffers = buffers
			continue
		}

		c.filterTLSRead([][]byte{bufferBytes})
		if chunkBuffer != nil {
			c.remainingBuffers = append(c.remainingBuffers, buf.As(chunkBuffer.Bytes()))
			chunkBuffer.Reset() // keep the chunk storage alive until remainingBuffers is drained
			continue
		}
		return n, nil
	}
}

func (c *VisionConn) Write(p []byte) (n int, err error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	filterState := c.filterTLS([][]byte{p})
	if c.isPadding {
		inputLen := len(p)
		buffers := reshapeBuffer(p)
		var specIndex int
		for i, buffer := range buffers {
			if filterState.isTLS && buffer.Len() > 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) {
				var command byte = commandPaddingEnd
				if filterState.enableXTLS {
					c.directWrite = true
					specIndex = i
					command = commandPaddingDirect
				}
				c.isPadding = false
				buffers[i] = c.padding(buffer, command, filterState.isTLS)
				break
			} else if !filterState.isTLS12orAbove && filterState.remainingPackets <= 1 {
				c.isPadding = false
				buffers[i] = c.padding(buffer, commandPaddingEnd, filterState.isTLS)
				break
			}
			buffers[i] = c.padding(buffer, commandPaddingContinue, filterState.isTLS)
		}
		if c.directWrite {
			encryptedBuffer := buffers[:specIndex+1]
			encryptedLength := buf.LenMulti(encryptedBuffer)
			err = c.writer.WriteVectorised(encryptedBuffer)
			if err != nil {
				return
			}
			buffers = buffers[specIndex+1:]
			c.writer = bufio.NewVectorisedWriter(c.netConn)
			if len(buffers) > 0 {
				c.logger.Trace("XtlsWrite writeV ", specIndex, " ", encryptedLength, " ", len(buffers))
			}
		}
		if len(buffers) > 0 {
			err = c.writer.WriteVectorised(buffers)
		}
		if err == nil {
			n = inputLen
		}
		return
	}
	if c.directWrite {
		return c.netConn.Write(p)
	} else {
		return c.Conn.Write(p)
	}
}

type tlsFilterState struct {
	isTLS            bool
	isTLS12orAbove   bool
	enableXTLS       bool
	remainingPackets int
}

func (c *VisionConn) filterTLS(buffers [][]byte) tlsFilterState {
	return c.filterTLSDirection(buffers, &c.writeFilter)
}

func (c *VisionConn) filterTLSRead(buffers [][]byte) tlsFilterState {
	return c.filterTLSDirection(buffers, &c.readFilter)
}

func (c *VisionConn) filterTLSDirection(buffers [][]byte, direction *visionTLSFilter) tlsFilterState {
	c.filterAccess.Lock()
	defer c.filterAccess.Unlock()
	for _, buffer := range buffers {
		if direction.stopped || c.numberOfPacketToFilter <= 0 && !c.isTLS && direction.headerLength == 0 {
			break
		}
		if c.numberOfPacketToFilter > 0 {
			c.numberOfPacketToFilter--
		}
		if c.scanTLSFragment(direction, buffer) {
			break
		}
		if c.numberOfPacketToFilter == 0 {
			c.logger.Trace("XtlsFilterTls stop filtering ", len(buffer))
		}
	}
	return tlsFilterState{
		isTLS: c.isTLS, isTLS12orAbove: c.isTLS12orAbove,
		enableXTLS: c.enableXTLS, remainingPackets: c.numberOfPacketToFilter,
	}
}

func (c *VisionConn) scanTLSFragment(direction *visionTLSFilter, buffer []byte) bool {
	if direction.headerLength < len(direction.header) {
		copied := copy(direction.header[direction.headerLength:], buffer)
		direction.headerLength += copied
		buffer = buffer[copied:]
		if direction.headerLength < len(direction.header) {
			return false
		}
		header := direction.header[:]
		if header[0] != 22 || header[1] != 3 {
			direction.stopped = true
			return false
		}
		c.isTLS = true
		if header[5] != 2 {
			if header[5] == 1 {
				c.logger.Trace("XtlsFilterTls found tls client hello")
			}
			direction.stopped = true
			return false
		}
		if header[2] != 3 {
			direction.stopped = true
			return false
		}
		direction.serverHello = true
		direction.recordRemaining = int(header[3])<<8 | int(header[4])
		if direction.recordRemaining < 1 {
			direction.stopped = true
			return false
		}
		direction.recordRemaining--
		copy(direction.prefix[:], header)
		direction.prefixLength = len(header)
		c.isTLS12orAbove = true
		c.remainingServerHello = int32(direction.recordRemaining)
		if c.scanTLS13Version(direction, header) {
			return c.finishTLS13(direction)
		}
	}
	if !direction.serverHello {
		return false
	}
	if len(buffer) > direction.recordRemaining {
		buffer = buffer[:direction.recordRemaining]
	}
	if direction.prefixLength < len(direction.prefix) {
		copied := copy(direction.prefix[direction.prefixLength:], buffer)
		direction.prefixLength += copied
		c.parseVisionCipher(direction)
	}
	direction.recordRemaining -= len(buffer)
	c.remainingServerHello = int32(direction.recordRemaining)
	if c.scanTLS13Version(direction, buffer) {
		return c.finishTLS13(direction)
	}
	if direction.recordRemaining == 0 {
		direction.stopped = true
		c.numberOfPacketToFilter = 0
		c.logger.Trace("XtlsFilterTls found tls 1.2")
		return true
	}
	return false
}

func (c *VisionConn) parseVisionCipher(direction *visionTLSFilter) {
	if c.cipher != 0 || direction.prefixLength < 44 {
		return
	}
	sessionIDLength := int(direction.prefix[43])
	cipherStart := 44 + sessionIDLength
	cipherEnd := cipherStart + 2
	if sessionIDLength > 32 {
		direction.stopped = true
		c.logger.Trace("XtlsFilterTls invalid server hello session id length ", sessionIDLength)
		return
	}
	if cipherEnd <= direction.prefixLength {
		c.cipher = uint16(direction.prefix[cipherStart])<<8 | uint16(direction.prefix[cipherStart+1])
	}
}

func (c *VisionConn) scanTLS13Version(direction *visionTLSFilter, buffer []byte) bool {
	for _, value := range buffer {
		if value == tls13SupportedVersions[direction.versionMatch] {
			direction.versionMatch++
			if direction.versionMatch == len(tls13SupportedVersions) {
				return true
			}
		} else if value == tls13SupportedVersions[0] {
			direction.versionMatch = 1
		} else {
			direction.versionMatch = 0
		}
	}
	return false
}

func (c *VisionConn) finishTLS13(direction *visionTLSFilter) bool {
	c.parseVisionCipher(direction)
	switch c.cipher {
	case 0x1301, 0x1302, 0x1303, 0x1304:
		c.enableXTLS = true
	}
	direction.stopped = true
	c.numberOfPacketToFilter = 0
	c.logger.Trace("XtlsFilterTls found tls 1.3! ", c.cipher, " ", c.enableXTLS)
	return true
}

func (c *VisionConn) padding(buffer *buf.Buffer, command byte, isTLS bool) *buf.Buffer {
	contentLen := 0
	paddingLen := 0
	if buffer != nil {
		contentLen = buffer.Len()
	}
	if contentLen < 900 && isTLS {
		paddingLen = common.Must1(visionRandom(500)) + 900 - contentLen
	} else {
		paddingLen = common.Must1(visionRandom(256))
	}
	var bufferLen int
	if c.writeUUID {
		bufferLen += 16
	}
	bufferLen += 5
	if buffer != nil {
		bufferLen += buffer.Len()
	}
	bufferLen += paddingLen
	newBuffer := buf.NewSize(bufferLen)
	if c.writeUUID {
		common.Must1(newBuffer.Write(c.userUUID[:]))
		c.writeUUID = false
	}
	common.Must1(newBuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)}))
	if buffer != nil {
		common.Must1(newBuffer.Write(buffer.Bytes()))
		buffer.Release()
	}
	newBuffer.Extend(paddingLen)
	c.logger.Trace("XtlsPadding ", contentLen, " ", paddingLen, " ", command)
	return newBuffer
}

func readBuffered(reader io.Reader, size int) (*buf.Buffer, error) {
	if size == 0 {
		return nil, nil
	}
	buffer := buf.NewSize(size)
	if _, err := buffer.ReadFullFrom(reader, size); err != nil {
		buffer.Release()
		return nil, err
	}
	return buffer, nil
}

func (c *VisionConn) unPadding(buffer []byte) []*buf.Buffer {
	var bufferIndex int
	if !c.initialPaddingChecked {
		copyLength := minimum(len(c.initialPadding)-c.initialPaddingLength, len(buffer))
		copy(c.initialPadding[c.initialPaddingLength:], buffer[:copyLength])
		c.initialPaddingLength += copyLength
		bufferIndex += copyLength
		if c.initialPaddingLength < len(c.initialPadding) {
			return nil
		}
		c.initialPaddingChecked = true
		if bytes.Equal(c.userUUID[:], c.initialPadding[:16]) {
			c.currentCommand = c.initialPadding[16]
			c.remainingContent = int(c.initialPadding[17])<<8 | int(c.initialPadding[18])
			c.remainingPadding = int(c.initialPadding[19])<<8 | int(c.initialPadding[20])
		} else {
			buffers := []*buf.Buffer{buf.As(c.initialPadding[:]).ToOwned()}
			if bufferIndex < len(buffer) {
				buffers = append(buffers, buf.As(buffer[bufferIndex:]).ToOwned())
			}
			return buffers
		}
	}
	if c.remainingContent == -1 && c.remainingPadding == -1 {
		return []*buf.Buffer{buf.As(buffer).ToOwned()}
	}
	var buffers []*buf.Buffer
	for bufferIndex < len(buffer) {
		if c.remainingContent <= 0 && c.remainingPadding <= 0 {
			if c.currentCommand == commandPaddingEnd {
				buffers = append(buffers, buf.As(buffer[bufferIndex:]).ToOwned())
				break
			} else {
				copyLength := minimum(len(c.paddingHeader)-c.paddingHeaderLength, len(buffer)-bufferIndex)
				copy(c.paddingHeader[c.paddingHeaderLength:], buffer[bufferIndex:bufferIndex+copyLength])
				c.paddingHeaderLength += copyLength
				bufferIndex += copyLength
				if c.paddingHeaderLength < len(c.paddingHeader) {
					break
				}
				c.currentCommand = c.paddingHeader[0]
				c.remainingContent = int(c.paddingHeader[1])<<8 | int(c.paddingHeader[2])
				c.remainingPadding = int(c.paddingHeader[3])<<8 | int(c.paddingHeader[4])
				c.paddingHeaderLength = 0
				c.logger.Trace("Xtls Unpadding new block ", bufferIndex, " ", c.remainingContent, " padding ", c.remainingPadding, " ", c.currentCommand)
			}
		} else if c.remainingContent > 0 {
			end := c.remainingContent
			if end > len(buffer)-bufferIndex {
				end = len(buffer) - bufferIndex
			}
			buffers = append(buffers, buf.As(buffer[bufferIndex:bufferIndex+end]).ToOwned())
			c.remainingContent -= end
			bufferIndex += end
		} else {
			end := c.remainingPadding
			if end > len(buffer)-bufferIndex {
				end = len(buffer) - bufferIndex
			}
			c.remainingPadding -= end
			bufferIndex += end
		}
		if bufferIndex == len(buffer) {
			break
		}
	}
	return buffers
}

func minimum(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func (c *VisionConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *VisionConn) Upstream() any {
	return c.Conn
}

func visionRandom(n int64) (int, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0, err
	}
	return int(value.Int64()), nil
}

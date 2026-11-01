// Derived from XTLS/Xray-core transport/internet/splithttp/hub.go at b17a88f9b46d.
// Licensed under MPL-2.0; see LICENSES/MPL-2.0/MPL-2.0.txt.

package xhttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (server *Server) serveUpload(
	writer http.ResponseWriter,
	request *http.Request,
	session *serverSession,
	sequence string,
	parsedSequence uint64,
) {
	if sequence == "" {
		server.serveStreamUpload(writer, request, session)
		return
	}
	if !oneOf(server.config.Mode, ModeAuto, ModePacketUp) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	if server.config.PendingTimeout > 0 {
		controller := http.NewResponseController(writer)
		_ = controller.SetReadDeadline(time.Now().Add(server.config.PendingTimeout))
		defer controller.SetReadDeadline(time.Time{})
	}
	packet, err := server.readPacketPayload(request, session.upload, parsedSequence)
	if err != nil {
		switch {
		case errors.Is(err, io.ErrShortBuffer), errors.Is(err, errUploadPostTooLarge):
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
		case errors.Is(err, errUploadBufferStall):
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusServiceUnavailable)
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			writer.WriteHeader(http.StatusRequestTimeout)
		default:
			writer.WriteHeader(http.StatusBadRequest)
		}
		return
	}
	if err = session.upload.push(request.Context(), packet); err != nil {
		session.upload.releasePayload(packet.owner)
		if errors.Is(err, io.ErrClosedPipe) {
			writer.WriteHeader(http.StatusConflict)
		} else {
			writer.WriteHeader(http.StatusInternalServerError)
		}
		return
	}
	if len(packet.payload) == 0 {
		writer.Header().Set("Cache-Control", "no-store")
	}
	writer.WriteHeader(http.StatusOK)
}

func (server *Server) serveStreamUpload(writer http.ResponseWriter, request *http.Request, session *serverSession) {
	if !oneOf(server.config.Mode, ModeAuto, ModeStreamUp) {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	stream := newServerStream(request.Body, flushWriter{ResponseWriter: writer, Flusher: flusher})
	if err := session.upload.push(request.Context(), uploadPacket{reader: stream}); err != nil {
		writer.WriteHeader(http.StatusConflict)
		return
	}
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	if request.Header.Get("Referer") != "" || server.config.XPaddingObfsMode {
		server.requests.Add(1)
		go func() { defer server.requests.Done(); server.streamUploadKeepalive(stream) }()
	}
	select {
	case <-request.Context().Done():
	case <-stream.wait():
	case <-server.closed:
	}
	_ = stream.Close()
}

func (server *Server) streamUploadKeepalive(stream *serverStream) {
	if server.config.ScStreamUpServerSecs.To <= 0 {
		return
	}
	for {
		timer := time.NewTimer(time.Duration(server.config.ScStreamUpServerSecs.random()) * time.Second)
		select {
		case <-timer.C:
		case <-stream.wait():
			timer.Stop()
			return
		case <-server.closed:
			timer.Stop()
			return
		}
		if _, err := stream.Write(bytes.Repeat([]byte{'X'}, server.config.XPaddingBytes.random())); err != nil {
			return
		}
	}
}

func (server *Server) readPacketPayload(
	request *http.Request,
	queue *uploadQueue,
	sequence uint64,
) (uploadPacket, error) {
	placement := server.config.UplinkDataPlacement
	var headerEncoded, cookieEncoded string
	if oneOf(placement, PlacementAuto, PlacementHeader) {
		headerEncoded = server.headerPayloadEncoded(request)
	}
	if oneOf(placement, PlacementAuto, PlacementCookie) {
		cookieEncoded = server.cookiePayloadEncoded(request)
	}
	headerSize := base64.RawURLEncoding.DecodedLen(len(headerEncoded))
	cookieSize := base64.RawURLEncoding.DecodedLen(len(cookieEncoded))
	limit := int64(server.config.ScMaxEachPostBytes.To)
	bodySize := int64(0)
	unknownBody := false
	if oneOf(placement, PlacementAuto, PlacementBody) {
		if request.ContentLength > limit {
			return uploadPacket{}, io.ErrShortBuffer
		}
		if request.ContentLength < 0 {
			unknownBody = true
			bodySize = limit - int64(headerSize+cookieSize)
		} else {
			bodySize = request.ContentLength
		}
	}
	upper := int64(headerSize+cookieSize) + bodySize
	if bodySize < 0 || upper < 0 || upper > limit {
		return uploadPacket{}, io.ErrShortBuffer
	}
	packet, err := queue.reservePacket(request.Context(), sequence, upper)
	if err != nil {
		return uploadPacket{}, err
	}
	owner := queue.takePayload(int(upper))
	payload := owner.data
	fail := func(err error) (uploadPacket, error) {
		queue.releaseReservation(packet.reserved)
		queue.releasePayload(owner)
		return uploadPacket{}, err
	}
	offset, err := decodePayload(payload, headerEncoded)
	if err != nil {
		return fail(err)
	}
	decoded, err := decodePayload(payload[offset:], cookieEncoded)
	if err != nil {
		return fail(err)
	}
	offset += decoded
	if oneOf(placement, PlacementAuto, PlacementBody) {
		if unknownBody {
			decoded, err = readUnknownBody(request.Body, payload[offset:])
		} else {
			decoded, err = io.ReadFull(request.Body, payload[offset:])
		}
		if err != nil {
			return fail(err)
		}
		offset += decoded
	}
	queue.shrinkReservation(&packet, int64(offset))
	packet.payload = payload[:offset]
	packet.owner = owner
	return packet, nil
}

func decodePayload(destination []byte, encoded string) (int, error) {
	if encoded == "" {
		return 0, nil
	}
	return base64.RawURLEncoding.Decode(destination, []byte(encoded))
}

func readUnknownBody(body io.Reader, destination []byte) (int, error) {
	n, err := io.ReadFull(body, destination)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return n, nil
	}
	if err != nil {
		return n, err
	}
	var extra [1]byte
	if _, err = io.ReadFull(body, extra[:]); errors.Is(err, io.EOF) {
		return n, nil
	} else if err != nil {
		return n, err
	}
	return n, io.ErrShortBuffer
}

func (server *Server) headerPayloadEncoded(request *http.Request) string {
	var chunks []string
	for index := 0; ; index++ {
		value := request.Header.Get(fmt.Sprintf("%s-%d", server.config.UplinkDataKey, index))
		if value == "" {
			break
		}
		chunks = append(chunks, value)
	}
	return strings.Join(chunks, "")
}

func (server *Server) cookiePayloadEncoded(request *http.Request) string {
	var chunks []string
	for index := 0; ; index++ {
		cookie, _ := request.Cookie(fmt.Sprintf("%s_%d", server.config.UplinkDataKey, index))
		if cookie == nil {
			break
		}
		chunks = append(chunks, cookie.Value)
	}
	return strings.Join(chunks, "")
}

type flushWriter struct {
	http.ResponseWriter
	http.Flusher
}

func (w flushWriter) Abort() {
	controller := http.NewResponseController(w.ResponseWriter)
	_ = controller.SetReadDeadline(time.Now())
	_ = controller.SetWriteDeadline(time.Now())
}

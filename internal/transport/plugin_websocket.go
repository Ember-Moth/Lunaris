// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"

	carrier "github.com/Ember-Moth/Lunaris/internal/transport/ssplugin/websocket"
	"github.com/coder/websocket"
)

func pluginWebsocketUpgrade(config carrier.Config) func(*socketServer, http.ResponseWriter, *http.Request) {
	return func(s *socketServer, w http.ResponseWriter, r *http.Request) {
		for name, value := range config.Headers {
			if r.Header.Get(name) != value {
				http.NotFound(w, r)
				return
			}
		}
		if config.HTTPUpgrade {
			httpUpgrade(s, w, r)
			return
		}
		var early []byte
		if config.MaxEarlyData > 0 {
			encoded := r.Header.Get(config.EarlyDataHeader)
			if len(encoded) > base64.RawURLEncoding.EncodedLen(config.MaxEarlyData) {
				http.Error(w, "invalid early data", 400)
				return
			}
			var err error
			early, err = base64.RawURLEncoding.Strict().DecodeString(encoded)
			if err != nil || len(early) > config.MaxEarlyData {
				http.Error(w, "invalid early data", 400)
				return
			}
			// Early bytes are protocol data rather than a negotiated WebSocket subprotocol.
			r.Header.Del(config.EarlyDataHeader)
		} else if r.Header.Get("Sec-WebSocket-Protocol") != "" {
			http.Error(w, "early data is disabled", 400)
			return
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer ws.CloseNow()
		conn := websocket.NetConn(s.ctx, ws, websocket.MessageBinary)
		ws.SetReadLimit(1 << 20)
		if len(early) > 0 {
			conn = &pluginReplayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(early), conn)}
		}
		s.serve(r.Context(), conn)
	}
}

type pluginReplayConn struct {
	net.Conn
	reader io.Reader
}

func (c *pluginReplayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

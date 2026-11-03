// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
	"github.com/Ember-Moth/Lunaris/internal/model"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestReportedSourceReachesProtocolWithoutHeaderBytes(t *testing.T) {
	observed := make(chan [2]string, 1)
	r := ResolvedSpec{Address: "127.0.0.1", Network: []string{"tcp"}, Limits: model.DefaultLimits()}
	instance, err := (TCPFactory{}).Build(r, Binding{Stream: &StreamHandler{Serve: func(ctx context.Context, c net.Conn, source M.Socksaddr, close N.CloseHandlerFunc) error {
		var payload [4]byte
		if _, err := io.ReadFull(c, payload[:]); err != nil {
			return err
		}
		if string(payload[:]) != "auth" {
			return io.ErrUnexpectedEOF
		}
		local, _ := ingress.LocalIP(ctx)
		observed <- [2]string{source.String(), local.String()}
		close(nil)
		return nil
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := instance.Stop(ctx); err != nil {
			t.Error(err)
		}
	}()
	c, err := net.Dial("tcp", instance.(interface{ Addr() net.Addr }).Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "PROXY TCP4 198.18.0.10 198.19.0.20 12345 443\r\nauth")
	select {
	case value := <-observed:
		if value != [2]string{"198.18.0.10:12345", "198.19.0.20"} {
			t.Fatal("protocol did not receive reported endpoints", value)
		}
	case <-time.After(time.Second):
		t.Fatal("protocol did not receive application payload")
	}
}

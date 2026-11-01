// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/testutil"
	Q "github.com/sagernet/quic-go"
)

func TestHTTP3UnauthenticatedConnectionExpires(t *testing.T) {
	cert, clientTLS := testutil.Certificate(t)
	limits := model.DefaultLimits()
	limits.HandshakeTimeout = 60 * time.Millisecond
	limits.MaxConnections = 1
	instance, err := (QUICFactory{}).Build(ResolvedSpec{Address: "127.0.0.1", Limits: limits, Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}, Binding{HTTP: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = instance.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer instance.Stop(context.Background())
	clientTLS.NextProtos = []string{"h3"}
	c, err := Q.DialAddr(ctx, instance.(interface{ Addr() net.Addr }).Addr().String(), clientTLS, &Q.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseWithError(0, "")
	select {
	case <-c.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("unauthenticated HTTP/3 connection retained its slot")
	}
}

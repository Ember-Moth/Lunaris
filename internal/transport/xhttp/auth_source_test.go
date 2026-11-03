// SPDX-License-Identifier: GPL-3.0-only
package xhttp

import (
	"context"
	"net"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/ingress"
)

func TestRequestFlowKeepsPhysicalAuthenticationPeer(t *testing.T) {
	server := &Server{ctx: context.Background()}
	request := httptest.NewRequest("POST", "http://localhost/proxy", nil)
	request.RemoteAddr = "127.0.0.9:1234"
	physical := netip.MustParseAddr("127.0.0.2")
	request = request.WithContext(ingress.WithPeerIP(request.Context(), physical))
	ctx, _ := server.requestFlow(request)
	if actual := ingress.PeerIP(ctx, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 9)}); actual != physical {
		t.Fatal("PROXY address replaced physical peer", actual)
	}
}

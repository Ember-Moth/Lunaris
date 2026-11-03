// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

func TestOutboundRotationPlansDisconnectsAndLabelsKeepConnections(t *testing.T) {
	runtime := startFake(t, &scriptedFactory{})
	candidate := fakeConfig()
	candidate.Credentials["outbound-key"] = []byte("old-password")
	candidate.Config.Outbounds = []model.OutboundSpec{{ID: "proxy", Protocol: "socks5", Address: "127.0.0.1", Port: 1080, CredentialRef: "outbound-key", Options: []byte(`{"username":"alice"}`)}}
	candidate.Config.Route = &model.RouteConfig{Final: "proxy"}
	if _, err := runtime.Apply(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Config.Outbounds[0].Name = "new label"
	plan, err := runtime.Plan(candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if change.Action != "keep" {
			t.Fatal("label changed running sockets", plan)
		}
	}
	candidate.Credentials["outbound-key"] = []byte("rotated-password")
	plan, err = runtime.Plan(candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if change.Action != "replace" || !change.ClosesConnections {
			t.Fatal("outbound-only secret rotation did not revoke sessions", plan)
		}
	}
	if _, err := runtime.Apply(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Config.Outbounds = nil
	if _, err := runtime.Apply(context.Background(), candidate); err == nil {
		t.Fatal("missing outbound published")
	}
	if len(runtime.config.Config.Outbounds) != 1 {
		t.Fatal("invalid candidate replaced active outbound")
	}
}

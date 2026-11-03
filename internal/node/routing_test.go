// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"context"
	"errors"
	"testing"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/route"
)

func TestGlobalRoutingPlanRollbackAndResolverContext(t *testing.T) {
	sawResolver := false
	factory := &scriptedFactory{start: func(ctx context.Context, spec model.ListenerSpec, n int) error {
		if spec.ID == "a" && n == 2 {
			sawResolver = route.NameResolverFromContext(ctx) != nil
			return errors.New("injected new listener failure")
		}
		if spec.ID == "a" && n == 3 && route.NameResolverFromContext(ctx) != nil {
			return errors.New("rollback retained candidate DNS resolver")
		}
		return nil
	}}
	runtime := startFake(t, factory)
	candidate := fakeConfig()
	candidate.Config.Route = &model.RouteConfig{Block: []string{"suffix:blocked.test"}}
	plan, err := runtime.Plan(candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if change.Action != "replace" || !change.ClosesConnections {
			t.Fatal("global routing change was absent from impact", plan)
		}
	}
	result, err := runtime.Apply(context.Background(), candidate)
	if err == nil || result.Outcome != "rolled_back" || !sawResolver {
		t.Fatal("candidate resolver or rollback missing", result, err, sawResolver)
	}
	if runtime.config.Config.Route != nil || runtime.Snapshot().Degraded {
		t.Fatal("failed routing change became active")
	}
	result, err = runtime.Apply(context.Background(), candidate)
	if err != nil || result.Outcome != "applied" {
		t.Fatal(result, err)
	}
	next := fakeConfig()
	next.Config.Route = candidate.Config.Route
	next.Config.DNS = &model.DNSConfig{Strategy: "only_ipv6"}
	plan, err = runtime.Plan(next)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range plan.Changes {
		if change.Action != "replace" || !change.ClosesConnections {
			t.Fatal("DNS change did not replace generation", plan)
		}
	}
	invalid := fakeConfig()
	invalid.Config.Route = &model.RouteConfig{Block: []string{"regex:("}}
	if _, err := runtime.Apply(context.Background(), invalid); err == nil {
		t.Fatal("invalid route published")
	}
	if runtime.config.Config.Route.Block[0] != "suffix:blocked.test" {
		t.Fatal("invalid policy changed active state")
	}
}

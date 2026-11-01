// SPDX-License-Identifier: GPL-3.0-only
package builtin_test

import (
	"context"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"testing"
	"time"
)

func TestMieruManagedSocketStop(t *testing.T) {
	for _, networks := range [][]string{{"tcp"}, {"udp"}, {"tcp", "udp"}} {
		t.Run(networks[0]+string(rune('0'+len(networks))), func(t *testing.T) {
			s := startConfigured(t, "mieru", "native", false, model.DefaultLimits(), func(spec *model.ListenerSpec) {
				spec.Network = networks
				spec.Options = []byte(`{"users":[{"username":"alice","credential_ref":"one"},{"username":"bob","credential_ref":"two"}]}`)
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := s.instance.Stop(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

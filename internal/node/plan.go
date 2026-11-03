// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

type Change struct {
	ID                string `json:"id"`
	Action            string `json:"action"`
	ClosesConnections bool   `json:"closes_connections"`
}

type Plan struct {
	BaseRevision   uint64   `json:"base_revision"`
	RuntimeEpoch   uint64   `json:"runtime_epoch"`
	ContentChanged bool     `json:"content_changed"`
	Changes        []Change `json:"changes"`
}

func (p Plan) changesRuntime() bool {
	for _, change := range p.Changes {
		if change.Action != "keep" {
			return true
		}
	}
	return false
}

// fingerprint is keyed per boot so publishing a status digest does not create
// an offline password oracle. Labels and shutdown policy do not affect a socket.
func (r *Runtime) fingerprint(snapshot *model.RuntimeConfig, spec model.ListenerSpec) string {
	spec.Name = ""
	limits := snapshot.Config.Limits
	limits.ShutdownTimeout = 0
	credentials := make(map[string][]byte, len(spec.CredentialRefs))
	for _, ref := range r.registry.CredentialRefs(spec) {
		credentials[ref] = snapshot.Credentials[ref]
	}
	content, _ := json.Marshal(struct {
		Policy      string
		Spec        model.ListenerSpec
		Limits      model.Limits
		Credentials map[string][]byte
		Certificate []byte
		PrivateKey  []byte
	}{snapshot.PolicyDigest, spec, limits, credentials, snapshot.Certificates[spec.CertificateRef].Certificate, snapshot.Certificates[spec.CertificateRef].PrivateKey})
	mac := hmac.New(sha256.New, r.fingerprintKey[:])
	_, _ = mac.Write(content)
	return hex.EncodeToString(mac.Sum(nil))
}

func specs(snapshot *model.RuntimeConfig) map[string]model.ListenerSpec {
	result := make(map[string]model.ListenerSpec)
	if snapshot != nil {
		for _, spec := range snapshot.Config.Listeners {
			result[spec.ID] = spec
		}
	}
	return result
}

// Plan is advisory. Apply recomputes it under the transition gate; a plan is
// neither a reserved port nor a persisted operation token.
func (r *Runtime) Plan(input *model.RuntimeConfig) (Plan, error) {
	normalized, err := r.registry.Normalize(input)
	if err != nil {
		return Plan{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return Plan{}, ErrClosed
	}
	if r.applying {
		return Plan{}, ErrBusy
	}
	if r.blocked {
		return Plan{}, ErrRecoveryRequired
	}
	return r.planLocked(normalized), nil
}

func (r *Runtime) planLocked(target *model.RuntimeConfig) Plan {
	plan := Plan{BaseRevision: r.revision, RuntimeEpoch: r.epoch, ContentChanged: !reflect.DeepEqual(r.config, target), Changes: make([]Change, 0)}
	previous, next := specs(r.config), specs(target)
	ids := make(map[string]bool)
	for id := range previous {
		ids[id] = true
	}
	for id := range next {
		ids[id] = true
	}
	for id := range r.records {
		ids[id] = true
	}
	for id := range ids {
		old, hadOld := previous[id]
		wanted, exists := next[id]
		rec := r.records[id]
		change := Change{ID: id, Action: "keep"}
		switch {
		case !exists:
			change.Action = "remove"
		case !wanted.Enabled:
			if (hadOld && old.Enabled) || (rec != nil && rec.state != "stopped") {
				change.Action = "disable"
			}
		case rec == nil || rec.state != "running" || rec.ctx.Err() != nil:
			if hadOld && old.Enabled {
				change.Action = "recover"
			} else {
				change.Action = "create"
			}
		case rec.fingerprint != r.fingerprint(target, wanted):
			change.Action = "replace"
		}
		change.ClosesConnections = change.Action != "keep" && rec != nil && rec.state != "stopped"
		plan.Changes = append(plan.Changes, change)
	}
	slices.SortFunc(plan.Changes, func(a, b Change) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return plan
}

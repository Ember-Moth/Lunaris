// SPDX-License-Identifier: GPL-3.0-only
package node

import (
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
)

type ListenerStatus struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Protocol    model.ProtocolType `json:"protocol"`
	Address     string             `json:"address"`
	Port        uint16             `json:"port"`
	Network     []string           `json:"network"`
	Generation  uint64             `json:"generation"`
	SpecDigest  string             `json:"spec_digest"`
	State       string             `json:"state"`
	Provisional bool               `json:"provisional"`
	LastError   string             `json:"last_error,omitempty"`
	ActiveTCP   int                `json:"active_tcp"`
	ActiveUDP   int                `json:"active_udp"`
}

type Status struct {
	BootID            string           `json:"boot_id"`
	Revision          uint64           `json:"revision"`
	RuntimeEpoch      uint64           `json:"runtime_epoch"`
	Applying          bool             `json:"applying"`
	Closed            bool             `json:"closed"`
	Degraded          bool             `json:"degraded"`
	RecoveryRequired  bool             `json:"recovery_required"`
	LastApplyOutcome  string           `json:"last_apply_outcome,omitempty"`
	LastApplyError    string           `json:"last_apply_error,omitempty"`
	Listeners         []ListenerStatus `json:"listeners"`
	RetainedInstances []ListenerStatus `json:"retained_instances"`
}

func view(rec *record) ListenerStatus {
	tcp, udp := rec.relay.Active()
	return ListenerStatus{ID: rec.spec.ID, Name: rec.spec.Name, Protocol: rec.spec.Protocol, Address: rec.spec.Address, Port: rec.spec.Port, Network: slices.Clone(rec.spec.Network), Generation: rec.generation, SpecDigest: rec.fingerprint, State: rec.state, Provisional: rec.provisional, LastError: rec.lastError, ActiveTCP: tcp, ActiveUDP: udp}
}

func (r *Runtime) healthyLocked(snapshot *model.RuntimeConfig) bool {
	if snapshot == nil {
		return len(r.records) == 0
	}
	for _, spec := range snapshot.Config.Listeners {
		if !spec.Enabled {
			continue
		}
		rec := r.records[spec.ID]
		if rec == nil || rec.state != "running" || rec.ctx.Err() != nil || rec.fingerprint != r.fingerprint(snapshot, spec) {
			return false
		}
	}
	return true
}

// Snapshot returns no credentials, mutable runtime maps or shared slices.
func (r *Runtime) Snapshot() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	status := Status{BootID: r.bootID, Revision: r.revision, RuntimeEpoch: r.epoch, Applying: r.applying, Closed: r.closed, RecoveryRequired: r.blocked,
		Degraded: !r.closed && !r.applying && (r.blocked || !r.healthyLocked(r.config)), LastApplyOutcome: r.lastOutcome, LastApplyError: r.lastApplyError,
		Listeners: make([]ListenerStatus, 0), RetainedInstances: make([]ListenerStatus, 0)}
	configured := specs(r.config)
	for id, rec := range r.records {
		entry := view(rec)
		if spec, ok := configured[id]; ok && !rec.provisional {
			entry.Name = spec.Name
		}
		status.Listeners = append(status.Listeners, entry)
		delete(configured, id)
	}
	for _, spec := range configured {
		state := "disabled"
		if spec.Enabled {
			state = "failed"
		}
		status.Listeners = append(status.Listeners, ListenerStatus{ID: spec.ID, Name: spec.Name, Protocol: spec.Protocol, Address: spec.Address, Port: spec.Port, Network: slices.Clone(spec.Network), State: state})
	}
	for rec := range r.owned {
		if r.records[rec.spec.ID] != rec {
			status.RetainedInstances = append(status.RetainedInstances, view(rec))
		}
	}
	slices.SortFunc(status.Listeners, func(a, b ListenerStatus) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	slices.SortFunc(status.RetainedInstances, func(a, b ListenerStatus) int {
		if a.Generation < b.Generation {
			return -1
		}
		if a.Generation > b.Generation {
			return 1
		}
		return 0
	})
	return status
}

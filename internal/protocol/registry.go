// SPDX-License-Identifier: GPL-3.0-only
package protocol

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/transport"
	"github.com/sagernet/sing/common/logger"
)

// RelayHandler is the shared boundary for library-backed and native protocols.
type RelayHandler = transport.RelayHandler

type Capabilities struct {
	Type        model.ProtocolType `json:"type"`
	TCP         bool               `json:"tcp"`
	UDP         bool               `json:"udp"`
	TCPRelay    bool               `json:"tcp_relay"`
	UDPRelay    bool               `json:"udp_relay"`
	TLS         bool               `json:"tls"`
	TLSRequired bool               `json:"tls_required"`
	Transports  []string           `json:"transports,omitempty"`
}

// ResolvedListenerSpec is private to the runtime and must never be JSON encoded.
// Factories receive their own immutable snapshot, including resolved assets.
type ResolvedListenerSpec struct {
	Spec        model.ListenerSpec
	Limits      model.Limits
	Credentials map[string][]byte `json:"-"`
	Certificate []byte            `json:"-"`
	PrivateKey  []byte            `json:"-"`
}

type Dependencies struct {
	Handler RelayHandler
	Logger  logger.ContextLogger
}

type InstanceEvent = transport.InstanceEvent
type Instance = transport.Instance

type Factory interface {
	Capabilities() Capabilities
	Validate(model.ListenerSpec) []model.FieldError
	Build(ResolvedListenerSpec, Dependencies) (transport.Binding, error)
}

// AssetValidator checks resolved secrets before a draft can be saved or applied.
type AssetValidator interface {
	ValidateAssets(ResolvedListenerSpec) error
}

// Registry is constructed once during dependency assembly and is read-only after.
type Registry struct {
	factories map[model.ProtocolType]Factory
}

func NewRegistry(factories ...Factory) (*Registry, error) {
	r := &Registry{factories: make(map[model.ProtocolType]Factory)}
	for _, factory := range factories {
		if factory == nil || (reflect.ValueOf(factory).Kind() == reflect.Pointer && reflect.ValueOf(factory).IsNil()) {
			return nil, fmt.Errorf("nil protocol factory")
		}
		kind := factory.Capabilities().Type
		if kind == "" {
			return nil, fmt.Errorf("protocol type must not be empty")
		}
		if _, exists := r.factories[kind]; exists {
			return nil, fmt.Errorf("duplicate protocol type %q", kind)
		}
		r.factories[kind] = factory
	}
	return r, nil
}

func (r *Registry) Capabilities() []Capabilities {
	result := make([]Capabilities, 0, len(r.factories))
	for _, factory := range r.factories {
		caps := factory.Capabilities()
		caps.Transports = slices.Clone(caps.Transports)
		result = append(result, caps)
	}
	slices.SortFunc(result, func(a, b Capabilities) int {
		if a.Type < b.Type {
			return -1
		}
		if a.Type > b.Type {
			return 1
		}
		return 0
	})
	return result
}

func (r *Registry) Lookup(kind model.ProtocolType) (Factory, bool) {
	factory, found := r.factories[kind]
	return factory, found
}

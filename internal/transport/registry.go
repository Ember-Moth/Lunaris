// SPDX-License-Identifier: GPL-3.0-only
package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"slices"

	"github.com/Ember-Moth/Lunaris/internal/model"
	qtls "github.com/sagernet/sing-quic"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type RelayHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}
type InstanceEvent struct {
	State string
	Err   error
}
type Instance interface {
	Start(context.Context) error
	Events() <-chan InstanceEvent
	Stop(context.Context) error
}

type Capabilities struct {
	Type       string `json:"type"`
	TCP        bool   `json:"tcp"`
	UDP        bool   `json:"udp"`
	TLS        bool   `json:"tls"`
	Secure     bool   `json:"secure"`
	UDPStreams bool   `json:"udp_streams,omitempty"`
}

// ResolvedSpec contains only carrier settings and TLS material, never credentials
// or protocol options. Build must not bind sockets or start goroutines.
type ResolvedSpec struct {
	Address     string
	Port        uint16
	Network     []string
	Transport   model.Transport
	Limits      model.Limits
	Certificate []byte            `json:"-" yaml:"-"`
	PrivateKey  []byte            `json:"-" yaml:"-"`
	Secrets     map[string][]byte `json:"-" yaml:"-"`
}

type AssetFactory interface {
	CredentialRefs(model.ListenerSpec) []string
	ValidateAssets(ResolvedSpec) error
}

// Binding exposes protocol entry points to a transport without selecting a
// transport implementation. Constructors prepare resources; Start activates them.
type Binding struct {
	HTTP   http.Handler
	Stream *StreamHandler
	Packet *PacketHandler
	QUIC   *QUICHandler
}
type StreamHandler struct {
	Serve ServeFunc
	Start func() error
	Close func() error
}
type PacketHandler struct {
	Serve func(context.Context, net.PacketConn) error
	Close func(context.Context) error
}
type QUICService interface {
	Start(net.PacketConn) error
	Close() error
}
type QUICHandler struct {
	NewService      func(context.Context, aTLS.ServerConfig, qtls.QUICOptions) (QUICService, error)
	ALPN            []string
	ReservedStreams int
}

type Factory interface {
	Capabilities() Capabilities
	Validate(model.ListenerSpec) []model.FieldError
	Build(ResolvedSpec, Binding) (Instance, error)
}

// Registry is immutable after construction. Each transport supplies its own
// validator and constructor; adding one does not change a central type switch.
type Registry struct{ factories map[string]Factory }

func NewRegistry(factories ...Factory) (*Registry, error) {
	r := &Registry{factories: make(map[string]Factory)}
	for _, f := range factories {
		if f == nil || (reflect.ValueOf(f).Kind() == reflect.Pointer && reflect.ValueOf(f).IsNil()) {
			return nil, errors.New("nil transport factory")
		}
		c := f.Capabilities()
		if c.Type == "" {
			return nil, errors.New("transport type must not be empty")
		}
		if !c.TCP && !c.UDP {
			return nil, errors.New("transport must support a listening network")
		}
		if _, ok := r.factories[c.Type]; ok {
			return nil, fmt.Errorf("duplicate transport type %q", c.Type)
		}
		r.factories[c.Type] = f
	}
	return r, nil
}
func (r *Registry) Lookup(kind string) (Factory, bool) { f, ok := r.factories[kind]; return f, ok }
func (r *Registry) Capabilities() []Capabilities {
	out := make([]Capabilities, 0, len(r.factories))
	for _, f := range r.factories {
		out = append(out, f.Capabilities())
	}
	slices.SortFunc(out, func(a, b Capabilities) int {
		if a.Type < b.Type {
			return -1
		}
		if a.Type > b.Type {
			return 1
		}
		return 0
	})
	return out
}

// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/config"
	"github.com/Ember-Moth/Lunaris/internal/inbound"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/node"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
)

type Version struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	APISchema string `json:"api_schema"`
	Frontend  string `json:"frontend_build"`
}
type APIOptions struct {
	Repository     ports.ManagementRepository
	Service        *config.Service
	Registry       *inbound.Registry
	Auth           *auth.Service
	Origin         string
	NativeTLS      bool
	TrustedProxies []netip.Prefix
	Version        Version
}
type API struct {
	repo              ports.ManagementRepository
	service           *config.Service
	registry          *inbound.Registry
	auth              *auth.Service
	origin, scheme    string
	secure, nativeTLS bool
	proxies           []netip.Prefix
	requests          chan struct{}
	geoUploads        chan struct{}
	attempts          attemptLimiter
	logs              *Logs
	version           Version
}

func NewAPI(ctx context.Context, o APIOptions) (*API, error) {
	if o.Repository == nil || o.Service == nil || o.Registry == nil || o.Auth == nil {
		return nil, errors.New("management dependencies are required")
	}
	origin, err := config.CanonicalOrigin(o.Origin)
	if err != nil {
		return nil, err
	}
	scheme := originScheme(origin)
	if scheme == "https" && !o.NativeTLS && len(o.TrustedProxies) == 0 || scheme == "http" && (o.NativeTLS || len(o.TrustedProxies) > 0) {
		return nil, errors.New("management transport does not match public origin")
	}
	status, err := o.Service.Status(ctx)
	if err != nil {
		return nil, err
	}
	a := &API{repo: o.Repository, service: o.Service, registry: o.Registry, auth: o.Auth, origin: origin, scheme: scheme, secure: scheme == "https", nativeTLS: o.NativeTLS, proxies: append([]netip.Prefix(nil), o.TrustedProxies...), requests: make(chan struct{}, 32), geoUploads: make(chan struct{}, 1), logs: NewLogs(status.Runtime.BootID), version: o.Version}
	a.logs.Add("info", "management service initialized", "")
	if status.RestoreError != "" {
		a.logs.Add("error", "committed proxy listeners require repair", "")
	}
	return a, nil
}
func (a *API) LogOperation(level, id, status string) {
	a.logs.add(level, "configuration application finished: "+status, "", id)
}

func (a *API) Log(level, message string) { a.logs.Add(level, message, "") }
func (a *API) Register(h *server.Hertz) {
	g := h.Group("/api/v1")
	g.GET("/setup/status", a.setupStatus)
	g.POST("/setup", a.setup)
	g.POST("/auth/login", a.login)
	g.GET("/auth/session", a.session)
	g.POST("/auth/logout", a.logout)
	g.PUT("/auth/password", a.password)
	g.POST("/auth/reauth", a.reauth)
	g.GET("/system/version", a.systemVersion)
	g.GET("/capabilities", a.capabilities)
	g.GET("/status", a.status)
	g.GET("/logs", a.logPage)
	g.GET("/config/draft", a.getDraft)
	g.PUT("/config/draft", a.putDraft)
	g.GET("/config/committed", a.getCommitted)
	g.POST("/config/validate", a.validate)
	g.POST("/config/plans", a.plan)
	g.POST("/config/apply", a.apply)
	g.GET("/operations/:id", a.operation)
	g.GET("/config/revisions", a.revisions)
	g.POST("/config/draft/from-revision", a.fromRevision)
	g.GET("/credentials", a.credentials)
	g.POST("/credentials", a.createCredential)
	g.DELETE("/credentials/:id", a.deleteCredential)
	g.GET("/geodata", a.geodata)
	g.POST("/geodata", a.createGeoData)
	g.DELETE("/geodata/:id", a.deleteGeoData)
	g.GET("/certificates", a.certificates)
	g.POST("/certificates", a.createCertificate)
	g.DELETE("/certificates/:id", a.deleteCertificate)
	g.POST("/listeners/:id/connection-info", a.connectionInfo)
}
func (a *API) fail(c *app.RequestContext, status, code int, message string, data any) {
	if data == nil {
		data = map[string]any{"request_id": string(c.Response.Header.Peek("X-Request-ID"))}
	}
	c.Abort()
	reply(c, status, code, message, data)
}
func (a *API) error(c *app.RequestContext, err error, validation bool) {
	switch {
	case errors.Is(err, auth.ErrAuthentication):
		a.fail(c, 401, 40100, "Authentication failed", nil)
	case errors.Is(err, auth.ErrInitialized):
		a.fail(c, 409, 40900, "Administrator already initialized", nil)
	case errors.Is(err, config.ErrInvalidDraft) || errors.Is(err, ports.ErrInvalidInput):
		a.fail(c, 422, 42200, "Configuration validation failed", map[string]any{"fields": []model.FieldError{{Path: "config", Code: "invalid", Message: "check protocol, routing, DNS, limits, asset references and management endpoint"}}, "request_id": string(c.Response.Header.Peek("X-Request-ID"))})
	case errors.Is(err, auth.ErrInvalidInput):
		a.fail(c, 422, 42200, "Invalid authentication input", nil)
	case errors.Is(err, auth.ErrLimited):
		a.fail(c, 429, 42900, "Authentication is busy", nil)
	case errors.Is(err, ports.ErrBusy) || errors.Is(err, node.ErrBusy):
		check, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		status, _ := a.service.Status(check)
		a.fail(c, 409, 40901, "Operation in progress", map[string]any{"operation_id": status.ActiveOperation, "request_id": string(c.Response.Header.Peek("X-Request-ID"))})
	case errors.Is(err, config.ErrPlanExpired) || errors.Is(err, node.ErrStalePlan):
		a.fail(c, 409, 40902, "Application plan expired or changed", nil)
	case errors.Is(err, ports.ErrIdempotencyConflict):
		a.fail(c, 409, 40903, "Idempotency key conflicts with an earlier request", nil)
	case errors.Is(err, config.ErrDisconnectAcknowledgement):
		a.fail(c, 409, 40904, "Acknowledge affected connections before applying", nil)
	case errors.Is(err, ports.ErrReferenced):
		a.fail(c, 409, 40905, "Asset is referenced by a retained configuration", nil)
	case errors.Is(err, ports.ErrConflict):
		a.fail(c, 409, 40900, "Configuration state changed", nil)
	case errors.Is(err, config.ErrPersistenceUncertain) || errors.Is(err, node.ErrRecoveryRequired) || errors.Is(err, node.ErrClosed):
		a.fail(c, 503, 50300, "Configuration writes are unavailable; inspect node status", nil)
	case errors.Is(err, ports.ErrNotFound) && !validation:
		a.fail(c, 404, 40400, "Resource not found", nil)
	default:
		if validation {
			a.fail(c, 422, 42200, "Configuration or asset validation failed", map[string]any{"fields": []model.FieldError{{Path: "config", Code: "invalid", Message: "check protocol, routing, DNS, limits, references and reserved management endpoint"}}, "request_id": string(c.Response.Header.Peek("X-Request-ID"))})
		} else {
			a.fail(c, 503, 50300, "Management service unavailable", nil)
		}
	}
}
func (a *API) decode(ctx context.Context, c *app.RequestContext, value any, limit int, optional bool) bool {
	body, ok := a.readBody(ctx, c, limit)
	if !ok {
		return false
	}
	if optional && len(bytes.TrimSpace(body)) == 0 {
		return true
	}
	media, _, err := mime.ParseMediaType(string(c.Request.Header.ContentType()))
	if err != nil || media != "application/json" {
		a.fail(c, 415, 41500, "Expected application/json", nil)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(value); err != nil {
		a.fail(c, 400, 40000, "Invalid JSON fields or types", nil)
		return false
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		a.fail(c, 400, 40000, "Expected one JSON document", nil)
		return false
	}
	return true
}
func (a *API) ifMatch(c *app.RequestContext) (string, bool) {
	value := string(c.Request.Header.Peek("If-Match"))
	if value == "" {
		a.fail(c, 428, 42800, "If-Match is required", nil)
		return "", false
	}
	if len(value) < 3 || len(value) > 130 || value[0] != '"' || value[len(value)-1] != '"' || strings.ContainsAny(value[1:len(value)-1], "\"\r\n, ") {
		a.fail(c, 400, 40000, "Expected one strong revision ETag", nil)
		return "", false
	}
	return strings.Clone(value[1 : len(value)-1]), true
}
func (a *API) pagination(c *app.RequestContext) (string, int, bool) {
	args := c.QueryArgs()
	valid := true
	counts := map[string]int{}
	args.VisitAll(func(k, v []byte) {
		counts[string(k)]++
		if string(k) != "cursor" && string(k) != "limit" {
			valid = false
		}
	})
	if !valid || counts["cursor"] > 1 || counts["limit"] > 1 {
		a.fail(c, 400, 40000, "Invalid pagination fields", nil)
		return "", 0, false
	}
	cursor := string(args.Peek("cursor"))
	limit := 50
	if raw := string(args.Peek("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			a.fail(c, 400, 40000, "Limit must be between 1 and 100", nil)
			return "", 0, false
		}
		limit = n
	}
	if len(cursor) > 256 {
		a.fail(c, 400, 40000, "Cursor is too long", nil)
		return "", 0, false
	}
	return cursor, limit, true
}
func (a *API) audit(ctx context.Context, message string) {
	id, _ := ctx.Value(requestIDKey{}).(string)
	a.logs.Add("info", message, id)
}

func (a *API) readBody(ctx context.Context, c *app.RequestContext, limit int) ([]byte, bool) {
	if c.Request.Header.ContentLength() > limit {
		a.fail(c, 413, 41300, "Request body too large", nil)
		return nil, false
	}
	if encoding := string(c.Request.Header.Peek("Content-Encoding")); encoding != "" && encoding != "identity" {
		a.fail(c, 415, 41500, "Content encoding is unsupported", nil)
		return nil, false
	}
	var reader io.Reader
	if c.Request.IsBodyStream() {
		reader = c.RequestBodyStream()
	} else {
		reader = bytes.NewReader(c.Request.Body())
	}
	conn := c.GetConn()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadTimeout(time.Nanosecond); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	body, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if len(body) > limit {
		a.fail(c, 413, 41300, "Request body too large", nil)
		return nil, false
	}
	if err != nil {
		a.fail(c, 400, 40000, "Cannot read request body", nil)
		return nil, false
	}
	return body, true
}

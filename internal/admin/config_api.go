// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/cloudwego/hertz/pkg/app"
)

func newDraftInput() model.DraftInput {
	return model.DraftInput{Config: model.NodeConfig{SchemaVersion: 1, Limits: model.DefaultLimits()}, CredentialAssets: map[string]string{}, CertificateAssets: map[string]string{}}
}
func (a *API) readRevision(ctx context.Context, c *app.RequestContext, draft bool) {
	heads, err := a.repo.Heads(ctx)
	if err != nil {
		a.error(c, err, false)
		return
	}
	id := heads.CommittedRevision
	if draft {
		id = heads.DraftRevision
	}
	revision, err := a.repo.Revision(ctx, id)
	if err != nil {
		a.error(c, err, false)
		return
	}
	c.Header("ETag", "\""+revision.ID+"\"")
	reply(c, 200, 0, "ok", revision)
}
func (a *API) getDraft(ctx context.Context, c *app.RequestContext)     { a.readRevision(ctx, c, true) }
func (a *API) getCommitted(ctx context.Context, c *app.RequestContext) { a.readRevision(ctx, c, false) }
func (a *API) saveDraft(ctx context.Context, c *app.RequestContext, expected string, input model.DraftInput) {
	if !a.validateShape(c, input) {
		return
	}
	saved, err := a.service.SaveManagedDraft(ctx, expected, input)
	if errors.Is(err, ports.ErrConflict) {
		a.fail(c, 412, 41200, "Draft revision changed", nil)
		return
	}
	if err != nil {
		a.error(c, err, false)
		return
	}
	c.Header("ETag", "\""+saved.ID+"\"")
	a.audit(ctx, "configuration draft saved")
	reply(c, 200, 0, "ok", saved)
}
func (a *API) validateShape(c *app.RequestContext, input model.DraftInput) bool {
	if input.Config.Listeners == nil || len(input.Config.Listeners) > 1024 {
		a.fail(c, 422, 42200, "Listeners must be an explicit array with at most 1024 entries", nil)
		return false
	}
	for _, s := range input.Config.Listeners {
		if len(s.ID) > 128 || len(s.Name) > 256 || strings.ContainsAny(s.ID, "/\\\r\n\x00") {
			a.fail(c, 422, 42200, "Invalid listener identifier or label", nil)
			return false
		}
	}
	return true
}
func (a *API) putDraft(ctx context.Context, c *app.RequestContext) {
	expected, ok := a.ifMatch(c)
	if !ok {
		return
	}
	input := newDraftInput()
	if !a.decode(ctx, c, &input, 1<<20, false) {
		return
	}
	a.saveDraft(ctx, c, expected, input)
}
func (a *API) validate(ctx context.Context, c *app.RequestContext) {
	input := newDraftInput()
	if !a.decode(ctx, c, &input, 1<<20, false) || !a.validateShape(c, input) {
		return
	}
	normalized, err := a.service.ValidateDraft(ctx, input)
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", map[string]any{"valid": true, "document": normalized})
}
func (a *API) plan(ctx context.Context, c *app.RequestContext) {
	var request struct {
		Draft string `json:"draft_revision"`
		Base  string `json:"base_revision"`
	}
	if !a.decode(ctx, c, &request, 4096, false) {
		return
	}
	result, err := a.service.CreatePlan(ctx, request.Draft, request.Base)
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", result)
}
func (a *API) apply(ctx context.Context, c *app.RequestContext) {
	var request struct {
		PlanID      string `json:"plan_id"`
		Acknowledge bool   `json:"acknowledge_disconnects"`
	}
	if !a.decode(ctx, c, &request, 4096, false) {
		return
	}
	rawKey := string(c.Request.Header.Peek("Idempotency-Key"))
	if len(rawKey) == 0 || len(rawKey) > 128 || strings.TrimSpace(rawKey) != rawKey || strings.ContainsAny(rawKey, "\r\n\x00") {
		a.fail(c, 400, 40000, "Idempotency-Key must contain 1 to 128 bytes", nil)
		return
	}
	if request.PlanID == "" || len(request.PlanID) > 128 {
		a.fail(c, 422, 42200, "A valid plan_id is required", nil)
		return
	}
	p := principalFrom(ctx)
	sum := sha256.Sum256([]byte(p.account.ID + "\x00POST /api/v1/config/apply\x00" + rawKey))
	key := "http_" + hex.EncodeToString(sum[:])
	operation, err := a.service.AcceptPlan(ctx, key, request.PlanID, request.Acknowledge)
	if err != nil {
		a.error(c, err, false)
		return
	}
	c.Header("Location", "/api/v1/operations/"+operation.ID)
	a.audit(ctx, "configuration application accepted")
	reply(c, 202, 0, "ok", map[string]any{"operation_id": operation.ID, "operation": operationView(operation)})
}
func operationView(op model.ApplyOperation) map[string]any {
	return map[string]any{"id": op.ID, "target_revision": op.TargetRevision, "base_revision": op.BaseRevision, "status": op.Status, "phase": op.Phase, "error": op.Error, "created_at": op.CreatedAt, "updated_at": op.UpdatedAt}
}
func (a *API) operation(ctx context.Context, c *app.RequestContext) {
	op, err := a.service.Operation(ctx, strings.Clone(c.Param("id")))
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", operationView(op))
}
func (a *API) revisions(ctx context.Context, c *app.RequestContext) {
	cursor, limit, ok := a.pagination(c)
	if !ok {
		return
	}
	if len(cursor) > 128 {
		a.fail(c, 400, 40000, "Invalid revision cursor", nil)
		return
	}
	values, next, err := a.repo.RevisionPage(ctx, cursor, limit)
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", map[string]any{"items": values, "next_cursor": next})
}
func (a *API) fromRevision(ctx context.Context, c *app.RequestContext) {
	expected, ok := a.ifMatch(c)
	if !ok {
		return
	}
	var request struct {
		Revision string `json:"revision"`
	}
	if !a.decode(ctx, c, &request, 4096, false) {
		return
	}
	saved, err := a.service.DraftFrom(ctx, expected, request.Revision)
	if errors.Is(err, ports.ErrConflict) {
		a.fail(c, 412, 41200, "Draft revision changed", nil)
		return
	}
	if err != nil {
		a.error(c, err, false)
		return
	}
	c.Header("ETag", "\""+saved.ID+"\"")
	a.audit(ctx, "historical revision copied to draft")
	reply(c, 200, 0, "ok", saved)
}

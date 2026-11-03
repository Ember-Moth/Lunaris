// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"mime"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/model"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/cloudwego/hertz/pkg/app"
)

func (a *API) geodata(ctx context.Context, c *app.RequestContext) {
	cursor, limit, ok := a.pagination(c)
	if !ok {
		return
	}
	items, next, err := a.repo.GeoDataPage(ctx, cursor, limit)
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", map[string]any{"items": items, "next_cursor": next})
}
func (a *API) createGeoData(ctx context.Context, c *app.RequestContext) {
	kind := string(c.QueryArgs().Peek("kind"))
	if kind != "geosite" && kind != "geoip" {
		a.fail(c, 422, 42200, "Expected geosite or geoip", nil)
		return
	}
	media, _, err := mime.ParseMediaType(string(c.Request.Header.ContentType()))
	if err != nil || media != "application/octet-stream" {
		a.fail(c, 415, 41500, "Expected application/octet-stream", nil)
		return
	}
	label := string(c.QueryArgs().Peek("label"))
	valid := true
	counts := map[string]int{}
	c.QueryArgs().VisitAll(func(k, v []byte) {
		key := string(k)
		counts[key]++
		if key != "kind" && key != "label" {
			valid = false
		}
	})
	if !valid || counts["kind"] != 1 || counts["label"] > 1 || len(label) > 256 {
		a.fail(c, 400, 40000, "Invalid geodata query fields", nil)
		return
	}
	select {
	case a.geoUploads <- struct{}{}:
		defer func() { <-a.geoUploads }()
	default:
		a.fail(c, 429, 42900, "Another geodata upload is in progress", nil)
		return
	}
	var asset model.GeoDataAsset
	err = a.service.MutateAsset(ctx, func(ctx context.Context, repo ports.ManagementRepository) error {
		body, ok := a.readBody(ctx, c, model.MaxGeoDataSize)
		if !ok {
			return nil
		}
		var err error
		asset, err = repo.CreateGeoData(ctx, kind, label, body)
		return err
	})
	if c.IsAborted() {
		return
	}
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.audit(ctx, "geodata asset created")
	reply(c, 201, 0, "ok", asset)
}
func (a *API) deleteGeoData(ctx context.Context, c *app.RequestContext) {
	if !a.decode(ctx, c, &struct{}{}, 1024, true) {
		return
	}
	id := strings.Clone(c.Param("id"))
	err := a.service.MutateAsset(ctx, func(ctx context.Context, repo ports.ManagementRepository) error { return repo.DeleteGeoData(ctx, id) })
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.audit(ctx, "unreferenced geodata asset deleted")
	reply(c, 200, 0, "ok", nil)
}

// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"github.com/cloudwego/hertz/pkg/app"
)

func (a *API) setupStatus(ctx context.Context, c *app.RequestContext) {
	needed, err := a.auth.SetupStatus(ctx)
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", map[string]bool{"needs_setup": needed})
}
func (a *API) setup(ctx context.Context, c *app.RequestContext) {
	if !a.authAttempt(ctx, c, "setup") {
		return
	}
	var request struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !a.decode(ctx, c, &request, 4096, false) {
		return
	}
	account, err := a.auth.Initialize(ctx, request.Token, request.Username, request.Password)
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.audit(ctx, "administrator initialized")
	reply(c, 201, 0, "ok", account)
}
func (a *API) login(ctx context.Context, c *app.RequestContext) {
	if !a.authAttempt(ctx, c, "login") {
		return
	}
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !a.decode(ctx, c, &request, 4096, false) {
		return
	}
	token, view, err := a.auth.Login(ctx, request.Username, request.Password)
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.setCookie(c, token, view.ExpiresAt)
	a.audit(ctx, "administrator logged in")
	reply(c, 200, 0, "ok", view)
}
func (a *API) session(ctx context.Context, c *app.RequestContext) {
	p := principalFrom(ctx)
	reply(c, 200, 0, "ok", a.auth.View(p.account, p.session))
}
func (a *API) logout(ctx context.Context, c *app.RequestContext) {
	if !a.decode(ctx, c, &struct{}{}, 1024, true) {
		return
	}
	p := principalFrom(ctx)
	if err := a.auth.Logout(ctx, p.session); err != nil {
		a.error(c, err, false)
		return
	}
	a.setCookie(c, "", p.session.ExpiresAt)
	a.audit(ctx, "administrator logged out")
	reply(c, 200, 0, "ok", nil)
}
func (a *API) password(ctx context.Context, c *app.RequestContext) {
	if !a.authAttempt(ctx, c, "password") {
		return
	}
	var request struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !a.decode(ctx, c, &request, 8192, false) {
		return
	}
	p := principalFrom(ctx)
	if err := a.auth.ChangePassword(ctx, p.account, request.Current, request.New); err != nil {
		a.error(c, err, false)
		return
	}
	a.setCookie(c, "", p.session.ExpiresAt)
	a.audit(ctx, "administrator password changed; all sessions revoked")
	reply(c, 200, 0, "ok", nil)
}
func (a *API) reauth(ctx context.Context, c *app.RequestContext) {
	if !a.authAttempt(ctx, c, "reauth") {
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if !a.decode(ctx, c, &request, 4096, false) {
		return
	}
	p := principalFrom(ctx)
	until, err := a.auth.Reauthenticate(ctx, p.account, p.session, request.Password)
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.audit(ctx, "sensitive access authorized")
	reply(c, 200, 0, "ok", map[string]any{"reauth_until": until})
}

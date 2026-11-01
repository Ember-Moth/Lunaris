// SPDX-License-Identifier: GPL-3.0-only
package admin

import "github.com/cloudwego/hertz/pkg/app"

const (
	CodeOK               = 0
	CodeNotFound         = 40400
	CodeMethodNotAllowed = 40500
	CodeUnavailable      = 50300
)

// Response is the envelope for all application HTTP API responses.
type Response struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

func reply(c *app.RequestContext, status, code int, msg string, data any) {
	c.JSON(status, Response{Code: code, Msg: msg, Data: data})
}

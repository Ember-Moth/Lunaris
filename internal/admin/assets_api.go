// SPDX-License-Identifier: GPL-3.0-only
package admin

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"slices"
	"strings"

	"github.com/Ember-Moth/Lunaris/internal/auth"
	"github.com/Ember-Moth/Lunaris/internal/model"
	"github.com/Ember-Moth/Lunaris/internal/protocol/vless/wire/encryption"
	ports "github.com/Ember-Moth/Lunaris/internal/store"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/gofrs/uuid/v5"
)

var credentialKinds = []string{"generic", "password", "uuid", "ss2022-128", "ss2022-256", "x25519", "vless-encryption"}

func credentialValue(kind string, secret *string, generate bool) ([]byte, error) {
	if !slices.Contains(credentialKinds, kind) || generate == (secret != nil) {
		return nil, errors.New("choose one secret source")
	}
	var value string
	if generate {
		switch kind {
		case "generic", "password":
			value = auth.Token()
		case "uuid":
			id, err := uuid.NewV4()
			if err != nil {
				return nil, err
			}
			value = id.String()
		case "ss2022-128", "ss2022-256":
			size := 32
			if kind == "ss2022-128" {
				size = 16
			}
			b := make([]byte, size)
			if _, err := rand.Read(b); err != nil {
				return nil, err
			}
			value = base64.StdEncoding.EncodeToString(b)
		case "x25519", "vless-encryption":
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			value = base64.RawURLEncoding.EncodeToString(key.Bytes())
			if kind == "vless-encryption" {
				value = "mlkem768x25519plus.native.600s." + value
			}
		}
	} else {
		value = *secret
	}
	if len(value) == 0 || len(value) > 4096 {
		return nil, errors.New("invalid secret size")
	}
	switch kind {
	case "uuid":
		id, err := uuid.FromString(value)
		if err != nil || id == uuid.Nil {
			return nil, errors.New("invalid UUID")
		}
	case "ss2022-128", "ss2022-256":
		b, err := base64.StdEncoding.Strict().DecodeString(value)
		size := 32
		if kind == "ss2022-128" {
			size = 16
		}
		if err != nil || len(b) != size || base64.StdEncoding.EncodeToString(b) != value {
			return nil, errors.New("invalid SS2022 key")
		}
	case "x25519":
		b, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || len(b) != 32 {
			return nil, errors.New("invalid X25519 key")
		}
	case "vless-encryption":
		cfg, err := encryption.ParseServerConfig(value)
		if err != nil || cfg == nil {
			return nil, errors.New("invalid VLESS decryption configuration")
		}
	}
	return []byte(value), nil
}
func (a *API) credentials(ctx context.Context, c *app.RequestContext) {
	cursor, limit, ok := a.pagination(c)
	if !ok {
		return
	}
	if len(cursor) > 128 {
		a.fail(c, 400, 40000, "Invalid asset cursor", nil)
		return
	}
	items, next, err := a.repo.Credentials(ctx, cursor, limit)
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", map[string]any{"items": items, "next_cursor": next})
}
func (a *API) createCredential(ctx context.Context, c *app.RequestContext) {
	var request struct {
		Kind     string  `json:"kind"`
		Label    string  `json:"label"`
		Secret   *string `json:"secret"`
		Generate bool    `json:"generate"`
	}
	if !a.decode(ctx, c, &request, 16<<10, false) {
		return
	}
	if request.Kind == "" {
		request.Kind = "generic"
	}
	secret, err := credentialValue(request.Kind, request.Secret, request.Generate)
	if err != nil || len(request.Label) > 256 {
		a.fail(c, 422, 42200, "Invalid credential kind, secret or label", nil)
		return
	}
	var asset model.CredentialAsset
	err = a.service.MutateAsset(ctx, func(ctx context.Context, repo ports.ManagementRepository) error {
		var err error
		asset, err = repo.CreateCredential(ctx, request.Kind, request.Label, secret)
		return err
	})
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.audit(ctx, "credential asset created")
	reply(c, 201, 0, "ok", asset)
}
func (a *API) deleteCredential(ctx context.Context, c *app.RequestContext) {
	if !a.decode(ctx, c, &struct{}{}, 1024, true) {
		return
	}
	id := strings.Clone(c.Param("id"))
	err := a.service.MutateAsset(ctx, func(ctx context.Context, repo ports.ManagementRepository) error {
		return repo.DeleteCredential(ctx, id)
	})
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.audit(ctx, "unreferenced credential asset deleted")
	reply(c, 200, 0, "ok", nil)
}
func (a *API) certificates(ctx context.Context, c *app.RequestContext) {
	cursor, limit, ok := a.pagination(c)
	if !ok {
		return
	}
	if len(cursor) > 128 {
		a.fail(c, 400, 40000, "Invalid asset cursor", nil)
		return
	}
	items, next, err := a.repo.Certificates(ctx, cursor, limit)
	if err != nil {
		a.error(c, err, false)
		return
	}
	reply(c, 200, 0, "ok", map[string]any{"items": items, "next_cursor": next})
}
func (a *API) createCertificate(ctx context.Context, c *app.RequestContext) {
	var request struct {
		Label       string `json:"label"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private_key"`
	}
	if !a.decode(ctx, c, &request, 3<<20, false) {
		return
	}
	if len(request.Label) > 256 || len(request.Certificate) > 1<<20 || len(request.PrivateKey) > 1<<20 {
		a.fail(c, 422, 42200, "Invalid certificate asset size", nil)
		return
	}
	value := model.Certificate{Certificate: []byte(request.Certificate), PrivateKey: []byte(request.PrivateKey)}
	if _, err := tls.X509KeyPair(value.Certificate, value.PrivateKey); err != nil {
		a.fail(c, 422, 42200, "Certificate and private key must be a valid matching pair", nil)
		return
	}
	var asset model.CertificateAsset
	err := a.service.MutateAsset(ctx, func(ctx context.Context, repo ports.ManagementRepository) error {
		var err error
		asset, err = repo.CreateCertificate(ctx, request.Label, value)
		return err
	})
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.audit(ctx, "certificate asset created")
	reply(c, 201, 0, "ok", asset)
}
func (a *API) deleteCertificate(ctx context.Context, c *app.RequestContext) {
	if !a.decode(ctx, c, &struct{}{}, 1024, true) {
		return
	}
	id := strings.Clone(c.Param("id"))
	err := a.service.MutateAsset(ctx, func(ctx context.Context, repo ports.ManagementRepository) error {
		return repo.DeleteCertificate(ctx, id)
	})
	if err != nil {
		a.error(c, err, false)
		return
	}
	a.audit(ctx, "unreferenced certificate asset deleted")
	reply(c, 200, 0, "ok", nil)
}

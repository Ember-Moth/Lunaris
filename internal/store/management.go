// SPDX-License-Identifier: GPL-3.0-only
package store

import (
	"context"
	"errors"
	"github.com/Ember-Moth/Lunaris/internal/model"
)

var ErrReferenced = errors.New("asset is referenced by a retained revision")

type ManagementRepository interface {
	CreateGeoData(context.Context, string, string, []byte) (model.GeoDataAsset, error)
	GeoData(context.Context, string) (model.GeoDataAsset, error)
	GeoDataPage(context.Context, string, int) ([]model.GeoDataAsset, string, error)
	DeleteGeoData(context.Context, string) error
	Repository
	ResolveDraftInput(context.Context, model.DraftInput) (*model.RuntimeConfig, error)
	SaveDraftReferences(context.Context, string, model.DraftInput) (model.ConfigRevision, error)
	CreateCredential(context.Context, string, string, []byte) (model.CredentialAsset, error)
	Credential(context.Context, string) (model.CredentialAsset, error)
	Credentials(context.Context, string, int) ([]model.CredentialAsset, string, error)
	DeleteCredential(context.Context, string) error
	CreateCertificate(context.Context, string, model.Certificate) (model.CertificateAsset, error)
	Certificate(context.Context, string) (model.CertificateAsset, error)
	Certificates(context.Context, string, int) ([]model.CertificateAsset, string, error)
	DeleteCertificate(context.Context, string) error
	RevisionPage(context.Context, string, int) ([]model.ConfigRevision, string, error)
	OperationID(context.Context, string) (model.ApplyOperation, error)
	BeginManagedApply(context.Context, string, string, string, string) (model.ApplyOperation, bool, error)
}

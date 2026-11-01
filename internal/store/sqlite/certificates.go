// SPDX-License-Identifier: GPL-3.0-only
package sqlite

import (
	"context"
	"github.com/Ember-Moth/Lunaris/internal/model"
)

func certificateBindings(ctx context.Context, q queryer, revision string) (map[string]string, map[string]model.Certificate, error) {
	rows, err := q.QueryContext(ctx, `SELECT b.logical_id,b.asset_id,a.certificate,a.private_key FROM revision_certificates b JOIN certificate_assets a ON a.id=b.asset_id WHERE b.revision_id=?`, revision)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	ids := make(map[string]string)
	assets := make(map[string]model.Certificate)
	for rows.Next() {
		var name, id string
		var cert model.Certificate
		if err := rows.Scan(&name, &id, &cert.Certificate, &cert.PrivateKey); err != nil {
			return nil, nil, err
		}
		ids[name], assets[name] = id, cert
	}
	return ids, assets, rows.Err()
}

func certificateIDs(ctx context.Context, q queryer, revision string) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, "SELECT logical_id,asset_id FROM revision_certificates WHERE revision_id=?", revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make(map[string]string)
	for rows.Next() {
		var name, id string
		if err := rows.Scan(&name, &id); err != nil {
			return nil, err
		}
		ids[name] = id
	}
	return ids, rows.Err()
}

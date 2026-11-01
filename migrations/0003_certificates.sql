-- SPDX-License-Identifier: GPL-3.0-only
CREATE TABLE certificate_assets (
    id TEXT PRIMARY KEY,
    certificate BLOB NOT NULL CHECK (length(certificate) BETWEEN 1 AND 1048576),
    private_key BLOB NOT NULL CHECK (length(private_key) BETWEEN 1 AND 1048576),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE TABLE revision_certificates (
    revision_id TEXT NOT NULL REFERENCES config_revisions(id),
    logical_id TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES certificate_assets(id),
    PRIMARY KEY (revision_id, logical_id)
);
CREATE TRIGGER immutable_certificate BEFORE UPDATE ON certificate_assets
BEGIN SELECT RAISE(ABORT, 'certificate assets are immutable'); END;
CREATE TRIGGER immutable_certificate_binding BEFORE UPDATE ON revision_certificates
BEGIN SELECT RAISE(ABORT, 'certificate bindings are immutable'); END;

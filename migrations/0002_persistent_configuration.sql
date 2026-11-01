-- SPDX-License-Identifier: GPL-3.0-only
CREATE TABLE credential_assets (
    id TEXT PRIMARY KEY,
    secret BLOB NOT NULL CHECK (length(secret) BETWEEN 1 AND 4096),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE revision_credentials (
    revision_id TEXT NOT NULL REFERENCES config_revisions(id),
    logical_id TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES credential_assets(id),
    PRIMARY KEY (revision_id, logical_id)
);

CREATE TABLE apply_operations (
    id TEXT PRIMARY KEY,
    request_key TEXT NOT NULL UNIQUE CHECK (length(request_key) BETWEEN 1 AND 128),
    request_digest TEXT NOT NULL,
    expected_base TEXT NOT NULL,
    target_revision TEXT NOT NULL REFERENCES config_revisions(id),
    base_revision TEXT NOT NULL REFERENCES config_revisions(id),
    status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed','failed_rolled_back','degraded','interrupted')),
    phase TEXT NOT NULL,
    error_message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX one_running_apply ON apply_operations((1)) WHERE status = 'running';

CREATE TRIGGER immutable_revision BEFORE UPDATE ON config_revisions
BEGIN SELECT RAISE(ABORT, 'configuration revisions are immutable'); END;
CREATE TRIGGER immutable_credential BEFORE UPDATE ON credential_assets
BEGIN SELECT RAISE(ABORT, 'credential assets are immutable'); END;
CREATE TRIGGER immutable_binding BEFORE UPDATE ON revision_credentials
BEGIN SELECT RAISE(ABORT, 'credential bindings are immutable'); END;

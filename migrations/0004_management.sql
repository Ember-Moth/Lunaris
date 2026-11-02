-- SPDX-License-Identifier: GPL-3.0-only
CREATE TABLE installation (
    id INTEGER PRIMARY KEY CHECK (id=1),
    setup_token_hash TEXT NOT NULL DEFAULT '',
    setup_expires INTEGER NOT NULL DEFAULT 0
);
INSERT INTO installation(id) VALUES(1);
CREATE TABLE admin_account (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    id TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE admin_sessions (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES admin_account(id),
    account_version INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    reauth_until INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX admin_sessions_expiry ON admin_sessions(expires_at);
ALTER TABLE credential_assets ADD COLUMN kind TEXT NOT NULL DEFAULT 'generic';
ALTER TABLE credential_assets ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE certificate_assets ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE apply_operations ADD COLUMN caller_digest TEXT NOT NULL DEFAULT '';

CREATE INDEX revision_credentials_asset ON revision_credentials(asset_id);
CREATE INDEX revision_certificates_asset ON revision_certificates(asset_id);

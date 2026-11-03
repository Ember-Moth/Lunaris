-- SPDX-License-Identifier: GPL-3.0-only
CREATE TABLE geodata_assets (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('geosite','geoip')),
    label TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL CHECK(length(sha256)=64),
    data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 134217728),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(kind, sha256)
);
CREATE TABLE revision_geodata (
    revision_id TEXT NOT NULL REFERENCES config_revisions(id),
    logical_id TEXT NOT NULL CHECK(logical_id IN ('geosite','geoip')),
    asset_id TEXT NOT NULL REFERENCES geodata_assets(id),
    PRIMARY KEY(revision_id, logical_id)
);
CREATE INDEX revision_geodata_asset ON revision_geodata(asset_id);
CREATE TRIGGER immutable_geodata BEFORE UPDATE ON geodata_assets
BEGIN SELECT RAISE(ABORT,'geodata assets are immutable'); END;
CREATE TRIGGER immutable_geodata_binding BEFORE UPDATE ON revision_geodata
BEGIN SELECT RAISE(ABORT,'geodata bindings are immutable'); END;

-- SPDX-License-Identifier: GPL-3.0-only
CREATE TABLE config_revisions (
    id TEXT PRIMARY KEY,
    parent_id TEXT REFERENCES config_revisions(id),
    schema_version INTEGER NOT NULL,
    document TEXT NOT NULL CHECK (json_valid(document)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE config_heads (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    draft_revision TEXT NOT NULL REFERENCES config_revisions(id),
    committed_revision TEXT NOT NULL REFERENCES config_revisions(id)
);

INSERT INTO config_revisions(id, schema_version, document)
VALUES ('r0', 1, '{"schema_version":1,"listeners":[]}');

INSERT INTO config_heads(id, draft_revision, committed_revision)
VALUES (1, 'r0', 'r0');

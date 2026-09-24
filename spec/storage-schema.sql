-- Haskoki SQLite store schema, format version 1.
--
-- PROVENANCE: adapted from
--   ws/docs/incoming/haskell-pkcs11-design/examples/storage-schema.sql
-- (Design-bundle input, read-only). Adaptations recorded here:
--
-- * `store_format` is `haskoki-demo-v1` (repo naming, not `hsp11-demo-v1`).
-- * `store_meta` gains a `schema_version` key (`1`): the minimal
--   integer schema version the opener checks. A wrong/future version
--   is rejected without rewriting the database.
-- * `detached_jobs` is created with the rest of the schema but first
--   populated by the record writer; the store layer owns the lifecycle.
--
-- The Haskell backend (`src/Haskoki/Runtime/Storage/SQLite.hs`)
-- issues these statements at init; this file is the readable
-- reference. Full-width unsigned quantities travel as 8-byte blobs
-- or fixed hex text, never as blind SQLite signed-integer casts
-- (only the bounded `revision` counter uses INTEGER, guarded by a
-- CHECK constraint).
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = DELETE;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;

CREATE TABLE store_meta (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE tokens (
    token_id TEXT PRIMARY KEY NOT NULL,
    slot_key BLOB NOT NULL CHECK (typeof(slot_key) = 'blob' AND length(slot_key) = 8),
    generation_key BLOB NOT NULL CHECK (typeof(generation_key) = 'blob' AND length(generation_key) = 8),
    record_json TEXT NOT NULL,
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    UNIQUE(slot_key)
);

CREATE TABLE objects (
    object_id TEXT PRIMARY KEY NOT NULL,
    token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE,
    class_key BLOB NOT NULL CHECK (typeof(class_key) = 'blob' AND length(class_key) = 8),
    key_type_key BLOB CHECK (key_type_key IS NULL OR (typeof(key_type_key) = 'blob' AND length(key_type_key) = 8)),
    attributes_json TEXT NOT NULL,
    material_encoding TEXT NOT NULL,
    material_blob BLOB,
    revision INTEGER NOT NULL CHECK (revision > 0),
    format_version INTEGER NOT NULL CHECK (format_version = 1)
);
CREATE INDEX objects_by_token ON objects(token_id);

CREATE TABLE detached_jobs (
    persistent_id_key BLOB PRIMARY KEY NOT NULL CHECK (typeof(persistent_id_key) = 'blob' AND length(persistent_id_key) = 8),
    token_id TEXT NOT NULL REFERENCES tokens(token_id) ON DELETE CASCADE,
    token_generation_key BLOB NOT NULL CHECK (typeof(token_generation_key) = 'blob' AND length(token_generation_key) = 8),
    function_name TEXT NOT NULL,
    execution_state TEXT NOT NULL CHECK (execution_state IN ('queued','ready','failed','canceled','delivered')),
    record_json TEXT NOT NULL,
    format_version INTEGER NOT NULL CHECK (format_version = 1)
);
CREATE INDEX jobs_by_token ON detached_jobs(token_id);

INSERT INTO store_meta(key, value) VALUES ('store_format', 'haskoki-demo-v1');
INSERT INTO store_meta(key, value) VALUES ('schema_version', '1');
INSERT INTO store_meta(key, value) VALUES ('next_persistent_job_id', '0000000000000001');

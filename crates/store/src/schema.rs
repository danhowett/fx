//! Case database schema.
//!
//! A case is a single DuckDB file. The schema is deliberately denormalized on
//! the `events` table (the hot path for timelining and hunting) with the full
//! original record kept as JSON so nothing is lost. Evidence and case metadata
//! give provenance and integrity; `unclassified` and `ingest_report` make the
//! "never silently drop, always account for every file" guarantee visible.

/// Bumped whenever the schema changes; `case_meta.schema_version` records the
/// version a case file was created with, so the app can migrate or refuse.
pub const SCHEMA_VERSION: i32 = 1;

/// Full DDL, executed once at case creation inside a transaction.
pub const DDL: &str = r#"
-- One row. Identity and integrity anchor for the whole case.
CREATE TABLE IF NOT EXISTS case_meta (
    case_id           UUID    PRIMARY KEY,
    name              TEXT    NOT NULL,
    examiner          TEXT,
    created_utc       TIMESTAMP NOT NULL,
    schema_version    INTEGER NOT NULL,
    tool_version      TEXT    NOT NULL,
    -- Timezone the analyst wants times DISPLAYED in. Storage is always UTC.
    display_timezone  TEXT    NOT NULL DEFAULT 'UTC'
);

-- Every source file registered into the case, with its hash. This is the
-- chain-of-custody spine: each event's evidence_id points here.
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id       UUID    PRIMARY KEY,
    source_path       TEXT    NOT NULL,   -- path as found in the collection
    absolute_path     TEXT    NOT NULL,   -- where it was read from on this host
    artefact_kind     TEXT    NOT NULL,
    container_format  TEXT    NOT NULL,
    id_method         TEXT    NOT NULL,
    id_confidence     REAL    NOT NULL,
    size_bytes        BIGINT  NOT NULL,
    sha256            TEXT    NOT NULL,
    -- Collection-format assertions (host/tz/time) recorded but NOT trusted.
    asserted_host     TEXT,
    asserted_timezone TEXT,
    collection_tool   TEXT,
    registered_utc    TIMESTAMP NOT NULL
);

-- The normalized timeline. One row per fx_core::Event. Common fields are
-- lifted into columns for fast filtering; `raw` holds the complete original.
CREATE TABLE IF NOT EXISTS events (
    id               UUID      PRIMARY KEY,
    ts               TIMESTAMP NOT NULL,   -- always UTC
    ts_kind          TEXT      NOT NULL,   -- created/executed/logged/...
    artefact         TEXT      NOT NULL,
    action           TEXT      NOT NULL,
    host             TEXT,
    user_name        TEXT,
    user_sid         TEXT,
    user_domain      TEXT,
    process_name     TEXT,
    process_path     TEXT,
    process_pid      INTEGER,
    command_line     TEXT,
    process_sha1     TEXT,
    parent_name      TEXT,
    target_path      TEXT,
    target_value     TEXT,
    src_ip           TEXT,
    dst_ip           TEXT,
    logon_type       INTEGER,
    message          TEXT      NOT NULL,
    evidence_id      UUID      NOT NULL,
    parser           TEXT      NOT NULL,
    parser_version   TEXT      NOT NULL,
    source_ref       TEXT,
    raw              JSON      NOT NULL
);

-- Files identified only by container but with no artefact rule, or not
-- identified at all. Surfaced in the GUI; proof nothing was dropped.
CREATE TABLE IF NOT EXISTS unclassified (
    evidence_id   UUID PRIMARY KEY,
    source_path   TEXT NOT NULL,
    absolute_path TEXT NOT NULL,
    container     TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    reason        TEXT NOT NULL
);

-- Per-artefact outcome of each ingest run: parsed / unsupported / failed,
-- with counts and warnings. The audit trail for "what happened to my data".
CREATE TABLE IF NOT EXISTS ingest_report (
    id              UUID PRIMARY KEY,
    run_utc         TIMESTAMP NOT NULL,
    source_path     TEXT NOT NULL,
    artefact_kind   TEXT NOT NULL,
    status          TEXT NOT NULL,       -- parsed | unsupported | failed
    detail          TEXT,                -- failure message, if any
    records_read    BIGINT NOT NULL,
    events_emitted  BIGINT NOT NULL,
    warning_count   INTEGER NOT NULL
);

-- Analyst bookmarks/tags on events, for building the report later.
CREATE TABLE IF NOT EXISTS tags (
    event_id  UUID NOT NULL,
    tag       TEXT NOT NULL,
    note      TEXT,
    tagged_utc TIMESTAMP NOT NULL,
    PRIMARY KEY (event_id, tag)
);

-- Hunt results. One row per rule firing, from either detection engine. The
-- contributing event ids are stored as a comma-separated list (a detection can
-- span many events); the GUI expands them to pivot back to the timeline.
CREATE TABLE IF NOT EXISTS detections (
    id            UUID PRIMARY KEY,
    rule_id       TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    attack        TEXT NOT NULL,     -- comma-separated ATT&CK ids
    summary       TEXT NOT NULL,
    event_ids     TEXT NOT NULL,     -- comma-separated event UUIDs
    ts            TIMESTAMP NOT NULL,
    host          TEXT,
    engine        TEXT NOT NULL,
    detected_utc  TIMESTAMP NOT NULL
);
"#;

/// Per-case UI state (saved IOC hunt list, last results). Idempotent; run on
/// create and on open so older case files pick it up.
pub const CASE_KV_DDL: &str = "CREATE TABLE IF NOT EXISTS case_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);";

/// Indexes created after bulk load (cheaper to build once data is in). Called
/// separately from DDL so ingest can defer them until after the first load.
pub const INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_artefact  ON events (artefact);
CREATE INDEX IF NOT EXISTS idx_events_action    ON events (action);
CREATE INDEX IF NOT EXISTS idx_events_host      ON events (host);
CREATE INDEX IF NOT EXISTS idx_events_user      ON events (user_name);
CREATE INDEX IF NOT EXISTS idx_events_target    ON events (target_path);
CREATE INDEX IF NOT EXISTS idx_events_evidence  ON events (evidence_id);
"#;

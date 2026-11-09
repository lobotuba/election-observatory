"""SQLite store. Evidence tables are append-only: triggers reject UPDATE and DELETE."""
import sqlite3
from datetime import datetime, timezone

from . import config

APPEND_ONLY_TABLES = ["acquisitions", "parse_runs", "vote_obs", "page_stamps", "validation_findings", "alerts",
                      "clock_status", "custody_events", "timestamp_attempts", "replication_events", "manifests",
                      "endpoint_observations", "releases", "source_config_versions", "artifact_digests", "audit_segments",
                      "coverage_manifests", "coverage_events", "source_authority_records", "qualification_records",
                      "result_fingerprints", "news_items"]

SCHEMA_DIGEST_INPUT = None  # filled lazily: sha256 of all DDL, recorded in manifests (REQ-SCHEMA-001)


def schema_digest() -> str:
    import hashlib
    return hashlib.sha256((SCHEMA + EVIDENCE_SCHEMA + EVIDENCE_SCHEMA_2 + EVIDENCE_SCHEMA_3 + EVIDENCE_SCHEMA_4 + EVIDENCE_SCHEMA_5).encode()).hexdigest()

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    source_id TEXT PRIMARY KEY,
    registry_json TEXT NOT NULL,
    registered_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS acquisitions (
    acquisition_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    election_id TEXT NOT NULL,
    requested_url TEXT NOT NULL,
    http_method TEXT NOT NULL DEFAULT 'GET',
    request_started_utc TEXT NOT NULL,
    response_received_utc TEXT,
    duration_ms INTEGER,
    http_status INTEGER,
    redirect_chain TEXT,
    response_headers TEXT,
    content_type TEXT,
    content_encoding TEXT,
    content_length INTEGER,
    etag TEXT,
    last_modified TEXT,
    cache_control TEXT,
    sha256 TEXT,
    artifact_path TEXT,
    collector_name TEXT,
    collector_version TEXT,
    prior_acquisition_id INTEGER,
    content_changed INTEGER,
    error_class TEXT,
    error_detail TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_acq_source_time ON acquisitions(source_id, response_received_utc);
CREATE INDEX IF NOT EXISTS ix_acq_hash ON acquisitions(sha256);

CREATE TABLE IF NOT EXISTS parse_runs (
    parse_run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    acquisition_id INTEGER NOT NULL,
    parser_name TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    started_utc TEXT NOT NULL,
    status TEXT NOT NULL,              -- OK | FAILED
    observation_count INTEGER NOT NULL DEFAULT 0,
    error_detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_parse_acq ON parse_runs(acquisition_id);

CREATE TABLE IF NOT EXISTS vote_obs (
    obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
    parse_run_id INTEGER NOT NULL,
    acquisition_id INTEGER NOT NULL,
    source_id TEXT NOT NULL,
    election_id TEXT NOT NULL,
    contest_id TEXT NOT NULL,          -- canonical: <election_id>:<source race id>
    source_race_id TEXT NOT NULL,
    race_name TEXT NOT NULL,
    area TEXT,
    party_code TEXT,
    source_candidate_id TEXT NOT NULL,
    candidate_name TEXT NOT NULL,
    vote_for INTEGER,
    votes INTEGER,
    source_pct_text TEXT,              -- source's own percentage, kept verbatim
    precincts_label TEXT,              -- source's own "n/m" label, kept verbatim
    precincts_reporting INTEGER,
    precincts_total INTEGER,
    votes_absentee INTEGER,
    votes_election_day INTEGER,
    votes_early INTEGER,
    observed_type TEXT NOT NULL DEFAULT 'OBSERVED',
    result_status TEXT NOT NULL DEFAULT 'UNOFFICIAL',
    observed_at_utc TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    validation_state TEXT NOT NULL DEFAULT 'OK'
);
CREATE INDEX IF NOT EXISTS ix_obs_acq ON vote_obs(acquisition_id);
CREATE INDEX IF NOT EXISTS ix_obs_contest ON vote_obs(contest_id, source_id);

CREATE TABLE IF NOT EXISTS page_stamps (
    stamp_id INTEGER PRIMARY KEY AUTOINCREMENT,
    acquisition_id INTEGER NOT NULL,
    source_id TEXT NOT NULL,
    displayed_text TEXT NOT NULL,      -- exactly as shown by the source
    displayed_iso_utc TEXT,            -- our interpretation (derived)
    observed_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    acquisition_id INTEGER NOT NULL,
    parse_run_id INTEGER,
    severity TEXT NOT NULL,            -- INFO | WARN | ERROR
    code TEXT NOT NULL,
    detail TEXT,
    created_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_utc TEXT NOT NULL,
    source_id TEXT,
    kind TEXT NOT NULL,                -- SOURCE_UNAVAILABLE | PARSER_FAILURE | SCHEMA_CHANGE | CIRCUIT_OPEN | ...
    detail TEXT
);

CREATE TABLE IF NOT EXISTS manifests (
    manifest_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                -- hourly | daily | adhoc
    window_start_utc TEXT NOT NULL,
    window_end_utc TEXT NOT NULL,
    artifact_count INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    merkle_root TEXT,
    path TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_utc TEXT NOT NULL
);
"""


EVIDENCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS clock_status (
    clock_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sampled_utc TEXT NOT NULL,
    host TEXT NOT NULL,
    offset_ms REAL,                    -- median of lowest-delay SNTP exchanges; >0 means local clock is behind
    uncertainty_ms REAL,
    spread_ms REAL,
    state TEXT NOT NULL,               -- SYNCHRONIZED | DEGRADED | UNKNOWN
    servers_json TEXT,
    errors_json TEXT,
    os_sync_json TEXT,
    tolerance_ms REAL
);

CREATE TABLE IF NOT EXISTS custody_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_kind TEXT NOT NULL,       -- acquisition | manifest | package
    evidence_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,          -- ACQUIRED | HASH_VERIFIED | MANIFEST_INCLUDED | TIMESTAMPED | REPLICATED | REVERIFIED | EXPORTED | ...
    event_utc TEXT NOT NULL,
    actor TEXT NOT NULL,
    host TEXT NOT NULL,
    reason TEXT,
    prior_state TEXT,
    new_state TEXT,
    artifact_sha256 TEXT,
    authorization_ref TEXT,
    prev_event_hash TEXT,
    event_hash TEXT NOT NULL           -- sha256 over this event's fields + prev_event_hash (tamper-evident chain)
);
CREATE INDEX IF NOT EXISTS ix_custody_ev ON custody_events(evidence_kind, evidence_id);

CREATE TABLE IF NOT EXISTS timestamp_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_id INTEGER NOT NULL,
    attempted_utc TEXT NOT NULL,
    tsa_url TEXT NOT NULL,
    outcome TEXT NOT NULL,             -- OK | ERROR
    detail TEXT,
    request_path TEXT,
    response_path TEXT,
    response_sha256 TEXT,
    gen_time_utc TEXT,
    serial_number TEXT,
    policy_oid TEXT,
    hash_algorithm TEXT,
    nonce TEXT,
    tsa_name TEXT,
    verify_result TEXT,                -- VERIFIED | FAILED | NOT_VERIFIED
    verify_detail TEXT,
    verifier TEXT
);
CREATE INDEX IF NOT EXISTS ix_tsa_manifest ON timestamp_attempts(manifest_id);

CREATE TABLE IF NOT EXISTS replication_events (
    repl_id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_kind TEXT NOT NULL,         -- artifact | manifest | timestamp
    object_ref TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    replica_dir TEXT NOT NULL,
    copied_utc TEXT NOT NULL,
    reverified INTEGER NOT NULL,
    separate_boundary_declared INTEGER NOT NULL
);
"""

EVIDENCE_SCHEMA_2 = """
CREATE TABLE IF NOT EXISTS endpoint_observations (   -- REQ-EVID-016: who we actually talked to
    obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_utc TEXT NOT NULL,
    probe_kind TEXT NOT NULL,          -- ADJACENT_PROBE: separate TCP/TLS connection to the same host, made close in time
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    collector_host TEXT,
    dns_answers_json TEXT,
    dns_resolvers_json TEXT,
    dns_query_utc TEXT,
    remote_ip TEXT,
    remote_port INTEGER,
    local_ip TEXT,
    sni TEXT,
    tls_version TEXT,
    cipher TEXT,
    cert_sha256 TEXT,
    cert_sha1 TEXT,
    cert_path TEXT,
    cert_subject TEXT,
    cert_issuer TEXT,
    cert_sans_json TEXT,
    cert_not_before TEXT,
    cert_not_after TEXT,
    chain_json TEXT,
    chain_status TEXT,                 -- PRESENT | NOT_COLLECTED
    validation_result TEXT,            -- VALID | FAILED
    validation_detail TEXT,
    revocation_status TEXT,            -- NOT_CHECKED (no OCSP/CRL performed)
    anomalies_json TEXT
);
CREATE TABLE IF NOT EXISTS releases (   -- REQ-REPRO-001 (partial): identity of the running software
    release_id INTEGER PRIMARY KEY AUTOINCREMENT,
    release_sha256 TEXT NOT NULL UNIQUE,
    created_utc TEXT NOT NULL,
    observatory_version TEXT,
    python_version TEXT,
    platform TEXT,
    source_files_json TEXT,
    lock_sha256 TEXT,
    lock_text TEXT,
    sbom_path TEXT,
    signed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS source_config_versions (   -- REQ-CONFIG-001/002 (partial)
    cfg_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    config_sha256 TEXT NOT NULL,
    config_json TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    author TEXT,
    reviewer TEXT,
    approval_status TEXT NOT NULL,
    reason TEXT,
    previous_cfg_id INTEGER
);
CREATE TABLE IF NOT EXISTS artifact_digests (   -- REQ-CRYPTO-001: digests are a collection, not one fixed field
    digest_id INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_sha256 TEXT NOT NULL,     -- artifact_id = its SHA-256
    algorithm TEXT NOT NULL,
    oid TEXT,
    value TEXT NOT NULL,
    calculated_utc TEXT NOT NULL,
    implementation TEXT,
    input_length INTEGER,
    verification_status TEXT NOT NULL,
    UNIQUE(artifact_sha256, algorithm)
);
CREATE TABLE IF NOT EXISTS audit_segments (   -- REQ-EVID-017/026: log tables are digested into each timestamped manifest
    seg_id INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_seq INTEGER NOT NULL,
    table_name TEXT NOT NULL,
    first_id INTEGER NOT NULL,
    last_id INTEGER NOT NULL,
    row_count INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL
);
"""

EVIDENCE_SCHEMA_3 = """
CREATE TABLE IF NOT EXISTS coverage_manifests (   -- REQ-COMP-001: what we EXPECTED to collect, signed and versioned
    cov_id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL,
    created_utc TEXT NOT NULL,
    author TEXT,
    approval_status TEXT NOT NULL,
    baseline_acquisition_id INTEGER,
    expected_contest_count INTEGER,
    expected_source_count INTEGER,
    manifest_sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS coverage_events (   -- gaps, unexpected discoveries and post-baseline changes (REQ-COMP-004, REQ-BASE-004)
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_utc TEXT NOT NULL,
    cov_id INTEGER,
    kind TEXT NOT NULL,                -- COVERAGE_GAP | UNEXPECTED_DISCOVERY | BASELINE_CHANGE | COVERAGE_RESTORED
    contest_id TEXT,
    source_id TEXT,
    detail TEXT,
    detail_key TEXT,
    acquisition_id INTEGER
);
CREATE TABLE IF NOT EXISTS source_authority_records (   -- REQ-SOURCE-001: authority is not endpoint identity
    sar_id INTEGER PRIMARY KEY AUTOINCREMENT,
    authority_key TEXT NOT NULL,
    version INTEGER NOT NULL,
    created_utc TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    record_json TEXT NOT NULL,
    approval_status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS qualification_records (   -- REQ-QUAL-001
    qual_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_utc TEXT NOT NULL,
    path TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    summary_json TEXT,
    authorization_status TEXT NOT NULL
);
"""

EVIDENCE_SCHEMA_4 = """
CREATE TABLE IF NOT EXISTS result_fingerprints (   -- derived, insert-only: identity of the RESULT content, ignoring free text
    acquisition_id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,         -- sha256 over (race id, candidate id, party, candidate name, votes, precinct label, vote-method counts)
    row_count INTEGER NOT NULL,
    fingerprint_version INTEGER NOT NULL,
    computed_utc TEXT NOT NULL
);
"""

EVIDENCE_SCHEMA_5 = """
CREATE TABLE IF NOT EXISTS news_items (   -- media/press context ONLY; never feeds results, seat counts or contests
    item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    item_key TEXT NOT NULL,            -- feed guid, else link
    content_sha256 TEXT NOT NULL,      -- over title+summary so a later headline edit is kept as a new version
    title TEXT NOT NULL,
    link TEXT,
    summary TEXT,                      -- tags stripped and truncated; never full article text
    published_text TEXT,               -- verbatim from the feed
    published_utc TEXT,                -- parsed when parseable, else NULL
    election_related INTEGER NOT NULL, -- keyword heuristic, NOT a verdict on accuracy or relevance
    first_seen_acquisition_id INTEGER NOT NULL,
    first_seen_utc TEXT NOT NULL,
    UNIQUE(source_id, item_key, content_sha256)
);
CREATE INDEX IF NOT EXISTS ix_news_pub ON news_items(published_utc);
"""

ACQ_NEW_COLUMNS_4 = [("origin_instance_tag", "TEXT")]

ACQ_NEW_COLUMNS_3 = [("attempt_number", "INTEGER"), ("schedule_id", "TEXT"), ("retry_of_acquisition_id", "INTEGER"),
                     ("failure_status", "TEXT"), ("stage_reached", "TEXT"), ("configured_timeout_s", "INTEGER"),
                     ("observation_status", "TEXT"), ("next_retry_utc", "TEXT"), ("byte_layer", "TEXT"),
                     ("transfer_encoding", "TEXT"), ("decoded_sha256", "TEXT"), ("decoded_length", "INTEGER"),
                     ("decode_detail", "TEXT"), ("source_version_id", "TEXT")]

ACQ_NEW_COLUMNS_2 = [("release_id", "INTEGER"), ("source_config_version_id", "INTEGER"), ("endpoint_obs_id", "INTEGER"),
                     ("final_url", "TEXT"), ("http_version", "TEXT"), ("set_cookie_present", "INTEGER"),
                     ("restricted_commitment", "TEXT"), ("restricted_path", "TEXT"), ("bytes_on_wire_note", "TEXT")]

ACQ_NEW_COLUMNS = [
    ("scheduler_created_utc", "TEXT"), ("request_sent_utc", "TEXT"), ("first_byte_received_utc", "TEXT"),
    ("response_completed_utc", "TEXT"), ("artifact_write_started_utc", "TEXT"), ("artifact_write_completed_utc", "TEXT"),
    ("hash_calculated_utc", "TEXT"), ("hash_algorithm", "TEXT"), ("hash_implementation", "TEXT"),
    ("post_write_verified", "INTEGER"), ("time_confidence", "TEXT"), ("clock_id", "INTEGER"), ("normalized_sha256", "TEXT"),
]
MANIFEST_NEW_COLUMNS = [("seq", "INTEGER"), ("first_acquisition_id", "INTEGER"), ("last_acquisition_id", "INTEGER"),
                        ("manifest_sha256", "TEXT"), ("signature_b64", "TEXT")]


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def connect(path=None) -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(str(path or config.DB_PATH), timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(conn: sqlite3.Connection):
    conn.executescript(SCHEMA)
    conn.executescript(EVIDENCE_SCHEMA)
    conn.executescript(EVIDENCE_SCHEMA_2)
    conn.executescript(EVIDENCE_SCHEMA_3)
    conn.executescript(EVIDENCE_SCHEMA_4)
    conn.executescript(EVIDENCE_SCHEMA_5)
    for table, new_cols in (("acquisitions", ACQ_NEW_COLUMNS + ACQ_NEW_COLUMNS_2 + ACQ_NEW_COLUMNS_3 + ACQ_NEW_COLUMNS_4), ("manifests", MANIFEST_NEW_COLUMNS)):
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        for name, typ in new_cols:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {typ}")
    for t in APPEND_ONLY_TABLES:
        for op in ("UPDATE", "DELETE"):
            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS {t}_no_{op.lower()} BEFORE {op} ON {t} "
                f"BEGIN SELECT RAISE(ABORT, '{t} is append-only'); END"
            )


def sync_source_registry(conn: sqlite3.Connection):
    import json
    for s in config.SOURCES:
        conn.execute(
            "INSERT OR IGNORE INTO sources(source_id, registry_json, registered_at_utc) VALUES (?,?,?)",
            (s["source_id"], json.dumps(s, sort_keys=True), now_utc()),
        )

"""Election Coverage Manifest, pre-election baseline and completeness accounting
(addendum 003 REQ-COMP-001..005, REQ-BASE-001..004).

The baseline is the zero-results export captured before any returns were published. It defines the expected
NM contest/candidate set. National federal coverage is NOT collected by this build and is declared as an
explicit gap rather than silently omitted.
"""
import base64
import hashlib
import json
from pathlib import Path

from . import config, custody, manifest
from .db import now_utc

COVERAGE_DIR = config.DATA_DIR / "coverage"


def _contest_map(conn, acquisition_id: int) -> dict:
    out = {}
    for r in conn.execute("SELECT * FROM vote_obs WHERE acquisition_id=? ORDER BY obs_id", (acquisition_id,)):
        c = out.setdefault(r["contest_id"], dict(contest_id=r["contest_id"], source_race_id=r["source_race_id"], race_name=r["race_name"],
                                                 area=r["area"], vote_for=r["vote_for"], precincts_total=r["precincts_total"],
                                                 candidates=[], votes_total=0))
        c["candidates"].append(dict(source_candidate_id=r["source_candidate_id"], name=r["candidate_name"], party=r["party_code"]))
        c["votes_total"] += r["votes"] or 0
    return out


def _cand_key(c: dict) -> str:
    return json.dumps(sorted((x["source_candidate_id"], x["name"], x["party"] or "") for x in c["candidates"]))


def latest(conn):
    return conn.execute("SELECT * FROM coverage_manifests ORDER BY cov_id DESC LIMIT 1").fetchone()


def find_baseline_acquisition(conn):
    """Earliest parsed primary-export acquisition in which no votes had been reported."""
    for r in conn.execute("SELECT a.acquisition_id FROM acquisitions a JOIN parse_runs p ON p.acquisition_id=a.acquisition_id AND p.status='OK' "
                          "WHERE a.source_id=? ORDER BY a.acquisition_id", (config.PRIMARY_SOURCE_ID,)):
        return r["acquisition_id"]
    return None


def create_baseline(conn, acquisition_id: int | None = None, author: str = "operator (single person)", notes: str = "") -> dict:
    acquisition_id = acquisition_id or find_baseline_acquisition(conn)
    if not acquisition_id:
        raise ValueError("no parsed primary-source acquisition to baseline from")
    contests = _contest_map(conn, acquisition_id)
    acq = conn.execute("SELECT * FROM acquisitions WHERE acquisition_id=?", (acquisition_id,)).fetchone()
    all_zero = all(c["votes_total"] == 0 for c in contests.values())
    prev = latest(conn)
    version = (prev["version"] + 1) if prev else 1
    cfgs = {r["source_id"]: dict(cfg_id=r["cfg_id"], version=r["version"], config_sha256=r["config_sha256"])
            for r in conn.execute("SELECT * FROM source_config_versions WHERE cfg_id IN (SELECT MAX(cfg_id) FROM source_config_versions GROUP BY source_id)")}
    body = {
        "schema": {"schema_name": "eio.coverage_manifest", "schema_version": 1, "canonicalization": manifest.CANON_PROFILE},
        "election_id": config.ELECTION_ID, "version": version, "created_utc": now_utc(), "author": author,
        "approval_status": "DRAFT_UNAPPROVED_NO_INDEPENDENT_REVIEWER", "responsible_operator": author,
        "baseline": {
            "acquisition_id": acquisition_id, "source_id": acq["source_id"], "acquired_at_utc": acq["response_received_utc"],
            "artifact_sha256": acq["sha256"], "all_vote_counts_zero": all_zero,
            "note": ("pre-results export" if all_zero else "WARNING: baseline already contains reported votes"),
            "lead_time_note": "captured on election day; the 7-day pre-election baseline and review (REQ-BASE-002) was NOT met",
        },
        "expected_nm_contests": [dict(c, votes_total=None) for c in contests.values()],
        "expected_nm_contest_count": len(contests),
        "expected_federal_contests_nm": sorted(cid for cid, c in contests.items() if c["race_name"].startswith("United States")),
        "expected_national_federal_contests": {
            "status": "JURISDICTIONS_ENUMERATED_CONTESTS_NOT_ENUMERATED",
            "note": ("Expected jurisdictions are listed from the State Election Authority Source Matrix v0.1. Individual federal contests "
                     "outside New Mexico are NOT enumerated, no outside-NM result is parsed, and no jurisdiction other than NM is "
                     "authority-verified. Declared coverage gap (REQ-COMP-004)."),
            "expected_jurisdictions": [{k: j[k] for k in ("jurisdiction", "federal_coverage", "tracker_depth", "matrix_status", "entry_sources")}
                                       for j in config.JURISDICTIONS]},
        "expected_sources": [{"source_id": s["source_id"], "classification": s.get("source_classification"),
                              "endpoint_url": s["endpoint_url"], "polling_interval_s": s["polling_interval_s"],
                              "config": cfgs.get(s["source_id"])} for s in config.SOURCES],
        "expected_fallback_sources": [], "expected_certification_sources": [],
        "collection_window": {"start_utc": now_utc(), "end_utc": None, "note": "open-ended through canvass; no certification schedule configured"},
        "accepted_exclusions": [], "notes": notes,
    }
    key = manifest._load_or_create_key()
    sig = base64.b64encode(key.sign(manifest._canon(body))).decode()
    data = json.dumps({"body": body, "signature_ed25519_b64": sig}, indent=1).encode()
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
    path = COVERAGE_DIR / f"coverage_manifest_v{version:03d}.json"
    with open(path, "xb") as f:
        f.write(data)
    cur = conn.execute(
        "INSERT INTO coverage_manifests(version,created_utc,author,approval_status,baseline_acquisition_id,expected_contest_count,"
        "expected_source_count,manifest_sha256,path,signature_b64,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (version, body["created_utc"], author, body["approval_status"], acquisition_id, len(contests), len(config.SOURCES),
         hashlib.sha256(data).hexdigest(), path.name, sig, notes))
    custody.append(conn, evidence_kind="package", evidence_id=cur.lastrowid, event_type="COVERAGE_MANIFEST_SIGNED",
                   actor=author, reason=f"v{version}: {len(contests)} expected NM contests from baseline acquisition {acquisition_id}; "
                   f"all-zero={all_zero}", artifact_sha256=hashlib.sha256(data).hexdigest(), new_state=body["approval_status"])
    return {"cov_id": cur.lastrowid, "version": version, "contests": len(contests), "all_zero": all_zero, "path": str(path)}


def _load(conn, cov):
    return json.loads((COVERAGE_DIR / cov["path"]).read_bytes())["body"]


def _event(conn, cov_id, kind, contest_id, source_id, detail, key, acq_id):
    last = conn.execute("SELECT kind FROM coverage_events WHERE detail_key=? ORDER BY event_id DESC LIMIT 1", (key,)).fetchone()
    if last and last["kind"] == kind:
        return False   # already recorded; don't flood
    conn.execute("INSERT INTO coverage_events(created_utc,cov_id,kind,contest_id,source_id,detail,detail_key,acquisition_id) VALUES (?,?,?,?,?,?,?,?)",
                 (now_utc(), cov_id, kind, contest_id, source_id, detail, key, acq_id))
    if kind != "COVERAGE_RESTORED":
        conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)", (now_utc(), source_id, kind, detail))
    return True


def check_and_record(conn, acquisition_id: int):
    """Compare a newly parsed primary export with the baseline; record gaps/unexpected/changed items as events + alerts."""
    cov = latest(conn)
    if not cov or acquisition_id == cov["baseline_acquisition_id"]:
        return 0
    body = _load(conn, cov)
    expected = {c["contest_id"]: c for c in body["expected_nm_contests"]}
    now_map = _contest_map(conn, acquisition_id)
    n = 0
    for cid, ec in expected.items():
        if cid not in now_map:
            n += _event(conn, cov["cov_id"], "COVERAGE_GAP", cid, config.PRIMARY_SOURCE_ID,
                        f"expected contest missing from export: {ec['race_name']} {ec['area'] or ''}".strip(), f"GAP:{cid}", acquisition_id)
        else:
            _event(conn, cov["cov_id"], "COVERAGE_RESTORED", cid, config.PRIMARY_SOURCE_ID, "contest present again", f"GAP:{cid}", acquisition_id) \
                if conn.execute("SELECT 1 FROM coverage_events WHERE detail_key=? LIMIT 1", (f"GAP:{cid}",)).fetchone() else None
            if _cand_key(now_map[cid]) != _cand_key(ec):
                n += _event(conn, cov["cov_id"], "BASELINE_CHANGE", cid, config.PRIMARY_SOURCE_ID,
                            f"candidate/choice list differs from baseline for {ec['race_name']} {ec['area'] or ''}".strip(),
                            f"BC:{cid}:{hashlib.sha256(_cand_key(now_map[cid]).encode()).hexdigest()[:12]}", acquisition_id)
    for cid, c in now_map.items():
        if cid not in expected:
            n += _event(conn, cov["cov_id"], "UNEXPECTED_DISCOVERY", cid, config.PRIMARY_SOURCE_ID,
                        f"contest not in coverage manifest: {c['race_name']} {c['area'] or ''}".strip(), f"UX:{cid}", acquisition_id)
    return n


def evaluate(conn) -> dict:
    """Real-time completeness accounting (REQ-COMP-002/003)."""
    from . import queries
    cov = latest(conn)
    health = {h["source_id"]: h for h in queries.source_health(conn)}
    out = {"coverage_manifest": None, "sources": {}, "contests": {}, "national_federal": None, "events": []}
    src_counts = {"EXPECTED": 0, "CONFIGURED": 0, "VERIFIED": 0, "ACTIVE": 0, "HEALTHY": 0, "DEGRADED": 0, "FAILED": 0, "NOT_STARTED": 0}
    for s in config.SOURCES:
        h = health[s["source_id"]]
        states = ["EXPECTED", "CONFIGURED"]           # all sources are in the registry
        if h["state"] == "NOT_YET_POLLED":
            states.append("NOT_STARTED")
        else:
            states.append("ACTIVE")
            states.append("HEALTHY" if h["state"] == "OK" else "DEGRADED" if h["consecutive_failures"] < 5 else "FAILED")
        for st in states:
            src_counts[st] += 1
        out["sources"][s["source_id"]] = {"states": states, "verified": False,
                                          "verified_note": "no Source Authority Record has been independently reviewed"}
    out["source_counts"] = src_counts
    # National completeness dashboard (matrix): every expected jurisdiction is accounted for, none silently omitted.
    jur = {"expected": len(config.JURISDICTIONS), "by_matrix_status": {}, "collecting_entry_page": 0, "degraded": 0, "no_source": 0,
           "authority_verified": 0, "production_approved": 0, "no_source_list": []}
    for j in config.JURISDICTIONS:
        jur["by_matrix_status"][j["matrix_status"]] = jur["by_matrix_status"].get(j["matrix_status"], 0) + 1
        hs = [health.get(sid, {"state": "NOT_YET_POLLED"})["state"] for sid in (j["entry_sources"] or ([config.PRIMARY_SOURCE_ID] if j["jurisdiction"] == "NM" else []))]
        if not hs:
            jur["no_source"] += 1
            jur["no_source_list"].append(j["jurisdiction"])
        elif "OK" in hs:
            jur["collecting_entry_page"] += 1
        else:
            jur["degraded"] += 1
    out["jurisdictions"] = jur
    if not cov:
        out["coverage_manifest"] = None
        out["contest_counts"] = None
        return out
    body = _load(conn, cov)
    out["coverage_manifest"] = {"cov_id": cov["cov_id"], "version": cov["version"], "approval_status": cov["approval_status"],
                                "created_utc": cov["created_utc"], "baseline_acquisition_id": cov["baseline_acquisition_id"],
                                "baseline_all_zero": body["baseline"]["all_vote_counts_zero"], "baseline_note": body["baseline"]["lead_time_note"]}
    out["national_federal"] = body["expected_national_federal_contests"]
    acq = queries.latest_parsed_acquisition(conn, config.PRIMARY_SOURCE_ID, None)
    now_map = _contest_map(conn, acq["acquisition_id"]) if acq else {}
    primary_ok = health.get(config.PRIMARY_SOURCE_ID, {"state": "OK"})["state"] == "OK"
    counts = {"EXPECTED": len(body["expected_nm_contests"]), "ACTIVE": 0, "HEALTHY": 0, "DEGRADED": 0, "MISSING_GAP": 0, "UNEXPECTED_DISCOVERY": 0}
    gaps = []
    for ec in body["expected_nm_contests"]:
        if ec["contest_id"] in now_map:
            counts["ACTIVE"] += 1
            counts["HEALTHY" if primary_ok else "DEGRADED"] += 1
        else:
            counts["MISSING_GAP"] += 1
            gaps.append({"contest_id": ec["contest_id"], "race_name": ec["race_name"], "area": ec["area"]})
    exp_ids = {c["contest_id"] for c in body["expected_nm_contests"]}
    unexpected = [{"contest_id": c, "race_name": now_map[c]["race_name"], "area": now_map[c]["area"]} for c in now_map if c not in exp_ids]
    counts["UNEXPECTED_DISCOVERY"] = len(unexpected)
    out["contest_counts"], out["contest_gaps"], out["unexpected"] = counts, gaps, unexpected
    out["events"] = [dict(r) for r in conn.execute("SELECT * FROM coverage_events ORDER BY event_id DESC LIMIT 50")]
    return out

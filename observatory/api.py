"""Read-only tracker API (spec 12.1 subset). Opens the database read-only: it cannot alter evidence."""
import json
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response

from . import VERSION, archive, config, coverage, evidence, queries

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="Election Information Observatory", version=VERSION)


def db():
    conn = sqlite3.connect(f"file:{config.DB_PATH.as_posix()}?mode=ro", uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


@app.get("/api/elections")
def elections():
    return [{"election_id": config.ELECTION_ID, "label": config.ELECTION_LABEL,
             "status_banner": "UNOFFICIAL RESULTS - subject to canvass and certification"}]


@app.get("/api/elections/{election_id}")
def election(election_id: str):
    if election_id != config.ELECTION_ID:
        raise HTTPException(404, "unknown election")
    conn = db()
    try:
        times = queries.change_times(conn)
        health = queries.source_health(conn)
        last_ok = max((h["last_success_utc"] for h in health if h["last_success_utc"]), default=None)
        stamp = conn.execute(
            "SELECT displayed_text, displayed_iso_utc, observed_at_utc FROM page_stamps ORDER BY stamp_id DESC LIMIT 1").fetchone()
        alerts = conn.execute("SELECT * FROM alerts ORDER BY alert_id DESC LIMIT 10").fetchall()
        return {
            "election_id": election_id, "label": config.ELECTION_LABEL, "status": "UNOFFICIAL",
            "first_observation_utc": times[0] if times else None, "last_observation_utc": times[-1] if times else None,
            "observation_count": len(times), "last_successful_collection_utc": last_ok,
            "last_official_displayed_update": dict(stamp) if stamp else None,
            "sources_ok": sum(h["state"] == "OK" for h in health), "sources_total": len(health),
            "sources_degraded": [h["source_id"] for h in health if h["state"] == "DEGRADED"],
            "recent_alerts": [dict(a) for a in alerts],
        }
    finally:
        conn.close()


@app.get("/api/elections/{election_id}/contests")
def contests(election_id: str, as_of: str | None = None, source_id: str | None = None):
    conn = db()
    try:
        sid = source_id or config.PRIMARY_SOURCE_ID
        acq, cs = queries.contests_as_of(conn, sid, as_of)
        obs = queries.observation_status(conn, sid, as_of)   # REQ-OBS-003: say what we could and could not observe
        if not acq:
            return {"as_of": as_of, "no_observation": True, "observation": obs, "contests": []}
        return {"as_of": as_of, "no_observation": False, "acquisition_id": acq["acquisition_id"],
                "acquired_at_utc": acq["response_received_utc"], "observation": obs, "poll_close": config.POLL_CLOSE,
                "evidence": evidence.evidence_level(conn, acq["acquisition_id"]), "contests": cs}
    finally:
        conn.close()


@app.get("/api/observation-times")
def observation_times():
    conn = db()
    try:
        return {"source_id": config.PRIMARY_SOURCE_ID, "times": queries.change_times(conn)}
    finally:
        conn.close()


@app.get("/api/contests/{contest_id}/current")
def contest_current(contest_id: str, as_of: str | None = None):
    conn = db()
    try:
        acq, cs = queries.contests_as_of(conn, config.PRIMARY_SOURCE_ID, as_of, contest_id)
        if not cs:
            raise HTTPException(404, "no observation of this contest at that time")
        return cs[0]
    finally:
        conn.close()


@app.get("/api/contests/{contest_id}/timeline")
def contest_timeline(contest_id: str):
    conn = db()
    try:
        return queries.contest_timeline(conn, contest_id)
    finally:
        conn.close()


@app.get("/api/contests/{contest_id}/sources")
def contest_sources(contest_id: str, as_of: str | None = None):
    conn = db()
    try:
        return queries.contest_sources(conn, contest_id, as_of)
    finally:
        conn.close()


@app.get("/api/contests/{contest_id}/changes")
def contest_changes(contest_id: str, t_from: str, t_to: str):
    conn = db()
    try:
        return queries.changes_between(conn, config.PRIMARY_SOURCE_ID, t_from, t_to, contest_id)
    finally:
        conn.close()


@app.get("/api/changes")
def changes(t_from: str, t_to: str):
    conn = db()
    try:
        return queries.changes_between(conn, config.PRIMARY_SOURCE_ID, t_from, t_to)
    finally:
        conn.close()


@app.get("/api/contests/{contest_id}/calls")
def contest_calls(contest_id: str):
    # Race-call ingestion (AP / media) is not part of this slice; calls would live in their own table.
    return {"contest_id": contest_id, "calls": [], "note": "No race-call sources are connected yet."}


@app.get("/api/sources")
def sources():
    return [{k: v for k, v in s.items()} for s in config.SOURCES]


@app.get("/api/sources/health")
def sources_health():
    conn = db()
    try:
        return queries.source_health(conn)
    finally:
        conn.close()


@app.get("/api/alerts")
def alerts(limit: int = Query(50, le=500)):
    conn = db()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY alert_id DESC LIMIT ?", (limit,))]
    finally:
        conn.close()


@app.get("/api/artifacts/{acquisition_id}/metadata")
def artifact_metadata(acquisition_id: int):
    conn = db()
    try:
        a = conn.execute("SELECT * FROM acquisitions WHERE acquisition_id=?", (acquisition_id,)).fetchone()
        if not a:
            raise HTTPException(404, "unknown acquisition")
        d = dict(a)
        d["redirect_chain"] = json.loads(d["redirect_chain"] or "[]")
        d["response_headers"] = json.loads(d["response_headers"] or "{}")
        d["parse_runs"] = [dict(r) for r in conn.execute("SELECT * FROM parse_runs WHERE acquisition_id=?", (acquisition_id,))]
        d["validation_findings"] = [dict(r) for r in conn.execute(
            "SELECT severity,code,detail FROM validation_findings WHERE acquisition_id=? LIMIT 200", (acquisition_id,))]
        d["previous_acquisition_id"] = (conn.execute(
            "SELECT MAX(acquisition_id) m FROM acquisitions WHERE source_id=? AND acquisition_id<?", (a["source_id"], acquisition_id)).fetchone()["m"])
        d["next_acquisition_id"] = (conn.execute(
            "SELECT MIN(acquisition_id) m FROM acquisitions WHERE source_id=? AND acquisition_id>?", (a["source_id"], acquisition_id)).fetchone()["m"])
        d["source"] = config.SOURCES_BY_ID.get(a["source_id"])
        d["integrity_ok"] = archive.verify(a["sha256"]) if a["sha256"] else None
        d["raw_url"] = f"/api/artifacts/{acquisition_id}/raw" if a["sha256"] else None
        d["evidence_level"] = evidence.evidence_level(conn, acquisition_id)
        d["predicates_url"] = f"/api/artifacts/{acquisition_id}/predicates"
        d["structured_times"] = evidence.structured_times(conn, a)
        d.pop("restricted_path", None)   # sensitive-tier locator is never served by the public API
        return d
    finally:
        conn.close()


@app.get("/api/artifacts/{acquisition_id}/predicates")
def artifact_predicates(acquisition_id: int):
    conn = db()
    try:
        if not conn.execute("SELECT 1 FROM acquisitions WHERE acquisition_id=?", (acquisition_id,)).fetchone():
            raise HTTPException(404, "unknown acquisition")
        return evidence.evidence_predicates(conn, acquisition_id)
    finally:
        conn.close()


@app.get("/api/observation-status")
def observation_status_all():
    conn = db()
    try:
        return [queries.observation_status(conn, s["source_id"]) for s in config.SOURCES]
    finally:
        conn.close()


def _jur_sources(health: dict, j: dict) -> list:
    ids = j["entry_sources"] or ([s["source_id"] for s in config.SOURCES if s.get("jurisdiction") == "NM"] if j["jurisdiction"] == "NM" else [])
    return [health[i] for i in ids if i in health]


@app.get("/api/jurisdictions")
def jurisdictions():
    """Compact one-row-per-election summary for the selector/overview. Deliberately small: no per-contest data."""
    conn = db()
    try:
        health = {h["source_id"]: h for h in queries.source_health(conn)}
        out = []
        for j in config.JURISDICTIONS:
            hs = _jur_sources(health, j)
            ok = [h for h in hs if h["state"] == "OK"]
            polled = [h for h in hs if h["state"] != "NOT_YET_POLLED"]
            last = max((h["last_success_utc"] for h in hs if h["last_success_utc"]), default=None)
            chg = max((h["last_change_utc"] for h in hs if h["last_change_utc"]), default=None)
            out.append(dict(jurisdiction=j["jurisdiction"], name=j["name"], matrix_status=j["matrix_status"], tracker_depth=j["tracker_depth"],
                            federal_coverage=j["federal_coverage"], sources=len(hs), sources_ok=len(ok),
                            collection=("NO_SOURCE" if not hs else "OK" if ok and len(ok) == len(hs) else "PARTIAL" if ok else
                                        "NOT_YET_POLLED" if not polled else "DEGRADED"),
                            results_parsed=(j["jurisdiction"] == "NM"), last_success_utc=last, last_change_utc=chg))
        return out
    finally:
        conn.close()


@app.get("/api/jurisdictions/{jur}")
def jurisdiction_detail(jur: str):
    conn = db()
    try:
        j = next((x for x in config.JURISDICTIONS if x["jurisdiction"] == jur.upper()), None)
        if not j:
            raise HTTPException(404, "unknown jurisdiction")
        health = {h["source_id"]: h for h in queries.source_health(conn)}
        srcs = []
        for h in _jur_sources(health, j):
            s = config.SOURCES_BY_ID[h["source_id"]]
            la = conn.execute("SELECT acquisition_id, sha256, content_length FROM acquisitions WHERE source_id=? AND sha256 IS NOT NULL "
                              "AND error_class IS NULL ORDER BY acquisition_id DESC LIMIT 1", (h["source_id"],)).fetchone()
            recent = [dict(acquisition_id=r["acquisition_id"], at=r["response_received_utc"], changed=bool(r["content_changed"]),
                           http_status=r["http_status"], error_class=r["error_class"])
                      for r in conn.execute("SELECT acquisition_id,response_received_utc,content_changed,http_status,error_class FROM acquisitions "
                                            "WHERE source_id=? ORDER BY acquisition_id DESC LIMIT 8", (h["source_id"],))]
            srcs.append(dict(health=h, url=s["endpoint_url"], classification=s.get("source_classification"), role=s.get("role"),
                             parser=s["parser_name"], publication_status=s.get("publication_status"),
                             latest_acquisition_id=la["acquisition_id"] if la else None, latest_bytes=la["content_length"] if la else None,
                             latest_evidence=evidence.evidence_level(conn, la["acquisition_id"]) if la else None, recent=recent))
        return dict(jurisdiction=j["jurisdiction"], name=j["name"], matrix_status=j["matrix_status"], tracker_depth=j["tracker_depth"],
                    federal_coverage=j["federal_coverage"], results_parsed=(j["jurisdiction"] == "NM"), sources=srcs,
                    note=("Full contest-level tracking (see the tabs)." if j["jurisdiction"] == "NM" else
                          "Source pages are archived byte-exact. The race totals below are a DERIVED view computed from the latest archived statewide CSV by a new "
                          "parser, not stored as evidence records; the archived file is the evidence." if j["jurisdiction"] == "AK" else
                          "Entry pages are archived byte-exact but NOT parsed: no vote counts, no seat tally. Source official status is unverified. "
                          "'Content changes' on these pages include page noise (tokens, scripts, timestamps), not just result changes."
                          if srcs else "No source has been identified or reached for this jurisdiction; nothing is being collected."))
    finally:
        conn.close()


@app.get("/api/results/AK")
def results_ak():
    from . import ak_results
    conn = db()
    try:
        return ak_results.latest(conn)
    except ValueError as e:
        return {"available": False, "reason": str(e)}
    finally:
        conn.close()


@app.get("/api/news")
def news(limit: int = Query(100, le=500), election_only: bool = True, source: str | None = None, q: str | None = None,
         kind: str | None = None):
    """Media/press CONTEXT. Newest first by the feed's own publication time, falling back to first-seen time."""
    conn = db()
    try:
        where, args = [], []
        if election_only:
            where.append("n.election_related=1")
        if source:
            where.append("n.source_id=?"); args.append(source)
        if q:
            where.append("(n.title LIKE ? OR n.summary LIKE ?)"); args += [f"%{q}%", f"%{q}%"]
        rows = conn.execute(
            "SELECT n.* FROM news_items n " + ("WHERE " + " AND ".join(where) if where else "") +
            " ORDER BY COALESCE(n.published_utc, n.first_seen_utc) DESC LIMIT ?", (*args, limit * 3 if kind else limit)).fetchall()
        out = []
        for r in rows:
            s = config.SOURCES_BY_ID.get(r["source_id"], {})
            k = "official" if "OFFICIAL_PRESS_RELEASES" in (s.get("source_classification") or []) else "media"
            if kind and kind != k:
                continue
            out.append(dict(r) | dict(outlet=s.get("source_name", r["source_id"]).replace("News/press feed - ", ""), kind=k))
        return {"context_only": True,
                "notice": "Media and press reporting, shown as context. Not official results, not verified by this system, and never used in any tally or race call.",
                "items": out[:limit]}
    finally:
        conn.close()


@app.get("/api/news/sources")
def news_sources():
    conn = db()
    try:
        health = {h["source_id"]: h for h in queries.source_health(conn)}
        out = []
        for s in config.NEWS_SOURCES:
            h = health[s["source_id"]]
            n = conn.execute("SELECT COUNT(*) c, SUM(election_related) e FROM news_items WHERE source_id=?", (s["source_id"],)).fetchone()
            out.append(dict(source_id=s["source_id"], outlet=s["source_name"].replace("News/press feed - ", ""), url=s["endpoint_url"],
                            kind="official" if "OFFICIAL_PRESS_RELEASES" in s["source_classification"] else "media",
                            state=h["state"], last_success_utc=h["last_success_utc"], interval_s=h["interval_s"],
                            items=n["c"], election_items=n["e"] or 0))
        return out
    finally:
        conn.close()


@app.get("/api/crosscheck")
def crosscheck_state(detail: bool = False):
    from . import crosscheck
    conn = db()
    try:
        return crosscheck.run_all(conn, detail)
    finally:
        conn.close()


@app.get("/api/coverage")
def coverage_state():
    conn = db()
    try:
        return coverage.evaluate(conn)
    finally:
        conn.close()


@app.get("/api/evidence/summary")
def evidence_summary():
    conn = db()
    try:
        from . import manifest
        return {**evidence.evidence_summary(conn), "sequence_gaps": manifest.audit_gaps(conn)}
    finally:
        conn.close()


@app.get("/api/clock")
def clock_status():
    conn = db()
    try:
        return [dict(r) for r in conn.execute("SELECT clock_id,sampled_utc,host,offset_ms,uncertainty_ms,spread_ms,state,tolerance_ms FROM clock_status ORDER BY clock_id DESC LIMIT 30")]
    finally:
        conn.close()


@app.get("/api/endpoint")
def endpoint_status():
    conn = db()
    try:
        rows = conn.execute("SELECT obs_id,observed_utc,host,tls_version,cipher,cert_sha256,cert_subject,cert_issuer,cert_not_after,validation_result,"
                            "anomalies_json,chain_status,probe_kind FROM endpoint_observations ORDER BY obs_id DESC LIMIT 20").fetchall()
        return [dict(r) for r in rows]   # network identifiers (IPs, resolvers) are SECURITY-tier and not served here
    finally:
        conn.close()


@app.get("/api/authority")
def authority_record():
    conn = db()
    try:
        r = conn.execute("SELECT * FROM source_authority_records ORDER BY sar_id DESC LIMIT 1").fetchone()
        return {"sar_id": r["sar_id"], "version": r["version"], "approval_status": r["approval_status"], "record": json.loads(r["record_json"])} if r else None
    finally:
        conn.close()


@app.get("/api/qualification")
def qualification_latest():
    conn = db()
    try:
        r = conn.execute("SELECT * FROM qualification_records ORDER BY qual_id DESC LIMIT 1").fetchone()
        if not r:
            return {"status": "NO_QUALIFICATION_RECORD", "authorization_status": "NOT_AUTHORIZED"}
        return {"created_utc": r["created_utc"], "authorization_status": r["authorization_status"], "summary": json.loads(r["summary_json"]),
                "sha256": r["record_sha256"]}
    finally:
        conn.close()


@app.get("/api/artifacts/{acquisition_id}/raw")
def artifact_raw(acquisition_id: int):
    conn = db()
    try:
        a = conn.execute("SELECT sha256, content_type, source_id FROM acquisitions WHERE acquisition_id=?", (acquisition_id,)).fetchone()
    finally:
        conn.close()
    if not a or not a["sha256"]:
        raise HTTPException(404, "no artifact")
    ext = {"csv": "csv", "xml": "xml", "pdf": "pdf"}.get(config.SOURCES_BY_ID[a["source_id"]]["expected_format"], "html")
    return Response(archive.read(a["sha256"]), media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{a["source_id"]}_{acquisition_id}_{a["sha256"][:12]}.{ext}"'})


@app.get("/api/manifests")
def manifests():
    conn = db()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM manifests ORDER BY manifest_id DESC LIMIT 100")]
    finally:
        conn.close()


@app.get("/api/about")
def about():
    return {
        "version": VERSION,
        "scope": "New Mexico 2026 general election, official unofficial returns from the NM Secretary of State only.",
        "not_connected": ["Associated Press", "national media", "local media", "race calls", "county canvass/certification",
                          "federal contests outside New Mexico", "browser/rendered-page capture"],
        "notes": [
            "A 'numeric delta' is the difference between two observed totals. It is not asserted to be 'new votes' unless the source's semantics support that.",
            "A gap in observation (failed or missing attempts) is shown as a gap; it is never displayed as 'observed, unchanged'.",
            "Evidence badges (E0-E4) and the listed predicates describe how well a capture is preserved and timestamped; they say nothing about whether the content is correct.",
            "Poll-close time shown is operator-entered statutory hours, not verified against an official artifact; the tracker does not infer that polls are closed from the clock alone.",
            "All values are UNOFFICIAL until canvass and certification.",
            "Percentages shown are derived from vote totals; the source's own percentage text is retained in evidence.",
            "Precinct 'n/m' is the source's reporting measure; it is not a share of ballots counted.",
            "A difference between exports or times is not an error finding; it may be latency or scope.",
        ],
    }


@app.get("/")
def index():
    return FileResponse(WEB_DIR / "index.html")

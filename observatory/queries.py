"""Read-side logic: as-of reconstruction, deltas, source comparison, health.

Every state is rebuilt from acquisitions with response_received_utc <= as_of, so later
information can never leak into a historical view (spec 6.5).
"""
import json
from datetime import datetime, timezone

from . import config

FAR_FUTURE = "9999-12-31T23:59:59.999Z"


def _iso_ms(s: str | None) -> str:
    """Normalise an API-supplied timestamp to the stored format (UTC, ms, Z)."""
    if not s:
        return FAR_FUTURE
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def observation_status(conn, source_id: str, as_of: str | None = None) -> dict:
    """What do we actually know about this source at as_of? (addendum 003 REQ-OBS-003)

    A failed or missing attempt is never presented as 'observed, unchanged'. Returns the latest attempt's status, how long
    the source has been unobserved, and the last good observation that any displayed value actually comes from.
    """
    t = _iso_ms(as_of)
    src = config.SOURCES_BY_ID[source_id]
    interval = src["polling_interval_s"] * config.INTERVAL_SCALE
    last = conn.execute("SELECT * FROM acquisitions WHERE source_id=? AND response_received_utc<=? ORDER BY acquisition_id DESC LIMIT 1",
                        (source_id, t)).fetchone()
    good = conn.execute("SELECT * FROM acquisitions WHERE source_id=? AND response_received_utc<=? AND error_class IS NULL "
                        "AND sha256 IS NOT NULL ORDER BY acquisition_id DESC LIMIT 1", (source_id, t)).fetchone()
    now_ref = datetime.fromisoformat(t.replace("Z", "+00:00")) if as_of else datetime.now(timezone.utc)
    out = {"source_id": source_id, "status": "NOT_YET_OBSERVED", "latest_attempt_utc": None, "last_good_observation_utc": None,
           "last_good_acquisition_id": None, "unobserved_since_utc": None, "unobserved_for_s": None, "attempt_failure": None}
    # how many byte-different versions vs result-different versions were seen recently? (flapping presentation / backend instances)
    rv = conn.execute(
        "SELECT COUNT(DISTINCT a.sha256) b, COUNT(DISTINCT f.fingerprint) r FROM (SELECT * FROM acquisitions WHERE source_id=? AND sha256 IS NOT NULL "
        "AND error_class IS NULL AND response_received_utc<=? ORDER BY acquisition_id DESC LIMIT 120) a "
        "LEFT JOIN result_fingerprints f ON f.acquisition_id=a.acquisition_id", (source_id, t)).fetchone()
    out["recent_byte_versions"], out["recent_result_versions"] = rv["b"], rv["r"]
    if good:
        out.update(last_good_observation_utc=good["response_received_utc"], last_good_acquisition_id=good["acquisition_id"])
    if not last:
        return out
    out.update(latest_attempt_utc=last["response_received_utc"], status=last["observation_status"] or ("OBSERVED_CHANGED" if not last["error_class"] else "OBSERVATION_FAILED"),
               attempt_failure=last["error_class"])
    if last["error_class"]:
        first_bad = conn.execute("SELECT MIN(response_received_utc) m FROM acquisitions WHERE source_id=? AND acquisition_id>? AND response_received_utc<=?",
                                 (source_id, good["acquisition_id"] if good else 0, t)).fetchone()["m"]
        out["unobserved_since_utc"] = first_bad
        out["unobserved_for_s"] = round((now_ref - _parse(first_bad)).total_seconds(), 1) if first_bad else None
    else:
        age = (now_ref - _parse(last["response_received_utc"])).total_seconds()
        if age > 3 * interval + 90:
            # no attempt record for far longer than the schedule: the collector itself may not have been running
            out.update(status="OBSERVATION_INDETERMINATE", unobserved_since_utc=last["response_received_utc"], unobserved_for_s=round(age, 1))
    return out


def latest_parsed_acquisition(conn, source_id: str, as_of: str | None):
    """Latest successfully parsed acquisition for a source at or before as_of."""
    return conn.execute(
        "SELECT a.* FROM acquisitions a JOIN parse_runs p ON p.acquisition_id=a.acquisition_id AND p.status='OK' "
        "WHERE a.source_id=? AND a.response_received_utc<=? ORDER BY a.acquisition_id DESC LIMIT 1",
        (source_id, _iso_ms(as_of)),
    ).fetchone()


def _contest_from_rows(rows, acq):
    first = rows[0]
    cands = []
    for r in rows:
        cands.append(dict(
            candidate_id=r["source_candidate_id"], name=r["candidate_name"], party=r["party_code"],
            votes=r["votes"], source_pct_text=r["source_pct_text"],
            votes_absentee=r["votes_absentee"], votes_election_day=r["votes_election_day"], votes_early=r["votes_early"],
            # REQ-DATA-001: a blank in the source is NOT_PUBLISHED, never silently zero
            breakdown_state={k: ("NOT_PUBLISHED" if r[col] is None else "ZERO" if r[col] == 0 else "VALUE")
                             for k, col in (("early", "votes_early"), ("absentee", "votes_absentee"), ("election_day", "votes_election_day"))},
        ))
    total = sum(c["votes"] or 0 for c in cands)
    for c in cands:
        c["pct"] = round(100.0 * c["votes"] / total, 2) if total else None   # DERIVED, not the source's number
    cands.sort(key=lambda c: (-(c["votes"] or 0), c["name"]))
    leader = margin = margin_pp = None
    if total and cands:
        top = cands[0]
        tied = len(cands) > 1 and cands[1]["votes"] == top["votes"]
        leader = None if tied else top["name"]
        if len(cands) > 1:
            margin = top["votes"] - cands[1]["votes"]
            margin_pp = round(100.0 * margin / total, 2)
    return dict(
        contest_id=first["contest_id"], source_race_id=first["source_race_id"], title=first["race_name"],
        area=first["area"], vote_for=first["vote_for"], candidates=cands, total_votes=total,
        leader=leader, margin_votes=margin, margin_pp=margin_pp,
        precincts_label=first["precincts_label"], precincts_reporting=first["precincts_reporting"],
        precincts_total=first["precincts_total"],
        status="UNOFFICIAL", source_id=first["source_id"], acquisition_id=acq["acquisition_id"],
        acquired_at_utc=acq["response_received_utc"], sha256=acq["sha256"],
    )


def contests_as_of(conn, source_id: str, as_of: str | None, contest_id: str | None = None):
    acq = latest_parsed_acquisition(conn, source_id, as_of)
    if not acq:
        return None, []
    sql = "SELECT * FROM vote_obs WHERE acquisition_id=?"
    args = [acq["acquisition_id"]]
    if contest_id:
        sql += " AND contest_id=?"
        args.append(contest_id)
    by = {}
    for r in conn.execute(sql + " ORDER BY obs_id", args):
        by.setdefault(r["contest_id"], []).append(r)
    return acq, [_contest_from_rows(rows, acq) for rows in by.values()]


def change_times(conn, source_id: str | None = None):
    """Timestamps at which the primary source's content changed and parsed OK (slider stops)."""
    sid = source_id or config.PRIMARY_SOURCE_ID
    out, prev = [], None
    for r in conn.execute(
            "SELECT DISTINCT a.acquisition_id, a.response_received_utc, f.fingerprint FROM acquisitions a "
            "JOIN parse_runs p ON p.acquisition_id=a.acquisition_id AND p.status='OK' "
            "LEFT JOIN result_fingerprints f ON f.acquisition_id=a.acquisition_id WHERE a.source_id=? ORDER BY a.acquisition_id", (sid,)):
        fp = r["fingerprint"] or f"unfingerprinted-{r['acquisition_id']}"
        if fp != prev:          # only acquisitions whose RESULTS differ from the previous one are timeline stops
            out.append(r["response_received_utc"])
            prev = fp
    return out


def changes_between(conn, source_id: str, t_from: str, t_to: str, contest_id: str | None = None):
    """What changed between the states known at t_from and t_to (spec 6.6)."""
    a_acq, a = contests_as_of(conn, source_id, t_from, contest_id)
    b_acq, b = contests_as_of(conn, source_id, t_to, contest_id)
    a_map = {c["contest_id"]: c for c in a}
    out = []
    for c in b:
        prev = a_map.get(c["contest_id"])
        pv = {x["candidate_id"]: x["votes"] for x in prev["candidates"]} if prev else {}
        cand_changes = []
        for x in c["candidates"]:
            d = x["votes"] - pv.get(x["candidate_id"], 0)
            if d:
                cand_changes.append(dict(candidate=x["name"], party=x["party"], delta=d, votes=x["votes"]))
        # REQ-DELTA-001: this is a difference between two observed totals, not a count of "new votes".
        delta = c["total_votes"] - (prev["total_votes"] if prev else 0)
        lead_change = bool(prev and prev["leader"] != c["leader"] and (prev["total_votes"] or c["total_votes"]))
        reporting_change = bool(prev and prev["precincts_reporting"] != c["precincts_reporting"])
        # A decrease stays visible (never clamped to zero) and is flagged neutrally; we never call it an error.
        decreases = [x for x in cand_changes if x["delta"] < 0]
        # REQ-DELTA-002: cause is UNKNOWN_CAUSE unless the evidence supports more. The one supported inference here is
        # that a rise in the source's own precincts-reporting count accompanied an increase (a heuristic, labelled as such).
        if decreases or delta < 0:
            cause, basis = "UNKNOWN_CAUSE", "total or a candidate count decreased between observations"
        elif delta > 0 and reporting_change and prev and (c["precincts_reporting"] or 0) > (prev["precincts_reporting"] or 0):
            cause, basis = "NORMAL_COUNT_UPDATE", "heuristic: source's precincts-reporting count rose with the totals"
        elif delta > 0:
            cause, basis = "UNKNOWN_CAUSE", "totals rose without a change in the source's reporting counts"
        else:
            cause, basis = None, None
        if delta or reporting_change or lead_change or cand_changes:
            out.append(dict(
                contest_id=c["contest_id"], title=c["title"], area=c["area"],
                observed_numeric_delta=delta, delta_cause=cause, delta_cause_basis=basis,
                candidate_changes=cand_changes, lead_change=lead_change,
                prior_leader=prev["leader"] if prev else None, leader=c["leader"],
                margin_before=prev["margin_votes"] if prev else None, margin_after=c["margin_votes"],
                precincts_before=prev["precincts_label"] if prev else None, precincts_after=c["precincts_label"],
                possible_source_revision=bool(decreases),
            ))
    out.sort(key=lambda x: -abs(x["observed_numeric_delta"]))
    return dict(
        from_acquisition=a_acq["acquisition_id"] if a_acq else None,
        from_acquired_at=a_acq["response_received_utc"] if a_acq else None,
        to_acquisition=b_acq["acquisition_id"] if b_acq else None,
        to_acquired_at=b_acq["response_received_utc"] if b_acq else None,
        changes=out,
    )


def contest_timeline(conn, contest_id: str, source_id: str | None = None):
    """Per-acquisition totals for one contest (only acquisitions that parsed)."""
    sid = source_id or config.PRIMARY_SOURCE_ID
    rows = conn.execute(
        "SELECT acquisition_id, observed_at_utc, source_candidate_id, candidate_name, party_code, votes, precincts_label "
        "FROM vote_obs WHERE source_id=? AND contest_id=? ORDER BY acquisition_id, obs_id", (sid, contest_id)).fetchall()
    pts = {}
    for r in rows:
        p = pts.setdefault(r["acquisition_id"], dict(acquisition_id=r["acquisition_id"], t=r["observed_at_utc"],
                                                     precincts=r["precincts_label"], candidates={}, total=0))
        p["candidates"][r["candidate_name"]] = r["votes"]
        p["total"] += r["votes"] or 0
    return list(pts.values())


def contest_sources(conn, contest_id: str, as_of: str | None):
    """Same contest across every source that carries it, with a neutral comparison to the primary baseline."""
    out, base = [], None
    ids = [config.PRIMARY_SOURCE_ID] + [s["source_id"] for s in config.SOURCES
                                         if s["parser_name"] == "nm_sos_csv" and not s.get("primary")]
    for sid in ids:
        acq, cs = contests_as_of(conn, sid, as_of, contest_id)
        if not cs:
            continue
        c = cs[0]
        entry = dict(source_id=sid, source_name=config.SOURCES_BY_ID[sid]["source_name"], acquired_at_utc=c["acquired_at_utc"],
                     acquisition_id=c["acquisition_id"], total_votes=c["total_votes"], precincts_label=c["precincts_label"],
                     candidates={x["name"]: x["votes"] for x in c["candidates"]})
        if base is None:
            base = entry
            entry["comparison"] = "BASELINE"
        else:
            diffs = {n: v - base["candidates"].get(n, 0) for n, v in entry["candidates"].items()}
            if all(d == 0 for d in diffs.values()) and entry["precincts_label"] == base["precincts_label"]:
                entry["comparison"] = "MATCH"
            elif entry["acquired_at_utc"] != base["acquired_at_utc"]:
                # Different capture times: the difference may just be latency between polls.
                entry["comparison"] = "LATENCY_POSSIBLE"
            else:
                entry["comparison"] = "UNRESOLVED_DIFFERENCE"
            entry["diff_vs_baseline"] = diffs
            entry["seconds_after_baseline"] = round((_parse(entry["acquired_at_utc"]) - _parse(base["acquired_at_utc"])).total_seconds(), 1)
        out.append(entry)
    return out


def _parse(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def source_health(conn):
    now = datetime.now(timezone.utc)
    out = []
    for s in config.SOURCES:
        sid = s["source_id"]
        last = conn.execute("SELECT * FROM acquisitions WHERE source_id=? ORDER BY acquisition_id DESC LIMIT 1", (sid,)).fetchone()
        last_ok = conn.execute(
            "SELECT * FROM acquisitions WHERE source_id=? AND error_class IS NULL AND http_status<400 ORDER BY acquisition_id DESC LIMIT 1", (sid,)).fetchone()
        last_chg = conn.execute(
            "SELECT response_received_utc FROM acquisitions WHERE source_id=? AND content_changed=1 AND error_class IS NULL "
            "ORDER BY acquisition_id DESC LIMIT 1", (sid,)).fetchone()
        counts = conn.execute(
            "SELECT COUNT(*) n, SUM(error_class IS NOT NULL) errs, AVG(duration_ms) avg_ms, SUM(content_changed=1) changed "
            "FROM acquisitions WHERE source_id=?", (sid,)).fetchone()
        parse = conn.execute(
            "SELECT SUM(status='OK') ok, SUM(status='FAILED') failed FROM parse_runs p JOIN acquisitions a USING(acquisition_id) WHERE a.source_id=?",
            (sid,)).fetchone()
        consec = 0
        for r in conn.execute("SELECT error_class FROM acquisitions WHERE source_id=? ORDER BY acquisition_id DESC LIMIT 20", (sid,)):
            if r["error_class"]:
                consec += 1
            else:
                break
        stamp = conn.execute(
            "SELECT displayed_text, displayed_iso_utc FROM page_stamps WHERE source_id=? ORDER BY stamp_id DESC LIMIT 1", (sid,)).fetchone()
        age = (now - _parse(last_ok["response_received_utc"])).total_seconds() if last_ok else None
        interval = s["polling_interval_s"] * config.INTERVAL_SCALE
        if not last:
            state = "NOT_YET_POLLED"
        elif age is None or age > interval * config.STALE_AFTER_FACTOR or consec >= 2:
            state = "DEGRADED"
        else:
            state = "OK"
        skew = None
        if last_ok:
            try:
                h = json.loads(last_ok["response_headers"] or "{}")
                d = next((v for k, v in h.items() if k.lower() == "date"), None)
                if d:
                    from email.utils import parsedate_to_datetime
                    skew = round((_parse(last_ok["response_received_utc"]) - parsedate_to_datetime(d)).total_seconds(), 1)
            except Exception:
                skew = None
        out.append(dict(
            source_id=sid, source_name=s["source_name"], format=s["expected_format"], interval_s=interval, state=state,
            last_acquisition_utc=last["response_received_utc"] if last else None,
            last_success_utc=last_ok["response_received_utc"] if last_ok else None,
            last_change_utc=last_chg["response_received_utc"] if last_chg else None,
            success_age_s=round(age, 1) if age is not None else None,
            consecutive_failures=consec, polls=counts["n"], errors=counts["errs"] or 0, changes=counts["changed"] or 0,
            avg_duration_ms=round(counts["avg_ms"]) if counts["avg_ms"] else None,
            parse_ok=parse["ok"] or 0, parse_failed=parse["failed"] or 0,
            last_http_status=last["http_status"] if last else None,
            last_error=last["error_detail"] if last and last["error_class"] else None,
            displayed_update=stamp["displayed_text"] if stamp else None,
            displayed_update_utc=stamp["displayed_iso_utc"] if stamp else None,
            clock_skew_s_vs_server_date=skew,
            terms_review_status=s["terms_review_status"],
        ))
    return out

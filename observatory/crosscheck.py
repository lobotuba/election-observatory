"""New Mexico internal consistency check: narrower official exports vs the STATE baseline export.

Implements the classification from the State Election Authority Source Matrix ("NM INTERNAL CONSISTENCY RULE").
For each narrower export, its latest parsed acquisition is compared contest by contest with the primary (STATE) export
acquisitions that bracket it in time. If the primary changed between the two bracketing acquisitions, a differing contest is
VERSION_MISMATCH (the sources may simply have been captured at different publication versions) rather than VALUE_DIFFERENCE.

Not determinable without a category crosswalk (not yet defined): MISSING_FROM_SUBSET, because the primary legitimately
contains contests outside any one narrower export's category. Reported as a count of primary contests absent from the
subset ONLY informationally; it is never raised as a defect.
"""
from . import config

CLASSES = ["CONSISTENT", "VALUE_DIFFERENCE", "MISSING_FROM_STATE", "MISSING_FROM_SUBSET", "SCOPE_DIFFERENCE",
           "VERSION_MISMATCH", "PARSER_DIFFERENCE", "CROSSWALK_AMBIGUITY", "INDETERMINATE"]


def _contests(conn, acquisition_id: int) -> dict:
    out = {}
    for r in conn.execute("SELECT * FROM vote_obs WHERE acquisition_id=? ORDER BY obs_id", (acquisition_id,)):
        c = out.setdefault(r["contest_id"], dict(race_name=r["race_name"], area=r["area"], vote_for=r["vote_for"],
                                                 precincts=r["precincts_label"], parser=r["parser_version"], cands={}))
        c["cands"][r["source_candidate_id"]] = (r["candidate_name"], r["votes"])
    return out


def _parsed_acquisitions(conn, source_id: str):
    return conn.execute(
        "SELECT a.acquisition_id, a.response_received_utc t FROM acquisitions a JOIN parse_runs p ON p.acquisition_id=a.acquisition_id "
        "AND p.status='OK' WHERE a.source_id=? AND a.error_class IS NULL ORDER BY a.acquisition_id", (source_id,)).fetchall()


def _same(a: dict, b: dict) -> bool:
    return a["cands"] == b["cands"] and a["precincts"] == b["precincts"]


def _classify(sub: dict, st: dict | None, st_other: dict | None, by_name: dict) -> str:
    if st is None:
        key = (sub["race_name"], sub["area"])
        return "CROSSWALK_AMBIGUITY" if key in by_name else "MISSING_FROM_STATE"
    if sub["parser"] != st["parser"]:
        return "PARSER_DIFFERENCE"
    if set(sub["cands"]) != set(st["cands"]) or sub["vote_for"] != st["vote_for"] or sub["area"] != st["area"]:
        return "SCOPE_DIFFERENCE"
    if _same(sub, st):
        return "CONSISTENT"
    # differs from the earlier primary version; if the primary itself moved across the bracket, the capture times straddle a publication
    if st_other is not None and not _same(st, st_other):
        return "VERSION_MISMATCH"
    return "VALUE_DIFFERENCE"


def run(conn, source_id: str, detail: bool = False) -> dict:
    prim = _parsed_acquisitions(conn, config.PRIMARY_SOURCE_ID)
    subs = _parsed_acquisitions(conn, source_id)
    res = {"source_id": source_id, "classes": {c: 0 for c in CLASSES}, "contests": 0, "notes": []}
    if not prim or not subs:
        res["classes"]["INDETERMINATE"] = 1
        res["notes"].append("no parsed acquisition for the primary or the subset source")
        return res
    s = subs[-1]
    before = [p for p in prim if p["t"] <= s["t"]]
    after = [p for p in prim if p["t"] >= s["t"]]
    p_b = before[-1] if before else None
    p_a = after[0] if after else None
    if p_b is None and p_a is None:
        res["classes"]["INDETERMINATE"] = 1
        return res
    st_b = _contests(conn, p_b["acquisition_id"]) if p_b else None
    st_a = _contests(conn, p_a["acquisition_id"]) if p_a else None
    sub = _contests(conn, s["acquisition_id"])
    res.update(subset_acquisition_id=s["acquisition_id"], subset_acquired_utc=s["t"],
               primary_before=p_b and p_b["acquisition_id"], primary_after=p_a and p_a["acquisition_id"])
    primary_for_names = st_b or st_a
    by_name = {(c["race_name"], c["area"]): cid for cid, c in primary_for_names.items()}
    rows = []
    for cid, c in sub.items():
        # compare against the later bracketing primary version when both exist, so VERSION_MISMATCH can see a straddle
        st = (st_a or st_b).get(cid)
        other = (st_b or st_a).get(cid) if (st_a and st_b) else None
        k = _classify(c, st, other, by_name)
        if k == "VALUE_DIFFERENCE" and st_b and st_a:
            # matches the earlier version exactly => the subset was captured before the primary's newer publication
            sb = st_b.get(cid)
            if sb is not None and _same(c, sb) and not _same(sb, st_a.get(cid, sb)):
                k = "VERSION_MISMATCH"
        res["classes"][k] += 1
        if detail and k != "CONSISTENT":
            rows.append(dict(contest_id=cid, race_name=c["race_name"], area=c["area"], classification=k))
    res["contests"] = len(sub)
    res["primary_contests_absent_from_subset_informational"] = len(set(primary_for_names) - set(sub))
    if p_b and p_a and p_b["acquisition_id"] != p_a["acquisition_id"]:
        res["notes"].append("primary was captured on both sides of the subset capture")
    if detail:
        res["differences"] = rows
    return res


def run_all(conn, detail: bool = False) -> list:
    return [run(conn, s["source_id"], detail) for s in config.SOURCES
            if s["parser_name"] == "nm_sos_csv" and not s.get("primary")]

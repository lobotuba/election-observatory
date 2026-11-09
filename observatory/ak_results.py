"""Alaska: DERIVED statewide totals for the federal and governor contests, computed at request time from the latest archived
statewide precinct CSV. Nothing here is written to the evidence tables: the archived bytes remain the evidence, this is a view of
them. The Alaska parser is new, has not been rehearsed against a live count, and the meaning of Reporting_flag is inferred.
Ranked-choice (instant-runoff) tabulation is NOT computed; the file's votes are what the source publishes per candidate."""
import csv
import io

from . import archive

SOURCE_ID = "nat-ak-enr-statewide-precinct-csv"
SHOW = ("U.S. Senator", "U.S. Representative", "Governor / Lieutenant Governor")


def derive(data: bytes) -> dict:
    rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig", errors="replace"))))
    if not rows or "Contest_title" not in rows[0] or "total_votes" not in rows[0]:
        raise ValueError("unexpected Alaska CSV layout")
    contests = {}
    for r in rows:
        if r["Contest_title"] not in SHOW:
            continue
        c = contests.setdefault(r["Contest_Id"], dict(contest_id=r["Contest_Id"], title=r["Contest_title"], cands={}, pcts={}, ballots=0))
        key = r["candidate_id"]
        cand = c["cands"].setdefault(key, dict(name=r["candidate_name"], party=r["Party_Code"] or None, votes=0))
        cand["votes"] += int(r["total_votes"] or 0)
        c["pcts"][r["Pct_Id"]] = r["Reporting_flag"]
        if key == next(iter(c["cands"])):
            c["ballots"] += int(r["total_ballots"] or 0)
    out = []
    for c in contests.values():
        cands = sorted(c["cands"].values(), key=lambda x: -x["votes"])
        tot = sum(x["votes"] for x in cands)
        for x in cands:
            x["pct"] = round(100 * x["votes"] / tot, 2) if tot else None
        out.append(dict(contest_id=c["contest_id"], title=c["title"], total_votes=tot, ballots=c["ballots"], candidates=cands,
                        precincts_total=len(c["pcts"]), precincts_flagged_reporting=sum(1 for v in c["pcts"].values() if v not in ("", "0"))))
    out.sort(key=lambda c: SHOW.index(c["title"]))
    return dict(contests=out, all_contest_count=len({r["Contest_Id"] for r in rows}), rows=len(rows))


def latest(conn) -> dict:
    a = conn.execute("SELECT acquisition_id, response_received_utc, sha256, decoded_sha256, response_headers, http_status FROM acquisitions "
                     "WHERE source_id=? AND sha256 IS NOT NULL AND error_class IS NULL AND http_status<400 ORDER BY acquisition_id DESC LIMIT 1",
                     (SOURCE_ID,)).fetchone()
    if not a:
        return {"available": False, "reason": "no successful capture of the Alaska statewide CSV yet"}
    import json
    hdr = {k.lower(): v for k, v in json.loads(a["response_headers"] or "{}").items()}
    res = derive(archive.read(a["decoded_sha256"] or a["sha256"]))
    return dict(available=True, acquisition_id=a["acquisition_id"], captured_utc=a["response_received_utc"], artifact_sha256=a["sha256"],
                source_last_modified=hdr.get("last-modified"), raw_url=f"/api/artifacts/{a['acquisition_id']}/raw",
                caveats=["Derived from the archived CSV by a new, un-rehearsed parser; check against the source before relying on it.",
                         "Precinct 'reporting' is the source's own flag; its exact meaning is inferred, not documented.",
                         "Alaska uses ranked-choice voting for general-election contests; these are the published candidate vote totals, not a ranked-choice tabulation.",
                         "Unofficial results; not canvassed or certified."], **res)

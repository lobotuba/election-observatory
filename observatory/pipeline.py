"""Parse an already-archived acquisition into append-only observations."""
from . import archive, config
from .db import now_utc
from .parsers import PARSERS, SchemaError


FINGERPRINT_VERSION = 1


def compute_fingerprint(conn, acquisition_id: int):
    """Identity of the RESULT content of an acquisition: ids, party, candidate name, votes, the source's own precinct
    label and the vote-method counts. Free text (race names, ballot-question wording) is deliberately excluded, so two
    byte-different presentations of identical results compare equal. The bytes themselves are never altered or discarded."""
    import hashlib
    rows = conn.execute(
        "SELECT source_race_id, source_candidate_id, party_code, candidate_name, votes, precincts_label, votes_early, votes_absentee, votes_election_day "
        "FROM vote_obs WHERE acquisition_id=? ORDER BY source_race_id, source_candidate_id", (acquisition_id,)).fetchall()
    if not rows:
        return None, 0
    h = hashlib.sha256()
    for r in rows:
        h.update(("|".join("" if v is None else str(v) for v in tuple(r)) + "\n").encode())
    return h.hexdigest(), len(rows)


def store_fingerprint(conn, acquisition_id: int):
    fp, n = compute_fingerprint(conn, acquisition_id)
    if fp:
        conn.execute("INSERT OR IGNORE INTO result_fingerprints(acquisition_id,fingerprint,row_count,fingerprint_version,computed_utc) VALUES (?,?,?,?,?)",
                     (acquisition_id, fp, n, FINGERPRINT_VERSION, now_utc()))
    return fp


def parse_acquisition(conn, acquisition_id: int) -> dict:
    """Idempotent per (acquisition, parser_version): returns the outcome and records alerts on failure."""
    acq = conn.execute("SELECT * FROM acquisitions WHERE acquisition_id=?", (acquisition_id,)).fetchone()
    src = config.SOURCES_BY_ID[acq["source_id"]]
    parser_name, parser_version = src["parser_name"], src["parser_version"]

    done = conn.execute(
        "SELECT 1 FROM parse_runs WHERE acquisition_id=? AND parser_version=? AND status='OK'",
        (acquisition_id, parser_version),
    ).fetchone()
    if done:
        return {"status": "SKIPPED"}
    if not acq["sha256"] or (acq["http_status"] or 0) >= 400:
        return {"status": "NO_ARTIFACT"}

    started = now_utc()
    try:
        # parsers read the CONTENT layer (decoded if a Content-Encoding was applied); the entity bytes stay the original
        result = PARSERS[parser_name](archive.read(acq["decoded_sha256"] or acq["sha256"]))
        status, err = "OK", None
    except SchemaError as e:
        result, status, err = None, "FAILED", str(e)
    except Exception as e:  # parser bug: raw artifact stays archived and visible as unparsed
        result, status, err = None, "FAILED", f"{type(e).__name__}: {e}"

    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "INSERT INTO parse_runs(acquisition_id,parser_name,parser_version,started_utc,status,observation_count,error_detail)"
            " VALUES (?,?,?,?,?,?,?)",
            (acquisition_id, parser_name, parser_version, started, status,
             len(result.observations) if result else 0, err),
        )
        run_id = cur.lastrowid
        if result:
            for sev, code, detail in result.findings:
                conn.execute(
                    "INSERT INTO validation_findings(acquisition_id,parse_run_id,severity,code,detail,created_utc) VALUES (?,?,?,?,?,?)",
                    (acquisition_id, run_id, sev, code, detail, now_utc()),
                )
            rows = [
                (run_id, acquisition_id, acq["source_id"], config.ELECTION_ID,
                 f"{config.ELECTION_ID}:{o['source_race_id']}", o["source_race_id"], o["race_name"], o["area"],
                 o["party_code"], o["source_candidate_id"], o["candidate_name"], o["vote_for"], o["votes"],
                 o["source_pct_text"], o["precincts_label"], o["precincts_reporting"], o["precincts_total"],
                 o["votes_absentee"], o["votes_election_day"], o["votes_early"],
                 acq["response_received_utc"], parser_version, o["validation_state"])
                for o in result.observations
            ]
            conn.executemany(
                "INSERT INTO vote_obs(parse_run_id,acquisition_id,source_id,election_id,contest_id,source_race_id,race_name,area,"
                "party_code,source_candidate_id,candidate_name,vote_for,votes,source_pct_text,precincts_label,precincts_reporting,"
                "precincts_total,votes_absentee,votes_election_day,votes_early,observed_at_utc,parser_version,validation_state)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            for sev, code, detail in result.findings:
                if code == "ELECTION_IDENTITY_MISMATCH":
                    conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                                 (now_utc(), acq["source_id"], code, f"acquisition {acquisition_id}: {detail}"))
            if result.news_items:
                import hashlib
                conn.executemany(
                    "INSERT OR IGNORE INTO news_items(source_id,item_key,content_sha256,title,link,summary,published_text,published_utc,"
                    "election_related,first_seen_acquisition_id,first_seen_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    [(acq["source_id"], i["item_key"], hashlib.sha256((i["title"] + "\n" + (i["summary"] or "")).encode()).hexdigest(),
                      i["title"], i["link"], i["summary"], i["published_text"], i["published_utc"], i["election_related"],
                      acquisition_id, acq["response_received_utc"]) for i in result.news_items])
            if result.stamp:
                conn.execute(
                    "INSERT INTO page_stamps(acquisition_id,source_id,displayed_text,displayed_iso_utc,observed_at_utc) VALUES (?,?,?,?,?)",
                    (acquisition_id, acq["source_id"], result.stamp["displayed_text"],
                     result.stamp["displayed_iso_utc"], acq["response_received_utc"]),
                )
        else:
            kind = "SCHEMA_CHANGE" if err and ("header" in err or "empty" in err or "no data" in err) else "PARSER_FAILURE"
            conn.execute(
                "INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                (now_utc(), acq["source_id"], kind, f"acquisition {acquisition_id}: {err}"),
            )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    if status == "OK" and parser_name == "nm_sos_csv":
        try:
            fp = store_fingerprint(conn, acquisition_id)
            prev = conn.execute(
                "SELECT f.fingerprint FROM result_fingerprints f JOIN acquisitions a USING(acquisition_id) WHERE a.source_id=? AND f.acquisition_id<? "
                "ORDER BY f.acquisition_id DESC LIMIT 1", (acq["source_id"], acquisition_id)).fetchone()
            if fp and prev and prev["fingerprint"] == fp:
                # bytes changed but every result value is identical: a presentation variant, not a change in results
                conn.execute("INSERT INTO validation_findings(acquisition_id,severity,code,detail,created_utc) VALUES (?,?,?,?,?)",
                             (acquisition_id, "INFO", "PRESENTATION_VARIANT_SAME_RESULTS",
                              "bytes differ from the previous version but all votes, precinct labels and candidate fields are identical "
                              "(only free text differs, e.g. ballot-question wording)", now_utc()))
        except Exception:
            import logging
            logging.getLogger("pipeline").exception("fingerprint failed")
    if status == "OK" and acq["source_id"] == config.PRIMARY_SOURCE_ID:
        try:   # completeness accounting against the signed coverage manifest (REQ-COMP-004, REQ-BASE-004)
            from . import coverage
            coverage.check_and_record(conn, acquisition_id)
        except Exception:
            import logging
            logging.getLogger("pipeline").exception("coverage check failed")
    return {"status": status, "error": err, "observations": len(result.observations) if result else 0}

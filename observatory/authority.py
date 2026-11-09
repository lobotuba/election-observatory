"""Source Authority Records (addendum 003 REQ-SOURCE-001/002).

Authority is a different question from endpoint identity: a valid TLS certificate shows who we reached, not that the
election authority designated that endpoint. This module assembles a DRAFT record from evidence we actually captured
and states plainly what has not been verified by a human.
"""
import hashlib
import json
import socket
import subprocess

from . import archive, config
from .db import now_utc

KEY = "nm-sos-results"
RESULTS_HOSTS = ("electionresults.sos.nm.gov", "electionresults.sos.state.nm.us")


def _cname(host: str) -> str | None:
    try:
        out = subprocess.run(["nslookup", "-type=CNAME", host], capture_output=True, text=True, timeout=20).stdout
        for line in out.splitlines():
            if "canonical name" in line.lower():
                return line.split("=", 1)[1].strip().rstrip(".")
    except Exception:
        pass
    return None


def _designation_evidence(conn) -> list[dict]:
    out = []
    for s in config.SOURCES:
        if s.get("role") != "DESIGNATION_EVIDENCE":
            continue
        a = conn.execute("SELECT acquisition_id, sha256, response_received_utc FROM acquisitions WHERE source_id=? AND sha256 IS NOT NULL "
                         "AND error_class IS NULL ORDER BY acquisition_id DESC LIMIT 1", (s["source_id"],)).fetchone()
        if not a:
            out.append({"source_id": s["source_id"], "url": s["endpoint_url"], "captured": False})
            continue
        text = archive.read(a["sha256"]).decode("utf-8", errors="replace")
        out.append({"source_id": s["source_id"], "url": s["endpoint_url"], "captured": True, "acquisition_id": a["acquisition_id"],
                    "artifact_sha256": a["sha256"], "captured_utc": a["response_received_utc"],
                    "links_found_to": [h for h in RESULTS_HOSTS if h in text]})
    return out


def build_record(conn) -> dict:
    ep = conn.execute("SELECT * FROM endpoint_observations WHERE host=? ORDER BY obs_id DESC LIMIT 1", ("electionresults.sos.nm.gov",)).fetchone()
    last = conn.execute("SELECT response_headers FROM acquisitions WHERE source_id=? AND response_headers IS NOT NULL ORDER BY acquisition_id DESC LIMIT 1",
                        (config.PRIMARY_SOURCE_ID,)).fetchone()
    hdrs = json.loads(last["response_headers"]) if last else {}
    designation = _designation_evidence(conn)
    linked = sorted({h for d in designation for h in d.get("links_found_to", [])})
    return {
        "schema": {"schema_name": "eio.source_authority_record", "schema_version": 1},
        "authority_key": KEY,
        "source_ids": [s["source_id"] for s in config.SOURCES if s.get("authority_record_key") == KEY],
        "owning_election_authority": "New Mexico Secretary of State",
        "jurisdiction": "NM",
        "authority_level": "OFFICIAL_UNOFFICIAL (election-night returns; not canvassed or certified)",
        "source_classification": ["PRIMARY_OFFICIAL"],
        "election_scope": config.ELECTION_LABEL,
        "officially_designated_publication_page": "https://www.sos.nm.gov/voting-and-elections/election-results/",
        "official_endpoint": config.BASE_URL,
        "results_system_provider": "NOT_IDENTIFIED (ASP.NET application; no vendor named in captured evidence)",
        "hosting_provider_observation": {
            "note": "observations, not verified conclusions",
            "response_server_header": hdrs.get("Server"),
            "dns_cname": _cname("electionresults.sos.nm.gov"),
            "latest_endpoint_observation_id": ep["obs_id"] if ep else None,
            "tls_certificate_sha256": ep["cert_sha256"] if ep else None,
            "tls_certificate_subject": ep["cert_subject"] if ep else None,
            "tls_certificate_issuer": ep["cert_issuer"] if ep else None,
        },
        "cdn_provider": "NOT_IDENTIFIED",
        "authority_chain": ["New Mexico Secretary of State", "Official site pages (www.sos.nm.gov)", "Results application (electionresults.sos.nm.gov)",
                            "Hosting/CDN endpoint (see hosting observation)", "Collector"],
        "designation_evidence": designation,
        "results_hosts_linked_from_official_site": linked,
        "official_designation_artifact": ("official-site captures listed in designation_evidence; they show links to the results host, "
                                          "which is evidence of designation but not a formal designation document"),
        "verification_method": "automated capture of the authority's own site and comparison of linked hosts; no human review",
        "verifier": "automated draft", "independent_reviewer": None, "verification_date": None, "activation_date": None,
        "revalidation_triggers": ["before each covered election", "endpoint or registrable-domain change", "certificate or ownership change",
                                  "vendor migration", "official announcement affecting publication", "incident"],
        "approval_status": "DRAFT_UNVERIFIED",
        "known_limitations": [
            "No human verified that these endpoints are the designated publication channel; no independent reviewer exists.",
            "The authority's pages also link to legacy host electionresults.sos.state.nm.us, which did not complete a TLS handshake from the collector.",
            "The authority's pages carry explicit election-id (eid) links that point to 2021 elections; the 2026 General is served only as the site default, "
            "so the collector cannot pin the election by id and instead checks the page's election title/date on every parse.",
            "Network endpoint authentication (TLS) shows who was contacted; it does not establish designation.",
        ],
    }


def refresh(conn) -> dict:
    rec = build_record(conn)
    stable = {k: v for k, v in rec.items() if k not in ("hosting_provider_observation",)}  # observations may change without a new version
    digest = hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    last = conn.execute("SELECT * FROM source_authority_records WHERE authority_key=? ORDER BY sar_id DESC LIMIT 1", (KEY,)).fetchone()
    if last and last["record_sha256"] == digest:
        return {"changed": False, "sar_id": last["sar_id"]}
    cur = conn.execute("INSERT INTO source_authority_records(authority_key,version,created_utc,record_sha256,record_json,approval_status) VALUES (?,?,?,?,?,?)",
                       (KEY, (last["version"] + 1) if last else 1, now_utc(), digest, json.dumps(rec, sort_keys=True, default=str), rec["approval_status"]))
    return {"changed": True, "sar_id": cur.lastrowid}

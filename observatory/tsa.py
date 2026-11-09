"""RFC 3161 trusted timestamping of manifest digests, with a durable retry queue (addendum 001 4.7/8.1,
addendum 002 REQ-CRYPTO-005/006: two independent TSAs).

Only the SHA-256 digest of the manifest file leaves this machine. A late timestamp is recorded with the
time it was actually obtained; nothing is ever backdated. Each TSA is an independent anchor with its own
retry state; evidence reaches E3 when at least one anchor verifies and is "dual anchored" when two do.
"""
import hashlib
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime, timezone

import certifi
import requests
from asn1crypto import tsp

from . import config, custody
from .db import now_utc

log = logging.getLogger("tsa")


def _openssl() -> str | None:
    for c in config.OPENSSL_CANDIDATES:
        try:
            p = subprocess.run([c, "version"], capture_output=True, text=True, timeout=10)
            if p.returncode == 0:
                return c
        except Exception:
            continue
    return None


def build_request(digest: bytes) -> tuple[bytes, int]:
    nonce = int.from_bytes(os.urandom(8), "big")
    req = tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
        "nonce": nonce,
        "cert_req": True,
    })
    return req.dump(), nonce


def parse_response(tsr: bytes, digest: bytes, nonce: int) -> dict:
    resp = tsp.TimeStampResp.load(tsr)
    status = resp["status"]["status"].native
    out = {"status": status}
    if status not in ("granted", "granted_with_mods"):
        out["error"] = f"TSA status {status}: {resp['status']['status_string'].native if resp['status']['status_string'] else ''}"
        return out
    info = resp["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
    imprint = info["message_imprint"]
    out.update(
        gen_time_utc=info["gen_time"].native.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        serial_number=str(info["serial_number"].native),
        policy_oid=info["policy"].native,
        hash_algorithm=imprint["hash_algorithm"]["algorithm"].native,
        imprint_ok=imprint["hashed_message"].native == digest,
        nonce_ok=info["nonce"].native == nonce,
        nonce=str(nonce),
        tsa_name=str(info["tsa"].native) if info["tsa"] else None,
        certificate_count=len(resp["time_stamp_token"]["content"]["certificates"] or []),
    )
    return out


def verify_token(tsq: bytes, tsr: bytes) -> tuple[str, str, str]:
    """Verify with OpenSSL against the standard public roots. Returns (VERIFIED|FAILED|NOT_VERIFIED, detail, verifier)."""
    ossl = _openssl()
    if not ossl:
        return "NOT_VERIFIED", "openssl not available", "none"
    with tempfile.TemporaryDirectory() as d:
        q, r = os.path.join(d, "q.tsq"), os.path.join(d, "r.tsr")
        open(q, "wb").write(tsq)
        open(r, "wb").write(tsr)
        p = subprocess.run([ossl, "ts", "-verify", "-queryfile", q, "-in", r, "-CAfile", certifi.where()],
                           capture_output=True, text=True, timeout=30)
        ver = subprocess.run([ossl, "version"], capture_output=True, text=True).stdout.strip()
    ok = p.returncode == 0 and "Verification: OK" in p.stdout
    return ("VERIFIED" if ok else "FAILED"), (p.stdout + p.stderr).strip()[:500], ver


def verified_anchors(conn, manifest_id: int) -> list:
    """One verified attempt per distinct TSA, earliest first."""
    seen, out = set(), []
    for r in conn.execute("SELECT * FROM timestamp_attempts WHERE manifest_id=? AND outcome='OK' AND verify_result='VERIFIED' ORDER BY attempt_id",
                          (manifest_id,)):
        if r["tsa_url"] not in seen:
            seen.add(r["tsa_url"])
            out.append(r)
    return out


def pending_pairs(conn):
    """(manifest, tsa_url) combinations that still lack a verified token."""
    out = []
    for m in conn.execute("SELECT * FROM manifests WHERE seq IS NOT NULL ORDER BY seq"):
        have = {r["tsa_url"] for r in verified_anchors(conn, m["manifest_id"])}
        for url in config.TSA_URLS:
            if url not in have:
                out.append((m, url))
    return out


def pending_manifests(conn):
    """Manifests with NO verified anchor at all (evidence for these is still below E3)."""
    return [m for m in conn.execute("SELECT * FROM manifests WHERE seq IS NOT NULL ORDER BY seq") if not verified_anchors(conn, m["manifest_id"])]


def _write_once(path, data: bytes):
    if path.exists():
        return
    with open(path, "xb") as f:
        f.write(data)


def attempt_one(conn, m, url: str) -> bool:
    """One request to one TSA for one manifest. Returns True when a VERIFIED token was stored."""
    file_bytes = (config.MANIFEST_DIR / m["path"]).read_bytes()
    digest = hashlib.sha256(file_bytes).digest()
    if digest.hex() != m["manifest_sha256"]:
        conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                     (now_utc(), None, "MANIFEST_TAMPER_SUSPECTED", f"manifest {m['seq']} file digest != recorded digest"))
        return False
    first_anchor = not verified_anchors(conn, m["manifest_id"])
    t = now_utc()
    tsq, nonce = build_request(digest)
    try:
        r = requests.post(url, data=tsq, headers={"Content-Type": "application/timestamp-query"}, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        info = parse_response(r.content, digest, nonce)
        if info["status"] not in ("granted", "granted_with_mods"):
            raise RuntimeError(info.get("error", "not granted"))
        if not (info["imprint_ok"] and info["nonce_ok"]):
            raise RuntimeError("TSA response imprint/nonce mismatch")
        vres, vdetail, verifier = verify_token(tsq, r.content)
        n = conn.execute("SELECT COUNT(*) c FROM timestamp_attempts WHERE manifest_id=?", (m["manifest_id"],)).fetchone()["c"]
        stem = f"manifest_{m['seq']:06d}.a{n + 1}"
        qpath, rpath = config.TIMESTAMP_DIR / f"{stem}.tsq", config.TIMESTAMP_DIR / f"{stem}.tsr"
        _write_once(qpath, tsq)
        _write_once(rpath, r.content)
        conn.execute(
            "INSERT INTO timestamp_attempts(manifest_id,attempted_utc,tsa_url,outcome,detail,request_path,response_path,response_sha256,"
            "gen_time_utc,serial_number,policy_oid,hash_algorithm,nonce,tsa_name,verify_result,verify_detail,verifier) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (m["manifest_id"], t, url, "OK", None, qpath.name, rpath.name, hashlib.sha256(r.content).hexdigest(),
             info["gen_time_utc"], info["serial_number"], info["policy_oid"], info["hash_algorithm"], info["nonce"],
             info["tsa_name"], vres, vdetail, verifier))
        if vres == "VERIFIED":
            if first_anchor:
                _custody_timestamped(conn, m, info["gen_time_utc"], rpath.name)
            else:
                custody.append(conn, evidence_kind="manifest", evidence_id=m["manifest_id"], event_type="ANCHORED_SECONDARY",
                               artifact_sha256=m["manifest_sha256"], prior_state="E3_TIMESTAMPED", new_state="E3_DUAL_ANCHORED",
                               reason=f"second independent TSA {url}; genTime {info['gen_time_utc']}; token {rpath.name}")
            log.info("manifest %s anchored by %s at %s (verified)", m["seq"], url, info["gen_time_utc"])
            return True
        log.warning("manifest %s token from %s NOT verified: %s", m["seq"], url, vdetail[:120])
    except Exception as e:
        conn.execute("INSERT INTO timestamp_attempts(manifest_id,attempted_utc,tsa_url,outcome,detail) VALUES (?,?,?,?,?)",
                     (m["manifest_id"], t, url, "ERROR", f"{type(e).__name__}: {e}"[:400]))
        log.warning("TSA %s failed for manifest %s: %s", url, m["seq"], e)
    return False


def _custody_timestamped(conn, m, gen_time, token_name):
    entries = json.loads((config.MANIFEST_DIR / m["path"]).read_bytes())["body"]["entries"]
    events = [dict(evidence_kind="acquisition", evidence_id=e[0], event_type="TIMESTAMPED", artifact_sha256=e[2],
                   prior_state="E2_CHAINED", new_state="E3_TIMESTAMPED",
                   reason=f"covered by manifest seq {m['seq']}; RFC3161 genTime {gen_time}; token {token_name}") for e in entries]
    events.append(dict(evidence_kind="manifest", evidence_id=m["manifest_id"], event_type="TIMESTAMPED",
                       artifact_sha256=m["manifest_sha256"], prior_state="E2_CHAINED", new_state="E3_TIMESTAMPED",
                       reason=f"RFC3161 genTime {gen_time}; token {token_name}"))
    custody.append_many(conn, events)


def process_queue(conn, max_attempts: int = 8) -> dict:
    """Work through (manifest, TSA) pairs that lack a verified token, oldest manifest first, with per-pair backoff."""
    ok = fail = deferred = 0
    tried = 0
    for m, url in pending_pairs(conn):
        if tried >= max_attempts:
            break
        hist = conn.execute("SELECT attempted_utc FROM timestamp_attempts WHERE manifest_id=? AND tsa_url=? ORDER BY attempt_id DESC",
                            (m["manifest_id"], url)).fetchall()
        if hist:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(hist[0]["attempted_utc"].replace("Z", "+00:00"))).total_seconds()
            if age < min(config.TSA_RETRY_MIN_S * (2 ** min(len(hist) - 1, 4)), 900):
                deferred += 1
                continue
        tried += 1
        if attempt_one(conn, m, url):
            ok += 1
        else:
            fail += 1
            errs = conn.execute("SELECT COUNT(*) c FROM timestamp_attempts WHERE manifest_id=? AND tsa_url=? AND (outcome='ERROR' OR verify_result!='VERIFIED')",
                                (m["manifest_id"], url)).fetchone()["c"]
            if errs == 3:
                conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                             (now_utc(), None, "TSA_UNAVAILABLE",
                              f"manifest {m['seq']} still lacks a verified token from {url}"
                              + ("; evidence stays below E3 until a token verifies" if not verified_anchors(conn, m["manifest_id"]) else "")))
    return {"anchored": ok, "failed": fail, "deferred": deferred}

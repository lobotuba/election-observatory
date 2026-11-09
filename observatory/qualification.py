"""Evidence System Qualification Record (addendum 003 REQ-QUAL-001..005).

This is a SELF-ASSESSMENT produced by the system's own author. It runs real tests and records real results and known
defects. It does not, and cannot, grant authorization to operate: that needs an independent approver (REQ-WIT-002).
"""
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from . import VERSION, archive, clock, config, custody, manifest, tsa, verify_package
from .db import now_utc

QUAL_DIR = config.DATA_DIR / "qualification"

KNOWN_DEFECTS = [
    ("D-001", "No version control, signed tag, build provenance, OCI image or signed release; releases are identified only by file digests.", ["REQ-BUILD-001..004", "REQ-REPRO-001"]),
    ("D-002", "No immutable (WORM/object-lock) storage. A host administrator can rewrite the archive, database and logs; detection relies on hashes, signatures and external timestamps.", ["REQ-EVID-008", "REQ-SEC-002"]),
    ("D-003", "No replica in a separate administrative boundary; evidence level E4 cannot be reached.", ["REQ-EVID-009", "REQ-CRYPTO-005"]),
    ("D-004", "The manifest-signing key is an unencrypted PEM file on the collector host (no HSM, no dual control, no rotation).", ["addendum 001 4.10", "REQ-SEC-003"]),
    ("D-005", "Source configurations, the coverage manifest and the source authority record have no independent reviewer or approver; all are DRAFT/UNAPPROVED.", ["REQ-CONFIG-002/003", "REQ-SOURCE-001", "REQ-COMP-005"]),
    ("D-006", "No browser/dynamic-page capture. Wire/TLS bytes are not preserved (only the transfer-decoded entity). Render evidence does not exist.", ["REQ-EVID-022..025", "REQ-BYTE-001..003"]),
    ("D-007", "Endpoint authentication is an adjacent TLS probe, not the connection that carried each response; chain may be leaf-only; no OCSP/CRL check; DNS resolver identity is the OS configuration, not the server consulted.", ["REQ-EVID-016"]),
    ("D-008", "National federal coverage is not implemented. Only New Mexico sources are collected.", ["REQ-SCOPE-001", "REQ-COMP-001"]),
    ("D-009", "No official poll-close artifact, certification/canvass acquisition pathway, RFC 4998 evidence records, legal-hold workflow, or ranked-choice model.", ["REQ-TIME-005", "REQ-CERTREC-*", "REQ-CRYPTO-003", "REQ-HOLD-*", "REQ-RCV-*"]),
    ("D-010", "Pre-election baseline was captured on election day, not seven days prior, and was not reviewed by a second person.", ["REQ-BASE-002"]),
    ("D-011", "Single operator; no independent observer, rehearsal record, or external examiner exercise has occurred.", ["REQ-WIT-001..004"]),
    ("D-012", "The results site serves 'the current election' implicitly; the election cannot be pinned by id. Mitigated only by checking the page's election title/date.", ["REQ-SOURCE-003"]),
    ("D-013", "Clock offset is measured by unauthenticated SNTP to public servers; accuracy claims are limited by path asymmetry and are not a substitute for the trusted timestamp.", ["REQ-TIME-002", "addendum 001 4.6"]),
    ("D-014", "A trusted timestamp covers a manifest created up to one manifest interval after an acquisition, so it bounds existence to the manifest time, not the acquisition instant.", ["addendum 001 4.2"]),
    ("D-015", "Manifests created before the EIO-MERKLE-1 profile use the legacy EIO-MERKLE-0 construction (no domain separation); they verify under their declared profile only.", ["REQ-MERKLE-001..003"]),
    ("D-016", "Canonical serialization has a single implementation family (Python json); the offline verifier reuses the same convention, so cross-implementation conformance (REQ-CANON-003) is not demonstrated.", ["REQ-CANON-003"]),
    ("D-017", "Access to restricted (encrypted) records is protected by a key on the same host; there is no second custodian.", ["REQ-EVID-020", "REQ-SEC-003"]),
]


def _t(tests, name, fn):
    try:
        ok, detail = fn()
        tests.append({"test": name, "result": "PASS" if ok else "FAIL", "detail": detail})
    except Exception as e:
        tests.append({"test": name, "result": "ERROR", "detail": f"{type(e).__name__}: {e}"})


def run(conn, with_pytest: bool = False) -> dict:
    QUAL_DIR.mkdir(parents=True, exist_ok=True)
    tests = []

    _t(tests, "hash implementation known-answer (SHA-256 'abc', SHA3-256 'abc')", lambda: (
        hashlib.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        and hashlib.sha3_256(b"abc").hexdigest() == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "known-answer vectors matched"))

    def canon():
        a = manifest._canon({"b": 1, "a": [True, None, "é"]})
        ok = a == b'{"a":[true,null,"\\u00e9"],"b":1}'
        try:
            manifest._no_floats({"x": 1.5})
            return False, "float was not rejected"
        except ValueError:
            return ok, f"canonical bytes {a!r}; floats rejected"
    _t(tests, "canonical serialization (EIO-CANON-JSON-1)", canon)

    def merkle():
        bad = []
        for n in list(range(0, 40)) + [64, 100, 129]:
            leaves = [f"{i}:s:{'ab' * 32}:t" for i in range(n)]
            root = manifest.merkle_root(leaves)
            if verify_package.rfc_root([l.encode() for l in leaves]).hex() != root:
                bad.append(("root", n))
            for i in range(n):
                p = manifest.merkle_proof(leaves, i)
                if not verify_package.rfc_verify_inclusion(leaves[i].encode(), i, n, p["audit_path"], root):
                    bad.append(("proof", n, i))
                    break
        # negative control: a proof for the wrong leaf must fail
        leaves = [f"{i}" for i in range(7)]
        p = manifest.merkle_proof(leaves, 3)
        if verify_package.rfc_verify_inclusion(b"nope", 3, 7, p["audit_path"], manifest.merkle_root(leaves)):
            bad.append("accepted a wrong leaf")
        return not bad, f"two implementations agree on roots and inclusion proofs for 43 tree sizes; failures: {bad}"
    _t(tests, "Merkle conformance (manifest.py vs independent verify_package.py)", merkle)

    _t(tests, "clock sample (independent SNTP servers)", lambda: (lambda r: (r["state"] == "SYNCHRONIZED", f"{r}"))(clock.sample(conn)))

    def dual_tsa():
        digest = hashlib.sha256(b"qualification-probe-" + os.urandom(8)).digest()
        res = []
        for url in config.TSA_URLS:
            tsq, nonce = tsa.build_request(digest)
            import requests
            r = requests.post(url, data=tsq, headers={"Content-Type": "application/timestamp-query"}, timeout=30)
            info = tsa.parse_response(r.content, digest, nonce)
            v = tsa.verify_token(tsq, r.content)[0] if info.get("imprint_ok") and info.get("nonce_ok") else "BAD_RESPONSE"
            res.append((url, v, info.get("gen_time_utc")))
        return all(v == "VERIFIED" for _, v, _ in res) and len(res) >= 2, f"{res}"
    _t(tests, "dual independent RFC 3161 anchors (throwaway digest)", dual_tsa)

    def tamper():
        a = conn.execute("SELECT sha256 FROM acquisitions WHERE sha256 IS NOT NULL ORDER BY acquisition_id DESC LIMIT 1").fetchone()
        data = bytearray(archive.read(a["sha256"]))
        data[len(data) // 2] ^= 1
        return archive.sha256_hex(bytes(data)) != a["sha256"] and archive.verify(a["sha256"]), "single-byte change detected; original verifies"
    _t(tests, "tamper detection (AT-EVID-001)", tamper)

    def append_only():
        conn.execute("BEGIN")
        try:
            conn.execute("UPDATE acquisitions SET http_status=0 WHERE acquisition_id=(SELECT MAX(acquisition_id) FROM acquisitions)")
            return False, "UPDATE on acquisitions was allowed"
        except Exception as e:
            return "append-only" in str(e), f"UPDATE rejected: {e}"
        finally:
            conn.execute("ROLLBACK")
    _t(tests, "database append-only enforcement", append_only)

    _t(tests, "custody ledger hash chain", lambda: (lambda r: (r["ok"], str(r)))(custody.verify_chain(conn)))
    _t(tests, "audit sequence gaps", lambda: (lambda g: (not g, str(g or "none")))(manifest.audit_gaps(conn)))

    def manifests_ok():
        bad = []
        n = 0
        for p in sorted(config.MANIFEST_DIR.glob("manifest_*.json")):
            r = manifest.verify_manifest(p, check_artifacts=False)
            n += 1
            if not (r["signature_valid"] and r["merkle_ok"] and not r["audit_segments_bad"]):
                bad.append(p.name)
        return not bad, f"{n} manifests verified (each under its declared Merkle profile); failures: {bad}"
    _t(tests, "all signed manifests verify", manifests_ok)

    def package_roundtrip():
        from . import evidence
        a = conn.execute("SELECT acquisition_id FROM acquisitions a WHERE sha256 IS NOT NULL AND EXISTS (SELECT 1 FROM manifests m WHERE m.seq IS NOT NULL "
                         "AND a.acquisition_id BETWEEN m.first_acquisition_id AND m.last_acquisition_id) ORDER BY acquisition_id DESC LIMIT 1").fetchone()
        with tempfile.TemporaryDirectory() as d:
            root = evidence.export_package(conn, a["acquisition_id"], Path(d), "public", "qualification self-test")
            ok = subprocess.run([sys.executable, "-I", str(root / "verify_package.py"), str(root)], capture_output=True, text=True)
            bad = root / "ORIGINAL" / "response.bin"
            b = bytearray(bad.read_bytes())
            b[0] ^= 1
            bad.write_bytes(bytes(b))
            neg = subprocess.run([sys.executable, "-I", str(root / "verify_package.py"), str(root)], capture_output=True, text=True)
        return ok.returncode == 0 and neg.returncode != 0, f"clean package rc={ok.returncode}; tampered copy rc={neg.returncode} (must be non-zero)"
    _t(tests, "evidence package export + offline verification + tamper (AT-EVID-004, AT-003-024 precursor)", package_roundtrip)

    if with_pytest:
        def pytest_run():
            p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", str(Path(__file__).resolve().parent.parent / "tests")],
                               capture_output=True, text=True, timeout=600)
            return p.returncode == 0, (p.stdout.strip().splitlines() or [""])[-1]
        _t(tests, "automated test suite (failure modes, parser, replay, evidence)", pytest_run)

    cov = conn.execute("SELECT * FROM coverage_manifests ORDER BY cov_id DESC LIMIT 1").fetchone()
    rel = conn.execute("SELECT * FROM releases ORDER BY release_id DESC LIMIT 1").fetchone()
    cfgs = [dict(source_id=r["source_id"], version=r["version"], config_sha256=r["config_sha256"], approval_status=r["approval_status"])
            for r in conn.execute("SELECT * FROM source_config_versions WHERE cfg_id IN (SELECT MAX(cfg_id) FROM source_config_versions GROUP BY source_id)")]
    sar = conn.execute("SELECT * FROM source_authority_records ORDER BY sar_id DESC LIMIT 1").fetchone()
    failed = [t for t in tests if t["result"] != "PASS"]
    body = {
        "schema": {"schema_name": "eio.qualification_record", "schema_version": 1, "canonicalization": manifest.CANON_PROFILE},
        "election_id": config.ELECTION_ID, "created_utc": now_utc(), "author": "system author (self-assessment)",
        "system": {"observatory_version": VERSION, "python": platform.python_version(), "platform": platform.platform(),
                   "release_sha256": rel["release_sha256"] if rel else None, "release_signed": False,
                   "sbom": rel["sbom_path"] if rel else None},
        "source_configuration_set": cfgs,
        "coverage_manifest": ({"version": cov["version"], "sha256": cov["manifest_sha256"], "approval_status": cov["approval_status"]} if cov else None),
        "source_authority_record": ({"version": sar["version"], "sha256": sar["record_sha256"], "approval_status": sar["approval_status"]} if sar else None),
        "tests": tests,
        "test_summary": {"total": len(tests), "passed": len(tests) - len(failed), "not_passed": len(failed)},
        "not_performed": ["immutable-storage test (none exists)", "replication/restore test (no replica)", "browser capture test (no browser capture)",
                          "security assessment (none)", "operator training records (none)", "independent witnessed rehearsal (none)",
                          "external examiner verification (none)", "build provenance / SBOM signature verification (unsigned)"],
        "known_defects": [{"id": i, "description": d, "requirements": r, "status": "OPEN"} for i, d, r in KNOWN_DEFECTS],
        "risk_acceptances": [],
        "risk_acceptance_note": "NONE. No independent approver exists to accept risk; the defects above are unaccepted, not waived.",
        "authorization_to_operate": {"status": "NOT_AUTHORIZED", "authorized_by": None,
                                     "reason": "self-assessment only; independent approval is required (REQ-QUAL-002/003, REQ-WIT-002)",
                                     "note": "The system is running for collection and preservation. This record does not authorize reliance on it for any production purpose."},
    }
    key = manifest._load_or_create_key()
    sig = base64.b64encode(key.sign(manifest._canon(body))).decode()
    data = json.dumps({"body": body, "signature_ed25519_b64": sig}, indent=1).encode()
    stamp = now_utc().replace(":", "").replace(".", "")
    path = QUAL_DIR / f"qualification_{stamp}.json"
    with open(path, "xb") as f:
        f.write(data)
    digest = hashlib.sha256(data).digest()
    import requests
    tokens = []
    for i, url in enumerate(config.TSA_URLS):
        try:
            tsq, nonce = tsa.build_request(digest)
            r = requests.post(url, data=tsq, headers={"Content-Type": "application/timestamp-query"}, timeout=30)
            info = tsa.parse_response(r.content, digest, nonce)
            v, detail, _ = tsa.verify_token(tsq, r.content)
            (QUAL_DIR / f"{path.stem}.a{i + 1}.tsr").write_bytes(r.content)
            (QUAL_DIR / f"{path.stem}.a{i + 1}.tsq").write_bytes(tsq)
            tokens.append({"tsa": url, "gen_time_utc": info.get("gen_time_utc"), "verify": v})
        except Exception as e:
            tokens.append({"tsa": url, "error": f"{type(e).__name__}: {e}"})
    (QUAL_DIR / f"{path.stem}.timestamps.json").write_text(json.dumps(tokens, indent=1))
    cur = conn.execute("INSERT INTO qualification_records(created_utc,path,record_sha256,signature_b64,summary_json,authorization_status) VALUES (?,?,?,?,?,?)",
                       (body["created_utc"], path.name, hashlib.sha256(data).hexdigest(), sig,
                        json.dumps({"tests": body["test_summary"], "timestamps": tokens}), "NOT_AUTHORIZED"))
    custody.append(conn, evidence_kind="package", evidence_id=cur.lastrowid, event_type="QUALIFICATION_RECORDED", actor="system author",
                   artifact_sha256=hashlib.sha256(data).hexdigest(), reason=f"{body['test_summary']}; anchors {tokens}", new_state="NOT_AUTHORIZED")
    return {"path": str(path), "tests": body["test_summary"], "failed": [t for t in tests if t["result"] != "PASS"], "timestamps": tokens,
            "authorization": "NOT_AUTHORIZED"}

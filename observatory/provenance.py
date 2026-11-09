"""Configuration versions, software release identity + SBOM, algorithm-agile digests, restricted tier.

Honest limits: there is no signed tag, OCI image or build provenance (the project is not in version control yet),
and no independent reviewer exists for source configs, so approval_status says so rather than implying review.
"""
import base64
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

from cryptography.fernet import Fernet

from . import VERSION, config, custody
from .db import now_utc

OIDS = {"sha256": "2.16.840.1.101.3.4.2.1", "sha3_256": "2.16.840.1.101.3.4.2.8", "sha384": "2.16.840.1.101.3.4.2.2",
        "sha512": "2.16.840.1.101.3.4.2.3", "sha3_384": "2.16.840.1.101.3.4.2.9", "sha3_512": "2.16.840.1.101.3.4.2.10"}


# ---------- source configuration versions ----------
def register_source_configs(conn) -> dict[str, int]:
    """Append a new version row whenever a source's configuration digest changes. Returns source_id -> cfg_id."""
    out = {}
    for s in config.SOURCES:
        blob = json.dumps(s, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(blob.encode()).hexdigest()
        last = conn.execute("SELECT * FROM source_config_versions WHERE source_id=? ORDER BY cfg_id DESC LIMIT 1", (s["source_id"],)).fetchone()
        if last and last["config_sha256"] == digest:
            out[s["source_id"]] = last["cfg_id"]
            continue
        cur = conn.execute(
            "INSERT INTO source_config_versions(source_id,version,config_sha256,config_json,created_utc,author,reviewer,approval_status,reason,previous_cfg_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (s["source_id"], (last["version"] + 1) if last else 1, digest, blob, now_utc(), "operator (single person)", None,
             "UNAPPROVED_NO_INDEPENDENT_REVIEW", "initial registration" if not last else "configuration digest changed",
             last["cfg_id"] if last else None))
        custody.append(conn, evidence_kind="package", evidence_id=cur.lastrowid, event_type="SOURCE_CONFIG_VERSIONED",
                       actor="observatory-collector", reason=f"{s['source_id']} v{(last['version'] + 1) if last else 1} sha256 {digest[:16]}",
                       new_state="UNAPPROVED_NO_INDEPENDENT_REVIEW")
        out[s["source_id"]] = cur.lastrowid
    return out


# ---------- release identity + SBOM ----------
def _pip_freeze() -> str:
    try:
        return subprocess.run([sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, timeout=60).stdout
    except Exception as e:
        return f"# pip freeze unavailable: {e}\n"


def register_release(conn) -> int:
    pkg = Path(__file__).resolve().parent
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(pkg.glob("*.py"))}
    lock = _pip_freeze()
    lock_sha = hashlib.sha256(lock.encode()).hexdigest()
    release_sha = hashlib.sha256(json.dumps({"files": files, "lock": lock_sha, "py": platform.python_version()}, sort_keys=True).encode()).hexdigest()
    row = conn.execute("SELECT release_id FROM releases WHERE release_sha256=?", (release_sha,)).fetchone()
    if row:
        return row["release_id"]
    components = []
    for line in lock.splitlines():
        if "==" in line:
            n, v = line.split("==", 1)
            components.append({"type": "library", "name": n.strip(), "version": v.strip(), "purl": f"pkg:pypi/{n.strip().lower()}@{v.strip()}"})
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": now_utc(), "component": {"type": "application", "name": "election-information-observatory", "version": VERSION,
                                                                "hashes": [{"alg": "SHA-256", "content": release_sha}]}},
            "components": components}
    sbom_path = config.RELEASE_DIR / f"sbom_{release_sha[:16]}.cdx.json"
    sbom_path.write_text(json.dumps(sbom, indent=1))
    cur = conn.execute(
        "INSERT INTO releases(release_sha256,created_utc,observatory_version,python_version,platform,source_files_json,lock_sha256,lock_text,sbom_path,signed) "
        "VALUES (?,?,?,?,?,?,?,?,?,0)",
        (release_sha, now_utc(), VERSION, platform.python_version(), platform.platform(), json.dumps(files), lock_sha, lock, sbom_path.name))
    custody.append(conn, evidence_kind="package", evidence_id=cur.lastrowid, event_type="RELEASE_REGISTERED", actor="observatory-collector",
                   reason=f"release {release_sha[:16]} ({len(files)} source files, {len(components)} dependencies); UNSIGNED", new_state="unsigned")
    return cur.lastrowid


# ---------- algorithm-agile digests ----------
def record_digests(conn, sha256_hex: str, data: bytes, algorithms=None):
    for alg in ["sha256"] + list(algorithms if algorithms is not None else config.EXTRA_DIGEST_ALGORITHMS):
        if conn.execute("SELECT 1 FROM artifact_digests WHERE artifact_sha256=? AND algorithm=?", (sha256_hex, alg)).fetchone():
            continue
        value = hashlib.new(alg, data).hexdigest()
        conn.execute(
            "INSERT OR IGNORE INTO artifact_digests(artifact_sha256,algorithm,oid,value,calculated_utc,implementation,input_length,verification_status) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (sha256_hex, alg, OIDS.get(alg), value, now_utc(), f"python-hashlib/{platform.python_version()}", len(data), "COMPUTED_FROM_VERIFIED_BYTES"))


# ---------- restricted tier (REQ-EVID-020) ----------
def _fernet() -> Fernet:
    p = config.KEY_DIR / "restricted.fernet.key"
    if not p.exists():
        config.ensure_dirs()
        p.write_bytes(Fernet.generate_key())
    return Fernet(p.read_bytes())


def commit_restricted(stem: str, payload: dict) -> tuple[str, str]:
    """Encrypt a restricted record and return (commitment_sha256, file name). The commitment is over salt+plaintext,
    so it proves what was withheld without revealing it. The key sits on this host: this protects against casual
    exposure, NOT against a host administrator."""
    import os
    salt = os.urandom(16).hex()
    plain = json.dumps({"salt": salt, "payload": payload}, sort_keys=True).encode()
    commitment = hashlib.sha256(plain).hexdigest()
    name = f"{stem}.enc"
    path = config.RESTRICTED_DIR / name
    with open(path, "xb") as f:
        f.write(_fernet().encrypt(plain))
    return commitment, name


def read_restricted(conn, acq_id: int, actor: str, reason: str) -> dict:
    row = conn.execute("SELECT restricted_path, restricted_commitment FROM acquisitions WHERE acquisition_id=?", (acq_id,)).fetchone()
    plain = _fernet().decrypt((config.RESTRICTED_DIR / row["restricted_path"]).read_bytes())
    ok = hashlib.sha256(plain).hexdigest() == row["restricted_commitment"]
    custody.append(conn, evidence_kind="acquisition", evidence_id=acq_id, event_type="RESTRICTED_ACCESSED", actor=actor, reason=reason,
                   new_state="commitment matched" if ok else "COMMITMENT MISMATCH")
    return {"commitment_ok": ok, **json.loads(plain)}

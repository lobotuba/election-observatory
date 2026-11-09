"""Optional replication of evidence to a second location, with re-verification (addendum 4.8 steps 8-9).

A replica on the same host or under the same administrator is a backup, not a second administrative
boundary. E4 is therefore claimed only when the operator declares the boundary (config.REPLICA_IS_SEPARATE_BOUNDARY).
"""
import hashlib
import shutil
from pathlib import Path

from . import archive, config, custody
from .db import now_utc


def _copy_verified(src: Path, dst: Path) -> bool:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if not dst.exists():
        shutil.copy2(src, dst)
    return hashlib.sha256(dst.read_bytes()).hexdigest() == hashlib.sha256(src.read_bytes()).hexdigest()


def run(conn, limit: int = 400) -> dict:
    rd = config.REPLICA_DIR
    if not rd:
        return {"enabled": False}
    declared = 1 if config.REPLICA_IS_SEPARATE_BOUNDARY else 0
    copied = bad = 0
    have = {(r["object_kind"], r["object_ref"]) for r in conn.execute("SELECT object_kind, object_ref FROM replication_events WHERE reverified=1")}

    def record(kind, ref, sha, ok):
        conn.execute("INSERT INTO replication_events(object_kind,object_ref,sha256,replica_dir,copied_utc,reverified,separate_boundary_declared) "
                     "VALUES (?,?,?,?,?,?,?)", (kind, ref, sha, str(rd), now_utc(), 1 if ok else 0, declared))

    for r in conn.execute("SELECT DISTINCT sha256 FROM acquisitions WHERE sha256 IS NOT NULL").fetchall():
        sha = r["sha256"]
        if ("artifact", sha) in have:
            continue
        if copied >= limit:
            break
        ok = _copy_verified(archive.artifact_path(sha), archive.artifact_path(sha, rd / "archive"))
        record("artifact", sha, sha, ok)
        copied += ok
        bad += not ok
    for m in conn.execute("SELECT path, manifest_sha256 FROM manifests WHERE seq IS NOT NULL").fetchall():
        if ("manifest", m["path"]) in have:
            continue
        ok = _copy_verified(config.MANIFEST_DIR / m["path"], rd / "manifests" / m["path"])
        record("manifest", m["path"], m["manifest_sha256"], ok)
        copied += ok
        bad += not ok
    for t in conn.execute("SELECT DISTINCT request_path, response_path, response_sha256 FROM timestamp_attempts WHERE outcome='OK'").fetchall():
        for name in (t["request_path"], t["response_path"]):
            if name and ("timestamp", name) not in have:
                ok = _copy_verified(config.TIMESTAMP_DIR / name, rd / "timestamps" / name)
                record("timestamp", name, t["response_sha256"] or "", ok)
                copied += ok
                bad += not ok
    if copied:
        custody.append(conn, evidence_kind="package", evidence_id=0, event_type="REPLICATED",
                       actor="observatory-replicator", reason=f"{copied} objects copied and re-verified at {rd}; "
                       f"separate administrative boundary declared={bool(declared)}")
    if bad:
        conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                     (now_utc(), None, "REPLICATION_VERIFY_FAILED", f"{bad} objects failed re-verification at {rd}"))
    return {"enabled": True, "copied": copied, "failed": bad, "separate_boundary_declared": bool(declared)}

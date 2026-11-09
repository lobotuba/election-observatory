"""Signed, hash-chained Merkle manifests of acquired artifacts (spec 7.5, addendum 4.8).

A batch covers every acquisition with a body that no earlier manifest covered, so there are no
time-window gaps. Each manifest binds: the previous manifest's file digest, the custody-ledger head,
and a clock snapshot. The RFC 3161 token (see tsa.py) is requested over the digest of the manifest FILE.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import VERSION, archive, config, custody
from .db import now_utc, schema_digest

PRIV = "manifest_ed25519.pem"
PUB = "manifest_ed25519.pub.pem"


def _load_or_create_key():
    config.ensure_dirs()
    priv_path = config.KEY_DIR / PRIV
    if priv_path.exists():
        return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    priv_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (config.KEY_DIR / PUB).write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


# ---- Merkle trees ----
# EIO-MERKLE-1 (current): RFC 6962 / RFC 9162 Merkle tree hash. Leaf = SHA-256(0x00 || leaf bytes), node = SHA-256(0x01 || L || R),
#   no leaf duplication (the tree is split at the largest power of two below n), empty tree = SHA-256(""), SHA-256 only.
#   Inclusion proofs are RFC 9162 section 2.1.3 audit paths. Leaf bytes = UTF-8 of leaf_string().
# EIO-MERKLE-0 (legacy, manifests whose body has no "merkle_profile"): leaf = SHA-256(leaf), node = SHA-256(L||R),
#   odd levels duplicate the last node. Kept ONLY so old manifests still verify under the rules they were made with;
#   it lacks domain separation and must not be used for new manifests.
MERKLE_PROFILE = "EIO-MERKLE-1"
CANON_PROFILE = "EIO-CANON-JSON-1"   # UTF-8, ASCII-escaped, sorted keys, no whitespace, no floats/NaN, ints/strings/bools/null only


def leaf_string(acq_id, source_id, sha, received_utc) -> str:
    return f"{acq_id}:{source_id}:{sha}:{received_utc}"


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _leaf_hash(data: bytes) -> bytes:
    return _h(b"\x00" + data)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


def _split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)   # largest power of two strictly less than n (n >= 2)


def mth(leaf_data: list[bytes]) -> bytes:
    n = len(leaf_data)
    if n == 0:
        return _h(b"")
    if n == 1:
        return _leaf_hash(leaf_data[0])
    k = _split(n)
    return _node_hash(mth(leaf_data[:k]), mth(leaf_data[k:]))


def audit_path(index: int, leaf_data: list[bytes]) -> list[bytes]:
    n = len(leaf_data)
    if n <= 1:
        return []
    k = _split(n)
    if index < k:
        return audit_path(index, leaf_data[:k]) + [mth(leaf_data[k:])]
    return audit_path(index - k, leaf_data[k:]) + [mth(leaf_data[:k])]


def verify_inclusion(leaf_data: bytes, index: int, tree_size: int, path: list[str], root_hex: str) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if index >= tree_size:
        return False
    fn, sn, r = index, tree_size - 1, _leaf_hash(leaf_data)
    for p in map(bytes.fromhex, path):
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == root_hex


def merkle_root(leaves: list[str]) -> str:
    return mth([l.encode() for l in leaves]).hex()


def merkle_proof(leaves: list[str], index: int) -> dict:
    data = [l.encode() for l in leaves]
    return {"profile": MERKLE_PROFILE, "leaf_index": index, "tree_size": len(leaves),
            "audit_path": [p.hex() for p in audit_path(index, data)]}


# ---- legacy EIO-MERKLE-0 ----
def legacy_merkle_levels(leaves: list[str]) -> list[list[bytes]]:
    level = [_h(l.encode()) for l in leaves]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2:
            level = level + [level[-1]]
            levels[-1] = level
        level = [_h(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def legacy_merkle_root(leaves: list[str]) -> str | None:
    return legacy_merkle_levels(leaves)[-1][0].hex() if leaves else None


def legacy_merkle_proof(leaves: list[str], index: int) -> dict:
    levels = legacy_merkle_levels(leaves)
    proof, idx = [], index
    for level in levels[:-1]:
        sib = idx ^ 1
        proof.append({"sibling": level[sib].hex(), "side": "left" if sib < idx else "right"})
        idx //= 2
    return {"profile": "EIO-MERKLE-0", "proof": proof}


def merkle_root_for(body: dict) -> str | None:
    """Recompute a manifest's root under the profile it DECLARES (no silent reinterpretation)."""
    leaves = [leaf_string(*e) for e in body["entries"]]
    if body.get("merkle_profile") == MERKLE_PROFILE:
        return merkle_root(leaves)
    return legacy_merkle_root(leaves)   # manifests created before the profile field existed


def _no_floats(obj, path="body"):
    if isinstance(obj, float):
        raise ValueError(f"floating-point value at {path}: canonical profile {CANON_PROFILE} forbids floats (use strings)")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _no_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _no_floats(v, f"{path}[{i}]")


def _canon(obj) -> bytes:
    """EIO-CANON-JSON-1: UTF-8, ASCII-escaped, keys sorted, no insignificant whitespace, NaN/Infinity rejected."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def last_manifest(conn):
    return conn.execute("SELECT * FROM manifests WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1").fetchone()


AUDIT_TABLES = [("custody_events", "event_id"), ("alerts", "alert_id"), ("clock_status", "clock_id"),
                ("timestamp_attempts", "attempt_id"), ("parse_runs", "parse_run_id"), ("endpoint_observations", "obs_id"),
                ("source_config_versions", "cfg_id"), ("releases", "release_id"), ("artifact_digests", "digest_id"),
                ("replication_events", "repl_id"), ("validation_findings", "finding_id"),
                # every acquisition row (including failed attempts, REQ-OBS-004) and the expectation/authority/qualification records
                ("acquisitions", "acquisition_id"), ("coverage_manifests", "cov_id"), ("coverage_events", "event_id"),
                ("source_authority_records", "sar_id"), ("qualification_records", "qual_id")]


def build_audit_segments(conn, seq: int) -> list[dict]:
    """Digest every log row added since the last manifest (REQ-EVID-017/026). Rows go to a write-once JSONL file whose
    SHA-256 is bound into the signed, timestamped manifest, so later alteration of a copied segment is detectable."""
    segs = []
    for table, idcol in AUDIT_TABLES:
        last = conn.execute("SELECT MAX(last_id) m FROM audit_segments WHERE table_name=?", (table,)).fetchone()["m"] or 0
        rows = conn.execute(f"SELECT * FROM {table} WHERE {idcol}>? ORDER BY {idcol}", (last,)).fetchall()
        if not rows:
            continue
        data = "\n".join(json.dumps(dict(r), sort_keys=True, separators=(",", ":"), default=str) for r in rows).encode() + b"\n"
        name = f"seg_{seq:06d}_{table}.jsonl"
        with open(config.AUDIT_DIR / name, "xb") as f:
            f.write(data)
        segs.append(dict(table=table, first_id=rows[0][idcol], last_id=rows[-1][idcol], row_count=len(rows),
                         sha256=hashlib.sha256(data).hexdigest(), file=name))
    return segs


def audit_gaps(conn) -> list[str]:
    """Sequence-gap monitor (REQ-EVID-027): autoincrement ids of evidence tables must be contiguous."""
    problems = []
    for table, idcol in AUDIT_TABLES:
        r = conn.execute(f"SELECT MIN({idcol}) lo, MAX({idcol}) hi, COUNT(*) n FROM {table}").fetchone()
        if r["n"] and r["hi"] - r["lo"] + 1 != r["n"]:
            problems.append(f"{table}: ids {r['lo']}..{r['hi']} but {r['n']} rows (gap or deletion)")
    return problems


def make_batch(conn, force: bool = False):
    """Create the next manifest if there are unmanifested acquisitions or new audit rows. Returns the row or None."""
    prev = last_manifest(conn)
    after = prev["last_acquisition_id"] if prev else 0
    rows = conn.execute(
        "SELECT acquisition_id, source_id, sha256, content_length, response_received_utc FROM acquisitions "
        "WHERE acquisition_id>? AND sha256 IS NOT NULL ORDER BY acquisition_id", (after,)).fetchall()
    seq_probe = (prev["seq"] + 1) if prev else 1
    pending_audit = any(
        conn.execute(f"SELECT 1 FROM {t} WHERE {c}>COALESCE((SELECT MAX(last_id) FROM audit_segments WHERE table_name=?),0) LIMIT 1", (t,)).fetchone()
        for t, c in AUDIT_TABLES)
    if not rows and not pending_audit:
        return None
    key = _load_or_create_key()
    uniq = {r["sha256"]: r["content_length"] or 0 for r in rows}
    leaves = [leaf_string(r["acquisition_id"], r["source_id"], r["sha256"], r["response_received_utc"]) for r in rows]
    prev_hash = prev["manifest_sha256"] if prev else None
    head = custody.verify_chain(conn)
    clk = conn.execute("SELECT sampled_utc, offset_ms, uncertainty_ms, state FROM clock_status ORDER BY clock_id DESC LIMIT 1").fetchone()
    seq = seq_probe
    created = now_utc()
    segments = build_audit_segments(conn, seq)
    body = {
        "manifest_version": 4,
        "schema": {   # REQ-SCHEMA-001
            "schema_name": "eio.manifest", "schema_version": 4, "schema_digest": schema_digest(),
            "schema_ref": "observatory/manifest.py::make_batch (database DDL digest in schema_digest)",
            "serialization": "JSON", "canonicalization": CANON_PROFILE,
            "producing_release_id": conn.execute("SELECT MAX(release_id) m FROM releases").fetchone()["m"],
        },
        "seq": seq,
        "election_id": config.ELECTION_ID,
        "first_acquisition_id": rows[0]["acquisition_id"] if rows else after + 1,
        "last_acquisition_id": rows[-1]["acquisition_id"] if rows else after,
        "window_start_utc": rows[0]["response_received_utc"] if rows else created,
        "window_end_utc": rows[-1]["response_received_utc"] if rows else created,
        "created_utc": created,
        "audit_segments": segments,
        "acquisition_count": len(rows),
        "unique_artifact_count": len(uniq),
        "unique_artifact_bytes": sum(uniq.values()),
        "hash_algorithm": "sha256",
        "merkle_root": merkle_root(leaves),
        "merkle_profile": MERKLE_PROFILE,
        "merkle_tree_size": len(leaves),
        "merkle_leaf_format": "{acquisition_id}:{source_id}:{sha256}:{response_received_utc}",
        "merkle_construction": "RFC 6962/9162 tree hash: leaf=SHA256(0x00||utf8(leaf)), node=SHA256(0x01||L||R), split at largest power of two < n, empty=SHA256('')",
        "previous_manifest_seq": prev["seq"] if prev else None,
        "previous_manifest_sha256": prev_hash,
        "custody_ledger_head": head.get("head"),
        "custody_ledger_events": head.get("checked"),
        "key_id": key_id(key.public_key()),
        "software": f"observatory {VERSION}",
        "clock_snapshot": ({"sampled_utc": clk["sampled_utc"], "offset_ms": str(clk["offset_ms"]),
                            "uncertainty_ms": str(clk["uncertainty_ms"]), "state": clk["state"]} if clk else None),
        "entries": [[r["acquisition_id"], r["source_id"], r["sha256"], r["response_received_utc"]] for r in rows],
    }
    _no_floats(body)
    sig = base64.b64encode(key.sign(_canon(body))).decode()
    file_bytes = json.dumps({"body": body, "signature_ed25519_b64": sig}, indent=1).encode()
    name = f"manifest_{seq:06d}.json"
    path = config.MANIFEST_DIR / name
    with open(path, "xb") as f:   # write-once
        f.write(file_bytes)
    file_sha = hashlib.sha256(file_bytes).hexdigest()
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "INSERT INTO manifests(kind,window_start_utc,window_end_utc,artifact_count,total_bytes,merkle_root,path,key_id,created_utc,"
            "seq,first_acquisition_id,last_acquisition_id,manifest_sha256,signature_b64) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("batch", body["window_start_utc"], body["window_end_utc"], len(rows), body["unique_artifact_bytes"],
             body["merkle_root"], name, body["key_id"], created, seq, body["first_acquisition_id"],
             body["last_acquisition_id"], file_sha, sig))
        mid = cur.lastrowid
        for sg in segments:
            conn.execute("INSERT INTO audit_segments(manifest_seq,table_name,first_id,last_id,row_count,sha256,path) VALUES (?,?,?,?,?,?,?)",
                         (seq, sg["table"], sg["first_id"], sg["last_id"], sg["row_count"], sg["sha256"], sg["file"]))
        events = [dict(evidence_kind="acquisition", evidence_id=r["acquisition_id"], event_type="MANIFEST_INCLUDED",
                       artifact_sha256=r["sha256"], prior_state="E1_HASHED", new_state="E2_CHAINED",
                       reason=f"manifest seq {seq} merkle_root {body['merkle_root'][:16]} ({MERKLE_PROFILE})") for r in rows]
        events.append(dict(evidence_kind="manifest", evidence_id=mid, event_type="MANIFEST_SIGNED", artifact_sha256=file_sha,
                           reason=f"seq {seq}, {len(rows)} acquisitions, key {body['key_id']}", new_state="E2_CHAINED"))
        custody.append_many(conn, events)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return conn.execute("SELECT * FROM manifests WHERE manifest_id=?", (mid,)).fetchone()


def load_manifest_file(row_or_path):
    p = config.MANIFEST_DIR / row_or_path["path"] if not isinstance(row_or_path, (str,)) and hasattr(row_or_path, "keys") else row_or_path
    return json.loads(open(p, "rb").read())


def verify_manifest(path, check_artifacts=True, pub_pem: bytes | None = None) -> dict:
    raw = open(path, "rb").read()
    doc = json.loads(raw)
    body, sig = doc["body"], base64.b64decode(doc["signature_ed25519_b64"])
    pub = serialization.load_pem_public_key(pub_pem or (config.KEY_DIR / PUB).read_bytes())
    out = {"path": str(path), "file_sha256": hashlib.sha256(raw).hexdigest(), "signature_valid": True,
           "artifacts_checked": 0, "artifacts_bad": []}
    try:
        pub.verify(sig, _canon(body))
    except InvalidSignature:
        out["signature_valid"] = False
    if key_id(pub) != body["key_id"]:
        out["signature_valid"] = False
        out["note"] = "key id mismatch"
    out["merkle_profile"] = body.get("merkle_profile", "EIO-MERKLE-0")
    out["merkle_ok"] = merkle_root_for(body) == body["merkle_root"]
    if check_artifacts:
        for sha in {e[2] for e in body["entries"]}:
            out["artifacts_checked"] += 1
            if not archive.verify(sha):
                out["artifacts_bad"].append(sha)
    out["audit_segments_bad"] = []
    for sg in body.get("audit_segments", []):
        p = config.AUDIT_DIR / sg["file"]
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != sg["sha256"]:
            out["audit_segments_bad"].append(sg["file"])
    return out

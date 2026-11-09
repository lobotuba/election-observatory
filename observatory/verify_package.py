#!/usr/bin/env python3
"""Offline verifier for an Election Information Observatory evidence package (addendum 5.3).

Needs only Python 3.9+. Optional extras make more checks possible instead of being skipped:
  * `cryptography` (pip install cryptography)  -> Ed25519 signature checks
  * `openssl` on PATH (or --openssl PATH)      -> RFC 3161 timestamp token verification
Usage:  python verify_package.py <package_dir> [--cafile roots.pem] [--openssl PATH] [--json out.json]

It never contacts the network or the production system. Exit code 0 = every check that could run passed.
What a pass means: these exact bytes existed no later than the attested time. It does NOT show the
bytes were true, what any other visitor saw, or why two sources differ.
"""
import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RESULTS = []


def check(name, status, detail=""):
    RESULTS.append({"check": name, "status": status, "detail": detail})
    mark = {"PASS": "[PASS]", "FAIL": "[FAIL]", "SKIPPED": "[SKIP]"}[status]
    print(f"{mark} {name}" + (f" - {detail}" if detail else ""))


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def merkle_h(b):
    return hashlib.sha256(b).digest()


# --- EIO-MERKLE-1 : RFC 6962/9162 tree hash. Deliberately written independently of observatory/manifest.py. ---
def rfc_leaf(data):
    return merkle_h(b"\x00" + data)


def rfc_node(l, r):
    return merkle_h(b"\x01" + l + r)


def rfc_root(items):
    n = len(items)
    if n == 0:
        return merkle_h(b"")
    if n == 1:
        return rfc_leaf(items[0])
    k = 1
    while k * 2 < n:        # largest power of two strictly below n
        k *= 2
    return rfc_node(rfc_root(items[:k]), rfc_root(items[k:]))


def rfc_verify_inclusion(leaf_bytes, index, size, path, root_hex):
    """RFC 9162 section 2.1.3.2, restated."""
    if index >= size:
        return False
    fn, sn = index, size - 1
    h = rfc_leaf(leaf_bytes)
    for sib_hex in path:
        sib = bytes.fromhex(sib_hex)
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            h = rfc_node(sib, h)
            while fn % 2 == 0 and fn != 0:
                fn //= 2
                sn //= 2
        else:
            h = rfc_node(h, sib)
        fn //= 2
        sn //= 2
    return sn == 0 and h.hex() == root_hex


# --- EIO-MERKLE-0 (legacy): no domain separation, duplicate-last. Only to verify manifests made under that profile. ---
def legacy_root(leaves):
    if not leaves:
        return None
    level = [merkle_h(l.encode()) for l in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [merkle_h(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0].hex()


def legacy_verify_proof(leaf, proof, root):
    cur = merkle_h(leaf.encode())
    for step in proof:
        sib = bytes.fromhex(step["sibling"])
        cur = merkle_h(sib + cur) if step["side"] == "left" else merkle_h(cur + sib)
    return cur.hex() == root


def ed25519_verify(pub_pem: bytes, sig: bytes, msg: bytes):
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None
    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def find_openssl(explicit):
    for c in ([explicit] if explicit else []) + [shutil.which("openssl") or "", r"C:\Program Files\Git\usr\bin\openssl.exe"]:
        if c and (os.path.exists(c) or shutil.which(c)):
            return c
    return None


def default_cafile(explicit):
    if explicit:
        return explicit
    try:
        import certifi
        return certifi.where()
    except ImportError:
        pass
    for p in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"):
        if os.path.exists(p):
            return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("--cafile")
    ap.add_argument("--openssl")
    ap.add_argument("--json")
    a = ap.parse_args()
    root = Path(a.package)

    required = ["ORIGINAL/response.bin", "ACQUISITION/acquisition.json", "ACQUISITION/request.json",
                "ACQUISITION/response_headers.json", "ACQUISITION/clock_status.json", "INTEGRITY/response.sha256",
                "INTEGRITY/manifest.json", "INTEGRITY/manifest.sig", "INTEGRITY/merkle_proof.json",
                "INTEGRITY/bundle_manifest.json", "EXPORT/export_manifest.json", "EXPORT/export_manifest.sig",
                "EXPORT/redaction_manifest.json"]
    missing = [r for r in required if not (root / r).exists()]
    check("package structure", "FAIL" if missing else "PASS", f"missing: {missing}" if missing else f"{len(required)} required files present")
    if missing:
        return finish(a)

    acq = json.loads((root / "ACQUISITION/acquisition.json").read_text())
    # 1. original bytes and digest
    actual = sha256_file(root / "ORIGINAL/response.bin")
    recorded = (root / "INTEGRITY/response.sha256").read_text().split()[0]
    check("original bytes match response.sha256", "PASS" if actual == recorded else "FAIL", actual)
    check("digest matches acquisition record", "PASS" if actual == acq.get("sha256") else "FAIL")
    size_ok = os.path.getsize(root / "ORIGINAL/response.bin") == acq.get("content_length")
    check("byte length matches acquisition record", "PASS" if size_ok else "FAIL")

    # 2. manifest signature and Merkle inclusion
    mfile = root / "INTEGRITY/manifest.json"
    doc = json.loads(mfile.read_text())
    body = doc["body"]
    pub_path = root / "INTEGRITY/manifest_public_key.pem"
    sig = base64.b64decode(doc["signature_ed25519_b64"])
    if pub_path.exists():
        r = ed25519_verify(pub_path.read_bytes(), sig, canon(body))
        if r is None:
            check("manifest signature (Ed25519)", "SKIPPED", "install `cryptography` to enable")
        else:
            check("manifest signature (Ed25519)", "PASS" if r else "FAIL", f"key_id {body.get('key_id')}")
    else:
        check("manifest signature (Ed25519)", "SKIPPED", "no public key in package")
    leaves = ["{}:{}:{}:{}".format(*e) for e in body["entries"]]
    profile = body.get("merkle_profile", "EIO-MERKLE-0")   # the manifest declares its own rules; never reinterpret
    mp = json.loads((root / "INTEGRITY/merkle_proof.json").read_text())
    expected_leaf = "{}:{}:{}:{}".format(acq["acquisition_id"], acq["source_id"], actual, acq["response_received_utc"])
    if profile == "EIO-MERKLE-1":
        # the root does not commit to the tree size, so the size must match the signed manifest's own entry count
        size_ok = mp.get("tree_size") == len(leaves) == body.get("merkle_tree_size")
        check("Merkle tree size matches the signed manifest", "PASS" if size_ok else "FAIL", f"proof says {mp.get('tree_size')}, manifest has {len(leaves)}")
        recomputed = rfc_root([l.encode() for l in leaves]).hex()
        proof_ok = rfc_verify_inclusion(mp["leaf"].encode(), mp["leaf_index"], mp["tree_size"], mp["audit_path"], body["merkle_root"])
    elif profile == "EIO-MERKLE-0":
        recomputed = legacy_root(leaves)
        proof_ok = legacy_verify_proof(mp["leaf"], mp["proof"], body["merkle_root"])
    else:
        recomputed, proof_ok = None, False
        check("Merkle profile recognised", "FAIL", f"unknown profile {profile!r}")
    check(f"manifest Merkle root recomputed from entries ({profile})", "PASS" if recomputed == body["merkle_root"] else "FAIL", str(body["merkle_root"])[:16] + "...")
    check("Merkle leaf is this acquisition's recorded bytes", "PASS" if mp["leaf"] == expected_leaf else "FAIL")
    check("Merkle inclusion proof", "PASS" if proof_ok else "FAIL")
    check("artifact listed in manifest entries", "PASS" if any(e[0] == acq["acquisition_id"] and e[2] == actual for e in body["entries"]) else "FAIL")

    # 3. RFC 3161 trusted timestamp over the manifest file
    tsr = root / "INTEGRITY/timestamp_response.tsr"
    if not tsr.exists():
        check("RFC 3161 trusted timestamp", "SKIPPED", "package has no timestamp token (evidence is below E3)")
    else:
        ossl = find_openssl(a.openssl)
        ca = default_cafile(a.cafile)
        if not ossl:
            check("RFC 3161 trusted timestamp", "SKIPPED", "openssl not found; pass --openssl")
        elif not ca:
            check("RFC 3161 trusted timestamp", "SKIPPED", "no CA bundle found; pass --cafile")
        else:
            p = subprocess.run([ossl, "ts", "-verify", "-data", str(mfile), "-in", str(tsr), "-CAfile", ca],
                               capture_output=True, text=True)
            ok = p.returncode == 0 and "Verification: OK" in p.stdout
            gen = ""
            q = subprocess.run([ossl, "ts", "-reply", "-in", str(tsr), "-text"], capture_output=True, text=True)
            for line in q.stdout.splitlines():
                if line.strip().startswith("Time stamp:"):
                    gen = line.split(":", 1)[1].strip()
            check("RFC 3161 trusted timestamp covers manifest.json", "PASS" if ok else "FAIL",
                  f"TSA-attested time: {gen}" if ok else (p.stdout + p.stderr).strip()[:300])

    # 3b. additional independent anchors over the same manifest file
    extra = sorted((root / "INTEGRITY/additional_anchors").glob("*.tsr")) if (root / "INTEGRITY/additional_anchors").exists() else []
    for t in extra:
        if find_openssl(a.openssl) and default_cafile(a.cafile):
            p = subprocess.run([find_openssl(a.openssl), "ts", "-verify", "-data", str(mfile), "-in", str(t), "-CAfile", default_cafile(a.cafile)],
                               capture_output=True, text=True)
            check(f"additional independent anchor {t.name}", "PASS" if p.returncode == 0 and "Verification: OK" in p.stdout else "FAIL",
                  "" if p.returncode == 0 else (p.stdout + p.stderr).strip()[:200])
        else:
            check(f"additional independent anchor {t.name}", "SKIPPED", "openssl/CA bundle unavailable")

    # 3c. bundle manifest: every PRESENT component's digest matches, and statuses are stated explicitly
    bm = json.loads((root / "INTEGRITY/bundle_manifest.json").read_text())
    bad_c = [c["component"] for c in bm["components"]
             if c["status"] in ("PRESENT", "RESTRICTED") and c.get("path") and (root / c["path"]).is_file()
             and c.get("digest") and sha256_file(root / c["path"]) != c["digest"]]
    check("bundle manifest component digests", "FAIL" if bad_c else "PASS", f"mismatch: {bad_c}" if bad_c else f"{len(bm['components'])} components")
    gaps = [f"{c['component']}={c['status']}" for c in bm["components"] if c["status"] in ("NOT_COLLECTED", "WITHHELD", "COLLECTION_FAILED")]
    if gaps:
        print("       components not present in this package:", ", ".join(gaps))

    # 4. export manifest
    em = json.loads((root / "EXPORT/export_manifest.json").read_text())
    bad = [f for f, h in em["files"].items() if not (root / f).exists() or sha256_file(root / f) != h]
    check("export manifest file hashes", "FAIL" if bad else "PASS", f"mismatch: {bad}" if bad else f"{len(em['files'])} files")
    if pub_path.exists():
        esig = base64.b64decode((root / "EXPORT/export_manifest.sig").read_text().strip())
        r = ed25519_verify(pub_path.read_bytes(), esig, canon(em))
        check("export manifest signature", "SKIPPED" if r is None else ("PASS" if r else "FAIL"))

    # 5. custody
    if (root / "CUSTODY/chain_of_custody.json").exists():
        cust = json.loads((root / "CUSTODY/chain_of_custody.json").read_text())
        check("custody events present for this acquisition", "PASS" if cust.get("acquisition_events") else "FAIL",
              f"{len(cust.get('acquisition_events', []))} events")
        check("custody ledger chain at export time", "PASS" if cust.get("ledger_verification", {}).get("ok") else "FAIL")
    else:
        check("chain of custody", "SKIPPED", "withheld by this access profile (see EXPORT/redaction_manifest.json)")

    return finish(a)


def finish(a):
    fails = [r for r in RESULTS if r["status"] == "FAIL"]
    skips = [r for r in RESULTS if r["status"] == "SKIPPED"]
    print()
    print("RESULT:", "FAILED" if fails else "PASSED" + (f" ({len(skips)} check(s) skipped)" if skips else ""))
    print("Scope of this result: identified bytes were acquired and existed no later than the attested time.")
    print("It does not establish that the content was accurate, what others saw, or the cause of any difference.")
    out = {"result": "FAILED" if fails else "PASSED", "checks": RESULTS}
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())

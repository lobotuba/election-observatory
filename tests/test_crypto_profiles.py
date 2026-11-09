"""Canonical serialization and Merkle determinism (addendum 003 REQ-CANON/REQ-MERKLE, AT-003-015/016)."""
import hashlib
import json

import pytest

from observatory import archive, manifest, verify_package as vp


@pytest.mark.parametrize("n", list(range(0, 33)) + [63, 64, 65, 100])
def test_two_independent_implementations_agree(n):
    leaves = [f"{i}:src:{hashlib.sha256(str(i).encode()).hexdigest()}:t" for i in range(n)]
    root = manifest.merkle_root(leaves)
    assert vp.rfc_root([l.encode() for l in leaves]).hex() == root
    for i in range(n):
        p = manifest.merkle_proof(leaves, i)
        assert vp.rfc_verify_inclusion(leaves[i].encode(), i, n, p["audit_path"], root)
        assert manifest.verify_inclusion(leaves[i].encode(), i, n, p["audit_path"], root)


def test_wrong_leaf_or_index_fails():
    leaves = [str(i) for i in range(11)]
    root = manifest.merkle_root(leaves)
    p = manifest.merkle_proof(leaves, 4)
    assert not vp.rfc_verify_inclusion(b"5", 4, 11, p["audit_path"], root)
    assert not vp.rfc_verify_inclusion(b"4", 5, 11, p["audit_path"], root)
    assert not vp.rfc_verify_inclusion(b"4", 4, 5, p["audit_path"], root)       # shape-changing size is rejected
    # NOTE: a proof for index 4 verifies equally for sizes 11 and 12 (same left/right shape), because the root does not
    # commit to the tree size. The size therefore comes from the SIGNED manifest and is checked there (next test).


def test_known_rfc6962_vectors():
    # RFC 6962 reference: empty tree = SHA-256(""); single leaf = SHA-256(0x00 || data)
    assert manifest.merkle_root([]) == hashlib.sha256(b"").hexdigest()
    assert manifest.merkle_root(["x"]) == hashlib.sha256(b"\x00x").hexdigest()


def test_no_leaf_duplication_second_preimage():
    """Legacy duplicate-last made [a,b,c] and [a,b,c,c] share a root; the current profile must not."""
    assert manifest.legacy_merkle_root(["a", "b", "c"]) == manifest.legacy_merkle_root(["a", "b", "c", "c"])
    assert manifest.merkle_root(["a", "b", "c"]) != manifest.merkle_root(["a", "b", "c", "c"])


def test_domain_separation_leaf_cannot_masquerade_as_node():
    a, b = b"a", b"b"
    node = manifest._node_hash(manifest._leaf_hash(a), manifest._leaf_hash(b))
    forged_leaf = manifest._leaf_hash(manifest._leaf_hash(a) + manifest._leaf_hash(b))
    assert node != forged_leaf


def test_canonical_json_rules():
    assert manifest._canon({"b": 1, "a": [True, None, "é"]}) == b'{"a":[true,null,"\\u00e9"],"b":1}'
    with pytest.raises(ValueError):
        manifest._canon({"x": float("nan")})
    with pytest.raises(ValueError):
        manifest._no_floats({"clock": {"offset": 1.5}})


def test_archive_is_write_once_and_detects_tampering(tmp_path):
    data = b"exact bytes \r\n with odd endings \xff"
    sha, path, new = archive.store(data, tmp_path)
    assert new and path.read_bytes() == data       # no normalisation of line endings or bytes
    sha2, _, new2 = archive.store(data, tmp_path)
    assert sha2 == sha and not new2                # dedup returns the same artifact
    assert archive.verify(sha, tmp_path)
    path.chmod(0o600)
    path.write_bytes(data[:-1] + b"X")
    assert not archive.verify(sha, tmp_path)

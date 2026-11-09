"""Replay of a synthetic election night + evidence chain, coverage and delta semantics."""
import json
import shutil
import sqlite3
import subprocess
import sys

import requests

from observatory import collector, config, coverage, custody, evidence, manifest, queries
from tests.conftest import BASE_ROWS, TEST_SOURCE_ID, _REAL_SLEEP, make_csv


def votes(rows, **by_cand):
    return [r[:6] + (by_cand.get(str(r[4]), r[6]),) + r[7:] for r in rows]


def play(conn, server, src_factory, bodies, monkeypatch):
    _, state = server
    monkeypatch.setattr(config, "PRIMARY_SOURCE_ID", TEST_SOURCE_ID)
    st = collector.SourceState(src_factory("/csv"))
    s = requests.Session()
    times = []
    for body in bodies:
        state["csv"] = body
        assert collector.acquire(conn, s, st)
        times.append(conn.execute("SELECT MAX(response_received_utc) m FROM acquisitions").fetchone()["m"])
        _REAL_SLEEP(0.05)   # Windows system-clock ticks are ~15 ms; loopback acquisitions can otherwise share a timestamp
    return times


def test_time_travel_deltas_and_negative_values(conn, server, src_factory, monkeypatch):
    b0 = make_csv(BASE_ROWS)
    b1 = make_csv(votes(BASE_ROWS, **{"11": 100, "12": 90}))
    b2 = make_csv(votes(BASE_ROWS, **{"11": 100, "12": 130}))    # lead changes
    b3 = make_csv(votes(BASE_ROWS, **{"11": 95, "12": 130}))     # a candidate's count goes DOWN
    t = play(conn, server, src_factory, [b0, b1, b2, b3], monkeypatch)

    # no future leakage: state at t[1] shows 100/90 even though later data exist
    acq, cs = queries.contests_as_of(conn, TEST_SOURCE_ID, t[1], "nm-2026-general:1")
    assert {c["name"]: c["votes"] for c in cs[0]["candidates"]} == {"ALICE ADAMS": 100, "BOB BROWN": 90}
    assert cs[0]["leader"] == "ALICE ADAMS"
    assert queries.contests_as_of(conn, TEST_SOURCE_ID, "2000-01-01T00:00:00Z")[0] is None

    d = queries.changes_between(conn, TEST_SOURCE_ID, t[0], t[2], "nm-2026-general:1")["changes"][0]
    assert "new_votes" not in d and d["observed_numeric_delta"] == 230   # labelled as an observed delta, not "new votes"
    assert d["lead_change"] and d["delta_cause"] == "UNKNOWN_CAUSE"      # totals rose with no reporting-unit change

    neg = queries.changes_between(conn, TEST_SOURCE_ID, t[2], t[3], "nm-2026-general:1")["changes"][0]
    assert neg["observed_numeric_delta"] == -5 and neg["possible_source_revision"]      # visible, not clamped
    assert neg["delta_cause"] == "UNKNOWN_CAUSE"
    assert any(x["delta"] == -5 for x in neg["candidate_changes"])


def test_byte_flapping_with_identical_results_is_not_a_result_change(conn, server, src_factory, monkeypatch):
    """Observed on the real source: two backends alternate, differing only in ballot-question wording."""
    long_q = [r[:1] + ("Constitutional Amendment 3: " + "very long ballot question text " * 30,) + r[2:] for r in BASE_ROWS]
    short_q = [r[:1] + (r[1][:120],) + r[2:] for r in long_q]
    changed = [r[:6] + (50,) + r[7:] if r[4] == 11 else r for r in long_q]
    play(conn, server, src_factory, [make_csv(long_q), make_csv(short_q), make_csv(long_q), make_csv(short_q), make_csv(changed)], monkeypatch)
    assert conn.execute("SELECT COUNT(DISTINCT sha256) c FROM acquisitions").fetchone()["c"] == 3   # every byte version is still preserved
    stops = queries.change_times(conn, TEST_SOURCE_ID)
    assert len(stops) == 2                                    # first observation + the one real change in results
    assert conn.execute("SELECT COUNT(*) c FROM validation_findings WHERE code='PRESENTATION_VARIANT_SAME_RESULTS'").fetchone()["c"] >= 2
    obs = queries.observation_status(conn, TEST_SOURCE_ID)
    assert obs["recent_byte_versions"] == 3 and obs["recent_result_versions"] == 2


def test_blank_breakdown_is_not_published_not_zero(conn, server, src_factory, monkeypatch):
    play(conn, server, src_factory, [make_csv(BASE_ROWS)], monkeypatch)
    _, cs = queries.contests_as_of(conn, TEST_SOURCE_ID, None)
    c0 = cs[0]["candidates"][0]
    assert c0["votes_early"] is None and c0["breakdown_state"]["early"] == "NOT_PUBLISHED"


def test_coverage_gap_unexpected_and_restoration(conn, server, src_factory, monkeypatch):
    play(conn, server, src_factory, [make_csv(BASE_ROWS)], monkeypatch)
    info = coverage.create_baseline(conn)
    assert info["contests"] == 2 and info["all_zero"]
    missing_gov = [r for r in BASE_ROWS if r[0] == 1]
    extra = BASE_ROWS + [(3, "State Auditor", "", "DEM", 31, "EVE EVANS", 0, "0/100")]
    # gap: Governor disappears; unexpected: a new contest appears
    play(conn, server, src_factory, [make_csv(missing_gov + [extra[-1]])], monkeypatch)
    kinds = {r["kind"] for r in conn.execute("SELECT kind FROM coverage_events")}
    assert {"COVERAGE_GAP", "UNEXPECTED_DISCOVERY"} <= kinds
    assert conn.execute("SELECT COUNT(*) c FROM alerts WHERE kind='COVERAGE_GAP'").fetchone()["c"] == 1
    ev = coverage.evaluate(conn)
    assert ev["contest_counts"]["MISSING_GAP"] == 1 and ev["contest_gaps"][0]["contest_id"] == "nm-2026-general:2"
    # same state again must not flood alerts
    play(conn, server, src_factory, [make_csv(missing_gov + [extra[-1]] + [(9, "x", "", "DEM", 91, "Y", 0, "0/1")])], monkeypatch)
    assert conn.execute("SELECT COUNT(*) c FROM alerts WHERE kind='COVERAGE_GAP'").fetchone()["c"] == 1
    # restored
    play(conn, server, src_factory, [make_csv(BASE_ROWS)], monkeypatch)
    assert "COVERAGE_RESTORED" in {r["kind"] for r in conn.execute("SELECT kind FROM coverage_events")}
    # candidate list changed after baseline
    changed = [r if r[4] != 12 else r[:5] + ("ROBERT BROWNE",) + r[6:] for r in BASE_ROWS]
    play(conn, server, src_factory, [make_csv(changed)], monkeypatch)
    assert "BASELINE_CHANGE" in {r["kind"] for r in conn.execute("SELECT kind FROM coverage_events")}


def test_manifest_chain_package_export_and_tamper(conn, server, src_factory, monkeypatch, tmp_path):
    play(conn, server, src_factory, [make_csv(BASE_ROWS), make_csv(votes(BASE_ROWS, **{"11": 7}))], monkeypatch)
    m = manifest.make_batch(conn)
    assert m and m["seq"] >= 1
    assert evidence.evidence_level(conn, 1)["level"] == "E2"            # chained, but no trusted timestamp yet -> says so
    assert "awaiting a verified RFC 3161" in " ".join(evidence.evidence_level(conn, 1)["notes"])
    pr = evidence.evidence_predicates(conn, 1)["predicates"]
    assert pr["TRUSTED_TIMESTAMP_VERIFIED"]["value"] is False and pr["ARTIFACT_HASH_VERIFIED"]["value"] is True
    assert pr["SOURCE_AUTHORITY_VERIFIED"]["value"] is False and pr["IMMUTABLE_STORAGE_VERIFIED"]["value"] is False
    assert isinstance(pr["CLOCK_WITHIN_POLICY"]["value"], bool) and "trust_score" not in json.dumps(pr).lower()

    for profile in ("public", "research", "internal", "legal", "security"):
        root = evidence.export_package(conn, 1, tmp_path / profile, profile, "pytest")
        r = subprocess.run([sys.executable, "-I", str(root / "verify_package.py"), str(root)], capture_output=True, text=True)
        assert r.returncode == 0, (profile, r.stdout[-800:])
        redaction = json.loads((root / "EXPORT/redaction_manifest.json").read_text())
        if profile == "public":
            assert not (root / "CUSTODY").exists() and redaction["withheld"]
            assert "remote_ip" not in json.loads((root / "SOURCE_IDENTITY/endpoint_observation.json").read_text()) \
                if (root / "SOURCE_IDENTITY/endpoint_observation.json").exists() else True
        if profile == "security":
            assert (root / "CUSTODY").exists()
    # tamper with the original in a copy
    root = tmp_path / "public" / "EIO-EVIDENCE-nm-2026-general-NM-1-PUBLIC"
    p = root / "ORIGINAL/response.bin"
    p.write_bytes(p.read_bytes() + b"x")
    r = subprocess.run([sys.executable, "-I", str(root / "verify_package.py"), str(root)], capture_output=True, text=True)
    assert r.returncode != 0 and "[FAIL]" in r.stdout


def test_custody_chain_detects_tampering(conn, server, src_factory, monkeypatch, tmp_path):
    play(conn, server, src_factory, [make_csv(BASE_ROWS)], monkeypatch)
    assert custody.verify_chain(conn)["ok"]
    copy = tmp_path / "copy.db"
    dst = sqlite3.connect(copy)
    conn.backup(dst)
    dst.row_factory = sqlite3.Row
    for trig in [r[0] for r in dst.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='custody_events'")]:
        dst.execute(f"DROP TRIGGER {trig}")      # an attacker with file access can do this to a COPY...
    dst.execute("UPDATE custody_events SET reason='edited' WHERE event_id=1")
    dst.commit()
    assert not custody.verify_chain(dst)["ok"]   # ...but the hash chain exposes it


def test_audit_segment_tamper_and_gap_detection(conn, server, src_factory, monkeypatch):
    play(conn, server, src_factory, [make_csv(BASE_ROWS)], monkeypatch)
    m = manifest.make_batch(conn)
    path = config.MANIFEST_DIR / m["path"]
    assert manifest.verify_manifest(path)["audit_segments_bad"] == []
    seg = next(config.AUDIT_DIR.glob(f"seg_{m['seq']:06d}_acquisitions.jsonl"))
    seg.write_bytes(seg.read_bytes().replace(b"HTTP", b"HTTX", 1) if b"HTTP" in seg.read_bytes() else seg.read_bytes() + b" ")
    assert manifest.verify_manifest(path)["audit_segments_bad"]
    assert manifest.audit_gaps(conn) == []

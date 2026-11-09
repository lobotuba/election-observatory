"""CLI: python -m observatory <command>

  init | collect [--once] [--seconds N] | serve | status
  evidence-tick            run clock sample, manifest, timestamp queue (and replication) once, now
  evidence-status          counts of artifacts by evidence level, pending timestamps
  verify-manifests         verify every signed manifest and the custody-ledger chain
  export <acq_id> [--out DIR]    write a self-contained evidence package
  verify-package <dir> [--cafile F] [--openssl P] [--json OUT]    offline verification of a package
  reparse
"""
import argparse
import json
import sys


def main(argv=None):
    p = argparse.ArgumentParser(prog="observatory")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    c = sub.add_parser("collect"); c.add_argument("--once", action="store_true"); c.add_argument("--seconds", type=float)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    sub.add_parser("evidence-tick")
    sub.add_parser("evidence-status")
    sub.add_parser("verify-manifests")
    e = sub.add_parser("export"); e.add_argument("acquisition_id", type=int); e.add_argument("--out")
    e.add_argument("--profile", default="public", choices=["public", "research", "internal", "legal", "security"])
    e.add_argument("--requester", default="local operator")
    d = sub.add_parser("add-digest", help="backfill another digest algorithm for every artifact (no schema change)"); d.add_argument("algorithm")
    vp = sub.add_parser("verify-package"); vp.add_argument("package"); vp.add_argument("--cafile"); vp.add_argument("--openssl"); vp.add_argument("--json")
    sub.add_parser("reparse")
    sub.add_parser("status")
    b = sub.add_parser("coverage-baseline", help="freeze the expected-contest baseline from the earliest (pre-results) export")
    b.add_argument("--acquisition", type=int); b.add_argument("--notes", default="")
    sub.add_parser("coverage-status")
    x = sub.add_parser("crosscheck", help="classify narrower NM exports against the STATE baseline export")
    x.add_argument("--detail", action="store_true")
    sub.add_parser("authority-refresh")
    sub.add_parser("backfill-fingerprints", help="compute result fingerprints for already-parsed CSV acquisitions")
    q = sub.add_parser("qualify", help="run self-tests and write a signed, timestamped Evidence System Qualification Record")
    q.add_argument("--with-pytest", action="store_true")
    a = p.parse_args(argv)

    from . import config
    from .db import connect, init_db, sync_source_registry

    if a.cmd == "collect":
        from . import collector
        collector.run(stop_after_s=a.seconds, once=a.once)
        return
    if a.cmd == "serve":
        import uvicorn
        config.ensure_dirs()
        conn = connect(); init_db(conn); sync_source_registry(conn); conn.close()
        uvicorn.run("observatory.api:app", host=a.host, port=a.port, log_level="info")
        return
    if a.cmd == "verify-package":
        from . import verify_package
        sys.argv = ["verify_package", a.package] + (["--cafile", a.cafile] if a.cafile else []) + \
                   (["--openssl", a.openssl] if a.openssl else []) + (["--json", a.json] if a.json else [])
        sys.exit(verify_package.main())

    conn = connect()
    init_db(conn)
    sync_source_registry(conn)
    if a.cmd == "init":
        print(f"initialised {config.DB_PATH}")
    elif a.cmd == "evidence-tick":
        from . import evidence_jobs
        print(json.dumps(evidence_jobs.tick(conn, {}), indent=1, default=str))
    elif a.cmd == "evidence-status":
        from . import evidence, tsa
        print(json.dumps(evidence.evidence_summary(conn), indent=1))
        print("pending manifests (no verified trusted timestamp):", [m["seq"] for m in tsa.pending_manifests(conn)])
    elif a.cmd == "verify-manifests":
        from . import custody, manifest
        bad = 0
        for path in sorted(config.MANIFEST_DIR.glob("manifest_*.json")):
            r = manifest.verify_manifest(path)
            ok = r["signature_valid"] and r["merkle_ok"] and not r["artifacts_bad"] and not r["audit_segments_bad"]
            bad += not ok
            print(("OK  " if ok else "FAIL"), path.name, f"artifacts={r['artifacts_checked']}",
                  f"bad_audit_segments={r['audit_segments_bad']}" if r["audit_segments_bad"] else "")
        led = custody.verify_chain(conn)
        gaps = manifest.audit_gaps(conn)
        print("custody ledger:", led)
        print("sequence gaps:", gaps or "none")
        sys.exit(1 if bad or not led["ok"] or gaps else 0)
    elif a.cmd == "export":
        from pathlib import Path
        from . import evidence
        root = evidence.export_package(conn, a.acquisition_id, Path(a.out) if a.out else None, a.profile, a.requester)
        print(root)
    elif a.cmd == "add-digest":
        from . import archive, provenance
        n = 0
        for r in conn.execute("SELECT DISTINCT sha256 FROM acquisitions WHERE sha256 IS NOT NULL").fetchall():
            provenance.record_digests(conn, r["sha256"], archive.read(r["sha256"]), [a.algorithm])
            n += 1
        print(f"{a.algorithm}: processed {n} artifacts")
    elif a.cmd == "coverage-baseline":
        from . import coverage
        print(json.dumps(coverage.create_baseline(conn, a.acquisition, notes=a.notes), indent=1))
    elif a.cmd == "coverage-status":
        from . import coverage
        r = coverage.evaluate(conn)
        print(json.dumps({k: r[k] for k in ("coverage_manifest", "source_counts", "contest_counts", "national_federal") if k in r}, indent=1, default=str))
        print("gaps:", r.get("contest_gaps"), "unexpected:", len(r.get("unexpected", [])))
    elif a.cmd == "crosscheck":
        from . import crosscheck
        for r in crosscheck.run_all(conn, a.detail):
            print(r["source_id"], r["contests"], {k: v for k, v in r["classes"].items() if v}, r.get("notes") or "")
            for d in r.get("differences", [])[:40]:
                print("   ", d)
    elif a.cmd == "backfill-fingerprints":
        from . import pipeline
        n = 0
        for r in conn.execute("SELECT DISTINCT a.acquisition_id FROM acquisitions a JOIN parse_runs p ON p.acquisition_id=a.acquisition_id AND p.status='OK' "
                              "WHERE p.parser_name='nm_sos_csv' AND a.acquisition_id NOT IN (SELECT acquisition_id FROM result_fingerprints)").fetchall():
            n += bool(pipeline.store_fingerprint(conn, r["acquisition_id"]))
        print(f"fingerprinted {n} acquisitions")
    elif a.cmd == "authority-refresh":
        from . import authority
        print(authority.refresh(conn))
    elif a.cmd == "qualify":
        from . import qualification
        r = qualification.run(conn, with_pytest=a.with_pytest)
        print(json.dumps(r, indent=1, default=str))
        sys.exit(0 if not r["failed"] else 1)
    elif a.cmd == "reparse":
        from . import pipeline
        n = 0
        for r in conn.execute("SELECT acquisition_id FROM acquisitions WHERE sha256 IS NOT NULL AND content_changed=1 "
                              "AND http_status<400 ORDER BY acquisition_id").fetchall():
            out = pipeline.parse_acquisition(conn, r["acquisition_id"])
            n += out["status"] not in ("SKIPPED", "NO_ARTIFACT")
        print(f"reparsed {n} acquisitions")
    elif a.cmd == "status":
        from . import queries
        for h in queries.source_health(conn):
            print(f"{h['state']:<16}{h['source_id']:<22}polls={h['polls']:<5}err={h['errors']:<3}chg={h['changes']:<4}last={h['last_success_utc']}")


if __name__ == "__main__":
    main()

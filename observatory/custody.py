"""Append-only, hash-chained chain-of-custody ledger (addendum 4.11)."""
import hashlib
import json
import socket

from .db import now_utc

HOST = socket.gethostname()
FIELDS = ["evidence_kind", "evidence_id", "event_type", "event_utc", "actor", "host", "reason",
          "prior_state", "new_state", "artifact_sha256", "authorization_ref"]


def _hash(prev: str | None, rec: dict) -> str:
    payload = json.dumps([rec[f] for f in FIELDS] + [prev], separators=(",", ":"), sort_keys=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def append_many(conn, events: list[dict]):
    """Each event: evidence_kind, evidence_id, event_type, and optional reason/prior_state/new_state/artifact_sha256/actor."""
    own_txn = not conn.in_transaction
    if own_txn:
        conn.execute("BEGIN IMMEDIATE")  # serialise writers so the chain stays linear across processes
    try:
        row = conn.execute("SELECT event_hash FROM custody_events ORDER BY event_id DESC LIMIT 1").fetchone()
        prev = row["event_hash"] if row else None
        for e in events:
            rec = dict(evidence_kind=e["evidence_kind"], evidence_id=e["evidence_id"], event_type=e["event_type"],
                       event_utc=e.get("event_utc") or now_utc(), actor=e.get("actor", "observatory-collector"),
                       host=HOST, reason=e.get("reason"), prior_state=e.get("prior_state"), new_state=e.get("new_state"),
                       artifact_sha256=e.get("artifact_sha256"), authorization_ref=e.get("authorization_ref"))
            h = _hash(prev, rec)
            conn.execute(
                f"INSERT INTO custody_events({','.join(FIELDS)},prev_event_hash,event_hash) VALUES ({','.join('?' * len(FIELDS))},?,?)",
                [rec[f] for f in FIELDS] + [prev, h])
            prev = h
        if own_txn:
            conn.execute("COMMIT")
    except Exception:
        if own_txn:
            conn.execute("ROLLBACK")
        raise


def append(conn, **event):
    append_many(conn, [event])


def verify_chain(conn) -> dict:
    prev, n = None, 0
    for r in conn.execute("SELECT * FROM custody_events ORDER BY event_id"):
        rec = {f: r[f] for f in FIELDS}
        if r["prev_event_hash"] != prev or _hash(prev, rec) != r["event_hash"]:
            return {"ok": False, "first_bad_event_id": r["event_id"], "checked": n}
        prev, n = r["event_hash"], n + 1
    return {"ok": True, "checked": n, "head": prev}


def for_evidence(conn, kind: str, evidence_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM custody_events WHERE evidence_kind=? AND evidence_id=? ORDER BY event_id", (kind, evidence_id))]

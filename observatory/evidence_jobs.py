"""Background evidence worker: clock samples, manifests, RFC 3161 timestamps, replication."""
import logging
import threading
import time

from . import authority, clock, config, endpoint, manifest, replication, tsa
from .db import connect, init_db

log = logging.getLogger("evidence")


def tick(conn, state: dict) -> dict:
    """Run whichever jobs are due. `state` carries last-run monotonic times between calls."""
    now = time.monotonic()
    out = {}
    if now - state.get("clock", -1e9) >= config.CLOCK_SAMPLE_INTERVAL_S:
        state["clock"] = now
        try:
            out["clock"] = clock.sample(conn)
        except Exception:
            log.exception("clock sample failed")
    if now - state.get("endpoint", -1e9) >= config.ENDPOINT_PROBE_INTERVAL_S:
        state["endpoint"] = now
        try:
            out["endpoint"] = endpoint.probe(conn)
        except Exception:
            log.exception("endpoint probe failed")
    if now - state.get("manifest", -1e9) >= config.MANIFEST_INTERVAL_S:
        state["manifest"] = now
        try:
            m = manifest.make_batch(conn)
            out["manifest"] = m["seq"] if m else None
            if m:
                log.info("manifest seq %s: %s acquisitions, merkle %s", m["seq"], m["artifact_count"], (m["merkle_root"] or "none (audit-only)")[:16])
        except Exception:
            log.exception("manifest creation failed")
    if now - state.get("authority", -1e9) >= 1800:
        state["authority"] = now
        try:
            out["authority"] = authority.refresh(conn)
        except Exception:
            log.exception("authority record refresh failed")
    if now - state.get("tsa", -1e9) >= 20:  # retry queue is checked often; per-manifest backoff lives in tsa.process_queue
        state["tsa"] = now
        try:
            out["tsa"] = tsa.process_queue(conn)
        except Exception:
            log.exception("timestamp queue failed")
    if config.REPLICA_DIR and now - state.get("repl", -1e9) >= 120:
        state["repl"] = now
        try:
            out["replication"] = replication.run(conn)
        except Exception:
            log.exception("replication failed")
    return out


def start_background(skip: bool = False):
    if skip:
        return None
    stop = threading.Event()

    def loop():
        conn = connect()
        init_db(conn)
        state = {"clock": time.monotonic(), "endpoint": time.monotonic()}  # the collector already took the first samples
        while not stop.is_set():
            tick(conn, state)
            stop.wait(5)

    threading.Thread(target=loop, name="evidence-jobs", daemon=True).start()
    return stop

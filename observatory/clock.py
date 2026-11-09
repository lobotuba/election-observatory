"""Clock monitoring (addendum 4.6): independent SNTP offsets from several servers plus the OS sync state."""
import json
import socket
import statistics
import struct
import subprocess
import time

from . import config
from .db import now_utc

NTP_EPOCH_DELTA = 2208988800  # seconds between 1900-01-01 and 1970-01-01


def sntp_query(server: str, timeout: float = 2.0) -> dict:
    """One SNTP exchange. offset_ms > 0 means the local clock is BEHIND the server."""
    pkt = b"\x1b" + 47 * b"\0"  # LI=0, VN=3, Mode=3 (client)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t1 = time.time()
        s.sendto(pkt, (server, 123))
        data, _ = s.recvfrom(512)
        t4 = time.time()
    if len(data) < 48:
        raise ValueError("short NTP reply")
    f = struct.unpack("!12I", data[:48])
    stratum = (data[1])
    t2 = f[8] - NTP_EPOCH_DELTA + f[9] / 2**32   # server receive
    t3 = f[10] - NTP_EPOCH_DELTA + f[11] / 2**32  # server transmit
    offset = ((t2 - t1) + (t3 - t4)) / 2
    delay = (t4 - t1) - (t3 - t2)
    return {"server": server, "stratum": stratum, "offset_ms": round(offset * 1000, 2), "delay_ms": round(delay * 1000, 2)}


def os_sync_status() -> dict:
    try:
        out = subprocess.run(["w32tm", "/query", "/status"], capture_output=True, text=True, timeout=10).stdout
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    keys = {"Stratum", "Source", "Last Successful Sync Time", "Poll Interval", "Root Dispersion", "Leap Indicator"}
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip() in keys:
                d[k.strip()] = v.strip()
    return d


def sample(conn) -> dict:
    """Take and persist one clock sample. Returns the stored summary."""
    results, errors = [], []
    for srv in config.NTP_SERVERS:
        try:
            results.append(sntp_query(srv))
        except Exception as e:
            errors.append(f"{srv}: {type(e).__name__}")
    if results:
        # Trust the exchanges with the lowest round-trip delay; asymmetric paths inflate error on slow ones.
        best = sorted(results, key=lambda r: r["delay_ms"])[: max(1, (len(results) + 1) // 2)]
        offset = statistics.median(r["offset_ms"] for r in best)
        uncertainty = max(r["delay_ms"] for r in best) / 2
        spread = max(r["offset_ms"] for r in results) - min(r["offset_ms"] for r in results)
    else:
        offset = uncertainty = spread = None
    if offset is None:
        state = "UNKNOWN"
    elif abs(offset) > config.CLOCK_TOLERANCE_MS:
        state = "DEGRADED"
    else:
        state = "SYNCHRONIZED"
    osd = os_sync_status()
    cur = conn.execute(
        "INSERT INTO clock_status(sampled_utc,host,offset_ms,uncertainty_ms,spread_ms,state,servers_json,errors_json,os_sync_json,tolerance_ms) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (now_utc(), socket.gethostname(), offset, uncertainty, spread, state, json.dumps(results),
         json.dumps(errors), json.dumps(osd), config.CLOCK_TOLERANCE_MS),
    )
    if offset is not None and abs(offset) > config.CLOCK_ALERT_MS:
        conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                     (now_utc(), None, "CLOCK_OFFSET", f"collector clock offset {offset} ms exceeds {config.CLOCK_ALERT_MS} ms"))
    return {"clock_id": cur.lastrowid, "state": state, "offset_ms": offset}


def confidence(conn, at_utc: str) -> tuple[str, int | None]:
    """TIME_CONFIDENCE for an acquisition: based on the latest clock sample at or before it."""
    row = conn.execute("SELECT clock_id, sampled_utc, state FROM clock_status WHERE sampled_utc<=? ORDER BY clock_id DESC LIMIT 1", (at_utc,)).fetchone()
    if not row:
        return "TIME_CONFIDENCE_UNKNOWN", None
    from datetime import datetime
    age = (datetime.fromisoformat(at_utc.replace("Z", "+00:00")) - datetime.fromisoformat(row["sampled_utc"].replace("Z", "+00:00"))).total_seconds()
    if row["state"] != "SYNCHRONIZED" or age > config.CLOCK_MAX_AGE_S:
        return ("TIME_CONFIDENCE_DEGRADED" if row["state"] == "DEGRADED" or age > config.CLOCK_MAX_AGE_S
                else "TIME_CONFIDENCE_UNKNOWN"), row["clock_id"]
    return "TIME_CONFIDENCE_OK", row["clock_id"]

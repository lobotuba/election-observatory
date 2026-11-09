"""Polite, single-threaded collector: archive first, hash, record, then parse.

Every attempt, successful or not, is its own append-only acquisition event (addendum 003 REQ-OBS-001/005).
"""
import gzip
import http.cookiejar
import json
import logging
import random
import time
import uuid
import zlib
from datetime import datetime, timedelta, timezone

import requests
import urllib3

from . import (COLLECTOR_NAME, VERSION, archive, clock, config, custody, endpoint, evidence_jobs, parsers, pipeline,
               provenance)
from .db import connect, init_db, now_utc, sync_source_registry

log = logging.getLogger("collector")

MIN_GAP_S = 1.0  # host-level concurrency of 1, with a minimum gap between requests

# REQ-OBS-002 failure statuses that are worth an in-schedule retry (each retry is a distinct event)
RETRYABLE = {"DNS_FAILED", "CONNECTION_FAILED", "TLS_FAILED", "TIMEOUT_BEFORE_HEADERS", "TIMEOUT_DURING_BODY", "CONNECTION_RESET",
             "PARTIAL_RESPONSE", "HTTP_SERVER_ERROR", "RATE_LIMITED", "EMPTY_RESPONSE", "UNKNOWN_FAILURE"}
# REQ-OBS-003 negative-observation semantics derived from the failure status
UNAVAILABLE = {"DNS_FAILED", "CONNECTION_FAILED", "TLS_FAILED", "CERTIFICATE_VALIDATION_FAILED", "TIMEOUT_BEFORE_HEADERS",
               "TIMEOUT_DURING_BODY", "CONNECTION_RESET", "HTTP_SERVER_ERROR", "RATE_LIMITED"}


def observation_status_for(failure_status: str | None, changed: int | None) -> str:
    if failure_status is None:
        return "OBSERVED_CHANGED" if changed else "OBSERVED_UNCHANGED"
    if failure_status in UNAVAILABLE:
        return "SOURCE_UNAVAILABLE"
    if failure_status == "EMPTY_RESPONSE":
        return "SOURCE_RETURNED_EMPTY"
    if failure_status == "PARTIAL_RESPONSE":
        return "SOURCE_RETURNED_PARTIAL"
    return "OBSERVATION_FAILED"


class SourceState:
    def __init__(self, src):
        self.src = src
        self.next_due = 0.0
        self.failures = 0            # consecutive failed polls (a poll = one schedule, all its attempts)
        self.circuit_open_until = 0.0
        self.paused = False
        self.etag = None
        self.last_modified = None
        self.prior_id = None
        self.prior_sha = None
        self.prior_norm = None
        self.prior_version = None
        self.scheduled_utc = None
        self.release_id = None
        self.config_version_id = None
        self.alerted_streak = False

    @property
    def interval(self):
        return self.src["polling_interval_s"] * config.INTERVAL_SCALE


def _norm_sha(src, data: bytes) -> str:
    return archive.sha256_hex(parsers.normalize_for_change(src["expected_format"], data))


def _load_state(conn, st: SourceState):
    row = conn.execute(
        "SELECT acquisition_id, sha256, decoded_sha256, etag, last_modified, source_version_id FROM acquisitions "
        "WHERE source_id=? AND sha256 IS NOT NULL AND error_class IS NULL ORDER BY acquisition_id DESC LIMIT 1",
        (st.src["source_id"],),
    ).fetchone()
    if row:
        st.prior_id, st.prior_sha, st.etag, st.last_modified, st.prior_version = (
            row["acquisition_id"], row["sha256"], row["etag"], row["last_modified"], row["source_version_id"])
        st.prior_norm = _norm_sha(st.src, archive.read(row["decoded_sha256"] or row["sha256"]))


def _alert(conn, source_id, kind, detail):
    conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                 (now_utc(), source_id, kind, detail))
    log.warning("ALERT %s %s %s", source_id, kind, detail)


def _safe_headers(resp) -> dict:
    # Session cookies are handled by the restricted tier (REQ-EVID-020), not the public header record.
    return {k: v for k, v in resp.headers.items() if k.lower() != "set-cookie"}


def classify_exception(e: Exception, body_phase: bool) -> tuple[str, str]:
    """Map an exception to (REQ-OBS-002 failure status, stage reached)."""
    text = f"{type(e).__name__}: {e}"
    low = text.lower()
    if isinstance(e, requests.exceptions.SSLError):
        if "certificate_verify_failed" in low or "certificate verify failed" in low:
            return "CERTIFICATE_VALIDATION_FAILED", "TLS"
        return "TLS_FAILED", "TLS"
    if isinstance(e, requests.exceptions.TooManyRedirects):
        return "REDIRECT_POLICY_FAILED", "REDIRECTS"
    if isinstance(e, requests.exceptions.ConnectTimeout):
        return "TIMEOUT_BEFORE_HEADERS", "TCP_CONNECT"
    if isinstance(e, (requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError, TimeoutError)) or "timed out" in low:
        return ("TIMEOUT_DURING_BODY", "BODY_READ") if body_phase else ("TIMEOUT_BEFORE_HEADERS", "AWAITING_HEADERS")
    if any(k in low for k in ("getaddrinfo", "nameresolution", "name or service not known", "temporary failure in name resolution")):
        return "DNS_FAILED", "DNS"
    if "connection reset" in low or isinstance(e, ConnectionResetError):
        return "CONNECTION_RESET", "BODY_READ" if body_phase else "AWAITING_HEADERS"
    if body_phase and any(k in low for k in ("incompleteread", "connection broken", "protocolerror", "chunkedencodingerror")):
        return "PARTIAL_RESPONSE", "BODY_READ"
    if isinstance(e, (requests.exceptions.ChunkedEncodingError, urllib3.exceptions.ProtocolError, urllib3.exceptions.IncompleteRead)):
        return "PARTIAL_RESPONSE", "BODY_READ"
    if isinstance(e, requests.exceptions.ConnectionError):
        return "CONNECTION_FAILED", "TCP_CONNECT"
    return "UNKNOWN_FAILURE", "UNKNOWN"


def decode_content(entity: bytes, content_encoding: str) -> tuple[bytes | None, str | None, str]:
    """REQ-BYTE-004: decode a Content-Encoding. Returns (decoded|None, failure_status|None, detail)."""
    ce = (content_encoding or "").strip().lower()
    if not ce or ce == "identity":
        return None, None, "no content encoding"
    try:
        if ce in ("gzip", "x-gzip"):
            out = gzip.decompress(entity)
            impl = "python-gzip"
        elif ce == "deflate":
            try:
                out = zlib.decompress(entity)
            except zlib.error:
                out = zlib.decompress(entity, -zlib.MAX_WBITS)
            impl = "python-zlib"
        else:
            return None, "DECOMPRESSION_FAILED", f"unsupported Content-Encoding {ce!r}"
        return out, None, f"{impl}; input {len(entity)} bytes -> output {len(out)} bytes"
    except Exception as e:
        return None, "DECOMPRESSION_FAILED", f"{type(e).__name__}: {e}"


def _attempt(conn, session, st: SourceState, schedule_id: str, attempt_no: int, scheduler_utc: str, first_id: int | None) -> dict:
    src = st.src
    url = src["endpoint_url"]
    # identity encoding: ask for the unencoded entity so the stored bytes are the entity as delivered.
    headers = {"User-Agent": config.USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"}
    if st.etag:
        headers["If-None-Match"] = st.etag
    if st.last_modified:
        headers["If-Modified-Since"] = st.last_modified

    started_utc, t0 = now_utc(), time.monotonic()
    sent_utc = now_utc()
    resp, entity, chunks = None, b"", []
    fail = detail = None
    stage = "REQUEST_SENT"
    first_byte_utc = None
    try:
        verify = config.tls_bundle(src["tls_extra_ca"]) if src.get("tls_extra_ca") else True
        resp = session.get(url, headers=headers, timeout=(10, config.REQUEST_TIMEOUT_S), allow_redirects=True, stream=True, verify=verify)
        stage = "HEADERS_RECEIVED"
        try:
            first_byte_utc = (datetime.fromisoformat(sent_utc.replace("Z", "+00:00")) + resp.elapsed
                              ).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except Exception:
            pass
        try:
            for chunk in resp.raw.stream(65536, decode_content=False):  # entity bytes, before content decoding
                chunks.append(chunk)
            stage = "BODY_READ"
            resp.raw.release_conn()
        except Exception as be:
            fail, stage = classify_exception(be, True)
            detail = f"{type(be).__name__}: {be}"[:400]
            resp.close()
        entity = b"".join(chunks)
    except requests.RequestException as e:
        fail, stage = classify_exception(e, False)
        detail = f"{type(e).__name__}: {e}"[:400]
    except Exception as e:  # anything unforeseen is still an event
        fail, stage, detail = "UNKNOWN_FAILURE", "UNKNOWN", f"{type(e).__name__}: {e}"[:400]

    received_utc = now_utc()
    duration_ms = int((time.monotonic() - t0) * 1000)
    status = resp.status_code if resp is not None else None
    hdrs = _safe_headers(resp) if resp is not None else {}
    if fail is None and status is not None:
        if status == 429:
            fail, detail = "RATE_LIMITED", "HTTP 429"
        elif status == 401:
            fail, detail = "AUTHENTICATION_FAILED", "HTTP 401"
        elif status == 403:
            fail, detail = "AUTHORIZATION_DENIED", "HTTP 403"
        elif status >= 500:
            fail, detail = "HTTP_SERVER_ERROR", f"HTTP {status}"
        elif status >= 400:
            fail, detail = "HTTP_CLIENT_ERROR", f"HTTP {status}"
        elif status != 304 and not entity:
            fail, detail = "EMPTY_RESPONSE", f"HTTP {status} with zero-length body"

    # decode (transport -> content layer), keeping both forms (REQ-BYTE-003)
    decoded, decode_fail, decode_detail = (None, None, "no content encoding")
    if entity and fail is None:
        decoded, decode_fail, decode_detail = decode_content(entity, hdrs.get("Content-Encoding", ""))
        if decode_fail:
            fail, detail = decode_fail, decode_detail

    sha = path = norm = decoded_sha = None
    changed = None
    st_times = {}
    if status == 304 and fail is None:
        sha, changed = st.prior_sha, 0
    elif entity:
        try:
            st_times = archive.store_timed(entity)   # evidence first, even for error pages and partial bodies
            sha, path = st_times["sha"], str(st_times["path"].relative_to(config.ARCHIVE_DIR))
            if decoded is not None:
                decoded_sha = archive.store_timed(decoded)["sha"]
            if fail is None:
                norm = _norm_sha(src, decoded if decoded is not None else entity)
                changed = 0 if norm == st.prior_norm else 1
        except Exception as e:
            fail, detail, stage = "ARCHIVE_WRITE_FAILED", f"{type(e).__name__}: {e}"[:400], "ARCHIVE_WRITE"
            st_times = {}
            sha = path = None

    time_conf, clock_id = clock.confidence(conn, received_utc)
    chain = [{"url": h.url, "status": h.status_code} for h in resp.history] if resp is not None else []
    restricted_commitment = restricted_path = None
    set_cookie = resp.headers.get("Set-Cookie") if resp is not None else None
    if set_cookie:
        restricted_commitment, restricted_path = provenance.commit_restricted(
            f"acq_{received_utc.replace(':', '').replace('.', '')}_{src['source_id']}_{attempt_no}", {"Set-Cookie": set_cookie})
    final_url = resp.url if resp is not None else None
    if final_url:
        endpoint.check_response_path(conn, src["source_id"], url, final_url)
    http_version = {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2"}.get(getattr(getattr(resp, "raw", None), "version", None)) if resp is not None else None
    if st_times and st_times.get("newly_written") and sha:
        provenance.record_digests(conn, sha, entity)
    version_id = hdrs.get("ETag") or hdrs.get("Last-Modified")
    # Which backend instance answered? ARRAffinity identifies it; only a short hash is kept in the public record
    # (the cookie itself stays in the restricted tier). Lets alternating versions be tied to an instance.
    instance_tag = None
    if set_cookie:
        import re as _re
        m_aff = _re.search(r"ARRAffinity=([^;,\s]+)", set_cookie)
        if m_aff:
            instance_tag = archive.sha256_hex(m_aff.group(1).encode())[:12]
    retryable = fail in RETRYABLE and attempt_no <= config.MAX_RETRIES
    delay = None
    if retryable:
        delay = min(2 ** (attempt_no - 1) * 2, 20) + random.random()
        if fail == "RATE_LIMITED":
            try:
                delay = min(float(hdrs.get("Retry-After", delay)), 60)
            except ValueError:
                pass
    obs_status = observation_status_for(fail, changed)

    row = dict(
        source_id=src["source_id"], election_id=config.ELECTION_ID, requested_url=url, http_method="GET",
        request_started_utc=started_utc, response_received_utc=received_utc, duration_ms=duration_ms, http_status=status,
        redirect_chain=json.dumps(chain), response_headers=json.dumps(hdrs), content_type=hdrs.get("Content-Type"),
        content_encoding=hdrs.get("Content-Encoding"), content_length=len(entity) if resp is not None else None,
        etag=hdrs.get("ETag"), last_modified=hdrs.get("Last-Modified"), cache_control=hdrs.get("Cache-Control"),
        sha256=sha, artifact_path=path, collector_name=COLLECTOR_NAME, collector_version=VERSION, prior_acquisition_id=st.prior_id,
        content_changed=changed, error_class=fail, error_detail=detail, retry_count=attempt_no - 1, normalized_sha256=norm,
        scheduler_created_utc=scheduler_utc, request_sent_utc=sent_utc, first_byte_received_utc=first_byte_utc,
        response_completed_utc=received_utc, artifact_write_started_utc=st_times.get("write_started_utc"),
        artifact_write_completed_utc=st_times.get("write_completed_utc"), hash_calculated_utc=st_times.get("hash_calculated_utc"),
        hash_algorithm="sha256" if sha else None, hash_implementation="python-hashlib" if sha else None,
        post_write_verified=(1 if st_times.get("post_write_verified") else 0) if st_times else None,
        time_confidence=time_conf, clock_id=clock_id,
        release_id=st.release_id, source_config_version_id=st.config_version_id, endpoint_obs_id=endpoint.latest_id(conn),
        final_url=final_url, http_version=http_version, set_cookie_present=1 if set_cookie else 0,
        restricted_commitment=restricted_commitment, restricted_path=restricted_path,
        bytes_on_wire_note=("byte_layer=HTTP_ENTITY_PAYLOAD (transfer-decoded, before content decoding); raw wire/TLS bytes are not "
                            "exposed by this HTTP library and are NOT claimed") if sha else None,
        attempt_number=attempt_no, schedule_id=schedule_id, retry_of_acquisition_id=first_id if attempt_no > 1 else None,
        failure_status=fail, stage_reached=stage, configured_timeout_s=config.REQUEST_TIMEOUT_S, observation_status=obs_status,
        next_retry_utc=(datetime.now(timezone.utc) + timedelta(seconds=delay)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if delay else None,
        byte_layer="HTTP_ENTITY_PAYLOAD" if sha else None, transfer_encoding=hdrs.get("Transfer-Encoding"),
        decoded_sha256=decoded_sha, decoded_length=len(decoded) if decoded is not None else None, decode_detail=decode_detail,
        source_version_id=version_id, origin_instance_tag=instance_tag,
    )
    cur = conn.execute(f"INSERT INTO acquisitions({','.join(row)}) VALUES ({','.join('?' * len(row))})", list(row.values()))
    acq_id = cur.lastrowid

    if st_times:
        custody.append_many(conn, [
            dict(evidence_kind="acquisition", evidence_id=acq_id, event_type="ACQUIRED", artifact_sha256=sha, event_utc=received_utc,
                 reason=f"GET {url} (attempt {attempt_no}, {obs_status})",
                 new_state="E1_HASHED" if st_times["post_write_verified"] else "E0_UNVERIFIED"),
            dict(evidence_kind="acquisition", evidence_id=acq_id, event_type="HASH_VERIFIED", artifact_sha256=sha,
                 event_utc=st_times["write_completed_utc"],
                 reason="post-write read-back digest " + ("matched" if st_times["post_write_verified"] else "DID NOT MATCH"),
                 new_state="verified" if st_times["post_write_verified"] else "FAILED"),
        ])
        if not st_times["post_write_verified"]:
            _alert(conn, src["source_id"], "ARCHIVE_VERIFY_FAILED", f"acquisition {acq_id} sha {sha}")
    else:
        custody.append(conn, evidence_kind="acquisition", evidence_id=acq_id, event_type="ATTEMPT_RECORDED",
                       event_utc=received_utc, reason=f"GET {url} attempt {attempt_no}: {obs_status} {fail or ''} at stage {stage}",
                       new_state=obs_status)
    if fail == "CERTIFICATE_VALIDATION_FAILED":
        _alert(conn, src["source_id"], "ENDPOINT_ANOMALY", f"certificate validation failed: {detail}")
    if fail == "ARCHIVE_WRITE_FAILED":
        _alert(conn, src["source_id"], "ARCHIVE_WRITE_FAILED", detail or "")

    ok = fail is None
    if ok:
        # REQ-VERSION-003: version identity vs byte identity disagreeing is a reviewable anomaly
        if version_id and st.prior_version:
            if version_id == st.prior_version and changed:
                conn.execute("INSERT INTO validation_findings(acquisition_id,severity,code,detail,created_utc) VALUES (?,?,?,?,?)",
                             (acq_id, "WARN", "SOURCE_VERSION_ANOMALY", "same source version id but different bytes", now_utc()))
            elif version_id != st.prior_version and changed == 0:
                conn.execute("INSERT INTO validation_findings(acquisition_id,severity,code,detail,created_utc) VALUES (?,?,?,?,?)",
                             (acq_id, "WARN", "SOURCE_VERSION_ANOMALY", "different source version id but identical bytes", now_utc()))
        if hdrs.get("ETag"):
            st.etag = hdrs["ETag"]
        if hdrs.get("Last-Modified"):
            st.last_modified = hdrs["Last-Modified"]
        if changed:
            outcome = pipeline.parse_acquisition(conn, acq_id)
            log.info("%s acq=%s %s bytes sha=%s parse=%s", src["source_id"], acq_id, len(entity), (sha or "")[:10], outcome.get("status"))
        else:
            log.debug("%s acq=%s unchanged", src["source_id"], acq_id)
        if sha:
            st.prior_id, st.prior_sha, st.prior_version = acq_id, sha, version_id
            if norm:
                st.prior_norm = norm
    else:
        log.warning("%s acq=%s attempt %d %s (%s) stage=%s", src["source_id"], acq_id, attempt_no, fail, obs_status, stage)
    return {"ok": ok, "retry_delay": delay, "acq_id": acq_id}


def acquire(conn, session: requests.Session, st: SourceState) -> bool:
    """One scheduled collection: up to 1+MAX_RETRIES attempts, each a distinct, linked acquisition event."""
    schedule_id = uuid.uuid4().hex
    scheduler_utc = st.scheduled_utc or now_utc()
    first_id = None
    for attempt_no in range(1, config.MAX_RETRIES + 2):
        r = _attempt(conn, session, st, schedule_id, attempt_no, scheduler_utc, first_id)
        first_id = first_id or r["acq_id"]
        if r["ok"]:
            return True
        if r["retry_delay"] is None:
            return False
        time.sleep(r["retry_delay"])
    return False


def run(stop_after_s: float | None = None, once: bool = False):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config.ensure_dirs()
    conn = connect()
    init_db(conn)
    sync_source_registry(conn)
    session = requests.Session()
    session.cookies.set_policy(http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))  # keep no cookies

    states = [SourceState(s) for s in config.SOURCES]
    release_id = provenance.register_release(conn)
    cfg_ids = provenance.register_source_configs(conn)
    for st in states:
        _load_state(conn, st)
        st.release_id, st.config_version_id = release_id, cfg_ids[st.src["source_id"]]
    try:  # endpoint identity before the first request
        log.info("initial endpoint observation: %s", endpoint.probe(conn))
    except Exception:
        log.exception("initial endpoint probe failed")
    t_start = time.monotonic()
    last_request = 0.0
    log.info("collector started: %d sources, interval scale %.2f, data dir %s",
             len(states), config.INTERVAL_SCALE, config.DATA_DIR)
    try:  # so the very first acquisitions already have a clock reference
        log.info("initial clock sample: %s", clock.sample(conn))
    except Exception:
        log.exception("initial clock sample failed")
    # Clock sampling, manifests, RFC 3161 timestamping and replication run off the polling thread
    # so a slow TSA can never delay source collection.
    stop_evt = evidence_jobs.start_background(skip=once)

    while True:
        if stop_after_s and time.monotonic() - t_start > stop_after_s:
            break
        if config.STOP_FILE.exists():
            log.warning("STOP file present; collection halted (delete %s to resume)", config.STOP_FILE)
            time.sleep(5)
            continue

        now = time.monotonic()
        due = [s for s in states if not s.paused and s.next_due <= now and s.circuit_open_until <= now]
        if not due:
            time.sleep(0.5)
            continue

        st = min(due, key=lambda s: s.next_due)
        st.scheduled_utc = now_utc()
        wait = MIN_GAP_S - (time.monotonic() - last_request)
        if wait > 0:
            time.sleep(wait)
        try:
            ok = acquire(conn, session, st)
        except Exception as e:  # never let one source kill the loop
            log.exception("acquire crashed for %s", st.src["source_id"])
            _alert(conn, st.src["source_id"], "COLLECTOR_ERROR", f"{type(e).__name__}: {e}")
            ok = False
        last_request = time.monotonic()

        sid = st.src["source_id"]
        if ok:
            st.failures, st.alerted_streak = 0, False
            st.next_due = time.monotonic() + st.interval * random.uniform(0.9, 1.1)
        else:
            st.failures += 1
            backoff = min(st.interval * (2 ** min(st.failures, 4)), 600)
            st.next_due = time.monotonic() + backoff * random.uniform(0.9, 1.1)
            if st.failures >= 2 and not st.alerted_streak:
                _alert(conn, sid, "SOURCE_UNAVAILABLE", f"{st.failures} consecutive failed collections")
                st.alerted_streak = True
            if st.failures >= config.CIRCUIT_BREAKER_FAILURES:
                st.circuit_open_until = time.monotonic() + config.CIRCUIT_BREAKER_PAUSE_S
                st.failures = 0
                _alert(conn, sid, "CIRCUIT_OPEN", f"paused {config.CIRCUIT_BREAKER_PAUSE_S}s after repeated failures")
        if once and all(s.next_due > 0 for s in states):
            break

    if stop_evt:
        stop_evt.set()
    log.info("collector stopped")

"""Source endpoint authentication evidence (addendum 002, REQ-EVID-016/018).

The probe is a SEPARATE TCP/TLS connection to the same host, made close in time to the acquisitions it is linked
to. It is not the very connection that carried a given response; the record says so (probe_kind=ADJACENT_PROBE).
"""
import hashlib
import json
import socket
import ssl
import subprocess
import time
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from . import config
from .db import now_utc

_resolvers_cache = {"t": 0.0, "v": []}


def dns_resolvers() -> list[str]:
    """DNS servers the OS is configured to use (the resolver actually consulted is not observable via getaddrinfo)."""
    if time.monotonic() - _resolvers_cache["t"] < 600 and _resolvers_cache["v"]:
        return _resolvers_cache["v"]
    out = []
    try:
        txt = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=15).stdout
        grab = False
        for line in txt.splitlines():
            if "DNS Servers" in line:
                grab = True
                out.append(line.split(":", 1)[1].strip())
            elif grab and line.startswith(" " * 20) and line.strip():
                out.append(line.strip())
            else:
                grab = False
    except Exception:
        pass
    _resolvers_cache.update(t=time.monotonic(), v=sorted(set(out)))
    return _resolvers_cache["v"]


def registrable_domain(host: str) -> str:
    """Heuristic (last two labels). Good enough for .gov/.com style hosts; not a public-suffix lookup."""
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _cert_info(der: bytes) -> dict:
    c = x509.load_der_x509_certificate(der)
    try:
        sans = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []
    return dict(
        sha256=hashlib.sha256(der).hexdigest(), sha1=hashlib.sha1(der).hexdigest(),
        subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(), sans=sans,
        not_before=c.not_valid_before.strftime("%Y-%m-%dT%H:%M:%SZ"), not_after=c.not_valid_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _handshake(ip: str, host: str, port: int, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((ip, port), timeout=10)
    s = ctx.wrap_socket(raw, server_hostname=host)
    return s


def probe(conn, url: str | None = None) -> dict:
    """Take one endpoint observation for the primary host, persist it, and raise anomaly alerts."""
    host = urlparse(url or config.BASE_URL).hostname
    port = 443
    rec = dict(observed_utc=now_utc(), probe_kind="ADJACENT_PROBE", host=host, port=port, collector_host=socket.gethostname(),
               sni=host, revocation_status="NOT_CHECKED", chain_status="NOT_COLLECTED")
    anomalies = []
    rec["dns_query_utc"] = now_utc()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = sorted({i[4][0] for i in infos})
    except Exception as e:
        ips = []
        anomalies.append(f"DNS_FAILURE: {type(e).__name__}: {e}")
    rec["dns_answers_json"] = json.dumps(ips)
    rec["dns_resolvers_json"] = json.dumps(dns_resolvers())
    if ips:
        verify_ok = True
        sock = None
        try:
            sock = _handshake(ips[0], host, port, True)
            rec["validation_result"], rec["validation_detail"] = "VALID", "default trust store, hostname verified"
        except ssl.SSLCertVerificationError as e:
            verify_ok = False
            rec["validation_result"], rec["validation_detail"] = "FAILED", str(e)[:300]
            anomalies.append(f"CERT_VALIDATION_FAILED: {e}")
            try:  # still capture what the server presented; the failure itself stays on the record
                sock = _handshake(ips[0], host, port, False)
            except Exception as e2:
                anomalies.append(f"HANDSHAKE_FAILED: {type(e2).__name__}: {e2}")
        except Exception as e:
            rec["validation_result"], rec["validation_detail"] = "FAILED", f"{type(e).__name__}: {e}"[:300]
            anomalies.append(f"HANDSHAKE_FAILED: {type(e).__name__}: {e}")
        if sock:
            with sock:
                rec["remote_ip"], rec["remote_port"] = sock.getpeername()[:2]
                rec["local_ip"] = sock.getsockname()[0]
                rec["tls_version"] = sock.version()
                rec["cipher"] = json.dumps(sock.cipher())
                der = sock.getpeercert(binary_form=True)
                if der:
                    ci = _cert_info(der)
                    cert_path = config.CERT_DIR / f"{ci['sha256']}.der"
                    if not cert_path.exists():
                        cert_path.write_bytes(der)
                    rec.update(cert_sha256=ci["sha256"], cert_sha1=ci["sha1"], cert_path=cert_path.name, cert_subject=ci["subject"],
                               cert_issuer=ci["issuer"], cert_sans_json=json.dumps(ci["sans"]),
                               cert_not_before=ci["not_before"], cert_not_after=ci["not_after"])
                chain = None
                try:
                    getter = getattr(sock._sslobj, "get_verified_chain", None) or getattr(sock._sslobj, "get_unverified_chain", None)
                    if getter:
                        chain = [c if isinstance(c, bytes) else c.public_bytes(ssl._ssl.ENCODING_DER) for c in getter()]
                except Exception:
                    chain = None
                if chain:
                    entries = []
                    for d in chain:
                        ci = _cert_info(d)
                        p = config.CERT_DIR / f"{ci['sha256']}.der"
                        if not p.exists():
                            p.write_bytes(d)
                        entries.append({"sha256": ci["sha256"], "subject": ci["subject"], "issuer": ci["issuer"]})
                    rec["chain_json"], rec["chain_status"] = json.dumps(entries), "PRESENT"
                else:
                    rec["chain_json"] = json.dumps({"reason": "this Python build does not expose the peer chain; leaf certificate only"})
        if rec.get("tls_version") and rec["tls_version"] < config.MIN_TLS_VERSION:
            anomalies.append(f"TLS_BELOW_POLICY: {rec['tls_version']}")

    # --- anomaly detection against the previous observation of this host (REQ-EVID-018) ---
    prev = conn.execute("SELECT * FROM endpoint_observations WHERE host=? ORDER BY obs_id DESC LIMIT 1", (host,)).fetchone()
    if prev:
        if ips and json.loads(prev["dns_answers_json"] or "[]") and set(ips) != set(json.loads(prev["dns_answers_json"])):
            anomalies.append(f"DNS_ANSWERS_CHANGED: {prev['dns_answers_json']} -> {json.dumps(ips)}")
        if prev["cert_sha256"] and rec.get("cert_sha256") and prev["cert_sha256"] != rec["cert_sha256"]:
            anomalies.append(f"CERTIFICATE_CHANGED: {prev['cert_sha256'][:16]} -> {rec['cert_sha256'][:16]}")
    rec["anomalies_json"] = json.dumps(anomalies)
    cols = list(rec)
    cur = conn.execute(f"INSERT INTO endpoint_observations({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", [rec[c] for c in cols])
    for a in anomalies:
        conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                     (now_utc(), None, "ENDPOINT_ANOMALY", f"{host}: {a}"))
    return {"obs_id": cur.lastrowid, "anomalies": anomalies, "remote_ip": rec.get("remote_ip"), "tls": rec.get("tls_version")}


def latest_id(conn) -> int | None:
    r = conn.execute("SELECT MAX(obs_id) m FROM endpoint_observations").fetchone()
    return r["m"]


def check_response_path(conn, source_id: str, requested_url: str, final_url: str):
    """Redirect-based anomalies, evaluated per acquisition."""
    req, fin = urlparse(requested_url), urlparse(final_url)
    msgs = []
    if req.scheme == "https" and fin.scheme != "https":
        msgs.append(f"HTTP_DOWNGRADE: {requested_url} -> {final_url}")
    if registrable_domain(req.hostname or "") != registrable_domain(fin.hostname or ""):
        msgs.append(f"REDIRECT_NEW_DOMAIN: {req.hostname} -> {fin.hostname}")
    if registrable_domain(fin.hostname or "") in CHALLENGE_DOMAINS:
        msgs.append(f"BOT_CHALLENGE_REDIRECT: {req.hostname} sent us to a bot-protection challenge ({fin.hostname}); "
                    "what was archived is the challenge, not the source's content")
    for m in msgs:
        # A standing redirect is one fact, not an event per poll: alert when this exact anomaly is new for the source.
        if conn.execute("SELECT 1 FROM alerts WHERE source_id=? AND kind='ENDPOINT_ANOMALY' AND detail=? LIMIT 1", (source_id, m)).fetchone():
            continue
        conn.execute("INSERT INTO alerts(created_utc,source_id,kind,detail) VALUES (?,?,?,?)",
                     (now_utc(), source_id, "ENDPOINT_ANOMALY", m))
    return msgs


CHALLENGE_DOMAINS = {"perfdrive.com", "captcha-delivery.com", "datadome.co", "px-cloud.net", "px-cdn.net"}

"""Evidence quality levels (addendum 001 4.13) and self-contained evidence-package export with access profiles
(addendum 001 section 5, addendum 002 REQ-PACK-001..003)."""
import base64
import hashlib
import json
import shutil
from pathlib import Path

from asn1crypto import tsp

from . import VERSION, archive, config, custody, manifest, tsa
from .db import now_utc

LEVEL_NAMES = {"E0": "UNVERIFIED", "E1": "HASHED", "E2": "CHAINED", "E3": "INDEPENDENTLY TIMESTAMPED",
               "E4": "REPLICATED AND REVERIFIED"}
CLAIM = ("Supports only this claim: these exact bytes were acquired and were in the archive no later than the "
         "attested time. It does not show the content was accurate, what other visitors saw, when the source "
         "created it, or why any two sources differ.")
PROFILES = ("public", "research", "internal", "legal", "security")
_RANK = {p: i for i, p in enumerate(PROFILES)}


def evidence_level(conn, acq_id: int) -> dict:
    a = conn.execute("SELECT * FROM acquisitions WHERE acquisition_id=?", (acq_id,)).fetchone()
    notes = []
    if not a or not a["sha256"]:
        return {"level": "E0", "name": LEVEL_NAMES["E0"], "notes": ["no artifact was preserved for this acquisition"], "claim": CLAIM}
    if not archive.verify(a["sha256"]):
        return {"level": "E0", "name": LEVEL_NAMES["E0"], "notes": ["stored artifact does not match its digest"], "claim": CLAIM}
    if a["post_write_verified"] != 1:
        notes.append("post-write verification was not recorded at acquisition time (digest re-verified now)")
    level = "E1"
    m = conn.execute("SELECT * FROM manifests WHERE seq IS NOT NULL AND first_acquisition_id<=? AND last_acquisition_id>=?",
                     (acq_id, acq_id)).fetchone()
    anchors = []
    if m:
        level = "E2"
        anchors = tsa.verified_anchors(conn, m["manifest_id"])
        if anchors:
            level = "E3"
        else:
            notes.append("awaiting a verified RFC 3161 trusted timestamp for its manifest")
    else:
        notes.append("not yet included in a signed manifest")
    if level == "E3":
        refs = [("artifact", a["sha256"]), ("manifest", m["path"]), ("timestamp", anchors[0]["response_path"])]
        ok = all(conn.execute("SELECT 1 FROM replication_events WHERE object_kind=? AND object_ref=? AND reverified=1 "
                              "AND separate_boundary_declared=1", r).fetchone() for r in refs)
        if ok:
            level = "E4"
        elif config.REPLICA_DIR and not config.REPLICA_IS_SEPARATE_BOUNDARY:
            notes.append("replica exists but is not declared a separate administrative boundary, so E4 is not claimed")
        else:
            notes.append("no cross-boundary replica configured")
        if len(anchors) < 2:
            notes.append("only one independent trusted-timestamp anchor so far (two required for dual anchoring)")
    if a["time_confidence"] and a["time_confidence"] != "TIME_CONFIDENCE_OK":
        notes.append(a["time_confidence"])
    return {
        "level": level, "name": LEVEL_NAMES[level], "manifest_seq": m["seq"] if m else None,
        "anchor_count": len(anchors), "dual_anchored": len(anchors) >= 2,
        "trusted_timestamp": ({"gen_time_utc": anchors[0]["gen_time_utc"], "tsa_url": anchors[0]["tsa_url"],
                               "policy_oid": anchors[0]["policy_oid"], "serial_number": anchors[0]["serial_number"]} if anchors else None),
        "anchors": [{"tsa_url": r["tsa_url"], "gen_time_utc": r["gen_time_utc"]} for r in anchors],
        "time_confidence": a["time_confidence"], "notes": notes, "claim": CLAIM,
    }


def evidence_summary(conn) -> dict:
    total = conn.execute("SELECT COUNT(*) c FROM acquisitions WHERE sha256 IS NOT NULL").fetchone()["c"]
    in_manifest = conn.execute("SELECT COUNT(*) c FROM acquisitions a WHERE sha256 IS NOT NULL AND EXISTS "
                               "(SELECT 1 FROM manifests m WHERE m.seq IS NOT NULL AND a.acquisition_id BETWEEN m.first_acquisition_id AND m.last_acquisition_id)").fetchone()["c"]
    stamped = conn.execute("SELECT COUNT(*) c FROM acquisitions a WHERE sha256 IS NOT NULL AND EXISTS "
                           "(SELECT 1 FROM manifests m JOIN timestamp_attempts t ON t.manifest_id=m.manifest_id AND t.outcome='OK' AND t.verify_result='VERIFIED' "
                           "WHERE a.acquisition_id BETWEEN m.first_acquisition_id AND m.last_acquisition_id)").fetchone()["c"]
    dual = conn.execute(
        "SELECT COUNT(*) c FROM acquisitions a WHERE sha256 IS NOT NULL AND EXISTS (SELECT 1 FROM manifests m WHERE a.acquisition_id BETWEEN "
        "m.first_acquisition_id AND m.last_acquisition_id AND (SELECT COUNT(DISTINCT tsa_url) FROM timestamp_attempts t WHERE t.manifest_id=m.manifest_id "
        "AND t.outcome='OK' AND t.verify_result='VERIFIED')>=2)").fetchone()["c"]
    return {"artifacts": total, "at_least_E2": in_manifest, "at_least_E3": stamped, "dual_anchored": dual,
            "pending_timestamp": in_manifest - stamped, "unmanifested": total - in_manifest}


_chain_cache = {"t": 0.0, "v": None}


def _chain_ok(conn) -> dict:
    import time
    if _chain_cache["v"] is None or time.monotonic() - _chain_cache["t"] > 60:
        _chain_cache.update(t=time.monotonic(), v=custody.verify_chain(conn))
    return _chain_cache["v"]


def evidence_predicates(conn, acq_id: int) -> dict:
    """Addendum 003 REQ-STATE-001..003: explicit, individually inspectable conditions. No composite or numeric trust score."""
    a = conn.execute("SELECT * FROM acquisitions WHERE acquisition_id=?", (acq_id,)).fetchone()
    P = {}

    def p(name, value, basis, ref=None):
        P[name] = {"value": value, "basis": basis, **({"reference": ref} if ref else {})}

    src = config.SOURCES_BY_ID.get(a["source_id"], {})
    sar = conn.execute("SELECT * FROM source_authority_records WHERE authority_key=? ORDER BY sar_id DESC LIMIT 1", (src.get("authority_record_key", ""),)).fetchone()
    p("SOURCE_AUTHORITY_VERIFIED", bool(sar and sar["approval_status"] == "APPROVED"),
      f"authority record {'v%d status %s' % (sar['version'], sar['approval_status']) if sar else 'absent'}; an independent human review has not occurred"
      if not (sar and sar["approval_status"] == "APPROVED") else "approved authority record", {"sar_id": sar["sar_id"]} if sar else None)
    ep = conn.execute("SELECT * FROM endpoint_observations WHERE obs_id=?", (a["endpoint_obs_id"],)).fetchone() if a["endpoint_obs_id"] else None
    ep_ok = bool(ep and ep["validation_result"] == "VALID" and not json.loads(ep["anomalies_json"] or "[]"))
    p("ENDPOINT_VERIFIED", ep_ok, ("TLS certificate validated and no endpoint anomaly on the adjacent observation" if ep_ok else
                                   "no clean endpoint observation linked to this acquisition"), {"endpoint_obs_id": a["endpoint_obs_id"]} if ep else None)
    p("TRANSACTION_CAPTURED", a["http_status"] is not None and a["error_class"] is None,
      f"HTTP {a['http_status']}, failure_status={a['error_class']}")
    hash_ok = bool(a["sha256"]) and archive.verify(a["sha256"])
    p("ARTIFACT_HASH_VERIFIED", hash_ok and a["post_write_verified"] in (1, None),
      "stored bytes re-hashed now" + ("; post-write verification recorded at acquisition" if a["post_write_verified"] == 1 else "; no post-write record (pre-upgrade acquisition)"))
    m = conn.execute("SELECT * FROM manifests WHERE seq IS NOT NULL AND first_acquisition_id<=? AND last_acquisition_id>=?", (acq_id, acq_id)).fetchone()
    sig_ok = False
    if m:
        try:
            vr = manifest.verify_manifest(config.MANIFEST_DIR / m["path"], check_artifacts=False)
            sig_ok = vr["signature_valid"] and vr["merkle_ok"]
        except Exception:
            sig_ok = False
    p("BUNDLE_SIGNATURE_VERIFIED", sig_ok, f"manifest seq {m['seq']} signature and Merkle root recomputed now" if m else "not yet in a signed manifest",
      {"manifest_seq": m["seq"]} if m else None)
    anchors = tsa.verified_anchors(conn, m["manifest_id"]) if m else []
    p("TRUSTED_TIMESTAMP_VERIFIED", len(anchors) >= 1, f"{len(anchors)} verified RFC 3161 token(s)", [x["gen_time_utc"] for x in anchors] or None)
    p("SECOND_ANCHOR_VERIFIED", len(anchors) >= 2, "two independent TSAs verified" if len(anchors) >= 2 else "fewer than two independent anchors verified")
    p("IMMUTABLE_STORAGE_VERIFIED", False, "read-only file attribute and append-only database triggers only; no WORM/object-lock storage")
    repl = bool(a["sha256"]) and bool(conn.execute("SELECT 1 FROM replication_events WHERE object_kind='artifact' AND object_ref=? AND reverified=1 AND separate_boundary_declared=1",
                                                   (a["sha256"],)).fetchone())
    p("REPLICA_VERIFIED", repl, "re-verified replica in a declared separate administrative boundary" if repl else "no replica in a separate administrative boundary")
    cfg = conn.execute("SELECT * FROM source_config_versions WHERE cfg_id=?", (a["source_config_version_id"],)).fetchone() if a["source_config_version_id"] else None
    p("CONFIGURATION_VERIFIED", bool(cfg and cfg["approval_status"] == "APPROVED"),
      f"source configuration v{cfg['version']} approval_status={cfg['approval_status']}" if cfg else "no configuration version linked")
    rel = conn.execute("SELECT * FROM releases WHERE release_id=?", (a["release_id"],)).fetchone() if a["release_id"] else None
    p("COLLECTOR_RELEASE_VERIFIED", bool(rel and rel["signed"]), "release is UNSIGNED: no signed tag, build provenance or OCI image" if rel else "no release linked")
    p("PARSER_RELEASE_VERIFIED", bool(rel and rel["signed"]), "parser ships in the same unsigned release" if rel else "no release linked")
    p("CROSSWALK_VERIFIED", False, "candidate/contest identity uses source IDs; no human-reviewed crosswalk exists")
    p("CONSISTENCY_VERIFIED", "NOT_APPLICABLE", "single-resource HTTP transaction; no multi-component bundle")
    p("CLOCK_WITHIN_POLICY", a["time_confidence"] == "TIME_CONFIDENCE_OK", a["time_confidence"] or "unknown")
    led = _chain_ok(conn)
    p("CUSTODY_CHAIN_VERIFIED", led["ok"], f"hash chain over {led.get('checked')} custody events")
    return {"acquisition_id": acq_id, "predicates": P,
            "note": "Each predicate stands alone. A false predicate means a control is incomplete, not that the content is false (REQ-STATE-004)."}


def structured_times(conn, a) -> dict:
    """REQ-TIME-001..004: material timestamps as structured objects; precision and accuracy are separate fields."""
    try:
        import tzdata
        tzdb = getattr(tzdata, "IANA_VERSION", "unknown")
    except Exception:
        tzdb = "unknown"
    clk = conn.execute("SELECT * FROM clock_status WHERE clock_id=?", (a["clock_id"],)).fetchone() if a["clock_id"] else None
    conf_map = {"TIME_CONFIDENCE_OK": "synchronized_within_policy", "TIME_CONFIDENCE_DEGRADED": "degraded", "TIME_CONFIDENCE_UNKNOWN": "unknown"}
    acc = None
    if clk and clk["offset_ms"] is not None:
        acc = round(abs(clk["offset_ms"]) + (clk["uncertainty_ms"] or 0), 1)
    common_leap = "system clock/NTP semantics; leap seconds smeared or stepped by the OS, not independently handled"
    out = {
        "response_completed": {
            "value": a["response_completed_utc"], "utc_offset": "+00:00", "iana_time_zone": None, "original_source_string": None,
            "time_authority": "COLLECTOR_SYSTEM_CLOCK", "technical_precision": "1 ms (format)",
            "estimated_accuracy_ms": acc, "accuracy_basis": ("abs(SNTP offset)+uncertainty from the nearest clock sample, measured separately from this event"
                                                              if acc is not None else "no clock sample available"),
            "synchronization_state": clk["state"] if clk else "UNKNOWN", "confidence_state": conf_map.get(a["time_confidence"], "unknown"),
            "leap_second_policy": common_leap, "tz_database_version": None, "derivation_method": "directly observed on the collector host"},
    }
    hd = json.loads(a["response_headers"] or "{}")
    date_hdr = next((v for k, v in hd.items() if k.lower() == "date"), None)
    if date_hdr:
        out["http_date_header"] = {"value": None, "utc_offset": "+00:00", "original_source_string": date_hdr, "time_authority": "HTTP_DATE_HEADER",
                                   "technical_precision": "1 s", "estimated_accuracy_ms": None, "accuracy_basis": "server clock; not assessed",
                                   "synchronization_state": "UNKNOWN", "confidence_state": "source_supplied_unverified",
                                   "leap_second_policy": "n/a", "tz_database_version": None, "derivation_method": "source-supplied header, unverified"}
    stamp = conn.execute("SELECT displayed_text, displayed_iso_utc FROM page_stamps WHERE acquisition_id=?", (a["acquisition_id"],)).fetchone()
    if stamp:
        out["source_displayed_update"] = {"value": stamp["displayed_iso_utc"], "utc_offset": "-07:00 or -06:00 (America/Denver; applies by date)",
                                          "iana_time_zone": "America/Denver (ASSUMED from the 'MT' suffix)", "original_source_string": stamp["displayed_text"],
                                          "time_authority": "SOURCE_DISPLAYED", "technical_precision": "1 minute (as displayed)",
                                          "estimated_accuracy_ms": None, "accuracy_basis": "unknown; source clock not assessed",
                                          "synchronization_state": "UNKNOWN", "confidence_state": "ambiguous",
                                          "leap_second_policy": "n/a", "tz_database_version": tzdb,
                                          "derivation_method": "DERIVED: local text converted to UTC assuming America/Denver"}
    m = conn.execute("SELECT * FROM manifests WHERE seq IS NOT NULL AND first_acquisition_id<=? AND last_acquisition_id>=?", (a["acquisition_id"], a["acquisition_id"])).fetchone()
    anchors = tsa.verified_anchors(conn, m["manifest_id"]) if m else []
    for i, t in enumerate(anchors):
        out[f"trusted_timestamp_{i + 1}"] = {"value": t["gen_time_utc"], "utc_offset": "+00:00", "original_source_string": "RFC 3161 TSTInfo.genTime",
                                             "time_authority": "RFC3161_TSA", "technical_precision": "1 s", "estimated_accuracy_ms": None,
                                             "accuracy_basis": "TSA policy-defined; not asserted here (see policy OID)", "tsa": t["tsa_url"], "policy_oid": t["policy_oid"],
                                             "synchronization_state": "attested by TSA", "confidence_state": "independently_attested",
                                             "leap_second_policy": "per TSA policy", "tz_database_version": None,
                                             "derivation_method": "directly attested; covers the manifest, not the acquisition instant"}
    return out


def _jdump(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=1, default=str))


def _source_revision() -> str:
    src = Path(__file__).resolve().parent
    parts = [f"{p.name} sha256 {hashlib.sha256(p.read_bytes()).hexdigest()}" for p in sorted(src.glob("*.py"))]
    return "\n".join(parts) + f"\nobservatory version {VERSION}\n(no VCS revision or signed release exists yet; file digests identify the exact source)\n"


def _pem(der: bytes) -> str:
    b = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"


def export_package(conn, acq_id: int, out_root: Path | None = None, profile: str = "public", requester: str = "local operator") -> Path:
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")
    rank = _RANK[profile]
    at_least = lambda p: rank >= _RANK[p]  # noqa: E731
    a = conn.execute("SELECT * FROM acquisitions WHERE acquisition_id=?", (acq_id,)).fetchone()
    if not a or not a["sha256"]:
        raise ValueError("no preserved artifact for that acquisition")
    out_root = out_root or config.EXPORT_DIR
    root = out_root / f"EIO-EVIDENCE-{config.ELECTION_ID}-NM-{acq_id}-{profile.upper()}"
    if root.exists():
        shutil.rmtree(root)
    lvl = evidence_level(conn, acq_id)
    withheld = []   # (path-or-field, reason category) -> redaction manifest
    components = []  # bundle manifest

    def comp(name, path, status, sensitivity, note=None):
        d = {"component": name, "path": path, "status": status, "sensitivity": sensitivity}
        if status == "PRESENT" and path and (root / path).is_file():
            data = (root / path).read_bytes()
            d.update(digest_algorithm="sha256", digest=hashlib.sha256(data).hexdigest(), bytes=len(data))
        if note:
            d["note"] = note
        components.append(d)

    # ORIGINAL (the evidentiary bytes)
    (root / "ORIGINAL").mkdir(parents=True)
    shutil.copyfile(archive.artifact_path(a["sha256"]), root / "ORIGINAL" / "response.bin")
    comp("response_body", "ORIGINAL/response.bin", "PRESENT", "public")

    # ACQUISITION
    acq = dict(a)
    for k in ("redirect_chain", "response_headers"):
        acq[k] = json.loads(acq[k] or "null")
    acq["times"] = {k: a[k] for k in ("scheduler_created_utc", "request_started_utc", "request_sent_utc", "first_byte_received_utc",
                                      "response_completed_utc", "artifact_write_started_utc", "artifact_write_completed_utc",
                                      "hash_calculated_utc")}
    stamp = conn.execute("SELECT displayed_text, displayed_iso_utc FROM page_stamps WHERE acquisition_id=?", (acq_id,)).fetchone()
    acq["times"]["source_reported_timestamp_raw"] = stamp["displayed_text"] if stamp else None
    acq["times"]["source_reported_timestamp_utc_interpreted"] = stamp["displayed_iso_utc"] if stamp else None
    acq["times"]["source_reported_timezone_assumed"] = "America/Denver" if stamp else None
    acq["distinct_times_note"] = ("source-reported, request, response-receipt, archive-write, hash, manifest and trusted-timestamp "
                                  "times are separate facts")
    m = conn.execute("SELECT * FROM manifests WHERE seq IS NOT NULL AND first_acquisition_id<=? AND last_acquisition_id>=?", (acq_id, acq_id)).fetchone()
    anchors = tsa.verified_anchors(conn, m["manifest_id"]) if m else []
    if m:
        acq["times"]["manifest_created_utc"] = m["created_utc"]
    acq["times"]["trusted_timestamp_utc"] = anchors[0]["gen_time_utc"] if anchors else None
    acq["evidence_level"] = lvl
    acq["structured_times"] = structured_times(conn, a)
    acq["byte_layers"] = {
        "evidentiary_original": a["byte_layer"] or "HTTP_ENTITY_PAYLOAD",
        "wire_or_transport_bytes_preserved": False,
        "note": "the HTTP library exposes the transfer-decoded entity; raw TLS/wire bytes are not available and are not claimed",
        "content_encoding": a["content_encoding"], "transfer_encoding": a["transfer_encoding"],
        "decoded_content_sha256": a["decoded_sha256"], "decoded_length": a["decoded_length"], "decode_detail": a["decode_detail"],
        "undeclared_normalization_applied_to_original": False}
    acq["observation"] = {"observation_status": a["observation_status"], "failure_status": a["error_class"], "attempt_number": a["attempt_number"],
                          "schedule_id": a["schedule_id"], "retry_of_acquisition_id": a["retry_of_acquisition_id"], "stage_reached": a["stage_reached"],
                          "source_version_id": a["source_version_id"]}
    # sensitive / non-public fields
    for field in ("restricted_path",):
        acq.pop(field, None)
    acq["set_cookie_present"] = bool(a["set_cookie_present"])
    if not at_least("internal"):
        for f in ("collector_name", "collector_version", "release_id", "source_config_version_id", "endpoint_obs_id", "clock_id"):
            acq.pop(f, None)
        withheld.append({"item": "acquisition.json: collector/release/config/endpoint/clock internal identifiers", "reason": "INTERNAL_OPERATIONAL_METADATA"})
    _jdump(root / "ACQUISITION/acquisition.json", acq)
    comp("acquisition_record", "ACQUISITION/acquisition.json", "PRESENT", "public")
    _jdump(root / "ACQUISITION/request.json", {
        "method": a["http_method"], "url": a["requested_url"], "final_url": a["final_url"], "source_id": a["source_id"],
        "request_headers_sent": {"Accept-Encoding": "identity", "User-Agent": config.USER_AGENT},
        "request_body": None, "redirect_chain": acq["redirect_chain"]})
    comp("request_metadata", "ACQUISITION/request.json", "PRESENT", "public")
    comp("request_body", None, "NOT_APPLICABLE", "public", "GET request, no body")
    _jdump(root / "ACQUISITION/response_headers.json", acq["response_headers"])
    comp("response_headers", "ACQUISITION/response_headers.json", "PRESENT", "public",
         "Set-Cookie omitted; see restricted tier" if a["set_cookie_present"] else None)
    clocks = [dict(r) for r in conn.execute(
        "SELECT * FROM clock_status WHERE clock_id=? OR clock_id IN (SELECT clock_id FROM clock_status WHERE sampled_utc>? ORDER BY clock_id LIMIT 1)",
        (a["clock_id"], a["response_received_utc"]))]
    _jdump(root / "ACQUISITION/clock_status.json", {"time_confidence": a["time_confidence"], "samples_bracketing_acquisition": clocks})
    comp("clock_status", "ACQUISITION/clock_status.json", "PRESENT", "public")
    comp("browser_acquisition", None, "NOT_COLLECTED", "public",
         "no browser/render capture exists in this build; the transport-layer response above is the evidence (addendum 002 REQ-EVID-022 not yet implemented)")

    # SOURCE_IDENTITY
    (root / "SOURCE_IDENTITY").mkdir()
    _jdump(root / "SOURCE_IDENTITY/source_registry_record.json", config.SOURCES_BY_ID.get(a["source_id"]))
    comp("source_registry_record", "SOURCE_IDENTITY/source_registry_record.json", "PRESENT", "public")
    cfg = conn.execute("SELECT * FROM source_config_versions WHERE cfg_id=?", (a["source_config_version_id"],)).fetchone()
    if cfg and at_least("internal"):
        _jdump(root / "SOURCE_IDENTITY/source_configuration.json", dict(cfg))
        comp("source_configuration", "SOURCE_IDENTITY/source_configuration.json", "PRESENT", "internal",
             f"approval_status={cfg['approval_status']}")
    else:
        comp("source_configuration", None, "WITHHELD" if cfg else "NOT_COLLECTED", "internal")
        if cfg:
            withheld.append({"item": "SOURCE_IDENTITY/source_configuration.json", "reason": "INTERNAL_OPERATIONAL_METADATA"})
    ep = conn.execute("SELECT * FROM endpoint_observations WHERE obs_id=?", (a["endpoint_obs_id"],)).fetchone()
    if ep:
        e = dict(ep)
        net_ids = ["dns_answers_json", "dns_resolvers_json", "remote_ip", "remote_port", "local_ip", "collector_host", "dns_query_utc"]
        if not at_least("security"):
            for f in net_ids:
                e.pop(f, None)
            withheld.append({"item": "SOURCE_IDENTITY/endpoint_observation.json: DNS answers, resolver, remote/local IP, collector host",
                             "reason": "NETWORK_IDENTIFIERS_SECURITY_TIER"})
        e["note"] = "separate TLS connection to the same host made close in time; not necessarily the connection that carried this response"
        _jdump(root / "SOURCE_IDENTITY/endpoint_observation.json", e)
        comp("endpoint_observation", "SOURCE_IDENTITY/endpoint_observation.json", "PRESENT", "public" if not at_least("security") else "security")
        for f in sorted({ep["cert_sha256"]} | {c["sha256"] for c in json.loads(ep["chain_json"] or "[]") if isinstance(c, dict) and "sha256" in c}):
            if f and (config.CERT_DIR / f"{f}.der").exists():
                shutil.copyfile(config.CERT_DIR / f"{f}.der", root / "SOURCE_IDENTITY" / f"cert_{f[:16]}.der")
        comp("server_certificate_der", f"SOURCE_IDENTITY/cert_{ep['cert_sha256'][:16]}.der" if ep["cert_sha256"] else None,
             "PRESENT" if ep["cert_sha256"] else "NOT_COLLECTED", "public")
    else:
        comp("endpoint_observation", None, "NOT_COLLECTED", "public", "acquired before endpoint authentication capture was enabled")

    # restricted tier
    if a["set_cookie_present"]:
        _jdump(root / "SOURCE_IDENTITY/restricted_record.json", {
            "present": True, "category": "Set-Cookie (session identifiers)", "commitment_sha256": a["restricted_commitment"],
            "note": "value is held encrypted; the commitment is a salted SHA-256 that proves what was withheld without revealing it"})
        comp("restricted_headers", "SOURCE_IDENTITY/restricted_record.json", "RESTRICTED", "restricted")
        if at_least("security") and a["restricted_path"]:
            shutil.copyfile(config.RESTRICTED_DIR / a["restricted_path"], root / "SOURCE_IDENTITY/request_headers_restricted.enc")
            comp("restricted_headers_encrypted", "SOURCE_IDENTITY/request_headers_restricted.enc", "RESTRICTED", "restricted",
                 "encrypted; key held separately by the evidence administrator")
        else:
            withheld.append({"item": "encrypted restricted header record", "reason": "SESSION_TOKENS_SENSITIVE_HEADERS"})

    # INTEGRITY
    (root / "INTEGRITY").mkdir()
    (root / "INTEGRITY/response.sha256").write_text(f"{a['sha256']}  response.bin\n")
    digs = [dict(r) for r in conn.execute("SELECT algorithm,oid,value,calculated_utc,implementation,input_length,verification_status "
                                           "FROM artifact_digests WHERE artifact_sha256=?", (a["sha256"],))]
    _jdump(root / "INTEGRITY/digests.json", digs or [{"algorithm": "sha256", "value": a["sha256"], "note": "only the primary digest was recorded"}])
    comp("digests", "INTEGRITY/digests.json", "PRESENT", "public")
    _jdump(root / "INTEGRITY/evidence_predicates.json", evidence_predicates(conn, acq_id))
    comp("evidence_predicates", "INTEGRITY/evidence_predicates.json", "PRESENT", "public")
    if m:
        mfile = config.MANIFEST_DIR / m["path"]
        shutil.copyfile(mfile, root / "INTEGRITY/manifest.json")
        doc = json.loads(mfile.read_bytes())
        (root / "INTEGRITY/manifest.sig").write_text(doc["signature_ed25519_b64"] + "\n")
        shutil.copyfile(config.KEY_DIR / manifest.PUB, root / "INTEGRITY/manifest_public_key.pem")
        entries = doc["body"]["entries"]
        leaves = [manifest.leaf_string(*e) for e in entries]
        idx = next(i for i, e in enumerate(entries) if e[0] == acq_id)
        profile = doc["body"].get("merkle_profile", "EIO-MERKLE-0")
        pr = manifest.merkle_proof(leaves, idx) if profile == manifest.MERKLE_PROFILE else manifest.legacy_merkle_proof(leaves, idx)
        _jdump(root / "INTEGRITY/merkle_proof.json", {
            "leaf": leaves[idx], "index": idx, "leaf_count": len(leaves), "root": doc["body"]["merkle_root"],
            "leaf_format": doc["body"]["merkle_leaf_format"], **pr})
        comp("bundle_manifest_signed", "INTEGRITY/manifest.json", "PRESENT", "public")
        comp("merkle_proof", "INTEGRITY/merkle_proof.json", "PRESENT", "public")
    else:
        comp("bundle_manifest_signed", None, "NOT_COLLECTED", "public", "not yet included in a signed manifest")
    if anchors:
        first = anchors[0]
        shutil.copyfile(config.TIMESTAMP_DIR / first["request_path"], root / "INTEGRITY/timestamp_request.tsq")
        shutil.copyfile(config.TIMESTAMP_DIR / first["response_path"], root / "INTEGRITY/timestamp_response.tsr")
        infos = []
        for i, t in enumerate(anchors):
            infos.append({k: t[k] for k in ("tsa_url", "gen_time_utc", "serial_number", "policy_oid", "hash_algorithm", "nonce",
                                            "tsa_name", "verify_result", "verifier", "response_sha256", "attempted_utc")}
                         | {"imprint_covers": "INTEGRITY/manifest.json (file bytes)", "file": "timestamp_response.tsr" if i == 0 else f"additional_anchors/anchor_{i}.tsr"})
            if i > 0:
                (root / "INTEGRITY/additional_anchors").mkdir(exist_ok=True)
                shutil.copyfile(config.TIMESTAMP_DIR / t["response_path"], root / f"INTEGRITY/additional_anchors/anchor_{i}.tsr")
                shutil.copyfile(config.TIMESTAMP_DIR / t["request_path"], root / f"INTEGRITY/additional_anchors/anchor_{i}.tsq")
        _jdump(root / "INTEGRITY/timestamp_info.json", infos)
        chain_dir = root / "INTEGRITY/certificate_chain"
        chain_dir.mkdir()
        resp = tsp.TimeStampResp.load((config.TIMESTAMP_DIR / first["response_path"]).read_bytes())
        for i, c in enumerate(resp["time_stamp_token"]["content"]["certificates"] or []):
            (chain_dir / f"cert_{i}.pem").write_text(_pem(c.chosen.dump()))
        comp("rfc3161_timestamp", "INTEGRITY/timestamp_response.tsr", "PRESENT", "public", f"{len(anchors)} independent anchor(s)")
    else:
        (root / "INTEGRITY/NO_TIMESTAMP.txt").write_text(
            "No verified RFC 3161 trusted timestamp existed for this artifact when the package was exported.\n"
            "Evidence quality is below E3 (see ACQUISITION/acquisition.json).\n")
        comp("rfc3161_timestamp", None, "NOT_COLLECTED", "public", "no verified token yet")
    comp("evidence_record_ers", None, "NOT_COLLECTED", "public", "RFC 4998 long-term evidence record not implemented (addendum 002 REQ-CRYPTO-003)")

    # PROCESSING (research and above) / CUSTODY (internal and above)
    if at_least("research"):
        (root / "PROCESSING").mkdir()
        runs = [dict(r) for r in conn.execute("SELECT * FROM parse_runs WHERE acquisition_id=?", (acq_id,))]
        _jdump(root / "PROCESSING/parsed_observation.json", [dict(r) for r in conn.execute("SELECT * FROM vote_obs WHERE acquisition_id=?", (acq_id,))])
        _jdump(root / "PROCESSING/normalization.json", {
            "canonical_contest_id_rule": f"{config.ELECTION_ID}:<source RaceID>",
            "percentages": "derived by the application from votes; the source's own text is retained as source_pct_text",
            "precincts": "source's 'n/m' label retained verbatim; not a share of ballots counted",
            "status": "all values UNOFFICIAL until canvass/certification"})
        comp("parsed_observation", "PROCESSING/parsed_observation.json", "PRESENT", "research")
        comp("normalization", "PROCESSING/normalization.json", "PRESENT", "research")
        _jdump(root / "PROCESSING/validation_findings.json", [dict(r) for r in conn.execute("SELECT * FROM validation_findings WHERE acquisition_id=?", (acq_id,))])
        if at_least("internal"):
            _jdump(root / "PROCESSING/parser_version.json", {"parse_runs": runs, "parser_registry": {
                k: config.SOURCES_BY_ID[a["source_id"]][k] for k in ("parser_name", "parser_version")}})
            (root / "PROCESSING/parser_source_revision.txt").write_text(_source_revision())
            rel = conn.execute("SELECT * FROM releases WHERE release_id=?", (a["release_id"],)).fetchone()
            if rel:
                _jdump(root / "PROCESSING/collection_release.json", {k: rel[k] for k in rel.keys() if k != "lock_text"} | {
                    "signed": False, "note": "no signed tag, OCI image or build provenance exists yet"})
                comp("collection_release", "PROCESSING/collection_release.json", "PRESENT", "internal")
        else:
            withheld.append({"item": "PROCESSING/parser_version.json, parser_source_revision.txt, collection_release.json", "reason": "INTERNAL_OPERATIONAL_METADATA"})
    else:
        withheld.append({"item": "PROCESSING/ (normalized records and lineage)", "reason": "RESEARCH_OR_HIGHER_PROFILE_ONLY"})
    if at_least("internal"):
        (root / "CUSTODY").mkdir()
        ledger = custody.verify_chain(conn)
        _jdump(root / "CUSTODY/chain_of_custody.json", {
            "acquisition_events": custody.for_evidence(conn, "acquisition", acq_id),
            "manifest_events": custody.for_evidence(conn, "manifest", m["manifest_id"]) if m else [],
            "ledger_verification": ledger})
        _jdump(root / "CUSTODY/replication_events.json", [dict(r) for r in conn.execute(
            "SELECT * FROM replication_events WHERE object_ref IN (?,?)", (a["sha256"], m["path"] if m else ""))])
        _jdump(root / "CUSTODY/verification_events.json", [e for e in custody.for_evidence(conn, "acquisition", acq_id)
                                                            if e["event_type"] in ("HASH_VERIFIED", "REVERIFIED")])
        comp("custody", "CUSTODY/chain_of_custody.json", "PRESENT", "internal")
    else:
        withheld.append({"item": "CUSTODY/ (chain of custody, replication and verification events)", "reason": "INTERNAL_OR_HIGHER_PROFILE_ONLY"})
        comp("custody", None, "WITHHELD", "internal")
    if at_least("legal"):
        anomalies = [dict(r) for r in conn.execute(
            "SELECT * FROM alerts WHERE created_utc BETWEEN ? AND ? ORDER BY alert_id",
            (a["request_started_utc"][:16] + ":00.000Z", a["response_received_utc"][:16] + ":59.999Z"))]
        _jdump(root / "CUSTODY/known_anomalies_near_acquisition.json", anomalies)
        _jdump(root / "CUSTODY/legal_hold_status.json", {
            "active_legal_holds": [], "note": "legal-hold workflow is NOT implemented in this build; absence of a record here is not a statement that no hold applies"})
        comp("legal_hold_status", "CUSTODY/legal_hold_status.json", "PRESENT", "legal")
    else:
        withheld.append({"item": "CUSTODY/legal_hold_status.json, known_anomalies_near_acquisition.json", "reason": "LEGAL_PROFILE_ONLY"})

    # README / VERIFY / verifier
    shutil.copyfile(Path(__file__).with_name("verify_package.py"), root / "verify_package.py")
    (root / "README.txt").write_text(
        f"Election Information Observatory - evidence package ({profile.upper()} profile)\n"
        f"Election: {config.ELECTION_LABEL}\nAcquisition: {acq_id}  Source: {a['source_id']}\nURL: {a['requested_url']}\n"
        f"Evidence level at export: {lvl['level']} ({lvl['name']}); independent anchors: {lvl.get('anchor_count', 0)}\nExported (UTC): {now_utc()}\n\n"
        f"WHAT THIS IS\nORIGINAL/response.bin is the response body exactly as delivered by the source (identity encoding requested).\n"
        f"Times in ACQUISITION/ are kept separate on purpose: the source's displayed time, our request/response times,\n"
        f"archive-write and hash times, and the independent trusted-timestamp time are different facts.\n\n"
        f"WHAT THIS DOES NOT PROVE\n{CLAIM}\n\n"
        f"Election-night values are UNOFFICIAL until canvass and certification.\n"
        f"EXPORT/redaction_manifest.json lists what this profile withholds and why. INTEGRITY/bundle_manifest.json states the\n"
        f"status of every evidence component (PRESENT / NOT_APPLICABLE / NOT_COLLECTED / RESTRICTED / WITHHELD).\n")
    (root / "VERIFY.txt").write_text(
        "Independent verification (no network, no production access needed):\n\n"
        "    python verify_package.py .            (run from inside this folder)\n\n"
        "Optional: `pip install cryptography` enables signature checks; OpenSSL on PATH (or --openssl) enables the\n"
        "RFC 3161 timestamp checks; --cafile supplies trusted root certificates if no default bundle is found.\n"
        "Manual alternative for the digest:  sha256sum ORIGINAL/response.bin   (compare with INTEGRITY/response.sha256)\n"
        "Manual timestamp check:  openssl ts -verify -data INTEGRITY/manifest.json -in INTEGRITY/timestamp_response.tsr -CAfile roots.pem\n")

    # bundle manifest (component statuses + digests) and redaction manifest
    _jdump(root / "INTEGRITY/bundle_manifest.json", {"bundle_id": f"acq-{acq_id}", "acquisition_id": acq_id, "artifact_id": a["sha256"],
                                                      "profile": profile, "components": components, "created_utc": now_utc()})
    (root / "EXPORT").mkdir()
    _jdump(root / "EXPORT/redaction_manifest.json", {"profile": profile, "withheld": withheld,
                                                      "note": "reasons are categories only; withheld values are not disclosed here"})

    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name not in ("export_manifest.json", "export_manifest.sig"):
            files[p.relative_to(root).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    em = {"exported_utc": now_utc(), "exporter": f"observatory {VERSION}", "acquisition_id": acq_id, "profile": profile,
          "evidence_level": lvl["level"], "requester": requester, "files": files}
    _jdump(root / "EXPORT/export_manifest.json", em)
    key = manifest._load_or_create_key()
    (root / "EXPORT/export_manifest.sig").write_text(base64.b64encode(key.sign(manifest._canon(em))).decode() + "\n")
    pkg_digest = hashlib.sha256((root / "EXPORT/export_manifest.json").read_bytes()).hexdigest()
    custody.append(conn, evidence_kind="acquisition", evidence_id=acq_id, event_type="EXPORTED", artifact_sha256=a["sha256"],
                   actor=f"observatory-export for {requester}",
                   reason=f"profile={profile}; scope=acquisition {acq_id}; delivery=local filesystem {root}; export_manifest sha256 {pkg_digest}; approver=none required/recorded",
                   new_state=f"exported at {lvl['level']}")
    return root

# Requirements status — master spec + Addenda 001, 002, 003

Status as of 2026-11-03 (election day, ~12:15 MT). **DONE** = implemented and exercised by a test or a live run.
**PARTIAL** = a working subset; the gap is stated. **NOT DONE** = not started; most need people, decisions or infrastructure,
not code. This is a self-assessment by the system's author; nobody independent has reviewed it.

## What the system can honestly claim tonight

Particular bytes were acquired from `electionresults.sos.nm.gov` (and the Secretary of State's own site) at a recorded time,
preserved unmodified, chained into signed manifests, and attested as existing no later than the time stated by **two
independent RFC 3161 authorities**. Failed attempts, gaps and source variants are recorded as such.
It does **not** claim the content is correct, that the endpoint was formally verified as the designated channel, or that
anything is admissible. Evidence level reaches **E3**; **E4 is unreachable** until a replica exists under a different administrator.

## Findings from the live source (worth knowing on election night)

1. **The "All Results" export alternates between two byte versions** on successive requests (112,307 vs 119,483 bytes).
   They differ only in the *wording of 32 ballot-question titles* (one truncates at ~528 chars); every vote/precinct value is
   identical. Probably two backend builds behind a load balancer (`Server: volt-adc`, `ARRAffinity` cookie → Azure App Service).
   Handled: every version preserved; a results fingerprint ignores free text, so the timeline only shows real result changes;
   an origin-instance tag is recorded so a **stale backend serving old vote counts** can be spotted tonight.
2. **The election cannot be pinned by id.** The site serves "the current election" by default. The `eid=` links on the
   Secretary of State's pages point to 2021 elections, and the SoS pages also link a legacy host
   (`electionresults.sos.state.nm.us`) that fails TLS from here. Mitigation: the page's election title/date is checked on every parse
   (`ELECTION_IDENTITY_MISMATCH` alert).
3. No `robots.txt` (404) and no stated terms on the results pages: every source is marked `UNREVIEWED` for terms/licensing.

## Addendum 003

| Req | Status | Notes |
|---|---|---|
| REQ-OBS-001/005 every attempt is an event; retries distinct | **DONE** | one row per attempt, linked by `schedule_id` / `retry_of_acquisition_id` |
| REQ-OBS-002 failure taxonomy | **PARTIAL** | ~20 of 28 statuses produced (DNS, connect, TLS, cert, timeouts, reset, partial, empty, 4xx/5xx, rate-limit, decompression, archive-write, redirect); browser/page/dependent-resource/timestamp/verification statuses n/a |
| REQ-OBS-003 negative-observation semantics | **PARTIAL** | OBSERVED_CHANGED/UNCHANGED, FAILED, SOURCE_UNAVAILABLE/EMPTY/PARTIAL, INDETERMINATE derived at read time; NOT_SCHEDULED, COLLECTION_SUPPRESSED, SOURCE_VERSION_* not distinguished |
| REQ-OBS-004 failure evidence gets same protection | **DONE** | acquisitions table (incl. failures) is digested into every timestamped manifest |
| REQ-SOURCE-001/002 authority record & chain | **PARTIAL** | draft record built from captured evidence; **unverified, no independent reviewer**; designation shown only as links on the SoS site |
| REQ-SOURCE-003 revalidation | NOT DONE | triggers are listed in the record; no workflow |
| REQ-SOURCE-004 classification | **DONE** | PRIMARY_OFFICIAL on all NM sources |
| REQ-TIME-001..004 structured time | **PARTIAL** | structured objects in the evidence package and API; precision vs accuracy separate; authority/confidence values mapped; no leap-second handling beyond OS |
| REQ-TIME-005/006 poll close, multi-zone | **PARTIAL** | one operator-entered NM record, flagged unverified; tracker never infers "closed" from the clock; no extension orders or other zones |
| REQ-CONSIST-* multi-component consistency | N/A / NOT DONE | single-resource transactions only (no browser bundles) |
| REQ-BYTE-001..005 byte layers | **PARTIAL** | evidentiary original = HTTP entity (transfer-decoded, pre-content-decoding); decoded form hashed separately when a Content-Encoding is applied; **raw wire/TLS bytes are not preserved and not claimed**; no normalization of originals |
| REQ-VERSION-001..004 source version identity | **PARTIAL** | ETag/Last-Modified captured (the source supplies neither); displayed stamp captured for HTML; byte-vs-version anomaly check implemented but dormant; fingerprint-based result identity added |
| REQ-AUTH-* hierarchy, conflict, fallback | NOT DONE | single official source family; no conflict/fallback logic |
| REQ-CERTREC-* certification records | NOT DONE | |
| REQ-RCV-* ranked-choice | NOT DONE | |
| REQ-DELTA-001..004 | **DONE** | "observed numeric delta", cause UNKNOWN_CAUSE unless supported, negatives visible. Other causes (corrections, reallocation, …) not auto-classified |
| REQ-SCHEMA-001 | **PARTIAL** | schema name/version/digest/canonicalization/release in each manifest; no schema registry or migration records |
| REQ-CANON-001/002 | **DONE** | `EIO-CANON-JSON-1` (UTF-8, ASCII-escaped, sorted keys, no floats/NaN) |
| REQ-CANON-003 cross-implementation test | **PARTIAL** | verifier reimplements it, but both are Python `json`; not independent enough |
| REQ-MERKLE-001..005 | **DONE** | `EIO-MERKLE-1` (RFC 6962/9162, domain-separated, no duplication); legacy `EIO-MERKLE-0` verified only under its declared profile; two implementations agree for 43 tree sizes; empty-tree and tree-size rules enforced |
| REQ-BUILD-* signed provenance | NOT DONE | no VCS/CI/signing; CycloneDX SBOM + file-digest release identity only; release marked UNSIGNED |
| REQ-COMP-001..004 coverage manifest & completeness | **DONE for NM** | signed manifest v1 (428 contests, frozen from the zero-results export); gap / unexpected / baseline-change events + alerts; live dashboard. **National federal contests are a declared gap.** |
| REQ-COMP-005 coverage change control | NOT DONE | no approver workflow |
| REQ-BASE-001..004 baseline | **PARTIAL** | contest/candidate/reporting-unit baseline, authority + endpoint evidence, status labels captured; **7-day lead and review not met**; no poll-close or ballot-method baseline artifacts |
| REQ-PRES-* presentation semantics | **PARTIAL** | precinct measure kept as the source's own label and never called ballots counted; turnout/estimates only archived (turnout page not parsed) |
| REQ-STATE-001..004 predicates | **DONE** | 16 predicates via API + package; no composite score; honest `false`s (see below) |
| REQ-QUAL-001..005 qualification | **PARTIAL** | `qualify` runs 11 self-tests, lists 17 known defects, records **no risk acceptances and NOT_AUTHORIZED**, signed + dual-timestamped. Not independent. |
| REQ-WIT-* rehearsal / observer / examiner | NOT DONE | needs people; synthetic data already isolated (separate ids/dirs) |

## Addendum 002

| Req | Status | Notes |
|---|---|---|
| Acquisition event / bundle model (§2) | **PARTIAL** | event-centric rows + exportable package with per-component status (PRESENT/NOT_COLLECTED/WITHHELD/RESTRICTED/NOT_APPLICABLE); no `bundle_id`/`evidence_record_id` objects |
| REQ-EVID-016/018 endpoint authentication & anomalies | **PARTIAL** | DNS answers, remote IP, TLS version/cipher, cert + fingerprints + validity, validation result; anomaly alerts (DNS change, cert change, validation fail, redirect to new domain, HTTP downgrade, TLS<1.2). **Adjacent probe, not in-band; leaf-only chain here; no OCSP/CRL; resolver identity = OS config** |
| REQ-EVID-019/021 HTTP transaction & cache evidence | **PARTIAL** | method, URL, redirects, headers, timings, encodings, lengths; no CDN-specific headers exist to capture |
| REQ-EVID-020 sensitive headers | **PARTIAL** | cookies removed from public record; encrypted restricted tier with salted commitment and access custody event. Key is on the same host |
| REQ-EVID-022..025 browser/dynamic capture | NOT DONE | marked NOT_COLLECTED in every package |
| REQ-EVID-017/026/027 audit logging | **PARTIAL** | log tables digested into signed, timestamped manifests; sequence-gap monitor; **no separate security boundary / replication** |
| REQ-CONFIG-001/004 config versions | **PARTIAL** | versioned + digested, linked to every acquisition; status `UNAPPROVED_NO_INDEPENDENT_REVIEW` |
| REQ-CONFIG-002/003 change control, source review | NOT DONE | no reviewer/approver exists |
| REQ-REPRO-001..005 | **PARTIAL** | release identity by file digests + pip lock + CycloneDX SBOM; no signed release, image, or parser replay container |
| REQ-CRYPTO-001 digest agility | **DONE** | `artifact_digests` table; SHA-256 + SHA3-256 live; `add-digest` backfills a new algorithm |
| REQ-CRYPTO-002 algorithm policy | NOT DONE | |
| REQ-CRYPTO-003/004 RFC 4998 evidence records, renewal | NOT DONE | decision not recorded |
| REQ-CRYPTO-005/006 dual anchor + failure handling | **DONE** (RFC 3161 ×2) | both are external to the operator; durable per-TSA retry queue; late tokens carry their real time. No transparency-log anchor |
| REQ-STORE-001..003 | **DONE** | artifact_id = SHA-256; every acquisition kept separately; no deletion code exists. REQ-STORE-004 GC: no GC at all |
| REQ-DATA-001 missing-data states | **PARTIAL** | NOT_PUBLISHED vs ZERO for vote-method fields; SOURCE_UNAVAILABLE/PARSER_FAILED at the observation level; others not modeled |
| REQ-DATA-002/003 correction taxonomy | **PARTIAL** | UNKNOWN_CAUSE / NORMAL_COUNT_UPDATE only; no reviewer workflow |
| REQ-ELECT-*, REQ-ID-* national model | NOT DONE | NM-only; candidate identity = source IDs, **no crosswalk review**; no stages/Maine-Nebraska/Senate classes/non-voting seats |
| REQ-HOLD-* legal hold | NOT DONE | (nothing deletes evidence, but there is no hold object) |
| REQ-SEC-001..004 trust boundaries, dual control, break-glass | NOT DONE | one host, one operator, signing key is a plain file |
| REQ-PACK-001..003 access profiles | **DONE** | five profiles, redaction manifest, export audit event (approver recorded as "none required") |
| REQ-CERT-* certification support report | NOT DONE | package + qualification record are the raw material |

## Addendum 001 / master spec — highlights

| Area | Status |
|---|---|
| Exact-byte archive, SHA-256, post-write verify, distinct timestamps | **DONE** |
| Clock monitoring (4 independent SNTP servers, TIME_CONFIDENCE_DEGRADED, alerts) | **DONE** (unauthenticated SNTP; see D-013) |
| RFC 3161 timestamps, offline verify, TSA-failure queue | **DONE** |
| Signed manifests, hash-chained custody ledger, Merkle proofs | **DONE** |
| Evidence package + standalone verifier, tamper test | **DONE** |
| Evidence levels E0–E4 | E0–E3 **DONE**; E4 **unreachable** (no separate administrative boundary) |
| HSM key management, immutable/WORM storage, cross-boundary replication | NOT DONE (replication code exists, off) |
| Tracker: contests, drill-down, timeline slider, what-changed, source comparison, evidence view, source health | **DONE** for NM statewide totals |
| County-level drill-down | NOT DONE (HTML pages archived, not parsed) |
| Maps, race calls, AP/media/aggregator sources, national coverage, certification reconciliation | NOT DONE |
| WCAG 2.2 AA | **PARTIAL** (semantic tables, keyboard-operable controls, non-color status text, high-contrast toggle; not audited) |
| Replay test dataset / load / failure tests | **PARTIAL** (67 tests incl. failure simulation; no load test, no historical-election replay) |

## Evidence predicates — what is false right now, and why (all deliberate)

`SOURCE_AUTHORITY_VERIFIED`, `CONFIGURATION_VERIFIED` (no independent reviewer) · `COLLECTOR_RELEASE_VERIFIED`,
`PARSER_RELEASE_VERIFIED` (unsigned release) · `IMMUTABLE_STORAGE_VERIFIED` (read-only attribute + DB triggers are not WORM) ·
`REPLICA_VERIFIED` (no replica) · `CROSSWALK_VERIFIED` (no reviewed crosswalk) · `ENDPOINT_VERIFIED` / `CLOCK_WITHIN_POLICY`
are false only for acquisitions captured before those controls existed.

## Decisions only you can make

1. **Independent reviewer/approver** — needed to move source config, coverage manifest, authority record and qualification off DRAFT. This is the single biggest lever on evidence quality.
2. **Replica location under a different administrator** (a second cloud tenant, a partner's bucket) → set `OBSERVATORY_REPLICA_DIR` and declare it; only then does E4 become possible.
3. **Put the project under version control** (and CI signing) so releases can be signed (REQ-BUILD).
4. **Counsel review** of the claim boundary, retention, and hold language before anything is relied on.
5. **National sources**: which federal-results provider (AP licence?) and the 50-state source matrix.
6. **Terms/licensing review** of the NM site and an agreed polling cadence (currently 60 s for the primary export; about 8 requests/min in total across 19 sources).

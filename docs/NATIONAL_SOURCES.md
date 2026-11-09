# National federal source inventory (scope per owner, 2026-11-03)

**Scope:** every federal contest nationally (President/VP and Electoral College, U.S. Senate regular/special, U.S. House incl.
at-large, non-voting delegates, runoffs/RCV where applicable) from **official government sources only**, plus every contest and
ballot question in New Mexico (the 19-source NM SoS package). AP, networks, media, campaign, social-media and aggregator feeds
are outside the acquisition boundary. 2026 is a midterm: no presidential contest or Electoral College tally exists tonight.

Addendum 004 was referenced but is **not in `specs/`** (only 001–003 are), so nothing from it is reflected here.

## What is running (registered in `observatory/config.py`, `NATIONAL_SOURCES`)

38 official state/territory entry points, polled every 300 s (900 s for slow-changing pages), archived byte-exact through the
same evidence chain as NM (append-only record, signed Merkle manifests, two RFC 3161 timestamps). **They are not parsed.**
Most are single-page apps or landing pages, so the archive shows what each official site presented at each moment but does
not yet yield Senate/House vote counts. **There is no national tally, no seat count, no 218 / Senate-control view.**

## Reached at 2026-11-03 probe, robots.txt allowed or absent (polled)

AR CA CO CT(2) DC FL GA HI IL IN IA KY LA MD MA MN MS MO NE NV NJ NC ND OH OR RI SC SD TX UT VT VA WA WV VI MP

Note Virginia's robots.txt disallows `*.json`, `*.csv`, `*.xls*`; a future VA data-endpoint collector must respect that.

## Removed after the first hour: archived content was a bot-protection page

MN (redirected to `validate.perfdrive.com`), CA and NV (a 920-byte Incapsula "Request unsuccessful" page instead of the site) were
polled for about an hour before I scanned the captures. What was archived is the challenge, not the source's content. They are no
longer polled; the captures stay in the archive as evidence of what was served. Not evaded. The list above therefore overstates
coverage by these three; actual entry-page coverage is 33 jurisdictions. DC, NJ and CNMI mention scripts/CAPTCHA markers but returned
full pages. Many other "200" pages are tiny script shells with no content in the HTML, which this check cannot detect.

## Second pass (after "fix all non-reporting states"): causes found and what changed

Many "unreachable" results were my environment or my guesses, not the states:
- **Stale CA bundle:** `certifi` was 2023.05; upgrading to 2026.10 fixed PA (Entrust/Sectigo R46 chain). The collector now uses it.
- **Servers that omit their TLS intermediate** (AK, AL, GU): a browser repairs this silently, Python does not. For these sources only,
  `observatory/trust/` ships the intermediate (fetched from the certificate's own AIA URL and proven to chain to a certifi root with
  OpenSSL before saving). Verification stays on. MT's `mtelectionresults.gov` verified the same way but its hostname check still fails; not polled.
- **Wrong guesses replaced by real endpoints:** AK (full statewide precinct CSV + summary PDF, with a derived federal/governor view),
  AL election-night pages, DE ENR page + state open-data CSV, GU unofficial-results page, ID Enhanced Voting JSON, WY/KS/MI/OK/PR
  authority pages, PA, and Maricopa County for AZ (county only; partial).

Still no source, and why (not evaded):
| Jurisdiction | Reason |
|---|---|
| AZ (state), ME, NH, NY, WI, TN (sos.tn.gov), MN, CA, NV | Bot-protection challenge / HTTP 403 to this client. Needs the operator to grant access or an alternate official feed. |
| MT, MI results host (`mielections.us`) | TCP connections time out from this network (not a challenge page). May be network- or geo-based; retry from elsewhere. |
| AS | No working hostname found. |
| TN results | `tnmap.tn.gov/electionresults/` returns 404. |

Only AK has a results view; DE, ID and AL have machine-readable or structured pages archived but not parsed.

## Not polled — and why

| Result | States / hosts | Next step |
|---|---|---|
| HTTP 403 (bot protection) | AZ results.arizona.vote, TX results.texas-election.com, NY nyenr/elections.ny.gov, WI elections.wi.gov, ME maine.gov, NH sos.nh.gov, TN sos.tn.gov, AR/GA clarityelections.com | Not evaded. Needs the operator to request access/permission or find an alternate official feed. |
| TLS/DNS/connect failure | AK, AL, DE results host, KS results host, KY results host, MI mielections.us, MO enrpages, MS electionnight, MT, OK, PA, TN results, VT/WY old hosts, CO results.sos.state.co.us, GU, AS | Hostnames were from memory and may be wrong, or this network may be blocked. Source discovery needed. |
| Wrong page | KS sos.ks.gov (redirects to a 404 page), ID (moved to votertools.voteidaho.gov), AL sos page (404) | Re-point. |

**38 entry points covering 36 jurisdictions are polled (plus New Mexico's own package). No working source yet:** 16 states
(AK AL AZ DE ID KS ME MI MT NH NY OK PA TN WI WY) and the territories GU and AS. For TX the only polled page is the SoS
elections index, not its results site (403). These are also only entry pages, not parsed results (see below).

## Conformance with `specs/state_election_authority_source_matrix.txt` (v0.1, added after the above was first built)

The matrix says non-NM rows stay `NOT_RESEARCHED` until endpoints, vendors, terms, robots and designation evidence are verified
from official sources, "to prevent unverified source assumptions from entering the evidentiary baseline". My first national
pass worked against that: the 38 entry pages came from memory and were labelled official. Corrected:

- They are now classified `CANDIDATE_UNVERIFIED`, matrix status `DISCOVERY_IN_PROGRESS` (36 jurisdictions) — **not** authority-
  or designation-verified, terms `LICENSING_UNREVIEWED`. Several hosts are vendor/unknown (`clarityelections.com`,
  `ctemspublic.pcctg.net`, `enr-scvotes.org`), so officially-designated status is genuinely unknown.
- Signed coverage manifest **v2** lists all 56 jurisdictions with matrix status (19 `NOT_RESEARCHED`: AL AK AZ DE ID KS ME MI MT NH
  NY OK PA TN WI WY AS GU PR; NM `TECHNICAL_SOURCE_SET_DEFINED`). The Coverage tab shows the jurisdiction dashboard; none can
  disappear silently. Individual federal contests outside NM are still not enumerated.
- NM internal-consistency classification (CONSISTENT / VALUE_DIFFERENCE / MISSING_FROM_STATE / SCOPE_DIFFERENCE /
  VERSION_MISMATCH / PARSER_DIFFERENCE / CROSSWALK_AMBIGUITY / INDETERMINATE) implemented in `observatory/crosscheck.py`
  (`python -m observatory crosscheck`, `/api/crosscheck`). First live result: all 11 narrower exports CONSISTENT with STATE.
  `MISSING_FROM_SUBSET` is not computed (needs a category crosswalk).
- Not done: per-jurisdiction discovery records, the 8 discovery gates, designation-evidence archiving for non-NM authorities,
  status enumeration tracking beyond the above, national normalization, rehearsals. Matrix still lists PRESIDENT everywhere
  although 2026 has no presidential contest.

## What full national tracking still needs (not built)

1. Per-platform data-endpoint discovery (Enhanced Voting `/results/public`, Clarity, ElectionStats, state-custom JSON/CSV) and
   the election-specific URLs, which for many states only appear on the night.
2. A federal-contest normalizer across jurisdictions (office, district, party, candidate identity, special/runoff, RCV rounds).
3. Seat accounting: current + called + uncalled, 218 / Senate control. "Called" must come from an official source or be defined
   by an explicit, documented rule; no media calls are collected.
4. Coverage baseline for expected national federal contests (35 Senate seats, 435 House seats, delegates). The frozen NM
   coverage manifest has `expected_national_federal_contests` empty.
5. Terms review per host; polling cadence agreed with each operator where possible.

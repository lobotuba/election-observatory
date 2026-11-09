# Election Information Observatory

A collector and tracker for **official, unofficial election returns**. It polls government results sources, preserves every
capture as byte-exact, timestamped evidence, and serves a local tracker UI (timeline, what-changed, coverage, source health,
evidence). It was built for the New Mexico 2026 general election (2026-11-03), where it covers every contest and ballot
question the New Mexico Secretary of State publishes, and it also archives official entry pages for other states and
territories.

Built spec-first against a master specification and three addenda in [specs/](specs/). **What is and isn't implemented is in
[docs/REQUIREMENTS_STATUS.md](docs/REQUIREMENTS_STATUS.md)**, which is deliberately blunt. In particular:

- The highest evidence level (E4) is intentionally unreachable: there is no independent reviewer and no replica under a
  separate administrator. The system will not claim otherwise.
- Only **New Mexico** results are parsed into contests and a time series. Alaska has a derived (unrehearsed) view. Every
  other state's pages are archived but **not parsed**, and there is no national tally or seat count.
- Several state sites block automated clients (HTTP 403 / bot challenges). The collector detects and records this and does
  **not** evade it. See [docs/NATIONAL_SOURCES.md](docs/NATIONAL_SOURCES.md).
- Sources are official government sites only. Media, campaign and aggregator feeds are out of scope for results. A separate,
  context-only news module collects headline, link and short snippet ([docs/NEWS_MODULE.md](docs/NEWS_MODULE.md)).

Source entries other than New Mexico's are `CANDIDATE_UNVERIFIED`: their URLs have not been verified as officially
designated. Check a source with its jurisdiction's election authority before relying on it.

## Requirements

Developed and tested only on Windows 11 with Python 3.11 (`run.ps1` needs PowerShell; other platforms are untested).
`pip install -r requirements.txt`, and OpenSSL on `PATH` (Git for Windows bundles one) to verify RFC 3161 timestamp tokens.

## Run it

```powershell
.\run.ps1            # starts collector + tracker (detached); tracker at http://127.0.0.1:8000
.\run.ps1 -Stop
python -m pytest -q  # synthetic data and a throwaway directory, never the production archive
```

Open the tracker over `http://127.0.0.1:8000`, not as a `file://` page.

Data lives **outside the project** in `~/electionTracker-data` (override with `ELECTION_DATA_DIR`; keep it out of any
cloud-synced folder, since syncing a live SQLite file is unsafe): `archive/` (content-addressed, write-once),
`observatory.db` (append-only SQLite), `manifests/`, `timestamps/`, `audit/`, `coverage/`, `qualification/`, `exports/`,
`keys/` (signing keys, generated on first run), `logs/`. Emergency stop of collection: create `<data>\STOP` (delete to
resume).

## Commands (`python -m observatory …`)

| Command | Purpose |
|---|---|
| `collect` / `serve` | the two long-running processes (`run.ps1` starts both) |
| `status`, `evidence-status`, `coverage-status` | quick health checks |
| `verify-manifests` | verify every signed manifest, audit segment, custody chain, and sequence gaps |
| `export <acq_id> --profile public\|research\|internal\|legal\|security` | self-contained evidence package |
| `verify-package <dir>` | offline verification (also runnable standalone: `python verify_package.py .` inside the package) |
| `coverage-baseline` | freeze the expected-contest baseline from the earliest pre-results export |
| `authority-refresh` | rebuild the (draft) Source Authority Record |
| `crosscheck [--detail]` | classify differences between the NM statewide export and the narrower exports |
| `qualify [--with-pytest]` | self-tests → signed, dual-timestamped Evidence System Qualification Record |
| `add-digest <alg>` | add another digest algorithm for every artifact (no schema change) |

## How the evidence chain works

acquisition → response entity bytes stored under their SHA-256 (write-once, read-back verified) → append-only acquisition
row (every attempt, including failures) + hash-chained custody events → every 5 min a signed manifest (RFC 6962/9162
Merkle tree, previous-manifest hash, custody head, and digests of the log tables) → RFC 3161 tokens from **two**
independent TSAs (DigiCert, Sectigo; only the manifest digest is sent) → evidence level E0–E4 and 16 explicit predicates.

Environment knobs: `OBSERVATORY_INTERVAL_SCALE`, `OBSERVATORY_MANIFEST_INTERVAL_S`, `OBSERVATORY_TSA_URLS`,
`OBSERVATORY_REPLICA_DIR` + `OBSERVATORY_REPLICA_SEPARATE_BOUNDARY=1` (only if the replica is truly under a different
administrator), `OBSERVATORY_CONTACT`. By default no contact information is sent to any site.

## Being a good citizen

The collector polls every few minutes per source (60 s for the New Mexico exports). It sends no contact details and never
works around bot protection: a redirect to a known challenge host raises an alert, and a source that serves challenge pages
should be removed from `observatory/config.py` by hand (the collector does not do that automatically). robots.txt and terms
were reviewed by hand when each source was chosen and are recorded per source as `terms_review_status`; the collector itself
does not enforce robots.txt, so check it yourself before adding a source. Do not lower the intervals or add sources that
block automation.

## License

[MIT](LICENSE). Election data fetched by this tool belongs to the respective government sources and is not part of this
repository.

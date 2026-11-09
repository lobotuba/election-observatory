# News and press context module (added 2026-11-03 by owner decision)

## Scope amendment (proposed text for Specification v1.0)

The earlier scope and the State Election Authority Source Matrix placed media outside the acquisition boundary "unless a later
specification explicitly adds them". The owner has added a **News and press context** module. Amended statement:

> Election-result observations are acquired from official government sources only. Separately, the Observatory SHALL collect
> headline-level reporting from designated official press feeds and designated news-outlet RSS feeds as **context**. News and press
> items are never used as a source of results, seat counts, contests, coverage, or race calls, are labeled as media reporting wherever
> shown, and are kept in tables and views separate from official results. Only headline, link, publication time, outlet and a short
> feed-supplied snippet are retained; full article text is not collected. AP, wire services, campaigns, parties, social media and
> third-party aggregators remain out of scope.

This is a draft amendment to the owner's own spec. It is not yet written into the spec files, and the spec has not been re-reviewed.

## What runs

16 RSS/Atom feeds, polled every 5-15 minutes, each capture archived byte-exact through the same evidence chain as the results
(append-only record, signed manifests, two RFC 3161 timestamps), then parsed into `news_items`:

- Official press: NM Secretary of State (`sos.nm.gov/feed/`), U.S. Election Assistance Commission.
- National media: NPR, PBS NewsHour, The Guardian US, BBC US & Canada, CBS, ABC, NBC, Politico, The Hill.
- New Mexico media: Source NM, NM Political Report, Searchlight NM, KOB, KRQE.

UI: choose "News" in the Election selector. API: `/api/news`, `/api/news/sources`.

## Design rules and limits

- `news_items` is append-only. An item's later headline or summary edit is stored as a new version (keyed by title+summary hash);
  nothing is overwritten.
- Snippet is tag-stripped and truncated to 400 characters. Headlines and snippets are the outlets' own words, unverified by this system.
- "Election-related" is a keyword heuristic only. It will include irrelevant items and miss relevant ones.
- News sources are `jurisdiction=NEWS`, `scope=NEWS_CONTEXT`, `authority_level=NONE_CONTEXT_ONLY`; tests assert they never attach to a
  jurisdiction's source list.
- Terms are `LICENSING_UNREVIEWED`. These are public RSS feeds published for syndication, robots.txt allowed or was absent
  (NPR and Politico have none; absence is not permission), but no outlet's terms were reviewed.
- Not found / not included: Albuquerque Journal and KUNM (feed URLs did not resolve), Santa Fe New Mexican (HTTP 429), AP and other
  wires (licence required).
- Feeds only list recent items, so history before the first poll is not captured.
- A feed's own publication time is shown when parseable; otherwise "first seen" time, labeled as such.
- Posted to the same "sources" health table and counts as the results sources; the Coverage tab's source counts now include them.

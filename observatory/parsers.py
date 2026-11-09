"""Parsers. They read archived bytes only; they never touch the network or the raw artifact."""
import csv
import html
import io
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

NM_CSV_COLUMNS = [
    "RaceID", "RaceName", "PartyCode", "AreaNum", "CandidateID", "CandidateName", "VoteFor",
    "CandidateVotes", "CandidatePercentage", "PrecinctsReporting", "CandidateAbsenteeVotes",
    "CandidateElectionDayVotes", "CandidateEarlyVotes",
]
_PRECINCT_RE = re.compile(r"^\s*(\d+)\s*/\s*(\d+)\s*$")


class SchemaError(Exception):
    """The artifact does not look like the format this parser was written for."""


@dataclass
class ParseResult:
    observations: list = field(default_factory=list)
    findings: list = field(default_factory=list)   # (severity, code, detail)
    stamp: dict | None = None                       # html pages only
    news_items: list = field(default_factory=list)  # rss_feed only


def _int(v):
    v = (v or "").strip().replace(",", "")
    if v == "":
        return None
    return int(v)


def parse_nm_sos_csv(data: bytes) -> ParseResult:
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        raise SchemaError("empty file")
    header = [h.strip() for h in header]
    # Trailing empty header cells are tolerated; the sample rows carry trailing commas.
    while header and header[-1] == "":
        header.pop()
    if header != NM_CSV_COLUMNS:
        raise SchemaError(f"unexpected header: {header}")

    res = ParseResult()
    for lineno, row in enumerate(reader, start=2):
        if not any(c.strip() for c in row):
            continue
        row = [c.strip() for c in row[: len(NM_CSV_COLUMNS)]]
        row += [""] * (len(NM_CSV_COLUMNS) - len(row))
        rec = dict(zip(NM_CSV_COLUMNS, row))
        try:
            votes = _int(rec["CandidateVotes"])
            if votes is None:
                raise ValueError("missing CandidateVotes")
            m = _PRECINCT_RE.match(rec["PrecinctsReporting"])
            obs = dict(
                source_race_id=rec["RaceID"],
                race_name=rec["RaceName"],
                area=rec["AreaNum"] or None,
                party_code=rec["PartyCode"] or None,
                source_candidate_id=rec["CandidateID"],
                candidate_name=rec["CandidateName"],
                vote_for=_int(rec["VoteFor"]),
                votes=votes,
                source_pct_text=rec["CandidatePercentage"] or None,
                precincts_label=rec["PrecinctsReporting"] or None,
                precincts_reporting=int(m.group(1)) if m else None,
                precincts_total=int(m.group(2)) if m else None,
                votes_absentee=_int(rec["CandidateAbsenteeVotes"]),
                votes_election_day=_int(rec["CandidateElectionDayVotes"]),
                votes_early=_int(rec["CandidateEarlyVotes"]),
                validation_state="OK",
            )
            if not rec["RaceID"] or not rec["CandidateID"]:
                raise ValueError("missing RaceID/CandidateID")
            if not m:
                obs["validation_state"] = "WARN"
                res.findings.append(("WARN", "PRECINCT_LABEL_UNPARSED", f"line {lineno}: {rec['PrecinctsReporting']!r}"))
            elif obs["precincts_reporting"] > obs["precincts_total"]:
                obs["validation_state"] = "WARN"
                res.findings.append(("WARN", "PRECINCTS_REPORTING_EXCEEDS_TOTAL", f"line {lineno}: {rec['PrecinctsReporting']}"))
            if votes < 0:
                obs["validation_state"] = "WARN"
                res.findings.append(("WARN", "NEGATIVE_VOTES", f"line {lineno}: race {rec['RaceID']}"))
            res.observations.append(obs)
        except (ValueError, KeyError) as e:
            res.findings.append(("ERROR", "ROW_REJECTED", f"line {lineno}: {e}"))
    if not res.observations:
        raise SchemaError("no data rows")
    return res


_UPDATED_RE = re.compile(r"Results\s+last\s+updated:\s*(?:<[^>]+>\s*)*([^<\r\n]+)", re.I)
_STAMP_FMT_RE = re.compile(r"(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2})\s*([AP]M)\s*(MT|MST|MDT)?", re.I)


def parse_displayed_timestamp(text: str) -> str | None:
    """'11/2/2026 3:35 PM MT' -> UTC ISO string. Interpretation is ours; the text is kept verbatim."""
    m = _STAMP_FMT_RE.search(text)
    if not m:
        return None
    dt = datetime.strptime(f"{m.group(1)} {m.group(2)} {m.group(3).upper()}", "%m/%d/%Y %I:%M %p")
    dt = dt.replace(tzinfo=ZoneInfo("America/Denver")).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_nm_sos_html(data: bytes) -> ParseResult:
    """HTML pages are archived as evidence; we only lift the displayed 'last updated' stamp."""
    text = data.decode("utf-8", errors="replace")
    res = ParseResult()
    m = _UPDATED_RE.search(text)
    if m:
        shown = re.sub(r"\s+", " ", m.group(1)).strip()
        res.stamp = {"displayed_text": shown, "displayed_iso_utc": parse_displayed_timestamp(shown)}
    else:
        res.findings.append(("INFO", "NO_DISPLAYED_TIMESTAMP", "page has no 'Results last updated' text"))
    # Election identity: the site serves "the current election" implicitly, so verify what it says it is serving.
    plain = re.sub(r"\s+", " ", re.sub(r"(?is)<script.*?</script>|<style.*?</style>|<[^>]+>", " ", text))
    em = re.search(r"Results\s+(.+?)\s+((?:January|February|March|April|May|June|July|August|September|October|November|December) \d{1,2}, \d{4})\s+Results last updated", plain)
    if em:
        title, date = em.group(1).strip(), em.group(2)
        from . import config
        if title.upper() != config.EXPECTED_ELECTION_TITLE or date != config.EXPECTED_ELECTION_DATE_TEXT:
            res.findings.append(("ERROR", "ELECTION_IDENTITY_MISMATCH", f"page says {title!r} {date!r}; expected "
                                 f"{config.EXPECTED_ELECTION_TITLE!r} {config.EXPECTED_ELECTION_DATE_TEXT!r}"))
        else:
            res.findings.append(("INFO", "ELECTION_IDENTITY_OK", f"{title} {date}"))
    return res


def parse_archive_only(data: bytes) -> ParseResult:
    """Pages kept purely as evidence (e.g. the authority's own site). Nothing is extracted."""
    return ParseResult(findings=[("INFO", "ARCHIVE_ONLY", "no fields extracted by design")])


_VOLATILE_RE = re.compile(rb'(name="__(?:VIEWSTATE|VIEWSTATEGENERATOR|EVENTVALIDATION|VIEWSTATEENCRYPTED)"[^>]*?value=")[^"]*(")', re.I)


def normalize_for_change(fmt: str, data: bytes) -> bytes:
    """Bytes used ONLY to decide 'did the content change'. The raw artifact is archived untouched.

    ASP.NET pages embed per-request encrypted tokens that differ on every fetch.
    """
    if fmt == "html":
        return _VOLATILE_RE.sub(rb"\1\2", data)
    return data


_NEWS_RE = re.compile(r"\b(elections?|ballots?|voters?|voting|votes?|polls?|polling|primar(?:y|ies)|precincts?|canvass|recount|turnout|"
                      r"senate|senator|congress(?:ional)?|house race|governor|gubernatorial|secretary of state|county clerk|"
                      r"candidates?|campaign|midterms?|electoral|redistricting|runoff)\b", re.I)


def _strip(s: str, n: int) -> str:
    s = re.sub(r"(?is)<script.*?</script>|<style.*?</style>", " ", s or "")
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(re.sub(r"\s+", " ", s)).strip()
    return s if len(s) <= n else s[:n - 1].rstrip() + "…"


def _iso(text: str | None) -> str | None:
    if not text:
        return None
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime
    for f in (lambda t: parsedate_to_datetime(t),
              lambda t: datetime.fromisoformat(t.strip().replace("Z", "+00:00"))):
        try:
            d = f(text)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
    return None


def parse_rss_feed(data: bytes) -> ParseResult:
    """RSS 2.0 / Atom headline feeds -> news items (title, link, short summary, time). Media context only: no article text is kept."""
    import xml.etree.ElementTree as ET
    if len(data) > 8_000_000:
        raise SchemaError("feed unreasonably large")
    if re.search(rb"<!ENTITY", data[:4096], re.I):
        raise SchemaError("feed declares XML entities; refusing to parse")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise SchemaError(f"feed is not well-formed XML: {e}")
    atom = "{http://www.w3.org/2005/Atom}"
    res = ParseResult()
    res.news_items = []
    nodes = root.findall(".//item") or root.findall(f".//{atom}entry")
    if not nodes:
        raise SchemaError("no items or entries in feed")
    for n in nodes[:200]:
        def t(*names):
            for nm in names:
                e = n.find(nm)
                if e is not None and (e.text or "").strip():
                    return e.text.strip()
            return None
        title = _strip(t("title", f"{atom}title") or "", 300)
        link = t("link")
        if not link:
            le = n.find(f"{atom}link")
            link = le.get("href") if le is not None else None
        key = t("guid", f"{atom}id") or link or title
        summ = _strip(t("description", f"{atom}summary", f"{atom}content") or "", 400)
        pub = t("pubDate", f"{atom}published", f"{atom}updated", "{http://purl.org/dc/elements/1.1/}date")
        if not title or not key:
            continue
        res.news_items.append(dict(item_key=key[:500], title=title, link=(link or "")[:1000] or None, summary=summ or None,
                                   published_text=pub, published_utc=_iso(pub),
                                   election_related=1 if _NEWS_RE.search(title + " " + summ) else 0))
    res.findings.append(("INFO", "NEWS_FEED_PARSED", f"{len(res.news_items)} items"))
    return res


PARSERS = {"nm_sos_csv": parse_nm_sos_csv, "nm_sos_html": parse_nm_sos_html, "html_archive_only": parse_archive_only,
           "rss_feed": parse_rss_feed}

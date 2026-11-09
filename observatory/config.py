"""Configuration and the source registry (spec 5.3, trimmed to what the MVP uses)."""
import os
from pathlib import Path

# Keep the data directory outside any cloud-synced folder: sync of a live SQLite file / write-once archive is unsafe.
DATA_DIR = Path(os.environ.get("ELECTION_DATA_DIR", str(Path.home() / "electionTracker-data")))
ARCHIVE_DIR = DATA_DIR / "archive"
MANIFEST_DIR = DATA_DIR / "manifests"
KEY_DIR = DATA_DIR / "keys"
DB_PATH = DATA_DIR / "observatory.db"
STOP_FILE = DATA_DIR / "STOP"  # existence halts all collection (emergency stop)

ELECTION_ID = "nm-2026-general"
ELECTION_LABEL = "New Mexico General Election, 2026-11-03"
BASE_URL = "https://electionresults.sos.nm.gov"

# Optional contact string appended to the User-Agent so operators can reach us.
OWNER_CONTACT = os.environ.get("OBSERVATORY_CONTACT", "")
USER_AGENT = "ElectionInformationObservatory/0.1 (public-records archiver)" + (
    f" contact={OWNER_CONTACT}" if OWNER_CONTACT else ""
)

# Global multiplier on all polling intervals (e.g. 0.5 to poll twice as fast).
INTERVAL_SCALE = float(os.environ.get("OBSERVATORY_INTERVAL_SCALE", "1.0"))

# --- Digital evidence subsystem (addendum 001) ---
MANIFEST_INTERVAL_S = int(os.environ.get("OBSERVATORY_MANIFEST_INTERVAL_S", "300"))   # addendum: 1-5 min when active
TIMESTAMP_DIR = DATA_DIR / "timestamps"
EXPORT_DIR = DATA_DIR / "exports"
# RFC 3161 TSAs, tried in order. Only a SHA-256 digest of the manifest is ever sent, never election content.
TSA_URLS = [u for u in os.environ.get(
    "OBSERVATORY_TSA_URLS", "http://timestamp.digicert.com,http://timestamp.sectigo.com").split(",") if u]
TSA_RETRY_MIN_S = 60
# Optional second copy. Evidence level E4 is claimed ONLY when the operator declares the replica
# is in a separate administrative boundary; a folder on the same machine is not one.
REPLICA_DIR = Path(os.environ["OBSERVATORY_REPLICA_DIR"]) if os.environ.get("OBSERVATORY_REPLICA_DIR") else None
REPLICA_IS_SEPARATE_BOUNDARY = os.environ.get("OBSERVATORY_REPLICA_SEPARATE_BOUNDARY") == "1"
RESTRICTED_DIR = DATA_DIR / "restricted"
AUDIT_DIR = DATA_DIR / "audit"
RELEASE_DIR = DATA_DIR / "releases"
CERT_DIR = DATA_DIR / "endpoint_certs"
ENDPOINT_PROBE_INTERVAL_S = 60
MIN_TLS_VERSION = "TLSv1.2"
EXTRA_DIGEST_ALGORITHMS = ["sha3_256"]   # in addition to SHA-256 (REQ-CRYPTO-001); more can be added without schema change
NTP_SERVERS =["time.cloudflare.com", "time.google.com", "time.windows.com", "pool.ntp.org"]
CLOCK_SAMPLE_INTERVAL_S = 60
CLOCK_TOLERANCE_MS = 100        # beyond this: TIME_CONFIDENCE_DEGRADED
CLOCK_ALERT_MS = 500            # alert at this offset
CLOCK_MAX_AGE_S = 300           # no successful clock sample for this long => degraded
OPENSSL_CANDIDATES = [r"C:\Program Files\Git\usr\bin\openssl.exe", "openssl"]

REQUEST_TIMEOUT_S = 30
MAX_RETRIES = 2                 # per scheduled poll, with exponential backoff
CIRCUIT_BREAKER_FAILURES = 5    # consecutive failed polls before the circuit opens
CIRCUIT_BREAKER_PAUSE_S = 300
STALE_AFTER_FACTOR = 5          # source "stale" if no success for 5x its interval


def _csv(sid, label, typ, interval, parser="nm_sos_csv"):
    return dict(
        source_id=sid,
        source_name=f"NM SoS Media/Results Export - {label}",
        organization_name="New Mexico Secretary of State",
        source_class="TIER1_OFFICIAL_UNOFFICIAL",
        authority_level="OFFICIAL_UNOFFICIAL",
        jurisdiction="NM",
        endpoint_url=f"{BASE_URL}/resultsCSV.aspx?text=All&type={typ}&map=CTY",
        platform_family="nm-sos-aspx",
        expected_format="csv",
        time_zone="America/Denver",
        source_timestamp_type="none-in-file",
        polling_interval_s=interval,
        parser_name=parser,
        parser_version="1",
        terms_review_status="UNREVIEWED: no robots.txt (404); no terms stated on the export page",
        export_type=typ,
        source_classification=["PRIMARY_OFFICIAL"],
        publication_status="machine-readable official export",
        authority_record_key="nm-sos-results",
    )


def _html(sid, label, path, interval, parser="nm_sos_html"):
    return dict(
        source_id=sid,
        source_name=f"NM SoS Results Website - {label}",
        organization_name="New Mexico Secretary of State",
        source_class="TIER1_OFFICIAL_UNOFFICIAL",
        authority_level="OFFICIAL_UNOFFICIAL",
        jurisdiction="NM",
        endpoint_url=f"{BASE_URL}{path}",
        platform_family="nm-sos-aspx",
        expected_format="html",
        time_zone="America/Denver",
        source_timestamp_type="displayed-on-page",
        polling_interval_s=interval,
        parser_name=parser,
        parser_version="1",
        terms_review_status="UNREVIEWED: no robots.txt (404); no terms stated on the results pages",
        source_classification=["PRIMARY_OFFICIAL"],
        publication_status="official publication (web presentation)",
        authority_record_key="nm-sos-results",
    )


def _designation(sid, label, url):
    """Pages on the authority's own site that show which results system it points people to (REQ-SOURCE-002)."""
    d = _html(sid, label, "/", 900, parser="html_archive_only")
    d.update(endpoint_url=url, source_name=f"NM SoS Official Site - {label}", source_timestamp_type="none",
             source_classification=["PRIMARY_OFFICIAL"], publication_status="authority's own site (designation evidence)",
             role="DESIGNATION_EVIDENCE")
    return d


# `primary` marks the source the tracker treats as the baseline for a contest.
SOURCES = [
    {**_csv("nm-sos-csv-all", "All Results", "STATE", 60), "primary": True},
    _csv("nm-sos-csv-fed", "Federal", "FED", 120),
    _csv("nm-sos-csv-sw", "Statewide Offices & Questions", "SW", 120),
    _csv("nm-sos-csv-lgx", "Legislative", "LGX", 120),
    _csv("nm-sos-csv-jdx", "District Judges", "JDX", 180),
    _csv("nm-sos-csv-ecx", "Public Education Commission", "ECX", 180),
    _csv("nm-sos-csv-jmc", "Metropolitan Court Judges", "JMC", 180),
    _csv("nm-sos-csv-mgx", "Magistrate Judges", "MGX", 180),
    _csv("nm-sos-csv-cty", "Offices and Questions by County", "CTY", 120),
    _csv("nm-sos-csv-mux", "Municipal", "MUX", 180),
    _csv("nm-sos-csv-clx", "College District Questions", "CLX", 300),
    _csv("nm-sos-csv-swx", "Soil & Water Conservation", "SWX", 300),
    _html("nm-sos-html-home", "Home (displayed update time, turnout)", "/", 60),
    _html("nm-sos-html-fed", "Federal results (web presentation)", "/resultsSW.aspx?type=FED&map=CTY", 120),
    _html("nm-sos-html-sw", "Statewide results (web presentation)", "/resultsSW.aspx?type=SW&map=CTY", 120),
    _html("nm-sos-html-cty", "Offices by county (web presentation)", "/resultsList.aspx?type=cty&map=CTY", 180),
    _html("nm-sos-html-turnout", "Voter turnout detail", "/VoterTurnoutDetails.aspx?map=TURN", 300),
    _designation("nm-sos-site-home", "Home page", "https://www.sos.nm.gov/"),
    _designation("nm-sos-site-results", "Election results page", "https://www.sos.nm.gov/voting-and-elections/election-results/"),
]


def _national(state, label, url, interval=300, **extra):
    """Official state/territory results entry point, archived byte-exact but NOT parsed (no race extraction yet).
    These show what each official site presented; extracting President/Senate/House results needs per-platform
    data-endpoint discovery (see docs/NATIONAL_SOURCES.md)."""
    d = _html(f"nat-{state.lower()}-{label}", label, "/", interval, parser="html_archive_only")
    d.update(endpoint_url=url, source_name=f"{state} candidate election entry page - {label}", jurisdiction=state,
             source_timestamp_type="none", source_classification=["CANDIDATE_UNVERIFIED"],
             publication_status="CANDIDATE entry page, unparsed; official status NOT established (no authority/designation evidence)",
             authority_record_key=None, role="NATIONAL_FEDERAL_ENTRY_POINT", scope="NATIONAL_FEDERAL",
             matrix_status="DISCOVERY_IN_PROGRESS",
             terms_review_status="LICENSING_UNREVIEWED; robots.txt allowed or absent at probe 2026-11-03 (absence is not permission)")
    d.update(extra)
    return d


# Reached and robots-permitted in the 2026-11-03 probe. Sites that blocked (403), failed TLS/DNS, or were not found are
# listed in docs/NATIONAL_SOURCES.md and are NOT polled; no attempt is made to evade blocking.
NATIONAL_SOURCES = [
    _national("AR", "sos-results", "https://www.sos.arkansas.gov/elections/research/election-results", 900),
    _national("CO", "enr", "https://results.enr.clarityelections.com/CO/"),
    _national("CT", "enr", "https://ctemspublic.pcctg.net/"),
    _national("CT", "sots-results", "https://portal.ct.gov/sots/election-services/election-results", 900),
    _national("DC", "results", "https://electionresults.dcboe.org/"),
    _national("FL", "results", "https://results.elections.myflorida.com/"),
    _national("GA", "results", "https://results.sos.ga.gov/"),
    _national("HI", "results", "https://elections.hawaii.gov/election-results/", 900),
    _national("IL", "vote-totals", "https://elections.il.gov/ElectionOperations/ElectionVoteTotals.aspx", 900),
    _national("IN", "enr", "https://enr.indianavoters.in.gov/"),
    _national("IA", "results", "https://electionresults.iowa.gov/"),
    _national("KY", "sbe", "https://elect.ky.gov/", 900),
    _national("LA", "graphical", "https://voterportal.sos.la.gov/graphical"),
    _national("MD", "elections-2026", "https://elections.maryland.gov/elections/2026/index.html", 900),
    _national("MA", "electionstats", "https://electionstats.state.ma.us/", 900),
    _national("MS", "sos-results", "https://www.sos.ms.gov/elections-voting/election-results", 900),
    _national("MO", "sos-results", "https://www.sos.mo.gov/elections/results"),
    _national("NE", "results", "https://electionresults.nebraska.gov/"),
    _national("NJ", "results", "https://nj.gov/state/elections/election-information-results.shtml", 900),
    _national("NC", "results", "https://er.ncsbe.gov/"),
    _national("ND", "results", "https://results.sos.nd.gov/"),
    _national("OH", "live", "https://liveresults.ohiosos.gov/"),
    _national("OR", "results", "https://results.oregonvotes.gov/"),
    _national("RI", "results", "https://www.ri.gov/election/results/"),
    _national("SC", "enr", "https://www.enr-scvotes.org/"),
    _national("SD", "results", "https://electionresults.sd.gov/"),
    _national("TX", "sos-elections", "https://www.sos.state.tx.us/elections/index.shtml", 900),
    _national("UT", "results", "https://electionresults.utah.gov/"),
    _national("VT", "archive", "https://electionarchive.vermont.gov/", 900),
    _national("VA", "results", "https://www.elections.virginia.gov/results/"),
    _national("WA", "results", "https://results.vote.wa.gov/"),
    _national("WV", "results", "https://apps.sos.wv.gov/elections/results/"),
    # Alaska Division of Elections (state-run; election-night files under /enr/26GENR/ are linked from its own results page).
    # The server does not send its TLS intermediate, so a stock client fails verification; we complete the chain with the
    # GlobalSign GCC R46 OV TLS CA 2025 intermediate (SHA-256 D160E2DE...63F9), which chains to GlobalSign Root R46 in certifi.
    *[_national("AK", label, url, interval, tls_extra_ca="globalsign_gcc_r46_ov_tls_ca_2025.pem",
                tls_note="Server omits its intermediate certificate; chain completed from AIA-fetched intermediate and verified to a certifi root.",
                expected_format=fmt, **kw)
      for label, url, interval, fmt, kw in [
          ("enr-statewide-precinct-csv", "https://www.elections.alaska.gov/enr/26GENR/results/GA_ENR_Precinct_State_of_Alaska.csv", 120, "csv",
           dict(role="BASELINE_CANDIDATE", publication_status="CANDIDATE statewide precinct-level CSV on the Division of Elections host; unparsed into the evidence tables")),
          ("enr-summary-pdf", "https://www.elections.alaska.gov/enr/26GENR/results/ElectionSummaryReportRPT.pdf", 120, "pdf", {}),
          ("results-page", "https://www.elections.alaska.gov/election-results/", 300, "html", {}),
          ("enr-map", "https://www.elections.alaska.gov/enr/26GENR/", 300, "html", {}),
          ("doe-home", "https://www.elections.alaska.gov/", 900, "html", dict(role="AUTHORITY_HOME_EVIDENCE")),
      ]],
    # --- Added after a diagnosis of every non-reporting jurisdiction (docs/NATIONAL_SOURCES.md). Each is still CANDIDATE_UNVERIFIED. ---
    # Alabama: SoS election-night pages; servers omit the GlobalSign Atlas intermediate.
    _national("AL", "election-night-results", "https://www2.alabamavotes.gov/electionNight/statewideResultsByContest.aspx?ecode=1001305", 120,
              tls_extra_ca="globalsign_atlas_r46_ov_tls_ca_2026_q3.pem", tls_note="Server omits its intermediate; chain completed from AIA-fetched intermediate verified to a certifi root."),
    _national("AL", "alabamavotes-home", "https://www.alabamavotes.gov/", 900, tls_extra_ca="globalsign_atlas_r46_ov_tls_ca_2026_q3.pem",
              tls_note="Server omits its intermediate; chain completed from AIA-fetched intermediate verified to a certifi root.", role="AUTHORITY_HOME_EVIDENCE"),
    # Delaware: Department of Elections ENR page plus the state's open-data (Socrata) CSV for the 2026 General.
    _national("DE", "ge2026-enr", "https://elections.delaware.gov/results/enr/GE2026.html", 120),
    _national("DE", "open-data-csv", "https://data.delaware.gov/resource/yg7x-kgjc.csv?election_name=2026%20General%20Election", 300, expected_format="csv",
              role="BASELINE_CANDIDATE", publication_status="CANDIDATE state open-data CSV; the Socrata API may cap rows per request, so completeness is unverified"),
    _national("DE", "results-index", "https://elections.delaware.gov/results/", 900, role="AUTHORITY_HOME_EVIDENCE"),
    # Guam (delegate): GEC unofficial results page; server omits the GoDaddy intermediate.
    _national("GU", "unofficial-results", "https://gec.guam.gov/2026-general-election-unofficial-results/", 300,
              tls_extra_ca="go_daddy_secure_certificate_authority_g2.pem", tls_note="Server omits its intermediate; chain completed from AIA-fetched intermediate verified to a certifi root."),
    # Idaho: Enhanced Voting JSON behind results.voteidaho.gov (election object has asOf/lastUpdated/precinctsReporting; contest detail endpoints not yet mapped).
    _national("ID", "election-json", "https://results.voteidaho.gov/results/public/api/elections/id/nov2026", 120, expected_format="json", role="BASELINE_CANDIDATE",
              publication_status="CANDIDATE statewide election summary JSON (vendor app on the state's results host); contest-level endpoints not mapped"),
    _national("ID", "localities-json", "https://results.voteidaho.gov/results/public/api/elections/id/nov2026/localities", 300, expected_format="json"),
    _national("ID", "sos-results-page", "https://voteidaho.gov/election-results/", 900, role="AUTHORITY_HOME_EVIDENCE"),
    _national("PA", "electionreturns", "https://www.electionreturns.pa.gov/", 120),   # reachable once certifi was upgraded (stale roots)
    _national("WY", "election-results", "https://sos.wyo.gov/Elections/ElectionResults.aspx", 300),
    _national("KS", "election-results", "https://sos.ks.gov/elections/election-results.html", 900),
    _national("MI", "sos-results-and-data", "https://www.michigan.gov/sos/elections/election-results-and-data", 900,
              publication_status="CANDIDATE authority page only; the results host mielections.us did not accept connections from this network"),
    _national("OK", "elections-home", "https://oklahoma.gov/elections.html", 900, role="AUTHORITY_HOME_EVIDENCE"),
    _national("PR", "ceepur-home", "https://ceepur.org/", 900),
    # Arizona: the state results site is bot-protected (403 to this client; not evaded). Maricopa County (largest county) is reachable.
    _national("AZ", "maricopa-county-results", "https://elections.maricopa.gov/results-and-data/election-results.html", 120,
              publication_status="CANDIDATE COUNTY page (Maricopa only). Arizona's statewide results site refuses this client; this is a partial stand-in, not the state source"),
    _national("VI", "vivote", "https://vivote.gov/", 900),
    _national("MP", "cnmi", "https://www.votecnmi.gov.mp/", 900),
]
def _news(sid, outlet, url, interval, official=False, **extra):
    """Headline feed. MEDIA/PRESS CONTEXT ONLY: archived byte-exact (same evidence chain) and parsed to headline+link+short
    snippet. Never used for results, seat counts, contests or race calls. Added by owner decision 2026-11-03 (scope amendment)."""
    d = _html(f"news-{sid}", outlet, "/", interval, parser="rss_feed")
    d.update(endpoint_url=url, source_name=f"News/press feed - {outlet}", expected_format="xml", jurisdiction="NEWS",
             source_class="NEWS_CONTEXT", authority_level="NONE_CONTEXT_ONLY", source_timestamp_type="item-level-in-feed",
             source_classification=["OFFICIAL_PRESS_RELEASES" if official else "MEDIA_CONTEXT"],
             publication_status="official press/news feed" if official else "media reporting; not an election authority",
             authority_record_key=None, role="NEWS_FEED", scope="NEWS_CONTEXT",
             terms_review_status="LICENSING_UNREVIEWED; public RSS feed; headline/link/short snippet only, no article text kept; robots.txt allowed or absent at probe 2026-11-03")
    d.update(extra)
    return d


NEWS_SOURCES = [
    _news("nm-sos", "NM Secretary of State", "https://www.sos.nm.gov/feed/", 300, official=True),
    _news("eac", "U.S. Election Assistance Commission", "https://www.eac.gov/rss.xml", 900, official=True),
    _news("ak-doe", "Alaska Division of Elections", "https://www.elections.alaska.gov/feed/", 300, official=True,
          tls_extra_ca="globalsign_gcc_r46_ov_tls_ca_2025.pem"),
    _news("npr-politics", "NPR Politics", "https://feeds.npr.org/1014/rss.xml", 600),
    _news("pbs-politics", "PBS NewsHour Politics", "https://www.pbs.org/newshour/feeds/rss/politics", 600),
    _news("guardian-uspol", "The Guardian US Politics", "https://www.theguardian.com/us-news/us-politics/rss", 600),
    _news("bbc-us", "BBC US & Canada", "https://feeds.bbci.co.uk/news/world/us_and_canada/rss.xml", 600),
    _news("cbs-politics", "CBS News Politics", "https://www.cbsnews.com/latest/rss/politics", 600),
    _news("abc-politics", "ABC News Politics", "https://abcnews.go.com/abcnews/politicsheadlines", 600),
    _news("nbc-politics", "NBC News Politics", "https://feeds.nbcnews.com/nbcnews/public/politics", 600),
    _news("politico", "Politico Politics", "https://rss.politico.com/politics-news.xml", 600),
    _news("thehill", "The Hill", "https://thehill.com/feed/", 600),
    _news("sourcenm", "Source NM", "https://sourcenm.com/feed/", 600),
    _news("nmpoliticalreport", "NM Political Report", "https://nmpoliticalreport.com/feed/", 300),
    _news("searchlightnm", "Searchlight New Mexico", "https://searchlightnm.org/feed/", 600),
    _news("kob", "KOB 4 (Albuquerque)", "https://www.kob.com/feed/", 300),
    _news("krqe", "KRQE (Albuquerque)", "https://www.krqe.com/feed/", 300),
]
SOURCES = SOURCES + NATIONAL_SOURCES + NEWS_SOURCES

# State Election Authority Source Matrix v0.1 (specs/state_election_authority_source_matrix.txt): 50 states + DC + 5 territories.
# Matrix status per jurisdiction is NOT_RESEARCHED unless something has been archived; no entry here is authority-verified.
_STATES = ("AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC "
           "SD TN TX UT VT VA WA WV WI WY").split()
_COVERAGE = {"DC": "PRESIDENT,DELEGATE", "AS": "DELEGATE", "GU": "DELEGATE", "MP": "DELEGATE", "PR": "RESIDENT_COMMISSIONER", "VI": "DELEGATE"}
_JUR_WITH_ENTRY = {s["jurisdiction"] for s in NATIONAL_SOURCES}
JURISDICTION_NAMES = dict(zip(
    "AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC AS GU MP PR VI".split(),
    ["Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut", "Delaware", "Florida", "Georgia", "Hawaii", "Idaho",
     "Illinois", "Indiana", "Iowa", "Kansas", "Kentucky", "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota",
     "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada", "New Hampshire", "New Jersey", "New Mexico", "New York", "North Carolina",
     "North Dakota", "Ohio", "Oklahoma", "Oregon", "Pennsylvania", "Rhode Island", "South Carolina", "South Dakota", "Tennessee", "Texas",
     "Utah", "Vermont", "Virginia", "Washington", "West Virginia", "Wisconsin", "Wyoming", "District of Columbia", "American Samoa", "Guam",
     "Northern Mariana Islands", "Puerto Rico", "U.S. Virgin Islands"]))
JURISDICTIONS = [
    dict(jurisdiction=j, name=JURISDICTION_NAMES[j], federal_coverage=_COVERAGE.get(j, "PRESIDENT,SENATE,HOUSE"),
         tracker_depth="ALL_CONTESTS_NM" if j == "NM" else "FEDERAL_ONLY",
         matrix_status=("TECHNICAL_SOURCE_SET_DEFINED" if j == "NM" else
                        "BASELINE_IDENTIFIED" if j == "AK" else
                        "DISCOVERY_IN_PROGRESS" if j in _JUR_WITH_ENTRY else "NOT_RESEARCHED"),
         entry_sources=[s["source_id"] for s in SOURCES if s.get("jurisdiction") == j and s.get("scope") == "NATIONAL_FEDERAL"])
    for j in _STATES + ["DC", "AS", "GU", "MP", "PR", "VI"]
]

# The results site returns "the current election" by default; there is no explicit id for it that we can pin.
# The page's own election title/date is therefore checked on every parse (ELECTION_IDENTITY_MISMATCH alert).
EXPECTED_ELECTION_TITLE = "GENERAL 2026"
EXPECTED_ELECTION_DATE_TEXT = "November 3, 2026"
# Statutory poll hours as understood by the operator; NOT verified against an official artifact (REQ-TIME-005).
POLL_CLOSE = {"jurisdiction": "NM", "time_zone": "America/Denver", "local_time": "19:00", "utc": "2026-11-04T02:00:00Z",
              "basis": "statutory poll hours (7:00 AM - 7:00 PM local), operator-entered", "verified_against_artifact": False,
              "extensions": [], "confidence": "operator_entered_unverified"}

SOURCES_BY_ID = {s["source_id"]: s for s in SOURCES}
PRIMARY_SOURCE_ID = next(s["source_id"] for s in SOURCES if s.get("primary"))


def tls_bundle(pem_name: str) -> str:
    """CA bundle = certifi roots + one intermediate shipped in observatory/trust/, for a server that does not send its intermediate.
    Verification stays ON and the chain must still end at a certifi root; the extra certificate is only used for sources that name it."""
    import certifi
    from pathlib import Path
    extra = (Path(__file__).parent / "trust" / pem_name).read_text()
    out = DATA_DIR / "trust" / f"bundle_{pem_name}"
    data = Path(certifi.where()).read_text() + "\n" + extra
    if not out.exists() or out.read_text() != data:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(data)
    return str(out)


def ensure_dirs():
    for d in (DATA_DIR, ARCHIVE_DIR, MANIFEST_DIR, KEY_DIR, TIMESTAMP_DIR, EXPORT_DIR, RESTRICTED_DIR, AUDIT_DIR, RELEASE_DIR, CERT_DIR):
        d.mkdir(parents=True, exist_ok=True)

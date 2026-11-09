"""AT-003-001/002/005-ish: every attempt is an event; outages are never shown as 'observed, unchanged'."""
import json

import pytest
import requests

from observatory import archive, collector, config, queries
from tests.conftest import BASE_ROWS, TEST_SOURCE_ID, make_csv


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(collector.time, "sleep", lambda s: None)   # no real backoff waits
    monkeypatch.setattr(config, "MAX_RETRIES", 2)
    monkeypatch.setattr(config, "REQUEST_TIMEOUT_S", 1)


def run(conn, src):
    st = collector.SourceState(src)
    st.release_id = st.config_version_id = None
    ok = collector.acquire(conn, requests.Session(), st)
    return ok, st


def rows(conn):
    return [dict(r) for r in conn.execute("SELECT * FROM acquisitions ORDER BY acquisition_id")]


def test_success_then_unchanged_then_changed(conn, server, src_factory):
    srv, state = server
    state["csv"] = make_csv(BASE_ROWS)
    src = src_factory("/csv")
    st = collector.SourceState(src)
    s = requests.Session()
    assert collector.acquire(conn, s, st)
    assert collector.acquire(conn, s, st)
    state["csv"] = make_csv([r[:6] + (5,) + r[7:] if r[4] == 11 else r for r in BASE_ROWS])
    assert collector.acquire(conn, s, st)
    r = rows(conn)
    assert [x["observation_status"] for x in r] == ["OBSERVED_CHANGED", "OBSERVED_UNCHANGED", "OBSERVED_CHANGED"]
    assert r[0]["sha256"] == r[1]["sha256"] != r[2]["sha256"]       # identical bytes -> one artifact, two acquisition events
    assert r[0]["post_write_verified"] == 1 and r[0]["byte_layer"] == "HTTP_ENTITY_PAYLOAD"
    assert {x["schedule_id"] for x in r} == {r[0]["schedule_id"], r[1]["schedule_id"], r[2]["schedule_id"]} and len({x["schedule_id"] for x in r}) == 3


def test_http_503_creates_one_event_per_attempt_linked_to_the_schedule(conn, src_factory):
    ok, _ = run(conn, src_factory("/503"))
    r = rows(conn)
    assert not ok and len(r) == 3                                    # 1 + MAX_RETRIES attempts, none collapsed
    assert [x["attempt_number"] for x in r] == [1, 2, 3]
    assert len({x["schedule_id"] for x in r}) == 1
    assert r[1]["retry_of_acquisition_id"] == r[0]["acquisition_id"] == r[2]["retry_of_acquisition_id"]
    assert {x["failure_status"] for x in r} == {"HTTP_SERVER_ERROR"}
    assert {x["observation_status"] for x in r} == {"SOURCE_UNAVAILABLE"}
    assert r[0]["next_retry_utc"] and r[2]["next_retry_utc"] is None   # last attempt has no further retry
    assert r[0]["sha256"]                                             # the error page itself is preserved as evidence


def test_empty_response(conn, src_factory):
    ok, _ = run(conn, src_factory("/empty"))
    assert not ok and {x["failure_status"] for x in rows(conn)} == {"EMPTY_RESPONSE"}
    assert rows(conn)[0]["observation_status"] == "SOURCE_RETURNED_EMPTY"


def test_partial_body_is_preserved_and_labelled(conn, src_factory):
    ok, _ = run(conn, src_factory("/partial"))
    r = rows(conn)
    assert not ok and r[0]["failure_status"] == "PARTIAL_RESPONSE"
    assert r[0]["observation_status"] == "SOURCE_RETURNED_PARTIAL"
    assert r[0]["sha256"] and len(archive.read(r[0]["sha256"])) == 200      # what arrived is kept, not discarded


def test_timeout_before_headers(conn, src_factory):
    ok, _ = run(conn, src_factory("/slow"))
    assert not ok and {x["failure_status"] for x in rows(conn)} == {"TIMEOUT_BEFORE_HEADERS"}


def test_connection_refused(conn, server, src_factory):
    src = src_factory("/csv")
    src["endpoint_url"] = "http://127.0.0.1:9/csv"      # nothing listens on the discard port
    ok, _ = run(conn, src)
    assert not ok and rows(conn)[0]["failure_status"] == "CONNECTION_FAILED"


def test_dns_failure(conn, src_factory):
    src = src_factory("/csv")
    src["endpoint_url"] = "http://no-such-host.invalid/csv"
    ok, _ = run(conn, src)
    assert not ok and rows(conn)[0]["failure_status"] == "DNS_FAILED"


def test_gzip_keeps_both_byte_layers_and_parser_reads_decoded(conn, server, src_factory):
    _, state = server
    state["csv"] = make_csv(BASE_ROWS)
    ok, _ = run(conn, src_factory("/gzip"))
    a = rows(conn)[0]
    assert ok and a["content_encoding"] == "gzip"
    assert a["decoded_sha256"] and a["decoded_sha256"] != a["sha256"]
    assert archive.read(a["decoded_sha256"]) == state["csv"]            # decoded layer
    assert archive.read(a["sha256"]) != state["csv"]                    # entity (encoded) layer preserved untouched
    assert conn.execute("SELECT COUNT(*) c FROM vote_obs WHERE acquisition_id=?", (a["acquisition_id"],)).fetchone()["c"] == 4


def test_cookie_value_is_not_in_public_record_but_commitment_exists(conn, server, src_factory):
    ok, _ = run(conn, src_factory("/cookie"))
    a = rows(conn)[0]
    assert ok and a["set_cookie_present"] == 1 and a["restricted_commitment"]
    assert "supersecret123" not in json.dumps(a, default=str)
    enc = (config.RESTRICTED_DIR / a["restricted_path"]).read_bytes()
    assert b"supersecret123" not in enc                                  # encrypted at rest
    from observatory import provenance
    got = provenance.read_restricted(conn, a["acquisition_id"], "test", "unit test")
    assert got["commitment_ok"] and "supersecret123" in json.dumps(got)
    assert conn.execute("SELECT COUNT(*) c FROM custody_events WHERE event_type='RESTRICTED_ACCESSED'").fetchone()["c"] == 1


def test_timeline_never_calls_an_outage_unchanged(conn, server, src_factory):
    _, state = server
    state["csv"] = make_csv(BASE_ROWS)
    st = collector.SourceState(src_factory("/csv"))
    s = requests.Session()
    assert collector.acquire(conn, s, st)
    good = queries.observation_status(conn, TEST_SOURCE_ID)
    assert good["status"] == "OBSERVED_UNCHANGED" or good["status"] == "OBSERVED_CHANGED"
    st.src["endpoint_url"] = st.src["endpoint_url"].replace("/csv", "/503")
    assert not collector.acquire(conn, s, st)
    bad = queries.observation_status(conn, TEST_SOURCE_ID)
    assert bad["status"] == "SOURCE_UNAVAILABLE"
    assert bad["last_good_observation_utc"] == good["last_good_observation_utc"]
    assert bad["unobserved_since_utc"] and bad["attempt_failure"] == "HTTP_SERVER_ERROR"
    # the earlier moment is still reconstructable as it was known then, with no later information
    t_good = good["last_good_observation_utc"]
    assert queries.observation_status(conn, TEST_SOURCE_ID, t_good)["status"] in ("OBSERVED_CHANGED", "OBSERVED_UNCHANGED")


def test_acquisition_rows_cannot_be_rewritten(conn, server, src_factory):
    run(conn, src_factory("/csv"))
    with pytest.raises(Exception, match="append-only"):
        conn.execute("UPDATE acquisitions SET http_status=500")
    with pytest.raises(Exception, match="append-only"):
        conn.execute("DELETE FROM acquisitions")

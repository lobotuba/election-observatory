import sqlite3

import pytest

from observatory import config, parsers

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>Voters line up as polls open in Albuquerque</title><link>https://example.org/a</link><guid>g1</guid>
<description>&lt;p&gt;Turnout is &lt;b&gt;heavy&lt;/b&gt;.&lt;/p&gt;</description><pubDate>Tue, 03 Nov 2026 14:00:00 GMT</pubDate></item>
<item><title>Local bakery wins award</title><link>https://example.org/b</link><description>Cakes.</description></item>
</channel></rss>"""
ATOM = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Senate race tightens</title><id>urn:1</id>
<link href="https://example.org/c"/><summary>Polls show a close race</summary><updated>2026-11-03T20:00:00Z</updated></entry></feed>"""


def test_rss_items_snippet_and_classification():
    r = parsers.parse_rss_feed(RSS)
    a, b = r.news_items
    assert a["election_related"] == 1 and b["election_related"] == 0
    assert a["summary"] == "Turnout is heavy ." or a["summary"] == "Turnout is heavy."   # tags stripped, never raw markup
    assert "<" not in a["summary"]
    assert a["published_utc"] == "2026-11-03T14:00:00Z"
    assert b["published_utc"] is None and b["item_key"] == "https://example.org/b"   # falls back to link when no guid


def test_atom_supported():
    r = parsers.parse_rss_feed(ATOM)
    assert r.news_items[0]["link"] == "https://example.org/c" and r.news_items[0]["published_utc"] == "2026-11-03T20:00:00Z"


def test_rejects_entities_and_non_feeds():
    with pytest.raises(parsers.SchemaError):
        parsers.parse_rss_feed(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><rss><channel><item><title>&a;</title></item></channel></rss>')
    with pytest.raises(parsers.SchemaError):
        parsers.parse_rss_feed(b"<html><body>not a feed</body></html>")
    with pytest.raises(parsers.SchemaError):
        parsers.parse_rss_feed(b"<rss><channel></channel></rss>")


def test_summary_is_truncated():
    big = b"<rss><channel><item><title>Vote</title><guid>1</guid><description>" + b"word " * 500 + b"</description></item></channel></rss>"
    assert len(parsers.parse_rss_feed(big).news_items[0]["summary"]) <= 400


def test_news_sources_are_context_only():
    assert config.NEWS_SOURCES and all(s["scope"] == "NEWS_CONTEXT" and s["jurisdiction"] == "NEWS" for s in config.NEWS_SOURCES)
    assert all(s["parser_name"] == "rss_feed" and s["authority_level"] == "NONE_CONTEXT_ONLY" for s in config.NEWS_SOURCES)
    # news must never be attached to a jurisdiction's source list (and therefore never to results)
    for j in config.JURISDICTIONS:
        assert not any(s.startswith("news-") for s in j["entry_sources"])


def test_news_table_is_append_only_and_dedupes(conn):
    row = ("s", "k", "h", "Title", None, None, None, None, 1, 1, "2026-11-03T00:00:00Z")
    sql = ("INSERT OR IGNORE INTO news_items(source_id,item_key,content_sha256,title,link,summary,published_text,published_utc,"
           "election_related,first_seen_acquisition_id,first_seen_utc) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    conn.execute(sql, row)
    conn.execute(sql, row)
    assert conn.execute("SELECT COUNT(*) c FROM news_items").fetchone()["c"] == 1
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE news_items SET title='x'")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM news_items")

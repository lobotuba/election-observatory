from pathlib import Path

import pytest

from observatory import config, parsers

FIXTURE = Path(__file__).parent / "fixtures" / "pre_election_all.csv"


def test_real_preelection_export_parses_completely():
    r = parsers.parse_nm_sos_csv(FIXTURE.read_bytes())
    assert len(r.observations) == 648
    assert len({o["source_race_id"] for o in r.observations}) == 428
    assert all(o["votes"] == 0 for o in r.observations)
    # source label kept verbatim, counts split out
    sen = next(o for o in r.observations if o["race_name"] == "United States Senator")
    assert sen["precincts_label"] == "0/2204" and sen["precincts_total"] == 2204
    # blank breakdown columns are NOT converted to zero
    assert sen["votes_early"] is None and sen["votes_absentee"] is None


def test_schema_change_is_detected_not_guessed():
    bad = b"RaceID,RaceName,Whatever\n1,2,3\n"
    with pytest.raises(parsers.SchemaError):
        parsers.parse_nm_sos_csv(bad)


def test_malformed_row_is_rejected_but_others_kept():
    good = FIXTURE.read_bytes().decode().splitlines()
    mangled = "\n".join(good[:3] + ['11185,"X","DEM","",19999,"NOBODY",1,notanumber,0,0/5,,,,'] + good[3:6])
    r = parsers.parse_nm_sos_csv(mangled.encode())
    assert any(code == "ROW_REJECTED" for _, code, _ in r.findings)
    assert len(r.observations) == 5


def test_displayed_timestamp_kept_verbatim_and_converted_separately():
    assert parsers.parse_displayed_timestamp("11/2/2026 3:35 PM MT") == "2026-11-02T22:35:00Z"
    html = b"<div>Results GENERAL 2026 November 3, 2026 Results last updated: 11/2/2026 3:35 PM MT</div>"
    r = parsers.parse_nm_sos_html(html)
    assert r.stamp["displayed_text"] == "11/2/2026 3:35 PM MT"
    assert any(c == "ELECTION_IDENTITY_OK" for _, c, _ in r.findings)


def test_wrong_election_is_flagged():
    html = b"<div>Results Regular Local Election November 2, 2021 Results last updated: 11/29/2021 1:30 PM MT</div>"
    r = parsers.parse_nm_sos_html(html)
    assert any(c == "ELECTION_IDENTITY_MISMATCH" for _, c, _ in r.findings)


def test_viewstate_noise_does_not_count_as_a_change():
    a = b'<input name="__VIEWSTATE" id="__VIEWSTATE" value="AAAA" /><p>same</p>'
    b = b'<input name="__VIEWSTATE" id="__VIEWSTATE" value="BBBB" /><p>same</p>'
    c = b'<input name="__VIEWSTATE" id="__VIEWSTATE" value="BBBB" /><p>different</p>'
    n = parsers.normalize_for_change
    assert n("html", a) == n("html", b)
    assert n("html", a) != n("html", c)
    assert n("csv", a) != n("csv", b)   # CSV is never normalised

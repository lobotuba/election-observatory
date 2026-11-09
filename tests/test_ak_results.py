import pytest

from observatory import ak_results, config

HDR = "Precinct_name,Reporting_flag,Pct_Id,Contest_Id,Contest_title,candidate_id,candidate_name,Party_Code,total_ballots,total_votes\n"


def test_derive_sums_precincts_and_ignores_other_contests():
    rows = HDR + "\n".join([
        "P1,1,01-001,6,U.S. Senator,1,Alpha A.,REP,100,60", "P1,1,01-001,6,U.S. Senator,2,Beta B.,DEM,100,40",
        "P2,0,01-002,6,U.S. Senator,1,Alpha A.,REP,50,5", "P2,0,01-002,6,U.S. Senator,2,Beta B.,DEM,50,20",
        "P1,1,01-001,8,Senate District A,9,Local L.,NON,100,99"])
    r = ak_results.derive(rows.encode())
    (c,) = r["contests"]
    assert c["title"] == "U.S. Senator" and c["total_votes"] == 125 and c["ballots"] == 150
    assert [x["name"] for x in c["candidates"]] == ["Alpha A.", "Beta B."] and c["candidates"][0]["votes"] == 65
    assert c["precincts_total"] == 2 and c["precincts_flagged_reporting"] == 1
    assert r["all_contest_count"] == 2


def test_derive_rejects_unknown_layout():
    with pytest.raises(ValueError):
        ak_results.derive(b"a,b\n1,2\n")


def test_alaska_sources_configured_with_chain_fix_and_unverified():
    ak = [s for s in config.SOURCES if s.get("jurisdiction") == "AK" and s.get("scope") == "NATIONAL_FEDERAL"]
    assert any(s["source_id"] == ak_results.SOURCE_ID for s in ak)
    assert all(s["tls_extra_ca"] and "CANDIDATE_UNVERIFIED" in s["source_classification"] for s in ak)
    assert config.tls_bundle("globalsign_gcc_r46_ov_tls_ca_2025.pem")

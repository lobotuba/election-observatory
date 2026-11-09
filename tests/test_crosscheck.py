from observatory import config, crosscheck


def _c(votes, cands=("a", "b"), area="State", vote_for=1, precincts="1/2", parser="1", name="US Senate"):
    return dict(race_name=name, area=area, vote_for=vote_for, precincts=precincts, parser=parser,
                cands={k: (k.upper(), v) for k, v in zip(cands, votes)})


def test_classes():
    base = _c((10, 5))
    by_name = {("US Senate", "State"): "x"}
    assert crosscheck._classify(_c((10, 5)), base, None, by_name) == "CONSISTENT"
    assert crosscheck._classify(_c((11, 5)), base, base, by_name) == "VALUE_DIFFERENCE"
    assert crosscheck._classify(_c((11, 5)), base, _c((9, 5)), by_name) == "VERSION_MISMATCH"
    assert crosscheck._classify(_c((10, 5), cands=("a", "c")), base, None, by_name) == "SCOPE_DIFFERENCE"
    assert crosscheck._classify(_c((10, 5), parser="2"), base, None, by_name) == "PARSER_DIFFERENCE"
    assert crosscheck._classify(_c((10, 5)), None, None, by_name) == "CROSSWALK_AMBIGUITY"
    assert crosscheck._classify(_c((10, 5), name="Other"), None, None, by_name) == "MISSING_FROM_STATE"


def test_jurisdiction_registry_complete_and_unverified():
    assert len(config.JURISDICTIONS) == 56 and len({j["jurisdiction"] for j in config.JURISDICTIONS}) == 56
    assert all(j["matrix_status"] != "PRODUCTION_APPROVED" for j in config.JURISDICTIONS)
    assert all("PRIMARY_OFFICIAL" not in s["source_classification"] for s in config.NATIONAL_SOURCES)
    ids = [s["source_id"] for s in config.SOURCES]
    assert len(ids) == len(set(ids))

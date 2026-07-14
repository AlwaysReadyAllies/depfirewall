import sarif


def _res(verdict, **kw):
    base = {"system": "pypi", "dep": "x", "version": "1.0", "verdict": verdict,
            "reason": "why", "severity": None, "source": "deps.dev", "advisories": []}
    base.update(kw)
    return base


def test_safe_is_not_a_finding():
    d = sarif.to_sarif([_res("SAFE"), _res("NEW")])
    ids = [r["ruleId"] for r in d["runs"][0]["results"]]
    assert "SAFE" not in ids                       # SAFE never becomes a result
    assert "NEW" in ids                            # NEW is a note-level finding


def test_unknown_and_vulnerable_are_errors():
    d = sarif.to_sarif([_res("UNKNOWN"), _res("VULNERABLE", severity=9.8)])
    by = {r["ruleId"]: r for r in d["runs"][0]["results"]}
    assert by["UNKNOWN"]["level"] == "error"
    assert by["VULNERABLE"]["level"] == "error"
    assert by["VULNERABLE"]["properties"]["security-severity"] == "9.8"   # CVSS passed through


def test_shape_is_valid_sarif():
    d = sarif.to_sarif([_res("VULNERABLE", severity=7.5)])
    assert d["version"] == "2.1.0"
    run = d["runs"][0]
    assert run["tool"]["driver"]["name"] == "depfirewall"
    assert run["results"][0]["locations"][0]["logicalLocations"][0]["kind"] == "package"

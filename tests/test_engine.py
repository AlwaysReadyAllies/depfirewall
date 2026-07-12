"""Engine verdicts — all offline via monkeypatched engine._get."""
from datetime import datetime, timedelta, timezone

import engine


def fake_get(responses):
    """responses: list of (match_substring, (data, err)); first match wins."""
    def _get(url):
        for frag, resp in responses:
            if frag in url:
                return resp
        raise AssertionError(f"unexpected URL: {url}")
    return _get


def _pkg(versions):
    return {"versions": versions}


def _ver(version, published_days_ago=10, is_default=True):
    ts = (datetime.now(timezone.utc) - timedelta(days=published_days_ago)).isoformat()
    return {"versionKey": {"version": version}, "publishedAt": ts, "isDefault": is_default}


def test_vulnerable_dedups_same_cve_keeps_highest_cvss(monkeypatch):
    monkeypatch.setattr(engine, "_get", fake_get([
        ("/advisories/GHSA-1", ({"aliases": ["CVE-2020-1"], "cvss3Score": 5.0, "title": "low"}, None)),
        ("/advisories/PYSEC-1", ({"aliases": ["CVE-2020-1"], "cvss3Score": 9.8, "title": "high"}, None)),
        ("/versions/1.0", ({"licenses": ["MIT"], "isDeprecated": False,
                            "advisoryKeys": [{"id": "GHSA-1"}, {"id": "PYSEC-1"}]}, None)),
        ("/packages/", (_pkg([_ver("1.0")]), None)),
    ]))
    r = engine.check_one("pypi", "badpkg", "1.0")
    assert r["verdict"] == "VULNERABLE"
    assert len(r["advisories"]) == 1  # same CVE deduped
    assert r["advisories"][0]["cvss"] == 9.8
    assert r["severity"] == 9.8


def test_double_404_is_unknown(monkeypatch):
    monkeypatch.setattr(engine, "_get", fake_get([
        ("api.deps.dev", (None, "http 404")),
        ("pypi.org", (None, "http 404")),
    ]))
    r = engine.check_one("pypi", "depfw-nope-xyz")
    assert r["verdict"] == "UNKNOWN"
    assert r["source"] == "registry-confirmed-404"
    assert "hallucinated" in r["reason"]


def test_depsdev_404_but_registry_200_is_new(monkeypatch):
    monkeypatch.setattr(engine, "_get", fake_get([
        ("api.deps.dev", (None, "http 404")),
        ("pypi.org", ({"info": {}}, None)),
    ]))
    r = engine.check_one("pypi", "brand-new-pkg")
    assert r["verdict"] == "NEW"
    assert r["source"] == "native-registry"


def test_deprecated(monkeypatch):
    monkeypatch.setattr(engine, "_get", fake_get([
        ("/versions/2.0", ({"licenses": [], "isDeprecated": True, "advisoryKeys": []}, None)),
        ("/packages/", (_pkg([_ver("2.0")]), None)),
    ]))
    assert engine.check_one("npm", "oldpkg", "2.0")["verdict"] == "DEPRECATED"


def test_stale(monkeypatch):
    monkeypatch.setattr(engine, "_get", fake_get([
        ("/versions/0.1", ({"licenses": [], "isDeprecated": False, "advisoryKeys": []}, None)),
        ("/packages/", (_pkg([_ver("0.1", published_days_ago=1200)]), None)),
    ]))
    r = engine.check_one("pypi", "abandoned", "0.1")
    assert r["verdict"] == "STALE"


def test_safe(monkeypatch):
    monkeypatch.setattr(engine, "_get", fake_get([
        ("/versions/3.0", ({"licenses": ["MIT"], "isDeprecated": False, "advisoryKeys": []}, None)),
        ("/packages/", (_pkg([_ver("3.0")]), None)),
    ]))
    assert engine.check_one("pypi", "fine", "3.0")["verdict"] == "SAFE"


DEFAULT_FAIL = {"UNKNOWN", "VULNERABLE"}


def test_should_fail_unknown_default():
    assert engine.should_fail({"verdict": "UNKNOWN"}, DEFAULT_FAIL)
    assert not engine.should_fail({"verdict": "STALE"}, DEFAULT_FAIL)
    assert not engine.should_fail({"verdict": "NEW"}, DEFAULT_FAIL)


def test_severity_floor():
    low = {"verdict": "VULNERABLE", "severity": 5.6}
    high = {"verdict": "VULNERABLE", "severity": 9.8}
    unscored = {"verdict": "VULNERABLE", "severity": None}
    assert not engine.should_fail(low, DEFAULT_FAIL, 7.0)
    assert engine.should_fail(high, DEFAULT_FAIL, 7.0)
    assert engine.should_fail(unscored, DEFAULT_FAIL, 7.0)  # unknown severity fails conservatively
    assert engine.should_fail(low, DEFAULT_FAIL, 0.0)  # floor 0 = any advisory fails

import io
import urllib.error

import gh

MARKER = "<!-- depfirewall-verdict -->"


def test_upsert_updates_existing(monkeypatch):
    calls = []

    def fake_api(path, token, method="GET", body=None):
        calls.append((method, path))
        if method == "GET":
            return [{"id": 5, "body": "old " + MARKER}]
        return {}

    monkeypatch.setattr(gh, "api", fake_api)
    assert gh.upsert_comment("o/r", 1, "new", "tok", MARKER) == "updated"
    assert ("PATCH", "/repos/o/r/issues/comments/5") in calls


def test_upsert_creates_when_absent(monkeypatch):
    calls = []

    def fake_api(path, token, method="GET", body=None):
        calls.append((method, path))
        return [] if method == "GET" else {}

    monkeypatch.setattr(gh, "api", fake_api)
    assert gh.upsert_comment("o/r", 1, "new", "tok", MARKER) == "created"
    assert ("POST", "/repos/o/r/issues/1/comments") in calls


def test_upsert_403_skips_gracefully(monkeypatch):
    def fake_api(path, token, method="GET", body=None):
        raise urllib.error.HTTPError("u", 403, "forbidden", {}, io.BytesIO())

    monkeypatch.setattr(gh, "api", fake_api)
    out = gh.upsert_comment("o/r", 1, "new", "tok", MARKER)
    assert out.startswith("skipped")
    assert "403" in out

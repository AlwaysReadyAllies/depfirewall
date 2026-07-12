import license_gate


def test_public_repo_free():
    ok, msg = license_gate.gate("o/r", "", "http://v", is_private=False)
    assert ok and "free" in msg


def test_private_no_key_blocked():
    ok, msg = license_gate.gate("o/r", "", "http://v", is_private=True)
    assert not ok
    assert license_gate.PURCHASE_URL in msg


def test_private_valid_key(monkeypatch):
    monkeypatch.setattr(license_gate, "verify_key", lambda k, r, u: (True, "ok"))
    ok, _ = license_gate.gate("o/r", "dfw_abc", "http://v", is_private=True)
    assert ok


def test_private_bound_elsewhere(monkeypatch):
    monkeypatch.setattr(license_gate, "verify_key",
                        lambda k, r, u: (False, "key is bound to a different repository"))
    ok, _ = license_gate.gate("o/r", "dfw_abc", "http://v", is_private=True)
    assert not ok


def test_verifier_down_fails_open(monkeypatch):
    monkeypatch.setattr(license_gate, "verify_key", lambda k, r, u: (None, "verifier unreachable"))
    ok, msg = license_gate.gate("o/r", "dfw_abc", "http://v", is_private=True)
    assert ok and "failing open" in msg


def test_visibility_unknown_fails_open():
    ok, msg = license_gate.gate("o/r", "", "http://v", is_private=None)
    assert ok and "failing open" in msg


def test_skip_env(monkeypatch):
    monkeypatch.setenv("DEPFIREWALL_SKIP_LICENSE", "1")
    ok, msg = license_gate.gate("o/r", "", "http://v", is_private=True)
    assert ok and "skipped" in msg

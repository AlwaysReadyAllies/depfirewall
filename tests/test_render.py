from render import MARKER, table


def _r(name, verdict, severity=None, reason="r | with pipe"):
    return {"system": "pypi", "name": name, "version": "1.0", "verdict": verdict,
            "severity": severity, "reason": reason, "advisories": []}


def test_marker_and_fail_header():
    md = table([_r("bad", "VULNERABLE", 9.8)], "FAIL", "diff")
    assert md.startswith(MARKER)
    assert "❌" in md and "FAIL" in md


def test_vulnerable_sorts_before_safe():
    md = table([_r("fine", "SAFE"), _r("bad", "VULNERABLE", 5.0)], "FAIL", "diff")
    assert md.index("VULNERABLE") < md.index("SAFE**")


def test_pipe_escaped_in_reason():
    md = table([_r("x", "SAFE")], "PASS", "full")
    assert "r \\| with pipe" in md


def test_pass_render_empty():
    md = table([], "PASS", "diff")
    assert "✅" in md and MARKER in md

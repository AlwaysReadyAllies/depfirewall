"""GitHub plumbing: event payload, REST calls, comment upsert, outputs, step summary.

Stdlib urllib only. Comment posting NEVER crashes the run — fork PRs get a read-only
token (403); we warn and rely on the step summary + exit code instead.
"""
import json
import os
import urllib.error
import urllib.request

API = "https://api.github.com"


def load_event():
    path = os.environ.get("GITHUB_EVENT_PATH")
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def pr_number(event):
    return (event.get("pull_request") or {}).get("number")


def api(path, token, method="GET", body=None):
    req = urllib.request.Request(
        f"{API}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "depfirewall",
        })
    with urllib.request.urlopen(req, timeout=20) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def repo_is_private(repo, token):
    """True/False, or None if undeterminable (no token / API error) — caller fails open."""
    try:
        return bool(api(f"/repos/{repo}", token).get("private"))
    except Exception:
        return None


def upsert_comment(repo, pr, body, token, marker):
    """Update our existing verdict comment in place, else create one. Returns status string."""
    try:
        comments = api(f"/repos/{repo}/issues/{pr}/comments?per_page=100", token)
        mine = next((c for c in comments if marker in (c.get("body") or "")), None)
        if mine:
            api(f"/repos/{repo}/issues/comments/{mine['id']}", token, "PATCH", {"body": body})
            return "updated"
        api(f"/repos/{repo}/issues/{pr}/comments", token, "POST", {"body": body})
        return "created"
    except urllib.error.HTTPError as e:
        return f"skipped (http {e.code} — fork PR tokens are read-only; see step summary)"
    except Exception as e:
        return f"skipped ({str(e)[:60]})"


def write_output(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as f:
            f.write(f"{name}={value}\n")


def append_summary(md):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(md + "\n")

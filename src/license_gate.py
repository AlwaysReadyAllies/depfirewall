"""Freemium gate: free on public repos, license required on private repos.

Key verification hits a Cloudflare Worker (/verify?key=K&repo=owner/name) which binds
the key to the repo on first use. FAIL-OPEN on verifier outage — an infra blip must
never block a paying customer. DEPFIREWALL_SKIP_LICENSE=1 is the dev escape hatch.
"""
import json
import os
import urllib.parse
import urllib.request

PURCHASE_URL = "https://alwaysreadyallies.com/depfirewall#pricing"

PURCHASE_NOTE = (
    "🔒 **This is a private repository.** depfirewall is free for public repos; "
    f"private repos need a license key — [get one here]({PURCHASE_URL}), then add it as "
    "the `DEPFIREWALL_KEY` secret and pass `license-key: ${{ secrets.DEPFIREWALL_KEY }}`."
)


def verify_key(key, repo, verify_url):
    """Returns (valid: bool|None, detail). None = verifier unreachable → fail open."""
    if not key:
        return False, "no license key provided"
    q = urllib.parse.urlencode({"key": key, "repo": repo})
    try:
        with urllib.request.urlopen(f"{verify_url}?{q}", timeout=10) as r:
            data = json.loads(r.read())
        return bool(data.get("valid")), data.get("reason", "")
    except Exception as e:
        return None, f"verifier unreachable ({str(e)[:60]})"


def gate(repo, license_key, verify_url, is_private):
    """Returns (allowed: bool, message: str)."""
    if os.environ.get("DEPFIREWALL_SKIP_LICENSE") == "1":
        return True, "license check skipped (DEPFIREWALL_SKIP_LICENSE=1)"
    if is_private is False:
        return True, "public repo — free tier"
    if is_private is None:
        return True, "repo visibility undeterminable — failing open"
    valid, detail = verify_key(license_key, repo, verify_url)
    if valid:
        return True, "license valid"
    if valid is None:
        return True, f"license {detail} — failing open"
    return False, f"private repo requires a license ({detail}). {PURCHASE_URL}"

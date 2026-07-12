"""Dependency verdict engine — deps.dev v3 (primary) + native registries (404 confirmation).

Vendored and hardened from dojo/depscheck.py. Stdlib only.

Verdicts:
  VULNERABLE  — has security advisories (severity = max CVSS across deduped CVEs)
  UNKNOWN     — not on deps.dev AND not on the native registry → hallucinated / slopsquat
  NEW         — not on deps.dev yet but IS on the native registry (indexing lag) → warn
  DEPRECATED  — registry marks it deprecated
  STALE       — newest release older than ~2 years
  SAFE        — none of the above
"""
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://api.deps.dev/v3"
STALE_DAYS = 730
USER_AGENT = "depfirewall/1.0 (+https://github.com/alwaysreadyallies/depfirewall)"

# Native-registry existence endpoints: 200 = the package exists even if deps.dev lags.
REGISTRY_URLS = {
    "pypi": "https://pypi.org/pypi/{name}/json",
    "npm": "https://registry.npmjs.org/{name}",
    "cargo": "https://crates.io/api/v1/crates/{name}",
    "go": "https://proxy.golang.org/{name}/@latest",
}


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read()), None
    except urllib.error.HTTPError as e:
        return None, f"http {e.code}"
    except Exception as e:
        return None, str(e)[:80]


def _age_days(iso):
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def registry_exists(system, name):
    """Confirm existence against the native registry. Returns True/False/None (couldn't check)."""
    tmpl = REGISTRY_URLS.get(system)
    if not tmpl:
        return None
    path = name.lower() if system == "go" else urllib.parse.quote(name, safe="")
    _, err = _get(tmpl.format(name=path))
    if err is None:
        return True
    if err == "http 404":
        return False
    return None  # registry hiccup — inconclusive


def check_one(system, name, version=None):
    system = system.lower()
    out = {
        "system": system, "name": name, "version": version, "verdict": "SAFE",
        "severity": None, "reason": "", "source": "deps.dev",
        "advisories": [], "license": None, "deprecated": False, "newest_age_days": None,
    }
    pkg, err = _get(f"{API}/systems/{system}/packages/{urllib.parse.quote(name, safe='')}")
    if err:
        exists = registry_exists(system, name) if err == "http 404" else None
        if exists:
            out["verdict"] = "NEW"
            out["source"] = "native-registry"
            out["reason"] = "not indexed by deps.dev yet, but exists on the native registry"
        else:
            out["verdict"] = "UNKNOWN"
            out["source"] = "registry-confirmed-404" if exists is False else "deps.dev"
            out["reason"] = (
                "package does not exist on deps.dev or the native registry — "
                "likely hallucinated or slopsquat bait" if exists is False
                else f"package not found ({err})"
            )
        return out

    versions = pkg.get("versions", [])
    newest = max((v for v in versions if v.get("publishedAt")), default=None,
                 key=lambda v: v.get("publishedAt", ""))
    out["newest_age_days"] = _age_days(newest["publishedAt"]) if newest else None
    if version is None:
        dflt = next((v for v in versions if v.get("isDefault")), newest)
        version = out["version"] = (dflt or {}).get("versionKey", {}).get("version")
    if not version:
        out["verdict"] = "UNKNOWN"
        out["reason"] = "no version resolvable"
        return out

    ver, err = _get(f"{API}/systems/{system}/packages/{urllib.parse.quote(name, safe='')}"
                    f"/versions/{urllib.parse.quote(version, safe='')}")
    if err:
        out["verdict"] = "UNKNOWN"
        out["reason"] = f"version {version} not found ({err})"
        return out

    out["license"] = ", ".join(ver.get("licenses", [])) or None
    out["deprecated"] = bool(ver.get("isDeprecated"))
    by_cve = {}  # GHSA + PYSEC often alias the SAME CVE — keep highest CVSS per CVE
    for ak in ver.get("advisoryKeys", []):
        adv, _ = _get(f"{API}/advisories/{ak['id']}")
        if not adv:
            continue
        cves = [a for a in adv.get("aliases", []) if a.startswith("CVE")]
        cve = cves[0] if cves else ak["id"]
        cand = {"id": ak["id"], "cve": cve, "cvss": adv.get("cvss3Score") or 0,
                "title": adv.get("title", "")[:100]}
        if cve not in by_cve or cand["cvss"] > by_cve[cve]["cvss"]:
            by_cve[cve] = cand
    out["advisories"] = sorted(by_cve.values(), key=lambda a: -a["cvss"])

    if out["advisories"]:
        out["verdict"] = "VULNERABLE"
        out["severity"] = max(a["cvss"] for a in out["advisories"]) or None
        top = out["advisories"][0]
        out["reason"] = f"{len(out['advisories'])} advisory(ies), worst {top['cve']} CVSS {top['cvss']}"
    elif out["deprecated"]:
        out["verdict"] = "DEPRECATED"
        out["reason"] = "registry marks this package deprecated"
    elif out["newest_age_days"] is not None and out["newest_age_days"] > STALE_DAYS:
        out["verdict"] = "STALE"
        out["reason"] = f"newest release {out['newest_age_days'] // 365}y old — likely unmaintained"
    return out


def should_fail(result, fail_on, severity_floor=0.0):
    """Gate policy. UNKNOWN and VULNERABLE fail by default; severity floor applies to
    VULNERABLE only (advisories with no CVSS score fail conservatively)."""
    verdict = result["verdict"]
    if verdict not in fail_on:
        return False
    if verdict == "VULNERABLE" and severity_floor > 0:
        sev = result.get("severity")
        return sev is None or sev >= severity_floor
    return True

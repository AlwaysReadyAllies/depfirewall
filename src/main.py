#!/usr/bin/env python3
"""depfirewall — block PRs that add hallucinated or vulnerable dependencies.

Modes:
  --check <system> <name> [version]     one-off check (CI-free local use)
  --manifest <path> [...]               scan specific manifest file(s)
  --pr                                  GitHub Action mode: diff the PR, check changed
                                        deps, write certificate, comment the verdict

Exit codes: 0 = pass, 1 = gate failed (UNKNOWN/VULNERABLE dep, or unlicensed private repo),
2 = usage error. Certificate: depfirewall-certificate.json (P-checkable JSON).
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gh
import license_gate
import render
from diff import changed_deps, fetch_base
from engine import check_one, should_fail
from parsers import MANIFEST_NAMES, discover_manifests, parse_manifest

DEFAULT_FAIL_ON = "unknown,vulnerable"
DEFAULT_VERIFY_URL = "https://depfirewall-verify.alwaysreadyallies.workers.dev/verify"


def build_certificate(results, overall, mode, repo="", pr=None, commit=""):
    return {
        "schema": 1,
        "tool": "depfirewall",
        "repo": repo,
        "pr": pr,
        "commit": commit,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "overall": overall,
        "checked": len(results),
        "results": [
            {"system": r["system"], "dep": r["name"], "version": r["version"],
             "verdict": r["verdict"], "reason": r.get("reason", ""),
             "severity": r.get("severity"), "source": r.get("source", "deps.dev"),
             "advisories": r.get("advisories", [])}
            for r in results
        ],
    }


def print_human(results, overall):
    icon = render.ICON
    print(f"\n  depfirewall — {len(results)} package(s)\n")
    for r in results:
        print(f"  {icon.get(r['verdict'], '?')} {r['verdict']:<11} {r['name']}@{r['version'] or 'latest'}"
              f"  {r.get('reason', '')}")
        for adv in r.get("advisories", []):
            print(f"        ↳ {adv['cve']}  CVSS {adv['cvss']}  {adv['title']}")
    print(f"\n  overall: {overall}\n")


def run_pr_mode(args, fail_on, floor):
    workspace = os.environ.get("GITHUB_WORKSPACE", ".")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    base_ref = os.environ.get("GITHUB_BASE_REF", "")
    commit = os.environ.get("GITHUB_SHA", "")
    event = gh.load_event()
    pr = gh.pr_number(event)

    # ---- freemium gate --------------------------------------------------
    is_private = event.get("repository", {}).get("private")
    if is_private is None:
        is_private = gh.repo_is_private(repo, token) if token else None
    allowed, lic_msg = license_gate.gate(repo, args.license_key, args.verify_url, is_private)
    print(f"license: {lic_msg}")
    if not allowed:
        gh.write_output("verdict", "BLOCKED")
        gh.append_summary(f"## 🔒 depfirewall — license required\n\n{license_gate.PURCHASE_NOTE}")
        if pr and token and not args.dry_run:
            gh.upsert_comment(repo, pr, render.MARKER + "\n" + license_gate.PURCHASE_NOTE,
                              token, render.MARKER)
        return 1

    # ---- what changed ----------------------------------------------------
    manifests = args.manifest or discover_manifests(workspace)
    rel = [os.path.relpath(m, workspace) for m in manifests]
    base_rev = fetch_base(workspace, base_ref)
    targets, mode = changed_deps(workspace, rel, base_rev)
    print(f"mode: {mode} ({len(targets)} dep(s) to check across {len(rel)} manifest(s))")

    # ---- check ------------------------------------------------------------
    results = [check_one(*t) for t in targets]
    failures = [r for r in results if should_fail(r, fail_on, floor)]
    overall = "FAIL" if failures else "PASS"

    # ---- certificate + outputs --------------------------------------------
    cert = build_certificate(results, overall, mode, repo, pr, commit)
    cert_path = os.path.join(workspace, "depfirewall-certificate.json")
    with open(cert_path, "w") as f:
        json.dump(cert, f, indent=2)
    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    gh.write_output("verdict", overall)
    gh.write_output("counts", json.dumps(counts))
    gh.write_output("certificate-path", cert_path)

    md = render.table(results, overall, mode)
    gh.append_summary(md)
    print_human(results, overall)

    if pr and token and args.comment:
        if args.dry_run:
            print(f"[dry-run] would upsert comment on {repo}#{pr} ({len(md)} chars)")
        else:
            status = gh.upsert_comment(repo, pr, md, token, render.MARKER)
            print(f"comment: {status}")

    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", nargs="+", metavar="ARG",
                    help="system name [version] — one-off check")
    ap.add_argument("--manifest", action="append", help="manifest path (repeatable)")
    ap.add_argument("--pr", action="store_true", help="GitHub Action mode")
    ap.add_argument("--fail-on", default=DEFAULT_FAIL_ON)
    ap.add_argument("--severity-floor", type=float, default=0.0)
    ap.add_argument("--license-key", default=os.environ.get("DEPFIREWALL_KEY", ""))
    ap.add_argument("--verify-url", default=DEFAULT_VERIFY_URL)
    ap.add_argument("--comment", default=True,
                    type=lambda s: str(s).lower() not in ("false", "0", "no"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    fail_on = {v.strip().upper() for v in args.fail_on.split(",") if v.strip()}
    floor = args.severity_floor

    if args.pr:
        return run_pr_mode(args, fail_on, floor)

    if args.check:
        if len(args.check) < 2:
            ap.error("--check needs: system name [version]")
        targets = [(args.check[0], args.check[1],
                    args.check[2] if len(args.check) > 2 else None)]
    elif args.manifest:
        targets = []
        for m in args.manifest:
            targets.extend(parse_manifest(m))
    else:
        ap.error(f"give --check, --manifest, or --pr (manifests: {', '.join(MANIFEST_NAMES)})")
        return 2

    results = [check_one(*t) for t in targets]
    failures = [r for r in results if should_fail(r, fail_on, floor)]
    overall = "FAIL" if failures else "PASS"
    if args.json:
        print(json.dumps(build_certificate(results, overall, "manual"), indent=2))
    else:
        print_human(results, overall)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

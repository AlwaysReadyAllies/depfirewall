# 🛡️ depfirewall — the dependency check that lives in your PR

[![CI](https://github.com/AlwaysReadyAllies/depfirewall/actions/workflows/ci.yml/badge.svg)](https://github.com/AlwaysReadyAllies/depfirewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-f0a028.svg)](LICENSE)
[![Free for public repos](https://img.shields.io/badge/public%20repos-free-5bb87a.svg)](#pricing)

A **GitHub Action**, not a platform. One workflow file, no account, no config, no code leaves
GitHub — it fails a pull request that adds a dependency **that doesn't exist on any registry**
(an AI hallucination, or the slopsquat package an attacker pre-registered on that name) or one
with **known CVEs**. **Free for public repos**, [$19/repo/month](#pricing) for private.

AI writes code that imports packages that don't exist; attackers register those names and wait.
Studies put LLM package-hallucination at [~5–20% of dependency suggestions](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen),
and dozens of the exact names every model invents are [still registrable today](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks).
`npm audit` and Dependabot can't help — they only scan packages that *exist*.

depfirewall checks every dependency a PR **adds or changes**:

| Verdict | Meaning | Default |
|---|---|---|
| ⛔ `UNKNOWN` | Package doesn't exist on deps.dev **or** its native registry — hallucinated / slopsquat bait | **fails the PR** |
| 🔴 `VULNERABLE` | Known CVEs (deps.dev / OSV data, deduped, max-CVSS scored) | **fails the PR** |
| 🆕 `NEW` | On the registry but not yet indexed by deps.dev | warns |
| 🟠 `DEPRECATED` / 🟡 `STALE` | Registry-deprecated / no release in 2+ years | warns |
| 🟢 `SAFE` | None of the above | passes |

Every run emits a **P-checkable JSON certificate** (`depfirewall-certificate.json`) —
the audit trail that proves your AI-written code was verified before merge.

## Install (30 seconds)

```yaml
# .github/workflows/depfirewall.yml
name: depfirewall
on: [pull_request]

permissions:
  contents: read
  pull-requests: write   # for the verdict comment

jobs:
  depfirewall:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: alwaysreadyallies/depfirewall@v1
```

That's it. No config, no API keys, no runtime dependencies (stdlib Python on the runner),
no code leaves GitHub — the Action only queries public registry metadata.

**Free for public repos.** Private repos need a [license key](https://buy.stripe.com/eVq14nd469kSbJ9fda8IU00) ($19/repo/month):

```yaml
      - uses: alwaysreadyallies/depfirewall@v1
        with:
          license-key: ${{ secrets.DEPFIREWALL_KEY }}
```

## Inputs

| Input | Default | What it does |
|---|---|---|
| `fail-on` | `unknown,vulnerable` | Verdicts that fail the check (`unknown,vulnerable,deprecated,stale`) |
| `severity-floor` | `0` | Min CVSS for VULNERABLE to fail (`7.0` = high/critical only; `0` = any advisory) |
| `manifests` | auto-discover | Explicit manifest paths (space-separated) |
| `comment` | `true` | Post/update the PR verdict comment |
| `license-key` | — | Required for private repos |

**Outputs:** `verdict` (`PASS`/`FAIL`/`BLOCKED`), `counts` (JSON), `certificate-path`.

**Manifests:** `requirements.txt`, `pyproject.toml` (PEP 621), `package.json`.
go.mod / Cargo.toml next. On PRs only *added or version-changed* deps are checked
(dep-set diff against the base branch); other events get a full scan.

## Local / pre-commit use

```bash
python3 src/main.py --check pypi some-package        # one dep
python3 src/main.py --manifest requirements.txt      # a manifest
python3 src/main.py --manifest requirements.txt --json  # certificate to stdout
```

## How it works

1. Diff the manifest dep-sets between the PR base and head — only what changed gets checked.
2. Ask [deps.dev](https://deps.dev) (Google Open Source Insights): does it exist? advisories? deprecated? stale?
3. On a 404, **confirm against the native registry** (PyPI/npm/crates.io/Go proxy) so a
   brand-new legit package is never falsely flagged — only a package that exists *nowhere* fails.
4. Post one verdict comment (updated in place on every push) + the JSON certificate.

Data sources are free and public; the check is pure metadata — your code is never uploaded.

## Why "UNKNOWN" matters

Studies show LLMs hallucinate package names in ~5–20% of generated dependency suggestions,
and those names are systematically pre-registered by attackers. A dependency that exists
nowhere is either a typo or a trap — either way it must not merge. That's the wedge no
linter and no `npm audit` covers: **they can only scan what exists.**

## Pricing

| | Public repos | Private repos |
|---|---|---|
| **Price** | **Free, forever** | **$19 / repo / month** |
| Full gate (UNKNOWN + CVE) | ✓ | ✓ |
| PR verdict comment + certificate | ✓ | ✓ |
| Severity floor & fail-on policy | ✓ | ✓ |

Priced **per repository**, not per developer — a small team pays for the repos it protects, not
every seat. [Get a private-repo license →](https://buy.stripe.com/eVq14nd469kSbJ9fda8IU00)

## Data handling & trust

- **Your code never leaves GitHub.** The Action runs on your own runner and makes outbound calls
  *only* to public package registries (deps.dev, PyPI, npm) with dependency **names** — never your
  source. No telemetry, nothing stored.
- **Advisory by default.** depfirewall reports a verdict and a check status; you decide whether a
  failing check blocks the merge (branch protection is yours to set). It is a decision-support tool,
  provided without warranty — not a guarantee of security.
- **Auditable.** The whole engine is stdlib Python, MIT-licensed, ~600 lines. Read every line.

---

MIT-licensed engine. Built by [Always Ready Allies](https://alwaysreadyallies.com) —
verification infrastructure for AI-written code.

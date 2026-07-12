# Show HN draft

**Title:** Show HN: A GitHub Action that fails PRs adding dependencies that don't exist

**Body:**

AI assistants hallucinate package names — studies put it between 5% and 20% of dependency
suggestions, worse for less-common ecosystems. Attackers noticed years ago and pre-register
the hallucinated names ("slopsquatting"). If your team merges AI-written code, at some point
a PR will add a dependency that was invented by a model, and there's a real chance someone
registered that name with a payload before you got there.

Nothing in the standard toolchain catches this. `npm audit`, Dependabot, Snyk — they scan
packages that *exist* for *known* vulnerabilities. A package that exists nowhere, or that was
registered last week to catch a hallucination, sails through.

So I built depfirewall: a GitHub Action that diffs the dependency set of every PR and checks
each **added or changed** dep:

- **UNKNOWN** — doesn't exist on deps.dev *or* the native registry (PyPI/npm/crates/Go proxy)
  → hallucinated or slopsquat bait → **PR fails**
- **VULNERABLE** — known CVEs (deps.dev/OSV, deduped, CVSS-scored, configurable severity floor)
  → **PR fails**
- NEW / DEPRECATED / STALE → warns

Design choices I care about:

- **Zero infrastructure to adopt**: composite action, stdlib Python only, runs on the GitHub
  runner. Your code never leaves GitHub — it's pure registry-metadata lookups.
- **False positives are treated as fatal**: a deps.dev 404 is confirmed against the native
  registry before failing, so a brand-new legit package gets a NEW warning, not a block.
- **Only what changed**: dep-set diff between base and head, so a 400-line requirements.txt
  doesn't get re-litigated on every PR.
- **Auditable output**: every run writes a JSON certificate (dep, verdict, reason, severity,
  source) — if you need to prove your AI-generated code was verified before merge, that's
  the artifact.

Free on public repos. Private repos are paid (that's the business).

Install is one workflow file: https://github.com/alwaysreadyallies/depfirewall

Would love feedback — especially on ecosystems to prioritize next (go.mod and Cargo.toml
are close) and what else belongs in the gate between AI code generation and merge.

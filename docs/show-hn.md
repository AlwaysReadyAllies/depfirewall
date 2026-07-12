# Show HN — post copy (ready to submit)

Post as a **Show HN** with the URL pointing at the GitHub repo. Best days: Tue–Thu, ~8–10am ET.
Have the demo repo (3 open PRs) and the landing page open to link in the first comment.

---

**Title:**
Show HN: A GitHub Action that fails PRs adding dependencies that don't exist

**URL:** https://github.com/AlwaysReadyAllies/depfirewall

**First comment (post immediately after submitting):**

I kept watching AI coding assistants suggest imports for packages that don't exist. That's a known
thing now — a USENIX Security 2025 study measured ~20% hallucinated package names on 2024-era models,
and it's still 5–6% on current frontier models. The nasty part is that attackers pre-register the
names models invent ("slopsquatting"), and researchers found dozens of the exact names *every* major
model hallucinates are still registrable on PyPI/npm today. A benign proof-of-concept fake
`huggingface-cli` pulled 30k+ real installs.

Nothing in the normal toolchain catches this. `npm audit`, Dependabot, and every SCA scanner check
packages that *exist* for *known* CVEs. A package that exists nowhere — or was registered last week to
catch a hallucination — sails straight through.

depfirewall is a GitHub Action that diffs the dependencies a PR adds or changes and, for each one,
asks: does this exist on deps.dev *and* its native registry? If it exists nowhere, the check fails
(UNKNOWN). If it has known CVEs, the check fails (VULNERABLE). It posts one verdict comment on the PR
and writes a JSON certificate.

Design decisions I'd want feedback on:

- **Zero infrastructure.** Composite Action, stdlib Python on the runner, ~600 lines, MIT. Your code
  never leaves GitHub — it only sends dependency *names* to public registries.
- **False positives treated as fatal.** A brand-new legit package would be a deps.dev 404, so before
  failing I confirm against the native registry (PyPI/npm/crates/Go proxy). Only a package that exists
  on *nothing* fails; a new-but-real one gets a "NEW" warning, not a block.
- **Advisory by default.** It reports a check status; you decide via branch protection whether it
  blocks. I didn't want to be a tool that silently hard-blocks merges.
- **Only what changed.** Dep-set diff against the base branch, so a 400-line lockfile isn't
  re-litigated on every PR.

It's free for public repos (that's the point — adoption), paid for private. I'm a solo founder; the
engine is fully open so you can audit it or run it as a pre-commit hook without me.

Live demo repo with three open PRs (clean / hallucinated / CVE) so you can see the checks pass and
fail: https://github.com/AlwaysReadyAllies/depfirewall-demo

What I'd genuinely like to know: which ecosystems to prioritize next (go.mod and Cargo.toml are
close), and — for anyone who's shipped dev-security tools — where the trust bar actually sits for a
tool that touches your CI.

---

## Notes for the poster (not part of the comment)

- **Don't over-claim.** We are *not* the only slopsquat defense — Socket ($1B) markets it too. Our
  honest edges are: free + zero-config + in-the-PR + per-repo pricing + fully open/auditable. Lead
  with those, not "we invented this."
- **If asked "how is this different from Socket/Snyk?":** "Those are platforms you adopt and pay
  per-seat; this is one workflow file, free on public repos, priced per-repo, and the whole engine is
  600 lines of MIT Python you can read. Different tool for a different size of team."
- **If asked about false positives / accuracy:** point at the registry-confirmation design and the
  NEW verdict; don't quote a number we can't reproduce.
- Reply to every comment in the first 3 hours. Fix any real bug reported, live.

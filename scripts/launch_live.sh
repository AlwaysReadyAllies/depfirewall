#!/usr/bin/env bash
# depfirewall live launch — run AFTER `gh auth login` (echooftheveil) and the
# `alwaysreadyallies` org exists. Creates the public repos, pushes, tags v1,
# and opens the three proof PRs (clean / hallucinated / CVE).
#
#   ./scripts/launch_live.sh            # full launch
#   ORG=someorg ./scripts/launch_live.sh
set -euo pipefail

ORG="${ORG:-alwaysreadyallies}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
FAKE_DEP="depfw-hallucinated-$(openssl rand -hex 6)"

echo "== preflight =="
gh auth status
gh api "orgs/$ORG" -q .login || { echo "org $ORG not found — create it in the web UI first"; exit 1; }

echo "== 1/4 push the action repo =="
cd "$HERE"
git remote get-url origin 2>/dev/null || git remote add origin "https://github.com/$ORG/depfirewall.git"
gh repo view "$ORG/depfirewall" >/dev/null 2>&1 || gh repo create "$ORG/depfirewall" --public \
  --description "Block PRs that add hallucinated or vulnerable dependencies — the firewall for AI-written code" \
  --homepage "https://alwaysreadyallies.com/depfirewall"
git push -u origin main
git tag -f v1 && git tag -f v1.0.0 && git push -f origin v1 v1.0.0

echo "== 2/4 create the demo repo =="
DEMO=/tmp/depfirewall-demo-$$
mkdir -p "$DEMO" && cd "$DEMO"
git init -qb main
cat > requirements.txt <<'EOF'
flask
numpy
EOF
mkdir -p .github/workflows
cat > .github/workflows/depfirewall.yml <<EOF
name: depfirewall
on: [pull_request]
permissions: { contents: read, pull-requests: write }
jobs:
  depfirewall:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: $ORG/depfirewall@v1
EOF
cat > README.md <<EOF
# depfirewall-demo
Live proof PRs for [depfirewall]($ORG/depfirewall): clean / hallucinated / CVE.
EOF
git add -A && git commit -qm "base: clean manifest + depfirewall workflow"
gh repo view "$ORG/depfirewall-demo" >/dev/null 2>&1 || gh repo create "$ORG/depfirewall-demo" --public \
  --description "Live demo: watch depfirewall block hallucinated and vulnerable dependencies"
git remote add origin "https://github.com/$ORG/depfirewall-demo.git" 2>/dev/null || true
git push -u origin main

echo "== 3/4 open the three proof PRs =="
git checkout -qb pr-clean
printf 'flask\nnumpy\nhttpx\n' > requirements.txt
git commit -qam "add httpx (clean dep — should PASS)"
git push -qu origin pr-clean
gh pr create --title "clean: add httpx" --body "Expected: ✅ PASS" --head pr-clean

git checkout -q main && git checkout -qb pr-hallucinated
printf 'flask\nnumpy\n%s==1.0\n' "$FAKE_DEP" > requirements.txt
git commit -qam "add $FAKE_DEP (hallucinated — should FAIL)"
git push -qu origin pr-hallucinated
gh pr create --title "hallucinated: add $FAKE_DEP" --body "Expected: ⛔ FAIL (UNKNOWN — exists on no registry)" --head pr-hallucinated

git checkout -q main && git checkout -qb pr-cve
printf 'flask\nnumpy\nrequests==2.5.0\n' > requirements.txt
git commit -qam "pin requests==2.5.0 (known CVEs — should FAIL)"
git push -qu origin pr-cve
gh pr create --title "cve: pin requests==2.5.0" --body "Expected: 🔴 FAIL (VULNERABLE — CVE-2018-18074 et al.)" --head pr-cve

echo "== 4/4 watch the checks =="
echo "PRs opened. Watch: gh pr checks 1 --repo $ORG/depfirewall-demo --watch (and 2, 3)"
echo "DONE-checklist verify: PR1 green, PR2+PR3 red, verdict comments present."

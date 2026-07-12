"""PR dep-set diff: which deps were ADDED or VERSION-CHANGED between base and head.

Strategy: parse the manifest at head (worktree) and at base (git show), diff the
(system, name, version) sets. Exact semantics, immune to reformatting — no hunk parsing.

Base resolution: `git fetch --no-tags --depth=1 origin <base_ref>` → FETCH_HEAD, so
consumers only need default actions/checkout@v4 (fetch-depth 1). Any failure falls back
to full-manifest scan (scan everything = strictly safer than scanning nothing).
"""
import subprocess
import tempfile

from parsers import parse_manifest, parse_manifest_text


def _git(repo_dir, *args):
    r = subprocess.run(["git", "-C", repo_dir, *args],
                       capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout


def fetch_base(repo_dir, base_ref):
    """Fetch the PR base ref; returns the git rev to read base manifests from, or None."""
    if not base_ref:
        return None
    code, _ = _git(repo_dir, "fetch", "--no-tags", "--depth=1", "origin", base_ref)
    return "FETCH_HEAD" if code == 0 else None


def base_manifest_text(repo_dir, base_rev, rel_path):
    """Manifest content at base, or None if it didn't exist there (new file → all deps added)."""
    code, out = _git(repo_dir, "show", f"{base_rev}:{rel_path}")
    return out if code == 0 else None


def changed_deps(repo_dir, manifest_relpaths, base_rev):
    """Returns (targets, mode): targets = deps to check, mode = 'diff' or 'full'.

    A dep is checked when (name) is new at head, or its pinned version changed.
    base_rev=None → full scan of every manifest.
    """
    targets, seen = [], set()

    def add(t):
        if (t[0], t[1], t[2]) not in seen:
            seen.add((t[0], t[1], t[2]))
            targets.append(t)

    if base_rev is None:
        for rel in manifest_relpaths:
            for t in parse_manifest(f"{repo_dir}/{rel}"):
                add(t)
        return targets, "full"

    with tempfile.TemporaryDirectory() as tmp:
        for rel in manifest_relpaths:
            head = parse_manifest(f"{repo_dir}/{rel}")
            base_text = base_manifest_text(repo_dir, base_rev, rel)
            if base_text is None:
                base = []
            else:
                try:
                    base = parse_manifest_text(rel, base_text, tmp)
                except Exception:
                    base = []  # unparseable base → treat all head deps as added
            base_names = {(s, n): v for s, n, v in base}
            for s, n, v in head:
                if (s, n) not in base_names or base_names[(s, n)] != v:
                    add((s, n, v))
    return targets, "diff"

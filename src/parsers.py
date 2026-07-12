"""Manifest parsers → list of (system, name, version) tuples. Stdlib only.

Supported: requirements.txt, package.json, pyproject.toml (PEP 621).
version is the pinned version if exactly pinned, else None (engine checks default/latest).
"""
import json
import re
import tomllib
from pathlib import Path

MANIFEST_NAMES = ("requirements.txt", "package.json", "pyproject.toml")

# PEP 503 normalized name + optional extras + exact pin
_REQ_RE = re.compile(r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(?:==\s*([A-Za-z0-9.+_!-]+))?")


def parse_requirements(path):
    reqs = []
    for ln in Path(path).read_text().splitlines():
        ln = ln.split("#", 1)[0].strip()
        if not ln or ln.startswith(("-", "http://", "https://", "git+", ".", "/")):
            continue
        m = _REQ_RE.match(ln)
        if m:
            reqs.append(("pypi", m.group(1), m.group(2)))
    return reqs


def parse_package_json(path):
    d = json.loads(Path(path).read_text())
    reqs = []
    for sec in ("dependencies", "devDependencies"):
        for name, spec in (d.get(sec) or {}).items():
            spec = str(spec)
            if spec.startswith(("file:", "link:", "git", "http", "workspace:")):
                reqs.append(("npm", name, None))
                continue
            v = re.sub(r"^[\^~>=<\s]*", "", spec).split(" ")[0] or None
            reqs.append(("npm", name, v if re.match(r"^\d+\.\d+\.\d+$", v or "") else None))
    return reqs


def _pep508_name_version(spec):
    """'requests[socks]>=2.0; python_version<"3.9"' → ('requests', None); 'a==1.2' → ('a','1.2')."""
    spec = spec.split(";", 1)[0].strip()
    m = re.match(r"^([A-Za-z0-9._-]+)", spec)
    if not m:
        return None
    name = m.group(1)
    pin = re.search(r"==\s*([A-Za-z0-9.+_!-]+)", spec)
    return (name, pin.group(1) if pin else None)


def parse_pyproject(path):
    data = tomllib.loads(Path(path).read_text())
    reqs = []
    project = data.get("project", {})
    specs = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        specs.extend(group)
    # poetry-style tables are v1.1; PEP 621 covers the modern ecosystem
    for spec in specs:
        nv = _pep508_name_version(str(spec))
        if nv:
            reqs.append(("pypi", nv[0], nv[1]))
    return reqs


_PARSERS = {
    "requirements.txt": parse_requirements,
    "package.json": parse_package_json,
    "pyproject.toml": parse_pyproject,
}


def parse_manifest(path):
    """Dispatch on basename. Returns [] for unrecognized files."""
    fn = _PARSERS.get(Path(path).name)
    return fn(path) if fn else []


def parse_manifest_text(name, text, tmpdir):
    """Parse manifest CONTENT (e.g. from `git show base:path`) by writing to a temp file."""
    p = Path(tmpdir) / Path(name).name
    p.write_text(text)
    return parse_manifest(p)


def discover_manifests(root="."):
    """Find supported manifests under root, skipping vendored/venv trees."""
    skip = {"node_modules", ".git", "venv", ".venv", "vendor", "dist", "build", "__pycache__"}
    found = []
    for p in Path(root).rglob("*"):
        if p.name in MANIFEST_NAMES and not (set(p.parts) & skip):
            found.append(str(p))
    return sorted(found)

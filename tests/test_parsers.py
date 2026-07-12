import parsers


def test_requirements_edge_cases(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text(
        "# comment\n"
        "requests==2.31.0\n"
        "flask  # inline comment\n"
        "celery[redis]==5.3.0\n"
        "-r other.txt\n"
        "--index-url https://x\n"
        "git+https://github.com/x/y.git\n"
        "numpy>=1.20\n"
        "\n"
    )
    got = parsers.parse_requirements(p)
    assert ("pypi", "requests", "2.31.0") in got
    assert ("pypi", "flask", None) in got
    assert ("pypi", "celery", "5.3.0") in got  # extras stripped
    assert ("pypi", "numpy", None) in got  # >= is not a pin
    names = [n for _, n, _ in got]
    assert "git+https" not in " ".join(names)
    assert len(got) == 4


def test_package_json(tmp_path):
    p = tmp_path / "package.json"
    p.write_text('''{
      "dependencies": {"lodash": "^4.17.4", "left-pad": "1.3.0",
                       "local": "file:../local", "repo": "git+https://x/y.git"},
      "devDependencies": {"jest": "~29.0.0"}
    }''')
    got = dict(((s, n), v) for s, n, v in parsers.parse_package_json(p))
    assert got[("npm", "lodash")] is None  # range, not a pin
    assert got[("npm", "left-pad")] == "1.3.0"
    assert got[("npm", "local")] is None
    assert got[("npm", "repo")] is None
    assert got[("npm", "jest")] is None


def test_pyproject_pep621(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text('''
[project]
name = "x"
version = "0"
dependencies = [
  "requests[socks]>=2.0; python_version < '3.13'",
  "pandas==2.2.0",
]
[project.optional-dependencies]
dev = ["pytest==8.0.0", "ruff"]
''')
    got = parsers.parse_pyproject(p)
    assert ("pypi", "requests", None) in got  # marker + extras stripped, >= not a pin
    assert ("pypi", "pandas", "2.2.0") in got
    assert ("pypi", "pytest", "8.0.0") in got
    assert ("pypi", "ruff", None) in got


def test_dispatch_and_discover(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.json").write_text("{}")
    sub = tmp_path / "app"
    sub.mkdir()
    (sub / "pyproject.toml").write_text('[project]\nname="a"\nversion="0"\ndependencies=[]\n')
    found = parsers.discover_manifests(tmp_path)
    assert any(f.endswith("requirements.txt") for f in found)
    assert any(f.endswith("app/pyproject.toml") for f in found)
    assert not any("node_modules" in f for f in found)
    assert parsers.parse_manifest(tmp_path / "requirements.txt") == [("pypi", "flask", None)]
    assert parsers.parse_manifest(tmp_path / "unknown.cfg") == []

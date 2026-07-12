import subprocess

from diff import changed_deps


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def make_repo(tmp_path):
    _git(tmp_path, "init", "-qb", "main")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")
    (tmp_path / "requirements.txt").write_text(
        "requests==2.32.0\nflask\ntotally-fake-dep==1.0\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "head")
    return tmp_path


def test_diff_mode_only_added_and_changed(tmp_path):
    repo = make_repo(tmp_path)
    targets, mode = changed_deps(str(repo), ["requirements.txt"], "HEAD~1")
    assert mode == "diff"
    assert ("pypi", "totally-fake-dep", "1.0") in targets
    assert ("pypi", "requests", "2.32.0") in targets  # version bump
    assert not any(n == "flask" for _, n, _ in targets)  # unchanged skipped


def test_full_mode_when_no_base(tmp_path):
    repo = make_repo(tmp_path)
    targets, mode = changed_deps(str(repo), ["requirements.txt"], None)
    assert mode == "full"
    assert len(targets) == 3  # everything scanned


def test_new_manifest_all_added(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "package.json").write_text('{"dependencies": {"left-pad": "1.3.0"}}')
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add npm manifest")
    targets, mode = changed_deps(str(repo), ["package.json"], "HEAD~1")
    assert mode == "diff"
    assert ("npm", "left-pad", "1.3.0") in targets

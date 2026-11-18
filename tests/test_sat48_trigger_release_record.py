"""SAT-48: `dirty` = tracked changes only, and the build identity's token carries no quota project.

- `scripts/common/release_record.py stamp`: `dirty` is true only when a TRACKED file differs from HEAD (untracked
  files, such as an operator's local tool notes, never make a build dirty: a dev install showed every component dirty).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys

import hcl2
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
G = "gi" + "t"
SHA = "c" * 40
MODULE = os.path.join(REPO, "infra", "modules", "cloud_build", "main.tf")
SCRIPT = os.path.join(REPO, "scripts", "common", "trigger_release.sh")


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rr = _load("sat48_release_record", "scripts/common/release_record.py")
ri = _load("sat48_release_info", "apps/control-center/release_info.py")


def _git_env(home):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.path.join(home, "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1", "HOME": home,
                "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.com"})
    return env


def _git(repo, *args, env=None):
    return subprocess.run([G, "-C", repo, "-c", "commit.gpgsign=false", *args],
                          capture_output=True, text=True, check=True, env=env)


@pytest.fixture
def checkout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    env = _git_env(str(home))
    repo = tmp_path / "repo"
    (repo / "apps" / "x").mkdir(parents=True)
    (repo / "VERSION").write_text("0.9.2\n")
    (repo / "apps" / "x" / "main.py").write_text("print(1)\n")
    _git(str(repo), "init", "-q", env=env)
    _git(str(repo), "add", "-A", env=env)
    _git(str(repo), "commit", "-q", "-m", "init", env=env)
    for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "HOME"):
        monkeypatch.setenv(k, env[k])
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    return repo, env


# ================================================================================================ dirty = tracked only
def test_untracked_files_only_is_not_dirty(checkout):
    repo, _ = checkout
    (repo / ".tool-notes").mkdir()
    (repo / ".tool-notes" / "notes.md").write_text("operator notes\n")
    (repo / "scratch.txt").write_text("x\n")
    assert rr.tracked_changes(str(repo)) is False
    assert rr.make_release_document(str(repo), env={})["dirty"] is False


@pytest.mark.parametrize("change", ["modify", "delete", "stage_new"])
def test_tracked_changes_are_dirty(checkout, change):
    repo, env = checkout
    if change == "modify":
        (repo / "apps" / "x" / "main.py").write_text("print(2)\n")
    elif change == "delete":
        (repo / "apps" / "x" / "main.py").unlink()
    else:
        (repo / "new.py").write_text("x = 1\n")
        _git(str(repo), "add", "new.py", env=env)  # staged: now tracked, so it is a change to the commit
    assert rr.tracked_changes(str(repo)) is True
    assert rr.make_release_document(str(repo), env={})["dirty"] is True


def test_not_a_checkout_is_still_never_claimed_clean(tmp_path, monkeypatch):
    """Do No Harm: the non-trigger rule for an unreadable tree is unchanged (commit unknown, dirty true)."""
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    (tmp_path / "VERSION").write_text("1.0.0\n")
    doc = rr.make_release_document(str(tmp_path), env={})
    assert doc["commit"] == "unknown" and doc["dirty"] is True and doc["builder"] == "deploy-services"


def test_platform_stamp_uses_the_same_rule():
    src = open(os.path.join(REPO, "scripts", "common", "platform_target.sh"), encoding="utf-8").read()
    assert "status --porcelain --untracked-files=no" in src
    rec = open(os.path.join(REPO, "scripts", "common", "release_record.py"), encoding="utf-8").read()
    assert '"status", "--porcelain", "--untracked-files=no"' in rec
    assert '"status", "--porcelain")' not in rec


def test_builders_agree_between_writer_and_readers():
    assert rr.BUILDERS == ri.BUILDERS and "trigger" not in rr.BUILDERS
    assert rr.BUILDERS[:3] == ("deploy-services", "upgrader", "bootstrap")  # existing values unchanged


# ================================================================================================ H-1 (Python)
class _Resp:
    def __init__(self, status, body):
        self.status, self._body = status, json.dumps(body).encode() if body is not None else b""
        self.headers = {}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _capture_urlopen(monkeypatch, module):
    seen = []

    def fake(req, timeout=None):
        seen.append({k.lower(): v for k, v in req.header_items()})
        return _Resp(200, {})
    monkeypatch.setattr(module.urllib.request, "urlopen", fake)
    return seen


def test_h1_metadata_token_requests_carry_no_quota_project_header(monkeypatch, tmp_path):
    """Review H-1: the build identity (metadata token) sends no X-Goog-User-Project (that would need
    serviceusage.services.use); the operator's stdin token keeps it."""
    rel = tmp_path / "release.json"
    rel.write_text(json.dumps({"schema_version": 1, "release": "0.9.2", "commit": SHA, "dirty": False,
                               "built_at": "t", "source_repo": "acme/stackvend", "builder": "trigger"}))
    seen = []

    def fake_write(http, *a, **k):
        http("GET", "https://firestore.googleapis.com/v1/x", None)
        return []
    monkeypatch.setattr(rr, "write_record", fake_write)
    calls = _capture_urlopen(monkeypatch, rr)
    monkeypatch.setattr(rr, "metadata_token", lambda: "meta-token")
    base = ["record", "--project", "p1", "--region", "us-central1", "--release-file", str(rel)]
    assert rr.main(base + ["--token-from-metadata", "mcp-gcloud-server"]) == 0
    seen.append(calls.pop())
    assert "x-goog-user-project" not in seen[-1] and seen[-1]["authorization"] == "Bearer meta-token"
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO("user-token\n"))
    assert rr.main(base + ["--token-stdin", "mcp-gcloud-server"]) == 0
    assert calls.pop()["x-goog-user-project"] == "p1"


def test_h1_make_http_header_only_with_a_quota_project(monkeypatch):
    calls = _capture_urlopen(monkeypatch, rr)
    rr.make_http("t", "")("GET", "https://example.invalid/a")
    rr.make_http("t", "p1")("GET", "https://example.invalid/a")
    assert "x-goog-user-project" not in calls[0] and calls[1]["x-goog-user-project"] == "p1"


def test_h1_upgrader_step0_and_stages_send_no_quota_project_header(monkeypatch):
    guard = _load("sat48_guard", "scripts/upgrade/guard.py")
    stage = _load("sat48_stage", "scripts/upgrade/stage.py")
    calls = _capture_urlopen(monkeypatch, guard)
    monkeypatch.setattr(guard, "metadata_token", lambda: "meta")
    guard._http_for("p1")("GET", "https://example.invalid/a")
    assert "x-goog-user-project" not in calls[-1]
    src = open(os.path.join(REPO, "scripts", "upgrade", "stage.py"), encoding="utf-8").read()
    assert "http_factory or (lambda project: make_http(access_token()))" in src
    calls = _capture_urlopen(monkeypatch, stage)
    stage.make_http("t")("GET", "https://example.invalid/a")
    assert "x-goog-user-project" not in calls[-1]


class _RunFake:
    def __init__(self, digests):
        self.digests, self.calls = digests, []

    def __call__(self, method, url, body=None):
        self.calls.append((method, url))
        if "firestore" in url:
            return (404, None) if method == "GET" else (200, {})
        if "/services/" in url:
            return 200, {"status": {"latestReadyRevisionName": url.rsplit("/", 1)[1] + "-00001"}}
        if "/revisions/" in url:
            return 200, {"status": {"imageDigest": self.digests[url.rsplit("/", 1)[1][:-len("-00001")]]}}
        if "/jobs/" in url:
            image = self.digests[url.rsplit("/", 1)[1]]
            return 200, {"spec": {"template": {"spec": {"template": {"spec": {"containers": [{"image": image}]}}}}}}
        return 404, None


REL = {"schema_version": 1, "release": "0.9.2", "commit": SHA, "dirty": False, "built_at": "t",
       "source_repo": "acme/stackvend", "builder": "trigger"}

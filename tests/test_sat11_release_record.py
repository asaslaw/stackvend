"""SAT-11 (FD-7C P3a, SELFUP-VERSION-RECORD / SELFUP-MANIFEST): the deployed version record.

- `release_info.py` (one byte-identical copy per component) reads the build's `release.json` once, never makes a
  release up ("unknown" when absent or invalid), and every service's `/health` reports it except the Control Center's
  public one and the Serverless Git server's public, minimal one (its authenticated capabilities route carries it);
  every job logs one `stackvend.release` line at start.
- `shared/release_manifest.py`: component list = deploy-services.sh, SemVer 2.0 incl. pre-releases, the strict
  `release-manifest.json` parser + release rules, the `apply.sh` guard (SELFUP-A-STAMP: no stamp = the RC release,
  assumed), Cloud Run reads through typed fields.
- `scripts/common/release_record.py`: release.json computed before anything is written; the record merges only the
  components that deployed, keeps 20 history entries, writes with a precondition and never fails the deploy.
- `scripts/deploy-services.sh` (lane 5 harness, logging stubs, no network): release.json in every build and removed
  after; the record is written once with exactly the deployed components; without the record script, or when it
  fails, the deploy is unchanged (Do No Harm).
- `release-manifest.json` + `scripts/release/check_manifest.py` (hermetic; local git only).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import fnmatch
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
G = "gi" + "t"


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


rm = _load("sat11_release_manifest", "shared/release_manifest.py")
rr = _load("sat11_release_record", "scripts/common/release_record.py")
# scripts/release/ is private release tooling: the public export leaves it out, so its tests skip there.
CM_PATH = os.path.join(REPO, "scripts/release/check_manifest.py")
# Only the export (no docs/) may lack it; in the private repo a missing checker fails at import.
IS_EXPORT = not os.path.isdir(os.path.join(REPO, "docs"))
cm = None if (IS_EXPORT and not os.path.exists(CM_PATH)) else _load("sat11_check_manifest", "scripts/release/check_manifest.py")
needs_check_manifest = pytest.mark.skipif(cm is None, reason="scripts/release/ is not in the public export")
ri = _load("sat11_release_info", "apps/control-center/release_info.py")
lane5 = _load("sat11_lane5", "tests/test_platform_safe_apply_lane5.py")

COMPONENT_DIRS = sorted({d for _, _, d in rm.COMPONENTS})
GOOD_RELEASE = {"schema_version": 1, "release": "0.9.2", "commit": "a" * 40, "dirty": False,
                "built_at": "2026-10-30T14:02:11Z", "source_repo": "acme/stackvend", "builder": "deploy-services"}


def _git_env(home):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.path.join(home, "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1", "HOME": home,
                "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.com"})
    return env


def _git(repo, *args, env=None):
    return subprocess.run([G, "-C", repo, "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                          capture_output=True, text=True, check=True, env=env)


# ================================================================================================ release_info.py
def test_release_info_copies_are_identical():
    """One copy at the root of every component deploy-services.sh builds (each builds from its own directory)."""
    src = open(os.path.join(REPO, "apps/control-center/release_info.py"), "rb").read()
    for d in COMPONENT_DIRS:
        with open(os.path.join(REPO, d, "release_info.py"), "rb") as fh:
            assert fh.read() == src, f"{d}/release_info.py drifted from apps/control-center/release_info.py"
    assert not os.path.exists(os.path.join(REPO, "shared", "release_info.py")), "no root copy (shadow-module rule)"


def test_release_info_reads_a_valid_file(tmp_path):
    (tmp_path / "release.json").write_text(json.dumps(GOOD_RELEASE))
    assert ri.load_release(str(tmp_path)) == GOOD_RELEASE


@pytest.mark.parametrize("content", [
    "not json", "[]", json.dumps({**GOOD_RELEASE, "extra": 1}),
    json.dumps({k: v for k, v in GOOD_RELEASE.items() if k != "commit"}),
    json.dumps({**GOOD_RELEASE, "schema_version": True}), json.dumps({**GOOD_RELEASE, "schema_version": 2}),
    json.dumps({**GOOD_RELEASE, "dirty": 0}), json.dumps({**GOOD_RELEASE, "commit": "ABC"}),
    json.dumps({**GOOD_RELEASE, "builder": "laptop"}), json.dumps({**GOOD_RELEASE, "release": ""}),
    json.dumps({**GOOD_RELEASE, "release": "1.0 <script>"}), "x" * 5000,
])
def test_release_info_never_makes_a_release_up(tmp_path, content):
    (tmp_path / "release.json").write_text(content)
    got = ri.load_release(str(tmp_path))
    assert got["release"] == "unknown" and set(got) == {"release", "reason"}


def test_release_info_missing_file_and_symlink(tmp_path):
    assert ri.load_release(str(tmp_path)) == {"release": "unknown", "reason": "no release.json in this build"}
    real = tmp_path / "real.json"
    real.write_text(json.dumps(GOOD_RELEASE))
    os.symlink(real, tmp_path / "release.json")
    assert ri.load_release(str(tmp_path))["release"] == "unknown"


def test_release_info_is_read_once_and_copied(tmp_path, monkeypatch):
    mod = _load("sat11_release_info_once", "apps/control-center/release_info.py")
    target = tmp_path / "release.json"
    target.write_text(json.dumps(GOOD_RELEASE))
    monkeypatch.setattr(mod, "load_release", lambda base_dir=None, _r=ri.load_release: _r(str(tmp_path)))
    first = mod.current_release()
    target.write_text(json.dumps({**GOOD_RELEASE, "release": "9.9.9"}))
    first["release"] = "mutated"
    assert mod.current_release()["release"] == "0.9.2"


def test_log_release_is_one_structured_line():
    buf = io.StringIO()
    rel = ri.log_release("infra-rollback-job", stream=buf)
    line = json.loads(buf.getvalue())
    assert buf.getvalue().count("\n") == 1
    assert line["message"] == "stackvend.release" and line["severity"] == "INFO"
    assert line["component"] == "infra-rollback-job" and line["release"] == rel


def _func(path, name):
    tree = ast.parse(open(os.path.join(REPO, path)).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{path}: no {name}")


def _calls_release(node, attr):
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == attr
               and isinstance(n.func.value, ast.Name) and n.func.value.id == "release_info" for n in ast.walk(node))


HEALTH_SERVICES = ["apps/orchestrator-gateway", "apps/project-vending", "apps/log-sre-sentinel", "apps/spec-ingestion",
                   "mcp-servers/terraform", "mcp-servers/gcloud", f"mcp-servers/{G}hub", "mcp-servers/workspace",
                   "mcp-servers/infracost", "mcp-servers/compliance", "mcp-servers/kubernetes",
                   "mcp-servers/agent-builder", "apps/refactor-scanner", "apps/finops-enforcer", "apps/infra-rollback",
                   "apps/sandbox-cleaner", "apps/sre-digest"]


@pytest.mark.parametrize("comp", HEALTH_SERVICES)
def test_every_private_health_reports_the_release(comp):
    fn = _func(f"{comp}/main.py", "health_check")
    assert _calls_release(fn, "current_release"), f"{comp} /health does not report release_info.current_release()"
    src = open(os.path.join(REPO, comp, "main.py")).read()
    assert "\nimport release_info" in src


def test_public_health_endpoints_unchanged():
    """Negative: the Control Center's public /health and the git server's public /health carry no release."""
    cc = open(os.path.join(REPO, "apps/control-center/routes/web.py")).read()
    assert "release_info" not in cc
    gs = _func(f"apps/{G}-server/main.py", "health_check")
    assert not _calls_release(gs, "current_release")
    assert _calls_release(_func(f"apps/{G}-server/main.py", "capabilities"), "current_release")


@pytest.mark.parametrize("path,func,name", [
    ("apps/infra-rollback/main.py", None, "infra-rollback-job"),
    ("apps/refactor-scanner/main.py", None, f"{G}hub-refactor-scanner-job"),
    ("apps/finops-enforcer/main.py", None, "finops-budget-enforcer-job"),
    ("apps/sandbox-cleaner/main.py", None, "sandbox-garbage-collector-job"),
    ("apps/sre-digest/main.py", None, "sre-telemetry-digest-job"),
    ("apps/qa-runner/sandbox_job.py", "main", "qa-sandbox-test-runner"),
    ("mcp-servers/terraform/applier.py", "run_job", "tf-applier"),
    ("apps/orchestrator-gateway/stage_runner.py", "run", "stage-runner"),   # STAGE-JOB-RUNNER
])
def test_jobs_log_their_release_at_start(path, func, name):
    src = open(os.path.join(REPO, path)).read()
    assert f'release_info.log_release("{name}")' in src
    assert name in rm.COMPONENT_KINDS and rm.COMPONENT_KINDS[name] == "job"
    if func:
        assert _calls_release(_func(path, func), "log_release")


# ================================================================================================ release_manifest.py
def _bash_array(text, name):
    start = text.index(f"{name}=(")
    body = text[start:text.index(")", start)]
    return [line.strip().strip('"') for line in body.splitlines()[1:] if line.strip().startswith('"')]


def test_components_match_deploy_services():
    # deploy-services.sh sources its SERVICES / JOBS from scripts/common/components.sh (SELFUP P3b B2)
    text = open(os.path.join(REPO, "scripts/common/components.sh")).read()
    expected = [(e.split(":")[0], "service", e.split(":")[1]) for e in _bash_array(text, "SERVICES")]
    expected += [(e.split(":")[0], "job", e.split(":")[1]) for e in _bash_array(text, "JOBS")]
    assert list(rm.COMPONENTS[:-2]) == expected
    # the two follower jobs: never built on their own, they run a service's image
    assert rm.COMPONENTS[-2:] == (("tf-applier", "job", "mcp-servers/terraform"),
                                  ("stage-runner", "job", "apps/orchestrator-gateway"))


@pytest.mark.parametrize("text,ok", [("0.9.0-preview", True), ("1.0.0-rc.1", True), ("1.2.3", True),
                                     ("01.0.0", False), ("1.0", False), ("1.0.0-", False), ("1.0.0-01", False),
                                     ("1.0.0+build", False), ("v1.0.0", False), (" 1.0.0", False), ("1.0.0-a..b", False)])
def test_semver_grammar(text, ok):
    assert (rm.parse_semver(text) is not None) is ok


def test_semver_precedence():
    order = ["0.9.0-preview", "0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
             "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1"]
    parsed = [rm.parse_semver(v) for v in order]
    assert [str(v) for v in sorted(reversed(parsed), key=lambda v: v.key())] == order
    assert rm.parse_release_tag("v0.9.3-preview").is_prerelease and rm.parse_release_tag("0.9.3") is None


def _manifest(**kw):
    m = {"schema_version": 1, "release": "0.9.3", "requires_apply_sh": True, "min_platform_release": "0.9.3"}
    m.update(kw)
    return json.dumps(m)


def test_manifest_strict_parser():
    m = rm.parse_manifest(_manifest().encode())
    assert str(m.release) == "0.9.3" and m.requires_apply_sh is True
    cases = [(_manifest(extra=1), "MANIFEST_INVALID"), (json.dumps({"schema_version": 1}), "MANIFEST_INVALID"),
             (_manifest(requires_apply_sh=1), "MANIFEST_INVALID"), (_manifest(schema_version=2), "MANIFEST_UNSUPPORTED"),
             (_manifest(schema_version="1"), "MANIFEST_INVALID"), (_manifest(release="v0.9.3"), "MANIFEST_INVALID"),
             (_manifest(min_platform_release="x"), "MANIFEST_INVALID"), ("[]", "MANIFEST_INVALID"),
             ("{", "MANIFEST_INVALID"), (" " * 5000, "MANIFEST_INVALID")]
    for raw, code in cases:
        with pytest.raises(rm.ManifestError) as e:
            rm.parse_manifest(raw)
        assert e.value.code == code, raw


def test_manifest_release_rules():
    assert rm.manifest_rule_errors(rm.parse_manifest(_manifest())) == []
    assert rm.manifest_rule_errors(rm.parse_manifest(_manifest(requires_apply_sh=False, min_platform_release="0.9.1"))) == []
    assert rm.manifest_rule_errors(rm.parse_manifest(_manifest(requires_apply_sh=False)))  # yes iff min == release
    assert rm.manifest_rule_errors(rm.parse_manifest(_manifest(requires_apply_sh=True, min_platform_release="0.9.1")))
    assert rm.manifest_rule_errors(rm.parse_manifest(_manifest(min_platform_release="1.0.0")))


def test_guard_table():
    none = rm.PlatformStamp()
    target = lambda mn: rm.parse_manifest(_manifest(release="0.9.4", requires_apply_sh=mn == "0.9.4",
                                                    min_platform_release=mn))
    # SELFUP-STAMP-RETIRE (review BL-1, code review L-1): every release is stamped (FD-4DA-STAMP), so a missing stamp
    # is always unknown (fail closed), whatever the services run; nothing is ever "assumed"
    for installed in (None, rm.parse_semver("0.8.0"), rm.parse_semver("0.9.0-preview"), rm.parse_semver("0.9.2")):
        for mn in ("0.9.0-preview", "0.9.3"):
            d = rm.guard_decision(none, target(mn), installed)
            assert d.decision == rm.PLATFORM_STAMP_UNKNOWN and not d.assumed and d.platform_release is None
        assert rm.platform_release_for(none, installed)[:2] == (None, False)
    assert not hasattr(rm, "ASSUMED_PLATFORM_RELEASE_WITHOUT_STAMP")
    # skipped releases: v0.9.4 says "no" but carries 0.9.3 forward; a platform on 0.9.1 is sent to apply.sh
    assert rm.guard_decision(rm.PlatformStamp("0.9.1", "b" * 40), target("0.9.3")).decision == rm.NEEDS_APPLY_SH
    ok = rm.guard_decision(rm.PlatformStamp("0.9.3", "b" * 40), target("0.9.3"))
    assert ok.decision == rm.ALLOW and not ok.assumed and not ok.warnings
    dirty = rm.guard_decision(rm.PlatformStamp("0.9.3", "b" * 40 + "+dirty"), target("0.9.3"))
    assert dirty.decision == rm.ALLOW and dirty.warnings
    assert rm.guard_decision(rm.PlatformStamp("junk", None), target("0.9.3")).decision == rm.PLATFORM_STAMP_UNKNOWN


def test_stamp_first_release_is_valid_and_not_newer_than_version():
    version = open(os.path.join(REPO, "VERSION")).read().strip()
    # SELFUP-STAMP-RETIRE: the stamp shipped with the first release (FD-4DA-STAMP; review BL-1)
    assert rm.STAMP_FIRST_RELEASE == "0.9.0-preview"
    shipped = rm.parse_semver(rm.STAMP_FIRST_RELEASE)
    assert shipped is not None and rm.compare(shipped, rm.parse_semver(version)) <= 0


@pytest.mark.parametrize("slug,ok", [("acme/stackvend", True), ("a-b/c.d_e", True), ("-a/b", False), ("a-/b", False),
                                     ("a/..", False), ("a/b/c", False), ("a", False), ("a" * 40 + "/b", False),
                                     ("a/" + "b" * 101, False), ("a b/c", False), ("a/b c", False)])
def test_repository_rules(slug, ok):
    assert rm.is_valid_repository(slug) is ok


@pytest.mark.parametrize("url,want", [("https://github.com/acme/stackvend.git", "acme/stackvend"),
                                      (f"{G}@github.com:acme/stackvend.git", "acme/stackvend"),
                                      ("https://github.com/acme/stackvend", "acme/stackvend"),
                                      ("https://gitlab.com/acme/stackvend.git", None),
                                      ("https://github.com/acme/stackvend/extra", None),
                                      ("https://token@github.com/acme/stackvend", None), ("", None)])
def test_repository_from_remote_url_exact_forms_only(url, want):
    assert rm.repository_from_remote_url(url) == want


def _run_fake(responses):
    calls = []

    def get(url):
        calls.append(url)
        return responses.get(url, (404, None))
    return get, calls


SVC_URL = "https://us-central1-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/p/services/mcp-gcloud-server"
REV_URL = "https://us-central1-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/p/revisions/mcp-gcloud-server-00002"
JOB_URL = "https://us-central1-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/p/jobs/infra-rollback-job"
DIGEST = "us-central1-docker.pkg.dev/p/r/img@sha256:" + "c" * 64


def test_read_component_service_and_job():
    get, calls = _run_fake({
        SVC_URL: (200, {"metadata": {"annotations": {"stackvend/platform-release": "0.9.3", "x": 1}},
                        "status": {"latestReadyRevisionName": "mcp-gcloud-server-00002"}}),
        REV_URL: (200, {"status": {"imageDigest": DIGEST}}),
        JOB_URL: (200, {"spec": {"template": {"spec": {"template": {"spec": {"containers": [{"image": DIGEST}]}}}}}}),
    })
    svc = rm.read_component(get, "p", "us-central1", "mcp-gcloud-server", "service")
    assert svc == {"image_digest": DIGEST, "revision": "mcp-gcloud-server-00002",
                   "annotations": {"stackvend/platform-release": "0.9.3"}}
    assert rm.read_component(get, "p", "us-central1", "infra-rollback-job", "job")["image_digest"] == DIGEST
    with pytest.raises(rm.ComponentReadError) as e:
        rm.read_component(get, "p", "us-central1", "castor-" + G + "-server", "service")
    assert e.value.code == "NOT_DEPLOYED"


@pytest.mark.parametrize("svc,rev,code", [
    ((200, {"status": {}}), None, "BAD_RESPONSE"),
    ((200, {"status": {"latestReadyRevisionName": "mcp-gcloud-server-00002"}}), (200, {"status": {}}), "BAD_RESPONSE"),
    ((200, {"status": {"latestReadyRevisionName": "mcp-gcloud-server-00002"}}), (200, {"status": {"imageDigest": "img:latest"}}), "BAD_RESPONSE"),
    ((403, None), None, "READ_FAILED"),
    ((200, ["x"]), None, "BAD_RESPONSE"),
])
def test_read_component_never_assumes(svc, rev, code):
    responses = {SVC_URL: svc}
    if rev:
        responses[REV_URL] = rev
    get, _ = _run_fake(responses)
    with pytest.raises(rm.ComponentReadError) as e:
        rm.read_component(get, "p", "us-central1", "mcp-gcloud-server", "service")
    assert e.value.code == code


def _job(image):
    return {JOB_URL: (200, {"spec": {"template": {"spec": {"template": {"spec": {"containers": [{"image": image}]}}}}}})}


@pytest.mark.parametrize("image", [
    "us-central1-docker.pkg.dev/p/r/qa-sandbox-test-runner:" + "a" * 40,  # what the Cloud Build triggers deploy
    "us-central1-docker.pkg.dev/p/r/img:latest",
    "us-central1-docker.pkg.dev/p/r/img",                         # implicit :latest
    "localhost:5000/img:v1",
])
def test_job_image_by_tag_is_reported_as_a_tag(image):
    """Review M4 (rework): a tag image is not an error: it comes back as `image_tag` with no digest, so it is never
    compared with a recorded digest."""
    get, _ = _run_fake(_job(image))
    assert rm.read_component(get, "p", "us-central1", "infra-rollback-job", "job") == {
        "image_digest": None, "image_tag": image, "revision": "", "annotations": {}}
    assert rm.classify_image(image) == rm.IMAGE_TAG


@pytest.mark.parametrize("image", [
    "",                                                           # empty
    None,
    123,
    "us-central1-docker.pkg.dev/p/r/img@sha256:" + "c" * 63,     # short digest
    "us-central1-docker.pkg.dev/p/r/img@sha256:" + "C" * 64,     # not lowercase hex
    "us-central1-docker.pkg.dev/p/r/img@sha256:" + "c" * 64 + "x",
    "@sha256:" + "c" * 64,                                       # no repository
    "us-central1-docker.pkg.dev/p/r/img@sha512:" + "c" * 64,
    "us-central1-docker.pkg.dev/p/r/img:v1 ",                    # whitespace
])
def test_job_image_missing_or_malformed_is_bad_response(image):
    get, _ = _run_fake(_job(image))
    with pytest.raises(rm.ComponentReadError) as e:
        rm.read_component(get, "p", "us-central1", "infra-rollback-job", "job")
    assert e.value.code == "BAD_RESPONSE"
    assert rm.classify_image(image) is None


def test_write_record_never_records_a_tag_image():
    """M4: deploy-services.sh's record skips a job deployed by tag (warning), records the rest."""
    class Tagged(FakeHttp):
        def __call__(self, method, url, body=None):
            if "/jobs/infra-rollback-job" in url:
                return 200, {"spec": {"template": {"spec": {"template": {"spec": {"containers": [
                    {"image": "us-central1-docker.pkg.dev/p/r/img:" + "a" * 40}]}}}}}}
            return super().__call__(method, url, body)
    http = Tagged()
    w = rr.write_record(http, "p", "r", _rel(), ["infra-rollback-job", "tf-applier"], "", False)
    assert any("infra-rollback-job" in x and "IMAGE_BY_TAG" in x for x in w)
    stored = [c for c in http.calls if c[0] == "PATCH"][0][2]
    assert list(rr.from_value({"mapValue": {"fields": stored["fields"]}})["components"]) == ["tf-applier"]


def test_digest_job_image_is_read_unchanged():
    """Negative (Do No Harm): a digest-qualified job image is returned byte for byte, as before."""
    for image in (DIGEST, "us-central1-docker.pkg.dev/p/r/img:v1@sha256:" + "0123456789abcdef" * 4):
        get, _ = _run_fake(_job(image))
        assert rm.read_component(get, "p", "us-central1", "infra-rollback-job", "job") == {
            "image_digest": image, "revision": "", "annotations": {}}
        assert rm.is_digest_reference(image) and rm.classify_image(image) == rm.IMAGE_DIGEST


# ================================================================================================ release_record.py
@pytest.fixture
def checkout(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = _git_env(str(home))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "VERSION").write_text("0.9.2\n")
    (repo / ".gitignore").write_text("/apps/x/release.json\n")
    (repo / "apps" / "x").mkdir(parents=True)
    (repo / "apps" / "x" / "main.py").write_text("print(1)\n")
    _git(str(repo), "init", "-q", env=env)
    _git(str(repo), "add", "-A", env=env)
    _git(str(repo), "commit", "-q", "-m", "init", env=env)
    old = {k: os.environ.get(k) for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "HOME")}
    os.environ.update({k: env[k] for k in old})
    yield repo, env
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_stamp_clean_checkout(checkout):
    repo, env = checkout
    head = _git(str(repo), "rev-parse", "HEAD", env=env).stdout.strip()
    doc = rr.make_release_document(str(repo), env={})
    assert doc["release"] == "0.9.2" and doc["commit"] == head and doc["dirty"] is False
    assert doc["source_repo"] == "local checkout" and doc["builder"] == "deploy-services"
    assert ri.validate_release_document(doc) == doc  # what the script writes, the services accept


def test_stamp_dirty_and_ignored_release_json(checkout):
    repo, env = checkout
    (repo / "apps" / "x" / "release.json").write_text("{}")  # git-ignored: never makes the tree dirty
    assert rr.make_release_document(str(repo), env={})["dirty"] is False
    (repo / "apps" / "x" / "main.py").write_text("print(2)\n")
    assert rr.make_release_document(str(repo), env={})["dirty"] is True


def test_stamp_source_repo(checkout):
    repo, env = checkout
    cfg = repo / ("." + G) / "config"
    base = cfg.read_text()
    cfg.write_text(base + '[remote "origin"]\n\turl = https://github.com/acme/stackvend.git\n')  # no network call
    assert rr.make_release_document(str(repo), env={})["source_repo"] == "acme/stackvend"
    assert rr.make_release_document(str(repo), env={"STACKVEND_SOURCE_REPO": "fork/sv"})["source_repo"] == "fork/sv"
    with pytest.raises(rr.RecordError):
        rr.make_release_document(str(repo), env={"STACKVEND_SOURCE_REPO": "not a repo"})
    cfg.write_text(base + '[remote "origin"]\n\turl = https://example.com/acme/stackvend.git\n')
    assert rr.make_release_document(str(repo), env={})["source_repo"] == "local checkout"


def test_stamp_refuses_without_version_and_outside_git(tmp_path):
    with pytest.raises(rr.RecordError):
        rr.make_release_document(str(tmp_path), env={})
    (tmp_path / "VERSION").write_text("not-semver\n")
    with pytest.raises(rr.RecordError):
        rr.make_release_document(str(tmp_path), env={})
    (tmp_path / "VERSION").write_text("1.0.0\n")
    doc = rr.make_release_document(str(tmp_path), env={})
    assert doc["commit"] == "unknown" and doc["dirty"] is True  # never claims a clean tree it could not read


def _rel(**kw):
    return {**GOOD_RELEASE, **kw}


def test_merge_first_partial_and_full_runs():
    rec, w = rr.merge_record(None, _rel(), {"mcp-gcloud-server": {"image_digest": DIGEST, "revision": "r1"}},
                             "op@example.com", "run1", "2026-10-31T00:00:00Z", False)
    assert w == [] and rec["release"] is None  # a partial run never sets the top-level release
    assert rec["components"]["mcp-gcloud-server"]["release"] == "0.9.2" and len(rec["history"]) == 1
    rec2, _ = rr.merge_record(rec, _rel(release="0.9.3", commit="b" * 40),
                              {n: {"image_digest": DIGEST, "revision": ""} for n in rm.COMPONENT_KINDS},
                              "op@example.com", "run2", "2026-10-31T01:00:00Z", True)
    assert rec2["release"] == "0.9.3" and rec2["history"][0]["full_run"] is True and len(rec2["history"]) == 2
    rec3, _ = rr.merge_record(rec2, _rel(release="0.9.4"), {"infra-rollback-job": {"image_digest": DIGEST}},
                              "op@example.com", "run3", "2026-10-31T02:00:00Z", False)
    assert rec3["release"] == "0.9.3"  # unchanged by a partial run
    assert rec3["components"]["infra-rollback-job"]["release"] == "0.9.4"
    assert rec3["components"]["mcp-gcloud-server"]["release"] == "0.9.3"  # untouched component kept
    assert rec3["history"][0]["components"] == ["infra-rollback-job"]


def test_merge_history_cap_and_malformed_record():
    rec = None
    for i in range(25):
        rec, _ = rr.merge_record(rec, _rel(), {"tf-applier": {"image_digest": DIGEST}}, "", f"r{i}", f"t{i:02d}", False)
    assert len(rec["history"]) == rm.HISTORY_LIMIT == 20 and rec["history"][0]["run_id"] == "r24"
    rec, w = rr.merge_record({"components": ["bad"]}, _rel(), {"tf-applier": {"image_digest": DIGEST}}, "", "x", "t", False)
    assert w and list(rec["components"]) == ["tf-applier"]


def test_firestore_value_roundtrip():
    doc = {"a": None, "b": True, "c": 3, "d": "x", "e": [1, {"f": False}], "g": {"h": 1.5}}
    assert rr.from_value(rr.to_value(doc)) == doc


class FakeHttp:
    def __init__(self, record=None, patch_status=(200,)):
        self.record, self.patch_status, self.calls = record, list(patch_status), []

    def __call__(self, method, url, body=None):
        self.calls.append((method, url, json.loads(body) if body else None))
        if "firestore" in url:
            if method == "GET":
                if self.record is None:
                    return 404, None
                return 200, {"fields": rr.to_value(self.record)["mapValue"]["fields"], "updateTime": "2026-10-31T00:00:00.1Z"}
            status = self.patch_status.pop(0) if self.patch_status else 200
            return status, {}
        if "/services/" in url:
            name = url.rsplit("/", 1)[1]
            return 200, {"status": {"latestReadyRevisionName": name + "-00001"}}
        if "/revisions/" in url:
            return 200, {"status": {"imageDigest": DIGEST}}
        if "/jobs/" in url:
            return 200, {"spec": {"template": {"spec": {"template": {"spec": {"containers": [{"image": DIGEST}]}}}}}}
        return 404, None


def test_write_record_first_write_and_precondition():
    http = FakeHttp()
    warnings = rr.write_record(http, "p", "us-central1", _rel(), ["mcp-gcloud-server", "tf-applier"], "op@x", False,
                               now_iso="t", run_id="r")
    patches = [c for c in http.calls if c[0] == "PATCH"]
    assert warnings == [] and len(patches) == 1 and patches[0][1].endswith("?currentDocument.exists=false")
    stored = rr.from_value({"mapValue": {"fields": patches[0][2]["fields"]}})
    assert sorted(stored["components"]) == ["mcp-gcloud-server", "tf-applier"]
    assert stored["components"]["mcp-gcloud-server"]["image_digest"] == DIGEST
    http2 = FakeHttp(record=stored, patch_status=(400, 200))  # someone wrote in between: re-read and retry
    rr.write_record(http2, "p", "us-central1", _rel(), ["infra-rollback-job"], "op@x", False)
    patches = [c for c in http2.calls if c[0] == "PATCH"]
    assert len(patches) == 2 and "currentDocument.updateTime=" in patches[1][1]


def test_write_record_failures_are_typed():
    with pytest.raises(rr.RecordError):
        rr.write_record(FakeHttp(), "p", "r", _rel(), ["not-a-component"], "", False)
    with pytest.raises(rr.RecordError):
        rr.write_record(FakeHttp(), "p", "r", {"release": "x"}, ["tf-applier"], "", False)
    with pytest.raises(rr.RecordError):
        rr.write_record(FakeHttp(patch_status=(403,)), "p", "r", _rel(), ["tf-applier"], "", False)

    class Unreadable(FakeHttp):
        def __call__(self, method, url, body=None):
            if "run.googleapis.com" in url:
                return 403, None
            return super().__call__(method, url, body)
    with pytest.raises(rr.RecordError):  # nothing could be read back: nothing is written
        rr.write_record(Unreadable(), "p", "r", _rel(), ["tf-applier"], "", False)


def test_write_record_skips_a_component_it_cannot_read():
    class Partial(FakeHttp):
        def __call__(self, method, url, body=None):
            if "/jobs/infra-rollback-job" in url:
                return 500, None
            return super().__call__(method, url, body)
    http = Partial()
    w = rr.write_record(http, "p", "r", _rel(), ["infra-rollback-job", "tf-applier"], "", False)
    assert any("infra-rollback-job" in x for x in w)
    stored = [c for c in http.calls if c[0] == "PATCH"][0][2]
    assert list(rr.from_value({"mapValue": {"fields": stored["fields"]}})["components"]) == ["tf-applier"]


def test_record_cli_needs_a_token(tmp_path, monkeypatch, capsys):
    f = tmp_path / "r.json"
    f.write_text(json.dumps(_rel()))
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert rr.main(["record", "--project", "p", "--region", "r", "--release-file", str(f), "--token-stdin",
                    "tf-applier"]) == 1
    assert "no access token" in capsys.readouterr().err


# ================================================================================================ .gitignore / uploads
def test_release_json_is_ignored_by_exact_entries():
    lines = open(os.path.join(REPO, ".gitignore")).read().splitlines()
    for d in COMPONENT_DIRS:
        assert f"/{d}/release.json" in lines
    res = subprocess.run([G, "-C", REPO, "check-ignore", "--no-index"] + [f"{d}/release.json" for d in COMPONENT_DIRS],
                         capture_output=True, text=True)
    assert sorted(res.stdout.split()) == sorted(f"{d}/release.json" for d in COMPONENT_DIRS)


def test_no_component_upload_ignore_file_drops_release_json():
    """gcloud uploads the component directory; its own .gcloudignore / .gitignore must not exclude release.json."""
    for d in COMPONENT_DIRS:
        for name in (".gcloudignore", "." + G + "ignore"):
            p = os.path.join(REPO, d, name)
            if not os.path.exists(p):
                continue
            for line in open(p).read().splitlines():
                pat = line.strip()
                if pat and not pat.startswith("#") and not pat.startswith("!"):
                    assert not fnmatch.fnmatch("release.json", pat.lstrip("/")), f"{p}: {pat} would drop release.json"


# ================================================================================================ deploy-services.sh
CAPTURE = r'''#!/bin/bash
a="$*"
case "$a" in
  "run deploy "*|"run jobs deploy "*)
    name="$3"; [ "$2" = "jobs" ] && name="$4"
    prev=""; src=""
    for x in "$@"; do [ "$prev" = "--source" ] && src="$x"; prev="$x"; done
    [ -f "$src/release.json" ] && cp "$src/release.json" "$STUB_LOG.release.$name" ;;
  "config get-value account"*) echo "op@example.com"; exit 0 ;;
esac
'''

RECORD_STUB = '''import os, runpy, sys
if len(sys.argv) > 1 and sys.argv[1] == "record":
    with open(os.environ["STUB_LOG"] + ".record", "a") as fh:
        fh.write(" ".join(sys.argv[1:]) + "\\n" + "stdin=" + sys.stdin.read().strip() + "\\n")
    sys.exit(int(os.environ.get("STUB_RECORD_RC", "0")))
sys.argv[0] = %r
runpy.run_path(%r, run_name="__main__")
'''


class TestDeployServicesRecord(lane5._Harness):
    def setUp(self):
        super().setUp()
        for d in lane5.TestDeployServices.DIRS:
            os.makedirs(os.path.join(self.repo, d), exist_ok=True)
            self.write(f"{d}/main.py", "# component\n")
        os.makedirs(os.path.join(self.repo, "apps/control-center/shared"), exist_ok=True)
        self.write("infra/modules/m/main.tf", "# module\n")
        self.write("shared/builtin_modules_payload.py", "PAYLOAD = {}\n")
        self.write("VERSION", "0.9.2\n")
        shutil.copy(os.path.join(REPO, ".gitignore"), os.path.join(self.repo, ".gitignore"))
        real = os.path.join(REPO, "scripts", "common", "release_record.py")
        with open(os.path.join(self.repo, "scripts", "common", "release_record.py"), "w") as fh:
            fh.write(RECORD_STUB % (real, real))
        with open(os.path.join(self.stub, "gcloud"), "w") as fh:
            fh.write(CAPTURE + lane5.GCLOUD_STUB.split("\n", 1)[1])
        self.git_json = os.path.join(self.tmp, "git.json")
        with open(self.git_json, "w") as fh:
            json.dump(lane5.GOOD_GIT_JSON, fh)
        home = os.path.join(self.tmp, "githome")
        os.makedirs(home)
        self.genv = _git_env(home)
        _git(self.repo, "init", "-q", env=self.genv)
        _git(self.repo, "add", "-A", env=self.genv)
        _git(self.repo, "commit", "-q", "-m", "x", env=self.genv)
        self.head = _git(self.repo, "rev-parse", "HEAD", env=self.genv).stdout.strip()

    def env(self, **extra):
        e = super().env(**extra)
        e.update({k: self.genv[k] for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM")})
        e["PATH"] = e["PATH"] + ":" + os.path.dirname(shutil.which(G) or "/usr/bin/" + G)
        return e

    def _captured(self, name):
        p = f"{self.log}.release.{name}"
        return json.load(open(p)) if os.path.exists(p) else None

    def _record(self):
        p = self.log + ".record"
        return open(p).read().splitlines() if os.path.exists(p) else []

    def _left_behind(self):
        return [d for d in lane5.TestDeployServices.DIRS if os.path.exists(os.path.join(self.repo, d, "release.json"))]

    def _deploys(self):
        return [x for x in self.calls() if x.startswith("gcloud run deploy") or x.startswith("gcloud run jobs deploy")]

    def test_single_service_build_carries_release_json_and_records_once(self):
        rc, out, err = self.run_script("deploy-services.sh", ["control-center"], PROJECT_ID=lane5.PROJ)
        self.assertEqual(rc, 0, out + err)
        rel = self._captured("product-control-center-ui")
        self.assertEqual((rel["release"], rel["commit"], rel["dirty"], rel["builder"]),
                         ("0.9.2", self.head, False, "deploy-services"))
        self.assertEqual(self._left_behind(), [])
        rec = self._record()
        self.assertEqual(len(rec), 2, rec)
        self.assertTrue(rec[0].startswith(f"record --project {lane5.PROJ} --region us-central1 --release-file "))
        self.assertIn("--deployed-by op@example.com --token-stdin product-control-center-ui", rec[0])
        self.assertNotIn("--full-run", rec[0])
        self.assertEqual(rec[1], "stdin=stub-token")
        self.assertNotIn("stub-token", "\n".join(self.calls()).replace("auth print-access-token", ""))

    def test_terraform_server_records_tf_applier_too(self):
        rc, out, err = self.run_script("deploy-services.sh", ["mcp-terraform-server"], PROJECT_ID=lane5.PROJ)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(self._record()[0].endswith("--token-stdin mcp-terraform-server tf-applier"))

    def test_gateway_records_stage_runner_too(self):
        """STAGE-JOB-RUNNER: the job runs the gateway's image; a gateway deploy syncs and records it."""
        rc, out, err = self.run_script("deploy-services.sh", ["orchestrator-gateway-service"], PROJECT_ID=lane5.PROJ)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(self._record()[0].endswith("--token-stdin orchestrator-gateway-service stage-runner"))

    def test_gateway_before_the_apply_skips_a_missing_stage_runner_loudly(self):
        rc, out, err = self.run_script("deploy-services.sh", ["orchestrator-gateway-service"], PROJECT_ID=lane5.PROJ,
                                       STUB_JOBS_LIST="")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("does not exist yet: nothing to sync", out + err)
        self.assertTrue(self._record()[0].endswith("--token-stdin orchestrator-gateway-service"))
        self.assertFalse([c for c in self.calls() if c.startswith("gcloud run jobs update stage-runner")])

    def test_gateway_fails_when_the_job_list_is_unreadable(self):
        rc, out, err = self.run_script("deploy-services.sh", ["orchestrator-gateway-service"], PROJECT_ID=lane5.PROJ,
                                       STUB_JOBS_LIST_RC="1")
        self.assertNotEqual(rc, 0)
        self.assertIn("stage-runner NOT updated", out + err)

    def test_stage_runner_target_syncs_to_the_serving_revision_and_builds_nothing(self):
        """N2 / N3: after a gateway traffic rollback (or after the apply) the job gets the SERVING revision's image."""
        gw_json = os.path.join(self.tmp, "gw.json")
        with open(gw_json, "w") as fh:
            json.dump({"status": {"latestReadyRevisionName": "gw-00009",
                                  "traffic": [{"revisionName": "gw-00007", "percent": 100},
                                              {"latestRevision": True, "percent": 0}]}}, fh)
        rc, out, err = self.run_script("deploy-services.sh", ["stage-runner"], PROJECT_ID=lane5.PROJ,
                                       STUB_GW_JSON=gw_json, STUB_REVISION_IMAGE="r/gw@sha256:" + "7" * 64)
        self.assertEqual(rc, 0, out + err)
        calls = self.calls()
        self.assertFalse([c for c in calls if c.startswith(("gcloud run deploy", "gcloud run jobs deploy"))])
        self.assertIn(f"gcloud run revisions describe gw-00007 --region=us-central1 --project={lane5.PROJ} "
                      f"--format=value(spec.containers[0].image) --quiet", calls)
        self.assertIn(f"gcloud run jobs update stage-runner --image=r/gw@sha256:{'7' * 64} --region=us-central1 "
                      f"--project={lane5.PROJ} --quiet", calls)
        self.assertTrue(self._record()[0].endswith("--token-stdin stage-runner"))

    def test_stage_runner_target_refuses_a_traffic_split(self):
        gw_json = os.path.join(self.tmp, "gw.json")
        with open(gw_json, "w") as fh:
            json.dump({"status": {"traffic": [{"revisionName": "a", "percent": 50},
                                              {"revisionName": "b", "percent": 50}]}}, fh)
        rc, out, err = self.run_script("deploy-services.sh", ["stage-runner"], PROJECT_ID=lane5.PROJ,
                                       STUB_GW_JSON=gw_json)
        self.assertNotEqual(rc, 0)
        self.assertIn("NOT updated", out + err)
        self.assertFalse([c for c in self.calls() if c.startswith("gcloud run jobs update stage-runner")])

    def test_full_run_records_every_component(self):
        rc, out, err = self.run_script("deploy-services.sh", ["--all-jobs"], PROJECT_ID=lane5.PROJ,
                                       STUB_GIT_JSON=self.git_json)
        self.assertEqual(rc, 0, out + err)
        for name, _, _ in rm.COMPONENTS[:-2]:   # tf-applier and stage-runner are never built on their own
            self.assertEqual(self._captured(name)["commit"], self.head, name)
        rec = self._record()[0]
        self.assertIn("--full-run", rec)
        names = rec.split("--token-stdin ")[1].split()
        self.assertEqual(sorted(names), sorted(rm.COMPONENT_KINDS))
        self.assertEqual(self._left_behind(), [])

    def test_failed_deploys_are_not_recorded(self):
        rc, out, _ = self.run_script("deploy-services.sh", [], PROJECT_ID=lane5.PROJ, STUB_DEPLOY_RC=1)
        self.assertNotEqual(rc, 0)
        self.assertEqual(self._record(), [])
        self.assertEqual(self._left_behind(), [])

    def test_dirty_checkout_is_recorded_dirty(self):
        self.write("apps/control-center/main.py", "# changed\n")
        rc, out, err = self.run_script("deploy-services.sh", ["control-center"], PROJECT_ID=lane5.PROJ)
        self.assertEqual(rc, 0, out + err)
        self.assertTrue(self._captured("product-control-center-ui")["dirty"])

    def test_untracked_files_only_are_recorded_clean(self):
        """SAT-48: an operator's untracked files (local tool notes) are not a change to the commit (a dev install showed
        every component dirty from untracked local tool files); a tracked change still is (test above)."""
        self.write(".tool-notes/notes.md", "operator notes\n")
        self.write("scratch.txt", "x\n")
        rc, out, err = self.run_script("deploy-services.sh", ["control-center"], PROJECT_ID=lane5.PROJ)
        self.assertEqual(rc, 0, out + err)
        rel = self._captured("product-control-center-ui")
        self.assertEqual((rel["commit"], rel["dirty"]), (self.head, False))

    def test_record_failure_never_fails_the_deploy(self):
        rc, out, err = self.run_script("deploy-services.sh", ["control-center"], PROJECT_ID=lane5.PROJ, STUB_RECORD_RC=1)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("version record (system_config/platform_release) was not updated", out)

    def test_without_the_record_script_the_deploy_is_unchanged(self):
        """Do No Harm: the same deploy commands, success, no release.json, a warning."""
        rc, out, err = self.run_script("deploy-services.sh", ["--all-jobs"], PROJECT_ID=lane5.PROJ,
                                       STUB_GIT_JSON=self.git_json)
        self.assertEqual(rc, 0, out + err)
        with_record = self._deploys()
        open(self.log, "w").close()
        os.remove(os.path.join(self.repo, "scripts", "common", "release_record.py"))
        for f in os.listdir(self.tmp):
            if f.startswith("calls.log.release."):
                os.remove(os.path.join(self.tmp, f))
        rc, out, err = self.run_script("deploy-services.sh", ["--all-jobs"], PROJECT_ID=lane5.PROJ,
                                       STUB_GIT_JSON=self.git_json)
        self.assertEqual(rc, 0, out + err)
        without_record = self._deploys()
        # The same deploy commands; after the git server (deployed first and alone) the rest run in parallel, so
        # their order is not fixed.
        self.assertEqual(without_record[:1], with_record[:1])
        self.assertEqual(sorted(without_record), sorted(with_record))
        self.assertIn("release_record.py not found", out)
        self.assertIsNone(self._captured("product-control-center-ui"))
        self.assertEqual(self._left_behind(), [])
        self.assertNotIn("auth print-access-token", "\n".join(self.calls()))

    def test_without_version_file_no_release_json_and_deploy_unchanged(self):
        os.remove(os.path.join(self.repo, "VERSION"))
        rc, out, err = self.run_script("deploy-services.sh", ["control-center"], PROJECT_ID=lane5.PROJ)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("Could not compute release.json", out)
        self.assertIsNone(self._captured("product-control-center-ui"))
        self.assertEqual(self._record(), [])


# ================================================================================================ manifest + checker
def test_repository_release_manifest_matches_version():
    m = rm.parse_manifest(open(os.path.join(REPO, "release-manifest.json"), "rb").read())
    assert str(m.release) == open(os.path.join(REPO, "VERSION")).read().strip()


@needs_check_manifest
def test_repository_release_manifest_passes_the_release_rules():
    assert cm.check_tree(REPO) == []


def _tree(tmp_path, manifest, changelog_flag="**requires apply.sh: yes**", version="0.9.3"):
    (tmp_path / "VERSION").write_text(version + "\n")
    (tmp_path / "release-manifest.json").write_text(manifest)
    (tmp_path / "CHANGELOG.md").write_text(f"# Changelog\n\n## [0.9.3] - 2026-11-01\n\n{changelog_flag}\n\n## [0.9.2]\n\n"
                                           "**requires apply.sh: no**\n")
    return str(tmp_path)


@needs_check_manifest
def test_check_manifest_negatives(tmp_path):
    assert cm.check_tree(_tree(tmp_path, _manifest())) == []
    assert cm.check_tree(_tree(tmp_path, _manifest(), version="0.9.4"))  # release != VERSION
    assert cm.check_tree(_tree(tmp_path, _manifest(), changelog_flag="**requires apply.sh: no**"))  # disagrees
    assert cm.check_tree(_tree(tmp_path, _manifest(), changelog_flag="requires apply.sh: yes"))  # no exact line
    assert cm.check_tree(_tree(tmp_path, _manifest(extra=1)))
    assert cm.check_tree(_tree(tmp_path, _manifest(requires_apply_sh=False)))
    assert cm.main(["--repo-root", _tree(tmp_path, _manifest(release="0.9.4"))]) == 1


@needs_check_manifest
def test_check_manifest_against_previous_release(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = _git_env(str(home))
    repo = tmp_path / "r"
    repo.mkdir()
    _tree(repo, _manifest(release="0.9.2", min_platform_release="0.9.2"), version="0.9.2")
    (repo / "CHANGELOG.md").write_text("## [0.9.2]\n**requires apply.sh: yes**\n## [0.9.3]\n**requires apply.sh: no**\n")
    _git(str(repo), "init", "-q", env=env)
    _git(str(repo), "add", "-A", env=env)
    _git(str(repo), "commit", "-q", "-m", "v092", env=env)
    _git(str(repo), "tag", "v0.9.2", env=env)
    old = {k: os.environ.get(k) for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "HOME")}
    os.environ.update({k: env[k] for k in old})
    try:
        (repo / "VERSION").write_text("0.9.3\n")
        (repo / "app.py").write_text("x = 1\n")
        (repo / "release-manifest.json").write_text(_manifest(requires_apply_sh=False, min_platform_release="0.9.2"))
        _git(str(repo), "add", "-A", env=env)
        _git(str(repo), "commit", "-q", "-m", "app only", env=env)
        assert cm.check_against_previous(str(repo), "v0.9.2", None) == []
        (repo / "release-manifest.json").write_text(_manifest(requires_apply_sh=False, min_platform_release="0.9.1"))
        assert cm.check_against_previous(str(repo), "v0.9.2", None)  # minimum must carry forward
        (repo / "infra" / "platform").mkdir(parents=True)
        (repo / "infra" / "platform" / "main.tf").write_text("# tf\n")
        (repo / "release-manifest.json").write_text(_manifest(requires_apply_sh=False, min_platform_release="0.9.2"))
        _git(str(repo), "add", "-A", env=env)
        _git(str(repo), "commit", "-q", "-m", "platform tf", env=env)
        errs = cm.check_against_previous(str(repo), "v0.9.2", None)
        assert errs and "infra/platform/main.tf" in errs[0]
        (repo / "release-manifest.json").write_text(_manifest())
        assert cm.check_against_previous(str(repo), "v0.9.2", None) == []
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

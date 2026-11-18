"""FD-4DC follow-ups (owner 10-29): FD-4DC-d, FD-4DC-e and the Upgrade-IaC parser pre-flight.

1. FD-4DC-d: the gateway's IAC_UPGRADE step commits only the module files the upgrade changed or added (plus
   deletions), while the pre-commit gate still sees the whole tree after the upgrade. `commit_and_open_pr` gains
   `commit_paths` / `files_to_delete`; with neither, every caller's commit is exactly what it was.
2. FD-4DC-e: Upgrade IaC (CC route and gateway) deletes a vendored module's .tf files that the new module version
   dropped: only files of an upgraded module, never anything else. `ServerlessGitProvider.commit_files` and the git
   server gain deletions (own route `/commits-with-deletions`; an older git server answers 404 and writes nothing).
3. The Upgrade-IaC pre-flight parses each upgraded .tf with python-hcl2 (.tf.json with json) instead of counting
   `{` / `}`.

Real functions with fakes only (CC route on Firestore fakes, the real engine, the real git server on a temp dir, the
real DeveloperAgent.commit_and_open_pr with fake VCS / verifier). Hermetic: no network, no GCP.
"""
import hermetic_guard  # noqa: F401  (first import: tests/hermetic_guard.py)

import ast
import glob
import json
import os
import shutil
import sys
from unittest.mock import MagicMock, patch

import pytest

from shared.providers import serverless_git_provider as sgp
from test_fd4dc_archive_and_partial_readers import (  # noqa: E402  (shared fakes of the FD-4DC suite)
    FIXTURE, WORKLOAD, _canonical, _cc_routes, _gateway_main, _manager_request, _Store, _upgrade_recorders,
    _use_provider, _workload_tree,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
ENGINE_COPIES = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                 "mcp-servers/terraform/shared"]
CR = "infra/modules/compute-cloudrun/"
LEGACY = CR + "legacy.tf"                 # a vendored file the canonical compute-cloudrun no longer has
MANIFEST = CR + ".castor-module.json"


class _Fs:
    """Firestore fake: only workloads/{pid} exists (custom_modules / custom_bundles lookups find nothing)."""

    def collection(self, name):
        class _Ref:
            def get(self):
                return _Doc(dict(WORKLOAD) if name == "workloads" else None)

            def update(self, data):
                pass

        class _Col:
            def document(self, doc_id):
                return _Ref()
        return _Col()


class _Doc:
    def __init__(self, data):
        self.exists, self._data = data is not None, data

    def to_dict(self):
        return dict(self._data or {})


FS = _Fs()


def _engine():
    from shared import iac_upgrade_engine as eng

    return eng


def _tree_with_dropped_files():
    """A workload tree whose compute-cloudrun has a .tf file upstream dropped, and whose second (current) module has
    an extra .tf too (that module is not upgraded, so it must keep it)."""
    tree = _workload_tree(drift=True)
    tree[LEGACY] = 'resource "null_resource" "legacy" {}\n'
    other = sorted({p.split("/")[2] for p in tree if p.startswith("infra/modules/") and not p.startswith(CR)})[0]
    tree[f"infra/modules/{other}/extra.tf"] = 'locals {\n  keep = true\n}\n'
    tree[MANIFEST] = json.dumps({"module_name": "compute-cloudrun", "version": "v0.9.0"})
    return tree, f"infra/modules/{other}/extra.tf"


# =============================================================================================== engine helper
def test_helper_lists_exactly_the_dropped_tf_files_of_the_upgraded_module():
    eng = _engine()
    tree, other_extra = _tree_with_dropped_files()
    updated, upgraded, _ = eng.upgrade_workload_iac_vendoring(dict(tree), modules_to_upgrade=["compute-cloudrun"],
                                                          firestore_client=FS)
    assert upgraded == ["compute-cloudrun"]
    assert eng.module_files_removed_by_upgrade(tree, updated, upgraded) == [LEGACY]
    assert other_extra in updated            # a module that was not upgraded loses nothing


def test_helper_without_dropped_files_is_empty():
    eng = _engine()
    tree = _workload_tree(drift=True)
    updated, upgraded, _ = eng.upgrade_workload_iac_vendoring(dict(tree), modules_to_upgrade=["compute-cloudrun"],
                                                          firestore_client=FS)
    assert eng.module_files_removed_by_upgrade(tree, updated, upgraded) == []
    assert eng.module_files_removed_by_upgrade(tree, dict(tree), []) == []


@pytest.mark.parametrize("victim", [
    "apps/api/main.py",                       # app code
    "infra/workload/main.tf",                 # root IaC
    "infra/human.tf",                         # human override
    "OTHER_MODULE",                           # a .tf of a module that was not upgraded
    MANIFEST,                                 # a non-.tf file of the upgraded module
    "infra/modules/compute-cloudrunx/main.tf",  # a sibling directory sharing the name prefix
    "infra/bundles/b1/main.tf",               # a bundle file (bundles never delete)
])
def test_a_removal_outside_the_upgraded_module_tf_files_is_never_a_deletion(victim):
    eng = _engine()
    tree, other_extra = _tree_with_dropped_files()
    tree["infra/modules/compute-cloudrunx/main.tf"] = "# sibling\n"
    tree["infra/bundles/b1/main.tf"] = "# bundle\n"
    victim = other_extra if victim == "OTHER_MODULE" else victim
    updated, upgraded, _ = eng.upgrade_workload_iac_vendoring(dict(tree), modules_to_upgrade=["compute-cloudrun"],
                                                          firestore_client=FS)
    broken = dict(updated)
    broken.pop(victim)                        # an engine defect: something else went missing
    with pytest.raises(eng.ModuleDeletionScopeError) as ei:
        eng.module_files_removed_by_upgrade(tree, broken, upgraded + ["bundle:b1"])
    assert victim in str(ei.value) and ei.value.error_class == "IAC_UPGRADE_DELETION_SCOPE"


def test_engine_helper_is_identical_in_every_copy():
    def segment(rel, name):
        src = open(os.path.join(REPO_ROOT, rel, "iac_upgrade_engine.py"), encoding="utf-8").read()
        node = next(n for n in ast.parse(src).body if getattr(n, "name", None) == name)
        return ast.get_source_segment(src, node)

    for name in ("ModuleDeletionScopeError", "module_files_removed_by_upgrade"):
        segs = {rel: segment(rel, name) for rel in ENGINE_COPIES}
        assert len(set(segs.values())) == 1, f"{name} drifted between {sorted(segs)}"


# =============================================================================================== CC Upgrade IaC
class _RecordingProvider:
    """A complete-tree provider that records every write call (positional files + keywords)."""

    def __init__(self, files):
        self.files, self.commits, self.branches = dict(files), [], []

    def fetch_file_tree(self, repo, branch="main", **kw):
        return dict(self.files)

    def create_or_verify_branch(self, repo, branch_name, source_branch="main"):
        self.branches.append(branch_name)
        return branch_name

    def commit_files(self, repo, branch, files, commit_message, **kw):
        self.commits.append((dict(files), dict(kw)))
        return "a" * 40

    def create_pull_request(self, repo, **kw):
        return {"pr_number": 7, "pull_request_url": "https://example.invalid/pull/7"}


def _run_upgrade(monkeypatch, tree, modules=("compute-cloudrun",), engine=None):
    wl = _cc_routes(monkeypatch)
    monkeypatch.setattr(wl, "get_db", lambda: _Store(dict(WORKLOAD)))
    rec = _upgrade_recorders(monkeypatch, wl)
    prov = _RecordingProvider(tree)
    _use_provider(monkeypatch, wl, prov)
    if engine is not None:
        monkeypatch.setattr(wl, "upgrade_workload_iac_vendoring", engine)
    req = wl.TriggerIaCUpgradeRequest(author="op@example.com", modules_to_upgrade=list(modules))
    try:
        out = wl.trigger_workload_iac_upgrade("app", req, _manager_request())
    except wl.HTTPException as e:
        return wl, e, prov, rec
    return wl, out, prov, rec


def test_cc_upgrade_deletes_the_dropped_module_file_and_writes_the_same_files(monkeypatch):
    tree, other_extra = _tree_with_dropped_files()
    _, out, prov, rec = _run_upgrade(monkeypatch, tree)
    ((written, kw),) = prov.commits
    assert set(written) == {CR + "main.tf", MANIFEST}            # the same file set as without a dropped file
    assert kw["files_to_delete"] == [LEGACY]
    assert other_extra not in kw["files_to_delete"]
    assert out["files_deleted"] == [LEGACY] and out["files_updated_count"] == 2
    (_, ckw), = rec["complete"]
    assert ckw["status"] == "SUCCESS" and ckw["details"]["files_deleted"] == [LEGACY]


def test_cc_upgrade_without_dropped_files_sends_no_deletion_keyword(monkeypatch):
    """Do No Harm: an upgrade that drops nothing makes exactly the commit call it made before."""
    _, out, prov, rec = _run_upgrade(monkeypatch, _workload_tree(drift=True))
    ((written, kw),) = prov.commits
    assert set(written) == {CR + "main.tf", MANIFEST}
    assert "files_to_delete" not in kw and "files_deleted" not in out
    (_, ckw), = rec["complete"]
    assert "files_deleted" not in ckw["details"]


def test_cc_upgrade_refuses_an_engine_removal_outside_the_module(monkeypatch):
    eng = _engine()
    tree, _ = _tree_with_dropped_files()

    def lossy(files, **kw):
        updated, mods, details = eng.upgrade_workload_iac_vendoring(files, **kw)
        updated.pop("apps/api/main.py")
        return updated, mods, details

    wl, err, prov, rec = _run_upgrade(monkeypatch, tree, engine=lossy)
    assert isinstance(err, wl.HTTPException) and err.status_code == 500
    assert err.detail.startswith("IAC_UPGRADE_DELETION_SCOPE: ") and "apps/api/main.py" in err.detail
    assert err.detail.endswith("Nothing was committed and no pull request was opened.")
    assert prov.commits == [] and prov.branches == []
    (_, ckw), = rec["complete"]
    assert ckw["status"] == "FAILED"


# =============================================================================================== parser pre-flight
from shared import hcl_utils  # noqa: E402

HAS_TOFU = hcl_utils.find_hcl_parser_binary() is not None
needs_tofu = pytest.mark.skipif(not HAS_TOFU, reason="no OpenTofu/Terraform binary on this host")

# RT F1: valid HCL that python-hcl2 7.3.1 refuses (an operator-leading continuation line inside parentheses)
F1_VALID = [
    'locals {\n  v = (\n    var.x\n    ? 1\n    : 2\n  )\n}\n',
    'locals {\n  v = (\n    var.x\n    && var.y\n  )\n}\n',
    'locals {\n  v = (\n    1\n    + 2\n  )\n}\n',
    'locals {\n  v = (\n    var.x\n    == 1\n  )\n}\n',
    'locals {\n  v = (\n    var.x\n    .y\n  )\n}\n',
    'locals {\n  v = (\n    var.l\n    [0]\n  )\n}\n',
]
BILLING_IAM = "infra/platform/billing_iam.tf"
BROKEN = [
    'locals {\n  a = 1\n',                                           # unbalanced
    'locals {\n  a = = 1\n}\n',                                      # balanced but broken (the old check passed it)
    'resource "x" "y" {\n  a = "unterminated\n}\n',
]


def _no_parser(monkeypatch):
    """The CC container today: python-hcl2 only, no OpenTofu binary."""
    monkeypatch.setattr(hcl_utils, "find_hcl_parser_binary", lambda: None)


def _f1_cases():
    billing = open(os.path.join(REPO_ROOT, BILLING_IAM), encoding="utf-8").read()
    return [pytest.param(t, id=f"construct{i}") for i, t in enumerate(F1_VALID)] + \
        [pytest.param(billing, id="billing_iam.tf")]


def _hcl2_refuses(text):
    from hcl2.parser import parser

    try:
        parser().parse(text + "\n")
    except Exception:  # noqa: BLE001
        return True
    return False


def _all_golden_tf():
    eng = _engine()
    files = {p: c for p, c in eng.get_canonical_module_files().items()}
    for path in glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True):
        rel = os.path.relpath(path, REPO_ROOT).replace(os.sep, "/")
        files.setdefault(rel, open(path, encoding="utf-8").read())
    from shared.builtin_bundles_payload import BUILTIN_BUNDLES
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES

    for mod, mfiles in BUILTIN_MODULE_FILES.items():
        for rel, code in mfiles.items():
            files[f"payload/{mod}/{rel}"] = code
    for bid, bundle in BUILTIN_BUNDLES.items():
        for rel, code in dict(bundle.hcl_files or {}).items():
            files[f"infra/bundles/{bid}/{rel}"] = code
    return files


def test_every_golden_module_tf_passes_the_preflight_with_python_hcl2_alone(monkeypatch):
    """Negative: no refusal of any golden module file (disk, canonical payload, BUILTIN_MODULE_FILES, bundles) by
    python-hcl2 alone, i.e. in the CC container without a binary; the input is never changed."""
    wl = _cc_routes(monkeypatch)
    _no_parser(monkeypatch)
    files = _all_golden_tf()
    tf = [p for p in files if p.endswith(".tf")]
    assert len([p for p in tf if p.startswith("payload/")]) >= 80 and len(tf) >= 170, len(tf)
    before = dict(files)
    wl._preflight_parse_upgraded_iac(files)
    assert files == before


@pytest.mark.parametrize("text", [
    'locals {\n  open = "{"\n}\n',                                   # lone brace in a string
    'locals {\n  doc = <<EOT\n}}} {\nEOT\n}\n',                       # unbalanced braces in a heredoc
    'locals {\r\n  a = 1\r\n}\r\n',                                  # CRLF
    '﻿locals {\n  a = 1\n}\n',                                  # UTF-8 BOM
    'locals {\n  a = 1\n}',                                          # no trailing newline
    "",                                                              # empty file
])
def test_valid_hcl_that_the_brace_count_refused_or_mishandled_is_accepted(monkeypatch, text):
    wl = _cc_routes(monkeypatch)
    _no_parser(monkeypatch)
    wl._preflight_parse_upgraded_iac({CR + "x.tf": text})


@needs_tofu
@pytest.mark.parametrize("text", _f1_cases())
def test_valid_hcl_python_hcl2_refuses_is_accepted_with_opentofu(monkeypatch, text):
    """RT F1: python-hcl2 refuses these valid files; OpenTofu's parser decides and accepts them."""
    wl = _cc_routes(monkeypatch)
    assert _hcl2_refuses(text)
    wl._preflight_parse_upgraded_iac({CR + "x.tf": text})


@pytest.mark.parametrize("text", _f1_cases())
def test_without_a_real_parser_the_refusal_is_typed_and_never_a_syntax_error(monkeypatch, text):
    wl = _cc_routes(monkeypatch)
    _no_parser(monkeypatch)
    with pytest.raises(wl.UpgradePreflightParserRefused) as ei:
        wl._preflight_parse_upgraded_iac({CR + "x.tf": text})
    msg = str(ei.value)
    assert ei.value.error_class == "IAC_PREFLIGHT_PARSER_REFUSED" and ei.value.path == CR + "x.tf"
    assert msg.startswith("IAC_PREFLIGHT_PARSER_REFUSED: python-hcl2 7.3.1 could not parse ")
    assert "syntax error" not in msg.lower() and "not proven broken" in msg
    assert not isinstance(ei.value, wl.UpgradePreflightParseError)


def test_a_binary_that_cannot_decide_is_no_verdict(monkeypatch):
    """hcl_parse_errors -> None (the binary could not run): no real verdict, so the typed parser refusal."""
    wl = _cc_routes(monkeypatch)
    monkeypatch.setattr(hcl_utils, "find_hcl_parser_binary", lambda: "/nonexistent/stackvend-test/tofu")
    with pytest.raises(wl.UpgradePreflightParserRefused):
        wl._preflight_parse_upgraded_iac({CR + "x.tf": F1_VALID[0]})


@needs_tofu
@pytest.mark.parametrize("text", BROKEN)
def test_a_broken_tf_is_a_syntax_error_by_opentofu_naming_the_file(monkeypatch, text):
    wl = _cc_routes(monkeypatch)
    with pytest.raises(wl.UpgradePreflightParseError) as ei:
        wl._preflight_parse_upgraded_iac({CR + "ok.tf": 'locals {\n  a = 1\n}\n', CR + "bad.tf": text})
    assert ei.value.path == CR + "bad.tf" and str(ei.value).startswith(f"Syntax error in {CR}bad.tf: ")
    assert "HCL parse error in" in ei.value.reason             # OpenTofu's verdict, not python-hcl2's


@pytest.mark.parametrize("text", BROKEN)
def test_a_broken_tf_without_a_real_parser_is_refused_naming_the_file(monkeypatch, text):
    wl = _cc_routes(monkeypatch)
    _no_parser(monkeypatch)
    with pytest.raises(wl.UpgradePreflightParserRefused) as ei:
        wl._preflight_parse_upgraded_iac({CR + "ok.tf": 'locals {\n  a = 1\n}\n', CR + "bad.tf": text})
    assert ei.value.path == CR + "bad.tf" and "syntax error" not in str(ei.value).lower()


def test_tf_json_is_parsed_as_json(monkeypatch):
    wl = _cc_routes(monkeypatch)
    wl._preflight_parse_upgraded_iac({CR + "a.tf.json": '{"locals": {"a": "{"}}'})
    with pytest.raises(wl.UpgradePreflightParseError) as ei:
        wl._preflight_parse_upgraded_iac({CR + "a.tf.json": '{"locals": '})
    assert ei.value.path == CR + "a.tf.json"


def _engine_writing(extra):
    eng = _engine()

    def run(files, **kw):
        updated, mods, details = eng.upgrade_workload_iac_vendoring(files, **kw)
        updated.update(extra)
        return updated, mods, details
    return run


BAD_ROUTE = {CR + "main.tf": 'locals {\n  a = = 1\n}\n'}   # balanced braces: the old pre-flight let this through


@needs_tofu
def test_route_refuses_a_broken_upgraded_file_and_commits_nothing(monkeypatch):
    wl, err, prov, rec = _run_upgrade(monkeypatch, _workload_tree(drift=True), engine=_engine_writing(BAD_ROUTE))
    assert isinstance(err, wl.HTTPException) and err.status_code == 400
    assert err.detail.startswith(f"Pre-flight IaC validation failed: Syntax error in {CR}main.tf: ")
    assert prov.commits == [] and prov.branches == []
    (_, ckw), = rec["complete"]
    assert ckw["status"] == "ROLLED_BACK" and f"{CR}main.tf" in ckw["validation_error"]


def test_route_without_a_real_parser_refuses_typed_and_commits_nothing(monkeypatch):
    _no_parser(monkeypatch)
    wl, err, prov, rec = _run_upgrade(monkeypatch, _workload_tree(drift=True), engine=_engine_writing(BAD_ROUTE))
    assert isinstance(err, wl.HTTPException) and err.status_code == 400
    assert err.detail.startswith("Pre-flight IaC validation failed: IAC_PREFLIGHT_PARSER_REFUSED: ")
    assert f"{CR}main.tf" in err.detail and "syntax error" not in err.detail.lower()
    assert prov.commits == [] and prov.branches == []
    (_, ckw), = rec["complete"]
    assert ckw["status"] == "ROLLED_BACK"


@needs_tofu
def test_route_commits_valid_hcl_that_python_hcl2_refuses(monkeypatch):
    ok = {CR + "main.tf": F1_VALID[0]}
    _, out, prov, _ = _run_upgrade(monkeypatch, _workload_tree(drift=True), engine=_engine_writing(ok))
    ((written, _),) = prov.commits
    assert written[CR + "main.tf"] == F1_VALID[0] and out["status"] == "SUCCESS"


def test_route_accepts_a_lone_brace_in_a_string(monkeypatch):
    _no_parser(monkeypatch)
    ok = {CR + "main.tf": 'locals {\n  open = "{"\n}\n'}  # the old pre-flight refused this valid file
    _, out, prov, _ = _run_upgrade(monkeypatch, _workload_tree(drift=True), engine=_engine_writing(ok))
    ((written, _),) = prov.commits
    assert written[CR + "main.tf"] == ok[CR + "main.tf"] and out["status"] == "SUCCESS"


def test_route_has_no_brace_count_left():
    src = open(os.path.join(REPO_ROOT, "apps", "control-center", "routes", "workloads.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)
              and n.name == "trigger_workload_iac_upgrade")
    counts = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr == "count"]
    assert counts == []


# =============================================================================================== Serverless client
class _Resp:
    def __init__(self, code, body=None):
        self.status_code, self._body, self.text = code, body if body is not None else {}, "x"
        self.headers = {"X-StackVend-Git-Server": "1"}   # GIT-404-TYPED: the git server's own answer

    def json(self):
        return self._body


def _client_provider(monkeypatch, *responses):
    calls = []
    queue = list(responses)

    def post(url, **kw):
        calls.append((url, kw.get("json")))
        return queue.pop(0)

    monkeypatch.setattr(sgp, "requests", MagicMock(post=post))
    prov = sgp.ServerlessGitProvider(server_url="https://git.example.invalid", project_id="mock-stackvend-project")
    monkeypatch.setattr(prov, "_get_headers", lambda: {})
    return prov, calls


def test_serverless_commit_without_deletions_is_the_old_request(monkeypatch):
    """Do No Harm: same route, same payload keys (no files_to_delete key at all)."""
    for dels in (None, []):
        prov, calls = _client_provider(monkeypatch, _Resp(200, {"commit_sha": "c" * 40}))
        kw = {} if dels is None else {"files_to_delete": dels}
        assert prov.commit_files("castor/app", "main", {"a.tf": "x"}, "m", **kw) == "c" * 40
        ((url, payload),) = calls
        assert url == "https://git.example.invalid/api/v1/repos/app/commits"
        assert set(payload) == {"branch", "files", "commit_message", "author_name", "author_email"}


def test_serverless_commit_with_deletions_uses_its_own_route(monkeypatch):
    prov, calls = _client_provider(monkeypatch, _Resp(200, {"commit_sha": "d" * 40, "files_deleted": [LEGACY]}))
    assert prov.commit_files("castor/app", "b1", {"a.tf": "x"}, "m", files_to_delete=[LEGACY]) == "d" * 40
    ((url, payload),) = calls
    assert url == "https://git.example.invalid/api/v1/repos/app/commits-with-deletions"
    assert payload["files_to_delete"] == [LEGACY] and payload["files"] == {"a.tf": "x"}


def test_old_git_server_refuses_loudly_and_nothing_else_is_sent(monkeypatch):
    prov, calls = _client_provider(monkeypatch, _Resp(404, {"detail": "Not Found"}))
    with pytest.raises(sgp.ServerlessGitDeletionUnsupported) as ei:
        prov.commit_files("castor/app", "b1", {"a.tf": "x"}, "m", files_to_delete=[LEGACY])
    assert "Nothing was committed" in str(ei.value) and len(calls) == 1
    assert ei.value.error_class == "VCS_DELETION_UNSUPPORTED"


@pytest.mark.parametrize("body", [{"commit_sha": "d" * 40}, {"files_deleted": []}, {}])
def test_an_answer_without_the_deletion_evidence_is_an_error(monkeypatch, body):
    prov, _ = _client_provider(monkeypatch, _Resp(200, body))
    with pytest.raises(sgp.ServerlessGitError):
        prov.commit_files("castor/app", "b1", {}, "m", files_to_delete=[LEGACY])


# =============================================================================================== real git server
@pytest.fixture()
def git_server(monkeypatch):
    from fd4k_support import load_git_server

    mod, client, outer = load_git_server(monkeypatch)
    assert client.post("/api/v1/repos", json={"product_id": "app"}).status_code == 201
    tree = dict(FIXTURE, **{LEGACY: "# legacy\n", CR + "variables.tf": "# vars\n"})
    assert client.post("/api/v1/repos/app/commits", json={"branch": "main", "files": tree}).status_code == 200
    yield mod, client, _tree(client)
    shutil.rmtree(outer, ignore_errors=True)


def _tree(client, branch="main"):
    return client.get(f"/api/v1/repos/app/tree/{branch}").json()["files"]


def test_git_server_commit_with_deletions_removes_exactly_those_files(git_server):
    mod, client, tree = git_server
    r = client.post("/api/v1/repos/app/commits-with-deletions", json={
        "branch": "main", "files": {CR + "main.tf": "# v2\n"},
        "files_to_delete": [LEGACY, CR + "absent.tf"]})
    assert r.status_code == 200, r.text
    assert r.json()["files_deleted"] == [LEGACY]           # an absent path is not an error and not reported
    after = _tree(client)
    assert LEGACY not in after and after[CR + "main.tf"] == "# v2\n"
    assert {p: c for p, c in after.items() if p not in (LEGACY, CR + "main.tf")} == \
        {p: c for p, c in tree.items() if p not in (LEGACY, CR + "main.tf")}


def test_git_server_plain_commit_is_unchanged(git_server):
    """Do No Harm: /commits never deletes. GIT-COMMITS-STRICT: a key it does not know (here `files_to_delete`) is
    a 422 before anything is written, instead of a commit that silently keeps the paths."""
    mod, client, tree = git_server
    r = client.post("/api/v1/repos/app/commits", json={"branch": "main", "files": {"new.txt": "n"},
                                                         "files_to_delete": [LEGACY]})
    assert r.status_code == 422, r.text
    assert _tree(client) == tree and LEGACY in tree
    r = client.post("/api/v1/repos/app/commits", json={"branch": "main", "files": {"new.txt": "n"}})
    assert r.status_code == 200 and "files_deleted" not in r.json()
    assert _tree(client) == dict(tree, **{"new.txt": "n"})


@pytest.mark.parametrize("body,code", [
    ({"branch": "main", "files": {"a.tf": "x"}, "files_to_delete": ["a.tf"]}, 422),   # written and deleted
    ({"branch": "main", "files": {}, "files_to_delete": []}, 422),                    # nothing to delete
    ({"branch": "main", "files": {}, "files_to_delete": ["../escape.tf"]}, 422),   # same rule as written keys
    ({"branch": "main", "files": {}, "files_to_delete": [".git/config"]}, 422),
    ({"branch": "main", "files": {}, "files_to_delete": ["/abs.tf"]}, 422),
])
def test_git_server_rejects_bad_deletions_before_writing(git_server, body, code):
    mod, client, tree = git_server
    r = client.post("/api/v1/repos/app/commits-with-deletions", json=body)
    assert r.status_code == code, r.text
    assert _tree(client) == tree


def test_git_server_deletion_route_needs_an_existing_repo_and_a_caller(git_server):
    mod, client, _ = git_server
    body = {"branch": "main", "files": {}, "files_to_delete": [LEGACY]}
    assert client.post("/api/v1/repos/other/commits-with-deletions", json=body).status_code == 404
    assert not os.path.isdir(mod.get_repo_path("other"))   # no auto-init
    from fastapi.testclient import TestClient

    anon = TestClient(mod.app)
    assert anon.post("/api/v1/repos/app/commits-with-deletions", json=body).status_code == 401


def _client_on(monkeypatch, client):
    """The real ServerlessGitProvider._call on the git server's TestClient (no network)."""
    class _Req:
        @staticmethod
        def post(url, headers=None, timeout=None, allow_redirects=False, **kw):
            return client.post(url, **kw)

        @staticmethod
        def get(url, headers=None, timeout=None, allow_redirects=False, **kw):
            return client.get(url, **kw)

    monkeypatch.setattr(sgp, "requests", _Req)
    prov = sgp.ServerlessGitProvider(server_url="http://testserver", project_id="mock-stackvend-project")
    monkeypatch.setattr(prov, "_get_headers", lambda: {})
    return prov


def test_client_and_server_end_to_end(git_server, monkeypatch):
    mod, client, tree = git_server
    prov = _client_on(monkeypatch, client)
    sha = prov.commit_files("castor/app", "main", {CR + "main.tf": "# v3\n"}, "m", files_to_delete=[LEGACY])
    assert len(sha) == 40 and LEGACY not in _tree(client)


def test_old_server_and_new_client_commit_nothing(git_server, monkeypatch):
    """An older git server has no deletion route: the client refuses and the branch is untouched."""
    mod, client, tree = git_server
    mod.app.router.routes[:] = [r for r in mod.app.router.routes
                                if getattr(r, "path", "") != "/api/v1/repos/{product_id}/commits-with-deletions"]
    prov = _client_on(monkeypatch, client)
    with pytest.raises(sgp.ServerlessGitDeletionUnsupported):
        prov.commit_files("castor/app", "main", {CR + "main.tf": "# v3\n"}, "m", files_to_delete=[LEGACY])
    assert _tree(client) == tree


# =============================================================================================== commit_and_open_pr
def _agent():
    if GW_DIR not in sys.path:
        sys.path.insert(0, GW_DIR)
    from developer_agent import handler as h

    agent = h.DeveloperAgent.__new__(h.DeveloperAgent)
    agent.db, agent.project_id, agent.vcs_provider, agent.github_owner = None, "", "GITHUB", "castor-org"
    agent.genai_client = MagicMock(name="llm")
    return h, agent


class _Verifier:
    """Records the tree it checks; `cure` maps path -> new content (applied when the path is present); the cure
    drops the `purge` paths (FD-55 W8: the pre-commit gate is one verify_and_cure call, no separate package pass)."""
    seen = []
    cure = {}
    purge = ()

    def __init__(self, product_id=None):
        pass

    def verify_and_cure(self, files, product_id=None, **kw):
        type(self).seen.append(dict(files))
        return {p: self.cure.get(p, c) for p, c in files.items() if p not in self.purge}, True, []


class _VCS:
    def __init__(self):
        self.commits = []

    def create_or_verify_branch(self, repo, branch, source_branch="main"):
        return None

    def commit_files(self, repo, branch, files, msg, **kw):
        self.commits.append((dict(files), dict(kw)))
        return "e" * 40

    def create_pull_request(self, repo, **kw):
        return {"pull_request_url": "https://example.invalid/pull/9", "pr_number": 9}


def _commit(files, *, cure=None, purge=(), vcs=None, **kw):
    h, agent = _agent()
    vcs = vcs or _VCS()
    verifier = type("V", (_Verifier,), {"seen": [], "cure": dict(cure or {}), "purge": tuple(purge)})
    token = MagicMock(return_value="test-token")
    with patch.object(h, "SynthesisVerifierAgent", verifier), \
            patch.object(h.VCSProviderFactory, "get_provider", return_value=vcs), \
            patch.object(h.time, "sleep", return_value=None), \
            patch.object(agent, "get_full_repo_name", return_value="castor-org/castor-app", create=True), \
            patch.object(agent, "fetch_github_token", token, create=True), \
            patch.object(agent, "_write_iac_provenance") as prov:
        try:
            res = agent.commit_and_open_pr(product_id="app", files=dict(files), branch_name="iac-upgrade/app-1", **kw)
        except Exception as e:  # noqa: BLE001
            return e, vcs, verifier, token, prov
    return res, vcs, verifier, token, prov


TREE = {"apps/app/main.py": "print('ok')\n", "infra/workload/main.tf": "# root\n", CR + "main.tf": "# new\n",
        MANIFEST: "{}"}


@pytest.mark.parametrize("cure", [{}, {"apps/app/main.py": "print('cured')\n"}])
@pytest.mark.parametrize("extra", [{}, {"commit_paths": None, "files_to_delete": None}, {"files_to_delete": []}])
def test_default_commit_is_unchanged_for_every_caller(cure, extra):
    """Negative: without commit_paths / files_to_delete the whole (cured) tree is written with the old 4-argument
    call, and the result has the old keys only."""
    from _fake_vcs import FakeVCS

    res, vcs, verifier, _, prov = _commit(TREE, cure=cure, vcs=FakeVCS(), **extra)   # FakeVCS: 4 positional args
    expected = {p: cure.get(p, c) for p, c in TREE.items()}
    assert vcs.commits == [expected]
    assert res["status"] == "COMMITTED" and res["files_committed"] == list(expected)
    assert "files_deleted" not in res
    assert verifier.seen == [TREE]
    prov.assert_called_once_with("app", None, expected)


def test_every_other_caller_passes_no_split():
    """Negative (static): only the IAC_UPGRADE branch uses commit_paths / files_to_delete."""
    split = []
    for rel in ("apps/orchestrator-gateway/main.py", "eval/stackvend_eval/stages.py"):
        src = open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read()
        for n in ast.walk(ast.parse(src)):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "commit_and_open_pr":
                kws = {k.arg for k in n.keywords}
                if kws & {"commit_paths", "files_to_delete"}:
                    split.append((rel, n.lineno))
    assert len(split) == 1 and split[0][0] == "apps/orchestrator-gateway/main.py"


def test_split_commit_writes_only_the_commit_paths_with_the_gate_bytes():
    paths = [CR + "main.tf", MANIFEST]
    res, vcs, verifier, _, prov = _commit(TREE, cure={CR + "main.tf": "# new, cured\n"},
                                          commit_paths=paths, files_to_delete=[LEGACY])
    assert verifier.seen == [TREE]                                    # the gate saw the whole tree
    ((written, kw),) = vcs.commits
    assert written == {CR + "main.tf": "# new, cured\n", MANIFEST: "{}"}
    assert kw == {"files_to_delete": [LEGACY]}
    assert res["files_committed"] == paths and res["files_deleted"] == [LEGACY]


def test_split_commit_without_deletions_sends_no_deletion_keyword():
    res, vcs, *_ = _commit(TREE, commit_paths=[CR + "main.tf"])
    ((written, kw),) = vcs.commits
    assert written == {CR + "main.tf": "# new\n"} and kw == {} and "files_deleted" not in res


def test_a_cure_outside_the_commit_set_is_a_gate_verdict_and_nothing_is_committed():
    from gate_errors import GateFailedError

    err, vcs, _, token, _ = _commit(TREE, cure={"apps/app/main.py": "print('cured')\n"},
                                    commit_paths=[CR + "main.tf", MANIFEST])
    assert isinstance(err, GateFailedError) and err.reason == "PRECOMMIT_CURE_OUTSIDE_COMMIT_SET"
    assert err.stage == "developer" and "apps/app/main.py" in str(err) and "committed first" in str(err)
    assert err.details["changed_outside"] == ["apps/app/main.py"]
    assert vcs.commits == [] and not token.called


@pytest.mark.parametrize("purge,key", [(["apps/app/main.py"], "changed_outside"), ([CR + "main.tf"], "dropped")])
def test_a_purge_inside_or_outside_the_commit_set_is_a_gate_verdict(purge, key):
    from gate_errors import GateFailedError

    err, vcs, *_ = _commit(TREE, purge=purge, commit_paths=[CR + "main.tf"])
    assert isinstance(err, GateFailedError) and err.reason == "PRECOMMIT_CURE_OUTSIDE_COMMIT_SET"
    assert err.details[key] == purge and vcs.commits == []


@pytest.mark.parametrize("kw,field", [
    ({"commit_paths": ["missing.tf"]}, "not_in_tree"),
    ({"commit_paths": [CR + "main.tf"], "files_to_delete": ["apps/app/main.py"]}, "deleted_but_in_tree"),
    ({"files_to_delete": [CR + "main.tf"]}, "deleted_but_in_tree"),
])
def test_an_invalid_split_is_refused_before_the_gate(kw, field):
    from gate_errors import PlatformDefectError

    err, vcs, verifier, token, _ = _commit(TREE, **kw)
    assert isinstance(err, PlatformDefectError) and err.reason == "COMMIT_SET_INVALID" and err.details[field]
    assert verifier.seen == [] and vcs.commits == [] and not token.called


def test_rest_fallback_writes_the_commit_set_and_deletes_with_null_sha():
    """The PyGithub REST path (no VCS provider, no git binary) honours the split too."""
    h, agent = _agent()
    repo = MagicMock(name="repo")
    gh = MagicMock(name="gh")
    gh.get_repo.return_value = repo
    verifier = type("V", (_Verifier,), {"seen": [], "cure": {}, "purge": ()})
    with patch.object(h, "SynthesisVerifierAgent", verifier), patch.object(h, "VCSProviderFactory", None), \
            patch.object(h.shutil, "which", return_value=None), patch.object(h, "Github", return_value=gh), \
            patch.object(h.time, "sleep", return_value=None), \
            patch.object(agent, "get_full_repo_name", return_value="castor-org/castor-app", create=True), \
            patch.object(agent, "fetch_github_token", return_value="test-token", create=True), \
            patch.object(agent, "_write_iac_provenance"):
        res = agent.commit_and_open_pr(product_id="app", files=dict(TREE), branch_name="iac-upgrade/app-1",
                                       commit_paths=[CR + "main.tf"], files_to_delete=[LEGACY])
    assert res["status"] == "SUCCESS", res
    elements = repo.create_git_tree.call_args[0][0]
    ids = [e._identity for e in elements]
    assert ids == [{"path": CR + "main.tf", "mode": "100644", "type": "blob", "content": "# new\n"},
                   {"path": LEGACY, "mode": "100644", "type": "blob", "sha": None}]


# =============================================================================================== gateway IAC_UPGRADE
def _gateway_upgrade(monkeypatch, tree, modules=("compute-cloudrun",)):
    gw = _gateway_main()
    prov = _RecordingProvider(tree)
    import shared.vcs_provider as vp

    monkeypatch.setattr(vp.VCSProviderFactory, "get_provider", staticmethod(lambda *a, **k: prov))
    monkeypatch.setattr(gw, "db", FS)
    monkeypatch.setattr(gw, "_record_pr_ledger", lambda *a, **k: None)
    req = gw.DeveloperExecuteRequest(product_id="app", trace_id="tr-1", change_type="IAC_UPGRADE",
                                     modules_to_upgrade=list(modules))
    return gw, prov, req


def test_gateway_upgrade_gates_the_whole_tree_and_commits_only_the_module_files(monkeypatch):
    tree, other_extra = _tree_with_dropped_files()
    gw, prov, req = _gateway_upgrade(monkeypatch, tree)
    h, agent = _agent()
    verifier = type("V", (_Verifier,), {"seen": [], "cure": {}, "purge": ()})
    monkeypatch.setattr(gw, "developer_agent", agent)
    with patch.object(h, "SynthesisVerifierAgent", verifier), \
            patch.object(h.VCSProviderFactory, "get_provider", return_value=prov), \
            patch.object(h.time, "sleep", return_value=None), \
            patch.object(agent, "get_full_repo_name", return_value="castor-org/castor-app", create=True), \
            patch.object(agent, "fetch_github_token", return_value="test-token", create=True), \
            patch.object(agent, "_write_iac_provenance"):
        out = gw.developer_execute(req)
    (gated,) = verifier.seen
    assert set(gated) == set(tree) - {LEGACY}                  # the merged tree: app code and every module
    assert gated["apps/api/main.py"] == tree["apps/api/main.py"] and other_extra in gated
    ((written, kw),) = prov.commits
    assert set(written) == {CR + "main.tf", MANIFEST}
    assert written[CR + "main.tf"] == _canonical("compute-cloudrun")[CR + "main.tf"]
    assert kw == {"files_to_delete": [LEGACY]}
    assert out["status"] == "SUCCESS" and out["files_count"] == 2 and out["files_deleted"] == [LEGACY]


def test_gateway_upgrade_passes_the_split_to_commit_and_open_pr(monkeypatch):
    tree, _ = _tree_with_dropped_files()
    gw, prov, req = _gateway_upgrade(monkeypatch, tree)
    dev = MagicMock()
    dev.commit_and_open_pr.return_value = {"status": "COMMITTED", "pull_request_url": "https://example.invalid/p/1"}
    monkeypatch.setattr(gw, "developer_agent", dev)
    gw.developer_execute(req)
    kw = dev.commit_and_open_pr.call_args.kwargs
    assert set(kw["files"]) == set(tree) - {LEGACY} and kw["files"][MANIFEST] != tree[MANIFEST]
    assert sorted(kw["commit_paths"]) == sorted([CR + "main.tf", MANIFEST])
    assert kw["files_to_delete"] == [LEGACY]


def test_gateway_upgrade_with_nothing_to_upgrade_commits_nothing(monkeypatch):
    gw, prov, req = _gateway_upgrade(monkeypatch, _workload_tree(drift=False), modules=())
    dev = MagicMock()
    monkeypatch.setattr(gw, "developer_agent", dev)
    out = gw.developer_execute(req)
    assert out["status"] == "SUCCESS" and out["files_count"] == 0 and out["pull_request_url"] == ""
    dev.commit_and_open_pr.assert_not_called()
    assert prov.commits == [] and prov.branches == []


def test_gateway_upgrade_engine_removal_outside_the_module_is_a_typed_defect(monkeypatch):
    eng = _engine()
    tree, _ = _tree_with_dropped_files()
    gw, prov, req = _gateway_upgrade(monkeypatch, tree)
    real = eng.upgrade_workload_iac_vendoring

    def lossy(files, **kw):
        updated, mods, details = real(files, **kw)
        updated.pop("infra/human.tf")
        return updated, mods, details

    for mod in {sys.modules.get("shared.iac_upgrade_engine"), eng}:
        monkeypatch.setattr(mod, "upgrade_workload_iac_vendoring", lossy)
    dev = MagicMock()
    monkeypatch.setattr(gw, "developer_agent", dev)
    from gate_errors import PlatformDefectError

    with pytest.raises(PlatformDefectError) as ei:
        gw.developer_execute(req)
    assert ei.value.reason == "IAC_UPGRADE_DELETION_SCOPE" and "infra/human.tf" in str(ei.value)
    dev.commit_and_open_pr.assert_not_called()

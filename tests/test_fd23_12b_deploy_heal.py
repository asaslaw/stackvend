"""FD23-12b (+ FD23-12a), register row HS-68: apply-time healers HC-11 / HA-11 are REPORT-ONLY.

In ``TerraformService.deploy_workload`` (mcp-servers/terraform/service.py) the Shift-Left HC-11 block (foundation
remap + secret/topic/bucket synthesis) and the HA-11 block (prune the failing resource block) used to write the
workspace ``custom.tf`` and then reference ``healed_files_to_sync`` (a local of ``prepare_workspace``) -> NameError,
caught, no re-validation. HC-11's synthesis guard also called ``files.get`` while ``files`` had been rebound to an
``os.walk`` list (FD23-12a) -> AttributeError.

HS-68: both blocks compute the would-be change in memory only, attach typed ``heal_findings`` to the
VALIDATION_FAILED result, never write the workspace, never re-validate, and the deploy returns the original error
exactly as before. The ``os.walk`` loop variable is renamed (``walk_files``). No hardcoded region is emitted.

S2-F (proposed row with the HB-13 deletion, not approved): the two report-only blocks are deleted (0 fires on the
94 committed cassette trees; ``heal_findings`` had no consumer). These tests keep the HS-68 guarantees (fail closed
with the original error, one validate, workspace byte-identical) and tombstone the blocks.

Hermetic: ``prepare_workspace`` is stubbed to a tmp workspace, every subprocess is faked, no network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib
import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVICE_PY = os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py")

MAIN_TF = (
    'module "foundation" {\n'
    '  source     = "./infra/modules/workload-foundation"\n'
    "  project_id = var.project_id\n"
    "}\n\n"
    'resource "google_pubsub_topic" "events" {\n'
    "  project = var.project_id\n"
    '  name    = "events"\n'
    "}\n"
)

# Triggers HC-11 (a foundation remap + an undeclared secret + an undeclared bucket; the topic IS declared in
# main.tf, which exercises the FD23-12a `files.get("main.tf")` guard) and HA-11 (the failing block is named).
CUSTOM_TF = (
    'resource "google_secret_manager_secret_version" "api_key_v" {\n'
    "  secret      = google_secret_manager_secret.api_key.id\n"
    '  secret_data = "placeholder"\n'
    "}\n\n"
    'resource "google_project_iam_member" "sa_invoker" {\n'
    "  project = var.project_id\n"
    '  role    = "roles/pubsub.publisher"\n'
    '  member  = "serviceAccount:${google_service_account.workload_sa.email}"\n'
    "}\n\n"
    'resource "google_storage_bucket_object" "seed" {\n'
    "  bucket  = google_storage_bucket.assets.name\n"
    '  name    = "seed.json"\n'
    '  content = google_pubsub_topic.events.id\n'
    "}\n"
)

UNDECLARED_ERR = (
    "\nError: Reference to undeclared resource\n\n"
    '  on custom.tf line 2, in resource "google_secret_manager_secret_version" "api_key_v":\n'
    "   2:   secret      = google_secret_manager_secret.api_key.id\n\n"
    'A managed resource "google_secret_manager_secret" "api_key" has not been declared in the root module.\n'
)

# Already remapped (module.foundation.*) and every secret ref declared in custom.tf: HC-11's trigger fires on
# UNDECLARED_ERR but there is nothing it would change (the realistic production case after HB-13).
CLEAN_CUSTOM_TF = (
    'resource "google_secret_manager_secret" "k" {\n  secret_id = "k"\n}\n\n'
    'resource "google_secret_manager_secret_version" "v" {\n  secret = google_secret_manager_secret.k.id\n}\n\n'
    'resource "google_project_iam_member" "m" {\n  member = "serviceAccount:${module.foundation.workload_sa_email}"\n}\n'
)

# The failing resource is in main.tf (the message mentions custom.tf elsewhere): HA-11's preview prunes nothing.
# Uses a type HC-10 ignores (an error naming google_cloud_run_v2_service fires the pre-existing HC-10 healer).
MAIN_TF_ERR = (
    "\nError: Reference to undeclared resource\n\n"
    '  on main.tf line 5, in resource "google_pubsub_subscription" "sub":\n'
    "   5:   x = google_secret_manager_secret.api_key.id\n\n"
    'A managed resource "google_secret_manager_secret" "api_key" has not been declared in the root module. See custom.tf.\n'
)

UNRELATED_ERR = '\nError: Unsupported argument\n\n  on custom.tf line 3:\n   3:   secret_data_x = "placeholder"\n'

OK = {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}


def _snapshot(ws):
    out = {}
    for root, dirs, names in os.walk(ws):
        dirs[:] = [d for d in dirs if d != ".terraform"]
        for n in names:
            p = os.path.join(root, n)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, ws)] = fh.read()
    return out


def _fake_module(monkeypatch, dotted):
    """Replace ``dotted`` with a MagicMock both in sys.modules and as an attribute of its parent package, so
    ``import a.b`` + ``a.b.x``, ``from a import b`` and ``from a.b import x`` all resolve to the fake, whatever other
    root tests left in sys.modules (the full suite re-imports google.* namespace packages). The real module is never
    imported (in a polluted full-suite process that can fail half-way)."""
    parent_name, leaf = dotted.rsplit(".", 1)
    fake = MagicMock(name=dotted)
    monkeypatch.setitem(sys.modules, dotted, fake)
    parent = sys.modules.get(parent_name)
    if parent is None and "." not in parent_name:
        parent = importlib.import_module(parent_name)  # the top-level `google` namespace package
    if parent is not None:
        monkeypatch.setattr(parent, leaf, fake, raising=False)
    return fake


@pytest.fixture
def svc_mod(monkeypatch):
    from fd4g_support import load_tf_service

    mod = load_tf_service(monkeypatch)
    # deploy_workload's best-effort cloud lookups (OAuth secrets, API keys, API enablement, IdP domains): no network.
    _fake_module(monkeypatch, "google.cloud.secretmanager")
    _fake_module(monkeypatch, "google.auth.transport.requests")
    _fake_module(monkeypatch, "google.auth").default.return_value = (MagicMock(), "p")
    import httpx

    monkeypatch.setattr(httpx, "Client", MagicMock(name="httpx.Client"))
    return mod


def _run_deploy(svc_mod, tmp_path, validate_results, custom_tf=CUSTOM_TF):
    """Run deploy_workload against a hand-built workspace. ``validate_results`` is the sequence returned by
    successive `validate` calls. Returns (result, calls, workspace, snapshot taken at the first validate)."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "main.tf").write_text(MAIN_TF, encoding="utf-8")
    (ws / "custom.tf").write_text(custom_tf, encoding="utf-8")
    calls = []
    at_validate = {}
    results = list(validate_results)

    def fake_run(self, cmd, *a, **k):
        if len(cmd) > 1 and cmd[1] == "validate" and "-json" in cmd:
            # DEPLOY-FAILURE-OWNER-ROUTER: the read-only `validate -json` that names the failing file's owner
            calls.append("validate-json")
            return dict(OK)
        calls.append(cmd[1] if len(cmd) > 1 else cmd[0])
        if len(cmd) > 1 and cmd[1] == "validate":
            if not at_validate:
                at_validate.update(_snapshot(str(ws)))
            return results.pop(0) if results else dict(OK)
        if len(cmd) > 1 and cmd[1] == "output":
            return {"success": True, "exit_code": 0, "stdout": "{}", "stderr": ""}
        return dict(OK)

    TS = svc_mod.TerraformService
    svc = TS(project_id="host-project", workspace_base_dir=str(tmp_path / "base"), firestore_client=MagicMock())
    with patch.object(TS, "prepare_workspace", return_value=str(ws)), \
            patch.object(TS, "_run_subprocess", fake_run), \
            patch.object(TS, "_fetch_repo_files", return_value={}), \
            patch.object(TS, "_build_and_push_container", return_value="img"), \
            patch.object(TS, "_ensure_binary", return_value="tofu"), \
            patch.object(TS, "_ensure_provider_mirror", return_value=""):
        res = svc.deploy_workload(
            product_id="testapp",
            trace_id="t-fd23-12b",
            hcl_files={"main.tf": MAIN_TF, "custom.tf": custom_tf},
            target_project_id="target-project-123",
        )
    return res, calls, ws, at_validate


def _fail(stderr):
    return {"success": False, "exit_code": 1, "stdout": "", "stderr": stderr}


def _assert_fail_closed(res, calls, ws, at_validate, err):
    """The deploy fails closed with the ORIGINAL engine error, exactly one validate, no apply, nothing written."""
    assert res["status"] == "VALIDATION_FAILED"
    # DEPLOY-FAILURE-OWNER-ROUTER: the engine gave no typed location here (repository-root layout, no -json output),
    # so the failure is not the developer's: typed UNKNOWN, the original engine error kept verbatim at the end
    assert res["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED" and res["operator_required"] is True
    assert res["error"].endswith(f"Engine error: Shift-Left IaC validation failed:\n{err}")
    assert res["stderr"] == err
    assert "heal_findings" not in res  # S2-F: HC-11 / HA-11 deleted (were report-only since HS-68)
    assert calls.count("validate") == 1 and calls.count("validate-json") == 1
    assert "apply" not in calls
    assert at_validate and _snapshot(str(ws)) == at_validate


def test_undeclared_reference_fails_closed_unchanged(svc_mod, tmp_path, caplog):
    """The HC-11 + HA-11 trigger input: same outcome as under HS-68 (fail-closed, original error, workspace
    byte-identical), minus the unconsumed `heal_findings` analysis."""
    caplog.set_level(logging.INFO)
    res, calls, ws, at_validate = _run_deploy(svc_mod, tmp_path, [_fail(UNDECLARED_ERR)])
    _assert_fail_closed(res, calls, ws, at_validate, UNDECLARED_ERR)
    assert (ws / "custom.tf").read_text(encoding="utf-8") == CUSTOM_TF
    # Invariant 3: no stub HCL (and so no hardcoded bucket region) anywhere in the result. FD-7M-a (SAT-22): the
    # result's own `region` field is the deploy's resolved region (here the env default), not stub HCL.
    assert "us-central1" not in repr({k: v for k, v in res.items() if k != "region"})
    # SAT-22 RT F4: non-vacuous: the field is the platform region the service resolves for this (MagicMock) client.
    assert isinstance(res.get("region"), str) and res["region"]
    assert res["region"] == svc_mod.resolve_platform_region(MagicMock())
    msgs = [r.getMessage() for r in caplog.records]
    assert not [m for m in msgs if "HC-11" in m or "HA-11" in m or "healed_files_to_sync" in m
                or "has no attribute 'get'" in m]


def test_validate_valid_workspace_is_untouched(svc_mod, tmp_path, caplog):
    """Do No Harm negative: validate passes -> custom.tf byte-identical, no findings."""
    caplog.set_level(logging.WARNING)
    res, calls, ws, at_validate = _run_deploy(svc_mod, tmp_path, [dict(OK)])
    assert res["status"] != "VALIDATION_FAILED"
    assert "heal_findings" not in res
    assert calls.count("validate") == 1
    assert (ws / "custom.tf").read_text(encoding="utf-8") == CUSTOM_TF
    assert at_validate["custom.tf"] == CUSTOM_TF.encode("utf-8")
    assert not [r for r in caplog.records if "HC-11" in r.getMessage() or "HA-11" in r.getMessage()]


@pytest.mark.parametrize("err,custom_tf", [(UNRELATED_ERR, CUSTOM_TF), (UNDECLARED_ERR, CLEAN_CUSTOM_TF),
                                           (MAIN_TF_ERR, CUSTOM_TF)],
                         ids=["unrelated_error", "trigger_nothing_to_heal", "failing_block_in_main_tf"])
def test_other_validation_errors_fail_closed_unchanged(svc_mod, tmp_path, err, custom_tf):
    res, calls, ws, at_validate = _run_deploy(svc_mod, tmp_path, [_fail(err)], custom_tf=custom_tf)
    _assert_fail_closed(res, calls, ws, at_validate, err)
    assert (ws / "custom.tf").read_text(encoding="utf-8") == custom_tf


def test_hc11_ha11_tombstone():
    """S2-F: no function in service.py binds `heal_findings` or emits an APPLY.HEAL_SUPPRESSED finding."""
    with open(SERVICE_PY, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    assert not [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "heal_findings"]
    assert not [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value == "APPLY.HEAL_SUPPRESSED"]


def _undefined_names(path):
    from pyflakes import checker, messages

    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    return sorted(
        f"{m.lineno}: {m.message_args[0]}"
        for m in checker.Checker(tree, filename=path).messages
        if isinstance(m, messages.UndefinedName)
    )


def test_terraform_service_has_no_undefined_names():
    """Static gate (pyflakes F821 class): the `healed_files_to_sync` NameErrors at apply time are gone."""
    assert _undefined_names(SERVICE_PY) == []


def _is_workspace_walk(node):
    """`for ... in os.walk(workspace_dir)`."""
    it = node.iter
    return (
        isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and it.func.attr == "walk"
        and isinstance(it.func.value, ast.Name) and it.func.value.id == "os"
        and bool(it.args) and isinstance(it.args[0], ast.Name) and it.args[0].id == "workspace_dir"
    )


def test_api_gate_walk_does_not_shadow_files():
    """FD23-12a: in the deploy body (selected by content, not by name: lane 14 PR-0 moves it into
    `_deploy_workload_impl`), no `for ... files ... in os.walk(workspace_dir)` rebinds the repo-file dict `files`."""
    with open(SERVICE_PY, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    deploy_bodies = [
        fn for fn in ast.walk(tree)
        if isinstance(fn, ast.FunctionDef)
        and any(isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value.startswith("Shift-Left IaC validation failed:") for n in ast.walk(fn))
    ]
    assert deploy_bodies, "no function returns the Shift-Left VALIDATION_FAILED error (deploy body not found)"
    for fn in deploy_bodies:
        walks = [n for n in ast.walk(fn) if isinstance(n, ast.For) and _is_workspace_walk(n)]
        assert walks, f"{fn.name}: the os.walk(workspace_dir) API-gate loop was not found (test would be vacuous)"
        rebinds = [
            n.lineno for n in ast.walk(fn)
            if isinstance(n, ast.For) and any(isinstance(t, ast.Name) and t.id == "files" for t in ast.walk(n.target))
        ]
        assert rebinds == [], fn.name

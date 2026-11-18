"""DEPLOY-FAILURE-OWNER-ROUTER (register row, owner 11-13; plan docs/planning/deploy-failure-owner-router-plan.md).

A failed deploy is routed by who can change what failed, from typed engine fields only:
- the terraform server's classifier (mcp-servers/terraform/deploy_failure_router.py + TerraformService) driven by
  recorded `tofu plan -json` / `validate -json` diagnostics (shapes recorded from OpenTofu 1.13.1, JSON UI 1.2; the
  workspace path is substituted), as a scenario matrix;
- the real deploy (`deploy_workload`) on a plan failure in the golden module (the 11-12 SA trailing-dash shape) and on
  an apply failure;
- the workflow paths (tests/workflow_sim.py) for every router verdict, FULL and DEPLOY_ONLY;
- the gateway's remediation allow-list;
- (the Control Center's report class: tests/test_deploy_failure_owner_router_cc.py);
- parity with artifact_ownership, the gateway constants, the CC classes and the workflow's operator list.

Negative tests (Do No Harm): a developer-owned failure leaves the deploy result unchanged (no class, no flag, same
error text) and is remediated exactly as before; typed classes are unchanged; an operator's RESUME_DEVELOPER first
dispatch is not checked. Hermetic: no network, no cloud clients (the one real-OpenTofu test is skipped without tofu and
uses only the built-in provider).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import types
from unittest.mock import MagicMock

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
sys.path.insert(0, os.path.dirname(__file__))

from fd4f_support import FakeDB, gw  # noqa: F401,E402  (gw is a fixture)
from test_lane17_workflow_sim import Fleet, assert_failed, calls, run, workflow  # noqa: F401,E402


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dfr = _load("dfr_under_test", os.path.join(TF_DIR, "deploy_failure_router.py"))


@pytest.fixture()
def tf(monkeypatch):
    from fd4g_support import load_tf_service

    return load_tf_service(monkeypatch)


# ===================================================================================== recorded engine output
# `tofu plan -json -input=false -no-color -lock=false` lines (OpenTofu 1.13.1). {WS} = the workspace directory: a
# module reached through the deploy's `../modules` link is reported by its resolved absolute path.
_VERSION = ('{"@level":"info","@message":"OpenTofu 1.13.1","@module":"tofu.ui","@timestamp":"2026-11-13T12:25:43.280634'
            '-05:00","tofu":"1.13.1","type":"version","ui":"1.2"}')
_SUMMARY = ('{"@level":"info","@message":"Plan: 0 to add, 0 to change, 0 to destroy.","@module":"tofu.ui","@timestamp":'
            '"2026-11-13T12:25:43.287426-05:00","changes":{"add":0,"change":0,"import":0,"remove":0,"forget":0,'
            '"operation":"plan"},"type":"change_summary"}')


def _diag_line(diag):
    return json.dumps({"@level": "error", "@message": "Error: " + diag["summary"], "@module": "tofu.ui",
                       "@timestamp": "2026-11-13T12:25:43.287496-05:00", "diagnostic": diag, "type": "diagnostic"})


# Recorded: an evaluation error inside the vendored golden module (range in the module body, absolute path).
GOLDEN_EVAL = {"severity": "error", "summary": "Invalid function argument",
               "detail": "Invalid value for \"v\" parameter: cannot convert \"sa-finalrun-testplan01-\" to number; "
                         "given string must be a decimal representation of a number.",
               "range": {"filename": "{WS}/infra/modules/workload-foundation/base/iam.tf",
                         "start": {"line": 6, "column": 21, "byte": 105}, "end": {"line": 6, "column": 24, "byte": 108}},
               "snippet": {"context": "resource \"terraform_data\" \"workload_sa\"",
                           "code": "  input = tonumber(\"sa-${substr(var.product_id, 0, 20)}\")", "start_line": 6,
                           "highlight_start_offset": 20, "highlight_end_offset": 23, "values": []}}
# The 11-12 SA case (register SA-ACCOUNT-ID-TRIM): the provider's ValidateFunc error on the module's account_id, on the
# recorded diagnostic shape (address = the engine's `with` resource; the production run's raw JSON was not kept).
GOLDEN_SA = {"severity": "error",
             "summary": "\"account_id\" (\"sa-finalrun-testplan01-\") must match regex "
                        "\"^[a-z]([-a-z0-9]*[a-z0-9])?$\"",
             "detail": "", "address": "module.foundation.google_service_account.workload_sa",
             "range": {"filename": "{WS}/infra/modules/workload-foundation/base/iam.tf",
                       "start": {"line": 84, "column": 18, "byte": 2940}, "end": {"line": 84, "column": 70, "byte": 2992}},
             "snippet": {"context": "resource \"google_service_account\" \"workload_sa\"",
                         "code": "  account_id   = \"sa-${substr(replace(var.product_id, \"_\", \"-\"), 0, 20)}\"",
                         "start_line": 84, "highlight_start_offset": 17, "highlight_end_offset": 69, "values": []}}
# Recorded: a developer custom.tf evaluation error (root file).
DEV_CUSTOM = {"severity": "error", "summary": "Invalid function argument",
              "detail": "Invalid value for \"v\" parameter: cannot convert \"abcfinalrun-testplan01-a\" to number; "
                        "given string must be a decimal representation of a number.",
              "range": {"filename": "custom.tf", "start": {"line": 2, "column": 21, "byte": 54},
                        "end": {"line": 2, "column": 24, "byte": 57}},
              "snippet": {"context": "resource \"terraform_data\" \"dev\"",
                          "code": "  input = tonumber(\"abc${var.product_id}\")", "start_line": 2,
                          "highlight_start_offset": 20, "highlight_end_offset": 23, "values": []}}
# Recorded: a failed input-variable validation is reported at the CALLER's argument (here the platform's main.tf).
CALLER_ARG_MAIN = {"severity": "error", "summary": "Invalid value for variable",
                   "detail": "product_id too long\n\nThis was checked by the validation rule at "
                             "modules/workload-foundation/base/iam.tf:3,3-13.",
                   "range": {"filename": "main.tf", "start": {"line": 8, "column": 16, "byte": 171},
                             "end": {"line": 8, "column": 30, "byte": 185}},
                   "snippet": {"context": "module \"foundation\"", "code": "  product_id = var.product_id",
                               "start_line": 8, "highlight_start_offset": 15, "highlight_end_offset": 29,
                               "values": []}}


def _with(diag, **range_over):
    d = json.loads(json.dumps(diag))
    d["range"].update(range_over)
    return d


def _at(diag, filename):
    return _with(diag, filename=filename)


def _no_range(diag):
    d = json.loads(json.dumps(diag))
    d.pop("range")
    return d


def _stream(*diags, ws=""):
    lines = [_VERSION, _SUMMARY] + [_diag_line(d) for d in diags]
    return "\n".join(lines).replace("{WS}", ws) + "\n"


# ===================================================================================== workspace (deploy layout)
LEGACY_MANIFEST = {"infra/workload/main.tf": "", "infra/workload/variables.tf": "", "infra/workload/outputs.tf": "",
                   "infra/workload/services.tf": "", "infra/workload/custom.tf": "", "infra/workload/human.tf": "",
                   "infra/workload/database.tf": "",
                   "infra/modules/workload-foundation/base/iam.tf": ""}


def _workspace(tmp_path, intent=False):
    """A deploy workspace as prepare_workspace leaves it: infra/workload/ flattened into the root, the vendored
    golden modules under infra/modules, `modules` -> infra/modules and the trace folder's `modules` -> the absolute
    infra/modules (the golden render's `../modules/...` sources)."""
    trace = tmp_path / "trace"
    ws = trace / "app"
    mod = ws / "infra" / "modules" / "workload-foundation" / "base"
    mod.mkdir(parents=True)
    (mod / "iam.tf").write_text("# golden module\n")
    for name in ("main.tf", "variables.tf", "outputs.tf", "services.tf", "custom.tf", "human.tf", "database.tf",
                 "backend.tf"):
        (ws / name).write_text("# file\n")
    os.symlink("infra/modules", ws / "modules")
    os.symlink(str(ws / "infra" / "modules"), trace / "modules")
    manifest = dict(LEGACY_MANIFEST)
    if intent:
        intent_doc = {"schema": "iac_intent/v1", "modules": [{"module": "storage-bucket", "name": "b", "args": {}}]}
        render = json.dumps({"//": "r", "module": {"b": {"source": "../modules/storage-bucket"}}}, indent=2)
        (ws / "iac_intent.json").write_text(json.dumps(intent_doc))
        (ws / "custom.tf.json").write_text(render)
        manifest.update({"infra/workload/iac_intent.json": "", "infra/workload/custom.tf.json": ""})
        manifest.pop("infra/workload/custom.tf")
    return str(ws), manifest


def _intent_entry_diag(ws):
    render = open(os.path.join(ws, "custom.tf.json")).read()
    inside = render.index('"source"')
    return {"severity": "error", "summary": "Unsupported argument", "detail": "d",
            "range": {"filename": "custom.tf.json", "start": {"line": 5, "column": 7, "byte": inside},
                      "end": {"line": 5, "column": 15, "byte": inside + 8}}}


def _classifier(tf, tmp_path, plan_res):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="b", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = None
    seen = []

    def _own(cmd, cwd, iac_engine, budget_s):
        seen.append((list(cmd), budget_s))
        return plan_res
    svc._run_with_own_budget = _own
    return svc, seen


def _failed_plan(stdout):
    return {"success": False, "returncode": 1, "stdout": stdout, "stderr": ""}


# ===================================================================================== the matrix
# (id, intent workspace?, diagnostics builder(ws) -> list, expected owner, expected first-finding reason)
MATRIX = [
    ("golden_module_sa_trailing_dash", False, lambda ws: [GOLDEN_SA], "PLATFORM_DEFECT", "GOLDEN_MODULE"),
    ("golden_module_eval", False, lambda ws: [GOLDEN_EVAL], "PLATFORM_DEFECT", "GOLDEN_MODULE"),
    ("golden_module_relative_link", False,
     lambda ws: [_at(GOLDEN_SA, "../modules/workload-foundation/base/iam.tf")], "PLATFORM_DEFECT", "GOLDEN_MODULE"),
    ("golden_module_root_link", False,
     lambda ws: [_at(GOLDEN_SA, "modules/workload-foundation/base/iam.tf")], "PLATFORM_DEFECT", "GOLDEN_MODULE"),
    ("platform_floor_main_caller_arg", False, lambda ws: [CALLER_ARG_MAIN], "PLATFORM_DEFECT", "PLATFORM_RENDERED"),
    ("platform_floor_services", False, lambda ws: [_at(DEV_CUSTOM, "services.tf")], "PLATFORM_DEFECT",
     "PLATFORM_RENDERED"),
    ("server_written_backend", False, lambda ws: [_at(DEV_CUSTOM, "backend.tf")], "PLATFORM_DEFECT",
     "SERVER_WRITTEN"),
    ("legacy_custom_tf", False, lambda ws: [DEV_CUSTOM], "DEVELOPER", "WORKLOAD_IAC"),
    ("legacy_other_ai_file", False, lambda ws: [_at(DEV_CUSTOM, "database.tf")], "DEVELOPER", "WORKLOAD_IAC"),
    ("legacy_two_developer_files", False, lambda ws: [DEV_CUSTOM, _at(DEV_CUSTOM, "database.tf")], "DEVELOPER",
     "WORKLOAD_IAC"),
    ("user_owned_human_tf", False, lambda ws: [_at(DEV_CUSTOM, "human.tf")], "OPERATOR_REQUIRED", "USER_OWNED_FILE"),
    ("user_owned_override", False, lambda ws: [_at(DEV_CUSTOM, "net_override.tf")], "OPERATOR_REQUIRED",
     "USER_OWNED_FILE"),
    ("no_range", False, lambda ws: [_no_range(DEV_CUSTOM)], "UNKNOWN", "NO_LOCATION"),
    ("remote_module", False, lambda ws: [_at(DEV_CUSTOM, ".terraform/modules/x/main.tf")], "UNKNOWN",
     "UNATTRIBUTED"),
    ("outside_workspace", False, lambda ws: [_at(DEV_CUSTOM, "/elsewhere/main.tf")], "UNKNOWN", "UNATTRIBUTED"),
    ("mixed_developer_golden", False, lambda ws: [DEV_CUSTOM, GOLDEN_SA], "PLATFORM_DEFECT", "GOLDEN_MODULE"),
    ("mixed_developer_user", False, lambda ws: [DEV_CUSTOM, _at(DEV_CUSTOM, "human.tf")], "OPERATOR_REQUIRED",
     "USER_OWNED_FILE"),
    ("mixed_developer_unlocated", False, lambda ws: [DEV_CUSTOM, _no_range(DEV_CUSTOM)], "UNKNOWN", "NO_LOCATION"),
    ("mixed_all_three", False, lambda ws: [_no_range(DEV_CUSTOM), _at(DEV_CUSTOM, "human.tf"), GOLDEN_EVAL],
     "PLATFORM_DEFECT", "GOLDEN_MODULE"),
    ("intent_entry", True, lambda ws: [_intent_entry_diag(ws)], "DEVELOPER", "INTENT_ENTRY"),
    ("intent_golden_module", True, lambda ws: [GOLDEN_SA], "PLATFORM_DEFECT", "PLATFORM_FILE"),
    ("intent_platform_floor", True, lambda ws: [CALLER_ARG_MAIN], "PLATFORM_DEFECT", "PLATFORM_FILE"),
    ("intent_legacy_custom_tf_is_users", True, lambda ws: [DEV_CUSTOM], "OPERATOR_REQUIRED", "USER_OWNED_FILE"),
    ("intent_mixed_entry_golden", True, lambda ws: [_intent_entry_diag(ws), GOLDEN_SA], "PLATFORM_DEFECT",
     "PLATFORM_FILE"),
    ("intent_unlocated", True, lambda ws: [_no_range(DEV_CUSTOM)], "UNKNOWN", "NO_LOCATION"),
]


@pytest.mark.parametrize("case", MATRIX, ids=[m[0] for m in MATRIX])
def test_matrix(tf, tmp_path, case):
    _id, intent, build, owner, reason = case
    ws, manifest = _workspace(tmp_path, intent=intent)
    svc, seen = _classifier(tf, tmp_path, _failed_plan(_stream(*build(ws), ws=ws)))
    route, report = svc._classify_plan_failure(ws, "OPENTOFU", manifest, intent)
    assert route["owner"] == owner, route
    assert route["findings"][0]["reason"] == reason, route
    assert route["phase"] == "plan" and route["basis"] == "ENGINE_JSON_DIAGNOSTICS"
    assert route["error_class"] == (None if owner == "DEVELOPER" else dfr.ERROR_CLASS_BY_OWNER[owner])
    # the re-plan is read-only and bounded: JSON, no lock, no plan file
    (cmd, budget), = seen
    assert cmd[:2] == ["terraform", "plan"] and "-json" in cmd and "-lock=false" in cmd
    assert not any(a.startswith("-out") for a in cmd) and budget == tf.CLASSIFY_PLAN_BUDGET_S
    if intent:
        from shared.diagnostics import ValidationReport
        rep = ValidationReport.model_validate(report)
        assert rep.source == "apply" and rep.status == "FAIL"
    else:
        assert report is None


def test_sa_case_names_the_module_file_and_address(tf, tmp_path):
    ws, manifest = _workspace(tmp_path)
    svc, _ = _classifier(tf, tmp_path, _failed_plan(_stream(GOLDEN_SA, ws=ws)))
    route, _ = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    f = route["findings"][0]
    assert (f["file"], f["line"], f["address"]) == ("infra/modules/workload-foundation/base/iam.tf", 84,
                                                    "module.foundation.google_service_account.workload_sa")


def test_no_decision_reads_engine_text(tf, tmp_path):
    """Invariant 2: summary / detail / snippet text never changes a decision (only typed fields do)."""
    ws, manifest = _workspace(tmp_path)
    for base in (GOLDEN_SA, DEV_CUSTOM, CALLER_ARG_MAIN):
        mutated = json.loads(json.dumps(base))
        mutated.update(summary="Error 429: quota exceeded; permission denied; billing disabled", detail="503")
        mutated["snippet"] = {"code": "human.tf custom.tf"}
        a, _ = _classifier(tf, tmp_path, _failed_plan(_stream(base, ws=ws)))[0]._classify_plan_failure(
            ws, "OPENTOFU", manifest, False)
        b, _ = _classifier(tf, tmp_path, _failed_plan(_stream(mutated, ws=ws)))[0]._classify_plan_failure(
            ws, "OPENTOFU", manifest, False)
        assert (a["owner"], a["findings"][0]["reason"]) == (b["owner"], b["findings"][0]["reason"])


@pytest.mark.parametrize("stdout,basis", [("not json at all\n", "ENGINE_OUTPUT_UNPARSEABLE"),
                                          ("", "ENGINE_OUTPUT_UNPARSEABLE"),
                                          (_VERSION + "\n" + _SUMMARY + "\n", "NO_ERROR_DIAGNOSTICS")])
def test_unparseable_or_empty_output_is_unknown(tf, tmp_path, stdout, basis):
    ws, manifest = _workspace(tmp_path)
    svc, _ = _classifier(tf, tmp_path, _failed_plan(stdout))
    route, _ = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert (route["owner"], route["basis"]) == ("UNKNOWN", basis)


def test_warnings_are_not_findings(tf, tmp_path):
    ws, manifest = _workspace(tmp_path)
    warn = dict(GOLDEN_SA, severity="warning")
    svc, _ = _classifier(tf, tmp_path, _failed_plan(_stream(warn, DEV_CUSTOM, ws=ws)))
    route, _ = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert route["owner"] == "DEVELOPER" and len(route["findings"]) == 1


def test_plan_not_reproduced_is_transient(tf, tmp_path):
    ws, manifest = _workspace(tmp_path)
    svc, _ = _classifier(tf, tmp_path, {"success": True, "returncode": 0, "stdout": _VERSION, "stderr": ""})
    route, report = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert (route["owner"], route["basis"], route["error_class"]) == (
        "PROVIDER_TRANSIENT", "PLAN_NOT_REPRODUCED", "PROVIDER_TRANSIENT") and report is None


def test_classify_timeout_does_not_mask_the_deploy(tf, tmp_path):
    """The advisory re-plan's own timeout never turns the deploy into TOFU_TIMEOUT."""
    ws, manifest = _workspace(tmp_path)
    svc, _ = _classifier(tf, tmp_path, None)
    slot = svc._tofu_timeout_slot()
    slot.in_deploy, slot.message, slot.deadline = True, None, None

    def _times_out(cmd, cwd, iac_engine, budget_s):
        slot.message = "TOFU_TIMEOUT: the OpenTofu command `plan` did not finish"
        return svc._tofu_timeout_result(slot.message)
    svc._run_with_own_budget = _times_out
    route, _ = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert (route["owner"], route["basis"]) == ("UNKNOWN", "CLASSIFY_TIMED_OUT")
    assert slot.message is None
    assert svc._with_tofu_timeout_class({"status": "FAILED", "error": "x"}) == {"status": "FAILED", "error": "x"}


def test_classify_not_run_after_a_deploy_timeout_or_without_budget(tf, tmp_path):
    ws, manifest = _workspace(tmp_path)
    svc, seen = _classifier(tf, tmp_path, _failed_plan(_stream(DEV_CUSTOM, ws=ws)))
    slot = svc._tofu_timeout_slot()
    slot.in_deploy, slot.message = True, "TOFU_TIMEOUT: earlier"
    route, _ = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert (route["owner"], route["basis"]) == ("UNKNOWN", "CLASSIFY_NOT_RUN") and seen == []
    slot.message = None
    svc._deploy_time_left = lambda: 5.0   # a sync /deploy with 5 s left
    route, _ = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert route["basis"] == "CLASSIFY_NOT_RUN" and seen == []
    svc._deploy_time_left = lambda: 100.0
    svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert seen[-1][1] == 100.0   # never past the deploy's own deadline


def test_access_var_file_is_passed_like_the_gated_plan(tf, tmp_path):
    ws, manifest = _workspace(tmp_path)
    open(os.path.join(ws, tf.PLATFORM_ACCESS_VARS_FILE), "w").write("{}")
    svc, seen = _classifier(tf, tmp_path, _failed_plan(_stream(DEV_CUSTOM, ws=ws)))
    svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert seen[0][0][-1] == f"-var-file={tf.PLATFORM_ACCESS_VARS_FILE}"


def test_intent_plan_report_routes_intent_repair(tf, tmp_path):
    """A developer plan error on a committed intent entry: the plan report is FAIL CODE_DEFECT on that entry, which
    deploy_repair turns into INTENT_REPAIR (targeted) instead of today's regeneration from an UNAVAILABLE report."""
    ws, manifest = _workspace(tmp_path, intent=True)
    svc, _ = _classifier(tf, tmp_path, _failed_plan(_stream(_intent_entry_diag(ws), ws=ws)))
    route, report = svc._classify_plan_failure(ws, "OPENTOFU", manifest, True)
    assert route["owner"] == "DEVELOPER"
    from shared.diagnostics import ErrorClass, ValidationReport
    rep = ValidationReport.model_validate(report)
    assert rep.error_class is ErrorClass.CODE_DEFECT
    assert [(d.file, d.block_address) for d in rep.diagnostics] == [("infra/workload/iac_intent.json", "module.b")]


# ===================================================================================== validate
def test_legacy_validate_routes_from_validate_json(tf, tmp_path):
    ws, manifest = _workspace(tmp_path)
    svc, _ = _classifier(tf, tmp_path, None)
    vjson = json.dumps({"format_version": "1.0", "valid": False, "error_count": 1, "warning_count": 0,
                        "diagnostics": [_at(DEV_CUSTOM, "variables.tf")]})
    route = svc._route_validate_failure(vjson, ws, manifest, False)
    assert (route["owner"], route["phase"], route["findings"][0]["file"]) == (
        "PLATFORM_DEFECT", "validate", "infra/workload/variables.tf")
    dev = json.dumps({"diagnostics": [DEV_CUSTOM]})
    assert svc._route_validate_failure(dev, ws, manifest, False)["owner"] == "DEVELOPER"
    assert svc._route_validate_failure("", ws, manifest, False)["owner"] == "UNKNOWN"


def test_intent_validate_route_follows_the_existing_report(tf, tmp_path):
    ws, manifest = _workspace(tmp_path, intent=True)
    svc, _ = _classifier(tf, tmp_path, None)
    vjson = json.dumps({"diagnostics": [_intent_entry_diag(ws)]})
    report = tf.apply_validation_report(vjson, ws, manifest_paths=manifest.keys())
    assert svc._route_validate_failure(vjson, ws, manifest, True, report)["owner"] == "DEVELOPER"
    vjson2 = json.dumps({"diagnostics": [CALLER_ARG_MAIN]})
    report2 = tf.apply_validation_report(vjson2, ws, manifest_paths=manifest.keys())
    assert svc._route_validate_failure(vjson2, ws, manifest, True, report2)["owner"] == "PLATFORM_DEFECT"


# ===================================================================================== the result and the record
class _RecordingDB:
    def __init__(self, exists=True, fail=False):
        self.updates, self.exists, self.fail = [], exists, fail

    def collection(self, name):
        db = self

        class _Doc:
            def __init__(self, path):
                self.path = path

            def update(self, data):
                if db.fail:
                    raise RuntimeError("firestore write failed")
                if not db.exists:
                    from google.api_core import exceptions as gexc
                    raise gexc.NotFound(self.path)
                db.updates.append((self.path, data))

        return types.SimpleNamespace(document=lambda d: _Doc(f"{name}/{d}"))


def _router_svc(tf, tmp_path, db=None):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="b", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = db
    return svc


def test_negative_developer_result_unchanged(tf, tmp_path):
    """Do No Harm: a developer-owned failure keeps its exact result (no class, no flag, same text): the workflow
    remediates it exactly as before. Only the route record is added."""
    db = _RecordingDB()
    svc = _router_svc(tf, tmp_path, db)
    result = {"status": "FAILED", "error": "Terraform apply failed: Error: Invalid function argument", "stdout": "",
              "stderr": "x", dfr.FAILURE_ROUTE_FIELD: dfr.route("DEVELOPER", "plan", "ENGINE_JSON_DIAGNOSTICS")}
    out = svc._route_failed_deploy(dict(result), "tr-1")
    assert {k: v for k, v in out.items() if k != dfr.FAILURE_ROUTE_FIELD} == {
        k: v for k, v in result.items() if k != dfr.FAILURE_ROUTE_FIELD}
    assert "error_class" not in out and "operator_required" not in out
    (path, data), = db.updates
    assert path == "pipeline_executions/tr-1" and list(data) == ["stages.terraform.failure_route"]
    rec = data["stages.terraform.failure_route"]
    assert rec["owner"] == "DEVELOPER"
    assert rec["error_sha256"] == hashlib.sha256(result["error"].encode()).hexdigest()


@pytest.mark.parametrize("owner,cls", [("PLATFORM_DEFECT", "PLATFORM_DEFECT"),
                                       ("OPERATOR_REQUIRED", "OPERATOR_REQUIRED"),
                                       ("PROVIDER_TRANSIENT", "PROVIDER_TRANSIENT"),
                                       ("UNKNOWN", "DEPLOY_FAILURE_UNATTRIBUTED")])
def test_non_developer_result_is_typed_and_flagged(tf, tmp_path, owner, cls):
    db = _RecordingDB()
    svc = _router_svc(tf, tmp_path, db)
    finding = {"owner": owner, "reason": "GOLDEN_MODULE", "file": "infra/modules/workload-foundation/base/iam.tf",
               "line": 84, "address": "module.foundation.google_service_account.workload_sa", "summary": "s"}
    result = {"status": "FAILED", "error": "Terraform apply failed: engine text",
              dfr.FAILURE_ROUTE_FIELD: dfr.route(owner, "plan", "ENGINE_JSON_DIAGNOSTICS", [finding])}
    out = svc._route_failed_deploy(result, "tr-1")
    assert out["error_class"] == cls and out["operator_required"] is True
    assert out["code"] == dfr.CODE_BY_OWNER[owner]
    assert out["error"].startswith(f"{cls} (plan failed; owner {owner}")
    assert "module.foundation.google_service_account.workload_sa in " \
           "infra/modules/workload-foundation/base/iam.tf:84" in out["error"]
    assert out["error"].endswith("Engine error: Terraform apply failed: engine text")
    rec = db.updates[0][1]["stages.terraform.failure_route"]
    assert rec["owner"] == owner and rec["error_sha256"] == hashlib.sha256(out["error"].encode()).hexdigest()


@pytest.mark.parametrize("result,owner", [
    ({"status": "FAILED", "error": "x", "error_class": "IAC_DEFECT"}, "DEVELOPER"),
    ({"status": "FAILED", "error": "x", "error_class": "STATE_LOCKED"}, "UNKNOWN"),
    ({"status": "FAILED", "error": "x", "error_class": "TOFU_TIMEOUT"}, "UNKNOWN"),
    ({"status": "FAILED", "error": "x", "error_class": "TFVARS_OVERRIDES_PLATFORM", "operator_required": True},
     "OPERATOR_REQUIRED"),
    ({"status": "FAILED", "error": "x", "error_class": "IAC_DEFECT", "operator_required": True}, "OPERATOR_REQUIRED"),
])
def test_typed_class_unchanged(tf, tmp_path, result, owner):
    db = _RecordingDB()
    svc = _router_svc(tf, tmp_path, db)
    given = dict(result)
    out = svc._route_failed_deploy(given, "tr-1")
    assert out is given and out == result   # the typed result itself, unchanged
    rec = db.updates[0][1]["stages.terraform.failure_route"]
    assert (rec["owner"], rec["basis"]) == (owner, "TYPED_CLASS")
    assert rec["error_sha256"] == hashlib.sha256(b"x").hexdigest()


def test_untyped_failure_without_a_route_is_unknown(tf, tmp_path):
    svc = _router_svc(tf, tmp_path, None)
    out = svc._route_failed_deploy({"status": "FAILED", "error": "something"}, "tr-1")
    assert out["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED" and out["operator_required"] is True
    assert out[dfr.FAILURE_ROUTE_FIELD]["basis"] == "CLASSIFY_NOT_RUN"


def test_success_is_untouched(tf, tmp_path):
    db = _RecordingDB()
    svc = _router_svc(tf, tmp_path, db)
    ok = {"status": "SUCCESS", "service_url": "https://x"}
    assert svc._route_failed_deploy(ok, "tr-1") is ok and db.updates == []


@pytest.mark.parametrize("db", [_RecordingDB(exists=False), _RecordingDB(fail=True)])
def test_route_write_never_creates_a_run_record_and_never_raises(tf, tmp_path, db):
    svc = _router_svc(tf, tmp_path, db)
    out = svc._route_failed_deploy({"status": "FAILED", "error": "e", dfr.FAILURE_ROUTE_FIELD:
                                    dfr.route("DEVELOPER", "plan", "ENGINE_JSON_DIAGNOSTICS")}, "tr-1")
    assert out["status"] == "FAILED" and db.updates == []


# ===================================================================================== the real deploy
def _deploy_harness(tf, tmp_path, monkeypatch, gated_result, run_results):
    import importlib

    import google.auth
    import google.auth.transport.requests as gatr
    settings = importlib.import_module("shared.settings")
    monkeypatch.setattr(settings, "_SETTINGS_CACHE", settings.PlatformSettings())
    monkeypatch.setattr(settings, "_LAST_FETCH_TIME", float("inf"))
    sess = MagicMock(name="session")
    sess.get.return_value = types.SimpleNamespace(status_code=404, json=lambda: {}, text="")
    sess.post.return_value = types.SimpleNamespace(status_code=404, json=lambda: {}, text="")
    monkeypatch.setattr(google.auth, "default", lambda *a, **k: (MagicMock(valid=True, token="t"), "p"))
    monkeypatch.setattr(gatr, "AuthorizedSession", lambda *a, **k: sess)
    ws, _ = _workspace(tmp_path)
    svc = tf.TerraformService(project_id="castor-parent", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock(name="firestore"))
    db = _RecordingDB()
    svc.db = None
    svc.state_bucket = ""
    svc._fetch_repo_files = lambda *a, **k: {}
    svc.prepare_workspace = lambda *a, **k: ws
    svc._build_and_push_container = lambda *a, **k: True
    svc._ensure_provider_mirror = lambda *a, **k: "/nonexistent/terraform.rc"
    svc._validate_no_engine_downgrade = lambda *a, **k: None
    svc._list_cloud_run_services = lambda *a, **k: ([], None)
    svc._compliance_gated_apply = lambda *a, **k: dict(gated_result)
    svc._run_subprocess = lambda cmd, **k: {"success": True, "returncode": 0, "stdout": "{}", "stderr": ""}
    seen = []

    def _own(cmd, cwd, iac_engine, budget_s):
        seen.append(list(cmd))
        return run_results.pop(0)
    svc._run_with_own_budget = _own
    # the route record is written at the end of deploy_workload (svc.db is read there)
    orig = svc._route_failed_deploy

    def _route(result, trace_id):
        svc.db = db
        try:
            return orig(result, trace_id)
        finally:
            svc.db = None
    svc._route_failed_deploy = _route
    return svc, ws, db, seen


def test_deploy_plan_failure_golden_module_end_to_end(tf, tmp_path, monkeypatch):
    """The 11-12 shape through the real deploy: the gated plan fails in module.foundation -> one read-only re-plan ->
    PLATFORM_DEFECT, operator_required, the file and address named; no developer route recorded."""
    plan_fail = {"success": False, "returncode": 1, "stdout": "",
                 "stderr": "Error: \"account_id\" (\"sa-finalrun-testplan01-\") must match regex",
                 "compliance_gate_phase": "plan"}
    replan = []
    svc, ws, db, seen = _deploy_harness(tf, tmp_path, monkeypatch, plan_fail, replan)
    replan.append(_failed_plan(_stream(GOLDEN_SA, ws=ws)))
    res = svc.deploy_workload(product_id="finalrun-testplan01-a", trace_id="tr-sa", target_project_id="child-1",
                              hcl_files={"infra/workload/main.tf": 'variable "project_id" {}\n'})
    assert res["status"] == "FAILED" and res["error_class"] == "PLATFORM_DEFECT" and res["operator_required"] is True
    assert "module.foundation.google_service_account.workload_sa" in res["error"]
    assert res["error"].endswith("Engine error: Terraform apply failed: " + plan_fail["stderr"])
    assert len(seen) == 1 and "-json" in seen[0]
    assert "validation_report" not in res   # not an intent workspace; no UNAVAILABLE report is added either
    rec = db.updates[0][1]["stages.terraform.failure_route"]
    assert rec["owner"] == "PLATFORM_DEFECT" and rec["phase"] == "plan"


def test_deploy_plan_failure_developer_end_to_end_unchanged(tf, tmp_path, monkeypatch):
    plan_fail = {"success": False, "returncode": 1, "stdout": "", "stderr": "Error: Invalid function argument",
                 "compliance_gate_phase": "plan"}
    replan = []
    svc, ws, db, _ = _deploy_harness(tf, tmp_path, monkeypatch, plan_fail, replan)
    replan.append(_failed_plan(_stream(DEV_CUSTOM, ws=ws)))
    res = svc.deploy_workload(product_id="app", trace_id="tr-dev", target_project_id="child-1",
                              hcl_files={"infra/workload/main.tf": "", "infra/workload/custom.tf": ""})
    assert res["status"] == "FAILED" and "error_class" not in res and "operator_required" not in res
    assert res["error"] == "Terraform apply failed: Error: Invalid function argument"
    rec = db.updates[0][1]["stages.terraform.failure_route"]
    assert rec["owner"] == "DEVELOPER"
    assert rec["error_sha256"] == hashlib.sha256(res["error"].encode()).hexdigest()


def test_apply_phase_failure_is_unattributed(tf, tmp_path, monkeypatch):
    """An apply-time failure has no typed diagnostics (incl. a provider 429/503, quota, permission or billing error
    during apply): UNKNOWN (APPLY_UNATTRIBUTED), operator stop; no classification re-plan runs."""
    apply_fail = {"success": False, "returncode": 1, "stdout": "",
                  "stderr": "Error: Error creating Service: googleapi: Error 429: Quota exceeded"}
    svc, ws, db, seen = _deploy_harness(tf, tmp_path, monkeypatch, apply_fail, [])
    res = svc.deploy_workload(product_id="app", trace_id="tr-ap", target_project_id="child-1",
                              hcl_files={"infra/workload/main.tf": ""})
    assert res["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED" and res["operator_required"] is True
    assert res[dfr.FAILURE_ROUTE_FIELD]["basis"] == "APPLY_UNATTRIBUTED" and seen == []


def _raising_deploy(tf, tmp_path, exc):
    db = _RecordingDB()
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="b", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = db
    svc._deploy_access_vars = lambda product_id: ("{}", {})
    svc._sync_feature_requests = lambda **k: None

    def _impl(**kw):
        raise exc
    svc._deploy_workload_impl = _impl
    return svc, db


def test_rt_f1_raised_developer_refusal_records_a_developer_route(tf, tmp_path, gw):
    """RT F1: ReservedEnvRefused (IAC_DEFECT, raised from the gated apply) records a DEVELOPER route whose digest
    matches the delivered error, so the gateway allows the developer's repair exactly as before G1."""
    result = tf.reserved_env_port_result("app", "tr-f1", [{"address": "module.compute.x", "container": "c"}])
    svc, db = _raising_deploy(tf, tmp_path, tf.ReservedEnvRefused(result))
    res = svc.deploy_workload(product_id="app", trace_id="tr-f1")
    assert res["error_class"] == "IAC_DEFECT" and "operator_required" not in res
    assert dfr.FAILURE_ROUTE_FIELD not in res   # the typed result itself
    (path, data), = db.updates
    rec = data["stages.terraform.failure_route"]
    assert path == "pipeline_executions/tr-f1" and rec["owner"] == "DEVELOPER" and rec["basis"] == "TYPED_CLASS"
    assert rec["error_sha256"] == hashlib.sha256(res["error"].encode()).hexdigest()
    fake = FakeDB()
    fake.docs["pipeline_executions/tr-f1"] = {"stages": {"terraform": {"failure_route": rec}}}
    req = gw.DeveloperExecuteRequest(trace_id="tr-f1", product_id="app", tf_remediation_context=res["error"],
                                     tf_retry_count=1)
    gw._assert_tf_remediation_allowed(req, fake)  # no raise


def test_rt_f1_raised_operator_refusal_records_a_non_developer_route(tf, tmp_path):
    result = tf.content_policy_refusal("app", "tr-f1b", [{"code": "POLICY.PROVISIONER", "message": "m"}])
    svc, db = _raising_deploy(tf, tmp_path, tf.ContentPolicyRefused(result))
    res = svc.deploy_workload(product_id="app", trace_id="tr-f1b")
    assert res["error_class"] == tf.ERROR_APPLY_CONTENT_POLICY
    rec = db.updates[0][1]["stages.terraform.failure_route"]
    assert rec["owner"] != "DEVELOPER" and rec["error_class"] == tf.ERROR_APPLY_CONTENT_POLICY


def test_rt_f4_typed_result_never_carries_a_stale_route(tf, tmp_path):
    """RT F4: a result typed after its failure point set a route (TOFU_TIMEOUT over a plan failure) carries the typed
    route in the callback body, the same one that is recorded."""
    db = _RecordingDB()
    svc = _router_svc(tf, tmp_path, db)
    stale = dfr.route("UNKNOWN", "plan", "CLASSIFY_NOT_RUN")
    given = {"status": "FAILED", "error_class": "TOFU_TIMEOUT", "error": "TOFU_TIMEOUT: x",
             dfr.FAILURE_ROUTE_FIELD: stale}
    out = svc._route_failed_deploy(given, "tr-f4")
    rec = db.updates[0][1]["stages.terraform.failure_route"]
    assert out[dfr.FAILURE_ROUTE_FIELD]["basis"] == "TYPED_CLASS" == rec["basis"]
    assert out[dfr.FAILURE_ROUTE_FIELD]["error_class"] == "TOFU_TIMEOUT" and out[dfr.FAILURE_ROUTE_FIELD]["phase"] == "plan"
    assert given[dfr.FAILURE_ROUTE_FIELD] is stale   # the input is not mutated


def test_untyped_phases_are_unattributed(tf):
    """init / container build / no root config set an UNKNOWN route with their phase (source pins)."""
    src = open(tf.__file__, encoding="utf-8").read()
    for phase in ("PHASE_INIT", "PHASE_BUILD", "PHASE_PREPARE"):
        assert f"dfr.route(dfr.UNKNOWN, dfr.{phase}, dfr.BASIS_NO_ENGINE_RESULT)" in src, phase


# ===================================================================================== real OpenTofu (optional)
@pytest.mark.skipif(shutil.which("tofu") is None, reason="OpenTofu is not installed")
def test_real_tofu_plan_json_routes_golden_module_and_developer_file(tf, tmp_path):
    """The deploy layout (root source `../modules/...` through the trace folder's link) with the built-in provider
    only: the real engine's diagnostics route the module-body error to PLATFORM_DEFECT and custom.tf to DEVELOPER."""
    ws, manifest = _workspace(tmp_path)
    for name in ("variables.tf", "outputs.tf", "services.tf", "human.tf", "database.tf", "backend.tf"):
        os.remove(os.path.join(ws, name))
    open(os.path.join(ws, "main.tf"), "w").write(
        'variable "product_id" {\n  type    = string\n  default = "finalrun-testplan01-a"\n}\n\n'
        'module "foundation" {\n  source     = "../modules/workload-foundation/base"\n'
        '  product_id = var.product_id\n}\n')
    open(os.path.join(ws, "infra", "modules", "workload-foundation", "base", "iam.tf"), "w").write(
        'variable "product_id" {\n  type = string\n}\n\nresource "terraform_data" "workload_sa" {\n'
        '  input = tonumber("sa-${substr(var.product_id, 0, 20)}")\n}\n')
    env = dict(os.environ, TF_IN_AUTOMATION="1", TF_CLI_CONFIG_FILE=os.devnull, CHECKPOINT_DISABLE="1")
    done = subprocess.run(["tofu", "init", "-input=false", "-no-color"], cwd=ws, env=env, capture_output=True,
                          text=True, timeout=120)
    assert done.returncode == 0, done.stderr

    def _plan():
        p = subprocess.run(["tofu", "plan", "-json", "-input=false", "-no-color", "-lock=false"], cwd=ws, env=env,
                           capture_output=True, text=True, timeout=120)
        return {"success": p.returncode == 0, "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}

    svc, _ = _classifier(tf, tmp_path, _plan())
    route, _ = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert route["owner"] == "PLATFORM_DEFECT" and route["findings"][0]["reason"] == "GOLDEN_MODULE", route
    open(os.path.join(ws, "infra", "modules", "workload-foundation", "base", "iam.tf"), "w").write(
        'variable "product_id" {\n  type = string\n}\n')
    open(os.path.join(ws, "custom.tf"), "w").write('resource "terraform_data" "dev" {\n'
                                                   '  input = tonumber("abc${var.product_id}")\n}\n')
    svc, _ = _classifier(tf, tmp_path, _plan())
    route, _ = svc._classify_plan_failure(ws, "OPENTOFU", manifest, False)
    assert route["owner"] == "DEVELOPER" and route["findings"][0]["file"] == "infra/workload/custom.tf", route


# ===================================================================================== workflow paths (YAML unchanged)
def _deploy_body(owner):
    r = dfr.apply_route({"status": "FAILED", "error": "engine text"},
                        dfr.route(owner, "plan", "ENGINE_JSON_DIAGNOSTICS"))
    return r


@pytest.mark.parametrize("owner", ["PLATFORM_DEFECT", "OPERATOR_REQUIRED", "PROVIDER_TRANSIENT", "UNKNOWN"])
@pytest.mark.parametrize("mode", ["FULL", "DEPLOY_ONLY"])
def test_workflow_paths_non_developer(workflow, owner, mode):
    f = Fleet()
    f.callbacks["deploy"] = [_deploy_body(owner), {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    kw = {"execution_mode": "DEPLOY_ONLY", "target_branch": "main"} if mode == "DEPLOY_ONLY" else {}
    res, _ = run(workflow, f, **kw)
    assert_failed(res, dfr.ERROR_CLASS_BY_OWNER[owner], "terraform")
    assert "handle_operator_deploy_failure" in res.steps_executed
    assert "increment_tf_retry" not in res.steps_executed and "handle_deploy_failure" not in res.steps_executed
    assert len(calls(res, "/agent/developer/execute")) == (0 if mode == "DEPLOY_ONLY" else 1)


def test_workflow_paths_developer_is_remediated_as_before(workflow):
    f = Fleet()
    f.callbacks["deploy"] = [_deploy_body("DEVELOPER"), {"status": "SUCCESS", "service_url": "https://app.run.app"}]
    res, _ = run(workflow, f)
    assert res.state == "SUCCEEDED", res.error
    assert "increment_tf_retry" in res.steps_executed
    assert len(calls(res, "/agent/developer/execute")) == 2


def test_router_classes_are_not_remediable_and_not_in_the_operator_list():
    ge = _load("dfr_gate_errors", os.path.join(GW_DIR, "gate_errors.py"))
    assert not dfr.ROUTER_ERROR_CLASSES & ge.NON_REMEDIABLE_DEPLOY_CLASSES   # the flag routes them, the list is unchanged
    assert "IAC_DEFECT" not in dfr.ROUTER_ERROR_CLASSES and "" not in dfr.ROUTER_ERROR_CLASSES


# ===================================================================================== gateway allow-list
TRACE = "tr-dfr-1"
CTX = "PLATFORM_DEFECT (plan failed; owner PLATFORM_DEFECT): engine text"


def _req(g, ctx=CTX, retry=1):
    return g.DeveloperExecuteRequest(trace_id=TRACE, product_id="app", tf_remediation_context=ctx,
                                     tf_retry_count=retry)


def _db_with_route(owner, ctx=CTX, **extra):
    db = FakeDB()
    rec = dict(dfr.route(owner, "plan", "ENGINE_JSON_DIAGNOSTICS", [
        {"owner": owner, "reason": "GOLDEN_MODULE", "file": "infra/modules/workload-foundation/base/iam.tf",
         "line": 84, "address": "module.foundation.google_service_account.workload_sa", "summary": "s"}]),
        error_sha256=hashlib.sha256(ctx.encode()).hexdigest(), **extra)
    db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"terraform": {"failure_route": rec}}}
    return db


def test_guard_allows_developer_route(gw):
    gw._assert_tf_remediation_allowed(_req(gw), _db_with_route("DEVELOPER"))  # no raise


def test_guard_refuses_platform_defect_typed(gw):
    from gate_errors import PlatformDefectError
    with pytest.raises(PlatformDefectError) as ei:
        gw._assert_tf_remediation_allowed(_req(gw), _db_with_route("PLATFORM_DEFECT"))
    body = ei.value.to_body()
    assert body["error_class"] == "PLATFORM_DEFECT" and body["stage"] == "developer"
    assert body["reason"] == "PLATFORM_DEFECT" and body["details"]["owner"] == "PLATFORM_DEFECT"
    assert body["details"]["findings"][0]["file"] == "infra/modules/workload-foundation/base/iam.tf"
    assert body["details"]["findings"][0]["address"] == "module.foundation.google_service_account.workload_sa"


@pytest.mark.parametrize("owner", ["OPERATOR_REQUIRED", "PROVIDER_TRANSIENT", "UNKNOWN"])
def test_guard_refuses_other_owners(gw, owner):
    from gate_errors import OperatorActionRequiredError
    with pytest.raises(OperatorActionRequiredError) as ei:
        gw._assert_tf_remediation_allowed(_req(gw), _db_with_route(owner))
    assert ei.value.reason == owner and ei.value.stage == "developer"


def test_guard_refuses_without_a_route(gw):
    from gate_errors import OperatorActionRequiredError
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"terraform": {"status": "FAILED"}}}
    with pytest.raises(OperatorActionRequiredError) as ei:
        gw._assert_tf_remediation_allowed(_req(gw), db)
    assert ei.value.reason == "NO_DEPLOY_FAILURE_ROUTE"


def test_guard_refuses_a_stale_route(gw):
    """A DEVELOPER route of an earlier round never authorises a later failure (exact error pairing)."""
    from gate_errors import OperatorActionRequiredError
    with pytest.raises(OperatorActionRequiredError) as ei:
        gw._assert_tf_remediation_allowed(_req(gw, ctx="a different, later failure"), _db_with_route("DEVELOPER"))
    assert ei.value.reason == "DEPLOY_FAILURE_ROUTE_STALE"


def test_guard_resume_first_dispatch_unchanged(gw):
    """An operator's RESUME_DEVELOPER relaunch (tf_retry_count 0, the previous run's error) is not checked."""
    db = FakeDB()
    db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"terraform": {"status": "QUEUED"}}}
    gw._assert_tf_remediation_allowed(_req(gw, retry=0), db)  # no raise


def test_guard_listed_class_still_refused_first(gw):
    from gate_errors import OperatorActionRequiredError
    db = _db_with_route("DEVELOPER")
    db.docs[f"pipeline_executions/{TRACE}"]["stages"]["terraform"]["error_class"] = "STATE_LOCKED"
    with pytest.raises(OperatorActionRequiredError) as ei:
        gw._assert_tf_remediation_allowed(_req(gw), db)
    assert ei.value.reason == "STATE_LOCKED"


def test_guard_pairs_with_the_server_digest(gw):
    """The server's digest (deploy_failure_router.error_digest of the delivered error) is what the gateway checks."""
    db = FakeDB()
    rec = dict(dfr.route("DEVELOPER", "plan", "ENGINE_JSON_DIAGNOSTICS"), error_sha256=dfr.error_digest(CTX))
    db.docs[f"pipeline_executions/{TRACE}"] = {"stages": {"terraform": {"failure_route": rec}}}
    gw._assert_tf_remediation_allowed(_req(gw), db)


# ===================================================================================== parity
def test_parity_with_artifact_ownership_and_the_gateway():
    from shared.artifact_ownership import PLATFORM_RENDERED_FLOOR
    assert dfr.PLATFORM_RENDERED_FLOOR == {p for p in PLATFORM_RENDERED_FLOOR if p.endswith(".tf")}
    ge = _load("dfr_gate_errors2", os.path.join(GW_DIR, "gate_errors.py"))
    assert ge.DEPLOY_FAILURE_ROUTE_FIELD == dfr.FAILURE_ROUTE_FIELD
    assert ge.DEPLOY_OWNERS == frozenset(dfr.OWNERS)
    assert (ge.DEPLOY_OWNER_DEVELOPER, ge.DEPLOY_OWNER_PLATFORM_DEFECT) == (dfr.DEVELOPER, dfr.PLATFORM_DEFECT)
    assert dfr.STAGE_ROUTE_FIELD_PATH == "stages.terraform." + ge.DEPLOY_FAILURE_ROUTE_FIELD


def test_parity_with_the_control_center_classes():
    src = open(os.path.join(REPO, "apps", "control-center", "routes", "telemetry.py"), encoding="utf-8").read()
    import ast
    tree = ast.parse(src)
    keys = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "DEPLOY_ROUTER_REMEDIATION"
                                                for t in node.targets):
            keys = {k.value for k in node.value.keys}
    assert keys == set(dfr.ROUTER_ERROR_CLASSES)


def test_iac_defect_constant_matches_the_service(tf):
    assert dfr.IAC_DEFECT == tf.IAC_DEFECT_ERROR_CLASS

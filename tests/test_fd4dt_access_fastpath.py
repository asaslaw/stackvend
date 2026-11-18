"""FD-4DT follow-ups: an access change applies on Fast-Path Deploy, and Auto picks Fast-Path after a success whose only
change is the access record.

(A) Every deploy (tf-applier / terraform MCP ``deploy_workload``) renders the workload's CURRENT access record
(``workloads/{pid}.access``) into one platform-owned variable file of the deploy workspace
(``stackvend-access.auto.tfvars.json``; values from ``shared.access_policy.deploy_access_tfvars``), passed to the
deploy as a manifest entry (never a committed file) and named by ``-var-file`` on the gated plan, so it beats the copy
the developer stage baked into the committed ``infra/workload/terraform.tfvars``. Private records only; PUBLIC_APP,
Express workloads, no record and no Firestore client render ``{}`` (the committed values apply, as before). A pending
widening (L19-F4) is refused at the deploy (ACCESS_WIDENING_UNAPPROVED, operator) and at the gateway's deploy-only gate
(ACCESS_WIDENING_PENDING), so DEPLOY_ONLY never applies an unapproved widening.

(B) ``access_only_fast_path``: the Control Center's Auto relaunch picks DEPLOY_ONLY only when the last run SUCCEEDED
and the only change since is a private-to-private access change (typed fields and parsed timestamps).

Hermetic: no repo fetch, no Secret Manager, no ADC, no network. The real-engine precedence test runs only when a tofu
binary is on PATH or named by STACKVEND_PINNED_TOFU (no providers, no backend, no network).
"""
import hermetic_guard  # noqa: F401  (first import)

import copy
import json
import os
import shutil
import subprocess
import sys
import types
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

from shared.access_policy import (  # noqa: E402
    AccessPolicy, AccessPolicyIncompleteError, DEPLOY_ACCESS_TFVARS_KEYS, deploy_access_tfvars)
from test_fd4aq_w1_no_host_secret import (  # noqa: E402,F401  (tf is a fixture)
    PROJECT, TREE, W, _Cloud, _db, _fake_cloud, _service, _Stop, tf)
from test_l19_11_access_intake import cc  # noqa: E402,F401  (cc is a fixture)
from fd4f_support import FakeDB as GwFakeDB, gw  # noqa: E402,F401  (gw is a fixture)

PID = "shop"
OFF = {"google": "DISABLED", "email_password": False, "additional_authorized_domains": []}
ACCESS_FILE = "stackvend-access.auto.tfvars.json"


def _rec(mode, members=("user:ana@example.com", "group:staff@example.com"), **kw):
    rec = {"mode": mode, "invoker_principals": list(members), "app_admin_emails": [], "public_api_routes": [],
           "sign_in": dict(OFF), "tenant_isolation_required": None, "source": "operator_hitl"}
    rec.update(kw)
    return rec


PUBLIC_REC = {"mode": "PUBLIC_APP", "invoker_principals": [], "app_admin_emails": [],
              "public_api_routes": ["GET /api/config"],
              "sign_in": {"google": "BYO", "email_password": False, "additional_authorized_domains": []},
              "tenant_isolation_required": False, "source": "intake"}
FLAG = {"required": True, "audit_log_id": "a1", "set_at": "2026-10-28T10:00:00+00:00", "set_by": "admin@example.com",
        "previous_mode": "PRIVATE_IAP", "previous_members": ["user:ana@example.com"], "new_mode": "PRIVATE_IAP",
        "added_members": ["user:bo@example.com"], "changes": ["MEMBERS_ADDED"]}

# The committed tree a full build produced for an IAP workload listing ana + staff (developer tfvars lines).
COMMITTED_TFVARS = ('enable_direct_iap          = true\nallow_unauthenticated      = false\n'
                    'authorized_invoker_members = ["user:ana@example.com", "group:staff@example.com"]\n')
COMMITTED = dict(TREE, **{W + "terraform.tfvars": COMMITTED_TFVARS})


# ============================================================================ shared: deploy_access_tfvars
def test_deploy_access_tfvars_private_modes_are_exact():
    iap = deploy_access_tfvars(AccessPolicy.model_validate(_rec("PRIVATE_IAP")))
    assert iap == {"allow_unauthenticated": False, "enable_direct_iap": True,
                   "authorized_invoker_members": ["user:ana@example.com", "group:staff@example.com"]}
    iam = deploy_access_tfvars(AccessPolicy.model_validate(_rec("PRIVATE_IAM", ["serviceAccount:x@p.iam.gserviceaccount.com"])))
    assert iam == {"allow_unauthenticated": False, "enable_direct_iap": False,
                   "authorized_invoker_members": ["serviceAccount:x@p.iam.gserviceaccount.com"]}
    assert set(iap) == set(iam) == set(DEPLOY_ACCESS_TFVARS_KEYS)


def test_deploy_access_tfvars_never_opens_a_public_record_and_never_renders_an_empty_private_list():
    assert deploy_access_tfvars(AccessPolicy.model_validate(PUBLIC_REC)) is None
    with pytest.raises(AccessPolicyIncompleteError):
        deploy_access_tfvars(AccessPolicy.model_validate(_rec("PRIVATE_IAP", [])))


@pytest.mark.parametrize("record", [_rec("PRIVATE_IAP"), _rec("PRIVATE_IAM"), _rec("PRIVATE_IAP", ["user:a@x.io"])])
def test_deploy_values_equal_what_the_developer_validator_requires(record):
    """Parity: the developer's access-policy validator (the contract of the committed tfvars) finds no
    POLICY.ACCESS_POLICY_MISMATCH for the deploy values, so Fast-Path applies what a full rebuild would commit."""
    gw_dir = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
    if gw_dir not in sys.path:
        sys.path.insert(0, gw_dir)
    from developer_agent import access_policy_validator as apv
    policy = AccessPolicy.model_validate(record)
    values = deploy_access_tfvars(policy)
    assert set(values) == set(apv.PLATFORM_TFVARS_KEYS) == set(DEPLOY_ACCESS_TFVARS_KEYS)
    assert [d for d in apv.validate({}, policy, tfvars=values) if d["code"] == "POLICY.ACCESS_POLICY_MISMATCH"] == []
    stale = dict(values, authorized_invoker_members=["user:old@example.com"])
    assert [d["code"] for d in apv.validate({}, policy, tfvars=stale)] == ["POLICY.ACCESS_POLICY_MISMATCH"]


# ============================================================================ terraform: render_deploy_access_vars
def test_render_table(tf):
    r = tf.render_deploy_access_vars
    for doc, reason in ((None, "NO_ACCESS_RECORD"), ({}, "NO_ACCESS_RECORD"), ({"access": None}, "NO_ACCESS_RECORD"),
                        ({"access": _rec("PRIVATE_IAP"), "creation_mode": "EXPRESS"}, "EXPRESS_WORKLOAD"),
                        ({"access": PUBLIC_REC}, "PUBLIC_APP_RECORD")):
        text, summary = r(PID, doc)
        assert text == "{}" and summary["rendered"] is False and summary["reason"] == reason, doc
    text, summary = r(PID, {"access": _rec("PRIVATE_IAM", ["user:ana@example.com"]),
                            "access_updated_at": "2026-10-28T11:00:00+00:00", "access_updated_by": "admin@example.com",
                            "access_widening_approval": None})   # explicit null flag: nothing pending
    assert json.loads(text) == {"allow_unauthenticated": False, "enable_direct_iap": False,
                                "authorized_invoker_members": ["user:ana@example.com"]}
    assert summary == {"rendered": True, "mode": "PRIVATE_IAM", "invoker_principals": ["user:ana@example.com"],
                       "access_updated_at": "2026-10-28T11:00:00+00:00", "access_updated_by": "admin@example.com"}


@pytest.mark.parametrize("doc, error_class", [
    ({"access": _rec("PRIVATE_IAP"), "access_widening_approval": FLAG}, "ACCESS_WIDENING_UNAPPROVED"),
    ({"access": _rec("PRIVATE_IAP"), "access_widening_approval": "garbage"}, "ACCESS_WIDENING_UNAPPROVED"),
    ({"access": PUBLIC_REC, "access_widening_approval": FLAG}, "ACCESS_WIDENING_UNAPPROVED"),
    ({"access": _rec("PRIVATE_IAP", ["ana@example.com"])}, "ACCESS_POLICY_INVALID"),     # unprefixed member
    ({"access": {"mode": "PRIVATE_IAP"}}, "ACCESS_POLICY_INVALID"),
    ({"access": "PRIVATE_IAP"}, "ACCESS_POLICY_INVALID"),
    ({"access": _rec("PRIVATE_IAP", ["domain:allAuthenticatedUsers"])}, "ACCESS_POLICY_INVALID"),
    ({"access": _rec("PRIVATE_IAP", [])}, "ACCESS_POLICY_INCOMPLETE"),
])
def test_render_refusals_are_typed_and_stop_for_an_operator(tf, doc, error_class):
    with pytest.raises(tf.DeployAccessRefused) as ei:
        tf.render_deploy_access_vars(PID, doc)
    assert ei.value.error_class == error_class and ei.value.operator_required is True
    res = ei.value.result(PID, "t-1")
    assert res["status"] == "FAILED" and res["error_class"] == error_class and res["operator_required"] is True


def test_error_classes_equal_the_developer_stage_classes(tf):
    gw_dir = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
    if gw_dir not in sys.path:
        sys.path.insert(0, gw_dir)
    from developer_agent import errors
    for name in ("ACCESS_POLICY_INVALID", "ACCESS_POLICY_INCOMPLETE", "ACCESS_POLICY_UNAVAILABLE",
                 "ACCESS_WIDENING_UNAPPROVED"):
        assert getattr(tf, name) == getattr(errors, name)
    from shared.access_policy import ACCESS_WIDENING_APPROVAL_FIELD
    assert tf.ACCESS_WIDENING_APPROVAL_FIELD == ACCESS_WIDENING_APPROVAL_FIELD
    assert tf.PLATFORM_ACCESS_VARS_MANIFEST_KEY == "infra/workload/" + tf.PLATFORM_ACCESS_VARS_FILE == W + ACCESS_FILE


# ============================================================================ terraform: deploy_workload end to end
def _deploy_to_gated_plan(tf, monkeypatch, tmp_path, db, tree=COMMITTED):
    """The REAL deploy_workload up to the gated plan (`_compliance_gated_apply`): (plan command, workspace, fetches)."""
    cloud = _Cloud()
    _fake_cloud(monkeypatch, cloud)
    svc = _service(tf, monkeypatch, tmp_path, db, tree)
    fetched = []
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: fetched.append(1) or copy.deepcopy(dict(tree)))
    seen = {}

    def _tofu(cmd, cwd=None, **kw):
        if len(cmd) > 1 and cmd[1] == "plan" and any(a.startswith("-out=") for a in cmd):
            seen["plan"], seen["ws"] = list(cmd), cwd
            raise _Stop()
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(svc, "_run_subprocess", _tofu)
    with pytest.raises(_Stop):
        svc.deploy_workload(product_id=PID, trace_id="t-fd4dt", target_project_id=PROJECT, branch="main",
                            iac_engine="OPENTOFU")
    return seen["plan"], seen["ws"], fetched


def _read(ws, rel):
    with open(os.path.join(ws, rel), encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize("record, expected", [
    # narrowing: staff removed (the committed tfvars still lists ana + staff)
    (_rec("PRIVATE_IAP", ["user:ana@example.com"]),
     {"allow_unauthenticated": False, "enable_direct_iap": True, "authorized_invoker_members": ["user:ana@example.com"]}),
    # IAP -> IAM (narrowing), same members
    (_rec("PRIVATE_IAM"),
     {"allow_unauthenticated": False, "enable_direct_iap": False,
      "authorized_invoker_members": ["user:ana@example.com", "group:staff@example.com"]}),
], ids=["narrow-members", "iap-to-iam"])
def test_fast_path_applies_the_current_access_record(tf, monkeypatch, tmp_path, record, expected):
    plan, ws, _ = _deploy_to_gated_plan(tf, monkeypatch, tmp_path, _db({"project_id": PROJECT, "access": record}))
    assert json.loads(_read(ws, ACCESS_FILE)) == expected                # workspace root: auto-loaded by OpenTofu
    assert plan[-1] == f"-var-file={ACCESS_FILE}" and plan.count(f"-var-file={ACCESS_FILE}") == 1   # and named last
    # code unchanged: the committed files are written to the workspace exactly as committed
    for path, content in COMMITTED.items():
        assert _read(ws, path) == content, path
    # the committed access values are still the merged root tfvars' values (the override is the platform file only)
    import hcl2
    assert hcl2.loads(_read(ws, "terraform.tfvars"))["authorized_invoker_members"] == [
        "user:ana@example.com", "group:staff@example.com"]


@pytest.mark.parametrize("doc", [{"project_id": PROJECT}, {"project_id": PROJECT, "access": PUBLIC_REC},
                                 {"project_id": PROJECT, "access": _rec("PRIVATE_IAP", ["user:z@example.com"]),
                                  "creation_mode": "EXPRESS"}],
                         ids=["no-record", "public", "express"])
def test_nothing_rendered_keeps_the_committed_values_and_neutralizes_a_committed_file(tf, monkeypatch, tmp_path, doc):
    """Negative (Do No Harm): nothing rendered -> the platform file is "{}" and the committed values apply unchanged. A
    repository file at the platform path (here one that would list an outsider) is replaced, never used."""
    hostile = json.dumps({"authorized_invoker_members": ["user:outsider@example.org"], "allow_unauthenticated": True})
    tree = dict(COMMITTED, **{W + ACCESS_FILE: hostile, ACCESS_FILE: hostile})
    plan, ws, _ = _deploy_to_gated_plan(tf, monkeypatch, tmp_path, _db(doc), tree)
    assert _read(ws, ACCESS_FILE) == "{}" and _read(ws, W + ACCESS_FILE) == "{}"
    assert f"-var-file={ACCESS_FILE}" in plan
    import hcl2
    assert hcl2.loads(_read(ws, "terraform.tfvars"))["authorized_invoker_members"] == [
        "user:ana@example.com", "group:staff@example.com"]
    for path, content in COMMITTED.items():
        assert _read(ws, path) == content, path


def test_no_firestore_client_renders_nothing(tf, monkeypatch, tmp_path):
    plan, ws, _ = _deploy_to_gated_plan(tf, monkeypatch, tmp_path, None)
    assert _read(ws, ACCESS_FILE) == "{}"


@pytest.mark.parametrize("flag", [FLAG, "garbage"])
def test_a_widening_without_approval_is_blocked_before_anything_runs(tf, monkeypatch, tmp_path, flag):
    cloud = _Cloud()
    _fake_cloud(monkeypatch, cloud)
    db = _db({"project_id": PROJECT, "access": _rec("PRIVATE_IAP", ["user:ana@example.com", "user:bo@example.com"]),
              "access_widening_approval": flag})
    svc = _service(tf, monkeypatch, tmp_path, db, COMMITTED)
    calls = []
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: calls.append("fetch") or dict(COMMITTED))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: calls.append("tofu") or {"success": True})
    synced = []
    monkeypatch.setattr(svc, "_sync_feature_requests", lambda **k: synced.append(k))
    res = svc.deploy_workload(product_id=PID, trace_id="t-w", target_project_id=PROJECT, branch="main",
                              iac_engine="OPENTOFU")
    assert res["status"] == "FAILED" and res["error_class"] == "ACCESS_WIDENING_UNAPPROVED"
    assert res["operator_required"] is True and "Full Swarm Rebuild" in res["error"]
    assert calls == [] and cloud.calls == []                        # nothing fetched, built, planned or applied
    assert synced and synced[0]["is_successful_deploy"] is False


class _CountingDB:
    """Counts every collection() call (any Firestore read starts with one)."""

    def __init__(self, doc):
        self.calls, self.doc = 0, doc

    def collection(self, name):
        self.calls += 1
        return _AuditDB(self.doc).collection(name)


@pytest.mark.parametrize("pid", ["Shop", "shop_api", "shop api", "-shop", "shop-", "", "../shop"])
def test_rt_f3_a_non_canonical_product_id_is_refused_before_any_read(tf, tmp_path, pid):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "b"), firestore_client=MagicMock())
    svc.db = _CountingDB({"access": _rec("PRIVATE_IAP"), "access_widening_approval": FLAG})
    svc._deploy_workload_impl = lambda **kw: pytest.fail("the impl must not run")
    res = svc.deploy_workload(product_id=pid, trace_id="t-f3")
    assert res["status"] == "FAILED" and res["error_class"] == "PRODUCT_ID_INVALID"
    assert res["operator_required"] is True and svc.db.calls == 0


def test_rt_f3_a_canonical_product_id_is_read_unchanged(tf, tmp_path):
    """Negative: a canonical id reaches the record read and the impl exactly as given."""
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "b"), firestore_client=MagicMock())
    svc.db = _AuditDB({"access": _rec("PRIVATE_IAP", ["user:ana@example.com"])})
    got = {}
    svc._deploy_workload_impl = lambda **kw: got.update(kw) or {"status": "FAILED"}
    svc.deploy_workload(product_id="shop-api-2", trace_id="t-f3")
    assert got["product_id"] == "shop-api-2"
    assert json.loads(got["hcl_files"][W + ACCESS_FILE])["authorized_invoker_members"] == ["user:ana@example.com"]


def test_gated_plan_without_the_platform_file_is_unchanged(tf, tmp_path):
    """Negative: a workspace without the platform file (any other caller) plans exactly as before."""
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "b"), firestore_client=MagicMock())
    seen = []

    def _tofu(cmd, cwd=None, **kw):
        seen.append(list(cmd))
        return {"success": False, "exit_code": 1, "stdout": "", "stderr": "stop"}

    svc._run_subprocess = _tofu
    ws = tmp_path / "ws"
    ws.mkdir()
    svc._compliance_gated_apply(PID, "t", str(ws), "OPENTOFU")
    assert seen[0] == ["terraform", "plan", "-out=" + tf.compliance_gate.GATE_PLAN_FILE, "-input=false", "-no-color"]
    (ws / ACCESS_FILE).write_text("{}")
    seen.clear()
    svc._compliance_gated_apply(PID, "t", str(ws), "OPENTOFU")
    assert seen[0][-1] == f"-var-file={ACCESS_FILE}"


class _AuditDB:
    """workloads/{pid} read + audit_logs writes (records every set)."""

    def __init__(self, doc):
        self.doc, self.sets = doc, []

    def collection(self, name):
        db = self

        class _Doc:
            def __init__(self, path):
                self.path = path

            def get(self):
                return types.SimpleNamespace(exists=db.doc is not None, to_dict=lambda: copy.deepcopy(db.doc))

            def collection(self, sub):
                return _Col(self.path + (sub,))

            def set(self, data, merge=False):
                db.sets.append((self.path, data))

        class _Col:
            def __init__(self, path):
                self.path = path

            def document(self, doc_id=None):
                return _Doc(self.path + (doc_id or "auto",))

        return _Col((name,))


@pytest.mark.parametrize("status, doc, audited", [
    ("SUCCESS", {"access": _rec("PRIVATE_IAP", ["user:ana@example.com"]), "access_updated_at": "u1",
                 "access_updated_by": "admin@example.com"}, True),
    ("FAILED", {"access": _rec("PRIVATE_IAP", ["user:ana@example.com"])}, False),
    ("SUCCESS", {"access": PUBLIC_REC}, False),
    ("SUCCESS", {}, False),
])
def test_a_successful_deploy_that_applied_the_record_is_audited(tf, tmp_path, status, doc, audited):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "b"), firestore_client=MagicMock())
    svc.db = _AuditDB(doc)
    got = {}

    def _impl(**kw):
        got.update(kw)
        return {"status": status}

    svc._deploy_workload_impl = _impl
    res = svc.deploy_workload(product_id=PID, trace_id="t-a", hcl_files={"extra.tf": "# x\n"})
    assert res["status"] == status
    assert got["hcl_files"]["extra.tf"] == "# x\n"                     # the caller's files are kept
    assert W + ACCESS_FILE in got["hcl_files"]
    audits = [d for p, d in svc.db.sets if p[:3] == ("workloads", PID, "audit_logs")]
    if not audited:
        assert audits == []
        return
    assert len(audits) == 1
    a = audits[0]
    assert a["action"] == "WORKLOAD_ACCESS_APPLIED" and a["trace_id"] == "t-a" and a["mode"] == "PRIVATE_IAP"
    assert a["invoker_principals"] == ["user:ana@example.com"] and a["access_updated_at"] == "u1"
    assert a["var_file"] == ACCESS_FILE


# ============================================================================ real engine: -var-file precedence
def _tofu_bin():
    pinned = os.environ.get("STACKVEND_PINNED_TOFU")
    if pinned and os.path.isfile(pinned):
        return pinned
    return shutil.which("tofu")


def test_real_engine_the_platform_file_wins_over_every_committed_variable_file(tmp_path):
    tofu = _tofu_bin()
    if not tofu:
        pytest.skip("no tofu binary on PATH or STACKVEND_PINNED_TOFU (the unit tests above still apply)")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "main.tf").write_text(
        'variable "authorized_invoker_members" {\n  type    = list(string)\n  default = ["user:default@example.com"]\n}\n'
        'variable "enable_direct_iap" {\n  type    = bool\n  default = false\n}\n'
        'output "members" {\n  value = var.authorized_invoker_members\n}\n'
        'output "iap" {\n  value = var.enable_direct_iap\n}\n')
    (ws / "terraform.tfvars").write_text('authorized_invoker_members = ["user:committed@example.com"]\n'
                                         'enable_direct_iap = true\n')
    # a committed auto file that sorts after the platform file
    (ws / "zzz-later.auto.tfvars").write_text('authorized_invoker_members = ["user:later@example.com"]\n')
    (ws / ACCESS_FILE).write_text(json.dumps({"allow_unauthenticated": False, "enable_direct_iap": False,
                                              "authorized_invoker_members": ["user:ana@example.com"]}))
    env = dict(os.environ, CHECKPOINT_DISABLE="1", TF_IN_AUTOMATION="1", TF_DATA_DIR=str(ws / ".tfdata"))
    init = subprocess.run([tofu, "init", "-input=false", "-no-color"], cwd=ws, env=env, capture_output=True,
                          text=True, timeout=120)
    assert init.returncode == 0, init.stderr
    plan = subprocess.run([tofu, "plan", "-out=p.tfplan", "-input=false", "-no-color", f"-var-file={ACCESS_FILE}"],
                          cwd=ws, env=env, capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stderr
    shown = subprocess.run([tofu, "show", "-json", "p.tfplan"], cwd=ws, env=env, capture_output=True, text=True,
                           timeout=120)
    outputs = json.loads(shown.stdout)["planned_values"]["outputs"]
    assert outputs["members"]["value"] == ["user:ana@example.com"] and outputs["iap"]["value"] is False


# ============================================================================ gateway: deploy-only gate
def _gw_client(gw, db):
    from fastapi.testclient import TestClient
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    return TestClient(gw.app)


@pytest.mark.parametrize("flag", [FLAG, "garbage"])
def test_deploy_only_gate_refuses_a_pending_widening(gw, flag):
    db = GwFakeDB()
    db.docs[f"workloads/{PID}"] = {"default_branch": "main", "access": _rec("PRIVATE_IAP"),
                                   "access_widening_approval": flag}
    r = _gw_client(gw, db).post("/governance/deploy-only-gate",
                                json={"trace_id": "tr-fd4dt-1", "product_id": PID, "branch": "main"})
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["error_class"] == "POLICY_REJECTED" and body["stage"] == "deploy_only_gate"
    assert body["reason"] == "ACCESS_WIDENING_PENDING"


def test_deploy_only_gate_allows_without_a_pending_widening(gw):
    db = GwFakeDB()
    db.docs[f"workloads/{PID}"] = {"default_branch": "main", "access": _rec("PRIVATE_IAP"),
                                   "access_widening_approval": None}
    r = _gw_client(gw, db).post("/governance/deploy-only-gate",
                                json={"trace_id": "tr-fd4dt-1", "product_id": PID, "branch": "main"})
    assert r.status_code == 200 and r.json()["status"] == "ALLOW"


# ============================================================================ CC: Auto routing (B)
STARTED, COMPLETED = "2026-10-28T09:00:00+00:00", "2026-10-28T09:30:00+00:00"
AFTER, BEFORE, MID = "2026-10-28T10:00:00+00:00", "2026-10-28T08:00:00+00:00", "2026-10-28T09:10:00+00:00"
OK_RUN = {"status": "SUCCEEDED", "started_at": STARTED, "completed_at": COMPLETED, "request_id": "fr-1"}
OK_WL = {"access": _rec("PRIVATE_IAP", ["user:ana@example.com"]), "access_updated_at": AFTER,
         "creation_mode": "AGENT"}
OK_FR = {"product_id": PID, "created_at": BEFORE}
OK_AUDIT = [{"action": "WORKLOAD_ACCESS_SET", "timestamp": AFTER, "previous_access": _rec("PRIVATE_IAP"),
             "new_access": _rec("PRIVATE_IAP", ["user:ana@example.com"])},
            {"action": "WORKLOAD_ACCESS_SET", "timestamp": BEFORE, "previous_access": PUBLIC_REC,   # before the run
             "new_access": _rec("PRIVATE_IAP")},
            {"action": "DECOMMISSION", "timestamp": AFTER}]


def _route(wl, run=OK_RUN, workload=OK_WL, fr=OK_FR, frs=None, audit=None, request_id="fr-1"):
    def _frs():
        if isinstance(frs, Exception):
            raise frs
        return [fr] if frs is None else frs

    def _audit():
        if isinstance(audit, Exception):
            raise audit
        return OK_AUDIT if audit is None else audit

    return wl.access_only_fast_path(prev_exec=run, request_id=request_id, feature_request=fr, workload=workload,
                                    load_feature_requests=_frs, load_access_audit=_audit)


def _iam_to_public_audit():
    return [{"action": "WORKLOAD_ACCESS_SET", "timestamp": AFTER, "previous_access": PUBLIC_REC,
             "new_access": _rec("PRIVATE_IAP", ["user:ana@example.com"])}]


ROUTING_CASES = [
    # positives
    ("access-only", {}, (True, "ACCESS_ONLY_CHANGE")),
    ("zulu-timestamps", {"run": dict(OK_RUN, started_at="2026-10-28T09:00:00Z", completed_at="2026-10-28T09:30:00Z")},
     (True, "ACCESS_ONLY_CHANGE")),
    ("no-request-id-recorded", {"run": {k: v for k, v in OK_RUN.items() if k != "request_id"}},
     (True, "ACCESS_ONLY_CHANGE")),
    ("iap-to-iam", {"workload": dict(OK_WL, access=_rec("PRIVATE_IAM", ["user:ana@example.com"])),
                    "audit": [dict(OK_AUDIT[0], new_access=_rec("PRIVATE_IAM", ["user:ana@example.com"]))]},
     (True, "ACCESS_ONLY_CHANGE")),
    # negatives
    ("failed-run", {"run": dict(OK_RUN, status="FAILED")}, (False, "LAST_RUN_NOT_SUCCEEDED")),
    ("active-run", {"run": dict(OK_RUN, status="ACTIVE")}, (False, "LAST_RUN_NOT_SUCCEEDED")),
    ("lowercase-status", {"run": dict(OK_RUN, status="succeeded")}, (False, "LAST_RUN_NOT_SUCCEEDED")),
    ("no-run", {"run": {}}, (False, "LAST_RUN_NOT_SUCCEEDED")),
    ("no-completed-at", {"run": dict(OK_RUN, completed_at=None)}, (False, "RUN_TIMES_UNREADABLE")),
    ("naive-timestamp", {"run": dict(OK_RUN, completed_at="2026-10-28T09:30:00")}, (False, "RUN_TIMES_UNREADABLE")),
    ("express", {"workload": dict(OK_WL, creation_mode="EXPRESS")}, (False, "EXPRESS_WORKLOAD")),
    ("other-feature-request", {"request_id": "fr-2"}, (False, "OTHER_FEATURE_REQUEST")),
    ("access-not-changed", {"workload": dict(OK_WL, access_updated_at=BEFORE)}, (False, "NO_ACCESS_CHANGE_SINCE_SUCCESS")),
    # RT F2: saved at the completion instant cannot be proved to post-date the deploy's read
    ("access-saved-at-completion", {"workload": dict(OK_WL, access_updated_at=COMPLETED)},
     (False, "NO_ACCESS_CHANGE_SINCE_SUCCESS")),
    ("access-changed-during-run", {"workload": dict(OK_WL, access_updated_at=MID)},
     (False, "NO_ACCESS_CHANGE_SINCE_SUCCESS")),
    ("access-never-changed", {"workload": {k: v for k, v in OK_WL.items() if k != "access_updated_at"}},
     (False, "NO_ACCESS_CHANGE_SINCE_SUCCESS")),
    ("widening-pending", {"workload": dict(OK_WL, access_widening_approval=FLAG)}, (False, "ACCESS_WIDENING_PENDING")),
    ("public-record", {"workload": dict(OK_WL, access=PUBLIC_REC)}, (False, "ACCESS_RECORD_NOT_PRIVATE")),
    ("invalid-record", {"workload": dict(OK_WL, access={"mode": "PRIVATE_IAP"})}, (False, "ACCESS_RECORD_NOT_PRIVATE")),
    ("incomplete-record", {"workload": dict(OK_WL, access=_rec("PRIVATE_IAP", []))}, (False, "ACCESS_RECORD_NOT_PRIVATE")),
    ("spec-edited", {"fr": dict(OK_FR, updated_at=AFTER)}, (False, "FEATURE_REQUEST_CHANGED")),
    ("new-feature-request", {"frs": [OK_FR, {"product_id": PID, "created_at": AFTER}]}, (False, "NEW_FEATURE_REQUEST")),
    ("unparseable-fr-created", {"frs": [{"product_id": PID, "created_at": "yesterday"}]}, (False, "NEW_FEATURE_REQUEST")),
    ("from-public", {"audit": _iam_to_public_audit()}, (False, "ACCESS_MODE_CHANGE_NEEDS_REBUILD")),
    ("no-audit-entry", {"audit": [OK_AUDIT[1]]}, (False, "HISTORY_UNREADABLE")),
    ("unreadable-history", {"frs": RuntimeError("down")}, (False, "HISTORY_UNREADABLE")),
    ("unreadable-audit", {"audit": RuntimeError("down")}, (False, "HISTORY_UNREADABLE")),
]


@pytest.mark.parametrize("name, kw, expected", ROUTING_CASES, ids=[c[0] for c in ROUTING_CASES])
def test_auto_routing_table(cc, name, kw, expected):
    _, wl = cc
    assert _route(wl, **kw) == expected


# -- the retrigger route wires it (in-memory Firestore with filtering + subcollections, fake publisher)
class _Snap:
    def __init__(self, id_, data):
        self.id, self._d, self.exists = id_, data, data is not None

    def to_dict(self):
        return copy.deepcopy(self._d) if self._d is not None else None


class _RDoc:
    def __init__(self, db, path):
        self.db, self.path, self.id = db, path, path[-1]

    def get(self):
        return _Snap(self.id, self.db.store.get(self.path))

    def set(self, data, merge=False):
        cur = self.db.store.get(self.path) if merge else None
        self.db.store[self.path] = {**(cur or {}), **copy.deepcopy(data)}

    def collection(self, name):
        return _RCol(self.db, self.path + (name,))


class _RCol:
    def __init__(self, db, path, filters=()):
        self.db, self.path, self.filters = db, path, filters

    def document(self, id_):
        return _RDoc(self.db, self.path + (id_,))

    def where(self, field, op, value):
        return _RCol(self.db, self.path, self.filters + ((field, op, value),))

    def limit(self, *_):
        return self

    def stream(self):
        return [_Snap(p[-1], d) for p, d in list(self.db.store.items())
                if len(p) == len(self.path) + 1 and p[:-1] == self.path
                and all(op == "==" and d.get(f) == v for f, op, v in self.filters)]


class _RDB:
    def __init__(self):
        self.store = {}

    def __bool__(self):
        return True

    def collection(self, name):
        return _RCol(self, (name,))


class _Pub:
    def __init__(self):
        self.messages = []

    def publish(self, topic, data):
        self.messages.append((topic, json.loads(data.decode("utf-8"))))
        return types.SimpleNamespace(result=lambda timeout=None: "msg-1")


def _retrigger(wl, monkeypatch, workload, audit, body):
    db, pub = _RDB(), _Pub()
    db.store[("feature_requests", "fr-1")] = dict(OK_FR, title="Shop", description="spec")
    db.store[("workloads", PID)] = dict(workload, project_id="sv-shop-1a2b", github_repo="example-org/shop")
    db.store[("pipeline_executions", "intake-shop-1")] = dict(OK_RUN, trace_id="intake-shop-1", product_id=PID,
                                                              current_stage="COMPLETE")
    for i, entry in enumerate(audit):
        db.store[("workloads", PID, "audit_logs", f"a{i}")] = entry
    main_mod = types.SimpleNamespace(project_id="mock-stackvend-project", get_pubsub_publisher=lambda: pub)
    monkeypatch.setattr(wl, "db", db)
    monkeypatch.setattr(wl, "verify_workload_access", lambda *a, **k: None)
    monkeypatch.setattr(wl, "get_caller_main_module", lambda: main_mod)
    monkeypatch.setattr(wl, "_refuse_new_run_in_maintenance", lambda *a, **k: None)
    from build_admission_support import admit_every_build
    admit_every_build(monkeypatch, wl)   # BUILD-ADMISSION-QUEUE: this store holds no build slots
    req = MagicMock()
    req.state.user_email = "operator@example.com"
    res = wl.retrigger_feature_request_build(PID, "fr-1", req, body=body)
    return res, pub


def test_retrigger_auto_after_access_only_change_picks_fast_path(cc, monkeypatch):
    _, wl = cc
    res, pub = _retrigger(wl, monkeypatch, OK_WL, OK_AUDIT, {"execution_mode": "AUTO"})
    assert res["execution_mode"] == "DEPLOY_ONLY" and res["trace_id"].startswith(f"fastpath-{PID}-")
    assert pub.messages[0][1]["execution_mode"] == "DEPLOY_ONLY"


@pytest.mark.parametrize("workload, audit, body, mode", [
    (dict(OK_WL, access_updated_at=BEFORE), OK_AUDIT, {"execution_mode": "AUTO"}, "FULL"),     # nothing changed
    (dict(OK_WL, access_widening_approval=FLAG), OK_AUDIT, {"execution_mode": "AUTO"}, "FULL"),
    (OK_WL, _iam_to_public_audit(), {"execution_mode": "AUTO"}, "FULL"),                       # from Public
    (OK_WL, OK_AUDIT, {"execution_mode": "FULL"}, "FULL"),                                     # explicit choice kept
    (OK_WL, OK_AUDIT, None, "DEPLOY_ONLY"),                                                    # no body = Auto
])
def test_retrigger_routing_negatives_and_explicit_modes(cc, monkeypatch, workload, audit, body, mode):
    _, wl = cc
    res, _ = _retrigger(wl, monkeypatch, workload, audit, body)
    assert res["execution_mode"] == mode

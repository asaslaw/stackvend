"""
Unit Tests for mcp-terraform-server
Tests workspace creation, subprocess execution, plan JSON parsing, and MCP endpoints.
"""

import json
import logging
import os
import shutil
import sys
import tempfile
import pathlib
from unittest.mock import MagicMock, patch

from tests.tofu_popen_fake import popen_from_run  # FD-4AQ W3: _run_subprocess uses Popen

# FD-4AY: no built-in GitHub owner; this suite runs as an install whose workloads org is "example-org".
os.environ.setdefault("GITHUB_ORG", "example-org")

for m in [
    'google', 'google.auth', 'google.auth.transport', 'google.auth.transport.requests',
    'google.cloud', 'google.cloud.firestore', 'google.cloud.storage', 'google.cloud.secretmanager',
    'google.cloud.run_v2', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

import google
google.auth = sys.modules.get('google.auth', MagicMock())
google.cloud = sys.modules.get('google.cloud', MagicMock())
google.cloud.storage = sys.modules.get('google.cloud.storage', MagicMock())

try:
    import httpx
except ImportError:
    sys.modules['httpx'] = MagicMock()

try:
    from fastapi.testclient import TestClient
    from main import app, AsyncDeployRequest, trigger_tf_applier_job
except ImportError:
    TestClient = None
    app = None
    AsyncDeployRequest = None
    trigger_tf_applier_job = None

try:
    import pytest
except ImportError:
    class _MockPytest:
        @staticmethod
        def fixture(func):
            return func
    pytest = _MockPytest()

from service import (
    TerraformService,
    extract_apis_from_hcl,
    sanitize_wheel_requirements,
    is_cloud_capacity_stockout,
)


@pytest.fixture(autouse=True)
def _compliance_gate_passes(monkeypatch):
    """Lane 14 PR-0: these tests exercise the deploy/apply machinery, not compliance. The plan gate itself fails closed
    without a compliance server; its behaviour is tested in tests/test_lane14_compliance_gate.py. Here it answers
    PASS without planning, so the subprocess call sequences under test are unchanged. Since RT F4 the gated apply
    plans to a file and applies that file; here it is the bare apply these sequences were written for (the gated
    plan-file flow is tested in tests/test_lane14_compliance_gate.py and tests/test_terraform_locking.py)."""
    monkeypatch.setattr(
        TerraformService, "_compliance_gate_check",
        lambda self, *a, **k: {"passed": True, "evidence": {"verified": True, "test": "gate stubbed PASS"}},
    )
    def _bare_apply(self, product_id, trace_id, workspace_dir, active_engine, destroy_policy=None, plan_sink=None,
                    pre_apply_adopt=None, expected_root_vars=None):
        # DEPLOY-ROOT-VARS: the root-variable check is tested in tests/test_deploy_root_vars.py (no plan here)
        # EXP-7: deploy_workload passes destroy_policy (None outside Express) to every gated apply.
        # FD-4CY W7: the plan a test hands in (`_w7_plan_json` on the service) is the plan this apply "applied"; no
        # plan (the default) means a 409 has no plan address to adopt. Pass 0 adoption runs on that plan too.
        plan_json = getattr(self, "_w7_plan_json", None)
        if plan_json is not None and pre_apply_adopt is not None:
            pre_apply_adopt(plan_json)
        if plan_sink is not None:
            plan_sink["plan_json"] = plan_json
        return self._run_subprocess(["terraform", "apply", "-input=false", "-auto-approve", "-no-color"],
                                    cwd=workspace_dir, iac_engine=active_engine)

    monkeypatch.setattr(TerraformService, "_compliance_gated_apply", _bare_apply)


# RT14-22: these tests run the real engine resolution (download + checksum, never PATH).
_REAL_ENGINE_RESOLUTION_TESTS = frozenset({
    "test_row7_binary_already_cached_no_download_and_workspace_identical",
    "test_row7_failed_download_fails_typed_before_writing",
    "test_row7_forbidden_terraform_version_fails_closed_before_writing",
})


@pytest.fixture(autouse=True)
def _rt14_22_engine_stand_in(request, monkeypatch):
    """RT14-22: production runs only a downloaded engine verified against binary_checksums.py (never a PATH binary;
    tests/test_rt14_tf_destructive_fake_success.py and the row7 tests here pin that). The other tests in this file test
    the deploy machinery around the engine, so a verified engine is stood in by the host's PATH binary (or the bare
    name, as `shutil.which` patches in these tests expect); no test here downloads anything."""
    if request.node.originalname in _REAL_ENGINE_RESOLUTION_TESTS:
        return
    import service as _svc_mod

    def _stand_in(self, engine="TERRAFORM", version=None):
        name = "tofu" if (engine or "").strip().upper() in ("OPENTOFU", "TOFU") else "terraform"
        return _svc_mod.shutil.which(name) or name

    monkeypatch.setattr(TerraformService, "_ensure_binary", _stand_in)


@pytest.fixture
def mock_tf_service(tmp_path):
    mock_db = MagicMock()
    return TerraformService(
        project_id="test-project",
        state_bucket="castor-tfstate-test-project",
        workspace_base_dir=str(tmp_path),
        firestore_client=mock_db,
    )


@pytest.fixture
def tf_svc(mock_tf_service):
    return mock_tf_service


def test_health_check():
    if not TestClient or not app:
        return
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_prepare_workspace(mock_tf_service):
    hcl_files = {
        "main.tf": 'resource "google_cloud_run_v2_service" "app" {}',
        "variables.tf": 'variable "project_id" { type = string }',
    }
    workspace_dir = mock_tf_service.prepare_workspace("auth-service", "trace-123", hcl_files)

    assert os.path.exists(workspace_dir)
    assert os.path.exists(os.path.join(workspace_dir, "backend.tf"))
    assert os.path.exists(os.path.join(workspace_dir, "main.tf"))

    with open(os.path.join(workspace_dir, "backend.tf")) as f:
        content = f.read()
        assert "castor-tfstate-test-project" in content
        assert "workloads/auth-service" in content


def test_generate_plan_mocked(mock_tf_service):
    mock_plan_json = {
        "resource_changes": [
            {
                "type": "google_cloud_run_v2_service",
                "name": "api",
                "change": {"actions": ["create"]},
            }
        ]
    }

    with patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
         patch.object(mock_tf_service, "_run_subprocess") as mock_sub:
        mock_sub.side_effect = [
            {"success": True, "stdout": "Init success", "stderr": "", "exit_code": 0},  # init
            {"success": True, "stdout": "{}", "stderr": "", "exit_code": 0},            # validate
            {"success": True, "stdout": "Plan: 1 to add", "stderr": "", "exit_code": 0}, # plan
            {"success": True, "stdout": json.dumps(mock_plan_json), "stderr": "", "exit_code": 0}, # show -json
        ]

        result = mock_tf_service.generate_plan(
            "auth-service",
            "trace-123",
            {"main.tf": "resource foo {}"},
        )

        assert result["status"] == "PLAN_READY"
        assert result["resource_changes"]["add"] == 1
        assert result["resource_changes"]["destroy"] == 0
        assert result["is_safe_autonomous"] is True


def test_apply_plan_mocked(mock_tf_service):
    workspace_dir = mock_tf_service.prepare_workspace("auth-service", "trace-456", {"main.tf": "..."})

    with open(os.path.join(workspace_dir, "tfplan"), "wb") as fh:
        fh.write(b"saved-plan")
    safe_plan = {"configuration": {"root_module": {}},   # FD-4AW-b: real `show -json` always carries it
                 "resource_changes": [{"address": "google_cloud_run_v2_service.api", "change": {"actions": ["create"]}}]}

    with patch.object(mock_tf_service, "_run_subprocess") as mock_sub:
        mock_sub.side_effect = [
            {"success": True, "stdout": json.dumps(safe_plan), "stderr": "", "exit_code": 0},  # show -json tfplan
            {"success": True, "stdout": "Apply complete! Resources: 1 added.", "stderr": "", "exit_code": 0},  # apply
            {"success": True, "stdout": json.dumps({"url": {"value": "https://api.run.app"}}), "stderr": "", "exit_code": 0}, # output
        ]

        result = mock_tf_service.apply_plan("auth-service", "trace-456")
        assert result["status"] == "APPLIED"
        assert result["outputs"]["url"]["value"] == "https://api.run.app"
        assert mock_sub.call_args_list[1][0][0] == ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"]


def test_deferred_failure_for_orchestrated_runs(mock_tf_service):
    """When apply fails in an orchestrated run (trace_id='retry-*'), feature_requests is NOT set to FAILED."""
    mock_doc = MagicMock()
    mock_doc.id = "spec-123"
    mock_doc.to_dict.return_value = {"status": "IN_PROGRESS"}
    mock_tf_service.db.collection.return_value.where.return_value.stream.return_value = [mock_doc]

    with patch.object(mock_tf_service, "apply_plan", return_value={"status": "FAILED", "error": "custom.tf syntax error"}), \
         patch.object(mock_tf_service, "prepare_workspace", return_value="/tmp/test"):
        res = mock_tf_service.apply_infrastructure(
            product_id="testplan02-a",
            trace_id="retry-testplan02-a-123",
            target_project_id="testplan02-a",
        )
        assert res["status"] == "FAILED"

        mock_set = mock_tf_service.db.collection.return_value.document.return_value.set
        assert mock_set.called
        call_payload = mock_set.call_args[0][0]
        assert call_payload.get("status") != "FAILED"
        assert "last_iac_error" in call_payload


def test_standalone_run_marks_failure(mock_tf_service):
    """When apply fails in an un-orchestrated standalone run, feature_requests IS set to FAILED."""
    mock_doc = MagicMock()
    mock_doc.id = "spec-standalone"
    mock_doc.to_dict.return_value = {"status": "IN_PROGRESS"}
    mock_tf_service.db.collection.return_value.where.return_value.stream.return_value = [mock_doc]

    with patch.object(mock_tf_service, "apply_plan", return_value={"status": "FAILED", "error": "standalone error"}), \
         patch.object(mock_tf_service, "prepare_workspace", return_value="/tmp/test"):
        res = mock_tf_service.apply_infrastructure(
            product_id="testplan02-a",
            trace_id="standalone-manual-run",
            target_project_id="testplan02-a",
        )
        assert res["status"] == "FAILED"

        mock_set = mock_tf_service.db.collection.return_value.document.return_value.set
        assert mock_set.called
        call_payload = mock_set.call_args[0][0]
        assert call_payload.get("status") == "FAILED"


def test_successful_deploy_closes_only_the_runs_feature_request(mock_tf_service):
    """FEATURE-REQUEST-CLOSE-OWN-ONLY through the real deploy: a request filed while the run built is left open."""
    stored = {"spec-1": {"product_id": "empty-project", "status": "IN_DEVELOPMENT"},
              "feat-2": {"product_id": "empty-project", "status": "PENDING_TRIAGE"}}
    writes = {}

    def _fr_doc(fr_id):
        doc = MagicMock()
        doc.id = fr_id
        doc.to_dict.return_value = stored[fr_id]
        doc.set.side_effect = lambda data, merge=False: writes.setdefault(fr_id, []).append(data)
        return doc

    run_snap = MagicMock(exists=True)
    run_snap.to_dict.return_value = {"product_id": "empty-project", "request_id": "spec-1"}

    def _collection(name):
        col = MagicMock()
        if name == "feature_requests":
            col.where.return_value.stream.return_value = [_fr_doc(fr_id) for fr_id in stored]
            col.document.side_effect = _fr_doc
        elif name == "pipeline_executions":
            col.document.return_value.get.return_value = run_snap
        else:
            col.document.return_value.get.return_value = MagicMock(exists=False)
        return col

    mock_tf_service.db = MagicMock()
    mock_tf_service.db.collection.side_effect = _collection
    files = {"main.tf": 'module "workload_foundation" {\n  source = "./modules/workload-foundation/base"\n}\n',
             "variables.tf": 'variable "project_id" { type = string }\n',
             "outputs.tf": 'output "workload_sa_email" { value = "sa@example.com" }\n'}

    with patch("google.cloud.storage.Client"), \
         patch("google.cloud.secretmanager.SecretManagerServiceClient"), \
         patch.object(mock_tf_service, "_fetch_repo_files", return_value={}), \
         patch.object(mock_tf_service, "_build_and_push_container"), \
         patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
         patch.object(mock_tf_service, "_run_subprocess", return_value={
             "success": True, "stdout": "Apply complete! Resources: 5 added, 0 changed, 0 destroyed.", "stderr": ""}):
        result = mock_tf_service.deploy_workload(product_id="empty-project", trace_id="retry-empty-1", hcl_files=files,
                                                 target_project_id="target-proj-empty")

    assert result["status"] == "SUCCESS"
    assert [w["status"] for w in writes["spec-1"]] == ["COMPLETED"] and writes["spec-1"][0]["trace_id"] == "retry-empty-1"
    assert "feat-2" not in writes


def test_mcp_tools_list():
    if not TestClient or not app:
        return
    client = TestClient(app)
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 200
    tools = response.json()["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    # FD-4AO: agents get read-only planning and drift tools only.
    assert tool_names == ["terraform_plan", "terraform_drift_check"]
    descriptions = " ".join(t["description"] for t in tools)
    assert "evaluates safety limits" not in descriptions


def test_hb42_sanitize_python_paths_is_deleted():
    """FD-4AD: the post-QA `.py` rewrite is gone (it prepended an import above `from __future__`)."""
    import service as svc_mod
    assert not hasattr(svc_mod, "sanitize_python_paths")


def test_prepare_workspace_writes_python_byte_identical(mock_tf_service):
    """FD-4AD Do No Harm: prepare_workspace writes every `.py` exactly as committed (after QA nothing rewrites app
    code): a `from __future__` file, an `apps/<svc>/static` literal and an `exceptions.is_transient_error` call stay."""
    main_py = (
        "from __future__ import annotations\n"
        "from google.api_core import exceptions\n"
        'app.mount("/static", StaticFiles(directory="apps/my-service/static"))\n'
        "RETRY = exceptions.is_transient_error\n"
    )
    files = {
        "apps/my-service/main.py": main_py,
        "main.tf": 'resource "google_cloud_run_v2_service" "app" {}',
    }
    workspace_dir = mock_tf_service.prepare_workspace("my-service", "trace-py", files)
    py_path = os.path.join(workspace_dir, "apps/my-service/main.py")
    assert os.path.exists(py_path)
    with open(py_path) as f:
        assert f.read() == main_py


def test_deploy_workload_failure_reported(mock_tf_service):
    with patch("google.cloud.storage.Client"), \
         patch("google.cloud.secretmanager.SecretManagerServiceClient"), \
         patch.object(mock_tf_service, "prepare_workspace", return_value=mock_tf_service.workspace_base_dir), \
         patch.object(mock_tf_service, "_fetch_repo_files", return_value={}), \
         patch.object(mock_tf_service, "_build_and_push_container", return_value=True), \
         patch.object(mock_tf_service, "_run_subprocess") as mock_sub:
        # Simulate terraform apply failing (e.g. revision rollout timeout)
        # but terraform output returning previous state URL
        mock_sub.side_effect = [
            {"success": True, "stdout": "", "stderr": "", "exit_code": 0},  # init
            {"success": True, "stdout": "", "stderr": "", "exit_code": 0},  # validate
            # FD-4CY W7: no `state list` any more (Pass 0 adopts from the gated plan)
            {"success": False, "stdout": "", "stderr": "Revision not ready", "exit_code": 1},  # apply fails
        ]

        result = mock_tf_service.deploy_workload("test-service", "trace-fail", {"main.tf": "..."})
        assert result["status"] == "FAILED"
        assert result["stderr"] == "Revision not ready"


def test_buildpack_tarball_contract_and_parallel_steps(mock_tf_service, tmp_path):
    import io
    import tarfile

    workspace_dir = str(tmp_path / "test_workspace")
    os.makedirs(os.path.join(workspace_dir, "apps", "frontend"), exist_ok=True)
    os.makedirs(os.path.join(workspace_dir, "apps", "backend-api"), exist_ok=True)

    with open(os.path.join(workspace_dir, "apps", "frontend", "main.py"), "w") as f:
        f.write("# frontend\n")
    with open(os.path.join(workspace_dir, "apps", "backend-api", "main.py"), "w") as f:
        f.write("# backend\n")

    uploaded_tar_bytes = None
    submitted_payload = None

    mock_blob = MagicMock()
    def fake_upload_from_string(data, content_type=None):
        nonlocal uploaded_tar_bytes
        uploaded_tar_bytes = data
    mock_blob.upload_from_string.side_effect = fake_upload_from_string

    mock_bucket = MagicMock()
    mock_bucket.exists.return_value = True
    mock_bucket.blob.return_value = mock_blob
    mock_bucket.get_iam_policy.return_value = MagicMock(bindings=[])

    mock_storage_client = MagicMock()
    mock_storage_client.bucket.return_value = mock_bucket

    mock_session = MagicMock()
    def fake_post(url, json=None, timeout=None):
        nonlocal submitted_payload
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        if "cloudbuild.googleapis.com/v1/projects/target-proj/builds" in url:
            submitted_payload = json
            mock_resp.json.return_value = {"id": "b-12345"}
        elif "repositories" in url:
            mock_resp.json.return_value = {}
        elif "services" in url:
            mock_resp.json.return_value = {}
        elif "getIamPolicy" in url:
            mock_resp.json.return_value = {"bindings": []}
        elif "setIamPolicy" in url:
            mock_resp.json.return_value = {}
        return mock_resp

    def fake_get(url, timeout=None):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        if "builds/b-12345" in url:
            mock_resp.json.return_value = {"status": "SUCCESS"}
        elif "defaultServiceAccount" in url:
            # FD-4BA: the staging bucket grant goes to the resolved Cloud Build default service account.
            mock_resp.json.return_value = {
                "serviceAccountEmail": "projects/target-proj/serviceAccounts/123456789-compute@developer.gserviceaccount.com"
            }
        elif "repositories" in url:
            mock_resp.status_code = 404  # triggers create
        elif "projects/target-proj" in url:
            mock_resp.json.return_value = {"projectNumber": "123456789"}
        return mock_resp

    mock_session.post.side_effect = fake_post
    mock_session.get.side_effect = fake_get

    with patch("google.auth.default", return_value=(MagicMock(), "proj")), \
         patch("google.auth.transport.requests.AuthorizedSession", return_value=mock_session), \
         patch.object(sys.modules['google.cloud.storage'], 'Client', return_value=mock_storage_client):

        success = mock_tf_service._build_and_push_container(
            product_id="multi-app",
            target_project_id="target-proj",
            workspace_dir=workspace_dir,
            image_tag="us-central1-docker.pkg.dev/target-proj/castor-multi-app/app:latest"
        )
        assert success is True

    # 1. Verify container contract files exist on disk in every service directory
    assert os.path.exists(os.path.join(workspace_dir, "Procfile"))
    assert os.path.exists(os.path.join(workspace_dir, ".python-version"))
    assert os.path.exists(os.path.join(workspace_dir, "apps", "frontend", "Procfile"))
    assert os.path.exists(os.path.join(workspace_dir, "apps", "frontend", ".python-version"))
    assert os.path.exists(os.path.join(workspace_dir, "apps", "backend-api", "Procfile"))
    assert os.path.exists(os.path.join(workspace_dir, "apps", "backend-api", ".python-version"))

    # 2. Verify tarball was packed with these files included
    assert uploaded_tar_bytes is not None
    with tarfile.open(fileobj=io.BytesIO(uploaded_tar_bytes), mode="r:gz") as tar:
        names = tar.getnames()
        assert "Procfile" in names
        assert ".python-version" in names
        assert "apps/frontend/Procfile" in names
        assert "apps/frontend/.python-version" in names
        assert "apps/backend-api/Procfile" in names
        assert "apps/backend-api/.python-version" in names

    # 3. Verify Cloud Build payload executed all steps in parallel with waitFor: ['-']
    assert submitted_payload is not None
    steps = submitted_payload.get("steps", [])
    assert len(steps) == 2  # frontend and backend-api
    for step in steps:
        assert step["waitFor"] == ["-"]
        assert "gcr.io/k8s-skaffold/pack" in step["name"]


def test_deploy_foundation_only_skips_cloud_build(mock_tf_service):
    """Verifies that deploying a foundation-only workload skips _build_and_push_container and deploys directly."""
    files = {
        "main.tf": """
module "foundation" {
  source = "./modules/workload-foundation/base"
}
""",
        "variables.tf": """
variable "project_id" { type = string }
variable "region" { type = string default = "us-central1" }
variable "product_id" { type = string }
variable "github_repo_full_name" { type = string default = "" }
variable "container_image" { type = string default = "" }
variable "oauth_client_id" { type = string default = "" }
variable "oauth_client_secret" { type = string default = "" }
variable "firebase_api_key" { type = string default = "" }
variable "firebase_auth_domain" { type = string default = "" }
""",
        "outputs.tf": """
output "workload_sa_email" { value = "sa@example.com" }
""",
    }

    with patch("google.cloud.storage.Client"), \
         patch("google.cloud.secretmanager.SecretManagerServiceClient"), \
         patch.object(mock_tf_service, "_fetch_repo_files", return_value={}), \
         patch.object(mock_tf_service, "_build_and_push_container") as mock_build, \
         patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
         patch.object(mock_tf_service, "_run_subprocess") as mock_subproc:

        mock_subproc.return_value = {
            "success": True,
            "stdout": "Apply complete! Resources: 5 added, 0 changed, 0 destroyed.",
            "stderr": "",
        }

        result = mock_tf_service.deploy_workload(
            product_id="empty-project",
            trace_id="trace-foundation-only",
            hcl_files=files,
            target_project_id="target-proj-empty",
        )

        # 1. Verify container build was completely bypassed
        mock_build.assert_not_called()

        # 2. Verify deploy succeeded
        assert result["status"] == "SUCCESS"

        # 3. Verify no fictitious service URL was generated
        assert result.get("service_url") == ""


def test_trigger_tf_applier_job_sdk_success(monkeypatch):
    if not AsyncDeployRequest or not trigger_tf_applier_job:
        return
    monkeypatch.setenv("PROJECT_ID", "test-proj")
    monkeypatch.setenv("REGION", "us-central1")
    monkeypatch.setenv("TF_APPLIER_JOB_NAME", "tf-applier")
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "true")
    monkeypatch.setenv("VCS_PROVIDER", "SERVERLESS_GIT")
    monkeypatch.setenv("GIT_SERVER_URL", "https://castor-git-server-test.a.run.app")

    req = AsyncDeployRequest(product_id="testapp", trace_id="trace-999", callback_url="https://workflow.googleapis.com/cb-1")
    mock_run_v2 = MagicMock()
    mock_client = MagicMock()
    mock_run_v2.JobsClient.return_value = mock_client
    mock_op = MagicMock()
    mock_op.operation.name = "operations/job-run-123"
    mock_client.run_job.return_value = mock_op

    with patch.dict("sys.modules", {"google.cloud.run_v2": mock_run_v2}):
        res = trigger_tf_applier_job(req)
        assert res is True
        mock_client.run_job.assert_called_once()
        override_call = mock_run_v2.RunJobRequest.Overrides.ContainerOverride.call_args[1]
        env_vars = {e["name"]: e["value"] for e in override_call["env"]}
        assert env_vars.get("VCS_PROVIDER") == "SERVERLESS_GIT"
        assert env_vars.get("GIT_SERVER_URL") == "https://castor-git-server-test.a.run.app"


def test_trigger_tf_applier_job_rest_fallback(monkeypatch):
    if not AsyncDeployRequest or not trigger_tf_applier_job:
        return
    monkeypatch.setenv("PROJECT_ID", "test-proj")
    monkeypatch.setenv("REGION", "us-central1")
    monkeypatch.setenv("TF_APPLIER_JOB_NAME", "tf-applier")
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "true")
    monkeypatch.setenv("VCS_PROVIDER", "SERVERLESS_GIT")
    monkeypatch.setenv("GIT_SERVER_URL", "https://castor-git-server-test.a.run.app")

    req = AsyncDeployRequest(product_id="testapp", trace_id="trace-999", callback_url="https://workflow.googleapis.com/cb-1")

    mock_creds = MagicMock()
    mock_creds.token = "fake-token"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"name": "operations/rest-op-456"}

    with patch.dict("sys.modules", {"google.cloud.run_v2": None}), \
         patch("google.auth.default", return_value=(mock_creds, "test-proj")), \
         patch("google.auth.transport.requests.Request"), \
         patch("requests.post", return_value=mock_resp) as mock_post:
        res = trigger_tf_applier_job(req)
        assert res is True
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert "jobs/tf-applier:run" in call_url
        call_body = mock_post.call_args[1]["json"]
        env_vars = {e["name"]: e["value"] for e in call_body["overrides"]["containerOverrides"][0]["env"]}
        assert env_vars.get("VCS_PROVIDER") == "SERVERLESS_GIT"
        assert env_vars.get("GIT_SERVER_URL") == "https://castor-git-server-test.a.run.app"


def test_trigger_tf_applier_job_disabled(monkeypatch):
    if not AsyncDeployRequest or not trigger_tf_applier_job:
        return
    monkeypatch.setenv("PROJECT_ID", "test-proj")
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "false")

    req = AsyncDeployRequest(product_id="testapp", trace_id="trace-999", callback_url="https://workflow.googleapis.com/cb-1")
    assert trigger_tf_applier_job(req) is False


def test_apply_time_text_healers_are_deleted():
    """FD-55 W6a (register FD55-W6a): the apply-time HB-19 Cloud Run timeouts copy (A22), the module.compute
    collision re-pointing (A12), the HB-17 naming copy (A10 / A41) and the workflow sanitizer (A7) are gone."""
    import service as svc_mod
    for name in ("inject_cloud_run_timeouts", "sanitize_gcp_naming_invariants", "sanitize_secret_manager_references",
                 "sanitize_github_workflow", "_deduplicate_env_block",
                 # FD-55 W6c (register FD55-W6c): the tfvars guesses (A42) and the validate- / apply-error text heals
                 "generate_rfc1123_variable_default", "parse_variables_tf_schema", "_ACCESS_KEY_DEFAULTS",
                 "strip_invalid_hcl_blocks", "strip_hcl_output", "sanitize_self_referential_hcl_blocks"):
        assert not hasattr(svc_mod, name), name
    assert not hasattr(TerraformService, "_reconcile_modular_compute_collisions")
    assert not hasattr(TerraformService, "_cloud_run_deletion_protection_off")


def test_deploy_workload_shift_left_no_longer_heals_undeclared_cloud_run(mock_tf_service):
    """FD-55 W6c (A45 DELETED): an undeclared `google_cloud_run_v2_service.<x>` reference on a legacy workspace is no
    longer rewritten to `module.compute`; validate runs once and the engine's error returns as VALIDATION_FAILED (the
    workflow's bounded regeneration). custom.tf is the committed text."""
    custom_tf_content = 'resource "google_cloud_scheduler_job" "cron" { name = "cron" depends_on = [ google_cloud_run_v2_service.service_a ] }'
    hcl_files = {
        "main.tf": 'module "compute" { source = "../modules/compute-cloudrun" service_name = "test-service" }',
        "custom.tf": custom_tf_content,
    }
    with patch("google.cloud.storage.Client"), \
         patch("google.cloud.secretmanager.SecretManagerServiceClient"), \
         patch.object(mock_tf_service, "_fetch_repo_files", return_value={}), \
         patch.object(mock_tf_service, "_build_and_push_container", return_value=True), \
         patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
         patch.object(mock_tf_service, "_run_subprocess") as mock_sub:
        mock_sub.side_effect = [
            {"success": True, "stdout": "", "stderr": "", "exit_code": 0},  # init
            # validate fails with undeclared google_cloud_run_v2_service.service_a: no heal, no re-validate
            {"success": False, "stdout": "", "stderr": 'Error: Reference to undeclared resource on custom.tf line 1: google_cloud_run_v2_service.service_a', "exit_code": 1},
            # DEPLOY-FAILURE-OWNER-ROUTER: `validate -json` (read-only) names the file
            {"success": False, "exit_code": 1, "stderr": "", "stdout": json.dumps({"diagnostics": [
                {"severity": "error", "summary": "Reference to undeclared resource",
                 "range": {"filename": "custom.tf", "start": {"line": 1, "column": 1, "byte": 0}}}]})},
        ]

        result = mock_tf_service.deploy_workload("test-service", "trace-shift-left", hcl_files)
        assert result["status"] == "VALIDATION_FAILED"
        assert "google_cloud_run_v2_service.service_a" in result["error"]
        assert [c.args[0][1] for c in mock_sub.call_args_list] == ["init", "validate", "validate"]
        assert mock_sub.call_args_list[-1].args[0] == ["terraform", "validate", "-json", "-no-color"]
        # this tree is a repository-ROOT config (no infra/workload/, which every generated workload uses: AGENTS.md
        # invariant 4), so nothing says the AI wrote custom.tf: UNKNOWN, operator stop (the text is kept after the class)
        assert (result["failure_route"]["owner"], result["failure_route"]["findings"][0]["reason"]) == (
            "UNKNOWN", "UNATTRIBUTED")
        assert result["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED" and result["operator_required"] is True
        workspace_dir = os.path.join(mock_tf_service.workspace_base_dir, "trace-shift-left", "test-service")
        with open(os.path.join(workspace_dir, "custom.tf"), "r") as f:
            assert f.read() == custom_tf_content


def test_extract_apis_detects_gke_from_golden_module():
    tf_files = {
        "infra/foundation/main.tf": """
            module "compute" {
              source = "../modules/compute-gke-autopilot"
              cluster_name = "autopilot-cluster"
            }
        """
    }
    apis = extract_apis_from_hcl(tf_files)
    assert "container.googleapis.com" in apis
    assert "compute.googleapis.com" in apis
    assert "run.googleapis.com" not in apis


def test_extract_apis_detects_gke_from_k8s_manifests():
    tf_files = {"main.tf": 'resource "google_storage_bucket" "b" { name = "my-bucket" }'}
    yaml_files = {
        "k8s/deployment.yaml": """
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: stream-worker
        """
    }
    apis = extract_apis_from_hcl(tf_files, yaml_files)
    assert "container.googleapis.com" in apis
    assert "compute.googleapis.com" in apis
    assert "storage.googleapis.com" in apis


def test_extract_apis_pure_cloud_run_no_gke():
    tf_files = {
        "main.tf": """
            module "compute" {
              source = "../modules/compute-cloudrun"
              service_name = "api-service"
            }
        """
    }
    apis = extract_apis_from_hcl(tf_files)
    assert "run.googleapis.com" in apis
    assert "container.googleapis.com" not in apis


def test_extract_apis_has_no_run_firestore_default():
    # S2-C C1b (register HS-63): the "default to Cloud Run + Firestore" rule is deleted (both are foundation base_apis)
    apis = extract_apis_from_hcl({}, {})
    assert apis == ["cloudresourcemanager.googleapis.com", "iam.googleapis.com", "serviceusage.googleapis.com"]


def test_extract_apis_detects_service_networking():
    # 1. From resource
    tf_files = {"custom.tf": 'resource "google_service_networking_connection" "psa" { network = "vpc" }'}
    apis = extract_apis_from_hcl(tf_files)
    assert "servicenetworking.googleapis.com" in apis

    # 2. From database-cloudsql module
    tf_files_mod = {"main.tf": 'module "db" { source = "../modules/database-cloudsql" }'}
    apis_mod = extract_apis_from_hcl(tf_files_mod)
    assert "servicenetworking.googleapis.com" in apis_mod
    assert "sqladmin.googleapis.com" in apis_mod


def test_sanitize_wheel_requirements_relaxes_numpy():
    raw_reqs = "fastapi==0.115.0\nnumpy==1.26.4\nuvicorn>=0.30.0\n"
    sanitized = sanitize_wheel_requirements(raw_reqs)
    assert "numpy>=1.26.0" in sanitized
    assert "fastapi==0.115.0" in sanitized
    assert "uvicorn>=0.30.0" in sanitized
    assert "auto-harmonized by Castor BOM" in sanitized


def test_sanitize_wheel_requirements_relaxes_scipy_pandas():
    raw_reqs = "scipy==1.11.2\npandas==1.5.3\n"
    sanitized = sanitize_wheel_requirements(raw_reqs)
    assert "scipy>=1.14.0" in sanitized
    assert "pandas>=2.2.0" in sanitized


def test_sanitize_wheel_requirements_relaxes_asyncpg():
    raw_reqs = "sqlalchemy>=2.0.28\nasyncpg>=0.29.0,<1.0.0\n"
    sanitized = sanitize_wheel_requirements(raw_reqs)
    assert "asyncpg>=0.30.0,<1.0.0" in sanitized
    assert "auto-harmonized by Castor BOM" in sanitized


def test_sanitize_wheel_requirements_preserves_unrelated_packages():
    raw_reqs = "requests==2.31.0\npydantic>=2.0.0\n# custom comment\n"
    sanitized = sanitize_wheel_requirements(raw_reqs)
    assert sanitized == raw_reqs


def test_disambiguate_services_skips_redundant_hyphen_alias():
    services = ["stream-worker", "testplan04-b", "testplan04_b"]
    manifest_content = "image: us-central1-docker.pkg.dev/proj/castor-containers/stream-worker:latest\nimage: us-central1-docker.pkg.dev/proj/castor-containers/testplan04_b:latest"
    
    pruned_services = []
    for svc in services:
        under_svc = svc.replace("-", "_")
        hyphen_svc = svc.replace("_", "-")
        if under_svc != hyphen_svc and under_svc in services and hyphen_svc in services:
            if hyphen_svc in manifest_content and under_svc not in manifest_content:
                if svc == hyphen_svc:
                    pruned_services.append(svc)
            else:
                if svc == under_svc:
                    pruned_services.append(svc)
        else:
            pruned_services.append(svc)

    assert "testplan04_b" in pruned_services
    assert "testplan04-b" not in pruned_services
    assert "stream-worker" in pruned_services


def test_sanitize_wheel_requirements_applies_central_bom_overrides():
    raw_reqs = "requests==2.28.0\nfastapi>=0.100.0\ninternal-client==1.0.0\n"
    bom = {
        "requests": ">=2.31.0",
        "internal-client": "==1.4.2",
    }
    sanitized = sanitize_wheel_requirements(raw_reqs, package_versions=bom)
    assert "requests>=2.31.0" in sanitized
    assert "internal-client==1.4.2" in sanitized
    assert "fastapi>=0.100.0" in sanitized
    assert "enforced by Platform BOM" in sanitized


def test_sanitize_wheel_requirements_injects_greenlet_for_async_sql():
    raw_reqs = "fastapi>=0.110.0\nsqlalchemy>=2.0.0\nasyncpg==0.29.0\n"
    sanitized = sanitize_wheel_requirements(raw_reqs)
    assert "greenlet>=3.1.1,<4.0.0" in sanitized
    assert "asyncpg>=0.30.0,<1.0.0" in sanitized  # relaxed by BOM for Python 3.13
    assert "starlette>=0.37.2,<1.0.0" in sanitized



def test_is_cloud_capacity_stockout():
    # Valid capacity errors
    assert is_cloud_capacity_stockout("Error: GCE_STOCKOUT: Google Compute Engine does not have enough resources available to fulfill request: us-central1")
    assert is_cloud_capacity_stockout("Error code: ZONE_RESOURCE_POOL_EXHAUSTED in zone us-central1-f")
    assert is_cloud_capacity_stockout("The zone us-central1-a does not have enough resources available")
    assert is_cloud_capacity_stockout("Try a different location, or try again later.")
    assert is_cloud_capacity_stockout("googleapi: Error 429: RESOURCE_EXHAUSTED")
    assert is_cloud_capacity_stockout("The service is currently overloaded, please retry later")
    assert is_cloud_capacity_stockout("Requested machine type temporarily unavailable in this zone")

    # Non-capacity errors
    assert not is_cloud_capacity_stockout("googleapi: Error 403: Permission denied on resource")
    assert not is_cloud_capacity_stockout("Syntax error: missing closing quote")
    assert not is_cloud_capacity_stockout("")
    assert not is_cloud_capacity_stockout(None)


def test_detect_errored_child_stubs_is_read_only():
    """RT14-01 (FD-4Q / lane 18 S3): the old purge REST-deleted every ERROR cluster in any region and ran a hardcoded
    `state rm`. Detection only GETs: errored stubs are listed (other regions marked, visibility only), nothing is
    deleted and no state command runs; the host project is refused."""
    service = TerraformService(project_id="test-platform-project", db=MagicMock())
    assert service.detect_errored_child_stubs("")["errors"]
    assert service.detect_errored_child_stubs("test-platform-project")["errors"]

    sess = MagicMock()
    vpc = MagicMock(status_code=200)
    vpc.json.return_value = {"connectors": [
        {"name": "projects/testplan04-b/locations/us-central1/connectors/conn-ready", "state": "READY"},
        {"name": "projects/testplan04-b/locations/us-central1/connectors/conn-dead", "state": "ERROR"}]}
    gke = MagicMock(status_code=200)
    gke.json.return_value = {"clusters": [
        {"name": "gke-active", "location": "us-central1", "status": "RUNNING"},
        {"name": "gke-corrupted", "location": "us-central1", "status": "ERROR"},
        {"name": "app-secondary", "location": "europe-west1", "status": "ERROR"}]}
    sess.get.side_effect = lambda url, **kwargs: vpc if "vpcaccess" in url else gke
    with patch("google.auth.default", return_value=(MagicMock(), "test-platform-project")), \
         patch("google.auth.transport.requests.AuthorizedSession", return_value=sess), \
         patch.object(service, "_run_subprocess") as run:
        found = service.detect_errored_child_stubs("testplan04-b", region="us-central1")
    assert sess.delete.call_count == 0 and run.call_count == 0
    assert [c["name"].rsplit("/", 1)[-1] for c in found["connectors"]] == ["conn-dead"]
    assert {(c["name"], c["in_workload_region"]) for c in found["clusters"]} == {
        ("gke-corrupted", True), ("app-secondary", False)}
    assert found["errors"] == []

    # an unreadable listing is typed, never "no stubs"
    bad = MagicMock()
    bad.get.return_value = MagicMock(status_code=403)
    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession", return_value=bad):
        found = service.detect_errored_child_stubs("testplan04-b", region="us-central1")
    assert len(found["errors"]) == 2 and all("STUB_DETECTION_UNREADABLE" in e for e in found["errors"])


def test_render_main_tf_gke_autopilot_wires_kubernetes_provider():
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "apps", "orchestrator-gateway", "developer_agent")))
    from terraform_engine import generate_golden_main_tf
    main_tf = generate_golden_main_tf(product_id="testplan04-c", archetype="gke-autopilot")
    assert 'provider "kubernetes"' in main_tf
    assert 'data "google_client_config" "default"' in main_tf
    assert 'module.compute.cluster_endpoint' in main_tf
    assert 'module.compute.cluster_ca_certificate' in main_tf
    assert 'source  = "hashicorp/kubernetes"' in main_tf


_W6E_GKE_MAIN = """
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}

module "compute" {
  source = "../modules/compute-gke-autopilot"
}
"""
_W6E_GKE_OUTPUTS = """
output "cluster_name" {
  value = google_container_cluster.autopilot.name
}
output "cluster_endpoint" {
  value = google_container_cluster.autopilot.endpoint
}
"""
# Every input one of the deleted Guardrail 4 steps rewrote: a subnetwork without ignore_changes, a
# kubernetes_deployment without timeouts, an annotated KSA without a Workload Identity binding (+ Firestore), a
# `repository_id` default other than the product id.
_W6E_GKE_CUSTOM = """
resource "google_compute_subnetwork" "gke" {
  name          = "gke-subnet"
  ip_cidr_range = "10.10.0.0/20"
  region        = var.region
  network       = "default"
}

resource "kubernetes_deployment" "web" {
  metadata {
    name = "web"
  }
  spec {
    template {
      metadata {
        labels = { app = "web" }
      }
      spec {
        service_account_name = kubernetes_service_account.app.metadata[0].name
        container {
          name  = "web"
          image = var.container_image
        }
      }
    }
  }
}

resource "kubernetes_service_account" "app" {
  metadata {
    name      = "app-ksa"
    namespace = "default"
    annotations = {
      "iam.gke.io/gcp-service-account" = google_service_account.app.email
    }
  }
}

resource "google_service_account" "app" {
  account_id = "app-gsa"
}

resource "google_firestore_database" "db" {
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
}

variable "repository_id" {
  type    = string
  default = "legacy-docker-repo"
}
"""


def test_deploy_workload_applies_a_gke_workload_as_committed(mock_tf_service):
    """FD55-W6e (A35 DELETED, Do No Harm negative): a GKE workload whose files every deleted Guardrail 4 step used to
    rewrite (kubernetes provider wiring, the GKE module's cluster_ca_certificate output, subnetwork ignore_changes,
    kubernetes_deployment timeouts, Workload Identity bindings + datastore role, the repository_id default) reaches the
    workspace exactly as committed (main.tf: only the FD-4BW module-source re-anchoring)."""
    repo_files = {
        "infra/workload/main.tf": _W6E_GKE_MAIN,
        "infra/modules/compute-gke-autopilot/outputs.tf": _W6E_GKE_OUTPUTS,
        "infra/workload/custom.tf": _W6E_GKE_CUSTOM,
    }

    with patch("google.cloud.storage.Client"), \
         patch("google.cloud.secretmanager.SecretManagerServiceClient"), \
         patch.object(mock_tf_service, "_fetch_repo_files", return_value=repo_files), \
         patch.object(mock_tf_service, "_build_and_push_container", return_value=True), \
         patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
         patch.object(mock_tf_service, "_run_subprocess") as mock_sub:

        mock_sub.side_effect = [
            {"success": True, "stdout": "", "stderr": "", "exit_code": 0},  # init
            {"success": True, "stdout": "", "stderr": "", "exit_code": 0},  # validate
            {"success": True, "stdout": "", "stderr": "", "exit_code": 0},  # state list
            {"success": True, "stdout": "Apply complete!", "stderr": "", "exit_code": 0},  # apply
            {"success": True, "stdout": json.dumps({"service_url": {"value": "https://gke.app"}}), "stderr": "", "exit_code": 0},  # output
        ]

        res = mock_tf_service.deploy_workload("testplan04-c", "trace-k8s")
        assert res["status"] == "SUCCESS"
        workspace_dir = mock_sub.call_args_list[0][1]["cwd"]
        assert workspace_dir and os.path.isdir(workspace_dir)

        with open(os.path.join(workspace_dir, "main.tf"), "r") as f:
            assert f.read() == _W6E_GKE_MAIN.replace("../modules/compute-gke-autopilot",
                                                     "./infra/modules/compute-gke-autopilot")
        with open(os.path.join(workspace_dir, "custom.tf"), "r") as f:
            assert f.read() == _W6E_GKE_CUSTOM
        with open(os.path.join(workspace_dir, "infra", "modules", "compute-gke-autopilot", "outputs.tf"), "r") as f:
            assert f.read() == _W6E_GKE_OUTPUTS


def test_w6e_deleted_gke_text_healers_are_gone():
    import service
    for name in ("inject_subnet_lifecycle_ignore_changes", "inject_kubernetes_deployment_timeouts",
                 "inject_gke_workload_identity_bindings"):
        assert not hasattr(service, name), name


def _hermetic_rc(directory):
    """A local CLI config so _run_subprocess never downloads the provider mirror (no network in tests)."""
    rc = os.path.join(directory, "terraform.rc")
    with open(rc, "w", encoding="utf-8") as fh:
        fh.write("# hermetic test CLI config\n")
    return rc


def test_run_subprocess_stubs_kubernetes_provider_during_foundational_import(mock_tf_service):
    """Verifies _run_subprocess temporarily stages _castor_k8s_override.tf during non-k8s imports and cleans it up."""
    with tempfile.TemporaryDirectory() as temp_dir:
        main_tf = os.path.join(temp_dir, "main.tf")
        with open(main_tf, "w", encoding="utf-8") as f:
            f.write(
                'provider "kubernetes" {\n'
                '  host = "https://${module.compute.cluster_endpoint}"\n'
                '  token = "abc"\n'
                '}\n'
            )

        override_path = os.path.join(temp_dir, "_castor_k8s_override.tf")
        override_existed_during_call = []

        def fake_run(cmd, cwd, **kwargs):
            override_existed_during_call.append(os.path.exists(override_path))
            if os.path.exists(override_path):
                with open(override_path, "r", encoding="utf-8") as f_ov:
                    override_existed_during_call.append(f_ov.read())
            class FakeResult:
                returncode = 0
                stdout = "Imported"
                stderr = ""
            return FakeResult()

        with patch("subprocess.Popen", side_effect=popen_from_run(fake_run)), \
             patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
             patch.object(mock_tf_service, "_ensure_provider_mirror", return_value=_hermetic_rc(temp_dir)):
            res = mock_tf_service._run_subprocess(
                ["terraform", "import", "module.foundation.google_artifact_registry_repository.docker_repo", "projects/p/locations/l/repositories/r"],
                cwd=temp_dir,
            )
            assert res["success"] is True
            assert override_existed_during_call[0] is True
            assert 'provider "kubernetes"' in override_existed_during_call[1]
            assert 'host                   = "https://127.0.0.1"' in override_existed_during_call[1]
            assert 'cluster_ca_certificate = base64decode(' in override_existed_during_call[1]
            assert not os.path.exists(override_path)


def test_run_subprocess_does_not_stub_k8s_for_kubernetes_import(mock_tf_service):
    """Verifies _run_subprocess does not stage override if the target resource is a kubernetes resource."""
    with tempfile.TemporaryDirectory() as temp_dir:
        main_tf = os.path.join(temp_dir, "main.tf")
        with open(main_tf, "w", encoding="utf-8") as f:
            f.write(
                'provider "kubernetes" {\n'
                '  host = "https://${module.compute.cluster_endpoint}"\n'
                '}\n'
            )
        override_path = os.path.join(temp_dir, "_castor_k8s_override.tf")
        override_existed = []

        def fake_run(cmd, cwd, **kwargs):
            override_existed.append(os.path.exists(override_path))
            class FakeResult:
                returncode = 0
                stdout = ""
                stderr = ""
            return FakeResult()

        with patch("subprocess.Popen", side_effect=popen_from_run(fake_run)), \
             patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
             patch.object(mock_tf_service, "_ensure_provider_mirror", return_value=_hermetic_rc(temp_dir)):
            res = mock_tf_service._run_subprocess(
                ["terraform", "import", "kubernetes_deployment.worker", "default/worker"],
                cwd=temp_dir,
            )
            assert res["success"] is True
            assert override_existed[0] is False
            assert not os.path.exists(override_path)


def test_prepare_workspace_keeps_a_module_compute_service_name_collision_as_committed(tf_svc):
    """FD-55 W6a (A12 DELETED): a module.compute that shares its service_name with a secondary module is no longer
    re-pointed at another app by output-name / app-dir guessing; main.tf and custom.tf are written byte-identical
    (the collision is the AI's to fix through validate / plan / apply feedback)."""
    main_tf_content = """module "compute" {
  source                = "./infra/modules/compute-cloudrun"
  service_name          = "warehouse-service"
  container_image       = replace(var.container_image, "/app:", "/warehouse-service:")
  allow_unauthenticated = var.allow_unauthenticated
}
"""
    custom_tf_content = """module "compute_warehouse_service" {
  source          = "./infra/modules/compute-cloudrun"
  service_name    = "warehouse-service"
  container_image = replace(var.container_image, "/app:", "/warehouse-service:")
}

output "storefront_service_name" {
  description = "The name of the deployed Storefront Cloud Run service"
  value       = module.compute.service_name
}
"""
    files = {"main.tf": main_tf_content, "custom.tf": custom_tf_content, "apps/storefront/main.py": "# entry\n"}
    ws = tf_svc.prepare_workspace("testplan06-a", "trace-w6a-collision", files)
    with open(os.path.join(ws, "main.tf"), "r") as f:
        assert f.read() == main_tf_content
    with open(os.path.join(ws, "custom.tf"), "r") as f:
        assert f.read() == custom_tf_content


def test_rollout_sets_exactly_the_given_image_even_when_the_current_one_names_the_service(tf_svc):
    """FD55-3D RT F2: the "Declarative Image Preservation" substring rule is deleted. The current image names the
    service (`/storefront:`) and the given (applied) image does not: the given image is set, not the current kept."""
    from unittest.mock import MagicMock, patch

    mock_resp_get = MagicMock()
    mock_resp_get.status_code = 200
    mock_resp_get.json.return_value = {
        "latestReadyRevision": "storefront-00001-xyz",
        "template": {
            "containers": [{"image": "us-central1-docker.pkg.dev/testplan06-a/testplan06-a/storefront:latest"}],
            "labels": {},
        },
    }

    mock_resp_patch = MagicMock()
    mock_resp_patch.status_code = 200

    mock_sess = MagicMock()
    mock_sess.get.side_effect = [
        mock_resp_get,
        MagicMock(
            status_code=200,
            json=lambda: {
                "latestReadyRevision": "storefront-00002-abc",
                "uri": "https://storefront-abc-uc.a.run.app",
                "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            },
        ),
    ]
    mock_sess.patch.return_value = mock_resp_patch

    with patch("google.auth.default", return_value=(MagicMock(), "test-proj")), \
         patch("google.auth.transport.requests.AuthorizedSession", return_value=mock_sess):
        ok, rev, uri = tf_svc._rollout_cloud_run_revision(
            target_project_id="testplan06-a",
            service_name="storefront",
            image_tag="us-central1-docker.pkg.dev/testplan06-a/testplan06-a/app:latest",
            poll_interval=0.1,
            max_wait_seconds=2,
        )
        assert ok is True
        assert rev == "storefront-00002-abc"
        # the applied image is sent as given (no name-based preservation of the current one)
        patch_call = mock_sess.patch.call_args
        assert patch_call is not None
        sent_tmpl = patch_call[1]["json"]["template"]
        assert sent_tmpl["containers"][0]["image"] == "us-central1-docker.pkg.dev/testplan06-a/testplan06-a/app:latest"
        assert "client.knative.dev/nonce" in sent_tmpl["labels"]


def test_buildpack_scaffold_stub_quarantine():
    """Rule 3: Verify that when both authentic UI microservices and generic scaffold stubs exist, UI is chosen as primary_svc."""
    active_pool = ["storefront", "testplan06-a", "warehouse", "warehouse-service"]
    clean_pid = "testplan06-a"

    ui_candidates = [
        s for s in active_pool
        if any(k in s.lower() for k in ("storefront", "frontend", "ui", "web", "gateway", "portal"))
    ]
    if ui_candidates:
        primary_svc = ui_candidates[0]
    elif clean_pid in active_pool and len(active_pool) > 1:
        other_candidates = [s for s in active_pool if s != clean_pid]
        primary_svc = other_candidates[0] if other_candidates else clean_pid
    elif clean_pid in active_pool:
        primary_svc = clean_pid
    else:
        primary_svc = active_pool[0]

    assert primary_svc == "storefront"


def test_sanitize_wheel_requirements_starlette_bom():
    # 1. When FastAPI is present without explicit starlette, starlette constraint is injected
    reqs_with_fastapi = "fastapi>=0.110.0\nuvicorn>=0.28.0\npydantic>=2.6.0\n"
    res1 = sanitize_wheel_requirements(reqs_with_fastapi)
    assert "starlette>=0.37.2,<1.0.0" in res1
    assert "fastapi>=0.110.0" in res1

    # 2. When Jinja2 is present without explicit starlette, starlette constraint is injected
    reqs_with_jinja = "jinja2>=3.1.5\nuvicorn>=0.28.0\n"
    res2 = sanitize_wheel_requirements(reqs_with_jinja)
    assert "starlette>=0.37.2,<1.0.0" in res2

    # 3. When starlette is already declared, it is harmonized against BOM
    reqs_with_unpinned_starlette = "fastapi>=0.110.0\nstarlette>=1.0.0\n"
    res3 = sanitize_wheel_requirements(reqs_with_unpinned_starlette)
    assert "starlette>=0.37.2,<1.0.0" in res3
    assert "starlette>=1.0.0" not in res3

    # 4. When neither FastAPI nor Jinja2 is declared, starlette is not injected
    reqs_other = "click>=8.0.0\nrequests>=2.31.0\n"
    res4 = sanitize_wheel_requirements(reqs_other)
    assert "starlette" not in res4


def test_sanitize_wheel_requirements_email_validator_bom():
    raw_reqs = "fastapi==0.115.0\nemail-validator>=1.0.0\n"
    sanitized = sanitize_wheel_requirements(raw_reqs)
    assert "email-validator>=2.0.0,<3.0.0" in sanitized


def test_prepare_workspace_adds_no_database_url_for_cloud_sql(tf_svc):
    """platform-db-connector-wiring (proposed row PDCW-2) deleted HA-13 phase 6 (a credential-less DATABASE_URL + DB_*
    keys built from the first Cloud SQL objects); FD-55 W6b deleted the function it lived in. The database binding is
    the typed consumer edges (address + credentials secret id): the root files reach the workspace byte-identical."""
    main_tf = '''
module "compute" {
  source = "../modules/compute-cloudrun"
  service_name = "billing-api"
  env_vars = merge(var.env_vars, {
    "PROJECT_ID" = var.project_id
  })
}
'''
    custom_tf = '''
resource "google_compute_network" "vpc" {
  name = "custom-vpc"
}
resource "google_service_networking_connection" "psa" {
  network = google_compute_network.vpc.id
}
resource "google_sql_database_instance" "postgres" {
  name             = "billing-postgres-instance"
  database_version = "POSTGRES_15"
  settings {
    ip_configuration {
      private_network = google_compute_network.vpc.id
    }
  }
}
resource "google_sql_database" "billing_db" {
  name     = "billing_db"
  instance = google_sql_database_instance.postgres.name
}
resource "google_sql_user" "db_user" {
  name     = "db_user"
  instance = google_sql_database_instance.postgres.name
}
'''
    files = {"infra/workload/main.tf": main_tf, "infra/workload/custom.tf": custom_tf}
    with tempfile.TemporaryDirectory() as td:
        tf_svc.workspace_base_dir = td
        ws = tf_svc.prepare_workspace("pdcw-sql", "trace-pdcw-sql", dict(files))
        for rel, text in files.items():
            with open(os.path.join(ws, rel), encoding="utf-8", newline="") as fh:
                assert fh.read() == text, rel
        assert "DATABASE_URL" not in files["infra/workload/main.tf"]


def test_prepare_workspace_keeps_an_explicit_database_url(tf_svc):
    main_tf = '''
module "compute" {
  source = "../modules/compute-cloudrun"
  service_name = "billing-api"
  env_vars = merge(var.env_vars, {
    "DATABASE_URL" = "custom-connection-string"
  })
}
'''
    custom_tf = '''
resource "google_sql_database_instance" "postgres" {
  name = "db"
}
'''
    files = {"infra/workload/main.tf": main_tf, "infra/workload/custom.tf": custom_tf}
    with tempfile.TemporaryDirectory() as td:
        tf_svc.workspace_base_dir = td
        ws = tf_svc.prepare_workspace("pdcw-url", "trace-pdcw-url", dict(files))
        with open(os.path.join(ws, "infra/workload/main.tf"), encoding="utf-8", newline="") as fh:
            assert fh.read() == main_tf


def test_rollout_injects_container_deploy_nonce(tf_svc):
    """Verify that _rollout_cloud_run_revision injects CASTOR_DEPLOY_NONCE into containers[0].env and preserves existing env vars."""
    mock_resp_get = MagicMock()
    mock_resp_get.status_code = 200
    mock_resp_get.json.return_value = {
        "latestReadyRevision": "storefront-00003-v9d",
        "template": {
            "containers": [{
                "image": "us-central1-docker.pkg.dev/testplan06-a/testplan06-a/storefront:latest",
                "env": [
                    {"name": "PROJECT_ID", "value": "testplan06-a"},
                    {"name": "ENVIRONMENT", "value": "prod"}
                ]
            }],
            "labels": {},
        },
    }

    mock_resp_patch = MagicMock()
    mock_resp_patch.status_code = 200

    mock_sess = MagicMock()
    mock_sess.get.side_effect = [
        mock_resp_get,
        MagicMock(
            status_code=200,
            json=lambda: {
                "latestReadyRevision": "storefront-00004-new",
                "uri": "https://storefront-abc-uc.a.run.app",
                "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
            },
        ),
    ]
    mock_sess.patch.return_value = mock_resp_patch

    with patch("google.auth.default", return_value=(MagicMock(), "test-proj")), \
         patch("google.auth.transport.requests.AuthorizedSession", return_value=mock_sess):
        ok, rev, uri = tf_svc._rollout_cloud_run_revision(
            target_project_id="testplan06-a",
            service_name="storefront",
            image_tag="us-central1-docker.pkg.dev/testplan06-a/testplan06-a/storefront:latest",
            poll_interval=0.1,
            max_wait_seconds=2,
        )
        assert ok is True
        assert rev == "storefront-00004-new"
        patch_call = mock_sess.patch.call_args
        assert patch_call is not None
        sent_tmpl = patch_call[1]["json"]["template"]
        env_dict = {e["name"]: e["value"] for e in sent_tmpl["containers"][0]["env"]}
        assert env_dict["PROJECT_ID"] == "testplan06-a"
        assert env_dict["ENVIRONMENT"] == "prod"
        assert "CASTOR_DEPLOY_NONCE" in env_dict


def test_builtin_modules_payload_compute_cloudrun_parity():
    """Assert BUILTIN_MODULE_FILES['compute-cloudrun'] declares vpc_access_connector and dynamic vpc_access."""
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    assert "compute-cloudrun" in BUILTIN_MODULE_FILES
    cc = BUILTIN_MODULE_FILES["compute-cloudrun"]
    assert "variables.tf" in cc
    assert "main.tf" in cc
    assert 'variable "vpc_access_connector"' in cc["variables.tf"]
    assert 'variable "vpc_egress"' in cc["variables.tf"]
    assert 'dynamic "vpc_access"' in cc["main.tf"]


def test_prepare_workspace_reports_a_stale_golden_module_and_applies_it_as_committed(tf_svc, caplog):
    """FD-55 W6d (register FD55-W6b+W6d, HS-42; was "overlays canonical Golden Module definitions"): an out-of-date
    vendored golden module is applied exactly as committed and reported (PLATFORM.VENDORED_MODULE_STALE), never
    overwritten with the payload and never queued for a commit back to the repository (A30 + A31 deleted)."""
    import logging
    caplog.set_level(logging.WARNING)
    with tempfile.TemporaryDirectory() as td:
        tf_svc.workspace_base_dir = td
        hcl_files = {
            "main.tf": 'module "compute" { source = "./infra/modules/compute-cloudrun" }',
            "infra/modules/compute-cloudrun/variables.tf": 'variable "old_var" { default = "legacy" }',
            "infra/modules/compute-cloudrun/main.tf": 'resource "google_cloud_run_v2_service" "app" {}',
        }
        ws_dir = tf_svc.prepare_workspace("test-product", "test-trace", hcl_files)
        for rel in ("infra/modules/compute-cloudrun/variables.tf", "infra/modules/compute-cloudrun/main.tf"):
            with open(os.path.join(ws_dir, rel), "r", encoding="utf-8", newline="") as f:
                assert f.read() == hcl_files[rel], rel
        assert not os.path.exists(os.path.join(ws_dir, "infra/modules/compute-cloudrun/outputs.tf"))  # nothing added
        assert not hasattr(tf_svc, "_last_healed_files")          # no write-back record exists any more
        stale = [r.getMessage() for r in caplog.records if "PLATFORM.VENDORED_MODULE_STALE" in r.getMessage()]
        assert len(stale) == 3, stale     # main.tf + variables.tf differ, outputs.tf is missing
        assert all("Upgrade IaC" in m for m in stale)



# ---------------------------------------------------------------------------
# FD-4B (D-1): Cloud Run 409 must not double-import nor prune HCL on "already managed"
# ---------------------------------------------------------------------------
_FD4B_ALREADY_MANAGED = (
    "Error: Resource already managed by Terraform\n\nTerraform is already managing a remote object for "
    "{addr}. To import to this address you must first remove the existing object from the state.\n"
)


def _fd4b_tf_snapshot(root):
    snap = {}
    for d, _, fns in os.walk(root):
        for fn in fns:
            if fn.endswith(".tf"):
                p = os.path.join(d, fn)
                with open(p, "r", encoding="utf-8") as fh:
                    snap[os.path.relpath(p, root)] = fh.read()
    return snap


def _w7_create(address, rtype, **after):
    """FD-4CY W7: one planned create as `tofu show -json` writes it (resource_changes[])."""
    return {"address": address, "mode": "managed", "type": rtype,
            "change": {"actions": ["create"], "after": dict(after), "after_unknown": {}}}


def _fd4b_run_409(tf_svc, ws, apply_err, already_managed_addr=None, plan_creates=()):
    """Drive deploy_workload's reconcile loop with a faked tofu. The first import of an address
    succeeds; a repeat import (or any import of `already_managed_addr`) returns tofu's real
    'Resource already managed' error. FD-4CY W7: `plan_creates` is the applied plan's resource_changes."""
    imports = []
    tf_svc._w7_plan_json = _w7_plan(plan_creates)

    def fake(self, cmd, *a, **k):
        if cmd[1] == "apply":
            if not imports:
                return {"success": False, "exit_code": 1, "stdout": "", "stderr": apply_err}
            return {"success": True, "exit_code": 0, "stdout": "Apply complete!", "stderr": ""}
        if cmd[1] == "import":
            addr = cmd[3]
            repeat = addr in imports
            imports.append(addr)
            if repeat or addr == already_managed_addr:
                return {"success": False, "exit_code": 1, "stdout": "", "stderr": _FD4B_ALREADY_MANAGED.format(addr=addr)}
            return {"success": True, "exit_code": 0, "stdout": "Import successful", "stderr": ""}
        if cmd[1] == "output":
            return {"success": True, "exit_code": 0, "stdout": '{"service_url": {"value": "https://t.run.app"}}', "stderr": ""}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    with open(os.path.join(ws, "main.tf"), "r", encoding="utf-8") as fh:
        main_tf = fh.read()
    with patch("shutil.which", return_value="/usr/local/bin/tofu"), \
         patch.object(TerraformService, "prepare_workspace", return_value=ws), \
         patch.object(TerraformService, "_build_and_push_container", return_value="img"), \
         patch.object(TerraformService, "_ensure_provider_mirror"), \
         patch.object(TerraformService, "_run_subprocess", fake), \
         patch.object(TerraformService, "_fetch_repo_files", return_value={}), \
         patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("httpx.Client"):
        res = tf_svc.deploy_workload(
            product_id="testapp", trace_id="fd4b", hcl_files={"main.tf": main_tf},
            target_project_id="target-project-123",
        )
    return res, imports


def test_fd4b_cloud_run_409_single_import_and_golden_module_untouched(tf_svc, tmp_path):
    """Regression for D-1: the typed Cloud Run handler imports once; the Universal 409 engine must
    skip the already-imported address and must never strip the resource from the vendored module."""
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    ws = str(tmp_path / "ws")
    shutil.copytree(repo_root / "infra" / "modules" / "compute-cloudrun",
                    os.path.join(ws, "infra", "modules", "compute-cloudrun"))
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('module "compute" {\n  source = "./infra/modules/compute-cloudrun"\n}\n')
    before = _fd4b_tf_snapshot(ws)
    err409 = (
        "Error: Error creating Service: googleapi: Error 409: Resource 'testapp' already exists.\n\n"
        "  with module.compute.google_cloud_run_v2_service.app,\n"
    )

    res, imports = _fd4b_run_409(tf_svc, ws, err409, plan_creates=[_w7_create(
        "module.compute.google_cloud_run_v2_service.app", "google_cloud_run_v2_service",
        name="testapp", location="us-central1", project="target-project-123")])

    assert imports == ["module.compute.google_cloud_run_v2_service.app"]
    assert res.get("status") == "SUCCESS"
    after = _fd4b_tf_snapshot(ws)
    mod_prefix = os.path.join("infra", "modules") + os.sep
    for rel, content in before.items():
        if rel.startswith(mod_prefix):
            assert after.get(rel) == content, f"vendored golden module file mutated: {rel}"
    assert 'resource "google_cloud_run_v2_service" "app"' in after[os.path.join("infra", "modules", "compute-cloudrun", "main.tf")]


@pytest.mark.parametrize("express", [False, True])
def test_rt14_01_cidr_conflict_is_typed_and_never_deleted(tf_svc, tmp_path, express):
    """RT14-01 (was EXP-7 RT B3): the retry loop's REST subnetwork delete by a regex over the error text is gone on
    every deploy (Agent and Express); the conflict ends the deploy FAILED with the typed SUBNET_CIDR_CONFLICT."""
    from service import DestroyPolicy

    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('module "net" {\n  source = "./infra/modules/networking-vpc"\n}\n')
    apply_err = ("Error: Error creating Subnetwork: googleapi: Error 400: Invalid IPCidrRange: 10.10.0.0/24 conflicts "
                 "with existing subnetwork 'castor-app-subnet' in region 'us-central1'.\n")

    def fake(self, cmd, *a, **k):
        if cmd[1] == "apply":
            return {"success": False, "exit_code": 1, "stdout": "", "stderr": apply_err}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    with patch("shutil.which", return_value="/usr/local/bin/tofu"), \
         patch.object(TerraformService, "prepare_workspace", return_value=ws), \
         patch.object(TerraformService, "_build_and_push_container", return_value="img"), \
         patch.object(TerraformService, "_ensure_provider_mirror"), \
         patch.object(TerraformService, "_run_subprocess", fake), \
         patch.object(TerraformService, "_fetch_repo_files", return_value={}), \
         patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession") as sess_cls, \
         patch("httpx.Client"):
        res = tf_svc.deploy_workload(product_id="testapp", trace_id="exp7-b3", hcl_files={"main.tf": "# x"},
                               target_project_id="target-project-123",
                               destroy_policy=DestroyPolicy() if express else None)
    assert sess_cls.return_value.delete.call_count == 0
    assert res["status"] == "FAILED" and res["error_class"] == "SUBNET_CIDR_CONFLICT" and res["stage"] == "apply"
    assert "castor-app-subnet" in res["error"]   # the engine's own text reaches the operator unchanged


@pytest.mark.parametrize("express", [False, True])
def test_rt14_01_pre_apply_orphan_subnet_is_never_deleted(tf_svc, tmp_path, express):
    """RT14-01 (was EXP-7 RT B3): the pre-apply orphan CIDR purge (case B, substring `castor` / product id) is gone on
    every deploy; negative: the deploy itself is unchanged (SUCCESS)."""
    from service import DestroyPolicy

    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    hcl = ('module "compute" {\n  source       = "./infra/modules/compute-cloudrun"\n  service_name = "testapp"\n}\n\n'
           'resource "google_compute_subnetwork" "app" {\n  name          = "testapp-subnet"\n'
           '  ip_cidr_range = "10.10.0.0/24"\n}\n')
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(hcl)

    def fake(self, cmd, *a, **k):
        if cmd[1] == "output":
            return {"success": True, "exit_code": 0, "stdout": "{}", "stderr": ""}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    listing = MagicMock(status_code=200)
    listing.json.return_value = {"items": [{"name": "castor-orphan", "ipCidrRange": "10.10.0.0/24",
                                            "network": "projects/p/global/networks/castor-vpc"}]}
    with patch("shutil.which", return_value="/usr/local/bin/tofu"), \
         patch.object(TerraformService, "prepare_workspace", return_value=ws), \
         patch.object(TerraformService, "_build_and_push_container", return_value="img"), \
         patch.object(TerraformService, "_ensure_provider_mirror"), \
         patch.object(TerraformService, "_run_subprocess", fake), \
         patch.object(TerraformService, "_fetch_repo_files", return_value={}), \
         patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession") as sess_cls, \
         patch("httpx.Client"), patch("time.sleep"):
        sess_cls.return_value.get.side_effect = lambda url, **k: listing if url.endswith("/subnetworks") else MagicMock(status_code=404)
        res = tf_svc.deploy_workload(product_id="testapp", trace_id="exp7-b3p", hcl_files={"main.tf": hcl},
                               target_project_id="target-project-123",
                               destroy_policy=DestroyPolicy() if express else None)
    assert sess_cls.return_value.delete.call_count == 0
    assert res["status"] == "SUCCESS"
    assert not any(str(c.args[0]).endswith("/subnetworks") for c in sess_cls.return_value.get.call_args_list if c.args)


def _rt14_gke_deploy(tf_svc, tmp_path, outputs_json, manifests, cluster_answer=None, apply_report=None,
                     apply_error=None):
    """deploy_workload of a GKE workload whose apply succeeds; `outputs_json` is `tofu output -json`."""
    ws = str(tmp_path / "ws")
    os.makedirs(ws, exist_ok=True)
    hcl = 'module "compute" {\n  source = "./infra/modules/compute-gke-autopilot"\n}\n'
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(hcl)
    if manifests is not None:
        os.makedirs(os.path.join(ws, "k8s"), exist_ok=True)
        for name, text in manifests.items():
            with open(os.path.join(ws, "k8s", name), "w", encoding="utf-8") as fh:
                fh.write(text)

    def fake(self, cmd, *a, **k):
        if cmd[1] == "output":
            return {"success": True, "exit_code": 0, "stdout": outputs_json, "stderr": ""}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    with patch.object(TerraformService, "prepare_workspace", return_value=ws), \
         patch.object(TerraformService, "_build_and_push_container", return_value="img"), \
         patch.object(TerraformService, "_ensure_provider_mirror"), \
         patch.object(TerraformService, "_run_subprocess", fake), \
         patch.object(TerraformService, "_fetch_repo_files", return_value={}), \
         patch("google.auth.default", return_value=(MagicMock(valid=True, token="tok"), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession") as sess_cls, \
         patch("httpx.Client"), patch("time.sleep"):
        sess_cls.return_value.get.side_effect = lambda url, **k: (
            cluster_answer if "container.googleapis.com" in url and cluster_answer is not None
            else MagicMock(status_code=404))
        if apply_report is not None or apply_error is not None:
            with patch("k8s_manifest_apply.apply_workspace_manifests", return_value=apply_report,
                       side_effect=apply_error) as applied:
                res = tf_svc.deploy_workload(product_id="testapp", trace_id="rt14-04", hcl_files={"main.tf": hcl},
                                             target_project_id="target-project-123")
            return res, applied
        res = tf_svc.deploy_workload(product_id="testapp", trace_id="rt14-04", hcl_files={"main.tf": hcl},
                                     target_project_id="target-project-123")
    return res, None


_RT14_DEPLOYMENT = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 1\n")
_RT14_CLUSTER_OUT = '{"cluster_name": {"sensitive": false, "type": "string", "value": "gke-testapp"}}'


def test_rt14_04_gke_manifests_that_cannot_apply_fail_the_deploy_typed(tf_svc, tmp_path):
    """RT14-04: under the real image layout (no `kubernetes` package, no k8s MCP source) the manifest step used to
    swallow its ImportError and report SUCCESS. Now a step that cannot apply (here: the cluster cannot be read) ends
    the deploy FAILED with K8S_MANIFEST_APPLY_FAILED; the workload record says FAILED too."""
    import sys
    assert "kubernetes.service" not in sys.modules
    res, _ = _rt14_gke_deploy(tf_svc, tmp_path, _RT14_CLUSTER_OUT, {"web.yaml": _RT14_DEPLOYMENT},
                              cluster_answer=MagicMock(status_code=403))
    assert res["status"] == "FAILED"
    assert res["error_class"] == "K8S_MANIFEST_APPLY_FAILED" and res["stage"] == "k8s_manifest_apply"
    assert res["k8s_manifest_code"] == "CLUSTER_UNREADABLE"


@pytest.mark.parametrize("status,reason,developer", [
    (422, "Invalid", True), (400, "BadRequest", True),                 # the cluster says: this manifest is invalid
    (403, "Forbidden", False), (401, "Unauthorized", False), (409, "Conflict", False), (422, "Forbidden", False),
])
def test_rt14_rt_d2_an_invalid_manifest_goes_to_the_developer_everything_else_to_the_operator(
        tf_svc, tmp_path, status, reason, developer):
    """RT D2 (owner 11-14): a server dry-run 422 Invalid / 400 BadRequest (typed status + Status.reason) is IAC_DEFECT,
    not flagged, routed DEVELOPER (the workflow's bounded developer repair); every other answer stays
    K8S_MANIFEST_APPLY_FAILED + operator_required. The deploy is FAILED either way."""
    import k8s_manifest_apply as kma
    import deploy_failure_router as dfr
    err = kma.ManifestApplyFailed("FAILED_SERVER_DRY_RUN", f"Deployment 'web': HTTP {status} {reason}",
                                  http_status=status, api_reason=reason)
    res, _ = _rt14_gke_deploy(tf_svc, tmp_path, _RT14_CLUSTER_OUT, {"web.yaml": _RT14_DEPLOYMENT}, apply_error=err)
    assert res["status"] == "FAILED" and res["stage"] == "k8s_manifest_apply"
    # a typed result is returned as it is; its route (recorded for the gateway) is route_of_typed_result's
    assert dfr.route_of_typed_result(res, "apply")["owner"] == (dfr.DEVELOPER if developer else dfr.OPERATOR_REQUIRED)
    if developer:
        assert res["error_class"] == "IAC_DEFECT" and res["operator_required"] is False
        assert res["code"] == "K8S_MANIFEST_APPLY_FAILED" and res["error"].startswith("K8S_MANIFEST_APPLY_FAILED")
    else:
        assert res["error_class"] == "K8S_MANIFEST_APPLY_FAILED" and res["operator_required"] is True


def test_rt14_04_applied_manifests_keep_success_and_are_reported(tf_svc, tmp_path):
    report = {"status": "APPLIED", "cluster_name": "gke-testapp",
              "resources": [{"kind": "Deployment", "name": "web", "status": "APPLIED"}]}
    res, applied = _rt14_gke_deploy(tf_svc, tmp_path, _RT14_CLUSTER_OUT, {"web.yaml": _RT14_DEPLOYMENT},
                                    apply_report=report)
    assert res["status"] == "SUCCESS" and res["k8s_manifests"] == report
    kw = applied.call_args.kwargs
    assert kw["cluster_name"] == "gke-testapp" and kw["project_id"] == "target-project-123"


@pytest.mark.parametrize("outputs_json,manifests", [
    ('{}', {"web.yaml": _RT14_DEPLOYMENT}),          # no cluster output: not a GKE apply
    (_RT14_CLUSTER_OUT, None),                         # no k8s/ directory
])
def test_rt14_04_negative_no_cluster_or_no_manifests_is_unchanged(tf_svc, tmp_path, outputs_json, manifests):
    res, applied = _rt14_gke_deploy(tf_svc, tmp_path, outputs_json, manifests, apply_report={"status": "APPLIED"})
    assert res["status"] == "SUCCESS" and "k8s_manifests" not in res and "error_class" not in res
    applied.assert_not_called()


def test_rt14_09_sensitive_outputs_never_reach_the_record_or_the_result(tf_svc, tmp_path):
    """RT14-09: a `sensitive = true` output (the pattern the platform's own HINT_SENSITIVE_OUTPUT suggests) is masked
    before the Firestore record and the result (which the tf-applier sends as its callback); the cluster name and
    the URL are still read from the unmasked in-memory map. Negative: unmarked outputs unchanged."""
    out = json.dumps({"db_password": {"sensitive": True, "type": "string", "value": "s3cret-pw"},
                      "cluster_name": {"sensitive": False, "type": "string", "value": "gke-testapp"},
                      "service_url": {"sensitive": False, "type": "string", "value": "https://t.run.app"}})
    report = {"status": "APPLIED", "cluster_name": "gke-testapp", "resources": []}
    res, applied = _rt14_gke_deploy(tf_svc, tmp_path, out, {"web.yaml": _RT14_DEPLOYMENT}, apply_report=report)
    assert res["status"] == "SUCCESS"
    assert res["outputs"]["db_password"]["value"] == "(sensitive value)"
    assert res["outputs"]["service_url"]["value"] == "https://t.run.app" and res["service_url"] == "https://t.run.app"
    assert applied.call_args.kwargs["cluster_name"] == "gke-testapp"
    assert "s3cret-pw" not in json.dumps(res, default=str)
    writes = [str(c) for c in tf_svc.db.mock_calls] if tf_svc.db is not None else []
    assert not any("s3cret-pw" in w for w in writes)


def test_rt14_21_binary_repo_files_reach_the_workspace_as_bytes(tf_svc, tmp_path):
    """RT14-21: a non-UTF-8 repository file (logo, font) travels to prepare_workspace as `binary_files` (exact bytes),
    never in the text manifest every text step reads; the deploy request's own text wins on the same path."""
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('module "net" {\n  source = "./infra/modules/networking-vpc"\n}\n')
    png = b"\x89PNG\r\n\x1a\n\xff\xfe"
    repo = {"main.tf": 'module "net" {\n  source = "./infra/modules/networking-vpc"\n}\n',
            "apps/web/static/logo.png": png, "apps/web/main.py": "print('hi')\n", "override.bin": b"\xff"}
    seen = {}

    def recording_prepare(self, product_id, trace_id, hcl_files, iac_engine=None, region=None, binary_files=None):
        seen["text"], seen["binary"] = dict(hcl_files), dict(binary_files or {})
        return ws

    def fake(self, cmd, *a, **k):
        return {"success": True, "exit_code": 0, "stdout": "{}" if cmd[1] == "output" else "", "stderr": ""}

    with patch.object(TerraformService, "prepare_workspace", recording_prepare), \
         patch.object(TerraformService, "_build_and_push_container", return_value="img"), \
         patch.object(TerraformService, "_ensure_provider_mirror"), \
         patch.object(TerraformService, "_run_subprocess", fake), \
         patch.object(TerraformService, "_fetch_repo_files", return_value=repo), \
         patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("httpx.Client"), patch("time.sleep"):
        res = tf_svc.deploy_workload(product_id="testapp", trace_id="rt14-21",
                                     hcl_files={"override.bin": "now text\n"}, target_project_id="target-project-123")
    assert res["status"] == "SUCCESS"
    assert seen["binary"] == {"apps/web/static/logo.png": png}
    assert all(isinstance(v, str) for v in seen["text"].values())
    assert seen["text"]["apps/web/main.py"] == "print('hi')\n" and seen["text"]["override.bin"] == "now text\n"


def test_fd4b_negative_already_managed_address_never_prunes_valid_hcl(tf_svc, tmp_path):
    """Negative (Do No Harm): valid workload HCL whose address is already in state. The Universal
    409 engine's import returns 'Resource already managed' -> HCL must stay byte-identical and the
    address must be imported at most once."""
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    valid_hcl = (
        'resource "google_compute_global_address" "lb_ip" {\n'
        '  name    = "testapp-lb-ip"\n'
        '  project = var.project_id\n'
        '}\n'
    )
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(valid_hcl)
    addr = "google_compute_global_address.lb_ip"
    err409 = (
        "Error: Error creating GlobalAddress: googleapi: Error 409: The resource "
        "'projects/target-project-123/global/addresses/testapp-lb-ip' already exists, alreadyExists\n\n"
        f"  with {addr},\n"
    )

    res, imports = _fd4b_run_409(tf_svc, ws, err409, already_managed_addr=addr, plan_creates=[_w7_create(
        addr, "google_compute_global_address", name="testapp-lb-ip", project="target-project-123")])

    assert imports.count(addr) == 1
    with open(os.path.join(ws, "main.tf"), "r", encoding="utf-8") as fh:
        assert fh.read() == valid_hcl


# ---------------------------------------------------------------------------
# FD-4CY W7 (proposed row FD55-W7): adoption from the plan; the connector text scan (3b) is deleted (OQ-9a)
# ---------------------------------------------------------------------------
_W7_PID = "target-project-123"
_W7_CONN_ADDR = "module.vpc_connector.google_vpc_access_connector.connector"
_W7_ADOPTION_URL_PARTS = ("/connectors/", "run.googleapis.com/v2/", "secretmanager.googleapis.com",
                          "iam.googleapis.com/v1/projects/", "/subnetworks", "storage.googleapis.com/storage/v1/b/")


def _w7_plan(changes, project_ref="var.project_id", project_value=_W7_PID):
    """The applied plan, with the platform provider block's shape in `configuration.provider_config` and the input
    variables (RT F5-1: a block without `project` gets the provider's default, read from the plan)."""
    return {"format_version": "1.2",
            "configuration": {"root_module": {}, "provider_config": {"google": {
                "name": "google", "full_name": "registry.opentofu.org/hashicorp/google",
                "expressions": {"project": {"references": [project_ref]}, "region": {"references": ["var.region"]}}}}},
            "variables": {"project_id": {"value": project_value}, "region": {"value": "us-central1"}},
            "resource_changes": list(changes)}


def _w7_change(address, rtype, actions=("create",), unknown=None, **after):
    return {"address": address, "mode": "managed", "type": rtype,
            "change": {"actions": list(actions), "after": dict(after), "after_unknown": dict(unknown or {})}}


def _w7_409(address, what="Resource"):
    return (f"Error: Error creating {what}: googleapi: Error 409: Requested entity already exists\n\n"
            f"  with {address},\n  on main.tf line 1, in resource:\n   1: resource {{\n")


def _w7_ws(tmp_path, main_tf, vendor_connector=False):
    ws = str(tmp_path / "ws")
    os.makedirs(ws, exist_ok=True)
    if vendor_connector:
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        shutil.copytree(repo_root / "infra" / "modules" / "networking-vpc-connector",
                        os.path.join(ws, "infra", "modules", "networking-vpc-connector"))
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(main_tf)
    return ws


def _w7_deploy(tf_svc, ws, apply_errs, plan_changes, get=None, import_ok=True, plan_kw=None):
    """deploy_workload with a faked tofu: each apply returns the next of `apply_errs` (None or exhausted = success);
    the applied plan is `plan_changes`; `get(url) -> (status, json)` answers Google REST GETs (default 404)."""
    tf_svc._w7_plan_json = None if plan_changes is None else _w7_plan(plan_changes, **(plan_kw or {}))
    cmds, gets, errs = [], [], list(apply_errs)

    def fake(self, cmd, *a, **k):
        cmds.append(list(cmd))
        if cmd[1] == "apply":
            err = errs.pop(0) if errs else None
            if err:
                return {"success": False, "exit_code": 1, "stdout": "", "stderr": err}
            return {"success": True, "exit_code": 0, "stdout": "Apply complete!", "stderr": ""}
        if cmd[1] == "import" and not import_ok:
            return {"success": False, "exit_code": 1, "stdout": "", "stderr": "Error: Cannot import non-existent remote object"}
        if cmd[1] == "output":
            return {"success": True, "exit_code": 0, "stdout": '{"service_url": {"value": "https://t.run.app"}}', "stderr": ""}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    def _get(url, *a, **k):
        gets.append(url)
        status, body = (get or (lambda u: (404, {})))(url)
        resp = MagicMock(status_code=status, text="")
        resp.json.return_value = body
        return resp

    with open(os.path.join(ws, "main.tf"), "r", encoding="utf-8") as fh:
        main_tf = fh.read()
    with patch("shutil.which", return_value="/usr/local/bin/tofu"), \
         patch.object(TerraformService, "prepare_workspace", return_value=ws), \
         patch.object(TerraformService, "_build_and_push_container", return_value="img"), \
         patch.object(TerraformService, "_ensure_provider_mirror"), \
         patch.object(TerraformService, "_run_subprocess", fake), \
         patch.object(TerraformService, "_fetch_repo_files", return_value={}), \
         patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession") as sess_cls, \
         patch("httpx.Client"), patch("time.sleep"):
        sess_cls.return_value.get.side_effect = _get
        res = tf_svc.deploy_workload(product_id="shop", trace_id="w7", hcl_files={"main.tf": main_tf},
                                     target_project_id=_W7_PID)
    posts = [c.args[0] for c in sess_cls.return_value.post.call_args_list if c.args]
    return res, cmds, gets, posts


def _w7_imports(cmds):
    return [c[3:] for c in cmds if c[1] == "import"]


def _w7_adoption_gets(gets):
    return [u for u in gets if any(p in u for p in _W7_ADOPTION_URL_PARTS)]


_W7_CONNECTOR_MAIN = ('module "vpc_connector" {\n  source = "./infra/modules/networking-vpc-connector"\n'
                      '  name   = "shop-conn"\n}\n')


def test_w7_connector_in_vendored_module_triggers_no_get_and_no_import(tf_svc, tmp_path):
    """The deleted 3b scan walked infra/modules/networking-vpc-connector on every connector workload (a GET, and an
    import at a ROOT address on a 200). Now: no 409, no GET, no import, files byte-identical."""
    ws = _w7_ws(tmp_path, _W7_CONNECTOR_MAIN, vendor_connector=True)
    before = _fd4b_tf_snapshot(ws)
    res, cmds, gets, _ = _w7_deploy(tf_svc, ws, [], [_w7_change(
        _W7_CONN_ADDR, "google_vpc_access_connector", name="shop-conn", region="us-central1", project=_W7_PID)],
        get=lambda u: (200, {}))   # even if the connector existed, nothing scans for it any more
    assert res["status"] == "SUCCESS"
    assert [u for u in gets if "/connectors/" in u] == []
    assert _w7_imports(cmds) == []
    assert _fd4b_tf_snapshot(ws) == before


def test_w7_module_connector_409_is_adopted_at_its_module_address_with_the_planned_id(tf_svc, tmp_path):
    ws = _w7_ws(tmp_path, _W7_CONNECTOR_MAIN, vendor_connector=True)
    before = _fd4b_tf_snapshot(ws)
    res, cmds, _, _ = _w7_deploy(tf_svc, ws, [_w7_409(_W7_CONN_ADDR, "Connector")], [_w7_change(
        _W7_CONN_ADDR, "google_vpc_access_connector", name="shop-conn", region="us-central1", project=_W7_PID)])
    assert res["status"] == "SUCCESS" and "error_class" not in res
    assert _w7_imports(cmds) == [[_W7_CONN_ADDR, f"projects/{_W7_PID}/locations/us-central1/connectors/shop-conn"]]
    assert _fd4b_tf_snapshot(ws) == before


def test_w7_root_connector_named_by_a_variable_uses_the_planned_name_and_region(tf_svc, tmp_path):
    """Was: any `var.*` connector name became `castor-vpc-conn`, region from the workload. Now the plan's values."""
    ws = _w7_ws(tmp_path, 'resource "google_vpc_access_connector" "conn" {\n  name   = var.connector_name\n'
                          '  region = var.connector_region\n}\n')
    addr = "google_vpc_access_connector.conn"
    res, cmds, _, _ = _w7_deploy(tf_svc, ws, [_w7_409(addr, "Connector")], [_w7_change(
        addr, "google_vpc_access_connector", name="orders-conn", region="europe-west1")])
    assert res["status"] == "SUCCESS"
    assert _w7_imports(cmds) == [[addr, f"projects/{_W7_PID}/locations/europe-west1/connectors/orders-conn"]]


@pytest.mark.parametrize("change,reason", [
    (_w7_change("google_secret_manager_secret.s", "google_secret_manager_secret", unknown={"secret_id": True}),
     "not known until apply"),
    (_w7_change("google_secret_manager_secret.s", "google_secret_manager_secret", secret_id="x", project="other-p"),
     "not the workload project"),
    (_w7_change("google_secret_manager_secret.s", "google_secret_manager_secret", actions=("update",), secret_id="x"),
     "does not create it"),
    (_w7_change("google_secret_manager_secret.other", "google_secret_manager_secret", secret_id="x"),
     "not in the applied plan"),
])
def test_w7_409_without_an_exact_planned_name_fails_typed_and_imports_nothing(tf_svc, tmp_path, change, reason):
    """Was: `order-signing-secret` / the product id. Now: typed APPLY_ADOPTION_UNRESOLVED naming the address."""
    ws = _w7_ws(tmp_path, 'resource "google_secret_manager_secret" "s" {\n  secret_id = var.sid\n}\n')
    res, cmds, _, _ = _w7_deploy(tf_svc, ws, [_w7_409("google_secret_manager_secret.s", "Secret")] * 3, [change])
    assert _w7_imports(cmds) == []
    assert res["status"] == "FAILED" and res["error_class"] == "APPLY_ADOPTION_UNRESOLVED"
    assert res["stage"] == "apply_adoption"
    assert res["adoption_unresolved"][0]["address"] == "google_secret_manager_secret.s"
    assert reason in res["adoption_unresolved"][0]["reason"]
    assert res["error"].startswith("Terraform apply failed: Error: Error creating Secret")   # text unchanged
    assert [c[1] for c in cmds].count("apply") == 1   # nothing imported -> no retry


@pytest.mark.parametrize("project_ref,project_value,adopted", [
    ("var.project_id", _W7_PID, True), ("var.other_project", _W7_PID, False), ("var.project_id", "host-p", False)])
def test_w7_rt_f5_1_root_secret_without_project_adopts_only_through_the_pinned_provider(tf_svc, tmp_path, project_ref,
                                                                                      project_value, adopted):
    """RT F5-1: an AI-written root block without `project` plans `project` as unknown; it is adopted with the exact
    id only when the plan's provider configuration pins the project to the workload project."""
    ws = _w7_ws(tmp_path, 'resource "google_secret_manager_secret" "order_key" {\n  secret_id = "order-key"\n}\n')
    addr = "google_secret_manager_secret.order_key"
    change = _w7_change(addr, "google_secret_manager_secret", unknown={"project": True}, secret_id="order-key")
    res, cmds, _, _ = _w7_deploy(tf_svc, ws, [_w7_409(addr, "Secret")], [change],
                                 plan_kw={"project_ref": project_ref, "project_value": project_value})
    if adopted:
        assert _w7_imports(cmds) == [[addr, f"projects/{_W7_PID}/secrets/order-key"]] and res["status"] == "SUCCESS"
    else:
        assert _w7_imports(cmds) == [] and res["error_class"] == "APPLY_ADOPTION_UNRESOLVED"
        assert "does not pin it to the workload project" in res["adoption_unresolved"][0]["reason"]


def test_w7_409_without_a_plan_or_without_an_address_fails_typed(tf_svc, tmp_path):
    ws = _w7_ws(tmp_path, "# x\n")
    res, cmds, _, _ = _w7_deploy(tf_svc, ws, [_w7_409("google_pubsub_topic.t", "Topic")], None)
    assert _w7_imports(cmds) == [] and res["error_class"] == "APPLY_ADOPTION_UNRESOLVED"
    assert res["adoption_unresolved"] == [{"address": "google_pubsub_topic.t",
                                           "reason": "no readable plan for the failed apply"}]
    no_addr = "Error: Error creating Topic: googleapi: Error 409: Resource already exists in the project\n"
    res, cmds, _, _ = _w7_deploy(tf_svc, ws, [no_addr], [])
    assert _w7_imports(cmds) == [] and res["error_class"] == "APPLY_ADOPTION_UNRESOLVED"
    assert res["adoption_unresolved"][0]["address"] == ""


def test_w7_failed_import_is_typed_and_never_touches_files(tf_svc, tmp_path):
    ws = _w7_ws(tmp_path, 'resource "google_pubsub_topic" "t" {\n  name = "orders"\n}\n')
    before = _fd4b_tf_snapshot(ws)
    addr = "google_pubsub_topic.t"
    res, cmds, _, _ = _w7_deploy(tf_svc, ws, [_w7_409(addr, "Topic")], [_w7_change(addr, "google_pubsub_topic",
                                                                                     name="orders")], import_ok=False)
    assert _w7_imports(cmds) == [[addr, f"projects/{_W7_PID}/topics/orders"]]
    assert res["error_class"] == "APPLY_ADOPTION_UNRESOLVED"
    assert "`import` of 'projects/target-project-123/topics/orders' failed" in res["adoption_unresolved"][0]["reason"]
    assert _fd4b_tf_snapshot(ws) == before


@pytest.mark.parametrize("bucket_project_number,adopted", [("222", True), ("111", False)])
def test_w7_bucket_409_is_adopted_only_when_the_bucket_is_in_the_workload_project(tf_svc, tmp_path,
                                                                                    bucket_project_number, adopted):
    ws = _w7_ws(tmp_path, 'resource "google_storage_bucket" "b" {\n  name = var.bucket\n}\n')
    addr = "google_storage_bucket.b"

    def get(url):
        if "storage.googleapis.com/storage/v1/b/shop-payloads" in url:
            return 200, {"projectNumber": bucket_project_number}
        if url.endswith(f"cloudresourcemanager.googleapis.com/v1/projects/{_W7_PID}"):
            return 200, {"projectNumber": "222"}
        return 404, {}

    res, cmds, _, _ = _w7_deploy(tf_svc, ws, [_w7_409(addr, "Bucket")], [_w7_change(
        addr, "google_storage_bucket", name="shop-payloads", location="US")], get=get)
    if adopted:
        assert _w7_imports(cmds) == [[addr, "shop-payloads"]] and res["status"] == "SUCCESS"
    else:
        assert _w7_imports(cmds) == [] and res["error_class"] == "APPLY_ADOPTION_UNRESOLVED"
        assert "not a bucket of the workload project" in res["adoption_unresolved"][0]["reason"]


def test_w7_wif_pool_409_undeletes_and_imports_the_planned_pool_id(tf_svc, tmp_path):
    """A52 kept (undelete before import), with the exact planned pool id (was a fixed `castor-gh-pool`)."""
    ws = _w7_ws(tmp_path, "# x\n")
    addr = "module.foundation.google_iam_workload_identity_pool.github_pool"
    res, cmds, _, posts = _w7_deploy(tf_svc, ws, [_w7_409(addr, "WorkloadIdentityPool")], [_w7_change(
        addr, "google_iam_workload_identity_pool", workload_identity_pool_id="shop-gh-pool", project=_W7_PID)])
    pool = f"projects/{_W7_PID}/locations/global/workloadIdentityPools/shop-gh-pool"
    assert f"https://iam.googleapis.com/v1/{pool}:undelete" in posts
    assert _w7_imports(cmds) == [[addr, pool]] and res["status"] == "SUCCESS"


def test_w7_pass0_pre_imports_an_existing_planned_secret_at_its_plan_address(tf_svc, tmp_path):
    ws = _w7_ws(tmp_path, "# x\n")
    sec = "module.app.google_secret_manager_secret.signing"
    unknown_sa = "google_service_account.runner"
    changes = [_w7_change(sec, "google_secret_manager_secret", secret_id="shop-signing"),
               _w7_change(unknown_sa, "google_service_account", unknown={"account_id": True}),
               _w7_change("google_pubsub_topic.t", "google_pubsub_topic", name="t")]   # not a Pass 0 type
    res, cmds, gets, _ = _w7_deploy(
        tf_svc, ws, [], changes,
        get=lambda u: (200, {}) if u.endswith(f"/projects/{_W7_PID}/secrets/shop-signing") else (404, {}))
    assert _w7_adoption_gets(gets) == [f"https://secretmanager.googleapis.com/v1/projects/{_W7_PID}/secrets/shop-signing"]
    assert _w7_imports(cmds) == [[sec, f"projects/{_W7_PID}/secrets/shop-signing"]]
    sub = [c[1] for c in cmds]
    assert sub.index("import") < sub.index("apply") and res["status"] == "SUCCESS"


def test_w7_negative_no_409_same_commands_and_no_adoption_rest_call(tf_svc, tmp_path):
    """Do No Harm: a deploy whose plan has nothing to adopt runs exactly the same tofu commands as one whose plan
    creates nothing, with no import and no `state list`; a plan without Pass 0 types makes no adoption GET; files are
    byte-identical."""
    ws = _w7_ws(tmp_path, 'module "compute" {\n  source       = "./infra/modules/compute-cloudrun"\n'
                          '  service_name = var.service_name\n}\n')
    before = _fd4b_tf_snapshot(ws)
    _, empty_cmds, empty_gets, _ = _w7_deploy(tf_svc, ws, [], [])
    creates = [_w7_change("module.compute.google_cloud_run_v2_service.app", "google_cloud_run_v2_service",
                          name="shop", location="us-central1"),
               _w7_change("google_pubsub_topic.t", "google_pubsub_topic", name="t")]
    res, cmds, gets, _ = _w7_deploy(tf_svc, ws, [], creates)   # the service does not exist (404)
    assert res["status"] == "SUCCESS"
    assert [c[1] for c in cmds] == [c[1] for c in empty_cmds]
    assert not {"import", "state"} & {c[1] for c in cmds}
    assert _w7_adoption_gets(empty_gets) == []
    assert _w7_adoption_gets(gets) == [f"https://run.googleapis.com/v2/projects/{_W7_PID}/locations/us-central1/services/shop"]
    assert _fd4b_tf_snapshot(ws) == before


# ---------------------------------------------------------------------------
# FD-4H: state locks are never broken automatically; state bytes are never rewritten
# ---------------------------------------------------------------------------
import contextlib
from datetime import datetime as _dt, timedelta as _td, timezone as _tz


class _FakeBlob:
    def __init__(self, bucket, name, data=None, generation=None, time_created=None):
        self.bucket_ref, self.name, self.data = bucket, name, data
        self.generation, self.time_created = generation, time_created

    def exists(self):
        return self.data is not None

    def download_as_bytes(self, **kwargs):
        self.bucket_ref.reads.append(self.name)
        return self.data

    def download_as_text(self, **kwargs):
        self.bucket_ref.reads.append(self.name)
        return self.data.decode("utf-8")

    def upload_from_string(self, *args, **kwargs):
        self.bucket_ref.writes.append(("upload", self.name))

    def delete(self, *args, **kwargs):
        self.bucket_ref.writes.append(("delete", self.name))

    def rewrite(self, *args, **kwargs):
        self.bucket_ref.writes.append(("rewrite", self.name))


class _FakeBucket:
    def __init__(self, objects):
        self.objects, self.reads, self.writes = objects, [], []

    def get_blob(self, name, **kwargs):
        spec = self.objects.get(name)
        return _FakeBlob(self, name, **spec) if spec else None

    def blob(self, name, **kwargs):
        spec = self.objects.get(name) or {}
        return _FakeBlob(self, name, **spec)


def _fake_storage_client(bucket):
    client = MagicMock()
    client.bucket.return_value = bucket
    return MagicMock(return_value=client)


_FD4H_STATE = b'{"resources":[{"instances":[{"attributes":{"deletion_protection": true}}]}]}'
_FD4H_LOCK_GEN = 1760000000123456


def _fd4h_lock_object(age_seconds=3600.0):
    return {
        "data": json.dumps({"ID": "uuid-ignored", "Operation": "OperationTypeApply",
                            "Who": "cnb@localhost", "Version": "1.13.1", "Created": "x"}).encode(),
        "generation": _FD4H_LOCK_GEN,
        "time_created": _dt.now(_tz.utc) - _td(seconds=age_seconds),
    }


def _fd4h_lock_stderr(created_dt):
    return (
        "Error: Error acquiring the state lock\n\nLock Info:\n  ID:        1760000000000000\n"
        "  Path:      bucket/workloads/testapp/default.tflock\n  Operation: OperationTypeApply\n"
        "  Who:       other-pipeline@runner\n  Version:   1.13.1\n  Created:   "
        + created_dt.strftime("%Y-%m-%d %H:%M:%S.000000 +0000 UTC") + "\n  Info:\n"
    )


@contextlib.contextmanager
def _fd4h_deploy_env(ws, fake_run, storage_client_factory):
    with patch("shutil.which", return_value="/usr/local/bin/tofu"), \
         patch.object(TerraformService, "prepare_workspace", return_value=ws), \
         patch.object(TerraformService, "_build_and_push_container", return_value=True) as build, \
         patch.object(TerraformService, "_ensure_provider_mirror"), \
         patch.object(TerraformService, "_run_subprocess", fake_run), \
         patch.object(TerraformService, "_fetch_repo_files", return_value={}) as fetch, \
         patch("google.cloud.storage.Client", storage_client_factory), \
         patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("httpx.Client"):
        yield build, fetch


def _fd4h_workspace(tmp_path):
    ws = str(tmp_path / "ws")
    os.makedirs(ws, exist_ok=True)
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('module "foundation" {\n  source = "./infra/modules/foundation"\n}\n')
    return ws


def _fd4h_recording_run(apply_results):
    calls = []
    results = list(apply_results)

    def fake(self, cmd, *a, **k):
        calls.append(list(cmd))
        if cmd[1] == "apply":
            return results.pop(0) if results else {"success": True, "exit_code": 0, "stdout": "Apply complete!", "stderr": ""}
        if cmd[1] == "output":
            return {"success": True, "exit_code": 0, "stdout": '{"service_url": {"value": "https://t.run.app"}}', "stderr": ""}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    return fake, calls


def test_fd4h_held_lock_preflight_never_deleted_and_state_never_written(tmp_path):
    """Probe 2 inverted: lock object present + state with deletion_protection=true. Nothing is deleted or
    uploaded, no tofu runs, no container is built, and the STATE_LOCKED contract names the GCS generation."""
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=MagicMock())
    svc.lock_timeout = "0s"  # the bounded pre-flight wait itself is covered by the F-4 tests below
    bucket = _FakeBucket({
        "workloads/testapp/default.tfstate": {"data": _FD4H_STATE},
        "workloads/testapp/default.tflock": _fd4h_lock_object(age_seconds=7 * 24 * 3600),
    })
    fake, calls = _fd4h_recording_run([])
    with _fd4h_deploy_env(_fd4h_workspace(tmp_path), fake, _fake_storage_client(bucket)) as (build, fetch):
        res = svc.deploy_workload(product_id="testapp", trace_id="t1", hcl_files=None, target_project_id="child-123")

    assert bucket.writes == []
    assert calls == []
    build.assert_not_called()
    fetch.assert_not_called()
    assert res["status"] == "FAILED"
    assert res["error_class"] == "STATE_LOCKED"
    assert res["error"].startswith("STATE_LOCKED: ")
    assert res["lock_info"]["lock_id"] == str(_FD4H_LOCK_GEN)
    assert res["lock_info"]["who"] == "cnb@localhost"
    assert f'"lock_id": "{_FD4H_LOCK_GEN}"' in res["error"]
    assert "/api/workloads/testapp/force-unlock" in res["error"]
    assert res["lock_holder"]["verdict"] == "NOT_ASSESSED"


def test_fd4h_no_lock_deploy_never_rewrites_state_bytes(tmp_path):
    """Negative: no lock, state still says deletion_protection=true. The deploy proceeds and the state object
    is never uploaded, rewritten or deleted (the raw text edit is gone)."""
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=MagicMock())
    bucket = _FakeBucket({"workloads/testapp/default.tfstate": {"data": _FD4H_STATE}})
    fake, calls = _fd4h_recording_run([])
    with _fd4h_deploy_env(_fd4h_workspace(tmp_path), fake, _fake_storage_client(bucket)):
        res = svc.deploy_workload(product_id="testapp", trace_id="t1", hcl_files={"main.tf": "# x"},
                                  target_project_id="child-123")

    assert res["status"] == "SUCCESS"
    assert bucket.writes == []
    assert "workloads/testapp/default.tfstate" not in bucket.reads
    assert not any(c[1] == "force-unlock" for c in calls)


def test_fd4h_preflight_read_failure_proceeds_and_never_unlocks(tmp_path):
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=MagicMock())
    fake, calls = _fd4h_recording_run([])
    with _fd4h_deploy_env(_fd4h_workspace(tmp_path), fake, MagicMock(side_effect=RuntimeError("no creds"))):
        res = svc.deploy_workload(product_id="testapp", trace_id="t1", hcl_files={"main.tf": "# x"},
                                  target_project_id="child-123")
    assert res["status"] == "SUCCESS"
    assert not any(c[1] == "force-unlock" for c in calls)


@pytest.mark.parametrize("age", [_td(seconds=0.5), _td(minutes=19, seconds=59), _td(minutes=20, seconds=1), _td(days=30)])
def test_fd4h_lock_at_apply_is_never_force_unlocked(tmp_path, age):
    """Probe 1 inverted: fresh, boundary and weeks-old locks alike end in STATE_LOCKED after exactly one apply,
    with no force-unlock and no healer/import/state command afterwards."""
    svc = TerraformService(project_id="host", workspace_base_dir=str(tmp_path), firestore_client=MagicMock())
    lock_err = _fd4h_lock_stderr(_dt.now(_tz.utc) - age)
    fake, calls = _fd4h_recording_run([{"success": False, "exit_code": 1, "stdout": "", "stderr": lock_err}])
    with _fd4h_deploy_env(_fd4h_workspace(tmp_path), fake, MagicMock(side_effect=RuntimeError("unused"))):
        res = svc.deploy_workload(product_id="testapp", trace_id="t1", hcl_files={"main.tf": "# x"},
                                  target_project_id="target-project-123")

    sub = [c[1] for c in calls]
    assert sub.count("apply") == 1
    assert "force-unlock" not in sub
    assert sub[-1] == "apply", sub
    assert res["status"] == "FAILED"
    assert res["error_class"] == "STATE_LOCKED"
    assert res["error"].startswith("STATE_LOCKED: ")
    assert res["lock_info"]["lock_id"] == "1760000000000000"
    assert res["stderr"] == lock_err


def test_fd4h_protected_destroy_error_is_not_healed(tmp_path):
    """H5 deleted: a provider deletion_protection refusal is surfaced as-is. No `state rm` (which orphaned live
    services), no config rewrite, no retry loop."""
    svc = TerraformService(project_id="host", workspace_base_dir=str(tmp_path), firestore_client=MagicMock())
    ws = str(tmp_path / "ws")
    os.makedirs(ws)
    hcl = 'resource "google_cloud_run_v2_service" "app" {\n  name     = "app"\n  location = var.region\n}\n'
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(hcl)
    dp_err = (
        "Error: cannot destroy service without setting deletion_protection=false and running `terraform apply`\n\n"
        "  with google_cloud_run_v2_service.app,\n"
    )
    fake, calls = _fd4h_recording_run([{"success": False, "exit_code": 1, "stdout": "", "stderr": dp_err}] * 3)
    with _fd4h_deploy_env(ws, fake, MagicMock(side_effect=RuntimeError("unused"))):
        res = svc.deploy_workload(product_id="testapp", trace_id="t1", hcl_files={"main.tf": hcl},
                                  target_project_id="target-project-123")

    sub = [c[1] for c in calls]
    assert not any(c[1:3] == ["state", "rm"] for c in calls), calls
    assert sub.count("apply") == 1
    assert res["status"] == "FAILED"
    assert "deletion_protection" in res["error"]
    with open(os.path.join(ws, "main.tf"), "r", encoding="utf-8") as fh:
        assert fh.read() == hcl


def test_fd4h_read_state_lock_uses_gcs_metadata(tmp_path):
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=MagicMock())
    bucket = _FakeBucket({"workloads/testapp/default.tflock": _fd4h_lock_object(age_seconds=1200)})
    with patch("google.cloud.storage.Client", _fake_storage_client(bucket)):
        info = svc._read_state_lock("testapp")
    assert info["lock_id"] == str(_FD4H_LOCK_GEN)
    assert info["who"] == "cnb@localhost"
    assert info["operation"] == "OperationTypeApply"
    assert info["path"] == "gs://tfstate-bucket/workloads/testapp/default.tflock"
    assert 1199.0 <= info["age_seconds"] <= 1205.0
    assert bucket.writes == []

    with patch("google.cloud.storage.Client", _fake_storage_client(_FakeBucket({}))):
        assert svc._read_state_lock("testapp") is None

    bad = _fd4h_lock_object()
    bad["generation"] = None
    with patch("google.cloud.storage.Client", _fake_storage_client(_FakeBucket({"workloads/testapp/default.tflock": bad}))):
        with pytest.raises(ValueError):
            svc._read_state_lock("testapp")


def test_fd4h_tofu_lock_who_matches_go_user_current_order():
    """H-3: passwd name, then $USER, then empty; always '@' + hostname (OpenTofu statemgr.NewLockInfo)."""
    with patch("socket.gethostname", return_value="localhost"):
        with patch("pwd.getpwuid", return_value=MagicMock(pw_name="cnb")), patch.dict(os.environ, {"USER": "env-user"}):
            assert TerraformService._tofu_lock_who() == "cnb@localhost"
        with patch("pwd.getpwuid", side_effect=KeyError("uid")), patch.dict(os.environ, {"USER": "env-user"}):
            assert TerraformService._tofu_lock_who() == "env-user@localhost"
        with patch("pwd.getpwuid", side_effect=KeyError("uid")), patch.dict(os.environ, {}, clear=True):
            assert TerraformService._tofu_lock_who() == "@localhost"


def test_fd23_17_force_unlock_path_body_mismatch_rejected():
    if not TestClient or not app:
        return
    import main as tf_main
    client = TestClient(app)
    with patch.object(tf_main.service, "force_unlock", return_value={"status": "UNLOCKED"}) as fu:
        r = client.post("/api/workloads/app-a/force-unlock", json={"product_id": "app-b", "lock_id": "1"})
        assert r.status_code == 400
        fu.assert_not_called()
        r = client.post("/api/workloads/app-a/force-unlock", json={"product_id": "app-a", "lock_id": "7"})
        assert r.status_code == 200
        assert fu.call_args.kwargs["product_id"] == "app-a"
        assert fu.call_args.kwargs["lock_id"] == "7"


def test_fd23_16_deploy_async_marks_pipeline_in_flight():
    if not TestClient or not app:
        return
    import main as tf_main
    from fastapi import BackgroundTasks
    db = MagicMock()
    with patch.object(tf_main.service, "db", db):
        req = tf_main.AsyncDeployRequest(product_id="p", trace_id="tr-1", callback_url="http://cb")
        tf_main.deploy_infra_async(req, BackgroundTasks())
    payload = db.collection.return_value.document.return_value.set.call_args[0][0]
    assert payload["stages"]["terraform"]["status"] == "IN_FLIGHT"
    assert payload["stages"]["terraform"]["started_at"]



# ---------------------------------------------------------------------------
# FD-4AO: Terraform MCP tools fail closed
# ---------------------------------------------------------------------------
def _fd4ao_ok(stdout=""):
    return {"success": True, "exit_code": 0, "stdout": stdout, "stderr": ""}


def _fd4ao_plan(actions_by_address):
    # FD-4AW-b: a real `show -json` always carries `configuration` (the apply-time content policy reads it)
    return json.dumps({"configuration": {"root_module": {}}, "resource_changes": [
        {"address": addr, "type": addr.split(".")[-2], "name": addr.split(".")[-1], "change": {"actions": acts}}
        for addr, acts in actions_by_address.items()
    ]})


@pytest.mark.parametrize("actions", [["delete", "create"], ["create", "delete"], ["delete"]])
def test_fd4ao_generate_plan_counts_any_delete_as_destroy(mock_tf_service, actions):
    plan = _fd4ao_plan({"google_sql_database_instance.db": actions, "google_storage_bucket.b": ["create"]})
    with patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
         patch.object(mock_tf_service, "_run_subprocess") as mock_sub:
        mock_sub.side_effect = [_fd4ao_ok("init"), _fd4ao_ok("{}"), _fd4ao_ok("Plan"), _fd4ao_ok(plan)]
        res = mock_tf_service.generate_plan("auth-service", "trace-ao", {"main.tf": "# x"}, iac_engine="OPENTOFU")
    assert res["status"] == "PLAN_READY"
    assert res["resource_changes"]["destroy"] == 1
    assert res["resource_changes"]["add"] == 1
    assert res["resource_changes"]["destroy_addresses"] == ["google_sql_database_instance.db"]
    assert res["is_safe_autonomous"] is False


def test_fd4ao_generate_plan_validate_failure_fails_closed(mock_tf_service):
    with patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
         patch.object(mock_tf_service, "_run_subprocess") as mock_sub:
        mock_sub.side_effect = [_fd4ao_ok("init"),
                                {"success": False, "exit_code": 1, "stdout": '{"valid": false}', "stderr": "bad ref"}]
        res = mock_tf_service.generate_plan("auth-service", "trace-ao", {"main.tf": "# x"}, iac_engine="OPENTOFU")
    assert res["status"] == "VALIDATE_FAILED"
    assert res["is_safe_autonomous"] is False
    assert [c[0][0][1] for c in mock_sub.call_args_list] == ["init", "validate"]


@pytest.mark.parametrize("show", [
    {"success": False, "exit_code": 1, "stdout": "", "stderr": "boom"},
    _fd4ao_ok("not json"),
    _fd4ao_ok("[]"),
])
def test_fd4ao_generate_plan_unreadable_plan_is_unsafe(mock_tf_service, show):
    with patch.object(mock_tf_service, "_ensure_binary", return_value="tofu"), \
         patch.object(mock_tf_service, "_run_subprocess") as mock_sub:
        mock_sub.side_effect = [_fd4ao_ok("init"), _fd4ao_ok("{}"), _fd4ao_ok("Plan"), show]
        res = mock_tf_service.generate_plan("auth-service", "trace-ao", {"main.tf": "# x"}, iac_engine="OPENTOFU")
    assert res["is_safe_autonomous"] is False
    assert res["plan_json_error"]


def _fd4ao_workspace(svc, with_plan):
    ws = svc._workspace_dir("trace-ap", "auth-service")
    os.makedirs(ws, exist_ok=True)
    if with_plan:
        with open(os.path.join(ws, "tfplan"), "wb") as fh:
            fh.write(b"saved-plan")
    return ws


def test_fd4ao_apply_plan_refuses_without_saved_plan(mock_tf_service):
    _fd4ao_workspace(mock_tf_service, with_plan=False)
    with patch.object(mock_tf_service, "_run_subprocess") as mock_sub:
        res = mock_tf_service.apply_plan("auth-service", "trace-ap", iac_engine="OPENTOFU")
    assert res["status"] == "REFUSED"
    assert res["reason"] == "NO_SAVED_PLAN"
    mock_sub.assert_not_called()


@pytest.mark.parametrize("actions", [["delete"], ["delete", "create"], ["create", "delete"]])
def test_fd4ao_apply_plan_refuses_destroy_or_replace(mock_tf_service, actions):
    _fd4ao_workspace(mock_tf_service, with_plan=True)
    plan = _fd4ao_plan({"google_sql_database_instance.db": actions})
    with patch.object(mock_tf_service, "_run_subprocess", return_value=_fd4ao_ok(plan)) as mock_sub:
        res = mock_tf_service.apply_plan("auth-service", "trace-ap", iac_engine="OPENTOFU")
    assert res["status"] == "REFUSED"
    assert res["reason"] == "PLAN_HAS_DESTROY"
    assert res["destroy_addresses"] == ["google_sql_database_instance.db"]
    assert [c[0][0][1] for c in mock_sub.call_args_list] == ["show"]


def test_fd4ao_apply_plan_refuses_unreadable_plan(mock_tf_service):
    _fd4ao_workspace(mock_tf_service, with_plan=True)
    with patch.object(mock_tf_service, "_run_subprocess",
                      return_value={"success": False, "exit_code": 1, "stdout": "", "stderr": "corrupt"}) as mock_sub:
        res = mock_tf_service.apply_plan("auth-service", "trace-ap", iac_engine="OPENTOFU")
    assert res["status"] == "REFUSED"
    assert res["reason"] == "PLAN_UNREADABLE"
    assert [c[0][0][1] for c in mock_sub.call_args_list] == ["show"]


@pytest.mark.parametrize("exit_code,status", [(0, "IN_SYNC"), (2, "DRIFT_DETECTED"), (1, "ERROR"), (None, "ERROR")])
def test_fd4ao_check_drift_exit_codes(mock_tf_service, exit_code, status):
    _fd4ao_workspace(mock_tf_service, with_plan=False)
    sub = {"success": exit_code == 0, "exit_code": exit_code, "stdout": "", "stderr": "Error: x" if exit_code == 1 else ""}
    with patch.object(mock_tf_service, "_run_subprocess", return_value=sub) as mock_sub:
        res = mock_tf_service.check_drift("auth-service", "trace-ap")
    assert res["status"] == status
    assert res["has_drift"] is (status == "DRIFT_DETECTED")
    if status == "ERROR":
        assert res["error"]


def test_fd4ao_check_drift_uses_resolved_engine(mock_tf_service):
    _fd4ao_workspace(mock_tf_service, with_plan=False)
    doc = MagicMock(exists=True)
    doc.to_dict.return_value = {"iac_engine": "OPENTOFU"}
    mock_tf_service.db.collection.return_value.document.return_value.get.return_value = doc
    with patch.object(mock_tf_service, "_run_subprocess", return_value=_fd4ao_ok()) as mock_sub:
        mock_tf_service.check_drift("auth-service", "trace-ap")
    assert mock_sub.call_args.kwargs["iac_engine"] == "OPENTOFU"


def test_fd4ao_removed_mcp_write_tools_are_unknown():
    if not TestClient or not app:
        return
    import main as tf_main
    client = TestClient(app)
    with patch.object(tf_main.service, "apply_plan") as ap, patch.object(tf_main.service, "force_unlock") as fu:
        for name, args in [("terraform_apply", {"product_id": "a", "trace_id": "t"}),
                           ("terraform_force_unlock", {"product_id": "a", "lock_id": "1"})]:
            body = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                             "params": {"name": name, "arguments": args}}).json()
            assert body["error"]["code"] == -32601
        ap.assert_not_called()
        fu.assert_not_called()


def test_fd4ao_rest_apply_refused_is_409_and_drift_error_is_500():
    if not TestClient or not app:
        return
    import main as tf_main
    client = TestClient(app)
    with patch.object(tf_main.service, "apply_plan", return_value={"status": "REFUSED", "reason": "NO_SAVED_PLAN"}):
        assert client.post("/apply", json={"product_id": "a", "trace_id": "t"}).status_code == 409
    with patch.object(tf_main.service, "check_drift", return_value={"status": "ERROR", "error": "x"}):
        assert client.post("/drift-check", json={"product_id": "a", "trace_id": "t"}).status_code == 500
    with patch.object(tf_main.service, "check_drift", return_value={"status": "IN_SYNC"}):
        assert client.post("/drift-check", json={"product_id": "a", "trace_id": "t"}).status_code == 200


# ---------------------------------------------------------------------------
# FD-4BA: the build source bucket is never public and never falls back to the state bucket
# ---------------------------------------------------------------------------
_FD4BA_SA = "123456789-compute@developer.gserviceaccount.com"


def _fd4ba_policy(bindings):
    from google.api_core.iam import Policy
    pol = Policy(version=3)
    pol.bindings = bindings
    return pol


def _fd4ba_session(status=200, email=_FD4BA_SA):
    sess = MagicMock()
    resp = MagicMock(status_code=status, text="denied")
    resp.json.return_value = {"name": "projects/child/locations/global/defaultServiceAccount",
                              "serviceAccountEmail": f"projects/child/serviceAccounts/{email}"}
    sess.get.return_value = resp
    return sess


def _fd4ba_bucket(exists=True, bindings=None):
    bucket = MagicMock()
    bucket.exists.return_value = exists
    bucket.get_iam_policy.return_value = _fd4ba_policy(bindings or [])
    return bucket


def _fd4ba_all_members(bucket):
    members = set()
    for call in bucket.set_iam_policy.call_args_list:
        for b in call[0][0].bindings:
            members |= set(b["members"])
    return members


def test_fd4ba_grants_only_resolved_build_sa_and_strips_public_members(mock_tf_service):
    bucket = _fd4ba_bucket(bindings=[
        {"role": "roles/storage.objectViewer", "members": {"allAuthenticatedUsers"}},
        {"role": "roles/storage.legacyBucketOwner", "members": {"projectOwner:child", "allUsers"}},
    ])
    client = MagicMock()
    client.bucket.return_value = bucket
    sess = _fd4ba_session()

    mock_tf_service._stage_build_source(client, sess, "child", "child-cloudbuild-source", "sources/a/x/source.tar.gz", b"tgz")

    assert sess.get.call_args[0][0] == (
        "https://cloudbuild.googleapis.com/v1/projects/child/locations/global/defaultServiceAccount")
    written = bucket.set_iam_policy.call_args[0][0].bindings
    assert not (_fd4ba_all_members(bucket) & {"allUsers", "allAuthenticatedUsers"})
    viewers = [b for b in written if b["role"] == "roles/storage.objectViewer"]
    assert [set(b["members"]) for b in viewers] == [{f"serviceAccount:{_FD4BA_SA}"}]
    assert {"role": "roles/storage.legacyBucketOwner", "members": {"projectOwner:child"}} in written
    bucket.blob.assert_called_once_with("sources/a/x/source.tar.gz")
    bucket.blob.return_value.upload_from_string.assert_called_once()


def test_fd4ba_correct_policy_is_left_unchanged(mock_tf_service):
    """Negative (Do No Harm): a bucket that already grants only the build SA is not rewritten."""
    bucket = _fd4ba_bucket(bindings=[{"role": "roles/storage.objectViewer", "members": {f"serviceAccount:{_FD4BA_SA}"}}])
    client = MagicMock()
    client.bucket.return_value = bucket
    mock_tf_service._stage_build_source(client, _fd4ba_session(), "child", "child-cloudbuild-source", "o", b"tgz")
    bucket.set_iam_policy.assert_not_called()
    bucket.blob.return_value.upload_from_string.assert_called_once()


def test_fd4ba_new_bucket_uses_platform_region_and_blocks_public_access(mock_tf_service):
    client = MagicMock()
    client.bucket.return_value = _fd4ba_bucket(exists=False)
    created = _fd4ba_bucket(exists=True)
    client.create_bucket.return_value = created
    with patch.object(mock_tf_service, "_resolve_region", return_value="europe-west4"):
        mock_tf_service._stage_build_source(client, _fd4ba_session(), "child", "child-cloudbuild-source", "o", b"tgz")
    new_bucket = client.create_bucket.call_args[0][0]
    assert client.create_bucket.call_args.kwargs == {"project": "child", "location": "europe-west4"}
    assert new_bucket.iam_configuration.public_access_prevention == "enforced"
    assert new_bucket.iam_configuration.uniform_bucket_level_access_enabled is True
    assert _fd4ba_all_members(created) == {f"serviceAccount:{_FD4BA_SA}"}


@pytest.mark.parametrize("status,email", [(403, _FD4BA_SA), (200, ""), (200, "not-an-email")])
def test_fd4ba_unresolved_build_sa_raises_and_grants_nothing(mock_tf_service, status, email):
    bucket = _fd4ba_bucket(bindings=[])
    client = MagicMock()
    client.bucket.return_value = bucket
    with pytest.raises(RuntimeError):
        mock_tf_service._stage_build_source(client, _fd4ba_session(status, email), "child", "child-cloudbuild-source", "o", b"tgz")
    bucket.set_iam_policy.assert_not_called()
    bucket.blob.return_value.upload_from_string.assert_not_called()


def test_fd4ba_resolve_region_never_hardcoded(mock_tf_service):
    # FD-4AL: the setting is read through the server's own Firestore client (system_config/platform_settings).
    snap = MagicMock(exists=True)
    snap.to_dict.return_value = {"orchestration": {"default_gcp_region": "asia-south1"}}
    db = MagicMock()
    db.collection.return_value.document.return_value.get.return_value = snap
    with patch.object(mock_tf_service, "db", db):
        assert mock_tf_service._resolve_region() == "asia-south1"
    db.collection.return_value.document.return_value.get.side_effect = RuntimeError("no firestore")
    with patch.object(mock_tf_service, "db", db), patch.dict(os.environ, {"REGION": "", "DEFAULT_REGION": ""}):
        with pytest.raises(RuntimeError):
            mock_tf_service._resolve_region()


def test_fd4ak_unreadable_settings_fall_through_to_region_env_not_the_compiled_default(mock_tf_service):
    """FD-4AK (rewritten at the FD-4AL merge: the resolver reads through the server's injected Firestore client): an
    unreadable settings document is a typed miss, so the bucket region is $REGION (the install's region), never the
    compile-time default `us-central1`; with no $REGION / $DEFAULT_REGION it still refuses."""
    db = MagicMock()
    db.collection.return_value.document.return_value.get.side_effect = RuntimeError("no firestore")
    with patch.object(mock_tf_service, "db", db), \
         patch.dict(os.environ, {"REGION": "europe-west4", "DEFAULT_REGION": ""}):
        assert mock_tf_service._resolve_region() == "europe-west4"
    with patch.object(mock_tf_service, "db", db), \
         patch.dict(os.environ, {"REGION": "", "DEFAULT_REGION": ""}):
        with pytest.raises(RuntimeError):
            mock_tf_service._resolve_region()
    assert db.collection.return_value.document.return_value.get.call_count == 2


def test_fd4ba_staging_failure_fails_build_without_fallback_upload(mock_tf_service, tmp_path):
    """The old code uploaded the tarball into the platform state bucket when the child bucket failed."""
    ws = tmp_path / "app"
    ws.mkdir()
    (ws / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (ws / "requirements.txt").write_text("fastapi\n")
    client = MagicMock()
    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("google.cloud.storage.Client", return_value=client), \
         patch.object(TerraformService, "_stage_build_source", side_effect=RuntimeError("bucket denied")) as stage:
        ok = mock_tf_service._build_and_push_container("auth-service", "child", str(ws), "img:tag")
    assert ok is False
    stage.assert_called_once()
    assert "bucket denied" in mock_tf_service._last_build_error
    bucket_names = [c[0][0] for c in client.bucket.call_args_list]
    assert mock_tf_service.state_bucket not in bucket_names
    assert not any("tfstate" in name for name in bucket_names)


# ---------------------------------------------------------------------------
# FD-4BA follow-up: the build source tarball is an allow-list; tfvars/state/IaC/keys never ship
# ---------------------------------------------------------------------------
_FD4BA_SECRET = "GOCSPX-fake-oauth-secret-0123456789"


def _fd4ba_write(base, rel, text):
    path = os.path.join(str(base), rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _fd4ba_secret_bait(ws):
    """Every file a deploy workspace can hold that must never reach the build bucket."""
    secret_tfvars = f'oauth_client_secret = "{_FD4BA_SECRET}"\nfirebase_api_key = "{_FD4BA_SECRET}"\n'
    _fd4ba_write(ws, "terraform.tfvars", secret_tfvars)
    _fd4ba_write(ws, "secrets.auto.tfvars.json", f'{{"k": "{_FD4BA_SECRET}"}}')
    _fd4ba_write(ws, "backend.tf", 'terraform {\n  backend "gcs" {}\n}\n')
    _fd4ba_write(ws, "infra/workload/main.tf", f'# {_FD4BA_SECRET}\n')
    _fd4ba_write(ws, "terraform.tfstate", _FD4BA_SECRET)
    _fd4ba_write(ws, "tfplan", _FD4BA_SECRET)
    _fd4ba_write(ws, ".terraform/terraform.tfstate", _FD4BA_SECRET)
    _fd4ba_write(ws, ".env", f"SECRET={_FD4BA_SECRET}\n")


def _fd4ba_capture_tarball(svc, ws):
    """Run _build_and_push_container up to the upload and return (member names, decompressed tar bytes)."""
    import gzip
    import io
    import tarfile
    captured = {}

    def stage(**kwargs):
        captured["payload"] = kwargs["payload"]
        raise RuntimeError("stop after packaging")

    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("google.cloud.storage.Client"), \
         patch.object(TerraformService, "_stage_build_source", side_effect=stage):
        assert svc._build_and_push_container("auth-service", "child", str(ws), "img:tag") is False
    payload = captured["payload"]
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
        names = tar.getnames()
    return names, gzip.decompress(payload)


def _fd4ba_assert_clean(names, raw):
    assert _FD4BA_SECRET.encode() not in raw
    for name in names:
        base = name.rsplit("/", 1)[-1]
        assert not base.endswith((".tfvars", ".tfvars.json", ".tf", ".tfstate", ".pem", ".key")), name
        assert base not in ("tfplan", ".env", "Dockerfile"), name
        assert not name.startswith(("infra/", ".terraform/")), name


def test_fd4ba_tarball_services_mode_ships_only_service_dirs(mock_tf_service, tmp_path):
    ws = tmp_path / "ws"
    _fd4ba_write(ws, "apps/api/main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _fd4ba_write(ws, "apps/api/requirements.txt", "fastapi\n")
    _fd4ba_write(ws, "apps/api/templates/index.html", "<html></html>\n")
    _fd4ba_secret_bait(ws)
    _fd4ba_write(ws, "apps/api/terraform.tfvars", f'x = "{_FD4BA_SECRET}"\n')
    _fd4ba_write(ws, "apps/api/.env.production", f"S={_FD4BA_SECRET}\n")
    _fd4ba_write(ws, "apps/api/server.key", _FD4BA_SECRET)
    os.symlink(os.path.join(str(ws), "terraform.tfvars"), os.path.join(str(ws), "apps", "api", "linked.txt"))

    names, raw = _fd4ba_capture_tarball(mock_tf_service, ws)

    _fd4ba_assert_clean(names, raw)
    assert "apps/api/main.py" in names
    assert "apps/api/templates/index.html" in names
    assert "apps/api/linked.txt" not in names
    root_level = {n for n in names if "/" not in n}
    assert root_level <= {"Procfile", ".python-version", "requirements.txt"}, root_level
    assert all(n.startswith("apps/api/") for n in names if "/" in n), names


def test_fd4ba_tarball_root_mode_ships_only_app_sources(mock_tf_service, tmp_path):
    ws = tmp_path / "ws"
    _fd4ba_write(ws, "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _fd4ba_write(ws, "requirements.txt", "fastapi\n")
    _fd4ba_write(ws, "static/app.js", "console.log(1)\n")
    _fd4ba_secret_bait(ws)

    names, raw = _fd4ba_capture_tarball(mock_tf_service, ws)

    _fd4ba_assert_clean(names, raw)
    assert {"main.py", "requirements.txt", "static/app.js"} <= set(names)
    assert "terraform.tfvars" not in names


def test_fd4ba_allow_list_fails_closed_when_nothing_buildable(tmp_path):
    from service import select_build_source_files
    ws = tmp_path / "ws"
    _fd4ba_secret_bait(ws)
    _fd4ba_write(ws, "apps/api/terraform.tfvars", "x = 1\n")
    with pytest.raises(RuntimeError):
        select_build_source_files(str(ws), [])
    with pytest.raises(RuntimeError):
        select_build_source_files(str(ws), ["api"])
    with pytest.raises(RuntimeError):
        select_build_source_files(str(ws), ["missing"])



# ---------------------------------------------------------------------------
# Code red-team fixes (Fable): F-4 bounded pre-flight wait, F-5 drift downgrade gate,
# F-6 per-call build error, F-7 path product_id validation
# ---------------------------------------------------------------------------
class _FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class _ReleasingBucket(_FakeBucket):
    """Lock object present for the first `held_reads` reads, then released."""

    def __init__(self, objects, held_reads):
        super().__init__(objects)
        self.lock_reads = 0
        self.held_reads = held_reads

    def get_blob(self, name, **kwargs):
        if name.endswith("default.tflock"):
            self.lock_reads += 1
            if self.lock_reads > self.held_reads:
                return None
        return super().get_blob(name, **kwargs)


@pytest.mark.parametrize("raw,seconds", [("180s", 180.0), ("3m", 180.0), ("1h", 3600.0), ("45", 45.0), ("0s", 0.0), ("bogus", 180.0)])
def test_f4_lock_timeout_parsing(mock_tf_service, raw, seconds):
    mock_tf_service.lock_timeout = raw
    assert mock_tf_service._lock_timeout_seconds() == seconds


def test_f4_preflight_waits_for_transient_lock_then_deploys(tmp_path):
    """A transient plan/drift lock released within -lock-timeout must not fail the deploy (tofu would have waited)."""
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=MagicMock())
    svc.lock_timeout = "180s"
    bucket = _ReleasingBucket({"workloads/testapp/default.tflock": _fd4h_lock_object(age_seconds=2)}, held_reads=2)
    clock = _FakeClock()
    fake, calls = _fd4h_recording_run([])
    with _fd4h_deploy_env(_fd4h_workspace(tmp_path), fake, _fake_storage_client(bucket)), \
         patch("time.monotonic", clock.monotonic), patch("time.sleep", clock.sleep):
        res = svc.deploy_workload(product_id="testapp", trace_id="t1", hcl_files={"main.tf": "# x"},
                                  target_project_id="child-123")
    assert res["status"] == "SUCCESS"
    assert clock.sleeps == [5.0, 5.0]
    assert bucket.writes == []
    assert not any(c[1] == "force-unlock" for c in calls)


def test_f4_preflight_held_lock_fails_after_exactly_lock_timeout(tmp_path):
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=MagicMock())
    svc.lock_timeout = "12s"
    bucket = _FakeBucket({"workloads/testapp/default.tflock": _fd4h_lock_object(age_seconds=30)})
    clock = _FakeClock()
    fake, calls = _fd4h_recording_run([])
    with _fd4h_deploy_env(_fd4h_workspace(tmp_path), fake, _fake_storage_client(bucket)), \
         patch("time.monotonic", clock.monotonic), patch("time.sleep", clock.sleep):
        res = svc.deploy_workload(product_id="testapp", trace_id="t1", hcl_files={"main.tf": "# x"},
                                  target_project_id="child-123")
    assert clock.sleeps == [5.0, 5.0, 2.0]
    assert sum(clock.sleeps) == 12.0
    assert res["error_class"] == "STATE_LOCKED"
    assert calls == []
    assert bucket.writes == []


def test_f5_check_drift_runs_engine_downgrade_gate(mock_tf_service):
    from service import IaCEngineDowngradeBlockedError
    _fd4ao_workspace(mock_tf_service, with_plan=False)
    with patch.object(mock_tf_service, "_validate_no_engine_downgrade",
                      side_effect=IaCEngineDowngradeBlockedError("tofu state")) as gate, \
         patch.object(mock_tf_service, "_run_subprocess") as sub:
        with pytest.raises(IaCEngineDowngradeBlockedError):
            mock_tf_service.check_drift("auth-service", "trace-ap", iac_engine="TERRAFORM")
    gate.assert_called_once_with("auth-service", "TERRAFORM")
    sub.assert_not_called()


def test_f6_build_error_is_per_thread_not_shared(mock_tf_service):
    import threading
    seen = {}
    barrier = threading.Barrier(2)

    def worker(name):
        mock_tf_service._last_build_error = f"reason-{name}"
        barrier.wait()
        seen[name] = mock_tf_service._last_build_error

    threads = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert seen == {"a": "reason-a", "b": "reason-b"}
    assert mock_tf_service._last_build_error is None


def test_f7_force_unlock_path_product_id_validated():
    if not TestClient or not app:
        return
    import main as tf_main
    client = TestClient(app)
    with patch.object(tf_main.service, "force_unlock", return_value={"status": "UNLOCKED"}) as fu:
        r = client.post("/api/workloads/%2E%2E/force-unlock", json={"product_id": "", "lock_id": "1"})
        assert r.status_code in (400, 404), r.text
        fu.assert_not_called()

# ---------------------------------------------------------------------------
# Lane 8 pre-merge asks on this file: code-RT F4 (`random` in the provider-mirror include) and
# register row 7 production reach (engine binary present before prepare_workspace's steps; the row 7 healer itself
# was deleted by FD-55 W6b)
# ---------------------------------------------------------------------------
_L8_MANIFEST = {
    "main.tf": 'resource "google_storage_bucket" "b" {\n  name     = "x"\n  location = "US"\n}\n',
}


def _l8_service_module():
    return sys.modules[TerraformService.__module__]


def _l8_rc_include(rc_text):
    body = rc_text.split("include = [", 1)[1].split("]", 1)[0]
    return [line.strip().strip(",").strip('"') for line in body.splitlines() if line.strip()]


def test_f4_mirror_include_lists_random_for_both_registries(mock_tf_service):
    """F4: `random` is pre-cached into the mirror, so the CLI config must list it like google/google-beta;
    every included provider has a pre-cache directory in the mirror (no include without a cache entry)."""
    with patch("binary_checksums.fetch_to", side_effect=OSError("offline test")) as fetch:  # FD-4BQ fetch primitive
        rc_path = mock_tf_service._ensure_provider_mirror()
    with open(rc_path) as fh:
        rc_text = fh.read()
    include = _l8_rc_include(rc_text)
    # FD-4AQ W1b: exactly the 4 platform providers on both registry hosts (kubernetes was pre-cached but not listed)
    assert include == [
        "registry.opentofu.org/hashicorp/google",
        "registry.opentofu.org/hashicorp/google-beta",
        "registry.opentofu.org/hashicorp/kubernetes",
        "registry.opentofu.org/hashicorp/random",
        "registry.terraform.io/hashicorp/google",
        "registry.terraform.io/hashicorp/google-beta",
        "registry.terraform.io/hashicorp/kubernetes",
        "registry.terraform.io/hashicorp/random",
    ]
    mirror_dir = os.path.join(mock_tf_service.tooling_dir, "plugin_mirror")
    assert f'path = "{mirror_dir}"' in rc_text
    for entry in include:
        assert os.path.isdir(os.path.join(mirror_dir, entry)), entry
    # FD-4AQ W1b: the registry fallback carries the same exact include list (no unrestricted `direct {}`)
    assert "direct {}" not in rc_text
    assert _l8_rc_include(rc_text.split("direct {", 1)[1]) == include
    assert fetch.called  # pre-cache attempted (and failed offline) exactly as before; the rc is still written


def test_row7_prepare_workspace_ensures_binary_once_before_the_workspace_steps(mock_tf_service):
    """Register row 7's orphaned-syntax healer (the reason for this early ensure) was deleted by FD-55 W6b; the early
    ensure stays (a forbidden engine version still fails before any file is written). The marker is the stale-module
    report, prepare_workspace's last step."""
    events = []
    real_stale = _l8_service_module().stale_vendored_module_files

    def fake_ensure(engine="TERRAFORM", version=None):
        events.append(("ensure", engine))
        return "/fake/bin/tofu"

    def recording_stale(ws):
        events.append(("stale_check", None))
        return real_stale(ws)

    mock_tf_service.db = None
    with patch.object(mock_tf_service, "_ensure_binary", side_effect=fake_ensure), \
         patch.object(_l8_service_module(), "stale_vendored_module_files", side_effect=recording_stale):
        mock_tf_service.prepare_workspace("row7-app", "t-row7", dict(_L8_MANIFEST), iac_engine="OPENTOFU")
    assert events[0] == ("ensure", "OPENTOFU")
    assert events.count(("ensure", "OPENTOFU")) == 1 and len([e for e in events if e[0] == "ensure"]) == 1
    assert ("stale_check", None) in events


def test_row7_prepare_workspace_without_engine_never_ensures(mock_tf_service):
    """Direct callers/tests that pass no engine: unchanged (no binary lookup, no fetch)."""
    mock_tf_service.db = None
    with patch.object(mock_tf_service, "_ensure_binary") as ens:
        mock_tf_service.prepare_workspace("row7-app", "t-row7", dict(_L8_MANIFEST))
    ens.assert_not_called()


def test_row7_generate_plan_cold_path_ensures_before_the_workspace_steps_and_init(mock_tf_service):
    events = []
    real_stale = _l8_service_module().stale_vendored_module_files

    def fake_ensure(engine="TERRAFORM", version=None):
        events.append(("ensure", engine))
        return "/fake/bin/tofu"

    def recording_stale(ws):
        events.append(("stale_check", None))
        return real_stale(ws)

    def fake_run(cmd, *a, **k):
        events.append(("run", cmd[1]))
        return _fd4ao_ok("{}" if cmd[1] in ("validate", "show") else "")

    mock_tf_service.db = None
    with patch.object(mock_tf_service, "_ensure_binary", side_effect=fake_ensure), \
         patch.object(mock_tf_service, "_run_subprocess", side_effect=fake_run), \
         patch.object(_l8_service_module(), "stale_vendored_module_files", side_effect=recording_stale):
        mock_tf_service.generate_plan("row7-app", "t-row7", dict(_L8_MANIFEST), iac_engine="OPENTOFU")
    kinds = [e[0] for e in events]
    assert events[0] == ("ensure", "OPENTOFU")
    assert kinds.count("ensure") == 1
    assert kinds.index("ensure") < kinds.index("stale_check") < kinds.index("run")


def test_row7_deploy_workload_passes_resolved_engine_to_prepare_workspace(tmp_path):
    """deploy_workload hands the engine it resolved from Firestore (not None) to prepare_workspace."""
    db = MagicMock()
    db.collection.return_value.document.return_value.get.return_value.exists = True
    db.collection.return_value.document.return_value.get.return_value.to_dict.return_value = {
        "project_id": "child-123", "iac_engine": "TERRAFORM",
    }
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=db)
    svc.lock_timeout = "0s"
    seen = {}
    ws = _fd4h_workspace(tmp_path)

    def recording_prepare(self, product_id, trace_id, hcl_files, iac_engine=None, region=None):
        seen["iac_engine"] = iac_engine
        return ws

    fake, _calls = _fd4h_recording_run([])
    with _fd4h_deploy_env(ws, fake, MagicMock(side_effect=RuntimeError("no creds"))), \
         patch.object(TerraformService, "_validate_no_engine_downgrade"), \
         patch.object(TerraformService, "prepare_workspace", recording_prepare):
        svc.deploy_workload(product_id="testapp", trace_id="t1", hcl_files={"main.tf": "# x"},
                            target_project_id="child-123")
    assert seen["iac_engine"] == "TERRAFORM"


def test_row7_binary_already_cached_no_download_and_workspace_identical(mock_tf_service, monkeypatch):
    """Do No Harm: with the binary already verified in this process (RT14-22: a verified engine, recorded by path +
    stat signature), the early call downloads nothing and the prepared workspace is byte-identical to the no-engine
    call."""
    monkeypatch.setenv("OPENTOFU_VERSION", "1.9.0")
    cached = os.path.join(mock_tf_service.tooling_dir, "bin", "tofu_1.9.0")
    os.makedirs(os.path.dirname(cached), exist_ok=True)
    with open(cached, "w") as fh:
        fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(cached, 0o755)
    st = os.stat(cached)
    mock_tf_service._verified_engines = {("opentofu", "1.9.0"): (cached, (st.st_ino, st.st_size, st.st_mtime_ns))}
    mock_tf_service.db = None
    svc_mod = _l8_service_module()

    def files_of(ws):
        out = {}
        for root, _dirs, names in os.walk(ws):
            for n in names:
                p = os.path.join(root, n)
                if os.path.isfile(p) and not os.path.islink(p):
                    with open(p, "rb") as fh:
                        out[os.path.relpath(p, ws)] = fh.read()
        return out

    with patch.object(svc_mod.shutil, "which", return_value=None), \
         patch.object(svc_mod._binary_checksums_module(), "fetch_to",
                      side_effect=AssertionError("must not download")) as fetch, \
         patch.object(mock_tf_service, "_ensure_binary", wraps=mock_tf_service._ensure_binary) as ens:
        ws_with = mock_tf_service.prepare_workspace("row7-app", "t-with", dict(_L8_MANIFEST), iac_engine="OPENTOFU")
        ws_without = mock_tf_service.prepare_workspace("row7-app", "t-without", dict(_L8_MANIFEST))
    fetch.assert_not_called()
    assert ens.call_count == 1 and ens.return_value is not None
    assert files_of(ws_with) == files_of(ws_without)


def test_row7_failed_download_fails_typed_before_writing(mock_tf_service, monkeypatch):
    """RT14-22: cold job, download fails: the call raises the typed EngineUnverifiable (it used to return the bare
    name, so a PATH binary or nothing ran later). Raised before any workspace write; one fetch attempt."""
    monkeypatch.setenv("OPENTOFU_VERSION", "1.9.0")
    mock_tf_service.db = None
    svc_mod = _l8_service_module()
    with patch.object(svc_mod.shutil, "which", return_value="/usr/local/bin/tofu"), \
         patch.object(svc_mod._binary_checksums_module(), "fetch_to", side_effect=OSError("offline")) as fetch, \
         patch.object(mock_tf_service, "_ensure_binary", wraps=mock_tf_service._ensure_binary) as ens:
        with pytest.raises(svc_mod.EngineUnverifiable) as ei:
            mock_tf_service.prepare_workspace("row7-app", "t-cold", dict(_L8_MANIFEST), iac_engine="OPENTOFU")
    assert ei.value.error_class == "ENGINE_UNVERIFIABLE" and "OSError" in str(ei.value)
    assert not os.path.exists(os.path.join(mock_tf_service.workspace_root, "t-cold"))
    assert fetch.call_count == 1
    assert ens.call_count == 1


def test_row7_forbidden_terraform_version_fails_closed_before_writing(mock_tf_service, monkeypatch, tmp_path):
    """Same error the first `_run_subprocess` would raise (BSL ceiling), raised before any workspace write."""
    monkeypatch.setenv("TERRAFORM_VERSION", "1.6.0")
    mock_tf_service.db = None
    with pytest.raises(ValueError) as direct:
        mock_tf_service._ensure_binary("TERRAFORM")
    with pytest.raises(ValueError) as early:
        mock_tf_service.prepare_workspace("row7-app", "t-bsl", dict(_L8_MANIFEST), iac_engine="TERRAFORM")
    assert str(early.value) == str(direct.value)
    assert not os.path.exists(os.path.join(mock_tf_service.workspace_root, "t-bsl"))



# ---------------------------------------------------------------------------
# Lane 11 code RT F1 / F2: platform IPAM facts reach the apply; prepare_workspace never invents variable defaults
# ---------------------------------------------------------------------------
def _l11_platform_facts():
    """The gateway's platform_facts module, loaded by path (its renders need only pydantic + ipaddress)."""
    import importlib.util
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "apps", "orchestrator-gateway",
                                        "developer_agent", "platform_facts.py"))
    spec = importlib.util.spec_from_file_location("l11_platform_facts_for_tf_tests", path)
    mod = sys.modules.get(spec.name)
    if mod is None:
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod   # dataclasses resolve their module through sys.modules
        spec.loader.exec_module(mod)
    return mod


def _l11_fact_files():
    pf = _l11_platform_facts()
    facts = pf.NetworkFacts(product_id="testapp", region="us-central1", subnet_cidr="10.100.0.0/24",
                            connector_cidr="10.100.1.0/28")
    variables = ('variable "project_id" {\n  type = string\n}\n\nvariable "region" {\n  type    = string\n'
                 '  default = "us-central1"\n}\n\nvariable "additional_apis" {\n  type    = list(string)\n'
                 '  default = []\n}\n' + pf.render_fact_variables(facts))
    # Code RT 2 G2: runtime keys collide with the developer file, so the merge precedence is exercised (mutant M-b)
    tfvars = ('additional_apis            = ["vpcaccess.googleapis.com"]\n'
              'project_id                 = "not-the-child"\n'
              'github_repo_full_name      = "evil/repo"\n'
              'container_image            = "evil/image:latest"\n'
              + "\n".join(pf.render_fact_tfvars(facts)) + "\n")
    custom = ('resource "google_compute_subnetwork" "app" {\n  name          = "testapp-subnet"\n'
              '  ip_cidr_range = var.subnet_cidr\n  region        = var.region\n  network       = "testapp-vpc"\n}\n')
    return variables, tfvars, custom


# FD-4D (R04-1): deploy_workload refuses a workload without a root main.tf, so the lane-11 fixture carries one.
_L11_MAIN_TF = 'terraform {\n  required_version = ">= 1.6.0"\n}\n'


@contextlib.contextmanager
def _l11_deploy_env(fake_run):
    """FD-4H hermetic deploy env, except that the REAL prepare_workspace runs (spied, to find the workspace)."""
    real_prepare = TerraformService.prepare_workspace
    seen = {}

    def spy(self, *a, **k):
        seen["ws"] = real_prepare(self, *a, **k)
        return seen["ws"]

    with patch("shutil.which", return_value="/usr/local/bin/tofu"), \
         patch.object(TerraformService, "prepare_workspace", spy), \
         patch.object(TerraformService, "_build_and_push_container", return_value=True), \
         patch.object(TerraformService, "_ensure_provider_mirror"), \
         patch.object(TerraformService, "_run_subprocess", fake_run), \
         patch.object(TerraformService, "_fetch_repo_files", return_value={}), \
         patch("google.cloud.storage.Client", _fake_storage_client(_FakeBucket({}))), \
         patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("httpx.Client"):
        yield seen


def _l11_read_tfvars_keys(path):
    with open(path, "r", encoding="utf-8") as fh:
        return {line.split("=", 1)[0].strip(): line.split("=", 1)[1].strip()
                for line in fh.read().splitlines() if "=" in line}


def _l11_tofu():
    import shutil as _sh
    return _sh.which("tofu") or ("/opt/homebrew/bin/tofu" if os.path.exists("/opt/homebrew/bin/tofu") else None)


def _l11_tofu_run(tofu, cwd, *args):
    import subprocess
    env = dict(os.environ, TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1", TF_INPUT="0")
    return subprocess.run([tofu, *args], cwd=cwd, capture_output=True, text=True, timeout=120, env=env)


def test_lane11_fact_values_reach_the_root_tfvars_tf_applier_reads(tmp_path):
    """Code RT F1 (E3 inverted), through the real deploy_workload + real prepare_workspace: the developer's
    infra/workload/terraform.tfvars keys (the IPAM facts, which have no default, and additional_apis) are in the root
    terraform.tfvars that tofu reads; the runtime keys still win."""
    variables, tfvars, custom = _l11_fact_files()
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=MagicMock())
    fake, calls = _fd4h_recording_run([])
    hcl = {"infra/workload/variables.tf": variables, "infra/workload/terraform.tfvars": tfvars,
           "infra/workload/custom.tf": custom, "infra/workload/main.tf": _L11_MAIN_TF}
    with _l11_deploy_env(fake) as seen:
        res = svc.deploy_workload(product_id="testapp", trace_id="t-l11", hcl_files=hcl,
                                  target_project_id="child-123")
    assert res["status"] == "SUCCESS", res
    root = _l11_read_tfvars_keys(os.path.join(seen["ws"], "terraform.tfvars"))
    assert root["subnet_cidr"] == '"10.100.0.0/24"' and root["connector_cidr"] == '"10.100.1.0/28"'
    assert root["additional_apis"] == '["vpcaccess.googleapis.com"]'
    assert root["project_id"] == '"child-123"' and root["product_id"] == '"testapp"'   # runtime keys win
    # Code RT 2 G2: the fixture's colliding keys lose to the runtime values (WIF trust, deployed image)
    import service as _service
    _, _, runtime_repo = _service.resolve_repo_identity(None, product_id="testapp")
    assert root["github_repo_full_name"] == f'"{runtime_repo}"' != '"evil/repo"'
    assert root["container_image"] == '""'   # no compute module here: the runtime deployed_image is empty
    assert any(c[1] == "apply" for c in calls)
    # the platform's fact declarations reached the root module untouched (no injected default: F2); deploy_workload
    # appends its own platform variables after them
    pf = _l11_platform_facts()
    render = pf.render_fact_variables(pf.NetworkFacts(product_id="testapp", region="us-central1",
                                                      subnet_cidr="10.100.0.0/24", connector_cidr="10.100.1.0/28"))
    with open(os.path.join(seen["ws"], "variables.tf"), "r", encoding="utf-8") as fh:
        assert render.rstrip("\n") in fh.read()


def _fd4atc_deploy_root_tfvars(tmp_path, workload_doc):
    """The real deploy_workload + prepare_workspace with a Firestore workload doc; returns the root tfvars keys."""
    variables, tfvars, custom = _l11_fact_files()
    db = MagicMock()
    doc = MagicMock()
    doc.exists = True
    doc.to_dict.return_value = dict(workload_doc)
    db.collection.return_value.document.return_value.get.return_value = doc
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=db)
    fake, _calls = _fd4h_recording_run([])
    hcl = {"infra/workload/variables.tf": variables, "infra/workload/terraform.tfvars": tfvars,
           "infra/workload/custom.tf": custom, "infra/workload/main.tf": _L11_MAIN_TF}
    with _l11_deploy_env(fake) as seen:
        res = svc.deploy_workload(product_id="testapp", trace_id="t-fd4atc", hcl_files=hcl,
                                  target_project_id="child-123")
    assert res["status"] == "SUCCESS", res
    return _l11_read_tfvars_keys(os.path.join(seen["ws"], "terraform.tfvars"))


def test_fd4at_c_vend_time_repository_id_reaches_the_root_tfvars(tmp_path):
    """FD-4AT-c: the vend-time record for the repository being applied puts github_repository_id in the root
    terraform.tfvars (the generated root forwards it to the workload-foundation WIF condition)."""
    root = _fd4atc_deploy_root_tfvars(tmp_path, {
        "github_repo": "acme/castor-testapp",
        "github_repository_identity": {"full_name": "Acme/Castor-TestApp", "repository_id": "987654321"},
    })
    assert root["github_repo_full_name"] == '"acme/castor-testapp"'
    assert root["github_repository_id"] == '"987654321"'


@pytest.mark.parametrize("record", [
    None,                                                                       # vended before FD-4AT-c
    {"full_name": "acme/other-repo", "repository_id": "987654321"},             # recorded for another repository
    {"full_name": "acme/castor-testapp", "repository_id": None},                # unreadable at vend time
    {"full_name": "acme/castor-testapp", "repository_id": "98' || true || '"},  # not GitHub's digits-only id
])
def test_fd4at_c_no_matching_record_leaves_the_condition_unpinned(tmp_path, record):
    """Do No Harm: without a valid record for this exact repository no github_repository_id key is written, so the
    root default ("") keeps the FD-4AT condition byte for byte."""
    doc = {"github_repo": "acme/castor-testapp"}
    if record is not None:
        doc["github_repository_identity"] = record
    root = _fd4atc_deploy_root_tfvars(tmp_path, doc)
    assert root["github_repo_full_name"] == '"acme/castor-testapp"'
    assert "github_repository_id" not in root


def _r1_wif_root_tfvars_text(tmp_path, branch):
    """FD-4CI-b-R1-WIF: (root tfvars keys, exact root terraform.tfvars bytes) for a workload record whose
    default_branch is `branch` (None = no field)."""
    import glob
    doc = {"github_repo": "acme/castor-testapp",
           "github_repository_identity": {"full_name": "acme/castor-testapp", "repository_id": "987654321"}}
    if branch is not None:
        doc["default_branch"] = branch
    keys = _fd4atc_deploy_root_tfvars(tmp_path, doc)
    (path,) = glob.glob(os.path.join(str(tmp_path), "t-fd4atc", "testapp", "terraform.tfvars"))
    with open(path, "rb") as fh:
        return keys, fh.read()


# sha256 of the root terraform.tfvars this fixture produced at the base (before FD-4CI-b-R1-WIF), for every record.
_R1_WIF_BASE_ROOT_TFVARS_SHA256 = "513f770dbeab224c33139e1cb4a0f45f73faddf7809350b32f8ff373134d4d1d"


@pytest.mark.parametrize("branch", ["develop", "release/v1.2_rc-1"])
def test_r1_wif_recorded_branch_reaches_the_root_tfvars(tmp_path, branch):
    """FD-4CI-b-R1-WIF: the record's plain default branch (other than main) is the root's github_default_branch (the
    generated root forwards it to the workload-foundation WIF condition); nothing else in the tfvars changes."""
    import hashlib
    keys, text = _r1_wif_root_tfvars_text(tmp_path, branch)
    assert keys["github_default_branch"] == f'"{branch}"'
    assert keys["github_repository_id"] == '"987654321"'
    line = f'github_default_branch = "{branch}"\n'.encode()
    assert text.count(line) == 1
    assert hashlib.sha256(text.replace(line, b"", 1)).hexdigest() == _R1_WIF_BASE_ROOT_TFVARS_SHA256


@pytest.mark.parametrize("branch", [
    None,                    # a workload from before branches were recorded
    "main",                  # the module default
    "",                      # empty
    "bad branch",            # not a plain branch name
    "main' || true || '",    # CEL quote injection
    "feature/*",             # wildcard
    "HEAD",
    7,                       # not a string
])
def test_r1_wif_no_key_and_byte_identical_tfvars_without_a_plain_non_main_branch(tmp_path, branch):
    """Do No Harm / never widen: no github_default_branch key, and the root tfvars are byte-identical to the base."""
    import hashlib
    keys, text = _r1_wif_root_tfvars_text(tmp_path, branch)
    assert "github_default_branch" not in keys
    assert hashlib.sha256(text).hexdigest() == _R1_WIF_BASE_ROOT_TFVARS_SHA256


def test_r1_wif_recorded_wif_branch_accepts_only_a_plain_non_main_branch():
    """recorded_wif_branch: the record's value as written, or None (no key); never rewritten."""
    import service as _service
    assert _service.recorded_wif_branch("develop") == "develop"
    for v in (None, "main", "", "a..b", ["develop"]):
        assert _service.recorded_wif_branch(v) is None


def test_lane11_root_tfvars_satisfies_tofu_plan_offline(tmp_path):
    """Code RT F1, engine check (local tofu, no providers, no backend, no network): the root module deploy_workload
    leaves plans with the fact values; the same root without the developer's tfvars keys (the pre-fix merge) fails
    with the missing-variable error, so the check is not vacuous."""
    tofu = _l11_tofu()
    if not tofu:
        pytest.skip("needs a local tofu")
    variables, tfvars, custom = _l11_fact_files()
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path / "w"),
                           firestore_client=MagicMock())
    fake, _calls = _fd4h_recording_run([])
    with _l11_deploy_env(fake) as seen:
        svc.deploy_workload(product_id="testapp", trace_id="t-l11p", hcl_files={
            "infra/workload/variables.tf": variables, "infra/workload/terraform.tfvars": tfvars,
            "infra/workload/custom.tf": custom, "infra/workload/main.tf": _L11_MAIN_TF},
            target_project_id="child-123")
    probe = 'output "subnet" {\n  value = var.subnet_cidr\n}\n\noutput "connector" {\n  value = var.connector_cidr\n}\n'
    for name, keep_dev_keys in (("fixed", True), ("pre_fix", False)):
        d = tmp_path / name
        d.mkdir()
        shutil.copy(os.path.join(seen["ws"], "variables.tf"), d / "variables.tf")
        (d / "probe.tf").write_text(probe)
        root = _l11_read_tfvars_keys(os.path.join(seen["ws"], "terraform.tfvars"))
        if not keep_dev_keys:
            root = {k: v for k, v in root.items() if k not in ("subnet_cidr", "connector_cidr", "additional_apis")}
        (d / "terraform.tfvars").write_text("".join(f"{k} = {v}\n" for k, v in root.items()))
        init = _l11_tofu_run(tofu, str(d), "init", "-input=false", "-no-color", "-backend=false")
        assert init.returncode == 0, init.stderr
        plan = _l11_tofu_run(tofu, str(d), "plan", "-input=false", "-no-color", "-refresh=false")
        if keep_dev_keys:
            assert plan.returncode == 0, plan.stderr
            assert 'subnet    = "10.100.0.0/24"' in plan.stdout and 'connector = "10.100.1.0/28"' in plan.stdout
        else:
            assert plan.returncode != 0 and "No value for required variable" in plan.stderr, plan.stderr


def test_lane11_prepare_workspace_keeps_variable_declarations_byte_identical(mock_tf_service):
    """Code RT F2 (E4 inverted): the rendered fact declarations (nested validation{}, no default), an object()-typed
    variable and a validation-bearing variable pass through the real prepare_workspace byte-identical, and nothing
    is appended (the deleted _ensure_default injected `default = "10.10.0.0/24"` inside validation{})."""
    variables, _tfvars, custom = _l11_fact_files()
    extra = ('variable "cfg" {\n  type = object({\n    a = string\n  })\n}\n\nvariable "tier" {\n  type = string\n'
             '  validation {\n    condition     = contains(["a", "b"], var.tier)\n    error_message = "a or b"\n  }\n}\n')
    ws = mock_tf_service.prepare_workspace("testapp", "t2", {"variables.tf": variables, "extra.tf": extra,
                                                             "custom.tf": custom})
    for name, text in (("variables.tf", variables), ("extra.tf", extra)):
        with open(os.path.join(ws, name), "r", encoding="utf-8") as fh:
            # byte-identical except the final newline, which the pre-existing whole-file sanitizer ("Auto-sanitized
            # Terraform configuration", FD-4Z scope) trims on every root .tf
            assert fh.read().rstrip("\n") == text.rstrip("\n"), name
    tofu = _l11_tofu()
    if tofu:   # the prepared declarations are valid HCL for the engine (no providers needed for variables)
        d = os.path.join(ws, "_l11_validate")
        os.makedirs(d)
        shutil.copy(os.path.join(ws, "variables.tf"), d)
        shutil.copy(os.path.join(ws, "extra.tf"), d)
        assert _l11_tofu_run(tofu, d, "init", "-input=false", "-no-color", "-backend=false").returncode == 0
        val = _l11_tofu_run(tofu, d, "validate", "-no-color")
        assert val.returncode == 0, val.stderr


def test_lane11_tombstone_ensure_default_is_gone_and_no_cidr_is_invented():
    """Code RT F2 tombstones: prepare_workspace has no nested default-injecting healer, and no variable value is
    guessed from a CIDR-like name (FD-55 W6c: generate_rfc1123_variable_default itself is deleted)."""
    import ast
    import inspect
    import service as _svc_mod
    module = ast.parse(inspect.getsource(_svc_mod))
    [cls] = [n for n in module.body if isinstance(n, ast.ClassDef) and n.name == "TerraformService"]
    [prep] = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "prepare_workspace"]
    assert "_ensure_default" not in {n.name for n in ast.walk(prep) if isinstance(n, ast.FunctionDef)}
    assert not hasattr(_svc_mod, "generate_rfc1123_variable_default")


class _MainCaplog(logging.Handler):
    """Script-mode stand-in for pytest's caplog fixture (W6bd review F3): records every log record it sees."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []
        logging.getLogger().addHandler(self)

    def emit(self, record):
        self.records.append(record)

    def set_level(self, level, logger=None):
        logging.getLogger(logger).setLevel(level)


if __name__ == "__main__":
    import tempfile
    import pathlib
    print("Running mcp-servers/terraform/test_service.py unit tests...")
    with tempfile.TemporaryDirectory() as td:
        tf_svc = mock_tf_service(pathlib.Path(td))
        test_builtin_modules_payload_compute_cloudrun_parity()
        test_prepare_workspace_reports_a_stale_golden_module_and_applies_it_as_committed(tf_svc, _MainCaplog())
        test_rollout_sets_exactly_the_given_image_even_when_the_current_one_names_the_service(tf_svc)
        test_rollout_injects_container_deploy_nonce(tf_svc)
        test_buildpack_scaffold_stub_quarantine()
        test_sanitize_wheel_requirements_starlette_bom()
        test_prepare_workspace_adds_no_database_url_for_cloud_sql(tf_svc)
        test_prepare_workspace_keeps_an_explicit_database_url(tf_svc)
        test_prepare_workspace_keeps_a_module_compute_service_name_collision_as_committed(tf_svc)
        test_apply_time_text_healers_are_deleted()
        test_deploy_workload_shift_left_no_longer_heals_undeclared_cloud_run(tf_svc)
        test_extract_apis_detects_gke_from_golden_module()
        test_extract_apis_detects_gke_from_k8s_manifests()
        test_extract_apis_pure_cloud_run_no_gke()
        test_extract_apis_has_no_run_firestore_default()
        test_extract_apis_detects_service_networking()
        test_sanitize_wheel_requirements_relaxes_numpy()
        test_sanitize_wheel_requirements_relaxes_scipy_pandas()
        test_sanitize_wheel_requirements_preserves_unrelated_packages()
        test_disambiguate_services_skips_redundant_hyphen_alias()
        test_sanitize_wheel_requirements_applies_central_bom_overrides()
        test_is_cloud_capacity_stockout()
        test_purge_errored_child_stubs_guardrails()
        test_render_main_tf_gke_autopilot_wires_kubernetes_provider()
        test_deploy_workload_applies_a_gke_workload_as_committed(tf_svc)
        test_run_subprocess_stubs_kubernetes_provider_during_foundational_import(tf_svc)
        test_run_subprocess_does_not_stub_k8s_for_kubernetes_import(tf_svc)
        print("ALL TESTS PASSED!")






# ------------------------------------------------------------------ lane 10 RT F3: Layer 3b skipped on a topology workspace
_L10_GKE_MAIN = """
terraform {
  required_version = ">= 1.5.0"
}

module "compute" {
  source = "../modules/compute-gke-autopilot"
}
"""
_L10_TOPOLOGY = json.dumps({"schema": "service_topology/v1", "sha256": "0" * 64, "intent": {
    "services": [{"name": "stream-processor", "kind": "gke-autopilot"}, {"name": "edge-gateway", "kind": "cloudrun"}],
    "primary_service": "stream-processor", "edges": [], "resources": []}})


def _l10_layer3b_custom_tf(svc, with_topology):
    repo_files = {"infra/workload/main.tf": _L10_GKE_MAIN, "infra/workload/custom.tf": "",
                  "apps/stream-processor/main.py": "x = 1\n"}
    if with_topology is not None:
        repo_files["infra/workload/topology.json"] = with_topology
    with patch("google.cloud.storage.Client"), \
         patch("google.cloud.secretmanager.SecretManagerServiceClient"), \
         patch.object(svc, "_fetch_repo_files", return_value=repo_files), \
         patch.object(svc, "_build_and_push_container", return_value=True), \
         patch.object(svc, "_ensure_binary", return_value="tofu"), \
         patch.object(svc, "_run_subprocess") as mock_sub:
        mock_sub.side_effect = [{"success": True, "stdout": "", "stderr": "", "exit_code": 0}] * 4 + [
            {"success": True, "stdout": json.dumps({}), "stderr": "", "exit_code": 0}] * 4
        svc.deploy_workload("test-05-omni-fleet", "trace-l10-3b")
        workspace_dir = mock_sub.call_args_list[0][1]["cwd"]
    path = os.path.join(workspace_dir, "custom.tf")
    return open(path).read() if os.path.exists(path) else ""


def test_lane10_f3_layer3b_skipped_when_the_workspace_has_a_service_topology(mock_tf_service):
    assert 'module "compute_stream_processor"' not in _l10_layer3b_custom_tf(mock_tf_service, _L10_TOPOLOGY)


@pytest.mark.parametrize("topology", [None, "{not json", json.dumps({"schema": "other/v1", "intent": {}}),
                                      json.dumps({"schema": "service_topology/v1", "intent": []})],
                         ids=["absent", "unparseable", "other-schema", "intent-not-object"])
def test_w6e_layer3b_never_synthesizes_compute_without_a_topology(mock_tf_service, topology):
    """FD55-W6e (A43, Layer 3b DELETED): no (valid) topology.json -> still no synthetic Cloud Run module; the
    committed (empty) custom.tf reaches the workspace unchanged."""
    assert _l10_layer3b_custom_tf(mock_tf_service, topology) == ""


# ------------------------------------------------------------------ lane 19 (FD-4I) RT R1: access keys default closed
_L19_REF_MAIN = (
    'resource "google_cloud_run_v2_service_iam_member" "x" {\n'
    '  count    = var.allow_unauthenticated ? 1 : 0\n'
    '  name     = var.enable_direct_iap ? "a" : "b"\n'
    '  member   = join(",", var.authorized_invoker_members)\n'
    '  role     = var.enable_logging ? "r" : "s"\n'
    '}\n')


def _l19_root_variables(svc, files):
    ws = svc.prepare_workspace("l19-r1", "trace-l19-r1", files)
    with open(os.path.join(ws, "variables.tf")) as fh:
        return fh.read()


def test_lane19_r1_undeclared_access_vars_are_not_declared_at_apply(tf_svc):
    """FD-55 W6a (register FD55-W6a, A9 DELETED): prepare_workspace no longer appends guessed `variable` blocks for
    undeclared references (it used to declare the access vars closed). Nothing is written: a root that references
    undeclared variables fails `tofu validate` (reported back), so it can never apply, open or closed."""
    ws = tf_svc.prepare_workspace("l19-r1", "trace-l19-r1", {"main.tf": _L19_REF_MAIN})
    assert not os.path.exists(os.path.join(ws, "variables.tf"))
    with open(os.path.join(ws, "main.tf")) as fh:
        assert fh.read() == _L19_REF_MAIN


def test_lane19_r1_declared_access_vars_are_never_touched(tf_svc):
    """Do No Harm: a declared allow_unauthenticated (even = true) is left exactly as written."""
    declared = ('variable "allow_unauthenticated" {\n  type    = bool\n  default = true\n}\n'
                'variable "enable_direct_iap" {\n  type    = bool\n  default = false\n}\n'
                'variable "authorized_invoker_members" {\n  type    = list(string)\n  default = ["user:a@example.com"]\n}\n'
                'variable "enable_logging" {\n  type    = bool\n  default = false\n}\n')
    text = _l19_root_variables(tf_svc, {"main.tf": _L19_REF_MAIN, "variables.tf": declared})
    assert text == declared                                         # FD55-W6a: final newline kept too
    assert "Auto-declared by workspace runner" not in text


# ------------------------------------------------------------------ TI-5a/b: typed-intent apply side (no text healing)
import service as _ti5_service  # noqa: E402

_TI5_W = "infra/workload/"
_TI5_INTENT = json.dumps({"schema": "iac_intent/v1", "modules": [
    {"module": "storage-bucket", "name": "uploads", "args": {"bucket_name_suffix": "uploads"}}]}, indent=2)
_TI5_RENDER = json.dumps({"//": "Rendered by StackVend", "module": {"uploads": {
    "source": "../modules/storage-bucket", "project_id": "${var.project_id}", "bucket_name_suffix": "uploads"}}},
    indent=2, sort_keys=True) + "\n"
_TI5_TOPOLOGY = json.dumps({"schema": "service_topology/v1", "intent": {
    "services": [{"name": "shop", "kind": "cloudrun"}], "primary_service": "shop", "edges": [], "resources": []}})
# Every one of these bytes is something a legacy apply-time healer rewrites (naming invariants, the default
# interpolation regex, the provider pin, the PORT env strip, output dedup); on an intent workspace none may change.
_TI5_MAIN = ('module "compute" {\n  source       = "./infra/modules/compute-cloudrun"\n'
             '  service_name = "${var.svc_prefix}-shop"\n}\n'
             'resource "google_storage_bucket" "b" {\n  name = "-data"\n}\n'
             'resource "google_cloud_run_v2_service" "x" {\n  name = "x"\n  template {\n    containers {\n'
             '      env {\n        name  = "PORT"\n        value = "8080"\n      }\n    }\n  }\n}\n')
_TI5_VARS = ('variable "svc_prefix" {\n  type    = string\n  default = "${var.product_id}-x"\n}\n'
             'terraform {\n  required_providers {\n    google = {\n      version = "~> 5.0"\n    }\n  }\n}\n')
_TI5_OUTPUTS = 'output "service_url" {\n  value = module.compute.service_uri\n}\n'
_TI5_HUMAN = ('resource "google_storage_bucket" "h" {\n  name = "${var.bucket_prefix}-data"\n}\n'
              'output "service_url" {\n  value = "human"\n}\n')
_TI5_OVERRIDE = 'variable "x" {\n  default = "${var.product_id}-y"\n}\n'


def _ti5_tree(intent=True, topology=True, human=True):
    files = {_TI5_W + "main.tf": _TI5_MAIN, _TI5_W + "variables.tf": _TI5_VARS, _TI5_W + "outputs.tf": _TI5_OUTPUTS}
    if intent:
        files.update({_TI5_W + "iac_intent.json": _TI5_INTENT, _TI5_W + "custom.tf.json": _TI5_RENDER})
    if topology:
        files[_TI5_W + "topology.json"] = _TI5_TOPOLOGY
    if human:
        files.update({_TI5_W + "human.tf": _TI5_HUMAN, _TI5_W + "override.tf": _TI5_OVERRIDE})
    # the deploy flatten: every infra/workload/<p> is also at the workspace root (module sources already root-anchored)
    files.update({k[len(_TI5_W):]: v for k, v in list(files.items())})
    return files


def _ti5_read_tree(ws):
    out = {}
    for root, dirs, names in os.walk(ws):
        for n in names:
            p = os.path.join(root, n)
            if os.path.islink(p) or n == "backend.tf":
                continue
            with open(p, encoding="utf-8") as fh:
                out[os.path.relpath(p, ws)] = fh.read()
    return out


def test_ti5_prepare_workspace_intent_tree_is_byte_identical(tf_svc):
    files = _ti5_tree()
    ws = tf_svc.prepare_workspace("ti5shop", "trace-ti5-prep", files)
    got = _ti5_read_tree(ws)
    assert {k: got[k] for k in files} == files       # effective tree == repo tree, byte for byte
    assert not hasattr(tf_svc, "_last_healed_files")   # FD-55 W6b: no write-back record exists at all


def test_ti5_negative_legacy_workspace_text_heals_are_gone_and_user_files_never_edited(tf_svc):
    """FD-55 W6a (register FD55-W6a): without an intent the legacy apply text heals (naming invariants, default
    interpolation wipe, provider pin, output dedup, newline trim) no longer run either, so the AI / platform files of
    a legacy workspace are byte-identical too. TI-5b: human.tf and the override file are byte-identical everywhere."""
    files = _ti5_tree(intent=False, topology=False)
    ws = tf_svc.prepare_workspace("ti5shop", "trace-ti5-legacy", files)
    got = _ti5_read_tree(ws)
    assert {k: got[k] for k in files} == files


def test_ti5_human_tf_byte_identical_through_prepare_workspace_on_an_intent_workspace(tf_svc):
    files = _ti5_tree()
    got = _ti5_read_tree(tf_svc.prepare_workspace("ti5shop", "trace-ti5-human", files))
    for p in ("human.tf", "override.tf", _TI5_W + "human.tf", _TI5_W + "override.tf"):
        assert got[p] == files[p], p


# A stale vendored golden module (the HA-31 alignment, A30) and a human file with a plural `locals.` reference (the
# locals curing, A28) were the last two apply-side writers that made the TI-5 partition observable after FD-55 W6a.
# FD-55 W6b / W6d deleted both: no prepare_workspace step writes a committed file on either side of the partition.
_TI5_STALE_MODULE = {"infra/modules/compute-cloudrun/main.tf": "# stale vendored copy\n"}
_TI5_HUMAN_PLURAL = 'locals {\n  greeting = "hi"\n}\n\noutput "greeting" {\n  value = locals.greeting\n}\n'


def test_ti5_no_writer_is_left_on_either_side_of_the_partition(tf_svc, monkeypatch):
    """Mutation check, inverted by FD-55 W6b / W6d: even with the intent switch off (so an intent tree is prepared as
    legacy) and the USER_OWNED rule off, the stale module and human.tf reach the workspace byte-identical, because no
    writer is left (before: the A30 refresh overwrote the module and the A28 curing edited human.tf)."""
    stale = dict(_ti5_tree(), **_TI5_STALE_MODULE)
    files = dict(_ti5_tree(intent=False, topology=False), **{"human.tf": _TI5_HUMAN_PLURAL},
                 **_TI5_STALE_MODULE)
    for label in ("as-is", "intent-off", "intent-and-user-owned-off"):
        if label == "intent-off":
            monkeypatch.setattr(_ti5_service, "files_have_iac_intent", lambda files: False)
        if label == "intent-and-user-owned-off":
            monkeypatch.setattr(_ti5_service, "apply_user_owned", lambda relpath, intent_workspace=False: False)
        for tree, tag in ((stale, "i"), (files, "l")):
            got = _ti5_read_tree(tf_svc.prepare_workspace("ti5shop", f"trace-ti5-{label}-{tag}", tree))
            assert {k: got[k] for k in tree} == tree, (label, tag)


def _ti5_deploy(tf_svc, files, side_effect):
    with patch("google.cloud.storage.Client"), \
         patch("google.cloud.secretmanager.SecretManagerServiceClient"), \
         patch.object(tf_svc, "_fetch_repo_files", return_value={}), \
         patch.object(tf_svc, "_build_and_push_container", return_value=True), \
         patch.object(tf_svc, "_ensure_binary", return_value="tofu"), \
         patch.object(tf_svc, "_run_subprocess") as mock_sub:
        mock_sub.side_effect = side_effect
        result = tf_svc.deploy_workload("ti5shop", "trace-ti5-deploy", files)
    return result, mock_sub


def test_ti5_intent_workspace_undeclared_reference_writes_no_file_and_returns_a_typed_report(tf_svc):
    """Plan §TI-5 test 1: "Reference to undeclared resource" on an intent workspace -> HC-18 (which writes custom.tf,
    or main.tf when there is no custom.tf) does not run, main.tf stays byte-identical, and the failure returns typed."""
    files = _ti5_tree(human=False)
    off = files["custom.tf.json"].index('"uploads"')
    vjson = json.dumps({"valid": False, "diagnostics": [
        {"severity": "error", "summary": "Reference to undeclared resource",
         "detail": "A managed resource \"google_cloud_run_v2_service\" \"service_a\" has not been declared.",
         "range": {"filename": "main.tf", "start": {"line": 2, "column": 3, "byte": 20},
                   "end": {"line": 2, "column": 9, "byte": 26}}},
        {"severity": "error", "summary": "Unsupported argument",
         "range": {"filename": "custom.tf.json", "start": {"line": 4, "column": 5, "byte": off + 12},
                   "end": {"line": 4, "column": 9, "byte": off + 16}}}]})
    err = "Error: Reference to undeclared resource on main.tf line 2: google_cloud_run_v2_service.service_a"
    result, mock_sub = _ti5_deploy(tf_svc, files, [
        {"success": True, "stdout": "", "stderr": "", "exit_code": 0},     # init
        {"success": False, "stdout": "", "stderr": err, "exit_code": 1},   # validate
        {"success": False, "stdout": vjson, "stderr": "", "exit_code": 1},  # validate -json (typed report)
    ])
    assert result["status"] == "VALIDATION_FAILED" and "Reference to undeclared resource" in result["error"]
    calls = [c.args[0] for c in mock_sub.call_args_list]
    assert calls[-1] == ["terraform", "validate", "-json", "-no-color"] and len(calls) == 3   # no heal + re-validate
    got = _ti5_read_tree(os.path.join(tf_svc.workspace_base_dir, "trace-ti5-deploy", "ti5shop"))
    assert got["main.tf"] == _TI5_MAIN and got[_TI5_W + "main.tf"] == _TI5_MAIN
    assert "custom.tf" not in got                                   # HC-18's target is never created
    rep = result["validation_report"]
    assert rep["status"] == "FAIL" and rep["source"] == "apply" and rep["error_class"] == "PLATFORM_DEFECT"
    by_code = {d["code"]: d for d in rep["diagnostics"]}
    assert by_code["TF.REFERENCE_TO_UNDECLARED_RESOURCE"]["file"] == _TI5_W + "main.tf"
    assert by_code["TF.REFERENCE_TO_UNDECLARED_RESOURCE"]["error_class"] == "PLATFORM_DEFECT"
    mapped = by_code["TF.UNSUPPORTED_ARGUMENT"]   # in the render: back to the intent entry that rendered it
    assert (mapped["error_class"], mapped["file"], mapped["block_address"], mapped["attribute_path"]) == (
        "CODE_DEFECT", _TI5_W + "iac_intent.json", "module.uploads", "/modules/0")


_TI5_LEGACY_MAIN_VJSON = json.dumps({"diagnostics": [
    {"severity": "error", "summary": "Reference to undeclared resource",
     "range": {"filename": "main.tf", "start": {"line": 9, "column": 17, "byte": 300}}}]})


def test_ti5_legacy_undeclared_reference_is_reported_without_healing(tf_svc):
    """FD-55 W6c (A45 DELETED): the same failure without an intent is no longer healed either (HC-10 used to fall
    back to main.tf when there is no custom.tf, re-validate and apply). Legacy keeps its untyped VALIDATION_FAILED
    (the engine's text for the bounded regeneration); main.tf is the committed text and validate runs once."""
    files = _ti5_tree(intent=False, topology=False, human=False)
    files["main.tf"] = files[_TI5_W + "main.tf"] = (
        _TI5_MAIN + 'resource "google_cloud_scheduler_job" "c" {\n'
                    '  depends_on = [google_cloud_run_v2_service.service_a]\n}\n')
    result, mock_sub = _ti5_deploy(tf_svc, files, [
        {"success": True, "stdout": "", "stderr": "", "exit_code": 0},
        {"success": False, "stdout": "", "stderr": "Error: Reference to undeclared resource on main.tf line 9: "
                                                   "google_cloud_run_v2_service.service_a", "exit_code": 1},
        {"success": False, "stdout": _TI5_LEGACY_MAIN_VJSON, "stderr": "", "exit_code": 1},   # validate -json
    ])
    assert result["status"] == "VALIDATION_FAILED" and "validation_report" not in result
    assert "google_cloud_run_v2_service.service_a" in result["error"]
    assert mock_sub.call_count == 3                     # init + one validate + the read-only `validate -json`
    # DEPLOY-FAILURE-OWNER-ROUTER: the error is in the platform's main.tf -> PLATFORM_DEFECT, operator stop
    assert (result["error_class"], result["operator_required"]) == ("PLATFORM_DEFECT", True)
    assert result["failure_route"]["findings"][0]["file"] == _TI5_W + "main.tf"
    got = _ti5_read_tree(os.path.join(tf_svc.workspace_base_dir, "trace-ti5-deploy", "ti5shop"))
    # not healed: the reference stays (the A34 PORT env strip still edits this legacy main.tf until FD-55 W6e)
    assert "depends_on = [google_cloud_run_v2_service.service_a]" in got["main.tf"]
    assert "module.compute" not in got["main.tf"].split('resource "google_cloud_scheduler_job"')[1]


def test_w6a_legacy_deploy_applies_committed_names_and_reports_the_engine_error(tf_svc):
    """FD-55 W6a (register FD55-W6a, A9 / A10 / A41 DELETED): a legacy workspace whose custom.tf references an
    undeclared variable inside a resource name is neither "declared" by prepare_workspace nor renamed by the pre-apply
    naming pass; the validate error reaches the caller as VALIDATION_FAILED with the engine's own text (the existing
    regeneration path), and the workspace custom.tf is the committed text."""
    custom = 'resource "google_pubsub_topic" "dl" {\n  name = "${var.pubsub_topic_name}-dead-letter"\n}\n'
    files = _ti5_tree(intent=False, human=False)
    files["custom.tf"] = files[_TI5_W + "custom.tf"] = custom
    err = ('Error: Reference to undeclared input variable\n\n  on custom.tf line 2, in resource "google_pubsub_topic" '
           '"dl":\n   2:   name = "${var.pubsub_topic_name}-dead-letter"')

    def _sub(cmd, *a, **kw):
        if "validate" in cmd:
            return {"success": False, "stdout": "", "stderr": err, "exit_code": 1}
        return {"success": True, "stdout": "", "stderr": "", "exit_code": 0}

    result, _ = _ti5_deploy(tf_svc, files, _sub)
    assert result["status"] == "VALIDATION_FAILED" and err in result["error"]
    got = _ti5_read_tree(os.path.join(tf_svc.workspace_base_dir, "trace-ti5-deploy", "ti5shop"))
    assert got["custom.tf"] == custom
    assert "pubsub_topic_name" not in got.get("variables.tf", "")


def test_ti5_intent_without_topology_or_unreadable_is_refused_typed_before_anything_runs(tf_svc):
    for files, code in ((_ti5_tree(topology=False), "APPLY.INTENT_WITHOUT_TOPOLOGY"),
                        (dict(_ti5_tree(), **{_TI5_W + "iac_intent.json": "{not json"}), "APPLY.INTENT_UNREADABLE")):
        result, mock_sub = _ti5_deploy(tf_svc, files, [])
        assert (result["status"], result["error_class"]) == ("FAILED", code)
        assert mock_sub.call_count == 0


def test_ti5_untyped_apply_failure_on_an_intent_workspace_carries_the_text_verbatim(tf_svc, monkeypatch):
    monkeypatch.setattr(_ti5_service.time, "sleep", lambda s: None)   # the init retry back-off
    result, _ = _ti5_deploy(tf_svc, _ti5_tree(human=False), [
        {"success": False, "stdout": "", "stderr": "boom: init exploded", "exit_code": 1}] * 6)   # init x6
    # DEPLOY-FAILURE-OWNER-ROUTER: init gives no typed owner -> UNKNOWN, operator stop (the report is kept as before)
    assert result["status"] == "FAILED" and result["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED"
    assert result["operator_required"] is True and result["failure_route"]["phase"] == "init"
    rep = result["validation_report"]
    # Fable RT F1: no engine result exists (init never succeeded), so the report claims no tofu run and no class
    # from a tofu result: UNAVAILABLE / GATE_UNAVAILABLE, the deploy's text verbatim as a report-only note
    assert (rep["status"], rep["error_class"], rep["tools_ran"], rep["diagnostics"]) == (
        "UNAVAILABLE", "GATE_UNAVAILABLE", [], [])
    (d,) = rep["report_only"]
    assert d["code"] == "APPLY.UNTYPED_FAILURE" and d["tool"] == "platform" and "boom: init exploded" in d["message"]


def test_ti5_untyped_failure_wrapper_never_opens_a_relative_path(tf_svc, monkeypatch, tmp_path):
    """Fable RT F1: the wrapper's report reads nothing relative to the process CWD (a decoy intent + render there
    must never be read), and the intent is read only from an absolute workspace dir."""
    import builtins
    decoy = tmp_path / "cwd"
    decoy.mkdir()
    (decoy / "iac_intent.json").write_text(_TI5_INTENT)
    (decoy / "custom.tf.json").write_text(_TI5_RENDER)
    monkeypatch.chdir(decoy)
    monkeypatch.setattr(_ti5_service.time, "sleep", lambda s: None)
    opened = []
    real_open = builtins.open

    def spy(path, *a, **k):
        opened.append(str(path))
        return real_open(path, *a, **k)

    real_report = _ti5_service.apply_validation_report

    def report(*a, **k):
        builtins.open = spy
        try:
            return real_report(*a, **k)
        finally:
            builtins.open = real_open

    monkeypatch.setattr(_ti5_service, "apply_validation_report", report)
    result, _ = _ti5_deploy(tf_svc, _ti5_tree(human=False), [
        {"success": False, "stdout": "", "stderr": "boom", "exit_code": 1}] * 6)
    assert result["validation_report"]["status"] == "UNAVAILABLE"
    assert opened == []                                            # nothing read at all on the fallback path
    # a real engine result with an empty (relative) workspace dir: still nothing read relative to the CWD
    vjson = json.dumps({"diagnostics": [{"severity": "error", "summary": "X",
                                         "range": {"filename": "custom.tf.json", "start": {"byte": 5}}}]})
    rep = report(vjson, "")
    assert rep["status"] == "FAIL" and opened == []
    assert rep["diagnostics"][0]["error_class"] == "PLATFORM_DEFECT"   # the decoy intent was not used


def test_ti5_apply_report_owner_rules(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "iac_intent.json").write_text(_TI5_INTENT)
    (ws / "custom.tf.json").write_text(_TI5_RENDER)
    off = _TI5_RENDER.index('"uploads"')

    def rng(f, b):
        return {"filename": f, "start": {"line": 1, "column": 1, "byte": b}, "end": {"line": 1, "byte": b}}
    vjson = json.dumps({"diagnostics": [
        {"severity": "error", "summary": 'Unsupported argument: "x"',
         "range": rng("custom.tf.json", off + len('"uploads": ') + 2)},   # inside the rendered module object
        {"severity": "error", "summary": "Duplicate output definition", "range": rng("human.tf", 0)},
        {"severity": "error", "summary": "Invalid value", "range": rng("custom.tf.json", 1)},   # the `//` header
        {"severity": "warning", "summary": "Deprecated", "range": rng("main.tf", 0)},
        {"severity": "error", "summary": "Module not installed"}]})
    manifest = {_TI5_W + "iac_intent.json", _TI5_W + "custom.tf.json", _TI5_W + "human.tf", _TI5_W + "main.tf"}
    rep = _ti5_service.apply_validation_report(vjson, str(ws), manifest_paths=manifest)
    ds = rep["diagnostics"]
    assert [d["error_class"] for d in ds] == ["CODE_DEFECT", "BROWNFIELD_CONFLICT", "PLATFORM_DEFECT",
                                              "PLATFORM_DEFECT"]
    assert ds[0]["code"] == "TF.UNSUPPORTED_ARGUMENT" and ds[0]["block_address"] == "module.uploads"
    assert ds[2]["file"] == _TI5_W + "custom.tf.json" and ds[3]["file"] == "<unlocated>"
    assert rep["error_class"] == "PLATFORM_DEFECT"
    # Fable RT F5: a server-written root file (backend.tf, terraform.tfvars) or a root file the manifest does not hold
    # at infra/workload/ gets no repository path
    server = json.dumps({"diagnostics": [
        {"severity": "error", "summary": "Bad backend", "range": rng("backend.tf", 0)},
        {"severity": "error", "summary": "Bad value", "range": rng("terraform.tfvars", 0)},
        {"severity": "error", "summary": "Bad main", "range": rng("main.tf", 0)}]})
    files = [d["file"] for d in _ti5_service.apply_validation_report(server, str(ws), manifest_paths=manifest)[
        "diagnostics"]]
    assert files == ["<workspace>/backend.tf", "<workspace>/terraform.tfvars", _TI5_W + "main.tf"]
    assert [d["file"] for d in _ti5_service.apply_validation_report(server, str(ws))["diagnostics"]][2] == (
        "<workspace>/main.tf")                                     # no manifest: nothing is assumed
    bad = _ti5_service.apply_validation_report("not json", str(ws), fallback_error="raw error text")
    assert [d["code"] for d in bad["diagnostics"]] == ["TF.UNPARSED_APPLY_ERROR"]
    assert bad["diagnostics"][0]["message"] == "raw error text"
    many = json.dumps({"diagnostics": [{"severity": "error", "summary": f"E{i}"} for i in range(50)]})
    capped = _ti5_service.apply_validation_report(many, str(ws))
    assert len(capped["diagnostics"]) == 20 and capped["truncated"] is True


def test_ti5_user_owned_classifier_is_exact():
    uo = _ti5_service.apply_user_owned
    assert uo("human.tf") and uo("infra/workload/human_override.tf") and uo("humans_extra.tf")
    assert uo("override.tf") and uo("x_override.tf") and uo("x_override.tf.json")
    assert not uo("custom.tf") and uo("custom.tf", True)          # legacy custom.tf only beside an intent
    assert not uo("main.tf", True) and not uo("override_notes.tf") and not uo("human.md")


def test_ti5_applier_forwards_the_typed_report(monkeypatch):
    import applier
    report = {"status": "FAIL", "diagnostics": [{"code": "TF.X"}]}
    seen = {}

    class FakeService:
        db = None

        def deploy_workload(self, **kw):
            return {"status": "VALIDATION_FAILED", "error": "e", "validation_report": report}

        def workspace_trace_dir(self, trace_id):   # FD4BD-Q3: the run's quota project is registered per workspace
            return f"/nonexistent/{trace_id}"

        def _register_workspace_billing(self, workspace_dir, project_id):
            return workspace_dir, {"project_id": project_id}

    class Scope:
        def __init__(self, **kw):
            self.outcome = {}

        def __enter__(self):
            return self.outcome

        def __exit__(self, *a):
            seen.update(self.outcome)
            return False

    monkeypatch.setattr(applier, "TerraformService", FakeService)
    monkeypatch.setattr(applier, "guaranteed_callback_scope", lambda **kw: Scope(**kw))
    monkeypatch.setenv("PRODUCT_ID", "ti5shop")
    monkeypatch.setenv("TRACE_ID", "trace-ti5-applier")
    monkeypatch.delenv("HCL_FILES_JSON", raising=False)
    with pytest.raises(SystemExit):
        applier.run_job()
    assert seen["status"] == "FAILED" and seen["validation_report"] == report


def test_ti5_deploy_mutant_without_the_intent_switch_loses_the_typed_report(tf_svc, monkeypatch):
    """Mutation check for the deploy path: with the intent switch off, the same intent tree and the same undeclared
    reference take the legacy branch, which returns no typed validation_report (FD-55 W6c: it no longer rewrites
    main.tf either); the typed-report test above kills this mutant."""
    monkeypatch.setattr(_ti5_service, "iac_intent_state", lambda files: "")
    files = _ti5_tree(human=False)
    files["main.tf"] = files[_TI5_W + "main.tf"] = (
        _TI5_MAIN + 'resource "google_cloud_scheduler_job" "c" {\n'
                    '  depends_on = [google_cloud_run_v2_service.service_a]\n}\n')
    result, _ = _ti5_deploy(tf_svc, files, [
        {"success": True, "stdout": "", "stderr": "", "exit_code": 0},
        {"success": False, "stdout": "", "stderr": "Error: Reference to undeclared resource on main.tf line 9: "
                                                   "google_cloud_run_v2_service.service_a", "exit_code": 1},
        {"success": False, "stdout": _TI5_LEGACY_MAIN_VJSON, "stderr": "", "exit_code": 1},   # validate -json
    ])
    assert result["status"] == "VALIDATION_FAILED" and "validation_report" not in result


def test_ti5_a_lone_intent_keeps_todays_path_like_the_gateway(tf_svc):
    """The gateway's sticky rule (TI-3 RT F7): only the intent AND its render make an intent workload; a lone
    iac_intent.json was generated on the legacy path, so the apply side keeps today's legacy path for it too. After
    FD-55 W6b / W6d the legacy path writes nothing either: the stale module is applied as committed."""
    files = dict(_ti5_tree(), **_TI5_STALE_MODULE)
    for k in ("custom.tf.json", _TI5_W + "custom.tf.json"):
        files.pop(k)
    assert _ti5_service.iac_intent_state(files) == ""
    got = _ti5_read_tree(tf_svc.prepare_workspace("ti5shop", "trace-ti5-lone", files))
    assert got["infra/modules/compute-cloudrun/main.tf"] == _TI5_STALE_MODULE["infra/modules/compute-cloudrun/main.tf"]
    assert _ti5_service.iac_intent_state(_ti5_tree()) == "intent"


def test_ti5_workspace_has_iac_intent_reads_the_prepared_workspace(tf_svc, tmp_path):
    ws = tf_svc.prepare_workspace("ti5shop", "trace-ti5-ws", _ti5_tree())
    assert _ti5_service.workspace_has_iac_intent(ws)
    assert not _ti5_service.workspace_has_iac_intent(str(tmp_path))


# ------------------------------------------------------------------------------------------------ GHA-DEPLOY-SWITCH
_GHA_DECL = ('\nvariable "enable_github_actions_deploy" {\n  type        = bool\n  default     = false\n}\n')


def _gha_deploy(tmp_path, switch, declared):
    """GHA-DEPLOY-SWITCH: (deploy result, root tfvars bytes or None, tofu calls) for a record whose
    github_actions_deploy is `switch` (the string "missing" = no field) and a root that declares the switch variable
    (`declared`, as the developer renders it while the switch is off) or not."""
    import glob
    variables, tfvars, custom = _l11_fact_files()
    doc = {"github_repo": "acme/castor-testapp",
           "github_repository_identity": {"full_name": "acme/castor-testapp", "repository_id": "987654321"}}
    if switch != "missing":
        doc["github_actions_deploy"] = switch
    db = MagicMock()
    snap = MagicMock()
    snap.exists = True
    snap.to_dict.return_value = dict(doc)
    db.collection.return_value.document.return_value.get.return_value = snap
    svc = TerraformService(project_id="host", state_bucket="tfstate-bucket", workspace_base_dir=str(tmp_path),
                           firestore_client=db)
    fake, calls = _fd4h_recording_run([])
    hcl = {"infra/workload/variables.tf": variables + (_GHA_DECL if declared else ""),
           "infra/workload/terraform.tfvars": tfvars, "infra/workload/custom.tf": custom,
           "infra/workload/main.tf": _L11_MAIN_TF}
    with _l11_deploy_env(fake):
        res = svc.deploy_workload(product_id="testapp", trace_id="t-fd4atc", hcl_files=hcl,
                                  target_project_id="child-123")
    paths = glob.glob(os.path.join(str(tmp_path), "t-fd4atc", "testapp", "terraform.tfvars"))
    text = None
    if paths:
        with open(paths[0], "rb") as fh:
            text = fh.read()
    return res, text, calls


@pytest.mark.parametrize("switch", ["missing", True])
def test_gha_switch_on_with_a_root_without_it_leaves_the_tfvars_byte_identical(tmp_path, switch):
    """Do No Harm: every workload before the switch (missing / true, root rendered without it): the root tfvars are
    byte-identical to the R1-WIF base."""
    import hashlib
    res, text, _calls = _gha_deploy(tmp_path, switch, declared=False)
    assert res["status"] == "SUCCESS", res
    assert hashlib.sha256(text).hexdigest() == _R1_WIF_BASE_ROOT_TFVARS_SHA256


@pytest.mark.parametrize("switch, value", [(False, b"false"), (True, b"true"), ("missing", b"true")])
def test_gha_switch_reaches_a_root_that_declares_it_at_deploy_time(tmp_path, switch, value):
    """OQ-37 (deploy time): a root rendered with the switch off gets the record's current value on every deploy, so
    turning it back on takes effect on the next deploy without a re-render; only that line is added."""
    import hashlib
    res, text, _calls = _gha_deploy(tmp_path, switch, declared=True)
    assert res["status"] == "SUCCESS", res
    line = b"enable_github_actions_deploy = " + value + b"\n"
    assert text.count(line) == 1
    assert hashlib.sha256(text.replace(line, b"", 1)).hexdigest() == _R1_WIF_BASE_ROOT_TFVARS_SHA256


def test_gha_switch_off_with_a_root_rendered_on_stops_typed_before_anything_runs(tmp_path):
    res, _text, calls = _gha_deploy(tmp_path, False, declared=False)
    assert res["status"] == "FAILED" and res["code"] == "APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC"
    assert res["error_class"] == "IAC_DEFECT" and res["error"].startswith("APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC: ")
    assert res["operator_required"] is True   # RT F1: an admin toggle never buys an automatic developer (LLM) run
    assert "Nothing was built, planned or applied." in res["error"]
    assert not [c for c in calls if len(c) > 1 and c[1] in ("init", "plan", "apply")]


@pytest.mark.parametrize("bad", ["false", 0, {"x": 1}])
def test_gha_switch_invalid_value_is_an_operator_stop(tmp_path, bad):
    res, _text, calls = _gha_deploy(tmp_path, bad, declared=True)
    assert res["status"] == "FAILED" and res["error_class"] == "GHA_DEPLOY_SWITCH_INVALID"
    assert res["operator_required"] is True
    assert not [c for c in calls if len(c) > 1 and c[1] in ("init", "plan", "apply")]


# ---------------------------------------------------------------------------
# CLOUDSQL-CREATE-OWN-OPERATION (register row, awaiting owner; ex08-g13 2026-11-17): the provider stops waiting for a
# Cloud SQL create on a passing operation error and drops the instance from state; the deploy reads its own create
# back from the SQL Admin API (typed fields) and adopts it when it finished cleanly, else fails typed.
# ---------------------------------------------------------------------------
_CSQL_ADDR = "module.postgres.google_sql_database_instance.instance"
_CSQL_NAME = f"{_W7_PID}-postgres"
_CSQL_ADDR2 = "module.reports.google_sql_database_instance.instance"
_CSQL_NAME2 = f"{_W7_PID}-reports"
_CSQL_FUTURE = "2099-01-01T00:00:00.000Z"   # inserted after this deploy's first apply (this deploy's own create)
_CSQL_PAST = "2020-01-01T00:00:00.000Z"     # an instance older than this deploy


def _csql_err(addr=_CSQL_ADDR):
    return ("Error: Error waiting for Create Instance: \n\n"
            f"  with {addr},\n  on infra/modules/database-cloudsql/main.tf line 25, in resource "
            "\"google_sql_database_instance\" \"instance\":\n  25: resource \"google_sql_database_instance\" \"instance\" {\n")


_CSQL_ERR = _csql_err()


def _csql_change(project=_W7_PID, unknown=None, addr=_CSQL_ADDR, name=_CSQL_NAME, **extra):
    after = {"name": name, "project": project, "region": "us-central1", "database_version": "POSTGRES_15"}
    after.update(extra)
    return _w7_change(addr, "google_sql_database_instance", unknown=unknown, **after)


def _csql_op(status="RUNNING", codes=(), insert=_CSQL_FUTURE, op_type="CREATE", target=_CSQL_NAME, name=None,
             project=_W7_PID):
    op = {"name": name or f"op-{target}", "operationType": op_type, "status": status, "targetId": target,
          "targetProject": project, "insertTime": insert}
    if codes:
        op["error"] = {"errors": [{"code": c} for c in codes]}
    return op


_CSQL_USERS = {"items": [{"name": "postgres", "host": ""}, {"name": "app_user", "host": ""}]}


class _CsqlApi:
    """REST answers per instance: `ops[name]` (operations.list items), `op_states[name]` (successive operation GETs,
    the last repeats), `state[name]` (instance GET), `users[name]` (users.list), `ops_status` (operations.list HTTP)."""

    def __init__(self, ops, op_states=None, state=None, users=None, ops_status=200):
        self.ops, self.ops_status = ops, ops_status
        self.op_states = {k: list(v) for k, v in (op_states or {}).items()}
        self.state = state or {}
        self.users = users or {}

    def __call__(self, url):
        base = f"https://sqladmin.googleapis.com/v1/projects/{_W7_PID}"
        for name in (_CSQL_NAME, _CSQL_NAME2):
            if url == f"{base}/operations?instance={name}":
                return self.ops_status, {"items": self.ops.get(name, [])}
            if url == f"{base}/operations/op-{name}":
                states = self.op_states.get(name) or [None]
                return 200, (states.pop(0) if len(states) > 1 else states[0])
            if url == f"{base}/instances/{name}":
                return 200, {"name": name, "state": self.state.get(name, "RUNNABLE")}
            if url == f"{base}/instances/{name}/users":
                return 200, self.users.get(name, _CSQL_USERS)
        return 404, {}


def _csql_get(ops_list, op_states=(), instance_state="RUNNABLE", ops_status=200, users=None):
    """Single-instance shorthand of _CsqlApi."""
    return _CsqlApi({_CSQL_NAME: ops_list}, {_CSQL_NAME: list(op_states)} if op_states else None,
                    {_CSQL_NAME: instance_state}, {_CSQL_NAME: users} if users is not None else None, ops_status)


def _csql_run(tf_svc, tmp_path, apply_errs, plan_changes, get=None, state_list="", import_ok=True, gated_wrap=None,
              extra_patches=()):
    """`_w7_deploy` with `state list` (inside the recovery only) answering `state_list`; returns
    (res, commands, SQL Admin GETs, `state list` commands). `gated_wrap(orig)` replaces the gated apply."""
    import contextlib
    ws = _w7_ws(tmp_path, 'module "postgres" {\n  source = "../modules/database-cloudsql"\n}\n')
    state_cmds = []
    real_impl = TerraformService._recover_own_cloudsql_creates

    def recover(self, *a, **k):
        inner = self._run_subprocess

        def run(cmd, *ra, **rk):
            if list(cmd[1:3]) == ["state", "list"]:
                state_cmds.append(list(cmd))
                return {"success": True, "exit_code": 0, "stdout": state_list, "stderr": ""}
            return inner(cmd, *ra, **rk)
        self._run_subprocess = run
        try:
            return real_impl(self, *a, **k)
        finally:
            del self._run_subprocess

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(TerraformService, "_recover_own_cloudsql_creates", recover))
        stack.enter_context(patch.object(TerraformService, "_child_credentials", return_value=MagicMock()))
        if gated_wrap is not None:
            stack.enter_context(patch.object(TerraformService, "_compliance_gated_apply",
                                             gated_wrap(TerraformService._compliance_gated_apply)))
        for p in extra_patches:
            stack.enter_context(p)
        res, cmds, gets, _ = _w7_deploy(tf_svc, ws, apply_errs, plan_changes, get=get, import_ok=import_ok)
    return res, cmds, [u for u in gets if "sqladmin.googleapis.com" in u], state_cmds


def _csql_op_gets(gets, name=_CSQL_NAME):
    return [u for u in gets if u.endswith(f"/operations/op-{name}")]


def _applies(cmds):
    return [c[1] for c in cmds].count("apply")


def test_csql_own_create_that_finishes_after_a_passing_internal_error_is_adopted_and_applied_again(tf_svc, tmp_path):
    """ex08-g13: the provider failed on a RUNNING create carrying INTERNAL_ERROR; Cloud SQL finished it."""
    get = _csql_get([_csql_op("RUNNING", ("INTERNAL_ERROR",))], op_states=[_csql_op("RUNNING"), _csql_op("DONE")])
    res, cmds, gets, state_cmds = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()], get=get)
    assert res["status"] == "SUCCESS" and "error_class" not in res
    assert _w7_imports(cmds) == [[_CSQL_ADDR, f"projects/{_W7_PID}/instances/{_CSQL_NAME}"]]
    assert _applies(cmds) == 2   # the failed apply + one retry
    assert len(state_cmds) == 1 and len(_csql_op_gets(gets)) == 2
    assert gets[0] == f"https://sqladmin.googleapis.com/v1/projects/{_W7_PID}/operations?instance={_CSQL_NAME}"
    assert gets[-1].endswith(f"/instances/{_CSQL_NAME}/users")   # RT F1: users read before the import
    assert [w["code"] for w in res.get("warnings") or []] == ["CLOUDSQL_CREATE_ADOPTED"]
    assert "IMPORTED" in res["warnings"][0]["message"]


def test_csql_own_create_done_with_an_error_fails_typed_for_an_operator_and_imports_nothing(tf_svc, tmp_path):
    get = _csql_get([_csql_op("DONE", ("INTERNAL_ERROR",))], instance_state="FAILED")
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()], get=get)
    assert res["status"] == "FAILED" and res["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED"
    assert res["stage"] == "apply_cloudsql_create" and res["operator_required"] is True
    assert _w7_imports(cmds) == [] and _applies(cmds) == 1
    rec = res["cloudsql_create"][0]
    assert (rec["address"], rec["instance"], rec["outcome"], rec["error_codes"], rec["instance_state"]) == (
        _CSQL_ADDR, _CSQL_NAME, "OPERATION_FAILED", ["INTERNAL_ERROR"], "FAILED")
    assert res["error"].startswith("CLOUDSQL_CREATE_UNRESOLVED (apply_cloudsql_create): ")
    assert "Terraform apply failed: Error: Error waiting for Create Instance" in res["error"]   # engine text kept
    assert res["failure_route"]["owner"] == "OPERATOR_REQUIRED"
    assert res["failure_route"]["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED"


def test_csql_own_create_still_running_after_the_bounded_wait_fails_typed(tf_svc, tmp_path):
    import cloudsql_create_recovery as csql
    get = _csql_get([_csql_op("RUNNING")], op_states=[_csql_op("RUNNING")])
    res, cmds, gets, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()], get=get)
    assert res["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED"
    assert res["cloudsql_create"][0]["outcome"] == "OPERATION_NOT_DONE"
    assert len(_csql_op_gets(gets)) == csql.wait_polls(None) > 0
    assert not [u for u in gets if f"/instances/{_CSQL_NAME}" in u]   # not read before DONE
    assert _w7_imports(cmds) == []


def test_csql_wait_stops_at_the_wall_clock_deadline(tf_svc, tmp_path):
    """RT F3: the wait is bounded by the clock, not only by a poll count (each poll takes 400 s of clock here)."""
    clock = [1000.0]
    api = _csql_get([_csql_op("RUNNING")], op_states=[_csql_op("RUNNING")])

    def get(url):
        if "/operations/op-" in url:
            clock[0] += 400.0
        return api(url)
    res, cmds, gets, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()], get=get, extra_patches=(
        patch("time.monotonic", side_effect=lambda: clock[0]),))
    assert res["cloudsql_create"][0]["outcome"] == "OPERATION_NOT_DONE"
    # deadline = start + 1500 s: polls end at +400, +800, +1200, +1600; none starts within POLL_S of the deadline
    assert len(_csql_op_gets(gets)) == 4


def test_csql_sync_deploy_budget_leaves_no_wait_and_no_apply_after_the_deadline(tf_svc, tmp_path):
    """RT F3/F7: a sync deploy with less than RETRY_RESERVE_S left polls nothing and does not retry."""
    get = _csql_get([_csql_op("RUNNING")], op_states=[_csql_op("DONE")])
    res, cmds, gets, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()], get=get, extra_patches=(
        patch.object(TerraformService, "_deploy_time_left", return_value=100.0),))
    assert res["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED"
    assert res["cloudsql_create"][0]["outcome"] == "OPERATION_NOT_DONE"
    assert _csql_op_gets(gets) == [] and _w7_imports(cmds) == [] and _applies(cmds) == 1


def test_csql_own_create_done_but_instance_not_runnable_fails_typed(tf_svc, tmp_path):
    get = _csql_get([_csql_op("DONE")], instance_state="MAINTENANCE")
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()], get=get)
    assert res["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED"
    assert res["cloudsql_create"][0]["outcome"] == "INSTANCE_NOT_RUNNABLE" and _w7_imports(cmds) == []


@pytest.mark.parametrize("users,extra,why", [
    ({"items": [{"name": "root", "host": "%"}]}, {}, "`root`@`%`"),
    (None, {"restore_backup_context": [{"instance_id": "src", "backup_run_id": 7}]}, "restore_backup_context"),
    ("unreadable", {}, "users could not be read"),
])
def test_csql_rt_f1_own_create_with_root_any_host_or_restore_is_refused(tf_svc, tmp_path, users, extra, why):
    api = _csql_get([_csql_op("DONE")], users=users if users not in (None, "unreadable") else None)
    if users == "unreadable":
        api.users = {}
        orig = api.__call__

        def get(url):
            return (403, {}) if url.endswith("/users") else orig(url)
    else:
        get = api
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change(**extra)], get=get)
    assert res["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED" and _w7_imports(cmds) == [] and _applies(cmds) == 1
    assert res["cloudsql_create"][0]["outcome"] == "ADOPTION_REFUSED" and why in res["cloudsql_create"][0]["reason"]


def test_csql_failed_import_is_typed(tf_svc, tmp_path):
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()], get=_csql_get([_csql_op("DONE")]),
                                import_ok=False)
    assert _w7_imports(cmds) == [[_CSQL_ADDR, f"projects/{_W7_PID}/instances/{_CSQL_NAME}"]]
    assert res["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED"
    assert res["cloudsql_create"][0]["outcome"] == "IMPORT_FAILED" and _applies(cmds) == 1


def _csql_two():
    return [_csql_change(), _csql_change(addr=_CSQL_ADDR2, name=_CSQL_NAME2)]


def test_csql_rt_f4_mixed_outcomes_import_nothing(tf_svc, tmp_path):
    """RT F4: all-or-nothing: one adoptable and one failed create -> nothing imported, both recorded."""
    api = _CsqlApi({_CSQL_NAME: [_csql_op("DONE")], _CSQL_NAME2: [_csql_op("DONE", ("INTERNAL_ERROR",),
                                                                          target=_CSQL_NAME2)]})
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR + _csql_err(_CSQL_ADDR2)], _csql_two(), get=api)
    assert _w7_imports(cmds) == [] and _applies(cmds) == 1 and res["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED"
    assert [(r["instance"], r["outcome"]) for r in res["cloudsql_create"]] == [
        (_CSQL_NAME, "ADOPT"), (_CSQL_NAME2, "OPERATION_FAILED")]


def test_csql_rt_f4_sibling_without_its_own_create_is_recorded_not_skipped(tf_svc, tmp_path):
    """RT N1: a sibling whose readable operations hold no create of this deploy (a replica whose create never started)
    is recorded but does not block: the adoptable instance is imported and the retry apply handles the sibling."""
    api = _CsqlApi({_CSQL_NAME: [_csql_op("DONE")], _CSQL_NAME2: []})
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], _csql_two(), get=api)
    assert res["status"] == "SUCCESS" and _applies(cmds) == 2
    assert _w7_imports(cmds) == [[_CSQL_ADDR, f"projects/{_W7_PID}/instances/{_CSQL_NAME}"]]
    msg = res["warnings"][0]["message"]
    assert f"({_CSQL_NAME}): IMPORTED" in msg and f"({_CSQL_NAME2}): NO_OWN_OPERATION" in msg


def test_csql_rt_n1_sibling_with_unreadable_operations_still_blocks(tf_svc, tmp_path):
    api = _CsqlApi({_CSQL_NAME: [_csql_op("DONE")], _CSQL_NAME2: []})

    def get(url):
        return (403, {}) if url.endswith(f"/operations?instance={_CSQL_NAME2}") else api(url)
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], _csql_two(), get=get)
    assert _w7_imports(cmds) == [] and _applies(cmds) == 1 and res["error_class"] == "CLOUDSQL_CREATE_UNRESOLVED"
    assert [(r["instance"], r["outcome"]) for r in res["cloudsql_create"]] == [
        (_CSQL_NAME, "ADOPT"), (_CSQL_NAME2, "UNREADABLE")]


def test_csql_rt_n3_adoption_unresolved_result_also_carries_the_cloudsql_records(tf_svc, tmp_path):
    """RT N3: one failed apply with an unadoptable 409 and this deploy's own failed Cloud SQL create: the result is
    APPLY_ADOPTION_UNRESOLVED (unchanged precedence) and also carries the `cloudsql_create` records."""
    secret = "google_secret_manager_secret.s"
    plan = [_csql_change(), _w7_change(secret, "google_secret_manager_secret", unknown={"secret_id": True})]
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_w7_409(secret, "Secret") + _CSQL_ERR], plan,
                                get=_csql_get([_csql_op("DONE", ("INTERNAL_ERROR",))]))
    assert res["error_class"] == "APPLY_ADOPTION_UNRESOLVED" and _w7_imports(cmds) == []
    assert res["adoption_unresolved"][0]["address"] == secret
    assert [(r["instance"], r["outcome"]) for r in res["cloudsql_create"]] == [(_CSQL_NAME, "OPERATION_FAILED")]


def test_csql_two_own_creates_both_adoptable_are_both_imported(tf_svc, tmp_path):
    api = _CsqlApi({_CSQL_NAME: [_csql_op("DONE")], _CSQL_NAME2: [_csql_op("DONE", target=_CSQL_NAME2)]})
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], _csql_two(), get=api)
    assert res["status"] == "SUCCESS" and _applies(cmds) == 2
    assert _w7_imports(cmds) == [[_CSQL_ADDR, f"projects/{_W7_PID}/instances/{_CSQL_NAME}"],
                                 [_CSQL_ADDR2, f"projects/{_W7_PID}/instances/{_CSQL_NAME2}"]]


def test_csql_retry_that_fails_again_is_reported_as_before_and_not_recovered_twice(tf_svc, tmp_path):
    other = ("Error: Error creating Database: googleapi: Error 400: bad\n\n"
             "  with module.postgres.google_sql_database.database,\n")
    res, cmds, _, state_cmds = _csql_run(tf_svc, tmp_path, [_CSQL_ERR, other], [_csql_change()],
                                         get=_csql_get([_csql_op("DONE")]))
    assert _applies(cmds) == 2 and len(state_cmds) == 1
    assert res["status"] == "FAILED" and res["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED"
    assert "Error creating Database" in res["error"] and "cloudsql_create" not in res


def test_csql_rt_f5_retry_refused_by_destroy_block_carries_the_adoption_warning(tf_svc, tmp_path):
    import service as svc_mod
    calls = []

    def wrap(orig):
        def gated(self, *a, **k):
            calls.append(1)
            if len(calls) == 2:
                raise svc_mod.DestroyBlocked({"status": "FAILED", "error": "DESTROY_BLOCKED: x",
                                              "error_class": "DESTROY_REQUIRES_APPROVAL"})
            return orig(self, *a, **k)
        return gated
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()], get=_csql_get([_csql_op("DONE")]),
                                gated_wrap=wrap)
    assert len(calls) == 2 and res["status"] == "FAILED" and res["error_class"] == "DESTROY_REQUIRES_APPROVAL"
    assert [w["code"] for w in res.get("warnings") or []] == ["CLOUDSQL_CREATE_ADOPTED"]


@pytest.mark.parametrize("delta,adopted", [(-0.001, False), (0.0, True), (0.5, True)])
def test_csql_rt_f7_insert_time_boundary_against_the_deploys_first_apply(tf_svc, tmp_path, delta, adopted):
    import datetime as dt
    t0 = 1_900_000_000.0
    stamp = dt.datetime.fromtimestamp(t0 + delta, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()],
                                get=_csql_get([_csql_op("DONE", insert=stamp)]),
                                extra_patches=(patch("time.time", return_value=t0),))
    if adopted:
        assert res["status"] == "SUCCESS" and len(_w7_imports(cmds)) == 1
    else:
        assert res["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED" and _w7_imports(cmds) == []


def test_csql_rt_f9_create_of_another_project_is_not_own(tf_svc, tmp_path):
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()],
                                get=_csql_get([_csql_op("DONE", project="host-p")]))
    assert res["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED" and _w7_imports(cmds) == []


def test_csql_rt_f7_plan_phase_failure_is_skipped(tf_svc, tmp_path):
    def wrap(orig):
        def gated(self, *a, **k):
            r = orig(self, *a, **k)
            return r if r.get("success") else dict(r, compliance_gate_phase="plan")
        return gated
    res, cmds, gets, state_cmds = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()],
                                            get=_csql_get([_csql_op("DONE")]), gated_wrap=wrap)
    assert state_cmds == [] and gets == [] and _w7_imports(cmds) == [] and res["status"] == "FAILED"


def test_csql_rt_f7_tofu_timeout_is_skipped(tf_svc, tmp_path):
    def wrap(orig):
        def gated(self, *a, **k):
            r = orig(self, *a, **k)
            if not r.get("success"):
                self._tofu_timeout_slot().message = "TOFU_TIMEOUT: the OpenTofu command `apply` timed out"
            return r
        return gated
    res, cmds, gets, state_cmds = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], [_csql_change()],
                                            get=_csql_get([_csql_op("DONE")]), gated_wrap=wrap)
    assert state_cmds == [] and gets == [] and _w7_imports(cmds) == []
    assert res["error_class"] == "TOFU_TIMEOUT"


# --- Do No Harm: every other apply failure is unchanged (no state read, no SQL Admin call, same typed result) ---
def _csql_baseline(tf_svc, tmp_path, apply_errs, plan_changes):
    """The same deploy with the recovery switched off (the behaviour before CLOUDSQL-CREATE-OWN-OPERATION)."""
    with patch.object(TerraformService, "_recover_own_cloudsql_creates", lambda self, *a, **k: ([], False)):
        res, cmds, _, _ = _w7_deploy(tf_svc, _w7_ws(tmp_path / "base", "# x\n"), apply_errs, plan_changes)
    return res, cmds


_CSQL_RESULT_KEYS = ("status", "error_class", "error", "operator_required", "code", "stage", "warnings")


@pytest.mark.parametrize("case", ["no_sql_create", "in_state", "older_instance", "ops_unreadable", "other_project",
                                  "other_target", "update_op", "name_unknown"])
def test_csql_negative_other_failures_are_unchanged(tf_svc, tmp_path, case):
    plan = [_csql_change()]
    state_list = ""
    ops = [_csql_op("DONE")]
    ops_status = 200
    if case == "no_sql_create":
        plan = [_w7_change("google_pubsub_topic.t", "google_pubsub_topic", name="t")]
    elif case == "in_state":
        state_list = f"module.foundation.google_service_account.sa\n{_CSQL_ADDR}\n"
    elif case == "older_instance":
        ops = [_csql_op("DONE", insert=_CSQL_PAST)]
    elif case == "ops_unreadable":
        ops_status = 403
    elif case == "other_project":
        plan = [_csql_change(project="host-p")]
    elif case == "other_target":
        ops = [_csql_op("DONE", target=_CSQL_NAME + "-2")]
    elif case == "update_op":
        ops = [_csql_op("DONE", op_type="UPDATE")]
    elif case == "name_unknown":
        plan = [_csql_change(unknown={"name": True})]
    base, _ = _csql_baseline(tf_svc, tmp_path, [_CSQL_ERR], plan)
    res, cmds, gets, state_cmds = _csql_run(tf_svc, tmp_path, [_CSQL_ERR], plan,
                                            get=_csql_get(ops, ops_status=ops_status), state_list=state_list)
    assert {k: res.get(k) for k in _CSQL_RESULT_KEYS} == {k: base.get(k) for k in _CSQL_RESULT_KEYS}
    assert res["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED"
    assert _w7_imports(cmds) == [] and _applies(cmds) == 1
    assert "cloudsql_create" not in res
    assert not [u for u in gets if "/instances/" in u or "/operations/op-" in u]
    if case in ("no_sql_create", "other_project", "name_unknown"):
        assert state_cmds == [] and gets == []
    if case == "in_state":
        assert gets == []


def test_csql_negative_successful_apply_reads_nothing(tf_svc, tmp_path):
    res, cmds, gets, state_cmds = _csql_run(tf_svc, tmp_path, [], [_csql_change()], get=_csql_get([_csql_op("DONE")]))
    assert res["status"] == "SUCCESS" and state_cmds == [] and gets == [] and _w7_imports(cmds) == []


# --- the W7 409 adoption of an existing instance (a same-project re-run), gated like buckets (RT F1/F2) ---
def test_csql_rerun_409_on_a_runnable_instance_is_adopted_with_the_planned_id(tf_svc, tmp_path):
    """A re-run after the provider dropped the instance from state meets a 409; the instance name is project-scoped,
    so the W7 adoption imports it at the plan's address (was: APPLY_ADOPTION_UNRESOLVED, no import rule)."""
    res, cmds, gets, _ = _csql_run(tf_svc, tmp_path, [_w7_409(_CSQL_ADDR, "Cloud SQL instance")], [_csql_change()],
                                   get=_csql_get([]))
    assert res["status"] == "SUCCESS"
    assert _w7_imports(cmds) == [[_CSQL_ADDR, f"projects/{_W7_PID}/instances/{_CSQL_NAME}"]]
    assert [u.rsplit("/", 1)[-1] for u in gets] == [_CSQL_NAME, "users"]


@pytest.mark.parametrize("state,users,extra,why", [
    ("PENDING_CREATE", None, {}, "is PENDING_CREATE, not RUNNABLE"),
    ("FAILED", None, {}, "is FAILED, not RUNNABLE"),
    ("RUNNABLE", {"items": [{"name": "root", "host": "%"}]}, {}, "`root`@`%`"),
    ("RUNNABLE", None, {"restore_backup_context": [{"instance_id": "src"}]}, "restore_backup_context"),
])
def test_csql_rt_f1_f2_409_on_an_instance_that_must_not_be_adopted_fails_typed(tf_svc, tmp_path, state, users,
                                                                                extra, why):
    res, cmds, gets, _ = _csql_run(tf_svc, tmp_path, [_w7_409(_CSQL_ADDR, "Cloud SQL instance")],
                                   [_csql_change(**extra)], get=_csql_get([], instance_state=state, users=users))
    assert _w7_imports(cmds) == [] and res["error_class"] == "APPLY_ADOPTION_UNRESOLVED"
    assert res["adoption_unresolved"][0]["address"] == _CSQL_ADDR and why in res["adoption_unresolved"][0]["reason"]
    if state != "RUNNABLE":
        assert not [u for u in gets if u.endswith("/users")]


def test_csql_409_with_an_unreadable_instance_is_not_adopted(tf_svc, tmp_path):
    res, cmds, _, _ = _csql_run(tf_svc, tmp_path, [_w7_409(_CSQL_ADDR, "Cloud SQL instance")], [_csql_change()],
                                get=lambda u: (404, {}))
    assert _w7_imports(cmds) == [] and res["error_class"] == "APPLY_ADOPTION_UNRESOLVED"
    assert "could not be read" in res["adoption_unresolved"][0]["reason"]

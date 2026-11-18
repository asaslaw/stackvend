"""Lane 13 Stage A (FD-4F, register row 19 option A): static checks on the QA job infrastructure in infra/platform.

The gateway's QA job client (apps/orchestrator-gateway/qa_job_client.py) needs PROJECT_ID, REGION, QA_JOB_NAME,
QA_STAGING_BUCKET and QA_SANDBOX_SA, the isolated job, its zero-role SA and the staging bucket, so that
GET /agent/qa/readiness answers 200. These tests pin that contract, the bucket settings, the job identity that
verify_job_identity enforces, and that no QA sandbox identity receives a role (least privilege).

Hermetic: text/HCL walker from the FD-09 test (comment- and string-aware), no tofu, no network, no credentials.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import glob
import importlib.util
import os
import re

import owner_identifiers

HERE =os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
MAIN_TF = os.path.join(PLATFORM, "main.tf")
QA_TF = os.path.join(PLATFORM, "qa_sandbox.tf")
QA_CLIENT = os.path.join(REPO, "apps", "orchestrator-gateway", "qa_job_client.py")

_spec = importlib.util.spec_from_file_location("fd09_walker_lane13", os.path.join(HERE, "test_platform_validate_fd09.py"))
_fd09 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fd09)
attributes = _fd09.attributes

SERVICES = 'resource "google_cloud_run_v2_service" "services"'
JOBS = 'resource "google_cloud_run_v2_job" "jobs"'
QA_JOB = 'resource "google_cloud_run_v2_job" "qa_sandbox"'
BUCKET = 'resource "google_storage_bucket" "qa_staging"'
BUCKET_IAM = 'resource "google_storage_bucket_iam_member" "qa_staging_gateway"'
SIGN = 'resource "google_service_account_iam_member" "gateway_self_sign_blob"'
GATEWAY = "orchestrator-gateway-service"
DEV_SA = 'google_service_account.agents["sa-castor-developer"]'
SANDBOX_EMAIL = "google_service_account.qa_sandbox.email"

# qa_job_client.QAJobConfig.REQUIRED_ENV (cross-checked below whenever the client file is present on this branch).
REQUIRED_ENV = ("PROJECT_ID", "REGION", "QA_JOB_NAME", "QA_STAGING_BUCKET", "QA_SANDBOX_SA")
EXPECTED_GATEWAY_ENV = {
    "REGION": "var.region",
    "QA_JOB_NAME": "google_cloud_run_v2_job.qa_sandbox.name",
    "QA_STAGING_BUCKET": "google_storage_bucket.qa_staging.name",
    "QA_SANDBOX_SA": SANDBOX_EMAIL,
}


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _platform_files():
    files = sorted(glob.glob(os.path.join(PLATFORM, "*.tf")))
    assert MAIN_TF in files and QA_TF in files
    return files


def _attrs(path):
    return attributes(_read(path))


def _top_blocks(text):
    """[(header, block_text)] for every top-level block (comments stripped, braces in strings blanked)."""
    out, cur, depth = [], None, 0
    for line in _fd09._strip(text):
        if depth == 0 and line.strip().endswith("{"):
            cur = [line.strip()[:-1].strip(), [line]]
        elif cur is not None:
            cur[1].append(line)
        depth += line.count("{") - line.count("}")
        if depth == 0 and cur is not None:
            out.append((cur[0], "\n".join(cur[1])))
            cur = None
    assert depth == 0
    return out


def _gateway_dynamic_env():
    """name -> value of every services dynamic "env" whose for_each is exactly the gateway's key."""
    dyn = (SERVICES, "template", "containers", 'dynamic "env"')
    blocks, cur = [], None
    for p, a, v in _attrs(MAIN_TF):
        if p == dyn and a == "for_each":
            cur = {"for_each": v}
            blocks.append(cur)
        elif p == dyn + ("content",) and cur is not None:
            cur[a] = v
    gw = [b for b in blocks if b["for_each"] == f'each.key == "{GATEWAY}" ? [1] : []']
    names = [b["name"].strip('"') for b in gw]
    assert len(names) == len(set(names)), names
    return {b["name"].strip('"'): _resolve_platform_local(b["value"]) for b in gw}


def _resolve_platform_local(value):
    """STAGE-JOB-RUNNER: the services read their env values from infra/platform/stage_runner.tf's maps
    (local.platform_service_env / local.gateway_service_env); follow such a reference to the map entry's expression."""
    m = re.fullmatch(r'\$?\{?local\.(platform_service_env|gateway_service_env)\["(\w+)"\]\}?', str(value).strip().strip('"'))
    if not m:
        return value
    text = open(os.path.join(REPO, "infra", "platform", "stage_runner.tf"), encoding="utf-8").read()
    start = text.index(f"  {m.group(1)} = {{")
    body = text[start:text.index("\n  }\n", start)]
    [expr] = [ln.split("=", 1)[1].strip() for ln in body.splitlines()[1:]
              if ln.strip().split(" ", 1)[0] == m.group(2) and "=" in ln]
    return expr


def _client_constants():
    if not os.path.exists(QA_CLIENT):
        return None
    tree = ast.parse(_read(QA_CLIENT))
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ("REQUIRED_ENV", "JOB_TASK_TIMEOUT_S"):
                found[node.targets[0].id] = ast.literal_eval(node.value)
    return found


# ------------------------------------------------------------------------------
# Gateway env (qa_job_client.py QAJobConfig.from_env)
# ------------------------------------------------------------------------------
def test_gateway_gets_every_required_qa_env_key():
    gw = _gateway_dynamic_env()
    assert gw == EXPECTED_GATEWAY_ENV
    statics, last = {}, None
    for p, a, v in _attrs(MAIN_TF):
        if p == (SERVICES, "template", "containers", "env"):
            if a == "name":
                last = v.strip('"')
            elif a == "value":
                statics[last] = _resolve_platform_local(v)
    assert statics["PROJECT_ID"] == "var.project_id"
    # REGION/QA_* come only from the gateway-scoped blocks; PROJECT_ID is set for every service.
    assert set(REQUIRED_ENV) == {"PROJECT_ID"} | set(gw)
    assert not (set(gw) & set(statics))


def test_required_env_matches_the_gateway_client_when_present():
    consts = _client_constants()
    if consts is None:  # before the lane 13 + 17 bundle merges, the pinned tuple above is the contract
        assert REQUIRED_ENV[0] == "PROJECT_ID"
        return
    assert tuple(consts["REQUIRED_ENV"]) == REQUIRED_ENV
    assert consts["JOB_TASK_TIMEOUT_S"] == 900


def test_gateway_runtime_sa_is_the_one_the_stage_a_grants_target():
    sas = [v for p, a, v in _attrs(MAIN_TF) if p == (SERVICES, "template") and a == "service_account"]
    # Lane 18 S0 (L18-h, merged in lane18-window-v2): per-service runtime SA lookup; the fallback is the developer SA
    # and the gateway is not one of the services moved to their own identity (destructive_guard.tf service_runtime_sa).
    assert sas == [f"lookup(local.service_runtime_sa, each.key, {DEV_SA}.email)"]
    with open(os.path.join(PLATFORM, "destructive_guard.tf"), encoding="utf-8") as f:
        guard = f.read()
    # FD-7L (SAT-33): the literal map is merged with tf_runner_service_runtime_sa ({} until step B, then only
    # mcp-terraform-server); the gateway is in neither.
    moved = guard[guard.index("service_runtime_sa = merge({"):]
    moved = moved[:moved.index("}")]
    assert set(re.findall(r'"([a-z0-9-]+)"\s*=', moved)) == {"product-control-center-ui", "project-repo-vending-service"}
    assert GATEWAY not in moved


def test_qa_sandbox_sa_value_is_the_same_expression_as_the_job_sa():
    """verify_job_identity compares the job's serviceAccount with QA_SANDBOX_SA by exact equality."""
    job_sa = [v for p, a, v in _attrs(QA_TF) if p == (QA_JOB, "template", "template") and a == "service_account"]
    assert job_sa == [SANDBOX_EMAIL] == [_gateway_dynamic_env()["QA_SANDBOX_SA"]]


# ------------------------------------------------------------------------------
# Staging bucket
# ------------------------------------------------------------------------------
def test_staging_bucket_settings():
    attrs = _attrs(QA_TF)
    top = {a: v for p, a, v in attrs if p == (BUCKET,)}
    assert top["name"] == '"castor-qa-staging-$ var.project_id "'  # the walker blanks braces inside strings
    assert 'name                        = "castor-qa-staging-${var.project_id}"' in _read(QA_TF)
    assert top["location"] == "var.region"
    assert top["project"] == "var.project_id"
    assert top["uniform_bucket_level_access"] == "true"
    assert top["public_access_prevention"] == '"enforced"'
    assert top["force_destroy"] == "false"
    assert {a: v for p, a, v in attrs if p == (BUCKET, "versioning")} == {"enabled": "false"}
    assert {a: v for p, a, v in attrs if p == (BUCKET, "soft_delete_policy")} == {"retention_duration_seconds": "0"}
    assert {a: v for p, a, v in attrs if p == (BUCKET, "lifecycle_rule", "condition")} == {"age": "1"}
    assert {a: v for p, a, v in attrs if p == (BUCKET, "lifecycle_rule", "action")} == {"type": '"Delete"'}
    assert not [p for p, _, _ in attrs if p[:1] == (BUCKET,) and len(p) > 1 and p[1] in ("retention_policy", "cors", "website")]


def test_staging_bucket_access_is_the_gateway_sa_only_and_never_admin():
    attrs = {a: v for p, a, v in _attrs(QA_TF) if p == (BUCKET_IAM,)}
    assert attrs["bucket"] == "google_storage_bucket.qa_staging.name"
    assert attrs["for_each"] == 'toset(["roles/storage.objectCreator", "roles/storage.objectViewer"])'
    assert attrs["role"] == "each.key"
    assert attrs["member"] == f"{DEV_SA}.member"
    # No other IAM resource anywhere touches the staging bucket.
    for f in _platform_files():
        for head, body in _top_blocks(_read(f)):
            if "_iam_" in head and head != BUCKET_IAM:
                assert "qa_staging" not in body, (os.path.basename(f), head)


def test_sign_blob_grant_is_resource_scoped_to_the_gateway_sa_itself():
    attrs = {a: v for p, a, v in _attrs(QA_TF) if p == (SIGN,)}
    assert attrs == {
        "service_account_id": f"{DEV_SA}.name",
        "role": '"roles/iam.serviceAccountTokenCreator"',
        "member": f"{DEV_SA}.member",
    }


def test_iamcredentials_api_is_enabled_for_sign_blob():
    services_list = "\n".join(_fd09._strip(_read(MAIN_TF))).split("services = [", 1)[1].split("]", 1)[0]
    assert '"iamcredentials.googleapis.com",' in [x.strip() for x in services_list.splitlines()]


# ------------------------------------------------------------------------------
# The QA job (what verify_job_identity checks: SA, maxRetries 0, one container without env, timeout <= 900 s)
# ------------------------------------------------------------------------------
def test_qa_job_identity_matches_the_gateway_check():
    attrs = _attrs(QA_TF)
    top = {a: v for p, a, v in attrs if p == (QA_JOB,)}
    assert top["name"] == "local.qa_job_name"
    assert top["deletion_protection"] == "true"
    assert top["location"] == "var.region"
    task = {a: v for p, a, v in attrs if p == (QA_JOB, "template", "template")}
    assert task["service_account"] == SANDBOX_EMAIL
    assert task["max_retries"] == "0"
    assert task["timeout"] == '"900s"'
    assert not [a for p, a, _ in attrs if p == (QA_JOB, "template") and a == "max_retries"]  # FD-09
    assert {a: v for p, a, v in attrs if p == (QA_JOB, "template")} == {"task_count": "1"}
    container_paths = {p[:4] for p, _, _ in attrs if len(p) >= 4 and p[:4] == (QA_JOB, "template", "template", "containers")}
    assert len(container_paths) == 1
    body = dict(_top_blocks(_read(QA_TF)))[QA_JOB]
    assert body.count("containers {") == 1
    assert not re.search(r'^\s*(env|dynamic "env")\s*\{', body, re.M), "the QA job template must carry no env"
    assert "volumes" not in body and "secret" not in body
    c = {a: v for p, a, v in attrs if p == (QA_JOB, "template", "template", "containers")}
    assert c["command"] == '["/cnb/lifecycle/launcher"]'
    assert c["args"] == '["python3", "-m", "sandbox_job"]'
    limits = {a: v for p, a, v in attrs if p == (QA_JOB, "template", "template", "containers", "resources", "{")}
    assert limits == {"cpu": '"2000m"', "memory": '"4096Mi"'}


def test_qa_job_ignores_only_the_deploy_owned_fields():
    body = _read(QA_TF).split(QA_JOB, 1)[1]
    m = re.search(r"ignore_changes\s*=\s*\[\n(.*?)\n\s*\]", body, re.S)
    items = [x.split("#", 1)[0].strip().rstrip(",") for x in m.group(1).splitlines()]
    # Row L3-PRB-r: the image deploy paths also own the job contract label (only that key; every other label stays TF's).
    assert sorted(i for i in items if i) == sorted(["template[0].template[0].containers[0].image", "client", "client_version",
                                                    'labels["stackvend-qa-job-contract"]', "template[0].labels"])


def test_qa_job_is_moved_not_recreated_and_left_the_generic_jobs_block():
    moved = {a: v for p, a, v in _attrs(QA_TF) if p == ("moved",)}
    assert moved == {"from": 'google_cloud_run_v2_job.jobs["qa-sandbox-test-runner"]', "to": "google_cloud_run_v2_job.qa_sandbox"}
    assert {a: v for p, a, v in _attrs(QA_TF) if p == ("locals",)} == {"qa_job_name": '"qa-sandbox-test-runner"'}
    for_each = [v for p, a, v in _attrs(MAIN_TF) if p == (JOBS,) and a == "for_each"]
    assert for_each == ["{ for k, v in local.cloud_run_jobs : k => v if k != local.qa_job_name }"]
    # The inventory map still lists it (sentinel classifier / REQUIRED_COMPONENTS parity, lane 14 test).
    assert '"qa-sandbox-test-runner"        = "Executes test suites and linters in isolated sandboxes"' in _read(MAIN_TF)


# ------------------------------------------------------------------------------
# Least privilege: no role for the QA sandbox identity, no project/folder/org grant in Stage A
# ------------------------------------------------------------------------------
def test_qa_sandbox_sa_holds_no_role_anywhere():
    agent_roles = _read(MAIN_TF).split("agent_roles = {", 1)[1].split("}", 1)[0]
    assert "qa-sandbox" not in agent_roles  # would inherit every for_each agent grant
    tf_files = _platform_files() + [f for f in glob.glob(os.path.join(REPO, "infra", "modules", "**", "*.tf"), recursive=True)
                                    if "/.terraform/" not in f]
    for f in tf_files:
        for head, body in _top_blocks(_read(f)):
            if "_iam_" in head:
                assert "qa_sandbox" not in body and "sa-castor-qa-sandbox" not in body, (os.path.relpath(f, REPO), head)


def test_stage_a_adds_no_project_folder_or_org_level_grant():
    heads = [h for h, _ in _top_blocks(_read(QA_TF))]
    assert heads == ["locals", BUCKET, BUCKET_IAM, SIGN, "moved", QA_JOB]
    for h in heads:
        assert not re.match(r'resource "google_(project|folder|organization)_iam_', h), h


def test_stage_a_file_has_no_hardcoded_project_or_region():
    text = "\n".join(_fd09._strip(_read(QA_TF)))
    for literal in ("us-central1", "mock-stackvend-project", ".iam.gserviceaccount.com"):
        assert literal not in text, literal
    # the dev installs' project ids, by digest (tests/owner_identifiers.py; no real identifier is written here)
    assert owner_identifiers.find(text, {"host_project_a", "host_project_b"}) == []

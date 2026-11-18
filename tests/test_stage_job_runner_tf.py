"""STAGE-JOB-RUNNER (G7, owner 11-13): infra/platform/stage_runner.tf (the stage-runner Cloud Run Job, its IAM) and the
services' env refactor (stage_runner.tf local.platform_service_env), plus the job's place in the inventories.

Plan: docs/planning/stage-job-runner-plan.md. Static checks always run; the plan-level contract
(tests/fixtures/stage_runner/stage_runner.tftest.hcl, MOCK providers) runs when OpenTofu and a local provider mirror
(STACKVEND_TOFU_PROVIDER_MIRROR) are present; nothing is downloaded.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLAT = os.path.join(REPO, "infra", "platform")
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

import stage_deadline as sdm  # noqa: E402
import stage_jobs  # noqa: E402


def _read(*parts):
    return open(os.path.join(REPO, *parts), encoding="utf-8").read()


def _block(text, header):
    """The text of one top-level block (balanced braces) starting at `header`."""
    i = text.index(header)
    depth, j = 0, text.index("{", i)
    while True:
        c = text[j]
        depth += (c == "{") - (c == "}")
        j += 1
        if depth == 0:
            return text[i:j]


TF = _read("infra", "platform", "stage_runner.tf")
JOB = _block(TF, 'resource "google_cloud_run_v2_job" "stage_runner"')
MAIN = _read("infra", "platform", "main.tf")
SERVICES = _block(MAIN, 'resource "google_cloud_run_v2_service" "services"')


def test_job_name_matches_the_gateway_constant():
    assert 'stage_runner_job_name = "stage-runner"' in TF
    assert stage_jobs.STAGE_RUNNER_JOB == "stage-runner"
    assert "name     = local.stage_runner_job_name" in JOB


def test_job_runs_the_gateway_entry_point_without_retries():
    assert 'args    = ["python3", "-m", "stage_runner"]' in JOB
    assert 'command = ["/cnb/lifecycle/launcher"]' in JOB
    assert re.search(r"^\s*max_retries = 0\b", JOB, re.M)
    assert "deletion_protection = true" in JOB
    assert os.path.isfile(os.path.join(GW_DIR, "stage_runner.py"))


def test_task_timeout_covers_the_latest_answer_and_stays_below_the_await_bound():
    """RT §6.4: task timeout >= hard answer + delivery, and below the await bound (per the budget table + YAML)."""
    [t] = re.findall(r'^\s*timeout\s*=\s*"(\d+)s"', JOB, re.M)
    timeout = int(t)
    rows = [b for (stage, mode), b in sdm.STAGE_BUDGETS.items() if mode == sdm.StageMode.CALLBACK]
    worst_delivery = sum((1.5, 3, 6, 12)) + stage_jobs.CALLBACK_MAX_ATTEMPTS * stage_jobs.CALLBACK_TIMEOUT_S
    assert timeout >= max(b.answer_at_s for b in rows) + worst_delivery
    assert timeout < max(b.workflow_timeout_s for b in rows)
    doc = yaml.safe_load(_read("workflows", "main_orchestrator.yaml"))
    awaits = []

    def walk(x):
        if isinstance(x, dict):
            if x.get("call") == "run_stage_job":
                awaits.append(x["args"]["await_timeout_s"])
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(doc)
    assert timeout < max(awaits) == 3900


def test_job_shares_the_gateway_identity_env_network_and_limits():
    assert "service_account = local.stage_runner_sa_email" in JOB
    assert ('stage_runner_sa_email = lookup(local.service_runtime_sa, local.gateway_service_name, '
            'google_service_account.agents["sa-castor-developer"].email)') in TF
    assert ('service_account = lookup(local.service_runtime_sa, each.key, '
            'google_service_account.agents["sa-castor-developer"].email)') in SERVICES
    assert "for_each = local.stage_runner_env" in JOB
    assert "for_each = local.host_vpc_access" in JOB
    assert 'lookup(local.cloud_run_service_cpu, local.gateway_service_name, "1000m")' in JOB
    assert 'lookup(local.cloud_run_service_memory, local.gateway_service_name, "1024Mi")' in JOB
    # image: the gateway's live image at creation, then owned by the deploy paths
    assert ('image   = google_cloud_run_v2_service.services[local.gateway_service_name].template[0].containers[0].image'
            in JOB)
    assert "template[0].template[0].containers[0].image," in JOB


def test_every_service_env_value_comes_from_the_shared_locals():
    """No drift-prone second copy: every common env block of the services resource reads stage_runner.tf's locals,
    and every name in those locals is set on the services."""
    common = re.findall(r'^\s{4}(\w+)\s+=', _block(TF, "platform_service_env = {"), re.M)
    assert len(common) == 16
    for name in common:
        assert f'value = local.platform_service_env["{name}"]' in SERVICES, name
        assert f'name  = "{name}"' in SERVICES or f'name = "{name}"' in SERVICES, name
    for name in ("REGION", "QA_JOB_NAME", "QA_STAGING_BUCKET", "QA_SANDBOX_SA"):
        assert f'value = local.gateway_service_env["{name}"]' in SERVICES, name
    assert "value = local.service_gemini_model[each.key]" in SERVICES
    assert "var.environment" not in SERVICES.split("containers {", 1)[1].split("scaling {", 1)[0]


def test_dispatcher_role_is_three_permissions_on_the_one_job():
    role = _block(TF, 'resource "google_project_iam_custom_role" "stage_runner_dispatcher"')
    perms = re.findall(r'"(run\.[a-zA-Z.]+)"', role)
    assert sorted(perms) == ["run.executions.get", "run.jobs.run", "run.jobs.runWithOverrides"]
    binding = _block(TF, 'resource "google_cloud_run_v2_job_iam_member" "gateway_stage_runner_dispatcher"')
    assert "name     = google_cloud_run_v2_job.stage_runner.name" in binding
    assert 'member   = "serviceAccount:${local.stage_runner_sa_email}"' in binding
    # nothing project-wide, no act-as, no admin
    assert "google_project_iam_member" not in TF.replace("google_project_iam_member.persona_datastore_users", "") \
        .replace("google_project_iam_member.guard_db_readers", "")
    assert "serviceAccountUser" not in TF and "run.admin" not in TF


def test_gateway_cpu_is_request_based_again():
    """GATEWAY-CPU-ALWAYS-ALLOCATED is withdrawn (superseded by STAGE-JOB-RUNNER): no stage work after a response."""
    [line] = [x for x in MAIN.splitlines() if x.strip().startswith("cpu_idle = contains(")]
    listed = {n.strip().strip('"') for n in line.split("contains([", 1)[1].split("]", 1)[0].split(",")}
    assert listed == {"mcp-terraform-server", "project-repo-vending-service"}


def test_inventories_list_the_job():
    # docs/ is internal and not part of the public export: the inventory doc is checked only where docs/ exists (the
    # private repo, where a missing REQUIRED_COMPONENTS.md still fails); the shipped inventories below always run.
    if os.path.isdir(os.path.join(REPO, "docs")):
        assert "stage-runner" in _read("docs", "REQUIRED_COMPONENTS.md")
    import importlib.util
    spec = importlib.util.spec_from_file_location("g7_rm", os.path.join(REPO, "shared", "release_manifest.py"))
    rm = importlib.util.module_from_spec(spec)
    sys.modules["g7_rm"] = rm    # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(rm)
    assert ("stage-runner", "job", "apps/orchestrator-gateway") in rm.COMPONENTS
    comps = _read("scripts", "common", "components.sh")
    assert 'SV_STAGE_RUNNER_JOB="stage-runner"' in comps
    assert 'SV_STAGE_RUNNER_FOLLOWS="orchestrator-gateway-service"' in comps


# ------------------------------------------------------------------------------------------------ plan-level
_TOFU = shutil.which("tofu")
_MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")
_FIXTURE = os.path.join(HERE, "fixtures", "stage_runner", "stage_runner.tftest.hcl")


@unittest.skipUnless(_TOFU and _MIRROR and os.path.isdir(os.path.join(_MIRROR, "registry.opentofu.org", "hashicorp", "google")),
                     "needs OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
class TestStageRunnerPlanContractMockProviders(unittest.TestCase):
    def test_tofu_test_contract(self):
        tmp = tempfile.mkdtemp(prefix="stage-runner-tf-")
        try:
            shutil.copytree(os.path.join(REPO, "infra"), os.path.join(tmp, "infra"),
                            ignore=shutil.ignore_patterns(".terraform*", "*.tfvars", "*.tfstate*"))
            shutil.copytree(os.path.join(REPO, "workflows"), os.path.join(tmp, "workflows"))
            os.makedirs(os.path.join(tmp, "mcp-servers", "kubernetes"))
            shutil.copy(os.path.join(REPO, "mcp-servers", "kubernetes", "helm-pin.json"),
                        os.path.join(tmp, "mcp-servers", "kubernetes"))
            shutil.copy(os.path.join(REPO, "VERSION"), os.path.join(tmp, "VERSION"))
            plat = os.path.join(tmp, "infra", "platform")
            os.makedirs(os.path.join(plat, "tests"))
            shutil.copy(_FIXTURE, os.path.join(plat, "tests"))
            rc_file = os.path.join(tmp, "cli.tfrc")
            with open(rc_file, "w", encoding="utf-8") as f:
                f.write('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                        '    include = ["registry.opentofu.org/*/*"]\n  }\n}\n' % _MIRROR)
            env = hermetic_guard.child_env(extra={"TF_CLI_CONFIG_FILE": rc_file,
                                                  "TF_DATA_DIR": os.path.join(tmp, "tfdata"), "TF_IN_AUTOMATION": "1"})
            init = subprocess.run([_TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=plat, env=env,
                                  capture_output=True, text=True, timeout=300)
            self.assertEqual(init.returncode, 0, init.stdout + init.stderr)
            res = subprocess.run([_TOFU, "test", "-no-color", "-filter=tests/stage_runner.tftest.hcl"], cwd=plat,
                                 env=env, capture_output=True, text=True, timeout=900)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("2 passed, 0 failed", res.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

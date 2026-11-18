"""C10 (owner 11-07): machine callers off the Control Center. Static checks of the platform Terraform and of the
component inventories and replicated copies (no tofu run: tofu plan needs the real backend).

Plan expectations pinned here: the subscription / scheduler names and resource addresses are kept (in-place updates);
the only removal is the FINOPS-IAP-ACCESS IAP accessor; the new jobs are google_cloud_run_v2_job.jobs instances with
their own least-privilege personas; job-scoped run grants only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import re
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
C10_JOBS = {"finops-spend-sync-job": "apps/finops-spend-sync", "sandbox-workload-sweeper-job": "apps/sandbox-sweeper",
            "billing-alert-drain-job": "apps/billing-alert-drain"}
PERSONAS = {"finops-spend-sync-job": "sa-stackvend-finops-sync", "sandbox-workload-sweeper-job": "sa-stackvend-sandbox-sweeper",
            "billing-alert-drain-job": "sa-stackvend-billing-drain"}


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(text):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _block(text, head):
    start = text.index(head)
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[start:j + 1]
    raise AssertionError(head)


MAIN = _strip_comments(_read("infra", "platform", "main.tf"))
GUARD = _strip_comments(_read("infra", "platform", "destructive_guard.tf"))


def _keys(block):
    return set(re.findall(r'^\s*"([a-z0-9-]+)"\s*=', block, re.M))


# ------------------------------------------------------------------------------------------------ subscription
def test_billing_subscription_is_pull_in_place_with_the_same_name_and_dlq():
    sub = _block(MAIN, 'resource "google_pubsub_subscription" "billing_alerts_push"')
    assert 'name       = "billing-alerts-push-subscription"' in sub
    assert "topic      = google_pubsub_topic.billing_budget_alerts.name" in sub
    assert "push_config" not in sub and "oidc_token" not in sub
    assert "ack_deadline_seconds         = 600" in sub
    assert "enable_exactly_once_delivery = true" in sub
    assert 'message_retention_duration   = "604800s"' in sub
    assert "max_delivery_attempts = 5" in sub and "google_pubsub_topic.castor_dlq.id" in sub
    assert '"billing-alerts-push-subscription",' in _block(MAIN, 'resource "google_pubsub_subscription_iam_member" "pubsub_dlq_subscribers"')
    drain = _block(MAIN, 'resource "google_pubsub_subscription_iam_member" "billing_alert_drain_subscriber"')
    assert 'role         = "roles/pubsub.subscriber"' in drain and "local.billing_drain_sa_email" in drain


# ------------------------------------------------------------------------------------------------ schedulers
@pytest.mark.parametrize("res, name, job, schedule", [
    ("finops_nightly_spend_sync", "castor-finops-nightly-spend-sync", "finops-spend-sync-job", "0 3 * * *"),
    ("sandbox_workload_sweeper", "castor-sandbox-workload-sweeper", "sandbox-workload-sweeper-job", "0 4 * * *"),
    ("billing_alert_drain", "stackvend-billing-alert-drain", "billing-alert-drain-job", "*/30 * * * *"),
])
def test_schedulers_run_jobs_with_oauth_never_the_control_center(res, name, job, schedule):
    blk = _block(MAIN, f'resource "google_cloud_scheduler_job" "{res}"')
    assert f'name        = "{name}"' in blk and f'schedule    = "{schedule}"' in blk
    assert ('uri         = "https://${var.region}-run.googleapis.com/v2/projects/${var.project_id}/locations/'
            f'${{var.region}}/jobs/{job}:run"') in blk
    assert "oauth_token {" in blk and "oidc_token" not in blk and "product-control-center-ui" not in blk
    assert 'service_account_email = google_service_account.agents["sa-castor-finops"].email' in blk
    assert 'scope                 = "https://www.googleapis.com/auth/cloud-platform"' in blk
    assert "google_cloud_run_v2_job.jobs" in blk


def test_nothing_in_terraform_calls_the_control_center_as_a_machine():
    for path in ("main.tf", "destructive_guard.tf", "pubsub_publishers.tf"):
        text = _strip_comments(_read("infra", "platform", path))
        assert "/api/finops/sync-spend" not in text and "/api/alerts/billing" not in text
        assert "/api/workloads/sweep-expired-sandboxes" not in text
    assert "control_center_iap_platform_callers" not in MAIN


# ------------------------------------------------------------------------------------------------ jobs
def test_new_jobs_are_inventory_jobs_with_timeouts_and_env():
    inv = _block(MAIN, "  cloud_run_jobs =")
    assert set(C10_JOBS) <= _keys(inv)
    assert _keys(_block(MAIN, "  job_timeouts =")) == set(C10_JOBS)
    jobs = _block(MAIN, 'resource "google_cloud_run_v2_job" "jobs"')
    assert "timeout = lookup(local.job_timeouts, each.key, null)" in jobs
    assert "lookup(local.c10_job_env, each.key, {})" in jobs
    assert "max_retries = 0" in jobs
    env = _block(MAIN, "  c10_job_env =")
    sweeper = _block(env, '"sandbox-workload-sweeper-job" =')
    assert "VENDING_SERVICE_URL = local.vending_service_url" in sweeper and "REGION" in sweeper
    drain = _block(env, '"billing-alert-drain-job" =')
    for needle in ('BILLING_ALERTS_SUBSCRIPTION = "projects/${var.project_id}/subscriptions/billing-alerts-push-subscription"',
                   'FINOPS_ENFORCER_JOB         = "finops-budget-enforcer-job"',
                   "BILLING_ACCOUNT_ID          = var.billing_account_id",
                   'BILLING_BREACH_ENFORCEMENT  = var.billing_breach_enforcement_enabled ? "true" : "false"'):
        assert needle in drain
    runner = _strip_comments(_read("infra", "platform", "tf_runner_identity.tf"))
    assert '"finops-spend-sync-job" = {' in _block(runner, "  tf_runner_job_env =")


def test_enforcement_variable_defaults_on():
    var = _block(_read("infra", "platform", "variables.tf"), 'variable "billing_breach_enforcement_enabled"')
    assert "type        = bool" in var and "default     = true" in var


def test_job_run_grants_are_job_scoped_and_minimal():
    sched = _block(MAIN, 'resource "google_cloud_run_v2_job_iam_member" "c10_job_schedulers"')
    assert 'role     = "roles/run.invoker"' in sched and "sa-castor-finops" in sched
    assert set(re.findall(r'"([a-z-]+-job)"', _block(MAIN, "  c10_scheduled_jobs ="))) == set(C10_JOBS)
    role = _block(MAIN, 'resource "google_project_iam_custom_role" "billing_drain_enforcer_runner"')
    perms = set(re.findall(r'"(run\.[a-zA-Z.]+)"', role))
    assert perms == {"run.jobs.run", "run.jobs.runWithOverrides", "run.executions.get"}
    bind = _block(MAIN, 'resource "google_cloud_run_v2_job_iam_member" "billing_drain_enforcer_runner"')
    assert 'name     = google_cloud_run_v2_job.jobs["finops-budget-enforcer-job"].name' in bind
    assert "local.billing_drain_sa_email" in bind
    # RT residual R3: the Control Center's restores run the same job, with the same role, on that one job only
    cc = _block(MAIN, 'resource "google_cloud_run_v2_job_iam_member" "cc_enforcer_runner"')
    assert 'name     = google_cloud_run_v2_job.jobs["finops-budget-enforcer-job"].name' in cc
    assert "role     = google_project_iam_custom_role.billing_drain_enforcer_runner.name" in cc
    assert 'member   = "serviceAccount:${local.cc_sa_email}"' in cc
    # no project-wide run role for the personas
    for res in re.findall(r'resource "google_project_iam_member" "([a-z0-9_]+)"', MAIN + GUARD):
        blk = _block(MAIN + GUARD if f'"{res}"' in MAIN else GUARD, f'resource "google_project_iam_member" "{res}"')
        if any(k in blk for k in ("sweeper_sa_email", "spend_sync_sa_email", "billing_drain_sa_email")):
            assert "roles/run." not in blk and "roles/secretmanager" not in blk, res


def test_personas_and_runtime_identities():
    personas = _block(GUARD, 'resource "google_service_account" "stackvend_personas"')
    for job, account in PERSONAS.items():
        assert f'"{account}"' in personas
        assert re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", account) and "castor" not in account
    runtime = _block(GUARD, "  job_runtime_sa =")
    assert '"finops-spend-sync-job"         = local.spend_sync_sa_email' in runtime
    assert '"sandbox-workload-sweeper-job"  = local.sweeper_sa_email' in runtime
    assert '"billing-alert-drain-job"       = local.billing_drain_sa_email' in runtime
    vending = _block(GUARD, '"project-repo-vending-service" = {')
    assert re.search(r'SANDBOX_TTL_CALLERS\s+= join\(",", \[local\.cc_sa_email, local\.sweeper_sa_email\]\)', vending)
    # RT finding 1: the sweeper is NOT a destructive caller (runner identity, managed tag, lifecycle routes)
    assert re.search(r"DESTRUCTIVE_CALLERS\s+= local\.cc_sa_email\n", vending)
    assert "sweeper" not in re.search(r"DESTRUCTIVE_CALLERS[^\n]*", vending).group(0)
    assert '"sweeper:project-repo-vending-service"' in _block(GUARD, 'resource "google_cloud_run_v2_service_iam_member" "persona_invokers"')
    ds = _block(GUARD, 'resource "google_project_iam_member" "persona_datastore_users"')
    assert {"sweeper", "spend", "drain"} <= set(re.findall(r"^\s*([a-z_]+)\s*=", ds, re.M))
    assert re.search(r"spend\s+= local\.spend_sync_sa_email",
                     _block(GUARD, 'resource "google_project_iam_member" "guard_db_readers"'))
    upgrader = _read("infra", "platform", "platform_upgrader.tf")
    for account in PERSONAS.values():
        assert f'"{account}"' in _block(upgrader, "  platform_upgrader_actas_accounts =")


# ------------------------------------------------------------------------------------------------ inventories
def _bash_jobs():
    out = subprocess.run(["/bin/bash", "-c", '. "$1"; for e in "${JOBS[@]}"; do echo "$e"; done', "x",
                          os.path.join(REPO, "scripts", "common", "components.sh")],
                         capture_output=True, text=True, check=True).stdout.split()
    return dict(e.split(":", 1) for e in out)


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod    # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(mod)
    return mod


def test_every_inventory_names_the_new_jobs():
    tf_jobs = _keys(_block(MAIN, "  cloud_run_jobs ="))
    bash = _bash_jobs()
    assert tf_jobs == set(bash)
    for job, d in C10_JOBS.items():
        assert bash[job] == d and os.path.isfile(os.path.join(REPO, d, "main.py"))
        assert open(os.path.join(REPO, d, "Procfile")).read() == "web: python3 main.py\n"
        assert f'release_info.log_release("{job}")' in open(os.path.join(REPO, d, "main.py")).read()
    clf = _load("c10_sre_classifier", "apps/log-sre-sentinel/sre_classifier.py")
    for job, d in C10_JOBS.items():
        assert job in clf.DEFAULT_PLATFORM_JOBS and clf.PLATFORM_SOURCE_DIRS[job] == d + "/"
    rm = _load("c10_release_manifest", "shared/release_manifest.py")
    guard = _load("c10_upgrade_guard", "scripts/upgrade/guard.py")
    for job, d in C10_JOBS.items():
        assert (job, "job", d) in rm.COMPONENTS and guard.COMPONENT_KINDS[job] == "job"


# ------------------------------------------------------------------------------------------------ replicated copies
COPIES = {
    "shared/day2_job.py": ["apps/finops-spend-sync/shared/day2_job.py", "apps/sandbox-sweeper/shared/day2_job.py",
                           "apps/billing-alert-drain/shared/day2_job.py"],
    "shared/spend_sync.py": ["apps/control-center/shared/spend_sync.py", "apps/finops-spend-sync/shared/spend_sync.py"],
    "shared/sandbox_sweep.py": ["apps/control-center/shared/sandbox_sweep.py",
                                "apps/sandbox-sweeper/shared/sandbox_sweep.py"],
    "shared/billing_alerts.py": ["apps/control-center/shared/billing_alerts.py",
                                 "apps/billing-alert-drain/shared/billing_alerts.py"],
    "shared/enforcer_job.py": ["apps/control-center/shared/enforcer_job.py",
                               "apps/billing-alert-drain/shared/enforcer_job.py"],
    "shared/sandbox_detection.py": ["apps/sandbox-sweeper/shared/sandbox_detection.py"],
    "shared/runner_identity.py": ["apps/finops-spend-sync/shared/runner_identity.py"],
    "shared/settings.py": ["apps/billing-alert-drain/shared/settings.py"],
    "shared/gemini_model_config.py": ["apps/billing-alert-drain/shared/gemini_model_config.py"],
    "shared/__init__.py": ["apps/finops-spend-sync/shared/__init__.py", "apps/sandbox-sweeper/shared/__init__.py",
                           "apps/billing-alert-drain/shared/__init__.py"],
    "apps/control-center/services/finops_sync.py": ["apps/finops-spend-sync/services/finops_sync.py"],
    "apps/control-center/services/runner_state.py": ["apps/finops-spend-sync/services/runner_state.py"],
    "apps/control-center/services/__init__.py": ["apps/finops-spend-sync/services/__init__.py"],
    "apps/control-center/workflow_executions.py": ["apps/sandbox-sweeper/workflow_executions.py",
                                                   # BUILD-ADMISSION-QUEUE RT F3a: the gateway's admission reads the
                                                   # Workflows state of build-slot holders
                                                   "apps/orchestrator-gateway/workflow_executions.py"],
}


@pytest.mark.parametrize("source", sorted(COPIES))
def test_c10_copies_are_byte_identical(source):
    want = open(os.path.join(REPO, source), "rb").read()
    for copy in COPIES[source]:
        assert open(os.path.join(REPO, copy), "rb").read() == want, f"{copy} drifted from {source}"


def test_control_center_has_no_machine_caller_left():
    identity = _read("apps", "control-center", "identity.py")
    body = identity[identity.index("def platform_callers()"):identity.index("def _discover()")]
    assert body.rstrip().endswith("return frozenset()") and "sa-castor-finops@" not in body
    auth = _read("apps", "control-center", "auth.py")
    assert "iap_platform_caller" not in auth

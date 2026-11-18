"""Lane 19 L19-0a: two OAuth clients per install, enforced by Terraform (plan §2.7.1; register rows 27b, 44, L5-26).

Offline: the A1 precondition and the variable validations are evaluated with `tofu console` in a scratch module that
copies the exact blocks from infra/platform (no providers, no init, no network). Skipped when tofu is not installed;
it never downloads anything.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import shutil
import subprocess

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MAIN = os.path.join(REPO, "infra", "platform", "main.tf")
VARS = os.path.join(REPO, "infra", "platform", "variables.tf")
EXAMPLE = os.path.join(REPO, "infra", "platform", "terraform.tfvars.example")
TOFU = shutil.which("tofu")
CC = "123456789012-ccclient.apps.googleusercontent.com"
TENANT = "123456789012-tenantclient.apps.googleusercontent.com"


def _block(text, header):
    """The full `header { ... }` block (brace-balanced; test-only extraction of a known block)."""
    start = text.index(header)
    depth, i = 0, text.index("{", start)
    while True:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1


def _precondition_condition():
    svc = _block(open(MAIN).read(), 'resource "google_cloud_run_v2_service" "services"')
    pre = _block(svc, "precondition")
    line = next(ln for ln in pre.splitlines() if ln.strip().startswith("condition"))
    return line.split("=", 1)[1].strip()


def _console(tmp_path, expr, **tfvars):
    variables = open(VARS).read()
    module = "\n".join([
        _block(variables, 'variable "cc_google_oauth_client_id"'),
        _block(variables, 'variable "tenant_google_client_id"'),
        'variable "allow_unauthenticated" {\n  type = bool\n  default = true\n}',
        'variable "enable_direct_iap" {\n  type = bool\n  default = false\n}',
        "locals {\n  probe = " + expr + "\n}",
    ])
    (tmp_path / "main.tf").write_text(module)
    args = [TOFU, "console"] + [f"-var={k}={v}" for k, v in tfvars.items()]
    res = subprocess.run(args, input="local.probe\n", cwd=str(tmp_path), capture_output=True, text=True, timeout=60,
                         env=hermetic_guard.child_env(extra={"TF_IN_AUTOMATION": "1"}))
    return res


def test_tenant_variable_declared_with_the_same_exact_format_rule():
    variables = open(VARS).read()
    cc = _block(variables, 'variable "cc_google_oauth_client_id"')
    tenant = _block(variables, 'variable "tenant_google_client_id"')
    cond = lambda b: next(ln.strip() for ln in b.splitlines() if ln.strip().startswith("condition"))
    assert cond(tenant) == cond(cc).replace("cc_google_oauth_client_id", "tenant_google_client_id")
    assert 'default     = ""' in tenant


def test_tenant_client_id_is_never_wired_into_any_service_env():
    main = open(MAIN).read()
    assert "value = var.tenant_google_client_id" not in main.replace("  ", " ")
    svc = _block(main, 'resource "google_cloud_run_v2_service" "services"')
    template = _block(svc, "template")
    assert "tenant_google_client_id" not in template


def test_cc_client_pinned_check_present():
    chk = _block(open(MAIN).read(), 'check "cc_client_pinned"')
    assert "var.cc_google_oauth_client_id != \"\"" in chk and "var.enable_direct_iap" in chk


def test_tfvars_example_lists_both_clients_without_any_secret():
    ex = open(EXAMPLE).read()
    assert "cc_google_oauth_client_id" in ex and "tenant_google_client_id" in ex
    assert "client_secret" not in ex.replace("tenant_google_client_secret", "")


@pytest.mark.skipif(TOFU is None, reason="tofu not installed (never downloaded)")
@pytest.mark.parametrize("cc,tenant,ok", [
    (CC, TENANT, True), (CC, CC, False), ("", CC, True), (CC, "", True), ("", "", True),
])
def test_a1_precondition(tmp_path, cc, tenant, ok):
    res = _console(tmp_path, _precondition_condition(), cc_google_oauth_client_id=cc, tenant_google_client_id=tenant)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == ("true" if ok else "false")


@pytest.mark.skipif(TOFU is None, reason="tofu not installed (never downloaded)")
@pytest.mark.parametrize("bad", ["not-a-client", " " + TENANT, "123-ABC.apps.googleusercontent.com", "123-abc.apps.googleusercontent.com.evil"])
def test_tenant_variable_validation_rejects_malformed(tmp_path, bad):
    res = _console(tmp_path, "true", tenant_google_client_id=bad)
    # `tofu console` prints the validation error (and may still exit 0); the plan/apply path fails on it.
    assert "tenant_google_client_id must be empty" in (res.stdout + res.stderr)
    good = _console(tmp_path, "true", tenant_google_client_id=TENANT)
    assert "must be empty" not in (good.stdout + good.stderr) and good.stdout.strip() == "true"


# ------------------------------------------------------------------------------------------------ L19-0b
def _for_each_members(resource_header):
    blk = _block(open(MAIN).read(), resource_header)
    inner = blk[blk.index("toset([") + len("toset(["):blk.index("])")]
    return sorted(x.strip().strip('",') for x in inner.split("\n") if x.strip())


def test_oauth_pair_readers_trimmed_to_the_developer_sa():
    for name in ("oauth_client_id_accessors", "oauth_client_secret_accessors"):
        members = _for_each_members(f'resource "google_secret_manager_secret_iam_member" "{name}"')
        assert members == ["sa-castor-developer"], (name, members)


def test_qa_sandbox_sa_exists_with_zero_roles():
    main = open(MAIN).read()
    blk = _block(main, 'resource "google_service_account" "qa_sandbox"')
    assert 'account_id   = "sa-castor-qa-sandbox"' in blk
    # Zero roles. Lane 13 Stage A adopted it: the platform references it ONLY as the gateway's QA_SANDBOX_SA env value
    # (STAGE-JOB-RUNNER: the value lives in stage_runner.tf local.gateway_service_env, read by main.tf's gateway env
    # block and by the stage-runner job) and the job attachment in qa_sandbox.tf; no IAM member anywhere
    # (tests/test_lane13_stage_a_tf.py).
    assert main.count("google_service_account.qa_sandbox") == 0
    assert main.count('value = local.gateway_service_env["QA_SANDBOX_SA"]') == 1
    runner = open(os.path.join(os.path.dirname(MAIN), "stage_runner.tf")).read()
    assert runner.count("google_service_account.qa_sandbox") == 1
    assert runner.count("QA_SANDBOX_SA     = google_service_account.qa_sandbox.email") == 1
    assert "sa-castor-qa-sandbox" not in main.replace(blk, "")

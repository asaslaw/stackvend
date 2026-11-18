"""SCHEDULING-CRON-AUDIENCE (owner 11-14): the golden scheduling-cron module takes an optional OIDC token `audience`.

Before: `infra/modules/scheduling-cron` had no audience input, so a Cloud Scheduler job built from the golden module
always sent a token whose audience was the target URI. Example 02 (row EXAMPLE-02-SCHEDULER-OIDC) requires Service A
to accept exactly the audience constant `https://service-a.orders.example`; with the golden module the real Scheduler
call was refused (red-team follow-up F1 in docs/planning/ex02-workflow-env-and-spec-rt.md).

Now: `variable "audience"` (string, default null, validated non-empty without surrounding whitespace when set) is
passed to `http_target.oidc_token.audience`; null leaves the provider attribute unset (it is optional, not computed),
so the planned job is the same as before. A set audience without `service_account_email` fails the plan
(lifecycle precondition): the job would send no token and the audience would be dropped silently (fail loudly).
The typed IaC intent classifies `audience` as AI (a literal or a Ref, type-checked); the platform renders it into the
module call only when the intent sets it.

Do No Harm: an intent without audience renders a byte-identical module block; the module's previous text is pinned
(sha256) and is exactly the new text minus the added lines. Hermetic: python-hcl2 parsing; the real `tofu validate`
/ `tofu test` (mock provider, production tofu + mirror) only when present."""
import hermetic_guard  # noqa: F401  (first import)

import functools
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install the gateway requirements; this file must not skip", pytrace=False)

from shared import iac_intent as ii  # noqa: E402

MODULE_ID = "scheduling-cron"
MODULE_DIRS = (os.path.join("infra", "modules", MODULE_ID),
               os.path.join("apps", "control-center", "infra", "modules", MODULE_ID))
PAYLOADS = ("shared", "mcp-servers/terraform/shared", "apps/orchestrator-gateway/shared", "apps/control-center/shared")
FILES = ("main.tf", "variables.tf", "outputs.tf")
AUDIENCE = "https://service-a.orders.example"   # example 02's reconcile audience constant

# The module before this change (main da059890).
BEFORE_SHA256 = {
    "main.tf": "369e0536a0969ae2bb52e7cf3be37b3462cef364d84d25baf10d25e85b1db221",
    "variables.tf": "199f4a172ec6b9e50661b8df1c0110273230c8c1db7b754f917a4ecb5ff9640d",
    "outputs.tf": "3d626b53692b30c163f36856d20fb56c60f4e07e3e04b979913444e740ce59ff",
}
# Exactly the lines this change added (removing them must give back the pinned module).
ADDED_MAIN = (
    "        # SCHEDULING-CRON-AUDIENCE: null leaves the attribute unset, so the token's audience stays the target URI.\n"
    "        audience = var.audience\n",
    "\n"
    "  lifecycle {\n"
    "    # SCHEDULING-CRON-AUDIENCE: an audience is carried by the OIDC token only; without a service account there is no\n"
    "    # token, so a set audience would be dropped silently. Fail the plan instead.\n"
    "    precondition {\n"
    "      condition     = var.audience == null || var.service_account_email != \"\"\n"
    "      error_message = \"scheduling-cron: audience is set but service_account_email is empty; the job sends no OIDC "
    "token, so the audience would be ignored. Set service_account_email or leave audience null.\"\n"
    "    }\n"
    "  }\n",
)
ADDED_VARIABLES = (
    "\n"
    "variable \"audience\" {\n"
    "  description = \"OIDC token audience (e.g. the exact audience constant the target service verifies). Null keeps the "
    "default: the target URI. Needs service_account_email.\"\n"
    "  type        = string\n"
    "  default     = null\n"
    "  validation {\n"
    "    condition     = var.audience == null ? true : (length(var.audience) > 0 && trimspace(var.audience) == var.audience)\n"
    "    error_message = \"audience must be null or a non-empty string without leading or trailing whitespace.\"\n"
    "  }\n"
    "}\n",
)


def _read(module_dir, name):
    with open(os.path.join(REPO_ROOT, module_dir, name), encoding="utf-8") as f:
        return f.read()


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _without(text, added):
    for block in added:
        assert text.count(block) == 1, block
        text = text.replace(block, "")
    return text


def _expr(text):
    """python-hcl2 7.x prints the HCL literals null / true inside an expression as null or None / True."""
    return text.replace("None", "null").replace("True", "true")


def _job(module_dir):
    main = hcl2.loads(_read(module_dir, "main.tf"))
    return next(r["google_cloud_scheduler_job"]["job"] for r in main["resource"] if "google_cloud_scheduler_job" in r)


def _variable(module_dir, name):
    return next(v[name] for v in hcl2.loads(_read(module_dir, "variables.tf"))["variable"] if name in v)


# ------------------------------------------------------------------------------------------------ module text
@pytest.mark.parametrize("module_dir", MODULE_DIRS)
def test_previous_module_is_the_new_one_minus_the_added_lines(module_dir):
    """Do No Harm: every pre-existing line is unchanged (pinned), only the audience lines were added."""
    assert _sha(_without(_read(module_dir, "main.tf"), ADDED_MAIN)) == BEFORE_SHA256["main.tf"]
    assert _sha(_without(_read(module_dir, "variables.tf"), ADDED_VARIABLES)) == BEFORE_SHA256["variables.tf"]
    assert _sha(_read(module_dir, "outputs.tf")) == BEFORE_SHA256["outputs.tf"]


@pytest.mark.parametrize("module_dir", MODULE_DIRS)
def test_audience_variable_is_optional_null_and_validated(module_dir):
    var = _variable(module_dir, "audience")
    assert var["type"] == "string"
    assert var["default"] is None
    assert "null" in var["description"].lower() and "service_account_email" in var["description"]
    (rule,) = var["validation"]
    assert _expr(rule["condition"]).startswith("${var.audience == null ? true : ")
    assert "length(var.audience) > 0" in rule["condition"]
    assert "trimspace(var.audience) == var.audience" in rule["condition"]


@pytest.mark.parametrize("module_dir", MODULE_DIRS)
def test_audience_goes_to_the_oidc_token_only(module_dir):
    job = _job(module_dir)
    (target,) = job["http_target"]
    (dyn,) = target["dynamic"]
    block = dyn["oidc_token"]
    assert block["for_each"] == '${var.service_account_email != "" ? [1] : []}'   # unchanged gate
    assert block["content"] == [{"service_account_email": "${var.service_account_email}",
                                 "audience": "${var.audience}"}]
    (lc,) = job["lifecycle"]
    (pre,) = lc["precondition"]
    assert _expr(pre["condition"]) == '${var.audience == null || var.service_account_email != ""}'


def test_provider_attribute_is_optional_and_not_computed():
    """null audience == attribute unset: the planned job without audience is the job planned before this change."""
    job = ii.load_artifacts().resource_schema("google_cloud_scheduler_job")
    assert job is not None
    oidc = job["block_types"]["http_target"]["block"]["block_types"]["oidc_token"]["block"]
    aud = oidc["attributes"]["audience"]
    assert aud["optional"] is True and aud["computed"] is False and aud["type"] == "string"


# ------------------------------------------------------------------------------------------------ replicas
def test_module_copies_and_the_four_payloads_carry_the_same_text():
    for name in FILES:
        disk = _read(MODULE_DIRS[0], name)
        assert _read(MODULE_DIRS[1], name) == disk, name
        for rel in PAYLOADS:
            ns = {}
            path = os.path.join(REPO_ROOT, rel, "builtin_modules_payload.py")
            with open(path, encoding="utf-8") as f:
                exec(compile(f.read(), path, "exec"), ns)  # noqa: S102 - repo-owned data module
            assert ns["BUILTIN_MODULE_FILES"][MODULE_ID][name] == disk, (rel, name)


def test_embedded_contract_lists_audience():
    from developer_agent.contract_inspector import _EMBEDDED_MODULE_CONTRACTS
    assert "audience" in _EMBEDDED_MODULE_CONTRACTS[MODULE_ID]["inputs"]


def test_catalog_classifies_audience_as_an_optional_ai_string_and_is_current():
    assert ii.MODULE_ARG_CLASS["audience"] == {"class": "AI"}
    var = ii.load_artifacts().module(MODULE_ID)["variables"]["audience"]
    assert var["class"] == "AI" and var["hcl_type"] == "string"
    assert var["default"] is None and var["has_default"] is True and var["count_driver"] is False
    r = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "scripts", "build_iac_catalog.py"), "--check"],
                       cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, env=hermetic_guard.child_env())
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]


# ------------------------------------------------------------------------------------------------ typed intent
CTX = ii.IntentContext(services={"gateway": ("module.compute", "compute-cloudrun")})
SVC = {"$ref": {"kind": "service", "service": "gateway", "output": "service_uri"}}
WSA = {"$ref": {"kind": "fact", "fact": "workload_sa_email"}}
BASE_ARGS = {"target_uri": SVC, "service_account_email": WSA, "schedule": "0 2 * * *", "job_name_suffix": "reconcile"}
# The module block an intent without audience rendered before this change (the renderer is unchanged).
BEFORE_BLOCK = {
    "job_name_suffix": "reconcile",
    "project_id": "${var.project_id}",
    "region": "${var.region}",
    "schedule": "0 2 * * *",
    "service_account_email": "${module.foundation.workload_sa_email}",
    "source": "../modules/scheduling-cron",
    "target_uri": "${module.compute.service_uri}",
}


def _gate(args):
    doc = {"schema": "iac_intent/v1", "modules": [{"module": MODULE_ID, "name": "reconcile", "args": args}],
           "resources": [], "outputs": []}
    return ii.validate_intent(doc, ii.load_artifacts(), CTX)


def _block(args):
    g = _gate(args)
    assert g.ok, [(d.code, d.message) for d in g.diagnostics]
    return json.loads(ii.render_intent(g.validated).files[ii.RENDER_PATH])["module"]["reconcile"]


def test_intent_without_audience_renders_the_same_block():
    """Negative (Do No Harm): no audience in the intent, no audience in the module call."""
    assert _block(BASE_ARGS) == BEFORE_BLOCK


def test_intent_audience_is_carried_to_the_module_call():
    assert _block(dict(BASE_ARGS, audience=AUDIENCE)) == dict(BEFORE_BLOCK, audience=AUDIENCE)


def test_intent_audience_must_be_a_string():
    g = _gate(dict(BASE_ARGS, audience=[AUDIENCE]))
    assert not g.ok and "IAC.TYPE_MISMATCH" in {d.code for d in g.diagnostics}


# ------------------------------------------------------------------------------------------------ real tofu
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")


@functools.lru_cache(maxsize=1)
def _skip_reason():
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        return "production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present"
    return None


@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if _skip_reason():
        pytest.skip(_skip_reason())
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("cron-audience-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


ROOT_TEST = '''mock_provider "google" {}

variables {
  project_id            = "cron-test"
  target_uri            = "https://gateway-abc-uc.a.run.app/api/v1/reconcile"
  service_account_email = "wsa@cron-test.iam.gserviceaccount.com"
}

run "no_audience_leaves_the_attribute_unset" {
  command = plan
  assert {
    condition     = google_cloud_scheduler_job.job.http_target[0].oidc_token[0].audience == null
    error_message = "audience = null must leave oidc_token.audience unset (the target URI applies)"
  }
}

run "audience_is_set_on_the_token" {
  command = plan
  variables {
    audience = "https://service-a.orders.example"
  }
  assert {
    condition     = google_cloud_scheduler_job.job.http_target[0].oidc_token[0].audience == "https://service-a.orders.example"
    error_message = "audience must reach oidc_token.audience"
  }
}

run "empty_audience_is_refused" {
  command = plan
  variables {
    audience = ""
  }
  expect_failures = [var.audience]
}

run "audience_without_a_token_fails_the_plan" {
  command = plan
  variables {
    service_account_email = ""
    audience              = "https://service-a.orders.example"
  }
  expect_failures = [google_cloud_scheduler_job.job]
}
'''


def test_module_validates_and_plans_with_and_without_audience(runner, tmp_path):
    wd = tmp_path / MODULE_ID
    wd.mkdir()
    for name in FILES:
        (wd / name).write_text(_read(MODULE_DIRS[0], name), encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-json", "-no-color"], cwd=wd)
    assert json.loads(r.stdout)["valid"], r.stdout[-3000:]
    (wd / "tests").mkdir()
    (wd / "tests" / "root.tftest.hcl").write_text(ROOT_TEST, encoding="utf-8")
    r = runner._run(["test", "-test-directory=tests", "-no-color"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "4 passed, 0 failed" in out, out[-4000:]

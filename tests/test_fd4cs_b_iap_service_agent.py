"""FD-4CS-b (proposed row; Fable RT 10-24 on FD-4CS): the golden compute-cloudrun module creates the workload project's
IAP service agent before it grants that agent `roles/run.invoker`.

`google_cloud_run_v2_service_iam_member.iap_agent_invoker` names `service-<project number>@gcp-sa-iap...`, which does
not exist in a fresh child project until it is created through the Service Usage API. The module now declares
`google_project_service_identity.iap_service_agent` (google-beta, `iap.googleapis.com`) under exactly the invoker
binding's condition (private + Direct IAP) and the binding `depends_on` it. Express and Agent mode both vendor this
module (Express synthesizer; terraform_engine from BUILTIN_MODULE_FILES; the terraform server's canonical alignment),
so OSS-D23 / FD-4CS private-IAP workloads both get it.

Do No Harm: with IAP off nothing changes. Removing exactly the added block and the added `depends_on` line gives the
pre-FD-4CS-b file byte for byte (sha256 below), and under `tofu test` mock providers the identity is planned 0 times
for a public service and for a private IAM-only service, once for a private Direct-IAP service. The terraform server's
compute-cloudrun text healer strips only a block named `iap_sa`; the real deploy-workspace preparation keeps this one.

Hermetic: python-hcl2 parsing; real `tofu test` at the production set only when it is on this machine (skip otherwise).
"""
import hermetic_guard  # noqa: F401  (first import)

import functools
import hashlib
import os
import sys
from pathlib import Path

import pytest

from fd4cs_b_module_delta import ADDED_BLOCK, ADDED_DEPENDS_ON

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

MODULE = os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun")
COPIES = [os.path.join(MODULE, "main.tf"),
          os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", "compute-cloudrun", "main.tf")]
PAYLOADS = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "mcp-servers/terraform/shared"]
PRE_FD4CS_B_SHA256 = "f070d7ff291de4d2470d1218f61ab4f3980ce268ef0ed9824e07a1b82b3252d6"   # main 13b49095
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")


def _text():
    with open(COPIES[0], encoding="utf-8") as f:
        return f.read()


def _resources(rtype):
    return {name: body for block in hcl2.loads(_text()).get("resource", []) if rtype in block
            for name, body in block[rtype].items()}


def test_identity_is_declared_under_the_invoker_condition_with_google_beta():
    ident = _resources("google_project_service_identity")
    assert set(ident) == {"iap_service_agent"}
    body = ident["iap_service_agent"]
    invoker = _resources("google_cloud_run_v2_service_iam_member")["iap_agent_invoker"]
    assert body["service"] == "iap.googleapis.com" and body["project"] == "${var.project_id}"
    assert body["provider"] == "${google-beta}"
    assert body["count"] == invoker["count"]
    assert invoker["depends_on"] == ["${google_project_service_identity.iap_service_agent}"]


def test_negative_without_the_addition_the_file_is_the_pre_fd4cs_b_module():
    from push_private_module_delta import pre_push_private   # PUSH-TO-PRIVATE (appended later): stripped first
    from iap_known_member_render import pre_iap_known_member   # IAP-GATE-KNOWN-MEMBER (appended later): stripped first
    from google_cloud_project_env_delta import pre_google_cloud_project_env   # CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV
    rel = "infra/modules/compute-cloudrun/main.tf"
    text = pre_push_private(rel, pre_iap_known_member(rel, pre_google_cloud_project_env(rel, _text())))
    assert text.count(ADDED_BLOCK) == 1 and text.count(ADDED_DEPENDS_ON) == 1
    before = text.replace(ADDED_BLOCK, "").replace(ADDED_DEPENDS_ON, "")
    from visible_rename_render import pre_visible_rename   # visible-rename-3: the header comment only
    before = pre_visible_rename(before)
    assert hashlib.sha256(before.encode("utf-8")).hexdigest() == PRE_FD4CS_B_SHA256


def test_disk_copies_and_every_payload_carry_the_same_module():
    text = _text()
    for path in COPIES:
        with open(path, encoding="utf-8") as f:
            assert f.read() == text, path
    for rel in PAYLOADS:
        ns = {}
        path = os.path.join(REPO_ROOT, rel, "builtin_modules_payload.py")
        with open(path, encoding="utf-8") as f:
            exec(compile(f.read(), path, "exec"), ns)  # noqa: S102 - repo-owned data module
        assert ns["BUILTIN_MODULE_FILES"]["compute-cloudrun"]["main.tf"] == text, rel


def test_the_terraform_servers_text_healer_does_not_target_this_block():
    """service.py strips `resource "google_project_service_identity" "iap_sa"` (an older block of this module). The
    new block has a different name; the deploy-workspace test in test_express_validate_end_to_end runs the real
    preparation and checks it survives."""
    assert "iap_sa" not in _resources("google_project_service_identity")


# ------------------------------------------------------------------------------------------------ real engine
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
    r = TofuRunner(tmp_path_factory.mktemp("fd4csb-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


MODULE_TEST = '''mock_provider "google" {}
mock_provider "google-beta" {}

variables {
  project_id            = "fd4csb-test"
  product_id            = "fd4csb"
  service_account_email = "workload-sa@fd4csb-test.iam.gserviceaccount.com"
}

run "public_service_has_no_iap_agent" {
  command = plan
  variables {
    allow_unauthenticated = true
  }
  assert {
    condition     = length(google_project_service_identity.iap_service_agent) == 0 && length(google_cloud_run_v2_service_iam_member.iap_agent_invoker) == 0
    error_message = "IAP off (public) must plan no IAP agent"
  }
}

run "private_iam_service_has_no_iap_agent" {
  command = plan
  variables {
    allow_unauthenticated      = false
    enable_direct_iap          = false
    authorized_invoker_members = ["user:ana@example.com"]
  }
  assert {
    condition     = length(google_project_service_identity.iap_service_agent) == 0 && length(google_cloud_run_v2_service_iam_member.iap_agent_invoker) == 0
    error_message = "IAP off (private IAM) must plan no IAP agent"
  }
}

run "private_iap_service_creates_the_agent_before_the_binding" {
  command = plan
  variables {
    allow_unauthenticated      = false
    enable_direct_iap          = true
    authorized_invoker_members = ["user:ana@example.com"]
  }
  assert {
    condition     = length(google_project_service_identity.iap_service_agent) == 1 && google_project_service_identity.iap_service_agent[0].service == "iap.googleapis.com"
    error_message = "Direct IAP must plan the IAP service agent"
  }
  assert {
    condition     = length(google_cloud_run_v2_service_iam_member.iap_agent_invoker) == 1
    error_message = "Direct IAP must plan the invoker binding"
  }
}
'''


def test_module_plans_the_agent_only_with_direct_iap(runner, tmp_path):
    wd = tmp_path / "compute-cloudrun"
    wd.mkdir()
    for name in ("main.tf", "variables.tf", "outputs.tf"):
        (wd / name).write_text(Path(MODULE, name).read_text(encoding="utf-8"), encoding="utf-8")
    (wd / "tests").mkdir()
    (wd / "tests" / "fd4csb.tftest.hcl").write_text(MODULE_TEST, encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["test", "-test-directory=tests", "-filter=tests/fd4csb.tftest.hcl", "-no-color"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "3 passed, 0 failed" in out, out[-4000:]

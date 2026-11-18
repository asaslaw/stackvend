"""PREWIRE-APIS (register row PREWIRE-APIS): the host project enables the Model Armor and Cloud Billing Budget APIs.

Both are ordinary entries of local.services, so an apply enables them through google_project_service.apis. They are
deliberately NOT in the installer's gcloud pre-enable lists: those exist only for APIs a resource of the same apply
needs before OpenTofu could enable them (compute.googleapis.com, orgpolicy.googleapis.com), and no resource of the
platform Terraform calls either of these two. Static checks only; nothing is applied.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os

import hcl2
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MAIN_TF = os.path.join(REPO_ROOT, "infra", "platform", "main.tf")
PRE_ENABLE_SCRIPTS = [os.path.join(REPO_ROOT, "scripts", "common", "platform_target.sh"),
                      os.path.join(REPO_ROOT, "scripts", "bootstrap.sh")]
NEW_APIS = ("modelarmor.googleapis.com", "billingbudgets.googleapis.com")


def _services():
    with open(MAIN_TF, encoding="utf-8") as fh:
        doc = hcl2.load(fh)
    [services] = [blk["services"] for blk in doc.get("locals", []) if "services" in blk]
    return services


@pytest.mark.parametrize("api", NEW_APIS)
def test_the_api_is_in_the_host_enabled_set_exactly_once(api):
    assert _services().count(api) == 1


def test_the_host_enabled_set_has_no_duplicates():
    services = _services()
    assert len(services) == len(set(services))


@pytest.mark.parametrize("script", PRE_ENABLE_SCRIPTS)
@pytest.mark.parametrize("api", NEW_APIS)
def test_the_api_is_not_pre_enabled_by_the_installer(script, api):
    with open(script, encoding="utf-8") as fh:
        assert api not in fh.read()

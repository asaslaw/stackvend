"""
Unit Tests for Developer Preflight AST Org Policy detection (HD-15) after S2-B B6.

Nothing heals on these org-policy facts (register HS-31a: the HC-04 strip/inject healer is deleted; FD-55 W4 deleted
HD-15 itself, whose four regex rules only gated the generation-time sweeps). Each case is reported by an exact typed
check instead (a validator never writes):
1. COMPUTE_NO_PUBLIC_IP   -> V2e POLICY.ORG_CONSTRAINT (constraints/compute.vmExternalIpAccess); no firewall injected.
2. STORAGE_UNIFORM_ACCESS -> V2e POLICY.ORG_CONSTRAINT (constraints/storage.uniformBucketLevelAccess).
3. COMPUTE_OS_LOGIN       -> V2e POLICY.ORG_CONSTRAINT (constraints/compute.requireOsLogin).
4. IAM_NO_STATIC_KEYS     -> V2a POLICY.FORBIDDEN_RESOURCE_TYPE (google_service_account_key).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.step1 import OrgConstraintValidator, PolicyValidator  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402


def _typed(path, hcl):
    files = {path: hcl}
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, vendored=frozenset(),
                                  draft={}, assembly=None, extras={}, trace_id="t")
    return [(d.code, d.detail) for d in OrgConstraintValidator().validate(ctx) + PolicyValidator().validate(ctx)]


class TestPreflightOrgPolicySelfCorrection(unittest.TestCase):
    def test_public_ip_is_reported_not_stripped_and_no_firewall_is_injected(self):
        hcl = '''
resource "google_compute_instance" "vm" {
  name         = "backend-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  network_interface {
    network    = "default"
    subnetwork = "default"
    access_config {
      // Ephemeral IP assigned
    }
  }
}
'''
        path = "infra/workload/main.tf"
        self.assertEqual(_typed(path, hcl), [("POLICY.ORG_CONSTRAINT", "constraints/compute.vmExternalIpAccess")])

    def test_bucket_without_uniform_access_is_reported_not_injected(self):
        hcl = '''
resource "google_storage_bucket" "artifacts" {
  name          = "my-bucket-artifacts"
  location      = "US"
  force_destroy = true
}
'''
        path = "infra/workload/storage.tf"
        self.assertEqual(_typed(path, hcl),
                         [("POLICY.ORG_CONSTRAINT", "constraints/storage.uniformBucketLevelAccess")])

    def test_os_login_false_is_reported_not_flipped(self):
        hcl = '''
resource "google_compute_instance" "worker" {
  name         = "worker-vm"
  machine_type = "e2-medium"
  zone         = "us-central1-b"

  metadata = {
    enable-oslogin = "false"
  }

  network_interface {
    network = "default"
  }
}
'''
        path = "infra/workload/compute.tf"
        self.assertEqual(_typed(path, hcl), [("POLICY.ORG_CONSTRAINT", "constraints/compute.requireOsLogin")])

    def test_static_service_account_key_is_forbidden_not_stripped(self):
        hcl = '''
resource "google_service_account" "sa" {
  account_id   = "app-sa"
  display_name = "Application Service Account"
}

resource "google_service_account_key" "bad_key" {
  service_account_id = google_service_account.sa.name
}
'''
        path = "infra/workload/iam.tf"
        self.assertEqual(_typed(path, hcl), [("POLICY.FORBIDDEN_RESOURCE_TYPE", None)])


if __name__ == "__main__":
    unittest.main()

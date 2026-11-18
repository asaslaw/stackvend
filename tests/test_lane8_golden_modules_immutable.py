"""Wave 1 lane 8 (FD-4AB): golden modules are platform-owned and never changed by a post-generation healer.

Enforcement: developer_agent.handler records exactly what vendor_terraform_modules wrote (vendor_platform_files) and
restores it before generate_code_files returns (restore_platform_files). The other choke point, the partition in
preflight_validator.self_correct_hcl, went with self_correct_hcl itself (FD-55 W4, register FD55-W4), and with it the
cases that drove its healer loops.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import os
import sys
import unittest
from unittest.mock import MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY_PATH, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

for m in [
    "httpx", "fastapi", "fastapi.responses", "google", "google.genai", "google.genai.types", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.logging", "google.cloud.pubsub_v1", "github", "jwt",
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

from developer_agent.terraform_engine import get_canonical_module_files  # noqa: E402

MINIMAL_MAIN = '''module "foundation" {
  source     = "../modules/workload-foundation/base"
  project_id = var.project_id
}
'''
MINIMAL_VARS = '''variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}
'''


class _ImmutabilityMixin:
    def _module_sets(self):
        canonical = get_canonical_module_files()
        sets = {"disk": canonical}
        from shared.builtin_modules_payload import BUILTIN_MODULE_FILES

        payload = {
            f"infra/modules/{mod_id}/{fname}": content
            for mod_id, fdict in BUILTIN_MODULE_FILES.items()
            for fname, content in fdict.items()
        }
        sets["builtin_payload"] = payload
        return sets

    def _workload(self, modules):
        files = dict(modules)
        files["infra/workload/main.tf"] = MINIMAL_MAIN
        files["infra/workload/variables.tf"] = MINIMAL_VARS
        files["apps/demo/main.py"] = "print('ok')\n"
        return files

    def _assert_modules_identical(self, before, after, label):
        changed = sorted(p for p, src in before.items() if after.get(p) != src)
        self.assertEqual(changed, [], f"{label}: golden module files changed")


class TestSelfCorrectHclNeverTouchesGoldenModules(_ImmutabilityMixin, unittest.TestCase):
    def test_canonical_set_is_the_85_vendored_files(self):
        # 85 + lane 10 L10-s compute-gce-worker (main/outputs/variables.tf) + lane 14 PR-0b
        # workload-foundation/base/compliance.tf - FD-4CB-b the host-only `workflows` module (main/outputs/variables.tf,
        # never vendored to a workload: tests/test_fd4cb_b_host_platform_modules.py) - FD-4CB-c the host-only
        # `cloud_build` module (main/outputs/variables.tf, same rule) + FD-4BH networking-vpc-connector
        # (main/outputs/variables.tf); the test name keeps its history
        self.assertEqual(len(get_canonical_module_files()), 86)


class TestHandlerVendoringProvenance(_ImmutabilityMixin, unittest.TestCase):
    def setUp(self):
        from developer_agent import handler

        self.handler = handler

    def test_vendor_platform_files_records_exactly_what_was_vendored(self):
        canonical = get_canonical_module_files()
        for archetype in ("cloudrun", "gke-autopilot", "gce-bastion", "event-worker", "foundation-only"):
            files = {"infra/workload/main.tf": MINIMAL_MAIN, "infra/modules/llm-made/main.tf": "# llm\n"}
            vendored, platform_files = self.handler.vendor_platform_files(dict(files), archetype)
            self.assertTrue(platform_files, archetype)
            self.assertNotIn("infra/modules/llm-made/main.tf", platform_files)
            self.assertNotIn("infra/workload/main.tf", platform_files)
            for path, content in platform_files.items():
                self.assertEqual(vendored[path], content)
                if path in canonical:
                    self.assertEqual(content, canonical[path])


if __name__ == "__main__":
    unittest.main()

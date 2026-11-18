"""FD-4N red-team H9 / FD-4AY: managed-folder containment for deploy-to-folder, create-folder and create-workload.

The only trusted root is MANAGED_WORKLOADS_FOLDER_ID (Terraform). Containment is a CRM v3 folders.get parent walk
with exact resource-name equality; API errors, organizations, depth overrun and an unset root all fail closed.
Hermetic: the folder lookup is injected; no credentials, no network.
"""
import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

import importlib.util
import os
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "cc_folders_fd4n", os.path.join(HERE, "..", "apps", "control-center", "folders.py"))
folders = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(folders)

ROOT = "111111111111"
TREE = {  # folder -> parent
    "folders/200": f"folders/{ROOT}",
    "folders/300": "folders/200",
    "folders/900": "organizations/42",
}


def lookup(name):
    if name not in TREE:
        raise PermissionError("403 outside the CC service account's scope")
    return {"name": name, "parent": TREE[name]}


class TestFolderContainment(unittest.TestCase):
    def setUp(self):
        p = patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": ROOT})
        p.start()
        self.addCleanup(p.stop)

    def test_root_and_descendants(self):
        self.assertTrue(folders.is_descendant_of_root(f"folders/{ROOT}", get_folder=lookup))
        self.assertTrue(folders.is_descendant_of_root(ROOT, get_folder=lookup))
        self.assertTrue(folders.is_descendant_of_root("folders/200", get_folder=lookup))
        self.assertTrue(folders.is_descendant_of_root("300", get_folder=lookup))
        self.assertFalse(folders.is_descendant_of_root(f"folders/{ROOT}", get_folder=lookup, include_root=False))

    def test_refusals(self):
        for bad in ("organizations/42", "folders/900", "folders/404", "", "folders/abc", "../folders/200",
                    f"folders/{ROOT}/x"):
            self.assertFalse(folders.is_descendant_of_root(bad, get_folder=lookup), bad)

    def test_cycle_or_deep_chain_fails_closed(self):
        loop = {"folders/1": "folders/2", "folders/2": "folders/1"}
        self.assertFalse(folders.is_descendant_of_root("folders/1", get_folder=lambda n: {"parent": loop[n]}))

    def test_unset_or_non_numeric_root_fails_closed_and_never_guesses(self):
        for val in ("", "folders/", "my-folder"):
            with patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": val}):
                self.assertFalse(folders.is_descendant_of_root("folders/200", get_folder=lookup))
                with self.assertRaises(folders.FolderConfigError):
                    folders.managed_root_folder()

    def test_normalize(self):
        self.assertEqual(folders.normalize_folder_name("123"), "folders/123")
        self.assertEqual(folders.normalize_folder_name("folders/123"), "folders/123")
        self.assertIsNone(folders.normalize_folder_name("organizations/123"))


if __name__ == "__main__":
    unittest.main()

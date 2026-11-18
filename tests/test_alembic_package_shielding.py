"""
Unit tests for Alembic package shielding.
Verifies that the platform never injects __init__.py into third-party library or migration folders, and (FD-4AD) never
moves, rewrites or deletes the AI's files: the alembic/ -> migrations/ normalization is deleted.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest

# Ensure apps/orchestrator-gateway is importable
GATEWAY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "orchestrator-gateway"))
if GATEWAY_DIR not in sys.path:
    sys.path.insert(0, GATEWAY_DIR)

from gatekeeper_agent.verifier import SynthesisVerifierAgent


def validate_and_heal_python_packages(files):
    # FD-55 W5 (G26): the preflight copy is deleted; the gatekeeper's purge_shadowed_package_files is the one rule
    return SynthesisVerifierAgent(product_id="testplan08-b").purge_shadowed_package_files(dict(files))


class TestAlembicPackageShielding(unittest.TestCase):
    def setUp(self):
        self.verifier = SynthesisVerifierAgent(product_id="testplan08-b")

    def _assert_add_only(self, files, out):
        for path, text in files.items():
            self.assertIn(path, out)
            self.assertEqual(out[path], text, path)   # Do No Harm: every input file byte-identical
        for path in set(out) - set(files):
            self.assertTrue(path.endswith("/__init__.py"), path)

    def test_preflight_keeps_alembic_dir_byte_identical(self):
        """FD-4AD (HB-27): the alembic/ -> migrations/ move, the alembic.ini regex and the `.py` path replace are
        deleted. An `alembic/` dir without `__init__.py` never shadows the installed package (a namespace portion loses
        to a regular package), so nothing needs to move; the shield still keeps the platform from adding an init."""
        files = {
            "apps/billing-api/requirements.txt": "fastapi>=0.110.0\nalembic>=1.13.0\nsqlalchemy>=2.0.0\n",
            "apps/billing-api/alembic.ini": "[alembic]\nscript_location = alembic\n",
            "apps/billing-api/alembic/env.py": "from logging.config import fileConfig\n",
            "apps/billing-api/alembic/versions/001_initial.py": "revision = '001'\n",
            "apps/billing-api/main.py": "from alembic import command\n",
            "apps/billing-api/db.py": 'ALEMBIC_INI = "alembic/alembic.ini"\n',
        }

        healed, actions = validate_and_heal_python_packages(files)

        self._assert_add_only(files, healed)
        self.assertNotIn("apps/billing-api/migrations/env.py", healed)
        self.assertNotIn("apps/billing-api/alembic/__init__.py", healed)
        self.assertNotIn("apps/billing-api/alembic/versions/__init__.py", healed)

    def test_preflight_keeps_preexisting_alembic_init(self):
        """FD-4AD (HB-27): an existing `__init__.py` is never deleted; the shadow it causes for an entrypoint import is
        GATE.ENTRYPOINT_SHADOWED (test_gatekeeper_shift_left_entrypoint_smoke_test)."""
        files = {
            "apps/billing-api/requirements.txt": "alembic\n",
            "apps/billing-api/alembic.ini": "[alembic]\nscript_location = alembic\n",
            "apps/billing-api/alembic/__init__.py": "# Auto-generated package init by Castor Platform\n",
            "apps/billing-api/alembic/env.py": "# env\n",
            "apps/billing-api/main.py": "import os\n",
        }

        healed, actions = validate_and_heal_python_packages(files)

        self._assert_add_only(files, healed)
        self.assertNotIn("apps/billing-api/migrations/__init__.py", healed)

    def test_gatekeeper_adds_inits_only_and_shields_alembic(self):
        files = {
            "apps/billing-api/requirements.txt": "fastapi\nalembic\n",
            "apps/billing-api/alembic.ini": "[alembic]\nscript_location = alembic\n",
            "apps/billing-api/alembic/__init__.py": "# bad init\n",
            "apps/billing-api/alembic/env.py": "# env\n",
            "apps/billing-api/routers/billing.py": "def route(): pass\n",
            "apps/billing-api/main.py": "import os\n",
        }

        cured, purged = self.verifier.purge_shadowed_package_files(files)

        self._assert_add_only(files, cured)
        self.assertEqual(purged, [])
        self.assertIn("apps/billing-api/routers/__init__.py", cured)      # legitimate package: init added
        self.assertNotIn("apps/billing-api/migrations/__init__.py", cured)
        self.assertNotIn("apps/billing-api/alembic/versions/__init__.py", cured)

    def test_gatekeeper_shift_left_entrypoint_smoke_test(self):
        # Case A: Shadowed import triggers error
        bad_files = {
            "apps/billing-api/requirements.txt": "alembic\n",
            "apps/billing-api/main.py": "from alembic import command\n",
            "apps/billing-api/alembic/__init__.py": "# bad init\n",
        }
        _, errors = self.verifier.verify_container_entrypoint_imports(bad_files)
        self.assertTrue(len(errors) > 0)
        self.assertIn("shadowed by local package directory", errors[0])

        # Case B: Clean un-shadowed import passes cleanly
        good_files = {
            "apps/billing-api/requirements.txt": "alembic\n",
            "apps/billing-api/main.py": "from alembic import command\n",
            "apps/billing-api/migrations/env.py": "# env\n",
        }
        _, errors = self.verifier.verify_container_entrypoint_imports(good_files)
        self.assertEqual(len(errors), 0)


if __name__ == "__main__":
    unittest.main()

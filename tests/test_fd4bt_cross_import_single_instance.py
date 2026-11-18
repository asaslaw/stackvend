"""
FD-4BT: a test file that imports helpers from another test file must see ONE instance of each product module.

tests/conftest.py (FD-05A) gives each test file its own sys.modules view. It used to keep the collected test module
itself in sys.modules, so ``from test_step1_s1b_loop import _ctx`` in test_step1_repair_token_bound.py (collected
later) reused s1b's copy, bound to s1b's ``shared.diagnostics`` instance, next to token_bound's fresh copy of the
same file: two ``ErrorClass`` enums, and repair_loop's ``is ErrorClass.CODE_DEFECT`` checks misrouted (5 failures,
only in that collection order). Production is unaffected (one ``shared`` per container); the hazard was the test
sandbox. Proof: run the failing order in a child pytest and require it to pass.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")


def test_s1b_loop_then_token_bound_passes_in_one_process():
    env = hermetic_guard.child_env(extra={"PROJECT_ID": "mock-stackvend-project",
                                          "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--tb=line", "-rf",
         "tests/test_step1_s1b_loop.py", "tests/test_step1_repair_token_bound.py"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, (out.stdout + out.stderr)[-4000:]

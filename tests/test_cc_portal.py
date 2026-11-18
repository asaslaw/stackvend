"""FD-08: hermetic Control Center portal tests (replaces apps/control-center/test_portal.py).

The cases live in tests/cc_portal_harness.py and run once in a clean `python -I` subprocess on top of the FD-4E
hermetic prefix (outbound sockets/DNS refused and recorded, ADC disabled, in-memory Firestore, real signed
session cookies and Google ID tokens). Each harness case is reported here as its own pytest item.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import ast
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "cc_portal_harness.py")


def _case_names():
    with open(HARNESS, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TestControlCenterPortal")
    return [n.name for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]


CASES = _case_names()


@pytest.fixture(scope="module")
def harness():
    # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy) for the child.
    env = hermetic_guard.child_env(
        drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL", "CC_INSECURE_LOCAL_COOKIES",
              "CASTOR_GIT_SERVER_URL", "GIT_SERVER_URL"),
        extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project",
               # Lane 4 FD-4AY (register L4-n): no owner/folder/repo defaults; the install configures them.
               "MANAGED_WORKLOADS_FOLDER_ID": "111111111111", "GITHUB_OWNER": "example-org",
               "GITHUB_REPO": "example-org/stackvend"})
    out = subprocess.run([sys.executable, "-I", HARNESS], capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_harness_is_hermetic(harness):
    assert harness["network_attempts"] == []
    assert harness["db_is_fake"] is True
    assert harness["test_mode_unset"] is True
    assert sorted(harness["results"]) == sorted(CASES)


@pytest.mark.parametrize("case", CASES)
def test_portal_case(harness, case):
    outcome = harness["results"][case]
    if outcome.startswith("XFAIL: "):
        pytest.xfail(outcome[:300])
    assert outcome == "pass", outcome

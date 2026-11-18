"""FD-4F H1 regression lock (review Stage C0): the QA sandbox SA can mint a *verified* Google ID token for any
audience, so Control Center must never trust it. FD-4M made CC trust only an exact platform-caller allow-list;
this test fails if the sandbox identity is ever added to it (or if a pattern grant comes back).

Runs in a clean `python -I` subprocess: CC's `config`/`identity` modules are top-level names that collide with
other apps' modules in the shared test interpreter.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import subprocess
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO, "apps", "control-center")
SANDBOX = "sa-castor-qa-sandbox@mock-stackvend-project.iam.gserviceaccount.com"

SCRIPT = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
import identity
from google.oauth2 import id_token

sandbox = sys.argv[2]
out = {"callers": sorted(identity.platform_callers())}
ri = identity.RuntimeIdentity(service_urls=("https://cc.example",), platform_callers=identity.platform_callers())
id_token.verify_oauth2_token = lambda token, req, audience=None, clock_skew_in_seconds=0: {
    "email": sandbox, "email_verified": True, "aud": audience[0]}
try:
    identity.verify_service_bearer("tok", "/api/users", ri)
    out["sandbox_bearer"] = "ACCEPTED"
except ValueError:
    out["sandbox_bearer"] = "REJECTED"
finops = "sa-castor-finops@mock-stackvend-project.iam.gserviceaccount.com"
id_token.verify_oauth2_token = lambda token, req, audience=None, clock_skew_in_seconds=0: {
    "email": finops, "email_verified": True, "aud": audience[0]}
try:  # C10 (owner 11-07): the allow-list is empty, so even the former platform caller is refused
    identity.verify_service_bearer("tok", "/api/users", ri)
    out["finops_bearer"] = "ACCEPTED"
except ValueError:
    out["finops_bearer"] = "REJECTED"
print(json.dumps(out))
"""


def test_sandbox_sa_is_never_a_control_center_platform_caller():
    # Lane 2 standing rule: the child inherits the hermetic Layer-0 env (network/ADC blocked) via child_env().
    env = hermetic_guard.child_env(drop=("K_SERVICE", "TEST_MODE"), extra={
        "PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project",
        "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc-disabled.json"})
    res = subprocess.run([sys.executable, "-I", "-c", SCRIPT, CC_DIR, SANDBOX], capture_output=True, text=True,
                         env=env, cwd=CC_DIR, timeout=120)
    assert res.returncode == 0, res.stderr[-2000:]
    out = json.loads(res.stdout.strip().splitlines()[-1])
    assert SANDBOX not in out["callers"]
    assert out["callers"] == []   # C10-MACHINE-CALLERS-OFF-CC: nothing machine-calls the Control Center
    assert out["sandbox_bearer"] == "REJECTED"
    assert out["finops_bearer"] == "REJECTED"

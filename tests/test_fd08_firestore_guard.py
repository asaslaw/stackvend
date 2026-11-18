"""FD-08: the repo-root conftest.py must stop any test from constructing a real google.cloud.firestore Client,
and fail fast when a test under apps/ attempts it (even if the code under test swallows the error).

Each scenario runs in a separate pytest subprocess inside tmp_path with a verbatim copy of the root conftest, so this
process never imports the real google.cloud.firestore (which would defeat other tests' sys.modules stubs).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import os
import shutil
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as ET

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

PROBES = {
    # Swallowed at import time (the control-center db.py pattern) -> collection error.
    "test_import_swallowed.py": """
        try:
            from google.cloud import firestore
            db = firestore.Client(project="mock-stackvend-project")
        except Exception:
            db = None

        def test_never_runs():
            assert db is None
    """,
    # Swallowed inside a test -> the test still fails.
    "test_runtime_swallowed.py": """
        def test_swallowed():
            from google.cloud import firestore
            try:
                firestore.Client(project="mock-stackvend-project")
            except Exception:
                pass
    """,
    # Async client inherits the same BaseClient.__init__.
    "test_async_client.py": """
        import pytest

        def test_async_blocked():
            from google.cloud import firestore
            with pytest.raises(RuntimeError, match="FD-08 guard"):
                firestore.AsyncClient(project="mock-stackvend-project")
    """,
    # Do No Harm: mocks and sys.modules stubs keep working.
    "test_mocked_ok.py": """
        import sys, types
        from unittest.mock import MagicMock, patch

        def test_patch_client():
            from google.cloud import firestore
            with patch("google.cloud.firestore.Client") as c:
                firestore.Client(project="x")
                c.assert_called_once()

        def test_sys_modules_stub():
            fs = types.ModuleType("google.cloud.firestore")
            fs.Client = MagicMock(name="Client")
            saved = sys.modules.get("google.cloud.firestore")
            sys.modules["google.cloud.firestore"] = fs
            try:
                import importlib
                assert importlib.import_module("google.cloud.firestore").Client is fs.Client
            finally:
                if saved is not None:
                    sys.modules["google.cloud.firestore"] = saved
    """,
    # Do No Harm: the local emulator is allowed (construction does not connect).
    # Outside apps/ (e.g. tests/): blocked, but a swallowed attempt is not reported (existing suites rely on it).
    "tests/test_nonstrict_swallowed.py": """
        def test_nonstrict():
            from google.cloud import firestore
            try:
                firestore.Client(project="mock-stackvend-project")
                built = True
            except RuntimeError as e:
                assert "FD-08 guard" in str(e)
                built = False
            assert built is False
    """,
    "test_emulator_ok.py": """
        def test_emulator(monkeypatch):
            monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "localhost:8085")
            from google.cloud import firestore
            assert firestore.Client(project="mock-stackvend-project") is not None
    """,
    # A non-local "emulator" host is not an escape hatch.
    "test_remote_emulator_blocked.py": """
        import pytest

        def test_remote_emulator(monkeypatch):
            monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "firestore.googleapis.com:443")
            from google.cloud import firestore
            with pytest.raises(RuntimeError, match="FD-08 guard"):
                firestore.Client(project="mock-stackvend-project")
    """,
}


@pytest.fixture(scope="module")
def outcomes(tmp_path_factory):
    import importlib.util
    try:
        found = importlib.util.find_spec("google.cloud.firestore_v1") is not None  # no import of the module itself
    except ImportError:
        found = False
    if not found:
        pytest.skip("google-cloud-firestore not installed")
    d = tmp_path_factory.mktemp("fd08_guard")
    shutil.copy(os.path.join(REPO, "conftest.py"), d / "conftest.py")
    # The root conftest also installs the hermetic guard (lane 2) from tests/; copy it verbatim too.
    (d / "tests").mkdir(exist_ok=True)
    for helper in ("hermetic_guard.py", "hermetic_known_leaks.py"):
        shutil.copy(os.path.join(REPO, "tests", helper), d / "tests" / helper)
    (d / "pytest.ini").write_text("[pytest]\n")
    for name, src in PROBES.items():
        # Probes mirror the repo layout: strict checks apply to apps/<service>/test_*.py.
        dest = d / name if "/" in name else d / "apps" / "demo" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(textwrap.dedent(src))
    # hermetic_guard.child_env: Layer-0 env (no ADC, loopback proxy, no git credentials) for the child pytest.
    env = hermetic_guard.child_env(drop=("FIRESTORE_EMULATOR_HOST",), extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--continue-on-collection-errors", "--import-mode=importlib",
         f"--junitxml={d / 'r.xml'}", str(d)],
        cwd=d, capture_output=True, text=True, timeout=300, env=env)
    res = {}
    for case in ET.parse(d / "r.xml").getroot().iter("testcase"):
        key = f"{case.get('classname')}::{case.get('name')}"
        kinds = [c.tag for c in case if c.tag in ("failure", "error", "skipped")]
        msg = " ".join((c.get("message") or "") + (c.text or "") for c in case)
        res[key] = (kinds[0] if kinds else "passed", msg)
    return res, out.stdout + out.stderr


def _find(res, needle):
    hits = [v for k, v in res.items() if needle in k]
    assert hits, f"{needle} not in {sorted(res)}"
    return hits


def test_import_time_swallowed_attempt_fails_collection(outcomes):
    res, log = outcomes
    (kind, msg), = _find(res, "test_import_swallowed")
    assert kind == "error", log[-3000:]
    assert "FD-08 guard" in msg


def test_runtime_swallowed_attempt_fails_test(outcomes):
    res, log = outcomes
    (kind, msg), = _find(res, "::test_swallowed")
    assert kind in ("failure", "error"), log[-3000:]
    assert "FD-08 guard" in msg


def test_async_client_blocked(outcomes):
    res, _ = outcomes
    (kind, msg), = _find(res, "::test_async_blocked")
    # The raise is asserted inside the probe; the recorded attempt still fails it at teardown.
    assert kind in ("failure", "error") and "FD-08 guard" in msg


def test_remote_emulator_host_not_an_escape_hatch(outcomes):
    res, _ = outcomes
    (kind, msg), = _find(res, "::test_remote_emulator")
    assert kind in ("failure", "error") and "FD-08 guard" in msg


def test_mocks_stubs_and_local_emulator_unaffected(outcomes):
    res, log = outcomes
    for needle in ("::test_patch_client", "::test_sys_modules_stub", "::test_emulator"):
        (kind, msg), = _find(res, needle)
        assert kind == "passed", (needle, msg, log[-3000:])


def test_outside_apps_blocked_but_not_strict(outcomes):
    res, log = outcomes
    (kind, msg), = _find(res, "::test_nonstrict")
    assert kind == "passed", (msg, log[-3000:])

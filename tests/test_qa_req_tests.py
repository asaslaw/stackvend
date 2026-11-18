"""QA-REQ-TESTS + QA-START-MSG (owner 10-27; diagnosis docs/handoff/qa-exit4-diagnosis.md).

Live failure: a single-service FastAPI workload keeps its tests in the root `tests/`; `tests/conftest.py` imports
`fastapi.testclient.TestClient`, which needs httpx. The QA sandbox job installs only `apps/<svc>/requirements.txt`,
and since FD-4AD the add-only requirements contract read only `apps/<svc>/**/*.py`, so nothing added httpx and pytest
exited 4 (conftest ImportError) before any test ran, reported as "pytest exited 4 without a readable junit report".

A: the contract also reads the root test files the QA job runs with the single service's venv (the job's own layout
   rule, parity-tested here), add-only; every negative case is byte-identical (Invariant 1).
B: when pytest stops without writing a junit report, the diagnostic's message leads with pytest's own first error block.
D: the end-to-end chain that failed live, hermetic: gatekeeper contract -> the QA job's real layout + requirements
   collection -> the job's real venv/pip/pytest run against a local index (fake fastapi + httpx wheels, loopback only).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import dataclasses
import hashlib
import json
import os
import sys

import pytest

import qa_sandbox_support as sup

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gatekeeper_agent import requirements_contract as rc  # noqa: E402
from qa_source import deterministic_tar_gz  # noqa: E402

sj = sup.load_sandbox_job("sandbox_job_qa_req_tests")

HTTPX = "httpx>=0.27.0"
MAIN = (
    "from fastapi import FastAPI\n\n"
    "app = FastAPI()\n\n\n"
    "@app.get('/health')\n"
    "def health():\n"
    "    return {'status': 'healthy'}\n"
)
CONFTEST = (
    "import pytest\n"
    "from fastapi.testclient import TestClient\n\n"
    "from main import app\n\n\n"
    "@pytest.fixture\n"
    "def client():\n"
    "    return TestClient(app)\n"
)
TEST_MAIN = "def test_health(client):\n    assert client.get('/health') == {'status': 'healthy'}\n"


def single_service(**extra):
    """The live shape (testplan01-d2): one service, tests in the root `tests/`, requirements without httpx."""
    files = {
        "apps/api/main.py": MAIN,
        "apps/api/requirements.txt": "fastapi>=0.110.0\n",
        "tests/conftest.py": CONFTEST,
        "tests/test_main.py": TEST_MAIN,
        "README.md": "# demo\n",
    }
    files.update(extra)
    return {k: v for k, v in files.items() if v is not None}


# ================================================================================================== A: the contract
def test_root_tests_testclient_appends_httpx_to_the_single_service():
    files = single_service()
    out, actions = rc.append_missing_requirements(files)
    assert out["apps/api/requirements.txt"] == "fastapi>=0.110.0\n" + HTTPX + "\n"
    assert actions == [f"appended ['{HTTPX}'] to apps/api/requirements.txt"]
    assert {k: v for k, v in out.items() if k != "apps/api/requirements.txt"} == \
        {k: v for k, v in files.items() if k != "apps/api/requirements.txt"}


def test_castor_shape_root_requirements_is_never_read_or_touched():
    """testplan01-d (castor): the AI wrote httpx into a ROOT requirements.txt the QA job never reads. The service file
    gains httpx; the root file stays byte-identical (the contract never touches it)."""
    files = single_service(**{"requirements.txt": "httpx>=0.27.0\npytest\npytest-asyncio\nruff\n"})
    out, _ = rc.append_missing_requirements(files)
    assert out["apps/api/requirements.txt"] == "fastapi>=0.110.0\n" + HTTPX + "\n"
    assert out["requirements.txt"] == files["requirements.txt"]


def test_root_conftest_counts_for_the_single_service():
    files = single_service(**{"tests/conftest.py": None, "conftest.py": CONFTEST})
    out, _ = rc.append_missing_requirements(files)
    assert out["apps/api/requirements.txt"].endswith(HTTPX + "\n")


@pytest.mark.parametrize("declared", ["httpx", "HTTPX==0.28.1", "httpx>=0.27,<1  # test client"])
def test_negative_httpx_already_declared_is_byte_identical(declared):
    files = single_service(**{"apps/api/requirements.txt": f"fastapi>=0.110.0\n{declared}\n"})
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_negative_runner_toolchain_is_never_appended():
    """`pytest` / `pytest-timeout` are the QA job's own pinned toolchain: a root-test import of them adds nothing."""
    files = single_service(**{"tests/test_main.py": "import pytest\nimport pytest_timeout\n\n" + TEST_MAIN,
                              "apps/api/requirements.txt": "fastapi>=0.110.0\nhttpx\n"})
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_negative_local_names_in_root_tests_never_become_distributions():
    """Root packages/modules, modules under tests/ and the service's own modules are local, even when a catalog
    distribution has the same import name (redis, yaml, requests)."""
    files = {
        "apps/api/main.py": "app = object()\n",
        "apps/api/requests.py": "X = 1\n",                       # service-local, named like a catalog import
        "apps/api/requirements.txt": "",
        "contracts/__init__.py": "",
        "contracts/models.py": "M = 1\n",
        "yaml.py": "Y = 1\n",                                   # root module named like a catalog import
        "tests/helpers/__init__.py": "",
        "tests/helpers/redis.py": "R = 1\n",                     # module under tests/ named like a catalog import
        "tests/test_local.py": ("import contracts.models\nimport yaml\nimport redis\nimport requests\n"
                                "from helpers import redis as r\nfrom main import app\nfrom apps.api import main\n"
                                "import tests.helpers\nimport os, json\nfrom . import x\n\ndef test_x():\n    pass\n"),
    }
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_negative_multi_service_root_tests_are_not_read():
    """With more than one service the QA job rejects a root tests/ (PY.TEST_LAYOUT): nothing is read there, and the
    result equals the result without the root tests (pre-QA-REQ-TESTS behavior)."""
    base = {"apps/a/main.py": "import yaml\n", "apps/a/requirements.txt": "",
            "apps/b/main.py": "x = 1\n", "apps/b/requirements.txt": "fastapi\n"}
    with_root = dict(base, **{"tests/conftest.py": CONFTEST, "tests/test_x.py": "import redis\n"})
    out, actions = rc.append_missing_requirements(with_root)
    base_out, base_actions = rc.append_missing_requirements(base)
    assert actions == base_actions
    assert {k: v for k, v in out.items() if not k.startswith("tests/")} == base_out


def test_negative_multi_service_service_tests_unchanged():
    """apps/<svc>/tests/ were always read as service files (FD-4AD; incl. its `pytest` row): unchanged."""
    files = {"apps/a/main.py": "x = 1\n", "apps/a/requirements.txt": "",
             "apps/a/tests/test_a.py": "import pytest\nfrom fastapi.testclient import TestClient\n",
             "apps/b/main.py": "x = 1\n", "apps/b/requirements.txt": ""}
    out, _ = rc.append_missing_requirements(files)
    assert out["apps/a/requirements.txt"] == "fastapi>=0.110.0\nhttpx>=0.27.0\npytest>=8.0.0\n"
    assert out["apps/b/requirements.txt"] == ""


def test_negative_non_python_single_service_is_untouched():
    """A requirements.txt-only service without `.py` (the contract covers Python services only): unchanged."""
    files = {"apps/web/requirements.txt": "", "apps/web/index.js": "1\n", "tests/test_x.py": CONFTEST}
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_negative_unparseable_root_test_is_skipped():
    files = single_service(**{"tests/conftest.py": "from fastapi.testclient import TestClient\ndef f(:\n"})
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_negative_no_root_tests_is_unchanged():
    files = single_service(**{"tests/conftest.py": None, "tests/test_main.py": None})
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_idempotent():
    out, _ = rc.append_missing_requirements(single_service())
    again, actions = rc.append_missing_requirements(out)
    assert again == out and actions == []


# ---------------------------------------------------------------------------------- parity with the QA sandbox job
PARITY_TREES = [
    single_service(),
    {"apps/a/main.py": "x = 1\n", "tests/test_x.py": "x = 1\n"},                       # requirements created
    {"apps/a/requirements.txt": "", "apps/a/main.py": "x = 1\n", "apps/a/x/requirements.txt": "",
     "tests/test_x.py": "x = 1\n"},                                                    # nested file: not a service
    {"apps/a/main.py": "x = 1\n", "apps/b/main.py": "x = 1\n", "tests/test_x.py": "x = 1\n"},   # two (created)
    {"apps/a/main.py": "x = 1\n", "apps/shared/requirements.txt": "", "tests/t.py": "x = 1\n"},  # shared counts in QA
    {"apps/a/main.py": "x = 1\n", "apps/shared/util.py": "x = 1\n", "tests/t.py": "x = 1\n"},   # shared .py: no svc
    {"apps/web/requirements.txt": "", "apps/web/index.js": "1\n", "tests/t.py": "x = 1\n"},      # not Python
    {"apps/a.b/requirements.txt": "", "apps/a.b/main.py": "x = 1\n", "tests/t.py": "x = 1\n"},   # dotted name
    {"apps/a/main.py": "x = 1\n", "apps/a/requirements.txt": ""},                                 # no root tests
    {"apps/a/main.py": "x = 1\n", "tests/README.md": "x\n"},                                      # non-.py root test
    {"README.md": "x\n", "tests/test_x.py": "x = 1\n"},                                            # no service
]


@pytest.mark.parametrize("files", PARITY_TREES)
def test_single_service_rule_matches_discover_layout(files):
    """The contract's rule equals the QA job's on the tree the contract returns: the same service list, and the root
    tests/ are read for exactly the service the job runs them with (when it is a Python service)."""
    out, _ = rc.append_missing_requirements(files)
    layout = sj.discover_layout(out)
    assert rc.qa_services(files) == [s.name for s in layout.services]
    runs_root = [s.name for s in layout.services if "tests" in s.test_roots]
    expected = runs_root[0] if runs_root and runs_root[0] in rc.python_services(files) else None
    assert rc.root_tests_service(files) == expected


def test_runner_toolchain_parity():
    """The skipped distributions are exactly the job's own test toolchain (default Toolchain + its constraints)."""
    default = next(f for f in dataclasses.fields(sj.Toolchain) if f.name == "test_packages").default
    assert {rc.canonical_name(n) for n in default} == rc.QA_RUNNER_TEST_TOOLCHAIN
    with open(os.path.join(sup.QA_DIR, "qa_toolchain_constraints.txt")) as f:
        pinned = {rc.requirement_name(ln.strip()) for ln in f if ln.strip() and not ln.startswith("#")}
    # Row QA-PYTEST-CRASH: the constraints also pin allow-listed pytest plugins the job installs only when a workload
    # names them (never into every venv), so a test-file import of one is still appended to the requirements.
    assert rc.QA_RUNNER_TEST_TOOLCHAIN <= pinned
    assert pinned - rc.QA_RUNNER_TEST_TOOLCHAIN == {"pytest-asyncio"}
    assert pinned - rc.QA_RUNNER_TEST_TOOLCHAIN <= {rc.canonical_name(n) for n in sj.OPTIONAL_PYTEST_PLUGIN_DISTS}


def test_verifier_runs_the_contract_on_root_tests():
    """The gatekeeper's pre-commit pass (verifier.reconcile_service_requirements) is the caller: it gains httpx."""
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    out = SynthesisVerifierAgent("prod").reconcile_service_requirements(single_service())
    assert out["apps/api/requirements.txt"] == "fastapi>=0.110.0\n" + HTTPX + "\n"


# ============================================================================================ B: pytest start message
def test_first_output_block_takes_lines_up_to_the_first_blank_line():
    text = "\n\nImportError while loading conftest '/x/tests/conftest.py'.\nconftest.py:2: in <module>\n" \
           "E   RuntimeError: needs httpx\n\nlater block\n"
    assert sj.first_output_block(text) == ("ImportError while loading conftest '/x/tests/conftest.py'.\n"
                                           "conftest.py:2: in <module>\nE   RuntimeError: needs httpx")
    assert sj.first_output_block("") == "" and sj.first_output_block("\n  \n") == ""


def test_first_output_block_keeps_first_and_last_lines_when_long():
    lines = ["ImportError while loading conftest 'c.py'."] + [f"  frame {i} " + "x" * 50 for i in range(100)] + \
            ["E   RuntimeError: needs httpx"]
    block = sj.first_output_block("\n".join(lines), limit=600)
    assert len(block) <= 600
    assert block.startswith("ImportError while loading conftest 'c.py'.\n...\n")
    assert block.endswith("E   RuntimeError: needs httpx")


def test_head_file_drops_a_line_cut_by_the_limit(tmp_path):
    p = tmp_path / "log"
    p.write_bytes(b"first line\nsecond https://signed.example/very-long-url\n")
    assert sj._head_file(str(p), 20) == "first line\n"
    assert sj._head_file(str(p), 10_000) == p.read_text()
    assert sj._head_file(str(tmp_path / "missing"), 100) == ""


# ======================================================================================= D: the live chain, hermetic
def test_chain_contract_then_qa_layout_and_requirements(tmp_path):
    """Contract output -> the QA job's discover_layout + check_requirements (what pip is given): httpx is there, and
    the root tests run with that service. Before the contract it is not (the live failure)."""
    def qa_requirements(files):
        src = tmp_path / ("src-%d" % len(list(tmp_path.iterdir())))
        for rel, text in files.items():
            (src / rel).parent.mkdir(parents=True, exist_ok=True)
            (src / rel).write_text(text)
        layout = sj.discover_layout(files)
        assert layout.diagnostics == []
        assert [(s.rel, s.test_roots) for s in layout.services] == [("apps/api", ["tests"])]
        assert sj.check_requirements(str(src), layout.services) == []
        return layout.services[0].requirements

    files = single_service()
    assert qa_requirements(files) == ["fastapi>=0.110.0"]
    out, _ = rc.append_missing_requirements(files)
    assert qa_requirements(out) == ["fastapi>=0.110.0", HTTPX]


FAKE_FASTAPI = {
    "fastapi/__init__.py": (
        "class FastAPI:\n"
        "    def __init__(self):\n"
        "        self.routes = {}\n\n"
        "    def get(self, path):\n"
        "        def deco(fn):\n"
        "            self.routes[path] = fn\n"
        "            return fn\n"
        "        return deco\n"
    ),
    # Same shape as starlette.testclient: the HTTP client is imported at module import time.
    "fastapi/testclient.py": (
        "try:\n"
        "    import httpx  # noqa: F401\n"
        "except ImportError:\n"
        "    raise RuntimeError('The starlette.testclient module requires the httpx package to be installed.')\n\n\n"
        "class TestClient:\n"
        "    def __init__(self, app):\n"
        "        self.app = app\n\n"
        "    def get(self, path):\n"
        "        return self.app.routes[path]()\n"
    ),
}


@pytest.fixture(scope="module")
def wheelhouse(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("wheelhouse-qa-req"))
    index = sup.build_wheelhouse(d)
    index["fastapi"] = [sup.build_wheel(d, "fastapi", "0.115.0", FAKE_FASTAPI)]
    index["httpx"] = [sup.build_wheel(d, "httpx", "0.28.1", {"httpx.py": "VERSION = '0.28.1'\n"})]
    return d, index


@pytest.fixture()
def cloud(wheelhouse):
    c = sup.FakeCloud(wheelhouse[0], dict(wheelhouse[1]))
    yield c
    c.close()


@pytest.fixture()
def toolchain(cloud, tmp_path):
    return sup.make_toolchain(sj, cloud, str(tmp_path))


def run_job(cloud, toolchain, files):
    archive = deterministic_tar_gz({k: v.encode() for k, v in files.items()})
    cloud.source = archive
    env = {
        "QA_SOURCE_URL": cloud.url("source.tar.gz"), "QA_SOURCE_SHA256": hashlib.sha256(archive).hexdigest(),
        "QA_STATIC_PUT_URL": cloud.url("static.json"), "QA_REPORT_PUT_URL": cloud.url("report.json"),
        "QA_NONCE": "0123456789abcdef0123456789abcdef", "QA_TRACE_ID": "trace-qa-req", "QA_COMMIT_SHA": "c" * 40,
        "QA_PRODUCT_ID": "demo-app", "QA_DEADLINE_SECONDS": "300",
    }
    code = sj.run_job(env, toolchain=toolchain, transport=sj.HttpTransport(sleep=lambda s: None))
    raw = cloud.objects.get("report.json")
    return code, (json.loads(raw) if raw else None)


def test_live_failure_reproduced_and_message_leads_with_pytest_error(cloud, toolchain):
    """Before the contract: pytest exits 4 at conftest import (no junit). QA-START-MSG: the message leads with
    pytest's own error block, which ends with the RuntimeError naming the missing package; detail is kept."""
    code, report = run_job(cloud, toolchain, single_service())
    assert code == 10, report
    [d] = [d for d in report["diagnostics"] if d["severity"] == "error"]
    # QA-PYTEST-CRASH (Opus RT F2/F3): exit 4 before any junit is typed PYTEST.STARTUP_ERROR, scoped to the service
    assert d["code"] == "PYTEST.STARTUP_ERROR" and d["file"] == "apps/api/requirements.txt"
    assert d["message"].startswith("ImportError while loading conftest ")
    assert "RuntimeError: The starlette.testclient module requires the httpx package" in d["message"]
    assert "(pytest stopped before writing a junit report for apps/api: exit 4; full output in detail)" in d["message"]
    assert "ImportError while loading conftest" in d["detail"]


def test_after_the_contract_qa_passes(cloud, toolchain):
    out, _ = rc.append_missing_requirements(single_service())
    code, report = run_job(cloud, toolchain, out)
    assert code == 0, report
    assert report["tests_total"] == 1 and report["tests_failed"] == 0


def test_negative_unreadable_junit_keeps_the_old_message(cloud, toolchain):
    """A junit that exists but does not parse is not a start failure: the message is unchanged."""
    forge = ("import os\n\ndef test_forge(request):\n"
             "    open(request.config.option.xmlpath, 'w').write('<not xml')\n"
             "    os._exit(1)\n")
    out, _ = rc.append_missing_requirements(single_service(**{"tests/test_main.py": forge}))
    code, report = run_job(cloud, toolchain, out)
    assert code == 10, report
    [d] = [d for d in report["diagnostics"] if d["code"] == "PYTEST.REPORT_INVALID"]
    assert d["message"] == "pytest exited 1 without a readable junit report (ParseError)"

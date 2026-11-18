"""Lane 3 PR-B: the gateway <-> QA job contract, pinned from BOTH sides.

1. Loop tests: the gateway's real `QAJobClient.run` stages a real `qa_source.deterministic_tar_gz`, signs URLs and
   "runs the job"; the fake Run API executes the real `sandbox_job.run_job` with exactly the env overrides the
   gateway sent, reports the job's exit code the way Cloud Run does, and the gateway classifies the artifacts the
   job wrote. Signed URLs and the package index are loopback fakes (qa_sandbox_support.FakeCloud).
2. Static pins: env names, exit codes, caps, headers, deadlines, archive caps, entrypoint, job imports.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import os

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
import qa_job_client as gw
import qa_source
from gate_errors import ErrorClass

sj = sup.load_sandbox_job("sandbox_job_contract")

CFG = gw.QAJobConfig("p", "r", "qa-sandbox-test-runner", "bkt", "sa-castor-qa-sandbox@p.iam.gserviceaccount.com")
# Row L3-PRB-g (FD-4BR): dispatch also requires the egress contract (args + vpcAccess; tests/test_fd4br_qa_readiness.py).
JOB = {"template": {"template": {
    "serviceAccount": CFG.sandbox_sa, "timeout": "900s",
    "containers": [{"image": "i", "args": gw.expected_job_args(CFG)}],
    "vpcAccess": {"egress": "ALL_TRAFFIC", "networkInterfaces": [{"network": gw.expected_networks(CFG)[0]}]},
}}}
EXEC_NAME = f"{CFG.job_path}/executions/e1"


class _Res:
    def __init__(self, status=200, payload=None):
        self.status_code, self._p = status, payload

    def json(self):
        return self._p


class CloudRunThatRunsTheJob:
    """Run API fake: `:run` executes sandbox_job.run_job with the override env; the execution/tasks documents carry
    the exit code exactly as Cloud Run v2 JSON does (proto3: exitCode omitted when 0)."""

    def __init__(self, toolchain):
        self.toolchain = toolchain
        self.sent_env = None
        self.sent_overrides = None
        self.exit_code = None

    def get(self, url, **kw):
        if url.endswith("/tasks"):
            last = {} if self.exit_code == 0 else {"exitCode": self.exit_code}
            return _Res(payload={"tasks": [{"lastAttemptResult": last}]})
        if "/executions/" in url:
            counts = {"succeededCount": 1} if self.exit_code == 0 else {"failedCount": 1}
            return _Res(payload={"completionTime": "t", **counts})
        return _Res(payload=JOB)

    def post(self, url, json=None, **kw):
        if url.endswith(":run"):
            self.sent_overrides = json["overrides"]
            self.sent_env = {e["name"]: e["value"] for e in json["overrides"]["containerOverrides"][0]["env"]}
            self.exit_code = sj.run_job(dict(self.sent_env), toolchain=self.toolchain,
                                        transport=sj.HttpTransport(sleep=lambda s: None))
            return _Res(200, {"metadata": {"name": EXEC_NAME}})
        return _Res(payload={})


class StoreOnFakeCloud:
    """The gateway's GcsStore interface (upload / sign / download) backed by the loopback signed-URL fake."""

    def __init__(self, cloud):
        self.cloud = cloud
        self.signed = []

    def upload(self, name, data, content_type):
        assert name.endswith("/source.tar.gz") and content_type == "application/gzip"
        self.cloud.source = data

    def sign(self, name, method, ttl_s, headers=None):
        self.signed.append((name.rsplit("/", 1)[1], method, headers))
        return self.cloud.url(name.rsplit("/", 1)[1])

    def download(self, name, max_bytes):
        return self.cloud.objects.get(name.rsplit("/", 1)[1])


@pytest.fixture(scope="module")
def wheelhouse(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("wheelhouse"))
    return d, sup.build_wheelhouse(d)


@pytest.fixture()
def cloud(wheelhouse):
    c = sup.FakeCloud(*wheelhouse)
    yield c
    c.close()


def gateway_run(cloud, tmp_path, files):
    run_api = CloudRunThatRunsTheJob(sup.make_toolchain(sj, cloud, str(tmp_path)))
    store = StoreOnFakeCloud(cloud)
    clock = {"t": 0.0}
    client = gw.QAJobClient(CFG, run_api, store, sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
                            clock=lambda: clock["t"], poll_interval_s=1)
    tar = qa_source.deterministic_tar_gz({k: v.encode() for k, v in files.items()})
    outcome = client.run(tar_bytes=tar, commit_sha="a" * 40, trace_id="tr-contract-1", product_id="demo-app",
                         deadline=10_000)
    return outcome, run_api, store


APP = {
    "apps/svc/main.py": "def health():\n    return {'status': 'healthy'}\n",
    "apps/svc/requirements.txt": "",
    "tests/test_main.py": "from main import health\n\ndef test_health():\n    assert health()['status'] == 'healthy'\n",
}


def test_loop_pass(cloud, tmp_path):
    outcome, run_api, store = gateway_run(cloud, tmp_path, APP)
    assert run_api.exit_code == 0
    assert outcome.passed is True and outcome.error_class is None, outcome
    assert outcome.report["tests_total"] == 1 and outcome.static["index_reachable"] is True
    # The gateway signed exactly one GET and two create-only PUTs, and the job used exactly those three.
    assert sorted((n, m) for n, m, _ in store.signed) == [("report.json", "PUT"), ("source.tar.gz", "GET"),
                                                         ("static.json", "PUT")]
    assert cloud.put_order == ["static.json", "report.json"]


def test_loop_failing_test_is_code_defect_with_diagnostics(cloud, tmp_path):
    files = dict(APP, **{"tests/test_main.py": "def test_x():\n    assert 2 + 2 == 5\n"})
    outcome, run_api, _ = gateway_run(cloud, tmp_path, files)
    assert run_api.exit_code == 10
    assert outcome.error_class == ErrorClass.CODE_DEFECT
    assert outcome.diagnostics[0]["code"] == "PY.TEST_FAILED" and outcome.diagnostics[0]["file"] == "tests/test_main.py"


def test_loop_static_failure_is_code_defect_without_report(cloud, tmp_path):
    files = dict(APP, **{"apps/svc/Dockerfile": "FROM scratch\n"})
    outcome, run_api, _ = gateway_run(cloud, tmp_path, files)
    assert run_api.exit_code == 10 and outcome.report is None
    assert outcome.error_class == ErrorClass.CODE_DEFECT and outcome.diagnostics[0]["code"] == "POLICY.DOCKERFILE"


def test_loop_index_down_is_gate_unavailable(cloud, tmp_path):
    cloud.index_up = False
    outcome, run_api, _ = gateway_run(cloud, tmp_path, APP)
    assert run_api.exit_code == 11
    assert outcome.passed is False and outcome.error_class == ErrorClass.GATE_UNAVAILABLE


def test_loop_forged_report_is_gate_unavailable(cloud, tmp_path):
    cloud.objects["report.json"] = b'{"schema_version": 1, "passed": true}'  # pre-written: the job's PUT gets 412
    outcome, run_api, _ = gateway_run(cloud, tmp_path, APP)
    assert run_api.exit_code == 11 and outcome.error_class == ErrorClass.GATE_UNAVAILABLE


# ------------------------------------------------------------------------------------------------------------------
# Static pins (both sides)
# ------------------------------------------------------------------------------------------------------------------
def _gateway_env_names():
    """Names of the env overrides QAJobClient.run sends (read from the code, not restated)."""
    src = open(os.path.join(sup.GW_DIR, "qa_job_client.py")).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "run":
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "env" for t in sub.targets)
                        and isinstance(sub.value, ast.Dict)):
                    return {k.value for k in sub.value.keys}
    raise AssertionError("env dict not found in QAJobClient.run")


def test_env_names_are_exactly_what_the_gateway_sends():
    assert set(sj.REQUIRED_INPUTS) == _gateway_env_names()


def test_loop_overrides_carry_only_the_contract(cloud, tmp_path):
    _, run_api, _ = gateway_run(cloud, tmp_path, APP)
    assert set(run_api.sent_env) == set(sj.REQUIRED_INPUTS)
    assert int(run_api.sent_env["QA_DEADLINE_SECONDS"]) == gw.JOB_INTERNAL_DEADLINE_S
    assert run_api.sent_overrides["timeout"] == f"{gw.JOB_TASK_TIMEOUT_S}s" and run_api.sent_overrides["taskCount"] == 1


def test_exit_codes_caps_and_headers_match():
    assert (sj.EXIT_PASS, sj.EXIT_CODE_DEFECT, sj.EXIT_RUNNER_ERROR, sj.EXIT_TIMEOUT_DEFECT) == (
        gw.EXIT_PASS, gw.EXIT_CODE_DEFECT, gw.EXIT_RUNNER_ERROR, gw.EXIT_TIMEOUT_DEFECT)
    assert sj.MAX_ARTIFACT_BYTES == gw.MAX_ARTIFACT_BYTES
    assert sj.MAX_DIAGNOSTICS == gw.MAX_DIAGNOSTICS
    assert sj.MAX_FIELD_CHARS == gw.MAX_FIELD_CHARS
    assert sj.CREATE_ONLY_HEADERS == gw.CREATE_ONLY_HEADERS
    assert sj.MAX_MEMBERS == qa_source.MAX_MEMBERS and sj.MAX_TOTAL_BYTES == qa_source.MAX_TOTAL_BYTES


def test_deadlines_nest():
    # gateway internal deadline <= what the job accepts < Cloud Run task timeout (room to PUT report.json after a
    # timeout in untrusted code); the job's own copy of the task timeout is the gateway's (red-team F9).
    assert gw.JOB_INTERNAL_DEADLINE_S <= sj.MAX_DEADLINE_S < gw.JOB_TASK_TIMEOUT_S
    assert sj.TASK_TIMEOUT_S == gw.JOB_TASK_TIMEOUT_S


def test_artifact_models_accept_every_field_the_job_writes():
    static_fields = {"schema_version", "nonce", "passed", "diagnostics", "diagnostics_truncated", "index_reachable",
                     "toolchain"}
    report_fields = {"schema_version", "nonce", "passed", "diagnostics", "diagnostics_truncated", "tests_total",
                     "tests_failed", "logs_tail"}
    assert static_fields <= set(gw.StaticV1.model_fields)
    assert report_fields <= set(gw.ReportV1.model_fields)
    # QA-REPAIR-MISSING-MODULE: `missing_module` is written only with a module name (the import smoke's typed fact)
    assert set(sj.diag("t", "C.X", "m")) | {"missing_module"} == set(gw.DiagnosticIn.model_fields)
    assert set(sj.diag("t", "C.X", "m", missing_module="asyncpg")) == set(gw.DiagnosticIn.model_fields)


def test_entrypoint_matches_terraform_and_procfile():
    tf = open(os.path.join(sup.REPO_ROOT, "infra", "platform", "qa_sandbox.tf")).read()
    assert 'args    = ["python3", "-m", "sandbox_job"]' in tf
    with open(os.path.join(sup.QA_DIR, "Procfile")) as f:
        assert f.read().strip() == "web: python3 -m sandbox_job"
    assert os.path.isfile(os.path.join(sup.QA_DIR, "sandbox_job.py"))
    with open(os.path.join(sup.QA_DIR, ".python-version")) as f:
        # Review H9: same minor as generated services. FD-4BS: the QA job trigger (and deploy-services.sh's QA path)
        # build on the generated-workload builder, which serves 3.13 (tests/test_fd4bs_qa_builder.py).
        assert f.read().strip() == "3.13"


def test_job_imports_only_stdlib_and_path_safety():
    """The job holds no client library: no google.*, requests, firestore, git, fastapi (plan B1 "not in the job").
    `packaging` (the PEP 508 parser pip itself uses) is the one third-party import (red-team F1)."""
    import sys

    tree = ast.parse(open(os.path.join(sup.QA_DIR, "sandbox_job.py")).read())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    assert mods - set(sys.stdlib_module_names) == {"shared", "packaging", "release_info"}

    # SAT-11 (FD-7C P3a): `release_info` is the job's own stdlib-only release.json reader (one `stackvend.release` log
    # line at start; byte-identical copies, tests/test_sat11_release_record.py). It must stay stdlib-only.
    ri_tree = ast.parse(open(os.path.join(sup.QA_DIR, "release_info.py")).read())
    ri_mods = {a.name.split(".")[0] for n in ast.walk(ri_tree) if isinstance(n, ast.Import) for a in n.names}
    ri_mods |= {n.module.split(".")[0] for n in ast.walk(ri_tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert ri_mods <= set(sys.stdlib_module_names) | {"__future__"}, ri_mods
    shared_imports = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module
                      and n.module.startswith("shared")}
    assert shared_imports == {"shared.path_safety"}
    assert os.path.isfile(os.path.join(sup.QA_DIR, "shared", "path_safety.py"))


def test_job_reads_no_test_mode():
    src = open(os.path.join(sup.QA_DIR, "sandbox_job.py")).read()
    assert "TEST_MODE" not in src.split('"""', 2)[2]  # the docstring may mention it, the code may not

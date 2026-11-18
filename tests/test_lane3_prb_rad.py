"""Lane 3 PR-B owner rows (10-13): L3-PRB-r (readiness proves the job contract), L3-PRB-a (explicit first-contact
verdicts), L3-PRB-d (old qa-runner FastAPI/in-process runner deleted; tombstone).

Hermetic: fake Run API session, loopback signed-URL / index fakes (qa_sandbox_support), stub gcloud for
deploy-services.sh (lane 5 harness), HCL parsed with python-hcl2. No network, no credentials.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import os
import subprocess
from pathlib import Path

import hcl2
import pytest
from fastapi.testclient import TestClient

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
import qa_job_client as qjc
import test_platform_safe_apply_lane5 as l5
from fd4f_support import FakeDB, FakeQAClient, code_defect_outcome, gw, passing_outcome  # noqa: F401
from gate_errors import ErrorClass, GateUnavailableError
from test_fd4f_qa_endpoints_fail_closed import _qa, _wire
from test_lane3_prb_qa_contract import cloud, gateway_run, wheelhouse  # noqa: F401  (fixtures)

REPO = Path(__file__).resolve().parent.parent
QA_DIR = REPO / "apps" / "qa-runner"
sj = sup.load_sandbox_job("sandbox_job_rad")

CFG = qjc.QAJobConfig("p", "r", "qa-sandbox-test-runner", "bkt", "sa-castor-qa-sandbox@p.iam.gserviceaccount.com")
READY_JOB = {
    "labels": {"environment": "dev", "managed_by": "castor-terraform", "stackvend-qa-job-contract": "1"},
    "template": {"template": {"serviceAccount": CFG.sandbox_sa, "timeout": "900s", "containers": [
        # Row L3-PRB-g (FD-4BR): entrypoint + the index on argv, and ALL egress into the sandbox network.
        {"image": "i", "command": ["/cnb/lifecycle/launcher"],
         "args": ["python3", "-m", "sandbox_job", "--index-url", "https://r-python.pkg.dev/p/castor-pypi-remote/simple/"]}],
        "vpcAccess": {"egress": "ALL_TRAFFIC", "networkInterfaces": [
            {"network": "projects/p/global/networks/castor-qa-sandbox",
             "subnetwork": "projects/p/regions/r/subnetworks/castor-qa-sandbox-r"}]}}},
}


def codes(diags):
    return [d["code"] for d in diags]


# ==================================================================================================== L3-PRB-r
class _Res:
    def __init__(self, status=200, payload=None):
        self.status_code, self._p = status, payload

    def json(self):
        return self._p


class JobSession:
    def __init__(self, job=None, status=200, exc=None):
        self.job, self.status, self.exc, self.gets = job, status, exc, []

    def get(self, url, **kw):
        self.gets.append(url)
        if self.exc is not None:
            raise self.exc
        return _Res(self.status, copy.deepcopy(self.job))

    def post(self, url, **kw):  # readiness never runs, cancels or stages anything
        raise AssertionError(f"readiness must not POST ({url})")


def _client(session, clock=None):
    clock = clock or {"t": 0.0}
    return qjc.QAJobClient(CFG, session, store=None, sleep=lambda s: None, clock=lambda: clock["t"])


def _job(**changes):
    job = copy.deepcopy(READY_JOB)
    for path, value in changes.items():
        node, keys = job, path.split("__")
        for k in keys[:-1]:
            node = node[int(k)] if isinstance(node, list) else node[k]
        if value is _DELETE:
            del node[keys[-1]]
        else:
            node[keys[-1]] = value
    return job


_DELETE = object()
CONTAINER = "template__template__containers__0"


def test_r_negative_ready_job_passes_one_get_and_is_cached():
    s = JobSession(READY_JOB)
    clock = {"t": 0.0}
    c = _client(s, clock)
    c.verify_job_readiness()
    c.verify_job_readiness()
    assert len(s.gets) == 1 and s.gets[0].endswith(CFG.job_path)
    clock["t"] = qjc.IDENTITY_CACHE_S + 1
    c.verify_job_readiness()
    assert len(s.gets) == 2
    c.verify_job_identity()  # a passing readiness also satisfies the dispatch-time identity cache
    assert len(s.gets) == 2


@pytest.mark.parametrize("changes,not_ready", [
    ({"labels": _DELETE}, ["labels.stackvend-qa-job-contract"]),                      # image shipped before the trigger change
    ({"labels__stackvend-qa-job-contract": _DELETE}, ["labels.stackvend-qa-job-contract"]),
    ({"labels__stackvend-qa-job-contract": "0"}, ["labels.stackvend-qa-job-contract"]),   # older contract
    ({"labels__stackvend-qa-job-contract": 1}, ["labels.stackvend-qa-job-contract"]),     # not the string "1"
    ({"labels": ["stackvend-qa-job-contract"]}, ["labels.stackvend-qa-job-contract"]),
    ({f"{CONTAINER}__args": _DELETE}, ["args"]),                                     # pre-Stage-A job: no args
    ({f"{CONTAINER}__args": ["python3", "main.py"]}, ["args"]),                       # old FastAPI runner
    ({f"{CONTAINER}__args": ["python3", "-m", "sandbox_job", "--x"]}, ["args"]),
    ({f"{CONTAINER}__args": "python3 -m sandbox_job"}, ["args"]),
    ({f"{CONTAINER}__args": _DELETE, "labels": {}}, ["args", "labels.stackvend-qa-job-contract"]),
])
def test_r_contract_miss_is_typed_not_ready(changes, not_ready):
    s = JobSession(_job(**changes))
    c = _client(s)
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_readiness()
    e = ei.value
    assert e.reason == "QA_JOB_NOT_READY" and e.http_status == 503
    assert e.details["not_ready"] == not_ready and e.details["expected_contract"] == "1"
    with pytest.raises(GateUnavailableError):  # a failure is never cached as ready
        c.verify_job_readiness()
    assert len(s.gets) == 2


@pytest.mark.parametrize("changes", [
    {"template__template__serviceAccount": "sa-castor-developer@p.iam.gserviceaccount.com"},
    {"template__template__maxRetries": 3},
    {"template__template__timeout": "3600s"},
    {f"{CONTAINER}__env": [{"name": "PROJECT_ID", "value": "p"}]},
])
def test_r_identity_drift_is_checked_by_readiness(changes):
    with pytest.raises(GateUnavailableError) as ei:
        _client(JobSession(_job(**changes))).verify_job_readiness()
    assert ei.value.reason == "QA_JOB_DRIFT"


@pytest.mark.parametrize("session", [
    JobSession(READY_JOB, status=404),
    JobSession(READY_JOB, status=403),
    JobSession(exc=ConnectionError("down")),
    JobSession({"labels": {}}),
    JobSession(["not", "an", "object"]),
    JobSession({"template": {"template": "x"}}),
])
def test_r_lookup_failures_are_typed(session):
    with pytest.raises(GateUnavailableError) as ei:
        _client(session).verify_job_readiness()
    assert ei.value.reason == "QA_JOB_LOOKUP"


def test_r_negative_dispatch_identity_check_unchanged():
    # The dispatch-time H3 check is NOT widened by this row: a job without the label still passes it.
    _client(JobSession(_job(labels=_DELETE))).verify_job_identity()
    # Row L3-PRB-g (FD-4BR) widened dispatch on purpose: args (and vpcAccess) are now required there too.
    with pytest.raises(GateUnavailableError) as ei:
        _client(JobSession(_job(labels=_DELETE, **{f"{CONTAINER}__args": _DELETE}))).verify_job_identity()
    assert ei.value.reason == "QA_JOB_DRIFT" and ei.value.details["drift"] == ["args"]


def _ready_gw(gw, client):
    gw.app.dependency_overrides[gw.get_qa_job_client] = lambda: client
    gw.app.dependency_overrides[gw.get_evidence_db] = lambda: FakeDB()
    return TestClient(gw.app).get("/agent/qa/readiness")


def test_r_endpoint_runs_the_job_contract_check(gw):
    qa = FakeQAClient(passing_outcome())
    r = _ready_gw(gw, qa)
    assert r.status_code == 200, r.text
    assert qa.readiness_checks == 1 and qa.calls == []


def test_r_endpoint_with_the_real_client_and_a_pre_prb_job_is_503(gw):
    r = _ready_gw(gw, _client(JobSession(_job(labels=_DELETE))))
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["error_class"] == "GATE_UNAVAILABLE" and body["reason"] == "QA_JOB_NOT_READY"
    assert body["details"]["not_ready"] == ["labels.stackvend-qa-job-contract"]
    assert _ready_gw(gw, _client(JobSession(READY_JOB))).status_code == 200


@pytest.mark.parametrize("error,reason", [
    (GateUnavailableError("drift", reason="QA_JOB_DRIFT"), "QA_JOB_DRIFT"),
    (RuntimeError("unexpected"), "QA_JOB_LOOKUP"),
    (AttributeError("old client without verify_job_readiness"), "QA_JOB_LOOKUP"),
])
def test_r_endpoint_fails_closed_typed(gw, error, reason):
    qa = FakeQAClient(passing_outcome())
    qa.readiness_error = error
    r = _ready_gw(gw, qa)
    assert r.status_code == 503 and r.json()["reason"] == reason and r.json()["error_class"] == "GATE_UNAVAILABLE"


# --- the contract is the same value on every side (gateway, job, Terraform, trigger, deploy-services.sh) -------------
def _tf(path):
    with open(REPO / path) as f:
        return hcl2.load(f)


def _qa_job_tf():
    jobs = [r["google_cloud_run_v2_job"] for r in _tf("infra/platform/qa_sandbox.tf")["resource"]
            if "google_cloud_run_v2_job" in r]
    return jobs[0]["qa_sandbox"]


def test_r_contract_values_agree_everywhere():
    assert qjc.JOB_CONTRACT_VERSION == sj.JOB_CONTRACT_VERSION == "1"
    container = _qa_job_tf()["template"][0]["template"][0]["containers"][0]
    assert tuple(container["args"]) == qjc.JOB_CONTRACT_ARGS == ("python3", "-m", "sandbox_job")
    assert (QA_DIR / "Procfile").read_text().strip() == "web: " + " ".join(qjc.JOB_CONTRACT_ARGS)


def test_r_terraform_ignores_only_the_contract_label():
    ignored = _qa_job_tf()["lifecycle"][0]["ignore_changes"]
    assert '${labels["stackvend-qa-job-contract"]}' in ignored or 'labels["stackvend-qa-job-contract"]' in ignored, ignored
    assert "labels" not in ignored and "${labels}" not in ignored  # TF keeps managing environment / managed_by


class TestDeployServicesSetsTheContractLabel(l5._Harness):
    """deploy-services.sh (script-deployed install path) ships the job and its label in one `gcloud run jobs deploy`."""

    def setUp(self):
        super().setUp()
        for d in l5.TestDeployServices.DIRS:
            os.makedirs(os.path.join(self.repo, d), exist_ok=True)
        os.makedirs(os.path.join(self.repo, "apps/control-center/shared"), exist_ok=True)
        self.write("infra/modules/m/main.tf", "# module\n")
        self.write("shared/builtin_modules_payload.py", "PAYLOAD = {}\n")

    def _job_deploys(self):
        return [x for x in self.calls() if x.startswith("gcloud run jobs deploy")]

    def test_single_qa_job_deploy_carries_the_label(self):
        rc, out, err = self.run_script("deploy-services.sh", ["qa-sandbox-test-runner"], PROJECT_ID=l5.PROJ)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._job_deploys(), [
            f"gcloud run jobs deploy qa-sandbox-test-runner --source apps/qa-runner --region us-central1 "
            f"--project {l5.PROJ} --quiet"])
        # `jobs deploy` has no --update-labels (live failure 10-13): the label follows via `jobs update`.
        self.assertIn(f"gcloud run jobs update qa-sandbox-test-runner --region us-central1 --project {l5.PROJ} "
                      f"--update-labels=stackvend-qa-job-contract=1 --quiet", self.calls())
        self.assertFalse([x for x in self._job_deploys() if "--update-labels" in x])

    def test_bulk_only_the_qa_job_carries_the_label(self):
        rc, out, err = self.run_script("deploy-services.sh", ["--all-jobs"], PROJECT_ID=l5.PROJ)
        self.assertEqual(rc, 0, out + err)
        deploys = self._job_deploys()
        self.assertEqual(len(deploys), 9, deploys)   # C10: + 3 jobs
        self.assertFalse([x for x in deploys if "--update-labels" in x], deploys)
        updates = [x for x in self.calls() if x.startswith("gcloud run jobs update") and "--update-labels" in x]
        self.assertEqual(updates, [
            f"gcloud run jobs update qa-sandbox-test-runner --region us-central1 --project {l5.PROJ} "
            f"--update-labels=stackvend-qa-job-contract=1 --quiet"])


# ==================================================================================================== L3-PRB-a
def _one(diags):
    assert len(diags) == 1, diags
    return diags[0]


def test_a_node_only_workload_is_no_tests_and_names_what_was_found():
    d = _one(sj.discover_layout(["apps/web/package.json", "apps/web/src/index.js", "tests/app.test.js",
                                 "infra/workload/main.tf"]).diagnostics)
    assert d["code"] == "PY.NO_TESTS" and d["severity"] == "error"
    assert "Node-only" in d["message"] and d["detail"] == (
        "apps/ directories without a requirements.txt (not Python services): apps/web")


def test_a_no_apps_at_all_is_no_tests():
    d = _one(sj.discover_layout(["README.md", "infra/workload/main.tf"]).diagnostics)
    assert d["code"] == "PY.NO_TESTS" and d["detail"] == "no apps/<service>/ directory"


def test_a_services_without_tests_are_listed():
    d = _one(sj.discover_layout(["apps/a/requirements.txt", "apps/a/main.py", "apps/b/requirements.txt"]).diagnostics)
    assert d["code"] == "PY.NO_TESTS" and d["detail"] == "services without tests: apps/a, apps/b"


def test_a_root_tests_with_two_services_is_test_layout_with_both_lists():
    files = ["apps/a/requirements.txt", "apps/b/requirements.txt", "apps/b/tests/test_b.py"] + [
        f"tests/test_{i:02d}.py" for i in range(12)]
    d = _one(sj.discover_layout(files).diagnostics)
    assert d["code"] == "PY.TEST_LAYOUT" and d["file"] == "tests"
    assert d["detail"] == ("services: apps/a, apps/b; root tests/ files: "
                           + ", ".join(f"tests/test_{i:02d}.py" for i in range(10)) + " (+2 more)")


def test_a_negative_valid_layouts_have_no_verdict():
    one = sj.discover_layout(["apps/a/requirements.txt", "tests/test_x.py"])
    two = sj.discover_layout(["apps/a/requirements.txt", "apps/a/tests/test_a.py", "apps/b/requirements.txt",
                              "apps/b/tests/test_b.py", "apps/web/package.json"])
    assert one.diagnostics == [] and [(s.rel, s.test_roots) for s in one.services] == [("apps/a", ["tests"])]
    assert two.diagnostics == [] and [(s.rel, s.test_roots) for s in two.services] == [
        ("apps/a", ["apps/a/tests"]), ("apps/b", ["apps/b/tests"])]


NODE_ONLY = {
    "apps/web/package.json": '{"name": "web", "scripts": {"test": "jest"}}\n',
    "apps/web/index.js": "console.log('hi')\n",
    "tests/app.test.js": "test('x', () => {})\n",
}
TWO_SERVICES_ROOT_TESTS = {
    "apps/a/main.py": "def health():\n    return {'status': 'healthy'}\n",
    "apps/a/requirements.txt": "",
    "apps/b/main.py": "X = 1\n",
    "apps/b/requirements.txt": "",
    "tests/test_main.py": "def test_x():\n    assert True\n",
}


@pytest.mark.parametrize("files,code,detail_part", [
    (NODE_ONLY, "PY.NO_TESTS", "apps/web"),
    (TWO_SERVICES_ROOT_TESTS, "PY.TEST_LAYOUT", "services: apps/a, apps/b"),
])
def test_a_first_contact_verdict_is_code_defect_end_to_end(cloud, tmp_path, files, code, detail_part):
    """Gateway QAJobClient.run -> real job -> gateway classify: exit 10, static phase only (nothing untrusted ran,
    no report.json), CODE_DEFECT with the explicit diagnostic (back to the developer, row 19o)."""
    outcome, run_api, _ = gateway_run(cloud, tmp_path, files)
    assert run_api.exit_code == 10
    assert outcome.error_class == ErrorClass.CODE_DEFECT and outcome.report is None, outcome
    d = _one(outcome.diagnostics)
    assert d["code"] == code and detail_part in d["detail"]
    assert outcome.static["index_reachable"] is None  # static failed: the index was never needed


@pytest.mark.parametrize("code", ["PY.NO_TESTS", "PY.TEST_LAYOUT"])
def test_a_gateway_returns_the_verdict_to_the_developer(gw, code):
    c, _ = _wire(gw, client=FakeQAClient(code_defect_outcome(code=code, message="m", file=None)), db=FakeDB())
    r = _qa(c, attempt=0)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["error_class"] == "CODE_DEFECT" and body["retryable"] is True and body["diagnostics"][0]["code"] == code


# ==================================================================================================== L3-PRB-d
DELETED = ("apps/qa-runner/main.py", "apps/qa-runner/runner.py", "apps/qa-runner/test_runner.py")


def _tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True,
                         env=hermetic_guard.child_env()).stdout
    return [p for p in out.decode().split("\0") if p]


def test_d_tombstone_old_runner_files_are_gone():
    for rel in DELETED:
        assert not (REPO / rel).exists(), f"{rel} was deleted by register row L3-PRB-d; the QA job replaces it"


def test_d_nothing_outside_docs_references_the_deleted_runner():
    needles = DELETED + ("QASandboxRunner(", "from runner import", "qa-runner/runner", "qa_runner/runner",
                         "test_fd4g_qa_runner", "test_fd4j_qa_runner_secrets")
    allowed = {"tests/test_lane3_prb_rad.py"}
    hits = []
    for rel in _tracked():
        if rel.startswith("docs/") or rel in allowed or rel == "eval/config/healer_targets.json":
            continue
        if not rel.endswith((".py", ".sh", ".tf", ".yaml", ".yml", ".txt", ".ini", ".cfg", ".toml", ".json", "Procfile")):
            continue
        try:
            text = (REPO / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        hits += [(rel, n) for n in needles if n in text]
    assert hits == []


def test_d_requirements_are_the_jobs_only():
    reqs = []
    for line in (QA_DIR / "requirements.txt").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            reqs.append(line)
    names = sorted(r.split(">=")[0].split("==")[0].strip().lower() for r in reqs)
    assert names == ["bandit", "packaging"], reqs


def test_d_the_job_is_kept():
    assert (QA_DIR / "sandbox_job.py").is_file()
    assert (QA_DIR / "Procfile").read_text().strip() == "web: python3 -m sandbox_job"
    tree = ast.parse((QA_DIR / "sandbox_job.py").read_text())
    third_party = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            third_party |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            third_party.add(node.module.split(".")[0])
    import sys
    third_party -= set(sys.stdlib_module_names) | {"shared", "release_info"}  # SAT-11: stdlib-only local reader
    assert third_party <= {"packaging"}, third_party  # bandit runs as `python -m bandit`, never imported

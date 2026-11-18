"""FD-4BR C3 (row L3-PRB-g, QA egress Phase 2): the gateway refuses a QA job that is not behind the egress wall.

`QAJobClient.verify_job_identity` (dispatch, before any code is staged) and `verify_job_readiness` (pipeline start,
GET /agent/qa/readiness) both require, on the job's task template:
    vpcAccess.egress == "ALL_TRAFFIC", exactly one network interface on the sandbox network, no connector;
    args == entrypoint + ["--index-url", "https://<REGION>-python.pkg.dev/<PROJECT_ID>/castor-pypi-remote/simple/"].
A miss is typed: readiness -> GateUnavailableError QA_JOB_NOT_READY (503, details.not_ready); dispatch ->
QA_JOB_DRIFT (details.drift); never cached, never a pass. The expected values are pinned against the Terraform
(qa_sandbox_egress.tf / qa_sandbox.tf) and the job's own argv parser (apps/qa-runner/sandbox_job.py).
Transition (RT F2, until C3b): exactly ONE of two complete shapes passes: legacy (args == entrypoint exactly, no
vpcAccess) or the full egress shape above. Any mix is refused, typed.

Hermetic: fake Run API session, no network, no credentials.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy

import pytest
from fastapi.testclient import TestClient

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
import qa_job_client as qjc
from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)
from gate_errors import GateUnavailableError

sj = sup.load_sandbox_job("sandbox_job_fd4br_readiness")

CFG = qjc.QAJobConfig("proj-a", "europe-west4", "qa-sandbox-test-runner", "bkt",
                      "sa-castor-qa-sandbox@proj-a.iam.gserviceaccount.com")
INDEX = "https://europe-west4-python.pkg.dev/proj-a/castor-pypi-remote/simple/"
NET = "projects/proj-a/global/networks/castor-qa-sandbox"
READY_JOB = {
    "labels": {"environment": "dev", "managed_by": "castor-terraform", "stackvend-qa-job-contract": "1"},
    "template": {"template": {
        "serviceAccount": CFG.sandbox_sa, "timeout": "900s",
        "containers": [{"image": "i", "command": ["/cnb/lifecycle/launcher"],
                        "args": ["python3", "-m", "sandbox_job", "--index-url", INDEX]}],
        "vpcAccess": {"egress": "ALL_TRAFFIC", "networkInterfaces": [
            {"network": NET, "subnetwork": "projects/proj-a/regions/europe-west4/subnetworks/castor-qa-sandbox-europe-west4"}]},
    }},
}
# What both installs run before the egress apply: the PR-B entrypoint, default egress, no index argument.
PRE_PHASE2_JOB = copy.deepcopy(READY_JOB)
PRE_PHASE2_JOB["template"]["template"]["containers"][0]["args"] = ["python3", "-m", "sandbox_job"]
del PRE_PHASE2_JOB["template"]["template"]["vpcAccess"]


class _Res:
    def __init__(self, status=200, payload=None):
        self.status_code, self._p = status, payload

    def json(self):
        return self._p


class JobSession:
    def __init__(self, job):
        self.job, self.gets = job, []

    def get(self, url, **kw):
        self.gets.append(url)
        return _Res(200, copy.deepcopy(self.job))

    def post(self, url, **kw):
        raise AssertionError(f"identity/readiness must not POST ({url})")


class RecordingStore:
    def __init__(self):
        self.uploads = []

    def upload(self, name, data, content_type):
        self.uploads.append(name)

    def sign(self, *a, **k):
        raise AssertionError("nothing may be signed for a refused job")


def _client(job, store=None):
    clock = {"t": 0.0}
    session = JobSession(job)
    return qjc.QAJobClient(CFG, session, store, sleep=lambda s: None, clock=lambda: clock["t"]), session


def _job(mutate):
    job = copy.deepcopy(READY_JOB)
    mutate(job["template"]["template"])
    return job


def test_expected_values_are_derived_from_the_gateway_config():
    """Gateway side only (the TF side of the same pin lives with the Terraform, tests/test_fd4br_qa_egress_tf.py,
    so this group lands before the Terraform does: re-check R1)."""
    assert qjc.QA_SANDBOX_NETWORK == "castor-qa-sandbox" and qjc.QA_PYPI_REPOSITORY == "castor-pypi-remote"
    assert qjc.expected_index_url(CFG) == INDEX
    assert qjc.expected_job_args(CFG) == ["python3", "-m", "sandbox_job", "--index-url", INDEX]
    assert qjc.expected_networks(CFG) == [NET, "castor-qa-sandbox"]
    assert qjc.JOB_VPC_EGRESS == "ALL_TRAFFIC"


def test_the_job_accepts_exactly_the_args_the_gateway_expects():
    expected = qjc.expected_job_args(CFG)
    assert expected[:3] == list(qjc.JOB_CONTRACT_ARGS)
    assert qjc.JOB_INDEX_ARG == sj.INDEX_ARG
    tc = sj.toolchain_from_argv(expected[3:])  # what `python3 -m sandbox_job <rest>` parses
    assert tc.index_url == INDEX and tc.index_auth_metadata is True
    assert tc.index_probe_url() == INDEX + "pip/"


# ------------------------------------------------------------------------------
# Ready job: both checks pass (negative)
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("network", [NET, "castor-qa-sandbox"])
def test_negative_a_job_behind_the_egress_wall_passes_both_checks(network):
    job = _job(lambda t: t["vpcAccess"]["networkInterfaces"][0].__setitem__("network", network))
    c, s = _client(job)
    c.verify_job_readiness()
    c.verify_job_identity()  # served by the readiness cache
    assert len(s.gets) == 1
    c2, s2 = _client(job)
    c2.verify_job_identity()
    assert len(s2.gets) == 1


# ------------------------------------------------------------------------------
# Misses: typed, never cached, never a pass
# ------------------------------------------------------------------------------
MISSES = [
    ("no vpcAccess (default internet egress)", lambda t: t.pop("vpcAccess"), ["vpcAccess.egress", "vpcAccess.network"]),
    ("private ranges only", lambda t: t["vpcAccess"].__setitem__("egress", "PRIVATE_RANGES_ONLY"), ["vpcAccess.egress"]),
    ("egress missing", lambda t: t["vpcAccess"].pop("egress"), ["vpcAccess.egress"]),
    ("other network", lambda t: t["vpcAccess"]["networkInterfaces"][0].__setitem__("network", "default"),
     ["vpcAccess.network"]),
    ("same name, other project", lambda t: t["vpcAccess"]["networkInterfaces"][0].__setitem__(
        "network", "projects/proj-b/global/networks/castor-qa-sandbox"), ["vpcAccess.network"]),
    ("subnetwork only", lambda t: t["vpcAccess"]["networkInterfaces"][0].pop("network"), ["vpcAccess.network"]),
    ("two interfaces", lambda t: t["vpcAccess"]["networkInterfaces"].append({"network": "default"}),
     ["vpcAccess.network"]),
    ("no interfaces", lambda t: t["vpcAccess"].__setitem__("networkInterfaces", []), ["vpcAccess.network"]),
    ("connector instead", lambda t: t.__setitem__("vpcAccess", {"egress": "ALL_TRAFFIC",
                                                                "connector": "projects/proj-a/locations/x/connectors/c"}),
     ["vpcAccess.network", "vpcAccess.connector"]),
    ("vpcAccess not an object", lambda t: t.__setitem__("vpcAccess", "ALL_TRAFFIC"),
     ["vpcAccess.egress", "vpcAccess.network"]),
    ("pre-Phase-2 args", lambda t: t["containers"][0].__setitem__("args", ["python3", "-m", "sandbox_job"]), ["args"]),
    ("pypi.org index", lambda t: t["containers"][0]["args"].__setitem__(4, "https://pypi.org/simple"), ["args"]),
    ("other project's index", lambda t: t["containers"][0]["args"].__setitem__(
        4, "https://europe-west4-python.pkg.dev/proj-b/castor-pypi-remote/simple/"), ["args"]),
    ("other region's index", lambda t: t["containers"][0]["args"].__setitem__(
        4, "https://us-east1-python.pkg.dev/proj-a/castor-pypi-remote/simple/"), ["args"]),
    ("extra argument", lambda t: t["containers"][0]["args"].append("--x"), ["args"]),
    ("args as a string", lambda t: t["containers"][0].__setitem__("args", " ".join(t["containers"][0]["args"])),
     ["args"]),
]


@pytest.mark.parametrize("label,mutate,expected", MISSES, ids=[m[0] for m in MISSES])
def test_readiness_miss_is_typed_not_ready_and_never_cached(label, mutate, expected):
    c, s = _client(_job(mutate))
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_readiness()
    e = ei.value
    assert e.reason == "QA_JOB_NOT_READY" and e.http_status == 503
    assert e.details["not_ready"] == expected
    assert e.details["expected_args"] == qjc.expected_job_args(CFG)
    assert e.details["expected_network"] == NET and e.details["expected_vpc_egress"] == "ALL_TRAFFIC"
    with pytest.raises(GateUnavailableError):
        c.verify_job_readiness()
    with pytest.raises(GateUnavailableError):  # a failed readiness never primes the dispatch cache
        c.verify_job_identity()
    assert len(s.gets) == 3


@pytest.mark.parametrize("label,mutate,expected", MISSES, ids=[m[0] for m in MISSES])
def test_dispatch_miss_is_typed_drift_and_stages_nothing(label, mutate, expected):
    store = RecordingStore()
    c, s = _client(_job(mutate), store)
    with pytest.raises(GateUnavailableError) as ei:
        c.run(tar_bytes=b"tgz", commit_sha="a" * 40, trace_id="tr-1", product_id="app", deadline=10_000)
    assert ei.value.reason == "QA_JOB_DRIFT" and ei.value.details["drift"] == expected
    assert store.uploads == []
    with pytest.raises(GateUnavailableError):  # never cached
        c.verify_job_identity()
    assert len(s.gets) == 2


def test_details_show_what_was_found():
    c, _ = _client(_job(lambda t: t["vpcAccess"].update(
        egress="PRIVATE_RANGES_ONLY", networkInterfaces=[{"network": "default"}])))
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_readiness()
    d = ei.value.details
    assert d["found_vpc_egress"] == "PRIVATE_RANGES_ONLY" and d["found_networks"] == ["default"]


def test_identity_drift_still_wins_over_egress():
    c, _ = _client(_job(lambda t: (t.__setitem__("maxRetries", 3), t.pop("vpcAccess"))))
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_readiness()
    assert ei.value.reason == "QA_JOB_DRIFT"


def test_label_miss_on_a_legacy_job_is_reported_alone():
    job = copy.deepcopy(PRE_PHASE2_JOB)
    del job["labels"]["stackvend-qa-job-contract"]
    c, _ = _client(job)
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_readiness()
    assert ei.value.details["not_ready"] == ["labels.stackvend-qa-job-contract"]
    assert ei.value.details["job_shape"] == "legacy" and ei.value.details["egress_lockdown"] is False
    # Re-check R3: a legacy-shaped 503 names the legacy args, not the egress args.
    assert ei.value.details["expected_args"] == ["python3", "-m", "sandbox_job"]


def test_label_and_egress_misses_are_reported_together():
    job = _job(lambda t: t.pop("vpcAccess"))  # egress args without vpcAccess: a mix
    del job["labels"]["stackvend-qa-job-contract"]
    c, _ = _client(job)
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_readiness()
    assert ei.value.details["not_ready"] == ["vpcAccess.egress", "vpcAccess.network",
                                             "labels.stackvend-qa-job-contract"]
    assert ei.value.details["expected_args"] == qjc.expected_job_args(CFG)  # a mix is judged as the egress shape


# ------------------------------------------------------------------------------
# RT F2: exactly one of two complete shapes (transition until C3b)
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("vpc", [None, {}])
def test_a_pre_phase2_job_passes_until_c3b(vpc):
    """Today's job on both installs (legacy shape) passes both checks, so C3 can deploy BEFORE the egress apply."""
    job = copy.deepcopy(PRE_PHASE2_JOB)
    if vpc is not None:
        job["template"]["template"]["vpcAccess"] = vpc
    assert qjc.job_shape(job) == "legacy"
    c, s = _client(job)
    c.verify_job_readiness()
    assert c.egress_lockdown is False
    c.verify_job_identity()  # served by the readiness cache
    c2, _ = _client(job)
    c2.verify_job_identity()
    assert len(s.gets) == 1


def test_the_full_egress_shape_reports_lockdown():
    c, _ = _client(READY_JOB)
    c.verify_job_readiness()
    assert qjc.job_shape(READY_JOB) == "egress" and c.egress_lockdown is True


LEGACY_ARGS = ["python3", "-m", "sandbox_job"]
MIXES = [
    ("egress args, no vpcAccess", lambda t: t.pop("vpcAccess"), ["vpcAccess.egress", "vpcAccess.network"]),
    ("legacy args, full vpcAccess", lambda t: t["containers"][0].__setitem__("args", list(LEGACY_ARGS)), ["args"]),
    ("legacy args, partial vpcAccess", lambda t: (t["containers"][0].__setitem__("args", list(LEGACY_ARGS)),
                                                  t.__setitem__("vpcAccess", {"egress": "ALL_TRAFFIC"})),
     ["args", "vpcAccess.network"]),
    ("legacy args, connector", lambda t: (t["containers"][0].__setitem__("args", list(LEGACY_ARGS)),
                                          t.__setitem__("vpcAccess", {"connector": "projects/proj-a/locations/x/connectors/c"})),
     ["args", "vpcAccess.egress", "vpcAccess.network", "vpcAccess.connector"]),
    ("egress args, wrong network", lambda t: t["vpcAccess"]["networkInterfaces"][0].__setitem__("network", "default"),
     ["vpcAccess.network"]),
    ("legacy args + extra, no vpcAccess", lambda t: (t["containers"][0].__setitem__("args", LEGACY_ARGS + ["--x"]),
                                                     t.pop("vpcAccess")),
     ["args", "vpcAccess.egress", "vpcAccess.network"]),
    ("no args, no vpcAccess", lambda t: (t["containers"][0].pop("args"), t.pop("vpcAccess")),
     ["args", "vpcAccess.egress", "vpcAccess.network"]),
]


@pytest.mark.parametrize("label,mutate,expected", MIXES, ids=[m[0] for m in MIXES])
def test_any_mix_of_the_two_shapes_is_refused_by_both_checks(label, mutate, expected):
    job = _job(mutate)
    assert qjc.job_shape(job) == "egress"
    c, _ = _client(job)
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_readiness()
    assert ei.value.reason == "QA_JOB_NOT_READY" and ei.value.details["not_ready"] == expected
    assert ei.value.details["egress_lockdown"] is False
    store = RecordingStore()
    c2, _ = _client(job, store)
    with pytest.raises(GateUnavailableError) as ei:
        c2.run(tar_bytes=b"tgz", commit_sha="a" * 40, trace_id="tr-1", product_id="app", deadline=10_000)
    assert ei.value.reason == "QA_JOB_DRIFT" and ei.value.details["drift"] == expected
    assert store.uploads == []


# ------------------------------------------------------------------------------
# GET /agent/qa/readiness with the real client
# ------------------------------------------------------------------------------
def _ready(gw, client):
    gw.app.dependency_overrides[gw.get_qa_job_client] = lambda: client
    gw.app.dependency_overrides[gw.get_evidence_db] = lambda: FakeDB()
    return TestClient(gw.app).get("/agent/qa/readiness")


def test_readiness_endpoint_503_for_a_mixed_job(gw):
    r = _ready(gw, _client(_job(lambda t: t.pop("vpcAccess")))[0])  # new args, egress not applied: a mix
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["error_class"] == "GATE_UNAVAILABLE" and body["reason"] == "QA_JOB_NOT_READY"
    assert body["details"]["not_ready"] == ["vpcAccess.egress", "vpcAccess.network"]


def test_readiness_endpoint_200_for_the_legacy_job_until_c3b(gw):
    assert _ready(gw, _client(PRE_PHASE2_JOB)[0]).status_code == 200


def test_readiness_endpoint_200_for_a_job_behind_it(gw, monkeypatch):
    for k, v in {"PROJECT_ID": CFG.project_id, "REGION": CFG.region, "QA_JOB_NAME": CFG.job_name,
                 "QA_STAGING_BUCKET": CFG.staging_bucket, "QA_SANDBOX_SA": CFG.sandbox_sa}.items():
        monkeypatch.setenv(k, v)
    r = _ready(gw, _client(READY_JOB)[0])
    assert r.status_code == 200, r.text

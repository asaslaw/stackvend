"""Row HOST-VPC-EGRESS (internal-ingress plan §3.5, Phase 1d): the gateway refuses a QA sandbox job whose
`vpcAccess.networkInterfaces[].network` names the host platform network `stackvend-host`.

On that network the job (untrusted generated code) would be an internal source for every internal-only host service.
Both QAJobClient.verify_job_readiness (pipeline start) and verify_job_identity (dispatch) raise GateUnavailableError
QA_JOB_DRIFT, before anything is staged, whatever the job's shape; never cached. Negative: the sandbox-network job
and the legacy job (no vpcAccess) still pass.

Hermetic: fake Run API session, no network, no credentials.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy

import pytest

import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
import qa_job_client as qjc
from gate_errors import GateUnavailableError

from test_fd4br_qa_readiness import CFG, PRE_PHASE2_JOB, READY_JOB, RecordingStore, _client

HOST_NETS = ["projects/proj-a/global/networks/stackvend-host", "stackvend-host",
             "projects/123456789012/global/networks/stackvend-host"]


def _on(networks, base=READY_JOB):
    job = copy.deepcopy(base)
    tmpl = job["template"]["template"]
    tmpl["vpcAccess"] = {"egress": "ALL_TRAFFIC", "networkInterfaces": [{"network": n} for n in networks]}
    return job


def test_host_network_name_is_pinned():
    assert qjc.HOST_PLATFORM_NETWORK == "stackvend-host"
    assert qjc.HOST_PLATFORM_NETWORK != qjc.QA_SANDBOX_NETWORK


@pytest.mark.parametrize("network", HOST_NETS)
def test_readiness_refuses_a_job_on_the_host_network(network):
    c, s = _client(_on([network]))
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_readiness()
    assert ei.value.reason == "QA_JOB_DRIFT"
    assert ei.value.details["drift"] == ["vpcAccess.host_network"]
    assert ei.value.details["found_networks"] == [network]
    with pytest.raises(GateUnavailableError):   # never cached
        c.verify_job_readiness()
    assert len(s.gets) == 2


def test_dispatch_refuses_and_stages_nothing_even_next_to_the_sandbox_network():
    store = RecordingStore()
    c, _ = _client(_on(["projects/proj-a/global/networks/castor-qa-sandbox", "stackvend-host"]), store)
    with pytest.raises(GateUnavailableError) as ei:
        c.run(tar_bytes=b"tgz", commit_sha="a" * 40, trace_id="tr-1", product_id="app", deadline=10_000)
    assert ei.value.reason == "QA_JOB_DRIFT" and ei.value.details["drift"] == ["vpcAccess.host_network"]
    assert store.uploads == []


def test_host_network_wins_over_other_identity_drift():
    job = _on(["stackvend-host"])
    job["template"]["template"]["maxRetries"] = 3
    c, _ = _client(job)
    with pytest.raises(GateUnavailableError) as ei:
        c.verify_job_identity()
    assert ei.value.details["drift"] == ["vpcAccess.host_network"]


@pytest.mark.parametrize("job", [READY_JOB, PRE_PHASE2_JOB], ids=["sandbox-network", "legacy-no-vpc"])
def test_negative_jobs_off_the_host_network_still_pass(job):
    c, _ = _client(copy.deepcopy(job))
    c.verify_job_readiness()
    c.verify_job_identity()


@pytest.mark.parametrize("value,name", [
    ("stackvend-host", "stackvend-host"),
    ("projects/p/global/networks/stackvend-host", "stackvend-host"),
    ("projects/p/global/networks/castor-qa-sandbox", "castor-qa-sandbox"),
    ("projects/p/regions/r/subnetworks/stackvend-host", None),
    ("stackvend-host-2", "stackvend-host-2"),
    ("", None), (None, None), (7, None),
])
def test_network_name_reads_the_resource_name_structure(value, name):
    assert qjc.network_name(value) == name

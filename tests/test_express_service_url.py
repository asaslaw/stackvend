"""EXPRESS-SERVICE-URL (10-27, seen live on a release-candidate install): an Express deploy succeeded (Cloud Run
service Ready at its run.app URL), but the workload's `service_url` was empty and the stage said "Deployed successfully. URL: N/A".
Express names its Cloud Run root outputs `compute_<instance>_uri` and has no `service_url` / `service_uri` output, so
the deploy result's generic `service_url` is empty. The Control Center now records the URL of the primary service
(the first compute-cloudrun instance in the request's typed module order) from the deploy result's `outputs` by that
exact output name. No output name or value is guessed.

Hermetic: dict-backed Firestore, terraform/vending calls mocked (harness shared with the EXP-7 tests).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import)

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from test_exp7_express_destroy_approval import _route  # noqa: E402

from shared.express_synthesizer import ExpressHCLSynthesizer, express_primary_service_output  # noqa: E402

PE, WL = "pipeline_executions/tr-exp7", "workloads/exp-app"
GATEWAY_URL = "https://exp-app-gateway-abc123-uc.a.run.app"
WORKER_URL = "https://exp-app-admin-abc123-uc.a.run.app"

INSTANCES = [
    {"module_id": "database-firestore", "instance_name": "store", "parameters": {}},
    {"module_id": "compute-cloudrun", "instance_name": "gateway", "parameters": {}},
    {"module_id": "compute-cloudrun", "instance_name": "admin", "parameters": {}},
]


def _outputs(**values):
    return {name: {"sensitive": False, "type": "string", "value": v} for name, v in values.items()}


def _run(wl, instances):
    wl.execute_express_provisioning(
        product_id="exp-app", target_project_id="castor-exp-1", clean_vcs_provider="GITHUB",
        full_github_repo="org/exp-repo", target_branch="main", target_folder=None, budget=50.0,
        clean_engine="OPENTOFU", is_sandbox=False, admin_email="admin@example.com",
        module_instances=instances, include_vpc=False, trace_id="tr-exp7", region="us-central1")   # FD-7M-a


# ------------------------------------------------------------------ the typed output name
def test_primary_output_is_the_first_cloud_run_instance_in_request_order():
    assert express_primary_service_output(INSTANCES) == "compute_gateway_uri"
    assert express_primary_service_output(list(reversed(INSTANCES))) == "compute_admin_uri"


def test_primary_output_name_is_the_one_the_synthesizer_renders():
    """Same planning keys as synthesize_workload: the name exists as a root output in the rendered outputs.tf."""
    _main, outputs_tf = ExpressHCLSynthesizer()._synthesize_main_and_outputs(
        product_id="exp-app", instances=INSTANCES, has_vpc=False, files={})
    name = express_primary_service_output(INSTANCES)
    assert f'output "{name}" {{' in outputs_tf
    assert 'output "service_url"' not in outputs_tf and 'output "service_uri"' not in outputs_tf


def test_no_cloud_run_instance_has_no_primary_output():
    assert express_primary_service_output([{"module_id": "database-firestore", "instance_name": "store"}]) is None
    assert express_primary_service_output([]) is None
    assert express_primary_service_output(None) is None


# ------------------------------------------------------------------ the recorded URL
def test_express_deploy_records_the_primary_service_url(monkeypatch):
    body = {"status": "SUCCESS", "service_url": "",
            "outputs": _outputs(compute_admin_uri=WORKER_URL, compute_gateway_uri=GATEWAY_URL,
                                workload_sa_email="sa@castor-exp-1.iam.gserviceaccount.com")}
    wl, store, _ = _route(monkeypatch, tf_json=body)
    _run(wl, INSTANCES)
    wdoc, pe = store.docs[WL], store.docs[PE]
    assert wdoc["status"] == "ACTIVE" and wdoc["service_url"] == GATEWAY_URL
    assert pe["outputs"]["service_url"] == GATEWAY_URL
    assert pe["stages"]["terraform"]["summary"] == f"Deployed successfully. URL: {GATEWAY_URL}"


def test_negative_generic_service_url_is_kept_without_a_typed_output(monkeypatch):
    """No Cloud Run instance (or its output missing): the deploy result's own service_url is used unchanged."""
    wl, store, _ = _route(monkeypatch, tf_json={"status": "SUCCESS", "service_url": "https://x.run.app",
                                                "outputs": _outputs(other="https://y.run.app")})
    _run(wl, INSTANCES)
    assert store.docs[WL]["service_url"] == "https://x.run.app"


def test_negative_no_outputs_and_no_url_stays_empty(monkeypatch):
    wl, store, _ = _route(monkeypatch, tf_json={"status": "SUCCESS", "service_url": ""})
    _run(wl, INSTANCES)
    assert store.docs[WL]["service_url"] == ""
    assert store.docs[PE]["stages"]["terraform"]["summary"] == "Deployed successfully. URL: N/A"


@pytest.mark.parametrize("entry", [{"value": None}, {"value": 7}, {"value": ""}, {"value": ["https://z.run.app"]},
                                   "https://bare.run.app", None])
def test_negative_a_malformed_output_entry_is_not_used(monkeypatch, entry):
    out = {"compute_gateway_uri": entry}
    wl, store, _ = _route(monkeypatch, tf_json={"status": "SUCCESS", "service_url": "", "outputs": out})
    _run(wl, INSTANCES)
    assert store.docs[WL]["service_url"] == ""

"""EXP-4: compute-event-worker `name_suffix`, Express several event workers; EXP-5: Express hcl_synthesis fails closed.

- Module: optional `name_suffix` (default null). Null / empty keep the product-only names (Do No Harm); a suffix is
  appended as `-<suffix>` to the Cloud Run job, Pub/Sub topic and subscription names. Both module trees, the 4
  builtin payload copies and the embedded contract (contract_inspector) carry the same interface.
- Express: one event worker passes no suffix (rendered text unchanged); several each pass their instance name.
  Equal suffixes -> ExpressModuleNameCollisionError; a suffix that is not an RFC 1123 label ->
  ExpressInvalidNameSuffixError (both ExpressSynthesisRefused, typed `reason`).
- CC route (EXP-5): a refused / failed / empty synthesis is a FAILED hcl_synthesis stage carrying the typed reason;
  nothing is committed or deployed and the workload is FAILED (no message parsing).
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

import shared.express_synthesizer as express_mod  # noqa: E402
from shared.express_synthesizer import ExpressHCLSynthesizer  # noqa: E402

MOD = "compute-event-worker"
TREES = ["infra/modules", "apps/control-center/infra/modules"]
PAYLOADS = ["shared", "mcp-servers/terraform/shared", "apps/orchestrator-gateway/shared", "apps/control-center/shared"]


def _read(rel):
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _inst(mid, name, params=None):
    return {"module_id": mid, "instance_name": name, "parameters": params or {}}


def _synth(instances):
    return ExpressHCLSynthesizer().synthesize_workload(product_id="expv", project_id="p-1", module_instances=instances)


def _modules(main_tf):
    return {n: b for block in hcl2.loads(main_tf).get("module", []) for n, b in block.items()}


# ------------------------------------------------------------------------------------------------ module interface
def test_name_suffix_is_an_optional_variable_with_a_null_default():
    variables = {n: b for block in hcl2.loads(_read(f"infra/modules/{MOD}/variables.tf"))["variable"]
                 for n, b in block.items()}
    v = variables["name_suffix"]
    assert v["default"] is None and v["type"] in ("string", "${string}") and v.get("validation")


def test_every_name_reads_the_suffixed_stem():
    resources = {}
    for block in hcl2.loads(_read(f"infra/modules/{MOD}/main.tf"))["resource"]:
        for rtype, body in block.items():
            for rname, attrs in body.items():
                resources[(rtype, rname)] = attrs
    assert resources[("google_pubsub_topic", "events")]["name"] == "events-${local.name_stem}"
    assert resources[("google_pubsub_subscription", "worker_sub")]["name"] == "worker-sub-${local.name_stem}"
    assert resources[("google_cloud_run_v2_job", "worker")]["name"] == "worker-${local.name_stem}"


@pytest.mark.parametrize("fname", ["main.tf", "variables.tf", "outputs.tf"])
def test_module_trees_and_payload_copies_are_identical(fname):
    disk = _read(f"{TREES[0]}/{MOD}/{fname}")
    assert all(_read(f"{t}/{MOD}/{fname}") == disk for t in TREES[1:])
    for copy in PAYLOADS:
        tree = ast.parse(_read(f"{copy}/builtin_modules_payload.py"))
        payload = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.AnnAssign))
        assert payload[MOD][fname] == disk, copy


def test_embedded_contract_matches_the_module_on_disk():
    import importlib.util
    path = os.path.join(REPO_ROOT, "apps/orchestrator-gateway/developer_agent/contract_inspector.py")
    spec = importlib.util.spec_from_file_location("exp4_contract_inspector", path)
    ci = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ci)
    emb = ci._EMBEDDED_MODULE_CONTRACTS[MOD]
    disk_in = {n for b in hcl2.loads(_read(f"infra/modules/{MOD}/variables.tf"))["variable"] for n in b}
    disk_out = {n for b in hcl2.loads(_read(f"infra/modules/{MOD}/outputs.tf"))["output"] for n in b}
    assert set(emb["inputs"]) == disk_in and set(emb["outputs"]) == disk_out


# ------------------------------------------------------------------------------------------------ Express
def test_one_event_worker_passes_no_suffix_and_its_block_is_unchanged():
    """Do No Harm: the single-worker block is the exact pre-EXP-4 text (no name_suffix line)."""
    main = _synth([_inst(MOD, "jobs")])["infra/workload/main.tf"]
    assert '''# Event Worker: jobs
module "worker_jobs" {
  source = "../modules/compute-event-worker"

  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  service_account_email = module.foundation.workload_sa_email
  container_image       = "us-docker.pkg.dev/cloudrun/container/hello"
  depends_on            = [module.foundation]
}''' in main
    assert "name_suffix" not in main


@pytest.mark.parametrize("name", ["My Worker!", "Ingest_", "x" * 80, ""])
def test_one_event_worker_with_any_name_is_not_refused(name):
    """Do No Harm: the suffix checks apply only when there are several event workers (no suffix otherwise)."""
    files = _synth([_inst(MOD, name)])
    assert "name_suffix" not in files["infra/workload/main.tf"]


def test_several_event_workers_each_pass_their_instance_name_as_suffix():
    files = _synth([_inst("compute-cloudrun", "api"), _inst(MOD, "ingest"), _inst(MOD, "Nightly_Reports"),
                    _inst(MOD, "")])
    mods = _modules(files["infra/workload/main.tf"])
    assert mods["worker_ingest"]["name_suffix"] == "ingest"
    assert mods["worker_Nightly_Reports"]["name_suffix"] == "nightly-reports"
    assert mods["worker_compute_event_worker_4"]["name_suffix"] == "compute-event-worker-4"
    assert "name_suffix" not in mods["compute_api"]
    outs = {n for b in hcl2.loads(files["infra/workload/outputs.tf"])["output"] for n in b}
    assert {"worker_ingest_job_name", "worker_Nightly_Reports_job_name", "worker_compute_event_worker_4_job_name"} <= outs
    assert sum(k.startswith(f"infra/modules/{MOD}/") for k in files) == 3   # vendored once


def test_the_suffix_line_is_fmt_aligned():
    main = _synth([_inst(MOD, "a"), _inst(MOD, "b")])["infra/workload/main.tf"]
    assert '''  product_id            = var.product_id
  name_suffix           = "a"
  service_account_email = module.foundation.workload_sa_email''' in main


@pytest.mark.parametrize("names, suffix", [(["jobs", "Jobs"], "jobs"), (["a_b", "a-b"], "a-b"),
                                           (["jobs", "jobs"], "jobs")])
def test_equal_suffixes_are_refused(names, suffix):
    with pytest.raises(express_mod.ExpressModuleNameCollisionError) as err:
        _synth([_inst(MOD, n) for n in names])
    assert err.value.reason == "EXPRESS_MODULE_NAME_COLLISION" and err.value.name_suffix == suffix
    assert err.value.instance_names == names


@pytest.mark.parametrize("bad", ["my worker", "-lead", "trail-", "x" * 64, "dot.name"])
def test_a_suffix_that_is_not_an_rfc1123_label_is_refused(bad):
    with pytest.raises(express_mod.ExpressInvalidNameSuffixError) as err:
        _synth([_inst(MOD, "ok"), _inst(MOD, bad)])
    assert err.value.reason == "EXPRESS_INVALID_NAME_SUFFIX" and err.value.instance_name == bad
    assert isinstance(err.value, express_mod.ExpressSynthesisRefused)


def test_name_length_table_matches_the_module_names():
    """The prefixes Express checks are the ones the module puts in front of local.name_stem."""
    names = []
    for block in hcl2.loads(_read(f"infra/modules/{MOD}/main.tf"))["resource"]:
        for body in block.values():
            for attrs in body.values():
                names.append(attrs["name"])
    prefixes = sorted(n[: -len("${local.name_stem}")] for n in names)
    assert prefixes == sorted(p for _, p, _ in express_mod.NAME_SUFFIX_RESOURCE_NAMES[MOD])
    assert {r: limit for r, _, limit in express_mod.NAME_SUFFIX_RESOURCE_NAMES[MOD]} == {
        "Cloud Run job": 63, "Pub/Sub topic": 255, "Pub/Sub subscription": 255}


# product "expv": the job name is "worker-expv-<suffix>" (12 + len(suffix) characters)
@pytest.mark.parametrize("suffix_len, refused", [(51, False), (52, True)])
def test_job_name_63_is_accepted_and_64_is_refused(suffix_len, refused):
    suffix = "s" * suffix_len
    instances = [_inst(MOD, "ok"), _inst(MOD, suffix)]
    if not refused:
        mods = _modules(_synth(instances)["infra/workload/main.tf"])
        assert len(f"worker-expv-{mods['worker_' + suffix]['name_suffix']}") == 63
        return
    with pytest.raises(express_mod.ExpressResourceNameTooLongError) as err:
        _synth(instances)
    e = err.value
    assert e.reason == "EXPRESS_RESOURCE_NAME_TOO_LONG" and isinstance(e, express_mod.ExpressSynthesisRefused)
    assert e.resource == "Cloud Run job" and e.limit == 63 and len(e.resource_name) == 64
    assert e.resource_name == f"worker-expv-{suffix}" and e.instance_name == suffix


def test_job_name_length_uses_the_product_id_with_hyphens():
    """product_id `my_prod` is written `my-prod` in the names: 'worker-my-prod-' (15) + 48 = 63 accepted, 49 refused."""
    def synth(n):
        return ExpressHCLSynthesizer().synthesize_workload(
            product_id="my_prod", project_id="p-1", module_instances=[_inst(MOD, "a"), _inst(MOD, "t" * n)])
    assert 'name_suffix           = "' + "t" * 48 + '"' in synth(48)["infra/workload/main.tf"]
    with pytest.raises(express_mod.ExpressResourceNameTooLongError) as err:
        synth(49)
    assert err.value.resource_name == "worker-my-prod-" + "t" * 49


def test_pubsub_name_limits_are_checked_too(monkeypatch):
    """The topic / subscription limits (255) never bind while the job limit (63) holds; the same loop checks them."""
    table = {MOD: (("Cloud Run job", "worker-", 63), ("Pub/Sub topic", "events-", 255),
                   ("Pub/Sub subscription", "worker-sub-", 20))}
    monkeypatch.setattr(express_mod, "NAME_SUFFIX_RESOURCE_NAMES", table)
    with pytest.raises(express_mod.ExpressResourceNameTooLongError) as err:
        _synth([_inst(MOD, "a"), _inst(MOD, "abcdef")])
    assert err.value.resource == "Pub/Sub subscription" and err.value.resource_name == "worker-sub-expv-abcdef"
    assert err.value.limit == 20


@pytest.mark.parametrize("name", ["s" * 63, "x" * 60])
def test_one_event_worker_with_a_long_name_is_unchanged(name):
    """Do No Harm: the length check is part of the multi-worker suffix plan only."""
    assert "name_suffix" not in _synth([_inst(MOD, name)])["infra/workload/main.tf"]


def test_rfc1123_label_check():
    ok = ["a", "0", "a-b", "x" * 63, "worker-2"]
    bad = ["", "-a", "a-", "A", "a_b", "a b", "x" * 64]
    assert all(express_mod._is_rfc1123_label(s) for s in ok)
    assert not any(express_mod._is_rfc1123_label(s) for s in bad)


# ------------------------------------------------------------------------------------------------ CC route (EXP-5)
def _route(monkeypatch):
    from fd4f_support import FakeDB

    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl

    monkeypatch.setattr(cc_db, "_db_client", False)
    store = FakeDB()
    monkeypatch.setattr(wl, "db", store)
    vending = MagicMock()
    vending.return_value.status_code = 200
    vending.return_value.json.return_value = {"project_id": "castor-exp-1", "github_repo": "org/exp-repo"}
    monkeypatch.setattr(wl, "make_vending_request", vending)
    tf = MagicMock()
    tf.return_value.status_code = 200
    tf.return_value.json.return_value = {"status": "SUCCESS", "service_url": "https://x.run.app"}
    monkeypatch.setattr(wl, "make_terraform_request", tf)
    provider = MagicMock()
    factory = MagicMock()
    factory.get_provider.return_value = provider
    monkeypatch.setattr(wl, "VCSProviderFactory", factory)
    return wl, store, tf, provider


def _run(wl, instances):
    wl.execute_express_provisioning(
        product_id="exp-app", target_project_id="castor-exp-1", clean_vcs_provider="GITHUB",
        full_github_repo="org/exp-repo", target_branch="main", target_folder=None, budget=50.0,
        clean_engine="OPENTOFU", is_sandbox=False, admin_email="admin@example.com", module_instances=instances,
        include_vpc=False, trace_id="tr-exp4", region="us-central1")   # FD-7M-a: as create passes it


def _assert_failed(store, tf, provider, error_class):
    pe = store.docs["pipeline_executions/tr-exp4"]
    stage = pe["stages"]["hcl_synthesis"]
    assert stage["status"] == "FAILED" and stage["error_class"] == error_class and stage["summary"]
    assert pe["status"] == "FAILED" and pe["current_stage"] == "FAILED" and pe["error_class"] == error_class
    assert pe["stages"]["vcs_seed"]["status"] == "SKIPPED" and pe["stages"]["terraform"]["status"] == "SKIPPED"
    wl_doc = store.docs["workloads/exp-app"]
    assert wl_doc["status"] == "FAILED" and wl_doc["failure_reason"].startswith(error_class)
    provider.commit_files.assert_not_called()
    tf.assert_not_called()


def test_route_records_a_refused_synthesis_as_a_failed_stage(monkeypatch):
    wl, store, tf, provider = _route(monkeypatch)
    _run(wl, [_inst(MOD, "jobs"), _inst(MOD, "JOBS")])
    _assert_failed(store, tf, provider, "EXPRESS_MODULE_NAME_COLLISION")


def test_route_records_an_unexpected_synthesis_error_as_a_failed_stage(monkeypatch):
    wl, store, tf, provider = _route(monkeypatch)
    with patch.object(wl.ExpressHCLSynthesizer, "synthesize_workload", side_effect=RuntimeError("boom")):
        _run(wl, [_inst("compute-cloudrun", "api")])
    _assert_failed(store, tf, provider, "EXPRESS_SYNTHESIS_ERROR")
    assert "RuntimeError: boom" in store.docs["pipeline_executions/tr-exp4"]["error_message"]


def test_route_records_an_empty_synthesis_as_a_failed_stage(monkeypatch):
    wl, store, tf, provider = _route(monkeypatch)
    with patch.object(wl.ExpressHCLSynthesizer, "synthesize_workload", return_value={}):
        _run(wl, [_inst("compute-cloudrun", "api")])
    _assert_failed(store, tf, provider, "EXPRESS_SYNTHESIS_EMPTY")


def test_route_without_a_synthesizer_fails_closed(monkeypatch):
    wl, store, tf, provider = _route(monkeypatch)
    monkeypatch.setattr(wl, "ExpressHCLSynthesizer", None)
    _run(wl, [_inst("compute-cloudrun", "api")])
    _assert_failed(store, tf, provider, "EXPRESS_SYNTHESIZER_UNAVAILABLE")


def test_route_negative_a_successful_synthesis_still_commits_and_deploys(monkeypatch):
    """Do No Harm: a synthesis that produces files keeps the SUCCESS stage, the commit and the deploy."""
    wl, store, tf, provider = _route(monkeypatch)
    _run(wl, [_inst("compute-cloudrun", "api"), _inst(MOD, "ingest"), _inst(MOD, "reports")])
    pe = store.docs["pipeline_executions/tr-exp4"]
    assert pe["status"] == "COMPLETED" and "error_class" not in pe
    # FakeDB merges shallowly (Firestore merges nested maps), so read the stage from the writes themselves
    synth = [w[1]["stages"]["hcl_synthesis"]["status"] for w in store.writes
             if w[0] == "pipeline_executions/tr-exp4" and "hcl_synthesis" in w[1].get("stages", {})]
    assert synth[-1] == "SUCCESS" and "FAILED" not in synth
    files = provider.commit_files.call_args[1]["files"]
    assert 'name_suffix           = "reports"' in files["infra/workload/main.tf"]
    tf.assert_called_once()
    assert store.docs["workloads/exp-app"]["status"] == "ACTIVE"

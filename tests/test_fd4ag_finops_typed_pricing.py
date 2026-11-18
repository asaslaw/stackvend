"""
FD-4AG-b (AG-5, AG-6, rest of AG-7): the FinOps cost check prices the architect's TYPED compute fields from one exact
table, never task description keywords; `/evaluate-plan-json` honours the caller's budget; the workspace Drive
folder listing refuses an ID that could rewrite the Drive `q` string.

Hermetic: modules are loaded by file path; every InfracostCalculator gets a fake Firestore (no real client is
built, the budget is passed explicitly or read from the fake); the Drive service is a recording fake.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent
IC_DIR = REPO / "mcp-servers" / "infracost"
WS_DIR = REPO / "mcp-servers" / "workspace"


# ------------------------------------------------------------------------------------------------- fakes / loaders
class _Doc:
    def __init__(self, data):
        self._data = data
        self.exists = data is not None

    def to_dict(self):
        return copy.deepcopy(self._data)


class FakeDb:
    """collection(c).document(d).get() over a {(collection, doc_id): dict} map; records every read."""

    def __init__(self, docs=None, fail=False):
        self.docs = docs or {}
        self.fail = fail
        self.reads = []

    def collection(self, cname):
        db = self

        class _Ref:
            def __init__(self, doc_id):
                self.doc_id = doc_id

            def get(self):
                db.reads.append((cname, self.doc_id))
                if db.fail:
                    raise RuntimeError("firestore unavailable")
                return _Doc(db.docs.get((cname, self.doc_id)))

        class _Coll:
            def document(self, doc_id):
                return _Ref(doc_id)

        return _Coll()


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod   # unique fd4agb_* names; dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


calc_mod = _load("fd4agb_infracost_calculator", IC_DIR / "calculator.py")
MAIN_DB = FakeDb()


def _load_infracost_main():
    shim = types.ModuleType("calculator")
    shim.InfracostCalculator = lambda: calc_mod.InfracostCalculator(firestore_client=MAIN_DB)
    saved = sys.modules.get("calculator")
    sys.modules["calculator"] = shim
    try:
        return _load("fd4agb_infracost_main", IC_DIR / "main.py")
    finally:
        if saved is None:
            sys.modules.pop("calculator", None)
        else:
            sys.modules["calculator"] = saved


ic_main = _load_infracost_main()
ws_service = _load("fd4agb_ws_service", WS_DIR / "service.py")


def _load_ws_main():
    shim = types.ModuleType("service")
    shim.WorkspaceService = lambda: ws_service.WorkspaceService(drive_service=MagicMock(), docs_service=MagicMock())
    shim.InvalidDriveIdError = ws_service.InvalidDriveIdError
    incident_doc = _load("fd4agb_ws_incident_doc", WS_DIR / "incident_doc.py")  # FD-4BM: main.py imports it
    saved = {name: sys.modules.get(name) for name in ("service", "incident_doc")}
    sys.modules["service"] = shim
    sys.modules["incident_doc"] = incident_doc
    try:
        return _load("fd4agb_ws_main", WS_DIR / "main.py")
    finally:
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod


ws_main = _load_ws_main()


def calc(db=None):
    return calc_mod.InfracostCalculator(firestore_client=db if db is not None else FakeDb())


def topo(services, resources=(), primary=None):
    """A v2 architect_compute_intent record (architect_agent/schemas.py compute_intent_record form)."""
    services = [{"name": n, "kind": k, "purpose": "", "scaling": None, "vm": None} for n, k in services]
    prim = primary or (services[0]["name"] if services else None)
    kind = services[0]["kind"] if services else "foundation-only"
    return {
        "schema": "architect_compute_intent/v2",
        "target_compute_services": [s["name"] for s in services],
        "bundle_id": None,
        "compute_archetype": kind,
        "service_topology": {
            "schema": "service_topology/v1",
            "intent": {"services": services, "primary_service": prim, "edges": [],
                       "resources": [{"type": t, "logical_name": ln, "purpose": "", "consumers": []}
                                     for t, ln in resources]},
            "sha256": "0" * 64, "archetype": kind, "service_names": [s["name"] for s in services],
            "http_entrypoint": None,
        },
    }


def plan(*descriptions, requires_approval=False):
    return {"infra_tasks_count": len(descriptions), "requires_approval": requires_approval,
            "tasks": [{"task_id": f"INFRA-0{i + 1}", "title": f"Infra task {i + 1}", "description": d}
                      for i, d in enumerate(descriptions)]}


RESPONSE_KEYS = {"monthly_cost_estimate", "monthly_cost_delta_usd", "budget_ceiling_usd", "is_under_budget",
                 "requires_human_approval", "breakdown", "risk_assessment", "status"}


# ------------------------------------------------------------------------------------------------- AG-5 pricing
def test_fd27_11_gke_described_with_firestore_is_priced_as_gke_and_needs_approval():
    """The FD27-11 example: the old chain hit the Firestore branch first ($0, no GKE flag, no approval)."""
    res = calc().evaluate_infra_plan(
        "p", "tr-1", plan("Provision a GKE Autopilot cluster; the app stores state in Firestore"),
        budget_ceiling=500.0, compute_intent=topo([("api", "gke-autopilot")]))
    assert res["monthly_cost_delta_usd"] == 73.0
    assert [(b["kind"], b["high_risk"]) for b in res["breakdown"]] == [("gke-autopilot", True)]
    assert res["requires_human_approval"] is True
    assert "GKE" in res["risk_assessment"]
    assert RESPONSE_KEYS <= set(res)


def test_cloudrun_plan_mentioning_sql_and_nosql_gets_no_sql_line_from_text():
    res = calc().evaluate_infra_plan(
        "p", "tr-2", plan("Cloud Run service that uses Cloud SQL and nosql", "Wire the Postgres / MySQL client"),
        budget_ceiling=40.0, compute_intent=topo([("web", "cloudrun")]))
    assert res["monthly_cost_delta_usd"] == 0.0
    assert all(b["monthly_cost"] != 15.0 for b in res["breakdown"])
    assert [b["kind"] for b in res["breakdown"]] == ["cloudrun"]
    assert res["requires_human_approval"] is False
    assert res["unpriced_items"] == 0 and res["estimate_is_lower_bound"] is False
    assert res["monthly_cost_estimate"] == "+$0.00/mo"


@pytest.mark.parametrize("intent", [
    topo([("web", "cloudrun")]),
    topo([("api", "gke-autopilot"), ("ui", "cloudrun")], resources=[("google_sql_database_instance", "db")]),
    None,   # no typed fields: unpriced task TITLES (approval required), still independent of the description
])
def test_description_text_has_no_effect_on_the_result(intent):
    """Negative (Do No Harm) test: same typed plan, three very different descriptions -> identical output."""
    descs = ["GKE kubernetes cluster with Cloud SQL postgres", "stores state in Firestore / datastore",
             "a plain cloud run service"]
    outs = [calc().evaluate_infra_plan("p", "tr-3", plan(d), budget_ceiling=40.0, compute_intent=intent)
            for d in descs]
    assert outs[0] == outs[1] == outs[2]


def test_unknown_kind_is_unpriced_and_requires_approval():
    """FD-4AG-b-r F2: an unpriced COMPUTE kind fails closed (was a silent pass)."""
    intent = topo([("web", "cloudrun")])
    intent["service_topology"]["intent"]["services"].append({"name": "x", "kind": "tpu-pod"})
    res = calc().evaluate_infra_plan("p", "tr-4", plan("anything"), budget_ceiling=40.0, compute_intent=intent)
    unpriced = [b for b in res["breakdown"] if not b["priced"]]
    assert unpriced == [{"resource": "x (kind 'tpu-pod')", "line": "compute", "kind": "tpu-pod",
                         "monthly_cost": None, "priced": False}]
    assert res["unpriced_items"] == 1 and res["estimate_is_lower_bound"] is True
    assert res["requires_human_approval"] is True
    assert res["approval_reasons"] == [calc_mod.APPROVAL_UNPRICED_COMPUTE]
    assert "no price row" in res["risk_assessment"]
    assert res["monthly_cost_estimate"] == "+$0.00/mo (lower bound; 1 unpriced)"


def test_service_without_kind_requires_approval():
    intent = topo([("web", "cloudrun")])
    intent["service_topology"]["intent"]["services"].append({"name": "nokind"})
    res = calc().evaluate_infra_plan("p", "tr-4a", plan("x"), budget_ceiling=40.0, compute_intent=intent)
    assert res["requires_human_approval"] is True
    assert res["approval_reasons"] == [calc_mod.APPROVAL_UNPRICED_COMPUTE]


def test_unknown_resource_type_is_unpriced_lower_bound_only():
    """A non-catalog resource type (cannot pass the topology gate) only makes the estimate a lower bound."""
    res = calc().evaluate_infra_plan(
        "p", "tr-4b", plan(), budget_ceiling=40.0,
        compute_intent=topo([("web", "cloudrun")], resources=[("google_spanner_instance", "db")]))
    assert res["breakdown"][1] == {"resource": "google_spanner_instance.db", "line": "resource",
                                   "resource_type": "google_spanner_instance", "monthly_cost": None, "priced": False}
    assert res["unpriced_items"] == 1 and res["requires_human_approval"] is False
    assert res["approval_reasons"] == []


def test_every_topology_catalog_type_has_a_price_row():
    """FD-4AG-b-r F1: a catalog addition without a price row fails here instead of failing open."""
    st = _load("fd4agb_service_topology_cat", REPO / "shared" / "service_topology.py")
    assert set(st.BOOTSTRAP_CATALOG) <= set(calc_mod.GCP_RESOURCE_PRICING)


def test_redis_backed_cloud_run_plan_is_priced():
    res = calc().evaluate_infra_plan(
        "p", "tr-4c", plan(), budget_ceiling=40.0,
        compute_intent=topo([("web", "cloudrun")], resources=[("google_redis_instance", "cache"),
                                                               ("google_bigquery_dataset", "lake")]))
    assert res["monthly_cost_delta_usd"] == 35.0 and res["unpriced_items"] == 0
    assert res["requires_human_approval"] is False


def test_no_typed_fields_lists_every_task_title_unpriced_and_requires_approval():
    """FD-4AG-b-r F2: no typed record for a plan with tasks fails closed (the old chain priced GKE text $73)."""
    db = FakeDb()   # no pipeline_executions document
    res = calc(db).evaluate_infra_plan("p", "tr-5", plan("GKE cluster", "Cloud SQL"), budget_ceiling=40.0)
    assert res["breakdown"] == [{"resource": "Infra task 1", "line": "task", "monthly_cost": None, "priced": False},
                                {"resource": "Infra task 2", "line": "task", "monthly_cost": None, "priced": False}]
    assert res["pricing_source"] == calc_mod.PRICING_SOURCE_NONE
    assert res["unpriced_items"] == 2 and res["monthly_cost_delta_usd"] == 0.0
    assert res["requires_human_approval"] is True
    assert res["approval_reasons"] == [calc_mod.APPROVAL_NO_TYPED_RECORD]
    assert "No typed compute record for trace 'tr-5'" in res["risk_assessment"]
    assert db.reads == [("pipeline_executions", "tr-5")]


def test_no_db_and_no_record_requires_approval():
    c = calc_mod.InfracostCalculator(firestore_client=FakeDb())
    c.db = None   # PROJECT_ID unset / client construction failed at startup
    res = c.evaluate_infra_plan("p", "auto-trace", plan("Create Kubernetes cluster"), budget_ceiling=40.0)
    assert res["requires_human_approval"] is True


def test_empty_plan_without_typed_fields_needs_no_approval():
    res = calc().evaluate_infra_plan("p", "tr-5c", plan(), budget_ceiling=40.0)
    assert res["breakdown"] == [] and res["requires_human_approval"] is False


def test_v2_record_without_compute_archetype_or_topology_is_untyped():
    res = calc().evaluate_infra_plan("p", "tr-5b", plan("x"), budget_ceiling=40.0,
                                     compute_intent={"schema": "architect_compute_intent/v1",
                                                     "target_compute_services": ["a"], "compute_archetype": None})
    assert res["pricing_source"] == calc_mod.PRICING_SOURCE_NONE and res["unpriced_items"] == 1
    assert res["requires_human_approval"] is True


def _scaled(kind, n):
    intent = topo([("web", kind)])
    intent["service_topology"]["intent"]["services"][0]["scaling"] = {
        "min_instances": n, "max_instances": 10, "cpu_always_allocated": n > 0}
    return intent


@pytest.mark.parametrize("kind", ["cloudrun", "event-worker"])
def test_min_instances_zero_is_unchanged(kind):
    """FD-4AG-b-r F3 negative (Do No Harm): min_instances 0 prices exactly like no scaling at all."""
    a = calc().evaluate_infra_plan("p", "tr-s0", plan(), budget_ceiling=40.0, compute_intent=_scaled(kind, 0))
    b = calc().evaluate_infra_plan("p", "tr-s0", plan(), budget_ceiling=40.0, compute_intent=topo([("web", kind)]))
    assert a == b and a["monthly_cost_delta_usd"] == 0.0


@pytest.mark.parametrize("kind", ["cloudrun", "event-worker"])
def test_two_min_instances_cross_the_ceiling(kind):
    res = calc().evaluate_infra_plan("p", "tr-s2", plan(), budget_ceiling=40.0, compute_intent=_scaled(kind, 2))
    assert res["monthly_cost_delta_usd"] == 45.0
    assert res["breakdown"][1] == {"resource": "web min instances x2", "line": "min_instances", "kind": kind,
                                   "monthly_cost": 45.0, "priced": True, "high_risk": False}
    assert res["requires_human_approval"] is True and res["is_under_budget"] is False


def test_min_instances_on_a_vm_kind_is_not_billed():
    intent = topo([("vm", "gce-worker")])
    intent["service_topology"]["intent"]["services"][0]["scaling"] = {"min_instances": 3}
    res = calc().evaluate_infra_plan("p", "tr-s3", plan(), budget_ceiling=40.0, compute_intent=intent)
    assert res["monthly_cost_delta_usd"] == 25.0


@pytest.mark.parametrize("archetype,services,expect_cost", [
    ("gke-autopilot", [], 73.0),                          # the reviewer's probe: foundation-only must not win
    ("gke-autopilot", [("web", "cloudrun")], 73.0),
    ("foundation-only", [("web", "cloudrun")], 0.0),
    ("tpu-pod", [("web", "cloudrun")], 0.0),
])
def test_archetype_inconsistent_with_topology_requires_approval(archetype, services, expect_cost):
    """FD-4AG-b-r F4: the archetype is priced too (max, never min) and the record is flagged -> approval."""
    intent = topo(services)
    intent["compute_archetype"] = archetype
    res = calc().evaluate_infra_plan("p", "tr-f4", plan(), budget_ceiling=500.0, compute_intent=intent)
    assert res["monthly_cost_delta_usd"] == expect_cost
    assert calc_mod.APPROVAL_INCONSISTENT_RECORD in res["approval_reasons"]
    assert res["requires_human_approval"] is True


def test_consistent_record_is_not_flagged():
    res = calc().evaluate_infra_plan("p", "tr-f4b", plan(), budget_ceiling=40.0,
                                     compute_intent=topo([("web", "cloudrun"), ("w", "event-worker")]))
    assert res["approval_reasons"] == [] and res["requires_human_approval"] is False


def test_multi_service_topology_prices_every_service_once():
    intent = topo([("api", "cloudrun"), ("events", "event-worker"), ("batch", "gce-worker")],
                  resources=[("google_sql_database_instance", "db"), ("google_storage_bucket", "uploads"),
                             ("google_pubsub_topic", "jobs")])
    res = calc().evaluate_infra_plan("p", "tr-6", plan("a", "b", "c", "d", "e"), budget_ceiling=100.0,
                                     compute_intent=intent)
    kinds = [b.get("kind") for b in res["breakdown"] if "kind" in b]
    assert kinds == ["cloudrun", "event-worker", "gce-worker"]
    assert [b["resource"] for b in res["breakdown"]] == [
        "api (Cloud Run (Scale to Zero))", "events (Cloud Run event worker (Scale to Zero))",
        "batch (Compute Engine worker VM)", "google_sql_database_instance.db", "google_storage_bucket.uploads",
        "google_pubsub_topic.jobs"]
    assert res["monthly_cost_delta_usd"] == 40.5   # 0 + 0 + 25 + 15 + 0.50 + 0
    assert res["requires_human_approval"] is False


def test_over_budget_from_typed_fields_requires_approval():
    intent = topo([("bastion", "gce-bastion"), ("batch", "gce-worker")],
                  resources=[("google_sql_database_instance", "db")])
    res = calc().evaluate_infra_plan("p", "tr-7", plan(), budget_ceiling=40.0, compute_intent=intent)
    assert res["monthly_cost_delta_usd"] == 65.0 and res["is_under_budget"] is False
    assert res["requires_human_approval"] is True


def test_foundation_only_topology_is_one_zero_line():
    res = calc().evaluate_infra_plan("p", "tr-8", plan("APIs only"), budget_ceiling=40.0, compute_intent=topo([]))
    assert res["breakdown"] == [{"resource": "Foundation only (no compute)", "line": "compute",
                                 "kind": "foundation-only", "monthly_cost": 0.0, "priced": True, "high_risk": False}]
    assert res["requires_human_approval"] is False


def test_v1_record_prices_archetype_then_cloud_run_secondaries():
    intent = {"schema": "architect_compute_intent/v1", "target_compute_services": ["cluster-app", "ui"],
              "bundle_id": None, "compute_archetype": "gke-autopilot"}
    res = calc().evaluate_infra_plan("p", "tr-9", plan(), budget_ceiling=500.0, compute_intent=intent)
    assert [b["kind"] for b in res["breakdown"]] == ["gke-autopilot", "cloudrun"]
    assert res["monthly_cost_delta_usd"] == 73.0 and res["requires_human_approval"] is True


def test_plan_requires_approval_flag_still_triggers():
    res = calc().evaluate_infra_plan("p", "tr-10", plan("x", requires_approval=True), budget_ceiling=40.0,
                                     compute_intent=topo([("web", "cloudrun")]))
    assert res["requires_human_approval"] is True


def test_every_table_row_is_a_typed_compute_value():
    """The table keys are exactly the typed kinds (shared/service_topology.py) plus the foundation-only archetype."""
    st = _load("fd4agb_service_topology", REPO / "shared" / "service_topology.py")
    assert set(calc_mod.COMPUTE_KIND_PRICING) == set(st.COMPUTE_KINDS) | {st.FOUNDATION_ONLY}
    assert calc_mod.COMPUTE_KIND_PRICING["gke-autopilot"] == {
        "label": "GKE Autopilot Cluster", "monthly_cost": 73.0, "high_risk": True}
    for k in ("cloudrun", "event-worker", "foundation-only"):
        assert calc_mod.COMPUTE_KIND_PRICING[k]["monthly_cost"] == 0.0
    assert [k for k, v in calc_mod.COMPUTE_KIND_PRICING.items() if v["high_risk"]] == ["gke-autopilot"]


def test_pricing_path_never_reads_description_text():
    """Acceptance: no `.lower()` and no 'description' lookup anywhere in the pricing path (AST, not text)."""
    tree = ast.parse((IC_DIR / "calculator.py").read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "InfracostCalculator")
    names = {"evaluate_infra_plan", "price_compute_intent", "_price_kind", "_price_resource", "load_compute_intent"}
    funcs = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert len(funcs) == len(names)
    for fn in funcs:
        for node in ast.walk(fn):
            assert not (isinstance(node, ast.Attribute) and node.attr == "lower"), fn.name
            assert not (isinstance(node, ast.Constant) and node.value == "description"), fn.name
            assert not isinstance(node, ast.Compare) or not any(
                isinstance(op, (ast.In, ast.NotIn)) and isinstance(c, ast.Name) and c.id == "desc"
                for op, c in zip(node.ops, node.comparators)), fn.name


# ------------------------------------------------------------------------------------------------- typed source
def test_firestore_compute_intent_record_is_used_when_the_request_has_none():
    db = FakeDb({("pipeline_executions", "tr-11"): {"architect_compute_intent": topo([("api", "gke-autopilot")])}})
    res = calc(db).evaluate_infra_plan("p", "tr-11", plan("stores state in Firestore"), budget_ceiling=500.0)
    assert res["pricing_source"] == calc_mod.PRICING_SOURCE_FIRESTORE
    assert res["requires_human_approval"] is True and res["monthly_cost_delta_usd"] == 73.0


def test_persisted_record_outranks_the_request_field():
    """FD-4AG-b-r F5: the record written inside the architect's gate wins over whatever the caller sends."""
    db = FakeDb({("pipeline_executions", "tr-12"): {"architect_compute_intent": topo([("api", "gke-autopilot")])}})
    res = calc(db).evaluate_infra_plan("p", "tr-12", plan(), budget_ceiling=40.0,
                                       compute_intent=topo([("web", "cloudrun")]))
    assert res["pricing_source"] == calc_mod.PRICING_SOURCE_FIRESTORE
    assert db.reads == [("pipeline_executions", "tr-12")]
    assert res["monthly_cost_delta_usd"] == 73.0 and res["requires_human_approval"] is True


def test_request_field_is_used_only_without_a_persisted_record():
    db = FakeDb()
    res = calc(db).evaluate_infra_plan("p", "tr-12b", plan("x"), budget_ceiling=40.0,
                                       compute_intent=topo([("web", "cloudrun")]))
    assert res["pricing_source"] == calc_mod.PRICING_SOURCE_REQUEST
    assert db.reads == [("pipeline_executions", "tr-12b")]
    assert res["requires_human_approval"] is False


def test_firestore_read_error_fails_closed():
    with pytest.raises(calc_mod.ComputeIntentUnavailableError):
        calc(FakeDb(fail=True)).evaluate_infra_plan("p", "tr-13", plan("x"), budget_ceiling=40.0)


def test_evaluate_route_read_error_is_500_so_the_gate_requires_approval():
    MAIN_DB.fail = True
    try:
        r = TestClient(ic_main.app).post("/evaluate", json={
            "trace_id": "tr-14", "product_id": "p", "proposed_infra_plan": plan("x"), "budget_ceiling": 40.0})
    finally:
        MAIN_DB.fail = False
    assert r.status_code == 500 and "could not be read" in r.json()["detail"]


def test_evaluate_route_passes_architect_compute_intent():
    r = TestClient(ic_main.app).post("/evaluate", json={
        "trace_id": "tr-15", "product_id": "p", "proposed_infra_plan": plan("stores state in Firestore"),
        "budget_ceiling": 40.0, "architect_compute_intent": topo([("api", "gke-autopilot")])})
    assert r.status_code == 200
    body = r.json()
    assert body["requires_human_approval"] is True and body["pricing_source"] == calc_mod.PRICING_SOURCE_REQUEST
    assert RESPONSE_KEYS <= set(body)


# ------------------------------------------------------------------------------------------------- AG-6
def test_evaluate_plan_json_honours_the_budget_ceiling():
    MAIN_DB.reads.clear()
    plan_json = {"resource_changes": [{"type": "google_sql_database_instance", "name": "db",
                                       "change": {"actions": ["create"], "after": {}}}]}
    r = TestClient(ic_main.app).post("/evaluate-plan-json", json={"plan_json": plan_json, "budget_ceiling": 10})
    assert r.status_code == 200
    body = r.json()
    assert body["budget_ceiling_usd"] == 10.0
    assert body["monthly_cost_delta_usd"] == 15.0 and body["is_under_budget"] is False
    assert body["requires_human_approval"] is True
    assert MAIN_DB.reads == []   # an explicit ceiling never consults the workload budget


def test_evaluate_plan_json_uses_the_product_budget_when_no_ceiling_is_given():
    MAIN_DB.docs[("workloads", "prod-x")] = {"budget_ceiling_monthly_usd": 12.5}
    try:
        r = TestClient(ic_main.app).post("/evaluate-plan-json", json={"plan_json": {}, "product_id": "prod-x"})
    finally:
        MAIN_DB.docs.pop(("workloads", "prod-x"), None)
    assert r.status_code == 200 and r.json()["budget_ceiling_usd"] == 12.5


# ------------------------------------------------------------------------------------------------- AG-7 Drive q
class RecordingDrive:
    def __init__(self):
        self.calls = []

    def files(self):
        drive = self

        class _Files:
            def list(self, **kw):
                drive.calls.append(kw)
                req = MagicMock()
                req.execute.return_value = {"files": [{"id": "f1"}]}
                return req

        return _Files()


@pytest.mark.parametrize("bad", ["x' in parents or name contains '", "", "a" * 129, "abc def", "abc\\", "földer",
                                 "abc'", None, 123])
def test_list_folder_files_rejects_non_drive_ids_before_any_drive_call(bad):
    drive = RecordingDrive()
    svc = ws_service.WorkspaceService(drive_service=drive, docs_service=MagicMock())
    with pytest.raises(ws_service.InvalidDriveIdError):
        svc.list_folder_files(bad)
    assert drive.calls == []


@pytest.mark.parametrize("good", ["1AbC-dEf_9", "root", "a" * 128])
def test_list_folder_files_valid_id_passes_unchanged(good):
    """Negative (Do No Harm) test: a valid Drive ID reaches Drive exactly as before."""
    drive = RecordingDrive()
    svc = ws_service.WorkspaceService(drive_service=drive, docs_service=MagicMock())
    assert svc.list_folder_files(good) == [{"id": "f1"}]
    assert drive.calls[0]["q"] == f"'{good}' in parents and trashed = false"
    assert ws_service.validate_drive_id(good) == good


def test_list_folder_route_answers_422_typed():
    drive = RecordingDrive()
    saved = ws_main.service
    ws_main.service = ws_service.WorkspaceService(drive_service=drive, docs_service=MagicMock())
    try:
        r = TestClient(ws_main.app).post("/list-folder", json={"folder_id": "x' in parents or name contains '"})
        ok = TestClient(ws_main.app).post("/list-folder", json={"folder_id": "1AbC"})
    finally:
        ws_main.service = saved
    assert r.status_code == 422 and r.json()["error_class"] == "INVALID_DRIVE_ID"
    assert ok.status_code == 200 and ok.json() == {"files": [{"id": "f1"}]}
    assert len(drive.calls) == 1


def test_list_folder_route_maps_only_invalid_ids_to_422():
    """FD-4AG-b-r F6: a ValueError raised by Drive after a valid ID passed is a 500, not "invalid id"."""
    drive = MagicMock()
    drive.files.return_value.list.return_value.execute.side_effect = ValueError("bad json from drive")
    saved = ws_main.service
    ws_main.service = ws_service.WorkspaceService(drive_service=drive, docs_service=MagicMock())
    try:
        r = TestClient(ws_main.app).post("/list-folder", json={"folder_id": "1AbC"})
    finally:
        ws_main.service = saved
    assert r.status_code == 500


# ------------------------------------------------------------------------------------------------- F7 plan-JSON
def test_plan_json_min_instances_only_for_exact_cloud_run_service_types():
    c = calc()
    assert c.estimate_resource_cost("google_cloud_run_v2_job", {"scaling": {"min_instance_count": 1}}) == 0.0
    assert c.estimate_resource_cost("google_cloud_run_v2_service", {"scaling": {"min_instance_count": 1}}) == 22.5
    assert c.estimate_resource_cost("google_cloud_run_service", {"scaling": {"min_instance_count": 2}}) == 45.0


@pytest.mark.parametrize("cfg", [{"scaling": [{"min_instance_count": 1}]}, {"scaling": None}, {}, None,
                                 {"scaling": {"min_instance_count": True}}])
def test_plan_json_scaling_shapes_never_raise(cfg):
    """A list-shaped `scaling` (as `terraform show -json` nests it) is not read (separate row) and never raises."""
    assert calc().estimate_resource_cost("google_cloud_run_v2_service", cfg) == 0.0


def test_workspace_fake_success_statuses_are_gone():
    """AG-7 (WS-1, already landed): no 200 fake-success fallbacks remain in the workspace server."""
    src = (WS_DIR / "main.py").read_text() + (WS_DIR / "service.py").read_text()
    assert "ERROR_SUPPRESSED" not in src and "APPROVAL_RECORDED_FALLBACK" not in src

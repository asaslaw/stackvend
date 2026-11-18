"""
Wave 2 lane 14 PR-2: log-sre-sentinel classification, recording and dispatch rules (owner register row 24; plan
docs/planning/wave2-lane14-core-services-plan.md section 2.5).

Hermetic: an in-memory Firestore fake, injected resolvers (host project number, Cloud Run URLs) and an injected
workflow starter. Nothing here builds a cloud client.

The log entries below are modeled on the documented Cloud Logging shapes of each resource type. Stage 2 (owner,
read-only) replaces them with one captured live entry per type (plan G6); the assertions on label keys stay.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)


import ast
import base64
import copy
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from google.api_core.exceptions import AlreadyExists, FailedPrecondition, NotFound
from google.cloud import firestore

REPO = Path(__file__).resolve().parent.parent
APP_DIR = REPO / "apps" / "log-sre-sentinel"


def _load_app_modules():
    """Load sre_classifier, sentinel and main from the app dir without leaving it on sys.path (other suites import
    their own ``main``)."""
    sys.path.insert(0, str(APP_DIR))
    try:
        import sre_classifier  # noqa: F401
        import sentinel as sentinel_mod

        spec = importlib.util.spec_from_file_location("lane14_sentinel_main", APP_DIR / "main.py")
        main_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main_mod)
    finally:
        sys.path.remove(str(APP_DIR))
    return sys.modules["sre_classifier"], sentinel_mod, main_mod


clf, sentinel_mod, main_mod = _load_app_modules()

HOST = "mock-stackvend-project"
HOST_NUMBER = "123456789012"
REGION = "us-central1"
NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------------------------------------------
# Firestore fake
# ---------------------------------------------------------------------------------------------------------------
class FakeSnap:
    def __init__(self, doc_id, data, update_time=None):
        self.id = doc_id
        self._data = copy.deepcopy(data)
        self.update_time = update_time if data is not None else None

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return copy.deepcopy(self._data)


class FakeDocRef:
    def __init__(self, db, coll, doc_id):
        self.db, self.coll, self.id = db, coll, doc_id

    def _store(self):
        self.db._check(self.coll)
        return self.db.data.setdefault(self.coll, {})

    def _touch(self):
        self.db.versions[(self.coll, self.id)] = self.db.versions.get((self.coll, self.id), 0) + 1

    def get(self):
        store = self._store()
        return FakeSnap(self.id, store.get(self.id), self.db.versions.get((self.coll, self.id), 0))

    def set(self, data, merge=False):
        store = self._store()
        if merge and self.id in store:
            store[self.id].update(copy.deepcopy(data))
        else:
            store[self.id] = copy.deepcopy(data)
        self._touch()

    def create(self, data):
        store = self._store()
        if self.id in store:
            raise AlreadyExists(f"{self.coll}/{self.id}")
        store[self.id] = copy.deepcopy(data)
        self._touch()

    def update(self, data, option=None):
        store = self._store()
        if self.id not in store:
            raise NotFound(f"{self.coll}/{self.id}")
        if option is not None and option.last_update_time != self.db.versions.get((self.coll, self.id), 0):
            raise FailedPrecondition(f"{self.coll}/{self.id}: stale last_update_time")
        for k, v in data.items():
            if isinstance(v, firestore.Increment):
                store[self.id][k] = store[self.id].get(k, 0) + v.value
            else:
                store[self.id][k] = copy.deepcopy(v)
        self._touch()

    def delete(self):
        self._store().pop(self.id, None)
        self._touch()


class FakeWriteOption:
    def __init__(self, last_update_time):
        self.last_update_time = last_update_time


class FakeBatch:
    """All-or-nothing like a Firestore WriteBatch: every precondition and collection is checked before any write."""

    def __init__(self, db):
        self.db, self.ops = db, []

    def create(self, ref, data):
        self.ops.append(("create", ref, data, None))

    def set(self, ref, data, merge=False):
        self.ops.append(("set", ref, data, merge))

    def update(self, ref, data, option=None):
        self.ops.append(("update", ref, data, option))

    def commit(self):
        self.db.commits += 1
        for op, ref, _data, option in self.ops:
            store = ref._store()  # raises for a failing collection
            if op == "create" and ref.id in store:
                raise AlreadyExists(f"{ref.coll}/{ref.id}")
            if op == "update" and ref.id not in store:
                raise NotFound(f"{ref.coll}/{ref.id}")
            if op == "update" and option is not None and \
                    option.last_update_time != self.db.versions.get((ref.coll, ref.id), 0):
                raise FailedPrecondition(f"{ref.coll}/{ref.id}: stale last_update_time")
        for op, ref, data, extra in self.ops:
            if op == "create":
                ref.create(data)
            elif op == "set":
                ref.set(data, merge=extra)
            else:
                ref.update(data)


class FakeQuery:
    def __init__(self, db, coll, filters=(), limit_n=None):
        self.db, self.coll, self.filters, self.limit_n = db, coll, tuple(filters), limit_n

    def where(self, field, op, value):
        assert op == "=="
        return FakeQuery(self.db, self.coll, self.filters + ((field, value),), self.limit_n)

    def limit(self, n):
        return FakeQuery(self.db, self.coll, self.filters, n)

    def stream(self):
        self.db._check(self.coll)
        out = [FakeSnap(k, v) for k, v in self.db.data.get(self.coll, {}).items()
               if all(v.get(f) == val for f, val in self.filters)]
        return iter(out[: self.limit_n] if self.limit_n is not None else out)


class FakeCollection(FakeQuery):
    def document(self, doc_id):
        return FakeDocRef(self.db, self.coll, doc_id)


class FakeDB:
    def __init__(self):
        self.data = {}
        self.versions = {}
        self.failing = set()
        self.commits = 0

    def _check(self, coll):
        if coll in self.failing:
            raise RuntimeError(f"firestore unavailable: {coll}")

    def collection(self, name):
        return FakeCollection(self, name)

    def batch(self):
        return FakeBatch(self)

    @staticmethod
    def write_option(last_update_time):
        return FakeWriteOption(last_update_time)


def _ledger(db):
    db.data["workloads"] = {
        "shop-app": {"project_id": "child-shop-1", "status": "ACTIVE", "sre_auto_healing_enabled": True,
                     "code_freeze": False, "github_repo": "acme/shop-app"},
        "other-app": {"project_id": "child-other-2", "status": "ACTIVE", "sre_auto_healing_enabled": True,
                      "code_freeze": False, "github_repo": "acme/other-app"},
        "project-castor": {"project_id": HOST, "is_castor": True, "status": "ACTIVE",
                           "sre_auto_healing_enabled": True, "code_freeze": False},
    }
    return db


class Harness:
    def __init__(self, env=None, host_number=HOST_NUMBER, url_resolver=None, starter_error=None, db=None):
        self.db = db if db is not None else _ledger(FakeDB())
        self.env = {"PROJECT_ID": HOST, "REGION": REGION}
        self.env.update(env or {})
        self.starts = []
        self.now = NOW

        def starter(parent, argument_json):
            if starter_error:
                raise starter_error
            self.starts.append((parent, json.loads(argument_json)))
            return f"{parent}/executions/exec-{len(self.starts)}"

        self.sentinel = sentinel_mod.LogSRESentinel(
            project_id=HOST,
            firestore_client=self.db,
            env=self.env,
            host_number_resolver=lambda project: host_number,
            service_url_resolver=url_resolver or (lambda project, region, name: f"https://{name}-h4sh.a.run.app"),
            workflow_starter=starter,
            clock=lambda: self.now,
        )

    def process(self, entry):
        return self.sentinel.process_log_event(entry)

    def incident(self, result):
        return self.db.data["incidents"][result["incident_id"]]


# ---------------------------------------------------------------------------------------------------------------
# Log entry fixtures (documented shapes; see module docstring)
# ---------------------------------------------------------------------------------------------------------------
def workflows_entry(workflow_id="castor-main-orchestrator", execution_id="7d1c2a9e-0f3c-4c55-9a51-2b7f0e6d1a10",
                    container=HOST_NUMBER, project=HOST, message="Execution failed: StackVendPipelineError"):
    return {
        "insertId": "wf-1",
        "logName": f"projects/{project}/logs/workflows.googleapis.com%2Fexecutions_system",
        "resource": {
            "type": "workflows.googleapis.com/Workflow",
            "labels": {"workflow_id": workflow_id, "location": REGION, "resource_container": container},
        },
        "labels": {"workflows.googleapis.com/execution_id": execution_id},
        "severity": "ERROR",
        "jsonPayload": {"message": message, "state": "FAILED"},
    }


def run_service_entry(service_name, project=HOST, trace="Traceback\nKeyError: 'doc_id'", severity="ERROR",
                      label_project=None):
    return {
        "insertId": "run-1",
        "logName": f"projects/{project}/logs/run.googleapis.com%2Fstderr",
        "resource": {
            "type": "cloud_run_revision",
            "labels": {"service_name": service_name, "revision_name": f"{service_name}-00001-abc",
                       "location": REGION, "configuration_name": service_name,
                       "project_id": label_project if label_project is not None else project},
        },
        "severity": severity,
        "jsonPayload": {"stack_trace": trace},
    }


def run_job_entry(job_name, execution_name="finops-budget-enforcer-job-x7k2p", project=HOST,
                  text="Container called exit(3)."):
    return {
        "insertId": "job-1",
        "logName": f"projects/{project}/logs/run.googleapis.com%2Fvarlog%2Fsystem",
        "resource": {"type": "cloud_run_job", "labels": {"job_name": job_name, "location": REGION, "project_id": project}},
        "labels": {"run.googleapis.com/execution_name": execution_name, "run.googleapis.com/task_index": "0",
                   "run.googleapis.com/task_attempt": "0"},
        "severity": "ERROR",
        "textPayload": text,
    }


def k8s_entry(project="child-shop-1"):
    return {
        "logName": f"projects/{project}/logs/stderr",
        "resource": {"type": "k8s_container", "labels": {"project_id": project, "location": REGION,
                                                          "cluster_name": "c1", "namespace_name": "app",
                                                          "pod_name": "web-1", "container_name": "web"}},
        "severity": "ERROR",
        "textPayload": "panic: nil map",
    }


# ---------------------------------------------------------------------------------------------------------------
# logName parsing + fixture shape
# ---------------------------------------------------------------------------------------------------------------
def test_entry_project_is_positional():
    assert clf.entry_project({"logName": "projects/p-1/logs/run.googleapis.com%2Fstderr"}) == "p-1"
    for bad in ["", "projects/p-1/logs", "projects/p-1/logs/a/b", "folders/1/logs/x", "projects//logs/x",
                "projects/p-1/log/x", "organizations/1/logs/x", "projects/p-1/logs/", None, 7, {"a": 1}]:
        assert clf.entry_project({"logName": bad}) is None, bad


def test_workflows_fixture_has_no_project_id_label_and_numeric_container():
    entry = workflows_entry()
    labels = entry["resource"]["labels"]
    assert "project_id" not in labels
    assert labels["resource_container"].isdigit()
    assert clf.parse_project_number("projects/123456789012") == "123456789012"
    for bad in ["123", "projects/abc", "projects/12/x", "", None]:
        assert clf.parse_project_number(bad) is None


# ---------------------------------------------------------------------------------------------------------------
# Classification table
# ---------------------------------------------------------------------------------------------------------------
def test_workflows_pipeline_failure_is_platform_incident_linked_by_execution_id_and_never_dispatched():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD", "PLATFORM_REMEDIATION"])})
    h.db.data["pipeline_executions"] = {
        "tr-shop-9": {"trace_id": "tr-shop-9", "product_id": "shop-app",
                      "workflow_execution_id": "7d1c2a9e-0f3c-4c55-9a51-2b7f0e6d1a10"},
        "tr-other": {"trace_id": "tr-other", "workflow_execution_id": "another"},
    }
    res = h.process(workflows_entry())
    c = res["classification"]
    assert (c["incident_class"], c["kind"], c["workflow_id"]) == ("PLATFORM_INCIDENT", "pipeline", "castor-main-orchestrator")
    assert c["execution_id"] == "7d1c2a9e-0f3c-4c55-9a51-2b7f0e6d1a10"
    rec = h.incident(res)
    assert rec["auto_remediation_status"] == "RECORD_ONLY:PIPELINE_LINKED"
    assert rec["link_status"] == "LINKED" and rec["linked_pipeline_trace_id"] == "tr-shop-9"
    assert rec["linked_product_id"] == "shop-app"
    assert h.starts == []


def test_workflows_entry_with_other_resource_container_is_unattributed():
    h = Harness()
    res = h.process(workflows_entry(container="999999999999"))
    assert res["classification"]["incident_class"] == "UNATTRIBUTED"
    assert res["classification"]["reason"] == "RESOURCE_CONTAINER_MISMATCH"
    assert h.incident(res)["auto_remediation_status"] == "RECORD_ONLY:UNATTRIBUTED"


def test_workflows_entry_when_host_number_unresolved_is_unattributed_and_health_degraded():
    h = Harness(host_number=None)
    res = h.process(workflows_entry())
    assert res["classification"]["reason"] == "HOST_NUMBER_UNRESOLVED"
    assert "HOST_NUMBER_UNRESOLVED" in h.sentinel.health()["degraded_reasons"]
    assert h.sentinel.health()["status"] == "degraded"


def test_workflows_entry_from_child_project_is_unattributed():
    h = Harness()
    res = h.process(workflows_entry(project="child-shop-1"))
    assert res["classification"]["reason"] == "WORKFLOW_OUTSIDE_HOST"


def test_sre_workflow_own_failure_is_recorded_never_dispatched_self_loop_guard():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD", "PLATFORM_REMEDIATION"])})
    res = h.process(workflows_entry(workflow_id="castor-sre-remediation"))
    assert res["classification"]["kind"] == "sre_workflow"
    assert h.incident(res)["auto_remediation_status"] == "RECORD_ONLY:SELF_LOOP"
    assert h.starts == []
    # Honours a custom SRE_WORKFLOW_NAME exactly
    h2 = Harness(env={"SRE_WORKFLOW_NAME": "sv-sre"})
    assert h2.process(workflows_entry(workflow_id="sv-sre"))["classification"]["kind"] == "sre_workflow"
    assert h2.process(workflows_entry(workflow_id="castor-sre-remediation", execution_id="e2"))["classification"]["kind"] == "pipeline"


def test_sentinel_own_errors_are_never_dispatched():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["PLATFORM_REMEDIATION"])})
    res = h.process(run_service_entry("log-sre-sentinel-service"))
    assert h.incident(res)["auto_remediation_status"] == "RECORD_ONLY:SELF_LOOP"
    assert h.starts == []


@pytest.mark.parametrize("accepted", [[], ["FULL_BUILD"], ["FULL_BUILD", "PLATFORM_REMEDIATION"]])
def test_platform_service_incident_is_recorded_only(accepted):
    expected = "RECORD_ONLY:CONSUMER_MODE"
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(accepted)})
    res = h.process(run_service_entry("orchestrator-gateway-service"))
    assert res["classification"]["incident_class"] == "PLATFORM_INCIDENT"
    assert res["classification"]["kind"] == "service"
    rec = h.incident(res)
    assert rec["auto_remediation_status"] == expected
    assert rec["status"] == "OPEN" and rec["service_name"] == "orchestrator-gateway-service"  # CC card fields
    assert h.starts == []


def test_unknown_host_service_is_unattributed():
    h = Harness()
    res = h.process(run_service_entry("hand-made-service"))
    assert res["classification"]["reason"] == "UNKNOWN_HOST_SERVICE"


def test_job_incident_with_not_configured_run_record_is_never_dispatched():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD", "PLATFORM_REMEDIATION"])})
    h.db.data["finops-budget-enforcer-job_runs"] = {
        "finops-budget-enforcer-job-x7k2p": {"outcome": "NOT_CONFIGURED", "missing": ["BILLING_EXPORT_DATASET"]}}
    res = h.process(run_job_entry("finops-budget-enforcer-job"))
    c = res["classification"]
    assert (c["incident_class"], c["kind"], c["job_name"], c["execution_name"]) == (
        "PLATFORM_INCIDENT", "job", "finops-budget-enforcer-job", "finops-budget-enforcer-job-x7k2p")
    rec = h.incident(res)
    assert rec["error_class"] == "NOT_CONFIGURED"
    assert rec["auto_remediation_status"] == "RECORD_ONLY:NOT_CONFIGURED"
    assert h.starts == []


def test_job_incident_without_not_configured_record_follows_platform_rule():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["PLATFORM_REMEDIATION"])})
    h.db.data["sre-telemetry-digest-job_runs"] = {"sre-telemetry-digest-job-a1": {"outcome": "FAILED"}}
    res = h.process(run_job_entry("sre-telemetry-digest-job", execution_name="sre-telemetry-digest-job-a1",
                                  text="Traceback\nValueError: bad"))
    assert "error_class" not in h.incident(res)
    assert h.incident(res)["auto_remediation_status"] == "RECORD_ONLY:CONSUMER_MODE"
    assert h.starts == []


def test_job_incident_whose_run_record_cannot_be_read_is_never_dispatched():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["PLATFORM_REMEDIATION"])})
    h.db.failing.add("finops-budget-enforcer-job_runs")
    res = h.process(run_job_entry("finops-budget-enforcer-job"))
    assert h.incident(res)["auto_remediation_status"] == "RECORD_ONLY:RUN_RECORD_UNAVAILABLE"
    entry = run_job_entry("finops-budget-enforcer-job", text="other failure")
    del entry["labels"]["run.googleapis.com/execution_name"]
    assert h.incident(h.process(entry))["auto_remediation_status"] == "RECORD_ONLY:RUN_RECORD_UNAVAILABLE"
    assert h.starts == []


def test_unknown_resource_type_is_unattributed():
    h = Harness()
    entry = {"logName": f"projects/{HOST}/logs/cloudaudit.googleapis.com%2Factivity",
             "resource": {"type": "gcs_bucket", "labels": {"bucket_name": "b", "project_id": HOST}},
             "severity": "ERROR", "textPayload": "x"}
    res = h.process(entry)
    assert res["classification"]["reason"] == "UNKNOWN_RESOURCE_TYPE"
    child = dict(entry, logName="projects/child-shop-1/logs/x")
    assert h.process(child)["classification"]["reason"] == "UNKNOWN_RESOURCE_TYPE"


def test_malformed_logname_is_unattributed():
    h = Harness()
    entry = run_service_entry("orchestrator-gateway-service")
    entry["logName"] = "orchestrator-gateway-service/logs/stderr"
    res = h.process(entry)
    assert res["classification"]["reason"] == "LOGNAME_MALFORMED"
    assert h.incident(res)["auto_remediation_status"] == "RECORD_ONLY:UNATTRIBUTED"


def test_project_label_must_equal_logname_project():
    h = Harness()
    res = h.process(run_service_entry("web", project="child-shop-1", label_project="child-other-2"))
    assert res["classification"]["reason"] == "PROJECT_LABEL_MISMATCH"


def test_host_project_non_platform_workload_type_is_unattributed():
    h = Harness()
    res = h.process(k8s_entry(project=HOST))
    assert res["classification"]["reason"] == "HOST_RESOURCE_NOT_PLATFORM"


# ---------------------------------------------------------------------------------------------------------------
# Tenant incidents
# ---------------------------------------------------------------------------------------------------------------
def test_tenant_incident_suppressed_until_intake_contract_accepted():
    h = Harness()
    res = h.process(run_service_entry("web", project="child-shop-1"))
    c = res["classification"]
    assert (c["incident_class"], c["product_id"]) == ("WORKLOAD_INCIDENT", "shop-app")
    rec = h.incident(res)
    assert rec["auto_remediation_status"] == "SUPPRESSED:INTAKE_CONTRACT_PENDING"
    assert rec["product_id"] == "shop-app" and rec["rca"]["affected_repository"] == "acme/shop-app"
    assert h.starts == []
    assert "sre_open_requests" not in h.db.data


def test_tenant_incident_dispatches_full_build_with_exact_args():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})  # CONSUMER install
    res = h.process(run_service_entry("web", project="child-shop-1"))
    assert res["status"] == "INCIDENT_DISPATCHED"
    [(parent, args)] = h.starts
    assert parent == f"projects/{HOST}/locations/{REGION}/workflows/castor-sre-remediation"
    assert tuple(args) == sentinel_mod.REMEDIATION_ARG_KEYS
    assert args["execution_mode"] == "FULL_BUILD"
    assert args["incident_id"] == res["incident_id"] and args["trace_id"] == res["trace_id"]
    assert args["sre_sentinel_url"] == "https://log-sre-sentinel-service-h4sh.a.run.app"
    assert args["workspace_mcp_url"] == "https://mcp-workspace-connector-h4sh.a.run.app"
    assert args["spec_intake_topic"] == f"projects/{HOST}/topics/spec-intake-events"
    rec = h.incident(res)
    assert rec["auto_remediation_status"] == "DISPATCHED"
    assert rec["remediation_workflow_execution"].endswith("/executions/exec-1")
    assert rec["require_plan_approval"] is True


def test_spec_intake_topic_env_is_used_verbatim():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"]),
                     "SPEC_INTAKE_TOPIC": "projects/p/topics/custom"})
    h.process(run_service_entry("web", project="child-shop-1"))
    assert h.starts[0][1]["spec_intake_topic"] == "projects/p/topics/custom"


def test_gateway_named_service_in_tenant_is_its_product_not_platform():
    h = Harness()
    res = h.process(run_service_entry("my-gateway-app", project="child-other-2"))
    c = res["classification"]
    assert (c["incident_class"], c["product_id"], c["component"]) == ("WORKLOAD_INCIDENT", "other-app", "my-gateway-app")


def test_same_error_in_two_child_projects_records_two_products():
    h = Harness()
    a = h.process(run_service_entry("web", project="child-shop-1"))
    b = h.process(run_service_entry("web", project="child-other-2"))
    assert a["status"] == b["status"] == "INCIDENT_RECORDED"
    assert a["incident_id"] != b["incident_id"]
    assert {a["classification"]["product_id"], b["classification"]["product_id"]} == {"shop-app", "other-app"}


def test_project_not_in_ledger_or_ambiguous_is_unattributed():
    h = Harness()
    assert h.process(run_service_entry("web", project="child-unknown"))["classification"]["reason"] == "PRODUCT_NOT_IN_LEDGER"
    h.db.data["workloads"]["dup-app"] = {"project_id": "child-shop-1", "status": "ACTIVE"}
    res = h.process(run_service_entry("web2", project="child-shop-1", trace="other"))
    assert res["classification"]["reason"] == "PRODUCT_AMBIGUOUS"


def test_k8s_container_in_child_project_is_workload_incident():
    h = Harness()
    res = h.process(k8s_entry())
    assert (res["classification"]["incident_class"], res["classification"]["product_id"]) == ("WORKLOAD_INCIDENT", "shop-app")


@pytest.mark.parametrize("patch,expected", [
    ({"code_freeze": True}, "SUPPRESSED:CODE_FREEZE"),
    ({"sre_auto_healing_enabled": False}, "SUPPRESSED:AUTO_HEALING_DISABLED"),
    ({"sre_auto_healing_enabled": None}, "SUPPRESSED:AUTO_HEALING_DISABLED"),
    ({"status": "PROVISIONING"}, "SUPPRESSED:WORKLOAD_NOT_ACTIVE"),
])
def test_tenant_governance_gates(patch, expected):
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    h.db.data["workloads"]["shop-app"].update(patch)
    res = h.process(run_service_entry("web", project="child-shop-1"))
    assert h.incident(res)["auto_remediation_status"] == expected
    assert h.starts == []


def test_kill_switch_suppresses_dispatch():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    h.db.data["governance"] = {"platform_kill_switch": {"emergency_stop_active": True}}
    res = h.process(run_service_entry("web", project="child-shop-1"))
    assert h.incident(res)["auto_remediation_status"] == "SUPPRESSED:KILL_SWITCH"
    assert h.starts == []


def test_one_open_request_per_product_and_release_on_failure_outcome():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    first = h.process(run_service_entry("web", project="child-shop-1", trace="KeyError: 'a'"))
    second = h.process(run_service_entry("web", project="child-shop-1", trace="ValueError: b"))
    assert h.incident(first)["auto_remediation_status"] == "DISPATCHED"
    assert h.incident(second)["auto_remediation_status"] == "SUPPRESSED:REQUEST_OPEN"
    assert len(h.starts) == 1
    # The workflow reports a failure -> lock released -> the next incident dispatches
    h.sentinel.record_outcome(first["incident_id"], "REMEDIATION_FAILED", "SRE_PRODUCT_UNRESOLVED", "x")
    assert "shop-app" not in h.db.data["sre_open_requests"]
    third = h.process(run_service_entry("web", project="child-shop-1", trace="TypeError: c"))
    assert h.incident(third)["auto_remediation_status"] == "DISPATCHED"


def test_open_request_lock_expires_after_ttl():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"]), "SRE_OPEN_REQUEST_TTL_SECONDS": "60"})
    h.process(run_service_entry("web", project="child-shop-1", trace="KeyError: 'a'"))
    h.now = NOW + timedelta(seconds=61)
    res = h.process(run_service_entry("web", project="child-shop-1", trace="ValueError: b"))
    assert h.incident(res)["auto_remediation_status"] == "DISPATCHED"


def test_url_resolution_failure_is_recorded_suppressed_and_holds_no_lock():
    def resolver(project, region, name):
        if name == "mcp-workspace-connector":
            raise RuntimeError("services.get 403")
        return f"https://{name}-h4sh.a.run.app"

    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])}, url_resolver=resolver)
    res = h.process(run_service_entry("web", project="child-shop-1"))
    assert h.incident(res)["auto_remediation_status"] == "SUPPRESSED:URL_UNRESOLVED"
    assert h.starts == [] and "sre_open_requests" not in h.db.data


def test_missing_region_suppresses_dispatch_and_degrades_health():
    h = Harness(env={"REGION": "", "SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    res = h.process(run_service_entry("web", project="child-shop-1"))
    assert h.incident(res)["auto_remediation_status"] == "SUPPRESSED:NOT_CONFIGURED"
    assert "REGION_MISSING" in h.sentinel.health()["degraded_reasons"]


def test_workflow_start_failure_is_recorded_and_releases_lock():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])}, starter_error=RuntimeError("503"))
    res = h.process(run_service_entry("web", project="child-shop-1"))
    assert res["status"] == "INCIDENT_RECORDED"
    assert h.incident(res)["auto_remediation_status"] == "DISPATCH_FAILED"
    assert "shop-app" not in h.db.data.get("sre_open_requests", {})


def test_invalid_or_unknown_accepted_modes_never_enable_dispatch():
    for raw in ["FULL_BUILD", "{\"FULL_BUILD\": 1}", json.dumps(["full_build"]), json.dumps(["FULL"])]:
        h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": raw})
        res = h.process(run_service_entry("web", project="child-shop-1"))
        assert h.incident(res)["auto_remediation_status"] == "SUPPRESSED:INTAKE_CONTRACT_PENDING", raw
        assert h.sentinel.health()["status"] == "degraded"


# ---------------------------------------------------------------------------------------------------------------
# De-duplication (Do No Harm: the fingerprint and in-window clustering are unchanged)
# ---------------------------------------------------------------------------------------------------------------
def _pre_pr2_fingerprint(stack_trace, service_name):
    """Verbatim copy of the pre-PR-2 algorithm (sentinel.py at main 8095d98)."""
    import hashlib
    import re

    clean = re.sub(r'0x[0-9a-fA-F]+', '0xMEM', stack_trace)
    clean = re.sub(r'line \d+', 'line N', clean)
    clean = re.sub(r':\d+:', ':N:', clean)
    clean = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TIMESTAMP', clean)
    normalized = f"{service_name.strip().lower()}::{clean.strip()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("trace,svc", [
    ('File "service.py", line 45, in foo at 0x7fff5fbff840\nKeyError: "doc_id"', "workspace-service"),
    ("2026-10-12T10:00:00 ValueError: x :12: y", "Orchestrator-Gateway-Service "),
    ("", "unknown-service"),
])
def test_fingerprint_algorithm_unchanged(trace, svc):
    h = Harness()
    assert h.sentinel.compute_stack_fingerprint(trace, svc) == _pre_pr2_fingerprint(trace, svc)


def test_platform_service_cluster_key_is_unchanged_so_existing_clusters_keep_matching():
    h = Harness()
    entry = run_service_entry("orchestrator-gateway-service", trace="Traceback\nKeyError: 'x'")
    res = h.process(entry)
    assert res["fingerprint_hash"] == _pre_pr2_fingerprint("Traceback\nKeyError: 'x'", "orchestrator-gateway-service")


def test_tenant_duplicate_within_cooldown_is_clustered_exactly_as_before():
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    first = h.process(run_service_entry("web", project="child-shop-1"))
    h.now = NOW + timedelta(minutes=30)
    second = h.process(run_service_entry("web", project="child-shop-1"))
    assert second["status"] == "DUPLICATE_CLUSTERED"
    assert second["incident_id"] == first["incident_id"]
    assert second["fingerprint_hash"] == first["fingerprint_hash"]
    cluster = h.db.data["incident_clusters"][first["fingerprint_hash"]]
    assert cluster["occurrence_count"] == 2 and cluster["active_incident_id"] == first["incident_id"]
    assert len(h.db.data["incidents"]) == 1 and len(h.starts) == 1


def test_storm_keeps_one_incident_with_sliding_window():
    h = Harness()
    first = h.process(run_service_entry("web", project="child-shop-1"))
    for minutes in (50, 100, 150):
        h.now = NOW + timedelta(minutes=minutes)
        assert h.process(run_service_entry("web", project="child-shop-1"))["incident_id"] == first["incident_id"]


def test_resolved_or_quiet_fingerprint_opens_a_new_incident():
    h = Harness()
    first = h.process(run_service_entry("web", project="child-shop-1"))
    fp = first["fingerprint_hash"]
    h.db.data["incident_clusters"][fp]["status"] = "RESOLVED"
    h.now = NOW + timedelta(days=30)
    second = h.process(run_service_entry("web", project="child-shop-1"))
    assert second["status"] == "INCIDENT_RECORDED" and second["incident_id"] != first["incident_id"]
    assert h.db.data["incident_clusters"][fp]["previous_incident_id"] == first["incident_id"]
    # quiet longer than the cooldown (default 1 h) -> new incident too
    h.now = NOW + timedelta(days=30, hours=2)
    third = h.process(run_service_entry("web", project="child-shop-1"))
    assert third["incident_id"] not in (first["incident_id"], second["incident_id"])


def _interleave_after_first_cluster_read(monkeypatch, competitor):
    """The first read of ``incident_clusters`` returns its snapshot, then ``competitor()`` (another instance handling a
    concurrent delivery) runs to completion before the reader continues: the reader now holds a stale snapshot."""
    real_get = FakeDocRef.get
    fired = []

    def racing_get(self):
        snap = real_get(self)
        if self.coll == "incident_clusters" and not fired:
            fired.append(True)
            competitor()
        return snap

    monkeypatch.setattr(FakeDocRef, "get", racing_get)
    return fired


def test_concurrent_first_sighting_clusters_onto_the_winner(monkeypatch):
    h = Harness()
    other = Harness(db=h.db)  # second Cloud Run instance, same Firestore
    entry = run_service_entry("web", project="child-shop-1")
    won = {}
    fired = _interleave_after_first_cluster_read(monkeypatch, lambda: won.update(other.process(entry)))
    res = h.process(entry)
    assert fired and won["status"] == "INCIDENT_RECORDED"
    assert res["status"] == "DUPLICATE_CLUSTERED" and res["incident_id"] == won["incident_id"]
    assert list(h.db.data["incidents"]) == [won["incident_id"]]
    assert h.db.data["incident_clusters"][won["fingerprint_hash"]]["occurrence_count"] == 2


@pytest.mark.parametrize("why", ["resolved", "quiet"])
def test_concurrent_reopen_opens_exactly_one_incident(monkeypatch, why):
    """RT F2: two deliveries after a RESOLVED cluster / a quiet hour race; exactly one reopens, the other clusters."""
    h = Harness()
    other = Harness(db=h.db)
    entry = run_service_entry("web", project="child-shop-1")
    first = h.process(entry)
    fp = first["fingerprint_hash"]
    if why == "resolved":
        h.db.data["incident_clusters"][fp]["status"] = "RESOLVED"
    later = NOW + timedelta(hours=2)
    h.now = other.now = later
    won = {}
    fired = _interleave_after_first_cluster_read(monkeypatch, lambda: won.update(other.process(entry)))
    res = h.process(entry)
    assert fired and won["status"] == "INCIDENT_RECORDED" and won["incident_id"] != first["incident_id"]
    assert res["status"] == "DUPLICATE_CLUSTERED" and res["incident_id"] == won["incident_id"]
    assert sorted(h.db.data["incidents"]) == sorted([first["incident_id"], won["incident_id"]])  # 2, not 3
    cluster = h.db.data["incident_clusters"][fp]
    assert cluster["active_incident_id"] == won["incident_id"]
    assert cluster["previous_incident_id"] == first["incident_id"]
    assert cluster["occurrence_count"] == 2 and cluster["reopened_at"] == later.isoformat()


def test_failed_incident_write_leaves_no_cluster_and_redelivery_records_it():
    """RT F1: the incident write fails -> 503 and NOTHING is written (no cluster, no lock, no dispatch); the Pub/Sub
    redelivery of the same message records the incident instead of being acked as a duplicate."""
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    entry = run_service_entry("web", project="child-shop-1")
    h.db.failing.add("incidents")
    with pytest.raises(sentinel_mod.FirestoreUnavailable):
        h.process(entry)
    assert h.db.data.get("incident_clusters", {}) == {}
    assert h.db.data.get("sre_open_requests", {}) == {}
    assert h.starts == []
    h.db.failing.discard("incidents")
    res = h.process(entry)  # redelivery
    assert res["status"] == "INCIDENT_DISPATCHED"
    assert h.incident(res)["auto_remediation_status"] == "DISPATCHED"
    cluster = h.db.data["incident_clusters"][res["fingerprint_hash"]]
    assert cluster["active_incident_id"] == res["incident_id"] and cluster["occurrence_count"] == 1
    assert len(h.starts) == 1 and list(h.db.data["incidents"]) == [res["incident_id"]]


def test_failed_reopen_write_leaves_the_cluster_unchanged_and_redelivery_reopens():
    h = Harness()
    entry = run_service_entry("web", project="child-shop-1")
    first = h.process(entry)
    fp = first["fingerprint_hash"]
    h.db.data["incident_clusters"][fp]["status"] = "RESOLVED"
    before = copy.deepcopy(h.db.data["incident_clusters"][fp])
    h.now = NOW + timedelta(days=1)
    h.db.failing.add("incidents")
    with pytest.raises(sentinel_mod.FirestoreUnavailable):
        h.process(entry)
    assert h.db.data["incident_clusters"][fp] == before
    h.db.failing.discard("incidents")
    res = h.process(entry)
    assert res["status"] == "INCIDENT_RECORDED" and res["incident_id"] != first["incident_id"]
    assert h.db.data["incident_clusters"][fp]["previous_incident_id"] == first["incident_id"]
    assert sorted(h.db.data["incidents"]) == sorted([first["incident_id"], res["incident_id"]])


def test_entries_without_trace_fields_dedup_on_a_stable_projection():
    """RT F4: an entry with no jsonPayload.stack_trace/message and no textPayload used to fingerprint str(entry),
    insertId included, so it never clustered. Its per-occurrence LogEntry fields are now left out."""
    h = Harness()
    a = workflows_entry()
    a["jsonPayload"] = {"state": "FAILED", "detail": "step publish_intake failed"}
    a.update({"timestamp": "2026-10-12T12:00:00.1Z", "receiveTimestamp": "2026-10-12T12:00:00.2Z",
              "trace": "projects/p/traces/1", "spanId": "1"})
    b = copy.deepcopy(a)
    b.update({"insertId": "wf-2", "timestamp": "2026-10-12T12:00:05.1Z", "receiveTimestamp": "2026-10-12T12:00:05.2Z",
              "trace": "projects/p/traces/2", "spanId": "2"})
    first, second = h.process(a), h.process(b)
    assert first["status"] == "INCIDENT_RECORDED"
    assert second["status"] == "DUPLICATE_CLUSTERED" and second["incident_id"] == first["incident_id"]
    c = copy.deepcopy(a)
    c["jsonPayload"]["detail"] = "step execute_rca failed"
    assert h.process(c)["incident_id"] != first["incident_id"]  # a different error is a different incident
    # Do No Harm: entries that carry a trace field fingerprint exactly as before
    job = run_job_entry("sre-telemetry-digest-job", execution_name="sre-telemetry-digest-job-a1")
    assert h.process(job)["fingerprint_hash"] == _pre_pr2_fingerprint("Container called exit(3).",
                                                                      "job/sre-telemetry-digest-job")


def test_firestore_unavailable_raises_so_push_is_redelivered():
    h = Harness()
    h.sentinel.db = None
    with pytest.raises(sentinel_mod.FirestoreUnavailable):
        h.process(run_service_entry("web", project="child-shop-1"))
    h2 = Harness()
    h2.db.failing.add("incidents")
    with pytest.raises(sentinel_mod.FirestoreUnavailable):
        h2.process(run_service_entry("web", project="child-shop-1"))


# ---------------------------------------------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------------------------------------------
@pytest.fixture
def client_harness():
    from fastapi.testclient import TestClient

    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    main_mod._sentinel = h.sentinel
    try:
        yield TestClient(main_mod.app), h
    finally:
        main_mod._sentinel = None


def _envelope(entry):
    return {"message": {"data": base64.b64encode(json.dumps(entry).encode()).decode(), "messageId": "m1"}}


def test_push_endpoint_triage_and_outcome(client_harness):
    client, h = client_harness
    res = client.post("/events/log-sink", json=_envelope(run_service_entry("web", project="child-shop-1"))).json()
    assert res["status"] == "INCIDENT_DISPATCHED"
    incident_id = res["incident_id"]

    tri = client.post("/triage", json={"trace_id": res["trace_id"], "incident_id": incident_id})
    assert tri.status_code == 200
    body = tri.json()
    assert body["product_id"] == "shop-app" and body["incident_id"] == incident_id
    assert f"SRE incident {incident_id}" in body["spec_text"] and "KeyError" in body["spec_text"]

    assert client.post("/triage", json={"incident_id": "inc-missing"}).status_code == 404
    assert client.post(f"/incidents/{incident_id}/outcome", json={"outcome": "BOGUS"}).status_code == 422
    assert client.post("/incidents/inc-missing/outcome", json={"outcome": "INTAKE_PUBLISHED"}).status_code == 404
    ok = client.post(f"/incidents/{incident_id}/outcome", json={"outcome": "INTAKE_PUBLISHED", "detail": "doc-1"})
    assert ok.status_code == 200
    assert h.db.data["incidents"][incident_id]["remediation_outcome"] == "INTAKE_PUBLISHED"
    # INTAKE_PUBLISHED keeps the one-open-request lock (the pipeline is now running)
    assert h.db.data["sre_open_requests"]["shop-app"]["incident_id"] == incident_id


def test_push_endpoint_undecodable_is_acked_and_unrecordable_is_503(client_harness):
    client, h = client_harness
    bad = client.post("/events/log-sink", json={"message": {"data": "!!!not-base64-json"}})
    assert bad.status_code == 200 and bad.json()["status"] == "DISCARDED_UNDECODABLE"
    h.db.failing.add("incident_clusters")
    down = client.post("/events/log-sink", json=_envelope(run_service_entry("web", project="child-shop-1")))
    assert down.status_code == 503 and down.json()["error_class"] == "FIRESTORE_UNAVAILABLE"


def test_legacy_triage_body_still_works(client_harness):
    client, _ = client_harness
    body = client.post("/triage", json={"trace_id": "tr-1", "incident_data": {
        "service_name": "mcp-workspace-connector", "stack_trace": 'File "service.py", line 12\nKeyError: "id"'}}).json()
    assert body["status"] == "TRIAGED" and body["affected_repository"] == "mcp-servers/workspace/"
    assert body["product_id"] == ""


def test_processing_failure_answers_500_with_error_class_and_own_entries_never_log_error(client_harness, caplog,
                                                                                         monkeypatch):
    """RT F7: an unexpected processing failure answers 500 (Pub/Sub retries, then the DLQ). It is logged at ERROR for
    an ordinary entry, but at WARNING when the failing entry is the sentinel's own log entry, so a deterministic
    failure cannot feed itself through the sink without bound."""
    client, h = client_harness

    def boom(_entry):
        raise RuntimeError("boom")

    monkeypatch.setattr(h.sentinel, "process_log_event", boom)
    caplog.set_level("INFO", logger="log-sre-sentinel-service")
    own = client.post("/events/log-sink", json=_envelope(run_service_entry("log-sre-sentinel-service")))
    assert own.status_code == 500
    assert own.json()["error_class"] == "PROCESSING_ERROR" and own.json()["exception_type"] == "RuntimeError"
    assert not [r for r in caplog.records if r.levelname == "ERROR"]
    assert [r for r in caplog.records if r.levelname == "WARNING" and "boom" in r.getMessage()]
    caplog.clear()
    other = client.post("/events/log-sink", json=_envelope(run_service_entry("web", project="child-shop-1")))
    assert other.status_code == 500 and other.json()["error_class"] == "PROCESSING_ERROR"
    assert [r for r in caplog.records if r.levelname == "ERROR" and "boom" in r.getMessage()]


def test_sentinel_own_entry_is_exact():
    own = run_service_entry("log-sre-sentinel-service")
    assert sentinel_mod.is_sentinel_own_entry(own, HOST) is True
    assert sentinel_mod.is_sentinel_own_entry(run_service_entry("log-sre-sentinel-service-2"), HOST) is False
    assert sentinel_mod.is_sentinel_own_entry(run_service_entry("log-sre-sentinel-service", project="child-shop-1"),
                                              HOST) is False
    assert sentinel_mod.is_sentinel_own_entry(own, "") is False
    assert sentinel_mod.is_sentinel_own_entry("not-a-dict", HOST) is False


def test_ledger_doc_without_auto_healing_field_uses_the_control_center_default():
    """RT F8: a ledger doc with no sre_auto_healing_enabled is shown as enabled by the Control Center; the sentinel's
    gate now uses the same default (explicit False/None still suppress: test_tenant_governance_gates)."""
    h = Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    del h.db.data["workloads"]["shop-app"]["sre_auto_healing_enabled"]
    res = h.process(run_service_entry("web", project="child-shop-1"))
    assert h.incident(res)["auto_remediation_status"] == "DISPATCHED"


def test_auto_healing_default_agrees_with_control_center():
    tree = ast.parse((REPO / "apps" / "control-center" / "routes" / "workloads.py").read_text())
    defaults = [ast.literal_eval(n.args[1]) for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
                and len(n.args) == 2 and isinstance(n.args[0], ast.Constant)
                and n.args[0].value == "sre_auto_healing_enabled"]
    assert len(defaults) >= 3 and set(defaults) == {sentinel_mod.SRE_AUTO_HEALING_DEFAULT_WHEN_ABSENT}


def test_main_import_builds_no_client():
    assert main_mod._sentinel is None or isinstance(main_mod._sentinel, sentinel_mod.LogSRESentinel)


# ---------------------------------------------------------------------------------------------------------------
# Static guards: no substring heuristics; platform sets pinned to infra
# ---------------------------------------------------------------------------------------------------------------
def _exact_comparison_violations(source):
    """Substring / prefix heuristics the classifier must not contain (AGENTS.md invariant 2)."""
    tree = ast.parse(source)
    out = []
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    out += [f"import {m}" for m in sorted({"re", "fnmatch"} & imported)]
    banned_calls = {"startswith", "endswith", "find", "rfind", "index", "rindex", "count", "__contains__", "match",
                    "search", "fullmatch"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in banned_calls:
            out.append(f"line {node.lineno}: {node.func.attr}")
        if isinstance(node, ast.Compare):
            for op, right in zip(node.ops, node.comparators):
                if isinstance(op, (ast.In, ast.NotIn)):
                    ok = (isinstance(right, ast.Name) and right.id in {"WORKLOAD_RESOURCE_TYPES", "PROJECT_LABELED_TYPES"}) or (
                        isinstance(right, ast.Attribute) and right.attr in {"platform_services", "platform_jobs"})
                    if not ok:
                        out.append(f"line {node.lineno}: membership test against {ast.dump(right)}")
            # RT F6: a slice compared to a value is a prefix/suffix match in disguise (x[:n] == "...")
            for operand in [node.left, *node.comparators]:
                if isinstance(operand, ast.Subscript) and isinstance(operand.slice, ast.Slice):
                    out.append(f"line {node.lineno}: slice comparison")
    return out


def test_classifier_uses_exact_comparisons_only():
    assert _exact_comparison_violations((APP_DIR / "sre_classifier.py").read_text()) == []


@pytest.mark.parametrize("snippet", [
    "import re",
    "from fnmatch import fnmatch",
    'name.startswith("castor-")',
    'name.endswith("-job")',
    '"gateway" in name',
    'name[:7] == "castor-"',
    'name[-4:] != "-job"',
    '"castor-" == name[0:7]',
    'name[:3] in KNOWN',
])
def test_exact_comparison_checker_flags_substring_and_prefix_heuristics(snippet):
    assert _exact_comparison_violations(snippet), snippet


@pytest.mark.parametrize("snippet", [
    'parts[0] == "projects"',
    "rtype in WORKLOAD_RESOURCE_TYPES",
    "name in host.platform_services",
    "len(parts) != 4",
])
def test_exact_comparison_checker_allows_exact_comparisons(snippet):
    assert _exact_comparison_violations(snippet) == []


def test_sentinel_substring_maps_are_gone():
    src = (APP_DIR / "sentinel.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op, right in zip(node.ops, node.comparators):
                if isinstance(op, (ast.In, ast.NotIn)) and isinstance(right, ast.Name):
                    assert right.id not in {"service_name", "stack_trace", "error_msg", "text_payload"}, node.lineno
    for gone in ('"workspace" in service_name', "any(p in service_name", '"Crash"', 'replace("-service", "")'):
        assert gone not in src


def _tf_map_keys(main_tf: str, local_name: str):
    lines = main_tf.splitlines()
    start = next(i for i, line in enumerate(lines) if line.split("=")[0].strip() == local_name and line.rstrip().endswith("{"))
    keys = []
    for line in lines[start + 1:]:
        if line.strip() == "}":
            break
        if line.strip().startswith('"'):
            keys.append(line.split('"')[1])
    return keys


def test_default_platform_sets_match_infra_locals():
    main_tf = (REPO / "infra" / "platform" / "main.tf").read_text()
    services = set(_tf_map_keys(main_tf, "cloud_run_services")) | {"castor-git-server"}
    jobs = set(_tf_map_keys(main_tf, "cloud_run_jobs")) | {"tf-applier"}
    assert 'name        = "castor-git-server"' in main_tf and 'name       = "tf-applier"' in main_tf
    assert set(clf.DEFAULT_PLATFORM_SERVICES) == services
    assert set(clf.DEFAULT_PLATFORM_JOBS) == jobs
    assert set(clf.PLATFORM_SOURCE_DIRS) == services | jobs
    for comp, src_dir in clf.PLATFORM_SOURCE_DIRS.items():
        assert (REPO / src_dir).is_dir(), (comp, src_dir)


def test_platform_sets_env_overrides_defaults_exactly():
    h = Harness(env={"PLATFORM_SERVICES": json.dumps(["svc-a"]), "PLATFORM_JOBS": json.dumps(["job-a"])})
    assert h.process(run_service_entry("svc-a"))["classification"]["kind"] == "service"
    assert h.process(run_service_entry("orchestrator-gateway-service"))["classification"]["reason"] == "UNKNOWN_HOST_SERVICE"

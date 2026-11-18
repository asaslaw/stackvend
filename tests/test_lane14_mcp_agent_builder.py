"""Lane 14 PR-1 (+ PR-9): mcp-agent-builder-server codegen safety and real child-project calls (FD27-12, C44).

Hermetic: modules are loaded by path under the names main.py imports; no Google client is constructed.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
AB_DIR = os.path.join(REPO, "mcp-servers", "agent-builder")
sys.path.insert(0, os.path.dirname(__file__))

MODULES = ("validator", "evaluator", "scaffold", "service")


@pytest.fixture()
def ab(monkeypatch):
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    from fd4g_support import load_module, real_modules

    real_modules(monkeypatch)
    loaded = {}
    for extra in ("managed_target_seam", "cloud"):
        path = os.path.join(AB_DIR, f"{extra}.py")
        if os.path.exists(path):
            loaded[extra] = load_module(monkeypatch, extra, path)
    for name in MODULES:
        loaded[name] = load_module(monkeypatch, name, os.path.join(AB_DIR, f"{name}.py"))
    main = load_module(monkeypatch, "lane14_agent_builder_main", os.path.join(AB_DIR, "main.py"))
    return SimpleNamespace(main=main, client=TestClient(main.app), **loaded)


def tool(name, level="READ_ONLY"):
    return {"name": name, "description": "d", "safety_level": level, "parameters_schema": {"type": "object"}}


# ================================================================================================ PR-1 codegen
def test_triple_quote_instruction_stays_a_literal(ab):
    payload = 'Be helpful."""\nimport os\nos.system("id")\n"""'
    res = ab.service.AgentBuilderService().scaffold_adk_project("a", payload, [tool("lookup")])
    assert res["status"] == "SUCCESS"
    tree = ast.parse(res["files"]["agent.py"])
    assigns = {t.targets[0].id: t.value for t in tree.body if isinstance(t, ast.Assign)}
    assert isinstance(assigns["SYSTEM_INSTRUCTION"], ast.Constant) and assigns["SYSTEM_INSTRUCTION"].value == payload
    assert not any(isinstance(n, (ast.Import, ast.ImportFrom)) and getattr(n, "module", None) == "os"
                   for n in ast.walk(tree))


@pytest.mark.parametrize("bad", ["x():\n import os", "class", "has space", "1abc", "a" * 65, "naïve", ""])
def test_tool_name_must_be_an_identifier(ab, bad):
    res = ab.service.AgentBuilderService().scaffold_adk_project("a", "i", [tool(bad)])
    assert res["status"] == "VALIDATION_FAILED" and res["stage"] == "tool_matrix"
    r = ab.client.post("/api/v1/adk/scaffold", json={"agent_name": "a", "system_instruction": "i",
                                                       "tools_definition": [tool(bad)]})
    assert r.status_code == 400


def test_duplicate_tool_names_refused(ab):
    res = ab.service.AgentBuilderService().scaffold_adk_project("a", "i", [tool("x"), tool("x", "STATE_MUTATING")])
    assert res["status"] == "VALIDATION_FAILED"


@pytest.mark.parametrize("field,value", [("max_turns", 0), ("max_turns", 10**6), ("max_turns", True),
                                         ("per_request_timeout_seconds", -1)])
def test_numeric_limits_are_typed(ab, field, value):
    kwargs = {field: value}
    res = ab.service.AgentBuilderService().scaffold_adk_project("a", "i", [], **kwargs)
    assert res["status"] == "VALIDATION_FAILED" and res["stage"] == "parameters"


def test_valid_scaffold_is_unchanged_in_shape_and_parses(ab):
    """Negative (Do No Harm): a valid request renders, every .py parses, and the AST validator passes it."""
    svc = ab.service.AgentBuilderService()
    res = svc.scaffold_adk_project("travel-assistant", "Assist employees.", [tool("get_weather"),
                                   tool("book_flight", "STATE_MUTATING")], grounding_datastore_id="ds-travel",
                                   max_turns=6, per_request_timeout_seconds=25)
    assert res["status"] == "SUCCESS" and res["max_turns"] == 6 and res["grounding_configured"] is True
    for fname, src in res["files"].items():
        if fname.endswith(".py"):
            ast.parse(src)
            assert ab.validator.run_static_security_check(src) == (True, []), fname
    assert "<retrieved_context>" in res["files"]["agent.py"]
    assert "require_confirmation" in res["files"]["tools/action_tools.py"]
    assert "read_tools.get_weather" in res["files"]["agent.py"]


@pytest.mark.parametrize("src,needle", [
    ("import importlib\nimportlib.import_module('os')\n", "importlib"),
    ("x = getattr(object, name)\n", "getattr"),
    ("__import__('os')\n", "__import__"),
    ("import subprocess\nsubprocess.run(['id'])\n", "subprocess"),
    ("import os\nos.popen('id')\n", "os"),
    ("from pickle import loads\n", "pickle"),
    ("exec('1')\n", "exec"),
    ("def f(:\n", "parse"),
])
def test_ast_validator_rejects(ab, src, needle):
    ok, violations = ab.validator.run_static_security_check(src)
    assert ok is False and any(needle in v for v in violations), violations


def test_ast_validator_accepts_literal_getattr_and_allowed_imports(ab):
    ok, violations = ab.validator.run_static_security_check(
        "from typing import Any\nfrom google.adk.agents import Agent\nx = getattr(Agent, 'name', None)\n")
    assert ok and violations == []


def test_shape_check_detects_a_structural_change(ab):
    sc = ab.scaffold
    p = sc.ScaffoldParams("a", "m", "i", "", 1, 1, ("t",), ())
    assert sc.ast_shape(sc.render_agent(p)) == sc.ast_shape(sc.render_agent(sc._neutral(p)))
    assert sc.ast_shape("x = 1\n") != sc.ast_shape("x = 1\nimport os\n")


def test_server_never_imports_generated_code_or_the_sdk(ab):
    """G5: the server package imports none of vertexai.agent_engines, google.adk, importlib, pickle."""
    banned = {"vertexai", "google.adk", "importlib", "pickle", "cloudpickle"}
    for fname in os.listdir(AB_DIR):
        if not fname.endswith(".py") or fname.startswith("test_"):
            continue
        tree = ast.parse(open(os.path.join(AB_DIR, fname)).read())
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                mods = [node.module or ""]
            for m in mods:
                assert not any(m == b or m.startswith(b + ".") for b in banned), (fname, m)


# ================================================================================================ PR-9 real calls
import copy
import io
import json
import tarfile
from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
CHILD = "claims-child-123"
SA = f"agent-build@{CHILD}.iam.gserviceaccount.com"


class _Snap:
    def __init__(self, doc_id, data):
        self.id, self._data = doc_id, data
        self.exists = data is not None

    def to_dict(self):
        return copy.deepcopy(self._data)


class _Query:
    def __init__(self, store, coll, flt=None, n=None):
        self.store, self.coll, self.flt, self.n = store, coll, flt, n

    def where(self, filter=None):  # noqa: A002 (Firestore API)
        return _Query(self.store, self.coll, filter, self.n)

    def limit(self, n):
        return _Query(self.store, self.coll, self.flt, n)

    def stream(self):
        if self.store.get("__raise_query__"):
            raise RuntimeError("query down")
        out = []
        for key, data in sorted(self.store.items()):
            if not key.startswith(self.coll + "/") or key.count("/") != 1:
                continue
            if self.flt is not None and data.get(self.flt.field_path) != self.flt.value:
                continue
            out.append(_Snap(key.split("/", 1)[1], data))
        return out[: self.n] if self.n else out


class _Doc:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def get(self):
        if self.store.get("__raise_get__"):
            raise RuntimeError("firestore down")
        return _Snap(self.path.rsplit("/", 1)[1], self.store.get(self.path))

    def set(self, data, merge=False):
        self.store[self.path] = copy.deepcopy(data)

    def create(self, data):
        if self.path in self.store:
            raise RuntimeError("409 AlreadyExists")
        self.store[self.path] = copy.deepcopy(data)


class _Coll(_Query):
    def __init__(self, store, name):
        super().__init__(store, name)

    def document(self, doc_id):
        return _Doc(self.store, f"{self.coll}/{doc_id}")


class FakeDB:
    def __init__(self, store):
        self.store = store

    def collection(self, name):
        return _Coll(self.store, name)


class FakeCloud:
    def __init__(self, enabled=("aiplatform.googleapis.com", "cloudbuild.googleapis.com", "storage.googleapis.com",
                                "discoveryengine.googleapis.com")):
        self.enabled, self.calls, self.objects = set(enabled), [], {}
        self.build_state, self.engine_ok = "WORKING", True
        self.query_fail = self.eval_fail = False

    def service_enabled(self, project, api):
        self.calls.append(("service_enabled", project, api))
        return api in self.enabled

    def upload_object(self, bucket, name, data, content_type):
        self.calls.append(("upload", bucket, name))
        self.objects[(bucket, name)] = data
        return {"name": name}

    def read_object(self, bucket, name):
        self.calls.append(("read", bucket, name))
        return self.objects.get((bucket, name))

    def create_build(self, project, region, build):
        self.calls.append(("create_build", project, region))
        self.last_build = build
        return {"name": f"projects/{project}/locations/{region}/operations/op1", "metadata": {"build": {"id": "b-123"}}}

    def get_build(self, project, region, build_id):
        self.calls.append(("get_build", project, region, build_id))
        return {"id": build_id, "status": self.build_state}

    def get_project_number(self, project):
        self.calls.append(("project_get", project))
        if getattr(self, "project_get_fail", False):
            raise self.CloudError("PROJECT_GET", 503, "")
        return getattr(self, "project_number", "987654321")

    def get_reasoning_engine(self, region, name):
        self.calls.append(("engine_get", region, name))
        if not self.engine_ok:
            raise self.CloudError("ENGINE_GET", 404, "")
        return {"name": name, "createTime": "2026-10-13T12:05:00Z"}

    def stream_query(self, region, name, user_id, message):
        self.calls.append(("query", region, name))
        if self.query_fail:
            raise self.CloudError("ENGINE_QUERY", 500, "")
        return "I can only help with travel policy questions."

    def evaluate_instance(self, project, region, input_key, result_key, instance):
        self.calls.append(("evaluate", project, region, input_key))
        self.instances = getattr(self, "instances", []) + [instance]
        if self.eval_fail:
            raise self.CloudError("EVALUATE", 503, "")
        return {"score": 1.0}

    def create_datastore(self, project, location, datastore_id, body):
        self.calls.append(("create_datastore", project, location, datastore_id))
        return {"name": f"projects/{project}/locations/{location}/operations/ds-op"}


def _approval(action="AGENT_ENGINE_DEPLOY", **over):
    rec = {"status": "APPROVED", "action": action, "product_id": "claims", "project_id": CHILD,
           "principal_type": "USER", "approved_by_role": "ADMIN", "approved_by": "owner@example.com",
           "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    rec.update(over)
    return rec


def _store(**over):
    s = {
        "workloads/claims": {"project_id": CHILD, "status": "ACTIVE",
                             "agent_engine": {"staging_bucket": "claims-agent-staging", "build_service_account": SA,
                                              "region": "us-east4"}},
        "destructive_approvals/ap-1": _approval(),
        "destructive_approvals/ap-ds": _approval("DATASTORE_CREATE"),
    }
    s.update(over)
    return s


@pytest.fixture()
def real(ab, monkeypatch):
    from types import SimpleNamespace

    store = _store()
    cloud = FakeCloud()
    cloud.CloudError = ab.cloud.CloudError
    consumed, consumed_bindings = [], []

    def consumer(approval_id, *, action, product_id, project_id, binding):
        consumed.append((approval_id, action, product_id))
        consumed_bindings.append((project_id, binding))

    svc = ab.service.AgentBuilderService(
        firestore_factory=lambda db: FakeDB(store), cloud=cloud, approval_consumer=consumer,
        env={"PROJECT_ID": "host-platform"}, clock=lambda: NOW, id_factory=lambda: "dep1")
    monkeypatch.setattr(ab.main, "service", svc)
    seam = ab.managed_target_seam

    def deploy_approval(deploy=None, **over):
        """APPROVAL-CONSUME-VIA-VENDING: ap-1 as the Control Center mints it for exactly these deploy arguments."""
        binding = svc.deploy_approval_binding(**(deploy or DEPLOY))
        rec = _approval(binding=binding, binding_digest=seam.binding_digest(binding))
        rec.update(over)
        store["destructive_approvals/ap-1"] = rec
        return rec

    def ds_approval(**over):
        rec = _approval("DATASTORE_CREATE", binding=DS_BINDING, binding_digest=seam.binding_digest(DS_BINDING))
        rec.update(over)
        store["destructive_approvals/ap-ds"] = rec
        return rec

    deploy_approval()
    ds_approval()
    return SimpleNamespace(svc=svc, store=store, cloud=cloud, consumed=consumed, consumed_bindings=consumed_bindings,
                           deploy_approval=deploy_approval, ds_approval=ds_approval)


DEPLOY = dict(product_id="claims", approval_id="ap-1", agent_name="claims-helper", system_instruction="Help.",
              tools_definition=[tool("lookup_claim")], requirements=["google-adk==1.0.0"])
DS_BINDING = {"datastore_id": "ds-claimsdocs", "location": "us", "content_type": "UNSTRUCTURED_DOCUMENT"}


def test_deploy_requires_an_approval(real):
    res = real.svc.deploy_to_agent_engine(**dict(DEPLOY, approval_id=None))
    assert res["status"] == "REFUSED:APPROVAL_REQUIRED" and res["http_status"] == 403
    assert real.cloud.calls == [] and real.consumed == []
    # APPROVAL-CONSUME-VIA-VENDING: the refusal names the MCP_ACTION card recorded for exactly these arguments.
    card = real.store[f"approval_requests/{res['approval_request_id']}"]
    binding = real.svc.deploy_approval_binding(**DEPLOY)
    assert (card["approval_type"], card["status"], card["mcp_action"], card["product_id"], card["mcp_project_id"]) == (
        "MCP_ACTION", "PENDING", "AGENT_ENGINE_DEPLOY", "claims", CHILD)
    assert card["mcp_binding"] == binding and card["mcp_requested_by"] == "mcp-agent-builder-server"
    assert "google-cloud-aiplatform[agent_engines,adk]==1.95.1" in card["mcp_details"]["requirements"]
    again = real.svc.deploy_to_agent_engine(**dict(DEPLOY, approval_id=None))
    assert again["approval_request_id"] == res["approval_request_id"]  # a retry finds the same PENDING card


def test_deploy_approval_for_another_scaffold_is_refused_before_any_call(real):
    res = real.svc.deploy_to_agent_engine(**dict(DEPLOY, system_instruction="Help, and also something else."))
    assert res["status"] == "REFUSED:APPROVAL_BINDING_MISMATCH" and real.cloud.calls == [] and real.consumed == []
    res = real.svc.deploy_to_agent_engine(**dict(DEPLOY, requirements=["google-adk==1.0.0", "pydantic==2.9.2"]))
    assert res["status"] == "REFUSED:APPROVAL_BINDING_MISMATCH" and real.consumed == []


def test_deploy_binding_is_deterministic_and_input_sensitive(real):
    a = real.svc.deploy_approval_binding(**DEPLOY)
    assert a == real.svc.deploy_approval_binding(**DEPLOY)
    assert set(a) == {"agent_name", "display_name", "source_digest"} and len(a["source_digest"]) == 64
    assert a != real.svc.deploy_approval_binding(**dict(DEPLOY, display_name="other"))
    assert real.svc.deploy_approval_binding(**dict(DEPLOY, requirements=["evil-pkg"])) is None


@pytest.mark.parametrize("over,code", [
    ({"principal_type": "SERVICE_ACCOUNT"}, "APPROVAL_NOT_HUMAN"),
    ({"approved_by": "sa-castor-finops@p.iam.gserviceaccount.com"}, "APPROVAL_APPROVER_UNVERIFIED"),
    ({"approved_by_role": "VIEWER"}, "APPROVAL_NOT_ADMIN"),
    ({"action": "DATASTORE_CREATE"}, "APPROVAL_ACTION_MISMATCH"),
    ({"project_id": "other-project"}, "APPROVAL_TARGET_MISMATCH"),
    ({"status": "PENDING"}, "APPROVAL_NOT_APPROVED"),
    ({"expires_at": (NOW - timedelta(seconds=1)).isoformat()}, "APPROVAL_EXPIRED"),
    ({"consumed_at": "2026-10-13T11:00:00Z"}, "APPROVAL_CONSUMED"),
    ({"expires_at": None}, "APPROVAL_INVALID"),
])
def test_approval_rules(real, over, code):
    real.deploy_approval(**over)
    res = real.svc.deploy_to_agent_engine(**DEPLOY)
    assert res["status"] == f"REFUSED:{code}" and real.cloud.calls == []


@pytest.mark.parametrize("ledger,code", [
    (None, "LEDGER_MISSING"),
    ({"project_id": "host-platform"}, "HOST_PROJECT"),
    ({"project_id": CHILD, "is_castor": True}, "PLATFORM_WORKLOAD"),
    ({"project_id": CHILD, "status": "DECOMMISSIONED"}, "NOT_ACTIVE"),
])
def test_target_identity_refusals(real, ledger, code):
    if ledger is None:
        del real.store["workloads/claims"]
    else:
        real.store["workloads/claims"] = ledger
    res = real.svc.deploy_to_agent_engine(**DEPLOY)
    assert res["status"] == f"REFUSED:{code}" and real.cloud.calls == []


def test_two_workloads_claiming_one_project_are_refused(real):
    real.store["workloads/other"] = {"project_id": CHILD}
    assert real.svc.deploy_to_agent_engine(**DEPLOY)["status"] == "REFUSED:LEDGER_MISMATCH"


def test_request_project_must_equal_the_ledger(real):
    assert real.svc.deploy_to_agent_engine(**dict(DEPLOY, project_id="evil"))["status"] == "REFUSED:TARGET_MISMATCH"


def test_api_not_enabled_is_prerequisite_missing_and_nothing_is_consumed(real):
    real.cloud.enabled.discard("cloudbuild.googleapis.com")
    res = real.svc.deploy_to_agent_engine(**DEPLOY)
    assert res["status"] == "PREREQUISITE_MISSING:cloudbuild.googleapis.com" and res["http_status"] == 412
    assert real.consumed == [] and not [c for c in real.cloud.calls if c[0] in ("upload", "create_build")]


@pytest.mark.parametrize("cfg,item", [
    (None, "agent_engine"),
    ({"staging_bucket": "b", "region": "us-east4", "build_service_account": "x@other.iam.gserviceaccount.com"},
     "build_service_account"),
    ({"build_service_account": SA, "region": "us-east4"}, "staging_bucket"),
    ({"build_service_account": SA, "staging_bucket": "b"}, "region"),
])
def test_workload_engine_settings_are_required(real, cfg, item):
    wl = real.store["workloads/claims"]
    if cfg is None:
        wl.pop("agent_engine")
    else:
        wl["agent_engine"] = cfg
    assert real.svc.deploy_to_agent_engine(**DEPLOY)["status"] == f"PREREQUISITE_MISSING:{item}"


def test_region_comes_from_the_workload_record(real):
    res = real.svc.deploy_to_agent_engine(**dict(DEPLOY, region="europe-west1"))
    assert res["status"] == "REFUSED:REGION_NOT_ALLOWED"
    assert not [c for c in real.cloud.calls if c[0] in ("upload", "create_build")] and real.consumed == []


def test_deploy_builds_in_the_child_project_as_the_child_sa_and_polls_to_the_real_resource(real, ab, monkeypatch):
    imported = []

    class _Guard:
        def find_spec(self, name, path=None, target=None):
            if name in ("agent", "app", "tools", "tools.read_tools", "tools.action_tools", "stackvend_package_agent"):
                imported.append(name)
            return None

    guard = _Guard()
    sys.meta_path.insert(0, guard)
    try:
        res = real.svc.deploy_to_agent_engine(**DEPLOY)
    finally:
        sys.meta_path.remove(guard)
    assert imported == []  # the server never imports the scaffold or the packager
    assert res["status"] == "BUILD_STARTED" and res["http_status"] == 202 and res["build_id"] == "b-123"
    assert ("create_build", CHILD, "us-east4") in real.cloud.calls
    assert real.consumed == [("ap-1", "AGENT_ENGINE_DEPLOY", "claims")]
    assert real.consumed_bindings == [(CHILD, real.svc.deploy_approval_binding(**DEPLOY))]
    build = real.cloud.last_build
    assert build["serviceAccount"] == f"projects/{CHILD}/serviceAccounts/{SA}"
    assert build["source"]["storageSource"] == {"bucket": "claims-agent-staging",
                                                "object": "stackvend-agent-builds/dep1/source.tar.gz"}
    env = dict(e.split("=", 1) for e in build["steps"][1]["env"])
    assert env["SV_PROJECT"] == CHILD and env["SV_LOCATION"] == "us-east4"
    assert "google-cloud-aiplatform[agent_engines,adk]==1.95.1" in json.loads(env["SV_REQUIREMENTS_JSON"])
    assert all("entrypoint" in s and s["entrypoint"] == "python" for s in build["steps"])  # no shell
    tar = tarfile.open(fileobj=io.BytesIO(real.cloud.objects[("claims-agent-staging",
                                                              "stackvend-agent-builds/dep1/source.tar.gz")]))
    names = set(tar.getnames())
    assert {"agent.py", "app.py", "tools/read_tools.py", "stackvend_package_agent.py"} <= names
    packager = tar.extractfile("stackvend_package_agent.py").read().decode()
    assert packager == open(os.path.join(AB_DIR, "packaging", "stackvend_package_agent.py")).read()

    # Poll: still building -> unchanged
    assert real.svc.get_deployment("dep1", "claims")["status"] == "BUILD_STARTED"
    # Build done + result object -> the real engine is fetched before DEPLOYED is reported
    real.cloud.build_state = "SUCCESS"
    name = f"projects/987654321/locations/us-east4/reasoningEngines/555"
    real.cloud.objects[("claims-agent-staging", "stackvend-agent-builds/dep1/result.json")] = json.dumps(
        {"resource_name": name}).encode()
    out = real.svc.get_deployment("dep1", "claims")
    assert out["status"] == "DEPLOYED" and out["resource_name"] == name
    assert ("engine_get", "us-east4", name) in real.cloud.calls
    assert real.store["agent_engine_deployments/dep1"]["status"] == "DEPLOYED"


def test_deploy_failure_outcomes_are_typed(real):
    real.svc.deploy_to_agent_engine(**DEPLOY)
    real.cloud.build_state = "FAILURE"
    assert real.svc.get_deployment("dep1", "claims")["status"] == "DEPLOY_FAILED:BUILD"
    real.store["agent_engine_deployments/dep1"]["status"] = "BUILD_STARTED"
    real.cloud.build_state = "SUCCESS"
    real.cloud.objects[("claims-agent-staging", "stackvend-agent-builds/dep1/result.json")] = json.dumps(
        {"resource_name": "projects/x/locations/elsewhere/reasoningEngines/1"}).encode()
    assert real.svc.get_deployment("dep1", "claims")["status"] == "DEPLOY_FAILED:RESULT"
    real.store["agent_engine_deployments/dep1"]["status"] = "BUILD_STARTED"
    real.cloud.objects[("claims-agent-staging", "stackvend-agent-builds/dep1/result.json")] = json.dumps(
        {"resource_name": f"projects/{CHILD}/locations/us-east4/reasoningEngines/1"}).encode()
    real.cloud.engine_ok = False
    assert real.svc.get_deployment("dep1", "claims")["status"] == "DEPLOY_FAILED:ENGINE_GET"


def test_consume_unavailable_refuses_before_any_upload(real, ab):
    def consumer(approval_id, *, action, product_id, project_id, binding):
        raise ab.managed_target_seam.ApprovalRefused("APPROVAL_CONSUME_UNAVAILABLE", "HTTP 404")

    real.svc._approval_consumer = consumer
    res = real.svc.deploy_to_agent_engine(**DEPLOY)
    assert res["status"] == "REFUSED:APPROVAL_CONSUME_UNAVAILABLE" and res["http_status"] == 503
    assert not [c for c in real.cloud.calls if c[0] in ("upload", "create_build")]


def test_supply_chain_and_substitution_characters_rejected(real):
    assert real.svc.deploy_to_agent_engine(**dict(DEPLOY, requirements=["evil-pkg"]))["status"] == "DEPLOYMENT_REJECTED"
    assert real.svc.deploy_to_agent_engine(**dict(DEPLOY, display_name="x$PROJECT_ID"))["status"] == "DEPLOYMENT_REJECTED"
    assert real.cloud.calls == []


def test_deploy_rejects_an_unsafe_scaffold_before_any_call(real):
    res = real.svc.deploy_to_agent_engine(**dict(DEPLOY, tools_definition=[tool("x():\n import os")]))
    assert res["status"] == "VALIDATION_FAILED" and real.cloud.calls == [] and real.consumed == []


def test_datastore_create_is_real_and_approved(real):
    base = dict(product_id="claims", approval_id="ap-ds", datastore_name="Claims Docs", source_uri="gs://b/docs/")
    assert real.svc.provision_discovery_datastore(**dict(base, location=None))["http_status"] == 400
    assert real.svc.provision_discovery_datastore(**dict(base, location="asia"))["http_status"] == 400
    res = real.svc.provision_discovery_datastore(**dict(base, location="us"))
    assert res["status"] == "DATASTORE_CREATE_STARTED" and res["operation"].endswith("/operations/ds-op")
    assert res["document_import"] == "NOT_STARTED"
    assert ("create_datastore", CHILD, "us", "ds-claimsdocs") in real.cloud.calls
    assert real.consumed == [("ap-ds", "DATASTORE_CREATE", "claims")]
    assert real.consumed_bindings == [(CHILD, DS_BINDING)]
    # the approval is bound to the datastore id, location and content type
    real.ds_approval()
    other = real.svc.provision_discovery_datastore(**dict(base, location="us", datastore_name="Other Docs"))
    assert other["status"] == "REFUSED:APPROVAL_BINDING_MISMATCH" and len(real.consumed) == 1
    real.cloud.enabled.discard("discoveryengine.googleapis.com")
    real.ds_approval()
    assert real.svc.provision_discovery_datastore(**dict(base, location="us"))["status"] == \
        "PREREQUISITE_MISSING:discoveryengine.googleapis.com"


def _deployed(real, name):
    real.store["agent_engine_deployments/dep1"] = {"product_id": "claims", "project_id": CHILD, "region": "us-east4",
                                                   "status": "DEPLOYED", "resource_name": name}


def test_eval_scores_real_responses_and_stores_them(real):
    name = f"projects/{CHILD}/locations/us-east4/reasoningEngines/9"
    _deployed(real, name)
    res = real.svc.run_eval_suite("claims", name, [{"user_prompt": "hi", "prohibited_content": ["secret"]}])
    assert res["status"] == "EVALUATED" and res["evaluated_tests"] == res["total_tests"] == 4
    assert all(r["raw_score"] == 1.0 and r["score"] == 1.0 for r in res["results"])
    assert real.store["agent_builder_evals/dep1"]["status"] == "EVALUATED"
    assert sum(1 for c in real.cloud.calls if c[0] == "query") == 4


def test_eval_failure_is_never_a_default_score(real):
    name = f"projects/{CHILD}/locations/us-east4/reasoningEngines/9"
    _deployed(real, name)
    real.cloud.eval_fail = True
    res = real.svc.run_eval_suite("claims", name, [{"user_prompt": "hi"}])
    assert res["status"] == "EVAL_FAILED:EVALUATE" and res["overall_score"] is None and res["passed"] is False
    assert res["http_status"] == 502


def test_eval_only_on_engines_this_server_deployed_for_the_product(real):
    res = real.svc.run_eval_suite("claims", f"projects/{CHILD}/locations/us-east4/reasoningEngines/other", [])
    assert res["status"] == "REFUSED:ENGINE_NOT_DEPLOYED_BY_PLATFORM" and real.cloud.calls == []


def test_http_and_mcp_surface(real, ab):
    r = ab.client.post("/api/v1/agent-engine/deploy", json=DEPLOY)
    assert r.status_code == 202 and r.json()["status"] == "BUILD_STARTED"
    assert ab.client.get("/api/v1/agent-engine/deployments/dep1?product_id=claims").status_code == 200
    assert ab.client.get("/api/v1/agent-engine/deployments/nope?product_id=claims").status_code == 404
    # RT F4: scoped to the product; product_id is required
    assert ab.client.get("/api/v1/agent-engine/deployments/dep1?product_id=other").status_code == 404
    assert ab.client.get("/api/v1/agent-engine/deployments/dep1").status_code == 422
    r = ab.client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "agent_engine_deployment_status", "arguments": {"deployment_id": "dep1", "product_id": "other"}}})
    assert "error" in r.json()
    r = ab.client.post("/mcp", json={"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
        "name": "agent_engine_deployment_status", "arguments": {"deployment_id": "dep1", "product_id": "claims"}}})
    assert "result" in r.json()
    r = ab.client.post("/api/v1/agent-engine/deploy", json=dict(DEPLOY, approval_id=None))
    assert r.status_code == 403 and r.json()["detail"]["status"] == "REFUSED:APPROVAL_REQUIRED"
    r = ab.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                     "params": {"name": "agent_engine_deploy", "arguments": dict(DEPLOY, approval_id=None)}})
    assert r.json()["error"]["code"] == -32002
    tools = {t["name"] for t in ab.client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).json()["result"]["tools"]}
    assert {"adk_scaffold_project", "discovery_datastore_provision", "adk_eval_suite", "agent_engine_deploy",
            "agent_engine_deployment_status"} <= tools


def test_offline_evaluator_never_simulates_responses(ab):
    with pytest.raises(ValueError):
        ab.evaluator.AgentEvaluator().evaluate_test_cases("<retrieved_context>", [{"user_prompt": "x"}])
    report = ab.evaluator.AgentEvaluator().evaluate_test_cases(
        "<retrieved_context>", [{"user_prompt": "x", "prohibited_content": ["leak"]}],
        mock_response_generator=lambda p: "this would leak")
    assert report.passed is False


def test_no_literal_region_or_project_in_the_server(ab):
    """Invariant 3: the only region strings are the Discovery Engine location enum."""
    for fname in ("service.py", "main.py", "cloud.py", "managed_target_seam.py"):
        src = open(os.path.join(AB_DIR, fname)).read()
        assert "us-central1" not in src, fname


# ================================================================================================ RT fixes (lane14-sync)
def test_rt_f1_eval_instance_carries_only_the_prediction(real):
    name = f"projects/{CHILD}/locations/us-east4/reasoningEngines/9"
    _deployed(real, name)
    res = real.svc.run_eval_suite("claims", name, [{"user_prompt": "hi"}])
    assert res["status"] == "EVALUATED"
    assert real.cloud.instances and all(set(i) == {"prediction"} for i in real.cloud.instances)
    assert res["results"][0]["prompt"] == "hi"  # the prompt is kept in the stored per-case result


@pytest.mark.parametrize("metric", ["safety", "fluency", "coherence"])
def test_rt_f1_eval_request_body_parses_with_the_real_proto(ab, metric):
    """The body ChildProjectClient.evaluate_instance posts must parse as google.cloud.aiplatform.v1
    EvaluateInstancesRequest (the REST front end rejects unknown fields). No network: the session is a fake. The
    proto parse runs in a fresh interpreter, because other root tests stub the `google` namespace in sys.modules."""
    import subprocess

    input_key, result_key, _ = ab.service.EVAL_METRICS[metric]
    posted = []

    class _Res:
        status_code = 200

        @staticmethod
        def json():
            return {result_key: {"score": 1.0}}

    class _Session:
        def post(self, url, timeout=None, **kw):
            posted.append(kw["json"])
            return _Res()

    client = ab.cloud.ChildProjectClient(session_factory=_Session)
    out = client.evaluate_instance(CHILD, "us-east4", input_key, result_key, {"prediction": "a reply"})
    assert out["score"] == 1.0
    checker = (
        "import json, sys\n"
        "try:\n"
        "    from google.cloud.aiplatform_v1.types import EvaluateInstancesRequest as R\n"
        "    from google.protobuf import json_format\n"
        "except ImportError:\n"
        "    sys.exit(3)\n"
        "good, bad = json.load(sys.stdin)\n"
        "json_format.ParseDict(good, R.pb(R()))\n"
        "try:\n"
        "    json_format.ParseDict(bad, R.pb(R()))\n"
        "except json_format.ParseError:\n"
        "    sys.exit(0)\n"
        "sys.exit(4)\n")
    bad = {input_key: {"metricSpec": {}, "instance": {"prediction": "x", "prompt": "y"}}}  # the pre-fix body
    proc = subprocess.run([sys.executable, "-c", checker], input=json.dumps([posted[0], bad]),
                          env=hermetic_guard.child_env(),
                          capture_output=True, text=True, timeout=120)
    if proc.returncode == 3:
        pytest.skip("google-cloud-aiplatform is not installed")
    assert proc.returncode == 0, proc.stderr[-2000:]


@pytest.mark.parametrize("line", [
    "google-adk @ https://evil.example/x.whl",          # direct URL
    "fastapi[all] @ git+https://evil/x",                 # direct VCS URL
    "requestsx==1.0",                                    # look-alike name
    "httpx-evil==1.0",                                   # prefix extension
    "pytest-evil==1.0",
    "google-cloud-totally-not-google==1.0",              # unlisted google-cloud-*
    "google-adk>=1.0",                                   # not an == pin
    "google-adk",                                        # unpinned
    "google-adk==1.*",                                   # wildcard pin
    "google-adk==1.0,==1.1",                             # two specifiers
    "google-adk==1.0; python_version>'3'",               # marker
    "google-adk==1.0 --hash=sha256:00",                  # pip option, not PEP 508
    "pickle5==0.0.12",
])
def test_rt_f2_requirement_refusals(ab, line):
    ok, violations = ab.validator.validate_dependencies([line])
    assert ok is False and len(violations) == 1, (line, violations)


def test_rt_f2_requirement_refusals_reach_the_deploy_route_before_any_call(real):
    res = real.svc.deploy_to_agent_engine(**dict(DEPLOY, requirements=["google-adk @ https://evil.example/x.whl"]))
    assert res["status"] == "DEPLOYMENT_REJECTED" and res["http_status"] == 400
    assert real.cloud.calls == [] and real.consumed == []
    assert real.svc.deploy_to_agent_engine(**dict(DEPLOY, requirements="google-adk==1.0"))["http_status"] == 400


def test_rt_f2_pinned_allowed_requirements_are_unchanged(ab, real):
    """Negative test: today's default spec and exact pins of listed names pass; the final list is recorded."""
    good = ["google-cloud-aiplatform[agent_engines,adk]==1.95.1", "Google_ADK==1.2.0", "pydantic==2.9.2",
            "google-cloud-storage==2.18.0"]
    assert ab.validator.validate_dependencies(good) == (True, [])
    assert ab.validator.validate_dependencies(["", "  # comment"]) == (True, [])
    assert ab.validator.requirement_name("google-cloud-aiplatform[agent_engines,adk]==1.95.1") == \
        "google-cloud-aiplatform"
    real.deploy_approval(dict(DEPLOY, requirements=good + [""]))
    res = real.svc.deploy_to_agent_engine(**dict(DEPLOY, requirements=good + [""]))
    assert res["status"] == "BUILD_STARTED"
    assert res["requirements"] == good  # aiplatform present -> no runtime spec appended; blank line dropped
    env = dict(e.split("=", 1) for e in real.cloud.last_build["steps"][1]["env"])
    assert json.loads(env["SV_REQUIREMENTS_JSON"]) == good


def _poll_with_result(real, resource_name):
    real.cloud.build_state = "SUCCESS"
    real.cloud.objects[("claims-agent-staging", "stackvend-agent-builds/dep1/result.json")] = json.dumps(
        {"resource_name": resource_name}).encode()
    return real.svc.get_deployment("dep1", "claims")


def test_rt_f3_engine_in_another_project_number_is_refused(real):
    real.store["workloads/claims"]["project_number"] = "111222333"
    assert real.svc.deploy_to_agent_engine(**DEPLOY)["project_number"] == "111222333"
    out = _poll_with_result(real, "projects/999999/locations/us-east4/reasoningEngines/123")
    assert out["status"] == "DEPLOY_FAILED:RESULT"
    assert not [c for c in real.cloud.calls if c[0] in ("engine_get", "project_get")]


def test_rt_f3_engine_under_the_ledger_number_or_the_child_id_is_accepted(real):
    real.store["workloads/claims"]["project_number"] = "111222333"
    real.svc.deploy_to_agent_engine(**DEPLOY)
    assert _poll_with_result(real, "projects/111222333/locations/us-east4/reasoningEngines/1")["status"] == "DEPLOYED"
    real.store["agent_engine_deployments/dep1"]["status"] = "BUILD_STARTED"
    assert _poll_with_result(real, f"projects/{CHILD}/locations/us-east4/reasoningEngines/1")["status"] == "DEPLOYED"
    assert not [c for c in real.cloud.calls if c[0] == "project_get"]


def test_rt_f3_missing_ledger_number_is_resolved_with_resource_manager(real):
    real.svc.deploy_to_agent_engine(**DEPLOY)  # ledger has no project_number
    real.cloud.project_get_fail = True
    out = _poll_with_result(real, "projects/987654321/locations/us-east4/reasoningEngines/1")
    assert out["http_status"] == 502 and real.store["agent_engine_deployments/dep1"]["status"] == "BUILD_STARTED"
    real.cloud.project_get_fail = False
    real.cloud.project_number = "5"
    assert _poll_with_result(real, "projects/987654321/locations/us-east4/reasoningEngines/1")["status"] == \
        "DEPLOY_FAILED:RESULT"
    assert real.store["agent_engine_deployments/dep1"]["project_number"] == "5"  # resolved once, then fixed
    real.store["agent_engine_deployments/dep1"]["status"] = "BUILD_STARTED"
    del real.store["agent_engine_deployments/dep1"]["project_number"]
    real.cloud.project_number = "987654321"
    out = _poll_with_result(real, "projects/987654321/locations/us-east4/reasoningEngines/1")
    assert out["status"] == "DEPLOYED" and real.store["agent_engine_deployments/dep1"]["project_number"] == "987654321"
    assert ("project_get", CHILD) in real.cloud.calls


def test_rt_f3_is_reasoning_engine_name_positional(ab):
    f = ab.service.is_reasoning_engine_name
    assert f("projects/123/locations/r/reasoningEngines/9", "c", "r", "123")
    assert not f("projects/123/locations/r/reasoningEngines/9", "c", "r", None)
    assert not f("projects/123/locations/r/reasoningEngines/9", "c", "r", "124")
    assert f("projects/c/locations/r/reasoningEngines/9", "c", "r", None)


@pytest.mark.parametrize("name", ["require_confirmation", "Dict", "Any", "wrapper", "func", "build_root_agent",
                                  "runtime_limits", "AGENT_NAME"])
def test_rt_f6_tool_names_that_shadow_scaffold_names_are_refused(ab, name):
    svc = ab.service.AgentBuilderService()
    res = svc.scaffold_adk_project("a", "Help.", [tool(name, "STATE_MUTATING"), tool("do_x", "STATE_MUTATING")])
    assert res["status"] == "VALIDATION_FAILED" and res["stage"] == "tool_matrix"
    assert any(repr(name) in v for v in res["violations"])


def test_rt_f6_ordinary_tool_names_still_render(ab):
    """Negative test: names outside the reserved set are unchanged and the action tool stays a function."""
    svc = ab.service.AgentBuilderService()
    res = svc.scaffold_adk_project("a", "Help.", [tool("lookup_claim"), tool("do_x", "STATE_MUTATING")])
    assert res["status"] == "SUCCESS"
    tree = ast.parse(res["files"]["tools/action_tools.py"])
    assert [n.name for n in tree.body if isinstance(n, ast.FunctionDef)] == ["require_confirmation", "do_x"]
    assert "lookup_claim" not in ab.scaffold.reserved_names() and "require_confirmation" in ab.scaffold.reserved_names()


def test_rt_f2_validator_has_no_regex(ab):
    src = open(os.path.join(AB_DIR, "validator.py")).read()
    tree = ast.parse(src)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert "re" not in imported

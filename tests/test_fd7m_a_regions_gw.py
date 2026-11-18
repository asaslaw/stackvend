"""FD-7M-a (owner 10-31), SAT-23: the gateway (developer, IPAM, quota gate), the FinOps enforcer and the Serverless Git
build template use the WORKLOAD's region (workloads/{pid}.region through shared.settings.workload_region).

- Developer: `terraform_engine.resolve_workload_region(db, product_id=...)` -> the record region when approved, typed
  REGION_NOT_APPROVED before any LLM call when not, the platform region (byte-identical to before) when the record
  has none. `_platform_region(product_id)` (k8s ${REGION}), the IPAM pool region and the committed cloudbuild.yaml
  `_REGION` follow the same region.
- Quota gate (`/discovery/validate-headroom`, owner OQ-26): the product from pipeline_executions/{trace}, else the one
  workload with the project id; the record region wins over the request's target_region (logged); none / several ->
  503 REGION_UNAVAILABLE. `/discovery/quotas` harvests the request's regions plus the approved list.
- quota_inspector: a claim with no region is skipped (typed log), never counted as a guessed region; no region asked
  -> the approved list, never a fixed list.
- FinOps enforcer: Cloud Run list / scale in the workload's region; not approved / unreadable -> typed REFUSED with
  nothing listed or scaled.

Do No Harm (negatives): a workload without a recorded region, or recorded in the default region, renders and checks
byte-identically; the Serverless Git template for us-central1 is the previous text; a /discovery/quotas request on a
default install harvests exactly the requested regions.

Hermetic: fake Firestore clients and a fake Gemini client; no ADC, no network.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import importlib.util
import logging
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
FINOPS = os.path.join(REPO, "apps", "finops-enforcer")
for _p in (GATEWAY, REPO, os.path.join(REPO, "eval")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent import handler as h  # noqa: E402
from developer_agent import platform_facts as PF  # noqa: E402
from developer_agent.errors import ERROR_CLASSES, REGION_NOT_APPROVED, DeveloperStageError  # noqa: E402
from shared import quota_inspector as qi  # noqa: E402
from shared.providers import serverless_git_provider as sgp  # noqa: E402
from shared.settings import OrchestrationSettings, PlatformSettings  # noqa: E402

DEFAULT = "us-central1"      # the settings schema default (the install region on both dev installs)
OTHER = "europe-west1"       # an added approved region
ROGUE = "asia-south1"        # never approved here
APPROVED = {"default_gcp_region": DEFAULT, "approved_deployable_regions": [DEFAULT, OTHER]}
INGRESS = dict(allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)


# ------------------------------------------------------------------------------------------------ fakes
class _Snap:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data
        self.exists = data is not None
        self.reference = SimpleNamespace(delete=lambda: None)

    def to_dict(self):
        return dict(self._data) if self._data is not None else None


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def where(self, field, op, value):
        assert op == "=="
        return _Query([(i, d) for i, d in self.rows if d.get(field) == value])

    def limit(self, n):
        return _Query(self.rows[:n])

    def stream(self):
        return [_Snap(i, d) for i, d in self.rows]


class FakeDb:
    """docs: {"collection/doc_id": dict}; raises: {"collection/doc_id": Exception} (reads of that document raise)."""

    def __init__(self, docs=None, raises=None):
        self.docs = dict(docs or {})
        self.raises = dict(raises or {})
        self.reads, self.writes = [], []

    def batch(self):
        """RT14-05 / RT14-20: the enforcer writes its markers in one batch (applied in order on commit)."""
        ops = []
        return SimpleNamespace(set=lambda ref, data, merge=False: ops.append(lambda: ref.set(data, merge=merge)),
                               delete=lambda ref: ops.append(ref.delete),
                               commit=lambda: [op() for op in ops])

    def collection(self, name):
        db = self

        class _Col:
            def document(self, doc_id):
                key = f"{name}/{doc_id}"

                class _Doc:
                    def get(self):
                        db.reads.append(key)
                        if key in db.raises:
                            raise db.raises[key]
                        return _Snap(doc_id, db.docs.get(key))

                    def set(self, data, merge=False):
                        db.writes.append((key, data))
                        db.docs[key] = dict(db.docs.get(key) or {}, **data) if merge else dict(data)

                    def create(self, data):   # RT14-20: the snapshot is created, never overwritten
                        assert key not in db.docs, key
                        self.set(data)

                    def delete(self):
                        db.docs.pop(key, None)
                return _Doc()

            def add(self, data):
                db.writes.append((f"{name}/+", data))
                db.docs[f"{name}/auto{len(db.writes)}"] = dict(data)

            def where(self, field, op, value):
                rows = [(k.split("/", 1)[1], d) for k, d in db.docs.items() if k.startswith(name + "/")]
                db.reads.append(f"{name}?{field}=={value}")
                return _Query(rows).where(field, op, value)
        return _Col()


def _db(record=None, settings=APPROVED, pid="shop", extra=None):
    docs = {}
    if settings is not None:
        docs["system_config/platform_settings"] = {"orchestration": dict(settings)}
    if record is not None:
        docs[f"workloads/{pid}"] = dict(record)
    docs.update(extra or {})
    return FakeDb(docs)


# ------------------------------------------------------------------------------------------------ resolver
def test_record_region_approved_is_used():
    assert te.resolve_workload_region(_db({"region": OTHER}), product_id="shop") == OTHER


def test_record_region_not_approved_is_typed():
    with pytest.raises(te.RegionNotApproved) as ei:
        te.resolve_workload_region(_db({"region": ROGUE}), product_id="shop")
    assert ei.value.error_class == REGION_NOT_APPROVED == "REGION_NOT_APPROVED"
    assert ei.value.region == ROGUE and ei.value.approved == [DEFAULT, OTHER]
    assert REGION_NOT_APPROVED in ERROR_CLASSES
    for bad in ("", 7):   # a blank / non-string stored region is never "no region"
        with pytest.raises(te.RegionNotApproved):
            te.resolve_workload_region(_db({"region": bad}), product_id="shop")


@pytest.mark.parametrize("record", [None, {"product_id": "shop"}, {"region": None}], ids=["no-record", "legacy", "null"])
def test_negative_no_recorded_region_is_the_platform_region(record):
    """Do No Harm: the answer and the settings read are today's; nothing else decides the region."""
    db = _db(record, settings={"default_gcp_region": OTHER})
    assert te.resolve_workload_region(db, product_id="shop") == te.resolve_workload_region(_db(None, {
        "default_gcp_region": OTHER})) == OTHER
    assert db.reads == ["system_config/platform_settings", "workloads/shop"]   # no approval read for legacy


def test_negative_without_product_or_client_nothing_new_is_read(monkeypatch):
    db = _db({"region": ROGUE})
    assert te.resolve_workload_region(db) == DEFAULT and db.reads == ["system_config/platform_settings"]
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    assert te.resolve_workload_region(None, product_id="shop") == te.WORKLOAD_REGION_DEFAULT   # eval harness child
    assert te.resolve_workload_region(MagicMock(), product_id="shop") == DEFAULT   # non-snapshot = no store


def test_default_region_recorded_is_the_same_region():
    assert te.resolve_workload_region(_db({"region": DEFAULT}), product_id="shop") == DEFAULT
    # empty approved list = [default_gcp_region] (owner OQ-21)
    assert te.resolve_workload_region(_db({"region": DEFAULT}, settings={}), product_id="shop") == DEFAULT
    with pytest.raises(te.RegionNotApproved):
        te.resolve_workload_region(_db({"region": OTHER}, settings={}), product_id="shop")


def test_unreadable_record_or_settings_is_region_unavailable():
    db = _db(None)
    db.raises["workloads/shop"] = RuntimeError("down")
    with pytest.raises(te.RegionUnavailable, match="workloads/shop unreadable"):
        te.resolve_workload_region(db, product_id="shop")

    class _SettingsOnce(FakeDb):   # the platform-region read works, the approval read fails
        def collection(self, name):
            if name == "system_config" and self.reads.count("system_config/platform_settings") >= 1:
                self.raises["system_config/platform_settings"] = RuntimeError("blip")
            return super().collection(name)
    db2 = _SettingsOnce({"system_config/platform_settings": {"orchestration": APPROVED},
                         "workloads/shop": {"region": OTHER}})
    with pytest.raises(te.RegionUnavailable, match="settings document unreadable"):
        te.resolve_workload_region(db2, product_id="shop")


# ------------------------------------------------------------------------------------------------ developer dispatch
def _agent(db):
    agent = h.DeveloperAgent.__new__(h.DeveloperAgent)
    agent.db = db
    agent.genai_client = object()          # past the LLM-presence check; nothing reaches an LLM here
    agent._stack_runs, agent._stack_last_trace = {}, None
    agent.project_id = ""                  # no project: the agent builds no Firestore client of its own
    return agent


def test_dispatch_refuses_an_unapproved_record_region_before_any_llm(monkeypatch):
    monkeypatch.setattr(h.DeveloperAgent, "_resolve_regulated_controls",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must stop before")))
    with pytest.raises(DeveloperStageError) as ei:
        _agent(_db({"region": ROGUE})).generate_code_files("shop", "spec", [{"step_id": "S1"}], trace_id="t",
                                                            **INGRESS)
    assert ei.value.error_class == REGION_NOT_APPROVED and ROGUE in str(ei.value)


def test_dispatch_threads_the_record_region_into_the_compliance_check(monkeypatch):
    seen = {}

    def _controls(self, product_id, compliance_decision=None, region=None):
        seen["region"] = region
        raise DeveloperStageError("COMPLIANCE_REGION_NOT_ALLOWED", "stop here")
    monkeypatch.setattr(h.DeveloperAgent, "_resolve_regulated_controls", _controls)
    with pytest.raises(DeveloperStageError):
        _agent(_db({"region": OTHER})).generate_code_files("shop", "spec", [{"step_id": "S1"}], trace_id="t",
                                                            **INGRESS)
    assert seen == {"region": OTHER}


def _settings_obj(orch=APPROVED):
    return PlatformSettings(orchestration=OrchestrationSettings(**orch))


def test_k8s_hydration_region_follows_the_record(monkeypatch):
    import shared.settings as settings_mod
    monkeypatch.setattr(settings_mod, "get_platform_settings", lambda **k: _settings_obj())
    assert _agent(_db({"region": OTHER}))._platform_region("shop") == OTHER
    assert _agent(_db({"region": ROGUE}))._platform_region("shop") == ""          # unusable -> typed downstream
    unreadable = _db(None)
    unreadable.raises["workloads/shop"] = RuntimeError("down")
    assert _agent(unreadable)._platform_region("shop") == ""
    # negatives: no product / no recorded region -> the setting exactly as before
    legacy = _db({"product_id": "shop"})
    assert _agent(legacy)._platform_region("shop") == _agent(legacy)._platform_region() == DEFAULT
    assert _agent(_db({"region": OTHER}))._platform_region() == DEFAULT
    # the hydration hook passes the product (zero-argument callable, called only when a manifest needs it)
    import ast
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8").read()
    # COMMITTED-READ-VIEW (RT F3): the assembly (step 8) and the read view share DeveloperAgent._hydrate_k8s, which
    # passes its `region` argument through unchanged; step 8 gives it the product-bound resolver
    calls = [c for c in ast.walk(ast.parse(src)) if isinstance(c, ast.Call)
             and getattr(c.func, "attr", "") == "_hydrate_k8s"]
    assert "functools.partial(self._platform_region, product_id)" in {ast.unparse(c.args[3]) for c in calls
                                                                       if len(c.args) > 3}
    inner = next(c for c in ast.walk(ast.parse(src)) if isinstance(c, ast.Call)
                 and getattr(c.func, "id", "") == "hydrate_kubernetes_manifests")
    assert ast.unparse(next(k.value for k in inner.keywords if k.arg == "region")) == "region"


# ------------------------------------------------------------------------------------------------ IPAM
def test_ipam_pool_takes_the_workload_region():
    pool = PF.IpamPool(supernet="10.100.0.0/16", subnet_prefix=24, connector_prefix=28, region=DEFAULT)
    assert pool.for_region(None) is pool and pool.for_region("") is pool and pool.for_region(DEFAULT) is pool
    other = pool.for_region(OTHER)
    assert other.region == OTHER and other.supernet == pool.supernet and other.psa_prefix == pool.psa_prefix
    facts = PF.MemoryFactsProvider().resolve("shop", PF.PURPOSES, pool=other)
    assert facts.region == OTHER
    # the IPAM engine provider records the pool's region on each ledger record
    from developer_agent import stack_clients as sc
    engine = MagicMock()
    engine.allocate_next_cidr.side_effect = lambda pid, **k: SimpleNamespace(cidr_block="10.100.0.0/24")
    provider = sc.FirestoreFactsProvider.__new__(sc.FirestoreFactsProvider)
    provider.db = object()
    with patch.object(sc.FirestoreFactsProvider, "_engine", lambda self, p: engine):
        got = provider.resolve("shop", [PF.PURPOSE_SUBNET], pool=other)
    assert got.region == OTHER
    assert engine.allocate_next_cidr.call_args.kwargs["region"] == OTHER


def test_developer_uses_the_dispatch_region_for_the_pool():
    import ast
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)
              and n.name == "_resolve_network_facts")
    body = ast.unparse(fn)
    assert "pool = load_ipam_pool(self.project_id)" in body and "pool = pool.for_region(inputs.region)" in body


# ------------------------------------------------------------------------------------------------ Serverless Git


def _sg(region=None):
    kw = {} if region is None else {"region": region}
    return sgp.ServerlessGitProvider.get_pipeline_contract(None, "svc", "prod", **kw).template_content


def test_serverless_git_template_renders_the_region():
    base = _sg()
    assert base == _sg(DEFAULT) and '\n  _REGION: "us-central1"\n' in base       # the previous exact line
    other = _sg(OTHER)
    assert other == base.replace('_REGION: "us-central1"', f'_REGION: "{OTHER}"') and DEFAULT not in other
    import yaml
    assert yaml.safe_load(other)["substitutions"] == {"_REGION": OTHER}


def test_negative_serverless_git_template_text_is_unchanged_for_the_default():
    """The template text with `{region}` filled with us-central1 is exactly the pre-FD-7M-a constant."""
    before = ('substitutions:\n  _REGION: "us-central1"\n\nimages:\n'
              '  - "${_REGION}-docker.pkg.dev/${PROJECT_ID}/castor-docker-repo/prod:${COMMIT_SHA}"\n')
    assert before in _sg()
    # sha256 of the pre-FD-7M-a render (DEFAULT_CLOUDBUILD_TEMPLATE at main 4409b731; service "svc", product "prod")
    assert hashlib.sha256(_sg().encode()).hexdigest() == \
        "edac107c0de2f1fd33387f8ab954856a1c927357c66aa5b0f7e3d13a1164784f"


def test_serverless_git_provider_copies_are_identical():
    rels = ["shared", "apps/control-center/shared", "apps/qa-runner/shared", "apps/project-vending/shared",
            "apps/orchestrator-gateway/shared", "mcp-servers/terraform/shared", "mcp-servers/" + "gith" + "ub/shared"]
    texts = {open(os.path.join(REPO, r, "providers", "serverless_" + "git" + "_provider.py"), "rb").read()
             for r in rels}
    assert len(texts) == 1


def test_handler_passes_the_dispatch_region_to_the_pipeline_contract():
    import ast
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8").read()
    call = next(c for c in ast.walk(ast.parse(src)) if isinstance(c, ast.Call)
                and getattr(c.func, "attr", "") == "get_pipeline_contract")
    assert ast.unparse(call) == "vcs.get_pipeline_contract(svc, product_id, region=inputs.region)"


# ------------------------------------------------------------------------------------------------ end to end render
def _fake_firestore_module(db):
    return SimpleNamespace(Client=lambda *a, **k: db)


def _generate(record, vcs="GITHUB", settings=APPROVED, monkeypatch=None):
    from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
    import google
    import google.cloud
    import shared.settings as settings_mod
    rec = dict({"project_id": "shop-1234", "project_number": "123456789012", "vcs_provider": vcs,
                "github_repo": "example-org/shop" if vcs == "GITHUB" else "serverless-git/shop.git"}, **record)
    db = _db(rec, settings=settings)
    fake = _fake_firestore_module(db)
    fake_genai = MagicMock()
    monkeypatch.setattr(settings_mod, "get_platform_settings", lambda **k: _settings_obj(settings))
    with patch.dict(sys.modules, {"google.cloud.firestore": fake, "google.genai": fake_genai,
                                  "google.genai.types": fake_genai.types}), \
            patch.object(google.cloud, "firestore", fake, create=True), \
            patch.object(google, "genai", fake_genai, create=True), \
            patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false", "GITHUB_ORG": "example-org"}):
        dev = h.DeveloperAgent(project_id="test-proj")
        dev.db = db
        dev.genai_client = FakeGenaiClient(files=canned_workload_files("shop"))
        with patch.object(dev, "fetch_existing_repo_files", return_value={}):
            return dev.generate_code_files(product_id="shop", spec_text="FastAPI app", task_dag=[],
                                           trace_id="trace-fd7m", architect_compute_intent={
                                               "target_compute_services": ["shop"]}, **INGRESS)


RENDERED = ("infra/workload/variables.tf", "infra/workload/main.tf", ".github/workflows/deploy-shop.yml")


def test_end_to_end_github_render_uses_the_record_region(monkeypatch):
    files = _generate({"region": OTHER}, monkeypatch=monkeypatch)
    variables = hcl2.loads(files["infra/workload/variables.tf"])
    region_var = next(v["region"] for v in variables["variable"] if "region" in v)
    assert region_var["default"] == OTHER
    assert f"\n  REGION: {OTHER}\n" in files[".github/workflows/deploy-shop.yml"]
    assert not [p for p in RENDERED if DEFAULT in files[p]], [p for p in RENDERED if DEFAULT in files[p]]


def test_negative_end_to_end_default_region_recorded_equals_legacy(monkeypatch):
    """Do No Harm: a workload recorded in the default region renders exactly what a workload without a recorded
    region renders (today's path), file by file."""
    legacy = _generate({}, monkeypatch=monkeypatch)
    stamped = _generate({"region": DEFAULT}, monkeypatch=monkeypatch)
    assert set(legacy) == set(stamped)
    for path in RENDERED:
        assert legacy[path] == stamped[path], path
    assert "\n  REGION: us-central1\n" in legacy[".github/workflows/deploy-shop.yml"]


def test_end_to_end_serverless_git_cloudbuild_uses_the_record_region(monkeypatch):
    files = _generate({"region": OTHER}, vcs="SERVERLESS_GIT", monkeypatch=monkeypatch)
    assert f'\n  _REGION: "{OTHER}"\n' in files["cloudbuild.yaml"]
    legacy = _generate({}, vcs="SERVERLESS_GIT", monkeypatch=monkeypatch)
    assert legacy["cloudbuild.yaml"] == _sg_for("shop")


def _sg_for(product_id):
    return sgp.ServerlessGitProvider.get_pipeline_contract(None, product_id, product_id).template_content


# ------------------------------------------------------------------------------------------------ quota gate
_GW_MAIN = []


def _gateway_main():
    """The gateway module, loaded once with no project configured (so its import builds no Firestore client; every
    test injects its own fake `db`)."""
    if not _GW_MAIN:
        spec = importlib.util.spec_from_file_location("fd7m_gw_main", os.path.join(GATEWAY, "main.py"))
        mod = importlib.util.module_from_spec(spec)
        with hermetic_guard.unavailable("google.genai.Client", "Gemini"), \
                patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": ""}):
            spec.loader.exec_module(mod)
        _GW_MAIN.append(mod)
    return _GW_MAIN[0]


def _gw(monkeypatch, db):
    mod = _gateway_main()
    monkeypatch.setattr(mod, "db", db)
    calls = []

    class _Inspector:
        def __init__(self, db_client=None):
            pass

        def harvest_quota_snapshot(self, project_id, regions=None, force_refresh=False):
            calls.append(("harvest", project_id, list(regions or [])))
            return {"status": "HEALTHY", "project_id": project_id, "regions": {r: {} for r in regions or []}}

        def estimate_bom_demand(self, spec):
            return {"compute.googleapis.com/cpus": 1}

        def validate_headroom(self, snapshot, target_region, demand, trace_id=None):
            calls.append(("validate", target_region))
            return True, [], {"target_region": target_region}

        def create_in_flight_claim(self, project_id, region, demand, trace_id):
            calls.append(("claim", region))
            return f"claim-{trace_id}-{region}"
    monkeypatch.setattr(mod, "CloudQuotaInspector", _Inspector)
    return mod, calls


def _headroom(mod, **body):
    return mod.discovery_validate_headroom(mod.ValidateHeadroomRequest(**body))


def test_quota_gate_uses_the_record_region_and_ignores_another_request_region(monkeypatch, caplog):
    db = _db({"region": OTHER}, extra={"pipeline_executions/tr-1": {"product_id": "shop"}})
    mod, calls = _gw(monkeypatch, db)
    with caplog.at_level(logging.WARNING):
        out = _headroom(mod, project_id="child-1", target_region=DEFAULT, trace_id="tr-1")
    assert out["target_region"] == OTHER and ("harvest", "child-1", [OTHER]) in calls and ("claim", OTHER) in calls
    msg = next(r.getMessage() for r in caplog.records if "QUOTA_TARGET_REGION_IGNORED" in r.getMessage())
    assert repr(DEFAULT) in msg and repr(OTHER) in msg


def test_quota_gate_finds_the_product_by_project_when_no_pipeline_record(monkeypatch):
    db = _db({"region": OTHER, "project_id": "child-1"})
    mod, calls = _gw(monkeypatch, db)
    assert _headroom(mod, project_id="child-1", trace_id="tr-x")["target_region"] == OTHER


@pytest.mark.parametrize("extra", [{}, {"workloads/b": {"project_id": "child-1"}}], ids=["none", "several"])
def test_quota_gate_without_a_unique_workload_is_503(monkeypatch, extra):
    from fastapi import HTTPException
    db = _db({"project_id": "child-1"} if extra else None, extra=extra)
    mod, calls = _gw(monkeypatch, db)
    with pytest.raises(HTTPException) as ei:
        _headroom(mod, project_id="child-1", trace_id="tr-x")
    assert ei.value.status_code == 503 and ei.value.detail.startswith("REGION_UNAVAILABLE")
    assert calls == []


def test_quota_gate_unapproved_record_region_is_422(monkeypatch):
    from fastapi import HTTPException
    db = _db({"region": ROGUE}, extra={"pipeline_executions/tr-1": {"product_id": "shop"}})
    mod, calls = _gw(monkeypatch, db)
    with pytest.raises(HTTPException) as ei:
        _headroom(mod, project_id="child-1", trace_id="tr-1")
    assert ei.value.status_code == 422 and ei.value.detail.startswith("REGION_NOT_APPROVED") and calls == []


def test_negative_quota_gate_default_region_workload_body_is_unchanged(monkeypatch):
    """Do No Harm: a legacy (or default-region) workload gets exactly the body the pre-FD-7M-a path gave (the
    platform region resolved from the settings)."""
    bodies = []
    for record in ({}, {"region": DEFAULT}):
        db = _db(dict(record, project_id="child-1"), settings={},
                 extra={"pipeline_executions/tr-1": {"product_id": "shop"}})
        mod, calls = _gw(monkeypatch, db)
        bodies.append((_headroom(mod, project_id="child-1", trace_id="tr-1"), calls))
    # the pre-FD-7M-a path: the region from the platform setting only (resolve_workload_region(db))
    mod, calls = _gw(monkeypatch, None)       # no pipeline store: the request's target_region as given (today's path)
    before_region = te.resolve_workload_region(_db(None, settings={}))
    before = _headroom(mod, project_id="child-1", target_region=before_region, trace_id="tr-1")
    for body, seen in bodies:
        assert body == before and seen == calls


def test_discovery_quotas_harvests_the_union(monkeypatch):
    workflow_list = ["us-central1", "us-east4", "europe-west1"]   # main_orchestrator.yaml harvest_project_quotas
    mod, calls = _gw(monkeypatch, _db(None, settings={"default_gcp_region": DEFAULT,
                                                       "approved_deployable_regions": [DEFAULT, ROGUE]}))
    mod.discovery_quotas(mod.DiscoveryQuotasRequest(project_id="child-1", regions=workflow_list))
    assert calls[-1] == ("harvest", "child-1", workflow_list + [ROGUE])
    mod.discovery_quotas(mod.DiscoveryQuotasRequest(project_id="child-1"))
    assert calls[-1] == ("harvest", "child-1", [DEFAULT, ROGUE])        # no region asked: the approved list


@pytest.mark.parametrize("settings", [None, {}, APPROVED], ids=["no-document", "defaults", "approved-in-list"])
def test_negative_discovery_quotas_default_install_harvests_the_request(monkeypatch, settings):
    workflow_list = ["us-central1", "us-east4", "europe-west1"]
    mod, calls = _gw(monkeypatch, _db(None, settings=settings))
    mod.discovery_quotas(mod.DiscoveryQuotasRequest(project_id="child-1", regions=workflow_list))
    assert calls == [("harvest", "child-1", workflow_list)]


def test_discovery_quotas_unreadable_settings(monkeypatch, caplog):
    """RT F3: with requested regions, an unreadable approved list harvests the requested ones (typed log line);
    503 only when nothing was requested."""
    from fastapi import HTTPException
    db = _db(None)
    db.raises["system_config/platform_settings"] = RuntimeError("down")
    mod, calls = _gw(monkeypatch, db)
    with caplog.at_level(logging.WARNING):
        mod.discovery_quotas(mod.DiscoveryQuotasRequest(project_id="child-1", regions=[DEFAULT, "us-east4"]))
    assert calls == [("harvest", "child-1", [DEFAULT, "us-east4"])]
    assert any(r.getMessage().startswith("REGION_UNAVAILABLE: approved deployable regions not harvested")
               for r in caplog.records)
    with pytest.raises(HTTPException) as ei:
        mod.discovery_quotas(mod.DiscoveryQuotasRequest(project_id="child-1"))
    assert ei.value.status_code == 503 and ei.value.detail.startswith("REGION_UNAVAILABLE") and len(calls) == 1


# ------------------------------------------------------------------------------------------------ quota inspector
def test_claims_without_a_region_are_skipped_not_guessed(caplog):
    insp = qi.CloudQuotaInspector(db_client=FakeDb())
    insp._in_memory_claims = {
        "c1": {"project_id": "p", "status": "ACTIVE", "expires_at": "9999", "region": OTHER,
               "demand": {"compute.googleapis.com/cpus": 2}},
        "c2": {"project_id": "p", "status": "ACTIVE", "expires_at": "9999", "demand": {"compute.googleapis.com/cpus": 5}},
    }
    with caplog.at_level(logging.WARNING):
        got = insp.get_active_claims("p")
    assert got == {f"{OTHER}:compute.googleapis.com/cpus": 2}
    assert any(qi.QUOTA_CLAIM_REGION_MISSING in r.getMessage() and "c2" in r.getMessage() for r in caplog.records)
    db = FakeDb({"quota_claims/c3": {"project_id": "p", "status": "ACTIVE", "expires_at": "9999",
                                     "demand": {"compute.googleapis.com/cpus": 1}}})
    insp2 = qi.CloudQuotaInspector(db_client=db)
    insp2._in_memory_claims = {}
    assert insp2.get_active_claims("p") == {}


def test_negative_claims_with_a_region_count_as_before():
    insp = qi.CloudQuotaInspector(db_client=FakeDb())
    insp.create_in_flight_claim("p", DEFAULT, {"compute.googleapis.com/cpus": 3}, trace_id="t-neg")
    try:
        assert insp.get_active_claims("p")[f"{DEFAULT}:compute.googleapis.com/cpus"] >= 3
    finally:
        insp.release_in_flight_claim(trace_id="t-neg")


def test_harvest_without_regions_uses_the_approved_list():
    insp = qi.CloudQuotaInspector(db_client=_db(None, settings={"default_gcp_region": DEFAULT,
                                                                 "approved_deployable_regions": [DEFAULT, OTHER]}))
    assert sorted(insp.harvest_quota_snapshot("test-p")["regions"]) == [OTHER, DEFAULT]
    insp2 = qi.CloudQuotaInspector(db_client=_db(None, settings=None))
    assert list(insp2.harvest_quota_snapshot("test-p2")["regions"]) == [DEFAULT]   # no document: [default]
    assert list(insp2.harvest_quota_snapshot("test-p3", regions=["bad region!"])["regions"]) == [DEFAULT]
    with pytest.raises(qi.QuotaRegionsUnavailable):
        qi.approved_quota_regions(None)
    bad = _db(None)
    bad.raises["system_config/platform_settings"] = RuntimeError("down")
    with pytest.raises(qi.QuotaRegionsUnavailable) as ei:
        qi.CloudQuotaInspector(db_client=bad).harvest_quota_snapshot("test-p4")
    assert ei.value.error_class == "REGION_UNAVAILABLE"


def test_negative_harvest_with_regions_reads_no_settings():
    db = _db(None)
    snap = qi.CloudQuotaInspector(db_client=db).harvest_quota_snapshot("test-p5", regions=[DEFAULT, "us-east4"])
    assert list(snap["regions"]) == [DEFAULT, "us-east4"]
    assert "system_config/platform_settings" not in db.reads


def test_quota_inspector_copies_are_identical():
    rels = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "mcp-servers/terraform/shared"]
    assert len({open(os.path.join(REPO, r, "quota_inspector.py"), "rb").read() for r in rels}) == 1


# ------------------------------------------------------------------------------------------------ FinOps enforcer
def _enforcer_module():
    spec = importlib.util.spec_from_file_location("fd7m_finops_enforcer", os.path.join(FINOPS, "enforcer.py"))
    mod = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/fd7m.json"}):
        spec.loader.exec_module(mod)
    return mod


ENF = _enforcer_module()
MANAGED_ROOT = "111111111111"


def _crm():
    crm = MagicMock()
    numbers = {}
    crm.projects.return_value.getAncestry.side_effect = lambda projectId, body: MagicMock(**{
        "execute.return_value": {"ancestor": [{"resourceId": {"type": "project", "id": projectId}},
                                              {"resourceId": {"type": "folder", "id": MANAGED_ROOT}}]}})
    crm.projects.return_value.get.side_effect = lambda projectId: MagicMock(**{
        "execute.return_value": {"projectNumber": numbers.setdefault(projectId, str(100 + len(numbers)))}})
    return crm


@pytest.fixture
def enforcer_env(monkeypatch):
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", MANAGED_ROOT)
    monkeypatch.setenv("PROJECT_ID", "host-p")


def _engine(db):
    run = MagicMock()
    services = run.projects.return_value.locations.return_value.services.return_value
    services.list.return_value.execute.return_value = {"services": [{"name": "x/services/api", "template": {}}]}
    compute = MagicMock()                                    # no VMs; one aggregatedList page
    compute.instances.return_value.aggregatedList.return_value.execute.return_value = {}
    compute.instances.return_value.aggregatedList_next.return_value = None
    sql = MagicMock()
    sql.instances.return_value.list.return_value.execute.return_value = {}
    container = MagicMock()
    container.projects.return_value.locations.return_value.clusters.return_value.list.return_value \
        .execute.return_value = {}
    eng = ENF.FinopsBudgetEnforcer(project_id="host-p", firestore_client=db, run_service=run,
                                   compute_service=compute, sql_service=sql, container_service=container,
                                   billing_service=MagicMock(), crm_service=_crm(), advisor=SimpleNamespace(
                                       available=False))
    return eng, services


def _paths(services):
    return ([c.kwargs["parent"] for c in services.list.call_args_list],
            [c.kwargs["name"] for c in services.patch.call_args_list])


def test_enforcer_scales_in_the_record_region(enforcer_env):
    eng, services = _engine(_db({"region": OTHER}))
    res = eng.quarantine_workload("shop", "child-1", spend_amount=2.0, budget_amount=1.0)
    assert res["status"] == "QUARANTINED" and res["quarantined_resources"] == ["run/api"]
    assert _paths(services) == ([f"projects/child-1/locations/{OTHER}"],
                                [f"projects/child-1/locations/{OTHER}/services/api"])
    eng2, services2 = _engine(_db({"region": OTHER, "status": "QUARANTINED"},
                                  extra={"quarantine_snapshots/shop": {"cloud_run_services": [
                                      {"name": "api", "max_instances": 3, "min_instances": 0}]}}))
    # RT14-05: the restore reads the service back (in the same region) before reporting RESTORED
    services2.list.return_value.execute.return_value = {"services": [
        {"name": "x/services/api", "template": {"scaling": {"maxInstanceCount": 3}}}]}
    out = eng2.restore_workload("shop", "child-1")
    assert out["status"] == "RESTORED" and out["restored_services"] == ["api"]
    assert _paths(services2)[0] == [f"projects/child-1/locations/{OTHER}"]
    assert _paths(services2)[1] == [f"projects/child-1/locations/{OTHER}/services/api"]


@pytest.mark.parametrize("record,settings", [({}, None), ({"region": DEFAULT}, APPROVED), (None, {})],
                         ids=["legacy-no-settings-doc", "default-recorded", "no-record"])
def test_negative_enforcer_default_region_paths_are_unchanged(enforcer_env, record, settings):
    """Do No Harm: a workload in the default region is listed / scaled at exactly the paths used before (the engine's
    us-central1, which equals the settings default on both dev installs)."""
    eng, services = _engine(_db(record, settings=settings))
    eng.quarantine_workload("shop", "child-1", spend_amount=2.0, budget_amount=1.0)
    assert _paths(services) == (["projects/child-1/locations/us-central1"],
                                ["projects/child-1/locations/us-central1/services/api"])


def test_enforcer_legacy_workload_follows_the_default_setting(enforcer_env):
    eng, services = _engine(_db({}, settings={"default_gcp_region": OTHER}))
    eng.quarantine_workload("shop", "child-1", spend_amount=2.0, budget_amount=1.0)
    assert _paths(services)[0] == [f"projects/child-1/locations/{OTHER}"]


@pytest.mark.parametrize("case", ["not-approved", "record-unreadable", "settings-unreadable"])
def test_enforcer_region_refusal_is_typed_and_touches_nothing(enforcer_env, case):
    db = _db({"region": ROGUE if case == "not-approved" else OTHER})
    if case == "record-unreadable":
        db.raises["workloads/shop"] = RuntimeError("down")
    if case == "settings-unreadable":
        db.raises["system_config/platform_settings"] = RuntimeError("down")
    eng, services = _engine(db)
    res = eng.quarantine_workload("shop", "child-1", spend_amount=2.0, budget_amount=1.0)
    assert res["status"] == "REFUSED" and res["action"] == "QUARANTINE"
    assert res["error_class"] == ("REGION_NOT_APPROVED" if case == "not-approved" else "REGION_UNAVAILABLE")
    assert _paths(services) == ([], [])
    # RT Q3: no snapshot, no status change; the breach stays visible: one billing alert + one BUDGET_BREACH card
    written = [k for k, _ in db.writes]
    assert written == ["billing_alerts/+", f"approval_requests/{res['approval_id']}"], written
    card = db.docs[f"approval_requests/{res['approval_id']}"]
    assert card["approval_type"] == "BUDGET_BREACH" and card["status"] == "PENDING"
    assert card["quarantined_resources"] == [] and res["error_class"] in card["risk_assessment"]
    alert = db.writes[0][1]
    assert alert["severity"] == "ERROR" and res["error_class"] in alert["message"]
    assert db.docs.get("workloads/shop", {}).get("status") is None and "quarantine_snapshots/shop" not in db.docs
    res2 = eng.restore_workload("shop", "child-1")
    # C10 (owner-directed 11-07): the refused quarantine scaled nothing down, so a restore changes no service: it
    # answers NOTHING_TO_RESTORE (and clears the breach latch) before any region lookup; with the workload record
    # unreadable it cannot tell and answers SNAPSHOT_UNREADABLE, writing nothing.
    assert _paths(services) == ([], [])
    if case == "record-unreadable":
        assert res2["status"] == "SNAPSHOT_UNREADABLE" and len(db.writes) == 2
    else:
        assert res2["status"] == "NOTHING_TO_RESTORE" and res2["restored_services"] == []
        assert [k for k, _ in db.writes][2:] == ["workloads/shop"]   # the latch clear only


def test_negative_card_and_alert_writers_keep_the_hitl_and_alert_only_records(enforcer_env):
    """Do No Harm: the HITL card and the ALERT_ONLY alert written through the shared writers are the same records."""
    db = _db({"region": OTHER})
    eng, _ = _engine(db)
    res = eng.quarantine_workload("shop", "child-1", trace_id="tr", spend_amount=2.0, budget_amount=1.0,
                                  policy="HITL_CONFIRMATION_REQUIRED")
    card = db.docs[f"approval_requests/{res['approval_id']}"]
    assert set(card) == {"approval_id", "approval_type", "product_id", "target_project_id", "trace_id",
                         "cost_delta_monthly", "risk_assessment", "status", "requested_at", "current_spend_usd",
                         "budget_ceiling_usd", "buffer_ceiling_usd", "quarantined_resources"}
    assert card["risk_assessment"] == ("100% Budget breach detected ($2.00 / $1.00). Awaiting operator remediation "
                                       "choice.") and card["buffer_ceiling_usd"] == 1.15
    eng.quarantine_workload("shop", "child-1", trace_id="tr", spend_amount=2.0, budget_amount=1.0, policy="ALERT_ONLY")
    alert = [d for k, d in db.writes if k == "billing_alerts/+"][0]
    assert alert["severity"] == "WARNING" and alert["policy"] == "ALERT_ONLY"
    assert alert["message"] == "Workload shop exceeded budget ceiling ($2.00 / $1.00)"


def test_enforcer_configured_install_without_client_refuses(enforcer_env):
    """RT F1: a platform project is configured but there is no Firestore client -> typed, never the engine region."""
    eng, services = _engine(FakeDb())
    eng.db = None
    with pytest.raises(ENF.WorkloadRegionRefused) as ei:
        eng.resolve_workload_region("shop")
    assert ei.value.error_class == "REGION_UNAVAILABLE"
    res = eng.quarantine_workload("shop", "child-1", spend_amount=2.0, budget_amount=1.0)
    assert res["status"] == "REFUSED" and res["error_class"] == "REGION_UNAVAILABLE" and _paths(services) == ([], [])


def test_enforcer_blank_default_region_refuses(enforcer_env):
    """RT F2: a blank stored default_gcp_region never builds locations//services."""
    db = _db({}, settings={"default_gcp_region": ""})
    eng, services = _engine(db)
    res = eng.quarantine_workload("shop", "child-1", spend_amount=2.0, budget_amount=1.0)
    assert res["status"] == "REFUSED" and res["error_class"] == "REGION_UNAVAILABLE" and _paths(services) == ([], [])


@pytest.mark.parametrize("policy", ["ALERT_ONLY", "HITL_CONFIRMATION_REQUIRED", "NUCLEAR_UNLINK_BILLING"])
def test_negative_policies_without_cloud_run_read_no_region(enforcer_env, policy):
    db = _db({"region": ROGUE})                              # would refuse if it were read
    eng, services = _engine(db)
    res = eng.quarantine_workload("shop", "child-1", spend_amount=2.0, budget_amount=1.0, policy=policy)
    assert res["status"] != "REFUSED" and "system_config/platform_settings" not in db.reads


def test_negative_enforcer_without_a_store_uses_its_region():
    eng, services = _engine(FakeDb())
    eng.db = None                                            # no Firestore client (built without one) ...
    eng.platform_project_id = ""                             # ... and no project at all (direct callers)
    assert eng.resolve_workload_region("shop") == eng.region
    eng.db = MagicMock()                                     # a test double: not a Firestore snapshot
    assert eng.resolve_workload_region("shop") == eng.region


# ------------------------------------------------------------------------------------------------ review fixes (11-01)
def test_configured_install_without_client_is_region_unavailable(monkeypatch):
    """RT F1 (= the terraform server): PROJECT_ID set, no client, a product -> typed; without a product the FD-4AL
    answer is unchanged; the harness case (no project at all) keeps the platform region."""
    monkeypatch.setenv("PROJECT_ID", "host-p")
    monkeypatch.setenv("REGION", "us-east4")
    with pytest.raises(te.RegionUnavailable, match="no Firestore client although a project is configured"):
        te.resolve_workload_region(None, product_id="shop")
    assert te.resolve_workload_region(None) == "us-east4"                 # no product: FD-4AL as before
    monkeypatch.delenv("PROJECT_ID")
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("REGION")
    monkeypatch.delenv("DEFAULT_REGION", raising=False)
    assert te.resolve_workload_region(None, product_id="shop") == te.WORKLOAD_REGION_DEFAULT


def test_dispatch_configured_install_without_client_stops_typed(monkeypatch):
    monkeypatch.setenv("PROJECT_ID", "host-p")
    monkeypatch.setattr(h.DeveloperAgent, "_resolve_regulated_controls",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must stop before")))
    with pytest.raises(DeveloperStageError) as ei:
        _agent(None).generate_code_files("shop", "spec", [{"step_id": "S1"}], trace_id="t", **INGRESS)
    assert ei.value.error_class == "REGION_UNAVAILABLE"


def test_k8s_hydration_configured_install_without_client_is_unusable(monkeypatch):
    import shared.settings as settings_mod
    monkeypatch.setattr(settings_mod, "get_platform_settings", lambda **k: _settings_obj())
    monkeypatch.setenv("PROJECT_ID", "host-p")
    assert _agent(None)._platform_region("shop") == ""
    assert _agent(None)._platform_region() == DEFAULT                    # no product: the setting as before
    monkeypatch.delenv("PROJECT_ID")
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    assert _agent(None)._platform_region("shop") == DEFAULT              # harness: the setting as before


def test_blank_stored_default_approves_the_platform_region(monkeypatch):
    """RT F2 (= the terraform server): a blank stored default is FD-4AL's "no setting": the record in the env region is
    approved (the legacy path renders there too); another region is still refused."""
    monkeypatch.setenv("REGION", "us-east4")
    blank = {"default_gcp_region": ""}
    assert te.resolve_workload_region(_db({"region": "us-east4"}, settings=blank), product_id="shop") == "us-east4"
    assert te.resolve_workload_region(_db({}, settings=blank), product_id="shop") == "us-east4"   # legacy, unchanged
    with pytest.raises(te.RegionNotApproved):
        te.resolve_workload_region(_db({"region": OTHER}, settings=blank), product_id="shop")


def test_region_not_approved_string_parity(monkeypatch):
    from developer_agent import errors
    from fd4g_support import load_tf_service
    import shared.settings as settings_mod
    tf = load_tf_service(monkeypatch)
    assert errors.REGION_NOT_APPROVED == tf.REGION_NOT_APPROVED == settings_mod.REGION_NOT_APPROVED \
        == te.RegionNotApproved.error_class == "REGION_NOT_APPROVED"
    assert errors.REGION_UNAVAILABLE == tf.REGION_UNAVAILABLE == "REGION_UNAVAILABLE"


# Q7: the architect's IPAM allocation records the workload region, not the Gemini location
def _architect_db(record):
    data = {"workloads": {"order-processor": record},
            "system_config": {"platform_settings": {"orchestration": APPROVED}}}
    db = MagicMock()

    def collection(name):
        col = MagicMock()
        if name in data:
            col.document.side_effect = lambda doc_id: SimpleNamespace(
                get=lambda: _Snap(doc_id, data[name].get(doc_id)), set=MagicMock(), update=MagicMock(),
                collection=MagicMock())
        return col
    db.collection.side_effect = collection
    return db


def _architect_allocate(db, monkeypatch):
    import json as _json
    import shared.ipam as ipam_mod
    from architect_agent.handler import ArchitectAgent
    monkeypatch.setenv("GEMINI_LOCATION", "global")
    monkeypatch.setenv("PROJECT_ID", "")              # the agent builds no Firestore client of its own (db injected)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "")
    # DEFAULT-MODEL-GEMINI-4-CARBON: the agent's model is its settings role, read at construction too
    with hermetic_guard.unavailable("google.genai.Client", "Gemini"), \
            patch("shared.settings.get_platform_settings", return_value=PlatformSettings()):
        agent = ArchitectAgent(project_id="")
    dag = {"product_id": "order-processor", "project_tier": 1, "summary": "s", "architecture_overview": "o",
           "infra_tasks": [{"task_id": "INFRA-01", "title": "t", "category": "INFRA",
                            "target_files": ["infra/workload/main.tf"], "description": "d",
                            "acceptance_criteria": ["a"], "depends_on": [], "assigned_agent": "gcp-devops",
                            "priority": "HIGH"}],
           "code_tasks": [], "estimated_complexity": "MEDIUM", "requires_human_approval": False,
           "risk_assessment": "r", "service_topology": {"services": [{"name": "order-processor", "kind": "cloudrun"}],
                                                        "primary_service": "order-processor", "edges": [],
                                                        "resources": []}}
    client = MagicMock()
    client.models.generate_content.return_value = SimpleNamespace(text=_json.dumps(dag))
    agent.genai_client = client
    agent.db = db
    rec = ipam_mod.CidrAllocationRecord(cidr_block="10.100.0.16/28", sanitized_id="10_100_0_16_28",
                                        product_id="order-processor")
    with patch.object(ipam_mod.CastorIPAMEngine, "allocate_next_cidr", autospec=True, return_value=rec) as alloc, \
            patch("shared.settings.get_platform_settings", return_value=PlatformSettings()):
        result = agent.decompose(spec_text="Build an order processor that reaches Cloud SQL through a VPC connector",
                                 product_id="order-processor", trace_id="trace-q7")
    return result, alloc


def test_architect_ipam_records_the_workload_region(monkeypatch):
    result, alloc = _architect_allocate(_architect_db({"region": OTHER}), monkeypatch)
    assert alloc.call_args.kwargs["region"] == OTHER
    assert result.architecture_plan.assigned_cidr_block == "10.100.0.16/28"


def test_architect_ipam_default_region_allocation_is_unchanged_but_records_the_install_region(monkeypatch):
    """Default-region workload: the same range, purpose and /28 from the same pool as before; the ledger region is
    the install's region (was the Gemini location "global", metadata only)."""
    for record in ({"product_id": "order-processor"}, {"region": DEFAULT}):
        result, alloc = _architect_allocate(_architect_db(record), monkeypatch)
        engine = alloc.call_args.args[0]
        assert engine.supernet_cidr == "10.100.0.0/16" and alloc.call_args.kwargs["prefix_len"] == 28
        assert alloc.call_args.kwargs["purpose"] == "SERVERLESS_VPC_CONNECTOR"
        assert alloc.call_args.kwargs["region"] == DEFAULT
        assert result.architecture_plan.assigned_cidr_block == "10.100.0.16/28"


def test_architect_ipam_unapproved_region_assigns_no_range(monkeypatch):
    result, alloc = _architect_allocate(_architect_db({"region": ROGUE}), monkeypatch)
    assert not alloc.called and result.architecture_plan.assigned_cidr_block is None
    assert result.architecture_plan.requires_vpc is True

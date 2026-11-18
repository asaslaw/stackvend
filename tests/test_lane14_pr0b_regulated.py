"""Lane 14 PR-0b (owner decision L14-i, 10-18): regulated-profile builds can pass the strict PR-0 compliance plan gate.

For a regulated stored compliance profile (HIPAA, FedRAMP, CJIS, PCI-DSS, EU) the platform renders a per-workload KMS
key (golden security-kms, 90-day rotation, in the workload region), grants the Google service agents
cryptoKeyEncrypterDecrypter with the provider's typed `member`, wires the key into every platform-rendered
CMEK-capable golden module (foundation Artifact Registry + Firestore, compute-cloudrun primary and secondaries,
compute-event-worker, compute-gke-autopilot) and turns on Data Access audit logging (allServices DATA_READ +
DATA_WRITE). A STANDARD (or absent) profile renders byte-identical IaC (Do No Harm).

Covered here:
  * the profile source (same precedence as the gate's compliance_gate.load_decision) and the typed refusals (unknown
    profile, platform region outside the profile) BEFORE any LLM call; an unreadable decision renders STANDARD and
    the gate (which re-reads it at apply) enforces;
  * the real developer assembly end to end (fake draft, fake /validate) for a stored HIPAA decision and for none;
  * parity of the requirements table with the compliance server's `get_compliance_requirements`;
  * STANDARD renders: sha256 of every platform render equals the pre-PR-0b render (digests recorded from main 1202c76);
  * regulated renders per archetype, secondaries, service agents;
  * golden-module copies (infra/modules, control-center, the 4 builtin_modules_payload.py) identical;
  * production column (tofu 1.9.0 + google 6.35.0 mirror): `tofu validate` + plan-only `tofu test` with mock providers,
    and a REAL offline `tofu plan` (sandboxed, no network, fake token) whose `show -json` is evaluated by the PR-0 plan
    gate (mcp-servers/compliance/plan_gate.py when present on the branch; until PR-0 merges, a strict replica of its
    CMEK / audit / region rules whose tables are parity-tested against plan_gate.py once it exists) -> PASS; the
    STANDARD plan carries no CMEK, KMS or audit resource.
"""
import hermetic_guard  # noqa: F401  (first import)

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import compliance_profile as cp  # noqa: E402
from developer_agent import terraform_engine as te  # noqa: E402
from fd4atc_render import without_fd4atc  # noqa: E402  (FD-4AT-c pin normalization)
from visible_rename_render import pre_visible_rename  # noqa: E402  (VISIBLE-RENAME pin normalization)
from developer_agent import topology_wiring as tw  # noqa: E402
from developer_agent.errors import ERROR_CLASSES, DeveloperStageError  # noqa: E402

W = "infra/workload/"
PROD_TOFU = os.environ.get("STACKVEND_PROD_TOFU") or os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.environ.get("STACKVEND_PROD_MIRROR") or os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
SANDBOX_PROFILE = "(version 1)(allow default)(deny network-outbound (remote ip))"
KEY = "projects/mock-proj/locations/us-central1/keyRings/mock-proj-workload-cmek/cryptoKeys/workload-cmek"

TOUCHED_MODULES = {
    "security-kms": ("main.tf", "outputs.tf", "variables.tf"),
    "workload-foundation/base": ("compliance.tf", "database.tf", "registry.tf"),
    "compute-cloudrun": ("main.tf", "variables.tf"),
    "compute-event-worker": ("main.tf", "variables.tf"),
    "compute-gke-autopilot": ("main.tf", "variables.tf"),
    "storage-bucket": ("main.tf", "variables.tf"),
    "messaging-pubsub": ("main.tf", "variables.tf"),
    "analytics-bigquery": ("main.tf", "variables.tf"),
    "cache-redis": ("main.tf", "variables.tf"),
    "database-cloudsql": ("main.tf", "variables.tf"),
}
PAYLOADS = ("shared/builtin_modules_payload.py", "mcp-servers/terraform/shared/builtin_modules_payload.py",
            "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
            "apps/control-center/shared/builtin_modules_payload.py")


def _hipaa(profile="HIPAA"):
    return cp.resolve_regulated_controls(profile, cp.PROFILE_SOURCE_DECISION, te.WORKLOAD_REGION_DEFAULT)


def _load_by_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ================================================================================ profile source + typed refusals
@pytest.mark.parametrize("doc, want", [
    (None, ("STANDARD", cp.PROFILE_SOURCE_DEFAULT)),
    ({}, ("STANDARD", cp.PROFILE_SOURCE_DEFAULT)),
    ({"compliance_profile": "HIPAA"}, ("HIPAA", cp.PROFILE_SOURCE_PROFILE)),
    # Integration (compliance-profile-explicit RT F1): a decision recorded before the explicit-profile change (no
    # `profile_source`) is rebased to the stored selection, else STANDARD; a current one is used as is.
    ({"compliance_decision": {"profile": "PCI_DSS"}, "compliance_profile": "HIPAA"}, ("STANDARD", cp.PROFILE_SOURCE_LEGACY)),
    ({"compliance_decision": {"profile": "PCI_DSS"}, "requested_compliance_profile": "HIPAA"},
     ("HIPAA", cp.PROFILE_SOURCE_LEGACY)),
    ({"compliance_decision": {"profile": "PCI_DSS", "profile_source": "EXPLICIT_REQUEST", "requested_profile": "PCI_DSS"},
      "requested_compliance_profile": "PCI_DSS", "compliance_profile": "HIPAA"}, ("PCI_DSS", cp.PROFILE_SOURCE_DECISION)),
    ({"compliance_decision": {"profile": "STANDARD", "profile_source": "DEFAULT_STANDARD", "requested_profile": None}},
     ("STANDARD", cp.PROFILE_SOURCE_DECISION)),
    ({"requested_compliance_profile": "CJIS", "compliance_profile": "HIPAA"}, ("CJIS", cp.PROFILE_SOURCE_SELECTION)),
    ({"compliance_decision": {"profile": ""}, "compliance_profile": "CJIS"}, ("CJIS", cp.PROFILE_SOURCE_PROFILE)),
    ({"compliance_decision": "HIPAA"}, ("STANDARD", cp.PROFILE_SOURCE_DEFAULT)),
    ({"compliance_profile": 7}, ("STANDARD", cp.PROFILE_SOURCE_DEFAULT)),
])
def test_profile_comes_from_the_stored_decision_with_the_gate_precedence(doc, want):
    assert cp.profile_from_workload_doc(doc) == want


def test_stale_stored_decision_is_a_typed_refusal_like_the_gate():
    doc = {"compliance_decision": {"profile": "HIPAA", "profile_source": "EXPLICIT_REQUEST", "requested_profile": "HIPAA"},
           "requested_compliance_profile": "STANDARD"}
    with pytest.raises(cp.ComplianceRenderRefused) as e:
        cp.profile_from_workload_doc(doc)
    assert e.value.error_class == cp.COMPLIANCE_DECISION_STALE


def test_profile_precedence_matches_the_plan_gate_loader_when_pr0_is_present():
    path = os.path.join(REPO_ROOT, "mcp-servers", "terraform", "compliance_gate.py")
    if not os.path.exists(path):
        pytest.skip("lane 14 PR-0 (mcp-servers/terraform/compliance_gate.py) not on this branch yet")
    cg = _load_by_path("pr0b_compliance_gate", path)
    assert (cg.PROFILE_SOURCE_DECISION, cg.PROFILE_SOURCE_PROFILE, cg.PROFILE_SOURCE_DEFAULT,
            cg.PROFILE_SOURCE_SELECTION, cg.PROFILE_SOURCE_LEGACY, cg.REQUESTED_PROFILE_FIELD) == (
        cp.PROFILE_SOURCE_DECISION, cp.PROFILE_SOURCE_PROFILE, cp.PROFILE_SOURCE_DEFAULT,
        cp.PROFILE_SOURCE_SELECTION, cp.PROFILE_SOURCE_LEGACY, cp.REQUESTED_PROFILE_FIELD)
    current = {"profile": "CJIS", "profile_source": "EXPLICIT_REQUEST", "requested_profile": "CJIS"}

    def _db(doc):
        snap = types.SimpleNamespace(exists=bool(doc), to_dict=lambda d=doc: dict(d))
        return types.SimpleNamespace(collection=lambda _c, s=snap: types.SimpleNamespace(
            document=lambda _d: types.SimpleNamespace(get=lambda: s)))
    for doc in ({}, {"compliance_profile": "HIPAA"}, {"compliance_decision": {"profile": "CJIS"}},
                {"compliance_decision": {"profile": ""}, "compliance_profile": "PCI_DSS"},
                {"compliance_decision": {"profile": "CJIS"}, "requested_compliance_profile": "HIPAA"},
                {"compliance_decision": current, "requested_compliance_profile": "CJIS"},
                {"requested_compliance_profile": "PCI_DSS", "compliance_profile": "HIPAA"}):
        decision, source = cg.load_decision(_db(doc), "p")
        assert (decision["profile"], source) == cp.profile_from_workload_doc(doc)
    stale = {"compliance_decision": current, "requested_compliance_profile": "HIPAA"}
    with pytest.raises(cg.DecisionStale):
        cg.load_decision(_db(stale), "p")
    with pytest.raises(cp.ComplianceRenderRefused):
        cp.profile_from_workload_doc(stale)


def test_requirements_table_equals_the_compliance_server_table():
    svc_mod = _load_by_path("pr0b_compliance_service", os.path.join(REPO_ROOT, "mcp-servers", "compliance", "service.py"))
    svc = svc_mod.ComplianceService.__new__(svc_mod.ComplianceService)
    assert cp.REGULATED_PROFILES == {"HIPAA", "FEDRAMP_MODERATE", "FEDRAMP_HIGH", "CJIS", "EU_REGIONS_AND_SUPPORT",
                                     "PCI_DSS"}
    for profile, want in cp.PROFILE_REQUIREMENTS.items():
        got = svc.get_compliance_requirements(profile)
        assert got["profile"] == profile
        assert (bool(got["requires_cmek"]), bool(got["requires_audit_logging"]), tuple(got["allowed_regions"])) == (
            want["requires_cmek"], want["requires_audit_logging"], want["allowed_regions"]), profile
    plan_gate = os.path.join(REPO_ROOT, "mcp-servers", "compliance", "plan_gate.py")
    if os.path.exists(plan_gate):
        assert _load_by_path("pr0b_plan_gate_vocab", plan_gate).KNOWN_PROFILES == cp.KNOWN_PROFILES


def test_standard_renders_nothing_and_regulated_profiles_render_both_controls():
    assert cp.resolve_regulated_controls("STANDARD", cp.PROFILE_SOURCE_DEFAULT, "us-central1") is None
    for profile in ("HIPAA", "FEDRAMP_MODERATE", "FEDRAMP_HIGH", "CJIS", "PCI_DSS"):
        rc = _hipaa(profile)
        assert (rc.profile, rc.cmek, rc.audit_logging, rc.region) == (profile, True, True, "us-central1")


@pytest.mark.parametrize("profile, region, error_class", [
    ("EU_REGIONS_AND_SUPPORT", "us-central1", cp.COMPLIANCE_REGION_NOT_ALLOWED),
    ("HIPAA", "europe-west1", cp.COMPLIANCE_REGION_NOT_ALLOWED),
    ("PCI_DSS", "us-west1", cp.COMPLIANCE_REGION_NOT_ALLOWED),
    ("SOC2", "us-central1", cp.COMPLIANCE_PROFILE_UNKNOWN),
    ("hipaa", "us-central1", cp.COMPLIANCE_PROFILE_UNKNOWN),
])
def test_unrenderable_profiles_are_refused_typed(profile, region, error_class):
    with pytest.raises(cp.ComplianceRenderRefused) as e:
        cp.resolve_regulated_controls(profile, cp.PROFILE_SOURCE_DECISION, region)
    assert e.value.error_class == error_class
    assert error_class in ERROR_CLASSES


def test_platform_region_constant_is_the_region_the_terraform_server_applies():
    """FD-4AL: the pre-generation region check and the terraform server's runtime tfvars `region` (which wins at
    apply) read the same source, the platform setting `orchestration.default_gcp_region`: the server writes the
    deploy's resolved `workload_region` (no literal), and the developer's direct-caller default is that setting's
    schema default (tests/test_fd4al_region.py covers both resolvers)."""
    import ast
    from shared.settings import OrchestrationSettings
    src = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py")).read()
    values = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "region":
                    values.append(v)
    assert len(values) == 1 and isinstance(values[0], ast.JoinedStr)
    assert [n.id for n in ast.walk(values[0]) if isinstance(n, ast.Name)] == ["workload_region"]
    assert te.WORKLOAD_REGION_DEFAULT == OrchestrationSettings().default_gcp_region
    assert f'default     = "{te.WORKLOAD_REGION_DEFAULT}"' in te.generate_golden_variables_tf("shop", "acme/shop")


# ---------------------------------------------------------------------------------------- developer handler
class _Snap:
    def __init__(self, data):
        self.exists = data is not None
        self._data = data

    def to_dict(self):
        return dict(self._data or {})


class _FakeDb:
    def __init__(self, data=None, raises=None):
        self.data, self.raises, self.reads = data, raises, []

    def collection(self, name):
        db = self

        class _Coll:
            def document(self, doc_id):
                class _Doc:
                    def get(self):
                        db.reads.append((name, doc_id))
                        if db.raises:
                            raise db.raises
                        return _Snap(db.data)
                return _Doc()
        return _Coll()


# FD-4R R-6: the developer is always called with the ingress flags of a compliance decision.
INGRESS = {"allow_unauthenticated": True, "enable_direct_iap": False, "domain_restricted_sharing": False}


def _agent(db):
    from developer_agent.handler import DeveloperAgent
    agent = DeveloperAgent.__new__(DeveloperAgent)
    agent.db = db
    agent._stack_runs, agent._stack_last_trace = {}, None
    return agent


def test_handler_stale_stored_decision_is_a_typed_stage_error():
    """Integration: COMPLIANCE_DECISION_STALE is a registered developer error class (DeveloperStageError refuses
    unknown classes), raised before any LLM call on the direct-caller path."""
    from developer_agent import errors
    assert {"COMPLIANCE_PROFILE_UNKNOWN", "COMPLIANCE_REGION_NOT_ALLOWED", "COMPLIANCE_DECISION_UNAVAILABLE",
            "COMPLIANCE_DECISION_STALE"} <= errors.ERROR_CLASSES
    db = _FakeDb({"compliance_decision": {"profile": "HIPAA", "profile_source": "EXPLICIT_REQUEST",
                                          "requested_profile": "HIPAA"}, "requested_compliance_profile": "PCI_DSS"})
    with pytest.raises(DeveloperStageError) as e:
        _agent(db)._resolve_regulated_controls("p")
    assert e.value.error_class == "COMPLIANCE_DECISION_STALE"


def test_handler_resolves_the_stored_profile():
    assert _agent(None)._resolve_regulated_controls("p") is None
    assert _agent(_FakeDb(None))._resolve_regulated_controls("p") is None
    assert _agent(_FakeDb({"compliance_profile": "STANDARD"}))._resolve_regulated_controls("p") is None
    db = _FakeDb({"compliance_decision": {"profile": "HIPAA", "profile_source": "EXPLICIT_REQUEST",
                                          "requested_profile": "HIPAA"}, "requested_compliance_profile": "HIPAA"})
    rc = _agent(db)._resolve_regulated_controls("p")
    assert (rc.profile, rc.source, rc.cmek, rc.audit_logging) == ("HIPAA", cp.PROFILE_SOURCE_DECISION, True, True)
    assert db.reads == [("workloads", "p")]


def test_unreadable_decision_is_a_typed_refusal_owner_q1(caplog):
    """Owner Q1 = yes (10-18): an unreadable workloads/{pid} stops the stage (was: STANDARD + an ERROR log)."""
    with pytest.raises(DeveloperStageError) as e:
        _agent(_FakeDb(raises=RuntimeError("firestore down")))._resolve_regulated_controls("p")
    assert e.value.error_class == "COMPLIANCE_DECISION_UNAVAILABLE"
    assert "COMPLIANCE_DECISION_UNREADABLE" not in caplog.text


def test_unreadable_decision_with_q1_off_renders_standard(monkeypatch, caplog):
    """The pre-decision behaviour, kept reachable by the constant (owner may revert it with one line)."""
    monkeypatch.setattr(cp, "FAIL_CLOSED_ON_UNREADABLE_DECISION", False)
    caplog.set_level("ERROR")
    assert _agent(_FakeDb(raises=RuntimeError("firestore down")))._resolve_regulated_controls("p") is None
    assert "COMPLIANCE_DECISION_UNREADABLE" in caplog.text


@pytest.mark.parametrize("db, error_class", [
    (_FakeDb({"compliance_decision": {"profile": "EU_REGIONS_AND_SUPPORT", "profile_source": "EXPLICIT_REQUEST",
                                      "requested_profile": "EU_REGIONS_AND_SUPPORT"},
              "requested_compliance_profile": "EU_REGIONS_AND_SUPPORT"}), "COMPLIANCE_REGION_NOT_ALLOWED"),
    (_FakeDb({"compliance_profile": "SOC2"}), "COMPLIANCE_PROFILE_UNKNOWN"),
])
def test_generate_code_files_refuses_before_any_llm_call(db, error_class):
    agent = _agent(db)

    class _NoLLM:
        def __getattr__(self, name):
            raise AssertionError(f"LLM client touched ({name}) after a compliance refusal")
    agent.genai_client = _NoLLM()
    with pytest.raises(DeveloperStageError) as e:
        agent.generate_code_files("p", "spec", [{"step_id": "S1"}], trace_id="t", **INGRESS)
    assert e.value.error_class == error_class


class _FakeDbWithWrites(_FakeDb):
    """Reads return the workload document; the stage's own pipeline_executions writes are accepted and dropped."""

    def collection(self, name):
        coll = super().collection(name)

        class _Coll:
            def document(self, doc_id):
                doc = coll.document(doc_id)
                doc.set = lambda *a, **k: None
                return doc
        return _Coll()


@pytest.mark.parametrize("stored, regulated", [
    (None, False),
    ({"compliance_decision": {"profile": "HIPAA", "profile_source": "EXPLICIT_REQUEST", "requested_profile": "HIPAA"},
      "requested_compliance_profile": "HIPAA"}, True),
    ({"compliance_decision": {"profile": "HIPAA"}}, False),   # legacy (pre-explicit) decision: rebased to STANDARD
])
def test_generate_code_files_renders_the_regulated_tree_end_to_end(stored, regulated):
    """The real developer assembly (fake draft + fake /validate, no network): the stored decision decides the render;
    STANDARD (no decision) is unchanged."""
    from test_step1_s1b_generation import Client, _agent as _s1b_agent, _generate, _runtime
    agent = _s1b_agent(_runtime(Client()))
    agent.db = _FakeDbWithWrites(stored)
    files = _generate(agent, trace=f"trace-pr0b-{regulated}")
    main = files[W + "main.tf"]
    assert ('module "cmek" {' in main) is regulated
    assert ("encryption_key        = module.cmek.crypto_key_name" in main) is regulated
    assert ("enable_data_access_audit_logs = true" in main) is regulated
    assert ("infra/modules/security-kms/main.tf" in files) is regulated
    assert ("infra/modules/workload-foundation/base/compliance.tf" in files)   # vendored with the foundation, inert
    tfvars = files.get(W + "terraform.tfvars", "")
    assert ('"cloudkms.googleapis.com"' in tfvars) is regulated
    assert ("kms" in main) is regulated


# ============================================ integration: the pipeline renders from the gateway-resolved v2 record
def _record(profile, **kw):
    reqs = cp.PROFILE_REQUIREMENTS.get(profile, {"requires_cmek": False, "requires_audit_logging": False})
    rec = {"source_trace_id": "t", "compliance_profile": profile, "is_regulated": profile != "STANDARD",
           "requires_cmek": reqs["requires_cmek"], "requires_audit_logging": reqs["requires_audit_logging"]}
    rec.update(kw)
    return rec


def test_pipeline_record_decides_and_the_workload_doc_is_not_read():
    """FD-4R RT F3: one decision per run. A stored product-keyed doc that says otherwise is not consulted."""
    db = _FakeDb({"compliance_decision": {"profile": "PCI_DSS", "profile_source": "EXPLICIT_REQUEST",
                                          "requested_profile": "PCI_DSS"}, "requested_compliance_profile": "PCI_DSS"})
    agent = _agent(db)
    rc = agent._resolve_regulated_controls("p", _record("HIPAA"))
    assert (rc.profile, rc.source, rc.cmek, rc.audit_logging) == ("HIPAA", cp.PROFILE_SOURCE_RECORD, True, True)
    assert agent._resolve_regulated_controls("p", _record("STANDARD")) is None
    assert db.reads == []


@pytest.mark.parametrize("record", [
    _record("STANDARD", is_regulated=True),                         # private ingress / domain restriction
    _record("HIPAA", requires_cmek=None, requires_audit_logging=None),   # pre-R-6 v1 record (no requires_*)
    {"source_trace_id": "t", "compliance_profile": "STANDARD"},
])
def test_pipeline_record_valid_shapes_are_accepted_unchanged(record):
    """Do No Harm: a consistent record (v2, or v1 without the requires_* fields) resolves; the input is not mutated."""
    before = dict(record)
    cp.controls_from_decision_record(record, "us-central1")
    assert record == before


@pytest.mark.parametrize("profile", [["HIPAA"], {"profile": "HIPAA"}, 7, 1.5, True])
def test_non_string_profile_is_a_typed_unknown_profile(profile):
    """Integration RT F2: a non-string profile in the record is COMPLIANCE_PROFILE_UNKNOWN (never a TypeError from an
    unhashable dict key), on the record path and the stored-doc path."""
    record = {"source_trace_id": "t", "compliance_profile": profile}
    with pytest.raises(cp.ComplianceRenderRefused) as e:
        cp.controls_from_decision_record(record, "us-central1")
    assert e.value.error_class == cp.COMPLIANCE_PROFILE_UNKNOWN
    with pytest.raises(cp.ComplianceRenderRefused) as e:
        cp.resolve_regulated_controls(profile, cp.PROFILE_SOURCE_DECISION, "us-central1")
    assert e.value.error_class == cp.COMPLIANCE_PROFILE_UNKNOWN
    with pytest.raises(DeveloperStageError) as e:
        _agent(None)._resolve_regulated_controls("p", record)
    assert e.value.error_class == "COMPLIANCE_PROFILE_UNKNOWN"


def test_string_profile_is_unchanged_by_the_type_guard():
    """Do No Harm for F2: a valid string profile resolves exactly as before."""
    rc = cp.resolve_regulated_controls("HIPAA", cp.PROFILE_SOURCE_DECISION, "us-central1")
    assert (rc.profile, rc.cmek, rc.audit_logging) == ("HIPAA", True, True)
    assert cp.resolve_regulated_controls("STANDARD", cp.PROFILE_SOURCE_DEFAULT, "us-central1") is None


@pytest.mark.parametrize("record, error_class", [
    (_record("STANDARD", requires_cmek=True), "COMPLIANCE_DECISION_UNAVAILABLE"),
    (_record("HIPAA", requires_audit_logging=False), "COMPLIANCE_DECISION_UNAVAILABLE"),
    (_record("PCI_DSS", is_regulated=False), "COMPLIANCE_DECISION_UNAVAILABLE"),
    (_record("SOC2"), "COMPLIANCE_PROFILE_UNKNOWN"),
    (_record(None), "COMPLIANCE_PROFILE_UNKNOWN"),
    (_record("EU_REGIONS_AND_SUPPORT"), "COMPLIANCE_REGION_NOT_ALLOWED"),
    ("HIPAA", "COMPLIANCE_DECISION_UNAVAILABLE"),
])
def test_pipeline_record_refusals_before_any_llm_call(record, error_class):
    agent = _agent(_FakeDb(None))

    class _NoLLM:
        def __getattr__(self, name):
            raise AssertionError(f"LLM client touched ({name}) after a compliance refusal")
    agent.genai_client = _NoLLM()
    with pytest.raises(DeveloperStageError) as e:
        agent.generate_code_files("p", "spec", [{"step_id": "S1"}], trace_id="t", compliance_decision=record,
                                  **INGRESS)
    assert e.value.error_class == error_class


@pytest.mark.parametrize("profile, regulated", [("STANDARD", False), ("HIPAA", True)])
def test_pipeline_record_renders_the_regulated_tree_end_to_end(profile, regulated):
    """The real developer assembly with the record the gateway passes (the stored doc says nothing)."""
    import functools
    from test_step1_s1b_generation import Client, _agent as _s1b_agent, _generate, _runtime
    agent = _s1b_agent(_runtime(Client()))
    agent.db = _FakeDbWithWrites(None)
    agent.generate_code_files = functools.partial(type(agent).generate_code_files, agent,
                                                  compliance_decision=_record(profile))
    files = _generate(agent, trace=f"trace-pr0b-record-{regulated}")
    main = files[W + "main.tf"]
    assert ('module "cmek" {' in main) is regulated
    assert ("enable_data_access_audit_logs = true" in main) is regulated


def test_gateway_passes_the_resolved_record_to_the_developer():
    """main.py: `_resolve_developer_compliance_decision` returns the record's regulated fields and
    `_execute_developer_logic` forwards them as `compliance_decision` (one record for ingress and controls)."""
    src = open(os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "main.py"), encoding="utf-8").read()
    import ast
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_execute_developer_logic")
    call = next(n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "generate_code_files")
    assert "compliance_decision" in {k.arg for k in call.keywords}


# ============================================================================== STANDARD: byte-identical renders
def standard_render_cases(te):
    """The platform renders a STANDARD workload gets (no `regulated` argument anywhere): main.tf per archetype (plain
    and with every optional input), variables.tf, and the HB-04 secondaries appended to custom.tf."""
    out = {}
    for arch in ("cloudrun", "gce-bastion", "gke-autopilot", "event-worker", "foundation-only", "unknown-archetype"):
        out[f"main:{arch}"] = te.generate_golden_main_tf("shop", arch, "")
        out[f"main:{arch}:full"] = te.generate_golden_main_tf(
            "shop_x", arch, "keep 2 warm instances", allow_unauthenticated=False, enable_direct_iap=True,
            authorized_invoker_members=["domain:example.com"], service_name="api",
            custom_tf_content='resource "google_compute_network" "vpc" {\n  name = "v"\n}\n',
            env_vars_override={"X_URL": '"https://x"'},
            scaling_override={"min_instances": 1, "max_instances": 3, "cpu_idle": False})
    out["variables"] = te.generate_golden_variables_tf("shop", "acme/shop")
    out["variables:private"] = te.generate_golden_variables_tf(
        "shop", "acme/shop", allow_unauthenticated=False, enable_direct_iap=True,
        authorized_invoker_members=["domain:example.com"])
    for arch, services in (("cloudrun", ["shop", "billing", "ledger"]), ("gke-autopilot", ["shop", "edge"])):
        files = {"infra/workload/main.tf": te.generate_golden_main_tf("shop", arch, ""), "infra/workload/custom.tf": ""}
        te.reconcile_multi_service_declarations(files, "shop", "", archetype=arch, target_services=services)
        out[f"reconcile:{arch}:custom.tf"] = files["infra/workload/custom.tf"]
        out[f"reconcile:{arch}:main.tf"] = files["infra/workload/main.tf"]
    # FD-4AT-c: the pins predate its two root additions (tests/fd4atc_render.py); everything else stays byte-identical.
    # IAP-GATE-KNOWN-MEMBER: a Direct IAP cloudrun render gained the root project-number data source and input line.
    # RT14-F1: a gce-bastion render gained the root zone read and the module's zone input.
    from iap_known_member_render import without_iap_known_member
    from rt14_bastion_zone_render import without_rt14_bastion_zone
    return {k: hashlib.sha256(without_fd4atc(pre_visible_rename(without_iap_known_member(without_rt14_bastion_zone(v))))
                              .encode("utf-8")).hexdigest()
            for k, v in sorted(out.items())}


# sha256 of standard_render_cases(te) with main 1202c76's terraform_engine (the pre-PR-0b renders).
PRE_PR0B_STANDARD_RENDER_SHA256 = {
    "main:cloudrun": "c4e22cb4e7bb2d3abc3afa0aaffa93121561aecad872b3779010fd84837380f7",
    "main:cloudrun:full": "0fa4679a38d825fc26e149089a7a5310d2335ae7a5df1403d9de147dc05166cb",
    "main:event-worker": "b54132d9121656965c75a61355cc38e77e6733c5a34577bcba83ef85a2516432",
    "main:event-worker:full": "b54132d9121656965c75a61355cc38e77e6733c5a34577bcba83ef85a2516432",
    "main:foundation-only": "a3f505aaee5b59fd69d92834e4271262b2c9a180cb49d898f489deafbeee1f1e",
    "main:foundation-only:full": "a3f505aaee5b59fd69d92834e4271262b2c9a180cb49d898f489deafbeee1f1e",
    "main:gce-bastion": "66c60e93f287ec4ffe48151c90f3b2624b8d906e4d3b44982d2cd43c466fdced",
    "main:gce-bastion:full": "66c60e93f287ec4ffe48151c90f3b2624b8d906e4d3b44982d2cd43c466fdced",
    "main:gke-autopilot": "45d1cc1ba016cb351385789245d9a86189367a085e20fa304f143614e276424e",
    "main:gke-autopilot:full": "fd1194ce4f84435cc3c087b144354d5506a918ced38740573d07dd98864745c9",
    "main:unknown-archetype": "ae2fb164b1f9aa0e7cf964fe3c750dbe1709e37363edb8909ca57e5d6dc53ce4",
    "main:unknown-archetype:full": "48af01e7de740f9cee91bb042443ccee2d18b98b35e64d7739b97664a2b7ed08",
    "reconcile:cloudrun:custom.tf": "3efb23815a35588a23a183f65ea04b5362f873446660a7c35d7a7dbf913a3127",
    "reconcile:cloudrun:main.tf": "c4e22cb4e7bb2d3abc3afa0aaffa93121561aecad872b3779010fd84837380f7",
    "reconcile:gke-autopilot:custom.tf": "975469fda8998da436cf00841e3de43e67718149295e63ff1c6db5f7616e0c4f",
    "reconcile:gke-autopilot:main.tf": "45d1cc1ba016cb351385789245d9a86189367a085e20fa304f143614e276424e",
    # SAT-02 / FD4BD-SENS (deliberate): the two variables renders gained exactly `sensitive   = true` on
    # oauth_client_secret and firebase_api_key (pre-change hashes 104d1b19... / 0eaffcbe..., re-derived by
    # tests/test_sat02_sensitive_platform_variables.py::test_engine_variables_change_is_exactly_the_two_sensitive_lines).
    "variables": "46b1e49702318c1f036ebef1912d010af0f98cd0be57182992d5da3ae79a6930",
    "variables:private": "cd5d80e9cbc8a79c314454ffd8ccd1aed9591c2472a6c081deeb015bf683012a",
}


def test_standard_renders_are_byte_identical_to_before_pr0b():
    assert standard_render_cases(te) == PRE_PR0B_STANDARD_RENDER_SHA256


def test_regulated_none_is_the_default_everywhere():
    for arch in ("cloudrun", "gke-autopilot", "event-worker", "foundation-only"):
        assert te.generate_golden_main_tf("shop", arch, "", regulated=None) == te.generate_golden_main_tf("shop", arch, "")
    vt = _worker_topology()
    assert tw.render_secondary_worker_block(vt, "worker", None, kms_key_reference=None) == \
        tw.render_secondary_worker_block(vt, "worker", None)


# ================================================================================ regulated renders
def test_regulated_cloudrun_main_tf_wires_the_key_and_audit_logging():
    main = te.generate_golden_main_tf("shop", "cloudrun", "", regulated=_hipaa())
    assert 'module "cmek" {\n  source                 = "../modules/security-kms"' in main
    assert 'rotation_period        = "7776000s"' in main and "location               = var.region" in main
    assert ('service_agent_services = ["artifactregistry.googleapis.com", "firestore.googleapis.com", '
            '"run.googleapis.com"]') in main
    # Owner Q2 = yes (10-18): the foundation also logs ADMIN_READ.
    assert ("  kms_key_name          = module.cmek.crypto_key_name\n  enable_data_access_audit_logs = true\n"
            '  data_access_log_types = ["ADMIN_READ", "DATA_READ", "DATA_WRITE"]\n}') in main
    assert "  encryption_key        = module.cmek.crypto_key_name\n\n  depends_on = [module.foundation]" in main
    assert "compliance profile HIPAA" in main


@pytest.mark.parametrize("arch, attr, agents", [
    ("event-worker", "  kms_key_name          = module.cmek.crypto_key_name\n",
     ["artifactregistry.googleapis.com", "firestore.googleapis.com", "pubsub.googleapis.com", "run.googleapis.com"]),
    ("gke-autopilot", "  database_encryption_key = module.cmek.crypto_key_name\n",
     ["artifactregistry.googleapis.com", "container.googleapis.com", "firestore.googleapis.com"]),
    ("foundation-only", None, ["artifactregistry.googleapis.com", "firestore.googleapis.com"]),
    ("gce-bastion", None, ["artifactregistry.googleapis.com", "firestore.googleapis.com"]),
    ("unknown-archetype", "  encryption_key        = module.cmek.crypto_key_name\n",
     ["artifactregistry.googleapis.com", "firestore.googleapis.com", "run.googleapis.com"]),
])
def test_regulated_archetypes(arch, attr, agents):
    main = te.generate_golden_main_tf("shop", arch, "", regulated=_hipaa())
    assert f"service_agent_services = {json.dumps(agents)}\n" in main
    assert te.cmek_service_agent_services(arch) == agents
    if attr:
        assert attr in main
    assert main.count("module.cmek.crypto_key_name") == (2 if attr else 1)


def test_service_agents_follow_the_platform_secondaries_by_exact_module_source():
    files = {W + "custom.tf": 'module "compute_edge" {\n  source = "../modules/compute-cloudrun"\n}\n'
                              'module "x" {\n  source = "../modules/compute-cloudrun-extra"\n}\n',
             W + "other.tf": 'module "w" {\n  source = "./modules/compute-event-worker/"\n}\n',
             "infra/modules/compute-gke-autopilot/main.tf": 'module "n" {\n  source = "../compute-cloudrun"\n}\n'}
    assert te.cmek_service_agent_services("gke-autopilot", files) == [
        "artifactregistry.googleapis.com", "container.googleapis.com", "firestore.googleapis.com",
        "pubsub.googleapis.com", "run.googleapis.com"]
    assert te.cmek_service_agent_services("gke-autopilot", {W + "custom.tf": "# no modules\n"}) == [
        "artifactregistry.googleapis.com", "container.googleapis.com", "firestore.googleapis.com"]


def test_regulated_secondaries_get_the_key():
    files = {W + "main.tf": te.generate_golden_main_tf("shop", "cloudrun", "", regulated=_hipaa()), W + "custom.tf": ""}
    te.reconcile_multi_service_declarations(files, "shop", "", archetype="cloudrun",
                                            target_services=["shop", "billing", "ledger"], regulated=_hipaa())
    custom = files[W + "custom.tf"]
    assert custom.count('source                = "../modules/compute-cloudrun"') == 2
    assert custom.count("  encryption_key        = module.cmek.crypto_key_name\n\n  depends_on") == 2
    std = {W + "main.tf": te.generate_golden_main_tf("shop", "cloudrun", ""), W + "custom.tf": ""}
    te.reconcile_multi_service_declarations(std, "shop", "", archetype="cloudrun",
                                            target_services=["shop", "billing", "ledger"])
    assert custom.replace("  encryption_key        = module.cmek.crypto_key_name\n", "") == std[W + "custom.tf"]


def _worker_topology():
    return types.SimpleNamespace(kind=lambda n: "event-worker", label=lambda n: f"compute_{n}",
                                 intent=types.SimpleNamespace(primary_service="web"))


def test_event_worker_secondary_gets_the_key():
    block = tw.render_secondary_worker_block(_worker_topology(), "worker", None, kms_key_reference=te.CMEK_KEY_REFERENCE)
    assert "  kms_key_name          = module.cmek.crypto_key_name\n\n  depends_on = [module.foundation]" in block
    assert block.replace("  kms_key_name          = module.cmek.crypto_key_name\n", "") == \
        tw.render_secondary_worker_block(_worker_topology(), "worker", None)


# ================================================================================ golden-module copies
def _payload_dict(path):
    import ast
    for n in ast.parse(open(os.path.join(REPO_ROOT, path)).read()).body:
        if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", "") == "BUILTIN_MODULE_FILES":
            return ast.literal_eval(n.value)
    raise AssertionError(f"{path}: no BUILTIN_MODULE_FILES")


def test_touched_modules_are_identical_in_every_copy():
    payloads = {p: _payload_dict(p) for p in PAYLOADS}
    for mod, fnames in TOUCHED_MODULES.items():
        for fname in fnames:
            src = open(os.path.join(REPO_ROOT, "infra", "modules", mod, fname)).read()
            assert open(os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", mod, fname)).read() == src
            for p, d in payloads.items():
                assert d[mod][fname] == src, (p, mod, fname)


def test_new_module_inputs_default_to_today():
    """Do No Harm at the module boundary: every PR-0b input defaults to 'nothing' (null / false / [])."""
    import hcl2
    want = {
        "security-kms/variables.tf": {"service_agent_services": [], "enable_apis": False, "protection_level": "SOFTWARE"},
        "workload-foundation/base/compliance.tf": {"kms_key_name": None, "enable_data_access_audit_logs": False,
                                                   "data_access_log_types": ["DATA_READ", "DATA_WRITE"]},
        "compute-cloudrun/variables.tf": {"encryption_key": None},
        "compute-event-worker/variables.tf": {"kms_key_name": None},
        "compute-gke-autopilot/variables.tf": {"database_encryption_key": None},
        "storage-bucket/variables.tf": {"kms_key_name": None},
        "messaging-pubsub/variables.tf": {"kms_key_name": None},
        "analytics-bigquery/variables.tf": {"kms_key_name": None},
        "cache-redis/variables.tf": {"kms_key_name": None},
        "database-cloudsql/variables.tf": {"kms_key_name": None},
    }
    for rel, names in want.items():
        parsed = hcl2.loads(open(os.path.join(REPO_ROOT, "infra", "modules", rel)).read())
        defaults = {}
        for block in parsed.get("variable") or []:
            for name, body in block.items():
                defaults[name] = body.get("default", "<required>")
        for name, default in names.items():
            assert defaults.get(name, "<missing>") == default, (rel, name, defaults.get(name, "<missing>"))


def test_compute_cloudrun_module_has_only_the_iap_service_identity():
    """The terraform server's apply-time compute-cloudrun healer strips a `google_project_service_identity` block
    named `iap_sa` from that module by text (service.py); PR-0b keeps every KMS service identity in security-kms.
    FD-4CS-b (proposed row) adds exactly one identity here, `iap_service_agent` (the IAP agent the module's own
    invoker binding names), which that healer does not target (tests/test_fd4cs_b_iap_service_agent.py and the
    deploy-workspace test in test_express_validate_end_to_end)."""
    import hcl2

    for root in ("infra/modules", "apps/control-center/infra/modules"):
        parsed = hcl2.loads(open(os.path.join(REPO_ROOT, root, "compute-cloudrun", "main.tf")).read())
        names = [name for block in parsed.get("resource", []) for name in block.get("google_project_service_identity", {})]
        assert names == ["iap_service_agent"], (root, names)


# ============================================================================ production column (real engine)
def _prod_column():
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column (tofu 1.9.0 + eval/.tofu-mirror-prod, untracked; or STACKVEND_PROD_TOFU / "
                    "STACKVEND_PROD_MIRROR) not present")
    from stackvend_eval.tofu_runner import verify_mirror_manifest
    status = verify_mirror_manifest(Path(PROD_MIRROR))["status"]
    if status != "verified":
        pytest.skip(f"production mirror not verified: {status}")


def _tree(archetype="cloudrun", profile=None, secondaries=None):
    reg = _hipaa(profile) if profile else None
    files = {}
    if secondaries:
        files = {W + "main.tf": te.generate_golden_main_tf("shop", archetype, "", regulated=reg), W + "custom.tf": ""}
        te.reconcile_multi_service_declarations(files, "shop", "", archetype=archetype, target_services=secondaries,
                                                regulated=reg)
        files = {k: v for k, v in files.items() if k.startswith(W) and k != W + "main.tf"}
    files[W + "main.tf"] = te.generate_golden_main_tf("shop", archetype, "", app_files=dict(files), regulated=reg)
    files[W + "variables.tf"] = te.generate_golden_variables_tf("shop", "acme/shop")
    files[W + "outputs.tf"] = te.generate_golden_outputs_tf("shop", archetype)
    te.vendor_terraform_modules(files, archetype)
    return files


def _sandboxed_tofu(tmp_path, tree, extra):
    """Writes `tree` (+ `extra` files, paths relative to infra/workload) and returns tofu(*args) for that root
    module: the production engine and mirror, offline (macOS sandbox denies outbound IP), env allowlist. Only
    init / validate / test / plan / show are ever run (never apply)."""
    _prod_column()
    if not os.path.exists(SANDBOX_EXEC):
        pytest.skip("sandbox-exec (macOS) unavailable: the engine only runs here with outbound network denied")
    root = tmp_path / "tree"
    for rel, text in tree.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    wd = root / "infra" / "workload"
    for rel, text in extra.items():
        (wd / rel).parent.mkdir(parents=True, exist_ok=True)
        (wd / rel).write_text(text)
    rc = tmp_path / "tofu.tfrc"
    rc.write_text('provider_installation {\n  filesystem_mirror {\n    path    = %s\n    include = ["*/*/*"]\n  }\n}\n'
                  % json.dumps(PROD_MIRROR))
    home = tmp_path / "home"
    home.mkdir()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TF_CLI_CONFIG_FILE": str(rc), "CHECKPOINT_DISABLE": "1",
           "TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}

    def tofu(*args):
        assert args[0] in ("init", "validate", "test", "plan", "show")
        r = subprocess.run([SANDBOX_EXEC, "-p", SANDBOX_PROFILE, PROD_TOFU, *args], cwd=str(wd), env=env,
                           capture_output=True, text=True, timeout=600)
        assert r.returncode == 0, (args[0], (r.stdout + r.stderr)[-3000:])
        return r.stdout
    tofu("init", "-backend=false", "-input=false", "-no-color")
    return tofu


# Plan-only `tofu test` with mock providers. The mocks pin the few computed values the provider validates at plan
# time (a mock's random string is not a service-account name / IAM member) and the key id the security-kms output
# precondition compares with its computed crypto_key_name.
MOCK_TEST = """mock_provider "google" {
  # FD-4AT RT F1/R1: the foundation's build-SA actAs grant takes the project number from the pool's resource name.
  mock_resource "google_iam_workload_identity_pool" {
    defaults = {
      name = "projects/123456789/locations/global/workloadIdentityPools/castor-gh-pool"
    }
  }
  mock_resource "google_kms_crypto_key" {
    defaults = {
      id = "%(key)s"
    }
  }
}

mock_provider "google-beta" {
  mock_resource "google_project_service_identity" {
    defaults = {
      email  = "service-1@gcp-sa-mock.iam.gserviceaccount.com"
      member = "serviceAccount:service-1@gcp-sa-mock.iam.gserviceaccount.com"
    }
  }
}

override_resource {
  target = module.foundation.google_service_account.github_deployer
  values = {
    name  = "projects/mock-proj/serviceAccounts/sa-gh-deployer@mock-proj.iam.gserviceaccount.com"
    email = "sa-gh-deployer@mock-proj.iam.gserviceaccount.com"
  }
}

# FD-4AT: the deployer's iam.serviceAccountUser is granted on the runtime SA (google_service_account_iam_member).
override_resource {
  target = module.foundation.google_service_account.workload_sa
  values = {
    name  = "projects/mock-proj/serviceAccounts/sa-shop@mock-proj.iam.gserviceaccount.com"
    email = "sa-shop@mock-proj.iam.gserviceaccount.com"
  }
}

run "plan" {
  command = plan
  variables {
    project_id = "mock-proj"
  }
}
"""


@pytest.mark.parametrize("archetype, profile, secondaries", [
    ("cloudrun", None, ["shop", "billing"]),
    ("cloudrun", "HIPAA", ["shop", "billing"]),
    ("event-worker", "CJIS", None),
    ("foundation-only", "PCI_DSS", None),
    ("gce-bastion", "FEDRAMP_MODERATE", None),
])
def test_validate_and_mock_provider_plan_on_the_production_column(tmp_path, archetype, profile, secondaries):
    """(GKE Autopilot is planned for real below: its module output indexes the computed master_auth[0] block, which
    an OpenTofu mock cannot supply.)"""
    tofu = _sandboxed_tofu(tmp_path, _tree(archetype, profile, secondaries),
                           {"pr0b_tests/plan.tftest.hcl": MOCK_TEST % {"key": KEY}})
    tofu("validate", "-no-color")
    out = tofu("test", "-test-directory=pr0b_tests", "-no-color")
    assert "1 passed, 0 failed" in out, out


OFFLINE_PROVIDERS = ('provider "google" {\n  access_token = "offline-test-token"\n}\n\n'
                     'provider "google-beta" {\n  access_token = "offline-test-token"\n}\n')


def _offline_plan_json(tmp_path, tree):
    """A REAL `tofu plan` with the production providers: offline, fake access token via an override file, no
    refresh, no backend, no state; `show -json` of the saved plan."""
    tofu = _sandboxed_tofu(tmp_path, tree, {"zz_offline_provider_override.tf": OFFLINE_PROVIDERS})
    tofu("validate", "-no-color")
    tofu("plan", "-input=false", "-no-color", "-refresh=false", "-lock=false", "-out=plan.bin",
         "-var", "project_id=mock-proj")
    return json.loads(tofu("show", "-json", "plan.bin"))


# ---- the gate: plan_gate.py when PR-0 is on the branch, else a strict replica of its CMEK / audit / region rules
REPLICA_CMEK_PATHS = {
    "google_storage_bucket": (("encryption", 0, "default_kms_key_name"),),
    "google_artifact_registry_repository": (("kms_key_name",),),
    "google_firestore_database": (("cmek_config", 0, "kms_key_name"),),
    "google_sql_database_instance": (("encryption_key_name",),),
    "google_bigquery_dataset": (("default_encryption_configuration", 0, "kms_key_name"),),
    "google_bigquery_table": (("encryption_configuration", 0, "kms_key_name"),),
    "google_pubsub_topic": (("kms_key_name",),),
    "google_compute_disk": (("disk_encryption_key", 0, "kms_key_self_link"),),
    "google_redis_instance": (("customer_managed_key",),),
    "google_container_cluster": (("database_encryption", 0, "key_name"),),
    "google_cloud_run_v2_service": (("template", 0, "encryption_key"),),
    "google_spanner_database": (("encryption_config", 0, "kms_key_name"),),
    "google_logging_project_bucket_config": (("cmek_settings", 0, "kms_key_name"),),
    "google_secret_manager_secret": (
        ("replication", 0, "auto", 0, "customer_managed_encryption", 0, "kms_key_name"),
        ("replication", 0, "user_managed", 0, "replicas", "*", "customer_managed_encryption", 0, "kms_key_name"),
    ),
}
REPLICA_AUDIT = ("google_project_iam_audit_config", "allServices", frozenset({"DATA_READ", "DATA_WRITE"}))
REPLICA_LOCATION_ATTRIBUTES = ("location", "region", "zone")


def _plan_gate():
    path = os.path.join(REPO_ROOT, "mcp-servers", "compliance", "plan_gate.py")
    return _load_by_path("pr0b_plan_gate", path) if os.path.exists(path) else None


def test_replica_rules_equal_the_plan_gate_when_present():
    pg = _plan_gate()
    if pg is None:
        pytest.skip("lane 14 PR-0 (mcp-servers/compliance/plan_gate.py) not on this branch yet")
    assert pg.CMEK_ATTRIBUTE_PATHS == REPLICA_CMEK_PATHS
    assert (pg.AUDIT_CONFIG_TYPE, pg.AUDIT_ALL_SERVICES, pg.AUDIT_REQUIRED_LOG_TYPES) == REPLICA_AUDIT
    assert tuple(pg.LOCATION_ATTRIBUTES) == REPLICA_LOCATION_ATTRIBUTES


def _is_kms_key_name(value):
    parts = value.split("/") if isinstance(value, str) else []
    return (len(parts) == 8 and (parts[0], parts[2], parts[4], parts[6]) == ("projects", "locations", "keyRings",
                                                                           "cryptoKeys") and all(parts[1::2]))


def _leaves(after, unknown, path):
    if not path:
        return [(after, unknown is True)]
    if unknown is True:
        return [(None, True)]
    step, rest = path[0], path[1:]
    if step == "*":
        items = after if isinstance(after, list) else []
        unk = unknown if isinstance(unknown, list) else []
        return [leaf for i, item in enumerate(items) for leaf in _leaves(item, unk[i] if i < len(unk) else None, rest)] \
            or [(None, False)]
    if isinstance(step, int):
        if not isinstance(after, list) or len(after) <= step:
            return [(None, isinstance(unknown, list) and len(unknown) > step and unknown[step] is True)]
        return _leaves(after[step], unknown[step] if isinstance(unknown, list) and len(unknown) > step else None, rest)
    return _leaves((after or {}).get(step) if isinstance(after, dict) else None,
                   unknown.get(step) if isinstance(unknown, dict) else None, rest)


def _replica_violations(plan, allowed_regions):
    """Stricter than the gate: a CMEK leaf or a location known only after apply is a violation (the gate may trace
    it); PR-0b's design makes every one of them known at plan time."""
    out = []
    changes = [rc for rc in plan.get("resource_changes") or []
               if rc.get("mode") == "managed" and rc["change"]["actions"] != ["delete"]]
    for rc in changes:
        after, unknown = rc["change"]["after"], rc["change"].get("after_unknown") or {}
        alts = REPLICA_CMEK_PATHS.get(rc["type"])
        if alts and not any(all((not unk) and _is_kms_key_name(v) for v, unk in _leaves(after, unknown, path))
                            for path in alts):
            out.append(("CMEK", rc["address"]))
        for attr in REPLICA_LOCATION_ATTRIBUTES:
            if unknown.get(attr) is True:
                out.append(("LOCATION_UNVERIFIABLE", rc["address"]))
            elif isinstance(after.get(attr), str) and after[attr]:
                loc = after[attr].lower()
                head, sep, tail = loc.rpartition("-")
                region = head if sep and len(tail) == 1 and tail.isalpha() and head in allowed_regions else loc
                if region != "global" and region not in allowed_regions:
                    out.append(("REGION", rc["address"], after[attr]))
    typ, svc, log_types = REPLICA_AUDIT
    if not any(rc["type"] == typ and rc["change"]["after"].get("service") == svc
               and log_types <= {c.get("log_type") for c in rc["change"]["after"].get("audit_log_config") or []}
               for rc in changes):
        out.append(("AUDIT_LOGGING_NOT_CONFIGURED",))
    return out


def _gate(plan, profile):
    """(decision, violations) of the PR-0 gate for `profile` (no ingress flags: this PR does not change ingress)."""
    pg = _plan_gate()
    reqs = dict(cp.PROFILE_REQUIREMENTS[profile], allowed_regions=list(cp.PROFILE_REQUIREMENTS[profile]["allowed_regions"]))
    if pg is not None:
        res = pg.evaluate_plan(plan, profile=profile, requirements=reqs, ingress={})
        return res["decision"], res["violations"]
    violations = _replica_violations(plan, set(reqs["allowed_regions"]))
    return ("VIOLATION" if violations else "PASS"), violations


def test_regulated_sample_workload_passes_the_plan_gate_on_a_real_plan(tmp_path):
    plan = _offline_plan_json(tmp_path, _tree("cloudrun", "HIPAA", ["shop", "billing"]))
    assert _gate(plan, "HIPAA") == ("PASS", [])
    by_addr = {rc["address"]: rc["change"]["after"] for rc in plan["resource_changes"]}
    assert by_addr["module.foundation.google_artifact_registry_repository.docker_repo"]["kms_key_name"] == KEY
    assert by_addr["module.foundation.google_firestore_database.database"]["cmek_config"] == [{"kms_key_name": KEY}]
    assert by_addr["module.compute.google_cloud_run_v2_service.app"]["template"][0]["encryption_key"] == KEY
    assert by_addr["module.compute_billing.google_cloud_run_v2_service.app"]["template"][0]["encryption_key"] == KEY
    assert by_addr["module.cmek.google_kms_crypto_key.key"]["rotation_period"] == "7776000s"
    assert by_addr["module.cmek.google_kms_key_ring.keyring"]["location"] == "us-central1"
    grants = {a: v for a, v in by_addr.items() if a.startswith("module.cmek.google_kms_crypto_key_iam_member.service_agents")}
    assert sorted(grants) == [f'module.cmek.google_kms_crypto_key_iam_member.service_agents["{s}"]' for s in (
        "artifactregistry.googleapis.com", "firestore.googleapis.com", "run.googleapis.com")]
    assert {v["role"] for v in grants.values()} == {"roles/cloudkms.cryptoKeyEncrypterDecrypter"}
    audit = by_addr["module.foundation.google_project_iam_audit_config.data_access[0]"]
    assert (audit["service"], sorted(c["log_type"] for c in audit["audit_log_config"])) == (
        "allServices", ["ADMIN_READ", "DATA_READ", "DATA_WRITE"])   # owner Q2 = yes (10-18)
    # the same plan under a profile whose regions exclude the platform region is refused (the gate is not loosened)
    assert _gate(plan, "EU_REGIONS_AND_SUPPORT")[0] == "VIOLATION"


@pytest.mark.parametrize("archetype, profile, secondaries", [
    ("event-worker", "CJIS", None),
    ("gke-autopilot", "FEDRAMP_HIGH", ["shop", "edge"]),
    ("foundation-only", "PCI_DSS", None),
    ("cloudrun", "FEDRAMP_MODERATE", None),
])
def test_every_platform_archetype_passes_the_plan_gate_when_regulated(tmp_path, archetype, profile, secondaries):
    plan = _offline_plan_json(tmp_path, _tree(archetype, profile, secondaries))
    assert _gate(plan, profile) == ("PASS", [])


def test_standard_workload_plan_has_no_cmek_kms_or_audit_resources(tmp_path):
    plan = _offline_plan_json(tmp_path, _tree("cloudrun", None, ["shop", "billing"]))
    types_ = {rc["type"] for rc in plan["resource_changes"]}
    assert not types_ & {"google_kms_key_ring", "google_kms_crypto_key", "google_kms_crypto_key_iam_member",
                         "google_project_service_identity", "google_project_iam_audit_config"}
    by_addr = {rc["address"]: rc["change"]["after"] for rc in plan["resource_changes"]}
    assert by_addr["module.foundation.google_artifact_registry_repository.docker_repo"].get("kms_key_name") is None
    assert by_addr["module.foundation.google_firestore_database.database"]["cmek_config"] == []
    assert by_addr["module.compute.google_cloud_run_v2_service.app"]["template"][0].get("encryption_key") is None
    # and a regulated gate refuses it exactly as before PR-0b (F1 of the PR-0 RT)
    assert _gate(plan, "HIPAA")[0] == "VIOLATION"


# ================================================================ RT F2: typed refusal class reaches the callback
@pytest.mark.parametrize("error_class", ["COMPLIANCE_REGION_NOT_ALLOWED", "COMPLIANCE_PROFILE_UNKNOWN",
                                         "LLM_UNAVAILABLE"])
def test_async_callback_carries_the_developer_stage_error_class(error_class):
    """Mutation checked: without `except DeveloperStageError` in run_developer_execute_in_background the payload has
    no error_class (the workflow then records CONTRACT_VIOLATION)."""
    from unittest.mock import patch
    from test_step1_typed_failures import _gateway_main
    gw = _gateway_main()
    sent = []
    req = gw.DeveloperExecuteRequest(product_id="shop", trace_id="trace-pr0b-f2",
                                     callback_url="https://workflowexecutions.googleapis.com/v1/x/callbacks/c")
    exc = DeveloperStageError(error_class, "refused before any LLM call")
    with patch.object(gw, "_execute_developer_logic", side_effect=exc), patch.object(gw, "db", None), \
            patch.object(gw.CallbackDeliveryClient, "send_callback", side_effect=lambda **kw: sent.append(kw["payload"])):
        with pytest.raises(DeveloperStageError):
            gw.run_developer_execute_in_background(req)
    assert len(sent) == 1
    assert sent[0]["status"] == "FAILED" and sent[0]["error"] == f"DeveloperStageError: {exc}"   # unchanged contract
    assert sent[0]["error_class"] == error_class


# ============================================== owner options Q1-Q3 (RT §6): code-ready, OFF by default, NOT decided
def test_owner_options_are_the_owner_decisions():
    """Pins the owner's decisions (10-18, register 73507f9): Q1 fail closed, Q2 ADMIN_READ on, Q3 HSM for FEDRAMP_HIGH
    and CJIS (report §6)."""
    assert cp.FAIL_CLOSED_ON_UNREADABLE_DECISION is True
    assert tuple(cp.AUDIT_LOG_TYPES) == ("ADMIN_READ", "DATA_READ", "DATA_WRITE")
    assert cp.HSM_PROFILES == frozenset({"FEDRAMP_HIGH", "CJIS"})
    for profile in cp.REGULATED_PROFILES - {"EU_REGIONS_AND_SUPPORT"}:
        rc = _hipaa(profile)
        hsm = profile in ("FEDRAMP_HIGH", "CJIS")
        assert (rc.protection_level, rc.audit_log_types) == (
            "HSM" if hsm else "SOFTWARE", ("ADMIN_READ", "DATA_READ", "DATA_WRITE"))
        main = te.generate_golden_main_tf("shop", "cloudrun", "", regulated=rc)
        assert ('protection_level       = "HSM"' in main) is hsm
        assert 'data_access_log_types = ["ADMIN_READ", "DATA_READ", "DATA_WRITE"]' in main


def test_owner_q1_fail_closed_refuses_an_unreadable_decision_before_the_llm(monkeypatch):
    monkeypatch.setattr(cp, "FAIL_CLOSED_ON_UNREADABLE_DECISION", True)
    # FD-7M-a: with this fake every read fails, so the dispatch's workload-region read (workloads/{pid}.region) would
    # stop first with REGION_UNAVAILABLE (also typed, also before the LLM). The region is given here so the compliance
    # read is the one under test.
    monkeypatch.setattr("developer_agent.handler.resolve_workload_region", lambda *_a, **_k: "us-central1")
    agent = _agent(_FakeDb(raises=RuntimeError("firestore down")))

    class _NoLLM:
        def __getattr__(self, name):
            raise AssertionError(f"LLM client touched ({name}) after a compliance refusal")
    agent.genai_client = _NoLLM()
    with pytest.raises(DeveloperStageError) as e:
        agent.generate_code_files("p", "spec", [{"step_id": "S1"}], trace_id="t", **INGRESS)
    assert e.value.error_class == "COMPLIANCE_DECISION_UNAVAILABLE"
    # a readable document is unaffected by the flag
    assert _agent(_FakeDb(None))._resolve_regulated_controls("p") is None


def test_owner_q2_q3_render_admin_read_and_hsm(monkeypatch):
    monkeypatch.setattr(cp, "AUDIT_LOG_TYPES", ("ADMIN_READ", "DATA_READ", "DATA_WRITE"))
    monkeypatch.setattr(cp, "HSM_PROFILES", frozenset({"FEDRAMP_HIGH", "CJIS"}))
    for profile, hsm in (("FEDRAMP_HIGH", True), ("CJIS", True), ("FEDRAMP_MODERATE", False), ("HIPAA", False)):
        main = te.generate_golden_main_tf("shop", "cloudrun", "", regulated=_hipaa(profile))
        assert ('  rotation_period        = "7776000s"\n  protection_level       = "HSM"\n' in main) is hsm
        assert '  data_access_log_types = ["ADMIN_READ", "DATA_READ", "DATA_WRITE"]\n}' in main


def test_owner_q2_q3_real_plan_still_passes_the_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "AUDIT_LOG_TYPES", ("ADMIN_READ", "DATA_READ", "DATA_WRITE"))
    monkeypatch.setattr(cp, "HSM_PROFILES", frozenset({"FEDRAMP_HIGH", "CJIS"}))
    plan = _offline_plan_json(tmp_path, _tree("cloudrun", "FEDRAMP_HIGH", ["shop", "billing"]))
    assert _gate(plan, "FEDRAMP_HIGH") == ("PASS", [])
    by_addr = {rc["address"]: rc["change"]["after"] for rc in plan["resource_changes"]}
    assert by_addr["module.cmek.google_kms_crypto_key.key"]["version_template"] == [
        {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protection_level": "HSM"}]
    audit = by_addr["module.foundation.google_project_iam_audit_config.data_access[0]"]
    assert sorted(c["log_type"] for c in audit["audit_log_config"]) == ["ADMIN_READ", "DATA_READ", "DATA_WRITE"]


def test_default_key_is_software_protected_on_a_real_plan(tmp_path):
    """Owner Q3 = yes (10-18): FEDRAMP_HIGH / CJIS keys are HSM; every other regulated profile stays SOFTWARE."""
    plan = _offline_plan_json(tmp_path, _tree("cloudrun", "HIPAA", None))
    by_addr = {rc["address"]: rc["change"]["after"] for rc in plan["resource_changes"]}
    assert by_addr["module.cmek.google_kms_crypto_key.key"].get("version_template") in (None, [])
    plan = _offline_plan_json(tmp_path / "fh", _tree("cloudrun", "FEDRAMP_HIGH", None))
    by_addr = {rc["address"]: rc["change"]["after"] for rc in plan["resource_changes"]}
    assert by_addr["module.cmek.google_kms_crypto_key.key"].get("version_template") == [
        {"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protection_level": "HSM"}]

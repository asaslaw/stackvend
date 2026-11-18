"""FD-4I remainder (Wave 2 lane 19: L19-2 developer site, L19-8 compliance part, L19-12 vending, L19-5a golden
compute module, tf-applier widening deletions). Plan: docs/planning/wave2-lane19-generated-app-security-plan.md §2.1,
§3, §10. Report: docs/handoff/fd-4i-tenant-authz-report.md.

Owner policy: deny by default; exact enums; no guessed principals (none -> typed failure, operator / HITL); no
widening to allAuthenticatedUsers; spec text never decides who may reach a workload. Every negative here is a
Do-No-Harm or fail-closed case; the module tests run plan-only `tofu test` against mock providers (no GCP).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
for p in (GATEWAY, os.path.dirname(__file__), os.path.join(REPO, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

from _lane19_fake_genai import FakeGenaiClient, canned_workload_files  # noqa: E402
from developer_agent.access_resolution import (  # noqa: E402
    SOURCE_COMPLIANCE_FLAGS, SOURCE_REQUEST, SOURCE_WORKLOAD_RECORD, resolve_access)
from developer_agent.errors import (  # noqa: E402
    ACCESS_COMPLIANCE_CONFLICT, ACCESS_ERROR_CLASSES, ACCESS_ORG_POLICY_CONFLICT, ACCESS_POLICY_INCOMPLETE, ACCESS_POLICY_INVALID,
    ACCESS_POLICY_REQUIRED, ACCESS_POLICY_UNAVAILABLE, DeveloperStageError)
from developer_agent.handler import DeveloperAgent  # noqa: E402
from shared.access_policy import AccessMode, PlatformRole, parse_platform_role  # noqa: E402

PUBLIC = {"mode": "PUBLIC_APP", "sign_in": {"google": "BYO"}, "tenant_isolation_required": True, "source": "intake"}
IAP = {"mode": "PRIVATE_IAP", "invoker_principals": ["group:staff@example.com", "user:ops@example.com"],
       "app_admin_emails": ["ops@example.com"], "sign_in": {"google": "DISABLED"}, "source": "intake"}
IAM = {"mode": "PRIVATE_IAM", "invoker_principals": ["serviceAccount:caller@p.iam.gserviceaccount.com"],
       "sign_in": {"google": "DISABLED"}, "source": "operator_hitl"}
TFVARS = "infra/workload/terraform.tfvars"


# ============================================================================ 1. resolve_access (pure, no I/O)
def _err(**kw):
    with pytest.raises(DeveloperStageError) as ei:
        resolve_access(**kw)
    return ei.value.error_class


def test_record_modes_map_exactly():
    pub = resolve_access(access=PUBLIC)
    assert (pub.mode, pub.allow_unauthenticated, pub.enable_direct_iap, pub.invoker_members) == \
        (AccessMode.PUBLIC_APP, True, False, ())
    iap = resolve_access(access=IAP)
    assert (iap.mode, iap.allow_unauthenticated, iap.enable_direct_iap) == (AccessMode.PRIVATE_IAP, False, True)
    assert iap.invoker_members == ("group:staff@example.com", "user:ops@example.com")
    assert iap.app_admin_emails == ("ops@example.com",) and iap.source == SOURCE_REQUEST
    iam = resolve_access(workload_access=IAM)
    assert (iam.mode, iam.allow_unauthenticated, iam.enable_direct_iap) == (AccessMode.PRIVATE_IAM, False, False)
    assert iam.source == SOURCE_WORKLOAD_RECORD


def test_request_access_wins_over_the_workload_record_and_the_flags():
    r = resolve_access(access=IAP, workload_access=PUBLIC, allow_unauthenticated=True, enable_direct_iap=False)
    assert r.mode == AccessMode.PRIVATE_IAP and r.source == SOURCE_REQUEST


@pytest.mark.parametrize("mode", ["PRIVATE_IAP", "PRIVATE_IAM"])
def test_private_record_without_principals_is_incomplete(mode):
    rec = {"mode": mode, "sign_in": {"google": "DISABLED"}, "source": "intake"}
    assert _err(access=rec) == ACCESS_POLICY_INCOMPLETE
    assert _err(workload_access=rec) == ACCESS_POLICY_INCOMPLETE


@pytest.mark.parametrize("flags", [
    {"enable_direct_iap": True},
    {"enable_direct_iap": True, "allow_unauthenticated": True},   # IAP wins over the public flag, as before
    {"allow_unauthenticated": False},
    {"allow_unauthenticated": False, "enable_direct_iap": False},
])
def test_compliance_flags_give_a_private_mode_but_never_principals(flags):
    assert _err(**flags) == ACCESS_POLICY_INCOMPLETE


def test_public_compliance_flag_is_public_with_no_members():
    r = resolve_access(allow_unauthenticated=True, enable_direct_iap=False)
    assert r.mode == AccessMode.PUBLIC_APP and r.invoker_members == () and r.source == SOURCE_COMPLIANCE_FLAGS


@pytest.mark.parametrize("flags", [{}, {"enable_direct_iap": False}, {"domain_restricted_sharing": False}])
def test_no_record_and_no_typed_decision_is_required(flags):
    assert _err(**flags) == ACCESS_POLICY_REQUIRED


@pytest.mark.parametrize("bad", [
    {**IAP, "invoker_principals": ["allAuthenticatedUsers"]},
    {**IAP, "invoker_principals": ["domain:allAuthenticatedUsers"]},
    {**IAP, "invoker_principals": ["allUsers"]},
    {**IAP, "invoker_principals": ["C0xyz789"]},
    {**IAP, "invoker_principals": ["alice@example.com"]},          # unprefixed: never auto-prefixed
    {**IAP, "invoker_principals": ["projectOwner:p"]},
    {**IAP, "sign_in": {"google": "SHARED_PLATFORM_CLIENT"}},       # rows 42/46
    {**PUBLIC, "tenant_isolation_required": None},                 # A8 / row 45
    {**IAP, "extra_field": 1},
    "PRIVATE_IAP", ["user:a@example.com"], 7,
])
def test_invalid_record_is_access_policy_invalid(bad):
    assert _err(access=bad) == ACCESS_POLICY_INVALID
    assert _err(workload_access=bad) == ACCESS_POLICY_INVALID


@pytest.mark.parametrize("kw", [{"access": PUBLIC}, {"workload_access": PUBLIC}, {"allow_unauthenticated": True}])
def test_public_under_domain_restricted_sharing_is_an_org_policy_conflict(kw):
    assert _err(domain_restricted_sharing=True, **kw) == ACCESS_ORG_POLICY_CONFLICT


@pytest.mark.parametrize("src", ["access", "workload_access"])
@pytest.mark.parametrize("flags", [
    {"enable_direct_iap": True},
    {"allow_unauthenticated": False},
    {"enable_direct_iap": True, "allow_unauthenticated": True},
    {"enable_direct_iap": False, "allow_unauthenticated": False},
])
def test_public_record_under_a_private_compliance_decision_is_a_conflict(src, flags):
    """L19-11 RT F5: most restrictive wins; a PUBLIC_APP record never overrides a private compliance decision."""
    assert _err(**{src: PUBLIC}, **flags) == ACCESS_COMPLIANCE_CONFLICT


@pytest.mark.parametrize("flags", [{}, {"allow_unauthenticated": True}, {"allow_unauthenticated": True,
                                                                          "enable_direct_iap": False}])
def test_public_record_under_a_public_or_absent_decision_is_unchanged(flags):
    """F5 negative: no contradiction -> exactly the record (Do No Harm)."""
    r = resolve_access(workload_access=PUBLIC, **flags)
    assert (r.mode, r.source, r.invoker_members) == (AccessMode.PUBLIC_APP, SOURCE_WORKLOAD_RECORD, ())


@pytest.mark.parametrize("rec", [IAP, IAM])
@pytest.mark.parametrize("flags", [{"allow_unauthenticated": True, "enable_direct_iap": False},
                                   {"enable_direct_iap": True}, {"allow_unauthenticated": False}])
def test_private_record_is_used_as_is_whatever_the_decision(rec, flags):
    """F5: a private record is at least as restrictive as any decision; it is used as recorded."""
    r = resolve_access(workload_access=rec, **flags)
    assert r.mode == AccessMode(rec["mode"]) and r.invoker_members == tuple(rec["invoker_principals"])


def test_private_mode_under_domain_restricted_sharing_is_fine():
    assert resolve_access(access=IAP, domain_restricted_sharing=True).mode == AccessMode.PRIVATE_IAP


def test_mode_strings_are_the_access_policy_enum_values():
    from developer_agent import access_resolution as ar
    assert ar.MODES == {m.value for m in AccessMode}
    assert (ar.PUBLIC_APP, ar.PRIVATE_IAM, ar.PRIVATE_IAP) == ("PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP")


def test_record_without_the_model_in_the_image_fails_closed(monkeypatch):
    """Before lane 12 vendoring, a record is refused (ACCESS_POLICY_UNAVAILABLE), never ignored; no record -> flags."""
    monkeypatch.setitem(sys.modules, "shared.access_policy", None)  # `from shared.access_policy import` -> ImportError
    assert _err(access=IAP) == ACCESS_POLICY_UNAVAILABLE
    assert _err(workload_access=PUBLIC, allow_unauthenticated=True) == ACCESS_POLICY_UNAVAILABLE
    assert resolve_access(allow_unauthenticated=True).mode == "PUBLIC_APP"


def test_access_resolution_imports_the_model_only_to_validate_a_record():
    tree = ast.parse(_src("apps/orchestrator-gateway/developer_agent/access_resolution.py"))
    top = [n for n in tree.body if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("shared")]
    assert top == []  # module level: nothing from shared (the gateway image has no access_policy copy yet)


def test_access_error_classes_are_exact_and_registered():
    assert ACCESS_ERROR_CLASSES == {ACCESS_POLICY_INCOMPLETE, ACCESS_POLICY_INVALID, ACCESS_POLICY_REQUIRED,
                                    ACCESS_POLICY_UNAVAILABLE, ACCESS_ORG_POLICY_CONFLICT, ACCESS_COMPLIANCE_CONFLICT,
                                    "ACCESS_WIDENING_UNAPPROVED"}  # L19-F4
    for cls in ACCESS_ERROR_CLASSES:
        assert DeveloperStageError(cls).error_class == cls
    with pytest.raises(ValueError):
        DeveloperStageError("ACCESS_SOMETHING_ELSE")


# ============================================================================ 2. generate_code_files wiring
class _ExplodingModels:
    def __init__(self):
        self.calls = []

    def generate_content(self, *a, **k):
        self.calls.append(1)
        raise AssertionError("no LLM call may happen before the access policy is resolved")


@pytest.fixture
def agent(monkeypatch):
    monkeypatch.setenv("ENABLE_DEVELOPER_SWARM", "false")
    for k in ("K_SERVICE", "PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    from google.cloud import firestore

    def _no_firestore(*a, **k):  # never even attempt a real client (FD-08 ratchet); code paths degrade to no-db
        raise RuntimeError("no Firestore in this test")
    monkeypatch.setattr(firestore, "Client", _no_firestore)
    a = DeveloperAgent()  # no project id: no Vertex client either
    assert a.db is None and a.project_id == ""
    return a


def _gen(agent, pid="authzapp", spec="An internal app", files=None, **kw):
    # FD-4R R-6 (integration): the developer is always called with the three compliance flags (the gateway resolves
    # them from the persisted decision); a test's own value wins, the rest is a plain public decision.
    kw.setdefault("allow_unauthenticated", True)
    kw.setdefault("enable_direct_iap", False)
    kw.setdefault("domain_restricted_sharing", False)
    if agent.genai_client is None:
        agent.genai_client = FakeGenaiClient(files=files or canned_workload_files(pid))
    with patch.object(agent, "fetch_existing_repo_files", return_value={}):
        return agent.generate_code_files(product_id=pid, spec_text=spec, task_dag=[], **kw)


def _workload_text(files):
    """Workload files (not the platform-owned golden modules, whose validation rule names the forbidden members)."""
    return "\n".join(v for p, v in files.items() if isinstance(v, str) and not p.startswith("infra/modules/"))


@pytest.mark.parametrize("kw", [
    {"enable_direct_iap": True},
    {"allow_unauthenticated": False},
    {"access": {"mode": "PRIVATE_IAP", "sign_in": {"google": "DISABLED"}, "source": "intake"}},
    {"enable_direct_iap": True, "allowed_domains": ["example.com", "C0xyz789", "allAuthenticatedUsers"]},
])
def test_private_without_principals_stops_before_any_llm_call(agent, kw):
    models = _ExplodingModels()
    agent.genai_client = SimpleNamespace(models=models)
    with pytest.raises(DeveloperStageError) as ei:
        _gen(agent, **kw)
    assert ei.value.error_class == ACCESS_POLICY_INCOMPLETE
    assert models.calls == []


@pytest.mark.parametrize("flags", [{"enable_direct_iap": True}, {"allow_unauthenticated": False}])
def test_public_record_vs_private_decision_stops_before_any_llm_call(agent, flags):
    models = _ExplodingModels()
    agent.genai_client = SimpleNamespace(models=models)
    with pytest.raises(DeveloperStageError) as ei:
        _gen(agent, access=PUBLIC, **flags)
    assert ei.value.error_class == ACCESS_COMPLIANCE_CONFLICT and models.calls == []


def test_no_typed_decision_stops_before_any_llm_call(agent):
    """Integration with FD-4R R-6: without the compliance decision the developer stops at R-6's
    COMPLIANCE_DECISION_MISSING (it runs first); the access resolution's own ACCESS_POLICY_REQUIRED is pinned on
    `_resolve_run_access` below."""
    from gate_errors import GateUnavailableError
    models = _ExplodingModels()
    agent.genai_client = SimpleNamespace(models=models)
    with patch.object(agent, "fetch_existing_repo_files", return_value={}), \
            pytest.raises(GateUnavailableError) as ei:
        agent.generate_code_files(product_id="authzapp", task_dag=[],
                                  spec_text="internal portal with IAP, corporate SSO, domain-restricted, restrict access")
    assert ei.value.reason == "COMPLIANCE_DECISION_MISSING" and models.calls == []
    with pytest.raises(DeveloperStageError) as ei2:
        agent._resolve_run_access("authzapp", None, [], None, None, None, None, [])
    assert ei2.value.error_class == ACCESS_POLICY_REQUIRED


def test_keyword_spec_with_a_public_decision_stays_public(agent):
    """I12 tombstone: IAP / SSO / domain-restricted words in the spec have no effect on ingress."""
    spec = ("internal portal protected with IAP and identity platform, corporate sso, domain-restricted sharing, "
            "restrict access, do not allow unauthenticated browser login")
    files = _gen(agent, spec=spec, allow_unauthenticated=True, enable_direct_iap=False)
    tfvars = files.get(TFVARS, "")
    assert "enable_direct_iap" not in tfvars
    assert "allow_unauthenticated      = false" not in tfvars
    assert "authorized_invoker_members" not in tfvars


def test_task_dag_contents_are_never_read_for_ingress(agent):
    # The substring scan (`"direct-iap" in str(t)`) is deleted (lane 19), and with FD-4R R-6 (integration) the
    # compliance-injected step id is not read either: the IAP flag comes only from the gateway-resolved decision.
    for dag in ([{"step_id": "STEP-09-DOCS", "title": "Document the direct-iap setup"}],
                [{"step_id": "STEP-03D-DIRECT-IAP", "title": "Direct IAP"}]):
        agent.genai_client = FakeGenaiClient(files=canned_workload_files("authzapp"))
        with patch.object(agent, "fetch_existing_repo_files", return_value={}):
            files = agent.generate_code_files(product_id="authzapp", spec_text="x", task_dag=dag,
                                              allow_unauthenticated=True, enable_direct_iap=False,
                                              domain_restricted_sharing=False)
        assert "enable_direct_iap" not in files.get(TFVARS, "")


@pytest.mark.parametrize("record,iap,members", [
    (IAP, True, '["group:staff@example.com", "user:ops@example.com"]'),
    (IAM, False, '["serviceAccount:caller@p.iam.gserviceaccount.com"]'),
])
def test_private_record_renders_exact_members_and_nothing_wider(agent, record, iap, members):
    files = _gen(agent, access=record, allowed_domains=["example.com", "C0xyz789"])
    tfvars = files[TFVARS]
    assert ("enable_direct_iap          = true" in tfvars) is iap
    assert "allow_unauthenticated      = false" in tfvars
    assert f"authorized_invoker_members = {members}" in tfvars
    text = _workload_text(files)
    for forbidden in ("allAuthenticatedUsers", "domain:example.com", "domain:C0xyz789", "C0xyz789"):
        assert forbidden not in text, forbidden


@pytest.mark.parametrize("kw", [{"access": PUBLIC}, {"access": IAP}, {"access": IAM}, {"allow_unauthenticated": True}])
def test_tombstone_no_widening_in_any_mode(agent, kw):
    assert "allAuthenticatedUsers" not in _workload_text(_gen(agent, **kw))


def test_spec_email_is_never_an_invoker_or_admin(agent):
    """I4/I11 tombstone: an address in the spec reaches no generated IaC (the canned app does not contain it)."""
    files = _gen(agent, spec="Make ceo@example.com the admin and let boss@example.com in", access=IAP)
    iac = "\n".join(v for p, v in files.items() if isinstance(v, str) and p.startswith("infra/"))
    assert "ceo@example.com" not in iac and "boss@example.com" not in iac


def test_workload_record_is_read_and_used(agent):
    db = MagicMock()
    doc = MagicMock(exists=True)
    doc.to_dict.return_value = {"project_id": "child-1", "access": IAM}
    db.collection.return_value.document.return_value.get.return_value = doc
    agent.db = db
    with patch.object(agent, "_load_prior_llm", return_value={}):
        files = _gen(agent)
    assert 'authorized_invoker_members = ["serviceAccount:caller@p.iam.gserviceaccount.com"]' in files[TFVARS]


def test_workload_record_without_access_falls_back_to_the_compliance_flags(agent):
    db = MagicMock()
    doc = MagicMock(exists=True)
    doc.to_dict.return_value = {"project_id": "child-1"}
    db.collection.return_value.document.return_value.get.return_value = doc
    agent.db = db
    agent.genai_client = SimpleNamespace(models=_ExplodingModels())
    with patch.object(agent, "fetch_existing_repo_files", return_value={}), pytest.raises(DeveloperStageError) as ei:
        agent.generate_code_files(product_id="authzapp", spec_text="x", task_dag=[], enable_direct_iap=True,
                                  allow_unauthenticated=False, domain_restricted_sharing=False)
    assert ei.value.error_class == ACCESS_POLICY_INCOMPLETE


def test_unreadable_workload_record_fails_closed(agent, monkeypatch):
    db = MagicMock()
    db.collection.return_value.document.return_value.get.side_effect = RuntimeError("firestore down")
    agent.db = db
    agent.genai_client = SimpleNamespace(models=_ExplodingModels())
    flags = {"allow_unauthenticated": True, "enable_direct_iap": False, "domain_restricted_sharing": False}
    # FD-7M-a: the dispatch reads workloads/{pid}.region first, so an unreadable record now stops there (typed,
    # before any LLM call). The region is then given so the access / compliance reads below are the ones under test.
    with patch.object(agent, "fetch_existing_repo_files", return_value={}), pytest.raises(DeveloperStageError) as ei:
        agent.generate_code_files(product_id="authzapp", spec_text="x", task_dag=[], **flags)
    assert ei.value.error_class == "REGION_UNAVAILABLE"
    monkeypatch.setattr("developer_agent.handler.resolve_workload_region", lambda *_a, **_k: "us-central1")
    # Pipeline shape (integration): the regulated controls come from the gateway-resolved compliance record, so the
    # unreadable workloads/{pid} is met by the access-record read.
    record = {"source_trace_id": "t", "compliance_profile": "STANDARD", "is_regulated": False,
              "requires_cmek": False, "requires_audit_logging": False}
    with patch.object(agent, "fetch_existing_repo_files", return_value={}), pytest.raises(DeveloperStageError) as ei:
        agent.generate_code_files(product_id="authzapp", spec_text="x", task_dag=[], compliance_decision=record,
                                  **flags)
    assert ei.value.error_class == ACCESS_POLICY_UNAVAILABLE
    # Direct caller without a record: the PR-0b compliance-profile read meets it first (owner Q1 = fail closed).
    with patch.object(agent, "fetch_existing_repo_files", return_value={}), pytest.raises(DeveloperStageError) as ei:
        agent.generate_code_files(product_id="authzapp", spec_text="x", task_dag=[], **flags)
    assert ei.value.error_class == "COMPLIANCE_DECISION_UNAVAILABLE"


def test_no_firestore_client_on_cloud_run_fails_closed(agent, monkeypatch):
    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    agent.genai_client = SimpleNamespace(models=_ExplodingModels())
    with patch.object(agent, "fetch_existing_repo_files", return_value={}), pytest.raises(DeveloperStageError) as ei:
        agent.generate_code_files(product_id="authzapp", spec_text="x", task_dag=[], allow_unauthenticated=True,
                                  enable_direct_iap=False, domain_restricted_sharing=False)
    assert ei.value.error_class == ACCESS_POLICY_UNAVAILABLE


def test_request_access_wins_over_the_stored_record(agent):
    """L19-F4 RT R3: with a client the workload doc is read also for a request `access` (for the pending-widening
    flag), but the request record stays the source; an unreadable doc is a typed stop (fail closed)."""
    db = MagicMock()
    db.collection.return_value.document.return_value.get.return_value = SimpleNamespace(
        exists=True, to_dict=lambda: {"access": IAM})  # re-check N5: NARROWER stored record, another member
    agent.db = db
    resolved, drs, allowed = agent._resolve_run_access("authzapp", None, [], IAP, None, None, None, ["C0xyz789"])
    assert resolved.mode == AccessMode.PRIVATE_IAP and resolved.source == SOURCE_REQUEST
    assert resolved.invoker_members == ("group:staff@example.com", "user:ops@example.com")  # exactly the request's
    assert drs is False and allowed == ["C0xyz789"]  # passed through, never turned into members
    assert "domain:C0xyz789" not in resolved.invoker_members
    db.collection.return_value.document.return_value.get.side_effect = RuntimeError("firestore down")
    with pytest.raises(DeveloperStageError) as ei:
        agent._resolve_run_access("authzapp", None, [], IAP, None, None, None, ["C0xyz789"])
    assert ei.value.error_class == ACCESS_POLICY_UNAVAILABLE
    agent.db = None  # no client (eval harness): the request record resolves without any read
    assert agent._resolve_run_access("authzapp", None, [], IAP, None, None, None, [])[0].source == SOURCE_REQUEST


def test_developer_request_model_carries_access():
    import importlib
    src = Path(GATEWAY, "main.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "DeveloperExecuteRequest")
    fields = {t.target.id for t in cls.body if isinstance(t, ast.AnnAssign)}
    assert "access" in fields
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "generate_code_files")
    assert any(k.arg == "access" for k in call.keywords)
    assert importlib.util.find_spec("shared.access_policy") is not None


# ============================================================================ 3. tombstones (code)
def _src(rel):
    return Path(REPO, rel).read_text(encoding="utf-8")


@pytest.mark.parametrize("rel,cls", [
    ("apps/orchestrator-gateway/developer_agent/handler.py", "DeveloperAgent"),
    ("apps/orchestrator-gateway/compliance_agent/handler.py", "ComplianceAgentHandler"),
    ("apps/project-vending/vending.py", "ProjectRepoVendingEngine"),
])
def test_guessed_principal_collector_is_gone(rel, cls):
    tree = ast.parse(_src(rel))
    klass = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == cls)
    names = {n.name for n in klass.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert "get_admin_and_creator_members" not in names


def _string_constants(rel):
    return [n.value for n in ast.walk(ast.parse(_src(rel))) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


@pytest.mark.parametrize("rel", ["apps/orchestrator-gateway/developer_agent/handler.py",
                                 "apps/orchestrator-gateway/developer_agent/access_resolution.py",
                                 "apps/orchestrator-gateway/compliance_agent/handler.py",
                                 "apps/project-vending/vending.py"])
def test_no_admin_substring_role_check_and_no_widening_literal(rel):
    tree = ast.parse(_src(rel))
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            left = node.left
            assert not (isinstance(left, ast.Constant) and left.value == "ADMIN"), f"{rel}: `\"ADMIN\" in ...`"
    # The literal may appear in comments / docstrings, never as a value the code can emit.
    code_values = [v for v in _string_constants(rel) if v == "allAuthenticatedUsers" or v == ["allAuthenticatedUsers"]]
    assert code_values == [], rel


def test_developer_has_no_spec_keyword_ingress_inference():
    src = _src("apps/orchestrator-gateway/developer_agent/handler.py")
    for gone in ("iap_keywords", '"identity-aware proxy"', '"corporate sso"', '"domain-restricted"',
                 '"allowedpolicymemberdomains"', '"direct-iap" in str(t)'):
        assert gone not in src, gone


def test_tf_applier_service_name_widening_rule_is_gone():
    src = _src("mcp-servers/terraform/service.py")
    assert '("storefront", "frontend", "ui", "web", "portal")' not in src
    assert "'allow_unauthenticated = true'," not in src


# ============================================================================ 4. vending (L19-12)
# In tests/test_vending_multi_admin.py (that module owns the vending import and its stubs).


# ============================================================================ 5. compliance (L19-8 part)
def test_compliance_private_decision_adds_no_principals(monkeypatch):
    from compliance_agent import handler as ch
    from compliance_agent.schemas import ComplianceAuditRequest
    for k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GEMINI_API_KEY", "K_SERVICE", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ADMIN_USER_EMAIL", "env@example.com")
    h = ch.ComplianceAgentHandler(mode="inprocess", require_remote_engine=False)
    h.genai_client = None
    monkeypatch.setattr(h, "_persist_audit_record", lambda *a, **k: None)
    monkeypatch.setattr(h, "_determine_approval_requirement", lambda c: c)
    decision = {"profile": "STANDARD", "enable_direct_iap": True, "allow_unauthenticated": False,
                "domain_restricted_sharing": False, "allowed_domains": [], "mandated_tasks": [],
                "policy_matrix": {"has_constraints": False}}
    monkeypatch.setattr(h, "_fetch_compliance_decision", lambda **k: dict(decision))
    res = h.audit_and_enrich(ComplianceAuditRequest(product_id="p1", spec_text="internal IAP portal",
                                                    task_dag=[{"step_id": "STEP-01"}], trace_id="t1"))
    assert res.enable_direct_iap is True and res.allow_unauthenticated is False
    assert res.allowed_domains == []


# ============================================================================ 6. golden compute-cloudrun (L19-5a)
MODULE_TREES = ["infra/modules", "apps/control-center/infra/modules"]
PAYLOAD_DIRS = ["shared", "apps/orchestrator-gateway/shared", "apps/control-center/shared", "mcp-servers/terraform/shared"]
PROD_TOFU = os.path.join(REPO, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO, "eval", ".tofu-mirror-prod")


def _payload(rel_dir):
    ns = {}
    rel = os.path.join(rel_dir, "builtin_modules_payload.py")
    exec(compile(Path(REPO, rel).read_text(encoding="utf-8"), rel, "exec"), ns)  # noqa: S102 - repo-owned data
    return ns["BUILTIN_MODULE_FILES"]


@pytest.mark.parametrize("rel_dir", PAYLOAD_DIRS)
def test_compute_cloudrun_payload_equals_disk(rel_dir):
    payload = _payload(rel_dir)["compute-cloudrun"]
    disk = Path(REPO, "infra/modules/compute-cloudrun")
    assert set(payload) == {f.name for f in disk.iterdir() if f.suffix == ".tf"}
    for fn, text in payload.items():
        assert text == (disk / fn).read_text(encoding="utf-8"), f"{rel_dir}: compute-cloudrun/{fn} != disk"


def test_compute_cloudrun_cc_copy_equals_disk():
    for fn in ("main.tf", "variables.tf", "outputs.tf"):
        assert Path(REPO, MODULE_TREES[0], "compute-cloudrun", fn).read_text() == \
            Path(REPO, MODULE_TREES[1], "compute-cloudrun", fn).read_text()


@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("l19-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


_RUNS = [
    # (name, allow_unauthenticated, members, expect_failures or None)
    ("public_default", "true", "[]", None),
    ("private_user", "false", '["user:alice@example.com"]', None),
    ("private_kinds", "false", '["group:g@example.com", "serviceAccount:s@p.iam.gserviceaccount.com", '
                               '"domain:example.com"]', None),
    ("public_with_members_ignored", "true", '["user:alice@example.com"]', None),
    ("rejects_allUsers", "false", '["allUsers"]', "var.authorized_invoker_members"),
    ("rejects_allAuthenticatedUsers", "false", '["allAuthenticatedUsers"]', "var.authorized_invoker_members"),
    ("rejects_domain_allAuthenticatedUsers", "false", '["domain:allAuthenticatedUsers"]',
     "var.authorized_invoker_members"),
    ("rejects_user_allUsers", "false", '["user:allUsers"]', "var.authorized_invoker_members"),
    ("rejects_unprefixed", "false", '["alice@example.com"]', "var.authorized_invoker_members"),
    ("rejects_other_kind", "false", '["projectOwner:p"]', "var.authorized_invoker_members"),
    ("rejects_empty_value", "false", '["user:"]', "var.authorized_invoker_members"),
    ("private_without_invokers_fails", "false", "[]", "google_cloud_run_v2_service.app"),
]


def test_compute_cloudrun_member_validation_and_private_precondition(runner, tmp_path):
    wd = tmp_path / "m"
    shutil.copytree(os.path.join(REPO, "infra/modules/compute-cloudrun"), wd)
    blocks = []
    for name, unauth, members, expect in _RUNS:
        body = (f'run "{name}" {{\n  command = plan\n  plan_options {{\n    target = [google_cloud_run_v2_service.app]\n  }}\n'
                f"  variables {{\n    allow_unauthenticated      = {unauth}\n"
                f"    authorized_invoker_members = {members}\n  }}\n")
        if expect:
            body += f"  expect_failures = [{expect}]\n"
        blocks.append(body + "}\n")
    test = ('mock_provider "google" {}\nmock_provider "google-beta" {}\n\n'
            'variables {\n  project_id            = "l19-test"\n  product_id            = "l19"\n'
            '  service_account_email = "sa@l19-test.iam.gserviceaccount.com"\n}\n\n' + "\n".join(blocks))
    (wd / "l19_tests").mkdir()
    (wd / "l19_tests" / "l19.tftest.hcl").write_text(test, encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
    r = runner._run(["test", "-test-directory=l19_tests", "-filter=l19_tests/l19.tftest.hcl", "-no-color"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out[-4000:]
    assert f"{len(_RUNS)} passed, 0 failed" in out, out[-4000:]


def test_compute_cloudrun_validates_at_production_set(runner, tmp_path):
    wd = tmp_path / "v"
    shutil.copytree(os.path.join(REPO, "infra/modules/compute-cloudrun"), wd)
    assert runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd).returncode == 0
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]


# ============================================================================ 7. eval harness operator answer
def test_eval_harness_supplies_an_operator_access_record_only_for_private_decisions():
    from shared.access_policy import AccessPolicy
    from stackvend_eval.stages import HARNESS_OPERATOR_PRINCIPAL, harness_access
    ns = SimpleNamespace
    assert harness_access(ns(allow_unauthenticated=True, enable_direct_iap=False)) is None
    assert harness_access(ns(allow_unauthenticated=None, enable_direct_iap=None)) is None
    iap = AccessPolicy.model_validate(harness_access(ns(allow_unauthenticated=False, enable_direct_iap=True)))
    iam = AccessPolicy.model_validate(harness_access(ns(allow_unauthenticated=False, enable_direct_iap=False)))
    assert (iap.mode.value, iam.mode.value) == ("PRIVATE_IAP", "PRIVATE_IAM")
    assert iap.invoker_members() == iam.invoker_members() == [HARNESS_OPERATOR_PRINCIPAL]


# ============================================================================ 8. RT R1: variable-default generator
def test_r1_no_copy_of_the_variable_default_generator_or_its_access_table_is_left():
    """FD-55 W4 (FD55-W4) deleted the gateway copy of the generator and its `_ACCESS_KEY_DEFAULTS` table; FD-55 W6c
    (FD55-W6c) deleted the terraform MCP's apply-time copy with the pre-apply tfvars reconciler, its only caller. R1's
    property (the platform access keys are never guessed open) now holds because no value is guessed for any
    variable: a root without a value for them fails at plan (or keeps its declared default)."""
    from developer_agent import preflight_validator as pv
    assert not hasattr(pv, "_ACCESS_KEY_DEFAULTS") and not hasattr(pv, "generate_rfc1123_variable_default")
    tree = ast.parse(_src("mcp-servers/terraform/service.py"))
    defined = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)} | {
        t.id for n in tree.body if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
    assert not {"_ACCESS_KEY_DEFAULTS", "generate_rfc1123_variable_default"} & defined


# ============================================================================ 9. RT S1: compliance attestation read
def _attestation_db(attestation=None, raises=None):
    db = MagicMock()
    wl = db.collection.return_value.document.return_value
    wl.get.return_value = MagicMock(exists=True, to_dict=MagicMock(return_value={"project_id": "child-1"}))
    att_get = wl.collection.return_value.document.return_value.get
    if raises is not None:
        att_get.side_effect = raises
    else:
        att_get.return_value = MagicMock(exists=attestation is not None, to_dict=MagicMock(return_value=attestation))
    return db


def test_s1_r6_the_compliance_attestation_is_never_read_by_the_developer(agent):
    """FD-4I RT S1's direct-caller `compliance_audits/{trace}` fallback is deleted with FD-4R R-6 (integration): one
    source, the gateway-resolved decision. Without the IAP flag and without a record the resolution refuses
    (ACCESS_POLICY_REQUIRED); the attestation is not read, even when it would say IAP or is unreadable."""
    for db in (_attestation_db({"enable_direct_iap": True, "domain_restricted_sharing": False}),
               _attestation_db(raises=RuntimeError("must not be read")), _attestation_db(None)):
        agent.db = db
        with pytest.raises(DeveloperStageError) as ei:
            agent._resolve_run_access("authzapp", "trace-1", [], None, True, None, None, [])
        assert ei.value.error_class == ACCESS_POLICY_REQUIRED
        wl = db.collection.return_value.document.return_value
        assert wl.collection.return_value.document.return_value.get.call_count == 0


def test_s1_flags_present_skip_the_attestation_read(agent):
    agent.db = _attestation_db(raises=RuntimeError("must not be read"))
    resolved, drs, _ = agent._resolve_run_access("authzapp", "trace-1", [], None, True, False, False, [])
    assert resolved.mode == "PUBLIC_APP" and drs is False

"""FD-4R R-6 + FD-4F A9 / A10 / A12: hermetic fail-closed tests (negatives for every fail-open path + Do No Harm).

R-6  the persisted compliance decision is complete and fail-loud; the gateway resolves the developer's ingress from it
     only (request flags ignored); the developer agent's own keyword / Firestore / default fallbacks are gone.
A9   pre-commit verifier: any exception -> GATE_UNAVAILABLE, failed verdict -> CODE_DEFECT, no VCS credential ->
     GATE_UNAVAILABLE (no MOCK_COMMITTED), hard imports (no stub gates).
A10  the compiler pre-flight tier: a tool that cannot run is PREFLIGHT_UNAVAILABLE, never a pass (the uncalled tier was
     deleted by FD-55 W1).
A12  QA audit schema pass/fail defaults are False, 5 byte-identical copies.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import importlib
import json
import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)
from test_lane17_workflow_sim import Fleet, calls, run, workflow  # noqa: F401  (workflow is a fixture)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

PID = "app"
TRACE = "tr-1"


def _record(**kw):
    base = {"schema_version": 2, "product_id": PID, "trace_id": TRACE, "allow_unauthenticated": False,
            "enable_direct_iap": True, "domain_restricted_sharing": False, "allowed_domains": ["example.com"]}
    base.update(kw)
    return base


# ======================================================================================= R-6: persisted decision
def _compliance_handler(monkeypatch, db, *, pipeline=False):
    import compliance_agent.handler as ch

    for k in ("PROJECT_ID", "GEMINI_API_KEY", "K_SERVICE", "COMPLIANCE_MODE", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(ch.ComplianceAgentHandler, "db", property(lambda self: db))
    h = ch.ComplianceAgentHandler(compliance_server_url="http://compliance.invalid", mode="inprocess",
                                  require_remote_engine=False)
    h.genai_client = None
    h.model = None
    # (lane 19 L19-8: the compliance handler no longer collects principals; nothing to stub)
    monkeypatch.setattr(h, "_determine_approval_requirement", lambda has_conflicts: has_conflicts)
    if pipeline:
        h.require_remote_engine = True  # the gateway route's setting (after the in-process answer was obtained)
    return h


def _audit_req(spec):
    from compliance_agent.schemas import ComplianceAuditRequest

    return ComplianceAuditRequest(product_id=PID, spec_text=spec, trace_id=TRACE,
                                  task_dag=[{"step_id": "STEP-01-APIS"}, {"step_id": "STEP-06-COMPUTE"}])


@pytest.mark.parametrize("spec,public", [("a simple public todo app", True),
                                         ("internal web app with IAP single sign-on for company employees", False),
                                         ("HIPAA compliant portal storing patient electronic health records (ePHI)",
                                          None)])
def test_persisted_decision_is_complete_and_matches_the_response(monkeypatch, spec, public):
    db = FakeDB()
    h = _compliance_handler(monkeypatch, db)
    res = h.audit_and_enrich(_audit_req(spec))
    rec = db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"]
    # Integration (lane 14 PR-0 on R-6): one batch writes the record and the plan gate's product-keyed projection.
    [(path, _, merge)] = [w for w in db.writes if w[0] == f"workloads/{PID}/compliance_audits/{TRACE}"]
    assert merge is False  # replaced, never merged with an older decision
    [(_, projection, pmerge)] = [w for w in db.writes if w[0] == f"workloads/{PID}"]
    assert pmerge == ["compliance_decision", "compliance_profile"]  # only the projected fields are replaced
    assert projection["compliance_decision"]["trace_id"] == TRACE
    assert projection["compliance_decision"]["recorded_at"] == rec["decided_at"]
    assert rec["schema_version"] == 2 and rec["product_id"] == PID and rec["trace_id"] == TRACE
    for k in ("allow_unauthenticated", "enable_direct_iap", "domain_restricted_sharing", "allowed_domains",
              "enforce_private_ingress", "requires_cmek", "requires_audit_logging", "injected_tasks", "status",
              "is_regulated", "has_policy_conflicts", "policy_conflicts", "requires_human_approval"):
        assert rec[k] == json.loads(json.dumps(getattr(res, k))), k
    # compliance-profile-explicit (integration): the server answer is contract v3.
    assert isinstance(rec["decided_at"], float) and rec["contract_version"] == 3
    if public is not None:
        assert rec["allow_unauthenticated"] is public


def test_persist_write_failure_stops_the_gate(monkeypatch):
    from gate_errors import GateUnavailableError

    db = FakeDB()
    db.fail_writes = True
    h = _compliance_handler(monkeypatch, db)
    with pytest.raises(GateUnavailableError) as ei:
        h.audit_and_enrich(_audit_req("a simple public todo app"))
    assert ei.value.reason == "COMPLIANCE_PERSIST_FAILED" and ei.value.details["failure"] == "WRITE"
    assert ei.value.http_status == 503
    assert db.docs == {} and db.writes == []  # atomic: neither the record nor the gate's projection landed


def test_persist_without_store_on_the_pipeline_gate_raises(monkeypatch):
    from gate_errors import GateUnavailableError

    h = _compliance_handler(monkeypatch, None, pipeline=True)
    with pytest.raises(GateUnavailableError) as ei:
        h._persist_audit_record({"product_id": PID, "trace_id": TRACE})
    assert ei.value.reason == "COMPLIANCE_PERSIST_FAILED" and ei.value.details["failure"] == "NO_STORE"


def test_persist_without_store_off_pipeline_is_logged_and_skipped(monkeypatch, caplog):
    h = _compliance_handler(monkeypatch, None)
    res = h.audit_and_enrich(_audit_req("a simple public todo app"))  # eval harness / local dev: no store
    assert res.status == "PASSED" and "not persisted" in caplog.text


# ---------------------------------------------------------------------------------- decision validation (pure)
@pytest.mark.parametrize("record,problems", [
    (None, ["NO_COMPLIANCE_RECORD"]),
    ({}, ["NO_COMPLIANCE_RECORD"]),
    (_record(product_id="other"), ["PRODUCT_MISMATCH"]),
    (_record(trace_id="t-other"), ["TRACE_MISMATCH"]),
    ({k: v for k, v in _record().items() if k != "allow_unauthenticated"}, ["FIELD_INVALID:allow_unauthenticated"]),
    (_record(enable_direct_iap="false"), ["FIELD_INVALID:enable_direct_iap"]),
    (_record(domain_restricted_sharing=None), ["FIELD_INVALID:domain_restricted_sharing"]),
    (_record(allowed_domains="example.com"), ["FIELD_INVALID:allowed_domains"]),
    (_record(allowed_domains=[1]), ["FIELD_INVALID:allowed_domains"]),
])
def test_developer_decision_problems_never_default_a_flag(record, problems):
    import workflow_gates

    assert workflow_gates.developer_decision_problems(record, product_id=PID, trace_id=TRACE) == problems


def test_developer_decision_problems_negative_complete_record_is_usable():
    import workflow_gates

    assert workflow_gates.developer_decision_problems(_record(), product_id=PID, trace_id=TRACE) == []
    # a v1 record (no schema_version, no enforce_private_ingress) still carries every ingress field: usable
    v1 = {k: v for k, v in _record().items() if k != "schema_version"}
    assert workflow_gates.developer_decision_problems(v1, product_id=PID, trace_id=TRACE) == []


# ---------------------------------------------------------------------------------- gateway resolution
def _dev_capture(gw, monkeypatch, db):
    seen = {}
    monkeypatch.setattr(gw, "db", db)
    monkeypatch.setattr(gw.developer_agent, "fetch_github_token", lambda *a, **k: None)

    def gen(**kw):
        seen.update(kw)
        return {"apps/app/main.py": "x = 1\n"}

    monkeypatch.setattr(gw.developer_agent, "generate_code_files", gen)
    monkeypatch.setattr(gw.developer_agent, "commit_and_open_pr", lambda **kw: {
        "status": "COMMITTED", "branch_name": kw["branch_name"], "commit_sha": "a" * 40,
        "files_committed": ["apps/app/main.py"], "pull_request_url": "https://example.invalid/pr/1"})
    return seen


def test_developer_ingress_comes_from_the_persisted_decision_and_request_flags_are_ignored(gw, monkeypatch):
    db = FakeDB()
    db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"] = _record()
    seen = _dev_capture(gw, monkeypatch, db)
    out = gw._execute_developer_logic(gw.DeveloperExecuteRequest(
        trace_id=TRACE, product_id=PID, allow_unauthenticated=True, enable_direct_iap=False,
        domain_restricted_sharing=False, allowed_domains=[]))  # legacy public flags: ignored
    assert (seen["allow_unauthenticated"], seen["enable_direct_iap"], seen["domain_restricted_sharing"],
            seen["allowed_domains"]) == (False, True, False, ["example.com"])
    assert out["status"] == "SUCCESS" and out["compliance_trace_id"] == TRACE


def test_developer_negative_public_decision_stays_public(gw, monkeypatch):
    """Do No Harm: a persisted public decision is passed through unchanged (no over-restriction)."""
    db = FakeDB()
    db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"] = _record(allow_unauthenticated=True,
                                                                     enable_direct_iap=False, allowed_domains=[])
    seen = _dev_capture(gw, monkeypatch, db)
    gw._execute_developer_logic(gw.DeveloperExecuteRequest(trace_id=TRACE, product_id=PID))
    assert (seen["allow_unauthenticated"], seen["enable_direct_iap"], seen["domain_restricted_sharing"],
            seen["allowed_domains"]) == (True, False, False, [])


def test_resume_uses_the_explicit_compliance_trace(gw, monkeypatch):
    db = FakeDB()
    db.docs[f"workloads/{PID}/compliance_audits/t-old"] = _record(trace_id="t-old")
    seen = _dev_capture(gw, monkeypatch, db)
    out = gw._execute_developer_logic(gw.DeveloperExecuteRequest(trace_id="t-new", product_id=PID,
                                                                 compliance_trace_id="t-old"))
    assert seen["enable_direct_iap"] is True and out["compliance_trace_id"] == "t-old"


def test_resume_from_an_older_workflow_uses_the_last_prebuild_gate_trace(gw, monkeypatch):
    db = FakeDB()
    db.docs[f"workloads/{PID}"] = {"last_prebuild_gate": {"status": "PASS", "trace_id": "t-old", "product_id": PID}}
    db.docs[f"workloads/{PID}/compliance_audits/t-old"] = _record(trace_id="t-old")
    seen = _dev_capture(gw, monkeypatch, db)
    out = gw._execute_developer_logic(gw.DeveloperExecuteRequest(trace_id="t-new", product_id=PID,
                                                                 allow_unauthenticated=True))
    assert seen["allow_unauthenticated"] is False and out["compliance_trace_id"] == "t-old"


@pytest.mark.parametrize("setup,failure", [
    ("no_store", "NO_STORE"),
    ("read_error", "READ"),
    ("no_record", "NOT_FOUND"),
    ("explicit_missing", "NOT_FOUND"),
    ("incomplete", "INVALID"),
    ("other_product", "INVALID"),
])
def test_developer_without_a_usable_decision_is_gate_unavailable_before_any_generation(gw, monkeypatch, setup,
                                                                                        failure):
    from gate_errors import GateUnavailableError

    db = FakeDB()
    if setup == "read_error":
        db.fail_reads = True
    if setup == "explicit_missing":
        db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"] = _record()  # exists, but not the one asked for
    if setup == "incomplete":
        db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"] = {"product_id": PID, "trace_id": TRACE}
    if setup == "other_product":
        db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"] = _record(product_id="someone-else")
    seen = _dev_capture(gw, monkeypatch, None if setup == "no_store" else db)
    req = gw.DeveloperExecuteRequest(trace_id=TRACE, product_id=PID, allow_unauthenticated=True,
                                     compliance_trace_id="t-old" if setup == "explicit_missing" else None)
    with pytest.raises(GateUnavailableError) as ei:
        gw._execute_developer_logic(req)
    assert ei.value.reason == "COMPLIANCE_DECISION_UNAVAILABLE" and ei.value.details["failure"] == failure
    assert seen == {}  # no generation, no LLM call


def test_developer_route_returns_typed_503_without_a_decision(gw, monkeypatch):
    _dev_capture(gw, monkeypatch, FakeDB())
    r = TestClient(gw.app).post("/agent/developer/execute", json={"trace_id": TRACE, "product_id": PID,
                                                                  "allow_unauthenticated": True})
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["error_class"] == "GATE_UNAVAILABLE" and body["reason"] == "COMPLIANCE_DECISION_UNAVAILABLE"


def test_compliance_trace_id_is_validated(gw):
    with pytest.raises(Exception):
        gw.DeveloperExecuteRequest(product_id=PID, compliance_trace_id="../x")
    assert gw.DeveloperExecuteRequest(product_id=PID, compliance_trace_id="").compliance_trace_id is None


# ---------------------------------------------------------------------------------- RT §4 sanity invariant
INVARIANT_SPECS = ["internal web app with IAP single sign-on for company employees", "a simple public todo app",
                   "Backend worker with no public IP and private ingress internal only"]


def _audit_then_develop(gw, monkeypatch, spec):
    db = FakeDB()
    _compliance_handler(monkeypatch, db).audit_and_enrich(_audit_req(spec))
    seen = _dev_capture(gw, monkeypatch, db)
    out = gw._execute_developer_logic(gw.DeveloperExecuteRequest(trace_id=TRACE, product_id=PID))
    return db, db.docs[f"workloads/{PID}/compliance_audits/{TRACE}"], seen, out


@pytest.mark.parametrize("spec", INVARIANT_SPECS)
def test_invariant_decision_record_and_developer_run_agree(gw, monkeypatch, spec):
    """RT §4: for one trace, the persisted v2 decision and what the developer stage used are the same decision."""
    _, record, seen, out = _audit_then_develop(gw, monkeypatch, spec)
    assert out["compliance_trace_id"] == record["trace_id"] == TRACE
    for k in ("allow_unauthenticated", "enable_direct_iap", "domain_restricted_sharing", "allowed_domains"):
        assert seen[k] == record[k], k


@pytest.mark.parametrize("spec", INVARIANT_SPECS)
def test_invariant_product_projection_agrees_with_the_decision_record(gw, monkeypatch, spec):
    db, record, _, out = _audit_then_develop(gw, monkeypatch, spec)
    projection = (db.docs.get(f"workloads/{PID}") or {}).get("compliance_decision")
    assert isinstance(projection, dict)
    assert projection.get("trace_id") == out["compliance_trace_id"] == record["trace_id"]
    assert projection.get("profile") == record["compliance_profile"]
    for k in ("enable_direct_iap", "allow_unauthenticated", "enforce_private_ingress"):
        assert projection.get(k) == record[k], k
    # Integration: the apply-time gate's legacy/stale check (compliance-profile-explicit RT F1) reads these two.
    assert projection.get("profile_source") == record["profile_source"] and projection["profile_source"]
    assert projection.get("requested_profile") == record["requested_profile"]


# ---------------------------------------------------------------------------------- workflow body
def test_workflow_full_run_sends_its_own_trace_as_compliance_trace(workflow):
    res, _ = run(workflow)
    assert res.state == "SUCCEEDED", res.error
    [dev] = calls(res, "/agent/developer/execute")
    assert dev["body"]["compliance_trace_id"] == "tr-sim-1"


def test_workflow_resume_sends_the_prior_full_trace(workflow):
    outcome = {"status": "SUCCESS", "source_trace_id": "t-old", "prebuild_gate": {"status": "PASS", "trace_id": "t-old"},
               "compliance": {"allow_unauthenticated": False, "enable_direct_iap": True,
                              "domain_restricted_sharing": False, "allowed_domains": [], "trace_id": "t-old"}}
    res, _ = run(workflow, Fleet(**{"/agent/resume/outcome": (200, outcome)}), execution_mode="RESUME_DEVELOPER")
    assert res.state == "SUCCEEDED", res.error
    [dev] = calls(res, "/agent/developer/execute")
    assert dev["body"]["compliance_trace_id"] == "t-old"
    # RESUME-DEVELOPER-TASK-DAG: the developer's input is unchanged; QA reads the plan kept for the reused gate
    assert dev["body"]["task_dag"] == []


# ---------------------------------------------------------------------------------- developer agent
def _bare_agent():
    from developer_agent import handler as h

    agent = h.DeveloperAgent.__new__(h.DeveloperAgent)
    agent.db = None
    agent.project_id = ""
    agent.vcs_provider = "GITHUB"
    agent.github_owner = "castor-org"
    agent.genai_client = MagicMock(name="llm")
    return h, agent


@pytest.mark.parametrize("flags", [
    {},
    {"allow_unauthenticated": True, "enable_direct_iap": False},
    {"allow_unauthenticated": "true", "enable_direct_iap": False, "domain_restricted_sharing": False},
])
def test_generate_code_files_without_a_full_decision_stops_before_any_llm_call(flags):
    from gate_errors import GateUnavailableError

    h, agent = _bare_agent()
    with patch.object(agent, "fetch_existing_repo_files", side_effect=AssertionError("no repo read")):
        with pytest.raises(GateUnavailableError) as ei:
            agent.generate_code_files(product_id=PID, spec_text="internal portal with corporate sso", task_dag=[],
                                      trace_id=TRACE, **flags)
    assert ei.value.reason == "COMPLIANCE_DECISION_MISSING"
    assert agent.genai_client.models.mock_calls == []  # no model call (only the client's truthiness was read)


def test_developer_handler_has_no_ingress_keyword_engine():
    """R-6: the developer's three intent fallbacks are deleted (ast check on generate_code_files)."""
    import ast

    src = open(os.path.join(GW_DIR, "developer_agent", "handler.py"), encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "generate_code_files")
    consts = {n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert not consts & {"compliance_audits", "identity-aware proxy", "corporate sso", "domain-restricted",
                         "STEP-03D-DIRECT-IAP", "direct-iap"}


# ======================================================================================= A9: pre-commit gate
FILES = {"apps/app/main.py": "print('ok')\n", "apps/app/requirements.txt": "fastapi\n"}


class _Verifier:
    mode = "pass"

    def __init__(self, product_id=None):
        pass

    def purge_shadowed_package_files(self, files):
        return dict(files), []

    def verify_and_cure(self, files, product_id=None, **kw):
        if self.mode == "raise":
            raise ValueError("verifier crashed")
        if self.mode == "shape":
            return dict(files), True  # RT F5: a 2-tuple instead of (files, passed, errors)
        if self.mode == "fail":
            return dict(files), False, ["apps/app/main.py: SyntaxError"]
        return dict(files, **{"apps/app/requirements.txt": "fastapi>=0.110\n"}), True, []

    def verify(self, files):
        if self.mode == "raise":
            raise KeyError("boom")
        if self.mode == "fail":
            return [MagicMock(message="apps/app/main.py: SyntaxError", spec=["message"])]
        return []


def _commit(mode, *, token="test-token", validated=False):
    from _fake_vcs import FakeVCS

    h, agent = _bare_agent()
    vcs = FakeVCS()
    verifier = type("V", (_Verifier,), {"mode": mode})
    if validated:
        from shared.diagnostics import artifact_hash

        agent._record_stack("t-stack", validated_hash=artifact_hash(dict(FILES)))
    token_fn = MagicMock(return_value=token)
    with patch.object(h, "SynthesisVerifierAgent", verifier), \
            patch.object(h.VCSProviderFactory, "get_provider", return_value=vcs), \
            patch.object(h.time, "sleep", return_value=None), \
            patch.object(agent, "get_full_repo_name", return_value="castor-org/castor-app", create=True), \
            patch.object(agent, "fetch_github_token", token_fn, create=True), \
            patch.object(agent, "_write_iac_provenance") as prov:
        try:
            res = agent.commit_and_open_pr(product_id=PID, files=dict(FILES), branch_name="castor/app-1",
                                           trace_id="t-stack" if validated else None)
        except Exception as e:  # noqa: BLE001
            return e, vcs, token_fn, prov
    return res, vcs, token_fn, prov


@pytest.mark.parametrize("validated", [False, True])
def test_precommit_verifier_crash_is_gate_unavailable_and_nothing_is_committed(validated):
    from gate_errors import GateUnavailableError

    err, vcs, token_fn, _ = _commit("raise", validated=validated)
    assert isinstance(err, GateUnavailableError), err
    assert err.reason == "PRECOMMIT_VERIFIER_UNAVAILABLE" and isinstance(err.__cause__, (ValueError, KeyError))
    token_fn.assert_not_called()
    assert vcs.commits == []


@pytest.mark.parametrize("validated", [False, True])
def test_precommit_failed_verdict_is_code_defect_with_diagnostics(validated):
    from gate_errors import GateFailedError

    err, vcs, token_fn, _ = _commit("fail", validated=validated)
    assert isinstance(err, GateFailedError), err
    assert err.error_class.value == "CODE_DEFECT" and err.reason == "PRECOMMIT_VERIFY_FAILED"
    assert "Gatekeeper pre-commit verification failed" in str(err)  # message unchanged (RuntimeError subclass)
    assert err.diagnostics and "SyntaxError" in err.diagnostics[0]["message"]
    token_fn.assert_not_called()
    assert vcs.commits == []


def test_precommit_none_verifier_fails_closed():
    from gate_errors import GateUnavailableError

    h, agent = _bare_agent()
    with patch.object(h, "SynthesisVerifierAgent", None), \
            patch.object(agent, "get_full_repo_name", return_value="castor-org/castor-app", create=True), \
            patch.object(agent, "fetch_github_token", side_effect=AssertionError("no commit"), create=True):
        with pytest.raises(GateUnavailableError) as ei:
            agent.commit_and_open_pr(product_id=PID, files=dict(FILES), branch_name="castor/app-1")
    assert ei.value.reason == "PRECOMMIT_VERIFIER_UNAVAILABLE"


def test_no_vcs_credential_is_gate_unavailable_never_mock_committed():
    from gate_errors import GateUnavailableError

    err, vcs, token_fn, prov = _commit("pass", token="")
    assert isinstance(err, GateUnavailableError), err
    assert err.reason == "VCS_CREDENTIAL_UNAVAILABLE" and err.details["repo_name"] == "castor-org/castor-app"
    token_fn.assert_called_once()
    prov.assert_not_called()  # nothing committed -> no provenance
    assert vcs.commits == []


def test_precommit_negative_passing_tree_is_committed_exactly_as_the_verifier_returned_it():
    res, vcs, _, prov = _commit("pass")
    assert res["status"] == "COMMITTED"
    assert vcs.commits == [dict(FILES, **{"apps/app/requirements.txt": "fastapi>=0.110\n"})]
    prov.assert_called_once()


def test_precommit_negative_validated_tree_is_committed_byte_identically():
    res, vcs, _, _ = _commit("pass", validated=True)
    assert res["status"] == "COMMITTED" and vcs.commits == [dict(FILES)]


def test_precommit_unexpected_verifier_shape_is_typed_unavailable():
    """RT F5: the legacy path unpacks the verifier's answer inside the guarded call."""
    from gate_errors import GateUnavailableError

    err, vcs, token_fn, _ = _commit("shape")
    assert isinstance(err, GateUnavailableError), err
    assert err.reason == "PRECOMMIT_VERIFIER_UNAVAILABLE" and isinstance(err.__cause__, ValueError)
    token_fn.assert_not_called()
    assert vcs.commits == []


def test_package_import_fails_when_a_gate_module_is_missing(monkeypatch):
    """RT F1: `import developer_agent` (what main.py does) raises the real ImportError; no `DeveloperAgent = None`."""
    monkeypatch.setitem(sys.modules, "developer_agent.preflight_validator", None)
    monkeypatch.delitem(sys.modules, "developer_agent.handler", raising=False)
    monkeypatch.delitem(sys.modules, "developer_agent", raising=False)
    with pytest.raises(ImportError):
        importlib.import_module("developer_agent")


def test_package_import_negative_binds_the_real_agent():
    import developer_agent
    from developer_agent.handler import DeveloperAgent

    assert developer_agent.DeveloperAgent is DeveloperAgent


def test_handler_import_fails_when_a_gate_module_is_missing(monkeypatch):
    """FS-1: a missing pre-flight module crashes the handler import instead of binding (True, []) stubs."""
    monkeypatch.setitem(sys.modules, "developer_agent.preflight_validator", None)
    monkeypatch.delitem(sys.modules, "developer_agent.handler", raising=False)
    with pytest.raises(ImportError):
        importlib.import_module("developer_agent.handler")


def test_handler_import_negative_primary_path_binds_the_real_gates():
    from developer_agent import handler as h
    from developer_agent import preflight_validator as pv
    from gatekeeper_agent.verifier import SynthesisVerifierAgent

    # FD-55 W4: preflight_validate_terraform / self_correct_hcl are deleted; the remaining pre-flight gates bind
    assert h.hydrate_kubernetes_manifests is pv.hydrate_kubernetes_manifests
    # FD-55 W5: the preflight copies of the add-only requirements / package passes and the zero-Dockerfile check are
    # deleted (the gatekeeper's contracts and handler.enforce_container_contract are the one rules)
    for gone in ("validate_and_heal_python_requirements", "validate_and_heal_python_packages",
                 "validate_zero_dockerfiles"):
        assert not hasattr(h, gone) and not hasattr(pv, gone), gone
    assert not hasattr(h, "preflight_validate_terraform") and not hasattr(h, "self_correct_hcl")
    assert h.SynthesisVerifierAgent is SynthesisVerifierAgent


# ======================================================================================= A10: compiler pre-flight
# FD-55 W1 (register FD55-W1): run_compiler_preflight_check (no production caller; the production compiler gate is
# V1b, `tofu validate` on the terraform server) is DELETED with its three cases; tests/test_fd55_w1_dead_code.py.


# ======================================================================================= A12: QA schema defaults
SCHEMA_COPIES = ["shared/qa_audit_schemas.py", "apps/orchestrator-gateway/shared/qa_audit_schemas.py",
                 "apps/control-center/shared/qa_audit_schemas.py", "apps/qa-runner/shared/qa_audit_schemas.py",
                 "mcp-servers/terraform/shared/qa_audit_schemas.py"]


def test_qa_audit_schema_copies_are_byte_identical():
    digests = {p: hashlib.sha256(open(os.path.join(REPO_ROOT, p), "rb").read()).hexdigest() for p in SCHEMA_COPIES}
    assert len(set(digests.values())) == 1, digests


def test_qa_audit_schema_pass_fields_default_to_not_verified():
    from shared.qa_audit_schemas import AdherenceLensResult, DeterministicGateReport, SecurityLensResult

    r = DeterministicGateReport(passed=True)
    assert (r.pytest_success, r.bandit_passed, r.zero_dockerfile_passed, r.ast_syntax_passed) == (False,) * 4
    # QA-RECORD-HCL-FIELD (owner 11-14): HCL not checked by the producer = None ("not checked"), never a pass
    assert r.hcl_syntax_passed is None
    assert SecurityLensResult().passed is False and AdherenceLensResult().passed is False


def test_qa_audit_schema_negative_explicit_values_are_kept():
    from shared.qa_audit_schemas import DeterministicGateReport, SecurityLensResult

    r = DeterministicGateReport(passed=True, pytest_success=True, bandit_passed=True, hcl_syntax_passed=True,
                                zero_dockerfile_passed=True, ast_syntax_passed=True)
    assert all((r.pytest_success, r.bandit_passed, r.hcl_syntax_passed, r.zero_dockerfile_passed, r.ast_syntax_passed))
    assert SecurityLensResult(passed=True).passed is True

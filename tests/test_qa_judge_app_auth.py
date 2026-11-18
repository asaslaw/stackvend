"""QA-JUDGE-APP-AUTH: the Stage 2 security judge audits application-level authentication, defines critical vs advisory,
and may name the file of each critical vulnerability (typed field `critical_vulnerability_files`, the rule of
QA-JUDGE-FILE-MAPPING) so a JUDGE.SECURITY finding can be routed to a repair instead of riding along as text.

Live cases (examples 02 and 09): an on-by-default auth bypass demoted to a compliance flag, JWT decoding with
`verify=False` ignored, a fail-open identity check and a hardcoded fallback token missed.

Hermetic: fake judge, FakeDB, fake source backend, fake QA job. A prompt test proves what the judge is told, never how
a real model answers: that is proven only by live re-runs.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import logging
from unittest.mock import MagicMock, patch

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory, code_defect_outcome, passing_outcome, seed_context
from test_qa_feedback import _block_parts, _feedback  # noqa: E402

import qa_auditor.judge as judge_mod  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from qa_auditor import adherence_lens as AL  # noqa: E402
from qa_auditor import security_lens as SL  # noqa: E402
from qa_auditor.lens_common import LensUnavailableError  # noqa: E402
from shared.qa_audit_schemas import CompositeAuditReport, SecurityLensResult  # noqa: E402

BRANCH = "castor/app-1"
APPMAIN, AUTH, TEST = "apps/admin/main.py", "apps/admin/middleware/iap_auth.py", "apps/admin/tests/test_auth.py"
PYV = "apps/admin/.python-version"
TREE = {APPMAIN: "from fastapi import FastAPI\napp = FastAPI()\n", AUTH: "import jwt\n", TEST: "def test(): pass\n",
        "apps/admin/requirements.txt": "fastapi\n", PYV: "3.13\n", ".python-version": "3.13\n"}
DAG = [{"task_id": "CODE-01", "category": "CODE", "target_files": [APPMAIN, AUTH]}]
VERIFY_OFF = "jwt.decode with verify=False in iap_auth.py lets any caller forge an operator identity"
BYPASS = "ALLOW_LOCAL_MOCK_AUTH defaults to true, so every request skips authentication"


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "qa_jaa_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _reply(crit=(), files=None, passed=None, **extra):
    body = {"passed": (not crit) if passed is None else passed, "critical_vulnerabilities": list(crit), **extra}
    if files is not None:
        body["critical_vulnerability_files"] = files
    return json.dumps(body)


def _lens(monkeypatch, reply, policy=None):
    """Runs the real lens on a canned reply; returns (verdict, the prompt it sent)."""
    seen = []

    def _call(prompt, model, **kw):
        seen.append(prompt)
        return reply
    monkeypatch.setattr(judge_mod, "call", _call)
    verdict = SL.evaluate_security_lens("diff --git a b", ingress_policy=policy or {}, model_name="m", file_inventory="x")
    return verdict, seen[0]


def _judge(sec_reply, adherence=None):
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            return sec_reply
        return json.dumps(adherence or {"instruction_adherence_score": 1.0, "grounding_score": 1.0,
                                         "missed_directives": [], "hallucinated_features": [], "summary": "a"})
    return _call


def _db():
    db = FakeDB()
    seed_context(db)
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG
    return db


def _run(gw, monkeypatch, sec_reply, *, db=None, outcome=None, adherence=None):
    monkeypatch.setattr(judge_mod, "call", _judge(sec_reply, adherence))
    head = {p: t.encode() for p, t in TREE.items()}
    backend = FakeBackend({BRANCH: head, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH, attempt=0)
    return gw.run_qa(req, client=FakeQAClient(outcome or passing_outcome()),
                     source_backend_factory=backend_factory(backend), evidence_db=db if db is not None else _db())


def _sec(out):
    return [d for d in out["diagnostics"] if d["code"] == "JUDGE.SECURITY"]


# ============================================================================ parsing: the typed field
@pytest.mark.parametrize("raw,expected", [
    ([AUTH, ""], [AUTH, None]),
    (None, [None, None]),                 # an older-shaped reply
    ([AUTH], [None, None]),               # wrong length
    ([AUTH, APPMAIN, TEST], [None, None]),
    (AUTH, [None, None]),                 # wrong type
    ({"a": 1}, [None, None]),
    ([AUTH, 3], [None, None]),
    ([AUTH, None], [None, None]),
])
def test_critical_files_are_exact_or_nothing(raw, expected):
    data = {} if raw is None else {"critical_vulnerability_files": raw}
    assert SL._critical_files(data, ["a", "b"]) == expected


def test_older_shaped_reply_still_parses_and_still_blocks(monkeypatch):
    verdict, _ = _lens(monkeypatch, _reply([VERIFY_OFF]))
    assert verdict.passed is False and verdict.critical_vulnerabilities == [VERIFY_OFF]
    assert verdict.critical_vulnerability_files == [None]


@pytest.mark.parametrize("files", [[AUTH, APPMAIN], "nope", [1], 7, {"x": 1}])
def test_unusable_file_field_never_crashes_and_never_turns_a_finding_into_a_pass(monkeypatch, files):
    verdict, _ = _lens(monkeypatch, _reply([VERIFY_OFF], files=files))
    assert verdict.passed is False and verdict.critical_vulnerabilities == [VERIFY_OFF]
    assert verdict.critical_vulnerability_files == [None]


def test_the_shared_schema_is_unchanged():
    assert "critical_vulnerability_files" not in SecurityLensResult.model_fields
    assert issubclass(SL.SecurityVerdict, SecurityLensResult)


def test_vertex_schema_asks_for_the_field_optionally():
    assert SL.SECURITY_RESPONSE_SCHEMA["properties"]["critical_vulnerability_files"] == SL._STR_LIST
    assert set(SL.SECURITY_RESPONSE_SCHEMA["required"]) == {"passed", "critical_vulnerabilities"}


# ============================================================================ passing behaviour is unchanged
@pytest.mark.parametrize("reply", [
    _reply(),                                                                        # the shape before this change
    _reply(files=[]),
    _reply(files=[AUTH]),                                                            # a stray path names nothing
    _reply(moderate_vulnerabilities=["add a rate limit"], compliance_flags=["SOC2 note"]),
])
def test_no_criticals_still_passes(gw, monkeypatch, reply):
    db = _db()
    out = _run(gw, monkeypatch, reply, db=db)
    assert (out["passed"], out["error_class"], out["reason"], out["diagnostics"]) == (True, None, None, [])
    assert db.docs["qa_test_runs/tr-1"]["security_lens"]["passed"] is True


def test_the_verdict_rule_is_unchanged(monkeypatch):
    assert _lens(monkeypatch, _reply())[0].passed is True
    # JUDGE-GATE-ENUMERATED-FINDINGS (was: passed is False): "no" with no entry contradicts the reply contract ->
    # UNPARSEABLE -> no verdict, never a block without a finding and never a pass
    with pytest.raises(LensUnavailableError, match="passed=false and no critical_vulnerabilities"):
        _lens(monkeypatch, _reply(passed=False))
    assert _lens(monkeypatch, _reply([VERIFY_OFF], passed=True))[0].passed is False   # an entry always blocks
    assert _lens(monkeypatch, _reply([VERIFY_OFF], files=[AUTH], passed=True))[0].passed is False


# ============================================================================ gateway: file mapping
def test_a_named_committed_file_is_routed(gw, monkeypatch):
    out = _run(gw, monkeypatch, _reply([VERIFY_OFF, BYPASS], files=[AUTH, APPMAIN]))
    assert [(d["file"], d["message"], d["detail"]) for d in _sec(out)] == [(AUTH, VERIFY_OFF, None),
                                                                           (APPMAIN, BYPASS, None)]
    assert (out["passed"], out["error_class"], out["reason"]) == (False, "CODE_DEFECT", "STAGE2_FAILED")
    assert all(d[QR.JUDGE_FINDING_FIELD] is True and d["severity"] == "error" for d in _sec(out))


@pytest.mark.parametrize("named", ["apps/admin/missing.py", "./" + AUTH, AUTH.upper(), "/" + AUTH, "../" + AUTH,
                                   "apps/admin", AUTH + "\n"])
def test_an_unknown_file_is_reported_keeps_blocking_and_is_not_pinned(gw, monkeypatch, caplog, named):
    with caplog.at_level(logging.WARNING):
        out = _run(gw, monkeypatch, _reply([VERIFY_OFF], files=[named]))
    (d,) = _sec(out)
    assert d["file"] is None and d["severity"] == "error" and d["message"] == VERIFY_OFF
    assert repr(named) in d["detail"] and "not in the reviewed commit" in d["detail"]
    assert (out["passed"], out["error_class"], out["reason"]) == (False, "CODE_DEFECT", "STAGE2_FAILED")
    assert any("not in the reviewed commit" in r.getMessage() and repr(named) in r.getMessage() for r in caplog.records)


def test_an_oversized_unknown_path_is_capped(gw, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        out = _run(gw, monkeypatch, _reply([VERIFY_OFF], files=["x" * 5000]))
    (d,) = _sec(out)
    assert d["file"] is None and "x" * 200 in d["detail"] and "x" * 201 not in d["detail"]


@pytest.mark.parametrize("reply", [_reply([VERIFY_OFF]), _reply([VERIFY_OFF], files=[""]),
                                   _reply([VERIFY_OFF], files=[AUTH, APPMAIN])])
def test_no_usable_name_is_file_less_as_before(gw, monkeypatch, reply):
    (d,) = _sec(_run(gw, monkeypatch, reply))
    assert (d["file"], d["detail"]) == (None, None)


def test_a_mixed_reply_routes_only_the_committed_path(gw, monkeypatch):
    out = _run(gw, monkeypatch, _reply([VERIFY_OFF, BYPASS, "third"], files=[AUTH, "nope.py", ""]))
    assert [d["file"] for d in _sec(out)] == [AUTH, None, None]


def test_the_plain_shared_schema_still_maps(gw):
    """A result without the field (the shared schema) stays file-less: nothing else in the gateway must change."""
    ctx = {"task_dag": DAG}
    adh = MagicMock(passed=True)
    out = gw._judge_diagnostics(SecurityLensResult(passed=False, critical_vulnerabilities=["a"]), adh, ctx, {AUTH: "x"})
    assert [(d["code"], d["file"], d["detail"]) for d in out] == [("JUDGE.SECURITY", None, None)]


def test_the_file_is_kept_in_the_evidence_and_not_in_the_composite(gw, monkeypatch):
    db = _db()
    _run(gw, monkeypatch, _reply([VERIFY_OFF, BYPASS], files=[AUTH, "nope.py"]), db=db)
    doc = db.docs["qa_test_runs/tr-1"]
    assert doc["security_lens"]["critical_vulnerability_files"] == [AUTH, "nope.py"]    # what the judge said
    assert [d["file"] for d in doc["diagnostics"] if d["code"] == "JUDGE.SECURITY"] == [AUTH, None]   # what was routed
    assert "critical_vulnerability_files" not in doc["composite_audit"]["security_lens"]
    assert CompositeAuditReport.model_fields["security_lens"].annotation is SecurityLensResult


def test_the_routed_file_is_part_of_the_fingerprint(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (was: the routed file is not part of it): the fingerprint is the typed repair seed
    (code + file), never the wording."""
    routed = _sec(_run(gw, monkeypatch, _reply([VERIFY_OFF], files=[AUTH])))
    unrouted = _sec(_run(gw, monkeypatch, _reply([VERIFY_OFF])))
    reworded = _sec(_run(gw, monkeypatch, _reply([BYPASS], files=[AUTH])))
    assert routed[0]["file"] == AUTH and unrouted[0]["file"] is None
    assert routed[0]["fingerprint"] != unrouted[0]["fingerprint"]
    assert routed[0]["fingerprint"] == reworded[0]["fingerprint"]


def test_the_stage2_on_test_fail_path_routes_too(gw, monkeypatch):
    outcome = code_defect_outcome(code="PY.TEST_FAILED", message="a test failed", file=APPMAIN)
    db = _db()
    out = _run(gw, monkeypatch, _reply([VERIFY_OFF], files=[AUTH]), db=db, outcome=outcome)
    assert [(d["code"], d["file"]) for d in out["diagnostics"]] == [("PY.TEST_FAILED", APPMAIN), ("JUDGE.SECURITY", AUTH)]
    assert db.docs["qa_test_runs/tr-1"]["stage2_on_test_fail"]["security_lens"]["critical_vulnerability_files"] == [AUTH]


# ============================================================================ routing into plan_qa_repair
def _plan_of(out, *, reason="STAGE2_FAILED"):
    fb = _feedback(TREE, *out["diagnostics"])
    fb[QR.QA_REASON_FIELD] = reason
    return QR.plan_qa_repair(fb, stack_configured=True)


def test_a_routed_finding_becomes_a_repair_seed(gw, monkeypatch):
    plan = _plan_of(_run(gw, monkeypatch, _reply([VERIFY_OFF], files=[AUTH])))
    assert (plan.mode, plan.reason) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES")
    assert plan.repairable_paths == {AUTH} and [(s.code, s.file) for s in plan.seeds] == [("JUDGE.SECURITY", AUTH)]
    _token, content = _block_parts(plan.untrusted_output)
    assert VERIFY_OFF in content


def test_a_file_less_finding_still_regenerates(gw, monkeypatch):
    plan = _plan_of(_run(gw, monkeypatch, _reply([VERIFY_OFF])))
    assert (plan.mode, plan.reason, plan.seeds) == (QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", ())


def test_an_unknown_file_alone_regenerates_and_is_not_lost(gw, monkeypatch):
    plan = _plan_of(_run(gw, monkeypatch, _reply([VERIFY_OFF], files=["nope.py"])))
    assert (plan.mode, plan.reason, plan.seeds) == (QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", ())


def test_an_unknown_file_rides_along_as_text_next_to_a_seed(gw, monkeypatch):
    plan = _plan_of(_run(gw, monkeypatch, _reply([VERIFY_OFF, BYPASS], files=[AUTH, "nope.py"])))
    assert (plan.mode, plan.repairable_paths) == (QR.QA_REPAIR, {AUTH})
    _token, content = _block_parts(plan.untrusted_output)
    assert VERIFY_OFF in content and BYPASS in content and "not in the reviewed commit" in content


def test_a_finding_on_the_platform_runtime_pin_is_not_a_seed(gw, monkeypatch):
    plan = _plan_of(_run(gw, monkeypatch, _reply([VERIFY_OFF, BYPASS], files=[PYV, AUTH])))
    assert (plan.mode, plan.repairable_paths) == (QR.QA_REPAIR, {AUTH})


# ============================================================================ prompt content
PROMPT = SL.SECURITY_AUDITOR_PROMPT_TEMPLATE


@pytest.mark.parametrize("needle", [
    "4. **Application Authentication**",
    "non-test code",
    "Unverified identity",
    "`jwt.decode(token, verify=False)`",
    '`options={{"verify_signature": False}}`',
    "Fail-open check",
    "when verification could not run",
    "Fallback or placeholder credential",
    "On-by-default bypass",
    "is switched on by the workload's own deployed settings",
    "does not excuse a broken check",
])
def test_the_invariant_is_in_the_prompt(needle):
    assert needle in PROMPT


def test_the_direct_iap_rule_is_accurate():
    rule = next(ln for ln in PROMPT.splitlines() if ln.startswith("- When 'Identity-Aware Proxy In Front Of The Service'"))
    assert "`X-Goog-Authenticated-User-Email`" in rule and "is NOT a finding" in rule
    assert "does not claim stronger verification" in rule
    assert "When it is False" in rule and "any caller can forge it" in rule
    broken = next(ln for ln in PROMPT.splitlines() if "does not excuse a broken check" in ln)
    assert "`X-Goog-IAP-JWT-Assertion` without checking its signature" in broken


def test_the_allowed_list_is_in_the_prompt():
    allowed = next(ln for ln in PROMPT.splitlines() if ln.startswith("- NOT findings:"))
    for needle in ("public health endpoints", "`/api/config`-style routes", "PUBLIC_APP", "off by default", "test code"):
        assert needle in allowed


def test_severity_is_defined_and_advisory_cannot_hold_a_critical():
    section = PROMPT.split("### SEVERITY", 1)[1].split("{files_section}", 1)[0]
    assert "only `critical_vulnerabilities` stops the build" in section
    assert "- `critical_vulnerabilities`: a concrete defect" in section
    assert "- `moderate_vulnerabilities`: hardening that is not exploitable as deployed" in section
    assert "- `compliance_flags`: regulatory or documentation observations only" in section
    assert "never in the two advisory lists" in section
    assert "Set `passed` to false exactly when `critical_vulnerabilities` is non-empty" in section


def test_the_three_original_invariants_are_kept():
    for needle in ("1. **Secret Hygiene**", "2. **Least-Privilege IAM**", "3. **Data Protection**", "INGRESS SECURITY RULE",
                   "EFFECTIVE SETTINGS VS. MODULE DEFAULTS"):
        assert needle in PROMPT


def test_the_prompt_asks_for_the_field_like_the_adherence_lens():
    field = PROMPT.split('"critical_vulnerability_files"', 1)[1].split("\n", 1)[0]
    assert "at the same position" in field and "exact repository path" in field and "empty string" in field


@pytest.mark.parametrize("policy,told", [
    ({"access_mode": "PRIVATE_IAP", "enable_direct_iap": True}, "Identity-Aware Proxy In Front Of The Service: True"),
    ({"access_mode": "PUBLIC_APP", "allow_unauthenticated": True}, "Identity-Aware Proxy In Front Of The Service: False"),
    ({}, "Identity-Aware Proxy In Front Of The Service: False"),                   # unknown reads as the restrictive value
])
def test_the_prompt_renders_and_carries_the_workloads_real_policy(monkeypatch, policy, told):
    """`str.format` on the real template: the new text's braces are escaped, and the rule reads the real IAP fact."""
    _, prompt = _lens(monkeypatch, _reply(), policy=policy)
    assert told in prompt and '`options={"verify_signature": False}`' in prompt and "{{" not in prompt


# ============================================================================ the adherence lens is not touched
def test_the_adherence_prompt_has_no_auth_invariant():
    for needle in ("Application Authentication", "Fail-open", "X-Goog-", "critical_vulnerability_files"):
        assert needle not in AL.ADHERENCE_AUDITOR_PROMPT_TEMPLATE


def test_the_adherence_schema_is_unchanged():
    assert set(AL.ADHERENCE_RESPONSE_SCHEMA["properties"]) == {
        "instruction_adherence_score", "grounding_score", "missed_directives", "missed_directive_task_ids",
        "missed_directive_files", "hallucinated_features", "summary",
        "missed_directive_removals"}   # JUDGE-NAMED-INTENT-REMOVAL (ex02-1115): the one adherence field added since
    assert "critical_vulnerability_files" not in AL.AdherenceVerdict.model_fields


def test_adherence_routing_is_unchanged_next_to_a_routed_security_finding(gw, monkeypatch):
    out = _run(gw, monkeypatch, _reply([VERIFY_OFF], files=[AUTH]),
               adherence={"instruction_adherence_score": 0.5, "grounding_score": 1.0, "missed_directives": ["a"],
                          "missed_directive_task_ids": ["CODE-01"], "missed_directive_files": [APPMAIN],
                          "hallucinated_features": [], "summary": "a"})
    assert [(d["code"], d["file"]) for d in out["diagnostics"]] == [("JUDGE.SECURITY", AUTH), ("JUDGE.ADHERENCE", APPMAIN)]

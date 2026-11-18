"""ADHERENCE-PLATFORM-SATISFIED (owner 11-11): a requirement the platform itself satisfies (typed facet + typed workload
record) is never a blocking JUDGE.ADHERENCE finding against the workload's code or IaC; it stays visible as
"satisfied by the platform". Everything else, and every finding whose facet the platform does NOT satisfy for this
workload, still blocks (fail closed). The security lens is untouched.

Live case (ex09-c1, 11-10): the spec ended "... and a $10.00 FinOps budget cap."; the judge raised 3 blocking findings
("google_billing_budget ... missing from infra/workload/iac_intent.json", "enable billingbudgets.googleapis.com", ...).
StackVend never creates Cloud Billing budgets for workloads (known limitation); the cap is the workload record's
`budget_ceiling_monthly_usd`. No repair could meet the findings, so the run failed after its rounds.

Hermetic: fake judge, FakeDB, fake source backend, fake QA job.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (QA_IAP_ACCESS as QA_IAP, SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory,
                          code_defect_outcome, passing_outcome, seed_context)

import qa_auditor.judge as judge_mod  # noqa: E402
from qa_auditor import adherence_lens as AL  # noqa: E402
from qa_auditor import judge_input as ji  # noqa: E402
from qa_auditor import platform_satisfied as PS  # noqa: E402

BRANCH = "castor/app-1"
APPMAIN = "apps/admin/main.py"
TREE = {APPMAIN: "from fastapi import FastAPI\napp = FastAPI()\n", "tests/test_main.py": "def test(): pass\n"}
DAG = [{"task_id": "INFRA-01", "category": "INFRA", "target_files": ["infra/workload/iac_intent.json"]},
       {"task_id": "CODE-01", "category": "CODE", "target_files": [APPMAIN]},
       # the ex02 task the live finding named (category INFRA: IaC kind by its exact category)
       {"task_id": "INFRA-03", "category": "INFRA", "target_files": ["infra/workload/services.tf"]}]
BUDGET_MSGS = [
    "Enable billingbudgets.googleapis.com API via iac_intent.json",
    "$10.00 USD monthly google_billing_budget FinOps budget cap resource is missing from infra/workload/iac_intent.json",
    "FinOps budget cap of $10.00 is not provisioned",
]
HEALTH_MSG = "GET /health is missing"
_EXPIRES = datetime.now(timezone.utc) + timedelta(days=30)
SANDBOX_ENDS = _EXPIRES.date().isoformat()
SANDBOX_RECORD = {"is_sandbox": True, "sandbox_ttl_days": 30, "sandbox_expires_at": _EXPIRES.isoformat()}


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "adh_ps_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _judge(missed, facets=None, *, adh=0.85, gnd=1.0, task_ids=None, files=None, sec_crit=None, prompts=None,
           schemas=None):
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            if prompts is not None:
                prompts.append(("security", prompt))
            crit = sec_crit or []
            return json.dumps({"passed": not crit, "critical_vulnerabilities": crit})
        if prompts is not None:
            prompts.append(("adherence", prompt))
        if schemas is not None:
            schemas.append(kw.get("response_schema"))
        body = {"instruction_adherence_score": adh, "grounding_score": gnd, "missed_directives": missed,
                "hallucinated_features": [], "summary": "s"}
        if facets is not None:
            body["missed_directive_facets"] = facets
        if task_ids is not None:
            body["missed_directive_task_ids"] = task_ids
        if files is not None:
            body["missed_directive_files"] = files
        return json.dumps(body)
    return _call


def _db(record=None):
    db = FakeDB()
    seed_context(db)
    db.docs["workloads/app"].update(record or {})
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG
    return db


def _run(gw, monkeypatch, judge, *, record=None, db=None, outcome=None):
    monkeypatch.setattr(judge_mod, "call", judge)
    head = {p: t.encode() for p, t in TREE.items()}
    backend = FakeBackend({BRANCH: head, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH, attempt=0)
    return gw.run_qa(req, client=FakeQAClient(outcome or passing_outcome()),
                     source_backend_factory=backend_factory(backend),
                     evidence_db=db if db is not None else _db(record))


def _adh(out):
    return [d for d in out["diagnostics"] if d["code"] == "JUDGE.ADHERENCE"]


# ============================================================================ the ex09 shape
def test_ex09_budget_cap_findings_are_satisfied_by_the_platform_not_blocking(gw, monkeypatch):
    db, prompts = _db({"budget_ceiling_monthly_usd": 10.0}), []
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS, ["BUDGET_CAP"] * 3, prompts=prompts), db=db)
    assert out["passed"] is True and out["error_class"] is None and _adh(out) == []
    doc = db.docs["qa_test_runs/tr-1"]
    sat = doc["adherence_lens"]["platform_satisfied_directives"]
    assert [e["directive"] for e in sat] == BUDGET_MSGS and {e["facet"] for e in sat} == {"BUDGET_CAP"}
    assert all("$10.00" in e["how"] and "never creates a Cloud Billing budget" in e["how"] for e in sat)
    assert doc["adherence_lens"]["missed_directives"] == [] and doc["adherence_lens"]["passed"] is True
    assert doc["adherence_lens"]["instruction_adherence_score"] == 0.85               # kept as judged
    assert doc["adherence_lens"]["adherence_score_waived"] is True
    # visible to the operator (invariant 8), with the recorded ceiling
    assert "Satisfied by the platform, not judged against the code: BUDGET_CAP" in out["summary"]
    assert "$10.00/month" in out["summary"] and "3 finding(s)" in out["summary"]
    # (b) the judge was told, as a trusted platform fact
    (adh_prompt,) = [p for k, p in prompts if k == "adherence"]
    facts = adh_prompt.split("### PLATFORM FACTS", 1)[1].split("Sections marked UNTRUSTED", 1)[0]
    assert "- Budget cap (facet BUDGET_CAP): StackVend FinOps holds this workload's monthly budget ceiling of $10.00" \
        in facts
    assert '"missed_directive_facets"' in adh_prompt and "5. **Facets**" in adh_prompt


def test_same_findings_without_a_recorded_ceiling_still_block(gw, monkeypatch):
    prompts = []
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS, ["BUDGET_CAP"] * 3, prompts=prompts), record={})
    assert out["passed"] is False and out["reason"] == "STAGE2_FAILED"
    assert [d["message"] for d in _adh(out)] == BUDGET_MSGS
    assert "Satisfied by the platform" not in out["summary"]
    (adh_prompt,) = [p for k, p in prompts if k == "adherence"]
    assert "Budget cap" not in adh_prompt
    # IAM-POLICY-PLATFORM-FACT (ex02-g13) re-pin: this DAG has infrastructure tasks, so the IAM_POLICY facet is the one
    # handled facet (was: no facet handled, no facet field); BUDGET_CAP is still not handled and its findings block
    facts = adh_prompt.split("### PLATFORM FACTS", 1)[1].split("Sections marked UNTRUSTED", 1)[0]
    assert [x for x in facts.split("\n") if "(facet " in x and x.startswith("- ")] == [
        x for x in facts.split("\n") if x.startswith("- IAM policy (facet IAM_POLICY):")]
    assert '"missed_directive_denied_roles"' in adh_prompt


def test_code_only_dag_without_handled_facets_keeps_the_pre_facet_prompt(gw, monkeypatch):
    """IAM-POLICY-PLATFORM-FACT RT 5 (companion of the re-pin above): a plan with no infrastructure task, no recorded
    ceiling and a tree without a compute module handles no facet: no facet rubric, no facet or denied-role field in the
    prompt or the schema (the pre-facet prompt), and the finding blocks."""
    prompts, schemas = [], []
    db = _db({})
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = [DAG[1]]
    out = _run(gw, monkeypatch, _judge([HEALTH_MSG], ["IAM_POLICY"], task_ids=["CODE-01"], prompts=prompts,
                                       schemas=schemas), db=db)
    assert out["passed"] is False and [d["message"] for d in _adh(out)] == [HEALTH_MSG]
    (adh_prompt,) = [p for k, p in prompts if k == "adherence"]
    assert "5. **Facets**" not in adh_prompt and "(facet " not in adh_prompt
    assert "missed_directive_facets" not in adh_prompt and "missed_directive_denied_roles" not in adh_prompt
    (schema,) = schemas
    assert schema is AL.ADHERENCE_RESPONSE_SCHEMA


@pytest.mark.parametrize("ceiling", [None, 0, 0.0, -10.0, math.nan, math.inf, True, "10.00", [10], 1e-9, 0.005])
def test_malformed_ceiling_is_not_satisfied(gw, monkeypatch, ceiling):
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"]), record={"budget_ceiling_monthly_usd": ceiling})
    assert out["passed"] is False and len(_adh(out)) == 1


@pytest.mark.parametrize("facets", [
    ["OTHER"] * 3,                              # the judge says it is something else
    ["budget_cap", "Budget_Cap", "BUDGET"],     # not an exact member: OTHER
    ["BILLING", None, 3],                       # unknown value / wrong type: OTHER
    ["BUDGET_CAP"],                             # wrong length: every directive OTHER
    "BUDGET_CAP",                               # not a list
    None,                                       # absent
])
def test_unusable_or_other_facets_stay_blocking(gw, monkeypatch, facets):
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS, facets), record={"budget_ceiling_monthly_usd": 10.0})
    assert out["passed"] is False and [d["message"] for d in _adh(out)] == BUDGET_MSGS


def test_mixed_reply_keeps_the_other_finding_blocking_with_its_task_and_file(gw, monkeypatch):
    db = _db({"budget_ceiling_monthly_usd": 10.0})
    out = _run(gw, monkeypatch, _judge([BUDGET_MSGS[1], HEALTH_MSG], ["BUDGET_CAP", "OTHER"],
                                       task_ids=["INFRA-01", "CODE-01"], files=["", APPMAIN]), db=db)
    assert out["passed"] is False
    (d,) = _adh(out)
    assert (d["message"], d["task_id"], d["file"]) == (HEALTH_MSG, "CODE-01", APPMAIN)
    lens = db.docs["qa_test_runs/tr-1"]["adherence_lens"]
    assert lens["missed_directives"] == [HEALTH_MSG]
    assert lens["missed_directive_task_ids"] == ["CODE-01"] and lens["missed_directive_files"] == [APPMAIN]
    (e,) = lens["platform_satisfied_directives"]
    assert (e["directive"], e["facet"], e["task_id"]) == (BUDGET_MSGS[1], "BUDGET_CAP", "INFRA-01")
    reasons = db.docs["qa_test_runs/tr-1"]["composite_audit"]["blocking_reasons"]
    assert f"Missed Directive: {HEALTH_MSG}" in reasons
    assert not any(m in r for r in reasons for m in BUDGET_MSGS)


def test_satisfied_only_with_grounding_below_threshold_is_informational(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (was: still blocks on the grounding score): nothing blocking is listed."""
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"], gnd=0.5),
               record={"budget_ceiling_monthly_usd": 10.0})
    assert out["passed"] is True and _adh(out) == []
    assert "grounding score 0.50" in out["summary"] and "informational" in out["summary"]


def test_low_score_with_no_listed_directive_is_informational(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (was: blocks on the score): a low score with nothing listed is an advisory."""
    out = _run(gw, monkeypatch, _judge([], [], adh=0.85), record={"budget_ceiling_monthly_usd": 10.0})
    assert out["passed"] is True and _adh(out) == []
    assert "Adherence score 0.85" in out["summary"]
    # F1: below the 0.80 contradiction floor the same answer is no verdict
    with pytest.raises(gw.GateUnavailableError) as ei:
        _run(gw, monkeypatch, _judge([], [], adh=0.5), record={"budget_ceiling_monthly_usd": 10.0})
    assert ei.value.reason == "STAGE2_UNAVAILABLE"


# ============================================================================ sandbox lifecycle
def test_sandbox_lifecycle_finding_is_satisfied_for_a_recorded_sandbox(gw, monkeypatch):
    db = _db(dict(SANDBOX_RECORD))
    msg = "30-Day Sandbox lifecycle TTL is not implemented in infra/workload"
    out = _run(gw, monkeypatch, _judge([msg], ["SANDBOX_LIFECYCLE"]), db=db)
    assert out["passed"] is True and _adh(out) == []
    (e,) = db.docs["qa_test_runs/tr-1"]["adherence_lens"]["platform_satisfied_directives"]
    assert e["facet"] == "SANDBOX_LIFECYCLE" and f"30-day lifespan ending {SANDBOX_ENDS}" in e["how"]
    assert f"SANDBOX_LIFECYCLE (StackVend sandbox lifecycle, 30-day lifespan ending {SANDBOX_ENDS}" in out["summary"]


@pytest.mark.parametrize("record", [
    {"budget_ceiling_monthly_usd": 10.0},                                                    # not a sandbox
    {"budget_ceiling_monthly_usd": 10.0, **SANDBOX_RECORD, "is_sandbox": "true"},             # not exactly True
    {"budget_ceiling_monthly_usd": 10.0, **SANDBOX_RECORD, "sandbox_ttl_days": "30"},
    {"budget_ceiling_monthly_usd": 10.0, **SANDBOX_RECORD, "sandbox_ttl_days": 0},
    {"budget_ceiling_monthly_usd": 10.0, **SANDBOX_RECORD, "sandbox_expires_at": None},
    {"budget_ceiling_monthly_usd": 10.0, **SANDBOX_RECORD, "sandbox_expires_at": "in 30 days"},
])
def test_sandbox_facet_blocks_when_the_record_does_not_show_a_sandbox_lifecycle(gw, monkeypatch, record):
    out = _run(gw, monkeypatch, _judge(["sandbox TTL missing"], ["SANDBOX_LIFECYCLE"]), record=record)
    assert out["passed"] is False and [d["message"] for d in _adh(out)] == ["sandbox TTL missing"]


def test_budget_facet_does_not_satisfy_a_sandbox_finding_and_vice_versa(gw, monkeypatch):
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"]), record=dict(SANDBOX_RECORD))
    assert out["passed"] is False and len(_adh(out)) == 1


# ============================================================================ security lens untouched
def test_security_findings_still_block_and_the_security_prompt_is_unchanged(gw, monkeypatch):
    with_rec, without = [], []
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS, ["BUDGET_CAP"] * 3, sec_crit=["SQL injection in /admin"],
                                       prompts=with_rec), record={"budget_ceiling_monthly_usd": 10.0})
    assert out["passed"] is False
    assert [d["code"] for d in out["diagnostics"]] == ["JUDGE.SECURITY"]
    _run(gw, monkeypatch, _judge([], [], adh=1.0, prompts=without), record={})
    sec_a = [p for k, p in with_rec if k == "security"][0]
    sec_b = [p for k, p in without if k == "security"][0]
    adh_a = [p for k, p in with_rec if k == "adherence"][0]
    # SECURITY-LENS-PLATFORM-FACTS (owner 11-13): the security judge now reads the same PLATFORM FACTS section as the
    # adherence judge (one facts object); a budget cap is not a security facet, so it gets no facet rubric or field.
    section = lambda p: p.split("### PLATFORM FACTS", 1)[1].split("\n\n", 1)[0]  # noqa: E731
    assert section(sec_a) == section(adh_a) and "Budget cap (facet BUDGET_CAP)" in section(sec_a)
    assert "critical_vulnerability_facets" not in sec_a and "critical_vulnerability_facets" not in sec_b
    strip = lambda p: [ln for ln in p.split("\n") if "UNTRUSTED_" not in ln and "facet BUDGET_CAP" not in ln]  # noqa: E731
    assert strip(sec_a) == strip(sec_b)


# ============================================================================ Stage 2 on a failed test run
def test_stage2_on_test_fail_adds_no_finding_for_a_satisfied_facet(gw, monkeypatch):
    db = _db({"budget_ceiling_monthly_usd": 10.0})
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS, ["BUDGET_CAP"] * 3), db=db, outcome=code_defect_outcome())
    assert _adh(out) == [] and [d["code"] for d in out["diagnostics"]] == ["PY.TEST_FAILED"]
    s2 = db.docs["qa_test_runs/tr-1"]["stage2_on_test_fail"]
    assert s2["status"] == "CLEAN" and len(s2["adherence_lens"]["platform_satisfied_directives"]) == 3


# ============================================================================ Do No Harm: byte-identical otherwise
# sha256 of the adherence prompt / schema for the fixed input below, captured on main f7d2d635 before this change.
# Prompt re-pinned by JUDGE-GATE-ENUMERATED-FINDINGS RT F2 (rubric items 1 and 3: list every omission; only listed
# items fail the build). The schema is unchanged.
# Re-pinned by JUDGE-NAMED-INTENT-REMOVAL (ex02-1115): one optional schema line and field, missed_directive_removals
# (was prompt ceb3ff9d..., schema a0b4d1d1...).
MAIN_PROMPT_SHA = "38cad9c51954c8016cd70f6a8b0ad544f88868c127fedc4125c14990ca50f688"
MAIN_SCHEMA_SHA = "de8ea87d34f25329f45fe5f6f3b76f1d5085e01c03c4cd8d5cf99f060de816da"


def _lens_call(monkeypatch, reply, **kw):
    seen = {}

    def fake(prompt, model, **k):
        seen["prompt"], seen["schema"] = prompt, k.get("response_schema")
        return json.dumps(reply)

    monkeypatch.setattr(judge_mod, "call", fake)
    monkeypatch.setattr(judge_mod, "untrusted_block", lambda label, content: f"<<{label}>>{content}<</{label}>>")
    from qa_auditor.platform_facts import PlatformFacts
    # SECURITY-LENS-PLATFORM-FACTS: the facts text and the handled facets travel as one object
    res = AL.evaluate_adherence_lens("diff --git a/x b/x", task_dag=[{"task_id": "t1"}], pytest_logs="ok",
                                     compliance_summary="c", model_name="m", file_inventory="x",
                                     platform_facts=PlatformFacts(text="- fact",
                                                                  handled=kw.get("platform_handled") or {}))
    return res, seen


@pytest.mark.parametrize("kw", [{}, {"platform_handled": None}, {"platform_handled": {}}])
def test_without_satisfied_facets_prompt_and_schema_are_byte_identical_to_main(monkeypatch, kw):
    _res, seen = _lens_call(monkeypatch, {"instruction_adherence_score": 1.0, "grounding_score": 1.0,
                                          "missed_directives": []}, **kw)
    assert hashlib.sha256(seen["prompt"].encode()).hexdigest() == MAIN_PROMPT_SHA
    assert seen["schema"] is AL.ADHERENCE_RESPONSE_SCHEMA
    assert hashlib.sha256(json.dumps(seen["schema"], sort_keys=True).encode()).hexdigest() == MAIN_SCHEMA_SHA


@pytest.mark.parametrize("reply", [
    {"instruction_adherence_score": 0.5, "grounding_score": 1.0, "missed_directives": ["a", "b"],
     "missed_directive_facets": ["BUDGET_CAP", "BUDGET_CAP"], "missed_directive_task_ids": ["t1", ""]},
    {"instruction_adherence_score": 1.0, "grounding_score": 1.0, "missed_directives": []},
    {"instruction_adherence_score": 0.85, "grounding_score": 1.0, "missed_directives": []},   # F1: 0.80 floor
])
def test_without_satisfied_facets_the_verdict_ignores_any_facet_field(monkeypatch, reply):
    res, _ = _lens_call(monkeypatch, reply)
    assert res.missed_directives == reply["missed_directives"] and res.platform_satisfied_directives == []
    assert res.platform_limitation_advisories == [] and res.adherence_score_waived is False
    # JUDGE-GATE-ENUMERATED-FINDINGS (owner 11-13; was: score >= 0.95 and no missed directive): only the listed
    # directives decide the verdict
    assert res.passed is (not reply["missed_directives"])


def test_with_satisfied_facets_the_schema_adds_only_the_enum_field(monkeypatch):
    _res, seen = _lens_call(monkeypatch, {"instruction_adherence_score": 1.0, "grounding_score": 1.0,
                                          "missed_directives": []},
                            platform_handled=PS.platform_handlings({"budget_ceiling_monthly_usd": 10.0}))
    schema = seen["schema"]
    assert schema["properties"]["missed_directive_facets"] == {
        "type": "ARRAY", "items": {"type": "STRING",
                                   # GKE-NETWORK-PLATFORM-FACT (ex04-1115b) re-pin: GKE_NETWORK before OTHER;
                                   # IMAGE-BUILD-PLATFORM-FACT (ex01-g13) re-pin: IMAGE_BUILD before OTHER;
                                   # IAM-POLICY-PLATFORM-FACT (ex02-g13) re-pin: IAM_POLICY before OTHER
                                   "enum": ["BUDGET_CAP", "SANDBOX_LIFECYCLE", "PER_SERVICE_ACCESS", "GKE_NETWORK",
                                            "IMAGE_BUILD", "IAM_POLICY", "OTHER"]}}
    rest = {k: v for k, v in schema["properties"].items() if k != "missed_directive_facets"}
    assert rest == AL.ADHERENCE_RESPONSE_SCHEMA["properties"]
    assert schema["required"] == AL.ADHERENCE_RESPONSE_SCHEMA["required"]   # optional: absent = all OTHER
    assert "missed_directive_facets" not in AL.ADHERENCE_RESPONSE_SCHEMA["properties"]   # base never mutated


def test_platform_facts_text_is_byte_identical_without_satisfied_facets():
    base = ji.platform_facts_text("GITHUB", "off", DAG)
    assert ji.platform_facts_text("GITHUB", "off", DAG, platform_handled=None) == base
    assert ji.platform_facts_text("GITHUB", "off", DAG, platform_handled={}) == base
    sat = PS.platform_handlings({"budget_ceiling_monthly_usd": 25, **SANDBOX_RECORD})
    lines = ji.platform_facts_text("GITHUB", "off", DAG, platform_handled=sat).split("\n")
    assert lines[2].startswith("- Budget cap (facet BUDGET_CAP):") and "$25.00" in lines[2]
    assert lines[3].startswith("- Sandbox lifespan (facet SANDBOX_LIFECYCLE):")
    assert "\n".join(lines[:2] + lines[4:]) == base


# ============================================================================ the typed record and facet parsing
@pytest.mark.parametrize("record,facets", [
    ({}, set()),
    (None, set()),
    ("budget", set()),
    ({"budget_ceiling_monthly_usd": 10}, {"BUDGET_CAP"}),
    ({"budget_ceiling_monthly_usd": 10.5}, {"BUDGET_CAP"}),
    (dict(SANDBOX_RECORD), {"SANDBOX_LIFECYCLE"}),
    ({"budget_ceiling_monthly_usd": 40.0, **SANDBOX_RECORD}, {"BUDGET_CAP", "SANDBOX_LIFECYCLE"}),
    ({**SANDBOX_RECORD, "sandbox_ttl_days": True}, set()),
])
def test_platform_handlings_reads_only_typed_record_fields(record, facets):
    assert set(PS.platform_handlings(record)) == facets


@pytest.mark.parametrize("raw,expected", [
    ("BUDGET_CAP", "BUDGET_CAP"), ("SANDBOX_LIFECYCLE", "SANDBOX_LIFECYCLE"), ("OTHER", "OTHER"),
    ("budget_cap", "OTHER"), (" BUDGET_CAP", "OTHER"), ("", "OTHER"), (None, "OTHER"), (1, "OTHER"),
    (["BUDGET_CAP"], "OTHER"),
])
def test_facet_of_is_exact_membership(raw, expected):
    assert PS.facet_of(raw) == expected


def test_facet_enum_matches_the_schema_and_prompt():
    # GKE-NETWORK-PLATFORM-FACT (ex04-1115b) re-pin: GKE_NETWORK before OTHER; IMAGE-BUILD-PLATFORM-FACT (ex01-g13)
    # re-pin: IMAGE_BUILD before OTHER; IAM-POLICY-PLATFORM-FACT (ex02-g13) re-pin: IAM_POLICY before OTHER
    assert PS.FACETS == ("BUDGET_CAP", "SANDBOX_LIFECYCLE", "PER_SERVICE_ACCESS", "GKE_NETWORK", "IMAGE_BUILD",
                         "IAM_POLICY", "OTHER")
    assert set(PS.FACET_MEANINGS) == set(PS.FACETS)
    assert AL.FACET_SCHEMA_LINE.rstrip().endswith(
        'one of BUDGET_CAP, SANDBOX_LIFECYCLE, PER_SERVICE_ACCESS, GKE_NETWORK, IMAGE_BUILD, IAM_POLICY, OTHER"],')


# ============================================================================ documented limitation: PER_SERVICE_ACCESS
# Live case ex02-c1 (trace intake-ex02-c1-ad6940, 11-10): a Public app, tests 46/46, security clean; adherence 0.85 with
# one missed directive: restrict one Cloud Run service's invoker to the workload's service account. In a Public app
# every Cloud Run service is public (known limitation); the workload cannot change that.
PUBLIC = {"mode": "PUBLIC_APP", "sign_in": {"google": "BYO"}, "tenant_isolation_required": True, "source": "intake"}
IAM = {"mode": "PRIVATE_IAM", "invoker_principals": ["serviceAccount:caller@p.iam.gserviceaccount.com"],
       "sign_in": {"google": "DISABLED"}, "source": "operator_hitl"}
CR_TREE = {**TREE, "infra/workload/main.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n'}
GKE_TREE = {**TREE, "infra/workload/main.tf": 'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n'}
EX02_MSG = ("INFRA-03: core-processor fails to restrict Cloud Run IAM invoker access solely to the authenticated "
            "workload Service Account (services.tf sets allow_unauthenticated = var.allow_unauthenticated)")
ADVISORY = {"code": "ACCESS.INTERNAL_SERVICE_PUBLIC", "service": "core-processor",
            "message": "core-processor will be reachable from the internet", "pushed_by": ["orders-topic"]}


def _access_db(access, *, public_decision, advisories=None, record=None):
    db = _db(record)
    db.docs["workloads/app"]["access"] = dict(access)
    dec = db.docs["workloads/app/compliance_audits/tr-1"]
    dec.update({"allow_unauthenticated": public_decision, "enable_direct_iap": False})
    if advisories is not None:
        dec["access_advisories"] = advisories
    return db


def _run_tree(gw, monkeypatch, judge, tree, db):
    monkeypatch.setattr(judge_mod, "call", judge)
    head = {p: t.encode() for p, t in tree.items()}
    backend = FakeBackend({BRANCH: head, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH, attempt=0)
    return gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                     evidence_db=db)


def test_ex02_public_app_per_service_access_is_a_typed_advisory_not_blocking(gw, monkeypatch):
    db, prompts = _access_db(PUBLIC, public_decision=True, advisories=[dict(ADVISORY)]), []
    out = _run_tree(gw, monkeypatch, _judge([EX02_MSG], ["PER_SERVICE_ACCESS"], adh=0.85, task_ids=["INFRA-03"],
                                            prompts=prompts), CR_TREE, db)
    assert out["passed"] is True and _adh(out) == []             # not blocking, no repair seed
    lens = db.docs["qa_test_runs/tr-1"]["adherence_lens"]
    assert lens["missed_directives"] == [] and lens["platform_satisfied_directives"] == []
    (a,) = lens["platform_limitation_advisories"]
    assert (a["directive"], a["facet"], a["task_id"]) == (EX02_MSG, "PER_SERVICE_ACCESS", "INFRA-03")
    assert a["known_limitation"] == "Cloud Run services cannot be made internal-only yet"
    assert a["access_advisory_services"] == ["core-processor"]
    # score handling: the judge's 0.85 is kept, not applied, and recorded as waived
    assert lens["instruction_adherence_score"] == 0.85 and lens["adherence_score_waived"] is True
    assert "Documented platform limitation, not a code defect (advisory): PER_SERVICE_ACCESS" in out["summary"]
    assert "ACCESS.INTERNAL_SERVICE_PUBLIC: core-processor" in out["summary"]
    (adh_prompt,) = [p for k, p in prompts if k == "adherence"]
    facts = adh_prompt.split("### PLATFORM FACTS", 1)[1].split("Sections marked UNTRUSTED", 1)[0]
    assert "- Per-service access (facet PER_SERVICE_ACCESS): This workload is a Public app" in facts
    assert "already named: core-processor." in facts


def test_public_app_without_a_plan_time_advisory_still_names_the_limitation(gw, monkeypatch):
    db = _access_db(PUBLIC, public_decision=True)
    out = _run_tree(gw, monkeypatch, _judge([EX02_MSG], ["PER_SERVICE_ACCESS"]), CR_TREE, db)
    assert out["passed"] is True
    (a,) = db.docs["qa_test_runs/tr-1"]["adherence_lens"]["platform_limitation_advisories"]
    assert a["access_advisory_services"] == [] and "ACCESS.INTERNAL_SERVICE_PUBLIC" not in out["summary"]


@pytest.mark.parametrize("access,public_decision", [(dict(QA_IAP), False), (dict(IAM), False)])
def test_private_modes_keep_the_same_finding_blocking(gw, monkeypatch, access, public_decision):
    db = _access_db(access, public_decision=public_decision)
    out = _run_tree(gw, monkeypatch, _judge([EX02_MSG], ["PER_SERVICE_ACCESS"]), CR_TREE, db)
    assert out["passed"] is False and [d["message"] for d in _adh(out)] == [EX02_MSG]
    lens = db.docs["qa_test_runs/tr-1"]["adherence_lens"]
    assert lens["platform_limitation_advisories"] == [] and lens["adherence_score_waived"] is False


def test_public_app_without_cloud_run_keeps_the_finding_blocking(gw, monkeypatch):
    db = _access_db(PUBLIC, public_decision=True)
    out = _run_tree(gw, monkeypatch, _judge([EX02_MSG], ["PER_SERVICE_ACCESS"]), GKE_TREE, db)
    assert out["passed"] is False and [d["message"] for d in _adh(out)] == [EX02_MSG]


def test_per_service_access_mixed_with_a_real_defect_blocks_only_the_defect(gw, monkeypatch):
    db = _access_db(PUBLIC, public_decision=True)
    out = _run_tree(gw, monkeypatch, _judge([EX02_MSG, HEALTH_MSG], ["PER_SERVICE_ACCESS", "OTHER"], adh=0.7,
                                            task_ids=["INFRA-01", "CODE-01"], files=["", APPMAIN]), CR_TREE, db)
    assert out["passed"] is False
    (d,) = _adh(out)
    assert (d["message"], d["task_id"], d["file"]) == (HEALTH_MSG, "CODE-01", APPMAIN)
    lens = db.docs["qa_test_runs/tr-1"]["adherence_lens"]
    assert len(lens["platform_limitation_advisories"]) == 1 and lens["adherence_score_waived"] is False
    assert "Documented platform limitation" in out["summary"]   # still visible next to the real failure


def test_low_grounding_next_to_a_handled_limitation_is_informational(gw, monkeypatch):
    """JUDGE-GATE-ENUMERATED-FINDINGS (was: a grounding score below 0.95 blocks): nothing blocking is listed, so the
    build passes; the score stays recorded and is named in the summary."""
    db = _access_db(PUBLIC, public_decision=True)
    out = _run_tree(gw, monkeypatch, _judge([EX02_MSG], ["PER_SERVICE_ACCESS"], gnd=0.6), CR_TREE, db)
    assert out["passed"] is True and _adh(out) == []
    assert db.docs["qa_test_runs/tr-1"]["adherence_lens"]["grounding_score"] == 0.6
    assert "grounding score 0.60" in out["summary"] and "informational" in out["summary"]


def test_malformed_stored_access_advisories_stop_qa_loudly(gw, monkeypatch):
    db = _access_db(PUBLIC, public_decision=True, advisories=[{"code": "SOMETHING_ELSE", "service": "x"}])
    with pytest.raises(gw.GateUnavailableError) as ei:
        _run_tree(gw, monkeypatch, _judge([], [], adh=1.0), CR_TREE, db)
    assert ei.value.reason == "QA_ACCESS_POLICY"


@pytest.mark.parametrize("policy,cloud_run,expected", [
    ({"access_mode": "PUBLIC_APP", "allow_unauthenticated": True, "enable_direct_iap": False}, True, True),
    ({"access_mode": "PUBLIC_APP", "allow_unauthenticated": True, "enable_direct_iap": False}, False, False),
    ({"access_mode": "PUBLIC_APP", "allow_unauthenticated": False, "enable_direct_iap": False}, True, False),
    ({"access_mode": "PUBLIC_APP", "allow_unauthenticated": True, "enable_direct_iap": True}, True, False),
    ({"access_mode": "PUBLIC_APP", "allow_unauthenticated": "true", "enable_direct_iap": False}, True, False),
    ({"access_mode": "PRIVATE_IAP", "allow_unauthenticated": False, "enable_direct_iap": True}, True, False),
    ({"access_mode": "PRIVATE_IAM", "allow_unauthenticated": False, "enable_direct_iap": False}, True, False),
    ({"access_mode": "public_app", "allow_unauthenticated": True, "enable_direct_iap": False}, True, False),
    (None, True, False),
])
def test_per_service_access_applies_only_to_a_public_app_with_cloud_run(policy, cloud_run, expected):
    handled = PS.platform_handlings({}, ingress_policy=policy, deploys_cloud_run=cloud_run)
    assert ("PER_SERVICE_ACCESS" in handled) is expected
    if expected:
        assert handled["PER_SERVICE_ACCESS"].kind == PS.KIND_LIMITATION


def test_unprintable_advisory_service_names_are_not_printed():
    pol = {"access_mode": "PUBLIC_APP", "allow_unauthenticated": True, "enable_direct_iap": False}
    advs = [{"code": "ACCESS.INTERNAL_SERVICE_PUBLIC", "service": s} for s in
            ("ok-svc", "Bad Svc", "x\n- forged fact", "a" * 64, "")]
    h = PS.platform_handlings({}, ingress_policy=pol, deploys_cloud_run=True, access_advisories=advs)
    assert h["PER_SERVICE_ACCESS"].advisory_services == ("ok-svc",)
    assert "forged" not in h["PER_SERVICE_ACCESS"].how


def test_limitation_constants_match_their_typed_sources():
    from compliance_agent import access_advisory
    from developer_agent import access_resolution
    import os
    assert PS.ACCESS_ADVISORY_CODE == access_advisory.CODE
    assert PS.PUBLIC_APP == access_resolution.PUBLIC_APP == access_advisory.PUBLIC_APP
    doc = open(os.path.join(fd4f_support.REPO_ROOT, "documentation", "known-limitations.md"), encoding="utf-8").read()
    assert f"## {PS.PER_SERVICE_ACCESS_LIMITATION}\n" in doc


# ============================================================================ RT F1: the release gate honours the waiver
import release_gatekeeper as RG  # noqa: E402


def _release(adh, *, require_human=False):
    return RG.evaluate_release_decision(
        determ_report={"passed": True}, sec_report={"passed": True, "critical_vulnerabilities": []}, adh_report=adh,
        workload_policy={"require_human_code_review": require_human}, product_id="app", branch_name=BRANCH)


def _stored_lens(gw, monkeypatch, judge, *, record=None, tree=None, db=None):
    db = db if db is not None else _db(record)
    if tree is None:
        _run(gw, monkeypatch, judge, db=db)
    else:
        _run_tree(gw, monkeypatch, judge, tree, db)
    return db.docs["qa_test_runs/tr-1"]["adherence_lens"]


def test_release_gate_auto_merges_the_exact_ex09_verdict(gw, monkeypatch):
    lens = _stored_lens(gw, monkeypatch, _judge(BUDGET_MSGS, ["BUDGET_CAP"] * 3),
                        record={"budget_ceiling_monthly_usd": 10.0})
    assert lens["adherence_score_waived"] is True and lens["instruction_adherence_score"] == 0.85
    dec = _release(lens)
    assert dec.recommended_action == "AUTO_MERGE" and dec.is_approved is True and dec.blocking_reasons == []
    assert dec.adherence_score == 0.85                                          # never rewritten
    assert "| **Task DAG Adherence Lens** | ✅ PASSED |" in dec.release_certificate_markdown
    assert "platform-handled, not code defects: BUDGET_CAP x3 (score below 95% waived)" in dec.release_certificate_markdown


def test_release_gate_auto_merges_the_ex02_verdict(gw, monkeypatch):
    db = _access_db(PUBLIC, public_decision=True, advisories=[dict(ADVISORY)])
    lens = _stored_lens(gw, monkeypatch, _judge([EX02_MSG], ["PER_SERVICE_ACCESS"], task_ids=["INFRA-03"]),
                        tree=CR_TREE, db=db)
    dec = _release(lens)
    assert dec.recommended_action == "AUTO_MERGE" and dec.blocking_reasons == []
    assert "PER_SERVICE_ACCESS x1" in dec.release_certificate_markdown


def test_release_gate_with_human_review_waits_for_review_not_reject(gw, monkeypatch):
    lens = _stored_lens(gw, monkeypatch, _judge(BUDGET_MSGS, ["BUDGET_CAP"] * 3),
                        record={"budget_ceiling_monthly_usd": 10.0})
    dec = _release(lens, require_human=True)
    assert dec.recommended_action == "BLOCK_FOR_HITL_REVIEW" and dec.blocking_reasons == []


WAIVED = {"instruction_adherence_score": 0.85, "grounding_score": 1.0, "passed": True, "missed_directives": [],
          "adherence_score_waived": True,
          "platform_satisfied_directives": [{"directive": "d", "facet": "BUDGET_CAP", "how": "h", "task_id": None}]}


# JUDGE-GATE-ENUMERATED-FINDINGS (owner 11-13) changed this table: the release gate no longer blocks on the score, so
# the waiver flag only words the certificate. A missed directive or a failed verdict still blocks; a waiver flag that is
# absent or not exactly True now just drops the "(score below 95% waived)" wording; F1: below the floor the record is
# contradictory and blocks.
@pytest.mark.parametrize("change,blocks,reason", [
    ({"missed_directives": ["GET /health is missing"]}, True, "Missed Directive: GET /health is missing"),
    ({"passed": False}, True, "Adherence lens did not pass (missing or failed verdict)."),
    ({"adherence_score_waived": None}, False, None),
    ({"adherence_score_waived": "true"}, False, None),
    ({"instruction_adherence_score": 0.79}, True,               # F1: below the contradiction floor
     "Adherence lens record is contradictory (score 0.79 below 0.80 with no missed directive)."),
])
def test_release_gate_blocks_only_findings_or_failed_verdicts(change, blocks, reason):
    adh = {**WAIVED, **change}
    if adh["adherence_score_waived"] is None:
        del adh["adherence_score_waived"]
    dec = _release(adh)
    assert not any("below mandatory" in r for r in dec.blocking_reasons)   # never the 0.95 threshold
    if blocks:
        assert dec.recommended_action == "AUTO_REJECT" and dec.blocking_reasons == [reason]
        assert "| **Task DAG Adherence Lens** | ❌ DEFECTS |" in dec.release_certificate_markdown
    else:
        assert dec.recommended_action == "AUTO_MERGE" and dec.blocking_reasons == []
        assert "(score below 95% waived)" not in dec.release_certificate_markdown
        assert "score below 95%: informational, not a blocking reason" in dec.release_certificate_markdown


def test_release_gate_without_handled_findings_blocks_on_the_failed_verdict_not_the_score():
    dec = _release({"instruction_adherence_score": 0.85, "grounding_score": 1.0, "passed": False,
                    "missed_directives": []})
    assert dec.blocking_reasons == ["Adherence lens did not pass (missing or failed verdict)."]
    assert "platform-handled" not in dec.release_certificate_markdown


def test_waiver_floor_constants_agree():
    assert RG.ADHERENCE_WAIVER_FLOOR == AL.ADHERENCE_WAIVER_FLOOR == 0.80


# ============================================================================ RT F2: the waiver floor
# JUDGE-GATE-ENUMERATED-FINDINGS (owner 11-13): below the floor the build used to fail on a score finding; F1 makes
# it no verdict (STAGE2_UNAVAILABLE: the judge has seen more than it listed). From the floor up nothing blocking is
# listed, so it passes and the score is informational. The waiver flag is still recorded as before.
@pytest.mark.parametrize("adh,passed,waived", [(0.80, True, True), (0.85, True, True), (0.79, None, False),
                                               (0.5, None, False), (0.95, True, False)])
def test_waiver_floor_boundary(gw, monkeypatch, adh, passed, waived):
    db = _db({"budget_ceiling_monthly_usd": 10.0})
    if passed is None:
        with pytest.raises(gw.GateUnavailableError) as ei:
            _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"], adh=adh), db=db)
        assert ei.value.reason == "STAGE2_UNAVAILABLE"
        assert "contradictory answer" in db.docs["qa_test_runs/tr-1"]["summary"]
        return
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"], adh=adh), db=db)
    lens = db.docs["qa_test_runs/tr-1"]["adherence_lens"]
    assert out["passed"] is passed and lens["adherence_score_waived"] is waived
    assert len(lens["platform_satisfied_directives"]) == 1          # still recorded as handled
    assert _adh(out) == []                                          # never a score finding


def test_no_facet_label_at_the_waiver_range_still_blocks(gw, monkeypatch):
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], None, adh=0.85), record={"budget_ceiling_monthly_usd": 10.0})
    assert out["passed"] is False and [d["message"] for d in _adh(out)] == BUDGET_MSGS[:1]


# ============================================================================ RT F3: the facet applies only to IaC tasks
def test_per_service_access_label_on_a_code_task_blocks(gw, monkeypatch):
    db = _access_db(PUBLIC, public_decision=True)
    out = _run_tree(gw, monkeypatch, _judge([EX02_MSG], ["PER_SERVICE_ACCESS"], task_ids=["CODE-01"]), CR_TREE, db)
    assert out["passed"] is False
    (d,) = _adh(out)
    assert (d["message"], d["task_id"]) == (EX02_MSG, "CODE-01")
    assert db.docs["qa_test_runs/tr-1"]["adherence_lens"]["platform_limitation_advisories"] == []


def test_budget_cap_label_on_a_code_task_blocks(gw, monkeypatch):
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"], task_ids=["CODE-01"]),
               record={"budget_ceiling_monthly_usd": 10.0})
    assert out["passed"] is False and [(d["message"], d["task_id"]) for d in _adh(out)] == [(BUDGET_MSGS[0], "CODE-01")]


@pytest.mark.parametrize("task_ids", [["INFRA-01"], ["INFRA-03"], [""], ["NOT-A-TASK"], None])
def test_iac_task_or_no_attribution_is_handled(gw, monkeypatch, task_ids):
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"], task_ids=task_ids),
               record={"budget_ceiling_monthly_usd": 10.0})
    assert out["passed"] is True and _adh(out) == []


def test_iac_target_path_task_counts_as_infrastructure(gw, monkeypatch):
    """A task with no IaC category whose exact target is a platform IaC path (task_fact_kinds' path rule)."""
    db = _db({"budget_ceiling_monthly_usd": 10.0})
    db.docs["pipeline_executions/tr-1"]["stages"]["architect"]["details"]["task_dag"] = DAG + [
        {"task_id": "MISC-01", "category": "CODE", "target_files": ["infra/workload/terraform.tfvars"]}]
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"], task_ids=["MISC-01"]), db=db)
    assert out["passed"] is True


# ============================================================================ RT F5: fact boundaries
def test_ceiling_of_one_cent_is_the_smallest_satisfied():
    assert "BUDGET_CAP" in PS.platform_handlings({"budget_ceiling_monthly_usd": 0.01})
    assert "BUDGET_CAP" not in PS.platform_handlings({"budget_ceiling_monthly_usd": 0.009})


@pytest.mark.parametrize("expires,today,satisfied", [
    ("2026-11-10T21:00:00+00:00", "2026-11-10", True),       # ends today: still running
    ("2026-11-09T23:59:59+00:00", "2026-11-10", False),      # ended yesterday
    ("2026-11-10T01:00:00+05:00", "2026-11-10", False),      # 2026-11-09 20:00 UTC: ended
    ("2020-01-01T00:00:00+00:00", "2026-11-10", False),
    ("2026-12-10", "2026-11-10", True),                      # date only
])
def test_expired_sandbox_is_not_satisfied(expires, today, satisfied):
    rec = {"is_sandbox": True, "sandbox_ttl_days": 30, "sandbox_expires_at": expires}
    assert ("SANDBOX_LIFECYCLE" in PS.platform_handlings(rec, today=today)) is satisfied


def test_expired_sandbox_finding_blocks(gw, monkeypatch):
    rec = {**SANDBOX_RECORD, "sandbox_expires_at": "2020-01-01T00:00:00+00:00"}
    out = _run(gw, monkeypatch, _judge(["sandbox TTL missing"], ["SANDBOX_LIFECYCLE"]), record=rec)
    assert out["passed"] is False and [d["message"] for d in _adh(out)] == ["sandbox TTL missing"]


# ============================================================================ RT R1: no task attribution + a named file
@pytest.mark.parametrize("task_ids,files,handled", [
    ([""], [APPMAIN], False),                                    # app file, no task: blocks
    (["NOT-A-TASK"], [APPMAIN], False),                          # unknown task = no attribution
    (None, [APPMAIN], False),                                    # no task list at all
    ([""], ["infra/workload/iac_intent.json"], True),            # workload IaC file: handled
    ([""], ["infra/workload/services.tf"], True),
    ([""], ["infra/workload/../../apps/admin/main.py"], False),  # not under the root by components
    ([""], ["./infra/workload/main.tf"], False),
    ([""], ["infra/workload/"], False),
    ([""], ["infra/modules/compute-cloudrun/main.tf"], False),
    ([""], [""], True),                                          # no task and no file: handled
    (None, None, True),
])
def test_unattributed_finding_is_handled_only_for_a_workload_iac_file(gw, monkeypatch, task_ids, files, handled):
    out = _run(gw, monkeypatch, _judge(BUDGET_MSGS[:1], ["BUDGET_CAP"], task_ids=task_ids, files=files),
               record={"budget_ceiling_monthly_usd": 10.0})
    assert out["passed"] is handled and (_adh(out) == []) is handled


def test_unattributed_per_service_access_on_an_app_file_blocks(gw, monkeypatch):
    db = _access_db(PUBLIC, public_decision=True)
    out = _run_tree(gw, monkeypatch, _judge([EX02_MSG], ["PER_SERVICE_ACCESS"], task_ids=[""], files=[APPMAIN]),
                    CR_TREE, db)
    assert out["passed"] is False and [d["message"] for d in _adh(out)] == [EX02_MSG]


def test_workload_root_constant_is_the_platform_one():
    from shared.artifact_ownership import WORKLOAD_ROOT
    assert WORKLOAD_ROOT == "infra/workload/" and AL.WORKLOAD_ROOT is WORKLOAD_ROOT


# ============================================================================ release gate: typed stored score
@pytest.mark.parametrize("score", [True, "0.99", None])
def test_release_gate_reads_the_stored_score_typed(score):
    """JUDGE-GATE-ENUMERATED-FINDINGS: a stored record without a numeric score is malformed evidence (it blocks as such,
    no longer as a threshold)."""
    dec = _release({"instruction_adherence_score": score, "grounding_score": 1.0, "passed": True,
                    "missed_directives": []})
    assert dec.recommended_action == "AUTO_REJECT" and dec.adherence_score == 0.0
    assert dec.blocking_reasons == ["Adherence lens record is malformed (no numeric adherence and grounding scores)."]

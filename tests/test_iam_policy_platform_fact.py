"""IAM-POLICY-PLATFORM-FACT (ex02-g13, docs/handoff/ex02-g13-repair-exhaustion-diagnosis.md).

Live run ex02-g13 (stackvend13, 11-16): the architect's IAM task INFRA-03 asked for roles/iam.serviceAccountTokenCreator
on the workload service account "for Cloud Scheduler OIDC token generation". StackVend's IAM policy refuses that role in
every workload's IaC (policy_tables.PRIVILEGED_ROLES; the typed intent's role tables never hold it: IAC.ROLE_NOT_ALLOWED).
The adherence judge reported it missing from iac_intent.json on both QA attempts; three IaC repairs could not express it
(two answers cut off while thinking, one refused grant) and the developer stopped on ITERATIONS.

Fix: a typed LIMITATION facet IAM_POLICY, handled when the plan has an infrastructure task; the judge names the exact
role in `missed_directive_denied_roles` and the facet applies only when that role is one of PRIVILEGED_ROLES (exact
membership) and the finding is on an infrastructure task. Negatives: any other role, no role, a malformed list, a
code task, an unhandled facet: the finding stays blocking; without the facet handled the prompt and schema carry no
denied-role field.
"""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import re
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

import fd4f_support  # noqa: E402,F401  (gateway dir on sys.path)
from developer_agent.validators.policy_tables import PRIVILEGED_ROLES  # noqa: E402
from qa_auditor import adherence_lens as AL  # noqa: E402
from qa_auditor import judge_input as ji  # noqa: E402
from qa_auditor import platform_satisfied as PS  # noqa: E402
from shared import iac_intent as II  # noqa: E402

TOKEN_CREATOR = "roles/iam.serviceAccountTokenCreator"
# the live finding (qa_test_runs/intake-ex02-g13-882b5e, attempt 1)
LIVE_MSG = ("INFRA-03: Shared workload service account is missing the roles/iam.serviceAccountTokenCreator IAM binding "
            "on itself so Cloud Scheduler and token flows can mint OIDC tokens.")
DAG = [{"task_id": "INFRA-03", "category": "IAM", "target_files": ["infra/workload/main.tf"]},
       {"task_id": "CODE-03", "category": "CODE", "target_files": ["apps/gateway/tests/test_gateway.py"]}]


# ============================================================================ the facet and its one role table
def test_facet_registry():
    assert PS.FACETS[-2:] == ("IAM_POLICY", "OTHER") and PS.FACET_IAM_POLICY == "IAM_POLICY"
    assert PS.FACET_IAM_POLICY not in PS.SECURITY_FACETS
    assert all(r in PS.FACET_MEANINGS[PS.FACET_IAM_POLICY] for r in PRIVILEGED_ROLES)


def test_denied_roles_is_exactly_the_policy_table():
    assert PS.denied_roles() == frozenset(PRIVILEGED_ROLES)
    assert TOKEN_CREATOR in PS.denied_roles()


@pytest.mark.parametrize("raw,expected", [
    (TOKEN_CREATOR, True), ("roles/owner", True), ("roles/run.admin", True),
    ("roles/iam.serviceAccountUser", False), ("roles/secretmanager.secretAccessor", False),
    (" " + TOKEN_CREATOR, False), (TOKEN_CREATOR.lower(), False), ("iam.serviceAccountTokenCreator", False),
    ("", False), (None, False), ([TOKEN_CREATOR], False), (1, False),
])
def test_is_denied_role_is_exact_membership(raw, expected):
    assert PS.is_denied_role(raw) is expected


def test_no_typed_intent_role_table_holds_a_denied_role():
    """The fact says the typed intent cannot grant one: every role_allow table of the catalog is disjoint."""
    with open(os.path.join(GATEWAY, "shared", "iac_intent", "allowed_types.json"), encoding="utf-8") as fh:
        role_allow = json.load(fh)["role_allow"]
    granted = {r for roles in role_allow.values() if isinstance(roles, list) for r in roles}
    assert granted and not granted & PS.denied_roles()


def test_handled_only_with_an_infrastructure_task():
    assert PS.FACET_IAM_POLICY not in PS.platform_handlings(None)
    assert PS.FACET_IAM_POLICY not in PS.platform_handlings({"budget_ceiling_monthly_usd": 10.0})
    assert PS.FACET_IAM_POLICY not in PS.platform_handlings(None, has_iac_task=1)   # typed: True only
    h = PS.platform_handlings(None, has_iac_task=True)[PS.FACET_IAM_POLICY]
    assert h.kind == PS.KIND_LIMITATION and h.known_limitation == PS.IAM_POLICY_LIMITATION
    assert TOKEN_CREATOR in h.how and "missed_directive_denied_roles" in h.how


def test_the_known_limitation_section_exists_and_lists_exactly_the_policy_roles():
    with open(os.path.join(REPO_ROOT, "documentation", "known-limitations.md"), encoding="utf-8") as fh:
        doc = fh.read()
    head = f"## {PS.IAM_POLICY_LIMITATION}\n"
    assert head in doc
    section = doc.split(head, 1)[1].split("\n## ", 1)[0]
    first = section.strip().split("\n", 1)[0]
    assert set(re.findall(r"`(roles/[A-Za-z.]+)`", first)) == set(PRIVILEGED_ROLES)


def test_facts_line_appears_only_when_handled():
    base = ji.platform_facts_text("GITHUB", "generate", DAG)
    with_fact = ji.platform_facts_text("GITHUB", "generate", DAG,
                                       platform_handled=PS.platform_handlings(None, has_iac_task=True))
    added = [x for x in with_fact.split("\n") if x not in base.split("\n")]
    assert len(added) == 1 and added[0].startswith("- IAM policy (facet IAM_POLICY):")


# ============================================================================ the adherence lens
def _lens(monkeypatch, facets, task_ids, roles, handled=None, files=None):
    import qa_auditor.judge as judge_mod
    from qa_auditor.platform_facts import PlatformFacts

    seen = {}

    def fake(prompt, model, **k):
        seen["prompt"], seen["schema"] = prompt, k.get("response_schema")
        body = {"instruction_adherence_score": 0.9, "grounding_score": 1.0, "missed_directives": [LIVE_MSG],
                "hallucinated_features": [], "summary": "s", "missed_directive_task_ids": task_ids,
                "missed_directive_files": files or [II.INTENT_PATH]}
        if facets is not None:
            body["missed_directive_facets"] = facets
        if roles is not None:
            body["missed_directive_denied_roles"] = roles
        return json.dumps(body)

    monkeypatch.setattr(judge_mod, "call", fake)
    monkeypatch.setattr(judge_mod, "untrusted_block", lambda label, content: f"<<{label}>>{content}<</{label}>>")
    hand = handled if handled is not None else PS.platform_handlings(None, has_iac_task=True)
    res = AL.evaluate_adherence_lens("diff --git a/x b/x", task_dag=DAG, pytest_logs="ok", compliance_summary="c",
                                     model_name="m", file_inventory="x",
                                     platform_facts=PlatformFacts(text="- fact", handled=hand))
    return res, seen


def test_the_live_finding_labelled_with_the_denied_role_is_an_advisory(monkeypatch):
    res, seen = _lens(monkeypatch, ["IAM_POLICY"], ["INFRA-03"], [TOKEN_CREATOR])
    assert res.passed is True and res.missed_directives == []
    (adv,) = res.platform_limitation_advisories
    assert adv.facet == "IAM_POLICY" and adv.denied_role == TOKEN_CREATOR and adv.task_id == "INFRA-03"
    assert adv.known_limitation == PS.IAM_POLICY_LIMITATION
    assert AL.DENIED_ROLE_SCHEMA_LINE in seen["prompt"]
    assert seen["schema"]["properties"]["missed_directive_denied_roles"] == {"type": "ARRAY",
                                                                            "items": {"type": "STRING"}}
    dumped = res.model_dump()["platform_limitation_advisories"][0]
    assert dumped["denied_role"] == TOKEN_CREATOR


@pytest.mark.parametrize("facets,task_ids,roles", [
    (["OTHER"], ["INFRA-03"], [TOKEN_CREATOR]),                        # judge did not label it
    (None, ["INFRA-03"], [TOKEN_CREATOR]),                             # no facet field
    (["IAM_POLICY"], ["INFRA-03"], None),                              # no role named
    (["IAM_POLICY"], ["INFRA-03"], [""]),                              # empty role
    (["IAM_POLICY"], ["INFRA-03"], ["roles/iam.serviceAccountUser"]),  # a role the workload CAN grant (mislabel)
    (["IAM_POLICY"], ["INFRA-03"], [" " + TOKEN_CREATOR]),             # not exact
    (["IAM_POLICY"], ["INFRA-03"], [TOKEN_CREATOR, TOKEN_CREATOR]),    # wrong length
    (["IAM_POLICY"], ["INFRA-03"], TOKEN_CREATOR),                     # wrong type
    (["IAM_POLICY"], ["CODE-03"], [TOKEN_CREATOR]),                    # a code task stays blocking whatever its label
])
def test_otherwise_the_finding_still_blocks(monkeypatch, facets, task_ids, roles):
    res, _ = _lens(monkeypatch, facets, task_ids, roles)
    assert res.passed is False and res.missed_directives == [LIVE_MSG]
    assert res.platform_limitation_advisories == []


def test_unattributed_finding_on_the_intent_still_blocks(monkeypatch):
    """The LIMITATION rule is unchanged: with no task, the named file must be one the platform wrote."""
    res, _ = _lens(monkeypatch, ["IAM_POLICY"], [""], [TOKEN_CREATOR])
    assert res.passed is False and res.missed_directives == [LIVE_MSG]


def test_not_handled_no_denied_role_field_and_the_label_blocks(monkeypatch):
    """Another facet handled (budget), IAM_POLICY not: the prompt and schema are exactly the facet-only ones."""
    hand = PS.platform_handlings({"budget_ceiling_monthly_usd": 10.0})
    res, seen = _lens(monkeypatch, ["IAM_POLICY"], ["INFRA-03"], [TOKEN_CREATOR], handled=hand)
    assert res.passed is False and res.missed_directives == [LIVE_MSG]
    assert "missed_directive_denied_roles" not in seen["prompt"]
    assert "missed_directive_denied_roles" not in seen["schema"]["properties"]
    assert seen["schema"] == AL.adherence_response_schema(True)


def test_without_any_handled_facet_the_schema_is_the_base_object():
    assert AL.adherence_response_schema(False, True) is AL.ADHERENCE_RESPONSE_SCHEMA
    assert "missed_directive_denied_roles" not in AL.ADHERENCE_RESPONSE_SCHEMA["properties"]


def test_main_passes_the_typed_infrastructure_task_rule():
    """The gateway decides `has_iac_task` from the DAG's typed task kinds (judge_input.task_fact_kinds), nothing else."""
    with open(os.path.join(GATEWAY, "main.py"), encoding="utf-8") as fh:
        src = fh.read()
    assert ("has_iac_task=any(_qa_judge_input.FACT_IAC in _qa_judge_input.task_fact_kinds(t)\n"
            "                         for t in (ctx[\"task_dag\"] or []))") in src
    assert ji.FACT_IAC in ji.task_fact_kinds(DAG[0]) and ji.FACT_IAC not in ji.task_fact_kinds(DAG[1])


# ============================================================================ Opus RT (11-16) fixes
def test_rt1_one_role_per_entry_is_stated_in_meaning_fact_and_schema_line():
    """RT 1: the facet applies only to an entry whose sole ask is ONE refused role; the task's other asks are their own
    entries labelled OTHER (stated in the facet meaning, the trusted fact and the schema line)."""
    h = PS.platform_handlings(None, has_iac_task=True)[PS.FACET_IAM_POLICY]
    assert "only ask is granting ONE IAM role" in PS.FACET_MEANINGS[PS.FACET_IAM_POLICY]
    assert "its own entry, labelled OTHER" in PS.FACET_MEANINGS[PS.FACET_IAM_POLICY]
    assert "only ask is that one role" in h.how and "separate missed directive labelled OTHER" in h.how
    assert "ONE exact IAM role that is its only ask" in AL.DENIED_ROLE_SCHEMA_LINE
    assert "separate entry labelled OTHER" in AL.DENIED_ROLE_SCHEMA_LINE


@pytest.mark.parametrize("task,role,expected", [
    (DAG[0], TOKEN_CREATOR, True),
    (None, TOKEN_CREATOR, False),                                   # no task (unknown id / unusable list map to None)
    (DAG[1], TOKEN_CREATOR, False),                                 # a code task
    (DAG[0], None, False),
    (DAG[0], "roles/iam.serviceAccountUser", False),
    ("INFRA-03", TOKEN_CREATOR, False),                             # not a task mapping
])
def test_rt2_iam_policy_handled_needs_positive_evidence(task, role, expected):
    assert AL.iam_policy_handled(task, role) is expected


@pytest.mark.parametrize("task_ids", [
    ["INFRA-99"],              # an id that is not in the DAG
    [""],                      # no task
    ["INFRA-03", "CODE-03"],   # wrong length: attributes nothing
    None,                      # unusable task-id list
])
def test_rt2_without_a_known_infrastructure_task_the_finding_blocks(monkeypatch, task_ids):
    """Positive evidence (mirrors image_build_handled): no file named either, so only the task could carry it."""
    res, _ = _lens(monkeypatch, ["IAM_POLICY"], task_ids, [TOKEN_CREATOR], files=[""])
    assert res.passed is False and res.missed_directives == [LIVE_MSG]
    assert res.platform_limitation_advisories == []


def test_rt3_summary_note_names_the_refused_role():
    hand = PS.platform_handlings(None, has_iac_task=True)
    note = PS.summary_note(hand, [{"facet": "IAM_POLICY", "denied_role": TOKEN_CREATOR},
                                  {"facet": "IAM_POLICY", "denied_role": "not a role\nforged line"}])
    assert note.startswith("Documented platform limitation, not a code defect (advisory): IAM_POLICY (")
    assert f"2 finding(s); role(s): {TOKEN_CREATOR})" in note and "forged" not in note
    # no usable role: the line is as before (no role list)
    assert "role(s)" not in PS.summary_note(hand, [{"facet": "IAM_POLICY", "denied_role": None}])


def test_rt3_release_certificate_counts_name_the_refused_role():
    import release_gatekeeper as RG
    rec = {"platform_limitation_advisories": [
        {"facet": "IAM_POLICY", "denied_role": TOKEN_CREATOR},
        {"facet": "IAM_POLICY", "denied_role": "roles/iam.serviceAccountUser"},   # not a refused role: never printed
        {"facet": "PER_SERVICE_ACCESS"}]}
    assert RG._handled_counts(rec) == f"IAM_POLICY x2 ({TOKEN_CREATOR}), PER_SERVICE_ACCESS x1"
    assert RG._handled_counts({"platform_satisfied_directives": [{"facet": "BUDGET_CAP"}] * 3}) == "BUDGET_CAP x3"


def test_rt3_certificate_says_so_when_the_role_table_cannot_be_imported(monkeypatch, caplog):
    """Opus re-review (a): an import failure prints no role and logs a warning (never silent, never a failure)."""
    import logging
    import release_gatekeeper as RG
    monkeypatch.setitem(sys.modules, "qa_auditor.platform_satisfied", None)   # import -> ImportError
    with caplog.at_level(logging.WARNING, logger="castor-release-gatekeeper"):
        out = RG._handled_counts({"platform_limitation_advisories": [{"facet": "IAM_POLICY",
                                                                      "denied_role": TOKEN_CREATOR}]})
    assert out == "IAM_POLICY x1"
    assert any("IAM policy role table could not be imported" in r.getMessage() for r in caplog.records)

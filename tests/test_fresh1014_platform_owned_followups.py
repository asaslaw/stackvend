"""fresh 10-14 regression (11/26 vs 15/27): why 13 runs ended on POLICY.PLATFORM_OWNED_TYPE or
TF.REFERENCE_TO_UNDECLARED_RESOURCE, and the two contract fixes (no healer: nothing rewrites an AI file).

Recorded evidence (cassettes 20261014-FRESH-main-769600e-record; docs/handoff/fresh-1014-regression-report.md):
  (1) lane 10's typed topology lists the workload's Firestore database as a topology resource
      (`google_firestore_database.default`). The platform rendered its consumers' env binding as
      `google_firestore_database.default.name` into module.compute / module.compute_<svc> (platform files), and the
      IaC contract said "Declare these resources ... google_firestore_database.default" -- while policy says the
      (default) database is platform-owned and its hint says "delete this block and every reference". After the
      AI deleted it, the platform's own binding was a dangling reference (PLATFORM_DEFECT: 01-r1, 02-r1, 05-r2,
      05-r3, 06-r3, 09-r1, 09-r2) or made the removal look like a regression (01-r2, 01-r3, 02-r2, 06-r2).
  (2) the IaC persona was given only custom.tf; the references sat in its outputs.tf (and k8s_manifests.tf), so the
      correct deletion was rejected as NEW_FINGERPRINT and the identical next prompt got the identical answer
      (04-r1, 04-r3, and the outputs half of every run in (1)).
Fakes stand in for the LLM and for `tofu validate`; no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.repair_loop import (Assembled, Attempt, LoopContext, RepairLoop, Routing,  # noqa: E402
                                         removal_followups)
from developer_agent.topology_wiring import topology_contract_rule  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from shared.diagnostics import (AssemblyRecord, Diagnostic, ErrorClass, MemoryLedgerStore,  # noqa: E402
                                ValidationReport, fingerprint)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402
from shared.service_topology import FOUNDATION_PROVIDED, validate_service_topology  # noqa: E402

CUSTOM = "infra/workload/custom.tf"
OUTPUTS = "infra/workload/outputs.tf"
DB = "google_firestore_database.default"
DB_BLOCK = ('resource "google_firestore_database" "default" {\n  project = var.project_id\n  name = "(default)"\n'
            '  location_id = var.region\n  type = "FIRESTORE_NATIVE"\n}\n')
TOPIC = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'
OUT_DB = 'output "db" {\n  value = google_firestore_database.default.name\n}\n'
OUT_TOPIC = 'output "topic" {\n  value = google_pubsub_topic.t.name\n}\n'
OUT_FOUNDATION = 'output "db" {\n  value = module.foundation.database_name\n}\n'


# ------------------------------------------------------------------------------------------------ (1) topology
def _vt(resources, services=None):
    raw = {"services": services or [{"name": "api", "kind": "cloudrun"}], "primary_service": "api", "edges": [],
           "resources": resources}
    vt, diags = validate_service_topology(raw, product_id="shop")
    assert vt is not None, [d.code for d in diags]
    return vt


FIRESTORE = {"type": "google_firestore_database", "logical_name": "default",
             "consumers": [{"service": "api", "env_key": "FIRESTORE_DATABASE"}]}
BUCKET = {"type": "google_storage_bucket", "logical_name": "media",
          "consumers": [{"service": "api", "env_key": "MEDIA_BUCKET"}]}


def test_foundation_provided_table_is_exact_and_names_a_real_foundation_output():
    assert dict(FOUNDATION_PROVIDED) == {"google_firestore_database": {"name": "module.foundation.database_name"}}
    with open(os.path.join(REPO_ROOT, "infra/modules/workload-foundation/base/outputs.tf")) as f:
        assert 'output "database_name"' in f.read()


def test_topology_firestore_binding_is_the_foundation_output_and_is_not_asked_to_be_declared():
    """01-r1/02-r1/05-r2/06-r3/09-r1 etc.: the platform rendered google_firestore_database.default.name."""
    vt = _vt([FIRESTORE, BUCKET])
    assert vt.env_for("api") == {"FIRESTORE_DATABASE": "module.foundation.database_name",
                                 "MEDIA_BUCKET": "google_storage_bucket.media.name"}
    assert vt.declared_resources() == (("google_storage_bucket", "media"),)
    assert vt.foundation_resources() == (("google_firestore_database", "default"),)
    rule = topology_contract_rule(vt)
    assert "with exactly these addresses: google_storage_bucket.media." in rule
    assert "google_firestore_database.default" not in rule
    assert "- Do not declare google_firestore_database: the workload foundation (module.foundation)" in rule
    assert "module.foundation.database_name" in rule


def test_any_logical_name_of_a_foundation_type_binds_the_foundation_output():
    vt = _vt([dict(FIRESTORE, logical_name="agent_db")])
    assert vt.env_for("api") == {"FIRESTORE_DATABASE": "module.foundation.database_name"}
    assert "Declare these resources" not in topology_contract_rule(vt)   # nothing left for the AI to declare


def test_negative_topology_without_a_foundation_type_is_unchanged():
    """Do No Harm: every other catalog type binds and is declared exactly as before."""
    vt = _vt([BUCKET])
    assert vt.env_for("api") == {"MEDIA_BUCKET": "google_storage_bucket.media.name"}
    assert vt.declared_resources() == (("google_storage_bucket", "media"),)
    assert vt.foundation_resources() == () and vt.foundation_outputs() == ()
    rule = topology_contract_rule(vt)
    assert rule.endswith("- Declare these resources in infra/workload/custom.tf with exactly these addresses: "
                         "google_storage_bucket.media.")
    assert "Do not declare" not in rule


# ------------------------------------------------------------------------------------------------ (2) repair loop
class FakeTofu:
    """Stands in for policy + `tofu validate`: the platform-owned (default) database in custom.tf, and an undeclared
    reference wherever a root .tf file references google_firestore_database.default while no file declares it."""

    id, tool = "Vfake", "tofu"

    def validate(self, ctx):
        files = {p: t for p, t in ctx.files.items() if p.startswith("infra/workload/")}
        declared = any('resource "google_firestore_database" "default"' in t for t in files.values())
        out = []
        if declared:
            out.append(Diagnostic(tool="policy", code="POLICY.PLATFORM_OWNED_TYPE", severity="error", file=CUSTOM,
                                  block_address=DB, message="google_firestore_database is declared by the workload "
                                  "foundation", source="precommit"))
        else:
            for p, t in sorted(files.items()):
                if DB + ".name" in t:
                    out.append(Diagnostic(tool="tofu", code="TF.REFERENCE_TO_UNDECLARED_RESOURCE", severity="error",
                                          file=p, block_address="output.db", symbol=DB,
                                          message="Reference to undeclared resource", source="precommit"))
        return out


class IaC:
    """The recorded answer: delete the block (and fix references in whatever files it is given)."""

    def __init__(self):
        self.tasks = []

    def __call__(self, task):
        self.tasks.append(task)
        files = {}
        for p, t in task.files_to_fix.items():
            files[p] = t.replace(DB_BLOCK, "").replace(OUT_DB, OUT_FOUNDATION)
        return {"files": files, "envelope_ok": True, "finish_reason": "STOP", "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def _loop(repair_fn, persona_of_outputs="IAC_ENGINEER"):
    st = ValidatorStack()
    st.register(FakeTofu(), "blocking")
    attribution = {CUSTOM: "IAC_ENGINEER", OUTPUTS: persona_of_outputs}

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root=dict(d))
    return LoopContext(trace_id="t1", product_id="p", assemble=assemble, stack=st, ledger_store=MemoryLedgerStore(),
                       settings=HallucinationStackSettings(), attribution=attribution,
                       llm_draft_paths={CUSTOM, OUTPUTS}, preexisting=set(), repair_fn=repair_fn, model="m",
                       available_providers=["google"])


def test_removal_rejected_only_for_references_elsewhere_is_followed_by_a_task_that_offers_those_files():
    """01-r2 / 04-r3 shape: iteration 1 offers custom.tf only; the deletion leaves output.db in outputs.tf dangling
    (rejected: NEW_FINGERPRINT). Iteration 2 offers outputs.tf too, with a hint naming the removed block."""
    iac = IaC()
    loop = RepairLoop(_loop(iac))
    tree, report = loop.run({CUSTOM: TOPIC + DB_BLOCK, OUTPUTS: OUT_TOPIC + OUT_DB})
    assert report.status == "PASS"
    assert DB_BLOCK not in tree[CUSTOM] and OUT_FOUNDATION in tree[OUTPUTS] and TOPIC in tree[CUSTOM]
    assert [sorted(t.files_to_fix) for t in iac.tasks] == [[CUSTOM], [CUSTOM, OUTPUTS]]
    follow = [x for x in iac.tasks[1].diagnostics if x["code"] == "TF.REFERENCE_TO_UNDECLARED_RESOURCE"]
    assert len(follow) == 1 and follow[0]["file"] == OUTPUTS and follow[0]["block"] == "output.db"
    hint = json.loads(follow[0]["hint"])
    assert hint["removed"] == DB and hint["reference"] == "output.db" and "module.foundation" in hint["platform"]
    ev = [(e.iteration, e.accepted, e.reject_reason) for e in loop.ctx.events]
    assert ev == [(1, False, "NEW_FINGERPRINT"), (2, True, None)]


def test_followup_goes_to_the_persona_that_owns_the_referencing_file():
    iac = IaC()
    loop = RepairLoop(_loop(iac, persona_of_outputs="DEVOPS_ENGINEER"))
    tree, report = loop.run({CUSTOM: TOPIC + DB_BLOCK, OUTPUTS: OUT_TOPIC + OUT_DB})
    assert report.status == "PASS"
    assert [(t.persona, sorted(t.files_to_fix)) for t in iac.tasks] == [
        ("IAC_ENGINEER", [CUSTOM]), ("DEVOPS_ENGINEER", [OUTPUTS]), ("IAC_ENGINEER", [CUSTOM])]


def _attempt(prev, new, routes, reasons, why="NEW_FINGERPRINT", accepted=False):
    return Attempt(accepted, why, {}, None, new, routes, set(reasons), dict(reasons), "", prev)


def _rep(*diags):
    return ValidationReport(status="FAIL" if diags else "PASS", source="precommit", artifact_hash="h",
                            diagnostics=list(diags))


PO = Diagnostic(tool="policy", code="POLICY.PLATFORM_OWNED_TYPE", severity="error", file=CUSTOM, block_address=DB,
                message="m", source="precommit")
REF = Diagnostic(tool="tofu", code="TF.REFERENCE_TO_UNDECLARED_RESOURCE", severity="error", file=OUTPUTS,
                 block_address="output.db", symbol=DB, message="m", source="precommit")
OWNED = Routing(ErrorClass.CODE_DEFECT, "IAC_ENGINEER", OUTPUTS, 2, None)
JUST = {DB: "REMOVAL_CODE:POLICY.PLATFORM_OWNED_TYPE"}


def test_removal_followups_exact_signals():
    assert removal_followups(_attempt(_rep(PO), _rep(REF), {fingerprint(REF): OWNED}, JUST)) == [(REF, OWNED, DB)]


def test_negative_no_followups_for_a_real_regression_or_another_rejection():
    other = Diagnostic(tool="tofu", code="TF.UNSUPPORTED_ATTRIBUTE", severity="error", file=OUTPUTS,
                       block_address="output.x", message="m", source="precommit")
    stray = REF.model_copy(update={"symbol": "google_firestore_database.other"})   # not the removed address
    routes = {fingerprint(x): OWNED for x in (REF, other, stray)}
    assert removal_followups(_attempt(_rep(PO), _rep(REF, other), routes, JUST)) == []     # mixed: real regression
    assert removal_followups(_attempt(_rep(PO), _rep(stray), routes, JUST)) == []
    assert removal_followups(_attempt(_rep(PO), _rep(REF), routes, {})) == []              # unjustified removal
    assert removal_followups(_attempt(_rep(PO), _rep(REF), routes, JUST, why="PRESERVATION_VIOLATION")) == []
    assert removal_followups(_attempt(_rep(PO), _rep(REF), routes, JUST, why=None, accepted=True)) == []


def test_negative_reference_in_a_platform_file_is_never_offered():
    platform = Routing(ErrorClass.PLATFORM_DEFECT)
    assert removal_followups(_attempt(_rep(PO), _rep(REF), {fingerprint(REF): platform}, JUST)) == []


def test_negative_prompts_without_followups_are_unchanged():
    """Do No Harm for the cassettes: a task list built with no follow-ups is identical to before (no new key)."""
    loop = RepairLoop(_loop(IaC()))
    d = {CUSTOM: TOPIC + DB_BLOCK, OUTPUTS: OUT_TOPIC + OUT_DB}
    asm = loop.ctx.assemble(d)
    report, routes = loop.validate(d, asm, 0)
    from shared.diagnostics import RepairLedger
    s, led = loop.ctx.settings, RepairLedger(trace_id="t1")
    a = [t.prompt() for t in loop._tasks(d, report, routes, led, s, {}, 0)]
    b = [t.prompt() for t in loop._tasks(d, report, routes, led, s, {}, 0, [])]
    assert a == b and len(a) == 1 and OUTPUTS not in a[0]


# ------------------------------------------------------------------------------------------------ PO-1b (Fable F1/F2)
from developer_agent.repair_loop import FOUNDATION_DECLARED_TYPES, PLATFORM_OWNED_REFERENCE_ACTION  # noqa: E402
from developer_agent.repair_loop import followup_hint  # noqa: E402

# The follow-up hint actually sent in a recorded run (cassette 20261015-AC-2-3-6-fresh-record-b377559, 05-r1,
# IAC_ENGINEER iteration 2): the own-persona, in-block text must stay byte-identical (cassette keys unchanged).
RECORDED_BUDGET_HINT = (
    '{"action": "Your previous answer deleted google_billing_budget.fleet_budget, as its diagnostic requires, but '
    'output.fleet_budget_id still references it. Keep google_billing_budget.fleet_budget deleted and, in the same '
    'answer, delete this reference (a depends_on entry, or an output that only re-exports it) or point it at an '
    'address that exists.", "reference": "output.fleet_budget_id", "removed": "google_billing_budget.fleet_budget"}')


def _pre_po1b_hint(x, removed_addr):
    """Frozen copy of followup_hint before PO-1b (the text recorded prompts carry)."""
    hint = {"removed": removed_addr, "reference": x.block_address,
            "action": (f"Your previous answer deleted {removed_addr}, as its diagnostic requires, but "
                       f"{x.block_address} still references it. Keep {removed_addr} deleted and, in the same answer, "
                       "delete this reference (a depends_on entry, or an output that only re-exports it) or point it "
                       "at an address that exists.")}
    if removed_addr.split(".", 1)[0] in FOUNDATION_DECLARED_TYPES:
        hint["platform"] = PLATFORM_OWNED_REFERENCE_ACTION
    return json.dumps(hint, sort_keys=True)


def test_po1b_own_persona_in_block_hint_is_byte_identical_to_the_recorded_prompt():
    budget = REF.model_copy(update={"block_address": "output.fleet_budget_id",
                                    "symbol": "google_billing_budget.fleet_budget"})
    assert followup_hint(budget, "google_billing_budget.fleet_budget") == RECORDED_BUDGET_HINT
    assert followup_hint(budget, "google_billing_budget.fleet_budget", own=True) == RECORDED_BUDGET_HINT
    assert followup_hint(REF, DB) == _pre_po1b_hint(REF, DB)   # foundation type: "platform" key kept as well


def test_po1b_cross_persona_hint_is_neutral_and_offers_the_same_file():
    """F1: DEVOPS_ENGINEER owns outputs.tf; IAC_ENGINEER deleted the database. The follow-up must not tell
    DEVOPS_ENGINEER 'your previous answer deleted' it. Same tasks, same files as before PO-1b."""
    iac = IaC()
    loop = RepairLoop(_loop(iac, persona_of_outputs="DEVOPS_ENGINEER"))
    tree, report = loop.run({CUSTOM: TOPIC + DB_BLOCK, OUTPUTS: OUT_TOPIC + OUT_DB})
    assert report.status == "PASS"
    assert [(t.persona, sorted(t.files_to_fix)) for t in iac.tasks] == [
        ("IAC_ENGINEER", [CUSTOM]), ("DEVOPS_ENGINEER", [OUTPUTS]), ("IAC_ENGINEER", [CUSTOM])]
    follow = [x for x in iac.tasks[1].diagnostics if x["code"] == "TF.REFERENCE_TO_UNDECLARED_RESOURCE"]
    assert len(follow) == 1 and follow[0]["file"] == OUTPUTS
    hint = json.loads(follow[0]["hint"])
    assert hint["removed"] == DB and hint["reference"] == "output.db" and "module.foundation" in hint["platform"]
    assert hint["action"] == (f"A previous repair answer deleted {DB}, as its diagnostic requires, but output.db "
                              f"still references it. {DB} stays deleted: delete this reference (a depends_on entry, "
                              "or an output that only re-exports it) or point it at an address that exists.")
    assert "Your previous answer" not in iac.tasks[1].prompt()


def test_po1b_same_persona_loop_prompt_is_unchanged():
    """Do No Harm: the persona that deleted the block also owns the referencing file -> pre-PO-1b hint, byte for
    byte, inside the rendered prompt."""
    iac = IaC()
    RepairLoop(_loop(iac)).run({CUSTOM: TOPIC + DB_BLOCK, OUTPUTS: OUT_TOPIC + OUT_DB})
    follow = [x for x in iac.tasks[1].diagnostics if x["code"] == "TF.REFERENCE_TO_UNDECLARED_RESOURCE"]
    assert follow[0]["hint"] == _pre_po1b_hint(REF, DB)
    assert json.loads(follow[0]["hint"])["action"].startswith(f"Your previous answer deleted {DB}, ")


def test_po1b_reference_outside_any_block_says_this_file_never_none():
    """F2: enclosing_block -> None. The sentence names "this file"; the JSON reference stays null (the fact)."""
    loose = REF.model_copy(update={"block_address": None})
    for own in (True, False):
        hint = json.loads(followup_hint(loose, DB, own=own))
        assert hint["reference"] is None
        assert "None" not in hint["action"] and "but this file still references it." in hint["action"]


def _followup_tasks(followups, persona_of_outputs="IAC_ENGINEER"):
    from shared.diagnostics import RepairLedger
    loop = RepairLoop(_loop(IaC(), persona_of_outputs=persona_of_outputs))
    d = {CUSTOM: TOPIC + DB_BLOCK, OUTPUTS: OUT_TOPIC + OUT_DB}
    report, routes = loop.validate(d, loop.ctx.assemble(d), 0)
    tasks = loop._tasks(d, report, routes, RepairLedger(trace_id="t1"), loop.ctx.settings, {}, 0, followups)
    return {t.persona: t for t in tasks}


def _follow_entries(task):
    return sorted(((x["block"], json.loads(x["hint"])["removed"]) for x in task.diagnostics
                   if x["code"] == "TF.REFERENCE_TO_UNDECLARED_RESOURCE"), key=str)


def test_po1b_followup_dedup_is_on_code_file_block_symbol():
    """F2: the dedup key includes the symbol: two removed addresses referenced from one block (or from outside any
    block) each keep their entry; an identical finding offered twice is listed once."""
    other = "google_pubsub_topic.t"
    ref_other = REF.model_copy(update={"symbol": other})
    loose, loose_other = (x.model_copy(update={"block_address": None}) for x in (REF, ref_other))
    tasks = _followup_tasks([(REF, OWNED, DB), (ref_other, OWNED, other), (REF, OWNED, DB)])
    assert _follow_entries(tasks["IAC_ENGINEER"]) == [("output.db", DB), ("output.db", other)]
    tasks = _followup_tasks([(loose, OWNED, DB), (loose_other, OWNED, other), (loose, OWNED, DB)])
    assert _follow_entries(tasks["IAC_ENGINEER"]) == [(None, DB), (None, other)]


def test_po1b_task_files_are_unchanged_by_the_wording():
    """Wording only: own and cross-persona follow-ups offer the same files to the same personas."""
    devops = Routing(ErrorClass.CODE_DEFECT, "DEVOPS_ENGINEER", OUTPUTS, 2, None)
    own = _followup_tasks([(REF, OWNED, DB)])
    cross = _followup_tasks([(REF, devops, DB)], persona_of_outputs="DEVOPS_ENGINEER")
    assert {p: sorted(t.files_to_fix) for p, t in own.items()} == {"IAC_ENGINEER": [CUSTOM, OUTPUTS]}
    assert {p: sorted(t.files_to_fix) for p, t in cross.items()} == {"DEVOPS_ENGINEER": [OUTPUTS],
                                                                       "IAC_ENGINEER": [CUSTOM]}
    own_hint = [x["hint"] for x in own["IAC_ENGINEER"].diagnostics if x["file"] == OUTPUTS][0]
    cross_hint = [x["hint"] for x in cross["DEVOPS_ENGINEER"].diagnostics if x["file"] == OUTPUTS][0]
    assert own_hint == _pre_po1b_hint(REF, DB) and "Your previous answer" not in cross_hint

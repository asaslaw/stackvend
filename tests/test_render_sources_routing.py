"""QA-STOP-RENDER-SOURCES + QA-RECORD-HCL-FIELD (owner 11-14 "yes, approve A-E"; plan
docs/planning/render-sources-routing-plan.md; diagnosis docs/handoff/ex08-1114-qa-routing-diagnosis.md sections 3-5).

B: shared.artifact_ownership.RENDER_SOURCES maps each platform render to its typed sources. A QA finding on a render
in the explicit map REPAIR_THROUGH (custom.tf.json -> iac_intent.json) is seeded on that document; every
other render finding stays the typed PLATFORM_DEFECT stop, whose message and details now name the sources and say
whether it is a platform capability gap or an architect/topology issue. E: DeterministicGateReport.hcl_syntax_passed
is None when the producer did not check HCL (QA never does), never a misleading False. Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import hashlib
import os
import sys

import pytest

TESTS = os.path.dirname(__file__)
REPO = os.path.dirname(TESTS)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

import test_qa_feedback  # noqa: E402,F401  (puts the gateway on sys.path)
from test_qa_feedback import _feedback, _qa_diag  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent.runtime_pin import PLATFORM_PYTHON_VERSION_CONTENT  # noqa: E402
from qa_auditor import judge_input as JI  # noqa: E402
from shared import artifact_ownership as AO  # noqa: E402
from shared import iac_intent as II  # noqa: E402

W = "infra/workload/"
MAIN_PY = "apps/shop/main.py"
TEST_PY = "apps/shop/tests/test_main.py"
INTENT = W + "iac_intent.json"
CUSTOM = W + "custom.tf.json"
TOPO = W + "topology.json"
PYV = "apps/shop/.python-version"
WF = ".github/workflows/deploy-shop.yml"
TREE = {MAIN_PY: "app = 1\n", TEST_PY: "def test_a():\n    assert True\n", INTENT: '{"modules": []}\n',
        CUSTOM: "{}\n", TOPO: "{}\n", W + "main.tf": "# rendered\n", W + "services.tf": "# rendered\n",
        W + "variables.tf": "# rendered\n", W + "outputs.tf": "# rendered\n", W + "moved.tf": "# rendered\n",
        W + "intent_facts.tf.json": "{}\n", W + "terraform.tfvars": "x = 1\n", WF: "on: push\n",
        "cloudbuild.yaml": "steps: []\n", PYV: PLATFORM_PYTHON_VERSION_CONTENT}
DRAFT = [MAIN_PY, TEST_PY, INTENT]


def _jd(file, code="JUDGE.ADHERENCE", line=None):
    return dict(_qa_diag(file=file, code=code, line=line), tool="judge", **{QR.JUDGE_FINDING_FIELD: True})


def _plan(*diags, tree=TREE, draft=DRAFT, reason=None, **kw):
    fb = _feedback(tree, *diags, draft_paths=draft, **kw)
    if reason is not None:
        fb[QR.QA_REASON_FIELD] = reason
    return QR.plan_qa_repair(fb, stack_configured=True)


# ------------------------------------------------------------------------------------------------ the table
def test_artifact_ownership_copies_are_byte_identical():
    digests = {p: hashlib.sha256(open(os.path.join(REPO, p), "rb").read()).hexdigest()
               for p in ("shared/artifact_ownership.py", "apps/orchestrator-gateway/shared/artifact_ownership.py")}
    assert len(set(digests.values())) == 1, digests


def _defined_names(path):
    tree = ast.parse(open(os.path.join(REPO, path), encoding="utf-8").read())
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            out |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.add(node.target.id)
    return out


@pytest.mark.parametrize("key", sorted(AO.RENDER_SOURCES))
def test_every_source_ref_names_real_code(key):
    for src in AO.RENDER_SOURCES[key]:
        path, symbol = src.ref
        assert os.path.isfile(os.path.join(REPO, path)), (key, src)
        assert symbol in _defined_names(path), (key, src)
        assert isinstance(src.owner, AO.SourceOwner) and src.source


def test_every_platform_render_has_sources_and_no_other_file_does():
    """Completeness against the one registry (judge_input.is_platform_rendered): every file it calls a render has a
    row; app files and the AI's intent have none."""
    for path, content in TREE.items():
        rendered = JI.is_platform_rendered(path, content)
        assert bool(JI.render_sources_of(path, content)) is rendered, path
    for floor in AO.PLATFORM_RENDERED_FLOOR | {II.RENDER_PATH, II.FACTS_RENDER_PATH, W + "terraform.tfvars"}:
        assert floor in AO.RENDER_SOURCES, floor
    assert JI.render_sources_of(".python-version", PLATFORM_PYTHON_VERSION_CONTENT) == AO.RENDER_SOURCES[
        AO.RUNTIME_PIN_RENDER]
    assert JI.render_sources_of(PYV, "3.11\n") == ()                   # not the platform's pin: the AI's file
    assert JI.render_sources_of(".github/workflows/mine.yml", "x") == ()  # a person's own CI file
    assert JI.render_sources_of(INTENT, "{}") == ()                     # the AI's document is not a render


def test_only_custom_tf_json_is_repaired_through_a_developer_document():
    assert dict(AO.REPAIR_THROUGH) == {II.RENDER_PATH: II.INTENT_PATH}
    assert AO._INTENT_DOC == II.INTENT_PATH and AO._INTENT_RENDER == II.RENDER_PATH


def test_repair_through_names_a_developer_document_of_its_render_row():
    for render, doc in AO.REPAIR_THROUGH.items():
        assert doc in {s.path for s in AO.RENDER_SOURCES[render] if s.owner is AO.SourceOwner.DEVELOPER}, render


def test_the_custom_tf_json_row_names_the_platform_additions_honestly():
    """RT F1: the renderer adds platform fact expressions, realization-required arguments, forced arguments and
    generated secret versions to the intent; the row says so (routing is REPAIR_THROUGH, not the row length)."""
    row = AO.RENDER_SOURCES[II.RENDER_PATH]
    assert [s.owner for s in row] == [AO.SourceOwner.DEVELOPER] + [AO.SourceOwner.PLATFORM] * 3
    assert [s.ref for s in row[1:]] == [("shared/iac_intent.py", "FACTS"),
                                        ("shared/iac_intent.py", "REALIZATION_REQUIRED_ARGS"),
                                        ("shared/iac_intent.py", "GENERATED_SECRET_ARG")]


def test_topology_json_names_the_architect_record_and_the_platform_catalog():
    owners = [s.owner for s in AO.RENDER_SOURCES[TOPO]]
    assert owners == [AO.SourceOwner.ARCHITECT, AO.SourceOwner.PLATFORM]
    assert AO.render_stop_kind(AO.RENDER_SOURCES[TOPO]) == AO.STOP_TOPOLOGY_OR_PLATFORM_GAP


@pytest.mark.parametrize("key,kind", [
    (W + "main.tf", AO.STOP_TOPOLOGY_OR_PLATFORM_GAP), (W + "services.tf", AO.STOP_TOPOLOGY_OR_PLATFORM_GAP),
    (AO.DEPLOY_WORKFLOW_RENDER, AO.STOP_TOPOLOGY_OR_PLATFORM_GAP), ("cloudbuild.yaml", AO.STOP_TOPOLOGY_OR_PLATFORM_GAP),
    (W + "variables.tf", AO.STOP_PLATFORM_CAPABILITY_GAP), (W + "outputs.tf", AO.STOP_PLATFORM_CAPABILITY_GAP),
    (W + "moved.tf", AO.STOP_PLATFORM_CAPABILITY_GAP), (W + "terraform.tfvars", AO.STOP_PLATFORM_CAPABILITY_GAP),
    (W + "intent_facts.tf.json", AO.STOP_PLATFORM_CAPABILITY_GAP),
    (AO.RUNTIME_PIN_RENDER, AO.STOP_PLATFORM_CAPABILITY_GAP),
])
def test_stop_kind_by_owner_only(key, kind):
    assert AO.render_stop_kind(AO.RENDER_SOURCES[key]) == kind
    assert key not in AO.REPAIR_THROUGH


def test_render_repair_target_needs_a_render_in_the_map_negative():
    draft = {INTENT: "x"}
    assert QR.render_repair_target(CUSTOM, TREE, draft) == INTENT
    assert QR.render_repair_target(TOPO, TREE, draft) is None                    # a render outside the map
    assert QR.render_repair_target(INTENT, TREE, draft) is None                  # the document itself
    assert QR.render_repair_target(None, TREE, draft) is None


# ------------------------------------------------------------------------------------------------ routing (B)
def test_a_custom_tf_json_finding_is_seeded_on_the_intent():
    plan = _plan(_jd(CUSTOM, line=7))
    assert (plan.mode, plan.reason) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES")
    assert [(s.file, s.line) for s in plan.seeds] == [(INTENT, None)]       # a render line is not an intent line
    assert CUSTOM in plan.seeds[0].message and plan.seed_files == {INTENT: TREE[INTENT]}
    assert "from this file and platform tables" in plan.seeds[0].message      # RT F1: never "this file only"
    assert "only" not in plan.seeds[0].message
    assert QR.render_repair_target(CUSTOM, TREE, plan.draft) == INTENT


def test_a_custom_tf_json_finding_rides_no_longer_as_text_beside_a_sandbox_finding():
    plan = _plan(_qa_diag(file=MAIN_PY), _jd(CUSTOM))
    assert plan.mode == QR.QA_REPAIR and plan.repairable_paths == {MAIN_PY, INTENT}


def test_without_an_intent_the_custom_tf_json_route_is_unchanged_negative():
    tree = {k: v for k, v in TREE.items() if k != INTENT}
    plan = _plan(_jd(CUSTOM), tree=tree, draft=[MAIN_PY, TEST_PY])
    assert (plan.mode, plan.reason, plan.off_draft_files, plan.seeds) == (QR.REGENERATE, QR.NOT_ON_A_DRAFT_FILE, (),
                                                                          ())
    assert QR.render_repair_target(CUSTOM, tree, {MAIN_PY: "x"}) is None
    assert QR.render_repair_target(CUSTOM, {}, {INTENT: "x"}) is None        # not a file of the tested tree


@pytest.mark.parametrize("other", [TOPO, W + "main.tf"])
def test_custom_tf_json_and_another_render_judge_findings_stage2_only_still_stop(other):
    """RT F2 (conservative option): a routed custom.tf.json finding never unlocks ride-along. With a judge finding on
    topology.json / main.tf beside it on a Stage 2-only failure the plan is the same typed stop as before the route
    (custom.tf.json was never a stop file: it was the AI's document), not a QA repair with the render as text."""
    plan = _plan(_jd(CUSTOM), _jd(other), reason=QR.STAGE2_FAILED_REASON)
    assert (plan.mode, plan.reason, plan.stop_files) == (QR.STOP, QR.PLATFORM_RENDERED_REASON, (other,))
    plan = _plan(_jd(other), _jd(CUSTOM), reason=QR.STAGE2_FAILED_REASON)      # order does not matter
    assert (plan.mode, plan.reason, plan.stop_files) == (QR.STOP, QR.PLATFORM_RENDERED_REASON, (other,))


def test_an_intent_finding_still_lets_another_render_ride_along_stage2_only_negative():
    """QA-STAGE2-ONLY-REPAIR is unchanged: beside a judge finding that names a draft file the render rides along."""
    plan = _plan(_jd(INTENT), _jd(TOPO), reason=QR.STAGE2_FAILED_REASON)
    assert plan.mode == QR.QA_REPAIR and [s.file for s in plan.seeds] == [INTENT]


@pytest.mark.parametrize("finding", [_jd(INTENT), _qa_diag(file=MAIN_PY, line=3), _jd(MAIN_PY, line=4)])
def test_findings_on_draft_files_are_seeded_exactly_as_before_negative(finding):
    """Do No Harm: a finding that names a draft file keeps its file, line and message (the 08b route included)."""
    plan = _plan(finding)
    (seed,) = plan.seeds
    assert (plan.mode, seed.file, seed.line) == (QR.QA_REPAIR, finding["file"], finding["line"])
    assert seed.message == f"QA finding 1 ({finding['code']}) in this file: see QA TEST OUTPUT finding 1"


@pytest.mark.parametrize("path", [TOPO, W + "main.tf", W + "services.tf", W + "variables.tf", W + "outputs.tf",
                                  W + "moved.tf", W + "intent_facts.tf.json", W + "terraform.tfvars", WF,
                                  "cloudbuild.yaml", PYV])
def test_every_other_render_stays_the_typed_stop(path):
    plan = _plan(_jd(path))
    assert (plan.mode, plan.reason, plan.stop_files, plan.seeds) == (QR.STOP, QR.PLATFORM_RENDERED_REASON, (path,), ())
    assert plan.stop_kinds == {path: AO.render_stop_kind(JI.render_sources_of(path, TREE[path]))}
    assert plan.summary()["stop_kinds"] == dict(plan.stop_kinds)


def test_ex08_topology_stop_names_its_sources_and_kind():
    """ex08-1114: the INFRA-04 judge finding on topology.json. Still PLATFORM_DEFECT; the message now says what the
    render comes from and that it is an architect/topology issue or a platform capability gap."""
    finding = _jd(TOPO)
    plan = _plan(finding)
    body = QR.stop_error(plan, "shop", _feedback(TREE, finding, draft_paths=DRAFT)).to_body()
    assert (body["error_class"], body["reason"], body["stage"]) == ("PLATFORM_DEFECT", QR.PLATFORM_RENDERED_REASON,
                                                                    "qa")
    (fact,) = body["details"]["render_sources"]
    assert fact["file"] == TOPO and fact["kind"] == AO.STOP_TOPOLOGY_OR_PLATFORM_GAP
    assert [s["owner"] for s in fact["sources"]] == ["ARCHITECT", "PLATFORM"]
    assert fact["sources"][1]["ref"] == "shared/service_topology.py:BOOTSTRAP_CATALOG"
    msg = body["summary"]
    assert "architect service topology record (workloads.service_topology.record) [ARCHITECT]" in msg
    assert "topology catalog (the attributes a topology can bind) [PLATFORM]" in msg
    assert "an architect/topology issue, or a platform capability gap" in msg
    assert finding["message"] not in msg                                  # QA's untrusted text never in the stop


def test_a_platform_only_render_stop_says_platform_capability_gap():
    finding = _jd(W + "outputs.tf")
    body = QR.stop_error(_plan(finding), "shop", _feedback(TREE, finding, draft_paths=DRAFT)).to_body()
    assert body["details"]["render_sources"][0]["kind"] == AO.STOP_PLATFORM_CAPABILITY_GAP
    assert "This is a platform capability gap" in body["summary"]
    assert body["details"]["files"] == [W + "outputs.tf"]                  # the existing details are unchanged


def test_stop_error_without_a_tree_still_stops_typed():
    plan = QR.QARepairPlan(QR.STOP, QR.PLATFORM_RENDERED_REASON, stop_files=(TOPO,))
    body = QR.stop_error(plan, "shop", None).to_body()
    assert body["error_class"] == "PLATFORM_DEFECT" and body["details"]["render_sources"][0]["kind"]
    unknown = QR.render_stop_facts(["apps/x.py"], {})
    assert unknown == [{"file": "apps/x.py", "kind": None, "sources": []}]


def test_the_scenario_corpus_has_fixture_08b():
    import scenario_replay as SR
    ids = {SR.load_scenario(p)["id"] for p in SR.scenario_files()}
    assert any(i.startswith("08b-") for i in ids), ids


# ------------------------------------------------------------------------------------------------ E: the QA record
def test_hcl_syntax_passed_is_not_checked_by_default_and_explicit_values_are_kept():
    from shared.qa_audit_schemas import DeterministicGateReport
    assert DeterministicGateReport(passed=True).hcl_syntax_passed is None
    assert DeterministicGateReport(passed=True, hcl_syntax_passed=False).hcl_syntax_passed is False
    assert DeterministicGateReport(passed=True, hcl_syntax_passed=True).hcl_syntax_passed is True
    assert DeterministicGateReport(passed=True).model_dump()["hcl_syntax_passed"] is None


def test_the_stage2_composite_records_hcl_as_not_checked():
    from qa_auditor.coordinator import DualLensAuditorCoordinator
    determ = DualLensAuditorCoordinator._coerce_determ({"passed": True, "pytest_success": True})
    assert determ.hcl_syntax_passed is None and determ.hcl_errors == []


@pytest.mark.parametrize("determ,want", [
    ({"passed": True, "hcl_errors": []}, "HCL syntax not checked by QA"),
    ({"passed": True, "hcl_syntax_passed": None}, "HCL syntax not checked by QA"),
    ({"passed": True, "hcl_syntax_passed": True}, "0 HCL syntax errors"),           # negative: a real check counts
    ({"passed": True, "hcl_syntax_passed": False, "hcl_errors": ["a", "b"]}, "2 HCL syntax errors"),
    ({"passed": True, "hcl_errors": ["a"]}, "1 HCL syntax errors"),                 # listed errors always count
])
def test_release_certificate_reads_the_hcl_field_honestly(determ, want):
    import release_gatekeeper as RG
    dec = RG.evaluate_release_decision(determ, {"passed": True}, {"passed": True, "instruction_adherence_score": 1.0,
                                                                    "grounding_score": 1.0}, {})
    row = [ln for ln in dec.release_certificate_markdown.splitlines() if "Deterministic Hard Gate" in ln][0]
    assert want in row, row

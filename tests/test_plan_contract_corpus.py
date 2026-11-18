"""PLAN-CONTRACT-CHECK corpus (plan docs/planning/plan-contract-check-plan.md §8.3, W4): real architect plans, typed and
anonymized, run through the platform plan contract (`architect_agent.plan_contract`, interface §8.1).

One entry = one JSON file in tests/plan_contract_corpus/ (not globbed by tests/scenario_replay.py, which reads only
scenario_corpus/). Each file holds the plan exactly as the architect typed it (the raw model JSON of the plan the
gate would see), its provenance, what was anonymized, and the expected violations per VCS kind:

* live runs (Carbon, read-only from the architect stage trace `agent_output`): ex01-g13 (root `cloudbuild.yaml` typed
  in INFRA-05 and STEP-CICD: refused on GITHUB), ex02-g13 (privileged role in prose only: must PASS, the v1 IAM gap,
  pins invariant 2), and two passing controls (ex04-g13, ex09-g13);
* recorded eval cassettes (Flash): example 04 plans with a Dockerfile, a root `cloudbuild.yaml`, a non-deploy
  workflow, an app-level `cloudbuild.yaml` (passes), two with a pre-existing DAG error (re-planned or stripped, never
  refused for it), and valid controls incl. negated / conditional roles in prose.

The expectations were derived from the real platform predicates (`qa_auditor.judge_input.is_platform_ci_path`,
`is_platform_deploy_workflow`, `developer_agent.handler.is_prohibited_container_file`); the corpus-data tests below
re-check that, so the data stays honest even if the contract module changes. No network, no credentials, no model.
"""
import hermetic_guard  # noqa: F401  (first import)

import copy
import glob
import json
import os
import re
import sys
from types import SimpleNamespace

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from architect_agent.schemas import ArchitecturePlan  # noqa: E402

CORPUS_DIR = os.path.join(REPO_ROOT, "tests", "plan_contract_corpus")
VCS_KINDS = ("GITHUB", "SERVERLESS_GIT", None)
CI_CODE, CONTAINER_CODE = "PLAN.PLATFORM_CI_FILE", "PLAN.CONTAINER_FILE"
NOT_CHECKED_ROOT = "PLAN.PLATFORM_CI_FILE:cloudbuild.yaml (vcs unknown)"   # plan §2.1, verbatim
ROOT_CLOUDBUILD = "cloudbuild.yaml"
ADDRESS_RE = re.compile(r"^(infra_tasks|code_tasks|sequenced_build_plan\.steps)\[([^\]]+)\]\.target_files\[(\d+)\]$")
# The entries plan §8.3 names (W4); more may be added (data only).
REQUIRED_IDS = (
    "ex01-g13-cloudbuild-plan",
    "ex02-g13-prose-role-plan",
    "ex04-gatea-rerec-r1-dockerfile-orphans",
    "ex04-gatea-r1-root-cloudbuild",
    "ex04-gatea-r3-app-cloudbuild",
    "ex04-ti5r2-r1-build-and-push",
    "ex04-44a2747-r3-ordering-inverted-dockerfile",
    "s6-ti0-gate-b-r1-negated-owner",
    "ex06-fd4amc-r2-conditional-token-creator",
    "ex01-gatea-rerec-r1-control",
    "ex06-gatea-rerec-r1-control",
)
PROSE_FIELDS = ("task_id", "step_id", "title", "category", "description", "acceptance_criteria", "depends_on",
                "assigned_agent", "priority", "step_index")


# ------------------------------------------------------------------------------------------------ corpus loading
def _load_entries():
    out = []
    for path in sorted(glob.glob(os.path.join(CORPUS_DIR, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            entry = json.load(fh)
        entry["_file"] = os.path.basename(path)
        out.append(entry)
    return out


ENTRIES = _load_entries()
BY_ID = {e["id"]: e for e in ENTRIES}


def _expect(entry, vcs_kind):
    for case in entry["expect"]:
        if case["vcs_kind"] == vcs_kind:
            return case
    raise AssertionError(f"{entry['id']}: no expectation for vcs_kind={vcs_kind!r}")


def _violating(entry, vcs_kind="GITHUB"):
    return bool(_expect(entry, vcs_kind)["violations"])


VALID = [e for e in ENTRIES if not any(_violating(e, v) for v in VCS_KINDS)]
VIOLATING = [e for e in ENTRIES if _violating(e, "GITHUB")]
DAG_PREEXISTING = [e for e in VIOLATING if not e["dag_preexisting"]["is_valid"]]


def load_plan(entry):
    """A fresh ArchitecturePlan from the entry, parsed the way the architect handler parses a model answer: the
    topology is kept raw (the topology gate validates it, not this parse)."""
    data = copy.deepcopy(entry["plan"])
    raw_topology = data.pop("service_topology", None)
    plan = ArchitecturePlan(**data)
    plan._raw_service_topology = raw_topology
    return plan


def _items(plan):
    """address prefix -> item, every task and build step."""
    out = {}
    for t in plan.infra_tasks:
        out[f"infra_tasks[{t.task_id}]"] = t
    for t in plan.code_tasks:
        out[f"code_tasks[{t.task_id}]"] = t
    for s in (plan.sequenced_build_plan.steps if plan.sequenced_build_plan else []):
        out[f"sequenced_build_plan.steps[{s.step_id}]"] = s
    return out


def _remove_exact(plan, violations):
    """The faithful re-plan / strip oracle: drop exactly the expected entries (by block address), nothing else."""
    by_item = {}
    for v in violations:
        m = ADDRESS_RE.match(v["block_address"])
        assert m, v["block_address"]
        by_item.setdefault(f"{m.group(1)}[{m.group(2)}]", []).append((int(m.group(3)), v["symbol"]))
    items = _items(plan)
    for prefix, hits in by_item.items():
        item = items[prefix]
        for index, symbol in sorted(hits, reverse=True):
            assert item.target_files[index] == symbol
        drop = {i for i, _ in hits}
        item.target_files = [f for i, f in enumerate(item.target_files) if i not in drop]
    return plan


def _prose(plan):
    """Every task/step field except target_files, in order (what a strip must never touch)."""
    return {prefix: {k: v for k, v in item.model_dump(mode="json").items() if k in PROSE_FIELDS}
            for prefix, item in _items(plan).items()}


def _plan_without_targets(plan):
    d = plan.model_dump(mode="json")
    for key in ("infra_tasks", "code_tasks"):
        for t in d[key]:
            t.pop("target_files")
    for s in (d.get("sequenced_build_plan") or {}).get("steps") or []:
        s.pop("target_files")
    return json.dumps(d, sort_keys=True)


def _triples(diags):
    return [(d.code, d.symbol, d.block_address) for d in diags]


def _expected_triples(entry, vcs_kind):
    return [(v["code"], v["symbol"], v["block_address"]) for v in _expect(entry, vcs_kind)["violations"]]


def _field(d, key):
    """A diagnostic as the error body carries it: a dict (to_body form) or a Diagnostic."""
    return d[key] if isinstance(d, dict) else getattr(d, key)


def _ids(entries):
    return [e["id"] for e in entries]


@pytest.fixture
def pc():
    """The plan-contract module (W1). Imported here, not at collection, so the corpus-data tests run on their own."""
    from architect_agent import plan_contract
    return plan_contract


def _never_called(*_a, **_k):
    raise AssertionError("replan_fn must not be called")


def _gate(pc, plan, vcs_kind="GITHUB", replan_fn=None, is_map_reduce=False):
    return pc.gate_plan_contract(plan, vcs_kind=vcs_kind, replan_fn=replan_fn, is_map_reduce=is_map_reduce,
                                 trace_id="trace-corpus", product_id=plan.product_id,
                                 read_model_build_plan=lambda: True)


# ------------------------------------------------------------------------------------------------ corpus data
def test_corpus_entries_are_complete():
    assert ENTRIES, "tests/plan_contract_corpus/ is empty"
    for rid in REQUIRED_IDS:
        assert rid in BY_ID, f"missing corpus entry {rid}"
    for e in ENTRIES:
        assert e["_file"] == e["id"] + ".json"
        for key in ("summary", "source", "anonymized", "expect", "dag_preexisting", "plan"):
            assert key in e, (e["id"], key)
        assert e["source"]["kind"] in ("live", "cassette"), e["id"]
        assert [c["vcs_kind"] for c in e["expect"]] == list(VCS_KINDS), e["id"]
        load_plan(e)   # every entry is a plan the architect schema accepts
    # the shapes the plan asks for are all present
    assert VALID and VIOLATING and DAG_PREEXISTING
    assert {e["id"] for e in DAG_PREEXISTING} >= {"ex04-gatea-rerec-r1-dockerfile-orphans",
                                                  "ex04-44a2747-r3-ordering-inverted-dockerfile"}


def test_corpus_is_anonymized():
    """No home paths, install / host project names, run trace ids or e-mail addresses in the data;
    live plans carry no live workload id (the run label stays in the provenance only)."""
    forbidden = re.compile(r"/(?:Users|home)/|stackvend\d|castor-\d|intake-ex|[\w.+-]+@[\w-]+\.[\w.-]+", re.IGNORECASE)
    for path in sorted(glob.glob(os.path.join(CORPUS_DIR, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        hit = forbidden.search(text)
        assert hit is None, f"{os.path.basename(path)}: {hit.group(0)!r}"
    for e in ENTRIES:
        if e["source"]["kind"] == "live":
            assert re.search(r"g13", json.dumps(e["plan"]), re.IGNORECASE) is None, e["id"]
        sbp = e["plan"].get("sequenced_build_plan") or {}
        assert sbp.get("trace_id") is None, e["id"]
        assert e["plan"].get("assigned_cidr_block") is None, e["id"]


def test_expectations_match_the_real_platform_predicates():
    """The corpus expectations are the developer's own exact rules (independent of the contract module)."""
    from qa_auditor import judge_input as ji
    from developer_agent.handler import is_prohibited_container_file
    for e in ENTRIES:
        plan = load_plan(e)
        items = _items(plan)
        for vcs in VCS_KINDS:
            flagged = set()
            for v in _expect(e, vcs)["violations"]:
                m = ADDRESS_RE.match(v["block_address"])
                assert m, (e["id"], v)
                item = items[f"{m.group(1)}[{m.group(2)}]"]
                assert item.target_files[int(m.group(3))] == v["symbol"], (e["id"], v)
                if v["code"] == CI_CODE:
                    assert ji.is_platform_ci_path(v["symbol"]) and not ji.is_platform_deploy_workflow(v["symbol"])
                    if v["symbol"] == ji.SERVERLESS_GIT_PIPELINE_FILE:
                        assert vcs == ji.VCS_GITHUB, (e["id"], vcs)
                else:
                    assert v["code"] == CONTAINER_CODE and is_prohibited_container_file(v["symbol"]), (e["id"], v)
                flagged.add(v["block_address"])
            # every unflagged target is one the developer keeps (or, root cloudbuild.yaml off GITHUB, writes itself)
            for prefix, item in items.items():
                for i, f in enumerate(item.target_files):
                    if f"{prefix}.target_files[{i}]" in flagged:
                        continue
                    assert not is_prohibited_container_file(f), (e["id"], vcs, f)
                    if ji.is_platform_ci_path(f):
                        assert ji.is_platform_deploy_workflow(f) or (f == ROOT_CLOUDBUILD and vcs != ji.VCS_GITHUB), \
                            (e["id"], vcs, f)


def test_prose_markers_are_present_in_prose_only():
    """The entries that pin invariant 2 really carry the role / file in prose (and not in a typed target)."""
    marked = [e for e in ENTRIES if e.get("prose_markers")]
    assert {e["id"] for e in marked} >= {"ex02-g13-prose-role-plan", "s6-ti0-gate-b-r1-negated-owner",
                                         "ex06-fd4amc-r2-conditional-token-creator"}
    for e in marked:
        items = _items(load_plan(e))
        for m in e["prose_markers"]:
            item = items[m["item"]]
            if m["field"] == "description":
                text = item.description
            else:
                text = item.acceptance_criteria[int(re.fullmatch(r"acceptance_criteria\[(\d+)\]", m["field"]).group(1))]
            assert m["contains"] in text, (e["id"], m)
    ex02 = BY_ID["ex02-g13-prose-role-plan"]
    targets = [f for item in _items(load_plan(ex02)).values() for f in item.target_files]
    assert not any("roles/" in f for f in targets)


# ------------------------------------------------------------------------------------------------ check_plan_contract
@pytest.mark.parametrize("vcs_kind", VCS_KINDS, ids=["GITHUB", "SERVERLESS_GIT", "None"])
@pytest.mark.parametrize("entry", ENTRIES, ids=_ids(ENTRIES))
def test_check_matches_corpus(pc, entry, vcs_kind):
    plan = load_plan(entry)
    violations, not_checked = pc.check_plan_contract(plan, vcs_kind)
    assert _triples(violations) == _expected_triples(entry, vcs_kind)
    for d in violations:
        assert (d.tool, d.severity, d.source, d.file) == ("platform", "error", "architect", "architect:plan")
        assert getattr(d.error_class, "value", d.error_class) == "ARCHITECT_DEFECT"
    if vcs_kind is None:
        assert set(not_checked) <= {NOT_CHECKED_ROOT}
        if any(f == ROOT_CLOUDBUILD for item in _items(plan).values() for f in item.target_files):
            assert not_checked == [NOT_CHECKED_ROOT]
    else:
        assert not_checked == []


@pytest.mark.parametrize("entry", ENTRIES, ids=_ids(ENTRIES))
def test_check_is_read_only(pc, entry):
    plan = load_plan(entry)
    before = plan.model_dump_json()
    for vcs in VCS_KINDS:
        pc.check_plan_contract(plan, vcs)
    assert plan.model_dump_json() == before


# ------------------------------------------------------------------------------------------------ the gate (Do No Harm)
@pytest.mark.parametrize("mode", ["STRIP", "FAIL"])
@pytest.mark.parametrize("entry", VALID, ids=_ids(VALID))
def test_valid_plan_passes_as_the_same_object(pc, monkeypatch, entry, mode):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", mode)
    for vcs in VCS_KINDS:
        plan = load_plan(entry)
        before = plan.model_dump_json()
        result = _gate(pc, plan, vcs_kind=vcs, replan_fn=_never_called)
        assert result.outcome == "PASSED"
        assert result.plan is plan
        assert plan.model_dump_json() == before
        assert pc.render_contract_note(result.record) == ""


# ------------------------------------------------------------------------------------------------ exhaustion: STRIP / FAIL
def _judge_dag(plan):
    """The QA task DAG as the gateway hands it to the judge (infra tasks then code tasks, model_dump JSON form)."""
    return [t.model_dump(mode="json") for t in list(plan.infra_tasks) + list(plan.code_tasks)]


def _judge_facts(plan):
    from qa_auditor import judge_input
    return judge_input.platform_facts_text("GITHUB", "off", _judge_dag(plan))


@pytest.mark.parametrize("entry", VIOLATING, ids=_ids(VIOLATING))
def test_strip_removes_exactly_the_flagged_entries(pc, monkeypatch, entry):
    """Every flagged entry is removed, except (code review finding 1) one that the QA judge's per-task facts rest on
    in an infra or code task: that one is kept and recorded. The judge's facts are byte-identical after the strip."""
    from qa_auditor import judge_input
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "STRIP")
    plan = load_plan(entry)
    prose, rest = _prose(plan), _plan_without_targets(plan)
    kinds_before = [judge_input.task_fact_kinds(t) for t in _judge_dag(plan)]
    facts_before = _judge_facts(plan)

    result = _gate(pc, plan, replan_fn=None)   # no model -> exhaustion NO_MODEL -> strip the draft
    assert result.outcome == "STRIPPED"
    assert result.plan is plan
    assert result.record["stopped"] == "NO_MODEL"
    removed = sorted((s["id"], r["path"], r["code"]) for s in result.record["stripped"] for r in s["removed"])
    kept = sorted((s["id"], k["path"], k["code"]) for s in result.record["stripped"] for k in s.get("kept") or [])
    flagged = _expect(entry, "GITHUB")["violations"]
    want = sorted((ADDRESS_RE.match(v["block_address"]).group(2), v["symbol"], v["code"]) for v in flagged)
    assert sorted(removed + kept) == want                                    # an exact partition of the flagged set
    for s in result.record["stripped"]:
        for k in s.get("kept") or []:
            assert s["kind"] in ("infra_task", "code_task")                 # build steps are never judged
            assert judge_input.is_platform_ci_path(k["path"]) and k["reason"] == "JUDGE_TASK_FACTS"
    # the judge's per-task facts are unchanged by the strip
    assert [judge_input.task_fact_kinds(t) for t in _judge_dag(plan)] == kinds_before
    assert _judge_facts(plan) == facts_before
    # only target_files changed, and exactly as the oracle says for the removed subset
    kept_keys = {(i, p) for i, p, _c in kept}
    expected = _remove_exact(load_plan(entry), [v for v in flagged if (
        ADDRESS_RE.match(v["block_address"]).group(2), v["symbol"]) not in kept_keys])
    for prefix, item in _items(plan).items():
        assert item.target_files == _items(expected)[prefix].target_files, prefix
    assert _prose(plan) == prose
    assert _plan_without_targets(plan) == rest
    left = pc.check_plan_contract(plan, "GITHUB")[0]
    assert sorted((ADDRESS_RE.match(d.block_address).group(2), d.symbol, d.code) for d in left) == kept
    note = pc.render_contract_note(result.record)
    assert note.startswith("## Platform plan contract")
    for _id, path, _code in want:
        assert path in note


@pytest.mark.parametrize("entry_id", ["ex04-ti5r2-r1-build-and-push", "ex04-gatea-r1-root-cloudbuild"])
def test_strip_keeps_the_judge_ci_fact_of_a_release_task(pc, monkeypatch, entry_id):
    """Code review finding 1 (dry run): CODE-02 (category RELEASE) names `cloudbuild.yaml`; its description still asks
    for it, and that target is the judge's only typed "CI/CD facts apply" signal for the task. The strip keeps it
    (the developer never writes it; the platform deletes it, exactly as today) and still strips the build steps and
    the Dockerfile."""
    from qa_auditor import judge_input
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "STRIP")
    plan = load_plan(BY_ID[entry_id])
    code02 = _items(plan)["code_tasks[CODE-02]"]
    assert getattr(code02.category, "value", code02.category) == "RELEASE"
    assert judge_input.task_fact_kinds(code02.model_dump(mode="json")) == ["CI/CD"]
    result = _gate(pc, plan, replan_fn=None)
    assert ROOT_CLOUDBUILD in code02.target_files
    assert "apps/stream-processor/Dockerfile" not in code02.target_files
    assert judge_input.task_fact_kinds(code02.model_dump(mode="json")) == ["CI/CD"]
    rec = next(s for s in result.record["stripped"] if s["id"] == "CODE-02")
    assert ROOT_CLOUDBUILD in [k["path"] for k in rec["kept"]]
    for prefix, item in _items(plan).items():
        if prefix.startswith("sequenced_build_plan"):
            assert ROOT_CLOUDBUILD not in item.target_files, prefix
    assert "kept in the target files" in pc.render_contract_note(result.record)


def test_ex01_g13_strip_keeps_nothing_the_deploy_workflow_carries_the_ci_fact(pc, monkeypatch):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "STRIP")
    result = _gate(pc, load_plan(BY_ID["ex01-g13-cloudbuild-plan"]), replan_fn=None)
    assert all(not s.get("kept") for s in result.record["stripped"])


@pytest.mark.parametrize("entry", VIOLATING, ids=_ids(VIOLATING))
def test_fail_mode_refuses_with_the_typed_error(pc, monkeypatch, entry):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")
    plan = load_plan(entry)
    before = plan.model_dump_json()
    with pytest.raises(pc.PlanContractViolationError) as ei:
        _gate(pc, plan, replan_fn=None)
    err = ei.value
    assert getattr(err.error_class, "value", err.error_class) == "ARCHITECT_DEFECT"
    assert err.http_status == 422
    assert err.reason == "ARCHITECT_PLAN_CONTRACT_VIOLATION"
    assert err.stage == "architect"
    assert [(_field(d, "code"), _field(d, "symbol"), _field(d, "block_address")) for d in err.diagnostics] == \
        _expected_triples(entry, "GITHUB")
    assert err.details["vcs_kind"] == "GITHUB" and err.details["stopped"] == "NO_MODEL"
    assert err.plan_contract_record["outcome"] == "REFUSED"
    assert plan.model_dump_json() == before   # FAIL never edits the plan


# ------------------------------------------------------------------------------------------------ re-plan acceptance
@pytest.mark.parametrize("entry", VIOLATING, ids=_ids(VIOLATING))
def test_faithful_replan_is_accepted_even_with_a_preexisting_dag_error(pc, monkeypatch, entry):
    """A re-plan that removes exactly the flagged entries is accepted. For the DAG-invalid drafts the error was there
    before the re-plan (baseline), so it never refuses the re-plan; it is recorded as `dag_preexisting`."""
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "FAIL")   # acceptance must not depend on the strip
    draft = load_plan(entry)
    draft_dump = draft.model_dump_json()
    replan = _remove_exact(load_plan(entry), _expect(entry, "GITHUB")["violations"])
    calls = []

    def replan_fn(plan_to_fix, violations):
        calls.append((plan_to_fix, _triples(violations)))
        return SimpleNamespace(architecture_plan=replan)

    result = _gate(pc, draft, replan_fn=replan_fn)
    assert result.outcome == "REPLANNED"
    assert result.plan is replan
    assert len(calls) == 1 and calls[0][0] is draft
    assert calls[0][1] == _expected_triples(entry, "GITHUB")
    assert draft.model_dump_json() == draft_dump   # the draft is never edited on an accepted re-plan
    pre = result.record["dag_preexisting"]
    want = entry["dag_preexisting"]
    assert pre["cycle_detected"] == want["cycle_detected"]
    assert pre["orphan_dependencies"] == want["orphan_dependencies"]
    assert pre["ordering_violations"] == want["ordering_violations"]
    assert (pre["count"] > 0) == (not want["is_valid"])


@pytest.mark.parametrize("entry", DAG_PREEXISTING, ids=_ids(DAG_PREEXISTING))
def test_preexisting_dag_error_is_stripped_never_refused(pc, monkeypatch, entry):
    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "STRIP")
    plan = load_plan(entry)
    result = _gate(pc, plan, replan_fn=None)
    assert result.outcome == "STRIPPED"
    assert result.record["dag_preexisting"]["count"] > 0


# ------------------------------------------------------------------------------------------------ the two live runs
def test_ex01_g13_cloudbuild_plan_is_refused_on_github_and_keeps_the_deploy_workflow(pc, monkeypatch):
    """ex01-g13: the typed plan (not reconstructed from markdown) names root cloudbuild.yaml in BOTH INFRA-05 and
    STEP-CICD (the diagnosis inferred INFRA-05; the stage trace proves it). The deploy workflow next to it passes."""
    entry = BY_ID["ex01-g13-cloudbuild-plan"]
    assert entry["source"]["kind"] == "live"
    plan = load_plan(entry)
    violations, _ = pc.check_plan_contract(plan, "GITHUB")
    assert _triples(violations) == [
        (CI_CODE, ROOT_CLOUDBUILD, "infra_tasks[INFRA-05].target_files[0]"),
        (CI_CODE, ROOT_CLOUDBUILD, "sequenced_build_plan.steps[STEP-CICD].target_files[0]"),
    ]
    deploy = ".github/workflows/deploy-ex01-live.yml"
    assert _items(plan)["infra_tasks[INFRA-05]"].target_files == [ROOT_CLOUDBUILD, deploy]
    assert pc.check_plan_contract(plan, "SERVERLESS_GIT")[0] == []
    assert pc.check_plan_contract(plan, None) == ([], [NOT_CHECKED_ROOT])

    monkeypatch.setattr(pc, "PLAN_CONTRACT_ON_EXHAUSTION", "STRIP")
    _gate(pc, plan, replan_fn=None)
    assert _items(plan)["infra_tasks[INFRA-05]"].target_files == [deploy]
    assert _items(plan)["sequenced_build_plan.steps[STEP-CICD]"].target_files == [deploy]


def test_ex02_g13_prose_role_plan_passes_v1(pc):
    """ex02-g13: roles/iam.serviceAccountTokenCreator is asked for in prose only; v1 reads typed target_files only
    (invariant 2), so the plan passes on every VCS kind. This records the v1 IAM gap (plan §2.3, Q1 deferred)."""
    entry = BY_ID["ex02-g13-prose-role-plan"]
    assert entry["source"]["kind"] == "live"
    for vcs in VCS_KINDS:
        violations, _ = pc.check_plan_contract(load_plan(entry), vcs)
        assert violations == []
    plan = load_plan(entry)
    result = _gate(pc, plan, replan_fn=_never_called)
    assert result.outcome == "PASSED" and result.plan is plan

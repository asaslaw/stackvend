"""QA-REPAIR-ON-CRASH (register row, owner 10-29; gateway only): a QA finding that says pytest crashed (the QA runner's
crash codes: PYTEST.INTERNAL_ERROR, PYTEST.SESSION_ERROR, PYTEST.STARTUP_ERROR) is a targeted QA_REPAIR of the crashed
service's test setup (its `conftest.py`, `tests/__init__.py` and `requirements.txt`, plus the ones outside `apps/`;
the runner names the service through the finding's `file`) with pytest's crash output in the untrusted QA block,
instead of today's regeneration. Decided by the diagnostic code, never by its text. PYTEST.REPORT_INVALID (an
unreadable report after another exit, or exit 0 with failures listed) keeps today's rule (Opus RT F2).

Covered: the code parity with the QA runner; the test-setup file rule; the plan for each crash code; the group
liveness of the crash seeds (one changed setup file ends the group, an unchanged group never passes); the developer end
to end (the repair task offers exactly the setup files, the crash output is in the QA block, the repaired tree is
committed; an unchanged setup is bounded; a write outside the setup is rejected); and the negative table: every routing
decision of a feedback without a crash code is exactly as before.

Seen live 10-29 (second install, run newplan1-a2): `PY.TEST_FAILED pytest.internal: internal error` (no file) -> REGENERATE
FINDING_NOT_ON_A_DRAFT_FILE -> the regenerated workload failed two different tests and the retry ran out.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
from unittest.mock import MagicMock, patch

import pytest

import qa_sandbox_support as sup
from test_qa_feedback import (MAIN, SCHEMAS, TREE, W, _block_parts, _develop, _feedback, _first_build,  # noqa: E402
                              _qa_diag, _section)
from test_qa_stage2_on_test_fail import ADH_NOFILE, ADH_PLATFORM, SEC_NOFILE  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from shared.diagnostics import ErrorClass, RepairBudgetExhausted  # noqa: E402

REQS = "apps/shop/requirements.txt"
CONFTEST = "tests/conftest.py"
TESTS_INIT = "tests/__init__.py"
CRASH_TEXT = "INTERNALERROR> RuntimeError: pytest_asyncio needs pytest<9"
CRASH_DETAIL = "Traceback (most recent call last):\n  File \"_pytest/main.py\", line 330\n" + CRASH_TEXT


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


def _crash(code="PYTEST.INTERNAL_ERROR", **kw):
    base = dict(file=None, code=code, message=f"{CRASH_TEXT}\n(pytest crashed with an internal error for apps/shop)",
                detail=CRASH_DETAIL)
    base.update(kw)
    d = _qa_diag(**base)
    d["tool"] = "pytest"
    return d


SETUP_TREE = dict(TREE, **{CONFTEST: "import pytest\n", TESTS_INIT: "", "tests/test_main.py": "def test_x():\n    pass\n"})


# ------------------------------------------------------------------------------------------------ parity + file rule
def test_crash_codes_are_the_qa_runner_codes():
    sj = sup.load_sandbox_job("sandbox_job_crash_parity")
    with open(os.path.join(sup.QA_DIR, "sandbox_job.py")) as f:
        runner = f.read()
    assert QR.CRASH_CODES == sj.PYTEST_CRASH_CODES == {sj.PYTEST_INTERNAL_ERROR_CODE, sj.PYTEST_SESSION_ERROR_CODE,
                                                       sj.PYTEST_STARTUP_ERROR_CODE}
    assert '"PYTEST.REPORT_INVALID"' in runner and "PYTEST.REPORT_INVALID" not in QR.CRASH_CODES
    assert sj.service_scope_file("apps/shop") == REQS


def test_crash_repair_files_are_the_test_setup_by_path_structure():
    draft = {"conftest.py": "", "apps/shop/tests/conftest.py": "", "apps/shop/tests/__init__.py": "",
             "tests/__init__.py": "", "tests/sub/conftest.py": "", REQS: "fastapi\n", "apps/api/requirements.txt": "",
             # not the test setup (or no effect in QA): pytest config (QA runs its own `-c` ini), a root or nested
             # requirements file (QA installs apps/<service>/requirements.txt only), an ordinary package, tests, code
             "pytest.ini": "", "pyproject.toml": "", "apps/shop/setup.cfg": "", "tox.ini": "", "requirements.txt": "",
             "apps/shop/sub/requirements.txt": "", "apps/shop/schemas/__init__.py": "", "tests/test_a.py": "",
             "apps/shop/main.py": "", "apps/shop/conftest.py.bak": "", "mytests/__init__.py": "",
             "apps/shop/requirements-dev.txt": "", "x/conftest.py": b"bytes"}
    assert QR.crash_repair_files(draft) == ["apps/api/requirements.txt", REQS, "apps/shop/tests/__init__.py",
                                            "apps/shop/tests/conftest.py", "conftest.py", "tests/__init__.py",
                                            "tests/sub/conftest.py"]
    assert QR.crash_repair_files({}) == []


# ------------------------------------------------------------------------------------------------ the plan
@pytest.mark.parametrize("code", sorted(QR.CRASH_CODES))
def test_a_pytest_crash_is_a_repair_of_the_test_setup(code):
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _crash(code)), stack_configured=True)
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "PYTEST_CRASH_ON_TEST_SETUP", 1)
    assert [(s.code, s.file) for s in plan.seeds] == [(code, REQS), (code, TESTS_INIT), (code, CONFTEST)]
    assert plan.repairable_paths == {REQS, CONFTEST, TESTS_INIT}
    assert plan.seed_files == {p: SETUP_TREE[p] for p in (REQS, CONFTEST, TESTS_INIT)}
    assert plan.tree == SETUP_TREE and MAIN in plan.draft
    for s in plan.seeds:
        assert (s.tool, s.source, s.error_class, s.line) == ("pytest", "qa", ErrorClass.CODE_DEFECT, None)
        assert s.hint == QR.CRASH_SEED_HINT and s.message.startswith(f"QA finding 1 ({code}): pytest crashed")
        assert "INTERNALERROR" not in s.model_dump_json()           # the crash text lives only in the QA block
    _token, content = _block_parts(plan.untrusted_output)
    assert CRASH_TEXT in content and json.loads(content)["detail"].endswith(CRASH_TEXT)


def test_a_crash_in_a_draft_without_test_setup_files_is_todays_regeneration():
    tree = {MAIN: TREE[MAIN], W + "main.tf": "# platform\n"}      # no requirements.txt, conftest or tests/__init__.py
    plan = QR.plan_qa_repair(_feedback(tree, _crash()), stack_configured=True)
    assert (plan.mode, plan.reason, plan.seeds) == (QR.REGENERATE, "CRASH_WITHOUT_TEST_SETUP_FILES", ())


def test_a_crash_code_that_names_a_draft_file_adds_that_file_to_the_group():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _crash(file=MAIN)), stack_configured=True)
    assert plan.mode == QR.QA_REPAIR and plan.repairable_paths == {REQS, CONFTEST, TESTS_INIT, MAIN}


def test_a_crash_with_a_file_finding_repairs_both():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _qa_diag(), _crash()), stack_configured=True)
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "PYTEST_CRASH_ON_TEST_SETUP", 2)
    assert [(s.code, s.file) for s in plan.seeds] == [("PY.TEST_FAILED", MAIN), ("PYTEST.INTERNAL_ERROR", REQS),
                                                      ("PYTEST.INTERNAL_ERROR", TESTS_INIT),
                                                      ("PYTEST.INTERNAL_ERROR", CONFTEST)]


def test_a_crash_with_a_reviewer_finding_without_a_file_keeps_it_as_text():
    """QA-STAGE2-ON-TEST-FAIL's rule: the sandbox finding is repairable, so the judge finding rides along as text."""
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _crash(), SEC_NOFILE), stack_configured=True)
    assert plan.mode == QR.QA_REPAIR and plan.findings == 2
    assert {s.code for s in plan.seeds} == {"PYTEST.INTERNAL_ERROR"}
    assert "bucket is publicly readable" in _block_parts(plan.untrusted_output)[1]


@pytest.mark.parametrize("extra,mode,reason", [
    # PLATFORM-RENDERED-FINDING (owner 11-13): a platform-rendered file is a typed stop
    (_qa_diag(file=W + "main.tf"), QR.STOP, QR.PLATFORM_RENDERED_REASON),
    (_qa_diag(file="apps/shop/missing.py"), QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE"),
    (_qa_diag(file=None, code="PY.TEST_FAILED"), QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE")])
def test_a_crash_with_an_unrepairable_sandbox_finding_is_todays_regeneration(extra, mode, reason):
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _crash(), extra), stack_configured=True)
    assert (plan.mode, plan.reason) == (mode, reason)


def test_a_judge_finding_with_a_crash_code_is_not_a_crash():
    """Typed by the gateway's judge stamp and the code: a Stage 2 finding is never a pytest crash."""
    judge = dict(SEC_NOFILE, code="PYTEST.INTERNAL_ERROR")
    assert not QR.is_crash_finding(judge) and QR.is_crash_finding(_crash())
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, judge), stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE")


def test_a_crash_without_the_repair_loop_is_todays_regeneration():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _crash()), stack_configured=False)
    assert (plan.mode, plan.reason) == (QR.REGENERATE, "NO_REPAIR_LOOP")


# ------------------------------------------------------------------------------------------------ negative table
# Every routing decision of a feedback without a crash code, as it was before this row (main aaa5fdb2): mode, reason,
# and the seeds' (code, file).
UNCHANGED = [
    ([_qa_diag()], True, QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES", [("PY.TEST_FAILED", MAIN)]),
    ([_qa_diag(file=REQS, code="REQ.UNRESOLVABLE")], True, QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES",
     [("REQ.UNRESOLVABLE", REQS)]),
    ([_qa_diag()], False, QR.REGENERATE, "NO_REPAIR_LOOP", []),
    ([_qa_diag(file=None, code="PY.TEST_FAILED")], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    # Opus RT F2: an unreadable report after another exit / exit 0 with failures listed is not a crash: today's rule
    ([_qa_diag(file=None, code="PYTEST.REPORT_INVALID",
               message="pytest exited 1 without a readable junit report (ParseError)")], True, QR.REGENERATE,
     "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(file=None, code="PYTEST.REPORT_INVALID",
               message="pytest exited 0 but its report lists 1 failure(s) for apps/shop")], True, QR.REGENERATE,
     "FINDING_NOT_ON_A_DRAFT_FILE", []),
    # Opus RT F1: an unhashable code never raises: the base decision
    ([_qa_diag(code=["x"])], True, QR.REGENERATE, "FINDING_INVALID", []),
    ([_qa_diag(code={"a": 1})], True, QR.REGENERATE, "FINDING_INVALID", []),
    ([_qa_diag(file=None, code=["PYTEST.INTERNAL_ERROR"])], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(file=None, code={"a": 1})], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(file=None, code="PY.IMPORT_FAILED")], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(file=None, code="PY.NO_TESTS")], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(), _qa_diag(file=None, code="JUDGE.SECURITY")], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    # PLATFORM-RENDERED-FINDING (owner 11-13): a finding forcing a regeneration on a platform-rendered file stops
    ([_qa_diag(file=W + "main.tf")], True, QR.STOP, QR.PLATFORM_RENDERED_REASON, []),
    ([_qa_diag(file="apps/shop/missing.py")], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(code="not a code")], True, QR.REGENERATE, "FINDING_INVALID", []),
    ([_qa_diag(severity="warning")], True, QR.REGENERATE, "NO_ERROR_FINDINGS", []),
    ([_qa_diag(severity="warning", code="PYTEST.INTERNAL_ERROR", file=None)], True, QR.REGENERATE,
     "NO_ERROR_FINDINGS", []),                                    # a crash code that is only a warning: no error
    ([_qa_diag(), SEC_NOFILE, ADH_NOFILE, ADH_PLATFORM], True, QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES",
     [("PY.TEST_FAILED", MAIN)]),
    ([SEC_NOFILE, ADH_NOFILE], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([ADH_PLATFORM], True, QR.STOP, QR.PLATFORM_RENDERED_REASON, []),
    ([_qa_diag(file=None, code="PY.TEST_FAILED"), SEC_NOFILE], True, QR.REGENERATE, "FINDING_NOT_ON_A_DRAFT_FILE", []),
    ([_qa_diag(file="infra/workload/main.tf"), ADH_NOFILE], True, QR.STOP, QR.PLATFORM_RENDERED_REASON, []),
]


@pytest.mark.parametrize("tree", [TREE, SETUP_TREE], ids=["tree", "tree_with_test_setup"])
@pytest.mark.parametrize("diags,stack,mode,reason,seeds", UNCHANGED)
def test_n_every_routing_without_a_crash_code_is_unchanged(tree, diags, stack, mode, reason, seeds):
    plan = QR.plan_qa_repair(_feedback(tree, *diags), stack_configured=stack)
    assert (plan.mode, plan.reason, [(s.code, s.file) for s in plan.seeds]) == (mode, reason, seeds)
    if mode == QR.QA_REPAIR:
        assert plan.seed_files == {f: tree[f] for _c, f in seeds}
        assert _block_parts(plan.untrusted_output)[1] == QR.render_findings(
            [d for d in diags if d.get("severity") == "error"])
    else:
        assert not plan.seeds and not plan.untrusted_output


# ------------------------------------------------------------------------------------------------ per service (F3)
API_REQS = "apps/api/requirements.txt"
TWO = dict(SETUP_TREE, **{API_REQS: "fastapi\n", "apps/api/main.py": "x = 1\n", "apps/api/tests/conftest.py": "",
                          "apps/api/tests/__init__.py": "", "apps/api/tests/test_a.py": "def test_a():\n    pass\n",
                          "apps/shop/tests/conftest.py": ""})


def test_crash_targets_are_the_crashed_services_setup_plus_the_root():
    assert QR.crash_targets(_crash(file=API_REQS), TWO) == [API_REQS, "apps/api/tests/__init__.py",
                                                            "apps/api/tests/conftest.py", TESTS_INIT, CONFTEST]
    assert QR.crash_targets(_crash(file=REQS), TWO) == [REQS, "apps/shop/tests/conftest.py", TESTS_INIT, CONFTEST]
    assert QR.crash_targets(_crash(), TWO) == QR.crash_repair_files(TWO)       # no scope (an older runner): all
    assert QR.crash_targets(_crash(file=["x"]), TWO) == QR.crash_repair_files(TWO)


def test_two_crashed_services_are_two_groups():
    plan = QR.plan_qa_repair(_feedback(TWO, _crash(file=API_REQS), _crash("PYTEST.STARTUP_ERROR", file=REQS)),
                             stack_configured=True)
    assert (plan.mode, plan.reason, plan.findings) == (QR.QA_REPAIR, "PYTEST_CRASH_ON_TEST_SETUP", 2)
    groups = {}
    for s in plan.seeds:
        groups.setdefault(s.symbol, set()).add(s.file)
    assert groups == {"qa_crash_finding_1": {API_REQS, "apps/api/tests/__init__.py", "apps/api/tests/conftest.py",
                                             TESTS_INIT, CONFTEST},
                      "qa_crash_finding_2": {REQS, "apps/shop/tests/conftest.py", TESTS_INIT, CONFTEST}}
    draft = dict(plan.draft)
    api_fixed = dict(draft, **{API_REQS: draft[API_REQS] + "pytest-asyncio==1.4.0\n"})
    assert {s.symbol for s in QR.live_seeds(plan.seeds, plan.seed_files, api_fixed)} == {"qa_crash_finding_2"}
    root_fixed = dict(draft, **{CONFTEST: draft[CONFTEST] + "\n# fixed\n"})      # shared by both groups
    assert QR.live_seeds(plan.seeds, plan.seed_files, root_fixed) == []
    assert QR.live_seeds(plan.seeds, plan.seed_files, draft) == list(plan.seeds)


def test_a_scoped_crash_on_a_service_without_setup_files_still_targets_its_requirements():
    plan = QR.plan_qa_repair(_feedback(TREE, _crash(file=REQS)), stack_configured=True)
    assert plan.mode == QR.QA_REPAIR and plan.repairable_paths == {REQS}


# ------------------------------------------------------------------------------------------------ group liveness
def test_crash_seeds_are_one_group_and_other_seeds_keep_the_per_file_rule():
    plan = QR.plan_qa_repair(_feedback(SETUP_TREE, _qa_diag(), _crash()), stack_configured=True)
    draft = dict(plan.draft)
    assert QR.live_seeds(plan.seeds, plan.seed_files, draft) == list(plan.seeds)
    one = dict(draft, **{REQS: draft[REQS] + "pytest-asyncio==1.4.0\n"})       # one setup file changed
    assert [(s.code, s.file) for s in QR.live_seeds(plan.seeds, plan.seed_files, one)] == [("PY.TEST_FAILED", MAIN)]
    fixed = dict(draft, **{MAIN: "x = 1\n"})                                     # only the file finding fixed
    assert {s.code for s in QR.live_seeds(plan.seeds, plan.seed_files, fixed)} == {"PYTEST.INTERNAL_ERROR"}


def test_n_without_crash_seeds_liveness_is_the_per_file_rule():
    plan = QR.plan_qa_repair(_feedback(TREE, _qa_diag(), _qa_diag(file=REQS, code="REQ.UNRESOLVABLE")),
                             stack_configured=True)
    draft = dict(plan.draft)
    for changed, live in [((), [MAIN, REQS]), ((MAIN,), [REQS]), ((REQS,), [MAIN]), ((MAIN, REQS), [])]:
        d = dict(draft, **{p: draft[p] + "\n# changed\n" for p in changed})
        assert [s.file for s in QR.live_seeds(plan.seeds, plan.seed_files, d)] == live


# ------------------------------------------------------------------------------------------------ developer stage
def _crash_tree():
    tree = _first_build("off")
    return dict(tree, **{CONFTEST: "import pytest\n\n\n@pytest.fixture\ndef client():\n    return None\n"})


def test_a_crash_is_repaired_on_the_test_setup_without_regenerating():
    tree = _crash_tree()
    pinned = tree[REQS] + "pytest-asyncio==1.4.0\n"
    files, agent, client, seen = _develop("off", feedback=_feedback(tree, _crash()), repairs=[{REQS: pinned}])
    assert seen["swarm"] == 0 and not seen["lead_calls"]                       # no generation call at all
    (task,) = seen["repair_tasks"]
    prompt = task["prompt"]
    assert json.loads(_section(prompt, "FILES TO FIX:", QR.QA_OUTPUT_HEADER)) == {CONFTEST: tree[CONFTEST],
                                                                                REQS: tree[REQS]}
    diags = json.loads(_section(prompt, "DIAGNOSTICS:", "FILES TO FIX:"))
    assert sorted((x["code"], x["file"]) for x in diags) == [("PYTEST.INTERNAL_ERROR", REQS),
                                                             ("PYTEST.INTERNAL_ERROR", CONFTEST)]
    assert all(x["hint"] == QR.CRASH_SEED_HINT and x["detail"] is None for x in diags)
    assert "INTERNALERROR" not in json.dumps(diags)
    _head, rest = prompt.split(QR.QA_OUTPUT_HEADER + "\n\n", 1)
    framed = rest.split("\n\nREAD-ONLY CONTEXT (do not return these):", 1)[0]
    assert CRASH_TEXT in _block_parts(framed)[1]                               # pytest's crash output, framed
    context = json.loads(rest.split("READ-ONLY CONTEXT (do not return these):\n\n", 1)[1])
    assert MAIN in context and SCHEMAS in context and CONFTEST not in context  # the other .py files, read-only
    assert agent.last_validation_report.status == "PASS" and files[REQS] == pinned
    assert files[CONFTEST] == tree[CONFTEST]                                   # one setup file changed is enough
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["reason"]) == (QR.QA_REPAIR, "PYTEST_CRASH_ON_TEST_SETUP")
    assert sorted(s["file"] for s in rec["seeds"]) == [REQS, CONFTEST]


def test_an_unchanged_test_setup_never_passes_and_the_loop_stays_bounded():
    tree = _crash_tree()
    with pytest.raises(RepairBudgetExhausted) as ei:
        _develop("off", feedback=_feedback(tree, _crash()), repairs=[{REQS: tree[REQS]}],
                 repair_max_iterations_precommit=1)
    assert ei.value.error_class is ErrorClass.CODE_DEFECT
    assert sorted((d.code, d.file) for d in ei.value.report.diagnostics) == [("PYTEST.INTERNAL_ERROR", REQS),
                                                                             ("PYTEST.INTERNAL_ERROR", CONFTEST)]


def test_a_crash_repair_that_writes_outside_the_test_setup_is_rejected():
    tree = _crash_tree()
    with pytest.raises(RepairBudgetExhausted):
        _develop("off", feedback=_feedback(tree, _crash()), repairs=[{MAIN: tree[MAIN] + "\n# x\n"}],
                 repair_max_iterations_precommit=1)

"""AC-1 (app-code reliability plan, register row AC-1): V3a-syntax reports every broken top-level unit of a Python
file, so a repair that fixes one of several syntax errors is accepted as progress instead of `NO_IMPROVEMENT`.

Fixtures (tests/fixtures/ac1/) are the 10-14 fresh record's 03-r2 `apps/batch-worker/tests/test_worker.py`: the
TEST_ENGINEER first draft (6 unparenthesized multi-line `with` statements) and the recorded iteration-1 and
iteration-2 repair answers (each fixed exactly one). The single-error prompt snapshot
(tests/fixtures/ac1/single_error_prompts.json) was rendered by the code BEFORE AC-1 (origin/main 30270c8) from
`single_error_scenario_prompts()` below. No network, no LLM."""
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

from developer_agent.repair_loop import Assembled, LoopContext, RepairLoop, accept  # noqa: E402
from developer_agent.validators.base import ValidationContext, ValidatorStack  # noqa: E402
from developer_agent.validators.step1 import PythonSyntaxValidator, UndefinedNameValidator  # noqa: E402
from shared.diagnostics import (AssemblyRecord, Diagnostic, MemoryLedgerStore, RepairBudgetExhausted,  # noqa: E402
                                ValidationReport, fingerprint)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "ac1")
TW = "apps/batch-worker/tests/test_worker.py"


def _fixture(name):
    with open(os.path.join(FIX, name)) as fh:
        return fh.read()


def _syntax(files):
    return PythonSyntaxValidator().validate(ValidationContext.build(files, ownership=lambda p: None))


def _before_ac1(path, src):
    """The V3a-syntax diagnostic exactly as it was built before AC-1 (one per file, no symbol)."""
    try:
        compile(src, path, "exec", dont_inherit=True)
        return None
    except SyntaxError as e:
        return Diagnostic(tool="ast", code="PY.SYNTAX", file=path, line=e.lineno, column=e.offset,
                          message=f"{type(e).__name__}: {e.msg}", snippet=(e.text or "").rstrip("\n") or None,
                          iteration=0, source="precommit", severity="error")


BROKEN_WITH = ('def {name}():\n    with patch("a"),\n         patch("b"):\n        pass\n')
VALID = {
    "plain.py": "import os\n\nX = 1\n",
    "decorated.py": ("import functools\n\n\n@functools.lru_cache(\n    maxsize=None)\n@staticmethod\ndef f(a,\n"
                     "      b):\n    return a\n\n\nclass C:\n    @property\n    def p(self):\n        return 1\n"),
    "toplevel_compound.py": ("import sys\nif sys.version_info >= (3, 13):\n    A = 1\nelif sys.platform == 'x':\n"
                             "    A = 2\nelse:\n    A = 3\ntry:\n    import json\nexcept ImportError:\n    json = None\n"
                             "else:\n    pass\nfinally:\n    B = 2\nfor i in range(2):\n    pass\nelse:\n    C = 1\n"
                             "while False:\n    pass\nelse:\n    D = 1\n"),
    "async_and_match.py": ("async def g():\n    async with x() as (a, b):\n        pass\n\n\ndef m(v):\n    match v:\n"
                           "        case 1:\n            return 'a'\n        case _:\n            return 'b'\n"),
    "strings.py": ('"""Module doc.\n\nsome text at column 0\n"""\nS = """\ndef not_a_def(:\n"""\nT = (\n    1,\n'
                   '2)\nU = 1 + \\\n    2\n\n\ndef h():\n    """doc\nat column 0\n    """\n# comment at column 0\n'
                   '    return S\n'),
    "parenthesized_with.py": 'from unittest.mock import patch\n\n\ndef t():\n    with (patch("a") as x,\n'
                             '          patch("b") as y):\n        pass\n',
    "crlf.py": "def a():\r\n    return 1\r\n\r\nclass B:\r\n    pass\r\n",
    "empty.py": "",
}


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_valid_files_yield_no_finding_and_never_reach_the_unit_split(monkeypatch):
    import developer_agent.validators.step1 as step1

    def boom(*a, **kw):
        raise AssertionError("a file that compiles must never reach the unit split")
    monkeypatch.setattr(step1, "broken_units", boom)
    files = dict(VALID)
    assert _syntax(files) == []
    assert files == VALID   # nothing rewritten


# ------------------------------------------------------------------------------------------------ 0 or 1 error
SINGLE = {
    "in_def.py": ("import os\n\n\n" + BROKEN_WITH.format(name="test_one") + "\n\ndef ok():\n    return 1\n",
                  "test_one"),
    "in_class.py": ("class TestX:\n    def test_a(self):\n        with a,\n             b:\n            pass\n\n\n"
                    "def ok():\n    pass\n", "TestX"),
    "decorated.py": ("import pytest\n\n\n@pytest.fixture\n@pytest.mark.x(\n    1)\n" + BROKEN_WITH.format(name="fx"),
                     "fx"),
    "async_def.py": ("async def co():\n    await = 1\n\n\ndef ok():\n    pass\n", "co"),
    "module_stmt.py": ("import os\nwith open('a'),\n     open('b'):\n    pass\n\n\ndef ok():\n    pass\n", "<module>"),
    "html_outside_string.py": ("def page():\n    return '<p>'\n    <div>x</div>\n\n\ndef ok():\n    pass\n", "page"),
}


@pytest.mark.parametrize("name", sorted(SINGLE))
def test_single_broken_unit_is_the_pre_ac1_diagnostic_plus_symbol(name):
    src, symbol = SINGLE[name]
    out = _syntax({name: src})
    assert len(out) == 1
    assert out[0].symbol == symbol
    assert out[0].model_dump(exclude={"symbol"}) == _before_ac1(name, src).model_dump(exclude={"symbol"})


FALLBACK = {
    # tokenize cannot read the stream
    "unterminated_triple.py": 'def a():\n    pass\n\nX = """never closed\n\ndef b(:\n    pass\n',
    "bytes_across_lines.py": "def data():\n    return b'[\n{}]'\n\n\n" + BROKEN_WITH.format(name="test_two"),
    "unclosed_bracket.py": "def a(:\n    pass\n\nX = (1,\n",
    # the first error spans units (the def has no body; the error is reported on the next statement)
    "spans_units.py": "def f():\nx = 1\n\n\n" + BROKEN_WITH.format(name="test_three"),
    # a misspelled `except` starts a new unit; `try:` alone and the rest alone both fail: one error, not two
    "misspelled_except.py": ("try:\n    import x\ntry_fallback:\n    pass\nexcept ImportError:\n    pass\n\n\n"
                             + BROKEN_WITH.format(name="test_five")),
    # first line indented: no top-level unit holds the error
    "leading_indent.py": "  x = 1\n" + BROKEN_WITH.format(name="test_four"),
}


@pytest.mark.parametrize("name", sorted(FALLBACK))
def test_unsplittable_files_keep_the_single_pre_ac1_diagnostic(name):
    src = FALLBACK[name]
    out = _syntax({name: src})
    assert out == [_before_ac1(name, src)]


def test_null_bytes_keep_the_single_whole_file_finding():
    # SyntaxError since CPython 3.12 (ValueError before): either way one finding, no unit
    out = _syntax({"n.py": "def a():\n    pass\nx = 1\0\n" + BROKEN_WITH.format(name="b")})
    assert len(out) == 1 and "null bytes" in out[0].message and out[0].symbol is None


def test_an_unexpected_split_failure_falls_back_to_the_pre_ac1_diagnostic(monkeypatch):
    import developer_agent.validators.step1 as step1

    def boom(*a, **kw):
        raise RuntimeError("bug in the split")
    monkeypatch.setattr(step1, "broken_units", boom)
    src = BROKEN_WITH.format(name="a") + BROKEN_WITH.format(name="b")
    assert _syntax({"t.py": src}) == [_before_ac1("t.py", src)]   # never UNAVAILABLE, never lost


# ------------------------------------------------------------------------------------------------ >= 2 errors
def test_03r2_first_draft_reports_every_broken_test_function():
    src = _fixture("03r2_test_worker_draft.py.txt")
    out = _syntax({TW: src})
    assert [d.line for d in out] == [178, 215, 314, 353, 407, 431]
    assert [d.symbol for d in out] == [
        "test_get_metadata_attribute_retries_and_exhausts", "test_get_access_token_failure_raises",
        "test_trigger_poweroff_all_fail_handled_gracefully", "test_main_success_flow",
        "test_main_failure_publishes_error_and_exits", "test_main_failure_without_token_exits_safely"]
    assert all(d.message == "SyntaxError: invalid syntax" and d.snippet.lstrip().startswith("with patch(")
               for d in out)
    assert out[0].model_dump(exclude={"symbol"}) == _before_ac1(TW, src).model_dump(exclude={"symbol"})
    assert len({fingerprint(d) for d in out}) == 6


def test_top_level_compound_statements_and_decorators_are_not_split():
    src = (VALID["toplevel_compound.py"] + VALID["decorated.py"] + "\n\n" + BROKEN_WITH.format(name="test_bad")
           + "\n\n@pytest.fixture\n" + BROKEN_WITH.format(name="fx_bad"))
    out = _syntax({"m.py": src})
    assert [d.symbol for d in out] == ["test_bad", "fx_bad"]


def test_future_flags_of_the_file_apply_to_each_unit():
    src = "from __future__ import barry_as_FLUFL\nassert 1 <> 2\n\n\n" + BROKEN_WITH.format(name="a") + \
        BROKEN_WITH.format(name="b")
    out = _syntax({"f.py": src})
    assert [d.symbol for d in out] == ["a", "b"]   # `<>` is valid under the file's own future import


def test_crlf_line_numbers_match_compile():
    src = (BROKEN_WITH.format(name="a") + "\n" + BROKEN_WITH.format(name="b")).replace("\n", "\r\n")
    out = _syntax({"c.py": src})
    assert [(d.symbol, d.line) for d in out] == [("a", 2), ("b", 7)]
    fixed_a = src.replace('with patch("a"),\r\n', 'with patch("a"), \\\r\n', 1)
    assert [(d.symbol, d.line) for d in _syntax({"c.py": fixed_a})] == [("b", 7)]


# ------------------------------------------------------------------------------------------------ acceptance
def _rep(files):
    diags = _syntax(files)
    return ValidationReport(status="FAIL" if diags else "PASS", source="precommit", artifact_hash="h",
                            diagnostics=diags)


def _accept(before, after):
    a1, a2 = (Assembled(tree=dict(t), record=AssemblyRecord()) for t in (before, after))
    return accept(before, after, a1, a2, _rep(before), _rep(after), set(), "opentofu 1.9.0")


def test_fixing_one_of_several_broken_units_is_progress():
    d = {TW: _fixture("03r2_test_worker_draft.py.txt")}
    it1 = {TW: _fixture("03r2_test_worker_it1_answer.py.txt")}
    it2 = {TW: _fixture("03r2_test_worker_it2_answer.py.txt")}
    assert _accept(d, it1) == (True, None)       # 6 -> 5 broken units
    assert _accept(it1, it2) == (True, None)     # 5 -> 4: the 10-14 run judged this NO_IMPROVEMENT
    assert _accept(it2, it2) == (False, "NO_IMPROVEMENT")
    three = {"t.py": "".join(BROKEN_WITH.format(name=n) for n in "abc")}
    one = {"t.py": BROKEN_WITH.format(name="a").replace('"a"),\n', '"a"), \\\n') +
           "".join(BROKEN_WITH.format(name=n) for n in "bc")}
    assert _accept(three, one) == (True, None)


def test_a_newly_broken_unit_is_a_new_fingerprint():
    before = {"t.py": BROKEN_WITH.format(name="a") + "def b():\n    pass\n"}
    after = {"t.py": "def a():\n    pass\n" + BROKEN_WITH.format(name="b")}
    assert _accept(before, after) == (False, "NEW_FINGERPRINT")
    # splittable -> unsplittable (the repair broke the token stream) is not explained either
    unsplittable = {"t.py": BROKEN_WITH.format(name="a") + 'X = """never closed\n'}
    two = {"t.py": BROKEN_WITH.format(name="a") + BROKEN_WITH.format(name="b")}
    assert _accept(two, unsplittable) == (False, "NEW_FINGERPRINT")


def test_fixing_the_error_that_hid_the_units_reveals_them():
    # whole-file finding (tokenize fails on the unterminated string) -> fixed -> the remaining units are revealed
    before = {"t.py": BROKEN_WITH.format(name="a") + 'X = """never closed\n' + BROKEN_WITH.format(name="b")}
    after = {"t.py": BROKEN_WITH.format(name="a") + 'X = """closed"""\n' + BROKEN_WITH.format(name="b")}
    assert [d.symbol for d in _rep(before).diagnostics] == [None]
    assert [d.symbol for d in _rep(after).diagnostics] == ["a", "b"]
    assert _accept(before, after) == (True, None)


def test_a_unit_the_repair_rewrote_is_not_revealed():
    # Fable RT F1: closing the string AND rewriting both (valid) defs as broken ones is not a reveal
    before = {"t.py": 'X = """never closed\n' + "def a():\n    pass\n\n\ndef b():\n    pass\n"}
    after = {"t.py": 'X = """closed"""\n' + BROKEN_WITH.format(name="a") + BROKEN_WITH.format(name="b")}
    assert [d.symbol for d in _rep(before).diagnostics] == [None]
    assert _accept(before, after) == (False, "NEW_FINGERPRINT")


def test_gutting_an_unparsable_file_to_a_broken_stub_is_not_revealed():
    # Fable RT F1: unterminated string + 40 valid tests -> one broken stub (preservation is blind to unparsable files)
    tests = "".join(f"def test_{i}():\n    assert {i}\n\n\n" for i in range(40))
    before = {"t.py": 'X = """never closed\n' + tests}
    after = {"t.py": BROKEN_WITH.format(name="test_stub")}
    assert _accept(before, after) == (False, "NEW_FINGERPRINT")


def test_duplicate_def_names_get_distinct_identities():
    # Fable RT F2: the k-th def/class of a repeated name is `name#k`; module statements stay `<module>`
    two = {"t.py": BROKEN_WITH.format(name="test_x") + BROKEN_WITH.format(name="test_x")}
    assert [d.symbol for d in _rep(two).diagnostics] == ["test_x", "test_x#2"]
    one = {"t.py": "def test_x():\n    pass\n" + BROKEN_WITH.format(name="test_x")}
    assert [d.symbol for d in _rep(one).diagnostics] == ["test_x#2"]
    assert _accept(two, one) == (True, None)


def test_a_def_named_like_a_dropped_tf_key_is_still_routed_to_its_author():
    # Fable RT F5: `terraform` is a bare file_keys() key; a dropped root `terraform` block must not turn the syntax
    # finding of `def terraform()` into PLATFORM_DEFECT
    main_tf = "infra/workload/main.tf"
    py = "apps/svc/tasks.py"
    persona = Persona()
    ctx = _loop_ctx(persona, {py: "BACKEND_ENGINEER", main_tf: "IAC_ENGINEER"},
                    settings=HallucinationStackSettings(repair_max_iterations_precommit=1))
    with pytest.raises(RepairBudgetExhausted):   # not StageError("not repairable by the developer")
        RepairLoop(ctx).run({main_tf: "terraform {\n}\n", py: BROKEN_WITH.format(name="terraform")})
    assert [(t.persona, [x["code"] for x in t.diagnostics]) for t in persona.tasks] == [
        ("BACKEND_ENGINEER", ["PY.SYNTAX"])]


def test_a_syntax_unit_name_never_excuses_deleting_that_name_elsewhere():
    t = "apps/a/tests/test_x.py"
    h = "apps/a/helpers.py"
    before = {t: BROKEN_WITH.format(name="test_keep") + BROKEN_WITH.format(name="z"),
              h: "def test_keep():\n    return 1\n\n\ndef other():\n    return 2\n"}
    after = {t: "def test_keep():\n    pass\n" + BROKEN_WITH.format(name="z"), h: "def other():\n    return 2\n"}
    assert _accept(before, after) == (False, "PRESERVATION_VIOLATION")


# ------------------------------------------------------------------------------------------------ the loop
class Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        files = self.responses.pop(0) if self.responses else {}
        return {"files": files, "envelope_ok": True, "model": "m", "tokens_in": 10, "tokens_out": 10,
                "tokens_thoughts": 0}


def _loop_ctx(persona, attribution, settings=None):
    st = ValidatorStack()
    st.register(PythonSyntaxValidator(), "blocking")
    st.register(UndefinedNameValidator(), "blocking")

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st,
                       ledger_store=MemoryLedgerStore(), settings=settings or HallucinationStackSettings(),
                       attribution=dict(attribution), llm_draft_paths=set(attribution), preexisting=set(),
                       repair_fn=persona, model="gemini-test", available_providers=["google"])


def test_03r2_loop_accepts_each_partial_fix():
    persona = Persona({TW: _fixture("03r2_test_worker_it1_answer.py.txt")},
                      {TW: _fixture("03r2_test_worker_it2_answer.py.txt")},
                      {TW: _fixture("03r2_test_worker_it2_answer.py.txt")})
    ctx = _loop_ctx(persona, {TW: "TEST_ENGINEER"})
    with pytest.raises(RepairBudgetExhausted):
        RepairLoop(ctx).run({TW: _fixture("03r2_test_worker_draft.py.txt")})
    first = persona.tasks[0].diagnostics
    assert [x["line"] for x in first] == [178, 215, 314, 353, 407, 431]
    assert [(e.accepted, e.reject_reason, len(e.fingerprints_before), len(e.fingerprints_after))
            for e in ctx.events] == [(True, None, 6, 5), (True, None, 5, 4), (False, "NO_IMPROVEMENT", 4, 4)]
    assert "\"symbol\"" not in persona.tasks[0].prompt()   # the unit identity never reaches the prompt


SNAPSHOT = os.path.join(FIX, "single_error_prompts.json")
SNAPSHOT_DRAFT = {
    # one broken unit (a multi-line `with` in a test function)
    "tests/test_one.py": "import os\n\n\ndef test_ok():\n    assert os\n\n\n" + BROKEN_WITH.format(name="test_one"),
    # one error the split cannot attribute (tokenize fails): the whole-file finding
    "tests/test_str.py": "def data():\n    return b'[\n{}]'\n",
    # 0 syntax errors, one undefined name: in the prompt for another code
    "apps/svc/main.py": "def handler():\n    return missing_name\n",
    "apps/svc/ok.py": "def fine():\n    return 1\n",
}
SNAPSHOT_ATTRIBUTION = {"tests/test_one.py": "TEST_ENGINEER", "tests/test_str.py": "TEST_ENGINEER",
                        "apps/svc/main.py": "BACKEND_ENGINEER", "apps/svc/ok.py": "BACKEND_ENGINEER"}


def single_error_scenario_prompts():
    """Iteration-1 repair prompts of a draft whose Python files have 0 or 1 syntax error each. Uses only APIs that
    exist before AC-1, so the same function renders the snapshot on the old code."""
    persona = Persona()
    ctx = _loop_ctx(persona, SNAPSHOT_ATTRIBUTION,
                    settings=HallucinationStackSettings(repair_max_iterations_precommit=1))
    try:
        RepairLoop(ctx).run(dict(SNAPSHOT_DRAFT))
    except RepairBudgetExhausted:
        pass
    return {t.persona: t.prompt() for t in persona.tasks}


def test_repair_prompts_for_files_with_0_or_1_syntax_error_are_byte_identical():
    with open(SNAPSHOT) as fh:
        expected = json.load(fh)
    got = single_error_scenario_prompts()
    assert sorted(got) == ["BACKEND_ENGINEER", "TEST_ENGINEER"]
    assert got == expected

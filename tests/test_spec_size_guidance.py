"""SPEC-SIZE-GUIDANCE (owner 2026-11-17; docs/planning/large-spec-handling-plan.md §5).

The New Workload modal shows a static size note under **Upload Document** and a live character count under the
specification box (warn only: neutral up to SPEC_CHARS_OPTIMUM, amber above it, red above SPEC_CHARS_MAY_FAIL). These
tests pin the three constants to the code they describe (the architect's split threshold and the lead developer's
40,000-character cut), pin that the counter reads ``newWorkloadForm.spec_content`` (present in both form literals), that
the static note repeats the same numbers, and that nothing refuses a submit on size.
Hermetic: reads files only.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import re

TESTS = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
DASHBOARD = os.path.join(REPO_ROOT, "apps", "control-center", "templates", "dashboard.html")
DECOMPOSER = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "architect_agent", "spec_decomposer.py")
LEAD = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "developer_agent", "lead_orchestrator.py")
KNOWN_LIMITATIONS = os.path.join(REPO_ROOT, "documentation", "known-limitations.md")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _js_const(html, name):
    found = re.findall(rf"^\s*const {name} = (\d+);\s*$", html, flags=re.M)
    assert len(found) == 1, f"{name} must be declared exactly once in dashboard.html, found {found}"
    return int(found[0])


def _getter(html, name):
    m = re.search(rf"^\s*get {name}\(\) \{{\n(.*?)^\s*\}},$", html, flags=re.M | re.S)
    assert m, f"getter {name}() not found"
    return m.group(1)


def test_constants_match_the_pipeline_limits():
    html = _read(DASHBOARD)
    chunk = re.search(r"^\s*CHUNK_THRESHOLD_CHARS = ([\d_]+)\s*$", _read(DECOMPOSER), flags=re.M)
    assert chunk, "spec_decomposer.CHUNK_THRESHOLD_CHARS not found"
    assert _js_const(html, "SPEC_CHARS_OPTIMUM") == int(chunk.group(1).replace("_", "")) == 25000
    cuts = re.findall(r"spec_text\[:(\d+)\]", _read(LEAD))
    assert cuts == ["40000"], f"lead_orchestrator spec cut changed: {cuts}"
    assert _js_const(html, "SPEC_CHARS_LEAD_READS") == 40000
    assert _js_const(html, "SPEC_CHARS_MAY_FAIL") == 100000
    # The comment names the code each constant mirrors.
    i = html.index("const SPEC_CHARS_OPTIMUM")
    comment = html[html.rindex("SPEC-SIZE-GUIDANCE", 0, i):i]
    assert "spec_decomposer.CHUNK_THRESHOLD_CHARS" in comment
    assert "lead_orchestrator" in comment and "40000" in comment


def test_counter_reads_spec_content_and_grades_by_the_constants():
    html = _read(DASHBOARD)
    count = _getter(html, "specCharCount")
    assert "this.newWorkloadForm.spec_content" in count
    level = _getter(html, "specSizeLevel")
    assert "SPEC_CHARS_MAY_FAIL" in level and "SPEC_CHARS_OPTIMUM" in level
    assert "25000" not in level and "100000" not in level  # constants in one place
    # The live counter under the textarea binds to the getters.
    block = html[html.index('data-testid="spec-char-count"'):]
    block = block[:block.index("</div>")]
    assert 'x-text="specCharCount.toLocaleString()' in block
    assert 'x-text="specSizeHint"' in block
    assert "text-amber-400" in block and "text-rose-400" in block
    # It sits under the specification textarea of the New Workload modal.
    textarea = html.index('x-model="newWorkloadForm.spec_content"')
    assert textarea < html.index('data-testid="spec-char-count"')


def test_both_form_literals_carry_spec_content():
    html = _read(DASHBOARD)
    init = html.index("newWorkloadForm: {")
    reset = html.index("this.newWorkloadForm = {")
    for start in (init, reset):
        literal = html[start:html.index("}", start)]
        assert "spec_content: ''" in literal


def test_static_note_states_the_same_numbers_next_to_upload():
    html = _read(DASHBOARD)
    upload = html.index("📄 Upload Document")
    note_at = html.index('data-testid="spec-size-note"')
    assert upload < note_at < html.index('x-model="newWorkloadForm.spec_content"')
    note = html[note_at:html.index("</p>", note_at)]
    for text in ("25,000 characters", "8-10 pages", "first 40,000 characters", "100,000 characters",
                 "may fail to process"):
        assert text in note


def test_guidance_never_refuses_a_submit():
    html = _read(DASHBOARD)
    start = html.index("                async submitNewWorkload() {")
    nxt = re.compile(r"^                (?:async |get )?\w+\([^)]*\) \{$", re.M).search(html, start + 1)
    assert nxt, "end of submitNewWorkload not found"
    body = html[start:nxt.start()]
    assert "spec_content" in body  # the right method
    for name in ("SPEC_CHARS_", "specSizeLevel", "specCharCount", "specSizeHint"):
        assert name not in body
    # The submit button is not disabled by the size either.
    assert not re.search(r":disabled=\"[^\"]*spec(Size|CharCount)", html)


def test_known_limitations_states_the_limits():
    text = _read(KNOWN_LIMITATIONS)
    m = re.search(r"^\* \*\*Long specifications lose detail\.\*\*.*$", text, flags=re.M)
    assert m
    line = m.group(0)
    for fact in ("25,000 characters", "first 40,000 characters", "not from the specification",
                 "100,000 characters", "Cloud Workflows"):
        assert fact in line

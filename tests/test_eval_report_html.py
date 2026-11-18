"""FD-4BN Phase 0: the static HTML report is escaped, script-free and deterministic (plan §12.3; red team F11).
Pure, offline: render() takes in-memory dicts."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import metrics, report  # noqa: E402

PAYLOADS = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "javascript:alert(1)",
            "</style><script>alert(2)</script>", "'><svg onload=alert(3)>", "<a href=\"javascript:alert(4)\">x</a>"]
EVIL = " ".join(PAYLOADS)
REPORT_SRC = ROOT / "eval" / "stackvend_eval" / "report.py"


def _record(key="spec-r1", outcome="committed_passed", validate_ok=True, evil=EVIL):
    result = {
        "example": "spec", "run": 1, "valid_run": True, "invalid_reasons": [], "pipeline_outcome": outcome,
        "product_id": "dryrun-12345678",
        "stages": {
            "architect": {"ok": True, "tasks": 3, "consensus_status": evil, "target_compute_services": [evil],
                          "plan_file_path": evil, "wall_s": 1.0},
            "compliance": {"ok": False, "error": "ValueError: " + evil, "profile": evil},
            "developer": {"ok": True, "path": "swarm", "files": 2},
            "precommit": {"ok": True, "status": "MOCK_COMMITTED", "note": evil},
            "gatekeeper_4_5": {"ok": True, "passed": True, "idempotent": True, "errors": [evil]},
        },
        "hallucination_stack": {
            "validation_report": {"status": "FAIL", "diagnostics": [
                {"tool": "hcl-parse", "code": "HCL.SYNTAX", "severity": "error", "error_class": "CODE_DEFECT",
                 "file": "infra/workload/" + evil + ".tf", "line": 3, "message": evil,
                 "snippet": "SNIPPET-CONTENT-MUST-NOT-APPEAR " + evil}]},
            "developer_failed_typed": {"error_class": "CODE_DEFECT", "codes": [evil]},
        },
        "state": {"events": [{"stage": "compliance", "kind": "client_blocked", "detail": {"call": evil}},
                             {"stage": "canary", "kind": "egress_blocked", "detail": {"host": "canary-only"}}]},
        "llm": {"calls": 2, "usd": 0.01, "served": {"backend": 2, "replay": 0, "replay_fallback": 0, "replay_miss": 0}},
        "spec_provenance": {"source": "spec_file", "spec_sha256": "ab" * 32, "match": None},
        "started": 0.0, "finished": 2.5,
    }
    score = {"checkpoints": {"C3_committed": {
        "tofu": {"status": "validated", "validate_ok": validate_ok,
                 "diagnostics": [{"severity": "error", "summary": evil, "detail": evil, "file": evil, "line": 1}]},
        "invariants": {"violations": 1, "I6_service_uri_cycles": [], "I3_literals": [evil]}}}}
    return {"key": key, "result": result, "score": score, "run_dir": "/nonexistent",
            "c3_files": [{"name": "infra/workload/" + evil + ".tf", "bytes": 12}, {"name": "main.py", "bytes": 3}]}


def _summary(records, evil=EVIL):
    s = metrics.aggregate(records)
    s["manifest"] = {"id": evil, "llm_mode": "synthetic", "model": evil, "product_sha": evil, "harness_sha": "abc",
                     "spec_source": "file", "spec_sha256": "ab" * 32, "product_id": "dryrun-12345678",
                     "tofu": evil, "provider_set": evil}
    return s


def _render(records=None):
    records = records or [_record()]
    return report.render(_summary(records), records)


ALLOWED_TAGS = {"html", "head", "meta", "title", "style", "body", "main", "h1", "h2", "h3", "p", "table", "tr", "th",
                "td", "div", "section", "span", "ul", "li"}
ALLOWED_ATTRS = {"lang", "charset", "http-equiv", "content", "name", "class"}


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.style_text = [], [], []
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs += [(tag, k, v) for k, v in attrs]
        self._in_style = tag == "style"

    def handle_endtag(self, tag):
        self._in_style = False

    def handle_data(self, data):
        if self._in_style:
            self.style_text.append(data)


def _parse_page(page):
    p = _Tags()
    p.feed(page)
    p.close()
    return p


def test_payloads_are_escaped_everywhere():
    page = _render()
    parsed = _parse_page(page)
    # the browser's view: only the module's own tags and attributes, whatever the data contained
    assert set(parsed.tags) <= ALLOWED_TAGS, set(parsed.tags) - ALLOWED_TAGS
    assert {k for _, k, _ in parsed.attrs} <= ALLOWED_ATTRS, parsed.attrs
    assert parsed.tags.count("style") == 1 and page.count("</style>") == 1
    assert not [a for a in parsed.attrs if a[1] == "class" and not re.fullmatch(r"[a-z ]+", a[2] or "")]
    low = page.lower()
    assert "<script" not in low and "<img" not in low and "<svg" not in low and "<a " not in low
    assert not re.search(r"<[a-z][^>]*\son[a-z]+\s*=", low), "inline event handler attribute"
    # the payload text is still visible, escaped
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in page
    assert "javascript:alert(1)" in page  # inert text, never an attribute value


def test_csp_meta_and_no_external_resources():
    page = _render()
    assert ('<meta http-equiv="Content-Security-Policy" content="default-src &#x27;none&#x27;; '
            'style-src &#x27;unsafe-inline&#x27;">') in page
    parsed = _parse_page(page)
    for bad in ("script", "link", "iframe", "object", "embed", "form", "base", "img", "a", "svg"):
        assert bad not in parsed.tags, bad
    assert not [a for a in parsed.attrs if a[1] in ("src", "href", "action", "style")]
    css = "".join(parsed.style_text)
    assert css == report.STYLE and "url(" not in css and "@import" not in css


def test_generated_file_contents_are_never_embedded():
    page = _render()
    assert "SNIPPET-CONTENT-MUST-NOT-APPEAR" not in page
    assert "main.py" in page and "names and sizes only" in page


def test_both_limit_boxes_and_the_wording_rule_are_present():
    page = _render()
    assert "What this does not check" in page and "How this differs from a real run" in page
    for line in report.NOT_CHECKED + report.differs("synthetic"):
        assert report._e(line) in page
    assert "never means &quot;will deploy&quot;" in page


@pytest.mark.parametrize("mode", ["synthetic", "replay-strict", "record", "live", "replay-then-live"])
def test_credentials_line_is_qualified_by_mode(mode):
    """RT fix 5: only synthetic and replay-strict may say the child has no credentials."""
    rec = _record()
    s = _summary([rec])
    s["manifest"]["llm_mode"] = mode
    page = report.render(s, [rec])
    lines = report.differs(mode)
    for line in lines:
        assert report._e(line) in page
    last = lines[-1]
    if mode in report.BILLED_MODES:
        assert "no credentials" not in last and "one short-lived access token" in last
        assert "--impersonate-service-account" in last
        assert report._e(report.differs("synthetic")[-1]) not in page
    else:
        assert "no credentials and no token" in last
    assert report.differs(mode)[:-1] == report.DIFFERS_COMMON


def test_synthetic_wording_names_the_eval_only_junior_files():
    """RT fix 6: after lane 19 the product has no junior stub; synthetic supplies eval-only junior files."""
    line = report.NOT_CHECKED[-1]
    assert "eval-only junior files" in line and "architect, red team and lead plan" in line


def _hostile_record(key=EVIL):
    rec = _record(key=key, outcome=EVIL)
    rec["result"]["llm"]["served"] = {EVIL: 1, "replay": 1}
    return rec


@pytest.mark.parametrize("variant", ["outcome", "invalid_reasons", "key_and_served"])
def test_payloads_in_outcome_reasons_key_and_served_are_escaped(variant):
    """RT fix 4: the fields that reach the verdict chip and the run heading (mutants M6/M7)."""
    if variant == "outcome":  # rule 7 echoes the outcome into the verdict, and the verdict into the chip
        rec = _record(outcome=EVIL)
    elif variant == "invalid_reasons":  # rule 2 puts the first reason into the verdict, and so into the chip
        rec = _record()
        rec["result"]["valid_run"] = False
        rec["result"]["invalid_reasons"] = [EVIL, "timeout"]
    else:
        rec = _hostile_record()
    page = report.render(_summary([rec]), [rec])
    parsed = _parse_page(page)
    assert set(parsed.tags) <= ALLOWED_TAGS, set(parsed.tags) - ALLOWED_TAGS
    assert {k for _, k, _ in parsed.attrs} <= ALLOWED_ATTRS, parsed.attrs
    low = page.lower()
    assert "<script" not in low and "<img" not in low and "<svg" not in low and "<a " not in low
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    if variant != "key_and_served":
        assert "<span class=\"chip inc\">INCONCLUSIVE:" + report._e(
            ("unknown_outcome:" if variant == "outcome" else "") + EVIL) in page


def test_same_input_gives_byte_identical_output():
    recs = [_record("spec-r1"), _record("spec-r2", validate_ok=False)]
    a = report.render(_summary(recs), recs)
    b = report.render(_summary(copy.deepcopy(recs)), copy.deepcopy(recs))
    assert a == b and a.encode("utf-8") == b.encode("utf-8")


def test_matrix_shows_k_of_n_and_every_verdict():
    recs = [_record("spec-r1"), _record("spec-r2", validate_ok=False), _record("spec-r3", validate_ok=None)]
    page = report.render(_summary(recs), recs)
    assert "1/3 would succeed" in page
    for v in ("WOULD_SUCCEED", "WOULD_FAIL_AT:deploy", "INCONCLUSIVE:validator_unavailable"):
        assert v in page


def test_long_strings_are_truncated_with_a_marker():
    rec = _record(evil="A" * 5000)
    page = report.render(_summary([rec], evil="ok"), [rec])
    assert "A" * 2000 + report.TRUNC_MARKER in page and "A" * 2001 not in page


def test_missing_stages_and_scores_render():
    rec = {"key": "spec-r1", "result": {"example": "spec", "run": 1, "valid_run": False,
                                        "invalid_reasons": ["harness_error"], "pipeline_outcome": None},
           "run_dir": "/nonexistent"}
    page = report.render(_summary([rec]), [rec])
    assert "INCONCLUSIVE:harness_error" in page and "not reached" in page


# Markup builders: a call to one of these returns markup built only from escaped values (each body is itself checked)
BUILDERS = {"_e", "_row", "_table", "_kv", "_ul", "_chip", "_card", "_chip_class", "_run_section", "_stage_pairs"}
# Parameters that are documented as markup (the caller passes builder output); every call site is checked instead
MARKUP_PARAMS = {("_card", "inner", 1)}
SAFE_MODULE_NAMES = {"STYLE"}


def _flatten_add(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _flatten_add(node.left) + _flatten_add(node.right)
    return [node]


class _Safety:
    """Every operand that reaches markup is a str constant, an _e(...) / builder call, STYLE, a local built only from
    those, or a documented markup parameter."""

    def __init__(self, tree):
        self.tree = tree
        self.funcs = {f.name: f for f in tree.body if isinstance(f, ast.FunctionDef)}
        self.module_assigns = {}
        for n in tree.body:
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        self.module_assigns.setdefault(t.id, []).append(n.value)

    def _local_values(self, fn, name):
        vals = []
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
                vals.append(n.value)
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and isinstance(n.target, ast.Name) \
                    and n.target.id == name and n.value is not None:
                vals.append(n.value)
            elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "append"
                  and isinstance(n.func.value, ast.Name) and n.func.value.id == name):
                vals += n.args
        return vals

    def safe(self, node, fn, seen=()):
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            return node.func.id in BUILDERS
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join" \
                and isinstance(node.func.value, ast.Constant) and len(node.args) == 1:
            arg = node.args[0]
            if isinstance(arg, (ast.GeneratorExp, ast.ListComp)):
                return self.safe(arg.elt, fn, seen)
            return self.safe(arg, fn, seen)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return all(self.safe(o, fn, seen) for o in _flatten_add(node))
        if isinstance(node, ast.IfExp):
            return self.safe(node.body, fn, seen) and self.safe(node.orelse, fn, seen)
        if isinstance(node, ast.List):
            return all(self.safe(e, fn, seen) for e in node.elts)
        if isinstance(node, ast.Name):
            if node.id in SAFE_MODULE_NAMES:
                return True
            if fn is not None and any(fn.name == f and node.id == p for f, p, _ in MARKUP_PARAMS):
                return True
            if (fn and fn.name, node.id) in seen:
                return True
            if fn is not None and node.id in {a.arg for a in fn.args.args}:
                return False  # a raw parameter
            vals = self._local_values(fn, node.id) if fn is not None else []
            vals = vals or self.module_assigns.get(node.id, [])
            return bool(vals) and all(self.safe(v, fn, seen + ((fn and fn.name, node.id),)) for v in vals)
        return False

    def violations(self):
        bad = []
        for fn in self.funcs.values():
            if fn.name == "_e":
                continue  # the escaper itself (truncation marker concatenation)
            for node in ast.walk(fn):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    ops = _flatten_add(node)
                    markup = any(isinstance(o, ast.Constant) and isinstance(o.value, str)
                                 and ("<" in o.value or ">" in o.value) for o in ops)
                    if markup and not self.safe(node, fn):
                        bad.append(fn.name + ": " + ast.unparse(node))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    for f, _, idx in MARKUP_PARAMS:
                        if node.func.id == f and len(node.args) > idx and not self.safe(node.args[idx], fn):
                            bad.append(fn.name + ": markup arg " + ast.unparse(node.args[idx]))
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "join"
                        and isinstance(node.func.value, ast.Constant) and node.func.value.value == ""
                        and node.args and isinstance(node.args[0], ast.Name)
                        and not self.safe(node.args[0], fn)):
                    bad.append(fn.name + ": joined list " + node.args[0].id)
        return bad


def test_every_concatenation_into_markup_is_escaped():
    """RT fix 4: report.py builds markup with `+` (it has no f-strings), so the pin is over `+` chains: every operand
    of a chain that emits markup is a constant, `_e(...)`, a builder call, STYLE, or a local built only from those."""
    tree = ast.parse(REPORT_SRC.read_text())
    assert _Safety(tree).violations() == []


@pytest.mark.parametrize("mutant", [
    ('"\\">" + _e(v) + "</span>"', '"\\">" + v + "</span>"'),            # M6: chip renders v unescaped
    ('<h3>" + _e(title) + "</h3>', '<h3>" + title + "</h3>'),             # M7: card renders title unescaped
    ('"<li>" + _e(i) + "</li>"', '"<li>" + str(i) + "</li>"'),
    ('parts.append("</section>")', 'parts.append(str(row.get("key")))'),
    ('_card("LLM", _kv(', '_card("LLM", str(row) + _kv('),
])
def test_concatenation_pin_kills_unescaped_mutants(mutant):
    src = REPORT_SRC.read_text()
    old, new = mutant
    assert src.count(old) == 1, old
    assert _Safety(ast.parse(src.replace(old, new))).violations() != []


def _formatted_values(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    yield v


def test_module_interpolates_only_escaped_values():
    """AST pin: every f-string value in report.py is a direct `_e(...)` call; no str.format, no %-formatting."""
    tree = ast.parse(REPORT_SRC.read_text())
    bad = [ast.unparse(v.value) for v in _formatted_values(tree)
           if not (isinstance(v.value, ast.Call) and isinstance(v.value.func, ast.Name) and v.value.func.id == "_e")]
    assert bad == [], bad
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            pytest.fail("str.format in report.py: " + ast.unparse(node))
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)):
            pytest.fail("%-formatting in report.py: " + ast.unparse(node))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not names & {"open", "Path", "urlopen", "subprocess"}, "render() must stay pure (no I/O)"


def test_escape_helper_escapes_quotes_and_angle_brackets():
    assert report._e('<"\'&>') == "&lt;&quot;&#x27;&amp;&gt;"
    assert report._e(None) == ""

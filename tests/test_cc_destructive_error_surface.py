"""The Control Center dashboard shows every refused or failed destructive action (fail loudly, invariant 8).

Live 10-29 (dev install): "I understand, decommission workload" spun and came back with no message. The route answered
502 with vending's typed {code, detail} (LEDGER_UNPROVENANCED: the lane 18 destructive guard refuses a project vended
before the provenance ledger), but the dashboard showed it in a toast, which sits under the open modal and is gone
after 4 seconds.

Now:
  * the decommission modal stays open and shows the HTTP status, the typed `code` and the server's `detail`
    (x-text only), and the spinner stops;
  * archive, unarchive, sandbox extend / confirm / promote and the redeploy modal show the same fields in an error
    dialog that sits above every modal and stays until dismissed;
  * a known code adds an operator explanation + next step from DESTRUCTIVE_REFUSAL_GUIDE (an exact-key map in the
    template); an unknown code shows the raw detail only. The map covers every refusal code project-vending's guard
    and lifecycle routes and the Control Center's approval / vending-call paths can send (read from their source with
    `ast`, so a new code without an explanation fails here).

Hermetic: the template is checked statically; the parsing functions are also executed with a local JavaScript engine
when one is on the machine (node, or JavaScriptCore through osascript), fed through stdin (no file, no network), on
bodies produced by the real destructive_actions.failure_response / refusal_response.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO, "apps", "control-center")
DASHBOARD = os.path.join(CC_DIR, "templates", "dashboard.html")
GUARD_SOURCES = [os.path.join(REPO, "apps", "project-vending", "destructive_guard.py"),
                 os.path.join(REPO, "apps", "project-vending", "vending.py")]
CC_SOURCES = [os.path.join(CC_DIR, "destructive_actions.py"),
              os.path.join(CC_DIR, "routes", "install_status.py")]
GUIDE_DECL = "const DESTRUCTIVE_REFUSAL_GUIDE = "
LEDGER_UNPROVENANCED_TEXT = {
    "explanation": "This workload's project was created before StackVend's deletion safety existed, so StackVend "
                   "will not delete it.",
    "next_step": "If you are sure, delete the project yourself in the Google Cloud console.",
}
# The handlers of the destructive flows and the action label each one shows.
HANDLERS = {
    "archiveWorkload": "Archive",
    "unarchiveWorkload": "Unarchive",
    "extendSandboxWorkload": "Sandbox extend",
    "confirmSandboxWorkload": "Sandbox confirm",
    "promoteSandboxWorkload": "Sandbox promote",
    "submitRedeploy": "Redeploy",
}


@pytest.fixture(scope="module")
def html():
    with open(DASHBOARD, encoding="utf-8") as f:
        return f.read()


def _method(html, name):
    """The body of one Alpine component method (`name(...) {` up to the next method at the same indent)."""
    start = html.index("\n                " + name + "(")
    end = html.index("\n                },\n", start)
    return html[start:end + len("\n                },")]


def _guide_span(html):
    start = html.index(GUIDE_DECL) + len(GUIDE_DECL)
    guide, length = json.JSONDecoder().raw_decode(html[start:])
    return guide, start, start + length


def _guide(html):
    return _guide_span(html)[0]


def _call_name(call):
    f = call.func
    return f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)


def _codes_from(paths, constructors):
    """String-literal codes passed to the typed refusal constructors (`name -> index of the code argument`)."""
    codes = set()
    for path in paths:
        with open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in constructors:
                if _call_name(node) == "VendingOutcome" and not (
                        node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value is False):
                    continue  # VendingOutcome(True, 200, "OK", ...) is the success outcome, not a refusal
                idx = constructors[_call_name(node)]
                arg = node.args[idx] if len(node.args) > idx else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    codes.add(arg.value)
    return codes


def _vending_decommission_failed_literal():
    """vending.py turns a non-guard exception during the delete into DECOMMISSION_FAILED (a conditional, not a call)."""
    with open(GUARD_SOURCES[1], encoding="utf-8") as f:
        tree = ast.parse(f.read())
    return any(isinstance(n, ast.IfExp) and isinstance(n.orelse, ast.Constant) and n.orelse.value == "DECOMMISSION_FAILED"
               for n in ast.walk(tree))


def _all_codes():
    guard = _codes_from(GUARD_SOURCES, {"_refuse": 0, "DeletionRefused": 0, "DecommissionFailed": 0,
                                         "CallerRefused": 1})
    cc = _codes_from(CC_SOURCES, {"MintRefused": 1, "VendingOutcome": 2})
    extra = {"DECOMMISSION_FAILED"} if _vending_decommission_failed_literal() else set()
    return guard, cc, extra


# ============================================================================ the typed explanation map
def test_guide_is_strict_json_keyed_by_code_with_explanation_and_next_step(html):
    guide = _guide(html)
    assert isinstance(guide, dict) and guide
    for code, entry in guide.items():
        assert code == code.strip() and code.upper() == code, code
        assert set(entry) == {"explanation", "next_step"}, code
        assert all(isinstance(v, str) and v.strip() for v in entry.values()), code


def test_code_collection_is_not_vacuous():
    guard, cc, extra = _all_codes()
    assert {"LEDGER_UNPROVENANCED", "GUARD_UNCONFIGURED", "LEDGER_MISMATCH", "NOT_STACKVEND_OWNED", "LIEN_PRESENT",
            "APPROVAL_EXPIRED", "CALLER_NOT_ALLOWED", "EXTENSION_LIMIT", "LIFECYCLE_FAILED"} <= guard
    assert {"APPROVAL_NOT_ADMIN", "APPROVAL_TARGET_UNKNOWN", "VENDING_UNREACHABLE", "VENDING_UNCONFIGURED"} <= cc
    assert extra == {"DECOMMISSION_FAILED"}
    assert len(guard) >= 30


def test_guide_covers_every_guard_and_cc_code(html):
    guide = _guide(html)
    guard, cc, extra = _all_codes()
    missing = sorted((guard | cc | extra) - set(guide))
    assert missing == [], f"add an explanation + next step to DESTRUCTIVE_REFUSAL_GUIDE for: {missing}"


def test_guide_has_no_codes_nobody_sends(html):
    guard, cc, extra = _all_codes()
    unknown = sorted(set(_guide(html)) - (guard | cc | extra))
    assert unknown == [], unknown


def test_guide_covers_the_guard_status_table():
    """Every code in the guard's HTTP status table (destructive_guard._STATUS) has an explanation too."""
    with open(GUARD_SOURCES[0], encoding="utf-8") as f:
        tree = ast.parse(f.read())
    [table] = [n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "_STATUS" for t in n.targets)]
    keys = {k.value for k in table.keys}
    with open(DASHBOARD, encoding="utf-8") as f:
        guide = _guide(f.read())
    assert keys and keys <= set(guide), sorted(keys - set(guide))


def test_ledger_unprovenanced_text_is_exact(html):
    assert _guide(html)["LEDGER_UNPROVENANCED"] == LEDGER_UNPROVENANCED_TEXT


def test_guide_lookup_is_an_exact_own_key():
    with open(DASHBOARD, encoding="utf-8") as f:
        html = f.read()
    fn = _method(html, "refusalGuide")
    assert "typeof code === 'string'" in fn
    assert "Object.prototype.hasOwnProperty.call(DESTRUCTIVE_REFUSAL_GUIDE, code)" in fn


def test_code_is_never_read_out_of_the_message_text(html):
    parse = _method(html, "actionErrorFromAnswer") + _method(html, "refusalGuide")
    for pattern_api in ("RegExp", ".match(", ".test(", ".search(", ".split(", "indexOf(", "startsWith(", "/^"):
        assert pattern_api not in parse, pattern_api
    assert "typeof body.code === 'string'" in parse


# ============================================================================ the decommission modal
def _decommission_modal(html):
    start = html.index("<!-- HIGH-FRICTION DECOMMISSION WORKLOAD MODAL -->")
    return html[start:html.index('<span x-text="isDecommissioning ? ', start)]


def _block(html, element_id):
    start = html.rindex("<div", 0, html.index(f'id="{element_id}"'))
    depth, i = 0, start
    while True:
        nxt_open, nxt_close = html.find("<div", i), html.find("</div>", i)
        if nxt_open != -1 and nxt_open < nxt_close:
            depth, i = depth + 1, nxt_open + 4
        else:
            depth, i = depth - 1, nxt_close + 6
            if depth == 0:
                return html[start:i]


def test_decommission_modal_renders_status_code_detail_and_guide_as_text(html):
    modal = _decommission_modal(html)
    assert 'id="decommission-error"' in modal  # inside the modal, so it shows while the modal is open
    block = _block(html, "decommission-error")
    assert 'x-show="decommissionError"' in block and 'role="alert"' in block
    for binding in ("x-text=\"decommissionError && decommissionError.status ? ('HTTP ' + decommissionError.status)",
                    "x-text=\"decommissionError ? decommissionError.code : ''\"",
                    "x-text=\"decommissionError && decommissionError.guide ? decommissionError.guide.explanation : ''\"",
                    "x-text=\"decommissionError && decommissionError.guide ? decommissionError.guide.next_step : ''\"",
                    "x-text=\"decommissionError ? decommissionError.detail : ''\""):
        assert binding in block, binding
    assert "x-html" not in block


def test_submit_decommission_keeps_the_modal_open_with_the_error_and_stops_the_spinner(html):
    fn = _method(html, "async submitDecommission")
    assert "failure = await this.describeActionError(res, 'Decommission', pid);" in fn
    assert "failure = this.networkActionError(e, 'Decommission', pid);" in fn
    assert "} finally {\n                        this.isDecommissioning = false;\n                    }" in fn
    # the error path sets the in-modal error and returns before anything closes the modal
    err = fn.index("if (failure) {")
    assert fn.index("this.decommissionError = failure;", err) < fn.index("return;", err)
    assert fn.index("this.closeDecommissionModal();") > fn.index("if (decommissioned) {") > err
    assert fn.count("this.closeDecommissionModal();") == 1
    # closed meanwhile -> the error dialog shows it instead (never dropped)
    assert "this.showActionError(failure);" in fn
    assert "showToast(err.detail" not in fn and "res.json()" not in fn


def test_opening_and_closing_the_modal_clears_a_previous_error(html):
    assert "this.decommissionError = null;" in _method(html, "openDecommissionModal")
    assert "this.decommissionError = null;" in _method(html, "closeDecommissionModal")


# ============================================================================ the other destructive flows
def test_error_dialog_sits_above_every_modal_and_renders_text_only(html):
    block = _block(html, "action-error-dialog")
    assert 'x-show="actionError"' in block and 'role="alertdialog"' in block
    assert "z-[60]" in block  # every modal is z-50; a toast (z-50, earlier in the page) is hidden under them
    for binding in ("x-text=\"actionError && actionError.status ? ('HTTP ' + actionError.status)",
                    "x-text=\"actionError ? actionError.code : ''\"",
                    "x-text=\"actionError && actionError.guide ? actionError.guide.explanation : ''\"",
                    "x-text=\"actionError && actionError.guide ? actionError.guide.next_step : ''\"",
                    "x-text=\"actionError ? actionError.detail : ''\"",
                    '@click="dismissActionError()"'):
        assert binding in block, binding
    assert "x-html" not in block
    # it stays until dismissed: nothing clears it on a timer
    assert "setTimeout" not in _method(html, "showActionError")


@pytest.mark.parametrize("name,label", sorted(HANDLERS.items()))
def test_destructive_handlers_show_every_non_2xx_answer_in_the_dialog(html, name, label):
    fn = _method(html, "async " + name)
    assert f"await this.describeActionError(res, '{label}'" in fn, name
    assert f"this.showActionError(this.networkActionError(e, '{label}'" in fn, name
    assert "this.showActionError(" in fn
    assert "showToast(err.detail" not in fn and "await res.json();\n" not in fn.split("if (res.ok)")[1].split("} else {")[1]


def test_redeploy_outcome_unknown_branch_is_kept(html):
    fn = _method(html, "async submitRedeploy")
    i = fn.index("d.error_class === 'REDEPLOY_OUTCOME_UNKNOWN'")
    assert "const d = failure.body ? failure.body.detail : null;" in fn[:i]
    assert "'info'" in fn[i:i + 600] and "this.fetchWorkloads()" in fn[i:i + 600]


# ============================================================================ executed with a JavaScript engine
def _js_runner():
    if shutil.which("node"):
        return ["node", "-"], "process.stdout.write(%s)"
    if shutil.which("osascript"):
        return ["osascript", "-l", "JavaScript", "-"], "%s"
    return None, None


def _cc_bodies():
    """Bodies from the real route helpers (the shape the dashboard reads)."""
    saved = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "error-surface-test.apps.googleusercontent.com"
    try:
        if CC_DIR not in sys.path:
            sys.path.insert(0, CC_DIR)
        import destructive_actions as da
    finally:
        if saved is None:
            os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
        else:
            os.environ["GOOGLE_OAUTH_CLIENT_ID"] = saved
    unprov = da.failure_response(
        da.VendingOutcome(False, 403, "LEDGER_UNPROVENANCED", "workload_provenance/testplan02-c does not exist"),
        action="Decommission", product_id="testplan02-c")
    novel = da.failure_response(da.VendingOutcome(False, 409, "SOMETHING_NEW", "a new refusal"),
                                action="Decommission", product_id="testplan02-c")
    mint = da.refusal_response(da.MintRefused(403, "APPROVAL_NOT_HUMAN", "no verified email on this session"))
    return [(r.status_code, r.body.decode()) for r in (unprov, novel, mint)]


def test_parsing_executes_on_real_route_bodies_and_other_answers(html):
    cmd, emit = _js_runner()
    if cmd is None:
        pytest.skip("no local JavaScript engine (node or osascript); the static checks above still apply")
    guide, start, end = _guide_span(html)
    decl = "var DESTRUCTIVE_REFUSAL_GUIDE = " + html[start:end] + ";\n"
    obj = "var o = {\n%s\n%s\n%s\n};\n" % (_method(html, "refusalGuide").strip(),
                                          _method(html, "actionErrorFromAnswer").strip(),
                                          _method(html, "networkActionError").strip().rstrip(","))
    proxy_html = "<html><body>502 Bad Gateway</body></html>"
    cases = _cc_bodies() + [
        (404, json.dumps({"detail": "Workload 'x' not found."})),
        (422, json.dumps({"detail": [{"loc": ["body", "confirm_product_id"], "msg": "field required"}]})),
        (502, json.dumps({"detail": {"error_class": "REDEPLOY_FAILED", "detail": "boom"}})),
        (504, proxy_html),
        (500, ""),
        (403, json.dumps({"detail": "x", "code": "toString"})),
        (403, json.dumps({"detail": "x", "code": "__proto__"})),
    ]
    body = (decl + obj + "var cases = %s;\n" % json.dumps(cases)
            + emit % ("JSON.stringify({r: cases.map(function (c) { var e = o.actionErrorFromAnswer(c[0], c[1], "
                      "'Decommission', 'testplan02-c'); return [e.status, e.code, e.detail, e.guide, e.action, "
                      "e.target]; }), n: o.networkActionError({message: 'Failed to fetch'}, 'Archive', 'p')})")
            + ";\n")
    out = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout.strip().splitlines()[-1])
    r = got["r"]
    # the live case: typed code, the server's detail verbatim, the operator guide
    assert r[0] == [502, "LEDGER_UNPROVENANCED",
                    "LEDGER_UNPROVENANCED: workload_provenance/testplan02-c does not exist",
                    LEDGER_UNPROVENANCED_TEXT, "Decommission", "testplan02-c"]
    # an unknown code: raw detail only, no guide
    assert r[1][:4] == [502, "SOMETHING_NEW", "SOMETHING_NEW: a new refusal", None]
    # the CC's own refusal carries its code too
    assert r[2][:3] == [403, "APPROVAL_NOT_HUMAN", "APPROVAL_NOT_HUMAN: no verified email on this session"]
    assert r[2][3] == guide["APPROVAL_NOT_HUMAN"]
    # untyped answers: shown as sent, no guide
    assert r[3][:4] == [404, "", "Workload 'x' not found.", None]
    assert r[4][1] == "" and json.loads(r[4][2]) == [{"loc": ["body", "confirm_product_id"], "msg": "field required"}]
    assert r[5][:4] == [502, "REDEPLOY_FAILED", "boom", None]
    assert r[6][:4] == [504, "", proxy_html, None]
    assert r[7][:4] == [500, "", "(the answer had no body)", None]
    # inherited object keys are never a guide entry
    assert r[8][3] is None and r[9][3] is None
    assert got["n"]["status"] == 0 and "Failed to fetch" in got["n"]["detail"] and got["n"]["guide"] is None


# ============================================================================ MCP_ACTION card refusals
MCP_GUIDE_DECL = "const MCP_CARD_REFUSAL_GUIDE = "


def test_mcp_card_refusal_guide_is_strict_json_and_covers_the_decision_codes(html):
    """APPROVAL-CONSUME-VIA-VENDING RT N3: the platform-action card guide parses and explains every 409 code of
    routes/approvals.py::_decide_mcp_action."""
    start = html.index(MCP_GUIDE_DECL) + len(MCP_GUIDE_DECL)
    guide, _ = json.JSONDecoder().raw_decode(html[start:])
    for code, entry in guide.items():
        assert code == code.strip() and code.upper() == code, code
        assert set(entry) == {"explanation", "next_step"}, code
        assert all(isinstance(v, str) and v.strip() for v in entry.values()), code
    with open(os.path.join(CC_DIR, "routes", "approvals.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    [fn] = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_decide_mcp_action"]
    codes = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("APPROVAL_"):
            codes.add(node.value.split(":", 1)[0])
        if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant) \
                and str(node.values[0].value).startswith("APPROVAL_"):
            codes.add(str(node.values[0].value).split(":", 1)[0])
    assert {"APPROVAL_CARD_CHANGED", "APPROVAL_CARD_MALFORMED", "APPROVAL_TARGET_MISMATCH",
            "APPROVAL_TARGET_UNKNOWN"} <= codes
    assert codes <= set(guide), sorted(codes - set(guide))

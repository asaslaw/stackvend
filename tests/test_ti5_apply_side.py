"""TI-5a / TI-5b (register rows, owner 10-21): parity of the terraform server's typed-intent apply side with the shared
contracts it mirrors (the MCP container has its own shared/ copy without diagnostics / artifact_ownership / iac_intent,
so the server keeps exact local copies of the few constants and rules; these tests pin them to the originals).
Behaviour tests live in mcp-servers/terraform/test_service.py (test_ti5_*). Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW = os.path.join(REPO, "apps", "orchestrator-gateway")
for p in (os.path.dirname(__file__), GW, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture()
def tf(monkeypatch):
    from fd4g_support import load_tf_service
    return load_tf_service(monkeypatch)


def test_constants_match_the_shared_contracts(tf):
    from shared import iac_intent as II
    from shared.diagnostics import MESSAGE_CAP
    assert tf.IAC_INTENT_SCHEMA == II.SCHEMA_ID
    assert tf.IAC_INTENT_REPO_PATH == II.INTENT_PATH
    assert tf.IAC_INTENT_RENDER_BASENAME == os.path.basename(II.RENDER_PATH)
    assert tf._APPLY_MESSAGE_CAP == MESSAGE_CAP
    assert tf.TOPOLOGY_RECORD_SCHEMA == __import__("shared.service_topology", fromlist=["x"]).TOPOLOGY_RECORD_SCHEMA


def test_user_owned_rule_covers_the_artifact_ownership_rule(tf):
    """Every file artifact_ownership.classify_path calls USER_OWNED by name (human files, override files, the legacy
    custom.tf beside an intent) is USER_OWNED for the apply side too; platform renders never are."""
    from shared.artifact_ownership import (CUSTOM_TF, PLATFORM_RENDERED_FLOOR, USER_OWNED_BASENAMES,
                                           _is_override_file)
    for base in sorted(USER_OWNED_BASENAMES) + ["override.tf", "a_override.tf", "override.tf.json",
                                                 "a_override.tf.json"]:
        assert _is_override_file(base) or base in USER_OWNED_BASENAMES
        assert tf.apply_user_owned("infra/workload/" + base), base
    assert tf.apply_user_owned(CUSTOM_TF, True) and not tf.apply_user_owned(CUSTOM_TF, False)
    for p in PLATFORM_RENDERED_FLOOR:
        assert not tf.apply_user_owned(p, True), p


@pytest.mark.parametrize("summary", ["Reference to undeclared resource", 'Unsupported argument: "foo"',
                                     'Duplicate resource "google_x" configuration', "Cycle: module.a, module.b",
                                     "Invalid value for \"x\" parameter: bad", "", "Missing required argument",
                                     "x" * 200])
def test_code_naming_is_the_gateway_slug(tf, summary):
    from developer_agent.validators.tofu_diagnostics import slug
    assert tf._apply_code_slug(summary) == slug(summary)


def test_apply_report_is_a_valid_shared_validation_report(tf, tmp_path):
    from shared.diagnostics import ErrorClass, ValidationReport
    (tmp_path / "iac_intent.json").write_text(json.dumps({"schema": "iac_intent/v1", "modules": [
        {"module": "storage-bucket", "name": "b", "args": {}}]}))
    render = json.dumps({"//": "r", "module": {"b": {"source": "../modules/storage-bucket"}}}, indent=2)
    (tmp_path / "custom.tf.json").write_text(render)
    inside = render.index('"source"')
    vjson = json.dumps({"diagnostics": [
        {"severity": "error", "summary": "Unsupported argument", "detail": "d" * 5000,
         "range": {"filename": "custom.tf.json", "start": {"line": 5, "column": 7, "byte": inside},
                   "end": {"line": 5, "column": 15, "byte": inside + 8}}, "snippet": {"code": "x\n" * 30}},
        {"severity": "error", "summary": "Bad", "range": {"filename": "infra/modules/m/main.tf",
                                                          "start": {"line": 1, "byte": 0}}}]})
    raw = tf.apply_validation_report(vjson, str(tmp_path))
    rep = ValidationReport.model_validate(raw)
    assert rep.source == "apply" and rep.status == "FAIL" and rep.error_class is ErrorClass.PLATFORM_DEFECT
    d0, d1 = rep.diagnostics
    assert (d0.error_class, d0.file, d0.block_address, d0.attribute_path) == (
        ErrorClass.CODE_DEFECT, "infra/workload/iac_intent.json", "module.b", "/modules/0")
    assert d1.file == "infra/modules/m/main.tf" and d1.error_class is ErrorClass.PLATFORM_DEFECT
    from shared.diagnostics import SNIPPET_MAX_LINES
    assert len(d0.detail.encode()) <= 2048
    assert len(raw["diagnostics"][0]["snippet"].split("\n")) == SNIPPET_MAX_LINES   # capped before the model
    only_intent = tf.apply_validation_report(json.dumps({"diagnostics": [json.loads(vjson)["diagnostics"][0]]}),
                                             str(tmp_path))
    assert ValidationReport.model_validate(only_intent).error_class is ErrorClass.CODE_DEFECT
    unparsed = ValidationReport.model_validate(tf.apply_validation_report("", "", fallback_error="engine text"))
    assert [d.code for d in unparsed.diagnostics] == ["TF.UNPARSED_APPLY_ERROR"]
    # Fable RT F1: no engine result -> a valid UNAVAILABLE report that claims no tofu run
    none = ValidationReport.model_validate(tf.apply_validation_report("", "", engine_result=False,
                                                                      fallback_error="container build failed"))
    assert (none.status, none.error_class, none.tools_ran, none.diagnostics) == (
        "UNAVAILABLE", ErrorClass.GATE_UNAVAILABLE, [], [])
    assert [d.code for d in none.report_only] == ["APPLY.UNTYPED_FAILURE"]
    assert none.report_only[0].message == "container build failed"


def test_json_spans_is_an_exact_scanner(tf):
    doc = {"//": "x", "module": {"a": {"k": [1, {"z": "}"}], "s": "q\"{"}, "b": {}},
           "resource": {"t": {"n": {"x": True, "y": None, "w": -1.5e3}}}, "output": {"o": {"value": "${a}"}}}
    for indent in (None, 2):
        text = json.dumps(doc, indent=indent, sort_keys=True)
        spans = tf._JsonSpans(text.encode()).spans()
        assert set(spans) == {"module.a", "module.b", "t.n", "output.o"}
        for addr, path in (("module.a", ("module", "a")), ("t.n", ("resource", "t", "n")),
                           ("output.o", ("output", "o"))):
            s, e = spans[addr]
            node = doc
            for k in path:
                node = node[k]
            assert json.loads(text[s:e]) == node
    assert tf._JsonSpans(b"{not json").spans() == {}

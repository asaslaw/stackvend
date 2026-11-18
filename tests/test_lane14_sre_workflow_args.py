"""
Wave 2 lane 14 PR-2: static pin between workflows/sre_remediation.yaml (castor-sre-remediation) and the sentinel's
dispatch payload (owner register row 24: the init_incident KeyError fix; plan section 2.5 item 8).

- init_incident reads every argument as ``${map.get(args, "<key>")}``: no KeyError is possible;
- the key set equals apps/log-sre-sentinel/sentinel.py REMEDIATION_ARG_KEYS and build_remediation_args() both ways;
- no other step expression references ``args``;
- validate_args raises a typed StackVendPipelineError SRE_ARGS_MISSING for each key;
- the intake message is published to spec-intake-events with source_channel "sre_sentinel", an explicit validated
  execution_mode (only FULL_BUILD today, never PLATFORM_REMEDIATION) and require_plan_approval true;
- the workflow never starts the main orchestrator directly (executions.create) and never logs at ERROR.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / "workflows" / "sre_remediation.yaml"
APP_DIR = REPO / "apps" / "log-sre-sentinel"


def _doc():
    return yaml.safe_load(WORKFLOW.read_text())


def _main_steps():
    return _doc()["main"]["steps"]


def _step(steps, name):
    for item in steps:
        if name in item:
            return item[name]
    raise KeyError(name)


def _walk(node, path=()):
    """Yield (path, value) for every scalar in the YAML tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, path + (i,))
    else:
        yield path, node


def _sentinel_arg_keys():
    """REMEDIATION_ARG_KEYS read from sentinel.py by AST (no import needed)."""
    tree = ast.parse((APP_DIR / "sentinel.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "REMEDIATION_ARG_KEYS":
            return tuple(ast.literal_eval(node.value))
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "REMEDIATION_ARG_KEYS" for t in node.targets):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError("REMEDIATION_ARG_KEYS not found in sentinel.py")


def _init_assignments():
    assigns = _step(_main_steps(), "init_incident")["assign"]
    out = {}
    for entry in assigns:
        assert isinstance(entry, dict) and len(entry) == 1
        out.update(entry)
    return out


def test_init_incident_reads_every_arg_with_map_get():
    assigns = _init_assignments()
    for key, expr in assigns.items():
        assert expr == '${map.get(args, "' + key + '")}', (key, expr)


def test_arg_keys_match_sentinel_both_ways():
    yaml_keys = set(_init_assignments())
    sentinel_keys = set(_sentinel_arg_keys())
    assert yaml_keys == sentinel_keys
    assert len(_sentinel_arg_keys()) == len(sentinel_keys)


def test_build_remediation_args_produces_exactly_the_yaml_keys():
    sys.path.insert(0, str(APP_DIR))
    try:
        import sentinel as sentinel_mod
    finally:
        sys.path.remove(str(APP_DIR))
    s = sentinel_mod.LogSRESentinel(project_id="mock-stackvend-project", firestore_client=object(), env={})
    args = s.build_remediation_args(incident_id="inc-1", trace_id="sre-1", execution_mode="FULL_BUILD",
                                    sre_sentinel_url="https://a", workspace_mcp_url="https://b",
                                    spec_intake_topic="projects/p/topics/spec-intake-events")
    assert set(args) == set(_init_assignments())
    assert all(isinstance(v, str) and v for v in args.values())


ARGS_OBJECT_CHECK = '${get_type(args) != "map"}'


def test_args_object_is_validated_before_any_map_get():
    """RT F5: a start with a null / non-map argument raises the typed SRE_ARGS_MISSING error before init_incident's
    map.get calls (which would raise an untyped TypeError on null)."""
    steps = _main_steps()
    names = [list(item)[0] for item in steps]
    assert names[:3] == ["validate_args_object", "init_incident", "validate_args"]
    switch = _step(steps, "validate_args_object")["switch"]
    assert [c["condition"] for c in switch] == [ARGS_OBJECT_CHECK]
    err = switch[0]["steps"][0]["raise_args_not_a_map"]["raise"]
    assert err == {"tag": "StackVendPipelineError", "error_class": "SRE_ARGS_MISSING", "key": "args"}


def test_no_other_step_references_args():
    steps = _main_steps()
    assert _doc()["main"]["params"] == ["args"]
    for item in steps:
        (name, body), = item.items()
        if name == "init_incident":
            continue
        if name == "validate_args_object":  # only the type check, pinned exactly above
            assert [c["condition"] for c in body["switch"]] == [ARGS_OBJECT_CHECK]
            continue
        for path, value in _walk(body):
            if isinstance(value, str):
                assert "args," not in value and "args." not in value and "args)" not in value, (name, path, value)


def test_validate_args_raises_typed_error_for_each_key():
    switch = _step(_main_steps(), "validate_args")["switch"]
    raised = {}
    for cond in switch:
        (inner_name, inner), = cond["steps"][0].items()
        err = inner["raise"]
        assert err["tag"] == "StackVendPipelineError" and err["error_class"] == "SRE_ARGS_MISSING"
        assert cond["condition"] == '${default(' + err["key"] + ', "") == ""}'
        raised[err["key"]] = inner_name
    assert set(raised) == set(_init_assignments())


def _remediate_steps():
    return _step(_main_steps(), "remediate")["try"]["steps"]


def test_execution_mode_is_validated_and_only_full_build_is_accepted():
    switch = _step(_remediate_steps(), "validate_execution_mode")["switch"]
    assert [c["condition"] for c in switch] == ['${execution_mode != "FULL_BUILD"}']
    err = switch[0]["steps"][0]["raise_mode_unsupported"]["raise"]
    assert err["error_class"] == "SRE_MODE_UNSUPPORTED"
    assert all("PLATFORM_REMEDIATION" not in str(v) for _, v in _walk(_doc()))  # comments excluded


def test_intake_message_published_to_topic_with_explicit_mode_and_forced_plan_approval():
    steps = _remediate_steps()
    msg = _step(steps, "build_intake_message")["assign"][0]["intake_message"]
    assert msg["source_channel"] == "sre_sentinel"
    assert msg["execution_mode"] == "${execution_mode}"
    assert msg["require_plan_approval"] is True
    assert msg["product_id"] == "${product_id}"
    assert set(msg) == {"product_id", "trace_id", "incident_id", "source_channel", "execution_mode",
                        "require_plan_approval", "spec_doc_id", "spec_text"}
    publish = _step(steps, "publish_intake")
    assert publish["call"] == "googleapis.pubsub.v1.projects.topics.publish"
    assert publish["args"]["topic"] == "${spec_intake_topic}"
    assert publish["args"]["body"]["messages"][0]["data"] == "${base64.encode(json.encode(intake_message))}"


def test_product_id_comes_from_triage_never_service_name():
    read = _step(_remediate_steps(), "read_rca")["assign"]
    assert {"product_id": '${default(map.get(rca_output.body, "product_id"), "")}'} in read
    text = WORKFLOW.read_text()
    assert "product_id: ${rca_output.body.service_name}" not in text
    assert _step(_remediate_steps(), "execute_rca")["args"]["body"] == {"trace_id": "${trace_id}",
                                                                        "incident_id": "${incident_id}"}


def test_incident_spec_503_not_configured_continues_without_doc():
    ticket = _step(_remediate_steps(), "create_incident_ticket")
    assert ticket["try"]["steps"][0]["call_create_incident_spec"]["call"] == "http.post"
    exc = ticket["except"]
    assert exc["as"] == "ticket_error"
    names = [list(s)[0] for s in exc["steps"]]
    assert names == ["check_ticket_status", "check_ticket_error_class", "continue_without_doc"]
    class_check = exc["steps"][1]["check_ticket_error_class"]["switch"][0]["condition"]
    assert '"INCIDENT_TEMPLATE_NOT_CONFIGURED"' in class_check
    assert exc["steps"][2]["continue_without_doc"]["assign"] == [{"spec_doc_id": ""}]


def test_failures_are_reported_to_sentinel_and_logged_at_warning_only():
    remediate = _step(_main_steps(), "remediate")
    exc_steps = remediate["except"]["steps"]
    names = [list(s)[0] for s in exc_steps]
    assert names == ["log_remediation_failure", "report_failure_outcome", "finish_failed"]
    report = exc_steps[1]["report_failure_outcome"]["try"]
    assert report["args"]["url"] == '${sre_sentinel_url + "/incidents/" + incident_id + "/outcome"}'
    assert report["args"]["body"]["outcome"] == "REMEDIATION_FAILED"
    severities = []

    def _collect(node):
        if isinstance(node, dict):
            if node.get("call") == "sys.log":
                severities.append(node["args"]["severity"])
            for v in node.values():
                _collect(v)
        elif isinstance(node, list):
            for v in node:
                _collect(v)

    _collect(_doc())
    assert len(severities) == 3 and set(severities) == {"WARNING"}


def test_never_starts_main_orchestrator_directly():
    calls = [v for p, v in _walk(_doc()) if p and p[-1] == "call"]
    assert "googleapis.workflowexecutions.v1.projects.locations.workflows.executions.create" not in calls
    assert set(calls) <= {"http.post", "sys.log", "googleapis.pubsub.v1.projects.topics.publish"}
    text = WORKFLOW.read_text()
    assert "main_orchestrator_name" not in text and "dlq_topic" not in text


def test_outcome_values_match_sentinel_allow_set():
    tree = ast.parse((APP_DIR / "sentinel.py").read_text())
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Constant):
                consts[node.targets[0].id] = node.value.value
    allowed = {consts["OUTCOME_REMEDIATION_FAILED"], consts["OUTCOME_INTAKE_PUBLISHED"]}
    outcomes = {v for p, v in _walk(_doc()) if p and p[-1] == "outcome"}
    assert outcomes == allowed


def test_step_names_are_unique():
    names = []

    def _collect(steps):
        for item in steps:
            (name, body), = item.items()
            names.append(name)
            _nested(body)

    def _nested(body):
        if isinstance(body, dict):
            for key, value in body.items():
                if key == "steps" and isinstance(value, list):
                    _collect(value)
                else:
                    _nested(value)
        elif isinstance(body, list):
            for v in body:
                _nested(v)

    _collect(_main_steps())
    assert len(names) == len(set(names)), sorted(n for n in names if names.count(n) > 1)

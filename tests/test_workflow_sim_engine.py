"""
Unit tests of the offline Cloud Workflows interpreter (tests/workflow_sim.py) on small inline YAML snippets.

Scenario tests of workflows/main_orchestrator.yaml live elsewhere; these only pin the interpreter's semantics,
including the binding rule that unmodelled syntax/functions raise SimulatorUnsupported.
"""

import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import base64
import json
import textwrap

import pytest

from workflow_sim import (
    SimConnectionError,
    SimTimeout,
    Simulator,
    SimulatorUnsupported,
    WorkflowError,
    http_error,
    iter_expressions,
    known_calls,
    known_functions,
    parse_expression,
    run,
    validate,
)


def wf(text: str) -> str:
    return textwrap.dedent(text)


def ret(expr: str, args=None, **kw):
    """Run a one-step workflow returning ``expr`` (a YAML scalar, usually '${...}')."""
    doc = {"main": {"params": ["args"], "steps": [{"r": {"return": expr}}]}}
    return run(doc, args, **kw)


def ret_value(expr: str, args=None, **kw):
    res = ret(expr, args, **kw)
    assert res.state == "SUCCEEDED", res.error
    return res.result


def ret_error(expr: str, args=None, **kw):
    res = ret(expr, args, **kw)
    assert res.state == "FAILED", res.result
    return res.error


# ------------------------------------------------------------------------------------------------------ expressions
@pytest.mark.parametrize(
    "expr,expected",
    [
        ("${1 + 2 * 3}", 7),
        ("${(1 + 2) * 3}", 9),
        ("${7 // 2}", 3),
        ("${7 % 3}", 1),
        ("${7 / 2}", 3.5),
        ("${-3 + 1}", -2),
        ("${1.5 + 1}", 2.5),
        ('${"a" + "b"}', "ab"),
        ('${"x" == "x" and 1 < 2}', True),
        ("${1 == 1.0}", True),
        ('${1 == "1"}', False),
        ("${null == null}", True),
        ("${not false}", True),
        ("${true or false}", True),
        ("${2 in [1, 2, 3]}", True),
        ("${4 in [1, 2, 3]}", False),
        ('${"k" in {"k": 1}}', True),
        ('${"z" in {"k": 1}}', False),
        ('${{"a": [1, {"b": 2}]}}', {"a": [1, {"b": 2}]}),
        ('${"say \\"hi\\""}', 'say "hi"'),
        ("${[1, 2] == [1, 2]}", True),
    ],
)
def test_expression_values(expr, expected):
    assert ret_value(expr) == expected


def test_variables_attribute_and_index_access():
    args = {"m": {"k": [10, {"deep": "v"}]}}
    assert ret_value("${args.m.k[1].deep}", args) == "v"
    assert ret_value('${args["m"]["k"][0]}', args) == 10


def test_missing_attribute_raises_keyerror():
    err = ret_error("${args.missing}", {"present": 1})
    assert err == {"tags": ["KeyError"], "message": "KeyError: key not found: missing"}


def test_attribute_on_null_raises_typeerror():
    err = ret_error("${args.a.b}", {"a": None})
    assert err["tags"] == ["TypeError"]


def test_index_out_of_range_raises_indexerror():
    assert ret_error("${args.l[3]}", {"l": [1]})["tags"] == ["IndexError"]
    assert ret_error("${args.l[-1]}", {"l": [1]})["tags"] == ["IndexError"]


def test_string_plus_int_is_typeerror():
    assert ret_error('${"n=" + 1}')["tags"] == ["TypeError"]
    assert ret_value('${"n=" + string(1)}') == "n=1"


def test_comparison_and_logic_type_errors():
    assert ret_error('${1 < "2"}')["tags"] == ["TypeError"]
    assert ret_error("${1 and true}")["tags"] == ["TypeError"]
    assert ret_error("${not 1}")["tags"] == ["TypeError"]
    assert ret_error("${[1] + [2]}")["tags"] == ["TypeError"]


def test_division_by_zero():
    assert ret_error("${1 / 0}")["tags"] == ["ZeroDivisionError"]


def test_and_or_short_circuit():
    # The right operand would raise KeyError; it is never evaluated.
    assert ret_value("${false and args.missing}", {}) is False
    assert ret_value("${true or args.missing}", {}) is True


def test_in_requires_list_or_map():
    assert ret_error('${"a" in "abc"}')["tags"] == ["TypeError"]


def test_ambiguous_syntax_is_unsupported():
    for bad in ("${not a == b}", "${1 < 2 < 3}", "${'single'}", "${a = 1}", "${a ? 1 : 2}"):
        with pytest.raises(SimulatorUnsupported):
            parse_expression(bad[2:-1])


def test_embedded_expression_string_is_unsupported():
    with pytest.raises(SimulatorUnsupported):
        ret("prefix ${args}")


# -------------------------------------------------------------------------------------------------------- functions
def test_unknown_function_is_unsupported():
    with pytest.raises(SimulatorUnsupported, match="unknown function"):
        ret("${text.replace_all(\"a\", \"b\", \"c\")}")
    with pytest.raises(SimulatorUnsupported, match="unknown function"):
        validate({"main": {"steps": [{"a": {"assign": [{"x": "${frobnicate(1)}"}]}}]}})


def test_wrong_arity_is_unsupported():
    with pytest.raises(SimulatorUnsupported):
        parse_expression("default(1)")


def test_default_only_replaces_null():
    assert ret_value('${default(null, "d")}') == "d"
    assert ret_value('${default("", "d")}') == ""
    assert ret_value('${default(map.get(args, "x"), "d")}', {}) == "d"


def test_default_does_not_mask_keyerror():
    err = ret_error('${default(args.missing, "d")}', {})
    assert err["tags"] == ["KeyError"]


def test_map_get():
    assert ret_value('${map.get(args, "a")}', {"a": 1}) == 1
    assert ret_value('${map.get(args, "b")}', {"a": 1}) is None
    assert ret_value('${map.get(args, ["a", "b"])}', {"a": {"b": 2}}) == 2
    assert ret_value('${map.get(args, ["a", "zz", "b"])}', {"a": {"b": 2}}) is None
    assert ret_value('${map.get(null, "a")}') is None  # documented choice
    assert ret_error('${map.get("str", "a")}')["tags"] == ["TypeError"]


def test_map_get_null_error_mode():
    """Bundle RT F6: null_map_get="error" makes map.get(null, k) raise (the pessimistic runtime reading), while a
    missing key / nested path on a real map still answers null."""
    assert ret_error('${map.get(null, "a")}', null_map_get="error")["tags"] == ["TypeError"]
    assert ret_value('${map.get(args, "b")}', {"a": 1}, null_map_get="error") is None
    assert ret_value('${map.get(args, ["a", "zz", "b"])}', {"a": {"b": 2}}, null_map_get="error") is None
    with pytest.raises(ValueError):
        run({"main": {"steps": [{"r": {"return": 1}}]}}, null_map_get="maybe")


def test_map_merge_keys_len():
    assert ret_value('${map.merge({"a": 1}, {"b": 2, "a": 3})}') == {"a": 3, "b": 2}
    assert ret_value('${keys({"a": 1, "b": 2})}') == ["a", "b"]
    assert ret_value('${len("abc") + len([1]) + len({"a": 1})}') == 5
    assert ret_error("${len(1)}")["tags"] == ["TypeError"]


def test_conversions():
    assert ret_value("${string(5)}") == "5"
    assert ret_value("${string(true)}") == "true"
    assert ret_value("${string(1.5)}") == "1.5"
    assert ret_value('${int("42") + int(2.9)}') == 44
    assert ret_value('${double("1.5")}') == 1.5
    assert ret_value('${bool("true")}') is True
    assert ret_error('${int("x")}')["tags"] == ["ValueError"]


def test_string_of_map_or_list_is_typeerror():
    assert ret_error('${string({"a": 1})}')["tags"] == ["TypeError"]
    assert ret_error("${string([1])}")["tags"] == ["TypeError"]


def test_string_of_unmodelled_values_is_unsupported():
    with pytest.raises(SimulatorUnsupported):
        ret("${string(null)}")
    with pytest.raises(SimulatorUnsupported):
        ret("${string(2.0)}")


def test_get_type():
    doc = '${[get_type(null), get_type(true), get_type(1), get_type(1.5), get_type("s"), get_type([]), get_type({}), get_type(json.encode(1))]}'
    assert ret_value(doc) == ["null", "boolean", "integer", "double", "string", "list", "map", "bytes"]


def test_json_and_base64():
    assert ret_value('${json.encode({"a": 1})}') == b'{"a":1}'
    assert ret_value('${json.encode_to_string([1, "x"])}') == '[1,"x"]'
    assert ret_value('${json.decode("{\\"a\\": [1]}")}') == {"a": [1]}
    assert ret_value('${json.decode(json.encode({"a": 2}))}') == {"a": 2}
    encoded = ret_value('${base64.encode(json.encode({"a": 1}))}')
    assert json.loads(base64.b64decode(encoded)) == {"a": 1}
    assert ret_value('${base64.decode(base64.encode(json.encode("x")))}') == b'"x"'
    assert ret_error('${base64.encode("not bytes")}')["tags"] == ["TypeError"]


def test_text_and_list_functions():
    assert ret_value('${text.to_lower("AbC") + text.to_upper("x")}') == "abcX"
    assert ret_value('${text.split("a,b", ",")}') == ["a", "b"]
    assert ret_value("${list.concat([1], 2)}") == [1, 2]


def test_uuid_is_deterministic_and_env_lookup():
    assert ret_value("${[uuid.generate(), uuid.generate()]}") == [
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-000000000002",
    ]
    assert ret_value('${sys.get_env("GOOGLE_CLOUD_WORKFLOW_EXECUTION_ID")}', env={
        "GOOGLE_CLOUD_WORKFLOW_EXECUTION_ID": "exec-9"}) == "exec-9"
    assert ret_value('${sys.get_env("NOPE", "fallback")}') == "fallback"
    with pytest.raises(SimulatorUnsupported):
        ret('${sys.get_env("NOPE")}')


def test_known_functions_and_calls():
    fns = known_functions()
    for name in ("default", "map.get", "string", "json.encode", "base64.encode", "uuid.generate", "sys.get_env"):
        assert name in fns
    assert "http.post" in known_calls() and "googleapis.pubsub.v1.projects.topics.publish" in known_calls()


def test_iter_expressions():
    doc = wf("""
        main:
          steps:
            - a:
                assign:
                  - x: ${1 + 1}
                  - y: plain
                  - z: '${"q" + "r"}'
            - b:
                return: ${x}
    """)
    assert list(iter_expressions(doc)) == ["${1 + 1}", '${"q" + "r"}', "${x}"]


# -------------------------------------------------------------------------------------------- steps and control flow
def test_assign_forms_and_value_semantics():
    doc = wf("""
        main:
          steps:
            - init:
                assign:
                  - m: {"a": {"b": 1}, "l": [1, 2]}
                  - copy_of_m: ${m}
                  - m.a.b: 5
                  - m["c"]: "new"
                  - m.l[1]: 9
                  - n: ${m.a.b + 1}
            - done:
                return: [ "${m}", "${copy_of_m}", "${n}" ]
    """)
    res = run(doc)
    assert res.state == "SUCCEEDED"
    assert res.result == [{"a": {"b": 5}, "l": [1, 9], "c": "new"}, {"a": {"b": 1}, "l": [1, 2]}, 6]


def test_assign_into_missing_intermediate_raises_keyerror():
    doc = {"main": {"steps": [{"a": {"assign": [{"m": {}}, {"m.x.y": 1}]}}]}}
    assert run(doc).error["tags"] == ["KeyError"]


def test_switch_first_true_wins_and_fallthrough():
    doc = wf("""
        main:
          params: [args]
          steps:
            - pick:
                switch:
                  - condition: ${args.n > 10}
                    next: big
                  - condition: ${args.n > 5}
                    assign:
                      - label: "medium"
                    next: finish
                  - condition: ${args.n > 5}
                    next: big
            - small:
                assign:
                  - label: "small"
                next: finish
            - big:
                assign:
                  - label: "big"
            - finish:
                return: ${label}
    """)
    assert run(doc, {"n": 20}).result == "big"
    assert run(doc, {"n": 7}).result == "medium"
    assert run(doc, {"n": 1}).result == "small"
    assert run(doc, {"n": 1}).steps_executed == ["pick", "small", "finish"]


def test_switch_step_level_next_when_nothing_matches():
    doc = wf("""
        main:
          steps:
            - s:
                switch:
                  - condition: ${false}
                    next: a
                next: b
            - a:
                return: "a"
            - b:
                return: "b"
    """)
    assert run(doc).result == "b"


def test_switch_condition_must_be_boolean():
    doc = {"main": {"steps": [{"s": {"switch": [{"condition": "${1}", "next": "end"}]}}]}}
    assert run(doc).error["tags"] == ["TypeError"]


def test_switch_case_return_raise_and_steps():
    doc = wf("""
        main:
          params: [args]
          steps:
            - s:
                switch:
                  - condition: ${args == "ret"}
                    return: "returned"
                  - condition: ${args == "raise"}
                    raise: "raised"
                  - condition: ${args == "steps"}
                    steps:
                      - inner:
                          assign:
                            - v: "from-steps"
                      - inner_ret:
                          return: ${v}
            - tail:
                return: "tail"
    """)
    assert run(doc, "ret").result == "returned"
    assert run(doc, "raise").error == "raised"
    assert run(doc, "steps").result == "from-steps"
    assert run(doc, "none").result == "tail"


def test_ambiguous_switch_case_without_next_is_unsupported():
    doc = wf("""
        main:
          steps:
            - s:
                switch:
                  - condition: ${true}
                    assign:
                      - x: 1
                next: t
            - t:
                return: 1
    """)
    with pytest.raises(SimulatorUnsupported):
        run(doc)


def test_nested_steps_jump_out_to_enclosing_scope():
    doc = wf("""
        main:
          steps:
            - outer:
                steps:
                  - inner_a:
                      assign:
                        - path: "inner_a"
                  - inner_b:
                      next: target
                  - inner_never:
                      assign:
                        - path: "wrong"
            - skipped:
                assign:
                  - path: "skipped"
            - target:
                return: ${path}
    """)
    res = run(doc)
    assert res.result == "inner_a"
    assert res.steps_executed == ["outer", "inner_a", "inner_b", "target"]


def test_nested_steps_complete_then_parent_next():
    doc = wf("""
        main:
          steps:
            - outer:
                steps:
                  - inner:
                      assign:
                        - x: 1
                next: last
            - skipped:
                return: "skipped"
            - last:
                return: ${x}
    """)
    assert run(doc).result == 1


def test_jump_into_nested_block_is_unsupported():
    doc = wf("""
        main:
          steps:
            - first:
                next: inner
            - outer:
                steps:
                  - inner:
                      return: 1
    """)
    with pytest.raises(SimulatorUnsupported, match="enclosing"):
        run(doc)


def test_next_end_and_implicit_null_return():
    doc = wf("""
        main:
          steps:
            - a:
                next: end
            - b:
                return: "never"
    """)
    res = run(doc)
    assert res.state == "SUCCEEDED" and res.result is None and res.steps_executed == ["a"]


def test_raise_map_escapes_main():
    doc = wf("""
        main:
          steps:
            - boom:
                raise:
                  code: 55
                  message: ${"bad " + "thing"}
    """)
    res = run(doc)
    assert res.state == "FAILED"
    assert res.error == {"code": 55, "message": "bad thing"}
    assert res.result is None


def test_raise_expression_and_string():
    assert run({"main": {"steps": [{"r": {"raise": '${"x" + "y"}'}}]}}).error == "xy"
    assert run({"main": {"steps": [{"r": {"raise": "plain"}}]}}).error == "plain"


def test_step_budget_catches_infinite_loop():
    doc = {"main": {"steps": [{"loop": {"next": "loop"}}]}}
    with pytest.raises(SimulatorUnsupported, match="step budget"):
        run(doc, step_budget=50)


@pytest.mark.parametrize(
    "doc",
    [
        {"main": {"steps": [{"a": {"for": {"value": "v", "in": [1], "steps": [{"b": {"next": "continue"}}]}}}]}},
        {"main": {"steps": [{"a": {"parallel": {"branches": []}}}]}},
        {"main": {"steps": [{"a": {"assign": [{"x": 1}], "bogus": 1}}]}},
        {"main": {"steps": [{"a": {"next": "missing_step"}}]}},
        {"main": {"steps": [{"a": {"next": "break"}}]}},
        {"main": {"steps": [{"a": {"call": "not.a.thing"}}]}},
        {"main": {"steps": [{"a": {"assign": [{"x": 1}]}}, {"a": {"assign": [{"y": 1}]}}]}},
        {"main": {"steps": [{"a": {"assign": [{"x": 1}], "return": 1}}]}},
        {"main": {"steps": [{"a": {"try": {"call": "sys.log", "args": {"text": "x"}}}}]}},
        {"main": {"steps": [{"a": {"call": "http.post", "args": {"url": "u", "frobs": 1}}}]}},
        {"notmain": {"steps": [{"a": {"return": 1}}]}},
    ],
)
def test_unmodelled_or_invalid_documents_are_unsupported(doc):
    with pytest.raises(SimulatorUnsupported):
        validate(doc)


def test_unassigned_variable_modes():
    doc = {"main": {"steps": [{"r": {"return": "${nope}"}}]}}
    with pytest.raises(SimulatorUnsupported, match="unassigned"):
        run(doc)
    assert run(doc, unassigned_variable="keyerror").error["tags"] == ["KeyError"]


# ------------------------------------------------------------------------------------------------------------ calls
class Http:
    """Scripted http_handler: url-suffix -> list of responses (status, body) or exceptions, consumed in order."""

    def __init__(self, script):
        self.script = {k: list(v) for k, v in script.items()}
        self.seen = []

    def __call__(self, method, url, body, args):
        self.seen.append((method, url, body))
        for suffix, queue in self.script.items():
            if url.endswith(suffix):
                item = queue.pop(0) if len(queue) > 1 else queue[0]
                if isinstance(item, Exception):
                    raise item
                return item
        raise AssertionError(f"unexpected url {url}")


POST_DOC = wf("""
    main:
      steps:
        - post:
            call: http.post
            args:
              url: https://svc/agent/do
              auth:
                type: OIDC
              timeout: 30
              body:
                a: ${1 + 1}
            result: out
        - done:
            return: ${out}
""")


def test_http_post_success_result_shape_and_call_record():
    http = Http({"/agent/do": [(200, {"ok": True})]})
    res = run(POST_DOC, http_handler=http)
    assert res.result == {"code": 200, "body": {"ok": True}, "headers": {}}
    assert http.seen == [("POST", "https://svc/agent/do", {"a": 2})]
    assert len(res.calls) == 1
    call = res.calls[0]
    assert (call["step"], call["call"], call["url"], call["method"], call["body"]) == (
        "post", "http.post", "https://svc/agent/do", "POST", {"a": 2})
    assert res.calls_to("/agent/do") == res.calls and res.calls_to("/agent/developer/execute") == []


def test_http_503_raises_exact_httperror_shape_with_body():
    http = Http({"/agent/do": [(503, {"error_class": "UPSTREAM_UNAVAILABLE"})]})
    res = run(POST_DOC, http_handler=http)
    assert res.state == "FAILED"
    assert res.error == {
        "tags": ["HttpError"],
        "code": 503,
        "message": "HTTP server responded with error code 503",
        "body": {"error_class": "UPSTREAM_UNAVAILABLE"},
        "headers": {},
    }
    assert res.error == http_error(503, {"error_class": "UPSTREAM_UNAVAILABLE"})


def test_http_without_handler_is_unsupported():
    with pytest.raises(SimulatorUnsupported):
        run(POST_DOC)


def test_http_request_method_and_get():
    doc = wf("""
        main:
          steps:
            - r:
                call: http.request
                args:
                  url: https://svc/x
                  method: patch
                result: a
            - g:
                call: http.get
                args:
                  url: https://svc/y
                result: b
            - done:
                return: ${[a.code, b.body]}
    """)
    http = Http({"/x": [(204, None)], "/y": [(200, "txt")]})
    assert run(doc, http_handler=http).result == [204, "txt"]
    assert [m for m, _, _ in http.seen] == ["PATCH", "GET"]


TRY_DOC = wf("""
    main:
      steps:
        - guarded:
            try:
              call: http.post
              args:
                url: https://svc/agent/do
              result: out
            except:
              as: e
              steps:
                - handle:
                    assign:
                      - cls: ${e.body.error_class}
                    next: report
        - unreachable:
            return: "no error"
        - report:
            return: ${[cls, e.code, e.tags]}
""")


def test_try_except_catches_httperror_and_as_variable_is_visible_afterwards():
    http = Http({"/agent/do": [(503, {"error_class": "QUOTA"})]})
    res = run(TRY_DOC, http_handler=http)
    assert res.state == "SUCCEEDED"
    assert res.result == ["QUOTA", 503, ["HttpError"]]
    assert res.steps_executed == ["guarded", "handle", "report"]


def test_try_success_skips_except():
    http = Http({"/agent/do": [(200, {})]})
    assert run(TRY_DOC, http_handler=http).result == "no error"


def test_handler_exceptions_map_to_workflows_errors():
    assert run(POST_DOC, http_handler=Http({"/agent/do": [SimTimeout("slow")]})).error["tags"] == ["TimeoutError"]
    assert run(POST_DOC, http_handler=Http({"/agent/do": [SimConnectionError()]})).error["tags"] == [
        "ConnectionError"]
    custom = {"tags": ["AuthError"], "message": "denied"}
    assert run(POST_DOC, http_handler=Http({"/agent/do": [WorkflowError(custom)]})).error == custom


def test_handler_bug_is_not_swallowed_by_except():
    def broken(method, url, body, args):
        raise RuntimeError("test bug")

    with pytest.raises(RuntimeError):
        run(TRY_DOC, http_handler=broken)


def retry_doc(policy: str) -> str:
    return wf(f"""
        main:
          steps:
            - guarded:
                try:
                  call: http.post
                  args:
                    url: https://svc/agent/do
                  result: out
                retry: {policy}
                except:
                  as: e
                  steps:
                    - failed:
                        return: ${{"failed:" + string(e.code)}}
            - done:
                return: ${{out.body}}
    """)


def test_default_retry_retries_503_then_succeeds():
    http = Http({"/agent/do": [(503, {}), (503, {}), (200, "ok")]})
    res = run(retry_doc("${http.default_retry}"), http_handler=http)
    assert res.result == "ok"
    assert res.attempts == {"guarded": 3}
    assert [r["attempt"] for r in res.retries] == [1, 2]
    assert [r["error"]["code"] for r in res.retries] == [503, 503]
    assert len(res.calls_to("/agent/do")) == 3
    assert res.sleeps == [("retry", 1.0), ("retry", 1.25)]


def test_default_retry_gives_up_after_max_retries():
    http = Http({"/agent/do": [(503, {})]})
    res = run(retry_doc("${http.default_retry}"), http_handler=http)
    assert res.result == "failed:503"
    assert res.attempts == {"guarded": 6}  # 1 + 5 retries
    assert len(http.seen) == 6


def test_default_retry_does_not_retry_400():
    http = Http({"/agent/do": [(400, {}), (200, "ok")]})
    res = run(retry_doc("${http.default_retry}"), http_handler=http)
    assert res.result == "failed:400"
    assert res.attempts == {"guarded": 1} and res.retries == []


def test_default_retry_retries_connection_and_timeout_errors():
    http = Http({"/agent/do": [SimConnectionError(), SimTimeout(), (200, "ok")]})
    res = run(retry_doc("${http.default_retry}"), http_handler=http)
    assert res.result == "ok" and res.attempts == {"guarded": 3}


def test_non_idempotent_retry_does_not_retry_502():
    http = Http({"/agent/do": [(502, {}), (200, "ok")]})
    res = run(retry_doc("${http.default_retry_non_idempotent}"), http_handler=http)
    assert res.result == "failed:502"
    http = Http({"/agent/do": [(503, {}), (200, "ok")]})
    assert run(retry_doc("${http.default_retry_non_idempotent}"), http_handler=http).result == "ok"


def test_custom_retry_map_with_predicate_subworkflow():
    doc = wf("""
        main:
          steps:
            - guarded:
                try:
                  call: http.post
                  args:
                    url: https://svc/agent/do
                  result: out
                retry:
                  predicate: ${only_409}
                  max_retries: 2
                  backoff:
                    initial_delay: 2
                    max_delay: 3
                    multiplier: 2
            - done:
                return: ${out.code}
        only_409:
          params: [e]
          steps:
            - check:
                return: ${map.get(e, "code") == 409}
    """)
    http = Http({"/agent/do": [(409, {})]})
    res = run(doc, http_handler=http)
    assert res.state == "FAILED" and res.error["code"] == 409
    assert res.attempts == {"guarded": 3}
    assert res.sleeps == [("retry", 2.0), ("retry", 3.0)]


def test_unknown_retry_policy_is_unsupported():
    with pytest.raises(SimulatorUnsupported):
        validate(retry_doc("${http.some_other_retry}"))


def test_retry_without_except_propagates_last_error():
    doc = wf("""
        main:
          steps:
            - guarded:
                try:
                  call: http.post
                  args:
                    url: https://svc/agent/do
                retry: ${http.default_retry}
    """)
    res = run(doc, http_handler=Http({"/agent/do": [(504, {"n": 1})]}))
    assert res.state == "FAILED" and res.error["code"] == 504 and res.attempts == {"guarded": 6}


def test_try_steps_block_and_jump_out_of_except():
    doc = wf("""
        main:
          steps:
            - guarded:
                try:
                  steps:
                    - s1:
                        assign:
                          - progress: 1
                    - s2:
                        raise: {"tags": ["Custom"], "message": "m"}
                    - s3:
                        assign:
                          - progress: 3
                except:
                  as: err
                  steps:
                    - h:
                        next: recovered
            - not_here:
                return: "fell through"
            - recovered:
                return: ${[progress, err.message]}
    """)
    res = run(doc)
    assert res.result == [1, "m"]
    assert res.steps_executed == ["guarded", "s1", "s2", "h", "recovered"]


def test_except_reraise_propagates():
    doc = wf("""
        main:
          steps:
            - guarded:
                try:
                  steps:
                    - s:
                        raise: "first"
                except:
                  as: e
                  steps:
                    - again:
                        raise: ${"wrapped:" + e}
    """)
    assert run(doc).error == "wrapped:first"


def test_try_step_level_next_after_except_completes():
    doc = wf("""
        main:
          steps:
            - guarded:
                try:
                  steps:
                    - s:
                        raise: "x"
                except:
                  steps:
                    - log:
                        call: sys.log
                        args:
                          text: "handled"
                next: final
            - skipped:
                return: "skipped"
            - final:
                return: "final"
    """)
    res = run(doc)
    assert res.result == "final"
    assert res.logs == [("DEFAULT", "handled")]


# --------------------------------------------------------------------------------------------------- subworkflows
SUB_DOC = wf("""
    main:
      params: [args]
      steps:
        - call_sub:
            call: add
            args:
              a: ${args.x}
              b: 10
            result: total
        - call_defaulted:
            call: greet
            args:
              who: "bob"
            result: greeting
        - done:
            return: ${[total, greeting]}
    add:
      params: [a, b]
      steps:
        - compute:
            return: ${a + b}
    greet:
      params: [who, prefix: "hi "]
      steps:
        - compute:
            return: ${prefix + who}
""")


def test_subworkflow_call_returns_value_and_param_defaults():
    res = run(SUB_DOC, {"x": 5})
    assert res.result == [15, "hi bob"]
    assert [c["call"] for c in res.calls] == ["add", "greet"]


def test_subworkflow_has_fresh_scope():
    doc = wf("""
        main:
          steps:
            - set:
                assign:
                  - secret: 1
            - c:
                call: peek
        peek:
          steps:
            - look:
                return: ${secret}
    """)
    with pytest.raises(SimulatorUnsupported, match="unassigned"):
        run(doc)


def test_subworkflow_raise_propagates_to_caller_and_is_catchable():
    doc = wf("""
        main:
          steps:
            - guarded:
                try:
                  call: fail
                  args:
                    why: "nope"
                except:
                  as: e
                  steps:
                    - h:
                        return: ${"caught " + e.message}
        fail:
          params: [why]
          steps:
            - r:
                raise:
                  message: ${why}
    """)
    assert run(doc).result == "caught nope"
    uncaught = {"main": {"steps": [{"c": {"call": "boom"}}]}, "boom": {"steps": [{"r": {"raise": "x"}}]}}
    assert run(uncaught).error == "x"


def test_subworkflow_missing_required_param_is_unsupported():
    doc = {"main": {"steps": [{"c": {"call": "add", "args": {"a": 1}}}]},
           "add": {"params": ["a", "b"], "steps": [{"r": {"return": "${a}"}}]}}
    with pytest.raises(SimulatorUnsupported):
        run(doc)


# ------------------------------------------------------------------------------------------- callbacks / pubsub / log
CALLBACK_DOC = wf("""
    main:
      steps:
        - create:
            call: events.create_callback_endpoint
            args:
              http_callback_method: "POST"
            result: cb
        - wait:
            try:
              call: events.await_callback
              args:
                callback: ${cb}
                timeout: 600
              result: resp
            except:
              as: e
              steps:
                - timed_out:
                    return: ${e.tags}
        - done:
            return: ${[cb.url, resp.http_request.body.decision]}
""")


def test_callbacks_deliver_body():
    seen = []

    def cb(url, timeout):
        seen.append((url, timeout))
        return {"decision": "APPROVED"}

    res = run(CALLBACK_DOC, callback_handler=cb)
    assert res.result == ["https://sim.callbacks/1", "APPROVED"]
    assert seen == [("https://sim.callbacks/1", 600)]
    assert [c["event"] for c in res.callbacks] == ["created", "await"]


def test_callback_timeout_raises_timeouterror():
    def cb(url, timeout):
        raise SimTimeout()

    assert run(CALLBACK_DOC, callback_handler=cb).result == ["TimeoutError"]


PUBSUB_DOC = wf("""
    main:
      steps:
        - payload:
            assign:
              - p:
                  reason: "dlq"
        - publish:
            call: googleapis.pubsub.v1.projects.topics.publish
            args:
              topic: projects/x/topics/dlq
              body:
                messages:
                  - data: ${base64.encode(json.encode(p))}
            result: pub
        - done:
            return: ${pub}
""")


def test_pubsub_publish_is_recorded_and_decoded():
    res = run(PUBSUB_DOC)
    assert res.state == "SUCCEEDED" and res.result == {"messageIds": ["1"]}
    assert len(res.published) == 1
    assert res.published[0]["topic"] == "projects/x/topics/dlq"
    assert res.published[0]["data"] == [{"reason": "dlq"}]


def test_pubsub_failure_injection():
    def failing(topic, messages):
        raise WorkflowError(http_error(403, {"error": {"status": "PERMISSION_DENIED"}}))

    res = run(PUBSUB_DOC, pubsub_handler=failing)
    assert res.state == "FAILED" and res.error["code"] == 403
    assert res.published == []
    assert res.calls[-1]["call"] == "googleapis.pubsub.v1.projects.topics.publish"


def test_pubsub_rejects_non_base64_data():
    doc = PUBSUB_DOC.replace("${base64.encode(json.encode(p))}", "not base64 !!")
    assert run(doc).error["code"] == 400


def test_sys_log_records_severity_and_default():
    doc = wf("""
        main:
          steps:
            - a:
                call: sys.log
                args:
                  text: "one"
                  severity: WARNING
            - b:
                call: sys.log
                args:
                  text: ${"two"}
            - c:
                call: sys.log
                args:
                  json: {"k": 1}
                  severity: INFO
    """)
    assert run(doc).logs == [("WARNING", "one"), ("DEFAULT", "two"), ("INFO", {"k": 1})]


def test_sys_log_bad_severity_is_unsupported():
    doc = {"main": {"steps": [{"a": {"call": "sys.log", "args": {"text": "x", "severity": "LOUD"}}}]}}
    with pytest.raises(SimulatorUnsupported):
        run(doc)


def test_simulator_instance_exposes_records_and_resets_per_run():
    sim = Simulator(http_handler=Http({"/agent/do": [(200, {})]}))
    sim.run(POST_DOC)
    sim.run(POST_DOC)
    assert len(sim.calls) == 1 and sim.steps_executed == ["post", "done"]


def test_main_without_args_gets_null():
    doc = {"main": {"params": ["args"], "steps": [{"r": {"return": '${map.get(args, "x")}'}}]}}
    assert run(doc).result is None
    assert run({"main": {"params": ["args"], "steps": [{"r": {"return": "${args.x}"}}]}}).error["tags"] == [
        "TypeError"]

"""
Offline interpreter for the subset of Google Cloud Workflows syntax StackVend uses (lane 17, workflow integrity).

Purpose: hermetic tests of ``workflows/main_orchestrator.yaml`` (routing, error handling, retries, callbacks, DLQ)
without deploying anything. Every external effect goes through a test-provided handler and is recorded.

BINDING DESIGN RULE: unknown syntax, unknown functions/calls, or semantics this module does not model raise
``SimulatorUnsupported``. Nothing is silently accepted. ``SimulatorUnsupported`` is a plain Python exception: it is
never catchable by a workflow ``except`` block, so it always fails the test that hit it.

Public API
----------
``Simulator(http_handler=None, callback_handler=None, pubsub_handler=None, env=None, step_budget=10000,
            unassigned_variable="unsupported", null_map_get="null")``
    ``null_map_get``: ``"null"`` (default, the modelled choice: ``map.get(null, k) -> null``) or ``"error"``
    (the pessimistic reading: ``map.get(null, k)`` raises TypeError). Bundle RT F6: scenarios that must not
    depend on the choice run under ``"error"``.
    ``.run(workflow, args=None) -> SimResult``   workflow = YAML text, or an already-parsed dict/list.
    After a run the simulator also exposes ``calls``, ``logs``, ``published``, ``steps_executed``, ``retries``,
    ``attempts``, ``callbacks``, ``sleeps`` (same objects as on the SimResult).
``run(workflow, args=None, **simulator_kwargs) -> SimResult``   convenience wrapper.
``validate(workflow)``   static (deploy-time-like) checks only; raises SimulatorUnsupported.
``known_functions() -> list[str]``   expression functions supported.
``known_calls() -> list[str]``       ``call:`` targets supported (besides subworkflows).
``iter_expressions(workflow) -> Iterator[str]``   every string containing ``${`` in the document.
``parse_expression(text)``   parse the inside of ``${...}``; raises SimulatorUnsupported on anything unknown.
``http_error(code, body=None, headers=None) -> dict``   the exact HttpError map Workflows raises.
``WorkflowError(value)``   a Workflows-level error (catchable by ``except``); ``.value`` is the error value.
``SimTimeout``, ``SimConnectionError(message, tag="ConnectionError"|"ConnectionFailedError")``.

Handler contracts
-----------------
``http_handler(method, url, body, args) -> (status:int, body) | (status, body, headers)``
    method is upper case ("GET", "POST", ...); body is ``args.get("body")``; args is the full evaluated ``args`` map.
    It may raise ``WorkflowError(value)`` (propagated as is), ``SimTimeout`` (-> TimeoutError) or
    ``SimConnectionError`` (-> ConnectionError / ConnectionFailedError). Status >= 400 raises the HttpError map.
``callback_handler(callback_url, timeout) -> body``   body of the HTTP request that hits the callback.
    It may raise ``SimTimeout`` (-> TimeoutError, as await_callback does when nothing arrives) or ``WorkflowError``.
``pubsub_handler(topic, messages) -> result``   optional; default returns ``{"messageIds": [...]}``. To inject a
    publish failure raise ``WorkflowError(http_error(403, ...))`` (or any error value) from it.

Retries: every execution of a ``try`` body counts in ``attempts[step_name]``; every retry decision appends
``{"step", "attempt", "error", "delay"}`` to ``retries`` and the backoff delay to ``sleeps`` as ``("retry", s)``.
Every executed call (each attempt) is appended to ``calls`` before its handler runs.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

import yaml

__all__ = [
    "SimResult",
    "SimConnectionError",
    "SimTimeout",
    "Simulator",
    "SimulatorUnsupported",
    "WorkflowError",
    "http_error",
    "iter_expressions",
    "known_calls",
    "known_functions",
    "load_workflow",
    "parse_expression",
    "run",
    "validate",
]


# ----------------------------------------------------------------------------------------------------------- errors
class SimulatorUnsupported(Exception):
    """Syntax/function/semantics the simulator does not model (or a definite deploy-time error). Never catchable."""


class WorkflowError(Exception):
    """An error raised inside the workflow (catchable by ``except``). ``value`` is the Workflows error value."""

    def __init__(self, value: Any):
        super().__init__(repr(value))
        self.value = value


class SimTimeout(Exception):
    """Raised by a test handler to simulate a timeout (HTTP call or await_callback)."""


class SimConnectionError(Exception):
    """Raised by an http_handler to simulate a connection failure."""

    def __init__(self, message: str = "connection error", tag: str = "ConnectionError"):
        if tag not in ("ConnectionError", "ConnectionFailedError"):
            raise SimulatorUnsupported(f"SimConnectionError tag {tag!r} not modelled")
        super().__init__(message)
        self.tag = tag


def http_error(code: int, body: Any = None, headers: dict | None = None) -> dict:
    """The error map Cloud Workflows raises for an HTTP response with status >= 400."""
    return {
        "tags": ["HttpError"],
        "code": code,
        "message": f"HTTP server responded with error code {code}",
        "body": body,
        "headers": dict(headers or {}),
    }


def _err(tag: str, message: str) -> WorkflowError:
    return WorkflowError({"tags": [tag], "message": message})


def _key_error(key: Any) -> WorkflowError:
    return _err("KeyError", f"KeyError: key not found: {key}")


# ------------------------------------------------------------------------------------------------------------ types
def _type_name(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "double"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "list"
    if isinstance(v, dict):
        return "map"
    if isinstance(v, bytes):
        return "bytes"
    raise SimulatorUnsupported(f"value of Python type {type(v).__name__} is not a Workflows type: {v!r}")


def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _type_error(msg: str) -> WorkflowError:
    return _err("TypeError", f"TypeError: {msg}")


def _wf_equal(a: Any, b: Any) -> bool:
    # Numbers compare numerically across integer/double. Values of different types are unequal (modelled as false,
    # not a TypeError: an assumption, Workflows docs do not spell out cross-type ==). Lists/maps compare deeply.
    if _is_num(a) and _is_num(b):
        return a == b
    ta, tb = _type_name(a), _type_name(b)
    if ta != tb:
        return False
    if ta == "list":
        return len(a) == len(b) and all(_wf_equal(x, y) for x, y in zip(a, b))
    if ta == "map":
        return a.keys() == b.keys() and all(_wf_equal(a[k], b[k]) for k in a)
    return a == b


# ------------------------------------------------------------------------------------------------------ expressions
_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<num>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>//|==|!=|<=|>=|[-+*/%<>()\[\]{},:.])
    """,
    re.VERBOSE,
)
_KEYWORDS = {"true", "false", "null", "and", "or", "not", "in"}
_STR_ESCAPES = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r", "/": "/"}
_COMPARISON_OPS = {"==", "!=", "<", "<=", ">", ">=", "in"}
_ARITH_OPS = {"+", "-", "*", "/", "%", "//"}


def _tokenize(text: str) -> list[tuple[str, Any]]:
    tokens: list[tuple[str, Any]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise SimulatorUnsupported(f"expression syntax not modelled at {text[pos:pos + 20]!r} in {text!r}")
        pos = m.end()
        kind = m.lastgroup
        raw = m.group(kind)
        if kind == "ws":
            continue
        if kind == "num":
            tokens.append(("lit", float(raw) if any(c in raw for c in ".eE") else int(raw)))
        elif kind == "str":
            out, i, body = [], 0, raw[1:-1]
            while i < len(body):
                c = body[i]
                if c == "\\":
                    nxt = body[i + 1]
                    if nxt not in _STR_ESCAPES:
                        raise SimulatorUnsupported(f"string escape \\{nxt} not modelled in {text!r}")
                    out.append(_STR_ESCAPES[nxt])
                    i += 2
                else:
                    out.append(c)
                    i += 1
            tokens.append(("lit", "".join(out)))
        elif kind == "ident":
            if raw in ("true", "false"):
                tokens.append(("lit", raw == "true"))
            elif raw == "null":
                tokens.append(("lit", None))
            elif raw in _KEYWORDS:
                tokens.append(("kw", raw))
            else:
                tokens.append(("ident", raw))
        else:
            tokens.append(("op", raw))
    tokens.append(("eof", None))
    return tokens


class _Parser:
    """Precedence (low -> high): or, and, comparison (== != < <= > >= in, non-chaining), + -, * / % //,
    unary (- not), postfix (. [] call). ``not`` directly followed by an arithmetic/comparison operator is rejected:
    whether Workflows binds ``not a == b`` as ``not (a == b)`` or ``(not a) == b`` is not modelled."""

    def __init__(self, text: str):
        self.text = text
        self.toks = _tokenize(text)
        self.i = 0

    def peek(self) -> tuple[str, Any]:
        return self.toks[self.i]

    def take(self) -> tuple[str, Any]:
        t = self.toks[self.i]
        self.i += 1
        return t

    def expect_op(self, op: str) -> None:
        t = self.take()
        if t != ("op", op):
            raise SimulatorUnsupported(f"expected {op!r}, got {t[1]!r} in {self.text!r}")

    def is_op(self, *ops: str) -> bool:
        k, v = self.peek()
        return k == "op" and v in ops

    def is_kw(self, *kws: str) -> bool:
        k, v = self.peek()
        return k == "kw" and v in kws

    def parse(self):
        node = self.p_or()
        if self.peek()[0] != "eof":
            raise SimulatorUnsupported(f"unexpected token {self.peek()[1]!r} in expression {self.text!r}")
        return node

    def p_or(self):
        node = self.p_and()
        while self.is_kw("or"):
            self.take()
            node = ("bin", "or", node, self.p_and())
        return node

    def p_and(self):
        node = self.p_cmp()
        while self.is_kw("and"):
            self.take()
            node = ("bin", "and", node, self.p_cmp())
        return node

    def _cmp_op(self) -> str | None:
        if self.is_op("==", "!=", "<", "<=", ">", ">="):
            return self.peek()[1]
        if self.is_kw("in"):
            return "in"
        return None

    def p_cmp(self):
        node = self.p_add()
        op = self._cmp_op()
        if op:
            self.take()
            node = ("bin", op, node, self.p_add())
            if self._cmp_op():
                raise SimulatorUnsupported(f"chained comparison not modelled in {self.text!r}")
        return node

    def p_add(self):
        node = self.p_mul()
        while self.is_op("+", "-"):
            op = self.take()[1]
            node = ("bin", op, node, self.p_mul())
        return node

    def p_mul(self):
        node = self.p_unary()
        while self.is_op("*", "/", "%", "//"):
            op = self.take()[1]
            node = ("bin", op, node, self.p_unary())
        return node

    def p_unary(self):
        if self.is_op("-"):
            self.take()
            return ("un", "-", self.p_unary())
        if self.is_kw("not"):
            self.take()
            operand = self.p_unary()
            if self._cmp_op() or self.is_op(*_ARITH_OPS):
                raise SimulatorUnsupported(
                    f"precedence of 'not' before a binary operator is not modelled (parenthesize) in {self.text!r}"
                )
            return ("un", "not", operand)
        return self.p_postfix()

    def p_postfix(self):
        node = self.p_primary()
        while True:
            if self.is_op("."):
                self.take()
                k, v = self.take()
                if k not in ("ident", "kw"):
                    raise SimulatorUnsupported(f"expected attribute name after '.' in {self.text!r}")
                node = ("attr", node, v)
            elif self.is_op("["):
                self.take()
                idx = self.p_or()
                self.expect_op("]")
                node = ("index", node, idx)
            elif self.is_op("("):
                fname = _dotted_name(node)
                if fname is None:
                    raise SimulatorUnsupported(f"call of a non-function expression in {self.text!r}")
                if fname not in _FUNCS:
                    raise SimulatorUnsupported(f"unknown function {fname}() in {self.text!r}")
                self.take()
                args = []
                if not self.is_op(")"):
                    args.append(self.p_or())
                    while self.is_op(","):
                        self.take()
                        args.append(self.p_or())
                self.expect_op(")")
                lo, hi = _FUNCS[fname][0], _FUNCS[fname][1]
                if not lo <= len(args) <= hi:
                    raise SimulatorUnsupported(f"{fname}() takes {lo}..{hi} arguments, got {len(args)}: {self.text!r}")
                node = ("call", fname, args)
            else:
                return node

    def p_primary(self):
        k, v = self.take()
        if k == "lit":
            return ("lit", v)
        if k == "ident":
            return ("var", v)
        if (k, v) == ("op", "("):
            node = self.p_or()
            self.expect_op(")")
            return node
        if (k, v) == ("op", "["):
            items = []
            if not self.is_op("]"):
                items.append(self.p_or())
                while self.is_op(","):
                    self.take()
                    items.append(self.p_or())
            self.expect_op("]")
            return ("list", items)
        if (k, v) == ("op", "{"):
            entries = []
            if not self.is_op("}"):
                while True:
                    kk, kv = self.take()
                    if kk != "lit" or not isinstance(kv, str):
                        raise SimulatorUnsupported(f"map literal keys must be string literals in {self.text!r}")
                    self.expect_op(":")
                    entries.append((kv, self.p_or()))
                    if not self.is_op(","):
                        break
                    self.take()
            self.expect_op("}")
            return ("map", entries)
        raise SimulatorUnsupported(f"unexpected token {v!r} in expression {self.text!r}")


def _dotted_name(node) -> str | None:
    if node[0] == "var":
        return node[1]
    if node[0] == "attr":
        base = _dotted_name(node[1])
        return f"{base}.{node[2]}" if base else None
    return None


def parse_expression(text: str):
    """Parse the inside of ``${...}`` into an AST tuple. Raises SimulatorUnsupported."""
    return _Parser(text).parse()


def _is_expr(s: Any) -> bool:
    return isinstance(s, str) and s.startswith("${") and s.endswith("}")


def _expr_text(s: str) -> str:
    return s[2:-1]


def _check_string(s: str) -> None:
    if _is_expr(s):
        parse_expression(_expr_text(s))
    elif "${" in s:
        # Workflows only evaluates a value that is entirely one ${...}; anything else is a literal string, which in
        # our code base would be a bug. Refuse instead of guessing.
        raise SimulatorUnsupported(f"string with embedded (non whole-value) expression not modelled: {s!r}")


# -------------------------------------------------------------------------------------------- expression functions
# name -> (min_args, max_args, method name on Simulator)
_FUNCS: dict[str, tuple[int, int, str]] = {
    "default": (2, 2, "_f_default"),
    "map.get": (2, 2, "_f_map_get"),
    "map.merge": (2, 2, "_f_map_merge"),
    "keys": (1, 1, "_f_keys"),
    "len": (1, 1, "_f_len"),
    "string": (1, 1, "_f_string"),
    "int": (1, 1, "_f_int"),
    "double": (1, 1, "_f_double"),
    "bool": (1, 1, "_f_bool"),
    "get_type": (1, 1, "_f_get_type"),
    "json.encode": (1, 1, "_f_json_encode"),
    "json.encode_to_string": (1, 1, "_f_json_encode_to_string"),
    "json.decode": (1, 1, "_f_json_decode"),
    "base64.encode": (1, 2, "_f_base64_encode"),
    "base64.decode": (1, 2, "_f_base64_decode"),
    "text.to_lower": (1, 1, "_f_to_lower"),
    "text.to_upper": (1, 1, "_f_to_upper"),
    "text.split": (2, 2, "_f_split"),
    "uuid.generate": (0, 0, "_f_uuid"),
    "sys.get_env": (1, 2, "_f_get_env"),
    "list.concat": (2, 2, "_f_list_concat"),
}

_HTTP_METHODS = {"http.get": "GET", "http.post": "POST", "http.put": "PUT", "http.delete": "DELETE",
                 "http.patch": "PATCH", "http.request": None}
_HTTP_ARG_KEYS = {"url", "method", "headers", "body", "query", "auth", "timeout"}
_PUBSUB_PUBLISH = "googleapis.pubsub.v1.projects.topics.publish"
_CALLS = set(_HTTP_METHODS) | {
    "events.create_callback_endpoint", "events.await_callback", _PUBSUB_PUBLISH, "sys.log", "sys.sleep", "sys.get_env",
}
_LOG_SEVERITIES = {"DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY"}

_DEFAULT_ENV = {
    "GOOGLE_CLOUD_PROJECT_ID": "mock-stackvend-project",
    "GOOGLE_CLOUD_PROJECT_NUMBER": "000000000000",
    "GOOGLE_CLOUD_LOCATION": "us-central1",
    "GOOGLE_CLOUD_WORKFLOW_ID": "sim-workflow",
    "GOOGLE_CLOUD_WORKFLOW_REVISION_ID": "000001-sim",
    "GOOGLE_CLOUD_WORKFLOW_EXECUTION_ID": "sim-execution-1",
}


def known_functions() -> list[str]:
    """Every expression function the simulator models."""
    return sorted(_FUNCS)


def known_calls() -> list[str]:
    """Every ``call:`` target the simulator models (subworkflows are also callable)."""
    return sorted(_CALLS)


# ------------------------------------------------------------------------------------------------------- retry
_RETRY_POLICIES = {
    # Cloud Workflows built-ins: max_retries 5, backoff initial 1s, max 60s, multiplier 1.25.
    "http.default_retry": ("http.default_retry_predicate", 5, 1.0, 60.0, 1.25),
    "http.default_retry_non_idempotent": ("http.default_retry_predicate_non_idempotent", 5, 1.0, 60.0, 1.25),
}
_RETRY_PREDICATES = {"http.default_retry_predicate", "http.default_retry_predicate_non_idempotent"}


def _builtin_retry_predicate(name: str, err: Any) -> bool:
    if not isinstance(err, dict):
        return False
    tags = err.get("tags") or []
    code = err.get("code") if "HttpError" in tags else None
    if name == "http.default_retry_predicate":
        # 429, 502, 503, 504, ConnectionError, ConnectionFailedError, TimeoutError.
        return code in (429, 502, 503, 504) or any(
            t in tags for t in ("ConnectionError", "ConnectionFailedError", "TimeoutError")
        )
    # non-idempotent: only failures where the request was certainly not processed: 429, 503, ConnectionFailedError.
    return code in (429, 503) or "ConnectionFailedError" in tags


def _parse_retry(spec: Any, subworkflows: dict) -> dict:
    """Returns {predicate: builtin name or ("sub", name), max_retries, initial, max_delay, multiplier}."""
    if _is_expr(spec):
        name = _dotted_name(parse_expression(_expr_text(spec)))
        if name not in _RETRY_POLICIES:
            raise SimulatorUnsupported(f"retry policy {spec!r} not modelled")
        pred, mx, ini, mxd, mult = _RETRY_POLICIES[name]
        return {"predicate": pred, "max_retries": mx, "initial": ini, "max_delay": mxd, "multiplier": mult}
    if not isinstance(spec, dict):
        raise SimulatorUnsupported(f"retry spec not modelled: {spec!r}")
    unknown = set(spec) - {"predicate", "max_retries", "backoff"}
    if unknown or "predicate" not in spec or "max_retries" not in spec:
        raise SimulatorUnsupported(f"retry map must be {{predicate, max_retries, backoff}}: {spec!r}")
    pred_spec = spec["predicate"]
    if not _is_expr(pred_spec):
        raise SimulatorUnsupported(f"retry predicate must be an expression: {pred_spec!r}")
    pname = _dotted_name(parse_expression(_expr_text(pred_spec)))
    if pname in _RETRY_PREDICATES:
        pred: Any = pname
    elif pname in subworkflows:
        pred = ("sub", pname)
    else:
        raise SimulatorUnsupported(f"retry predicate {pred_spec!r} not modelled")
    mx = spec["max_retries"]
    if not _is_num(mx) or isinstance(mx, float) or mx < 0:
        raise SimulatorUnsupported(f"retry max_retries must be a literal non-negative integer: {mx!r}")
    backoff = spec.get("backoff")
    if not isinstance(backoff, dict) or set(backoff) != {"initial_delay", "max_delay", "multiplier"}:
        raise SimulatorUnsupported(f"retry backoff must be {{initial_delay, max_delay, multiplier}}: {backoff!r}")
    if not all(_is_num(backoff[k]) for k in backoff):
        raise SimulatorUnsupported(f"retry backoff values must be literal numbers: {backoff!r}")
    return {"predicate": pred, "max_retries": mx, "initial": float(backoff["initial_delay"]),
            "max_delay": float(backoff["max_delay"]), "multiplier": float(backoff["multiplier"])}


# ---------------------------------------------------------------------------------------------- static validation
_PRIMARY_KEYS = {"assign", "call", "switch", "try", "raise", "return", "steps", "for", "parallel"}
_EXTRA_KEYS = {
    "assign": {"next"}, "call": {"args", "result", "next"}, "switch": {"next"}, "try": {"retry", "except", "next"},
    "raise": set(), "return": set(), "steps": {"next"}, None: {"next"},
}
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class _Program:
    def __init__(self, doc: Any):
        if isinstance(doc, str):
            doc = yaml.safe_load(doc)
        if isinstance(doc, list):  # simple form: a bare list of steps is main with no params
            doc = {"main": {"steps": doc}}
        if not isinstance(doc, dict) or "main" not in doc:
            raise SimulatorUnsupported("workflow document must be a map of subworkflows including 'main'")
        self.doc = doc
        self.subs: dict[str, dict] = {}
        self.block_index: dict[int, dict[str, int]] = {}
        for name, defn in doc.items():
            if not isinstance(name, str) or not _IDENT_RE.match(name):
                raise SimulatorUnsupported(f"invalid subworkflow name {name!r}")
            if not isinstance(defn, dict) or set(defn) - {"params", "steps"} or "steps" not in defn:
                raise SimulatorUnsupported(f"subworkflow {name!r} must be {{params?, steps}}")
            self.subs[name] = {"params": self._params(name, defn.get("params", [])), "steps": defn["steps"]}
        main_params = self.subs["main"]["params"]
        if len(main_params) > 1:
            raise SimulatorUnsupported("main takes at most one parameter")
        for name, sub in self.subs.items():
            names: set[str] = set()
            targets: list[str] = []
            self._walk_block(sub["steps"], names, targets)
            for t in targets:
                if t != "end" and t not in names:
                    raise SimulatorUnsupported(f"next target {t!r} does not exist in subworkflow {name!r}")

    @staticmethod
    def _params(sub: str, params: Any) -> list[tuple[str, bool, Any]]:
        if not isinstance(params, list):
            raise SimulatorUnsupported(f"params of {sub!r} must be a list")
        out = []
        for p in params:
            if isinstance(p, str):
                out.append((p, False, None))
            elif isinstance(p, dict) and len(p) == 1:
                (pn, pd), = p.items()
                _check_value(pd)
                out.append((pn, True, pd))
            else:
                raise SimulatorUnsupported(f"param spec not modelled in {sub!r}: {p!r}")
        return out

    def _walk_block(self, block: Any, names: set, targets: list) -> None:
        if not isinstance(block, list) or not block:
            raise SimulatorUnsupported(f"steps must be a non-empty list, got {block!r}")
        idx: dict[str, int] = {}
        for i, item in enumerate(block):
            if not isinstance(item, dict) or len(item) != 1:
                raise SimulatorUnsupported(f"each step must be a single-key map, got {item!r}")
            (name, body), = item.items()
            if not isinstance(name, str) or not name:
                raise SimulatorUnsupported(f"invalid step name {name!r}")
            if name in names:
                raise SimulatorUnsupported(f"duplicate step name {name!r}")
            names.add(name)
            idx[name] = i
            self._check_body(name, body, names, targets)
        self.block_index[id(block)] = idx

    def _check_next(self, nxt: Any, targets: list) -> None:
        if not isinstance(nxt, str):
            raise SimulatorUnsupported(f"next must be a step name, got {nxt!r}")
        if nxt in ("break", "continue"):
            raise SimulatorUnsupported(f"next: {nxt} (for loops) not modelled")
        targets.append(nxt)

    def _check_body(self, name: str, body: Any, names: set, targets: list) -> None:
        if not isinstance(body, dict):
            raise SimulatorUnsupported(f"step {name!r} body must be a map")
        unknown = set(body) - _PRIMARY_KEYS - {"args", "result", "next", "retry", "except"}
        if unknown:
            raise SimulatorUnsupported(f"step {name!r}: unknown keys {sorted(unknown)}")
        primaries = set(body) & _PRIMARY_KEYS
        if primaries & {"for", "parallel"}:
            raise SimulatorUnsupported(f"step {name!r}: for/parallel not modelled")
        if len(primaries) > 1:
            raise SimulatorUnsupported(f"step {name!r}: multiple step kinds {sorted(primaries)}")
        kind = primaries.pop() if primaries else None
        if kind is None and set(body) != {"next"}:
            raise SimulatorUnsupported(f"step {name!r}: no step kind")
        extra = set(body) - {kind} - _EXTRA_KEYS[kind]
        if extra:
            raise SimulatorUnsupported(f"step {name!r}: keys {sorted(extra)} not allowed with {kind!r}")
        if "next" in body:
            self._check_next(body["next"], targets)
        if kind == "assign":
            self._check_assign(name, body["assign"])
        elif kind == "call":
            self._check_call(name, body)
        elif kind == "switch":
            cases = body["switch"]
            if not isinstance(cases, list) or not cases:
                raise SimulatorUnsupported(f"step {name!r}: switch must be a non-empty list")
            for case in cases:
                if not isinstance(case, dict) or "condition" not in case:
                    raise SimulatorUnsupported(f"step {name!r}: switch case needs a condition: {case!r}")
                ck = set(case) - {"condition"}
                if ck - {"next", "assign", "steps", "return", "raise"}:
                    raise SimulatorUnsupported(f"step {name!r}: switch case keys {sorted(ck)} not modelled")
                if not ck:
                    raise SimulatorUnsupported(f"step {name!r}: switch case without an action")
                if {"return", "raise"} <= ck or (ck & {"return", "raise"} and "next" in ck):
                    raise SimulatorUnsupported(f"step {name!r}: switch case combines return/raise with next")
                if not ck & {"next", "return", "raise"} and "next" in body:
                    # Matched case with no next of its own while the step has a next: whether Workflows then takes
                    # the step-level next or the following step is not modelled.
                    raise SimulatorUnsupported(f"step {name!r}: switch case without next inside a step with next")
                _check_value(case["condition"])
                if "next" in case:
                    self._check_next(case["next"], targets)
                if "assign" in case:
                    self._check_assign(name, case["assign"])
                if "steps" in case:
                    self._walk_block(case["steps"], names, targets)
                for k in ("return", "raise"):
                    if k in case:
                        _check_value(case[k])
        elif kind == "try":
            tbody = body["try"]
            if not isinstance(tbody, dict):
                raise SimulatorUnsupported(f"step {name!r}: try body must be a map")
            if "steps" in tbody:
                if set(tbody) != {"steps"}:
                    raise SimulatorUnsupported(f"step {name!r}: try with steps takes no other keys")
                self._walk_block(tbody["steps"], names, targets)
            elif "call" in tbody:
                if set(tbody) - {"call", "args", "result"}:
                    raise SimulatorUnsupported(f"step {name!r}: try call body keys {sorted(tbody)} not modelled")
                self._check_call(name, tbody)
            else:
                raise SimulatorUnsupported(f"step {name!r}: try body must be a call or steps")
            if "retry" in body:
                _parse_retry(body["retry"], self.subs)
            if "except" in body:
                exc = body["except"]
                if not isinstance(exc, dict) or set(exc) - {"as", "steps"} or "steps" not in exc:
                    raise SimulatorUnsupported(f"step {name!r}: except must be {{as?, steps}}")
                if "as" in exc and (not isinstance(exc["as"], str) or not _IDENT_RE.match(exc["as"])):
                    raise SimulatorUnsupported(f"step {name!r}: except.as must be a variable name")
                self._walk_block(exc["steps"], names, targets)
            elif "retry" not in body:
                raise SimulatorUnsupported(f"step {name!r}: try without retry or except")
        elif kind in ("raise", "return"):
            _check_value(body[kind])
        elif kind == "steps":
            self._walk_block(body["steps"], names, targets)

    def _check_assign(self, name: str, items: Any) -> None:
        if not isinstance(items, list) or not items:
            raise SimulatorUnsupported(f"step {name!r}: assign must be a non-empty list")
        for item in items:
            if not isinstance(item, dict) or len(item) != 1:
                raise SimulatorUnsupported(f"step {name!r}: assign entries must be single-key maps: {item!r}")
            (key, value), = item.items()
            _parse_target(key)
            _check_value(value)

    def _check_call(self, name: str, body: dict) -> None:
        target = body["call"]
        if not isinstance(target, str):
            raise SimulatorUnsupported(f"step {name!r}: call target must be a name")
        if target not in self.subs and target not in _CALLS:
            raise SimulatorUnsupported(f"step {name!r}: call {target!r} not modelled")
        args = body.get("args", {})
        if not isinstance(args, dict):
            raise SimulatorUnsupported(f"step {name!r}: args must be a map")
        if target in self.subs:
            pnames = {p[0] for p in self.subs[target]["params"]}
            unknown = set(args) - pnames
            if unknown:
                raise SimulatorUnsupported(f"step {name!r}: {target} has no params {sorted(unknown)}")
        if target in _HTTP_METHODS and set(args) - _HTTP_ARG_KEYS:
            raise SimulatorUnsupported(f"step {name!r}: http args {sorted(set(args) - _HTTP_ARG_KEYS)} not modelled")
        _check_value(args)
        if "result" in body and (not isinstance(body["result"], str) or not _IDENT_RE.match(body["result"])):
            raise SimulatorUnsupported(f"step {name!r}: result must be a variable name")


def _check_value(v: Any) -> None:
    if isinstance(v, str):
        _check_string(v)
    elif isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str) or "${" in k:
                raise SimulatorUnsupported(f"map key {k!r} not modelled (must be a literal string)")
            _check_value(x)
    elif isinstance(v, list):
        for x in v:
            _check_value(x)
    elif v is not None and not isinstance(v, (bool, int, float)):
        raise SimulatorUnsupported(f"YAML value of type {type(v).__name__} not modelled: {v!r}")


def _parse_target(key: Any):
    if not isinstance(key, str):
        raise SimulatorUnsupported(f"assign key must be a string: {key!r}")
    node = parse_expression(key)
    n = node
    while n[0] in ("attr", "index"):
        n = n[1]
    if n[0] != "var":
        raise SimulatorUnsupported(f"assign target not modelled: {key!r}")
    return node


def validate(workflow: Any) -> None:
    """Static checks (like a deploy): raises SimulatorUnsupported on anything not modelled."""
    _Program(workflow)


def load_workflow(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def iter_expressions(workflow: Any) -> Iterator[str]:
    """Yield every string value (and map key) containing ``${`` anywhere in the document, in document order."""
    doc = yaml.safe_load(workflow) if isinstance(workflow, str) else workflow

    def walk(v):
        if isinstance(v, str):
            if "${" in v:
                yield v
        elif isinstance(v, dict):
            for k, x in v.items():
                if isinstance(k, str) and "${" in k:
                    yield k
                yield from walk(x)
        elif isinstance(v, list):
            for x in v:
                yield from walk(x)

    yield from walk(doc)


# ---------------------------------------------------------------------------------------------------- execution
class _Jump(Exception):
    def __init__(self, target: str):
        self.target = target


class _Return(Exception):
    def __init__(self, value: Any):
        self.value = value


class _Frame:
    __slots__ = ("name", "vars")

    def __init__(self, name: str, vars_: dict):
        self.name = name
        self.vars = vars_


@dataclass
class SimResult:
    state: str  # "SUCCEEDED" | "FAILED"
    result: Any
    error: Any
    calls: list = field(default_factory=list)
    logs: list = field(default_factory=list)
    published: list = field(default_factory=list)
    steps_executed: list = field(default_factory=list)
    retries: list = field(default_factory=list)
    attempts: dict = field(default_factory=dict)
    callbacks: list = field(default_factory=list)
    sleeps: list = field(default_factory=list)

    def calls_to(self, url_part: str) -> list[dict]:
        """HTTP calls whose url contains ``url_part`` (test convenience)."""
        return [c for c in self.calls if url_part in (c.get("url") or "")]


class Simulator:
    def __init__(
        self,
        http_handler: Callable | None = None,
        callback_handler: Callable | None = None,
        pubsub_handler: Callable | None = None,
        env: dict | None = None,
        step_budget: int = 10000,
        unassigned_variable: str = "unsupported",
        max_call_depth: int = 50,
        null_map_get: str = "null",
    ):
        if unassigned_variable not in ("unsupported", "keyerror"):
            raise ValueError("unassigned_variable must be 'unsupported' or 'keyerror'")
        if null_map_get not in ("null", "error"):
            raise ValueError("null_map_get must be 'null' or 'error'")
        self.null_map_get = null_map_get
        self.http_handler = http_handler
        self.callback_handler = callback_handler
        self.pubsub_handler = pubsub_handler
        self.env = {**_DEFAULT_ENV, **(env or {})}
        self.step_budget = step_budget
        self.unassigned_variable = unassigned_variable
        self.max_call_depth = max_call_depth
        self._reset()

    def _reset(self) -> None:
        self.calls: list[dict] = []
        self.logs: list[tuple[str, Any]] = []
        self.published: list[dict] = []
        self.steps_executed: list[str] = []
        self.retries: list[dict] = []
        self.attempts: dict[str, int] = {}
        self.callbacks: list[dict] = []
        self.sleeps: list[tuple[str, float]] = []
        self._callback_urls: set[str] = set()
        self._counters = {"uuid": 0, "callback": 0, "message": 0}
        self._depth = 0

    # ------------------------------------------------------------------------------------------------ entry point
    def run(self, workflow: Any, args: Any = None) -> SimResult:
        self._reset()
        self.program = _Program(workflow)
        main_params = self.program.subs["main"]["params"]
        call_args = {main_params[0][0]: copy.deepcopy(args)} if main_params else {}
        state, result, error = "SUCCEEDED", None, None
        try:
            result = self._run_sub("main", call_args)
        except WorkflowError as e:
            state, error = "FAILED", e.value
        return SimResult(state, result, error, self.calls, self.logs, self.published, self.steps_executed,
                         self.retries, self.attempts, self.callbacks, self.sleeps)

    # ------------------------------------------------------------------------------------------------ subworkflows
    def _run_sub(self, name: str, args: dict) -> Any:
        sub = self.program.subs[name]
        scope: dict[str, Any] = {}
        for pname, has_default, pdefault in sub["params"]:
            if pname in args:
                scope[pname] = copy.deepcopy(args[pname])
            elif has_default:
                scope[pname] = None  # placeholder; evaluated below in the callee scope
            else:
                raise SimulatorUnsupported(f"call of {name!r} without required param {pname!r}")
        frame = _Frame(name, scope)
        for pname, has_default, pdefault in sub["params"]:
            if pname not in args and has_default:
                scope[pname] = copy.deepcopy(self._value(pdefault, frame))
        self._depth += 1
        try:
            if self._depth > self.max_call_depth:
                raise SimulatorUnsupported("subworkflow call depth limit exceeded")
            self._run_block(frame, sub["steps"])
            return None
        except _Return as r:
            return r.value
        except _Jump as j:
            raise SimulatorUnsupported(
                f"jump to {j.target!r} in {name!r}: target is not in the current or an enclosing block"
            ) from None
        finally:
            self._depth -= 1

    def _run_block(self, frame: _Frame, block: list) -> None:
        index = self.program.block_index[id(block)]
        i = 0
        while i < len(block):
            (sname, body), = block[i].items()
            try:
                nxt = self._exec_step(frame, sname, body)
            except _Jump as j:
                nxt = j.target
            if nxt is None:
                i += 1
                continue
            if nxt == "end":
                raise _Return(None)
            if nxt not in index:
                raise _Jump(nxt)
            i = index[nxt]

    def _exec_step(self, frame: _Frame, name: str, body: dict) -> str | None:
        if len(self.steps_executed) >= self.step_budget:
            raise SimulatorUnsupported(f"step budget of {self.step_budget} exceeded (infinite loop?)")
        self.steps_executed.append(name)
        if "assign" in body:
            self._do_assign(frame, body["assign"])
        elif "call" in body:
            self._do_call(frame, name, body)
        elif "switch" in body:
            return self._do_switch(frame, name, body)
        elif "try" in body:
            self._do_try(frame, name, body)
        elif "raise" in body:
            raise WorkflowError(copy.deepcopy(self._value(body["raise"], frame)))
        elif "return" in body:
            raise _Return(copy.deepcopy(self._value(body["return"], frame)))
        elif "steps" in body:
            self._run_block(frame, body["steps"])
        return body.get("next")

    def _do_switch(self, frame: _Frame, name: str, body: dict) -> str | None:
        for case in body["switch"]:
            cond = self._value(case["condition"], frame)
            if not isinstance(cond, bool):
                raise _type_error(f"switch condition in step {name!r} must be a boolean, got {_type_name(cond)}")
            if not cond:
                continue
            if "assign" in case:
                self._do_assign(frame, case["assign"])
            if "steps" in case:
                self._run_block(frame, case["steps"])
            if "return" in case:
                raise _Return(copy.deepcopy(self._value(case["return"], frame)))
            if "raise" in case:
                raise WorkflowError(copy.deepcopy(self._value(case["raise"], frame)))
            return case.get("next")
        return body.get("next")

    def _do_try(self, frame: _Frame, name: str, body: dict) -> None:
        policy = _parse_retry(body["retry"], self.program.subs) if "retry" in body else None
        tbody = body["try"]
        attempt = 0
        while True:
            attempt += 1
            self.attempts[name] = self.attempts.get(name, 0) + 1
            try:
                if "steps" in tbody:
                    self._run_block(frame, tbody["steps"])
                else:
                    self._do_call(frame, name, tbody)
                return
            except WorkflowError as e:
                caught = e.value
            if policy and attempt <= policy["max_retries"] and self._retryable(policy, caught):
                delay = min(policy["initial"] * policy["multiplier"] ** (attempt - 1), policy["max_delay"])
                self.retries.append({"step": name, "attempt": attempt, "error": copy.deepcopy(caught),
                                     "delay": delay})
                self.sleeps.append(("retry", delay))
                continue
            if "except" not in body:
                raise WorkflowError(caught)
            exc = body["except"]
            if "as" in exc:
                frame.vars[exc["as"]] = copy.deepcopy(caught)
            self._run_block(frame, exc["steps"])
            return

    def _retryable(self, policy: dict, err: Any) -> bool:
        pred = policy["predicate"]
        if isinstance(pred, tuple):
            sub = pred[1]
            params = self.program.subs[sub]["params"]
            if len(params) != 1:
                raise SimulatorUnsupported(f"retry predicate subworkflow {sub!r} must take exactly one param")
            verdict = self._run_sub(sub, {params[0][0]: err})
            if not isinstance(verdict, bool):
                raise _type_error(f"retry predicate {sub!r} must return a boolean")
            return verdict
        return _builtin_retry_predicate(pred, err)

    # ------------------------------------------------------------------------------------------------ assignment
    def _do_assign(self, frame: _Frame, items: list) -> None:
        for item in items:
            (key, value), = item.items()
            target = _parse_target(key)
            val = copy.deepcopy(self._value(value, frame))
            if target[0] == "var":
                frame.vars[target[1]] = val
                continue
            container = self._eval(target[1], frame)
            if target[0] == "attr":
                k = target[2]
            else:
                k = self._eval(target[2], frame)
            if isinstance(container, dict):
                if not isinstance(k, str):
                    raise _type_error(f"map keys must be strings, got {_type_name(k)}")
                container[k] = val
            elif isinstance(container, list) and target[0] == "index":
                if not _is_num(k) or isinstance(k, float):
                    raise _type_error(f"list index must be an integer, got {_type_name(k)}")
                if not 0 <= k < len(container):
                    raise _err("IndexError", "IndexError: list index out of range")
                container[k] = val
            else:
                raise _type_error(f"cannot assign {key!r}: container is {_type_name(container)}")

    # ------------------------------------------------------------------------------------------------ calls
    def _do_call(self, frame: _Frame, step: str, body: dict) -> None:
        target = body["call"]
        args = copy.deepcopy(self._value(body.get("args", {}), frame))
        record: dict[str, Any] = {"step": step, "call": target, "args": copy.deepcopy(args)}
        if target in _HTTP_METHODS:
            record["url"] = args.get("url")
            method = args.get("method") if target == "http.request" else _HTTP_METHODS[target]
            record["method"] = method.upper() if isinstance(method, str) else method
            if "body" in args:
                record["body"] = copy.deepcopy(args["body"])
        elif target == _PUBSUB_PUBLISH:
            record["topic"] = args.get("topic")
            record["body"] = copy.deepcopy(args.get("body"))
        self.calls.append(record)
        if target in self.program.subs:
            result = self._run_sub(target, args)
        elif target in _HTTP_METHODS:
            result = self._call_http(target, args)
        elif target == "events.create_callback_endpoint":
            result = self._call_create_callback(step, args)
        elif target == "events.await_callback":
            result = self._call_await_callback(step, args)
        elif target == _PUBSUB_PUBLISH:
            result = self._call_publish(step, args)
        elif target == "sys.log":
            result = self._call_log(args)
        elif target == "sys.sleep":
            if set(args) != {"seconds"} or not _is_num(args["seconds"]):
                raise SimulatorUnsupported(f"sys.sleep args not modelled: {args!r}")
            self.sleeps.append(("sys.sleep", float(args["seconds"])))
            result = None
        elif target == "sys.get_env":
            if set(args) - {"name", "default"} or "name" not in args:
                raise SimulatorUnsupported(f"sys.get_env args not modelled: {args!r}")
            result = self._f_get_env(*([args["name"]] + ([args["default"]] if "default" in args else [])))
        else:  # unreachable after validation
            raise SimulatorUnsupported(f"call {target!r} not modelled")
        if "result" in body:
            frame.vars[body["result"]] = copy.deepcopy(result)

    def _call_http(self, target: str, args: dict) -> dict:
        if self.http_handler is None:
            raise SimulatorUnsupported(f"{target} executed but no http_handler was provided")
        url = args.get("url")
        if not isinstance(url, str) or not url:
            raise _type_error(f"{target}: url must be a non-empty string, got {_type_name(url)}")
        if target == "http.request":
            method = args.get("method")
            if not isinstance(method, str):
                raise SimulatorUnsupported("http.request without a method")
            method = method.upper()
        else:
            if "method" in args:
                raise SimulatorUnsupported(f"{target} with a method arg not modelled")
            method = _HTTP_METHODS[target]
        try:
            response = self.http_handler(method, url, copy.deepcopy(args.get("body")), copy.deepcopy(args))
        except SimTimeout as e:
            raise _err("TimeoutError", f"HTTP request timed out: {e}") from None
        except SimConnectionError as e:
            raise _err(e.tag, f"{e.tag}: {e}") from None
        if not isinstance(response, tuple) or len(response) not in (2, 3):
            raise SimulatorUnsupported(f"http_handler must return (status, body[, headers]), got {response!r}")
        status, rbody = response[0], copy.deepcopy(response[1])
        headers = dict(response[2]) if len(response) == 3 else {}
        if not isinstance(status, int) or isinstance(status, bool):
            raise SimulatorUnsupported(f"http_handler status must be an int, got {status!r}")
        if rbody is not None:
            _type_name(rbody)  # refuse non-Workflows Python values early
        if status >= 400:
            raise WorkflowError(http_error(status, rbody, headers))
        return {"code": status, "body": rbody, "headers": headers}

    def _call_create_callback(self, step: str, args: dict) -> dict:
        if set(args) - {"http_callback_method"}:
            raise SimulatorUnsupported(f"create_callback_endpoint args not modelled: {sorted(args)}")
        method = args.get("http_callback_method", "POST")
        self._counters["callback"] += 1
        url = f"https://sim.callbacks/{self._counters['callback']}"
        self._callback_urls.add(url)
        self.callbacks.append({"step": step, "event": "created", "url": url, "method": method})
        return {"url": url}

    def _call_await_callback(self, step: str, args: dict) -> dict:
        if set(args) - {"callback", "timeout"} or "callback" not in args:
            raise SimulatorUnsupported(f"await_callback args not modelled: {sorted(args)}")
        cb = args["callback"]
        if not isinstance(cb, dict) or cb.get("url") not in self._callback_urls:
            raise _type_error("await_callback: callback must be a map returned by create_callback_endpoint")
        timeout = args.get("timeout", 43200)  # Workflows default: 12 hours
        if self.callback_handler is None:
            raise SimulatorUnsupported("events.await_callback executed but no callback_handler was provided")
        self.callbacks.append({"step": step, "event": "await", "url": cb["url"], "timeout": timeout})
        try:
            rbody = copy.deepcopy(self.callback_handler(cb["url"], timeout))
        except SimTimeout:
            raise _err("TimeoutError", f"Timeout occurred while waiting for callback {cb['url']}") from None
        if rbody is not None:
            _type_name(rbody)
        return {
            "http_request": {"body": rbody, "headers": {}, "method": "POST", "query": {}, "url": cb["url"]},
            "received_time": "1970-01-01T00:00:00Z",
            "type": "HTTP",
        }

    def _call_publish(self, step: str, args: dict) -> Any:
        if set(args) - {"topic", "body"} or "topic" not in args or "body" not in args:
            raise SimulatorUnsupported(f"pubsub publish args not modelled: {sorted(args)}")
        body = args["body"]
        if not isinstance(body, dict) or set(body) != {"messages"} or not isinstance(body["messages"], list):
            raise SimulatorUnsupported(f"pubsub publish body must be {{messages: [...]}}: {body!r}")
        decoded = []
        for msg in body["messages"]:
            if not isinstance(msg, dict) or set(msg) - {"data", "attributes", "orderingKey"}:
                raise SimulatorUnsupported(f"pubsub message shape not modelled: {msg!r}")
            data = msg.get("data")
            try:
                raw = base64.b64decode(data, validate=True) if isinstance(data, str) else None
            except (binascii.Error, ValueError):
                raw = None
            if raw is None:
                # The Pub/Sub API rejects a non-base64 data field with HTTP 400.
                raise WorkflowError(http_error(400, {"error": {"message": "Invalid data: must be base64"}}))
            try:
                decoded.append(json.loads(raw))
            except (ValueError, UnicodeDecodeError):
                decoded.append(raw)
        if self.pubsub_handler is not None:
            result = copy.deepcopy(self.pubsub_handler(args["topic"], copy.deepcopy(body["messages"])))
        else:
            ids = []
            for _ in body["messages"]:
                self._counters["message"] += 1
                ids.append(str(self._counters["message"]))
            result = {"messageIds": ids}
        self.published.append({"step": step, "topic": args["topic"], "messages": copy.deepcopy(body["messages"]),
                               "data": decoded})
        return result

    def _call_log(self, args: dict) -> None:
        if set(args) - {"text", "json", "data", "severity"} or len(set(args) & {"text", "json", "data"}) != 1:
            raise SimulatorUnsupported(f"sys.log args not modelled: {sorted(args)}")
        severity = args.get("severity", "DEFAULT")
        if severity not in _LOG_SEVERITIES:
            raise SimulatorUnsupported(f"sys.log severity {severity!r} not modelled")
        if "text" in args and not isinstance(args["text"], str):
            raise SimulatorUnsupported(f"sys.log text of type {_type_name(args['text'])} not modelled")
        payload = args.get("text", args.get("json", args.get("data")))
        self.logs.append((severity, payload))
        return None

    # ------------------------------------------------------------------------------------------------ evaluation
    def _value(self, v: Any, frame: _Frame) -> Any:
        """Evaluate a YAML value: whole-string ${...} expressions, recursively through maps and lists."""
        if isinstance(v, str):
            if _is_expr(v):
                return self._eval(parse_expression(_expr_text(v)), frame)
            _check_string(v)
            return v
        if isinstance(v, dict):
            return {k: self._value(x, frame) for k, x in v.items()}
        if isinstance(v, list):
            return [self._value(x, frame) for x in v]
        if v is None or isinstance(v, (bool, int, float)):
            return v
        raise SimulatorUnsupported(f"YAML value of type {type(v).__name__} not modelled: {v!r}")

    def _lookup(self, frame: _Frame, name: str) -> Any:
        if name in frame.vars:
            return frame.vars[name]
        if self.unassigned_variable == "keyerror":
            raise _key_error(name)
        raise SimulatorUnsupported(
            f"reference to unassigned variable {name!r} in subworkflow {frame.name!r} (runtime semantics not "
            "modelled; pass unassigned_variable='keyerror' to model it as a KeyError)"
        )

    def _eval(self, node, frame: _Frame) -> Any:
        kind = node[0]
        if kind == "lit":
            return node[1]
        if kind == "var":
            return self._lookup(frame, node[1])
        if kind == "attr":
            return _get_key(self._eval(node[1], frame), node[2], attr=True)
        if kind == "index":
            obj = self._eval(node[1], frame)
            return _get_key(obj, self._eval(node[2], frame), attr=False)
        if kind == "list":
            return [self._eval(x, frame) for x in node[1]]
        if kind == "map":
            return {k: self._eval(x, frame) for k, x in node[1]}
        if kind == "call":
            fname, argn = node[1], node[2]
            args = [self._eval(a, frame) for a in argn]
            return getattr(self, _FUNCS[fname][2])(*args)
        if kind == "un":
            x = self._eval(node[2], frame)
            if node[1] == "-":
                if not _is_num(x):
                    raise _type_error(f"unary - on {_type_name(x)}")
                return -x
            if not isinstance(x, bool):
                raise _type_error(f"not on {_type_name(x)}")
            return not x
        if kind == "bin":
            op = node[1]
            if op in ("and", "or"):
                # Modelled as short-circuit (left to right); both operands must be booleans.
                left = self._eval(node[2], frame)
                if not isinstance(left, bool):
                    raise _type_error(f"{op} on {_type_name(left)}")
                if (op == "and" and not left) or (op == "or" and left):
                    return left
                right = self._eval(node[3], frame)
                if not isinstance(right, bool):
                    raise _type_error(f"{op} on {_type_name(right)}")
                return right
            return _binop(op, self._eval(node[2], frame), self._eval(node[3], frame))
        raise SimulatorUnsupported(f"AST node {kind!r}")  # pragma: no cover

    # ------------------------------------------------------------------------------------------------ functions
    @staticmethod
    def _f_default(v, d):
        # Only null is replaced; an error while evaluating v (e.g. KeyError of a.b) propagates (args are eager).
        return d if v is None else v

    def _f_map_get(self, m, key):
        # Choice: map.get(null, k) -> null (null_map_get="null", default) or TypeError (null_map_get="error");
        # map.get(<non-map>, k) -> TypeError. key may be a string or a list of strings (nested path; null as soon
        # as a level is missing). A non-null, non-map intermediate level is not modelled.
        path = key if isinstance(key, list) else [key]
        if not path or not all(isinstance(k, str) for k in path):
            raise _type_error("map.get key must be a string or a non-empty list of strings")
        if m is None and self.null_map_get == "error":
            raise _type_error("map.get on null (null_map_get='error')")
        if m is not None and not isinstance(m, dict):
            raise _type_error(f"map.get on {_type_name(m)}")
        cur = m
        for k in path:
            if cur is None:
                return None
            if not isinstance(cur, dict):
                raise SimulatorUnsupported(f"map.get through a non-map intermediate ({_type_name(cur)})")
            cur = cur.get(k)
        return cur

    @staticmethod
    def _f_map_merge(a, b):
        if not isinstance(a, dict) or not isinstance(b, dict):
            raise _type_error(f"map.merge on {_type_name(a)}, {_type_name(b)}")
        return {**a, **b}

    @staticmethod
    def _f_keys(m):
        if not isinstance(m, dict):
            raise _type_error(f"keys on {_type_name(m)}")
        return list(m.keys())  # insertion order (Workflows map key order is not modelled beyond that)

    @staticmethod
    def _f_len(v):
        if isinstance(v, (str, list, dict, bytes)):
            return len(v)
        raise _type_error(f"len on {_type_name(v)}")

    @staticmethod
    def _f_string(v):
        if isinstance(v, str):
            return v
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            if math.isfinite(v) and not v.is_integer():
                return repr(v)
            raise SimulatorUnsupported(f"string() of the double {v!r}: formatting not modelled")
        if isinstance(v, (list, dict)):
            raise _type_error(f"string() only converts scalars, got {_type_name(v)}")
        raise SimulatorUnsupported(f"string() of {_type_name(v)} not modelled")

    @staticmethod
    def _f_int(v):
        if isinstance(v, bool):
            raise _type_error("int() of boolean")
        if isinstance(v, int):
            return v
        if isinstance(v, float):
            if not math.isfinite(v):
                raise _err("ValueError", f"ValueError: int() of {v!r}")
            return int(v)  # truncation toward zero
        if isinstance(v, str):
            if not re.fullmatch(r"[+-]?\d+", v):
                raise _err("ValueError", f"ValueError: cannot convert {v!r} to integer")
            return int(v)
        raise _type_error(f"int() of {_type_name(v)}")

    @staticmethod
    def _f_double(v):
        if isinstance(v, bool):
            raise _type_error("double() of boolean")
        if _is_num(v):
            return float(v)
        if isinstance(v, str):
            try:
                return float(v)
            except ValueError:
                raise _err("ValueError", f"ValueError: cannot convert {v!r} to double") from None
        raise _type_error(f"double() of {_type_name(v)}")

    @staticmethod
    def _f_bool(v):
        if isinstance(v, bool):
            return v
        if v in ("true", "false"):
            return v == "true"
        raise SimulatorUnsupported(f"bool() of {v!r} not modelled")

    @staticmethod
    def _f_get_type(v):
        return _type_name(v)

    @staticmethod
    def _json_text(v) -> str:
        def check(x):
            t = _type_name(x)
            if t == "bytes":
                raise _type_error("json.encode of bytes")
            if t == "list":
                for y in x:
                    check(y)
            if t == "map":
                for y in x.values():
                    check(y)

        check(v)
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False)

    def _f_json_encode(self, v):
        return self._json_text(v).encode("utf-8")

    def _f_json_encode_to_string(self, v):
        return self._json_text(v)

    @staticmethod
    def _f_json_decode(v):
        if not isinstance(v, (bytes, str)):
            raise _type_error(f"json.decode of {_type_name(v)}")
        try:
            return json.loads(v)
        except (ValueError, UnicodeDecodeError) as e:
            raise _err("ValueError", f"ValueError: invalid JSON: {e}") from None

    @staticmethod
    def _f_base64_encode(v, padding=True):
        if not isinstance(v, bytes):
            raise _type_error(f"base64.encode expects bytes, got {_type_name(v)}")
        if not isinstance(padding, bool):
            raise _type_error("base64.encode padding must be a boolean")
        out = base64.b64encode(v).decode("ascii")
        return out if padding else out.rstrip("=")

    @staticmethod
    def _f_base64_decode(v, padding=True):
        if not isinstance(v, str):
            raise _type_error(f"base64.decode expects a string, got {_type_name(v)}")
        if not isinstance(padding, bool):
            raise _type_error("base64.decode padding must be a boolean")
        text = v if padding else v + "=" * (-len(v) % 4)
        try:
            return base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            raise _err("ValueError", "ValueError: invalid base64 input") from None

    @staticmethod
    def _f_to_lower(v):
        if not isinstance(v, str):
            raise _type_error(f"text.to_lower of {_type_name(v)}")
        return v.lower()

    @staticmethod
    def _f_to_upper(v):
        if not isinstance(v, str):
            raise _type_error(f"text.to_upper of {_type_name(v)}")
        return v.upper()

    @staticmethod
    def _f_split(source, sep):
        if not isinstance(source, str) or not isinstance(sep, str):
            raise _type_error("text.split expects (string, string)")
        if sep == "":
            raise SimulatorUnsupported("text.split with an empty separator not modelled")
        return source.split(sep)

    def _f_uuid(self):
        self._counters["uuid"] += 1
        return f"00000000-0000-4000-8000-{self._counters['uuid']:012d}"

    def _f_get_env(self, name, *default):
        if not isinstance(name, str):
            raise _type_error("sys.get_env name must be a string")
        if name in self.env:
            return self.env[name]
        if default:
            return default[0]
        raise SimulatorUnsupported(f"sys.get_env({name!r}): variable not provided to the Simulator(env=...)")

    @staticmethod
    def _f_list_concat(lst, value):
        if not isinstance(lst, list):
            raise _type_error(f"list.concat expects a list, got {_type_name(lst)}")
        return lst + [copy.deepcopy(value)]


def _get_key(obj: Any, key: Any, attr: bool) -> Any:
    if isinstance(obj, dict):
        if not isinstance(key, str):
            raise _type_error(f"map keys must be strings, got {_type_name(key)}")
        if key not in obj:
            raise _key_error(key)
        return obj[key]
    if isinstance(obj, list) and not attr:
        if not _is_num(key) or isinstance(key, float):
            raise _type_error(f"list index must be an integer, got {_type_name(key)}")
        if not 0 <= key < len(obj):
            raise _err("IndexError", "IndexError: list index out of range")
        return obj[key]
    what = f"attribute {key!r}" if attr else f"index [{key!r}]"
    raise _type_error(f"cannot access {what} of a {_type_name(obj)} value")


def _binop(op: str, a: Any, b: Any) -> Any:
    ta, tb = _type_name(a), _type_name(b)
    if op == "==":
        return _wf_equal(a, b)
    if op == "!=":
        return not _wf_equal(a, b)
    if op == "in":
        if tb == "list":
            return any(_wf_equal(a, x) for x in b)
        if tb == "map":
            if ta != "string":
                raise _type_error(f"'in' a map needs a string key, got {ta}")
            return a in b
        raise _type_error(f"'in' needs a list or map on the right, got {tb}")
    if op in ("<", "<=", ">", ">="):
        if not ((_is_num(a) and _is_num(b)) or (ta == tb == "string")):
            raise _type_error(f"unsupported operand types for {op}: {ta} and {tb}")
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    if op == "+" and ta == tb == "string":
        return a + b
    if not (_is_num(a) and _is_num(b)):
        raise _type_error(f"unsupported operand types for {op}: {ta} and {tb}")
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op in ("/", "%", "//") and b == 0:
        raise _err("ZeroDivisionError", "ZeroDivisionError: division by zero")
    if op == "/":
        return a / b  # modelled as always producing a double
    if op == "%":
        return a % b
    if op == "//":
        return a // b
    raise SimulatorUnsupported(f"operator {op!r}")  # pragma: no cover


def run(workflow: Any, args: Any = None, **simulator_kwargs) -> SimResult:
    """Convenience: ``Simulator(**simulator_kwargs).run(workflow, args)``."""
    return Simulator(**simulator_kwargs).run(workflow, args)

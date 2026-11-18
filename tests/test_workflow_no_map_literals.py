import hermetic_guard  # noqa: F401  (lane 2 standing rule: first import)
"""Cloud Workflows expressions (`${...}`) have no map literals; `{` inside an expression is a deploy-time parse error.

Regression for the castor apply of a25b980 (10-13): `map.merge(failure, {"trace_id": ...})` in publish_dead_letter was
accepted by tests/workflow_sim.py but rejected by the Workflows API ("extraneous input '{'"). Static check over every
expression in both workflow files, independent of the simulator.
"""
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["workflows/main_orchestrator.yaml", "workflows/sre_remediation.yaml"]


def _expressions(text):
    # Exact Workflows expression delimiters: `${` ... matching `}` (string literals inside respected).
    i = 0
    while True:
        start = text.find("${", i)
        if start < 0:
            return
        depth, j, quote = 0, start + 1, None
        while j < len(text):
            ch = text[j]
            if quote:
                if ch == "\\":
                    j += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    yield text.count("\n", 0, start) + 1, text[start + 2:j]
                    break
            j += 1
        i = j + 1


@pytest.mark.parametrize("rel", FILES)
def test_no_map_literal_inside_expressions(rel):
    text = open(os.path.join(ROOT, rel), encoding="utf-8").read()
    bad = []
    for line, expr in _expressions(text):
        depth, quote = 0, None
        for k, ch in enumerate(expr):
            if quote:
                if ch == quote and expr[k - 1] != "\\":
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "{":
                bad.append((line, expr[:80]))
                break
    assert not bad, f"map literal inside a Workflows expression (not supported by the API): {bad}"

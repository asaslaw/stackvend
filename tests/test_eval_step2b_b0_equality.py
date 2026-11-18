"""S2-B B0 equality tool (eval/tools/step2b_b0_equality.py): the "old function with branches disabled" is built from
the AST by marker ownership, never by text surgery (Step 2 plan §3.2 B0)."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import importlib.util
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVAL_DIR = os.path.join(REPO_ROOT, "eval")
if EVAL_DIR not in sys.path:
    sys.path.insert(0, EVAL_DIR)

_spec = importlib.util.spec_from_file_location("step2b_b0_equality_t",
                                               os.path.join(EVAL_DIR, "tools", "step2b_b0_equality.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
disable_branches = _mod.disable_branches

SRC = '''
def _self_correct_workload_hcl(files, errors, product_id="workload"):
    healed_files = dict(files)
    for err in errors:
        # 0. Handle HCL syntax errors
        healed_files["a"] = "error-branch"
        # 1. Handle undeclared variable
        healed_files["b"] = "kept-error-branch"

    # Autonomous Network Graph Auto-Wiring
    healed_files["sweep"] = "sweep"

    # Deduplicate outputs across root .tf files
    healed_files["tail"] = "tail"
    return healed_files
'''

BRANCHES = [
    {"marker": "# 0. Handle HCL syntax errors", "id": "E0", "kind": "error"},
    {"marker": "# 1. Handle undeclared variable", "id": "E1", "kind": "error"},
    {"marker": "# Autonomous Network Graph Auto-Wiring", "id": "S", "kind": "sweep"},
    {"marker": "# Deduplicate outputs across root .tf files", "id": "T", "kind": "tail"},
]


def _run(tree):
    ns = {}
    exec(compile(tree, "<t>", "exec"), ns)
    return ns["_self_correct_workload_hcl"]({}, ["x"])


def test_nothing_disabled_is_the_original_function():
    tree, removed = disable_branches(SRC, BRANCHES, set())
    assert removed == {}
    assert _run(tree) == _run(ast.parse(SRC))


def test_disabled_branches_lose_exactly_their_statements_and_the_return_is_kept():
    tree, removed = disable_branches(SRC, BRANCHES, {0, 3})
    assert removed == {0: 1, 3: 1}
    assert _run(tree) == {"b": "kept-error-branch", "sweep": "sweep"}


def test_an_emptied_error_loop_still_compiles():
    tree, removed = disable_branches(SRC, BRANCHES, {0, 1, 3})
    assert removed == {0: 1, 1: 1, 3: 1}
    assert _run(tree) == {"sweep": "sweep"}

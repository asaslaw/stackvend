"""
FD-4AH remainder (FD21-18): apps/orchestrator-gateway/developer_agent/handler.py used ``random`` (the jittered
back-off on a non-fast-forward branch-ref collision during the Git commit) without importing it, so the retry path
raised NameError instead of rebasing and retrying.

Static gate: pyflakes (pinned in apps/orchestrator-gateway/requirements.txt) must report no undefined name
(F821 class) anywhere in that file. Hermetic: pyflakes only parses the source; nothing is imported or executed.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import os

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HANDLER = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "developer_agent", "handler.py")


def _undefined_names(path):
    from pyflakes import checker, messages

    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source, filename=path)
    found = checker.Checker(tree, filename=path)
    return sorted(
        f"{m.lineno}: {m.message_args[0]}"
        for m in found.messages
        if isinstance(m, messages.UndefinedName)
    )


def test_developer_handler_has_no_undefined_names():
    assert _undefined_names(HANDLER) == []


def test_pyflakes_gate_detects_undefined_name(tmp_path):
    """The gate itself must fire: a file reading an unimported module is reported."""
    bad = tmp_path / "bad.py"
    bad.write_text("import time\n\ndef f():\n    time.sleep(random.uniform(0.2, 0.8))\n", encoding="utf-8")
    assert _undefined_names(str(bad)) == ["4: random"]

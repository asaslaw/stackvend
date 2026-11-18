"""Validity oracles (scoring child only). Python: ast.parse + pyflakes undefined names. HCL: `tofu fmt -` (the
production grammar) via TofuRunner; python-hcl2 is used only for *structure* (invariants), never for validity."""
from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional, Tuple

from .paths import add_deps_to_path


def py_ast(text: str, filename: str = "<generated>") -> Tuple[bool, Optional[str]]:
    try:
        ast.parse(text, filename=filename)
        return True, None
    except SyntaxError as e:
        return False, f"{e.msg} (line {e.lineno})"
    except ValueError as e:  # null bytes etc.
        return False, str(e)


def py_undefined_names(text: str, filename: str = "<generated>") -> Optional[List[str]]:
    """pyflakes UndefinedName/UndefinedLocal/UndefinedExport messages; None when pyflakes is unavailable or the
    file does not parse."""
    add_deps_to_path()
    try:
        from pyflakes import checker
        from pyflakes import messages as pf_msgs
    except Exception:
        return None
    try:
        tree = ast.parse(text, filename=filename)
    except Exception:
        return None
    w = checker.Checker(tree, filename=filename)
    kinds = (pf_msgs.UndefinedName, pf_msgs.UndefinedLocal, pf_msgs.UndefinedExport)
    return [f"{m.lineno}: {m.message % m.message_args}" for m in w.messages if isinstance(m, kinds)]


def score_python(tree: Dict[str, str]) -> Dict[str, Any]:
    files = {k: v for k, v in tree.items() if k.endswith(".py")}
    ast_fail = {}
    undefined: Dict[str, List[str]] = {}
    pyflakes_available = True
    for path, text in sorted(files.items()):
        ok, err = py_ast(text, path)
        if not ok:
            ast_fail[path] = err
            continue
        u = py_undefined_names(text, path)
        if u is None:
            pyflakes_available = False
        elif u:
            undefined[path] = u[:20]
    return {"py_files": len(files), "ast_ok": len(files) - len(ast_fail), "ast_fail": ast_fail,
            "undefined_names": undefined, "files_with_undefined_names": len(undefined),
            "pyflakes_available": pyflakes_available}


def py_file_validate_level(text: str, path: str) -> str:
    """H1 tri-state for one .py file: valid | invalid | unknown (validate-level = ast + no undefined names)."""
    ok, _ = py_ast(text, path)
    if not ok:
        return "invalid"
    u = py_undefined_names(text, path)
    if u is None:
        return "unknown"
    return "invalid" if u else "valid"

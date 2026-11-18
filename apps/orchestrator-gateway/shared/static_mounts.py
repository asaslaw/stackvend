"""The one static-directory placeholder rule (FD-55 W5 G21 + FD55-A8-CONVERT): which `<dir>/.gitkeep` a service needs.

A Starlette / FastAPI `StaticFiles(directory="<dir>")` mount fails at start-up when `<dir>` does not exist, and Git does
not keep an empty directory. Two places add the empty placeholder, both through this module:

- the developer stage, on the committed tree (apps/orchestrator-gateway/developer_agent/handler.enforce_container_contract,
  FD-55 W5, register FD55-W5);
- the deploy, on the deploy workspace copy only (mcp-servers/terraform/service.prepare_workspace, FD55-A8-CONVERT,
  owner 10-27; never committed back, FD55-W6b). It replaced the substring test `"StaticFiles" in main.py`.

The directory is found with Python's parser (`ast`), never by a text match: only a call whose callee is the name
`StaticFiles` or an attribute `<x>.StaticFiles`, with a `directory=` keyword that is a string literal, counts. A comment,
a string, an import alone, a non-literal directory (e.g. `Path(__file__).parent / "static"`) or a file that does not parse
adds nothing. The placeholder is add-only: only when the directory holds no file yet.

Byte-identical copies (the gateway and terraform MCP images are built from their own shared/ directories):
apps/orchestrator-gateway/shared/static_mounts.py and mcp-servers/terraform/shared/static_mounts.py
(tests/test_fd55_a8_static_mounts.py).
"""
import ast
import posixpath
from typing import Any, List, Mapping

PLACEHOLDER_NAME = ".gitkeep"


def static_mount_dirs(py_text: str) -> List[str]:
    """FD-55 W5 (register FD55-W5; plan G21 CONVERT): the directories a Python file mounts with Starlette / FastAPI
    `StaticFiles(directory="<d>")`, by `ast`: a call whose callee is the name `StaticFiles` or an attribute
    `<x>.StaticFiles`, with a `directory=` keyword that is a string literal. The value is normalized
    (`posixpath.normpath`) and kept only when it is a plain relative path inside the service (not absolute, no `..`,
    not `.`). A file that does not parse, a non-literal directory, or `StaticFiles` in a comment or a string -> [].
    Replaces the substring test `"StaticFiles" in main.py and "static" in main.py`."""
    try:
        tree = ast.parse(py_text)
    except (SyntaxError, ValueError, RecursionError):   # RT F1: a pathologically nested file must not stop the deploy
        return []
    out: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else None)
        if name != "StaticFiles":
            continue
        for kw in node.keywords:
            if kw.arg == "directory" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                d = posixpath.normpath(kw.value.value)
                if d and d != "." and not d.startswith("/") and ".." not in d.split("/") and d not in out:
                    out.append(d)
    return out


def static_placeholder_files(service_files: Mapping[str, Any]) -> List[str]:
    """The placeholder files one service needs, as paths relative to the service root (`<dir>/.gitkeep`).

    `service_files` maps every file of the service (path relative to the service root, `/`-separated) to its text;
    only `.py` entries whose value is a `str` are parsed (any other value, e.g. None for a file that was not read, only
    counts as "a file exists here"). Directories are collected in sorted path order; a placeholder is listed only when
    no file (including a placeholder listed before it) lies under that directory."""
    mounted: List[str] = []
    for path in sorted(service_files):
        text = service_files[path]
        if path.endswith(".py") and isinstance(text, str):
            for d in static_mount_dirs(text):
                if d not in mounted:
                    mounted.append(d)
    keys = list(service_files)
    out: List[str] = []
    for d in mounted:
        if not any(k.startswith(f"{d}/") for k in keys):
            rel = f"{d}/{PLACEHOLDER_NAME}"
            out.append(rel)
            keys.append(rel)
    return out

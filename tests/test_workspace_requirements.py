"""Workspace MCP server: every third-party module it imports at runtime is declared in its requirements.txt.

Found 10-28: `/request-approval` without `approval_id` persists the approval through `google.cloud.firestore`
(imported inside `_firestore_client`), but the server's requirements.txt did not declare google-cloud-firestore, so
on Cloud Run that path failed 502 APPROVAL_PERSIST_FAILED. The scan below reads every import statement (module level
and function level) of the server's runtime files with `ast` (never imports them) and resolves each one to the
distribution that provides it through an explicit table: an import the table does not know fails, so a new
dependency must be added to the table and to requirements.txt together. Hermetic: no network, no clients."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import re
import sys
from importlib.metadata import PackageNotFoundError, distribution

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKSPACE = os.path.join(REPO_ROOT, "mcp-servers", "workspace")

# Import path (dotted prefix) -> the distribution that installs it. Longest prefix wins (google.* is a namespace).
IMPORT_TO_DIST = {
    "fastapi": "fastapi",
    "pydantic": "pydantic",
    "uvicorn": "uvicorn",
    "google.auth": "google-auth",
    "googleapiclient": "google-api-python-client",
    "google.cloud.firestore": "google-cloud-firestore",
    "google_auth_httplib2": "google-auth-httplib2",   # incident_doc.py: Drive/Docs discovery client transport
    "httplib2": "httplib2",
}


def _canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _runtime_files():
    return sorted(f for f in os.listdir(WORKSPACE) if f.endswith(".py") and not f.startswith("test_"))


def _local_modules():
    return {f[:-3] for f in _runtime_files()}


def _imports():
    """(file, line, dotted import path) for every absolute import in the runtime files. `from a.b import c` yields
    `a.b.c` (c may be a submodule, as in `from google.cloud import firestore`)."""
    found = []
    for name in _runtime_files():
        with open(os.path.join(WORKSPACE, name), encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found += [(name, node.lineno, a.name) for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found += [(name, node.lineno, f"{node.module}.{a.name}") for a in node.names]
    return found


def _third_party(path):
    top = path.split(".")[0]
    return top not in sys.stdlib_module_names and top not in _local_modules()


def _distribution_for(path):
    best = None
    for prefix in IMPORT_TO_DIST:
        if path == prefix or path.startswith(prefix + "."):
            if best is None or len(prefix) > len(best):
                best = prefix
    return IMPORT_TO_DIST.get(best)


def _declared():
    declared = {}
    with open(os.path.join(WORKSPACE, "requirements.txt"), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", line)
            assert m, line
            declared[_canonical(m.group(1))] = m.group(3).strip()
    return declared


def test_every_runtime_import_is_declared():
    declared = _declared()
    unknown, missing = [], []
    for name, line, path in _imports():
        if not _third_party(path):
            continue
        dist = _distribution_for(path)
        if dist is None:
            unknown.append(f"{name}:{line} {path}")
        elif _canonical(dist) not in declared:
            missing.append(f"{name}:{line} {path} -> {dist}")
    assert not unknown, f"imports with no IMPORT_TO_DIST entry (add the entry and the requirement): {unknown}"
    assert not missing, f"imports whose distribution mcp-servers/workspace/requirements.txt does not declare: {missing}"


def test_the_scan_sees_function_level_imports():
    """Not vacuous: the approval record's lazy firestore import (the 10-28 gap) and uvicorn's __main__ import are
    both found and resolved."""
    paths = {p for _, _, p in _imports()}
    assert "google.cloud.firestore" in paths
    assert "uvicorn" in paths
    assert _distribution_for("google.cloud.firestore") == "google-cloud-firestore"
    assert _distribution_for("google.auth.transport.requests.AuthorizedSession") == "google-auth"
    assert _distribution_for("google.cloud.storage") is None   # the namespace alone never matches a sibling


def test_firestore_pin_matches_the_other_services():
    pins = {}
    for group in ("apps", "mcp-servers"):
        for svc in sorted(os.listdir(os.path.join(REPO_ROOT, group))):
            req = os.path.join(REPO_ROOT, group, svc, "requirements.txt")
            if os.path.isfile(req) and svc != "workspace":
                with open(req, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.split("#", 1)[0].strip()
                        if _canonical(re.split(r"[<>=!~\[\s;]", line, 1)[0]) == "google-cloud-firestore":
                            pins[f"{group}/{svc}"] = line
    assert pins, "no other service declares google-cloud-firestore"
    assert len(set(pins.values())) == 1, pins
    assert "google-cloud-firestore" + _declared()["google-cloud-firestore"] == next(iter(pins.values()))


@pytest.mark.parametrize("prefix,dist", sorted(IMPORT_TO_DIST.items()))
def test_table_entries_match_installed_metadata(prefix, dist):
    """The table itself is checked against package metadata where the distribution is installed locally: the
    distribution really ships the import path."""
    try:
        files = distribution(dist).files or []
    except PackageNotFoundError:
        pytest.skip(f"{dist} not installed in this environment")
    rel = prefix.replace(".", "/")
    assert any(str(f).startswith(rel + "/") or str(f) == rel + ".py" for f in files), (prefix, dist)

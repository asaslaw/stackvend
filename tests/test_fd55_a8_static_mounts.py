"""FD55-A8-CONVERT (owner 10-27): the deploy adds `<dir>/.gitkeep` to its workspace copy only when the code really
mounts that directory, found with Python's parser by the gateway's own FD-55 W5 rule (G21), instead of the substring
test `'StaticFiles' in code and 'static' in code` on each `main.py`.

One rule, three byte-identical copies of shared/static_mounts.py (root, gateway image, terraform MCP image): the
gateway's enforce_container_contract and the terraform MCP's prepare_workspace both call static_placeholder_files.
Only the deploy workspace copy is affected (nothing is committed back, FD55-W6b). Hermetic: prepare_workspace into
tmp_path (no backend, no subprocess, no network)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import filecmp
import inspect
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from fd4g_support import load_tf_service  # noqa: E402
from shared import static_mounts as SM  # noqa: E402

PID = "shopx"
COPIES = ("apps/orchestrator-gateway/shared/static_mounts.py", "mcp-servers/terraform/shared/static_mounts.py")

MOUNT = ("from fastapi import FastAPI\nfrom fastapi.staticfiles import StaticFiles\napp = FastAPI()\n"
         "app.mount('/static', StaticFiles(directory='static'), name='static')\n")
IMPORT_ONLY = "from fastapi import FastAPI\nfrom fastapi.staticfiles import StaticFiles\napp = FastAPI()\n"
NO_MOUNT = "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/health')\ndef health():\n    return {'ok': True}\n"


# ------------------------------------------------------------------------------------------------ one rule
@pytest.mark.parametrize("copy", COPIES)
def test_replicas_are_byte_identical(copy):
    assert filecmp.cmp(os.path.join(REPO_ROOT, "shared", "static_mounts.py"), os.path.join(REPO_ROOT, copy),
                       shallow=False), copy


def test_gateway_uses_the_shared_rule():
    from developer_agent import handler as h
    assert h.static_mount_dirs.__module__ == "shared.static_mounts"
    assert h.static_placeholder_files.__module__ == "shared.static_mounts"
    src = inspect.getsource(h.enforce_container_contract)
    assert "static_placeholder_files(" in src


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


def test_terraform_server_uses_the_shared_rule_and_no_substring_test(tf):
    assert tf.static_placeholder_files.__module__ == "shared.static_mounts"
    src = inspect.getsource(tf.TerraformService.prepare_workspace)
    assert "self._add_static_mount_placeholders(workspace_dir)" in src
    assert "'StaticFiles' in" not in src and '"StaticFiles" in' not in src
    helper = inspect.getsource(tf.TerraformService._add_static_mount_placeholders)
    assert "static_placeholder_files(" in helper and "'StaticFiles' in" not in helper


@pytest.mark.parametrize("service_files,want", [
    ({"main.py": MOUNT}, ["static/.gitkeep"]),
    ({"main.py": MOUNT, "static/app.css": "x"}, []),                               # add-only: the dir has a file
    ({"main.py": IMPORT_ONLY}, []),                                                # import only
    ({"main.py": NO_MOUNT}, []),
    ({"main.py": "# app.mount('/s', StaticFiles(directory='static'))\n"}, []),     # a comment
    ({"main.py": "DOC = \"StaticFiles(directory='static')\"\n"}, []),              # a string
    ({"main.py": "StaticFiles(directory=STATIC_DIR)\n"}, []),                      # not a literal
    ({"routes/ui.py": "import fastapi.staticfiles as s\nm = s.StaticFiles(directory='assets/')\n"},
     ["assets/.gitkeep"]),                                                         # any .py, attribute form, normpath
    ({"main.py": MOUNT, "notes.txt": "StaticFiles(directory='docs')"}, ["static/.gitkeep"]),   # only .py is parsed
    ({"main.py": "StaticFiles(directory='static/css')\nStaticFiles(directory='static')\n"},
     ["static/css/.gitkeep"]),                                                     # the first placeholder counts
])
def test_static_placeholder_files(service_files, want):
    assert SM.static_placeholder_files(service_files) == want


# ------------------------------------------------------------------------------------------------ deploy workspace
def _svc(tf, tmp_path):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    return svc


def _read_tree(ws):
    out = {}
    for root, _dirs, names in os.walk(ws):
        for n in names:
            p = os.path.join(root, n)
            if not os.path.islink(p):
                out[os.path.relpath(p, ws).replace(os.sep, "/")] = Path(p).read_bytes()
    return out


def _prepare(tf, tmp_path, files, trace):
    ws = _svc(tf, tmp_path).prepare_workspace(PID, trace, dict(files), region="us-central1")
    return _read_tree(ws)


def _committed(files):
    return {k: v.encode("utf-8") for k, v in files.items()}


TF = {"main.tf": 'locals {\n  a = "b"\n}\n'}


def test_positive_literal_mount_adds_the_placeholder_to_the_workspace(tf, tmp_path):
    files = {**TF, "apps/web/main.py": MOUNT}
    got = _prepare(tf, tmp_path, files, "trace-a8-pos")
    assert got == {**_committed(files), "apps/web/static/.gitkeep": b""}


def test_positive_non_static_literal_directory(tf, tmp_path):
    """The old rule only ever made `static/`; the AST rule adds the directory the code names."""
    files = {**TF, "apps/web/main.py": MOUNT.replace("directory='static'", "directory='public'")}
    got = _prepare(tf, tmp_path, files, "trace-a8-public")
    assert got == {**_committed(files), "apps/web/public/.gitkeep": b""}


@pytest.mark.parametrize("case,files", [
    ("no_mount", {**TF, "apps/api/main.py": NO_MOUNT}),
    ("import_only", {**TF, "apps/api/main.py": IMPORT_ONLY}),                      # old rule: added static/.gitkeep
    ("comment", {**TF, "apps/api/main.py": NO_MOUNT + "# StaticFiles(directory='static')\n"}),
    ("string", {**TF, "apps/api/main.py": NO_MOUNT + "HELP = 'serve static via StaticFiles'\n"}),
    ("non_literal", {**TF, "apps/api/main.py": IMPORT_ONLY + "from pathlib import Path\n"
                     "app.mount('/s', StaticFiles(directory=Path(__file__).parent / 'static'))\n"}),
    ("dir_already_has_a_file", {**TF, "apps/api/main.py": MOUNT, "apps/api/static/index.html": "<p>hi</p>\n"}),
    ("unparseable", {**TF, "apps/api/main.py": "StaticFiles(directory='static'\n"}),
    # RT F1: ast.parse raises RecursionError on a pathologically nested file; the deploy must not stop
    ("too_deeply_nested", {**TF, "apps/api/main.py": "x = " + "1+" * 200000 + "1\n"}),
    ("root_import_only_beside_apps", {**TF, "main.py": IMPORT_ONLY, "apps/api/main.py": NO_MOUNT}),   # A3 + A8
    ("no_python_at_all", dict(TF)),
])
def test_negative_nothing_is_added_and_committed_files_are_byte_identical(tf, tmp_path, case, files):
    """Do No Harm: without a literal mount of a directory that holds no file, the workspace is exactly the commit."""
    got = _prepare(tf, tmp_path, files, f"trace-a8-{case.replace('_', '-')[:24]}")
    assert got == _committed(files), case


def test_root_main_py_that_really_mounts_beside_apps(tf, tmp_path):
    """A3 + A8 (FD55-W6a review F4): a committed root main.py beside apps/ gets a root placeholder only when it really
    mounts a literal directory (workspace copy only; the root is not packed when services exist). Its .py files under
    apps/ belong to the apps/<d> services, not to the root."""
    files = {**TF, "main.py": MOUNT, "apps/api/main.py": NO_MOUNT}
    got = _prepare(tf, tmp_path, files, "trace-a8-root")
    assert got == {**_committed(files), "static/.gitkeep": b""}


def test_root_does_not_parse_service_code_but_sees_its_files(tf, tmp_path):
    files = {**TF, "apps/api/main.py": MOUNT, "apps/api/static/a.css": "x\n"}
    got = _prepare(tf, tmp_path, files, "trace-a8-rootapps")
    assert got == _committed(files)        # neither the service (dir has a file) nor the root gets a placeholder


def test_unsafe_directory_is_skipped_not_raised(tf, tmp_path):
    """A file in the way of the mounted directory: logged and skipped, the workspace is the commit."""
    files = {**TF, "apps/api/main.py": MOUNT.replace("directory='static'", "directory='Procfile/x'"),
             "apps/api/Procfile": "web: uvicorn main:app\n"}
    got = _prepare(tf, tmp_path, files, "trace-a8-blocked")
    assert got == _committed(files)


def test_reserved_directories_are_not_walked(tf, tmp_path):
    svc = _svc(tf, tmp_path)
    ws = tmp_path / "ws"
    (ws / ".terraform" / "x").mkdir(parents=True)
    (ws / ".terraform" / "x" / "m.py").write_text(MOUNT)
    assert svc._add_static_mount_placeholders(str(ws)) == []
    assert not (ws / ".terraform" / "x" / "static").exists() and not (ws / "static").exists()

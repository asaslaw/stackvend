"""FD-4G Do-No-Harm (red-team H4): real platform output must pass the path guards unchanged.

1. Every key the deterministic synthesizer emits (each built-in module, plus all modules with the VPC) passes
   validate_relpath(reserved=TF_WORKSPACE_RESERVED), and each manifest goes through the REAL
   TerraformService.prepare_workspace twice (the second run is the workspace-reuse case, with platform-made
   symlinks present) with safe_join(ws, k) == os.path.join(ws, k) for every key.
2. Every BUILTIN_MODULE_FILES / built-in bundle payload key, as a workspace path, passes.
3. Every path-like string dict key in the existing test corpus passes (FD-4G's own attack tests excluded).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import os
import re
import socket
import sys
import tempfile
from unittest.mock import MagicMock

import pytest

from shared.path_safety import TF_WORKSPACE_RESERVED, UnsafePathError, safe_join, validate_relpath

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4G test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


def _synthesized_manifests():
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    from shared.express_synthesizer import ExpressHCLSynthesizer

    syn = ExpressHCLSynthesizer(db=None)
    mods = sorted(BUILTIN_MODULE_FILES)
    manifests = []
    for m in mods:
        files = syn.synthesize_workload(
            "dnh-" + m.replace("/", "-").replace("_", "-")[:20].strip("-"), "mock-stackvend-project",
            state_bucket="mock-castor-tfstate",
            module_instances=[{"module_id": m, "instance_name": "i1", "parameters": {}}], include_vpc=True)
        manifests.append((m, files))
    files = syn.synthesize_workload(
        "dnh-all", "mock-stackvend-project", state_bucket="mock-castor-tfstate",
        module_instances=[{"module_id": m, "instance_name": f"i{i}", "parameters": {}} for i, m in enumerate(mods)],
        include_vpc=True)
    manifests.append(("ALL", files))
    return mods, manifests


def test_synthesized_manifest_keys_pass_and_join_identically():
    mods, manifests = _synthesized_manifests()
    assert len(manifests) == len(mods) + 1
    total = 0
    rejected = []
    for name, files in manifests:
        for k in files:
            total += 1
            try:
                validate_relpath(k, reserved=TF_WORKSPACE_RESERVED)
            except UnsafePathError as e:
                rejected.append((name, k, e.reason))
    assert total > 500
    assert rejected == []


def test_synthesized_manifests_through_real_prepare_workspace_twice(monkeypatch):
    from fd4g_support import load_tf_service

    tfsvc = load_tf_service(monkeypatch)

    _, manifests = _synthesized_manifests()
    with tempfile.TemporaryDirectory() as base:
        svc = tfsvc.TerraformService(project_id="mock-stackvend-project", state_bucket="mock-castor-tfstate",
                                     workspace_base_dir=base, firestore_client=MagicMock())
        svc.db = None
        mismatches = []
        for name, files in manifests:
            pid = re.sub(r"[^a-z0-9-]", "-", name.lower()).strip("-")[:30].strip("-") or "x"
            ws1 = svc.prepare_workspace(pid, "dnh-trace", dict(files))
            ws2 = svc.prepare_workspace(pid, "dnh-trace", dict(files))  # reuse: platform symlinks now exist
            assert ws1 == ws2 == os.path.join(base, "dnh-trace", pid)
            for k in files:
                if safe_join(ws2, k, reserved=TF_WORKSPACE_RESERVED) != os.path.join(ws2, k):
                    mismatches.append((name, k))
        assert mismatches == []


def test_builtin_module_and_bundle_payload_keys_pass():
    from shared.builtin_bundles_payload import list_builtin_bundles
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES

    keys = [f"infra/modules/{mod}/{fname}" for mod, files in BUILTIN_MODULE_FILES.items() for fname in files]
    keys += [k for b in list_builtin_bundles() for k in b.hcl_files]
    keys += [f"infra/modules/{b.bundle_id}/{k}" for b in list_builtin_bundles() for k in b.hcl_files]
    assert len(keys) > 80
    for k in keys:
        assert validate_relpath(k, reserved=TF_WORKSPACE_RESERVED) == k


_PATHLIKE = re.compile(
    r"\.(tf|py|txt|json|yml|yaml|md|tfvars|toml|cfg|sh|js|ts|tsx|html|css)$|(^|/)(Procfile|\.python-version|\.gitignore)$")
# FD-4G's own tests intentionally contain attack keys.
# files whose dict keys are unsafe ON PURPOSE (they test the rejection of unsafe keys)
_EXCLUDED = {"test_path_safety.py", "test_step1_f11_f12_routing.py",
             "test_provenance_cleanup_matrix.py"}   # PROVENANCE-HISTORY: tests that a `..` record key is refused


def test_existing_test_corpus_dict_keys_pass():
    files = []
    for root in ["tests", "mcp-servers/terraform", "apps/orchestrator-gateway", "apps/git-server", "apps/qa-runner"]:
        for r, ds, fs in os.walk(os.path.join(REPO_ROOT, root)):
            if "shared" in r.split(os.sep) or "__pycache__" in r:
                continue
            files += [os.path.join(r, f) for f in fs
                      if f.startswith("test") and f.endswith(".py") and f not in _EXCLUDED and not f.startswith("test_fd4g_")]
    n = 0
    bad = []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) and _PATHLIKE.search(k.value):
                        n += 1
                        try:
                            validate_relpath(k.value, reserved=TF_WORKSPACE_RESERVED)
                        except UnsafePathError as e:
                            bad.append((os.path.relpath(f, REPO_ROOT), k.value, e.reason))
    assert n > 300
    assert bad == []

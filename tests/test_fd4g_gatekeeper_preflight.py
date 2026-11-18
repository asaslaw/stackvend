"""FD-4G: gatekeeper compile_in_memory / verify_and_cure (T5, H5), preflight (T6), handler pre-commit gate.

The verify_and_cure golden (``tests/fixtures/fd4g_gatekeeper_golden.json``) was produced by the PRE-FD-4G
verifier from ``main`` (scratch script, see docs/implemented/fd-4g-implementation-notes.md), so "valid manifests
behave identically" is measured against the old code.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json
import os
import posixpath
import socket
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

from gatekeeper_agent.verifier import SynthesisVerifierAgent  # noqa: E402
from shared.path_safety import UnsafePathError  # noqa: E402

GOLDEN_PATH = os.path.join(REPO_ROOT, "tests", "fixtures", "fd4g_gatekeeper_golden.json")

# Valid multi-service manifest (key shapes from plan section 7).
VALID_MANIFEST = {
    "apps/api/main.py": (
        "import os\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get('/items')\n"
        "def items():\n    return {'region': os.getenv('REGION', 'us-central1')}\n"
    ),
    "apps/api/requirements.txt": "fastapi\nuvicorn\n",
    "apps/web/main.py": "from flask import Flask\n\napp = Flask(__name__)\n\n\n@app.route('/')\ndef index():\n    return 'ok'\n",
    "apps/web/requirements.txt": "flask\ngunicorn\n",
    "infra/workload/main.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n',
    "infra/workload/variables.tf": 'variable "project_id" {\n  type = string\n}\n',
    ".github/workflows/deploy-golden.yml": "name: deploy\non: [push]\njobs: {}\n",
    ".gitignore": "__pycache__/\n",
    "README.md": "# golden\n",
}

SYNTAX_ERROR_MANIFEST = {"apps/api/main.py": "def broken(:\n    pass\n"}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4G test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


@pytest.fixture()
def pinned_tmp(monkeypatch):
    """Pin tempfile.tempdir to a scratch dir so 'nothing written outside' is observable."""
    outer = tempfile.mkdtemp(prefix="fd4g-gk-")
    scratch = os.path.join(outer, "tmp")
    os.makedirs(scratch)
    monkeypatch.setattr(tempfile, "tempdir", scratch)
    yield outer
    import shutil

    shutil.rmtree(outer, ignore_errors=True)


def _listing(root):
    out = set()
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            out.add(os.path.relpath(os.path.join(dirpath, n), root))
    return out


def _summarize(cured, passed, errors):
    return {
        "passed": passed,
        "errors": errors,
        "files": {k: hashlib.sha256(v.encode("utf-8")).hexdigest() for k, v in sorted(cured.items())},
    }


# ---------------------------------------------------------------- compile_in_memory (T5)

@pytest.mark.parametrize("key", ["../x.py", "../../escape.py", "/abs.py", "a//b.py", "./a.py"])
def test_compile_in_memory_bad_key_is_error_and_writes_nothing_outside(pinned_tmp, key):
    before = _listing(pinned_tmp)
    ok, errors = SynthesisVerifierAgent("app").compile_in_memory({key: "x = 1\n", "apps/api/ok.py": "y = 2\n"})
    assert ok is False
    assert any(repr(key) in e for e in errors)
    assert _listing(pinned_tmp) == before


def test_compile_in_memory_valid_manifest_unchanged():
    ok, errors = SynthesisVerifierAgent("app").compile_in_memory(VALID_MANIFEST)
    assert (ok, errors) == (True, [])


def test_compile_in_memory_syntax_error_message_text_unchanged():
    ok, errors = SynthesisVerifierAgent("app").compile_in_memory(SYNTAX_ERROR_MANIFEST)
    assert ok is False and len(errors) == 1
    assert errors[0].startswith("Syntax/Compilation Error in 'apps/api/main.py': ")
    assert "SyntaxError" in errors[0] or "invalid syntax" in errors[0]


# ---------------------------------------------------------------- verify_and_cure (H5)

@pytest.mark.parametrize("key", ["../x.py", ".git/config", ".GIT/hooks/pre-commit", "apps/x/.git/config", "/abs.py"])
def test_verify_and_cure_returns_failed_and_never_raises(pinned_tmp, key):
    files = {key: "x = 1\n", "apps/api/main.py": "print(1)\n"}
    before = _listing(pinned_tmp)
    cured, passed, errors = SynthesisVerifierAgent("app").verify_and_cure(files, product_id="app")
    assert passed is False
    assert len(errors) == 1 and "unsafe path key" in errors[0] and repr(key) in errors[0]
    assert cured == files  # returned unchanged, key not silently dropped
    assert _listing(pinned_tmp) == before


# Lane 19 L19-5a (FD-4I): the golden compute-cloudrun module gained an invoker validation block and a private-service
# precondition. Pin that these blocks are the ONLY change: removing them reproduces the pre-lane-19 bytes.
_L19_VALIDATION_START = "\n\n  # StackVend FD-4I (lane 19 L19-5a): exact \"<kind>:<value>\" members only."
_L19_PRECONDITION_START = "\n\n  # StackVend FD-4I (lane 19 L19-5a): a private service with zero invokers fails at plan"


def _l19_pre_5a(rel, text):
    start = _L19_VALIDATION_START if rel.endswith("variables.tf") else _L19_PRECONDITION_START
    assert text.count(start) == 1, rel
    i = text.index(start)
    end_marker = "\n  }\n}\n" if rel.endswith("variables.tf") else "\n    }\n  }\n"
    j = text.index(end_marker, i) + len(end_marker)
    tail = "\n}\n" if rel.endswith("variables.tf") else "\n"
    return text[:i] + tail + text[j:]


def _l19_compute_cloudrun_hashes(expected_hashes):
    """{relpath under infra/modules/compute-cloudrun: new sha256}, after checking pre-5a bytes == the golden hash."""
    out = {}
    for fn, old_hash in expected_hashes.items():
        with open(os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun", fn), encoding="utf-8") as fh:
            new = fh.read()
        # Integration: the file also carries the lane 14 PR-0b CMEK insertion; strip it first (each exactly once).
        from pr0b_module_deltas import pre_pr0b
        from fd4cs_b_module_delta import pre_fd4cs_b   # FD-4CS-b: the IAP service agent block, exactly once
        from push_private_module_delta import pre_push_private   # PUSH-TO-PRIVATE: the push identity grants
        rel = f"infra/modules/compute-cloudrun/{fn}"
        from visible_rename_render import pre_visible_rename   # visible-rename-3: the header comment only
        from iap_known_member_render import pre_iap_known_member   # IAP-GATE-KNOWN-MEMBER: the module's own lines
        from google_cloud_project_env_delta import pre_google_cloud_project_env   # CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV
        new_pre = pre_google_cloud_project_env(rel, new)
        pre = _l19_pre_5a(fn, pre_pr0b(rel, pre_fd4cs_b(rel, pre_visible_rename(pre_push_private(rel, pre_iap_known_member(rel, new_pre))))))
        assert hashlib.sha256(pre.encode("utf-8")).hexdigest() == old_hash, fn
        out[fn] = hashlib.sha256(new.encode("utf-8")).hexdigest()
    return out


def test_verify_and_cure_valid_manifest_matches_pre_fd4g_golden():
    with open(GOLDEN_PATH, encoding="utf-8") as fh:
        golden = json.load(fh)
    cured, passed, errors = SynthesisVerifierAgent("golden").verify_and_cure(dict(VALID_MANIFEST), product_id="golden")
    # Step 2 S2-A (register HS-09): the HB-29 branches of enforce_container_contracts are deleted, so the golden's
    # platform-written Procfiles are gone and both main.py files stay byte-identical to the input (no /health
    # injection, no `import os` prepend). Everything else must still match the pre-FD-4G golden exactly.
    expected = json.loads(json.dumps(golden["valid"]))
    for svc in ("api", "web"):
        expected["files"].pop(f"apps/{svc}/Procfile")
        expected["files"][f"apps/{svc}/main.py"] = hashlib.sha256(
            VALID_MANIFEST[f"apps/{svc}/main.py"].encode("utf-8")).hexdigest()
        # FD-4AD: the HB-28 rewrite (9 prepended base pins) is deleted; both files already name every proven need
        # (fastapi / flask is not in the closed-world catalog), so they stay byte-identical to the input.
        expected["files"][f"apps/{svc}/requirements.txt"] = hashlib.sha256(
            VALID_MANIFEST[f"apps/{svc}/requirements.txt"].encode("utf-8")).hexdigest()
    # FD-4AZ (owner scope A, D5 10-16): the vendored foundation variables.tf now defaults firestore_delete_protection
    # to true. Pin that this is the ONLY change to that file: swapping the FD-4AZ block back reproduces the golden hash.
    fvars = "infra/modules/workload-foundation/base/variables.tf"
    with open(os.path.join(REPO_ROOT, fvars), encoding="utf-8") as fh:
        new_vars = fh.read()
    fd4az_block = (
        'variable "firestore_delete_protection" {\n'
        '  description = "Enable delete protection on the workload Firestore database (FD-4AZ: on by default). '
        'Set false explicitly only for an ephemeral workload."\n'
        '  type        = bool\n  default     = true\n}\n')
    pre_fd4az_block = ('variable "firestore_delete_protection" {\n'
                       '  description = "Enable delete protection on the Firestore database"\n'
                       '  type        = bool\n  default     = false\n}\n')
    assert new_vars.count(fd4az_block) == 1
    # FD-4AT-c: the module also gained exactly the github_repository_id input (tests/fd4atc_render.py).
    from fd4atc_render import MODULE_VARIABLE_BLOCK
    assert new_vars.count(MODULE_VARIABLE_BLOCK) == 1
    from visible_rename_render import pre_visible_rename   # visible-rename-3: the header comment only
    # FD-4CI-b-R1-WIF: and exactly the github_default_branch input (tests/r1_wif_render.py).
    from r1_wif_render import MODULE_VARIABLE_BLOCK as R1_WIF_BLOCK, without_r1_wif
    assert new_vars.count(R1_WIF_BLOCK) == 1
    # GHA-DEPLOY-SWITCH: and exactly the enable_github_actions_deploy input (tests/gha_switch_render.py).
    from gha_switch_render import without_gha_switch
    pre_vars = without_r1_wif(pre_visible_rename(without_gha_switch("variables.tf", new_vars))).replace(
        fd4az_block, pre_fd4az_block).replace(MODULE_VARIABLE_BLOCK, "", 1)
    assert hashlib.sha256(pre_vars.encode("utf-8")).hexdigest() == expected["files"][fvars]
    expected["files"][fvars] = hashlib.sha256(new_vars.encode("utf-8")).hexdigest()
    # Lane 14 PR-0b: the vendored compute-cloudrun / foundation files gained only the CMEK inputs (null defaults) and
    # the foundation gained compliance.tf. Removing exactly those insertions reproduces the golden hash
    # (compute-cloudrun: together with the lane 19 L19-5a blocks, below).
    from pr0b_module_deltas import NEW_FILES, PR0B_INSERTIONS, pre_pr0b, sha256
    for path in PR0B_INSERTIONS:
        if path.startswith("infra/modules/compute-cloudrun/"):
            continue
        with open(os.path.join(REPO_ROOT, path), encoding="utf-8") as fh:
            now = fh.read()
        assert sha256(pre_pr0b(path, pre_visible_rename(now))) == expected["files"][path], path
        expected["files"][path] = sha256(now)
    for path in NEW_FILES:
        with open(os.path.join(REPO_ROOT, path), encoding="utf-8") as fh:
            expected["files"][path] = sha256(fh.read())
    cr = {fn: expected["files"][f"infra/modules/compute-cloudrun/{fn}"] for fn in ("main.tf", "variables.tf")}
    for fn, h in _l19_compute_cloudrun_hashes(cr).items():
        expected["files"][f"infra/modules/compute-cloudrun/{fn}"] = h
    # FD-4AT (owner 10-20): the vendored foundation iam.tf / wif.tf changed only in the CI deployer grants and the WIF
    # provider (real-parser diff against these pre-FD-4AT fixtures in tests/test_fd4at_ci_least_privilege.py).
    for fn in ("iam.tf", "wif.tf"):
        path = f"infra/modules/workload-foundation/base/{fn}"
        with open(os.path.join(REPO_ROOT, "tests", "fixtures", "fd4at", f"pre_fd4at_{fn}.txt"), encoding="utf-8") as fh:
            assert hashlib.sha256(fh.read().encode("utf-8")).hexdigest() == expected["files"][path], path
        with open(os.path.join(REPO_ROOT, path), encoding="utf-8") as fh:
            expected["files"][path] = hashlib.sha256(fh.read().encode("utf-8")).hexdigest()
    # FD-55 W5 (plan G23, register FD55-W5): the verifier's container-contract twin is deleted, so verify_and_cure no
    # longer writes `.python-version` pins or removes Dockerfiles (handler.enforce_container_contract, run on every
    # assembled tree, is the one rule). Every other file still matches the golden.
    for path in [p for p in expected["files"] if p not in VALID_MANIFEST and p.endswith(".python-version")]:
        expected["files"].pop(path)
    for path, text in VALID_MANIFEST.items():
        if path not in expected["files"] and posixpath.basename(path).lower().startswith("dockerfile"):
            expected["files"][path] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    # VISIBLE-RENAME (owner 10-26): the platform-written package inits changed only in the comment's product name.
    from visible_rename_render import pre_visible_rename
    for path, text in cured.items():
        if path.endswith("__init__.py") and path not in VALID_MANIFEST:
            assert hashlib.sha256(pre_visible_rename(text).encode("utf-8")).hexdigest() == expected["files"][path], path
            expected["files"][path] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    # visible-rename-3 (owner 10-26): vendored golden-module files changed only in their header comment.
    for path, text in cured.items():
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if path.startswith("infra/modules/") and expected["files"].get(path) not in (None, h):
            # GHA-DEPLOY-SWITCH: the foundation outputs.tf also changed only in its three deployer / WIF outputs
            # (tests/gha_switch_render.py undoes exactly those edits).
            base = (without_gha_switch("outputs.tf", text)
                    if path == "infra/modules/workload-foundation/base/outputs.tf" else text)
            assert pre_visible_rename(base) != base, path
            assert hashlib.sha256(pre_visible_rename(base).encode("utf-8")).hexdigest() == expected["files"][path], path
            expected["files"][path] = h
    # FD-55 W8 (register FD55-W8): module vendoring is add-only and archetype-free. The manifest calls only
    # ../modules/compute-cloudrun, so exactly that module's files are added; the foundation module it does not call
    # is no longer vendored with it (the pre-W8 cure rewrote / added every foundation file on any missing module).
    foundation = [p for p in expected["files"] if p.startswith("infra/modules/workload-foundation/")]
    assert foundation and not [p for p in cured if p.startswith("infra/modules/workload-foundation/")]
    for path in foundation:
        expected["files"].pop(path)
    assert _summarize(cured, passed, errors) == expected


def test_gatekeeper_contract_keys_pass_git_reserved():
    """Keys the developer stage's container contract generates (FD-55 W5: handler.enforce_container_contract, the one
    rule; the verifier twin is deleted) are valid manifest keys."""
    from shared.path_safety import GIT_RESERVED, validate_relpath
    from developer_agent.handler import enforce_container_contract

    src = {"apps/api/main.py": ("from fastapi import FastAPI\nfrom fastapi.staticfiles import StaticFiles\n"
                                "app = FastAPI()\napp.mount('/s', StaticFiles(directory='static'))\n"),
           "apps/web/main.py": "print(1)\n", "infra/workload/main.tf": "", "README.md": ""}
    out = dict(src)
    enforce_container_contract(out, "rt-app", "cloudrun")
    assert set(out) - set(src)  # it did generate keys
    for k in out:
        assert validate_relpath(k, reserved=GIT_RESERVED) == k


# ---------------------------------------------------------------- preflight (T6)
# FD-55 W1 (register FD55-W1): preflight_validator.run_compiler_preflight_check had no production caller and is
# DELETED with its two cases; the production compiler gate is V1b (tests/test_fd55_w1_dead_code.py).


# ---------------------------------------------------------------- gateway request boundary (T5)

@pytest.fixture()
def gw_main(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    import importlib.util

    # Hermetic import: no project -> no Firestore / Vertex clients are constructed at import time.
    for k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    spec = importlib.util.spec_from_file_location("fd4g_gw_main", os.path.join(GW_DIR, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_gateway_verify_request_rejects_unsafe_keys_422(gw_main):
    from fastapi.testclient import TestClient

    c = TestClient(gw_main.app)
    for key in ["../x.py", ".git/config", "/abs.py", "a\\b.py"]:
        r = c.post("/agent/gatekeeper/verify", json={"trace_id": "tr-1", "product_id": "app", "files": {key: "x = 1\n"}})
        assert r.status_code == 422, (key, r.text)
        assert "unsafe path" in r.text


def test_gateway_verify_request_model_accepts_legit_manifest(gw_main):
    # FD-4F QA-5 / row 19g (lane 13): trace_id is required on the gatekeeper request.
    req = gw_main.GatekeeperVerifyRequest(trace_id="tr-1", product_id="app", files=dict(VALID_MANIFEST))
    assert req.files == VALID_MANIFEST
    assert gw_main.GatekeeperVerifyRequest(trace_id="tr-1", product_id="app").files is None


def test_gateway_unsafe_path_handler_maps_to_400(gw_main):
    from fastapi.testclient import TestClient

    @gw_main.app.get("/__fd4g_probe")
    def _probe():
        raise UnsafePathError("../x", "non-canonical component '..'")

    r = TestClient(gw_main.app).get("/__fd4g_probe")
    assert r.status_code == 400
    assert r.json() == {"detail": "unsafe path: non-canonical component '..'"}


# ---------------------------------------------------------------- handler pre-commit gate (H5)

def test_handler_precommit_gate_raises_runtime_error_on_unsafe_key():
    from developer_agent import handler as h

    agent = h.DeveloperAgent.__new__(h.DeveloperAgent)
    agent.db = None
    agent.project_id = ""  # no Firestore client construction (hermetic)
    agent.vcs_provider = "GITHUB"
    with patch.object(agent, "get_full_repo_name", return_value="castor-org/castor-app", create=True), \
         patch.object(agent, "fetch_github_token", side_effect=AssertionError("must not reach commit"), create=True):
        with pytest.raises(RuntimeError, match="Gatekeeper pre-commit verification failed"):
            agent.commit_and_open_pr(
                "app", {".git/config": "[core]\n", "apps/api/main.py": "print(1)\n"}, branch_name="feature/x")


if __name__ == "__main__" and "--regen" in sys.argv:
    # Run against the PRE-FD-4G verifier only (see implementation notes); never regenerate from post-fix code.
    _cured, _passed, _errors = SynthesisVerifierAgent("golden").verify_and_cure(dict(VALID_MANIFEST), product_id="golden")
    with open(GOLDEN_PATH, "w", encoding="utf-8") as _fh:
        json.dump({"valid": _summarize(_cured, _passed, _errors)}, _fh, indent=1, sort_keys=True)
        _fh.write("\n")
    print("wrote", GOLDEN_PATH)

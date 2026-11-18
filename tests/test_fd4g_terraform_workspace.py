"""FD-4G: Terraform MCP workspace path safety (T1-T4, tooling relocation).

The golden snapshot (``tests/fixtures/fd4g_workspace_golden.json``) was captured from ``main`` BEFORE the
FD-4G fix, so "byte-identical workspace for legitimate manifests" is measured, not asserted.
Regenerate only deliberately: ``python tests/test_fd4g_terraform_workspace.py --regen``.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json
import os
import sys
import tempfile
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
GOLDEN_PATH = os.path.join(REPO_ROOT, "tests", "fixtures", "fd4g_workspace_golden.json")


_STATE = {}


@pytest.fixture(autouse=True)
def _isolated_tf_service(monkeypatch):
    """Load the REAL TF service.py (by path) with real web-stack modules, restored after each test."""
    from fd4g_support import load_tf_service

    _STATE["svc"] = load_tf_service(monkeypatch)
    yield
    _STATE.pop("svc", None)


def _import_service():
    if "svc" in _STATE:
        return _STATE["svc"]
    # --regen (script) path only
    if TF_DIR not in sys.path:
        sys.path.insert(0, TF_DIR)
    sys.modules.pop("service", None)
    import service  # noqa: E402

    return service


# A representative, static manifest covering every generated key shape class (FD-4G plan section 7).
REPRESENTATIVE_MANIFEST = {
    "infra/workload/main.tf": (
        'module "compute" {\n'
        '  source     = "../modules/compute-cloudrun"\n'
        "  project_id = var.project_id\n"
        "  region     = var.region\n"
        '  service_name = "golden-app-api"\n'
        "}\n"
    ),
    "infra/workload/variables.tf": (
        'variable "project_id" {\n  type = string\n}\n\n'
        'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n'
    ),
    "infra/workload/outputs.tf": 'output "service_uri" {\n  value = module.compute.service_uri\n}\n',
    "infra/workload/terraform.tfvars": 'region = "us-central1"\n',
    "infra/workload/.terraform.lock.hcl": "# lock file placeholder\n",
    "infra/modules/compute-cloudrun/main.tf": (
        'resource "google_cloud_run_v2_service" "svc" {\n'
        "  name     = var.service_name\n"
        "  location = var.region\n"
        "  project  = var.project_id\n"
        "  template {\n    containers {\n      image = \"us-docker.pkg.dev/cloudrun/container/hello\"\n    }\n  }\n"
        "}\n"
    ),
    "infra/modules/compute-cloudrun/variables.tf": (
        'variable "project_id" {\n  type = string\n}\n'
        'variable "region" {\n  type = string\n}\n'
        'variable "service_name" {\n  type = string\n}\n'
    ),
    "infra/modules/compute-cloudrun/outputs.tf": 'output "service_uri" {\n  value = google_cloud_run_v2_service.svc.uri\n}\n',
    "apps/api/main.py": "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get('/')\ndef root():\n    return {'ok': True}\n",
    "apps/api/requirements.txt": "fastapi\nuvicorn\n",
    "apps/api/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
    "apps/api/.python-version": "3.12\n",
    "apps/api/Dockerfile": "FROM scratch\n",
    "Dockerfile": "FROM scratch\n",
    "main.py": "print('legacy root file, suppressed when apps/ exists')\n",
    ".gitignore": ".terraform/\n",
    "README.md": "# golden-app\n",
    "apps/web/app/[id]/page.tsx": "export default function Page() { return null }\n",
}


def _snapshot(base: str, trace_id: str) -> dict:
    """Return {relpath: {"file": sha256} | {"link": target}} for the trace dir, with base paths neutralised."""
    root = os.path.join(base, trace_id)
    base_forms = sorted({base, os.path.realpath(base)}, key=len, reverse=True)
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                target = os.readlink(full)
                for b in base_forms:
                    target = target.replace(b, "<BASE>")
                out[rel] = {"link": target}
            elif os.path.isfile(full):
                with open(full, "rb") as fh:
                    out[rel] = {"file": hashlib.sha256(fh.read()).hexdigest()}
            else:
                out[rel] = {"dir": True}
    return dict(sorted(out.items()))


def _prepare_twice(service_mod, base: str) -> dict:
    svc = service_mod.TerraformService(
        project_id="mock-stackvend-project",
        state_bucket="mock-castor-tfstate",
        workspace_base_dir=base,
        firestore_client=MagicMock(),
    )
    svc.db = None
    # Second call = workspace reuse (deterministic trace IDs such as auto-deploy are reused in prod).
    svc.prepare_workspace("golden-app", "auto-deploy", dict(REPRESENTATIVE_MANIFEST))
    svc.prepare_workspace("golden-app", "auto-deploy", dict(REPRESENTATIVE_MANIFEST))
    return _snapshot(base, "auto-deploy")


# Step 1 HS-08 extension (owner-approved 10-12): apply-time healers no longer edit golden module files, so the inert
# copies prepare_workspace mirrors from the top-level modules/ dir into apps/<svc>/ (made before the HA-31 alignment
# refreshes infra/modules) no longer inherit the golden-file healer output (`deletion_protection` / variable defaults
# injected into infra/modules/compute-cloudrun). The copies themselves are not golden paths, so the per-file chain still
# runs on them as before. Exactly these 8 entries move; everything else stays byte-identical to the pre-FD-4G
# measurement. These copies are inert (apps/<svc>/ is never a Terraform root).
HS08_EXT_EXPECTED = {
    **{f"golden-app/apps/{svc}/{p}": {"file": "aac5665dc3c58f8d5915897a0351e1c42f8a4876580543994b28ac6fb79b2d05"}
       for svc in ("api", "web") for p in ("main.tf", "modules/compute-cloudrun/main.tf")},
    **{f"golden-app/apps/{svc}/{p}": {"file": "2e979ad191109b18988f0dc0a75282f2366de132340daed4fef58c9ce86aa20f"}
       for svc in ("api", "web") for p in ("variables.tf", "modules/compute-cloudrun/variables.tf")},
}

# FD-4AE-c (#16b, proposed row FD4AE-6): prepare_workspace no longer mirrors top-level dirs into apps/<svc>/, so the
# inert copies of the top-level modules/ dir (hierarchical and flat, per service) are gone. Exactly these 16 entries
# disappear; nothing else moves.
FD4AE_C_REMOVED = sorted(
    [f"golden-app/apps/{svc}/{d}" for svc in ("api", "web") for d in ("modules", "modules/compute-cloudrun")]
    + [f"golden-app/apps/{svc}/{pre}{fn}" for svc in ("api", "web") for pre in ("", "modules/compute-cloudrun/")
       for fn in ("main.tf", "outputs.tf", "variables.tf")])

# Lane 11 code RT F2 (deleted `_ensure_default`, HB-08 / FD-4Z): prepare_workspace no longer injects a guessed default
# into a variable block without one, so the root `variable "project_id" { type = string }` stays as written (it used to
# gain `default = "golden-app-project-id"`; its value comes from terraform.tfvars at deploy). Exactly this entry moves;
# the file is now the manifest's variables.tf plus the unchanged `env_vars` auto-declaration, without the final newline.
L11_F2_EXPECTED = {
    "golden-app/infra/workload/variables.tf": {"file": "9584ff9e3ec796b3eef54e75f70a66bedad58e77e8b41bcca680b179fe9416a8"},
}


# FD-55 W6a (register FD55-W6a): prepare_workspace writes every file as committed. Exactly these 5 entries move, each
# to the bytes it was given: the three infra/workload/*.tf files (no output dedup / env_vars declaration / newline
# trim), the root `main.py` (A3: legacy root files are no longer dropped when apps/ exists) and the platform-written
# backend.tf (HB-10's newline trim used to drop its final newline too).
def _w6a_expected():
    sha = lambda t: {"file": hashlib.sha256(t.encode("utf-8")).hexdigest()}  # noqa: E731
    out = {f"golden-app/{k}": sha(REPRESENTATIVE_MANIFEST[k]) for k in
           ("infra/workload/main.tf", "infra/workload/outputs.tf", "infra/workload/variables.tf", "main.py")}
    out["golden-app/backend.tf"] = sha('terraform {\n  required_version = ">= 1.5.0"\n  backend "gcs" {\n'
                                       '    bucket = "mock-castor-tfstate"\n    prefix = "workloads/golden-app"\n'
                                       '  }\n}\n')
    return out


# FD-55 W6d (register FD55-W6b+W6d, HS-42): a vendored golden module is applied as committed; the HA-31 refresh to the
# platform payload (A30) is deleted. The manifest's deliberately old compute-cloudrun copy (3 files) now reaches the
# workspace as given (reported as PLATFORM.VENDORED_MODULE_STALE). Exactly these 3 entries move (the payload has no
# other compute-cloudrun file, so the deleted refresh added none).
def _w6d_expected():
    def sha(t):
        return {"file": hashlib.sha256(t.encode("utf-8")).hexdigest()}
    return {f"golden-app/{k}": sha(REPRESENTATIVE_MANIFEST[k]) for k in REPRESENTATIVE_MANIFEST
            if k.startswith("infra/modules/compute-cloudrun/")}


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


def test_representative_manifest_workspace_matches_pre_fd4g_golden():
    service_mod = _import_service()
    with open(GOLDEN_PATH, "r", encoding="utf-8") as fh:
        golden = json.load(fh)
    assert set(HS08_EXT_EXPECTED) <= set(golden) and set(L11_F2_EXPECTED) <= set(golden)
    golden.update(HS08_EXT_EXPECTED)
    golden.update(L11_F2_EXPECTED)
    # Lane 14 PR-0b: the refreshed golden compute-cloudrun files gained only the null-default CMEK input; removing
    # exactly that insertion (and the lane 19 L19-5a blocks, below) reproduces the golden hash.
    from pr0b_module_deltas import PR0B_INSERTIONS, pre_pr0b, sha256
    for path in PR0B_INSERTIONS:
        key = f"golden-app/{path}"
        if key in golden and not path.startswith("infra/modules/compute-cloudrun/"):
            with open(os.path.join(REPO_ROOT, path), encoding="utf-8") as fh:
                now = fh.read()
            from visible_rename_render import pre_visible_rename   # visible-rename-3: header comments only
            assert sha256(pre_pr0b(path, pre_visible_rename(now))) == golden[key]["file"], key
            golden[key] = {"file": sha256(now)}
    cr = {fn: golden[f"golden-app/infra/modules/compute-cloudrun/{fn}"]["file"] for fn in ("main.tf", "variables.tf")}
    for fn, h in _l19_compute_cloudrun_hashes(cr).items():
        golden[f"golden-app/infra/modules/compute-cloudrun/{fn}"] = {"file": h}
    assert len(FD4AE_C_REMOVED) == 16 and set(FD4AE_C_REMOVED) <= set(golden)
    for key in FD4AE_C_REMOVED:
        del golden[key]
    w6a = _w6a_expected()
    assert set(w6a) - {"golden-app/main.py"} <= set(golden) and "golden-app/main.py" not in golden
    golden.update(w6a)
    w6d = _w6d_expected()
    assert len(w6d) == 3 and set(w6d) <= set(golden)
    assert not [k for k in golden if k.startswith("golden-app/infra/modules/compute-cloudrun/") and k not in w6d]
    golden.update(w6d)
    with tempfile.TemporaryDirectory() as base:
        snap = _prepare_twice(service_mod, base)
        # visible-rename-3 (owner 10-26): vendored golden-module files changed only in their header comment; reverting
        # exactly that edit reproduces the golden hash, then the new bytes are expected.
        from visible_rename_render import pre_visible_rename
        for key, entry in list(golden.items()):
            if "/infra/modules/" in key and "file" in entry and snap.get(key) != entry:
                with open(os.path.join(base, "auto-deploy", key), encoding="utf-8") as fh:
                    text = fh.read()
                assert pre_visible_rename(text) != text, key
                assert hashlib.sha256(pre_visible_rename(text).encode("utf-8")).hexdigest() == entry["file"], key
                golden[key] = {"file": hashlib.sha256(text.encode("utf-8")).hexdigest()}
        assert snap == golden



def test_dockerfile_skip_still_applies_and_root_files_are_kept():
    """Dockerfiles are still dropped (invariant 4). FD-55 W6a (A3): the root main.py is written as committed even when
    apps/ exists (it used to be dropped)."""
    service_mod = _import_service()
    with tempfile.TemporaryDirectory() as base:
        snap = _prepare_twice(service_mod, base)
    assert "golden-app/Dockerfile" not in snap
    assert "golden-app/apps/api/Dockerfile" not in snap
    assert "golden-app/main.py" in snap
    assert "golden-app/apps/api/main.py" in snap


# ---------------------------------------------------------------- FD-4G attack tests (post-fix)

import importlib.util  # noqa: E402
import socket  # noqa: E402
import stat  # noqa: E402
from unittest.mock import patch  # noqa: E402

from shared.path_safety import UnsafePathError  # noqa: E402


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4G test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    # Provider pre-caching must never download in tests.
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlretrieve", MagicMock(side_effect=OSError("download blocked")))


def _svc(service_mod, base):
    svc = service_mod.TerraformService(
        project_id="mock-stackvend-project",
        state_bucket="mock-castor-tfstate",
        workspace_base_dir=base,
        firestore_client=MagicMock(),
    )
    svc.db = None
    return svc


def _listing(root):
    out = set()
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            out.add(os.path.relpath(os.path.join(dirpath, n), root))
    return out


@pytest.fixture()
def base(tmp_path):
    # FD-05 B-17: tests walk dirname(base) before/after; it must be private to the test. A bare TemporaryDirectory()
    # made that the shared system temp dir, so any concurrent process (e.g. a tofu plugin dir) flaked the test.
    d = tmp_path / "parent" / "base"
    d.mkdir(parents=True)
    yield str(d)


def test_traversal_key_rejected_atomically(base):
    svc = _svc(_import_service(), base)
    before = _listing(os.path.dirname(base))
    with pytest.raises(UnsafePathError):
        svc.prepare_workspace(
            "app", "t1", {"infra/workload/main.tf": "# ok\n", "../../terraform.rc": "provider_installation {}\n"}
        )
    # Nothing written anywhere: not the workspace, not the base's parent.
    assert _listing(os.path.dirname(base)) == before
    assert not os.path.exists(os.path.join(base, "t1"))


@pytest.mark.parametrize("key", [".terraform/providers/x", "terraform.d/plugins/x", "infra/workload/.terraform/x",
                                 ".git/config", "/abs.tf", "a//b.tf", "./a.tf"])
def test_tool_owned_and_noncanonical_keys_rejected(base, key):
    svc = _svc(_import_service(), base)
    with pytest.raises(UnsafePathError):
        svc.prepare_workspace("app", "t1", {key: "x"})
    assert not os.path.exists(os.path.join(base, "t1"))


@pytest.mark.parametrize("trace_id", [".castor-tooling", "../x", "..", "a/b", ""])
def test_bad_trace_ids_rejected(base, trace_id):
    svc = _svc(_import_service(), base)
    with pytest.raises(UnsafePathError):
        svc.prepare_workspace("app", trace_id, {"main.tf": ""})
    with pytest.raises(UnsafePathError):
        svc.apply_plan("app", trace_id, iac_engine="OPENTOFU")
    with pytest.raises(UnsafePathError):
        svc.check_drift("app", trace_id)


@pytest.mark.parametrize("product_id", ["../x", "..", "a/b", ""])
def test_bad_product_ids_rejected(base, product_id):
    svc = _svc(_import_service(), base)
    with pytest.raises(UnsafePathError):
        svc.prepare_workspace(product_id, "t1", {"main.tf": ""})
    with pytest.raises(UnsafePathError):
        svc.check_drift(product_id, "t1")
    with pytest.raises(UnsafePathError):
        svc.force_unlock(product_id=product_id, lock_id="1", trace_id="t1")


def test_trace_named_like_old_tooling_dir_is_harmless(base):
    """T3: trace 'plugin_mirror' used to BE the provider mirror; tooling now lives under .castor-tooling."""
    service_mod = _import_service()
    svc = _svc(service_mod, base)
    rc_path = svc._ensure_provider_mirror()
    mirror = os.path.join(svc.tooling_dir, "plugin_mirror")
    assert rc_path == os.path.join(base, ".castor-tooling", "terraform.rc")
    before = _listing(svc.tooling_dir)
    key = "hashicorp/google/6.35.0/linux_amd64/terraform-provider-google_v6.35.0"
    ws = svc.prepare_workspace("registry.opentofu.org", "plugin_mirror", {key: "not a provider"})
    assert ws == os.path.join(base, "plugin_mirror", "registry.opentofu.org")
    assert _listing(svc.tooling_dir) == before
    assert not os.path.exists(os.path.join(mirror, "registry.opentofu.org", key))


def test_h3_product_id_colliding_with_platform_symlink_rejected(base):
    svc = _svc(_import_service(), base)
    manifest_a = {
        "infra/workload/main.tf": 'module "m" {\n  source = "../modules/m"\n}\n',
        "infra/modules/m/main.tf": "# module m\n",
    }
    wa = svc.prepare_workspace("app-a", "auto-deploy", manifest_a)
    sibling = os.path.join(base, "auto-deploy", "modules")
    assert os.path.islink(sibling)  # platform-made link (FD23-18 debt, intentionally kept)
    snap_before = _snapshot(base, "auto-deploy")
    with open(os.path.join(wa, "infra/modules/m/main.tf")) as fh:
        module_before = fh.read()
    with pytest.raises(UnsafePathError):
        svc.prepare_workspace("modules", "auto-deploy", {"main.tf": "# product B\n"})
    assert _snapshot(base, "auto-deploy") == snap_before
    with open(os.path.join(wa, "infra/modules/m/main.tf")) as fh:
        assert fh.read() == module_before


def test_tampered_rc_restored_exact_and_read_only(base):
    svc = _svc(_import_service(), base)
    rc_path = svc._ensure_provider_mirror()
    with open(rc_path) as fh:
        expected = fh.read()
    assert stat.S_IMODE(os.stat(rc_path).st_mode) == 0o444
    os.chmod(rc_path, 0o644)
    with open(rc_path, "w") as fh:
        # Keeps the substring the pre-FD-4G check looked for, so only an exact compare catches it.
        # FD-4AQ W1b: the registry fallback is `direct { include = [...] }`; swap it for an unrestricted mirror.
        assert expected.count("  direct {\n") == 1
        fh.write(expected.replace("  direct {\n", '  network_mirror {\n    url = "https://evil.invalid/"\n'))
    assert svc._ensure_provider_mirror() == rc_path
    with open(rc_path) as fh:
        assert fh.read() == expected
    assert stat.S_IMODE(os.stat(rc_path).st_mode) == 0o444
    assert 'path = "%s"' % os.path.join(base, ".castor-tooling", "plugin_mirror") in expected


def test_rc_unchanged_is_not_rewritten(base):
    service_mod = _import_service()
    svc = _svc(service_mod, base)
    rc_path = svc._ensure_provider_mirror()
    with patch.object(service_mod.os, "replace") as rep:
        svc._ensure_provider_mirror()
    rep.assert_not_called()
    assert os.path.isfile(rc_path)


def test_rc_write_failure_fails_closed_before_tofu(base):
    service_mod = _import_service()
    svc = _svc(service_mod, base)
    with patch.object(svc, "_ensure_binary", return_value="tofu"), \
         patch.object(service_mod.os, "replace", side_effect=OSError("read-only fs")), \
         patch.object(service_mod.subprocess, "Popen") as run:
        with pytest.raises(OSError):
            svc._run_subprocess(["tofu", "version"], cwd=base, iac_engine="OPENTOFU")
    run.assert_not_called()


def test_rc_missing_after_ensure_fails_closed(base):
    service_mod = _import_service()
    svc = _svc(service_mod, base)
    with patch.object(svc, "_ensure_binary", return_value="tofu"), \
         patch.object(svc, "_ensure_provider_mirror", return_value=os.path.join(base, "nope.rc")), \
         patch.object(service_mod.subprocess, "Popen") as run:
        with pytest.raises(RuntimeError, match="provider mirror CLI config missing"):
            svc._run_subprocess(["tofu", "version"], cwd=base, iac_engine="OPENTOFU")
    run.assert_not_called()


def test_run_subprocess_sets_cli_config_negative(base):
    service_mod = _import_service()
    svc = _svc(service_mod, base)
    fake = MagicMock(returncode=0, communicate=MagicMock(return_value=("ok", "")))
    with patch.object(svc, "_ensure_binary", return_value="tofu"), \
         patch.object(service_mod.subprocess, "Popen", return_value=fake) as run:
        res = svc._run_subprocess(["tofu", "version"], cwd=base, iac_engine="OPENTOFU")
    assert res["success"] is True
    env = run.call_args.kwargs["env"]
    assert env["TF_CLI_CONFIG_FILE"] == os.path.join(base, ".castor-tooling", "terraform.rc")
    assert env["TF_PLUGIN_CACHE_DIR"] == os.path.join(base, ".castor-tooling", "plugin_cache")


def test_rc_write_concurrent_cold_start(base):
    """R-1: concurrent first tofu runs on a fresh instance must not race on a shared rc temp file."""
    import threading

    service_mod = _import_service()
    expected = None
    for trial in range(10):
        tbase = os.path.join(base, f"trial{trial}")
        os.makedirs(tbase)
        svcs = [_svc(service_mod, tbase) for _ in range(8)]
        barrier = threading.Barrier(len(svcs))
        errors, results = [], []

        def worker(svc):
            try:
                barrier.wait()
                results.append(svc._ensure_provider_mirror())
            except BaseException as exc:  # noqa: BLE001 - collected and asserted below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(s,)) for s in svcs]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        rc_path = os.path.join(tbase, ".castor-tooling", "terraform.rc")
        assert results == [rc_path] * len(svcs)
        with open(rc_path) as fh:
            content = fh.read()
        assert 'path = "%s"' % os.path.join(tbase, ".castor-tooling", "plugin_mirror") in content
        normalised = content.replace(tbase, "<BASE>")
        assert expected is None or normalised == expected
        expected = normalised
        assert stat.S_IMODE(os.stat(rc_path).st_mode) == 0o444
        assert [n for n in os.listdir(os.path.dirname(rc_path)) if n.endswith(".tmp")] == []
    # Exact content matches a single-threaded write.
    solo = os.path.join(base, "solo")
    os.makedirs(solo)
    with open(_svc(service_mod, solo)._ensure_provider_mirror()) as fh:
        assert fh.read().replace(solo, "<BASE>") == expected


def test_provider_copy_failure_warns_and_tofu_still_runs(base, caplog):
    """R-2: provider mirror copy/download failures stay warnings; the rc write still fails closed."""
    import logging

    service_mod = _import_service()
    svc = _svc(service_mod, base)
    if TF_DIR not in sys.path:
        sys.path.insert(0, TF_DIR)
    import binary_checksums as bc  # the module _ensure_provider_mirror imports (PROVIDER-CHECKSUMS copy primitive)
    for arch in ("amd64", "arm64"):
        src = os.path.join(svc.tooling_dir, "plugin_mirror", "registry.terraform.io", "hashicorp", "google",
                           "6.35.0", f"linux_{arch}")
        os.makedirs(src)
        with open(os.path.join(src, "terraform-provider-google_v6.35.0_x5"), "wb") as fh:
            fh.write(b"verified google\n")
        # a verified copy this process installed, so the second registry copies it instead of downloading
        svc.__dict__.setdefault("_provider_bins_verified", {})[src] = bc.record_provider_files(
            src, {"terraform-provider-google_v6.35.0_x5": hashlib.sha256(b"verified google\n").hexdigest()})
    fake = MagicMock(returncode=0, communicate=MagicMock(return_value=("ok", "")))
    with caplog.at_level(logging.WARNING), \
         patch.object(svc, "_ensure_binary", return_value="tofu"), \
         patch.object(bc, "copy_verified_provider", side_effect=OSError("ENOSPC")) as copy2, \
         patch.object(service_mod.subprocess, "Popen", return_value=fake) as run:
        res = svc._run_subprocess(["tofu", "version"], cwd=base, iac_engine="OPENTOFU")
    assert copy2.called
    assert res["success"] is True
    run.assert_called()
    assert any("ENOSPC" in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records)
    # The rc block is outside the warning try: a write failure still aborts before tofu.
    os.chmod(os.path.join(svc.tooling_dir, "terraform.rc"), 0o644)
    os.remove(os.path.join(svc.tooling_dir, "terraform.rc"))
    with patch.object(svc, "_ensure_binary", return_value="tofu"), \
         patch.object(service_mod.os, "replace", side_effect=OSError("read-only fs")), \
         patch.object(service_mod.subprocess, "Popen") as run2:
        with pytest.raises(OSError, match="read-only fs"):
            svc._run_subprocess(["tofu", "version"], cwd=base, iac_engine="OPENTOFU")
    run2.assert_not_called()
    assert [n for n in os.listdir(svc.tooling_dir) if n.endswith(".tmp")] == []


# ---------------------------------------------------------------- HTTP / MCP / applier boundaries

def _load_tf_module(monkeypatch, base, filename, modname):
    # main.py imports its sibling validate_service (Step 1 S1-B): the terraform server directory must be importable
    # whether or not an earlier test file left it on sys.path (order-independent; failed when run alone)
    monkeypatch.syspath_prepend(TF_DIR)
    service_mod = _import_service()
    real_cls = service_mod.TerraformService

    def factory(*a, **k):
        k.setdefault("workspace_base_dir", base)
        k.setdefault("firestore_client", MagicMock())
        inst = real_cls(*a, **k)
        inst.db = None
        return inst

    monkeypatch.setattr(service_mod, "TerraformService", factory)
    spec = importlib.util.spec_from_file_location(modname, os.path.join(TF_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(service_mod, "TerraformService", real_cls)
    return mod


@pytest.fixture()
def tf_main(monkeypatch, base):
    return _load_tf_module(monkeypatch, base, "main.py", "fd4g_tf_main")


@pytest.fixture()
def sent_callbacks(monkeypatch):
    import shared.callbacks as cb

    sent = []
    monkeypatch.setattr(cb.CallbackDeliveryClient, "send_callback",
                        staticmethod(lambda callback_url, payload, **kw: sent.append(dict(payload))))
    return sent


def test_plan_endpoint_rejects_bad_key_422(tf_main):
    from fastapi.testclient import TestClient

    tf_main.service.generate_plan = MagicMock()
    c = TestClient(tf_main.app)
    for key in ["../terraform.rc", ".terraform/x", "/abs.tf"]:
        r = c.post("/plan", json={"product_id": "app", "hcl_files": {key: ""}})
        assert r.status_code == 422, (key, r.text)
    r = c.post("/plan", json={"product_id": "../x", "hcl_files": {"main.tf": ""}})
    assert r.status_code == 422
    r = c.post("/plan", json={"product_id": "app", "trace_id": "../x", "hcl_files": {"main.tf": ""}})
    assert r.status_code == 422
    for path in ["/apply", "/drift-check"]:
        assert c.post(path, json={"product_id": "app", "trace_id": "../x"}).status_code == 422
    assert c.post("/force-unlock", json={"product_id": "../x", "lock_id": "1"}).status_code == 422
    assert c.post("/deploy", json={"product_id": "app", "hcl_files": {"../x": ""}}).status_code == 422
    assert c.post("/deploy-async", json={"product_id": "app", "callback_url": "http://x",
                                         "hcl_files": {"../x": ""}}).status_code == 422
    tf_main.service.generate_plan.assert_not_called()


def test_empty_trace_id_is_absent_but_bad_trace_id_rejected(tf_main):
    """R-3: routes treat trace_id "" as absent (derived trace); non-empty bad values still fail validation."""
    from pydantic import ValidationError

    assert tf_main.DeployRequest(product_id="a", trace_id="").trace_id == ""
    assert tf_main.ForceUnlockRequest(product_id="a", lock_id="1", trace_id="").trace_id == ""
    for bad in ["../x", ".castor-tooling", "a/b"]:
        with pytest.raises(ValidationError):
            tf_main.DeployRequest(product_id="a", trace_id=bad)
        with pytest.raises(ValidationError):
            tf_main.ForceUnlockRequest(product_id="a", lock_id="1", trace_id=bad)


def test_plan_endpoint_legit_request_passes_through(tf_main):
    from fastapi.testclient import TestClient

    tf_main.service.generate_plan = MagicMock(return_value={"status": "PLANNED"})
    c = TestClient(tf_main.app)
    r = c.post("/plan", json={"product_id": "app", "hcl_files": dict(REPRESENTATIVE_MANIFEST)})
    assert r.status_code == 200 and r.json() == {"status": "PLANNED"}
    tf_main.service.generate_plan.assert_called_once()
    # Legacy force-unlock route still accepts an empty body product_id (falls back to the path param).
    tf_main.service.force_unlock = MagicMock(return_value={"status": "UNLOCKED"})
    r = c.post("/api/workloads/app/force-unlock", json={"product_id": "", "lock_id": "1"})
    assert r.status_code == 200


def test_sink_raised_unsafe_path_maps_to_400(tf_main):
    from fastapi.testclient import TestClient

    c = TestClient(tf_main.app)
    tf_main.service.check_drift = MagicMock(side_effect=UnsafePathError("x", "symlink inside path"))
    r = c.post("/drift-check", json={"product_id": "app", "trace_id": "t1"})
    assert r.status_code == 400
    assert r.json() == {"detail": "unsafe path: symlink inside path"}


def test_mcp_terraform_plan_bad_key_returns_error_with_reason(tf_main, base):
    from fastapi.testclient import TestClient

    c = TestClient(tf_main.app)
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
        "name": "terraform_plan",
        "arguments": {"product_id": "app", "trace_id": "t1", "hcl_files": {"../../terraform.rc": "x"},
                      "iac_engine": "OPENTOFU"}}})
    body = r.json()
    assert "error" in body and "non-canonical component '..'" in body["error"]["message"]
    assert not os.path.exists(os.path.join(base, "t1"))


def test_deploy_async_fallback_bad_trace_no_rmtree_and_failed_callback(tf_main, sent_callbacks):
    req = tf_main.AsyncDeployRequest.model_construct(
        product_id="app", trace_id="../x", hcl_files=None, target_project_id=None, branch=None,
        callback_url="http://127.0.0.1:9/cb", iac_engine=None)
    with patch.object(tf_main, "trigger_tf_applier_job") as trig, patch("shutil.rmtree") as rm:
        with pytest.raises(UnsafePathError):
            tf_main.run_deploy_in_background(req)
    rm.assert_not_called()
    trig.assert_not_called()
    assert sent_callbacks and sent_callbacks[-1]["status"] == "FAILED"
    assert "UnsafePathError" in sent_callbacks[-1]["error"]


def test_deploy_async_fallback_legit_trace_cleans_only_its_trace_dir(tf_main, sent_callbacks, base):
    os.makedirs(os.path.join(base, "deploy-async-app", "app"))
    tf_main.service.deploy_workload = MagicMock(return_value={"status": "SUCCESS", "service_url": "https://x"})
    req = tf_main.AsyncDeployRequest(product_id="app", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)
    assert not os.path.exists(os.path.join(base, "deploy-async-app"))
    assert os.path.isdir(os.path.join(base, ".castor-tooling"))
    assert sent_callbacks[-1]["status"] == "SUCCESS"


def _patched_applier(monkeypatch, base, modname, deploy):
    applier = _load_tf_module(monkeypatch, base, "applier.py", modname)
    real_cls = applier.TerraformService

    def factory(*a, **k):
        inst = real_cls(*a, workspace_base_dir=base, firestore_client=MagicMock(), **k)
        inst.db = None
        inst.deploy_workload = deploy
        return inst

    monkeypatch.setattr(applier, "TerraformService", factory)
    for k in ("PRODUCT_ID", "TRACE_ID", "HCL_FILES_JSON", "TARGET_PROJECT_ID", "BRANCH"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CALLBACK_URL", "http://127.0.0.1:9/cb")
    monkeypatch.setattr(sys, "argv", ["applier.py"])  # run_job falls back to argv[1:3]
    return applier


@pytest.mark.parametrize("env", [
    {"PRODUCT_ID": "app", "TRACE_ID": "t1", "HCL_FILES_JSON": json.dumps({"../../terraform.rc": "x"})},
    {"PRODUCT_ID": "app", "TRACE_ID": "t1", "HCL_FILES_JSON": json.dumps({".terraform/x": "x"})},
    {"PRODUCT_ID": "app", "TRACE_ID": "../x"},
    {"PRODUCT_ID": "../x", "TRACE_ID": "t1"},
])
def test_applier_bad_input_sends_failed_callback_and_exits_nonzero(monkeypatch, base, sent_callbacks, env):
    deploy = MagicMock()
    applier = _patched_applier(monkeypatch, base, "fd4g_tf_applier", deploy)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises((UnsafePathError, SystemExit)) as ei:
        applier.run_job()
    if isinstance(ei.value, SystemExit):
        assert ei.value.code not in (0, None)
    deploy.assert_not_called()
    assert sent_callbacks and sent_callbacks[-1]["status"] == "FAILED"


def test_applier_legit_input_deploys(monkeypatch, base, sent_callbacks):
    deploy = MagicMock(return_value={"status": "SUCCESS", "service_url": "https://x"})
    applier = _patched_applier(monkeypatch, base, "fd4g_tf_applier_ok", deploy)
    monkeypatch.setenv("PRODUCT_ID", "app")
    monkeypatch.setenv("HCL_FILES_JSON", json.dumps({"infra/workload/main.tf": "# ok\n"}))
    with pytest.raises(SystemExit) as ei:
        applier.run_job()
    assert ei.value.code == 0
    assert deploy.call_args.kwargs["trace_id"] == "tf-applier-app"
    assert deploy.call_args.kwargs["hcl_files"] == {"infra/workload/main.tf": "# ok\n"}
    assert sent_callbacks[-1]["status"] == "SUCCESS"


if __name__ == "__main__" and "--regen" in sys.argv:
    sys.path.insert(0, REPO_ROOT)
    import shared  # noqa: F401,E402  (pin the root shared package, as tests/conftest.py does)

    _svc = _import_service()
    with tempfile.TemporaryDirectory() as _base:
        _snap = _prepare_twice(_svc, _base)
    os.makedirs(os.path.dirname(GOLDEN_PATH), exist_ok=True)
    with open(GOLDEN_PATH, "w", encoding="utf-8") as _fh:
        json.dump(_snap, _fh, indent=1, sort_keys=True)
        _fh.write("\n")
    print(f"wrote {len(_snap)} entries to {GOLDEN_PATH}")

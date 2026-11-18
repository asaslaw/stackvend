"""FD-4D-b (register row, owner 10-20): the deploy copies infra/workload/ files to the workspace by PATH (subdirectories
kept), never by basename, so a nested module's main.tf can never replace the root main.tf.

- direct children of infra/workload/ land at the workspace root exactly as before (legacy trees byte-identical);
- nested files land at their path below infra/workload/ (infra/workload/modules/db/main.tf -> modules/db/main.tf) and
  never replace a file the manifest already holds at that path;
- a nested file's local module sources that leave infra/workload/ are re-anchored by exact path arithmetic;
- typed-intent detection is unchanged (the intent is a direct child; its root copy is its path below infra/workload/).

Real deploy_workload / prepare_workspace with fakes only. Hermetic: no network, no GCP (one optional local-tofu check).
"""
import hermetic_guard  # noqa: F401  (first import: tests/hermetic_guard.py)

import json
import os
import shutil
import subprocess
import sys
import types
from unittest.mock import MagicMock

import pytest

W = "infra/workload/"
ROOT_TF = 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n'
ROOT_TF_FLAT = 'module "compute" {\n  source = "./infra/modules/compute-cloudrun"\n}\n'
VARS_TF = 'variable "project_id" {\n  type = string\n}\n'
OUT_TF = 'output "url" {\n  value = module.compute.service_uri\n}\n'
MODULE_TF = 'resource "null_resource" "db" {}\n'
MODULE_VARS_TF = 'variable "tier" {\n  type = string\n}\n'


class _StopAfterGuard(Exception):
    pass


@pytest.fixture
def tf(monkeypatch):
    from fd4g_support import load_tf_service

    return load_tf_service(monkeypatch)


def _svc(tf, tmp_path):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    return svc


def _no_gcp(monkeypatch):
    import google.auth
    import google.cloud

    def _no_client(*_a, **_k):
        raise RuntimeError("no Secret Manager in tests")

    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _no_client
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", _no_client, raising=False)


def _files_reaching_the_workspace(tf, monkeypatch, tmp_path, tree):
    """The manifest deploy_workload hands prepare_workspace for `tree` (nothing built, no tofu)."""
    svc = _svc(tf, tmp_path)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(tree))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: pytest.fail("tofu ran"))
    monkeypatch.setattr(svc, "_build_and_push_container", lambda *a, **k: True)
    seen = {}

    def _prep(_pid, _trace_id, hcl_files, *_a, **_k):
        seen["files"] = dict(hcl_files)
        raise _StopAfterGuard()

    monkeypatch.setattr(svc, "prepare_workspace", _prep)
    _no_gcp(monkeypatch)
    with pytest.raises(_StopAfterGuard):
        svc.deploy_workload(product_id="app", trace_id="t-fd4db", target_project_id="p-1", branch="main",
                            iac_engine="OPENTOFU")
    files = seen["files"]
    files.pop("terraform.tfvars", None)   # install-dependent values (pinned by the FD-4D tests)
    return files


# ------------------------------------------------------------------------------------------- pure helpers
@pytest.mark.parametrize("path,expected", [
    ("infra/workload/main.tf", "main.tf"),
    ("infra/workload/modules/db/main.tf", "modules/db/main.tf"),
    ("infra/workload/iac_intent.json", "iac_intent.json"),
    ("infra/workload/", None), ("infra/workloads/main.tf", None), ("infra/workload", None),
    ("main.tf", None), ("apps/infra/workload/main.tf", None), (None, None),
])
def test_workload_relpath_is_exact(tf, path, expected):
    assert tf.workload_relpath(path) == expected


def test_intent_root_copy_is_the_path_below_infra_workload(tf):
    assert tf.IAC_INTENT_ROOT_PATH == "iac_intent.json" == os.path.basename(tf.IAC_INTENT_REPO_PATH)


@pytest.mark.parametrize("value,expected", [
    ("../shared", None),                                      # stays inside infra/workload/: same relative layout
    ("./child", None),
    ("../../modules/x", None),                                # infra/workload/modules/x: inside
    ("../../../modules/storage-bucket", "../../infra/modules/storage-bucket"),   # infra/modules/storage-bucket
    ("../../../bundles/web", "../../infra/bundles/web"),
    ("../../../../shared-tf/m", "../../shared-tf/m"),        # a repository-root directory
    ("../../../../../outside", None),                         # leaves the repository: left as written
    ("../..", None),                                          # infra/workload itself (the root config)
    ("terraform-google-modules/network/google", None),        # registry / non-local
    ("git::https://example.com/m.git", None),
])
def test_nested_module_source_path_arithmetic(tf, value, expected):
    assert tf._nested_module_source(value, "infra/workload/modules/db/main.tf") == expected


def test_nested_rewrite_changes_only_escaping_sources_and_keeps_every_other_byte(tf):
    text = ('module "inner" {\n  source = "../shared"\n}\n\n'
            'module "golden" {\n  source     = "../../../modules/storage-bucket"\n  project_id = var.project_id\n}\n')
    out = tf.rewrite_flattened_module_sources(text, filename="x", nested_repo_path=W + "modules/db/main.tf")
    assert out == text.replace("../../../modules/storage-bucket", "../../infra/modules/storage-bucket")


def test_nested_rewrite_is_a_no_op_on_valid_inside_sources_and_unparseable_text(tf):
    """Do No Harm: a nested file whose sources all stay inside infra/workload/ (or that python-hcl2 cannot parse) is
    returned byte-identical (no regex fallback for nested files)."""
    inside = 'module "inner" {\n  source = "../shared"\n}\n'
    assert tf.rewrite_flattened_module_sources(inside, nested_repo_path=W + "modules/db/main.tf") == inside
    broken = 'module "x" {\n  source = "../../../modules/y"\n'   # unterminated block
    assert tf.rewrite_flattened_module_sources(broken, nested_repo_path=W + "modules/db/main.tf") == broken


# ------------------------------------------------------------------------------------------- the deploy copy
@pytest.mark.parametrize("nested_first", [True, False])
def test_nested_main_tf_never_replaces_the_root_main_tf(tf, monkeypatch, tmp_path, nested_first):
    nested = {W + "modules/db/main.tf": MODULE_TF, W + "modules/db/variables.tf": MODULE_VARS_TF}
    root = {W + "main.tf": ROOT_TF, W + "variables.tf": VARS_TF}
    tree = dict(**nested, **root) if nested_first else dict(**root, **nested)
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, tree)
    assert files["main.tf"] == ROOT_TF_FLAT and files["variables.tf"] == VARS_TF
    assert files["modules/db/main.tf"] == MODULE_TF and files["modules/db/variables.tf"] == MODULE_VARS_TF
    for k, v in tree.items():   # the repository files themselves are unchanged
        assert files[k] == v


def test_legacy_flat_tree_is_byte_identical(tf, monkeypatch, tmp_path):
    """Do No Harm (negative): a tree with only direct children of infra/workload/ gives exactly the dict (keys,
    values and key order) main handed prepare_workspace before FD-4D-b (same pin as the FD-4D test)."""
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        W + "main.tf": ROOT_TF, W + "variables.tf": VARS_TF, W + "outputs.tf": OUT_TF})
    # FD-4DT: plus the platform access var file ("{}": no access record), added by deploy_workload after the
    # repository files and flattened like them; every repository entry is unchanged.
    assert list(files.items()) == [
        (W + "main.tf", ROOT_TF), (W + "variables.tf", VARS_TF), (W + "outputs.tf", OUT_TF),
        (W + "stackvend-access.auto.tfvars.json", "{}"),
        ("main.tf", ROOT_TF_FLAT), ("variables.tf", VARS_TF), ("outputs.tf", OUT_TF),
        ("stackvend-access.auto.tfvars.json", "{}")]


def test_direct_child_still_replaces_a_same_named_repository_root_file(tf, monkeypatch, tmp_path):
    """Negative: the existing direct-child rule (infra/workload/ wins over a root file of the same name) is kept."""
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        "main.tf": 'terraform {}\n', W + "main.tf": ROOT_TF})
    assert files["main.tf"] == ROOT_TF_FLAT


def test_nested_copy_never_replaces_a_file_the_repository_holds_at_that_path(tf, monkeypatch, tmp_path):
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        W + "main.tf": ROOT_TF, "modules/db/main.tf": "# repository root module\n", W + "modules/db/main.tf": MODULE_TF})
    assert files["modules/db/main.tf"] == "# repository root module\n"
    assert files["main.tf"] == ROOT_TF_FLAT


K8S_YAML = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"


def test_nested_k8s_manifest_lands_in_the_workspace_k8s_dir(tf, monkeypatch, tmp_path):
    """Fable RT note: infra/workload/k8s/deployment.yaml now lands at k8s/deployment.yaml (before: at the root as
    deployment.yaml), so the post-GKE-apply step that applies the workspace's k8s/*.yaml applies it, exactly like a
    repository-root k8s/*.yaml. Byte-identical content."""
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        W + "main.tf": ROOT_TF, W + "k8s/deployment.yaml": K8S_YAML})
    assert files["k8s/deployment.yaml"] == K8S_YAML and "deployment.yaml" not in files


def test_repository_root_k8s_manifest_wins_over_a_nested_workload_copy(tf, monkeypatch, tmp_path):
    root_yaml = "apiVersion: v1\nkind: Service\nmetadata:\n  name: root\n"
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        W + "main.tf": ROOT_TF, "k8s/deployment.yaml": root_yaml, W + "k8s/deployment.yaml": K8S_YAML})
    assert files["k8s/deployment.yaml"] == root_yaml and files[W + "k8s/deployment.yaml"] == K8S_YAML


def test_nested_module_golden_source_is_re_anchored_in_the_copy_only(tf, monkeypatch, tmp_path):
    mod = 'module "bucket" {\n  source = "../../../modules/storage-bucket"\n}\n'
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        W + "main.tf": 'module "db" {\n  source = "./modules/db"\n}\n', W + "modules/db/main.tf": mod})
    assert files["main.tf"] == 'module "db" {\n  source = "./modules/db"\n}\n'          # inside: as written
    assert files["modules/db/main.tf"] == mod.replace("../../../modules/", "../../infra/modules/")
    assert files[W + "modules/db/main.tf"] == mod                                       # repository copy as committed


def test_plural_workloads_nested_main_tf_is_not_merged_into_the_root(tf, monkeypatch, tmp_path):
    """infra/workloads/ (plural): a nested main.tf is no longer treated as the root main.tf (HB-15 merge). FD55-W6e:
    beside a root config from infra/workload/ a plural file is never dropped silently (typed stop,
    tests/test_fd55_w6e_legacy_apply.py); as the only root config every plural file is copied to its path."""
    nested_mod = 'resource "google_storage_bucket" "nested" {\n  name = "n"\n}\n'
    # nested listed first: before FD-4D-b it became the root main.tf and the real root was merged into custom.tf
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, {
        "infra/workloads/modules/x/main.tf": nested_mod, "infra/workloads/main.tf": ROOT_TF})
    assert files["main.tf"] == ROOT_TF_FLAT and files["modules/x/main.tf"] == nested_mod
    assert "custom.tf" not in files


# ------------------------------------------------------------------------------------------- typed intent
_INTENT = json.dumps({"schema": "iac_intent/v1", "modules": [
    {"module": "storage-bucket", "name": "uploads", "args": {"bucket_name_suffix": "uploads"}}]})
_RENDER = json.dumps({"module": {"uploads": {"source": "../modules/storage-bucket"}}}, indent=2) + "\n"
_TOPOLOGY = json.dumps({"schema": "service_topology/v1", "intent": {
    "services": [{"name": "shop", "kind": "cloudrun"}], "primary_service": "shop", "edges": [], "resources": []}})


def _intent_tree():
    return {W + "main.tf": ROOT_TF, W + "iac_intent.json": _INTENT, W + "custom.tf.json": _RENDER,
            W + "topology.json": _TOPOLOGY}


def test_intent_workspace_is_still_detected(tf, monkeypatch, tmp_path):
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, _intent_tree())
    assert files["iac_intent.json"] == _INTENT and files["custom.tf.json"] == _RENDER
    assert tf.files_have_iac_intent(files) and tf.iac_intent_state(files) == "intent"
    ws = tmp_path / "ws"
    for rel in ("iac_intent.json", "custom.tf.json"):
        ws.joinpath(rel).parent.mkdir(parents=True, exist_ok=True)
        ws.joinpath(rel).write_text(files[rel])
    assert tf.workspace_has_iac_intent(str(ws))


def test_a_nested_intent_file_never_becomes_the_root_intent(tf, monkeypatch, tmp_path):
    """Before FD-4D-b a nested infra/workload/**/iac_intent.json was copied over the root intent; now it stays at its
    path and the workspace's intent is the real one."""
    tree = dict(_intent_tree(), **{W + "examples/iac_intent.json": "{not an intent"})
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path, tree)
    assert files["iac_intent.json"] == _INTENT and files["examples/iac_intent.json"] == "{not an intent"
    assert tf.iac_intent_state(files) == "intent"


def test_apply_report_maps_a_nested_copy_to_its_repository_path(tf, tmp_path):
    vjson = json.dumps({"diagnostics": [
        {"severity": "error", "summary": "Bad", "range": {"filename": "modules/db/main.tf", "start": {"line": 1}}},
        {"severity": "error", "summary": "Bad", "range": {"filename": "main.tf", "start": {"line": 1}}},
        {"severity": "error", "summary": "Bad", "range": {"filename": "infra/modules/m/main.tf",
                                                          "start": {"line": 1}}}]})
    manifest = {W + "main.tf", "main.tf", W + "modules/db/main.tf", "modules/db/main.tf", "infra/modules/m/main.tf"}
    rep = tf.apply_validation_report(vjson, str(tmp_path), manifest_paths=manifest)
    assert [d["file"] for d in rep["diagnostics"]] == [W + "modules/db/main.tf", W + "main.tf",
                                                        "infra/modules/m/main.tf"]


# ------------------------------------------------------------------------------------------- engine check
# The eval harness's pinned production engine (OpenTofu 1.9.0), preferred when present on this machine.
PINNED_TOFU = os.environ.get("STACKVEND_PINNED_TOFU", "")  # the production tofu 1.9.0 when set; else the local tofu


def _tofu():
    if os.path.isfile(PINNED_TOFU) and os.access(PINNED_TOFU, os.X_OK):
        return PINNED_TOFU
    return shutil.which("tofu") or ("/opt/homebrew/bin/tofu" if os.path.exists("/opt/homebrew/bin/tofu") else None)


def test_nested_module_tree_resolves_in_the_real_engine(tf, monkeypatch, tmp_path):
    """Engine check (local tofu, no providers, no backend, no network): the workspace the deploy builds from a root
    main.tf + nested module + golden module resolves every module and validates."""
    tofu = _tofu()
    if not tofu:
        pytest.skip("needs a local tofu")
    tree = {W + "main.tf": 'module "db" {\n  source = "./modules/db"\n}\noutput "v" {\n  value = module.db.v\n}\n',
            W + "modules/db/main.tf": 'module "g" {\n  source = "../../../modules/g"\n}\n'
                                      'output "v" {\n  value = module.g.v\n}\n',
            "infra/modules/g/main.tf": 'output "v" {\n  value = "ok"\n}\n'}
    files = _files_reaching_the_workspace(tf, monkeypatch, tmp_path / "a", tree)
    ws = tmp_path / "ws"
    for rel, text in files.items():
        if rel.endswith(".tf"):
            ws.joinpath(rel).parent.mkdir(parents=True, exist_ok=True)
            ws.joinpath(rel).write_text(text)
    env = dict(os.environ, TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1", TF_INPUT="0")
    init = subprocess.run([tofu, "init", "-backend=false", "-no-color"], cwd=ws, capture_output=True, text=True,
                          timeout=120, env=env)
    assert init.returncode == 0, init.stderr
    val = subprocess.run([tofu, "validate", "-no-color"], cwd=ws, capture_output=True, text=True, timeout=120, env=env)
    assert val.returncode == 0, val.stderr

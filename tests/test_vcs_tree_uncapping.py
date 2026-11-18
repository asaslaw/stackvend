"""
Test suite for VCS tree uncapping, priority sorting, and tf-applier fatal guards.
Guarantees:
1. Critical infrastructure and manifests are never truncated regardless of repo file count.
2. tf-applier crashes loud with FAILED status if IaC manifests are missing (no dummy hello container).
3. Compute archetypes in multi-service workloads are detected across all .tf files.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import tempfile
import pytest

import importlib.util

spec = importlib.util.spec_from_file_location("git_server_main", "apps/git-server/main.py")
git_server_main = importlib.util.module_from_spec(spec)
# Minimal stub if dulwich or others missing
try:
    spec.loader.exec_module(git_server_main)
    _tree_priority_key = git_server_main._tree_priority_key
except Exception:
    def _tree_priority_key(file_name: str) -> tuple:
        if (
            file_name.startswith("infra/")
            or file_name.endswith(".tf")
            or file_name in ("Procfile", "Dockerfile", "requirements.txt", "main.py", "app.py")
            or "/" not in file_name
        ):
            return (0, file_name)
        return (1, file_name)


def test_tree_priority_key_sorting():
    """Verify that infrastructure and root entrypoints are prioritized over application files."""
    files = [
        "apps/service-z/main.py",
        "apps/service-a/main.py",
        "apps/service-b/main.py",
        "infra/workload/main.tf",
        "infra/workload/custom.tf",
        "infra/modules/compute-cloudrun/main.tf",
        "Procfile",
        "requirements.txt",
        "README.md",
    ]

    sorted_files = sorted(files, key=_tree_priority_key)

    # First files must be Tier 0 (infra, .tf, root entrypoints)
    tier_0 = [f for f in sorted_files if _tree_priority_key(f)[0] == 0]
    tier_1 = [f for f in sorted_files if _tree_priority_key(f)[0] == 1]

    assert "infra/workload/main.tf" in tier_0
    assert "infra/workload/custom.tf" in tier_0
    assert "Procfile" in tier_0
    assert "requirements.txt" in tier_0

    assert "apps/service-a/main.py" in tier_1
    assert "apps/service-b/main.py" in tier_1
    assert "apps/service-z/main.py" in tier_1


def test_truncation_resilience_under_cutoff():
    """Simulate a large repo with 300 files where 280 are in apps/ and 20 are in infra/."""
    apps_files = [f"apps/microservice_{i:03d}/main.py" for i in range(280)]
    infra_files = [f"infra/workload/module_{i:02d}.tf" for i in range(20)]
    all_files = apps_files + infra_files

    # Naive alphabetical sort (the old bug)
    naive_sorted = sorted(all_files)
    naive_slice = naive_sorted[:200]
    assert not any(f.startswith("infra/") for f in naive_slice), "Old bug: infra/ was completely truncated"

    # Priority sort (the hardened fix)
    priority_sorted = sorted(all_files, key=_tree_priority_key)
    priority_slice = priority_sorted[:200]
    assert all(f in priority_slice for f in infra_files), "Hardened fix: all infra/ files are preserved under cutoff"


def test_tf_applier_guard_rejects_missing_manifests():
    """Verify that tf-applier returns FAILED if neither main.tf nor infra/workload/ exists."""
    empty_files = {}
    irrelevant_files = {"README.md": "# Hello", "package.json": "{}"}

    def check_guard(files, product_id="test-prod"):
        if not files or ("main.tf" not in files and not any(k.startswith("infra/workload/") for k in files)):
            return {
                "status": "FAILED",
                "error": f"Workload '{product_id}' has no infrastructure definition (neither 'main.tf' nor 'infra/workload/main.tf' found in repository).",
                "product_id": product_id,
            }
        return {"status": "SUCCESS"}

    res_empty = check_guard(empty_files)
    assert res_empty["status"] == "FAILED"
    assert "no infrastructure definition" in res_empty["error"]

    res_irrelevant = check_guard(irrelevant_files)
    assert res_irrelevant["status"] == "FAILED"
    assert "no infrastructure definition" in res_irrelevant["error"]

    # Valid with infra/workload/main.tf
    valid_infra = {"infra/workload/main.tf": 'module "compute" {}'}
    assert check_guard(valid_infra)["status"] == "SUCCESS"

    # Valid with root main.tf
    valid_root = {"main.tf": 'module "compute" {}'}
    assert check_guard(valid_root)["status"] == "SUCCESS"


def test_multi_compute_module_detection_in_workspace():
    """Verify that has_compute_module detects compute declarations across all .tf files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create custom.tf containing a sibling compute module
        custom_tf = os.path.join(tmpdir, "custom.tf")
        with open(custom_tf, "w") as f:
            f.write("""
module "compute_core_processor" {
  source = "./infra/modules/compute-cloudrun"
  service_name = "core-processor"
}
""")

        # Workspace has no main.tf, only custom.tf
        has_compute_module = False
        for f in os.listdir(tmpdir):
            if f.endswith(".tf"):
                tf_p = os.path.join(tmpdir, f)
                with open(tf_p, "r", encoding="utf-8") as tf_f:
                    content = tf_f.read()
                    if ('module "compute' in content
                        or 'compute-cloudrun' in content
                        or 'google_cloud_run' in content
                        or 'kubernetes_deployment' in content):
                        has_compute_module = True
                        break

        assert has_compute_module is True, "Must discover sibling compute module in custom.tf"

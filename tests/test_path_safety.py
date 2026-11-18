"""FD-4G: shared/path_safety.py helper contract, attack matrix, Do-No-Harm and replica parity."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import filecmp
import glob
import os
import tempfile

import pytest

from shared.path_safety import (
    GIT_RESERVED,
    TF_WORKSPACE_RESERVED,
    UnsafePathError,
    safe_join,
    validate_manifest_keys,
    validate_path_component,
    validate_product_id,
    validate_relpath,
    validate_trace_id,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Review section 6.1: the 16 classic attack strings.
ATTACKS = [
    "../x", "a/../../x", "/etc/passwd", "..", ".", "", "a//b", "./a", "a/", "x/..",
    "C:\\x", "C:x", "\\\\host\\s", "..\\x", "a\x00b", "//host/share/x",
]

LEGIT_KEYS = [
    "infra/workload/main.tf",
    ".gitignore",
    ".python-version",
    ".github/workflows/deploy-x.yml",
    "apps/web/app/[id]/page.tsx",
    "apps/api/my file.py",
    "a..b/c",
    "...hidden",
    "apps/\u00e9t\u00e9/main.py",
    "%2e%2e/x",
    "\uff0e\uff0e/x",
    "infra/workload/.terraform.lock.hcl",
    "a.git/x",
    ".gitkeep",
]


@pytest.fixture()
def base():
    with tempfile.TemporaryDirectory() as d:
        yield d


# ---------------------------------------------------------------- attacks

@pytest.mark.parametrize("key", ATTACKS)
def test_attack_strings_rejected(base, key):
    with pytest.raises(UnsafePathError):
        validate_relpath(key)
    with pytest.raises(UnsafePathError):
        safe_join(base, key)


@pytest.mark.parametrize("key", [None, 1, b"a", ["a"], {"a": 1}])
def test_non_string_rejected(base, key):
    with pytest.raises(UnsafePathError):
        validate_relpath(key)


def test_unsafe_path_error_is_value_error_with_fields():
    with pytest.raises(ValueError) as ei:
        validate_relpath("../x")
    assert ei.value.value == "../x"
    assert "'..'" in ei.value.reason


@pytest.mark.parametrize("key", [".git/config", ".GIT/config", "apps/x/.git/config", ".Git", "a/.git"])
def test_git_reserved_components_rejected(base, key):
    with pytest.raises(UnsafePathError):
        safe_join(base, key, reserved=GIT_RESERVED)
    # Without the reserved set the key is a structurally valid relpath.
    assert validate_relpath(key) == key


@pytest.mark.parametrize("key", [".terraform/x", "terraform.d/x", "infra/workload/.terraform/x",
                                 ".TERRAFORM/providers/x", ".git/config"])
def test_tf_workspace_reserved_components_rejected(base, key):
    with pytest.raises(UnsafePathError):
        safe_join(base, key, reserved=TF_WORKSPACE_RESERVED)


@pytest.mark.parametrize("key", [".gitignore", ".github/workflows/a.yml", ".terraform.lock.hcl",
                                 "a.git", "terraform.d.bak/x", "infra/terraform.tfvars"])
def test_reserved_is_whole_component_not_substring(base, key):
    assert safe_join(base, key, reserved=TF_WORKSPACE_RESERVED) == os.path.join(base, key)
    assert safe_join(base, key, reserved=GIT_RESERVED) == os.path.join(base, key)


def test_symlink_escape_rejected(base):
    os.symlink(os.path.dirname(base), os.path.join(base, "out"))
    with pytest.raises(UnsafePathError):
        safe_join(base, "out/x")


def test_key_resolving_to_base_rejected(base):
    os.symlink(".", os.path.join(base, "self"))
    with pytest.raises(UnsafePathError):
        safe_join(base, "self")


def test_no_key_rejected(base):
    with pytest.raises(UnsafePathError):
        safe_join(base)


def test_no_symlinks_rejects_symlinked_component(base):
    os.makedirs(os.path.join(base, "real"))
    os.symlink(os.path.join(base, "real"), os.path.join(base, "inl"))
    with pytest.raises(UnsafePathError):
        safe_join(base, "inl", "x", no_symlinks=True)


def test_manifest_validation_is_atomic_and_type_checked(base):
    with pytest.raises(UnsafePathError):
        validate_manifest_keys({"ok/a.tf": "", "../b.tf": ""})
    with pytest.raises(UnsafePathError):
        validate_manifest_keys(["a"])  # not a mapping
    assert validate_manifest_keys({"ok/a.tf": ""}) is None


@pytest.mark.parametrize("tid", ["..", ".", ".x", "a/b", "-a", "_a", "a" * 129, "", None, "a b", "a\\b", "a\x00"])
def test_trace_id_rejected(tid):
    with pytest.raises(UnsafePathError):
        validate_trace_id(tid)


@pytest.mark.parametrize("pid", ["a/b", "..", ".", "", None, "a\\b"])
def test_product_id_component_rejected(pid):
    with pytest.raises(UnsafePathError):
        validate_path_component(pid)


@pytest.mark.parametrize("pid", ["A", "-a", "a-", "a" * 64, 'a"b', "a_b", "a.b", "", None])
def test_product_id_format_rejected(pid):
    with pytest.raises(UnsafePathError):
        validate_product_id(pid)


# ---------------------------------------------------------------- Do-No-Harm

@pytest.mark.parametrize("key", LEGIT_KEYS)
def test_legit_keys_return_exact_os_path_join(base, key):
    assert validate_relpath(key) == key
    assert safe_join(base, key) == os.path.join(base, key)


def test_in_base_symlink_accepted_by_default(base):
    os.makedirs(os.path.join(base, "real"))
    os.symlink(os.path.join(base, "real"), os.path.join(base, "inl"))
    assert safe_join(base, "inl/x") == os.path.join(base, "inl/x")


def test_symlinked_base_returns_unresolved_candidate():
    with tempfile.TemporaryDirectory() as d:
        real = os.path.join(d, "real")
        os.makedirs(real)
        link = os.path.join(d, "link")
        os.symlink(real, link)
        assert safe_join(link, "a/b.tf") == os.path.join(link, "a/b.tf")
        assert safe_join(link, "a", "b", no_symlinks=True) == os.path.join(link, "a", "b")


@pytest.mark.parametrize("tid", [
    "a" * 128,
    "3f2b6c1e-7d4a-4f59-9a2b-0c1d2e3f4a5b",
    "express-1760000000",
    "fastpath-abc123",
    "redeploy-my-app-1760000000",
    "deploy-async-my-app",
    "tf-applier-my-app",
    "force-unlock-my-app-1760000000",
    "qa-async-my-app",
    "sre-my-app-1760000000",
    "hitl-approved-my-app",
    "intake-abc",
    "auto-trace",
    "auto-deploy",
    "auto-qa-trace",
    "Trace.With_Dots-1",
])
def test_trace_id_generator_formats_accepted(tid):
    assert validate_trace_id(tid) == tid


def test_trace_id_uuid_generators_accepted():
    import uuid

    for _ in range(20):
        assert validate_trace_id(str(uuid.uuid4()))
        assert validate_trace_id(uuid.uuid4().hex)


@pytest.mark.parametrize("pid", ["a" * 63, "3d-render", "my-app", "a", "0"])
def test_product_id_format_accepted(pid):
    assert validate_product_id(pid) == pid
    assert validate_path_component(pid) == pid


@pytest.mark.parametrize("pid", ["o'brien & co", "My_App", "team.gitops"])
def test_product_id_component_check_is_structural_only(pid):
    # Structural check accepts IDs that fail the format allow-list (Q-1 phase 2 decides format at sinks).
    assert validate_path_component(pid) == pid


# ---------------------------------------------------------------- replica parity

PATH_SAFETY_COPIES = {
    "shared/path_safety.py",
    "mcp-servers/terraform/shared/path_safety.py",
    "apps/orchestrator-gateway/shared/path_safety.py",
    "apps/qa-runner/shared/path_safety.py",
    "apps/control-center/shared/path_safety.py",
    "apps/project-vending/shared/path_safety.py",
    "mcp-servers/github/shared/path_safety.py",
    "apps/git-server/shared/path_safety.py",
    "apps/spec-ingestion/shared/path_safety.py",   # RT14-37: Drive product ids
}

GITHUB_PROVIDER_COPIES = {
    "shared/providers/github_provider.py",
    "apps/control-center/shared/providers/github_provider.py",
    "apps/orchestrator-gateway/shared/providers/github_provider.py",
    "apps/project-vending/shared/providers/github_provider.py",
    "apps/qa-runner/shared/providers/github_provider.py",
    "mcp-servers/github/shared/providers/github_provider.py",
    "mcp-servers/terraform/shared/providers/github_provider.py",
}


def _assert_parity(expected: set, pattern: str):
    found = set(glob.glob(pattern, root_dir=REPO_ROOT, recursive=True))
    assert found == expected, f"unregistered or missing replicas: {sorted(found ^ expected)}"
    canonical = os.path.join(REPO_ROOT, sorted(p for p in expected if p.startswith("shared/"))[0])
    for rel in sorted(expected):
        assert filecmp.cmp(canonical, os.path.join(REPO_ROOT, rel), shallow=False), f"{rel} drifted from {canonical}"


def test_path_safety_replica_parity():
    _assert_parity(PATH_SAFETY_COPIES, "**/shared/path_safety.py")


def test_github_provider_replica_parity():
    _assert_parity(GITHUB_PROVIDER_COPIES, "**/shared/providers/github_provider.py")


def test_git_server_shared_is_a_package():
    assert os.path.isfile(os.path.join(REPO_ROOT, "apps", "git-server", "shared", "__init__.py"))

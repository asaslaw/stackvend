"""FD-55 W1 (register FD55-W1, owner 10-24): unused fixer code is deleted (duplicate-resource clean-up, label coercion,
depends_on insertion, a Python syntax "cure", three workflow sanitizers incl. the unused sanitize_pipeline_content in
every VCS provider copy). No production caller existed, so no workload output changes.

Tombstones (source read with `ast`, nothing executed), an over-deletion guard for the bodies that are still live (the
old HCL syntax checker U9 and the other apply-time hcl_utils mutators go with W6b; the terraform server's output strip
went with W6c, register FD55-W6c). FD-55 W6a (register FD55-W6a) deleted the terraform server's own workflow
sanitizer too, so the idempotence / expression-integrity cases that ran on it are gone and the mutant guard below now
covers service.py.
Hermetic."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

HCL_UTILS_COPIES = [
    "shared/hcl_utils.py",
    "apps/orchestrator-gateway/developer_agent/hcl_utils.py",
    "apps/orchestrator-gateway/shared/hcl_utils.py",
    "mcp-servers/terraform/hcl_utils.py",
    "mcp-servers/terraform/shared/hcl_utils.py",
]
SHARED_COPIES = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                 "apps/project-vending/shared", "apps/qa-runner/shared", "mcp-servers/github/shared",
                 "mcp-servers/terraform/shared"]
PROVIDER_FILES = {"vcs_provider.py": "VCSProvider", "providers/github_provider.py": "GitHubProvider",
                  "providers/serverless_git_provider.py": "ServerlessGitProvider"}

# U4-U8 (+ their private block-body helpers, which nothing else used)
HCL_UTILS_DELETED = {"deduplicate_semantic_hcl_resources", "deduplicate_semantic_hcl_blocks", "strip_hcl_resource_block",
                     "strip_hcl_data_block", "strip_hcl_provider_block", "coerce_hcl_metadata_maps",
                     "_ensure_resource_depends_on", "_extract_resource_target_identifier", "_extract_block_body_at"}
# still there (the read-only parser helpers): W1 must not take them. The apply-time mutators that W1 left (U1-U3, U9)
# were deleted by FD-55 W6b and the locals pair (U2) when W6b + W6c merged (tests/test_fd55_w6bd_no_writeback.py).
HCL_UTILS_LIVE = {"find_hcl_parser_binary", "hcl_parse_errors"}
# X1 + X7 (and the helpers / constant only they used)
PV_DELETED = {"strip_hcl_output", "strip_hcl_resource_type", "strip_hcl_resource_block",
              "deduplicate_semantic_hcl_resources", "_extract_resource_target_identifier", "_extract_block_body_at",
              "run_compiler_preflight_check", "PREFLIGHT_UNAVAILABLE"}
EVERY_DELETED = (HCL_UTILS_DELETED | PV_DELETED | {"extract_bespoke_custom_resources", "cure_syntax_errors",
                                                   "sanitize_pipeline_content", "sanitize_github_workflow",
                                                   "_deduplicate_env_block"})
# FD-55 W6c deleted the terraform server's apply-time output strip (strip_hcl_output with strip_invalid_hcl_blocks,
# its validate-error caller); FD-55 W6a its workflow sanitizer. Nothing deleted here is live elsewhere any more, so
# the mutant guard below covers service.py for every name.
LIVE_ELSEWHERE: set = set()


def _tree(rel):
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        return ast.parse(f.read())


def _top_level_names(rel):
    names = set()
    for node in _tree(rel).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return names


def _methods(rel, cls):
    for node in _tree(rel).body:
        if isinstance(node, ast.ClassDef) and node.name == cls:
            return {n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    raise AssertionError(f"class {cls} not found in {rel}")


def _imported_names(rel):
    return {a.asname or a.name for node in ast.walk(_tree(rel)) if isinstance(node, ast.ImportFrom)
            for a in node.names}


# ------------------------------------------------------------------------------------------------ U4-U8 (hcl_utils x5)
@pytest.mark.parametrize("rel", HCL_UTILS_COPIES)
def test_hcl_utils_dead_bodies_are_gone_and_live_ones_stay(rel):
    names = _top_level_names(rel)
    assert not HCL_UTILS_DELETED & names, HCL_UTILS_DELETED & names
    assert HCL_UTILS_LIVE <= names, HCL_UTILS_LIVE - names


# ------------------------------------------------------------------------------------------------ X1 / X7 / U10 (PV)
def test_preflight_copies_compiler_preflight_and_hcl_utils_imports_are_gone():
    rel = "apps/orchestrator-gateway/developer_agent/preflight_validator.py"
    names = _top_level_names(rel)
    assert not PV_DELETED & names, PV_DELETED & names
    assert not HCL_UTILS_DELETED & _imported_names(rel)
    assert "hydrate_kubernetes_manifests" in names  # the kept FD-4AF hydration


# ------------------------------------------------------------------------------------------------ X2 / X3 / X4 / X9
def test_hb03_hc15_and_the_gateway_workflow_sanitizer_are_gone():
    te = "apps/orchestrator-gateway/developer_agent/terraform_engine.py"
    assert "extract_bespoke_custom_resources" not in _top_level_names(te)
    init = "apps/orchestrator-gateway/developer_agent/__init__.py"
    assert "extract_bespoke_custom_resources" not in _imported_names(init)
    assert "cure_syntax_errors" not in _methods("apps/orchestrator-gateway/gatekeeper_agent/verifier.py",
                                                "SynthesisVerifierAgent")
    handler = "apps/orchestrator-gateway/developer_agent/handler.py"
    assert not {"sanitize_github_workflow", "_deduplicate_env_block"} & _top_level_names(handler)
    assert not os.path.exists(os.path.join(GATEWAY, "gatekeeper_agent", "ast_transformer.py"))


# ------------------------------------------------------------------------------------------------ X6 / U10 (service.py)
def test_terraform_server_dead_strip_and_unused_imports_are_gone_live_copies_stay():
    rel = "mcp-servers/terraform/service.py"
    names = _top_level_names(rel)
    assert "strip_hcl_resource_block" not in names
    assert not HCL_UTILS_DELETED & _imported_names(rel)
    assert {n for f, n in LIVE_ELSEWHERE if f == rel} <= names
    # U9 (validate_hcl_syntax_tree) and the other apply-time hcl_utils mutators were W6b's, not W1's (pinned absent in
    # tests/test_fd55_w6bd_no_writeback.py)


# ------------------------------------------------------------------------------------------------ X5 (VCS x7)
@pytest.mark.parametrize("copy", SHARED_COPIES)
def test_sanitize_pipeline_content_is_gone_from_every_provider_copy(copy):
    for rel, cls in PROVIDER_FILES.items():
        methods = _methods(f"{copy}/{rel}", cls)
        assert "sanitize_pipeline_content" not in methods, (copy, rel)
        assert "validate_pipeline_content" in methods, (copy, rel)  # the live check stays


def test_eval_identity_contract_row_for_hb44_is_gone():
    sys.path.insert(0, os.path.join(REPO_ROOT, "eval"))
    try:
        from stackvend_eval.healer_probe import IDENTITY_CONTRACTS
    finally:
        sys.path.remove(os.path.join(REPO_ROOT, "eval"))
    assert "GitHubProvider.sanitize_pipeline_content" not in IDENTITY_CONTRACTS


# ------------------------------------------------------------------------------------------------ no caller anywhere
def _product_sources():
    for top in ("apps", "mcp-servers", "shared", "eval/stackvend_eval", "eval/tools"):
        for dirpath, dirnames, filenames in os.walk(os.path.join(REPO_ROOT, top)):
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", "__pycache__", ".deps", ".tools")
                           and not d.startswith(".")]
            for fn in filenames:
                if fn.endswith(".py") and not fn.startswith("test_"):
                    yield os.path.relpath(os.path.join(dirpath, fn), REPO_ROOT)


def test_no_product_module_defines_imports_or_calls_a_deleted_body():
    """Mutant guard: re-adding any deleted body (or a call to it) anywhere in product code fails here."""
    hits = []
    for rel in _product_sources():
        try:
            tree = _tree(rel)
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            name = None
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = node.name
            elif isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            elif isinstance(node, ast.alias):
                name = node.asname or node.name
            if name in EVERY_DELETED and (rel, name) not in LIVE_ELSEWHERE:
                hits.append((rel, getattr(node, "lineno", None), name))
    assert hits == []


# ------------------------------------------------------------------------------------------------ live apply copy
# FD-55 W6a: the terraform server's workflow sanitizer is deleted (prepare_workspace validates the committed text);
# the two cases that ran the gateway twin's idempotence / expression-integrity checks on it are gone with it.
def test_terraform_server_workflow_sanitizer_is_gone():
    names = _top_level_names("mcp-servers/terraform/service.py")
    assert not {"sanitize_github_workflow", "_deduplicate_env_block"} & names

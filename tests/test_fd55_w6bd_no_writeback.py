"""FD-55 W6b + W6d (register FD55-W6b+W6d, incl. HS-42): deploy never commits to the workload repository, and no
apply-time step rewrites a committed .tf file.

Deleted (mcp-servers/terraform/service.py prepare_workspace / _deploy_workload_impl, and hcl_utils.py x5):
- A27 (HC-14) self_correct_hcl_syntax + U9 (HE-01) validate_hcl_syntax_tree: the in-process delimiter "balancer".
- A28 (HA-17) the prepare_workspace call of sanitize_hcl_locals_invariants (`locals.` -> `local.`, invented locals).
  FD-55 W6c deleted its last callers (the validate-error / apply-error heals A44 / A48); the merged W6b + W6c change
  deleted the body and extract_declared_locals from hcl_utils x5 and the service.py import (U2).
- A29 (HB-24 / HA-13 Phase 0) auto_wire_network_graph_dependencies, heal_orphaned_root_resource_syntax,
  heal_orphaned_resource_syntax (parser-gated orphaned depends_on rebuild; register row 7 condition met: FD-53 is live).
- A31 the "Autonomous GitOps Writeback (Option B)": the commit of prepare_workspace's healed files to the deploy branch,
  and the `_last_healed_files` / `_last_healed_traces` record that fed it.
Converted:
- A30 (HA-31 "Canonical Golden Module Alignment") -> report only on every workspace: a vendored golden module that
  differs from the platform payload is applied as committed, logged as PLATFORM.VENDORED_MODULE_STALE, and the deploy
  marks the workload "IaC outdated" (Control Center `iac_drift_detected` / `iac_drift_count`); the fix is the
  Upgrade IaC pull request (refused under Code Freeze).

Mutant guards: an AST check that neither service.py nor applier.py calls a VCS write method or writes to a GitHub
URL (literal, or a name assigned a string in the same function), that service.py obtains exactly one VCS provider and
uses it only to read the tree (a re-added commit fails here), plus deploy-level tests that assert the VCS factory is never asked for a provider after the repo read. Every
removed behaviour has a negative test: valid (and invalid) committed input reaches the workspace byte-identical.

Hermetic: no repo fetch, no Secret Manager, no ADC, no network, no tofu (a deploy stops at the first tofu call).
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import logging
import os
import sys
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fd4g_support import load_tf_service  # noqa: E402

TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
SERVICE = os.path.join(TF_DIR, "service.py")
APPLIER = os.path.join(TF_DIR, "applier.py")
HCL_UTILS_COPIES = [
    "shared/hcl_utils.py",
    "apps/orchestrator-gateway/shared/hcl_utils.py",
    "apps/orchestrator-gateway/developer_agent/hcl_utils.py",
    "mcp-servers/terraform/hcl_utils.py",
    "mcp-servers/terraform/shared/hcl_utils.py",
]
W6B_DELETED_HCL_UTILS = {"validate_hcl_syntax_tree", "self_correct_hcl_syntax", "heal_orphaned_resource_syntax",
                         "heal_orphaned_root_resource_syntax", "auto_wire_network_graph_dependencies",
                         "_root_tf_paths", "MATCHING_DELIMITERS", "MATCHING_CLOSING",
                         # U2 (HA-17), deleted when W6b + W6c merged (no production caller left)
                         "extract_declared_locals", "sanitize_hcl_locals_invariants"}
# Every VCSProvider method that writes to a repository (shared/vcs_provider.py). The deploy only reads the repo.
VCS_WRITE_METHODS = {"vend_repository", "create_or_verify_branch", "commit_files", "create_pull_request",
                     "reconcile_automated_pull_requests", "merge_pull_request"}
HTTP_WRITE_METHODS = {"put", "post", "patch", "delete"}
# The one GitHub POST the terraform server makes: minting a GitHub App installation token for the repository READ
# (``/app/installations/<id>/access_tokens``, authentication, not a repository write). Pinned to exactly one call.
GITHUB_TOKEN_MINT_PARTS = ("https://api.github.com/app/installations/", "/access_tokens")

W = "infra/workload/"
PROJECT = "p-1"
MAIN = (
    'module "compute" {\n'
    '  source          = "../modules/compute-cloudrun"\n'
    '  project_id      = var.project_id\n'
    '  region          = var.region\n'
    '  service_name    = "shop"\n'
    '  container_image = var.container_image\n'
    '}\n'
)
VARIABLES = (
    'variable "project_id" {\n  type = string\n}\n\n'
    'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n\n'
    'variable "container_image" {\n  type    = string\n  default = ""\n}\n'
)
APPS = {"apps/shop/main.py": "app = None\n", "apps/shop/requirements.txt": "fastapi\n"}
INTENT_FILES = {
    W + "iac_intent.json": '{"schema": "iac_intent/v1", "modules": []}\n',
    W + "custom.tf.json": '{"//": "Rendered by StackVend"}\n',
    W + "topology.json": ('{"schema": "service_topology/v1", "intent": {"services": [{"name": "shop", "kind": '
                          '"cloudrun"}], "primary_service": "shop", "edges": [], "resources": []}}'),
}
STALE_MODULE = {"infra/modules/compute-cloudrun/main.tf": 'resource "google_cloud_run_v2_service" "app" {}\n'}

# ---- inputs each deleted step used to rewrite (valid ones first: Do No Harm; then the broken shapes they "fixed")
# A27: valid HCL whose heredoc / strings hold unbalanced brackets (an in-process delimiter count is fooled by them)
A27_VALID_HEREDOC = (
    'resource "google_cloud_run_v2_service" "svc" {\n'
    '  name     = "svc"\n'
    '  location = var.region\n'
    '  template {\n'
    '    containers {\n'
    '      image = var.container_image\n'
    '      env {\n'
    '        name  = "BOOT"\n'
    '        value = <<-EOT\n'
    '          ] ) } {\n'
    '        EOT\n'
    '      }\n'
    '    }\n'
    '  }\n'
    '}\n'
)
A27_STRAY_BRACKET = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n]\n}\n'          # the "balancer" deleted `]`
A27_UNCLOSED = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n'                    # and appended `}`
# A28: a plural `locals.` reference and an undeclared local (it rewrote / invented them)
A28_VALID_LOCALS = 'locals {\n  bucket = "raw"\n}\n\nresource "google_storage_bucket" "b" {\n  name = local.bucket\n}\n'
A28_PLURAL = 'locals {\n  bucket = "raw"\n}\n\nresource "google_storage_bucket" "b" {\n  name = locals.bucket\n}\n'
A28_UNDECLARED = 'resource "google_project_iam_member" "m" {\n  for_each = toset(local.agent_roles)\n  role = each.key\n}\n'
# A29: the orphaned depends_on shape it rebuilt, and a VALID nested block its regex also matched (review M3)
A29_ORPHANED = (
    'resource "google_vpc_access_connector" "c" {\n'
    '  name          = "c"\n'
    '  ip_cidr_range = "10.8.0.0/28"\n'
    '  network       = google_compute_network.vpc.name\n'
    '  max_instances = 3\n'
    ',\n'
    '    google_compute_network.vpc\n'
    '}\n'
)
A29_VALID_NESTED = (
    'resource "google_cloud_run_v2_service" "svc" {\n'
    '  name = "app"\n'
    '  template {\n'
    '    containers {\n'
    '      env {\n'
    '        name  = "JS"\n'
    '        value = <<-EOT\n'
    '          const s = {\n'
    '            region,\n'
    '            network\n'
    '          }\n'
    '        EOT\n'
    '      }\n'
    '    }\n'
    '  }\n'
    '}\n'
)


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


def _tree(path):
    with open(path, encoding="utf-8") as fh:
        return ast.parse(fh.read())


def _call_attrs(tree):
    return [n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]


def _read(ws, rel):
    with open(os.path.join(ws, rel), encoding="utf-8", newline="") as fh:   # exact bytes
        return fh.read()


def _svc(tf, tmp_path, db=None):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "base"), firestore_client=MagicMock())
    svc.db = db
    svc.state_bucket = ""
    return svc


# ------------------------------------------------------------------------------------------------ structure
def _functions_with_parents(tree):
    """{id(node): innermost enclosing FunctionDef / AsyncFunctionDef (None at module level)} for every node."""
    owner = {}

    def visit(node, fn):
        for child in ast.iter_child_nodes(node):
            owner[id(child)] = fn
            visit(child, child if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn)
    visit(tree, None)
    return owner


def _string_parts(node):
    """The string constants of an expression (literal, f-string, concatenation)."""
    return [c.value for c in ast.walk(node) if isinstance(c, ast.Constant) and isinstance(c.value, str)]


def _folded_string(node):
    """A string the expression evaluates to when it is built from constants only ("a" + "b"), else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded_string(node.left), _folded_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _url_parts(call, fn):
    """The string parts of a write call's arguments, with each bare-name argument resolved to every string
    expression assigned to that name in the enclosing function (or module, at top level)."""
    parts = []
    scope = fn
    for arg in list(call.args) + [k.value for k in call.keywords]:
        parts += _string_parts(arg)
        if isinstance(arg, ast.Name) and scope is not None:
            for node in ast.walk(scope):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if any(isinstance(t, ast.Name) and t.id == arg.id for t in targets):
                        parts += _string_parts(node.value)
    return parts


def _is_token_mint(parts):
    return all(any(p.startswith(want) or p == want for p in parts) for want in GITHUB_TOKEN_MINT_PARTS)


@pytest.mark.parametrize("path", [SERVICE, APPLIER], ids=["service.py", "applier.py"])
def test_the_terraform_server_never_calls_a_repository_write(path):
    """Mutant guard (A31): re-adding any commit / branch / pull-request call to the deploy fails here, whether the
    method is called by name or through getattr with a constant-built name, and so does a raw GitHub REST write whose
    URL is a literal or a name assigned a string in the same function (W6bd review F1)."""
    tree = _tree(path)
    assert not VCS_WRITE_METHODS & set(_call_attrs(tree)), VCS_WRITE_METHODS & set(_call_attrs(tree))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
                and len(node.args) >= 2):
            assert _folded_string(node.args[1]) not in VCS_WRITE_METHODS, ast.dump(node.args[1])
    owner = _functions_with_parents(tree)
    token_mints = 0
    for node in ast.walk(tree):   # nor a raw GitHub REST write (the legacy repo fetch is a GET)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in HTTP_WRITE_METHODS:
            parts = _url_parts(node, owner.get(id(node)))
            if not [p for p in parts if "github" in p.lower()]:
                continue
            assert node.func.attr == "post" and _is_token_mint(parts), (node.func.attr, node.lineno, parts)
            token_mints += 1
    assert token_mints == (1 if path == SERVICE else 0)   # the installation-token mint (auth for the read) only


def test_the_terraform_server_obtains_one_vcs_provider_and_only_reads_with_it():
    """W6bd review F1: service.py asks the VCS factory for a provider exactly once, and the name it is bound to is
    used only to read the tree (``fetch_file_tree``) or inspected (``is None`` / ``isinstance`` / ``type``); it is
    never passed to a helper, so no other code can write through it. applier.py obtains none."""
    assert "get_provider" not in _call_attrs(_tree(APPLIER))
    tree = _tree(SERVICE)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "get_provider"]
    assert len(calls) == 1, [c.lineno for c in calls]
    owner = _functions_with_parents(tree)
    fn = owner[id(calls[0])]
    assert fn is not None
    bound = {t.id for n in ast.walk(fn) if isinstance(n, ast.Assign) and n.value is calls[0]
             for t in n.targets if isinstance(t, ast.Name)}
    assert len(bound) == 1, bound
    name = bound.pop()
    parents = {}
    for node in ast.walk(fn):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    attrs, other = set(), []
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)):
            continue
        parent = parents[id(node)]
        if isinstance(parent, ast.Attribute):
            attrs.add(parent.attr)
        elif isinstance(parent, ast.Compare) and all(isinstance(c, ast.Constant) and c.value is None
                                                     for c in parent.comparators):
            continue                                    # `vcs is not None`
        elif (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
              and parent.func.id in ("isinstance", "type") and parent.args and parent.args[0] is node):
            continue                                    # isinstance(vcs, GitHubProvider) / type(vcs).__name__
        elif (isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name)
              and parent.func.id in ("add_serverless_git_binaries", "_is_serverless_git_reader")
              and parent.args and parent.args[0] is node):
            continue                                    # RT14-21: read-only archive read (guarded in test_rt14_*)
        else:
            other.append((node.lineno, type(parent).__name__))
    assert attrs == {"fetch_file_tree"}, attrs
    assert not other, other
    # and nothing else in the module talks to the factory
    factory_uses = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                    and n.value.id == "VCSProviderFactory"]
    assert [n.attr for n in factory_uses] == ["get_provider"]


def test_no_write_back_record_and_no_deleted_import_in_service_py():
    tree = _tree(SERVICE)
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not {"_last_healed_files", "_last_healed_traces"} & attrs
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "healed_files_to_sync" not in names
    imported = {a.asname or a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert not W6B_DELETED_HCL_UTILS & imported, W6B_DELETED_HCL_UTILS & imported
    # after W6b + W6c the service imports no hcl_utils rewriter (U2's import block is gone too); SAT-01 (OQ-3) imports
    # only the read-only parser helpers, for the deploy's auto-loaded variables-file check
    hcl_utils_imports = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
                         and (n.module or "").split(".")[-1] == "hcl_utils" for a in n.names}
    assert hcl_utils_imports <= {"find_hcl_parser_binary", "hcl_parse_errors"}, hcl_utils_imports


@pytest.mark.parametrize("rel", HCL_UTILS_COPIES)
def test_hcl_utils_w6b_bodies_are_gone(rel):
    tree = _tree(os.path.join(REPO_ROOT, rel))
    top = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            top.add(node.name)
        elif isinstance(node, ast.Assign):
            top |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    assert not W6B_DELETED_HCL_UTILS & top, W6B_DELETED_HCL_UTILS & top
    assert {"find_hcl_parser_binary", "hcl_parse_errors"} <= top   # the read-only parser helpers stay


def test_prepare_workspace_calls_no_hcl_rewriter():
    fn = next(n for n in ast.walk(_tree(SERVICE)) if isinstance(n, ast.FunctionDef) and n.name == "prepare_workspace")
    called = {(c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", None))
              for c in ast.walk(fn) if isinstance(c, ast.Call)}
    assert not {"self_correct_hcl_syntax", "sanitize_hcl_locals_invariants", "extract_declared_locals",
                "auto_wire_network_graph_dependencies", "heal_orphaned_root_resource_syntax"} & called
    assert "stale_vendored_module_files" in called   # A30 -> report only


# ------------------------------------------------------------------------------------------------ A27-A29 negatives
@pytest.mark.parametrize("name,text", [
    ("A27_valid_heredoc_with_brackets", A27_VALID_HEREDOC),
    ("A27_stray_bracket", A27_STRAY_BRACKET),
    ("A27_unclosed_block", A27_UNCLOSED),
    ("A28_valid_locals", A28_VALID_LOCALS),
    ("A28_plural_locals_reference", A28_PLURAL),
    ("A28_undeclared_local", A28_UNDECLARED),
    ("A29_orphaned_depends_on", A29_ORPHANED),
    ("A29_valid_nested_heredoc", A29_VALID_NESTED),
])
@pytest.mark.parametrize("layout", ["root", "infra/workload"])
def test_committed_tf_reaches_the_workspace_byte_identical(tf, tmp_path, name, text, layout):
    """Valid input is unchanged (Do No Harm); so is the broken input the deleted steps "cured": it fails
    `tofu validate` / apply and is reported back instead of being rewritten and committed."""
    prefix = "" if layout == "root" else W
    files = {f"{prefix}custom.tf": text, f"{prefix}variables.tf": VARIABLES}
    svc = _svc(tf, tmp_path)
    ws = svc.prepare_workspace("shop", f"t-{name}", dict(files))
    for rel, content in files.items():
        assert _read(ws, rel) == content, (name, rel)
    assert not hasattr(svc, "_last_healed_files")


def test_user_owned_and_intent_files_are_unchanged_too(tf, tmp_path):
    files = dict({W + "main.tf": MAIN, W + "variables.tf": VARIABLES, "human.tf": A28_PLURAL,
                  W + "custom.tf": A27_STRAY_BRACKET}, **INTENT_FILES)
    ws = _svc(tf, tmp_path).prepare_workspace("shop", "t-intent", dict(files))
    for rel, content in files.items():
        assert _read(ws, rel) == content, rel


# ------------------------------------------------------------------------------------------------ A30 -> report only
@pytest.mark.parametrize("intent", [False, True], ids=["legacy", "intent"])
def test_stale_vendored_module_is_applied_as_committed_and_reported(tf, tmp_path, caplog, intent):
    files = dict({W + "main.tf": MAIN, W + "variables.tf": VARIABLES}, **STALE_MODULE)
    if intent:
        files.update(INTENT_FILES)
    caplog.set_level(logging.WARNING, logger="mcp-terraform-server")
    ws = _svc(tf, tmp_path).prepare_workspace("shop", "t-stale", dict(files))
    assert _read(ws, "infra/modules/compute-cloudrun/main.tf") == STALE_MODULE["infra/modules/compute-cloudrun/main.tf"]
    for missing in ("variables.tf", "outputs.tf"):   # payload files the refresh used to add: not added
        assert not os.path.exists(os.path.join(ws, "infra/modules/compute-cloudrun", missing))
    msgs = [r.getMessage() for r in caplog.records if "PLATFORM.VENDORED_MODULE_STALE" in r.getMessage()]
    assert sorted(m.split("'")[1] for m in msgs) == [
        "infra/modules/compute-cloudrun/main.tf", "infra/modules/compute-cloudrun/outputs.tf",
        "infra/modules/compute-cloudrun/variables.tf"]       # once each: the `modules` symlink is not reported twice


def test_current_vendored_module_is_not_reported(tf, tmp_path, caplog):
    """Negative: a module equal to the payload (what generation vendors) gives no finding."""
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    files = {W + "main.tf": MAIN, W + "variables.tf": VARIABLES}
    files.update({f"infra/modules/compute-cloudrun/{f}": t for f, t in BUILTIN_MODULE_FILES["compute-cloudrun"].items()})
    caplog.set_level(logging.WARNING, logger="mcp-terraform-server")
    ws = _svc(tf, tmp_path).prepare_workspace("shop", "t-current", dict(files))
    assert not [r for r in caplog.records if "PLATFORM.VENDORED_MODULE_STALE" in r.getMessage()]
    assert tf.stale_vendored_module_files(ws) == {}
    for rel, content in files.items():
        assert _read(ws, rel) == content, rel


def test_stale_vendored_module_files_is_read_only(tf, tmp_path):
    ws = tmp_path / "ws"
    mod = ws / "infra" / "modules" / "compute-cloudrun"
    mod.mkdir(parents=True)
    (mod / "main.tf").write_text("# old\n", encoding="utf-8")
    (ws / "modules").symlink_to("infra/modules")
    (ws / "infra" / "modules" / "not-golden").mkdir()
    (ws / "infra" / "modules" / "not-golden" / "main.tf").write_text("# mine\n", encoding="utf-8")
    before = {p: p.read_bytes() for p in ws.rglob("*") if p.is_file()}
    stale = tf.stale_vendored_module_files(str(ws))
    assert set(stale) == {"compute-cloudrun"}
    assert sorted(stale["compute-cloudrun"]) == [f"infra/modules/compute-cloudrun/{f}"
                                                 for f in ("main.tf", "outputs.tf", "variables.tf")]
    assert {p: p.read_bytes() for p in ws.rglob("*") if p.is_file()} == before   # nothing written or created


def _vendor_payload(ws, transform=lambda f, t: t):
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    mod = ws / "infra" / "modules" / "compute-cloudrun"
    mod.mkdir(parents=True)
    for fname, text in BUILTIN_MODULE_FILES["compute-cloudrun"].items():
        (mod / fname).write_bytes(transform(fname, text).encode("utf-8"))
    return BUILTIN_MODULE_FILES["compute-cloudrun"]


def test_whitespace_only_module_difference_is_not_reported(tf, tmp_path):
    """W6bd review F2 negative: the deploy uses the Control Center's comparison (calculate_module_content_hash), so
    trailing whitespace, CRLF line ends and extra leading / trailing blank lines (which the CC drift inspection would
    clear again) raise nothing; the files stay as committed."""
    ws = tmp_path / "ws"
    _vendor_payload(ws, lambda f, t: "\n\n" + "\r\n".join(line + "   \t" for line in t.split("\n")) + "\n\n\n")
    before = {p: p.read_bytes() for p in ws.rglob("*") if p.is_file()}
    assert tf.stale_vendored_module_files(str(ws)) == {}
    assert {p: p.read_bytes() for p in ws.rglob("*") if p.is_file()} == before


def test_real_module_content_difference_is_reported(tf, tmp_path):
    """W6bd review F2 positive: one changed value in one file is reported (that file only)."""
    ws = tmp_path / "ws"
    payload = _vendor_payload(ws)
    target = sorted(payload)[0]
    path = ws / "infra" / "modules" / "compute-cloudrun" / target
    path.write_text(payload[target] + '\nvariable "w6bd_review_f2_probe" {\n  default = "x"\n}\n', encoding="utf-8")
    assert tf.stale_vendored_module_files(str(ws)) == {
        "compute-cloudrun": [f"infra/modules/compute-cloudrun/{target}"]}


def test_stale_check_reuses_the_control_center_comparison_rule(tf):
    """W6bd review F2: the deploy and the Control Center drift inspection compare modules with the same function."""
    fn = tf._module_content_hash_fn()
    assert fn is not None
    assert (fn.__module__.rsplit(".", 1)[-1], fn.__name__) == ("iac_upgrade_engine", "calculate_module_content_hash")


# ------------------------------------------------------------------------------------------------ IaC outdated flag
class _Doc:
    def __init__(self, exists=True, data=None, fail=False):
        self.exists_flag, self.data, self.fail = exists, dict(data or {}), fail
        self.sets = []

    def get(self):
        if self.fail:
            raise RuntimeError("firestore unavailable")
        return MagicMock(exists=self.exists_flag, to_dict=lambda: dict(self.data))

    def set(self, payload, merge=False):
        self.sets.append((payload, merge))


def _db(doc):
    db = MagicMock()
    db.collection.return_value.document.return_value = doc
    return db


STALE = {"compute-cloudrun": ["infra/modules/compute-cloudrun/main.tf"],
         "workload-foundation/base": ["infra/modules/workload-foundation/base/apis.tf"]}


def test_report_marks_the_workload_iac_outdated(tf, tmp_path):
    doc = _Doc(data={"iac_drift_detected": False, "iac_drift_count": 0})
    svc = _svc(tf, tmp_path, db=_db(doc))
    svc._report_iac_outdated("shop", "t-1", STALE)
    assert doc.sets == [({"iac_drift_detected": True, "iac_drift_count": 2}, True)]
    svc.db.collection.assert_called_with("workloads")
    svc.db.collection.return_value.document.assert_called_with("shop")


@pytest.mark.parametrize("data,stale,expected", [
    ({"iac_drift_detected": True, "iac_drift_count": 3}, STALE, []),            # already flagged with more: untouched
    ({"iac_drift_detected": True, "iac_drift_count": 1}, STALE,                # raised, never lowered
     [({"iac_drift_detected": True, "iac_drift_count": 2}, True)]),
    ({"iac_drift_detected": False, "iac_drift_count": 5}, {"compute-cloudrun": ["x"]},
     [({"iac_drift_detected": True, "iac_drift_count": 5}, True)]),
    ({}, {}, []),                                                               # nothing stale: nothing written
])
def test_report_only_raises_the_flag(tf, tmp_path, data, stale, expected):
    doc = _Doc(data=data)
    _svc(tf, tmp_path, db=_db(doc))._report_iac_outdated("shop", "t-1", stale)
    assert doc.sets == expected


def test_report_never_creates_a_workload_record_and_never_raises(tf, tmp_path):
    missing = _Doc(exists=False)
    _svc(tf, tmp_path, db=_db(missing))._report_iac_outdated("ghost", "t-1", STALE)
    assert missing.sets == []
    broken = _Doc(fail=True)
    _svc(tf, tmp_path, db=_db(broken))._report_iac_outdated("shop", "t-1", STALE)   # logged, not raised
    assert broken.sets == []
    _svc(tf, tmp_path, db=None)._report_iac_outdated("shop", "t-1", STALE)          # no Firestore: no-op


# ------------------------------------------------------------------------------------------------ deploy (A31)
class _StopAtTofu(BaseException):
    """Raised by the first tofu call: everything the deploy writes before plan / apply has been written."""


def _no_gcp(monkeypatch):
    import google.auth

    class _SM:
        def __init__(self, *a, **k):
            pass

        def access_secret_version(self, name):
            raise RuntimeError("no secrets in tests")

    def _no_adc(*_a, **_k):
        raise RuntimeError("no ADC in tests")

    import types
    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _SM
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", _no_adc, raising=False)
    assert google.auth.default is _no_adc


def _deploy(tf, monkeypatch, tmp_path, files):
    svc = _svc(tf, tmp_path)
    monkeypatch.setenv("GITHUB_ORG", "acme-test")
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(files))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    monkeypatch.setattr(svc, "_build_and_push_container", lambda *a, **k: True)
    _no_gcp(monkeypatch)
    factory = MagicMock(name="VCSProviderFactory")
    monkeypatch.setattr(tf, "VCSProviderFactory", factory)
    reports = []
    real_report = svc._report_iac_outdated
    monkeypatch.setattr(svc, "_report_iac_outdated",
                        lambda pid, trace, stale: (reports.append((pid, trace, stale)), real_report(pid, trace, stale)))
    seen = {}

    def _tofu(*_a, **kw):
        seen["ws"] = kw.get("cwd")
        raise _StopAtTofu()

    monkeypatch.setattr(svc, "_run_subprocess", _tofu)
    try:
        res = svc.deploy_workload(product_id="shop", trace_id="t-deploy", target_project_id=PROJECT,
                                  branch="main", iac_engine="OPENTOFU")
    except _StopAtTofu:
        res = None
    return res, seen, factory, reports


@pytest.mark.parametrize("intent", [False, True], ids=["legacy", "intent"])
def test_deploy_never_touches_the_repository_and_reports_iac_outdated(tf, monkeypatch, tmp_path, intent):
    """Mutant guard (A31): a deploy whose committed tree the deleted steps would have rewritten (plural locals, a
    heredoc the delimiter count and the orphaned-depends_on regex misread, a stale module) never asks the VCS factory
    for a provider after the repo read (_fetch_repo_files is the read), so nothing can be committed; the tree reaches
    the workspace as committed and the stale module is reported once. (A root .tf python-hcl2 cannot parse stops the
    deploy earlier with APPLY.SOURCE_UNPARSEABLE, FD55-TFVARS; tests/test_fd55_w3_deploy_gaps.py.)"""
    files = dict({W + "main.tf": MAIN, W + "variables.tf": VARIABLES, W + "custom.tf": A28_PLURAL,
                  W + "extra.tf": A29_VALID_NESTED, W + "boot.tf": A27_VALID_HEREDOC}, **APPS, **STALE_MODULE)
    if intent:
        files.update(INTENT_FILES)
    res, seen, factory, reports = _deploy(tf, monkeypatch, tmp_path, files)
    assert res is None, res
    assert factory.mock_calls == []            # no provider, no commit, no pull request
    assert _read(seen["ws"], "infra/modules/compute-cloudrun/main.tf") == \
        STALE_MODULE["infra/modules/compute-cloudrun/main.tf"]
    for rel, text in ((W + "custom.tf", A28_PLURAL), (W + "extra.tf", A29_VALID_NESTED), (W + "boot.tf", A27_VALID_HEREDOC),
                      ("custom.tf", A28_PLURAL)):     # the infra/workload copy and the flattened root copy
        assert _read(seen["ws"], rel) == text, rel
    assert len(reports) == 1 and reports[0][:2] == ("shop", "t-deploy")
    assert set(reports[0][2]) == {"compute-cloudrun"}


def test_deploy_with_current_modules_reports_nothing(tf, monkeypatch, tmp_path):
    files = dict({W + "main.tf": MAIN, W + "variables.tf": VARIABLES}, **APPS)
    res, _seen, factory, reports = _deploy(tf, monkeypatch, tmp_path, files)
    assert res is None, res
    assert factory.mock_calls == []
    assert reports == [("shop", "t-deploy", {})]   # called, empty: _report_iac_outdated writes nothing

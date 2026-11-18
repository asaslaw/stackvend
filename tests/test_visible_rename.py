"""VISIBLE-RENAME (owner 10-26): text StackVend writes into users' repositories and the agent personas say StackVend;
internal identifiers (castor- resources, castor/ branches, the castor-metadata PR marker, the managed-by label, the
agent author email) are unchanged. Read statically so no service import graph is loaded."""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)
import ast
import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHARED_COPIES = ("shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "apps/project-vending/shared",
                 "apps/qa-runner/shared", "mcp-servers/github/shared", "mcp-servers/terraform/shared")
GW = "apps/orchestrator-gateway"


def read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def string_constants(rel):
    """Every str constant (incl. f-string parts) in a module, docstrings excluded: the text the code emits."""
    tree = ast.parse(read(rel))
    docs = {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body
            and isinstance(n.body[0], ast.Expr) and isinstance(n.body[0].value, ast.Constant)}
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in docs]


EMITTERS = [f"{d}/{f}" for d in SHARED_COPIES for f in ("vcs_provider.py", "providers/github_provider.py",
                                                         "providers/serverless_git_provider.py")] + [
    "apps/git-server/main.py", "apps/project-vending/vending.py", f"{GW}/developer_agent/handler.py", f"{GW}/main.py",
    f"{GW}/release_gatekeeper.py", f"{GW}/developer_agent/terraform_engine.py", f"{GW}/developer_agent/prompt.py",
    f"{GW}/developer_agent/lead_orchestrator.py", f"{GW}/developer_agent/swarm_schemas.py",
    f"{GW}/developer_agent/contract_registry.py", f"{GW}/architect_agent/prompt.py",
    f"{GW}/architect_agent/spec_decomposer.py", f"{GW}/compliance_agent/prompt.py", f"{GW}/compliance_agent/handler.py",
    f"{GW}/qa_auditor/adherence_lens.py", f"{GW}/qa_auditor/security_lens.py", "shared/agent_evaluator.py",
    "shared/builtin_skills_provider.py", "shared/express_synthesizer.py", "shared/iac_upgrade_engine.py",
    "mcp-servers/terraform/shared/builtin_prompts.py", "apps/control-center/routes/agent_evals.py",
    # visible-rename-3 (RT F2): the module-inspector / workflow-validator messages, and the two Control Center files
    # (platform-inventory SA display names mirror infra/platform/main.tf; their logger lines say StackVend too)
    "shared/module_inspector.py", "shared/workflow_validator.py", "apps/control-center/routes/workloads.py",
    "apps/control-center/assistant.py",
] + [f"{GW}/developer_agent/juniors/{w}_worker.py" for w in ("backend", "frontend", "devops", "iac", "test")]

OLD_PRODUCT_NAME = re.compile(r"Project Castor|PROJECT CASTOR|\bCastor(?=[ ']|$)")


@pytest.mark.parametrize("rel", EMITTERS)
def test_emitted_text_no_longer_says_castor(rel):
    hits = [s for s in string_constants(rel) if OLD_PRODUCT_NAME.search(s)]
    assert hits == [], hits


@pytest.mark.parametrize("d", SHARED_COPIES)
def test_default_commit_identity(d):
    assert 'author_name: str = "StackVend Developer Agent"' in read(f"{d}/vcs_provider.py")
    # the email is unchanged (identifier; already neutral)
    assert '"stackvend-agent@noreply.invalid"' in read(f"{d}/vcs_provider.py")


def test_internal_identifiers_unchanged():
    handler = read(f"{GW}/developer_agent/handler.py")
    assert handler.count("<!-- castor-metadata: ") == 2 and handler.count("<!-- managed-by: project-castor -->") == 2
    gs = read("apps/git-server/main.py")
    assert 'f"StackVend <{AGENT_AUTHOR_EMAIL}>"' in gs and 'f"StackVend Release Agent <{AGENT_AUTHOR_EMAIL}>"' in gs
    # GITHUB-REPO-NAME-NO-PREFIX (owner 11-12): the GitHub repository default is the bare workload id (visible name)
    assert "repo_name = repo or clean_pid" in read(f"{GW}/developer_agent/terraform_engine.py")
    assert 'f"{prefix}.castor-bundle.json"' in read(f"{GW}/developer_agent/terraform_engine.py")


def test_plan_front_matter_author():
    for rel in (f"{GW}/architect_agent/handler.py", f"{GW}/developer_agent/handler.py"):
        assert 'author: "StackVend Autonomous Engineering Pipeline"' in read(rel)


def test_assistant_persona_copies_identical():
    root = read("shared/builtin_prompts.py")
    assert "You are **StackVend Assistant**" in root
    for d in SHARED_COPIES:
        p = f"{d}/builtin_prompts.py"
        if os.path.exists(os.path.join(REPO, p)):
            assert read(p) == root, p


# --- visible-rename-3 (owner 10-26): host display text, its Control Center mirror, golden-module comments ---------
# python-hcl2 7.3.1 cannot parse billing_iam.tf (a multi-line conditional); it declares no display text, which
# test_unparsed_platform_files_have_no_display_text pins, so a display_name added there must extend this test.
HCL2_UNPARSEABLE = {os.path.join("infra", "platform", "billing_iam.tf")}
PLATFORM_TF = sorted(os.path.join("infra", "platform", f) for f in os.listdir(os.path.join(REPO, "infra", "platform"))
                     if f.endswith(".tf") and os.path.join("infra", "platform", f) not in HCL2_UNPARSEABLE)
# the host-platform-only module infra/platform/main.tf instantiates (shared/host_platform_modules.py)
PLATFORM_TF += sorted(os.path.join("infra", "modules", m, f) for m in ("workflows",)
                      for f in os.listdir(os.path.join(REPO, "infra", "modules", m)) if f.endswith(".tf"))
MODULE_DIRS = ("infra/modules", "apps/control-center/infra/modules")
PAYLOAD_COPIES = [f"{d}/builtin_modules_payload.py" for d in ("shared", "apps/control-center/shared",
                                                               "apps/orchestrator-gateway/shared",
                                                               "mcp-servers/terraform/shared")]
BUNDLE_COPIES = [p.replace("builtin_modules_payload", "builtin_bundles_payload") for p in PAYLOAD_COPIES]


def _hcl(rel):
    import hcl2
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return hcl2.load(fh)


def _agent_roles():
    for block in _hcl("infra/platform/main.tf").get("locals", []):
        if "agent_roles" in block:
            return block["agent_roles"]
    raise AssertionError("local.agent_roles not found in infra/platform/main.tf")


def test_host_resource_display_text_says_stackvend():
    """display_name / description of every host resource (what the GCP console shows), parsed with python-hcl2."""
    hits = [f"{a}: {v}" for a, v in _agent_roles().items() if OLD_PRODUCT_NAME.search(v)]
    for rel in PLATFORM_TF:
        for entry in _hcl(rel).get("resource", []):
            for rtype, named in entry.items():
                for name, body in named.items():
                    for attr in ("display_name", "description"):
                        val = body.get(attr)
                        if isinstance(val, str) and OLD_PRODUCT_NAME.search(val):
                            hits.append(f"{rel}: {rtype}.{name}.{attr} = {val}")
    assert hits == [], hits


@pytest.mark.parametrize("rel", sorted(HCL2_UNPARSEABLE))
def test_unparsed_platform_files_have_no_display_text(rel):
    text = read(rel)
    assert "display_name" not in text and "description" not in text


def test_cc_platform_inventory_mirrors_host_sa_display_names():
    """The Control Center's platform-workload inventory (routes/workloads.py, google_service_account entries) shows
    the same display_name as infra/platform/main.tf local.agent_roles for that account id."""
    roles = _agent_roles()
    tree = ast.parse(read("apps/control-center/routes/workloads.py"))
    seen = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "DeployedResource"):
            continue
        kw = {k.arg: k.value for k in node.keywords}
        rtype = kw.get("resource_type")
        if not (isinstance(rtype, ast.Constant) and rtype.value == "google_service_account"):
            continue
        rid = kw["resource_id"]
        head = rid.values[0].value if isinstance(rid, ast.JoinedStr) else rid.value
        account_id = head.split("@", 1)[0]
        attrs = ast.literal_eval(ast.Dict(keys=[k for k in kw["attributes"].keys],
                                          values=[v if isinstance(v, ast.Constant) else ast.Constant(None)
                                                  for v in kw["attributes"].values]))
        seen[account_id] = attrs["display_name"]
    assert len(seen) >= 2, seen
    assert {a: roles.get(a) for a in seen} == seen


def _text_hits(rel, text):
    """Every line (comment or attribute text) that says (Project) Castor; lowercase castor- identifiers do not match."""
    return [f"{rel}:{i}: {line}" for i, line in enumerate(text.split("\n"), 1) if OLD_PRODUCT_NAME.search(line)]


def test_golden_module_text_says_stackvend():
    """Golden-module and composite-bundle text vendored into every workload repo: header comments (visible-rename-3)
    and attribute display text / variable descriptions (visible-rename-3b, owner 10-26). Checked on disk, in the
    Control Center copy, in the 4 builtin payload copies and in every bundle's hcl_files in the 4 bundle payloads."""
    hits = []
    for d in MODULE_DIRS:
        for root, _, names in os.walk(os.path.join(REPO, d)):
            for n in names:
                if n.endswith(".tf"):
                    rel = os.path.relpath(os.path.join(root, n), REPO)
                    hits += _text_hits(rel, read(rel))
    for rel in PAYLOAD_COPIES:
        ns = {}
        exec(compile(read(rel), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
        for mod_id, files in ns["BUILTIN_MODULE_FILES"].items():
            for fname, text in files.items():
                hits += _text_hits(f"{rel}[{mod_id}/{fname}]", text)
    for rel in BUNDLE_COPIES:
        ns = {}
        exec(compile(read(rel), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
        assert ns["BUILTIN_BUNDLES"], rel
        for bundle_id, rec in ns["BUILTIN_BUNDLES"].items():
            for fname, text in rec.hcl_files.items():
                hits += _text_hits(f"{rel}[{bundle_id}/{fname}]", text)
    assert hits == [], hits

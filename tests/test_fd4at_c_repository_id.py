import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

"""FD-4AT-c (register row FD-4AT-c, owner 10-20): the tenant WIF condition also binds the GitHub repository_id.

Chain under test (module condition itself: tests/test_fd4at_ci_least_privilege.py + its tofu test; tf-applier's root
tfvars: mcp-servers/terraform/test_service.py::test_fd4at_c_*):
- shared/github_identity.py: the record vending writes and the exact reader tf-applier uses (digits only, same
  repository name, never an old id with a new name);
- vending resolves the id from the GitHub API with the existing provider client and records it on every vend of a
  GitHub repository (unresolved -> explicit None); a reused repository or Serverless Git records nothing;
- the generated roots (developer + Express) forward the input with an empty default;
- the developer prompt is byte-identical (the input is platform-only, not advertised).
"""
import os
import sys
from types import SimpleNamespace as NS

import pytest

import destructive_guard_fakes as f
from test_destructive_guard_vending import (  # noqa: F401  (fixtures)
    _freeze_setting_without_firestore, _vend_crm, _vend_engine, vmain,
)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from shared import github_identity as gi  # noqa: E402

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

REPLICAS = ["apps/control-center/shared/github_identity.py", "apps/orchestrator-gateway/shared/github_identity.py",
            "apps/project-vending/shared/github_identity.py", "apps/qa-runner/shared/github_identity.py",
            "mcp-servers/terraform/shared/github_identity.py"]


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


# ------------------------------------------------------------------------------------------- shared record / reader
@pytest.mark.parametrize("raw,expected", [
    (123456789, "123456789"), ("123456789", "123456789"),
    (0, None), (-5, None), (True, None), (False, None), (12.0, None), ("", None), ("0123", None), ("12a", None),
    ("１２３", None), ("²", None), (" 123", None), ("123' || true || '", None), (None, None), ([1], None),
])
def test_record_keeps_only_githubs_numeric_id(raw, expected):
    assert gi.github_repository_identity_record("acme/app", raw) == {"full_name": "acme/app", "repository_id": expected}


def test_reader_pins_only_the_recorded_repository():
    rec = gi.github_repository_identity_record("Acme/App", 42)
    assert gi.pinned_github_repository_id(rec, "acme/app") == "42"           # GitHub names are case-insensitive
    assert gi.pinned_github_repository_id(rec, "acme/app-2") is None         # renamed / re-pointed workload
    assert gi.pinned_github_repository_id(rec, "") is None
    assert gi.pinned_github_repository_id(None, "acme/app") is None          # vended before FD-4AT-c
    assert gi.pinned_github_repository_id("42", "acme/app") is None
    assert gi.pinned_github_repository_id({"full_name": "acme/app", "repository_id": None}, "acme/app") is None
    assert gi.pinned_github_repository_id({"full_name": "acme/app", "repository_id": "4 2"}, "acme/app") is None
    assert gi.pinned_github_repository_id({"repository_id": "42"}, "acme/app") is None


def test_github_identity_replicas_identical():
    root = _read("shared/github_identity.py")
    for rel in REPLICAS:
        assert _read(rel) == root, rel


# ------------------------------------------------------------------------------------------------------ vending
class _Repo:
    def __init__(self, full_name, repo_id):
        self.full_name, self.id = full_name, repo_id


class _Vcs:
    def __init__(self, repo=None, error=None, meta_name="acme/castor-app", provider="GITHUB"):
        self.repo, self.error, self.asked = repo, error, []
        self.meta = NS(provider=provider, repo_name="castor-app", full_name=meta_name, html_url="h", clone_url_http="c",
                       is_reused=False)

    def vend_repository(self, product_id, **kw):
        return self.meta

    def get_client(self):
        vcs = self

        class _Client:
            def get_repo(self, name):
                vcs.asked.append(name)
                if vcs.error:
                    raise vcs.error
                return vcs.repo
        return _Client()


def _engine_with_vcs(vmain, monkeypatch, vcs, db=None):
    eng = _vend_engine(vmain, db or f.FakeDB(), _vend_crm())
    globs = vmain.ProjectRepoVendingEngine.vend_gcp_project.__globals__  # the vending module (undecorated)
    monkeypatch.setitem(globs, "VCSProviderFactory", NS(get_provider=lambda **kw: vcs))
    return eng


def test_vend_github_repo_reads_the_id_with_the_provider_client(vmain, monkeypatch):
    vcs = _Vcs(repo=_Repo("acme/castor-app", 987654321))
    res = _engine_with_vcs(vmain, monkeypatch, vcs).vend_github_repo("app", vcs_provider="GITHUB")
    assert res["repository_id"] == 987654321 and res["full_name"] == "acme/castor-app"
    assert vcs.asked == ["acme/castor-app"]


@pytest.mark.parametrize("vcs", [
    _Vcs(repo=_Repo("acme/renamed-app", 1)),                 # GitHub followed a rename: the id is another name's
    _Vcs(error=RuntimeError("403 Forbidden")),               # unreadable: never fails the vend
    _Vcs(repo=None),
    _Vcs(repo=_Repo("acme/castor-app", 5), provider="SERVERLESS_GIT"),
])
def test_vend_github_repo_unresolved_id_is_none(vmain, monkeypatch, vcs):
    res = _engine_with_vcs(vmain, monkeypatch, vcs).vend_github_repo("app", vcs_provider="GITHUB")
    assert res["repository_id"] is None and res["full_name"] == "acme/castor-app"


def _vend_all(vmain, db, github_res, doc=None, vcs_provider="GITHUB"):
    if doc is not None:
        db.docs["workloads/app"] = dict(doc)
    eng = _vend_engine(vmain, db, _vend_crm())
    eng.vend_gcp_project = lambda product_id, trace_id, **kw: {"project_id": "p-1", "project_number": f.NUMBER}
    calls = []

    def fake_repo(product_id, **kw):
        calls.append(kw)
        return dict(github_res)

    eng.vend_github_repo = fake_repo
    res = eng.vend_all("app", "tr-fd4atc", vcs_provider=vcs_provider)
    assert res["status"] == "WORKLOAD_VENDED"
    return db.doc("workloads/app"), calls


def test_vend_all_records_the_id_with_the_repository_name(vmain):
    stored, _ = _vend_all(vmain, f.FakeDB(), {"full_name": "acme/castor-app", "repository_id": 4242,
                                               "reused_existing": False})
    assert stored["github_repo"] == "acme/castor-app"
    assert stored["github_repository_identity"] == {"full_name": "acme/castor-app", "repository_id": "4242"}


def test_vend_all_unreadable_id_is_recorded_as_none(vmain):
    stored, _ = _vend_all(vmain, f.FakeDB(), {"full_name": "acme/castor-app"})
    assert stored["github_repository_identity"] == {"full_name": "acme/castor-app", "repository_id": None}


# Existing doc whose repository is vended through vend_github_repo again (repo name == product id: not "reused").
_SAME_NAME = {"github_repo": "acme/app",
              "github_repository_identity": {"full_name": "acme/app", "repository_id": "1111"}}


def _vend_same_name(vmain, github_res):
    db = f.FakeDB()
    db.docs["workloads/app"] = dict(_SAME_NAME)
    eng = _vend_engine(vmain, db, _vend_crm())
    eng.vend_gcp_project = lambda product_id, trace_id, **kw: {"project_id": "p-1", "project_number": f.NUMBER}
    eng.vend_github_repo = lambda product_id, **kw: dict(github_res, full_name="acme/app", repo_name="app")
    eng.vend_all("app", "tr-fd4atc", vcs_provider="GITHUB")
    return db.doc("workloads/app")["github_repository_identity"]


@pytest.mark.parametrize("github_res", [
    {"repository_id": None, "reused_existing": True},     # unreadable now: never unpins
    {"repository_id": 2222, "reused_existing": True},     # same name, different repository: fail closed
    {"repository_id": 2222},                              # direct-creation fallback (creation unknown): fail closed
    {"repository_id": None, "reused_existing": False},
])
def test_vend_all_never_replaces_a_recorded_id_silently(vmain, github_res):
    assert _vend_same_name(vmain, github_res) == {"full_name": "acme/app", "repository_id": "1111"}


def test_vend_all_platform_created_repository_replaces_the_stale_id(vmain):
    """The platform created the repository in this vend (the old one was gone): its id is the new pin."""
    assert _vend_same_name(vmain, {"repository_id": 2222, "reused_existing": False}) == \
        {"full_name": "acme/app", "repository_id": "2222"}


def test_vend_all_reused_repository_is_read_once(vmain, monkeypatch):
    """The common re-vend (repo castor-<pid>, promoted, brownfield, env branch) reuses the repository without
    vend_github_repo; its id is read from GitHub only while no valid id is recorded for it."""
    asked = []

    def lookup(self, full_name, github_owner=None, product_id=None):
        asked.append(full_name)
        return 5150

    monkeypatch.setattr(vmain.ProjectRepoVendingEngine, "_lookup_github_repository_id", lookup)
    stored, calls = _vend_all(vmain, f.FakeDB(), {"full_name": "unused"}, doc={"github_repo": "acme/castor-app"})
    assert calls == [] and asked == ["acme/castor-app"]
    assert stored["github_repository_identity"] == {"full_name": "acme/castor-app", "repository_id": "5150"}
    db = f.FakeDB()
    stored, _ = _vend_all(vmain, db, {"full_name": "unused"}, doc=stored)
    assert asked == ["acme/castor-app"] and stored["github_repository_identity"]["repository_id"] == "5150"


def test_lookup_uses_the_github_provider_client(vmain, monkeypatch):
    vcs = _Vcs(repo=_Repo("acme/castor-app", 77))
    eng = _engine_with_vcs(vmain, monkeypatch, vcs)
    assert eng._lookup_github_repository_id("acme/castor-app") == 77 and vcs.asked == ["acme/castor-app"]
    vcs.error = RuntimeError("404")
    assert eng._lookup_github_repository_id("acme/castor-app") is None


def test_vend_all_serverless_git_records_nothing(vmain):
    stored, _ = _vend_all(vmain, f.FakeDB(), {"full_name": "serverless-git/castor-app", "repository_id": 7},
                          vcs_provider="SERVERLESS_GIT")
    assert "github_repository_identity" not in stored


@pytest.mark.parametrize("existing,resolved,created,expected", [
    (None, 9, False, {"full_name": "acme/app", "repository_id": "9"}),
    ({"full_name": "acme/other", "repository_id": "1"}, 9, False, {"full_name": "acme/app", "repository_id": "9"}),
    ({"full_name": "acme/app", "repository_id": None}, 9, False, {"full_name": "acme/app", "repository_id": "9"}),
    ({"full_name": "acme/app", "repository_id": "1"}, 1, False, None),
    ({"full_name": "ACME/app", "repository_id": "1"}, None, True, None),
    ({"full_name": "acme/app", "repository_id": "1"}, 9, False, None),
    ({"full_name": "acme/app", "repository_id": "1"}, 9, True, {"full_name": "acme/app", "repository_id": "9"}),
])
def test_next_record_is_fail_closed(existing, resolved, created, expected):
    assert gi.next_github_repository_identity(existing, "acme/app", resolved, repository_created=created) == expected


# ------------------------------------------------------------------------------------------- generated roots
def _module_foundation(main_tf):
    for block in hcl2.loads(main_tf).get("module", []):
        if "foundation" in block:
            return block["foundation"]
    raise AssertionError("module foundation missing")


def _variables(variables_tf):
    return {n: body for block in hcl2.loads(variables_tf).get("variable", []) for n, body in block.items()}


def test_developer_root_forwards_the_input_with_an_empty_default(monkeypatch):
    monkeypatch.setenv("GITHUB_ORG", "acme")
    from developer_agent.terraform_engine import generate_golden_main_tf, generate_golden_variables_tf
    foundation = _module_foundation(generate_golden_main_tf("app"))
    assert foundation["github_repository_id"] == "${var.github_repository_id}"
    assert foundation["github_repo_full_name"] == "${var.github_repo_full_name}"
    var = _variables(generate_golden_variables_tf("app"))["github_repository_id"]
    assert var["default"] == "" and var["type"] == "string"


@pytest.mark.parametrize("arch", ["cloudrun", "gce-bastion", "gke-autopilot", "event-worker", "foundation-only",
                                  "unknown-archetype"])
def test_root_additions_are_exactly_the_normalized_ones(monkeypatch, arch):
    """tests/fd4atc_render.py strips exactly what FD-4AT-c adds, once per render, so the older byte-identity pins that
    use it still prove nothing else changed."""
    monkeypatch.setenv("GITHUB_ORG", "acme")
    import fd4atc_render as fr
    from developer_agent.terraform_engine import generate_golden_main_tf, generate_golden_variables_tf
    main = generate_golden_main_tf("shop", arch, "")
    assert main.count(fr.FOUNDATION_ARG_LINE) == 1
    assert main.index(fr.FOUNDATION_ARG_LINE) == \
        main.index("  github_repo_full_name = var.github_repo_full_name\n") + len("  github_repo_full_name = var.github_repo_full_name\n")
    variables = generate_golden_variables_tf("shop", "acme/shop")
    assert variables.count(fr.VARIABLE_BLOCK) == 1
    assert "github_repository_id" not in fr.without_fd4atc(main) + fr.without_fd4atc(variables)


def test_express_root_forwards_the_input_with_an_empty_default():
    from shared.express_synthesizer import ExpressHCLSynthesizer
    files = ExpressHCLSynthesizer().synthesize_workload(
        product_id="express-demo", project_id="castor-express-demo-1234", github_repo_full_name="acme/castor-express-demo",
        module_instances=[{"module_id": "compute-cloudrun", "instance_name": "gateway", "parameters": {}}],
        state_bucket="castor-tfstate-1234")
    main = next(v for k, v in files.items() if k.endswith("infra/workload/main.tf"))
    variables = next(v for k, v in files.items() if k.endswith("infra/workload/variables.tf"))
    assert _module_foundation(main)["github_repository_id"] == "${var.github_repository_id}"
    assert _variables(variables)["github_repository_id"]["default"] == ""


def test_express_synthesizer_replicas_identical():
    root = _read("shared/express_synthesizer.py")
    for rel in ("apps/control-center/shared/express_synthesizer.py", "apps/orchestrator-gateway/shared/express_synthesizer.py"):
        assert _read(rel) == root, rel


# ------------------------------------------------------------------------------------------- developer prompt
def test_foundation_contract_text_is_unchanged():
    """The rendered contract (developer prompt grounding) is byte-identical to the pre-FD-4AT-c text."""
    from developer_agent import contract_inspector as ci
    expected = (
        '### Golden Module Contract: `workload-foundation/base` (source = "../modules/workload-foundation/base")\n'
        "- **Allowed Inputs**: additional_apis, base_apis, firestore_delete_protection, github_repo_full_name, "
        "product_id, project_id, region\n"
        "- **Allowed Outputs**: module.<name>.database_name, module.<name>.deployer_sa_email, "
        "module.<name>.docker_repo_id, module.<name>.wif_pool_name, module.<name>.wif_provider_name, "
        "module.<name>.workload_sa_email, module.<name>.workload_sa_id\n"
        "*CRITICAL: Never reference an output or input not explicitly listed above.*\n")
    try:
        on_disk = ci.get_golden_module_contract("workload-foundation/base", force_refresh=True)
        from unittest.mock import patch
        with patch.object(ci, "get_platform_modules_path", return_value=None):
            unmounted = ci.get_golden_module_contract("workload-foundation/base", force_refresh=True)
    finally:
        ci._CONTRACT_CACHE.pop("workload-foundation/base", None)
    assert on_disk == unmounted == expected
    assert "github_repository_id" in ci._EMBEDDED_MODULE_CONTRACTS["workload-foundation/base"]["inputs"]


def test_platform_only_inputs_hide_nothing_else():
    """Do No Harm: the filter names exactly these inputs; every other contract is unfiltered. PUSH-TO-PRIVATE adds
    compute-cloudrun push_service_accounts (platform-rendered from the typed intent); PUSH-SUB-RENDER adds
    messaging-pubsub push (rendered from the typed intent's closed push form); FD-4CI-b-R1-WIF adds
    workload-foundation/base github_default_branch (platform-rendered from the workload record); GHA-DEPLOY-SWITCH
    adds workload-foundation/base enable_github_actions_deploy (the record's switch, platform-rendered);
    IAP-GATE-KNOWN-MEMBER adds compute-cloudrun project_number (platform-rendered for Direct IAP);
    SECRET-INITIAL-VERSION adds security-secret generate_initial_version (rendered from the architect's topology)."""
    from developer_agent import contract_inspector as ci
    assert ci._PLATFORM_ONLY_INPUTS == {"workload-foundation/base": frozenset({"github_repository_id",
                                                                             "github_default_branch",
                                                                             "enable_github_actions_deploy"}),
                                        "compute-cloudrun": frozenset({"push_service_accounts", "project_number"}),
                                        "messaging-pubsub": frozenset({"push"}),
                                        "security-secret": frozenset({"generate_initial_version"})}

import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

"""FD-4CI-b-R1-WIF-SHARED (register row SAT-1031 approvals, owner 10-29; brief SAT-16): workloads that share one
GitHub repository (promoted workloads, environment branches) get their own deploy secrets.

Chain under test:
- shared.github_identity.branch_secret_suffix: the one rule for the branch-named secret suffix (vending's former
  inline `clean_br`), used by vending's redeploy (writer) and the generated workflow (reader); x6 copies identical.
- shared.github_identity.repository_shared_with_other_workload: the shared-repository check (moved from vending).
- handler.generate_service_workflow(branch_secrets=True) on a non-main branch reads GCP_PROJECT_ID_<B> /
  WIF_PROVIDER_<B> / WIF_SERVICE_ACCOUNT_<B> first, then everything it read before in the same order.
- DeveloperAgent._deploy_secrets_branch_named: vending's decision (non-main AND promoted / shared / unknown).
- Do No Harm: main renders and own-repository renders are byte-identical to the base (sha256 pinned from main
  3dfe3f73, before this change; the FD-4CI-b-R1-WIF pin 4b2d5967... is re-checked in test_r1_wif_default_branch.py).
Vending's redeploy names: tests/test_flexible_folders.py::test_r1wif_*.
"""
import ast
import hashlib
import os
import re
import sys
from types import SimpleNamespace

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from shared import github_identity as gi  # noqa: E402

ARCHETYPES = ("cloudrun", "event-worker", "gce-bastion", "gke-autopilot")
BRANCHES = ("main", "develop", "release/v1.2-rc")
# sha256 of generate_service_workflow("r1wif-app", "r1wif-app", "r1wif-app-1234", "123456789012", archetype=<a>,
# region="us-central1", branch=<b>) at main 3dfe3f73 (before this change). GHA-FIREBASE-ENV-NO-BLANK (deliberate): the
# three cloudrun pins are re-taken after the FIREBASE_* pair left the deploy flag; tests/test_gha_firebase_env_no_blank.py
# pins that the former renders (b6aeb662... / 2af2833e... / d867c3b5...) are today's with exactly that pair put back.
BASE_WORKFLOW_SHA256 = {
    "cloudrun:develop": "fa4998055bdb9c7687f46ec880b98df29ee2480295d26eadf6ac0c24ddc056fd",
    "cloudrun:main": "b7ca87422620b665a1be1294ea78e68866c3d841cb1f7f31e29765f93fa3a2dc",
    "cloudrun:release/v1.2-rc": "f2eeabced9bb027295229f749888f7cd1615b2d9e4dd98760c06b41b62966d3a",
    "event-worker:develop": "8bdc78fbcfb166776a9ea143d2db3f03e13369c8e192c4b90d6bb36e3f7f1380",
    "event-worker:main": "13280b5fb4f857e962df3de0aaeda4faf3b89d9e8a154a3e170746525d0bef33",
    "event-worker:release/v1.2-rc": "8e1118cca445ac5fa7c8acfdb6a748c57f7b4dfe86bf40ae7319cc4c1c6d38ec",
    "gce-bastion:develop": "7ef7cec842f2972dc25a42f090a38a6e6c0110c0ca36ce3de6d12cd42d3e6349",
    "gce-bastion:main": "782d4869f4f560bb4a36b0f84662aafd2910fb94fec8daff8bc8a81ed84a61de",
    "gce-bastion:release/v1.2-rc": "1267f47cb7487619671493697a8c0c2445534f1a40bc1fe1294b74a90c58482f",
    "gke-autopilot:develop": "2005a06d534a57368ddd32e6a6d93b66aeb2c40ec5c7bf60dc4dacbd9547dfc0",
    "gke-autopilot:main": "745b6e3d5a308b6d02b342fddd9b796b93cc3e285c69a8fafbb8114b1f3ba79f",
    "gke-autopilot:release/v1.2-rc": "2b835e6bd892c70ea3791c51d8b18986ea59a066192f34a4e4c154fcf44cdf21",
}
COPIES = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "apps/project-vending/shared",
          "apps/qa-runner/shared", "mcp-servers/terraform/shared"]


def handler():
    from developer_agent import handler as h
    return h


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _render(arch, branch, **kw):
    return handler().generate_service_workflow("r1wif-app", "r1wif-app", "r1wif-app-1234", "123456789012",
                                               archetype=arch, region="us-central1", branch=branch, **kw)


# ------------------------------------------------------------------------------------------------ shared rule
@pytest.mark.parametrize("branch,suffix", [
    ("prod", "PROD"), ("stage", "STAGE"), ("feature-x", "FEATURE_X"), ("release/v1.2-rc", "RELEASE_V1_2_RC"),
    ("a.b/c_d", "A_B_C_D"), ("Develop", "DEVELOP"), ("v2", "V2")])
def test_branch_secret_suffix_is_vendings_former_rule(branch, suffix):
    assert gi.branch_secret_suffix(branch) == suffix
    assert gi.branch_secret_suffix(branch) == re.sub(r"[^A-Z0-9_]", "_", branch.upper())   # the former inline rule


@pytest.mark.parametrize("bad", ["", None, 7, b"prod"])
def test_branch_secret_suffix_refuses_a_non_branch(bad):
    with pytest.raises(ValueError):
        gi.branch_secret_suffix(bad)


def test_github_identity_copies_are_identical():
    texts = {c: open(os.path.join(REPO, c, "github_identity.py"), encoding="utf-8").read() for c in COPIES}
    assert len(set(texts.values())) == 1, sorted(texts)


def test_vending_uses_the_shared_rule_and_check():
    """One rule: vending's redeploy computes the suffix with branch_secret_suffix and its shared-repository check
    delegates to repository_shared_with_other_workload (no inline [^A-Z0-9_] rewrite left)."""
    src = open(os.path.join(REPO, "apps", "project-vending", "vending.py"), encoding="utf-8").read()
    assert "[^A-Z0-9_]" not in src
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_write_deploy_secrets")
    assert any(isinstance(c, ast.Call) and getattr(c.func, "id", None) == "branch_secret_suffix" for c in ast.walk(fn))
    chk = next(n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_repository_shared_with_other_workload")
    assert any(isinstance(c, ast.Call) and getattr(c.func, "id", None) == "repository_shared_with_other_workload"
               for c in ast.walk(chk))


# ------------------------------------------------------------------------------------------------ the workflow
@pytest.mark.parametrize("arch", ARCHETYPES)
@pytest.mark.parametrize("branch", BRANCHES)
def test_without_branch_secrets_every_render_is_byte_identical_to_the_base(arch, branch):
    """Do No Harm: a workload on its own repository (any branch) and every main render are unchanged."""
    assert _sha(_render(arch, branch)) == BASE_WORKFLOW_SHA256[f"{arch}:{branch}"]
    assert _sha(_render(arch, branch, branch_secrets=False)) == BASE_WORKFLOW_SHA256[f"{arch}:{branch}"]


@pytest.mark.parametrize("arch", ARCHETYPES)
def test_main_with_branch_secrets_is_byte_identical_to_the_base(arch):
    """main always reads the plain names (the WIF-SHARED rule applies to non-main branches only)."""
    assert _sha(_render(arch, "main", branch_secrets=True)) == BASE_WORKFLOW_SHA256[f"{arch}:main"]


@pytest.mark.parametrize("arch", ARCHETYPES)
@pytest.mark.parametrize("branch,sfx", [("prod", "PROD"), ("develop", "DEVELOP"), ("release/v1.2-rc", "RELEASE_V1_2_RC")])
def test_a_shared_repository_branch_reads_the_branch_named_secrets_first(arch, branch, sfx):
    new = _render(arch, branch, branch_secrets=True)
    old = _render(arch, branch)
    adds = [f"secrets.GCP_PROJECT_ID_{sfx} || ", f"secrets.WIF_PROVIDER_{sfx} || ",
            f"secrets.WIF_SERVICE_ACCOUNT_{sfx} || "]
    for a in adds:
        assert new.count(a) == 1, a
    assert f"PROJECT_ID: ${{{{ secrets.GCP_PROJECT_ID_{sfx} || vars.GCP_PROJECT_ID || secrets.GCP_PROJECT_ID || " in new
    assert f'workload_identity_provider: "${{{{ secrets.WIF_PROVIDER_{sfx} || secrets.WIF_PROVIDER || ' in new
    assert f'service_account: "${{{{ secrets.WIF_SERVICE_ACCOUNT_{sfx} || secrets.WIF_SERVICE_ACCOUNT || ' in new
    stripped = new
    for a in adds:
        stripped = stripped.replace(a, "", 1)
    assert stripped == old   # nothing else changes; the fallbacks keep their order


def test_the_workflow_reads_exactly_the_names_vending_writes():
    """Vending writes {GCP_PROJECT_ID, WIF_PROVIDER, WIF_SERVICE_ACCOUNT}_<branch_secret_suffix(branch)>; the workflow
    reads those exact names."""
    for branch in ("prod", "release/v1.2-rc", "feature.x"):
        text = _render("cloudrun", branch, branch_secrets=True)
        read = set(re.findall(r"secrets\.([A-Z0-9_]+)", text))
        written = {f"{n}_{gi.branch_secret_suffix(branch)}" for n in gi.DEPLOY_SECRET_BASE_NAMES}
        assert written <= read


def test_a_shared_workflow_without_the_shared_module_is_refused(monkeypatch):
    monkeypatch.setattr(handler(), "branch_secret_suffix", None)
    with pytest.raises(RuntimeError):
        _render("cloudrun", "prod", branch_secrets=True)
    assert _sha(_render("cloudrun", "prod")) == _sha(_render("cloudrun", "prod", branch_secrets=False))
    assert _sha(_render("cloudrun", "main", branch_secrets=True)) == BASE_WORKFLOW_SHA256["cloudrun:main"]


def test_assembly_passes_the_decision_to_both_workflow_renders():
    with open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_assemble_tree")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and getattr(c.func, "id", None) ==
             "generate_service_workflow"]
    assert len(calls) == 2
    for c in calls:
        v = {k.arg: k.value for k in c.keywords}.get("branch_secrets")
        assert isinstance(v, ast.Attribute) and v.attr == "deploy_secrets_branch_named" and v.value.id == "inputs"
    assert handler().AssemblyInputs.__dataclass_fields__["deploy_secrets_branch_named"].default is False


# ------------------------------------------------------------------------------------------------ the decision
class _Doc:
    def __init__(self, pid, data):
        self.id = pid
        self._data = data

    def to_dict(self):
        return dict(self._data)


class _DB:
    def __init__(self, docs=None, error=None):
        self.docs = [_Doc(p, d) for p, d in (docs or [])]
        self.error = error
        self.streams = 0

    def collection(self, name):
        assert name == "workloads"
        return self

    def stream(self):
        self.streams += 1
        if self.error:
            raise self.error
        return list(self.docs)


def _decide(branch, repo="example-org/r1wif-app", promoted=None, db=None, owner="example-org", pid="r1wif-app-x"):
    me = SimpleNamespace(github_owner=owner)
    return handler().DeveloperAgent._deploy_secrets_branch_named(me, pid, branch, repo, promoted, db)


def test_decision_main_is_false_without_any_read():
    db = _DB([("r1wif-app", {"github_repo": "example-org/r1wif-app"})])
    assert _decide("main", db=db, promoted="r1wif-app") is False
    assert db.streams == 0


def test_decision_promoted_is_true_without_any_read():
    db = _DB()
    assert _decide("prod", promoted="r1wif-app", db=db) is True
    assert db.streams == 0


def test_decision_own_repository_is_false():
    """Do No Harm: a workload on its own repository (no other record names it) keeps the plain names."""
    db = _DB([("r1wif-app-x", {"github_repo": "example-org/r1wif-app"}),
              ("other", {"github_repo": "example-org/other"}), ("legacy", {"github_repo": {"full_name": "x/y"}}),
              ("nofield", {})])
    assert _decide("develop", db=db) is False
    assert db.streams == 1


@pytest.mark.parametrize("sibling", [{"github_repo": "Example-Org/R1WIF-App"},
                                     {"github_repo": {"full_name": "example-org/r1wif-app"}}])
def test_decision_repository_named_by_another_workload_is_true(sibling):
    assert _decide("stage", db=_DB([("r1wif-app", sibling)])) is True


def test_decision_sibling_without_github_repo_is_its_default_repository():
    assert _decide("develop", repo="example-org/other", db=_DB([("other", {})])) is True
    assert _decide("develop", repo="", db=_DB([("other", {})]), pid="other-2") is False   # o/other-2 is its own


def test_decision_unreadable_records_count_as_shared():
    assert _decide("develop", db=_DB(error=RuntimeError("firestore down"))) is True
    assert _decide("develop", db=None) is True


def test_decision_no_owner_counts_as_shared(monkeypatch):
    for k in ("GITHUB_ORG", "GITHUB_DEPLOYMENTS_ORG", "GITHUB_OWNER", "VCS_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    assert _decide("develop", repo="", owner=None, db=_DB()) is True


def test_shared_check_matches_vendings_former_semantics():
    """repository_shared_with_other_workload: self skipped, case-insensitive, dict records, missing field = default
    repository, unreadable = None."""
    f = gi.repository_shared_with_other_workload
    assert f(_DB([("a", {"github_repo": "o/r"})]), "a", "o/r", default_owner="o") is False
    assert f(_DB([("b", {"github_repo": "O/R"})]), "a", "o/r", default_owner="o") is True
    assert f(_DB([("b", {"github_repo": {"full_name": "o/r"}})]), "a", "o/r", default_owner="o") is True
    assert f(_DB([("r", {})]), "a", "o/r", default_owner="o") is True
    assert f(_DB(error=RuntimeError("x")), "a", "o/r", default_owner="o") is None
    assert f(None, "a", "o/r") is None
    assert f(_DB(), "a", "", default_owner="o") is None

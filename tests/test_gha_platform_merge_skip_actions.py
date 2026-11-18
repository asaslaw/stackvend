"""GHA-PLATFORM-MERGE-SKIP-ACTIONS (owner 11-16): the platform's own GitHub merges carry `[skip actions]`.

The gateway release auto-merge (`_release_merge`) and the Control Center approval merge (`_merge_workload_pr`) are
each followed by the platform's own build and apply. Their merge commit used to start the workload repo's push-to-main
Actions Day-2 deploy about 3 s later, before the first apply had created the WIF pool (invalid_target red X on every
new repo) or, on a re-run, racing the apply. GitHub's documented directive in the merge commit's message stops that
run. Diagnosis: docs/handoff/gha-first-push-wif-diagnosis.md.

Checked here:
- one shared constant + helper in shared/vcs_ledger.py (byte-identical in the gateway and CC copies), used by both
  call sites; no second copy of the directive text in either service;
- both GitHub merge paths send a commit message that is the old message + "\\n\\n[skip actions]" (exactly once), with
  every other merge argument unchanged;
- through the REAL GitHubProvider and the REAL PyGithub PullRequest.merge, the PUT body carries the directive in
  `commit_message` (squash: GitHub's commit title stays the PR title, the message body is this text) and still
  `merge_method=squash` + `sha=<ledger head>` and no `commit_title`;
- Do No Harm: both Serverless Git merge paths send the message byte-identical to before.
The Control Center merge tests are in tests/test_gha_platform_merge_skip_actions_cc.py (test_approvals.py's
import-time stubs cannot share a module with the gateway release fixture).
Hermetic: in-memory Firestore fakes, MagicMock / fake VCS providers, a MagicMock PyGithub requester; no network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import hashlib
import importlib
import os
import sys
import types
from unittest.mock import MagicMock

import pytest

from fd4f_support import SHA_A, gw, load_gateway  # noqa: F401
from fd4g_support import real_modules
from test_fd4f_release_evidence import BRANCH, _evidence, _promote, rel  # noqa: F401

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIRECTIVE = "[skip actions]"
LEDGER_COPIES = ("shared/vcs_ledger.py", "apps/control-center/shared/vcs_ledger.py",
                 "apps/orchestrator-gateway/shared/vcs_ledger.py")
CALL_SITES = ("apps/orchestrator-gateway/main.py", "apps/control-center/routes/approvals.py")


def _ledger():
    from shared import vcs_ledger

    return vcs_ledger


# ============================================================================ the shared constant
def test_directive_constant_is_githubs_documented_text():
    assert _ledger().PLATFORM_MERGE_SKIP_ACTIONS == DIRECTIVE


def test_helper_appends_the_directive_once_after_a_blank_line():
    msg = "feat(app): automated release merge into main by StackVend"
    out = _ledger().github_platform_merge_message(msg)
    assert out == f"{msg}\n\n{DIRECTIVE}"
    assert out.count(DIRECTIVE) == 1 and out.startswith(msg)


@pytest.mark.parametrize("bad", ["", None, 7, b"bytes"])
def test_helper_refuses_a_missing_message_loudly(bad):
    with pytest.raises(ValueError):
        _ledger().github_platform_merge_message(bad)


def test_ledger_copies_are_byte_identical():
    digests = {p: hashlib.sha256(open(os.path.join(REPO_ROOT, p), "rb").read()).hexdigest() for p in LEDGER_COPIES}
    assert len(set(digests.values())) == 1, digests


def _calls_to(tree, attr):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == attr]


@pytest.mark.parametrize("path", CALL_SITES)
def test_call_sites_use_the_shared_helper_and_hold_no_copy_of_the_text(path):
    src = open(os.path.join(REPO_ROOT, path), encoding="utf-8").read()
    tree = ast.parse(src)
    helper_calls = _calls_to(tree, "github_platform_merge_message")
    assert len(helper_calls) == 1, path  # exactly one platform GitHub merge per service
    assert all(isinstance(c.func.value, ast.Name) and c.func.value.id == "vcs_ledger" for c in helper_calls), path
    literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert not [s for s in literals if DIRECTIVE in s], path  # the text lives only in shared/vcs_ledger.py
    # The helper's result goes straight into the provider merge's commit_message (GitHub branch only).
    merges = [c for c in _calls_to(tree, "merge_pull_request")
              if any(k.arg == "commit_message" and isinstance(k.value, ast.Call)
                     and getattr(k.value.func, "attr", None) == "github_platform_merge_message" for k in c.keywords)]
    assert len(merges) == 1 and any(k.arg == "expected" for k in merges[0].keywords), path


# ============================================================================ gateway: _release_merge
class _Vcs:
    def __init__(self, result):
        self.result, self.calls = result, []

    def merge_pull_request(self, repo, **kwargs):
        self.calls.append((repo, kwargs))
        return self.result


def _entry(**over):
    e = {"ledger_id": "lid-1", "repo_full_name": "o/r", "branch": BRANCH, "base_branch": "main", "head_sha": SHA_A,
         "pr_number": 7, "repo_id": 77, "provider": "GITHUB"}
    e.update(over)
    return e


def test_gateway_github_merge_sends_the_directive(gw, monkeypatch):
    vcs = _Vcs({"status": "MERGED", "merged": True, "pr_number": 7})
    monkeypatch.setattr(gw, "_release_vcs", lambda kind, pid, repo: vcs)
    gw._release_merge("GITHUB", _entry(), "app", "msg")
    ((repo, kwargs),) = vcs.calls
    assert repo == "o/r" and set(kwargs) == {"expected", "commit_message"}  # nothing else added
    assert kwargs["commit_message"] == f"msg\n\n{DIRECTIVE}"
    exp = kwargs["expected"]
    assert (exp.pr_number, exp.branch, exp.base_branch, exp.head_sha, exp.repo_id) == (7, BRANCH, "main", SHA_A, 77)


def test_negative_gateway_serverless_merge_message_is_byte_identical(gw, monkeypatch):
    vcs = _Vcs({"status": "MERGED", "merged": True, "commit_sha": "c0ffee", "source_sha_checked": True})
    monkeypatch.setattr(gw, "_release_vcs", lambda kind, pid, repo: vcs)
    msg = "feat(app): automated release merge into main by StackVend"
    gw._release_merge("SERVERLESS_GIT", _entry(provider="SERVERLESS_GIT", pr_number=None, repo_id=None), "app", msg)
    ((_, kwargs),) = vcs.calls
    assert kwargs["commit_message"] == msg and DIRECTIVE not in kwargs["commit_message"]
    assert kwargs == {"pr_number": 0, "commit_message": msg, "source_branch": BRANCH, "target_branch": "main",
                      "expected_source_sha": SHA_A}


def test_gateway_release_promote_auto_merge_carries_the_directive(rel):
    """End to end through /agent/release/promote: the auto-merge's message is the old one plus the directive."""
    gw, db, merge, _ = rel
    db.docs["qa_test_runs/tr-1"] = _evidence()
    r = _promote(gw, expected_commit_sha=SHA_A)
    assert r.status_code == 200 and r.json()["auto_merged"] is True, r.text
    merge.assert_called_once()
    assert set(merge.call_args.kwargs) == {"expected", "commit_message"}
    assert merge.call_args.kwargs["commit_message"] == (
        f"feat(app): automated release merge into main by StackVend\n\n{DIRECTIVE}")


# ============================================================================ real provider + real PyGithub
def _real_pygithub_pull_request(monkeypatch):
    """The REAL github.PullRequest class. fd4g_support.real_modules sets aside another test module's MagicMock stubs
    of `github` (and the web stack) for this test and, at teardown, pops every stack module first imported during
    it (the real `github.*` included), so no stub package is left mixed with real submodules."""
    real_modules(monkeypatch)
    return importlib.import_module("github.PullRequest").PullRequest


def _live(monkeypatch, ledger, *, repo_id=77, full_name="o/r", branch=BRANCH, head_sha=SHA_A):
    """The REAL GitHubProvider over a REAL PyGithub PullRequest whose requester only records (no network). The
    provider must come from the same `shared` module graph as `ledger` (the caller's bound vcs_ledger), or its
    PRIdentity check would compare two copies of the class."""
    PullRequest = _real_pygithub_pull_request(monkeypatch)
    requester = MagicMock(name="requester", base_url="https://api.github.com", is_not_lazy=True, is_lazy=False)
    requester.requestJsonAndCheck.return_value = ({}, {"merged": True, "sha": "m" * 40, "message": "ok"})
    repo_attrs = {"id": repo_id, "full_name": full_name, "url": f"https://api.github.com/repos/{full_name}"}
    pr = PullRequest(requester, {}, {
        "url": f"https://api.github.com/repos/{full_name}/pulls/7", "number": 7, "state": "open", "merged": False,
        "title": "feat(app): automated implementation by StackVend Developer Agent",
        "user": {"id": 31337, "type": "Bot", "login": "stackvend[bot]"},
        "head": {"ref": branch, "sha": head_sha, "repo": repo_attrs},
        "base": {"ref": "main", "sha": "f" * 40, "repo": repo_attrs}}, completed=True)
    repo = types.SimpleNamespace(id=repo_id, full_name=full_name, get_pull=lambda n: pr,
                                 get_git_ref=lambda name: (_ for _ in ()).throw(RuntimeError("404 ref")))
    prov_mod = importlib.import_module(ledger.__name__.rsplit(".", 1)[0] + ".providers.github_provider")
    assert prov_mod.PRIdentity is ledger.PRIdentity, "provider and ledger come from different `shared` graphs"
    prov = prov_mod.GitHubProvider(project_id="", github_token="test-token", default_owner="o")
    prov._get_repo = lambda _ident: repo
    prov.actor_identity = lambda: (31337, "Bot")
    return prov, requester


@pytest.fixture()
def gw_one_graph(monkeypatch):
    """The gateway bound to the `shared` modules that sys.modules holds now. After an earlier test module's teardown
    (fd4g_support.real_modules pops the `shared.*` modules its tests imported) the `shared` package can keep an
    attribute such as `vcs_ledger` that points at a popped module, and `from shared import vcs_ledger` reads that
    attribute first: the gateway would bind a ledger whose PRIdentity is not the one the provider imports. Such stale
    submodule attributes are set aside for this test (monkeypatch restores them), so the gateway re-imports them from
    the current graph; modules imported here are popped at teardown (real_modules inside load_gateway)."""
    pkg = sys.modules.get("shared")
    if pkg is not None:
        for attr, val in list(vars(pkg).items()):
            if (isinstance(val, types.ModuleType) and val.__name__ == f"shared.{attr}"
                    and sys.modules.get(val.__name__) is not val):
                monkeypatch.delattr(pkg, attr)
    mod = load_gateway(monkeypatch, name="gha_skip_actions_gw_main")
    yield mod
    mod.app.dependency_overrides.clear()


def _put_bodies(requester):
    return [c.kwargs["input"] for c in requester.requestJsonAndCheck.call_args_list
            if c.args[0] == "PUT"]


def test_real_provider_squash_merge_put_body_carries_the_directive(gw_one_graph, monkeypatch):
    gw = gw_one_graph
    prov, requester = _live(monkeypatch, gw.vcs_ledger)
    monkeypatch.setattr(gw, "_release_vcs", lambda kind, pid, repo: prov)
    res = gw._release_merge("GITHUB", _entry(), "app", "feat(app): automated release merge into main by StackVend")
    assert res["merged"] is True
    (body,) = _put_bodies(requester)
    # Unchanged arguments: squash at the ledger head SHA, no commit_title (GitHub keeps the PR title "(#7)" as the
    # squash commit title; commit_message becomes the commit body, i.e. part of the head commit's message).
    assert body == {"commit_message": f"feat(app): automated release merge into main by StackVend\n\n{DIRECTIVE}",
                    "merge_method": "squash", "sha": SHA_A}
    assert body["commit_message"].count(DIRECTIVE) == 1


"""FD-7L Phase 4 (SAT-30) red team L1: the `/runner/repo-token` answer contract between vending and the runner.

Vending (`apps/project-vending/vending.py` `mint_repository_read_token`) verifies GitHub's ACTUAL grant: `contents: read`
plus at most `metadata: read` (GitHub adds it to every installation token) and exactly the pinned repository. The broker
(`runner_broker.py` `RunnerBroker.repo_token`) then answers the runner with the FIXED claim
`{"repository": <pin>, "permissions": {"contents": "read"}}`, and the runner (`mcp-servers/terraform/runner_credentials.py`
`check_repo_token_answer`) requires exactly that claim.

So the runner check is defence in depth against a changed vending, and the two sides form one cross-service contract:
**vending must keep echoing exactly `contents: read` and must never pass GitHub's real `permissions` through** (it
contains `metadata: read`, which the runner refuses: every Per-workload GitHub read would stop with
RUNNER_TARGET_MISMATCH). These tests pin both sides; a change to either breaks them first.

Hermetic: vending's World fakes (tests/test_fd7l_vending_runner_identity.py), GitHub answered by a fake; no network.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys

import pytest

from test_destructive_guard_vending import vmain, _freeze_setting_without_firestore  # noqa: F401  (fixtures)
from test_fd7l_vending_runner_identity import (  # noqa: F401  (fixture `w` and helpers)
    APP, _GH, _gh_engine, _ready, _session, k, w,
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PINNED = "acme/castor-shop-api"            # the World's pinned GitHub repository


@pytest.fixture
def rc():
    """The runner's mcp-servers/terraform/runner_credentials.py (loaded by path; it imports `shared.runner_identity`)."""
    path = os.path.join(REPO_ROOT, "mcp-servers", "terraform", "runner_credentials.py")
    spec = importlib.util.spec_from_file_location("sat30_contract_runner_credentials", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.modules.pop(spec.name, None)


def _engine_class(vmain):
    return vmain.ProjectRepoVendingEngine


def test_the_permission_constants_agree(rc, vmain):
    """What vending ASKS GitHub for is exactly what the runner accepts; what vending ACCEPTS from GitHub has the same
    `contents` grant (plus only GitHub's implicit `metadata: read`)."""
    eng = _engine_class(vmain)
    assert rc.REPO_TOKEN_PERMISSIONS == eng.RUNNER_REPO_TOKEN_PERMISSIONS == {"contents": "read"}
    assert eng.RUNNER_REPO_TOKEN_ALLOWED_ANSWER == dict(rc.REPO_TOKEN_PERMISSIONS, metadata="read")


def test_github_grant_with_metadata_reaches_the_runner_as_exactly_contents_read(rc, vmain, w):
    """The whole chain with GitHub's real answer shape: GitHub grants contents:read + metadata:read -> vending's mint
    accepts it -> the broker answers exactly contents:read -> the runner's check passes."""
    eng = _gh_engine(vmain, APP)
    github = _GH()                                                # permissions: contents read + metadata read
    assert github.json()["permissions"] == {"contents": "read", "metadata": "read"}
    w.deps.github_repo_token = lambda name, rid: eng.mint_repository_read_token(
        name, rid, http_post=lambda url, headers, json: github)
    _ready(w)
    _exe, key = _session(w)
    answer = w.broker().repo_token(k.RUNNER_SA, key)
    assert answer["permissions"] == rc.REPO_TOKEN_PERMISSIONS     # never GitHub's own permissions
    assert answer["repository"] == PINNED
    rc.check_repo_token_answer({kk: v for kk, v in answer.items() if kk != "token"}, PINNED)


def test_passing_githubs_real_permissions_through_would_stop_every_read(rc):
    """The trap the contract guards against: if vending ever forwarded GitHub's `permissions` (always with
    `metadata: read`), the runner would refuse every Per-workload GitHub read (fail closed, RUNNER_TARGET_MISMATCH)."""
    with pytest.raises(rc.ri.RunnerIdentityError) as e:
        rc.check_repo_token_answer({"repository": PINNED, "permissions": {"contents": "read", "metadata": "read"}},
                                   PINNED)
    assert e.value.code == "RUNNER_TARGET_MISMATCH"

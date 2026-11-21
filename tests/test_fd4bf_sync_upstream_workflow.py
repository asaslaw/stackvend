"""FD-4BF-a: Tests for opt-in, tag-based upstream sync workflow and helpers."""
from __future__ import annotations

import hermetic_guard  # noqa: F401  (must stay the first import: tests/test_hermetic_guard.py)

import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import unicodedata
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from owner_identifiers import find as find_owner_identifiers

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "sync-upstream.yml"
SCRIPT_PATH = REPO_ROOT / "scripts" / "sync_upstream_needs_apply.py"
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
README_PATH = REPO_ROOT / "README.md"
KNOWN_LIMITATIONS_PATH = REPO_ROOT / "documentation" / "known-limitations.md"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("sync_upstream_needs_apply", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sync_mod = _load_script_module()


def _load_workflow() -> dict[Any, Any]:
    raw = WORKFLOW_PATH.read_text(encoding="utf-8")
    loaded = yaml.safe_load(raw)
    assert isinstance(loaded, dict)
    return loaded


def _workflow_triggers(wf: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML 1.1 parses bare `on` as boolean True.
    triggers = wf.get("on") if "on" in wf else wf.get(True)
    assert isinstance(triggers, dict)
    return triggers


def _get_step_by_name(wf: dict[Any, Any], job_name: str, step_name: str) -> dict[str, Any]:
    steps = wf["jobs"][job_name]["steps"]
    for step in steps:
        if step.get("name") == step_name:
            return step
    raise AssertionError(f"Step {step_name!r} not found in job {job_name!r}")


def _parse_github_output(output_file: Path) -> dict[str, str]:
    if not output_file.exists():
        return {}
    result: dict[str, str] = {}
    for line in output_file.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            result[k] = v
    return result


def _eval_sync_job_if(
    if_expr: str,
    *,
    upstream_sync: str = "",
    upstream_repo: str = "",
    github_repository: str = "consumer-org/stackvend",
) -> bool:
    """Evaluate the job-level `if:` clauses of `jobs.sync-upstream`.

    Note (F4): GitHub Actions' `==` / `!=` and `contains()` operators are
    case-insensitive. Exact case-sensitive `'true'` enforcement is performed by
    the bash step (`[ "${UPSTREAM_SYNC}" != "true" ]`), tested separately.
    """
    clauses = [c.strip() for c in if_expr.split("&&")]
    expected_clauses = {
        "vars.STACKVEND_UPSTREAM_SYNC == 'true'",
        "vars.STACKVEND_UPSTREAM_REPO != ''",
        "contains(vars.STACKVEND_UPSTREAM_REPO, '/')",
        "github.repository != vars.STACKVEND_UPSTREAM_REPO",
    }
    assert set(clauses) == expected_clauses
    return (
        upstream_sync.lower() == "true"
        and upstream_repo != ""
        and ("/" in upstream_repo.lower())
        and github_repository.lower() != upstream_repo.lower()
    )


def test_workflow_triggers_and_top_level_env():
    wf = _load_workflow()
    triggers = _workflow_triggers(wf)
    assert "schedule" in triggers
    assert "workflow_dispatch" in triggers

    env = wf.get("env")
    assert isinstance(env, dict)
    assert env.get("UPSTREAM_SYNC") == "${{ vars.STACKVEND_UPSTREAM_SYNC }}"
    assert env.get("UPSTREAM_REPO") == "${{ vars.STACKVEND_UPSTREAM_REPO }}"


def test_workflow_permissions_are_minimal():
    wf = _load_workflow()
    perms = wf.get("permissions")
    assert perms == {"contents": "write", "pull-requests": "write"}
    assert set(perms.keys()) <= {"contents": "write", "pull-requests": "write"}.keys()

    # F8: sync-notice has empty permissions: {}
    jobs = wf.get("jobs", {})
    assert jobs["sync-notice"].get("permissions") == {}

    for job_name, job in jobs.items():
        if "permissions" in job:
            assert set(job["permissions"].keys()) <= {"contents", "pull-requests"}, job_name


def test_sync_job_if_guard_and_case_sensitivity_layers():
    wf = _load_workflow()
    jobs = wf.get("jobs", {})
    assert "sync-upstream" in jobs
    if_expr = jobs["sync-upstream"].get("if", "")
    assert "vars.STACKVEND_UPSTREAM_SYNC == 'true'" in if_expr
    assert "github.repository != vars.STACKVEND_UPSTREAM_REPO" in if_expr
    assert "vars.STACKVEND_UPSTREAM_REPO != ''" in if_expr

    # Positive case at the GitHub `if:` layer: opt-in == 'true', valid upstream repo, running in fork.
    assert _eval_sync_job_if(
        if_expr,
        upstream_sync="true",
        upstream_repo="example-org/stackvend",
        github_repository="consumer-org/stackvend",
    )

    # F4: GitHub's `==` in `if:` is case-insensitive, so 'TRUE' and 'True' pass the `if:` expression
    # and are then blocked by the case-sensitive bash step (`[ "${UPSTREAM_SYNC}" != "true" ]`).
    for case_variant in ("TRUE", "True"):
        assert _eval_sync_job_if(
            if_expr,
            upstream_sync=case_variant,
            upstream_repo="example-org/stackvend",
            github_repository="consumer-org/stackvend",
        )

    # Negative cases blocked already at the `if:` layer: unset, false, 1, yes, on, empty/non-slash repo, or matching upstream.
    for bad_sync in ("", "false", "1", "yes", "on"):
        assert not _eval_sync_job_if(
            if_expr,
            upstream_sync=bad_sync,
            upstream_repo="example-org/stackvend",
            github_repository="consumer-org/stackvend",
        )
    assert not _eval_sync_job_if(
        if_expr,
        upstream_sync="true",
        upstream_repo="",
        github_repository="consumer-org/stackvend",
    )
    assert not _eval_sync_job_if(
        if_expr,
        upstream_sync="true",
        upstream_repo="not-a-slug",
        github_repository="consumer-org/stackvend",
    )
    assert not _eval_sync_job_if(
        if_expr,
        upstream_sync="true",
        upstream_repo="example-org/stackvend",
        github_repository="example-org/stackvend",
    )


def test_workflow_has_notice_step_explaining_how_to_enable():
    wf = _load_workflow()
    jobs = wf.get("jobs", {})
    assert "sync-notice" in jobs
    notice_job = jobs["sync-notice"]
    assert "if" not in notice_job
    notice_runs = "\n".join(step.get("run", "") for step in notice_job.get("steps", []))
    assert "gh variable set STACKVEND_UPSTREAM_SYNC --body true" in notice_runs
    assert "gh variable set STACKVEND_UPSTREAM_REPO" in notice_runs


def test_workflow_contains_no_hardcoded_owner_or_repo_slug_and_deduplicates_validator():
    raw = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert find_owner_identifiers(raw) == []
    assert "STACKVEND_UPSTREAM_REPO" in raw
    assert "github.com/${UPSTREAM_REPO}.git" in raw

    # F8: slug validator lives in one place (`scripts/sync_upstream_needs_apply.py`), not inline in YAML.
    assert "allowed = set(" not in raw
    assert "<<'PY'" not in raw
    assert "--validate-slug" in raw

    wf = _load_workflow()
    for job in wf.get("jobs", {}).values():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if uses:
                # F8: do not pin exact checkout major version in test
                assert uses.startswith("actions/checkout@")
            run_script = step.get("run", "")
            for token in run_script.split():
                if "github.com/" in token:
                    assert "${UPSTREAM_REPO}" in token, f"Hardcoded github.com URL token: {token}"


def test_f3a_no_github_expression_inside_any_run_script():
    wf = _load_workflow()
    for job_name, job in wf.get("jobs", {}).items():
        for step in job.get("steps", []):
            run_script = step.get("run", "")
            assert "${{" not in run_script, (
                f"Job {job_name!r} step {step.get('name')!r} contains '${{{{' inside `run:`"
            )


def test_f3b_workflow_calls_script_for_tag_selection_no_inline_grep_or_sort():
    wf = _load_workflow()
    step = _get_step_by_name(wf, "sync-upstream", "Fetch, Verify and Check Ancestry of the Newest Upstream Release Tag")
    run_script = step["run"]
    assert "scripts/sync_upstream_needs_apply.py --latest-tag" in run_script
    assert "refs/upstream-tags" in run_script
    assert "grep" not in run_script
    assert "sort" not in run_script


_SLUG_ERR = "STACKVEND_UPSTREAM_REPO is unset or not an exact owner/repo slug"
_OFF = "Upstream sync is OFF"


def _notice_enabled(repo: str) -> str:
    return f"Upstream sync is enabled for {repo} (the sync-upstream job validates the exact slug)."


# The notice job has no checkout, so it can only mirror the job-level `if:` (non-empty, contains '/',
# not the upstream itself); the exact slug check is the "Validate Upstream Slug" step's job.
@pytest.mark.parametrize(
    "upstream_sync,upstream_repo,github_repo,expect_valid,expected_substring,notice_substring",
    [
        (None, None, "consumer-org/stackvend", False, _OFF, _OFF),
        ("", "example-org/stackvend", "consumer-org/stackvend", False, _OFF, _OFF),
        ("false", "example-org/stackvend", "consumer-org/stackvend", False, _OFF, _OFF),
        ("TRUE", "example-org/stackvend", "consumer-org/stackvend", False, _OFF, _OFF),
        ("True", "example-org/stackvend", "consumer-org/stackvend", False, _OFF, _OFF),
        ("true", "", "consumer-org/stackvend", False, _SLUG_ERR, _SLUG_ERR),
        ("true", "not-a-slug", "consumer-org/stackvend", False, _SLUG_ERR, _SLUG_ERR),
        ("true", "example-org/stackvend; rm -rf /", "consumer-org/stackvend", False, _SLUG_ERR, _notice_enabled("example-org/stackvend; rm -rf /")),
        ("true", "../evil/repo", "consumer-org/stackvend", False, _SLUG_ERR, _notice_enabled("../evil/repo")),
        ("true", "example-org/stackvend.git", "consumer-org/stackvend", False, _SLUG_ERR, _notice_enabled("example-org/stackvend.git")),
        ("true", "example-org/stackvend", "example-org/stackvend", False, "current repository matches STACKVEND_UPSTREAM_REPO", "current repository matches STACKVEND_UPSTREAM_REPO"),
        ("true", "example-org/stackvend", "consumer-org/stackvend", True, "", _notice_enabled("example-org/stackvend")),
    ],
)
def test_f3c_plain_shell_validation_steps_execute_over_env_matrix(
    tmp_path: Path,
    upstream_sync: str | None,
    upstream_repo: str | None,
    github_repo: str,
    expect_valid: bool,
    expected_substring: str,
    notice_substring: str,
):
    wf = _load_workflow()
    notice_script = _get_step_by_name(wf, "sync-notice", "Log Upstream Sync Status")["run"]
    validate_script = _get_step_by_name(wf, "sync-upstream", "Validate Upstream Slug")["run"]

    gh_output = tmp_path / "github_output.txt"
    extra_env: dict[str, str] = {
        "GITHUB_REPOSITORY": github_repo,
        "GITHUB_OUTPUT": str(gh_output),
        "HOME": str(tmp_path),
    }
    if upstream_sync is not None:
        extra_env["UPSTREAM_SYNC"] = upstream_sync
    if upstream_repo is not None:
        extra_env["UPSTREAM_REPO"] = upstream_repo

    drop_keys: list[str] = []
    if upstream_sync is None:
        drop_keys.append("UPSTREAM_SYNC")
    if upstream_repo is None:
        drop_keys.append("UPSTREAM_REPO")
    env = hermetic_guard.child_env(drop=drop_keys, extra=extra_env)

    # The notice job has no checkout: run it in an empty directory, as on the GitHub runner.
    no_checkout = tmp_path / "no_checkout"
    no_checkout.mkdir()
    res_notice = subprocess.run(
        ["bash", "-eo", "pipefail"],
        input=notice_script,
        text=True,
        capture_output=True,
        cwd=no_checkout,
        env=env,
        check=True,
    )
    assert notice_substring in res_notice.stdout
    assert res_notice.stdout.count("\n") == 1  # exactly one log line

    gh_output.write_text("", encoding="utf-8")
    res_validate = subprocess.run(
        ["bash", "-eo", "pipefail"],
        input=validate_script,
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        env=env,
        check=True,
    )
    outputs = _parse_github_output(gh_output)
    assert outputs.get("valid") == ("true" if expect_valid else "false")
    if not expect_valid:
        assert expected_substring in res_validate.stdout


def test_workflow_is_pr_only_and_never_pushes_main_or_merges():
    wf = _load_workflow()
    all_runs: list[str] = []
    for job in wf.get("jobs", {}).values():
        for step in job.get("steps", []):
            if "run" in step:
                all_runs.append(step["run"])
    combined = "\n".join(all_runs)

    # Must not merge PRs or enable auto-merge.
    assert "gh pr merge" not in combined
    assert "--auto" not in combined

    # Must not fetch or merge upstream/main (tag-based only).
    assert "upstream/main" not in combined
    assert "git fetch upstream main" not in combined
    assert 'git merge-base --is-ancestor "${TAG_COMMIT}" HEAD' in combined  # FD-104: the verified commit
    # FD-104 review 2: the existing-PR lookup is the REST list, filtered on the server by base and owner:branch head.
    assert 'gh api "repos/${GITHUB_REPOSITORY}/pulls" -X GET --paginate' in combined
    assert '-f head="${GITHUB_REPOSITORY_OWNER}:${BRANCH_NAME}"' in combined
    assert "gh pr create" in combined

    # Inspect every `git ... push` command (continuation lines joined) to ensure it pushes only the sync branch,
    # by its full ref name, never main or HEAD:main (FD-104: the token comes from a per-command credential helper).
    git_commands = [
        shlex.split(line.strip())
        for line in combined.replace("\\\n", " ").splitlines()
        if line.strip().startswith("git ")
    ]
    push_commands = [argv for argv in git_commands if "push" in argv]
    assert len(push_commands) == 1
    push = push_commands[0]
    assert push[push.index("push"):] == [
        "push", "--force-with-lease", "origin", "refs/heads/${BRANCH_NAME}:refs/heads/${BRANCH_NAME}",
    ]
    for forbidden in ("main", "HEAD:main", "HEAD:refs/heads/main", "origin main"):
        assert forbidden not in " ".join(push)


RELEASE_PRINCIPAL = "stackvend-release"
_SIGNERS_REL = "scripts/release/allowed_signers"


@pytest.fixture(scope="session")
def sync_keys(tmp_path_factory) -> dict[str, str]:
    """Throwaway ed25519 keys made here (never a real key): `release` (in the fork's allowed_signers) and
    `attacker` (not in it). Same pattern as tests/test_release_onto.py `keys`."""
    if shutil.which("ssh-keygen") is None:
        pytest.skip("needs ssh-keygen")
    d = tmp_path_factory.mktemp("fd104-keys")
    out: dict[str, str] = {}
    for name in ("release", "attacker"):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"fd104-test-{name}", "-f", str(d / name)],
            check=True, capture_output=True, env=hermetic_guard.child_env(extra={"HOME": str(d)}),
        )
        out[name] = str(d / name)
        out[f"{name}_pub"] = (d / f"{name}.pub").read_text(encoding="utf-8").strip()
    return out


def _signers_line(pub: str, principal: str = RELEASE_PRINCIPAL) -> str:
    return f"{principal} {pub}\n"


def _sign_tag(repo: Path, env: dict[str, str], key: str, name: str, target: str = "HEAD",
              message: str | None = None, signed: bool = True) -> str:
    """An annotated tag, SSH-signed with `key` (or unsigned with signed=False); returns the tag object id."""
    subprocess.run(
        ["git", "-c", "gpg.format=ssh", "-c", f"user.signingkey={key}", "-c", "gpg.ssh.program=ssh-keygen",
         "tag", "-s" if signed else "-a", name, target, "-m", message or f"StackVend {name}"],
        cwd=repo, env=env, check=True, capture_output=True,
    )
    return _git(repo, env, "rev-parse", f"refs/tags/{name}").strip()


def _init_scratch_upstream_and_fork(
    tmp_path: Path, keys: dict[str, str] | None = None
) -> tuple[Path, Path, dict[str, str]]:
    """Create a local upstream repo and a fork repo with git URL rewrite to local upstream.

    With `keys`, the shared history commits `scripts/release/allowed_signers` naming the release key (FD-104: the
    fork's own committed signer list)."""
    home_dir = tmp_path / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    upstream_dir = tmp_path / "upstream"
    fork_dir = tmp_path / "fork"
    upstream_dir.mkdir()
    fork_dir.mkdir()

    env = hermetic_guard.child_env(
        extra={
            "HOME": str(home_dir),
            "GIT_AUTHOR_NAME": "Test User",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test User",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
    )

    subprocess.run(["git", "init", "-b", "main"], cwd=upstream_dir, env=env, check=True, capture_output=True)
    (upstream_dir / "README.md").write_text("base\n", encoding="utf-8")
    (upstream_dir / "infra" / "platform").mkdir(parents=True)
    (upstream_dir / "infra" / "platform" / "main.tf").write_text("# main\n", encoding="utf-8")
    (upstream_dir / "infra" / "platform" / "legacy.tf").write_text("# legacy\n", encoding="utf-8")
    if keys is not None:
        (upstream_dir / "scripts" / "release").mkdir(parents=True)
        (upstream_dir / _SIGNERS_REL).write_text(_signers_line(keys["release_pub"]), encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=upstream_dir, env=env, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=upstream_dir, env=env, check=True, capture_output=True)
    if keys is not None:
        _sign_tag(upstream_dir, env, keys["release"], "v1.0.0")
    else:
        subprocess.run(["git", "tag", "v1.0.0"], cwd=upstream_dir, env=env, check=True)

    subprocess.run(
        ["git", "clone", "-b", "main", f"file://{upstream_dir}", str(fork_dir)],
        env=env,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "git",
            "config",
            f"url.file://{upstream_dir}.insteadOf",
            "https://github.com/example-org/stackvend.git",
        ],
        cwd=fork_dir,
        env=env,
        check=True,
    )
    (fork_dir / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy2(SCRIPT_PATH, fork_dir / "scripts" / "sync_upstream_needs_apply.py")
    return upstream_dir, fork_dir, env


def test_f1_and_f3d_upstream_tags_fetched_into_upstream_refs_and_is_ancestor_not_inverted(tmp_path: Path, sync_keys):
    """F1 + F3d:
    - Upstream tags are fetched into `refs/upstream-tags/*` (not `refs/tags/*`).
    - A fork's own higher tag (`v9.9.9` in `refs/tags/*`) never blocks syncing upstream `v1.2.0`.
    - `--is-ancestor` is not inverted: when fork HEAD already contains the latest upstream tag,
      `should_sync=false`; when upstream has a newer release tag not in fork HEAD, `should_sync=true`.
    """
    wf = _load_workflow()
    check_tag_script = _get_step_by_name(
        wf, "sync-upstream", "Fetch, Verify and Check Ancestry of the Newest Upstream Release Tag"
    )["run"]

    upstream_dir, fork_dir, base_env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    base_env["RUNNER_TEMP"] = str(runner_temp)

    # Create a fork-local tag v9.9.9 on fork's HEAD (must be ignored by upstream tag discovery).
    subprocess.run(["git", "tag", "v9.9.9"], cwd=fork_dir, env=base_env, check=True)

    # 1. F3d (already up-to-date): upstream's newest release tag is v1.0.0, which is an ancestor of fork HEAD.
    gh_output = tmp_path / "gh_output_uptodate.txt"
    gh_output.write_text("", encoding="utf-8")
    env_uptodate = dict(base_env)
    env_uptodate.update(
        {
            "UPSTREAM_REPO": "example-org/stackvend",
            "GITHUB_OUTPUT": str(gh_output),
        }
    )
    res_uptodate = subprocess.run(
        ["bash", "-eo", "pipefail"],
        input=check_tag_script,
        text=True,
        capture_output=True,
        cwd=fork_dir,
        env=env_uptodate,
        check=True,
    )
    out_uptodate = _parse_github_output(gh_output)
    assert out_uptodate.get("should_sync") == "false"
    assert "Fork already contains release tag v1.0.0" in res_uptodate.stdout

    # 2. F1 + F3d (upstream advances to v1.2.0 + pre-release v1.3.0-rc1; fork still has local v9.9.9):
    (upstream_dir / "README.md").write_text("release 1.2.0\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=upstream_dir, env=base_env, check=True)
    subprocess.run(["git", "commit", "-m", "release v1.2.0"], cwd=upstream_dir, env=base_env, check=True, capture_output=True)
    _sign_tag(upstream_dir, base_env, sync_keys["release"], "v1.2.0")
    subprocess.run(["git", "tag", "v1.3.0-rc1"], cwd=upstream_dir, env=base_env, check=True)

    gh_output_behind = tmp_path / "gh_output_behind.txt"
    gh_output_behind.write_text("", encoding="utf-8")
    env_behind = dict(base_env)
    env_behind.update(
        {
            "UPSTREAM_REPO": "example-org/stackvend",
            "GITHUB_OUTPUT": str(gh_output_behind),
        }
    )
    res_behind = subprocess.run(
        ["bash", "-eo", "pipefail"],
        input=check_tag_script,
        text=True,
        capture_output=True,
        cwd=fork_dir,
        env=env_behind,
        check=True,
    )
    out_behind = _parse_github_output(gh_output_behind)
    assert out_behind.get("should_sync") == "true"
    assert out_behind.get("target_tag") == "v1.2.0"
    assert out_behind.get("branch_name") == "chore/sync-upstream-v1.2.0"
    assert "Latest upstream release tag v1.2.0 is not yet merged into HEAD." in res_behind.stdout

    # Verify fork's refs/tags/ did NOT receive v1.2.0 (it lives under refs/upstream-tags/v1.2.0).
    fork_local_tags = subprocess.run(
        ["git", "tag", "--list"],
        cwd=fork_dir,
        env=base_env,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.splitlines()
    assert "v9.9.9" in fork_local_tags
    assert "v1.2.0" not in fork_local_tags


def _run_check(script: str, *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the fetch/verify step; copy its outputs into `env` as the merge step's `env:` maps them."""
    res = _run_bash(script, cwd=cwd, env=env)
    out = _parse_github_output(Path(env["GITHUB_OUTPUT"]))
    env.update({"TAG_OID": out.get("tag_oid", ""), "TAG_COMMIT": out.get("tag_commit", ""),
                "BASE_SHA": out.get("base_sha", "")})
    return res


def _run_bash(script: str, *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    res = subprocess.run(
        ["bash", "-eo", "pipefail"],
        input=script,
        text=True,
        cwd=cwd,
        env=env,
        capture_output=True,
    )
    assert res.returncode == 0, f"bash failed (exit {res.returncode}):\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    return res


def test_f2_post_merge_diff_handles_renames_non_ascii_and_ignores_fork_only_edits(tmp_path: Path, sync_keys):
    """F2: Execute the workflow's post-merge diff & needs-apply step in a scratch git repo for:
    1. Fork-only edits under `infra/platform/` -> ignored (`needs_apply=no`).
    2. Rename out of `infra/platform/` -> detected (`needs_apply=yes`).
    3. Non-ASCII file path under `infra/platform/` -> detected (`needs_apply=yes`).
    """
    wf = _load_workflow()
    check_tag_script = _get_step_by_name(
        wf, "sync-upstream", "Fetch, Verify and Check Ancestry of the Newest Upstream Release Tag"
    )["run"]
    merge_and_diff_script = _get_step_by_name(
        wf, "sync-upstream", "Merge Upstream Release Tag and Compute Apply Requirement"
    )["run"]

    upstream_dir, fork_dir, base_env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()

    # Fork makes a fork-only edit inside `infra/platform/fork_only.tf` on `main`.
    (fork_dir / "infra" / "platform" / "fork_only.tf").write_text("# fork custom\n", encoding="utf-8")
    subprocess.run(["git", "add", "infra/platform/fork_only.tf"], cwd=fork_dir, env=base_env, check=True)
    subprocess.run(["git", "commit", "-m", "fork-only platform customization"], cwd=fork_dir, env=base_env, check=True, capture_output=True)
    fork_main_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=fork_dir, env=base_env, text=True, capture_output=True, check=True
    ).stdout.strip()

    # Case 1: Upstream v1.1.0 only touches `apps/control-center/main.py` (no platform path).
    (upstream_dir / "apps" / "control-center").mkdir(parents=True)
    (upstream_dir / "apps" / "control-center" / "main.py").write_text("print('v1.1.0')\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=upstream_dir, env=base_env, check=True)
    subprocess.run(["git", "commit", "-m", "v1.1.0 app-only"], cwd=upstream_dir, env=base_env, check=True, capture_output=True)
    _sign_tag(upstream_dir, base_env, sync_keys["release"], "v1.1.0")

    gh_out = tmp_path / "gh_out_1.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(base_env)
    step_env.update(
        {
            "UPSTREAM_REPO": "example-org/stackvend",
            "GITHUB_OUTPUT": str(gh_out),
            "RUNNER_TEMP": str(runner_temp),
            "BRANCH_NAME": "chore/sync-upstream-v1.1.0",
            "TARGET_TAG": "v1.1.0",
        }
    )
    _run_check(check_tag_script, cwd=fork_dir, env=step_env)
    _run_bash(merge_and_diff_script, cwd=fork_dir, env=step_env)

    assert _parse_github_output(gh_out).get("needs_apply") == "no"
    pr_body_1 = (runner_temp / "pr_body.md").read_text(encoding="utf-8")
    assert "needs apply.sh: no" in pr_body_1
    assert "fork_only.tf" not in pr_body_1

    # Reset fork back to main for Case 2 (rename out of `infra/platform/` -> `docs/legacy.tf`).
    subprocess.run(["git", "checkout", "main"], cwd=fork_dir, env=base_env, check=True, capture_output=True)
    subprocess.run(["git", "reset", "--hard", fork_main_sha], cwd=fork_dir, env=base_env, check=True, capture_output=True)

    (upstream_dir / "docs").mkdir(exist_ok=True)
    subprocess.run(["git", "mv", "infra/platform/legacy.tf", "docs/legacy.tf"], cwd=upstream_dir, env=base_env, check=True)
    subprocess.run(["git", "commit", "-m", "v1.2.0 rename out of infra/platform"], cwd=upstream_dir, env=base_env, check=True, capture_output=True)
    _sign_tag(upstream_dir, base_env, sync_keys["release"], "v1.2.0")

    gh_out_2 = tmp_path / "gh_out_2.txt"
    gh_out_2.write_text("", encoding="utf-8")
    step_env.update(
        {
            "GITHUB_OUTPUT": str(gh_out_2),
            "BRANCH_NAME": "chore/sync-upstream-v1.2.0",
            "TARGET_TAG": "v1.2.0",
        }
    )
    _run_check(check_tag_script, cwd=fork_dir, env=step_env)
    _run_bash(merge_and_diff_script, cwd=fork_dir, env=step_env)

    assert _parse_github_output(gh_out_2).get("needs_apply") == "yes"
    pr_body_2 = (runner_temp / "pr_body.md").read_text(encoding="utf-8")
    assert "needs apply.sh: yes" in pr_body_2
    assert "- `infra/platform/legacy.tf`" in pr_body_2

    # Case 3: Advance fork main to include v1.2.0, then upstream v1.3.0 adds a non-ASCII file under `infra/platform/`.
    subprocess.run(["git", "checkout", "main"], cwd=fork_dir, env=base_env, check=True, capture_output=True)
    subprocess.run(["git", "merge", "--no-edit", "chore/sync-upstream-v1.2.0"], cwd=fork_dir, env=base_env, check=True, capture_output=True)

    non_ascii_rel = "infra/platform/café_ñ_설정.tf"
    (upstream_dir / non_ascii_rel).write_text("# non-ascii\n", encoding="utf-8")
    subprocess.run(["git", "add", non_ascii_rel], cwd=upstream_dir, env=base_env, check=True)
    subprocess.run(["git", "commit", "-m", "v1.3.0 non-ascii platform file"], cwd=upstream_dir, env=base_env, check=True, capture_output=True)
    _sign_tag(upstream_dir, base_env, sync_keys["release"], "v1.3.0")

    gh_out_3 = tmp_path / "gh_out_3.txt"
    gh_out_3.write_text("", encoding="utf-8")
    step_env.update(
        {
            "GITHUB_OUTPUT": str(gh_out_3),
            "BRANCH_NAME": "chore/sync-upstream-v1.3.0",
            "TARGET_TAG": "v1.3.0",
        }
    )
    _run_check(check_tag_script, cwd=fork_dir, env=step_env)
    _run_bash(merge_and_diff_script, cwd=fork_dir, env=step_env)

    assert _parse_github_output(gh_out_3).get("needs_apply") == "yes"
    pr_body_3 = (runner_temp / "pr_body.md").read_text(encoding="utf-8")
    assert "needs apply.sh: yes" in pr_body_3
    assert f"- `{non_ascii_rel}`" in pr_body_3


# Offline stand-in for `gh api repos/<repo>/pulls -X GET --paginate -f state= -f base= -f head=owner:branch
# -f per_page= --jq <expr>` (FD-104 review 2): filters a JSON fixture of REST pull-request rows on the server side as
# GitHub does (state open/closed, base ref, head `owner:ref` = the head repository's owner and branch), pages with
# per_page (default 30, at most 100), returns only the first page without --paginate, and applies the step's own
# --jq expression to every page with the real `jq`. Unknown arguments fail the call; FAKE_GH_FAIL=1 fails it.
_FAKE_GH = r"""
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\n")
ignore_filters = os.environ.get("FAKE_GH_IGNORE_FILTERS") == "1"  # a server that ignores base= and head=
if os.environ.get("FAKE_GH_FAIL") == "1":
    sys.stderr.write("HTTP 502\n")
    sys.exit(1)
if args[:2] != ["api", "repos/" + os.environ["GITHUB_REPOSITORY"] + "/pulls"]:
    sys.exit(90)
fields, paginate, jq_expr, method, i, rest = {}, False, None, None, 0, args[2:]
while i < len(rest):
    if rest[i] == "--paginate":
        paginate, i = True, i + 1
    elif rest[i] == "-X":
        method, i = rest[i + 1], i + 2
    elif rest[i] == "-f":
        key, val = rest[i + 1].split("=", 1)
        if key in fields:
            sys.exit(91)
        fields[key], i = val, i + 2
    elif rest[i] == "--jq":
        jq_expr, i = rest[i + 1], i + 2
    else:
        sys.exit(92)
if method != "GET" or set(fields) - {"state", "base", "head", "per_page"}:
    sys.exit(93)
state = fields.get("state", "open")
owner, _, ref = fields.get("head", ":").partition(":")
rows = [
    p for p in json.loads(os.environ["FAKE_GH_PRS"])
    if (state == "all" or p["state"] == state)
    and (ignore_filters or "base" not in fields or p["base"]["ref"] == fields["base"])
    and (ignore_filters or "head" not in fields
         or (p["head"]["ref"] == ref and ((p["head"]["repo"] or {}).get("owner") or {}).get("login") == owner))
]
per_page = min(int(fields.get("per_page", "30")), 100)
pages = [rows[k:k + per_page] for k in range(0, len(rows), per_page)] or [[]]
for page in pages if paginate else pages[:1]:
    if jq_expr is None:
        sys.stdout.write(json.dumps(page) + "\n")
    else:
        res = subprocess.run(["jq", "-r", jq_expr], input=json.dumps(page), text=True, capture_output=True, check=True)
        sys.stdout.write(res.stdout)
"""

_BR = "chore/sync-upstream-v1.2.0"
_OWN_REPO = "consumer-org/stackvend"


def _pr(number: int, state: str, head: str = _BR, base: str = "main", repo: str | None = _OWN_REPO) -> dict[str, Any]:
    """A REST pull-request row. `repo` = the head repository: another owner's repository is filtered out by the
    server (`head=owner:branch`); another repository of the same owner reaches the step's same-repo check; None = a
    deleted head repository (`head.repo` is null)."""
    rest_state, merged_at = {"OPEN": ("open", None), "CLOSED": ("closed", None),
                             "MERGED": ("closed", "2026-11-01T00:00:00Z")}[state]
    head_repo = None if repo is None else {"full_name": repo, "owner": {"login": repo.split("/")[0]}}
    return {"number": number, "state": rest_state, "merged_at": merged_at, "base": {"ref": base},
            "head": {"ref": head, "repo": head_repo}}


def _pr_step_env(tmp_path: Path, prs: list[dict[str, Any]], base: str, **extra: str) -> tuple[dict[str, str], Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(f"#!{sys.executable}\n" + _FAKE_GH, encoding="utf-8")
    fake_gh.chmod(0o755)
    gh_log = tmp_path / "gh_calls.jsonl"
    gh_out = tmp_path / "gh_out_pr.txt"
    gh_out.write_text("", encoding="utf-8")
    env = hermetic_guard.child_env(
        extra={
            "HOME": str(tmp_path),
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "GITHUB_OUTPUT": str(gh_out),
            "GITHUB_REPOSITORY": _OWN_REPO,
            "GITHUB_REPOSITORY_OWNER": "consumer-org",
            "BRANCH_NAME": _BR,
            "TARGET_TAG": "v1.2.0",
            "BASE_BRANCH": base,  # FD-4DA F10: the step's env, from the "Resolve Default Branch" output
            "FAKE_GH_PRS": json.dumps(prs),
            "FAKE_GH_LOG": str(gh_log),
            **extra,
        }
    )
    return env, gh_out, gh_log


def _assert_pr_calls(gh_log: Path, base: str) -> None:
    calls = [json.loads(line) for line in gh_log.read_text(encoding="utf-8").splitlines()]
    assert calls, "gh api was never called"
    for call in calls:
        assert call[:5] == ["api", f"repos/{_OWN_REPO}/pulls", "-X", "GET", "--paginate"]
        assert f"base={base}" in call and f"head=consumer-org:{_BR}" in call and "per_page=100" in call


_OPEN_MSG = "Sync PR #{n} for v1.2.0 (chore/sync-upstream-v1.2.0) is already open; skipping."
_CLOSED_MSG = (
    "Sync PR #{n} for v1.2.0 (chore/sync-upstream-v1.2.0) was closed without merging; "
    "skipping until a newer release."
)


@pytest.mark.parametrize(
    "prs,expect_exists,expect_log",
    [
        pytest.param([], "false", None, id="no-pr"),
        pytest.param([_pr(42, "OPEN")], "true", _OPEN_MSG.format(n=42), id="open"),
        pytest.param([_pr(7, "CLOSED"), _pr(42, "OPEN")], "true", _OPEN_MSG.format(n=42), id="open-wins"),
        # F7 (owner 10-19): a closed, unmerged PR for this exact release branch = release declined.
        pytest.param([_pr(7, "CLOSED")], "true", _CLOSED_MSG.format(n=7), id="closed-unmerged"),
        pytest.param([_pr(8, "MERGED"), _pr(7, "CLOSED")], "true", _CLOSED_MSG.format(n=7), id="merged-and-closed"),
        # A merged PR is not a decline (e.g. squash-merged; documented in F6) -> not skipped by F7.
        pytest.param([_pr(8, "MERGED")], "false", None, id="merged-only"),
        # PRs for another release branch or another base never block this release.
        pytest.param(
            [_pr(5, "CLOSED", head="chore/sync-upstream-v1.1.0"), _pr(6, "OPEN", head="chore/sync-upstream-v1.1.0")],
            "false",
            None,
            id="other-branch",
        ),
        pytest.param([_pr(9, "CLOSED", base="release"), _pr(10, "OPEN", base="release")], "false", None, id="other-base"),
        # FD-104 A2: a pull request from another repository's branch of the same name never skips or spoofs the
        # sync: another owner's (filtered by the server) or another repository of the same owner (the step's check).
        pytest.param([_pr(66, "OPEN", repo="outsider/stackvend")], "false", None, id="other-owner-open"),
        pytest.param([_pr(67, "CLOSED", repo="outsider/stackvend")], "false", None, id="other-owner-closed"),
        pytest.param([_pr(68, "OPEN", repo="consumer-org/stackvend-copy")], "false", None, id="same-owner-other-repo"),
        pytest.param([_pr(69, "CLOSED", repo="consumer-org/stackvend-copy")], "false", None,
                     id="same-owner-other-repo-closed"),
        pytest.param([_pr(68, "OPEN", repo="consumer-org/stackvend-copy"), _pr(42, "OPEN")], "true",
                     _OPEN_MSG.format(n=42), id="own-open-beside-other-repo"),
        pytest.param([_pr(69, "CLOSED", repo="consumer-org/stackvend-copy"), _pr(7, "CLOSED")], "true",
                     _CLOSED_MSG.format(n=7), id="own-closed-beside-other-repo"),
    ],
)
def test_f3e_f7_existing_sync_pr_dedup(
    tmp_path: Path, prs: list[dict[str, Any]], expect_exists: str, expect_log: str | None
):
    """F3e + F7: execute the `Check for Existing Sync PR` step against an argument-checking `gh` double."""
    if shutil.which("jq") is None:
        pytest.skip("jq is required to evaluate the step's --jq expressions")

    wf = _load_workflow()
    check_pr_script = _get_step_by_name(wf, "sync-upstream", "Check for Existing Sync PR")["run"]
    env, gh_out, gh_log = _pr_step_env(tmp_path, prs, "main")
    res = subprocess.run(
        ["bash", "-eo", "pipefail"],
        input=check_pr_script,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
    )
    assert res.returncode == 0, res.stderr
    assert _parse_github_output(gh_out) == {"pr_exists": expect_exists}
    if expect_log is None:
        assert res.stdout == ""
    else:
        assert res.stdout == expect_log + "\n"  # exactly one log line
    _assert_pr_calls(gh_log, "main")


@pytest.mark.parametrize("state,msg", [("OPEN", _OPEN_MSG.format(n=4242)), ("CLOSED", _CLOSED_MSG.format(n=4242))])
def test_fd104_own_pr_after_more_than_a_page_of_other_rows_is_found(tmp_path: Path, state: str, msg: str):
    """Review 2: 150 rows of another repository of the same owner come first; the own pull request is on page 2."""
    if shutil.which("jq") is None:
        pytest.skip("jq is required to evaluate the step's --jq expressions")
    prs = [_pr(n, state, repo="consumer-org/stackvend-copy") for n in range(1, 151)] + [_pr(4242, state)]
    script = _get_step_by_name(_load_workflow(), "sync-upstream", "Check for Existing Sync PR")["run"]
    env, gh_out, gh_log = _pr_step_env(tmp_path, prs, "main")
    res = subprocess.run(["bash", "-eo", "pipefail"], input=script, text=True, capture_output=True, cwd=tmp_path,
                         env=env)
    assert res.returncode == 0, res.stderr
    assert res.stdout == msg + "\n"
    assert _parse_github_output(gh_out) == {"pr_exists": "true"}
    _assert_pr_calls(gh_log, "main")
    # The double really pages: without --paginate the own pull request is not on the first page.
    first_page = subprocess.run(  # the double is a Python script: run it by the interpreter
        [sys.executable, str(tmp_path / "bin" / "gh"), "api", f"repos/{_OWN_REPO}/pulls", "-X", "GET", "-f",
         f"state={'open' if state == 'OPEN' else 'closed'}", "-f", "per_page=100", "--jq", ".[].number"],
        text=True, capture_output=True, check=True,
        env=hermetic_guard.child_env(extra={k: env[k] for k in ("HOME", "PATH", "GITHUB_OUTPUT", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "BRANCH_NAME", "TARGET_TAG", "BASE_BRANCH", "FAKE_GH_PRS", "FAKE_GH_LOG")}),
    ).stdout.split()
    assert len(first_page) == 100 and "4242" not in first_page


@pytest.mark.parametrize(
    "prs,expect_exists,expect_log",
    [
        # This repository's own pull requests for another branch or another base, returned by a server that ignored
        # the filters, never count: the step checks head branch, base branch and head repository itself.
        pytest.param([_pr(11, "OPEN", head="feature-x")], "false", None, id="own-other-branch"),
        pytest.param([_pr(12, "OPEN", base="release")], "false", None, id="own-other-base"),
        pytest.param([_pr(13, "CLOSED", head="feature-x"), _pr(14, "CLOSED", base="release")], "false", None,
                     id="own-closed-elsewhere"),
        pytest.param([_pr(11, "OPEN", head="feature-x"), _pr(42, "OPEN")], "true", _OPEN_MSG.format(n=42),
                     id="own-match-after-unrelated"),
        # Review delta 3: a deleted head repository (null head.repo) and a null merged_at give "-" placeholders, so
        # the tab-separated fields never shift.
        pytest.param([_pr(5, "CLOSED", repo=None)], "false", None, id="deleted-head-repo"),
        pytest.param([_pr(6, "MERGED", repo=None)], "false", None, id="deleted-head-repo-merged"),
        pytest.param([_pr(5, "CLOSED", repo=None), _pr(7, "CLOSED")], "true", _CLOSED_MSG.format(n=7),
                     id="own-after-deleted-head-repo"),
        pytest.param([_pr(8, "MERGED")], "false", None, id="own-merged-is-not-declined"),
    ],
)
def test_fd104_pr_rows_are_checked_again_by_the_step(tmp_path: Path, prs, expect_exists: str, expect_log):
    if shutil.which("jq") is None:
        pytest.skip("jq is required to evaluate the step's --jq expressions")
    script = _get_step_by_name(_load_workflow(), "sync-upstream", "Check for Existing Sync PR")["run"]
    env, gh_out, gh_log = _pr_step_env(tmp_path, prs, "main", FAKE_GH_IGNORE_FILTERS="1")
    res = subprocess.run(["bash", "-eo", "pipefail"], input=script, text=True, capture_output=True, cwd=tmp_path,
                         env=env)
    assert res.returncode == 0, res.stderr
    assert _parse_github_output(gh_out) == {"pr_exists": expect_exists}
    assert res.stdout == ("" if expect_log is None else expect_log + "\n")
    _assert_pr_calls(gh_log, "main")


def test_fd104_failed_pr_lookup_is_a_typed_error(tmp_path: Path):
    script = _get_step_by_name(_load_workflow(), "sync-upstream", "Check for Existing Sync PR")["run"]
    env, gh_out, _log = _pr_step_env(tmp_path, [], "main", FAKE_GH_FAIL="1")
    res = subprocess.run(["bash", "-eo", "pipefail"], input=script, text=True, capture_output=True, cwd=tmp_path,
                         env=env)
    assert res.returncode == 1
    assert [x for x in res.stdout.splitlines() if x.startswith("::error::")] == [
        f"::error::SYNC_PR_LOOKUP_FAILED: listing the open pull requests of {_OWN_REPO} for {_BR} failed; nothing was "
        "merged or pushed."
    ]
    assert _parse_github_output(gh_out) == {}


def _git(cwd: Path, env: dict[str, str], *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, text=True, capture_output=True, check=True
    ).stdout


def test_merge_step_never_runs_upstream_helper_after_merge(tmp_path: Path, sync_keys):
    """Post-merge, the working tree holds upstream's files while the job holds a write token.

    An upstream release that changes `scripts/sync_upstream_needs_apply.py` must not get that code
    executed: the step runs the fork's helper snapshotted before the merge. Also covers an
    annotated upstream tag (ancestry + merge through `refs/upstream-tags/*` tag objects).
    """
    wf = _load_workflow()
    check_tag_script = _get_step_by_name(wf, "sync-upstream", "Fetch, Verify and Check Ancestry of the Newest Upstream Release Tag")["run"]
    merge_script = _get_step_by_name(wf, "sync-upstream", "Merge Upstream Release Tag and Compute Apply Requirement")["run"]

    upstream_dir, fork_dir, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    # Both sides track the real helper (as in a real fork): commit it upstream, fork pulls it.
    (fork_dir / "scripts" / "sync_upstream_needs_apply.py").unlink()
    (upstream_dir / "scripts").mkdir(exist_ok=True)
    shutil.copy2(SCRIPT_PATH, upstream_dir / "scripts" / "sync_upstream_needs_apply.py")
    _git(upstream_dir, env, "add", "scripts")
    _git(upstream_dir, env, "commit", "-m", "add helper")
    _git(fork_dir, env, "pull", "--no-rebase", "origin", "main")

    marker = tmp_path / "upstream_code_ran"
    (upstream_dir / "scripts" / "sync_upstream_needs_apply.py").write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(marker)!r}).write_text('ran')\n"
        "sys.stdout.write('no\\n')\n",
        encoding="utf-8",
    )
    (upstream_dir / "infra" / "platform" / "main.tf").write_text("# main v1.1.0\n", encoding="utf-8")
    _git(upstream_dir, env, "add", ".")
    _git(upstream_dir, env, "commit", "-m", "v1.1.0 changes helper + platform")
    tag_oid = _sign_tag(upstream_dir, env, sync_keys["release"], "v1.1.0", message="release v1.1.0")

    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_out.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(env)
    step_env.update(
        {
            "UPSTREAM_REPO": "example-org/stackvend",
            "GITHUB_OUTPUT": str(gh_out),
            "RUNNER_TEMP": str(runner_temp),
            "BRANCH_NAME": "chore/sync-upstream-v1.1.0",
            "TARGET_TAG": "v1.1.0",
        }
    )
    _run_check(check_tag_script, cwd=fork_dir, env=step_env)
    assert _parse_github_output(gh_out).get("should_sync") == "true"
    _run_bash(merge_script, cwd=fork_dir, env=step_env)

    # The merge really brought upstream's helper into the working tree ...
    assert "upstream_code_ran" in (fork_dir / "scripts" / "sync_upstream_needs_apply.py").read_text(encoding="utf-8")
    # ... but it never ran; the fork's helper computed the (correct) answer.
    assert not marker.exists()
    assert _parse_github_output(gh_out).get("needs_apply") == "yes"
    body = (runner_temp / "pr_body.md").read_text(encoding="utf-8")
    assert "needs apply.sh: yes" in body
    assert "- `infra/platform/main.tf`" in body
    # FD-104: the changed helper is a trust anchor and is listed; the body names the verified tag object.
    assert "### Trust-anchor paths changed by this release\n" in body
    assert "- `scripts/sync_upstream_needs_apply.py`" in body
    assert f"- Tag object: `{tag_oid}`" in body
    assert _git(fork_dir, env, "rev-parse", "--abbrev-ref", "HEAD").strip() == "chore/sync-upstream-v1.1.0"


def test_merge_conflict_fails_with_one_clear_error_line(tmp_path: Path, sync_keys):
    wf = _load_workflow()
    check_tag_script = _get_step_by_name(wf, "sync-upstream", "Fetch, Verify and Check Ancestry of the Newest Upstream Release Tag")["run"]
    merge_script = _get_step_by_name(wf, "sync-upstream", "Merge Upstream Release Tag and Compute Apply Requirement")["run"]

    upstream_dir, fork_dir, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    (fork_dir / "README.md").write_text("fork edit\n", encoding="utf-8")
    _git(fork_dir, env, "commit", "-am", "fork README")
    (upstream_dir / "README.md").write_text("upstream edit\n", encoding="utf-8")
    _git(upstream_dir, env, "commit", "-am", "upstream README")
    _sign_tag(upstream_dir, env, sync_keys["release"], "v1.1.0")

    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_out.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(env)
    step_env.update(
        {
            "UPSTREAM_REPO": "example-org/stackvend",
            "GITHUB_OUTPUT": str(gh_out),
            "RUNNER_TEMP": str(runner_temp),
            "BRANCH_NAME": "chore/sync-upstream-v1.1.0",
            "TARGET_TAG": "v1.1.0",
        }
    )
    _run_check(check_tag_script, cwd=fork_dir, env=step_env)
    res = subprocess.run(
        ["bash", "-eo", "pipefail"], input=merge_script, text=True, capture_output=True, cwd=fork_dir, env=step_env
    )
    assert res.returncode == 1
    error_lines = [line for line in res.stdout.splitlines() if line.startswith("::error::")]
    assert error_lines == [
        "::error::Merging upstream v1.1.0 failed (usually merge conflicts). " + _manual_path("v1.1.0")
    ]
    assert "needs_apply" not in _parse_github_output(gh_out)
    assert not (runner_temp / "pr_body.md").exists()


def test_f5_optional_sync_token_falls_back_to_github_token():
    """F5 (owner 10-19): optional `STACKVEND_SYNC_TOKEN` (workflow write access) else the default token.

    FD-104: the checkout and the read-only `gh` calls use the default token; only the push / PR step sees
    STACKVEND_SYNC_TOKEN."""
    wf = _load_workflow()
    steps = wf["jobs"]["sync-upstream"]["steps"]
    checkouts = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1
    assert checkouts[0]["with"]["token"] == "${{ github.token }}"
    assert checkouts[0]["with"]["persist-credentials"] is False
    gh_steps = [s for s in steps if "GH_TOKEN" in s.get("env", {})]
    assert {s["name"] for s in gh_steps} == {
        "Resolve Default Branch", "Check for Existing Sync PR", "Push Sync Branch and Open Pull Request",
    }
    for step in gh_steps:
        expected = (
            "${{ secrets.STACKVEND_SYNC_TOKEN || github.token }}"
            if step["name"] == "Push Sync Branch and Open Pull Request"
            else "${{ github.token }}"
        )
        assert step["env"]["GH_TOKEN"] == expected, step["name"]
    raw = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert set(re.findall(r"secrets\.([A-Za-z0-9_]+)", raw)) == {"STACKVEND_SYNC_TOKEN"}


def test_null_mode_splits_on_nul_only_and_keeps_paths_verbatim():
    # Negative: a single NUL-terminated path that merely contains a newline / leading space is not a platform path.
    assert sync_mod.check_needs_apply("docs/a\ninfra/platform/x.tf\0 infra/platform/y.tf\0", null_delimited=True) == (False, [])
    # Positive: spaces inside / at the end of a real platform path are preserved exactly.
    assert sync_mod.check_needs_apply("infra/platform/a b.tf \0apps/x.py\0", null_delimited=True) == (
        True,
        ["infra/platform/a b.tf "],
    )


@pytest.mark.parametrize(
    "slug,expected",
    [
        ("example-org/stackvend", True),
        ("org_1/repo-2.0", True),
        ("", False),
        ("   ", False),
        (" example-org/stackvend", False),
        ("example-org/stackvend ", False),
        ("only-owner", False),
        ("owner/", False),
        ("/repo", False),
        ("a/b/c", False),
        ("./repo", False),
        ("owner/..", False),
        ("example-org/stackvend.git", False),
        ("https://github.com/example-org/stackvend", False),
        ("owner/repo with space", False),
    ],
)
def test_repo_slug_validation(slug: str, expected: bool):
    assert sync_mod.is_valid_repo_slug(slug) is expected
    rc = sync_mod.main(["--validate-slug", slug])
    assert (rc == 0) is expected


@pytest.mark.parametrize(
    "paths,expected_bool,expected_matches",
    [
        (["infra/platform/main.tf"], True, ["infra/platform/main.tf"]),
        (["infra/modules/workflows/main.tf"], True, ["infra/modules/workflows/main.tf"]),
        (["workflows/main_orchestrator.yaml"], True, ["workflows/main_orchestrator.yaml"]),
        (["infra/platform/café_ñ.tf"], True, ["infra/platform/café_ñ.tf"]),
        (["infra/modules/compute-cloudrun/main.tf"], False, []),
        (["infra/platformx/a.tf"], False, []),
        (["infra/modules/workflowsx/main.tf"], False, []),
        (["infra/modules/cloud_build/main.tf"], False, []),
        (["workflowsx/main.yaml"], False, []),
        ([".github/workflows/sync-upstream.yml"], False, []),
        (["apps/control-center/main.py"], False, []),
        ([], False, []),
        ([""], False, []),
    ],
)
def test_needs_apply_path_membership(
    paths: list[str], expected_bool: bool, expected_matches: list[str]
):
    req, matched = sync_mod.check_needs_apply(paths)
    assert req is expected_bool
    assert matched == expected_matches
    assert sync_mod.needs_apply(paths) is expected_bool


def test_needs_apply_cli_stdin_and_stdout(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    # Empty input -> no
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert sync_mod.main([]) == 0
    assert capsys.readouterr().out == "no\n"

    # Non-matching paths -> no (negative test: valid non-platform paths do not trigger apply.sh)
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO("infra/modules/compute-cloudrun/main.tf\ninfra/platformx/a.tf\napps/control-center/main.py\n"),
    )
    assert sync_mod.main([]) == 0
    assert capsys.readouterr().out == "no\n"

    # Mixed paths -> yes + exact matching paths in order, deduplicated
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            "apps/control-center/main.py\n"
            "infra/platform/main.tf\n"
            "infra/platformx/a.tf\n"
            "workflows/main_orchestrator.yaml\n"
            "infra/platform/main.tf\n"
        ),
    )
    assert sync_mod.main([]) == 0
    assert capsys.readouterr().out == (
        "yes\n"
        "infra/platform/main.tf\n"
        "workflows/main_orchestrator.yaml\n"
    )

    # NUL-delimited (-z) mode with non-ASCII path
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO("apps/control-center/main.py\0infra/platform/café.tf\0"),
    )
    assert sync_mod.main(["-z"]) == 0
    assert capsys.readouterr().out == "yes\ninfra/platform/café.tf\n"


def test_needs_apply_cli_subprocess():
    res_yes = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "-z"],
        input="infra/platform/café.tf\0apps/control-center/main.py\0",
        text=True,
        capture_output=True,
        env=hermetic_guard.child_env(),
        check=True,
    )
    assert res_yes.stdout == "yes\ninfra/platform/café.tf\n"

    res_no = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "-z"],
        input="infra/platformx/a.tf\0infra/modules/compute-cloudrun/main.tf\0",
        text=True,
        capture_output=True,
        env=hermetic_guard.child_env(),
        check=True,
    )
    assert res_no.stdout == "no\n"


def test_tag_parser_numeric_sorting_and_prerelease_filtering(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    assert sync_mod.parse_release_tag("v1.10.0") == (1, 10, 0)
    assert sync_mod.parse_release_tag("v1.9.3") == (1, 9, 3)
    assert sync_mod.parse_release_tag("v1.10.0") > sync_mod.parse_release_tag("v1.9.3")

    for ignored in (
        "v1.2.3-rc1",
        "v1.2.3-alpha.1",
        "v1.2.3+20261019",
        "1.2.3",
        "v1.2",
        "v1.2.3.4",
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
        "v-1.2.3",
        "latest",
        "",
    ):
        assert sync_mod.parse_release_tag(ignored) is None

    tags = [
        "v0.9.0-preview",
        "v1.9.3",
        "v1.2.3-rc1",
        "1.2.3",
        "v1.2",
        "v1.10.0",
        "v1.2.0",
    ]
    assert sync_mod.filter_release_tags(tags) == ["v1.2.0", "v1.9.3", "v1.10.0"]
    assert sync_mod.select_latest_release_tag(tags) == "v1.10.0"
    assert sync_mod.select_latest_release_tag(["v1.2.3-rc1", "1.2.3", "v1.2"]) is None

    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(tags) + "\n"))
    assert sync_mod.main(["--latest-tag"]) == 0
    assert capsys.readouterr().out == "v1.10.0\n"


_OID_T = "a" * 40
_OID_C = "b" * 40
_BODY_KW = {"tag_object": _OID_T, "tag_commit": _OID_C, "signers": [RELEASE_PRINCIPAL]}


def test_pr_body_formatting():
    body_yes = sync_mod.format_pr_body(
        "v1.10.0",
        "example-org/stackvend",
        ["apps/control-center/main.py", "infra/platform/main.tf", "workflows/main_orchestrator.yaml"],
        **_BODY_KW,
    )
    assert "needs apply.sh: yes" in body_yes
    assert "- `infra/platform/main.tf`" in body_yes
    assert "- `workflows/main_orchestrator.yaml`" in body_yes
    assert "apps/control-center/main.py" not in body_yes
    assert "CHANGELOG.md" in body_yes
    assert "merge commit" in body_yes
    assert "GITHUB_TOKEN" in body_yes
    assert "STACKVEND_SYNC_TOKEN" in body_yes
    assert "close this Pull Request without merging" in body_yes

    body_no = sync_mod.format_pr_body(
        "v1.10.0",
        "example-org/stackvend",
        ["apps/control-center/main.py", "infra/modules/compute-cloudrun/main.tf"],
        **_BODY_KW,
    )
    assert "needs apply.sh: no" in body_no
    assert "CHANGELOG.md" in body_no
    # FD-104: the trust-anchor section is always present; the verification lines name object, commit and signer.
    assert "\nTrust-anchor paths: none changed.\n" in body_no
    assert "### Trust-anchor paths changed by this release" not in body_no
    for body in (body_yes, body_no):
        assert f"- Tag object: `{_OID_T}`" in body
        assert f"- Commit merged: `{_OID_C}`" in body
        assert f"- Signed by: `{RELEASE_PRINCIPAL}` " in body


def test_docs_and_changelog_conventions_present():
    changelog = CHANGELOG_PATH.read_text(encoding="utf-8")
    assert "## Release entry convention" in changelog
    assert "requires apply.sh: yes" in changelog
    assert "requires apply.sh: no" in changelog

    for doc_path in (README_PATH, KNOWN_LIMITATIONS_PATH):
        text = doc_path.read_text(encoding="utf-8")
        assert "STACKVEND_UPSTREAM_SYNC" in text
        assert "STACKVEND_UPSTREAM_REPO" in text
        assert "needs apply.sh" in text
        assert "GITHUB_TOKEN" in text
        assert "merge commit" in text
        assert ".github/workflows/**" in text
        assert find_owner_identifiers(text) == []
        # F5 / F7 (owner 10-19): optional workflow-scoped token secret; closed unmerged PR = release skipped.
        assert "STACKVEND_SYNC_TOKEN" in text
        assert "pull request without merging it" in text
        assert "owner decision pending" not in text


# ------------------------------------------------------------------------------------------------
# FD-4DA F10 (SAT-10): checkout pinned to a SHA and to the default branch; the PR base is the default branch.
# ------------------------------------------------------------------------------------------------
_DEFAULT_BRANCH_EXPR = "${{ github.event.repository.default_branch }}"
_BASE_OUTPUT_EXPR = "${{ steps.base.outputs.base_branch }}"


def _ci_checkout_pins() -> set[str]:
    ci = yaml.safe_load((REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    pins = set()
    for job in ci["jobs"].values():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if uses.startswith("actions/checkout@"):
                pins.add(uses)
    return pins


def test_f10_checkout_pinned_to_sha_and_default_branch():
    wf = _load_workflow()
    steps = wf["jobs"]["sync-upstream"]["steps"]
    checkouts = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1
    uses = checkouts[0]["uses"]
    assert re.fullmatch(r"actions/checkout@[0-9a-f]{40}", uses), uses
    # One action version across workflows (release checklist: "require actions to be pinned to a full-length SHA").
    assert _ci_checkout_pins() == {uses}
    assert checkouts[0]["with"]["ref"] == _DEFAULT_BRANCH_EXPR
    assert checkouts[0]["with"]["fetch-depth"] == 0
    assert wf["jobs"]["sync-upstream"]["env"] == {"DEFAULT_BRANCH": _DEFAULT_BRANCH_EXPR}
    # Every `uses:` in the workflow is SHA-pinned.
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            if step.get("uses"):
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"]), step["uses"]


def test_f10_pull_requests_use_the_resolved_default_branch_never_a_literal():
    wf = _load_workflow()
    raw = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "--base main" not in raw
    steps = wf["jobs"]["sync-upstream"]["steps"]
    names = [s.get("name") for s in steps]
    # Resolved right after the slug validation, before anything reads tags, merges or pushes.
    assert names.index("Resolve Default Branch") == names.index("Validate Upstream Slug") + 1
    resolve = _get_step_by_name(wf, "sync-upstream", "Resolve Default Branch")
    assert resolve["id"] == "base"
    assert resolve["if"] == "steps.validate.outputs.valid == 'true'"
    for step in steps:
        run = step.get("run", "")
        if "--base" in run or " base=" in run:
            assert step["env"]["BASE_BRANCH"] == _BASE_OUTPUT_EXPR, step["name"]
            for line in run.splitlines():
                if "--base" in line:
                    assert '--base "${BASE_BRANCH}"' in line, line
                if " base=" in line:  # FD-104: the REST lookup's query field
                    assert '-f base="${BASE_BRANCH}"' in line, line
    gh_base_steps = {s["name"] for s in steps if "--base" in s.get("run", "") or " base=" in s.get("run", "")}
    assert gh_base_steps == {"Check for Existing Sync PR", "Push Sync Branch and Open Pull Request"}


_FAKE_GH_API = r'''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\n")
if args != ["api", "repos/" + os.environ["GITHUB_REPOSITORY"], "--jq", ".default_branch"]:
    sys.exit(90)
sys.stdout.write(os.environ.get("FAKE_DEFAULT_BRANCH", "") + "\n")
'''


def _fork_on_branch(tmp_path: Path, branch: str) -> tuple[Path, dict[str, str]]:
    """A clone whose HEAD is `branch`, with refs/remotes/origin/* as actions/checkout (fetch-depth 0) leaves them."""
    env = hermetic_guard.child_env(
        extra={
            "HOME": str(tmp_path),
            "GIT_AUTHOR_NAME": "Test User",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test User",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
    )
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, env, "init", "-b", branch)
    (origin / "README.md").write_text("base\n", encoding="utf-8")
    _git(origin, env, "add", ".")
    _git(origin, env, "commit", "-m", "base")
    _git(origin, env, "checkout", "-b", "feature")
    (origin / "feature.txt").write_text("feature\n", encoding="utf-8")
    _git(origin, env, "add", ".")
    _git(origin, env, "commit", "-m", "feature")
    _git(origin, env, "checkout", branch)
    fork = tmp_path / "fork"
    subprocess.run(["git", "clone", "-b", branch, f"file://{origin}", str(fork)], env=env, check=True,
                   capture_output=True)
    return fork, env


def _run_resolve(tmp_path: Path, fork: Path, env: dict[str, str], default_branch: str, api_branch: str = ""):
    wf = _load_workflow()
    script = _get_step_by_name(wf, "sync-upstream", "Resolve Default Branch")["run"]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(f"#!{sys.executable}\n" + _FAKE_GH_API, encoding="utf-8")
    fake_gh.chmod(0o755)
    gh_log = tmp_path / "gh_calls.jsonl"
    gh_out = tmp_path / "gh_out_base.txt"
    gh_out.write_text("", encoding="utf-8")
    run_env = dict(env)
    run_env.update({
        "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH') or os.environ.get('PATH', '')}",
        "GITHUB_OUTPUT": str(gh_out),
        "GITHUB_REPOSITORY": "consumer-org/stackvend",
        "DEFAULT_BRANCH": default_branch,
        "FAKE_DEFAULT_BRANCH": api_branch,
        "FAKE_GH_LOG": str(gh_log),
    })
    res = subprocess.run(["bash", "-eo", "pipefail"], input=script, text=True, capture_output=True, cwd=fork,
                         env=run_env)
    calls = [json.loads(x) for x in gh_log.read_text(encoding="utf-8").splitlines()] if gh_log.exists() else []
    return res, _parse_github_output(gh_out), calls


def test_f10_resolve_default_branch_from_event_payload(tmp_path: Path):
    fork, env = _fork_on_branch(tmp_path, "trunk")
    res, out, calls = _run_resolve(tmp_path, fork, env, default_branch="trunk")
    assert res.returncode == 0, res.stderr
    assert out == {"base_branch": "trunk"}
    assert calls == []  # the payload had it: no API call


def test_f10_resolve_default_branch_from_api_when_payload_has_none(tmp_path: Path):
    fork, env = _fork_on_branch(tmp_path, "trunk")
    res, out, calls = _run_resolve(tmp_path, fork, env, default_branch="", api_branch="trunk")
    assert res.returncode == 0, res.stderr
    assert out == {"base_branch": "trunk"}
    assert calls == [["api", "repos/consumer-org/stackvend", "--jq", ".default_branch"]]


@pytest.mark.parametrize(
    "default_branch,api_branch,checkout",
    [
        pytest.param("", "", None, id="unresolvable"),
        pytest.param("bad..name", "", None, id="invalid-name"),
        # A manual run started from another branch must never sync that branch (F10).
        pytest.param("trunk", "", "feature", id="checkout-not-default-head"),
    ],
)
def test_f10_resolve_default_branch_refuses(tmp_path: Path, default_branch: str, api_branch: str, checkout):
    fork, env = _fork_on_branch(tmp_path, "trunk")
    if checkout:
        _git(fork, env, "checkout", "-q", "-b", checkout, f"origin/{checkout}")
    res, out, _calls = _run_resolve(tmp_path, fork, env, default_branch=default_branch, api_branch=api_branch)
    assert res.returncode == 1
    assert out == {}
    errors = [line for line in res.stdout.splitlines() if line.startswith("::error::")]
    assert len(errors) == 1 and "nothing was synced" in errors[0]


@pytest.mark.parametrize(
    "prs,expect_exists",
    [
        pytest.param([_pr(42, "OPEN", base="main")], "false", id="open-on-other-base"),
        pytest.param([_pr(42, "OPEN", base="trunk")], "true", id="open-on-default"),
        pytest.param([_pr(7, "CLOSED", base="trunk")], "true", id="closed-on-default"),
    ],
)
def test_f10_existing_pr_lookup_uses_default_branch(tmp_path: Path, prs: list[dict[str, Any]], expect_exists: str):
    if shutil.which("jq") is None:
        pytest.skip("jq is required to evaluate the step's --jq expressions")
    wf = _load_workflow()
    script = _get_step_by_name(wf, "sync-upstream", "Check for Existing Sync PR")["run"]
    env, gh_out, gh_log = _pr_step_env(tmp_path, prs, "trunk")
    res = subprocess.run(["bash", "-eo", "pipefail"], input=script, text=True, capture_output=True, cwd=tmp_path,
                         env=env)
    assert res.returncode == 0, res.stderr
    assert _parse_github_output(gh_out) == {"pr_exists": expect_exists}
    _assert_pr_calls(gh_log, "trunk")


# ------------------------------------------------------------------------------------------------
# FD-104 (security hotfix 0.9.1-preview.2): only an SSH-signed annotated tag with the right inner name, signed by a
# key in the fork's own committed allowed_signers, is merged; the PR body lists every changed trust-anchor path; the
# sync token is used only by the push / PR step.
# ------------------------------------------------------------------------------------------------
_CHECK_TAG_STEP = "Fetch, Verify and Check Ancestry of the Newest Upstream Release Tag"
_MERGE_STEP = "Merge Upstream Release Tag and Compute Apply Requirement"
_PUSH_STEP = "Push Sync Branch and Open Pull Request"
_UPSTREAM = "example-org/stackvend"
_ANCHOR_HEADING = "### Trust-anchor paths changed by this release\n"


def _manual_path(tag: str) -> str:
    return (
        f"Manual path: git fetch https://github.com/{_UPSTREAM}.git tag {tag}; check that the header of git cat-file "
        f"tag {tag} says tag {tag}; git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen -c gpg.program=false "
        "-c gpg.openpgp.program=false -c gpg.x509.program=false "
        f"-c gpg.ssh.allowedSignersFile=scripts/release/allowed_signers verify-tag {tag}; only then git merge {tag}."
    )


def _commit_files(repo: Path, env: dict[str, str], files: dict[str, str | None], msg: str) -> str:
    for rel, content in files.items():
        path = repo / rel
        if content is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    _git(repo, env, "add", "-A")
    _git(repo, env, "commit", "-m", msg)
    return _git(repo, env, "rev-parse", "HEAD").strip()


def _write_tag_object(repo: Path, env: dict[str, str], raw: bytes, ref_name: str) -> str:
    """Store a hand-made tag object (git's own format checks still apply) and point refs/tags/<ref_name> at it."""
    oid = subprocess.run(
        ["git", "hash-object", "-t", "tag", "-w", "--stdin"], input=raw, cwd=repo, env=env, capture_output=True,
        check=True,
    ).stdout.decode("ascii").strip()
    _git(repo, env, "update-ref", f"refs/tags/{ref_name}", oid)
    return oid


def _raw_tag(repo: Path, env: dict[str, str], oid: str) -> bytes:
    return subprocess.run(["git", "cat-file", "tag", oid], cwd=repo, env=env, capture_output=True, check=True).stdout


def _run_sync_through_merge(
    tmp_path: Path, fork: Path, env: dict[str, str], tag: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, str], Path]:
    """The fetch/verify step, then (when it passed and picked `tag`) the merge step, as the job runs them. A failed
    fetch/verify step is returned as the result: the job stops there. On success the result's stdout is both
    steps' stdout, in order."""
    wf = _load_workflow()
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir(exist_ok=True)
    gh_out = tmp_path / "gh_out_fd104.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(env)
    step_env.update(
        {
            "UPSTREAM_REPO": _UPSTREAM,
            "GITHUB_OUTPUT": str(gh_out),
            "RUNNER_TEMP": str(runner_temp),
            "BRANCH_NAME": f"chore/sync-upstream-{tag}",
            "TARGET_TAG": tag,
        }
    )
    check = subprocess.run(
        ["bash", "-eo", "pipefail"], input=_get_step_by_name(wf, "sync-upstream", _CHECK_TAG_STEP)["run"], text=True,
        capture_output=True, cwd=fork, env=step_env,
    )
    picked = _parse_github_output(gh_out)
    if check.returncode != 0:
        return check, picked, runner_temp
    assert picked.get("should_sync") == "true" and picked.get("target_tag") == tag, (picked, check.stdout)
    step_env.update({"TAG_OID": picked["tag_oid"], "TAG_COMMIT": picked["tag_commit"], "BASE_SHA": picked["base_sha"]})
    res = subprocess.run(
        ["bash", "-eo", "pipefail"], input=_get_step_by_name(wf, "sync-upstream", _MERGE_STEP)["run"], text=True,
        capture_output=True, cwd=fork, env=step_env,
    )
    res.stdout = check.stdout + res.stdout
    return res, _parse_github_output(gh_out), runner_temp


def _assert_refused(res, outputs, runner_temp: Path, fork: Path, env, code: str, tag: str, pre_head: str) -> None:
    assert res.returncode == 1, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    errors = [line for line in res.stdout.splitlines() if line.startswith("::error::")]
    assert len(errors) == 1, res.stdout
    oid = _git(fork, env, "rev-parse", f"refs/upstream-tags/{tag}").strip()
    assert errors[0].startswith(f"::error::{code}: upstream tag {tag} (object {oid}) "), errors[0]
    assert "nothing was merged or pushed" in errors[0]
    assert "stops it until upstream removes that tag" in errors[0]
    assert errors[0].endswith(_manual_path(tag)), errors[0]
    if code != "SYNC_SIGNER_KEY_NOT_CURRENT":  # that refusal comes after verify-tag passed
        assert "Verified upstream tag" not in res.stdout
    # No branch, no merge, no PR body, no needs_apply output.
    branch = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/heads/chore/sync-upstream-{tag}"], cwd=fork, env=env
    )
    assert branch.returncode == 1
    assert _git(fork, env, "symbolic-ref", "HEAD").strip() == "refs/heads/main"
    assert _git(fork, env, "rev-parse", "HEAD").strip() == pre_head
    assert "needs_apply" not in outputs and "should_sync" not in outputs and "tag_oid" not in outputs
    assert not (runner_temp / "pr_body.md").exists()


def test_fd104_good_signed_tag_merges_and_body_lists_signer_and_every_trust_anchor(tmp_path: Path, sync_keys):
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    pre_head = _git(fork, env, "rev-parse", "HEAD").strip()
    anchors = {
        ".github/workflows/ci.yml": "on: push\n",
        ".agents/skills/example/SKILL.md": "skill\n",
        ".envrc": "export X=1\n",
        ".gitattributes": "* text=auto\n",
        "AGENTS.md": "instructions\n",
        "conftest.py": "# root conftest\n",
        "pytest.ini": "[pytest]\n",
        "tests/conftest.py": "# tests conftest\n",
        "apps/control-center/requirements.txt": "flask==3.0.0\n",
        "infra/platform/upgrade_step0/verify.sh": "#!/bin/sh\n",
        "infra/platform/platform_upgrader.tf": "# upgrader\n",
        "shared/release_manifest.py": "# manifest\n",
        "apps/control-center/release_source.py": "# source\n",
        _SIGNERS_REL: _signers_line(sync_keys["release_pub"]) + "# key list reviewed\n",
        "docs/café.txt": "non-ASCII name\n",
    }
    others = {
        "apps/control-center/main.py": "print('not an anchor')\n",
        "documentation/notes.txt": "public documentation text is not an anchor\n",
        "tests/test_x.py": "def test_x(): pass\n",
    }
    commit = _commit_files(upstream, env, {**anchors, **others}, "v1.1.0")
    oid = _sign_tag(upstream, env, sync_keys["release"], "v1.1.0")

    res, outputs, runner_temp = _run_sync_through_merge(tmp_path, fork, env, "v1.1.0")
    assert res.returncode == 0, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    assert not [line for line in res.stdout.splitlines() if line.startswith("::error::")]
    assert f"Verified upstream tag v1.1.0: object {oid}, commit {commit}." in res.stdout
    # Even when the fork has no commits of its own, the sync is a two-parent merge commit (--no-ff), as before
    # FD-104: first parent the default branch's head, second the tag's commit, with the same message.
    assert _git(fork, env, "rev-parse", "--abbrev-ref", "HEAD").strip() == "chore/sync-upstream-v1.1.0"
    assert _git(fork, env, "rev-parse", "HEAD^1", "HEAD^2").split() == [pre_head, commit]
    assert _git(fork, env, "log", "-1", "--format=%s").strip() == "chore: sync upstream StackVend v1.1.0"
    assert outputs.get("needs_apply") == "yes"  # infra/platform/ changed

    body = (runner_temp / "pr_body.md").read_text(encoding="utf-8")
    assert f"- Tag object: `{oid}` (annotated, inner tag name `v1.1.0`, one SSH signature)" in body
    assert f"- Commit merged: `{commit}`" in body
    assert f"- Signed by: `{RELEASE_PRINCIPAL}` (a key in this repository's own" in body
    assert body.count(_ANCHOR_HEADING) == 1
    assert "Trust-anchor paths: none changed." not in body
    section = body.split(_ANCHOR_HEADING, 1)[1].split("\n\n", 1)[0]
    listed = sorted(unicodedata.normalize("NFC", line) for line in section.splitlines() if line.startswith("- "))
    assert listed == sorted(f"- `{p}`" for p in anchors)


def _hostile_lightweight(upstream, fork, env, keys):
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _git(upstream, env, "tag", "v1.1.0")
    return "v1.1.0", "SYNC_TAG_NOT_ANNOTATED"


def _hostile_unsigned_annotated(upstream, fork, env, keys):
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, keys["release"], "v1.1.0", signed=False)
    return "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT"


def _hostile_unknown_key(upstream, fork, env, keys):
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, keys["attacker"], "v1.1.0")
    return "v1.1.0", "SYNC_TAG_SIGNATURE_INVALID"


def _hostile_tag_swaps_allowed_signers(upstream, fork, env, keys):
    # The release itself replaces the signer list with the attacker's key and is signed by that key.
    _commit_files(upstream, env, {_SIGNERS_REL: _signers_line(keys["attacker_pub"])}, "v1.1.0 new signer")
    _sign_tag(upstream, env, keys["attacker"], "v1.1.0")
    return "v1.1.0", "SYNC_TAG_SIGNATURE_INVALID"


def _hostile_work_tree_signers_ignored(upstream, fork, env, keys):
    # Only the committed blob at the default branch's head counts, never the work tree's copy.
    (fork / _SIGNERS_REL).write_text(_signers_line(keys["attacker_pub"]), encoding="utf-8")
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, keys["attacker"], "v1.1.0")
    return "v1.1.0", "SYNC_TAG_SIGNATURE_INVALID"


def _hostile_older_signed_object_under_higher_name(upstream, fork, env, keys):
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    old = _sign_tag(upstream, env, keys["release"], "v1.1.0")
    _git(upstream, env, "update-ref", "refs/tags/v2.0.0", old)
    return "v2.0.0", "SYNC_TAG_NAME_MISMATCH"


def _hostile_decoy_tag_line_in_message(upstream, fork, env, keys):
    # A real release-key signature over a v1.1.0 tag whose message holds a decoy `tag v2.0.0` line.
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    obj = _sign_tag(upstream, env, keys["release"], "v1.1.0", message="StackVend v1.1.0\n\ntag v2.0.0\n")
    assert b"\ntag v2.0.0\n" in _raw_tag(upstream, env, obj)
    _git(upstream, env, "update-ref", "refs/tags/v2.0.0", obj)
    return "v2.0.0", "SYNC_TAG_NAME_MISMATCH"


def _hostile_pgp_armor(upstream, fork, env, keys):
    commit = _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    raw = (
        f"object {commit}\ntype commit\ntag v1.1.0\ntagger Test User <test@example.com> 1700000000 +0000\n\n"
        "StackVend v1.1.0\n-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEEexample\n=abcd\n"
        "-----END PGP SIGNATURE-----\n"
    ).encode("ascii")
    _write_tag_object(upstream, env, raw, "v1.1.0")
    return "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT"


def _two_blocks(upstream, env, keys, extra: bytes):
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    good = _sign_tag(upstream, env, keys["release"], "v1.1.0")
    raw = _raw_tag(upstream, env, good)
    i = raw.index(b"-----BEGIN SSH SIGNATURE-----")
    _git(upstream, env, "tag", "-d", "v1.1.0")
    _write_tag_object(upstream, env, raw[:i] + (extra or raw[i:]) + raw[i:], "v1.1.0")


def _hostile_two_ssh_blocks(upstream, fork, env, keys):
    _two_blocks(upstream, env, keys, b"")  # the real SSH block, twice
    return "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT"


def _hostile_pgp_then_ssh_block(upstream, fork, env, keys):
    _two_blocks(upstream, env, keys, b"-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n")
    return "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT"


def _hostile_no_signer_file(upstream, fork, env, keys):
    _git(fork, env, "rm", "-q", _SIGNERS_REL)
    _git(fork, env, "commit", "-q", "-m", "drop signer list")
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, keys["release"], "v1.1.0")
    return "v1.1.0", "SYNC_NO_TRUSTED_KEYS"


def _hostile_signer_file_is_symlink(upstream, fork, env, keys):
    # The link's target holds the right key and the tag is validly signed: refused anyway (not a regular file).
    (fork / "keys").mkdir()
    (fork / "keys" / "signers").write_text(_signers_line(keys["release_pub"]), encoding="utf-8")
    (fork / _SIGNERS_REL).unlink()
    os.symlink("../../keys/signers", fork / _SIGNERS_REL)
    _git(fork, env, "add", "-A")
    _git(fork, env, "commit", "-q", "-m", "signer list as a link")
    assert _git(fork, env, "ls-tree", "HEAD", "--", _SIGNERS_REL).startswith("120000 ")
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, keys["release"], "v1.1.0")
    return "v1.1.0", "SYNC_NO_TRUSTED_KEYS"


def _hostile_signer_file_without_keys(upstream, fork, env, keys):
    (fork / _SIGNERS_REL).write_text("# no keys yet\n\n", encoding="utf-8")
    _git(fork, env, "commit", "-q", "-am", "empty signer list")
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, keys["release"], "v1.1.0")
    return "v1.1.0", "SYNC_NO_TRUSTED_KEYS"


def _hostile_transplanted_release_signature(upstream, fork, env, keys):
    # A real release signature over v1.1.0 at commit A, with the object line moved to another commit B: the signed
    # bytes changed, so verify-tag must fail (review G1).
    first = _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    good = _sign_tag(upstream, env, keys["release"], "v1.1.0")
    second = _commit_files(upstream, env, {"apps/a.py": "attacker\n"}, "not a release")
    raw = _raw_tag(upstream, env, good)
    assert raw.startswith(f"object {first}\n".encode())
    _git(upstream, env, "tag", "-d", "v1.1.0")
    _write_tag_object(upstream, env, f"object {second}\n".encode() + raw.split(b"\n", 1)[1], "v1.1.0")
    return "v1.1.0", "SYNC_TAG_SIGNATURE_INVALID"


def _hostile_flipped_byte_in_message(upstream, fork, env, keys):
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    good = _sign_tag(upstream, env, keys["release"], "v1.1.0", message="StackVend v1.1.0 release notes")
    raw = _raw_tag(upstream, env, good)
    assert raw.count(b"release notes") == 1
    _git(upstream, env, "tag", "-d", "v1.1.0")
    _write_tag_object(upstream, env, raw.replace(b"release notes", b"release notez"), "v1.1.0")
    return "v1.1.0", "SYNC_TAG_SIGNATURE_INVALID"


def _hostile_unsigned_high_tag_on_an_ancestor(upstream, fork, env, keys):
    # Review A1: a lightweight v2.0.0 on a commit the fork already has must fail typed, never read as "nothing to
    # sync" (the verification runs before the ancestry test).
    _git(upstream, env, "tag", "v2.0.0", "v1.0.0^{commit}")
    return "v2.0.0", "SYNC_TAG_NOT_ANNOTATED"


def _hostile_unsigned_annotated_high_tag_on_an_ancestor(upstream, fork, env, keys):
    _sign_tag(upstream, env, keys["release"], "v2.0.0", target="v1.0.0^{commit}", signed=False)
    return "v2.0.0", "SYNC_TAG_SIGNATURE_FORMAT"


def _hostile_signed_tag_of_a_tree(upstream, fork, env, keys):
    # Review G6: a correctly signed tag that points at a tree, not a commit.
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, keys["release"], "v1.1.0", target="HEAD^{tree}")
    return "v1.1.0", "SYNC_TAG_TARGET_NOT_COMMIT"


@pytest.mark.parametrize(
    "make",
    [
        _hostile_transplanted_release_signature,
        _hostile_flipped_byte_in_message,
        _hostile_unsigned_high_tag_on_an_ancestor,
        _hostile_unsigned_annotated_high_tag_on_an_ancestor,
        _hostile_signed_tag_of_a_tree,
        _hostile_lightweight,
        _hostile_unsigned_annotated,
        _hostile_unknown_key,
        _hostile_tag_swaps_allowed_signers,
        _hostile_work_tree_signers_ignored,
        _hostile_older_signed_object_under_higher_name,
        _hostile_decoy_tag_line_in_message,
        _hostile_pgp_armor,
        _hostile_two_ssh_blocks,
        _hostile_pgp_then_ssh_block,
        _hostile_no_signer_file,
        _hostile_signer_file_is_symlink,
        _hostile_signer_file_without_keys,
    ],
    ids=lambda f: f.__name__[len("_hostile_"):],
)
def test_fd104_hostile_tags_are_refused_before_anything_is_merged(tmp_path: Path, sync_keys, make):
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    tag, code = make(upstream, fork, env, sync_keys)
    pre_head = _git(fork, env, "rev-parse", "HEAD").strip()
    res, outputs, runner_temp = _run_sync_through_merge(tmp_path, fork, env, tag)
    _assert_refused(res, outputs, runner_temp, fork, env, code, tag, pre_head)


def test_fd104_the_same_fixture_with_a_release_signature_merges(tmp_path: Path, sync_keys):
    """Positive twin of the hostile cases: the fixture differs only in the tag, so the refusals above come from the
    tag and not from the scratch setup."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, sync_keys["release"], "v1.1.0")
    res, outputs, runner_temp = _run_sync_through_merge(tmp_path, fork, env, "v1.1.0")
    assert res.returncode == 0, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    assert outputs.get("needs_apply") == "no"
    body = (runner_temp / "pr_body.md").read_text(encoding="utf-8")
    assert "\nTrust-anchor paths: none changed.\n" in body


def test_fd104_verified_newest_tag_already_in_the_fork_is_nothing_to_sync(tmp_path: Path, sync_keys):
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)  # v1.0.0 signed, fork has it
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_out.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(env, UPSTREAM_REPO=_UPSTREAM, GITHUB_OUTPUT=str(gh_out), RUNNER_TEMP=str(runner_temp))
    res = _run_bash(_get_step_by_name(_load_workflow(), "sync-upstream", _CHECK_TAG_STEP)["run"], cwd=fork,
                    env=step_env)
    assert "Verified upstream tag v1.0.0" in res.stdout
    assert "Fork already contains release tag v1.0.0; nothing to sync." in res.stdout
    assert _parse_github_output(gh_out) == {"should_sync": "false"}


@pytest.mark.parametrize("odd", ["v9.9.9\u00a0", "v9.9.9\u2028", "\u00a0v9.9.9", "v9.9.9\u2028v9.9.8"])
def test_fd104_tag_names_that_only_look_canonical_are_ignored(tmp_path: Path, sync_keys, odd: str):
    """Review A4: a ref whose name is a release version plus a Unicode space or line separator is not a release tag
    (it is never stripped or split into one); the verified v1.1.0 is synced."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, sync_keys["release"], "v1.1.0")
    _git(upstream, env, "tag", odd, "HEAD")
    assert odd in _git(upstream, env, "for-each-ref", "--format=%(refname:strip=2)", "refs/tags").split("\n")
    res, outputs, _rt = _run_sync_through_merge(tmp_path, fork, env, "v1.1.0")
    assert res.returncode == 0, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    assert outputs.get("target_tag") == "v1.1.0"


def _key_valid_until_2021(fork: Path, env: dict[str, str], keys: dict[str, str]) -> None:
    (fork / _SIGNERS_REL).write_text(
        f'{RELEASE_PRINCIPAL} valid-before="20210101" {keys["release_pub"]}\n', encoding="utf-8")
    _git(fork, env, "commit", "-q", "-am", "key valid until 2021")


def test_fd104_backdated_tag_from_an_expired_key_is_refused(tmp_path: Path, sync_keys):
    """Review delta 1: verify-tag checks the key at the tagger's time, which the signer chooses. A tag backdated to
    2020 by a key that expired in 2021 passes verify-tag; find-principals (current time) names no one, so a sync is
    refused (a stolen expired key cannot ship a release)."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    _key_valid_until_2021(fork, env, sync_keys)
    pre_head = _git(fork, env, "rev-parse", "HEAD").strip()
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, dict(env, GIT_COMMITTER_DATE="2020-06-01T00:00:00+0000"), sync_keys["release"], "v1.1.0")
    res, outputs, runner_temp = _run_sync_through_merge(tmp_path, fork, env, "v1.1.0")
    _assert_refused(res, outputs, runner_temp, fork, env, "SYNC_SIGNER_KEY_NOT_CURRENT", "v1.1.0", pre_head)
    assert "Verified upstream tag v1.1.0" in res.stdout  # verify-tag itself passed
    assert "::warning::" not in res.stdout


def test_fd104_key_current_only_for_another_namespace_is_refused(tmp_path: Path, sync_keys):
    """Review delta 5: the same key has a `git` entry that expired in 2021 and a current entry for the `file`
    namespace only. A tag backdated to 2020 passes verify-tag (git entry at the tagger's time); find-principals may
    name the principal (it does not check the namespace), but `ssh-keygen -Y verify -n git` at the current time
    fails, so the sync is refused."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    pub = sync_keys["release_pub"]
    (fork / _SIGNERS_REL).write_text(
        f'{RELEASE_PRINCIPAL} namespaces="git",valid-before="20210101" {pub}\n'
        f'{RELEASE_PRINCIPAL} namespaces="file" {pub}\n', encoding="utf-8")
    _git(fork, env, "commit", "-q", "-am", "git entry expired, file entry current")
    pre_head = _git(fork, env, "rev-parse", "HEAD").strip()
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, dict(env, GIT_COMMITTER_DATE="2020-06-01T00:00:00+0000"), sync_keys["release"], "v1.1.0")
    res, outputs, runner_temp = _run_sync_through_merge(tmp_path, fork, env, "v1.1.0")
    _assert_refused(res, outputs, runner_temp, fork, env, "SYNC_SIGNER_KEY_NOT_CURRENT", "v1.1.0", pre_head)
    assert "Verified upstream tag v1.1.0" in res.stdout  # verify-tag itself passed
    # The log says why (find-principals named the principal; -Y verify -n git refused it now).
    assert (f"Principal {RELEASE_PRINCIPAL} did not verify upstream tag v1.1.0 at the current time (namespace git)."
            in res.stdout)
    assert "or one not valid for the git namespace" in res.stdout


def test_fd104_current_git_namespace_entry_syncs_and_names_the_principal(tmp_path: Path, sync_keys):
    """Positive twin: a current entry restricted to the `git` namespace verifies now; the body names it."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    (fork / _SIGNERS_REL).write_text(f'{RELEASE_PRINCIPAL} namespaces="git" {sync_keys["release_pub"]}\n',
                                     encoding="utf-8")
    _git(fork, env, "commit", "-q", "-am", "git namespace only")
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, sync_keys["release"], "v1.1.0")
    res, outputs, runner_temp = _run_sync_through_merge(tmp_path, fork, env, "v1.1.0")
    assert res.returncode == 0, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    assert (runner_temp / "tag_signers.txt").read_text() == f"{RELEASE_PRINCIPAL}\n"
    assert f"- Signed by: `{RELEASE_PRINCIPAL}` " in (runner_temp / "pr_body.md").read_text(encoding="utf-8")


def test_fd104_find_principals_naming_no_one_with_exit_0_is_refused(tmp_path: Path, sync_keys):
    """Review delta 4: an ssh-keygen whose find-principals prints nothing and exits 0 for the workflow's own call
    (git's verify-tag runs find-principals on its own temporary file, which goes to the real ssh-keygen, so
    verify-tag still passes) leaves no current principal: the sync is refused."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    pre_head = _git(fork, env, "rev-parse", "HEAD").strip()
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, sync_keys["release"], "v1.1.0")
    real = shutil.which("ssh-keygen")
    bin_dir = tmp_path / "sshbin"
    bin_dir.mkdir()
    (bin_dir / "ssh-keygen").write_text(
        '#!/bin/sh\n'
        'if [ "$1" = -Y ] && [ "$2" = find-principals ]; then\n'
        '  for a in "$@"; do [ "$a" = "$RUNNER_TEMP/tag_signature.sig" ] && exit 0; done\n'
        'fi\n'
        f'exec "{real}" "$@"\n',
        encoding="utf-8")
    (bin_dir / "ssh-keygen").chmod(0o755)
    wrapped = dict(env, PATH=f"{bin_dir}{os.pathsep}{env.get('PATH') or os.environ.get('PATH', '')}")
    res, outputs, runner_temp = _run_sync_through_merge(tmp_path, fork, wrapped, "v1.1.0")
    _assert_refused(res, outputs, runner_temp, fork, env, "SYNC_SIGNER_KEY_NOT_CURRENT", "v1.1.0", pre_head)
    assert (runner_temp / "tag_signers.txt").read_text() == ""


def test_fd104_expired_key_on_a_tag_already_in_the_fork_only_warns(tmp_path: Path, sync_keys):
    """Already-ancestor twin: nothing would be synced, so the current-time check is a warning only."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    _key_valid_until_2021(fork, env, sync_keys)
    _sign_tag(upstream, dict(env, GIT_COMMITTER_DATE="2020-06-01T00:00:00+0000"), sync_keys["release"], "v2.0.0",
              target="v1.0.0^{commit}")
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_out.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(env, UPSTREAM_REPO=_UPSTREAM, GITHUB_OUTPUT=str(gh_out), RUNNER_TEMP=str(runner_temp))
    res = _run_bash(_get_step_by_name(_load_workflow(), "sync-upstream", _CHECK_TAG_STEP)["run"], cwd=fork,
                    env=step_env)
    warnings = [x for x in res.stdout.splitlines() if x.startswith("::warning::")]
    assert len(warnings) == 1
    assert warnings[0].startswith("::warning::SYNC_SIGNER_PRINCIPAL_UNKNOWN: upstream tag v2.0.0")
    assert not [x for x in res.stdout.splitlines() if x.startswith("::error::")]
    assert "Fork already contains release tag v2.0.0; nothing to sync." in res.stdout
    assert _parse_github_output(gh_out) == {"should_sync": "false"}


def test_fd104_expired_key_at_the_tagger_time_is_refused(tmp_path: Path, sync_keys):
    """Negative twin of the principal-unknown case: a tag made after the key's valid-before fails verify-tag."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    (fork / _SIGNERS_REL).write_text(
        f'{RELEASE_PRINCIPAL} valid-before="20210101" {sync_keys["release_pub"]}\n', encoding="utf-8")
    _git(fork, env, "commit", "-q", "-am", "key valid until 2021")
    pre_head = _git(fork, env, "rev-parse", "HEAD").strip()
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, sync_keys["release"], "v1.1.0")  # tagger time = now
    res, outputs, runner_temp = _run_sync_through_merge(tmp_path, fork, env, "v1.1.0")
    _assert_refused(res, outputs, runner_temp, fork, env, "SYNC_TAG_SIGNATURE_INVALID", "v1.1.0", pre_head)


def _verified_then_merge_env(tmp_path: Path, sync_keys) -> tuple[Path, dict[str, str], Path, Path]:
    """A fork and a signed v1.1.0 after the verify step ran (its outputs in env), before the merge step."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, sync_keys["release"], "v1.1.0")
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_out.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(env, UPSTREAM_REPO=_UPSTREAM, GITHUB_OUTPUT=str(gh_out), RUNNER_TEMP=str(runner_temp),
                    BRANCH_NAME="chore/sync-upstream-v1.1.0", TARGET_TAG="v1.1.0")
    _run_check(_get_step_by_name(_load_workflow(), "sync-upstream", _CHECK_TAG_STEP)["run"], cwd=fork, env=step_env)
    return fork, step_env, runner_temp, gh_out


def _run_merge_step(fork: Path, step_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-eo", "pipefail"], input=_get_step_by_name(_load_workflow(), "sync-upstream", _MERGE_STEP)["run"],
        text=True, capture_output=True, cwd=fork, env=step_env,
    )


def _no_sync_branch(fork: Path, env: dict[str, str]) -> bool:
    return subprocess.run(["git", "show-ref", "--verify", "--quiet", "refs/heads/chore/sync-upstream-v1.1.0"],
                          cwd=fork, env=env).returncode == 1


@pytest.mark.parametrize("what", ["head-moved", "other-commit"])
def test_fd104_state_changed_between_verify_and_merge_is_refused(tmp_path: Path, sync_keys, what: str):
    fork, step_env, runner_temp, gh_out = _verified_then_merge_env(tmp_path, sync_keys)
    if what == "head-moved":
        _commit_files(fork, step_env, {"fork.txt": "moved\n"}, "HEAD moved after verification")
    else:
        step_env["TAG_COMMIT"] = step_env["BASE_SHA"]
    res = _run_merge_step(fork, step_env)
    assert res.returncode == 1
    assert [x for x in res.stdout.splitlines() if x.startswith("::error::")] == [
        f"::error::SYNC_STATE_CHANGED: the checkout or the verified tag object {step_env['TAG_OID']} changed after "
        "verification; nothing was merged or pushed."
    ]
    assert _no_sync_branch(fork, step_env)
    assert "needs_apply" not in _parse_github_output(gh_out)
    assert not (runner_temp / "pr_body.md").exists()


def test_fd104_failed_pr_body_is_a_typed_error(tmp_path: Path, sync_keys):
    fork, step_env, runner_temp, gh_out = _verified_then_merge_env(tmp_path, sync_keys)
    (runner_temp / "tag_signers.txt").unlink()  # the body helper cannot read the signer list
    res = _run_merge_step(fork, step_env)
    assert res.returncode == 1
    assert [x for x in res.stdout.splitlines() if x.startswith("::error::")] == [
        f"::error::SYNC_PR_BODY_FAILED: the pull request body for v1.1.0 (object {step_env['TAG_OID']}) could not "
        "be written; nothing was pushed."
    ]
    assert not (runner_temp / "pr_body.md").exists()


def test_fd104_failed_ancestry_check_is_a_typed_error(tmp_path: Path, sync_keys):
    """A `git` wrapper first on PATH makes only `merge-base` fail with 128 (as on a damaged repository)."""
    upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    _commit_files(upstream, env, {"apps/a.py": "x\n"}, "v1.1.0")
    _sign_tag(upstream, env, sync_keys["release"], "v1.1.0")
    real_git = shutil.which("git")
    bin_dir = tmp_path / "gitbin"
    bin_dir.mkdir()
    (bin_dir / "git").write_text(
        f'#!/bin/sh\nif [ "$1" = merge-base ]; then echo "fatal: damaged" >&2; exit 128; fi\nexec "{real_git}" "$@"\n',
        encoding="utf-8")
    (bin_dir / "git").chmod(0o755)
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_out.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(env, UPSTREAM_REPO=_UPSTREAM, GITHUB_OUTPUT=str(gh_out), RUNNER_TEMP=str(runner_temp),
                    PATH=f"{bin_dir}{os.pathsep}{env.get('PATH') or os.environ.get('PATH', '')}")
    res = subprocess.run(
        ["bash", "-eo", "pipefail"], input=_get_step_by_name(_load_workflow(), "sync-upstream", _CHECK_TAG_STEP)["run"],
        text=True, capture_output=True, cwd=fork, env=step_env,
    )
    assert res.returncode == 128
    assert [x for x in res.stdout.splitlines() if x.startswith("::error::")] == [
        "::error::SYNC_ANCESTRY_CHECK_FAILED: git merge-base --is-ancestor failed for v1.1.0 (exit 128); nothing was "
        "merged or pushed."
    ]
    assert "should_sync" not in _parse_github_output(gh_out)


def test_fd104_failed_upstream_fetch_is_a_typed_error(tmp_path: Path, sync_keys):
    """Review G8: the checkout keeps no credential, so a private (or missing) upstream fails typed."""
    _upstream, fork, env = _init_scratch_upstream_and_fork(tmp_path, sync_keys)
    _git(fork, env, "config", f"url.file://{tmp_path / 'no-such-repo'}.insteadOf",
         "https://github.com/example-org/private-stackvend.git")
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir()
    gh_out = tmp_path / "gh_out.txt"
    gh_out.write_text("", encoding="utf-8")
    step_env = dict(env, UPSTREAM_REPO="example-org/private-stackvend", GITHUB_OUTPUT=str(gh_out),
                    RUNNER_TEMP=str(runner_temp))
    res = subprocess.run(
        ["bash", "-eo", "pipefail"], input=_get_step_by_name(_load_workflow(), "sync-upstream", _CHECK_TAG_STEP)["run"],
        text=True, capture_output=True, cwd=fork, env=step_env,
    )
    assert res.returncode == 1
    errors = [x for x in res.stdout.splitlines() if x.startswith("::error::")]
    assert errors == [
        "::error::SYNC_UPSTREAM_FETCH_FAILED: could not fetch the tags of "
        "https://github.com/example-org/private-stackvend.git without credentials; the upstream must be a public "
        "repository. Nothing was synced."
    ]
    assert _parse_github_output(gh_out) == {}


# ---- static checks of the workflow -------------------------------------------------------------------------------
def _string_paths(node: Any, needle: str, path: tuple = ()) -> list[tuple]:
    if isinstance(node, dict):
        return [p for k, v in node.items() for p in _string_paths(v, needle, path + (k,))]
    if isinstance(node, list):
        return [p for i, v in enumerate(node) for p in _string_paths(v, needle, path + (i,))]
    return [path] if isinstance(node, str) and needle in node else []


def _push_command(run: str) -> list[str]:
    commands = [
        shlex.split(line.strip())
        for line in run.replace("\\\n", " ").splitlines()
        if line.strip().startswith("git ")
    ]
    pushes = [argv for argv in commands if "push" in argv]
    assert len(pushes) == 1
    return pushes[0]


def test_fd104_sync_token_reaches_only_the_push_step():
    wf = _load_workflow()
    steps = wf["jobs"]["sync-upstream"]["steps"]
    names = [s.get("name") for s in steps]
    push_i = names.index(_PUSH_STEP)
    assert push_i == len(steps) - 1  # the last step: nothing runs after the token is present
    base = ("jobs", "sync-upstream", "steps", push_i, "env")
    assert sorted(_string_paths(wf, "STACKVEND_SYNC_TOKEN")) == sorted([base + ("GH_TOKEN",), base + ("SYNC_PUSH_TOKEN",)])
    assert sorted(_string_paths(wf, "secrets.")) == sorted([base + ("GH_TOKEN",), base + ("SYNC_PUSH_TOKEN",)])

    checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["token"] == "${{ github.token }}"

    # The push gets the token from a credential helper on its own command line only, with hooks off.
    run = steps[push_i]["run"]
    assert run.count("SYNC_PUSH_TOKEN") == 1
    push = _push_command(run)
    configs = [push[i + 1] for i, arg in enumerate(push) if arg == "-c"]
    helpers = [c for c in configs if c.startswith("credential.helper=")]
    assert helpers[0] == "credential.helper="  # resets any inherited helper first
    assert len(helpers) == 2 and helpers[1].startswith("credential.helper=!") and "${SYNC_PUSH_TOKEN}" in helpers[1]
    assert "core.hooksPath=/dev/null" in configs
    for step in steps[:push_i]:
        assert "SYNC_PUSH_TOKEN" not in json.dumps(step)
        assert "git push" not in step.get("run", "") and "gh pr create" not in step.get("run", "")


def test_fd104_helper_runs_isolated_and_the_tag_is_verified_before_ancestry_and_merge():
    wf = _load_workflow()
    steps = wf["jobs"]["sync-upstream"]["steps"]
    for step in steps:
        code = "\n".join(line for line in step.get("run", "").splitlines() if not line.strip().startswith("#"))
        assert code.count("python3") == code.count("python3 -I "), step["name"]
    check = _get_step_by_name(wf, "sync-upstream", _CHECK_TAG_STEP)["run"]
    merge = _get_step_by_name(wf, "sync-upstream", _MERGE_STEP)["run"]
    # One object id, resolved once from the fetched ref in the verify step; the merge step never reads the ref.
    assert check.count("TAG_OID=") == 1
    assert 'TAG_OID=$(git rev-parse --verify "refs/upstream-tags/${TARGET_TAG}")' in check
    assert "refs/upstream-tags" not in merge and "TAG_OID=" not in merge
    assert 'git merge-base --is-ancestor "${TAG_COMMIT}" HEAD' in check
    order = [check.index(x) for x in (
        "--check-signers", "cat-file -t", "--check-tag-object", 'verify-tag "${TAG_OID}"', "TAG_COMMIT=",
        "find-principals", "merge-base --is-ancestor", "refuse SYNC_SIGNER_KEY_NOT_CURRENT", "should_sync=true",
    )]
    assert order == sorted(order)
    for flag in ("gpg.format=ssh", "gpg.ssh.program=ssh-keygen", "gpg.program=false", "gpg.openpgp.program=false",
                 "gpg.x509.program=false", '"gpg.ssh.allowedSignersFile=${SIGNERS}" verify-tag "${TAG_OID}"'):
        assert f"-c {flag}" in check, flag
    # The signer list is the default branch's committed blob, never a work-tree file.
    assert '"${BASE_SHA}" -- scripts/release/allowed_signers' in check
    assert "cat scripts/release" not in check and "< scripts/release" not in check
    for code in ("SYNC_NO_TRUSTED_KEYS", "SYNC_TAG_NOT_ANNOTATED", "SYNC_TAG_NAME_MISMATCH",
                 "SYNC_TAG_SIGNATURE_FORMAT", "SYNC_TAG_SIGNATURE_INVALID", "SYNC_TAG_TARGET_NOT_COMMIT",
                 "SYNC_SIGNER_KEY_NOT_CURRENT"):
        assert f"refuse {code} " in check, code
    for code in ("SYNC_UPSTREAM_FETCH_FAILED", "SYNC_ANCESTRY_CHECK_FAILED", "SYNC_SIGNER_PRINCIPAL_UNKNOWN"):
        assert code in check, code
    # The current-time check: -Y verify per principal, namespace git, no verify-time option.
    assert 'ssh-keygen -Y verify -f "${SIGNERS}" -I "${principal}" -n git' in check
    assert '< "${RUNNER_TEMP}/tag_payload.bin"' in check and "verify-time" not in check
    # The merge step merges exactly the verified object onto the verified head, as a two-parent commit.
    assert merge.count("python3 -I \"") == 2  # needs apply, --pr-body
    assert '"${PRE_MERGE_SHA}" != "${BASE_SHA}"' in merge and "SYNC_STATE_CHANGED" in merge
    assert "SYNC_PR_BODY_FAILED" in merge
    merge_lines = [line.strip() for line in merge.splitlines() if "git merge " in line and "::error::" not in line]
    assert merge_lines == [
        'if ! GIT_LFS_SKIP_SMUDGE=1 git merge --no-ff "${TAG_OID}^{commit}" --no-edit -m "chore: sync upstream '
        'StackVend ${TARGET_TAG}"; then'
    ]
    assert merge.index("SYNC_STATE_CHANGED") < merge.index("git checkout -B")
    step_env = _get_step_by_name(wf, "sync-upstream", _MERGE_STEP)["env"]
    for key, out in (("TAG_OID", "tag_oid"), ("TAG_COMMIT", "tag_commit"), ("BASE_SHA", "base_sha")):
        assert step_env[key] == "${{ steps.check_tag.outputs.%s }}" % out


def test_fd104_every_gh_step_pins_this_repository():
    """Review A3: gh never resolves the repository from the `upstream` remote."""
    wf = _load_workflow()
    for step in wf["jobs"]["sync-upstream"]["steps"]:
        calls_gh = any(
            line.strip().startswith("gh ") or "$(gh " in line for line in step.get("run", "").splitlines()
        )
        if calls_gh or "GH_TOKEN" in step.get("env", {}):
            assert step["env"]["GH_REPO"] == "${{ github.repository }}", step["name"]


def test_fd104_run_scripts_use_the_shell_the_tests_use():
    """Review G9: every run script stops on the first failure, inside pipes too, exactly as the tests run them
    (`shell: bash` is GitHub's `bash --noprofile --norc -eo pipefail {0}`; the tests run `bash -eo pipefail`)."""
    wf = _load_workflow()
    assert wf["defaults"] == {"run": {"shell": "bash"}}
    for job in wf["jobs"].values():
        assert "defaults" not in job
        for step in job["steps"]:
            assert "shell" not in step


# ---- the push / PR step, executed -------------------------------------------------------------------------------
_FAKE_GH_CREATE = r'''
import json, os, sys
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
sys.exit(0 if sys.argv[1:3] == ["pr", "create"] else 90)
'''
_TOKEN_SENTINEL = "fd104-sentinel-token-value"


def _push_world(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    env = hermetic_guard.child_env(
        extra={
            "HOME": str(tmp_path),
            "GIT_AUTHOR_NAME": "Test User",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test User",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
    )
    origin = tmp_path / "origin.git"
    _git(tmp_path, env, "init", "-q", "--bare", "-b", "main", str(origin))
    work = tmp_path / "work"
    _git(tmp_path, env, "clone", "-q", f"file://{origin}", str(work))
    _commit_files(work, env, {"README.md": "base\n"}, "base")
    _git(work, env, "push", "-q", "origin", "main")
    _git(work, env, "checkout", "-q", "-b", "chore/sync-upstream-v1.2.0")
    _commit_files(work, env, {"README.md": "synced\n"}, "sync")
    return origin, work, env


def _run_push_step(tmp_path: Path, work: Path, env: dict[str, str], branch: str, tag: str, base: str):
    wf = _load_workflow()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake_gh = bin_dir / "gh"
    fake_gh.write_text(f"#!{sys.executable}\n" + _FAKE_GH_CREATE, encoding="utf-8")
    fake_gh.chmod(0o755)
    runner_temp = tmp_path / "runner_temp"
    runner_temp.mkdir(exist_ok=True)
    (runner_temp / "pr_body.md").write_text("body\n", encoding="utf-8")
    gh_log = tmp_path / "gh_calls.jsonl"
    run_env = dict(env)
    run_env.update(
        {
            "PATH": f"{bin_dir}{os.pathsep}{env.get('PATH') or os.environ.get('PATH', '')}",
            "SYNC_PUSH_TOKEN": _TOKEN_SENTINEL,
            "GH_TOKEN": _TOKEN_SENTINEL,
            "BRANCH_NAME": branch,
            "TARGET_TAG": tag,
            "BASE_BRANCH": base,
            "RUNNER_TEMP": str(runner_temp),
            "FAKE_GH_LOG": str(gh_log),
        }
    )
    res = subprocess.run(
        ["bash", "-eo", "pipefail"], input=_get_step_by_name(wf, "sync-upstream", _PUSH_STEP)["run"], text=True,
        capture_output=True, cwd=work, env=run_env,
    )
    calls = [json.loads(x) for x in gh_log.read_text(encoding="utf-8").splitlines()] if gh_log.exists() else []
    return res, calls, runner_temp


def _remote_heads(origin: Path, env: dict[str, str]) -> dict[str, str]:
    out = _git(origin, env, "for-each-ref", "--format=%(refname) %(objectname)", "refs/heads")
    return dict(line.split(" ", 1) for line in out.splitlines())


def test_fd104_push_step_pushes_only_the_sync_branch_and_persists_no_credential(tmp_path: Path):
    origin, work, env = _push_world(tmp_path)
    main_before = _remote_heads(origin, env)["refs/heads/main"]
    res, calls, runner_temp = _run_push_step(tmp_path, work, env, "chore/sync-upstream-v1.2.0", "v1.2.0", "main")
    assert res.returncode == 0, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    heads = _remote_heads(origin, env)
    assert heads == {
        "refs/heads/main": main_before,
        "refs/heads/chore/sync-upstream-v1.2.0": _git(work, env, "rev-parse", "HEAD").strip(),
    }
    assert calls == [[
        "pr", "create", "--base", "main", "--head", "chore/sync-upstream-v1.2.0",
        "--title", "🔄 chore: sync upstream StackVend v1.2.0", "--body-file", str(runner_temp / "pr_body.md"),
    ]]
    # Nothing of the token or of the helper was written to the repository's configuration.
    assert _TOKEN_SENTINEL not in (work / ".git" / "config").read_text(encoding="utf-8")
    assert subprocess.run(["git", "config", "--local", "--get-all", "credential.helper"], cwd=work, env=env).returncode == 1


@pytest.mark.parametrize(
    "branch,tag,base",
    [
        pytest.param("main", "v1.2.0", "main", id="default-branch"),
        pytest.param("chore/sync-upstream-v1.2.0", "v1.2.0", "chore/sync-upstream-v1.2.0", id="sync-name-is-default"),
        pytest.param("chore/sync-upstream-v1.2.0", "v1.3.0", "main", id="other-tag"),
        pytest.param("chore/sync-upstream-v1.2.0", "v1.2.0", "", id="no-base"),
    ],
)
def test_fd104_push_step_refuses_the_default_branch_or_any_other_target(tmp_path: Path, branch, tag, base):
    origin, work, env = _push_world(tmp_path)
    before = _remote_heads(origin, env)
    res, calls, _rt = _run_push_step(tmp_path, work, env, branch, tag, base)
    assert res.returncode == 1
    errors = [line for line in res.stdout.splitlines() if line.startswith("::error::")]
    assert len(errors) == 1 and errors[0].startswith("::error::SYNC_PUSH_TARGET: ") and "nothing was pushed" in errors[0]
    assert _remote_heads(origin, env) == before
    assert calls == []


def test_fd104_credential_helper_answers_get_only_from_the_environment(tmp_path: Path):
    push = _push_command(_get_step_by_name(_load_workflow(), "sync-upstream", _PUSH_STEP)["run"])
    snippet = next(push[i + 1] for i, a in enumerate(push) if a == "-c" and push[i + 1].startswith("credential.helper=!"))
    snippet = snippet[len("credential.helper=!"):]
    env = hermetic_guard.child_env(extra={"HOME": str(tmp_path), "SYNC_PUSH_TOKEN": _TOKEN_SENTINEL})
    # git runs a `!` helper as a shell snippet with the action appended (gitcredentials(7)).
    got = subprocess.run(["sh", "-c", f"{snippet} get"], text=True, capture_output=True, env=env, check=True)
    assert got.stdout == f"username=x-access-token\npassword={_TOKEN_SENTINEL}\n"
    for action in ("store", "erase"):
        other = subprocess.run(["sh", "-c", f"{snippet} {action}"], text=True, capture_output=True, env=env, check=True)
        assert other.stdout == ""
    assert _TOKEN_SENTINEL not in snippet


# ---- helper: tag object, signer list, trust anchors, PR body ----------------------------------------------------
_FAKE_SSH_BLOCK = b"-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ\nAAAA\n-----END SSH SIGNATURE-----\n"
_PGP_BLOCK = b"-----BEGIN PGP SIGNATURE-----\n\niQEz\n=abcd\n-----END PGP SIGNATURE-----\n"


def _tag_raw(name: bytes = b"v1.1.0", message: bytes = b"StackVend v1.1.0\n", sig: bytes = _FAKE_SSH_BLOCK,
             extra_headers: bytes = b"") -> bytes:
    return (
        b"object " + b"c" * 40 + b"\ntype commit\ntag " + name + b"\n" + extra_headers
        + b"tagger Test User <test@example.com> 1700000000 +0000\n\n" + message + sig
    )


@pytest.mark.parametrize(
    "raw,expected_tag,code",
    [
        pytest.param(_tag_raw(), "v1.1.0", None, id="good"),
        pytest.param(_tag_raw(sig=_FAKE_SSH_BLOCK + b"\n\n"), "v1.1.0", None, id="good-trailing-blank-lines"),
        pytest.param(_tag_raw(message=b"notes\ntag v2.0.0\n"), "v2.0.0", "SYNC_TAG_NAME_MISMATCH", id="decoy-in-message"),
        pytest.param(_tag_raw(message=b"notes\ntag v2.0.0\n"), "v1.1.0", None, id="decoy-ignored-for-real-name"),
        pytest.param(_tag_raw(), "v2.0.0", "SYNC_TAG_NAME_MISMATCH", id="other-name"),
        pytest.param(_tag_raw(name=b"v1.1.0 "), "v1.1.0", "SYNC_TAG_NAME_MISMATCH", id="trailing-space"),
        pytest.param(_tag_raw(extra_headers=b"tag v2.0.0\n"), "v1.1.0", "SYNC_TAG_NAME_MISMATCH", id="two-tag-headers"),
        pytest.param(b"object " + b"c" * 40 + b"\ntype commit\n\nmsg\n" + _FAKE_SSH_BLOCK, "v1.1.0",
                     "SYNC_TAG_NAME_MISMATCH", id="no-tag-header"),
        pytest.param(_tag_raw(sig=b""), "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT", id="unsigned"),
        pytest.param(_tag_raw(sig=_PGP_BLOCK), "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT", id="pgp"),
        pytest.param(_tag_raw(sig=_PGP_BLOCK + _FAKE_SSH_BLOCK), "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT", id="pgp+ssh"),
        pytest.param(_tag_raw(sig=_FAKE_SSH_BLOCK + _FAKE_SSH_BLOCK), "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT",
                     id="ssh+ssh"),
        pytest.param(_tag_raw(sig=_FAKE_SSH_BLOCK + b"trailing text\n"), "v1.1.0", "SYNC_TAG_SIGNATURE_FORMAT",
                     id="text-after-block"),
        pytest.param(_tag_raw(sig=_FAKE_SSH_BLOCK.replace(b"-----END SSH SIGNATURE-----\n", b"")), "v1.1.0",
                     "SYNC_TAG_SIGNATURE_FORMAT", id="no-end-line"),
        pytest.param(_tag_raw(sig=b"-----BEGIN SIGNED MESSAGE-----\nx\n" + _FAKE_SSH_BLOCK), "v1.1.0",
                     "SYNC_TAG_SIGNATURE_FORMAT", id="x509-style+ssh"),
    ],
)
def test_fd104_check_tag_object(raw: bytes, expected_tag: str, code: str | None, tmp_path: Path):
    assert sync_mod.check_tag_object(raw, expected_tag) == code
    sig_out = tmp_path / "sig"
    res = subprocess.run(
        [sys.executable, "-I", str(SCRIPT_PATH), "--check-tag-object", "--tag", expected_tag,
         "--signature-out", str(sig_out)],
        input=raw, capture_output=True, env=hermetic_guard.child_env(),
    )
    assert res.returncode == {None: 0, "SYNC_TAG_NAME_MISMATCH": 3, "SYNC_TAG_SIGNATURE_FORMAT": 4}[code]
    if code is None:
        assert sig_out.read_bytes() == _FAKE_SSH_BLOCK
    else:
        assert not sig_out.exists()
        assert res.stderr.decode() == f"{code}\n"


def test_fd104_signed_payload_is_the_object_before_the_signature(tmp_path: Path):
    raw = _tag_raw(sig=_FAKE_SSH_BLOCK + b"\n")
    assert sync_mod.signed_payload(raw) == raw[: raw.index(b"-----BEGIN SSH SIGNATURE-----")]
    assert sync_mod.signed_payload(_tag_raw(sig=_PGP_BLOCK)) is None
    assert sync_mod.signed_payload(_tag_raw(sig=b"")) is None
    out = tmp_path / "payload"
    res = subprocess.run(
        [sys.executable, "-I", str(SCRIPT_PATH), "--check-tag-object", "--tag", "v1.1.0", "--payload-out", str(out)],
        input=raw, capture_output=True, env=hermetic_guard.child_env(),
    )
    assert res.returncode == 0 and out.read_bytes() == sync_mod.signed_payload(raw)


@pytest.mark.parametrize("tag", ["", "v1.1", "v1.1.0-rc1", " v1.1.0", "v1.1.0 "])
def test_fd104_check_tag_object_refuses_an_invalid_tag_argument(tag: str):
    res = subprocess.run(
        [sys.executable, "-I", str(SCRIPT_PATH), "--check-tag-object", "--tag", tag],
        input=_tag_raw(), capture_output=True, env=hermetic_guard.child_env(),
    )
    assert res.returncode == 2


@pytest.mark.parametrize(
    "content,ok",
    [
        (b"", False),
        (b"\n\n  \n", False),
        (b"# only a comment\n\n", False),
        (b"   # indented comment\n", False),
        (b"stackvend-release ssh-ed25519 AAAAexample\n", True),
        (b"# comment\nstackvend-release ssh-ed25519 AAAAexample", True),
    ],
)
def test_fd104_check_signers(content: bytes, ok: bool):
    assert sync_mod.has_trusted_keys(content) is ok
    res = subprocess.run(
        [sys.executable, "-I", str(SCRIPT_PATH), "--check-signers"], input=content, capture_output=True,
        env=hermetic_guard.child_env(),
    )
    assert res.returncode == (0 if ok else 1)


@pytest.mark.parametrize(
    "path,expected",
    [
        ("scripts/release/allowed_signers", True),
        ("scripts/upgrade.sh", True),
        ("scripts/sync_upstream_needs_apply.py", True),
        ("Scripts/upgrade.sh", True),  # case folding (macOS folds case)
        ("SCRIPTS/RELEASE/ALLOWED_SIGNERS", True),
        ("scripts-old/x", False),  # whole components, never a string prefix
        ("scripts", True),  # a file that replaces the folder (review A5 / G4)
        ("my-scripts/x", False),
        (".github/workflows/ci.yml", True),
        (".GitHub/workflows/ci.yml", True),
        (".githubx/y", True),  # a root dot entry
        (".agents/skills/example/SKILL.md", True),
        (".vscode/settings.json", True),
        (".devcontainer/devcontainer.json", True),
        (".envrc", True),
        (".gitattributes", True),
        (".gitmodules", True),
        (".lfsconfig", True),
        ("docs/.hidden", True),  # a dot entry at any depth
        ("apps/x/.tool/settings.json", True),
        ("documentation/.hidden/x", True),
        ("apps/x.y/z.py", False),  # a dot inside a name is not a dot entry
        ("AGENTS.md", True),
        ("README.MD", True),
        ("CHANGELOG.md", True),
        ("AGENTS.md.bak", False),
        ("docs/AGENTS.md", True),  # agent instruction file in a sub-folder
        ("docs/agents.md", True),
        ("docs/AGENTS.md.txt", False),
        ("docs/notes.md", True),  # every Markdown file, at any depth
        ("apps/x/skills/review/SKILL.md", True),
        ("documentation/guide.md", True),
        ("documentation/sub/guide.md", True),
        ("documentation/sub/SKILL.md", True),
        ("apps/documentation/x.md", True),
        ("Documentation/guide.MD", True),
        ("documentation/guide.txt", False),
        ("documentation/AGENTS.md", True),  # the AGENTS.md name rule still applies
        ("documentation.md", True),  # a root file, not under documentation/
        ("docs/notes.mdx", False),
        ("shared/release_manifest.py", True),
        ("Shared/Release_Manifest.py", True),
        ("shared/release_manifest.pyc", False),
        ("apps/control-center/shared/release_manifest.py", False),
        ("apps/control-center/release_source.py", True),
        ("infra/platform/upgrade_step0/verify.sh", True),
        ("infra/platform/upgrade_step0x/a.sh", False),
        ("infra/platform/upgrade_step0", True),
        ("infra/platform/platform_upgrader.tf", True),
        ("infra/platform/main.tf", False),
        ("conftest.py", True),
        ("pytest.ini", True),
        ("tests/conftest.py", True),
        ("tests/sub/conftest.py", True),  # conftest.py at any depth
        ("apps/x/conftest.py", True),
        ("apps/x/my_conftest.py", False),
        ("apps/x/sitecustomize.py", True),
        ("lib/SiteCustomize.py", True),
        ("apps/x/ci-constraints.txt", True),
        ("constraints.txt", True),
        ("apps/x/constraints.py", False),
        ("pyproject.toml", True),
        ("apps/x/pyproject.toml", True),
        ("apps/x/setup.py", True),
        ("apps/x/setup.cfg", True),
        ("apps/x/pytest.ini", True),
        ("apps/x/tox.ini", True),
        ("lib/usercustomize.py", True),
        ("lib/python3/site-packages/evil.pth", True),
        ("x.pth", True),
        ("apps/x/GNUmakefile", True),
        ("apps/x/setup.pyc", False),
        ("setup.cfg", True),
        ("tox.ini", True),
        ("Makefile", True),
        ("makefile", True),
        ("apps/Makefile", True),
        ("requirements.txt", True),
        ("apps/x/requirements.txt", True),
        ("mcp-servers/y/requirements-dev.txt", True),
        ("apps/x/Requirements.TXT", True),
        ("apps/x/requirements.txt.orig", False),
        ("apps/x/my-requirements.txt", False),
        ("apps/control-center/main.py", False),
        ("tests/test_x.py", False),
        ("", False),
        # every path holding a non-ASCII character, whatever the rules say
        ("ſcripts/x", True),  # long s: casefold() makes it "scripts", lower() would not
        ("apps/a‌b.py", True),  # ZWNJ (HFS+ ignores some invisible code points)
        (unicodedata.normalize("NFD", "docs/café.txt"), True),
        ("docs/café.txt", True),
    ],
)
def test_fd104_trust_anchor_membership(path: str, expected: bool):
    assert sync_mod.is_trust_anchor(path) is expected


def test_fd104_trust_anchor_folding_is_nfc_then_casefold():
    assert sync_mod._fold("ſcripts/X") == "scripts/x"
    assert sync_mod._fold(unicodedata.normalize("NFD", "Café")) == "café"
    assert "ſcripts".lower() != "scripts"  # why lower() is not enough


def test_fd104_trust_anchor_paths_keep_order_and_spelling_and_drop_duplicates():
    paths = ["apps/a.py", "Scripts/x.sh", ".github/a.yml", "Scripts/x.sh", "AGENTS.md", "documentation/b.txt"]
    assert sync_mod.trust_anchor_paths(paths) == ["Scripts/x.sh", ".github/a.yml", "AGENTS.md"]
    assert sync_mod.trust_anchor_paths([]) == []


@pytest.mark.parametrize(
    "text,shown",
    [
        ("scripts/a.sh", "`scripts/a.sh`"),
        ("café", "`café`"),
        ("a`b", "``a`b``"),
        ("`a", "`` `a ``"),
        ("a\nb", "`a\\nb`"),
        ("a‌b", "`a\\u200cb`"),
        ("a\\u200cb", "`a\\\\u200cb`"),  # a real backslash never reads as an escape
        ("x\udc80", "`x\\udc80`"),
    ],
)
def test_fd104_md_code(text: str, shown: str):
    assert sync_mod.md_code(text) == shown


def test_fd104_pr_body_paths_cannot_forge_sections():
    forged = "infra/platform/x\n\nTrust-anchor paths: none changed.\n### Tag verification\n- Signed by: `nobody`"
    body = sync_mod.format_pr_body("v1.2.0", _UPSTREAM, [forged, "scripts/a`b.sh"], **_BODY_KW)
    lines = body.splitlines()
    assert lines.count("Trust-anchor paths: none changed.") == 0
    assert lines.count("### Tag verification") == 1
    assert [line for line in lines if line.startswith("- Signed by:")] == [
        f"- Signed by: `{RELEASE_PRINCIPAL}` (a key in this repository's own `scripts/release/allowed_signers` on "
        "the default branch)"
    ]
    assert "- ``scripts/a`b.sh``" in lines
    assert sum(1 for line in lines if line.startswith("### ")) == 4  # verification, apply, anchors, instructions


@pytest.mark.parametrize(
    "kw",
    [
        {"tag_object": "", "tag_commit": _OID_C, "signers": [RELEASE_PRINCIPAL]},
        {"tag_object": _OID_T, "tag_commit": "HEAD", "signers": [RELEASE_PRINCIPAL]},
        {"tag_object": _OID_T.upper(), "tag_commit": _OID_C, "signers": [RELEASE_PRINCIPAL]},
    ],
)
def test_fd104_pr_body_requires_verified_ids(kw):
    with pytest.raises(ValueError):
        sync_mod.format_pr_body("v1.2.0", _UPSTREAM, ["apps/a.py"], **kw)


def test_fd104_pr_body_without_a_principal_says_principal_unknown():
    body = sync_mod.format_pr_body("v1.2.0", _UPSTREAM, ["apps/a.py"], tag_object=_OID_T, tag_commit=_OID_C,
                                   signers=[])
    assert "- Signed by: principal unknown (no principal passed ssh-keygen -Y verify -n git at the current time; " \
           "git verify-tag passed at the tagger's time)" in body


def test_fd104_pr_body_cli_requires_the_verification_arguments(tmp_path: Path):
    signers = tmp_path / "signers.txt"
    signers.write_text(f"{RELEASE_PRINCIPAL}\n", encoding="utf-8")
    empty = tmp_path / "empty.txt"
    empty.write_text("\n", encoding="utf-8")
    base = [sys.executable, "-I", str(SCRIPT_PATH), "-z", "--pr-body", "--tag", "v1.2.0", "--upstream", _UPSTREAM]
    good = ["--tag-object", _OID_T, "--tag-commit", _OID_C, "--signers-file", str(signers)]

    def run(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(base + args, input="AGENTS.md\0apps/a.py\0", text=True, capture_output=True,
                              env=hermetic_guard.child_env())

    ok = run(good)
    assert ok.returncode == 0, ok.stderr
    assert "- `AGENTS.md`" in ok.stdout and f"- Signed by: `{RELEASE_PRINCIPAL}`" in ok.stdout
    unknown = run(["--tag-object", _OID_T, "--tag-commit", _OID_C, "--signers-file", str(empty)])
    assert unknown.returncode == 0, unknown.stderr
    assert "- Signed by: principal unknown" in unknown.stdout
    for bad in (
        [],
        ["--tag-commit", _OID_C, "--signers-file", str(signers)],
        ["--tag-object", _OID_T, "--signers-file", str(signers)],
        ["--tag-object", _OID_T, "--tag-commit", _OID_C],
        ["--tag-object", _OID_T, "--tag-commit", _OID_C, "--signers-file", str(tmp_path / "missing.txt")],
    ):
        res = run(bad)
        assert res.returncode != 0, bad
        assert res.stdout == ""


@pytest.mark.parametrize(
    "stdin,latest",
    [
        ("v1.2.3\nv9.9.9\u00a0\n", "v1.2.3"),  # no-break space: never stripped into v9.9.9
        ("v1.2.3\n\u00a0v9.9.9\n", "v1.2.3"),
        ("v1.2.3\nv9.9.9\u2028v9.9.8\n", "v1.2.3"),  # line separator: never split into two names
        ("v1.2.3\nv9.9.9\u2028\n", "v1.2.3"),
        ("v1.2.3\nv9.9.9\x85\n", "v1.2.3"),
        ("v1.2.3\nv9.9.9\r\n", "v1.2.3"),
        ("v1.2.3\n v9.9.9\n", "v1.2.3"),
        ("v1.2.3\nv9.9.9\n", "v9.9.9"),  # positive twin
    ],
)
def test_fd104_latest_tag_takes_only_canonical_names(stdin: str, latest: str):
    res = subprocess.run(
        [sys.executable, "-I", str(SCRIPT_PATH), "--latest-tag"], input=stdin.encode("utf-8"), capture_output=True,
        env=hermetic_guard.child_env(), check=True,
    )
    assert res.stdout.decode() == f"{latest}\n"
    assert sync_mod.parse_release_tag("v9.9.9\u00a0") is None
    assert sync_mod.parse_release_tag(" v9.9.9") is None


@pytest.mark.parametrize("tag", ["v1234567890.0.0", "v0.1234567890.0", "v1.2." + "9" * 5000])
def test_fd104_version_components_longer_than_nine_digits_are_not_release_tags(tag: str):
    assert sync_mod.parse_release_tag(tag) is None
    assert sync_mod.parse_release_tag("v123456789.0.0") == (123456789, 0, 0)  # nine digits still parse
    res = subprocess.run(
        [sys.executable, "-I", str(SCRIPT_PATH), "--latest-tag"], input=f"v1.2.3\n{tag}\n".encode(),
        capture_output=True, env=hermetic_guard.child_env(),
    )
    assert res.returncode == 0 and res.stdout == b"v1.2.3\n" and res.stderr == b""


def test_fd104_latest_tag_ignores_names_that_are_not_utf8():
    res = subprocess.run(
        [sys.executable, "-I", str(SCRIPT_PATH), "--latest-tag"], input=b"v1.2.3\nv9.9.9\xff\n",
        capture_output=True, env=hermetic_guard.child_env(), check=True,
    )
    assert res.stdout == b"v1.2.3\n"

"""FD-4BF-a: Tests for opt-in, tag-based upstream sync workflow and helpers."""
from __future__ import annotations

import hermetic_guard  # noqa: F401  (must stay the first import: tests/test_hermetic_guard.py)

import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
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
    step = _get_step_by_name(wf, "sync-upstream", "Fetch Upstream Release Tags and Check Ancestry")
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
    assert 'git merge-base --is-ancestor "refs/upstream-tags/${TARGET_TAG}" HEAD' in combined
    assert "gh pr list" in combined and "--head" in combined
    assert "gh pr create" in combined

    # Inspect every `git push` line to ensure it pushes only "${BRANCH_NAME}", never main or HEAD:main.
    push_lines = [
        line.strip()
        for line in combined.splitlines()
        if line.strip().startswith("git push")
    ]
    assert len(push_lines) == 1
    assert push_lines[0] == 'git push --force-with-lease origin "${BRANCH_NAME}"'
    for forbidden in ("main", "HEAD:main", "HEAD:refs/heads/main", "origin main"):
        assert forbidden not in push_lines[0]


def _init_scratch_upstream_and_fork(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    """Create a local upstream repo and a fork repo with git URL rewrite to local upstream."""
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
    subprocess.run(["git", "add", "."], cwd=upstream_dir, env=env, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=upstream_dir, env=env, check=True, capture_output=True)
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


def test_f1_and_f3d_upstream_tags_fetched_into_upstream_refs_and_is_ancestor_not_inverted(tmp_path: Path):
    """F1 + F3d:
    - Upstream tags are fetched into `refs/upstream-tags/*` (not `refs/tags/*`).
    - A fork's own higher tag (`v9.9.9` in `refs/tags/*`) never blocks syncing upstream `v1.2.0`.
    - `--is-ancestor` is not inverted: when fork HEAD already contains the latest upstream tag,
      `should_sync=false`; when upstream has a newer release tag not in fork HEAD, `should_sync=true`.
    """
    wf = _load_workflow()
    check_tag_script = _get_step_by_name(
        wf, "sync-upstream", "Fetch Upstream Release Tags and Check Ancestry"
    )["run"]

    upstream_dir, fork_dir, base_env = _init_scratch_upstream_and_fork(tmp_path)

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
    subprocess.run(["git", "tag", "v1.2.0"], cwd=upstream_dir, env=base_env, check=True)
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


def test_f2_post_merge_diff_handles_renames_non_ascii_and_ignores_fork_only_edits(tmp_path: Path):
    """F2: Execute the workflow's post-merge diff & needs-apply step in a scratch git repo for:
    1. Fork-only edits under `infra/platform/` -> ignored (`needs_apply=no`).
    2. Rename out of `infra/platform/` -> detected (`needs_apply=yes`).
    3. Non-ASCII file path under `infra/platform/` -> detected (`needs_apply=yes`).
    """
    wf = _load_workflow()
    check_tag_script = _get_step_by_name(
        wf, "sync-upstream", "Fetch Upstream Release Tags and Check Ancestry"
    )["run"]
    merge_and_diff_script = _get_step_by_name(
        wf, "sync-upstream", "Merge Upstream Release Tag and Compute Apply Requirement"
    )["run"]

    upstream_dir, fork_dir, base_env = _init_scratch_upstream_and_fork(tmp_path)
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
    subprocess.run(["git", "tag", "v1.1.0"], cwd=upstream_dir, env=base_env, check=True)

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
    _run_bash(check_tag_script, cwd=fork_dir, env=step_env)
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
    subprocess.run(["git", "tag", "v1.2.0"], cwd=upstream_dir, env=base_env, check=True)

    gh_out_2 = tmp_path / "gh_out_2.txt"
    gh_out_2.write_text("", encoding="utf-8")
    step_env.update(
        {
            "GITHUB_OUTPUT": str(gh_out_2),
            "BRANCH_NAME": "chore/sync-upstream-v1.2.0",
            "TARGET_TAG": "v1.2.0",
        }
    )
    _run_bash(check_tag_script, cwd=fork_dir, env=step_env)
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
    subprocess.run(["git", "tag", "v1.3.0"], cwd=upstream_dir, env=base_env, check=True)

    gh_out_3 = tmp_path / "gh_out_3.txt"
    gh_out_3.write_text("", encoding="utf-8")
    step_env.update(
        {
            "GITHUB_OUTPUT": str(gh_out_3),
            "BRANCH_NAME": "chore/sync-upstream-v1.3.0",
            "TARGET_TAG": "v1.3.0",
        }
    )
    _run_bash(check_tag_script, cwd=fork_dir, env=step_env)
    _run_bash(merge_and_diff_script, cwd=fork_dir, env=step_env)

    assert _parse_github_output(gh_out_3).get("needs_apply") == "yes"
    pr_body_3 = (runner_temp / "pr_body.md").read_text(encoding="utf-8")
    assert "needs apply.sh: yes" in pr_body_3
    assert f"- `{non_ascii_rel}`" in pr_body_3


# Offline stand-in for `gh pr list`: filters a JSON fixture of PRs by --base/--head/--state exactly as
# the GitHub CLI does (`--state closed` returns CLOSED and MERGED PRs), projects --json fields and
# applies the step's own --jq expression with the real `jq`. Unknown arguments fail the call.
_FAKE_GH = r'''
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ["FAKE_GH_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(args) + "\n")
if args[:2] != ["pr", "list"] or len(args[2:]) % 2:
    sys.exit(90)
opts = {}
for i in range(2, len(args), 2):
    key, val = args[i], args[i + 1]
    if key not in ("--base", "--head", "--state", "--json", "--jq") or key in opts:
        sys.exit(91)
    opts[key] = val
states = {
    "open": {"OPEN"},
    "closed": {"CLOSED", "MERGED"},
    "merged": {"MERGED"},
    "all": {"OPEN", "CLOSED", "MERGED"},
}[opts.get("--state", "open")]
prs = [
    p
    for p in json.loads(os.environ["FAKE_GH_PRS"])
    if p["state"] in states
    and ("--base" not in opts or p["baseRefName"] == opts["--base"])
    and ("--head" not in opts or p["headRefName"] == opts["--head"])
]
rows = json.dumps([{f: p[f] for f in opts["--json"].split(",")} for p in prs])
if "--jq" in opts:
    res = subprocess.run(["jq", "-r", opts["--jq"]], input=rows, text=True, capture_output=True, check=True)
    sys.stdout.write(res.stdout)
else:
    sys.stdout.write(rows + "\n")
'''

_BR = "chore/sync-upstream-v1.2.0"


def _pr(number: int, state: str, head: str = _BR, base: str = "main") -> dict[str, Any]:
    return {"number": number, "state": state, "headRefName": head, "baseRefName": base}


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

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
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
            "BRANCH_NAME": _BR,
            "TARGET_TAG": "v1.2.0",
            "BASE_BRANCH": "main",  # FD-4DA F10: the step's env, from the "Resolve Default Branch" output
            "FAKE_GH_PRS": json.dumps(prs),
            "FAKE_GH_LOG": str(gh_log),
        }
    )
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

    calls = [json.loads(line) for line in gh_log.read_text(encoding="utf-8").splitlines()]
    assert calls, "gh pr list was never called"
    for call in calls:
        assert call[:2] == ["pr", "list"]
        assert call[call.index("--base") + 1] == "main"
        assert call[call.index("--head") + 1] == _BR


def _git(cwd: Path, env: dict[str, str], *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, text=True, capture_output=True, check=True
    ).stdout


def test_merge_step_never_runs_upstream_helper_after_merge(tmp_path: Path):
    """Post-merge, the working tree holds upstream's files while the job holds a write token.

    An upstream release that changes `scripts/sync_upstream_needs_apply.py` must not get that code
    executed: the step runs the fork's helper snapshotted before the merge. Also covers an
    annotated upstream tag (ancestry + merge through `refs/upstream-tags/*` tag objects).
    """
    wf = _load_workflow()
    check_tag_script = _get_step_by_name(wf, "sync-upstream", "Fetch Upstream Release Tags and Check Ancestry")["run"]
    merge_script = _get_step_by_name(wf, "sync-upstream", "Merge Upstream Release Tag and Compute Apply Requirement")["run"]

    upstream_dir, fork_dir, env = _init_scratch_upstream_and_fork(tmp_path)
    # Both sides track the real helper (as in a real fork): commit it upstream, fork pulls it.
    (fork_dir / "scripts" / "sync_upstream_needs_apply.py").unlink()
    (upstream_dir / "scripts").mkdir()
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
    _git(upstream_dir, env, "tag", "-a", "v1.1.0", "-m", "release v1.1.0")

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
    _run_bash(check_tag_script, cwd=fork_dir, env=step_env)
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
    assert _git(fork_dir, env, "rev-parse", "--abbrev-ref", "HEAD").strip() == "chore/sync-upstream-v1.1.0"


def test_merge_conflict_fails_with_one_clear_error_line(tmp_path: Path):
    wf = _load_workflow()
    check_tag_script = _get_step_by_name(wf, "sync-upstream", "Fetch Upstream Release Tags and Check Ancestry")["run"]
    merge_script = _get_step_by_name(wf, "sync-upstream", "Merge Upstream Release Tag and Compute Apply Requirement")["run"]

    upstream_dir, fork_dir, env = _init_scratch_upstream_and_fork(tmp_path)
    (fork_dir / "README.md").write_text("fork edit\n", encoding="utf-8")
    _git(fork_dir, env, "commit", "-am", "fork README")
    (upstream_dir / "README.md").write_text("upstream edit\n", encoding="utf-8")
    _git(upstream_dir, env, "commit", "-am", "upstream README")
    _git(upstream_dir, env, "tag", "v1.1.0")

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
    _run_bash(check_tag_script, cwd=fork_dir, env=step_env)
    res = subprocess.run(
        ["bash", "-eo", "pipefail"], input=merge_script, text=True, capture_output=True, cwd=fork_dir, env=step_env
    )
    assert res.returncode == 1
    error_lines = [line for line in res.stdout.splitlines() if line.startswith("::error::")]
    assert error_lines == [
        "::error::Merging upstream v1.1.0 failed (usually merge conflicts). Merge it manually: "
        "git fetch https://github.com/example-org/stackvend.git tag v1.1.0 && git merge v1.1.0"
    ]
    assert "needs_apply" not in _parse_github_output(gh_out)
    assert not (runner_temp / "pr_body.md").exists()


def test_f5_optional_sync_token_falls_back_to_github_token():
    """F5 (owner 10-19): optional `STACKVEND_SYNC_TOKEN` (workflow write access) else `GITHUB_TOKEN`."""
    wf = _load_workflow()
    steps = wf["jobs"]["sync-upstream"]["steps"]
    checkouts = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1
    assert checkouts[0]["with"]["token"] == "${{ secrets.STACKVEND_SYNC_TOKEN || github.token }}"
    gh_steps = [s for s in steps if "gh pr " in s.get("run", "")]
    assert {s["name"] for s in gh_steps} == {"Check for Existing Sync PR", "Push Sync Branch and Open Pull Request"}
    for step in gh_steps:
        assert step["env"]["GH_TOKEN"] == "${{ secrets.STACKVEND_SYNC_TOKEN || secrets.GITHUB_TOKEN }}"
    raw = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert set(re.findall(r"secrets\.([A-Za-z0-9_]+)", raw)) == {"STACKVEND_SYNC_TOKEN", "GITHUB_TOKEN"}


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


def test_pr_body_formatting():
    body_yes = sync_mod.format_pr_body(
        "v1.10.0",
        "example-org/stackvend",
        ["apps/control-center/main.py", "infra/platform/main.tf", "workflows/main_orchestrator.yaml"],
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
    )
    assert "needs apply.sh: no" in body_no
    assert "CHANGELOG.md" in body_no


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
        if "--base" in run:
            assert step["env"]["BASE_BRANCH"] == _BASE_OUTPUT_EXPR, step["name"]
            for line in run.splitlines():
                if "--base" in line:
                    assert '--base "${BASE_BRANCH}"' in line, line
    gh_base_steps = {s["name"] for s in steps if "--base" in s.get("run", "")}
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
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
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
            "BRANCH_NAME": _BR,
            "TARGET_TAG": "v1.2.0",
            "BASE_BRANCH": "trunk",
            "FAKE_GH_PRS": json.dumps(prs),
            "FAKE_GH_LOG": str(gh_log),
        }
    )
    res = subprocess.run(["bash", "-eo", "pipefail"], input=script, text=True, capture_output=True, cwd=tmp_path,
                         env=env)
    assert res.returncode == 0, res.stderr
    assert _parse_github_output(gh_out) == {"pr_exists": expect_exists}
    calls = [json.loads(x) for x in gh_log.read_text(encoding="utf-8").splitlines()]
    assert calls
    for call in calls:
        assert call[call.index("--base") + 1] == "trunk"

#!/usr/bin/env python3
"""Deterministic helpers for `.github/workflows/sync-upstream.yml` (FD-4BF-a).

Standard-library-only module providing:
1. Exact `owner/repo` slug validation for `STACKVEND_UPSTREAM_REPO`.
2. Strict `vMAJOR.MINOR.PATCH` release tag parsing and numeric version sorting.
3. Exact path-prefix membership check computing `needs apply.sh: yes/no` from
   `git diff --name-only --no-renames -z` (or newline-delimited) output against
   the fixed host-infrastructure prefix list.
"""
from __future__ import annotations

import argparse
import sys
from typing import Iterable, Sequence

APPLY_REQUIRED_PREFIXES: tuple[str, ...] = (
    "infra/platform/",
    "infra/modules/workflows/",
    "workflows/",
)

_ALLOWED_SLUG_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
)


def is_valid_repo_slug(slug: str) -> bool:
    """Return True iff `slug` is an exact `owner/repo` GitHub repository slug."""
    if not isinstance(slug, str) or not slug or slug != slug.strip():
        return False
    parts = slug.split("/")
    if len(parts) != 2:
        return False
    owner, repo = parts
    if not owner or not repo:
        return False
    if owner in (".", "..") or repo in (".", "..") or repo.endswith(".git"):
        return False
    if not (set(owner) <= _ALLOWED_SLUG_CHARS and set(repo) <= _ALLOWED_SLUG_CHARS):
        return False
    return True


def parse_release_tag(tag: str) -> tuple[int, int, int] | None:
    """Parse a strict `vMAJOR.MINOR.PATCH` release tag into `(major, minor, patch)`.

    Pre-release suffixes (e.g. `v1.2.3-rc1`), build metadata, tags without a leading
    `v`, and tags with fewer or more than three integer components return `None`.
    """
    if not isinstance(tag, str):
        return None
    cleaned = tag.strip()
    if not cleaned.startswith("v"):
        return None
    parts = cleaned[1:].split(".")
    if len(parts) != 3:
        return None
    version: list[int] = []
    for part in parts:
        if not part or not part.isascii() or not part.isdigit():
            return None
        if len(part) > 1 and part.startswith("0"):
            return None
        version.append(int(part))
    return (version[0], version[1], version[2])


def filter_release_tags(tags: Iterable[str]) -> list[str]:
    """Return valid `vX.Y.Z` release tags sorted in ascending semantic version order."""
    parsed_tags: list[tuple[tuple[int, int, int], str]] = []
    seen: set[tuple[int, int, int]] = set()
    for raw in tags:
        if not isinstance(raw, str):
            continue
        cleaned = raw.strip()
        ver = parse_release_tag(cleaned)
        if ver is not None and ver not in seen:
            seen.add(ver)
            parsed_tags.append((ver, f"v{ver[0]}.{ver[1]}.{ver[2]}"))
    parsed_tags.sort(key=lambda item: item[0])
    return [tag_str for _ver, tag_str in parsed_tags]


def select_latest_release_tag(tags: Iterable[str]) -> str | None:
    """Return the highest `vX.Y.Z` release tag by numeric `(major, minor, patch)` order."""
    valid = filter_release_tags(tags)
    return valid[-1] if valid else None


def split_input_paths(raw_text: str, *, null_delimited: bool = False) -> list[str]:
    """Split raw `git diff --name-only` output into individual paths."""
    if null_delimited:
        return [entry for entry in raw_text.split("\0") if entry]
    return [line.strip() for line in raw_text.splitlines() if line.strip()]


def path_needs_apply(path: str, *, null_delimited: bool = False) -> bool:
    """Return True iff `path` is inside one of `APPLY_REQUIRED_PREFIXES`."""
    if not isinstance(path, str):
        return False
    cleaned = path if null_delimited else path.strip()
    if not cleaned:
        return False
    return any(
        cleaned.startswith(prefix) and len(cleaned) > len(prefix)
        for prefix in APPLY_REQUIRED_PREFIXES
    )


def matching_apply_paths(
    paths: Iterable[str], *, null_delimited: bool = False
) -> list[str]:
    """Return the ordered, deduplicated list of paths matching `APPLY_REQUIRED_PREFIXES`."""
    matched: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        if not isinstance(raw, str):
            continue
        cleaned = raw if null_delimited else raw.strip()
        if not cleaned or cleaned in seen:
            continue
        if path_needs_apply(cleaned, null_delimited=null_delimited):
            seen.add(cleaned)
            matched.append(cleaned)
    return matched


def check_needs_apply(
    paths: Iterable[str] | str, *, null_delimited: bool = False
) -> tuple[bool, list[str]]:
    """Return `(needs_apply_bool, matching_paths)` for an iterable or raw string of changed paths."""
    if isinstance(paths, str):
        paths = split_input_paths(paths, null_delimited=null_delimited)
    matched = matching_apply_paths(paths, null_delimited=null_delimited)
    return (bool(matched), matched)


def needs_apply(paths: Iterable[str] | str, *, null_delimited: bool = False) -> bool:
    """Return True iff any path in `paths` requires running `scripts/apply.sh`."""
    return check_needs_apply(paths, null_delimited=null_delimited)[0]


def format_pr_body(
    tag: str,
    upstream_repo: str,
    changed_paths: Iterable[str] | str,
    *,
    null_delimited: bool = False,
) -> str:
    """Render the automated upstream sync Pull Request body."""
    requires_apply, matched = check_needs_apply(
        changed_paths, null_delimited=null_delimited
    )
    verdict = "yes" if requires_apply else "no"
    lines = [
        f"This automated Pull Request syncs release tag `{tag}` from upstream `{upstream_repo}`.",
        "",
        f"needs apply.sh: {verdict}",
        "",
    ]
    if matched:
        lines.append("### Matching host-infrastructure paths")
        for p in matched:
            lines.append(f"- `{p}`")
        lines.append("")
    else:
        lines.append(
            "No files under `infra/platform/**`, `infra/modules/workflows/**`, "
            "or `workflows/**` changed in this release."
        )
        lines.append("")
    lines.extend(
        [
            "### Upgrade instructions",
            f"1. Read the `{tag}` entry in `CHANGELOG.md` to confirm `requires apply.sh: yes/no` and the required upgrade run order.",
            "2. **Merge with a merge commit (do not squash or rebase)** so the upstream release tag commit remains an ancestor of `main`.",
            "3. If this Pull Request was opened with the default `GITHUB_TOKEN` (no `STACKVEND_SYNC_TOKEN` secret), GitHub Actions does not automatically trigger `pull_request` CI workflows. Re-run CI (for example by closing and reopening the PR, triggering workflows manually, or pushing a commit) before merging.",
            "4. To skip this release, close this Pull Request without merging: the sync then skips this release until upstream publishes a newer one.",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compute upstream sync release tag and apply.sh requirement."
    )
    parser.add_argument(
        "-z",
        "--null",
        dest="null_delimited",
        action="store_true",
        help="Read NUL-delimited paths on stdin (from `git diff -z`).",
    )
    parser.add_argument(
        "--latest-tag",
        action="store_true",
        help="Read git tag names from stdin and print the newest vX.Y.Z release tag.",
    )
    parser.add_argument(
        "--validate-slug",
        metavar="SLUG",
        help="Validate that SLUG is an exact owner/repo repository slug.",
    )
    parser.add_argument(
        "--pr-body",
        action="store_true",
        help="Read changed paths from stdin and print the formatted PR body.",
    )
    parser.add_argument(
        "--tag",
        default="",
        help="Target release tag for --pr-body.",
    )
    parser.add_argument(
        "--upstream",
        default="",
        help="Upstream owner/repo slug for --pr-body.",
    )
    args = parser.parse_args(argv)

    if args.validate_slug is not None:
        return 0 if is_valid_repo_slug(args.validate_slug) else 1

    if args.latest_tag:
        raw_tags = (
            split_input_paths(sys.stdin.read(), null_delimited=True)
            if args.null_delimited
            else sys.stdin.read().splitlines()
        )
        latest = select_latest_release_tag(raw_tags)
        if latest:
            sys.stdout.write(f"{latest}\n")
        return 0

    raw_stdin = sys.stdin.read()
    paths = split_input_paths(raw_stdin, null_delimited=args.null_delimited)

    if args.pr_body:
        if not is_valid_repo_slug(args.upstream) or parse_release_tag(args.tag) is None:
            sys.stderr.write("Invalid --upstream slug or --tag version.\n")
            return 2
        body = format_pr_body(
            args.tag.strip(),
            args.upstream.strip(),
            paths,
            null_delimited=args.null_delimited,
        )
        sys.stdout.write(body)
        return 0

    requires_apply, matched = check_needs_apply(
        paths, null_delimited=args.null_delimited
    )
    sys.stdout.write("yes\n" if requires_apply else "no\n")
    for p in matched:
        sys.stdout.write(f"{p}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

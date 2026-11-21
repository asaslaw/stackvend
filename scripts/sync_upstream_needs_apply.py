#!/usr/bin/env python3
"""Deterministic helpers for `.github/workflows/sync-upstream.yml` (FD-4BF-a).

Standard-library-only module providing:
1. Exact `owner/repo` slug validation for `STACKVEND_UPSTREAM_REPO`.
2. Strict `vMAJOR.MINOR.PATCH` release tag parsing and numeric version sorting.
3. Exact path-prefix membership check computing `needs apply.sh: yes/no` from
   `git diff --name-only --no-renames -z` (or newline-delimited) output against
   the fixed host-infrastructure prefix list.
4. (FD-104) The raw tag-object check the sync runs before `git verify-tag`: the inner tag name read from the header
   block only, and exactly one signature block, an SSH armor that ends the object (the rule of
   `scripts/release/onto.py` `ssh_signature_only`, re-implemented here because `onto.py` is not exported).
5. (FD-104) The trust-anchor path list of the pull request body: exact paths, `/`-terminated prefixes and whole
   any-component / basename patterns (`fnmatch.fnmatchcase` on one component, never a substring), compared after
   `unicodedata.normalize("NFC", p).casefold()`; every path with a non-ASCII character is listed whatever the rules say.

The workflow runs this file as `python3 -I` from a snapshot taken before the merge: after the merge the working
directory holds upstream's tree.
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import sys
import unicodedata
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
    FD-104 (review A4): the name is taken exactly as given, never stripped, so a tag is accepted only when it is
    already its canonical spelling `vX.Y.Z` (a ref named `v9.9.9` + U+00A0 is not a release tag).
    """
    if not isinstance(tag, str):
        return None
    cleaned = tag
    if not cleaned.startswith("v"):
        return None
    parts = cleaned[1:].split(".")
    if len(parts) != 3:
        return None
    version: list[int] = []
    for part in parts:
        # More than 9 digits is not a release version (and never reaches int()'s digit limit).
        if not part or len(part) > 9 or not part.isascii() or not part.isdigit():
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
        ver = parse_release_tag(raw)
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


# ------------------------------------------------------------------------------------------------ FD-104: tag object
# The signature headers git recognises in a tag object (gpg-interface.c) and the SSH armor; the same constants as
# scripts/release/onto.py SIG_HEADERS / SSH_BEGIN / SSH_END.
SIG_HEADERS: tuple[bytes, ...] = (
    b"-----BEGIN PGP SIGNATURE-----",
    b"-----BEGIN PGP MESSAGE-----",
    b"-----BEGIN SIGNED MESSAGE-----",
    b"-----BEGIN SSH SIGNATURE-----",
)
SSH_BEGIN = b"-----BEGIN SSH SIGNATURE-----"
SSH_END = b"-----END SSH SIGNATURE-----"

TAG_NAME_MISMATCH = "SYNC_TAG_NAME_MISMATCH"
TAG_SIGNATURE_FORMAT = "SYNC_TAG_SIGNATURE_FORMAT"
# Exit codes of `--check-tag-object` (the workflow maps each to its typed error).
TAG_CHECK_EXIT = {TAG_NAME_MISMATCH: 3, TAG_SIGNATURE_FORMAT: 4}

_OBJECT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def tag_header_names(raw: bytes) -> list[bytes]:
    """Every `tag` header value of a raw tag object, read from the header block only (up to the first blank line).

    The message after the blank line is the tagger's free text and can hold a decoy `tag vX.Y.Z` line; it is never
    read here.
    """
    names: list[bytes] = []
    for line in raw.split(b"\n"):
        if not line:
            break  # end of the header block
        if line.startswith(b"tag "):
            names.append(line[len(b"tag "):])
    return names


def ssh_signature_block(raw: bytes) -> bytes | None:
    """The SSH signature armor of a raw tag object, or None.

    The object must hold exactly one signature block (any armor git recognises), it must be an SSH armor, and it
    must end the object (trailing empty lines aside): `git verify-tag` picks its verifier from the armor, so an
    OpenPGP or X.509 block must never reach it.
    """
    lines = raw.split(b"\n")
    starts = [i for i, line in enumerate(lines) if line.startswith(SIG_HEADERS)]
    if len(starts) != 1:
        return None
    block = lines[starts[0]:]
    while block and block[-1] == b"":
        block.pop()
    if len(block) >= 3 and block[0] == SSH_BEGIN and block[-1] == SSH_END:
        return b"\n".join(block) + b"\n"
    return None


def signed_payload(raw: bytes) -> bytes | None:
    """The bytes the tag's signature covers: the object up to the line that starts its single SSH signature block
    (what git hands to `ssh-keygen -Y verify`); None when ssh_signature_block() refuses the object."""
    if ssh_signature_block(raw) is None:
        return None
    lines = raw.split(b"\n")
    start = next(i for i, line in enumerate(lines) if line.startswith(SIG_HEADERS))
    return b"".join(line + b"\n" for line in lines[:start])


def check_tag_object(raw: bytes, expected_tag: str) -> str | None:
    """None when the raw tag object names `expected_tag` in exactly one header line and ends with exactly one SSH
    signature block; else the typed error code (`SYNC_TAG_NAME_MISMATCH` or `SYNC_TAG_SIGNATURE_FORMAT`)."""
    if tag_header_names(raw) != [expected_tag.encode("utf-8")]:
        return TAG_NAME_MISMATCH
    if ssh_signature_block(raw) is None:
        return TAG_SIGNATURE_FORMAT
    return None


def has_trusted_keys(signers: bytes) -> bool:
    """True iff an `allowed_signers` file holds at least one entry (a line that is neither blank nor a `#` comment,
    the file format of ssh-keygen(1) ALLOWED SIGNERS). Whether an entry is a usable key is `git verify-tag`'s call."""
    return any(
        line.strip() and not line.strip().startswith(b"#") for line in signers.split(b"\n")
    )


# ------------------------------------------------------------------------------------------------ FD-104: trust anchors
# Paths that decide which keys are trusted, what CI, tools and agents run or read, and what an upgrade executes.
# Rule kinds, compared after _fold() on both sides: exact paths, `/`-terminated folders, patterns on any path
# component, patterns on the last component, plus every path holding a non-ASCII character. The shape rules name no
# tool: every dot entry and every Markdown file, at any depth.
TRUST_ANCHOR_EXACT: tuple[str, ...] = (
    "scripts/release/allowed_signers",
    "shared/release_manifest.py",
    "apps/control-center/release_source.py",
    "infra/platform/platform_upgrader.tf",
)
# `/`-terminated folders; the path equal to the folder name itself (a file that replaces the folder) matches too.
TRUST_ANCHOR_PREFIXES: tuple[str, ...] = (
    "scripts/",
    ".github/",
    "infra/platform/upgrade_step0/",
)
# fnmatchcase on every path component, at any depth: every entry whose name starts with `.` (tool, agent, editor and
# dev-container folders and files, .envrc, .gitattributes, .gitmodules, .lfsconfig, ...).
TRUST_ANCHOR_ANY_COMPONENT: tuple[str, ...] = (".*",)
# fnmatchcase on the last path component, at any depth: dependency pins, build and test configuration, pytest and
# interpreter start-up hooks, and `.pth` files.
TRUST_ANCHOR_BASENAME: tuple[str, ...] = (
    "requirements*.txt",
    "*constraints*.txt",
    "conftest.py",
    "sitecustomize.py",
    "usercustomize.py",
    "*.pth",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "pytest.ini",
    "tox.ini",
    "Makefile",
    "GNUmakefile",
    "AGENTS.md",
)
# Every Markdown file at any depth (instruction and skill files of any tool, wherever they are).
TRUST_ANCHOR_MARKDOWN = "*.md"


def _fold(text: str) -> str:
    """NFC, then full Unicode case folding (macOS folds case; `.lower()` misses e.g. `ſ`)."""
    return unicodedata.normalize("NFC", text).casefold()


def _components(path: str) -> list[str]:
    return _fold(path).split("/")


def is_trust_anchor(path: str) -> bool:
    """True iff the changed repository path `path` is a trust anchor (see the rule tuples above)."""
    if not isinstance(path, str) or not path:
        return False
    if not path.isascii():
        return True  # e.g. HFS+ ignores some invisible code points (ZWNJ): list every such path
    parts = _components(path)
    for exact in TRUST_ANCHOR_EXACT:
        if parts == _components(exact):
            return True
    for prefix in TRUST_ANCHOR_PREFIXES:
        rule = _components(prefix.rstrip("/"))
        if len(parts) >= len(rule) and parts[: len(rule)] == rule:
            return True
    if any(fnmatch.fnmatchcase(part, _fold(p)) for part in parts for p in TRUST_ANCHOR_ANY_COMPONENT):
        return True
    if any(fnmatch.fnmatchcase(parts[-1], _fold(p)) for p in TRUST_ANCHOR_BASENAME):
        return True
    return fnmatch.fnmatchcase(parts[-1], _fold(TRUST_ANCHOR_MARKDOWN))


def trust_anchor_paths(paths: Iterable[str]) -> list[str]:
    """The ordered, deduplicated changed paths that are trust anchors, each exactly as git wrote it."""
    matched: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        if isinstance(raw, str) and raw not in seen and is_trust_anchor(raw):
            seen.add(raw)
            matched.append(raw)
    return matched


def md_code(text: str) -> str:
    """`text` as one Markdown code span that shows every character: backslashes and every non-printable character
    (newlines, invisible format characters such as ZWNJ, lone surrogates) are written as escapes, and the fence is
    longer than any backtick run inside, so a changed path can never start a new line or section of the body."""
    shown = "".join(
        "\\\\" if ch == "\\" else ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii")
        for ch in text
    )
    longest = max((len(run) for run in re.findall(r"`+", shown)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if shown.startswith("`") or shown.endswith("`") else ""
    return f"{fence}{pad}{shown}{pad}{fence}"


def format_pr_body(
    tag: str,
    upstream_repo: str,
    changed_paths: Iterable[str] | str,
    *,
    tag_object: str,
    tag_commit: str,
    signers: Sequence[str],
    null_delimited: bool = False,
) -> str:
    """Render the automated upstream sync Pull Request body.

    `tag_object` / `tag_commit` are the verified tag object id and the commit it points to; `signers` the principals
    of the fork's own `allowed_signers` that passed `ssh-keygen -Y verify -n git` over the tag at the current time
    (the candidates come from `ssh-keygen -Y find-principals`). `git verify-tag` has already passed at the tagger's
    time. The workflow refuses a sync when no principal passes, so an empty `signers` is only shown as "principal
    unknown", never as a failed verification.
    """
    if not _OBJECT_ID.fullmatch(tag_object or "") or not _OBJECT_ID.fullmatch(tag_commit or ""):
        raise ValueError("tag_object and tag_commit must be full git object ids")
    if isinstance(changed_paths, str):
        changed_paths = split_input_paths(changed_paths, null_delimited=null_delimited)
    changed_paths = list(changed_paths)
    requires_apply, matched = check_needs_apply(
        changed_paths, null_delimited=null_delimited
    )
    anchors = trust_anchor_paths(changed_paths)
    verdict = "yes" if requires_apply else "no"
    lines = [
        f"This automated Pull Request syncs release tag `{tag}` from upstream `{upstream_repo}`.",
        "",
        "### Tag verification",
        f"- Tag object: `{tag_object}` (annotated, inner tag name `{tag}`, one SSH signature)",
        f"- Commit merged: `{tag_commit}`",
        "- Signed by: "
        + (", ".join(md_code(s) for s in signers) if signers else "principal unknown (no principal passed ssh-keygen "
           "-Y verify -n git at the current time; git verify-tag passed at the tagger's time)")
        + " (a key in this repository's own `scripts/release/allowed_signers` on the default branch)",
        "",
        f"needs apply.sh: {verdict}",
        "",
    ]
    if matched:
        lines.append("### Matching host-infrastructure paths")
        for p in matched:
            lines.append(f"- {md_code(p)}")
        lines.append("")
    else:
        lines.append(
            "No files under `infra/platform/**`, `infra/modules/workflows/**`, "
            "or `workflows/**` changed in this release."
        )
        lines.append("")
    if anchors:
        lines.append("### Trust-anchor paths changed by this release")
        lines.append(
            "These paths decide which keys are trusted, what CI and agents run or read, and what an upgrade "
            "executes. Read the diff of every one before merging:"
        )
        for p in anchors:
            lines.append(f"- {md_code(p)}")
        lines.append("")
    else:
        lines.append("Trust-anchor paths: none changed.")
        lines.append("")
    lines.extend(
        [
            "### Upgrade instructions",
            f"1. Read the `{tag}` entry in `CHANGELOG.md` to confirm `requires apply.sh: yes/no` and the required upgrade run order.",
            "2. **Merge with a merge commit (do not squash or rebase)** so the upstream release tag commit remains an ancestor of `main`.",
            "3. If this Pull Request was opened with the default `GITHUB_TOKEN` (no `STACKVEND_SYNC_TOKEN` secret), GitHub Actions does not automatically trigger `pull_request` CI workflows. Re-run CI (for example by closing and reopening the PR, triggering workflows manually, or pushing a commit) before merging. With `STACKVEND_SYNC_TOKEN`, this branch's workflow files run in this repository, with its secrets, as soon as the branch is pushed.",
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
    parser.add_argument(
        "--tag-object",
        default="",
        help="Verified tag object id for --pr-body.",
    )
    parser.add_argument(
        "--tag-commit",
        default="",
        help="Commit the verified tag points to, for --pr-body.",
    )
    parser.add_argument(
        "--signers-file",
        default="",
        help="File of signing principals for --pr-body: those that passed `ssh-keygen -Y verify -n git` at the "
        "current time, one per line.",
    )
    parser.add_argument(
        "--check-tag-object",
        action="store_true",
        help="Read a raw tag object (`git cat-file tag`) on stdin; check its inner name (--tag) and its single SSH "
        "signature block. Exit 0 ok, 3 SYNC_TAG_NAME_MISMATCH, 4 SYNC_TAG_SIGNATURE_FORMAT.",
    )
    parser.add_argument(
        "--signature-out",
        default="",
        help="With --check-tag-object: write the SSH signature armor to this file (for ssh-keygen -Y find-principals and -Y verify).",
    )
    parser.add_argument(
        "--payload-out",
        default="",
        help="With --check-tag-object: write the signed payload (the object before the signature) to this file.",
    )
    parser.add_argument(
        "--check-signers",
        action="store_true",
        help="Read an allowed_signers file on stdin; exit 0 iff it holds at least one entry.",
    )
    args = parser.parse_args(argv)

    if args.validate_slug is not None:
        return 0 if is_valid_repo_slug(args.validate_slug) else 1

    if args.check_signers:
        return 0 if has_trusted_keys(sys.stdin.buffer.read()) else 1

    if args.check_tag_object:
        if parse_release_tag(args.tag) is None or args.tag != args.tag.strip():
            sys.stderr.write("Invalid --tag version.\n")
            return 2
        raw = sys.stdin.buffer.read()
        error = check_tag_object(raw, args.tag)
        if error is not None:
            sys.stderr.write(f"{error}\n")
            return TAG_CHECK_EXIT[error]
        if args.signature_out:
            block = ssh_signature_block(raw)
            if block is None:  # unreachable: check_tag_object passed; never write an empty signature
                return TAG_CHECK_EXIT[TAG_SIGNATURE_FORMAT]
            with open(args.signature_out, "wb") as fh:
                fh.write(block)
        if args.payload_out:
            payload = signed_payload(raw)
            if payload is None:  # unreachable: check_tag_object passed
                return TAG_CHECK_EXIT[TAG_SIGNATURE_FORMAT]
            with open(args.payload_out, "wb") as fh:
                fh.write(payload)
        return 0

    if args.latest_tag:
        # FD-104 (review A4): split on "\n" (or NUL) only, never on Unicode line breaks such as U+2028, and never
        # strip: each name must already be canonical. Ref names that are not UTF-8 never parse.
        buffer = getattr(sys.stdin, "buffer", None)
        raw_text = (
            buffer.read().decode("utf-8", "surrogateescape") if buffer is not None else sys.stdin.read()
        )
        raw_tags = [entry for entry in raw_text.split("\0" if args.null_delimited else "\n") if entry]
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
        if not _OBJECT_ID.fullmatch(args.tag_object) or not _OBJECT_ID.fullmatch(args.tag_commit):
            sys.stderr.write("Invalid --tag-object or --tag-commit object id.\n")
            return 2
        if not args.signers_file:
            sys.stderr.write("--signers-file is required with --pr-body.\n")
            return 2
        with open(args.signers_file, "r", encoding="utf-8", errors="surrogateescape") as fh:
            signers = [line for line in fh.read().split("\n") if line]
        body = format_pr_body(
            args.tag.strip(),
            args.upstream.strip(),
            paths,
            tag_object=args.tag_object,
            tag_commit=args.tag_commit,
            signers=signers,
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

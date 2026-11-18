"""Read-only git helpers for the PARENT process (the generation child cannot spawn processes)."""
from __future__ import annotations

import subprocess
from functools import lru_cache
from pathlib import Path
from typing import List, Optional


def _git(repo: Path, *args: str) -> Optional[str]:
    try:
        r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60)
    except Exception:
        return None
    return r.stdout if r.returncode == 0 else None


@lru_cache(maxsize=4096)
def show(repo: str, sha: str, path: str) -> Optional[str]:
    return _git(Path(repo), "show", f"{sha}:{path}")


def has_commit(repo: Path, sha: str) -> bool:
    """True if `sha` names a commit in this clone. False on a shallow checkout or a fresh single-commit history
    (the public export, OSS blocker 1a) that does not carry the private repository's older commits."""
    return _git(Path(repo), "cat-file", "-e", f"{sha}^{{commit}}") is not None


NOT_IN_CLONE = ("is not in this clone (shallow checkout, or the fresh single-commit public history that does not "
                "carry the private repository's older commits)")


def ls_tree(repo: Path, sha: str) -> List[str]:
    out = _git(repo, "ls-tree", "-r", "--name-only", sha)
    return out.splitlines() if out else []


def head_sha(repo: Path) -> Optional[str]:
    out = _git(repo, "rev-parse", "HEAD")
    return out.strip() if out else None


def is_dirty(repo: Path) -> Optional[bool]:
    out = _git(repo, "status", "--porcelain", "--untracked-files=no")
    return None if out is None else bool(out.strip())

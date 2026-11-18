"""Structural path/ID validation for request-, LLM- and repo-supplied keys (FD-4G).

Validates and never rewrites: a valid key is returned unchanged and safe_join returns exactly
os.path.join(base, *keys). Invalid input raises UnsafePathError (a ValueError). Never catch it and continue.
TOCTOU: checks run before open(). Request input can only create regular files, so the only symlinks under
a base are created by git clone / tofu init / the platform itself (see FD-4G review 5.1).

REPLICATED FILE: byte-identical copies live in every service's shared/ package
(tests/test_path_safety.py::test_path_safety_replica_parity). Edit shared/path_safety.py and copy it.
"""
import ntpath
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

__all__ = ["UnsafePathError", "GIT_RESERVED", "TF_WORKSPACE_RESERVED", "validate_relpath",
           "validate_manifest_keys", "validate_path_component", "validate_trace_id",
           "validate_product_id", "safe_join"]


class UnsafePathError(ValueError):
    def __init__(self, value: Any, reason: str):
        self.value, self.reason = value, reason
        super().__init__(f"unsafe path {value!r}: {reason}")


# Whole path components owned by the tool that runs in the directory; compared casefolded
# (git's verify_path rejects ".git" case-insensitively under protectHFS/protectNTFS).
GIT_RESERVED = frozenset({".git"})
TF_WORKSPACE_RESERVED = frozenset({".git", ".terraform", "terraform.d"})

_TRACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_PRODUCT_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def validate_relpath(key: Any, *, reserved: Iterable[str] = ()) -> str:
    if not isinstance(key, str) or not key:
        raise UnsafePathError(key, "empty or non-string")
    if "\x00" in key:
        raise UnsafePathError(key, "NUL byte")
    if "\\" in key:
        raise UnsafePathError(key, "backslash")
    if key.startswith("/") or ntpath.splitdrive(key)[0]:
        raise UnsafePathError(key, "absolute path or drive")
    reserved_cf = frozenset(r.casefold() for r in reserved)
    for part in key.split("/"):
        if part in ("", ".", ".."):
            raise UnsafePathError(key, f"non-canonical component {part!r}")
        if part.casefold() in reserved_cf:
            raise UnsafePathError(key, f"reserved component {part!r}")
    return key


def validate_manifest_keys(files: Mapping[str, Any], *, reserved: Iterable[str] = ()) -> None:
    """Validate ALL keys before anything is written (atomic rejection)."""
    if not isinstance(files, Mapping):
        raise UnsafePathError(type(files).__name__, "manifest is not a mapping")
    for key in files:
        validate_relpath(key, reserved=reserved)


def validate_path_component(value: Any) -> str:
    validate_relpath(value)
    if "/" in value:
        raise UnsafePathError(value, "must be a single path component")
    return value


def validate_trace_id(value: Any) -> str:
    if not isinstance(value, str) or not _TRACE_RE.fullmatch(value):
        raise UnsafePathError(value, "invalid trace_id")
    return value


def validate_product_id(value: Any) -> str:
    """Format allow-list (RFC 1123 label). Enforced only where section 4 says."""
    if not isinstance(value, str) or not _PRODUCT_RE.fullmatch(value):
        raise UnsafePathError(value, "invalid product_id")
    return value


def safe_join(base: str, *keys: str, reserved: Iterable[str] = (), no_symlinks: bool = False) -> str:
    if not keys:
        raise UnsafePathError("", "no key")
    for key in keys:
        validate_relpath(key, reserved=reserved)
    candidate = os.path.join(base, *keys)
    base_real = Path(os.path.realpath(base))
    resolved = Path(os.path.realpath(candidate))
    if resolved == base_real or not resolved.is_relative_to(base_real):
        raise UnsafePathError("/".join(keys), "resolves outside base")
    if no_symlinks and resolved != base_real.joinpath(*"/".join(keys).split("/")):
        raise UnsafePathError("/".join(keys), "symlink inside path")
    return candidate

"""
StackVend deployed release, read-only (FD-7C P3a, SELFUP-VERSION-RECORD).

`scripts/deploy-services.sh` (and the upgrader) writes `release.json` next to this file into each component's source
directory before the build (never committed). This module reads it ONCE (first use) and never changes it:

    {"schema_version": 1, "release": "0.9.2", "commit": "<40 hex>|unknown", "dirty": false,
     "built_at": "2026-10-30T14:02:11Z", "source_repo": "<owner>/<repo>|local checkout", "builder": "deploy-services"}

A missing or invalid file answers {"release": "unknown", "reason": "..."}: a release is never made up.
Services report it on `GET /health` (never on the Control Center's public `/health`); jobs log one structured line
`stackvend.release` at start.

IDENTICAL COPIES (each component builds from its own directory): `release_info.py` at the root of every component
deployed by `scripts/deploy-services.sh` (parity: tests/test_sat11_release_record.py::test_release_info_copies_are_identical).
Standard library only.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Dict, Optional

RELEASE_FILE_NAME = "release.json"
SCHEMA_VERSION = 1
BUILDERS = ("deploy-services", "upgrader", "bootstrap")
LOCAL_CHECKOUT = "local checkout"
MAX_FILE_BYTES = 4096
_FIELDS = {"schema_version": int, "release": str, "commit": str, "dirty": bool, "built_at": str,
           "source_repo": str, "builder": str}
_HEX = frozenset("0123456789abcdef")

_cached: Optional[Dict[str, Any]] = None


def _unknown(reason: str) -> Dict[str, Any]:
    return {"release": "unknown", "reason": reason}


def validate_release_document(raw: Any) -> Optional[Dict[str, Any]]:
    """The document if it has exactly the release.json fields with exact JSON types, else None."""
    if not isinstance(raw, dict) or set(raw) != set(_FIELDS):
        return None
    for key, typ in _FIELDS.items():
        value = raw[key]
        if type(value) is not typ:  # exact type: a bool is not an int, an int is not a bool
            return None
    if raw["schema_version"] != SCHEMA_VERSION or raw["builder"] not in BUILDERS:
        return None
    release = raw["release"]
    if not release or len(release) > 64 or not all(c.isascii() and (c.isalnum() or c in ".-+") for c in release):
        return None
    commit = raw["commit"]
    if commit != "unknown" and (len(commit) != 40 or not set(commit) <= _HEX):
        return None
    if not raw["built_at"] or len(raw["built_at"]) > 40 or not raw["source_repo"] or len(raw["source_repo"]) > 140:
        return None
    return dict(raw)


def load_release(base_dir: Optional[str] = None) -> Dict[str, Any]:
    """Read and validate `release.json` in `base_dir` (default: this file's directory). Never raises."""
    path = os.path.join(base_dir or os.path.dirname(os.path.abspath(__file__)), RELEASE_FILE_NAME)
    try:
        if os.path.islink(path):
            return _unknown("release.json is a symlink")
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return _unknown("no release.json in this build")
    except OSError as e:
        return _unknown(f"release.json unreadable ({type(e).__name__})")
    if len(data) > MAX_FILE_BYTES:
        return _unknown("release.json too large")
    try:
        doc = validate_release_document(json.loads(data.decode("utf-8")))
    except (UnicodeDecodeError, ValueError):
        doc = None
    return doc if doc is not None else _unknown("release.json is not a valid release record")


def current_release() -> Dict[str, Any]:
    """This build's release (read once, then the same answer for the life of the process). A copy each call."""
    global _cached
    if _cached is None:
        _cached = load_release()
    return dict(_cached)


def log_release(component: str, stream: Any = None) -> Dict[str, Any]:
    """Jobs: one structured log line `stackvend.release` at start, as a JSON object on stdout (Cloud Logging reads
    `severity` / `message`; works before any logging configuration). Returns the release it logged."""
    release = current_release()
    line = json.dumps({"severity": "INFO", "message": "stackvend.release", "event": "stackvend.release",
                       "component": component, "release": release}, sort_keys=True)
    out = stream or sys.stdout
    try:
        out.write(line + "\n")
        out.flush()
    except (OSError, ValueError) as e:  # a closed stdout must never stop the job
        logging.getLogger("stackvend.release").warning(f"could not write the stackvend.release line: {e}")
    return release

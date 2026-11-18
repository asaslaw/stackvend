"""FD-4AQ W3 (register AQ-5): per-trace workspace lifecycle for the Terraform MCP server.

The server writes every deploy, plan, apply and drift check under `<workspace_root>/<trace_id>/<product_id>`
(`TerraformService.workspace_trace_dir`). That folder holds the tenant's app source, `.terraform` and plan files, so:

* a deploy's trace folder is deleted when the deploy ends (success, failure or exception), unless another running
  request still holds the same trace ID (two sync `/deploy` calls may share the default trace ID);
* plan folders (`/plan`, then `/apply` or `/drift-check` on the same trace ID) are kept, and a sweep deletes trace
  folders older than `TF_WORKSPACE_TTL_HOURS` (24) that no running request holds.

The sweep only considers direct children of the workspace root whose name is a valid trace ID (so never the
dot-prefixed `.castor-tooling` folder), never a symlink, and deletes with `shutil.rmtree`, which unlinks symlinks
inside the tree instead of following them. Every decision is made from exact names and `lstat` results.
"""
from __future__ import annotations

import contextlib
import logging
import os
import shutil
import stat
import threading
import time
from typing import Callable, Dict, Iterator, List, Optional

# The service's own shared/ package (in the build context); no fallback: a missing path guard must crash at boot.
from shared.path_safety import UnsafePathError, validate_trace_id

logger = logging.getLogger("mcp-terraform-server")

DEFAULT_TTL_HOURS = 24.0
# The sweep runs at startup and before requests, at most once per this many seconds (a directory listing).
DEFAULT_SWEEP_INTERVAL_S = 300.0


def workspace_ttl_seconds() -> float:
    """`TF_WORKSPACE_TTL_HOURS` (default 24) in seconds; an unreadable or non-positive value keeps the default."""
    raw = os.getenv("TF_WORKSPACE_TTL_HOURS", "")
    try:
        hours = float(raw) if raw else DEFAULT_TTL_HOURS
    except ValueError:
        logger.warning(f"TF_WORKSPACE_TTL_HOURS={raw!r} is not a number; using {DEFAULT_TTL_HOURS:g} h")
        hours = DEFAULT_TTL_HOURS
    if hours <= 0:
        logger.warning(f"TF_WORKSPACE_TTL_HOURS={raw!r} is not positive; using {DEFAULT_TTL_HOURS:g} h")
        hours = DEFAULT_TTL_HOURS
    return hours * 3600.0


class WorkspaceLifecycle:
    """Tracks which trace folders running requests hold, deletes deploy folders on release and sweeps old ones."""

    def __init__(self, workspace_root: str, trace_dir: Callable[[str], str],
                 clock: Callable[[], float] = time.time,
                 sweep_interval_s: float = DEFAULT_SWEEP_INTERVAL_S):
        self.workspace_root = workspace_root
        self._trace_dir = trace_dir            # TerraformService.workspace_trace_dir (validates; raises UnsafePathError)
        self._clock = clock
        self._sweep_interval_s = sweep_interval_s
        self._lock = threading.Lock()
        self._holds: Dict[str, int] = {}      # trace_id -> number of running requests holding it
        self._last_sweep: Optional[float] = None

    # ------------------------------------------------------------------ holds
    def active_traces(self) -> List[str]:
        with self._lock:
            return sorted(self._holds)

    @contextlib.contextmanager
    def hold(self, trace_id: str, delete_on_release: bool) -> Iterator[None]:
        """Marks `trace_id` as in use for the duration of the block. With `delete_on_release`, the trace folder is
        deleted when the block ends (however it ends) and no other running request holds the same trace ID."""
        with self._lock:
            self._holds[trace_id] = self._holds.get(trace_id, 0) + 1
        try:
            yield
        finally:
            with self._lock:
                left = self._holds.get(trace_id, 1) - 1
                if left > 0:
                    self._holds[trace_id] = left
                else:
                    self._holds.pop(trace_id, None)
                # Deleted under the lock so a request that takes the same trace ID next waits for the delete
                # instead of having its fresh folder removed.
                if delete_on_release and left <= 0:
                    self._delete_trace(trace_id, reason="deploy ended")

    def _delete_trace(self, trace_id: str, reason: str) -> bool:
        try:
            path = self._trace_dir(trace_id)
        except UnsafePathError as e:
            logger.warning(f"WORKSPACE_CLEANUP_SKIPPED: trace ID {trace_id!r} is not a safe path ({e.reason})")
            return False
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return False
        except OSError as e:
            logger.warning(f"WORKSPACE_CLEANUP_FAILED: could not stat {path}: {type(e).__name__}")
            return False
        if not stat.S_ISDIR(st.st_mode):
            # A symlink (or anything that is not a real directory) is never followed or removed.
            logger.warning(f"WORKSPACE_CLEANUP_SKIPPED: {path} is not a plain directory")
            return False
        try:
            shutil.rmtree(path)
        except OSError as e:
            logger.warning(f"WORKSPACE_CLEANUP_FAILED: could not delete {path} ({reason}): {type(e).__name__}")
            return False
        logger.info(f"WORKSPACE_DELETED: {path} ({reason})")
        return True

    # ------------------------------------------------------------------ sweep
    def _age_seconds(self, path: str, now: float) -> Optional[float]:
        """Seconds since the newest change of the trace folder or any of its direct entries (lstat; no follow)."""
        try:
            newest = os.lstat(path).st_mtime
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        newest = max(newest, entry.stat(follow_symlinks=False).st_mtime)
                    except OSError:
                        continue
        except OSError:
            return None
        return now - newest

    def sweep(self, ttl_seconds: Optional[float] = None) -> List[str]:
        """Deletes trace folders older than the TTL that no running request holds. Returns the deleted names."""
        ttl = workspace_ttl_seconds() if ttl_seconds is None else ttl_seconds
        now = self._clock()
        deleted: List[str] = []
        try:
            names = sorted(os.listdir(self.workspace_root))
        except OSError as e:
            logger.warning(f"WORKSPACE_SWEEP_FAILED: cannot list {self.workspace_root}: {type(e).__name__}")
            return deleted
        for name in names:
            try:
                validate_trace_id(name)          # never `.castor-tooling` or any other dot-prefixed tool folder
            except UnsafePathError:
                continue
            path = os.path.join(self.workspace_root, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISDIR(st.st_mode):     # symlinks and files at the root are left alone
                continue
            age = self._age_seconds(path, now)
            if age is None or age < ttl:
                continue
            with self._lock:
                if name in self._holds:
                    continue
                if self._delete_trace(name, reason=f"older than {ttl / 3600:g} h"):
                    deleted.append(name)
        with self._lock:
            self._last_sweep = now
        return deleted

    def maybe_sweep(self) -> List[str]:
        """The sweep, at most once per sweep interval (used before requests)."""
        now = self._clock()
        with self._lock:
            due = self._last_sweep is None or now - self._last_sweep >= self._sweep_interval_s
        if not due:
            return []
        return self.sweep()

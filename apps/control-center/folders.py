"""
StackVend Control Center: managed-folder containment (FD-4N red-team H9, FD-4AY).

The ONLY trusted root is MANAGED_WORKLOADS_FOLDER_ID (set by Terraform on the Control Center service). Firestore
`managed_folders` docs are agent-writable and are never an allow-list. Containment is resolved through the Cloud
Resource Manager v3 REST API (folders.get parent walk) with exact resource-name equality; any API error, 403
(outside the CC SA's folderAdmin scope), or depth overrun means "not contained" (fail closed).
"""
import logging
import os
from typing import Callable, Optional

logger = logging.getLogger("control-center-folders")

MAX_DEPTH = 10
_CRM_V3 = "https://cloudresourcemanager.googleapis.com/v3/"


class FolderConfigError(RuntimeError):
    """MANAGED_WORKLOADS_FOLDER_ID is not configured (no guessed default)."""


def normalize_folder_name(value: str) -> Optional[str]:
    """'123' or 'folders/123' -> 'folders/123'. Anything else (organizations/*, paths, junk) -> None."""
    v = (value or "").strip()
    if v.startswith("folders/"):
        v = v[len("folders/"):]
    return f"folders/{v}" if v.isdigit() else None


def managed_root_folder() -> str:
    root = normalize_folder_name(os.getenv("MANAGED_WORKLOADS_FOLDER_ID", ""))
    if not root:
        raise FolderConfigError("MANAGED_WORKLOADS_FOLDER_ID is not configured (or is not a numeric folder id).")
    return root


def _default_get_folder(name: str) -> dict:
    import google.auth
    from google.auth.transport.requests import AuthorizedSession
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    resp = AuthorizedSession(creds).get(_CRM_V3 + name, timeout=10)
    if resp.status_code != 200:
        raise PermissionError(f"folders.get {name} -> HTTP {resp.status_code}")
    return resp.json() or {}


def is_descendant_of_root(folder_name: str, get_folder: Optional[Callable[[str], dict]] = None,
                          include_root: bool = True) -> bool:
    """True iff `folder_name` is the managed root (when include_root) or a folder below it."""
    try:
        root = managed_root_folder()
    except FolderConfigError as e:
        logger.error(str(e))
        return False
    name = normalize_folder_name(folder_name)
    if not name:
        return False
    if name == root:
        return include_root
    fetch = get_folder or _default_get_folder
    current = name
    for _ in range(MAX_DEPTH):
        try:
            parent = (fetch(current) or {}).get("parent")
        except Exception as e:  # noqa: BLE001 - fail closed
            logger.warning(f"Folder containment check refused for {folder_name!r}: {e}")
            return False
        if not isinstance(parent, str) or not parent.startswith("folders/"):
            return False  # reached an organization (or garbage) without meeting the root
        if parent == root:
            return True
        current = parent
    return False

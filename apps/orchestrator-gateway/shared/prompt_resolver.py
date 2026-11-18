"""
Project Castor: Core Dynamic Prompt Resolver & Versioning Engine
Thread-safe cached prompt retrieval, automated zero-touch seeding,
subcollection version storage, git diff generation, and 1-click rollback.
"""

import difflib
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from shared.builtin_prompts import (
        AGENT_DISPLAY_METADATA,
        BUILTIN_PROMPTS,
        PRIMARY_AGENT_ROLES,
        get_builtin_prompt,
    )
    from shared.prompt_registry_schema import (
        AgentPromptDocument,
        PromptDiffResponse,
        PromptVersionRecord,
        PromptVersionSummary,
    )
except ImportError:
    from builtin_prompts import (
        AGENT_DISPLAY_METADATA,
        BUILTIN_PROMPTS,
        PRIMARY_AGENT_ROLES,
        get_builtin_prompt,
    )
    from prompt_registry_schema import (
        AgentPromptDocument,
        PromptDiffResponse,
        PromptVersionRecord,
        PromptVersionSummary,
    )

logger = logging.getLogger("castor-prompt-resolver")

# In-memory thread-safe cache: { role: (prompt_text, active_version, timestamp) }
_PROMPT_CACHE: Dict[str, Tuple[str, int, float]] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_TTL = 60.0  # seconds


def invalidate_prompt_cache(agent_role: Optional[str] = None) -> None:
    """Invalidates the in-memory cache for a specific agent persona or all personas."""
    with _CACHE_LOCK:
        if agent_role:
            clean = normalize_agent_role(agent_role)
            _PROMPT_CACHE.pop(clean, None)
            logger.debug(f"Invalidated prompt cache for {clean}")
        else:
            _PROMPT_CACHE.clear()
            logger.debug("Cleared entire prompt cache")


def normalize_agent_role(agent_role: str) -> str:
    """Harmonizes agent persona strings to standard enum key."""
    clean = (agent_role or "").upper().strip().replace("-", "_")
    if clean.startswith("ARCHITECT_RED_TEAM") or clean == "ARCHITECT_CRITIC":
        return "ARCHITECT_RED_TEAM_CRITIC"
    if clean.startswith("DEVELOPER_JUNIOR_"):
        return clean
    if not clean.endswith("_AGENT") and clean not in ("ASSISTANT", "ALL_AGENTS"):
        clean = f"{clean}_AGENT"
    if clean in ("QA_REVIEWER_AGENT", "QA_REVIEWER"):
        clean = "QA_AGENT"
    elif clean in ("DEVOPS_AGENT", "GCP_DEVOPS"):
        clean = "GCP_DEVOPS_AGENT"
    elif clean in ("RELEASE_AGENT", "RELEASE_ENGINEER"):
        clean = "RELEASE_ENGINEER_AGENT"
    return clean


def get_agent_system_prompt(
    agent_role: str,
    fallback_constant: Optional[str] = None,
    force_refresh: bool = False,
    db_client: Any = None,
) -> str:
    """
    Thread-safe cached prompt retrieval.
    Priority Hierarchy:
    1. In-memory thread-safe cache (sub-millisecond, 60s TTL)
    2. Firestore parent document `agent_prompts/{agent_role}`
    3. Auto-seed Firestore from baseline if document missing
    4. Code fallback constant or builtin prompt (Zero-crash safety net)
    """
    role = normalize_agent_role(agent_role)
    now = time.time()

    if not force_refresh:
        with _CACHE_LOCK:
            cached = _PROMPT_CACHE.get(role)
            if cached and (now - cached[2]) < _CACHE_TTL:
                return cached[0]

    code_fallback = fallback_constant or get_builtin_prompt(role)

    # Initialize Firestore client if not passed
    client = db_client
    if client is None:
        try:
            from google.cloud import firestore
            proj = os.getenv("PROJECT_ID", "")
            if proj:
                client = firestore.Client(project=proj)
        except Exception as e:
            logger.debug(f"Firestore Client init skipped in prompt resolver: {e}")
            client = None

    if client is None:
        return code_fallback

    try:
        doc_ref = client.collection("agent_prompts").document(role)
        snap = doc_ref.get()

        if hasattr(snap, "exists") and snap.exists:
            data = snap.to_dict() if callable(getattr(snap, "to_dict", None)) else {}
            if isinstance(data, dict):
                active_prompt = data.get("system_prompt") or code_fallback
                active_ver = int(data.get("active_version", 1))
                with _CACHE_LOCK:
                    _PROMPT_CACHE[role] = (active_prompt, active_ver, now)
                return active_prompt

        # Document does not exist: Seed Version 1 from code baseline
        return _seed_initial_prompt(role, code_fallback, client)
    except Exception as e:
        logger.warning(f"Failed to query prompt for {role} from Firestore: {e}. Using code fallback.")
        return code_fallback


def _seed_initial_prompt(role: str, prompt_text: str, client: Any) -> str:
    """Zero-touch seeder: writes Version 1 parent doc and subcollection record."""
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        meta = AGENT_DISPLAY_METADATA.get(role, {})
        display_name = meta.get("name", role.replace("_", " ").title())
        role_title = meta.get("role_title", "Autonomous Platform Persona")
        avatar_icon = meta.get("avatar_icon", "🤖")

        v1_summary = {
            "version": 1,
            "created_at": now_iso,
            "created_by": "system-baseline",
            "change_summary": "Initial baseline prompt seeded from source code constant",
            "is_active": True,
            "char_count": len(prompt_text),
        }

        parent_data = {
            "agent_role": role,
            "display_name": display_name,
            "role_title": role_title,
            "avatar_icon": avatar_icon,
            "active_version": 1,
            "system_prompt": prompt_text,
            "updated_at": now_iso,
            "updated_by": "system-baseline",
            "recent_versions": [v1_summary],
            "total_versions_count": 1,
        }

        # 1. Write parent document
        client.collection("agent_prompts").document(role).set(parent_data)

        # 2. Write immutable subcollection record: agent_prompts/{role}/versions/1
        v1_record = {
            **v1_summary,
            "agent_role": role,
            "prompt_text": prompt_text,
        }
        client.collection("agent_prompts").document(role).collection("versions").document("1").set(v1_record)

        with _CACHE_LOCK:
            _PROMPT_CACHE[role] = (prompt_text, 1, time.time())

        logger.info(f"Successfully auto-seeded Version 1 for agent prompt '{role}'")
        return prompt_text
    except Exception as e:
        logger.warning(f"Auto-seeding prompt for {role} failed ({e}). Returning fallback constant.")
        return prompt_text


def save_agent_prompt_version(
    agent_role: str,
    new_prompt_text: str,
    user_email: str,
    change_summary: str,
    db_client: Any,
) -> AgentPromptDocument:
    """
    Publishes a new prompt version:
    1. Determines next sequential version (active_version + 1 or max version in subcollection)
    2. Stores immutable snapshot in subcollection `agent_prompts/{role}/versions/{v}`
    3. Updates parent doc with active_version = v and prepends to recent_versions (capped at 10)
    4. Invalidates in-memory cache
    """
    role = normalize_agent_role(agent_role)
    if not new_prompt_text or not new_prompt_text.strip():
        raise ValueError("Prompt text cannot be empty")
    clean_text = new_prompt_text
    now_iso = datetime.now(timezone.utc).isoformat()

    doc_ref = db_client.collection("agent_prompts").document(role)
    snap = doc_ref.get()

    parent_data = {}
    if hasattr(snap, "exists") and snap.exists:
        parent_data = snap.to_dict() if callable(getattr(snap, "to_dict", None)) else {}

    current_ver = int(parent_data.get("active_version", 0))
    total_ver = int(parent_data.get("total_versions_count", current_ver))
    new_ver = max(current_ver, total_ver) + 1

    meta = AGENT_DISPLAY_METADATA.get(role, {})
    display_name = parent_data.get("display_name") or meta.get("name", role.replace("_", " ").title())
    role_title = parent_data.get("role_title") or meta.get("role_title", "")
    avatar_icon = parent_data.get("avatar_icon") or meta.get("avatar_icon", "🤖")

    # Historical summary item
    new_summary = {
        "version": new_ver,
        "created_at": now_iso,
        "created_by": user_email or "admin",
        "change_summary": change_summary.strip() or f"Published version {new_ver}",
        "is_active": True,
        "char_count": len(clean_text),
    }

    # Mark older items in recent_versions as inactive
    old_recent = parent_data.get("recent_versions", [])
    updated_recent = [new_summary]
    for r in old_recent:
        r_copy = dict(r)
        r_copy["is_active"] = False
        updated_recent.append(r_copy)
    updated_recent = updated_recent[:10]  # Cap at 10 summaries in parent document

    # 1. Write immutable snapshot to subcollection
    subcoll_data = {
        **new_summary,
        "agent_role": role,
        "prompt_text": clean_text,
    }
    doc_ref.collection("versions").document(str(new_ver)).set(subcoll_data)

    # 2. Update parent doc
    updated_parent = {
        "agent_role": role,
        "display_name": display_name,
        "role_title": role_title,
        "avatar_icon": avatar_icon,
        "active_version": new_ver,
        "system_prompt": clean_text,
        "updated_at": now_iso,
        "updated_by": user_email or "admin",
        "recent_versions": updated_recent,
        "total_versions_count": new_ver,
    }
    doc_ref.set(updated_parent, merge=True)

    # 3. Invalidate cache
    invalidate_prompt_cache(role)
    with _CACHE_LOCK:
        _PROMPT_CACHE[role] = (clean_text, new_ver, time.time())

    return AgentPromptDocument(**updated_parent)


def rollback_agent_prompt_version(
    agent_role: str,
    target_version: int,
    user_email: str,
    db_client: Any,
    rollback_reason: Optional[str] = None,
) -> AgentPromptDocument:
    """
    Reinstates a previous version:
    1. Loads target version snapshot from subcollection
    2. Updates parent document to active_version = target_version
    3. Invalidates in-memory cache
    """
    role = normalize_agent_role(agent_role)
    doc_ref = db_client.collection("agent_prompts").document(role)

    # 1. Retrieve historical snapshot
    ver_ref = doc_ref.collection("versions").document(str(target_version))
    ver_snap = ver_ref.get()

    if not (hasattr(ver_snap, "exists") and ver_snap.exists):
        raise ValueError(f"Version {target_version} does not exist for agent {role}")

    ver_data = ver_snap.to_dict() if callable(getattr(ver_snap, "to_dict", None)) else {}
    restored_text = ver_data.get("prompt_text", "")
    now_iso = datetime.now(timezone.utc).isoformat()

    # 2. Update parent document
    parent_snap = doc_ref.get()
    parent_data = parent_snap.to_dict() if (hasattr(parent_snap, "exists") and parent_snap.exists) else {}

    # Update recent_versions is_active flags
    recent = parent_data.get("recent_versions", [])
    found = False
    for r in recent:
        if r.get("version") == target_version:
            r["is_active"] = True
            found = True
        else:
            r["is_active"] = False

    if not found:
        recent.insert(0, {
            "version": target_version,
            "created_at": ver_data.get("created_at", now_iso),
            "created_by": ver_data.get("created_by", "unknown"),
            "change_summary": f"Restored version {target_version}" + (f": {rollback_reason}" if rollback_reason else ""),
            "is_active": True,
            "char_count": len(restored_text),
        })
        recent = recent[:10]

    reason_str = f"Rolled back to v{target_version}" + (f" ({rollback_reason})" if rollback_reason else "")
    updated_parent = {
        "agent_role": role,
        "active_version": target_version,
        "system_prompt": restored_text,
        "updated_at": now_iso,
        "updated_by": user_email or "admin",
        "recent_versions": recent,
    }
    doc_ref.set(updated_parent, merge=True)

    # 3. Invalidate in-memory cache
    invalidate_prompt_cache(role)
    with _CACHE_LOCK:
        _PROMPT_CACHE[role] = (restored_text, target_version, time.time())

    full_parent = {**parent_data, **updated_parent}
    return AgentPromptDocument(**full_parent)


def reset_agent_prompt_to_default(
    agent_role: str,
    user_email: str,
    db_client: Any,
) -> AgentPromptDocument:
    """
    Emergency 1-click recovery:
    Loads code baseline constant from shared/builtin_prompts.py and publishes it
    as the newest active version with changelog note 'Reset to code baseline default'.
    """
    role = normalize_agent_role(agent_role)
    baseline_text = get_builtin_prompt(role)

    return save_agent_prompt_version(
        agent_role=role,
        new_prompt_text=baseline_text,
        user_email=user_email,
        change_summary=f"Reset to code baseline default by {user_email or 'operator'}",
        db_client=db_client,
    )


def get_prompt_diff(
    agent_role: str,
    version: Optional[int] = None,
    db_client: Any = None,
) -> PromptDiffResponse:
    """
    Computes standard unified git diff between the target version (or active version)
    and the immutable code baseline constant.
    """
    role = normalize_agent_role(agent_role)
    baseline_text = get_builtin_prompt(role)
    active_text = baseline_text
    active_ver = 1

    if db_client:
        try:
            doc_ref = db_client.collection("agent_prompts").document(role)
            if version:
                ver_snap = doc_ref.collection("versions").document(str(version)).get()
                if hasattr(ver_snap, "exists") and ver_snap.exists:
                    vdata = ver_snap.to_dict() or {}
                    active_text = vdata.get("prompt_text", baseline_text)
                    active_ver = version
            else:
                snap = doc_ref.get()
                if hasattr(snap, "exists") and snap.exists:
                    data = snap.to_dict() or {}
                    active_text = data.get("system_prompt", baseline_text)
                    active_ver = int(data.get("active_version", 1))
        except Exception as e:
            logger.warning(f"Could not load prompt for diff calculation ({e}). Falling back to baseline.")

    baseline_lines = baseline_text.splitlines(keepends=True)
    active_lines = active_text.splitlines(keepends=True)

    diff_lines = list(
        difflib.unified_diff(
            baseline_lines,
            active_lines,
            fromfile=f"a/{role.lower()}_baseline.py",
            tofile=f"b/{role.lower()}_v{active_ver}.md",
            lineterm="",
        )
    )

    unified_diff_str = "".join(diff_lines) if diff_lines else "No differences detected vs code baseline."
    has_changes = bool(diff_lines and active_text.strip() != baseline_text.strip())

    return PromptDiffResponse(
        agent_role=role,
        active_version=active_ver,
        unified_diff=unified_diff_str,
        has_changes=has_changes,
        baseline_char_count=len(baseline_text),
        active_char_count=len(active_text),
    )


def get_all_agent_prompt_summaries(
    db_client: Any = None,
    include_specialists: bool = False,
) -> List[AgentPromptDocument]:
    """Retrieves summaries for registered platform agent personas, auto-seeding if empty."""
    results: List[AgentPromptDocument] = []
    registered_roles = list(BUILTIN_PROMPTS.keys()) if include_specialists else PRIMARY_AGENT_ROLES

    for role in registered_roles:
        # Resolve prompt (which will auto-seed if doc missing and db_client present)
        current_text = get_agent_system_prompt(role, db_client=db_client)
        meta = AGENT_DISPLAY_METADATA.get(role, {})

        active_ver = 1
        updated_at = datetime.now(timezone.utc).isoformat()
        updated_by = "system"
        recent = []
        total_count = 1

        if db_client:
            try:
                snap = db_client.collection("agent_prompts").document(role).get()
                if hasattr(snap, "exists") and snap.exists:
                    data = snap.to_dict() or {}
                    active_ver = int(data.get("active_version", 1))
                    updated_at = data.get("updated_at", updated_at)
                    updated_by = data.get("updated_by", "admin")
                    recent = [PromptVersionSummary(**r) for r in data.get("recent_versions", [])]
                    total_count = int(data.get("total_versions_count", len(recent) or 1))
            except Exception:
                pass

        if not recent:
            recent = [
                PromptVersionSummary(
                    version=1,
                    created_at=updated_at,
                    created_by="system-baseline",
                    change_summary="Initial baseline prompt from source code",
                    is_active=True,
                    char_count=len(current_text),
                )
            ]

        doc = AgentPromptDocument(
            agent_role=role,
            display_name=meta.get("name", role.replace("_", " ").title()),
            role_title=meta.get("role_title", ""),
            avatar_icon=meta.get("avatar_icon", "🤖"),
            active_version=active_ver,
            system_prompt=current_text,
            updated_at=updated_at,
            updated_by=updated_by,
            recent_versions=recent,
            total_versions_count=total_count,
        )
        results.append(doc)

    return results

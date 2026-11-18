"""
Project Castor: Agent Prompt Registry & Versioning Routes
Provides REST API endpoints for listing agent prompts, inspecting versions,
publishing new versions, diffing against code baselines, rolling back, and resetting to default.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Request
from authz import ADMIN, require

from auth import extract_user_email, verify_admin_access
from config import DynamicHTTPException as HTTPException
from db import db
from schemas import (
    AgentPromptDocument,
    PromptDiffResponse,
    PromptVersionRecord,
    PublishPromptRequest,
    RollbackPromptRequest,
)

try:
    from shared.prompt_resolver import (
        get_agent_system_prompt,
        get_all_agent_prompt_summaries,
        get_prompt_diff,
        normalize_agent_role,
        reset_agent_prompt_to_default,
        rollback_agent_prompt_version,
        save_agent_prompt_version,
    )
except ImportError:
    from apps.control_center.shared.prompt_resolver import (
        get_agent_system_prompt,
        get_all_agent_prompt_summaries,
        get_prompt_diff,
        normalize_agent_role,
        reset_agent_prompt_to_default,
        rollback_agent_prompt_version,
        save_agent_prompt_version,
    )

logger = logging.getLogger("control-center-prompts-router")

router = APIRouter(prefix="/api/prompts", tags=["Agent Prompts"])


@router.get("", response_model=List[AgentPromptDocument], dependencies=[require(ADMIN)])
def list_agent_prompts(request: Request, include_specialists: bool = False):
    """
    Lists prompt documents and active version summaries for registered platform agents.
    Auto-seeds empty personas from immutable source code constants.
    """
    try:
        return get_all_agent_prompt_summaries(db_client=db, include_specialists=include_specialists)
    except Exception as e:
        logger.error(f"Error listing agent prompts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list agent prompts: {str(e)}")


@router.get("/{agent_role}", response_model=AgentPromptDocument, dependencies=[require(ADMIN)])
def get_agent_prompt(agent_role: str, request: Request):
    """Retrieves active prompt document and version history for a specific agent role."""
    clean_role = normalize_agent_role(agent_role)
    try:
        summaries = get_all_agent_prompt_summaries(db_client=db, include_specialists=True)
        for s in summaries:
            if s.agent_role == clean_role:
                return s
        raise HTTPException(status_code=404, detail=f"Agent prompt for role '{agent_role}' not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading prompt for {agent_role}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{agent_role}/versions/{version}", response_model=PromptVersionRecord, dependencies=[require(ADMIN)])
def get_agent_prompt_version(agent_role: str, version: int, request: Request):
    """Retrieves full text and metadata for a specific historical version from the subcollection."""
    clean_role = normalize_agent_role(agent_role)
    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    try:
        doc_ref = db.collection("agent_prompts").document(clean_role)
        ver_snap = doc_ref.collection("versions").document(str(version)).get()
        if not (hasattr(ver_snap, "exists") and ver_snap.exists):
            raise HTTPException(
                status_code=404,
                detail=f"Version {version} not found for agent {clean_role}",
            )
        data = ver_snap.to_dict() or {}
        return PromptVersionRecord(
            agent_role=clean_role,
            version=int(data.get("version", version)),
            created_at=data.get("created_at", ""),
            created_by=data.get("created_by", "unknown"),
            change_summary=data.get("change_summary", ""),
            is_active=bool(data.get("is_active", False)),
            char_count=int(data.get("char_count", len(data.get("prompt_text", "")))),
            prompt_text=data.get("prompt_text", ""),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error loading version {version} for {agent_role}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{agent_role}", response_model=AgentPromptDocument, dependencies=[require(ADMIN)])
def publish_agent_prompt(
    agent_role: str,
    payload: PublishPromptRequest,
    request: Request,
):
    """
    Publishes a new prompt version for an agent persona.
    Restricted to Platform Administrators.
    Stores immutable snapshot in subcollection, updates active parent doc, and clears memory cache.
    """
    verify_admin_access(request)
    user_email = extract_user_email(request) or "admin"
    clean_role = normalize_agent_role(agent_role)

    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    try:
        updated_doc = save_agent_prompt_version(
            agent_role=clean_role,
            new_prompt_text=payload.prompt_text,
            user_email=user_email,
            change_summary=payload.change_summary,
            db_client=db,
        )
        logger.info(
            f"User '{user_email}' published v{updated_doc.active_version} for agent '{clean_role}'"
        )
        return updated_doc
    except Exception as e:
        logger.error(f"Failed to publish prompt version for {agent_role}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to publish prompt version: {str(e)}")


@router.post("/{agent_role}/rollback", response_model=AgentPromptDocument, dependencies=[require(ADMIN)])
def rollback_agent_prompt(
    agent_role: str,
    payload: RollbackPromptRequest,
    request: Request,
):
    """
    Reverts active prompt to a historical version from the subcollection.
    Restricted to Platform Administrators.
    """
    verify_admin_access(request)
    user_email = extract_user_email(request) or "admin"
    clean_role = normalize_agent_role(agent_role)

    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    try:
        updated_doc = rollback_agent_prompt_version(
            agent_role=clean_role,
            target_version=payload.target_version,
            user_email=user_email,
            db_client=db,
            rollback_reason=payload.rollback_reason,
        )
        logger.info(
            f"User '{user_email}' rolled back agent '{clean_role}' to v{payload.target_version}"
        )
        return updated_doc
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        logger.error(f"Failed to rollback prompt for {agent_role}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to rollback prompt: {str(e)}")


@router.post("/{agent_role}/reset-default", response_model=AgentPromptDocument, dependencies=[require(ADMIN)])
def reset_agent_prompt(agent_role: str, request: Request):
    """
    Emergency recovery: resets the agent prompt to the immutable code baseline
    from shared/builtin_prompts.py and publishes it as the newest active version.
    Restricted to Platform Administrators.
    """
    verify_admin_access(request)
    user_email = extract_user_email(request) or "admin"
    clean_role = normalize_agent_role(agent_role)

    if not db:
        raise HTTPException(status_code=503, detail="Firestore database unavailable")

    try:
        updated_doc = reset_agent_prompt_to_default(
            agent_role=clean_role,
            user_email=user_email,
            db_client=db,
        )
        logger.info(
            f"User '{user_email}' reset agent '{clean_role}' to code default (now v{updated_doc.active_version})"
        )
        return updated_doc
    except Exception as e:
        logger.error(f"Failed to reset prompt for {agent_role}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reset prompt: {str(e)}")


@router.get("/{agent_role}/diff", response_model=PromptDiffResponse, dependencies=[require(ADMIN)])
def get_agent_prompt_diff(
    agent_role: str,
    version: Optional[int] = None,
    request: Request = None,
):
    """
    Computes a standard unified git diff comparing the active prompt (or requested version)
    against the immutable source code baseline constant.
    """
    clean_role = normalize_agent_role(agent_role)
    try:
        return get_prompt_diff(
            agent_role=clean_role,
            version=version,
            db_client=db,
        )
    except Exception as e:
        logger.error(f"Error computing prompt diff for {agent_role}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

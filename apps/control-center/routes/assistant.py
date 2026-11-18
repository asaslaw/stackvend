"""
Project Castor: Assistant Chat Routes
Conversational AI chat engine grounded in workload and execution context.
"""

import logging
from fastapi import APIRouter, Request
from authz import SCOPED, require

from assistant import CastorAssistantEngine
from config import PROJECT_ID
from db import db
from schemas import ChatQueryRequest, ChatResponse, UserRole

logger = logging.getLogger("control-center-assistant")

router = APIRouter(tags=["Assistant"])

assistant_engine = CastorAssistantEngine(project_id=PROJECT_ID, firestore_client=db)


@router.post("/api/assistant/chat", response_model=ChatResponse, dependencies=[require(SCOPED)])
def assistant_chat(req: ChatQueryRequest, request: Request):
    """Processes natural-language queries about system state with pre-LLM context sandboxing."""
    user_role = getattr(request.state, "user_role", UserRole.VIEWER)
    assigned_workloads = getattr(request.state, "assigned_workloads", [])
    user_email = getattr(request.state, "user_email", "user")
    return assistant_engine.handle_chat_message(
        message=req.message,
        conversation_history=req.conversation_history,
        user_role=user_role,
        assigned_workloads=assigned_workloads,
        user_email=user_email,
    )

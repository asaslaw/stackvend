"""
Project Castor: Dynamic Junior Prompt Registry Resolver
Resolves junior subagent system prompts dynamically from Firestore PromptRegistry with fallback to local modules.
"""

import logging
from typing import Optional
from google.cloud import firestore

from .backend_worker import BACKEND_WORKER_PROMPT
from .frontend_worker import FRONTEND_WORKER_PROMPT
from .iac_worker import IAC_WORKER_PROMPT
from .test_worker import TEST_WORKER_PROMPT
from .devops_worker import DEVOPS_WORKER_PROMPT

logger = logging.getLogger("castor-junior-prompts")

LOCAL_PROMPTS_MAP = {
    "BACKEND_ENGINEER": BACKEND_WORKER_PROMPT,
    "FRONTEND_ENGINEER": FRONTEND_WORKER_PROMPT,
    "IAC_ENGINEER": IAC_WORKER_PROMPT,
    "TEST_ENGINEER": TEST_WORKER_PROMPT,
    "DEVOPS_ENGINEER": DEVOPS_WORKER_PROMPT,
    "DATABASE_ENGINEER": BACKEND_WORKER_PROMPT,
}


def resolve_junior_prompt(persona: str, db: Optional[firestore.Client] = None) -> str:
    """
    Attempts to fetch active persona prompt from Firestore PromptRegistry (`prompts` collection).
    Falls back to embedded immutable constants if Firestore is offline or unseeded.
    """
    clean_persona = str(persona).upper().replace("JUNIOR_", "")
    prompt_key = f"developer_junior_{clean_persona.lower()}"

    if db:
        try:
            doc = db.collection("prompts").document(prompt_key).get()
            if doc.exists:
                data = doc.to_dict() or {}
                active_text = data.get("current_prompt") or data.get("prompt_text")
                if active_text and len(active_text.strip()) > 50:
                    logger.debug(f"Resolved prompt for {clean_persona} from Firestore ({prompt_key})")
                    return active_text.strip()
        except Exception as e:
            logger.debug(f"Firestore prompt resolution skipped for {prompt_key}: {e}")

    # Fallback to local prompt definition
    return LOCAL_PROMPTS_MAP.get(clean_persona, BACKEND_WORKER_PROMPT)

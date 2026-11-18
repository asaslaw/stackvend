"""
Project Castor: Compliance Agent Prompts
Directs Gemini to audit and remediate architecture plans and application code
against Google Cloud Organization Policies, Assured Workloads, and CMEK encryption mandates.
"""

import os
from typing import Any, Optional

try:
    from shared.builtin_prompts import COMPLIANCE_SYSTEM_PROMPT
except ImportError:
    try:
        from apps.orchestrator_gateway.shared.builtin_prompts import COMPLIANCE_SYSTEM_PROMPT
    except ImportError:
        COMPLIANCE_SYSTEM_PROMPT = """You are **The Compliance Agent** in StackVend, an autonomous multi-agent software engineering and cloud infrastructure platform on Google Cloud.
Your mission is to audit infrastructure plans and application code against Google Cloud Organization Policies, Assured Workloads regulatory controls, CMEK encryption mandates, and data residency boundaries prior to provisioning.
"""


def build_compliance_system_prompt(task_context: str = "", db_client: Any = None) -> str:
    """Constructs the Compliance Agent system prompt dynamically from the prompt registry."""
    try:
        try:
            from shared.prompt_resolver import get_agent_system_prompt
        except ImportError:
            from apps.orchestrator_gateway.shared.prompt_resolver import get_agent_system_prompt
        prompt = get_agent_system_prompt(
            agent_role="COMPLIANCE_AGENT",
            fallback_constant=COMPLIANCE_SYSTEM_PROMPT,
            db_client=db_client,
        )
    except Exception:
        prompt = COMPLIANCE_SYSTEM_PROMPT

    # Dynamic Operational Directives managed via Glass Pane
    try:
        if not db_client:
            from google.cloud import firestore
            proj = os.getenv("PROJECT_ID", "")
            if proj:
                db_client = firestore.Client(project=proj)
        if db_client:
            doc = db_client.collection("system_config").document("platform_settings").get()
            if hasattr(doc, "exists") and doc.exists:
                data = doc.to_dict() or {}
                directives = (data.get("models") or {}).get("custom_directives", {}).get("COMPLIANCE_AGENT", [])
                if directives and isinstance(directives, list):
                    directives_block = "\n### ACTIVE OPERATIONAL DIRECTIVES (MANAGED VIA GLASS PANE):\n"
                    directives_block += "\n".join(f"- [DIRECTIVE]: {d}" for d in directives if d)
                    prompt = f"{prompt}\n{directives_block}\n"
    except Exception:
        pass

    return prompt

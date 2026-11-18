"""
Project Castor: Shared Agentic Skills Resolver
Dynamically resolves and formats active skills for any target agent based on role and task context.
Sub-5ms execution with zero-database overhead for built-in skills.
"""

import logging
from typing import Dict, List, Any, Optional

from shared.builtin_skills_provider import get_builtin_skills

logger = logging.getLogger("castor-skills-resolver")


def resolve_active_skills(
    target_agent: str,
    context_text: str = "",
    db_client: Any = None,
) -> List[Dict[str, Any]]:
    """
    Resolves all active skills that apply to target_agent (or ALL_AGENTS).
    A skill is activated if:
      1. is_active is True, AND
      2. target_agent matches (or is ALL_AGENTS), AND
      3. always_active is True OR any trigger keyword matches context_text (case-insensitive).
    """
    active_skills: List[Dict[str, Any]] = []
    norm_context = context_text.lower() if context_text else ""

    # 1. Load built-in skills
    try:
        builtins = get_builtin_skills()
    except Exception as e:
        logger.warning(f"Failed to load built-in skills: {e}")
        builtins = []

    # 2. Load custom skills from Firestore if db available
    custom_skills: List[Dict[str, Any]] = []
    if db_client:
        try:
            docs = db_client.collection("custom_skills").stream()
            for doc in docs:
                data = doc.to_dict() or {}
                if "skill_id" not in data:
                    data["skill_id"] = doc.id
                custom_skills.append(data)
        except Exception as e:
            logger.warning(f"Error loading custom skills from Firestore: {e}")

    all_candidate_skills = builtins + custom_skills

    for skill in all_candidate_skills:
        # Check active status
        if not skill.get("is_active", True):
            continue

        # Check role match
        skill_target = skill.get("target_agent", "ALL_AGENTS")
        if skill_target not in (target_agent, "ALL_AGENTS"):
            continue

        # Check activation condition
        if skill.get("always_active", False):
            active_skills.append(skill)
            continue

        # Check trigger keywords
        keywords = skill.get("trigger_keywords") or []
        if not keywords:
            # If no keywords and not always active, default to active for target agent
            active_skills.append(skill)
            continue

        # Keyword match against context text
        if any(kw.lower() in norm_context for kw in keywords if kw):
            active_skills.append(skill)

    # Sort deterministically: built-in first, then by skill_id
    active_skills.sort(key=lambda s: (0 if s.get("is_builtin") else 1, s.get("skill_id", "")))
    return active_skills


def format_skills_for_prompt(skills: List[Dict[str, Any]]) -> str:
    """Formats active skills into a structured markdown block for LLM prompt context injection."""
    if not skills:
        return ""

    blocks: List[str] = [
        "================================================================================",
        "DYNAMIC AGENTIC SKILLS & DOMAIN GUIDELINES (STRICT COMPLIANCE REQUIRED):",
        "The following specialized platform skills have been dynamically activated for this task.",
        "You MUST adhere strictly to all architectural invariants and patterns defined below:",
        "================================================================================",
    ]

    for s in skills:
        title = s.get("name", s.get("skill_id", "Skill"))
        sid = s.get("skill_id", "")
        body = s.get("instructions_markdown", "").strip()
        blocks.append(f"\n--- [ACTIVE SKILL: {title} (`{sid}`)] ---\n{body}\n")

    blocks.append("================================================================================\n")
    return "\n".join(blocks)

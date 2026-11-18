"""
Project Castor: Prompt Registry & Versioning Schemas
Pydantic data models for Firestore-backed system prompts, version snapshots,
publish requests, diff summaries, and rollbacks.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class PromptVersionSummary(BaseModel):
    """Lean summary of a historical prompt version for list views and change timelines."""
    version: int = Field(description="Sequential 1-based version index")
    created_at: str = Field(description="ISO-8601 timestamp of publication")
    created_by: str = Field(description="User email or system service that published this version")
    change_summary: str = Field(description="Brief changelog message for this version")
    is_active: bool = Field(default=False, description="True if this version represents the current live prompt")
    char_count: int = Field(default=0, description="Length of prompt string in characters")


class PromptVersionRecord(PromptVersionSummary):
    """Complete version record containing immutable prompt instructions stored in subcollection."""
    agent_role: str = Field(description="Target agent role (e.g. ARCHITECT_AGENT)")
    prompt_text: str = Field(description="Complete raw system instructions string")


class AgentPromptDocument(BaseModel):
    """
    Primary parent document stored in Firestore at `agent_prompts/{agent_role}`.
    Keeps a lightweight live snapshot and the last 10 versions metadata for fast UI rendering.
    """
    agent_role: str = Field(description="Target agent role (e.g. ARCHITECT_AGENT)")
    display_name: str = Field(description="Human-readable agent title (e.g. The Architect)")
    role_title: str = Field(default="", description="Operational persona subtitle")
    avatar_icon: str = Field(default="🤖", description="Emoji or avatar identifier")
    active_version: int = Field(default=1, description="Currently live version index")
    system_prompt: str = Field(description="Active system prompt instructions string")
    updated_at: str = Field(description="ISO-8601 timestamp of last modification")
    updated_by: str = Field(default="system", description="Email of user who last modified this prompt")
    recent_versions: List[PromptVersionSummary] = Field(
        default_factory=list,
        description="Capped list of the 10 most recent version summaries for quick history views",
    )
    total_versions_count: int = Field(default=1, description="Lifetime total versions published")


class PublishPromptRequest(BaseModel):
    """Request payload to publish a new active prompt version."""
    prompt_text: str = Field(
        min_length=10,
        max_length=100000,
        description="Markdown or plaintext system prompt instructions",
    )
    change_summary: str = Field(
        min_length=3,
        max_length=250,
        description="Brief explanation of changes made in this version",
    )


class RollbackPromptRequest(BaseModel):
    """Request payload to revert active prompt to a previous version from subcollection."""
    target_version: int = Field(ge=1, description="Historical version number to reinstate")
    rollback_reason: Optional[str] = Field(
        default=None,
        description="Optional justification for rolling back to this version",
    )


class PromptDiffResponse(BaseModel):
    """Diff inspection comparing active or selected version against code baseline."""
    agent_role: str
    active_version: int
    unified_diff: str = Field(description="Standard unified git diff text")
    has_changes: bool = Field(description="True if active prompt differs from code default")
    baseline_char_count: int
    active_char_count: int

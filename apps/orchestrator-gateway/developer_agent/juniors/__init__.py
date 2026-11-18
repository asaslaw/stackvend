"""
Project Castor: Junior Developer Specialists Package
"""

from .prompt_registry import resolve_junior_prompt
from .backend_worker import BACKEND_WORKER_PROMPT
from .frontend_worker import FRONTEND_WORKER_PROMPT
from .iac_worker import IAC_WORKER_PROMPT
from .test_worker import TEST_WORKER_PROMPT
from .devops_worker import DEVOPS_WORKER_PROMPT

__all__ = [
    "resolve_junior_prompt",
    "BACKEND_WORKER_PROMPT",
    "FRONTEND_WORKER_PROMPT",
    "IAC_WORKER_PROMPT",
    "TEST_WORKER_PROMPT",
    "DEVOPS_WORKER_PROMPT",
]

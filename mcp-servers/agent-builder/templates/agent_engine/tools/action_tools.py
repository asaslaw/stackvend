"""
State-Mutating Tools: Requires explicit confirmation / approval decorator.
"""

from typing import Dict, Any

def require_operator_approval(func):
    """Decorator ensuring state-mutating actions require confirmed authorization."""
    def wrapper(*args, **kwargs):
        confirmation_token = kwargs.get("confirmation_token")
        if not confirmation_token:
            return {
                "status": "APPROVAL_REQUIRED",
                "action": func.__name__,
                "message": "This is a state-mutating operation. Explicit operator confirmation token is required.",
                "pending_approval": True,
            }
        return func(*args, **kwargs)
    return wrapper


@require_operator_approval
def execute_state_mutation(resource_id: str, new_value: str, confirmation_token: str = None) -> Dict[str, Any]:
    """Mutates external system state after confirmation."""
    return {
        "status": "SUCCESS",
        "resource_id": resource_id,
        "mutation": "APPLIED",
    }

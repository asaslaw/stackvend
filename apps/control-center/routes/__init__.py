import sys
from unittest.mock import MagicMock

def _mock_decorator(*args, **kwargs):
    def inner(fn):
        return fn
    return inner

# If fastapi is mocked by a test runner (e.g. test_approvals, test_flight_deck), ensure APIRouter returns a mock with decorator passthroughs
mock_fastapi = sys.modules.get("fastapi")
if mock_fastapi and (isinstance(mock_fastapi, MagicMock) or not hasattr(mock_fastapi, "__path__")):
    class MockRouter:
        def __init__(self, *args, **kwargs):
            self.routes = []
            self.get = _mock_decorator
            self.post = _mock_decorator
            self.put = _mock_decorator
            self.delete = _mock_decorator
            self.patch = _mock_decorator
    mock_fastapi.APIRouter = MockRouter

from routes import (
    approvals,
    assistant,
    finops,
    settings,
    telemetry,
    users,
    web,
    workloads,
)

__all__ = [
    "approvals",
    "assistant",
    "finops",
    "settings",
    "telemetry",
    "users",
    "web",
    "workloads",
]

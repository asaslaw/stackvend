"""
Tests for Agent Location Resolution (Gemini 3.7 Global Endpoint Routing).
Verifies:
1. DeveloperAgent() defaults location to 'global' (or os.getenv('GEMINI_LOCATION')).
2. DeveloperAgent(location='...') respects explicit location.
3. ArchitectAgent() defaults location to 'global'.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock

# Mock third-party dependencies before importing agents
for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt', 'pydantic'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from developer_agent.handler import DeveloperAgent
from architect_agent.handler import ArchitectAgent


class TestAgentLocationResolution(unittest.TestCase):
    def setUp(self):
        self.orig_env = os.environ.copy()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_developer_agent_default_global(self):
        os.environ.pop("GEMINI_LOCATION", None)
        os.environ.pop("VERTEX_LOCATION", None)
        agent = DeveloperAgent()
        self.assertEqual(agent.location, "global")

    def test_developer_agent_env_location(self):
        os.environ["GEMINI_LOCATION"] = "custom-region"
        agent = DeveloperAgent()
        self.assertEqual(agent.location, "custom-region")

    def test_developer_agent_explicit_location(self):
        os.environ["GEMINI_LOCATION"] = "custom-region"
        agent = DeveloperAgent(location="europe-west4")
        self.assertEqual(agent.location, "europe-west4")

    def test_architect_agent_default_global(self):
        os.environ.pop("GEMINI_LOCATION", None)
        os.environ.pop("VERTEX_LOCATION", None)
        agent = ArchitectAgent()
        self.assertEqual(agent.location, "global")

    def test_architect_agent_env_location(self):
        os.environ["GEMINI_LOCATION"] = "asia-northeast1"
        agent = ArchitectAgent()
        self.assertEqual(agent.location, "asia-northeast1")


if __name__ == "__main__":
    unittest.main()

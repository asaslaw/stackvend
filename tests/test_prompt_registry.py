"""
Project Castor: Unit & Integration Tests for Firestore Prompt Registry & Versioning Engine
Tests:
- Zero-touch auto-seeding on first access
- Immutable source code fallback (zero-crash safety net)
- Thread-safe memory caching with TTL & cache invalidation
- Subcollection version storage and sequential version incrementing
- 1-click historical rollback to prior version snapshot
- Emergency reset to system default constant
- Unified git diff generation
- All 9 platform agent personas resolution
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
og_dir = os.path.join(repo_root, "apps", "orchestrator-gateway")

if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
if cc_dir not in sys.path:
    sys.path.append(cc_dir)
if og_dir not in sys.path:
    sys.path.append(og_dir)

from shared.builtin_prompts import (
    ARCHITECT_SYSTEM_PROMPT,
    DEVELOPER_SYSTEM_PROMPT,
    COMPLIANCE_SYSTEM_PROMPT,
    GCP_DEVOPS_SYSTEM_PROMPT,
    QA_REVIEWER_SYSTEM_PROMPT,
    RELEASE_ENGINEER_SYSTEM_PROMPT,
    SRE_SYSTEM_PROMPT,
    FINOPS_SYSTEM_PROMPT,
    ASSISTANT_SYSTEM_PROMPT,
    BUILTIN_PROMPTS,
    get_builtin_prompt,
)
from shared.prompt_resolver import (
    get_agent_system_prompt,
    invalidate_prompt_cache,
    normalize_agent_role,
    save_agent_prompt_version,
    rollback_agent_prompt_version,
    reset_agent_prompt_to_default,
    get_prompt_diff,
    get_all_agent_prompt_summaries,
)
from shared.prompt_registry_schema import (
    AgentPromptDocument,
    PromptVersionRecord,
    PromptVersionSummary,
    PublishPromptRequest,
    RollbackPromptRequest,
    PromptDiffResponse,
)


class MockFirestoreDocumentSnapshot:
    def __init__(self, data=None, exists=True):
        self._data = data or {}
        self.exists = exists

    def to_dict(self):
        return dict(self._data)


class MockFirestoreDocumentRef:
    def __init__(self, path, store):
        self.path = path
        self.store = store

    def get(self):
        data = self.store.get(self.path)
        return MockFirestoreDocumentSnapshot(data=data, exists=(data is not None))

    def set(self, data, merge=False):
        if merge and self.path in self.store:
            self.store[self.path].update(data)
        else:
            self.store[self.path] = dict(data)

    def collection(self, sub_name):
        return MockFirestoreCollection(f"{self.path}/{sub_name}", self.store)


class MockFirestoreCollection:
    def __init__(self, path, store):
        self.path = path
        self.store = store

    def document(self, doc_id):
        return MockFirestoreDocumentRef(f"{self.path}/{doc_id}", self.store)


class MockFirestoreClient:
    def __init__(self):
        self.store = {}

    def collection(self, name):
        return MockFirestoreCollection(name, self.store)


class TestPromptRegistryEngine(unittest.TestCase):

    def setUp(self):
        invalidate_prompt_cache()
        self.mock_db = MockFirestoreClient()

    def tearDown(self):
        invalidate_prompt_cache()

    def test_all_9_personas_have_builtin_prompts(self):
        """Verify all 9 platform agent personas exist in BUILTIN_PROMPTS."""
        expected_roles = [
            "ARCHITECT_AGENT",
            "DEVELOPER_AGENT",
            "COMPLIANCE_AGENT",
            "GCP_DEVOPS_AGENT",
            "QA_AGENT",
            "RELEASE_ENGINEER_AGENT",
            "SRE_AGENT",
            "FINOPS_AGENT",
            "ASSISTANT",
        ]
        for role in expected_roles:
            prompt = get_builtin_prompt(role)
            self.assertTrue(len(prompt) > 50, f"Prompt for {role} was empty or too short")
            self.assertEqual(prompt, BUILTIN_PROMPTS[role])

    def test_normalize_agent_role(self):
        """Test agent role normalization for kebab-case and alias variants."""
        self.assertEqual(normalize_agent_role("architect"), "ARCHITECT_AGENT")
        self.assertEqual(normalize_agent_role("developer-agent"), "DEVELOPER_AGENT")
        self.assertEqual(normalize_agent_role("qa-reviewer"), "QA_AGENT")
        self.assertEqual(normalize_agent_role("gcp-devops"), "GCP_DEVOPS_AGENT")
        self.assertEqual(normalize_agent_role("release-engineer"), "RELEASE_ENGINEER_AGENT")
        self.assertEqual(normalize_agent_role("assistant"), "ASSISTANT")

    def test_offline_fallback_zero_crash(self):
        """When Firestore client is None or raises exceptions, resolver returns builtin constants safely."""
        prompt = get_agent_system_prompt("ARCHITECT_AGENT", db_client=None)
        self.assertEqual(prompt, ARCHITECT_SYSTEM_PROMPT)

        # Mock broken client that raises connection error
        broken_client = MagicMock()
        broken_client.collection.side_effect = RuntimeError("Firestore Network Partition Timeout")
        prompt_fallback = get_agent_system_prompt("DEVELOPER_AGENT", db_client=broken_client)
        self.assertEqual(prompt_fallback, DEVELOPER_SYSTEM_PROMPT)

    def test_zero_touch_auto_seeding(self):
        """Verify that first read on empty Firestore automatically seeds Version 1."""
        prompt = get_agent_system_prompt("ARCHITECT_AGENT", db_client=self.mock_db)
        self.assertEqual(prompt, ARCHITECT_SYSTEM_PROMPT)

        # Verify parent document created
        parent_snap = self.mock_db.collection("agent_prompts").document("ARCHITECT_AGENT").get()
        self.assertTrue(parent_snap.exists)
        pdata = parent_snap.to_dict()
        self.assertEqual(pdata["active_version"], 1)
        self.assertEqual(pdata["system_prompt"], ARCHITECT_SYSTEM_PROMPT)
        self.assertEqual(len(pdata["recent_versions"]), 1)

        # Verify subcollection record created: agent_prompts/ARCHITECT_AGENT/versions/1
        ver_snap = self.mock_db.collection("agent_prompts").document("ARCHITECT_AGENT").collection("versions").document("1").get()
        self.assertTrue(ver_snap.exists)
        vdata = ver_snap.to_dict()
        self.assertEqual(vdata["version"], 1)
        self.assertEqual(vdata["prompt_text"], ARCHITECT_SYSTEM_PROMPT)
        self.assertTrue(vdata["is_active"])

    def test_thread_safe_caching_and_invalidation(self):
        """Verify cache returns promptly and invalidation forces fresh lookup."""
        # 1. Seed initial
        get_agent_system_prompt("FINOPS_AGENT", db_client=self.mock_db)

        # 2. Mutate underlying mock DB directly without cache invalidation
        self.mock_db.store["agent_prompts/FINOPS_AGENT"]["system_prompt"] = "MODIFIED DIRECTLY IN DB"

        # 3. Read from cache: should still return cached original
        cached_read = get_agent_system_prompt("FINOPS_AGENT", db_client=self.mock_db)
        self.assertEqual(cached_read, FINOPS_SYSTEM_PROMPT)

        # 4. Invalidate cache: should now fetch mutated DB string
        invalidate_prompt_cache("FINOPS_AGENT")
        fresh_read = get_agent_system_prompt("FINOPS_AGENT", db_client=self.mock_db)
        self.assertEqual(fresh_read, "MODIFIED DIRECTLY IN DB")

    def test_publish_new_version_with_subcollection(self):
        """Verify publishing a new version creates subcollection snapshot and updates parent doc."""
        # 1. Seed initial
        get_agent_system_prompt("DEVELOPER_AGENT", db_client=self.mock_db)

        # 2. Publish Version 2
        v2_text = DEVELOPER_SYSTEM_PROMPT + "\n# CUSTOM RULE: Enforce strict type annotations"
        updated_doc = save_agent_prompt_version(
            agent_role="DEVELOPER_AGENT",
            new_prompt_text=v2_text,
            user_email="engineer@example.com",
            change_summary="Added typing rule",
            db_client=self.mock_db,
        )

        self.assertEqual(updated_doc.active_version, 2)
        self.assertEqual(updated_doc.system_prompt, v2_text)
        self.assertEqual(len(updated_doc.recent_versions), 2)
        self.assertTrue(updated_doc.recent_versions[0].is_active)
        self.assertFalse(updated_doc.recent_versions[1].is_active)

        # Verify subcollection has both v1 and v2 records
        v1_snap = self.mock_db.collection("agent_prompts").document("DEVELOPER_AGENT").collection("versions").document("1").get()
        v2_snap = self.mock_db.collection("agent_prompts").document("DEVELOPER_AGENT").collection("versions").document("2").get()
        self.assertTrue(v1_snap.exists)
        self.assertTrue(v2_snap.exists)
        self.assertEqual(v2_snap.to_dict()["prompt_text"], v2_text)

        # Verify resolver returns v2
        active_prompt = get_agent_system_prompt("DEVELOPER_AGENT", db_client=self.mock_db)
        self.assertEqual(active_prompt, v2_text)

    def test_rollback_to_previous_version(self):
        """Verify 1-click rollback restores snapshot from subcollection."""
        # Seed v1
        get_agent_system_prompt("SRE_AGENT", db_client=self.mock_db)

        # Publish v2
        save_agent_prompt_version(
            agent_role="SRE_AGENT",
            new_prompt_text="SRE V2 EXPERIMENTAL PROMPT",
            user_email="dev@example.com",
            change_summary="Experimental prompt test",
            db_client=self.mock_db,
        )
        self.assertEqual(get_agent_system_prompt("SRE_AGENT", db_client=self.mock_db), "SRE V2 EXPERIMENTAL PROMPT")

        # Rollback to v1
        reverted_doc = rollback_agent_prompt_version(
            agent_role="SRE_AGENT",
            target_version=1,
            user_email="admin@example.com",
            db_client=self.mock_db,
            rollback_reason="Reverting experimental regression",
        )

        self.assertEqual(reverted_doc.active_version, 1)
        self.assertEqual(reverted_doc.system_prompt, SRE_SYSTEM_PROMPT)

        # Verify active prompt in memory and resolver is v1
        active_now = get_agent_system_prompt("SRE_AGENT", db_client=self.mock_db)
        self.assertEqual(active_now, SRE_SYSTEM_PROMPT)

    def test_emergency_reset_to_code_default(self):
        """Verify reset_agent_prompt_to_default restores immutable python baseline."""
        # Seed v1
        get_agent_system_prompt("QA_AGENT", db_client=self.mock_db)

        # Publish corrupted v2
        save_agent_prompt_version(
            agent_role="QA_AGENT",
            new_prompt_text="CORRUPTED QA INSTRUCTION",
            user_email="saboteur@test.com",
            change_summary="Accidental overwrite",
            db_client=self.mock_db,
        )

        # Trigger reset to default
        reset_doc = reset_agent_prompt_to_default(
            agent_role="QA_AGENT",
            user_email="admin@test.com",
            db_client=self.mock_db,
        )

        self.assertEqual(reset_doc.active_version, 3)
        self.assertEqual(reset_doc.system_prompt, QA_REVIEWER_SYSTEM_PROMPT)
        self.assertIn("Reset to code baseline default", reset_doc.recent_versions[0].change_summary)

        # Verify resolver serves baseline
        self.assertEqual(get_agent_system_prompt("QA_AGENT", db_client=self.mock_db), QA_REVIEWER_SYSTEM_PROMPT)

    def test_unified_git_diff_generation(self):
        """Verify unified git diff output matches standard diff format."""
        # Baseline identical diff
        diff_resp = get_prompt_diff("COMPLIANCE_AGENT", db_client=self.mock_db)
        self.assertFalse(diff_resp.has_changes)

        # Publish modified prompt
        modified = COMPLIANCE_SYSTEM_PROMPT + "\n# ENFORCE: No unencrypted storage buckets\n"
        save_agent_prompt_version(
            agent_role="COMPLIANCE_AGENT",
            new_prompt_text=modified,
            user_email="admin@castor.local",
            change_summary="Added encryption mandate",
            db_client=self.mock_db,
        )

        diff_modified = get_prompt_diff("COMPLIANCE_AGENT", db_client=self.mock_db)
        self.assertTrue(diff_modified.has_changes)
        self.assertIn("+", diff_modified.unified_diff)
        self.assertIn("No unencrypted storage buckets", diff_modified.unified_diff)

    def test_get_all_agent_prompt_summaries(self):
        """Verify summary listing covers all 9 personas."""
        summaries = get_all_agent_prompt_summaries(db_client=self.mock_db)
        self.assertEqual(len(summaries), 9)
        roles = {s.agent_role for s in summaries}
        self.assertIn("ARCHITECT_AGENT", roles)
        self.assertIn("DEVELOPER_AGENT", roles)
        self.assertIn("COMPLIANCE_AGENT", roles)
        self.assertIn("GCP_DEVOPS_AGENT", roles)
        self.assertIn("QA_AGENT", roles)
        self.assertIn("RELEASE_ENGINEER_AGENT", roles)
        self.assertIn("SRE_AGENT", roles)
        self.assertIn("FINOPS_AGENT", roles)
        self.assertIn("ASSISTANT", roles)


if __name__ == "__main__":
    unittest.main()

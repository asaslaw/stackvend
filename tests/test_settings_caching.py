"""
Project Castor: Unit Tests for Platform Global Settings In-Memory Caching & Client
Validates 60s TTL, cache invalidation, and fallback resilience when Firestore is absent or unreachable.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
import unittest
from unittest.mock import MagicMock

mock_firestore = MagicMock()
mock_google_cloud = MagicMock()
mock_google_cloud.firestore = mock_firestore
sys.modules["google"] = MagicMock()
sys.modules["google.cloud"] = mock_google_cloud
sys.modules["google.cloud.firestore"] = mock_firestore

from shared.settings import (
    PlatformSettings,
    get_platform_settings,
    invalidate_settings_cache,
)


class TestSettingsCaching(unittest.TestCase):
    def setUp(self):
        invalidate_settings_cache()
        mock_firestore.reset_mock()
        mock_firestore.Client.side_effect = None
        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_firestore.Client.return_value.collection.return_value.document.return_value.get.return_value = mock_doc

    def tearDown(self):
        invalidate_settings_cache()
        mock_firestore.reset_mock()
        mock_firestore.Client.side_effect = None
        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_firestore.Client.return_value.collection.return_value.document.return_value.get.return_value = mock_doc

    def test_caching_within_ttl(self):
        mock_db = MagicMock()
        mock_firestore.Client.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "finops": {"default_monthly_budget_usd": 75.0},
            "version": 2,
        }
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        # First fetch: queries Firestore
        settings_1 = get_platform_settings(project_id="test-proj")
        self.assertEqual(settings_1.finops.default_monthly_budget_usd, 75.0)
        self.assertEqual(settings_1.version, 2)
        mock_db.collection.assert_called_once_with("system_config")

        # Second fetch: within 60s TTL, uses cached object, doesn't call Firestore again
        mock_db.collection.reset_mock()
        settings_2 = get_platform_settings(project_id="test-proj")
        self.assertIs(settings_1, settings_2)
        mock_db.collection.assert_not_called()

    def test_force_refresh_bypasses_cache(self):
        mock_db = MagicMock()
        mock_firestore.Client.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "finops": {"default_monthly_budget_usd": 50.0},
            "version": 1,
        }
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        s1 = get_platform_settings(project_id="test-proj")
        self.assertEqual(s1.finops.default_monthly_budget_usd, 50.0)

        # Update mock data and force refresh
        mock_doc.to_dict.return_value = {
            "finops": {"default_monthly_budget_usd": 90.0},
            "version": 2,
        }
        s2 = get_platform_settings(force_refresh=True, project_id="test-proj")
        self.assertEqual(s2.finops.default_monthly_budget_usd, 90.0)
        self.assertEqual(s2.version, 2)

    def test_cache_invalidation(self):
        mock_db = MagicMock()
        mock_firestore.Client.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"version": 1}
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        get_platform_settings(project_id="test-proj")
        self.assertEqual(mock_db.collection.call_count, 1)

        # Invalidate cache
        invalidate_settings_cache()

        get_platform_settings(project_id="test-proj")
        self.assertEqual(mock_db.collection.call_count, 2)

    def test_fallback_when_document_missing(self):
        mock_db = MagicMock()
        mock_firestore.Client.return_value = mock_db
        mock_doc = MagicMock()
        mock_doc.exists = False
        mock_db.collection.return_value.document.return_value.get.return_value = mock_doc

        # Must fall back gracefully to compile-time defaults
        settings = get_platform_settings(project_id="test-proj")
        self.assertEqual(settings.finops.default_monthly_budget_usd, 40.0)
        self.assertEqual(settings.orchestration.default_gcp_region, "us-central1")
        self.assertEqual(settings.version, 1)

    def test_fallback_when_firestore_errors(self):
        mock_firestore.Client.side_effect = Exception("Firestore unavailable")

        # Must not crash; returns defaults
        settings = get_platform_settings(project_id="test-proj")
        self.assertEqual(settings.finops.default_monthly_budget_usd, 40.0)
        self.assertEqual(settings.version, 1)


if __name__ == "__main__":
    unittest.main()

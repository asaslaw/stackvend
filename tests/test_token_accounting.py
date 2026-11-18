"""
Project Castor: Unit Tests for Token Accounting & FinOps Attribution
Tests cost calculations, token usage extraction, atomic Firestore increments,
and multi-tier rollup across feature requests and greenfield workloads.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import unittest
from unittest.mock import MagicMock, patch
from shared.token_accounting import (
    MODEL_PRICING,
    AgentTokenRecord,
    ExecutionTokenSummary,
    calculate_token_cost,
    extract_token_usage,
    record_agent_tokens,
    rollup_tokens_to_feature,
)


class TestTokenAccounting(unittest.TestCase):
    def test_calculate_token_cost_flash(self):
        # gemini-3.7-flash: prompt: $0.075/M ($0.000000075), candidates: $0.30/M ($0.0000003)
        cost = calculate_token_cost("gemini-3.7-flash", prompt_tokens=1_000_000, candidates_tokens=1_000_000)
        self.assertAlmostEqual(cost, 0.375, places=4)

        # 10k prompt, 2k candidates
        cost_small = calculate_token_cost("gemini-3.7-flash", prompt_tokens=10_000, candidates_tokens=2_000)
        expected = (10_000 * 0.075 / 1_000_000) + (2_000 * 0.30 / 1_000_000)
        self.assertAlmostEqual(cost_small, expected, places=6)

    def test_calculate_token_cost_fallback(self):
        # A built-in model without its own price row falls back to the default pricing (as before)
        cost = calculate_token_cost("gemini-2.5-pro", prompt_tokens=100_000, candidates_tokens=50_000)
        self.assertGreater(cost, 0.0)
        # OPEN-MODEL-SETTINGS (owner 11-10): an id with no built-in rules and no price row has an unknown cost (None,
        # never $0 and never another model's price)
        self.assertIsNone(calculate_token_cost("unknown-model-xyz", prompt_tokens=100_000, candidates_tokens=50_000))

    def test_extract_token_usage_genai_object(self):
        mock_response = MagicMock()
        mock_response.usage_metadata.prompt_token_count = 1200
        mock_response.usage_metadata.candidates_token_count = 450
        mock_response.usage_metadata.total_token_count = 1650

        rec = extract_token_usage(mock_response, "gemini-3.7-flash")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.prompt_tokens, 1200)
        self.assertEqual(rec.candidates_tokens, 450)
        self.assertEqual(rec.total_tokens, 1650)
        self.assertEqual(rec.model, "gemini-3.7-flash")
        self.assertGreater(rec.cost_usd, 0.0)

    def test_extract_token_usage_dict(self):
        dict_response = {
            "usage_metadata": {
                "prompt_token_count": 800,
                "candidates_token_count": 200,
                "total_token_count": 1000,
            }
        }
        rec = extract_token_usage(dict_response, "gemini-3.8-flash")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.prompt_tokens, 800)
        self.assertEqual(rec.candidates_tokens, 200)
        self.assertEqual(rec.total_tokens, 1000)

    def test_extract_token_usage_fallback(self):
        rec = extract_token_usage(None, "gemini-3.7-flash")
        self.assertIsNone(rec)

    def test_record_agent_tokens_atomic_increment(self):
        mock_db = MagicMock()
        mock_doc = MagicMock()
        mock_db.collection.return_value.document.return_value = mock_doc

        rec = AgentTokenRecord(
            model="gemini-3.7-flash",
            prompt_tokens=5000,
            candidates_tokens=1500,
            total_tokens=6500,
            cost_usd=0.0011,
        )

        res = record_agent_tokens(mock_db, "trace-test-123", "architect", rec)
        self.assertTrue(res)
        mock_db.collection.assert_called_with("pipeline_executions")
        mock_db.collection.return_value.document.assert_called_with("trace-test-123")

        # Verify update was called with atomic increments
        mock_doc.update.assert_called_once()
        args, kwargs = mock_doc.update.call_args
        payload = args[0]
        self.assertIn("token_usage.total_prompt_tokens", payload)
        self.assertIn("token_usage.by_agent.architect.prompt_tokens", payload)

    def test_record_agent_tokens_handles_none_db(self):
        rec = AgentTokenRecord(
            model="gemini-3.7-flash",
            prompt_tokens=100,
            candidates_tokens=50,
            total_tokens=150,
            cost_usd=0.0001,
        )
        # Should gracefully return False without raising an exception
        self.assertFalse(record_agent_tokens(None, "trace-123", "architect", rec))
        self.assertFalse(record_agent_tokens(MagicMock(), "", "architect", rec))

    def test_rollup_tokens_to_feature_and_workload(self):
        mock_db = MagicMock()
        mock_exec_doc = MagicMock()
        mock_exec_doc.exists = True
        mock_exec_doc.to_dict.return_value = {
            "request_id": "feat-456",
            "product_id": "prod-789",
            "token_usage": {
                "total_prompt_tokens": 15000,
                "total_candidates_tokens": 3000,
                "total_tokens": 18000,
                "total_cost_usd": 0.0027,
                "by_agent": {
                    "architect": {"prompt_tokens": 5000, "candidates_tokens": 1000, "total_tokens": 6000},
                    "developer_swarm": {"prompt_tokens": 10000, "candidates_tokens": 2000, "total_tokens": 12000},
                }
            }
        }

        mock_db.collection.return_value.document.return_value.get.return_value = mock_exec_doc

        result = rollup_tokens_to_feature(mock_db, "trace-test-123", request_id="feat-456", product_id="prod-789")
        self.assertIsNotNone(result)
        self.assertEqual(result["total_tokens"], 18000)
        self.assertIn("agents", result)

        # Verify feature_requests update
        mock_db.collection.assert_any_call("feature_requests")
        # Verify workloads cumulative update
        mock_db.collection.assert_any_call("workloads")

    def test_rollup_tokens_greenfield_workload_without_feature_request(self):
        mock_db = MagicMock()
        mock_exec_doc = MagicMock()
        mock_exec_doc.exists = True
        mock_exec_doc.to_dict.return_value = {
            "product_id": "prod-greenfield",
            "token_usage": {
                "total_prompt_tokens": 20000,
                "total_candidates_tokens": 5000,
                "total_tokens": 25000,
                "total_cost_usd": 0.0040,
                "by_agent": {
                    "architect": {"prompt_tokens": 20000, "candidates_tokens": 5000, "total_tokens": 25000},
                }
            }
        }
        mock_db.collection.return_value.document.return_value.get.return_value = mock_exec_doc

        # No request_id provided (greenfield initial workload synthesis)
        result = rollup_tokens_to_feature(mock_db, "trace-greenfield", request_id=None, product_id="prod-greenfield")
        self.assertIsNotNone(result)
        self.assertEqual(result["total_tokens"], 25000)

        # Workloads collection updated with cumulative tokens
        mock_db.collection.assert_any_call("workloads")


if __name__ == "__main__":
    unittest.main()

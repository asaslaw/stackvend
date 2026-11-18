"""
Unit tests for FinOps Live Spend Reconciler & Active Accrual Engine
Validates tfstate parsing, hourly resource pricing, accrued spend calculation,
BigQuery export precedence, and Firestore hourly burn caching.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import sys
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
SERVICES_DIR = os.path.join(CC_DIR, "services")

sys.path.insert(0, REPO_ROOT)
sys.path.insert(1, CC_DIR)
sys.path.insert(2, SERVICES_DIR)

from finops_sync import (
    calculate_hourly_burn_from_tfstate,
    compute_accrued_spend,
    reconcile_workload_spend,
    HOURLY_RESOURCE_RATES,
)


class TestFinopsLiveSync(unittest.TestCase):
    def setUp(self):
        os.environ["TEST_MODE"] = "true"
        os.environ["ENVIRONMENT"] = "test"

    def test_tfstate_parsing_cloud_sql_and_vpc_connector(self):
        """Verify that calculate_hourly_burn_from_tfstate correctly detects Cloud SQL & VPC connector."""
        sample_tfstate = {
            "version": 4,
            "terraform_version": "1.9.0",
            "resources": [
                {
                    "type": "google_sql_database_instance",
                    "name": "postgres",
                    "instances": [
                        {
                            "attributes": {
                                "name": "billing-postgres-instance",
                                "settings": [
                                    {
                                        "tier": "db-f1-micro",
                                        "disk_size": 10,
                                    }
                                ]
                            }
                        }
                    ]
                },
                {
                    "type": "google_vpc_access_connector",
                    "name": "connector",
                    "instances": [
                        {
                            "attributes": {
                                "name": "connector-testplan08-a",
                                "min_instances": 2,
                            }
                        }
                    ]
                },
                {
                    "type": "google_compute_router_nat",
                    "name": "nat",
                    "instances": [
                        {
                            "attributes": {
                                "name": "nat-gateway",
                            }
                        }
                    ]
                },
            ]
        }

        hourly_burn, summary = calculate_hourly_burn_from_tfstate(sample_tfstate)
        # Rates:
        # sql_db_f1_micro = 0.0105
        # disk = 10 * (0.170 / 730) = 0.002328...
        # vpc = 2 * 0.0180 = 0.0360
        # nat = 0.0014
        # total = ~0.0502
        self.assertGreater(hourly_burn, 0.045)
        self.assertLess(hourly_burn, 0.060)
        self.assertIn("cloud_sql", summary)
        self.assertEqual(summary["cloud_sql"]["tier"], "db-f1-micro")
        self.assertIn("vpc_connector", summary)
        self.assertEqual(summary["vpc_connector"]["min_instances"], 2)
        self.assertIn("cloud_nat", summary)

    def test_compute_accrued_spend(self):
        """Verify that compute_accrued_spend calculates uptime * hourly_rate accurately."""
        now = datetime.now(timezone.utc)
        # 24 hours ago
        deployed_at = (now - timedelta(hours=24)).isoformat()
        hourly_rate = 0.05  # $0.05/hr

        spend = compute_accrued_spend(deployed_at, hourly_rate, now=now)
        # 24 * 0.05 = $1.20
        self.assertAlmostEqual(spend, 1.20, delta=0.05)

    def test_reconcile_workload_spend_with_active_accrual(self):
        """Verify that reconcile_workload_spend computes accrual when BigQuery is unconfigured."""
        os.environ["TEST_LIVE_FINOPS"] = "true"
        now = datetime.now(timezone.utc)
        deployed_at = (now - timedelta(hours=20)).isoformat()

        workload_data = {
            "product_id": "testplan08-a",
            "project_id": "testplan08-a",
            "deployed_at": deployed_at,
            "cached_hourly_burn_usd": 0.0488,
            "budget_ceiling_monthly_usd": 40.0,
        }

        res = reconcile_workload_spend(
            product_id="testplan08-a",
            workload_data=workload_data,
            host_project="test-platform-project",
        )

        self.assertEqual(res["spend_source"], "ESTIMATED_ACTIVE_ACCRUAL")
        self.assertGreater(res["current_spend_usd"], 0.90)
        # Assert magnitude sanity: 0.0488 * 730 = $35.62/mo, NOT pennies from calendar-day dilution
        self.assertAlmostEqual(res["projected_monthly_spend_usd"], 35.62, delta=1.5)
        self.assertIn("spend_last_updated_at", res)
        os.environ.pop("TEST_LIVE_FINOPS", None)

    def test_reconcile_newly_deployed_workload_prevents_dilution(self):
        """Verify that a workload deployed 2 hours ago is not diluted by current_day of month."""
        os.environ["TEST_LIVE_FINOPS"] = "true"
        now = datetime.now(timezone.utc)
        deployed_at = (now - timedelta(hours=2)).isoformat()

        workload_data = {
            "product_id": "fresh-cloudsql-workload",
            "project_id": "fresh-cloudsql-workload",
            "deployed_at": deployed_at,
            "cached_hourly_burn_usd": 0.0502,
            "budget_ceiling_monthly_usd": 40.0,
        }

        res = reconcile_workload_spend(
            product_id="fresh-cloudsql-workload",
            workload_data=workload_data,
            host_project="test-platform-project",
        )

        # 0.0502 * 730 = $36.65
        self.assertAlmostEqual(res["projected_monthly_spend_usd"], 36.65, delta=1.0)
        self.assertFalse(res["is_overrun_projected"])
        os.environ.pop("TEST_LIVE_FINOPS", None)

    def test_reconcile_workload_spend_bigquery_precedence(self):
        """Verify that when BigQuery export reports costs, it takes precedence as GCP_BILLING_EXPORT."""
        os.environ["TEST_LIVE_FINOPS"] = "true"
        os.environ["BILLING_EXPORT_DATASET"] = "my_project.billing_export"

        mock_bq_client = MagicMock()
        mock_row = MagicMock()
        mock_row.net_cost = 14.50
        mock_bq_client.query.return_value.result.return_value = [mock_row]

        workload_data = {
            "product_id": "testplan08-a",
            "project_id": "testplan08-a",
            "cached_hourly_burn_usd": 0.05,
            "budget_ceiling_monthly_usd": 40.0,
        }

        res = reconcile_workload_spend(
            product_id="testplan08-a",
            workload_data=workload_data,
            host_project="test-platform-project",
            bq_client=mock_bq_client,
        )

        self.assertEqual(res["spend_source"], "GCP_BILLING_EXPORT")
        self.assertEqual(res["current_spend_usd"], 14.50)
        os.environ.pop("TEST_LIVE_FINOPS", None)
        os.environ.pop("BILLING_EXPORT_DATASET", None)


if __name__ == "__main__":
    unittest.main()

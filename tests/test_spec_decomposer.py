"""
Unit Tests for ChunkedSpecDecomposer (90-Page Enterprise Specification Map-Reduce)
Verifies chunking, domain mapping, plan reduction, and DAG generation.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/orchestrator-gateway")))

from architect_agent.spec_decomposer import ChunkedSpecDecomposer
from architect_agent.schemas import ArchitecturePlanDAG, TaskCategory


class TestChunkedSpecDecomposer(unittest.TestCase):
    def setUp(self):
        self.decomposer = ChunkedSpecDecomposer(genai_client=None, model_name="gemini-3.7-flash")

    def test_should_activate_map_reduce(self):
        short_spec = "Build a simple microservice with FastAPI and Cloud Run."
        self.assertFalse(self.decomposer.should_activate_map_reduce(short_spec))

        # 30,000 char spec
        huge_spec = "# Enterprise Architecture\n" + ("Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n" * 600)
        self.assertTrue(self.decomposer.should_activate_map_reduce(huge_spec))

        # Multi-header 15,000 char spec
        multi_header = """# Global Ingestion Architecture
## 1. Edge API Gateway
""" + ("Edge ingress details.\n" * 100) + """
## 2. Event Streaming Core
""" + ("Pub/Sub streaming topic details.\n" * 100) + """
## 3. Data Warehouse Analytics
""" + ("BigQuery and Firestore database setup.\n" * 100) + """
## 4. Security, IAM & Compliance
""" + ("IAM roles, Secret Manager, VPC connector.\n" * 100)
        self.assertTrue(self.decomposer.should_activate_map_reduce(multi_header))

    def test_split_spec_into_domains(self):
        spec_text = """# Chapter 1: Ingestion System
Ingestion details and webhook processing.
# Chapter 2: Processing Core
Worker nodes, task queues, and async workers.
# Chapter 3: Analytics Storage
BigQuery datasets and partition tables.
"""
        chunks = self.decomposer.split_spec_into_domains(spec_text)
        self.assertGreaterEqual(len(chunks), 1)
        self.assertTrue(any("Chapter" in c["domain_title"] or "Domain" in c["domain_title"] for c in chunks))

    def test_reduce_subplans_deduplication_and_dag_generation(self):
        subplans = [
            {
                "domain": "Ingestion Gateway",
                "services": ["api-gateway", "event-producer"],
                "requires_vpc": False,
                "cloud_apis": ["run.googleapis.com", "pubsub.googleapis.com"],
                "shared_contracts": {"EventEnvelope": "class EventEnvelope(BaseModel): event_id: str"},
                "infra_tasks": [
                    {
                        "task_id": "INFRA-ING-01",
                        "title": "Provision Ingestion PubSub Topics",
                        "category": "INFRA",
                        "target_files": ["infra/workload/main.tf"],
                    }
                ],
                "code_tasks": [
                    {
                        "task_id": "CODE-ING-01",
                        "title": "Implement API Gateway",
                        "category": "CODE",
                        "target_files": ["apps/api-gateway/main.py"],
                    }
                ],
            },
            {
                "domain": "Processing Core & Data Warehouse",
                "services": ["event-consumer", "analytics-worker"],
                "requires_vpc": True,
                "cloud_apis": ["run.googleapis.com", "bigquery.googleapis.com"],
                "shared_contracts": {"EventEnvelope": "class EventEnvelope(BaseModel): event_id: str"},
                "infra_tasks": [
                    {
                        "task_id": "INFRA-ING-01",  # Duplicate ID should be deduplicated
                        "title": "Provision Ingestion PubSub Topics",
                        "category": "INFRA",
                        "target_files": ["infra/workload/main.tf"],
                    },
                    {
                        "task_id": "INFRA-DATA-01",
                        "title": "Provision BigQuery Datasets",
                        "category": "INFRA",
                        "target_files": ["infra/workload/main.tf"],
                    }
                ],
                "code_tasks": [
                    {
                        "task_id": "CODE-PROC-01",
                        "title": "Implement Analytics Worker",
                        "category": "CODE",
                        "target_files": ["apps/analytics-worker/main.py"],
                    }
                ],
            }
        ]

        dag = self.decomposer.reduce_subplans(subplans, product_id="enterprise-app", original_spec="")
        self.assertIsInstance(dag, ArchitecturePlanDAG)
        self.assertEqual(dag.product_id, "enterprise-app")
        self.assertTrue(dag.requires_vpc)
        # Deduplicated: 2 unique infra tasks (INFRA-ING-01 deduplicated, INFRA-DATA-01 added)
        self.assertEqual(len(dag.infra_tasks), 2)
        # 2 code tasks
        self.assertEqual(len(dag.code_tasks), 2)
        # Sequenced build plan present
        self.assertIsNotNone(dag.sequenced_build_plan)
        self.assertEqual(dag.sequenced_build_plan.total_steps, 7)


if __name__ == "__main__":
    unittest.main()

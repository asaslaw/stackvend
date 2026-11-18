"""
Unit tests for Implementation Plan 04: Firestore Query Guardrails & Automated Composite Index Generation.
Verifies the AST scanner, index requirement rules, Single-Generator HCL and JSON generation,
and Developer Agent workflow integration.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import json
import os
import sys
import unittest

import pytest
from unittest.mock import MagicMock, patch

# Ensure mocks for third-party libs if not installed in host environment
for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'fastapi.staticfiles', 'google', 'google.genai',
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

from developer_agent.firestore_scanner import (
    FirestoreFieldSpec,
    FirestoreIndexRequirement,
    scan_firestore_queries,
    scan_firestore_queries_in_code,
)
from developer_agent.terraform_engine import (
    generate_firestore_indexes_json,
    generate_golden_indexes_tf,
)
from developer_agent.handler import DeveloperAgent


class TestFirestoreScannerAndIndexGenerator(unittest.TestCase):

    def test_single_equality_no_composite_index(self):
        """Single equality filter does not require a composite index."""
        code = """
def get_user(db, user_id):
    return db.collection("users").where("user_id", "==", user_id).stream()
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 0)

    def test_multi_equality_no_composite_index_zigzag(self):
        """Multi-equality filter does NOT require a composite index (Firestore zigzag merge)."""
        code = """
def find_users(db, org_id, role, status):
    return db.collection("users").where("org_id", "==", org_id).where("role", "==", role).where("status", "==", status).stream()
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 0, "Multi-equality queries should not produce false positive composite indexes.")

    def test_single_order_by_no_composite_index(self):
        """Single order_by does not require a composite index."""
        code = """
def list_recent(db):
    return db.collection("audit_logs").order_by("timestamp", direction="DESCENDING").stream()
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 0)

    def test_single_inequality_no_composite_index(self):
        """Single inequality does not require a composite index."""
        code = """
def list_adults(db):
    return db.collection("people").where("age", ">=", 18).stream()
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 0)

    def test_equality_and_order_by_compound_index(self):
        """Equality + order_by on different fields strictly requires a composite index."""
        code = """
def list_user_orders(db, uid):
    return db.collection("orders").where("user_id", "==", uid).order_by("created_at", "DESCENDING").stream()
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 1)
        req = reqs[0]
        self.assertEqual(req.collection_id, "orders")
        self.assertEqual(req.query_scope, "COLLECTION")
        self.assertEqual(len(req.fields), 2)
        self.assertEqual(req.fields[0].field_path, "user_id")
        self.assertEqual(req.fields[0].order, "ASCENDING")
        self.assertEqual(req.fields[1].field_path, "created_at")
        self.assertEqual(req.fields[1].order, "DESCENDING")

    def test_equality_and_inequality_compound_index(self):
        """Equality + inequality on different fields strictly requires a composite index."""
        code = """
def find_eligible(db, dept_id, min_score):
    return db.collection("candidates").where("department", "==", dept_id).where("score", ">=", min_score).stream()
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 1)
        req = reqs[0]
        self.assertEqual(req.collection_id, "candidates")
        self.assertEqual(len(req.fields), 2)
        self.assertEqual(req.fields[0].field_path, "department")
        self.assertEqual(req.fields[0].order, "ASCENDING")
        self.assertEqual(req.fields[1].field_path, "score")
        self.assertEqual(req.fields[1].order, "ASCENDING")

    def test_modern_field_filter_kwarg(self):
        """Modern where(filter=FieldFilter(...)) syntax is accurately parsed."""
        code = """
from google.cloud.firestore_v1.base_query import FieldFilter

def get_pending(db, cat):
    return (
        db.collection("tasks")
        .where(filter=FieldFilter("category", "==", cat))
        .order_by("priority", direction="DESCENDING")
        .stream()
    )
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 1)
        req = reqs[0]
        self.assertEqual(req.collection_id, "tasks")
        self.assertEqual(req.fields[0].field_path, "category")
        self.assertEqual(req.fields[1].field_path, "priority")
        self.assertEqual(req.fields[1].order, "DESCENDING")

    def test_modern_field_filter_direct(self):
        """Direct .filter(FieldFilter(...)) method syntax is accurately parsed."""
        code = """
def query_events(db, tenant):
    return (
        db.collection("events")
        .filter(FieldFilter("tenant_id", "==", tenant))
        .order_by("timestamp")
        .stream()
    )
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 1)
        req = reqs[0]
        self.assertEqual(req.collection_id, "events")
        self.assertEqual(req.fields[0].field_path, "tenant_id")
        self.assertEqual(req.fields[1].field_path, "timestamp")
        self.assertEqual(req.fields[1].order, "ASCENDING")

    def test_collection_group_query(self):
        """db.collection_group() emits query_scope = 'COLLECTION_GROUP'."""
        code = """
def get_all_items(db, store_id):
    return (
        db.collection_group("inventory")
        .where("store_id", "==", store_id)
        .order_by("sku")
        .stream()
    )
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 1)
        req = reqs[0]
        self.assertEqual(req.collection_id, "inventory")
        self.assertEqual(req.query_scope, "COLLECTION_GROUP")

    def test_array_contains_filter(self):
        """array_contains filter emits mode='ARRAY' and order='CONTAINS'."""
        code = """
def get_tagged_posts(db, tag):
    return (
        db.collection("posts")
        .where("tags", "array_contains", tag)
        .order_by("published_at", direction="DESCENDING")
        .stream()
    )
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 1)
        req = reqs[0]
        self.assertEqual(req.fields[0].field_path, "tags")
        self.assertEqual(req.fields[0].mode, "ARRAY")
        self.assertEqual(req.fields[0].order, "CONTAINS")
        self.assertEqual(req.fields[1].field_path, "published_at")
        self.assertEqual(req.fields[1].order, "DESCENDING")

    def test_multiple_order_by(self):
        """Multiple order_by calls across different fields require a composite index."""
        code = """
def get_leaderboard(db):
    return db.collection("players").order_by("league", "ASC").order_by("points", "DESC").stream()
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 1)
        req = reqs[0]
        self.assertEqual(len(req.fields), 2)
        self.assertEqual(req.fields[0].field_path, "league")
        self.assertEqual(req.fields[0].order, "ASCENDING")
        self.assertEqual(req.fields[1].field_path, "points")
        self.assertEqual(req.fields[1].order, "DESCENDING")

    def test_multiple_inequalities(self):
        """Multiple range/inequality filters on different fields require a composite index."""
        code = """
def search_range(db, min_p, max_w):
    return db.collection("products").where("price", ">=", min_p).where("weight", "<=", max_w).stream()
"""
        reqs = scan_firestore_queries_in_code(code)
        self.assertEqual(len(reqs), 1)
        req = reqs[0]
        self.assertEqual(len(req.fields), 2)
        self.assertEqual(req.fields[0].field_path, "price")
        self.assertEqual(req.fields[1].field_path, "weight")

    def test_deduplication_and_test_file_skip(self):
        """Deduplicates queries across files and ignores test files."""
        files = {
            "apps/order_svc/main.py": """
def q1(db, uid):
    return db.collection("orders").where("user_id", "==", uid).order_by("created_at").stream()
""",
            "apps/order_svc/routes.py": """
def q2(db, uid):
    return db.collection("orders").where("user_id", "==", uid).order_by("created_at").stream()
""",
            "tests/test_mock_queries.py": """
def test_mock(db, uid):
    # Should be ignored by scan_firestore_queries
    return db.collection("ignored_coll").where("foo", "==", "bar").order_by("baz").stream()
""",
        }
        reqs = scan_firestore_queries(files)
        self.assertEqual(len(reqs), 1, "Duplicate queries should be collapsed into a single index.")
        self.assertEqual(reqs[0].collection_id, "orders")

    def test_generate_golden_indexes_tf(self):
        """Tests deterministic HCL generation for Terraform with module.foundation dependency."""
        reqs = [
            FirestoreIndexRequirement(
                collection_id="orders",
                query_scope="COLLECTION",
                fields=[
                    FirestoreFieldSpec(field_path="user_id", mode="ORDER", order="ASCENDING"),
                    FirestoreFieldSpec(field_path="created_at", mode="ORDER", order="DESCENDING"),
                ],
            ),
            FirestoreIndexRequirement(
                collection_id="articles",
                query_scope="COLLECTION_GROUP",
                fields=[
                    FirestoreFieldSpec(field_path="tags", mode="ARRAY", order="CONTAINS"),
                    FirestoreFieldSpec(field_path="view_count", mode="ORDER", order="DESCENDING"),
                ],
            ),
        ]

        # 1. Empty requirements return None
        self.assertIsNone(generate_golden_indexes_tf([]))

        # 2. Non-empty generates valid HCL
        hcl = generate_golden_indexes_tf(reqs)
        self.assertIsNotNone(hcl)
        self.assertIn('resource "google_firestore_index" "idx_orders_user_id_created_at"', hcl)
        self.assertIn('resource "google_firestore_index" "idx_articles_tags_view_count"', hcl)
        self.assertIn('depends_on = [module.foundation]', hcl)
        self.assertIn('collection  = "orders"', hcl)
        self.assertIn('query_scope = "COLLECTION"', hcl)
        self.assertIn('collection  = "articles"', hcl)
        self.assertIn('query_scope = "COLLECTION_GROUP"', hcl)
        self.assertIn('array_config = "CONTAINS"', hcl)
        self.assertIn('order      = "DESCENDING"', hcl)

    def test_generate_firestore_indexes_json(self):
        """Tests deterministic firestore.indexes.json generation."""
        reqs = [
            FirestoreIndexRequirement(
                collection_id="orders",
                query_scope="COLLECTION",
                fields=[
                    FirestoreFieldSpec(field_path="user_id", mode="ORDER", order="ASCENDING"),
                    FirestoreFieldSpec(field_path="created_at", mode="ORDER", order="DESCENDING"),
                ],
            ),
            FirestoreIndexRequirement(
                collection_id="articles",
                query_scope="COLLECTION",
                fields=[
                    FirestoreFieldSpec(field_path="tags", mode="ARRAY", order="CONTAINS"),
                    FirestoreFieldSpec(field_path="score", mode="ORDER", order="ASCENDING"),
                ],
            ),
        ]

        json_str = generate_firestore_indexes_json(reqs)
        parsed = json.loads(json_str)
        self.assertIn("indexes", parsed)
        self.assertEqual(len(parsed["indexes"]), 2)
        self.assertEqual(parsed["indexes"][0]["collectionGroup"], "orders")
        self.assertEqual(parsed["indexes"][0]["queryScope"], "COLLECTION")
        self.assertEqual(parsed["indexes"][0]["fields"][0], {"fieldPath": "user_id", "order": "ASCENDING"})
        self.assertEqual(parsed["indexes"][0]["fields"][1], {"fieldPath": "created_at", "order": "DESCENDING"})
        self.assertEqual(parsed["indexes"][1]["fields"][0], {"fieldPath": "tags", "arrayConfig": "CONTAINS"})
        self.assertEqual(parsed["indexes"][1]["fields"][1], {"fieldPath": "score", "order": "ASCENDING"})
        self.assertEqual(parsed["fieldOverrides"], [])

    def test_developer_agent_integration(self):
        """Verifies DeveloperAgent.generate_code_files automatically produces indexes.tf and firestore.indexes.json."""
        from _lane19_fake_genai import FakeGenaiClient
        agent = DeveloperAgent()

        compound_code = """
from fastapi import FastAPI
from google.cloud import firestore

app = FastAPI()
db = firestore.Client()

@app.get("/items")
def list_items(category: str):
    return list(db.collection("catalog").where("category", "==", category).order_by("price", direction="DESCENDING").stream())
"""
        # FD-05 B-3: this test (09-07) predates the developer swarm (09-23). Index generation runs on every
        # generation path (handler.generate_code_files), so pin the single-turn LLM path with a fake model (lane 19
        # L19-3b: the template scaffold is deleted, owner row 27a). The no-client case is covered by
        # test_swarm_without_genai_client_fails_loudly (FD-4C, fixed by 27a).
        agent.genai_client = FakeGenaiClient(files={
            "apps/catalog-svc/main.py": compound_code,
            "apps/catalog-svc/requirements.txt": "fastapi\n",
            "apps/catalog-svc/Procfile": "web: uvicorn main:app --port 8080\n",
            "apps/catalog-svc/.python-version": "3.13\n",
        })
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(agent, "fetch_existing_repo_files", return_value={}):
            files = agent.generate_code_files(
                product_id="catalog-svc",
                spec_text="Catalog service with sorted product queries",
                task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
            )

            self.assertIn("infra/workload/indexes.tf", files)
            self.assertIn("apps/catalog-svc/firestore.indexes.json", files)

            indexes_tf = files["infra/workload/indexes.tf"]
            self.assertIn('resource "google_firestore_index"', indexes_tf)
            self.assertIn('collection  = "catalog"', indexes_tf)
            self.assertIn('depends_on = [module.foundation]', indexes_tf)

            indexes_json = files["apps/catalog-svc/firestore.indexes.json"]
            parsed_json = json.loads(indexes_json)
            self.assertEqual(parsed_json["indexes"][0]["collectionGroup"], "catalog")
            self.assertEqual(parsed_json["indexes"][0]["fields"][0]["fieldPath"], "category")
            self.assertEqual(parsed_json["indexes"][0]["fields"][1]["fieldPath"], "price")
            self.assertEqual(parsed_json["indexes"][0]["fields"][1]["order"], "DESCENDING")

    def test_rt14_08_injected_collection_id_stops_the_build_typed(self):
        """RT14-08: app code whose collection id would close the HCL string in indexes.tf stops the developer stage
        with DeveloperStageError(FIRESTORE_INDEX_ID_INVALID); no indexes.tf with an added resource is returned."""
        from _lane19_fake_genai import FakeGenaiClient
        from developer_agent.errors import DeveloperStageError
        agent = DeveloperAgent()
        injected = 'orders\\"\\n}\\nresource \\"google_storage_bucket_iam_member\\" \\"x\\" {\\n  bucket = \\"b'
        code = ("from google.cloud import firestore\n\ndb = firestore.Client()\n\n"
                "def items(category):\n"
                f"    return list(db.collection(\"{injected}\").where(\"category\", \"==\", category)"
                ".order_by(\"price\", direction=\"DESCENDING\").stream())\n")
        agent.genai_client = FakeGenaiClient(files={
            "apps/catalog-svc/main.py": code,
            "apps/catalog-svc/requirements.txt": "fastapi\n",
            "apps/catalog-svc/Procfile": "web: uvicorn main:app --port 8080\n",
            "apps/catalog-svc/.python-version": "3.13\n",
        })
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(agent, "fetch_existing_repo_files", return_value={}):
            with self.assertRaises(DeveloperStageError) as ctx:
                agent.generate_code_files(
                    product_id="catalog-svc", spec_text="Catalog service with sorted product queries",
                    task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
        self.assertEqual(ctx.exception.error_class, "FIRESTORE_INDEX_ID_INVALID")

    # FD-4C (D-2) fixed by lane 19 L19-3a (owner register row 27a): the strict xfail marker is removed.
    def test_swarm_without_genai_client_fails_loudly(self):
        """Outside TEST_MODE, a missing LLM client must fail code generation, never commit stub code."""
        env = {k: v for k, v in os.environ.items() if k != "TEST_MODE"}
        env["ENABLE_DEVELOPER_SWARM"] = "true"
        with patch.dict(os.environ, env, clear=True):
            agent = DeveloperAgent()
            agent.genai_client = None
            with patch.object(agent, "fetch_existing_repo_files", return_value={}):
                try:
                    files = agent.generate_code_files(
                        product_id="catalog-svc",
                        spec_text="Catalog service with sorted product queries",
                        task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
                    )
                except (AttributeError, TypeError, NameError, LookupError, ImportError):
                    raise  # a crash is not fail-closed
                except Exception as e:
                    self.assertEqual(getattr(e, "error_class", None), "LLM_UNAVAILABLE")
                    return  # fail-closed: the desired behaviour
        stub_markers = ("# Auto-generated module by Junior Specialist", "# Auto-generated infrastructure module")
        stubbed = sorted(k for k, v in (files or {}).items() if isinstance(v, str) and v.startswith(stub_markers))
        self.assertFalse(files, f"code generation without an LLM client returned files (stubs: {stubbed[:5]})")


if __name__ == "__main__":
    unittest.main()

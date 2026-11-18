"""
Project Castor: Centralized VPC CIDR IPAM Ledger Unit Tests
Verifies mathematical disjoint calculations, sequential allocation, decommission preservation,
redeployment reclamation, multi-folder promotion uniqueness, and Control Center topology visualization.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
vending_dir = os.path.join(repo_root, "apps", "project-vending")
sys.path.insert(0, repo_root)
sys.path.insert(0, cc_dir)
sys.path.insert(0, vending_dir)

# Mock external cloud clients and frameworks before imports
for mod in [
    "google", "google.auth", "google.auth.transport", "google.auth.transport.requests",
    "google.oauth2", "google.oauth2.id_token", "googleapiclient", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.logging",
    "google.cloud.logging_v2", "google.cloud.pubsub_v1", "starlette", "starlette.middleware",
    "starlette.middleware.base"
]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()

# Mock Pydantic if not present
try:
    import pydantic
except ImportError:
    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None, **kwargs):
            self.default = default
            self.default_factory = default_factory
        def get_value(self):
            if self.default_factory is not None:
                return self.default_factory()
            return self.default

    class MockBaseModel:
        def __init__(self, **kwargs):
            for cls in reversed(self.__class__.__mro__):
                for k, v in cls.__dict__.items():
                    if not k.startswith('_') and not callable(v):
                        default_val = v.get_value() if isinstance(v, MockFieldInfo) else v
                        if default_val is not Ellipsis:
                            setattr(self, k, default_val)
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self):
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith('_'):
                    if hasattr(v, 'model_dump'):
                        res[k] = v.model_dump()
                    elif isinstance(v, list):
                        res[k] = [item.model_dump() if hasattr(item, 'model_dump') else item for item in v]
                    elif isinstance(v, dict):
                        res[k] = {ik: (iv.model_dump() if hasattr(iv, 'model_dump') else iv) for ik, iv in v.items()}
                    else:
                        res[k] = v
            return res

        def dict(self):
            return self.model_dump()

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default=default, default_factory=default_factory)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

# Load Control Center schemas
_cc_schemas_spec = importlib.util.spec_from_file_location("cc_schemas", os.path.join(cc_dir, "schemas.py"))
cc_schemas = importlib.util.module_from_spec(_cc_schemas_spec)
sys.modules["schemas"] = cc_schemas
_cc_schemas_spec.loader.exec_module(cc_schemas)

# Load Settings
_settings_spec = importlib.util.spec_from_file_location("shared_settings", os.path.join(repo_root, "shared", "settings.py"))
shared_settings = importlib.util.module_from_spec(_settings_spec)
sys.modules["shared.settings"] = shared_settings
_settings_spec.loader.exec_module(shared_settings)
PlatformSettings = shared_settings.PlatformSettings
OrchestrationSettings = shared_settings.OrchestrationSettings

# Load IPAM
_ipam_spec = importlib.util.spec_from_file_location("shared_ipam", os.path.join(repo_root, "shared", "ipam.py"))
shared_ipam = importlib.util.module_from_spec(_ipam_spec)
sys.modules["shared.ipam"] = shared_ipam
_ipam_spec.loader.exec_module(shared_ipam)
CastorIPAMEngine = shared_ipam.CastorIPAMEngine
CidrAllocationRecord = shared_ipam.CidrAllocationRecord
CidrStatus = shared_ipam.CidrStatus

from ipam_fake_firestore import FakeFirestore, fake_transactional  # noqa: E402  (tests/ helper)

# Load Diagram Engine
_diagram_spec = importlib.util.spec_from_file_location("cc_diagram", os.path.join(cc_dir, "diagram.py"))
cc_diagram = importlib.util.module_from_spec(_diagram_spec)
sys.modules["diagram"] = cc_diagram
_diagram_spec.loader.exec_module(cc_diagram)
ArchitectureDiagramEngine = cc_diagram.ArchitectureDiagramEngine


class MockFirestoreDoc:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data

    def to_dict(self):
        return dict(self._data)

    @property
    def exists(self):
        return self._data is not None


class MockFirestoreCollection:
    def __init__(self, storage, coll_name):
        self._storage = storage
        self._coll_name = coll_name

    def document(self, doc_id):
        return MockFirestoreDocRef(self._storage, self._coll_name, doc_id)

    def stream(self):
        coll_data = self._storage.get(self._coll_name, {})
        for k, v in coll_data.items():
            yield MockFirestoreDoc(k, v)

    def where(self, field, op, value):
        class FilteredStream:
            def __init__(self, storage, coll_name, f, val):
                self._storage = storage
                self._coll_name = coll_name
                self._field = f
                self._val = val

            def stream(self):
                coll_data = self._storage.get(self._coll_name, {})
                for k, v in coll_data.items():
                    if v and v.get(self._field) == self._val:
                        yield MockFirestoreDoc(k, v)

        return FilteredStream(self._storage, self._coll_name, field, value)


class MockFirestoreDocRef:
    def __init__(self, storage, coll_name, doc_id):
        self._storage = storage
        self._coll_name = coll_name
        self._doc_id = doc_id

    def get(self):
        coll_data = self._storage.get(self._coll_name, {})
        data = coll_data.get(self._doc_id)
        return MockFirestoreDoc(self._doc_id, data)

    def set(self, data, merge=False):
        if self._coll_name not in self._storage:
            self._storage[self._coll_name] = {}
        if merge and self._doc_id in self._storage[self._coll_name]:
            self._storage[self._coll_name][self._doc_id].update(data)
        else:
            self._storage[self._coll_name][self._doc_id] = dict(data)

    def delete(self):
        if self._coll_name in self._storage and self._doc_id in self._storage[self._coll_name]:
            del self._storage[self._coll_name][self._doc_id]


class MockFirestoreClient:
    def __init__(self):
        self._storage = {}

    def collection(self, coll_name):
        return MockFirestoreCollection(self._storage, coll_name)


class TestIPAMEngine(unittest.TestCase):
    def setUp(self):
        # Row IPAM-1: allocation runs in a Firestore transaction; the in-memory fake implements that contract. The
        # expected ranges below are unchanged from the pre-transaction engine (Do No Harm).
        self.mock_db = FakeFirestore()
        self.engine = CastorIPAMEngine(db=self.mock_db, supernet_cidr="10.100.0.0/16", transactional=fake_transactional)

    def test_mathematical_overlap_detection(self):
        """Test that adjacent vs overlapping subnets are accurately evaluated."""
        rec1 = CidrAllocationRecord(
            cidr_block="10.100.0.0/28",
            sanitized_id="10_100_0_0_28",
            product_id="service-a",
            status=CidrStatus.ALLOCATED,
        )
        # Adjacent subnets: no overlap
        overlaps, conflict = self.engine.check_overlap("10.100.0.16/28", existing_records=[rec1])
        self.assertFalse(overlaps)
        self.assertIsNone(conflict)

        # Enclosing subnets (/24 enclosing /28)
        overlaps_enclosed, conflict_enclosed = self.engine.check_overlap("10.100.0.0/24", existing_records=[rec1])
        self.assertTrue(overlaps_enclosed)
        self.assertEqual(conflict_enclosed.product_id, "service-a")

        # Exact collision
        overlaps_exact, conflict_exact = self.engine.check_overlap("10.100.0.0/28", existing_records=[rec1])
        self.assertTrue(overlaps_exact)

    def test_sequential_disjoint_allocation(self):
        """Test allocating consecutive /28 blocks without collision."""
        alloc1 = self.engine.allocate_next_cidr("service-alpha", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
        alloc2 = self.engine.allocate_next_cidr("service-beta", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
        alloc3 = self.engine.allocate_next_cidr("service-gamma", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)

        self.assertEqual(alloc1.cidr_block, "10.100.0.0/28")
        self.assertEqual(alloc2.cidr_block, "10.100.0.16/28")
        self.assertEqual(alloc3.cidr_block, "10.100.0.32/28")
        self.assertNotEqual(alloc1.cidr_block, alloc2.cidr_block)
        self.assertNotEqual(alloc2.cidr_block, alloc3.cidr_block)

    def test_decommission_preserves_reservation_preventing_poaching(self):
        """Test that decommissioning preserves CIDR as RESERVED_DECOMMISSIONED so new workloads cannot claim it."""
        alloc_a = self.engine.allocate_next_cidr("billing-api", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
        self.assertEqual(alloc_a.cidr_block, "10.100.0.0/28")

        count = self.engine.mark_workload_decommissioned("billing-api", operator_email="admin@castor.org")
        self.assertEqual(count, 1)

        records = self.engine.list_allocations(include_decommissioned=True)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, CidrStatus.RESERVED_DECOMMISSIONED)

        # Workload B requests allocation: MUST NOT receive billing-api's preserved CIDR
        alloc_b = self.engine.allocate_next_cidr("inventory-api", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
        self.assertEqual(alloc_b.cidr_block, "10.100.0.16/28")
        self.assertNotEqual(alloc_b.cidr_block, alloc_a.cidr_block)

    def test_redeploy_reclaims_original_cidr(self):
        """Test that redeploying a decommissioned workload reclaims its exact original CIDR."""
        self.engine.allocate_next_cidr("payment-gateway", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
        self.engine.mark_workload_decommissioned("payment-gateway", operator_email="admin@castor.org")

        reclaimed = self.engine.reclaim_workload_cidrs("payment-gateway", new_project_id="castor-payment-v2")
        self.assertEqual(len(reclaimed), 1)
        self.assertEqual(reclaimed[0].cidr_block, "10.100.0.0/28")
        self.assertEqual(reclaimed[0].status, CidrStatus.ALLOCATED)
        self.assertEqual(reclaimed[0].project_id, "castor-payment-v2")

    def test_multi_folder_promotion_allocates_unique_cidr(self):
        """Test that promoting a workload to a new folder assigns a distinct non-overlapping CIDR."""
        dev_alloc = self.engine.allocate_next_cidr(
            "order-service",
            purpose="SERVERLESS_VPC_CONNECTOR",
            prefix_len=28,
            folder_id="folders/111111",
        )
        self.assertEqual(dev_alloc.cidr_block, "10.100.0.0/28")

        prod_alloc = self.engine.allocate_next_cidr(
            "order-service-prod",
            purpose="SERVERLESS_VPC_CONNECTOR",
            prefix_len=28,
            folder_id="folders/222222",
        )
        self.assertEqual(prod_alloc.cidr_block, "10.100.0.16/28")
        self.assertNotEqual(dev_alloc.cidr_block, prod_alloc.cidr_block)

    def test_permanent_purge_releases_cidr(self):
        """Test that permanent workload purge releases the CIDR back to the pool."""
        alloc = self.engine.allocate_next_cidr("temp-sandbox", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
        self.assertEqual(alloc.cidr_block, "10.100.0.0/28")

        released_count = self.engine.release_workload_cidrs("temp-sandbox", operator_email="admin@castor.org")
        self.assertEqual(released_count, 1)

        new_alloc = self.engine.allocate_next_cidr("new-service", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
        self.assertEqual(new_alloc.cidr_block, "10.100.0.0/28")

    def test_pool_statistics(self):
        """Test IPAM pool utilization calculations."""
        self.engine.allocate_next_cidr("svc-1", prefix_len=28)
        self.engine.allocate_next_cidr("svc-2", prefix_len=28)
        self.engine.mark_workload_decommissioned("svc-2")

        stats = self.engine.get_pool_statistics()
        self.assertEqual(stats["supernet_cidr"], "10.100.0.0/16")
        self.assertEqual(stats["total_capacity_slash_28"], 4096)
        self.assertEqual(stats["allocated_count"], 1)
        self.assertEqual(stats["reserved_decommissioned_count"], 1)
        self.assertEqual(stats["available_count"], 4094)
        self.assertGreater(stats["utilization_pct"], 0.0)

    def test_settings_has_ipam_fields(self):
        """Verify OrchestrationSettings defines IPAM fields."""
        orch = OrchestrationSettings()
        self.assertEqual(orch.ipam_supernet_cidr, "10.100.0.0/16")
        self.assertEqual(orch.ipam_connector_prefix, 28)
        self.assertEqual(orch.ipam_subnet_prefix, 24)

    def test_control_center_diagram_renders_vpc_perimeter(self):
        """Verify ArchitectureDiagramEngine renders Network subgraph when VPC is detected."""
        engine = ArchitectureDiagramEngine()
        res = engine.generate_mermaid_diagram(
            product_id="payment-service",
            workload_data={
                "project_id": "castor-payment",
                "status": "ACTIVE",
                "network": {
                    "connector_cidr": "10.100.5.0/28",
                    "vpc_name": "vpc-payment-service",
                },
            },
            build_plan_data={},
        )
        self.assertIn("subgraph Network", res.mermaid_code)
        self.assertIn("10.100.5.0/28", res.mermaid_code)
        self.assertIn("vpc-payment-service", res.mermaid_code)
        self.assertTrue(any("Virtual Private Cloud" in b for b in res.security_boundaries))


if __name__ == "__main__":
    unittest.main(verbosity=2)

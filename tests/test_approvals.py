"""
Unit Tests for Tier 3.5 Pre-Developer HITL Governance & Rework Gateway.
Tests plan approval registration, and operator decision execution (APPROVED, REJECTED, REWORK).
"""

import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")

sys.path.insert(0, REPO_ROOT)
sys.path.insert(1, GATEWAY_DIR)
sys.path.insert(2, CC_DIR)

# Ensure mocks for third-party libs if not installed in host environment
try:
    import pydantic
except ImportError:
    class MockBaseModel:
        def __init__(self, **kwargs):
            for k, v in self.__class__.__dict__.items():
                if not k.startswith('_') and not callable(v):
                    default_val = getattr(v, 'default', v)
                    if default_val is not Ellipsis:
                        setattr(self, k, default_val)
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default if default is not None else (default_factory() if default_factory else None)

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default, default_factory)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

class MockHTTPException(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{status_code}: {detail}")

def mock_decorator(*args, **kwargs):
    def inner(fn):
        return fn
    return inner

mock_app = MagicMock()
mock_app.get = mock_decorator
mock_app.post = mock_decorator
mock_app.put = mock_decorator
mock_app.delete = mock_decorator
mock_app.patch = mock_decorator

mock_fastapi = MagicMock()
mock_fastapi.HTTPException = MockHTTPException
mock_fastapi.FastAPI = lambda *args, **kwargs: mock_app
mock_fastapi.Request = MagicMock
mock_fastapi.Response = MagicMock
sys.modules["fastapi"] = mock_fastapi

mock_google = sys.modules.get('google') or MagicMock()
mock_google_auth = sys.modules.get('google.auth') or MagicMock()
mock_google_auth_transport = sys.modules.get('google.auth.transport') or MagicMock()
mock_google_auth_transport_requests = sys.modules.get('google.auth.transport.requests') or MagicMock()
mock_google_cloud = sys.modules.get('google.cloud') or MagicMock()
mock_firestore = sys.modules.get('google.cloud.firestore') or MagicMock()

mock_google.auth = mock_google_auth
mock_google.auth.transport = mock_google_auth_transport
mock_google.auth.transport.requests = mock_google_auth_transport_requests
mock_google.cloud = mock_google_cloud
mock_google_cloud.firestore = mock_firestore

sys.modules.setdefault('google', mock_google)
sys.modules.setdefault('google.auth', mock_google_auth)
sys.modules.setdefault('google.auth.transport', mock_google_auth_transport)
sys.modules.setdefault('google.auth.transport.requests', mock_google_auth_transport_requests)
sys.modules.setdefault('google.cloud', mock_google_cloud)
sys.modules.setdefault('google.cloud.firestore', mock_firestore)

for m in [
    'httpx', 'fastapi.responses', 'fastapi.staticfiles',
    'google.oauth2', 'google.oauth2.id_token', 'googleapiclient',
    'google.genai', 'google.genai.types',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.logging_v2',
    'google.cloud.pubsub_v1', 'starlette', 'starlette.middleware', 'starlette.middleware.base',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

# Import gateway main
gw_spec = importlib.util.spec_from_file_location(
    "gw_main", os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "main.py")
)
gw_main = importlib.util.module_from_spec(gw_spec)
gw_spec.loader.exec_module(gw_main)

# Import control-center main
cc_spec = importlib.util.spec_from_file_location(
    "cc_main", os.path.join(REPO_ROOT, "apps", "control-center", "main.py")
)
cc_main = importlib.util.module_from_spec(cc_spec)
cc_spec.loader.exec_module(cc_main)

# Import schemas
schemas_spec = importlib.util.spec_from_file_location(
    "cc_schemas", os.path.join(REPO_ROOT, "apps", "control-center", "schemas.py")
)
cc_schemas = importlib.util.module_from_spec(schemas_spec)
schemas_spec.loader.exec_module(cc_schemas)

ApprovalDecisionRequest = cc_schemas.ApprovalDecisionRequest
ApprovalStatus = cc_schemas.ApprovalStatus
ApprovalType = cc_schemas.ApprovalType


class TestApprovalsWorkflow(unittest.TestCase):
    def setUp(self):
        self.mock_db = MagicMock()
        gw_main.db = self.mock_db
        cc_main.db = self.mock_db
        mock_firestore.Client.return_value = self.mock_db

    def test_gateway_register_plan_approval_request(self):
        """Verifies Step 2.5 registers ARCHITECTURAL_PLAN approval request in Firestore."""
        req = gw_main.PlanApprovalRequest(
            trace_id="trace-123",
            product_id="test-product",
            callback_url="https://workflow.googleapis.com/callback/123",
            plan_markdown="# Architecture Plan\n...",
            plan_file_path="docs/architecture.md",
            task_dag=[{"step_id": "STEP-01"}],
            cost_delta_monthly=45.0,
            compliance_summary="Protected by IAP",
            rework_cycle=0,
        )
        res = gw_main.register_plan_approval_request(req)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertTrue(res["approval_id"].startswith("plan-test-product-"))

        # Check firestore set was called
        self.mock_db.collection.assert_any_call("approval_requests")
        self.mock_db.collection.assert_any_call("pipeline_executions")

    def _forbid_token_minting(self):
        """FD-4N / lane-6 hermeticity: the approvals path must NEVER mint a credential in tests (or for an unvalidated
        callback). Any call to google.auth.default / AuthorizedSession fails the test."""
        ga = sys.modules.get("google.auth")
        gatr = sys.modules.get("google.auth.transport.requests")
        boom = MagicMock(side_effect=AssertionError("credential minting attempted"))
        patches = []
        if ga is not None:
            patches.append(patch.object(ga, "default", boom))
        if gatr is not None:
            patches.append(patch.object(gatr, "AuthorizedSession", boom, create=True))
        for pt in patches:
            pt.start()
            self.addCleanup(pt.stop)
        return boom

    def _decide_expect_error(self, approval_id, req, mock_request):
        with self.assertRaises(Exception) as ctx:
            cc_main.decide_approval_request(approval_id, req, mock_request)
        return ctx.exception

    def test_control_center_decide_approval_approved(self):
        """APPROVED on a plan approval: until lane 3's callback validator ships, delivery FAILS CLOSED (no token is
        minted, nothing is sent) and the record becomes CALLBACK_FAILED (re-decidable), answered 502."""
        boom = self._forbid_token_minting()
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "approval_id": "plan-123",
            "approval_type": "ARCHITECTURAL_PLAN",
            "product_id": "test-product",
            "trace_id": "trace-123",
            "status": "PENDING",
            "callback_url": "https://workflowexecutions.googleapis.com/v1/projects/p/locations/l/workflows/w/executions/e/callbacks/c",
        }
        self.mock_db.collection().document().get.return_value = mock_doc

        req = ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED, reason="Architecture blueprint approved")
        mock_request = MagicMock()
        mock_request.state.user_email = "approver@example.com"
        mock_request.state.user_role = "ADMIN"

        exc = self._decide_expect_error("plan-123", req, mock_request)
        self.assertEqual(getattr(exc, "status_code", None), 502)
        self.assertIn("CALLBACK_FAILED", str(getattr(exc, "detail", exc)))
        boom.assert_not_called()
        final_writes = [c.args[0] for c in self.mock_db.collection().document().set.call_args_list if c.args]
        self.assertEqual(final_writes[0]["status"], "DECIDING")
        self.assertEqual(final_writes[-1]["status"], "CALLBACK_FAILED")
        self.assertEqual(final_writes[-1]["pending_decision"], "APPROVED")

    def test_control_center_decide_approval_rework(self):
        """REWORK delivers through the same fail-closed callback path: no token, CALLBACK_FAILED, 502."""
        boom = self._forbid_token_minting()
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "approval_id": "plan-123",
            "approval_type": "ARCHITECTURAL_PLAN",
            "product_id": "test-product",
            "trace_id": "trace-123",
            "status": "PENDING",
            "callback_url": "https://attacker.example/steal-token",
            "rework_cycle": 0,
        }
        self.mock_db.collection().document().get.return_value = mock_doc

        req = ApprovalDecisionRequest(
            decision=ApprovalStatus.REWORK,
            feedback="Route egress through central Shared VPC instead of Cloud NAT.",
        )
        mock_request = MagicMock()
        mock_request.state.user_email = "architect-lead@example.com"
        mock_request.state.user_role = "ADMIN"

        exc = self._decide_expect_error("plan-123", req, mock_request)
        self.assertEqual(getattr(exc, "status_code", None), 502)
        boom.assert_not_called()
        final = [c.args[0] for c in self.mock_db.collection().document().set.call_args_list if c.args][-1]
        self.assertEqual(final["status"], "CALLBACK_FAILED")
        self.assertEqual(final["pending_decision"], "REWORK")

    def test_control_center_index_page_renders_successfully(self):
        """Verifies index_page renders without f-string formatting or NameError exceptions and includes plan approval UI."""
        mock_request = MagicMock()
        mock_request.state.user_email = "admin@example.com"
        mock_request.state.user_role = "ADMIN"
        html = cc_main.index_page(mock_request)
        self.assertIsInstance(html, str)
        self.assertIn("StackVend", html)
        self.assertIn("Architecture Plan Blueprint", html)
        self.assertIn("renderMarkdown", html)
        # Verify Plan Approval UI controls
        self.assertIn("platformSettings.governance.require_plan_approval", html)
        self.assertIn("platformSettings.governance.plan_approval_policy", html)
        self.assertIn("newWorkloadForm.require_plan_approval", html)
        self.assertIn("toggleWorkloadPolicy('require_plan_approval'", html)
        self.assertIn("Plan Approval (HITL)", html)
        self.assertIn("approvalsFilter", html)
        self.assertIn("filteredApprovals", html)

    def test_workload_policies_plan_approval_toggle(self):
        """Verifies GET and PATCH /api/workloads/{product_id}/policies handles require_plan_approval."""
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "test-app",
            "require_plan_approval": True,
            "code_freeze": False,
        }
        mock_coll = MagicMock()
        mock_coll.document.return_value = mock_doc
        mock_db = MagicMock()
        mock_db.collection.return_value = mock_coll

        orig_db = cc_main.db
        try:
            cc_main.db = mock_db
            policies = cc_main.get_workload_policies("test-app")
            self.assertTrue(policies.get("require_plan_approval"))

            mock_request = MagicMock()
            mock_request.state.user_email = "admin@example.com"
            mock_request.state.user_role = "ADMIN"
            req = cc_main.UpdateWorkloadPoliciesRequest(require_plan_approval=False)
            res = cc_main.update_workload_policies("test-app", req, mock_request)
            self.assertEqual(res["status"], "UPDATED")
            self.assertEqual(res["policies"]["require_plan_approval"], False)
            mock_doc.set.assert_called_with({"require_plan_approval": False}, merge=True)
        finally:
            cc_main.db = orig_db

    def test_list_pending_approvals_with_missing_and_legacy_fields(self):
        """Verifies list_pending_approvals returns legacy records missing approval_type or with PR_MERGE."""
        doc1 = MagicMock()
        doc1.id = "appr-legacy-1"
        doc1.to_dict.return_value = {
            "product_id": "test-app",
            "trace_id": "trace-1",
            "status": "APPROVED",
            "requested_at": "2026-09-10T22:00:00Z",
            "decided_at": "2026-09-10T22:05:00Z",
            "decided_by": "operator@example.com",
            # Note: NO approval_type field!
        }

        doc2 = MagicMock()
        doc2.id = "appr-legacy-2"
        doc2.to_dict.return_value = {
            "product_id": "test-app",
            "trace_id": "trace-2",
            "approval_type": "PR_MERGE",
            "status": "APPROVED",
            "created_at_iso": "2026-09-10T21:00:00Z",
        }

        doc3 = MagicMock()
        doc3.id = "appr-plan-3"
        doc3.to_dict.return_value = {
            "product_id": "test-app",
            "trace_id": "trace-3",
            "approval_type": "ARCHITECTURAL_PLAN",
            "status": "PENDING",
            "requested_at": "2026-09-11T10:00:00Z",
        }

        mock_coll = MagicMock()
        mock_coll.stream.return_value = [doc1, doc2, doc3]
        mock_db = MagicMock()
        mock_db.collection.return_value = mock_coll

        orig_db = cc_main.db
        try:
            cc_main.db = mock_db
            mock_request = MagicMock()
            mock_request.state.user_email = "admin@example.com"
            mock_request.state.user_role = "ADMIN"

            records = cc_main.list_pending_approvals(mock_request)
            self.assertEqual(len(records), 3)

            # Check sorting: doc3 is newest, then doc1, then doc2
            self.assertEqual(records[0].approval_id, "appr-plan-3")
            self.assertEqual(records[0].approval_type, ApprovalType.ARCHITECTURAL_PLAN)
            self.assertEqual(records[0].status, ApprovalStatus.PENDING)

            self.assertEqual(records[1].approval_id, "appr-legacy-1")
            self.assertEqual(records[1].approval_type, ApprovalType.PULL_REQUEST)
            self.assertEqual(records[1].status, ApprovalStatus.APPROVED)

            self.assertEqual(records[2].approval_id, "appr-legacy-2")
            self.assertEqual(records[2].approval_type, ApprovalType.PULL_REQUEST)
            self.assertEqual(records[2].status, ApprovalStatus.APPROVED)
        finally:
            cc_main.db = orig_db


class _Snap:
    def __init__(self, id_, data):
        self.id, self._d, self.exists = id_, data, data is not None

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class _Doc:
    def __init__(self, store, key):
        self.store, self.key = store, key

    def get(self, **kw):
        return _Snap(self.key[1], self.store.get(self.key))

    def set(self, data, merge=False):
        cur = self.store.get(self.key) if merge else None
        self.store[self.key] = {**(cur or {}), **data}

    def create(self, data):
        if self.key in self.store:
            raise RuntimeError("AlreadyExists")
        self.store[self.key] = dict(data)


class _Col:
    def __init__(self, store, name):
        self.store, self.name = store, name

    def document(self, doc_id):
        return _Doc(self.store, (self.name, doc_id))


class _MemDB:
    """Tiny in-memory Firestore stand-in (no network, no credentials)."""

    def __init__(self):
        self.store = {}

    def collection(self, name):
        return _Col(self.store, name)


from types import SimpleNamespace as _NS  # noqa: E402

from shared import vcs_ledger as _ledger  # noqa: E402

LEDGER_SHA = "e" * 40


def _seed_ledger(db, *, product_id="tenant-a", repo="example-org/tenant-a", branch="feature-x", pr_number=7,
                 provider="GITHUB", base_branch="main", trace_id="tr-1", repo_id=100):
    """FD-4P: the PR ledger entry the gateway writes when the developer step creates the PR."""
    return _ledger.record_created(
        db, provider=provider, repo_full_name=repo, repo_id=repo_id if provider == "GITHUB" else None,
        product_id=product_id, trace_id=trace_id, origin=_ledger.ORIGIN_DEVELOPER, branch=branch,
        base_branch=base_branch, head_sha=LEDGER_SHA, pr_number=pr_number if provider == "GITHUB" else None,
        pr_url=f"https://github.com/{repo}/pull/{pr_number}" if provider == "GITHUB" else None)


class _LiveRepo:
    """PyGithub-shaped fake for the REAL GitHubProvider (numeric ids; records every mutation)."""

    def __init__(self, pr, repo_id=100, full_name="example-org/tenant-a"):
        self.id, self.full_name, self.pr = repo_id, full_name, pr
        self.deleted_refs = []

    def get_pull(self, n):
        assert n == self.pr.number
        return self.pr

    def get_git_ref(self, name):
        repo = self
        return _NS(object=_NS(sha=LEDGER_SHA), delete=lambda: repo.deleted_refs.append(name))


def _live_pr(*, head_repo_id=100, head_ref="feature-x", head_sha=LEDGER_SHA, number=7):
    pr = MagicMock(name="live-pr")
    pr.number, pr.state, pr.merged, pr.title = number, "open", False, "t"
    pr.user = _NS(id=31337, type="Bot")  # RT M1: opened by the platform identity
    pr.head = _NS(ref=head_ref, sha=head_sha, repo=_NS(id=head_repo_id, full_name="example-org/tenant-a"))
    pr.base = _NS(ref="main", repo=_NS(id=100, full_name="example-org/tenant-a"))
    pr.merge.return_value = _NS(merged=True, sha="m" * 40, message="ok")
    return pr


def _real_github_provider(live_repo):
    from shared.providers.github_provider import GitHubProvider

    prov = GitHubProvider(project_id="", github_token="test-token", default_owner="example-org")
    prov._get_repo = lambda _ident: live_repo
    prov.actor_identity = lambda: (31337, "Bot")  # RT M1 (resolution itself: tests/test_pr_integrity_ledger.py)
    return prov


class TestHitlMergeSafety(unittest.TestCase):
    """FD-4N red-team B4/B6/H4/H6 + the Wave 2 lane 16 finding: the HITL merge used to merge PR #1 for every
    `/tree/<branch>` URL (pr_num = 1 fallback) in a repo chosen by the approval record."""

    REPO = "example-org/tenant-a"

    def setUp(self):
        self.appr = sys.modules["routes.approvals"]
        self.db = _MemDB()
        self.db.collection("workloads").document("tenant-a").set(
            {"product_id": "tenant-a", "github_repo": self.REPO, "vcs_provider": "GITHUB", "project_id": "proj-a"})
        self.vcs = MagicMock(name="vcs")
        self.repo = MagicMock(name="repo")
        self.repo.full_name = self.REPO
        self.vcs._get_repo.return_value = self.repo
        self.factory = MagicMock(name="VCSProviderFactory")
        self.factory.get_provider.return_value = self.vcs
        self.req = MagicMock()
        self.req.state.user_email = "admin@example.com"
        self.req.state.user_role = "ADMIN"
        for target, attr, value in ((self.appr, "db", self.db), (self.appr, "VCSProviderFactory", self.factory)):
            pt = patch.object(target, attr, value)
            pt.start()
            self.addCleanup(pt.stop)
        ga = sys.modules.get("google.auth")
        self.boom = MagicMock(side_effect=AssertionError("credential minting attempted"))
        if ga is not None:
            pt = patch.object(ga, "default", self.boom)
            pt.start()
            self.addCleanup(pt.stop)

    def _seed(self, **fields):
        base = {"approval_type": "PULL_REQUEST", "product_id": "tenant-a", "branch_name": "feature-x", "status": "PENDING",
                "callback_url": "https://workflowexecutions.googleapis.com/v1/projects/p/locations/l/workflows/w/executions/e/callbacks/c"}
        base.update(fields)
        self.db.collection("approval_requests").document("appr-1").set(base)

    def _seed_with_ledger(self, **fields):
        lid = _seed_ledger(self.db)
        self._seed(pr_number=7, ledger_id=lid, **fields)
        return lid

    def _use_real_provider(self, live_pr):
        live_repo = _LiveRepo(live_pr)
        self.factory.get_provider.return_value = _real_github_provider(live_repo)
        return live_repo

    def _ledger_state(self, lid):
        return self.db.collection("vcs_ledger").document(lid).get().to_dict()["state"]

    def _pr(self, head_repo=REPO, head_ref="feature-x", base_repo=REPO):
        pr = MagicMock(name="pr")
        pr.head.repo.full_name = head_repo
        pr.head.ref = head_ref
        pr.base.repo.full_name = base_repo
        self.repo.get_pull.return_value = pr
        return pr

    def _decide(self, decision=ApprovalStatus.APPROVED):
        try:
            res = self.appr.decide_approval_request("appr-1", ApprovalDecisionRequest(decision=decision), self.req)
            return 200, res
        except Exception as e:  # noqa: BLE001
            return getattr(e, "status_code", None), e

    def _record(self):
        return self.db.collection("approval_requests").document("appr-1").get().to_dict()

    def test_tree_url_without_pr_number_never_merges_pr_1(self):
        self._seed(pull_request_url=f"https://github.com/{self.REPO}/tree/feature-x")
        code, _ = self._decide()
        self.assertEqual(code, 502)
        self.vcs.merge_pull_request.assert_not_called()
        self.assertEqual(self._record()["status"], "MERGE_FAILED")
        self.boom.assert_not_called()

    def test_pull_url_is_not_parsed_for_pr_identity(self):
        self._seed(pull_request_url=f"https://github.com/{self.REPO}/pull/42")
        code, _ = self._decide()
        self.assertEqual(code, 502)
        self.vcs.merge_pull_request.assert_not_called()
        self.assertIn("pr_number", self._record()["failure_reason"])

    def test_record_repo_mismatch_refused(self):
        self._seed(pr_number=7, github_repo="example-org/platform")
        self._pr()
        code, _ = self._decide()
        self.assertEqual(code, 502)
        self.vcs.merge_pull_request.assert_not_called()
        self.assertEqual(self._record()["status"], "MERGE_FAILED")

    def test_fork_pr_refused_before_any_merge_or_branch_delete(self):
        """FD-4BB with the REAL GitHubProvider: PR #7's head is a fork (other numeric repo id)."""
        lid = self._seed_with_ledger()
        pr = _live_pr(head_repo_id=999)
        live_repo = self._use_real_provider(pr)
        code, _ = self._decide()
        self.assertEqual(code, 502)
        pr.merge.assert_not_called()
        self.assertEqual(live_repo.deleted_refs, [])
        self.assertIn("head_repo_id", self._record()["failure_reason"])
        self.assertEqual(self._ledger_state(lid), "MERGE_FAILED")

    def test_wrong_head_ref_refused(self):
        self._seed_with_ledger()
        pr = _live_pr(head_ref="other-branch")
        live_repo = self._use_real_provider(pr)
        self.assertEqual(self._decide()[0], 502)
        pr.merge.assert_not_called()
        self.assertEqual(live_repo.deleted_refs, [])

    def test_head_moved_after_qa_refused(self):
        """Someone pushed to the PR after StackVend created it: the HITL merge pins the ledger SHA (Q10)."""
        self._seed_with_ledger()
        pr = _live_pr(head_sha="f" * 40)
        self._use_real_provider(pr)
        self.assertEqual(self._decide()[0], 502)
        pr.merge.assert_not_called()
        self.assertIn("head_sha", self._record()["failure_reason"])

    def test_positive_real_provider_merges_the_ledger_pr_at_its_sha(self):
        lid = self._seed_with_ledger()
        pr = _live_pr()
        live_repo = self._use_real_provider(pr)
        self._decide()  # merge OK, then the callback fails closed (not this test's concern)
        pr.merge.assert_called_once()
        self.assertEqual(pr.merge.call_args.kwargs["sha"], LEDGER_SHA)
        self.assertEqual(live_repo.deleted_refs, ["heads/feature-x"])
        self.assertEqual(self._record()["merge_status"], "MERGED")
        self.assertEqual(self._ledger_state(lid), "MERGED")

    def test_missing_ledger_entry_never_merges(self):
        """A gateway-shaped record from before the ledger (pr_number but no ledger_id) -> MERGE_FAILED."""
        self._seed(pr_number=7)
        self._pr()
        self.assertEqual(self._decide()[0], 502)
        self.vcs.merge_pull_request.assert_not_called()
        self.assertIn("PR ledger", self._record()["failure_reason"])

    def test_other_products_ledger_entry_never_merges(self):
        lid = _seed_ledger(self.db, product_id="tenant-b")  # same repo + branch, another product's entry
        self._seed(pr_number=7, ledger_id=lid)
        self.assertEqual(self._decide()[0], 502)
        self.vcs.merge_pull_request.assert_not_called()
        self.assertIn("PRODUCT_MISMATCH", self._record()["failure_reason"])

    def test_ledger_entry_for_another_branch_never_merges(self):
        lid = _seed_ledger(self.db, branch="feature-y", pr_number=8)  # forged record pointing at another entry
        self._seed(pr_number=7, ledger_id=lid)
        self.assertEqual(self._decide()[0], 502)
        self.vcs.merge_pull_request.assert_not_called()

    def test_record_pr_number_differs_from_ledger_never_merges(self):
        lid = _seed_ledger(self.db)
        self._seed(pr_number=1, ledger_id=lid)  # the old PR #1 guess on an agent-writable record
        self.assertEqual(self._decide()[0], 502)
        self.vcs.merge_pull_request.assert_not_called()

    def test_platform_pseudo_workload_never_merged(self):
        self.db.collection("workloads").document("project-castor").set({"github_repo": self.REPO})
        self._seed(product_id="project-castor", pr_number=7)
        self._pr()
        self.assertEqual(self._decide()[0], 502)
        self.vcs.merge_pull_request.assert_not_called()

    def test_same_repo_pr_merges_once_by_number_without_branch_fallback(self):
        self._seed_with_ledger()
        self._pr()
        code, _ = self._decide()
        self.assertEqual(code, 502)  # merge OK, then the callback fails closed (lane 3 validator pending)
        self.vcs.merge_pull_request.assert_called_once()
        args, kwargs = self.vcs.merge_pull_request.call_args
        self.assertEqual(args[0], self.REPO)
        exp = kwargs["expected"]  # FD-4BB: the ledger identity, not a bare PR number
        self.assertEqual((exp.pr_number, exp.branch, exp.head_sha, exp.repo_id), (7, "feature-x", LEDGER_SHA, 100))
        self.assertNotIn("pr_number", kwargs)
        self.assertNotIn("source_branch", kwargs)  # no branch-name lookup (it matched fork PRs)
        rec = self._record()
        self.assertEqual(rec["status"], "CALLBACK_FAILED")
        self.assertEqual(rec["merge_status"], "MERGED")
        # Re-decide after CALLBACK_FAILED: allowed, and the PR is NOT merged a second time.
        self.assertEqual(self._decide()[0], 502)
        self.vcs.merge_pull_request.assert_called_once()
        self.boom.assert_not_called()

    def test_decided_approval_cannot_be_decided_again(self):
        for status in ("APPROVED", "REJECTED", "REWORK", "DECIDING"):
            self._seed(pr_number=7, status=status)
            self._pr()
            code, _ = self._decide()
            self.assertEqual(code, 409, status)
            self.assertEqual(self._record()["status"], status)
        self.vcs.merge_pull_request.assert_not_called()

    def test_legacy_approval_without_callback_is_not_reinjected(self):
        self._seed(pr_number=7, callback_url=None)
        self._pr()
        publisher = MagicMock()
        with patch.object(self.appr, "get_pubsub_publisher", publisher, create=True):
            code, _ = self._decide()
        self.assertEqual(code, 409)
        publisher.assert_not_called()
        self.vcs.merge_pull_request.assert_not_called()
        self.assertEqual(self._record()["status"], "PENDING")  # claim released; nothing happened

    def test_operator_cannot_submit_internal_states(self):
        self._seed(pr_number=7)
        for bad in (ApprovalStatus.MERGE_FAILED, ApprovalStatus.CALLBACK_FAILED, ApprovalStatus.DECIDING, ApprovalStatus.PENDING):
            self.assertEqual(self._decide(bad)[0], 400)



# ================================================================================================ code RT fixes (lane 4)
import hashlib as _hashlib

CC_CALLBACKS = os.path.join(CC_DIR, "shared", "callbacks.py")
ROOT_CALLBACKS = os.path.join(REPO_ROOT, "shared", "callbacks.py")
OWN_CALLBACK = ("https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/us-central1/"
                "workflows/castor-main/executions/e1/callbacks/c1")


def _load_cc_callbacks():
    """The callbacks module the Control Center image ships (apps/control-center/shared/callbacks.py), loaded by path."""
    spec = importlib.util.spec_from_file_location("cc_shared_callbacks_under_test", CC_CALLBACKS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _root_has_lane3_callbacks() -> bool:
    with open(ROOT_CALLBACKS, encoding="utf-8") as f:
        return "def classify_callback_url" in f.read()


class _Resp:
    def __init__(self, code=200, body=None):
        self.status_code, self._body, self.text = code, body if body is not None else {"ok": True}, "ok"

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _Creds:
    token = "workflows-callback-token"

    def refresh(self, _req):
        return None


class _CCCallbacksMixin:
    """Routes `from shared.callbacks import ...` (lazy, inside approvals) to the CC's own replica, exactly as the CC
    container resolves it, and captures HTTP + credential minting."""

    def _use_cc_callbacks(self):
        mod = _load_cc_callbacks()
        pt = patch.dict(sys.modules, {"shared.callbacks": mod})
        pt.start()
        self.addCleanup(pt.stop)
        self.posts = []

        def fake_post(url, **kw):
            self.posts.append((url, kw))
            return _Resp(200)
        pt = patch("requests.post", side_effect=fake_post)
        pt.start()
        self.addCleanup(pt.stop)
        ga = sys.modules.get("google.auth")
        self.minted = MagicMock(return_value=(_Creds(), "mock-stackvend-project"))
        if ga is not None:
            pt = patch.object(ga, "default", self.minted)
            pt.start()
            self.addCleanup(pt.stop)
        return mod


class TestCallbackDeliveryUsesLane3Helper(_CCCallbacksMixin, unittest.TestCase):
    """Code RT F3: the fail-closed stub is replaced by lane 3's validator + sender (6th replica). These tests FAIL if
    the stub (or any sender that skips classify_callback_url / follows redirects) is what ships."""

    def setUp(self):
        self.appr = sys.modules["routes.approvals"]
        self.db = _MemDB()
        pt = patch.object(self.appr, "db", self.db)
        pt.start()
        self.addCleanup(pt.stop)
        self.req = MagicMock()
        self.req.state.user_email = "admin@example.com"
        self.req.state.user_role = "ADMIN"
        self._use_cc_callbacks()

    def _seed_plan(self, callback_url):
        self.db.collection("approval_requests").document("plan-1").set({
            "approval_type": "ARCHITECTURAL_PLAN", "product_id": "tenant-a", "trace_id": "trace-1",
            "status": "PENDING", "callback_url": callback_url})

    def _decide(self, decision=ApprovalStatus.APPROVED):
        try:
            return 200, self.appr.decide_approval_request("plan-1", ApprovalDecisionRequest(decision=decision), self.req)
        except Exception as e:  # noqa: BLE001
            return getattr(e, "status_code", None), e

    def test_cc_replica_is_lane3_module(self):
        mod = _load_cc_callbacks()
        for name in ("classify_callback_url", "CallbackURLRejected", "CallbackDeliveryClient", "KIND_WORKFLOWS"):
            self.assertTrue(hasattr(mod, name), name)
        with open(CC_CALLBACKS, encoding="utf-8") as f:
            self.assertIn("allow_redirects=False", f.read())

    @unittest.skipUnless(os.path.exists(ROOT_CALLBACKS), "root shared/callbacks.py missing")
    def test_cc_replica_is_byte_identical_to_root_once_lane3_is_merged(self):
        """6th replica rule (lane 3 parity / lane 12 drift check). Before lane 3 merges, root still holds the
        pre-FD-4J module and this is an expected failure; after the rebase it must pass (strict: an unexpected pass
        while root is old cannot happen, and an XPASS-style mismatch after lane 3 is a real failure)."""
        if not _root_has_lane3_callbacks():
            self.skipTest("lane 3 not merged into this tree yet (root shared/callbacks.py is pre-FD-4J)")
        digest = lambda p: _hashlib.sha256(open(p, "rb").read()).hexdigest()  # noqa: E731
        self.assertEqual(digest(CC_CALLBACKS), digest(ROOT_CALLBACKS))

    def test_own_workflows_callback_delivered_once_without_redirects(self):
        self._seed_plan(OWN_CALLBACK)
        code, res = self._decide()
        self.assertEqual(code, 200, res)
        self.assertEqual(self.db.collection("approval_requests").document("plan-1").get().to_dict()["status"], "APPROVED")
        self.assertEqual(len(self.posts), 1)
        url, kw = self.posts[0]
        self.assertEqual(url, OWN_CALLBACK)
        self.assertIs(kw.get("allow_redirects"), False)
        self.assertEqual(kw["json"]["decision"], "APPROVED")
        self.assertEqual(kw["headers"].get("Authorization"), "Bearer workflows-callback-token")

    def test_forged_callback_is_never_contacted_and_no_token_is_minted(self):
        for forged in ("https://attacker.example/steal-token",
                       "https://workflowexecutions.googleapis.com/v1/projects/other-project/locations/l/workflows/w/executions/e/callbacks/c",
                       "https://workflowexecutions.googleapis.com.attacker.example/v1/projects/mock-stackvend-project/locations/l/workflows/w/executions/e/callbacks/c"):
            self._seed_plan(forged)
            code, _ = self._decide()
            self.assertEqual(code, 502, forged)
            rec = self.db.collection("approval_requests").document("plan-1").get().to_dict()
            self.assertEqual(rec["status"], "CALLBACK_FAILED")
            self.assertIn("refused", rec["failure_reason"])
        self.assertEqual(self.posts, [])
        self.minted.assert_not_called()

    def test_redirecting_endpoint_is_a_callback_failure_not_a_follow(self):
        self._seed_plan(OWN_CALLBACK)
        with patch("requests.post", return_value=_Resp(302)) as post, patch("time.sleep"):
            code, _ = self._decide()
        self.assertEqual(code, 502)
        self.assertTrue(all(c.kwargs.get("allow_redirects") is False for c in post.call_args_list))
        self.assertEqual(self.db.collection("approval_requests").document("plan-1").get().to_dict()["status"], "CALLBACK_FAILED")

    def test_stub_body_is_gone(self):
        import inspect
        src = inspect.getsource(self.appr._deliver_workflow_callback)
        self.assertIn("classify_callback_url(callback_url)", src)
        self.assertIn("CallbackDeliveryClient.send_callback(", src)
        self.assertNotIn("TODO(FD-4N H5 / lane 3)", src)


class TestGatewayRecordsPrNumberAndCcMergesIt(unittest.TestCase):
    """Code RT F1(a): the gateway records the integer PR number from the provider's PR-creation result and writes it
    on the HITL approval record; the CC then merges exactly that PR, once."""

    PID, REPO, BRANCH, TRACE = "tenant-a", "example-org/tenant-a", "castor/tenant-a-abc123", "trace-gw-1"

    def setUp(self):
        self.db = _MemDB()
        self.db.collection("workloads").document(self.PID).set({
            "product_id": self.PID, "github_repo": self.REPO, "vcs_provider": "GITHUB", "default_branch": "main",
            "require_human_code_review": True})
        fs_mod = sys.modules["google.cloud.firestore"]
        # FD-4F RL-3 (lane 13): the release gate is a hard import and always runs (it was None-patched here when a
        # missing gate silently skipped). The real gate with no QA evidence -> HITL, which is what this test needs.
        for target, attr, value in ((gw_main, "db", self.db),
                                    (gw_main, "post_release_certificate_to_vcs", None),
                                    (fs_mod, "Client", MagicMock(return_value=self.db))):
            pt = patch.object(target, attr, value, create=True)
            pt.start()
            self.addCleanup(pt.stop)

    SHA = "a1" * 20

    def _pr_result(self, **over):
        """What GitHubProvider.create_pull_request returns (FD-4P identity fields from the API response)."""
        res = {"pr_number": 17, "pull_request_url": f"https://github.com/{self.REPO}/pull/17", "head_ref": self.BRANCH,
               "head_sha": self.SHA, "head_repo_full_name": self.REPO, "head_repo_id": 100, "base_ref": "main",
               "base_repo_full_name": self.REPO, "base_repo_id": 100}
        res.update(over)
        return res

    def _developer_commit(self, pr_result):
        """Runs DeveloperAgent.commit_and_open_pr's provider path with a fake provider (no network, no sleep)."""
        from _fake_vcs import PassThroughVerifier  # FD-4F A9: a None verifier now fails closed
        handler_mod = sys.modules[type(gw_main.developer_agent).__module__]
        vcs = MagicMock(name="vcs")
        vcs.commit_files.return_value = self.SHA
        vcs.create_pull_request.return_value = pr_result
        factory = MagicMock()
        factory.get_provider.return_value = vcs
        agent = gw_main.developer_agent
        with patch.object(handler_mod, "VCSProviderFactory", factory), \
                patch.object(handler_mod, "SynthesisVerifierAgent", PassThroughVerifier), \
                patch.object(handler_mod.time, "sleep"), \
                patch.object(type(agent), "fetch_github_token", return_value="test-token"), \
                patch.object(agent, "vcs_provider", "GITHUB", create=True):
            result = agent.commit_and_open_pr(product_id=self.PID, files={}, branch_name=self.BRANCH,
                                              github_repo=self.REPO, trace_id=self.TRACE)
        vcs.merge_pull_request.assert_not_called()
        return result

    def _record_ledger(self, result):
        return gw_main._record_pr_ledger(self.TRACE, self.PID, self.BRANCH, result, _ledger.ORIGIN_DEVELOPER)

    def _release(self, branch=None):
        res = gw_main.release_promote(gw_main.ReleasePromoteRequest(
            trace_id=self.TRACE, product_id=self.PID, branch_name=branch or self.BRANCH))
        self.assertEqual(res["status"], "SUCCESS")
        appr = [v for (c, _), v in self.db.store.items() if c == "approval_requests"]
        self.assertEqual(len(appr), 1)
        return appr[0]

    def test_pr_number_comes_from_the_creation_result_only(self):
        self.assertEqual(self._developer_commit({"pr_number": 17, "pull_request_url": "https://github.com/x/y/pull/99"})["pr_number"], 17)
        for bad in (None, True, 0, -3, "17", 17.0):
            self.assertIsNone(self._developer_commit({"pr_number": bad, "pull_request_url": f"https://github.com/{self.REPO}/pull/17"})["pr_number"], bad)

    def test_gateway_shaped_record_merges_exactly_once_with_the_right_identity(self):
        result = self._developer_commit(self._pr_result())
        lid = self._record_ledger(result)
        self.assertEqual(lid, _ledger.ledger_id("GITHUB", self.REPO, self.BRANCH))
        record = self._release()
        self.assertEqual(record["pr_number"], 17)
        self.assertEqual((record["ledger_id"], record["head_sha"]), (lid, self.SHA))
        self.assertEqual(record["pull_request_url"], f"https://github.com/{self.REPO}/pull/17")  # not a /tree/ URL
        self.assertEqual(record["github_repo"], self.REPO)
        self.assertEqual(record["branch_name"], self.BRANCH)
        self.assertEqual(record["status"], "PENDING")

        # The CC decides the record exactly as the gateway wrote it (plus the callback the workflow registers).
        appr_mod = sys.modules["routes.approvals"]
        approval_id = record["approval_id"]
        self.db.collection("approval_requests").document(approval_id).set({"callback_url": OWN_CALLBACK}, merge=True)
        vcs = MagicMock(name="cc-vcs")
        repo = MagicMock()
        repo.full_name = self.REPO
        pr = MagicMock()
        pr.head.repo.full_name, pr.head.ref, pr.base.repo.full_name = self.REPO, self.BRANCH, self.REPO
        repo.get_pull.return_value = pr
        vcs._get_repo.return_value = repo
        vcs.merge_pull_request.return_value = {"status": "MERGED", "merged": True}
        factory = MagicMock()
        factory.get_provider.return_value = vcs
        req = MagicMock()
        req.state.user_email, req.state.user_role = "admin@example.com", "ADMIN"
        with patch.object(appr_mod, "db", self.db), patch.object(appr_mod, "VCSProviderFactory", factory), \
                patch.object(appr_mod, "_deliver_workflow_callback", return_value=(True, "")):
            appr_mod.decide_approval_request(approval_id, ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), req)
        vcs.merge_pull_request.assert_called_once()
        args, kwargs = vcs.merge_pull_request.call_args
        exp = kwargs["expected"]
        self.assertEqual((args[0], exp.pr_number, exp.branch, exp.head_sha, exp.repo_id), (self.REPO, 17, self.BRANCH, self.SHA, 100))
        self.assertNotIn("source_branch", kwargs)
        self.assertNotIn("pr_number", kwargs)
        self.assertEqual(factory.get_provider.call_args.kwargs["provider_name"], "GITHUB")
        final = self.db.collection("approval_requests").document(approval_id).get().to_dict()
        self.assertEqual((final["status"], final["merge_status"]), ("APPROVED", "MERGED"))
        self.assertEqual(self.db.collection("vcs_ledger").document(lid).get().to_dict()["state"], "MERGED")

    def test_release_of_another_branch_is_refused_without_an_approval(self):
        """N14: the release names a branch StackVend did not create for this run -> 409 NO_LEDGER_ENTRY."""
        self._record_ledger(self._developer_commit(self._pr_result()))
        with self.assertRaises(gw_main.ReleaseRefusedError) as ctx:
            gw_main.release_promote(gw_main.ReleasePromoteRequest(
                trace_id=self.TRACE, product_id=self.PID, branch_name="castor/tenant-a-other"))
        self.assertEqual(ctx.exception.reason, "NO_LEDGER_ENTRY")
        self.assertEqual([k for k in self.db.store if k[0] == "approval_requests"], [])

    def test_fork_head_or_foreign_pr_is_never_recorded(self):
        """FD-4BB at creation: a PR whose head is a fork / another branch / another commit gets no ledger entry, so
        neither the release step nor the CC can ever merge it."""
        for bad in ({"head_repo_id": 999, "head_repo_full_name": "attacker/tenant-a"}, {"head_ref": "other"},
                    {"head_sha": "b2" * 20}, {"base_repo_full_name": "example-org/platform"}):
            self.assertIsNone(self._record_ledger(self._developer_commit(self._pr_result(**bad))), bad)
        self.assertEqual([k for k in self.db.store if k[0] == "vcs_ledger"], [])
        self.assertIsNone(self._record_ledger(self._developer_commit({"pr_number": 17, "pull_request_url": "u"})))

    def test_release_writes_no_pr_number_for_serverless_git(self):
        self.db.collection("workloads").document(self.PID).set({"vcs_provider": "SERVERLESS_GIT"}, merge=True)
        _seed_ledger(self.db, product_id=self.PID, repo=self.REPO, branch=self.BRANCH, provider="SERVERLESS_GIT",
                     trace_id=self.TRACE)
        record = self._release()
        self.assertIsNone(record["pr_number"])
        self.assertEqual(record["vcs_provider"], "SERVERLESS_GIT")
        self.assertTrue(record["ledger_id"])


class TestServerlessGitMergesTheApprovedBranch(unittest.TestCase):
    """Code RT F1(b): with the REAL ServerlessGitProvider (HTTP captured), the CC sends source_branch = the approved
    branch and target_branch = the workload's default branch; it never lets the provider fall back to "stage"."""

    PID, BRANCH = "tenant-s", "castor/tenant-s-0a1b2c"

    def setUp(self):
        self.appr = sys.modules["routes.approvals"]
        self.db = _MemDB()
        self.db.collection("workloads").document(self.PID).set({
            "product_id": self.PID, "github_repo": f"castor/{self.PID}", "vcs_provider": "SERVERLESS_GIT",
            "default_branch": "main"})
        from shared.vcs_provider import VCSProviderFactory as RealFactory
        import shared.providers.serverless_git_provider as sgp
        self.http = MagicMock(name="requests")
        self.http.post.return_value = _Resp(200, {"status": "MERGED", "commit_sha": "c0ffee"})
        settings_mod = sys.modules.get("shared.settings")
        for target, attr, value in ((self.appr, "db", self.db), (self.appr, "VCSProviderFactory", RealFactory),
                                    (sgp, "requests", self.http),
                                    (self.appr, "_deliver_workflow_callback", MagicMock(return_value=(True, "")))):
            pt = patch.object(target, attr, value)
            pt.start()
            self.addCleanup(pt.stop)
        if settings_mod is not None:
            pt = patch.object(settings_mod, "get_platform_settings", return_value=None)
            pt.start()
            self.addCleanup(pt.stop)
        pt = patch.dict(os.environ, {"GIT_SERVER_URL": "http://git-server.invalid", "CASTOR_GIT_AUTH_TOKEN": "test-id-token",
                                     "GOOGLE_OIDC_ID_TOKEN": "test-id-token"})
        pt.start()
        self.addCleanup(pt.stop)
        self.req = MagicMock()
        self.req.state.user_email, self.req.state.user_role = "admin@example.com", "ADMIN"

    def _decide(self, base_branch="main", **fields):
        self.db.store = {k: v for k, v in self.db.store.items() if k[0] != "vcs_ledger"}
        lid = _seed_ledger(self.db, product_id=self.PID, repo=f"castor/{self.PID}", branch=self.BRANCH,
                           provider="SERVERLESS_GIT", base_branch=base_branch)
        rec = {"approval_type": "PULL_REQUEST", "product_id": self.PID, "branch_name": self.BRANCH, "status": "PENDING",
               "github_repo": f"castor/{self.PID}", "vcs_provider": "SERVERLESS_GIT", "pr_number": None,
               "callback_url": OWN_CALLBACK, "ledger_id": lid}
        rec.update(fields)
        self.db.collection("approval_requests").document("appr-s").set(rec)
        try:
            return 200, self.appr.decide_approval_request("appr-s", ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), self.req)
        except Exception as e:  # noqa: BLE001
            return getattr(e, "status_code", None), e

    def _merge_bodies(self):
        return [c.kwargs.get("json") for c in self.http.post.call_args_list if str(c.args[0]).endswith("/merge")]

    def test_approved_branch_is_merged_into_default_branch(self):
        code, res = self._decide()
        self.assertEqual(code, 200, res)
        bodies = self._merge_bodies()
        self.assertEqual(len(bodies), 1)
        self.assertEqual((bodies[0]["source_branch"], bodies[0]["target_branch"]), (self.BRANCH, "main"))
        self.assertTrue(str(self.http.post.call_args.args[0]).startswith("http://git-server.invalid/api/v1/repos/tenant-s/merge"))

    def test_never_sends_stage_even_with_a_synthetic_pr_number(self):
        """The target is the ledger's base branch (what the developer cut the branch from), never "stage"."""
        self.assertEqual(self._decide(base_branch="release")[0], 200)
        body = self._merge_bodies()[0]
        self.assertNotEqual(body["source_branch"], "stage")
        self.assertEqual((body["source_branch"], body["target_branch"]), (self.BRANCH, "release"))

    def test_target_branch_or_padded_branch_refused_before_any_http(self):
        for bad in ("main", " castor/tenant-s-0a1b2c"):
            self.assertEqual(self._decide(branch_name=bad)[0], 502, bad)
            self.assertEqual(self.db.collection("approval_requests").document("appr-s").get().to_dict()["status"], "MERGE_FAILED")
        self.assertEqual(self._merge_bodies(), [])

    def test_repo_mismatch_refused(self):
        self.assertEqual(self._decide(github_repo="castor/other-tenant")[0], 502)
        self.assertEqual(self._merge_bodies(), [])

    # ---- FD-4BE (row 11 follow-up): the git server's FF-only 409 ends the waiting run typed MAIN_MOVED
    _CONFLICT = {"status": "CONFLICT", "reason": "target advanced since the branch point", "target_branch": "main"}

    def _record(self):
        return self.db.collection("approval_requests").document("appr-s").get().to_dict()

    def _ledger_state(self):
        return self.db.collection("vcs_ledger").document(
            _ledger.ledger_id("SERVERLESS_GIT", f"castor/{self.PID}", self.BRANCH)).get().to_dict()["state"]

    # ---- SERVERLESS-AUTOMERGE-SHA: the human-approved merge is pinned to the ledger head, like GitHub's merge
    def test_serverless_automerge_sha_merge_names_the_ledger_head(self):
        self.assertEqual(self._decide()[0], 200)
        (body,) = self._merge_bodies()
        self.assertEqual(body["expected_source_sha"], LEDGER_SHA)
        self.assertEqual(self._ledger_state(), "MERGED")  # an older server (no echo) still merges a human approval

    def test_serverless_automerge_sha_source_moved_ends_the_run_release_failed(self):
        self.http.post.return_value = _Resp(409, {"status": "CONFLICT", "reason_code": "SOURCE_MOVED",
                                                  "expected_source_sha": LEDGER_SHA, "source_sha": "f" * 40})
        code, _ = self._decide()
        self.assertEqual(code, 502)
        self.assertEqual(len(self._merge_bodies()), 1)
        url, payload = self.appr._deliver_workflow_callback.call_args.args
        self.assertEqual((payload["decision"], payload["error_class"]), ("MERGE_FAILED", "RELEASE_FAILED"))
        self.assertIn("changed after QA tested it", payload["reason"])
        rec = self._record()
        self.assertEqual((rec["status"], rec["error_class"]), ("RELEASE_FAILED", "RELEASE_FAILED"))
        self.assertEqual(self._ledger_state(), "MERGE_FAILED")

    def test_fd4be_main_moved_409_ends_the_run_typed(self):
        self.http.post.return_value = _Resp(409, self._CONFLICT)
        code, _ = self._decide()
        self.assertEqual(code, 502)
        self.assertEqual(len(self._merge_bodies()), 1)  # one attempt, no rebase / retry
        cb = self.appr._deliver_workflow_callback
        cb.assert_called_once()
        url, payload = cb.call_args.args
        self.assertEqual(url, OWN_CALLBACK)
        self.assertEqual((payload["decision"], payload["error_class"]), ("MERGE_FAILED", "MAIN_MOVED"))
        self.assertIn("re-run", payload["reason"])
        rec = self._record()
        self.assertEqual((rec["status"], rec["error_class"]), ("MAIN_MOVED", "MAIN_MOVED"))
        self.assertNotEqual(rec.get("merge_status"), "MERGED")
        self.assertEqual(self._ledger_state(), "MERGE_FAILED")

    def test_fd4be_main_moved_is_terminal_one_merge_one_callback(self):
        """Review MED: after the run was ended, a re-click is 409 "not decidable": no second /merge POST, no second
        callback to the finished run, no false CALLBACK_FAILED."""
        self.http.post.return_value = _Resp(409, self._CONFLICT)
        self.assertEqual(self._decide()[0], 502)
        code, err = self._redecide()
        self.assertEqual(code, 409, err)
        self.assertIn("not decidable", str(getattr(err, "detail", err)))
        self.assertEqual(len(self._merge_bodies()), 1)
        self.assertEqual(self.appr._deliver_workflow_callback.call_count, 1)
        self.assertEqual(self._record()["status"], "MAIN_MOVED")
        # history, not pending: the record response carries the terminal status and its error_class
        listed = self.appr._record_response("appr-s", self._record(), "now", "admin@example.com")
        self.assertEqual((listed.status.value, listed.error_class), ("MAIN_MOVED", "MAIN_MOVED"))
        self.assertNotIn("MAIN_MOVED", self.appr.DECIDABLE_STATUSES)

    def test_fd4be_callback_failed_main_moved_stays_decidable_and_retries(self):
        self.http.post.return_value = _Resp(409, self._CONFLICT)
        self.appr._deliver_workflow_callback.return_value = (False, "callback delivery failed: boom")
        self.assertEqual(self._decide()[0], 502)
        self.appr._deliver_workflow_callback.return_value = (True, "")
        self.assertEqual(self._redecide()[0], 502)  # retried: merge 409 again, callback delivered now
        self.assertEqual(self.appr._deliver_workflow_callback.call_count, 2)
        self.assertEqual(self._record()["status"], "MAIN_MOVED")

    def test_fd4be_redecision_clears_a_stale_error_class(self):
        self.http.post.return_value = _Resp(409, self._CONFLICT)
        self.appr._deliver_workflow_callback.return_value = (False, "callback delivery failed: boom")
        self._decide()
        self.assertEqual(self._record()["error_class"], "MAIN_MOVED")
        self.http.post.return_value = _Resp(200, {"status": "MERGED", "commit_sha": "c0ffee"})
        self.appr._deliver_workflow_callback.return_value = (True, "")
        self.assertEqual(self._redecide()[0], 200)
        rec = self._record()
        self.assertEqual(rec["status"], "APPROVED")
        self.assertIsNone(rec["error_class"])

    def _redecide(self):
        try:
            return 200, self.appr.decide_approval_request("appr-s", ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), self.req)
        except Exception as e:  # noqa: BLE001
            return getattr(e, "status_code", None), e

    def test_fd4be_main_moved_callback_reaches_the_workflow_contract(self):
        """The CC's real callback payload, fed to the workflow's PR-approval wait: the run fails MAIN_MOVED now."""
        from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run
        from workflow_sim import load_workflow
        self.http.post.return_value = _Resp(409, self._CONFLICT)
        self._decide()
        payload = self.appr._deliver_workflow_callback.call_args.args[1]
        wf = load_workflow(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml"))
        f = Fleet(**{"/agent/release/promote": (200, {"status": "SUCCESS", "auto_merged": False,
                                                      "approval_id": "appr-s", "pull_request_url": "u"})})
        f.callbacks["pr"] = [payload]
        res, _ = run(wf, f)
        assert_failed(res, "MAIN_MOVED", "release")
        self.assertFalse(calls(res, TF))

    def test_fd4be_main_moved_callback_failure_is_callback_failed(self):
        self.http.post.return_value = _Resp(409, self._CONFLICT)
        self.appr._deliver_workflow_callback.return_value = (False, "callback delivery failed: boom")
        self.assertEqual(self._decide()[0], 502)
        rec = self._record()
        self.assertEqual((rec["status"], rec["error_class"]), ("CALLBACK_FAILED", "MAIN_MOVED"))

    def test_fd4be_negative_other_merge_failure_is_unchanged(self):
        """A non-409 git-server failure stays the re-decidable MERGE_FAILED with no workflow callback."""
        self.http.post.return_value = _Resp(500, {"detail": "boom"})
        self.assertEqual(self._decide()[0], 502)
        self.appr._deliver_workflow_callback.assert_not_called()
        rec = self._record()
        self.assertEqual(rec["status"], "MERGE_FAILED")
        self.assertIsNone(rec.get("error_class"))

    def test_fd4be_negative_success_is_unchanged(self):
        self.assertEqual(self._decide()[0], 200)
        payload = self.appr._deliver_workflow_callback.call_args.args[1]
        self.assertEqual(payload["decision"], "APPROVED")
        self.assertEqual(self._record()["status"], "APPROVED")


class TestGitHubMergeFailureEndsTheRun(unittest.TestCase):
    """GH-MERGE-CALLBACK (owner 10-27): a GitHub merge that the provider attempted and that failed calls the
    workflow back at once with decision MERGE_FAILED / error_class RELEASE_FAILED (the FD-4BE MAIN_MOVED path),
    instead of leaving the run waiting for the 24 h approval timeout. Refusals before the merge are unchanged."""

    REPO = TestHitlMergeSafety.REPO
    _seed = TestHitlMergeSafety._seed
    _seed_with_ledger = TestHitlMergeSafety._seed_with_ledger
    _use_real_provider = TestHitlMergeSafety._use_real_provider
    _ledger_state = TestHitlMergeSafety._ledger_state
    _decide = TestHitlMergeSafety._decide
    _record = TestHitlMergeSafety._record

    def setUp(self):
        TestHitlMergeSafety.setUp(self)
        self.cb = MagicMock(return_value=(True, ""))
        pt = patch.object(self.appr, "_deliver_workflow_callback", self.cb)
        pt.start()
        self.addCleanup(pt.stop)

    def _payload(self):
        self.cb.assert_called_once()
        return self.cb.call_args.args[1]

    def test_provider_merge_error_calls_back_release_failed(self):
        lid = self._seed_with_ledger()
        pr = _live_pr(head_sha="f" * 40)  # PR head moved after QA: the provider refuses the merge (PRIdentityMismatch)
        self._use_real_provider(pr)
        code, _ = self._decide()
        self.assertEqual(code, 502)
        pr.merge.assert_not_called()
        payload = self._payload()
        self.assertEqual((payload["status"], payload["decision"], payload["error_class"]),
                         ("MERGE_FAILED", "MERGE_FAILED", "RELEASE_FAILED"))
        self.assertIn("head_sha", payload["reason"])
        self.assertEqual(payload["decided_by"], "admin@example.com")
        rec = self._record()
        self.assertEqual((rec["status"], rec["error_class"]), ("RELEASE_FAILED", "RELEASE_FAILED"))
        self.assertIn("run ended RELEASE_FAILED", rec["failure_reason"])
        self.assertNotEqual(rec.get("merge_status"), "MERGED")
        self.assertEqual(self._ledger_state(lid), "MERGE_FAILED")

    def test_github_did_not_merge_calls_back_release_failed(self):
        self._seed_with_ledger()
        self.vcs.merge_pull_request.return_value = {"merged": False, "message": "Merge conflict"}
        self.assertEqual(self._decide()[0], 502)
        payload = self._payload()
        self.assertEqual((payload["decision"], payload["error_class"]), ("MERGE_FAILED", "RELEASE_FAILED"))
        self.assertIn("Merge conflict", payload["reason"])
        self.assertEqual(self._record()["status"], "RELEASE_FAILED")

    def test_run_ended_card_is_terminal_one_merge_one_callback(self):
        self._seed_with_ledger()
        self.vcs.merge_pull_request.side_effect = RuntimeError("GitHub 502")
        self.assertEqual(self._decide()[0], 502)
        code, err = self._decide()
        self.assertEqual(code, 409, err)
        self.assertIn("not decidable", str(getattr(err, "detail", err)))
        self.vcs.merge_pull_request.assert_called_once()
        self.cb.assert_called_once()
        self.assertNotIn("RELEASE_FAILED", self.appr.DECIDABLE_STATUSES)
        listed = self.appr._record_response("appr-1", self._record(), "now", "admin@example.com")
        self.assertEqual((listed.status.value, listed.error_class), ("RELEASE_FAILED", "RELEASE_FAILED"))

    def test_callback_failure_is_logged_and_surfaced_as_callback_failed(self):
        self._seed_with_ledger()
        self.vcs.merge_pull_request.side_effect = RuntimeError("GitHub 502")
        self.cb.return_value = (False, "callback delivery failed: boom")
        with self.assertLogs("control-center-approvals", level="ERROR") as logs:
            code, err = self._decide()
        self.assertEqual(code, 502)
        self.assertIn("CALLBACK_FAILED", str(getattr(err, "detail", err)))
        self.assertTrue(any("could not be ended" in m for m in logs.output), logs.output)
        rec = self._record()
        self.assertEqual((rec["status"], rec["error_class"]), ("CALLBACK_FAILED", "RELEASE_FAILED"))
        self.assertIn("GitHub 502", rec["failure_reason"])
        self.assertIn("could not be ended: callback delivery failed: boom", rec["failure_reason"])
        # Re-decidable: a re-decision retries the merge and the callback.
        self.cb.return_value = (True, "")
        self.assertEqual(self._decide()[0], 502)
        self.assertEqual(self.cb.call_count, 2)
        self.assertEqual(self._record()["status"], "RELEASE_FAILED")

    def test_callback_reaches_the_workflow_contract(self):
        """The CC's real callback payload, fed to the workflow's PR-approval wait: the run fails RELEASE_FAILED now."""
        from test_lane17_workflow_sim import TF, Fleet, assert_failed, calls, run
        from workflow_sim import load_workflow
        self._seed_with_ledger()
        self.vcs.merge_pull_request.side_effect = RuntimeError("GitHub 502")
        self._decide()
        wf = load_workflow(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml"))
        f = Fleet(**{"/agent/release/promote": (200, {"status": "SUCCESS", "auto_merged": False,
                                                      "approval_id": "appr-1", "pull_request_url": "u"})})
        f.callbacks["pr"] = [self._payload()]
        res, _ = run(wf, f)
        assert_failed(res, "RELEASE_FAILED", "release")
        self.assertFalse(calls(res, TF))

    def test_negative_success_is_unchanged(self):
        self._seed_with_ledger()
        self.vcs.merge_pull_request.return_value = {"merged": True, "status": "MERGED"}
        self.assertEqual(self._decide()[0], 200)
        payload = self._payload()
        self.assertEqual((payload["decision"], payload["branch_name"]), ("APPROVED", "feature-x"))
        self.assertNotIn("error_class", payload)
        rec = self._record()
        self.assertEqual((rec["status"], rec["merge_status"], rec["error_class"]), ("APPROVED", "MERGED", None))

    def test_negative_refusal_before_the_merge_is_unchanged(self):
        """No PR ledger entry: nothing was attempted; the card stays the re-decidable MERGE_FAILED, no callback."""
        self._seed(pr_number=7)
        self.assertEqual(self._decide()[0], 502)
        self.vcs.merge_pull_request.assert_not_called()
        self.cb.assert_not_called()
        rec = self._record()
        self.assertEqual(rec["status"], "MERGE_FAILED")
        self.assertIsNone(rec.get("error_class"))


class TestMergeStatusPersistedBeforeCallback(unittest.TestCase):
    """Code RT F5: merge_status=MERGED is written immediately after the merge, so an exception afterwards (which
    releases the claim to its prior status) can never lead to a second merge."""

    def setUp(self):
        self.appr = sys.modules["routes.approvals"]
        self.db = _MemDB()
        self.db.collection("workloads").document("tenant-a").set({"github_repo": "example-org/tenant-a", "vcs_provider": "GITHUB"})
        self.db.collection("approval_requests").document("appr-1").set({
            "approval_type": "PULL_REQUEST", "product_id": "tenant-a", "branch_name": "feature-x", "pr_number": 7,
            "status": "PENDING", "callback_url": OWN_CALLBACK, "ledger_id": _seed_ledger(self.db)})
        self.vcs = MagicMock()
        repo = MagicMock()
        repo.full_name = "example-org/tenant-a"
        pr = MagicMock()
        pr.head.repo.full_name = pr.base.repo.full_name = "example-org/tenant-a"
        pr.head.ref = "feature-x"
        repo.get_pull.return_value = pr
        self.vcs._get_repo.return_value = repo
        factory = MagicMock()
        factory.get_provider.return_value = self.vcs
        for attr, value in (("db", self.db), ("VCSProviderFactory", factory)):
            pt = patch.object(self.appr, attr, value)
            pt.start()
            self.addCleanup(pt.stop)
        self.req = MagicMock()
        self.req.state.user_email, self.req.state.user_role = "admin@example.com", "ADMIN"

    def test_exception_after_merge_never_remerges(self):
        with patch.object(self.appr, "_deliver_workflow_callback", side_effect=RuntimeError("callback exploded")):
            with self.assertRaises(Exception) as ctx:
                self.appr.decide_approval_request("appr-1", ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), self.req)
        self.assertEqual(getattr(ctx.exception, "status_code", None), 500)
        rec = self.db.collection("approval_requests").document("appr-1").get().to_dict()
        self.assertEqual(rec["status"], "PENDING")          # claim released to its prior status
        self.assertEqual(rec["merge_status"], "MERGED")     # ...but the merge is on record
        with patch.object(self.appr, "_deliver_workflow_callback", return_value=(True, "")):
            self.appr.decide_approval_request("appr-1", ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), self.req)
        self.vcs.merge_pull_request.assert_called_once()
        self.assertEqual(self.db.collection("approval_requests").document("appr-1").get().to_dict()["status"], "APPROVED")


class TestApprovalCardShowsMergeIdentity(unittest.TestCase):
    """Code RT F6: the PR approval card names the repository, branch and PR number the merge will use."""

    def test_list_carries_repo_branch_and_pr_number(self):
        appr = sys.modules["routes.approvals"]
        db = _MemDB()
        db.collection("workloads").document("tenant-a").set({"github_repo": "example-org/tenant-a"})
        db.collection("approval_requests").document("appr-1").set({
            "approval_type": "PULL_REQUEST", "product_id": "tenant-a", "branch_name": "feature-x", "pr_number": 7,
            "github_repo": "agent-written/ignored", "status": "PENDING", "requested_at": "2026-10-12T00:00:00Z"})
        db.collection("approval_requests").document("plan-1").set({
            "approval_type": "ARCHITECTURAL_PLAN", "product_id": "tenant-a", "status": "PENDING",
            "requested_at": "2026-10-11T00:00:00Z"})

        class _Stream(_Col):
            def stream(self):
                return [_Snap(k[1], v) for k, v in self.store.items() if k[0] == self.name]
        db.collection = lambda name: _Stream(db.store, name)
        req = MagicMock()
        req.state.user_email, req.state.user_role = "admin@example.com", "ADMIN"
        with patch.object(appr, "db", db), patch.object(appr, "workload_scope", return_value=MagicMock(all=True)):
            rows = {r.approval_id: r for r in appr.list_pending_approvals(req)}
        pr_row = rows["appr-1"]
        self.assertEqual((pr_row.github_repo, pr_row.branch_name, pr_row.pr_number, pr_row.vcs_provider),
                         ("example-org/tenant-a", "feature-x", 7, "GITHUB"))
        self.assertIsNone(rows["plan-1"].pr_number)

    def test_card_binds_the_identity_as_text(self):
        with open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8") as f:
            html = f.read()
        i = html.index('data-testid="approval-merge-identity"')
        tag = html[i:html.index("</p>", i)]
        for field in ("item.github_repo", "item.branch_name", "item.pr_number"):
            self.assertIn(field, tag)
        self.assertIn("x-text=", tag)
        self.assertNotIn("x-html", tag)


PAUSED_RELEASE = {"status": "PAUSED_FOR_APPROVAL", "summary": "Pull Request awaiting human code review (appr-s)"}


class TestReleaseStageOutcome(unittest.TestCase):
    """RELEASE-STAGE-OUTCOME (FD-4DT, live 10-27/28): an approved Serverless Git release left
    pipeline_executions/{trace}.stages.release at PAUSED_FOR_APPROVAL after the run SUCCEEDED. The decision now
    writes the stage's real outcome, keyed on the card's typed final status (REAL ServerlessGitProvider, HTTP fake)."""

    PID, BRANCH = TestServerlessGitMergesTheApprovedBranch.PID, TestServerlessGitMergesTheApprovedBranch.BRANCH
    setUp = TestServerlessGitMergesTheApprovedBranch.setUp

    def _decide(self, decision=ApprovalStatus.APPROVED, reason=None, **fields):
        self.db.store = {k: v for k, v in self.db.store.items() if k[0] != "vcs_ledger"}
        lid = _seed_ledger(self.db, product_id=self.PID, repo=f"castor/{self.PID}", branch=self.BRANCH,
                           provider="SERVERLESS_GIT", base_branch="main")
        rec = {"product_id": self.PID, "trace_id": "tr-1", "branch_name": self.BRANCH, "status": "PENDING",
               "github_repo": f"castor/{self.PID}", "vcs_provider": "SERVERLESS_GIT", "pr_number": None,
               "callback_url": OWN_CALLBACK, "ledger_id": lid}  # no approval_type: what /agent/release/promote writes
        rec.update(fields)
        self.db.collection("approval_requests").document("appr-s").set(rec)
        self.db.collection("pipeline_executions").document("tr-1").set({"stages": {"release": dict(PAUSED_RELEASE)}})
        try:
            return 200, self.appr.decide_approval_request(
                "appr-s", ApprovalDecisionRequest(decision=decision, reason=reason), self.req)
        except Exception as e:  # noqa: BLE001
            return getattr(e, "status_code", None), e

    def _release_stage(self):
        return self.db.collection("pipeline_executions").document("tr-1").get().to_dict()["stages"]["release"]

    def test_approved_serverless_git_release_is_success_merged_into_the_ledger_base(self):
        code, res = self._decide()
        self.assertEqual(code, 200, res)
        st = self._release_stage()
        self.assertEqual(st["status"], "SUCCESS")
        self.assertEqual(st["summary"], "Approved by admin@example.com; merged into main")
        self.assertEqual((st["decision"], st["approval_id"], st["decided_by"]), ("APPROVED", "appr-s", "admin@example.com"))
        card = self.db.collection("approval_requests").document("appr-s").get().to_dict()
        self.assertEqual((card["merge_status"], card["merged_into"]), ("MERGED", "main"))

    def test_rejected_release_is_its_typed_rejected_status(self):
        code, res = self._decide(ApprovalStatus.REJECTED, reason="not this week")
        self.assertEqual(code, 200, res)
        st = self._release_stage()
        self.assertEqual((st["status"], st["decision"]), ("REJECTED", "REJECTED"))
        self.assertEqual(st["summary"], "Rejected by admin@example.com: not this week")
        self.assertEqual(self._merge_bodies(), [])  # a rejection never merges

    def test_negative_callback_failed_leaves_the_stage_paused(self):
        """Re-decidable: the card still waits for a decision, so the stage stays paused (the merge is recorded on
        the card); the re-decision that delivers the callback then writes SUCCESS."""
        self.appr._deliver_workflow_callback.return_value = (False, "callback delivery failed: boom")
        self.assertEqual(self._decide()[0], 502)
        self.assertEqual(self._release_stage(), PAUSED_RELEASE)
        self.appr._deliver_workflow_callback.return_value = (True, "")
        self.appr.decide_approval_request("appr-s", ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), self.req)
        self.assertEqual(self._release_stage()["status"], "SUCCESS")
        self.assertEqual(self._release_stage()["summary"], "Approved by admin@example.com; merged into main")
        self.assertEqual(len(self._merge_bodies()), 1)  # merged once, never again

    def test_negative_merge_refused_or_main_moved_leaves_the_stage_alone(self):
        self.assertEqual(self._decide(branch_name="main")[0], 502)  # MERGE_FAILED (re-decidable)
        self.assertEqual(self._release_stage(), PAUSED_RELEASE)
        self.http.post.return_value = _Resp(409, TestServerlessGitMergesTheApprovedBranch._CONFLICT)
        self.assertEqual(self._decide()[0], 502)  # MAIN_MOVED: the workflow's typed failure owns the run
        self.assertEqual(self._release_stage(), PAUSED_RELEASE)

    def test_negative_cards_without_a_ledger_entry_or_trace_write_nothing(self):
        for fields in ({"ledger_id": None}, {"trace_id": None}, {"approval_type": "ARCHITECTURAL_PLAN"},
                       {"approval_type": "QUOTA_GATE", "branch_name": None}):
            upd = self.appr._release_stage_update(
                "appr-s", {"status": "APPROVED", "merge_status": "MERGED", "trace_id": "tr-1", "ledger_id": "l",
                           **fields}, "admin@example.com", "now")
            self.assertIsNone(upd, fields)
        # an APPROVED card with no recorded merge never claims one
        self.assertIsNone(self.appr._release_stage_update(
            "appr-s", {"status": "APPROVED", "trace_id": "tr-1", "ledger_id": "l"}, "a", "now"))

    def test_negative_plan_approval_never_touches_the_release_stage(self):
        self.db.collection("pipeline_executions").document("tr-1").set({"stages": {"release": dict(PAUSED_RELEASE)}})
        self.db.collection("approval_requests").document("plan-1").set({
            "approval_type": "ARCHITECTURAL_PLAN", "product_id": self.PID, "trace_id": "tr-1", "status": "PENDING",
            "callback_url": OWN_CALLBACK})
        self.appr.decide_approval_request("plan-1", ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), self.req)
        self.assertEqual(self._release_stage(), PAUSED_RELEASE)

    def test_stage_write_failure_never_fails_the_decision(self):
        real = self.db.collection

        def flaky(name):
            if name == "pipeline_executions":
                col = MagicMock()
                col.document.return_value.set.side_effect = RuntimeError("firestore down")
                return col
            return real(name)
        self.db.collection("pipeline_executions").document("tr-1").set({})
        with patch.object(self.db, "collection", side_effect=flaky):
            code, res = self._decide_no_seed()
        self.assertEqual(code, 200, res)
        self.assertEqual(self.db.collection("approval_requests").document("appr-s").get().to_dict()["status"], "APPROVED")

    def _decide_no_seed(self):
        lid = _seed_ledger(self.db, product_id=self.PID, repo=f"castor/{self.PID}", branch=self.BRANCH,
                           provider="SERVERLESS_GIT", base_branch="main")
        self.db.store[("approval_requests", "appr-s")] = {
            "product_id": self.PID, "trace_id": "tr-1", "branch_name": self.BRANCH, "status": "PENDING",
            "github_repo": f"castor/{self.PID}", "vcs_provider": "SERVERLESS_GIT", "callback_url": OWN_CALLBACK,
            "ledger_id": lid}
        try:
            return 200, self.appr.decide_approval_request(
                "appr-s", ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), self.req)
        except Exception as e:  # noqa: BLE001
            return getattr(e, "status_code", None), e

    def _merge_bodies(self):
        return [c.kwargs.get("json") for c in self.http.post.call_args_list if str(c.args[0]).endswith("/merge")]


class TestGitHubReleaseApprovalStage(unittest.TestCase):
    """The GitHub human-review path: same merge as before (ledger identity, REAL provider), and the release stage
    is written SUCCESS once the callback is delivered."""

    REPO = TestHitlMergeSafety.REPO
    setUp = TestHitlMergeSafety.setUp
    _seed = TestHitlMergeSafety._seed
    _seed_with_ledger = TestHitlMergeSafety._seed_with_ledger
    _use_real_provider = TestHitlMergeSafety._use_real_provider
    _decide = TestHitlMergeSafety._decide
    _record = TestHitlMergeSafety._record

    def test_github_approval_merges_unchanged_and_records_success(self):
        lid = self._seed_with_ledger(trace_id="tr-1")
        pr = _live_pr()
        self._use_real_provider(pr)
        self.db.collection("pipeline_executions").document("tr-1").set({"stages": {"release": dict(PAUSED_RELEASE)}})
        with patch.object(self.appr, "_deliver_workflow_callback", MagicMock(return_value=(True, ""))) as cb:
            code, res = self._decide()
        self.assertEqual(code, 200, res)
        pr.merge.assert_called_once()
        self.assertEqual(pr.merge.call_args.kwargs["sha"], LEDGER_SHA)  # unchanged: merged at the ledger SHA
        self.assertEqual(cb.call_args.args[1]["decision"], "APPROVED")
        self.assertEqual(self.db.collection("vcs_ledger").document(lid).get().to_dict()["state"], "MERGED")
        st = self.db.collection("pipeline_executions").document("tr-1").get().to_dict()["stages"]["release"]
        self.assertEqual((st["status"], st["summary"]), ("SUCCESS", "Approved by admin@example.com; merged into main"))


if __name__ == "__main__":
    unittest.main()

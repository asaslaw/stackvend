"""
FD-08: hermetic Control Center portal tests (NOT collected by pytest; run by tests/test_cc_portal.py in a clean
`python -I` subprocess). Replaces apps/control-center/test_portal.py, which resolved ADC and wrote to LIVE
Firestore when PROJECT_ID was unset, and authenticated with the forged X-Goog-Authenticated-User-Email header
that FD-4E/FD-4M removed.

Reuses the hermetic prefix of tests/cc_identity_harness.py (FD-4E) verbatim: outbound sockets and DNS are refused
and recorded, ADC is disabled, Firestore/Secret Manager are stubbed (in-memory fake), Google ID tokens are really
signed with local keys. Authentication uses real signed session cookies (auth.create_session_token) or a real
signed Google ID token through /auth/google-login. TEST_MODE is unset before any request (production auth paths).

Cookies are always passed explicitly: httpx does not resend `Secure` cookies from its jar over http://.

Usage: python -I tests/cc_portal_harness.py
Prints a single JSON object as the last stdout line:
  {"results": {test_name: "pass" | "XFAIL: ..." | "<failure text>"}, "network_attempts": [...], "db_is_fake": bool, ...}
"""
import io
import json
import os
import sys
import traceback
import unittest
from unittest.mock import MagicMock, patch

_HERE = os.path.dirname(os.path.abspath(__file__))
_PREFIX_MARKER = "# ================================================================ public mode"
with open(os.path.join(_HERE, "cc_identity_harness.py"), encoding="utf-8") as _f:
    _src = _f.read()
assert _PREFIX_MARKER in _src, "FD-4E harness prefix changed"
# Defines: fake, main, auth, config, identity, mode(), google_token(), forged_cookie(), LEGIT_CLIENT,
# NETWORK_ATTEMPTS, CERT_FETCHES, TestClient, ...
exec(compile(_src.split(_PREFIX_MARKER, 1)[0], os.path.join(_HERE, "cc_identity_harness.py"), "exec"), globals())
# Bound by the exec above and named here so static checks see them: CI runs ruff F821 with
# --ignore-noqa (code-RT finding 5), so a noqa comment cannot hide an undefined name.
(
    CERT_FETCHES, LEGIT_CLIENT, NETWORK_ATTEMPTS, TestClient, auth, fake, google_token, main, mode,
) = (globals()[_n] for _n in (
    "CERT_FETCHES", "LEGIT_CLIENT", "NETWORK_ATTEMPTS", "TestClient", "auth", "fake", "google_token", "main",
    "mode",
))

mode("")  # public mode (no IAP audience): sessions + Google Sign-In only

ADMIN = "owner@example.com"  # == ADMIN_EMAIL set by the FD-4E prefix
INTRUDER = "intruder@external.org"
USERS = fake.collection("authorized_users")
# Firestore is authoritative (FD-4M F2): seed the admin explicitly instead of relying on ADMIN_EMAIL fallbacks.
USERS.document(ADMIN).set({"role": "ADMIN", "assigned_workloads": [], "is_active": True})


def cookie(email):
    return {"stackvend_session": auth.create_session_token(email)}


def fresh():
    return TestClient(main.app, raise_server_exceptions=False)


def _git_server_unreachable():
    """castor-git-server is a remote Cloud Run service: make it deterministically unreachable (no DNS/socket)."""
    import requests

    def _down(*a, **k):
        raise requests.ConnectionError("castor-git-server unreachable (FD-08 hermetic portal harness)")

    return patch.multiple("requests", get=MagicMock(side_effect=_down), post=MagicMock(side_effect=_down))


class TestControlCenterPortal(unittest.TestCase):
    """Ported from apps/control-center/test_portal.py (FD-08). Admin auth = real signed session cookie."""

    @classmethod
    def setUpClass(cls):
        cls.client = fresh()
        cls.admin = cookie(ADMIN)
        cls.intruder = cookie(INTRUDER)

    def get(self, path, ck=None, **kw):
        return self.client.get(path, cookies=self.admin if ck is None else ck, **kw)

    def post(self, path, ck=None, **kw):
        return self.client.post(path, cookies=self.admin if ck is None else ck, **kw)

    # ------------------------------------------------------------------ public surface / auth
    def test_health_check_is_public(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "healthy")
        self.assertEqual(r.json()["auth_mode"], "GOOGLE_OAUTH_VERIFIED")

    def test_unauthenticated_browser_visit_renders_google_sign_in_page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 401)
        self.assertIn("accounts.google.com/gsi/client", r.text)
        self.assertIn("StackVend Control Center", r.text)
        self.assertIn("Sign in with your verified Google", r.text)

    def test_unauthenticated_api_requests_blocked(self):
        r = self.client.get("/api/workloads")
        self.assertEqual(r.status_code, 401)
        self.assertIn("Authentication required", r.json()["detail"])

    def test_forged_iap_email_header_is_not_authentication(self):
        """FD-4E removed header trust: the old test_portal auth mechanism must now be rejected."""
        r = self.client.get("/api/workloads", headers={"X-Goog-Authenticated-User-Email": f"accounts.google.com:{ADMIN}"})
        self.assertEqual(r.status_code, 401)

    def test_verified_google_oauth_login_flow(self):
        """Real RS256-signed Google ID tokens through /auth/google-login (no verify_oauth2_token patch)."""
        c = fresh()
        bad = c.post("/auth/google-login", json={"credential": "fake_forged_jwt"})
        self.assertEqual(bad.status_code, 401)
        self.assertIn("Google authentication failed", bad.json()["detail"])

        unapproved = c.post("/auth/google-login", json={"credential": google_token(INTRUDER, LEGIT_CLIENT)})
        self.assertEqual(unapproved.status_code, 403)
        self.assertIn("Access denied", unapproved.json()["detail"])

        login = c.post("/auth/google-login", json={"credential": google_token(ADMIN, LEGIT_CLIENT)})
        self.assertEqual(login.status_code, 200)
        self.assertEqual(login.json()["status"], "SUCCESS")
        self.assertEqual(login.json()["email"], ADMIN)
        sess = login.cookies.get("stackvend_session")
        self.assertTrue(sess)
        self.assertTrue(login.cookies.get("castor_session"))

        dash = c.get("/", cookies={"stackvend_session": sess})
        self.assertEqual(dash.status_code, 200)
        self.assertIn(ADMIN, dash.text)
        self.assertEqual(c.get("/api/workloads", cookies={"stackvend_session": sess}).status_code, 200)

        logout = c.post("/auth/logout", cookies={"stackvend_session": sess})
        self.assertEqual(logout.status_code, 200)
        cleared = [h for h in logout.headers.get_list("set-cookie") if h.startswith("stackvend_session=")]
        self.assertTrue(cleared and ("max-age=0" in cleared[0].lower() or "expires=" in cleared[0].lower()))
        self.assertEqual(c.get("/api/workloads").status_code, 401)

    def test_unauthorized_user_blocked(self):
        """A validly signed session for an email not in authorized_users gets 403 (UI and API)."""
        ui = self.get("/", ck=self.intruder)
        self.assertEqual(ui.status_code, 403)
        self.assertIn("Access Denied", ui.text)
        self.assertIn(INTRUDER, ui.text)
        api = self.get("/api/workloads", ck=self.intruder)
        self.assertEqual(api.status_code, 403)
        self.assertIn("Access denied", api.json()["detail"])

    def test_authorized_user_ui_dashboard(self):
        r = self.get("/")
        self.assertEqual(r.status_code, 200)
        for s in ("StackVend", "Architecture Topology", "StackVend Assistant", "Access Control", ADMIN):
            self.assertIn(s, r.text)

    # ------------------------------------------------------------------ workload catalog (fake Firestore)
    def test_bootstrap_castor_workload_and_list_api(self):
        r = self.post("/api/workloads/bootstrap-castor")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(d["product_id"], "project-castor")
        self.assertEqual(d["github_repo"], "example-org/stackvend")  # lane 4 FD-4AY: GITHUB_REPO
        self.assertEqual(d["default_branch"], "main")
        self.assertEqual(d["status"], "ACTIVE")
        self.assertEqual(d["budget_ceiling_monthly_usd"], 100.0)
        self.assertTrue(d.get("is_castor"))
        self.assertIsNotNone(fake.collection("workloads").document("project-castor").get().to_dict())
        lst = self.get("/api/workloads")
        self.assertEqual(lst.status_code, 200)
        self.assertIsInstance(lst.json(), list)

    # RT14-19: a create with no publisher is now 503 INTAKE_DISPATCH_UNAVAILABLE (it used to answer 200 with no build);
    # these tests are about the registered workload, so the first-build dispatch is stubbed out.
    @patch("routes.workloads._dispatch_first_build", return_value=None)
    def test_create_full_workload_api(self, _dispatch):
        payload = {
            "product_id": "payment-service",
            "title": "Payment Processing Microservice",
            "description": "High-throughput Stripe and PayPal webhook processor",
            "budget_ceiling_monthly_usd": 65.0,
            "github_repo": "example-org/payment-service",
            "spec_content": "Build FastAPI service with Stripe webhook validation and an idempotent event ledger.",
        }
        r = self.post("/api/workloads", json=payload)
        self.assertIn(r.status_code, (200, 201), r.text[:300])
        d = r.json()
        self.assertEqual(d["product_id"], "payment-service")
        self.assertEqual(d["status"], "PROVISIONING")
        self.assertEqual(d["budget_ceiling_monthly_usd"], 65.0)
        self.assertEqual(d["github_repo"], "example-org/payment-service")
        self.assertFalse(d["is_castor"])

    def test_get_workload_details_api(self):
        self.post("/api/workloads/bootstrap-castor")
        r = self.get("/api/workloads/project-castor/details")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(d["product_id"], "project-castor")
        self.assertEqual(d["github_repo"], "example-org/stackvend")  # lane 4 FD-4AY: GITHUB_REPO
        self.assertIsInstance(d["resources"], list)
        self.assertGreaterEqual(d["resources_count"], 1)
        self.assertIn("state_source", d)
        self.assertIn("outputs", d)

    def test_details_resolve_github_repo_when_record_has_none(self):
        # FD-4AY (code RT F2): a GitHub record without github_repo still gets the owner-resolved repo, so the
        # dashboard's GitHub links don't degrade to '#'.
        fake.collection("workloads").document("bare-app").set(
            {"product_id": "bare-app", "status": "ACTIVE", "vcs_provider": "GITHUB"})
        r = self.get("/api/workloads/bare-app/details")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual(r.json()["github_repo"], "example-org/bare-app")   # GITHUB-REPO-NAME-NO-PREFIX
        self.assertEqual(r.json()["git_clone_url"], "https://github.com/example-org/bare-app.git")

    def test_details_carry_typed_intent_warnings(self):
        # TI-3i: the developer's workloads/{id}.iac_intent_warnings reach the workload page (objects only, <= 20)
        w = {"code": "IAC.ENTRY_DROPPED", "address": "google_discovery_engine_data_store.docs",
             "removed_as": "IAC.TYPE_NOT_ALLOWED", "stops_build": False, "message": "removed"}
        fake.collection("workloads").document("warn-app").set(
            {"product_id": "warn-app", "status": "ACTIVE", "vcs_provider": "GITHUB",
             "iac_intent_warnings": [w, "not-an-object"] + [w] * 30})
        r = self.get("/api/workloads/warn-app/details")
        self.assertEqual(r.status_code, 200, r.text[:300])
        got = r.json()["iac_intent_warnings"]
        self.assertEqual(len(got), 20)
        self.assertEqual(got[0], w)
        fake.collection("workloads").document("warn-free-app").set(
            {"product_id": "warn-free-app", "status": "ACTIVE", "vcs_provider": "GITHUB"})
        r = self.get("/api/workloads/warn-free-app/details")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual(r.json().get("iac_intent_warnings"), [])

    def test_details_carry_runtime_env_advisories(self):
        # RUNTIME-ENV-CONTRACT-CHECK: workloads/{id}.runtime_env_advisories reach the workload page (objects only,
        # <= 50) with their total; no record field -> [] and 0
        a = {"code": "ENV.READ_NOT_PROVIDED", "service": "dispatcher", "file": "apps/dispatcher/config.py",
             "line": 56, "name": "GOOGLE_CLOUD_PROJECT", "form": "os.getenv", "has_default": True,
             "default": "local-project", "default_is_literal": True, "message": "not set"}
        fake.collection("workloads").document("env-app").set(
            {"product_id": "env-app", "status": "ACTIVE", "vcs_provider": "GITHUB",
             "runtime_env_advisories": [a, "not-an-object"] + [a] * 60, "runtime_env_advisories_total": 61})
        r = self.get("/api/workloads/env-app/details")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual(len(r.json()["runtime_env_advisories"]), 50)
        self.assertEqual(r.json()["runtime_env_advisories"][0], a)
        self.assertEqual(r.json()["runtime_env_advisories_total"], 61)
        fake.collection("workloads").document("env-bad-total").set(
            {"product_id": "env-bad-total", "status": "ACTIVE", "vcs_provider": "GITHUB",
             "runtime_env_advisories": [a, a], "runtime_env_advisories_total": "lots"})
        r = self.get("/api/workloads/env-bad-total/details")
        self.assertEqual(r.json()["runtime_env_advisories_total"], 2)
        fake.collection("workloads").document("env-free-app").set(
            {"product_id": "env-free-app", "status": "ACTIVE", "vcs_provider": "GITHUB"})
        r = self.get("/api/workloads/env-free-app/details")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual((r.json().get("runtime_env_advisories"), r.json().get("runtime_env_advisories_total")),
                         ([], 0))

    # FD-4AH rescan: routes/workloads.py::submit_feature_request used to read plan_fn/plan_fp before assigning them
    # (NameError -> HTTP 500 on every submission; found by FD-08). Fixed; this test now guards the route.
    def test_feature_request_submission_and_listing_lifecycle(self):
        self.post("/api/workloads/bootstrap-castor")
        payload = {
            "title": "Implement Redis Cache Layer",
            "description": "Add Redis caching for user auth sessions and rate limiting.",
            "change_type": "FEATURE_ENHANCEMENT",
            "priority": "HIGH",
            "target_components": "FastAPI Auth Middleware",
            "acceptance_criteria": "Unit tests pass with mock Redis and latencies < 5ms.",
        }
        r = self.post("/api/workloads/project-castor/feature-requests", json=payload)
        self.assertEqual(r.status_code, 200, r.text[:500])
        d = r.json()
        self.assertEqual(d["product_id"], "project-castor")
        self.assertEqual(d["title"], payload["title"])
        self.assertEqual(d["priority"], "HIGH")
        self.assertEqual(d["status"], "PENDING_TRIAGE")
        self.assertTrue(d["request_id"].startswith("feat-project-castor-"))
        lst = self.get("/api/workloads/project-castor/feature-requests")
        self.assertEqual(lst.status_code, 200)
        self.assertIsInstance(lst.json(), list)

    def test_get_workload_logs_api(self):
        self.post("/api/workloads/bootstrap-castor")
        r = self.get("/api/workloads/project-castor/logs?limit=100")
        # RT14-31: no Cloud Logging client in this hermetic run -> a typed 502, never a made-up "operational" entry
        self.assertEqual(r.status_code, 502)
        d = r.json()["detail"]
        self.assertEqual(d["error_class"], "LOGS_UNAVAILABLE")
        self.assertEqual([(f["source"], f["code"]) for f in d["failures"]], [("PLATFORM", "CLIENT_UNAVAILABLE")])

    def test_get_pipeline_overview_and_agents_api(self):
        r = self.get("/api/pipeline/overview")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(d["agents_count"], 9)
        self.assertEqual(len(d["agents"]), 9)
        self.assertIn("recent_intake_stream", d)
        self.assertGreaterEqual(d["total_active_tasks"], 0)
        agents = self.get("/api/pipeline/agents")
        self.assertEqual(agents.status_code, 200)
        ids = [a["agent_id"] for a in agents.json()]
        self.assertEqual(len(ids), 9)
        for expected in ("architect", "compliance", "developer", "gatekeeper", "gcp-devops", "qa-reviewer",
                         "release-engineer", "finops", "sre"):
            self.assertIn(expected, ids)

    def test_get_architecture_diagram_api(self):
        r = self.get("/api/diagram/project-castor")
        self.assertEqual(r.status_code, 200)
        p = r.json()
        self.assertEqual(p["product_id"], "project-castor")
        for s in ("graph TB", "Autonomous Multi-Agent Swarm", "Control Center", "Terraform MCP Server"):
            self.assertIn(s, p["mermaid_code"])
        self.assertNotIn("Identity-Aware Proxy", p["mermaid_code"])
        self.assertGreaterEqual(len(p["security_boundaries"]), 1)
        r = self.get("/api/diagram/castorcloudruntest")
        self.assertEqual(r.status_code, 200)
        w = r.json()
        self.assertEqual(w["product_id"], "castorcloudruntest")
        for s in ("graph TB", "Google Identity Services", "Cloud Run v2", "Workload Identity Federation",
                  "Cloud Firestore Native", "authorized_users"):
            self.assertIn(s, w["mermaid_code"])
        self.assertNotIn("Identity-Aware Proxy", w["mermaid_code"])
        self.assertNotEqual(p["mermaid_code"], w["mermaid_code"])

    def test_assistant_chat_api(self):
        r = self.post("/api/assistant/chat", json={"message": "Show me our active workloads"})
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertIn("Active StackVend Workloads", d["response_text"])
        self.assertGreaterEqual(len(d["actions_suggested"]), 1)

    def test_approved_emails_access_control_lifecycle(self):
        dev = "developer@company.com"
        dev_ck = cookie(dev)
        self.assertEqual(self.get("/api/workloads", ck=dev_ck).status_code, 403)
        add = self.post("/api/users", json={"email": dev, "role": "APPROVER"})
        self.assertEqual(add.status_code, 200)
        self.assertEqual(add.json()["email"], dev)
        # Legacy APPROVER is normalised to WORKLOAD_MANAGER (schemas.UserAccessRecord.__init__).
        self.assertEqual(add.json()["role"], "WORKLOAD_MANAGER")
        self.assertEqual(self.get("/api/workloads", ck=dev_ck).status_code, 200)
        lst = self.get("/api/users")
        self.assertEqual(lst.status_code, 200)
        self.assertIn(dev, [u["email"] for u in lst.json()])
        rm = self.client.delete(f"/api/users/{dev}", cookies=self.admin)
        self.assertEqual(rm.status_code, 200)
        self.assertEqual(rm.json()["status"], "REMOVED")
        self.assertEqual(self.get("/api/workloads", ck=dev_ck).status_code, 403)

    def test_workload_governance_policy_lifecycle(self):
        g = self.get("/api/workloads/project-castor/policies")
        self.assertEqual(g.status_code, 200)
        for k in ("code_freeze", "sre_auto_healing_enabled", "refactor_scanner_enabled"):
            self.assertIn(k, g.json())
        p = self.client.patch("/api/workloads/project-castor/policies", cookies=self.admin, json={
            "code_freeze": True, "sre_auto_healing_enabled": False, "refactor_scanner_enabled": False})
        self.assertEqual(p.status_code, 200)
        self.assertEqual(p.json()["status"], "UPDATED")
        self.assertTrue(p.json()["policies"]["code_freeze"])
        self.assertFalse(p.json()["policies"]["sre_auto_healing_enabled"])
        self.assertFalse(p.json()["policies"]["refactor_scanner_enabled"])

    # ------------------------------------------------------------------ routes with a MagicMock main.db
    # auth.db stays the fake Firestore (the admin record lives there), so only route data comes from the mock.
    @patch("main.db")
    def test_finops_spend_sync_and_run_rate_projection(self, mock_db):
        doc = MagicMock(id="project-castor", exists=True)
        doc.to_dict.return_value = {
            "product_id": "project-castor", "status": "HEALTHY", "current_spend_usd": 12.50,
            "projected_monthly_spend_usd": 38.75, "budget_ceiling_monthly_usd": 50.0, "is_overrun_projected": False,
            "spend_last_updated_at": "2026-10-08T00:00:00Z", "created_at": "2026-10-01T00:00:00Z",
            "deployed_at": "2026-10-01T00:00:00Z",
        }
        mock_db.collection.return_value.stream.return_value = [doc]
        mock_db.collection.return_value.document.return_value.get.return_value = doc
        # services.finops_sync returns deterministic spend only in TEST_MODE (no BigQuery).
        with patch.dict(os.environ, {"TEST_MODE": "true"}):
            s = self.post("/api/finops/sync-spend")
            self.assertEqual(s.status_code, 200, s.text[:300])
            self.assertEqual(s.json()["status"], "SUCCESS")
            self.assertIn("synced_at", s.json())
            d = self.get("/api/workloads/project-castor/details")
            self.assertEqual(d.status_code, 200)
            for k in ("projected_monthly_spend_usd", "spend_last_updated_at", "is_overrun_projected"):
                self.assertIn(k, d.json())
            w = self.post("/api/workloads/project-castor/sync-spend")
            self.assertEqual(w.status_code, 200, w.text[:300])
            self.assertEqual(w.json()["status"], "SUCCESS")
            self.assertIn("updated", w.json())

    @patch("main.db")
    def test_feature_queue_expandable_plan_and_doc_url(self, mock_db):
        doc = MagicMock(id="fr-drive-123")
        doc.to_dict.return_value = {
            "request_id": "fr-drive-123", "product_id": "test-workload", "title": "OAuth Centralization",
            "description": "Functional spec for central auth hub", "change_type": "FEATURE_ENHANCEMENT",
            "priority": "HIGH", "target_components": "mcp-servers/terraform",
            "acceptance_criteria": "1. Passes pytest\n2. Zero touch auth", "status": "QUEUED",
            "submitted_by": "user@example.com", "created_at": "2026-09-04T12:00:00Z", "channel": "google_docs",
            "source_channel": "google_docs", "spec_doc_id": "1nqLIHIGA6hykH5v6YyqKaOYE73eVzm1x1cIepziDlm8",
            "implementation_plan": "# Technical Implementation Plan\n\n1. Centralize auth domain.",
        }
        mock_db.collection.return_value.where.return_value.stream.return_value = [doc]
        r = self.get("/api/workloads/test-workload/feature-requests")
        self.assertEqual(r.status_code, 200)
        items = r.json()
        self.assertEqual(len(items), 1)
        it = items[0]
        self.assertEqual(it["request_id"], "fr-drive-123")
        self.assertEqual(it["spec_doc_id"], "1nqLIHIGA6hykH5v6YyqKaOYE73eVzm1x1cIepziDlm8")
        self.assertEqual(it["doc_url"], "https://docs.google.com/document/d/1nqLIHIGA6hykH5v6YyqKaOYE73eVzm1x1cIepziDlm8/edit")
        self.assertIn("Technical Implementation Plan", it["implementation_plan"])
        self.assertEqual(it["source_channel"], "google_docs")

    @patch("main.db")
    def test_get_single_feature_request_detail(self, mock_db):
        doc = MagicMock(id="fr-single-456", exists=True)
        doc.to_dict.return_value = {
            "request_id": "fr-single-456", "product_id": "test-workload", "title": "Single Feature View",
            "description": "Deep inspect single feature", "change_type": "BUG_FIX", "priority": "CRITICAL",
            "target_components": "apps/control-center", "acceptance_criteria": "Modal opens cleanly",
            "status": "IN_PROGRESS", "submitted_by": "architect@castor.ai", "created_at": "2026-09-04T13:00:00Z",
            "channel": "CONTROL_CENTER_UI", "implementation_plan": "Full architecture spec here.",
        }
        mock_db.collection.return_value.document.return_value.get.return_value = doc
        r = self.get("/api/workloads/test-workload/feature-requests/fr-single-456")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["request_id"], "fr-single-456")
        self.assertEqual(r.json()["title"], "Single Feature View")
        self.assertEqual(r.json()["implementation_plan"], "Full architecture spec here.")

    @patch("main.db")
    def test_decommission_platform_guard_blocked(self, mock_db):
        r = self.post("/api/workloads/project-castor/decommission",
                      json={"confirm_product_id": "project-castor", "reason": "Test"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("cannot be decommissioned", r.json()["detail"])

    @patch("main.db")
    def test_decommission_confirmation_mismatch_blocked(self, mock_db):
        doc = MagicMock(exists=True)
        doc.to_dict.return_value = {"product_id": "test-service", "status": "ACTIVE", "is_castor": False}
        mock_db.collection.return_value.document.return_value.get.return_value = doc
        r = self.post("/api/workloads/test-service/decommission", json={"confirm_product_id": "wrong-id", "reason": "Test"})
        self.assertEqual(r.status_code, 422)
        self.assertIn("does not match workload ID 'test-service'", r.json()["detail"])

    # The Vending call now goes through routes.settings.make_vending_request (httpx), not main.requests.post;
    # mocking it at the route keeps the in-process CRM-deletion fallback from ever running.
    @patch("routes.workloads.make_vending_request")
    @patch("main.db")
    def test_decommission_workload_success(self, mock_db, mock_vending):
        doc = MagicMock(exists=True)
        doc.to_dict.return_value = {"product_id": "test-service", "project_id": "castor-test-service-123456",
                                    "status": "ACTIVE", "is_castor": False}
        mock_db.collection.return_value.document.return_value.get.return_value = doc
        mock_vending.return_value = MagicMock(status_code=200)
        mock_vending.return_value.json.return_value = {
            "status": "SUCCESS", "product_id": "test-service", "decommissioned_project_id": "castor-test-service-123456"}
        r = self.post("/api/workloads/test-service/decommission",
                      json={"confirm_product_id": "test-service", "reason": "Admin test teardown"})
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual(r.json()["status"], "DECOMMISSIONED")
        self.assertEqual(r.json()["product_id"], "test-service")
        self.assertEqual(r.json()["decommissioned_by"], ADMIN)
        self.assertEqual(mock_vending.call_args.kwargs["path"], "/projects/test-service/decommission")
        self.assertEqual(mock_vending.call_args.kwargs["json_body"]["operator_email"], ADMIN)

    @patch("main.db")
    def test_redeploy_non_decommissioned_blocked(self, mock_db):
        doc = MagicMock(exists=True)
        doc.to_dict.return_value = {"product_id": "test-service", "status": "ACTIVE"}
        mock_db.collection.return_value.document.return_value.get.return_value = doc
        r = self.post("/api/workloads/test-service/redeploy", json={"reason": "Redeploy test"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("Only DECOMMISSIONED workloads can be redeployed", r.json()["detail"])

    @patch("routes.workloads.make_vending_request")
    @patch("main.db")
    def test_redeploy_workload_success(self, mock_db, mock_vending):
        doc = MagicMock(exists=True)
        doc.to_dict.return_value = {"product_id": "test-service", "status": "DECOMMISSIONED",
                                    "last_active_project_id": "castor-test-service-123456"}
        mock_db.collection.return_value.document.return_value.get.return_value = doc
        mock_vending.return_value = MagicMock(status_code=200)
        mock_vending.return_value.json.return_value = {
            "status": "SUCCESS", "product_id": "test-service", "project_id": "castor-test-service-789012",
            "service_url": "https://test-service-xyz.a.run.app"}
        r = self.post("/api/workloads/test-service/redeploy", json={"reason": "Test redeployment"})
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual(mock_vending.call_args.kwargs["path"], "/projects/test-service/redeploy")
        self.assertEqual(r.json()["status"], "ACTIVE")
        self.assertEqual(r.json()["redeployed_by"], ADMIN)
        self.assertEqual(r.json()["new_project_id"], "castor-test-service-789012")
        self.assertEqual(r.json()["service_url"], "https://test-service-xyz.a.run.app")

    def _archive_db(self, mock_db, workload):
        doc = MagicMock(exists=True)
        doc.to_dict.return_value = workload
        ref = MagicMock()
        ref.get.return_value = doc
        mock_db.collection.return_value.document.return_value = ref
        return ref

    @patch("main.db")
    def test_archive_non_decommissioned_blocked(self, mock_db):
        self._archive_db(mock_db, {"product_id": "active-service", "status": "ACTIVE"})
        r = self.post("/api/workloads/active-service/archive")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Only DECOMMISSIONED workloads can be archived", r.json()["detail"])

    @patch("main.db")
    def test_archive_decommissioned_workload_success(self, mock_db):
        ref = self._archive_db(mock_db, {"product_id": "decom-service", "status": "DECOMMISSIONED",
                                         "decommissioned_at": "2026-09-25T12:00:00Z"})
        r = self.post("/api/workloads/decom-service/archive")
        self.assertEqual(r.status_code, 200, r.text[:300])
        d = r.json()
        self.assertEqual(d["status"], "ARCHIVED")
        self.assertEqual(d["product_id"], "decom-service")
        self.assertIsNotNone(d["archived_at"])
        self.assertEqual(d["archived_by"], ADMIN)
        ref.set.assert_called()

    @patch("main.db")
    def test_unarchive_non_archived_blocked(self, mock_db):
        self._archive_db(mock_db, {"product_id": "decom-service", "status": "DECOMMISSIONED"})
        r = self.post("/api/workloads/decom-service/unarchive")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Only ARCHIVED workloads can be unarchived", r.json()["detail"])

    @patch("main.db")
    def test_unarchive_workload_success(self, mock_db):
        ref = self._archive_db(mock_db, {"product_id": "archived-service", "status": "ARCHIVED",
                                         "archived_at": "2026-09-25T12:00:00Z", "archived_by": "admin@example.com"})
        r = self.post("/api/workloads/archived-service/unarchive")
        self.assertEqual(r.status_code, 200, r.text[:300])
        self.assertEqual(r.json()["status"], "DECOMMISSIONED")
        self.assertEqual(r.json()["product_id"], "archived-service")
        ref.set.assert_called()

    # ------------------------------------------------------------------ serverless git
    @_git_server_unreachable()
    @patch("routes.workloads._dispatch_first_build", return_value=None)   # RT14-19: see test_create_full_workload_api
    def test_get_workload_details_serverless_git(self, _dispatch):
        payload = {"product_id": "test-srv-git-wl", "title": "Serverless Git Workload", "vcs_provider": "SERVERLESS_GIT",
                   "budget_ceiling_monthly_usd": 35.0, "target_branch": "main",
                   "spec_content": "Build microservice using internal serverless git."}
        c = self.post("/api/workloads", json=payload)
        self.assertIn(c.status_code, (200, 201), c.text[:300])
        # FALLBACK-URLS: the configured git server URL is used unchanged ...
        with patch.dict(os.environ, {"GIT_SERVER_URL": "https://git-server.example.test/"}):
            r = self.get("/api/workloads/test-srv-git-wl/details")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(d["product_id"], "test-srv-git-wl")
        self.assertEqual(d["vcs_provider"], "SERVERLESS_GIT")
        self.assertEqual(d["git_clone_url"], "https://git-server.example.test/git/test-srv-git-wl.git")
        self.assertIsNone(d["git_clone_url_error"])
        # ... and an unknown one is a typed error, never a URL guessed from the project id and a fixed region.
        env = {k: v for k, v in os.environ.items() if k not in ("GIT_SERVER_URL", "CASTOR_GIT_SERVER_URL")}
        with patch.dict(os.environ, env, clear=True):
            r = self.get("/api/workloads/test-srv-git-wl/details")
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertIsNone(d["git_clone_url"])
        self.assertEqual(d["git_clone_url_error"], "GIT_SERVER_URL_UNKNOWN")
        self.assertNotIn("run.app", r.text)
        self.assertNotIn("castor-git-server:8080", r.text)

    @_git_server_unreachable()
    def test_serverless_git_plans_and_raw_endpoint(self):
        payload = {"product_id": "test-srv-git-plans", "title": "Serverless Git Plans Workload",
                   "vcs_provider": "SERVERLESS_GIT", "budget_ceiling_monthly_usd": 40.0, "target_branch": "main",
                   "spec_content": "Workload with plans."}
        self.post("/api/workloads", json=payload)
        p = self.get("/api/workloads/test-srv-git-plans/plans")
        self.assertEqual(p.status_code, 200)
        self.assertGreaterEqual(p.json()["total_plans"], 1)
        item = p.json()["plans"][0]
        self.assertIn("/api/workloads/test-srv-git-plans/plans/", item["url"])
        self.assertTrue(item["url"].endswith("/raw"))
        raw = self.get(f"/api/workloads/test-srv-git-plans/plans/{item['filename']}/raw")
        self.assertEqual(raw.status_code, 200)
        self.assertEqual(raw.headers["content-type"], "text/markdown; charset=utf-8")
        self.assertIn("# Implementation Plan", raw.text)

    # ------------------------------------------------------------------ document extraction
    def test_extract_document_text_markdown_api(self):
        md = b"# Enterprise Payments Gateway\n\nBuild a high throughput payment gateway with Stripe and Cloud PubSub."
        r = self.post("/api/workloads/extract-document-text", files={"file": ("enterprise-payments.md", md, "text/markdown")})
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(d["filename"], "enterprise-payments.md")
        self.assertEqual(d["file_type"], "MARKDOWN")
        self.assertEqual(d["suggested_slug"], "enterprise-payments")
        self.assertEqual(d["suggested_title"], "Enterprise Payments Gateway")
        self.assertIn("Build a high throughput payment gateway", d["text"])
        self.assertGreater(d["word_count"], 5)
        self.assertEqual(d["pages_count"], 1)

    def test_extract_document_text_pdf_api(self):
        from pypdf import PdfWriter
        w = PdfWriter()
        w.add_blank_page(width=72, height=72)
        w.add_blank_page(width=72, height=72)
        buf = io.BytesIO()
        w.write(buf)
        r = self.post("/api/workloads/extract-document-text",
                      files={"file": ("cloud-architecture-spec.pdf", buf.getvalue(), "application/pdf")})
        self.assertEqual(r.status_code, 200)
        d = r.json()
        self.assertEqual(d["filename"], "cloud-architecture-spec.pdf")
        self.assertEqual(d["file_type"], "PDF")
        self.assertEqual(d["suggested_slug"], "cloud-architecture-spec")
        self.assertEqual(d["pages_count"], 2)

    def test_extract_document_text_unsupported_extension_rejected(self):
        r = self.post("/api/workloads/extract-document-text",
                      files={"file": ("malicious.exe", b"binarycontent", "application/octet-stream")})
        self.assertEqual(r.status_code, 400)
        self.assertIn("Unsupported file format", r.json()["detail"])

    # ------------------------------------------------------------------ FD-48: retrigger keeps the real 4xx
    def _retrigger_db(self, with_execution):
        """Fresh in-memory db: an ACTIVE workload with no project_id/github_repo (the inner retrigger refuses it
        with 409) and one feature request, found via an execution doc or the feature_requests fallback."""
        db = type(fake)()
        db.collection("workloads").document("retrig-app").set({"product_id": "retrig-app", "status": "ACTIVE"})
        db.collection("feature_requests").document("fr-retrig-1").set(
            {"product_id": "retrig-app", "request_id": "fr-retrig-1", "created_at": "2026-10-14T00:00:00Z"})
        if with_execution:
            db.collection("pipeline_executions").document("exec-1").set(
                {"product_id": "retrig-app", "request_id": "fr-retrig-1", "started_at": "2026-10-14T00:00:00Z"})
        return db

    def test_retrigger_latest_returns_inner_http_error_from_execution_path(self):
        # Before FD-48 the 409 from retrigger_feature_request_build was swallowed by `except Exception`, the
        # feature_requests fallback ran (and could retrigger a different request), and the client got a 404.
        with patch("main.db", self._retrigger_db(with_execution=True)):
            r = self.post("/api/workloads/retrig-app/retrigger", json={})
        self.assertEqual(r.status_code, 409, r.text[:300])
        self.assertIn("has no registered project_id/github_repo", r.json()["detail"])

    def test_retrigger_latest_returns_inner_http_error_from_feature_request_fallback(self):
        with patch("main.db", self._retrigger_db(with_execution=False)):
            r = self.post("/api/workloads/retrig-app/retrigger", json={"execution_mode": "BOGUS"})
        # The execution_mode allow-list check runs after the 409 project check, so the 409 is what surfaces.
        self.assertEqual(r.status_code, 409, r.text[:300])

    def test_retrigger_latest_still_404_when_nothing_to_retrigger(self):
        db = type(fake)()
        db.collection("workloads").document("retrig-app").set({"product_id": "retrig-app", "status": "ACTIVE"})
        with patch("main.db", db):
            r = self.post("/api/workloads/retrig-app/retrigger", json={})
        self.assertEqual(r.status_code, 404, r.text[:300])
        self.assertIn("No retriggerable feature request", r.json()["detail"])

    # ------------------------------------------------------------------ dashboard HTML bindings
    def _dashboard(self, *needles):
        r = self.get("/")
        self.assertEqual(r.status_code, 200)
        for n in needles:
            self.assertIn(n, r.text)

    def test_dashboard_html_contains_plan_modal_and_accordion(self):
        self._dashboard("showPlanModal", "openPlanModal", "closePlanModal", "toggleExpandFeature",
                        "Open Google Doc", "View Architecture Plan")

    def test_dashboard_html_contains_decommission_safeguards(self):
        self._dashboard("showDecommissionModal", "openDecommissionModal", "closeDecommissionModal",
                        "submitDecommission", "redeployWorkload", "decommissionConfirmInput",
                        "decommissionTargetWorkload", "Danger Zone: High-Friction Administrative Action")

    def test_dashboard_html_contains_dynamic_vcs_and_clone_command(self):
        self._dashboard("child-workload-plans", "copyGitCloneCommand", "Serverless Git Repo", "scrollToPlans")

    def test_dashboard_html_contains_archived_tab_and_table(self):
        self._dashboard("\U0001f4e6 Archived Workloads", "workloadCatalogFilter === 'ARCHIVED'", "archiveWorkload",
                        "unarchiveWorkload", "Archived Workloads Tabular View")

    def test_dashboard_html_contains_document_upload(self):
        self._dashboard("Upload Document", "handleSpecFileUpload", "handleSpecFileDrop", "uploadedDocSummary")


class _Collect(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.out = {}

    def addSuccess(self, test):
        self.out[test._testMethodName] = "pass"

    def _bad(self, test, err, kind):
        self.out[test._testMethodName] = f"{kind}: " + "".join(traceback.format_exception(*err))[-1500:]

    def addFailure(self, test, err):
        self._bad(test, err, "FAIL")

    def addError(self, test, err):
        self._bad(test, err, "ERROR")

    def addExpectedFailure(self, test, err):
        self.out[test._testMethodName] = "XFAIL: " + "".join(traceback.format_exception(*err))[-300:]

    def addUnexpectedSuccess(self, test):
        self.out[test._testMethodName] = "XPASS: expectedFailure marker is stale"

    def addSkip(self, test, reason):
        self.out[test._testMethodName] = f"SKIP: {reason}"


_res = _Collect()
unittest.defaultTestLoader.loadTestsFromTestCase(TestControlCenterPortal).run(_res)
print(json.dumps({
    "results": _res.out,
    "network_attempts": NETWORK_ATTEMPTS,
    "db_is_fake": main.db is fake and auth.db is fake,
    "test_mode_unset": "TEST_MODE" not in os.environ,
    "cert_urls_fetched": sorted(set(CERT_FETCHES)),
}))

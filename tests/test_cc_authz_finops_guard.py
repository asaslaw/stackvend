"""FD-4O / FD26-03 / FD26-20: FinOps enforcer target guard and caller authentication.

The enforcer quarantines (scale-to-zero, stop VMs/SQL/GKE, unlink billing) and restores workload projects. It must
NEVER act on the host platform project or on any project outside the managed workloads folder:
- target_project_id is mandatory (the old `target_project_id or self.platform_project_id` fallback is gone);
- the host project is refused by id AND by project number;
- the managed root folder (MANAGED_WORKLOADS_FOLDER_ID) must appear as a `folder` ancestor in Resource Manager
  getAncestry (exact type/id fields, REST), and every uncertainty fails closed;
- a refusal makes ZERO calls on run/compute/sql/container/billing and zero Firestore operations.
The enforcer's HTTP endpoints accept only an allow-listed OIDC bearer for a configured audience.

Hermetic: every Google client is a MagicMock; no credentials, no network.
"""
import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

HERE = os.path.dirname(os.path.abspath(__file__))
FINOPS_DIR = os.path.join(HERE, "..", "apps", "finops-enforcer")

ROOT = "111111111111"
HOST = "castor-host-proj"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(FINOPS_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/fd4o-adc.json"}):
    enf_mod = _load("fd4o_enforcer", "enforcer.py")


def _ancestry(project, *folders, org="999"):
    return {"ancestor": [{"resourceId": {"type": "project", "id": project}}]
            + [{"resourceId": {"type": "folder", "id": f}} for f in folders]
            + [{"resourceId": {"type": "organization", "id": org}}]}


def _crm(ancestries, numbers, fail=None):
    crm = MagicMock(name="crm")
    projects = crm.projects.return_value

    def get_ancestry(projectId, body):
        call = MagicMock()
        if fail:
            call.execute.side_effect = fail
        else:
            call.execute.return_value = ancestries.get(projectId, {"ancestor": []})
        return call

    def get(projectId):
        call = MagicMock()
        call.execute.return_value = {"projectNumber": numbers.get(projectId, "")}
        return call

    projects.getAncestry.side_effect = get_ancestry
    projects.get.side_effect = get
    return crm


class _Base(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": ROOT, "PROJECT_ID": HOST,
                                           "GOOGLE_CLOUD_PROJECT": HOST})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.mutators = {k: MagicMock(name=k) for k in ("run", "compute", "sql", "container", "billing")}
        self.db = MagicMock(name="firestore")

    def enforcer(self, crm):
        m = self.mutators
        return enf_mod.FinopsBudgetEnforcer(project_id=HOST, firestore_client=self.db, run_service=m["run"],
                                            compute_service=m["compute"], sql_service=m["sql"],
                                            container_service=m["container"], billing_service=m["billing"],
                                            crm_service=crm)

    def assert_no_mutation(self):
        def api_calls(mock):  # the constructor's truthiness checks (`client and ...`) are not API calls
            return [c for c in mock.mock_calls if not c[0].startswith("__")]

        for name, mock in self.mutators.items():
            self.assertEqual(api_calls(mock), [], f"{name} was called on a refused target")
        self.assertEqual(api_calls(self.db), [], "Firestore was touched on a refused target")


class TestEnforcerTargetGuard(_Base):
    def _refused(self, target, crm, policy="AUTONOMOUS_SCALE_TO_ZERO"):
        e = self.enforcer(crm)
        res = e.quarantine_workload(product_id="tenant-a", target_project_id=target, spend_amount=99, budget_amount=1,
                                    policy=policy)
        self.assertEqual(res["status"], "REFUSED", res)
        self.assert_no_mutation()
        return res

    def test_missing_target_never_falls_back_to_host(self):
        crm = _crm({}, {})
        self._refused(None, crm)
        self._refused("", crm)
        self.assertEqual([c for c in crm.mock_calls if not c[0].startswith("__")], [])

    def test_host_project_by_id(self):
        self._refused(HOST, _crm({HOST: _ancestry(HOST, ROOT)}, {HOST: "42"}))

    def test_host_project_alias_by_number(self):
        crm = _crm({"alias-proj": _ancestry("alias-proj", "555", ROOT)}, {HOST: "42", "alias-proj": "42"})
        self._refused("alias-proj", crm)

    def test_nuclear_unlink_on_host_never_touches_billing(self):
        self._refused(HOST, _crm({}, {HOST: "42"}), policy="NUCLEAR_UNLINK_BILLING")

    def test_non_descendant_project(self):
        crm = _crm({"other-tenant": _ancestry("other-tenant", "777")}, {HOST: "42", "other-tenant": "7"})
        self._refused("other-tenant", crm)

    def test_root_id_only_as_the_project_itself_or_wrong_type(self):
        anc = {"ancestor": [{"resourceId": {"type": "project", "id": ROOT}},
                            {"resourceId": {"type": "organization", "id": ROOT}}]}
        self._refused("p", _crm({"p": anc}, {HOST: "42", "p": "8"}))

    def test_ancestry_api_error_fails_closed(self):
        self._refused("proj-a", _crm({}, {HOST: "42"}, fail=PermissionError("403")))

    def test_root_not_configured_fails_closed(self):
        os.environ.pop("MANAGED_WORKLOADS_FOLDER_ID", None)
        self._refused("proj-a", _crm({"proj-a": _ancestry("proj-a", ROOT)}, {HOST: "42", "proj-a": "9"}))

    def test_no_resource_manager_client_fails_closed(self):
        e = self.enforcer(None)
        e.crm = None
        res = e.quarantine_workload(product_id="tenant-a", target_project_id="proj-a")
        self.assertEqual(res["status"], "REFUSED")
        self.assert_no_mutation()

    def test_restore_on_host_or_non_descendant_refused(self):
        for target, crm in ((HOST, _crm({}, {HOST: "42"})),
                            ("other", _crm({"other": _ancestry("other", "777")}, {HOST: "42", "other": "7"}))):
            res = self.enforcer(crm).restore_workload("tenant-a", target)
            self.assertEqual(res["status"], "REFUSED", res)
            self.assert_no_mutation()

    def test_descendant_project_proceeds_unchanged(self):
        """Do-No-Harm: a project under the managed folder (directly or via a sub-folder) is quarantined as before."""
        crm = _crm({"proj-a": _ancestry("proj-a", "555", ROOT)}, {HOST: "42", "proj-a": "9"})
        run = self.mutators["run"]
        svcs = run.projects.return_value.locations.return_value.services.return_value
        svcs.list.return_value.execute.return_value = {"services": [
            {"name": "projects/proj-a/locations/us-central1/services/api",
             "template": {"scaling": {"maxInstanceCount": 5}}}]}
        compute = self.mutators["compute"]
        compute.instances.return_value.aggregatedList.return_value.execute.return_value = {"items": {}}
        compute.instances.return_value.aggregatedList_next.return_value = None  # finite pagination
        self.mutators["sql"].instances.return_value.list.return_value.execute.return_value = {"items": []}
        (self.mutators["container"].projects.return_value.locations.return_value.clusters.return_value
         .list.return_value.execute.return_value) = {"clusters": []}
        e = self.enforcer(crm)
        self.assertEqual(e.authorize_target("proj-a"), "proj-a")
        res = e.quarantine_workload(product_id="tenant-a", target_project_id="proj-a", spend_amount=99, budget_amount=1)
        self.assertNotEqual(res.get("status"), "REFUSED")
        self.assertEqual(res.get("project_id"), "proj-a")
        parents = [c.kwargs.get("parent", "") for c in svcs.list.call_args_list]
        self.assertTrue(parents and all(p.startswith("projects/proj-a/") for p in parents), parents)
        for c in svcs.patch.call_args_list:
            self.assertTrue(c.kwargs["name"].startswith("projects/proj-a/"))


class TestEnforcerHttpCallerAuth(unittest.TestCase):
    """FD26-20: the duplicate unauthenticated billing webhook is gone; /enforce and /restore need a verified caller."""

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/fd4o-adc.json"}), \
                patch.dict(sys.modules, {"enforcer": enf_mod}):
            cls.main = _load("fd4o_enforcer_main", "main.py")

    def test_duplicate_billing_webhook_removed(self):
        paths = {getattr(r, "path", None) for r in self.main.app.routes}
        self.assertNotIn("/api/alerts/billing", paths)

    def _call(self, authorization, verify_result=None, env=None):
        env = env if env is not None else {"FINOPS_SERVICE_URL": "https://finops.example.run.app",
                                           "FINOPS_ALLOWED_CALLERS": "sa-castor-finops@p.iam.gserviceaccount.com"}
        verify = MagicMock(return_value=verify_result) if not isinstance(verify_result, Exception) \
            else MagicMock(side_effect=verify_result)
        import google.oauth2.id_token as gid
        with patch.dict(os.environ, env, clear=False), patch.object(gid, "verify_oauth2_token", verify):
            for k in ("FINOPS_SERVICE_URL", "FINOPS_ALLOWED_CALLERS"):
                if k not in env:
                    os.environ.pop(k, None)
            try:
                return 200, self.main.require_platform_caller(authorization), verify
            except Exception as e:  # noqa: BLE001
                return getattr(e, "status_code", None), None, verify

    def test_unconfigured_fails_closed(self):
        code, _, verify = self._call("Bearer x", {"email": "a"}, env={})
        self.assertEqual(code, 503)
        verify.assert_not_called()

    def test_missing_or_invalid_token(self):
        self.assertEqual(self._call(None)[0], 401)
        self.assertEqual(self._call("Bearer bad", ValueError("bad sig"))[0], 401)

    def test_audience_is_pinned_and_email_allow_listed(self):
        code, _, verify = self._call("Bearer t", {"email": "pwn@attacker.iam.gserviceaccount.com", "email_verified": True})
        self.assertEqual(code, 403)
        self.assertEqual(verify.call_args.kwargs.get("audience"), "https://finops.example.run.app")
        self.assertEqual(self._call("Bearer t", {"email": "sa-castor-finops@p.iam.gserviceaccount.com",
                                                 "email_verified": False})[0], 403)
        code, email, _ = self._call("Bearer t", {"email": "sa-castor-finops@p.iam.gserviceaccount.com",
                                                 "email_verified": True})
        self.assertEqual((code, email), (200, "sa-castor-finops@p.iam.gserviceaccount.com"))


if __name__ == "__main__":
    unittest.main()

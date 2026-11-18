"""
FD-4DB (residual of FD-4CT): read-only install IAM check, scripts/check-install-iam.sh + scripts/common/install_iam_check.py.

The check reports IAM grants on the host project, the managed workloads folder, the billing account, the
deletion-safety tag and the StackVend service accounts that are NOT in the applied platform Terraform state and that
reach past the lane 18 guards. Expected grants come only from the state (fakes here); the policies are fakes too.
Exit codes: 0 clean, 1 findings, 2 could not check.

Hermetic: the analysis tests import the helper; the offline wrapper tests run bash with no gcloud / curl / tofu; the
live-mode wrapper test runs with lane 5's stubs (gcloud, curl) and the real `tofu console` for the tfvars only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import test_platform_safe_apply_lane5 as lane5

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
SCRIPT = os.path.join(REPO, "scripts", "check-install-iam.sh")
HELPER = os.path.join(REPO, "scripts", "common", "install_iam_check.py")

_spec = importlib.util.spec_from_file_location("install_iam_check", HELPER)
iic = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(iic)

PROJ = lane5.PROJ  # "proj-aaaa1"
NUM = "111122223333"
FOLDER = "folders/4242"
BILLING = "0A0A0A-1B1B1B-2C2C2C"
TAG_KEY = "tagKeys/777"
TAG_VALUE = "tagValues/888"


def sa(name, project=PROJ):
    return f"{name}@{project}.iam.gserviceaccount.com"


DEV, PROV, CC, DEVOPS, CLEANER = (sa("sa-castor-developer"), sa("sa-project-provisioner"),
                                  sa("sa-stackvend-control-center"), sa("sa-castor-gcp-devops"),
                                  sa("sa-stackvend-sandbox-cleaner"))
COMPUTE = f"{NUM}-compute@developer.gserviceaccount.com"
GUARD = f'resource.name == "projects/{PROJ}/databases/stackvend-guard" || ' \
        f'resource.name.startsWith("projects/{PROJ}/databases/stackvend-guard/")'
NOT_GUARD = f"!({GUARD})"


def _cond(expr, title):
    return [{"expression": expr, "title": title, "description": ""}] if expr else []


def _res(rtype, name, instances, mode="managed", module=None):
    r = {"mode": mode, "type": rtype, "name": name, "provider": "provider[\"registry.opentofu.org/hashicorp/google\"]",
         "instances": [{"attributes": a} for a in instances]}
    if module:
        r["module"] = module
    return r


def make_state():
    """A raw (format 4) platform state with the shapes infra/platform declares."""
    accounts = {"sa-castor-developer": DEV, "sa-project-provisioner": PROV, "sa-castor-gcp-devops": DEVOPS}
    personas = {"sa-stackvend-control-center": CC, "sa-stackvend-sandbox-cleaner": CLEANER}
    return {"version": 4, "terraform_version": "1.9.0", "serial": 1, "lineage": "x", "outputs": {}, "resources": [
        _res("google_project", "platform_project", [{"project_id": PROJ, "number": NUM}], mode="data"),
        _res("google_service_account", "agents",
             [{"account_id": k, "email": v, "name": f"projects/{PROJ}/serviceAccounts/{v}"} for k, v in accounts.items()]),
        _res("google_service_account", "stackvend_personas",
             [{"account_id": k, "email": v, "name": f"projects/{PROJ}/serviceAccounts/{v}"} for k, v in personas.items()]),
        _res("google_project_iam_member", "agent_datastore_users", [
            {"project": PROJ, "role": "roles/datastore.user", "member": f"serviceAccount:{e}",
             "condition": _cond(NOT_GUARD, "stackvend-not-guard-db")} for e in (DEV, PROV, DEVOPS)]),
        _res("google_project_iam_member", "guard_db_writers", [
            {"project": PROJ, "role": "roles/datastore.user", "member": f"serviceAccount:{e}",
             "condition": _cond(GUARD, "stackvend-guard-db-only")} for e in (CC, PROV)]),
        _res("google_project_iam_member", "cloudbuild_compute_storage", [
            {"project": PROJ, "role": "roles/storage.admin", "member": f"serviceAccount:{COMPUTE}", "condition": []}]),
        _res("google_project_iam_member", "cloudbuild_run_admin", [
            {"project": PROJ, "role": "roles/run.admin", "member": f"serviceAccount:{DEV}", "condition": []}],
             module="module.cloud_build[0]"),
        _res("google_folder_iam_member", "folder_project_deleters", [
            {"folder": FOLDER, "role": "roles/resourcemanager.projectDeleter", "member": f"serviceAccount:{PROV}",
             "condition": []}]),
        _res("google_folder_iam_member", "folder_admins", [
            {"folder": FOLDER, "role": "roles/resourcemanager.folderAdmin", "member": f"serviceAccount:{PROV}",
             "condition": []}]),
        _res("google_folder_iam_member", "folder_project_creators", [
            {"folder": FOLDER, "role": "roles/resourcemanager.projectCreator", "member": f"serviceAccount:{e}",
             "condition": []} for e in (PROV, DEV)]),
        _res("google_tags_tag_key", "stackvend_managed", [{"id": TAG_KEY, "name": "777"}]),
        _res("google_tags_tag_value", "stackvend_managed_true", [{"id": TAG_VALUE, "name": "888"}]),
        # `.name` of the value is the bare numeric id (destructive_guard.tf comment): the check must normalize it.
        _res("google_tags_tag_value_iam_member", "stackvend_managed_vending_tag_user", [
            {"tag_value": "888", "role": "roles/resourcemanager.tagUser", "member": f"serviceAccount:{PROV}"}]),
        _res("google_service_account_iam_member", "gateway_self_sign_blob", [
            {"service_account_id": f"projects/{PROJ}/serviceAccounts/{DEV}",
             "role": "roles/iam.serviceAccountTokenCreator", "member": f"serviceAccount:{DEV}", "condition": []}]),
    ]}


def to_show_json(state):
    """The same state as `tofu show -json` prints it (values.root_module + child_modules)."""
    root, children = [], {}
    for r in state["resources"]:
        for inst in r["instances"]:
            item = {"mode": r["mode"], "type": r["type"], "name": r["name"], "values": inst["attributes"]}
            (children.setdefault(r["module"], []) if r.get("module") else root).append(item)
    return {"format_version": "1.0", "values": {"root_module": {
        "resources": root, "child_modules": [{"address": k, "resources": v} for k, v in children.items()]}}}


def _b(role, *members, cond=None):
    b = {"role": role, "members": list(members)}
    if cond:
        b["condition"] = {"expression": cond[0], "title": cond[1]}
    return b


ADMIN = "user:operator@example.com"


def clean_policies():
    """Live policies that hold exactly the Terraform grants plus what the check must NOT report."""
    sa_pols = {e: {"version": 1, "etag": "x"} for e in (CC, CLEANER, DEVOPS, PROV)}
    sa_pols[DEV] = {"bindings": [_b("roles/iam.serviceAccountTokenCreator", f"serviceAccount:{DEV}")]}
    return {
        "project": {"version": 3, "bindings": [
            _b("roles/datastore.user", *[f"serviceAccount:{e}" for e in (DEV, PROV, DEVOPS)],
               cond=(NOT_GUARD, "stackvend-not-guard-db")),
            _b("roles/datastore.user", f"serviceAccount:{CC}", f"serviceAccount:{PROV}",
               cond=(GUARD, "stackvend-guard-db-only")),
            _b("roles/storage.admin", f"serviceAccount:{COMPUTE}"),
            # case differences in e-mails are not findings
            _b("roles/run.admin", f"serviceAccount:{DEV.upper()}"),
            _b("roles/owner", ADMIN),                                           # administrator (inputs)
            _b("roles/editor", f"serviceAccount:{NUM}@cloudservices.gserviceaccount.com"),  # Google default
            _b("roles/run.serviceAgent", f"serviceAccount:service-{NUM}@serverless-robot-prod.iam.gserviceaccount.com"),
            _b("roles/aiplatform.user", f"serviceAccount:{sa('sa-stackvend-eval')}"),  # not guard-reaching
            _b("roles/viewer", "user:reader@example.com"),                      # not guard-reaching
            _b("roles/owner", "deleted:user:gone@example.com?uid=123"),         # deleted principal
        ]},
        "folder": {"version": 1, "bindings": [
            _b("roles/resourcemanager.projectDeleter", f"serviceAccount:{PROV}"),
            _b("roles/resourcemanager.folderAdmin", f"serviceAccount:{PROV}", ADMIN),
            _b("roles/resourcemanager.projectCreator", f"serviceAccount:{PROV}", f"serviceAccount:{DEV}"),
            _b("roles/resourcemanager.folderViewer", "user:reader@example.com"),
        ]},
        "billing": {"bindings": [
            # BG-1 installer fallback grants (scripts/bootstrap.sh gcloud path): not in state, still expected
            _b("roles/billing.user", f"serviceAccount:{PROV}", f"serviceAccount:{DEV}"),
            _b("roles/billing.viewer", f"serviceAccount:{CC}"),
            _b("roles/billing.admin", ADMIN),
        ]},
        "tag_key_0": {"etag": "x"},
        "tag_value_0": {"bindings": [_b("roles/resourcemanager.tagUser", f"serviceAccount:{PROV}"),
                                     _b("roles/resourcemanager.tagViewer", "user:reader@example.com")]},
        "sa": sa_pols,
    }


def inputs(**over):
    d = {"project": PROJ, "folder": "4242", "billing_account": "billingAccounts/" + BILLING.lower(),
         "organization": "organizations/123456789012", "admins": [ADMIN]}
    d.update(over)
    return d


FALLBACK = [("roles/billing.user", "sa-project-provisioner"), ("roles/billing.user", "sa-castor-developer"),
            ("roles/billing.viewer", "sa-stackvend-control-center")]


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fd4db-")
        self.state = make_state()
        self.pols = clean_policies()
        self.http = {}
        self.inputs = inputs()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_dir(self, d=None):
        """Lay the fakes out as the wrapper does: state.json, inputs.json, policies/<target name>.json|.http."""
        d = d or os.path.join(self.tmp, "evidence")
        pdir = os.path.join(d, "policies")
        os.makedirs(pdir, exist_ok=True)
        with open(os.path.join(d, "state.json"), "w") as f:
            json.dump(self.state, f)
        with open(os.path.join(d, "inputs.json"), "w") as f:
            json.dump(self.inputs, f)
        ps = iic.read_platform_state(self.state)
        for t in iic.build_targets(ps, self.inputs):
            pol = self.pols["sa"].get(t.scope) if t.kind == "service_account" else self.pols.get(t.name)
            if pol is not None:
                with open(os.path.join(pdir, t.name + ".json"), "w") as f:
                    json.dump(pol, f)
            if t.name in self.http:
                with open(os.path.join(pdir, t.name + ".http"), "w") as f:
                    f.write(self.http[t.name])
        return d

    def report(self, skip=(), admins=()):
        d = self.write_dir()
        return iic.analyze(self.state, self.inputs, os.path.join(d, "policies"), admins=admins,
                           billing_fallback=FALLBACK, skip_kinds=skip)

    def add(self, name, binding):
        self.pols[name].setdefault("bindings", []).append(binding)

    def only_finding(self, r):
        self.assertEqual(len(r.findings), 1, r.findings)
        self.assertEqual(r.exit_code, iic.EXIT_FINDINGS)
        return r.findings[0]


class TestAnalysis(_Fixture):
    def test_terraform_grants_and_known_defaults_are_clean(self):
        """Negative: exactly the Terraform set (+ admins, Google agents, installer billing, deleted, harmless)."""
        r = self.report()
        self.assertEqual(r.findings, [])
        self.assertEqual(r.unchecked, [])
        self.assertEqual(r.exit_code, iic.EXIT_CLEAN)
        c = r.counts
        self.assertEqual(c["bootstrap_billing"], 3)
        self.assertEqual(c["deleted_principal"], 1)
        self.assertGreaterEqual(c["administrator"], 3)
        self.assertEqual(c["google_agent"], 2)
        # every scope was read: project, folder, billing, tag key + value, 5 service accounts
        self.assertEqual(sorted({k for k, _s, st in r.checked if st == "ok"}),
                         ["billing", "folder", "project", "service_account", "tag_key", "tag_value"])
        self.assertEqual(sum(1 for k, _s, _st in r.checked if k == "service_account"), 5)

    def test_show_json_state_gives_the_same_answer(self):
        base = self.report()
        self.state = to_show_json(make_state())
        again = self.report()
        self.assertEqual(again.findings, [])
        self.assertEqual(again.counts, base.counts)
        self.assertEqual(again.expected_total, base.expected_total)

    def test_extra_owner_on_host_project(self):
        self.add("project", _b("roles/owner", "user:intruder@example.com"))
        f = self.only_finding(self.report())
        self.assertEqual((f.kind, f.scope, f.member, f.role), ("project", PROJ, "user:intruder@example.com",
                                                              "roles/owner"))
        self.assertIn("delete the host project", f.why)
        self.assertEqual(f.fix, f"gcloud projects remove-iam-policy-binding {PROJ} "
                                "--member=user:intruder@example.com --role=roles/owner --condition=None")

    def test_extra_owner_is_not_hidden_by_another_admin(self):
        """An administrator is one member, not a role: a second owner is still a finding."""
        self.add("project", _b("roles/owner", ADMIN, "group:everyone@example.com"))
        self.assertEqual(self.only_finding(self.report()).member, "group:everyone@example.com")

    def test_admin_flag_accepts_a_member(self):
        self.add("project", _b("roles/owner", "user:second-admin@example.com"))
        self.assertEqual(self.report(admins=["second-admin@example.com"]).exit_code, iic.EXIT_CLEAN)

    def test_foreign_sa_with_delete_role_on_folder(self):
        """FD-4CT items 2/3: another install's SA holds projectDeleter on the managed folder."""
        foreign = sa("sa-castor-developer", "other-install-1")
        self.add("folder", _b("roles/resourcemanager.projectDeleter", f"serviceAccount:{foreign}"))
        f = self.only_finding(self.report())
        self.assertEqual((f.kind, f.scope, f.role), ("folder", FOLDER, "roles/resourcemanager.projectDeleter"))
        self.assertIn("bypassing the decommission guard", f.why)
        self.assertIn("another project: other-install-1", f.why)
        self.assertTrue(f.fix.startswith("gcloud resource-manager folders remove-iam-policy-binding 4242 "), f.fix)

    def test_folder_admin_for_developer_sa_is_a_finding(self):
        """Lane 18 S0 dropped sa-castor-developer's folderAdmin: an out-of-band one is reported."""
        self.add("folder", _b("roles/resourcemanager.folderAdmin", f"serviceAccount:{DEV}"))
        f = self.only_finding(self.report())
        self.assertEqual((f.member, f.role), (f"serviceAccount:{DEV}", "roles/resourcemanager.folderAdmin"))

    def test_devops_folder_editor_out_of_band(self):
        """FD-4CT item 4: folder-wide Editor not declared (grant_devops_workloads_folder_editor off)."""
        self.add("folder", _b("roles/editor", f"serviceAccount:{DEVOPS}"))
        self.assertEqual(self.only_finding(self.report()).role, "roles/editor")

    def test_stackvend_sa_with_extra_role(self):
        """Any role beyond the Terraform set, even one that is harmless for other members."""
        self.add("project", _b("roles/viewer", f"serviceAccount:{DEVOPS}"))
        f = self.only_finding(self.report())
        self.assertEqual(f.member, f"serviceAccount:{DEVOPS}")
        self.assertEqual(f.why, iic.EXTRA_ROLE_REASON)

    def test_compute_sa_unconditioned_datastore_user(self):
        """FD-4CT item 1: the default compute SA (in Terraform for storage.admin) with guard-DB access."""
        self.add("project", _b("roles/datastore.user", f"serviceAccount:{COMPUTE}"))
        f = self.only_finding(self.report())
        self.assertIn("stackvend-guard database", f.why)

    def test_condition_is_part_of_the_grant(self):
        """The developer SA's datastore.user WITHOUT the not-guard-db condition is not its Terraform grant."""
        self.add("project", _b("roles/datastore.user", f"serviceAccount:{DEV}"))
        f = self.only_finding(self.report())
        self.assertEqual(f.condition, "")

    def test_conditional_extra_grant_names_its_condition(self):
        self.add("project", _b("roles/datastore.user", "user:dev@example.com", cond=("true", "anything")))
        f = self.only_finding(self.report())
        self.assertIn("conditional binding 'anything'", f.why)
        self.assertTrue(f.fix.endswith(" --condition=expression=true,title=anything"), f.fix)

    def test_tag_value_extra_tag_user(self):
        self.add("tag_value_0", _b("roles/resourcemanager.tagUser", "user:dev@example.com"))
        f = self.only_finding(self.report())
        self.assertEqual((f.kind, f.scope), ("tag_value", TAG_VALUE))
        self.assertTrue(f.fix.startswith(f"gcloud resource-manager tags values remove-iam-policy-binding {TAG_VALUE}"))

    def test_tag_key_admin(self):
        self.add("tag_key_0", _b("roles/resourcemanager.tagAdmin", "user:dev@example.com"))
        self.assertEqual(self.only_finding(self.report()).kind, "tag_key")

    def test_token_creator_on_a_destructive_executor(self):
        self.pols["sa"][PROV] = {"bindings": [_b("roles/iam.serviceAccountTokenCreator", "user:dev@example.com")]}
        f = self.only_finding(self.report())
        self.assertEqual((f.kind, f.scope), ("service_account", PROV))
        self.assertIn(f"gcloud iam service-accounts remove-iam-policy-binding {PROV} --project={PROJ}", f.fix)

    def test_billing_admin_and_unexpected_billing_user(self):
        self.add("billing", _b("roles/billing.admin", "user:dev@example.com"))
        self.add("billing", _b("roles/billing.user", f"serviceAccount:{DEVOPS}"))
        r = self.report()
        self.assertEqual(sorted((f.member, f.role) for f in r.findings),
                         [(f"serviceAccount:{DEVOPS}", "roles/billing.user"), ("user:dev@example.com",
                                                                              "roles/billing.admin")])
        self.assertTrue(all(f.fix.startswith(f"gcloud billing accounts remove-iam-policy-binding {BILLING} ")
                            and "--condition" not in f.fix for f in r.findings))

    def test_google_agent_destructive_role_is_reported(self):
        self.add("project", _b("roles/owner", f"serviceAccount:service-{NUM}@gcp-sa-cloudbuild.iam.gserviceaccount.com"))
        self.assertIn("never need", self.only_finding(self.report()).why)

    def test_other_projects_agent_is_not_exempt(self):
        """Only the HOST project's service agents are Google defaults here."""
        self.add("project", _b("roles/editor", "serviceAccount:999@cloudservices.gserviceaccount.com"))
        self.assertEqual(self.only_finding(self.report()).role, "roles/editor")

    def test_lookalike_agent_in_a_user_project_is_not_exempt(self):
        self.add("project", _b("roles/editor", f"serviceAccount:service-{NUM}x@{PROJ}.iam.gserviceaccount.com"))
        self.assertEqual(len(self.report().findings), 1)

    def test_unreadable_policy_is_could_not_check(self):
        self.http["billing"] = "403"
        r = self.report()
        self.assertEqual(r.exit_code, iic.EXIT_UNCHECKED)
        self.assertIn("billing", r.unchecked[0])
        self.assertIn("HTTP 403", iic.render_text(r))

    def test_findings_are_still_listed_when_a_scope_failed(self):
        self.http["folder"] = "403"
        self.add("project", _b("roles/owner", "user:intruder@example.com"))
        r = self.report()
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.exit_code, iic.EXIT_UNCHECKED)

    def test_missing_policy_is_could_not_check(self):
        del self.pols["tag_key_0"]
        self.assertEqual(self.report().exit_code, iic.EXIT_UNCHECKED)

    def test_skip_scope_is_not_a_failure(self):
        self.http["billing"] = "403"
        r = self.report(skip=iic.SKIP_CHOICES["billing"])
        self.assertEqual(r.exit_code, iic.EXIT_CLEAN)
        self.assertEqual(r.skipped, ["billing"])
        self.assertIn("skipped on request", iic.render_text(r))

    def test_no_folder_or_billing_configured(self):
        self.inputs = inputs(folder="", billing_account="")
        r = self.report()
        self.assertEqual({k for k, _s, _st in r.checked} & {"folder", "billing"}, set())
        self.assertEqual(r.exit_code, iic.EXIT_CLEAN)

    def test_state_of_another_install_is_refused(self):
        self.inputs = inputs(project="proj-bbbb2")
        with self.assertRaises(iic.CheckError):
            self.report()

    def test_state_without_service_accounts_is_refused(self):
        self.state["resources"] = [r for r in self.state["resources"] if r["type"] != "google_service_account"]
        with self.assertRaises(iic.CheckError):
            iic.read_platform_state(self.state)

    def test_not_a_state(self):
        with self.assertRaises(iic.CheckError):
            iic.read_platform_state({"hello": "world"})

    def test_bad_inputs_refused(self):
        for bad in (dict(project="Bad_Project"), dict(folder="folders/abc"), dict(billing_account="nope")):
            with self.assertRaises(iic.CheckError, msg=bad):
                iic.build_targets(iic.read_platform_state(self.state), inputs(**bad))

    def test_targets_are_read_only_google_api_calls(self):
        ts = iic.build_targets(iic.read_platform_state(self.state), self.inputs)
        self.assertEqual([t.name for t in ts][:5], ["project", "folder", "billing", "tag_key_0", "tag_value_0"])
        for t in ts:
            self.assertTrue(re.search(r":getIamPolicy(\?|$)", t.url), t.url)
            self.assertTrue(t.url.startswith(("https://cloudresourcemanager.googleapis.com/",
                                              "https://cloudbilling.googleapis.com/", "https://iam.googleapis.com/")))
        self.assertIn(f"/v3/projects/{PROJ}:getIamPolicy", ts[0].url)
        self.assertIn(f"/v1/billingAccounts/{BILLING}:getIamPolicy", ts[2].url)

    def test_text_report_is_a_table(self):
        self.add("project", _b("roles/owner", "user:intruder@example.com"))
        out = iic.render_text(self.report())
        self.assertIn("| # | Scope | Member | Role | Why it matters | Fix |", out)
        self.assertIn("| 1 | project proj-aaaa1 | user:intruder@example.com | roles/owner |", out)
        self.assertIn("gcloud organizations get-iam-policy 123456789012", out)

    def test_helper_has_no_network_or_process_code(self):
        with open(HELPER) as f:
            src = f.read()
        for bad in ("import subprocess", "import urllib", "import socket", "import http", "os.system", "requests"):
            self.assertNotIn(bad, src)


# ------------------------------------------------------------------------------
# The wrapper, offline mode (no gcloud, curl or tofu at all)
# ------------------------------------------------------------------------------
class TestWrapperOffline(_Fixture):
    def run_wrapper(self, *args):
        env = hermetic_guard.hermetic_env({"PATH": "/usr/bin:/bin", "HOME": self.tmp, "LANG": "C",
                                           "TMPDIR": self.tmp})
        r = subprocess.run(["/bin/bash", SCRIPT, *args], env=env, capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr

    def test_bash_syntax(self):
        r = subprocess.run(["/bin/bash", "-n", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_clean_exit_0(self):
        rc, out, err = self.run_wrapper(f"--offline={self.write_dir()}")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("Unexpected grants: none", out)
        self.assertIn("3 installer billing grants", out)   # the wrapper passes bootstrap's SA lists

    def test_finding_exit_1_and_json(self):
        self.add("project", _b("roles/owner", "user:intruder@example.com"))
        d = self.write_dir()
        rc, out, err = self.run_wrapper(f"--offline={d}")
        self.assertEqual(rc, 1, out + err)
        self.assertIn("user:intruder@example.com", out)
        rc, out, _err = self.run_wrapper(f"--offline={d}", "--json")
        self.assertEqual(rc, 1)
        body = json.loads(out)
        self.assertEqual([f["member"] for f in body["findings"]], ["user:intruder@example.com"])

    def test_admin_flag(self):
        self.add("project", _b("roles/owner", "user:intruder@example.com"))
        rc, out, err = self.run_wrapper(f"--offline={self.write_dir()}", "--admin=user:intruder@example.com")
        self.assertEqual(rc, 0, out + err)

    def test_unreadable_exit_2_and_skip(self):
        self.http["billing"] = "403"
        d = self.write_dir()
        rc, out, err = self.run_wrapper(f"--offline={d}")
        self.assertEqual(rc, 2, out + err)
        self.assertIn("COULD NOT CHECK", out)
        rc, out, err = self.run_wrapper(f"--offline={d}", "--skip=billing")
        self.assertEqual(rc, 0, out + err)

    def test_bad_state_exit_2(self):
        d = self.write_dir()
        with open(os.path.join(d, "state.json"), "w") as f:
            f.write("{not json")
        rc, _out, err = self.run_wrapper(f"--offline={d}")
        self.assertEqual(rc, 2)
        self.assertIn("could not check", err)

    def test_unknown_argument_exit_2(self):
        self.assertEqual(self.run_wrapper("--fix")[0], 2)
        self.assertEqual(self.run_wrapper("--skip=everything")[0], 2)

    def test_wrapper_never_mutates(self):
        """Static: no IAM write, no state write, no tofu init/plan/apply in the wrapper."""
        with open(SCRIPT) as f:
            src = "\n".join(l for l in f.read().splitlines() if not l.lstrip().startswith("#"))
        for bad in ("add-iam-policy-binding", "remove-iam-policy-binding", "set-iam-policy", "setIamPolicy",
                    " init", " apply", " plan", "storage cp", "storage rm", "objects update", "-X DELETE", "-X PATCH",
                    "-X PUT"):
            self.assertNotIn(bad, src)


# ------------------------------------------------------------------------------
# The wrapper, live mode, against stubs (lane 5 harness: stub gcloud / curl, real `tofu console` for the tfvars)
# ------------------------------------------------------------------------------
GCLOUD_STUB = r'''#!/bin/bash
echo "gcloud $*" >> "$STUB_LOG"
case "$*" in
  "auth print-access-token"*) echo "stub-token-value"; exit 0 ;;
  "storage cat gs://castor-tfstate-"*"/platform/state/default.tfstate") cat "$STUB_STATE"; exit 0 ;;
esac
exit 0
'''

# curl stub: the policy file is chosen by the URL (non-alphanumerics -> _); records whether the bearer token came on
# stdin (--config -) and never on argv.
CURL_STUB = r'''#!/bin/bash
echo "curl $*" >> "$STUB_LOG"
out=""; prev=""; url=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  case "$a" in https://*) url="$a" ;; esac
  prev="$a"
done
if grep -q '^header = "Authorization: Bearer stub-token-value"$'; then echo ok >> "$STUB_LOG.stdin"; fi
key="$(printf '%s' "$url" | tr -c 'A-Za-z0-9' '_')"
if [ -f "$STUB_POLICIES/$key.json" ]; then cat "$STUB_POLICIES/$key.json" > "$out"; printf 200; else printf 404; fi
exit 0
'''


def _url_key(url):
    return re.sub(r"[^A-Za-z0-9]", "_", url)


@unittest.skipUnless(lane5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestWrapperLive(lane5._Harness):
    def setUp(self):
        super().setUp()
        for name, body in (("gcloud", GCLOUD_STUB), ("curl", CURL_STUB)):
            with open(os.path.join(self.stub, name), "w") as f:
                f.write(body)
        self.write(f"infra/platform/{PROJ}.tfvars", lane5._tfvars(extra=(
            'castor_managed_workloads_folder_id = "folders/4242"\n'
            f'billing_account_id                 = "{BILLING}"\n'
            'organization_id                    = "organizations/123456789012"\n'
            'admin_email                        = "operator@example.com"\n')))
        self.state_file = os.path.join(self.tmp, "state.json")
        with open(self.state_file, "w") as f:
            json.dump(make_state(), f)
        self.pdir = os.path.join(self.tmp, "pols")
        os.makedirs(self.pdir)
        self.pols = clean_policies()

    def write_policies(self):
        ts = iic.build_targets(iic.read_platform_state(make_state()), inputs())
        for t in ts:
            pol = self.pols["sa"].get(t.scope) if t.kind == "service_account" else self.pols.get(t.name)
            with open(os.path.join(self.pdir, _url_key(t.url) + ".json"), "w") as f:
                json.dump(pol, f)
        return ts

    def run_check(self, *args):
        return self.run_script("check-install-iam.sh", list(args), PROJECT_ID=PROJ, STUB_STATE=self.state_file,
                               STUB_POLICIES=self.pdir)

    def test_live_clean_then_finding(self):
        ts = self.write_policies()
        rc, out, err = self.run_check()
        self.assertEqual(rc, 0, out + err)
        self.assertIn("Unexpected grants: none", out)
        calls = self.calls()
        self.assertEqual(sum(1 for c in calls if c.startswith("curl ")), len(ts))
        with open(self.log + ".stdin") as f:
            self.assertEqual(f.read().split(), ["ok"] * len(ts))   # the token went on stdin, every time
        joined = "\n".join(calls)
        self.assertNotIn("stub-token-value", joined)               # ...and never on a command line
        self.assertIn(f"gcloud storage cat gs://castor-tfstate-{PROJ}/platform/state/default.tfstate", joined)
        self.assertEqual([c for c in calls if c.startswith("gcloud ") and not c.startswith(
            ("gcloud storage cat ", "gcloud auth print-access-token"))], [])
        self.assertEqual(self.tofu_ops(), [])                      # only `tofu console` (logged separately)
        for c in calls:
            if c.startswith("curl "):
                self.assertRegex(c, r" -X (GET|POST) .*:getIamPolicy(\?options\.requestedPolicyVersion=3)?$")

        self.pols["project"]["bindings"].append(_b("roles/owner", "user:intruder@example.com"))
        self.write_policies()
        rc, out, err = self.run_check()
        self.assertEqual(rc, 1, out + err)
        self.assertIn("user:intruder@example.com", out)

    def test_live_admin_from_tfvars(self):
        """admin_email in the tfvars is an administrator: its owner grant is not a finding."""
        self.write_policies()
        rc, out, err = self.run_check("--json")
        self.assertEqual(rc, 0, out + err)
        self.assertGreaterEqual(json.loads(out)["not_reported"]["administrator"], 1)

    def test_live_no_state_exit_2(self):
        os.remove(self.state_file)
        self.write_policies()
        rc, out, err = self.run_check()
        self.assertEqual(rc, 2, out + err)

    def test_live_unreadable_policy_exit_2(self):
        ts = self.write_policies()
        os.remove(os.path.join(self.pdir, _url_key(ts[1].url) + ".json"))   # folder -> 404
        rc, out, err = self.run_check()
        self.assertEqual(rc, 2, out + err)
        self.assertIn("HTTP 404", out)


if __name__ == "__main__":
    unittest.main()

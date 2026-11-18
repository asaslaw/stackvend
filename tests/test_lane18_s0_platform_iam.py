import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""Wave 2 lane 18 S0 + S0b: host IAM split, ownership tag and guard database (infra/platform).

Two kinds of hermetic checks:

1. Static checks on infra/platform/*.tf and the deploy paths (text, no provider, no network).
2. A plan-level contract, tests/fixtures/lane18_s0/lane18_s0.tftest.hcl, run with `tofu test` and MOCK
   providers (in-memory state, no backend, no credentials; the hermetic child env points every proxy at a
   dead loopback port). It needs OpenTofu and a LOCAL provider mirror (google/google-beta 6.50.0,
   random 3.9.1): set STACKVEND_TOFU_PROVIDER_MIRROR to the mirror directory. Without both it is skipped;
   nothing is ever downloaded.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import test_platform_safe_apply_lane5 as lane5  # script harness (logging stubs for gcloud/tofu)
from owner_identifiers import find as find_owner_identifiers  # noqa: E402  (FD-12 digests)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
MODULES = os.path.join(REPO, "infra", "modules")
MAIN_TF = os.path.join(PLATFORM, "main.tf")
GUARD_TF = os.path.join(PLATFORM, "destructive_guard.tf")
TFTEST = os.path.join(HERE, "fixtures", "lane18_s0", "lane18_s0.tftest.hcl")
TOFU = shutil.which("tofu")
MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")

# Env names lane 18 S1 reads (apps/project-vending/destructive_guard.py, vending.py; S1 report).
S1_VENDING_ENV = {
    "STACKVEND_MANAGED_TAG_VALUE",
    "DESTRUCTIVE_CALLERS",
    "SANDBOX_TTL_CALLERS",
    "VENDING_SERVICE_URL",
    "STACKVEND_GUARD_FIRESTORE_DATABASE",
}


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _block(text, head):
    """Raw text of the top-level block that starts with `head {` (test-only brace matcher)."""
    start = text.index(head + " {")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError("unbalanced block " + head)


def _all_platform_tf():
    return {n: _read(os.path.join(PLATFORM, n)) for n in sorted(os.listdir(PLATFORM)) if n.endswith(".tf")}


class TestS0IdentitiesStatic(unittest.TestCase):
    def setUp(self):
        self.main = _read(MAIN_TF)
        self.guard = _read(GUARD_TF)

    def test_folder_delete_and_admin_roles_follow_the_vending_identity_only(self):
        for name in ("folder_project_deleters", "folder_admins"):
            blk = _strip_comments(_block(self.main, f'resource "google_folder_iam_member" "{name}"'))
            self.assertIn("local.folder_destructive_holders", blk, name)
            self.assertNotIn("sa-castor-developer", blk, name)
        holders = _block(self.guard, "locals")
        self.assertIn(
            'folder_destructive_holders = var.vending_runs_as_provisioner ? toset(["sa-project-provisioner"]) : '
            'toset(["sa-project-provisioner", "sa-castor-developer"])',
            holders,
        )

    def test_creator_roles_unchanged(self):
        for name in ("folder_project_creators", "folder_creators"):
            blk = _block(self.main, f'resource "google_folder_iam_member" "{name}"')
            self.assertIn('"sa-castor-developer"', blk)
            self.assertIn('"sa-project-provisioner"', blk)

    def test_runtime_service_accounts(self):
        svc = _block(self.main, 'resource "google_cloud_run_v2_service" "services"')
        self.assertIn('service_account = lookup(local.service_runtime_sa, each.key, google_service_account.agents["sa-castor-developer"].email)', svc)
        jobs = _block(self.main, 'resource "google_cloud_run_v2_job" "jobs"')
        self.assertIn('service_account = lookup(local.job_runtime_sa, each.key, google_service_account.agents["sa-castor-developer"].email)', jobs)
        locs = _block(self.guard, "locals")
        self.assertIn('"product-control-center-ui"    = local.cc_sa_email', locs)
        self.assertIn('"project-repo-vending-service" = local.vending_sa_email', locs)
        self.assertIn('"sandbox-garbage-collector-job" = local.cleaner_sa_email', locs)
        self.assertIn('vending_sa_key     = var.vending_runs_as_provisioner ? "sa-project-provisioner" : "sa-castor-developer"', locs)
        # tf-applier and the git server are not part of S0. The git server stays on sa-castor-developer; tf-applier
        # follows local.tf_applier_runtime_sa (FD-7L, SAT-33): sa-castor-developer until step B.
        self.assertRegex(_block(self.main, 'resource "google_cloud_run_v2_service" "git_server"'),
                         r'service_account\s*=\s*google_service_account\.agents\["sa-castor-developer"\]\.email')
        self.assertRegex(_block(self.main, 'resource "google_cloud_run_v2_job" "tf_applier"'),
                         r'service_account\s*=\s*local\.tf_applier_runtime_sa\n')
        runner = _read(os.path.join(PLATFORM, "tf_runner_identity.tf"))
        self.assertIn('tf_applier_runtime_sa        = var.tf_runner_dedicated_sa ? '
                      'google_service_account.tf_runners[local.tf_runner_job_account_id].email : '
                      'local.developer_sa_email', runner)

    def test_persona_accounts_use_stackvend_names_and_fit_the_id_limit(self):
        blk = _block(self.guard, 'resource "google_service_account" "stackvend_personas"')
        ids = re.findall(r'"(sa-[a-z0-9-]+)"\s*=', blk)
        self.assertEqual(sorted(ids), ["sa-stackvend-billing-drain", "sa-stackvend-control-center",   # + C10 jobs
                                       "sa-stackvend-finops-sync", "sa-stackvend-sandbox-cleaner",
                                       "sa-stackvend-sandbox-sweeper"])
        for i in ids:
            self.assertRegex(i, r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
            self.assertNotIn("castor", i)

    def test_every_component_still_declared(self):
        for name in (
            "spec-ingestion-service", "orchestrator-gateway-service", "mcp-terraform-server", "mcp-kubernetes-server",
            "mcp-gcloud-server", "mcp-github-toolserver", "mcp-workspace-connector", "mcp-infracost-server",
            "mcp-compliance-server", "project-repo-vending-service", "log-sre-sentinel-service",
            "mcp-agent-builder-server", "product-control-center-ui", "github-refactor-scanner-job",
            "qa-sandbox-test-runner", "finops-budget-enforcer-job", "infra-rollback-job",
            "sandbox-garbage-collector-job", "sre-telemetry-digest-job",
        ):
            self.assertIn(f'"{name}"', _block(self.main, "locals"), name)
        for head in ('resource "google_cloud_run_v2_job" "tf_applier"', 'resource "google_cloud_run_v2_service" "git_server"',
                     'resource "google_cloud_scheduler_job" "sandbox_ttl_cleaner"',
                     'resource "google_cloud_scheduler_job" "sandbox_workload_sweeper"'):
            self.assertIn(head, self.main)


class TestS0TagStatic(unittest.TestCase):
    def setUp(self):
        self.guard = _read(GUARD_TF)

    def test_tag_key_on_the_organization_with_value_true(self):
        key = _block(self.guard, 'resource "google_tags_tag_key" "stackvend_managed"')
        self.assertIn("parent      = local.organization", key)
        self.assertIn("prevent_destroy = true", key)
        val = _block(self.guard, 'resource "google_tags_tag_value" "stackvend_managed_true"')
        self.assertIn('short_name  = "true"', val)
        self.assertIn("prevent_destroy = true", val)

    def test_tag_user_only_for_the_vending_identity(self):
        blk = _block(self.guard, 'resource "google_tags_tag_value_iam_member" "stackvend_managed_vending_tag_user"')
        self.assertIn('role      = "roles/resourcemanager.tagUser"', blk)
        self.assertIn('member    = "serviceAccount:${local.vending_sa_email}"', blk)
        # Nowhere else in the platform configuration: no tagUser / tagAdmin grant, no binding by Terraform.
        for name, text in _all_platform_tf().items():
            body = _strip_comments(text)
            self.assertNotIn("roles/resourcemanager.tagAdmin", body, name)
            self.assertNotIn("google_tags_tag_binding", body, name)
            count = body.count("roles/resourcemanager.tagUser")
            self.assertEqual(count, 1 if name == "destructive_guard.tf" else 0, name)

    def test_tag_value_reaches_vending_env_from_the_resource(self):
        locs = _block(self.guard, "locals")
        self.assertIn("STACKVEND_MANAGED_TAG_VALUE        = local.managed_tag_value", locs)

    def test_env_tag_value_is_the_tagvalues_resource_name(self):
        """RT F1: S1 accepts only "tagValues/<digits>". In google 6.50.0 `.id` is that form ("tagValues/{{name}}");
        `.name` is the bare numeric id. The env (and output) must come from `.id`; the IAM member may use `.name`."""
        body = _strip_comments(_block(self.guard, "locals"))
        expr = re.search(r"^\s*managed_tag_value\s*=\s*(.+)$", body, re.M)
        self.assertIsNotNone(expr)
        self.assertEqual(expr.group(1).strip(),
                         'local.managed_tag_enabled ? google_tags_tag_value.stackvend_managed_true[0].id : ""')
        self.assertNotIn("stackvend_managed_true[0].name", expr.group(1))
        out = _read(os.path.join(PLATFORM, "outputs.tf"))
        self.assertIn("value       = local.managed_tag_value", _block(out, 'output "stackvend_managed_tag_value"'))
        tftest = _read(TFTEST)
        self.assertIn('values = { name = "281478392000", id = "tagValues/281478392000" }', tftest)
        self.assertIn('STACKVEND_MANAGED_TAG_VALUE           = "tagValues/281478392000"', tftest)

    def test_per_install_tag_key_name(self):
        locs = _block(self.guard, "locals")
        self.assertIn('"stackvend-managed-${var.project_id}"', locs)


class TestS0VendingEnvStatic(unittest.TestCase):
    def setUp(self):
        self.guard = _read(GUARD_TF)
        self.main = _read(MAIN_TF)

    def test_vending_env_contract(self):
        env = _block(self.guard, "locals")
        vend = env[env.index('"project-repo-vending-service" = {'):]
        vend = vend[:vend.index("}") + 1]
        keys = set(re.findall(r"^\s*([A-Z][A-Z0-9_]+)\s*=", vend, re.M))
        self.assertTrue(S1_VENDING_ENV <= keys, S1_VENDING_ENV - keys)
        self.assertIn("EPHEMERAL_TTL_CALLERS", keys)
        self.assertNotIn("EPHEMERAL_PRODUCERS", keys)  # lane 13's producer SA does not exist yet
        self.assertIn("DESTRUCTIVE_CALLERS                = local.cc_sa_email", vend)
        # C10 (owner 11-07): + the sandbox-workload-sweeper-job persona, for SANDBOX_TTL only (RT finding 1)
        self.assertIn('SANDBOX_TTL_CALLERS                = join(",", [local.cc_sa_email, local.sweeper_sa_email])', vend)
        self.assertIn("EPHEMERAL_TTL_CALLERS              = local.cleaner_sa_email", vend)
        self.assertIn("STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name", vend)

    def test_env_is_wired_into_the_services_block_and_empty_values_dropped(self):
        svc = _block(self.main, 'resource "google_cloud_run_v2_service" "services"')
        self.assertIn('for_each = { for k, v in lookup(local.guard_service_env, each.key, {}) : k => v if v != "" }', svc)

    def test_no_literal_ids_or_regions_in_guard_tf(self):
        body = _strip_comments(self.guard)
        self.assertIsNone(re.search(r"\b\d{6,}\b", body), "numeric project/folder/org id literal")
        self.assertNotIn("us-central1", body)
        # FD-12 (merged in lane18-window-v4): no owner install ids, checked by digest (tests/owner_identifiers.py).
        self.assertEqual(find_owner_identifiers(body), [])
        self.assertIsNone(re.search(r"(folders|organizations)/\d", body))

    def test_vending_folder_grants_follow_the_rollback_lever(self):
        """RT fix 5: vending-browser, vending-tagviewer and vending_legacy_revend use local.vending_sa_email."""
        readers = _strip_comments(_block(self.guard, 'resource "google_folder_iam_member" "guard_folder_readers"'))
        for key in ("vending-browser", "vending-tagviewer"):
            line = next(l for l in readers.splitlines() if f'"{key}"' in l)
            self.assertIn('member = "serviceAccount:${local.vending_sa_email}"', line, key)
        revend = _strip_comments(_block(self.guard, 'resource "google_folder_iam_member" "vending_legacy_revend"'))
        self.assertIn('member     = "serviceAccount:${local.vending_sa_email}"', revend)
        body = _strip_comments(self.guard)
        self.assertNotIn('google_service_account.agents["sa-project-provisioner"]', body)

    def test_git_server_allow_list_follows_the_split(self):
        gs = _block(self.main, 'resource "google_cloud_run_v2_service" "git_server"')
        self.assertIn('name  = "GIT_SERVER_ALLOWED_INVOKERS"', gs)
        self.assertIn("join(\",\", distinct([local.developer_sa_email, local.vending_sa_email, local.cc_sa_email]))", gs)


class TestS0bGuardDatabaseStatic(unittest.TestCase):
    def setUp(self):
        self.guard = _read(GUARD_TF)
        self.main = _read(MAIN_TF)

    def test_guard_database(self):
        db = _block(self.guard, 'resource "google_firestore_database" "stackvend_guard"')
        for needle in ('name        = local.guard_db_id', 'type        = "FIRESTORE_NATIVE"',
                       'point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"',
                       'delete_protection_state           = "DELETE_PROTECTION_ENABLED"',
                       'deletion_policy                   = "ABANDON"', "prevent_destroy = true"):
            self.assertIn(needle, db)
        self.assertIn('guard_db_id        = "stackvend-guard"', _block(self.guard, "locals"))

    def test_condition_is_exact_resource_name(self):
        locs = _block(self.guard, "locals")
        self.assertIn('guard_db_path      = "projects/${var.project_id}/databases/${local.guard_db_id}"', locs)
        self.assertIn(
            'guard_db_condition = "resource.name == \\"${local.guard_db_path}\\" || '
            'resource.name.startsWith(\\"${local.guard_db_path}/\\")"',
            locs,
        )

    def test_writers_are_cc_and_vending_only(self):
        w = _block(self.guard, 'resource "google_project_iam_member" "guard_db_writers"')
        for_each = w[w.index("for_each = {"):w.index("}")]
        self.assertEqual(re.findall(r"^\s*(\w+)\s*=\s*local\.(\w+)$", for_each, re.M), [("cc", "cc_sa_email"), ("vending", "vending_sa_email")])
        self.assertIn('role    = "roles/datastore.user"', w)
        self.assertIn("expression  = local.guard_db_condition", w)

    def test_readers_are_read_only(self):
        r = _block(self.guard, 'resource "google_project_iam_member" "guard_db_readers"')
        self.assertIn('role    = "roles/datastore.viewer"', r)
        self.assertIn("expression  = local.guard_db_condition", r)

    def test_every_other_datastore_grant_excludes_the_guard_db(self):
        agents = _block(self.main, 'resource "google_project_iam_member" "agent_datastore_users"')
        self.assertIn('expression  = "!(${local.guard_db_condition})"', agents)
        self.assertIn("create_before_destroy = true", agents)
        personas = _block(self.guard, 'resource "google_project_iam_member" "persona_datastore_users"')
        self.assertIn('expression  = "!(${local.guard_db_condition})"', personas)
        # No other unconditioned project-wide Firestore role anywhere in the platform config, nor in the host modules
        # it calls.
        tf_files = dict(_all_platform_tf())
        for mod in sorted(os.listdir(MODULES)):
            mdir = os.path.join(MODULES, mod)
            if os.path.isdir(mdir):
                tf_files.update({f"modules/{mod}/{n}": _read(os.path.join(mdir, n))
                                 for n in sorted(os.listdir(mdir)) if n.endswith(".tf")})
        checked = 0
        for name, text in tf_files.items():
            # custom roles carrying any datastore.* permission count like the predefined Firestore roles
            custom = [m.group(1) for m in re.finditer(r'resource "google_project_iam_custom_role" "(\w+)"', text)
                      if "datastore." in _block(text, f'resource "google_project_iam_custom_role" "{m.group(1)}"')]
            pattern = r'role\s*=\s*("roles/datastore\.(user|owner|viewer|importExportAdmin)"'
            pattern += "".join(rf"|google_project_iam_custom_role\.{c}(\[[^\]]*\])?\.(id|name)" for c in custom) + ")"
            for m in re.finditer(pattern, text):
                start = text.rfind("\nresource ", 0, m.start())
                head = text[start + 1:text.index("{", start)].strip()
                self.assertIn("condition {", _block(text, head), f"{name}: {head}")
                checked += 1
        self.assertGreater(checked, 0)

    def test_host_ledger_protected(self):
        db = _block(self.main, 'resource "google_firestore_database" "castor_state_db"')
        self.assertIn('delete_protection_state           = "DELETE_PROTECTION_ENABLED"', db)
        self.assertIn('point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"', db)
        self.assertIn('name        = "(default)"', db)


class TestStagedApplyStepA(unittest.TestCase):
    """RT fix 2: step A = `apply.sh apply -target=<CC service>` (no --allow-destroy). The services block must
    pull in every CC grant; the tftest run `step_a_targeted_control_center_canary` proves the closure."""

    def test_cc_grants_are_dependencies_of_the_services(self):
        svc = _strip_comments(_block(_read(MAIN_TF), 'resource "google_cloud_run_v2_service" "services"'))
        deps = svc[svc.index("depends_on = ["):svc.index("]", svc.index("depends_on = ["))]
        for dep in ("google_secret_manager_secret_iam_member.cc_secret_accessors", "google_project_iam_member.cc_project_roles",
                    "google_project_iam_member.persona_datastore_users", "google_project_iam_member.guard_db_writers",
                    "google_storage_bucket_iam_member.cc_state_admin", "google_folder_iam_member.guard_folder_readers",
                    "google_storage_bucket_iam_member.cc_state_viewer",  # SELFUP-STATE
                    "google_pubsub_topic_iam_member.cc_spec_intake_publisher",
                    "google_cloud_run_v2_service_iam_member.cc_git_server_invoker"):
            self.assertIn(dep, deps, dep)
        for never in ("agent_datastore_users", "folder_project_deleters", "folder_admins"):
            self.assertNotIn(never, deps, never)

    def test_apply_sh_allows_target(self):
        src = _read(os.path.join(REPO, "scripts", "apply.sh"))
        self.assertIn("apply:-target=*|", src)

    def test_tftest_has_the_targeted_run_first(self):
        tftest = _read(TFTEST)
        first = tftest.index('run "')
        self.assertTrue(tftest[first:].startswith('run "step_a_targeted_control_center_canary"'))
        self.assertIn('target = [google_cloud_run_v2_service.services["product-control-center-ui"]]', tftest)


class TestControlCenterBillingViewer(unittest.TestCase):
    """RT fix 4 (required): the Settings billing card calls billingAccounts.get as the CC's own SA."""

    def test_settings_card_uses_own_identity(self):
        src = _read(os.path.join(REPO, "apps", "control-center", "routes", "settings.py"))
        self.assertIn("cloudbilling.googleapis.com/v1/billingAccounts/", src)

    def test_bootstrap_grants_billing_viewer_to_the_cc_sa(self):
        src = _read(os.path.join(REPO, "scripts", "bootstrap.sh"))
        common = _read(os.path.join(REPO, "scripts", "common", "platform_target.sh"))
        self.assertIn('SV_BILLING_VIEWER_SA="sa-stackvend-control-center"', common)
        self.assertIn('CC_SA="serviceAccount:${SV_BILLING_VIEWER_SA}@${PROJECT_ID}.iam.gserviceaccount.com"', src)
        # The gcloud fallback (check could not run) tries the viewer grant like the two billing.user grants.
        self.assertIn('"${CC_SA}|roles/billing.viewer"', src)
        self.assertIn('--member="${BG_PAIR%%|*}" --role="${BG_PAIR#*|}"', src)
        # RC (owner 10-26, post-install billing access): declined / failed / not billing admin -> ONE helper prints
        # the exact viewer command (with the two billing.user ones); Terraform-granted path prints no viewer warning.
        viewer_cmd = ("--member=serviceAccount:${SV_BILLING_VIEWER_SA}@${PROJECT_ID}.iam.gserviceaccount.com "
                      "--role=roles/billing.viewer")
        self.assertEqual(src.count(viewer_cmd), 1)
        self.assertEqual(src.count('sv_billing_post_install_step "${CLEAN_BILLING}"'), 2)
        self.assertIn(viewer_cmd, common)   # apply.sh / preflight warning lists it too

    def test_terraform_billing_account_iam_is_bg1_only(self):
        """Before BG-1 platform TF never wrote billing-account IAM. BG-1 (owner 10-18) added billing_iam.tf:
        additive members only, roles/billing.user. BG-1-b (owner 10-20): plus ONE additive roles/billing.viewer
        member for the CC persona SA, same gate (bootstrap's gcloud grant stays as the fallback)."""
        for name, text in _all_platform_tf().items():
            body = _strip_comments(text)
            if name.endswith("billing_iam.tf"):
                self.assertNotIn("google_billing_account_iam_policy", body)
                self.assertNotIn("google_billing_account_iam_binding", body)
                self.assertEqual(body.count('resource "google_billing_account_iam_member"'), 2)
                self.assertIn('role               = "roles/billing.user"', body)
                self.assertEqual(body.count('role               = "roles/billing.viewer"'), 1)
                self.assertIn('member             = "serviceAccount:${local.cc_sa_email}"', body)
            else:
                self.assertNotIn("google_billing_account_iam", body, name)


class TestBootstrapBillingViewerRun(lane5._Harness):
    """Runs bootstrap.sh on a pty with lane 5's logging stubs (no gcloud, no tofu, no network): a billing
    account is given, so the CC SA gets roles/billing.viewer next to the two billing.user grants."""

    BILLING = "01ABCD-23EF45-6789AB"
    CC = f"serviceAccount:sa-stackvend-control-center@{lane5.PROJ}.iam.gserviceaccount.com"

    def _run(self, grant):
        plan_json = os.path.join(self.tmp, "plan.json")
        with open(plan_json, "w") as f:
            f.write(lane5._plan_json([["create"]]))
        # project, region, zone, org, billing, folder, env, mode, VCS, GitHub owner, ingress (Enter = Direct
        # IAP; always asked since install-polish), corp domain,
        # Control Center OAuth client (IAP: skip), tenant sign-in client (skip) [lane 19 L19-0d, merged in
        # lane18-window-v2], typed project id, billing grants?, deploy services?
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        answers = "\n".join([lane5.PROJ, "", "", "", self.BILLING, "", "y", "", "", "octo-org", "", "", "", "",
                             lane5.PROJ, grant, "n"])
        return self.run_script("bootstrap.sh", [], tty_input=answers, STUB_PLAN_JSON=plan_json)

    def _billing_calls(self):
        return [c for c in self.calls() if c.startswith("gcloud billing accounts add-iam-policy-binding")]

    def test_grant_includes_cc_billing_viewer(self):
        rc, out, err = self._run("Y")
        self.assertEqual(rc, 0, out + err)
        calls = self._billing_calls()
        self.assertIn(f"gcloud billing accounts add-iam-policy-binding {self.BILLING} --member={self.CC} --role=roles/billing.viewer --quiet", calls)
        self.assertEqual(len(calls), 3, calls)
        self.assertEqual(sum("roles/billing.user" in c for c in calls), 2, calls)
        self.assertNotIn(f"--member={self.CC} --role=roles/billing.user", "\n".join(calls))  # viewer only

    def test_declined_prints_the_required_command(self):
        rc, out, err = self._run("n")
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._billing_calls(), [])
        # Lane 18 v3 (L18-k3): never a required install step; Settings repeats it. RC (owner 10-26): printed as the
        # "Post-install step: billing access" block with the exact commands.
        self.assertIn("Post-install step: billing access", out + err)
        self.assertIn("the platform installed cleanly", out + err)
        self.assertNotIn("REQUIRED", out + err)
        self.assertIn("Control Center > Settings (billing card) shows which service account still lacks its grant", out + err)
        self.assertIn(f"gcloud billing accounts add-iam-policy-binding {self.BILLING} --member={self.CC} --role=roles/billing.viewer", out + err)


class TestDeployPathsKeepTerraformIdentity(unittest.TestCase):
    """A Cloud Build auto-deploy (installs with triggers) or deploy-services.sh (installs without) must not revert S0."""

    FORBIDDEN = ("--service-account", "--set-env-vars", "--update-env-vars", "--clear-env-vars",
                 "--remove-env-vars", "--env-vars-file", "--update-secrets", "--set-secrets")

    def _paths(self):
        return [
            os.path.join(REPO, "scripts", "deploy-services.sh"),
        ]

    def test_no_identity_or_env_flags(self):
        for p in self._paths():
            body = _read(p)
            for flag in self.FORBIDDEN:
                self.assertNotIn(flag, body, f"{p}: {flag}")

@unittest.skipUnless(TOFU and MIRROR and os.path.isdir(os.path.join(MIRROR, "registry.opentofu.org", "hashicorp", "google")),
                     "needs OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
class TestS0PlanContractMockProviders(unittest.TestCase):
    def test_tofu_test_contract(self):
        tmp = tempfile.mkdtemp(prefix="lane18-s0-")
        try:
            shutil.copytree(os.path.join(REPO, "infra"), os.path.join(tmp, "infra"),
                            ignore=shutil.ignore_patterns(".terraform*", "*.tfvars", "*.tfstate*"))
            shutil.copytree(os.path.join(REPO, "workflows"), os.path.join(tmp, "workflows"))
            # Lane 14 PR-8 / I10 (merged in lane18-window-v4): main.tf reads the Helm pin with file().
            os.makedirs(os.path.join(tmp, "mcp-servers", "kubernetes"))
            shutil.copy(os.path.join(REPO, "mcp-servers", "kubernetes", "helm-pin.json"),
                        os.path.join(tmp, "mcp-servers", "kubernetes"))
            plat = os.path.join(tmp, "infra", "platform")
            # tofu test destroys its in-memory state at the end; prevent_destroy (asserted statically above)
            # would block that teardown, so the throwaway copy turns it off.
            for n in os.listdir(plat):
                if n.endswith(".tf"):
                    p = os.path.join(plat, n)
                    text = _read(p)
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(text.replace("prevent_destroy = true", "prevent_destroy = false"))
            os.makedirs(os.path.join(plat, "tests"))
            shutil.copy(TFTEST, os.path.join(plat, "tests"))
            rc_file = os.path.join(tmp, "cli.tfrc")
            with open(rc_file, "w", encoding="utf-8") as f:
                f.write('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                        '    include = ["registry.opentofu.org/*/*"]\n  }\n}\n' % MIRROR)
            extra = {
                "TF_CLI_CONFIG_FILE": rc_file,
                "TF_DATA_DIR": os.path.join(tmp, "tfdata"),
                "TF_IN_AUTOMATION": "1",
            }
            # Provider plugins talk over a unix socket created in TMPDIR; macOS caps socket paths at 104 bytes,
            # so a long TMPDIR (agent scratch dirs) makes every provider fail its handshake.
            sock_dir = None
            if len(tempfile.gettempdir()) > 60:
                sock_dir = tempfile.mkdtemp(prefix="l18s0-", dir="/private/tmp" if os.path.isdir("/private/tmp") else "/tmp")
                extra["TMPDIR"] = sock_dir
            env = hermetic_guard.child_env(extra=extra)
            init = subprocess.run([TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=plat, env=env,
                                  capture_output=True, text=True, timeout=300)
            self.assertEqual(init.returncode, 0, init.stdout + init.stderr)
            res = subprocess.run([TOFU, "test", "-no-color"], cwd=plat, env=env, capture_output=True, text=True,
                                 timeout=600)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            # lane 18 v3: + installer_not_tag_admin_skips_only_the_tag, explicit_true_plans_the_tag
            # ORG-POLICY-FOLDER: + folder_vm_external_ip_policy_default_is_planned, ..._false_plans_nothing
            self.assertIn("8 passed, 0 failed", res.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            if "sock_dir" in locals() and sock_dir:
                shutil.rmtree(sock_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

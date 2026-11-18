import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""FD-7L Phase 7 (SAT-33) + FD-7L-n (SAT-35) + FD-4DA platform stamp: infra/platform runner identity, the step-B
readiness pre-check and the platform version stamp.

Hermetic checks:
1. Static checks on infra/platform/*.tf (text + the FD-09 block walker): the step-A inventory, that every existing
   resource keeps its identity and gets only appended env with the defaults (the plan-shape contract the owner's
   `apply.sh plan` must show), the step-B lever, the env contract SAT-19 reads, the stamp.
2. scripts/common/runner_identity_readiness.py: the signed bytes (golden vector = SAT-19's canonical_payload), the
   plan-switch detector, the readiness rules with a REAL RSA key and certificate made by the local openssl CLI
   (offline Firestore answers; no network), the CLI and the standalone script in offline mode.
3. scripts/common/install_iam_check.py FD-7L posture (state + offline policies).
4. sv_export_platform_stamp in a throwaway local git repository.
5. Plan-level contract tests/fixtures/fd7l_tf/fd7l_tf.tftest.hcl (`tofu test`, MOCK providers): skipped unless
   OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (a local provider mirror) are present; nothing is ever downloaded.
"""
import base64
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
MAIN_TF = os.path.join(PLATFORM, "main.tf")
GUARD_TF = os.path.join(PLATFORM, "destructive_guard.tf")
RUNNER_TF = os.path.join(PLATFORM, "tf_runner_identity.tf")
VARS_TF = os.path.join(PLATFORM, "variables.tf")
SCRIPTS = os.path.join(REPO, "scripts")
READINESS = os.path.join(SCRIPTS, "common", "runner_identity_readiness.py")
IAM_HELPER = os.path.join(SCRIPTS, "common", "install_iam_check.py")
TFTEST = os.path.join(HERE, "fixtures", "fd7l_tf", "fd7l_tf.tftest.hcl")
TOFU = shutil.which("tofu")
OPENSSL = shutil.which("openssl")
GIT = shutil.which("git")
MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")

SERVICES = 'resource "google_cloud_run_v2_service" "services"'
GIT_SERVER = 'resource "google_cloud_run_v2_service" "git_server"'
TF_APPLIER = 'resource "google_cloud_run_v2_job" "tf_applier"'
JOBS = 'resource "google_cloud_run_v2_job" "jobs"'


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_fd09 = _load("fd09_walker_fd7l", os.path.join(HERE, "test_platform_validate_fd09.py"))
attributes = _fd09.attributes
rd = _load("runner_identity_readiness", READINESS)
iic = _load("install_iam_check_fd7l", IAM_HELPER)


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _block(text, head):
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


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _resource_heads(text):
    return re.findall(r'^resource "([a-z0-9_]+)" "([a-z0-9_]+)"', text, re.M)


def _balanced_from(text, start):
    depth = 0
    for i in range(text.index("{", start), len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError("unbalanced block at %d" % start)


def _env_names(block):
    return set(re.findall(r"^\s*([A-Z][A-Z0-9_]*)\s*=", _strip_comments(block), re.M))


def _env_map(text, local_name):
    """Env names of a flat `local_name = { NAME = ... }` map in a locals block."""
    return _env_names(_block(text, local_name + " ="))


def _env_map_of_maps(text, local_name):
    """{component: env names} of a `local_name = { "component" = { NAME = ... } }` map in a locals block."""
    blk = _strip_comments(_block(text, local_name + " ="))
    out = {}
    for m in re.finditer(r'^\s*"([a-z0-9-]+)"\s*=\s*\{', blk, re.M):
        out[m.group(1)] = _env_names(_balanced_from(blk, m.start()))
    return out


# ==============================================================================================================
# 1. Static: step A inventory, inertness of existing resources, step B lever, env contract, stamp
# ==============================================================================================================
STEP_A_RESOURCES = [
    ("google_service_account", "tf_runners"),
    ("google_project_iam_custom_role", "stackvend_workflow_callback"),
    ("google_project_iam_custom_role", "stackvend_staging_create"),
    ("google_storage_bucket", "tf_runner_staging"),
    ("google_storage_bucket_iam_member", "tf_runner_staging_job_reader"),
    ("google_storage_bucket_iam_member", "tf_runner_staging_server_create"),
    ("google_project_iam_member", "tf_runner_project_roles"),
    ("google_project_iam_member", "tf_runner_datastore_users"),
    ("google_project_iam_member", "tf_runner_guard_db_readers"),
    ("google_cloud_run_v2_service_iam_member", "tf_runner_invokers"),
    ("google_cloud_run_v2_service_iam_member", "tf_runner_git_server_invoker"),
    ("google_service_account_iam_member", "vending_self_sign_blob"),
    ("google_service_account_iam_member", "vending_act_as_tf_applier"),
]


class TestStepAInventory(unittest.TestCase):
    def setUp(self):
        self.runner = _read(RUNNER_TF)
        self.code = _strip_comments(self.runner)

    def test_step_a_resources_are_exactly_the_plan_set(self):
        self.assertEqual(_resource_heads(self.runner), STEP_A_RESOURCES)

    def test_new_addresses_do_not_collide_with_existing_ones(self):
        others = set()
        for n in os.listdir(PLATFORM):
            if n.endswith(".tf") and n != "tf_runner_identity.tf":
                others.update(_resource_heads(_read(os.path.join(PLATFORM, n))))
        self.assertFalse(others & set(STEP_A_RESOURCES))

    def test_no_state_surgery_and_no_destroy_latch(self):
        for word in ("moved {", "removed {", "import {", "prevent_destroy", "data \""):
            self.assertNotIn(word, self.code, word)

    def test_runner_account_ids(self):
        sa = _block(self.runner, 'resource "google_service_account" "tf_runners"')
        self.assertEqual(sorted(re.findall(r'"(sa-[a-z0-9-]+)"\s*=', sa)), ["sa-stackvend-tf-applier", "sa-stackvend-tf-server"])
        for acc in ("sa-stackvend-tf-applier", "sa-stackvend-tf-server"):
            self.assertLessEqual(len(acc), 30)   # google_service_account.account_id limit

    def test_custom_roles_hold_one_permission_each(self):
        cb = _block(self.runner, 'resource "google_project_iam_custom_role" "stackvend_workflow_callback"')
        st = _block(self.runner, 'resource "google_project_iam_custom_role" "stackvend_staging_create"')
        self.assertIn('permissions = ["workflows.callbacks.send"]', cb)
        self.assertIn('role_id     = "stackvendWorkflowCallback"', cb)
        self.assertIn('permissions = ["storage.objects.create"]', st)
        self.assertIn('role_id     = "stackvendStagingCreate"', st)
        self.assertNotIn("stackvendTfApplierRun", self.code)   # fallback-design role: not built (broker chosen)

    def test_exact_grant_sets(self):
        roles = _block(self.runner, 'resource "google_project_iam_member" "tf_runner_project_roles"')
        self.assertEqual(sorted(re.findall(r'^\s*"([a-z-]+)"\s*=\s*\{', roles, re.M)),
                         ["job-log-writer", "job-workflow-callback", "server-log-writer", "server-workflow-callback"])
        self.assertEqual(roles.count('"roles/logging.logWriter"'), 2)
        self.assertEqual(roles.count("google_project_iam_custom_role.stackvend_workflow_callback.id"), 2)
        self.assertIn("google_project_iam_custom_role.stackvend_workflow_callback.id, member = local.tf_runner_job_member", roles)
        # Owner 11-01: the server's FD-7L Phase 5a watcher sends the typed FAILED callback (same role, same scope).
        self.assertIn("google_project_iam_custom_role.stackvend_workflow_callback.id, member = local.tf_runner_server_member", roles)
        inv = _block(self.runner, 'resource "google_cloud_run_v2_service_iam_member" "tf_runner_invokers"')
        self.assertEqual(sorted(re.findall(r'^\s*"([a-z:-]+)"\s*=\s*\{', inv, re.M)),
                         ["job:mcp-compliance-server", "job:project-repo-vending-service",
                          "server:project-repo-vending-service"])
        ds = _block(self.runner, 'resource "google_project_iam_member" "tf_runner_datastore_users"')
        self.assertIn('role    = "roles/datastore.user"', ds)
        self.assertIn('expression  = "!(${local.guard_db_condition})"', ds)
        gr = _block(self.runner, 'resource "google_project_iam_member" "tf_runner_guard_db_readers"')
        self.assertIn('role    = "roles/datastore.viewer"', gr)
        self.assertIn("expression  = local.guard_db_condition", gr)
        self.assertIn('role   = "roles/storage.objectViewer"',
                      _block(self.runner, 'resource "google_storage_bucket_iam_member" "tf_runner_staging_job_reader"'))
        self.assertIn("role   = google_project_iam_custom_role.stackvend_staging_create.id",
                      _block(self.runner, 'resource "google_storage_bucket_iam_member" "tf_runner_staging_server_create"'))

    def test_forbidden_rights_are_absent(self):
        for forbidden in ("roles/secretmanager", "google_secret_manager", "google_folder_iam", "google_organization_iam",
                          "roles/run.developer", "roles/run.admin", "roles/workflows.invoker", "roles/owner",
                          "roles/editor", "workload_tfstate_bucket", "roles/storage.objectAdmin",
                          "roles/billing", "agent_state_viewers", "agent_run_invokers"):
            self.assertNotIn(forbidden, self.code, forbidden)
        # The only token / act-as grants: vending on ITSELF, and the optional (default off) act-as on the job SA.
        self.assertEqual(self.code.count('"roles/iam.serviceAccountTokenCreator"'), 1)
        self_sign = _block(self.runner, 'resource "google_service_account_iam_member" "vending_self_sign_blob"')
        self.assertIn('service_account_id = google_service_account.agents["sa-project-provisioner"].name', self_sign)
        self.assertIn('member             = google_service_account.agents["sa-project-provisioner"].member', self_sign)
        self.assertIn("count              = var.vending_runs_as_provisioner ? 1 : 0", self_sign)
        act_as = _block(self.runner, 'resource "google_service_account_iam_member" "vending_act_as_tf_applier"')
        self.assertIn("count              = var.tf_runner_vending_act_as ? 1 : 0", act_as)
        self.assertIn('"roles/iam.serviceAccountUser"', act_as)

    def test_staging_bucket_is_private_and_short_lived(self):
        b = _block(self.runner, 'resource "google_storage_bucket" "tf_runner_staging"')
        for line in ('public_access_prevention    = "enforced"', "uniform_bucket_level_access = true",
                     "force_destroy               = false", "retention_duration_seconds = 0", "age = 1"):
            self.assertIn(line, b)
        self.assertIn('name                        = "stackvend-runner-staging-${var.project_id}"', b)
        self.assertLessEqual(len("stackvend-runner-staging-") + 30, 63)   # bucket name limit with a 30-char id


class TestExistingResourcesStayInertInStepA(unittest.TestCase):
    """With the defaults the owner's plan shows creates + in-place env ADDITIONS (and the CC stamp) only."""

    def setUp(self):
        self.main = _read(MAIN_TF)
        self.guard = _read(GUARD_TF)
        self.runner = _strip_comments(_read(RUNNER_TF))

    def test_variable_defaults_keep_todays_install(self):
        d = {p[0]: v for p, a, v in attributes(_read(VARS_TF)) if a == "default"}
        self.assertEqual(d['variable "tf_runner_identity"'], '"PLATFORM"')
        self.assertEqual(d['variable "tf_runner_dedicated_sa"'], "false")
        self.assertEqual(d['variable "tf_runner_vending_act_as"'], "false")
        self.assertEqual(d['variable "stackvend_platform_commit"'], '""')
        v = _block(_read(VARS_TF), 'variable "tf_runner_identity"')
        self.assertIn('contains(["PLATFORM", "PER_WORKLOAD"], var.tf_runner_identity)', v)

    def test_runtime_identities_change_only_with_the_lever(self):
        self.assertIn('tf_runner_service_runtime_sa = var.tf_runner_dedicated_sa ? { "mcp-terraform-server" = '
                      'google_service_account.tf_runners[local.tf_runner_server_account_id].email } : {}', self.runner)
        self.assertIn("tf_applier_runtime_sa        = var.tf_runner_dedicated_sa ? google_service_account.tf_runners"
                      "[local.tf_runner_job_account_id].email : local.developer_sa_email", self.runner)
        self.assertIn("}, local.tf_runner_service_runtime_sa)", self.guard)
        svc = _block(self.main, SERVICES)
        self.assertIn('service_account = lookup(local.service_runtime_sa, each.key, google_service_account.agents["sa-castor-developer"].email)', svc)
        self.assertRegex(_block(self.main, TF_APPLIER), r"service_account = local\.tf_applier_runtime_sa\n")
        self.assertRegex(_block(self.main, GIT_SERVER),
                         r'service_account\s*=\s*google_service_account\.agents\["sa-castor-developer"\]\.email')

    def test_member_lists_hold_developer_and_new_sa_until_step_b(self):
        self.assertIn("tf_runner_job_members    = var.tf_runner_dedicated_sa ? [local.tf_runner_job_sa_email] : "
                      "distinct([local.developer_sa_email, local.tf_runner_job_sa_email])", self.runner)
        self.assertIn("tf_runner_server_members = var.tf_runner_dedicated_sa ? [local.tf_runner_server_sa_email] : "
                      "distinct([local.developer_sa_email, local.tf_runner_server_sa_email])", self.runner)
        self.assertIn("git_server_runner_env = var.tf_runner_dedicated_sa ? { GIT_SERVER_READONLY_INVOKERS = "
                      "local.tf_runner_job_sa_email } : {}", self.runner)

    def test_env_values_are_known_at_plan_time(self):
        # Plain-string emails (the step-A plan shows each value); IAM members use the resource attribute.
        self.assertIn('tf_runner_job_sa_email    = "${local.tf_runner_job_account_id}@${var.project_id}.iam.gserviceaccount.com"', self.runner)
        self.assertIn('tf_runner_server_sa_email = "${local.tf_runner_server_account_id}@${var.project_id}.iam.gserviceaccount.com"', self.runner)
        for res in ("tf_runner_staging_job_reader", "tf_runner_staging_server_create"):
            self.assertNotIn("tf_runner_job_sa_email", _block(_read(RUNNER_TF), f'resource "google_storage_bucket_iam_member" "{res}"').split("member", 1)[1].split("\n")[0])

    def test_new_env_blocks_are_appended_last(self):
        svc = _block(self.main, SERVICES)
        containers = svc[svc.index("    containers {"):svc.index("    scaling {")]
        self.assertLess(containers.rindex("env {"), containers.index("local.tf_runner_service_env") + 200)
        self.assertGreater(containers.index("local.tf_runner_service_env"), containers.rindex('name  = "QA_SANDBOX_SA"'))
        job = _block(self.main, TF_APPLIER)
        self.assertGreater(job.index("local.tf_applier_runner_env"), job.index('name  = "GIT_SERVER_URL"'))
        git = _block(self.main, GIT_SERVER)
        self.assertGreater(git.index("local.git_server_runner_env"), git.index('name  = "GIT_SERVER_ALLOWED_INVOKERS"'))

    def test_env_contract_matches_the_vending_reader(self):
        env = _block(_read(RUNNER_TF), "locals")
        vend = env[env.index('"project-repo-vending-service" = {'):env.index('"mcp-terraform-server" = {')]
        self.assertEqual(sorted(re.findall(r"^\s*([A-Z_]+)\s*=", vend, re.M)),
                         ["STACKVEND_BROKER_SA", "STACKVEND_RUNNER_STAGING_BUCKET", "STACKVEND_TF_RUNNER_IDENTITY",
                          "STACKVEND_TF_RUNNER_MEMBERS", "STACKVEND_TF_SERVER_MEMBERS"])
        self.assertIn('STACKVEND_TF_RUNNER_MEMBERS     = join(",", local.tf_runner_job_members)', vend)
        self.assertIn("STACKVEND_BROKER_SA             = local.vending_sa_email", vend)
        # SAT-19 (shared/runner_identity.py, runner_broker.py) reads exactly these names and tokens.
        shared = os.path.join(REPO, "shared", "runner_identity.py")
        if os.path.exists(shared):
            src = _read(shared)
            for const in ('MODE_ENV = "STACKVEND_TF_RUNNER_IDENTITY"', 'MODE_PLATFORM = "PLATFORM"',
                          'MODE_PER_WORKLOAD = "PER_WORKLOAD"', 'BROKER_SA_ENV = "STACKVEND_BROKER_SA"',
                          'RUNNER_MEMBERS_ENV = "STACKVEND_TF_RUNNER_MEMBERS"',
                          'SERVER_MEMBERS_ENV = "STACKVEND_TF_SERVER_MEMBERS"'):
                self.assertIn(const, src)
        broker = os.path.join(REPO, "apps", "project-vending", "runner_broker.py")
        if os.path.exists(broker):
            self.assertIn('STAGING_BUCKET_ENV = "STACKVEND_RUNNER_STAGING_BUCKET"', _read(broker))

    def test_no_env_name_is_declared_twice_on_one_container(self):
        runner = _read(RUNNER_TF)
        # Services: the FD-7L names of each service vs the literal env of the services block and that service's guard
        # env (RT F2: STACKVEND_GUARD_FIRESTORE_DATABASE is new on mcp-terraform-server only; vending and the CC get it
        # from guard_service_env, so the FD-7L maps must not repeat it for them).
        literal = set(re.findall(r'name\s*=\s*"([A-Z_]+)"', _strip_comments(_block(self.main, SERVICES))))
        guard_svc = _env_map_of_maps(self.guard, "guard_service_env")
        runner_svc = _env_map_of_maps(runner, "tf_runner_service_env")
        self.assertEqual(sorted(runner_svc), ["mcp-terraform-server", "product-control-center-ui", "project-repo-vending-service"])
        for svc, names in runner_svc.items():
            # VENDING_SERVICE_URL is literal only for the CC (dynamic, keyed); new only on mcp-terraform-server.
            allowed = {"VENDING_SERVICE_URL"} if svc == "mcp-terraform-server" else set()
            self.assertFalse((names - allowed) & (literal | guard_svc.get(svc, set())), svc)
        self.assertIn("STACKVEND_GUARD_FIRESTORE_DATABASE", runner_svc["mcp-terraform-server"])
        self.assertNotIn("VENDING_SERVICE_URL", runner_svc["product-control-center-ui"])
        self.assertNotIn("VENDING_SERVICE_URL", runner_svc["project-repo-vending-service"])
        # tf-applier job.
        job_literal = set(re.findall(r'name\s*=\s*"([A-Z_]+)"', _strip_comments(_block(self.main, TF_APPLIER))))
        self.assertFalse(job_literal & _env_map(runner, "tf_applier_runner_env"))
        # Other jobs (RT F1): tf_runner_job_env vs the literal env of the jobs block and guard_job_env.
        jobs_literal = set(re.findall(r'name\s*=\s*"([A-Z_]+)"', _strip_comments(_block(self.main, JOBS))))
        guard_job = _env_map_of_maps(self.guard, "guard_job_env")
        for job, names in _env_map_of_maps(runner, "tf_runner_job_env").items():
            self.assertFalse(names & (jobs_literal | guard_job.get(job, set())), job)

    def test_runner_job_env_is_wired_last_in_the_jobs_block(self):
        jobs = _block(self.main, JOBS)
        self.assertIn("for_each = { for k, v in lookup(local.tf_runner_job_env, each.key, {}) : k => v if v != \"\" }", jobs)
        self.assertGreater(jobs.index("local.tf_runner_job_env"), jobs.index('name  = "GIT_SERVER_URL"'))
        containers = jobs[jobs.index("      containers {"):jobs.index("  lifecycle {")]
        self.assertLess(containers.rindex("env {"), containers.index("local.tf_runner_job_env") + 200)
        runner = _read(RUNNER_TF)
        self.assertEqual(_env_map_of_maps(runner, "tf_runner_job_env"),
                         {"infra-rollback-job": {"STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA",
                                                 "STACKVEND_GUARD_FIRESTORE_DATABASE"},
                          # C10: finops-spend-sync-job reads workload state like the CC (runner_state.py copy)
                          "finops-spend-sync-job": {"STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA",
                                                    "STACKVEND_GUARD_FIRESTORE_DATABASE"}})
        blk = _strip_comments(_block(runner, "tf_runner_job_env ="))
        self.assertIn("STACKVEND_TF_RUNNER_IDENTITY       = var.tf_runner_identity", blk)
        self.assertIn("STACKVEND_BROKER_SA                = local.vending_sa_email", blk)
        self.assertIn("STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name", blk)
        # No new IAM: the job keeps sa-castor-developer, which already reads the guard database.
        self.assertNotIn('"infra-rollback-job"', _block(self.guard, "job_runtime_sa ="))
        readers = _block(self.guard, 'resource "google_project_iam_member" "guard_db_readers"')
        self.assertIn("developer = local.developer_sa_email", readers)


# The runner-identity env a component's code reads (shared/runner_identity.py MODE_ENV, BROKER_SA_ENV) and what every
# such reader must get from the window code: the mode, the expected signer and the guard database the signed records
# live in (rollback.py resolve_state_bucket, services/runner_state.py, vending.py).
RUNNER_IDENTITY_ENV_NAMES = ("STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA")
RUNNER_READER_REQUIRED_ENV = {"STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA", "STACKVEND_GUARD_FIRESTORE_DATABASE"}
# Reader files that the component never imports (a replicated copy only). The test below proves they stay unimported;
# the day one is imported, the component must get the env too.
UNIMPORTED_READER_COPIES = {"apps/orchestrator-gateway": {"shared/express_synthesizer.py"}}


def _deployed_components():
    """{component: source dir} from scripts/common/components.sh SERVICES / JOBS (exact `name:dir` entries; the list
    deploy-services.sh and the upgrader share), plus tf-applier, which runs mcp-servers/terraform's applier module
    (main.tf args `-m applier`)."""
    text = _read(os.path.join(SCRIPTS, "common", "components.sh"))
    out = {}
    for arr, kind in (("SERVICES", "service"), ("JOBS", "job")):
        body = text[text.index(arr + "=(\n"):]
        body = body[:body.index("\n)")]
        for name, src in re.findall(r'^\s*"([a-z0-9-]+):([a-z0-9/_-]+)"\s*$', body, re.M):
            out[name] = (src, kind)
    out["tf-applier"] = ("mcp-servers/terraform", "tf_applier")
    return out


def _product_py_files(src_dir):
    root = os.path.join(REPO, src_dir)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("tests", "__pycache__", ".venv", "node_modules")]
        for fn in filenames:
            if fn.endswith(".py") and not fn.startswith("test_") and not fn.endswith("_test.py") and fn != "conftest.py":
                yield os.path.relpath(os.path.join(dirpath, fn), root)


def _string_constants(path):
    import ast
    tree = ast.parse(_read(path), filename=path)
    return {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _imported_modules(path):
    import ast
    tree = ast.parse(_read(path), filename=path)
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods.update(a.name.rsplit(".", 1)[-1] for a in n.names)
        elif isinstance(n, ast.ImportFrom):
            if n.module:
                mods.add(n.module.rsplit(".", 1)[-1])
            mods.update(a.name for a in n.names)
    return mods


def _runner_identity_readers():
    """{component: [reader files]}: components whose product code holds an exact string constant naming the
    runner-identity env (AST, not substring search)."""
    out = {}
    for comp, (src, _kind) in _deployed_components().items():
        hits = [rel for rel in _product_py_files(src)
                if set(RUNNER_IDENTITY_ENV_NAMES) & _string_constants(os.path.join(REPO, src, rel))]
        if hits:
            out[comp] = sorted(hits)
    return out


class TestEveryRunnerIdentityReaderGetsTheEnv(unittest.TestCase):
    """RT F1 regression: every deployed service / job whose code reads the runner-identity env gets the mode, the
    broker and the guard database from the window code (else a Per-workload install silently reads as Shared)."""

    def setUp(self):
        self.main = _read(MAIN_TF)
        self.guard = _read(GUARD_TF)
        self.runner = _read(RUNNER_TF)

    def _provided(self, comp, kind):
        if kind == "service":
            self.assertIn("lookup(local.tf_runner_service_env, each.key, {})", _block(self.main, SERVICES))
            self.assertIn("lookup(local.guard_service_env, each.key, {})", _block(self.main, SERVICES))
            return (_env_map_of_maps(self.runner, "tf_runner_service_env").get(comp, set())
                    | _env_map_of_maps(self.guard, "guard_service_env").get(comp, set()))
        if kind == "job":
            self.assertIn("lookup(local.tf_runner_job_env, each.key, {})", _block(self.main, JOBS))
            self.assertIn("lookup(local.guard_job_env, each.key, {})", _block(self.main, JOBS))
            return (_env_map_of_maps(self.runner, "tf_runner_job_env").get(comp, set())
                    | _env_map_of_maps(self.guard, "guard_job_env").get(comp, set()))
        self.assertEqual(kind, "tf_applier")
        self.assertIn("local.tf_applier_runner_env", _block(self.main, TF_APPLIER))
        self.assertIn('args    = ["python3", "-m", "applier"]', _block(self.main, TF_APPLIER))
        self.assertTrue(os.path.exists(os.path.join(REPO, "mcp-servers", "terraform", "applier.py")))
        return _env_map(self.runner, "tf_applier_runner_env")

    def test_the_scan_finds_the_known_readers(self):
        # Floor, so a broken scan cannot pass vacuously (main @ SAT-29: vending, CC, rollback, the terraform copy).
        readers = _runner_identity_readers()
        for comp in ("project-repo-vending-service", "product-control-center-ui", "infra-rollback-job",
                     "mcp-terraform-server", "tf-applier"):
            self.assertIn(comp, readers)

    def test_every_reader_gets_the_runner_identity_env(self):
        comps = _deployed_components()
        missing = {}
        for comp, files in _runner_identity_readers().items():
            src, kind = comps[comp]
            if set(files) <= UNIMPORTED_READER_COPIES.get(src, set()):
                continue
            lacking = RUNNER_READER_REQUIRED_ENV - self._provided(comp, kind)
            if lacking:
                missing[comp] = sorted(lacking)
        self.assertEqual(missing, {}, "components that read the runner identity but get no env from infra/platform")

    def test_unimported_reader_copies_stay_unimported(self):
        for src, copies in UNIMPORTED_READER_COPIES.items():
            mods = {os.path.splitext(os.path.basename(c))[0] for c in copies}
            for rel in _product_py_files(src):
                if rel in copies:
                    continue
                self.assertFalse(mods & _imported_modules(os.path.join(REPO, src, rel)),
                                 f"{src}/{rel} imports a runner-identity reader: give its component the env")

    def test_components_without_a_reader_get_no_runner_identity_env(self):
        # Do No Harm: the window adds the env only where code reads it.
        readers = _runner_identity_readers()
        for comp in _env_map_of_maps(self.runner, "tf_runner_service_env"):
            self.assertIn(comp, readers)
        for comp in _env_map_of_maps(self.runner, "tf_runner_job_env"):
            self.assertIn(comp, readers)

    def test_step_b_preconditions(self):
        cond = ('condition     = !var.tf_runner_dedicated_sa || (var.tf_runner_identity == "PER_WORKLOAD" && '
                'var.vending_runs_as_provisioner)')
        self.assertIn(cond, _block(self.main, SERVICES))
        self.assertIn(cond, _block(self.main, TF_APPLIER))

    def test_step_b_waits_for_the_grants(self):
        svc = _block(self.main, SERVICES)
        dep = svc[svc.index("depends_on = ["):svc.index("]")]
        for r in ("google_project_iam_member.tf_runner_project_roles", "google_project_iam_member.tf_runner_datastore_users",
                  "google_project_iam_member.tf_runner_guard_db_readers",
                  "google_storage_bucket_iam_member.tf_runner_staging_server_create"):
            self.assertIn(r, dep)
        self.assertNotIn("tf_runner_invokers", dep)   # they reference the services (would be a cycle)
        job = _block(self.main, TF_APPLIER)
        self.assertIn("google_storage_bucket_iam_member.tf_runner_staging_job_reader", job[:job.index("]")])


class TestPlatformStampTf(unittest.TestCase):
    def setUp(self):
        self.main = _read(MAIN_TF)

    def test_annotations_are_service_level_cc_only_and_managed(self):
        svc = _block(self.main, SERVICES)
        top = [v for p, a, v in attributes(self.main) if p == (SERVICES,) and a == "annotations"]
        self.assertEqual(top, ['(each.key == "product-control-center-ui" && length(local.platform_stamp_annotations) > 0) '
                               '? local.platform_stamp_annotations : null'])
        self.assertFalse([p for p, a, _ in attributes(self.main) if p[:2] == (SERVICES, "template") and a == "annotations"])
        ic = svc[svc.index("ignore_changes = ["):]
        ic = ic[:ic.index("]")]
        self.assertNotIn("annotations", ic)

    def test_stamp_values(self):
        self.assertIn('platform_release_file = "${path.module}/../../VERSION"', self.main)
        self.assertIn('"stackvend/platform-release" = local.platform_release', self.main)
        self.assertIn('"stackvend/platform-commit" = var.stackvend_platform_commit', self.main)
        self.assertTrue(_read(os.path.join(REPO, "VERSION")).strip())
        v = _block(_read(VARS_TF), 'variable "stackvend_platform_commit"')
        self.assertIn('can(regex("^([0-9a-f]{40}(\\\\+dirty)?)?$", var.stackvend_platform_commit))', v)

    def test_apply_wrapper_flags_unchanged_and_stamp_internal(self):
        apply_sh = _read(os.path.join(SCRIPTS, "apply.sh"))
        self.assertIn("plan:-target=*|plan:-replace=*|plan:-detailed-exitcode|plan:-no-color|plan:-compact-warnings|"
                      "plan:-parallelism=*|plan:-refresh-only|plan:-destroy) ok=1 ;;", apply_sh)
        self.assertNotIn("-var=", apply_sh.replace("Never allowed: -var,", ""))
        pt = _read(os.path.join(SCRIPTS, "common", "platform_target.sh"))
        self.assertIn("TF_VAR_*|TF_CLI_ARGS|", pt)   # a caller's TF_VAR_* is still refused
        gated = pt[pt.index("sv_gated_apply() {"):]
        self.assertLess(gated.index("sv_export_platform_stamp"), gated.index('"${IAC_BIN}" plan'))
        plan_branch = apply_sh[apply_sh.index("    plan)\n"):apply_sh.index("    apply)\n")]
        self.assertLess(plan_branch.index("sv_export_platform_stamp"), plan_branch.index('"${IAC_BIN}" plan'))


# ==============================================================================================================
# 2. Readiness helper
# ==============================================================================================================
HOST = "host-proj-1"
BROKER = f"sa-project-provisioner@{HOST}.iam.gserviceaccount.com"

GOLDEN = ('{"doc":"workload_provenance/prod-a#runner_identity","record":{"deployer_email":"stackvend-deployer@child-'
          'proj-1.iam.gserviceaccount.com","error_class":null,"migration":null,"product_id":"prod-a","project_id":"chi'
          'ld-proj-1","project_number":"123456789012","repository":{"full_name":"org/repo","id":42,"provider":"GITHUB"'
          '},"schema":"runner_identity/v1","signed_at":"2026-10-31T12:00:01+00:00","signed_by":"sa-project-provisioner'
          '@host-proj-1.iam.gserviceaccount.com","state_bucket":"child-proj-1-tfstate","state_prefix":"workloads/prod-'
          'a","status":"READY","updated_at":"2026-10-31T12:00:00+00:00"}}')


def _record(pid="prod-a", project="child-proj-1", status="READY", bucket=None, error_class=None, signer=BROKER):
    return {"schema": "runner_identity/v1", "product_id": pid, "project_id": project, "project_number": "123456789012",
            "deployer_email": f"stackvend-deployer@{project}.iam.gserviceaccount.com",
            "state_bucket": bucket if bucket is not None else f"{project}-tfstate", "state_prefix": f"workloads/{pid}",
            "repository": {"full_name": "org/repo", "id": 42, "provider": "GITHUB"}, "status": status,
            "migration": None, "error_class": error_class, "updated_at": "2026-10-31T12:00:00+00:00",
            "signed_by": signer, "signed_at": "2026-10-31T12:00:01+00:00"}


def _fs(value):
    """Python value -> Firestore REST Value."""
    if value is None:
        return {"nullValue": None}
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int):
        return {"integerValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, list):
        return {"arrayValue": {"values": [_fs(v) for v in value]}}
    return {"mapValue": {"fields": {k: _fs(v) for k, v in value.items()}}}


class _Keys:
    """A real RSA key + self-signed certificate made by the local openssl CLI (no network)."""

    def __init__(self, work):
        self.work = work
        self.key = os.path.join(work, "key.pem")
        self.cert = os.path.join(work, "cert.pem")
        subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", self.key, "-out",
                        self.cert, "-days", "1", "-subj", "/CN=fd7l-test"], check=True, capture_output=True,
                       timeout=60)
        self.cert_pem = _read(self.cert)

    def sign(self, payload: bytes) -> str:
        data = os.path.join(self.work, "data.bin")
        sig = os.path.join(self.work, "sig.bin")
        with open(data, "wb") as f:
            f.write(payload)
        subprocess.run([OPENSSL, "dgst", "-sha256", "-sign", self.key, "-out", sig, data], check=True,
                       capture_output=True, timeout=60)
        with open(sig, "rb") as f:
            return base64.b64encode(f.read()).decode("ascii")


def _signed(keys, rec, pid=None, key_id="k1"):
    pid = pid or rec["product_id"]
    out = dict(rec)
    out["signature"] = {"alg": "RS256", "key_id": key_id,
                        "value": keys.sign(rd.canonical_payload(rd.provenance_doc_path(pid), rec))}
    return out


class TestCanonicalPayload(unittest.TestCase):
    def test_golden_vector_equals_sat19_canonical_payload(self):
        rec = _record()
        rec["signature"] = {"alg": "RS256", "key_id": "k", "value": "AAAA"}   # never part of the signed bytes
        self.assertEqual(rd.canonical_payload(rd.provenance_doc_path("prod-a"), rec).decode("ascii"), GOLDEN)

    def test_parity_with_shared_runner_identity_when_present(self):
        shared = os.path.join(REPO, "shared", "runner_identity.py")
        if not os.path.exists(shared):
            self.skipTest("shared/runner_identity.py (SAT-19) is not on this branch yet; the golden vector pins it")
        ri = _load("shared_runner_identity_fd7l", shared)
        rec = _record()
        self.assertEqual(ri.canonical_payload(ri.provenance_doc_path("prod-a"), rec),
                         rd.canonical_payload(rd.provenance_doc_path("prod-a"), rec))
        self.assertEqual(ri.SCHEMA, rd.SCHEMA)
        self.assertEqual(ri.DEPLOYER_ACCOUNT_ID, rd.DEPLOYER_ACCOUNT_ID)

    def test_floats_are_never_signed(self):
        with self.assertRaises(ValueError):
            rd.canonical_payload("x", {"a": 1.5})


def _plan(address, before, after, actions=("update",), unknown=False, job=True):
    def wrap(sa):
        return {"template": [{"template": [{"service_account": sa}]}]} if job else {"template": [{"service_account": sa}]}
    au = ({"template": [{"template": [{"service_account": True}]}]} if job else {"template": [{"service_account": True}]}) if unknown else {}
    return {"resource_changes": [{"address": address, "change": {"actions": list(actions), "before": wrap(before) if before else None,
                                                                  "after": wrap(after), "after_unknown": au}}]}


DEV = f"sa-castor-developer@{HOST}.iam.gserviceaccount.com"
JOB = f"sa-stackvend-tf-applier@{HOST}.iam.gserviceaccount.com"
SRV = f"sa-stackvend-tf-server@{HOST}.iam.gserviceaccount.com"
JOB_ADDR = "google_cloud_run_v2_job.tf_applier"
SRV_ADDR = 'google_cloud_run_v2_service.services["mcp-terraform-server"]'


class TestPlanSwitch(unittest.TestCase):
    def test_step_b_switch_is_detected(self):
        self.assertTrue(rd.plan_switches(_plan(JOB_ADDR, DEV, JOB)))
        self.assertTrue(rd.plan_switches(_plan(SRV_ADDR, DEV, SRV, job=False)))
        self.assertTrue(rd.plan_switches(_plan(JOB_ADDR, DEV, None, unknown=True)))   # SA created in the same plan
        self.assertTrue(rd.plan_switches(_plan(JOB_ADDR, DEV, JOB, actions=("delete", "create"))))

    def test_negatives_step_a_new_install_rollback_other_resources(self):
        self.assertEqual(rd.plan_switches(_plan(JOB_ADDR, DEV, DEV)), [])               # step A: env-only update
        self.assertEqual(rd.plan_switches(_plan(JOB_ADDR, None, JOB, actions=("create",))), [])   # new install
        self.assertEqual(rd.plan_switches(_plan(JOB_ADDR, JOB, DEV)), [])               # rollback lever
        self.assertEqual(rd.plan_switches(_plan(JOB_ADDR, DEV, DEV, actions=("no-op",))), [])
        other = 'google_cloud_run_v2_service.services["orchestrator-gateway-service"]'
        self.assertEqual(rd.plan_switches(_plan(other, DEV, SRV, job=False)), [])
        self.assertEqual(rd.plan_switches({}), [])

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "plan.json")
            with open(p, "w") as f:
                json.dump(_plan(JOB_ADDR, DEV, JOB), f)
            self.assertEqual(rd.main(["plan-switch", "--plan", p]), rd.EXIT_SWITCH)
            with open(p, "w") as f:
                json.dump(_plan(JOB_ADDR, DEV, DEV), f)
            self.assertEqual(rd.main(["plan-switch", "--plan", p]), rd.EXIT_READY)
            self.assertEqual(rd.main(["plan-switch", "--plan", os.path.join(d, "missing.json")]), rd.EXIT_UNCHECKED)


def _ledger(**workloads):
    docs = []
    for pid, fields in workloads.items():
        docs.append({"name": f"projects/{HOST}/databases/(default)/documents/workloads/{pid}",
                     "fields": {k: _fs(v) for k, v in fields.items()}})
    return {"documents": docs}


def _prov(**records):
    docs = []
    for pid, fields in records.items():
        docs.append({"name": f"projects/{HOST}/databases/stackvend-guard/documents/workload_provenance/{pid}",
                     "fields": {k: (v if isinstance(v, dict) and len(v) == 1 and next(iter(v)).endswith("Value") else _fs(v))
                                for k, v in fields.items()}})
    return {"documents": docs}


@unittest.skipUnless(OPENSSL, "needs the openssl command line (signature verification)")
class TestReadiness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.mkdtemp(prefix="fd7l-keys-")
        cls.keys = _Keys(cls.work)
        cls.other = _Keys(tempfile.mkdtemp(prefix="fd7l-keys2-", dir=cls.work))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def _dir(self, ledger, prov, certs=None, codes=None):
        d = tempfile.mkdtemp(prefix="fd7l-off-", dir=self.work)
        for name, body in (("workloads", ledger), ("provenance", prov),
                           ("certs", certs if certs is not None else {"k1": self.keys.cert_pem})):
            with open(os.path.join(d, name + ".json"), "w") as f:
                json.dump(body, f)
        for name, code in (codes or {}).items():
            with open(os.path.join(d, name + ".http"), "w") as f:
                f.write(str(code))
        return d

    def _run(self, ledger, prov, **kw):
        return rd.readiness(rd.offline_fetcher(self._dir(ledger, prov, **kw)), HOST, BROKER)

    def _state(self, rep, pid):
        return [r["runner_identity"] for r in rep["workloads"] if r["product_id"] == pid][0]

    def test_ready_record_passes(self):
        rep = self._run(_ledger(**{"prod-a": {"status": "DEPLOYED", "project_id": "child-proj-1"}}),
                        _prov(**{"prod-a": {"project_id": "child-proj-1", "runner_identity": _signed(self.keys, _record())}}))
        self.assertEqual((rep["live_workloads"], rep["ready"], rep["not_ready"]), (1, 1, 0))

    def test_every_tamper_is_refused(self):
        good = _signed(self.keys, _record())
        changed = dict(good, state_bucket="child-proj-1-tfstate-abcdef")          # field change after signing
        wrong_key = _signed(self.other, _record())                               # e.g. written by the CC SA
        forged_signer = _signed(self.keys, _record(signer="sa-stackvend-control-center@host-proj-1.iam.gserviceaccount.com"))
        unsigned = {k: v for k, v in good.items() if k != "signature"}
        swapped = _signed(self.keys, _record(pid="prod-b", project="child-proj-1"), pid="prod-b")  # path swap
        unknown_key = dict(good, signature=dict(good["signature"], key_id="k9"))
        cases = {"t-changed": changed, "t-wrongkey": wrong_key, "t-signer": forged_signer, "t-unsigned": unsigned,
                 "t-swap": swapped, "t-unknownkey": unknown_key}
        ledger = _ledger(**{pid: {"status": "DEPLOYED", "project_id": "child-proj-1"} for pid in cases})
        prov = _prov(**{pid: {"project_id": "child-proj-1", "runner_identity": rec} for pid, rec in cases.items()})
        rep = self._run(ledger, prov)
        self.assertEqual(rep["ready"], 0)
        for pid in cases:
            self.assertEqual(self._state(rep, pid), "UNSIGNED", pid)

    def test_not_ready_and_mismatch(self):
        recs = {
            "p-failed": _signed(self.keys, _record(pid="p-failed", status="FAILED", error_class="VENDING.STATE_BUCKET_FAILED")),
            "p-migrating": _signed(self.keys, _record(pid="p-migrating", status="MIGRATING")),
            "p-err": _signed(self.keys, _record(pid="p-err", error_class="X")),
            "p-bucket": _signed(self.keys, _record(pid="p-bucket", bucket="someone-elses-bucket")),
            "p-project": _signed(self.keys, _record(pid="p-project", project="other-proj-9")),
        }
        ledger = _ledger(**{pid: {"status": "DEPLOYED", "project_id": "child-proj-1"} for pid in recs})
        prov = _prov(**{pid: {"project_id": "child-proj-1", "runner_identity": rec} for pid, rec in recs.items()})
        rep = self._run(ledger, prov)
        self.assertEqual(self._state(rep, "p-failed"), "NOT_READY")
        self.assertEqual(self._state(rep, "p-migrating"), "NOT_READY")
        self.assertEqual(self._state(rep, "p-err"), "NOT_READY")
        self.assertEqual(self._state(rep, "p-bucket"), "MISMATCH")
        self.assertEqual(self._state(rep, "p-project"), "MISMATCH")

    def test_missing_records_and_unsigned_value_types(self):
        with_double = _signed(self.keys, _record(pid="p-dbl"))
        prov = _prov(**{"p-noid": {"project_id": "child-proj-1"},
                        "p-dbl": {"project_id": "child-proj-1",
                                  "runner_identity": {"mapValue": {"fields": dict(
                                      {k: _fs(v) for k, v in with_double.items()},
                                      project_number={"doubleValue": 1.0})}}},
                        "p-provmis": {"project_id": "another-proj-1", "runner_identity": _signed(self.keys, _record(pid="p-provmis"))}})
        ledger = _ledger(**{p: {"status": "DEPLOYED", "project_id": "child-proj-1"}
                            for p in ("p-none", "p-noid", "p-dbl", "p-provmis")})
        rep = self._run(ledger, prov)
        self.assertEqual(self._state(rep, "p-none"), "NO_PROVENANCE")
        self.assertEqual(self._state(rep, "p-noid"), "NO_RUNNER_IDENTITY")
        self.assertEqual(self._state(rep, "p-dbl"), "UNSIGNED")
        self.assertEqual(self._state(rep, "p-provmis"), "MISMATCH")

    def test_only_live_vended_workloads_count(self):
        ledger = _ledger(**{
            "p-closed": {"status": "DECOMMISSIONED", "project_id": "child-proj-1"},
            "p-deleted": {"status": "DELETED", "project_id": "child-proj-1"},
            "p-archived": {"status": "ARCHIVED", "project_id": "child-proj-1"},   # SAT-40: archive follows decommission
            "platform": {"status": "DEPLOYED", "project_id": HOST},
            "p-castor": {"status": "DEPLOYED", "project_id": HOST, "is_castor": True},
            "p-unvended": {"status": "PENDING"},
        })
        rep = self._run(ledger, _prov(), certs={})
        self.assertEqual(rep["live_workloads"], 0)
        self.assertEqual(rep["not_ready"], 0)    # zero live workloads: ready (and no certificate read needed)

    def test_every_other_status_with_a_project_still_counts(self):
        """SAT-40 negative test: only DECOMMISSIONED / DELETED / ARCHIVED (exact values) leave the check; every other
        status with a project, including a stuck vend and a lower-case look-alike, is still a live workload."""
        statuses = ("DEPLOYED", "PROVISIONED", "PROVISIONING", "FAILED", "ACTIVE", "archived", "ARCHIVED_", None)
        ledger = _ledger(**{f"p-{i}": dict({"project_id": "child-proj-1"}, **({"status": s} if s else {}))
                            for i, s in enumerate(statuses)})
        rep = self._run(ledger, _prov())
        self.assertEqual(rep["live_workloads"], len(statuses))
        self.assertEqual({r["runner_identity"] for r in rep["workloads"]}, {"NO_PROVENANCE"})

    def test_closed_set_matches_the_phase0_script(self):
        """SAT-40: scripts/fd7l-phase0/phase0_reads.sh skips the same closed statuses as this check."""
        src = open(os.path.join(SCRIPTS, "fd7l-phase0", "phase0_reads.sh")).read()
        m = re.search(r'val\(f\.get\("status"\)\) in \(([^)]*)\)', src)
        self.assertIsNotNone(m)
        self.assertEqual(set(re.findall(r'"([A-Z_]+)"', m.group(1))), set(rd.CLOSED_STATUSES))
        self.assertEqual(rd.CLOSED_STATUSES, frozenset({"DECOMMISSIONED", "DELETED", "ARCHIVED"}))
        # option G: the same exact pending-deletion states, from the typed lifecycleState field, as a whole-word case
        m = re.search(r"--format='value\(lifecycleState\)'.*?case \"\$LSTATE\" in\s+([A-Z_|]+)\)", src, re.S)
        self.assertIsNotNone(m)
        self.assertEqual(set(m.group(1).split("|")), set(rd.PENDING_DELETION_STATES))
        self.assertIn(rd.STATE_PENDING_DELETION, src)

    def test_reads_that_fail_are_could_not_check(self):
        for codes in ({"workloads": 403}, {"provenance": 500}, {"certs": 404}):
            d = self._dir(_ledger(**{"prod-a": {"status": "DEPLOYED", "project_id": "child-proj-1"}}),
                          _prov(**{"prod-a": {"project_id": "child-proj-1", "runner_identity": _signed(self.keys, _record())}}),
                          codes=codes)
            with self.assertRaises(rd.CheckError, msg=str(codes)):
                rd.readiness(rd.offline_fetcher(d), HOST, BROKER)

    def test_cli_and_standalone_script_offline(self):
        d = self._dir(_ledger(**{"prod-a": {"status": "DEPLOYED", "project_id": "child-proj-1"},
                                 "prod-b": {"status": "DEPLOYED", "project_id": "child-proj-2"}}),
                      _prov(**{"prod-a": {"project_id": "child-proj-1", "runner_identity": _signed(self.keys, _record())}}))
        self.assertEqual(rd.main(["check", "--project", HOST, "--broker", BROKER, "--offline", d]), rd.EXIT_NOT_READY)
        env = hermetic_guard.child_env()
        res = subprocess.run(["/bin/bash", os.path.join(SCRIPTS, "check-runner-identity-readiness.sh"),
                              f"--offline={d}", f"--project={HOST}", "--json"],
                             env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        rep = json.loads(res.stdout)
        self.assertEqual({r["product_id"]: r["runner_identity"] for r in rep["workloads"]},
                         {"prod-a": "READY", "prod-b": "NO_PROVENANCE"})
        ok = self._dir(_ledger(**{"prod-a": {"status": "DEPLOYED", "project_id": "child-proj-1"}}),
                       _prov(**{"prod-a": {"project_id": "child-proj-1", "runner_identity": _signed(self.keys, _record())}}))
        res = subprocess.run(["/bin/bash", os.path.join(SCRIPTS, "check-runner-identity-readiness.sh"),
                              f"--offline={ok}", f"--project={HOST}"],
                             env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("RESULT: READY for step B", res.stdout)

    # -- SAT-40 option G (owner 11-02): a project pending deletion does not block; anything else still does ----------
    def _crm_dir(self, ledger, prov, crm):
        """crm: {key: body dict | HTTP status int}; a key absent from crm answers 404 (offline fetcher)."""
        d = self._dir(ledger, prov)
        for key, answer in crm.items():
            if isinstance(answer, int):
                with open(os.path.join(d, f"crm-{key}.http"), "w") as f:
                    f.write(str(answer))
            else:
                with open(os.path.join(d, f"crm-{key}.json"), "w") as f:
                    json.dump(answer, f)
        return d

    def test_pending_deletion_does_not_block(self):
        ledger = _ledger(**{
            "p-num": {"status": "DEPLOYED", "project_id": "child-proj-1", "project_number": "1234567"},
            "p-id": {"status": "DEPLOYED", "project_id": "child-proj-2"},
            "p-ready": {"status": "DEPLOYED", "project_id": "child-proj-1"},
        })
        prov = _prov(**{"p-ready": {"project_id": "child-proj-1",
                                    "runner_identity": _signed(self.keys, _record(pid="p-ready"), pid="p-ready")}})
        crm = {"1234567": {"name": "projects/1234567", "projectId": "child-proj-1", "state": "DELETE_REQUESTED"},
               "child-proj-2": {"projectId": "child-proj-2", "lifecycleState": "DELETE_IN_PROGRESS"}}
        rep = rd.readiness(rd.offline_fetcher(self._crm_dir(ledger, prov, crm)), HOST, BROKER)
        self.assertEqual(self._state(rep, "p-num"), rd.STATE_PENDING_DELETION)
        self.assertEqual(self._state(rep, "p-id"), rd.STATE_PENDING_DELETION)
        self.assertEqual(self._state(rep, "p-ready"), "READY")
        self.assertEqual((rep["live_workloads"], rep["ready"], rep["not_ready"], rep["pending_deletion"]), (1, 1, 0, 2))
        self.assertIn("project pending deletion (not blocking): 2", rd.render_text(rep))
        self.assertIn("RESULT: READY for step B", rd.render_text(rep))

    def test_anything_but_an_exact_pending_deletion_still_blocks(self):
        """Negative tests (fail closed): unreadable (403 / 404 / 500), ACTIVE, a look-alike or missing state, the state
        word in another field, another project's answer, a number that names another project."""
        cases = {
            "n-403": ("child-proj-1", None, 403),
            "n-404": ("child-proj-1", None, None),                       # no file: 404
            "n-500": ("child-proj-1", None, 500),
            "n-active": ("child-proj-1", None, {"projectId": "child-proj-1", "state": "ACTIVE"}),
            "n-lower": ("child-proj-1", None, {"projectId": "child-proj-1", "state": "delete_requested"}),
            "n-suffix": ("child-proj-1", None, {"projectId": "child-proj-1", "state": "DELETE_REQUESTED_X"}),
            "n-nostate": ("child-proj-1", None, {"projectId": "child-proj-1",
                                                 "displayName": "DELETE_REQUESTED"}),
            "n-nonstr": ("child-proj-1", None, {"projectId": "child-proj-1", "state": ["DELETE_REQUESTED"]}),
            "n-other": ("child-proj-1", None, {"projectId": "child-proj-9", "state": "DELETE_REQUESTED"}),
            "n-numname": ("child-proj-1", "7654321", {"name": "projects/1111111", "projectId": "child-proj-1",
                                                      "state": "DELETE_REQUESTED"}),
        }
        ledger, crm = {}, {}
        for i, (pid, (proj, number, answer)) in enumerate(cases.items()):
            proj = f"child-proj-{i + 10}"
            fields = {"status": "DEPLOYED", "project_id": proj}
            if number:
                fields["project_number"] = number
            ledger[pid] = fields
            if isinstance(answer, dict):
                answer = dict(answer, projectId=proj if answer.get("projectId") == "child-proj-1" else answer["projectId"])
            if answer is not None:
                crm[number or proj] = answer
        rep = rd.readiness(rd.offline_fetcher(self._crm_dir(_ledger(**ledger), _prov(), crm)), HOST, BROKER)
        self.assertEqual({r["product_id"]: r["runner_identity"] for r in rep["workloads"]},
                         {pid: "NO_PROVENANCE" for pid in cases})
        self.assertEqual((rep["not_ready"], rep["pending_deletion"]), (len(cases), 0))

    def test_a_mismatch_is_never_lifted_by_a_pending_deletion(self):
        """Review M1 (negative): a MISMATCH (provenance names another project; a signed record names another project)
        keeps blocking even when the ledger's project is DELETE_REQUESTED. UNSIGNED / NOT_READY are lifted, and the
        detail keeps the original state."""
        deleted = {"projectId": None, "state": "DELETE_REQUESTED"}
        rec_other = _signed(self.keys, _record(pid="m-rec", project="child-proj-2"), pid="m-rec")
        not_ready = _signed(self.keys, dict(_record(pid="m-notready"), status="FAILED"), pid="m-notready")
        unsigned = {k: v for k, v in _record(pid="m-unsigned").items() if k != "signature"}
        ledger = _ledger(**{pid: {"status": "DEPLOYED", "project_id": proj} for pid, proj in (
            ("m-prov", "child-proj-31"), ("m-rec", "child-proj-32"), ("m-notready", "child-proj-1"),
            ("m-unsigned", "child-proj-1"))})
        prov = _prov(**{"m-prov": {"project_id": "child-proj-99"},
                        "m-rec": {"project_id": "child-proj-32", "runner_identity": rec_other},
                        "m-notready": {"project_id": "child-proj-1", "runner_identity": not_ready},
                        "m-unsigned": {"project_id": "child-proj-1", "runner_identity": unsigned}})
        crm = {p: dict(deleted, projectId=p) for p in ("child-proj-31", "child-proj-32", "child-proj-1")}
        rep = rd.readiness(rd.offline_fetcher(self._crm_dir(ledger, prov, crm)), HOST, BROKER)
        self.assertEqual(self._state(rep, "m-prov"), "MISMATCH")
        self.assertEqual(self._state(rep, "m-rec"), "MISMATCH")
        self.assertEqual(self._state(rep, "m-notready"), rd.STATE_PENDING_DELETION)
        self.assertEqual(self._state(rep, "m-unsigned"), rd.STATE_PENDING_DELETION)
        details = {r["product_id"]: r["detail"] for r in rep["workloads"]}
        self.assertTrue(details["m-notready"].startswith("NOT_READY; project is DELETE_REQUESTED"), details)
        self.assertTrue(details["m-unsigned"].startswith("UNSIGNED; project is DELETE_REQUESTED"), details)
        self.assertEqual((rep["not_ready"], rep["pending_deletion"]), (2, 2))
        self.assertIn("NOT READY", rd.render_text(rep))

    def test_non_ascii_digits_are_not_a_project_number(self):
        """Review L3: a ledger number of non-ASCII digits is not used as the projects.get key (the id is)."""
        ledger = _ledger(**{"p-uni": {"status": "DEPLOYED", "project_id": "child-proj-41",
                                      "project_number": "１２３"}})
        crm = {"child-proj-41": {"projectId": "child-proj-41", "state": "DELETE_REQUESTED"}}
        rep = rd.readiness(rd.offline_fetcher(self._crm_dir(ledger, _prov(), crm)), HOST, BROKER)
        self.assertEqual(self._state(rep, "p-uni"), rd.STATE_PENDING_DELETION)

    def test_operator_note_and_apply_success_line_count(self):
        """Review L1 / L2: the undelete note appears only with a pending deletion, and apply.sh's sed reads the count
        from render_text's own summary line."""
        ledger = _ledger(**{"p-del": {"status": "DEPLOYED", "project_id": "child-proj-51"}})
        crm = {"child-proj-51": {"projectId": "child-proj-51", "state": "DELETE_REQUESTED"}}
        text = rd.render_text(rd.readiness(rd.offline_fetcher(self._crm_dir(ledger, _prov(), crm)), HOST, BROKER))
        self.assertIn(rd.UNDELETE_NOTE, text)
        self.assertIn("RESULT: READY for step B", text)
        self.assertNotIn(rd.UNDELETE_NOTE, rd.render_text(rd.readiness(rd.offline_fetcher(self._dir(_ledger(), _prov())),
                                                                       HOST, BROKER)))
        apply_sh = _read(os.path.join(SCRIPTS, "common", "runner_switch_gate.sh"))   # SAT-46: apply.sh's hook, moved
        expr = re.search(r"sed -n '([^']*project pending deletion[^']*)'", apply_sh).group(1)
        res = subprocess.run(["sed", "-n", expr], input=text, capture_output=True, text=True, timeout=30)
        self.assertEqual(res.stdout.strip(), "1")
        self.assertIn('every live workload is READY${pending_note}.', apply_sh)

    def test_ready_workloads_cost_no_resource_manager_read(self):
        ledger = _ledger(**{"prod-a": {"status": "DEPLOYED", "project_id": "child-proj-1"}})
        prov = _prov(**{"prod-a": {"project_id": "child-proj-1", "runner_identity": _signed(self.keys, _record())}})
        inner = rd.offline_fetcher(self._dir(ledger, prov))
        seen = []

        def fetch(url, authed):
            seen.append(url)
            return inner(url, authed)
        rep = rd.readiness(fetch, HOST, BROKER)
        self.assertEqual(rep["ready"], 1)
        self.assertFalse([u for u in seen if u.startswith(rd.CRM_V3_PROJECTS)])

    def test_deployers_are_derived_never_read(self):
        prov = _prov(**{"prod-a": {"project_id": "child-proj-1", "runner_identity": dict(_record(), deployer_email="evil@x.iam.gserviceaccount.com")},
                        "prod-b": {"project_id": "child-proj-2"}})
        d = self._dir(_ledger(), prov)
        self.assertEqual(rd.deployers(rd.offline_fetcher(d), HOST),
                         ["stackvend-deployer@child-proj-1.iam.gserviceaccount.com"])


class TestLiveFetcherScope(unittest.TestCase):
    def test_token_goes_only_to_firestore(self):
        fetch = rd.live_fetcher("tok", HOST)
        with self.assertRaises(rd.CheckError):
            fetch("https://example.invalid/x", True)
        with self.assertRaises(rd.CheckError):
            fetch("https://firestore.googleapis.com/v1/x", False)   # unauthenticated reads are the x509 URL only
        # SAT-40 option G: the token may also go to Resource Manager v3 projects.get, and nowhere else there
        for other in ("https://cloudresourcemanager.googleapis.com/v1/projects/x",
                      "https://cloudresourcemanager.googleapis.com/v3/folders/1",
                      "https://cloudresourcemanager.googleapis.com/v3/projects-x"):
            with self.assertRaises(rd.CheckError, msg=other):
                fetch(other, True)
        with self.assertRaises(rd.CheckError):
            fetch(rd.CRM_V3_PROJECTS + "child-proj-1", False)

    def test_firestore_value_decoding(self):
        self.assertEqual(rd.fs_value(_fs({"a": [1, "x", None, True]})), {"a": [1, "x", None, True]})
        for bad in ({"doubleValue": 1.0}, {"timestampValue": "2026-01-01T00:00:00Z"}, {"bytesValue": "AA=="}, {}):
            with self.assertRaises(rd.Unsupported):
                rd.fs_value(bad)


# ==============================================================================================================
# 3. install IAM check: FD-7L posture
# ==============================================================================================================
P = "proj-aaaa1"


def _sa(name, project=P):
    return f"{name}@{project}.iam.gserviceaccount.com"


IDEV, IPROV, ICC, IJOB, ISRV = (_sa("sa-castor-developer"), _sa("sa-project-provisioner"),
                                _sa("sa-stackvend-control-center"), _sa("sa-stackvend-tf-applier"),
                                _sa("sa-stackvend-tf-server"))


def _r(rtype, name, instances, mode="managed"):
    return {"mode": mode, "type": rtype, "name": name, "instances": [{"attributes": a} for a in instances]}


def _state(runners=True, vending=IPROV, extra=()):
    accounts = [("sa-castor-developer", IDEV), ("sa-project-provisioner", IPROV)]
    res = [
        _r("google_project", "platform_project", [{"project_id": P, "number": "111122223333"}], mode="data"),
        _r("google_service_account", "agents", [{"account_id": a, "email": e} for a, e in accounts]),
        _r("google_service_account", "stackvend_personas", [{"account_id": "sa-stackvend-control-center", "email": ICC}]),
        _r("google_cloud_run_v2_service", "services", [{"name": "project-repo-vending-service",
                                                         "template": [{"service_account": vending}]}]),
        _r("google_service_account_iam_member", "gateway_self_sign_blob", [
            {"service_account_id": f"projects/{P}/serviceAccounts/{IDEV}", "role": "roles/iam.serviceAccountTokenCreator",
             "member": f"serviceAccount:{IDEV}", "condition": []}]),
    ]
    if runners:
        res += [
            _r("google_service_account", "tf_runners", [{"account_id": "sa-stackvend-tf-applier", "email": IJOB},
                                                         {"account_id": "sa-stackvend-tf-server", "email": ISRV}]),
            _r("google_project_iam_member", "tf_runner_project_roles", [
                {"project": P, "role": "roles/logging.logWriter", "member": f"serviceAccount:{IJOB}", "condition": []},
                {"project": P, "role": f"projects/{P}/roles/stackvendWorkflowCallback", "member": f"serviceAccount:{IJOB}", "condition": []},
                {"project": P, "role": "roles/logging.logWriter", "member": f"serviceAccount:{ISRV}", "condition": []},
                {"project": P, "role": f"projects/{P}/roles/stackvendWorkflowCallback", "member": f"serviceAccount:{ISRV}", "condition": []}]),
            _r("google_project_iam_member", "tf_runner_datastore_users", [
                {"project": P, "role": "roles/datastore.user", "member": f"serviceAccount:{e}",
                 "condition": [{"expression": "!(x)", "title": "stackvend-not-guard-db"}]} for e in (IJOB, ISRV)]),
            _r("google_storage_bucket_iam_member", "tf_runner_staging_job_reader", [
                {"bucket": f"b/stackvend-runner-staging-{P}", "role": "roles/storage.objectViewer", "member": f"serviceAccount:{IJOB}"}]),
            _r("google_service_account_iam_member", "vending_self_sign_blob", [
                {"service_account_id": f"projects/{P}/serviceAccounts/{IPROV}", "role": "roles/iam.serviceAccountTokenCreator",
                 "member": f"serviceAccount:{IPROV}", "condition": []}]),
        ]
    return {"version": 4, "resources": res + list(extra)}


def _inputs(deployers=()):
    return {"project": P, "folder": "", "billing_account": "", "organization": "", "admins": [], "deployers": list(deployers)}


def _policies(d, pols):
    os.makedirs(d, exist_ok=True)
    for name, pol in pols.items():
        if isinstance(pol, int):
            with open(os.path.join(d, name + ".http"), "w") as f:
                f.write(str(pol))
        else:
            with open(os.path.join(d, name + ".json"), "w") as f:
                json.dump(pol, f)


def _analyze(state, inputs, pols, skip=("project", "service_account")):
    with tempfile.TemporaryDirectory() as d:
        _policies(d, pols)
        return iic.analyze(state, inputs, d, skip_kinds=list(skip))


class TestInstallIamRunnerPosture(unittest.TestCase):
    def test_step_a_state_is_clean(self):
        rep = _analyze(_state(), _inputs(), {})
        self.assertEqual(rep.findings, [])

    def test_step_a_project_policy_with_both_callback_grants_is_clean(self):
        # Owner 11-01: the server SA's stackvendWorkflowCallback binding is declared, so the live policy pass expects it.
        role = f"projects/{P}/roles/stackvendWorkflowCallback"
        pol = {"bindings": [{"role": role, "members": [f"serviceAccount:{IJOB}", f"serviceAccount:{ISRV}"]},
                            {"role": "roles/logging.logWriter", "members": [f"serviceAccount:{IJOB}", f"serviceAccount:{ISRV}"]}]}
        rep = _analyze(_state(), _inputs(), {"project": pol}, skip=("service_account",))
        self.assertEqual(rep.findings, [])
        self.assertIn(("project", P, "ok"), rep.checked)

    def test_before_step_a_nothing_new_is_checked(self):
        rep = _analyze(_state(runners=False, vending=IDEV), _inputs(), {})
        self.assertEqual(rep.findings, [])   # the R9 report starts once FD-7L is installed (no change today)

    def test_forbidden_declared_grants_are_reported(self):
        extra = [
            _r("google_secret_manager_secret_iam_member", "x", [{"secret_id": "s", "role": "roles/secretmanager.secretAccessor", "member": f"serviceAccount:{IJOB}"}]),
            _r("google_storage_bucket_iam_member", "y", [{"bucket": f"b/castor-tfstate-{P}", "role": "roles/storage.objectViewer", "member": f"serviceAccount:{ISRV}"}]),
            _r("google_folder_iam_member", "z", [{"folder": "folders/1", "role": "roles/browser", "member": f"serviceAccount:{IJOB}"}]),
            _r("google_project_iam_member", "w", [{"project": P, "role": "roles/run.developer", "member": f"serviceAccount:{IJOB}", "condition": []}]),
            _r("google_service_account_iam_member", "v", [{"service_account_id": f"projects/{P}/serviceAccounts/{IJOB}", "role": "roles/iam.serviceAccountTokenCreator", "member": f"serviceAccount:{IDEV}"}]),
            _r("google_service_account_iam_member", "u", [{"service_account_id": f"projects/{P}/serviceAccounts/{ISRV}", "role": "roles/iam.serviceAccountUser", "member": f"serviceAccount:{IPROV}"}]),
            _r("google_project_iam_member", "t", [{"project": P, "role": "roles/viewer", "member": "serviceAccount:stackvend-deployer@child-1.iam.gserviceaccount.com", "condition": []}]),
        ]
        rep = _analyze(_state(extra=extra), _inputs(), {})
        self.assertEqual(len(rep.findings), 7, [f.why for f in rep.findings])
        self.assertTrue(all(f.kind == "runner_identity" for f in rep.findings))
        self.assertEqual(rep.exit_code, iic.EXIT_FINDINGS)

    def test_vending_act_as_on_the_job_sa_is_the_one_allowed_grant(self):
        ok = [_r("google_service_account_iam_member", "vending_act_as_tf_applier", [
            {"service_account_id": f"projects/{P}/serviceAccounts/{IJOB}", "role": "roles/iam.serviceAccountUser", "member": f"serviceAccount:{IPROV}"}])]
        self.assertEqual(_analyze(_state(extra=ok), _inputs(), {}).findings, [])

    def test_vending_on_a_shared_identity_is_reported(self):
        rep = _analyze(_state(vending=IDEV), _inputs(), {})
        self.assertEqual([f.role for f in rep.findings], ["(runtime identity)"])

    def test_deployer_policies(self):
        dep1, dep2, dep3, dep4 = (f"stackvend-deployer@child-{i}x.iam.gserviceaccount.com" for i in range(1, 5))
        pols = {
            "deployer_0": {"bindings": [{"role": "roles/iam.serviceAccountTokenCreator", "members": [f"serviceAccount:{IPROV}"]}]},
            "deployer_1": {"bindings": [{"role": "roles/iam.serviceAccountTokenCreator", "members": [f"serviceAccount:{IPROV}", f"serviceAccount:{IDEV}"]}]},
            "deployer_2": 404,
            "deployer_3": 403,
        }
        rep = _analyze(_state(), _inputs([dep1, dep2, dep3, dep4]), pols)
        self.assertEqual([(f.kind, f.member) for f in rep.findings], [("deployer", f"serviceAccount:{IDEV}")])
        self.assertIn("--project=child-2x", rep.findings[0].fix)
        self.assertEqual(rep.counts["broker"], 2)
        self.assertEqual(len(rep.unchecked), 1)        # the 403 -> could not check
        self.assertEqual(rep.exit_code, iic.EXIT_UNCHECKED)

    def test_deployer_bound_on_a_host_scope_live(self):
        pols = {"project": {"bindings": [{"role": "roles/viewer", "members": ["serviceAccount:stackvend-deployer@child-1x.iam.gserviceaccount.com"]}]}}
        rep = _analyze(_state(), _inputs(), pols, skip=("service_account",))
        self.assertEqual([f.member for f in rep.findings], ["serviceAccount:stackvend-deployer@child-1x.iam.gserviceaccount.com"])

    def test_targets_and_inputs_validation(self):
        ps = iic.read_platform_state(_state())
        t = iic.build_targets(ps, _inputs(["stackvend-deployer@child-1x.iam.gserviceaccount.com"]), ["project", "service_account"])
        self.assertEqual([(x.name, x.kind) for x in t], [("deployer_0", "deployer")])
        with self.assertRaises(iic.CheckError):
            iic.build_targets(ps, _inputs(["sa-castor-developer@x-proj-1.iam.gserviceaccount.com"]), [])
        self.assertEqual(iic.build_targets(ps, _inputs(["stackvend-deployer@child-1x.iam.gserviceaccount.com"]),
                                           ["project", "service_account", "deployer"]), [])

    def test_installed_subcommand(self):
        with tempfile.TemporaryDirectory() as d:
            for runners, want in ((True, "yes"), (False, "no")):
                p = os.path.join(d, "state.json")
                with open(p, "w") as f:
                    json.dump(_state(runners=runners), f)
                res = subprocess.run(["python3", IAM_HELPER, "runner-identity-installed", "--state", p],
                                     env=hermetic_guard.child_env(), capture_output=True, text=True, timeout=60)
                self.assertEqual((res.returncode, res.stdout.strip()), (0, want))


# ==============================================================================================================
# 4. sv_export_platform_stamp (throwaway local git repository; no network)
# ==============================================================================================================
@unittest.skipUnless(GIT, "needs git")
class TestPlatformStampExport(unittest.TestCase):
    def _stamp(self, root):
        script = (f'set -e; PLATFORM_DIR="{root}/infra/platform"; . "{SCRIPTS}/common/platform_target.sh"; '
                  'sv_export_platform_stamp 2>/dev/null; printf "%s" "${TF_VAR_stackvend_platform_commit}"')
        env = hermetic_guard.child_env(extra={"HOME": root})
        res = subprocess.run(["/bin/bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return res.stdout

    def _git(self, root, *args):
        subprocess.run([GIT, "-C", root, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                        "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, timeout=60,
                       env=hermetic_guard.child_env(extra={"HOME": root}))

    def test_clean_dirty_and_not_a_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.realpath(tmp)
            os.makedirs(os.path.join(root, "infra", "platform"))
            self.assertEqual(self._stamp(root), "")                      # not a git checkout
            with open(os.path.join(root, "infra", "platform", "x.tf"), "w") as f:
                f.write("# x\n")
            self._git(root, "init", "-q")
            self._git(root, "add", "-A")
            self._git(root, "commit", "-q", "-m", "x")
            head = subprocess.run([GIT, "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True,
                                  env=hermetic_guard.child_env(extra={"HOME": root})).stdout.strip()
            self.assertRegex(head, r"^[0-9a-f]{40}$")
            self.assertEqual(self._stamp(root), head)
            # RT F3: an untracked file (e.g. local tool notes in the owner's checkout) does not mark the stamp dirty.
            os.makedirs(os.path.join(root, "notes"))
            with open(os.path.join(root, "notes", "untracked.md"), "w") as f:
                f.write("x\n")
            self.assertEqual(self._stamp(root), head)
            # A modified tracked file does.
            with open(os.path.join(root, "infra", "platform", "x.tf"), "a") as f:
                f.write("# changed\n")
            self.assertEqual(self._stamp(root), head + "+dirty")
            self.assertRegex(self._stamp(root), r"^([0-9a-f]{40}(\+dirty)?)?$")   # = the variable's validation


class TestApplyStepBHook(unittest.TestCase):
    def test_hook_is_wired_before_the_typed_confirmation_and_never_for_destroy(self):
        pt = _read(os.path.join(SCRIPTS, "common", "platform_target.sh"))
        gated = pt[pt.index("sv_gated_apply() {"):]
        self.assertLess(gated.index("sv_post_plan_check"), gated.index('sv_confirm_project "Apply the plan above'))
        self.assertIn('if [ "${mode}" != "destroy" ] && declare -F sv_post_plan_check', gated)
        # SAT-46: the hook moved unchanged from apply.sh section 3d to scripts/common/runner_switch_gate.sh, which
        # apply.sh AND bootstrap.sh source (a re-bootstrapped existing install is gated too).
        gate = _read(os.path.join(SCRIPTS, "common", "runner_switch_gate.sh"))
        hook = gate[gate.index("sv_post_plan_check() {"):gate.index("\n}\n", gate.index("sv_post_plan_check() {"))]
        self.assertIn("plan-switch --plan", hook)
        self.assertIn('check --project "${PROJECT_ID}" --broker "${broker}"', hook)
        self.assertIn('broker="sa-project-provisioner@${PROJECT_ID}.iam.gserviceaccount.com"', hook)
        self.assertIn("APPLY_RUNNER_SWITCH_NOT_READY", hook)
        self.assertIn("APPLY_RUNNER_SWITCH_UNCHECKED", hook)
        self.assertNotIn("sv_warn", hook)   # refuses, never warns (fail loudly)
        # Both wrappers source the one definition and neither defines its own (a new install's runners are creates,
        # which plan-switch never counts).
        for name in ("apply.sh", "bootstrap.sh"):
            src = _read(os.path.join(SCRIPTS, name))
            self.assertIn('. "${SCRIPT_DIR}/common/runner_switch_gate.sh"\n', src, name)
            self.assertNotIn("sv_post_plan_check()", src, name)
            self.assertLess(src.index("common/platform_target.sh\"\n"), src.index("common/runner_switch_gate.sh\"\n"))


# ==============================================================================================================
# 5. Plan-level contract (tofu test, mock providers) -- skipped without OpenTofu + a local provider mirror
# ==============================================================================================================
@unittest.skipUnless(TOFU and MIRROR and os.path.isdir(os.path.join(MIRROR, "registry.opentofu.org", "hashicorp", "google")),
                     "needs OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
class TestFd7lPlanContractMockProviders(unittest.TestCase):
    def test_tofu_test_contract(self):
        tmp = tempfile.mkdtemp(prefix="fd7l-tf-")
        sock_dir = None
        try:
            shutil.copytree(os.path.join(REPO, "infra"), os.path.join(tmp, "infra"),
                            ignore=shutil.ignore_patterns(".terraform*", "*.tfvars", "*.tfstate*"))
            shutil.copytree(os.path.join(REPO, "workflows"), os.path.join(tmp, "workflows"))
            os.makedirs(os.path.join(tmp, "mcp-servers", "kubernetes"))
            shutil.copy(os.path.join(REPO, "mcp-servers", "kubernetes", "helm-pin.json"),
                        os.path.join(tmp, "mcp-servers", "kubernetes"))
            shutil.copy(os.path.join(REPO, "VERSION"), os.path.join(tmp, "VERSION"))   # the platform-release stamp
            plat = os.path.join(tmp, "infra", "platform")
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
            extra = {"TF_CLI_CONFIG_FILE": rc_file, "TF_DATA_DIR": os.path.join(tmp, "tfdata"), "TF_IN_AUTOMATION": "1"}
            if len(tempfile.gettempdir()) > 60:
                sock_dir = tempfile.mkdtemp(prefix="fd7l-", dir="/private/tmp" if os.path.isdir("/private/tmp") else "/tmp")
                extra["TMPDIR"] = sock_dir
            env = hermetic_guard.child_env(extra=extra)
            init = subprocess.run([TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=plat, env=env,
                                  capture_output=True, text=True, timeout=300)
            self.assertEqual(init.returncode, 0, init.stdout + init.stderr)
            res = subprocess.run([TOFU, "test", "-no-color", "-filter=tests/fd7l_tf.tftest.hcl"], cwd=plat, env=env,
                                 capture_output=True, text=True, timeout=600)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("5 passed, 0 failed", res.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            if sock_dir:
                shutil.rmtree(sock_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

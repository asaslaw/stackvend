import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""SELFUP-B (P3b, pre-RC): the "Update StackVend" button's one-time core Terraform, infra/platform/platform_upgrader.tf.

Plan: docs/planning/self-upgrade-plan.md §4.2-§4.5; Fable plan RT §5 (footprint), H-1, H-2, M-1, M-2, M-4, BL-2, BL-3.

Hermetic checks:
1. Static (python-hcl2 + text, no provider, no network) over every infra/platform/*.tf: the exact resource inventory,
   all gated by enable_platform_upgrader (default false = nothing planned); the custom role's exact permission set; the
   upgrader's exact grants across the whole configuration (no Terraform-type, IAM-admin, cloudbuild.builds.create,
   run.invoker, no project-wide act-as); only the Control Center publishes to the topic; only the Cloud Build service
   agent may act as the upgrader; the Control Center gains only the publisher grant (+ one env); the act-as set
   follows every runtime identity of the components in shared/release_manifest.py COMPONENTS; the trigger's shape.
2. Step 0 parity: infra/platform/upgrade_step0/{verify.sh,guard.py} are byte copies of scripts/upgrade/{verify.sh,guard.py}
   (builder B2's frozen step 0, branch selfup-b2-scripts commit e9e69699). FAILS on this branch alone until it is
   merged with B2's branch (the reference files arrive with it).
3. scripts/common/install_iam_check.py (H-1): the upgrader's serviceAccountUser on the two runner SAs is the one
   accepted act-as besides vending's; anything else on them is still reported.
4. Plan-level contract (tofu test, MOCK providers): tests/fixtures/selfup_upgrader/*.tftest.hcl, skipped unless OpenTofu
   and STACKVEND_TOFU_PROVIDER_MIRROR (a local provider mirror) are present; nothing is ever downloaded.
"""
import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import hcl2

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
UPGRADER_TF = os.path.join(PLATFORM, "platform_upgrader.tf")
MAIN_TF = os.path.join(PLATFORM, "main.tf")
VARS_TF = os.path.join(PLATFORM, "variables.tf")
STEP0_COPIES = {n: os.path.join(PLATFORM, "upgrade_step0", n) for n in ("verify.sh", "guard.py")}
STEP0_REFERENCES = {n: os.path.join(REPO, "scripts", "upgrade", n) for n in ("verify.sh", "guard.py")}
# sha256 of B2's frozen files at selfup-b2-scripts e9e69699 (RT fixes M-A lease >= build timeout, L-A
# GIT_CONFIG_GLOBAL; the content embedded for the 11-06 apply). guard.py re-pinned for SAT-48 review H-1 (11-02).
STEP0_FROZEN_SHA256 = {
    "verify.sh": "a0233ff41b66adbc5c84218fac9a854d4397a6ad77e89e83fa5af9f93899a3ff",
    "guard.py": "7fb3f33bcac40d65efae94fff32e6ea00f53d481b5823116f7ecda8fd167f4af",  # C10: + the 3 new jobs in COMPONENT_KINDS
}
IAM_HELPER = os.path.join(REPO, "scripts", "common", "install_iam_check.py")
FIXTURES = os.path.join(HERE, "fixtures", "selfup_upgrader")
TOFU = shutil.which("tofu")
SSH_KEYGEN = shutil.which("ssh-keygen")
MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")

NAMESPACES_GIT = 'namespaces="git"'   # the one allowed_signers option step 0 accepts (RT L-B)
UPGRADER_REF = "google_service_account.stackvend_upgrader"
UPGRADER_MEMBER = "${google_service_account.stackvend_upgrader[0].member}"

# Fable plan RT §5: the 11 resource blocks of the footprint (18 instances after FD-7L step B). BL-3 (live spike 11-03)
# adds none: Cloud Build owns the trigger's subscription; no push identity, no source_to_build. SELFUP-BOOTSTRAP-ON adds
# the Cloud Build service identity (a new install applies the upgrader in its first apply): 12 blocks, 19 instances.
EXPECTED_RESOURCES = {
    ("google_service_account", "stackvend_upgrader"),
    ("google_project_iam_custom_role", "stackvend_upgrader_deploy"),
    ("google_project_iam_member", "platform_upgrader_project_roles"),
    ("google_artifact_registry_repository_iam_member", "platform_upgrader_ar_writer"),
    ("google_service_account_iam_member", "platform_upgrader_act_as"),
    ("google_project_iam_member", "platform_upgrader_guard_db_reader"),
    ("google_project_iam_member", "platform_upgrader_datastore_user"),
    ("google_pubsub_topic", "platform_upgrade"),
    ("google_pubsub_topic_iam_member", "cc_platform_upgrade_publisher"),
    ("google_project_service_identity", "cloudbuild_sa"),
    ("google_service_account_iam_member", "cloudbuild_agent_act_as_upgrader"),
    ("google_cloudbuild_trigger", "platform_upgrade"),
    # HOST-VPC-EGRESS (host_network_deployer_grants, default false): subnet use for Direct VPC egress revisions.
    ("google_compute_subnetwork_iam_member", "platform_upgrader_subnet_user"),
}
EXPECTED_PERMISSIONS = {
    "run.services.get", "run.services.list", "run.services.update",
    "run.revisions.get", "run.revisions.list",
    "run.jobs.get", "run.jobs.list", "run.jobs.update",
    "run.operations.get",
}
# HOST-VPC-EGRESS: added to the custom role only when host_vpc_egress && host_network_deployer_grants (default false).
GATED_SUBNET_PERMISSIONS = ["compute.subnetworks.get", "compute.subnetworks.use"]
SUBNET_GATE = "(var.host_vpc_egress && var.host_network_deployer_grants)"

# Permission families the upgrader must never hold (plan §4.2 "never has"; owner Q3: the button never runs Terraform).
FORBIDDEN_PERMISSION_PREFIXES = (
    "resourcemanager.", "iam.", "storage.", "secretmanager.", "cloudbuild.", "serviceusage.", "orgpolicy.",
    "billing.", "workflows.", "compute.", "container.", "datastore.", "pubsub.",
)
FORBIDDEN_RUN_PERMISSIONS = {
    "run.services.create", "run.services.delete", "run.services.setIamPolicy", "run.jobs.create", "run.jobs.delete",
    "run.jobs.setIamPolicy", "run.jobs.run", "run.jobs.runWithOverrides", "run.executions.cancel", "run.routes.invoke",
    "run.revisions.delete", "run.operations.delete",
}

# Every resource in the whole configuration whose member is the upgrader: (type, name, role expression).
EXPECTED_UPGRADER_GRANTS = {
    ("google_project_iam_member", "platform_upgrader_project_roles", "${each.value}"),
    ("google_artifact_registry_repository_iam_member", "platform_upgrader_ar_writer", "roles/artifactregistry.writer"),
    ("google_service_account_iam_member", "platform_upgrader_act_as", "roles/iam.serviceAccountUser"),
    ("google_project_iam_member", "platform_upgrader_guard_db_reader", "roles/datastore.viewer"),
    ("google_project_iam_member", "platform_upgrader_datastore_user", "roles/datastore.user"),
    ("google_compute_subnetwork_iam_member", "platform_upgrader_subnet_user", "roles/compute.networkUser"),
}
CLOUDBUILD_AGENT = "serviceAccount:service-${data.google_project.platform_project.number}@gcp-sa-cloudbuild.iam.gserviceaccount.com"


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


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


def _balanced_parens(text, start):
    depth = 0
    for i in range(text.index("(", start), len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError("unbalanced parens at %d" % start)


# python-hcl2 cannot parse a multi-line conditional that starts a line with `?` (billing_iam.tf); see
# tests/test_fd4as_c_topic_publishers.py. Such a file must not mention the upgrader or its topic at all.
PARSER_GAP_FILES = {"billing_iam.tf"}


def _platform_resources():
    """(type, name, body, file) for every resource block in infra/platform/*.tf."""
    out = []
    for n in sorted(os.listdir(PLATFORM)):
        if not n.endswith(".tf"):
            continue
        text = _read(os.path.join(PLATFORM, n))
        try:
            parsed = hcl2.loads(text)
        except Exception:
            assert n in PARSER_GAP_FILES, f"{n}: python-hcl2 cannot parse it"
            for needle in ("stackvend_upgrader", "platform_upgrade", "upgrader"):
                assert needle not in text, f"{n}: unparsed file mentions {needle}"
            continue
        for block in parsed.get("resource", []):
            for rtype, named in block.items():
                for name, body in named.items():
                    out.append((rtype, name, body, n))
    return out


def _s(v):
    """python-hcl2 renders expressions as strings (sometimes wrapped as ${...}); normalise to text."""
    return json.dumps(v, sort_keys=True) if not isinstance(v, str) else v


def _upgrader_resources():
    return {(t, n): b for t, n, b, f in _platform_resources() if f == "platform_upgrader.tf"}


# ==============================================================================================================
# 1. Static
# ==============================================================================================================
class TestInventoryAndGate(unittest.TestCase):
    def test_exact_resource_inventory(self):
        self.assertEqual(set(_upgrader_resources()), EXPECTED_RESOURCES)

    def test_every_resource_is_gated_by_the_switch(self):
        for (rtype, name), body in _upgrader_resources().items():
            gate = _s(body.get("count", body.get("for_each", "")))
            self.assertIn("var.enable_platform_upgrader", gate, name)

    def test_variables_and_defaults(self):
        text = _read(VARS_TF)
        expect = {
            "enable_platform_upgrader": ("bool", "false"),
            "platform_upgrade_trigger_disabled": ("bool", "false"),
            "platform_upgrade_approval_required": ("bool", "true"),    # H-2: on by default
        }
        for name, (typ, default) in expect.items():
            blk = _block(text, f'variable "{name}"')
            self.assertRegex(blk, rf"\n\s*type\s*=\s*{typ}\b", name)
            self.assertRegex(blk, rf"\n\s*default\s*=\s*{re.escape(default)}\s*\n", name)
        # BL-3 resolved by the live spike: no push-identity or source switch exists.
        self.assertEqual(set(re.findall(r'^variable "(platform_upgrade[a-z_]*|enable_platform_upgrader)"', text, re.M)),
                         set(expect))

    def test_bl3_no_push_identity_no_source_no_managed_subscription(self):
        res = _upgrader_resources()
        trig = res[("google_cloudbuild_trigger", "platform_upgrade")]
        self.assertEqual(set(trig["pubsub_config"][0]), {"topic"})          # no service_account_email
        self.assertNotIn("source_to_build", trig)
        self.assertEqual(trig["name"], "stackvend-platform-upgrade")        # stable: the subscription is gcb-<name>
        for rtype, name, body, f in _platform_resources():
            self.assertFalse(rtype.startswith("google_pubsub_subscription") and "platform_upgrade" in _s(body), name)
            self.assertNotIn("gcp-sa-pubsub", _s(body.get("member", "")) if "platform_upgrade" in name else "", name)

    def test_no_output_and_no_other_platform_file_creates_upgrader_resources(self):
        # The FD-7L step-B plan from the same commit must stay untouched with the default: no new output either.
        self.assertNotIn("upgrade", _read(os.path.join(PLATFORM, "outputs.tf")))
        for rtype, name, body, f in _platform_resources():
            if f != "platform_upgrader.tf":
                self.assertNotIn(UPGRADER_REF, _s(body), f"{f}: {rtype}.{name}")


def _role_permission_lists():
    """(base list, gated list) of the custom role: permissions = concat([base...], <gate> ? [gated...] : [])."""
    blk = _block(_strip_comments(_read(os.path.join(PLATFORM, "platform_upgrader.tf"))),
                 'resource "google_project_iam_custom_role" "stackvend_upgrader_deploy"')
    m = re.search(r"permissions = concat\(\[(.*?)\], (\(.*?\)) \? \[(.*?)\] : \[\]\)", blk, re.S)
    assert m, "the custom role permissions must be concat([base], <gate> ? [subnet permissions] : [])"
    base = re.findall(r'"([^"]+)"', m.group(1))
    gated = re.findall(r'"([^"]+)"', m.group(3))
    return base, m.group(2), gated


class TestCustomRole(unittest.TestCase):
    def test_exact_permission_set(self):
        base, gate, gated = _role_permission_lists()
        perms = set(base)
        self.assertEqual(perms, EXPECTED_PERMISSIONS)
        self.assertEqual(len(base), len(perms))
        self.assertNotIn("iam.serviceAccounts.get", perms)   # M-2
        # the only addition, and only behind both switches (default off)
        self.assertEqual(gated, GATED_SUBNET_PERMISSIONS)
        self.assertEqual(gate, SUBNET_GATE)

    def test_no_terraform_iam_admin_build_or_invoke_permission(self):
        perms = set(_role_permission_lists()[0])
        for p in perms:
            self.assertFalse(p.startswith(FORBIDDEN_PERMISSION_PREFIXES), p)
            self.assertNotIn(p, FORBIDDEN_RUN_PERMISSIONS)
            self.assertTrue(p.startswith("run."), p)
            self.assertFalse(p.endswith((".create", ".delete", ".setIamPolicy", ".run", ".invoke")), p)


class TestUpgraderGrants(unittest.TestCase):
    def test_exact_grants_across_the_whole_configuration(self):
        found = set()
        for rtype, name, body, f in _platform_resources():
            if "_iam_" in rtype and UPGRADER_MEMBER in _s(body.get("member", "")) + _s(body.get("members", "")):
                found.add((rtype, name, _s(body.get("role"))))
        self.assertEqual(found, EXPECTED_UPGRADER_GRANTS)

    def test_project_roles_are_the_custom_role_and_log_writer_only(self):
        blk = _strip_comments(_block(_read(UPGRADER_TF), 'resource "google_project_iam_member" "platform_upgrader_project_roles"'))
        fe = blk[blk.index("for_each"):blk.index("} : {}")]
        self.assertEqual(re.findall(r'^\s*"([a-z-]+)"\s*=\s*(\S+)\s*$', fe, re.M), [
            ("deploy", "google_project_iam_custom_role.stackvend_upgrader_deploy[0].id"),
            ("log-writer", '"roles/logging.logWriter"'),
        ])
        self.assertIn("role    = each.value", blk)

    def test_no_project_wide_act_as_and_no_token_creator(self):
        for rtype, name, body, f in _platform_resources():
            role = _s(body.get("role", ""))
            if rtype.startswith(("google_project_iam_", "google_folder_iam_", "google_organization_iam_")) and \
                    UPGRADER_MEMBER in _s(body):
                self.assertFalse(role.startswith("roles/iam."), f"{name}: project-wide {role}")
            if UPGRADER_MEMBER in _s(body.get("member", "")):
                self.assertNotIn("TokenCreator", role, name)
                self.assertNotIn("roles/run.", role, name)            # no run.invoker / run.developer / run.admin
                self.assertNotIn("roles/storage.", role, name)        # no state bucket
                self.assertNotIn("roles/cloudbuild.", role, name)     # no builds.create

    def test_act_as_is_per_account_and_ar_is_repo_level(self):
        res = _upgrader_resources()
        act = res[("google_service_account_iam_member", "platform_upgrader_act_as")]
        self.assertIn("local.platform_upgrader_actas_accounts", _s(act["for_each"]))
        self.assertIn("local.platform_upgrader_sa_by_account[each.key].name", _s(act["service_account_id"]))
        ar = res[("google_artifact_registry_repository_iam_member", "platform_upgrader_ar_writer")]
        self.assertIn("google_artifact_registry_repository.castor_docker_repo.name", _s(ar["repository"]))

    def test_firestore_conditions_reuse_the_guard_locals(self):
        res = _upgrader_resources()
        reader = res[("google_project_iam_member", "platform_upgrader_guard_db_reader")]
        user = res[("google_project_iam_member", "platform_upgrader_datastore_user")]
        self.assertEqual(_s(reader["condition"][0]["expression"]), "${local.guard_db_condition}")
        self.assertEqual(reader["condition"][0]["title"], "stackvend-guard-db-read")
        self.assertEqual(_s(user["condition"][0]["expression"]), "!(${local.guard_db_condition})")
        self.assertEqual(user["condition"][0]["title"], "stackvend-not-guard-db")


class TestTopicAndActAsOnTheUpgrader(unittest.TestCase):
    def test_only_the_control_center_publishes_to_the_upgrade_topic(self):
        grants = []
        for rtype, name, body, f in _platform_resources():
            if rtype.startswith("google_pubsub_topic_iam_") and "google_pubsub_topic.platform_upgrade" in _s(body.get("topic")):
                grants.append((rtype, name, body.get("role"), body.get("member")))
        self.assertEqual(grants, [("google_pubsub_topic_iam_member", "cc_platform_upgrade_publisher", "roles/pubsub.publisher",
                                   "serviceAccount:${local.cc_sa_email}")])
        for rtype, name, body, f in _platform_resources():   # no project-level publish grant for the CC either
            if rtype.startswith("google_project_iam_") and "local.cc_sa_email" in _s(body):
                self.assertNotIn("pubsub", _s(body), name)

    def test_only_the_cloud_build_agent_may_act_as_the_upgrader(self):
        on_upgrader = []
        for rtype, name, body, f in _platform_resources():
            if rtype.startswith("google_service_account_iam_") and UPGRADER_REF in _s(body.get("service_account_id")):
                on_upgrader.append((name, body.get("role"), body.get("member")))
        self.assertEqual(on_upgrader, [("cloudbuild_agent_act_as_upgrader", "roles/iam.serviceAccountUser", CLOUDBUILD_AGENT)])

    def test_the_control_center_gains_only_the_publisher_grant(self):
        cc = [(t, n) for (t, n), b in _upgrader_resources().items() if "local.cc_sa_email" in _s(b)]
        self.assertEqual(cc, [("google_pubsub_topic_iam_member", "cc_platform_upgrade_publisher")])



class TestActAsFollowsTheRuntimeIdentities(unittest.TestCase):
    """M-4: the act-as set == the runtime accounts of every component the upgrader redeploys."""

    def setUp(self):
        self.text = _strip_comments(_read(UPGRADER_TF))
        start = self.text.index("platform_upgrader_actas_accounts = toset(")
        self.accounts = _balanced_parens(self.text, start)

    def test_account_list_mirrors_each_runtime_map(self):
        for needle in ('"sa-castor-developer"', '"sa-stackvend-control-center"', "local.vending_sa_key",
                       "var.tf_runner_dedicated_sa ? [local.tf_runner_server_account_id] : []",
                       '"sa-stackvend-sandbox-cleaner"',
                       "var.tf_runner_dedicated_sa ? [local.tf_runner_job_account_id] : []",
                       "google_service_account.qa_sandbox.account_id"):
            self.assertIn(needle, self.accounts)
        guard = _read(os.path.join(PLATFORM, "destructive_guard.tf"))
        # The runtime maps name exactly these components (a new key there needs a line in the upgrader list).
        svc =_strip_comments(guard[guard.index("service_runtime_sa = merge({"):guard.index("job_runtime_sa = {")])
        self.assertEqual(set(re.findall(r'^\s*"([a-z0-9-]+)"\s*=', svc, re.M)),
                         {"product-control-center-ui", "project-repo-vending-service"})
        self.assertIn("local.tf_runner_service_runtime_sa", svc)
        job = _strip_comments(_block(guard, "  job_runtime_sa ="))
        self.assertEqual(set(re.findall(r'^\s*"([a-z0-9-]+)"\s*=', job, re.M)),
                         {"sandbox-garbage-collector-job", "finops-spend-sync-job", "sandbox-workload-sweeper-job",
                          "billing-alert-drain-job"})   # C10: each with its own persona (a line in the upgrader list)

    def test_precondition_compares_with_the_locals_every_component_resource_uses(self):
        trig = _block(self.text, 'resource "google_cloudbuild_trigger" "platform_upgrade"')
        for src in ("values(local.service_runtime_sa)", "values(local.job_runtime_sa)", "local.tf_applier_runtime_sa",
                    "google_service_account.qa_sandbox.email", "local.developer_sa_email"):
            self.assertIn(src, trig)
        self.assertNotIn("google_cloud_run_v2_", trig)   # no dependency on the services: the CC depends on the trigger
        # ... and those locals are exactly what the Cloud Run resources declare (the unlisted default = developer).
        main = _strip_comments(_read(MAIN_TF))
        want = {
            'resource "google_cloud_run_v2_service" "services"':
                'service_account = lookup(local.service_runtime_sa, each.key, google_service_account.agents["sa-castor-developer"].email)',
            'resource "google_cloud_run_v2_service" "git_server"':
                'service_account       = google_service_account.agents["sa-castor-developer"].email',
            'resource "google_cloud_run_v2_job" "jobs"':
                'service_account = lookup(local.job_runtime_sa, each.key, google_service_account.agents["sa-castor-developer"].email)',
            'resource "google_cloud_run_v2_job" "tf_applier"': "service_account = local.tf_applier_runtime_sa",
        }
        for head, line in want.items():
            blk = _block(main, head)
            self.assertEqual(len(re.findall(r"^\s*service_account\s*=", blk, re.M)), 1, head)
            self.assertIn(line, blk, head)
        qa = _strip_comments(_block(_read(os.path.join(PLATFORM, "qa_sandbox.tf")), 'resource "google_cloud_run_v2_job" "qa_sandbox"'))
        self.assertIn("service_account = google_service_account.qa_sandbox.email", qa)
        guard = _read(os.path.join(PLATFORM, "destructive_guard.tf"))
        self.assertIn('developer_sa_email = google_service_account.agents["sa-castor-developer"].email', guard)

    def test_those_resources_are_exactly_the_release_manifest_components(self):
        spec = importlib.util.spec_from_file_location("release_manifest_selfup", os.path.join(REPO, "shared", "release_manifest.py"))
        rm = importlib.util.module_from_spec(spec)
        sys.modules["release_manifest_selfup"] = rm    # dataclasses resolve their module through sys.modules
        spec.loader.exec_module(rm)
        main = _strip_comments(_read(MAIN_TF))
        services = set(re.findall(r'^\s*"([a-z0-9-]+)"\s*=', _block(main, "  cloud_run_services ="), re.M))
        jobs = set(re.findall(r'^\s*"([a-z0-9-]+)"\s*=', _block(main, "  cloud_run_jobs ="), re.M))
        git = re.search(r'resource "google_cloud_run_v2_service" "git_server" \{.*?\n  name\s*=\s*"([a-z0-9-]+)"', main, re.S).group(1)
        tfa = re.search(r'resource "google_cloud_run_v2_job" "tf_applier" \{.*?\n  name\s*=\s*"([a-z0-9-]+)"', main, re.S).group(1)
        qa = re.search(r'qa_job_name\s*=\s*"([a-z0-9-]+)"', _read(os.path.join(PLATFORM, "qa_sandbox.tf"))).group(1)
        self.assertIn(qa, jobs)   # google_cloud_run_v2_job.jobs skips it; qa_sandbox.tf builds it
        # STAGE-JOB-RUNNER: stage_runner.tf builds the stage-runner job (the gateway's identity: already acted as)
        runner = re.search(r'stage_runner_job_name\s*=\s*"([a-z0-9-]+)"', _read(os.path.join(PLATFORM, "stage_runner.tf"))).group(1)
        tf_components = {(n, "service") for n in services | {git}} | {(n, "job") for n in jobs | {tfa, runner}}
        self.assertEqual(tf_components, {(n, k) for n, k, _ in rm.COMPONENTS})
        self.assertEqual(len(rm.COMPONENTS), 25)   # C10: + 3 jobs; STAGE-JOB-RUNNER: + stage-runner


class TestTrigger(unittest.TestCase):
    def setUp(self):
        self.body = _upgrader_resources()[("google_cloudbuild_trigger", "platform_upgrade")]
        self.text = _strip_comments(_block(_read(UPGRADER_TF), 'resource "google_cloudbuild_trigger" "platform_upgrade"'))

    def test_pubsub_identity_approval_switches(self):
        b = self.body
        self.assertEqual(_s(b["service_account"]), "${google_service_account.stackvend_upgrader[0].id}")
        self.assertEqual(_s(b["pubsub_config"][0]["topic"]), "${google_pubsub_topic.platform_upgrade[0].id}")
        self.assertEqual(_s(b["approval_config"][0]["approval_required"]), "${var.platform_upgrade_approval_required}")
        self.assertEqual(_s(b["disabled"]), "${var.platform_upgrade_trigger_disabled}")
        self.assertEqual(_s(b["location"]), "${var.region}")
        self.assertEqual(b["substitutions"], {"_REQUEST_ID": "$(body.message.attributes.request_id)"})
        self.assertNotIn("github", b)
        self.assertNotIn("repository_event_config", b)
        self.assertNotIn("trigger_template", b)

    def test_build_is_unpack_then_verify_two_hours_cloud_logging_only(self):
        build = self.body["build"][0]
        self.assertEqual(build["timeout"], "7200s")
        self.assertEqual(build["options"][0]["logging"], "CLOUD_LOGGING_ONLY")
        self.assertEqual([s["id"] for s in build["step"]], ["step0-unpack", "step0-verify"])
        unpack, verify = build["step"]
        for s in (unpack, verify):
            self.assertEqual(_s(s["name"]), "${local.platform_upgrade_step0_image}")
            self.assertEqual(s["entrypoint"], "bash")
            self.assertNotIn("script", s)              # Cloud Build's `$` handling in `script` is not relied on
        self.assertEqual([_s(a) for a in unpack["args"]], ["-c", "${local.platform_upgrade_unpack_script}"])
        self.assertEqual([_s(e) for e in unpack["env"]], [
            # FD-148: gzip + base64 (Cloud Build caps each env string at 65,536; tests/test_fd148_step0_env_size.py)
            "STACKVEND_STEP0_VERIFY_SH_GZ_B64=${base64gzip(local.platform_upgrade_step0_verify_sh)}",
            "STACKVEND_STEP0_GUARD_PY_GZ_B64=${base64gzip(local.platform_upgrade_step0_guard_py)}",
            "STACKVEND_OFFICIAL_ALLOWED_SIGNERS_B64=${base64encode(local.platform_upgrade_allowed_signers)}",
        ])
        # The request id is its own argv element (no shell parses it); the only `$` in the build are Cloud Build's
        # substitutions: $_REQUEST_ID here and $BUILD_ID in the verify step's env (FD-148, the Control Center's build link).
        self.assertEqual([_s(a) for a in verify["args"]], [
            "/workspace/step0/verify.sh", "run", "--request-id", "$_REQUEST_ID", "--project", "${var.project_id}",
            "--region", "${var.region}", "--guard-database", "${google_firestore_database.stackvend_guard.name}",
            "--official-signers", "/workspace/step0/allowed_signers", "--workdir", "/workspace/up"])
        self.assertEqual(verify["env"], ["BUILD_ID=$BUILD_ID"])
        self.assertEqual(verify["wait_for"], ["step0-unpack"])
        self.assertNotIn("secret", json.dumps(build).lower())  # no secret in the build

    def test_unpack_script_has_no_dollar_and_checks_every_file(self):
        locs = _strip_comments(_read(UPGRADER_TF))
        start = locs.index("platform_upgrade_unpack_script = join(")
        blk = _balanced_parens(locs, start)
        body = re.sub(r"\$\{sha256\([a-z0-9_.]+\)\}", "HASH", blk)   # Terraform interpolations, resolved at plan time
        self.assertNotIn("$", body.replace("join(", ""))
        for f in ("verify.sh", "guard.py", "allowed_signers"):
            self.assertIn(f"HASH  /workspace/step0/{f}' | sha256sum -c --quiet -", body)
        for v, f in (("VERIFY_SH", "verify.sh"), ("GUARD_PY", "guard.py")):   # FD-148: gzipped, checked after gunzip
            self.assertIn(f"printenv STACKVEND_STEP0_{v}_GZ_B64 | base64 -d | gunzip > /workspace/step0/{f}", body)
        self.assertIn('"set -euo pipefail"', body)

    def test_trust_anchor_and_step0_come_from_fixed_repository_files(self):
        locs = _strip_comments(_read(UPGRADER_TF))
        self.assertIn('platform_upgrade_allowed_signers_file = "${path.module}/../../scripts/release/allowed_signers"', locs)
        self.assertIn('platform_upgrade_step0_dir       = "${path.module}/upgrade_step0"', locs)
        self.assertNotRegex(locs, r"(allowed_signers|step0)[^\n]*var\.")   # never a tfvars-selected trust anchor/step

    def test_build_timeout_equals_the_step0_lease_check(self):
        # RT M-A: step 0 refuses a lease that expires before a full build could finish (guard.py BUILD_TIMEOUT_S); the
        # trigger's frozen timeout must be that same number.
        m = re.findall(r"^BUILD_TIMEOUT_S = (\d+)$", _read(STEP0_COPIES["guard.py"]), re.M)
        self.assertEqual(len(m), 1)
        self.assertEqual(self.body["build"][0]["timeout"], "%ss" % m[0])
        self.assertEqual(self.body["build"][0]["timeout"], "7200s")

    def test_signer_line_regex_matches_the_step0_parser(self):
        # RT L-B: the plan accepts exactly the line forms step 0 accepts (upgrade_step0/guard.py parse_official_signers).
        locs = _strip_comments(_read(UPGRADER_TF))
        line = [ln for ln in locs.splitlines() if "platform_upgrade_signer_line_re =" in ln]
        self.assertEqual(len(line), 1)
        self.assertIn('([ \\\\t]+namespaces=\\"git\\")?[ \\\\t]+(ssh-ed25519|', line[0])
        self.assertIn("tokens[1] == '%s'" % NAMESPACES_GIT, _read(STEP0_COPIES["guard.py"]))

    def test_step0_image_is_pinned_by_digest(self):
        locs = _strip_comments(_read(UPGRADER_TF))
        self.assertRegex(locs, r'platform_upgrade_step0_image = "gcr\.io/google\.com/cloudsdktool/cloud-sdk@sha256:[0-9a-f]{64}"')

    def test_preconditions_refuse_empty_trust_set_missing_step0_unpinned_image_and_actas_drift(self):
        self.assertEqual(self.text.count("precondition {"), 4)
        self.assertIn("condition     = local.platform_upgrade_signers_valid", self.text)
        self.assertIn("SELFUP BL-2", self.text)
        self.assertIn('local.platform_upgrade_step0_verify_sh != "" && local.platform_upgrade_step0_guard_py != ""', self.text)
        self.assertIn("@sha256:[0-9a-f]{64}$", self.text)
        self.assertIn("SELFUP M-4", self.text)
        locs = _strip_comments(_read(UPGRADER_TF))
        self.assertIn("length(local.platform_upgrade_signer_lines) > 0 && alltrue(", locs)

    def test_trigger_is_last(self):
        deps = {d.strip("${}") for d in self.body["depends_on"]}
        others = {f"{t}.{n}" for t, n in EXPECTED_RESOURCES if t != "google_cloudbuild_trigger"}
        self.assertEqual(deps, others - {"google_service_account.stackvend_upgrader", "google_pubsub_topic.platform_upgrade"})
        # the SA and the topic are referenced directly (implicit dependencies)
        self.assertIn("google_service_account.stackvend_upgrader[0].id", self.text)
        self.assertIn("google_pubsub_topic.platform_upgrade[0].id", self.text)


class TestControlCenterEnv(unittest.TestCase):
    def test_env_is_appended_last_and_the_cc_waits_for_its_grant(self):
        main = _read(MAIN_TF)
        svc = _block(main, 'resource "google_cloud_run_v2_service" "services"')
        dyn = [m.start() for m in re.finditer(r'dynamic "env" \{', svc)]
        last = svc[dyn[-1]:]
        self.assertIn("local.platform_upgrader_service_env", last.split("scaling {")[0])
        self.assertIn("if v != \"\"", last.split("scaling {")[0])
        deps = svc[svc.index("depends_on = ["):svc.index("]", svc.index("depends_on = ["))]
        self.assertIn("google_pubsub_topic_iam_member.cc_platform_upgrade_publisher", deps)
        self.assertIn("google_cloudbuild_trigger.platform_upgrade", deps)   # no button without a trigger
        locs = _strip_comments(_read(UPGRADER_TF))
        blk = _block(locs, "  platform_upgrader_service_env =")
        self.assertEqual(set(re.findall(r'^\s*"([a-z0-9-]+)"\s*=', blk, re.M)), {"product-control-center-ui"})
        self.assertIn('STACKVEND_PLATFORM_UPGRADE_TOPIC = var.enable_platform_upgrader ? local.platform_upgrade_topic_path : ""', blk)
        self.assertIn('platform_upgrade_topic_path = "projects/${var.project_id}/topics/${local.platform_upgrade_topic_name}"', locs)


# ==============================================================================================================
# 2. Step 0 parity: the embedded copies are B2's frozen files (fails on this branch alone, before the B2 merge)
# ==============================================================================================================
class TestStep0Parity(unittest.TestCase):
    def test_copies_are_the_frozen_content(self):
        for name, path in STEP0_COPIES.items():
            with open(path, "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), STEP0_FROZEN_SHA256[name], path)

    def test_copies_are_byte_copies_of_the_reference_scripts(self):
        for name, ref in STEP0_REFERENCES.items():
            self.assertTrue(os.path.isfile(ref), f"scripts/upgrade/{name} (builder B2's reference step 0) is missing: "
                                                 "merge selfup-b2-scripts")
            with open(ref, "rb") as a, open(STEP0_COPIES[name], "rb") as b:
                self.assertEqual(a.read(), b.read(), f"infra/platform/upgrade_step0/{name} != scripts/upgrade/{name}")


# ==============================================================================================================
# 3. scripts/check-install-iam.sh helper (H-1, row FD7L-UPGRADER-ACTAS)
# ==============================================================================================================
def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


iic = _load("install_iam_check_selfup", IAM_HELPER)
P = "mock-stackvend-project"


def _sa(name, project=P):
    return f"{name}@{project}.iam.gserviceaccount.com"


IDEV, IPROV, IJOB, ISRV, IUPG = (_sa("sa-castor-developer"), _sa("sa-project-provisioner"), _sa("sa-stackvend-tf-applier"),
                                 _sa("sa-stackvend-tf-server"), _sa("sa-stackvend-upgrader"))


def _r(rtype, name, instances, mode="managed"):
    return {"mode": mode, "type": rtype, "name": name, "instances": [{"attributes": a} for a in instances]}


def _act_as(target, member, role="roles/iam.serviceAccountUser"):
    return {"service_account_id": f"projects/{P}/serviceAccounts/{target}", "role": role, "member": f"serviceAccount:{member}",
            "condition": []}


def _state(upgrader=True, extra=()):
    res = [
        _r("google_project", "platform_project", [{"project_id": P, "number": "111122223333"}], mode="data"),
        _r("google_service_account", "agents", [{"account_id": "sa-castor-developer", "email": IDEV},
                                                {"account_id": "sa-project-provisioner", "email": IPROV}]),
        _r("google_cloud_run_v2_service", "services", [{"name": "project-repo-vending-service",
                                                         "template": [{"service_account": IPROV}]}]),
        _r("google_service_account", "tf_runners", [{"account_id": "sa-stackvend-tf-applier", "email": IJOB},
                                                     {"account_id": "sa-stackvend-tf-server", "email": ISRV}]),
    ]
    if upgrader:
        res += [
            _r("google_service_account", "stackvend_upgrader", [{"account_id": "sa-stackvend-upgrader", "email": IUPG}]),
            _r("google_service_account_iam_member", "platform_upgrader_act_as",
               [_act_as(t, IUPG) for t in (IDEV, IPROV, IJOB, ISRV)]),
        ]
    return {"version": 4, "resources": res + list(extra)}


def _analyze(state):
    inputs = {"project": P, "folder": "", "billing_account": "", "organization": "", "admins": [], "deployers": []}
    with tempfile.TemporaryDirectory() as d:
        return iic.analyze(state, inputs, d, skip_kinds=["project", "service_account"])


class TestInstallIamUpgraderActAs(unittest.TestCase):
    def test_upgrader_service_account_user_on_both_runner_sas_is_accepted(self):
        rep = _analyze(_state())
        self.assertEqual(rep.findings, [], [f.why for f in rep.findings])
        self.assertEqual(rep.exit_code, iic.EXIT_CLEAN)

    def test_any_other_act_as_on_a_runner_sa_is_still_reported(self):
        extra = [_r("google_service_account_iam_member", "x", [_act_as(ISRV, IDEV), _act_as(IJOB, IPROV, "roles/iam.serviceAccountTokenCreator")])]
        rep = _analyze(_state(extra=extra))
        self.assertEqual(sorted((f.member, f.role) for f in rep.findings),
                         [(f"serviceAccount:{IDEV}", "roles/iam.serviceAccountUser"),
                          (f"serviceAccount:{IPROV}", "roles/iam.serviceAccountTokenCreator")])
        self.assertTrue(all("FD7L-UPGRADER-ACTAS" in f.why for f in rep.findings))

    def test_upgrader_token_creator_or_admin_on_a_runner_sa_is_reported(self):
        for role in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountAdmin", "roles/iam.workloadIdentityUser"):
            extra = [_r("google_service_account_iam_member", "y", [_act_as(ISRV, IUPG, role)])]
            rep = _analyze(_state(extra=extra))
            self.assertEqual([(f.member, f.role) for f in rep.findings], [(f"serviceAccount:{IUPG}", role)], role)

    def test_an_upgrader_named_account_of_another_project_is_reported(self):
        foreign = _sa("sa-stackvend-upgrader", "attacker-proj-1")
        extra = [_r("google_service_account_iam_member", "z", [_act_as(IJOB, foreign)])]
        rep = _analyze(_state(extra=extra))
        self.assertEqual([f.member for f in rep.findings], [f"serviceAccount:{foreign}"])

    def test_upgrader_grant_without_the_upgrader_in_the_state_is_reported(self):
        extra = [_r("google_service_account_iam_member", "w", [_act_as(IJOB, IUPG)])]
        rep = _analyze(_state(upgrader=False, extra=extra))
        self.assertEqual([f.member for f in rep.findings], [f"serviceAccount:{IUPG}"])

    def test_wrapper_header_names_the_allowance(self):
        self.assertIn("sa-stackvend-upgrader", _read(os.path.join(REPO, "scripts", "check-install-iam.sh")))


# ==============================================================================================================
# 4. Plan-level contract (tofu test, mock providers) -- skipped without OpenTofu + a local provider mirror
# ==============================================================================================================
@unittest.skipUnless(TOFU and SSH_KEYGEN and MIRROR and os.path.isdir(os.path.join(MIRROR, "registry.opentofu.org", "hashicorp", "google")),
                     "needs OpenTofu, ssh-keygen and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
class TestSelfupPlanContractMockProviders(unittest.TestCase):
    def _tree(self, tmp):
        shutil.copytree(os.path.join(REPO, "infra"), os.path.join(tmp, "infra"),
                        ignore=shutil.ignore_patterns(".terraform*", "*.tfvars", "*.tfstate*"))
        shutil.copytree(os.path.join(REPO, "workflows"), os.path.join(tmp, "workflows"))
        os.makedirs(os.path.join(tmp, "mcp-servers", "kubernetes"))
        shutil.copy(os.path.join(REPO, "mcp-servers", "kubernetes", "helm-pin.json"), os.path.join(tmp, "mcp-servers", "kubernetes"))
        shutil.copy(os.path.join(REPO, "VERSION"), os.path.join(tmp, "VERSION"))
        os.makedirs(os.path.join(tmp, "scripts", "release"))
        plat = os.path.join(tmp, "infra", "platform")
        for n in os.listdir(plat):
            if n.endswith(".tf"):
                p = os.path.join(plat, n)
                text = _read(p).replace("prevent_destroy = true", "prevent_destroy = false")
                with open(p, "w", encoding="utf-8") as f:
                    f.write(text)
        os.makedirs(os.path.join(plat, "tests"))
        for n in os.listdir(FIXTURES):
            shutil.copy(os.path.join(FIXTURES, n), os.path.join(plat, "tests"))
        return plat

    def test_tofu_test_contract(self):
        tmp = tempfile.mkdtemp(prefix="selfup-tf-")
        sock_dir = None
        try:
            plat = self._tree(tmp)
            signers = os.path.join(tmp, "scripts", "release", "allowed_signers")
            key = os.path.join(tmp, "k")
            subprocess.run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", key], check=True,
                           env=hermetic_guard.child_env(), capture_output=True, timeout=60)
            pub = _read(key + ".pub").split()
            rc_file = os.path.join(tmp, "cli.tfrc")
            with open(rc_file, "w", encoding="utf-8") as f:
                f.write('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                        '    include = ["registry.opentofu.org/*/*"]\n  }\n}\n' % MIRROR)
            extra = {"TF_CLI_CONFIG_FILE": rc_file, "TF_DATA_DIR": os.path.join(tmp, "tfdata"), "TF_IN_AUTOMATION": "1"}
            if len(tempfile.gettempdir()) > 60:
                sock_dir = tempfile.mkdtemp(prefix="selfup-", dir="/private/tmp" if os.path.isdir("/private/tmp") else "/tmp")
                extra["TMPDIR"] = sock_dir
            env = hermetic_guard.child_env(extra=extra)
            init = subprocess.run([TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=plat, env=env,
                                  capture_output=True, text=True, timeout=300)
            self.assertEqual(init.returncode, 0, init.stdout + init.stderr)

            def run(fixture):
                return subprocess.run([TOFU, "test", "-no-color", f"-filter=tests/{fixture}"], cwd=plat, env=env,
                                      capture_output=True, text=True, timeout=900)

            # Ready tree: valid official signer lines in both forms guard.py parse_official_signers accepts (comment and
            # blank lines allowed around them).
            with open(signers, "w", encoding="utf-8") as f:
                f.write("# StackVend release key\n\nstackvend-release %s %s\nstackvend-release %s %s %s\n"
                        % (pub[0], pub[1], NAMESPACES_GIT, pub[0], pub[1]))
            res = run("selfup_upgrader.tftest.hcl")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("4 passed, 0 failed", res.stdout)
            # BL-2: missing, comment-only and malformed trust sets all refuse the plan; RT L-B: so does any option other
            # than namespaces="git" between principal and key type (step 0 would refuse every build otherwise).
            for content in (None, "# nothing yet\n\n", "stackvend-release ssh-rsa AAAAB3NzaC1yc2E\n",
                            "stackvend-release %s %s\nnot a key line\n" % (pub[0], pub[1]),
                            "stackvend-release cert-authority %s %s\n" % (pub[0], pub[1]),
                            "stackvend-release valid-after=20261101 %s %s\n" % (pub[0], pub[1]),
                            'stackvend-release namespaces="file" %s %s\n' % (pub[0], pub[1])):
                if content is None:
                    os.remove(signers)
                else:
                    with open(signers, "w", encoding="utf-8") as f:
                        f.write(content)
                res = run("selfup_upgrader_refused.tftest.hcl")
                self.assertEqual(res.returncode, 0, repr(content) + res.stdout + res.stderr)
                self.assertIn("1 passed, 0 failed", res.stdout)
            # M-4: a runtime account missing from the act-as list stops the plan at the trigger (never a silent gap).
            with open(signers, "w", encoding="utf-8") as f:
                f.write("stackvend-release %s %s\n" % (pub[0], pub[1]))
            tf = os.path.join(plat, "platform_upgrader.tf")
            text = _read(tf)
            line = '    ["sa-stackvend-sandbox-cleaner"],'
            self.assertEqual(text.count(line), 1)
            with open(tf, "w", encoding="utf-8") as f:
                f.write(text.replace(line, ""))
            res = run("selfup_upgrader_actas_drift.tftest.hcl")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("1 passed, 0 failed", res.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            if sock_dir:
                shutil.rmtree(sock_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

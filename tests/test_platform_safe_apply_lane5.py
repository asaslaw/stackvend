"""Wave 1 lane 5: safe apply + infra (FD-07 step 2, FD-0B, FD-0D, FD-4W, FD-0A, FD-4AP).

Two kinds of tests, both hermetic:

1. Static checks on infra/platform/*.tf and the scripts (text/HCL walker from the FD-09 test).
2. Script harness: copies scripts/ + infra/platform/variables.tf into a temp dir and runs the real
   apply.sh / deploy-services.sh / bootstrap.sh under /bin/bash (3.2 on macOS) with LOGGING STUBS for
   gcloud, tofu, sudo, gsutil, uname, getent, curl and sleep first on a minimal PATH (stub dir, /usr/bin, /bin, /usr/sbin, /sbin).
   The env is built from scratch (never os.environ), with GOOGLE_APPLICATION_CREDENTIALS pointing
   at a nonexistent file and a temp CLOUDSDK_CONFIG. The tofu stub delegates ONLY `console` to the
   real OpenTofu binary (local HCL evaluation of a temp copy of variables.tf: no backend, no
   network, no credentials); tests that need it are skipped when tofu is not installed.
   Nothing here can reach GCP: no real gcloud/tofu plan/apply is ever on PATH.
   The Cloud Shell IPv4 fix (register row 17) runs against a FAKE root: the sudo stub rewrites
   /etc/* arguments to $STUB_SUDO_ROOT/etc/* and only then executes (python3/tee); sysctl is only
   logged. The getent stub answers with documentation-range addresses (no DNS).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import errno
import importlib.util
import json
import os
import pty
import re
import shutil
import stat
import subprocess
import tempfile
import termios
import textwrap
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
MAIN_TF = os.path.join(PLATFORM, "main.tf")
SCRIPTS = os.path.join(REPO, "scripts")
BASH = "/bin/bash"
REAL_TOFU = shutil.which("tofu")

_spec = importlib.util.spec_from_file_location("fd09_walker", os.path.join(HERE, "test_platform_validate_fd09.py"))
_fd09 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fd09)
attributes = _fd09.attributes

SERVICES = 'resource "google_cloud_run_v2_service" "services"'
GIT_SERVER = 'resource "google_cloud_run_v2_service" "git_server"'
JOBS = 'resource "google_cloud_run_v2_job" "jobs"'
TF_APPLIER = 'resource "google_cloud_run_v2_job" "tf_applier"'


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


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


def _ignore_changes(block_text):
    m = re.search(r"ignore_changes\s*=\s*\[\n(.*?)\n\s*\]", block_text, re.S)
    assert m, "no ignore_changes"
    items = []
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0].strip().rstrip(",")
        if line:
            items.append(line)
    return items


# ==============================================================================
# 1. Static checks
# ==============================================================================
class TestPlatformHclStatic(unittest.TestCase):
    def setUp(self):
        self.main = _read(MAIN_TF)
        self.attrs = attributes(self.main)

    def _top(self, res, name):
        return [v for p, a, v in self.attrs if p == (res,) and a == name]

    def test_fd0d_deletion_protection_true_everywhere(self):
        for res in (SERVICES, GIT_SERVER, JOBS, TF_APPLIER):
            self.assertEqual(self._top(res, "deletion_protection"), ["true"], res)

    def test_fd0d_no_false_latch_left(self):
        self.assertNotIn("deletion_protection = false", self.main)

    def test_git_server_volume_always_declared(self):
        gs = _block(self.main, GIT_SERVER)
        self.assertNotIn('dynamic "volumes"', gs)
        self.assertNotIn('dynamic "volume_mounts"', gs)
        names = [v for p, a, v in self.attrs if p[:3] == (GIT_SERVER, "template", "volumes") and a == "name"]
        self.assertEqual(names, ['"git-storage"'])
        mounts = {a: v for p, a, v in self.attrs if p == (GIT_SERVER, "template", "containers", "volume_mounts")}
        self.assertEqual(mounts, {"name": '"git-storage"', "mount_path": '"/data/git"'})

    def test_git_server_ignore_changes_scope(self):
        ic = _ignore_changes(_block(self.main, GIT_SERVER))
        self.assertEqual(sorted(ic), sorted(["template[0].containers[0].image", "client", "client_version", "build_config", "scaling"]))
        # max_instance_count = 1 (GCS FUSE single writer) must stay managed.
        self.assertNotIn("template[0].scaling", ic)
        scaling = {a: v for p, a, v in self.attrs if p == (GIT_SERVER, "template", "scaling")}
        self.assertEqual(scaling.get("max_instance_count"), "1")

    def test_services_ignore_changes_scope(self):
        ic = _ignore_changes(_block(self.main, SERVICES))
        self.assertEqual(sorted(ic), sorted(["template[0].containers[0].image", "client", "client_version", "build_config", "scaling"]))
        for managed in ("template[0].scaling", "template", "template[0].containers[0].env", "env"):
            self.assertNotIn(managed, ic)

    def test_vending_service_url_owned_by_terraform_on_cc_only(self):
        svc = _block(self.main, SERVICES)
        m = re.search(r'dynamic "env" \{\s*for_each = each\.key == "product-control-center-ui" \? \[1\] : \[\]\s*content \{\s*name\s*= "VENDING_SERVICE_URL"\s*value = "([^"]+)"', svc)
        self.assertIsNotNone(m, "CC must declare VENDING_SERVICE_URL")
        self.assertEqual(m.group(1), "https://project-repo-vending-service-${data.google_project.platform_project.number}.${var.region}.run.app")

    def test_gemini_model_is_a_variable_with_current_default(self):
        self.assertNotIn('value = "gemini-3.7-flash"', self.main)
        # the jobs resource's own lookup; the services read stage_runner.tf local.service_gemini_model (STAGE-JOB-RUNNER)
        self.assertEqual(self.main.count("lookup(var.gemini_model_overrides, each.key, var.gemini_model)"), 1)
        self.assertEqual(self.main.count("value = local.service_gemini_model[each.key]"), 1)
        runner = _read(os.path.join(PLATFORM, "stage_runner.tf"))
        self.assertIn("lookup(var.gemini_model_overrides, k, var.gemini_model)", runner)
        var_attrs = attributes(_read(os.path.join(PLATFORM, "variables.tf")))
        d = {p[0]: v for p, a, v in var_attrs if a == "default"}
        self.assertEqual(d['variable "gemini_model"'], '"gemini-3.7-flash"')
        self.assertEqual(d['variable "gemini_model_overrides"'], "{}")
        self.assertEqual(d['variable "cc_gemini_api_key_from_secret"'], "false")
        self.assertEqual(d['variable "grant_devops_workloads_folder_editor"'], "false")

    def test_gemini_api_key_is_secret_ref_gated(self):
        svc = _block(self.main, SERVICES)
        self.assertIn('for_each = (each.key == "product-control-center-ui" && var.cc_gemini_api_key_from_secret) ? [1] : []', svc)
        self.assertIn("secret  = google_secret_manager_secret.gemini_api_key.secret_id", svc)

    def test_vcs_provider_default_github(self):
        """Q1 (owner 10-12): the default is GITHUB; per-workload choice stays (not a TF concern)."""
        var_attrs = attributes(_read(os.path.join(PLATFORM, "variables.tf")))
        d = {p[0]: v for p, a, v in var_attrs if a == "default"}
        self.assertEqual(d['variable "vcs_provider"'], '"GITHUB"')

    def test_platform_github_repo_var_on_cc_only(self):
        """ORCHESTRATOR §5 item 4: GITHUB_REPO from per-install tfvars; no owner-specific default (OSS)."""
        var_attrs = attributes(_read(os.path.join(PLATFORM, "variables.tf")))
        d = {p[0]: v for p, a, v in var_attrs if a == "default"}
        self.assertEqual(d['variable "platform_github_repo"'], '""')
        svc = _block(self.main, SERVICES)
        m = re.search(r'dynamic "env" \{\s*for_each = \(each\.key == "product-control-center-ui" && var\.platform_github_repo != ""\) \? \[1\] : \[\]\s*content \{\s*name\s*= "GITHUB_REPO"\s*value = var\.platform_github_repo', svc)
        self.assertIsNotNone(m, "CC must take GITHUB_REPO from var.platform_github_repo")
        self.assertEqual(self.main.count('"GITHUB_REPO"'), 1)
        for f in ("main.tf", "variables.tf", "terraform.tfvars.example"):
            from owner_identifiers import find  # FD-12: identifiers held as SHA-256 digests only
            self.assertEqual(find(_read(os.path.join(PLATFORM, f)), {"owner_handle", "private_repo"}), [], f)
        self.assertIn('platform_github_repo               = "your-github-username/your-platform-repo"',
                      _read(os.path.join(PLATFORM, "terraform.tfvars.example")))

    @unittest.skipUnless(REAL_TOFU, "needs OpenTofu (local `tofu console`, no backend)")
    def test_platform_github_repo_validation(self):
        tmp = tempfile.mkdtemp(prefix="lane5-var-")
        try:
            shutil.copy(os.path.join(PLATFORM, "variables.tf"), tmp)
            for value, ok in (("example-org/example-repo", True), ("", True), ("my-org/my.repo_1", True),
                              ("https://github.com/a/b", False), ("a/b/c", False), ("owner", False),
                              ("-bad/x", False), ('a/b" ', False)):
                tfv = os.path.join(tmp, "t.tfvars")
                with open(tfv, "w") as f:
                    f.write('project_id = "proj-aaaa1"\nplatform_github_repo = %s\n' % json.dumps(value))
                r = subprocess.run([REAL_TOFU, "console", "-var-file=" + tfv], input="var.platform_github_repo\n",
                                   cwd=tmp, capture_output=True, text=True, timeout=60,
                                   env={"PATH": "/usr/bin:/bin", "HOME": tmp, "TF_DATA_DIR": os.path.join(tmp, ".d")})
                # NB: `tofu console` exits 0 even when a variable validation fails; check the diagnostic.
                if ok:
                    self.assertEqual(r.returncode, 0, (value, r.stderr))
                    self.assertNotIn("Invalid value for variable", r.stderr, value)
                    self.assertEqual(json.loads(r.stdout.strip()), value)
                else:
                    self.assertIn("Invalid value for variable", r.stderr, value)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cc_google_oauth_client_id_var_on_cc_only(self):
        """Owner 10-12 (lane 19 Q8/Q17): CC's own OAuth client ID from per-install tfvars, CC env only, unset when empty."""
        var_attrs = attributes(_read(os.path.join(PLATFORM, "variables.tf")))
        d = {p[0]: v for p, a, v in var_attrs if a == "default"}
        self.assertEqual(d['variable "cc_google_oauth_client_id"'], '""')
        svc = _block(self.main, SERVICES)
        m = re.search(r'dynamic "env" \{\s*for_each = \(each\.key == "product-control-center-ui" && var\.cc_google_oauth_client_id != ""\) \? \[1\] : \[\]\s*content \{\s*name\s*= "GOOGLE_OAUTH_CLIENT_ID"\s*value = var\.cc_google_oauth_client_id', svc)
        self.assertIsNotNone(m, "CC must take GOOGLE_OAUTH_CLIENT_ID from var.cc_google_oauth_client_id")
        # Only the CC gets it, and nowhere else in the platform HCL.
        self.assertEqual(self.main.count('"GOOGLE_OAUTH_CLIENT_ID"'), 1)
        # Lane 19 L19-0a adds 3 non-value references (A1 precondition x2, cc_client_pinned check x1): the value
        # itself still reaches exactly one place, the CC env above.
        self.assertEqual(self.main.count("var.cc_google_oauth_client_id"), 5)
        self.assertEqual(self.main.count("value = var.cc_google_oauth_client_id"), 1)
        # The existing secrets stay exactly as they were (not touched by this change).
        self.assertIn('secret_id  = "castor-oauth-client-id"', self.main)
        # install-polish: no placeholder client while Direct IAP (no client needed) is the example's active option.
        self.assertIn('cc_google_oauth_client_id          = ""', _read(os.path.join(PLATFORM, "terraform.tfvars.example")))

    @unittest.skipUnless(REAL_TOFU, "needs OpenTofu (local `tofu console`, no backend)")
    def test_cc_google_oauth_client_id_validation(self):
        tmp = tempfile.mkdtemp(prefix="lane5-var-")
        try:
            shutil.copy(os.path.join(PLATFORM, "variables.tf"), tmp)
            for value, ok in (("", True), ("123456789012-abc123def456.apps.googleusercontent.com", True),
                              ("123-a.apps.googleusercontent.com", True),
                              ("abc-123.apps.googleusercontent.com", False), ("123456789012-ABC.apps.googleusercontent.com", False),
                              ("123456789012-abc.apps.googleusercontent.com.evil.example", False),
                              ("https://123-abc.apps.googleusercontent.com", False), ("123456789012-abc", False),
                              ("123456789012-abcXapps.googleusercontent.com", False), ("GOCSPX-secretvalue", False)):
                tfv = os.path.join(tmp, "t.tfvars")
                with open(tfv, "w") as f:
                    f.write('project_id = "proj-aaaa1"\ncc_google_oauth_client_id = %s\n' % json.dumps(value))
                r = subprocess.run([REAL_TOFU, "console", "-var-file=" + tfv], input="var.cc_google_oauth_client_id\n",
                                   cwd=tmp, capture_output=True, text=True, timeout=60,
                                   env={"PATH": "/usr/bin:/bin", "HOME": tmp, "TF_DATA_DIR": os.path.join(tmp, ".d")})
                # NB: `tofu console` exits 0 even when a variable validation fails; check the diagnostic.
                if ok:
                    self.assertEqual(r.returncode, 0, (value, r.stderr))
                    self.assertNotIn("Invalid value for variable", r.stderr, value)
                    self.assertEqual(json.loads(r.stdout.strip()), value)
                else:
                    self.assertIn("Invalid value for variable", r.stderr, value)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_fd49_devops_editor_opt_in(self):
        res = 'resource "google_folder_iam_member" "devops_workloads_editor"'
        self.assertEqual(self._top(res, "count"),
                         ['(var.grant_devops_workloads_folder_editor && var.castor_managed_workloads_folder_id != "") ? 1 : 0'])

    def test_finops_iap_access_withdrawn(self):
        """C10 (owner 11-07) withdrew FINOPS-IAP-ACCESS (owner 10-26): nothing machine-calls the Control Center, so no
        service account is an IAP accessor of it; humans are unchanged (control_center_iap_accessors)."""
        self.assertNotIn('"control_center_iap_platform_callers"', self.main)
        self.assertIn('resource "google_iap_web_cloud_run_service_iam_member" "control_center_iap_accessors"', self.main)

    def test_fd0c_removed_block_kept(self):
        """Lane 5 must never delete the FD-0C removed block (orchestrator ruling)."""
        self.assertRegex(self.main, r"removed \{\s*from = google_storage_bucket\.workload_tfstate_bucket\s*lifecycle \{\s*destroy = false")

    def test_fd0a_exact_provider_pins(self):
        prov = _read(os.path.join(PLATFORM, "providers.tf"))
        self.assertRegex(prov, r'google = \{\s*source\s*= "hashicorp/google"\s*version = "6\.50\.0"')
        self.assertRegex(prov, r'google-beta = \{\s*source\s*= "hashicorp/google-beta"\s*version = "6\.50\.0"')
        self.assertRegex(prov, r'random = \{\s*source\s*= "hashicorp/random"\s*version = "3\.9\.1"')
        # RC B1: >= 1.10.0 (OpenTofu 1.9 cannot parse the FD-0C removed block). No upper bound and no engine
        # restriction: the owner's Terraform fallback is kept (Terraform needs >= 1.7 for `removed` anyway).
        self.assertIn('required_version = ">= 1.10.0"', prov)

    def test_platform_gitignore(self):
        gi = _read(os.path.join(PLATFORM, ".gitignore")).splitlines()
        self.assertIn(".terraform-*/", gi)
        self.assertIn(".terraform.lock.hcl", gi)


class TestScriptsStatic(unittest.TestCase):
    FILES = ("apply.sh", "deploy-services.sh", "bootstrap.sh", os.path.join("common", "platform_target.sh"))

    def test_bash_syntax(self):
        for f in self.FILES:
            r = subprocess.run([BASH, "-n", os.path.join(SCRIPTS, f)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f + ": " + r.stderr)

    def test_no_hosts_rewrite_trigger_delete_or_billing_on_wrapper(self):
        for f in self.FILES:
            src = _read(os.path.join(SCRIPTS, f))
            self.assertNotIn('open("/etc/hosts"', src, f)
            self.assertNotIn("triggers delete", src, f)
        for f in ("apply.sh", "deploy-services.sh"):
            src = _read(os.path.join(SCRIPTS, f))
            self.assertNotIn("add-iam-policy-binding", src, f)
            self.assertNotIn("--update-env-vars", src, f)
            # H3 + FD-4K (main e41be6b): nothing is ever made public; the only IAM-related flag is the git
            # server's --no-allow-unauthenticated (tests/test_deploy_services_git_server_auth.py counts it).
            self.assertNotIn(" --allow-unauthenticated", src, f)
            self.assertNotIn('"--allow-unauthenticated"', src, f)
            if f == "apply.sh":
                self.assertNotIn("allow-unauthenticated", src, f)
            self.assertNotIn("castor-docker-repo/${retry_item}:latest", src, f)

    def test_ipv4_fix_kept_with_marked_hosts_block(self):
        """Register row 17: all four layers kept; /etc/hosts only through the marked block."""
        common = _read(os.path.join(SCRIPTS, "common", "platform_target.sh"))
        self.assertIn("SV_IPV4_BEGIN='# BEGIN stackvend-ipv4'", common)
        self.assertIn("SV_IPV4_END='# END stackvend-ipv4'", common)
        self.assertIn('GODEBUG="${out:+${out},}netdns=cgo"', common)
        self.assertIn("precedence ::ffff:0:0/96 100", common)
        self.assertIn("net.ipv6.conf.all.disable_ipv6=1", common)
        self.assertIn('if [ "${CLOUD_SHELL:-}" != "true" ] && [ -z "${force}" ]; then', common)
        # The old greedy rewrite (delete any line CONTAINING a pinned domain) must not come back.
        self.assertNotIn("any(d in l", common)
        for f in ("apply.sh", "bootstrap.sh"):
            src = _read(os.path.join(SCRIPTS, f))
            self.assertIn('sv_network_setup "${IPV4_FIX}"', src, f)
            self.assertIn("--ipv4-fix) IPV4_FIX=1", src, f)
            self.assertNotIn("cloudshell-ipv4-fix", src, f)
        apply_src = _read(os.path.join(SCRIPTS, "apply.sh"))
        # Runs for every subcommand (plan included), after the allowlists and target guards.
        self.assertLess(apply_src.index("sv_resolve_platform_target\n"), apply_src.index('sv_network_setup "${IPV4_FIX}"'))
        self.assertNotIn("Ignoring --", apply_src)

    def test_bootstrap_writes_platform_github_repo(self):
        src = _read(os.path.join(SCRIPTS, "bootstrap.sh"))
        self.assertIn('platform_github_repo               = ""', src)

    def test_bootstrap_gemini_key_never_plaintext(self):
        src = _read(os.path.join(SCRIPTS, "bootstrap.sh"))
        # BOOTSTRAP-NO-GEMINI-KEY-PROMPT (owner 11-16): no key prompt any more; an existing ENABLED version is wired
        # as a secret reference (tests/test_bootstrap_no_gemini_key_prompt.py).
        self.assertNotIn("AI Studio Gemini API Key", src)
        self.assertNotIn("INPUT_GEMINI_KEY", src)
        self.assertNotIn("GEMINI_API_KEY=$", src)
        self.assertIn('--update-secrets="GEMINI_API_KEY=castor-gemini-api-key:latest"', src)
        self.assertIn('--filter="state=ENABLED"', src)

    def test_bootstrap_apply_is_gated(self):
        """Red team F4: bootstrap's apply goes through the shared gate; no -auto-approve left."""
        src = _read(os.path.join(SCRIPTS, "bootstrap.sh"))
        self.assertNotIn("-auto-approve", src)
        # BG-1: the only extra plan args are the billing preflight's -var=bind_billing_iam (tests/test_bg1_billing_grants.py).
        self.assertIn('if sv_gated_apply bootstrap "" ${SV_BILLING_TF_ARGS[@]+"${SV_BILLING_TF_ARGS[@]}"}; then', src)
        self.assertIn("--overwrite-tfvars) OVERWRITE_TFVARS=1", src)
        self.assertIn("*.tfvars.bak-*", _read(os.path.join(PLATFORM, ".gitignore")).splitlines())

    def test_bootstrap_needs_no_gcloud_beta(self):
        """RC B2: Terraform creates the service agents; no hidden `gcloud beta` prompt can stall the installer."""
        src = _read(os.path.join(SCRIPTS, "bootstrap.sh"))
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotIn("gcloud beta", code)
        self.assertNotIn("services identity create", code)
        main = _read(os.path.join(PLATFORM, "main.tf"))
        for name, svc in (("iap_sa", "iap"), ("logging_sa", "logging"), ("workflows_sa", "workflows")):
            self.assertRegex(main, r'resource "google_project_service_identity" "%s" \{[^}]*depends_on\s*=\s*\[google_project_service\.apis\][^}]*service\s*=\s*"%s\.googleapis\.com"' % (name, svc))

    def test_bootstrap_no_upgrade_and_per_install_vars(self):
        src = _read(os.path.join(SCRIPTS, "bootstrap.sh"))
        self.assertNotIn("init -upgrade", src)
        self.assertNotIn('-var-file="terraform.tfvars"', src)
        self.assertIn('TFVARS_PATH="${TF_DIR}/${PROJECT_ID}.tfvars"', src)


# ==============================================================================
# 2. Script harness
# ==============================================================================
GCLOUD_STUB = r'''#!/bin/bash
echo "gcloud $*" >> "$STUB_LOG"
a="$*"
case "$a" in
  "config get-value project"*) echo "${STUB_GCLOUD_CONFIG_PROJECT:-}"; exit 0 ;;
  "config get-value compute/region"*) echo ""; exit 0 ;;
  "auth print-access-token"*) echo "stub-token"; exit 0 ;;
  "projects describe"*) echo "${STUB_PROJECT_NUMBER-123456789012}"; exit 0 ;;
  "iam service-accounts describe"*) exit "${STUB_COMPUTE_SA_RC:-0}" ;;
  "storage objects describe"*) exit "${STUB_STATE_EXISTS_RC:-0}" ;;
  "storage buckets describe"*) exit "${STUB_BUCKET_EXISTS_RC:-0}" ;;
  "run services describe castor-git-server"*"--format=json"*)
      if [ -n "${STUB_GIT_JSON:-}" ] && [ -f "$STUB_GIT_JSON" ]; then cat "$STUB_GIT_JSON"; exit 0; fi; exit 1 ;;
  "run services describe castor-git-server"*) exit "${STUB_GIT_SVC_RC:-1}" ;;
  "run services describe mcp-terraform-server"*) echo "${STUB_TF_IMAGE-img@sha256:abc}"; exit 0 ;;
  "run services describe orchestrator-gateway-service"*"--format=json"*)
      if [ -n "${STUB_GW_JSON:-}" ]; then cat "$STUB_GW_JSON"; exit 0; fi
      echo '{"status": {"traffic": [{"percent": 100, "latestRevision": true}], "latestReadyRevisionName": "gw-00002"}}'; exit 0 ;;
  "run services describe"*) echo "https://stub.run.app"; exit 0 ;;
  "run jobs update"*) exit "${STUB_JOBS_UPDATE_RC:-0}" ;;
  "run jobs list"*) echo "${STUB_JOBS_LIST-stage-runner}"; exit "${STUB_JOBS_LIST_RC:-0}" ;;
  "run revisions describe"*) echo "${STUB_REVISION_IMAGE-img@sha256:serving}"; exit 0 ;;
  "run deploy "*|"run jobs deploy "*)
      if [ -n "${STUB_DEPLOY_FAIL_ONCE:-}" ] && [[ "$a" == *" ${STUB_DEPLOY_FAIL_ONCE} "* ]] && [ ! -e "$STUB_LOG.failed-once" ]; then
          touch "$STUB_LOG.failed-once"; exit 1
      fi
      exit "${STUB_DEPLOY_RC:-0}" ;;
  "builds triggers describe"*)
      if [ -n "${STUB_TRIGGER_ID:-}" ]; then echo "$STUB_TRIGGER_ID"; exit 0; fi; exit 1 ;;
  "secrets versions list"*) echo "${STUB_SECRET_VERSION:-}"; exit 0 ;;
esac
exit 0
'''

TOFU_STUB = r'''#!/bin/bash
for x in "$@"; do
  if [ "$x" = "console" ]; then
    [ -n "${REAL_TOFU:-}" ] || exit 1
    echo "${TF_DATA_DIR:-}" >> "$STUB_LOG.console"
    exec "$REAL_TOFU" "$@"
  fi
done
# RC B1: the wrappers' engine version check (sv_require_iac_version) reads `version -json`; not logged.
if [ "$1" = "version" ] && [ "${2:-}" = "-json" ]; then
  echo "{\"terraform_version\": \"${STUB_ENGINE_SEMVER:-1.13.1}\"}"; exit 0
fi
echo "tofu $*" >> "$STUB_LOG"
case "$1" in plan|apply) echo "GODEBUG=${GODEBUG-<unset>}" >> "$STUB_LOG.env" ;; esac
case "$1" in
  version) echo "OpenTofu v1.13.1"; exit 0 ;;
  init)
    b=""
    for x in "$@"; do case "$x" in -backend-config=bucket=*) b="${x#-backend-config=bucket=}" ;; esac; done
    mkdir -p "$TF_DATA_DIR"
    printf '{"backend":{"type":"gcs","config":{"bucket":"%s"}}}' "${STUB_INIT_BUCKET:-$b}" > "$TF_DATA_DIR/terraform.tfstate"
    exit 0 ;;
  plan)
    for x in "$@"; do case "$x" in -out=*) echo plan > "${x#-out=}"; echo "${x#-out=}" > "$STUB_LOG.planfile" ;; esac; done
    exit "${STUB_PLAN_RC:-0}" ;;
  show) cat "$STUB_PLAN_JSON"; exit 0 ;;
  apply) exit 0 ;;
  state) [ -n "${STUB_STATE_LIST:-}" ] && cat "$STUB_STATE_LIST"; exit 0 ;;
  workspace)
    # Real tofu: TF_WORKSPACE (scrubbed by the wrapper), else ${TF_DATA_DIR}/environment, else default.
    if [ -n "${STUB_WORKSPACE:-}" ]; then echo "$STUB_WORKSPACE"
    elif [ -f "$TF_DATA_DIR/environment" ]; then cat "$TF_DATA_DIR/environment"
    else echo default; fi
    exit 0 ;;
  import) exit "${STUB_IMPORT_RC:-0}" ;;
esac
exit 0
'''

LOGGER_STUB = '#!/bin/bash\necho "$(basename "$0") $*" >> "$STUB_LOG"\nexit 0\n'

# BOOTSTRAP-FOLDER-IAM-PREFLIGHT (scripts/common/folder_iam_preflight.sh): a curl-stub fragment, placed right after
# the shebang, that answers the Folder IAM Admin testIamPermissions call (and only it). Default: both permissions
# granted, HTTP 200. STUB_FOLDER_IAM_BODY (a file) / STUB_FOLDER_IAM_CODE / STUB_FOLDER_IAM_MODE=fail (curl rc 7)
# change the answer. The call is logged to $STUB_LOG.folderiam (not $STUB_LOG, so other tests' call lists are
# unchanged), with "auth-on-stdin" when the bearer token came on stdin (--config -).
FOLDER_IAM_CURL_CASE = r'''case "$*" in *resourcemanager.folders.setIamPolicy*)
  fi_out=""; fi_prev=""
  for fi_a in "$@"; do [ "$fi_prev" = "-o" ] && fi_out="$fi_a"; fi_prev="$fi_a"; done
  fi_stdin="$(cat)"
  echo "curl $*" >> "$STUB_LOG.folderiam"
  case "$fi_stdin" in *'header = "Authorization: Bearer '*) echo "auth-on-stdin" >> "$STUB_LOG.folderiam" ;; esac
  [ "${STUB_FOLDER_IAM_MODE:-answer}" = "fail" ] && exit 7
  if [ -n "${STUB_FOLDER_IAM_BODY:-}" ]; then cat "$STUB_FOLDER_IAM_BODY" > "$fi_out"
  else echo '{"permissions": ["resourcemanager.folders.setIamPolicy", "resourcemanager.folders.get"]}' > "$fi_out"; fi
  printf '%s' "${STUB_FOLDER_IAM_CODE:-200}"
  exit 0 ;;
esac
'''

# Logs every call. With STUB_SUDO_ROOT set (IPv4-fix tests only), re-roots /etc/* arguments into
# the fake root and runs the command (never sysctl). Without it, nothing is executed.
SUDO_STUB = r'''#!/bin/bash
echo "sudo $*" >> "$STUB_LOG"
[ -n "${STUB_SUDO_ROOT:-}" ] || exit 0
[ "$1" = "sysctl" ] && exit 0
args=()
for a in "$@"; do
  case "$a" in /etc/*) a="${STUB_SUDO_ROOT}${a}" ;; esac
  args+=("$a")
done
exec "${args[@]}"
'''

UNAME_STUB = '#!/bin/bash\necho "${STUB_UNAME:-Darwin}"\n'

# `getent -s hosts:dns ahostsv4 <host>` in glibc's output format; documentation-range address.
GETENT_STUB = r'''#!/bin/bash
echo "getent $*" >> "$STUB_LOG"
[ -n "${STUB_GETENT_FAIL:-}" ] && exit 2
h="${@: -1}"
ip="${STUB_GETENT_IP:-192.0.2.10}"
printf '%s       STREAM %s\n%s       DGRAM  \n' "$ip" "$h" "$ip"
'''

PROJ = "proj-aaaa1"
OTHER = "proj-bbbb2"


def _tfvars(project=PROJ, extra=""):
    # host_vpc_egress = false: the platform network's org policy preflight (scripts/common/host_network_preflight.sh)
    # then makes no call, so these harness runs see only the preflights they test; tests/test_host_network_preflight.py
    # covers it with the switches on.
    return textwrap.dedent(f'''\
        project_id                  = "{project}"
        region                      = "us-central1"
        vcs_provider                = "SERVERLESS_GIT"
        deploy_git_server           = true
        host_vpc_egress             = false
        ''') + extra


def _plan_json(actions_list, drift=None):
    d = {"resource_changes": [
        {"address": f"x.r{i}", "change": {"actions": a}} for i, a in enumerate(actions_list)]}
    if drift is not None:
        # `tofu show -json` of a `plan -refresh-only`: changes live in resource_drift (red team dry-run 3).
        d["resource_drift"] = [{"address": f"d.r{i}", "mode": "managed", "type": "time_rotating", "name": f"r{i}",
                                "change": {"actions": a}} for i, a in enumerate(drift)]
    return json.dumps(d)


GOOD_GIT_JSON = {"spec": {"template": {
    "metadata": {"annotations": {"run.googleapis.com/execution-environment": "gen2"}},
    "spec": {"volumes": [{"name": "git-storage", "csi": {"driver": "gcsfuse.run.googleapis.com",
                                                         "volumeAttributes": {"bucketName": f"castor-git-repos-{PROJ}"}}}],
             "containers": [{"image": "x", "volumeMounts": [{"name": "git-storage", "mountPath": "/data/git"}]}]}}}}


class _Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lane5-")
        self.repo = os.path.join(self.tmp, "repo")
        shutil.copytree(SCRIPTS, os.path.join(self.repo, "scripts"))
        self.platform = os.path.join(self.repo, "infra", "platform")
        os.makedirs(self.platform)
        shutil.copy(os.path.join(PLATFORM, "variables.tf"), self.platform)
        self.stub = os.path.join(self.tmp, "stubbin")
        os.makedirs(self.stub)
        for name, body in (("gcloud", GCLOUD_STUB), ("tofu", TOFU_STUB), ("sudo", SUDO_STUB), ("gsutil", LOGGER_STUB),
                           ("uname", UNAME_STUB), ("getent", GETENT_STUB), ("curl", LOGGER_STUB), ("sleep", LOGGER_STUB)):
            p = os.path.join(self.stub, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        os.symlink(shutil.which("python3") or "/usr/bin/python3", os.path.join(self.stub, "python3"))
        self.log = os.path.join(self.tmp, "calls.log")
        open(self.log, "w").close()
        for d in ("home", "gcloudcfg", "tmpdir"):
            os.makedirs(os.path.join(self.tmp, d))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, content):
        p = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        return p

    def env(self, **extra):
        e = {
            "PATH": f"{self.stub}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": os.path.join(self.tmp, "home"),
            "TMPDIR": os.path.join(self.tmp, "tmpdir"),
            "CLOUDSDK_CONFIG": os.path.join(self.tmp, "gcloudcfg"),
            "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc-disabled.json",
            "STUB_LOG": self.log,
            "REAL_TOFU": REAL_TOFU or "",
            "LANG": "C",
        }
        e.update({k: str(v) for k, v in extra.items()})
        # Lane 2 standing rule: the scripts start python3 children; give them the guard's Layer-0 security
        # settings (proxy sentinel, ADC disabled, sitecustomize shim) on top of this from-scratch env.
        return hermetic_guard.hermetic_env(e)

    def run_script(self, script, args, tty_input=None, **env):
        cmd = [BASH, os.path.join(self.repo, "scripts", script)] + list(args)
        if tty_input is None:
            r = subprocess.run(cmd, cwd=self.repo, env=self.env(**env), stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=120, start_new_session=True)
            return r.returncode, r.stdout, r.stderr
        master, slave = pty.openpty()
        # No echo, and drain the master: otherwise the exiting child blocks in tty close until
        # the (unread) echo of the typed input drains.
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        def _drain():
            try:
                while os.read(master, 1024):
                    pass
            except OSError:
                pass

        drainer = threading.Thread(target=_drain, daemon=True)
        drainer.start()
        try:
            p = subprocess.Popen(cmd, cwd=self.repo, env=self.env(**env), stdin=slave, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
            os.close(slave)
            slave = None
            os.write(master, tty_input.encode() + b"\n")
            out, err = p.communicate(timeout=120)
            return p.returncode, out.decode(errors="replace"), err.decode(errors="replace")
        finally:
            if slave is not None:
                os.close(slave)
            os.close(master)

    def calls(self):
        with open(self.log) as f:
            return f.read().splitlines()

    def tofu_ops(self):
        """tofu invocations other than the harmless engine probe (`tofu version`)."""
        return [x for x in self.calls() if x.startswith("tofu ") and x != "tofu version"]

    def console_data_dirs(self):
        p = self.log + ".console"
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return f.read().splitlines()

    def assert_no_mutation_calls(self):
        c = "\n".join(self.calls())
        for bad in ("sudo ", "services enable", "billing", "tofu import", "triggers delete", "buckets create",
                    "add-iam-policy-binding", "tofu apply", "gsutil "):
            self.assertNotIn(bad, c)


# ------------------------------------------------------------------------------
# apply.sh: allowlists (no tofu needed: they abort before target resolution)
# ------------------------------------------------------------------------------
class TestApplyAllowlists(_Harness):
    def test_refused_subcommands(self):
        for sub in (["refresh"], ["taint", "x"], ["state", "rm", "x"], ["state", "mv", "a", "b"], ["force-unlock", "1"],
                    ["workspace", "new", "x"], ["init-migrate"], ["init-upgrade"], ["upgrade"]):
            rc, out, err = self.run_script("apply.sh", sub, PROJECT_ID=PROJ)
            self.assertNotEqual(rc, 0, sub)
        self.assertEqual(self.calls(), [])

    def test_refused_flags(self):
        cases = [("plan", "-var=project_id=x"), ("plan", "-var-file=/tmp/x.tfvars"), ("plan", "-out=p.bin"),
                 ("plan", "-lock=true"), ("plan", "-refresh=false"), ("plan", "-state=x"), ("plan", "-chdir=/"),
                 ("plan", "-backend-config=bucket=x"), ("apply", "-auto-approve"), ("apply", "-refresh=false"),
                 ("apply", "-lock=false"), ("destroy", "-auto-approve"), ("plan", "-target"), ("output", "-state=x")]
        for sub, flag in cases:
            rc, out, err = self.run_script("apply.sh", [sub, flag], PROJECT_ID=PROJ)
            self.assertNotEqual(rc, 0, (sub, flag))
            self.assertIn("not allowed", err, (sub, flag))
        self.assertEqual(self.calls(), [])

    def test_plan_rejects_positional(self):
        rc, _, err = self.run_script("apply.sh", ["plan", "extra"], PROJECT_ID=PROJ)
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.calls(), [])


@unittest.skipUnless(REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestApplyTargetGuards(_Harness):
    def setUp(self):
        super().setUp()
        self.tfvars = self.write(f"infra/platform/{PROJ}.tfvars", _tfvars())
        self.tfvars_bytes = _read(self.tfvars)

    def test_plan_happy_path_is_read_only(self):
        rc, out, err = self.run_script("apply.sh", ["plan", "-no-color"], PROJECT_ID=PROJ)
        self.assertEqual(rc, 0, err)
        c = self.calls()
        self.assertIn(f"gcloud storage objects describe gs://castor-tfstate-{PROJ}/platform/state/default.tfstate --project={PROJ}", c)
        self.assertIn(f"tofu init -reconfigure -input=false -backend-config=bucket=castor-tfstate-{PROJ}", c)
        plans = [x for x in c if x.startswith("tofu plan")]
        self.assertEqual(plans, [f"tofu plan -lock=false -input=false -var-file={os.path.realpath(self.tfvars)} -no-color"])
        self.assert_no_mutation_calls()
        # Do No Harm: the vars file is never rewritten.
        self.assertEqual(_read(self.tfvars), self.tfvars_bytes)
        # G3: per-install init dir.
        self.assertTrue(os.path.isdir(os.path.join(self.platform, f".terraform-{PROJ}")))

    def test_project_mismatch_with_tfvars_file(self):
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=OTHER, TFVARS_FILE=self.tfvars)
        self.assertNotEqual(rc, 0)
        self.assertIn("Refusing to mix installs", err)
        self.assertEqual(self.tofu_ops(), [])

    def test_project_mismatch_inside_selected_file(self):
        self.write(f"infra/platform/{OTHER}.tfvars", _tfvars(project=PROJ))
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=OTHER)
        self.assertNotEqual(rc, 0)
        self.assertIn("Refusing to mix installs", err)
        self.assertEqual(self.tofu_ops(), [])

    def test_relative_tfvars_file_resolved_before_cd(self):
        rc, _, err = self.run_script("apply.sh", ["plan"], TFVARS_FILE=f"infra/platform/{PROJ}.tfvars")
        self.assertEqual(rc, 0, err)
        self.assertTrue(any(x.startswith(f"tofu plan -lock=false -input=false -var-file={os.path.realpath(self.tfvars)}") for x in self.calls()))

    def test_missing_project_id_in_file_aborts(self):
        """`tofu console` prints (known after apply) with rc 0 for a missing var: must still abort."""
        bad = self.write("infra/platform/nopid.tfvars", 'region = "us-central1"\n')
        rc, _, err = self.run_script("apply.sh", ["plan"], TFVARS_FILE=bad)
        self.assertNotEqual(rc, 0)
        self.assertIn("Cannot read a valid project_id", err)
        self.assertEqual(self.tofu_ops(), [])

    def test_unparseable_tfvars_aborts(self):
        self.write(f"infra/platform/{PROJ}.tfvars", 'project_id = "proj-aaaa1\n')
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ)
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.tofu_ops(), [])

    def test_invalid_project_id_rejected_before_any_path(self):
        for pid in ("../../etc", "Proj-Upper1", "ab", "proj_underscore"):
            rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=pid)
            self.assertNotEqual(rc, 0, pid)
            self.assertIn("not a valid GCP project id", err, pid)
        self.assertEqual([d for d in os.listdir(self.platform) if d.startswith(".terraform")], [])

    def test_invalid_region_rejected(self):
        self.write(f"infra/platform/{PROJ}.tfvars", _tfvars().replace('"us-central1"', '"../x"'))
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ)
        self.assertNotEqual(rc, 0)
        self.assertIn("not a valid GCP region", err)

    def test_tofu_env_channels_refused(self):
        for k, v in (("TF_VAR_project_id", OTHER), ("TF_CLI_ARGS", "-refresh=false"), ("TF_CLI_ARGS_apply", "-auto-approve"),
                     ("TF_WORKSPACE", "scratch"),
                     # red team F1: state/plan format and provider binding
                     ("TF_ENCRYPTION", 'key_provider "pbkdf2" "k" { passphrase = "x" }'),
                     ("GOOGLE_ENCRYPTION_KEY", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="),
                     ("GOOGLE_KMS_ENCRYPTION_KEY", "projects/p/locations/l/keyRings/r/cryptoKeys/k"),
                     ("TF_REATTACH_PROVIDERS", '{"registry.opentofu.org/hashicorp/google":{}}'),
                     ("TF_CLI_CONFIG_FILE", "/tmp/devoverrides.tfrc"), ("TERRAFORM_CONFIG", "/tmp/devoverrides.tfrc"),
                     ("TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE", "1")):
            open(self.log, "w").close()
            rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ, **{k: v})
            self.assertNotEqual(rc, 0, k)
            self.assertIn(k, err)
            self.assertIn("Refusing to run with these environment variables", err, k)
            self.assertEqual(self.tofu_ops(), [], k)
            self.assertEqual([x for x in self.calls() if x.startswith("gcloud")], [], k)

    def test_harmless_tofu_env_still_allowed(self):
        """Negative control: logging/cache/automation vars change neither state format nor provider binding."""
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ, TF_LOG="INFO", TF_IN_AUTOMATION="1",
                                     TF_PLUGIN_CACHE_DIR=os.path.join(self.tmp, "cache"), TF_INPUT="0")
        self.assertEqual(rc, 0, err)
        self.assertTrue([x for x in self.calls() if x.startswith("tofu plan")])

    def test_stale_workspace_file_is_reset_to_default(self):
        """Red team F2: init -reconfigure keeps ${TF_DATA_DIR}/environment; the wrapper drops it before init."""
        data_dir = os.path.join(self.platform, f".terraform-{PROJ}")
        os.makedirs(data_dir)
        with open(os.path.join(data_dir, "environment"), "w") as f:
            f.write("foo")
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ)
        self.assertEqual(rc, 0, err)
        self.assertFalse(os.path.exists(os.path.join(data_dir, "environment")))
        c = self.calls()
        init_i = c.index(f"tofu init -reconfigure -input=false -backend-config=bucket=castor-tfstate-{PROJ}")
        ws_i = c.index("tofu workspace show")
        plan_i = [i for i, x in enumerate(c) if x.startswith("tofu plan")][0]
        self.assertLess(init_i, ws_i)
        self.assertLess(ws_i, plan_i)

    def test_non_default_workspace_refused(self):
        for sub, tty in (("plan", None), ("apply", PROJ), ("state", None)):
            open(self.log, "w").close()
            args = [sub, "list"] if sub == "state" else [sub]
            rc, _, err = self.run_script("apply.sh", args, tty_input=tty, PROJECT_ID=PROJ, STUB_WORKSPACE="foo")
            self.assertNotEqual(rc, 0, sub)
            self.assertIn("Selected workspace is 'foo', expected 'default'", err, sub)
            ops = self.tofu_ops()
            self.assertEqual(ops[-1], "tofu workspace show", (sub, ops))
            self.assertFalse([x for x in self.calls() if "services enable" in x], sub)

    def test_autoload_files_refused(self):
        for name in ("terraform.tfvars.json", "x.auto.tfvars", "x.auto.tfvars.json", "terraform.tfvars"):
            p = self.write(f"infra/platform/{name}", "{}\n" if name.endswith(".json") else 'project_id = "proj-bbbb2"\n')
            rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ)
            self.assertNotEqual(rc, 0, name)
            os.remove(p)
        self.assertEqual(self.tofu_ops(), [])

    def test_terraform_tfvars_fallback_when_project_matches(self):
        os.remove(self.tfvars)
        legacy = self.write("infra/platform/terraform.tfvars", _tfvars())
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ)
        self.assertEqual(rc, 0, err)
        self.assertTrue(any(f"-var-file={os.path.realpath(legacy)}" in x for x in self.calls()))

    def test_gcloud_config_fallback_is_loud_and_guarded(self):
        rc, _, err = self.run_script("apply.sh", ["plan"], STUB_GCLOUD_CONFIG_PROJECT=PROJ)
        self.assertEqual(rc, 0, err)
        self.assertIn("from gcloud config", err)
        open(self.log, "w").close()
        rc, _, err = self.run_script("apply.sh", ["plan"], STUB_GCLOUD_CONFIG_PROJECT=OTHER)
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.tofu_ops(), [])

    def test_missing_state_object_aborts_before_init(self):
        """H7: the gcs backend would WRITE an empty state on init/plan when the object is missing."""
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ, STUB_STATE_EXISTS_RC=1)
        self.assertNotEqual(rc, 0)
        self.assertIn("No platform state", err)
        self.assertEqual(self.tofu_ops(), [])

    def test_backend_bucket_mismatch_aborts_before_plan(self):
        rc, _, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ, STUB_INIT_BUCKET=f"castor-tfstate-{OTHER}")
        self.assertNotEqual(rc, 0)
        self.assertIn("Backend is bound", err)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu plan")])


HOSTS_BEGIN = "# BEGIN stackvend-ipv4"
HOSTS_END = "# END stackvend-ipv4"
GAI_LINE = "precedence ::ffff:0:0/96 100"
N_PIN_DOMAINS = 30
# Lines a hosts file may legitimately hold: a comment naming a pinned host, a non-Google pin, a
# Google pin written by hand, CRLF, and no trailing newline (the old substring delete removed some).
HOSTS_ORIG = ("127.0.0.1\tlocalhost\n"
              "# iam.googleapis.com is pinned below by stackvend (comment, kept)\n"
              "10.1.2.3 build.internal.example\r\n"
              "10.9.9.9 myhost.example # run.googleapis.com mirror\n"
              "::1 ip6-localhost")


@unittest.skipUnless(REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestIPv4Fix(_Harness):
    """Register row 17 (owner 10-12): the Cloud Shell IPv4 fix is kept, all four layers."""

    def setUp(self):
        super().setUp()
        self.tfvars = self.write(f"infra/platform/{PROJ}.tfvars", _tfvars())
        self.root = os.path.join(self.tmp, "fakeroot")
        os.makedirs(os.path.join(self.root, "etc"))
        self.hosts = os.path.join(self.root, "etc", "hosts")
        self.gai = os.path.join(self.root, "etc", "gai.conf")
        self._write_hosts(HOSTS_ORIG)
        self.plan_json = os.path.join(self.tmp, "plan.json")
        with open(self.plan_json, "w") as f:
            f.write(_plan_json([["update"]]))

    def _write_hosts(self, text):
        with open(self.hosts, "w", newline="") as f:
            f.write(text)

    def _hosts(self):
        with open(self.hosts, newline="") as f:
            return f.read()

    def _run(self, args, cloud_shell=True, tty_input=None, **env):
        if cloud_shell:
            env["CLOUD_SHELL"] = "true"
        env.setdefault("STUB_UNAME", "Linux")
        return self.run_script("apply.sh", args, tty_input=tty_input, PROJECT_ID=PROJ, STUB_SUDO_ROOT=self.root,
                               STUB_PLAN_JSON=self.plan_json, **env)

    def _block(self, text):
        lines = text.splitlines()
        self.assertEqual(lines.count(HOSTS_BEGIN), 1, text)
        self.assertEqual(lines.count(HOSTS_END), 1, text)
        return lines[lines.index(HOSTS_BEGIN) + 1:lines.index(HOSTS_END)]

    def _outside(self, text):
        lines = text.splitlines(keepends=True)
        marks = [l.strip() for l in lines]
        b, e = marks.index(HOSTS_BEGIN), marks.index(HOSTS_END)
        return "".join(lines[:b] + lines[e + 1:])

    def _godebug(self):
        with open(self.log + ".env") as f:
            return f.read().splitlines()

    def test_cloud_shell_plan_writes_block_idempotently(self):
        rc, _, err = self._run(["plan"])
        self.assertEqual(rc, 0, err)
        text = self._hosts()
        block = self._block(text)
        self.assertEqual(len(block), N_PIN_DOMAINS)
        self.assertTrue(all(re.fullmatch(r"192\.0\.2\.10 [a-z0-9]+\.googleapis\.com", l) for l in block), block)
        # Every pre-existing line is kept byte-for-byte (only the missing final newline is added).
        self.assertTrue(text.startswith(HOSTS_ORIG + "\n" + HOSTS_BEGIN + "\n"), text)
        with open(self.gai) as f:
            self.assertEqual(f.read().splitlines(), [GAI_LINE])
        c = self.calls()
        self.assertTrue([x for x in c if x.startswith("sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1")])
        self.assertTrue([x for x in c if x.startswith("getent -s hosts:dns ahostsv4 ")])
        self.assertEqual(self._godebug(), ["GODEBUG=netdns=cgo"])
        # Everything else about plan stays read-only.
        joined = "\n".join(x for x in c if x.startswith(("gcloud", "tofu", "gsutil")))
        for bad in ("services enable", "billing", "tofu import", "tofu apply", "buckets create", "add-iam-policy-binding"):
            self.assertNotIn(bad, joined)

        # Second run, same addresses: no change at all.
        rc, _, err = self._run(["plan"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(self._hosts(), text)
        with open(self.gai) as f:
            self.assertEqual(f.read().splitlines(), [GAI_LINE])

        # Third run, new addresses: the block is replaced as a whole, in place; nothing else moves.
        rc, _, err = self._run(["plan"], STUB_GETENT_IP="198.51.100.7")
        self.assertEqual(rc, 0, err)
        text2 = self._hosts()
        self.assertTrue(all(l.startswith("198.51.100.7 ") for l in self._block(text2)))
        self.assertEqual(self._outside(text2), self._outside(text))

    def test_cloud_shell_apply_also_runs_fix(self):
        rc, _, err = self._run(["apply"], tty_input=PROJ)
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self._block(self._hosts())), N_PIN_DOMAINS)
        self.assertTrue([x for x in self.calls() if x.startswith("tofu apply")])
        self.assertTrue(all(x == "GODEBUG=netdns=cgo" for x in self._godebug()))

    def test_block_in_middle_replaced_in_place(self):
        before = "127.0.0.1 localhost\n"
        after = "10.0.0.5 after.example\n# trailing comment\n"
        self._write_hosts(before + HOSTS_BEGIN + "\n203.0.113.1 iam.googleapis.com\n" + HOSTS_END + "\n" + after)
        rc, _, err = self._run(["plan"])
        self.assertEqual(rc, 0, err)
        text = self._hosts()
        self.assertTrue(text.startswith(before + HOSTS_BEGIN + "\n"))
        self.assertTrue(text.endswith(HOSTS_END + "\n" + after))
        self.assertEqual(len(self._block(text)), N_PIN_DOMAINS)

    def test_malformed_markers_leave_hosts_untouched(self):
        for text in (HOSTS_BEGIN + "\n1.2.3.4 iam.googleapis.com\n",            # BEGIN without END
                     HOSTS_END + "\n" + HOSTS_BEGIN + "\n",                       # wrong order
                     (HOSTS_BEGIN + "\n" + HOSTS_END + "\n") * 2):                # two blocks
            self._write_hosts(text)
            rc, _, err = self._run(["plan"])
            self.assertEqual(rc, 0, err)
            self.assertEqual(self._hosts(), text)
            self.assertIn("Left unchanged", err)

    def test_dns_failure_keeps_existing_block(self):
        text = "127.0.0.1 localhost\n" + HOSTS_BEGIN + "\n203.0.113.1 iam.googleapis.com\n" + HOSTS_END + "\n"
        self._write_hosts(text)
        rc, _, err = self._run(["plan"], STUB_GETENT_FAIL="1")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self._hosts(), text)
        self.assertIn("left unchanged", err)

    def test_pins_outside_block_reported_never_edited(self):
        text = "127.0.0.1 localhost\n203.0.113.9 storage.googleapis.com\n"
        self._write_hosts(text)
        rc, _, err = self._run(["plan"])
        self.assertEqual(rc, 0, err)
        self.assertTrue(self._hosts().startswith(text))
        self.assertIn("outside the " + HOSTS_BEGIN, err)

    def test_existing_gai_conf_kept_line_appended_once(self):
        with open(self.gai, "w") as f:
            f.write("# local gai\nlabel ::1/128 0")
        rc, _, err = self._run(["plan"])
        self.assertEqual(rc, 0, err)
        with open(self.gai) as f:
            self.assertEqual(f.read(), "# local gai\nlabel ::1/128 0\n" + GAI_LINE + "\n")

    def test_not_cloud_shell_only_godebug(self):
        for sub, tty in (("plan", None), ("apply", PROJ)):
            open(self.log, "w").close()
            rc, _, err = self._run([sub], cloud_shell=False, tty_input=tty, GODEBUG="http2client=0,netdns=go")
            self.assertEqual(rc, 0, err)
            c = self.calls()
            self.assertFalse([x for x in c if x.startswith(("sudo", "getent"))], c)
            self.assertEqual(self._hosts(), HOSTS_ORIG)
            self.assertFalse(os.path.exists(self.gai))
            self.assertTrue(all(x == "GODEBUG=http2client=0,netdns=cgo" for x in self._godebug()))
        # CLOUD_SHELL must be exactly "true".
        open(self.log, "w").close()
        rc, _, err = self._run(["plan"], cloud_shell=False, CLOUD_SHELL="1")
        self.assertEqual(rc, 0, err)
        self.assertFalse([x for x in self.calls() if x.startswith(("sudo", "getent"))])

    def test_flag_forces_fix_outside_cloud_shell(self):
        rc, _, err = self._run(["plan", "--ipv4-fix"], cloud_shell=False)
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self._block(self._hosts())), N_PIN_DOMAINS)
        self.assertEqual([x for x in self.calls() if x.startswith("tofu plan")],
                         [f"tofu plan -lock=false -input=false -var-file={os.path.realpath(self.tfvars)}"])

    def test_flag_on_non_linux_sets_only_godebug(self):
        rc, _, err = self._run(["plan", "--ipv4-fix"], STUB_UNAME="Darwin")
        self.assertEqual(rc, 0, err)
        self.assertFalse([x for x in self.calls() if x.startswith(("sudo", "getent"))])
        self.assertEqual(self._hosts(), HOSTS_ORIG)
        self.assertEqual(self._godebug(), ["GODEBUG=netdns=cgo"])

    def test_hosts_replaced_atomically_mode_and_owner_kept(self):
        """Red team F5: temp file in the same dir + rename (new inode), original mode/owner kept, no temp left."""
        os.chmod(self.hosts, 0o640)
        before = os.stat(self.hosts)
        rc, _, err = self._run(["plan"])
        self.assertEqual(rc, 0, err)
        after = os.stat(self.hosts)
        self.assertNotEqual(before.st_ino, after.st_ino)
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o640)
        self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
        self.assertEqual([f for f in os.listdir(os.path.dirname(self.hosts)) if f.startswith(".hosts.stackvend.")], [])
        self.assertEqual(len(self._block(self._hosts())), N_PIN_DOMAINS)
        # Unchanged content: the file is not rewritten at all (same inode).
        rc, _, err = self._run(["plan"])
        self.assertEqual(rc, 0, err)
        self.assertEqual(os.stat(self.hosts).st_ino, after.st_ino)

    def _hosts_py(self, errno_value):
        """Run the root-step Python of sv_ipv4_files directly with os.replace failing with errno_value."""
        src = _read(os.path.join(SCRIPTS, "common", "platform_target.sh"))
        body = src[src.index("sv_ipv4_files() {"):]
        start = body.index("\n", body.index("<<'PY'")) + 1
        code = body[start:body.index("\nPY\n", start) + 1]
        code_path = os.path.join(self.tmp, "ipv4_files.py")
        with open(code_path, "w") as f:
            f.write(code)
        runner = os.path.join(self.tmp, "runner.py")
        with open(runner, "w") as f:
            f.write(textwrap.dedent('''\
                import os, sys
                code_path, err = sys.argv[1], int(sys.argv[2])
                def _replace(a, b):
                    raise OSError(err, os.strerror(err))
                os.replace = _replace
                sys.argv = [code_path] + sys.argv[3:]
                exec(compile(open(code_path).read(), code_path, "exec"), {"__name__": "__main__"})
                '''))
        entries = os.path.join(self.tmp, "entries")
        with open(entries, "w") as f:
            f.write("192.0.2.10 iam.googleapis.com\n")
        return subprocess.run([shutil.which("python3") or "/usr/bin/python3", runner, code_path, str(errno_value),
                               self.gai, self.hosts, entries, HOSTS_BEGIN, HOSTS_END, "iam.googleapis.com"],
                              capture_output=True, text=True, timeout=60,
                              env=hermetic_guard.child_env(extra={"PATH": "/usr/bin:/bin", "LANG": "C"}))

    def test_hosts_bind_mount_falls_back_to_in_place_write_first(self):
        """Containers bind-mount /etc/hosts: rename fails EBUSY/EXDEV -> overwrite in place, never empty."""
        for err_no in (errno.EBUSY, errno.EXDEV):
            self._write_hosts(HOSTS_ORIG)
            ino = os.stat(self.hosts).st_ino
            r = self._hosts_py(err_no)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("overwriting in place", r.stderr)
            text = self._hosts()
            self.assertEqual(text, HOSTS_ORIG + "\n" + HOSTS_BEGIN + "\n192.0.2.10 iam.googleapis.com\n" + HOSTS_END + "\n")
            self.assertEqual(os.stat(self.hosts).st_ino, ino)
            self.assertEqual([f for f in os.listdir(os.path.dirname(self.hosts)) if f.startswith(".hosts.stackvend.")], [])
        # Shrinking block: the in-place write truncates the old tail after writing.
        long_block = HOSTS_BEGIN + "\n" + "".join("203.0.113.%d iam.googleapis.com\n" % i for i in range(1, 2)) \
            + "# filler " + "x" * 400 + "\n" + HOSTS_END + "\n"
        self._write_hosts("127.0.0.1 localhost\n" + long_block)
        r = self._hosts_py(errno.EBUSY)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._hosts(), "127.0.0.1 localhost\n" + HOSTS_BEGIN + "\n192.0.2.10 iam.googleapis.com\n" + HOSTS_END + "\n")

    def test_hosts_other_rename_error_leaves_original(self):
        r = self._hosts_py(errno.EACCES)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self._hosts(), HOSTS_ORIG)
        self.assertEqual([f for f in os.listdir(os.path.dirname(self.hosts)) if f.startswith(".hosts.stackvend.")], [])

    def test_refused_command_never_touches_machine(self):
        rc, _, err = self._run(["plan", "-var=x=y"])
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self._hosts(), HOSTS_ORIG)


@unittest.skipUnless(REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestApplyGate(_Harness):
    def setUp(self):
        super().setUp()
        self.tfvars = self.write(f"infra/platform/{PROJ}.tfvars", _tfvars())
        self.plan_json = os.path.join(self.tmp, "plan.json")

    def _plan(self, *actions):
        with open(self.plan_json, "w") as f:
            f.write(_plan_json(list(actions)))

    def _planfile(self):
        with open(self.log + ".planfile") as f:
            return f.read().strip()

    def test_apply_happy_path_applies_reviewed_planfile(self):
        self._plan(["forget"], ["update"], ["create"], ["no-op"], ["read"])
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ, PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
        self.assertEqual(rc, 0, err)
        c = self.calls()
        planfile = self._planfile()
        self.assertIn(f"tofu plan -input=false -var-file={os.path.realpath(self.tfvars)} -out={planfile}", c)
        self.assertIn(f"tofu apply -input=false {planfile}", c)
        self.assertTrue(any(x.startswith("gcloud services enable") for x in c))
        self.assertFalse(os.path.exists(os.path.dirname(planfile)), "plan tmp dir must be removed")
        self.assertIn("forget=1", err)

    def test_b3_compute_enabled_and_default_sa_checked_before_apply(self):
        """RC B3: compute.googleapis.com is pre-enabled and the default compute SA is looked up (read-only) before the
        apply binds it; existing installs: one describe call, no wait."""
        self._plan(["update"])
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ, PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
        self.assertEqual(rc, 0, err)
        c = self.calls()
        enables = [x for x in c if x.startswith("gcloud services enable")]
        self.assertTrue(enables)
        self.assertTrue(any(" compute.googleapis.com " in e for e in enables))
        sa = [i for i, x in enumerate(c) if x.startswith("gcloud iam service-accounts describe 123456789012-compute@developer.gserviceaccount.com")]
        self.assertEqual(len(sa), 1)
        self.assertLess(sa[0], c.index(f"tofu apply -input=false {self._planfile()}"))
        self.assertFalse([x for x in c if x.startswith("sleep")])

    def test_b3_missing_default_sa_waits_bounded_then_applies(self):
        self._plan(["update"])
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ, PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json,
                                       STUB_COMPUTE_SA_RC=1)
        self.assertEqual(rc, 0, err)
        c = self.calls()
        self.assertEqual(len([x for x in c if x.startswith("gcloud iam service-accounts describe")]), 12)
        self.assertEqual(len([x for x in c if x.startswith("sleep 10")]), 12)
        self.assertIn("does not exist yet", err)
        self.assertTrue([x for x in c if x.startswith("tofu apply")])

    def test_b3_no_wait_for_refresh_only(self):
        self._plan(["no-op"])
        rc, out, err = self.run_script("apply.sh", ["apply", "-refresh-only"], tty_input=PROJ, PROJECT_ID=PROJ,
                                       STUB_PLAN_JSON=self.plan_json)
        self.assertEqual(rc, 0, err)
        self.assertFalse([x for x in self.calls() if "service-accounts describe" in x or "projects describe" in x])

    def test_apply_refuses_without_terminal(self):
        self._plan(["update"])
        rc, _, err = self.run_script("apply.sh", ["apply"], PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
        self.assertNotEqual(rc, 0)
        c = self.calls()
        self.assertFalse([x for x in c if x.startswith("tofu apply")])
        self.assertFalse([x for x in c if "services enable" in x])
        self.assertFalse(os.path.exists(os.path.dirname(self._planfile())))

    def test_apply_wrong_typed_project(self):
        self._plan(["update"])
        rc, _, err = self.run_script("apply.sh", ["apply"], tty_input=OTHER, PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
        self.assertNotEqual(rc, 0)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu apply")])

    def test_destroy_gate(self):
        for actions in (["delete"], ["delete", "create"], ["create", "delete"]):
            open(self.log, "w").close()
            self._plan(["update"], actions)
            rc, _, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ, PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
            self.assertNotEqual(rc, 0, actions)
            self.assertIn("DESTRUCTIVE", err)
            self.assertFalse([x for x in self.calls() if x.startswith("tofu apply")], actions)

    def test_destroy_gate_wrong_allow_value(self):
        self._plan(["delete"])
        rc, _, err = self.run_script("apply.sh", ["apply", f"--allow-destroy={OTHER}"], tty_input=PROJ, PROJECT_ID=PROJ,
                                     STUB_PLAN_JSON=self.plan_json)
        self.assertNotEqual(rc, 0)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu apply")])

    def test_destroy_gate_explicit_allow(self):
        self._plan(["delete", "create"])
        rc, _, err = self.run_script("apply.sh", ["apply", f"--allow-destroy={PROJ}"], tty_input=PROJ, PROJECT_ID=PROJ,
                                     STUB_PLAN_JSON=self.plan_json)
        self.assertEqual(rc, 0, err)
        self.assertTrue([x for x in self.calls() if x.startswith("tofu apply")])

    def test_no_changes_applies_nothing(self):
        self._plan(["no-op"], ["read"])
        rc, _, err = self.run_script("apply.sh", ["apply"], PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
        self.assertEqual(rc, 0, err)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu apply") or "services enable" in x])

    def _plan_drift(self, drift, *actions):
        with open(self.plan_json, "w") as f:
            f.write(_plan_json(list(actions), drift=drift))

    def test_refresh_only_applies_drift_through_gate(self):
        """Red team F3: a refresh-only plan has no resource_changes; its resource_drift must count."""
        self._plan_drift([["delete"], ["update"], ["no-op"]])
        rc, _, err = self.run_script("apply.sh", ["apply", "-refresh-only"], tty_input=PROJ, PROJECT_ID=PROJ,
                                     STUB_PLAN_JSON=self.plan_json)
        self.assertEqual(rc, 0, err)
        c = self.calls()
        planfile = self._planfile()
        self.assertIn(f"tofu plan -input=false -var-file={os.path.realpath(self.tfvars)} -refresh-only -out={planfile}", c)
        self.assertIn(f"tofu apply -input=false {planfile}", c)
        self.assertIn("2 drift entries to record in state (refresh-only)", err)
        self.assertIn("drift (state only): d.r0 (delete)", err)
        self.assertNotIn("DESTRUCTIVE", err)
        # A refresh-only apply changes state only: no API enable either.
        self.assertFalse([x for x in c if "services enable" in x])

    def test_refresh_only_still_needs_typed_id(self):
        self._plan_drift([["update"]])
        rc, _, err = self.run_script("apply.sh", ["apply", "-refresh-only"], PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
        self.assertNotEqual(rc, 0)
        self.assertIn("needs an interactive terminal", err)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu apply")])

    def test_drift_ignored_without_refresh_only(self):
        """A normal plan's resource_drift is informational: with no resource/output change, nothing is applied."""
        self._plan_drift([["update"]], ["no-op"])
        rc, _, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ, PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
        self.assertEqual(rc, 0, err)
        self.assertIn("No changes. Nothing to apply.", err)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu apply") or "services enable" in x])

    def test_refresh_only_without_drift_applies_nothing(self):
        self._plan_drift([["no-op"]])
        rc, _, err = self.run_script("apply.sh", ["apply", "-refresh-only"], PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json)
        self.assertEqual(rc, 0, err)
        self.assertIn("No changes. Nothing to apply.", err)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu apply")])

    def test_refresh_subcommand_points_at_working_path(self):
        rc, _, err = self.run_script("apply.sh", ["refresh"], PROJECT_ID=PROJ)
        self.assertNotEqual(rc, 0)
        self.assertIn("scripts/apply.sh apply -refresh-only", err)

    def test_destroy_needs_confirm_flag(self):
        rc, _, err = self.run_script("apply.sh", ["destroy"], tty_input=PROJ, PROJECT_ID=PROJ)
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.tofu_ops(), [])

    def test_adopt_import_failure_fails_closed_and_never_deletes(self):
        """FD-0B negative test: a failed import must exit non-zero and never delete anything."""
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write("google_cloud_run_v2_service.git_server[0]\n")   # the git bucket is live but not in state
        rc, _, err = self.run_script("apply.sh", ["adopt"], tty_input=PROJ, PROJECT_ID=PROJ, STUB_STATE_LIST=state,
                                     STUB_IMPORT_RC=1)
        self.assertNotEqual(rc, 0)
        c = "\n".join(self.calls())
        self.assertIn('tofu import -input=false', c)
        self.assertIn(f"{PROJ}/castor-git-repos-{PROJ}", c)
        self.assertNotIn("delete", c)

    def test_console_never_uses_the_backend_bound_data_dir(self):
        """sv_tfvar after init must not inherit TF_DATA_DIR (bound to the gcs backend)."""
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write("google_storage_bucket.git_repos_bucket[0]\ngoogle_cloud_run_v2_service.git_server[0]\n")
        rc, _, err = self.run_script("apply.sh", ["adopt"], PROJECT_ID=PROJ, STUB_STATE_LIST=state)
        self.assertEqual(rc, 0, err)
        dirs = self.console_data_dirs()
        self.assertTrue(dirs)
        bound = os.path.join(self.platform, f".terraform-{PROJ}")
        for d in dirs:
            self.assertNotEqual(os.path.realpath(d) if d else d, os.path.realpath(bound))
            self.assertTrue(d.endswith("/.tfdata"), d)

    def test_adopt_never_looks_for_a_build_trigger(self):
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write("google_storage_bucket.git_repos_bucket[0]\ngoogle_cloud_run_v2_service.git_server[0]\n")
        rc, _, err = self.run_script("apply.sh", ["adopt"], PROJECT_ID=PROJ, STUB_STATE_LIST=state)
        self.assertEqual(rc, 0, err)
        self.assertIn("Nothing to adopt", err)
        c = "\n".join(self.calls())
        self.assertNotIn("tofu import", c)
        self.assertNotIn("triggers describe", c)


# ------------------------------------------------------------------------------
# bootstrap.sh (red team F4): never clobbers <id>.tfvars silently; apply goes through the gate
# ------------------------------------------------------------------------------
class TestBootstrap(_Harness):
    """Fresh-install prompts answered on a pty: Consumer mode, GitHub VCS, no billing, Darwin (no IPv4 fix)."""

    def setUp(self):
        super().setUp()
        self.tfvars = os.path.join(self.platform, f"{PROJ}.tfvars")
        self.plan_json = os.path.join(self.tmp, "plan.json")
        with open(self.plan_json, "w") as f:
            f.write(_plan_json([["create"], ["create"]]))

    @staticmethod
    def _answers(confirm=PROJ):
        # project, region, zone, org, billing, folder, env, VCS (1), GitHub owner,
        # ingress mode (Enter = 1, Direct IAP; always asked since install-polish removed the
        # non-existent org-policy probe), corporate domain, Control Center OAuth client (IAP: skip),
        # tenant sign-in client (skip) [lane 19 L19-0d], typed project id, deploy services? n
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        return "\n".join([PROJ, "", "", "", "", "", "y", "", "", "octo-org", "", "", "", "", confirm, "n"])

    def _run(self, args=(), confirm=PROJ, **env):
        env.setdefault("STUB_PLAN_JSON", self.plan_json)
        return self.run_script("bootstrap.sh", list(args), tty_input=self._answers(confirm), **env)

    def _backups(self):
        return sorted(f for f in os.listdir(self.platform) if f.startswith(f"{PROJ}.tfvars.bak-"))

    def test_fresh_install_writes_vars_and_applies_reviewed_plan(self):
        rc, out, err = self._run()
        self.assertEqual(rc, 0, out + err)
        self.assertIn(f'project_id                         = "{PROJ}"', _read(self.tfvars))
        c = self.calls()
        self.assertIn(f"tofu init -reconfigure -input=false -backend-config=bucket=castor-tfstate-{PROJ}", c)
        self.assertIn("tofu workspace show", c)
        with open(self.log + ".planfile") as f:
            planfile = f.read().strip()
        plans = [x for x in c if x.startswith("tofu plan")]
        self.assertEqual(len(plans), 1)
        self.assertTrue(plans[0].startswith("tofu plan -input=false -var-file=") and plans[0].endswith(f"/{PROJ}.tfvars -out={planfile}"), plans)
        self.assertEqual([x for x in c if x.startswith("tofu apply")], [f"tofu apply -input=false {planfile}"])
        self.assertNotIn("-auto-approve", "\n".join(c))
        self.assertIn("create=2", err)
        self.assertEqual(self._backups(), [])
        self.assertFalse(os.path.exists(os.path.dirname(planfile)), "plan tmp dir must be removed")

    def test_existing_vars_file_refused_without_flag(self):
        # BOOTSTRAP-EXISTING-TFVARS-SELF-CORRECT: when the platform state cannot be checked (this harness's curl
        # answers nothing), the default answer is No: a typed stop, the curated file untouched, nothing run.
        curated = 'project_id = "proj-aaaa1"\ngemini_model_overrides = { "x" = "gemini-3.8-flash" }\n'
        with open(self.tfvars, "w") as f:
            f.write(curated)
        rc, out, err = self._run()
        self.assertNotEqual(rc, 0)
        self.assertIn("BOOTSTRAP_STATE_UNCHECKED", out + err)
        self.assertIn("--overwrite-tfvars", out + err)
        self.assertEqual(_read(self.tfvars), curated)
        self.assertEqual(self._backups(), [])
        c = self.calls()
        self.assertEqual(self.tofu_ops(), [])
        for bad in ("services enable", "config set project", "buckets create", "identity create"):
            self.assertFalse([x for x in c if bad in x], bad)

    def test_overwrite_flag_backs_up_first_then_gates(self):
        curated = 'project_id = "proj-aaaa1"\ngemini_model_overrides = { "x" = "gemini-3.8-flash" }\n'
        with open(self.tfvars, "w") as f:
            f.write(curated)
        os.chmod(self.tfvars, 0o600)
        rc, out, err = self._run(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        backups = self._backups()
        self.assertEqual(len(backups), 1, backups)
        self.assertRegex(backups[0], r"\.tfvars\.bak-\d{8}T\d{6}Z$")
        bak = os.path.join(self.platform, backups[0])
        self.assertEqual(_read(bak), curated)
        self.assertEqual(stat.S_IMODE(os.stat(bak).st_mode), 0o600)
        self.assertNotIn("gemini_model_overrides", _read(self.tfvars))
        self.assertTrue([x for x in self.calls() if x.startswith("tofu apply -input=false ")])

    def test_destructive_plan_refused(self):
        with open(self.plan_json, "w") as f:
            f.write(_plan_json([["create"], ["delete", "create"]]))
        rc, out, err = self._run()
        self.assertNotEqual(rc, 0)
        self.assertIn("DESTRUCTIVE", err)
        self.assertIn(f"scripts/apply.sh apply --allow-destroy={PROJ}", err)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu apply")])

    def test_wrong_typed_project_applies_nothing(self):
        rc, out, err = self._run(confirm=OTHER)
        self.assertNotEqual(rc, 0)
        self.assertIn("Confirmation did not match", err)
        self.assertFalse([x for x in self.calls() if x.startswith("tofu apply")])

    def test_stale_workspace_refused(self):
        rc, out, err = self._run(STUB_WORKSPACE="foo")
        self.assertNotEqual(rc, 0)
        self.assertIn("expected 'default'", err)
        self.assertFalse([x for x in self.calls() if x.startswith(("tofu plan", "tofu apply"))])

    def test_tofu_env_refused_before_anything(self):
        rc, out, err = self._run(TF_ENCRYPTION="x")
        self.assertNotEqual(rc, 0)
        self.assertIn("TF_ENCRYPTION", err)
        self.assertEqual([x for x in self.calls() if not x.startswith("tofu version")], [])
        self.assertFalse(os.path.exists(self.tfvars))

    def test_old_engine_refused_before_any_prompt_or_gcp_call(self):
        """RC B1: OpenTofu 1.9.0 (cannot parse infra/platform) stops with the version message, not a parse error."""
        rc, out, err = self._run(STUB_ENGINE_SEMVER="1.9.0")
        self.assertNotEqual(rc, 0)
        self.assertIn("1.9.0 is too old for infra/platform: it needs 1.10.0 or later", err)
        self.assertNotIn("Enter Google Cloud Project ID", out)
        self.assertEqual(self.tofu_ops(), [])
        self.assertFalse([x for x in self.calls() if x.startswith("gcloud ") and "auth print-access-token" not in x])
        self.assertFalse(os.path.exists(self.tfvars))


class TestEngineVersionGate(_Harness):
    """RC B1: sv_require_iac_version (scripts/common/platform_target.sh), exact semver against SV_IAC_MIN_VERSION."""

    def _check(self, semver):
        cmd = [BASH, "-c", '. scripts/common/platform_target.sh; IAC_BIN=tofu; sv_require_iac_version && echo GATE-OK']
        r = subprocess.run(cmd, cwd=self.repo, env=self.env(STUB_ENGINE_SEMVER=semver), stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout, r.stderr

    def test_minimum_matches_required_version(self):
        common = _read(os.path.join(SCRIPTS, "common", "platform_target.sh"))
        self.assertIn('SV_IAC_MIN_VERSION="1.10.0"', common)
        self.assertIn('required_version = ">= 1.10.0"', _read(os.path.join(PLATFORM, "providers.tf")))

    def test_accepts_minimum_and_later(self):
        for v in ("1.10.0", "1.10.7", "1.13.1", "2.0.0", "1.10.0+build.5"):
            with self.subTest(v=v):
                rc, out, err = self._check(v)
                self.assertEqual(rc, 0, err)
                self.assertIn("GATE-OK", out)

    def test_refuses_older_and_prereleases(self):
        for v in ("1.9.0", "1.9.99", "1.5.7", "0.15.5", "1.10.0-rc1", "1.10.0-beta2"):
            with self.subTest(v=v):
                rc, out, err = self._check(v)
                self.assertNotEqual(rc, 0)
                self.assertIn(f"tofu {v} is too old for infra/platform", err)
                self.assertNotIn("GATE-OK", out)

    def test_unreadable_version_refused(self):
        for v in ("1.10", "v1.10.0", "01.10.0", "garbage", "1.10.0.1"):
            with self.subTest(v=v):
                rc, out, err = self._check(v)
                self.assertNotEqual(rc, 0)
                self.assertIn("Could not read the tofu version", err)

    def test_apply_sh_refuses_old_engine_before_target_resolution(self):
        rc, out, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=PROJ, STUB_ENGINE_SEMVER="1.9.0")
        self.assertNotEqual(rc, 0)
        self.assertIn("1.9.0 is too old for infra/platform", err)
        self.assertEqual(self.tofu_ops(), [])
        self.assertFalse([x for x in self.calls() if x.startswith("gcloud ")])


# ------------------------------------------------------------------------------
# deploy-services.sh
# ------------------------------------------------------------------------------
class TestDeployServices(_Harness):
    DIRS = ("apps/control-center", "apps/orchestrator-gateway", "apps/project-vending", "apps/log-sre-sentinel",
            "apps/spec-ingestion", "mcp-servers/terraform", "mcp-servers/gcloud", "mcp-servers/github",
            "mcp-servers/workspace", "mcp-servers/infracost", "mcp-servers/compliance", "mcp-servers/kubernetes",
            "mcp-servers/agent-builder", "apps/git-server", "apps/refactor-scanner", "apps/qa-runner",
            "apps/finops-enforcer", "apps/infra-rollback", "apps/sandbox-cleaner", "apps/sre-digest",
            "apps/finops-spend-sync", "apps/sandbox-sweeper", "apps/billing-alert-drain")   # C10

    def setUp(self):
        super().setUp()
        for d in self.DIRS:
            os.makedirs(os.path.join(self.repo, d), exist_ok=True)
        os.makedirs(os.path.join(self.repo, "apps/control-center/shared"), exist_ok=True)
        self.write("infra/modules/m/main.tf", "# module\n")
        self.write("shared/builtin_modules_payload.py", "PAYLOAD = {}\n")
        self.git_json = os.path.join(self.tmp, "git.json")

    def _git(self, obj):
        with open(self.git_json, "w") as f:
            json.dump(obj, f)

    def _deploys(self):
        return [x for x in self.calls() if x.startswith("gcloud run deploy") or x.startswith("gcloud run jobs deploy")]

    def test_requires_explicit_project_non_interactive(self):
        rc, _, err = self.run_script("deploy-services.sh", ["control-center"], STUB_GCLOUD_CONFIG_PROJECT=PROJ)
        self.assertNotEqual(rc, 0)
        self.assertIn("PROJECT_ID is not set", err)
        self.assertEqual(self._deploys(), [])

    def test_invalid_project_or_region(self):
        rc, _, _ = self.run_script("deploy-services.sh", ["control-center"], PROJECT_ID="../x")
        self.assertNotEqual(rc, 0)
        rc, _, _ = self.run_script("deploy-services.sh", ["control-center"], PROJECT_ID=PROJ, REGION="us central")
        self.assertNotEqual(rc, 0)
        self.assertEqual(self._deploys(), [])

    def test_terraform_server_syncs_tf_applier_image_only(self):
        rc, out, err = self.run_script("deploy-services.sh", ["mcp-terraform-server"], PROJECT_ID=PROJ, REGION="us-central1",
                                       STUB_TF_IMAGE="us-central1-docker.pkg.dev/p/r/mcp-terraform-server@sha256:feed")
        self.assertEqual(rc, 0, out + err)
        c = self.calls()
        self.assertIn(f"gcloud run deploy mcp-terraform-server --source mcp-servers/terraform --region us-central1 --project {PROJ} --quiet", c)
        self.assertIn(f"gcloud run jobs update tf-applier --image=us-central1-docker.pkg.dev/p/r/mcp-terraform-server@sha256:feed --region=us-central1 --project={PROJ} --quiet", c)
        joined = "\n".join(c)
        for bad in ("--update-env-vars", "add-iam-policy-binding", "allow-unauthenticated", "--cpu", "castor-docker-repo/mcp-terraform-server:latest"):
            self.assertNotIn(bad, joined)

    def test_tf_applier_sync_failure_is_a_failure(self):
        rc, _, _ = self.run_script("deploy-services.sh", ["mcp-terraform-server"], PROJECT_ID=PROJ, STUB_JOBS_UPDATE_RC=1)
        self.assertNotEqual(rc, 0)
        rc, _, _ = self.run_script("deploy-services.sh", ["mcp-terraform-server"], PROJECT_ID=PROJ, STUB_TF_IMAGE="")
        self.assertNotEqual(rc, 0)

    def test_control_center_deploy_sets_no_env(self):
        rc, out, err = self.run_script("deploy-services.sh", ["control-center"], PROJECT_ID=PROJ)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._deploys(), [f"gcloud run deploy product-control-center-ui --source apps/control-center --region us-central1 --project {PROJ} --quiet"])
        self.assertTrue(os.path.exists(os.path.join(self.repo, "apps/control-center/infra/modules/m/main.tf")))
        self.assertNotIn("services update", "\n".join(self.calls()))

    def test_git_server_deploy_requires_fuse_volume(self):
        self._git(GOOD_GIT_JSON)
        rc, out, err = self.run_script("deploy-services.sh", ["git-server"], PROJECT_ID=PROJ, STUB_GIT_JSON=self.git_json)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self._deploys(), [f"gcloud run deploy castor-git-server --source apps/git-server --region us-central1 --project {PROJ} --no-allow-unauthenticated --quiet"])

    def test_git_server_deploy_refused_without_volume_or_gen2(self):
        bad_variants = []
        v = json.loads(json.dumps(GOOD_GIT_JSON)); v["spec"]["template"]["spec"]["volumes"] = []; bad_variants.append(v)
        v = json.loads(json.dumps(GOOD_GIT_JSON)); v["spec"]["template"]["metadata"]["annotations"] = {}; bad_variants.append(v)
        v = json.loads(json.dumps(GOOD_GIT_JSON)); v["spec"]["template"]["spec"]["containers"][0]["volumeMounts"] = []; bad_variants.append(v)
        v = json.loads(json.dumps(GOOD_GIT_JSON))
        v["spec"]["template"]["spec"]["volumes"][0]["csi"]["volumeAttributes"]["bucketName"] = "castor-git-repos-other1"; bad_variants.append(v)
        for v in bad_variants:
            self._git(v)
            open(self.log, "w").close()
            rc, out, err = self.run_script("deploy-services.sh", ["git-server"], PROJECT_ID=PROJ, STUB_GIT_JSON=self.git_json)
            self.assertNotEqual(rc, 0)
            self.assertEqual(self._deploys(), [])

    def test_git_server_absent_single_mode_fails(self):
        rc, out, _ = self.run_script("deploy-services.sh", ["git-server"], PROJECT_ID=PROJ)
        self.assertNotEqual(rc, 0)
        self.assertIn("does not exist", out)
        self.assertEqual(self._deploys(), [])

    def test_bulk_skips_absent_git_server_and_syncs_applier(self):
        rc, out, err = self.run_script("deploy-services.sh", [], PROJECT_ID=PROJ, PARALLEL_LIMIT=4)
        self.assertEqual(rc, 0, out + err)
        names = [x.split()[3] for x in self._deploys()]
        self.assertEqual(len(names), 13)
        self.assertNotIn("castor-git-server", names)
        self.assertIn("Skipping", out)
        self.assertTrue([x for x in self.calls() if x.startswith("gcloud run jobs update tf-applier --image=")])
        self.assertNotIn("/tmp/castor-builds", out)
        self.assertNotIn("add-iam-policy-binding", "\n".join(self.calls()))

    def test_bulk_with_jobs_and_git_server(self):
        self._git(GOOD_GIT_JSON)
        rc, out, err = self.run_script("deploy-services.sh", ["--all-jobs"], PROJECT_ID=PROJ, STUB_GIT_JSON=self.git_json)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(len(self._deploys()), 23)   # C10: + 3 jobs
        # FD-4K: the parallel path keeps the git server private too; no other deploy carries an auth flag.
        auth = [x for x in self._deploys() if "allow-unauthenticated" in x]
        self.assertEqual(auth, [f"gcloud run deploy castor-git-server --source apps/git-server --region us-central1 --project {PROJ} --no-allow-unauthenticated --quiet"])

    def test_bulk_retry_success_still_syncs_applier(self):
        rc, out, err = self.run_script("deploy-services.sh", [], PROJECT_ID=PROJ, STUB_DEPLOY_FAIL_ONCE="mcp-terraform-server")
        self.assertEqual(rc, 0, out + err)
        tf = [x for x in self._deploys() if x.split()[3] == "mcp-terraform-server"]
        self.assertEqual(len(tf), 2)
        self.assertEqual(len([x for x in self.calls() if x.startswith("gcloud run jobs update tf-applier")]), 1)
        self.assertNotIn("artifacts docker images describe", "\n".join(self.calls()))

    def test_bulk_failure_exits_nonzero(self):
        rc, out, _ = self.run_script("deploy-services.sh", [], PROJECT_ID=PROJ, STUB_DEPLOY_RC=1)
        self.assertNotEqual(rc, 0)
        self.assertIn("failed (exit 1", out)


if __name__ == "__main__":
    unittest.main()

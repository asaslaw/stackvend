"""Installer operator messages (owner 10-28, read-only review of scripts/bootstrap.sh): the installer never prints
[OK] / COMPLETE for a step that failed or was skipped.

Runs the real scripts/bootstrap.sh under lane 5's hermetic harness (logging stubs for gcloud/tofu/curl/...; no GCP,
no network). Fresh install answers: Consumer mode, GitHub VCS, no billing, Direct IAP.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)
import test_bg1_billing_grants as BG  # noqa: E402  (module import only: no Test* class is re-collected)

PROJ = L5.PROJ

FAILING_CURL = '#!/bin/bash\necho "curl $*" >> "$STUB_LOG"\nexit 22\n'
# Stands in for scripts/deploy-services.sh in the harness copy: writes the summary file, then fails.
FAILING_DEPLOY = ('#!/bin/bash\necho "deploy-services $*" >> "$STUB_LOG"\n'
                  '[ -n "${STACKVEND_DEPLOY_SUMMARY_FILE:-}" ] && echo "18 2 0" > "$STACKVEND_DEPLOY_SUMMARY_FILE"\n'
                  'exit 1\n')
OK_DEPLOY = '#!/bin/bash\necho "deploy-services $*" >> "$STUB_LOG"\nexit 0\n'


ACCOUNT = "admin@example.com"
# gcloud wrapper: lane 5's stub plus an active account (the Firestore admin seed runs only with one).
ACCOUNT_WRAPPER = r'''#!/bin/bash
case "$*" in
  "config get-value account"*) echo "gcloud $*" >> "$STUB_LOG"; echo "''' + ACCOUNT + r'''"; exit 0 ;;
esac
exec "$(dirname "$0")/gcloud.orig" "$@"
'''


class _Boot(L5._Harness):
    def setUp(self):
        super().setUp()
        stub = os.path.join(self.stub, "gcloud")
        os.rename(stub, os.path.join(self.stub, "gcloud.orig"))
        with open(stub, "w") as f:
            f.write(ACCOUNT_WRAPPER)
        os.chmod(stub, 0o755)
        self.plan_json = os.path.join(self.tmp, "plan.json")
        with open(self.plan_json, "w") as f:
            f.write(L5._plan_json([["create"]]))

    def boot(self, deploy="n", **env):
        # project, region, zone, org, billing, folder, env, mode, VCS, GitHub owner, ingress (Enter =
        # Direct IAP), extra IAP principal, CC client, tenant client, typed project id, deploy services?
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        answers = [PROJ, "", "", "", "", "", "y", "", "", "octo-org", "", "", "", "", PROJ, deploy]
        env.setdefault("STUB_PLAN_JSON", self.plan_json)
        rc, out, err = self.run_script("bootstrap.sh", [], tty_input="\n".join(answers), **env)
        return rc, out + err

    def replace(self, rel, body):
        p = self.write(rel, body)
        os.chmod(p, 0o755)


class TestStateBucket(_Boot):
    def test_bucket_that_cannot_be_created_stops_before_init(self):
        rc, text = self.boot(STUB_BUCKET_EXISTS_RC=1)
        self.assertNotEqual(rc, 0, text)
        self.assertIn(f"Could not create gs://castor-tfstate-{PROJ} (needs storage.buckets.create on {PROJ}", text)
        self.assertNotIn(f"State bucket gs://castor-tfstate-{PROJ} ready", text)
        self.assertEqual([x for x in self.tofu_ops() if not x.startswith("tofu version")], [])

    def test_existing_bucket_unchanged(self):
        rc, text = self.boot()
        self.assertEqual(rc, 0, text)
        self.assertIn(f"State bucket gs://castor-tfstate-{PROJ} exists.", text)


class TestFirestoreSeeds(_Boot):
    def test_failed_writes_warn_not_ok(self):
        self.replace(os.path.join("..", "stubbin", "curl"), FAILING_CURL)
        rc, text = self.boot()
        self.assertEqual(rc, 0, text)   # never fatal
        self.assertNotIn("Registered", text)
        self.assertIn(f"Could not write authorized_users/{ACCOUNT}", text)
        self.assertIn("(the Control Center still admits it as ADMIN_EMAIL)", text)
        self.assertIn("Default VCS not stored; set it in Control Center > Settings", text)

    def test_successful_writes_ok(self):
        rc, text = self.boot()
        self.assertEqual(rc, 0, text)
        self.assertIn("as Platform Administrator in Firestore.", text)
        self.assertIn("Registered default VCS provider", text)
        self.assertTrue([c for c in self.calls() if c.startswith("curl -fsS -X PATCH")])


class TestStage2Status(_Boot):
    def test_skipped_stage2_is_incomplete(self):
        rc, text = self.boot("n")
        self.assertEqual(rc, 0, text)
        self.assertNotIn("BOOTSTRAP COMPLETE", text)
        self.assertNotIn("ready for autonomous development", text)
        self.assertIn("BOOTSTRAP INCOMPLETE: stage 2 did not finish (skipped)", text)
        self.assertIn(f"PROJECT_ID={PROJ} REGION=us-central1 bash scripts/deploy-services.sh --all-jobs", text)

    def test_failed_stage2_reports_count(self):
        self.replace(os.path.join("scripts", "deploy-services.sh"), FAILING_DEPLOY)
        rc, text = self.boot("Y")
        self.assertEqual(rc, 0, text)
        self.assertIn("deploy-services --all-jobs", "\n".join(self.calls()))
        self.assertNotIn("BOOTSTRAP COMPLETE", text)
        self.assertIn("BOOTSTRAP INCOMPLETE: stage 2 did not finish (2 failed)", text)

    def test_successful_stage2_is_complete(self):
        self.replace(os.path.join("scripts", "deploy-services.sh"), OK_DEPLOY)
        rc, text = self.boot("Y")
        self.assertEqual(rc, 0, text)
        self.assertIn("STACKVEND PLATFORM BOOTSTRAP COMPLETE", text)
        self.assertNotIn("INCOMPLETE", text)
        self.assertIn("StackVend is installed. Open the Control Center:", text)

    def test_next_steps_backup_and_admission(self):
        rc, text = self.boot("n")
        self.assertEqual(rc, 0, text)
        tail = text[text.index("Next Steps:"):]
        # TFVARS-AUTO-BACKUP: no manual copy step. The harness's curl stub answers nothing, so the automatic backup
        # could not read the existing copy: a Next Steps item names the retry (tests/test_tfvars_auto_backup.py
        # covers the backup itself).
        self.assertNotIn("gcloud storage cp infra/platform/", tail)
        self.assertIn(f"Back up infra/platform/{PROJ}.tfvars (the automatic backup failed: "
                      "BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN above):", tail)
        self.assertIn(f"PROJECT_ID={PROJ} bash scripts/apply.sh apply (a run with no changes only refreshes the backup)",
                      tail)
        self.assertIn("authorized_invoker_members", tail)
        self.assertIn("Control Center user", tail)
        self.assertIn(f"Open the Control Center signed in as {ACCOUNT}", tail)
        # X1: the account warning right after "Authenticated as".
        self.assertIn("becomes the first Control Center ADMIN", text)
        self.assertIn("a personal Gmail account is", text)


class TestStatic:
    def test_deploy_summary_file_is_opt_in(self):
        src = L5._read(os.path.join(L5.SCRIPTS, "deploy-services.sh"))
        assert 'if [ -n "${STACKVEND_DEPLOY_SUMMARY_FILE:-}" ]; then' in src

    def test_no_internal_jargon_in_printed_text(self):
        src = L5._read(os.path.join(L5.SCRIPTS, "bootstrap.sh"))
        printed = [ln for ln in src.splitlines() if ln.lstrip().startswith(("echo", "read -r", "sv_"))]
        for bad in ("Red team", "register row", "lane 19", "L19-10", "Companion Mode", "castor-github-conn",
                    "without Git merge conflicts"):
            assert not [ln for ln in printed if bad in ln], bad



class TestBillingReminderInNextSteps(BG._BgHarness):
    """X4: when Terraform did not make the billing grants, Next Steps repeats them with the commands."""

    def setUp(self):
        super().setUp()
        self.plan_json = os.path.join(self.tmp, "plan.json")
        with open(self.plan_json, "w") as f:
            f.write(L5._plan_json([["create"]]))

    def _run(self, body, code):
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        answers = "\n".join([PROJ, "", "", "", BG.BILLING, "", "y", "", "", "octo-org", "", "", "", "", PROJ, "n"])
        rc, out, err = self.run_script("bootstrap.sh", [], tty_input=answers, STUB_PLAN_JSON=self.plan_json,
                                       STUB_CURL_BODY=body, STUB_CURL_CODE=code)
        return rc, out + err

    def test_not_admin_repeats_billing_commands(self):
        rc, text = self._run(BG.PERMS_READ, "200")
        self.assertEqual(rc, 0, text)
        tail = text[text.index("Next Steps:"):]
        self.assertIn(f"Billing access is still missing on billing account {BG.BILLING}", tail)
        self.assertIn("BILLING_NOT_LINKED", tail)
        for sa in BG.SAS:
            self.assertIn(f"--member=serviceAccount:{sa}@{PROJ}.iam.gserviceaccount.com --role=roles/billing.user", tail)
        self.assertIn("--role=roles/billing.viewer", tail)

    def test_admin_has_no_reminder(self):
        rc, text = self._run(BG.PERMS_ADMIN, "200")
        self.assertEqual(rc, 0, text)
        self.assertNotIn("Billing access is still missing", text)

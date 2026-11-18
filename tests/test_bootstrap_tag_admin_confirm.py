"""
BOOTSTRAP-TAG-ADMIN-CONFIRM (owner 11-11): the install can no longer slip past a missing deletion safety tag.

When the deletion safety tag will not be created (permissions missing, the check could not tell, or no organization /
managed folder), scripts/bootstrap.sh prints the prominent NO DELETION SAFETY block and asks
"Continue without deletion safety? [y/N]":
  y -> continues exactly as before (TF_VAR_create_stackvend_managed_tag=false, the apply runs);
  N / Enter -> BOOTSTRAP_TAG_ADMIN_DECLINED, exit 1;
  not a terminal -> BOOTSTRAP_TAG_ADMIN_UNCONFIRMED, the same stop.
Review F1: the question is asked EARLY (right after the folder ID, before any API enable, gcloud config change, vars
file, state bucket or tofu call) from a read-only check: the org testIamPermissions answer plus one GET of the platform
state (a tag already in state is kept, so that user is never asked). Only when the state cannot be read is the
question left to the preflight before the plan, and that stop lists what the run had changed.
A Tag Administrator sees no block and no question. scripts/apply.sh prints the same block and never asks.
Runs the real scripts under the lane 5 / lane 18 v3 hermetic harness (stubbed gcloud, curl and tofu; only
`tofu console` is the real engine).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import subprocess
import unittest

import test_platform_safe_apply_lane5 as lane5
import test_lane18_v3_tag_preflight as L18

PROMPT = "Continue without deletion safety? [y/N]"
BLOCK = "WARNING: NO DELETION SAFETY"
GRANT = (f'gcloud organizations add-iam-policy-binding {L18.ORG} --member="user:<your account>" '
         '--role="roles/resourcemanager.tagAdmin"')
STATE_GET = "platform%2Fstate%2Fdefault.tfstate"
WRITES = ("services enable", "config set project", "buckets create", "tofu init", "tofu import", "tofu plan",
          "tofu apply", "secrets ")


def _state_body(*resources):
    return json.dumps({"version": 4, "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": "p", "instances": [{"attributes": {}}]}
        for t, n in resources]})


TAG_IN_STATE = _state_body(("google_firestore_database", "stackvend_guard"),
                           ("google_tags_tag_key", "stackvend_managed"),
                           ("google_tags_tag_value", "stackvend_managed_true"),
                           ("google_tags_tag_value_iam_member", "stackvend_managed_vending_tag_user"))
NO_TAG_IN_STATE = _state_body(("google_firestore_database", "stackvend_guard"))


class _Boot(L18._PreflightHarness):
    ORG_ANSWER = f"organizations/{L18.ORG}"
    FOLDER_ANSWER = "folders/4242"

    def answers(self, early=None, late=None, org=None, folder=None, head=()):
        # project, [existing-install answer], region, zone, org, billing, folder, [EARLY tag question], env, VCS,
        # GitHub owner, ingress (Enter = Direct IAP), corp domain, CC OAuth client, tenant client,
        # [LATE tag question], typed project id, deploy services?
        a = [lane5.PROJ, *head, "", "", self.ORG_ANSWER if org is None else org, "",
             self.FOLDER_ANSWER if folder is None else folder]
        if early is not None:
            a.append(early)
        a += ["", "", "octo-org", "", "", "", ""]
        if late is not None:
            a.append(late)
        return "\n".join(a + [lane5.PROJ, "n"])

    def boot(self, early=None, late=None, org=None, folder=None, head=(), **env):
        return self.run_script("bootstrap.sh", [], tty_input=self.answers(early, late, org, folder, head),
                               STUB_PLAN_JSON=self.plan_json, **env)

    def boot_no_tty(self, early=None, **env):
        """stdin is a pipe (not a terminal): every answer is available, but `[ -t 0 ]` is false."""
        cmd = [lane5.BASH, os.path.join(self.repo, "scripts", "bootstrap.sh")]
        r = subprocess.run(cmd, cwd=self.repo, env=self.env(STUB_PLAN_JSON=self.plan_json, **env),
                           input=self.answers(early) + "\n", capture_output=True, text=True, timeout=120,
                           start_new_session=True)
        return r.returncode, r.stdout, r.stderr

    def state_body(self, body):
        p = os.path.join(self.tmp, "state.json")
        with open(p, "w") as f:
            f.write(body)
        return p

    def tfvars_path(self):
        return os.path.join(self.platform, f"{lane5.PROJ}.tfvars")

    def backups(self):
        return [f for f in os.listdir(self.platform) if f.startswith(f"{lane5.PROJ}.tfvars.bak-")]

    def applied(self):
        return "tofu apply -input=false" in "\n".join(self.calls())

    def assert_stopped_early(self, rc, text, code):
        """Review F1: the stop comes before any write."""
        self.assertEqual(rc, 1, text)
        self.assertIn(code, text)
        self.assertIn("Nothing was changed", text)
        self.assertIn("bash scripts/bootstrap.sh", text)
        calls = "\n".join(self.calls())
        for w in WRITES:
            self.assertNotIn(w, calls)
        self.assertFalse(os.path.exists(self.tfvars_path()))
        # The question comes before the environment prompt.
        self.assertNotIn("Enter Environment Tier", text)


class TestBootstrapNotATagAdmin(_Boot):
    def test_yes_continues_exactly_as_before(self):
        rc, out, err = self.boot("y", **self.granted(L18.PERMS[:1]))
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertTrue(self.applied())
        self.assertIn(BLOCK, text)
        self.assertEqual(text.count(PROMPT), 1)  # asked once, early
        self.assertLess(text.index(PROMPT), text.index("Enter Environment Tier"))
        self.assertIn("is not a Tag Administrator (roles/resourcemanager.tagAdmin)", text)
        self.assertIn("resourcemanager.tagValues.create resourcemanager.tagValues.setIamPolicy", text)
        self.assertIn("GUARD_UNCONFIGURED", text)
        self.assertIn(GRANT, text)
        self.assertIn("Continuing without deletion safety (you answered yes)", text)
        self.assertGreaterEqual(text.count("Deletion safety tag not set up"), 2)  # the end-of-run repeat stays
        # The early state lookup is a read-only GET with the token on stdin.
        [get] = [c for c in self.calls() if STATE_GET in c]
        self.assertIn(f"castor-tfstate-{lane5.PROJ}", get)
        self.assertNotIn("-X ", get)
        for c in self.calls():
            if STATE_GET in c or "testIamPermissions" in c:
                self.assertNotIn("stub-token", c)
                self.assertIn("--config -", c)

    def test_no_stops_before_any_write(self):
        rc, out, err = self.boot("n", **self.granted(L18.PERMS[:1]))
        self.assert_stopped_early(rc, out + err, "BOOTSTRAP_TAG_ADMIN_DECLINED")
        self.assertIn(PROMPT, out + err)

    def test_enter_defaults_to_no(self):
        rc, out, err = self.boot("", **self.granted(L18.PERMS[:1]))
        self.assert_stopped_early(rc, out + err, "BOOTSTRAP_TAG_ADMIN_DECLINED")

    def test_other_answers_are_no(self):
        rc, out, err = self.boot("dev", **self.granted(L18.PERMS[:1]))
        self.assert_stopped_early(rc, out + err, "BOOTSTRAP_TAG_ADMIN_DECLINED")

    def test_no_terminal_stops_without_asking(self):
        rc, out, err = self.boot_no_tty("y", **self.granted(L18.PERMS[:1]))
        text = out + err
        self.assert_stopped_early(rc, text, "BOOTSTRAP_TAG_ADMIN_UNCONFIRMED")
        self.assertIn(BLOCK, text)
        self.assertNotIn(PROMPT, text)
        self.assertNotIn("Continuing without deletion safety", text)

    def test_declined_then_rerun_as_tag_admin_installs(self):
        rc, out, err = self.boot("n", **self.granted(L18.PERMS[:1]))
        self.assertEqual(rc, 1, out + err)
        open(self.log, "w").close()
        rc, out, err = self.boot(None, **self.granted())
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertNotIn(PROMPT, text)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertTrue(self.applied())


class TestBootstrapPreflightCouldNotTell(_Boot):
    def test_http_error_never_claims_the_role_and_asks_early(self):
        rc, out, err = self.boot("n", **self.respond('{"error": {}}', code="503"))
        text = out + err
        self.assert_stopped_early(rc, text, "BOOTSTRAP_TAG_ADMIN_DECLINED")
        self.assertIn("could not tell", text)
        self.assertIn("(the permission check failed (HTTP 503))", text)
        self.assertIn("NOT confirmed", text)
        self.assertNotIn("is not a Tag Administrator", text)
        self.assertIn(PROMPT, text)

    def test_curl_failure_then_yes_continues(self):
        rc, out, err = self.boot("y", **self.respond("", mode="fail"))
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn("could not tell", text)
        self.assertEqual(text.count(PROMPT), 1)
        self.assertTrue(self.applied())


class TestBootstrapTagAlreadyInState(_Boot):
    def test_installed_platform_with_the_tag_is_never_asked(self):
        """A re-run of an install whose tag is in state: rule 5 keeps it planned, so nothing is asked."""
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write("".join(a + "\n" for a in L18.FULL_STATE))
        rc, out, err = self.boot(None, STUB_STATE_GET_CODE="200", STUB_STATE_GET_BODY=self.state_body(TAG_IN_STATE),
                                 STUB_STATE_LIST=state, **self.granted(L18.READ_PERMS))
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertNotIn(PROMPT, text)
        self.assertNotIn(BLOCK, text)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertIn("kept unchanged", text)
        self.assertTrue(self.applied())

    def test_installed_platform_without_the_tag_is_asked_early(self):
        rc, out, err = self.boot("n", STUB_STATE_GET_CODE="200",
                                 STUB_STATE_GET_BODY=self.state_body(NO_TAG_IN_STATE), **self.granted(L18.READ_PERMS))
        self.assert_stopped_early(rc, out + err, "BOOTSTRAP_TAG_ADMIN_DECLINED")

    def test_early_in_state_but_not_in_tofu_state_is_asked_late(self):
        """Fail closed: the late preflight decides from tofu's state; if it will not keep the tag, ask there."""
        rc, out, err = self.boot(None, late="n", STUB_STATE_GET_CODE="200",
                                 STUB_STATE_GET_BODY=self.state_body(TAG_IN_STATE), **self.granted(L18.READ_PERMS))
        text = out + err
        self.assertEqual(rc, 1, text)
        self.assertIn("BOOTSTRAP_TAG_ADMIN_DECLINED", text)
        self.assertFalse(self.applied())


class TestBootstrapStateUnreadable(_Boot):
    """The early check cannot read the platform state -> the question waits for the preflight before the plan."""

    def test_late_question_lists_what_was_changed(self):
        rc, out, err = self.boot(None, late="n", STUB_STATE_GET_CODE="503", **self.granted(L18.PERMS[:1]))
        text = out + err
        self.assertEqual(rc, 1, text)
        self.assertIn("BOOTSTRAP_TAG_ADMIN_DECLINED", text)
        self.assertEqual(text.count(PROMPT), 1)
        self.assertGreater(text.index(PROMPT), text.index("Enter Environment Tier"))
        self.assertEqual([c for c in self.calls() if c.startswith("tofu plan") or c.startswith("tofu apply")], [])
        self.assertNotIn("Nothing was changed", text)
        for fact in (f"enabled the base APIs on {lane5.PROJ}", f"written {self.tfvars_path()}",
                     f"gs://castor-tfstate-{lane5.PROJ}", "initialised OpenTofu",
                     "The next bootstrap run backs that vars file up (it may ask first)"):
            self.assertIn(fact, text)

    def test_late_yes_continues(self):
        rc, out, err = self.boot(None, late="y", STUB_STATE_GET_CODE="503", **self.granted(L18.PERMS[:1]))
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertEqual(text.count(PROMPT), 1)
        self.assertTrue(self.applied())

    def test_late_decline_then_rerun_as_tag_admin_backs_up_and_installs(self):
        """Review F2: the vars file left by a late stop is backed up by the next run, which then installs."""
        rc, out, err = self.boot(None, late="n", STUB_STATE_GET_CODE="503", **self.granted(L18.PERMS[:1]))
        self.assertEqual(rc, 1, out + err)
        self.assertTrue(os.path.exists(self.tfvars_path()))
        open(self.log, "w").close()
        # Re-run: the state GET now says "no install yet" (404), so the old file is moved aside without a question.
        rc, out, err = self.boot(None, STUB_STATE_GET_CODE="404", **self.granted())
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertEqual(len(self.backups()), 1)
        self.assertNotIn(PROMPT, text)
        self.assertTrue(self.applied())

    def test_late_decline_then_rerun_when_the_state_is_still_unreadable_asks_first(self):
        rc, out, err = self.boot(None, late="n", STUB_STATE_GET_CODE="503", **self.granted(L18.PERMS[:1]))
        self.assertEqual(rc, 1, out + err)
        open(self.log, "w").close()
        # The existing-vars-file check cannot read the state either: it asks (default No); "y" re-runs the installer.
        rc, out, err = self.boot(None, head=("y",), STUB_STATE_GET_CODE="503", **self.granted())
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertIn("Re-run the installer anyway?", text)
        self.assertEqual(len(self.backups()), 1)
        self.assertTrue(self.applied())


class TestBootstrapNoOrgOrFolder(_Boot):
    def test_skipped_org_or_folder_asks_before_any_write(self):
        for org, folder in (("", "folders/4242"), (f"organizations/{L18.ORG}", "")):
            with self.subTest(org=org, folder=folder):
                open(self.log, "w").close()
                rc, out, err = self.boot("n", org=org, folder=folder, **self.granted())
                text = out + err
                self.assert_stopped_early(rc, text, "BOOTSTRAP_TAG_ADMIN_DECLINED")
                self.assertIn(BLOCK, text)
                self.assertIn("cannot be created at all", text)
                self.assertIn(PROMPT, text)
                self.assertEqual(self.curl_calls(), [])  # nothing to check: no call

    def test_skipped_org_yes_continues_and_warns_at_the_end(self):
        rc, out, err = self.boot("y", org="", **self.granted())
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=<unset>"])  # unchanged: the tag is never planned
        self.assertEqual(text.count(PROMPT), 1)  # not asked again before the plan
        self.assertIn("gcloud organizations add-iam-policy-binding <ORGANIZATION_ID>", text)
        self.assertIn("No deletion safety tag (no organization ID or managed workloads folder ID)", text)


class TestBootstrapTagAdmin(_Boot):
    def test_tag_admin_sees_no_block_and_no_question(self):
        # No tag answer in the list: a question would eat the environment answer or the typed project id.
        rc, out, err = self.boot(None, **self.granted())
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertNotIn(BLOCK, text)
        self.assertNotIn(PROMPT, text)
        self.assertEqual([c for c in self.calls() if STATE_GET in c], [])  # granted: no state lookup
        self.assertTrue(self.applied())


class TestApplyShNeverAsks(L18._PreflightHarness):
    def test_apply_prints_the_block_and_applies_without_a_question(self):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", L18._tfvars())
        # The only input is the typed project id of the plan gate: a question would consume it.
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=lane5.PROJ, PROJECT_ID=lane5.PROJ,
                                       STUB_PLAN_JSON=self.plan_json, **self.granted(L18.PERMS[:1]))
        text = out + err
        self.assertEqual(rc, 0, text)
        self.assertIn("tofu apply -input=false", "\n".join(self.calls()))
        self.assertIn(BLOCK, text)
        self.assertNotIn(PROMPT, text)
        self.assertIn("Deletion safety tag not set up", text)  # the existing warning stays
        self.assertIn(f"then a Tag Administrator runs: PROJECT_ID={lane5.PROJ} bash scripts/apply.sh apply", text)
        self.assertEqual([c for c in self.calls() if STATE_GET in c], [])  # apply.sh makes no early state GET

    def test_plan_without_a_terminal_prints_the_block_and_succeeds(self):
        rc, out, err = self.plan(**self.respond("{}", code="403"))
        self.assertEqual(rc, 0, err)
        self.assertIn(BLOCK, err)
        self.assertIn("could not tell", err)
        self.assertNotIn(PROMPT, out + err)

    def test_explicit_false_prints_the_block(self):
        rc, out, err = self.plan(L18._tfvars("create_stackvend_managed_tag = false\n"), **self.granted())
        self.assertEqual(rc, 0, err)
        self.assertIn(BLOCK, err)
        self.assertIn("create_stackvend_managed_tag = false is set in", err)

    def test_no_block_with_tag_admin_or_tag_in_state(self):
        rc, out, err = self.plan(**self.granted())
        self.assertEqual(rc, 0, err)
        self.assertNotIn(BLOCK, err)
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write("".join(a + "\n" for a in L18.FULL_STATE))
        rc, out, err = self.plan(STUB_STATE_LIST=state, **self.granted(L18.READ_PERMS))
        self.assertEqual(rc, 0, err)
        self.assertNotIn(BLOCK, err)


class TestStatic(unittest.TestCase):
    def _read(self, *p):
        with open(os.path.join(L18.REPO, *p), encoding="utf-8") as f:
            return f.read()

    def test_only_bootstrap_asks(self):
        self.assertIn(f'read -r -p "{PROMPT}: "', self._read("scripts", "bootstrap.sh"))
        for p in (("scripts", "apply.sh"), ("scripts", "common", "tag_admin_preflight.sh")):
            src = self._read(*p)
            self.assertNotIn(PROMPT, src)
            self.assertIn("sv_tag_unprotected_block", src)

    def test_early_check_runs_before_any_write(self):
        boot = self._read("scripts", "bootstrap.sh")
        early = boot.index('sv_tag_admin_early_check "${ORGANIZATION_ID}" "${FOLDER_ID}" "${PROJECT_ID}"')
        self.assertLess(boot.index('sv_folder_iam_preflight BOOTSTRAP "${FOLDER_ID}"'), early)
        for write in ("gcloud services enable", 'gcloud config set project "${PROJECT_ID}"', 'cat <<EOF > "${TFVARS_PATH}"',
                      'gcloud storage buckets create', "sv_tf_init_bound"):
            self.assertLess(early, boot.index(write), write)

    def test_unprotected_fails_closed(self):
        for result, unprotected in (("true", 1), ("false", 0), ("not-applicable", 0), ("", 0), ("weird", 0)):
            script = (f'. "{os.path.join(L18.REPO, "scripts", "common", "tag_admin_preflight.sh")}"; '
                      f'SV_TAG_PREFLIGHT_RESULT="{result}"; sv_tag_unprotected')
            rc = subprocess.run([lane5.BASH, "-c", script], capture_output=True).returncode
            self.assertEqual(rc, unprotected, result)

    def test_block_helpers_stay_read_only(self):
        """RT delta F1: the helpers that print the warning block (sv_tag_member, sv_tag_unprotected_block; last in
        the file) never call curl / gcloud, read input or exit; the grant command is only echoed."""
        pre = self._read("scripts", "common", "tag_admin_preflight.sh")
        block = pre[pre.index("sv_tag_member() {"):]
        code = "\n".join(l for l in block.splitlines() if not l.lstrip().startswith("#"))
        for line in code.splitlines():
            if "add-iam-policy-binding" in line:
                self.assertTrue(line.lstrip().startswith("echo "), line)
        unechoed = "\n".join(l for l in code.splitlines() if not l.lstrip().startswith("echo "))
        for bad in ("curl ", "gcloud ", "read -r", "exit "):
            self.assertNotIn(bad, unechoed)


if __name__ == "__main__":
    unittest.main()

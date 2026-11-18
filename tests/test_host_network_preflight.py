"""HOST-VPC-EGRESS / HOST-INTERNAL-INGRESS (owner 11-07): the read-only organization policy preflight for the platform
network (scripts/common/host_network_preflight.sh), its wiring into scripts/apply.sh and scripts/bootstrap.sh, and
bootstrap's switch values (new install: both true; --overwrite-tfvars: the existing file's values, exactly).

The function tests source the real script in /bin/bash (Bash 3.2 on macOS) with stub gcloud / curl on a minimal PATH:
curl answers each Org Policy v2 getEffectivePolicy call from a canned body per constraint and logs its argv; nothing
reaches the network. The bootstrap tests run the real bootstrap.sh under lane 5's harness (only `tofu console` is the
real engine) and skip without OpenTofu.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)
import test_lane19_bootstrap_two_clients as L19  # noqa: E402  (module import only)

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SCRIPTS = os.path.join(REPO, "scripts")
PROJ = "proj-aaaa1"
EGRESS = "run.allowedVPCEgress"
PSC = "compute.disablePrivateServiceConnectCreationForConsumers"
INGRESS = "run.allowedIngress"

# curl stub: answers https://orgpolicy.googleapis.com/v2/projects/<p>/policies/<c>:getEffectivePolicy with
# $STUB_DIR/<c>.json and HTTP code $STUB_DIR/<c>.code (default 200; a missing body = '{}' (no rules)), or exits 7 when
# $STUB_DIR/<c>.fail exists. Logs argv to $STUB_DIR/curl.log and "auth-on-stdin" / "quota=<p>" from --config - stdin.
CURL = r'''#!/bin/bash
echo "curl $*" >> "$STUB_DIR/curl.log"
out=""; cfg=""; prev=""; url=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  [ "$prev" = "--config" ] && cfg="$a"
  case "$a" in https://*) url="$a" ;; esac
  prev="$a"
done
if [ "$cfg" = "-" ]; then
  stdin="$(cat)"
  printf '%s\n' "$stdin" | grep -q '^header = "Authorization: Bearer stub-token"$' && echo "auth-on-stdin" >> "$STUB_DIR/curl.log"
  q="$(printf '%s\n' "$stdin" | sed -n 's/^header = "x-goog-user-project: \(.*\)"$/\1/p')"
  [ -n "$q" ] && echo "quota=$q" >> "$STUB_DIR/curl.log"
fi
c="${url##*/policies/}"; c="${c%%:getEffectivePolicy}"
[ -e "$STUB_DIR/$c.fail" ] && exit 7
if [ -e "$STUB_DIR/$c.json" ]; then cat "$STUB_DIR/$c.json" > "$out"; else echo '{}' > "$out"; fi
if [ -e "$STUB_DIR/$c.code" ]; then cat "$STUB_DIR/$c.code"; else printf '200'; fi
exit 0
'''
GCLOUD = r'''#!/bin/bash
echo "gcloud $*" >> "$STUB_DIR/gcloud.log"
case "$*" in
  "auth print-access-token"*) [ -e "$STUB_DIR/no-token" ] && exit 1; echo "stub-token"; exit 0 ;;
esac
exit 0
'''


def _policy(*rules):
    return json.dumps({"name": "projects/123/policies/x", "spec": {"rules": list(rules)}})


class _Preflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hostnet-")
        self.stub = os.path.join(self.tmp, "bin")
        os.makedirs(self.stub)
        for name, body in (("curl", CURL), ("gcloud", GCLOUD)):
            p = os.path.join(self.stub, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        os.symlink(shutil.which("python3") or "/usr/bin/python3", os.path.join(self.stub, "python3"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def answer(self, constraint, body=None, code=None, fail=False):
        if body is not None:
            with open(os.path.join(self.tmp, f"{constraint}.json"), "w") as f:
                f.write(body)
        if code is not None:
            with open(os.path.join(self.tmp, f"{constraint}.code"), "w") as f:
                f.write(code)
        if fail:
            open(os.path.join(self.tmp, f"{constraint}.fail"), "w").close()

    def run_preflight(self, egress="true", ingress="true", prefix="APPLY", mode=""):
        script = (f'. "{SCRIPTS}/common/platform_target.sh"\n. "{SCRIPTS}/common/host_network_preflight.sh"\n'
                  f'PROJECT_ID={PROJ}\nTFVARS=/x/{PROJ}.tfvars\n'
                  f'sv_host_network_preflight {prefix} {egress} {ingress} "{mode}"\necho "RESULT rc=$? warnings=[$SV_HOSTNET_PREFLIGHT_WARNINGS]"\n')
        env = hermetic_guard.hermetic_env({"PATH": f"{self.stub}:/usr/bin:/bin", "STUB_DIR": self.tmp, "LANG": "C",
                                           "HOME": self.tmp, "TMPDIR": self.tmp})
        r = subprocess.run(["/bin/bash", "-c", script], env=env, capture_output=True, text=True, timeout=60,
                           stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr

    def curl_calls(self):
        p = os.path.join(self.tmp, "curl.log")
        return [l for l in open(p).read().splitlines() if l.startswith("curl ")] if os.path.exists(p) else []

    def curl_log(self):
        p = os.path.join(self.tmp, "curl.log")
        return open(p).read() if os.path.exists(p) else ""


class TestHostNetworkPreflight(_Preflight):
    def url(self, c):
        return f"https://orgpolicy.googleapis.com/v2/projects/{PROJ}/policies/{c}:getEffectivePolicy"

    def test_default_policies_pass_with_three_read_only_calls(self):
        rc, out = self.run_preflight()
        self.assertEqual(rc, 0, out)
        self.assertIn("RESULT rc=0 warnings=[]", out)
        for c, v in ((EGRESS, "private-ranges-only"), (PSC, "GOOGLE_APIS"), (INGRESS, "internal")):
            self.assertIn(f"[OK]\x1b[0m Platform network org policy preflight: constraints/{c} allows {v} on {PROJ}.", out)
        calls = self.curl_calls()
        self.assertEqual(len(calls), 3, calls)
        for c in (EGRESS, PSC, INGRESS):
            self.assertTrue(any(self.url(c) in x for x in calls), c)
        for x in calls:
            self.assertNotIn("stub-token", x)              # the token goes on stdin only
            self.assertNotIn("-X POST", x)                  # GET: read-only
        self.assertEqual(self.curl_log().count("auth-on-stdin"), 3)
        self.assertEqual(self.curl_log().count(f"quota={PROJ}"), 3)

    def test_both_switches_off_makes_no_call(self):
        rc, out = self.run_preflight("false", "false")
        self.assertEqual(rc, 0, out)
        self.assertIn("nothing to check", out)
        self.assertEqual(self.curl_calls(), [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "gcloud.log")))

    def test_egress_only_skips_the_ingress_constraint(self):
        rc, out = self.run_preflight("true", "false")
        self.assertEqual(rc, 0, out)
        calls = self.curl_calls()
        self.assertEqual(len(calls), 2)
        self.assertFalse(any(self.url(INGRESS) in x for x in calls))

    def test_allow_all_and_listed_values_pass(self):
        self.answer(EGRESS, _policy({"values": {"allowedValues": ["is:private-ranges-only", "all-traffic"]}}))
        self.answer(INGRESS, _policy({"allowAll": True}))
        self.answer(PSC, _policy({"allowAll": True}))
        rc, out = self.run_preflight()
        self.assertEqual(rc, 0, out)
        self.assertIn("RESULT rc=0 warnings=[]", out)

    def test_ingress_allowed_list_without_internal_is_refused(self):
        self.answer(INGRESS, _policy({"values": {"allowedValues": ["all"]}}))
        rc, out = self.run_preflight()
        self.assertNotEqual(rc, 0, out)
        self.assertIn("APPLY_HOST_NETWORK_ORG_POLICY_REFUSED: constraints/run.allowedIngress refuses internal "
                      "(it allows only all).", out)
        self.assertIn("Nothing was applied.", out)
        self.assertIn(f"gcloud org-policies describe <constraint> --effective --project={PROJ}", out)
        self.assertNotIn("RESULT", out)                      # sv_die exits

    def test_every_refusal_is_named_in_one_error(self):
        self.answer(EGRESS, _policy({"values": {"deniedValues": ["private-ranges-only"]}}))
        self.answer(INGRESS, _policy({"denyAll": True}))
        rc, out = self.run_preflight(prefix="BOOTSTRAP")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("BOOTSTRAP_HOST_NETWORK_ORG_POLICY_REFUSED: constraints/run.allowedVPCEgress refuses "
                      "private-ranges-only (it denies private-ranges-only); constraints/run.allowedIngress refuses "
                      "internal (it denies every value).", out)
        self.assertEqual(len(self.curl_calls()), 3)          # every constraint read before the refusal

    def test_unreadable_policy_warns_and_continues(self):
        self.answer(INGRESS, json.dumps({"error": {"code": 403}}), code="403")
        self.answer(EGRESS, fail=True)
        rc, out = self.run_preflight()
        self.assertEqual(rc, 0, out)
        self.assertIn("constraints/run.allowedIngress on proj-aaaa1: the effective policy could not be read (HTTP 403)", out)
        self.assertIn("constraints/run.allowedVPCEgress on proj-aaaa1: the effective policy could not be read (HTTP none)", out)
        self.assertIn("If it refuses internal, the apply stops with a 400 that names it.", out)
        self.assertIn(f"gcloud org-policies describe run.allowedIngress --effective --project={PROJ}", out)
        self.assertIn("RESULT rc=0 warnings=[HOST_NETWORK_ORG_POLICY_UNCHECKED HOST_NETWORK_ORG_POLICY_UNCHECKED]", out)

    def test_malformed_body_warns(self):
        self.answer(EGRESS, '{"spec": {"rules": "nope"}}')
        self.answer(INGRESS, "not json")
        rc, out = self.run_preflight()
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.count("the answer is not an organization policy"), 2)

    def test_conditional_rules_warn(self):
        self.answer(INGRESS, _policy({"values": {"allowedValues": ["all"]}, "condition": {"expression": "x"}}))
        rc, out = self.run_preflight()
        self.assertEqual(rc, 0, out)
        self.assertIn("it has 1 conditional (tag-based) rule(s), which cannot be evaluated here", out)

    def test_psc_constraint_never_refuses_but_warns_on_any_rule(self):
        for rule in ({"values": {"deniedValues": ["GOOGLE_APIS"]}}, {"denyAll": True},
                     {"values": {"allowedValues": ["SERVICE_PRODUCERS"]}}):
            self.answer(PSC, _policy(rule))
            rc, out = self.run_preflight("true", "false")
            self.assertEqual(rc, 0, (rule, out))
            self.assertIn(f"constraints/{PSC} on {PROJ}: the effective policy has rules", out)
            self.assertIn("check that it does not block GOOGLE_APIS endpoints", out)

    def test_no_token_warns_without_any_call(self):
        open(os.path.join(self.tmp, "no-token"), "w").close()
        rc, out = self.run_preflight()
        self.assertEqual(rc, 0, out)
        self.assertIn("could not get an access token", out)
        self.assertEqual(self.curl_calls(), [])

    def test_design_a_checks_all_traffic_and_no_psc_constraint(self):
        rc, out = self.run_preflight(mode="NAT_ALL_TRAFFIC")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"constraints/{EGRESS} allows all-traffic on {PROJ}.", out)
        calls = self.curl_calls()
        self.assertEqual(len(calls), 2, calls)                     # egress (all-traffic) + ingress; no PSC read
        self.assertFalse(any(self.url(PSC) in x for x in calls))

    def test_design_a_refused_when_the_org_allows_private_ranges_only(self):
        self.answer(EGRESS, _policy({"values": {"allowedValues": ["private-ranges-only"]}}))
        rc, out = self.run_preflight("true", "false", mode="NAT_ALL_TRAFFIC")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("constraints/run.allowedVPCEgress refuses all-traffic (it allows only private-ranges-only)", out)
        self.assertIn("host_egress_mode = NAT_ALL_TRAFFIC", out)

    def test_unknown_mode_warns_without_any_call(self):
        rc, out = self.run_preflight(mode="SOMETHING")
        self.assertEqual(rc, 0, out)
        self.assertIn("host_egress_mode is 'SOMETHING'", out)
        self.assertEqual(self.curl_calls(), [])

    def test_unreadable_switch_warns_without_any_call(self):
        rc, out = self.run_preflight("unreadable", "false")
        self.assertEqual(rc, 0, out)
        self.assertIn("preflight skipped: host_vpc_egress is 'unreadable'", out)
        self.assertEqual(self.curl_calls(), [])


class TestPreflightWiring(unittest.TestCase):
    def _read(self, rel):
        with open(os.path.join(REPO, rel), encoding="utf-8") as f:
            return f.read()

    def test_apply_runs_it_before_the_plan_of_plan_and_apply(self):
        src = self._read("scripts/apply.sh")
        self.assertIn('. "${SCRIPT_DIR}/common/host_network_preflight.sh"', src)
        self.assertIn('egress="$(sv_tfvar host_vpc_egress)" || egress="unreadable"', src)
        self.assertIn('ingress="$(sv_tfvar host_internal_ingress)" || ingress="unreadable"', src)
        self.assertIn('egress_mode="$(sv_tfvar host_egress_mode)" || egress_mode="unreadable"', src)
        self.assertIn('sv_host_network_preflight APPLY "${egress}" "${ingress}" "${egress_mode}"', src)
        dispatch = src[src.index('case "${SUBCMD}" in\n    plan)'):]
        plan = dispatch[:dispatch.index("    apply)")]
        apply_ = dispatch[dispatch.index("    apply)"):dispatch.index("    destroy)")]
        destroy = dispatch[dispatch.index("    destroy)"):dispatch.index("    init)")]
        for block, final in ((plan, '"${IAC_BIN}" plan'), (apply_, "sv_gated_apply apply")):
            self.assertIn("host_network_preflight_step", block)
            self.assertLess(block.index("tf_ready_existing"), block.index("host_network_preflight_step"))
            self.assertLess(block.index("host_network_preflight_step"), block.index(final))
        self.assertNotIn("host_network_preflight_step", destroy)

    def test_bootstrap_runs_it_before_the_gated_apply_with_the_written_switches(self):
        src = self._read("scripts/bootstrap.sh")
        self.assertIn('. "${SCRIPT_DIR}/common/host_network_preflight.sh"', src)
        call = 'sv_host_network_preflight BOOTSTRAP "${SV_HOST_VPC_EGRESS}" "${SV_HOST_INTERNAL_INGRESS}" "${SV_HOST_EGRESS_MODE}"'
        self.assertIn(call, src)
        self.assertLess(src.index('cat <<EOF > "${TFVARS_PATH}"'), src.index(call))
        self.assertLess(src.index(call), src.index('if sv_gated_apply bootstrap ""'))

    def test_bootstrap_heredoc_writes_the_switches_from_one_new_install_constant(self):
        src = self._read("scripts/bootstrap.sh")
        heredoc = src[src.index('cat <<EOF > "${TFVARS_PATH}"'):]
        heredoc = heredoc[:heredoc.index("\nEOF\n")]
        self.assertIn("host_vpc_egress                    = ${SV_HOST_VPC_EGRESS}", heredoc)
        self.assertIn("host_internal_ingress              = ${SV_HOST_INTERNAL_INGRESS}", heredoc)
        self.assertIn('host_egress_mode                   = "${SV_HOST_EGRESS_MODE}"', heredoc)
        before = src[:src.index('cat <<EOF > "${TFVARS_PATH}"')]
        self.assertIn('SV_HOST_VPC_EGRESS="true"\n', before)
        self.assertIn('SV_HOST_INTERNAL_INGRESS="${SV_NEW_INSTALL_HOST_INTERNAL_INGRESS}"\n', before)
        self.assertIn('SV_HOST_EGRESS_MODE="PSC_PRIVATE_RANGES"\n', before)

    def test_new_install_ingress_constant_is_true(self):
        """Review F2: one marked line, "true" since the live spike and flip passed: new installs are internal-only
        from their first apply (docs/handoff/FD-INT-INGRESS.md)."""
        src = self._read("scripts/bootstrap.sh")
        self.assertEqual(src.count("SV_NEW_INSTALL_HOST_INTERNAL_INGRESS="), 1)
        self.assertIn('\nSV_NEW_INSTALL_HOST_INTERNAL_INGRESS="true"\n', src)
        self.assertIn(">>> SV_NEW_INSTALL_HOST_INTERNAL_INGRESS: the ONE line that sets a new install's ingress", src)


# ------------------------------------------------------------------------------
# apply.sh behaviour (lane 5 harness, real `tofu console` for the vars file)
# ------------------------------------------------------------------------------
@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestApplyShHostNetworkPreflight(L5._Harness):
    def setUp(self):
        super().setUp()
        # this file's curl stub (STUB_DIR = the harness tmp dir) answers the getEffectivePolicy calls; other calls exit 0
        with open(os.path.join(self.stub, "curl"), "w") as f:
            f.write(CURL.replace('c="${url##*/policies/}"', 'case "$url" in *:getEffectivePolicy) ;; *) exit 0 ;; esac\n'
                                                           'c="${url##*/policies/}"', 1))

    def plan(self, extra=""):
        return self.plan_with(extra)

    def plan_with(self, extra, **env):
        # the vars file's own lines only: no host_vpc_egress line = the variables.tf defaults (true / false)
        tfvars = (f'project_id                  = "{PROJ}"\nregion                      = "us-central1"\n'
                  'vcs_provider                = "SERVERLESS_GIT"\ndeploy_git_server           = true\n' + extra)
        self.write(f"infra/platform/{PROJ}.tfvars", tfvars)
        return self.run_script("apply.sh", ["plan", "-no-color"], PROJECT_ID=PROJ, STUB_DIR=self.tmp, **env)

    def policy_calls(self):
        p = os.path.join(self.tmp, "curl.log")
        return [l for l in open(p).read().splitlines() if ":getEffectivePolicy" in l] if os.path.exists(p) else []

    def plans(self):
        return [c for c in self.calls() if c.startswith("tofu plan")]

    def test_defaults_check_the_egress_constraints_then_plan(self):
        rc, out, err = self.plan()
        self.assertEqual(rc, 0, err)
        calls = self.policy_calls()
        self.assertEqual(len(calls), 2, calls)                     # egress on, ingress off (variables.tf defaults)
        self.assertTrue(any(f"/policies/{EGRESS}:getEffectivePolicy" in c for c in calls))
        self.assertTrue(any(f"/policies/{PSC}:getEffectivePolicy" in c for c in calls))
        self.assertEqual(len(self.plans()), 1)

    def test_internal_ingress_also_checks_run_allowed_ingress(self):
        rc, out, err = self.plan("host_internal_ingress = true\n")
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.policy_calls()), 3)

    def test_a_refusing_policy_stops_before_the_plan(self):
        with open(os.path.join(self.tmp, f"{INGRESS}.json"), "w") as f:
            f.write(_policy({"values": {"allowedValues": ["all"]}}))
        rc, out, err = self.plan("host_internal_ingress = true\n")
        self.assertNotEqual(rc, 0, err)
        self.assertIn("APPLY_HOST_NETWORK_ORG_POLICY_REFUSED: constraints/run.allowedIngress refuses internal", err)
        self.assertEqual(self.plans(), [])

    def state(self, *addrs):
        p = os.path.join(self.tmp, "state.txt")
        with open(p, "w") as f:
            f.write("".join(a + "\n" for a in addrs))
        return p

    def test_ingress_before_the_network_is_refused_on_an_existing_install(self):
        """Review F8/F10: services in state, no subnet in state, host_internal_ingress = true -> typed refusal."""
        st = self.state('google_cloud_run_v2_service.services["orchestrator-gateway-service"]')
        self.write(f"infra/platform/{PROJ}.tfvars", "")
        rc, out, err = self.plan_with("host_internal_ingress = true\n", STUB_STATE_LIST=st)
        self.assertNotEqual(rc, 0, err)
        self.assertIn("APPLY_HOST_INGRESS_BEFORE_NETWORK: host_internal_ingress = true in", err)
        self.assertIn("Nothing was changed.", err)
        self.assertEqual(self.plans(), [])
        self.assertEqual(self.policy_calls(), [])

    def test_ingress_after_the_network_is_planned(self):
        st = self.state('google_cloud_run_v2_service.services["orchestrator-gateway-service"]',
                        "google_compute_subnetwork.host_run_egress[0]")
        rc, out, err = self.plan_with("host_internal_ingress = true\n", STUB_STATE_LIST=st)
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.plans()), 1)

    def test_ingress_on_a_fresh_state_is_not_refused(self):
        rc, out, err = self.plan_with("host_internal_ingress = true\n", STUB_STATE_LIST=self.state())
        self.assertEqual(rc, 0, err)
        self.assertNotIn("APPLY_HOST_INGRESS_BEFORE_NETWORK", err)

    def test_mode_switch_with_internal_ingress_is_refused(self):
        """Re-verification R1: Design B applied (PSC rule in state), tfvars asks for Design A with ingress internal."""
        svc = 'google_cloud_run_v2_service.services["orchestrator-gateway-service"]'
        subnet = "google_compute_subnetwork.host_run_egress[0]"
        for applied, extra, want in (
                ("google_compute_global_forwarding_rule.psc_google_apis[0]",
                 'host_internal_ingress = true\nhost_egress_mode = "NAT_ALL_TRAFFIC"\n', '"PSC_PRIVATE_RANGES" applied'),
                ("google_compute_router_nat.host[0]", "host_internal_ingress = true\n", '"NAT_ALL_TRAFFIC" applied')):
            open(self.log, "w").close()
            rc, out, err = self.plan_with(extra, STUB_STATE_LIST=self.state(svc, subnet, applied))
            self.assertNotEqual(rc, 0, err)
            self.assertIn("APPLY_HOST_EGRESS_MODE_SWITCH_WITH_INGRESS:", err)
            self.assertIn(want, err)
            self.assertIn("Switch in three applies", err)
            self.assertEqual(self.plans(), [])

    def test_mode_unchanged_or_switch_with_public_ingress_is_planned(self):
        svc = 'google_cloud_run_v2_service.services["orchestrator-gateway-service"]'
        subnet = "google_compute_subnetwork.host_run_egress[0]"
        psc = "google_compute_global_forwarding_rule.psc_google_apis[0]"
        for extra in ("host_internal_ingress = true\n",                                   # same design, internal
                      'host_egress_mode = "NAT_ALL_TRAFFIC"\n'):                          # switch, ingress public
            open(self.log, "w").close()
            rc, out, err = self.plan_with(extra, STUB_STATE_LIST=self.state(svc, subnet, psc))
            self.assertEqual(rc, 0, (extra, err))
            self.assertNotIn("APPLY_HOST_EGRESS_MODE_SWITCH_WITH_INGRESS", err)
            self.assertEqual(len(self.plans()), 1)

    def test_design_a_reads_its_mode_from_the_vars_file(self):
        rc, out, err = self.plan('host_egress_mode = "NAT_ALL_TRAFFIC"\n')
        self.assertEqual(rc, 0, err)
        calls = self.policy_calls()
        self.assertEqual(len(calls), 1, calls)
        self.assertIn(f"/policies/{EGRESS}:getEffectivePolicy", calls[0])

    def test_switches_off_make_no_call(self):
        rc, out, err = self.plan("host_vpc_egress = false\n")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.policy_calls(), [])
        self.assertNotIn("Platform network org policy preflight: constraints/", err)


# ------------------------------------------------------------------------------
# bootstrap.sh behaviour (lane 5 harness)
# ------------------------------------------------------------------------------
EGRESS_LINE = "host_vpc_egress                    = {}"
INGRESS_LINE = "host_internal_ingress              = {}"


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestBootstrapHostNetworkSwitches(L19._Boot):
    def boot_iap(self, args=(), **env):
        head = [PROJ, "", "", "", "", "", "y", "", "", "octo-org"]
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        answers = head + ["", ""] + ["", ""] + [PROJ, "n"]      # IAP ingress, no OAuth clients, confirm, no stage 2
        return self.run_script("bootstrap.sh", list(args), tty_input="\n".join(answers),
                               STUB_PLAN_JSON=self.plan_json, **env)

    def existing(self, extra):
        content = f'project_id = "{PROJ}"\nregion     = "us-central1"\n' + extra
        with open(self.tfvars, "w") as f:
            f.write(content)
        return content

    def assert_written(self, egress, ingress):
        tfvars = L5._read(self.tfvars)
        self.assertIn(EGRESS_LINE.format(egress), tfvars)
        self.assertIn(INGRESS_LINE.format(ingress), tfvars)
        self.assertEqual(len(re.findall(r"^host_vpc_egress\s*=", tfvars, re.M)), 1)
        self.assertEqual(len(re.findall(r"^host_internal_ingress\s*=", tfvars, re.M)), 1)

    def test_new_install_is_internal_from_its_first_apply(self):
        """No services in state: egress and ingress both true in the one first apply (no refusal, no rewrite)."""
        rc, out, err = self.boot_iap()
        self.assertEqual(rc, 0, out + err)
        self.assert_written("true", "true")
        self.assertIn('host_egress_mode                   = "PSC_PRIVATE_RANGES"', L5._read(self.tfvars))
        self.assertNotIn("keeping its platform network setting", out + err)
        self.assertNotIn("already has platform services in state but no platform network", out + err)
        self.assertEqual(len([c for c in self.tofu_ops() if c.startswith("tofu apply")]), 1)

    def test_overwrite_of_a_file_without_the_keys_keeps_the_defaults(self):
        self.existing("")
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assert_written("true", "false")                    # joins the network; ingress flips in a later apply
        self.assertIn('keeping its platform network setting (host_vpc_egress = true, host_internal_ingress = false, '
                      'host_egress_mode = "PSC_PRIVATE_RANGES")', out + err)

    def test_overwrite_carries_design_a(self):
        self.existing('host_egress_mode = "NAT_ALL_TRAFFIC"\n')
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assertIn('host_egress_mode                   = "NAT_ALL_TRAFFIC"', L5._read(self.tfvars))

    def test_overwrite_keeps_explicit_values(self):
        for extra, want in (("host_vpc_egress = true\nhost_internal_ingress = true\n", ("true", "true")),
                            ("host_vpc_egress = false\nhost_internal_ingress = false\n", ("false", "false"))):
            self.existing(extra)
            for b in glob.glob(self.tfvars + ".bak-*"):
                os.remove(b)
            rc, out, err = self.boot_iap(["--overwrite-tfvars"])
            self.assertEqual(rc, 0, out + err)
            self.assert_written(*want)

    def test_overwrite_refuses_ingress_without_egress_and_unreadable_values(self):
        # a value of the wrong type makes the whole file unreadable, so the earlier runner identity read refuses
        # first (SAT-46); both refusals leave the file as it was.
        for extra, needle in (("host_vpc_egress = false\nhost_internal_ingress = true\n",
                               "BOOTSTRAP_HOST_NETWORK_UNREADABLE: the existing"),
                              ('host_internal_ingress = "maybe"\n', "_UNREADABLE: cannot read")):
            before = self.existing(extra)
            rc, out, err = self.boot_iap(["--overwrite-tfvars"])
            self.assertNotEqual(rc, 0, out + err)
            self.assertIn(needle, out + err)
            self.assertEqual(L5._read(self.tfvars), before)      # file unchanged
            self.assertEqual(self.tofu_ops(), [])

    def test_existing_services_without_the_network_join_first(self):
        """A new vars file for an install whose services are already in state: no one-apply flip of both switches."""
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write('google_cloud_run_v2_service.services["orchestrator-gateway-service"]\n')
        rc, out, err = self.boot_iap(STUB_STATE_LIST=state)
        self.assertEqual(rc, 0, out + err)
        self.assert_written("true", "false")
        self.assertIn("already has platform services in state but no platform network", out + err)

    def test_existing_file_saying_true_without_the_network_joins_first(self):
        """Review F10: an EXISTING vars file with host_internal_ingress = true on an install without the network."""
        self.existing("host_vpc_egress = true\nhost_internal_ingress = true\n")
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write('google_cloud_run_v2_service.services["orchestrator-gateway-service"]\n')
        rc, out, err = self.boot_iap(["--overwrite-tfvars"], STUB_STATE_LIST=state)
        self.assertEqual(rc, 0, out + err)
        self.assert_written("true", "false")

    def test_existing_services_on_the_network_stay_internal(self):
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write('google_cloud_run_v2_service.services["orchestrator-gateway-service"]\n'
                    "google_compute_subnetwork.host_run_egress[0]\n")
        rc, out, err = self.boot_iap(STUB_STATE_LIST=state)
        self.assertEqual(rc, 0, out + err)
        self.assert_written("true", "true")


if __name__ == "__main__":
    unittest.main()

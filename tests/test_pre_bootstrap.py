"""scripts/pre-bootstrap.sh: prepares an organization for scripts/bootstrap.sh (owner request 11-03).

Runs the real script with /bin/bash (macOS: bash 3.2) and a fake `gcloud` and `curl` on PATH. The fakes keep a
small JSON model of the organization (projects, billing links, folders, IAM policies, testIamPermissions answers),
apply the script's writes to it (so a second run sees the prepared organization) and log every call. An unknown
gcloud command makes the fake fail, so every call the script makes is one listed here. No network, no GCP.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "pre-bootstrap.sh")
BASH = "/bin/bash"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

ORG = "123456789012"
BILLING = "01ABCD-23EF45-67890A"
OTHER_BILLING = "01FFFF-EEEEEE-DDDDDD"
ME = "admin@example.org"
RUNNER = "runner@example.org"
PROJ = "example-host"
TOKEN = "ya29.fake-token-for-tests"
TTY_EOF = b"\x04"   # Ctrl-D: end-of-file on a terminal line (one EOF per character)
TOS_NOTE = ("A new account must accept the Google Cloud Terms of Service once (open console.cloud.google.com as that "
            "account) before bootstrap can enable APIs.")

FAKE_GCLOUD = r'''#!/usr/bin/env python3
import json, os, sys

argv = sys.argv[1:]
state_path = os.environ["STUB_STATE"]
with open(state_path) as f:
    st = json.load(f)
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps({"tool": "gcloud", "argv": argv,
                        "prompts_disabled": os.environ.get("CLOUDSDK_CORE_DISABLE_PROMPTS") == "1"}) + "\n")

def save():
    with open(state_path, "w") as f:
        json.dump(st, f)

def flag(name):
    for a in argv:
        if a.startswith("--" + name + "="):
            return a.split("=", 1)[1]
    return None

def out(obj):
    print(json.dumps(obj))
    sys.exit(0)

def fail(msg, rc=1):
    sys.stderr.write("ERROR: " + msg + "\n")
    sys.exit(rc)

def parent_of(args):
    if flag("organization"):
        return "organizations/" + flag("organization")
    if flag("folder"):
        return "folders/" + flag("folder")
    fail("no parent")

pos = [a for a in argv if not a.startswith("--")]
cmd = " ".join(pos[:3])

# PERMISSION_DENIED on reads, like the real gcloud: "[]" on stdout for a list format, the error on stderr.
SIGN_IN = (["config", "get-value"], ["auth", "print-access-token"], ["config", "configurations"])
IS_WRITE = any(w in argv for w in ("create", "link", "add-iam-policy-binding"))
fail_reads = st.get("fail_reads") or []
if not IS_WRITE and not any(pos[:len(s)] == s for s in SIGN_IN) and (
        fail_reads == "all" or any(" ".join(pos).startswith(p) for p in fail_reads)):
    print("[]")
    sys.stderr.write("ERROR: (gcloud.%s) PERMISSION_DENIED: The caller does not have permission\n" % ".".join(pos[:3]))
    sys.exit(1)

if pos[:3] == ["config", "get-value", "account"]:
    print(st.get("account", ""))
    sys.exit(0)
if pos[:2] == ["config", "get-value"]:   # other properties: unset unless the state sets them (like gcloud)
    v = st.get("config", {}).get(pos[2], "")
    if v:
        print(v)
    else:
        sys.stderr.write("(unset)\n")
    sys.exit(0)
if pos[:3] == ["config", "configurations", "list"]:
    print("default")
    sys.exit(0)
if pos[:2] == ["projects", "get-ancestors"]:
    p = st["projects"].get(pos[2])
    if p is None:
        fail("not found")
    chain, cur = [{"id": pos[2], "type": "project"}], p["parent"]
    while cur:
        t, i = cur.split("/")
        chain.append({"id": i, "type": t.rstrip("s")})
        nxt = [f["parent"] for f in st["folders"] if f["name"] == cur]
        cur = nxt[0] if nxt else None
    out(chain)
if pos[:2] == ["projects", "list"]:
    import re
    m = re.search(r"parent\.id=(\d+)", flag("filter") or "")
    out([{"projectId": k} for k, v in st["projects"].items() if m and v["parent"] == "folders/" + m.group(1)])
if pos[:2] == ["auth", "print-access-token"]:
    print(st.get("token", ""))
    sys.exit(0)
if pos[:2] == ["organizations", "list"]:
    out([{"name": "organizations/" + o, "displayName": "org-" + o} for o in st["orgs"]])
if pos[:3] == ["billing", "accounts", "list"]:
    if st["billing_accounts"] is None:
        fail("(gcloud.billing.accounts.list) PERMISSION_DENIED")
    out([{"name": "billingAccounts/" + b["id"], "open": b.get("open", True), "displayName": "b"}
         for b in st["billing_accounts"]])
if pos[:2] == ["projects", "describe"]:
    p = st["projects"].get(pos[2])
    if p is None:
        fail("(gcloud.projects.describe) You do not have permission to access projects instance [%s] (or it may not exist)" % pos[2])
    t, i = p["parent"].split("/")
    out({"projectId": pos[2], "lifecycleState": p["state"], "parent": {"type": t.rstrip("s").replace("organization", "organization"), "id": i}})
if pos[:2] == ["projects", "create"]:
    pid = pos[2]
    if pid in st.get("taken", []) or pid in st["projects"]:
        fail("(gcloud.projects.create) Project creation failed. The project ID you specified is already in use by another project. Please try an alternative ID.")
    st["projects"][pid] = {"state": "ACTIVE", "parent": parent_of(argv)}
    st["iam"]["projects/" + pid] = [{"role": "roles/owner", "members": ["user:" + st["account"]]}]
    save()
    sys.exit(0)
if pos[:3] == ["billing", "projects", "describe"]:
    if pos[3] not in st["projects"]:
        fail("project not found")
    b = st["billing"].get(pos[3])
    if st.get("billing_disabled", {}).get(pos[3]):
        out({"billingAccountName": "billingAccounts/" + st["billing_disabled"][pos[3]], "billingEnabled": False})
    if b:
        out({"billingAccountName": "billingAccounts/" + b, "billingEnabled": True, "projectId": pos[3]})
    out({"billingAccountName": "", "billingEnabled": False, "projectId": pos[3]})
if pos[:3] == ["billing", "projects", "link"]:
    st["billing"][pos[3]] = flag("billing-account")
    save()
    sys.exit(0)
if pos[:3] == ["resource-manager", "folders", "list"]:
    parent = parent_of(argv)
    out([{"name": f["name"], "displayName": f["displayName"], "parent": f["parent"], "lifecycleState": f["state"]}
         for f in st["folders"] if f["parent"] == parent])
if pos[:3] == ["resource-manager", "folders", "describe"]:
    for f in st["folders"]:
        if f["name"] == "folders/" + pos[3]:
            out({"name": f["name"], "displayName": f["displayName"], "parent": f["parent"], "lifecycleState": f["state"]})
    fail("folder not found")
if pos[:3] == ["resource-manager", "folders", "create"]:
    n = "folders/" + str(700000000000 + len(st["folders"]) + 1)
    st["folders"].append({"name": n, "displayName": flag("display-name"), "parent": parent_of(argv), "state": "ACTIVE"})
    save()
    print(n)
    sys.exit(0)
if pos[:2] == ["projects", "get-iam-policy"]:
    out({"bindings": st["iam"].get("projects/" + pos[2], [])})
if pos[:3] == ["resource-manager", "folders", "get-iam-policy"]:
    out({"bindings": st["iam"].get("folders/" + pos[3], [])})
if pos[:2] == ["projects", "add-iam-policy-binding"] or pos[:3] == ["resource-manager", "folders", "add-iam-policy-binding"]:
    res = ("projects/" + pos[2]) if pos[0] == "projects" else ("folders/" + pos[3])
    st["iam"].setdefault(res, []).append({"role": flag("role"), "members": [flag("member")]})
    save()
    sys.exit(0)
# PREBOOTSTRAP-OFFER-ORG-ROLES: the organization IAM policy and the add-only grant. A grant to the signed-in account
# makes the role's permissions visible to testIamPermissions (every resource: inherited), on the
# "org_grant_visible_on_check"-th check after it (default 1: at once; IAM propagation); "org_grant_fail" makes the
# grant fail; "org_binding_invisible" keeps a --grant-to binding out of the policy reads.
ROLE_PERMS = {
    "roles/resourcemanager.tagAdmin": ["resourcemanager.tagKeys.create", "resourcemanager.tagValues.create",
                                       "resourcemanager.tagValues.setIamPolicy"],
    "roles/orgpolicy.policyAdmin": ["orgpolicy.policies.create", "orgpolicy.policies.update", "orgpolicy.policy.get",
                                    "orgpolicy.policy.set"],
}
if pos[:2] == ["organizations", "get-iam-policy"]:
    out({"bindings": st["iam"].get("organizations/" + pos[2], [])})
if pos[:2] == ["organizations", "add-iam-policy-binding"]:
    if st.get("org_grant_fail"):
        fail("(gcloud.organizations.add-iam-policy-binding) " + st["org_grant_fail"])
    binding = {"role": flag("role"), "members": [flag("member")]}
    if st.get("org_policy_fail_after_grant"):
        st["fail_reads"] = ["organizations get-iam-policy"]
    if st.get("org_binding_invisible"):
        st.setdefault("iam_hidden", []).append(binding)
    else:
        st["iam"].setdefault("organizations/" + pos[2], []).append(binding)
    me = st["account"]
    me = ("serviceAccount:" if me.endswith(".gserviceaccount.com") else "user:") + me
    if flag("member") == me:
        st.setdefault("pending_unlock", []).append(
            {"perms": ROLE_PERMS.get(flag("role"), []), "checks": 0, "on": st.get("org_grant_visible_on_check", 1)})
    save()
    sys.exit(0)
fail("STUB: unknown gcloud command: %s" % " ".join(argv), 97)
'''

FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys

args = sys.argv[1:]
with open(os.environ["STUB_STATE"]) as f:
    st = json.load(f)
out_file = data = url = None
config_stdin = False
i = 0
while i < len(args):
    a = args[i]
    if a in ("-o", "--data", "-d", "-w", "-H", "-X", "--max-time", "--config"):
        v = args[i + 1]
        if a == "-o":
            out_file = v
        elif a in ("--data", "-d"):
            data = v
        elif a == "--config" and v == "-":
            config_stdin = True
        i += 2
        continue
    if not a.startswith("-"):
        url = a
    i += 1
header = sys.stdin.read() if config_stdin else ""
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps({"tool": "curl", "argv": args, "url": url, "data": data,
                        "auth_on_stdin": ("Bearer " + st.get("token", "")) in header}) + "\n")
resource = url.split("/v3/", 1)[-1].split("/v1/", 1)[-1].split(":testIamPermissions")[0]
asked = json.loads(data)["permissions"]
# A grant made by the fake gcloud becomes visible on its n-th check (IAM propagation).
if st.get("pending_unlock"):
    left = []
    for u in st["pending_unlock"]:
        u["checks"] += 1
        if u["checks"] >= u["on"]:
            st["deny"] = [p for p in st.get("deny", []) if p not in u["perms"]]
            for r in st.get("deny_at", {}):
                st["deny_at"][r] = [p for p in st["deny_at"][r] if p not in u["perms"]]
        else:
            left.append(u)
    st["pending_unlock"] = left
    with open(os.environ["STUB_STATE"], "w") as f:
        json.dump(st, f)
deny = set(st.get("deny", [])) | set(st.get("deny_at", {}).get(resource, []))
code = st.get("tip_http", {}).get(resource, st.get("tip_http_all", 200))
if set(asked) & set(st.get("tip_fail_perms", [])):   # one call (by a permission it asks for) fails
    code = 503
with open(out_file, "w") as f:
    json.dump({"permissions": [p for p in asked if p not in deny]} if code == 200 else
              {"error": {"code": code, "message": st.get("tip_err", {}).get(resource, "")}}, f)
sys.stdout.write(str(code))
'''

WRITES = (
    ("projects", "create"),
    ("billing", "projects", "link"),
    ("resource-manager", "folders", "create"),
    ("projects", "add-iam-policy-binding"),
    ("resource-manager", "folders", "add-iam-policy-binding"),
    ("organizations", "add-iam-policy-binding"),
)


def fresh_state(**over):
    st = {
        "account": ME,
        "token": TOKEN,
        "orgs": [ORG],
        "billing_accounts": [{"id": BILLING}, {"id": "01CLOS-ED0000-000000", "open": False}],
        "projects": {},
        "billing": {},
        "folders": [],
        "iam": {},
        "taken": [],
        "deny": [],
    }
    st.update(over)
    return st


def prepared_state(**over):
    """An organization this script already prepared (project, billing, folder)."""
    st = fresh_state(
        projects={PROJ: {"state": "ACTIVE", "parent": "organizations/" + ORG}},
        billing={PROJ: BILLING},
        folders=[{"name": "folders/555000000001", "displayName": PROJ + "-workloads",
                  "parent": "organizations/" + ORG, "state": "ACTIVE"}],
        iam={"projects/" + PROJ: [{"role": "roles/owner", "members": ["user:" + ME]}]},
    )
    st.update(over)
    return st


# INSTALLER-OPENTOFU-OFFER: pre-bootstrap checks the engine bootstrap needs (silent when usable). A usable OpenTofu
# by default; tests/test_installer_opentofu_offer.py covers the missing / too-old paths.
FAKE_TOFU = r'''#!/bin/sh
if [ "$1" = "version" ] && [ "${2:-}" = "-json" ]; then echo '{"terraform_version": "1.13.1"}'; exit 0; fi
if [ "$1" = "version" ]; then echo "OpenTofu v1.13.1"; exit 0; fi
echo "fake tofu: unexpected call: $*" >&2
exit 2
'''


class _PreBootstrap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="preboot-")
        self.stub = os.path.join(self.tmp, "stubbin")
        os.makedirs(self.stub)
        for name, body in (("gcloud", FAKE_GCLOUD), ("curl", FAKE_CURL), ("tofu", FAKE_TOFU)):
            p = os.path.join(self.stub, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        os.symlink(sys.executable, os.path.join(self.stub, "python3"))
        self.log = os.path.join(self.tmp, "calls.log")
        self.state_path = os.path.join(self.tmp, "state.json")
        for d in ("home", "gcloudcfg", "tmpdir"):
            os.makedirs(os.path.join(self.tmp, d))
        self.set_state(fresh_state())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def set_state(self, st):
        with open(self.state_path, "w") as f:
            json.dump(st, f)
        open(self.log, "w").close()

    def state(self):
        with open(self.state_path) as f:
            return json.load(f)

    def run_script(self, *args, script=SCRIPT, **env):
        e = {
            "PATH": f"{self.stub}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": os.path.join(self.tmp, "home"),
            "TMPDIR": os.path.join(self.tmp, "tmpdir"),
            "CLOUDSDK_CONFIG": os.path.join(self.tmp, "gcloudcfg"),
            "STUB_LOG": self.log,
            "STUB_STATE": self.state_path,
            "LANG": "C",
        }
        e.update({k: str(v) for k, v in env.items()})
        r = subprocess.run([BASH, script] + list(args), cwd=REPO, env=hermetic_guard.hermetic_env(e),
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120,
                           start_new_session=True)
        return r.returncode, ANSI.sub("", r.stdout + r.stderr)

    def run_tty(self, args, answers, script=SCRIPT, timeout=120, **env):
        """Runs the script with a pseudo-terminal on stdin (interactive prompts), typing `answers`.

        After the answers the terminal sends end-of-file (Ctrl-D, several times), so a prompt the test did not answer
        reads EOF (the script's "no") instead of waiting forever; a run that still has not ended after `timeout`
        seconds is killed (its whole process group) and fails the test, so no test can hang the suite."""
        import pty
        import signal
        import termios
        import threading
        e = {
            "PATH": f"{self.stub}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": os.path.join(self.tmp, "home"),
            "TMPDIR": os.path.join(self.tmp, "tmpdir"),
            "CLOUDSDK_CONFIG": os.path.join(self.tmp, "gcloudcfg"),
            "STUB_LOG": self.log,
            "STUB_STATE": self.state_path,
            "LANG": "C",
        }
        e.update({k: str(v) for k, v in env.items()})
        master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        def _drain():
            try:
                while os.read(master, 1024):
                    pass
            except OSError:
                pass

        threading.Thread(target=_drain, daemon=True).start()
        try:
            p = subprocess.Popen([BASH, script] + list(args), cwd=REPO, env=hermetic_guard.hermetic_env(e),
                                 stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            os.close(slave)
            slave = None
            os.write(master, ("\n".join(answers) + "\n").encode() + TTY_EOF * 16)
            try:
                out, err = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
                out, err = p.communicate()
                self.fail("the script was still running after %ss (waiting for input?):\n%s" % (
                    timeout, ANSI.sub("", out.decode(errors="replace") + err.decode(errors="replace"))))
            return p.returncode, ANSI.sub("", out.decode(errors="replace") + err.decode(errors="replace"))
        finally:
            if slave is not None:
                os.close(slave)
            os.close(master)

    def calls(self):
        with open(self.log) as f:
            return [json.loads(line) for line in f if line.strip()]

    def gcloud_calls(self):
        return [c["argv"] for c in self.calls() if c["tool"] == "gcloud"]

    def writes(self):
        out = []
        for argv in self.gcloud_calls():
            pos = [a for a in argv if not a.startswith("--")]
            if any(tuple(pos[:len(w)]) == w for w in WRITES):
                out.append(argv)
        return out

    def assert_token_never_on_command_line(self):
        for c in self.calls():
            self.assertNotIn(TOKEN, " ".join(c["argv"]))
            if c["tool"] == "curl":
                self.assertTrue(c["auth_on_stdin"], c)


class TestFreshAndIdempotent(_PreBootstrap):
    def test_fresh_org_creates_project_links_billing_creates_folder_and_prints_answers(self):
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [
            ["projects", "create", PROJ, f"--organization={ORG}"],
            ["billing", "projects", "link", PROJ, f"--billing-account={BILLING}"],
            ["resource-manager", "folders", "create", f"--display-name={PROJ}-workloads", f"--organization={ORG}",
             "--format=value(name)"],
        ])
        folder = self.state()["folders"][0]["name"]
        self.assertIn(f"Project ID:                    {PROJ}", out)
        self.assertIn(f"Organization ID:               organizations/{ORG}", out)
        self.assertIn(f"Billing Account ID:            {BILLING}", out)
        self.assertIn(f"Managed Workloads Folder ID:   {folder}", out)
        self.assertIn("bash scripts/bootstrap.sh", out)
        self.assertNotIn("CLOUDSDK_ACTIVE_CONFIG_NAME=", out.split("Next:")[-1])
        self.assertIn("[DONE] Created project", out)
        self.assertIn("Rights pre-check passed", out)
        self.assert_token_never_on_command_line()
        # gcloud never stops at a prompt of its own.
        self.assertTrue(all(c["prompts_disabled"] for c in self.calls() if c["tool"] == "gcloud"))

    def test_full_rerun_on_prepared_org_changes_nothing(self):
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        open(self.log, "w").close()
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertIn("already exists (for example from an earlier run) and is ACTIVE under "
                      f"organizations/{ORG}; reusing it", out)
        self.assertIn("[OK] Project example-host is already linked to billing account", out)
        self.assertNotIn("[DONE]", out)
        self.assertIn(f"Managed Workloads Folder ID:   {self.state()['folders'][0]['name']}", out)

    def test_rerun_with_grant_to_changes_nothing(self):
        rc, out = self.run_script("--new-project", PROJ, "--yes", "--grant-to", f"user:{RUNNER}")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.writes()), 5)
        open(self.log, "w").close()
        rc, out = self.run_script("--new-project", PROJ, "--yes", "--grant-to", f"user:{RUNNER}")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])

    def test_prepared_org_with_existing_flags_changes_nothing(self):
        self.set_state(prepared_state())
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "folders/555000000001", "--yes")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertIn("Managed Workloads Folder ID:   folders/555000000001", out)

    def test_dry_run_makes_no_write(self):
        rc, out = self.run_script("--new-project", PROJ, "--dry-run")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.state(), fresh_state())
        self.assertIn(f"would run: gcloud projects create {PROJ} --organization={ORG}", out)
        self.assertIn(f"would run: gcloud billing projects link {PROJ} --billing-account={BILLING}", out)
        self.assertIn("would run: gcloud resource-manager folders create", out)
        self.assertIn("nothing was changed", out)

    def test_config_name_prefixes_the_next_command(self):
        rc, out = self.run_script("--new-project", PROJ, "--yes", CLOUDSDK_ACTIVE_CONFIG_NAME="stackvend")
        self.assertEqual(rc, 0, out)
        folder = self.state()["folders"][0]["name"]
        self.assertIn(f"CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend STACKVEND_PROJECT_ID={PROJ} "
                      f"STACKVEND_ORG_ID=organizations/{ORG} STACKVEND_BILLING_ACCOUNT_ID={BILLING} "
                      f"STACKVEND_FOLDER_ID={folder} bash scripts/bootstrap.sh", out)

    def test_not_confirmed_without_yes_when_not_a_terminal(self):
        rc, out = self.run_script("--new-project", PROJ)
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_NOT_CONFIRMED", out)
        self.assertEqual(self.writes(), [])


class TestRefusals(_PreBootstrap):
    def test_invalid_project_id_refused_before_any_gcloud_call(self):
        for bad in ("Bad_id", "abc", "1abcdef", "abcdef-", "a" * 31):
            rc, out = self.run_script("--new-project", bad, "--yes")
            self.assertNotEqual(rc, 0, bad)
            self.assertIn("PREBOOT_PROJECT_ID_INVALID", out)
            self.assertEqual(self.calls(), [], bad)

    def test_existing_and_new_project_are_mutually_exclusive(self):
        rc, out = self.run_script("--existing-project", PROJ, "--new-project", "other-host", "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_USAGE", out)
        self.assertEqual(self.calls(), [])

    def test_project_required_when_not_a_terminal(self):
        rc, out = self.run_script("--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_PROJECT_REQUIRED", out)
        self.assertEqual(self.calls(), [])

    def test_help_makes_no_call(self):
        rc, out = self.run_script("--help")
        self.assertEqual(rc, 0, out)
        self.assertIn("--existing-project", out)
        self.assertIn("--check-only", out)
        self.assertIn("at most 30 characters", out)
        self.assertIn("Nothing existing is deleted or changed.", out)
        self.assertIn(TOS_NOTE, out)                # BOOTSTRAP-TOS-FAIL-LOUD: a note, no (non-existent) check
        self.assertEqual(self.calls(), [])

    def test_interactive_folder_prompt_offers_no_over_long_default(self):
        long_id = "a" * 24                          # long_id-workloads would be 34 characters
        rc, out = self.run_tty(["--new-project", long_id], ["new", "short-name", "y", "n"])  # n: do not start bootstrap
        self.assertEqual(rc, 0, out)
        self.assertIn(f"'{long_id}-workloads' is too long", out)
        self.assertNotIn(f"[{long_id}-workloads]", out)
        self.assertIn(["resource-manager", "folders", "create", "--display-name=short-name", f"--organization={ORG}",
                       "--format=value(name)"], self.writes())

    def test_interactive_folder_prompt_offers_a_fitting_default(self):
        rc, out = self.run_tty(["--new-project", PROJ], ["new", "", "y", "n"])  # n: do not start bootstrap
        self.assertEqual(rc, 0, out)
        self.assertIn(f"[{PROJ}-workloads]", out)
        self.assertIn(f"--display-name={PROJ}-workloads", " ".join(" ".join(w) for w in self.writes()))

    def test_numbered_choice_2_creates_a_new_folder(self):
        """PREBOOTSTRAP-NUMBERED-CHOICE (owner 11-12): the existing-or-new question is a 1/2 menu."""
        rc, out = self.run_tty(["--new-project", PROJ], ["2", "", "y", "n"])  # n: do not start bootstrap
        self.assertEqual(rc, 0, out)
        self.assertIn("1) Use an existing managed-workloads folder", out)
        self.assertIn("2) Create a new managed-workloads folder", out)
        self.assertIn("Choose 1 or 2:", out)
        self.assertIn(f"--display-name={PROJ}-workloads", " ".join(" ".join(w) for w in self.writes()))

    def test_numbered_choice_rejects_other_answers(self):
        rc, out = self.run_tty(["--new-project", PROJ], ["3"])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("CHOICE_INVALID", out)
        self.assertIn("answer 1 (use an existing managed-workloads folder) or 2 (create a new one)", out)
        self.assertEqual(self.writes(), [])

    def test_personal_account_refused_without_yes(self):
        self.set_state(fresh_state(account="someone@gmail.com"))
        rc, out = self.run_script("--new-project", PROJ)
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_PERSONAL_ACCOUNT", out)
        self.assertIn("gcloud config configurations create stackvend --no-activate", out)
        self.assertIn("CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend gcloud auth login", out)
        self.assertEqual(self.writes(), [])

    def test_personal_account_only_warns_in_check_only_and_dry_run(self):
        for mode in ("--check-only", "--dry-run"):
            self.set_state(fresh_state(account="someone@gmail.com"))
            rc, out = self.run_script("--new-project", PROJ, mode)
            self.assertEqual(rc, 0, out)
            self.assertIn("is a personal Google account", out)
            self.assertNotIn("PREBOOT_PERSONAL_ACCOUNT", out)
            self.assertEqual(self.writes(), [])

    def test_no_active_account_names_the_configuration(self):
        self.set_state(fresh_state(account=""))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_NOT_SIGNED_IN: the gcloud configuration 'default' has no active account", out)
        self.set_state(fresh_state(account=""))
        rc, out = self.run_script("--new-project", PROJ, "--yes", CLOUDSDK_ACTIVE_CONFIG_NAME="stackvend")
        self.assertIn("configuration 'stackvend' has no active account", out)
        self.assertIn("CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend gcloud auth login", out)

    def test_new_project_existing_under_another_parent_refused(self):
        self.set_state(fresh_state(projects={PROJ: {"state": "ACTIVE", "parent": "folders/444000000001"}}))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_PROJECT_EXISTS_ELSEWHERE", out)
        self.assertIn("folders/444000000001", out)
        self.assertIn(f"--existing-project {PROJ}", out)
        self.assertEqual(self.writes(), [])

    def test_disabled_billing_link_is_not_repointed(self):
        self.set_state(prepared_state(billing={}, billing_disabled={PROJ: OTHER_BILLING}))
        rc, out = self.run_script("--existing-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_BILLING_DISABLED", out)
        self.assertIn(OTHER_BILLING, out)
        self.assertIn(f"gcloud billing projects link {PROJ} --billing-account={BILLING}", out)
        self.assertEqual(self.writes(), [])

    def test_personal_account_continues_with_yes(self):
        self.set_state(fresh_state(account="someone@gmail.com"))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        self.assertIn("[WARNING] someone@gmail.com is a personal Google account", out)
        self.assertEqual(len(self.writes()), 3)

    def test_delete_requested_project_refused(self):
        st = fresh_state(projects={PROJ: {"state": "DELETE_REQUESTED", "parent": "organizations/" + ORG}})
        for mode in ("--new-project", "--existing-project"):
            self.set_state(st)
            rc, out = self.run_script(mode, PROJ, "--yes")
            self.assertNotEqual(rc, 0, mode)
            self.assertIn("PREBOOT_PROJECT_NOT_ACTIVE", out)
            self.assertIn("gcloud projects undelete", out)
            self.assertEqual(self.writes(), [], mode)

    def test_more_than_one_org_refused_without_org_flag(self):
        self.set_state(fresh_state(orgs=[ORG, "999999999999"]))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_ORG_AMBIGUOUS", out)
        self.assertEqual(self.writes(), [])
        rc, out = self.run_script("--new-project", PROJ, "--yes", "--org", f"organizations/{ORG}")
        self.assertEqual(rc, 0, out)

    def test_more_than_one_open_billing_account_refused_without_flag(self):
        self.set_state(fresh_state(billing_accounts=[{"id": BILLING}, {"id": OTHER_BILLING}]))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_BILLING_AMBIGUOUS", out)
        self.assertEqual(self.writes(), [])

    def test_two_folders_with_the_same_name_refused(self):
        dup = [{"name": f"folders/55500000000{i}", "displayName": PROJ + "-workloads",
                "parent": "organizations/" + ORG, "state": "ACTIVE"} for i in (1, 2)]
        self.set_state(fresh_state(folders=dup))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_FOLDER_AMBIGUOUS", out)
        self.assertEqual(self.writes(), [])

    def test_new_project_id_taken_refused(self):
        self.set_state(fresh_state(taken=[PROJ]))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_PROJECT_ID_TAKEN", out)
        self.assertIn("Pick another --new-project id", out)
        self.assertEqual(self.writes(), [["projects", "create", PROJ, f"--organization={ORG}"]])

    def test_existing_project_not_visible_is_a_blocking_owner_row_after_the_full_table(self):
        rc, out = self.run_script("--existing-project", PROJ, "--check-only")
        self.assertEqual(rc, 1, out)
        self.assertIn(f"Project {PROJ} is not visible to {ME}", out)
        self.assertIn(f"Owner (projects/{PROJ}; not visible to you)", out)
        self.assertIn(f'gcloud projects add-iam-policy-binding {PROJ} --member="user:{ME}" --role="roles/owner"', out)
        for row in ("\n   5   ", "\n   6   ", "\n   7   ", "\n   8   "):     # the whole table was printed
            self.assertIn(row, out)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertEqual(self.writes(), [])
        rc, out = self.run_script("--existing-project", PROJ, "--yes")
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.writes(), [])

    def test_existing_folder_not_visible_is_a_blocking_folder_iam_admin_row(self):
        self.set_state(prepared_state())
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "999000000001", "--check-only")
        self.assertEqual(rc, 1, out)
        self.assertIn("Folder folders/999000000001 is not visible", out)
        self.assertIn("resourcemanager.folders.setIamPolicy (folders/999000000001; not visible to you)", out)
        self.assertIn(f'gcloud resource-manager folders add-iam-policy-binding 999000000001 --member="user:{ME}" '
                      f'--role="roles/resourcemanager.folderIamAdmin"', out)
        self.assertIn("\n   8   ", out)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertFalse([c for c in self.calls() if c["tool"] == "curl" and "/folders/999000000001:" in c["url"]])
        self.assertEqual(self.writes(), [])

    def test_everything_missing_is_reported_in_one_go(self):
        # No billing role, project and folder not visible: one run lists every missing right.
        self.set_state(fresh_state(billing_accounts=[], deny=["resourcemanager.tagKeys.create"]))
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "999000000001", "--check-only")
        self.assertEqual(rc, 1, out)
        blocking = out.split("Missing BLOCKING rights. Who must grant what:")[1]
        self.assertIn("row 3, Owner", blocking)
        self.assertIn("row 6, resourcemanager.folders.setIamPolicy", blocking)
        self.assertIn("Missing DEGRADED / OPTIONAL rights", out)
        self.assertIn("not tested  DEGRADED  billing.accounts.get/setIamPolicy (no billing account visible)", out)
        self.assertNotIn("resourcemanager.projects.create", out)       # an existing project is never created
        self.assertNotIn("PREBOOT_NO_BILLING_ACCOUNT", out)

    def test_folder_name_longer_than_30_characters_refused(self):
        rc, out = self.run_script("--new-project", "a" * 25, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_FOLDER_NAME_INVALID", out)
        self.assertEqual(self.calls(), [])


class TestExistingPaths(_PreBootstrap):
    def test_existing_project_is_never_created_and_billing_is_linked(self):
        self.set_state(fresh_state(projects={PROJ: {"state": "ACTIVE", "parent": "organizations/" + ORG}}))
        rc, out = self.run_script("--existing-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        self.assertFalse([a for a in self.gcloud_calls() if a[:2] == ["projects", "create"]])
        self.assertEqual(self.writes()[0], ["billing", "projects", "link", PROJ, f"--billing-account={BILLING}"])

    def test_existing_folder_is_never_created(self):
        self.set_state(prepared_state(folders=[{"name": "folders/555000000009", "displayName": "my-folder",
                                                "parent": "organizations/" + ORG, "state": "ACTIVE"}]))
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "555000000009", "--yes")
        self.assertEqual(rc, 0, out)
        self.assertFalse([a for a in self.gcloud_calls() if a[:3] == ["resource-manager", "folders", "create"]])
        self.assertIn("Managed Workloads Folder ID:   folders/555000000009", out)

    def test_no_billing_account_visible_and_project_already_linked_passes(self):
        # Live finding 11-03: a user without any billing role, on a project that is already linked.
        self.set_state(prepared_state(billing_accounts=[], deny=["billing.resourceAssociations.create",
                                                                 "billing.accounts.getIamPolicy",
                                                                 "billing.accounts.setIamPolicy"]))
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "555000000001", "--check-only")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"[OK] Project {PROJ} is already linked to billing account {BILLING}.", out)
        self.assertNotIn("billing.resourceAssociations.create", out)       # no link needed: no link row
        self.assertIn("Rights pre-check passed", out)
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "555000000001", "--yes")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertIn(f"Billing Account ID:            {BILLING}", out)

    def test_no_billing_account_visible_and_new_project_is_blocking(self):
        self.set_state(fresh_state(billing_accounts=[]))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 1, out)
        self.assertIn("Billing Account User on a billing account (none visible to you)", out)
        self.assertIn(f'gcloud billing accounts add-iam-policy-binding <BILLING_ACCOUNT_ID> --member="user:{ME}" '
                      '--role="roles/billing.user"', out)
        self.assertIn(f"gcloud billing projects link {PROJ} --billing-account=<BILLING_ACCOUNT_ID>", out)
        self.assertIn("billing.accounts.get/setIamPolicy (no billing account visible)", out)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertEqual(self.writes(), [])

    def test_billing_account_list_failure_never_aborts(self):
        self.set_state(fresh_state(billing_accounts=None))      # the fake then fails the list call
        rc, out = self.run_script("--new-project", PROJ, "--check-only")
        self.assertEqual(rc, 1, out)
        self.assertIn("'gcloud billing accounts list' failed, so no billing account is known", out)
        self.assertIn("Billing Account User on a billing account (none visible to you)", out)
        self.assertIn("\n   8   ", out)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        # Already linked: the list is not needed and nothing stops.
        self.set_state(prepared_state(billing_accounts=None))
        rc, out = self.run_script("--existing-project", PROJ, "--check-only")
        self.assertEqual(rc, 0, out)

    def test_billing_on_another_account_is_not_changed(self):
        self.set_state(prepared_state(billing={PROJ: OTHER_BILLING}))
        rc, out = self.run_script("--existing-project", PROJ, "--yes", "--billing-account", BILLING)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertIn(f"[WARNING] Project {PROJ} is already linked to billing account {OTHER_BILLING}, not {BILLING}", out)
        self.assertEqual(self.state()["billing"][PROJ], OTHER_BILLING)
        # Without --billing-account the existing link is simply used.
        rc, out = self.run_script("--existing-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"[OK] Project {PROJ} is already linked to billing account {OTHER_BILLING}.", out)
        self.assertIn(f"Billing Account ID:            {OTHER_BILLING}", out)
        self.assertEqual(self.writes(), [])

    def test_existing_project_prints_parent_as_resource_name(self):
        self.set_state(prepared_state())
        rc, out = self.run_script("--existing-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"(parent organizations/{ORG})", out)
        self.assertNotIn("parent organization/", out)
        self.assertNotIn("not under organizations/", out)
        self.assertNotIn("is not empty", out)

    def test_folder_with_children_only_warns(self):
        st = prepared_state()
        st["projects"]["someone-elses"] = {"state": "ACTIVE", "parent": "folders/555000000001"}
        st["folders"].append({"name": "folders/555000000077", "displayName": "sub", "parent": "folders/555000000001",
                              "state": "ACTIVE"})
        for args in (["--existing-folder", "555000000001"], []):     # given, and reused by name
            self.set_state(st)
            rc, out = self.run_script("--existing-project", PROJ, "--yes", *args)
            self.assertEqual(rc, 0, out)
            self.assertIn("Folder folders/555000000001 is not empty (1 project(s), 1 folder(s))", out)
            self.assertEqual(self.writes(), [])

    def test_existing_project_or_folder_outside_the_org_only_warns(self):
        st = prepared_state(projects={PROJ: {"state": "ACTIVE", "parent": "organizations/999999999999"}})
        st["folders"].append({"name": "folders/555000000088", "displayName": "elsewhere",
                              "parent": "organizations/999999999999", "state": "ACTIVE"})
        self.set_state(st)
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "555000000088", "--yes")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Project {PROJ} is not under organizations/{ORG}", out)
        self.assertIn(f"Folder folders/555000000088 is not confirmed to be under organizations/{ORG} "
                      "(top parent found: organizations/999999999999)", out)
        self.assertEqual(self.writes(), [])

    def test_parent_folder_is_used_for_project_and_folder(self):
        rc, out = self.run_script("--new-project", PROJ, "--yes", "--parent-folder", "folders/444000000001")
        self.assertEqual(rc, 0, out)
        w = self.writes()
        self.assertEqual(w[0], ["projects", "create", PROJ, "--folder=444000000001"])
        self.assertIn("--folder=444000000001", w[2])
        rc, out = self.run_script("--new-project", "example-host-2", "--yes", "--parent-folder", "444000000001",
                                  "--project-parent-org")
        self.assertEqual(rc, 0, out)
        self.assertIn(["projects", "create", "example-host-2", f"--organization={ORG}"], self.writes())


class TestGrantTo(_PreBootstrap):
    def test_grant_to_adds_only_missing_bindings(self):
        st = prepared_state()
        st["iam"]["projects/" + PROJ].append({"role": "roles/owner", "members": [f"user:{RUNNER}"]})
        self.set_state(st)
        rc, out = self.run_script("--existing-project", PROJ, "--yes", "--grant-to", f"user:{RUNNER}")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [[
            "resource-manager", "folders", "add-iam-policy-binding", "555000000001", f"--member=user:{RUNNER}",
            "--role=roles/resourcemanager.folderIamAdmin", "--condition=None", "--format=none"]])
        self.assertIn(f"user:{RUNNER} already has roles/owner on project {PROJ}", out)
        # The runner's own org/billing rights cannot be tested from here: the command for them is printed.
        self.assertIn("--check-only --existing-project example-host --existing-folder 555000000001", out)

    def test_next_command_for_someone_else_has_no_config_prefix(self):
        self.set_state(prepared_state())
        rc, out = self.run_script("--existing-project", PROJ, "--yes", "--grant-to", RUNNER,
                                  CLOUDSDK_ACTIVE_CONFIG_NAME="stackvend")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend bash scripts/bootstrap.sh", out)
        self.assertIn("with their own gcloud sign-in", out)
        self.assertIn("\n     bash scripts/bootstrap.sh", out)

    def test_conditional_binding_does_not_count(self):
        st = prepared_state()
        st["iam"]["projects/" + PROJ].append({"role": "roles/owner", "members": [f"user:{RUNNER}"],
                                              "condition": {"title": "expires"}})
        self.set_state(st)
        rc, out = self.run_script("--existing-project", PROJ, "--yes", "--grant-to", RUNNER)
        self.assertEqual(rc, 0, out)
        self.assertIn(["projects", "add-iam-policy-binding", PROJ, f"--member=user:{RUNNER}", "--role=roles/owner",
                       "--condition=None", "--format=none"], self.writes())


class TestRightsPreCheck(_PreBootstrap):
    def test_check_only_makes_no_write(self):
        rc, out = self.run_script("--new-project", PROJ, "--check-only")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertIn("Check only: nothing was changed.", out)
        urls = [c["url"] for c in self.calls() if c["tool"] == "curl"]
        self.assertIn(f"https://cloudresourcemanager.googleapis.com/v3/organizations/{ORG}:testIamPermissions", urls)
        self.assertIn(f"https://cloudbilling.googleapis.com/v1/billingAccounts/{BILLING}:testIamPermissions", urls)
        self.assert_token_never_on_command_line()

    def test_check_only_tests_existing_project_and_folder(self):
        self.set_state(prepared_state())
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "555000000001", "--check-only")
        self.assertEqual(rc, 0, out)
        urls = [c["url"] for c in self.calls() if c["tool"] == "curl"]
        self.assertIn(f"https://cloudresourcemanager.googleapis.com/v3/projects/{PROJ}:testIamPermissions", urls)
        self.assertIn("https://cloudresourcemanager.googleapis.com/v3/folders/555000000001:testIamPermissions", urls)
        self.assertEqual(self.writes(), [])

    def test_missing_blocking_right_stops_before_any_write_with_grant_command(self):
        self.set_state(fresh_state(deny=["resourcemanager.projects.create"]))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertIn(f'gcloud organizations add-iam-policy-binding {ORG} --member="user:{ME}" '
                      f'--role="roles/resourcemanager.projectCreator"', out)
        self.assertIn("--existing-project", out)
        self.assertEqual(self.writes(), [])

    def test_missing_folder_iam_admin_on_existing_folder_is_blocking(self):
        self.set_state(prepared_state(deny_at={"folders/555000000001": ["resourcemanager.folders.setIamPolicy"]}))
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "555000000001", "--check-only")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertIn(f'gcloud resource-manager folders add-iam-policy-binding 555000000001 --member="user:{ME}" '
                      f'--role="roles/resourcemanager.folderIamAdmin"', out)
        self.assertEqual(self.writes(), [])

    def test_missing_billing_link_right_is_blocking_only_when_a_link_is_needed(self):
        self.set_state(fresh_state(deny=["billing.resourceAssociations.create"]))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertIn(f"gcloud billing projects link {PROJ} --billing-account={BILLING}", out)
        self.assertEqual(self.writes(), [])
        self.set_state(prepared_state(deny=["billing.resourceAssociations.create"]))
        rc, out = self.run_script("--existing-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)

    def test_missing_owner_on_existing_project_is_blocking(self):
        self.set_state(prepared_state(deny_at={f"projects/{PROJ}": ["serviceusage.services.enable"]}))
        rc, out = self.run_script("--existing-project", PROJ, "--yes")
        self.assertNotEqual(rc, 0)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertIn(f'gcloud projects add-iam-policy-binding {PROJ} --member="user:{ME}" --role="roles/owner"', out)
        self.assertEqual(self.writes(), [])

    def test_missing_degraded_rights_continue_with_warning(self):
        self.set_state(fresh_state(deny=["resourcemanager.tagKeys.create", "billing.accounts.setIamPolicy",
                                         "orgpolicy.policies.create"]))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.writes()), 3)
        self.assertIn("Missing DEGRADED / OPTIONAL rights", out)
        self.assertIn("GUARD_UNCONFIGURED", out)
        self.assertIn(f'--role="roles/resourcemanager.tagAdmin"', out)
        self.assertIn(f'gcloud billing accounts add-iam-policy-binding {BILLING} --member="user:{ME}" '
                      f'--role="roles/billing.admin"', out)
        self.assertIn('--role="roles/orgpolicy.policyAdmin"', out)
        self.assertNotIn("PREBOOT_MISSING_RIGHTS", out)

    def test_unchecked_blocking_right_exits_2_in_check_only(self):
        self.set_state(fresh_state(tip_http={f"organizations/{ORG}": 400},
                                   tip_err={f"organizations/{ORG}": "Permission 'resourcemanager.bogus' is not valid."}))
        rc, out = self.run_script("--new-project", PROJ, "--check-only")
        self.assertEqual(rc, 2, out)
        self.assertIn("PREBOOT_RIGHTS_UNKNOWN", out)
        self.assertIn(f"organizations/{ORG}: HTTP 400: Permission 'resourcemanager.bogus' is not valid.", out)
        self.assertEqual(self.writes(), [])

    def test_unchecked_blocking_right_refuses_write_mode_before_any_write(self):
        self.set_state(fresh_state(tip_http={f"organizations/{ORG}": 403},
                                   tip_err={f"organizations/{ORG}": "The caller does not have permission"}))
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 2, out)
        self.assertIn("PREBOOT_RIGHTS_UNKNOWN", out)
        self.assertIn("HTTP 403: The caller does not have permission", out)
        self.assertEqual(self.writes(), [])

    def test_unchecked_degraded_right_only_warns(self):
        # Already linked: the billing call only decides row 4's DEGRADED billing-admin right.
        self.set_state(prepared_state(tip_http={f"billingAccounts/{BILLING}": 403}))
        rc, out = self.run_script("--existing-project", PROJ, "--check-only")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"testIamPermissions on billingAccounts/{BILLING} failed (HTTP 403)", out)
        self.assertIn("could not be checked", out)

    def test_org_policy_row_checks_the_preflight_set_on_the_folder(self):
        self.set_state(prepared_state(deny_at={"folders/555000000001": ["orgpolicy.policy.set"]}))
        rc, out = self.run_script("--existing-project", PROJ, "--existing-folder", "555000000001", "--check-only")
        self.assertEqual(rc, 0, out)
        folder_call = [c for c in self.calls() if c["tool"] == "curl" and "/folders/555000000001:" in c["url"]][0]
        for p in ("orgpolicy.policies.create", "orgpolicy.policies.update", "orgpolicy.policy.get",
                  "orgpolicy.policy.set"):
            self.assertIn(p, folder_call["data"])
        self.assertIn("(folders/555000000001)", out)
        self.assertIn('--role="roles/orgpolicy.policyAdmin"', out)
        # A new folder: the org call carries them instead.
        self.set_state(fresh_state())
        rc, out = self.run_script("--new-project", PROJ, "--check-only")
        org_call = [c for c in self.calls() if c["tool"] == "curl" and "/organizations/" in c["url"]][0]
        self.assertIn("orgpolicy.policy.set", org_call["data"])

    def test_service_account_member_in_grant_commands(self):
        sa = "deployer@example-host.iam.gserviceaccount.com"
        self.set_state(fresh_state(account=sa, deny=["resourcemanager.tagKeys.create"]))
        rc, out = self.run_script("--new-project", PROJ, "--check-only")
        self.assertEqual(rc, 0, out)
        self.assertIn(f'--member="serviceAccount:{sa}" --role="roles/resourcemanager.tagAdmin"', out)


ALLOWED_LINE_STARTS = ("   ", "==>", "[OK]", "[DONE]", "[INFO]", "[WARNING]", "[ERROR]", "[CHECK-ONLY]",
                       "[DRY-RUN]", "StackVend pre-bootstrap", "Missing BLOCKING rights", "BLOCKING rows",
                       "Check only:", "More than one")


class TestReadFailuresNeverStopEarly(_PreBootstrap):
    """Second live finding (11-03): a failed read in the state step must become an 'unknown' the table reports."""

    def assert_full_table(self, out):
        for row in ("1", "3", "4", "6", "7", "8"):
            self.assertRegex(out, r"\n   %s   \S" % row, f"row {row} missing:\n{out}")

    def assert_no_stray_lines(self, out):
        for line in out.splitlines():
            if line.strip():
                self.assertTrue(line.startswith(ALLOWED_LINE_STARTS), f"stray output line: {line!r}\n{out}")
            self.assertNotEqual(line.strip(), "[]")

    def test_folder_list_denied_with_folder_create_is_rights_unknown(self):
        self.set_state(fresh_state(fail_reads=["resource-manager folders list"]))
        rc, out = self.run_script("--new-project", "example-host-pbtest", "--folder-name", "pbtest-workloads",
                                  "--check-only")
        self.assertEqual(rc, 2, out)
        self.assertIn("Cannot tell whether a folder named 'pbtest-workloads' already exists", out)
        self.assertIn(f"Folder Viewer on organizations/{ORG} (needed to avoid creating a duplicate folder)", out)
        self.assertIn("PREBOOT_RIGHTS_UNKNOWN", out)
        self.assertNotIn("PREBOOT_FOLDER_LIST_FAILED", out)
        self.assert_full_table(out)
        self.assert_no_stray_lines(out)
        self.assertEqual(self.writes(), [])
        rc, out = self.run_script("--new-project", "example-host-pbtest", "--folder-name", "pbtest-workloads", "--yes")
        self.assertEqual(rc, 2, out)
        self.assertEqual(self.writes(), [])

    def test_folder_list_denied_without_folder_create_is_missing_rights(self):
        self.set_state(fresh_state(fail_reads=["resource-manager folders list"],
                                   deny=["resourcemanager.folders.create"]))
        rc, out = self.run_script("--new-project", PROJ, "--folder-name", "pbtest-workloads", "--check-only")
        self.assertEqual(rc, 1, out)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertIn('--role="roles/resourcemanager.folderCreator"', out)
        self.assertNotIn("Folder Viewer on", out)
        self.assert_no_stray_lines(out)

    def test_every_read_denied_at_once(self):
        for extra in ([], ["--org", ORG], ["--org", ORG, "--billing-account", BILLING, "--grant-to", RUNNER]):
            for mode in ("--check-only", "--yes"):
                self.set_state(fresh_state(fail_reads="all", tip_http_all=403,
                                           projects={PROJ: {"state": "ACTIVE", "parent": "organizations/" + ORG}},
                                           folders=[{"name": "folders/555000000001", "displayName": "f",
                                                     "parent": "organizations/" + ORG, "state": "ACTIVE"}]))
                for proj_flag in (["--existing-project", PROJ, "--existing-folder", "555000000001"],
                                  ["--new-project", "example-host-new"]):
                    open(self.log, "w").close()
                    rc, out = self.run_script(*proj_flag, mode, *extra)
                    label = f"{proj_flag} {mode} {extra}"
                    self.assertNotEqual(rc, 0, label + "\n" + out)
                    self.assert_full_table(out)
                    self.assert_no_stray_lines(out)
                    self.assertEqual(self.writes(), [], label)
                    self.assertNotIn("Traceback", out)

    def test_org_list_denied_is_reported_after_the_table(self):
        self.set_state(fresh_state(fail_reads=["organizations list"]))
        rc, out = self.run_script("--new-project", PROJ, "--check-only")
        self.assertEqual(rc, 1, out)
        self.assertIn("PREBOOT_ORG_UNKNOWN", out)
        self.assertIn("PERMISSION_DENIED", out)
        self.assert_full_table(out)
        self.assert_no_stray_lines(out)

    def test_org_learnt_from_an_existing_projects_ancestry(self):
        self.set_state(prepared_state(fail_reads=["organizations list"]))
        rc, out = self.run_script("--existing-project", PROJ, "--check-only")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Organization from the ancestry of {PROJ}: organizations/{ORG}", out)

    def test_unreadable_iam_policy_for_grant_to_refuses_before_any_write(self):
        self.set_state(prepared_state(fail_reads=["projects get-iam-policy"]))
        rc, out = self.run_script("--existing-project", PROJ, "--yes", "--grant-to", RUNNER)
        self.assertEqual(rc, 2, out)
        self.assertIn(f"getIamPolicy (projects/{PROJ})", out)
        self.assertEqual(self.writes(), [])


# BOOTSTRAP-PREFILL (owner 11-03): the bootstrap command carries the known values (STACKVEND_*), and a real run in a
# terminal offers to start it. The start is tested on a copy of scripts/ whose bootstrap.sh is a stub that records its
# environment (the real bootstrap never runs here).
STUB_BOOTSTRAP = r'''#!/bin/bash
{ env | grep -E '^(STACKVEND_|CLOUDSDK_ACTIVE_CONFIG_NAME=|CLOUDSDK_CORE_DISABLE_PROMPTS=)' | sort
  [ -t 0 ] && echo "stdin-is-a-terminal"; } > "$STUB_BOOT_ENV"
echo "STUB BOOTSTRAP RAN"
'''
FOLDER_ID = "folders/555000000001"
FULL_CMD = (f"STACKVEND_PROJECT_ID={PROJ} STACKVEND_ORG_ID=organizations/{ORG} "
            f"STACKVEND_BILLING_ACCOUNT_ID={BILLING} STACKVEND_FOLDER_ID={FOLDER_ID} bash scripts/bootstrap.sh")
RUN_QUESTION = "Run scripts/bootstrap.sh now with these values? [Y/n]"


class TestBootstrapHandOff(_PreBootstrap):
    def setUp(self):
        super().setUp()
        repo = os.path.join(self.tmp, "repo")
        shutil.copytree(os.path.join(REPO, "scripts"), os.path.join(repo, "scripts"))
        with open(os.path.join(repo, "scripts", "bootstrap.sh"), "w") as f:
            f.write(STUB_BOOTSTRAP)
        self.copy = os.path.join(repo, "scripts", "pre-bootstrap.sh")
        self.boot_env = os.path.join(self.tmp, "boot.env")
        self.set_state(prepared_state())

    def prepared_args(self, *extra):
        return ["--existing-project", PROJ, "--existing-folder", FOLDER_ID] + list(extra)

    def tty(self, args, answers, **env):
        return self.run_tty(args, answers, script=self.copy, STUB_BOOT_ENV=self.boot_env, **env)

    def boot_ran(self):
        return os.path.exists(self.boot_env)

    def boot_environment(self):
        with open(self.boot_env) as f:   # STACKVEND_HERMETIC_*: the test guard's own child settings
            return [l for l in f.read().splitlines() if not l.startswith("STACKVEND_HERMETIC_")]

    def test_printed_command_has_exactly_the_known_values(self):
        self.set_state(fresh_state())
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        folder = self.state()["folders"][0]["name"]
        self.assertIn("\n     " + FULL_CMD.replace(FOLDER_ID, folder) + "\n", out)
        self.assertNotIn(RUN_QUESTION, out)                     # not a terminal: printed, never asked

    def test_unknown_values_are_omitted_from_the_command(self):
        self.set_state(fresh_state())
        rc, out = self.run_script("--new-project", PROJ, "--dry-run")
        self.assertEqual(rc, 0, out)
        line = [l for l in out.splitlines() if l.strip().endswith("bash scripts/bootstrap.sh")][-1].strip()
        self.assertEqual(line, f"STACKVEND_PROJECT_ID={PROJ} STACKVEND_ORG_ID=organizations/{ORG} "
                               f"STACKVEND_BILLING_ACCOUNT_ID={BILLING} bash scripts/bootstrap.sh")   # folder not created yet
        self.assertNotRegex(out, r"STACKVEND_[A-Z_]+=(\s|$)")

    def test_check_only_prints_the_command(self):
        rc, out = self.run_script(*self.prepared_args("--check-only"))
        self.assertEqual(rc, 0, out)
        self.assertIn("\n     " + FULL_CMD + "\n", out)
        self.assertEqual(self.writes(), [])

    def test_config_name_prefixes_the_printed_command(self):
        rc, out = self.run_script(*self.prepared_args(), CLOUDSDK_ACTIVE_CONFIG_NAME="stackvend")
        self.assertEqual(rc, 0, out)
        self.assertIn("CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend " + FULL_CMD, out)

    def test_yes_on_a_terminal_starts_bootstrap_with_the_values(self):
        rc, out = self.tty(self.prepared_args(), [""], CLOUDSDK_ACTIVE_CONFIG_NAME="stackvend")   # Enter = Y
        self.assertEqual(rc, 0, out)
        self.assertIn(RUN_QUESTION, out)
        self.assertIn("STUB BOOTSTRAP RAN", out)
        self.assertEqual(self.boot_environment(), [
            "CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend",           # inherited
            f"STACKVEND_BILLING_ACCOUNT_ID={BILLING}",
            f"STACKVEND_FOLDER_ID={FOLDER_ID}",
            f"STACKVEND_ORG_ID=organizations/{ORG}",
            f"STACKVEND_PROJECT_ID={PROJ}",
            "stdin-is-a-terminal",
        ])                                                     # this script's CLOUDSDK_CORE_DISABLE_PROMPTS=1 is not passed on

    def test_callers_own_disable_prompts_is_kept(self):
        rc, out = self.tty(self.prepared_args(), ["y"], CLOUDSDK_CORE_DISABLE_PROMPTS="0")
        self.assertEqual(rc, 0, out)
        self.assertIn("CLOUDSDK_CORE_DISABLE_PROMPTS=0", self.boot_environment())

    def test_no_prints_the_command_and_does_not_start(self):
        rc, out = self.tty(self.prepared_args(), ["n"])
        self.assertEqual(rc, 0, out)
        self.assertIn(RUN_QUESTION, out)
        self.assertFalse(self.boot_ran())
        self.assertIn("\n     " + FULL_CMD, out)

    def test_yes_flag_never_starts_bootstrap(self):
        rc, out = self.tty(self.prepared_args("--yes"), [""])
        self.assertEqual(rc, 0, out)
        self.assertNotIn(RUN_QUESTION, out)
        self.assertFalse(self.boot_ran())
        self.assertIn("\n     " + FULL_CMD, out)

    def test_dry_run_and_check_only_never_start_bootstrap(self):
        for flag in ("--dry-run", "--check-only"):
            rc, out = self.tty(self.prepared_args(flag), [""])
            self.assertEqual(rc, 0, (flag, out))
            self.assertNotIn(RUN_QUESTION, out, flag)
            self.assertFalse(self.boot_ran(), flag)

    def test_grant_to_someone_else_is_never_started(self):
        # y: Proceed; n, n: the organization-role offers for the --grant-to person (PREBOOTSTRAP-OFFER-ORG-ROLES).
        rc, out = self.tty(self.prepared_args("--grant-to", f"user:{RUNNER}"), ["y", "n", "n", ""])
        self.assertEqual(rc, 0, out)
        self.assertNotIn(RUN_QUESTION, out)
        self.assertFalse(self.boot_ran())
        self.assertNotIn("organizations", " ".join(" ".join(w) for w in self.writes()))

    def test_rerun_on_a_prepared_org_asks_no_question(self):
        # owner live test 11-03: nothing to change -> no "Proceed?" (also without --yes and without a terminal)
        rc, out = self.run_script(*self.prepared_args())
        self.assertEqual(rc, 0, out)
        self.assertIn("[OK] Nothing to change.", out)
        self.assertNotIn("Proceed?", out)
        self.assertNotIn("PREBOOT_NOT_CONFIRMED", out)
        self.assertEqual(self.writes(), [])
        self.assertLess(out.index("[OK] Nothing to change."), out.index("Ready for scripts/bootstrap.sh"))
        rc, out = self.tty(self.prepared_args(), ["n"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("Proceed?", out)

    def test_summary_notes_the_cloud_terms(self):
        # BOOTSTRAP-TOS-FAIL-LOUD (live finding 11-03): the summary says a new account accepts the Cloud terms once.
        rc, out = self.run_script(*self.prepared_args())
        self.assertEqual(rc, 0, out)
        self.assertLess(out.index("Ready for scripts/bootstrap.sh"), out.index(TOS_NOTE))
        self.assertLess(out.index(TOS_NOTE), out.index("Next:"))

    def test_something_to_change_still_asks(self):
        st = prepared_state()
        st["billing"] = {}
        self.set_state(st)
        rc, out = self.run_script(*self.prepared_args())
        self.assertNotEqual(rc, 0, out)
        self.assertIn("PREBOOT_NOT_CONFIRMED", out)
        self.assertNotIn("Nothing to change", out)
        self.assertEqual(self.writes(), [])

    def test_missing_grant_to_binding_still_asks(self):
        rc, out = self.run_script(*self.prepared_args("--grant-to", f"user:{RUNNER}"))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("PREBOOT_NOT_CONFIRMED", out)


TAG_PERMS = ["resourcemanager.tagKeys.create", "resourcemanager.tagValues.create",
             "resourcemanager.tagValues.setIamPolicy"]
ORGPOL_PERMS = ["orgpolicy.policies.create", "orgpolicy.policies.update", "orgpolicy.policy.get",
                "orgpolicy.policy.set"]
TAG_ROLE = "roles/resourcemanager.tagAdmin"
ORGPOL_ROLE = "roles/orgpolicy.policyAdmin"
ASK = "Type yes to grant, or press Enter to skip"
STILL_MISSING_TODAY = "[WARNING] Still missing (not blocking): see the DEGRADED / OPTIONAL list above."


def org_grant(member, role):
    return ["organizations", "add-iam-policy-binding", ORG, f"--member={member}", f"--role={role}",
            "--condition=None", "--format=none"]


def org_question(member, role):
    """The exact question (both roles are organization-wide; only the full word yes grants)."""
    who = member.split(":", 1)[1]
    if role == TAG_ROLE:
        title, scope = "Tag Administrator", "create, change and delete tags and their access anywhere"
    else:
        title, scope = "Organization Policy Administrator", "change every organization policy"
    group = "" if who == ME else f" ({who} may already hold it through a group.)"
    return (f"Grant {title} ({role}) on organizations/{ORG} to {member} now? This is organization-wide: it lets {who} "
            f"{scope} in organizations/{ORG}.{group} Type yes to grant, or press Enter to skip")


class TestOfferOrgRoles(_PreBootstrap):
    """PREBOOTSTRAP-OFFER-ORG-ROLES (owner 11-16): when rows 7 / 8 are missing for the bootstrap runner and the
    signed-in account can set IAM on the organization, a terminal run offers each grant ([y/N]); only an explicit y
    grants (add-only), then the same read-only check runs again. Runs a copy of scripts/ whose bootstrap.sh is a stub,
    so a stray answer can never start the real installer."""

    ME_M = f"user:{ME}"
    RUNNER_M = f"user:{RUNNER}"

    def setUp(self):
        super().setUp()
        repo = os.path.join(self.tmp, "repo")
        shutil.copytree(os.path.join(REPO, "scripts"), os.path.join(repo, "scripts"))
        with open(os.path.join(repo, "scripts", "bootstrap.sh"), "w") as f:
            f.write(STUB_BOOTSTRAP)
        self.copy = os.path.join(repo, "scripts", "pre-bootstrap.sh")
        self.boot_env = os.path.join(self.tmp, "boot.env")

    def args(self, *extra):
        return ["--existing-project", PROJ, "--existing-folder", FOLDER_ID] + list(extra)

    def tty(self, args, answers, **env):
        env.setdefault("PB_ORG_GRANT_WAIT_SECS", "0")
        return self.run_tty(args, answers, script=self.copy, STUB_BOOT_ENV=self.boot_env, **env)

    def run_copy(self, *args, **env):
        env.setdefault("PB_ORG_GRANT_WAIT_SECS", "0")
        return self.run_script(*args, script=self.copy, STUB_BOOT_ENV=self.boot_env, **env)

    def runner_state(self, **over):
        """Prepared, and the --grant-to person already has Owner and Folder IAM Admin (nothing else to change)."""
        st = prepared_state(**over)
        st["iam"]["projects/" + PROJ].append({"role": "roles/owner", "members": [self.RUNNER_M]})
        st["iam"]["folders/555000000001"] = [{"role": "roles/resourcemanager.folderIamAdmin",
                                              "members": [self.RUNNER_M]}]
        return st

    def curl_checks(self, perm):
        """testIamPermissions calls (resource, asked) that ask for `perm`, in order."""
        out = []
        for c in self.calls():
            if c["tool"] == "curl" and perm in json.loads(c["data"])["permissions"]:
                out.append(c["url"].split("/v3/")[-1].split(":testIamPermissions")[0])
        return out

    def org_policy_reads(self):
        return [a for a in self.gcloud_calls() if a[:2] == ["organizations", "get-iam-policy"]]

    def assert_no_org_admin_probe(self):
        self.assertEqual(self.curl_checks("resourcemanager.organizations.setIamPolicy"), [])
        self.assertEqual(self.org_policy_reads(), [])

    # --- the signed-in account runs bootstrap (row 7) ---

    def test_yes_grants_once_rechecks_and_reports_done(self):
        self.set_state(prepared_state(deny=TAG_PERMS))
        rc, out = self.tty(self.args(), ["yes", "n"])   # yes: grant; n: do not start bootstrap
        self.assertEqual(rc, 0, out)
        self.assertIn(org_question(self.ME_M, TAG_ROLE), out)
        self.assertEqual(self.writes(), [org_grant(self.ME_M, TAG_ROLE)])
        self.assertIn(f"[DONE] Granted Tag Administrator ({TAG_ROLE}) on organizations/{ORG} to {self.ME_M}; "
                      f"verified: testIamPermissions on organizations/{ORG} now returns the row 7 permissions.", out)
        self.assertIn(f"[OK] Granted in this run and verified: row 7 (Tag Administrator, {TAG_ROLE}).", out)
        self.assertNotIn("Still missing", out)
        # The table's org check, then exactly one re-check after the grant (visible at once here).
        self.assertEqual(self.curl_checks(TAG_PERMS[0]), [f"organizations/{ORG}"] * 2)
        self.assertIn({"role": TAG_ROLE, "members": [self.ME_M]}, self.state()["iam"][f"organizations/{ORG}"])
        self.assertFalse(os.path.exists(self.boot_env))
        # Asked after the rights table and the project / folder steps.
        self.assertLess(out.index("Rights pre-check passed"), out.index("==> Organization roles for"))
        self.assertLess(out.index("==> Managed-workloads folder"), out.index("==> Organization roles for"))

    def test_no_and_enter_grant_nothing_and_print_what_they_printed_before(self):
        # Today's behaviour: the same organization, but the signed-in account cannot set IAM there (no offer).
        self.set_state(prepared_state(deny=TAG_PERMS + ["resourcemanager.organizations.setIamPolicy"]))
        rc, before = self.tty(self.args(), ["n"])
        self.assertEqual(rc, 0, before)
        before_calls = [a for a in self.gcloud_calls()]
        for answer in ("", "n", "N", "y", "Y", "ye"):   # y: a stray or typed-ahead key never grants
            with self.subTest(answer=answer):
                self.set_state(prepared_state(deny=TAG_PERMS))
                rc, out = self.tty(self.args(), [answer, "n"])
                self.assertEqual(rc, 0, out)
                self.assertIn(org_question(self.ME_M, TAG_ROLE), out)
                self.assertEqual(self.writes(), [])
                self.assertNotIn("[DONE]", out)
                self.assertIn(STILL_MISSING_TODAY, out)
                self.assertIn(f'gcloud organizations add-iam-policy-binding {ORG} --member="{self.ME_M}" '
                              f'--role="{TAG_ROLE}"', out)
                # Identical output except the step header and the question itself.
                stripped = re.sub(r"\n==> Organization roles for [^\n]*\n", "", out)
                stripped = stripped.replace(org_question(self.ME_M, TAG_ROLE) + ": ", "")
                note = ("[INFO] Row 7: not granted (only the full word yes grants it); the grant command is in the "
                        "list above.\n")
                if answer:
                    self.assertIn(note, stripped)
                    stripped = stripped.replace(note, "")
                self.assertEqual(stripped, before)
                # Identical gcloud calls except the one read-only organization policy read.
                self.assertEqual([a for a in self.gcloud_calls() if a[:2] != ["organizations", "get-iam-policy"]],
                                 before_calls)

    def test_yes_flag_no_terminal_and_check_only_never_offer(self):
        for how in ("--yes", "no-tty", "tty --yes", "--check-only", "tty --check-only"):
            with self.subTest(how=how):
                self.set_state(prepared_state(deny=TAG_PERMS))
                extra = [f for f in how.split() if f.startswith("--")]
                if how.startswith("tty"):
                    rc, out = self.tty(self.args(*extra), ["y", "y", "n"])
                else:
                    rc, out = self.run_copy(*self.args(*extra))
                self.assertEqual(rc, 0, out)
                self.assertNotIn(ASK, out)
                self.assertNotIn("Organization roles for", out)
                self.assertEqual(self.writes(), [])
                self.assert_no_org_admin_probe()
                self.assertIn(f'--role="{TAG_ROLE}"', out)          # the command is still printed
                self.assertFalse(os.path.exists(self.boot_env))

    def test_dry_run_prints_the_grant_and_makes_none(self):
        self.set_state(prepared_state(deny=TAG_PERMS))
        rc, out = self.run_copy(*self.args("--dry-run"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertIn(f'a real run in a terminal asks "{org_question(self.ME_M, TAG_ROLE)}"; on yes it runs:', out)
        self.assertIn(f"[DRY-RUN] would run: gcloud organizations add-iam-policy-binding {ORG} --member={self.ME_M} "
                      f"--role={TAG_ROLE} --condition=None --format=none", out)
        self.assertNotIn(f"organizations/{ORG}", json.dumps(self.state()["iam"]))
        self.assertNotIn("[DONE]", out)
        # --dry-run --yes: a real --yes run never offers, so nothing is printed for it either.
        self.set_state(prepared_state(deny=TAG_PERMS))
        rc, out = self.run_copy(*self.args("--dry-run", "--yes"))
        self.assertEqual(rc, 0, out)
        self.assertNotIn("add-iam-policy-binding " + ORG + " --member=" + self.ME_M, out)

    def test_cannot_set_org_iam_offers_nothing(self):
        for denied in ("resourcemanager.organizations.setIamPolicy", "resourcemanager.organizations.getIamPolicy"):
            with self.subTest(denied=denied):
                self.set_state(prepared_state(deny=TAG_PERMS + [denied]))
                rc, out = self.tty(self.args(), ["y", "n"])
                self.assertEqual(rc, 0, out)
                self.assertNotIn(ASK, out)
                self.assertNotIn("Organization roles for", out)
                self.assertEqual(self.writes(), [])
                self.assertEqual(self.org_policy_reads(), [])
                self.assertIn(STILL_MISSING_TODAY, out)

    def test_org_admin_check_or_policy_read_that_fails_warns_and_offers_nothing(self):
        self.set_state(prepared_state(deny=TAG_PERMS, tip_fail_perms=["resourcemanager.organizations.setIamPolicy"]))
        rc, out = self.tty(self.args(), ["y", "n"])
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Could not check whether {ME} can set IAM on organizations/{ORG} (testIamPermissions: "
                      "HTTP 503", out)
        self.assertNotIn(ASK, out)
        self.assertEqual(self.writes(), [])
        self.assertIn(STILL_MISSING_TODAY, out)
        self.set_state(prepared_state(deny=TAG_PERMS, fail_reads=["organizations get-iam-policy"]))
        rc, out = self.tty(self.args(), ["y", "n"])
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Could not read the IAM policy of organizations/{ORG} (ERROR: (gcloud.organizations."
                      "get-iam-policy", out)
        self.assertNotIn(ASK, out)
        self.assertEqual(self.writes(), [])

    def test_rights_present_or_binding_present_offers_nothing(self):
        self.set_state(prepared_state())
        rc, out = self.tty(self.args(), ["y", "n"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn(ASK, out)
        self.assert_no_org_admin_probe()
        # The binding is there but testIamPermissions denies (e.g. a deny policy): never granted again.
        st = prepared_state(deny=TAG_PERMS)
        st["iam"][f"organizations/{ORG}"] = [{"role": TAG_ROLE, "members": [self.ME_M]}]
        self.set_state(st)
        rc, out = self.tty(self.args(), ["y", "n"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn(ASK, out)
        self.assertIn(f"Row 7: {self.ME_M} already holds {TAG_ROLE} on organizations/{ORG}", out)
        self.assertEqual(self.writes(), [])

    def test_failed_grant_is_a_typed_warning_and_the_row_stays_missing(self):
        self.set_state(prepared_state(deny=TAG_PERMS, org_grant_fail="PERMISSION_DENIED: policy update refused"))
        rc, out = self.tty(self.args(), ["yes", "n"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [org_grant(self.ME_M, TAG_ROLE)])
        self.assertIn(f"[WARNING] PREBOOT_ORG_GRANT_FAILED: granting {TAG_ROLE} on organizations/{ORG} to "
                      f"{self.ME_M} failed", out)
        self.assertIn("PERMISSION_DENIED: policy update refused", out)
        self.assertNotIn("[DONE]", out)
        self.assertNotIn("verified:", out)
        self.assertIn(STILL_MISSING_TODAY, out)

    def test_grant_not_visible_yet_is_a_typed_warning_never_verified(self):
        self.set_state(prepared_state(deny=TAG_PERMS, org_grant_visible_on_check=99))
        rc, out = self.tty(self.args(), ["yes", "n"], PB_ORG_GRANT_WAIT_SECS="02", PB_ORG_GRANT_POLL_SECS="01")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [org_grant(self.ME_M, TAG_ROLE)])
        self.assertIn(f"[WARNING] PREBOOT_ORG_GRANT_NOT_VISIBLE: granted {TAG_ROLE} on organizations/{ORG} to "
                      f"{self.ME_M}, but after 2 s testIamPermissions", out)
        self.assertIn("Not verified.", out)
        self.assertNotIn("[DONE]", out)
        self.assertNotIn("verified:", out)
        self.assertNotIn("Granted in this run and verified", out)
        self.assertIn(f"Granted in this run, not verified yet (PREBOOT_ORG_GRANT_NOT_VISIBLE above): row 7 "
                      f"(Tag Administrator, {TAG_ROLE}). bootstrap checks it again.", out)
        # Bounded: the table's check + re-checks at 0, 1 and 2 s.
        self.assertEqual(len(self.curl_checks(TAG_PERMS[0])), 1 + 3)

    def test_grant_visible_after_propagation_polls_then_done(self):
        self.set_state(prepared_state(deny=TAG_PERMS, org_grant_visible_on_check=2))
        rc, out = self.tty(self.args(), ["yes", "n"], PB_ORG_GRANT_WAIT_SECS="5", PB_ORG_GRANT_POLL_SECS="1")
        self.assertEqual(rc, 0, out)
        self.assertIn("[DONE] Granted Tag Administrator", out)
        self.assertEqual(len(self.curl_checks(TAG_PERMS[0])), 1 + 2)

    def test_blocking_stop_or_declined_plan_writes_nothing_and_never_offers(self):
        self.set_state(prepared_state(deny=TAG_PERMS, deny_at={f"projects/{PROJ}": ["serviceusage.services.enable"]}))
        rc, out = self.tty(self.args(), ["y", "y", "n"])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("PREBOOT_MISSING_RIGHTS", out)
        self.assertNotIn(ASK, out)
        self.assertEqual(self.writes(), [])
        self.assert_no_org_admin_probe()
        self.set_state(fresh_state(deny=TAG_PERMS))
        rc, out = self.tty(["--new-project", PROJ, "--folder-name", "pbtest-workloads"], ["n", "y", "n"])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("PREBOOT_NOT_CONFIRMED", out)
        self.assertNotIn(ASK, out)
        self.assertEqual(self.writes(), [])

    def test_new_project_run_offers_after_the_creates(self):
        self.set_state(fresh_state(deny=TAG_PERMS))
        rc, out = self.tty(["--new-project", PROJ, "--folder-name", "pbtest-workloads"], ["y", "yes", "n"])
        self.assertEqual(rc, 0, out)
        w = self.writes()
        self.assertEqual(len(w), 4, w)
        self.assertEqual(w[-1], org_grant(self.ME_M, TAG_ROLE))
        self.assertIn("[DONE] Granted Tag Administrator", out)

    # --- row 8 ---

    def test_row_8_on_the_folder_yes_and_no(self):
        st = prepared_state(deny_at={"folders/555000000001": ORGPOL_PERMS})
        self.set_state(st)
        rc, out = self.tty(self.args(), ["yes", "n"])
        self.assertEqual(rc, 0, out)
        self.assertIn(org_question(self.ME_M, ORGPOL_ROLE), out)
        self.assertNotIn(org_question(self.ME_M, TAG_ROLE), out)
        # Granted on the organization (as row 8's printed command), re-checked where the table tested it.
        self.assertEqual(self.writes(), [org_grant(self.ME_M, ORGPOL_ROLE)])
        self.assertEqual(self.curl_checks("orgpolicy.policy.set"), ["folders/555000000001"] * 2)
        self.assertIn("verified: testIamPermissions on folders/555000000001 now returns the row 8 permissions", out)
        self.set_state(prepared_state(deny_at={"folders/555000000001": ORGPOL_PERMS}))
        rc, out = self.tty(self.args(), ["", "n"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertIn(STILL_MISSING_TODAY, out)

    def test_rows_7_and_8_each_asked_and_summary_lists_what_is_left(self):
        self.set_state(prepared_state(deny=TAG_PERMS + ORGPOL_PERMS))
        rc, out = self.tty(self.args(), ["yes", "", "n"])   # 7 yes, 8 Enter, do not start bootstrap
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [org_grant(self.ME_M, TAG_ROLE)])
        self.assertIn(org_question(self.ME_M, ORGPOL_ROLE), out)
        self.assertIn("[WARNING] Still missing (not blocking): row(s) 8 of the DEGRADED / OPTIONAL list above.", out)

    # --- --grant-to someone else: their binding in the organization IAM policy decides ---

    def test_grant_to_yes_and_no(self):
        self.set_state(self.runner_state())
        rc, out = self.tty(self.args("--grant-to", RUNNER), ["yes", ""])   # 7 yes, 8 Enter
        self.assertEqual(rc, 0, out)
        self.assertIn(org_question(self.RUNNER_M, TAG_ROLE), out)
        self.assertIn(org_question(self.RUNNER_M, ORGPOL_ROLE), out)
        self.assertEqual(self.writes(), [org_grant(self.RUNNER_M, TAG_ROLE)])
        self.assertIn(f"[DONE] Granted Tag Administrator ({TAG_ROLE}) on organizations/{ORG} to {self.RUNNER_M}; "
                      f"binding verified: the organization IAM policy lists it ({RUNNER}'s own rights are tested by "
                      "their check and by bootstrap).", out)
        self.assertIn(f"[OK] Granted in this run, binding verified in the organization IAM policy: row 7 (Tag "
                      f"Administrator, {TAG_ROLE}). {RUNNER}'s own rights are tested by their check and by bootstrap.",
                      out)
        self.assertNotIn("Granted in this run and verified", out)
        # Their own rights are still theirs to check: the command for it is still printed.
        self.assertIn("--check-only --existing-project example-host --existing-folder 555000000001", out)
        self.assertFalse(os.path.exists(self.boot_env))

    def test_grant_to_already_has_role_is_not_offered(self):
        st = self.runner_state()
        st["iam"][f"organizations/{ORG}"] = [{"role": TAG_ROLE, "members": [self.RUNNER_M]},
                                             {"role": ORGPOL_ROLE, "members": [self.RUNNER_M],
                                              "condition": {"title": "expires"}}]
        self.set_state(st)
        rc, out = self.tty(self.args("--grant-to", RUNNER), ["yes"])
        self.assertEqual(rc, 0, out)
        self.assertIn(f"[OK] Row 7: {self.RUNNER_M} already has Tag Administrator ({TAG_ROLE})", out)
        self.assertNotIn(org_question(self.RUNNER_M, TAG_ROLE), out)
        # A conditional binding does not count: row 8 is offered and granted unconditionally.
        self.assertIn(org_question(self.RUNNER_M, ORGPOL_ROLE), out)
        self.assertEqual(self.writes(), [org_grant(self.RUNNER_M, ORGPOL_ROLE)])

    def test_grant_to_binding_not_visible_is_a_typed_warning(self):
        self.set_state(self.runner_state(org_binding_invisible=True))
        rc, out = self.tty(self.args("--grant-to", RUNNER), ["yes", ""])
        self.assertEqual(rc, 0, out)
        self.assertIn(f"[WARNING] PREBOOT_ORG_GRANT_NOT_VISIBLE: granted {TAG_ROLE} on organizations/{ORG} to "
                      f"{self.RUNNER_M}, but after 0 s the organization IAM policy does not list the binding yet. "
                      "Not verified.", out)
        self.assertNotIn("[DONE]", out)

    def test_unanswered_offers_never_hang_and_grant_nothing(self):
        # Regression (11-16): a terminal run that answers only Proceed once waited forever at the second offer. The
        # harness now ends the input with EOF; an unanswered offer must read that as "no" and the run must end.
        self.set_state(prepared_state(deny=TAG_PERMS + ORGPOL_PERMS))
        rc, out = self.tty(self.args("--grant-to", RUNNER), ["y"], timeout=60)   # y: Proceed only
        self.assertEqual(rc, 0, out)
        self.assertIn(org_question(self.RUNNER_M, TAG_ROLE), out)
        self.assertIn(org_question(self.RUNNER_M, ORGPOL_ROLE), out)
        self.assertEqual([w for w in self.writes() if w[0] == "organizations"], [])
        self.set_state(prepared_state(deny=TAG_PERMS + ORGPOL_PERMS))
        rc, out = self.tty(self.args(), [], timeout=60)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.writes(), [])
        self.assertFalse(os.path.exists(self.boot_env))   # EOF at "Run ... now? [Y/n]" is no, too

    def test_callers_disable_prompts_means_no_offer(self):
        # CLOUDSDK_CORE_DISABLE_PROMPTS=1 from the caller marks an unattended run: never an organization-wide grant.
        for value in ("1", "true", "True"):
            with self.subTest(value=value):
                self.set_state(prepared_state(deny=TAG_PERMS))
                rc, out = self.tty(self.args(), ["y", "n"], CLOUDSDK_CORE_DISABLE_PROMPTS=value)
                self.assertEqual(rc, 0, out)
                self.assertNotIn(ASK, out)
                self.assertEqual(self.writes(), [])
                self.assert_no_org_admin_probe()
        self.set_state(prepared_state(deny=TAG_PERMS))
        rc, out = self.tty(self.args(), ["n", "n"], CLOUDSDK_CORE_DISABLE_PROMPTS="0")
        self.assertIn(org_question(self.ME_M, TAG_ROLE), out)

    # --- red-team fixes (11-16): skips, prompt scope, knob validation ---

    def test_project_or_folder_not_confirmed_in_the_org_is_not_offered(self):
        other = "organizations/999999999999"
        cases = {
            "project elsewhere": (prepared_state(deny=TAG_PERMS, projects={PROJ: {"state": "ACTIVE", "parent": other}}),
                                  self.args(), f"project {PROJ} is not under organizations/{ORG}"),
            "ancestry unreadable": (prepared_state(deny=TAG_PERMS, fail_reads=["projects get-ancestors"]),
                                    self.args(), f"the ancestors of project {PROJ} could not be read"),
        }
        st = prepared_state(deny=TAG_PERMS)
        st["folders"].append({"name": "folders/555000000088", "displayName": "elsewhere", "parent": other,
                              "state": "ACTIVE"})
        cases["folder elsewhere"] = (st, ["--existing-project", PROJ, "--existing-folder", "555000000088"],
                                     f"folder folders/555000000088 is not confirmed to be under organizations/{ORG} "
                                     f"(top parent found: {other})")
        for name, (state, args, why) in cases.items():
            with self.subTest(case=name):
                self.set_state(state)
                rc, out = self.tty(args, ["yes", "n"])
                self.assertEqual(rc, 0, out)
                self.assertIn(f"[WARNING] PREBOOT_ORG_OFFER_SKIPPED: rows 7 and 8 are not offered, because {why}; "
                              f"a grant on organizations/{ORG} might not reach it.", out)
                self.assertNotIn(ASK, out)
                self.assertEqual(self.writes(), [])
                self.assert_no_org_admin_probe()
                self.assertIn(f'--role="{TAG_ROLE}"', out)

    def test_personal_runner_account_is_not_offered(self):
        gmail = "someone@gmail.com"
        self.set_state(prepared_state(account=gmail, deny=TAG_PERMS))
        rc, out = self.tty(self.args(), ["y", "yes", "n"])   # y: continue with the personal account
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Rows 7 and 8 are not offered: {gmail} is a personal Google account (row 1).", out)
        self.assertNotIn(ASK, out)
        self.assertEqual([w for w in self.writes() if w[0] == "organizations"], [])
        self.assert_no_org_admin_probe()
        # --grant-to a personal account: the same.
        self.set_state(self.runner_state())
        rc, out = self.tty(self.args("--grant-to", "user:" + gmail), ["y", "y", "yes", "yes"])   # personal y, Proceed y
        self.assertIn(f"Rows 7 and 8 are not offered: {gmail} is a personal Google account (row 1).", out)
        self.assertEqual([w for w in self.writes() if w[0] == "organizations"], [])

    def test_impersonation_is_not_offered(self):
        # gcloud's property (the test guard strips CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT from every child's
        # environment, so that spelling is covered by the real gcloud reporting it as this property too).
        sa = "installer@example-host.iam.gserviceaccount.com"
        for how in ("config",):
            with self.subTest(how=how):
                st = prepared_state(deny=TAG_PERMS)
                st["config"] = {"auth/impersonate_service_account": sa}
                self.set_state(st)
                rc, out = self.tty(self.args(), ["yes", "n"])
                self.assertEqual(rc, 0, out)
                self.assertIn(f"Rows 7 and 8 are not offered: gcloud impersonates {sa} "
                              "(auth/impersonate_service_account)", out)
                self.assertNotIn(ASK, out)
                self.assertEqual(self.writes(), [])
                self.assert_no_org_admin_probe()

    def test_row_8_question_says_it_is_organization_wide(self):
        self.set_state(prepared_state(deny_at={"folders/555000000001": ORGPOL_PERMS}))
        rc, out = self.tty(self.args(), ["", "n"])
        self.assertIn(f"now? This is organization-wide: it lets {ME} change every organization policy in "
                      f"organizations/{ORG}. Type yes to grant, or press Enter to skip: ", out)

    def test_wait_knobs_are_validated(self):
        for wait, poll in (("08", "08"), ("9" * 20, "0"), ("abc", "9" * 20), ("", "-1")):
            with self.subTest(wait=wait, poll=poll):
                self.set_state(prepared_state(deny=TAG_PERMS))   # visible at once: no sleep needed
                rc, out = self.tty(self.args(), ["yes", "n"], PB_ORG_GRANT_WAIT_SECS=wait,
                                   PB_ORG_GRANT_POLL_SECS=poll)
                self.assertEqual(rc, 0, out)
                self.assertIn("[DONE] Granted Tag Administrator", out)
                self.assertNotIn("value too great", out)
                self.assertNotIn("syntax error", out)

    def test_grant_to_not_visible_reports_the_failed_policy_read(self):
        self.set_state(self.runner_state(org_policy_fail_after_grant=True))
        rc, out = self.tty(self.args("--grant-to", RUNNER), ["yes", ""])
        self.assertEqual(rc, 0, out)
        self.assertIn(f"PREBOOT_ORG_GRANT_NOT_VISIBLE: granted {TAG_ROLE} on organizations/{ORG} to {self.RUNNER_M}, "
                      "but after 0 s the organization IAM policy does not list the binding yet (last policy read "
                      "failed: ERROR: (gcloud.organizations.get-iam-policy", out)
        self.assertNotIn("[DONE]", out)

    def test_grant_to_never_offered_with_yes_no_terminal_or_without_org_iam(self):
        self.set_state(self.runner_state())
        rc, out = self.run_copy(*self.args("--grant-to", RUNNER, "--yes"))
        self.assertEqual(rc, 0, out)
        self.assertNotIn(ASK, out)
        self.assert_no_org_admin_probe()
        rc, out = self.run_copy(*self.args("--grant-to", RUNNER))
        self.assertEqual(rc, 0, out)
        self.assert_no_org_admin_probe()
        self.set_state(self.runner_state(deny=["resourcemanager.organizations.setIamPolicy"]))
        rc, out = self.tty(self.args("--grant-to", RUNNER), ["y", "y"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn(ASK, out)
        self.assertEqual(self.writes(), [])


class TestContracts(unittest.TestCase):
    def test_bash_syntax(self):
        r = subprocess.run([BASH, "-n", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_summary_formats_match_bootstrap_prompts(self):
        with open(os.path.join(REPO, "scripts", "bootstrap.sh")) as f:
            boot = f.read()
        self.assertIn("Enter Google Cloud Organization ID (e.g. organizations/123456789012)", boot)
        self.assertIn("Enter Billing Account ID (e.g. 01XXXX-XXXXXX-XXXXXX)", boot)
        self.assertIn("Enter Managed Workloads Folder ID (e.g. folders/123456789012)", boot)

    def test_self_check_permissions_cover_the_quickstart_self_check(self):
        with open(os.path.join(REPO, "documentation", "quickstart.md")) as f:
            qs = f.read()
        with open(SCRIPT) as f:
            script = f.read()
        for perm in ("resourcemanager.projects.create", "resourcemanager.folders.create",
                     "resourcemanager.folders.setIamPolicy", "resourcemanager.tagKeys.create",
                     "orgpolicy.policies.create"):
            self.assertIn(perm, qs)
            self.assertIn(perm, script)
        self.assertIn("scripts/pre-bootstrap.sh", qs)



class TestOpenTofuOffer(_PreBootstrap):
    """INSTALLER-OPENTOFU-OFFER: pre-bootstrap checks the engine bootstrap needs, before any gcloud call
    (the helper itself: tests/test_installer_opentofu_offer.py)."""

    def no_tofu(self):
        os.remove(os.path.join(self.stub, "tofu"))

    def test_missing_not_a_terminal_stops_typed_before_any_gcloud_call(self):
        self.no_tofu()
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 1, out)
        self.assertIn("PREBOOT_OPENTOFU_MISSING: OpenTofu ('tofu') is not installed or not on PATH.", out)
        self.assertRegex(out, r"(sha256sum|shasum -a 256) -c -")   # the host OS picks the tool
        self.assertNotIn("Install OpenTofu 1.13.1 into ~/bin now?", out)
        self.assertEqual(self.calls(), [])

    def test_missing_in_a_terminal_asks_and_no_stops_before_any_gcloud_call(self):
        self.no_tofu()
        rc, out = self.run_tty(["--new-project", PROJ, "--existing-folder", "555000000001"], ["n"])
        self.assertEqual(rc, 1, out)
        self.assertIn("Install OpenTofu 1.13.1 into ~/bin now? [y/N]", out)
        self.assertIn("PREBOOT_OPENTOFU_DECLINED", out)
        self.assertEqual(self.calls(), [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "home", "bin")))

    def test_check_only_dry_run_and_grant_to_do_not_need_the_engine(self):
        self.no_tofu()
        for extra in (["--check-only"], ["--dry-run"], ["--grant-to", RUNNER]):
            with self.subTest(extra=extra):
                rc, out = self.run_script("--new-project", PROJ, "--yes", *extra)
                self.assertNotIn("OPENTOFU", out)

    def test_usable_engine_is_silent(self):
        rc, out = self.run_script("--new-project", PROJ, "--yes")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("OpenTofu", out)


if __name__ == "__main__":
    unittest.main()

"""SAT-10 / FD-4DA: scripts/upgrade.sh (item 9) and the bootstrap "weekly auto-update from upstream" question (item 4).

Both run the real scripts under lane 5's hermetic harness (logging stubs for gcloud/tofu/curl/...; the tofu stub hands
only `console` to the real OpenTofu binary for local tfvars parsing; no GCP, no network).

upgrade.sh runs in a real temporary git checkout cloned (without tags) from a temporary "origin": commit A on `main`
(installed) and the release commit B tagged v0.9.1. scripts/apply.sh and scripts/deploy-services.sh are logging fakes
in both commits; B's upgrade.sh is a trap that would log BROKEN if bash re-read the file after the checkout.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)

PROJ = L5.PROJ
REPO = L5.REPO
UPGRADE = os.path.join(REPO, "scripts", "upgrade.sh")
SMOKE = os.path.join(REPO, "scripts", "common", "upgrade_smoke.py")
TAG = "v0.9.1"
OLD_TAG = "v0.9.0"
RENAMED_KINDS = ("renamed", "renamed-decoy", "renamed-unsigned", "hostile-name", "hostile-tagger")
# A tagger name with a raw ESC sequence and a literal backslash escape that `echo -e` would turn into one.
HOSTILE_TAGGER = "Evil\x1b[2J\\033[31mX"

_spec = importlib.util.spec_from_file_location("upgrade_smoke", SMOKE)
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)

FAKE_APPLY = '''#!/bin/bash
echo "apply.sh({rel}) $* project=${{PROJECT_ID:-}} tfvars_file=${{TFVARS_FILE:-}}" >> "$STUB_LOG"
case "$1" in
  plan) [ -z "${{STUB_APPLY_PLAN_SIGINT:-}}" ] || {{ kill -INT 0; sleep 1; }}; exit "${{STUB_APPLY_PLAN_RC:-0}}" ;;
  apply) [ -z "${{STUB_APPLY_APPLY_SIGINT:-}}" ] || {{ kill -INT 0; sleep 1; }}; exit "${{STUB_APPLY_APPLY_RC:-0}}" ;;
esac
exit 0
'''
FAKE_DEPLOY = '''#!/bin/bash
echo "deploy-services.sh({rel}) $* project=${{PROJECT_ID:-}} region=${{REGION:-}}" >> "$STUB_LOG"
exit "${{STUB_DEPLOY_RC:-0}}"
'''
BROKEN_UPGRADE = '#!/bin/bash\necho "BROKEN upgrade.sh re-read after checkout" >> "$STUB_LOG"\nexit 99\n'
GCLOUD_WRAPPER = r'''#!/bin/bash
case "$*" in
  "run services list"*)
      echo "gcloud $*" >> "$STUB_LOG"
      [ -n "${STUB_SERVICES_JSON:-}" ] && cat "$STUB_SERVICES_JSON" && exit 0
      exit 1 ;;
esac
exec "$(dirname "$0")/gcloud.orig" "$@"
'''
STAMP_HEAD = 'variable "stackvend_platform_commit"'
_RELEASE_STAMP = object()
STAMP_VARIABLE = '\nvariable "stackvend_platform_commit" {\n  type    = string\n  default = ""\n}\n'
GIT_ID = {"GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
          "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com"}


def _service(name, ready="True", newest="r2", serving="r2", platform=True, stamp=None):
    md = {"name": name, "labels": {"managed_by": "castor-terraform"} if platform else {"team": "x"}}
    if stamp is not None:
        md["annotations"] = {"stackvend/platform-commit": stamp}
    return {"metadata": md, "status": {"conditions": [{"type": "Ready", "status": ready}],
                                       "latestCreatedRevisionName": newest, "latestReadyRevisionName": serving}}


# ==============================================================================
# upgrade_smoke.py (pure)
# ==============================================================================
class TestSmokeCheck(unittest.TestCase):
    SHA = "a" * 40

    def test_pass_and_non_platform_services_ignored(self):
        svcs = [_service("product-control-center-ui"), _service("mcp-gcloud-server"),
                _service("someone-elses", ready="False", platform=False)]
        self.assertEqual(smoke.check(svcs, self.SHA, False), [])

    def test_no_platform_services_is_a_finding(self):
        self.assertEqual([f.split(":")[0] for f in smoke.check([_service("x", platform=False)], self.SHA, False)],
                         ["SMOKE_NO_PLATFORM_SERVICES"])

    def test_not_ready_and_newest_revision_not_serving(self):
        svcs = [_service("a", ready="False"), _service("b", newest="r3", serving="r2"), _service("c")]
        self.assertEqual(smoke.check(svcs, self.SHA, False),
                         ["SMOKE_SERVICE_NOT_READY: a (Ready=False)",
                          "SMOKE_NEWEST_REVISION_NOT_READY: b (newest r3, ready r2)"])

    def test_stamp(self):
        cc = "product-control-center-ui"
        self.assertEqual(smoke.check([_service(cc, stamp=self.SHA)], self.SHA, True), [])
        self.assertEqual([f.split(":")[0] for f in smoke.check([_service(cc)], self.SHA, True)], ["SMOKE_STAMP_MISSING"])
        self.assertEqual([f.split(":")[0] for f in smoke.check([_service(cc, stamp="b" * 40)], self.SHA, True)],
                         ["SMOKE_STAMP_MISMATCH"])
        self.assertEqual([f.split(":")[0] for f in smoke.check([_service(cc, stamp=self.SHA + "+dirty")], self.SHA, True)],
                         ["SMOKE_STAMP_MISMATCH"])
        # A release before the stamp: no annotation is fine; a stale one still must match.
        self.assertEqual(smoke.check([_service(cc)], self.SHA, False), [])
        self.assertEqual([f.split(":")[0] for f in smoke.check([_service(cc, stamp="b" * 40)], self.SHA, False)],
                         ["SMOKE_STAMP_MISMATCH"])

    def test_cli_unreadable_and_usage(self):
        tmp = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"sat10-smoke-{os.getpid()}.json")
        try:
            with open(tmp, "w") as f:
                f.write("{not json")
            self.assertEqual(smoke.main(["--services-json", tmp, "--expect-commit", self.SHA, "--stamp-required", "no"]), 2)
            with open(tmp, "w") as f:
                json.dump({"items": []}, f)
            self.assertEqual(smoke.main(["--services-json", tmp, "--expect-commit", self.SHA, "--stamp-required", "no"]), 2)
            self.assertEqual(smoke.main(["--services-json", tmp, "--expect-commit", "HEAD", "--stamp-required", "no"]), 2)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)


# ==============================================================================
# upgrade.sh: static contract
# ==============================================================================
class TestUpgradeScriptStatic(unittest.TestCase):
    def setUp(self):
        with open(UPGRADE, encoding="utf-8") as f:
            self.src = f.read()

    def test_runs_as_one_function_read_before_the_checkout(self):
        lines = [x for x in self.src.splitlines() if x.strip()]
        self.assertEqual(lines[-1], 'sv_upgrade_main "$@"; exit $?')
        self.assertIn("sv_upgrade_main() {", self.src)

    def test_strict_mode_and_signal_traps(self):
        self.assertIn("set -u -o pipefail", self.src)
        self.assertNotIn("set -e", self.src.replace("No `set -e`", ""))
        self.assertIn("trap 'sv_upgrade_interrupted INT' INT", self.src)
        self.assertIn("trap 'sv_upgrade_interrupted TERM' TERM", self.src)
        # The remote URL can hold credentials: it is never printed.
        self.assertNotIn('remote get-url "${remote}" 2>/dev/null)', self.src)

    def test_no_xtrace_no_iam_no_token(self):
        for bad in ("set -x", "set -o xtrace", "add-iam-policy-binding", "set-iam-policy", "print-access-token",
                    "print-identity-token", "--allow-destroy=${PROJECT_ID}"):
            self.assertNotIn(bad, self.src)

    def test_reuses_the_platform_target_guards(self):
        for fn in ("sv_scrub_tofu_env", "sv_require_iac_version", "sv_resolve_platform_target", "sv_tfvar"):
            self.assertIn(fn, self.src)
        self.assertNotIn("gcloud config get-value project", self.src)

    def test_executable(self):
        self.assertTrue(os.access(UPGRADE, os.X_OK))

    def test_signature_is_verified_ssh_only_with_the_installed_keys_before_the_checkout(self):
        """SELFUP-SIGN / review H-5: verify-tag with the installed checkout's allowed_signers (copied in preflight),
        OpenPGP / X.509 verifiers disabled for the check, and the verification precedes the checkout."""
        for needle in ("-c gpg.format=ssh", "-c gpg.ssh.program=ssh-keygen", "-c gpg.openpgp.program=false",
                       "-c gpg.x509.program=false", 'gpg.ssh.allowedSignersFile="${UP_SIGNERS}"', "verify-tag",
                       'cp "${signers_src}" "${UP_TMP}/allowed_signers"', "--trust-unsigned"):
            self.assertIn(needle, self.src)
        self.assertLess(self.src.index('UP_STAGE="VERIFY"'), self.src.index('UP_STAGE="CHECKOUT"'))
        self.assertLess(self.src.index('UP_STAGE="FETCH"'), self.src.index('UP_STAGE="VERIFY"'))
        self.assertFalse("signatures are not checked" in self.src.lower(), "stale 'not checked' text")

    def test_inner_tag_name_is_checked_before_the_signature_and_the_checkout(self):
        """FD-132 (R8-04): the annotated tag's own name (git's header parser, `%(tag)`) must equal the requested tag,
        checked in the VERIFY stage before verify-tag (so "good" is never printed for a misnamed tag) and before the
        checkout; verify-tag names the full ref."""
        for needle in ('[[ "${tag_oid}" =~ ^[0-9a-f]{40}$ ]] || tag_oid=""', 'cat-file -t "${tag_oid}"',
                       "for-each-ref --format='%(objectname) %(tag)' \"refs/tags/${tag}\"",
                       '[ "${ref_line%% *}" != "${tag_oid}" ] || inner_name="${ref_line#* }"',
                       'up_remove_fetched_tag "${tag}" "${tag_before}" "${tag_oid}"',
                       '[ "${inner_name}" != "${tag}" ]', "up_fail UPGRADE_TAG_NAME_MISMATCH",
                       'verify-tag "refs/tags/${tag}"', "verify-tag refs/tags/${tag}\"",
                       'fetch --no-tags --no-recurse-submodules',
                       "tagger=\"$(printf '%s' \"${tagger}\" | LC_ALL=C tr -cd 'A-Za-z0-9 @.,:<>+_-')\"",
                       "author=\"$(printf '%s' \"${author}\" | LC_ALL=C tr -cd 'A-Za-z0-9 @.,:<>+_-')\""):
            self.assertIn(needle, self.src)
        check = self.src.index("up_fail UPGRADE_TAG_NAME_MISMATCH")
        self.assertLess(self.src.index('UP_STAGE="VERIFY"'), check)
        self.assertLess(check, self.src.index('verify-tag "refs/tags/${tag}"'))
        self.assertLess(check, self.src.index('UP_STAGE="CHECKOUT"'))

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_remove_fetched_tag_only_when_fetched_and_only_that_object(self):
        """up_remove_fetched_tag: removes refs/tags/<tag> only when the checkout had no such tag before the fetch
        ($2 empty) and only while it still names the object id read after the fetch ($3); an empty or malformed $3
        removes nothing (an empty old value would make `update-ref -d` unconditional)."""
        import tempfile
        start = self.src.index("up_remove_fetched_tag() {")
        func = self.src[start:self.src.index("\n}\n", start) + 3]
        tmp = tempfile.mkdtemp(prefix="fd132-remove-")
        try:
            env = hermetic_guard.child_env(extra={"HOME": tmp, **GIT_ID})

            def git(*args):
                return subprocess.run(["git", "-C", tmp, *args], env=env, text=True, capture_output=True,
                                      check=True).stdout.strip()

            git("init", "-q")
            git("commit", "-q", "--allow-empty", "-m", "a")
            git("tag", "-a", TAG, "-m", "x")
            oid = git("rev-parse", f"refs/tags/{TAG}")
            other = git("rev-parse", "HEAD")

            def run(before, after):
                script = f'REPO_ROOT={json.dumps(tmp)}\n{func}\nup_remove_fetched_tag {TAG} "{before}" "{after}"'
                rc = subprocess.run(["/bin/bash", "-c", script], env=env, capture_output=True).returncode
                exists = subprocess.run(["git", "-C", tmp, "rev-parse", "--verify", "--quiet", f"refs/tags/{TAG}"],
                                        env=env, capture_output=True).returncode == 0
                return rc, exists

            self.assertEqual(run(oid, oid), (1, True))        # the tag was already here: kept
            self.assertEqual(run("", ""), (1, True))          # no object id read: nothing removed
            self.assertEqual(run("", "zz" * 20), (1, True))   # malformed id: nothing removed
            self.assertEqual(run("", other), (1, True))       # the ref names another object: nothing removed
            self.assertEqual(run("", oid), (0, False))        # fetched by this run, still that object: removed
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_old_git_and_openssh_are_refused_in_preflight_by_exact_version(self):
        """Code review M-2: git < 2.34 or OpenSSH < 8.2 would misreport a good signature as invalid."""
        for needle in ("up_version_at_least \"${git_version}\" '^git version ([0-9]+)\\.([0-9]+)' 2 34",
                       "up_version_at_least \"${ssh_version}\" '^OpenSSH_([0-9]+)\\.([0-9]+)' 8 2",
                       'git_version="$(git --version 2>/dev/null)"', 'ssh_version="$(ssh -V 2>&1)"'):
            self.assertIn(needle, self.src)
        self.assertLess(self.src.index("up_version_at_least \"${git_version}\""), self.src.index('UP_STAGE="FETCH"'))

    def test_version_compare_is_exact(self):
        start = self.src.index("up_version_at_least() {")
        func = self.src[start:self.src.index("\n}\n", start) + 3]
        git_re, ssh_re = r"'^git version ([0-9]+)\.([0-9]+)'", r"'^OpenSSH_([0-9]+)\.([0-9]+)'"
        cases = [("git version 2.34.0", git_re, 2, 34, True), ("git version 2.33.9", git_re, 2, 34, False),
                 ("git version 2.50.1 (Apple Git-155)", git_re, 2, 34, True), ("git version 3.0.0", git_re, 2, 34, True),
                 ("git version 1.99.0", git_re, 2, 34, False), ("git version 2.4.0", git_re, 2, 34, False),
                 ("", git_re, 2, 34, False), ("hub version 2.40", git_re, 2, 34, False),
                 ("OpenSSH_8.2p1 Ubuntu", ssh_re, 8, 2, True), ("OpenSSH_8.1p1, LibreSSL", ssh_re, 8, 2, False),
                 ("OpenSSH_9.9p2, LibreSSL 3.3.6", ssh_re, 8, 2, True), ("OpenSSH_10.0p1", ssh_re, 8, 2, True),
                 ("OpenSSH_7.9p1", ssh_re, 8, 2, False), ("Sun_SSH_1.1", ssh_re, 8, 2, False)]
        for text, regex, major, minor, ok in cases:
            script = f"{func}\nup_version_at_least {json.dumps(text)} {regex} {major} {minor}"
            rc = subprocess.run(["/bin/bash", "-c", script], capture_output=True).returncode
            self.assertEqual(rc == 0, ok, (text, rc))


# ==============================================================================
# upgrade.sh: behaviour in a real temporary git checkout
# ==============================================================================
@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
@unittest.skipUnless(shutil.which("git"), "needs git")
class TestUpgradeScript(L5._Harness):
    def setUp(self):
        super().setUp()
        stub = os.path.join(self.stub, "gcloud")
        os.rename(stub, os.path.join(self.stub, "gcloud.orig"))
        with open(stub, "w") as f:
            f.write(GCLOUD_WRAPPER)
        os.chmod(stub, 0o755)
        self.services_json = os.path.join(self.tmp, "services.json")

    # -- fixture ---------------------------------------------------------------------------------------------------
    def git(self, cwd, *args):
        env = hermetic_guard.child_env(extra={"HOME": os.path.join(self.tmp, "home"), **GIT_ID})
        return subprocess.run(["git", *args], cwd=cwd, env=env, text=True, capture_output=True, check=True).stdout.strip()

    def _write_fakes(self, root, rel):
        for name, body in (("apply.sh", FAKE_APPLY), ("deploy-services.sh", FAKE_DEPLOY)):
            p = os.path.join(root, "scripts", name)
            with open(p, "w") as f:
                f.write(body.format(rel=rel))
            os.chmod(p, 0o755)

    def keygen(self, name):
        """A fresh ed25519 test key pair (no passphrase) -> (private key path, allowed_signers line)."""
        keys = os.path.join(self.tmp, "keys")
        os.makedirs(keys, exist_ok=True)
        path = os.path.join(keys, name)
        if not os.path.exists(path):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", path], check=True,
                           capture_output=True)
        with open(path + ".pub") as f:
            kind, b64 = f.read().split()[:2]
        return path, f"stackvend-release {kind} {b64}\n"

    def _write_signers(self, root, which):
        """scripts/release/allowed_signers in a tree: "release" (the test release key), "other" (another key) or
        None (no file, as on main before the owner commits the official key)."""
        path = os.path.join(root, "scripts", "release", "allowed_signers")
        if which is None:
            if os.path.exists(path):
                os.remove(path)
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(self.keygen(which)[1])

    def sign_tag(self, cwd, key, target="HEAD", name=TAG):
        self.git(cwd, "-c", "gpg.format=ssh", "-c", f"user.signingkey={self.keygen(key)[0]}", "tag", "-s", name,
                 "-m", f"release {name}", target)

    def build(self, stamp_in_release=True, tfvars_extra="", broken_release_script=True, broken_release_vars=False,
              tag="signed", installed_signers="release", release_signers="release"):
        """origin: A (main, installed) and B (tag v0.9.1); self.repo = a tagless clone at A + the install's tfvars.
        tag: "signed" (SSH-signed with the release key), "other-key" (signed with another key), "annotated"
        (unsigned) or "lightweight". The trusted keys: A's (the installed checkout's) and B's (the release's own)."""
        origin = os.path.join(self.tmp, "origin")
        shutil.copytree(self.repo, origin)
        with open(os.path.join(origin, ".gitignore"), "w") as f:
            f.write("*.tfvars\n.terraform-*/\n")
        self._write_fakes(origin, "A")
        self._write_signers(origin, installed_signers)
        self.git(origin, "init", "-q", "-b", "main")
        self.git(origin, "add", "-A")
        self.git(origin, "commit", "-q", "-m", "A")
        self.sha_a = self.git(origin, "rev-parse", "HEAD")
        self.git(origin, "checkout", "-q", "-b", "release")
        self._write_fakes(origin, "B")
        self._write_signers(origin, release_signers)
        if broken_release_script:
            with open(os.path.join(origin, "scripts", "upgrade.sh"), "w") as f:
                f.write(BROKEN_UPGRADE)
        with open(os.path.join(origin, "RELEASE"), "w") as f:
            f.write(TAG + "\n")
        if broken_release_vars:
            with open(os.path.join(origin, "infra", "platform", "variables.tf"), "a") as f:
                f.write('\nvariable "broken" {\n')
        # The release declares the platform stamp (main's variables.tf does since SAT-33) unless a test asks for a
        # release from before the stamp: then the declaration is removed from B's variables.tf.
        vars_tf = os.path.join(origin, "infra", "platform", "variables.tf")
        with open(vars_tf) as f:
            text = f.read()
        declared = STAMP_HEAD + " {" in text
        if stamp_in_release and not declared:
            text += STAMP_VARIABLE
        elif not stamp_in_release and declared:
            text = text.replace(L5._block(text, STAMP_HEAD), "")
        with open(vars_tf, "w") as f:
            f.write(text)
        self.release_declares_stamp = stamp_in_release
        self.git(origin, "add", "-A")
        self.git(origin, "commit", "-q", "-m", "B")
        if tag == "signed":
            self.sign_tag(origin, "release")
        elif tag == "other-key":
            self.sign_tag(origin, "other")
        elif tag == "annotated":
            self.git(origin, "tag", "-a", TAG, "-m", "release")
        elif tag in RENAMED_KINDS:
            self._publish_under_another_name(origin, tag)
        else:
            self.git(origin, "tag", TAG)
        self.sha_b = self.git(origin, "rev-parse", "HEAD")
        self.git(origin, "checkout", "-q", "main")
        shutil.rmtree(self.repo)
        self.git(self.tmp, "clone", "-q", "--no-tags", "-b", "main", "file://" + origin, self.repo)
        for t in self.git(self.repo, "tag", "-l").split():
            self.git(self.repo, "tag", "-d", t)
        self.root = os.path.realpath(self.repo)  # upgrade.sh names the checkout by its physical path
        self.platform = os.path.join(self.repo, "infra", "platform")
        self.write(os.path.join("infra", "platform", f"{PROJ}.tfvars"), L5._tfvars(extra=tfvars_extra))
        self.origin = origin

    def _publish_under_another_name(self, origin, kind):
        """FD-132 (R8-04): a tag object made for OLD_TAG (or one with a hostile name) published as refs/tags/TAG.
        "renamed": SSH-signed with the trusted release key; "renamed-decoy": the same, and its message holds a
        `tag v0.9.1` line; "renamed-unsigned": annotated, unsigned; "hostile-name": a hand-made tag object whose own
        name is TAG followed by terminal control characters; "hostile-tagger": a hand-made, correctly named, unsigned
        tag object whose tagger name holds terminal control characters."""
        if kind in ("hostile-name", "hostile-tagger"):
            name, tagger = (f"{TAG}\x1b[2J\\033[31mx", "Test") if kind == "hostile-name" else (TAG, HOSTILE_TAGGER)
            body = (f"object {self.git(origin, 'rev-parse', 'HEAD')}\ntype commit\ntag {name}\n"
                    f"tagger {tagger} <test@example.com> 1700000000 +0000\n\nrelease\n")
            env = hermetic_guard.child_env(extra={"HOME": os.path.join(self.tmp, "home"), **GIT_ID})
            oid = subprocess.run(["git", "hash-object", "-t", "tag", "-w", "--literally", "--stdin"], cwd=origin,
                                 env=env, input=body, text=True, capture_output=True, check=True).stdout.strip()
        else:
            if kind == "renamed":
                self.sign_tag(origin, "release", name=OLD_TAG)
            elif kind == "renamed-decoy":
                self.git(origin, "-c", "gpg.format=ssh", "-c", f"user.signingkey={self.keygen('release')[0]}", "tag",
                         "-s", OLD_TAG, "-m", f"release {OLD_TAG}\n\ntag {TAG}", "HEAD")
            else:
                self.git(origin, "tag", "-a", OLD_TAG, "-m", f"release {OLD_TAG}", "HEAD")
            oid = self.git(origin, "rev-parse", f"refs/tags/{OLD_TAG}")
            self.git(origin, "tag", "-d", OLD_TAG)
        self.git(origin, "update-ref", f"refs/tags/{TAG}", oid)

    def services(self, stamp=_RELEASE_STAMP, ready="True"):
        """The fake `gcloud run services list`. By default the Control Center carries the stamp the release's apply
        writes: the release commit when the release declares the stamp, none otherwise. stamp=None: no annotation."""
        if stamp is _RELEASE_STAMP:
            stamp = self.sha_b if self.release_declares_stamp else None
        with open(self.services_json, "w") as f:
            json.dump([_service("product-control-center-ui", stamp=stamp, ready=ready), _service("mcp-gcloud-server"),
                       _service("unrelated", ready="False", platform=False)], f)

    def upgrade(self, args=(TAG,), tty="y", no_target=False, **env):
        env.setdefault("STUB_SERVICES_JSON", self.services_json)
        if not no_target and "TFVARS_FILE" not in env:
            env.setdefault("PROJECT_ID", PROJ)
        rc, out, err = self.run_script("upgrade.sh", list(args), tty_input=tty, **env)
        return rc, out + err

    def head(self):
        return self.git(self.repo, "rev-parse", "HEAD")

    def local_tags(self):
        return self.git(self.repo, "tag", "-l")

    def steps(self):
        """The commands upgrade.sh ran, in order (apply.sh, deploy-services.sh, the smoke list call)."""
        out = []
        for line in self.calls():
            if line.startswith(("apply.sh(", "deploy-services.sh(", "gcloud run services list", "BROKEN")):
                out.append(line.split(" project=")[0].split(" --project")[0])
        return out

    def assert_one_next_command(self, text, command):
        self.assertEqual(text.count("Next command:"), 1, text)
        after = text.split("Next command:", 1)[1].strip().splitlines()[0].strip()
        self.assertEqual(after, command)

    def assert_nothing_happened(self):
        self.assertEqual(self.steps(), [])
        self.assertEqual(self.head(), self.sha_a)
        self.assertEqual(self.local_tags(), "")

    # -- happy paths -----------------------------------------------------------------------------------------------
    def test_upgrade_with_a_vars_file_that_never_had_the_removed_keys(self):
        """REMOVE-DEVELOPER-MODE: L5._tfvars() has no removed key; deploy-services.sh always runs."""
        self.build()
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply", "deploy-services.sh(B) --all-jobs",
                                        "gcloud run services list"])

    def test_upgrade_with_an_old_vars_file_that_still_sets_the_removed_keys(self):
        """An old vars file (keys that no longer exist, even triggers = true) changes nothing: the services deploy."""
        self.build(tfvars_extra=("castor_deployment_mode = \"DEVELOPER\"\ngithub_repo = \"x\"\n"
                                 "cloudbuild_2nd_gen_repo_id = \"\"\nenable_cloud_build_triggers = true\n"))
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply", "deploy-services.sh(B) --all-jobs",
                                        "gcloud run services list"])
        self.assertIn(f"[OK]\x1b[0m {PROJ} runs {TAG} ({self.sha_b}).", text)

    def test_runs_the_steps_in_order_with_the_releases_scripts(self):
        self.build()
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply", "deploy-services.sh(B) --all-jobs",
                                        "gcloud run services list"])
        deploy = [x for x in self.calls() if x.startswith("deploy-services.sh(")][0]
        self.assertTrue(deploy.endswith(f"project={PROJ} region=us-central1"), deploy)
        self.assertIn(f"gcloud run services list --project={PROJ} --region=us-central1 --format=json --quiet", self.calls())
        self.assertEqual(self.head(), self.sha_b)
        self.assertEqual(self.git(self.repo, "rev-parse", "main"), self.sha_a)  # the branch is not moved
        self.assertIn(f"[OK]\x1b[0m {PROJ} runs {TAG} ({self.sha_b}).", text)
        self.assertNotIn("Next command:", text)
        self.assertNotIn("stub-token", text)
        self.assertEqual(self.git(self.repo, "status", "--porcelain"), "")

    # -- review fixes (11-01) --------------------------------------------------------------------------------------
    def test_release_commit_and_tagger_are_shown_before_the_plan(self):
        self.build(tag="lightweight")
        self.services()
        rc, text = self.upgrade(args=(TAG, "--trust-unsigned"))
        self.assertEqual(rc, 0, text)
        info = f"Release {TAG}: commit {self.sha_b}; tagged by (lightweight tag, no tagger); commit by Test test@example.com"
        self.assertIn(info, text)
        self.assertLess(text.index(info), text.index("Read-only plan of the release"))

    def test_annotated_tag_shows_its_tagger(self):
        self.build()  # signed (annotated) by default
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertIn(f"Release {TAG}: commit {self.sha_b}; tagged by Test <test@example.com> ", text)

    # -- signature (SELFUP-SIGN; review H-5, 11-02) ----------------------------------------------------------------
    def assert_refused_before_checkout(self, text, cls, stage):
        self.assertIn(f"{cls} (stage {stage})", text)
        self.assertEqual(self.steps(), [])  # nothing of the release ran
        self.assertEqual(self.head(), self.sha_a)
        self.assertNotIn("[OK]", text)

    def test_signed_tag_is_verified_with_the_installed_keys_before_the_plan(self):
        self.build()
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        good = f"1/6 Signature of {TAG}: good, by a key in scripts/release/allowed_signers of this checkout."
        self.assertIn(good, text)
        self.assertLess(text.index(good), text.index("Read-only plan of the release"))
        self.assertNotIn("--trust-unsigned", text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply", "deploy-services.sh(B) --all-jobs",
                                        "gcloud run services list"])

    def _refused_unsigned(self, kind, tag_already_local=False):
        self.build(tag=kind)
        if tag_already_local:
            self.git(self.repo, "fetch", "-q", "--no-tags", "origin", f"refs/tags/{TAG}:refs/tags/{TAG}")
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assert_refused_before_checkout(text, "UPGRADE_SIGNATURE_INVALID", "VERIFY")
        if tag_already_local:
            self.assertIn("the tag was already in this checkout before this run and is kept", text)
            self.assertEqual(self.local_tags(), TAG)
            self.assert_one_next_command(
                text, f"git -C {self.root} -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="
                      f"scripts/release/allowed_signers verify-tag refs/tags/{TAG}")
        else:
            # a tag this run fetched is removed again: a later, corrected publish is not blocked at the fetch
            self.assertIn("the tag this run fetched was removed again", text)
            self.assertEqual(self.local_tags(), "")
            self.assert_one_next_command(text, f"git -C {self.root} ls-remote --tags origin {TAG}")

    def test_unsigned_tag_that_was_already_local_is_kept(self):
        self._refused_unsigned("annotated", tag_already_local=True)

    def test_refused_signature_does_not_block_a_corrected_publish(self):
        """After a refusal the fetched tag is gone, so the same run after a corrected (signed) publish succeeds."""
        self.build(tag="annotated")
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.git(self.origin, "tag", "-d", TAG)
        self.sign_tag(self.origin, "release", target=self.sha_b)
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertIn(f"Signature of {TAG}: good", text)

    def test_unsigned_annotated_tag_is_refused(self):
        self._refused_unsigned("annotated")

    def test_lightweight_tag_is_refused(self):
        self._refused_unsigned("lightweight")

    def test_tag_signed_by_another_key_is_refused(self):
        self.build(tag="other-key")
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assert_refused_before_checkout(text, "UPGRADE_SIGNATURE_INVALID", "VERIFY")

    def test_the_release_never_chooses_its_own_trusted_keys(self):
        """B's allowed_signers trusts the key B is signed with; A's (installed) does not: refused."""
        self.build(tag="other-key", installed_signers="release", release_signers="other")
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assert_refused_before_checkout(text, "UPGRADE_SIGNATURE_INVALID", "VERIFY")

    # -- inner tag name (FD-132, R8-04) ------------------------------------------------------------------------------
    def _refused_renamed(self, kind, args=(TAG,), shown=f"'{OLD_TAG}'", tag_already_local=False):
        self.build(tag=kind)
        self.services()
        if tag_already_local:
            self.git(self.repo, "fetch", "-q", "--no-tags", "origin", f"refs/tags/{TAG}:refs/tags/{TAG}")
        rc, text = self.upgrade(args=args)
        self.assertEqual(rc, 1, text)
        self.assert_refused_before_checkout(text, "UPGRADE_TAG_NAME_MISMATCH", "VERIFY")
        self.assertIn(f"The tag object fetched as {TAG} is named {shown} inside", text)
        self.assertNotIn("Signature of", text)  # checked before the signature: "good" is never printed
        self.assertNotIn("[WARNING]", text)
        self.assertEqual(text.count("[ERROR]"), 1, text)
        if tag_already_local:
            self.assertIn("the tag was already in this checkout before this run and is kept", text)
            self.assertEqual(self.local_tags(), TAG)
            self.assert_one_next_command(
                text, f"git -C {self.root} for-each-ref --format='%(refname) %(tag)' refs/tags/{TAG}")
        else:
            self.assertIn("the tag this run fetched was removed again", text)
            self.assertEqual(self.local_tags(), "")  # the refused object is not left under the release's name
            self.assert_one_next_command(text, f"git -C {self.root} ls-remote --tags origin {TAG}")
        return text

    def test_a_misnamed_tag_that_was_already_local_is_kept(self):
        """Only a tag this run fetched is removed again; one the checkout already had is left alone."""
        self._refused_renamed("renamed", tag_already_local=True)

    def _hostile_tagger(self, args):
        self.build(tag="hostile-tagger")
        self.services()
        rc, text = self.upgrade(args=args)
        self.assertIn(f"Release {TAG}: commit {self.sha_b}; tagged by Evil2J033", text)
        for bad in ("\x1b[2J", "\x1b[31mX", "\\033[31m"):
            self.assertNotIn(bad, text)
        return rc, text

    def test_hostile_tagger_is_not_echoed(self):
        """The tagger of the fetched, unverified tag reaches `echo -e` only after unsafe characters are dropped."""
        rc, text = self._hostile_tagger((TAG,))
        self.assertEqual(rc, 1, text)
        self.assert_refused_before_checkout(text, "UPGRADE_SIGNATURE_INVALID", "VERIFY")

    def test_hostile_tagger_is_not_echoed_with_trust_unsigned(self):
        rc, text = self._hostile_tagger((TAG, "--trust-unsigned"))
        self.assertEqual(rc, 0, text)

    def test_older_signed_release_under_a_newer_name_is_refused(self):
        """A correctly signed tag object made for v0.9.0, published as v0.9.1: the signature alone would pass."""
        self._refused_renamed("renamed")

    def test_decoy_tag_line_in_the_message_is_ignored(self):
        """The name comes from the object's header; a `tag v0.9.1` line in the (signed) message changes nothing."""
        self._refused_renamed("renamed-decoy")

    def test_trust_unsigned_does_not_skip_the_name_check(self):
        self._refused_renamed("renamed-unsigned", args=(TAG, "--trust-unsigned"))

    def test_unsigned_misnamed_tag_is_refused_by_name_first(self):
        self._refused_renamed("renamed-unsigned")

    def test_hostile_inner_name_is_not_printed(self):
        """A name that is not a release tag (here with terminal control characters) is never echoed."""
        text = self._refused_renamed("hostile-name", shown="a name that is not a release tag")
        self.assertNotIn("\x1b[2J", text)
        self.assertNotIn("\x1b[31mx", text)

    def test_correctly_named_signed_tag_still_upgrades(self):
        """Do No Harm: the annotated, signed tag named as requested runs every step as before."""
        self.build()
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertNotIn("UPGRADE_TAG_NAME_MISMATCH", text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply", "deploy-services.sh(B) --all-jobs",
                                        "gcloud run services list"])

    def test_no_trusted_keys_in_the_checkout_is_refused_before_fetch(self):
        """Before the owner commits the official release key, the file does not exist: a typed refusal, nothing
        fetched, and the one next command is the explicit --trust-unsigned run."""
        self.build(installed_signers=None, release_signers=None)
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_NO_TRUSTED_KEYS (stage PREFLIGHT)", text)
        self.assertIn("has no scripts/release/allowed_signers", text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} bash scripts/upgrade.sh {TAG} --trust-unsigned")
        self.assert_nothing_happened()

    def _trusted_unsigned(self, kind, signers, reason):
        self.build(tag=kind, installed_signers=signers, release_signers=signers)
        self.services()
        rc, text = self.upgrade(args=(TAG, "--trust-unsigned"))
        self.assertEqual(rc, 0, text)
        self.assertIn(f"\x1b[0;31m[WARNING] --trust-unsigned: {TAG} is NOT verified ({reason}).", text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply", "deploy-services.sh(B) --all-jobs",
                                        "gcloud run services list"])

    def test_trust_unsigned_continues_with_a_red_warning_lightweight(self):
        self._trusted_unsigned("lightweight", "release", "not signed by a key in scripts/release/allowed_signers")

    def test_trust_unsigned_continues_with_a_red_warning_other_key(self):
        self._trusted_unsigned("other-key", "release", "not signed by a key in scripts/release/allowed_signers")

    def test_trust_unsigned_continues_with_a_red_warning_no_keys(self):
        self._trusted_unsigned("annotated", None, "this checkout has no scripts/release/allowed_signers")

    def test_trust_unsigned_with_a_good_signature_has_no_warning(self):
        self.build()
        self.services()
        rc, text = self.upgrade(args=(TAG, "--trust-unsigned"))
        self.assertEqual(rc, 0, text)
        self.assertIn(f"Signature of {TAG}: good", text)
        self.assertNotIn("[WARNING]", text)

    def _old_tool(self, name, version_line, version_arg, real):
        """A stub on PATH that reports an old version for `<name> <version_arg>` and runs the real tool otherwise."""
        p = os.path.join(self.stub, name)
        with open(p, "w") as f:
            f.write(f'#!/bin/bash\nif [ "$1" = "{version_arg}" ]; then echo "{version_line}" >&2; '
                    f'echo "{version_line}"; exit 0; fi\nexec {real} "$@"\n')
        os.chmod(p, 0o755)

    def test_old_git_is_refused_before_the_fetch(self):
        self.build()
        self._old_tool("git", "git version 2.30.2", "--version", shutil.which("git"))
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_PREREQ_MISSING (stage PREFLIGHT): git 2.34 or newer is needed", text)
        self.assert_one_next_command(text, "git --version")
        self.assert_nothing_happened()

    def test_old_openssh_is_refused_before_the_fetch(self):
        self.build()
        self._old_tool("ssh", "OpenSSH_8.1p1, OpenSSL 1.1.1", "-V", shutil.which("ssh") or "/usr/bin/ssh")
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_PREREQ_MISSING (stage PREFLIGHT): OpenSSH 8.2 or newer is needed", text)
        self.assert_one_next_command(text, "ssh -V")
        self.assert_nothing_happened()

    def test_trust_unsigned_is_kept_in_the_rerun_command(self):
        self.build(tag="lightweight")
        rc, text = self.upgrade(args=(TAG, "--trust-unsigned"), STUB_APPLY_APPLY_RC=1)
        self.assertEqual(rc, 1, text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} bash scripts/upgrade.sh {TAG} --trust-unsigned")

    def test_ctrl_c_during_plan_says_nothing_applied(self):
        self.build()
        rc, text = self.upgrade(STUB_APPLY_PLAN_SIGINT=1)
        self.assertEqual(rc, 130, text)
        self.assertEqual(text.count("[ERROR]"), 1, text)
        self.assertIn("UPGRADE_INTERRUPTED (stage PLAN, SIGINT): Nothing was applied", text)
        self.assert_one_next_command(text, f"git -C {self.root} checkout main")
        self.assertEqual(self.steps(), ["apply.sh(B) plan"])

    def test_ctrl_c_during_apply_never_says_nothing_changed(self):
        self.build()
        rc, text = self.upgrade(STUB_APPLY_APPLY_SIGINT=1)
        self.assertEqual(rc, 130, text)
        self.assertEqual(text.count("[ERROR]"), 1, text)
        self.assertIn("UPGRADE_INTERRUPTED (stage APPLY, SIGINT): The platform Terraform may be partly applied", text)
        self.assertNotIn("Nothing was changed", text)
        self.assertNotIn("Nothing was applied", text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} bash scripts/upgrade.sh {TAG}")
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply"])

    def test_ctrl_c_at_the_confirm_prompt(self):
        """M1: SIGINT to the process group while `read` waits at the y/N prompt (real pty, /bin/bash)."""
        import pty
        import select
        import signal
        import time
        self.build()
        master, slave = pty.openpty()
        try:
            p = subprocess.Popen([L5.BASH, os.path.join(self.repo, "scripts", "upgrade.sh"), TAG], cwd=self.repo,
                                 env=self.env(PROJECT_ID=PROJ, STUB_SERVICES_JSON=self.services_json), stdin=slave,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            os.close(slave)
            slave = None
            err = b""
            deadline = time.time() + 60
            while b"(y/N)" not in err and time.time() < deadline:
                ready, _, _ = select.select([p.stderr], [], [], 1)
                if ready:
                    chunk = os.read(p.stderr.fileno(), 4096)
                    if not chunk:
                        break
                    err += chunk
            self.assertIn(b"(y/N)", err)
            time.sleep(0.3)
            os.killpg(p.pid, signal.SIGINT)
            out, rest = p.communicate(timeout=60)
            text = (out + err + rest).decode(errors="replace")
        finally:
            if slave is not None:
                os.close(slave)
            os.close(master)
        self.assertEqual(p.returncode, 130, text)
        self.assertEqual(text.count("[ERROR]"), 1, text)
        self.assertIn("UPGRADE_INTERRUPTED (stage CONFIRM, SIGINT): Nothing was applied; the checkout is at", text)
        self.assert_one_next_command(text, f"git -C {self.root} checkout main")
        self.assertEqual(self.steps(), ["apply.sh(B) plan"])

    def test_rerun_keeps_tfvars_file_and_remote(self):
        self.build()
        self.git(self.repo, "remote", "add", "upstream", "file://" + self.origin)
        tfv = os.path.join(self.platform, f"{PROJ}.tfvars")
        rc, text = self.upgrade(args=(TAG, "--remote=upstream"), TFVARS_FILE=tfv, STUB_APPLY_APPLY_RC=1)
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_APPLY_FAILED", text)
        self.assert_one_next_command(
            text, f"TFVARS_FILE={os.path.realpath(tfv)} bash scripts/upgrade.sh {TAG} --remote=upstream")
        line = [x for x in self.calls() if x.startswith("apply.sh(B) apply")][0]
        self.assertIn(f"tfvars_file={os.path.realpath(tfv)}", line)

    def test_guard_refusal_rerun_keeps_the_callers_target(self):
        self.build()
        tfv = os.path.join(self.platform, f"{PROJ}.tfvars")
        rc, text = self.upgrade(PROJECT_ID=L5.OTHER, TFVARS_FILE=tfv)
        self.assertEqual(rc, 1, text)
        self.assert_one_next_command(text, f"PROJECT_ID={L5.OTHER} TFVARS_FILE={tfv} bash scripts/upgrade.sh {TAG}")

    def test_stamp_check_fails_closed_when_the_release_vars_cannot_be_evaluated(self):
        self.build(broken_release_vars=True)
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_TFVARS_UNREADABLE (stage SMOKE)", text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} bash scripts/apply.sh plan")
        self.assertNotIn("[OK]", text)

    def test_unloadable_guard_library_is_a_typed_stop(self):
        self.build()
        with open(os.path.join(self.repo, "scripts", "common", "platform_target.sh"), "w") as f:
            f.write("return 1\n")
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_PREREQ_MISSING (stage ARGS): Cannot load", text)
        self.assert_one_next_command(text, f"git -C {self.root} status")
        self.assertEqual(self.steps(), [])

    def test_rerun_at_the_tag_is_idempotent(self):
        self.build(broken_release_script=False)  # the second run is the release's own upgrade.sh
        self.services()
        self.assertEqual(self.upgrade()[0], 0)
        open(self.log, "w").close()
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertIn(f"The checkout is already at {TAG}", text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply", "deploy-services.sh(B) --all-jobs",
                                        "gcloud run services list"])

    def test_release_without_stamp_needs_none_but_a_stale_one_must_match(self):
        self.build(stamp_in_release=False, broken_release_script=False)  # the second run is the release's own script
        self.services()
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertNotIn("platform stamp matches", text)
        open(self.log, "w").close()
        self.services(stamp="b" * 40)
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("SMOKE_STAMP_MISMATCH", text)

    def test_release_stamp_naming_another_commit_fails(self):
        self.build(broken_release_script=False)
        self.services(stamp=self.sha_a)
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn(f"SMOKE_STAMP_MISMATCH: product-control-center-ui stackvend/platform-commit={self.sha_a}, "
                      f"expected {self.sha_b}", text)
        self.assertIn("UPGRADE_SMOKE_FAILED (stage SMOKE)", text)

    def test_release_with_stamp_requires_the_stamp_to_name_the_commit(self):
        self.build(stamp_in_release=True, broken_release_script=False)
        self.services(stamp=None)
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("SMOKE_STAMP_MISSING", text)
        self.assertIn("UPGRADE_SMOKE_FAILED (stage SMOKE)", text)
        open(self.log, "w").close()
        self.services(stamp=self.sha_b)
        rc, text = self.upgrade()
        self.assertEqual(rc, 0, text)
        self.assertIn("platform stamp matches", text)

    # -- refusals before anything changes ---------------------------------------------------------------------------
    def test_dirty_tree_refused_before_fetch(self):
        self.build()
        self.write("notes.txt", "local edit\n")
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_DIRTY_TREE (stage PREFLIGHT)", text)
        self.assertIn("?? notes.txt", text)
        self.assert_one_next_command(text, f"git -C {self.root} status")
        self.assert_nothing_happened()

    def test_modified_tracked_file_refused(self):
        self.build()
        with open(os.path.join(self.repo, "scripts", "apply.sh"), "a") as f:
            f.write("# local change\n")
        rc, text = self.upgrade()
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_DIRTY_TREE", text)
        self.assert_nothing_happened()

    def test_mismatched_project_and_vars_file_refused(self):
        self.build()
        rc, text = self.upgrade(PROJECT_ID=L5.OTHER,
                                TFVARS_FILE=os.path.join(self.platform, f"{PROJ}.tfvars"))
        self.assertEqual(rc, 1, text)
        self.assertIn("Refusing to mix installs", text)
        self.assertIn("UPGRADE_GUARD_REFUSED (stage PREFLIGHT)", text)
        self.assertEqual(text.count("Next command:"), 1, text)  # the command itself: test_guard_refusal_rerun_...
        self.assert_nothing_happened()

    def test_vars_file_of_another_install_refused(self):
        self.build()
        self.write(os.path.join("infra", "platform", f"{L5.OTHER}.tfvars"), L5._tfvars(project=PROJ))
        rc, text = self.upgrade(PROJECT_ID=L5.OTHER)
        self.assertEqual(rc, 1, text)
        self.assertIn("Refusing to mix installs", text)
        self.assert_nothing_happened()

    def test_region_mismatch_refused(self):
        self.build()
        rc, text = self.upgrade(PROJECT_ID=PROJ, REGION="europe-west1")
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_REGION_MISMATCH (stage PREFLIGHT)", text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} bash scripts/upgrade.sh {TAG}")
        self.assert_nothing_happened()

    def test_no_explicit_target_refused_even_with_gcloud_config(self):
        self.build()
        rc, text = self.upgrade(no_target=True, STUB_GCLOUD_CONFIG_PROJECT=PROJ)
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_NO_TARGET", text)
        self.assert_one_next_command(text, f"PROJECT_ID=<project_id> bash scripts/upgrade.sh {TAG}")
        self.assert_nothing_happened()

    def test_invalid_tags_and_flags_refused(self):
        self.build()
        for args, cls in (((), "UPGRADE_USAGE"), (("main",), "UPGRADE_TAG_INVALID"), (("v1.2",), "UPGRADE_TAG_INVALID"),
                          (("v1.2.3+build",), "UPGRADE_TAG_INVALID"), (("v01.2.3",), "UPGRADE_TAG_INVALID"),
                          ((TAG, "v0.9.2"), "UPGRADE_USAGE"), ((TAG, "--yes"), "UPGRADE_USAGE"),
                          ((TAG, "--remote=-x"), "UPGRADE_USAGE")):
            rc, text = self.upgrade(args=args, PROJECT_ID=PROJ)
            self.assertEqual(rc, 1, (args, text))
            self.assertIn(f"{cls} (stage ARGS)", text)
            self.assertEqual(text.count("Next command:"), 1, text)
        self.assert_nothing_happened()

    def test_unknown_remote_refused(self):
        self.build()
        rc, text = self.upgrade(args=(TAG, "--remote=upstream"), PROJECT_ID=PROJ)
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_REMOTE_MISSING", text)
        self.assert_nothing_happened()

    # -- fetch -----------------------------------------------------------------------------------------------------
    def test_missing_tag_on_remote(self):
        self.build()
        rc, text = self.upgrade(args=("v9.9.9",), PROJECT_ID=PROJ)
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_FETCH_FAILED (stage FETCH)", text)
        self.assert_one_next_command(text, f"git -C {self.root} ls-remote --tags origin v9.9.9")
        self.assert_nothing_happened()

    def test_local_tag_pointing_elsewhere_is_never_moved(self):
        self.build()
        self.git(self.repo, "tag", TAG, self.sha_a)
        rc, text = self.upgrade(PROJECT_ID=PROJ)
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_FETCH_FAILED", text)
        self.assertEqual(self.git(self.repo, "rev-parse", f"{TAG}^{{commit}}"), self.sha_a)
        self.assertEqual(self.steps(), [])
        self.assertEqual(self.head(), self.sha_a)

    # -- stops after the checkout ----------------------------------------------------------------------------------
    def test_declined_confirmation_applies_nothing(self):
        self.build()
        rc, text = self.upgrade(tty="n", PROJECT_ID=PROJ)
        self.assertEqual(rc, 1, text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan"])
        self.assertIn("UPGRADE_DECLINED (stage CONFIRM)", text)
        self.assert_one_next_command(text, f"git -C {self.root} checkout main")

    def test_no_terminal_applies_nothing(self):
        self.build()
        rc, out, err = self.run_script("upgrade.sh", [TAG], PROJECT_ID=PROJ)
        text = out + err
        self.assertEqual(rc, 1, text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan"])
        self.assertIn("UPGRADE_NEEDS_TERMINAL (stage CONFIRM)", text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} bash scripts/upgrade.sh {TAG}")

    def test_plan_failure_stops(self):
        self.build()
        rc, text = self.upgrade(PROJECT_ID=PROJ, STUB_APPLY_PLAN_RC=1)
        self.assertEqual(rc, 1, text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan"])
        self.assertIn("UPGRADE_PLAN_FAILED (stage PLAN)", text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} bash scripts/upgrade.sh {TAG}")

    def test_apply_failure_stops_before_deploy(self):
        self.build()
        rc, text = self.upgrade(PROJECT_ID=PROJ, STUB_APPLY_APPLY_RC=1)
        self.assertEqual(rc, 1, text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply"])
        self.assertIn("UPGRADE_APPLY_FAILED (stage APPLY)", text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} bash scripts/upgrade.sh {TAG}")

    def test_allow_destroy_is_passed_to_apply_only(self):
        self.build()
        self.services()
        rc, text = self.upgrade(args=(TAG, f"--allow-destroy={PROJ}"), PROJECT_ID=PROJ)
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.steps()[:2], ["apply.sh(B) plan", f"apply.sh(B) apply --allow-destroy={PROJ}"])

    def test_deploy_failure_names_the_deploy_command(self):
        self.build()
        rc, text = self.upgrade(PROJECT_ID=PROJ, STUB_DEPLOY_RC=1)
        self.assertEqual(rc, 1, text)
        self.assertEqual(self.steps(), ["apply.sh(B) plan", "apply.sh(B) apply", "deploy-services.sh(B) --all-jobs"])
        self.assertIn("UPGRADE_DEPLOY_FAILED (stage DEPLOY)", text)
        self.assert_one_next_command(text, f"PROJECT_ID={PROJ} REGION=us-central1 bash scripts/deploy-services.sh --all-jobs")

    def test_smoke_failure_is_loud(self):
        self.build()
        self.services(ready="False")
        rc, text = self.upgrade(PROJECT_ID=PROJ)
        self.assertEqual(rc, 1, text)
        self.assertIn("SMOKE_SERVICE_NOT_READY: product-control-center-ui (Ready=False)", text)
        self.assertIn("UPGRADE_SMOKE_FAILED (stage SMOKE)", text)
        self.assert_one_next_command(text, f"gcloud run services list --project={PROJ} --region=us-central1")

    def test_smoke_unreadable_is_loud(self):
        self.build()
        rc, text = self.upgrade(PROJECT_ID=PROJ, STUB_SERVICES_JSON="")
        self.assertEqual(rc, 1, text)
        self.assertIn("UPGRADE_SMOKE_UNREADABLE (stage SMOKE)", text)


# ==============================================================================
# bootstrap.sh: "weekly auto-update from upstream" (default No)
# ==============================================================================
GH_STUB = '#!/bin/bash\necho "gh $*" >> "$STUB_LOG"\nexit "${STUB_GH_RC:-0}"\n'
QUESTION = "Turn on weekly auto-update from upstream? (y/N): "
OFFICIAL = "asaslaw/stackvend"
BOOTSTRAP = os.path.join(REPO, "scripts", "bootstrap.sh")


if __name__ == "__main__":
    unittest.main()

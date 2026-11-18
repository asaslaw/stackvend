"""INSTALLER-OPENTOFU-OFFER (owner 11-10): the installer offers to install OpenTofu into ~/bin when it is missing or
older than SV_IAC_MIN_VERSION (scripts/common/opentofu_offer.sh, used by pre-bootstrap.sh, bootstrap.sh, apply.sh).

The helper runs with /bin/bash (macOS: bash 3.2), a fake HOME and TMPDIR, and stubs on PATH: `uname` (the
platform), `curl` (copies a local zip, logs the URL; no network), `tofu` / `terraform` when a case needs one. The
success path needs a zip whose SHA-256 matches the pin, so its driver replaces sv_tofu_pinned_sha256 with the fake
zip's hash (a test-only function override; the real pins are checked against the release checksum file below).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER = os.path.join(REPO, "scripts", "common", "opentofu_offer.sh")
BASH = "/bin/bash"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
PROMPT = "Install OpenTofu 1.13.1 into ~/bin now? [y/N]"

# Copied from https://github.com/opentofu/opentofu/releases/download/v1.13.1/tofu_1.13.1_SHA256SUMS (11-10).
RELEASE_SUMS = {
    "linux_amd64": "8ccbc6f8ee21d2827715f3c6e08a9b3e0209b1e62057c05067ef117e047c1a80",
    "linux_arm64": "b9614df40575cc3fc10a8a25025b7245d961da279f715ea3efff4ddae8e6938a",
    "darwin_amd64": "d44ab59ec53fb18e900f4ae3fc8b72e042c9e03ca957860edbaac04e4427218d",
    "darwin_arm64": "81aebe6453223bcb3ce3c28424b36d009ebfddd3ad65ad1ec3eed0d0d574a77b",
}

DRIVER = r'''
set -euo pipefail
. scripts/common/platform_target.sh
. scripts/common/opentofu_offer.sh
if [ -n "${FAKE_PIN:-}" ]; then
    sv_tofu_pinned_sha256() { case "$1" in linux_amd64|darwin_arm64) echo "${FAKE_PIN}" ;; *) return 1 ;; esac; }
fi
sv_ensure_opentofu TEST "$1"
echo "ENSURE-OK engine=$(command -v tofu || echo none)"
'''

FAKE_UNAME = r'''#!/bin/sh
case "$1" in
  -s) echo "${FAKE_UNAME_S:-Linux}" ;;
  -m) echo "${FAKE_UNAME_M:-x86_64}" ;;
  *) echo "${FAKE_UNAME_S:-Linux}" ;;
esac
'''

FAKE_CURL = r'''#!/bin/sh
echo "curl $*" >> "$STUB_LOG"
[ -n "${FAKE_CURL_FAIL:-}" ] && exit 22
out=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
cp "$FAKE_ZIP" "$out"
'''


def engine_stub(product, semver):
    """A `tofu`/`terraform` stub: `version` banner + `version -json` (the fields the scripts read)."""
    return (f'#!/bin/sh\nif [ "$1" = "version" ] && [ "${{2:-}}" = "-json" ]; then '
            f'echo \'{{"terraform_version": "{semver}"}}\'; exit 0; fi\n'
            f'if [ "$1" = "version" ]; then echo "{product} v{semver}"; exit 0; fi\nexit 2\n')


def fake_release_zip():
    """A release-shaped zip: the `tofu` binary (a stub reporting 1.13.1) plus files that must NOT be extracted."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("tofu")
        info.external_attr = 0o755 << 16
        z.writestr(info, engine_stub("OpenTofu", "1.13.1"))
        z.writestr("LICENSE", "license text\n")
        z.writestr("README.md", "readme\n")
    return buf.getvalue()


class _Offer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tofu-offer-")
        self.stub = os.path.join(self.tmp, "stubbin")
        self.home = os.path.join(self.tmp, "home")
        self.tmpdir = os.path.join(self.tmp, "tmpdir")
        for d in (self.stub, self.home, self.tmpdir):
            os.makedirs(d)
        self.write_stub("uname", FAKE_UNAME)
        self.write_stub("curl", FAKE_CURL)
        os.symlink(sys.executable, os.path.join(self.stub, "python3"))
        if not shutil.which("sha256sum", path="/usr/bin:/bin:/usr/sbin:/sbin"):
            # A host without coreutils' sha256sum (macOS < 15): same digest via shasum.
            self.write_stub("sha256sum", '#!/bin/sh\nexec shasum -a 256 "$@"\n')
        self.log = os.path.join(self.tmp, "calls.log")
        open(self.log, "w").close()
        self.zip = os.path.join(self.tmp, "release.zip")
        with open(self.zip, "wb") as f:
            f.write(fake_release_zip())
        with open(self.zip, "rb") as f:
            self.zip_sha = hashlib.sha256(f.read()).hexdigest()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_stub(self, name, body):
        p = os.path.join(self.stub, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)

    def env(self, **over):
        e = {
            "PATH": f"{self.stub}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": self.home,
            "TMPDIR": self.tmpdir,
            "STUB_LOG": self.log,
            "FAKE_ZIP": self.zip,
            "LANG": "C",
        }
        e.update({k: str(v) for k, v in over.items()})
        return hermetic_guard.hermetic_env(e)

    def run_helper(self, interactive, answer="", **env):
        r = subprocess.run([BASH, "-c", DRIVER, "driver", "1" if interactive else ""], cwd=REPO,
                           env=self.env(**env), input=answer + "\n", capture_output=True, text=True, timeout=60)
        return r.returncode, ANSI.sub("", r.stdout), ANSI.sub("", r.stderr)

    def curl_calls(self):
        with open(self.log) as f:
            return [line.strip() for line in f if line.startswith("curl ")]

    def installed(self):
        return os.path.exists(os.path.join(self.home, "bin", "tofu"))

    def assert_temp_clean(self):
        self.assertEqual(os.listdir(self.tmpdir), [])


class TestNoHarm(_Offer):
    def test_usable_opentofu_no_prompt_no_output_no_change(self):
        self.write_stub("tofu", engine_stub("OpenTofu", "1.13.1"))
        rc, out, err = self.run_helper(True, "y")
        self.assertEqual(rc, 0, err)
        self.assertEqual(err, "")
        self.assertEqual(out.strip(), f"ENSURE-OK engine={self.stub}/tofu")
        self.assertEqual(self.curl_calls(), [])
        self.assertEqual(os.listdir(self.home), [])
        self.assert_temp_clean()

    def test_minimum_version_is_usable(self):
        self.write_stub("tofu", engine_stub("OpenTofu", "1.10.0"))
        rc, out, err = self.run_helper(False)
        self.assertEqual((rc, err), (0, ""))

    def test_usable_fallback_engine_is_left_alone(self):
        # The existing detection keeps its fallback (FD-0C); the helper never offers when that engine is usable.
        self.write_stub("terraform", engine_stub("Terraform", "1.10.5"))
        rc, out, err = self.run_helper(False)
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(self.curl_calls(), [])

    def test_unreadable_version_is_left_to_the_existing_check(self):
        self.write_stub("tofu", '#!/bin/sh\n[ "$1" = version ] && [ -z "${2:-}" ] && echo "OpenTofu v1.13.1"\n'
                                'echo garbage\n')
        rc, out, err = self.run_helper(False)
        self.assertEqual((rc, err), (0, ""))


class TestDeclinedOrNotATerminal(_Offer):
    def test_missing_and_no_stops_typed_with_manual_commands(self):
        rc, out, err = self.run_helper(True, "n")
        self.assertEqual(rc, 1)
        self.assertIn(PROMPT, err)
        self.assertIn("TEST_OPENTOFU_DECLINED: OpenTofu ('tofu') is not installed or not on PATH.", err)
        url = "https://github.com/opentofu/opentofu/releases/download/v1.13.1/tofu_1.13.1_linux_amd64.zip"
        self.assertIn(f"curl -fLO {url}", err)
        self.assertIn(f'echo "{RELEASE_SUMS["linux_amd64"]}  tofu_1.13.1_linux_amd64.zip" | sha256sum -c -', err)
        self.assertIn('export PATH="$HOME/bin:$PATH"', err)
        self.assertNotIn("ENSURE-OK", out)
        self.assertEqual(self.curl_calls(), [])
        self.assertEqual(os.listdir(self.home), [])

    def test_default_answer_is_no(self):
        rc, out, err = self.run_helper(True, "")
        self.assertEqual(rc, 1)
        self.assertIn("TEST_OPENTOFU_DECLINED", err)
        self.assertFalse(self.installed())

    def test_too_old_and_no_stops_typed(self):
        self.write_stub("tofu", engine_stub("OpenTofu", "1.9.0"))
        rc, out, err = self.run_helper(True, "n")
        self.assertEqual(rc, 1)
        self.assertIn("TEST_OPENTOFU_DECLINED: tofu 1.9.0 is too old for infra/platform: it needs 1.10.0 or later.", err)
        self.assertEqual(self.curl_calls(), [])

    def test_old_fallback_engine_gets_the_offer_not_the_fallback(self):
        self.write_stub("terraform", engine_stub("Terraform", "1.5.7"))
        rc, out, err = self.run_helper(True, "n")
        self.assertEqual(rc, 1)
        self.assertIn("terraform 1.5.7 is too old for infra/platform", err)
        self.assertIn("OpenTofu", err)

    def test_not_a_terminal_never_prompts(self):
        rc, out, err = self.run_helper(False, "y")
        self.assertEqual(rc, 1)
        self.assertNotIn(PROMPT, err)
        self.assertIn("TEST_OPENTOFU_MISSING:", err)
        self.assertIn("Not a terminal, so the installer did not offer to install it.", err)
        self.assertIn("sha256sum -c -", err)
        self.assertEqual(self.curl_calls(), [])
        self.assertFalse(self.installed())

    def test_not_a_terminal_too_old_keeps_the_version_message(self):
        self.write_stub("tofu", engine_stub("OpenTofu", "1.9.0"))
        rc, out, err = self.run_helper(False)
        self.assertEqual(rc, 1)
        self.assertIn("TEST_OPENTOFU_TOO_OLD: tofu 1.9.0 is too old for infra/platform: it needs 1.10.0 or later.", err)

    def test_macos_manual_commands_use_shasum(self):
        rc, out, err = self.run_helper(False, FAKE_UNAME_S="Darwin", FAKE_UNAME_M="arm64")
        self.assertEqual(rc, 1)
        self.assertIn(f'echo "{RELEASE_SUMS["darwin_arm64"]}  tofu_1.13.1_darwin_arm64.zip" | shasum -a 256 -c -', err)

    def test_never_suggests_hashicorp_terraform(self):
        for answer, interactive in (("n", True), ("", False)):
            with self.subTest(interactive=interactive):
                rc, out, err = self.run_helper(interactive, answer)
                self.assertNotIn("terraform", err.lower())
                self.assertNotIn("hashicorp", err.lower())


class TestInstall(_Offer):
    def test_missing_and_yes_downloads_verifies_installs(self):
        rc, out, err = self.run_helper(True, "y", FAKE_PIN=self.zip_sha)
        self.assertEqual(rc, 0, err)
        self.assertIn(PROMPT, err)
        self.assertEqual(len(self.curl_calls()), 1)
        self.assertIn("https://github.com/opentofu/opentofu/releases/download/v1.13.1/tofu_1.13.1_linux_amd64.zip",
                      self.curl_calls()[0])
        binp = os.path.join(self.home, "bin", "tofu")
        self.assertEqual(os.listdir(os.path.join(self.home, "bin")), ["tofu"])   # only the binary
        self.assertTrue(os.stat(binp).st_mode & stat.S_IXUSR)
        self.assertIn(f"ENSURE-OK engine={binp}", out)                            # ~/bin first on PATH
        self.assertIn("Installed OpenTofu 1.13.1 to ~/bin/tofu", err)
        self.assertIn('In new shells, run: export PATH="$HOME/bin:$PATH"', err)
        self.assertIn("[OK] OpenTofu v1.13.1", err)
        self.assertEqual(sorted(os.listdir(self.home)), ["bin"])                  # nothing else written
        self.assert_temp_clean()

    def test_too_old_and_yes_shadows_the_old_engine(self):
        self.write_stub("tofu", engine_stub("OpenTofu", "1.9.0"))
        rc, out, err = self.run_helper(True, "yes", FAKE_PIN=self.zip_sha)
        self.assertEqual(rc, 0, err)
        self.assertIn(f"ENSURE-OK engine={os.path.join(self.home, 'bin', 'tofu')}", out)

    def test_macos_uses_shasum_and_installs(self):
        if not shutil.which("shasum", path="/usr/bin:/bin"):
            self.skipTest("no shasum on this host")
        rc, out, err = self.run_helper(True, "y", FAKE_PIN=self.zip_sha, FAKE_UNAME_S="Darwin", FAKE_UNAME_M="arm64")
        self.assertEqual(rc, 0, err)
        self.assertIn("tofu_1.13.1_darwin_arm64.zip", self.curl_calls()[0])
        self.assertTrue(self.installed())

    def test_hash_mismatch_refused_nothing_installed(self):
        # Real pins vs a zip that is not the release: fail closed.
        rc, out, err = self.run_helper(True, "y")
        self.assertEqual(rc, 1)
        self.assertIn(f"TEST_OPENTOFU_CHECKSUM_MISMATCH: tofu_1.13.1_linux_amd64.zip has SHA-256 '{self.zip_sha}'", err)
        self.assertIn(RELEASE_SUMS["linux_amd64"], err)
        self.assertIn("The download was deleted and nothing was installed.", err)
        self.assertFalse(os.path.exists(os.path.join(self.home, "bin")))
        self.assert_temp_clean()

    def test_unknown_platform_refused_before_download(self):
        for s, m in (("Linux", "s390x"), ("FreeBSD", "x86_64"), ("Linux", "armv7l")):
            with self.subTest(os=s, arch=m):
                rc, out, err = self.run_helper(True, "y", FAKE_PIN=self.zip_sha, FAKE_UNAME_S=s, FAKE_UNAME_M=m)
                self.assertEqual(rc, 1)
                self.assertIn("TEST_OPENTOFU_UNSUPPORTED_PLATFORM", err)
                self.assertEqual(self.curl_calls(), [])
                self.assertFalse(self.installed())
                self.assert_temp_clean()

    def test_download_failure_typed_and_cleaned_up(self):
        rc, out, err = self.run_helper(True, "y", FAKE_PIN=self.zip_sha, FAKE_CURL_FAIL=1)
        self.assertEqual(rc, 1)
        self.assertIn("TEST_OPENTOFU_DOWNLOAD_FAILED", err)
        self.assertFalse(self.installed())
        self.assert_temp_clean()

    def test_zip_without_tofu_refused(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../tofu", "escape attempt")
        with open(self.zip, "wb") as f:
            f.write(buf.getvalue())
        sha = hashlib.sha256(buf.getvalue()).hexdigest()
        rc, out, err = self.run_helper(True, "y", FAKE_PIN=sha)
        self.assertEqual(rc, 1)
        self.assertIn("TEST_OPENTOFU_EXTRACT_FAILED", err)
        self.assertFalse(os.path.exists(os.path.join(self.home, "bin")))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "tofu")))
        self.assert_temp_clean()


class TestPinsAndWiring(unittest.TestCase):
    def setUp(self):
        with open(HELPER) as f:
            self.src = f.read()

    def test_pins_match_the_release_checksum_file(self):
        self.assertIn("https://github.com/opentofu/opentofu/releases/download/v1.13.1/tofu_1.13.1_SHA256SUMS",
                      self.src)
        self.assertIn('SV_TOFU_OFFER_VERSION="1.13.1"', self.src)
        for plat, digest in RELEASE_SUMS.items():
            self.assertRegex(self.src, rf'{plat}\)\s+echo "{digest}"')

    def test_no_privileged_or_piped_install(self):
        code = "\n".join(l for l in self.src.splitlines() if not l.lstrip().startswith("#"))
        for bad in ("sudo", "apt", "brew ", "| sh", "|sh", "| bash", "hashicorp"):
            self.assertNotIn(bad, code)

    def test_scripts_source_and_call_the_helper(self):
        for script, prefix in (("pre-bootstrap.sh", "PREBOOT"), ("bootstrap.sh", "BOOTSTRAP"), ("apply.sh", "APPLY")):
            with self.subTest(script=script):
                with open(os.path.join(REPO, "scripts", script)) as f:
                    src = f.read()
                self.assertIn('. "${SCRIPT_DIR}/common/opentofu_offer.sh"', src)
                self.assertIn(f"sv_ensure_opentofu {prefix} ", src)

    def test_bootstrap_offers_before_its_engine_detection(self):
        with open(os.path.join(REPO, "scripts", "bootstrap.sh")) as f:
            src = f.read()
        self.assertLess(src.index("sv_ensure_opentofu BOOTSTRAP"), src.index('IAC_BIN="tofu"'))

    def test_apply_scrubs_env_then_offers_then_detects(self):
        with open(os.path.join(REPO, "scripts", "apply.sh")) as f:
            src = f.read()
        order = [src.index("\nsv_scrub_tofu_env"), src.index("\nsv_ensure_opentofu APPLY"),
                 src.index("\nsv_detect_iac_bin"), src.index("\nsv_require_iac_version")]
        self.assertEqual(order, sorted(order))


class TestApplyScript(_Offer):
    """apply.sh with no engine and no terminal: typed stop before any other work (no gcloud stub is even needed)."""

    def test_apply_without_opentofu_stops_typed(self):
        r = subprocess.run([BASH, os.path.join(REPO, "scripts", "apply.sh"), "plan"], cwd=REPO,
                           env=self.env(PROJECT_ID="example-host"), stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=60)
        err = ANSI.sub("", r.stderr)
        self.assertEqual(r.returncode, 1, err)
        self.assertIn("APPLY_OPENTOFU_MISSING: OpenTofu ('tofu') is not installed or not on PATH.", err)
        self.assertEqual(self.curl_calls(), [])
        self.assertEqual(os.listdir(self.home), [])


if __name__ == "__main__":
    unittest.main()

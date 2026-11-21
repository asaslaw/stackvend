import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""FD-148: the "Update StackVend" Cloud Build must fit Cloud Build's fixed build limits.

Found live (FD-148 rehearsal): approving the upgrade build failed with "invalid .steps.env field: build step 0 env string
too long (max: 65536)". step0-unpack carried guard.py as plain base64 (54,162 bytes -> 72,216 characters). The fix
embeds guard.py and verify.sh as gzip + base64 (Terraform base64gzip) and gunzips them in the unpack script; the
SHA-256 checks still run on the decompressed files.

Checks (hermetic: repository files only; bash/tofu children run with hermetic_guard.child_env, no network):
1. Every env string of the trigger's steps, evaluated from infra/platform/platform_upgrader.tf as Terraform would produce
   it (base64encode / base64gzip of the repository files; gzip bounded by levels 1, 6 and 9, plus OpenTofu's exact
   output when OpenTofu is installed) stays under 60,000 characters (limit 65,536). Fails on the old base64encode.
2. The other fixed limits: <= 100 env values and <= 100 args per step, each arg <= 10,000 characters, <= 300 steps.
3. The unpack script gunzips each gzipped variable, still checks every SHA-256, and runs end to end in bash on the real
   files (paths moved to a temp dir).
4. BUILD_ID: step0-verify passes Cloud Build's $BUILD_ID (guard.py records it; the Control Center links the build).
Cloud Build limits: https://cloud.google.com/build/quotas (Resource limits).
"""
import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import hcl2

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
UPGRADER_TF = os.path.join(PLATFORM, "platform_upgrader.tf")
TOFU = shutil.which("tofu")
BASH = shutil.which("bash")

# Cloud Build resource limits (fixed): https://cloud.google.com/build/quotas
ENV_VALUE_MAX = 65536
ENV_VALUES_PER_STEP_MAX = 100
ARGS_PER_STEP_MAX = 100
ARG_LENGTH_MAX = 10000
STEPS_PER_BUILD_MAX = 300
ENV_HEADROOM = 60000          # fail well before the hard limit, so a growing guard.py is caught in review

# The locals the step env reads, mapped to the repository files they come from (platform_upgrader.tf locals).
LOCAL_FILES = {
    "local.platform_upgrade_step0_verify_sh": os.path.join(PLATFORM, "upgrade_step0", "verify.sh"),
    "local.platform_upgrade_step0_guard_py": os.path.join(PLATFORM, "upgrade_step0", "guard.py"),
    "local.platform_upgrade_allowed_signers": os.path.join(REPO, "scripts", "release", "allowed_signers"),
}
ENV_EXPR = re.compile(r"^([A-Z_][A-Z0-9_]*)=\$\{(base64encode|base64gzip)\((local\.[a-z0-9_]+)\)\}$")
SHA_EXPR = re.compile(r"\$\{sha256\((local\.[a-z0-9_]+)\)\}")


def _read_bytes(p):
    with open(p, "rb") as f:
        return f.read()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _trigger_build():
    with open(UPGRADER_TF) as f:
        doc = hcl2.load(f)
    for res in doc.get("resource", []):
        trig = res.get("google_cloudbuild_trigger", {}).get("platform_upgrade")
        if trig:
            return trig["build"][0]
    raise AssertionError("google_cloudbuild_trigger.platform_upgrade not found")


def _steps():
    return {s["id"]: s for s in _trigger_build()["step"]}


def _gzip_upper_bound_b64_len(data):
    """Longest base64 of a gzip stream of ``data`` over levels 1, 6 (Go's default) and 9; mtime 0, no file name."""
    return max(len(base64.b64encode(gzip.compress(data, compresslevel=lvl, mtime=0))) for lvl in (1, 6, 9))


def _encoded_lengths(fn, data):
    """Every length the env value can have: exact for base64encode; for base64gzip the gzip-level bounds."""
    if fn == "base64encode":
        return [len(base64.b64encode(data))]
    return [_gzip_upper_bound_b64_len(data)]


def _env_entries(step):
    """(name, function or None, local or None, literal value) per env string of ``step``."""
    out = []
    for e in step.get("env", []):
        m = ENV_EXPR.match(e)
        if m:
            out.append((m.group(1), m.group(2), m.group(3), None))
        else:
            # Only literal values (Cloud Build substitutions such as $BUILD_ID) besides the embedded files.
            if "${" in e:
                raise AssertionError(f"unrecognised Terraform expression in a step env (extend this test): {e}")
            out.append((e.split("=", 1)[0], None, None, e))
    return out


def _unpack_script_lines():
    """The unpack script exactly as Terraform renders it: the join() list, HCL-unescaped, sha256() resolved."""
    locs = _strip_comments(open(UPGRADER_TF).read())
    start = locs.index("platform_upgrade_unpack_script = join(")
    depth, end = 0, None
    for i in range(locs.index("(", start), len(locs)):
        if locs[i] == "(":
            depth += 1
        elif locs[i] == ")":
            depth -= 1
            if depth == 0:
                end = i
                break
    blk = locs[start:end + 1]
    items = re.findall(r'^\s*"((?:[^"\\]|\\.)*)",\s*$', blk, re.M)
    lines = [json.loads('"%s"' % s) for s in items]   # HCL string escapes used here are JSON-compatible
    resolved = []
    for ln in lines:
        def sub(m):
            return hashlib.sha256(_read_bytes(LOCAL_FILES[m.group(1)])).hexdigest()
        resolved.append(SHA_EXPR.sub(sub, ln))
    return lines, resolved


def _env_values_python():
    """{name: value} for step0-unpack, gzip from Python (level 6, mtime 0)."""
    vals = {}
    for name, fn, local, _ in _env_entries(_steps()["step0-unpack"]):
        data = _read_bytes(LOCAL_FILES[local])
        enc = gzip.compress(data, compresslevel=6, mtime=0) if fn == "base64gzip" else data
        vals[name] = base64.b64encode(enc).decode("ascii")
    return vals


def _tofu_eval(expr, workdir):
    res = subprocess.run([TOFU, "console"], input=expr + "\n", capture_output=True, text=True, timeout=60,
                         cwd=workdir, env=hermetic_guard.child_env(extra={"TF_IN_AUTOMATION": "1"}))
    if res.returncode != 0:
        raise AssertionError(f"tofu console failed: {res.stderr}")
    return json.loads(res.stdout.strip())


# ==============================================================================================================
# 1. env string sizes
# ==============================================================================================================
class TestEnvStringSizes(unittest.TestCase):
    def test_every_step_env_string_is_under_the_cloud_build_limit(self):
        steps = _steps()
        self.assertIn("step0-unpack", steps)
        checked = 0
        for sid, step in steps.items():
            for name, fn, local, literal in _env_entries(step):
                if literal is not None:
                    # Cloud Build substitutes $BUILD_ID (a 36-character UUID) and the like: bound it generously.
                    lengths = [len(literal) + 64]
                else:
                    self.assertIn(local, LOCAL_FILES, f"{sid} {name}: unknown local {local}")
                    lengths = [len(name) + 1 + n for n in _encoded_lengths(fn, _read_bytes(LOCAL_FILES[local]))]
                for n in lengths:
                    self.assertLess(n, ENV_VALUE_MAX, f"{sid} env {name}: {n} characters >= Cloud Build's {ENV_VALUE_MAX}")
                    self.assertLess(n, ENV_HEADROOM, f"{sid} env {name}: {n} characters, too close to {ENV_VALUE_MAX}")
                checked += 1
        self.assertGreaterEqual(checked, 3)

    def test_the_two_scripts_are_gzipped(self):
        fns = {name: fn for name, fn, _, _ in _env_entries(_steps()["step0-unpack"])}
        self.assertEqual(fns, {
            "STACKVEND_STEP0_VERIFY_SH_GZ_B64": "base64gzip",
            "STACKVEND_STEP0_GUARD_PY_GZ_B64": "base64gzip",
            "STACKVEND_OFFICIAL_ALLOWED_SIGNERS_B64": "base64encode",
        })

    @unittest.skipUnless(TOFU, "OpenTofu not installed")
    def test_opentofu_base64gzip_exact_lengths_and_round_trip(self):
        # Exact: OpenTofu's own base64gzip (Go compress/gzip) in an empty directory (no config, no providers, no network).
        with tempfile.TemporaryDirectory() as d:
            for name, fn, local, _ in _env_entries(_steps()["step0-unpack"]):
                path = LOCAL_FILES[local]
                val = _tofu_eval('%s(file("%s"))' % (fn, path), d)
                self.assertLess(len(name) + 1 + len(val), ENV_HEADROOM, name)
                raw = base64.b64decode(val)
                if fn == "base64gzip":
                    raw = gzip.decompress(raw)
                self.assertEqual(raw, _read_bytes(path), name)


# ==============================================================================================================
# 2. other fixed limits
# ==============================================================================================================
class TestOtherBuildLimits(unittest.TestCase):
    def test_counts_and_arg_lengths(self):
        build = _trigger_build()
        self.assertLessEqual(len(build["step"]), STEPS_PER_BUILD_MAX)
        _, script = _unpack_script_lines()
        rendered_script = "\n".join(script)
        for step in build["step"]:
            self.assertLessEqual(len(step.get("env", [])), ENV_VALUES_PER_STEP_MAX)
            self.assertLessEqual(len(step.get("args", [])), ARGS_PER_STEP_MAX)
            for a in step.get("args", []):
                text = rendered_script if a == "${local.platform_upgrade_unpack_script}" else a
                self.assertLessEqual(len(text), ARG_LENGTH_MAX, f"{step['id']}: arg of {len(text)} characters")


# ==============================================================================================================
# 3. unpack script: gunzip + SHA-256, end to end
# ==============================================================================================================
class TestUnpackScript(unittest.TestCase):
    def test_static_gunzip_then_sha256_for_every_file(self):
        lines, _ = _unpack_script_lines()
        self.assertEqual(lines[0], "set -euo pipefail")
        gz = {name for name, fn, _, _ in _env_entries(_steps()["step0-unpack"]) if fn == "base64gzip"}
        for name, dest in (("STACKVEND_STEP0_VERIFY_SH_GZ_B64", "verify.sh"),
                           ("STACKVEND_STEP0_GUARD_PY_GZ_B64", "guard.py")):
            self.assertIn(name, gz)
            self.assertIn(f"printenv {name} | base64 -d | gunzip > /workspace/step0/{dest}", lines)
        self.assertIn("printenv STACKVEND_OFFICIAL_ALLOWED_SIGNERS_B64 | base64 -d > /workspace/step0/allowed_signers",
                      lines)
        for local, dest in (("local.platform_upgrade_step0_verify_sh", "verify.sh"),
                            ("local.platform_upgrade_step0_guard_py", "guard.py"),
                            ("local.platform_upgrade_allowed_signers", "allowed_signers")):
            check = "echo '${sha256(%s)}  /workspace/step0/%s' | sha256sum -c --quiet -" % (local, dest)
            self.assertIn(check, lines)
            # each check comes after the file is written
            writer = [i for i, ln in enumerate(lines) if ln.endswith(f"> /workspace/step0/{dest}")]
            self.assertEqual(len(writer), 1)
            self.assertLess(writer[0], lines.index(check))
        self.assertIn("chmod 0555 /workspace/step0/verify.sh /workspace/step0/guard.py", lines)
        self.assertIn("chmod 0444 /workspace/step0/allowed_signers", lines)
        # every printenv'd variable is one the step sets
        names = {n for n, _, _, _ in _env_entries(_steps()["step0-unpack"])}
        self.assertEqual(set(re.findall(r"printenv ([A-Z0-9_]+)", "\n".join(lines))), names)

    def _run_unpack(self, env_values, workdir):
        _, script = _unpack_script_lines()
        text = "\n".join(script).replace("/workspace/step0", os.path.join(workdir, "step0"))
        self.assertNotIn("/workspace", text)
        return subprocess.run([BASH, "-c", text], capture_output=True, text=True, timeout=60,
                              env=hermetic_guard.child_env(extra=env_values))

    @unittest.skipUnless(BASH and shutil.which("gunzip") and shutil.which("sha256sum") and shutil.which("base64"),
                         "bash, gunzip, sha256sum or base64 missing")
    def test_end_to_end_unpack_passes_the_sha256_checks(self):
        with tempfile.TemporaryDirectory() as d:
            res = self._run_unpack(_env_values_python(), d)
            self.assertEqual(res.returncode, 0, res.stderr)
            for local, dest in (("local.platform_upgrade_step0_verify_sh", "verify.sh"),
                                ("local.platform_upgrade_step0_guard_py", "guard.py"),
                                ("local.platform_upgrade_allowed_signers", "allowed_signers")):
                self.assertEqual(_read_bytes(os.path.join(d, "step0", dest)), _read_bytes(LOCAL_FILES[local]))

    @unittest.skipUnless(BASH and shutil.which("gunzip") and shutil.which("sha256sum") and shutil.which("base64"),
                         "bash, gunzip, sha256sum or base64 missing")
    def test_end_to_end_unpack_refuses_a_tampered_file(self):
        vals = _env_values_python()
        vals["STACKVEND_STEP0_GUARD_PY_GZ_B64"] = base64.b64encode(
            gzip.compress(_read_bytes(LOCAL_FILES["local.platform_upgrade_step0_guard_py"]) + b"\n# x\n", mtime=0)
        ).decode("ascii")
        with tempfile.TemporaryDirectory() as d:
            self.assertNotEqual(self._run_unpack(vals, d).returncode, 0)
        vals = _env_values_python()
        vals["STACKVEND_STEP0_VERIFY_SH_GZ_B64"] = vals["STACKVEND_OFFICIAL_ALLOWED_SIGNERS_B64"]   # not gzip
        with tempfile.TemporaryDirectory() as d:
            self.assertNotEqual(self._run_unpack(vals, d).returncode, 0)

    @unittest.skipUnless(TOFU and BASH and shutil.which("gunzip") and shutil.which("sha256sum"),
                         "OpenTofu, bash, gunzip or sha256sum missing")
    def test_end_to_end_unpack_with_opentofu_output(self):
        with tempfile.TemporaryDirectory() as d:
            vals = {}
            for name, fn, local, _ in _env_entries(_steps()["step0-unpack"]):
                vals[name] = _tofu_eval('%s(file("%s"))' % (fn, LOCAL_FILES[local]), d)
            res = self._run_unpack(vals, d)
            self.assertEqual(res.returncode, 0, res.stderr)


# ==============================================================================================================
# 4. BUILD_ID for the Control Center's build link
# ==============================================================================================================
class TestBuildId(unittest.TestCase):
    def test_verify_step_passes_cloud_builds_build_id(self):
        steps = _steps()
        self.assertEqual(steps["step0-verify"].get("env"), ["BUILD_ID=$BUILD_ID"])

    def test_unpack_env_has_no_cloud_build_substitution(self):
        for e in _steps()["step0-unpack"]["env"]:
            self.assertNotIn("$", ENV_EXPR.sub("", e), e)
            self.assertRegex(e, ENV_EXPR)

    def test_guard_records_build_id_from_the_environment(self):
        for p in (os.path.join(PLATFORM, "upgrade_step0", "guard.py"), os.path.join(REPO, "scripts", "upgrade", "guard.py")):
            self.assertEqual(open(p).read().count('"build_id": os.environ.get("BUILD_ID", "")'), 2, p)


if __name__ == "__main__":
    unittest.main()

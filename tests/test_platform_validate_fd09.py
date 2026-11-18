"""FD-09: google_cloud_run_v2_job.tf_applier must set max_retries on the TASK template (template.template).

`91b05ba` put `max_retries = 0` on the outer execution template, which the google provider schema rejects
("An argument named "max_retries" is not expected here"), so every untargeted plan/apply of infra/platform
failed. Omitting it is also wrong: the provider default is 3, which would raise live retries from 0 to 3.

Static cases are hermetic: a test-only, comment- and string-aware block walker (never used in production).
The opt-in case runs the real `tofu validate` offline (-backend=false; no state, credentials or tfvars) and
needs `tofu` on PATH plus STACKVEND_TOFU_VALIDATE=1 (it downloads providers from the registry).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM_MAIN = os.path.join(REPO, "infra", "platform", "main.tf")
TF_APPLIER = 'resource "google_cloud_run_v2_job" "tf_applier"'

_ATTR = re.compile(r'^([A-Za-z_][\w-]*)\s*=\s*(.*)$')
_HEAD = re.compile(r'^([A-Za-z_][\w-]*)((?:\s+"[^"]*")*)\s*\{')


def _strip(text):
    """Drop #, // and /* */ comments; keep string text but blank any braces inside strings."""
    lines, in_str, in_cmt = [], False, False
    for line in text.splitlines():
        buf, j = [], 0
        while j < len(line):
            c = line[j]
            if in_cmt:
                if line.startswith("*/", j):
                    in_cmt = False
                    j += 2
                else:
                    j += 1
                continue
            if in_str:
                if c == "\\":
                    buf.append(line[j:j + 2].replace("{", " ").replace("}", " "))
                    j += 2
                    continue
                if c == '"':
                    in_str = False
                buf.append(" " if c in "{}" else c)
                j += 1
                continue
            if c == '"':
                in_str = True
            elif c == "#" or line.startswith("//", j):
                break
            elif line.startswith("/*", j):
                in_cmt = True
                j += 2
                continue
            buf.append(c)
            j += 1
        lines.append("".join(buf))
    return lines


def attributes(text):
    """Return [(block_path_tuple, name, value)] for every `name = value` line inside a block."""
    out, path = [], []
    for raw in _strip(text):
        s = raw.strip()
        m = _ATTR.match(s)
        if m and path:
            out.append((tuple(path), m.group(1), m.group(2).strip()))
        opens, closes = s.count("{"), s.count("}")
        h = _HEAD.match(s)
        if h and opens > closes:
            labels = h.group(2).strip()
            path.append(h.group(1) + (" " + labels if labels else ""))
            opens -= 1
        path.extend(["{"] * max(opens - closes, 0))
        for _ in range(max(closes - opens, 0)):
            path.pop()
    assert not path, f"unbalanced braces, open: {path}"
    return out


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


class TestTfApplierMaxRetries(unittest.TestCase):
    def test_max_retries_on_task_template_is_zero(self):
        hits = [(p, v) for p, a, v in attributes(_read(PLATFORM_MAIN)) if p and p[0] == TF_APPLIER and a == "max_retries"]
        self.assertEqual(hits, [((TF_APPLIER, "template", "template"), "0")])

    def test_outer_template_has_no_max_retries(self):
        bad = [p for p, a, _ in attributes(_read(PLATFORM_MAIN)) if p[:2] == (TF_APPLIER, "template") and len(p) == 2 and a == "max_retries"]
        self.assertEqual(bad, [])

    def test_no_v2_job_in_repo_sets_max_retries_on_outer_template(self):
        files = [f for root in ("infra", os.path.join("apps", "control-center", "infra"))
                 for f in glob.glob(os.path.join(REPO, root, "**", "*.tf"), recursive=True) if "/.terraform/" not in f]
        self.assertTrue(files)
        bad = []
        for f in files:
            for p, a, _ in attributes(_read(f)):
                if a == "max_retries" and len(p) == 2 and p[0].startswith('resource "google_cloud_run_v2_job"') and p[1] == "template":
                    bad.append((os.path.relpath(f, REPO), p[0]))
        self.assertEqual(bad, [])

    def test_tf_applier_other_settings_unchanged(self):
        """Do No Harm: the move must not alter the rest of the task template."""
        attrs = {(p, a): v for p, a, v in attributes(_read(PLATFORM_MAIN)) if p and p[0] == TF_APPLIER}
        tt = (TF_APPLIER, "template", "template")
        self.assertEqual(attrs[(tt, "timeout")], '"86400s"')
        # FD-7L (SAT-33): the runtime SA is local.tf_applier_runtime_sa, which is sa-castor-developer until step B
        # (tf_runner_dedicated_sa = true); tests/test_fd7l_platform_runner_identity.py pins that local.
        self.assertEqual(attrs[(tt, "service_account")], "local.tf_applier_runtime_sa")
        self.assertEqual(attrs[(tt + ("containers",), "args")], '["python3", "-m", "applier"]')

    def test_walker_negative_controls(self):
        broken = 'resource "google_cloud_run_v2_job" "x" {\n  template {\n    max_retries = 0\n    template {\n      timeout = "1s" # {\n    }\n  }\n}\n'
        hits = [(p, a) for p, a, _ in attributes(broken) if a == "max_retries"]
        self.assertEqual(hits, [(('resource "google_cloud_run_v2_job" "x"', "template"), "max_retries")])
        tricky = 'locals {\n  s = "a { b"  // }\n  t = "${x}"\n}\n'
        self.assertEqual([a for _, a, _ in attributes(tricky)], ["s", "t"])


# live (red-team F8): downloads providers from the public registry, so it needs real network. CI covers the same
# check in the iac-validate job (.github/workflows/ci.yml). Run: STACKVEND_TOFU_VALIDATE=1 STACKVEND_ALLOW_NETWORK=1
# pytest --run-live tests/test_platform_validate_fd09.py
@pytest.mark.live
@unittest.skipUnless(shutil.which("tofu") and os.environ.get("STACKVEND_TOFU_VALIDATE") == "1",
                     "opt-in: needs tofu on PATH and STACKVEND_TOFU_VALIDATE=1 (downloads providers)")
class TestPlatformTofuValidate(unittest.TestCase):
    def test_platform_validates_offline(self):
        tmp = tempfile.mkdtemp(prefix="fd09-validate-")
        try:
            ign = shutil.ignore_patterns(".terraform", ".terraform.lock.hcl", "*.tfstate", "*.tfstate.*", "*.tfvars", "*.tfplan")
            for rel in (os.path.join("infra", "platform"), os.path.join("infra", "modules"), "workflows"):
                shutil.copytree(os.path.join(REPO, rel), os.path.join(tmp, rel), ignore=ign)
            env = dict(os.environ, TF_DATA_DIR=os.path.join(tmp, ".tfdata"), CHECKPOINT_DISABLE="1", TF_IN_AUTOMATION="1")
            cwd = os.path.join(tmp, "infra", "platform")
            init = subprocess.run(["tofu", "init", "-backend=false", "-input=false", "-no-color"], cwd=cwd, env=env,
                                  capture_output=True, text=True, timeout=900)
            self.assertEqual(init.returncode, 0, init.stderr[-4000:])
            val = subprocess.run(["tofu", "validate", "-json", "-no-color"], cwd=cwd, env=env,
                                 capture_output=True, text=True, timeout=600)
            res = json.loads(val.stdout)
            self.assertTrue(res["valid"], json.dumps(res["diagnostics"], indent=1)[-4000:])
            self.assertEqual(res["error_count"], 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

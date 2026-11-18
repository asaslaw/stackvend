"""FD-4CC: the golden `security-secret` module validates as a root module too.

`output "secret_version_id"` was `var.secret_data != "" ? version[0].id : ""`. During `validate` the condition is an
unknown that carries the sensitive mark of `var.secret_data`, so a root module failed ("Output refers to sensitive
values", outputs.tf). At plan time the condition is known and the id is NOT sensitive: child-module callers (how
workloads use the module) received a plain value. Declaring `sensitive = true` would have changed that (a caller's
plain root output of it would fail, plans would mask it), so the output now tests the version's count instead:
the same value (count = 1 exactly when secret_data != ""), never the input's mark.

- module: resources and variables byte-identical to before (pinned hashes); only that output expression changed.
- callers: the same values and marks as a child with the old and the new text (real `tofu test` plans), including a
  caller that exports it as a plain root output.
- replicas: the control-center copy and the four payload copies carry the same text; the typed-IaC catalog is
  unchanged (all three outputs plain; scripts/build_iac_catalog.py --check), so typed renders are unchanged.

Hermetic: python-hcl2 parsing; the real `tofu validate` / `tofu test` (mock provider, production tofu + mirror) only
when present.
"""
import hermetic_guard  # noqa: F401  (first import)

import functools
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from shared import iac_intent as ii  # noqa: E402

MODULE = os.path.join(REPO_ROOT, "infra", "modules", "security-secret")
CC_MODULE = os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", "security-secret")
PAYLOADS = ("shared", "mcp-servers/terraform/shared", "apps/orchestrator-gateway/shared",
            "apps/control-center/shared")
FILES = ("main.tf", "variables.tf", "outputs.tf")
# the module before FD-4CC (main 60cf910b): resources and variables must not change
BEFORE_SHA256 = {
    "main.tf": "20b23641ea2c7c61963250fc039a69015055ac8ec9f243e269b1ec0130907c9c",
    "variables.tf": "393c3588f326c0fb14631f643ab3b6c4deff5c1bda6739368b57bd6d2a96464f",
    "outputs.tf": "6a590c15b423ec536997c954b433e284d4bc8894acc38e343f0cf29b46000228",
}
NEW_VALUE = (
    "  # FD-4CC: test the version's count, not the sensitive var.secret_data (the same value: count = 1 exactly when\n"
    "  # secret_data != \"\"), so the id never takes the input's sensitive mark and the module also validates as a root.\n"
    "  value = length(google_secret_manager_secret_version.version) > 0 ? "
    "google_secret_manager_secret_version.version[0].id : \"\"\n")
OLD_VALUE = ("  value       = var.secret_data != \"\" ? google_secret_manager_secret_version.version[0].id : \"\"\n")
# SECRET-INITIAL-VERSION (owner 11-10) added exactly these blocks to main.tf / variables.tf (the random provider, the
# random first version and its input; tests/test_secret_initial_version.py). Removing them must give back the module
# FD-4CC pinned, so the pin below still covers every other line.
SIV_MAIN_ADDITIONS = (
    '    random = {\n      source = "hashicorp/random"\n    }\n',
    "# SECRET-INITIAL-VERSION (owner 11-10)",   # the comment + two resources, up to the accessor block (below)
)
SIV_VARIABLES_ADDITION = '\nvariable "generate_initial_version" {'


def _read(d, name):
    return Path(d, name).read_text(encoding="utf-8")


def _without_siv(name, text):
    """The module text without the SECRET-INITIAL-VERSION additions (exact blocks, each present once)."""
    if name == "main.tf":
        provider, marker = SIV_MAIN_ADDITIONS
        assert text.count(provider) == 1 and text.count(marker) == 1
        text = text.replace(provider, "")
        start = text.index(marker)
        end = text.index('resource "google_secret_manager_secret_iam_member" "accessor"', start)
        return text[:start] + text[end:]
    if name == "variables.tf":
        start = text.index(SIV_VARIABLES_ADDITION)
        assert text.count(SIV_VARIABLES_ADDITION) == 1 and text.endswith("}\n")
        return text[:start]
    return text


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


NEW_OUTPUTS = _read(MODULE, "outputs.tf")
OLD_OUTPUTS = NEW_OUTPUTS.replace(NEW_VALUE, OLD_VALUE)


# ------------------------------------------------------------------------------------------------ module text
def test_only_the_output_expression_changed():
    # SECRET-INITIAL-VERSION: every line FD-4CC pinned is unchanged; only that row's exact blocks were added
    assert _sha(_without_siv("main.tf", _read(MODULE, "main.tf"))) == BEFORE_SHA256["main.tf"]
    assert _sha(_without_siv("variables.tf", _read(MODULE, "variables.tf"))) == BEFORE_SHA256["variables.tf"]
    assert NEW_OUTPUTS.count(NEW_VALUE) == 1
    assert _sha(OLD_OUTPUTS) == BEFORE_SHA256["outputs.tf"], "OLD_OUTPUTS must reproduce the module before FD-4CC"


def test_no_output_is_declared_sensitive_or_reads_the_secret_input():
    outs = {k: v for o in hcl2.loads(NEW_OUTPUTS)["output"] for k, v in o.items()}
    assert set(outs) == {"secret_id", "secret_name", "secret_version_id"}
    for name, body in outs.items():
        assert "sensitive" not in body, name
        assert "var.secret_data" not in body["value"], name


def test_cc_copy_and_the_four_payloads_carry_the_same_text():
    for name in FILES:
        assert _read(CC_MODULE, name) == _read(MODULE, name), name
    for rel in PAYLOADS:
        ns = {}
        path = os.path.join(REPO_ROOT, rel, "builtin_modules_payload.py")
        with open(path, encoding="utf-8") as f:
            exec(compile(f.read(), path, "exec"), ns)  # noqa: S102 - repo-owned data module
        for name in FILES:
            assert ns["BUILTIN_MODULE_FILES"]["security-secret"][name] == _read(MODULE, name), (rel, name)


def test_catalog_outputs_stay_plain_and_the_catalog_is_current():
    outs = ii.load_artifacts().module("security-secret")["outputs"]
    assert {k: v["sensitive"] for k, v in outs.items()} == {
        "secret_id": False, "secret_name": False, "secret_version_id": False}
    r = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "scripts", "build_iac_catalog.py"), "--check"],
                       cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, env=hermetic_guard.child_env())
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]


# ------------------------------------------------------------------------------------------------ real engine
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")


@functools.lru_cache(maxsize=1)
def _skip_reason():
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        return "production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present"
    return None


@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if _skip_reason():
        pytest.skip(_skip_reason())
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("fd4cc-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


def _write_module(dst, outputs_text):
    dst.mkdir(parents=True)
    for name in ("main.tf", "variables.tf"):
        (dst / name).write_text(_read(MODULE, name), encoding="utf-8")
    (dst / "outputs.tf").write_text(outputs_text, encoding="utf-8")


def _validate(runner, wd):
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-json", "-no-color"], cwd=wd)
    return json.loads(r.stdout)


def _summaries(vj):
    return [(d.get("summary"), (d.get("range") or {}).get("filename")) for d in vj.get("diagnostics", [])]


def _tofu_test(runner, wd, name, text):
    (wd / "tests").mkdir(exist_ok=True)
    (wd / "tests" / name).write_text(text, encoding="utf-8")
    r = runner._run(["test", "-test-directory=tests", f"-filter=tests/{name}", "-no-color"], cwd=wd)
    return r.returncode, r.stdout + r.stderr


ROOT_TEST = '''mock_provider "google" {}

variables {
  project_id = "fd4cc-test"
  secret_id  = "api-key"
}

run "no_initial_data_plans_no_version_and_an_empty_id" {
  command = plan
  assert {
    condition     = length(google_secret_manager_secret_version.version) == 0 && output.secret_version_id == "" && !issensitive(output.secret_version_id)
    error_message = "secret_data = \\"\\" must plan no version and a plain empty secret_version_id"
  }
}

run "initial_data_plans_one_version_and_its_plain_id" {
  command = plan
  variables {
    secret_data = "s3cr3t"
  }
  assert {
    condition     = length(google_secret_manager_secret_version.version) == 1 && output.secret_version_id == google_secret_manager_secret_version.version[0].id && !issensitive(output.secret_version_id)
    error_message = "secret_data must plan one version and output its id, not sensitive"
  }
}
'''


def test_module_validates_and_plans_as_a_root_module(runner, tmp_path):
    wd = tmp_path / "security-secret"
    _write_module(wd, NEW_OUTPUTS)
    vj = _validate(runner, wd)
    assert vj["valid"], _summaries(vj)
    rc, out = _tofu_test(runner, wd, "root.tftest.hcl", ROOT_TEST)
    assert rc == 0 and "2 passed, 0 failed" in out, out[-4000:]


def test_the_module_before_fd4cc_failed_as_a_root_module(runner, tmp_path):
    """Negative control: the old text reproduces the TI-2 finding, so the root test above proves the fix."""
    wd = tmp_path / "security-secret"
    _write_module(wd, OLD_OUTPUTS)
    vj = _validate(runner, wd)
    assert not vj["valid"]
    assert ("Output refers to sensitive values", "outputs.tf") in _summaries(vj)


CHILD_MAIN = '''variable "api_key" {
  type      = string
  sensitive = true
  default   = ""
}

module "s" {
  source            = "./modules/security-secret"
  project_id        = "fd4cc-test"
  secret_id         = "api-key"
  secret_data       = var.api_key
  workload_sa_email = "wsa@fd4cc-test.iam.gserviceaccount.com"
}

module "bare" {
  source     = "./modules/security-secret"
  project_id = "fd4cc-test"
  secret_id  = "other"
}

# a caller that exports every output as a plain root output (must keep working)
output "sid" {
  value = module.s.secret_id
}

output "sname" {
  value = module.bare.secret_name
}

output "v" {
  value = module.s.secret_version_id
}

output "v_bare" {
  value = module.bare.secret_version_id
}
'''
CHILD_TEST = '''mock_provider "google" {}

run "no_initial_data" {
  command = plan
  assert {
    condition     = !issensitive(module.s.secret_version_id) && !issensitive(module.s.secret_id) && !issensitive(module.s.secret_name) && !issensitive(module.bare.secret_version_id)
    error_message = "no output may be sensitive"
  }
  assert {
    condition     = module.s.secret_version_id == "" && module.bare.secret_version_id == "" && output.v == ""
    error_message = "no initial data: an empty secret_version_id"
  }
}

run "initial_data" {
  command = plan
  variables {
    api_key = "s3cr3t"
  }
  assert {
    condition     = !issensitive(module.s.secret_version_id) && module.s.secret_version_id != "" && output.v == module.s.secret_version_id && module.bare.secret_version_id == ""
    error_message = "initial data: the version id, plain"
  }
}
'''


@pytest.mark.parametrize("label", ["before", "after"])
def test_child_callers_get_the_same_values_and_marks(runner, tmp_path, label):
    """As a child module the old output was plain at plan time; the new one is too, with the same values."""
    wd = tmp_path / "root"
    _write_module(wd / "modules" / "security-secret", OLD_OUTPUTS if label == "before" else NEW_OUTPUTS)
    (wd / "main.tf").write_text(CHILD_MAIN, encoding="utf-8")
    vj = _validate(runner, wd)
    assert vj["valid"], (label, _summaries(vj))
    rc, out = _tofu_test(runner, wd, "child.tftest.hcl", CHILD_TEST)
    assert rc == 0 and "2 passed, 0 failed" in out, (label, out[-4000:])

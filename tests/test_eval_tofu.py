"""FD-30 scoring-side OpenTofu runner (red-team H6). Offline: provider-less configs only, empty filesystem mirror,
sandbox-exec (macOS) denies outbound IP. Skipped when tofu or python-hcl2 is unavailable."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import paths  # noqa: E402
from stackvend_eval.tofu_runner import TofuRunner, find_tofu  # noqa: E402

pytestmark = pytest.mark.skipif(not (find_tofu() and paths.have_hcl2()), reason="needs tofu + python-hcl2")

OK_TF = 'variable "project_id" {\n  type = string\n}\noutput "p" {\n  value = var.project_id\n}\n'


def _runner(tmp_path):
    return TofuRunner(tmp_path / "work", mirror_dir=tmp_path / "empty-mirror", timeout_s=120)


def test_refuses_disallowed_subcommands(tmp_path):
    r = _runner(tmp_path)
    for bad in (["apply"], ["plan"], ["import", "a", "b"], ["state", "list"], ["destroy"], ["console"]):
        with pytest.raises(PermissionError):
            r._run(bad)
    with pytest.raises(PermissionError):
        r._run(["test"])  # unfiltered test runs every generated *.tftest.hcl


def test_fmt_parse_oracle(tmp_path):
    r = _runner(tmp_path)
    assert r.fmt_ok('resource "a" "b" {\n x = 1\n}\n')[0]
    assert not r.fmt_ok('resource "a" "b" {\n x = \n')[0]


def test_remote_module_source_is_refused_before_init(tmp_path):
    r = _runner(tmp_path)
    tree = {"infra/workload/main.tf": 'module "x" {\n  source = "git::https://example.com/evil.git"\n}\n'}
    out = r.validate_tree(tree, "remote")
    assert out["status"] == "remote_module_source"
    assert not (tmp_path / "work" / "trees" / "remote").exists()  # nothing written, nothing initialised


def test_validate_and_mock_plan_offline_and_generated_tests_are_dropped(tmp_path):
    r = _runner(tmp_path)
    evil = 'run "evil" {\n  command = apply\n  assert {\n    condition     = false\n    error_message = "x"\n  }\n}\n'
    tree = {"infra/workload/main.tf": OK_TF, "infra/workload/evil.tftest.hcl": evil,
            "infra/workload/tests/more.tftest.hcl": evil}
    out = r.validate_tree(tree, "ok")
    assert out["status"] == "validated" and out["validate_ok"] is True, out
    assert out["plan"]["plan_ok"] is True, out["plan"]
    wd = tmp_path / "work" / "trees" / "ok" / "infra" / "workload"
    assert not (wd / "evil.tftest.hcl").exists() and not (wd / "tests").exists()
    harness_test = (wd / ".stackvend_eval_tests" / "plan.tftest.hcl").read_text()
    assert "command = plan" in harness_test and "apply" not in harness_test
    assert 'project_id = "eval-mock-project_id"' in harness_test


def test_invalid_reference_fails_validate(tmp_path):
    r = _runner(tmp_path)
    tree = {"infra/workload/main.tf": 'output "p" {\n  value = var.nope\n}\n'}
    out = r.validate_tree(tree, "bad")
    assert out["validate_ok"] is False and out["diagnostics"]
    assert any("nope" in (d.get("detail") or "") + (d.get("summary") or "") for d in out["diagnostics"])


def test_provider_config_without_mirror_reports_offline_init_failure(tmp_path):
    r = _runner(tmp_path)
    tree = {"infra/workload/main.tf": 'terraform {\n  required_providers {\n    google = {\n'
                                      '      source = "hashicorp/google"\n    }\n  }\n}\n'}
    out = r.validate_tree(tree, "prov")
    assert out["status"] == "init_failed_offline_mirror" and out["init_ok"] is False

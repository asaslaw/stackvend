"""FD-30 oracles and invariant checks (measurement code), including negative cases (clean input -> no findings)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import invariants, paths  # noqa: E402
from stackvend_eval.oracles import py_ast, py_file_validate_level, score_python  # noqa: E402
from stackvend_eval.stats import mcnemar_exact, paired, wilson  # noqa: E402

needs_hcl2 = pytest.mark.skipif(not paths.have_hcl2(), reason="python-hcl2 not installed (eval/requirements.txt)")
needs_pyflakes = pytest.mark.skipif(not paths.have_pyflakes(), reason="pyflakes not installed (eval/requirements.txt)")

GOOD_MAIN = '''
module "compute_api" {
  source     = "../modules/compute-cloudrun"
  project_id = var.project_id
  region     = var.region
  env_vars   = { WORKER_URL = module.compute_worker.service_uri }
}
module "compute_worker" {
  source     = "../modules/compute-cloudrun"
  project_id = var.project_id
  region     = var.region
}
variable "project_id" {
  type = string
}
variable "region" {
  type    = string
  default = "us-central1"
}
'''


def test_python_ast_and_score():
    assert py_ast("x = 1\n")[0]
    ok, err = py_ast("def (:\n")
    assert not ok and "line" in err
    s = score_python({"a.py": "x = 1\n", "b.py": "def (:\n", "c.txt": "no"})
    assert s["py_files"] == 2 and s["ast_ok"] == 1 and "b.py" in s["ast_fail"]


@needs_pyflakes
def test_undefined_name_detection_catches_the_app_stub():
    stub = '@app.get("/health")\ndef health():\n    return {}\n'
    assert py_file_validate_level(stub, "main.py") == "invalid"
    assert py_file_validate_level("from fastapi import FastAPI\napp = FastAPI()\n", "main.py") == "valid"


@needs_hcl2
def test_clean_tree_has_no_violations():
    tree = {"infra/workload/main.tf": GOOD_MAIN, "infra/modules/compute-cloudrun/main.tf": 'variable "x" {}\n',
            "apps/api/main.py": "x = 1\n"}
    r = invariants.check(tree, regions=invariants.load_regions(), forbidden_projects=["host-proj-123"])
    assert r["violations"] == 0 and r["I3_literals"] == [] and r["I6_service_uri_cycles"] == []
    assert r["I6_service_uri_edges"] == 1
    assert r["I3_variable_default_literals"] == [{"file": "infra/workload/main.tf", "variable": "region",
                                                  "kind": "region"}]
    assert r["var_project_id_used"] is True


@needs_hcl2
def test_cycles_literals_and_layout_violations_are_found():
    cyclic = GOOD_MAIN.replace('region     = var.region\n}\n', 'region     = var.region\n'
                               '  env_vars   = { API_URL = module.compute_api.service_uri }\n}\n', 1)
    cyclic = cyclic.replace('module "compute_worker" {\n  source     = "../modules/compute-cloudrun"\n'
                            '  project_id = var.project_id\n  region     = var.region\n}',
                            'module "compute_worker" {\n  source     = "../modules/compute-cloudrun"\n'
                            '  project_id = var.project_id\n  region     = var.region\n'
                            '  env_vars   = { API_URL = module.compute_api.service_uri }\n}')
    lit = ('resource "google_compute_subnetwork" "s" {\n  region        = "europe-west1"\n'
           '  ip_cidr_range = "10.10.0.0/24"\n  project       = "host-proj-123"\n}\n')
    tree = {"infra/workload/main.tf": cyclic, "infra/workload/net.tf": lit, "terraform/stray.tf": "",
            "apps/api/Dockerfile": "FROM x\n"}
    r = invariants.check(tree, regions=invariants.load_regions(), forbidden_projects=["host-proj-123"])
    assert r["I6_service_uri_cycles"], r
    assert sorted(x["kind"] for x in r["I3_literals"]) == ["cidr", "project", "region"]
    assert r["I4_iac_outside_infra_workload"] == ["terraform/stray.tf"]
    assert r["I4_dockerfiles"] == ["apps/api/Dockerfile"]


def test_compare_flags_paired_regressions_and_new_dnh_fires():
    import compare
    base_o = {"fires_on_validate_valid": 0, "invariant_violations": 0, "invalid_reasons": [], "fires": 3,
              "fires_on_syntax_valid": 1, "usd": 0, "llm_calls": 0}
    run = {"valid": True, "outcome": "committed_passed", "c3_validate_ok": True}
    base = {"overall": base_o, "runs": [dict(run, key="01-r1"), dict(run, key="02-r1", c3_validate_ok=False)]}
    same = compare.compare(base, base)
    assert same["regressions"] == [] and same["paired"]["pairs"] == 2
    cand = {"overall": dict(base_o, fires_on_validate_valid=2),
            "runs": [dict(run, key="01-r1", c3_validate_ok=False), dict(run, key="02-r1", c3_validate_ok=True)]}
    out = compare.compare(base, cand)
    assert out["paired"]["regressed"] == ["01-r1"] and out["paired"]["improved"] == ["02-r1"]
    assert len(out["regressions"]) == 2


def test_stats():
    lo, hi = wilson(3, 3)
    assert 0.43 < lo < 0.45 and hi == 1.0
    assert wilson(0, 0) == (None, None)
    assert mcnemar_exact(0, 0) == 1.0
    assert mcnemar_exact(0, 6) == pytest.approx(0.03125)
    p = paired({"a": True, "b": True, "c": False}, {"a": False, "b": True, "c": True})
    assert p["regressed"] == ["a"] and p["improved"] == ["c"]

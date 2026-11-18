"""Step 2 S2-0 C4 apply-preparation checkpoint (eval/tools/c4_apply_prep.py). Hermetic: the apply-input mapping
(deploy_workload's infra/workload -> root copy through the PRODUCTION rewrite_flattened_module_sources, FD-55 W0;
modules kept; tfvars through the production merge_tfvars_texts with mock values), the run-tree selection, the
prepare_workspace read-back diff (Do-No-Harm negative: an input prepare_workspace leaves alone reports 0 changes),
and the report shape. prepare_workspace runs as tests/test_step1_hb10_golden_modules.py runs it (MagicMock db, no
state bucket, iac_engine=None, workspace under tmp_path). No tofu here: V1b is exercised by the tool's own run."""
import hermetic_guard  # noqa: F401  (first import)

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT))

from stackvend_eval.blobs import BlobStore  # noqa: E402
from eval.tools import c4_apply_prep as c4  # noqa: E402

WORKLOAD_MAIN = ('module "foundation" {\n  source = "../modules/workload-foundation/base"\n}\n\n'
                 'module "b" {\n  source = "../../bundles/x"\n}\n')
MODULE_MAIN = 'variable "project_id" {\n  type = string\n}\n'

# Valid root HCL that no prepare_workspace step has a reason to touch (no variables, resources or modules). FD-55 W6a:
# with its final newline (the HB-10 re-join that dropped it from every non-golden .tf, reported `ws-only`, is deleted).
UNTOUCHED_MAIN = ('terraform {\n  required_version = ">= 1.5.0"\n}\n\n'
                  'locals {\n  greeting = "hello"\n}\n\n'
                  'output "greeting" {\n  value = local.greeting\n}\n')


@pytest.fixture(scope="module")
def svc_mod():
    return c4.load_service(ROOT)


# ------------------------------------------------------------------------------------------------ mapping
def _parse_tfvars(text):
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def test_apply_input_maps_workload_to_root_and_keeps_modules(svc_mod):
    tree = {"infra/workload/main.tf": WORKLOAD_MAIN,
            "infra/workload/k8s/deploy.yaml": "kind: Deployment\n",
            "infra/modules/workload-foundation/base/main.tf": MODULE_MAIN,
            "apps/api/main.py": "print('x')\n"}
    ai = c4.build_apply_input(tree, "my_app", svc_mod)
    files = ai["files"]
    # infra/workload/<p> is also at workload_relpath(<p>) (FD-4D-b), with the relative source re-anchoring
    assert files["main.tf"] == WORKLOAD_MAIN.replace('"../modules/', '"./infra/modules/').replace(
        '"../../bundles/', '"./infra/bundles/')
    assert files["k8s/deploy.yaml"] == "kind: Deployment\n"
    assert ai["root_copies"] == ["k8s/deploy.yaml", "main.tf"]   # FD-4D-b: subdirectory kept
    # originals and modules kept byte-identical at their own paths
    for p, t in tree.items():
        assert files[p] == t
    assert ai["refused"] is None and ai["intent_ws"] is False
    # tfvars: deploy_workload's FD-4BV platform keys, mock values only; the FD-4BD secrets are never tfvars keys
    tfv = _parse_tfvars(files["terraform.tfvars"])
    assert set(tfv) == {"project_id", "region", "product_id", "github_repo_full_name", "container_image",
                        "oauth_client_id", "firebase_auth_domain"}
    assert tfv["project_id"] == f'"{c4.MOCK_PROJECT}"' and tfv["product_id"] == '"my-app"'
    assert tfv["oauth_client_id"] == '""'


def test_c4_has_no_copied_source_rewrites_and_calls_the_production_flatten(svc_mod):
    """FD-55 W0: the flatten is the product's rewrite_flattened_module_sources (only .tf files), not a C4 copy."""
    assert not hasattr(c4, "SOURCE_REWRITES")
    calls = []

    class Spy:
        def __getattr__(self, name):
            return getattr(svc_mod, name)

        @staticmethod
        def rewrite_flattened_module_sources(content, filename="", nested_repo_path=""):
            calls.append((filename, nested_repo_path))
            return svc_mod.rewrite_flattened_module_sources(content, filename=filename,
                                                               nested_repo_path=nested_repo_path)

    tree = {"infra/workload/main.tf": WORKLOAD_MAIN, "infra/workload/notes.md": 'source = "../modules/x"\n'}
    files = c4.build_apply_input(tree, "p", Spy())["files"]
    assert calls == [("infra/workload/main.tf", "")]
    assert files["notes.md"] == tree["infra/workload/notes.md"]       # non-.tf: copied, never rewritten


# Three trees whose flatten the copied exact-string rewrite got WRONG or right; the expectations are literal.
FLATTEN_CASES = [
    # fmt-aligned `source  =` (FD-4BW): production re-anchors it; the old C4 copy left it unchanged
    ({"infra/workload/main.tf": 'module "m" {\n  source  = "../modules/x"\n  name    = "a"\n}\n'},
     {"main.tf": 'module "m" {\n  source  = "./infra/modules/x"\n  name    = "a"\n}\n'}),
    # bundles + nested modules, two files; a non-module `source` attribute is left alone
    ({"infra/workload/main.tf": 'module "b" {\n  source = "../../bundles/web"\n}\n',
      "infra/workload/custom.tf": ('module "c" {\n  source = "../../modules/compute-cloudrun"\n}\n\n'
                                  'resource "google_storage_bucket_object" "o" {\n  name   = "o"\n  bucket = "b"\n'
                                  '  source = "../modules/not-a-module"\n}\n')},
     {"main.tf": 'module "b" {\n  source = "./infra/bundles/web"\n}\n',
      "custom.tf": ('module "c" {\n  source = "./infra/modules/compute-cloudrun"\n}\n\n'
                    'resource "google_storage_bucket_object" "o" {\n  name   = "o"\n  bucket = "b"\n'
                    '  source = "../modules/not-a-module"\n}\n')}),
    # a registry source and a source already at the root are kept byte-identical (Do-No-Harm)
    ({"infra/workload/main.tf": ('module "r" {\n  source  = "terraform-google-modules/network/google"\n'
                                 '  version = "9.0.0"\n}\n\nmodule "l" {\n  source = "./infra/modules/x"\n}\n')},
     {"main.tf": ('module "r" {\n  source  = "terraform-google-modules/network/google"\n  version = "9.0.0"\n}\n\n'
                  'module "l" {\n  source = "./infra/modules/x"\n}\n')}),
]


@pytest.mark.parametrize("tree,expected", FLATTEN_CASES)
def test_c4_flatten_equals_production(svc_mod, tree, expected):
    files = c4.build_apply_input(tree, "p", svc_mod)["files"]
    for root_name, want in expected.items():
        assert files[root_name] == want
        src = "infra/workload/" + root_name
        assert files[root_name] == svc_mod.rewrite_flattened_module_sources(tree[src], filename=src)


NESTED_MAIN = 'module "run" {\n  source = "../../../modules/compute-cloudrun"\n}\n'


def test_nested_workload_module_keeps_its_subdirectory_like_production(svc_mod):
    """FD-4D-b: infra/workload/modules/x/main.tf is copied to modules/x/main.tf (never over the root main.tf, as the
    old basename copy did), with its source re-anchored from the new location (nested_repo_path)."""
    tree = {"infra/workload/main.tf": WORKLOAD_MAIN, "infra/workload/modules/x/main.tf": NESTED_MAIN,
            "infra/modules/compute-cloudrun/main.tf": MODULE_MAIN}
    ai = c4.build_apply_input(tree, "p", svc_mod)
    files = ai["files"]
    assert files["main.tf"] == WORKLOAD_MAIN.replace('"../modules/', '"./infra/modules/').replace(
        '"../../bundles/', '"./infra/bundles/')                       # the root main.tf, not the nested one
    assert files["modules/x/main.tf"] == ('module "run" {\n  source = "../../infra/modules/compute-cloudrun"\n}\n')
    assert files["modules/x/main.tf"] == svc_mod.rewrite_flattened_module_sources(
        NESTED_MAIN, filename="infra/workload/modules/x/main.tf", nested_repo_path="infra/workload/modules/x/main.tf")
    assert ai["root_copies"] == ["main.tf", "modules/x/main.tf"] and ai["nested_not_copied"] == []
    for p, t in tree.items():
        assert files[p] == t


def test_nested_copy_never_replaces_an_existing_path(svc_mod):
    existing = 'variable "keep" {\n  type = string\n}\n'
    tree = {"infra/workload/main.tf": UNTOUCHED_MAIN, "infra/workload/modules/x/main.tf": NESTED_MAIN,
            "modules/x/main.tf": existing}
    ai = c4.build_apply_input(tree, "p", svc_mod)
    assert ai["files"]["modules/x/main.tf"] == existing
    assert ai["nested_not_copied"] == ["infra/workload/modules/x/main.tf"]
    # a direct child still replaces a same-named root file, as production does
    ai = c4.build_apply_input({"infra/workload/main.tf": UNTOUCHED_MAIN, "main.tf": "old"}, "p", svc_mod)
    assert ai["files"]["main.tf"] == UNTOUCHED_MAIN


def test_product_root_without_the_production_functions_fails_clearly(svc_mod, tmp_path):
    import types
    old = types.ModuleType("old_service")
    for name in c4.REQUIRED_PRODUCT_API:
        if name != "workload_relpath":
            setattr(old, name, getattr(svc_mod, name))
    with pytest.raises(c4.ProductApiError) as e:
        c4.require_product_api(old, tmp_path)
    assert "workload_relpath (FD-4D-b)" in str(e.value)
    old.workload_relpath = svc_mod.workload_relpath
    old.rewrite_flattened_module_sources = lambda content, filename="": content     # pre-FD-4D-b signature
    with pytest.raises(c4.ProductApiError, match="nested_repo_path"):
        c4.require_product_api(old, tmp_path)
    c4.require_product_api(svc_mod, tmp_path)                                         # current product: no error


def test_apply_input_tfvars_merge_keeps_workload_keys_and_drops_secrets(svc_mod):
    tree = {"infra/workload/main.tf": UNTOUCHED_MAIN,
            "infra/workload/terraform.tfvars": ('subnet_cidr = "10.20.0.0/24"\nproject_id = "ai-guess"\n'
                                                'firebase_api_key = "never-in-a-file"\n')}
    tfv = _parse_tfvars(c4.build_apply_input(tree, "p", svc_mod)["files"]["terraform.tfvars"])
    assert tfv["subnet_cidr"] == '"10.20.0.0/24"'             # the workload's own fact kept
    assert tfv["project_id"] == f'"{c4.MOCK_PROJECT}"'        # platform-owned key wins
    assert "firebase_api_key" not in tfv and "oauth_client_secret" not in tfv


def test_apply_input_refusals_match_production(svc_mod):
    ai = c4.build_apply_input({"README.md": "x"}, "p", svc_mod)
    assert ai["refused"] and "terraform.tfvars" in ai["files"]
    # FD-4D: a nested / non-root infra/workload file is not a root config (the old C4 check accepted any of them)
    assert c4.build_apply_input({"infra/workload/variables.tf": MODULE_MAIN}, "p", svc_mod)["refused"]
    assert c4.build_apply_input({"infra/workloads/main.tf": UNTOUCHED_MAIN}, "p", svc_mod)["refused"] is None
    # TI-5a: an intent beside its render that is not a typed intent -> the typed refusal code
    bad_intent = {"infra/workload/main.tf": UNTOUCHED_MAIN, "infra/workload/iac_intent.json": "{not json",
                  "infra/workload/custom.tf.json": "{}"}
    assert c4.build_apply_input(bad_intent, "p", svc_mod)["refused"] == svc_mod.APPLY_INTENT_UNREADABLE
    no_topology = dict(bad_intent, **{"infra/workload/iac_intent.json": json.dumps({"schema": "iac_intent/v1"})})
    ai = c4.build_apply_input(no_topology, "p", svc_mod)
    assert ai["intent_ws"] is True and ai["refused"] == svc_mod.APPLY_INTENT_WITHOUT_TOPOLOGY


def test_github_fetch_filter(svc_mod):
    tree = {"main.tf": UNTOUCHED_MAIN, ".github/workflows/d.yml": "on: push\n", ".gitignore": "x\n", "logo.png": "x"}
    ai = c4.build_apply_input(tree, "p", svc_mod, vcs_fetch="github")
    assert ai["fetch_dropped"] == [".github/workflows/d.yml", ".gitignore", "logo.png"]
    assert set(ai["files"]) == {"main.tf", "terraform.tfvars"}
    assert c4.build_apply_input(tree, "p", svc_mod)["fetch_dropped"] == []


def test_uncovered_triggers_flag_without_editing(svc_mod):
    port = 'resource "x" "y" {\n  env {\n    name = "PORT"\n  }\n}\n'
    files = {"main.tf": port, "human.tf": port,
             "infra/workloads/a.tf": "", "k.tf": 'resource "kubernetes_deployment" "d" {}\n'}
    before = dict(files)
    # FD55-W6e: the PORT strip and GKE Guardrail 4 are deleted from the product; only the plural step is labelled
    assert c4.uncovered_triggers(files, svc_mod) == {"plural_workloads": ["infra/workloads/a.tf"]}
    # TI-5a: an intent workspace never reads infra/workloads/
    assert c4.uncovered_triggers(files, svc_mod, intent_ws=True) == {"plural_workloads": []}
    assert files == before


def test_every_cited_product_step_landmark_exists(svc_mod):
    """The notes cite product steps by verbatim landmark, not line number (the line numbers had gone stale); every
    landmark must still occur in the method it names, so a moved or deleted step fails here."""
    import inspect
    src = {m: inspect.getsource(getattr(svc_mod.TerraformService, m)) for m in (c4.DEPLOY, c4.PREPARE)}
    for meth, mark, _ in c4.COVERED_STEPS + c4.NOT_COVERED_STEPS + c4.DELETED_SINCE:
        assert mark in src[meth], (meth, mark)
    assert any(c4.PREPARE in c and "`" in c for c in c4.COVERED)
    assert not [c for c in c4.COVERED + c4.NOT_COVERED if ":5" in c or ":6" in c or ":2" in c]


# ------------------------------------------------------------------------------------------------ run tree
def _run_dir(tmp_path, committed=None, assembled=None):
    rd = tmp_path / "runs" / "01-r1"
    rd.mkdir(parents=True)
    store = BlobStore(rd)
    res = {"product_id": "test-01", "pipeline_outcome": "x", "checkpoints": {}, "tree_dumps": {"assemble": []}}
    if committed is not None:
        res["checkpoints"]["C3_committed"] = {"tree": store.put_tree(committed), "files": len(committed)}
    if assembled is not None:
        res["tree_dumps"]["assemble"] = [{"assembled": store.put_tree({"old.tf": ""})},
                                         {"assembled": store.put_tree(assembled), "assembly_record": {"iteration": 0}}]
    (rd / "result.json").write_text(json.dumps(res))
    return rd


def test_run_tree_prefers_committed_then_last_assembled(tmp_path):
    a, c = {"infra/workload/main.tf": "a"}, {"infra/workload/main.tf": "c"}
    assert c4.load_run_tree(_run_dir(tmp_path / "1", committed=c, assembled=a))["label"] == "committed"
    src = c4.load_run_tree(_run_dir(tmp_path / "2", assembled=a))
    assert src["label"] == "assembled_iter0" and src["tree"] == a and src["iteration"] == 0
    assert c4.load_run_tree(_run_dir(tmp_path / "3"))["label"] == "no_tree"


# ------------------------------------------------------------------------------------------------ diff
def test_diff_and_module_split():
    d = c4.diff_trees({"a": "1", "b": "2", "./c": "3"}, {"a": "1", "b": "x", "c": "3", "d": "4"})
    assert d == {"added": ["d"], "removed": [], "changed": ["b"]}
    mp = c4.module_paths(["infra/modules/compute-cloudrun/main.tf", "modules/z/x.tf", "main.tf"],
                         lambda p: p.startswith("infra/modules/compute-cloudrun/"))
    assert mp == {"golden": ["infra/modules/compute-cloudrun/main.tf"],
                  "infra_modules": ["infra/modules/compute-cloudrun/main.tf", "modules/z/x.tf"]}


def test_whitespace_only_classification():
    b = {"a.tf": "x {\n}\n", "b.tf": "x {\n}\n", "c.tf": "same"}
    a = {"a.tf": "x {\n}", "b.tf": "y {\n}\n", "c.tf": "same"}
    assert c4.whitespace_only(b, a, ["a.tf", "b.tf"]) == ["a.tf"]


def test_cycle_diagnostics_compare_order_insensitive():
    b = {"diagnostics": [{"severity": "error", "summary": "Cycle: a, b, c", "file": None}]}
    a = {"diagnostics": [{"severity": "error", "summary": "Cycle: c, a, b", "file": None},
                         {"severity": "error", "summary": "Unsupported argument", "file": "main.tf"}]}
    d = c4.compare_diags(b, a)
    assert [x["summary"] for x in d["new"]] == ["Unsupported argument"] and d["resolved"] == []


# ------------------------------------------------------------------------------------------------ prepare_workspace
def test_prepare_workspace_untouched_input_reports_zero_changes(svc_mod, tmp_path):
    """Do-No-Harm negative: valid input that no prepare_workspace step applies to comes back byte-identical."""
    files = c4.build_apply_input({"main.tf": UNTOUCHED_MAIN}, "noop-app", svc_mod)["files"]
    prep = c4.run_prepare(svc_mod, tmp_path / "ws", "noop-app", "c4-test-noop", files)
    assert prep["status"] == "prepared", prep["error"]
    rb = prep["readback"]
    assert c4.diff_trees(files, rb["files"]) == {"added": [], "removed": [], "changed": []}
    assert rb["symlinks"] == {} and prep["healed_writeback"] == [] and prep["backend_tf"] is False
    assert str(tmp_path) in prep["workspace"]


def test_prepare_workspace_dockerfile_drop_is_reported(svc_mod, tmp_path):
    """Positive control: prepare_workspace drops every Dockerfile (Buildpacks exclusivity)."""
    files = c4.build_apply_input({"main.tf": UNTOUCHED_MAIN, "apps/api/Dockerfile": "FROM x\n"}, "dk-app",
                                 svc_mod)["files"]
    prep = c4.run_prepare(svc_mod, tmp_path / "ws", "dk-app", "c4-test-dk", files)
    assert c4.diff_trees(files, prep["readback"]["files"])["removed"] == ["apps/api/Dockerfile"]


def test_analyze_run_without_tofu_and_report_shape(svc_mod, tmp_path):
    rd = _run_dir(tmp_path, assembled={"main.tf": UNTOUCHED_MAIN})
    work = tmp_path / "work"
    work.mkdir()
    row = c4.analyze_run(rd, svc_mod, work, v1b=None)
    assert row["status"] == "ok" and row["label"] == "assembled_iter0"
    assert row["added"] == row["removed"] == row["changed"] == [] and row["golden_changed"] == []
    assert not (work / c4._trace_id("01-r1")).exists()          # workspace cleaned up
    rep = c4.build_report([row, {"run": "02-r1", "label": "no_tree", "status": "no_tree"}], {"results_dir": "x"})
    assert rep["checkpoint"] == "C4" and rep["schema"] == c4.SCHEMA
    assert rep["covered"] == c4.COVERED and rep["not_covered"] == c4.NOT_COVERED
    assert rep["aggregate"]["runs"] == 2 and rep["aggregate"]["status_no_tree"] == 1
    assert "prepare_changed_files" not in rep["aggregate"]
    md = c4.render_markdown(rep)
    assert "## Apply-side steps C4 covers" in md and "## Apply-side steps C4 does NOT cover" in md
    assert "| 01-r1 | assembled_iter0 | prepared | +0/-0/~0 (ws-only 0) | 0 | 0 |" in md
    assert "**proxy**" in md
    json.dumps(rep)

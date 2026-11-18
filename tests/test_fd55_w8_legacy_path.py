"""FD-55 W8 (= TI-7, register FD55-W8, owner 11-07): the last name-matching helpers of the no-topology path.

* W8-1 (FD-4X residual, plan G19): HD-03 `resolve_service_archetype` is deleted. A CI deploy workflow's compute kind
  comes from the typed compute intent on both paths: topology path unchanged; without a topology a planned secondary
  is Cloud Run (the ComputeIntent service-list contract), the primary and any other directory get the archetype. No
  AI HCL scan, no name substring.
* W8-2 (FD-4AD residual FD22-09, verifier.py): `verify_and_cure` / `reconcile_iac_module_vendoring` take no
  `archetype`; step 4b only ADDS the files of a referenced module that has none. It no longer rewrites the foundation
  module or adds the archetype's (default: Cloud Run) compute module.
* W8-3 (FD-4AD / FD-4AE-c note 4, HB-27 copy): the pre-commit gate no longer runs the add-only package pass twice.
Each change has a Do No Harm negative (valid input -> unchanged). Hermetic (no Firestore, no network)."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import inspect
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: this file is acceptance evidence and must not skip", pytrace=False)

from developer_agent import handler as h  # noqa: E402
from developer_agent.compute_intent import ComputeIntent, resolve_compute_intent  # noqa: E402
from gatekeeper_agent.verifier import SynthesisVerifierAgent  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

W = "infra/workload/"
MAIN = W + "main.tf"
CUSTOM = W + "custom.tf"
PID = "shop"
kind = h.DeveloperAgent._service_kind


def legacy_intent(archetype, services):
    return resolve_compute_intent(PID, {"compute_archetype": archetype, "target_compute_services": list(services)})


# ============================================================================================ W8-1: HD-03 deleted
def test_hd03_is_deleted():
    assert not hasattr(h, "resolve_service_archetype")
    assert set(inspect.signature(kind).parameters) == {"svc", "archetype", "intent"}   # no `files`: no HCL read


def test_legacy_kinds_come_from_the_typed_intent():
    intent = legacy_intent("gke-autopilot", ["engine", "edge-gateway"])
    assert intent.topology is None
    assert kind("engine", "gke-autopilot", intent) == "gke-autopilot"        # primary
    assert kind("edge-gateway", "gke-autopilot", intent) == "cloudrun"       # planned secondary
    assert kind("edge_gateway", "gke-autopilot", intent) == "cloudrun"       # directory spelling, as the topology path


@pytest.mark.parametrize("directory", ["Edge_Svc", "edge_svc", "EDGE-SVC", "edge-svc"])
def test_directory_name_is_normalized_like_the_intent_names(directory):
    """W8 review F1: `apps/Edge_Svc/` is the planned `edge-svc` (normalize_service_name: trim, lower, `_` -> `-`),
    on both paths; before, only `_` was mapped, so a mixed-case directory got the primary archetype."""
    intent = legacy_intent("gke-autopilot", ["engine", "edge-svc"])
    assert kind(directory, "gke-autopilot", intent) == "cloudrun"
    raw = {"services": [{"name": "engine", "kind": "gke-autopilot"}, {"name": "edge-svc", "kind": "cloudrun"}],
           "primary_service": "engine", "edges": [], "resources": []}
    vt, diags = validate_service_topology(raw, product_id=PID)
    assert vt is not None, [(d.code, d.message) for d in diags]
    topo_intent = ComputeIntent(archetype="gke-autopilot", service_names=vt.names, source="architect.service_topology",
                                archetype_source="architect.service_topology", topology=vt)
    assert kind(directory, "gke-autopilot", topo_intent) == "cloudrun"


@pytest.mark.parametrize("svc", ["api", "web", "storefront", "ingress", "edge"])
def test_an_unplanned_directory_is_never_turned_into_cloud_run_by_its_name(svc):
    """HD-03 step 3 deployed any GKE-fleet directory whose name contained `api` / `web` / ... as a Cloud Run service
    through CI (outside IaC). Now an unplanned directory gets the primary archetype, as on the topology path."""
    assert kind(svc, "gke-autopilot", legacy_intent("gke-autopilot", ["engine"])) == "gke-autopilot"


def test_ai_hcl_naming_another_kind_does_not_change_a_planned_service():
    """HD-03 read the AI's custom.tf: a `compute-event-worker` module labelled after the service made its workflow a
    Cloud Run Job deploy. The kind is the plan's; nothing reads the HCL (no `files` argument at all)."""
    intent = legacy_intent("cloudrun", ["shop", "worker"])
    assert kind("worker", "cloudrun", intent) == "cloudrun"
    assert kind("shop", "cloudrun", intent) == "cloudrun"


@pytest.mark.parametrize("svcs", [["shop"], ["shop", "api", "worker"]])
def test_negative_cloud_run_workload_every_kind_stays_cloudrun(svcs):
    """Do No Harm: a Cloud Run workload (the default archetype) gets `cloudrun` for every directory, which is what
    HD-03 returned for it when no AI HCL named another kind (its name step ran only on GKE workloads)."""
    intent = legacy_intent("cloudrun", svcs)
    for svc in svcs + ["unplanned"]:
        assert kind(svc, "cloudrun", intent) == "cloudrun"


def test_negative_topology_path_is_unchanged():
    raw = {"services": [{"name": "engine", "kind": "gke-autopilot"}, {"name": "edge", "kind": "cloudrun"}],
           "primary_service": "engine", "edges": [], "resources": []}
    vt, diags = validate_service_topology(raw, product_id=PID)
    assert vt is not None, [(d.code, d.message) for d in diags]
    intent = ComputeIntent(archetype="gke-autopilot", service_names=vt.names, source="architect.service_topology",
                           archetype_source="architect.service_topology", topology=vt)
    assert kind("engine", "gke-autopilot", intent) == "gke-autopilot"
    assert kind("edge", "gke-autopilot", intent) == "cloudrun"
    assert kind("other", "gke-autopilot", intent) == "gke-autopilot"


# ============================================================================================ W8-2: verifier (RT file)
FOUNDATION_OLD = "# an older vendored foundation version, kept by the repository\n"
GKE_MAIN = ('module "foundation" {\n  source = "../modules/workload-foundation/base"\n}\n\n'
            'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n')


def _gke_tree(**extra):
    tree = {MAIN: GKE_MAIN,
            "infra/modules/workload-foundation/base/main.tf": FOUNDATION_OLD,
            "infra/modules/compute-gke-autopilot/main.tf": "# vendored gke module\n"}
    tree.update(extra)
    return tree


def test_verifier_takes_no_archetype():
    v = SynthesisVerifierAgent(PID)
    assert "archetype" not in inspect.signature(v.verify_and_cure).parameters
    assert "archetype" not in inspect.signature(v.reconcile_iac_module_vendoring).parameters


def test_negative_fully_vendored_tree_is_byte_identical():
    """Do No Harm: every referenced module has files (the foundation's differ from the catalog) -> nothing changes,
    through step 4b alone and through the whole cure."""
    tree = _gke_tree()
    cured, errors = SynthesisVerifierAgent(PID).reconcile_iac_module_vendoring(dict(tree))
    assert cured == tree and errors == []
    cured, passed, errs = SynthesisVerifierAgent(PID).verify_and_cure(dict(tree), product_id=PID)
    assert passed, errs
    assert cured == tree


def test_missing_module_adds_only_that_module_and_rewrites_nothing():
    """FD22-09: a GKE tree with one unvendored module used to get the foundation module rewritten from the catalog
    and an unused compute-cloudrun module (the cure ran with the "cloudrun" default). Now exactly the missing
    module's files are added."""
    tree = _gke_tree(**{CUSTOM: 'module "events" {\n  source = "../modules/messaging-pubsub"\n}\n'})
    cured, errors = SynthesisVerifierAgent(PID).reconcile_iac_module_vendoring(dict(tree))
    assert errors == []
    added = sorted(set(cured) - set(tree))
    assert added and all(p.startswith("infra/modules/messaging-pubsub/") for p in added), added
    assert {p: cured[p] for p in tree} == tree                     # every existing file byte-identical
    assert not any(p.startswith("infra/modules/compute-cloudrun/") for p in cured)


def test_unknown_missing_module_is_still_an_error():
    tree = _gke_tree(**{CUSTOM: 'module "x" {\n  source = "../modules/not-a-catalog-module"\n}\n'})
    import unittest.mock as um
    with um.patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        cured, errors = SynthesisVerifierAgent(PID).reconcile_iac_module_vendoring(dict(tree))
    assert cured == tree
    assert errors and "not-a-catalog-module" in errors[0]


# ============================================================================================ W8-3: HB-27 copy
def _commit_fn():
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8").read()
    return next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "commit_and_open_pr")


def test_precommit_gate_runs_the_package_pass_once():
    called = {c.func.attr for c in ast.walk(_commit_fn()) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
    assert "purge_shadowed_package_files" not in called
    assert "verify_and_cure" in called


@pytest.mark.parametrize("tree", [
    {"apps/shop/main.py": "import routers.items\n", "apps/shop/routers/items.py": "x = 1\n",
     "apps/shop/requirements.txt": "fastapi==0.110.0\n"},
    {"apps/shop/main.py": "import yaml\n", "apps/shop/yaml/local.py": "x = 1\n",            # shielded (PyYAML)
     "apps/shop/requirements.txt": "PyYAML==6.0.1\n", "apps/shop/migrations/env.py": "y = 2\n"},
    {"apps/shop/main.py": "print(1)\n", "apps/shop/__init__.py": "# kept\n"},             # nothing to add
])
def test_negative_one_pass_equals_the_old_two_passes(tree):
    """Do No Harm / no behavior change: the deleted separate pass and verify_and_cure's step 0 are the same add-only
    rule, so curing the pre-purged tree (old) and the tree itself (new) gives identical bytes."""
    v = SynthesisVerifierAgent(PID)
    purged, _ = v.purge_shadowed_package_files(dict(tree))
    old, ok_old, err_old = v.verify_and_cure(purged, product_id=PID)
    new, ok_new, err_new = v.verify_and_cure(dict(tree), product_id=PID)
    assert new == old and (ok_new, err_new) == (ok_old, err_old)
    assert {p: new[p] for p in tree} == tree                     # the existing files themselves are untouched

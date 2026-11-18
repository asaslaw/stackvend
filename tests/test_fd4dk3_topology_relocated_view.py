"""FD4DK-3 (FD-4DK second RT F1): the topology-path connector rule (topology_wiring.topology_vpc_connector) reads the
assembled root module WITHOUT the AI's relocated draft keys, at both call sites (HB-04 secondaries in
terraform_engine.reconcile_multi_service_declarations, the primary's main.tf render in handler._assemble_tree), and
checks the connector's region / project as the legacy rule does.

assemble_root_module appends the AI's main.tf / variables.tf / outputs.tf / moved.tf drafts to custom.tf and leaves
them at their own key (full original text) until the golden render: read on the full tree, every database /
connector / subnet the AI wrote in main.tf was a duplicate and the typed rule silently returned None (Gate B S5-r1
shape). Do No Harm: without such a draft every render is byte-identical (corpus replay in
docs/handoff/fd4dk-3-report.md; negative tests below). Hermetic, offline."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402,F401
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt or put eval/.deps on "
                "PYTHONPATH; this file is acceptance evidence and must not skip", pytrace=False)

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF, assemble_root_module  # noqa: E402
from developer_agent.topology_wiring import topology_vpc_connector  # noqa: E402
from test_platform_db_connector_wiring import (CUSTOM_08, CUSTOM_S5, REDIS_CONSUMER, SQL_CONSUMER, SVC,  # noqa: E402
                                               compute_body, tree, vt_of)

W = "infra/workload/"
MAIN_TF = W + "main.tf"
REF = "google_vpc_access_connector.connector.id"
LINE = f"  vpc_access_connector  = {REF}\n"


def _assemble(draft):
    return assemble_root_module(draft, llm_paths=list(draft), preexisting=(), root_keys=set())


def _view(asm, files=None):
    """The handler's expression at both call sites."""
    return {p: t for p, t in (asm.files if files is None else files).items() if p not in asm.relocated_draft_paths}


# ------------------------------------------------------------------------------------------------ primary (handler view)
@pytest.mark.parametrize("custom,consumer", [(CUSTOM_S5, REDIS_CONSUMER), (CUSTOM_08, SQL_CONSUMER)])
def test_connector_in_the_ai_main_tf_draft_is_wired(custom, consumer):
    """Gate B S5-r1 shape: database, connector and its subnet written in the AI's main.tf."""
    asm = _assemble({MAIN_TF: custom})
    assert MAIN_TF in asm.relocated_draft_paths and MAIN_TF in asm.files   # still keyed until the golden render
    vt = vt_of([consumer])
    assert topology_vpc_connector(vt, SVC, asm.files) is None   # main's view: every block counted twice
    assert topology_vpc_connector(vt, SVC, _view(asm)) == REF


def test_only_part_of_the_facts_in_the_main_tf_draft_is_wired_too():
    """Connector + subnet in the AI's main.tf, Redis + network in its custom.tf."""
    split = CUSTOM_S5.index('resource "google_compute_subnetwork"')
    asm = _assemble({CUSTOM_TF: CUSTOM_S5[:split], MAIN_TF: CUSTOM_S5[split:]})
    vt = vt_of([REDIS_CONSUMER])
    assert topology_vpc_connector(vt, SVC, asm.files) is None
    assert topology_vpc_connector(vt, SVC, _view(asm)) == REF


def test_the_view_never_hides_a_declaration_that_exists_once():
    """Do No Harm: the facts only in custom.tf (no relocated draft, or one without them) give the same answer with the
    view as with the full tree, wired or refused."""
    secret = 'resource "google_secret_manager_secret" "s" {\n  secret_id = "s"\n  replication {\n    auto {}\n  }\n}\n'
    for draft in ({CUSTOM_TF: CUSTOM_S5}, {CUSTOM_TF: CUSTOM_S5, MAIN_TF: secret}):
        asm = _assemble(draft)
        for vt in (vt_of([REDIS_CONSUMER]), vt_of([])):
            assert topology_vpc_connector(vt, SVC, _view(asm)) == topology_vpc_connector(vt, SVC, asm.files)
    assert topology_vpc_connector(vt_of([REDIS_CONSUMER]), SVC, _view(_assemble({CUSTOM_TF: CUSTOM_S5}))) == REF


def test_two_connectors_in_the_draft_are_still_refused():
    """The view removes the stale copy only: a real second connector is still never chosen between."""
    second = CUSTOM_S5 + '''
resource "google_vpc_access_connector" "connector_b" {
  name   = "conn-b"
  region = var.region
  subnet {
    name = google_compute_subnetwork.connector_subnet.name
  }
}
'''
    asm = _assemble({MAIN_TF: second})
    assert topology_vpc_connector(vt_of([REDIS_CONSUMER]), SVC, _view(asm)) is None


# ------------------------------------------------------------------------------------------------ secondaries (reconcile)
def _reconcile(files, vt, **kw):
    te.reconcile_multi_service_declarations(
        files=files, product_id="p", spec_text="", archetype=vt.archetype, assembly_record=kw.pop("record"),
        llm_iac_paths=kw.pop("llm_iac_paths"), target_services=list(vt.names), topology=vt, **kw)
    return files


def _api_vt():
    return vt_of([dict(SQL_CONSUMER, consumers=[{"service": "api", "env_key": "DB_HOST",
                                               "attribute": "private_ip_address"}])],
                 services=((SVC, "cloudrun"), ("api", "cloudrun")))


def _apps():
    return {"apps/api/main.py": "x = 1\n", f"apps/{SVC}/main.py": "x = 1\n"}


def _run(draft, with_paths):
    asm = _assemble(draft)
    files = dict(asm.files, **_apps())
    kw = dict(record=asm.record, llm_iac_paths=list(asm.llm_iac_paths))
    if with_paths:
        kw["relocated_draft_paths"] = asm.relocated_draft_paths
    return _reconcile(files, _api_vt(), **kw)


def test_secondary_consumer_gets_the_connector_from_the_ai_main_tf_draft():
    before = _run({MAIN_TF: CUSTOM_08}, with_paths=False)   # main: no route
    after = _run({MAIN_TF: CUSTOM_08}, with_paths=True)
    assert "vpc_access_connector" not in before[te.SERVICES_TF]
    assert compute_body(after[te.SERVICES_TF], "compute_api")["vpc_access_connector"] == "${" + REF + "}"
    assert after[te.SERVICES_TF].replace(LINE, "", 1) == before[te.SERVICES_TF]   # exactly one line added
    assert {k: v for k, v in after.items() if k != te.SERVICES_TF} == \
        {k: v for k, v in before.items() if k != te.SERVICES_TF}


@pytest.mark.parametrize("draft", [{CUSTOM_TF: CUSTOM_08}, {CUSTOM_TF: CUSTOM_08, MAIN_TF: "# a comment\n"}])
def test_secondaries_without_a_relocated_fact_are_byte_identical(draft):
    """Do No Harm: the keyword changes nothing when no relocated draft holds a fact (wired or not)."""
    assert _run(draft, with_paths=True) == _run(draft, with_paths=False)
    files = {CUSTOM_TF: CUSTOM_08, **_apps()}
    plain = _reconcile(dict(files), _api_vt(), record=_assemble(files).record, llm_iac_paths=[CUSTOM_TF])
    assert _reconcile(dict(files), _api_vt(), record=_assemble(files).record, llm_iac_paths=[CUSTOM_TF],
                      relocated_draft_paths=()) == plain


# ------------------------------------------------------------------------------------------------ region / project check
def _with(custom, line):
    return custom.replace('resource "google_vpc_access_connector" "connector" {\n',
                          'resource "google_vpc_access_connector" "connector" {\n' + line, 1)


@pytest.mark.parametrize("region,expected", [("var.region", REF), ('"us-central1"', None), ("var.connector_region", None),
                                             ("local.region", None)])
def test_topology_rule_needs_the_platform_region(region, expected):
    custom = CUSTOM_08.replace("  region        = var.region\n  ip_cidr_range",
                               f"  region        = {region}\n  ip_cidr_range")
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(custom)) == expected


def test_topology_rule_accepts_an_absent_region():
    custom = CUSTOM_08.replace("  region        = var.region\n  ip_cidr_range", "  ip_cidr_range")
    assert "google_vpc_access_connector" in custom and custom != CUSTOM_08
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(custom)) == REF


@pytest.mark.parametrize("project,expected", [("var.project_id", REF), ('"host-project"', None),
                                              ("var.host_project", None)])
def test_topology_rule_needs_the_workload_project(project, expected):
    custom = _with(CUSTOM_S5, f"  project = {project}\n")
    assert topology_vpc_connector(vt_of([REDIS_CONSUMER]), SVC, tree(custom)) == expected


# ------------------------------------------------------------------------------------------------ call sites (AST pins)
def _handler_tree():
    with open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8") as fh:
        return ast.parse(fh.read())


def test_handler_passes_the_relocated_free_view_at_both_call_sites():
    calls = [n for n in ast.walk(_handler_tree()) if isinstance(n, ast.Call)]
    rec = [c for c in calls if getattr(c.func, "id", None) == "reconcile_multi_service_declarations"]
    assert len(rec) == 1
    assert {k.arg: ast.unparse(k.value) for k in rec[0].keywords}["relocated_draft_paths"] == \
        "assembly.relocated_draft_paths"
    topo = [c for c in calls if getattr(c.func, "id", None) == "topology_vpc_connector"]
    assert [ast.unparse(c) for c in topo] == [
        "topology_vpc_connector(vt, vt.primary.name, {p: t for p, t in files.items() "
        "if p not in assembly.relocated_draft_paths})"]


def test_reconcile_reads_the_connector_from_the_view_only():
    with open(os.path.join(GATEWAY, "developer_agent", "terraform_engine.py"), encoding="utf-8") as fh:
        tree_ = ast.parse(fh.read())
    topo = [n for n in ast.walk(tree_) if isinstance(n, ast.Call) and getattr(n.func, "id", None) ==
            "topology_vpc_connector"]
    assert [ast.unparse(c) for c in topo] == [
        "topology_vpc_connector(topology, clean_s_name, {p: t for p, t in files.items() if p not in relocated_drafts})"]

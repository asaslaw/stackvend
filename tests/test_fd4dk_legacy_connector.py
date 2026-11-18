"""FD-4DK (FD-4AA remainder): the legacy (no service topology) path renders the VPC connector of a private database /
cache from the workload's parsed IaC, and the report-only validator V2m measures a private-IP database that no compute
service can reach.

Legacy rule (topology_wiring.legacy_vpc_connector): a root-module Cloud SQL / Redis / AlloyDB cluster declared once
with an exact network reference, and exactly one root-module connector (no count / for_each, region absent or exactly
var.region) on that network -> every platform-rendered Cloud Run module of the legacy workload gets
`vpc_access_connector = google_vpc_access_connector.<c>.id`. Anything else -> None and the renders are byte-identical
(Do No Harm). The topology rule (topology_vpc_connector) is unchanged: tests/test_platform_db_connector_wiring.py.
Hermetic, offline."""
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
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt or put eval/.deps on "
                "PYTHONPATH; this file is acceptance evidence and must not skip", pytrace=False)

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF, assemble_root_module  # noqa: E402
from developer_agent.topology_wiring import legacy_vpc_connector, topology_vpc_connector  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.private_reach import CODE, PrivateDatabaseReachValidator, register  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402
from test_platform_db_connector_wiring import (CUSTOM_08, CUSTOM_S5, CUSTOM_S5_VAR, SQL_CONSUMER, SVC,  # noqa: E402
                                               compute_body, tree, vt_of)

W = "infra/workload/"
MAIN_TF = W + "main.tf"
REF = "google_vpc_access_connector.connector.id"

ALLOYDB = '''resource "google_compute_network" "vpc" {
  name                    = "vpc"
  auto_create_subnetworks = false
}

resource "google_alloydb_cluster" "db" {
  cluster_id = "db"
  location   = var.region
  network_config {
    network = google_compute_network.vpc.id
  }
}

resource "google_alloydb_instance" "primary" {
  cluster       = google_alloydb_cluster.db.name
  instance_id   = "primary"
  instance_type = "PRIMARY"
}

resource "google_vpc_access_connector" "connector" {
  name          = "conn"
  region        = var.region
  ip_cidr_range = var.connector_cidr
  network       = google_compute_network.vpc.name
}
'''


def _swap(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


# ------------------------------------------------------------------------------------------------ the legacy rule
@pytest.mark.parametrize("custom", [CUSTOM_08, CUSTOM_S5, CUSTOM_S5_VAR, ALLOYDB], ids=["sql", "redis-subnet",
                                                                                        "redis-var", "alloydb"])
def test_private_database_and_one_connector_on_its_network_wire_the_connector(custom):
    assert legacy_vpc_connector(tree(custom)) == REF


def test_connector_without_a_region_is_the_provider_region():
    custom = _swap(CUSTOM_08, '  region        = var.region\n  ip_cidr_range', '  ip_cidr_range')
    assert legacy_vpc_connector(tree(custom)) == REF


# ---- negative: nothing is rendered without the exact facts (Do No Harm)
def test_no_private_database_no_connector():
    conn_only = CUSTOM_08.split('resource "google_sql_database_instance"')[0]
    assert legacy_vpc_connector(tree(conn_only)) is None
    assert legacy_vpc_connector({}) is None and legacy_vpc_connector(None) is None


def test_public_cloud_sql_without_private_network_is_not_a_fact():
    custom = _swap(CUSTOM_08, "      private_network = google_compute_network.private_network.id\n", "")
    assert legacy_vpc_connector(tree(custom)) is None


def test_no_connector_no_wiring():
    custom = CUSTOM_08.split('resource "google_vpc_access_connector"')[0] + \
        'resource "google_sql_database_instance"' + CUSTOM_08.split('resource "google_sql_database_instance"')[1]
    assert legacy_vpc_connector(tree(custom)) is None


def test_two_connectors_on_the_network_are_never_chosen_between():
    second = '''
resource "google_vpc_access_connector" "other" {
  name          = "cr-conn-2"
  region        = var.region
  ip_cidr_range = var.connector_cidr
  network       = google_compute_network.private_network.id
}
'''
    assert legacy_vpc_connector(tree(CUSTOM_08 + second)) is None


def test_connector_on_another_network_is_not_wired():
    other = '''
resource "google_compute_network" "other" {
  name = "other"
}
'''
    custom = _swap(CUSTOM_08, "  network       = google_compute_network.private_network.name\n",
                   "  network       = google_compute_network.other.name\n") + other
    assert legacy_vpc_connector(tree(custom)) is None


@pytest.mark.parametrize("meta", ["  count = 1\n", '  for_each = toset(["a"])\n'])
def test_indexed_connector_is_not_wired(meta):
    custom = _swap(CUSTOM_08, '  name          = "cr-conn"\n', '  name          = "cr-conn"\n' + meta)
    assert legacy_vpc_connector(tree(custom)) is None


@pytest.mark.parametrize("region", ['"us-central1"', "var.connector_region", "local.region"])
def test_connector_region_other_than_var_region_is_not_wired(region):
    custom = _swap(CUSTOM_08, "  region        = var.region\n  ip_cidr_range",
                   f"  region        = {region}\n  ip_cidr_range")
    assert legacy_vpc_connector(tree(custom)) is None


@pytest.mark.parametrize("project,expected", [("var.project_id", REF), ('"host-project"', None),
                                              ("var.host_project", None)])
def test_connector_project_must_be_the_workload_project(project, expected):
    """FD-4DK RT F7: a connector in another project (Shared VPC) needs grants the platform does not render."""
    custom = _swap(CUSTOM_08, '  name          = "cr-conn"\n', f'  name          = "cr-conn"\n  project = {project}\n')
    assert legacy_vpc_connector(tree(custom)) == expected


def test_ai_main_tf_draft_is_read_once_where_the_assembly_put_it():
    """FD-4DK RT F1: the AI's main.tf draft is appended to custom.tf and keeps its key until the golden render; the
    handler's view without the relocated draft keys sees each declaration once (the full tree would see two)."""
    asm = assemble_root_module({MAIN_TF: CUSTOM_08}, llm_paths=[MAIN_TF], preexisting=(), root_keys=set())
    assert MAIN_TF in asm.relocated_draft_paths and MAIN_TF in asm.files
    assert legacy_vpc_connector(asm.files) is None   # every resource counted twice: nothing is guessed
    view = {p: t for p, t in asm.files.items() if p not in asm.relocated_draft_paths}
    assert legacy_vpc_connector(view) == REF


def test_literal_networks_are_never_compared():
    custom = _swap(_swap(CUSTOM_08, "      private_network = google_compute_network.private_network.id\n",
                         '      private_network = "projects/p/global/networks/vpc"\n'),
                   "  network       = google_compute_network.private_network.name\n", '  network       = "vpc"\n')
    assert legacy_vpc_connector(tree(custom)) is None


def test_database_declared_twice_or_in_an_unparseable_or_nested_file():
    dup = 'resource "google_sql_database_instance"' + CUSTOM_08.split('resource "google_sql_database_instance"')[1]
    dup = dup.split('resource "google_secret_manager_secret"')[0]
    assert legacy_vpc_connector({CUSTOM_TF: CUSTOM_08, W + "db.tf": dup}) is None
    assert legacy_vpc_connector({CUSTOM_TF: CUSTOM_08 + "\nresource {\n"}) is None
    assert legacy_vpc_connector({W + "sub/custom.tf": CUSTOM_08}) is None


def test_topology_rule_is_unchanged_by_the_legacy_rule():
    """The topology path still needs the typed consumer edge (no edge -> None even though the legacy rule fires)."""
    assert topology_vpc_connector(vt_of([]), SVC, tree(CUSTOM_08)) is None
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(CUSTOM_08)) == REF
    assert legacy_vpc_connector(tree(CUSTOM_08)) == REF


# ------------------------------------------------------------------------------------------------ rendering
def _legacy_reconcile(files, **kw):
    te.reconcile_multi_service_declarations(
        files=files, product_id="p", spec_text="", archetype="cloudrun", assembly_record=AssemblyRecord(),
        llm_iac_paths=[CUSTOM_TF], target_services=["web", "api"], **kw)
    return files


def _legacy_tree():
    return {CUSTOM_TF: CUSTOM_08, "apps/web/main.py": "x = 1\n", "apps/api/main.py": "x = 1\n"}


GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "fd4dk_main_render")


def _golden(name):
    with open(os.path.join(GOLDEN_DIR, name), encoding="utf-8") as fh:
        return fh.read()


def test_legacy_renders_without_connector_equal_mains_render():
    """FD-4DK RT F9: the golden files are main's (a04867fe) legacy renders, captured once from a main export; the
    branch with no connector must equal them byte for byte, and with it they gain exactly one line per module."""
    base = _legacy_reconcile(_legacy_tree())
    assert base[CUSTOM_TF] == _golden("legacy_custom_two_services.tf.golden")
    wired = _legacy_reconcile(_legacy_tree(), legacy_vpc_connector=REF)[CUSTOM_TF]
    assert wired.replace(f"  vpc_access_connector  = {REF}\n", "", 1) == base[CUSTOM_TF]
    kw = dict(service_name="web", custom_tf_content=CUSTOM_08)
    main = _golden("legacy_main_web.tf.golden")
    assert te.generate_golden_main_tf("p", "cloudrun", "", **kw) == main
    assert te.generate_golden_main_tf("p", "cloudrun", "", vpc_access_connector=REF, **kw).replace(
        f"  vpc_access_connector  = {REF}\n", "", 1) == main


def test_legacy_secondary_without_connector_is_byte_identical():
    """Do No Harm: the new keyword left at None (or absent) renders exactly today's secondaries."""
    base = _legacy_reconcile(_legacy_tree())
    assert _legacy_reconcile(_legacy_tree(), legacy_vpc_connector=None) == base
    assert "vpc_access_connector" not in base[CUSTOM_TF].split('module "compute_api"')[1]


def test_legacy_secondary_gets_exactly_the_connector_line():
    base = _legacy_reconcile(_legacy_tree())
    wired = _legacy_reconcile(_legacy_tree(), legacy_vpc_connector=REF)
    assert wired[CUSTOM_TF].replace(f"  vpc_access_connector  = {REF}\n", "", 1) == base[CUSTOM_TF]
    assert compute_body(wired[CUSTOM_TF], "compute_api")["vpc_access_connector"] == "${" + REF + "}"
    assert {k: v for k, v in wired.items() if k != CUSTOM_TF} == {k: v for k, v in base.items() if k != CUSTOM_TF}


def test_topology_secondaries_ignore_the_legacy_keyword():
    vt = vt_of([], services=((SVC, "cloudrun"), ("api", "cloudrun")))

    def run(**kw):
        files = {CUSTOM_TF: CUSTOM_08, "apps/api/main.py": "x = 1\n", f"apps/{SVC}/main.py": "x = 1\n"}
        te.reconcile_multi_service_declarations(
            files=files, product_id="p", spec_text="", archetype=vt.archetype, assembly_record=AssemblyRecord(),
            llm_iac_paths=[CUSTOM_TF], target_services=list(vt.names), topology=vt, **kw)
        return files
    assert run(legacy_vpc_connector=REF) == run()


def test_legacy_primary_render_is_main_plus_one_line():
    kw = dict(service_name="web", custom_tf_content=CUSTOM_08)
    base = te.generate_golden_main_tf("p", "cloudrun", "", **kw)
    wired = te.generate_golden_main_tf("p", "cloudrun", "", vpc_access_connector=legacy_vpc_connector(tree(CUSTOM_08)),
                                       **kw)
    assert wired.replace(f"  vpc_access_connector  = {REF}\n", "", 1) == base
    assert te.generate_golden_main_tf("p", "cloudrun", "", vpc_access_connector=None, **kw) == base


def _handler_calls(name):
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py")).read()
    tree_ = ast.parse(src)
    return tree_, [n for n in ast.walk(tree_) if isinstance(n, ast.Call) and getattr(n.func, "id", None) == name]


def test_handler_computes_the_legacy_connector_once_only_without_a_topology():
    tree_, _ = _handler_calls("legacy_vpc_connector")
    assigns = [n for n in ast.walk(tree_) if isinstance(n, ast.Assign)
               and any(getattr(t, "id", None) == "legacy_connector" for t in n.targets)]
    assert len(assigns) == 1
    assert ast.unparse(assigns[0].value) == (
        "legacy_vpc_connector({p: t for p, t in files.items() if p not in assembly.relocated_draft_paths}) "
        "if vt is None and inputs.iac_intent is None else None")


def test_handler_passes_it_to_the_legacy_secondaries_and_the_primary():
    _, calls = _handler_calls("reconcile_multi_service_declarations")
    assert len(calls) == 1
    kw = {k.arg: ast.unparse(k.value) for k in calls[0].keywords}
    assert kw["legacy_vpc_connector"] == "legacy_connector"
    _, mains = _handler_calls("generate_golden_main_tf")
    wired = [c for c in mains if any(k.arg == "vpc_access_connector" for k in c.keywords)]
    assert len(wired) == 1
    value = ast.unparse(next(k for k in wired[0].keywords if k.arg == "vpc_access_connector").value)
    assert value == ("topology_vpc_connector(vt, vt.primary.name, {p: t for p, t in files.items() "
                     "if p not in assembly.relocated_draft_paths}) if vt is not None and vt.primary is not None "
                     "else legacy_connector")   # FD4DK-3: the topology rule reads the same relocated-free view


# ------------------------------------------------------------------------------------------------ V2m (report only)
def _main(connector=None):
    return te.generate_golden_main_tf("p", "cloudrun", "", service_name="web", vpc_access_connector=connector)


def _found(files):
    ctx = ValidationContext.build(files, ownership=lambda p: None)
    return PrivateDatabaseReachValidator().validate(ctx)


def test_v2m_reports_a_private_database_no_service_can_reach():
    """FDCSQL fresh 08-r3 / 08-r2 shape: a private-IP Cloud SQL, a Cloud Run service, no connector anywhere."""
    custom = CUSTOM_08.split('resource "google_vpc_access_connector"')[0] + \
        'resource "google_sql_database_instance"' + CUSTOM_08.split('resource "google_sql_database_instance"')[1]
    found = _found({MAIN_TF: _main(), CUSTOM_TF: custom})
    assert [(d.code, d.severity, d.block_address, d.file) for d in found] == [
        (CODE, "warning", "google_sql_database_instance.postgres", CUSTOM_TF)]
    assert "google_sql_database_instance.postgres" in found[0].hint


def test_v2m_reports_a_declared_connector_no_service_uses():
    found = _found({MAIN_TF: _main(), CUSTOM_TF: CUSTOM_08})
    assert [d.block_address for d in found] == ["google_sql_database_instance.postgres"]


def test_v2m_silent_when_a_service_has_the_connector():
    assert _found({MAIN_TF: _main(REF), CUSTOM_TF: CUSTOM_08}) == []


@pytest.mark.parametrize("old,new", [
    ("      ipv4_enabled    = false\n", "      ipv4_enabled    = true\n"),       # public IP too
    ("      ipv4_enabled    = false\n", ""),                                   # default: public IP
    ("      private_network = google_compute_network.private_network.id\n", ""),   # no private IP at all
])
def test_v2m_silent_for_a_database_with_a_public_ip(old, new):
    assert _found({MAIN_TF: _main(), CUSTOM_TF: _swap(CUSTOM_08, old, new)}) == []


def test_v2m_silent_without_compute_or_with_vpc_native_compute():
    assert _found({CUSTOM_TF: CUSTOM_08}) == []
    gke = te.generate_golden_main_tf("p", "gke-autopilot", "")
    assert _found({MAIN_TF: gke, CUSTOM_TF: CUSTOM_08}) == []
    assert _found({MAIN_TF: te.generate_golden_main_tf("p", "foundation-only", ""), CUSTOM_TF: CUSTOM_08}) == []


def test_v2m_event_worker_has_no_route():
    worker = te.generate_golden_main_tf("p", "event-worker", "")
    assert [d.block_address for d in _found({MAIN_TF: worker, CUSTOM_TF: CUSTOM_08})] == [
        "google_sql_database_instance.postgres"]


@pytest.mark.parametrize("switch,expected", [(None, 1), ("false", 1), ("true", 0), ("var.public", 0), ('"true"', 0)])
def test_v2m_alloydb_instance_and_its_public_ip_switch(switch, expected):
    custom = ALLOYDB if switch is None else _swap(
        ALLOYDB, '  instance_type = "PRIMARY"\n',
        f'  instance_type = "PRIMARY"\n  network_config {{\n    enable_public_ip = {switch}\n  }}\n')
    found = _found({MAIN_TF: _main(), CUSTOM_TF: custom})
    assert [d.block_address for d in found] == ["google_alloydb_instance.primary"] * expected


@pytest.mark.parametrize("annotations,expected", [
    ("", 1),
    ('    metadata {\n      annotations = {\n        "run.googleapis.com/vpc-access-connector" = '
     'google_vpc_access_connector.c.id\n      }\n    }\n', 0),
    ('    metadata {\n      annotations = {\n        "autoscaling.knative.dev/maxScale" = "3"\n      }\n    }\n', 1),
])
def test_v2m_v1_cloud_run_service_connector_annotation(annotations, expected):
    """FD-4DK RT F6: a v1 google_cloud_run_service routes through its exact template annotation."""
    sql = 'resource "google_sql_database_instance"' + CUSTOM_08.split('resource "google_sql_database_instance"')[1]
    sql = sql.split('resource "google_secret_manager_secret"')[0]
    svc = 'resource "google_cloud_run_service" "s" {\n  name = "s"\n  template {\n' + annotations + '  }\n}\n'
    assert len(_found({MAIN_TF: _main(), CUSTOM_TF: sql + svc})) == expected


@pytest.mark.parametrize("body,expected", [
    ('  source             = "../modules/database-cloudsql"\n  private_network_id = google_compute_network.v.id\n',
     ["module.db"]),
    ('  source             = "../modules/database-cloudsql"\n  private_network_id = google_compute_network.v.id\n'
     '  enable_public_ip   = true\n', []),
    ('  source             = "../modules/database-cloudsql"\n  enable_public_ip   = true\n', []),
    ('  source             = "../modules/database-cloudsql"\n  private_network_id = google_compute_network.v.id\n'
     '  enable_public_ip   = var.public\n', []),
    ('  source             = "../modules/database-cloudsql"\n  private_network_id = google_compute_network.v.id\n'
     '  enable_public_ip   = false\n', ["module.db"]),
    ('  source  = "../modules/database-alloydb"\n  network = google_compute_network.v.id\n', ["module.db"]),
    ('  source  = "../modules/storage-bucket"\n', []),
])
def test_v2m_golden_database_modules(body, expected):
    custom = 'module "db" {\n' + body + '}\n'
    assert [d.block_address for d in _found({MAIN_TF: _main(), CUSTOM_TF: custom})] == expected


@pytest.mark.parametrize("template,expected", [
    ("", 1),
    ("  template {\n    vpc_access {\n      connector = google_vpc_access_connector.c.id\n    }\n  }\n", 0),
    ("  template {\n    vpc_access {\n      network_interfaces {\n        network = \"default\"\n      }\n    }\n  }\n",
     0),
])
def test_v2m_raw_cloud_run_service_routes(template, expected):
    sql = 'resource "google_sql_database_instance"' + CUSTOM_08.split('resource "google_sql_database_instance"')[1]
    sql = sql.split('resource "google_secret_manager_secret"')[0]
    svc = 'resource "google_cloud_run_v2_service" "s" {\n  name = "s"\n' + template + '}\n'
    assert len(_found({CUSTOM_TF: sql + svc})) == expected


def test_v2m_does_not_read_json_or_nested_or_unparseable_files():
    assert _found({W + "custom.tf.json": "{}", W + "sub/custom.tf": CUSTOM_08, MAIN_TF: _main()}) == []
    assert _found({CUSTOM_TF: CUSTOM_08 + "\nresource {\n", MAIN_TF: _main()}) == []


def test_v2m_is_report_only_and_never_fails_the_report():
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V2m") == "report_only"
    assert stack.ids.index("V2m") == stack.ids.index("VD") + 1
    mini = ValidatorStack()
    register(mini)
    report = mini.run(ValidationContext.build({MAIN_TF: _main(), CUSTOM_TF: CUSTOM_08}, ownership=lambda p: None))
    assert report.status == "PASS" and report.diagnostics == []
    assert [d.code for d in report.report_only] == [CODE]

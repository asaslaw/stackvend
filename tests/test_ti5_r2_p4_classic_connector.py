"""TI-5-R2 P4 (owner 10-25, register FOLLOWUPS-1025): on the classic (agent-written Terraform) path a Cloud Run
consumer of AlloyDB or a private Vertex AI endpoint gets the workload's VPC connector by the same exact network rule
as Cloud SQL / Redis (topology_wiring.topology_vpc_connector). Do No Harm: Cloud SQL / Redis decide as before, and a
tree without an exact network, a connector on it, or a typed consumer edge renders nothing. Hermetic, offline."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_platform_db_connector_wiring import (CUSTOM_08, CUSTOM_S5, REDIS_CONSUMER, SQL_CONSUMER, SVC,  # noqa: E402
                                               tree, vt_of)

from developer_agent import topology_wiring as TW  # noqa: E402
from developer_agent.topology_wiring import topology_vpc_connector  # noqa: E402

CONNECTOR = "google_vpc_access_connector.connector.id"

NETWORK = '''resource "google_compute_network" "vpc" {
  name                    = "${var.product_id}-vpc"
  auto_create_subnetworks = false
}

resource "google_vpc_access_connector" "connector" {
  name          = "cr-conn"
  region        = var.region
  ip_cidr_range = var.connector_cidr
  network       = google_compute_network.vpc.name
}
'''

ALLOYDB_TF = NETWORK + '''
resource "google_alloydb_cluster" "ledger_cluster" {
  cluster_id = "ledger"
  location   = var.region
  network_config {
    network = google_compute_network.vpc.id
  }
}

resource "google_alloydb_instance" "ledger" {
  cluster       = google_alloydb_cluster.ledger_cluster.name
  instance_id   = "ledger-primary"
  instance_type = "PRIMARY"
}
'''

VERTEX_TF = NETWORK + '''
data "google_project" "this" {
  project_id = var.project_id
}

resource "google_vertex_ai_endpoint" "scorer" {
  name         = "scorer"
  display_name = "scorer"
  location     = var.region
  network      = "projects/${data.google_project.this.number}/global/networks/${google_compute_network.vpc.name}"
}
'''

ALLOYDB = {"type": "google_alloydb_instance", "logical_name": "ledger",
           "consumers": [{"service": SVC, "env_key": "LEDGER_DB_HOST", "attribute": None}]}
VERTEX = {"type": "google_vertex_ai_endpoint", "logical_name": "scorer",
          "consumers": [{"service": SVC, "env_key": "SCORER_ENDPOINT", "attribute": None}]}


# ------------------------------------------------------------------------------------------------ the table
def test_p4_table_extends_cloud_sql_and_redis_exactly():
    assert TW.CLASSIC_PRIVATE_NETWORK_ATTRS == {
        "google_sql_database_instance": frozenset({"private_ip_address"}),
        "google_redis_instance": frozenset({"host", "port"}),
        "google_alloydb_instance": frozenset({"ip_address"}),
        "google_vertex_ai_endpoint": frozenset({"id", "name"}),
    }
    # the intent-path set and the Cloud SQL / Redis table are unchanged
    assert set(TW.PRIVATE_NETWORK_RESOURCES) == {"google_sql_database_instance", "google_redis_instance"}
    assert set(TW.CLASSIC_PRIVATE_NETWORK_ATTRS) == TW.INTENT_PRIVATE_NETWORK_TYPES


# ------------------------------------------------------------------------------------------------ AlloyDB
@pytest.mark.parametrize("attr", ["name", "id"])
def test_p4_alloydb_consumer_gets_the_connector_on_its_clusters_network(attr):
    tf = ALLOYDB_TF.replace("google_alloydb_cluster.ledger_cluster.name", f"google_alloydb_cluster.ledger_cluster.{attr}")
    assert topology_vpc_connector(vt_of([ALLOYDB]), SVC, tree(tf)) == CONNECTOR


def test_p4_alloydb_explicit_ip_address_attribute_is_the_same():
    explicit = dict(ALLOYDB, consumers=[{"service": SVC, "env_key": "LEDGER_DB_HOST", "attribute": "ip_address"}])
    assert topology_vpc_connector(vt_of([explicit]), SVC, tree(ALLOYDB_TF)) == CONNECTOR


def test_p4_alloydb_negatives():
    vt = vt_of([ALLOYDB])
    # the cluster is not an exact reference
    assert topology_vpc_connector(vt, SVC, tree(ALLOYDB_TF.replace(
        "cluster       = google_alloydb_cluster.ledger_cluster.name", 'cluster       = "projects/p/locations/r/clusters/x"'
    ))) is None
    # the referenced cluster is not declared
    assert topology_vpc_connector(vt, SVC, tree(ALLOYDB_TF.replace(
        "google_alloydb_cluster.ledger_cluster.name", "google_alloydb_cluster.other.name"))) is None
    # a literal cluster network is never compared
    assert topology_vpc_connector(vt, SVC, tree(ALLOYDB_TF.replace(
        "    network = google_compute_network.vpc.id", '    network = "projects/p/global/networks/vpc"'))) is None
    # the connector is on another network
    other = ALLOYDB_TF.replace("network       = google_compute_network.vpc.name",
                               "network       = google_compute_network.other.name") + '''
resource "google_compute_network" "other" {
  name                    = "other"
  auto_create_subnetworks = false
}
'''
    assert topology_vpc_connector(vt, SVC, tree(other)) is None
    # the instance is not at the topology's address
    assert topology_vpc_connector(vt, SVC, tree(ALLOYDB_TF.replace(
        'resource "google_alloydb_instance" "ledger"', 'resource "google_alloydb_instance" "primary"'))) is None
    # no consumer edge, or another service's edge
    assert topology_vpc_connector(vt_of([]), SVC, tree(ALLOYDB_TF)) is None
    other_svc = vt_of([dict(ALLOYDB, consumers=[{"service": "worker", "env_key": "LEDGER_DB_HOST", "attribute": None}])],
                      services=((SVC, "cloudrun"), ("worker", "cloudrun")))
    assert topology_vpc_connector(other_svc, SVC, tree(ALLOYDB_TF)) is None
    assert topology_vpc_connector(other_svc, "worker", tree(ALLOYDB_TF)) == CONNECTOR


# ------------------------------------------------------------------------------------------------ Vertex AI endpoint
def test_p4_vertex_endpoint_consumer_gets_the_connector_on_the_peered_network():
    assert topology_vpc_connector(vt_of([VERTEX]), SVC, tree(VERTEX_TF)) == CONNECTOR
    by_name = dict(VERTEX, consumers=[{"service": SVC, "env_key": "SCORER_NAME", "attribute": "name"}])
    assert topology_vpc_connector(vt_of([by_name]), SVC, tree(VERTEX_TF)) == CONNECTOR


def test_p4_vertex_endpoint_on_a_bare_variable_and_a_data_source_network():
    var_tf = VERTEX_TF.replace("network       = google_compute_network.vpc.name", "network       = var.network_id")
    var_tf = var_tf.replace(
        'network      = "projects/${data.google_project.this.number}/global/networks/${google_compute_network.vpc.name}"',
        "network      = var.network_id")
    assert topology_vpc_connector(vt_of([VERTEX]), SVC, tree(var_tf)) == CONNECTOR
    data_tf = VERTEX_TF + '''
data "google_compute_network" "shared" {
  name = "shared"
}
'''
    data_tf = data_tf.replace("network       = google_compute_network.vpc.name",
                              "network       = data.google_compute_network.shared.id")
    data_tf = data_tf.replace("${google_compute_network.vpc.name}", "${data.google_compute_network.shared.name}")
    assert topology_vpc_connector(vt_of([VERTEX]), SVC, tree(data_tf)) == CONNECTOR


@pytest.mark.parametrize("network", [
    '"projects/my-project/global/networks/vpc"',                                                   # literal
    '"projects/${var.project_id}/global/networks/${google_compute_network.vpc.name}"',             # not the number
    '"projects/${data.google_project.this.number}/regions/${google_compute_network.vpc.name}"',    # other form
    '"projects/${data.google_project.this.number}/global/networks/${google_compute_network.vpc.id}"',  # id, not name
    '"x-projects/${data.google_project.this.number}/global/networks/${google_compute_network.vpc.name}"',
    '"projects/${data.google_project.this.number}/global/networks/${google_compute_network.vpc.name}-x"',
    '"projects/${data.google_project.this.number}/global/networks/${lower(google_compute_network.vpc.name)}"',
])
def test_p4_vertex_network_not_in_the_exact_form_is_never_compared(network):
    tf = VERTEX_TF.replace(
        '"projects/${data.google_project.this.number}/global/networks/${google_compute_network.vpc.name}"', network)
    assert topology_vpc_connector(vt_of([VERTEX]), SVC, tree(tf)) is None


def test_p4_vertex_endpoint_without_a_network_is_public_and_gets_nothing():
    tf = VERTEX_TF.replace(
        '  network      = "projects/${data.google_project.this.number}/global/networks/${google_compute_network.vpc.name}"\n',
        "")
    assert "google_vertex_ai_endpoint" in tf and "global/networks" not in tf
    assert topology_vpc_connector(vt_of([VERTEX]), SVC, tree(tf)) is None


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_p4_dnh_cloud_sql_and_redis_decide_exactly_as_before():
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(CUSTOM_08)) == CONNECTOR
    assert topology_vpc_connector(vt_of([REDIS_CONSUMER]), SVC, tree(CUSTOM_S5)) == CONNECTOR
    conn_name = dict(SQL_CONSUMER, consumers=[{"service": SVC, "env_key": "DB_CONN", "attribute": "connection_name"}])
    assert topology_vpc_connector(vt_of([conn_name]), SVC, tree(CUSTOM_08)) is None


def test_p4_dnh_bigtable_is_not_vpc_bound():
    bigtable = {"type": "google_bigtable_instance", "logical_name": "events",
                "consumers": [{"service": SVC, "env_key": "BIGTABLE_INSTANCE", "attribute": None}]}
    tf = NETWORK + '''
resource "google_bigtable_instance" "events" {
  name = "events"
}
'''
    assert topology_vpc_connector(vt_of([bigtable]), SVC, tree(tf)) is None


def test_p4_dnh_the_no_topology_legacy_rule_is_unchanged():
    # legacy_vpc_connector (FD-4DK, no service topology) reads its own table; a Vertex endpoint is not in it
    assert set(TW.LEGACY_PRIVATE_NETWORK_RESOURCES) == {"google_sql_database_instance", "google_redis_instance",
                                                        "google_alloydb_cluster"}
    assert TW.legacy_vpc_connector(tree(VERTEX_TF)) is None
    assert TW.legacy_vpc_connector(tree(ALLOYDB_TF)) == CONNECTOR   # FD-4DK, as before


def test_p4_template_parts_reads_the_parser_grammar():
    assert TW._template_parts("projects/${data.google_project.p.number}/global/networks/${google_compute_network.v.name}") \
        == ["projects/", ("data", "google_project", "p", "number"), "/global/networks/",
            ("google_compute_network", "v", "name")]
    assert TW._template_parts("plain") == ["plain"]
    assert TW._template_parts("${f(x)}") is None
    assert TW._template_parts(None) is None and TW._template_parts(3) is None


# ------------------------------------------------------------------------------------------------ end to end (render)
@pytest.mark.parametrize("resource,tf", [(ALLOYDB, ALLOYDB_TF), (VERTEX, VERTEX_TF)])
def test_p4_secondary_consumer_render_carries_the_connector(resource, tf):
    from test_platform_db_connector_wiring import _reconcile, compute_body, te
    from developer_agent.assembly import CUSTOM_TF
    vt = vt_of([dict(resource, consumers=[dict(resource["consumers"][0], service="api")])],
               services=((SVC, "cloudrun"), ("api", "cloudrun")))
    files = _reconcile({CUSTOM_TF: tf, "apps/api/main.py": "x = 1\n", f"apps/{SVC}/main.py": "x = 1\n"}, vt)
    assert compute_body(files[te.SERVICES_TF], "compute_api")["vpc_access_connector"] == \
        "${google_vpc_access_connector.connector.id}"
    # without the consumer edge the render is unchanged (no connector line)
    bare = _reconcile({CUSTOM_TF: tf, "apps/api/main.py": "x = 1\n", f"apps/{SVC}/main.py": "x = 1\n"},
                      vt_of([], services=((SVC, "cloudrun"), ("api", "cloudrun"))))
    assert "vpc_access_connector" not in bare[te.SERVICES_TF]

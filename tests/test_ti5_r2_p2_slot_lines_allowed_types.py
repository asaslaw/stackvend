"""TI-5-R2 P2 (owner 10-25, register FOLLOWUPS-1025): the typed-intent contract offers "realize it with a `<type>`
resource" only for allow-listed types (the gate's own `allowed_types`), so the AI is never told to write a resource
the gate refuses (IAC.TYPE_NOT_ALLOWED). Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from types import SimpleNamespace

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import ART, UPLOADS, C, II, topo, vt_of  # noqa: E402
from test_typed_iac_ti5c_network_facts import CLOUDSQL, REDIS  # noqa: E402
from shared import service_topology as ST  # noqa: E402

from developer_agent import topology_wiring as TW  # noqa: E402

SUBSCRIPTION = {"type": "google_pubsub_subscription", "logical_name": "jobs", "purpose": "job queue",
                "consumers": [{"service": "shop", "env_key": "JOBS_SUBSCRIPTION", "attribute": None}]}


def _slot_line(vt, art=ART):
    lines = [x for x in C.topology_slot_lines(vt, art) if "infra/workload/iac_intent.json" in x]
    assert len(lines) == 1, lines
    return lines[0]


def test_p2_cloud_sql_and_redis_are_offered_only_their_golden_module():
    line = _slot_line(vt_of(topo([CLOUDSQL, REDIS])))
    assert "google_sql_database_instance" not in ART.allowed_types
    assert "google_redis_instance" not in ART.allowed_types
    assert "a google_sql_database_instance resource" not in line
    assert "a google_redis_instance resource" not in line
    # CLOUDSQL-PASSWORD-BINDING (owner 11-14): the consumer also reads the implied password secret id
    assert ("`db` (google_sql_database_instance; services read password_secret_id, private_ip_address; realize it "
            "with golden module database-cloudsql with grant_workload_secret_access: true)") in line
    assert "`cache` (google_redis_instance; services read host; realize it with golden module cache-redis)" in line


def test_p2_dnh_an_allow_listed_type_keeps_its_resource_option_byte_identical():
    assert "google_storage_bucket" in ART.allowed_types
    line = _slot_line(vt_of(topo([UPLOADS])))
    assert line == ("- In infra/workload/iac_intent.json add exactly one entry with \"realizes\": \"<name>\" for each "
                    "of these topology resources: `uploads` (google_storage_bucket; services read name; realize it "
                    "with golden module storage-bucket or a google_storage_bucket resource). The platform binds the "
                    "services' environment variables to that entry; never declare them twice.")


def test_p2_every_catalog_type_offers_the_resource_option_exactly_when_the_gate_allows_it():
    for rtype in sorted(set(ST.BOOTSTRAP_CATALOG) - set(ST.FOUNDATION_PROVIDED)):
        r = {"type": rtype, "logical_name": "res", "purpose": "p",
             "consumers": [{"service": "shop", "env_key": "RES_VALUE", "attribute": None}]}
        line = _slot_line(vt_of(topo([r])))
        offered = f"a {rtype} resource" in line
        assert offered == (rtype in ART.allowed_types), (rtype, line)
        assert "realize it with golden module" in line or offered, (rtype, line)   # never an empty option list


def test_p2_the_option_follows_the_allow_list_data_not_a_hand_written_table():
    # CLOUDSQL-PASSWORD-BINDING (owner 11-14): a Cloud SQL consumer now always reads a module-only attribute (the
    # password secret id), so even a widened allow-list never offers its resource option; Redis shows the data rule
    vt = vt_of(topo([REDIS]))
    widened = SimpleNamespace(allowed_types={**ART.allowed_types, "google_redis_instance": {}})
    assert "or a google_redis_instance resource" in _slot_line(vt, widened)
    sql = SimpleNamespace(allowed_types={**ART.allowed_types, "google_sql_database_instance": {}})
    assert "a google_sql_database_instance resource" not in _slot_line(vt_of(topo([CLOUDSQL])), sql)
    narrowed = SimpleNamespace(allowed_types={t: s for t, s in ART.allowed_types.items()
                                              if t != "google_storage_bucket"})
    line = _slot_line(vt_of(topo([UPLOADS])), narrowed)
    assert "a google_storage_bucket resource" not in line and "golden module storage-bucket" in line


def test_p2_no_realization_at_all_fails_loudly_typed():
    assert not any(t == "google_pubsub_subscription" for (_m, t) in II.REALIZATION_EXPORTS)
    vt = vt_of(topo([SUBSCRIPTION]))
    assert "a google_pubsub_subscription resource" in _slot_line(vt)   # allow-listed today: offered
    with pytest.raises(II.IntentGateUnavailable) as e:
        C.topology_slot_lines(vt, SimpleNamespace(allowed_types={}))
    assert e.value.code == "GATE.IAC_INTENT_ARTIFACT_INCONSISTENT"
    assert e.value.error_class == II.ErrorClass.GATE_UNAVAILABLE


def test_p2_default_artifacts_are_the_gate_artifacts():
    vt = vt_of(topo([CLOUDSQL, UPLOADS]))
    assert C.topology_slot_lines(vt) == C.topology_slot_lines(vt, ART)


def test_p2_run_context_and_typed_lead_contract_carry_the_same_lines():
    vt = vt_of(topo([CLOUDSQL, UPLOADS]))
    run = C.build_intent_run(vt, {}, artifacts=ART)
    for line in C.topology_slot_lines(vt, ART):
        assert line in run.run_context
        assert line in TW.topology_contract_rule(vt, iac_intent=True)
    assert "a google_sql_database_instance resource" not in run.run_context


def test_p2_dnh_the_classic_contract_is_unchanged():
    vt = vt_of(topo([CLOUDSQL, UPLOADS]))
    classic = TW.topology_contract_rule(vt, iac_intent=False)
    assert ("- Declare these resources in infra/workload/custom.tf with exactly these addresses: "
            "google_sql_database_instance.db, google_storage_bucket.uploads.") in classic
    assert "iac_intent.json" not in classic


def test_p2_no_resources_no_lines():
    assert C.topology_slot_lines(None) == []
    assert C.topology_slot_lines(vt_of(topo([])), SimpleNamespace(allowed_types={})) == []

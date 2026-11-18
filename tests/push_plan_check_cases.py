"""PUSH-PLAN-CHECK: topologies WITHOUT a push edge and the sha256 of what the platform derives from them, pinned with
main `e7cab11b`'s code (before this row). tests/test_push_plan_check.py recomputes the same digests with today's code:
a topology without `pushes` must persist, hash and prompt exactly as before (Do No Harm).

`digests()` imports `shared.service_topology` and the gateway's `developer_agent.iac_intent_contract` /
`developer_agent.topology_wiring` from whatever is first on sys.path, so the pins were produced by running it against
an export of that commit."""
import hashlib
import json

PID = "shop"

TOPOLOGIES = {
    # example 01's shape before this row: one Cloud Run service, a topic it publishes to, a bucket, Firestore
    "event_router": {
        "services": [{"name": "shop", "kind": "cloudrun", "purpose": "ingest and process events",
                      "scaling": {"min_instances": 0, "max_instances": 3, "cpu_always_allocated": False}}],
        "primary_service": "shop", "edges": [],
        "resources": [
            {"type": "google_pubsub_topic", "logical_name": "events", "purpose": "inbound events",
             "consumers": [{"service": "shop", "env_key": "EVENTS_TOPIC", "attribute": "id"}]},
            {"type": "google_storage_bucket", "logical_name": "raw", "purpose": "raw payloads",
             "consumers": [{"service": "shop", "env_key": "RAW_BUCKET", "attribute": None}]},
            {"type": "google_firestore_database", "logical_name": "db", "purpose": "audit records",
             "consumers": [{"service": "shop", "env_key": "FIRESTORE_DB", "attribute": None}]}]},
    # example 03's shape: Cloud Run + a gce-worker it launches, Pub/Sub without push
    "batch_worker": {
        "services": [{"name": "shop", "kind": "cloudrun", "purpose": "api"},
                     {"name": "batch", "kind": "gce-worker", "purpose": "batch",
                      "vm": {"machine_type": "e2-micro", "spot": True, "disk_size_gb": 10}}],
        "primary_service": "shop", "edges": [{"caller": "shop", "callee": "batch", "protocol": "launch"}],
        "resources": [
            {"type": "google_pubsub_topic", "logical_name": "jobs", "purpose": "batch jobs",
             "consumers": [{"service": "shop", "env_key": "JOBS_TOPIC", "attribute": None},
                           {"service": "batch", "env_key": "JOBS_TOPIC", "attribute": None}]}]},
    # two Cloud Run services with an http edge and an event-worker (pubsub edge)
    "multi": {
        "services": [{"name": "shop", "kind": "cloudrun"}, {"name": "api", "kind": "cloudrun"},
                     {"name": "jobs", "kind": "event-worker"}],
        "primary_service": "shop",
        "edges": [{"caller": "shop", "callee": "api", "protocol": "http"},
                  {"caller": "api", "callee": "jobs", "protocol": "pubsub"}],
        "resources": [{"type": "google_storage_bucket", "logical_name": "uploads",
                       "consumers": [{"service": "api", "env_key": "UPLOADS_BUCKET", "attribute": None}]}]},
}


def _h(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digests():
    from shared.service_topology import canonical_topology_json, render_topology_json, validate_service_topology
    from developer_agent.iac_intent_contract import topology_slot_lines
    from developer_agent.topology_wiring import topology_contract_rule
    out = {}
    for name, raw in sorted(TOPOLOGIES.items()):
        vt, diags = validate_service_topology(raw, product_id=PID)
        assert vt is not None, [(d.code, d.message) for d in diags]
        out[name] = {"canonical": _h(canonical_topology_json(vt.intent)), "sha256": vt.sha256,
                     "topology_json": _h(render_topology_json(vt)),
                     "slot_lines": _h("\n".join(topology_slot_lines(vt))),
                     "contract_typed": _h(topology_contract_rule(vt, iac_intent=True)),
                     "contract_classic": _h(topology_contract_rule(vt))}
    return out


# Pinned with main e7cab11b (before PUSH-PLAN-CHECK): `digests()` run on an export of that commit.
PINNED = {
    'batch_worker': {
        'canonical': 'cf2e1cda4690a3ecf5d6363d3c5473561a768e20710ef40b12b472123a8f6bd1',
        'contract_classic': '42c9005cf99182b816aae3cfa2dfcb23c485e0985358a924052d616c47aea9e4',
        'contract_typed': 'c84b87dd155d76102c92833c16b36c79f3d1b13f48aa8587c1a1e69239e942e8',
        'sha256': 'cf2e1cda4690a3ecf5d6363d3c5473561a768e20710ef40b12b472123a8f6bd1',
        'slot_lines': '7ddcb1436ee1fbad965f6af7842c95e4aad5e75f64a2bd1f18f065a975428647',
        'topology_json': '4b5fa6a7950acad2a612b90c92e9ed1a703f107a1dc06d64d91c9f39b0d509ab',
    },
    'event_router': {
        'canonical': 'f021ff56d1117840298297dc10dbca8f1613f22a74fa3034746256427f72ca0b',
        'contract_classic': 'a07c2258ca1ea59fa229adb4d046b9d3195b9fbfa077128c2735e7d5bc740d97',
        'contract_typed': '405cf139eb21895f590d6cd6b6e243c433dc49adf8a5f4d374b82a5273f8b5b9',
        'sha256': 'f021ff56d1117840298297dc10dbca8f1613f22a74fa3034746256427f72ca0b',
        'slot_lines': '754b0d1365dad068caa02a28834f5149b47c87e091a5c70c82d83a41efe868ff',
        'topology_json': '7fce90a12151f7a3fc297dd08078939a811964b9fbbf4d22bf38d16149295089',
    },
    'multi': {
        'canonical': 'd39c45b604461cb57e47c6939ebaa2812a3ef006b54b086c8a86c6d49c096ea0',
        'contract_classic': 'd574a4b0c79bc4da57701430a06bbae5f76bbbbd83e556bc8606209b045acd51',
        'contract_typed': 'fd0502d952881269377b14a9a0f416ea213c593d2d7ead31629c2218d8a037f1',
        'sha256': 'd39c45b604461cb57e47c6939ebaa2812a3ef006b54b086c8a86c6d49c096ea0',
        'slot_lines': '670eae334413e66e31e1a6bdd17719be3476bb1e1092e0c03090fbe9fb4fbf47',
        'topology_json': '0003cf54d4b63863ce99fa1fddbaef1699192516bf1b8e79f8cfc11393e8e0f2',
    },
}

if __name__ == "__main__":
    print(json.dumps(digests(), indent=1, sort_keys=True))

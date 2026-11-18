"""Typed IaC intent TI-2: the intent gate S0-S5 (plan §2.7) and the owner-answer data (Q-TI-3/4/5/7/9).

Covers: FACT / SECRET arguments rejected, Member as the only IAM member form, role tables, fail-closed unknown types,
RT F5 facts (project_number + service agents), RT F6 `[i]` only on list blocks, count drivers literal-only (RT F4),
ServiceRef URLs, realization slots, cycles, FACT.MISSING, owner answers as data. Pure."""
import hermetic_guard  # noqa: F401  (first import)

import copy
import dataclasses
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import iac_intent as ii  # noqa: E402
from developer_agent.validators import policy_tables as PT  # noqa: E402

ART = ii.load_artifacts()
CTX = ii.IntentContext(services={"api": ("module.compute", "compute-cloudrun")})
# TI-3 RT F3: a network-bound module needs the lane-11 facts (IAC.MODULE_FACT_UNAVAILABLE otherwise); the tests below
# that are about something else give them as the caller will once lane 11 provides them
NET_CTX = ii.IntentContext(services=CTX.services,
                           facts=dict(ii.default_facts(), network="var.network_id", zone="var.zone",
                                      network_by_project_number="var.network_path"),   # TI-5c: Vertex
                           unwired_modules=frozenset())   # these tests are about args, not the owner-10-21 hold


def F(fact):
    return {"$ref": {"kind": "fact", "fact": fact}}


def R(t, n, a):
    return {"$ref": {"kind": "resource_attr", "type": t, "name": n, "attr": a}}


def SVC(out="service_uri", svc="api"):
    return {"$ref": {"kind": "service", "service": svc, "output": out}}


def doc(*resources, modules=(), outputs=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources),
            "outputs": list(outputs)}


TOPIC = {"type": "google_pubsub_topic", "name": "events", "arguments": {"name": "events"}}


def gate(d, ctx=CTX, art=ART):
    return ii.validate_intent(d, art, ctx)


def codes(d, **kw):
    return {x.code for x in gate(d, **kw).diagnostics}


def iam(role="roles/pubsub.publisher", member=None, **extra):
    args = {"topic": R("google_pubsub_topic", "events", "name"), "role": role,
            "member": member if member is not None else {"$member": {"service_account": F("workload_sa_email")}}}
    args.update(extra)
    return {"type": "google_pubsub_topic_iam_member", "name": "pub", "arguments": args}


# ------------------------------------------------------------------------------------------------ S0
def test_s0_not_json_and_schema_violations_are_json_output_invalid():
    assert codes("{not json") == {"JSON.OUTPUT_INVALID"}
    assert codes({"schema": "iac_intent/v2"}) == {"JSON.OUTPUT_INVALID"}
    assert codes(dict(doc(TOPIC), extra=1)) == {"JSON.OUTPUT_INVALID"}
    assert codes(doc(dict(TOPIC, name="Bad-Name"))) == {"JSON.OUTPUT_INVALID"}


def test_clean_intent_passes_and_is_validated():
    g = gate(doc(TOPIC))
    assert g.ok and g.validated.sha256 == ii.intent_sha256(g.intent) and not g.diagnostics


# ------------------------------------------------------------------------------------------------ S1
def test_s1_duplicate_addresses_platform_names_and_existing_addresses():
    assert "IAC.DUPLICATE_ADDRESS" in codes(doc(TOPIC, copy.deepcopy(TOPIC)))
    for name in ("foundation", "compute", "compute_api"):
        assert "IAC.DUPLICATE_ADDRESS" in codes(doc(modules=[{"module": "storage-bucket", "name": name, "args": {}}]))
    ctx = dataclasses.replace(CTX, existing_addresses=frozenset({"google_pubsub_topic.events"}))
    assert "IAC.DUPLICATE_ADDRESS" in codes(doc(TOPIC), ctx=ctx)
    ctx = dataclasses.replace(CTX, platform_output_names=frozenset({"service_url"}))
    out = {"name": "service_url", "value": R("google_pubsub_topic", "events", "id")}
    assert "IAC.DUPLICATE_ADDRESS" in codes(doc(TOPIC, outputs=[out]), ctx=ctx)


def test_s1_realization_slots():
    ctx = dataclasses.replace(CTX, topology_resources={"uploads": "google_storage_bucket", "events": "google_pubsub_topic"})
    bucket_mod = {"module": "storage-bucket", "name": "uploads", "realizes": "uploads", "args": {}}
    topic = dict(TOPIC, realizes="events")
    assert gate(doc(topic, modules=[bucket_mod]), ctx=ctx).ok
    assert "IAC.TOPOLOGY_RESOURCE_UNREALIZED" in codes(doc(topic), ctx=ctx)
    assert "IAC.DUPLICATE_REALIZATION" in codes(doc(topic, dict(TOPIC, name="e2", realizes="events"),
                                                    modules=[bucket_mod]), ctx=ctx)
    assert "IAC.UNKNOWN_REALIZATION" in codes(doc(dict(TOPIC, realizes="nope")), ctx=ctx)
    wrong = {"module": "messaging-pubsub", "name": "uploads", "realizes": "uploads", "args": {}}
    assert "IAC.REALIZATION_TYPE_MISMATCH" in codes(doc(topic, modules=[wrong]), ctx=ctx)


# ------------------------------------------------------------------------------------------------ S2 types (Q-TI-7)
@pytest.mark.parametrize("rtype", ["google_project_service", "google_artifact_registry_repository",
                                   "google_firestore_database", "google_billing_budget", "google_project_iam_binding",
                                   "google_storage_bucket_iam_policy", "google_cloud_run_v2_service",
                                   "google_cloud_run_v2_service_iam_member", "google_compute_network",
                                   "google_vpc_access_connector", "google_redis_instance", "google_made_up_type"])
def test_s2_not_allowed_types_fail_closed(rtype):
    assert codes(doc({"type": rtype, "name": "x", "arguments": {}})) == {"IAC.TYPE_NOT_ALLOWED"}


def test_q_ti_answers_are_data_a_different_answer_is_a_data_edit():
    allowed = copy.deepcopy(dict(ART.allowed))
    allowed["owner_answers"]["Q-TI-4"]["answer"] = "no"
    art = dataclasses.replace(ART, allowed=allowed)
    rp = {"type": "random_password", "name": "pw", "arguments": {"length": 16}}
    assert gate(doc(rp)).ok
    assert codes(doc(rp), art=art) == {"IAC.TYPE_NOT_ALLOWED"}
    allowed["owner_answers"]["Q-TI-5"]["answer"] = "no"
    assert "kubernetes_manifest" not in dataclasses.replace(ART, allowed=allowed).allowed_types


def test_allow_list_is_the_17_types_plus_the_two_random_types():
    types = set(ART.allowed_types)
    assert len(types) == 19
    assert {t for t, s in ART.allowed["types"].items() if s["question"] == "Q-TI-3"} == types - {
        "random_id", "random_password", "kubernetes_manifest"}
    assert len([t for t in types if t.startswith("google_")]) == 16
    assert ART.allowed["unknown_type_policy"]["if_yes"] == "fail_closed"
    assert ART.allowed["bundles_in_v1"]["if_yes"] is False


def test_s2_module_unknown_and_platform_only_modules():
    for mid in ("compute-cloudrun", "networking-vpc", "workload-foundation", "no-such-module"):
        assert "IAC.MODULE_UNKNOWN" in codes(doc(modules=[{"module": mid, "name": "m", "args": {}}]))


# ------------------------------------------------------------------------------------------------ S2/S3 module args
@pytest.mark.parametrize("arg", ["project_id", "region", "workload_sa_email"])
def test_fact_args_are_platform_owned(arg):
    m = {"module": "storage-bucket", "name": "b", "args": {arg: "literal"}}
    assert "IAC.PLATFORM_OWNED_ARGUMENT" in codes(doc(modules=[m]))


@pytest.mark.parametrize("mid,arg", [("database-cloudsql", "db_password"), ("security-secret", "secret_data"),
                                     ("database-alloydb", "initial_user_password")])
def test_secret_args_are_rejected_even_as_references(mid, arg):
    base = {"security-secret": {"secret_id": "s"}}.get(mid, {})
    m = {"module": mid, "name": "m", "args": dict(base, **{arg: R("random_password", "pw", "result")})}
    rp = {"type": "random_password", "name": "pw", "arguments": {"length": 16}}
    assert "IAC.SECRET_ARGUMENT" in codes(doc(rp, modules=[m]))


def test_secret_policy_omit_means_the_renderer_never_sets_them():
    out = ii.render_intent(gate(doc(modules=[{"module": "security-secret", "name": "s",
                                               "args": {"secret_id": "api-key"}}])).validated)
    body = json.loads(out.files[ii.RENDER_PATH])["module"]["s"]
    assert "secret_data" not in body and body["workload_sa_email"] == "${module.foundation.workload_sa_email}"


def test_ref_only_args():
    ok = {"module": "scheduling-cron", "name": "c", "args": {"target_uri": SVC()}}
    assert gate(doc(modules=[ok])).ok
    assert "IAC.REF_REQUIRED" in codes(doc(modules=[{"module": "scheduling-cron", "name": "c",
                                                     "args": {"target_uri": "https://x"}}]))
    assert "IAC.REF_KIND_NOT_ALLOWED" in codes(doc(modules=[{"module": "scheduling-cron", "name": "c",
                                                             "args": {"target_uri": SVC("service_name")}}]))
    kms = {"module": "ai-vertex-endpoint", "name": "v", "args": {"kms_key_name": {"$ref": {
        "kind": "module_output", "module": "k", "output": "crypto_key_name"}}}}   # TI-5-G3 (owner 10-24)
    assert gate(doc(modules=[{"module": "security-kms", "name": "k", "args": {}}, kms]), ctx=NET_CTX).ok


def test_missing_required_module_argument():
    assert "IAC.MISSING_REQUIRED_ARGUMENT" in codes(doc(modules=[{"module": "scheduling-cron", "name": "c",
                                                                  "args": {}}]))


def test_count_drivers_are_literal_only():
    lit = {"module": "messaging-pubsub", "name": "m", "args": {"enable_subscription": False}}
    assert gate(doc(modules=[lit])).ok
    ref = {"module": "messaging-pubsub", "name": "m", "args": {"enable_subscription": {
        "$fn": "tostring", "$args": [True]}}}
    assert "IAC.LITERAL_REQUIRED" in codes(doc(modules=[ref]))
    drivers = {(m, v) for m, e in ART.catalog["modules"].items() for v, meta in e["variables"].items()
               if meta["count_driver"] and meta["class"] == "AI"}
    assert ("messaging-pubsub", "enable_subscription") in drivers and ("database-bigtable", "table_name") in drivers


def test_module_arg_literal_types_are_checked():
    m = {"module": "storage-bucket", "name": "b", "args": {"versioning_enabled": "yes-please"}}
    assert "IAC.TYPE_MISMATCH" in codes(doc(modules=[m]))
    m = {"module": "storage-bucket", "name": "b", "args": {"versioning_enabled": "true"}}   # tofu converts
    assert gate(doc(modules=[m])).ok
    m = {"module": "storage-bucket", "name": "b", "args": {"no_such_var": 1}}
    assert "IAC.UNKNOWN_ARGUMENT" in codes(doc(modules=[m]))
    m = {"module": "storage-bucket", "name": "b", "args": {"source": "git::https://evil"}}
    assert "IAC.META_ARGUMENT_NOT_ALLOWED" in codes(doc(modules=[m]))


# ------------------------------------------------------------------------------------------------ S3 resource schema
def test_s3_schema_walk_codes():
    assert "IAC.UNKNOWN_ARGUMENT" in codes(doc(dict(TOPIC, arguments={"name": "e", "nope": 1})))
    assert "IAC.MISSING_REQUIRED_ARGUMENT" in codes(doc(dict(TOPIC, arguments={})))
    assert "IAC.TYPE_MISMATCH" in codes(doc(dict(TOPIC, arguments={"name": "e", "labels": "not-a-map"})))
    assert "IAC.COMPUTED_ONLY_ATTRIBUTE" in codes(doc(dict(TOPIC, arguments={"name": "e", "effective_labels": {}})))
    sub = {"type": "google_pubsub_subscription", "name": "s", "arguments": {
        "name": "s", "topic": R("google_pubsub_topic", "events", "id"),
        "push_config": [{"push_endpoint": SVC()}, {"push_endpoint": SVC()}]}}
    assert "IAC.MAX_ITEMS_EXCEEDED" in codes(doc(TOPIC, sub))
    sec = {"type": "google_secret_manager_secret", "name": "s", "arguments": {"secret_id": "s"}}
    assert "IAC.MISSING_REQUIRED_BLOCK" in codes(doc(sec))
    sec["arguments"]["replication"] = "auto"
    assert "IAC.TYPE_MISMATCH" in codes(doc(sec))


@pytest.mark.parametrize("attr,code", [
    ("lifecycle_rule[0].action", None),                       # list block indexed: ok (the whole set block)
    ("lifecycle_rule[0].action[0].type", "IAC.NOT_INDEXABLE"),  # RT F6: action is a SET block in 6.35.0
    ("lifecycle_rule.action", "IAC.INDEX_REQUIRED"),           # list block must be indexed
    ("name", None), ("url", None), ("labels.team", None),       # map attribute traversal
    ("no_such_attr", "IAC.UNKNOWN_ATTRIBUTE"), ("name[0]", "IAC.NOT_INDEXABLE"),
])
def test_f6_index_only_on_nesting_mode_list_blocks(attr, code):
    b = {"type": "google_storage_bucket", "name": "b", "arguments": {"name": "b", "location": F("region")}}
    out = {"name": "o", "value": R("google_storage_bucket", "b", attr)}
    got = codes(doc(b, outputs=[out]))
    assert got == ({code} if code else set()), got


def test_s4_references_resolve():
    assert "IAC.UNKNOWN_REFERENCE" in codes(doc(dict(TOPIC, arguments={"name": R("google_pubsub_topic", "x", "id")})))
    assert "IAC.UNKNOWN_REFERENCE" in codes(doc(dict(TOPIC, arguments={"name": SVC(svc="nope")})))
    m = {"module": "storage-bucket", "name": "b", "args": {}}
    out = {"name": "o", "value": {"$ref": {"kind": "module_output", "module": "b", "output": "nope"}}}
    assert "IAC.UNKNOWN_OUTPUT" in codes(doc(modules=[m], outputs=[out]))
    dep = dict(TOPIC, depends_on=[{"module": "nope"}])
    assert "IAC.UNKNOWN_REFERENCE" in codes(doc(dep))
    ex = dict(TOPIC, arguments={"name": {"$ref": {"kind": "existing", "address": "google_pubsub_topic.legacy.name"}}})
    assert "IAC.UNKNOWN_REFERENCE" in codes(doc(ex))
    ctx = dataclasses.replace(CTX, existing_addresses=frozenset({"google_pubsub_topic.legacy"}))
    assert gate(doc(ex), ctx=ctx).ok


def test_s4_fact_missing_is_platform_defect():
    t = dict(TOPIC, arguments={"name": F("network")})
    g = gate(doc(t))
    assert {d.code for d in g.diagnostics} == {"FACT.MISSING"}
    assert g.diagnostics[0].error_class == ii.ErrorClass.PLATFORM_DEFECT


def test_s4_cycles_through_a_service_are_topology_cycles():
    ctx = dataclasses.replace(CTX, topology_resources={"events": "google_pubsub_topic"},
                              service_reads=(("api", "events"),))
    sub = {"type": "google_pubsub_subscription", "name": "s", "realizes": None, "arguments": {
        "name": "s", "topic": R("google_pubsub_topic", "events", "id"), "push_config": {"push_endpoint": SVC()}}}
    topic = dict(TOPIC, realizes="events", arguments={"name": "e", "labels": {"url": SVC()}})
    assert "TOPOLOGY.CYCLE" in codes(doc(topic, sub), ctx=ctx)
    a = {"type": "google_pubsub_topic", "name": "a", "arguments": {"name": R("google_pubsub_topic", "b", "name")}}
    b = {"type": "google_pubsub_topic", "name": "b", "arguments": {"name": R("google_pubsub_topic", "a", "name")}}
    assert "IAC.REFERENCE_CYCLE" in codes(doc(a, b))


# ------------------------------------------------------------------------------------------------ typed rules
def test_fact_attributes_take_only_facts():
    assert "IAC.FACT_REQUIRED" in codes(doc(dict(TOPIC, arguments={"name": "e", "project": "other-project"})))
    b = {"type": "google_storage_bucket", "name": "b", "arguments": {"name": "b", "location": "US"}}
    assert "IAC.FACT_REQUIRED" in codes(doc(b))
    assert gate(doc(dict(b, arguments={"name": "b", "location": F("region")}))).ok


def test_service_ref_only_paths_accept_a_service_url_and_nothing_else():
    def sub(ep):
        return doc(TOPIC, {"type": "google_pubsub_subscription", "name": "s", "arguments": {
            "name": "s", "topic": R("google_pubsub_topic", "events", "id"), "push_config": {"push_endpoint": ep}}})
    assert gate(sub(SVC())).ok
    assert gate(sub({"$fn": "format", "$args": ["%s/api/v1/push", SVC()]})).ok
    for bad in ("https://example.com/push", {"$fn": "format", "$args": ["https://evil/%s", SVC()]},
                {"$fn": "format", "$args": ["%s/%s", SVC(), "x"]}, SVC("service_name")):
        assert "IAC.SERVICE_REF_REQUIRED" in codes(sub(bad)), bad


def test_secret_data_only_from_random_password():
    def ver(data):
        return doc({"type": "random_password", "name": "pw", "arguments": {"length": 16}},
                   {"type": "google_secret_manager_secret", "name": "s",
                    "arguments": {"secret_id": "s", "replication": {"auto": {}}}},
                   {"type": "google_secret_manager_secret_version", "name": "v", "arguments": {
                       "secret": R("google_secret_manager_secret", "s", "id"), "secret_data": data}})
    assert gate(ver(R("random_password", "pw", "result"))).ok
    assert gate(ver({"$fn": "jsonencode", "$args": [{"p": R("random_password", "pw", "result")}]})).ok
    assert "IAC.SECRET_LITERAL" in codes(ver("sk_live_literal"))


def test_forced_value_and_account_id_pattern():
    b = {"type": "google_storage_bucket", "name": "b", "arguments": {"name": "b", "location": F("region"),
                                                                     "uniform_bucket_level_access": False}}
    assert "IAC.FORCED_VALUE" in codes(doc(b))
    sa = {"type": "google_service_account", "name": "sa", "arguments": {"account_id": "x"}}
    assert "IAC.INVALID_VALUE" in codes(doc(sa))
    sa["arguments"]["account_id"] = "worker-sa"
    assert gate(doc(sa)).ok


def test_sql_user_and_database_need_a_cloudsql_module_instance():
    mod = {"module": "database-cloudsql", "name": "db", "args": {}}
    ok = {"type": "google_sql_database", "name": "d", "arguments": {
        "name": "d", "instance": {"$ref": {"kind": "module_output", "module": "db", "output": "instance_name"}}}}
    assert gate(doc(ok, modules=[mod]), ctx=NET_CTX).ok
    bad = copy.deepcopy(ok)
    bad["arguments"]["instance"] = "literal-instance"
    assert "IAC.REF_KIND_NOT_ALLOWED" in codes(doc(bad, modules=[mod]))
    # TI-3 RT F3: without the network fact the module is refused, typed and removable
    assert "IAC.MODULE_FACT_UNAVAILABLE" in codes(doc(ok, modules=[mod]))


def test_kubernetes_manifest_is_dynamic_with_exact_fact_paths():
    def man(image, ns=F("kubernetes_namespace")):
        return doc({"type": "kubernetes_manifest", "name": "d", "arguments": {"manifest": {
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d", "namespace": ns},
            "spec": {"template": {"spec": {"containers": [{"name": "c", "image": image}]}}}}}})
    ctx = dataclasses.replace(CTX, facts=dict(ii.default_facts(), kubernetes_namespace="var.k8s_namespace"))
    assert gate(man(F("container_image")), ctx=ctx).ok
    assert "IAC.FACT_REQUIRED" in codes(man("gcr.io/evil/image:latest"), ctx=ctx)
    assert "IAC.FACT_REQUIRED" in codes(man(F("container_image"), ns="default"), ctx=ctx)
    assert ART.resource_schema("kubernetes_manifest")["attributes"]["manifest"]["type"] == "dynamic"


# ------------------------------------------------------------------------------------------------ S5 IAM
def test_member_is_the_only_iam_member_form():
    assert gate(doc(TOPIC, iam())).ok
    for bad in ("allUsers", "allAuthenticatedUsers", "serviceAccount:x@y.iam.gserviceaccount.com",
                {"$fn": "format", "$args": ["serviceAccount:%s", F("workload_sa_email")]}, F("workload_sa_member")):
        assert "IAC.MEMBER_NOT_TYPED" in codes(doc(TOPIC, iam(member=bad))), bad


def test_member_service_account_must_be_a_service_account():
    assert "IAC.MEMBER_NOT_SERVICE_ACCOUNT" in codes(doc(TOPIC, iam(member={"$member": {
        "service_account": F("project_id")}})))
    sa = {"type": "google_service_account", "name": "worker", "arguments": {"account_id": "worker-sa"}}
    assert gate(doc(TOPIC, sa, iam(member={"$member": {"service_account": R("google_service_account", "worker",
                                                                             "email")}}))).ok
    assert "IAC.MEMBER_NOT_SERVICE_ACCOUNT" in codes(doc(TOPIC, sa, iam(member={"$member": {
        "service_account": R("google_service_account", "worker", "name")}})))


def test_f5_service_agent_members_and_project_number_fact():
    assert set(ii.SERVICE_AGENT_FACTS) == {"gcs_service_agent", "pubsub_service_agent"}
    assert gate(doc(TOPIC, iam(member={"$member": {"service_agent": "gcs_service_agent"}}))).ok
    assert "project_number" in ii.default_facts()
    assert "IAC.RESERVED_KEY" in codes(doc(TOPIC, iam(member={"$member": {"service_agent": "project_id"}})))


def test_member_outside_an_iam_member_argument_is_refused():
    t = dict(TOPIC, arguments={"name": "e", "labels": {"m": {"$member": {"service_account": F("workload_sa_email")}}}})
    assert "IAC.MEMBER_NOT_ALLOWED_HERE" in codes(doc(t))


def test_roles_outside_the_per_type_tables_are_refused():
    assert "IAC.ROLE_NOT_ALLOWED" in codes(doc(TOPIC, iam(role="roles/owner")))
    assert "IAC.ROLE_NOT_ALLOWED" in codes(doc(TOPIC, iam(role={"$fn": "tostring", "$args": ["roles/pubsub.publisher"]})))
    p = {"type": "google_project_iam_member", "name": "p", "arguments": {
        "project": F("project_id"), "role": "roles/run.invoker",
        "member": {"$member": {"service_account": F("workload_sa_email")}}}}
    assert "IAC.ROLE_NOT_ALLOWED" in codes(doc(p))


def test_role_tables_never_hold_privileged_platform_or_invoker_roles():
    tables = {k: v for k, v in ART.allowed["role_allow"].items() if not k.startswith("_")}
    iam_types = {t for t, s in ART.allowed_types.items() if s.get("iam")}
    assert set(tables) == {s["iam"]["role_table"] for t, s in ART.allowed_types.items() if s.get("iam")}
    assert iam_types == {t for t in ART.allowed_types if t.endswith("_iam_member")}
    owned = {tuple(x) for k in ("platform_owned_bindings", "topology_owned_bindings")
             for x in ART.allowed["not_expressible"][k]}
    for t, roles in tables.items():
        assert roles == sorted(set(roles)), t
        for r in roles:
            assert r not in PT.PRIVILEGED_ROLES and (t, r) not in PT.PLATFORM_OWNED_BINDINGS and (t, r) not in owned
            assert r != "roles/run.invoker"
            if t in PT.PROJECT_LEVEL_IAM_TYPES:
                assert r not in PT.IMPERSONATION_ROLES
    assert set(PT.PLATFORM_OWNED_BINDINGS) <= owned


def test_not_expressible_tables_agree_with_policy_tables():
    ne = ART.allowed["not_expressible"]
    assert set(ne["forbidden"]) == set(PT.FORBIDDEN_RESOURCE_TYPES)
    assert tuple(sorted(ne["forbidden_type_suffixes"])) == tuple(sorted(PT.AUTHORITATIVE_IAM_SUFFIXES))
    assert set(PT.PLATFORM_OWNED_TYPES) <= set(ne["platform_owned"])
    owners = [set(ne[k]) for k in ("platform_owned", "forbidden", "topology_owned", "lane11_owned")]
    for i, a in enumerate(owners):
        assert not a & set(ART.allowed_types)
        for b in owners[i + 1:]:
            assert not a & b

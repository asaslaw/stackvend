"""Typed IaC intent TI-2b: hardening from the TI-2 code Fable RT (docs/planning/ti2-code-red-team-fable.md F1-F7).

F1 IAM targets and F2 data destinations / token identities / keys are Ref-only (`target_ref_only`), F3 only the
`$`-prefixed / `schema` spellings exist, F4 the `existing` grammar refuses reserved roots and an existing Member must
be a google_service_account .email, F5 the gateway copy carries the four artifacts byte-identical, F6 the catalog
classes the fd-csql-private-network variables, F7 a sensitive reference cannot land in a plain attribute. Pure."""
import hermetic_guard  # noqa: F401  (first import)

import copy
import dataclasses
import importlib.util
import json
import os
import shutil
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import iac_intent as ii  # noqa: E402

ART = ii.load_artifacts()
# TI-3 RT F3: with the lane-11 facts (network / zone) a network-bound module such as database-cloudsql is usable
CTX = ii.IntentContext(services={"api": ("module.compute", "compute-cloudrun")},
                       facts=dict(ii.default_facts(), network="var.network_id", zone="var.zone"))


def F(fact):
    return {"$ref": {"kind": "fact", "fact": fact}}


def R(t, n, a):
    return {"$ref": {"kind": "resource_attr", "type": t, "name": n, "attr": a}}


def MO(m, o):
    return {"$ref": {"kind": "module_output", "module": m, "output": o}}


def doc(*resources, modules=(), outputs=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources),
            "outputs": list(outputs)}


def codes(d, ctx=CTX):
    return {x.code for x in ii.validate_intent(d, ART, ctx).diagnostics}


WSA = {"$member": {"service_account": F("workload_sa_email")}}
TOPIC = {"type": "google_pubsub_topic", "name": "t", "arguments": {"name": "t"}}
SA = {"type": "google_service_account", "name": "w", "arguments": {"account_id": "worker-sa"}}
SECRET = {"type": "google_secret_manager_secret", "name": "s", "arguments": {"secret_id": "s", "replication": {"auto": {}}}}
BUCKET = {"type": "google_storage_bucket", "name": "b", "arguments": {"name": "b-x", "location": F("region")}}
SUB = {"type": "google_pubsub_subscription", "name": "sub", "arguments": {"name": "sub", "topic": R("google_pubsub_topic", "t", "id")}}


# ------------------------------------------------------------------------------------------------ F1 IAM targets
DEPLOYER = "projects/mock-stackvend-project/serviceAccounts/sa-gh-deployer@mock-stackvend-project.iam.gserviceaccount.com"


@pytest.mark.parametrize("entry", [
    # P1: the workload may actAs the DEPLOYER identity (privilege escalation) -> refused
    {"type": "google_service_account_iam_member", "name": "p1", "arguments": {
        "service_account_id": DEPLOYER, "role": "roles/iam.serviceAccountUser", "member": WSA}},
    # P2: a platform-owned secret by literal id
    {"type": "google_secret_manager_secret_iam_member", "name": "p2", "arguments": {
        "secret_id": "castor-platform-github-token", "role": "roles/secretmanager.secretAccessor", "member": WSA}},
    # P3: any (global) bucket name
    {"type": "google_storage_bucket_iam_member", "name": "p3", "arguments": {
        "bucket": "host-project-state-bucket", "role": "roles/storage.objectAdmin", "member": WSA}},
    # P4: a topic in another project
    {"type": "google_pubsub_topic_iam_member", "name": "p4", "arguments": {
        "topic": "projects/other/topics/t", "role": "roles/pubsub.publisher", "member": WSA}},
    {"type": "google_pubsub_subscription_iam_member", "name": "p4b", "arguments": {
        "subscription": "projects/other/subscriptions/s", "role": "roles/pubsub.subscriber", "member": WSA}},
    # a Call that builds the name is not a reference either
    {"type": "google_storage_bucket_iam_member", "name": "p3b", "arguments": {
        "bucket": {"$fn": "format", "$args": ["%s-state", F("project_id")]}, "role": "roles/storage.objectViewer",
        "member": WSA}},
])
def test_f1_iam_targets_must_be_references(entry):
    assert "IAC.TARGET_REF_REQUIRED" in codes(doc(entry))


def test_f1_iam_targets_accept_references_to_declared_resources_and_catalog_outputs():
    ok = doc(SA, SECRET, BUCKET, TOPIC, SUB,
             {"type": "google_service_account_iam_member", "name": "a", "arguments": {
                 "service_account_id": R("google_service_account", "w", "name"),
                 "role": "roles/iam.serviceAccountUser", "member": WSA}},
             {"type": "google_secret_manager_secret_iam_member", "name": "b", "arguments": {
                 "secret_id": R("google_secret_manager_secret", "s", "secret_id"),
                 "role": "roles/secretmanager.secretAccessor", "member": WSA}},
             {"type": "google_storage_bucket_iam_member", "name": "c", "arguments": {
                 "bucket": MO("uploads", "bucket_name"), "role": "roles/storage.objectViewer", "member": WSA}},
             {"type": "google_pubsub_topic_iam_member", "name": "d", "arguments": {
                 "topic": MO("events", "topic_id"), "role": "roles/pubsub.publisher", "member": WSA}},
             {"type": "google_pubsub_subscription_iam_member", "name": "e", "arguments": {
                 "subscription": R("google_pubsub_subscription", "sub", "name"), "role": "roles/pubsub.subscriber",
                 "member": WSA}},
             modules=[{"module": "storage-bucket", "name": "uploads", "args": {}},
                      {"module": "messaging-pubsub", "name": "events", "args": {}}])
    g = ii.validate_intent(ok, ART, CTX)
    assert g.ok, [(d.code, d.attribute_path) for d in g.diagnostics]


def test_f1_a_reference_of_the_wrong_shape_is_refused():
    wrong = {"type": "google_storage_bucket_iam_member", "name": "c", "arguments": {
        "bucket": MO("events", "topic_name"), "role": "roles/storage.objectViewer", "member": WSA}}
    assert "IAC.TARGET_REF_REQUIRED" in codes(doc(wrong, modules=[{"module": "messaging-pubsub", "name": "events",
                                                                   "args": {}}]))
    wrong2 = {"type": "google_service_account_iam_member", "name": "a", "arguments": {
        "service_account_id": R("google_service_account", "w", "email"), "role": "roles/iam.serviceAccountUser",
        "member": WSA}}
    assert "IAC.TARGET_REF_REQUIRED" in codes(doc(SA, wrong2))


def test_f1_existing_resource_of_the_listed_type_is_a_valid_target():
    e = {"type": "google_pubsub_topic_iam_member", "name": "d", "arguments": {
        "topic": {"$ref": {"kind": "existing", "address": "google_pubsub_topic.legacy.name"}},
        "role": "roles/pubsub.publisher", "member": WSA}}
    ctx = dataclasses.replace(CTX, existing_addresses=frozenset({"google_pubsub_topic.legacy"}))
    assert ii.validate_intent(doc(e), ART, ctx).ok
    e2 = copy.deepcopy(e)
    e2["arguments"]["topic"]["$ref"]["address"] = "google_storage_bucket.legacy.name"
    ctx2 = dataclasses.replace(CTX, existing_addresses=frozenset({"google_storage_bucket.legacy"}))
    assert "IAC.TARGET_REF_REQUIRED" in codes(doc(e2), ctx=ctx2)


def test_f1_every_iam_type_has_its_target_typed():
    for t, spec in ART.allowed_types.items():
        if t.endswith("_iam_member") and t != "google_project_iam_member":
            assert spec.get("target_ref_only"), t


# ------------------------------------------------------------------------------------------------ F2 destinations
@pytest.mark.parametrize("entry", [
    dict(SUB, arguments=dict(SUB["arguments"], topic="projects/other/topics/firehose")),                       # P8
    dict(SUB, arguments=dict(SUB["arguments"], cloud_storage_config={"bucket": "attacker-bucket"})),          # P5
    dict(SUB, arguments=dict(SUB["arguments"], dead_letter_policy={"dead_letter_topic": "projects/o/topics/d"})),
    dict(SUB, arguments=dict(SUB["arguments"], push_config={
        "push_endpoint": {"$ref": {"kind": "service", "service": "api", "output": "service_uri"}},
        "oidc_token": {"service_account_email": "sa-gh-deployer@mock-stackvend-project.iam.gserviceaccount.com"}})),
    {"type": "google_storage_notification", "name": "n", "arguments": {                                      # P9
        "bucket": R("google_storage_bucket", "b", "name"), "payload_format": "JSON_API_V1",
        "topic": "projects/other/topics/exfil"}},
    dict(BUCKET, arguments=dict(BUCKET["arguments"], logging={"log_bucket": "attacker-logs"})),               # P10
    dict(BUCKET, arguments=dict(BUCKET["arguments"], encryption={"default_kms_key_name": "projects/o/k"})),
    {"type": "google_secret_manager_secret_version", "name": "v", "arguments": {                             # secret
        "secret": "projects/other/secrets/collect", "secret_data": R("random_password", "pw", "result")}},
    dict(SECRET, arguments=dict(SECRET["arguments"], topics=[{"name": "projects/other/topics/secret-events"}])),
    {"type": "google_cloud_scheduler_job", "name": "j", "arguments": {
        "name": "j", "schedule": "* * * * *", "pubsub_target": {"topic_name": "projects/other/topics/t"}}},
    dict(TOPIC, arguments=dict(TOPIC["arguments"], kms_key_name="projects/other/locations/l/keyRings/r/cryptoKeys/k")),
])
def test_f2_data_destinations_identities_and_keys_must_be_references(entry):
    pw = {"type": "random_password", "name": "pw", "arguments": {"length": 16}}
    assert "IAC.TARGET_REF_REQUIRED" in codes(doc(TOPIC if entry["type"] != "google_pubsub_topic" else SUB, BUCKET,
                                                  pw, entry))


def test_f2_destinations_accept_declared_references():
    pw = {"type": "random_password", "name": "pw", "arguments": {"length": 16}}
    good = doc(
        TOPIC, BUCKET, SECRET, SA, pw,
        dict(SUB, arguments=dict(SUB["arguments"],
                                 dead_letter_policy={"dead_letter_topic": R("google_pubsub_topic", "t", "id")},
                                 cloud_storage_config={"bucket": R("google_storage_bucket", "b", "name"),
                                                       "service_account_email": R("google_service_account", "w",
                                                                                  "email")})),
        {"type": "google_storage_notification", "name": "n", "arguments": {
            "bucket": MO("uploads", "bucket_name"), "payload_format": "JSON_API_V1",
            "topic": R("google_pubsub_topic", "t", "id")}},
        {"type": "google_secret_manager_secret_version", "name": "v", "arguments": {
            "secret": R("google_secret_manager_secret", "s", "id"), "secret_data": R("random_password", "pw", "result")}},
        {"type": "google_cloud_scheduler_job", "name": "j", "arguments": {
            "name": "j", "schedule": "* * * * *", "region": F("region"),
            "pubsub_target": {"topic_name": MO("events", "topic_id")}}},
        modules=[{"module": "storage-bucket", "name": "uploads", "args": {}},
                 {"module": "messaging-pubsub", "name": "events", "args": {}}])
    g = ii.validate_intent(good, ART, CTX)
    assert g.ok, [(d.code, d.attribute_path, d.message) for d in g.diagnostics]


@pytest.mark.parametrize("entry,block", [
    (dict(SUB, arguments=dict(SUB["arguments"], bigquery_config={"table": "p.d.t"})), "bigquery_config"),
    (dict(TOPIC, arguments=dict(TOPIC["arguments"], ingestion_data_source_settings={
        "cloud_storage": {"bucket": "b", "text_format": {}}})), "ingestion_data_source_settings"),
])
def test_f2_blocks_without_a_producer_or_from_outside_sources_are_refused(entry, block):
    assert "IAC.BLOCK_NOT_ALLOWED" in codes(doc(TOPIC, entry) if entry["type"] != "google_pubsub_topic" else doc(entry))


def test_target_tables_name_real_schema_paths_and_real_producers():
    for t, spec in ART.allowed_types.items():
        schema = ART.resource_schema(t)
        for path, shapes in (spec.get("target_ref_only") or {}).items():
            block, parts = schema, path.split(".")
            for part in parts[:-1]:
                block = block["block_types"][part]["block"]
            attr = block["attributes"][parts[-1]]
            assert attr["required"] or attr["optional"], (t, path)
            for shape in shapes:
                if shape[0] == "resource_attr":
                    assert shape[1] in ART.allowed_types, (t, path, shape)
                    assert shape[2] in ART.resource_schema(shape[1])["attributes"], (t, path, shape)
                elif shape[0] == "module_output":
                    assert shape[2] in ART.catalog["modules"][shape[1]]["outputs"], (t, path, shape)
                else:
                    assert shape[0] == "fact" and shape[1] in ii.FACTS, (t, path, shape)
        for b in spec.get("refused_blocks") or ():
            assert b in schema["block_types"], (t, b)


# ------------------------------------------------------------------------------------------------ F3 synonyms
@pytest.mark.parametrize("synonym", [
    {"ref": {"kind": "fact", "fact": "project_id"}},                         # P12
    {"fn": "upper", "args": ["x"]},                                          # P13
    {"member": {"service_account": "sa@x.iam.gserviceaccount.com"}},                            # P14
])
def test_f3_unprefixed_names_are_data_not_reference_forms(synonym):
    m = {"type": "kubernetes_manifest", "name": "cm", "arguments": {"manifest": {
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "cm", "namespace": F("kubernetes_namespace")},
        "data": synonym}}}
    ctx = dataclasses.replace(CTX, facts=dict(ii.default_facts(), kubernetes_namespace="var.k8s_namespace"))
    intent = ii.IacIntent.model_validate(doc(m))
    data = intent.resources[0].arguments["manifest"]["data"]
    assert isinstance(data, dict) and not isinstance(data, (ii.Ref, ii.Call, ii.Member))
    out = json.loads(ii.render_intent(ii.validate_intent(doc(m), ART, ctx).validated).files[ii.RENDER_PATH])
    rendered = out["resource"]["kubernetes_manifest"]["cm"]["manifest"]["data"]
    assert "${" not in json.dumps(rendered).replace("$${", "")


def test_f3_schema_id_is_not_a_synonym_of_schema():
    d = doc(TOPIC)
    d["schema_id"] = d.pop("schema")
    assert codes(d) == {"JSON.OUTPUT_INVALID"}


def test_f3_aliases_still_parse_and_dump_identically():
    d = doc(TOPIC, {"type": "google_pubsub_topic", "name": "u", "arguments": {
        "name": {"$fn": "format", "$args": ["%s-u", F("product_id")]}}})
    intent = ii.IacIntent.model_validate(d)
    assert json.loads(ii.canonical_intent_json(intent))["resources"][1]["arguments"]["name"]["$fn"] == "format"


# ------------------------------------------------------------------------------------------------ F4 existing
@pytest.mark.parametrize("addr", ["var.github_token", "local.secret", "path.module", "terraform.workspace",
                                  "self.id", "each.value", "count.index", "data.google_project.p.number",
                                  "output.x", "provider.google"])
def test_f4_existing_grammar_refuses_reserved_roots_even_when_listed(addr):
    t = dict(TOPIC, arguments={"name": "t", "labels": {"x": {"$ref": {"kind": "existing", "address": addr}}}})
    ctx = dataclasses.replace(CTX, existing_addresses=frozenset({".".join(addr.split(".")[:2])}))
    got = codes(doc(t), ctx=ctx)
    assert "IAC.RESERVED_KEY" in got or "JSON.OUTPUT_INVALID" in got
    with pytest.raises(Exception):
        ii.ExistingRef.model_validate({"kind": "existing", "address": addr})


def test_f4_existing_member_must_be_a_service_account_email():
    def m(addr):
        return {"type": "google_pubsub_topic_iam_member", "name": "m", "arguments": {
            "topic": R("google_pubsub_topic", "t", "name"), "role": "roles/pubsub.publisher",
            "member": {"$member": {"service_account": {"$ref": {"kind": "existing", "address": addr}}}}}}
    ctx = dataclasses.replace(CTX, existing_addresses=frozenset({"google_service_account.legacy",
                                                                 "google_secret_manager_secret.s"}))
    assert ii.validate_intent(doc(TOPIC, m("google_service_account.legacy.email")), ART, ctx).ok
    for bad in ("google_service_account.legacy.name", "google_secret_manager_secret.s.secret_id"):
        assert "IAC.MEMBER_NOT_SERVICE_ACCOUNT" in codes(doc(TOPIC, m(bad)), ctx=ctx), bad


# ------------------------------------------------------------------------------------------------ F7 sensitive
def test_f7_sensitive_reference_into_a_plain_attribute_is_refused():
    pw = {"type": "random_password", "name": "pw", "arguments": {"length": 16}}
    leak = dict(TOPIC, arguments={"name": "t", "labels": {"x": R("random_password", "pw", "result")}})
    assert "IAC.SENSITIVE_IN_PLAIN_ATTRIBUTE" in codes(doc(pw, leak))
    wrapped = dict(TOPIC, arguments={"name": "t", "labels": {"x": {"$fn": "lower", "$args": [
        R("random_password", "pw", "result")]}}})
    assert "IAC.SENSITIVE_IN_PLAIN_ATTRIBUTE" in codes(doc(pw, wrapped))
    fine = dict(TOPIC, arguments={"name": "t", "labels": {"x": R("random_password", "pw", "length")}})
    assert ii.validate_intent(doc(pw, fine), ART, CTX).ok


def test_f7_sensitive_attributes_still_take_generated_secrets():
    pw = {"type": "random_password", "name": "pw", "arguments": {"length": 16}}
    v = {"type": "google_secret_manager_secret_version", "name": "v", "arguments": {
        "secret": R("google_secret_manager_secret", "s", "id"),
        "secret_data": {"$fn": "jsonencode", "$args": [{"p": R("random_password", "pw", "result")}]}}}
    mod = {"module": "database-cloudsql", "name": "db", "args": {}}
    u = {"type": "google_sql_user", "name": "u", "arguments": {"name": "app", "instance": MO("db", "instance_name"),
                                                               "password": R("random_password", "pw", "result")}}
    g = ii.validate_intent(doc(pw, SECRET, v, u, modules=[mod]), ART, CTX)
    assert g.ok, [(d.code, d.attribute_path) for d in g.diagnostics]


# ------------------------------------------------------------------------------------------------ F5 gateway artifacts
@pytest.mark.parametrize("name", ii.ARTIFACT_FILES)
def test_f5_gateway_copy_carries_the_artifacts_byte_identical(name):
    a = open(os.path.join(REPO_ROOT, "shared", "iac_intent", name), "rb").read()
    b = open(os.path.join(GATEWAY, "shared", "iac_intent", name), "rb").read()
    assert a == b, f"run the builder or: python3 deploy/vendor_shared.py sync --write shared/iac_intent/{name}"


def test_f5_gateway_copy_loads_its_own_artifacts():
    spec = importlib.util.spec_from_file_location("gw_iac_intent", os.path.join(GATEWAY, "shared", "iac_intent.py"))
    gw = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = gw
    spec.loader.exec_module(gw)
    art = gw.load_artifacts()
    assert os.path.realpath(art.data_dir) == os.path.realpath(os.path.join(GATEWAY, "shared", "iac_intent"))
    assert set(art.allowed_types) == set(ART.allowed_types)


# ------------------------------------------------------------------------------------------------ F6 catalog classes
def test_f6_fd_csql_variables_are_classified_and_the_catalog_still_builds(tmp_path):
    spec = importlib.util.spec_from_file_location("ti2b_builder", os.path.join(REPO_ROOT, "scripts",
                                                                              "build_iac_catalog.py"))
    b = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = b
    spec.loader.exec_module(b)
    mods = tmp_path / "modules"
    shutil.copytree(os.path.join(REPO_ROOT, "infra", "modules"), mods)
    with open(mods / "database-cloudsql" / "variables.tf", "a") as fh:
        fh.write('\nvariable "private_network_id" {\n  type    = string\n  default = null\n}\n'
                 'variable "enable_public_ip" {\n  type    = bool\n  default = false\n}\n'
                 'variable "ssl_mode" {\n  type    = string\n  default = "ENCRYPTED_ONLY"\n}\n')
    catalog, problems = b.build(mods)
    assert problems == []
    v = catalog["modules"]["database-cloudsql"]["variables"]
    assert (v["private_network_id"]["class"], v["private_network_id"]["fact"]) == ("FACT", "network")
    assert v["enable_public_ip"]["class"] == "AI" and v["ssl_mode"]["class"] == "AI"


# ------------------------------------------------------------------------------------------------ converter
def _conv():
    spec = importlib.util.spec_from_file_location("ti2b_convert", os.path.join(REPO_ROOT, "scripts",
                                                                              "convert_custom_tf.py"))
    c = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = c
    spec.loader.exec_module(c)
    return c


def test_converter_resolves_a_literal_target_only_to_the_declared_resource_with_that_exact_name():
    c = _conv()
    tf = ('resource "google_pubsub_topic" "events" {\n  name = "events-inbound"\n}\n'
          'resource "google_pubsub_subscription" "s" {\n  name = "s"\n  topic = "events-inbound"\n}\n'
          'resource "google_pubsub_subscription" "x" {\n  name = "x"\n  topic = "projects/other/topics/t"\n}\n')
    r = c.convert_tree({"infra/workload/custom.tf": tf}, ART)
    s = next(e for e in r.intent["resources"] if e["name"] == "s")
    assert s["arguments"]["topic"] == R("google_pubsub_topic", "events", "name")
    x = next(e for e in r.entries if e.address == "google_pubsub_subscription.x")
    assert x.reasons == ["CONVERT.TARGET_LITERAL"]
    assert ii.validate_intent(r.intent, ART, CTX).ok


def test_owner_fd4az_b1_ssl_mode_is_settable_only_to_the_encrypted_modes(tmp_path):
    spec = importlib.util.spec_from_file_location("ti2b_builder_ssl", os.path.join(REPO_ROOT, "scripts",
                                                                                  "build_iac_catalog.py"))
    b = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = b
    spec.loader.exec_module(b)
    mods = tmp_path / "modules"
    shutil.copytree(os.path.join(REPO_ROOT, "infra", "modules"), mods)
    with open(mods / "database-cloudsql" / "variables.tf", "a") as fh:
        fh.write('\nvariable "ssl_mode" {\n  type    = string\n  default = "ENCRYPTED_ONLY"\n}\n')
    catalog, problems = b.build(mods)
    assert problems == []
    assert catalog["modules"]["database-cloudsql"]["variables"]["ssl_mode"]["allowed_values"] == [
        "ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"]
    art = dataclasses.replace(ART, catalog=catalog)

    def gate(value):
        d = doc(modules=[{"module": "database-cloudsql", "name": "db", "args": {"ssl_mode": value}}])
        return ii.validate_intent(d, art, CTX)
    assert gate("ENCRYPTED_ONLY").ok and gate("TRUSTED_CLIENT_CERTIFICATE_REQUIRED").ok
    for bad in ("ALLOW_UNENCRYPTED_AND_ENCRYPTED", "encrypted_only", "", 1):
        assert {x.code for x in gate(bad).diagnostics} == {"IAC.INVALID_VALUE"}, bad
    assert {x.code for x in gate({"$fn": "upper", "$args": ["encrypted_only"]}).diagnostics} == {"IAC.LITERAL_REQUIRED"}

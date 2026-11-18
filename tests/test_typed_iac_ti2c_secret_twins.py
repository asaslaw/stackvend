"""Typed IaC intent TI-2c: residuals of the TI-2b Fable re-check (docs/planning/ti2b-recheck-fable.md).

R2 the write-only twins (`secret_data_wo`, `password_wo`, their `_wo_version` companions) are refused whatever their
value (`refused_attributes`), and the slice carries `write_only`; R1 a sensitive reference into a non-sensitive module
variable is refused (F7 for modules); R3 forward-compat reserved roots; R5 the per-path tables are disjoint. Pure."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import iac_intent as ii  # noqa: E402

ART = ii.load_artifacts()
CTX = ii.IntentContext(facts=dict(ii.default_facts(), network="var.network_id", zone="var.zone"))   # TI-3 RT F3


def F(fact):
    return {"$ref": {"kind": "fact", "fact": fact}}


def R(t, n, a):
    return {"$ref": {"kind": "resource_attr", "type": t, "name": n, "attr": a}}


PW = {"type": "random_password", "name": "pw", "arguments": {"length": 24}}
SECRET = {"type": "google_secret_manager_secret", "name": "s", "arguments": {"secret_id": "s", "replication": {"auto": {}}}}
DB = {"module": "database-cloudsql", "name": "db", "args": {}}


def doc(*resources, modules=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources), "outputs": []}


def codes(d):
    return {x.code for x in ii.validate_intent(d, ART, CTX).diagnostics}


def version(**args):
    base = {"secret": R("google_secret_manager_secret", "s", "id")}
    base.update(args)
    return {"type": "google_secret_manager_secret_version", "name": "v", "arguments": base}


def user(**args):
    base = {"name": "app", "instance": {"$ref": {"kind": "module_output", "module": "db", "output": "instance_name"}}}
    base.update(args)
    return {"type": "google_sql_user", "name": "u", "arguments": base}


# ------------------------------------------------------------------------------------------------ R2
@pytest.mark.parametrize("value", ["hunter2", R("random_password", "pw", "result"),
                                   {"$fn": "jsonencode", "$args": [{"p": R("random_password", "pw", "result")}]}])
@pytest.mark.parametrize("attr", ["secret_data_wo", "secret_data_wo_version"])
def test_r2_secret_version_write_only_twins_are_refused_literal_and_ref(attr, value):
    v = 1 if attr.endswith("_version") and isinstance(value, str) else value
    got = codes(doc(PW, SECRET, version(**{attr: v})))
    assert "IAC.ATTRIBUTE_NOT_ALLOWED" in got


@pytest.mark.parametrize("value", ["hunter2", R("random_password", "pw", "result")])
@pytest.mark.parametrize("attr", ["password_wo", "password_wo_version"])
def test_r2_sql_user_write_only_twins_are_refused_literal_and_ref(attr, value):
    got = codes(doc(PW, user(**{attr: value}), modules=[DB]))
    assert "IAC.ATTRIBUTE_NOT_ALLOWED" in got


def test_r2_the_sensitive_attributes_still_take_generated_secrets():
    ok = doc(PW, SECRET, version(secret_data=R("random_password", "pw", "result")),
             user(password=R("random_password", "pw", "result")), modules=[DB])
    g = ii.validate_intent(ok, ART, CTX)
    assert g.ok, [(d.code, d.attribute_path) for d in g.diagnostics]
    assert "IAC.SECRET_LITERAL" in codes(doc(SECRET, version(secret_data="hunter2")))


def test_r2_every_write_only_twin_in_the_slice_is_refused_and_the_slice_carries_the_flag():
    twins = set()
    for t, entry in ART.schema_slice["resource_schemas"].items():
        for n, a in entry["block"]["attributes"].items():
            assert "write_only" in a, (t, n)
            if a["write_only"] or n.endswith("_wo") or n.endswith("_wo_version"):
                twins.add((t, n))
    refused = {(t, n) for t, spec in ART.allowed_types.items() for n in spec.get("refused_attributes") or ()}
    assert twins and twins <= refused, twins - refused
    assert ART.manifest["provider_schema"]["engine"]["version"] == "1.9.0"   # tofu 1.9.0 does not report write_only


def test_r2_a_slice_flagged_write_only_attribute_is_refused_even_without_a_table_entry():
    import copy
    import dataclasses
    sl = copy.deepcopy(dict(ART.schema_slice))
    sl["resource_schemas"]["google_pubsub_topic"]["block"]["attributes"]["name"]["write_only"] = True
    art = dataclasses.replace(ART, schema_slice=sl)
    d = doc({"type": "google_pubsub_topic", "name": "t", "arguments": {"name": "t"}})
    assert "IAC.ATTRIBUTE_NOT_ALLOWED" in {x.code for x in ii.validate_intent(d, art, CTX).diagnostics}


# ------------------------------------------------------------------------------------------------ R1
def test_r1_sensitive_reference_into_a_non_sensitive_module_variable_is_refused():
    leak = dict(DB, args={"db_user": R("random_password", "pw", "result")})
    assert "IAC.SENSITIVE_IN_PLAIN_ATTRIBUTE" in codes(doc(PW, modules=[leak]))
    wrapped = dict(DB, args={"db_user": {"$fn": "lower", "$args": [R("random_password", "pw", "result")]}})
    assert "IAC.SENSITIVE_IN_PLAIN_ATTRIBUTE" in codes(doc(PW, modules=[wrapped]))


def test_r1_secret_class_args_keep_their_own_code_and_plain_refs_are_unchanged():
    sec = dict(DB, args={"db_password": R("random_password", "pw", "result")})
    assert codes(doc(PW, modules=[sec])) == {"IAC.SECRET_ARGUMENT"}
    plain = dict(DB, args={"db_user": {"$fn": "format", "$args": ["app-%s", F("product_id")]}})
    assert ii.validate_intent(doc(modules=[plain]), ART, CTX).ok


# ------------------------------------------------------------------------------------------------ R3 / R5
@pytest.mark.parametrize("root", ["ephemeral", "action", "check", "removed", "run"])
def test_r3_forward_compat_reserved_roots_are_refused(root):
    with pytest.raises(Exception):
        ii.ExistingRef.model_validate({"kind": "existing", "address": f"{root}.x.y"})


def test_r5_per_path_tables_are_disjoint_and_targets_are_not_fact_attributes():
    tables = ("service_ref_only", "random_password_only", "module_output_ref", "target_ref_only",
              "refused_attributes")
    fact_attrs = {k for k in ART.allowed["fact_attributes"] if not k.startswith("_")}
    for t, spec in ART.allowed_types.items():
        seen = {}
        for tab in tables:
            for path in spec.get(tab) or ():
                assert path not in seen, (t, path, seen.get(path), tab)
                seen[path] = tab
        for path in spec.get("target_ref_only") or {}:
            assert path.rsplit(".", 1)[-1] not in fact_attrs, (t, path)

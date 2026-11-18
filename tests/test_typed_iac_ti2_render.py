"""Typed IaC intent TI-2: value model + renderer (FD-4AW exfiltration surface).

Plan docs/planning/typed-iac-intent-plan.md §2.2 / §4 TI-2; RT docs/planning/typed-iac-intent-plan-red-team-fable.md F7;
lane 15 RT fixtures E1-E10 (docs/planning/wave2-lane15-plan-red-team-fable.md §2). Pure: no I/O beyond the committed
artifacts, no LLM, no tofu (the offline tofu evidence is eval/tools/iac_shadow.py)."""
import hermetic_guard  # noqa: F401  (first import)

import copy
import json
import os
import re
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import iac_intent as ii  # noqa: E402

ART = ii.load_artifacts()
CTX = ii.IntentContext(services={"api": ("module.compute", "compute-cloudrun")})


def F(fact):
    return {"$ref": {"kind": "fact", "fact": fact}}


def R(t, n, a):
    return {"$ref": {"kind": "resource_attr", "type": t, "name": n, "attr": a}}


def doc(*resources, modules=(), outputs=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources),
            "outputs": list(outputs)}


TOPIC = {"type": "google_pubsub_topic", "name": "events", "arguments": {"name": "events", "project": F("project_id")}}


def render(d):
    g = ii.validate_intent(d, ART, CTX)
    assert g.ok, [(x.code, x.attribute_path, x.message) for x in g.diagnostics]
    return ii.render_intent(g.validated)


def codes(d):
    return {x.code for x in ii.validate_intent(d, ART, CTX).diagnostics}


def custom(d):
    return json.loads(render(d).files[ii.RENDER_PATH])


# ------------------------------------------------------------------------------------------------ E8-E10 value model
def test_e8_model_builds_and_e10_refs_parse_at_depth_and_in_lists():
    deep = {"a": {"b": {"c": [1, {"d": F("region")}]}}}
    t = copy.deepcopy(TOPIC)
    t["arguments"]["labels"] = {"k": "v"}
    t["arguments"]["message_storage_policy"] = {"allowed_persistence_regions": [F("region")]}
    intent = ii.IacIntent.model_validate(doc(t))
    v = intent.resources[0].arguments["message_storage_policy"]["allowed_persistence_regions"][0]
    assert isinstance(v, ii.Ref) and v.ref.fact == "region"
    m = ii.IacIntent.model_validate(doc(dict(TOPIC, arguments=dict(TOPIC["arguments"], labels=deep))))
    assert isinstance(m.resources[0].arguments["labels"]["a"]["b"]["c"][1]["d"], ii.Ref)


def test_e10_bool_before_int_and_int_stays_int():
    m = ii.IacIntent.model_validate(doc(dict(TOPIC, arguments=dict(TOPIC["arguments"], labels={"a": True, "b": 1,
                                                                                               "c": 1.5}))))
    labels = m.resources[0].arguments["labels"]
    assert labels["a"] is True and type(labels["b"]) is int and type(labels["c"]) is float


@pytest.mark.parametrize("bad", [
    {"$ref": "google_pubsub_topic.t.name"},                                     # E9: string ref is not a Ref
    {"$ref": {"kind": "fact", "fact": "region"}, "extra": 1},                    # E9: $ref + extra key
    {"$bogus": "x"},                                                            # E9: unknown $ key
    {"$fn": "format", "$args": ["%s", "x"], "extra": True},
    {"$ref": {"kind": "fact", "fact": "not_a_fact"}},
])
def test_e9_malformed_reference_forms_are_rejected_not_passed_as_dicts(bad):
    t = copy.deepcopy(TOPIC)
    t["arguments"]["labels"] = {"k": bad}
    assert "IAC.RESERVED_KEY" in codes(doc(t))


@pytest.mark.parametrize("key", ["$x", "a${b}", "a%{if}", "//", "${file(\"/etc/hosts\")}"])
def test_e4_templated_or_reserved_object_keys_are_rejected_and_never_rendered(key):
    t = copy.deepcopy(TOPIC)
    t["arguments"]["labels"] = {key: "v"}
    assert "IAC.RESERVED_KEY" in codes(doc(t))
    with pytest.raises(ValueError):
        ii.render_parsed_for_shadow(ii.IacIntent.model_validate(doc(t)), ART, CTX)


# ------------------------------------------------------------------------------------------------ E1/E3 escaping
@pytest.mark.parametrize("literal", [
    '${file("/etc/hostname")}', "%{ if true }x%{ endif }", 'a"}%{ if file("/etc/hosts") != "" }LEAK%{ endif }',
    "$${already}", "%%{already}", "${", "%{", "$", "100%", "plain",
])
def test_e1_e3_literals_are_escaped_and_round_trip(literal):
    t = copy.deepcopy(TOPIC)
    t["arguments"]["labels"] = {"k": literal}
    out = custom(doc(t))["resource"]["google_pubsub_topic"]["events"]["labels"]["k"]
    assert out == ii.escape_template(literal)
    # HCL template unescaping ($${ -> ${, %%{ -> %{) gives back exactly the literal
    assert _hcl_unescape(out) == literal
    assert "${" not in out.replace("$${", "") and "%{" not in out.replace("%%{", "")


def _hcl_unescape(s):
    out, i = [], 0
    while i < len(s):
        if s.startswith("$${", i):
            out.append("${")
            i += 3
        elif s.startswith("%%{", i):
            out.append("%{")
            i += 3
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def test_hcl_string_literal_inside_call_escapes_quotes_backslashes_newlines_and_templates():
    lit = 'a"b\\c\nd\te${x}%{y}\x01'
    got = ii.hcl_string_literal(lit)
    assert got == '"a\\"b\\\\c\\nd\\te$${x}%%{y}\\u0001"'


# ------------------------------------------------------------------------------------------------ F7 renderer negatives
def _template_sites(obj, path=""):
    """Every string in the rendered JSON that contains an unescaped ${ (an interpolation)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            assert "${" not in k.replace("$${", ""), f"interpolation in a key at {path}/{k}"
            yield from _template_sites(v, f"{path}/{k}")
    elif isinstance(obj, list):
        for n, v in enumerate(obj):
            yield from _template_sites(v, f"{path}/{n}")
    elif isinstance(obj, str) and "${" in obj.replace("$${", ""):
        yield path, obj


RICH = doc(
    TOPIC,
    {"type": "google_pubsub_subscription", "name": "sub", "arguments": {
        "name": "sub", "topic": R("google_pubsub_topic", "events", "id"),
        "push_config": {"push_endpoint": {"$fn": "format", "$args": ["%s/api/v1/push",
                                                                     {"$ref": {"kind": "service", "service": "api",
                                                                               "output": "service_uri"}}]}},
        "labels": {"literal": "${file(\"/etc/passwd\")}"}}},
    {"type": "google_pubsub_topic_iam_member", "name": "pub", "arguments": {
        "topic": R("google_pubsub_topic", "events", "name"), "role": "roles/pubsub.publisher",
        "member": {"$member": {"service_account": F("workload_sa_email")}}}},
    {"type": "random_password", "name": "pw", "arguments": {"length": 24, "special": False}},
    {"type": "google_secret_manager_secret", "name": "s", "arguments": {
        "secret_id": {"$fn": "format", "$args": ["%s-key-${x}", F("product_id")]}, "replication": {"auto": {}}}},
    {"type": "google_secret_manager_secret_version", "name": "s", "arguments": {
        "secret": R("google_secret_manager_secret", "s", "id"),
        "secret_data": {"$fn": "jsonencode", "$args": [{"password": R("random_password", "pw", "result"),
                                                        "note": "q\"uote ${no}"}]}},
     "depends_on": [{"resource": {"type": "google_pubsub_topic", "name": "events"}}],
     "lifecycle": {"prevent_destroy": True, "ignore_changes": ["secret_data"]}},
    modules=[{"module": "storage-bucket", "name": "uploads", "args": {"bucket_name_suffix": "up${x}"}}],
    outputs=[{"name": "topic_id", "value": R("google_pubsub_topic", "events", "id")},
             {"name": "pw", "value": R("random_password", "pw", "result")}],
)

ALLOWED_INTERPOLATION = re.compile(
    r"^(\$\{(var|module|data|google_[a-z_]+|random_[a-z_]+|kubernetes_[a-z_]+)\.[A-Za-z0-9_.\[\]]+\}"
    r"|serviceAccount:\$\{[A-Za-z0-9_.\[\]]+\}"
    r"|\$\{(format|jsonencode)\(.*\)\})$", re.S)


def test_interpolation_appears_only_at_ref_member_call_positions():
    out = custom(RICH)
    sites = dict(_template_sites(out))
    assert sites, "the fixture renders references"
    for path, s in sites.items():
        assert ALLOWED_INTERPOLATION.match(s), (path, s)
    # literal strings never interpolate
    assert out["resource"]["google_pubsub_subscription"]["sub"]["labels"]["literal"] == '$${file("/etc/passwd")}'
    assert out["module"]["uploads"]["bucket_name_suffix"] == "up$${x}"
    # inside a Call, literal args are HCL string literals with templates escaped
    assert out["resource"]["google_secret_manager_secret"]["s"]["secret_id"] == \
        '${format("%s-key-$${x}", var.product_id)}'
    assert '"note" = "q\\"uote $${no}"' in out["resource"]["google_secret_manager_secret_version"]["s"]["secret_data"]


FORBIDDEN_KEYS = {"provisioner", "connection", "count", "for_each", "provider", "dynamic"}


def _all_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _all_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_keys(v)


def test_no_meta_argument_keys_and_provenance_only_at_top_level():
    out = custom(RICH)
    keys = list(_all_keys(out))
    assert not FORBIDDEN_KEYS & set(keys)
    assert keys.count("//") == 1 and "//" in out
    assert "intent_sha256=" + ii.intent_sha256(ii.IacIntent.model_validate(RICH)) in out["//"]


@pytest.mark.parametrize("meta", sorted(FORBIDDEN_KEYS | {"lifecycle", "depends_on"}))
def test_e6_meta_arguments_in_arguments_are_rejected_and_refused_by_the_renderer(meta):
    t = copy.deepcopy(TOPIC)
    t["arguments"][meta] = {"local-exec": {"command": "echo pwned"}} if meta == "provisioner" else 2
    assert "IAC.META_ARGUMENT_NOT_ALLOWED" in codes(doc(t))
    with pytest.raises(ValueError):
        ii.render_parsed_for_shadow(ii.IacIntent.model_validate(doc(t)), ART, CTX)


def test_e6_meta_argument_inside_a_nested_block_is_rejected():
    t = {"type": "google_secret_manager_secret", "name": "s",
         "arguments": {"secret_id": "s", "replication": {"auto": {}, "dynamic": {"x": 1}}}}
    assert "IAC.META_ARGUMENT_NOT_ALLOWED" in codes(doc(t))


@pytest.mark.parametrize("fn", ["file", "templatefile", "fileexists", "env", "uuid", "timestamp", "nonsensitive",
                                "try", "can", "regex", "toset"])
def test_e2_non_allow_listed_functions_are_rejected_and_refused_by_the_renderer(fn):
    t = copy.deepcopy(TOPIC)
    t["arguments"]["labels"] = {"k": {"$fn": fn, "$args": ["/etc/hosts"]}}
    assert "IAC.FUNCTION_NOT_ALLOWED" in codes(doc(t))
    with pytest.raises(ValueError):
        ii.render_parsed_for_shadow(ii.IacIntent.model_validate(doc(t)), ART, CTX)


def test_provider_function_syntax_is_not_a_function_name():
    t = copy.deepcopy(TOPIC)
    t["arguments"]["labels"] = {"k": {"$fn": "provider::x::y", "$args": []}}
    assert "IAC.RESERVED_KEY" in codes(doc(t))


def test_f7_call_set_includes_the_functions_the_drafts_use():
    assert {"trimsuffix", "trimprefix", "length", "base64encode", "replace", "format", "join", "jsonencode",
            "tostring", "lower", "upper", "concat", "merge", "coalesce"} == set(ART.functions)


def test_e5_depends_on_renders_plain_addresses():
    out = custom(RICH)
    assert out["resource"]["google_secret_manager_secret_version"]["s"]["depends_on"] == ["google_pubsub_topic.events"]


def test_e7_locals_variables_providers_data_are_not_expressible():
    for key in ("locals", "variable", "provider", "terraform", "data"):
        d = doc(TOPIC)
        d[key] = {"x": 1}
        assert codes(d) == {"JSON.OUTPUT_INVALID"}, key


def test_sensitive_reference_output_is_rendered_sensitive():
    out = custom(RICH)
    assert out["output"]["pw"]["sensitive"] is True and "sensitive" not in out["output"]["topic_id"]


def test_forced_values_are_rendered_and_module_facts_come_from_the_platform():
    b = {"type": "google_storage_bucket", "name": "b", "arguments": {"name": "b-x", "location": F("region")}}
    out = custom(doc(b, modules=[{"module": "storage-bucket", "name": "uploads", "args": {}}]))
    assert out["resource"]["google_storage_bucket"]["b"]["uniform_bucket_level_access"] is True
    assert out["module"]["uploads"] == {"source": "../modules/storage-bucket", "project_id": "${var.project_id}",
                                        "region": "${var.region}",
                                        "workload_sa_email": "${module.foundation.workload_sa_email}"}


def test_service_agent_facts_render_platform_data_sources_in_a_separate_platform_file():
    m = {"type": "google_pubsub_topic_iam_member", "name": "gcs", "arguments": {
        "topic": R("google_pubsub_topic", "events", "name"), "role": "roles/pubsub.publisher",
        "member": {"$member": {"service_agent": "pubsub_service_agent"}}}}
    r = render(doc(TOPIC, m))
    facts = json.loads(r.files[ii.FACTS_RENDER_PATH])
    assert facts["data"] == {"google_project": {"stackvend_intent_project": {"project_id": "${var.project_id}"}}}
    member = json.loads(r.files[ii.RENDER_PATH])["resource"]["google_pubsub_topic_iam_member"]["gcs"]["member"]
    assert member == ('serviceAccount:${format("service-%s@gcp-sa-pubsub.iam.gserviceaccount.com", '
                      'data.google_project.stackvend_intent_project.number)}')
    assert ii.FACTS_RENDER_PATH not in render(doc(TOPIC)).files


# ------------------------------------------------------------------------------------------------ determinism
def test_render_is_deterministic_and_rerender_is_byte_identical():
    a = render(RICH)
    shuffled = copy.deepcopy(RICH)
    shuffled["resources"][1]["arguments"] = dict(reversed(list(shuffled["resources"][1]["arguments"].items())))
    b = render(RICH)
    assert dict(a.files) == dict(b.files) and a.intent_sha256 == b.intent_sha256
    c = render(shuffled)   # argument order inside an entry does not change the bytes (sorted keys)
    assert dict(c.files) == dict(a.files)
    # re-render from the canonical form of the parsed intent is byte-identical
    canon = json.loads(ii.canonical_intent_json(ii.IacIntent.model_validate(RICH)))
    assert dict(render(canon).files) == dict(a.files)


def test_provenance_map_points_rendered_entries_back_to_intent_paths():
    r = render(RICH)
    assert r.provenance["/resource/google_pubsub_topic/events"] == "/resources/0"
    assert r.provenance["/module/uploads"] == "/modules/0"
    assert r.provenance["/output/topic_id"] == "/outputs/0"
    assert r.provenance["/resource/google_pubsub_subscription/sub/push_config"] == "/resources/1/arguments/push_config"


def test_render_intent_accepts_only_a_validated_intent():
    with pytest.raises(TypeError):
        ii.render_intent(ii.IacIntent.model_validate(RICH))
    with pytest.raises(TypeError):
        ii.ValidatedIntent(ii.IacIntent.model_validate(RICH), ART, CTX, "x")


# ------------------------------------------------------------------------------------------------ Gemini schema
def test_response_json_schema_generation_injects_the_data_driven_enums():
    s = ii.response_json_schema(ART)
    defs = s["$defs"]
    assert defs["ModuleInstance"]["properties"]["module"]["enum"] == list(ART.ai_modules)
    assert defs["ExtraResource"]["properties"]["type"]["enum"] == sorted(ART.allowed_types)
    assert defs["Call"]["properties"]["$fn"]["enum"] == sorted(ART.functions)
    json.dumps(s)   # serialisable as the request's response_json_schema

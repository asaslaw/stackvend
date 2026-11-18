"""TI-3j (register, owner 10-21): generate-mode "API-only" intent entries. A spec may enable an allow-listed Google API
plus its exact scoped workload role, with no infrastructure resource. The allow-list is an exact table
(shared/iac_intent.API_ONLY_SERVICES); the platform renders google_project_service + google_project_iam_member for the
workload SA fact; the AI names only the API. Negatives: an allow-list miss is refused with a typed code, an admin role
cannot be expressed, and an intent without API-only entries keeps its pre-TI-3j sha256 and render (Do No Harm).
Pure (artifacts, gate, render, python-hcl2-free), no network."""
import hermetic_guard  # noqa: F401  (first import)

import hashlib
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent import iac_intent_contract as C  # noqa: E402
from developer_agent import repair_loop as RL  # noqa: E402
from developer_agent.juniors import iac_worker  # noqa: E402
from developer_agent.validators import policy_tables as T  # noqa: E402
from shared import iac_intent as ii  # noqa: E402

ART = ii.load_artifacts()
CTX = ii.IntentContext()
FACT = (lambda f: {"$ref": {"kind": "fact", "fact": f}})
SA = {"$member": {"service_account": FACT("workload_sa_email")}}
AI = "aiplatform.googleapis.com"


def doc(api_only=(), resources=(), modules=()):
    d = {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources)}
    if api_only is not None:
        d["api_only"] = [{"service": s} for s in api_only]
    return d


# ------------------------------------------------------------------------------------------------ the exact table
def test_the_allow_list_is_exactly_the_reviewed_table():
    assert {s: dict(r["roles"]) for s, r in ii.API_ONLY_SERVICES.items()} == {
        "aiplatform.googleapis.com": {"roles/aiplatform.user": "aiplatform_user"},
        "documentai.googleapis.com": {"roles/documentai.apiUser": "documentai_api_user"},
        "speech.googleapis.com": {"roles/speech.client": "speech_client"},
        "translate.googleapis.com": {"roles/cloudtranslate.user": "cloudtranslate_user"},
        "vision.googleapis.com": {}, "language.googleapis.com": {}, "texttospeech.googleapis.com": {},   # TI-3j-c
    }
    labels = [r["label"] for r in ii.API_ONLY_SERVICES.values()]
    role_labels = [lbl for r in ii.API_ONLY_SERVICES.values() for lbl in r["roles"].values()]
    assert len(set(labels)) == len(labels) and len(set(role_labels)) == len(role_labels)
    import re
    for svc, row in ii.API_ONLY_SERVICES.items():
        assert re.fullmatch(ii.API_SERVICE_PATTERN.strip("^$"), svc)
        for lbl in [row["label"], *row["roles"].values()]:
            assert re.fullmatch(r"[a-z][a-z0-9_]{0,40}", lbl)


def test_no_admin_owner_editor_privileged_or_platform_owned_role_is_in_the_table():
    owned = {tuple(b) for k in ("platform_owned_bindings", "topology_owned_bindings")
             for b in (ART.allowed.get("not_expressible") or {}).get(k) or ()}
    for svc, row in ii.API_ONLY_SERVICES.items():
        # TI-3j-c: every row grants its exact role, or is in the explicit ENABLE_ONLY set and grants none
        assert bool(row["roles"]) is (svc not in ii.API_ONLY_ENABLE_ONLY), svc
        for role in row["roles"]:
            assert role.startswith("roles/") and role not in ("roles/owner", "roles/editor", "roles/viewer")
            tail = role.rsplit(".", 1)[-1].lower()
            assert not tail.endswith(("admin", "editor", "owner")), role
            assert role not in T.PRIVILEGED_ROLES and role not in T.IMPERSONATION_ROLES, role
            assert ("google_project_iam_member", role) not in T.PLATFORM_OWNED_BINDINGS | owned, role


def test_ti3j_c_enable_only_set_is_exactly_the_three_role_less_apis():
    """TI-3j-c (owner 10-25; read-only role check 11-07: no predefined role for Cloud Vision, Natural Language or
    Text-to-Speech). Negative: no other row may be role-less, and the set names only table rows."""
    assert ii.API_ONLY_ENABLE_ONLY == frozenset({"vision.googleapis.com", "language.googleapis.com",
                                                 "texttospeech.googleapis.com"})
    assert ii.API_ONLY_ENABLE_ONLY <= set(ii.API_ONLY_SERVICES)
    assert {s for s, r in ii.API_ONLY_SERVICES.items() if not r["roles"]} == ii.API_ONLY_ENABLE_ONLY
    for svc in sorted(ii.API_ONLY_SERVICES):   # removing a role from any granted row fails the rule above
        if svc not in ii.API_ONLY_ENABLE_ONLY:
            assert ii.API_ONLY_SERVICES[svc]["roles"], svc


def test_ti3j_c_enable_only_rows_render_the_api_and_no_grant():
    for svc in sorted(ii.API_ONLY_ENABLE_ONLY):
        r = ii.validate_intent(doc([svc]), ART, CTX)
        assert r.ok, [(d.code, d.message) for d in r.diagnostics]
        res = json.loads(ii.render_intent(r.validated).files[ii.RENDER_PATH])["resource"]
        label = ii.API_ONLY_SERVICES[svc]["label"]
        assert res == {"google_project_service": {f"stackvend_api_{label}": {
            "project": "${var.project_id}", "service": svc, "disable_on_destroy": False}}}
        assert ii.api_only_addresses(svc) == (f"google_project_service.stackvend_api_{label}",)
    # the rendered-policy check accepts exactly these bodies (no gate gap)
    r = ii.validate_intent(doc(sorted(ii.API_ONLY_ENABLE_ONLY) + [AI]), ART, CTX)
    assert _gaps(ii.render_intent(r.validated).files[ii.RENDER_PATH]) == []
    # no grant is ever refused as a duplicate next to an enable-only entry (it renders none)
    assert ii.validate_intent(doc(["vision.googleapis.com"], [GRANT]), ART, CTX).ok
    lines = iac_worker._api_only_lines()
    assert "- vision.googleapis.com: no role (the API needs none; the platform only enables it)" in lines
    assert "- aiplatform.googleapis.com: role roles/aiplatform.user" in lines   # granted rows: line unchanged


def test_table_apis_are_not_apis_the_foundation_or_vending_already_enable():
    from shared.api_requirements import load_table
    t = load_table()
    assert not set(ii.API_ONLY_SERVICES) & (set(t["base_apis"]) | set(t["foundation_base_apis"]))


def test_double_enablement_with_the_foundation_is_harmless_both_keep_the_api_on_destroy():
    """If a wired module ever enables the same API through the foundation's additional_apis (e.g. aiplatform once
    ai-vertex-endpoint is wired, pending R2), both google_project_service resources keep the API on destroy."""
    import hcl2
    with open(os.path.join(REPO_ROOT, "infra/modules/workload-foundation/base/apis.tf")) as fh:
        body = hcl2.loads(fh.read())["resource"][0]["google_project_service"]["apis"]
    assert body["disable_on_destroy"] is False
    r = ii.validate_intent(doc([AI]), ART, CTX)
    rendered = json.loads(ii.render_intent(r.validated).files[ii.RENDER_PATH])
    assert rendered["resource"]["google_project_service"]["stackvend_api_aiplatform"]["disable_on_destroy"] is False


# ------------------------------------------------------------------------------------------------ gate + render
def test_api_only_entry_renders_the_api_and_its_exact_role_for_the_workload_sa():
    r = ii.validate_intent(doc([AI, "translate.googleapis.com"]), ART, CTX)
    assert r.ok, [(d.code, d.message) for d in r.diagnostics]
    rr = ii.render_intent(r.validated)
    assert set(rr.files) == {ii.RENDER_PATH}   # no platform data source needed
    res = json.loads(rr.files[ii.RENDER_PATH])["resource"]
    assert res["google_project_service"] == {
        "stackvend_api_aiplatform": {"project": "${var.project_id}", "service": AI, "disable_on_destroy": False},
        "stackvend_api_translate": {"project": "${var.project_id}", "service": "translate.googleapis.com",
                                    "disable_on_destroy": False}}
    assert res["google_project_iam_member"] == {
        "stackvend_api_aiplatform_user": {
            "project": "${var.project_id}", "role": "roles/aiplatform.user",
            "member": "serviceAccount:${module.foundation.workload_sa_email}",
            "depends_on": ["google_project_service.stackvend_api_aiplatform"]},
        "stackvend_api_cloudtranslate_user": {
            "project": "${var.project_id}", "role": "roles/cloudtranslate.user",
            "member": "serviceAccount:${module.foundation.workload_sa_email}",
            "depends_on": ["google_project_service.stackvend_api_translate"]}}
    assert rr.facts_used == ("project_id", "workload_sa_email")
    assert rr.provenance["/resource/google_project_iam_member/stackvend_api_aiplatform_user"] == "/api_only/0"
    assert ii.api_only_services(r.intent) == (AI, "translate.googleapis.com")
    assert ii.api_only_addresses(AI) == ("google_project_service.stackvend_api_aiplatform",
                                         "google_project_iam_member.stackvend_api_aiplatform_user")


def test_allow_list_miss_is_refused_with_a_typed_code():
    for svc in ("discoveryengine.googleapis.com", "compute.googleapis.com", "iam.googleapis.com", "run.googleapis.com"):
        r = ii.validate_intent(doc([svc]), ART, CTX)
        assert not r.ok and r.codes == ("IAC.API_NOT_ALLOWED",), svc
        (d,) = r.diagnostics
        assert d.attribute_path == "/api_only/0/service" and AI in d.hint
    assert "IAC.API_NOT_ALLOWED" in C.INTENT_REMOVAL_CODES   # a repair may delete the refused entry


def test_an_admin_role_or_any_other_member_cannot_be_expressed():
    for extra in ({"role": "roles/owner"}, {"roles": ["roles/aiplatform.admin"]}, {"member": "user:a@b.c"}):
        r = ii.validate_intent({"schema": "iac_intent/v1", "api_only": [{"service": AI, **extra}]}, ART, CTX)
        assert not r.ok and r.codes == ("JSON.OUTPUT_INVALID",), extra
    for bad in ("aiplatform", "AIPLATFORM.googleapis.com", "aiplatform.googleapis.com.evil.com", "${var.x}", 7):
        r = ii.validate_intent({"schema": "iac_intent/v1", "api_only": [{"service": bad}]}, ART, CTX)
        assert not r.ok and r.codes == ("JSON.OUTPUT_INVALID",), bad
    rendered = json.dumps([ii.render_intent(ii.validate_intent(doc([s]), ART, CTX).validated).files
                           for s in ii.API_ONLY_SERVICES])
    for role in ("roles/owner", "roles/editor", ".admin"):
        assert role not in rendered


def test_duplicates_and_address_collisions_are_refused():
    r = ii.validate_intent(doc([AI, AI]), ART, CTX)
    assert r.codes == ("IAC.DUPLICATE_ADDRESS",) and r.diagnostics[0].attribute_path == "/api_only/1/service"
    clash = {"type": "google_project_iam_member", "name": "stackvend_api_aiplatform_user",
             "arguments": {"project": FACT("project_id"), "role": "roles/aiplatform.user", "member": SA}}
    r = ii.validate_intent(doc([AI], [clash]), ART, CTX)
    assert r.codes == ("IAC.DUPLICATE_ADDRESS",) and r.diagnostics[0].attribute_path == "/resources/0/name"
    assert ii.validate_intent(doc([], [clash]), ART, CTX).ok   # the name is free without the API-only entry
    for field in ("existing_addresses", "reserved_addresses"):
        ctx = ii.IntentContext(**{field: frozenset({"google_project_service.stackvend_api_aiplatform"})})
        assert ii.validate_intent(doc([AI]), ART, ctx).codes == ("IAC.DUPLICATE_ADDRESS",), field


def test_a_project_service_resource_gets_the_api_only_repair_hint():
    """Fable F1: the typed way to keep an API the code calls is named in the repair hint (and the table listed)."""
    r = ii.validate_intent(doc([], [{"type": "google_project_service", "name": "ai",
                                     "arguments": {"service": AI}}]), ART, CTX)
    (d,) = r.diagnostics
    assert d.code == "IAC.TYPE_NOT_ALLOWED" and "api_only" in d.hint
    assert all(s in d.hint for s in ii.API_ONLY_SERVICES)
    other = ii.validate_intent(doc([], [{"type": "google_compute_network", "name": "n", "arguments": {}}]), ART, CTX)
    assert "api_only" not in other.diagnostics[0].hint   # DNH: every other type keeps its hint


GRANT = {"type": "google_project_iam_member", "name": "gemini",
         "arguments": {"project": FACT("project_id"), "role": "roles/aiplatform.user", "member": SA}}


def test_duplicate_grant_next_to_an_api_only_entry_is_refused():
    """TI-3j-d (owner 10-25; Fable F3 accepted it before): an AI google_project_iam_member granting the workload SA a
    role an api_only entry already renders is refused with a typed code a repair may act on (delete the resource)."""
    r = ii.validate_intent(doc([AI], [GRANT]), ART, CTX)
    assert not r.ok and r.codes == (ii.API_ONLY_DUPLICATE_GRANT,)
    (d,) = r.diagnostics
    assert d.attribute_path == "/resources/0" and "/api_only/0" in d.message and "Delete" in d.hint
    assert ii.API_ONLY_DUPLICATE_GRANT in C.INTENT_REMOVAL_CODES   # a repair may delete the refused resource
    # the anchored diagnostic names the resource's own address (what a repair removal is judged on)
    assert C._anchor(d, C.intent_entry_addresses(r.intent)).block_address == "google_project_iam_member.gemini"
    for svc, row in ii.API_ONLY_SERVICES.items():   # every table role, exact table lookup (a role off role_allow
        for role in row["roles"]:                  # is also IAC.ROLE_NOT_ALLOWED, as before)
            g = {**GRANT, "arguments": {**GRANT["arguments"], "role": role}}
            assert ii.API_ONLY_DUPLICATE_GRANT in ii.validate_intent(doc([svc], [g]), ART, CTX).codes, role
    # the rendered-address collision keeps its one code (refused once, as before TI-3j-d)
    clash = {**GRANT, "name": "stackvend_api_aiplatform_user"}
    assert ii.validate_intent(doc([AI], [clash]), ART, CTX).codes == ("IAC.DUPLICATE_ADDRESS",)


def test_duplicate_grant_rule_leaves_every_other_grant_unchanged():
    """TI-3j-d Do No Harm: without the api_only entry, next to another API's entry, or for another member, the gate's
    outcome is what it was before."""
    assert ii.validate_intent(doc([], [GRANT]), ART, CTX).ok                  # no api_only entry: allowed as before
    assert ii.validate_intent(doc(None, [GRANT]), ART, CTX).ok
    assert ii.validate_intent(doc(["translate.googleapis.com"], [GRANT]), ART, CTX).ok   # that entry grants another
    agent = {**GRANT, "arguments": {**GRANT["arguments"],
                                    "member": {"$member": {"service_agent": "storage_service_agent"}}}}
    before = ii.validate_intent(doc([], [agent]), ART, CTX).codes
    assert ii.validate_intent(doc([AI], [agent]), ART, CTX).codes == before   # another member: unchanged outcome
    assert ii.API_ONLY_DUPLICATE_GRANT not in before


def test_shadow_render_refuses_an_off_table_service():
    intent = ii.IacIntent.model_validate(doc(["discoveryengine.googleapis.com"]))
    with pytest.raises(ValueError):
        ii.render_parsed_for_shadow(intent, ART, CTX)


def _gaps(render_text):
    from developer_agent.validators.base import ValidationContext
    from developer_agent.validators.iac_intent import RenderedIntentPolicyValidator
    asm = C.IntentAssembly(rendered=(ii.RENDER_PATH,), present=True)
    ctx = ValidationContext.build({ii.RENDER_PATH: render_text}, ownership=lambda p: None, extras={"iac_intent": asm})
    return [(d.code, d.block_address) for d in RenderedIntentPolicyValidator().validate(ctx)]


def test_rendered_policy_check_accepts_exactly_the_platform_api_only_bodies():
    r = ii.validate_intent(doc(list(ii.API_ONLY_SERVICES)), ART, CTX)
    text = ii.render_intent(r.validated).files[ii.RENDER_PATH]
    assert _gaps(text) == []
    base = json.loads(text)
    svc = base["resource"]["google_project_service"]
    for tamper in ({"service": "compute.googleapis.com"}, {"disable_on_destroy": True}, {"disable_dependent_services": True}):
        d = json.loads(text)
        d["resource"]["google_project_service"]["stackvend_api_aiplatform"].update(tamper)
        assert _gaps(json.dumps(d)) == [("PLATFORM.INTENT_GATE_GAP",
                                         "google_project_service.stackvend_api_aiplatform")], tamper
    d = json.loads(text)
    d["resource"]["google_project_service"]["other"] = dict(svc["stackvend_api_aiplatform"])
    assert _gaps(json.dumps(d)) == [("PLATFORM.INTENT_GATE_GAP", "google_project_service.other")]
    d = json.loads(text)
    d["resource"]["google_project_iam_member"]["stackvend_api_aiplatform_user"]["role"] = "roles/owner"
    assert _gaps(json.dumps(d)) == [("PLATFORM.INTENT_GATE_GAP", "google_project_iam_member.stackvend_api_aiplatform_user")]


def test_end_to_end_an_api_only_intent_passes_the_developer_stack_and_commits_the_platform_render():
    sys.path.insert(0, os.path.dirname(__file__))
    import test_typed_iac_ti3_contract as T3
    from unittest.mock import MagicMock, patch
    d = {"schema": "iac_intent/v1", "modules": [T3.BUCKET_MODULE], "api_only": [{"service": AI}]}
    draft = dict(T3.APP, **{C.INTENT_PATH: json.dumps(d, indent=2)})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        files, agent, client, _seen = T3._generate("generate", draft, att)
    assert agent.last_validation_report.status == "PASS"
    res = json.loads(files[ii.RENDER_PATH])["resource"]
    assert set(res["google_project_service"]) == {"stackvend_api_aiplatform"}
    assert set(res["google_project_iam_member"]) == {"stackvend_api_aiplatform_user"}
    assert client.validated and ii.RENDER_PATH in client.validated[-1]
    assert agent.stack_run("t-ti3")["iac_intent_warnings"] == []


# ------------------------------------------------------------------------------------------------ Do No Harm
# Pinned with the base commit's shared/iac_intent.py (ti-5-gate-fix 8f7b7138, before TI-3j) on these exact intents.
LEGACY = {
    "empty": ({"schema": "iac_intent/v1"},
              "b8de38beed7f57caaee3e91fd93c6102ee8155da96b4efbbead4a9faad29883e",
              "ce25a54efbdda29a9180f6ee5f0a33d6daa562ac96f006f88c59b8a40251f3c0"),
    "gemini_by_iam_only": ({"schema": "iac_intent/v1",
                            "resources": [{"type": "google_project_iam_member", "name": "gemini",
                                           "arguments": {"project": FACT("project_id"),
                                                         "role": "roles/aiplatform.user", "member": SA}}]},
                           "ed478bb74188ac52d4e9d48dcf7d7384f607fc8424c87bb983f83ef4c8849ba7",
                           "0b4c77c8ae812aa8868c5dc93fb3c0f3aec301e1ebeed1af62352af98c0b4558"),
}


@pytest.mark.parametrize("name", sorted(LEGACY))
def test_an_intent_without_api_only_entries_keeps_its_sha_and_render(name):
    d, sha, render_sha = LEGACY[name]
    for variant in (d, {**d, "api_only": []}):
        r = ii.validate_intent(variant, ART, CTX)
        assert r.ok and r.validated.sha256 == sha
        text = ii.render_intent(r.validated).files[ii.RENDER_PATH]
        assert hashlib.sha256(text.encode()).hexdigest() == render_sha
        assert "api_only" not in ii.canonical_intent_json(r.intent)


def test_contract_addresses_and_repair_preservation_cover_api_only_entries():
    r = ii.validate_intent(doc(["discoveryengine.googleapis.com"]), ART, CTX)
    entries = C.intent_entry_addresses(r.intent)
    assert entries["/api_only/0"] == "api_only.discoveryengine.googleapis.com"
    (d,) = [C._anchor(x, entries) for x in r.diagnostics]
    assert (d.block_address, d.attribute_path) == ("api_only.discoveryengine.googleapis.com", "/service")
    text = json.dumps(doc([AI]))
    assert RL._intent_addresses({C.INTENT_PATH: text}) == {"api_only." + AI}
    assert RL._intent_addresses({C.INTENT_PATH: json.dumps(doc(None))}) == set()   # legacy: unchanged


# ------------------------------------------------------------------------------------------------ prompt + schema
def test_the_iac_prompt_documents_the_table_and_the_structured_schema_enumerates_it():
    p = iac_worker.build_iac_intent_worker_prompt(ART)
    assert '"api_only": [{"service": "<an API of the API-ONLY list below>"}]' in p
    for svc, row in ii.API_ONLY_SERVICES.items():
        assert (f"- {svc}: role {', '.join(sorted(row['roles']))}" if row["roles"]
                else f"- {svc}: no role (the API needs none; the platform only enables it)") in p
    schema = ii.response_json_schema(ART)
    assert schema["$defs"]["ApiOnlyEntry"]["properties"]["service"]["enum"] == sorted(ii.API_ONLY_SERVICES)
    assert schema["$defs"]["ApiOnlyEntry"].get("additionalProperties") is False

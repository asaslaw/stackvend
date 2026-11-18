"""SECRET-INITIAL-VERSION (owner 11-10, plan docs/planning/secret-initial-version-plan.md).

Live defect: example 02 (`ex02-1110b`) deployed the secret `order-signing-secret` and its accessor grant but no secret
version, so the app's first read of `versions/latest` failed and a valid order answered HTTP 500.

Fix: the architect's typed topology states who supplies a secret's value (`resources[].initial_value`: "random" /
"operator"; absent = as before). For "random" the platform renders `generate_initial_version = true` on the golden
`security-secret` module that realizes it (a random_password first version, stable across applies), only when the
repository does not hold the secret yet (never shadows an operator's value) or already generated it (sticky). Secrets
created without a value are named at plan time (pre-build gate reason SECRET_CREATED_EMPTY). Hermetic.
"""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: put eval/.deps on PYTHONPATH; acceptance evidence must not skip", pytrace=False)

from developer_agent import iac_intent_contract as C  # noqa: E402
from developer_agent.contract_inspector import get_golden_module_contract  # noqa: E402
from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt  # noqa: E402
from developer_agent.topology_wiring import topology_contract_rule  # noqa: E402
from fd4f_support import FakeDB as GwFakeDB  # noqa: E402
from fd4f_support import gw  # noqa: E402,F401  (fixture)
from shared import iac_intent as II  # noqa: E402
from shared import service_topology as ST  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402

PID = "test-02-multi-cloudrun-mesh"
ART = II.load_artifacts()
MODULE_DIR = os.path.join(REPO_ROOT, "infra", "modules", "security-secret")
SECRET_TYPE = "google_secret_manager_secret"


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


# ------------------------------------------------------------------------------------------------ example 02 shape
def secret(initial_value=None, *, logical="order_signing_secret", attribute=None, service="service-b",
           env_key="ORDER_SIGNING_SECRET"):
    r = {"type": SECRET_TYPE, "logical_name": logical, "purpose": "order signing key",
         "consumers": [{"service": service, "env_key": env_key, "attribute": attribute}]}
    if initial_value is not None:
        r["initial_value"] = initial_value
    return r


def topo(*resources):
    """Example 02: a public gateway calling an internal core service over http; the core reads the secret."""
    return {"services": [{"name": "service-a", "kind": "cloudrun"}, {"name": "service-b", "kind": "cloudrun"}],
            "primary_service": "service-a",
            "edges": [{"caller": "service-a", "callee": "service-b", "protocol": "http"}],
            "resources": [dict(r) for r in resources]}


def vt_of(raw):
    vt, diags = ST.validate_service_topology(raw, product_id=PID)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def codes(raw, severity=None):
    _vt, diags = ST.validate_service_topology(raw, product_id=PID)
    return sorted(d.code for d in diags if severity is None or d.severity == severity)


SECRET_MODULE = {"module": "security-secret", "name": "order_signing_secret", "realizes": "order_signing_secret",
                 "args": {"secret_id": "order-signing-secret"}}
SECRET_RESOURCE = {"type": SECRET_TYPE, "name": "order_signing_secret", "realizes": "order_signing_secret",
                   "arguments": {"secret_id": "order-signing-secret", "replication": {"auto": {}}}}
AI_PASSWORD = {"type": "random_password", "name": "order_key", "arguments": {"length": 32, "special": False}}
AI_VERSION = {"type": "google_secret_manager_secret_version", "name": "order_key",
              "arguments": {"secret": {"$ref": {"kind": "module_output", "module": "order_signing_secret",
                                                "output": "secret_name"}},
                            "secret_data": {"$ref": {"kind": "resource_attr", "type": "random_password",
                                                     "name": "order_key", "attr": "result"}}}}


def intent(modules=(SECRET_MODULE,), resources=()):
    return json.dumps({"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources)}, indent=2)


def assemble(vt, intent_text, existing=None):
    files = {C.INTENT_PATH: intent_text}
    run = C.build_intent_run(vt, existing or {}, artifacts=ART)
    asm, _bound = C.assemble_intent(files, run, vt, ("module.foundation", "module.compute"),
                                    existing_files=existing or {}, record=AssemblyRecord())
    return asm, files


def rendered_module(files, name="order_signing_secret"):
    return json.loads(files[C.RENDER_PATH])["module"][name]


# ------------------------------------------------------------------------------------------------ 1. the typed field
def test_initial_value_is_an_exact_enum_on_secrets_only():
    assert ST.INITIAL_VALUES == ("random", "operator")
    for value in ("random", "operator"):
        assert vt_of(topo(secret(value))).secret_initial_values() == {"order_signing_secret": value}
    assert "TOPOLOGY.SCHEMA_INVALID" in codes(topo(secret("generated")))
    bucket = {"type": "google_storage_bucket", "logical_name": "uploads", "initial_value": "random",
              "consumers": [{"service": "service-b", "env_key": "UPLOADS_BUCKET"}]}
    assert codes(topo(bucket), "error") == ["TOPOLOGY.INITIAL_VALUE_NOT_APPLICABLE"]


def test_absent_on_a_secret_is_valid_and_adds_no_finding():
    """Do No Harm: a record written before the field validates exactly as before (no new finding, so the topology
    repair prompt, which lists every finding, is byte-identical); the pre-build gate names the secret instead."""
    vt, diags = ST.validate_service_topology(topo(secret()), product_id=PID)
    assert vt is not None and vt.secret_initial_values() == {"order_signing_secret": None}
    assert diags == []
    assert codes(topo(secret("random"))) == [] and codes(topo(secret("operator"))) == []


def test_a_random_secret_is_read_only_by_its_secret_id():
    assert codes(topo(secret("random", attribute="id")), "error") == ["TOPOLOGY.SECRET_ATTRIBUTE_NOT_GENERATED"]
    assert codes(topo(secret("random", attribute="secret_id")), "error") == []
    assert codes(topo(secret("operator", attribute="id")), "error") == []   # no generation: any catalog attribute
    assert ST.GENERATED_SECRET_ATTRIBUTES == frozenset(II.REALIZATION_EXPORTS[("security-secret", SECRET_TYPE)])


def test_absent_field_hashes_and_persists_exactly_as_before():
    """Do No Harm: a topology without the field (every record written before it) keeps its canonical JSON, sha256 and
    record, so the developer's prompts, topology.json and drift checks are unchanged."""
    vt = vt_of(topo(secret()))
    assert "initial_value" not in ST.canonical_topology_json(vt.intent)
    assert all("initial_value" not in r for r in vt.as_record()["intent"]["resources"])
    with_value = vt_of(topo(secret("random")))
    assert with_value.sha256 != vt.sha256
    assert json.loads(ST.canonical_topology_json(with_value.intent))["resources"][0]["initial_value"] == "random"
    # the persisted record re-validates (sha256 drift check) with and without the field
    for v in (vt, with_value):
        again, _diags = ST.topology_from_record(v.as_record(), product_id=PID)
        assert again is not None and again.sha256 == v.sha256


def test_architect_contract_and_schema_state_the_field():
    contract = ST.render_topology_contract()
    assert ST.SECRET_CONTRACT_LINE in contract and "`initial_value`" in contract
    schema = ST.ServiceTopologyIntent.model_json_schema()
    prop = schema["$defs"]["ResourceSpec"]["properties"]["initial_value"]
    assert {"enum": ["random", "operator"], "type": "string"} in prop["anyOf"]


# ------------------------------------------------------------------------------------------------ 2. the module
def _module_blocks():
    with open(os.path.join(MODULE_DIR, "main.tf")) as f:
        main = hcl2.load(f)
    res = {}
    for block in main["resource"]:
        for rtype, bodies in block.items():
            for name, body in bodies.items():
                res[(rtype, name)] = body
    with open(os.path.join(MODULE_DIR, "variables.tf")) as f:
        variables = {k: v for b in hcl2.load(f)["variable"] for k, v in b.items()}
    with open(os.path.join(MODULE_DIR, "outputs.tf")) as f:
        outputs = {k: v for b in hcl2.load(f)["output"] for k, v in b.items()}
    return main, res, variables, outputs


def test_module_generates_one_stable_version_only_when_asked():
    main, res, variables, outputs = _module_blocks()
    pw = res[("random_password", "initial")]
    assert pw["length"] == ST.GENERATED_SECRET_LENGTH and pw["special"] is False
    assert "keepers" not in pw, "no keepers: the value never changes on later applies"
    assert pw["count"] == "${var.generate_initial_version ? 1 : 0}"
    ver = res[("google_secret_manager_secret_version", "generated")]
    assert ver["count"] == "${var.generate_initial_version ? 1 : 0}"
    assert ver["secret_data"] == "${random_password.initial[0].result}"
    assert ver["deletion_policy"] == "ABANDON"
    assert ver["lifecycle"][0]["ignore_changes"] == ["${secret_data}"] or \
        ver["lifecycle"][0]["ignore_changes"] == ["secret_data"]
    var = variables["generate_initial_version"]
    assert var["type"] in ("bool", "${bool}") and var["default"] is False
    assert main["terraform"][0]["required_providers"][0]["random"]["source"] == "hashicorp/random"
    for name, body in outputs.items():   # the value is never a module output
        assert "random_password" not in json.dumps(body) and ".generated" not in json.dumps(body), name


def test_catalog_class_is_platform_owned_and_hidden_from_both_iac_prompts():
    var = ART.module("security-secret")["variables"]["generate_initial_version"]
    assert var["class"] == "TOPOLOGY" and var["count_driver"] is True and var["default"] is False
    assert II.MODULE_ARG_CLASS["generate_initial_version"]["class"] == "TOPOLOGY"
    assert "generate_initial_version" not in build_iac_intent_worker_prompt(ART)   # typed IaC prompt
    classic = get_golden_module_contract("security-secret", force_refresh=True)  # classic HCL prompt
    assert "secret_data" in classic and "generate_initial_version" not in classic


PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
MODULE_TEST = '''mock_provider "google" {}

variables {
  project_id        = "siv-test"
  secret_id         = "order-signing-secret"
  workload_sa_email = "sa@siv-test.iam.gserviceaccount.com"
}

run "default_creates_no_version" {
  command = plan
  assert {
    condition     = length(random_password.initial) == 0 && length(google_secret_manager_secret_version.generated) == 0 && length(google_secret_manager_secret_version.version) == 0
    error_message = "without generate_initial_version the module must plan no version (as before)"
  }
}

run "generated_version_is_planned" {
  command = plan
  variables {
    generate_initial_version = true
  }
  assert {
    condition     = length(random_password.initial) == 1 && random_password.initial[0].length == 64 && random_password.initial[0].special == false && length(google_secret_manager_secret_version.generated) == 1 && google_secret_manager_secret_version.generated[0].deletion_policy == "ABANDON" && length(google_secret_manager_secret_version.version) == 0
    error_message = "generate_initial_version must plan one 64-character random_password and one ABANDON version"
  }
}

run "generated_version_applies" {
  variables {
    generate_initial_version = true
  }
  assert {
    condition     = length(random_password.initial[0].result) == 64 && google_secret_manager_secret_version.generated[0].secret_data == random_password.initial[0].result
    error_message = "the version holds the generated value"
  }
}
'''


def test_module_plans_and_applies_with_the_production_engine(tmp_path):
    """Real OpenTofu 1.9.0 + the production provider mirror (mock google provider, real random provider), when the
    untracked production column is present (as tests/test_fd4cc_security_secret_root_validate.py)."""
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    sys.path.insert(0, os.path.join(REPO_ROOT, "eval"))
    from pathlib import Path

    from stackvend_eval.tofu_runner import TofuRunner
    runner = TofuRunner(tmp_path / "work", Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not runner.mirror_ready:
        pytest.skip(f"production mirror not verified: {runner.mirror_manifest['status']}")
    wd = tmp_path / "security-secret"
    (wd / "tests").mkdir(parents=True)
    for name in ("main.tf", "variables.tf", "outputs.tf"):
        (wd / name).write_text(open(os.path.join(MODULE_DIR, name)).read(), encoding="utf-8")
    (wd / "tests" / "siv.tftest.hcl").write_text(MODULE_TEST, encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-json", "-no-color"], cwd=wd)
    assert json.loads(r.stdout)["valid"], r.stdout[-3000:]
    r = runner._run(["test", "-test-directory=tests", "-filter=tests/siv.tftest.hcl", "-no-color"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "3 passed, 0 failed" in out, out[-4000:]


# ------------------------------------------------------------------------------------------------ 3. render
def test_ex02_random_secret_gets_the_generated_version():
    vt = vt_of(topo(secret("random")))
    asm, files = assemble(vt, intent())
    assert asm.diagnostics == ()
    body = rendered_module(files)
    assert body["generate_initial_version"] is True
    assert body["source"] == "../modules/security-secret" and body["secret_id"] == "order-signing-secret"
    assert "secret_data" not in body   # the value is never rendered: the module generates it


@pytest.mark.parametrize("value", ["operator", None], ids=["operator", "absent"])
def test_operator_and_absent_secrets_get_no_version(value):
    vt = vt_of(topo(secret(value)))
    asm, files = assemble(vt, intent())
    assert asm.diagnostics == ()
    body = rendered_module(files)
    assert "generate_initial_version" not in body
    assert set(body) == {"source", "project_id", "secret_id", "workload_sa_email"}


def test_absent_field_renders_byte_identically_to_operator_and_to_no_context():
    """The absent field is today's render: nothing is added (operator renders the same module body)."""
    _a, absent = assemble(vt_of(topo(secret())), intent())
    _o, operator = assemble(vt_of(topo(secret("operator"))), intent())
    assert json.loads(absent[C.RENDER_PATH])["module"] == json.loads(operator[C.RENDER_PATH])["module"]
    ctx = C.intent_context(vt_of(topo(secret())))
    assert ctx.secret_initial_values == {} and ctx.generated_secrets == frozenset()


def test_reapply_is_stable_the_second_build_renders_the_same_hcl():
    """A later build of the same workload (its repository now holds the committed intent and render) keeps the
    version: the same custom.tf.json, generate_initial_version still true (sticky), no new value."""
    vt = vt_of(topo(secret("random")))
    _asm, first = assemble(vt, intent())
    _asm2, second = assemble(vt, intent(), existing=dict(first))
    assert second[C.RENDER_PATH] == first[C.RENDER_PATH]
    assert rendered_module(second)["generate_initial_version"] is True
    # sticky even when a later plan stops saying "random" (the key is never abandoned and re-created)
    _asm3, third = assemble(vt_of(topo(secret("operator"))), intent(), existing=dict(first))
    assert rendered_module(third)["generate_initial_version"] is True


# ------------------------------------------------------------------------------------------------ 4. existing workloads
def _committed(render_generated):
    """A repository whose committed intent already realizes the secret, rendered with or without the version."""
    module = {"source": "../modules/security-secret", "secret_id": "order-signing-secret"}
    if render_generated:
        module["generate_initial_version"] = True
    return {C.INTENT_PATH: intent(), C.RENDER_PATH: json.dumps({"module": {"order_signing_secret": module}})}


def test_an_existing_secret_never_gets_a_new_version_and_the_operator_is_told():
    vt = vt_of(topo(secret("random")))
    generated, warnings = C.secret_generation(vt, _committed(False))
    assert generated == frozenset()
    assert [w["code"] for w in warnings] == ["SECRET.EXISTING_NOT_GENERATED"]
    assert warnings[0]["address"] == "module.order_signing_secret" and warnings[0]["stops_build"] is False
    asm, files = assemble(vt, intent(), existing=_committed(False))
    assert asm.diagnostics == () and "generate_initial_version" not in rendered_module(files)


def test_an_existing_secret_realized_by_a_resource_keeps_its_resource():
    """Do No Harm: no module is required for a secret that is not generated (the existing resource stays)."""
    vt = vt_of(topo(secret("random")))
    existing = {C.INTENT_PATH: intent(modules=(), resources=(SECRET_RESOURCE,))}
    generated, warnings = C.secret_generation(vt, existing)
    assert generated == frozenset() and warnings[0]["address"] == f"{SECRET_TYPE}.order_signing_secret"
    asm, _files = assemble(vt, intent(modules=(), resources=(SECRET_RESOURCE,)), existing=existing)
    assert asm.diagnostics == ()


def test_a_committed_render_with_the_version_is_sticky():
    for value in ("random", "operator", None):
        generated, warnings = C.secret_generation(vt_of(topo(secret(value))), _committed(True))
        assert generated == frozenset({"order_signing_secret"}) and warnings == (), value


def test_an_unreadable_committed_intent_never_generates():
    vt = vt_of(topo(secret("random")))
    for broken in ("{not json", json.dumps({"schema": "iac_intent/v1", "modules": "x"})):
        generated, warnings = C.secret_generation(vt, {C.INTENT_PATH: broken})
        assert generated == frozenset() and [w["code"] for w in warnings] == ["SECRET.EXISTING_NOT_GENERATED"]


def test_a_new_secret_beside_an_existing_intent_is_generated():
    vt = vt_of(topo(secret("random", logical="signing_key", env_key="SIGNING_KEY")))
    existing = {C.INTENT_PATH: intent(modules=(), resources=())}
    assert C.secret_generation(vt, existing) == (frozenset({"signing_key"}), ())


# ------------------------------------------------------------------------------------------------ 5. intent gate
def _gate_codes(vt, text, existing=None):
    asm, _files = assemble(vt, text, existing)
    return sorted({d.code for d in asm.diagnostics})


def test_the_ai_cannot_set_the_platform_input():
    vt = vt_of(topo(secret("random")))
    module = dict(SECRET_MODULE, args={"secret_id": "order-signing-secret", "generate_initial_version": False})
    assert _gate_codes(vt, intent(modules=(module,))) == ["IAC.PLATFORM_OWNED_ARGUMENT"]
    vt0 = vt_of(topo(secret()))   # also without the field: the input is never the AI's
    assert _gate_codes(vt0, intent(modules=(dict(module, args={"secret_id": "x", "generate_initial_version": True}),
                                            ))) == ["IAC.PLATFORM_OWNED_ARGUMENT"]


def test_a_generated_secret_is_realized_by_the_golden_module():
    vt = vt_of(topo(secret("random")))
    assert _gate_codes(vt, intent(modules=(), resources=(SECRET_RESOURCE,))) == \
        ["IAC.SECRET_REALIZATION_MODULE_REQUIRED"]
    assert "IAC.SECRET_REALIZATION_MODULE_REQUIRED" in C.INTENT_REMOVAL_CODES


@pytest.mark.parametrize("value", ["random", "operator"])
def test_the_intent_adds_no_version_to_a_stated_secret(value):
    vt = vt_of(topo(secret(value)))
    assert _gate_codes(vt, intent(resources=(AI_PASSWORD, AI_VERSION))) == ["IAC.SECRET_VERSION_PLATFORM_OWNED"]
    assert "IAC.SECRET_VERSION_PLATFORM_OWNED" in C.INTENT_REMOVAL_CODES


def test_negative_without_the_field_the_gate_is_unchanged():
    """Do No Harm: an AI version on a secret whose plan states nothing passes exactly as before."""
    vt = vt_of(topo(secret()))
    asm, files = assemble(vt, intent(resources=(AI_PASSWORD, AI_VERSION)))
    assert asm.diagnostics == ()
    assert "google_secret_manager_secret_version" in json.loads(files[C.RENDER_PATH])["resource"]


# ------------------------------------------------------------------------------------------------ 6. developer contract
def test_contract_lines_only_when_the_field_is_set():
    absent = topology_contract_rule(vt_of(topo(secret())), iac_intent=True)
    assert "first version" not in absent and "operator adds" not in absent
    assert C.secret_note_lines(vt_of(topo(secret()))) == []
    rnd = topology_contract_rule(vt_of(topo(secret("random"))), iac_intent=True)
    assert "`ORDER_SIGNING_SECRET` on `service-b` is the Secret Manager secret id of `order_signing_secret`, whose " \
           "first version the platform creates at deploy: 64 random letters and digits" in rnd
    assert "realize it with golden module security-secret; the platform creates its first version" in rnd
    assert "a google_secret_manager_secret resource" not in rnd   # only the module renders the version
    op = topology_contract_rule(vt_of(topo(secret("operator"))), iac_intent=True)
    assert "whose value an operator adds after the deploy" in op and "answer HTTP 503" in op
    assert "an operator adds its value: never declare a google_secret_manager_secret_version for it" in op
    assert topology_contract_rule(vt_of(topo(secret("random"))), iac_intent=False) == \
        topology_contract_rule(vt_of(topo(secret())), iac_intent=False)   # classic path: unchanged


def test_run_context_follows_the_dispatch_generation():
    vt = vt_of(topo(secret("random")))
    assert C.build_intent_run(vt, {}, artifacts=ART).generated_secrets == frozenset({"order_signing_secret"})
    existing = _committed(False)
    run = C.build_intent_run(vt, existing, artifacts=ART)
    assert run.generated_secrets == frozenset()
    assert "it already exists in this workload" in run.run_context


# ------------------------------------------------------------------------------------------------ 7. pre-build gate
def test_pure_secret_advisories():
    import workflow_gates as wg

    vt = vt_of(topo(secret("random"), secret("operator", logical="stripe_key", env_key="STRIPE_KEY"),
                    secret(logical="legacy", env_key="LEGACY_SECRET")))
    adv = wg.secret_advisories(vt)
    assert [(a["code"], a["secret"], a["services"]) for a in adv] == [
        ("SECRET.OPERATOR_VALUE_REQUIRED", "stripe_key", ["service-b"]),
        ("SECRET.VALUE_SOURCE_UNSTATED", "legacy", ["service-b"])]
    assert wg.secret_advisories(None) == [] and wg.secret_advisories(vt_of(topo(secret("random")))) == []
    assert wg.REASON_SECRET_CREATED_EMPTY in wg.PRE_BUILD_REASONS
    base = {"requires_human_approval": False, "has_policy_conflicts": False}
    fin = {"requires_human_approval": False, "monthly_cost_delta_usd": 1.0}
    # owner 11-10: warning-only. The advisories never add a reason; another reason still pauses as before
    assert wg.SECRET_ADVISORY_PAUSES_PLAN is False
    assert wg.evaluate_pre_build_gate(compliance=base, finops=fin, secret_advisories=[]) == ("PASS", [])
    assert wg.evaluate_pre_build_gate(compliance=base, finops=fin, secret_advisories=adv) == ("PASS", [])
    assert wg.evaluate_pre_build_gate(compliance=base, finops=fin, secret_advisories=adv, operator_requested=True) == (
        "AWAIT_APPROVAL", ["OPERATOR_REQUESTED"])
    with pytest.raises(ValueError):
        wg.secret_advisories(object())


TRACE = "t-siv"
CB = "https://workflowexecutions.googleapis.com/v1/callbacks/cb1"
CARD = f"approval_requests/appr-plan-{TRACE}-0"


def _gate(gw, record, operator_requested=False):
    db = GwFakeDB()
    db.docs[f"workloads/{PID}"] = {"product_id": PID}
    if record is not None:
        db.docs[f"pipeline_executions/{TRACE}"] = {"architect_compute_intent": record}
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    body = {"trace_id": TRACE, "product_id": PID, "callback_url": CB, "rework_cycle": 0,
            "compliance": {"requires_human_approval": False, "has_policy_conflicts": False,
                           "allow_unauthenticated": True},
            "finops": {"requires_human_approval": False, "monthly_cost_delta_usd": 1.0}, "finops_error": "",
            "policy_harvest_status": "SUCCESS", "operator_requested": operator_requested, "spec_doc_id": "",
            "task_dag": []}
    return TestClient(gw.app).post("/events/pre-build-gate", json=body), db


def _record(*resources):
    vt = vt_of(topo(*resources))
    return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names),
            "compute_archetype": vt.archetype, "service_topology": vt.as_record()}


SECRET_KEYS = ("secret_advisories", "secret_advisories_omitted")


def _decision(db, *, keep_secret=False):
    gate = dict(db.docs[f"pipeline_executions/{TRACE}"]["prebuild_gate"])
    gate.pop("decided_at")
    return gate if keep_secret else {k: v for k, v in gate.items() if k not in SECRET_KEYS}


@pytest.mark.parametrize("value, code", [("operator", "SECRET.OPERATOR_VALUE_REQUIRED"),
                                         (None, "SECRET.VALUE_SOURCE_UNSTATED")], ids=["operator", "unstated"])
def test_warning_only_a_secret_alone_never_pauses_the_plan(gw, value, code):
    """Owner 11-10 "warning-only": the run goes on exactly as without the secret (the same answer, no approval
    record, the same gate decision), and the persisted decision keeps the typed advisory beside it."""
    r, db = _gate(gw, _record(secret(value)))
    r0, db0 = _gate(gw, _record(secret("random")))   # the same plan shape with nothing to warn about: today's path
    assert r.status_code == 200, r.text
    assert r.json() == r0.json() == {"status": "SUCCESS", "decision": "PASS", "gate_reasons": [], "approval_id": ""}
    assert not [k for k in db.docs if k.startswith("approval_requests/")]
    assert _decision(db) == _decision(db0, keep_secret=True)   # decision, reasons, ids: unchanged
    gate = db.docs[f"pipeline_executions/{TRACE}"]["prebuild_gate"]
    assert [a["code"] for a in gate["secret_advisories"]] == [code] and gate["secret_advisories_omitted"] == 0
    assert db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["secret_advisories"] == gate["secret_advisories"]


def test_with_another_pause_reason_the_card_shows_the_secret(gw):
    r, db = _gate(gw, _record(secret("operator")), operator_requested=True)
    assert r.json()["decision"] == "AWAIT_APPROVAL" and r.json()["gate_reasons"] == ["OPERATOR_REQUESTED"]
    card = db.docs[CARD]
    assert card["gate_reasons"] == ["OPERATOR_REQUESTED"]
    assert card["risk_assessment"] == ("Pre-build gate: OPERATOR_REQUESTED (secrets the platform creates without a "
                                       "value: unless the workload's own infrastructure adds one, an operator must "
                                       "add it in Secret Manager before the app can read it: order_signing_secret)")
    assert [a["code"] for a in card["secret_advisories"]] == ["SECRET.OPERATOR_VALUE_REQUIRED"]
    assert card["secret_advisories_omitted"] == 0


def test_negative_another_pause_without_secrets_keeps_todays_card(gw):
    _r, db = _gate(gw, _record(secret("random")), operator_requested=True)
    card = db.docs[CARD]
    assert card["risk_assessment"] == "Pre-build gate: OPERATOR_REQUESTED" and card["secret_advisories"] == []


@pytest.mark.parametrize("record", [None, {"schema": "architect_compute_intent/v1"}], ids=["no record", "no topology"])
def test_random_or_no_topology_secret_passes_unchanged(gw, record):
    for rec in (_record(secret("random")), record):
        r, db = _gate(gw, rec)
        assert r.json() == {"status": "SUCCESS", "decision": "PASS", "gate_reasons": [], "approval_id": ""}
        assert set(db.docs[f"pipeline_executions/{TRACE}"]["prebuild_gate"]) & set(SECRET_KEYS) == set()


def test_unreadable_or_invalid_facts_stop_typed(gw):
    db = GwFakeDB()
    db.fail_reads = True
    with pytest.raises(gw.GateUnavailableError) as e:
        gw._plan_secret_advisories(db, PID, TRACE)
    assert e.value.reason == "SECRET_ADVISORY_FACTS_UNAVAILABLE"
    bad = _record(secret("operator"))
    bad["service_topology"] = dict(bad["service_topology"], sha256="0" * 64)   # drift: not what the platform wrote
    r, _db = _gate(gw, bad)
    assert r.status_code == 503 and r.json()["error_class"] == "PLATFORM_DEFECT"
    assert "SECRET_ADVISORY_FACTS_INVALID" in r.text

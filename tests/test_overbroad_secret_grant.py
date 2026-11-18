"""OVERBROAD-SECRET-GRANT (owner 11-14, ex08-1114 diagnosis §5.3): a project-level Secret Manager or IAM-admin role
granted by developer-owned IaC is a BLOCKING typed finding routed to the developer (CODE_DEFECT, removable so the
repair can replace it with the grant on the one secret).

Typed path: the intent gate's IAC.PROJECT_WIDE_GRANT (shared/iac_intent.py `_Gate.iam`), with the role off the
google_project_iam_member role table; defense in depth: V-IAC-RENDER reports it in the render as a gate gap.
Classic path: V2a's POLICY.PROJECT_WIDE_GRANT on AI-written HCL (validators/step1.py PolicyValidator).
Negatives (Do No Harm): the same role on one secret passes unchanged; every other project role passes unchanged; a
golden module's own secret grant (grant_workload_secret_access) is platform-rendered and not judged; a PRIVILEGED
role keeps its one POLICY.PRIVILEGED_ROLE finding. Exact table membership only. Pure, no network."""
import hermetic_guard  # noqa: F401  (first import)

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
from developer_agent.validators import policy_tables as T  # noqa: E402
from shared import iac_intent as ii  # noqa: E402
from shared.diagnostics import ErrorClass  # noqa: E402

ART = ii.load_artifacts()
CTX = ii.IntentContext(services={"api": ("module.compute", "compute-cloudrun")})
NET_CTX = ii.IntentContext(services=CTX.services, facts=dict(ii.default_facts(), network="var.network_id",
                                                            zone="var.zone"))
ACCESSOR = "roles/secretmanager.secretAccessor"


def F(fact):
    return {"$ref": {"kind": "fact", "fact": fact}}


def R(t, n, a):
    return {"$ref": {"kind": "resource_attr", "type": t, "name": n, "attr": a}}


WSA = {"$member": {"service_account": F("workload_sa_email")}}
OTHER_SA = {"$member": {"service_account": R("google_service_account", "w", "email")}}
SA = {"type": "google_service_account", "name": "w", "arguments": {"account_id": "worker-sa"}}
SECRET = {"type": "google_secret_manager_secret", "name": "creds",
          "arguments": {"secret_id": "creds", "replication": {"auto": {}}}}


def doc(*resources, modules=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources)}


def project_grant(role=ACCESSOR, member=WSA, name="workload_secret_accessor"):
    return {"type": "google_project_iam_member", "name": name,
            "arguments": {"project": F("project_id"), "role": role, "member": member}}


def secret_grant(role=ACCESSOR):
    return {"type": "google_secret_manager_secret_iam_member", "name": "creds_reader",
            "arguments": {"secret_id": R("google_secret_manager_secret", "creds", "secret_id"), "role": role,
                          "member": WSA}}


def gate(d, ctx=CTX):
    return ii.validate_intent(d, ART, ctx)


# ------------------------------------------------------------------------------------------------ the table
def test_deny_table_is_exact_and_disjoint_from_every_project_role_table():
    assert ii.PROJECT_WIDE_SECRET_ROLES == frozenset({
        "roles/secretmanager.secretAccessor", "roles/secretmanager.secretVersionManager",
        "roles/secretmanager.secretVersionAdder", "roles/secretmanager.admin"})
    assert ii.PROJECT_WIDE_IAM_ADMIN_ROLES == frozenset({
        "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin", "roles/iam.roleAdmin",
        "roles/iam.serviceAccountAdmin", "roles/iam.serviceAccountKeyAdmin"})
    assert ii.PROJECT_WIDE_DENIED_ROLES == ii.PROJECT_WIDE_SECRET_ROLES | ii.PROJECT_WIDE_IAM_ADMIN_ROLES
    assert ii.PROJECT_WIDE_GRANT_TYPES == T.PROJECT_LEVEL_IAM_TYPES
    roles = ART.allowed["role_allow"]
    for rtype, spec in ART.allowed_types.items():
        if rtype in ii.PROJECT_WIDE_GRANT_TYPES and spec.get("iam"):
            assert not set(roles[spec["iam"]["role_table"]]) & ii.PROJECT_WIDE_DENIED_ROLES, rtype
    # the scoped form stays expressible: the accessor role on the one secret
    assert ACCESSOR in roles["google_secret_manager_secret_iam_member"]
    # the platform's own project grants (api_only) never hit the table
    for row in ii.API_ONLY_SERVICES.values():
        assert not set(row["roles"]) & ii.PROJECT_WIDE_DENIED_ROLES
    # one table for both paths, both codes removable by a repair (the scoped grant replaces the refused one)
    assert T.PROJECT_WIDE_DENIED_ROLES is ii.PROJECT_WIDE_DENIED_ROLES
    assert ii.PROJECT_WIDE_GRANT_CODE in C.INTENT_REMOVAL_CODES and ii.PROJECT_WIDE_GRANT_CODE in RL.REMOVAL_CODES
    assert T.PROJECT_WIDE_GRANT_POLICY_CODE in RL.REMOVAL_CODES


def test_gateway_copies_are_byte_identical():
    for rel in (("iac_intent.py",), ("iac_intent", "allowed_types.json")):
        a = open(os.path.join(REPO_ROOT, "shared", *rel), "rb").read()
        b = open(os.path.join(GATEWAY, "shared", *rel), "rb").read()
        assert a == b, rel


# ------------------------------------------------------------------------------------------------ typed gate
def test_ex08_project_wide_secret_accessor_is_a_blocking_developer_finding():
    """ex08-1114: the developer intent's decoy secret plus a project-wide accessor grant to the workload SA."""
    r = gate(doc(SECRET, project_grant()))
    assert not r.ok and r.codes == (ii.PROJECT_WIDE_GRANT_CODE,)
    (d,) = r.diagnostics
    assert d.severity == "error" and d.error_class is ErrorClass.CODE_DEFECT and d.source == "precommit"
    assert d.file == C.INTENT_PATH and d.attribute_path == "/resources/1/arguments/role"
    assert "google_project_iam_member.workload_secret_accessor" in d.message and ACCESSOR in d.message
    assert "google_secret_manager_secret_iam_member" in d.hint and "grant_workload_secret_access" in d.hint
    # the anchored finding names the resource a repair replaces
    assert C._anchor(d, C.intent_entry_addresses(r.intent)).block_address == \
        "google_project_iam_member.workload_secret_accessor"


@pytest.mark.parametrize("role", sorted(ii.PROJECT_WIDE_DENIED_ROLES))
@pytest.mark.parametrize("member", [WSA, OTHER_SA], ids=["workload_sa", "other_sa"])
def test_every_denied_role_gets_exactly_the_typed_code(role, member):
    r = gate(doc(SA, SECRET, project_grant(role, member)))
    assert r.codes == (ii.PROJECT_WIDE_GRANT_CODE,), [(x.code, x.attribute_path) for x in r.diagnostics]
    hint = r.diagnostics[0].hint
    if role in ii.PROJECT_WIDE_SECRET_ROLES:
        assert "google_secret_manager_secret_iam_member" in hint
        # RT F2: the hint names a role the scoped table allows, also for admin / secretVersionManager
        assert ACCESSOR in hint
        assert ACCESSOR in ART.allowed["role_allow"]["google_secret_manager_secret_iam_member"]
    else:
        assert "Delete this resource" in hint
    assert role in hint and "{role}" not in hint


def test_negative_the_same_role_on_one_secret_passes_unchanged():
    r = gate(doc(SECRET, secret_grant()))
    assert r.ok, [(x.code, x.attribute_path) for x in r.diagnostics]
    for role in ART.allowed["role_allow"]["google_secret_manager_secret_iam_member"]:
        assert gate(doc(SECRET, secret_grant(role))).ok, role


def test_negative_every_other_project_role_passes_unchanged():
    for role in ART.allowed["role_allow"]["google_project_iam_member"]:
        r = gate(doc(project_grant(role, name="g")))
        assert r.ok, (role, r.codes)


def test_negative_an_off_table_role_keeps_the_generic_refusal():
    for role in ("roles/storage.admin", "roles/viewer", "roles/secretmanager.viewer"):
        assert gate(doc(project_grant(role, name="g"))).codes == ("IAC.ROLE_NOT_ALLOWED",), role


def test_negative_golden_module_secret_grant_is_platform_rendered_and_not_judged():
    """database-cloudsql's own accessor grant on its password secret (grant_workload_secret_access) is the module's
    resource, not an AI-written one: the gate accepts the instance."""
    mod = {"module": "database-cloudsql", "name": "postgres", "args": {"grant_workload_secret_access": True}}
    r = gate(doc(modules=[mod]), ctx=NET_CTX)
    assert r.ok, [(x.code, x.attribute_path) for x in r.diagnostics]


def test_typed_worker_prompt_no_longer_offers_the_project_wide_accessor():
    from developer_agent.juniors import iac_worker
    prompt = iac_worker.build_iac_intent_worker_prompt(ART)
    (proj,) = [x for x in prompt.split("\n") if x.startswith("- google_project_iam_member:")]
    (scoped,) = [x for x in prompt.split("\n") if x.startswith("- google_secret_manager_secret_iam_member:")]
    assert ACCESSOR not in proj and ACCESSOR in scoped
    assert "roles/datastore.user" in proj   # the rest of the table is unchanged


# ------------------------------------------------------------------------------------------------ render (defense in depth)
def _gaps(render_text):
    from developer_agent.validators.base import ValidationContext
    from developer_agent.validators.iac_intent import RenderedIntentPolicyValidator
    asm = C.IntentAssembly(rendered=(ii.RENDER_PATH,), present=True)
    ctx = ValidationContext.build({ii.RENDER_PATH: render_text}, ownership=lambda p: None, extras={"iac_intent": asm})
    return [(d.code, d.block_address, d.error_class) for d in RenderedIntentPolicyValidator().validate(ctx)]


def test_render_check_reports_a_project_wide_grant_as_a_gate_gap_only():
    r = gate(doc(SECRET, secret_grant()))
    text = ii.render_intent(r.validated).files[ii.RENDER_PATH]
    assert _gaps(text) == []   # the scoped grant renders clean
    d = json.loads(text)
    d["resource"]["google_project_iam_member"] = {"x": {"project": "p", "role": ACCESSOR, "member": "serviceAccount:a"}}
    assert _gaps(json.dumps(d)) == [("PLATFORM.INTENT_GATE_GAP", "google_project_iam_member.x",
                                     ErrorClass.PLATFORM_DEFECT)]
    # the platform's api_only project grants keep passing
    api = ii.validate_intent({"schema": "iac_intent/v1", "modules": [], "resources": [],
                              "api_only": [{"service": s} for s in ii.API_ONLY_SERVICES]}, ART, ii.IntentContext())
    assert _gaps(ii.render_intent(api.validated).files[ii.RENDER_PATH]) == []


# ------------------------------------------------------------------------------------------------ classic V2a
pytest_hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
W = "infra/workload/"


def _policy(text):
    from developer_agent.validators.base import ValidationContext
    from developer_agent.validators.step1 import PolicyValidator
    from shared.artifact_ownership import Ownership
    files = {W + "custom.tf": text}
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, vendored=frozenset(), draft={},
                                  assembly=None, extras={}, trace_id="t")
    return PolicyValidator().validate(ctx)


def _hcl(rtype, role, extra=""):
    return (f'resource "{rtype}" "g" {{\n{extra}  project = var.project_id\n  role    = "{role}"\n'
            '  member  = "serviceAccount:${module.foundation.workload_sa_email}"\n}\n')


def test_classic_project_wide_secret_accessor_is_blocking():
    (d,) = _policy(_hcl("google_project_iam_member", ACCESSOR))
    assert d.code == "POLICY.PROJECT_WIDE_GRANT" and d.severity == "error" and d.attribute_path == "role"
    assert d.block_address == "google_project_iam_member.g" and "google_secret_manager_secret_iam_member" in d.hint
    from developer_agent.validators.step1 import build_step1_stack
    assert build_step1_stack(validate_client=None, verifier_factory=None).mode_of("V2a") == "blocking"


def test_classic_iam_admin_role_and_privileged_overlap():
    (d,) = _policy(_hcl("google_project_iam_member", "roles/iam.roleAdmin"))
    assert d.code == "POLICY.PROJECT_WIDE_GRANT" and "Delete this resource" in d.hint
    for role in ii.PROJECT_WIDE_DENIED_ROLES & T.PRIVILEGED_ROLES:   # one finding per grant, the existing code
        assert [x.code for x in _policy(_hcl("google_project_iam_member", role))] == ["POLICY.PRIVILEGED_ROLE"], role


def test_classic_negative_scoped_and_other_grants_unchanged():
    scoped = _hcl("google_secret_manager_secret_iam_member", ACCESSOR,
                  extra="  secret_id = google_secret_manager_secret.creds.secret_id\n").replace(
        "  project = var.project_id\n", "")
    assert _policy(scoped) == []
    assert _policy(_hcl("google_project_iam_member", "roles/datastore.user")) == []
    assert _policy(_hcl("google_project_iam_member", "roles/secretmanager.viewer")) == []   # not on the table


def test_classic_non_literal_role_is_not_seen_today():
    """RT F1: classic V2a reads literal roles only (same limit as POLICY.PRIVILEGED_ROLE). Pinned so that closing
    the gap (evaluating the role from the plan JSON) is a decision, not an accident; the typed path has no such gap."""
    text = ('resource "google_project_iam_member" "g" {\n'
            '  for_each = toset(["roles/secretmanager.secretAccessor"])\n'
            '  project  = var.project_id\n  role     = each.value\n'
            '  member   = "serviceAccount:${module.foundation.workload_sa_email}"\n}\n')
    assert [d.code for d in _policy(text)] == []

"""APP-ADMIN-IAP-CONTRACT + APP-ADMIN-DEFAULT (owner 11-16, live example 09 run 11-16): the app administrators of a
Direct IAP (PRIVATE_IAP) Cloud Run workload.

Live defect: the generated app had a SuperAdmin role nobody could ever hold (every user without a role document was a
Viewer, and only a SuperAdmin could write one); an earlier run "passed" only because its code made the first visitor
SuperAdmin (trust on first use). The platform told neither the code writers nor the judges how the first administrator
is granted.

Pinned here:
* shared.access_policy: the effective admin list (record > verified submitter that is an exact `user:` invoker > none)
  and the two typed provenance fields it reads (never a creator field);
* access_resolution / handler: the run's ResolvedAccess carries it; the handler renders it only under the Direct IAP
  rule's gate and records a typed warning when it is empty;
* terraform_engine: `variable "app_admin_emails"` + `STACKVEND_APP_ADMIN_EMAILS = jsonencode(var.app_admin_emails)` on
  every platform Cloud Run module; None = byte-identical output (Do No Harm) for PUBLIC_APP, PRIVATE_IAM and non-Cloud
  Run workloads;
* prompt: the admin rule rides on the Direct IAP rule only;
* QA: the typed app administrator fact (count only) for both lenses, only for a Direct IAP Cloud Run commit whose root
  declares the variable;
* runtime env advisory: the platform-set env is a provided name;
* Control Center: a new intake workload records its verified submitter; a re-create never changes it.
Hermetic: no network, no Firestore, no LLM.
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import hashlib
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(os.path.abspath(__file__))
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import access_policy as ap  # noqa: E402
from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent import prompt as P  # noqa: E402
from developer_agent.access_resolution import resolve_access  # noqa: E402
from qa_auditor import judge_input as JI  # noqa: E402
from qa_auditor.platform_facts import build_platform_facts  # noqa: E402

ADMIN = "admin@example.com"
SUBMITTER_DOC = {"verified_submitter": {"member": f"user:{ADMIN}", "source": "submitter",
                                        "verified_by": "control_center_auth"}}
IAP_ON = {"allow_unauthenticated": False, "enable_direct_iap": True}
ENV_LINE = '"STACKVEND_APP_ADMIN_EMAILS" = jsonencode(var.app_admin_emails)'
VAR_DECL = 'variable "app_admin_emails"'


def _policy(invokers=(f"user:{ADMIN}",), admins=(), mode="PRIVATE_IAP"):
    return ap.AccessPolicy(mode=mode, invoker_principals=list(invokers), app_admin_emails=list(admins),
                           sign_in=ap.SignInPolicy(google="DISABLED"), source="intake")


# ------------------------------------------------------------------------------------------------ effective admins
def test_record_admins_win_in_record_order():
    assert ap.effective_app_admin_emails(_policy(admins=("b@example.com", "a@example.com")), f"user:{ADMIN}") == (
        ["b@example.com", "a@example.com"], ap.APP_ADMIN_SOURCE_RECORD)


def test_empty_record_defaults_to_the_verified_submitter_when_an_exact_user_invoker():
    assert ap.effective_app_admin_emails(_policy(), f"user:{ADMIN}") == ([ADMIN], ap.APP_ADMIN_SOURCE_SUBMITTER)


@pytest.mark.parametrize("invokers, submitter", [
    (("user:other@example.com",), f"user:{ADMIN}"),            # not an invoker
    (("group:staff@example.com",), f"user:{ADMIN}"),           # member of a group: membership is never resolved
    (("domain:example.com",), f"user:{ADMIN}"),                # whole domain: never "every invoker"
    ((f"user:{ADMIN}",), None),                                # no verified submitter
    ((f"user:{ADMIN}",), f"group:{ADMIN}"),                    # never a group
    ((f"user:{ADMIN}",), ADMIN),                               # unprefixed: not a member string
])
def test_otherwise_nobody_is_an_admin(invokers, submitter):
    assert ap.effective_app_admin_emails(_policy(invokers=invokers), submitter) == ([], ap.APP_ADMIN_SOURCE_NONE)


def test_public_app_has_no_submitter_default():
    pub = ap.AccessPolicy(mode="PUBLIC_APP", sign_in=ap.SignInPolicy(google="SHARED_PLATFORM_CLIENT"),
                          tenant_isolation_required=False, source="intake")
    assert ap.effective_app_admin_emails(pub, f"user:{ADMIN}") == ([], ap.APP_ADMIN_SOURCE_NONE)


@pytest.mark.parametrize("doc, expected", [
    (SUBMITTER_DOC, f"user:{ADMIN}"),
    ({"access_default_submitter": ap.submitter_provenance(f"user:{ADMIN}", "drive_file_owner")}, f"user:{ADMIN}"),
    ({"creator_email": ADMIN, "initialized_by": ADMIN}, None),                    # creator fields are not verified
    ({"verified_submitter": {"member": f"user:{ADMIN}", "source": "form", "verified_by": "control_center_auth"}}, None),
    ({"verified_submitter": {"member": f"user:{ADMIN}", "source": "submitter", "verified_by": "request_body"}}, None),
    ({"verified_submitter": {"member": "user:svc@p.iam.gserviceaccount.com", "source": "submitter",
                             "verified_by": "control_center_auth"}}, None),       # never a service account
    ({"verified_submitter": {"member": f"group:{ADMIN}", "source": "submitter",
                             "verified_by": "control_center_auth"}}, None),
    ({"verified_submitter": {"member": f"user:{ADMIN.upper()}", "source": "submitter",
                             "verified_by": "control_center_auth"}}, None),       # exact canonical form only
    ({"verified_submitter": f"user:{ADMIN}"}, None),
    (None, None), ("x", None), ({}, None),
])
def test_verified_submitter_is_read_only_from_typed_provenance(doc, expected):
    assert ap.workload_verified_submitter(doc) == expected


@pytest.mark.parametrize("copy", ["apps/control-center/shared/access_policy.py",
                                  "apps/orchestrator-gateway/shared/access_policy.py",
                                  "mcp-servers/terraform/shared/access_policy.py"])
def test_access_policy_replicas_are_byte_identical(copy):
    with open(os.path.join(REPO_ROOT, "shared", "access_policy.py"), "rb") as a, \
            open(os.path.join(REPO_ROOT, copy), "rb") as b:
        assert hashlib.sha256(a.read()).digest() == hashlib.sha256(b.read()).digest()


# ------------------------------------------------------------------------------------------------ resolution
def _record(**kw):
    rec = {"mode": "PRIVATE_IAP", "invoker_principals": [f"user:{ADMIN}"], "sign_in": {"google": "DISABLED"},
           "source": "intake"}
    rec.update(kw)
    return rec


def test_resolved_access_carries_the_effective_list_and_its_source():
    r = resolve_access(workload_access=_record(), enable_direct_iap=True, allow_unauthenticated=False,
                       workload_doc=dict(SUBMITTER_DOC, access=_record()))
    assert (r.effective_app_admin_emails, r.app_admin_source, r.app_admin_emails) == ((ADMIN,), "submitter", ())
    r = resolve_access(workload_access=_record(), enable_direct_iap=True, allow_unauthenticated=False)
    assert (r.effective_app_admin_emails, r.app_admin_source) == ((), "none")
    r = resolve_access(workload_access=_record(app_admin_emails=["boss@example.com"]), enable_direct_iap=True,
                       allow_unauthenticated=False, workload_doc=SUBMITTER_DOC)
    assert (r.effective_app_admin_emails, r.app_admin_source) == (("boss@example.com",), "record")


def test_legacy_flags_path_has_no_admins():
    """No record (the compliance flags give the mode only; a private mode stops there for an operator)."""
    r = resolve_access(enable_direct_iap=False, allow_unauthenticated=True, workload_doc=SUBMITTER_DOC)
    assert (r.effective_app_admin_emails, r.app_admin_source) == ((), "none")


# ------------------------------------------------------------------------------------------------ render
# sha256 of json.dumps([main.tf, variables.tf, reconcile's files], sort_keys=True) rendered by main cc229d59 (before
# APP-ADMIN-IAP-CONTRACT) with the arguments of _gated_off_render; the gate leaves app_admin_emails None for all of them.
PRE_CHANGE_RENDERS = {
    ("public", "cloudrun"): "b4d96b17794810e6384f2658cc88b397f4cd9ee5e553b78158bad89002f5b808",
    ("public", "gke-autopilot"): "a027661870301afbf76867c42ec4b9bda81c82c24402ae9f393c3a201e5d276b",
    ("public", "event-worker"): "08a2ee7dedfbe4515185bd82aa38a5676976092a6a1c94bce78f3c4fdc0575f7",
    ("public", "gce-bastion"): "7840207af12c5905768bbae52f10370e7486da9f3c3e4c3d21fe25a208a6942d",
    ("public", "foundation-only"): "e1ce4ae21a447293813bc55098a367d6f975774579e58594594ead4d9587cfd3",
    ("public", "unknown-arch"): "ece2f7b512ed6316ac5c4f12094ce5a9e36747691b07073188651e32c4e0d97e",
    ("iam", "cloudrun"): "8ce6ab37fb06747045475416e083a25c194c54950611436680dcf8394b438bfb",
    ("iam", "gke-autopilot"): "6ad9cd398cfa3d895816a23ba9131c95b0706015fb14b0220f13a6285a2a96de",
    ("iam", "event-worker"): "cc86d7ac8910da0d3644215c309ca43d828249dd80ec245caa2b43f050f11116",
    ("iam", "gce-bastion"): "82f8fad59f3d3c5c43a99cd8d8e2543062cab8fc0c898be3f04fca61f0cb45b8",
    ("iam", "foundation-only"): "a09878128635de3aa8c6b7b4c10e46398dcca48b8045fc9140214491f19fbb1d",
    ("iam", "unknown-arch"): "1d1969f14655e2d7321f3a21abe5bab8538396d64757a5e91e25cc563ccee252",
    ("iap", "cloudrun"): "9fa784c969712d1c53ebf9ad6144832953ce92f4e43a66eb61c34e809d5c44f6",
    ("iap", "gke-autopilot"): "a1441401df86caeb714e298992d7bb38acbf04ffc5cdd564580efed798aa4cba",
    ("iap", "event-worker"): "bcf59ce705d821290529d2d77ed1e8b43d1147523c634a5a21b8969a98e75644",
    ("iap", "gce-bastion"): "a1b76b3c8cdd7f3b456b19a9c99c204f1f9cd41131531128c2e92c5b8b4d55af",
    ("iap", "foundation-only"): "1990e36fc7122f045f27de745ecffdc01692ef2c8985cbd39b74a489efcfe151",
    ("iap", "unknown-arch"): "f81e1246e0a4492c12f93cae5b42d88b21b0a302997033d23659b8875e31df18",
}
_ACCESS = {"public": {"allow_unauthenticated": True, "enable_direct_iap": False},
           "iam": {"allow_unauthenticated": False, "enable_direct_iap": False}, "iap": IAP_ON}


def _gated_off_render(access, archetype):
    import json
    kw = dict(_ACCESS[access], authorized_invoker_members=["user:a@example.com"])
    main = te.generate_golden_main_tf("shop", archetype, "", **kw)
    variables = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1", **kw)
    files = {"infra/workload/custom.tf": ""}
    te.reconcile_multi_service_declarations(files, "shop", "", archetype=archetype, target_services=["shop", "edge"],
                                            **_ACCESS[access])
    return json.dumps([main, variables, files], sort_keys=True)


@pytest.mark.parametrize("access, archetype", sorted(PRE_CHANGE_RENDERS))
def test_gated_off_renders_equal_the_pre_change_renders_do_no_harm(access, archetype):
    """PUBLIC_APP, PRIVATE_IAM and PRIVATE_IAP with the gate off (no Cloud Run service, or a direct caller): no
    variable, no env, and byte for byte what main rendered before the change."""
    text = _gated_off_render(access, archetype)
    assert "app_admin_emails" not in text and "STACKVEND_APP_ADMIN_EMAILS" not in text
    assert hashlib.sha256(text.encode()).hexdigest() == PRE_CHANGE_RENDERS[(access, archetype)]


def test_direct_iap_cloud_run_primary_gets_the_env_and_the_variable():
    main = te.generate_golden_main_tf("shop", "cloudrun", "", app_admin_emails=(ADMIN,), **IAP_ON)
    assert main.count(ENV_LINE) == 1
    assert "env_vars              = merge(var.env_vars, {" in main
    variables = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1", app_admin_emails=(ADMIN,),
                                                **IAP_ON)
    assert variables.count(VAR_DECL) == 1
    assert f'  type        = list(string)\n  default     = ["{ADMIN}"]\n' in variables
    assert variables.index('variable "authorized_invoker_members"') < variables.index(VAR_DECL) < \
        variables.index('variable "additional_apis"')


def test_only_the_new_lines_differ_from_todays_render():
    import difflib
    base = te.generate_golden_main_tf("shop", "cloudrun", "", **IAP_ON).splitlines()
    new = te.generate_golden_main_tf("shop", "cloudrun", "", app_admin_emails=(ADMIN,), **IAP_ON).splitlines()
    removed = [l for l in difflib.ndiff(base, new) if l.startswith("- ")]
    added = [l for l in difflib.ndiff(base, new) if l.startswith("+ ")]
    assert removed == ["-   env_vars              = var.env_vars"]
    assert added == ["+   env_vars              = merge(var.env_vars, {", f"+     {ENV_LINE}", "+   })"]


def test_empty_admin_list_still_declares_the_variable_and_the_env():
    """APP-ADMIN-DEFAULT: nobody configured -> `[]` (the app reads an empty list; it never invents a bootstrap)."""
    variables = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1", app_admin_emails=(), **IAP_ON)
    assert f"{VAR_DECL} {{" in variables and "  default     = []\n" in variables.split(VAR_DECL, 1)[1]
    assert ENV_LINE in te.generate_golden_main_tf("shop", "cloudrun", "", app_admin_emails=(), **IAP_ON)


def test_primary_env_keeps_the_existing_bindings():
    main = te.generate_golden_main_tf("shop", "cloudrun", "", env_vars_override={"DB_HOST": "module.db.host"},
                                      app_admin_emails=(ADMIN,), **IAP_ON)
    assert '    "DB_HOST" = module.db.host\n' in main and ENV_LINE in main


@pytest.mark.parametrize("archetype, cloud_run_modules", [("cloudrun", ["compute_edge"]),
                                                          ("gke-autopilot", ["compute_edge"])])
def test_cloud_run_secondaries_get_the_env(archetype, cloud_run_modules):
    files = {"infra/workload/custom.tf": ""}
    te.reconcile_multi_service_declarations(files, "shop", "", archetype=archetype, target_services=["shop", "edge"],
                                            app_admin_emails=(ADMIN,), **IAP_ON)
    custom = files["infra/workload/custom.tf"]
    for label in cloud_run_modules:
        start = custom.index(f'module "{label}"')
        assert ENV_LINE in custom[start:custom.index("\n}", start)]


def test_the_default_fallback_cloud_run_primary_gets_the_env_too():
    main = te.generate_golden_main_tf("shop", "unknown-arch", "", app_admin_emails=(ADMIN,), **IAP_ON)
    assert main.count(ENV_LINE) == 1 and 'source                = "../modules/compute-cloudrun"' in main


def test_gke_primary_main_tf_is_unchanged_by_the_list():
    """The GKE module call has no env_vars: a Direct IAP workload with a GKE primary changes only its Cloud Run
    secondaries and variables.tf."""
    assert te.generate_golden_main_tf("shop", "gke-autopilot", "", **IAP_ON) == \
        te.generate_golden_main_tf("shop", "gke-autopilot", "", app_admin_emails=(ADMIN,), **IAP_ON)


@pytest.mark.parametrize("bad", [["Admin@Example.com"], ["not-an-email"], [ADMIN, ADMIN], [1], ['a"b@example.com']])
def test_the_variable_default_refuses_anything_but_distinct_canonical_emails(bad):
    with pytest.raises(ValueError):
        te.app_admin_variable_block(bad)


def test_a_binding_that_already_uses_the_platform_key_is_refused_never_overwritten():
    with pytest.raises(te.AppAdminEnvCollision):
        te.with_app_admin_env({te.APP_ADMIN_EMAILS_ENV: '"x"'}, [ADMIN])
    with pytest.raises(te.AppAdminEnvCollision):
        te.generate_golden_main_tf("shop", "cloudrun", "", env_vars_override={te.APP_ADMIN_EMAILS_ENV: '"x"'},
                                   app_admin_emails=(ADMIN,), **IAP_ON)
    env = {"A": "1"}
    assert te.with_app_admin_env(env, None) is env


def test_the_handler_reports_a_collision_typed():
    from types import SimpleNamespace
    from developer_agent.handler import APP_ADMIN_ENV_COLLISION, DeveloperAgent
    from gate_errors import PlatformDefectError
    dev = DeveloperAgent.__new__(DeveloperAgent)

    def boom(draft, inputs):
        raise te.AppAdminEnvCollision("STACKVEND_APP_ADMIN_EMAILS is platform-set")
    dev._assemble_tree = boom
    with pytest.raises(PlatformDefectError) as err:
        dev._assemble_tree_typed({}, SimpleNamespace(product_id="shop"))
    assert err.value.reason == APP_ADMIN_ENV_COLLISION
    dev._assemble_tree = lambda draft, inputs: ({"a": "b"}, {})   # no collision: the result passes through
    assert dev._assemble_tree_typed({}, SimpleNamespace(product_id="shop")) == ({"a": "b"}, {})


def test_both_assembly_call_sites_use_the_typed_wrapper():
    calls = [n for n in ast.walk(_handler_tree()) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr in ("_assemble_tree", "_assemble_tree_typed")]
    assert sorted(c.func.attr for c in calls) == ["_assemble_tree", "_assemble_tree_typed", "_assemble_tree_typed"]


def test_rendered_variable_parses_and_qa_reads_the_count():
    from developer_agent.assembly import index_blocks
    variables = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1",
                                                app_admin_emails=(ADMIN, "b@example.com"), **IAP_ON)
    decl = [b for b in index_blocks(variables) if b.kind == "variable" and b.labels == ("app_admin_emails",)]
    assert len(decl) == 1 and decl[0].body["default"] == [ADMIN, "b@example.com"]


# ------------------------------------------------------------------------------------------------ handler wiring
def _handler_tree():
    with open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8") as f:
        return ast.parse(f.read())


def test_every_platform_render_call_passes_the_inputs_list():
    names = {"generate_golden_main_tf": 2, "generate_golden_variables_tf": 2, "reconcile_multi_service_declarations": 1}
    calls = [n for n in ast.walk(_handler_tree()) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id in names]
    assert sorted(c.func.id for c in calls) == sorted(k for k, v in names.items() for _ in range(v))
    for c in calls:
        kw = {k.arg: ast.unparse(k.value) for k in c.keywords}
        assert kw.get("app_admin_emails") == "inputs.app_admin_emails", c.func.id


def test_the_list_has_exactly_the_rule_gate():
    src = ast.unparse(_handler_tree())
    assert "app_admin_emails = tuple(run_access.effective_app_admin_emails) if app_auth_rule else None" in src
    assert "app_admin_emails=app_admin_emails" in src
    from developer_agent.handler import AssemblyInputs
    assert AssemblyInputs.__dataclass_fields__["app_admin_emails"].default is None


def test_no_tfvars_key_is_rendered():
    """The variable's default is its only value: no deploy (FD-4DT included) passes a key a root may not declare."""
    with open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8") as f:
        src = f.read()
    assert "app_admin_emails  " not in src and "\"app_admin_emails =" not in src
    assert "app_admin_emails" not in ap.DEPLOY_ACCESS_TFVARS_KEYS


class _Doc:
    def __init__(self, sink):
        self.sink = sink

    def set(self, data, merge=False):
        self.sink.append((data, merge))


class _DB:
    def __init__(self):
        self.writes = []

    def collection(self, name):
        assert name == "workloads"
        return self

    def document(self, pid):
        return _Doc(self.writes)


def _outcome(emails, source):
    from types import SimpleNamespace
    from developer_agent.handler import DeveloperAgent
    dev = DeveloperAgent.__new__(DeveloperAgent)
    dev.db = _DB()
    dev._app_admin_outcome("shop", "t-1", SimpleNamespace(app_admin_source=source), emails)
    return dev


def test_outcome_records_counts_and_the_warning_never_addresses(caplog):
    from developer_agent.handler import APP_ADMIN_CONTRACT_FIELD, APP_ADMIN_NONE_CONFIGURED
    dev = _outcome((), "none")
    assert dev.db.writes == [({APP_ADMIN_CONTRACT_FIELD: {"admin_count": 0, "source": "none",
                                                          "warning": APP_ADMIN_NONE_CONFIGURED,
                                                          "admin_list_sha256": ap.app_admin_list_digest([]),
                                                          "trace_id": "t-1"}}, True)]
    assert APP_ADMIN_CONTRACT_FIELD == ap.APP_ADMIN_CONTRACT_FIELD
    assert dev.stack_run("t-1")["app_admin_contract"]["warning"] == APP_ADMIN_NONE_CONFIGURED
    assert APP_ADMIN_NONE_CONFIGURED in caplog.text
    dev = _outcome((ADMIN,), "submitter")
    assert dev.db.writes[0][0][APP_ADMIN_CONTRACT_FIELD] == {"admin_count": 1, "source": "submitter",
                                                             "warning": None,
                                                             "admin_list_sha256": ap.app_admin_list_digest([ADMIN]),
                                                             "trace_id": "t-1"}
    assert ADMIN not in repr(dev.db.writes)


from test_direct_iap_skill_verify import (_Stop, _developer, _generate, _no_recorded_region,  # noqa: E402,F401
                                          _swarm_plan, _v1_intent)


class _StopDispatcher:
    any_model_answered = False

    def __init__(self, **_):
        self.iac_intent = None

    async def execute_phased_junior_swarm(self, *a, **k):
        raise _Stop()


@pytest.mark.parametrize("direct_iap, archetype, recorded", [(True, "cloudrun", True), (False, "cloudrun", False),
                                                             (True, "gke-autopilot", False),
                                                             (True, "event-worker", False)])
def test_a_dispatch_resolves_the_list_only_under_the_rule_gate(direct_iap, archetype, recorded):
    """generate_code_files: a Direct IAP Cloud Run workload records its admin contract before any LLM call (the
    stub's verified submitter is its one exact user invoker); PUBLIC_APP and non-Cloud-Run workloads record nothing."""
    dev = _developer(direct_iap)
    _generate(dev, _swarm_plan(), _StopDispatcher, intent=_v1_intent(archetype))
    got = dev.stack_run("t").get("app_admin_contract")
    assert got == ({"admin_count": 1, "source": "submitter", "warning": None,
                    "admin_list_sha256": ap.app_admin_list_digest(["op@example.com"]), "trace_id": "t"}
                   if recorded else None)


def test_outcome_is_nothing_for_every_other_workload():
    dev = _outcome(None, "submitter")
    assert dev.db.writes == [] and "app_admin_contract" not in dev.stack_run("t-1")


# ------------------------------------------------------------------------------------------------ prompt rule
def _rule(**kw):
    args = dict(enable_direct_iap=True, allow_unauthenticated=False, cloud_run_services=("portal",))
    args.update(kw)
    return P.direct_iap_auth_rule(**args)


def test_the_admin_rule_rides_on_the_direct_iap_rule_only():
    assert _rule().endswith(P.DIRECT_IAP_APP_ADMIN_RULES)
    assert P.DIRECT_IAP_APP_ADMIN_RULES in _rule(other_services=("cluster",))
    for off in (dict(enable_direct_iap=False), dict(allow_unauthenticated=True), dict(cloud_run_services=())):
        assert _rule(**off) == ""


def test_the_admin_rule_states_the_contract():
    rule = P.DIRECT_IAP_APP_ADMIN_RULES
    for fact in ("`STACKVEND_APP_ADMIN_EMAILS`", "JSON list", "every Cloud Run service it renders",
                 "set by the platform at deploy time", "APPLICATION-WIDE administrative roles only",
                 "\"whoever creates a project owns that project\") is ordinary app logic", "highest such role",
                 "`app_admin_emails()`", "never at import", "audited action",
                 "not to the first user, the first visitor, an unknown user", "Add no other bootstrap",
                 "the platform's list is how the first administrator is made", "no self-service way",
                 "If the plan defines no application-wide administrative role, ignore the variable",
                 "When the plan defines such a role, tests set the variable",
                 "`monkeypatch.setenv(\"STACKVEND_APP_ADMIN_EMAILS\""):
        assert fact in rule, fact
    assert "SuperAdmin, Admin or Owner" not in rule and "access settings" not in rule


def test_env_name_is_one_name_everywhere():
    assert P.APP_ADMIN_EMAILS_ENV == te.APP_ADMIN_EMAILS_ENV == JI.APP_ADMIN_EMAILS_ENV == "STACKVEND_APP_ADMIN_EMAILS"
    from developer_agent.handler import APP_ADMIN_NONE_CONFIGURED
    assert JI.APP_ADMIN_NONE_CONFIGURED == APP_ADMIN_NONE_CONFIGURED


# ------------------------------------------------------------------------------------------------ judge facts
def _facts(**kw):
    return JI.platform_facts_text("GITHUB", "off", [], **kw)


def test_admin_fact_only_with_the_direct_iap_line_and_a_typed_count():
    base = _facts(direct_iap_cloud_run=True)
    assert _facts(direct_iap_cloud_run=True, app_admin_count=None) == base
    for not_a_count in (True, False, -1, "1", 1.0):
        assert _facts(direct_iap_cloud_run=True, app_admin_count=not_a_count) == base
    assert _facts(direct_iap_cloud_run=False, app_admin_count=2) == _facts()
    with_fact = _facts(direct_iap_cloud_run=True, app_admin_count=2)
    assert with_fact.startswith(base) and with_fact != base


def test_admin_fact_text_names_the_missed_directive_and_the_critical_bootstrap():
    two = _facts(direct_iap_cloud_run=True, app_admin_count=2)
    assert "`STACKVEND_APP_ADMIN_EMAILS`" in two and "holds 2 email address(es)" in two
    assert "no listed email can hold at runtime" in two and "is a missed directive" in two
    assert "first-user, first-visitor, empty-store" in two and "critical security defect" in two
    assert "unmandated feature" in two
    assert JI.APP_ADMIN_NONE_CONFIGURED not in two
    for fact in ("is met by the platform's administrator list: do not report the missing bootstrap as a missed "
                 "directive", "Ownership of a single resource", "application-wide administrative role"):
        assert fact in two and fact in _facts(direct_iap_cloud_run=True, app_admin_count=0)


def test_empty_list_fact_is_a_configuration_gap_not_a_missed_directive():
    zero = _facts(direct_iap_cloud_run=True, app_admin_count=0)
    assert "EMPTY" in zero and JI.APP_ADMIN_NONE_CONFIGURED in zero
    assert "not a missed directive" in zero and "critical security defect" in zero


def test_both_lenses_get_the_same_fact():
    facts = build_platform_facts("GITHUB", "off", [], direct_iap_cloud_run=True, app_admin_count=1)
    assert "STACKVEND_APP_ADMIN_EMAILS" in facts.text and "STACKVEND_APP_ADMIN_EMAILS" in facts.section()


# ------------------------------------------------------------------------------------------------ QA commit reader
@pytest.fixture
def gw(monkeypatch):
    import fd4f_support
    return fd4f_support.load_gateway(monkeypatch, "gw_app_admin")


def test_qa_counts_the_committed_platform_declaration(gw):
    variables = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1",
                                                app_admin_emails=(ADMIN, "b@example.com"), **IAP_ON)
    assert gw._commit_app_admin_count({"infra/workload/variables.tf": variables}) == 2
    empty = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1", app_admin_emails=(), **IAP_ON)
    assert gw._commit_app_admin_count({"infra/workload/variables.tf": empty}) == 0


def test_qa_has_no_count_without_the_declaration(gw):
    old = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1", **IAP_ON)
    for files in ({}, {"infra/workload/variables.tf": old}, {"infra/workload/variables.tf": "variable {"},
                  {"infra/workload/variables.tf": 'variable "app_admin_emails" {\n  default = "x"\n}\n'},
                  {"infra/workload/variables.tf": 'variable "app_admin_emails" {}\nvariable "app_admin_emails" {}\n'}):
        assert gw._commit_app_admin_count(files) is None


# ------------------------------------------------------------------------------------------------ runtime env advisory
def test_the_platform_set_env_is_a_provided_name_only_on_its_own_cloud_run_modules():
    from developer_agent.runtime_env_facts import platform_admin_env
    with_decl = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1", app_admin_emails=(), **IAP_ON)
    without = te.generate_golden_variables_tf("shop", "o/shop", region="us-central1", **IAP_ON)
    main = te.generate_golden_main_tf("shop", "cloudrun", "", app_admin_emails=(), **IAP_ON)
    services = ('module "compute_edge" {\n  source = "../modules/compute-cloudrun"\n}\n'
                'module "compute_jobs" {\n  source = "../modules/compute-event-worker"\n}\n')
    tree = {"infra/workload/variables.tf": with_decl, "infra/workload/main.tf": main,
            "infra/workload/services.tf": services}
    assert platform_admin_env(tree, "compute") == {"STACKVEND_APP_ADMIN_EMAILS"}
    assert platform_admin_env(tree, "compute_edge") == {"STACKVEND_APP_ADMIN_EMAILS"}
    assert platform_admin_env(tree, "compute_jobs") == frozenset()          # not Cloud Run
    assert platform_admin_env(tree, "compute_kept") == frozenset()          # skipped / kept: not the platform's render
    custom_only = dict(tree, **{"infra/workload/custom.tf": 'module "compute_kept" {\n  source = "../modules/compute-cloudrun"\n}\n'})
    assert platform_admin_env(custom_only, "compute_kept") == frozenset()
    assert platform_admin_env(dict(tree, **{"infra/workload/variables.tf": without}), "compute") == frozenset()
    assert platform_admin_env({}, "compute") == frozenset()


# ------------------------------------------------------------------------------------------------ Control Center
from test_l19_11_access_intake import (ADMIN_H, IAP_INTAKE, SUBMITTER, _create, cc)  # noqa: E402,F401


def test_a_new_intake_workload_records_its_verified_submitter(cc, monkeypatch):
    _, wl = cc
    r, fake_db, _ = _create(wl, monkeypatch, {"access": IAP_INTAKE}, headers=dict(ADMIN_H, **{
        "x-test-email": SUBMITTER, "x-test-auth-method": "iap"}))
    assert r.status_code in (200, 201, 202), r.text
    doc = fake_db["workloads/shop-app"]
    assert doc["verified_submitter"] == {"member": f"user:{SUBMITTER}", "source": "submitter",
                                         "verified_by": "control_center_auth"}
    assert doc["access"]["app_admin_emails"] == []   # the record itself is unchanged (no server-side fill)
    assert ap.workload_verified_submitter(doc) == f"user:{SUBMITTER}"


@pytest.mark.parametrize("method, email, recorded", [
    ("iap", SUBMITTER, True), ("session", SUBMITTER, True),
    ("bearer", SUBMITTER, False), ("", SUBMITTER, False), (None, SUBMITTER, False),
    ("iap", "runner@p.iam.gserviceaccount.com", False), ("iap", "admin-console", False), ("iap", None, False)])
def test_only_a_verified_human_is_recorded(cc, method, email, recorded):
    from types import SimpleNamespace
    _, wl = cc
    state = SimpleNamespace(user_email=email) if method is None else SimpleNamespace(user_email=email,
                                                                                     auth_method=method)
    fields = wl._verified_submitter_fields(SimpleNamespace(state=state))
    assert fields == ({"verified_submitter": {"member": f"user:{SUBMITTER}", "source": "submitter",
                                              "verified_by": "control_center_auth"}} if recorded else {})


@pytest.mark.parametrize("keep_first", [True, False])
def test_a_re_create_never_changes_the_recorded_submitter(cc, monkeypatch, keep_first):
    _, wl = cc
    first, first_db, _ = _create(wl, monkeypatch, {"access": IAP_INTAKE}, headers=dict(ADMIN_H, **{
        "x-test-email": SUBMITTER, "x-test-auth-method": "session"}))
    assert first.status_code in (200, 201, 202), first.text
    stored = {k: dict(v) for k, v in first_db.items() if k == "workloads/shop-app"}
    if not keep_first:   # a workload created before the field existed stays without one
        stored["workloads/shop-app"].pop("verified_submitter")
    r, fake_db, _ = _create(wl, monkeypatch, {"access": IAP_INTAKE}, initial=stored, headers=dict(ADMIN_H, **{
        "x-test-email": "other@example.com", "x-test-auth-method": "session"}))
    assert r.status_code in (200, 201, 202), r.text
    assert fake_db["workloads/shop-app"].get("verified_submitter") == stored["workloads/shop-app"].get(
        "verified_submitter")


# ------------------------------------------------------------------------------------------------ Fast-Path (CC)
from test_fd4dt_access_fastpath import OK_WL, _rec, _route  # noqa: E402

ANA = "ana@example.com"
ANA_SUBMITTER = {"verified_submitter": {"member": f"user:{ANA}", "source": "submitter",
                                        "verified_by": "control_center_auth"}}


def _contract(emails):
    return {"app_admin_contract": {"admin_count": len(emails), "source": "submitter", "warning": None,
                                   "admin_list_sha256": ap.app_admin_list_digest(emails), "trace_id": "t"}}


def test_fast_path_unchanged_without_an_admin_record(cc):
    _, wl = cc
    assert _route(wl, workload=dict(OK_WL, **ANA_SUBMITTER)) == (True, "ACCESS_ONLY_CHANGE")


def test_fast_path_allowed_when_the_admin_list_is_unchanged(cc):
    _, wl = cc
    assert _route(wl, workload=dict(OK_WL, **ANA_SUBMITTER, **_contract([ANA]))) == (True, "ACCESS_ONLY_CHANGE")


def test_an_admin_removed_by_the_access_change_needs_a_full_build(cc):
    _, wl = cc
    workload = dict(OK_WL, **ANA_SUBMITTER, **_contract([ANA]), access=_rec("PRIVATE_IAP", ["group:staff@example.com"]))
    assert _route(wl, workload=workload) == (False, "APP_ADMIN_CHANGE")


def test_an_admin_added_by_the_access_change_needs_a_full_build(cc):
    _, wl = cc
    assert _route(wl, workload=dict(OK_WL, **ANA_SUBMITTER, **_contract([]))) == (False, "APP_ADMIN_CHANGE")


@pytest.mark.parametrize("bad", ["x", {}, {"admin_list_sha256": None}])
def test_an_unreadable_admin_record_needs_a_full_build(cc, bad):
    _, wl = cc
    assert _route(wl, workload=dict(OK_WL, **ANA_SUBMITTER, app_admin_contract=bad)) == (False, "APP_ADMIN_CHANGE")


def test_digest_is_order_free_and_holds_no_address():
    assert ap.app_admin_list_digest(["b@example.com", "a@example.com"]) == \
        ap.app_admin_list_digest(["a@example.com", "b@example.com"])
    assert ap.app_admin_list_digest([]) != ap.app_admin_list_digest([ANA])
    assert ANA not in ap.app_admin_list_digest([ANA])

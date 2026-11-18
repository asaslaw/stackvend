"""FD-7L Phase 2b (plan docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, section 2.5): the apply
content-policy addition POLICY.PLATFORM_IDENTITY_TOUCHED (`platform_identity_violations`, plan JSON, exact types /
attributes / values), the self-healing import's reserved names (`reserved_import_reason`) and the gateway's reserved
names (developer_agent/validators/policy_tables.py, V2a).

Mode rule (OQ-32): refused in PER_WORKLOAD, POLICY_WOULD_REFUSE log lines only in PLATFORM (no result changes).
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import copy
import json
import logging
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (REPO_ROOT,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fd4g_support import load_tf_service  # noqa: E402
from shared import runner_identity as ri  # noqa: E402

CHILD = "shop-api-a1b2c3"
DEPLOYER = ri.deployer_email(CHILD)
STATE = f"{CHILD}-tfstate"
PLATFORM_BUCKET = "castor-tfstate-host"
PID = "shop-api"


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


def _identity(tf):
    return tf.platform_identity(CHILD, {STATE, PLATFORM_BUCKET})


def _rc(rtype, name="r", after=None, unknown=None, actions=("create",), module_address=None, before=None,
        importing=None):
    rc = {"address": (f"{module_address}." if module_address else "") + f"{rtype}.{name}", "mode": "managed",
          "type": rtype, "name": name,
          "change": {"actions": list(actions), "after": after, "before": before, "after_unknown": unknown or {}}}
    if module_address:
        rc["module_address"] = module_address
    if importing is not None:
        rc["importing"] = importing
    return rc


def _plan(*rcs, config=None):
    return {"configuration": config or {"root_module": {"resources": []}}, "resource_changes": list(rcs)}


def _codes(viol):
    return [v["code"] for v in viol]


# ------------------------------------------------------------------------------------------------ every case
TOUCHED = [
    ("google_service_account", {"account_id": ri.DEPLOYER_ACCOUNT_ID}),
    ("google_service_account_iam_member", {"service_account_id": DEPLOYER}),
    ("google_service_account_iam_member", {"service_account_id": f"projects/{CHILD}/serviceAccounts/{DEPLOYER}"}),
    ("google_service_account_iam_binding", {"service_account_id": f"projects/-/serviceAccounts/{DEPLOYER}"}),
    ("google_service_account_iam_policy", {"service_account_id": DEPLOYER}),
    ("google_service_account_key", {"service_account_id": DEPLOYER}),
    ("google_project_iam_policy", {"project": CHILD, "policy_data": "{}"}),
    ("google_project_iam_binding", {"role": "roles/owner", "members": ["user:a@b.c"]}),
    ("google_project_iam_member", {"role": "roles/editor", "member": "user:a@b.c"}),
    ("google_service_account_key", {"service_account_id": f"{CHILD}/{DEPLOYER}"}),
    ("google_project_iam_member_remove", {"role": "roles/viewer", "member": f"serviceAccount:{DEPLOYER}"}),
    ("google_project_iam_member_remove", {"role": "roles/owner", "member": "user:a@b.c"}),
    ("google_iam_deny_policy", {"parent": f"cloudresourcemanager.googleapis.com%2Fprojects%2F{CHILD}"}),
    ("google_storage_bucket", {"name": STATE}),
    ("google_storage_bucket", {"name": PLATFORM_BUCKET}),
    ("google_storage_bucket_iam_member", {"bucket": f"b/{STATE}"}),
    ("google_storage_bucket_object", {"bucket": STATE, "name": "workloads/shop-api/default.tfstate"}),
    ("google_storage_bucket_acl", {"bucket": STATE}),
    ("google_storage_notification", {"bucket": STATE}),
]
NOT_TOUCHED = [
    ("google_service_account", {"account_id": "app-sa"}),
    ("google_service_account_iam_member", {"service_account_id": f"projects/{CHILD}/serviceAccounts/app@{CHILD}.iam.gserviceaccount.com"}),
    ("google_project_iam_binding", {"role": "roles/viewer", "members": ["user:a@b.c"]}),
    ("google_project_iam_member", {"role": "roles/viewer", "member": f"serviceAccount:{DEPLOYER}"}),
    ("google_project_iam_member_remove", {"role": "roles/viewer", "member": "user:a@b.c"}),
    ("google_storage_bucket", {"name": f"{CHILD}-assets"}),
    ("google_storage_bucket_object", {"bucket": f"{CHILD}-assets", "name": "x"}),
]


@pytest.mark.parametrize("rtype,after", TOUCHED, ids=[f"{t}-{i}" for i, (t, _a) in enumerate(TOUCHED)])
def test_each_case_is_touched(tf, rtype, after):
    v = tf.platform_identity_violations(_plan(_rc(rtype, after=after)), _identity(tf))
    assert _codes(v) == ["POLICY.PLATFORM_IDENTITY_TOUCHED"], v


@pytest.mark.parametrize("rtype,after", NOT_TOUCHED, ids=[f"{t}-{i}" for i, (t, _a) in enumerate(NOT_TOUCHED)])
def test_negatives_are_not_touched(tf, rtype, after):
    assert tf.platform_identity_violations(_plan(_rc(rtype, after=after)), _identity(tf)) == []


def test_delete_of_the_deployer_is_touched_and_no_op_is_not(tf):
    before = {"account_id": ri.DEPLOYER_ACCOUNT_ID}
    rc = _rc("google_service_account", after=None, before=before, actions=("delete",))
    assert _codes(tf.platform_identity_violations(_plan(rc), _identity(tf))) == ["POLICY.PLATFORM_IDENTITY_TOUCHED"]
    noop = _rc("google_storage_bucket", after={"name": f"{CHILD}-assets"}, actions=("no-op",))
    assert tf.platform_identity_violations(_plan(noop), _identity(tf)) == []


def test_import_blocks_targeting_the_state_bucket_or_deployer(tf):
    for rtype, imp in [("google_storage_bucket", STATE), ("google_storage_bucket", f"{CHILD}/{STATE}"),
                       ("google_service_account", f"projects/{CHILD}/serviceAccounts/{DEPLOYER}")]:
        rc = _rc(rtype, after={"name": "other", "account_id": "other"}, actions=("no-op",),
                 importing={"id": imp})
        assert _codes(tf.platform_identity_violations(_plan(rc), _identity(tf))) == [
            "POLICY.PLATFORM_IDENTITY_TOUCHED"], imp
    ok = _rc("google_storage_bucket", after={"name": "x"}, actions=("no-op",), importing={"id": f"{CHILD}-assets"})
    assert tf.platform_identity_violations(_plan(ok), _identity(tf)) == []


# ------------------------------------------------------------------------------------------------ unknown values
def _cfg_resource(rtype, name, expressions):
    return {"address": f"{rtype}.{name}", "mode": "managed", "type": rtype, "name": name, "expressions": expressions}


def _sa_target(account_id="app-sa", name="app", known=True, module_address=None):
    after = {"account_id": account_id} if known else {}
    return _rc("google_service_account", name=name, after=after, module_address=module_address,
               unknown={} if known else {"account_id": True})


def _sa_grant_plan(refs, target=None, extra=()):
    config = {"root_module": {"resources": [
        _cfg_resource("google_service_account", "app", {"account_id": {"constant_value": "app-sa"}}),
        _cfg_resource("google_service_account_iam_member", "r", {"service_account_id": {"references": refs}})]}}
    grant = _rc("google_service_account_iam_member", after={"role": "roles/iam.serviceAccountUser"},
                unknown={"service_account_id": True})
    return _plan(grant, *([target] if target else []), *extra, config=config)


def _source(rendered):
    """A source lookup that answers `rendered` for the grant's service_account_id (the workload's HCL)."""
    return lambda path, rtype, name, attr: rendered


APP_NAME_REFS = ["google_service_account.app.name", "google_service_account.app"]


def test_unknown_service_account_from_a_safe_created_account_is_allowed(tf):
    plan = _sa_grant_plan(APP_NAME_REFS, _sa_target())
    assert tf.platform_identity_violations(plan, _identity(tf), _source("${google_service_account.app.name}")) == []
    # the same with a counted resource and the email / id attributes
    for attr in ("email", "id"):
        refs = [f"google_service_account.app[0].{attr}", "google_service_account.app[0]", "google_service_account.app"]
        plan = _sa_grant_plan(refs, _sa_target())
        assert tf.platform_identity_violations(plan, _identity(tf),
                                               _source(f"${{google_service_account.app[0].{attr}}}")) == [], attr


@pytest.mark.parametrize("case", ["deployer_account_id", "account_id_unknown", "no_planned_target",
                                  "function_around_it", "no_source", "template_text"])
def test_unknown_service_account_shape_violations_are_refused(tf, case):
    target = {"deployer_account_id": _sa_target(account_id=ri.DEPLOYER_ACCOUNT_ID),
              "account_id_unknown": _sa_target(known=False), "no_planned_target": None}.get(case, _sa_target())
    rendered = {"function_around_it": '${replace(google_service_account.app.name, "app-sa", "stackvend-deployer")}',
                "no_source": None, "template_text": "projects/-/serviceAccounts/${google_service_account.app.email}",
                }.get(case, "${google_service_account.app.name}")
    plan = _sa_grant_plan(APP_NAME_REFS, target)
    found = tf.platform_identity_violations(plan, _identity(tf), _source(rendered))
    assert [v["address"] for v in found if v["address"] == "google_service_account_iam_member.r"] == [
        "google_service_account_iam_member.r"], case   # (the target account itself is refused too when it is bad)
    # without any source lookup (direct callers) an unknown identity value is always refused
    assert _codes(tf.platform_identity_violations(_sa_grant_plan(APP_NAME_REFS, _sa_target()), _identity(tf))) == [
        "POLICY.PLATFORM_IDENTITY_TOUCHED"]


@pytest.mark.parametrize("refs", [
    ["terraform_data.x.output", "terraform_data.x"],               # review F1: an unknown that echoes a literal
    ["random_shuffle.s.result[0]", "random_shuffle.s.result", "random_shuffle.s"],
    ["data.google_service_account.d.name", "data.google_service_account.d"],
    ["local.sa"], ["var.sa"], ["module.m.sa", "module.m"], [],
    ["google_service_account.app.name", "google_pubsub_topic.t.id"],   # a second, unrelated resource
    ["google_service_account.app.unique_id"],                          # an attribute outside the shape
])
def test_unknown_value_from_anything_else_is_refused(tf, refs):
    plan = _sa_grant_plan(refs, _sa_target())
    lookup = _source("${" + refs[0] + "}" if refs else None)
    assert _codes(tf.platform_identity_violations(plan, _identity(tf), lookup)) == [
        "POLICY.PLATFORM_IDENTITY_TOUCHED"], refs


@pytest.mark.parametrize("rtype,attr", [("google_service_account_key", "service_account_id"),
                                        ("google_project_iam_binding", "role"),
                                        ("google_project_iam_member", "role"),
                                        ("google_storage_bucket_iam_member", "bucket"),
                                        ("google_service_account", "account_id"),
                                        ("google_project_iam_member_remove", "member")])
def test_reviewer_random_shuffle_and_terraform_data_bypasses(tf, rtype, attr):
    """Review F1 proof: `random_shuffle.s.result[0]` (input = ["stackvend-deployer"]) and `terraform_data.x.output`
    (input = the deployer) used as the identity attribute are refused (both are managed resources of the
    configuration, which the old rule accepted)."""
    for refs in (["random_shuffle.s.result[0]", "random_shuffle.s"], ["terraform_data.x.output", "terraform_data.x"]):
        config = {"root_module": {"resources": [_cfg_resource(rtype, "r", {attr: {"references": refs}})]}}
        rc = _rc(rtype, after={"project": CHILD}, unknown={attr: True})
        lookup = _source("${" + refs[0] + "}")
        assert _codes(tf.platform_identity_violations(_plan(rc, config=config), _identity(tf), lookup)) == [
            "POLICY.PLATFORM_IDENTITY_TOUCHED"], (rtype, refs)


def test_unknown_bucket_from_a_safe_created_bucket_is_allowed_and_a_state_bucket_is_not(tf):
    def plan_for(name):
        config = {"root_module": {"resources": [
            _cfg_resource("google_storage_bucket", "b", {"name": {"constant_value": name}}),
            _cfg_resource("google_storage_bucket_iam_member", "m", {"bucket": {
                "references": ["google_storage_bucket.b.id", "google_storage_bucket.b"]}})]}}
        return _plan(_rc("google_storage_bucket_iam_member", name="m", after={"role": "roles/storage.objectViewer"},
                         unknown={"bucket": True}),
                     _rc("google_storage_bucket", name="b", after={"name": name}), config=config)
    lookup = _source("${google_storage_bucket.b.id}")
    assert tf.platform_identity_violations(plan_for(f"{CHILD}-assets"), _identity(tf), lookup) == []
    assert _codes(tf.platform_identity_violations(plan_for(STATE), _identity(tf), lookup)) == [
        "POLICY.PLATFORM_IDENTITY_TOUCHED", "POLICY.PLATFORM_IDENTITY_TOUCHED"]   # the bucket and the grant


def test_foundation_build_sa_grant_is_known_at_plan(tf):
    """Review F1: the workload-foundation build-SA grant no longer derives the project number from the WIF pool (a
    managed resource, unknown on a first deploy) but from data.google_project.this (known at plan time), so its
    service_account_id is a known string and the known-value grammar applies. Every copy of the module agrees."""
    hcl2 = pytest.importorskip("hcl2")
    for tree in ("infra/modules", "apps/control-center/infra/modules"):
        text = open(os.path.join(REPO_ROOT, tree, "workload-foundation", "base", "iam.tf"), encoding="utf-8").read()
        doc = hcl2.loads(text)
        grants = {n: b for block in doc["resource"] for t, named in block.items() if t ==
                  "google_service_account_iam_member" for n, b in named.items()}
        sa_id = grants["deployer_build_sa_user"]["service_account_id"]
        assert sa_id == ("projects/${var.project_id}/serviceAccounts/${data.google_project.this[0].number}"
                         "-compute@developer.gserviceaccount.com"), tree
        assert "google_iam_workload_identity_pool" not in sa_id
        assert any("google_project" in b for b in doc.get("data", []))
    # the rendered value is one the grammar accepts as not the deployer
    assert not tf._names_deployer_or_unresolvable(
        f"projects/{CHILD}/serviceAccounts/123-compute@developer.gserviceaccount.com", _identity(tf))


# ------------------------------------------------------------------------------------------------ name grammar (F2)
@pytest.mark.parametrize("value", [
    DEPLOYER, DEPLOYER.upper(), f"projects/{CHILD}/serviceAccounts/{DEPLOYER}", f"projects/-/serviceAccounts/{DEPLOYER}",
    f"{CHILD}/{DEPLOYER}", f"projects/123456789012/serviceAccounts/{DEPLOYER}",
    "projects/-/serviceAccounts/112233445566778899001",                  # numeric unique id: cannot be resolved
    "112233445566778899001", f"projects/{CHILD}/serviceAccounts/{DEPLOYER}/extra",   # not of the grammar
    # re-check N2: stray characters make an account the platform cannot resolve (closed email grammar)
    f"{DEPLOYER} ", f" {DEPLOYER}", f"{DEPLOYER}\n", f"app@{CHILD}.iam.gserviceaccount.com.",
    f"app@{CHILD}.iam.gserviceaccount.com?x", f"projects/{CHILD}/serviceAccounts/app@{CHILD}..iam.gserviceaccount.com",
])
def test_service_account_name_grammar_refuses_the_deployer_and_the_unresolvable(tf, value):
    rc = _rc("google_service_account_key", after={"service_account_id": value})
    assert _codes(tf.platform_identity_violations(_plan(rc), _identity(tf))) == ["POLICY.PLATFORM_IDENTITY_TOUCHED"], value


@pytest.mark.parametrize("value", [f"app@{CHILD}.iam.gserviceaccount.com",
                                   f"projects/{CHILD}/serviceAccounts/app@{CHILD}.iam.gserviceaccount.com",
                                   f"{CHILD}/app@{CHILD}.iam.gserviceaccount.com",
                                   "projects/123/serviceAccounts/123-compute@developer.gserviceaccount.com",
                                   f"projects/-/serviceAccounts/service-123@gcp-sa-cloudbuild.iam.gserviceaccount.com",
                                   f"APP@{CHILD}.IAM.GSERVICEACCOUNT.COM"])
def test_service_account_name_grammar_negatives(tf, value):
    rc = _rc("google_service_account_iam_member", after={"service_account_id": value})
    assert tf.platform_identity_violations(_plan(rc), _identity(tf)) == [], value


def test_import_ids_use_the_same_grammar(tf):
    for imp in (f"{CHILD}/{DEPLOYER}", f"projects/123/serviceAccounts/{DEPLOYER}", "1122334455"):
        rc = _rc("google_service_account", after={"account_id": "x"}, actions=("no-op",), importing={"id": imp})
        assert _codes(tf.platform_identity_violations(_plan(rc), _identity(tf))) == [
            "POLICY.PLATFORM_IDENTITY_TOUCHED"], imp
        assert tf.reserved_import_reason("google_service_account", imp, _identity(tf)), imp


# ------------------------------------------------------------------------------------------------ privileged roles (F3)
@pytest.mark.parametrize("rtype", ["google_project_iam_member", "google_project_iam_binding"])
@pytest.mark.parametrize("role", ["roles/owner", "roles/editor", "roles/iam.serviceAccountTokenCreator"])
def test_privileged_project_roles_in_the_own_project(tf, rtype, role):
    # re-check N1: the provider-normalised spellings of the own project, and an unparseable value, count as own
    for project in (CHILD, None, f"projects/{CHILD}", "123456789012", CHILD.upper(), "not a project/!"):
        rc = _rc(rtype, after={"project": project, "role": role, "member": "user:a@b.c"})
        assert _codes(tf.platform_identity_violations(_plan(rc), _identity(tf))) == [
            "POLICY.PLATFORM_IDENTITY_TOUCHED"], (role, project)
    other = _rc(rtype, after={"project": "another-project-1", "role": role, "member": "user:a@b.c"})
    assert tf.platform_identity_violations(_plan(other), _identity(tf)) == []
    unknown_role = _rc(rtype, after={"project": CHILD}, unknown={"role": True})
    assert _codes(tf.platform_identity_violations(_plan(unknown_role), _identity(tf))) == [
        "POLICY.PLATFORM_IDENTITY_TOUCHED"]


def test_privileged_project_roles_are_the_gateways_and_golden_modules_grant_none(tf):
    _VC, T, _PV, _O = _gateway()
    assert tf.PRIVILEGED_PROJECT_ROLES <= T.PRIVILEGED_ROLES
    assert tf.PROJECT_LEVEL_IAM_TYPES == T.PROJECT_LEVEL_IAM_TYPES
    hcl2 = pytest.importorskip("hcl2")
    seen = 0
    for dirpath, _dirs, files in os.walk(os.path.join(REPO_ROOT, "infra", "modules")):
        for name in files:
            if not name.endswith(".tf"):
                continue
            doc = hcl2.loads(open(os.path.join(dirpath, name), encoding="utf-8").read())
            for block in doc.get("resource", []):
                for rtype, named in block.items():
                    if rtype not in tf.PROJECT_LEVEL_IAM_TYPES:
                        continue
                    for _n, body in named.items():
                        seen += 1
                        assert body.get("role") not in tf.PRIVILEGED_PROJECT_ROLES, (dirpath, name)
                        assert "${" not in str(body.get("role")), (dirpath, name)   # literal roles only
    assert seen > 0


@pytest.mark.parametrize("text,expected", [("", ()), (None, ()), ("module.a", ("a",)),
                                           ('module.a["k.x"].module.b[0]', ("a", "b")),
                                           ("module.a[", None), ("modul.a", None), ("module.", None)])
def test_module_path_parser(tf, text, expected):
    assert tf._parse_module_path(text) == expected


def test_no_identity_means_no_check(tf):
    assert tf.platform_identity_violations(_plan(_rc("google_project_iam_policy", after={})), None) == []
    assert tf.platform_identity(None, {STATE}) is None and tf.platform_identity("Bad_Id", {STATE}) is None


# ------------------------------------------------------------------------------------------------ mode wiring
def _ctx(tf, per_workload):
    return tf.RunnerStateContext(mode=ri.MODE_PER_WORKLOAD if per_workload else ri.MODE_PLATFORM,
                                 bucket=STATE if per_workload else PLATFORM_BUCKET,
                                 source="provenance" if per_workload else "platform", project_id=CHILD,
                                 deployer_email=DEPLOYER if per_workload else None)


def test_per_workload_refuses_platform_logs_only(tf, tmp_path, caplog):
    svc = tf.TerraformService(project_id="host", state_bucket=PLATFORM_BUCKET, workspace_base_dir=str(tmp_path),
                              firestore_client=object())
    plan = _plan(_rc("google_iam_deny_policy", after={}))
    assert _codes(svc._content_policy_findings(plan, _ctx(tf, True), PID, "t1")) == [
        "POLICY.PLATFORM_IDENTITY_TOUCHED"]
    with caplog.at_level(logging.WARNING):
        assert svc._content_policy_findings(plan, _ctx(tf, False), PID, "t1") == []
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.getMessage().startswith("{")]
    assert [(x["event"], x["code"], x["stage"]) for x in lines] == [
        ("POLICY_WOULD_REFUSE", "POLICY.PLATFORM_IDENTITY_TOUCHED", "content_policy")]
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        svc._content_policy_findings(plan, _ctx(tf, False), PID, "t1", log=False)
    assert not caplog.records


def test_platform_mode_violations_are_exactly_fd4awb(tf, tmp_path):
    """Do No Harm: in PLATFORM the content policy result is plan_content_policy_violations(plan, platform bucket)."""
    svc = tf.TerraformService(project_id="host", state_bucket=PLATFORM_BUCKET, workspace_base_dir=str(tmp_path),
                              firestore_client=object())
    plan = {"configuration": {"root_module": {"resources": [
        {"address": "data.terraform_remote_state.r", "mode": "data", "type": "terraform_remote_state", "name": "r",
         "expressions": {"backend": {"constant_value": "gcs"}, "config": {"constant_value": {
             "bucket": PLATFORM_BUCKET, "prefix": f"workloads/{PID}"}}}}]}},
        "resource_changes": [_rc("google_project_iam_policy", after={})]}
    assert svc._content_policy_findings(plan, _ctx(tf, False), PID, "t") == tf.plan_content_policy_violations(
        plan, PLATFORM_BUCKET, PID) == []
    # PER_WORKLOAD: the own-state rule names the workload's bucket, so the platform bucket is "another state"
    per = _codes(svc._content_policy_findings(plan, _ctx(tf, True), PID, "t"))
    assert per == ["POLICY.REMOTE_STATE_FORBIDDEN", "POLICY.PLATFORM_IDENTITY_TOUCHED"]


def test_refusal_text_unchanged_without_the_new_code(tf):
    viol = [{"code": "POLICY.PROVISIONER_FORBIDDEN", "address": "x", "message": "x declares provisioner"}]
    old = ("APPLY_CONTENT_POLICY: the plan breaks the platform's content policy (POLICY.PROVISIONER_FORBIDDEN): "
           "x declares provisioner. Nothing was applied. Workload Terraform (including human-written files) may not "
           "run provisioners, use non-local modules or providers outside the platform's set, or read another "
           "Terraform state.")
    assert tf.content_policy_refusal(PID, "t", viol)["error"] == old
    touched = [{"code": "POLICY.PLATFORM_IDENTITY_TOUCHED", "address": "y", "message": "y m"}]
    assert "deployer account" in tf.content_policy_refusal(PID, "t", touched)["error"]


# ------------------------------------------------------------------------------------------------ self-heal imports
def test_reserved_import_names(tf):
    ident = _identity(tf)
    assert tf.reserved_import_reason("google_service_account", f"projects/{CHILD}/serviceAccounts/{DEPLOYER}", ident)
    assert tf.reserved_import_reason("google_storage_bucket", STATE, ident)
    assert tf.reserved_import_reason("google_storage_bucket", PLATFORM_BUCKET, ident)
    assert tf.reserved_import_reason("google_storage_bucket", f"{CHILD}-cloudbuild-source", ident)
    for rtype, imp in [("google_storage_bucket", f"{CHILD}-assets"),
                       ("google_service_account", f"projects/{CHILD}/serviceAccounts/app@{CHILD}.iam.gserviceaccount.com"),
                       ("google_secret_manager_secret", STATE)]:
        assert tf.reserved_import_reason(rtype, imp, ident) is None
    assert tf.reserved_import_reason("google_storage_bucket", STATE, None) is None


def test_both_self_heal_import_sites_check_the_reserved_names_first():
    src = open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    impl = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_deploy_workload_impl")
    pass0 = next(n for n in ast.walk(impl) if isinstance(n, ast.FunctionDef) and n.name == "_pass0_adopt")
    loop_src = ast.get_source_segment(src, pass0)
    assert loop_src.index("_import_reserved(cand)") < loop_src.index('"terraform", "import"')
    impl_src = ast.get_source_segment(src, impl)
    adopt = impl_src.index("for cand in adoptable:")
    assert adopt < impl_src.index("reserved_why = _import_reserved(cand)", adopt) < impl_src.index(
        "_tf_import(cand.address, cand.import_id)", adopt)


# ------------------------------------------------------------------------------------------------ gateway parity
def _gateway():
    for p in (GATEWAY, REPO_ROOT):
        if p not in sys.path:
            sys.path.insert(0, p)
    pytest.importorskip("hcl2")
    from developer_agent.validators import ValidationContext
    from developer_agent.validators import policy_tables as T
    from developer_agent.validators.step1 import PolicyValidator
    from shared.artifact_ownership import Ownership
    return ValidationContext, T, PolicyValidator, Ownership


def test_gateway_reserved_names_equal_the_server(tf):
    _VC, T, _PV, _O = _gateway()
    assert T.RESERVED_SERVICE_ACCOUNT_IDS == {ri.DEPLOYER_ACCOUNT_ID}
    assert T.PLATFORM_IDENTITY_FORBIDDEN_TYPES <= (tf.ALWAYS_IDENTITY_TOUCHING_TYPES
                                                   | {"google_project_iam_member_remove"})
    assert not T.PLATFORM_IDENTITY_FORBIDDEN_TYPES & T.FORBIDDEN_RESOURCE_TYPES


@pytest.mark.parametrize("body,expected", [
    ('resource "google_iam_deny_policy" "d" {\n  parent = "x"\n  name = "n"\n}\n', ["POLICY.FORBIDDEN_RESOURCE_TYPE"]),
    ('resource "google_project_iam_member_remove" "d" {\n  project = "p"\n  role = "roles/viewer"\n'
     '  member = "user:a@b.c"\n}\n', ["POLICY.FORBIDDEN_RESOURCE_TYPE"]),
    ('resource "google_service_account" "d" {\n  account_id = "stackvend-deployer"\n}\n',
     ["POLICY.FORBIDDEN_RESOURCE_TYPE"]),
    ('resource "google_service_account" "d" {\n  account_id = "app-sa"\n}\n', []),
    ('resource "google_service_account" "d" {\n  account_id = var.name\n}\n', []),
])
def test_gateway_v2a_refuses_the_reserved_names(body, expected):
    VC, _T, PolicyValidator, Ownership = _gateway()
    files = {"infra/workload/custom.tf": body}
    ctx = VC.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, vendored=frozenset(), draft={},
                   assembly=None, extras={}, trace_id="t")
    assert sorted(d.code for d in PolicyValidator().validate(ctx)) == expected

"""FD-4AQ W4 (register AQ-4, owner 10-25): AI-written Terraform that sets up Google sign-in itself, puts the sign-in
module in a Private workload, or grants a role that can read the sign-in secret is refused before commit and sent back
for repair (step-1 validator V2l, blocking; validators/access_idp.py over the lane 19 access_policy_validator).

Negative tests (Do No Harm): valid workloads, golden modules (vendored and, except workload_auth, even treated as AI
files), platform-synthesized blocks and the codes the row does not cover produce no V2l finding; the validator never
changes its input (sha256).
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import glob
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.access_resolution import ResolvedAccess, resolve_access  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators import policy_tables as T  # noqa: E402
from developer_agent.validators.access_idp import AccessIdpValidator  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.access_policy import AccessPolicy  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import ErrorClass, artifact_hash  # noqa: E402

W = "infra/workload/"
GOLDEN_AUTH = "infra/modules/workload_auth/"


def _ctx(files, *, llm=None, vendored=(), rendered=(), extras=None):
    llm = set(files) if llm is None else set(llm)
    vend = frozenset(vendored)

    def own(path):
        if path in vend:
            return Ownership.PLATFORM_VENDORED
        return Ownership.LLM_AUTHORED if path in llm else Ownership.PLATFORM_RENDERED
    return ValidationContext.build(files, ownership=own, extras=extras or {}, trace_id="t", vendored=vend,
                                   rendered=frozenset(rendered), draft={})


def _run(files, access=None, **kw):
    ctx = _ctx(files, **kw)
    before = artifact_hash(dict(files))
    got = AccessIdpValidator(access).validate(ctx)
    assert artifact_hash(dict(ctx.files)) == before and artifact_hash(dict(files)) == before   # never writes
    return got


def _found(ds):
    return sorted((d.code, d.file, d.block_address) for d in ds)


def _record(mode, google="DISABLED", **kw):
    if mode == "PUBLIC_APP":
        pol = AccessPolicy(mode="PUBLIC_APP", sign_in={"google": google, "email_password": google == "DISABLED"},
                           tenant_isolation_required=False, source="intake")
    else:
        pol = AccessPolicy(mode=mode, invoker_principals=["group:ops@example.com"], sign_in={"google": "DISABLED"},
                           source="intake")
    return resolve_access(access=pol, **kw)


def _flags(mode):
    """No access record: the mode from the compliance decision's typed flags (every workload today). A private one
    needs principals to get past resolution, so it is built in the resolved shape directly."""
    if mode == "PUBLIC_APP":
        return resolve_access(allow_unauthenticated=True, enable_direct_iap=False)
    return ResolvedAccess(mode=mode, invoker_members=("group:ops@example.com",), app_admin_emails=(),
                          source="compliance_flags")


IDP_TF = (
    'resource "google_identity_platform_config" "auth" {\n  project = var.project_id\n}\n\n'
    'resource "google_identity_platform_default_supported_idp_config" "google" {\n  project = var.project_id\n'
    '  idp_id = "google.com"\n  client_id = var.oauth_client_id\n  client_secret = var.oauth_client_secret\n}\n\n'
    'resource "google_identity_platform_oauth_idp_config" "oidc" {\n  project = var.project_id\n  name = "oidc.x"\n'
    '  client_id = "x"\n  issuer = "https://issuer.example"\n}\n'
)
AUTH_MODULE_TF = 'module "auth" {\n  source = "../modules/workload_auth"\n  project_id = var.project_id\n}\n'
SECRET_READER_TF = (
    'resource "google_project_iam_member" "viewer" {\n  project = var.project_id\n'
    '  role = "roles/firebaseauth.viewer"\n  member = "serviceAccount:app@p.iam.gserviceaccount.com"\n}\n\n'
    'resource "google_project_iam_custom_role" "reader" {\n  project = var.project_id\n  role_id = "reader"\n'
    '  title = "r"\n  permissions = ["firebaseauth.configs.get", "storage.objects.get"]\n}\n'
)
VALID_TF = (
    'module "compute" {\n  source = "../modules/compute-cloudrun"\n  project_id = var.project_id\n'
    '  region = var.region\n}\n\n'
    'resource "google_storage_bucket" "data" {\n  name = "${var.project_id}-data"\n  location = var.region\n'
    '  uniform_bucket_level_access = true\n}\n\n'
    'resource "google_project_iam_member" "writer" {\n  project = var.project_id\n'
    '  role = "roles/storage.objectAdmin"\n  member = "serviceAccount:app@p.iam.gserviceaccount.com"\n}\n'
)


# ------------------------------------------------------------------------------------------------ sign-in config
@pytest.mark.parametrize("access", [None, "PUBLIC_APP", "PRIVATE_IAP", "PRIVATE_IAM"])
def test_identity_platform_resources_are_refused_in_every_workload(access):
    resolved = None if access is None else _flags(access)
    got = _run({W + "custom.tf": IDP_TF}, resolved)
    assert _found(got) == [
        ("POLICY.IDP_CONFIG_IN_IAC", W + "custom.tf", "google_identity_platform_config.auth"),
        ("POLICY.IDP_CONFIG_IN_IAC", W + "custom.tf", "google_identity_platform_default_supported_idp_config.google"),
        ("POLICY.IDP_CONFIG_IN_IAC", W + "custom.tf", "google_identity_platform_oauth_idp_config.oidc"),
    ]
    by_addr = {d.block_address: d for d in got}
    assert by_addr["google_identity_platform_config.auth"].line == 1
    assert by_addr["google_identity_platform_oauth_idp_config.oidc"].line == 12
    for d in got:
        assert d.severity == "error" and d.error_class is ErrorClass.CODE_DEFECT and d.hint == T.HINT_IDP_CONFIG
        assert d.tool == "policy" and d.source == "precommit"


@pytest.mark.parametrize("resolved", [_flags("PRIVATE_IAP"), _flags("PRIVATE_IAM"), _record("PRIVATE_IAP"),
                                      _record("PRIVATE_IAM")], ids=["iap-flags", "iam-flags", "iap-record",
                                                                   "iam-record"])
def test_sign_in_module_in_a_private_workload_is_refused(resolved):
    got = _run({W + "main_auth.tf": AUTH_MODULE_TF}, resolved)
    assert _found(got) == [("POLICY.IDP_CONFIG_IN_IAC", W + "main_auth.tf", "module.auth")]
    assert got[0].line == 1 and got[0].attribute_path == "source"


@pytest.mark.parametrize("resolved", [None, _flags("PUBLIC_APP"), _record("PUBLIC_APP")],
                         ids=["no-access", "public-flags", "public-record"])
def test_sign_in_module_in_a_public_or_unknown_workload_is_not_refused_by_v2k(resolved):
    assert _run({W + "main_auth.tf": AUTH_MODULE_TF}, resolved) == []


def test_secret_reader_roles_are_refused_only_with_the_shared_sign_in_client():
    files = {W + "iam.tf": SECRET_READER_TF}
    got = _run(files, _record("PUBLIC_APP", google="SHARED_PLATFORM_CLIENT"))
    assert _found(got) == [
        ("POLICY.IDP_SECRET_READER_FORBIDDEN", W + "iam.tf", "google_project_iam_custom_role.reader"),
        ("POLICY.IDP_SECRET_READER_FORBIDDEN", W + "iam.tf", "google_project_iam_member.viewer"),
    ]
    assert all(d.hint == T.HINT_IDP_SECRET_READER for d in got)
    # no shared client (sign-in disabled), no record (compliance flags), no access: nothing to read, no finding
    for resolved in (_record("PUBLIC_APP", google="DISABLED"), _flags("PUBLIC_APP"), _record("PRIVATE_IAM"), None):
        assert _run(files, resolved) == []


# ------------------------------------------------------------------------------------------------ provenance
def test_golden_sign_in_module_and_platform_files_are_never_judged():
    golden = {GOLDEN_AUTH + os.path.basename(p): open(p).read()
              for p in glob.glob(os.path.join(REPO_ROOT, GOLDEN_AUTH, "*.tf"))}
    assert any("google_identity_platform_default_supported_idp_config" in t for t in golden.values())
    files = dict(golden)
    files[W + "platform.tf"] = IDP_TF
    files[W + "custom.tf.json"] = '{"resource": {"google_identity_platform_config": {"a": {"project": "p"}}}}'
    got = _run(files, _record("PRIVATE_IAP"), llm={W + "custom.tf.json"}, vendored=set(golden),
               rendered={W + "custom.tf.json"})
    assert got == []


def test_platform_synthesized_block_inside_an_ai_file_is_not_judged():
    files = {W + "custom.tf": IDP_TF}
    platform = {(W + "custom.tf", "google_identity_platform_config.auth"),
                (W + "custom.tf", "google_identity_platform_default_supported_idp_config.google")}
    got = _run(files, None, extras={"platform_addresses": platform})
    assert _found(got) == [("POLICY.IDP_CONFIG_IN_IAC", W + "custom.tf",
                            "google_identity_platform_oauth_idp_config.oidc")]


def test_ai_written_tf_json_is_checked_too():
    files = {W + "modules/auth/main.tf.json":
             '{"resource": {"google_identity_platform_oauth_idp_config": {"o": {"name": "oidc.x"}}}}'}
    assert _found(_run(files, None)) == [("POLICY.IDP_CONFIG_IN_IAC", W + "modules/auth/main.tf.json",
                                          "google_identity_platform_oauth_idp_config.o")]


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_valid_workloads_have_no_finding_in_any_mode():
    for resolved in (None, _flags("PUBLIC_APP"), _flags("PRIVATE_IAP"), _record("PRIVATE_IAM"),
                     _record("PUBLIC_APP", google="SHARED_PLATFORM_CLIENT")):
        assert _run({W + "main.tf": VALID_TF}, resolved) == []


def test_codes_outside_the_row_are_not_reported_by_v2k():
    tf = ('resource "google_storage_bucket_iam_member" "pub" {\n  bucket = "b"\n  role = "roles/storage.objectViewer"\n'
          '  member = "allUsers"\n}\n\nresource "google_storage_bucket" "b" {\n  name = "b"\n  location = "US"\n'
          '  predefined_acl = "publicRead"\n}\n')
    files = {W + "pub.tf": tf, W + "broken.tf": 'resource "x" {\n', W + "terraform.tfvars": 'allow_unauthenticated = true\n'}
    assert _run(files, _record("PRIVATE_IAM"), llm={W + "pub.tf", W + "broken.tf"}) == []


def test_every_golden_module_except_the_sign_in_module_treated_as_ai_written_has_no_finding():
    dirs = {}
    for path in glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True):
        dirs.setdefault(os.path.dirname(path), []).append(path)
    assert len(dirs) >= 28
    checked = 0
    for d, paths in sorted(dirs.items()):
        if os.path.basename(d) == "workload_auth":
            continue
        files = {W + os.path.basename(p): open(p).read() for p in paths}
        for resolved in (_flags("PRIVATE_IAP"), _record("PUBLIC_APP", google="SHARED_PLATFORM_CLIENT")):
            got = _run(files, resolved)
            assert got == [], (os.path.relpath(d, REPO_ROOT), [(x.code, x.block_address) for x in got])
        checked += 1
    assert checked >= 27


def test_no_files_no_work():
    assert _run({}, None) == []
    assert _run({W + "README.md": "x"}, None) == []


# ------------------------------------------------------------------------------------------------ wiring
def test_registered_blocking_after_v2j_with_and_without_access():
    for access in (None, _flags("PRIVATE_IAM")):
        stack = build_step1_stack(validate_client=None, verifier_factory=None, access=access)
        assert stack.mode_of("V2l") == "blocking"
        assert stack.ids.index("V2l") == stack.ids.index("V2j") + 1
        assert stack.ids.index("V2j") == stack.ids.index("V2d") + 1   # FD-4AW pin unchanged


def test_access_facts_come_from_the_resolved_access_only():
    from developer_agent.validators.access_idp import access_facts
    f = access_facts(_record("PUBLIC_APP", google="SHARED_PLATFORM_CLIENT"))
    assert (f.mode, f.sign_in.google, f.allow_unauthenticated, f.enable_direct_iap) == (
        "PUBLIC_APP", "SHARED_PLATFORM_CLIENT", True, False)
    f = access_facts(_flags("PRIVATE_IAP"))
    assert (f.mode, f.sign_in.google, f.enable_direct_iap) == ("PRIVATE_IAP", None, True)
    f = access_facts(None)
    assert (f.mode, f.sign_in.google) == (None, None)
    assert isinstance(_flags("PUBLIC_APP"), ResolvedAccess)


def test_the_developer_passes_its_resolved_access_to_the_stack():
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    stack_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", None) ==
                   "build_step1_stack"]
    assert len(stack_calls) == 1
    kw = {k.arg: ast.unparse(k.value) for k in stack_calls[0].keywords if k.arg}
    assert kw["access"] == "inputs.run_access"
    inputs_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", None) ==
                    "AssemblyInputs"]
    assert len(inputs_calls) == 1
    kw = {k.arg: ast.unparse(k.value) for k in inputs_calls[0].keywords if k.arg}
    assert kw["run_access"] == "run_access"

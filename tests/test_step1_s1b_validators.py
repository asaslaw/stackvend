"""Step 1 S1-B validators (integration plan §1.7 rev 3, lane 8B §3, §10). Every validator: hash before == hash after
on every fixture (validators never write), zero diagnostics on the golden-module corpus, a positive and a negative
fixture per code. Exact tables only (no substring predicates)."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import glob
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.validators import ValidationContext, ValidatorUnavailable  # noqa: E402
from developer_agent.validators import policy_tables as T  # noqa: E402
from developer_agent.validators.step1 import (PLATFORM_SUPPLIED_VARIABLES, AssemblyPreservationValidator,  # noqa: E402
                                              GatekeeperCheckValidator, HclParseValidator, PathValidator,
                                              PolicyValidator, ProviderAvailabilityValidator, PyflakesValidator,
                                              PythonSyntaxValidator, RequirementsValidator, TofuValidateValidator,
                                              VariableWithoutValueValidator, VendoredDriftValidator,
                                              build_step1_stack)
from developer_agent.validators.tofu_diagnostics import map_raw_diagnostic, referenced_object, tf_code  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import AssemblyRecord, artifact_hash  # noqa: E402

W = "infra/workload/"


def _ctx(files, *, llm=None, vendored=(), draft=None, assembly=None, extras=None):
    llm = set(files) if llm is None else set(llm)
    vend = set(vendored)

    def own(path):
        if path in vend:
            return Ownership.PLATFORM_VENDORED
        if path in llm:
            return Ownership.LLM_AUTHORED
        return Ownership.PLATFORM_RENDERED
    return ValidationContext.build(files, ownership=own, vendored=frozenset(vend), draft=draft or {},
                                   assembly=assembly, extras=extras or {}, trace_id="t")


def _codes(ds):
    return sorted(d.code for d in ds)


def _golden_tree():
    tree = {}
    for path in glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True):
        rel = os.path.relpath(path, REPO_ROOT)
        tree[rel] = open(path).read()
    return tree


class FakeClient:
    def __init__(self, resp):
        self.resp, self.calls = resp, []

    def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
        self.calls.append(dict(files))
        return self.resp


ALL_VALIDATORS = [
    HclParseValidator(), PolicyValidator(), PolicyValidator(sa_scoped=True), VariableWithoutValueValidator(),
    AssemblyPreservationValidator(), ProviderAvailabilityValidator(), PythonSyntaxValidator(), PyflakesValidator(),
    RequirementsValidator(), PathValidator(), VendoredDriftValidator(),
    TofuValidateValidator(FakeClient({"status": "PASS", "diagnostics": []})),
]


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_no_validator_mutates_and_the_golden_corpus_is_clean():
    golden = _golden_tree()
    assert len(golden) >= 60
    files = dict(golden)
    files[W + "custom.tf"] = 'resource "google_storage_bucket" "b" {\n  name = "b"\n  location = "US"\n}\n'
    files["apps/api/main.py"] = "import os\n\nPORT = int(os.environ.get('PORT', '8080'))\n"
    files["apps/api/requirements.txt"] = "fastapi>=0.110.0\nuvicorn[standard]>=0.28.0  # server\n-r base.txt\n"
    before = artifact_hash(files)
    ctx = _ctx(files, llm={W + "custom.tf", "apps/api/main.py", "apps/api/requirements.txt"}, vendored=golden,
               extras={"available_providers": ["google", "google-beta", "kubernetes", "random"],
                       "platform_files": golden})
    for v in ALL_VALIDATORS:
        found = v.validate(ctx)
        assert found == [], (v.id, [(d.code, d.file) for d in found])
        assert artifact_hash(files) == before == artifact_hash(dict(ctx.files)), v.id
    # every golden module file parses with python-hcl2 (V1a) even when classified as LLM-owned
    ctx2 = _ctx(golden, llm=set(golden), extras={"available_providers": ["google", "google-beta", "kubernetes",
                                                                        "random", "kubernetes"]})
    assert HclParseValidator().validate(ctx2) == []


# ------------------------------------------------------------------------------------------------ V2a
def _policy(text, **kw):
    return PolicyValidator(**kw).validate(_ctx({W + "custom.tf": text}))


@pytest.mark.parametrize("text,code", [
    ('resource "google_billing_budget" "b" {\n  display_name = "b"\n}\n', "POLICY.FORBIDDEN_RESOURCE_TYPE"),
    ('resource "google_iam_workload_identity_pool" "p" {\n  workload_identity_pool_id = "p"\n}\n',
     "POLICY.FORBIDDEN_RESOURCE_TYPE"),
    ('resource "google_storage_bucket_iam_binding" "b" {\n  bucket = "b"\n  role = "roles/storage.objectViewer"\n'
     '  members = ["user:a@b.c"]\n}\n', "POLICY.FORBIDDEN_RESOURCE_TYPE"),
    ('resource "google_project_iam_member" "m" {\n  role = "roles/editor"\n  member = "user:a@b.c"\n}\n',
     "POLICY.PRIVILEGED_ROLE"),
    ('resource "google_project_iam_member" "m" {\n  role = "roles/iam.serviceAccountUser"\n  member = "user:a@b.c"\n}\n',
     "POLICY.PRIVILEGED_ROLE"),
    ('resource "google_cloud_run_v2_service_iam_member" "p" {\n  role = "roles/run.invoker"\n  member = "allUsers"\n}\n',
     "POLICY.PUBLIC_MEMBER"),
    ('resource "google_pubsub_topic_iam_member" "p" {\n  role = "roles/pubsub.publisher"\n'
     '  member = "allAuthenticatedUsers"\n}\n', "POLICY.PUBLIC_MEMBER"),
    ('resource "google_project_service" "run" {\n  service = "run.googleapis.com"\n}\n', "POLICY.PLATFORM_OWNED_TYPE"),
    ('resource "google_artifact_registry_repository" "r" {\n  repository_id = "r"\n  format = "DOCKER"\n}\n',
     "POLICY.PLATFORM_OWNED_TYPE"),
    ('resource "google_firestore_database" "d" {\n  name = "(default)"\n  location_id = "nam5"\n  type = "FIRESTORE_NATIVE"\n}\n',
     "POLICY.PLATFORM_OWNED_TYPE"),
])
def test_v2a_positive(text, code):
    assert code in _codes(_policy(text))


@pytest.mark.parametrize("text", [
    'module "compute" {\n  source = "../modules/compute-cloudrun"\n  allow_unauthenticated = true\n}\n',
    'resource "google_firestore_database" "orders" {\n  name = "orders"\n  location_id = "nam5"\n  type = "FIRESTORE_NATIVE"\n}\n',
    'resource "google_project_iam_member" "m" {\n  role = "roles/datastore.user"\n  member = "serviceAccount:${google_service_account.a.email}"\n}\n',
    'resource "google_service_account" "a" {\n  account_id = "a"\n}\n',
    'resource "google_service_account_iam_member" "wi" {\n  service_account_id = google_service_account.a.name\n'
    '  role = "roles/iam.workloadIdentityUser"\n  member = "serviceAccount:p.svc.id.goog[ns/ksa]"\n}\n',
    'resource "google_compute_firewall" "iap" {\n  name = "iap"\n  network = "default"\n  source_ranges = ["35.235.240.0/20"]\n}\n',
    'resource "google_compute_firewall" "all" {\n  name = "all"\n  network = "default"\n  source_ranges = ["0.0.0.0/0"]\n}\n',
    'resource "google_project_iam_member" "m" {\n  role = var.role\n  member = var.member\n}\n',
])
def test_v2a_negative(text):
    assert _policy(text) == []


def test_sa_scoped_impersonation_role_is_report_only_and_project_level_blocks():
    sa = ('resource "google_service_account_iam_member" "wi" {\n  service_account_id = "x"\n'
          '  role = "roles/iam.workloadIdentityUser"\n  member = "serviceAccount:p.svc.id.goog[ns/ksa]"\n}\n')
    assert _policy(sa) == []
    got = _policy(sa, sa_scoped=True)
    assert _codes(got) == ["POLICY.PRIVILEGED_ROLE"] and got[0].severity == "warning"
    stack = build_step1_stack(validate_client=FakeClient({"status": "PASS", "diagnostics": []}),
                              verifier_factory=None)
    assert stack.mode_of("V2a-sa-scoped") == "report_only" and stack.mode_of("V2a") == "blocking"


def test_privileged_hint_names_the_compliant_alternative_per_role_class():
    """RT fix 3 (R3c-fix review): project-level impersonation narrows to the one service account; a PRIVILEGED_ROLES
    grant has no narrower predefined role, so the hint says delete; the SA-scoped grant is the compliant scope."""
    proj = ('resource "google_project_iam_member" "u" {\n  role = "roles/iam.serviceAccountUser"\n'
            '  member = "serviceAccount:a@b.c"\n}\n')
    tok = ('resource "google_service_account_iam_member" "t" {\n  service_account_id = "x"\n'
           '  role = "roles/iam.serviceAccountTokenCreator"\n  member = "serviceAccount:a@b.c"\n}\n')
    (p,) = [x for x in _policy(proj) if x.code == "POLICY.PRIVILEGED_ROLE"]
    assert "google_service_account_iam_member" in p.hint and "roles/iam.serviceAccountUser" in p.hint
    assert "delete" not in p.hint.lower()
    (t,) = [x for x in _policy(tok) if x.code == "POLICY.PRIVILEGED_ROLE"]
    assert t.severity == "error" and "roles/iam.serviceAccountTokenCreator" in t.hint
    assert t.hint.startswith("No narrower predefined role exists") and "delete this block" in t.hint
    sa = proj.replace("google_project_iam_member", "google_service_account_iam_member").replace(
        '  role', '  service_account_id = "x"\n  role')
    (w,) = _policy(sa, sa_scoped=True)
    assert w.severity == "warning" and "compliant scope" in w.hint and "delete" not in w.hint.lower()
    assert "{role}" not in p.hint + t.hint + w.hint


def test_platform_synthesized_blocks_inside_custom_tf_are_not_policed():
    text = 'resource "google_cloud_run_v2_service_iam_member" "inv" {\n  role = "roles/run.invoker"\n  member = "allUsers"\n}\n'
    ctx = _ctx({W + "custom.tf": text},
               extras={"platform_addresses": {(W + "custom.tf", "google_cloud_run_v2_service_iam_member.inv")}})
    assert PolicyValidator().validate(ctx) == []


def test_foundation_classification_is_complete_and_not_stale():
    import hcl2
    types = set()
    for path in glob.glob(os.path.join(REPO_ROOT, "infra/modules/workload-foundation/base/*.tf")):
        for entry in hcl2.loads(open(path).read()).get("resource", []):
            types |= set(entry)
    assert types == set(T.FOUNDATION_CLASSIFICATION), (types - set(T.FOUNDATION_CLASSIFICATION),
                                                        set(T.FOUNDATION_CLASSIFICATION) - types)
    assert set(T.FOUNDATION_CLASSIFICATION.values()) <= {"PLATFORM_OWNED", "PLATFORM_OWNED_IF_DEFAULT", "FORBIDDEN",
                                                          "SHARED"}
    for t, c in T.FOUNDATION_CLASSIFICATION.items():
        if c == "FORBIDDEN":
            assert t in T.FORBIDDEN_RESOURCE_TYPES


# ------------------------------------------------------------------------------------------------ V2b / V2c / V2d
def test_v2b_variable_without_value():
    tf = ('variable "retention" {\n  type = number\n}\n\nvariable "kept" {\n  default = 1\n}\n\n'
          'variable "project_id" {\n  type = string\n}\n\nvariable "from_tfvars" {}\n')
    files = {W + "custom.tf": tf, W + "terraform.tfvars": 'from_tfvars = "x"\n'}
    got = VariableWithoutValueValidator().validate(_ctx(files, llm={W + "custom.tf"}))
    assert [(d.code, d.block_address) for d in got] == [("TF.VARIABLE_WITHOUT_VALUE", "variable.retention")]


def test_platform_supplied_variables_match_the_applier_var_file_writer():
    src = open(os.path.join(REPO_ROOT, "mcp-servers/terraform/service.py")).read()
    # FD-4BD: deploy_workload supplies `platform_tfvars` through the root terraform.tfvars and the
    # PLATFORM_SECRET_TFVARS (host OAuth secret, Firebase key) as TF_VAR_* environment variables (never in a file).
    keys, secret_keys = None, None
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "platform_tfvars" for t in node.targets):
            keys = {k.value for k in node.value.keys}
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "PLATFORM_SECRET_TFVARS" for t in node.targets):
            secret_keys = {e.value for e in node.value.elts}
    assert keys is not None and secret_keys == {"oauth_client_secret", "firebase_api_key"}
    assert not keys & secret_keys
    assert keys | secret_keys == set(PLATFORM_SUPPLIED_VARIABLES)


def test_v2c_reports_only_unrecorded_drops():
    draft = {W + "main.tf": 'resource "google_storage_bucket" "a" {}\nresource "google_cloud_run_v2_service" "api" {}\n'
                            'resource "google_pubsub_topic" "t" {}\n'}
    assembled = {W + "custom.tf": 'resource "google_storage_bucket" "a" {}\n'}
    rec = AssemblyRecord()
    rec.record("google_cloud_run_v2_service.api", "module.compute", "CLOUD_RUN_REPLACED_BY_MODULE")
    ctx = _ctx(assembled, draft=draft, assembly=rec, extras={"assembled_root": assembled})
    got = AssemblyPreservationValidator().validate(ctx)
    assert [(d.code, d.block_address, d.error_class.value) for d in got] == [
        ("PLATFORM.ASSEMBLY_DROPPED_DECLARATION", "google_pubsub_topic.t", "PLATFORM_DEFECT")]


def test_v2d_provider_availability():
    allowed = ["google", "google-beta", "kubernetes", "random"]
    ok = ('resource "google_storage_bucket" "a" {}\nresource "random_id" "r" {\n  byte_length = 4\n}\n'
          'resource "kubernetes_namespace" "n" {}\nresource "google_x" "b" {\n  provider = google-beta\n}\n')
    assert ProviderAvailabilityValidator().validate(_ctx({W + "custom.tf": ok},
                                                         extras={"available_providers": allowed})) == []
    # FD-4CW Q1: resource/data blocks are V2j's (one diagnostic per block); V2d judges provider blocks and
    # required_providers keys (tests/test_fd4cw_provider_check.py pins the split)
    assert ProviderAvailabilityValidator().validate(_ctx(
        {W + "custom.tf": 'resource "null_resource" "n" {}\ndata "archive_file" "z" {}\n'},
        extras={"available_providers": allowed})) == []
    bad = ('provider "null" {}\nterraform {\n  required_providers {\n    archive = {\n      source = "hashicorp/archive"'
           '\n    }\n  }\n}\n')
    got = ProviderAvailabilityValidator().validate(_ctx({W + "custom.tf": bad}, extras={"available_providers": allowed}))
    assert sorted(d.message for d in got) == ['provider "archive" is not available to the platform',
                                              'provider "null" is not available to the platform']
    assert "google, google-beta, kubernetes, random" in got[0].hint
    with pytest.raises(ValidatorUnavailable):
        ProviderAvailabilityValidator().validate(_ctx({W + "custom.tf": ok}))


# ------------------------------------------------------------------------------------------------ V3a / V4 / V7
def test_python_validators():
    files = {"tests/test_main.py": "def test_x(:\n    pass\n", "apps/api/main.py": "def f():\n    return undefined_y\n",
             "apps/api/ok.py": "import os\nprint(os.getcwd())\n"}
    syn = PythonSyntaxValidator().validate(_ctx(files))
    assert [(d.code, d.file) for d in syn] == [("PY.SYNTAX", "tests/test_main.py")]
    flakes = PyflakesValidator().findings(_ctx(files))
    assert [(d.code, d.file, d.symbol) for d in flakes if d.code == "PY.UNDEFINED_NAME"] == [
        ("PY.UNDEFINED_NAME", "apps/api/main.py", "undefined_y")]
    # Step 2a code RT F6: on an LLM-owned file the finding is V3a-undefined's (blocking), emitted once per report;
    # the report-only V3a-pyflakes view keeps every other pyflakes finding
    assert [d for d in PyflakesValidator().validate(_ctx(files)) if d.code == "PY.UNDEFINED_NAME"] == []
    vendored = PyflakesValidator().validate(_ctx(files, vendored={"apps/api/main.py"}))
    assert [(d.code, d.file) for d in vendored if d.code == "PY.UNDEFINED_NAME"] == [
        ("PY.UNDEFINED_NAME", "apps/api/main.py")]


def test_requirements_validator():
    files = {"apps/api/requirements.txt": "fastapi>=0.110\nnot a valid ==== req\n# comment\n-e .\nrequests # http\n"}
    got = RequirementsValidator().validate(_ctx(files))
    assert [(d.code, d.line) for d in got] == [("REQ.UNPARSEABLE", 2)]


def test_path_validator_iac_outside_workload_root():
    draft = {"infra/workloads/x.tf": "", "infra/workload/ok.tf": "", "infra/workload/sub/y.tf": ""}
    got = PathValidator().validate(_ctx(dict(draft), draft=draft))
    assert sorted(d.file for d in got if d.code == "PATH.IAC_OUTSIDE_WORKLOAD_ROOT") == [
        "infra/workload/sub/y.tf", "infra/workloads/x.tf"]


def test_vendored_drift_is_a_platform_defect():
    snap = {"infra/modules/compute-cloudrun/outputs.tf": "a"}
    got = VendoredDriftValidator().validate(_ctx({"infra/modules/compute-cloudrun/outputs.tf": "b"},
                                                 extras={"platform_files": snap}))
    assert [(d.code, d.error_class.value) for d in got] == [("PLATFORM.VENDORED_FILE_MUTATED", "PLATFORM_DEFECT")]


def test_gatekeeper_check_only_never_mutates():
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    files = {"apps/api/main.py": "def f(:\n", W + "custom.tf": 'module "x" {\n  source = "../modules/missing-mod"\n}\n'}
    before = json.dumps(files, sort_keys=True)
    got = GatekeeperCheckValidator(lambda: SynthesisVerifierAgent(product_id="p")).validate(_ctx(files))
    assert json.dumps(files, sort_keys=True) == before
    assert {d.code for d in got} == {"GATE.PY_COMPILE_ERROR", "GATE.UNVENDORED_MODULE"}


# ------------------------------------------------------------------------------------------------ V1b mapping
def test_tf_codes_and_reference_grammar():
    assert tf_code("Reference to undeclared resource") == "TF.REFERENCE_TO_UNDECLARED_RESOURCE"
    assert tf_code('Duplicate resource "google_x" configuration') == "TF.DUPLICATE_RESOURCE_CONFIGURATION"
    assert tf_code("Missing newline after argument") == "TF.MISSING_NEWLINE_AFTER_ARGUMENT"
    assert referenced_object("google_storage_bucket.events.name") == "google_storage_bucket.events"
    assert referenced_object('google_project_service.s["run.googleapis.com"].id') == "google_project_service.s"
    assert referenced_object("module.compute.service_uri") == "module.compute"
    assert referenced_object("data.google_project.p.number") == "data.google_project.p"
    assert referenced_object("var.region") is None and referenced_object("path.cwd") is None


def test_v1b_maps_raw_diagnostics_with_block_and_target():
    text = 'resource "google_pubsub_topic" "t" {\n  name = google_storage_bucket.gone.name\n}\n'
    start = text.index("google_storage_bucket.gone")
    raw = {"severity": "error", "summary": "Reference to undeclared resource",
           "detail": 'A managed resource "google_storage_bucket" "gone" has not been declared in the root module.',
           "range": {"filename": W + "custom.tf", "start": {"line": 2, "column": 10, "byte": start},
                     "end": {"line": 2, "column": 36, "byte": start + len("google_storage_bucket.gone")}}}
    client = FakeClient({"status": "FAIL", "diagnostics": [raw]})
    got = TofuValidateValidator(client).validate(_ctx({W + "custom.tf": text, "apps/a.py": "x = 1\n"}))
    assert len(got) == 1
    d = got[0]
    assert (d.code, d.file, d.line, d.block_address, d.symbol) == (
        "TF.REFERENCE_TO_UNDECLARED_RESOURCE", W + "custom.tf", 2, "google_pubsub_topic.t", "google_storage_bucket.gone")
    assert set(client.calls[0]) == {W + "custom.tf"}  # only infra/ is sent


@pytest.mark.parametrize("resp", [{"status": "UNAVAILABLE", "reason": "no binary"}, None, {"status": "FAIL"}])
def test_v1b_unavailable_is_never_a_pass(resp):
    with pytest.raises(ValidatorUnavailable):
        TofuValidateValidator(FakeClient(resp)).validate(_ctx({W + "main.tf": ""}))
    with pytest.raises(ValidatorUnavailable):
        TofuValidateValidator(None).validate(_ctx({W + "main.tf": ""}))


def test_unlocated_tofu_diagnostic_has_no_file():
    d, _ = map_raw_diagnostic({"severity": "error", "summary": "Cycle: module.a, module.b"}, {})
    assert d.file == "<unlocated>" and d.code == "TF.CYCLE"

"""FD-4CX-b (owner 10-29; RT finding F3ii of FD-4CX): in a Private (PRIVATE_IAM / PRIVATE_IAP) workload, a module call
that passes `allUsers` / `allAuthenticatedUsers` as a literal argument value is refused before commit and sent back to
the developer through the repair loop (step-1 validator V2l, blocking, code POLICY.PUBLIC_PRINCIPAL_IN_MODULE_CALL).

The check is the lane 19 `access_policy_validator.validate`, extended to `module` blocks: exact set membership on
python-hcl2 / json parsed values (AGENTS.md invariant 2), never a text search, never a rewrite (invariant 1: every
test below checks the input is unchanged). Golden, registered and workload-local module calls are all judged. On the
typed-intent path (generate mode) the platform's render of the AI's module instances is judged and the finding goes
to the intent file at the instance's address.

Negative tests (Do No Harm): the same trees in a Public workload or with no access facts, a private workload whose
module calls carry no public literal, expressions, near-miss strings, platform-owned files and platform-synthesized
blocks produce no finding.
"""
import hermetic_guard  # noqa: F401  (first import)

import glob
import json
import os
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import access_policy_validator as apv  # noqa: E402
from developer_agent import iac_intent_contract as C  # noqa: E402
from developer_agent.access_resolution import ResolvedAccess, resolve_access  # noqa: E402
from developer_agent.repair_loop import Assembled, LoopContext, RepairLoop, Router  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators import policy_tables as T  # noqa: E402
from developer_agent.validators.access_idp import FD4CXB_CODES, KEPT_CODES, AccessIdpValidator  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared import iac_intent as II  # noqa: E402
from shared import module_exposure as mx  # noqa: E402
from shared.access_policy import AccessPolicy  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import (AssemblyRecord, ErrorClass, MemoryLedgerStore, RepairBudgetExhausted,  # noqa: E402
                                artifact_hash)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

W = "infra/workload/"
CODE = apv.MODULE_PUBLIC_PRINCIPAL_CODE


# ------------------------------------------------------------------------------------------------ helpers
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
    return sorted((d.code, d.file, d.block_address, d.attribute_path) for d in ds)


def _record(mode):
    if mode == "PUBLIC_APP":
        pol = AccessPolicy(mode="PUBLIC_APP", sign_in={"google": "DISABLED", "email_password": True},
                           tenant_isolation_required=False, source="intake")
    else:
        pol = AccessPolicy(mode=mode, invoker_principals=["group:ops@example.com"], sign_in={"google": "DISABLED"},
                           source="intake")
    return resolve_access(access=pol)


def _flags(mode):
    if mode == "PUBLIC_APP":
        return resolve_access(allow_unauthenticated=True, enable_direct_iap=False)
    return ResolvedAccess(mode=mode, invoker_members=("group:ops@example.com",), app_admin_emails=(),
                          source="compliance_flags")


PRIVATE = [_flags("PRIVATE_IAM"), _flags("PRIVATE_IAP"), _record("PRIVATE_IAM"), _record("PRIVATE_IAP")]
PRIVATE_IDS = ["iam-flags", "iap-flags", "iam-record", "iap-record"]
NOT_PRIVATE = [None, _flags("PUBLIC_APP"), _record("PUBLIC_APP")]
NOT_PRIVATE_IDS = ["no-access", "public-flags", "public-record"]

# The live hole (RT F3ii): a registered (non-golden) Cloud Run module given a public invoker by its caller.
EDGE_TF = ('module "edge" {\n  source  = "../modules/acme-run"\n  name    = "edge"\n'
           '  members = ["allUsers"]\n}\n')
SHAPES_TF = (
    'module "shapes" {\n'
    '  source   = "../modules/acme-run"\n'
    '  invoker  = "allAuthenticatedUsers"\n'
    '  bindings = { "roles/run.invoker" = ["user:a@example.com", "allUsers"], viewer = ["allUsers"] }\n'
    '  iam      = [{ role = "roles/run.invoker", member = "allUsers" }]\n'
    '  ok       = ["serviceAccount:app@p.iam.gserviceaccount.com"]\n'
    '  member_roles = { allUsers = ["roles/run.invoker"] }\n'
    '  quoted_roles = { "allAuthenticatedUsers" = "roles/run.invoker" }\n'
    '}\n')
VAR_TF = ('variable "public_members" {\n  type    = list(string)\n  default = ["allUsers"]\n}\n\n'
          'variable "who" {\n  type    = string\n  default = "allAuthenticatedUsers"\n}\n\n'
          'module "via_var" {\n  source  = "../modules/acme-run"\n  members = var.public_members\n'
          '  extra   = ["group:ops@example.com", var.who]\n}\n')
GOLDEN_TF = ('module "uploads" {\n  source             = "../modules/storage-bucket"\n'
             '  project_id         = var.project_id\n  region             = var.region\n'
             '  bucket_name_suffix = "allUsers"\n}\n')
# Near misses and expressions: never findings (exact values on literals only; expressions are not judged).
NEAR_MISS_TF = (
    'variable "self" {\n  default = "${var.self}"\n}\n\n'
    'module "near" {\n'
    '  source   = "../modules/acme-run"\n'
    '  a        = "allUsers-edge"\n'
    '  b        = ["user:allUsers@example.com", "group:allAuthenticatedUsers@example.com", "allusers"]\n'
    '  c        = { viewer = "group:ops@example.com", "allUsers-x" = "allusers" }\n'
    '  d        = toset(["allUsers"])\n'
    '  e        = "${var.prefix}allUsers"\n'
    '  f        = concat(["allUsers"], [])\n'
    '  g        = var.self\n'
    '  h        = var.undeclared\n'
    '  i        = "$${allUsers}"\n'
    '  members  = var.authorized_invoker_members\n'
    '}\n')
PRIVATE_TFVARS = ('allow_unauthenticated      = false\nenable_direct_iap          = false\n'
                  'authorized_invoker_members = ["group:ops@example.com"]\n')


# ------------------------------------------------------------------------------------------------ positives
@pytest.mark.parametrize("resolved", PRIVATE, ids=PRIVATE_IDS)
def test_registered_module_call_with_a_public_member_is_refused_with_module_and_argument(resolved):
    got = _run({W + "edge.tf": EDGE_TF}, resolved)
    assert _found(got) == [(CODE, W + "edge.tf", "module.edge", "members[0]")]
    (d,) = got
    assert d.severity == "error" and d.error_class is ErrorClass.CODE_DEFECT and d.tool == "policy"
    assert d.source == "precommit" and d.line == 1 and d.end_line == 5
    assert d.hint == T.HINT_PUBLIC_PRINCIPAL_IN_MODULE_CALL
    assert d.message.startswith("module.edge passes allUsers in argument members[0]; this ")
    assert resolved.mode in d.message


def test_every_literal_shape_is_found_at_its_exact_place():
    got = _run({W + "shapes.tf": SHAPES_TF}, _record("PRIVATE_IAM"))
    assert _found(got) == sorted((CODE, W + "shapes.tf", "module.shapes", p) for p in (
        "invoker", 'bindings["roles/run.invoker"][1]', 'bindings["viewer"][0]', 'iam[0]["member"]',
        'member_roles["allUsers"]', 'quoted_roles["allAuthenticatedUsers"]'))


def test_variable_defaults_are_resolved_per_node():
    got = _run({W + "vars.tf": VAR_TF}, _flags("PRIVATE_IAP"))
    assert _found(got) == [(CODE, W + "vars.tf", "module.via_var", "extra[1]"),
                           (CODE, W + "vars.tf", "module.via_var", "members[0]")]
    # a default in a sibling file of the same directory resolves too
    split = {W + "variables.tf": VAR_TF.split('module "via_var"')[0],
             W + "main.tf": 'module "via_var"' + VAR_TF.split('module "via_var"')[1]}
    assert [d.attribute_path for d in _run(split, _flags("PRIVATE_IAP"))] == ["members[0]", "extra[1]"]


def test_golden_module_calls_are_judged_too():
    got = _run({W + "main.tf": GOLDEN_TF}, _record("PRIVATE_IAP"))
    assert _found(got) == [(CODE, W + "main.tf", "module.uploads", "bucket_name_suffix")]


def test_module_calls_inside_an_ai_written_local_module_use_that_directory_defaults():
    files = {W + "modules/front/main.tf": VAR_TF.replace("module \"via_var\"", "module \"inner\""),
             W + "main.tf": 'module "front" {\n  source = "./modules/front"\n}\n'}
    got = _run(files, _flags("PRIVATE_IAM"))
    assert _found(got) == [(CODE, W + "modules/front/main.tf", "module.inner", "extra[1]"),
                           (CODE, W + "modules/front/main.tf", "module.inner", "members[0]")]


def test_tf_json_module_call_is_checked_too():
    files = {W + "edge.tf.json": json.dumps({"module": {"edge": {"source": "../modules/acme-run",
                                                                  "members": ["allUsers"]}}})}
    assert _found(_run(files, _flags("PRIVATE_IAM"))) == [(CODE, W + "edge.tf.json", "module.edge", "members[0]")]
    keyed = {W + "keyed.tf.json": json.dumps({"module": {"k": {"source": "../modules/acme-run",
                                                               "member_roles": {"allUsers": ["roles/run.invoker"]}}}})}
    assert _found(_run(keyed, _flags("PRIVATE_IAM"))) == [(CODE, W + "keyed.tf.json", "module.k",
                                                           'member_roles["allUsers"]')]
    assert _run(keyed, _flags("PUBLIC_APP")) == []


# ------------------------------------------------------------------------------------------------ RT F2: root var files
ROOT_VAR_TF = ('variable "m" {\n  type    = list(string)\n  default = []\n}\n\n'
               'module "edge" {\n  source  = "../modules/acme-run"\n  members = var.m\n}\n')


@pytest.mark.parametrize("name,text", [
    ("m.auto.tfvars", 'm = ["allUsers"]\n'),
    ("m.auto.tfvars.json", '{"m": ["allUsers"]}'),
    ("terraform.tfvars.json", '{"m": ["allAuthenticatedUsers"]}'),
])
def test_an_ai_root_variable_file_that_opentofu_loads_is_read(name, text):
    files = {W + "edge.tf": ROOT_VAR_TF, W + name: text, W + "terraform.tfvars": PRIVATE_TFVARS}
    got = _run(files, _record("PRIVATE_IAM"), llm={W + "edge.tf", W + name})
    assert _found(got) == [(CODE, W + "edge.tf", "module.edge", "members[0]")]
    # the same files in a Public workload: nothing
    assert _run(files, _record("PUBLIC_APP"), llm={W + "edge.tf", W + name}) == []


def test_root_variable_files_follow_opentofu_precedence():
    from developer_agent.validators.access_idp import root_variable_files
    paths = [W + "z.auto.tfvars", W + "terraform.tfvars", W + "a.auto.tfvars.json", W + "terraform.tfvars.json",
             W + "modules/x/y.auto.tfvars", W + "other.tfvars", W + "edge.tf"]
    assert root_variable_files(paths) == [W + "terraform.tfvars.json", W + "a.auto.tfvars.json", W + "z.auto.tfvars"]
    # a later file replaces the whole value: the last one is clean -> no finding
    files = {W + "edge.tf": ROOT_VAR_TF, W + "a.auto.tfvars": 'm = ["allUsers"]\n',
             W + "b.auto.tfvars": 'm = ["group:ops@example.com"]\n'}
    assert _run(files, _flags("PRIVATE_IAP")) == []
    files[W + "c.auto.tfvars"] = 'm = ["allUsers"]\n'
    assert [d.attribute_path for d in _run(files, _flags("PRIVATE_IAP"))] == ["members[0]"]
    # the AI value wins over the platform terraform.tfvars, as in OpenTofu
    files = {W + "edge.tf": ROOT_VAR_TF, W + "terraform.tfvars": 'm = ["group:ops@example.com"]\n',
             W + "m.auto.tfvars": 'm = ["allUsers"]\n'}
    assert len(_run(files, _flags("PRIVATE_IAM"), llm={W + "edge.tf", W + "m.auto.tfvars"})) == 1


def test_negative_platform_tfvars_alone_and_clean_ai_variable_files_are_unchanged():
    # the platform's terraform.tfvars alone: resolution exactly as before (no AI variable file read)
    files = {W + "edge.tf": ROOT_VAR_TF, W + "terraform.tfvars": PRIVATE_TFVARS}
    assert _run(files, _record("PRIVATE_IAM"), llm={W + "edge.tf"}) == []
    # a clean AI *.auto.tfvars: nothing
    files[W + "m.auto.tfvars"] = 'm = ["serviceAccount:app@p.iam.gserviceaccount.com"]\n'
    assert _run(files, _record("PRIVATE_IAM"), llm={W + "edge.tf", W + "m.auto.tfvars"}) == []
    # a non-auto-loaded variables file and one in a module directory are not OpenTofu inputs: never read
    files = {W + "edge.tf": ROOT_VAR_TF, W + "extra.tfvars": 'm = ["allUsers"]\n',
             W + "modules/x/m.auto.tfvars": 'm = ["allUsers"]\n'}
    assert _run(files, _record("PRIVATE_IAM")) == []
    # a platform-rendered auto file is not the AI's (not read as an AI file)
    files = {W + "edge.tf": ROOT_VAR_TF, W + "m.auto.tfvars": "this is not hcl ==="}
    assert _run(files, _record("PRIVATE_IAM"), llm={W + "edge.tf"}, rendered={W + "m.auto.tfvars"}) == []


def test_an_unparseable_ai_variable_file_is_a_repairable_finding_never_a_skip():
    for name, text in (("m.auto.tfvars", "m = [\n"), ("m.auto.tfvars.json", "[1, 2]"),
                       ("terraform.tfvars.json", "{not json")):
        files = {W + "edge.tf": ROOT_VAR_TF, W + name: text}
        (d,) = _run(files, _flags("PRIVATE_IAM"))
        assert (d.code, d.file, d.error_class) == ("POLICY.UNCHECKABLE_FILE", W + name, ErrorClass.CODE_DEFECT)
        assert d.hint == T.HINT_UNCHECKABLE_VARIABLES_FILE
        assert _run(files, _flags("PUBLIC_APP")) == []   # public: not read, unchanged


# ------------------------------------------------------------------------------------------------ Do No Harm
@pytest.mark.parametrize("resolved", NOT_PRIVATE, ids=NOT_PRIVATE_IDS)
def test_negative_same_trees_in_a_public_or_unknown_workload_have_no_finding(resolved):
    for files in ({W + "edge.tf": EDGE_TF}, {W + "shapes.tf": SHAPES_TF}, {W + "vars.tf": VAR_TF},
                  {W + "main.tf": GOLDEN_TF}):
        assert _run(files, resolved) == []
        assert [f for f in apv.validate(files, _facts(resolved)) if f["code"] == CODE] == []


def _facts(resolved):
    from developer_agent.validators.access_idp import access_facts
    return access_facts(resolved)


@pytest.mark.parametrize("resolved", PRIVATE, ids=PRIVATE_IDS)
def test_negative_private_workload_without_a_public_literal_has_no_finding(resolved):
    files = {W + "near.tf": NEAR_MISS_TF, W + "terraform.tfvars": PRIVATE_TFVARS}
    assert _run(files, resolved, llm={W + "near.tf"}) == []
    clean = {W + "edge.tf": EDGE_TF.replace('"allUsers"', '"group:ops@example.com"')}
    assert _run(clean, resolved) == []


def test_negative_private_lane19_output_is_identical_without_a_public_literal():
    """A private tree with module calls but no public literal: validate() returns exactly what it returned before
    FD-4CX-b (the module rule adds nothing), byte for byte."""
    files = {W + "near.tf": NEAR_MISS_TF, W + "main.tf": GOLDEN_TF.replace('"allUsers"', '"uploads"')}
    facts = _facts(_record("PRIVATE_IAM"))
    got = apv.validate(files, facts)
    assert json.dumps(got, sort_keys=True) == json.dumps([], sort_keys=True)


def test_negative_platform_files_and_platform_synthesized_blocks_are_not_judged():
    files = {W + "edge.tf": EDGE_TF, W + "platform.tf": GOLDEN_TF, "infra/modules/acme-run/main.tf": EDGE_TF}
    got = _run(files, _record("PRIVATE_IAM"), llm={W + "edge.tf"}, vendored={"infra/modules/acme-run/main.tf"},
               rendered={W + "platform.tf"},
               extras={"platform_addresses": {(W + "edge.tf", "module.edge")}})
    assert got == []


def test_negative_every_golden_module_treated_as_ai_written_has_no_finding_in_a_private_workload():
    dirs = {}
    for path in glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True):
        dirs.setdefault(os.path.dirname(path), []).append(path)
    assert len(dirs) >= 28
    for d, paths in sorted(dirs.items()):
        files = {W + os.path.basename(p): open(p, encoding="utf-8").read() for p in paths}
        got = [f for f in apv.validate(files, _facts(_record("PRIVATE_IAM"))) if f["code"] == CODE]
        assert got == [], (os.path.relpath(d, REPO_ROOT), got)


def test_public_members_table_is_the_registered_module_check_table():
    assert apv.PUBLIC_MEMBERS == mx.PUBLIC_MEMBERS == T.PUBLIC_MEMBERS
    assert apv.PRIVATE_MODES == ("PRIVATE_IAP", "PRIVATE_IAM")
    assert FD4CXB_CODES == {CODE} and CODE in KEPT_CODES


def test_attribute_location_format():
    assert apv.attribute_location(("members", 0)) == "members[0]"
    assert apv.attribute_location(("b", "viewer", 2)) == 'b["viewer"][2]'
    assert apv.attribute_location(("b", "roles/run.invoker", 0)) == 'b["roles/run.invoker"][0]'
    assert apv.attribute_location(("member_roles", "allUsers")) == 'member_roles["allUsers"]'


# ------------------------------------------------------------------------------------------------ typed intent
TOPO = {"services": [{"name": "shop", "kind": "cloudrun"}], "primary_service": "shop", "edges": [],
        "resources": [{"type": "google_storage_bucket", "logical_name": "uploads", "purpose": "u",
                       "consumers": [{"service": "shop", "env_key": "UPLOADS_BUCKET", "attribute": None}]}]}
BUCKET = {"module": "storage-bucket", "name": "uploads", "realizes": "uploads",
          "args": {"bucket_name_suffix": "uploads"}}
BIGTABLE_PUBLIC = {"module": "database-bigtable", "name": "bt",
                   "args": {"column_families": ["cf", "allUsers"], "labels": {"who/x": "allAuthenticatedUsers"}}}


def _assemble(modules):
    vt, diags = validate_service_topology(TOPO, product_id="shop")
    assert vt is not None, diags
    files = {C.INTENT_PATH: json.dumps({"schema": "iac_intent/v1", "modules": list(modules)}, indent=2)}
    asm, _ = C.assemble_intent(files, C.build_intent_run(vt, {}, artifacts=II.load_artifacts()), vt,
                               ("module.foundation", "module.compute"), existing_files={}, record=AssemblyRecord())
    assert asm.diagnostics == () and C.RENDER_PATH in asm.rendered
    return asm, files


def _run_intent(files, asm, resolved):
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p == C.INTENT_PATH
                                  else Ownership.PLATFORM_RENDERED, extras={"iac_intent": asm}, trace_id="t",
                                  rendered=frozenset({C.RENDER_PATH}), draft={C.INTENT_PATH: files[C.INTENT_PATH]})
    before = artifact_hash(dict(files))
    got = AccessIdpValidator(resolved).validate(ctx)
    assert artifact_hash(dict(files)) == before
    return got


@pytest.mark.parametrize("resolved", PRIVATE, ids=PRIVATE_IDS)
def test_intent_module_instance_with_a_public_literal_is_refused_on_the_intent(resolved):
    asm, files = _assemble([BUCKET, BIGTABLE_PUBLIC])
    got = _run_intent(files, asm, resolved)
    assert _found(got) == [(CODE, C.INTENT_PATH, "module.bt", "/args/column_families/1"),
                           (CODE, C.INTENT_PATH, "module.bt", "/args/labels/who~1x")]
    for d in got:
        assert d.error_class is ErrorClass.CODE_DEFECT and d.hint == T.HINT_PUBLIC_PRINCIPAL_IN_MODULE_CALL
        assert "(intent entry /modules/1/args/" in d.message


@pytest.mark.parametrize("resolved", NOT_PRIVATE, ids=NOT_PRIVATE_IDS)
def test_negative_intent_same_document_public_or_unknown_has_no_finding(resolved):
    asm, files = _assemble([BUCKET, BIGTABLE_PUBLIC])
    assert _run_intent(files, asm, resolved) == []


def test_negative_intent_private_without_a_public_literal_and_mode_off_have_no_finding():
    asm, files = _assemble([BUCKET])
    assert _run_intent(files, asm, _record("PRIVATE_IAM")) == []
    # mode off (no IntentAssembly): a custom.tf.json the platform did not render from an intent is not read here
    asm2, files2 = _assemble([BUCKET, BIGTABLE_PUBLIC])
    assert _run_intent(files2, None, _record("PRIVATE_IAM")) == []
    assert _run_intent(files2, C.IntentAssembly(), _record("PRIVATE_IAM")) == []


def test_public_literal_in_a_rendered_module_that_is_not_an_intent_entry_is_a_platform_defect():
    asm, files = _assemble([BUCKET])
    doc = json.loads(files[C.RENDER_PATH])
    doc["module"]["platform_x"] = {"source": "../modules/acme-run", "members": ["allUsers"]}
    files = dict(files, **{C.RENDER_PATH: json.dumps(doc)})
    (d,) = _run_intent(files, asm, _flags("PRIVATE_IAM"))
    assert (d.code, d.file, d.block_address, d.error_class) == (CODE, C.RENDER_PATH, "module.platform_x",
                                                               ErrorClass.PLATFORM_DEFECT)
    files[C.RENDER_PATH] = "{not json"
    (d,) = _run_intent(files, asm, _flags("PRIVATE_IAM"))
    assert (d.code, d.error_class) == ("POLICY.UNCHECKABLE_FILE", ErrorClass.PLATFORM_DEFECT)


def test_intent_finding_routes_to_the_iac_persona_with_the_hint():
    asm, files = _assemble([BUCKET, BIGTABLE_PUBLIC])
    (d, _) = sorted(_run_intent(files, asm, _record("PRIVATE_IAP")), key=lambda x: x.attribute_path)
    draft = {C.INTENT_PATH: files[C.INTENT_PATH]}
    ctx = LoopContext(trace_id="t", product_id="shop", assemble=lambda x: None, stack=ValidatorStack(),
                      ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                      attribution={C.INTENT_PATH: "IAC_ENGINEER"}, llm_draft_paths=set(draft), preexisting=set())
    got = Router(ctx, draft, Assembled(tree=dict(files), record=AssemblyRecord(), iac_intent=asm)).route(d)
    assert (got.error_class, got.persona, got.draft_path) == (ErrorClass.CODE_DEFECT, "IAC_ENGINEER", C.INTENT_PATH)
    assert got.hint == T.HINT_PUBLIC_PRINCIPAL_IN_MODULE_CALL


# ------------------------------------------------------------------------------------------------ repair loop
class Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        return {"files": self.responses.pop(0) if self.responses else {}, "envelope_ok": True, "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def _loop(persona, llm_paths, access):
    st = ValidatorStack()
    st.register(AccessIdpValidator(access), "blocking")

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st,
                       ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                       attribution={p: "iac_worker" for p in llm_paths}, llm_draft_paths=set(llm_paths),
                       preexisting=set(), repair_fn=persona, model="m", available_providers=["google"])


FIXED_EDGE_TF = EDGE_TF.replace('"allUsers"', '"group:ops@example.com"')


def test_repair_loop_sends_the_exact_module_and_argument_back_and_accepts_the_fix():
    draft = {W + "edge.tf": EDGE_TF}
    persona = Persona({W + "edge.tf": FIXED_EDGE_TF})
    tree, report = RepairLoop(_loop(persona, set(draft), _record("PRIVATE_IAM"))).run(dict(draft))
    assert report.status == "PASS" and tree[W + "edge.tf"] == FIXED_EDGE_TF
    (t,) = persona.tasks
    assert t.persona == "iac_worker" and t.files_to_fix == {W + "edge.tf": EDGE_TF}
    (diag,) = t.diagnostics
    assert diag["code"] == CODE and diag["block"] == "module.edge" and diag["line"] == 1
    assert diag["message"].startswith("module.edge passes allUsers in argument members[0]; this PRIVATE_IAM ")
    assert diag["hint"] == T.HINT_PUBLIC_PRINCIPAL_IN_MODULE_CALL
    assert "members[0]" in t.prompt() and T.HINT_PUBLIC_PRINCIPAL_IN_MODULE_CALL in t.prompt()


def test_a_repair_that_does_not_remove_the_public_member_stops_the_run_at_pre_commit():
    draft = {W + "edge.tf": EDGE_TF}
    with pytest.raises(RepairBudgetExhausted) as e:
        RepairLoop(_loop(Persona(), set(draft), _record("PRIVATE_IAP"))).run(dict(draft))
    assert [d.code for d in e.value.report.diagnostics] == [CODE]


def test_negative_public_workload_passes_the_loop_untouched():
    draft = {W + "edge.tf": EDGE_TF}
    persona = Persona()
    tree, report = RepairLoop(_loop(persona, set(draft), _record("PUBLIC_APP"))).run(dict(draft))
    assert report.status == "PASS" and persona.tasks == [] and tree == draft


# ------------------------------------------------------------------------------------------------ wiring
def test_v2l_stays_blocking_in_the_real_stack_and_carries_the_access():
    stack = build_step1_stack(validate_client=None, verifier_factory=None, access=_record("PRIVATE_IAM"))
    assert stack.mode_of("V2l") == "blocking"
    (reg,) = [r for r in stack._regs if r.validator.id == "V2l"]
    assert reg.validator.facts.mode == "PRIVATE_IAM"

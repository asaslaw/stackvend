"""FD-4AW HCL content policy (V2j, developer_agent/validators/content_policy.py): provisioners, connection blocks,
`data "external"` and blocks of providers the platform does not offer are refused on python-hcl2's parse tree.
One positive test per code, Do No Harm negatives (valid roots, every golden module -> zero findings, nothing
rewritten), the V2d-style exclusions and the registration in the real stack builder."""
import hermetic_guard  # noqa: F401  (first import)

import glob
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

from developer_agent.validators import ValidationContext, ValidatorUnavailable  # noqa: E402
from developer_agent.validators import policy_tables as T  # noqa: E402
from developer_agent.validators.content_policy import ContentPolicyValidator, block_provider  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import artifact_hash  # noqa: E402

W = "infra/workload/"
# The validate service's pinned provider set (mcp-servers/terraform/validate_service.py VALIDATE_PROVIDERS).
AVAILABLE = ["google", "google-beta", "kubernetes", "random"]


CLOUDRUN_VENDORED = {"infra/modules/compute-cloudrun/main.tf": "", "infra/modules/compute-cloudrun/variables.tf": ""}


def _ctx(files, *, llm=None, extras=None, vendored=(), rendered=(), own=None, draft=None):
    llm = set(files) if llm is None else set(llm)
    vend, rend = frozenset(vendored), frozenset(rendered)

    def default_own(path):
        if path in vend:
            return Ownership.PLATFORM_VENDORED
        return Ownership.LLM_AUTHORED if path in llm else Ownership.PLATFORM_RENDERED
    ex = {"available_providers": AVAILABLE} if extras is None else extras
    return ValidationContext.build(files, ownership=own or default_own, extras=ex, trace_id="t", vendored=vend,
                                   rendered=rend, draft=draft or {})


def _run(text, vendored=None, **kw):
    files = {W + "custom.tf": text}
    vendored = CLOUDRUN_VENDORED if vendored is None else vendored
    files.update(vendored)
    ctx = _ctx(files, llm={W + "custom.tf"}, vendored=set(vendored), **kw)
    before = artifact_hash(files)
    got = ContentPolicyValidator().validate(ctx)
    assert artifact_hash(dict(ctx.files)) == before   # validators never write
    return got


def _found(ds):
    return sorted((d.code, d.block_address, d.line) for d in ds)


# ------------------------------------------------------------------------------------------------ positives
def test_provisioner_forbidden_every_type_incl_terraform_data():
    tf = ('resource "google_compute_instance" "vm" {\n'      # 1
          '  name = "vm"\n'
          '  provisioner "local-exec" {\n'                  # 3
          '    command = "curl http://example.invalid"\n'
          '  }\n'
          '  provisioner "file" {\n'                        # 6
          '    source      = "a"\n'
          '    destination = "/tmp/a"\n'
          '  }\n'
          '}\n'
          'resource "terraform_data" "t" {\n'               # 11
          '  provisioner "remote-exec" {\n'                 # 12
          '    inline = ["id"]\n'
          '  }\n'
          '}\n')
    got = _run(tf)
    assert _found(got) == [("POLICY.PROVISIONER_FORBIDDEN", "google_compute_instance.vm", 3),
                           ("POLICY.PROVISIONER_FORBIDDEN", "google_compute_instance.vm", 6),
                           ("POLICY.PROVISIONER_FORBIDDEN", "terraform_data.t", 12)]
    assert all(d.hint == T.HINT_PROVISIONER_FORBIDDEN and d.file == W + "custom.tf" for d in got)
    assert sorted(d.message for d in got)[0] == 'google_compute_instance.vm declares provisioner "file"'


def test_connection_forbidden_resource_level_and_inside_a_provisioner():
    tf = ('resource "google_compute_instance" "vm" {\n'      # 1
          '  name = "vm"\n'
          '  connection {\n'                                # 3
          '    type = "ssh"\n'
          '    host = self.network_interface.0.network_ip\n'
          '  }\n'
          '}\n'
          'resource "terraform_data" "t" {\n'               # 8
          '  provisioner "remote-exec" {\n'                 # 9
          '    inline = ["id"]\n'
          '    connection {\n'                              # 11
          '      host = "10.0.0.2"\n'
          '    }\n'
          '  }\n'
          '}\n')
    got = _run(tf)
    assert _found(got) == [("POLICY.CONNECTION_FORBIDDEN", "google_compute_instance.vm", 3),
                           ("POLICY.CONNECTION_FORBIDDEN", "terraform_data.t", 11),
                           ("POLICY.PROVISIONER_FORBIDDEN", "terraform_data.t", 9)]
    assert {d.hint for d in got if d.code == "POLICY.CONNECTION_FORBIDDEN"} == {T.HINT_CONNECTION_FORBIDDEN}


def test_external_data_forbidden_even_when_the_provider_is_available():
    tf = 'data "external" "x" {\n  program = ["python3", "x.py"]\n}\n'
    got = _run(tf, extras={"available_providers": AVAILABLE + ["external"]})
    assert _found(got) == [("POLICY.EXTERNAL_DATA_FORBIDDEN", "data.external.x", 1)]
    assert got[0].hint == T.HINT_EXTERNAL_DATA_FORBIDDEN
    # with the real provider set it is also a block of an unavailable provider (two distinct findings)
    assert _found(_run(tf)) == [("POLICY.EXTERNAL_DATA_FORBIDDEN", "data.external.x", 1),
                                ("POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE", "data.external.x", 1)]


def test_implicit_provider_not_available_per_block_incl_alias_form():
    tf = ('resource "null_resource" "a" {}\n'                # 1
          'resource "local_file" "f" {\n'                   # 2
          '  filename = "x"\n'
          '  content  = "y"\n'
          '}\n'
          'data "http" "h" {\n'                             # 6
          '  url = "https://example.invalid"\n'
          '}\n'
          'resource "null_resource" "b" {\n'                # 9
          '  provider = null.alias1\n'
          '}\n'
          'resource "google_storage_bucket" "c" {\n'        # 12: meta-argument names an unavailable provider
          '  provider = archive.x\n'
          '  name     = "c"\n'
          '  location = "US"\n'
          '}\n')
    got = _run(tf)
    assert _found(got) == [("POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE", "data.http.h", 6),
                           ("POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE", "google_storage_bucket.c", 12),
                           ("POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE", "local_file.f", 2),
                           ("POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE", "null_resource.a", 1),
                           ("POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE", "null_resource.b", 9)]
    msg = {d.block_address: d.message for d in got}
    assert msg["null_resource.b"] == ('null_resource.b belongs to provider "null", which is not available to the '
                                      'platform')   # python-hcl2 renders `null.alias1` as "${None.alias1}"
    assert msg["google_storage_bucket.c"].endswith('provider "archive", which is not available to the platform')
    assert got[0].hint == T.HINT_IMPLICIT_PROVIDER.format(provider="null",   # source order: null_resource.a first
                                                          providers="google, google-beta, kubernetes, random")


def test_block_provider_is_terraforms_rule_on_the_parsed_labels():
    assert block_provider("resource", ("google_storage_bucket", "b"), {}) == "google"
    assert block_provider("resource", ("random_id", "r"), {}) == "random"
    assert block_provider("data", ("external", "x"), {}) == "external"
    assert block_provider("resource", ("google_x", "y"), {"provider": "${google-beta}"}) == "google-beta"
    assert block_provider("resource", ("google_x", "y"), {"provider": "${google.west}"}) == "google"
    assert block_provider("resource", ("null_resource", "n"), {"provider": "${None.a}"}) == "null"
    assert block_provider("module", ("m",), {}) is None


# ------------------------------------------------------------------------------------------------ Do No Harm
VALID_ROOT = '''
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
    google-beta = {
      source = "hashicorp/google-beta"
    }
    random = {
      version = ">= 3.0"
    }
    kubernetes = ">= 2.0"
  }
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "google_pubsub_topic" "events" {
  name = "events-${random_id.suffix.hex}"
}

resource "google_firestore_database" "app" {
  name        = "app-db"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
}

module "api" {
  source       = "../modules/compute-cloudrun"
  project_id   = var.project_id
  region       = var.region
  service_name = "api"
  env_vars = {
    TOPIC = google_pubsub_topic.events.name
  }
}

data "google_project" "this" {}

resource "google_cloud_run_v2_service" "beta" {
  provider = google-beta
  name     = "beta"
  location = var.region
  template {
    containers {
      image = var.container_image
    }
  }
}

module "local_helper" {
  source = "./modules/helper"
}
'''


def test_valid_cloud_run_pubsub_firestore_root_has_zero_findings():
    assert _run(VALID_ROOT) == []


def test_attributes_named_like_meta_blocks_are_not_blocks():
    # not valid OpenTofu (V1b reports the unsupported argument), but never judged as a provisioner/connection block
    tf = 'resource "google_x" "a" {\n  connection = { a = 1 }\n  provisioner = [{ a = 1 }]\n}\n'
    assert _run(tf) == []


def test_platform_synthesized_blocks_and_non_llm_files_are_not_judged():
    bad = 'resource "null_resource" "n" {\n  provisioner "local-exec" {\n    command = "x"\n  }\n}\n'
    files = {W + "custom.tf": bad, W + "platform.tf": bad, W + "modules/x/main.tf": bad}
    ctx = _ctx(files, llm={W + "custom.tf", W + "modules/x/main.tf"},
               extras={"available_providers": AVAILABLE,
                       "platform_addresses": {(W + "custom.tf", "null_resource.n")}})
    assert ContentPolicyValidator().validate(ctx) == []


def test_missing_provider_set_is_unavailable_never_a_pass():
    with pytest.raises(ValidatorUnavailable):
        ContentPolicyValidator().validate(_ctx({W + "custom.tf": VALID_ROOT}, extras={}))


def _golden_module_dirs():
    dirs = {}
    for path in glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True):
        dirs.setdefault(os.path.dirname(path), []).append(path)
    return dirs


def test_every_golden_module_treated_as_llm_owned_has_zero_findings():
    dirs = _golden_module_dirs()
    assert len(dirs) >= 28
    for d, paths in sorted(dirs.items()):
        files = {W + os.path.basename(p): open(p).read() for p in paths}
        got = ContentPolicyValidator().validate(_ctx(files, extras={"available_providers": ["google", "google-beta",
                                                                                            "random"]}))
        assert got == [], (os.path.relpath(d, REPO_ROOT), [(x.code, x.block_address) for x in got])


# ------------------------------------------------------------------------------------------------ registration
def test_registered_blocking_in_the_real_stack_builder_next_to_v2d():
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V2j") == "blocking"
    assert stack.ids.index("V2j") == stack.ids.index("V2d") + 1
    assert stack.mode_of("V-K8S-PH") == "blocking"   # FD-4AF-r guard untouched


# ------------------------------------------------------------------------------------------------ FD-4AW-a (Fable RT)
EVIL = 'resource "terraform_data" "x" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\n'


def test_f1_llm_authored_root_tf_json_is_not_checkable():
    evil_json = '{"resource": {"terraform_data": {"x": {"provisioner": [{"local-exec": {"command": "id"}}]}}}}'
    files = {W + "evil.tf.json": evil_json, W + "modules/m/x.tf.json": evil_json}
    got = ContentPolicyValidator().validate(_ctx(files))
    assert [(d.code, d.file) for d in got] == [("POLICY.JSON_IAC_NOT_CHECKABLE", W + "evil.tf.json")]
    assert got[0].hint == T.HINT_JSON_IAC_NOT_CHECKABLE
    # an LLM_DOCUMENT custom.tf.json the platform did not render is refused too
    doc = {W + "custom.tf.json": evil_json}
    ctx = _ctx(doc, own=lambda p: Ownership.LLM_DOCUMENT)
    assert [d.code for d in ContentPolicyValidator().validate(ctx)] == ["POLICY.JSON_IAC_NOT_CHECKABLE"]


def test_f1_negative_platform_rendered_custom_tf_json_stays_allowed():
    doc = {W + "custom.tf.json": '{"resource": {"google_pubsub_topic": {"t": {"name": "t"}}}}'}
    ctx = _ctx(doc, own=lambda p: Ownership.LLM_DOCUMENT, rendered={W + "custom.tf.json"})
    assert ContentPolicyValidator().validate(ctx) == []
    ctx = _ctx(doc, own=lambda p: Ownership.PLATFORM_RENDERED)
    assert ContentPolicyValidator().validate(ctx) == []


def test_f2_llm_draft_at_user_owned_names_is_refused_and_renamed_by_its_author():
    from developer_agent.validators.step1 import PathValidator
    names = [W + "human.tf", W + "human_override.tf", W + "override.tf", W + "custom_override.tf",
             W + "x_override.tf.json"]
    draft = {p: EVIL for p in names}
    draft[W + "custom.tf"] = VALID_ROOT
    got = PathValidator().validate(_ctx(dict(draft), draft=draft))
    assert sorted((d.code, d.file) for d in got) == [("PATH.USER_OWNED_NAME_WRITTEN_BY_LLM", p) for p in sorted(names)]
    assert {d.hint for d in got} == {T.HINT_USER_OWNED_NAME}
    from developer_agent.repair_loop import RENAME_CODES
    assert {"PATH.USER_OWNED_NAME_WRITTEN_BY_LLM", "POLICY.JSON_IAC_NOT_CHECKABLE"} <= RENAME_CODES


def test_f2_negative_preexisting_human_tf_is_not_a_finding():
    from developer_agent.validators.step1 import PathValidator
    files = {W + "human.tf": EVIL, W + "human_override.tf": "", W + "custom.tf": VALID_ROOT}
    assert PathValidator().validate(_ctx(files, draft={W + "custom.tf": VALID_ROOT})) == []


def test_f3_module_source_must_be_a_local_vendored_or_workload_directory():
    tf = ('module "remote" {\n  source = "https://evil.invalid/mod.zip"\n}\n'                         # 1
          'module "git" {\n  source = "git::https://example.invalid/m.git"\n}\n'                     # 4
          'module "registry" {\n  source  = "terraform-aws-modules/vpc/aws"\n  version = "5.0.0"\n}\n'  # 7
          'module "versioned_local" {\n  source  = "../modules/compute-cloudrun"\n  version = "1.0"\n}\n'  # 11
          'module "not_vendored" {\n  source = "../modules/not-a-golden-module"\n}\n'               # 15
          'module "escape" {\n  source = "../../etc"\n}\n'                                          # 18
          'module "self" {\n  source = "./"\n}\n'                                                   # 21
          'module "expr" {\n  source = "../modules/${var.m}"\n}\n'                                   # 24
          'module "gcs" {\n  source = "gcs::https://www.googleapis.com/storage/v1/b/m.zip"\n}\n')     # 27
    got = _run(tf)
    assert _found(got) == sorted(("POLICY.MODULE_SOURCE_NOT_LOCAL", f"module.{n}", line) for n, line in [
        ("remote", 1), ("git", 4), ("registry", 7), ("versioned_local", 11), ("not_vendored", 15), ("escape", 18),
        ("self", 21), ("expr", 24), ("gcs", 27)])
    assert {d.hint for d in got} == {T.HINT_MODULE_SOURCE_NOT_LOCAL}


def test_f3_negative_golden_and_workload_local_modules():
    tf = ('module "api" {\n  source = "../modules/compute-cloudrun"\n}\n'
          'module "api2" {\n  source = "./../modules/compute-cloudrun/"\n}\n'
          'module "helper" {\n  source = "./modules/x"\n}\n')
    assert _run(tf) == []


def test_f4_required_providers_source_must_be_the_platforms():
    tf = ('terraform {\n  required_providers {\n    random = {\n      source = "hashicorp/local"\n    }\n'
          '    google = {\n      source = "evilcorp/google"\n    }\n  }\n}\n'
          'data "local_file" "f" {\n  provider = random\n  filename = "/etc/passwd"\n}\n')
    got = [d for d in _run(tf) if d.code == "POLICY.PROVIDER_SOURCE_MISMATCH"]
    assert sorted(d.message for d in got) == [
        'required_providers "google" has source \'evilcorp/google\'; the platform\'s "google" is \'hashicorp/google\'',
        'required_providers "random" has source \'hashicorp/local\'; the platform\'s "random" is \'hashicorp/random\'']
    assert {d.hint for d in got} == {T.HINT_PROVIDER_SOURCE_MISMATCH.format(
        sources="google = hashicorp/google, google-beta = hashicorp/google-beta, kubernetes = hashicorp/kubernetes, "
                "random = hashicorp/random")}


def _terraform_server_allowlist(name):
    """FD-4AQ W1b: the terraform server's single allow-list source (validate_service.VALIDATE_PROVIDERS / REGISTRIES
    and the apply-time tables derive from provider_allowlist.py)."""
    import ast as _ast
    src = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "provider_allowlist.py")).read()
    return next(_ast.literal_eval(n.value) for n in _ast.parse(src).body if isinstance(n, _ast.Assign)
                and any(getattr(t, "id", "") == name for t in n.targets))


def test_f4_table_is_the_validate_services_pinned_set():
    import ast as _ast
    src = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "validate_service.py")).read()
    pinned_expr = next(_ast.unparse(n.value) for n in _ast.parse(src).body if isinstance(n, _ast.Assign)
                       and any(getattr(t, "id", "") == "VALIDATE_PROVIDERS" for t in n.targets))
    assert pinned_expr == "tuple(provider_allowlist.PLATFORM_PROVIDER_SOURCES)"
    pinned = _terraform_server_allowlist("PLATFORM_PROVIDER_SOURCES")
    assert pinned == T.PLATFORM_PROVIDER_SOURCES
    assert set(pinned) == set(T.PLATFORM_PROVIDER_SOURCES) == set(AVAILABLE)
    assert all(v == f"hashicorp/{k}" for k, v in T.PLATFORM_PROVIDER_SOURCES.items())


def test_f5_terraform_remote_state_is_forbidden():
    tf = ('data "terraform_remote_state" "other" {\n  backend = "gcs"\n  config = {\n    bucket = "b"\n'
          '    prefix = "p"\n  }\n}\n')
    assert _found(_run(tf)) == [("POLICY.REMOTE_STATE_FORBIDDEN", "data.terraform_remote_state.other", 1)]


def test_f5_plain_terraform_data_passes_v2j_and_v2d():
    # Fable RT F5 left terraform_data to its own owner row; FD-4CW-Q2 (owner 10-27) admits it in V2d too
    from developer_agent.validators.step1 import ProviderAvailabilityValidator
    tf = 'resource "terraform_data" "marker" {\n  input = "x"\n}\n'
    assert _run(tf) == []
    assert ProviderAvailabilityValidator().validate(_ctx({W + "custom.tf": tf})) == []


def test_f1_f2_findings_are_repaired_by_their_author_with_a_rename():
    # the router sends both rename-only codes to the persona that wrote the key (CODE_DEFECT), never BROWNFIELD
    from developer_agent.repair_loop import Assembled, LoopContext, RepairLoop
    from developer_agent.validators.base import ValidatorStack
    from developer_agent.validators.step1 import PathValidator, TofuValidateValidator
    from shared.diagnostics import AssemblyRecord, MemoryLedgerStore
    from shared.hallucination_stack import HallucinationStackSettings

    class PassTofu:
        def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
            return {"status": "PASS", "diagnostics": []}

    topic = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'
    tasks = []

    def persona(task):
        tasks.append(task)
        return {"files": {W + "custom_human.tf": topic, W + "custom_json.tf": 'resource "google_pubsub_topic" "j" {\n'
                          '  name = "j"\n}\n'}, "envelope_ok": True, "model": "m", "tokens_in": 1, "tokens_out": 1,
                "tokens_thoughts": 0}

    def assemble(d):
        tree = dict(d)
        return Assembled(tree=tree, record=AssemblyRecord(),
                         assembled_root={k: v for k, v in tree.items() if k.endswith(".tf")})
    st = ValidatorStack()
    st.register(PathValidator(), "blocking")
    st.register(ContentPolicyValidator(), "blocking")
    st.register(TofuValidateValidator(PassTofu()), "blocking")
    draft = {W + "human.tf": topic, W + "evil.tf.json": '{"resource": {"google_pubsub_topic": {"j": {"name": "j"}}}}'}
    ctx = LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st, ledger_store=MemoryLedgerStore(),
                      settings=HallucinationStackSettings(), attribution={p: "backend_worker" for p in draft},
                      llm_draft_paths=set(draft), preexisting=set(), repair_fn=persona, model="m",
                      available_providers=AVAILABLE)
    tree, report = RepairLoop(ctx).run(dict(draft))
    assert report.status == "PASS" and not set(draft) & set(tree)
    assert tasks[0].persona == "backend_worker" and tasks[0].renames == sorted(draft)
    assert {d["hint"] for d in tasks[0].diagnostics} == {T.HINT_USER_OWNED_NAME, T.HINT_JSON_IAC_NOT_CHECKABLE}


# ------------------------------------------------------------------------------------------------ FD-4AW-r
def test_r1_module_source_must_be_a_vendored_module_directory_not_an_ancestor():
    # pre-R1 the prefix rule (any vendored file below the target) passed `../modules`, `../` and `../modules/`;
    # `..` is refused by the ./ / ../ prefix rule either way
    tf = ('module "modules_root" {\n  source = "../modules"\n}\n'          # 1
          'module "infra_root" {\n  source = "../"\n}\n'                   # 4
          'module "dot_dot" {\n  source = ".."\n}\n'                       # 7
          'module "modules_slash" {\n  source = "../modules/"\n}\n')       # 10
    assert _found(_run(tf)) == sorted(("POLICY.MODULE_SOURCE_NOT_LOCAL", f"module.{n}", line) for n, line in [
        ("modules_root", 1), ("infra_root", 4), ("dot_dot", 7), ("modules_slash", 10)])


def test_r1_negative_nested_golden_module_directory_still_passes():
    vend = {"infra/modules/workload-foundation/base/main.tf": "", "infra/modules/compute-cloudrun/main.tf": ""}
    tf = ('module "foundation" {\n  source = "../modules/workload-foundation/base"\n}\n'
          'module "api" {\n  source = "../modules/compute-cloudrun"\n}\n')
    assert _run(tf, vendored=vend) == []
    # the bundle's parent directory holds no file directly -> not a module directory
    assert [d.code for d in _run('module "f" {\n  source = "../modules/workload-foundation"\n}\n', vendored=vend)] \
        == ["POLICY.MODULE_SOURCE_NOT_LOCAL"]


def test_r2_fully_qualified_platform_provider_sources_are_accepted():
    tf = ('terraform {\n  required_providers {\n'
          '    google = {\n      source = "registry.terraform.io/hashicorp/google"\n    }\n'
          '    google-beta = {\n      source = "registry.opentofu.org/hashicorp/google-beta"\n    }\n'
          '    random = {\n      source = "registry.terraform.io/hashicorp/random"\n    }\n'
          '    kubernetes = {\n      source = "hashicorp/kubernetes"\n    }\n  }\n}\n')
    assert _run(tf) == []
    bad = ('terraform {\n  required_providers {\n'
           '    google = {\n      source = "evil.example/hashicorp/google"\n    }\n'
           '    random = {\n      source = "registry.terraform.io/hashicorp/local"\n    }\n  }\n}\n')
    assert sorted(d.message.split(" has ")[0] for d in _run(bad)) == ['required_providers "google"',
                                                                     'required_providers "random"']


def test_r2_registry_hosts_are_the_validate_services_mirrored_registries():
    import ast as _ast
    src = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "validate_service.py")).read()
    regs_expr = next(_ast.unparse(n.value) for n in _ast.parse(src).body if isinstance(n, _ast.Assign)
                     and any(getattr(t, "id", "") == "REGISTRIES" for t in n.targets))
    assert regs_expr == "provider_allowlist.PROVIDER_REGISTRIES"
    regs = _terraform_server_allowlist("PROVIDER_REGISTRIES")
    assert set(regs) == set(T.PLATFORM_PROVIDER_REGISTRIES)
    assert T.PLATFORM_PROVIDER_SOURCE_FORMS["google"] == frozenset({
        "hashicorp/google", "registry.opentofu.org/hashicorp/google", "registry.terraform.io/hashicorp/google"})

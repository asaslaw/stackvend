"""Step 2 S2-B (docs/planning/wave2-step2-plan.md rev 2 §3.2): the error-string HCL chain HD-15 -> self_correct_hcl
is retired behind typed checks. Per deleted branch: a tombstone (the code is gone), a Do-No-Harm negative (valid
input -> byte-identical) and the typed replacement that now reports the case (V1b `tofu validate` codes with the
production engine when it is present, V2a/V2e exact policy rows otherwise).

Real-engine tests use the owner-verified production column (eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod,
untracked) and skip with a reason when it is not on this machine.
FD-55 W4 (register FD55-W4): HD-15 and self_correct_hcl are deleted altogether, so the per-branch tombstones
and the "byte-identical through self_correct_hcl" negatives went with them; the typed replacements stay."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.validators.tofu_diagnostics import map_raw_diagnostic  # noqa: E402

W = "infra/workload/"
CUSTOM = W + "custom.tf"
PV_SRC = os.path.join(GATEWAY, "developer_agent", "preflight_validator.py")
TE_SRC = os.path.join(GATEWAY, "developer_agent", "terraform_engine.py")
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")

PROVIDERS = ('terraform {\n  required_providers {\n    google = {\n      source  = "hashicorp/google"\n'
             '      version = "6.35.0"\n    }\n  }\n}\n\nvariable "project_id" {\n  type = string\n}\n\n'
             'variable "region" {\n  type = string\n}\n')


def _function(path: str, name: str) -> ast.FunctionDef:
    return next(n for n in ast.walk(ast.parse(open(path).read())) if isinstance(n, ast.FunctionDef) and n.name == name)


def _code_strings(fn: ast.FunctionDef) -> set:
    """Every string constant the function's CODE uses (its docstring excluded; comments are not in the AST)."""
    doc = ast.get_docstring(fn, clean=False)
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value != doc:
            out.add(n.value)
    return out


def _called_names(fn: ast.FunctionDef) -> set:
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            out.add(f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None)
    return out


def _local_names(fn: ast.FunctionDef) -> set:
    return {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}


@pytest.fixture(scope="module")
def tofu(tmp_path_factory):
    """The production /validate column (tofu 1.9.0 + google 6.35.0 mirror), run like the eval harness's V1b."""
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    from stackvend_eval.tofu_runner import TofuRunner
    from stackvend_eval.validate_client import validate_tree_raw
    runner = TofuRunner(tmp_path_factory.mktemp("tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not runner.mirror_ready:
        pytest.skip(f"production mirror not verified: {runner.mirror_manifest['status']}")
    counter = {"n": 0}

    def validate(tree):
        counter["n"] += 1
        out = validate_tree_raw(runner, tree, label=f"t{counter['n']}", engine_version="1.9.0", providers={})
        assert out["status"] in ("PASS", "FAIL"), out
        return [map_raw_diagnostic(raw, tree)[0] for raw in out["diagnostics"] if raw.get("severity") == "error"]
    return validate


# ================================================================================================ B1 HB-01 (HS-02)
def test_b1_tombstone_hb01_prune_and_invoker_synthesis_are_gone():
    # FD-55 W5 (register FD55-W5): HB-01 itself is deleted, with its prune / invoker synthesis already gone (S2-B B1)
    assert not hasattr(te, "reconcile_iac_reference_graph")
    assert not hasattr(te, "_hcl2_depends_on") and not hasattr(te, "_dep_base")


def _hb04_single(files):
    """FD-55 W5: the former HB-01 entry, now the generation entry point HB-04 on a single-service tree."""
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="", archetype="cloudrun",
                                            llm_iac_paths=[CUSTOM])


@pytest.mark.parametrize("deps", [
    "[google_pubsub_topic.t]",
    '[google_project_service.services["firestore.googleapis.com"]]',
    "[google_cloud_run_v2_service_iam_member.ghost, google_ghost.x]",
    "[module.compute]",
])
def test_b1_depends_on_is_byte_identical_declared_or_not(deps):
    custom = ('resource "google_project_service" "services" {\n  for_each = toset(["firestore.googleapis.com"])\n'
              '  service  = each.value\n}\n\nresource "google_pubsub_topic" "t" {\n  name = "t"\n}\n\n'
              f'resource "google_pubsub_subscription" "s" {{\n  topic      = google_pubsub_topic.t.id\n'
              f'  depends_on = {deps}\n}}\n')
    files = {W + "main.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n', CUSTOM: custom}
    _hb04_single(files)
    assert files[CUSTOM] == custom


def test_b1_undeclared_depends_on_entry_is_reported_by_v1b(tofu):
    custom = ('resource "google_pubsub_topic" "t" {\n  name = "t"\n  depends_on = [\n'
              '    google_cloud_run_v2_service_iam_member.invoker\n  ]\n}\n')
    files = {W + "main.tf": PROVIDERS, CUSTOM: custom}
    _hb04_single(files)
    assert files[CUSTOM] == custom                       # kept, nothing synthesized
    diags = tofu(files)
    assert [(d.code, d.symbol) for d in diags] == [
        ("TF.REFERENCE_TO_UNDECLARED_RESOURCE", "google_cloud_run_v2_service_iam_member.invoker")]


# ------------------------------------------------------------------------------------------------ validator ctx
def _ctx(files, *, llm=None, vendored=(), draft=None, assembly=None, extras=None):
    from developer_agent.validators import ValidationContext
    from shared.artifact_ownership import Ownership
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


SWEEP_FREE_MAIN = PROVIDERS   # no compute module, no apps/: the lane-owned sweeps have nothing to do


# ================================================================================================ B2 HC-14 (HS-11)


# ================================================================================================ B3 HC-06 / HA-17 / HC-17


# ================================================================================================ B4 HC-05 rest (HS-19b)
SECRET = ('resource "google_secret_manager_secret" "api_key" {\n  secret_id = "api-key"\n  replication {\n'
          '    auto {}\n  }\n}\n')


def _golden_module(name):
    root = os.path.join(REPO_ROOT, "infra", "modules", name)
    return {f"infra/modules/{name}/{f}": open(os.path.join(root, f)).read()
            for f in sorted(os.listdir(root)) if f.endswith(".tf")}


def test_b4_platform_owned_binding_is_removable_by_the_ai():
    from developer_agent.repair_loop import REMOVAL_CODES
    assert "POLICY.PLATFORM_OWNED_BINDING" in REMOVAL_CODES


def test_b4_literal_secret_id_of_a_declared_secret_is_reported_exactly():
    from developer_agent.validators.step1 import IamLiteralSecretIdValidator

    def member(name, sid):
        return (f'resource "google_secret_manager_secret_iam_member" "{name}" {{\n  secret_id = {sid}\n'
                '  role      = "roles/secretmanager.secretAccessor"\n  member    = "user:a@b.com"\n}\n')
    custom = (SECRET + member("lit", '"api-key"') + member("ref", "google_secret_manager_secret.api_key.secret_id")
              + member("label_only", '"api_key"') + member("undeclared", '"elsewhere"')
              + member("path", '"projects/p/secrets/api-key"'))
    files = {W + "main.tf": SWEEP_FREE_MAIN, CUSTOM: custom}
    got = IamLiteralSecretIdValidator().validate(_ctx(files, llm={CUSTOM}))
    assert [(d.code, d.block_address) for d in got] == [
        ("IAC.IAM_LITERAL_SECRET_ID", "google_secret_manager_secret_iam_member.lit")]
    assert "google_secret_manager_secret.api_key.secret_id" in got[0].hint
    # a vendored/platform file is not judged
    assert IamLiteralSecretIdValidator().validate(_ctx(files, llm=set())) == []


def test_b4_literal_secret_id_with_depends_on_the_secret_is_not_reported():
    """bcd RT F2: `depends_on = [google_secret_manager_secret.api_key]` orders the grant after the secret, so the
    literal id is race-free and not reported; depends_on on something else is still reported (exact membership)."""
    from developer_agent.validators.step1 import IamLiteralSecretIdValidator

    def member(name, deps):
        return (f'resource "google_secret_manager_secret_iam_member" "{name}" {{\n  secret_id = "api-key"\n'
                '  role      = "roles/secretmanager.secretAccessor"\n  member    = "user:a@b.com"\n'
                f'  depends_on = [{deps}]\n}}\n')
    custom = (SECRET + member("ordered", "google_secret_manager_secret.api_key")
              + member("ordered_id", "google_secret_manager_secret.api_key.id")
              + member("other", "google_secret_manager_secret.api_key_two"))
    got = IamLiteralSecretIdValidator().validate(_ctx({W + "main.tf": SWEEP_FREE_MAIN, CUSTOM: custom}, llm={CUSTOM}))
    assert [d.block_address for d in got] == ["google_secret_manager_secret_iam_member.other"]


def test_b4_undeclared_foundation_type_reference_gets_the_foundation_hint():
    from developer_agent.repair_loop import Router
    from developer_agent.validators import policy_tables as T
    from shared.diagnostics import AssemblyRecord, Diagnostic

    class Asm:
        record = AssemblyRecord()
        tree = {}
    r = object.__new__(Router)
    r.asm = Asm()

    def d(symbol, code="TF.REFERENCE_TO_UNDECLARED_RESOURCE"):
        return Diagnostic(tool="tofu", code=code, severity="error", file=CUSTOM, symbol=symbol, message="m",
                          hint="engine hint", source="precommit")
    assert r._hint(d("google_firestore_database.db")) == T.HINT_PLATFORM_OWNED_REFERENCE
    # step2-bcd merge: main's R3c branch (PLATFORM_OWNED types -> JSON action) runs first, so S2-B's hint is the one
    # for the remaining foundation-declared types (PLATFORM_OWNED_IF_DEFAULT, e.g. the Firestore database).
    import json
    from developer_agent.repair_loop import PLATFORM_OWNED_REFERENCE_ACTION
    for sym in ("google_project_service.run", "google_artifact_registry_repository.r"):
        if sym.split(".", 1)[0] in T.PLATFORM_OWNED_TYPES:
            assert json.loads(r._hint(d(sym))) == {"reference": sym, "action": PLATFORM_OWNED_REFERENCE_ACTION}
        else:
            assert r._hint(d(sym)) == T.HINT_PLATFORM_OWNED_REFERENCE
    assert r._hint(d("google_pubsub_topic.t")) == "engine hint"                    # not a foundation type
    assert r._hint(d("google_firestore_database.db", "TF.UNSUPPORTED_ATTRIBUTE")) == "engine hint"


@pytest.mark.parametrize("expr,attr,want", [
    ("module.compute.service_url", ".service_url", "module.compute"),
    ('module.svc["a"].iap_client_id', ".iap_client_id", "module.svc"),
    ("google_pubsub_topic.t[0].nope", ".nope", "google_pubsub_topic.t"),
    ("data.google_project.p.nope", ".nope", "data.google_project.p"),
    ("var.cfg.nope", ".nope", None),
    ('"${local.x}".nope', ".nope", None),
])
def test_b4_attribute_step_range_names_its_object(expr, attr, want):
    text = f'output "o" {{\n  value = {expr}\n}}\n'
    end = text.index(expr) + len(expr)
    start = end - len(attr)
    raw = {"severity": "error", "summary": "Unsupported attribute", "detail": "d",
           "range": {"filename": CUSTOM, "start": {"line": 2, "column": 1, "byte": len(text[:start].encode())},
                     "end": {"line": 2, "column": 1, "byte": len(text[:end].encode())}}}
    assert map_raw_diagnostic(raw, {CUSTOM: text})[0].symbol == want


# ================================================================================================ B6 HC-04 -> V2e (HS-31a, HS-62)

VM = ('resource "google_compute_instance" "{name}" {{\n  name         = "{name}"\n  machine_type = "e2-small"\n'
      '  zone         = "us-central1-a"\n{meta}  boot_disk {{\n    initialize_params {{\n'
      '      image = "debian-cloud/debian-12"\n    }}\n  }}\n  network_interface {{\n    network = "vpc"\n{ac}  }}\n}}\n')


def _vm(name, meta="", ac=""):
    return VM.format(name=name, meta=meta, ac=ac)


def _bucket(name, ubla_line):
    return f'resource "google_storage_bucket" "{name}" {{\n  name     = "{name}"\n  location = "US"\n{ubla_line}}}\n'


V2E_CASES = [
    # (block text, expected constraint or None)
    (_vm("plain"), None),
    (_vm("ac_empty", ac="    access_config {}\n"), "constraints/compute.vmExternalIpAccess"),
    (_vm("ac_nat", ac='    access_config {\n      nat_ip = "1.2.3.4"\n    }\n'), "constraints/compute.vmExternalIpAccess"),
    (_vm("login_true", meta='  metadata = {\n    enable-oslogin = "TRUE"\n  }\n'), None),
    (_vm("login_FALSE", meta='  metadata = {\n    enable-oslogin = "FALSE"\n  }\n'), "constraints/compute.requireOsLogin"),
    (_vm("login_false", meta='  metadata = {\n    enable-oslogin = "false"\n  }\n'), "constraints/compute.requireOsLogin"),
    (_vm("login_bool", meta='  metadata = {\n    enable-oslogin = false\n  }\n'), "constraints/compute.requireOsLogin"),
    (_vm("login_other", meta='  metadata = {\n    enable-oslogin = "No"\n  }\n'), None),
    (_vm("login_expr", meta='  metadata = merge(var.m, { enable-oslogin = "FALSE" })\n'), None),
    (_bucket("ubla_true", "  uniform_bucket_level_access = true\n"), None),
    (_bucket("ubla_str_true", '  uniform_bucket_level_access = "true"\n'), None),
    (_bucket("ubla_absent", ""), "constraints/storage.uniformBucketLevelAccess"),
    (_bucket("ubla_false", "  uniform_bucket_level_access = false\n"), "constraints/storage.uniformBucketLevelAccess"),
    (_bucket("ubla_var", "  uniform_bucket_level_access = var.ubla\n"), "constraints/storage.uniformBucketLevelAccess"),
]


def test_b6_golden_modules_have_no_finding_except_the_parameterized_bucket():
    """The golden corpus under the exact rules. V2e only judges LLM root files, so golden modules are never reported;
    this pins what the rules would say about them: the bastion has no access_config, and the only shape is
    storage-bucket's `uniform_bucket_level_access = var.uniform_bucket_level_access` (default true), which the RT F9
    rule counts as not provably compliant (non-literal)."""
    import glob
    from developer_agent.assembly import index_blocks
    from developer_agent.validators.step1 import org_constraint_findings
    found = []
    paths = sorted(glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True))
    assert len(paths) >= 80
    for p in paths:
        blocks = index_blocks(open(p).read())
        assert blocks is not None, p
        found += [(os.path.relpath(p, REPO_ROOT), b.key, c) for b, c, _ in org_constraint_findings(blocks)]
    assert found == [("infra/modules/storage-bucket/main.tf", "google_storage_bucket.bucket",
                      "constraints/storage.uniformBucketLevelAccess")]
    bastion = [p for p in paths if "/compute-gce-bastion/" in p]
    assert bastion and not any(org_constraint_findings(index_blocks(open(p).read())) for p in bastion)


def _default_mode(validator_id):
    from developer_agent.validators.step1 import build_step1_stack
    return build_step1_stack(validate_client=None, verifier_factory=None).mode_of(validator_id)


def test_b6_v2e_is_blocking_after_the_fp_review():
    """G-B FP review (GB1, 27 replay trees): V2e reported 0 findings, so 0 false positives; the golden corpus is not
    judged (LLM root files only). Flipped to blocking in its own commit (plan §3.2 B6)."""
    assert _default_mode("V2e") == "blocking"
    assert _default_mode("V2i") == "blocking"


def test_b6_platform_files_are_not_judged():
    from developer_agent.validators.step1 import OrgConstraintValidator
    files = {W + "main.tf": SWEEP_FREE_MAIN, CUSTOM: _bucket("b", "")}
    assert OrgConstraintValidator().validate(_ctx(files, llm=set())) == []


VM_IP = "constraints/compute.vmExternalIpAccess"
TEMPLATE_TYPES = ["google_compute_instance_template", "google_compute_region_instance_template"]
TEMPLATE = ('resource "{rtype}" "{name}" {{\n  name_prefix  = "{name}-"\n  machine_type = "e2-small"\n{meta}'
            '  disk {{\n    source_image = "debian-cloud/debian-12"\n  }}\n{nics}}}\n')
NIC = '  network_interface {{\n    network = "vpc"\n{ac}  }}\n'
AC_EMPTY, AC_NAT = "    access_config {}\n", '    access_config {\n      nat_ip = "1.2.3.4"\n    }\n'


def _template(rtype, *acs, meta=""):
    return TEMPLATE.format(rtype=rtype, name="t", meta=meta, nics="".join(NIC.format(ac=ac) for ac in acs))


def _v2e(text, llm=None):
    from developer_agent.validators.step1 import OrgConstraintValidator
    return OrgConstraintValidator().validate(_ctx({CUSTOM: text}, llm=llm))


@pytest.mark.parametrize("rtype", TEMPLATE_TYPES)
@pytest.mark.parametrize("acs", [(AC_EMPTY,), (AC_NAT,), ("", AC_EMPTY), (AC_EMPTY, AC_NAT)],
                         ids=["empty", "nat_ip", "second_nic", "both_nics_one_finding"])
def test_b6_v2e_refuses_an_external_ip_on_an_instance_template(rtype, acs):
    """VM-EXTERNAL-IP-FALSE-CONFLICT F2-1: a template stamps the external IP onto every VM made from it."""
    found = _v2e(_template(rtype, *acs))
    assert [(d.code, d.detail, d.attribute_path, d.block_address) for d in found] == [
        ("POLICY.ORG_CONSTRAINT", VM_IP, "network_interface.access_config", f"{rtype}.t")]


@pytest.mark.parametrize("rtype", TEMPLATE_TYPES)
@pytest.mark.parametrize("acs", [("",), ("", "")], ids=["one_nic", "two_nics"])
def test_b6_v2e_passes_an_instance_template_with_no_external_ip(rtype, acs):
    """Invariant 1: a template without `access_config` gets no finding."""
    assert _v2e(_template(rtype, *acs)) == []


@pytest.mark.parametrize("rtype", TEMPLATE_TYPES)
def test_b6_v2e_template_rule_is_only_the_external_ip_rule(rtype):
    """The OS Login metadata rule was and stays about `google_compute_instance`."""
    assert _v2e(_template(rtype, "", meta='  metadata = {\n    enable-oslogin = "FALSE"\n  }\n')) == []


@pytest.mark.parametrize("text, want", [(_vm("v", ac=AC_EMPTY), [VM_IP]), (_vm("v"), []),
                                        (_vm("v", meta='  metadata = {\n    enable-oslogin = "FALSE"\n  }\n'),
                                         ["constraints/compute.requireOsLogin"])],
                         ids=["external_ip", "private", "os_login_off"])
def test_b6_v2e_keeps_its_decision_on_a_vm_instance(text, want):
    assert [d.detail for d in _v2e(text)] == want


def test_b6_platform_written_template_is_not_judged():
    assert _v2e(_template(TEMPLATE_TYPES[0], AC_EMPTY), llm=set()) == []


def test_b6_enforce_bucket_policy_only_is_an_unsupported_argument_on_google_6(tofu):
    custom = _bucket("legacy", "  enforce_bucket_policy_only = true\n")
    got = {d.code for d in tofu({W + "main.tf": SWEEP_FREE_MAIN, CUSTOM: custom})}
    assert got == {"TF.UNSUPPORTED_ARGUMENT"}, got


# ================================================================================================ B7 HC-07 (HS-22a)

TWO_CONNECTORS = ('resource "google_vpc_access_connector" "connector" {\n  name          = "conn-a"\n'
                  '  region        = var.region\n  ip_cidr_range = "10.8.0.0/28"\n  network       = "vpc"\n}\n'
                  'resource "google_vpc_access_connector" "serverless_connector" {\n  name          = "conn-b"\n'
                  '  region        = var.region\n  ip_cidr_range = "10.9.0.0/28"\n  network       = "vpc"\n}\n')
CONNECTOR_ERRORS = ["Error 409: Connector already exists", "overlaps with an existing range",
                    "Connector ID must follow the pattern ^[a-z][-a-z0-9]{0,23}[a-z0-9]$"]


# ================================================================================================ B8 HC-08 (HS-21a)


# ================================================================================================ B5 HC-02 (HS-31a)
BUDGET = ('resource "google_billing_budget" "finops_budget" {\n  billing_account = "000000-000000-000000"\n'
          '  display_name    = "b"\n  amount {\n    specified_amount {\n      units = "25"\n    }\n  }\n}\n')
BUDGET_OUTPUTS = ('output "budget_id" {\n  value = google_billing_budget.finops_budget.id\n}\n'
                  'output "budget_name" {\n  value = google_billing_budget.finops_budget.display_name\n}\n')
SPEND_ALERT = ('resource "google_monitoring_alert_policy" "spend_warning" {\n  display_name = "Monthly spend warning"\n'
               '  combiner     = "OR"\n  conditions {\n    display_name = "spend"\n    condition_threshold {\n'
               '      filter     = "metric.type=\\"serviceruntime.googleapis.com/api/request_count\\""\n'
               '      duration   = "60s"\n      comparison = "COMPARISON_GT"\n    }\n  }\n}\n')
TOPIC = 'resource "google_pubsub_topic" "stream" {\n  name = "stream"\n}\n'


def test_b5_removing_the_budget_and_its_outputs_is_an_accepted_repair():
    """RT F8: Step 1 code RT F5 scoped preservation to resource/data/module keys, so a candidate that removes the
    diagnosed budget AND the two outputs that reference it is not a PRESERVATION_VIOLATION."""
    from developer_agent.repair_loop import Assembled, RepairLoop, accept
    from shared.diagnostics import AssemblyRecord, Diagnostic, ValidationReport

    def rep(*diags):
        return ValidationReport(status="FAIL" if diags else "PASS", source="precommit", artifact_hash="h",
                                diagnostics=list(diags))
    d1 = {CUSTOM: BUDGET + BUDGET_OUTPUTS + SPEND_ALERT + TOPIC}
    diag = Diagnostic(tool="policy", code="POLICY.FORBIDDEN_RESOURCE_TYPE", severity="error", file=CUSTOM,
                      block_address="google_billing_budget.finops_budget", message="m", source="precommit")
    d2 = {CUSTOM: SPEND_ALERT + TOPIC}
    task = type("T", (), {"files_to_fix": {CUSTOM: d1[CUSTOM]}})()
    merged, why, removed = RepairLoop._merge(d1, [task], [{"envelope_ok": True, "files": d2}], rep(diag))
    assert why is None and removed == {"google_billing_budget.finops_budget"}
    asm1 = Assembled(tree=dict(d1), record=AssemblyRecord())
    assert accept(d1, merged, asm1, Assembled(tree=dict(merged), record=AssemblyRecord()), rep(diag), rep(),
                  removed, "x") == (True, None)


# ================================================================================================ B9 HC-09 + HA-14 call


# ================================================================================================ B11 HS-34a


# ================================================================================================ B10 V2b (HS-16)
def test_b9_duplicates_are_reported_by_v1b(tofu):
    files = {W + "main.tf": SWEEP_FREE_MAIN + 'data "google_client_config" "default" {}\n',
             CUSTOM: 'data "google_client_config" "default" {}\n'
                     'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'
                     'resource "google_pubsub_topic" "t" {\n  name = "u"\n}\n'}
    codes = {d.code for d in tofu(files)}   # FD-55 W4: no generation-time sweep runs before V1b any more
    assert codes == {"TF.DUPLICATE_DATA_CONFIGURATION", "TF.DUPLICATE_RESOURCE_CONFIGURATION"}, codes


def test_b10_variable_without_value_blocks_after_the_fp_review():
    """FP review (GB0 = step2a baseline, 27 trees): 2 report-only findings, both true positives -- 01-r1
    `variable "app_image"` (declared, no default, no tfvars value: `tofu plan -input=false` fails with "No value for
    required variable") and 01-r3 `variable "storage_bucket_name"` (only in terraform.tfvars.example, which OpenTofu
    does not load). Both runs were already CODE_DEFECT, so no class changes."""
    from developer_agent.validators.step1 import PLATFORM_SUPPLIED_VARIABLES, VariableWithoutValueValidator
    assert _default_mode("V2b") == "blocking"
    custom = ('variable "app_image" {\n  type = string\n}\nvariable "retention" {\n  default = 7\n}\n'
              'variable "region" {\n  type = string\n}\n')
    files = {W + "main.tf": SWEEP_FREE_MAIN, CUSTOM: custom, W + "terraform.tfvars": 'other = "x"\n'}
    got = VariableWithoutValueValidator().validate(_ctx(files, llm={CUSTOM}))
    assert [d.block_address for d in got] == ["variable.app_image"]          # defaults / platform-supplied pass
    assert "region" in PLATFORM_SUPPLIED_VARIABLES


# ================================================================================================ 3e (unreachable)

def test_b4_v1b_reports_the_former_hc05_triggers(tofu):
    files = {W + "main.tf": SWEEP_FREE_MAIN + 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n'
             '  project_id   = var.project_id\n  region       = var.region\n  service_name = "svc"\n'
             '  product_id   = "shop"\n  service_account_email = "a@b.iam.gserviceaccount.com"\n'
             '  container_image = "img"\n}\n',
             CUSTOM: ('output "url" {\n  value = module.compute.service_url\n}\n'
                      'output "db" {\n  value = google_firestore_database.db.name\n}\n')}
    files.update(_golden_module("compute-cloudrun"))
    diags = tofu(files)
    got = sorted((d.code, d.symbol) for d in diags if d.file == CUSTOM)
    assert got == [("TF.REFERENCE_TO_UNDECLARED_RESOURCE", "google_firestore_database.db"),
                   ("TF.UNSUPPORTED_ATTRIBUTE", "module.compute")], [(d.code, d.symbol, d.line, d.column, d.snippet)
                                                                     for d in diags]

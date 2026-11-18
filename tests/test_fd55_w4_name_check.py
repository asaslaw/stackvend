"""FD-55 W4 (register FD55-W4, owner 10-24): generation stops rewriting resource names and stops guessing
infrastructure. The name rewriters (HB-17 + HD-14 / HB-18 / HA-17, HB-23) are replaced by V2k IAC.NAME_INVALID, an
exact check of TEMPLATED names resolved from platform-known values only (validators/names.py); a literal name is the
provider's ValidateFunc at V1b (V2k-literal, blocking since FD55-W4-LIT, checks the one row the provider does not check
at validate). Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OG_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (REPO_ROOT, OG_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent.validators import names as N  # noqa: E402
from developer_agent.validators.base import ValidationContext  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402

W = "infra/workload/"
CUSTOM = W + "custom.tf"
PV = {"product_id": "acme-payments", "region": "us-central1", "project_id": "acme-payments-prj"}


def _ctx(files, owner=None):
    own = owner or {CUSTOM: Ownership.LLM_AUTHORED}

    def ownership(p):
        if p in own:
            return own[p]
        if p in (W + "main.tf", W + "variables.tf", W + "terraform.tfvars"):
            return Ownership.PLATFORM_RENDERED
        return Ownership.USER_OWNED if p.endswith(("human.tf", "_override.tf")) else None
    return ValidationContext.build(files, ownership=ownership)


def _run(files, *, literals=False, values=PV, owner=None):
    return N.NameTemplateValidator(values if not literals else None, literals=literals).validate(_ctx(files, owner))


def _connector(name):
    return (f'resource "google_vpc_access_connector" "c" {{\n  name          = "{name}"\n  region        = var.region\n'
            f'  ip_cidr_range = var.connector_cidr\n  network       = "default"\n}}\n')


def _sa(account_id, extra=""):
    return f'{extra}resource "google_service_account" "s" {{\n  account_id = "{account_id}"\n}}\n'


# ------------------------------------------------------------------------------------------------ resolution
@pytest.mark.parametrize("raw,expect", [
    ("${var.product_id}-conn", "acme-payments-conn"),
    ("${var.product_id}-${var.region}", "acme-payments-us-central1"),
    ("${ var.product_id }-x", "acme-payments-x"),
    ("${local.p}-x", "acme-payments-svc-x"),
    ("${local.q}", "acme-payments-svc-us-central1"),
    ("plain", "plain"),
])
def test_resolve_template_exact(raw, expect):
    locals_ = {"p": "${var.product_id}-svc", "q": "${local.p}-${var.region}"}
    assert N.resolve_template(raw, PV, locals_) == expect


@pytest.mark.parametrize("raw", [
    "${var.connector_name}-x",                 # an AI variable: not a platform value
    "${format(\"%s-x\", var.product_id)}",     # a function call
    "${var.product_id}-${count.index}",        # count.index
    "${module.foundation.workload_sa_email}",  # a resource / module attribute
    "${var.tags[0]}",                          # an index of a reference
    "${var.product_id}%{ if true }-x%{ endif }",   # a template directive
    "$${var.product_id}",                      # an escaped interpolation
    "${local.loop}",                           # a cycle
    "${local.missing}",
])
def test_resolve_template_unknown_part_is_not_resolved(raw):
    assert N.resolve_template(raw, PV, {"loop": "${local.loop}"}) is None


# ------------------------------------------------------------------------------------------------ V2k (blocking)
def test_templated_connector_name_over_the_limit_is_an_exact_finding():
    (d,) = _run({CUSTOM: _connector("${var.product_id}-serverless-connector")})
    assert (d.code, d.severity, d.file, d.attribute_path) == ("IAC.NAME_INVALID", "error", CUSTOM, "name")
    assert "acme-payments-serverless-connector" in d.message and d.block_address == "google_vpc_access_connector.c"


def test_templated_account_id_through_a_local_over_30_is_a_finding():
    extra = 'locals {\n  prefix = "${var.product_id}-svc"\n}\n'
    (d,) = _run({CUSTOM: _sa("${local.prefix}-dispatcher-worker", extra)})
    assert d.code == "IAC.NAME_INVALID" and "acme-payments-svc-dispatcher-worker" in d.message


def test_rendered_tfvars_string_values_are_platform_known():
    files = {CUSTOM: _connector("${var.connector_prefix}-vpc-connector"),
             W + "terraform.tfvars": 'connector_prefix = "acme-payments-long"\n'}
    (d,) = _run(files)
    assert "acme-payments-long-vpc-connector" in d.message


@pytest.mark.parametrize("own", [None, Ownership.LLM_AUTHORED, Ownership.USER_OWNED])
def test_dnh_tfvars_not_classified_platform_rendered_is_no_value_source(own):
    """Fable RT F3: only a tfvars the router classifies exactly PLATFORM_RENDERED supplies values; an unattributable
    (None), AI-authored or pre-existing copy does not, so the template has an unknown part and is not judged."""
    files = {CUSTOM: _connector("${var.connector_prefix}-vpc-connector"),
             W + "terraform.tfvars": 'connector_prefix = "acme-payments-long"\n'}
    assert _run(files, owner={CUSTOM: Ownership.LLM_AUTHORED, W + "terraform.tfvars": own}) == []


# ------------------------------------------------------------------------------------------------ DNH negatives
def test_dnh_resolved_valid_name_has_no_finding_and_the_file_is_unchanged():
    text = _connector("${var.product_id}-conn") + _sa("${var.product_id}-runner")
    files = {CUSTOM: text}
    assert _run(files) == []
    assert files[CUSTOM] == text   # a validator never writes


@pytest.mark.parametrize("name", ["${var.connector_name}", "${var.product_id}-${count.index}-connector-for-all",
                                  "${format(\"%s-connector-for-everything\", var.product_id)}"])
def test_dnh_unknown_part_is_not_judged(name):
    assert _run({CUSTOM: _connector(name)}) == []


def test_dnh_unknown_platform_value_is_not_judged():
    assert _run({CUSTOM: _connector("${var.region}-serverless-connector-x")},
                values={"product_id": "acme-payments"}) == []


def test_dnh_user_owned_and_platform_files_are_not_judged():
    bad = _connector("${var.product_id}-serverless-connector")
    assert _run({W + "human.tf": bad, W + "main.tf": bad}) == []


def test_literal_names_are_left_to_the_provider_at_v1b():
    """A literal account_id over 30 characters is the provider's ValidateFunc at `tofu validate` (V1b): V2k and
    V2k-literal add nothing for it (no duplicate diagnostic)."""
    files = {CUSTOM: _sa("operator-owned-service-account-x1")}
    assert _run(files) == [] and _run(files, literals=True) == []


# ------------------------------------------------------------------------------------------------ V2k-literal
def test_literal_connector_name_the_provider_does_not_check_is_reported():
    (d,) = _run({CUSTOM: _connector("x" * 26)}, literals=True)
    assert (d.code, d.severity, d.attribute_path) == ("IAC.NAME_INVALID", "error", "name")
    assert _run({CUSTOM: _connector("vpc-conn")}, literals=True) == []
    assert _run({CUSTOM: _connector("x" * 26)}) == []   # V2k judges templates only


def test_stack_registers_v2k_and_v2k_literal_blocking():
    from developer_agent.validators.step1 import build_step1_stack
    stack = build_step1_stack(validate_client=None, verifier_factory=lambda: None, platform_values=PV)
    assert stack.mode_of("V2k") == "blocking" and stack.mode_of("V2k-literal") == "blocking"   # FD55-W4-LIT


# ------------------------------------------------------------------------------------------------ rules = provider
def test_rules_cover_the_provider_validatefunc_rows_and_the_connector():
    assert N.NAME_RULES[("google_vpc_access_connector", "name")].provider_validates_literal is False
    assert all(r.provider_validates_literal for k, r in N.NAME_RULES.items()
               if k != ("google_vpc_access_connector", "name"))
    sa = N.NAME_RULES[("google_service_account", "account_id")]
    assert N.rule_violations(sa, "abcdef") == [] and N.rule_violations(sa, "x" * 31)
    assert N.rule_violations(sa, "abcde") and N.rule_violations(sa, "ab-cd-")
    bucket = N.NAME_RULES[("google_storage_bucket", "name")]
    assert N.rule_violations(bucket, "a" * 63 + ".bb") == [] and N.rule_violations(bucket, "a" * 64 + ".bb")
    assert N.rule_violations(bucket, "goog-bucket")


# ------------------------------------------------------------------------------------------------ removals
@pytest.mark.parametrize("name", [
    "sanitize_gcp_naming_invariants", "generate_rfc1123_variable_default", "sanitize_self_referential_hcl_blocks",
    "inject_cloud_run_timeouts", "sanitize_duplicate_gke_clusters", "sanitize_multiservice_compute_coverage",
    "inject_gke_workload_identity_bindings", "run_ast_preflight_check", "preflight_validate_terraform",
    "self_correct_hcl", "_self_correct_workload_hcl", "resolve_platform_files", "module_scope_locals",
    "validate_hcl_syntax_tree", "sanitize_hcl_locals_invariants", "heal_orphaned_root_resource_syntax",
])
def test_generation_time_hcl_rewriters_are_deleted(name):
    from developer_agent import preflight_validator as pv
    from developer_agent import handler as h
    assert not hasattr(pv, name) and not hasattr(h, name)


def test_hb23_account_id_cure_is_deleted():
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    assert not hasattr(SynthesisVerifierAgent, "cure_service_account_ids")
    long_sa = _sa("${var.product_id}-cr-dispatcher-prefix-worker")
    cured, _, _ = SynthesisVerifierAgent(product_id="acme").verify_and_cure({CUSTOM: long_sa}, product_id="acme")
    assert cured[CUSTOM] == long_sa


def test_deploy_platform_values_match_the_deploy_rule():
    from developer_agent.handler import deploy_platform_values
    assert deploy_platform_values("Acme_Pay", "europe-west1", "acme-prj") == {
        "product_id": "acme-pay", "region": "europe-west1", "project_id": "acme-prj"}
    assert deploy_platform_values("acme", None, "") == {"product_id": "acme"}

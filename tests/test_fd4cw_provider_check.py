"""FD-4CW (owner row FD-4CW-Q2, 10-27): rough edges of the pre-commit provider check V2d
(developer_agent/validators/step1.py ProviderAvailabilityValidator) next to V2j (validators/content_policy.py).

* Q2: V2d accepts OpenTofu's built-in `terraform` provider (`terraform_data`, a `terraform` required_providers key)
  without adding it to the installable provider allow-list (mcp-servers/terraform/provider_allowlist.py stays the
  four providers); `data "terraform_remote_state"` stays refused by V2j (POLICY.REMOTE_STATE_FORBIDDEN).
* Q1: V2d leaves `resource`/`data` blocks to V2j, so an unavailable-provider block gets exactly one diagnostic.
* Message: `provider = null.x` names provider "null", not python-hcl2's rendering "None".
Each change has a Do No Harm negative (valid google roots unaffected)."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.assembly import index_blocks  # noqa: E402
from developer_agent.validators import ValidationContext, ValidatorUnavailable  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.content_policy import ContentPolicyValidator  # noqa: E402
from developer_agent.validators.step1 import (ProviderAvailabilityValidator, block_provider,  # noqa: E402
                                              build_step1_stack, provider_local_names)
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import artifact_hash  # noqa: E402

W = "infra/workload/"
AVAILABLE = ["google", "google-beta", "kubernetes", "random"]   # validate_service.VALIDATE_PROVIDERS

VALID_GOOGLE = (
    'terraform {\n  required_providers {\n    google = {\n      source = "hashicorp/google"\n    }\n'
    '    random = {\n      source = "hashicorp/random"\n    }\n  }\n}\n'
    'provider "google" {\n  project = var.project_id\n  region  = var.region\n}\n'
    'provider "google-beta" {\n  alias = "beta"\n}\n'
    'resource "google_storage_bucket" "b" {\n  name     = "b"\n  location = var.region\n}\n'
    'resource "google_pubsub_topic" "t" {\n  provider = google-beta.beta\n  name     = "t"\n}\n'
    'data "google_project" "p" {}\nresource "random_id" "r" {\n  byte_length = 4\n}\n')


def _ctx(text, extras=None):
    files = {W + "custom.tf": text}
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED,
                                   extras={"available_providers": AVAILABLE} if extras is None else extras,
                                   trace_id="t")


def _v2d(text):
    ctx = _ctx(text)
    before = artifact_hash(dict(ctx.files))
    got = ProviderAvailabilityValidator().validate(ctx)
    assert artifact_hash(dict(ctx.files)) == before   # validators never write
    return got


def _stack_blocking(text):
    """V2d and V2j in the builder's order and modes; the blocking diagnostics a repair turn would get."""
    st = ValidatorStack()
    st.register(ProviderAvailabilityValidator(), "blocking")
    st.register(ContentPolicyValidator(), "blocking")
    return st.run(_ctx(text)).diagnostics


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_valid_google_root_is_unaffected():
    assert _v2d(VALID_GOOGLE) == []
    assert _stack_blocking(VALID_GOOGLE) == []


# ------------------------------------------------------------------------------------------------ Q2
def test_terraform_data_is_no_longer_flagged_by_v2d():
    tf = 'resource "terraform_data" "marker" {\n  input = "x"\n}\n'
    assert _v2d(tf) == []
    assert _stack_blocking(tf) == []


def test_builtin_terraform_required_providers_key_is_accepted():
    tf = ('terraform {\n  required_providers {\n    terraform = {\n      source = "terraform.io/builtin/terraform"\n'
          '    }\n  }\n}\n')
    assert _v2d(tf) == []


def test_terraform_remote_state_is_still_refused_once_by_v2j():
    tf = 'data "terraform_remote_state" "o" {\n  backend = "gcs"\n}\n'
    assert _v2d(tf) == []
    assert [d.code for d in _stack_blocking(tf)] == ["POLICY.REMOTE_STATE_FORBIDDEN"]


def test_installable_allow_list_stays_the_four_providers():
    # `terraform` is built in: it is accepted by V2d, never added to what `tofu init` may install (AQ-6)
    src = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "provider_allowlist.py")).read()
    table = next(ast.literal_eval(n.value) for n in ast.parse(src).body if isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") == "PLATFORM_PROVIDER_SOURCES" for t in n.targets))
    assert set(table) == set(AVAILABLE)


def test_v2d_hint_lists_only_the_installable_providers():
    got = _v2d('provider "aws" {}\n')
    assert [d.message for d in got] == ['provider "aws" is not available to the platform']
    assert "google, google-beta, kubernetes, random." in got[0].hint and "terraform" not in got[0].hint


# ------------------------------------------------------------------------------------------------ Q1
@pytest.mark.parametrize("tf,address", [
    ('resource "null_resource" "n" {}\n', "null_resource.n"),
    ('data "archive_file" "z" {\n  type = "zip"\n}\n', "data.archive_file.z"),
    ('resource "local_file" "f" {\n  filename = "x"\n}\n', "local_file.f"),
])
def test_unavailable_provider_block_gets_exactly_one_diagnostic(tf, address):
    got = _stack_blocking(tf)
    assert [(d.code, d.block_address) for d in got] == [("POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE", address)]


def test_v2d_still_reports_unavailable_provider_blocks_and_required_providers_keys():
    tf = ('terraform {\n  required_providers {\n    archive = {\n      source = "hashicorp/archive"\n    }\n  }\n}\n'
          'provider "null" {}\n')
    got = _v2d(tf)
    assert sorted(d.message for d in got) == ['provider "archive" is not available to the platform',
                                              'provider "null" is not available to the platform']
    assert all(d.code == "POLICY.PROVIDER_NOT_AVAILABLE" for d in got)


def test_v2d_without_a_provider_set_is_never_a_pass():
    with pytest.raises(ValidatorUnavailable):
        ProviderAvailabilityValidator().validate(_ctx(VALID_GOOGLE, extras={}))


def test_builder_registers_both_blocking():
    st = build_step1_stack(validate_client=None, verifier_factory=None)
    assert st.mode_of("V2d") == "blocking" and st.mode_of("V2j") == "blocking"


@pytest.mark.parametrize("modes", [{"V2j": "report_only"}, {"V2j": "off"}, {"V2j": "off", "V2d": "report_only"}])
def test_builder_refuses_v2j_weaker_than_v2d(modes):
    with pytest.raises(ValueError, match="V2j"):
        build_step1_stack(validate_client=None, verifier_factory=None, modes=modes)


@pytest.mark.parametrize("modes", [{"V2d": "off"}, {"V2d": "report_only", "V2j": "report_only"},
                                   {"V2d": "off", "V2j": "off"}])
def test_builder_accepts_v2j_at_least_as_strict_as_v2d(modes):
    build_step1_stack(validate_client=None, verifier_factory=None, modes=modes)


# ------------------------------------------------------------------------------------------------ message
def test_null_alias_reference_names_provider_null():
    tf = 'resource "google_storage_bucket" "b" {\n  provider = null.x\n  name     = "b"\n}\n'
    got = _stack_blocking(tf)
    assert len(got) == 1 and '"null"' in got[0].message and "None" not in got[0].message
    blocks = index_blocks(tf)
    assert set(provider_local_names(blocks)) == {"null"}


def test_block_provider_keyword_rendering_and_plain_names():
    assert block_provider("resource", ("google_x", "y"), {"provider": "${None.a}"}) == "null"
    assert block_provider("resource", ("google_x", "y"), {"provider": "${google.west}"}) == "google"
    assert block_provider("resource", ("google_storage_bucket", "b"), {}) == "google"
    assert block_provider("provider", ("google",), {}) is None


def test_v2j_reexports_the_shared_helper():
    from developer_agent.validators import content_policy
    assert content_policy.block_provider is block_provider

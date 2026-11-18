"""TI-5-R2 P5 (owner 10-25, register FOLLOWUPS-1025): `networking-vpc.psa_address` joins the IPAM allocation-attribute
table (developer_agent/platform_facts.ALLOCATION_ATTRIBUTES), so a literal there is POLICY.CIDR_LITERAL (V2h) on the
classic path, with a hint naming the exact platform expressions. It is an optional attribute: a network call without
it (or with null) asks for its subnet only, exactly as before. Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

import hcl2  # noqa: E402

from test_lane11_platform_facts import APP, SUBNET_LITERAL, W, _generate, _run  # noqa: E402
from developer_agent import platform_facts as PF  # noqa: E402
from developer_agent.validators.platform_facts import CODE_LITERAL, CODE_MISMATCH, CODE_NOT_ALLOCATED  # noqa: E402
from shared import iac_intent as II  # noqa: E402
from shared.diagnostics import ErrorClass, RepairBudgetExhausted  # noqa: E402

PSA_FACTS = PF.NetworkFacts(product_id="shop", region="us-central1", subnet_cidr="10.100.1.0/24",
                            connector_cidr="10.100.0.0/28", psa_cidr="10.100.16.0/20")
EXPR = 'psa_address = cidrhost(var.psa_cidr, 0) and psa_prefix_length = tonumber(element(split("/", var.psa_cidr), 1))'


def net(psa=None, subnet="var.subnet_cidr", prefix=None):
    lines = ['module "network" {', '  source              = "../modules/networking-vpc"',
             "  project_id          = var.project_id", f"  primary_subnet_cidr = {subnet}"]
    if psa is not None:
        lines.append(f"  psa_address         = {psa}")
    if prefix is not None:
        lines.append(f"  psa_prefix_length   = {prefix}")
    return "\n".join(lines) + "\n}\n"


FIXED = net("cidrhost(var.psa_cidr, 0)", prefix='tonumber(element(split("/", var.psa_cidr), 1))')


# ------------------------------------------------------------------------------------------------ the table
def test_p5_table_row_and_optional_attribute():
    assert PF.ALLOCATION_ATTRIBUTES[("module", PF.NETWORK_MODULE_DIR)] == {
        "primary_subnet_cidr": PF.PURPOSE_SUBNET, "psa_address": PF.PURPOSE_PSA}
    assert PF.OPTIONAL_ALLOCATION_ATTRIBUTES == {("module", PF.NETWORK_MODULE_DIR): frozenset({"psa_address"})}
    # the hint's expressions are exactly the typed-intent render's (one source of truth for the value form)
    expr, companions = PF.ADDRESS_ATTRIBUTE_VALUES[("module", PF.NETWORK_MODULE_DIR)]["psa_address"]
    assert "${" + expr + "}" == II._PLATFORM_NETWORK_PSA_ARGS["psa_address"]
    assert {a: "${" + e + "}" for a, e in companions} == {
        "psa_prefix_length": II._PLATFORM_NETWORK_PSA_ARGS["psa_prefix_length"]}
    # every other row is unchanged
    assert PF.ALLOCATION_ATTRIBUTES[("resource", "google_compute_subnetwork")] == {"ip_cidr_range": PF.PURPOSE_SUBNET}
    assert PF.ALLOCATION_ATTRIBUTES[("resource", "google_vpc_access_connector")] == {
        "ip_cidr_range": PF.PURPOSE_CONNECTOR}


# ------------------------------------------------------------------------------------------------ purposes
def test_p5_dnh_a_network_call_without_psa_address_asks_for_its_subnet_only():
    assert PF.required_network_purposes({W + "n.tf": net()}) == {PF.PURPOSE_SUBNET}
    assert PF.required_network_purposes({W + "n.tf": net("null")}) == {PF.PURPOSE_SUBNET}


@pytest.mark.parametrize("psa", ['"10.100.16.0"', "cidrhost(var.psa_cidr, 0)", "var.my_psa"])
def test_p5_a_set_psa_address_needs_the_psa_range(psa):
    assert PF.required_network_purposes({W + "n.tf": net(psa)}) == {PF.PURPOSE_SUBNET, PF.PURPOSE_PSA}


def test_p5_dnh_existing_network_detection_is_unchanged():
    assert PF.has_existing_network({W + "n.tf": net()}) is True
    assert PF.has_existing_network({W + "n.tf": 'module "x" {\n  source = "../modules/storage-bucket"\n}\n'}) is False


# ------------------------------------------------------------------------------------------------ V2h
def test_p5_literal_psa_address_is_cidr_literal_with_the_exact_expressions():
    [d] = _run({W + "n.tf": net('"10.100.16.0"')}, facts=PSA_FACTS)
    assert d.code == CODE_LITERAL and d.attribute_path == "psa_address" and d.block_address == "module.network"
    assert d.severity == "error" and d.error_class is ErrorClass.CODE_DEFECT
    assert d.hint.startswith("Set " + EXPR + " . ")
    assert "10.100.16.0/20" in d.hint and 'variable "psa_cidr"' in d.hint
    assert "var.psa_cidr ." not in d.hint            # never the whole range into an address input


def test_p5_literal_through_the_ais_own_variable_is_found_too():
    files = {W + "n.tf": net("var.my_psa"),
             W + "v.tf": 'variable "my_psa" {\n  type    = string\n  default = "10.100.16.0"\n}\n'}
    [d] = _run(files, facts=PSA_FACTS)
    assert d.code == CODE_LITERAL and 'variable "my_psa"' in d.message
    assert d.hint.startswith("Set " + EXPR + " . ") and 'Delete variable "my_psa"' in d.hint


def test_rt_f2_the_whole_psa_range_in_the_address_input_is_a_mismatch_with_the_address_form():
    """RT 11-07 F2: psa_address = var.psa_cidr (the range, not its address) would only fail the module's own
    validation at plan; it is CIDR_FACT_MISMATCH with the exact expressions (exact equality)."""
    [d] = _run({W + "n.tf": net("var.psa_cidr")}, facts=PSA_FACTS)
    assert d.code == CODE_MISMATCH and d.attribute_path == "psa_address" and d.severity == "error"
    assert d.hint.startswith("Set " + EXPR + " . ") and "10.100.16.0/20" in d.hint
    # the platform's expressions pass; without a PSA allocation the platform declares no var.psa_cidr (V1b reports)
    assert _run({W + "n.tf": FIXED}, facts=PSA_FACTS) == []
    no_psa = PF.NetworkFacts(product_id="shop", region="us-central1", subnet_cidr="10.100.1.0/24")
    assert _run({W + "n.tf": net("var.psa_cidr")}, facts=no_psa) == []
    # an existing network only measures
    [w] = _run({W + "n.tf": net("var.psa_cidr")}, facts=PSA_FACTS, existing_network=True)
    assert w.code == CODE_MISMATCH and w.severity == "warning"
    # Do No Harm: a range input on exactly its fact is still fine
    assert _run({W + "n.tf": net()}, facts=PSA_FACTS) == []


def test_p5_psa_address_on_another_purposes_fact_is_a_mismatch_with_the_address_form():
    [d] = _run({W + "n.tf": net("var.subnet_cidr")}, facts=PSA_FACTS)
    assert d.code == CODE_MISMATCH and d.attribute_path == "psa_address"
    assert EXPR in d.hint and "var.subnet_cidr is the workload subnet range" in d.hint


def test_p5_negatives_no_finding():
    assert _run({W + "n.tf": FIXED}, facts=PSA_FACTS) == []
    assert _run({W + "n.tf": net()}, facts=PSA_FACTS) == []
    assert _run({W + "n.tf": net("null")}, facts=PSA_FACTS) == []
    # another variable is not judged here (a literal default behind it is: test above)
    assert _run({W + "n.tf": net("var.my_psa")}, facts=PSA_FACTS) == []
    # another module directory is not in the table
    other = net('"10.100.16.0"').replace("../modules/networking-vpc", "../modules/networking-vpc-extra")
    assert _run({W + "n.tf": other}, facts=PSA_FACTS) == []


def test_p5_no_psa_allocation_is_a_platform_defect_and_an_existing_network_only_measures():
    no_psa = PF.NetworkFacts(product_id="shop", region="us-central1", subnet_cidr="10.100.1.0/24")
    [d] = _run({W + "n.tf": net('"10.100.16.0"')}, facts=no_psa)
    assert d.code == CODE_NOT_ALLOCATED and d.error_class is ErrorClass.PLATFORM_DEFECT
    [w] = _run({W + "n.tf": net('"10.100.16.0"')}, facts=no_psa, existing_network=True)
    assert w.code == CODE_LITERAL and w.severity == "warning"


def test_p5_dnh_subnet_and_connector_hints_are_unchanged():
    [one] = _run({W + "network.tf": SUBNET_LITERAL}, facts=PSA_FACTS)
    assert one.hint.startswith("Set ip_cidr_range = var.subnet_cidr . ")
    [sub] = _run({W + "n.tf": net(subnet='"10.0.0.0/24"')}, facts=PSA_FACTS)
    assert sub.attribute_path == "primary_subnet_cidr" and sub.hint.startswith("Set primary_subnet_cidr = var.subnet_cidr . ")


# ------------------------------------------------------------------------------------------------ end to end
def test_p5_e2e_a_literal_psa_address_stops_typed_with_the_hint():
    provider = PF.MemoryFactsProvider()
    with pytest.raises(RepairBudgetExhausted) as ei:
        _generate(dict(APP, **{W + "network.tf": net('"10.100.16.0"')}), provider)
    assert ei.value.error_class is ErrorClass.CODE_DEFECT
    [d] = [x for x in ei.value.report.diagnostics if x.code == CODE_LITERAL]
    assert d.attribute_path == "psa_address" and EXPR in d.hint
    assert ("shop", PF.PURPOSE_PSA) in provider.ledger           # the range the hint names is allocated


def test_p5_e2e_the_platform_expressions_pass_and_the_psa_fact_is_rendered():
    provider = PF.MemoryFactsProvider()
    agent, files = _generate(dict(APP, **{W + "network.tf": FIXED}), provider)
    assert agent.last_validation_report.status == "PASS"
    assert files[W + "network.tf"] == FIXED                        # Do No Harm: the AI file is byte-identical
    tfvars = hcl2.loads(files[W + "terraform.tfvars"])
    assert tfvars["psa_cidr"] == provider.ledger[("shop", PF.PURPOSE_PSA)]
    assert tfvars["psa_cidr"].endswith("/20")
    declared = {n for e in hcl2.loads(files[W + "variables.tf"])["variable"] for n in e}
    assert {"subnet_cidr", "psa_cidr"} <= declared


def test_p5_e2e_dnh_a_network_without_psa_address_allocates_no_psa_range():
    provider = PF.MemoryFactsProvider()
    agent, files = _generate(dict(APP, **{W + "network.tf": net()}), provider)
    assert agent.last_validation_report.status == "PASS"
    assert set(provider.ledger) == {("shop", PF.PURPOSE_SUBNET)}
    assert "psa_cidr" not in hcl2.loads(files[W + "terraform.tfvars"])

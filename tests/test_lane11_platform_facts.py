"""Lane 11 near-term (FD-52 / FD-4AK / FD-4AL): IPAM network facts as typed inputs + the POLICY.CIDR_LITERAL rule.

Covers: the facts model and renders (byte-identical without facts), exact purpose detection from parsed drafts, the
in-memory and Firestore facts providers (fail-closed; FD-4BZ: ledger writes via the transactional IPAM engine),
the V2h / V2h-secondary validators (positives with the exact variable in the hint, Do No Harm negatives incl. the R3d firewall ranges, hash unchanged,
zero findings on the golden-module corpus), stack registration, and the developer stage end to end (facts rendered,
the AI's files untouched, literal -> typed CODE_DEFECT, reference -> PASS, existing network -> measured only).
"""
import hermetic_guard  # noqa: F401  (first import)

import copy
import glob
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402  (python-hcl2: an orchestrator-gateway requirement, installed by CI and AGENTS.md setup)
except ImportError:  # pragma: no cover - environment check
    # code RT F7: never a silent skip in CI (CI=true there) or when STACKVEND_REQUIRE_HCL2=1; a local run without
    # the gateway requirements (or eval/.deps on PYTHONPATH) skips with this reason.
    if os.environ.get("CI") == "true" or os.environ.get("STACKVEND_REQUIRE_HCL2") == "1":
        raise
    pytest.skip("python-hcl2 (gateway requirement) not installed; put eval/.deps on PYTHONPATH",
                allow_module_level=True)

from developer_agent import hallucination_runtime as hr  # noqa: E402
from ipam_fake_firestore import FakeFirestore, fake_transactional  # noqa: E402
from developer_agent import platform_facts as PF  # noqa: E402
from developer_agent.stack_clients import FirestoreFactsProvider  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.platform_facts import (CODE_LITERAL, CODE_MISMATCH, CODE_NOT_ALLOCATED,  # noqa: E402
                                                       CODE_REUSED, CODE_SECONDARY, CidrFactValidator,
                                                       CidrSecondaryLiteralValidator, is_cidr_literal)
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import (ErrorClass, MemoryLedgerStore, MemoryProvenanceStore,  # noqa: E402
                                RepairBudgetExhausted, StageError, artifact_hash)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

W = "infra/workload/"
POOL = PF.IpamPool(supernet="10.100.0.0/16", subnet_prefix=24, connector_prefix=28, region="us-central1")
FACTS = PF.NetworkFacts(product_id="shop", region="us-central1", subnet_cidr="10.100.1.0/24",
                        connector_cidr="10.100.0.0/28")


def _ctx(files, *, llm=None):
    llm = set(files) if llm is None else set(llm)

    def own(path):
        return Ownership.LLM_AUTHORED if path in llm else Ownership.PLATFORM_RENDERED
    return ValidationContext.build(files, ownership=own, draft=dict(files), trace_id="t")


def _run(files, facts=FACTS, *, llm=None, existing_network=False):
    ctx = _ctx(files, llm=llm)
    before = artifact_hash(ctx.files)
    out = CidrFactValidator(facts, existing_network=existing_network).validate(ctx)
    assert artifact_hash(ctx.files) == before            # validators never write
    return out


SUBNET_LITERAL = ('resource "google_compute_subnetwork" "custom_subnet" {\n  name          = "castor-workload-subnet"\n'
                  '  ip_cidr_range = "10.0.0.0/24"\n  region        = var.region\n'
                  '  network       = google_compute_network.vpc.id\n}\n')
CONNECTOR_VIA_VAR = ('variable "network_connector_cidr" {\n  type    = string\n  default = "10.100.0.0/28"\n}\n\n'
                     'resource "google_vpc_access_connector" "serverless_connector" {\n  name          = "vpc-connector"\n'
                     '  region        = var.region\n  ip_cidr_range = var.network_connector_cidr\n'
                     '  network       = google_compute_network.vpc.name\n}\n')
# R3d 03-r1 firewall ranges (Google IAP TCP forwarding, any egress) + health-check ranges: never allocation attributes
FIREWALLS = ('resource "google_compute_firewall" "allow_egress" {\n  name = "egress"\n  network = "n"\n'
             '  direction = "EGRESS"\n  destination_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "all"\n  }\n}\n\n'
             'resource "google_compute_firewall" "allow_iap" {\n  name = "iap"\n  network = "n"\n'
             '  source_ranges = ["35.235.240.0/20"]\n  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }\n}\n\n'
             'resource "google_compute_firewall" "hc" {\n  name = "hc"\n  network = "n"\n'
             '  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]\n  allow {\n    protocol = "tcp"\n  }\n}\n\n'
             'resource "google_compute_route" "r" {\n  name = "r"\n  network = "n"\n  dest_range = "0.0.0.0/0"\n'
             '  next_hop_gateway = "default-internet-gateway"\n}\n')


# ------------------------------------------------------------------------------------------------ model + renders
def test_facts_model_accepts_only_network_cidrs():
    assert FACTS.variables() == {"subnet_cidr": "10.100.1.0/24", "connector_cidr": "10.100.0.0/28"}
    with pytest.raises(ValueError):
        PF.NetworkFacts(product_id="x", region="r", subnet_cidr="10.100.1.5/24")    # host bits set
    with pytest.raises(ValueError):
        PF.NetworkFacts(product_id="x", region="r", connector_cidr="not-a-cidr")


def test_renders_are_empty_without_facts_so_variables_tf_is_byte_identical():
    assert PF.render_fact_variables(None) == ""
    assert PF.render_fact_tfvars(None) == []
    assert PF.render_fact_variables(PF.NetworkFacts(product_id="x", region="r")) == ""
    from developer_agent.terraform_engine import generate_golden_variables_tf
    base = generate_golden_variables_tf("shop", "o/shop")
    assert base + PF.render_fact_variables(None) == base


def test_fact_variables_parse_and_have_no_default_and_tfvars_carry_the_values():
    text = PF.render_fact_variables(FACTS)
    doc = hcl2.loads(text)
    declared = {name: body for entry in doc["variable"] for name, body in entry.items()}
    assert set(declared) == {"subnet_cidr", "connector_cidr"}
    assert all("default" not in b for b in declared.values())
    assert all(b["validation"] for b in declared.values())
    tfvars = hcl2.loads("\n".join(PF.render_fact_tfvars(FACTS)) + "\n")
    assert tfvars == {"subnet_cidr": "10.100.1.0/24", "connector_cidr": "10.100.0.0/28"}
    only_connector = PF.NetworkFacts(product_id="x", region="r", connector_cidr="10.100.0.0/28")
    assert 'variable "subnet_cidr"' not in PF.render_fact_variables(only_connector)


# ------------------------------------------------------------------------------------------------ purposes
def test_required_purposes_come_from_exact_parsed_types():
    files = {W + "network.tf": SUBNET_LITERAL, W + "c.tf": CONNECTOR_VIA_VAR}
    assert PF.required_network_purposes(files) == {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}
    assert PF.required_network_purposes({W + "fw.tf": FIREWALLS}) == frozenset()
    mod = 'module "network" {\n  source = "../modules/networking-vpc"\n  primary_subnet_cidr = "10.0.0.0/24"\n}\n'
    assert PF.required_network_purposes({W + "n.tf": mod}) == {PF.PURPOSE_SUBNET}
    other = 'module "network" {\n  source = "../modules/networking-vpc-extra"\n}\n'
    assert PF.required_network_purposes({W + "n.tf": other}) == frozenset()
    # not a root-module file / unparseable / restricted to other paths -> nothing
    assert PF.required_network_purposes({"infra/modules/x/main.tf": SUBNET_LITERAL}) == frozenset()
    assert PF.required_network_purposes({W + "bad.tf": 'resource "google_compute_subnetwork" "s" {'}) == frozenset()
    assert PF.required_network_purposes(files, paths=[W + "c.tf"]) == {PF.PURPOSE_CONNECTOR}
    assert PF.has_existing_network({W + "network.tf": SUBNET_LITERAL}) is True
    assert PF.has_existing_network({}) is False and PF.has_existing_network(None) is False


# ------------------------------------------------------------------------------------------------ providers
def test_memory_provider_is_deterministic_disjoint_and_idempotent():
    p = PF.MemoryFactsProvider()
    a = p.resolve("shop", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}, pool=POOL)
    assert (a.subnet_cidr, a.connector_cidr) == ("10.100.0.0/24", "10.100.1.0/28")
    assert p.resolve("shop", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}, pool=POOL) == a
    b = p.resolve("cart", {PF.PURPOSE_CONNECTOR}, pool=POOL)
    assert b.subnet_cidr is None and b.connector_cidr == "10.100.1.16/28"
    import ipaddress
    nets = [ipaddress.ip_network(c) for c in p.ledger.values()]
    assert all(not x.overlaps(y) for i, x in enumerate(nets) for y in nets[i + 1:])
    tiny = PF.IpamPool(supernet="10.200.0.0/24", subnet_prefix=24, connector_prefix=28, region="r")
    PF.MemoryFactsProvider().resolve("a", {PF.PURPOSE_SUBNET}, pool=tiny)
    q = PF.MemoryFactsProvider(ledger={("a", PF.PURPOSE_SUBNET): "10.200.0.0/24"})
    with pytest.raises(PF.FactsUnavailable, match="POOL_EXHAUSTED"):
        q.resolve("b", {PF.PURPOSE_SUBNET}, pool=tiny)


def test_next_free_block_skips_every_occupied_range():
    assert PF.next_free_block("10.100.0.0/16", 24, ["10.100.0.0/28"]) == "10.100.1.0/24"
    assert PF.next_free_block("10.100.0.0/16", 28, ["10.100.0.0/24"]) == "10.100.1.0/28"
    with pytest.raises(ValueError):
        PF.next_free_block("10.100.0.0/16", 28, ["garbage"])


def _rec(cidr, product, purpose, status="ALLOCATED", **extra):
    """A ledger record in the shape CastorIPAMEngine writes (FD-4BZ: the provider now reads it through the engine)."""
    doc = {"cidr_block": cidr, "sanitized_id": cidr.replace(".", "_").replace("/", "_"), "product_id": product,
           "purpose": purpose, "prefix_length": int(cidr.split("/")[1]), "status": status}
    doc.update(extra)
    return doc


def _tx_db(*records):
    """FD-4BZ: an in-memory Firestore with transactions (tests/ipam_fake_firestore.py), seeded with ledger records."""
    db = FakeFirestore()
    db.store["cidr_allocations"] = {r["sanitized_id"]: dict(r) for r in records}
    return db


def _provider(db):
    return FirestoreFactsProvider(db, transactional=fake_transactional)


def _ledger(db):
    return copy.deepcopy(db.store.get("cidr_allocations", {}))


def test_firestore_provider_creates_reuses_reclaims_and_never_overwrites():
    db = _tx_db(_rec("10.100.0.0/28", "other", PF.PURPOSE_CONNECTOR))
    prov = _provider(db)
    f = prov.resolve("shop", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}, pool=POOL, project_id="castor-shop")
    assert (f.subnet_cidr, f.connector_cidr) == ("10.100.1.0/24", "10.100.0.16/28")
    assert sorted(_ledger(db)) == ["10_100_0_0_28", "10_100_0_16_28", "10_100_1_0_24"]
    assert _ledger(db)["10_100_0_0_28"] == _rec("10.100.0.0/28", "other", PF.PURPOSE_CONNECTOR)   # untouched
    new = _ledger(db)["10_100_1_0_24"]
    assert (new["product_id"], new["status"], new["project_id"], new["region"], new["prefix_length"]) == \
        ("shop", "ALLOCATED", "castor-shop", "us-central1", 24)
    assert new["notes"] == FirestoreFactsProvider.NOTES
    before = _ledger(db)
    assert prov.resolve("shop", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}, pool=POOL) == f
    assert _ledger(db) == before                                                   # reuse writes nothing
    db.store["cidr_allocations"]["10_100_0_16_28"]["status"] = "RESERVED_DECOMMISSIONED"
    assert prov.resolve("shop", {PF.PURPOSE_CONNECTOR}, pool=POOL).connector_cidr == "10.100.0.16/28"
    assert _ledger(db)["10_100_0_16_28"]["status"] == "ALLOCATED"


def test_firestore_provider_retries_a_lost_create_race_and_fails_closed():
    db = _tx_db()
    rival = _rec("10.100.0.0/24", "rival", PF.PURPOSE_SUBNET)

    def outside_writer(coll, txn):   # a writer outside the transaction takes the chosen block (no version bump)
        if txn is not None and "10_100_0_0_24" not in db.store["cidr_allocations"]:
            db.store["cidr_allocations"]["10_100_0_0_24"] = dict(rival)
    db.after_read = outside_writer
    f = _provider(db).resolve("shop", {PF.PURPOSE_SUBNET}, pool=POOL)
    db.after_read = None
    assert f.subnet_cidr == "10.100.1.0/24" and _ledger(db)["10_100_0_0_24"] == rival
    broken = _tx_db()
    broken.read_error = RuntimeError("deadline exceeded")
    with pytest.raises(PF.FactsUnavailable, match="IPAM.UNAVAILABLE"):
        _provider(broken).resolve("shop", {PF.PURPOSE_SUBNET}, pool=POOL)
    with pytest.raises(PF.FactsUnavailable, match="IPAM.UNAVAILABLE"):
        FirestoreFactsProvider(None).resolve("shop", {PF.PURPOSE_SUBNET}, pool=POOL)
    corrupt = _tx_db(_rec("10.100.9.0/24", "o", "X", cidr_block="nonsense"))
    with pytest.raises(PF.FactsUnavailable, match="LEDGER_CORRUPT"):
        _provider(corrupt).resolve("shop", {PF.PURPOSE_SUBNET}, pool=POOL)


# ------------------------------------------------------------------------------------------------ V2h positives
def test_literal_on_a_subnetwork_names_the_exact_fact_variable():
    [d] = _run({W + "network.tf": SUBNET_LITERAL})
    assert d.code == CODE_LITERAL and d.severity == "error" and d.error_class is ErrorClass.CODE_DEFECT
    assert d.block_address == "google_compute_subnetwork.custom_subnet" and d.attribute_path == "ip_cidr_range"
    assert d.file == W + "network.tf" and d.line == 1
    assert "ip_cidr_range = var.subnet_cidr" in d.hint and "10.100.1.0/24" in d.hint
    assert "10.0.0.0/24" in d.message


def test_literal_held_in_the_ais_own_variable_or_local_is_found_and_the_holder_named():
    [d] = _run({W + "custom.tf": CONNECTOR_VIA_VAR})
    assert d.code == CODE_LITERAL and "var.connector_cidr" in d.hint and 'variable "network_connector_cidr"' in d.hint
    loc = ('locals {\n  sub = "10.0.0.0/24"\n}\n\nresource "google_compute_subnetwork" "s" {\n  name = "s"\n'
           '  ip_cidr_range = local.sub\n  network = "n"\n}\n')
    [d2] = _run({W + "n.tf": loc})
    assert d2.code == CODE_LITERAL and "local.sub" in d2.hint and "var.subnet_cidr" in d2.hint


def test_golden_network_module_call_literal_and_fact_mismatch():
    mod = 'module "network" {\n  source = "../modules/networking-vpc"\n  primary_subnet_cidr = "10.0.0.0/24"\n}\n'
    [d] = _run({W + "n.tf": mod})
    assert d.code == CODE_LITERAL and d.block_address == "module.network" and "primary_subnet_cidr" in d.hint
    swapped = ('resource "google_vpc_access_connector" "c" {\n  name = "c"\n  ip_cidr_range = var.subnet_cidr\n'
               '  network = "n"\n}\n')
    [m] = _run({W + "c.tf": swapped})
    assert m.code == CODE_MISMATCH and "var.connector_cidr" in m.hint and "10.100.0.0/28" in m.hint


def test_no_allocation_is_a_platform_defect_never_a_repair():
    [d] = _run({W + "network.tf": SUBNET_LITERAL}, facts=None)
    assert d.code == CODE_NOT_ALLOCATED and d.error_class is ErrorClass.PLATFORM_DEFECT
    only_conn = PF.NetworkFacts(product_id="shop", region="r", connector_cidr="10.100.0.0/28")
    [d2] = _run({W + "network.tf": SUBNET_LITERAL}, facts=only_conn)
    assert d2.code == CODE_NOT_ALLOCATED


def test_existing_network_is_measured_only():
    [d] = _run({W + "network.tf": SUBNET_LITERAL}, existing_network=True)
    assert d.code == CODE_LITERAL and d.severity == "warning" and "pinned" in d.message


def test_secondary_ranges_are_report_only_warnings():
    gke = ('resource "google_compute_subnetwork" "gke_subnet" {\n  name = "g"\n  ip_cidr_range = var.subnet_cidr\n'
           '  network = "n"\n  secondary_ip_range {\n    range_name = "pods"\n    ip_cidr_range = "10.20.0.0/16"\n'
           '  }\n  secondary_ip_range {\n    range_name = "svc"\n    ip_cidr_range = "10.30.0.0/20"\n  }\n}\n')
    assert _run({W + "gke.tf": gke}) == []
    ds = CidrSecondaryLiteralValidator().validate(_ctx({W + "gke.tf": gke}))
    assert [d.code for d in ds] == [CODE_SECONDARY, CODE_SECONDARY]
    assert all(d.severity == "warning" for d in ds)
    assert [d.attribute_path for d in ds] == ["secondary_ip_range[0].ip_cidr_range", "secondary_ip_range[1].ip_cidr_range"]


# ------------------------------------------------------------------------------------------------ V2h negatives
def test_do_no_harm_negatives_emit_nothing():
    ok = ('resource "google_compute_subnetwork" "s" {\n  name = "s"\n  ip_cidr_range = var.subnet_cidr\n'
          '  network = "n"\n}\n\nresource "google_vpc_access_connector" "c" {\n  name = "c"\n'
          '  ip_cidr_range = var.connector_cidr\n  network = "n"\n}\n\n'
          'resource "google_compute_subnetwork" "derived" {\n  name = "d"\n'
          '  ip_cidr_range = cidrsubnet(var.subnet_cidr, 4, 1)\n  network = "n"\n}\n\n'
          'resource "google_compute_subnetwork" "escaped" {\n  name = "e"\n  ip_cidr_range = "$${var.x}"\n'
          '  network = "n"\n}\n\n'
          'resource "google_compute_subnetwork" "no_range" {\n  name = "n"\n  network = "n"\n}\n')
    # each valid shape on its own emits nothing (code RT F5: subnets that share one fact must each use a disjoint
    # part, so the whole-range `s` next to `derived` is an overlap and is tested in the F5 tests below)
    blocks = ok.split("\n\n")
    for blk in blocks:
        assert _run({W + "network.tf": blk + "\n"}) == [], blk
    assert _run({W + "network.tf": blocks[1] + "\n\n" + blocks[2] + "\n\n" + blocks[4] + "\n"}) == []
    assert [d.code for d in _run({W + "network.tf": ok})] == [CODE_REUSED]   # `s` (whole) overlaps `derived`
    assert _run({W + "fw.tf": FIREWALLS}) == []
    # a CIDR literal in a variable nobody uses for an allocation attribute is not this rule's finding
    assert _run({W + "v.tf": 'variable "allowed" {\n  default = ["10.0.0.0/8"]\n}\n'}) == []
    # platform-rendered files are never checked for repair
    assert _run({W + "network.tf": SUBNET_LITERAL}, llm=[]) == []


def test_is_cidr_literal_reads_values_not_text():
    assert is_cidr_literal("10.0.0.0/24") == "10.0.0.0/24"
    assert is_cidr_literal("${var.subnet_cidr}") is None
    assert is_cidr_literal("castor-vpc") is None
    assert is_cidr_literal(["10.0.0.0/24"]) is None
    assert is_cidr_literal(None) is None


def _golden_files():
    out = {}
    for path in glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True):
        out[os.path.relpath(path, REPO_ROOT)] = open(path).read()
    assert out
    return out


def test_golden_module_corpus_yields_zero_findings():
    golden = _golden_files()
    # as vendored (their real paths, platform-owned): never checked for repair
    assert _run(golden, llm=[]) == []
    # strictest reading: every module file presented as an AI root file. The one finding is the known golden default
    # `networking-vpc` primary_subnet_cidr = "10.10.0.0/24" (lane 11 C14, removed by 11c), reached through the
    # module's own variable. Lane 10 L10-u: the compute-gce-worker subnet takes var.subnet_cidr as is (it is its own
    # VPC); merged into one root with networking-vpc's subnets it reads as a reuse - an artifact of this strict
    # reading only (a real workload passes var.subnet_cidr into the module call, which is a platform block).
    # gce-bastion-network: the compute-gce-bastion own subnet is the same case as the gce-worker's.
    # Nothing else in the corpus trips the rule.
    as_llm = {W + p.replace("/", "__"): t for p, t in golden.items()}
    found = _run(as_llm)
    assert [(d.code, d.block_address, d.file) for d in found] == [
        (CODE_REUSED, "google_compute_subnetwork.bastion", W + "infra__modules__compute-gce-bastion__main.tf"),
        (CODE_REUSED, "google_compute_subnetwork.worker", W + "infra__modules__compute-gce-worker__main.tf"),
        (CODE_LITERAL, "google_compute_subnetwork.primary", W + "infra__modules__networking-vpc__main.tf")]
    assert 'variable "primary_subnet_cidr"' in found[2].hint
    assert CidrSecondaryLiteralValidator().validate(_ctx(as_llm)) == []


# ------------------------------------------------------------------------------------------------ stack
def test_stack_registers_v2h_blocking_and_secondary_report_only():
    stack = build_step1_stack(validate_client=None, verifier_factory=None, network_facts=FACTS)
    assert stack.mode_of("V2h") == "blocking" and stack.mode_of("V2h-secondary") == "report_only"
    assert stack.ids[-2:] == ["V2h", "V2h-secondary"]


# ------------------------------------------------------------------------------------------------ end to end
class _Client:
    def __init__(self):
        self.validated = []

    def ready(self, iac_engine="OPENTOFU"):
        return {"ready": True, "providers": ["google", "google-beta", "kubernetes", "random"], "engine": "OPENTOFU",
                "engine_version": "1.9.0"}

    def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
        self.validated.append(dict(files))
        return {"status": "PASS", "diagnostics": []}


APP = {
    "apps/shop/main.py": "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get('/health')\ndef health():\n"
                         "    return {'ok': True}\n",
    "apps/shop/requirements.txt": "fastapi>=0.110.0\nuvicorn>=0.28.0\n",
    "apps/shop/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
}
NET_OK = ('resource "google_compute_network" "vpc" {\n  name                    = "${var.product_id}-vpc"\n'
          '  auto_create_subnetworks = false\n}\n\n'
          'resource "google_compute_subnetwork" "app" {\n  name          = "${var.product_id}-subnet"\n'
          '  ip_cidr_range = var.subnet_cidr\n  region        = var.region\n'
          '  network       = google_compute_network.vpc.id\n}\n')
# R3d 03-r1 shape: the AI's own `variable "subnet_cidr"` with a literal default (relocated from its variables.tf)
AI_VARS = 'variable "subnet_cidr" {\n  type    = string\n  default = "10.100.0.0/28"\n}\n'


class _NoCallGenaiClient:
    """generate_code_files fails LLM_UNAVAILABLE without a client (lane 19 row 27a). The draft comes from the fake
    dispatcher, so any model call is a test failure."""

    class models:  # noqa: N801 - mirrors google.genai.Client().models
        @staticmethod
        def generate_content(*a, **k):
            raise AssertionError("unexpected LLM call: the draft comes from the fake dispatcher")


_DEFAULT_SETTINGS = object()


def _generate(draft, provider, existing=None, iterations=0, repairs=None, settings=_DEFAULT_SETTINGS):
    """generate_code_files on a fixed draft; `repairs` = the files each repair call returns, in order.
    FD-4AK: the IPAM pool comes from a strict settings read, so the platform settings are given explicitly (default:
    the stored-defaults PlatformSettings; `settings=None` = no settings patch, i.e. the read fails like Firestore)."""
    from developer_agent import handler as h
    from shared import settings as shared_settings
    if settings is _DEFAULT_SETTINGS:
        settings = shared_settings.PlatformSettings()
    settings_patch = (patch.object(shared_settings, "get_platform_settings", return_value=settings)
                      if settings is not None else patch.dict(os.environ, {}))
    repairs = list(repairs or [])
    rt = hr.HallucinationRuntime(ledger_store=MemoryLedgerStore(), provenance_store=MemoryProvenanceStore(),
                                 validate_client=_Client(), source="test", facts_provider=provider,
                                 settings=HallucinationStackSettings(repair_max_iterations_precommit=iterations))
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        agent = h.DeveloperAgent(project_id="")
    agent.genai_client = _NoCallGenaiClient()   # lane 19 (27a): None now raises LLM_UNAVAILABLE first
    agent.attach_stack_runtime(rt)
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]
    d = dict(draft)

    class FakeDispatcher:
        def __init__(self, *a, **k):
            self.last_file_attribution = {p: "iac_worker" if p.endswith(".tf") else "backend_worker" for p in d}
            self.envelope_checks = [{"ok": True, "error": None}]

        async def execute_phased_junior_swarm(self, *a, **k):
            return dict(d)

        def invoke_repair(self, persona, *a, **k):
            files = repairs.pop(0) if repairs else {}
            return {"files": dict(files), "envelope_ok": True, "error": None, "finish_reason": "STOP",
                    "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0, "model": "fake", "persona": persona}

    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value=dict(existing or {})), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")), settings_patch:
        lead.return_value.decompose_specification.return_value = plan
        files = agent.generate_code_files(product_id="shop", spec_text="FastAPI service with a private subnet",
                                          task_dag=[], trace_id="trace-l11",
                                          architect_compute_intent={"target_compute_services": ["shop"]}, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    return agent, files


def test_e2e_reference_passes_facts_are_rendered_and_ai_files_are_untouched():
    provider = PF.MemoryFactsProvider()
    agent, files = _generate(dict(APP, **{W + "network.tf": NET_OK, W + "variables.tf": AI_VARS}), provider)
    assert agent.last_validation_report.status == "PASS"
    assert files[W + "network.tf"] == NET_OK                            # Do No Harm: the AI file is byte-identical
    variables = hcl2.loads(files[W + "variables.tf"])
    declared = {n: b for e in variables["variable"] for n, b in e.items()}
    assert "default" not in declared["subnet_cidr"] and "connector_cidr" not in declared
    assert hcl2.loads(files[W + "terraform.tfvars"])["subnet_cidr"] == "10.100.0.0/24"
    # the AI's own `variable "subnet_cidr"` (literal default) is the platform's declaration now: exact-key splice,
    # recorded (S1-A PLATFORM_ROOT_DECLARATION), not a text edit
    rec = agent.last_assembly_record
    assert rec.replaced_reason.get("variable.subnet_cidr") == "PLATFORM_ROOT_DECLARATION"
    assert "10.100.0.0/28" not in files.get(W + "custom.tf", "")
    assert agent.stack_run("trace-l11")["network_facts"]["subnet_cidr"] == "10.100.0.0/24"
    assert provider.ledger == {("shop", PF.PURPOSE_SUBNET): "10.100.0.0/24"}


def test_e2e_literal_is_a_typed_code_defect_with_the_exact_hint():
    net = NET_OK.replace("var.subnet_cidr", '"10.0.0.0/24"')
    agent, _ = None, None
    with pytest.raises(RepairBudgetExhausted) as ei:
        _generate(dict(APP, **{W + "network.tf": net}), PF.MemoryFactsProvider())
    assert ei.value.error_class is ErrorClass.CODE_DEFECT
    [d] = [x for x in ei.value.report.diagnostics if x.code == CODE_LITERAL]
    assert d.file == W + "network.tf" and "var.subnet_cidr" in d.hint


def test_e2e_no_network_draft_allocates_nothing_and_renders_byte_identically():
    provider = PF.MemoryFactsProvider()
    agent, files = _generate(dict(APP, **{W + "storage.tf": 'resource "google_storage_bucket" "b" {\n'
                                                            '  name = "${var.product_id}-b"\n  location = var.region\n'
                                                            '  uniform_bucket_level_access = true\n}\n'}),
                             provider)
    assert agent.last_validation_report.status == "PASS" and provider.ledger == {}
    assert "subnet_cidr" not in files[W + "variables.tf"] and "connector_cidr" not in files[W + "variables.tf"]


def test_e2e_existing_network_is_never_reallocated_and_never_blocks():
    provider = PF.MemoryFactsProvider()
    net = NET_OK.replace("var.subnet_cidr", '"10.0.0.0/24"')
    agent, files = _generate(dict(APP, **{W + "network.tf": net}), provider, existing={W + "network.tf": net})
    assert provider.ledger == {} and agent.last_validation_report.status == "PASS"
    assert any(d.code == CODE_LITERAL and d.severity == "warning" for d in agent.last_validation_report.diagnostics)


def test_e2e_missing_provider_or_ipam_error_is_gate_unavailable():
    net = dict(APP, **{W + "network.tf": NET_OK})
    with pytest.raises(StageError) as ei:
        _generate(net, None)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE

    class Broken:
        def resolve(self, *a, **k):
            raise PF.FactsUnavailable("IPAM.UNAVAILABLE: ledger read failed")
    with pytest.raises(StageError) as ei2:
        _generate(net, Broken())
    assert ei2.value.error_class is ErrorClass.GATE_UNAVAILABLE


def test_fd4ak_unreadable_settings_stop_the_network_stage_never_the_default_pool():
    """FD-4AK (code RT F6.3): with the settings document unreadable the IPAM pool is unknown: GATE_UNAVAILABLE and
    nothing is allocated (formerly the compile-time pool 10.100.0.0/16 was used)."""
    from shared import settings as shared_settings
    shared_settings.invalidate_settings_cache()
    provider = PF.MemoryFactsProvider()
    try:
        with pytest.raises(StageError) as ei:
            _generate(dict(APP, **{W + "network.tf": NET_OK}), provider, settings=None)
    finally:
        shared_settings.invalidate_settings_cache()
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE
    assert "PLATFORM_SETTINGS_READ_FAILED" in str(ei.value) and provider.ledger == {}


def test_harness_runtime_installs_the_memory_provider():
    try:
        info = hr.configure_for_harness(validate_client=None)
        assert info["facts_provider"] == "memory"
        assert isinstance(hr.get_runtime().facts_provider, PF.MemoryFactsProvider)
    finally:
        hr.reset_for_tests()
    assert hr.get_runtime().facts_provider is None


# ================================================================================================ code RT fixes
# ------------------------------------------------------------------------------------------------ F3 reuse-only
def test_providers_reuse_only_never_create():
    p = PF.MemoryFactsProvider(ledger={("shop", PF.PURPOSE_SUBNET): "10.100.0.0/24"})
    f = p.resolve("shop", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}, pool=POOL, allocate=False)
    assert (f.subnet_cidr, f.connector_cidr) == ("10.100.0.0/24", None)
    assert p.ledger == {("shop", PF.PURPOSE_SUBNET): "10.100.0.0/24"}
    db = _tx_db(_rec("10.100.0.0/24", "shop", PF.PURPOSE_SUBNET))
    before = _ledger(db)
    g = _provider(db).resolve("shop", {PF.PURPOSE_SUBNET, PF.PURPOSE_CONNECTOR}, pool=POOL, allocate=False)
    assert (g.subnet_cidr, g.connector_cidr) == ("10.100.0.0/24", None) and _ledger(db) == before
    empty = _tx_db()
    assert _provider(empty).resolve("shop", {PF.PURPOSE_SUBNET}, pool=POOL, allocate=False).variables() == {}
    assert _ledger(empty) == {}


def test_committed_fact_values_are_parsed_never_guessed():
    tfv = 'enable_direct_iap          = true\nsubnet_cidr                = "10.100.0.0/24"\n'
    assert PF.committed_fact_values({W + "terraform.tfvars": tfv}) == {"subnet_cidr": "10.100.0.0/24"}
    assert PF.committed_fact_values({W + "terraform.tfvars": "enable_direct_iap = true\n"}) == {}
    assert PF.committed_fact_values(None) == {} and PF.committed_fact_values({}) == {}
    with pytest.raises(PF.FactsUnavailable, match="COMMITTED_TFVARS_UNREADABLE"):
        PF.committed_fact_values({W + "terraform.tfvars": 'subnet_cidr = "not-a-cidr"\n'})
    with pytest.raises(PF.FactsUnavailable, match="COMMITTED_TFVARS_UNREADABLE"):
        PF.committed_fact_values({W + "terraform.tfvars": 'subnet_cidr = = "x'})


def test_e2e_second_regeneration_reuses_the_facts_byte_identically():
    """Code RT F3 (E5 inverted): run 2 with run 1's tree as the repository renders the same fact declaration and
    tfvars line, leaves network.tf untouched, writes nothing to the ledger and never lets the legacy preflight
    auto-declare a fact variable with an invented default."""
    provider = PF.MemoryFactsProvider()
    draft = dict(APP, **{W + "network.tf": NET_OK})
    agent1, run1 = _generate(draft, provider)
    ledger1 = dict(provider.ledger)
    assert ledger1 == {("shop", PF.PURPOSE_SUBNET): "10.100.0.0/24"}
    agent2, run2 = _generate(draft, provider, existing=run1)
    assert agent2.last_validation_report.status == "PASS"
    assert agent2.stack_run("trace-l11")["existing_network"] is True
    assert agent2.stack_run("trace-l11")["facts_source"] == "reuse-only"
    assert provider.ledger == ledger1
    assert run2[W + "network.tf"] == run1[W + "network.tf"] == NET_OK
    assert run2[W + "variables.tf"] == run1[W + "variables.tf"]
    assert run2[W + "terraform.tfvars"] == run1[W + "terraform.tfvars"]
    assert "Auto-declared" not in run2[W + "variables.tf"]
    declared = [n for e in hcl2.loads(run2[W + "variables.tf"])["variable"] for n in e]
    assert declared.count("subnet_cidr") == 1
    # run 3: the AI does not re-emit network.tf (the repository's copy stays); its purposes still come from the
    # repository, so the fact is still declared and valued
    agent3, run3 = _generate(dict(APP), provider, existing=run1)
    assert agent3.last_validation_report.status == "PASS" and provider.ledger == ledger1
    assert run3[W + "variables.tf"] == run1[W + "variables.tf"]
    assert run3[W + "terraform.tfvars"] == run1[W + "terraform.tfvars"]


def test_e2e_pre_facts_workload_keeps_its_own_range_even_with_a_ledger_record():
    """Reuse-only renders a fact only when the committed platform tfvars carry it: a workload generated before facts
    (its range lives in the AI's own `variable "subnet_cidr"` default) is not re-bound to the architect's ledger record
    (that would move a live range), and nothing is allocated."""
    provider = PF.MemoryFactsProvider(ledger={("shop", PF.PURPOSE_SUBNET): "10.100.7.0/24"})
    ai_vars = 'variable "subnet_cidr" {\n  type    = string\n  default = "10.0.0.0/24"\n}\n'
    repo = {W + "network.tf": NET_OK, W + "variables.tf": ai_vars}
    agent, files = _generate(dict(APP, **{W + "network.tf": NET_OK, W + "variables.tf": ai_vars}), provider,
                             existing=repo)
    assert agent.last_validation_report.status == "PASS"
    assert provider.ledger == {("shop", PF.PURPOSE_SUBNET): "10.100.7.0/24"}
    assert agent.stack_run("trace-l11")["network_facts"] is None
    assert "10.100.7.0/24" not in "".join(files.values())
    assert "variable.subnet_cidr" not in agent.last_assembly_record.replaced_reason


def test_e2e_pre_facts_workload_needs_no_ipam_access():
    """A workload generated before facts (no fact in its committed tfvars) regenerates exactly as before: no provider
    call at all, so an IPAM outage or a missing provider cannot stop it."""
    net = NET_OK.replace("var.subnet_cidr", '"10.0.0.0/24"')

    class Exploding:
        def resolve(self, *a, **k):
            raise AssertionError("IPAM accessed for a pre-facts workload")
    for provider in (None, Exploding()):
        agent, _files = _generate(dict(APP, **{W + "network.tf": net}), provider, existing={W + "network.tf": net})
        assert agent.last_validation_report.status == "PASS"


def test_e2e_reuse_renders_only_the_committed_facts():
    """Reuse-only renders exactly the facts the committed tfvars carry: a ledger connector record of this product that
    the workload never received as a fact (its connector range lives in the AI's own variable) is not bound."""
    provider = PF.MemoryFactsProvider(ledger={("shop", PF.PURPOSE_SUBNET): "10.100.0.0/24",
                                              ("shop", PF.PURPOSE_CONNECTOR): "10.100.1.0/28"})
    conn_var = 'variable "connector_cidr" {\n  type    = string\n  default = "10.8.0.0/28"\n}\n'
    tf = NET_OK + "\n" + CONNECTOR_REF
    repo = {W + "network.tf": tf, W + "conn_vars.tf": conn_var,
            W + "terraform.tfvars": 'subnet_cidr                = "10.100.0.0/24"\n'}
    agent, files = _generate(dict(APP, **{W + "network.tf": tf, W + "conn_vars.tf": conn_var}), provider,
                             existing=repo)
    assert agent.last_validation_report.status == "PASS"
    assert agent.stack_run("trace-l11")["network_facts"]["connector_cidr"] is None
    assert hcl2.loads(files[W + "terraform.tfvars"]) == {"subnet_cidr": "10.100.0.0/24",
                                                          # S2-C (HS-63): exact API table for the declared types
                                                          "additional_apis": ["compute.googleapis.com", "vpcaccess.googleapis.com"]}
    assert "variable.connector_cidr" not in agent.last_assembly_record.replaced_reason


def test_e2e_committed_fact_the_ledger_does_not_hold_stops_the_stage():
    net = dict(APP, **{W + "network.tf": NET_OK})
    repo = {W + "network.tf": NET_OK, W + "terraform.tfvars": 'subnet_cidr = "10.100.0.0/24"\n'}
    for ledger in ({}, {("shop", PF.PURPOSE_SUBNET): "10.100.9.0/24"}):
        provider = PF.MemoryFactsProvider(ledger=dict(ledger))
        with pytest.raises(StageError) as ei:
            _generate(net, provider, existing=repo)
        assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and "LEDGER_MISMATCH" in str(ei.value)
        assert provider.ledger == ledger


# ------------------------------------------------------------------------------------------------ F4 per iteration
CONNECTOR_REF = ('resource "google_vpc_access_connector" "conn" {\n  name = "shop-conn"\n'
                 '  region        = var.region\n  ip_cidr_range = var.connector_cidr\n'
                 '  network       = google_compute_network.vpc.name\n}\n')


def test_e2e_repair_that_adds_a_connector_gets_its_fact():
    """Code RT F4: C0 needs only the subnet; the repair (C1) adds a connector. Facts are resolved per assembled
    draft, so C1 renders `connector_cidr` (declaration + tfvars), the ledger gains the connector block, and the
    subnet fact is unchanged (facts only grow)."""
    provider = PF.MemoryFactsProvider()
    c0 = NET_OK.replace("var.subnet_cidr", '"10.0.0.0/24"')
    c1 = NET_OK + "\n" + CONNECTOR_REF
    agent, files = _generate(dict(APP, **{W + "network.tf": c0}), provider, iterations=1,
                             repairs=[{W + "network.tf": c1}])
    assert agent.last_validation_report.status == "PASS"
    assert files[W + "network.tf"] == c1
    assert provider.ledger == {("shop", PF.PURPOSE_SUBNET): "10.100.0.0/24",
                               ("shop", PF.PURPOSE_CONNECTOR): "10.100.1.0/28"}
    declared = {n for e in hcl2.loads(files[W + "variables.tf"])["variable"] for n in e}
    assert {"subnet_cidr", "connector_cidr"} <= declared
    assert hcl2.loads(files[W + "terraform.tfvars"])["connector_cidr"] == "10.100.1.0/28"
    assert agent.stack_run("trace-l11")["network_facts"]["connector_cidr"] == "10.100.1.0/28"


def test_e2e_repair_connector_literal_is_a_code_defect_not_a_platform_defect():
    """Code RT F4: a repair that adds a connector with a literal gets POLICY.CIDR_LITERAL naming var.connector_cidr
    (CODE_DEFECT, repairable), never CIDR_NOT_ALLOCATED (PLATFORM_DEFECT)."""
    c0 = NET_OK.replace("var.subnet_cidr", '"10.0.0.0/24"')
    c1 = NET_OK + "\n" + CONNECTOR_REF.replace("var.connector_cidr", '"10.8.0.0/28"')
    seen = {}
    real = CidrFactValidator.validate

    def recording(self, ctx):
        out = real(self, ctx)
        seen[ctx.iteration] = out
        return out
    with patch.object(CidrFactValidator, "validate", recording), pytest.raises(RepairBudgetExhausted) as ei:
        _generate(dict(APP, **{W + "network.tf": c0}), PF.MemoryFactsProvider(), iterations=1,
                  repairs=[{W + "network.tf": c1}])
    assert ei.value.error_class is ErrorClass.CODE_DEFECT
    assert [(d.code, d.block_address) for d in seen[0]] == [(CODE_LITERAL, "google_compute_subnetwork.app")]
    [d] = seen[1]                                   # C1: the connector literal, with its fact in the hint
    assert (d.code, d.block_address, d.error_class) == (CODE_LITERAL, "google_vpc_access_connector.conn",
                                                        ErrorClass.CODE_DEFECT)
    assert "var.connector_cidr" in d.hint and "10.100.1.0/28" in d.hint


def test_validator_reads_the_current_facts_of_the_holder():
    holder = PF.FactsHolder()
    v = CidrFactValidator(holder)
    ctx = _ctx({W + "network.tf": SUBNET_LITERAL})
    assert [d.code for d in v.validate(ctx)] == [CODE_NOT_ALLOCATED]
    holder.facts = FACTS
    assert [d.code for d in v.validate(ctx)] == [CODE_LITERAL]


# ------------------------------------------------------------------------------------------------ F5 reused fact
TWO_SUBNETS = ('resource "google_compute_subnetwork" "gce_spot_subnet" {\n  name = "a"\n'
               '  ip_cidr_range = var.subnet_cidr\n  network = "n"\n}\n\n'
               'resource "google_compute_subnetwork" "gke_subnet" {\n  name = "b"\n'
               '  ip_cidr_range = var.subnet_cidr\n  network = "n"\n}\n')


def test_two_subnets_on_one_fact_are_reused_with_disjoint_cidrsubnet_hints():
    """Code RT F5 (R3d 05-r2 shape): both subnetworks get CIDR_FACT_REUSED, each with its own cidrsubnet index."""
    ds = _run({W + "network.tf": TWO_SUBNETS})
    assert [(d.code, d.block_address) for d in ds] == [(CODE_REUSED, "google_compute_subnetwork.gce_spot_subnet"),
                                                       (CODE_REUSED, "google_compute_subnetwork.gke_subnet")]
    assert all(d.severity == "error" and d.error_class is ErrorClass.CODE_DEFECT for d in ds)
    assert "ip_cidr_range = cidrsubnet(var.subnet_cidr, 1, 0)" in ds[0].hint
    assert "ip_cidr_range = cidrsubnet(var.subnet_cidr, 1, 1)" in ds[1].hint
    assert "10.100.1.0/24" in ds[0].hint and "google_compute_subnetwork.gke_subnet.ip_cidr_range" in ds[0].hint
    three = TWO_SUBNETS + TWO_SUBNETS.replace("gce_spot_subnet", "third").split("\n\n")[0] + "\n"
    ds3 = _run({W + "network.tf": three})
    assert [d.hint.split("cidrsubnet(")[1].split(")")[0] for d in ds3] == [
        "var.subnet_cidr, 2, 0", "var.subnet_cidr, 2, 1", "var.subnet_cidr, 2, 2"]
    # following the hints passes; the golden module + a subnetwork on the same fact is the same case
    fixed = TWO_SUBNETS.replace("var.subnet_cidr", "cidrsubnet(var.subnet_cidr, 1, 0)", 1).replace(
        "  ip_cidr_range = var.subnet_cidr", "  ip_cidr_range = cidrsubnet(var.subnet_cidr, 1, 1)")
    assert _run({W + "network.tf": fixed}) == []
    mod = 'module "network" {\n  source = "../modules/networking-vpc"\n  primary_subnet_cidr = var.subnet_cidr\n}\n'
    assert [d.code for d in _run({W + "n.tf": mod, W + "s.tf": TWO_SUBNETS.split("\n\n")[0] + "\n"})] == [
        CODE_REUSED, CODE_REUSED]


def test_two_subnet_literals_get_disjoint_hints_and_a_mixed_pair_is_flagged():
    """Code RT F5 at C0 (R3d 05-r2 had two literal subnets): each literal's hint names its own cidrsubnet index, so
    following both never produces CIDR_FACT_REUSED; a whole-range reference next to another subnet is flagged."""
    lits = TWO_SUBNETS.replace("var.subnet_cidr", '"10.0.0.0/24"', 1).replace(
        "  ip_cidr_range = var.subnet_cidr", '  ip_cidr_range = "10.1.0.0/24"')
    ds = _run({W + "network.tf": lits})
    assert [d.code for d in ds] == [CODE_LITERAL, CODE_LITERAL]
    assert "Set ip_cidr_range = cidrsubnet(var.subnet_cidr, 1, 0)" in ds[0].hint
    assert "Set ip_cidr_range = cidrsubnet(var.subnet_cidr, 1, 1)" in ds[1].hint
    mixed = TWO_SUBNETS.replace("var.subnet_cidr", '"10.0.0.0/24"', 1)
    dm = _run({W + "network.tf": mixed})
    assert [(d.code, d.block_address) for d in dm] == [
        (CODE_LITERAL, "google_compute_subnetwork.gce_spot_subnet"), (CODE_REUSED, "google_compute_subnetwork.gke_subnet")]
    assert "cidrsubnet(var.subnet_cidr, 1, 0)" in dm[0].hint and "cidrsubnet(var.subnet_cidr, 1, 1)" in dm[1].hint
    # a single subnet keeps the plain hint (byte-identical to before)
    [one] = _run({W + "network.tf": SUBNET_LITERAL})
    assert one.hint.startswith("Set ip_cidr_range = var.subnet_cidr . ")


def test_reused_fact_negatives_and_connector_hint():
    one = TWO_SUBNETS.split("\n\n")[0] + "\n"
    assert _run({W + "network.tf": one}) == []                                   # one use: fine
    assert _run({W + "network.tf": TWO_SUBNETS}, facts=None) == []                # no fact: V1b reports the var
    two_conn = CONNECTOR_REF + "\n" + CONNECTOR_REF.replace('"conn"', '"conn2"')
    ds = _run({W + "c.tf": two_conn})
    assert [d.code for d in ds] == [CODE_REUSED, CODE_REUSED]
    assert "cidrsubnet" not in ds[0].hint and "keep one google_vpc_access_connector" in ds[0].hint
    assert all(d.severity == "warning" for d in _run({W + "network.tf": TWO_SUBNETS}, existing_network=True))


# ------------------------------------------------------------------------------------------------ F6 / F7
def test_product_id_is_normalized_like_the_ipam_engine():
    """Code RT F6.2: the architect writes through CastorIPAMEngine (strip + lower); a reuse never misses its record."""
    db = _tx_db(_rec("10.100.3.0/24", "shop", PF.PURPOSE_SUBNET))
    before = _ledger(db)
    f = _provider(db).resolve(" Shop ", {PF.PURPOSE_SUBNET}, pool=POOL)
    assert f.subnet_cidr == "10.100.3.0/24" and f.product_id == "shop" and _ledger(db) == before
    m = PF.MemoryFactsProvider(ledger={("shop", PF.PURPOSE_SUBNET): "10.100.3.0/24"})
    assert m.resolve("SHOP", {PF.PURPOSE_SUBNET}, pool=POOL).subnet_cidr == "10.100.3.0/24"


def test_other_products_decommissioned_blocks_stay_occupied():
    """Code RT F7 M3: product A's RESERVED_DECOMMISSIONED block is never handed to product B, even under another
    prefix (a different document id): A may reclaim it and the ranges would overlap.
    FD-4BZ: a RELEASED record is free history, as in CastorIPAMEngine (the provider now allocates through it): its
    block is handed out again and its document replaced in the same transaction (before FD-4BZ the provider
    skipped it because it could only create())."""
    db = _tx_db(_rec("10.100.0.0/28", "a", PF.PURPOSE_CONNECTOR, status="RESERVED_DECOMMISSIONED"),
                _rec("10.100.1.0/24", "c", PF.PURPOSE_SUBNET, status="RELEASED"))
    f = _provider(db).resolve("b", {PF.PURPOSE_SUBNET}, pool=POOL)
    assert f.subnet_cidr == "10.100.1.0/24"
    assert _ledger(db)["10_100_0_0_28"]["status"] == "RESERVED_DECOMMISSIONED"
    assert (_ledger(db)["10_100_1_0_24"]["product_id"], _ledger(db)["10_100_1_0_24"]["status"]) == ("b", "ALLOCATED")
    assert sorted(_ledger(db)) == ["10_100_0_0_28", "10_100_1_0_24"]


def test_platform_declared_fact_name_is_not_read_as_the_ais_literal_holder():
    """Code RT F7 M1: when the platform declares subnet_cidr, `var.subnet_cidr` is the fact even if the AI also
    declared that name with a literal default (the splice replaces the AI's declaration)."""
    assert _run({W + "network.tf": NET_OK, W + "v.tf": AI_VARS}) == []


def test_module_source_with_interpolation_is_never_resolved():
    """Code RT F7 M9: an interpolated source can normalize onto the golden module path; it is not a literal path."""
    assert PF.module_dir("../modules/networking-vpc") == PF.NETWORK_MODULE_DIR
    assert PF.module_dir("./${var.x}/../../modules/networking-vpc") is None


# ------------------------------------------------------------------------------------------------ code RT 2 G1
# The RT2 P1 probe inverted: an LLM-authored root tfvars must never reach the committed tree (deploy_workload seeds
# the apply's root tfvars from this path since RT F1, so any key here would be honored at apply).
AI_TFVARS = ('memory_limit          = "8Gi"\ncpu_limit             = "4000m"\nallow_unauthenticated = true\n'
             'project_id            = "attacker-proj"\ngithub_repo_full_name = "evil/repo"\n'
             'network               = "attacker-vpc"\n')
AI_TFVARS_VALUES = ("8Gi", "4000m", "attacker-proj", "evil/repo", "attacker-vpc")
STORAGE_TF = ('resource "google_storage_bucket" "b" {\n  name = "${var.product_id}-b"\n  location = var.region\n'
              '  uniform_bucket_level_access = true\n}\n')  # V2e (S2-B B6): the compliant literal
BQ_TF = 'resource "google_bigquery_dataset" "d" {\n  dataset_id = "d"\n  location   = var.region\n}\n'


def _no_ai_value_in(tree):
    leaks = sorted((p, v) for p, text in tree.items() for v in AI_TFVARS_VALUES if v in text)
    assert leaks == [], leaks


def test_e2e_llm_tfvars_is_never_committed_when_the_platform_renders_no_lines():
    provider = PF.MemoryFactsProvider()
    agent, files = _generate(dict(APP, **{W + "terraform.tfvars": AI_TFVARS}), provider)
    assert agent.last_validation_report.status == "PASS"
    assert W + "terraform.tfvars" not in files
    _no_ai_value_in(files)
    assert agent.last_assembly_record.dropped == {W + "terraform.tfvars": "PLATFORM_PATH_RESERVED"}
    # the removal is the only effect: the tree equals the one assembled from the same draft without the AI file
    base_agent, base = _generate(dict(APP), PF.MemoryFactsProvider())
    assert files == base and base_agent.last_assembly_record.dropped == {}


def test_e2e_llm_tfvars_is_replaced_by_exactly_the_platform_lines():
    # S2-C (HS-63): storage is a foundation base API, so it is no longer repeated in additional_apis; a BigQuery
    # dataset is a type whose API the platform must add (exact table row), so the platform still renders one line.
    agent, files = _generate(dict(APP, **{W + "storage.tf": STORAGE_TF, W + "bq.tf": BQ_TF,
                                          W + "terraform.tfvars": AI_TFVARS}),
                             PF.MemoryFactsProvider())
    assert agent.last_validation_report.status == "PASS"
    assert files[W + "terraform.tfvars"] == 'additional_apis            = ["bigquery.googleapis.com"]\n'
    _no_ai_value_in(files)
    assert agent.last_assembly_record.dropped == {W + "terraform.tfvars": "PLATFORM_PATH_RESERVED"}


def test_e2e_llm_tfvars_cannot_override_the_ipam_fact_values():
    provider = PF.MemoryFactsProvider()
    ai = AI_TFVARS + 'subnet_cidr           = "10.0.0.0/8"\n'
    agent, files = _generate(dict(APP, **{W + "network.tf": NET_OK, W + "terraform.tfvars": ai}), provider)
    assert agent.last_validation_report.status == "PASS"
    assert hcl2.loads(files[W + "terraform.tfvars"]) == {"subnet_cidr": "10.100.0.0/24",
                                                          # S2-C (HS-63): exact API table for the declared types
                                                          "additional_apis": ["compute.googleapis.com"]}
    _no_ai_value_in(files)
    base_agent, base = _generate(dict(APP, **{W + "network.tf": NET_OK}), PF.MemoryFactsProvider())
    assert files == base


def test_e2e_no_llm_tfvars_records_no_drop():
    """Negative: without an AI file at the path nothing is removed or recorded (no tfvars is created either)."""
    agent, files = _generate(dict(APP), PF.MemoryFactsProvider())
    assert W + "terraform.tfvars" not in files and agent.last_assembly_record.dropped == {}

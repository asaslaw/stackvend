"""Row HOST-IPAM-RESERVATIONS (internal-ingress plan §3.3): host-platform address reservations in shared/ipam.py.

- PLATFORM_RESERVED_CIDRS holds HOST_RUN_EGRESS_SUBNET (/24) and HOST_PSC_GOOGLE_APIS (/32): canonical, RFC 1918,
  outside the default workload supernet, disjoint from each other and from the FD-4BR QA sandbox subnet;
- the allocator never hands out a reserved range, even when the supernet contains it;
- Do No Harm: with the default supernet the allocation order is unchanged;
- every ipam.py replica is byte-identical (tests/test_ipam_allocation_tx.py also checks it).
Hermetic: the in-memory Firestore fake (tests/ipam_fake_firestore.py).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import ipaddress
import os

import pytest

from ipam_fake_firestore import FakeFirestore, fake_transactional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPLICAS = [
    "shared/ipam.py",
    "apps/control-center/shared/ipam.py",
    "apps/orchestrator-gateway/shared/ipam.py",
    "apps/project-vending/shared/ipam.py",
    "mcp-servers/terraform/shared/ipam.py",
]
DEFAULT_SUPERNET = "10.100.0.0/16"
FD4BR_QA_SANDBOX_SUBNET = "10.254.0.0/26"   # unmerged branch fd-4br-egress; must stay disjoint


def _load(rel):
    name = "ipam_resv_" + rel.replace("/", "_").replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO_ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ipam = _load("shared/ipam.py")


def _engine(supernet):
    return ipam.CastorIPAMEngine(db=FakeFirestore(), supernet_cidr=supernet, transactional=fake_transactional)


def test_reservations_are_pinned():
    assert ipam.PLATFORM_RESERVED_CIDRS["HOST_RUN_EGRESS_SUBNET"] == "10.254.1.0/24"
    assert ipam.PLATFORM_RESERVED_CIDRS["HOST_PSC_GOOGLE_APIS"] == "10.254.2.10/32"


def test_reservations_are_canonical_private_and_disjoint():
    nets = {k: ipaddress.ip_network(v, strict=True) for k, v in ipam.PLATFORM_RESERVED_CIDRS.items()}
    assert {k: str(n) for k, n in nets.items()} == ipam.PLATFORM_RESERVED_CIDRS   # canonical text
    assert nets["HOST_RUN_EGRESS_SUBNET"].prefixlen == 24
    assert nets["HOST_PSC_GOOGLE_APIS"].prefixlen == 32
    rfc1918 = [ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    default = ipaddress.ip_network(DEFAULT_SUPERNET)
    qa = ipaddress.ip_network(FD4BR_QA_SANDBOX_SUBNET)
    for k, n in nets.items():
        assert any(n.subnet_of(r) for r in rfc1918), k
        assert not n.overlaps(default), k
        assert not n.overlaps(qa), k
    keys = sorted(nets)
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            assert not nets[a].overlaps(nets[b]), (a, b)


def test_default_allocation_order_is_unchanged():
    """Negative (Do No Harm): the reservations sit outside the default supernet, so the sequence is as before."""
    eng = _engine(DEFAULT_SUPERNET)
    got = [eng.allocate_next_cidr(f"svc-{i}", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28).cidr_block
           for i in range(4)]
    assert got == ["10.100.0.0/28", "10.100.0.16/28", "10.100.0.32/28", "10.100.0.48/28"]
    psa = eng.allocate_next_cidr("svc-0", purpose="PRIVATE_SERVICES_ACCESS", prefix_len=20).cidr_block
    assert psa == "10.100.16.0/20"


def test_reserved_ranges_are_never_allocated_from_a_supernet_that_contains_them():
    eng = _engine("10.254.0.0/16")
    got = []
    for i in range(40):   # /24s: 10.254.0.0, then skips 10.254.1.0 (egress) and 10.254.2.0 (holds the PSC /32)
        got.append(ipaddress.ip_network(
            eng.allocate_next_cidr(f"w-{i}", purpose="WORKLOAD_SUBNET", prefix_len=24).cidr_block))
    reserved = ipam.platform_reserved_networks()
    assert not any(g.overlaps(r) for g in got for r in reserved)
    assert [str(g) for g in got[:3]] == ["10.254.0.0/24", "10.254.3.0/24", "10.254.4.0/24"]


def test_a_supernet_that_is_only_reserved_is_exhausted():
    eng = _engine("10.254.1.0/24")
    with pytest.raises(ipam.IPAMPoolExhausted):
        eng.allocate_next_cidr("w", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)


def test_reservations_hold_no_ledger_row():
    db = FakeFirestore()
    eng = ipam.CastorIPAMEngine(db=db, supernet_cidr="10.254.0.0/16", transactional=fake_transactional)
    eng.allocate_next_cidr("w", purpose="SERVERLESS_VPC_CONNECTOR", prefix_len=28)
    rows = db.store.get("cidr_allocations", {})
    assert len(rows) == 1


def test_replicas_are_byte_identical():
    blobs = {rel: open(os.path.join(REPO_ROOT, rel), "rb").read() for rel in REPLICAS}
    assert len(set(blobs.values())) == 1, sorted(blobs)

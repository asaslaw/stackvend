"""
Project Castor: Centralized VPC CIDR IPAM Ledger & Non-Overlapping Subnet Allocation Engine
Provides deterministic, mathematically disjoint IPv4 subnet allocation from the platform supernet pool,
with permanent reservations maintained across workload decommissioning lifecycles.
"""

import inspect
import ipaddress
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

try:
    from pydantic import BaseModel, Field
except ImportError:
    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None, **kwargs):
            self.default = default
            self.default_factory = default_factory

        def get_value(self):
            if self.default_factory is not None:
                return self.default_factory()
            return self.default

    class MockBaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

        def dict(self):
            return self.model_dump()

    def Field(default=None, default_factory=None, **kwargs):
        return MockFieldInfo(default=default, default_factory=default_factory)

    BaseModel = MockBaseModel

logger = logging.getLogger("castor-ipam")

# Host-platform address reservations (NOT workload allocations; no Firestore ledger row). They sit in the platform
# block 10.254.0.0/16, outside the default workload supernet (10.100.0.0/16), and are chosen here and nowhere else.
# The platform Terraform's variable defaults will equal them (pinned by a test when the host network Terraform lands);
# a tfvars value will still override them.
#   HOST_RUN_EGRESS_SUBNET: the /24 subnet of the host network `stackvend-host` that Direct VPC egress of every host
#   Cloud Run service and job uses (internal-ingress plan §3.3; about 200 IPs needed, a /24 holds 252).
#   HOST_PSC_GOOGLE_APIS: the /32 internal address of the Private Service Connect endpoint for Google APIs on
#   `stackvend-host` (Design B); outside every subnet range of that network.
# Both leave 10.254.0.0/26 free (planned for the QA sandbox subnet, FD-4BR, not merged). The allocator below never
# hands out a range that overlaps any of them, even when an operator's supernet setting contains the block
# (HOST-IPAM-RESERVATIONS).
PLATFORM_RESERVED_CIDRS: Dict[str, str] = {
    "HOST_RUN_EGRESS_SUBNET": "10.254.1.0/24",
    "HOST_PSC_GOOGLE_APIS": "10.254.2.10/32",
}


def platform_reserved_networks() -> List[Any]:
    """PLATFORM_RESERVED_CIDRS as ip_network objects (strict: a non-canonical value is a programming error)."""
    return [ipaddress.ip_network(c) for c in PLATFORM_RESERVED_CIDRS.values()]


class CidrStatus(str, Enum):
    ALLOCATED = "ALLOCATED"
    RESERVED_DECOMMISSIONED = "RESERVED_DECOMMISSIONED"
    RELEASED = "RELEASED"


class CidrAllocationRecord(BaseModel):
    cidr_block: str = Field(description="CIDR notation, e.g. 10.100.1.0/28")
    sanitized_id: str = Field(description="Sanitized document ID, e.g. 10_100_1_0_28")
    product_id: str = Field(description="Workload ID, e.g. payment-service")
    project_id: Optional[str] = Field(default=None, description="GCP child project ID")
    purpose: str = Field(default="SERVERLESS_VPC_CONNECTOR", description="SERVERLESS_VPC_CONNECTOR | WORKLOAD_SUBNET | PRIVATE_SERVICES_ACCESS")
    prefix_length: int = Field(default=28)
    network_name: str = Field(default="vpc-default")
    subnet_name: str = Field(default="sb-default")
    region: str = Field(default="us-central1")
    folder_id: Optional[str] = Field(default=None, description="Parent Google Cloud folder ID")
    status: CidrStatus = Field(default=CidrStatus.ALLOCATED)
    allocated_at: str = Field(default="", description="ISO 8601 creation timestamp")
    updated_at: str = Field(default="", description="ISO 8601 update timestamp")
    notes: Optional[str] = None


class IPAMError(RuntimeError):
    """A typed IPAM failure (row IPAM-1). An allocation never falls back to a guessed range: the caller stops with
    this error (fail closed). `code` is a stable machine-readable reason, also the message prefix."""

    code = "IPAM.ERROR"

    def __init__(self, message: str):
        super().__init__(f"{self.code}: {message}")


class IPAMUnavailable(IPAMError):
    """The ledger could not be read or written (no Firestore client, read outage, write or commit failure)."""

    code = "IPAM.UNAVAILABLE"


class IPAMContention(IPAMError):
    """Concurrent allocations kept conflicting until the bounded retries ran out. Nothing was written."""

    code = "IPAM.CONTENTION"


class IPAMLedgerCorrupt(IPAMError):
    """A live ledger record holds a range that does not parse, so the set of occupied ranges is unknown."""

    code = "IPAM.LEDGER_CORRUPT"


class IPAMPoolExhausted(IPAMError, ValueError):
    """No free block of the requested size is left in the supernet (still a ValueError, as before)."""

    code = "IPAM.POOL_EXHAUSTED"


# HTTP status that google.api_core Conflict errors carry as `.code` (both Aborted and AlreadyExists are Conflicts).
_CONFLICT_HTTP_STATUS = 409


def _is_conflict(exc: Optional[BaseException]) -> bool:
    return exc is not None and getattr(exc, "code", None) == _CONFLICT_HTTP_STATUS


def _is_contention(exc: Optional[BaseException]) -> bool:
    """google-cloud-firestore's "retries used up": a ValueError raised from the last Aborted (a Conflict)."""
    return isinstance(exc, ValueError) and _is_conflict(exc.__cause__)


def _default_transactional() -> Any:
    """google-cloud-firestore's `transactional` decorator: begin, run, commit, re-run on Aborted, roll back on error."""
    try:
        from google.cloud.firestore_v1.transaction import transactional
    except Exception as e:  # noqa: BLE001
        raise IPAMUnavailable(f"Firestore transaction support unavailable: {type(e).__name__}: {e}") from e
    if not inspect.isfunction(transactional):
        raise IPAMUnavailable("Firestore transaction support unavailable (google.cloud.firestore_v1 is not loaded)")
    return transactional


class CastorIPAMEngine:
    """
    Centralized IP Address Management (IPAM) engine for Project Castor.
    Allocates non-overlapping CIDR blocks from a platform supernet pool and
    guarantees permanent reservation across workload decommissioning lifecycles.
    """

    # Bounded retries for one allocation: Firestore re-runs the transaction on Aborted up to this many times, and a
    # create() that loses a race (AlreadyExists) re-runs the whole allocation up to this many times.
    MAX_TRANSACTION_ATTEMPTS = 5

    def __init__(self, db=None, supernet_cidr: str = "10.100.0.0/16", transactional: Any = None):
        self.db = db
        self.supernet_cidr = supernet_cidr
        self.supernet = ipaddress.ip_network(supernet_cidr)
        # Transaction runner with google-cloud-firestore's `transactional` contract; None = the real one.
        self._transactional = transactional

    @staticmethod
    def sanitize_cidr(cidr_block: str) -> str:
        """Converts CIDR e.g. 10.100.1.0/28 into safe Firestore key 10_100_1_0_28."""
        return cidr_block.strip().replace(".", "_").replace("/", "_")

    def list_allocations(self, include_decommissioned: bool = True) -> List[CidrAllocationRecord]:
        """Fetches active and optionally decommissioned CIDR blocks from Firestore."""
        if not self.db:
            return []
        try:
            coll_ref = self.db.collection("cidr_allocations")
            docs = coll_ref.stream()
            records = []
            for doc in docs:
                data = doc.to_dict() or {}
                status_val = data.get("status", CidrStatus.ALLOCATED)
                if not include_decommissioned and status_val == CidrStatus.RESERVED_DECOMMISSIONED:
                    continue
                if status_val == CidrStatus.RELEASED:
                    continue
                try:
                    records.append(CidrAllocationRecord(**data))
                except Exception:
                    pass
            return records
        except Exception as e:
            # Row IPAM-1: a read error is never an empty ledger (an empty answer lets a caller hand out a used range).
            logger.error(f"Error listing CIDR allocations from Firestore: {e}")
            raise IPAMUnavailable(f"ledger read failed: {type(e).__name__}: {e}") from e

    def check_overlap(
        self, candidate_cidr: str, existing_records: Optional[List[CidrAllocationRecord]] = None
    ) -> Tuple[bool, Optional[CidrAllocationRecord]]:
        """Checks if a candidate CIDR overlaps with any active or preserved record."""
        candidate = ipaddress.ip_network(candidate_cidr.strip())
        records = existing_records if existing_records is not None else self.list_allocations(include_decommissioned=True)
        for record in records:
            if record.status in [CidrStatus.ALLOCATED, CidrStatus.RESERVED_DECOMMISSIONED]:
                existing_net = ipaddress.ip_network(record.cidr_block)
                if candidate.overlaps(existing_net):
                    return True, record
        return False, None

    def allocate_next_cidr(
        self,
        product_id: str,
        purpose: str = "SERVERLESS_VPC_CONNECTOR",
        prefix_len: int = 28,
        region: str = "us-central1",
        project_id: Optional[str] = None,
        folder_id: Optional[str] = None,
        network_name: Optional[str] = None,
        subnet_name: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> CidrAllocationRecord:
        """
        Allocates the next available mathematically non-overlapping CIDR block from the supernet.
        If the workload already has an existing allocation or preserved decommissioned allocation
        for this purpose, it reclaims and returns that exact CIDR without re-allocating.

        Row IPAM-1: the ledger read and the write of the record run in one Firestore transaction (a new record is
        create()d, never written over another), retried a bounded number of times on contention. Every failure
        raises an IPAMError subclass: there is no allocation without a ledger and no guessed range.

        FD-4BZ: this is the only allocator of the `cidr_allocations` ledger; the architect stage and the developer
        stage's lane 11 facts provider both call it, so their allocations are serialized by the same transaction.
        `notes` (optional) is stored on a newly created record only.
        """
        return self._allocate_or_reuse(product_id, purpose, prefix_len, region, project_id, folder_id,
                                       network_name, subnet_name, notes, create=True)

    def reuse_existing_cidr(
        self,
        product_id: str,
        purpose: str = "SERVERLESS_VPC_CONNECTOR",
        project_id: Optional[str] = None,
        folder_id: Optional[str] = None,
    ) -> Optional[CidrAllocationRecord]:
        """FD-4BZ: reuse-only. Returns this workload's ALLOCATED record for the purpose, or reclaims its
        RESERVED_DECOMMISSIONED one (in the same transaction as allocate_next_cidr); None when it has none. Never
        creates a record. Same typed errors as allocate_next_cidr."""
        return self._allocate_or_reuse(product_id, purpose, None, None, project_id, folder_id,
                                       None, None, None, create=False)

    def _allocate_or_reuse(
        self,
        product_id: str,
        purpose: str,
        prefix_len: Optional[int],
        region: Optional[str],
        project_id: Optional[str],
        folder_id: Optional[str],
        network_name: Optional[str],
        subnet_name: Optional[str],
        notes: Optional[str],
        *,
        create: bool,
    ) -> Optional[CidrAllocationRecord]:
        """The one ledger transaction behind allocate_next_cidr (create=True) and reuse_existing_cidr (create=False).
        `prefix_len` and `region` are only used when a new record is created."""
        if not self.db:
            raise IPAMUnavailable(f"no Firestore client; cannot allocate a {purpose} range for '{product_id}'")
        clean_pid = product_id.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        net_name = network_name or f"vpc-{clean_pid}"
        sb_name = subnet_name or (
            f"sb-{clean_pid}-connector" if purpose == "SERVERLESS_VPC_CONNECTOR"
            else f"sb-{clean_pid}-psa" if purpose == "PRIVATE_SERVICES_ACCESS"   # TI-5-F4
            else f"sb-{clean_pid}-primary"
        )
        try:
            coll_ref = self.db.collection("cidr_allocations")
        except Exception as e:  # noqa: BLE001
            raise IPAMUnavailable(f"ledger collection unavailable: {type(e).__name__}: {e}") from e
        transactional = self._transactional or _default_transactional()

        def _dump(rec: CidrAllocationRecord) -> Dict[str, Any]:
            dump_fn = getattr(rec, "model_dump", None) or getattr(rec, "dict", None)
            return dump_fn()

        def _allocate_in_transaction(transaction) -> Tuple[Optional[CidrAllocationRecord], bool]:
            """Returns (record, created). Every read precedes every write, as Firestore transactions require."""
            try:
                snapshots = [(snap.id, snap.to_dict() or {}) for snap in coll_ref.stream(transaction=transaction)]
            except Exception as e:  # noqa: BLE001
                if _is_conflict(e):
                    raise   # lock contention on the read: the bounded retry below runs the allocation again
                raise IPAMUnavailable(f"ledger read failed: {type(e).__name__}: {e}") from e

            # 1. Check if this workload already has an allocation for this purpose (idempotent reuse)
            for _doc_id, data in snapshots:
                if data.get("status", CidrStatus.ALLOCATED) not in (CidrStatus.ALLOCATED,
                                                                    CidrStatus.RESERVED_DECOMMISSIONED):
                    continue
                try:
                    rec = CidrAllocationRecord(**data)
                except Exception:  # noqa: BLE001  (a malformed record never matches; its range stays occupied below)
                    continue
                if rec.product_id == clean_pid and rec.purpose == purpose:
                    if rec.status == CidrStatus.RESERVED_DECOMMISSIONED:
                        # Reclaim preserved allocation
                        rec.status = CidrStatus.ALLOCATED
                        rec.updated_at = now_iso
                        if project_id:
                            rec.project_id = project_id
                        if folder_id:
                            rec.folder_id = folder_id
                        transaction.set(coll_ref.document(rec.sanitized_id), _dump(rec), merge=True)
                        logger.info(f"Reclaimed preserved CIDR {rec.cidr_block} for workload '{clean_pid}'")
                    return rec, False

            if not create:
                return None, False   # reuse-only: this workload holds no range for the purpose; nothing is written

            # 2. Every record that is not RELEASED occupies its range; an unparseable range stops the allocation
            occupied_networks = []
            for doc_id, data in snapshots:
                if data.get("status", CidrStatus.ALLOCATED) == CidrStatus.RELEASED:
                    continue
                try:
                    occupied_networks.append(ipaddress.ip_network(str(data.get("cidr_block") or "").strip()))
                except ValueError as e:
                    raise IPAMLedgerCorrupt(f"record {doc_id} has an unparseable range: {e}") from e

            # Host-platform reservations are always occupied (they hold no ledger row; a supernet may contain them)
            occupied_networks.extend(n for n in platform_reserved_networks() if n.version == self.supernet.version)

            # 3. Iterate through subnets of size prefix_len in the supernet
            chosen_net = None
            for candidate in self.supernet.subnets(new_prefix=prefix_len):
                if not any(candidate.overlaps(occ) for occ in occupied_networks):
                    chosen_net = candidate
                    break
            if not chosen_net:
                raise IPAMPoolExhausted(
                    f"IPAM pool exhausted: No free /{prefix_len} subnets available in supernet {self.supernet_cidr}"
                )

            cidr_str = str(chosen_net)
            sanitized_id = self.sanitize_cidr(cidr_str)
            record = CidrAllocationRecord(
                cidr_block=cidr_str,
                sanitized_id=sanitized_id,
                product_id=clean_pid,
                project_id=project_id or clean_pid,
                purpose=purpose,
                prefix_length=prefix_len,
                network_name=net_name,
                subnet_name=sb_name,
                region=region,
                folder_id=folder_id,
                status=CidrStatus.ALLOCATED,
                allocated_at=now_iso,
                updated_at=now_iso,
                notes=notes,
            )
            doc_ref = coll_ref.document(sanitized_id)
            if any(doc_id == sanitized_id for doc_id, _d in snapshots):
                # Only a RELEASED record (free history) can sit at a free block's id; it was read in this transaction
                transaction.set(doc_ref, _dump(record))
            else:
                transaction.create(doc_ref, _dump(record))   # precondition: the document does not exist yet
            return record, True

        for attempt in range(1, self.MAX_TRANSACTION_ATTEMPTS + 1):
            try:
                transaction = self.db.transaction(max_attempts=self.MAX_TRANSACTION_ATTEMPTS)
                record, created = transactional(_allocate_in_transaction)(transaction)
                break
            except IPAMError:
                raise
            except Exception as e:  # noqa: BLE001
                original = e
                ctx = e.__context__
                if not (_is_conflict(e) or _is_contention(e)) and (
                        isinstance(ctx, IPAMError) or _is_conflict(ctx) or _is_contention(ctx)):
                    # google-cloud-firestore rolls back on every error; a failed rollback replaces the original error
                    # (kept only as __context__). Classify by the original so the retry or the typed code survives.
                    logger.warning(f"IPAM transaction rollback failed for '{clean_pid}': {type(e).__name__}: {e}")
                    original = ctx
                if isinstance(original, IPAMError):
                    raise original
                if _is_conflict(original):
                    # create() lost a race to another writer (AlreadyExists): read the ledger again and choose again
                    logger.warning(f"IPAM allocation conflict for '{clean_pid}' (attempt {attempt}): {original}")
                    continue
                if _is_contention(original):
                    # google-cloud-firestore: the commit was Aborted on every one of the transaction's attempts
                    raise IPAMContention(
                        f"transaction aborted on every attempt for '{clean_pid}': {original}") from original
                raise IPAMUnavailable(f"ledger transaction failed: {type(e).__name__}: {e}") from e
        else:
            raise IPAMContention(
                f"no {purpose} range for '{clean_pid}' after {self.MAX_TRANSACTION_ATTEMPTS} conflicting attempts"
            )

        if not created:
            return record

        cidr_str = record.cidr_block
        # Update summary metadata on workloads/{product_id} (best effort, after the ledger commit)
        try:
            wl_ref = self.db.collection("workloads").document(clean_pid)
            wl_doc = wl_ref.get()
            if wl_doc.exists:
                net_meta = (wl_doc.to_dict() or {}).get("network", {})
                if purpose == "SERVERLESS_VPC_CONNECTOR":
                    net_meta["connector_cidr"] = cidr_str
                    net_meta["connector_subnet"] = sb_name
                elif purpose == "PRIVATE_SERVICES_ACCESS":   # TI-5-F4: never overwrites the subnet's summary
                    net_meta["psa_cidr"] = cidr_str
                else:
                    net_meta["subnet_cidr"] = cidr_str
                    net_meta["subnet_name"] = sb_name
                net_meta["vpc_name"] = net_name
                net_meta["status"] = "ALLOCATED"
                wl_ref.set({"network": net_meta}, merge=True)
        except Exception as wle:
            logger.warning(f"Could not update workload network metadata: {wle}")

        logger.info(f"Allocated CIDR {cidr_str} for workload '{clean_pid}' ({purpose})")
        return record

    def mark_workload_decommissioned(self, product_id: str, operator_email: str = "system") -> int:
        """Transitions all CIDRs for a workload to RESERVED_DECOMMISSIONED, preserving them in the ledger."""
        clean_pid = product_id.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        records = self.list_allocations(include_decommissioned=False)
        count = 0
        for rec in records:
            if rec.product_id == clean_pid and rec.status == CidrStatus.ALLOCATED:
                rec.status = CidrStatus.RESERVED_DECOMMISSIONED
                rec.updated_at = now_iso
                rec.notes = f"Decommissioned by {operator_email} at {now_iso}; reserved for redeployment."
                if self.db:
                    doc_ref = self.db.collection("cidr_allocations").document(rec.sanitized_id)
                    dump_fn = getattr(rec, "model_dump", None) or getattr(rec, "dict", None)
                    doc_ref.set(dump_fn(), merge=True)
                count += 1

        if count > 0 and self.db:
            try:
                wl_ref = self.db.collection("workloads").document(clean_pid)
                wl_doc = wl_ref.get()
                if wl_doc.exists:
                    doc_dict = wl_doc.to_dict() or {}
                    if "network" in doc_dict:
                        net_meta = doc_dict["network"] or {}
                        net_meta["status"] = "RESERVED_DECOMMISSIONED"
                        wl_ref.set({"network": net_meta}, merge=True)
            except Exception as wle:
                logger.warning(f"Could not update workload network metadata on decommission: {wle}")

        logger.info(f"Marked {count} CIDRs as RESERVED_DECOMMISSIONED for workload '{clean_pid}'")
        return count

    def reclaim_workload_cidrs(self, product_id: str, new_project_id: str) -> List[CidrAllocationRecord]:
        """Reclaims preserved CIDRs back to ALLOCATED status upon workload redeployment."""
        clean_pid = product_id.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        records = self.list_allocations(include_decommissioned=True)
        reclaimed = []
        for rec in records:
            if rec.product_id == clean_pid and rec.status == CidrStatus.RESERVED_DECOMMISSIONED:
                rec.status = CidrStatus.ALLOCATED
                rec.project_id = new_project_id
                rec.updated_at = now_iso
                rec.notes = f"Reclaimed for redeployment in {new_project_id} at {now_iso}."
                if self.db:
                    doc_ref = self.db.collection("cidr_allocations").document(rec.sanitized_id)
                    dump_fn = getattr(rec, "model_dump", None) or getattr(rec, "dict", None)
                    doc_ref.set(dump_fn(), merge=True)
                reclaimed.append(rec)

        if reclaimed and self.db:
            try:
                wl_ref = self.db.collection("workloads").document(clean_pid)
                wl_doc = wl_ref.get()
                if wl_doc.exists:
                    doc_dict = wl_doc.to_dict() or {}
                    if "network" in doc_dict:
                        net_meta = doc_dict["network"] or {}
                        net_meta["status"] = "ALLOCATED"
                        wl_ref.set({"network": net_meta}, merge=True)
            except Exception as wle:
                logger.warning(f"Could not update workload network metadata on reclaim: {wle}")

        logger.info(f"Reclaimed {len(reclaimed)} CIDRs for workload '{clean_pid}' into project '{new_project_id}'")
        return reclaimed

    def release_workload_cidrs(self, product_id: str, operator_email: str = "system") -> int:
        """Permanently releases CIDRs back to the available pool upon workload purge."""
        clean_pid = product_id.strip().lower()
        records = self.list_allocations(include_decommissioned=True)
        count = 0
        for rec in records:
            if rec.product_id == clean_pid:
                if self.db:
                    doc_ref = self.db.collection("cidr_allocations").document(rec.sanitized_id)
                    doc_ref.delete()
                count += 1
        logger.info(f"Permanently released {count} CIDRs for purged workload '{clean_pid}'")
        return count

    def get_pool_statistics(self) -> Dict[str, Any]:
        """Calculates IPAM pool capacity, allocated count, reserved count, and utilization percentage."""
        records = self.list_allocations(include_decommissioned=True)
        allocated_count = sum(1 for r in records if r.status == CidrStatus.ALLOCATED)
        reserved_count = sum(1 for r in records if r.status == CidrStatus.RESERVED_DECOMMISSIONED)

        supernet_prefix = self.supernet.prefixlen
        total_28_blocks = 2 ** (28 - supernet_prefix)
        used_blocks = allocated_count + reserved_count
        available_blocks = max(0, total_28_blocks - used_blocks)
        utilization_pct = round((used_blocks / total_28_blocks) * 100, 2) if total_28_blocks > 0 else 0.0

        return {
            "supernet_cidr": self.supernet_cidr,
            "total_capacity_slash_28": total_28_blocks,
            "allocated_count": allocated_count,
            "reserved_decommissioned_count": reserved_count,
            "available_count": available_blocks,
            "utilization_pct": utilization_pct,
            "total_records": len(records),
        }

"""
FD-7L Phase 3 (plan 2.9): which bucket holds a workload's OpenTofu state, for the Control Center's state readers
(resources view, FinOps spend sync).

Shared install (operative mode PLATFORM: `STACKVEND_TF_RUNNER_IDENTITY` unset / PLATFORM and no Per-workload Settings
record, FD-7L-F4): the caller's platform bucket, exactly as before; no provenance is read. Per-workload install: vending's signed provenance record (guard database) decides. A READY record
names the workload's own bucket; while there is no record or it is not READY, the platform bucket. A record whose
vending signature does not verify (the Control Center SA can itself write the guard database) raises
RunnerIdentityError; the readers report it and never fall back to another bucket.
"""
import logging
import os
from typing import Any, Callable, Dict, Mapping, Optional

from shared import runner_identity as ri

logger = logging.getLogger("control-center-runner-state")

_cert_fetcher: Optional[Callable[..., Mapping[str, str]]] = None

# Test seams (None = the real guard database and Google's published certificates).
guard_db_provider: Optional[Callable[[], Any]] = None
certs_provider: Optional[Callable[..., Mapping[str, str]]] = None


def _certs() -> Callable[..., Mapping[str, str]]:
    global _cert_fetcher
    if certs_provider is not None:
        return certs_provider
    if _cert_fetcher is None:
        _cert_fetcher = ri.X509CertFetcher()
    return _cert_fetcher


def _guard_db():
    if guard_db_provider is not None:
        return guard_db_provider()
    from db import get_guard_db
    return get_guard_db()


def _mode_guard_db():
    """The guard database for the operative-mode read; None when none is configured (ri then reads nothing). A
    configured guard database that cannot be opened is a typed 503, never the default database."""
    if not (os.getenv(ri.GUARD_DB_ENV) or "").strip():
        return None
    gdb = _guard_db()
    if gdb is None:
        raise ri.RunnerIdentityError("RUNNER_STORE_UNAVAILABLE", "the guard database is unavailable",
                                     stage="runner-identity-mode", http_status=503)
    return gdb


def operative_mode() -> str:
    """FD-7L-n / FD-7L-F4: the operative mode through the one shared reader (declaration, then vending's signed
    Settings record). Raises RunnerIdentityError (typed; 503 for a declaration or record that cannot be used)."""
    return ri.runner_identity_mode(guard_db=_mode_guard_db(), certs=_certs())


def per_workload() -> bool:
    return operative_mode() == ri.MODE_PER_WORKLOAD


def state_location(product_id: str, legacy_bucket: str) -> Dict[str, Any]:
    """{"bucket", "prefix", "source", "status"}; Shared install -> the legacy bucket without any read."""
    if not per_workload():
        return {"bucket": legacy_bucket, "prefix": ri.state_prefix(product_id), "source": "platform",
                "status": None}
    gdb = _guard_db()
    if gdb is None:
        raise ri.RunnerIdentityError("RUNNER_STORE_UNAVAILABLE", "the guard database is unavailable", http_status=503)
    try:
        snap = gdb.collection(ri.PROVENANCE_COLLECTION).document(product_id).get()
    except Exception as e:  # noqa: BLE001
        raise ri.RunnerIdentityError("RUNNER_STORE_UNAVAILABLE", f"provenance unreadable ({type(e).__name__})",
                                     http_status=503) from None
    prov = snap.to_dict() if getattr(snap, "exists", False) is True else None
    return ri.state_location(product_id, prov, legacy_bucket=legacy_bucket,
                             expected_signer=ri.expected_broker_email(), certs=_certs())


def state_bucket(product_id: str, legacy_bucket: str) -> str:
    return state_location(product_id, legacy_bucket)["bucket"]

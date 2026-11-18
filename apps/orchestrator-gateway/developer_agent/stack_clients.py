"""Production implementations behind the hallucination-stack runtime (Step 1 S1-B; lane 8B §7-§8):

- HttpValidateClient   V1b client for the terraform server's POST /validate and GET /validate/ready
- FirestoreLedgerStore pipeline_executions/{trace}.repair (per-trace repair budget, RT F2)
- FirestoreProvenanceStore workloads/{product_id}.iac_provenance (prior-run LLM IaC files, I-20)
- FirestoreFactsProvider cidr_allocations (IPAM network facts the workload IaC must reference, lane 11 near-term)

Every failure is explicit: the client answers UNAVAILABLE (never PASS), the stores raise StoreUnavailable (the
developer stage then stops with GATE_UNAVAILABLE before spending). Installed once by gateway startup (main.py).
"""
from __future__ import annotations

import logging
import os
import runtime_env  # G1: on_cloud_run() = service or stage-runner job (never K_SERVICE alone)
from typing import Any, Callable, Dict, Mapping, Optional

try:
    from shared.diagnostics import ProvenanceEntry, RepairLedger, StoreUnavailable
except ImportError:  # pragma: no cover
    from ..shared.diagnostics import ProvenanceEntry, RepairLedger, StoreUnavailable  # type: ignore

logger = logging.getLogger("castor-hallucination-stack")

VALIDATE_HTTP_TIMEOUT_S = 75   # the server's own budget is 60 s
# One /validate/ready probe (owner 10-13 bounded wait): short, so a probe stuck on a cold instance counts as one
# not-ready answer and the gateway's ~180 s wait stays bounded (worst case: wait + one probe).
READY_HTTP_TIMEOUT_S = 30


class HttpValidateClient:
    name = "http"

    def __init__(self, url_resolver: Callable[[], str], *, timeout_s: float = VALIDATE_HTTP_TIMEOUT_S,
                 ready_timeout_s: float = READY_HTTP_TIMEOUT_S,
                 token_fetcher: Optional[Callable[[str], str]] = None, http_factory: Optional[Callable[..., Any]] = None):
        self._resolve = url_resolver
        self.timeout_s = timeout_s
        self.ready_timeout_s = ready_timeout_s
        self._token_fetcher = token_fetcher
        self._http_factory = http_factory

    def _headers(self, base: str) -> Dict[str, str]:
        from compliance_agent.handler import id_token_audience
        audience = id_token_audience(base)
        if audience is None:
            if runtime_env.on_cloud_run():
                raise RuntimeError(f"terraform server URL {base!r} is not an https Cloud Run URL (no tokenless calls)")
            return {}
        fetch = self._token_fetcher or _fetch_id_token
        return {"Authorization": f"Bearer {fetch(audience)}"}

    def _client(self, timeout_s: Optional[float] = None):
        timeout = self.timeout_s if timeout_s is None else timeout_s
        if self._http_factory is not None:
            return self._http_factory(timeout=timeout, follow_redirects=False)
        import httpx
        return httpx.Client(timeout=timeout, follow_redirects=False)

    def ready(self, iac_engine: str = "OPENTOFU") -> Dict[str, Any]:
        try:
            base = self._resolve().rstrip("/")
            with self._client(self.ready_timeout_s) as c:
                res = c.get(f"{base}/validate/ready", params={"iac_engine": iac_engine}, headers=self._headers(base))
            if res.status_code != 200:
                return {"ready": False, "reason": f"HTTP {res.status_code}"}
            body = res.json()
            return body if isinstance(body, dict) else {"ready": False, "reason": "invalid ready body"}
        except Exception as e:  # noqa: BLE001
            return {"ready": False, "reason": f"{type(e).__name__}: {e}"}

    def validate(self, files: Mapping[str, str], *, iac_engine: str = "OPENTOFU", trace_id: str = "") -> Dict[str, Any]:
        try:
            base = self._resolve().rstrip("/")
            with self._client() as c:
                res = c.post(f"{base}/validate", json={"files": dict(files), "iac_engine": iac_engine,
                                                       "trace_id": trace_id or None},
                             headers=self._headers(base))
            if res.status_code != 200:
                return {"status": "UNAVAILABLE", "reason": f"HTTP {res.status_code}", "diagnostics": []}
            body = res.json()
            if not isinstance(body, dict) or body.get("status") not in ("PASS", "FAIL", "UNAVAILABLE"):
                return {"status": "UNAVAILABLE", "reason": "invalid /validate body", "diagnostics": []}
            return body
        except Exception as e:  # noqa: BLE001 - never a PASS
            return {"status": "UNAVAILABLE", "reason": f"{type(e).__name__}: {e}", "diagnostics": []}


def _fetch_id_token(audience: str) -> str:  # pragma: no cover - Cloud Run metadata server
    from google.auth.transport.requests import Request as GoogleAuthRequest
    from google.oauth2 import id_token as google_id_token
    token = google_id_token.fetch_id_token(GoogleAuthRequest(), audience)
    if not isinstance(token, str) or not token:
        raise RuntimeError("the metadata server returned an empty ID token")
    return token


class FirestoreLedgerStore:
    def __init__(self, db: Any):
        self.db = db

    def load(self, trace_id: str) -> Optional[RepairLedger]:
        try:
            snap = self.db.collection("pipeline_executions").document(trace_id).get()
            data = (snap.to_dict() or {}) if snap.exists else {}
            raw = data.get("repair")
            return RepairLedger.model_validate(raw) if isinstance(raw, dict) else None
        except Exception as e:  # noqa: BLE001
            raise StoreUnavailable(f"repair ledger read failed for {trace_id}: {type(e).__name__}: {e}") from e

    def save(self, ledger: RepairLedger) -> None:
        try:
            self.db.collection("pipeline_executions").document(ledger.trace_id).set(
                {"repair": ledger.model_dump(mode="json")}, merge=True)
        except Exception as e:  # noqa: BLE001
            raise StoreUnavailable(f"repair ledger write failed for {ledger.trace_id}: {type(e).__name__}: {e}") from e


class FirestoreProvenanceStore:
    def __init__(self, db: Any):
        self.db = db

    def load(self, product_id: str) -> Dict[str, ProvenanceEntry]:
        try:
            snap = self.db.collection("workloads").document(product_id).get()
            data = (snap.to_dict() or {}) if snap.exists else {}
            raw = data.get("iac_provenance") or {}
            return {p: ProvenanceEntry.model_validate(v) for p, v in raw.items() if isinstance(v, dict)}
        except Exception as e:  # noqa: BLE001
            raise StoreUnavailable(f"IaC provenance read failed for {product_id}: {type(e).__name__}: {e}") from e

    def save(self, product_id: str, entries: Dict[str, ProvenanceEntry]) -> None:
        try:
            self.db.collection("workloads").document(product_id).set(
                {"iac_provenance": {p: e.model_dump(mode="json") for p, e in entries.items()}},
                merge=["iac_provenance"])
        except Exception as e:  # noqa: BLE001
            raise StoreUnavailable(f"IaC provenance write failed for {product_id}: {type(e).__name__}: {e}") from e


class FirestoreFactsProvider:
    """Lane 11 near-term: the workload's IPAM network facts from the platform ledger `cidr_allocations` (the
    collection shared/ipam.py writes and the Control Center reads), fail-closed.

    FD-4BZ: every ledger read and write goes through `shared.ipam.CastorIPAMEngine` (row IPAM-1's transactional
    allocator), the same allocator the architect stage uses. A purpose this workload already holds is reused (a
    RESERVED_DECOMMISSIONED record is reclaimed); otherwise the engine creates the first free block of the pool in
    the same transaction that read the ledger, so this stage and the architect stage can never take overlapping
    ranges. Every engine error (`IPAMError`: unavailable, contention, corrupt ledger, pool exhausted) becomes
    FactsUnavailable with the engine's code (the stage stops with GATE_UNAVAILABLE); nothing is skipped or
    defaulted."""

    name = "firestore"
    COLLECTION = "cidr_allocations"
    NOTES = "allocated by the developer stage for the workload IaC (lane 11 near-term)"

    def __init__(self, db: Any, *, transactional: Any = None):
        self.db = db
        # google-cloud-firestore's `transactional` contract; None = the real one (CastorIPAMEngine's default)
        self._transactional = transactional

    def _engine(self, pool: Any) -> Any:
        try:
            from shared.ipam import CastorIPAMEngine
        except ImportError:  # pragma: no cover
            from ..shared.ipam import CastorIPAMEngine  # type: ignore
        return CastorIPAMEngine(db=self.db, supernet_cidr=str(pool.supernet), transactional=self._transactional)

    def resolve(self, product_id: str, purposes: Any, *, pool: Any, project_id: str = "",
                allocate: bool = True) -> Any:
        """`allocate=False` (existing network, code RT F3): reuse-only. This product's ALLOCATED records are
        returned (a RESERVED_DECOMMISSIONED one is still reclaimed: it is this workload's own range); a purpose with
        no record gets no fact, and nothing is ever created."""
        from .platform_facts import FACT_VARIABLE, PURPOSES, FactsUnavailable, NetworkFacts, normalize_product_id
        try:
            from shared.ipam import IPAMError
        except ImportError:  # pragma: no cover
            from ..shared.ipam import IPAMError  # type: ignore
        if self.db is None:
            raise FactsUnavailable("IPAM.UNAVAILABLE: no Firestore client")
        # code RT F6.2: the architect writes through CastorIPAMEngine, which lowercases; compare the same way
        product_id = normalize_product_id(product_id)
        wanted = set(purposes)
        values: Dict[str, str] = {}
        try:
            engine = self._engine(pool)
            for purpose in PURPOSES:
                if purpose not in wanted:
                    continue
                if allocate:
                    rec = engine.allocate_next_cidr(product_id, purpose=purpose, prefix_len=pool.prefix_for(purpose),
                                                    region=pool.region, project_id=project_id or None,
                                                    notes=self.NOTES)
                else:
                    rec = engine.reuse_existing_cidr(product_id, purpose=purpose, project_id=project_id or None)
                    if rec is None:
                        continue   # reuse-only: no record for this purpose -> no fact, nothing written
                values[FACT_VARIABLE[purpose]] = str(rec.cidr_block)
        except IPAMError as e:   # the message starts with the engine's code (IPAM.UNAVAILABLE, IPAM.CONTENTION, ...)
            raise FactsUnavailable(str(e)) from e
        except ValueError as e:   # an engine argument the pool settings made invalid (e.g. an unparseable supernet)
            raise FactsUnavailable(f"IPAM.UNAVAILABLE: IPAM pool unusable: {e}") from e
        try:
            return NetworkFacts(product_id=product_id, region=pool.region, source="ipam", **values)
        except ValueError as e:
            raise FactsUnavailable(f"IPAM.LEDGER_CORRUPT: {e}") from e

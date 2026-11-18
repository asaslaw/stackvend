"""
StackVend: Infrastructure Rollback & Disaster Recovery Engine
Restores a workload's OpenTofu remote state (GCS) to a previous object generation and records the real outcome.

FD-4AV-a (owner row FD-4AV-a, 10-20): every outcome is reported as what actually happened.
  * REVERTED              a previous state generation was copied over the live state (the only success).
  * NO_PREVIOUS_VERSION   fewer than two state generations exist; nothing is copied (the live state is never
                          "restored" onto itself).
  * ROLLBACK_UNAVAILABLE  no GCS client, no state bucket, or the bucket is not versioned (a restore would be
                          irreversible); no history is fabricated and nothing is copied.
  * REFUSED_STATE_LOCKED  the OpenTofu GCS-backend lock object (``workloads/<pid>/default.tflock``, next to
                          ``default.tfstate``; backend prefix ``workloads/<pid>``, workspace ``default``) exists, or
                          the live state changed between listing and copy; nothing is (or was) copied.
  * SUPERSEDED            (FD-4AV-b) the copy ran, but the re-check right after it found that the restore is not (or
                          may not stay) the live state: the live generation is no longer the copy's generation (a
                          concurrent apply wrote over it), or the state lock is held (a concurrent OpenTofu run may
                          write over it). Never reported as REVERTED.
  * ROLLBACK_FAILED       listing, the lock check or the copy raised, there is no live state object, or (FD-4AV-b)
                          the copy ran but could not be re-checked (``restore_unverified``: the outcome is unknown).
The lock check is advisory (RT F2): with the destination precondition it closes the write race, but not a tofu run
that takes the lock and reads the state after our check; FD-4AV-b's post-copy re-check reports that case as
SUPERSEDED. The engine only reads the lock object: it never creates or deletes a lock (FD-4H rule; owner 10-20
declined FD-4AV-a F2), and the only object it writes is the state object, through the generation-guarded copy.
The Firestore audit record ``rollback_events/{trace_id}`` carries the same ``status``.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from google.cloud import firestore, storage

from shared import runner_identity as ri   # FD-7L: this job's shared/ replica (byte-identical to root; no fallback)

logger = logging.getLogger("infra-rollback-job")
logging.basicConfig(level=logging.INFO)

REVERTED = "REVERTED"
NO_PREVIOUS_VERSION = "NO_PREVIOUS_VERSION"
ROLLBACK_UNAVAILABLE = "ROLLBACK_UNAVAILABLE"
REFUSED_STATE_LOCKED = "REFUSED_STATE_LOCKED"
ROLLBACK_FAILED = "ROLLBACK_FAILED"
SUPERSEDED = "SUPERSEDED"
ROLLBACK_OUTCOMES = (REVERTED, NO_PREVIOUS_VERSION, ROLLBACK_UNAVAILABLE, REFUSED_STATE_LOCKED, ROLLBACK_FAILED,
                     SUPERSEDED)


class RollbackUnavailable(Exception):
    """No GCS client or no state bucket: the engine cannot see the state at all."""


class InvalidRollbackRequest(ValueError):
    """The request itself is malformed (bad product id / trace id / generation, or a generation not in history)."""


class NoLiveState(Exception):
    """Only noncurrent state versions exist: there is no live object to restore over."""


class StateChangedDuringRollback(Exception):
    """The destination precondition (live generation) failed: someone wrote the state after we listed it."""


class RestoreUnverified(Exception):
    """FD-4AV-b: the copy ran but could not be re-checked (no generation returned, or the re-check read failed)."""

    def __init__(self, message: str, detail: Dict[str, Any]):
        super().__init__(message)
        self.detail = detail


def validate_product_id(product_id: Any) -> str:
    """The id becomes one GCS path component of ``workloads/<pid>/``: it must be exactly one non-empty component."""
    if not isinstance(product_id, str) or not product_id or product_id != product_id.strip() \
            or "/" in product_id or product_id in (".", ".."):
        raise InvalidRollbackRequest(f"invalid product_id {product_id!r}")
    return product_id


def validate_generation(generation: Any) -> str:
    """A GCS object generation is a positive decimal integer."""
    if not isinstance(generation, str) or not generation.isdecimal() or int(generation) <= 0:
        raise InvalidRollbackRequest(f"invalid target_generation {generation!r} (expected a GCS object generation)")
    return generation


def _is_precondition_failed(exc: BaseException) -> bool:
    """HTTP 412 from GCS (google.api_core.exceptions.PreconditionFailed has code 412). Typed field, no text match."""
    return getattr(exc, "code", None) == 412


class InfraRollbackEngine:
    def __init__(
        self,
        project_id: Optional[str] = None,
        state_bucket_name: Optional[str] = None,
        firestore_client: Optional[Any] = None,
        storage_client: Optional[Any] = None,
    ):
        self.project_id = project_id or os.getenv("PROJECT_ID", "")
        self.state_bucket_name = (
            state_bucket_name
            or os.getenv("TFSTATE_BUCKET", f"castor-tfstate-{self.project_id}" if self.project_id else "")
        )
        # FD-7L Phase 3 test seams (None = the guard database client / Google's published certificates on demand).
        self.guard_db: Optional[Any] = None
        self.certs: Optional[Any] = None

        # Firestore Client
        if firestore_client:
            self.db = firestore_client
        else:
            try:
                self.db = firestore.Client(project=self.project_id) if self.project_id else None
            except Exception as e:
                logger.warning(f"Could not initialize Firestore client for Rollback Engine: {e}")
                self.db = None

        # Google Cloud Storage Client
        if storage_client:
            self.storage = storage_client
        else:
            try:
                self.storage = storage.Client(project=self.project_id) if self.project_id else None
            except Exception as e:
                logger.warning(f"Could not initialize GCS client for Rollback Engine: {e}")
                self.storage = None

    def get_state_blob_path(self, product_id: str) -> str:
        """Returns the remote state file path within the central GCS bucket."""
        return f"workloads/{product_id}/default.tfstate"

    def get_state_lock_path(self, product_id: str) -> str:
        """The OpenTofu GCS backend lock object for workspace ``default`` under prefix ``workloads/<pid>``."""
        return f"workloads/{product_id}/default.tflock"

    def _bucket(self, bucket_name: Optional[str] = None):
        name = bucket_name or self.state_bucket_name
        if not self.storage or not name:
            raise RollbackUnavailable("no GCS client or no state bucket (TFSTATE_BUCKET / PROJECT_ID)")
        return self.storage.bucket(name)

    def resolve_state_bucket(self, product_id: str) -> str:
        """FD-7L Phase 3 (plan 2.9). Shared install (operative mode PLATFORM: STACKVEND_TF_RUNNER_IDENTITY unset /
        PLATFORM and no Per-workload Settings record, FD-7L-F4): the platform bucket, no provenance read. Per-workload
        install: the bucket named by vending's signed provenance record in the guard database
        (STACKVEND_GUARD_FIRESTORE_DATABASE); the platform bucket only while that record is not READY. A record that
        cannot be trusted, a mode that cannot be read, or a guard database that is not configured, raises
        RollbackUnavailable (nothing is copied; no other bucket is tried)."""
        guard_db = (os.getenv("STACKVEND_GUARD_FIRESTORE_DATABASE") or "").strip()
        try:
            mode_client = None
            if guard_db and getattr(self, "guard_db", None) is not None:
                mode_client = self.guard_db
            if ri.runner_identity_mode(guard_db=mode_client, certs=getattr(self, "certs", None)) \
                    != ri.MODE_PER_WORKLOAD:
                return self.state_bucket_name
        except ri.RunnerIdentityError as e:
            raise RollbackUnavailable(f"{e.code}: {e.detail}") from None
        if not guard_db:
            raise RollbackUnavailable("RUNNER_STORE_UNAVAILABLE: STACKVEND_GUARD_FIRESTORE_DATABASE is not set; the "
                                      "workload's state location cannot be read")
        try:
            client = self.guard_db if getattr(self, "guard_db", None) is not None else \
                firestore.Client(project=self.project_id, database=guard_db)
            snap = client.collection(ri.PROVENANCE_COLLECTION).document(product_id).get()
            prov = snap.to_dict() if getattr(snap, "exists", False) is True else None
            certs = getattr(self, "certs", None) or ri.X509CertFetcher()
            loc = ri.state_location(product_id, prov, legacy_bucket=self.state_bucket_name,
                                    expected_signer=ri.expected_broker_email(), certs=certs)
        except ri.RunnerIdentityError as e:
            raise RollbackUnavailable(f"{e.code}: {e.detail}") from None
        except Exception as e:  # noqa: BLE001 - guard database unreadable
            raise RollbackUnavailable(f"RUNNER_STORE_UNAVAILABLE: provenance unreadable ({type(e).__name__})") from None
        return loc["bucket"]

    def get_state_history(self, product_id: str, bucket_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists the state file's object generations, latest first.

        Raises RollbackUnavailable without a client/bucket and lets listing errors propagate: an unreadable history is
        never reported as an empty one.
        """
        blob_path = self.get_state_blob_path(validate_product_id(product_id))
        if bucket_name is None:
            bucket_name = self.resolve_state_bucket(product_id)
        bucket = self._bucket(bucket_name)
        versions = []
        for b in bucket.list_blobs(prefix=blob_path, versions=True):
            if b.name == blob_path:
                entry = {
                    "generation": str(b.generation),
                    "updated": b.updated.isoformat() if b.updated else "",
                    "size_bytes": b.size,
                    "etag": b.etag,
                    # RT L1: GCS sets timeDeleted only on noncurrent versions; the live object has none.
                    "live": getattr(b, "time_deleted", None) is None,
                }
                # FD-7L Phase 3 (plan 2.7): a migrated generation carries its original time in custom metadata.
                metadata = getattr(b, "metadata", None)
                if isinstance(metadata, dict) and isinstance(metadata.get("stackvend-source-updated"), str) \
                        and metadata["stackvend-source-updated"]:
                    entry["source_updated"] = metadata["stackvend-source-updated"]
                    entry["source_generation"] = metadata.get("stackvend-source-generation")
                versions.append(entry)
        versions.sort(key=lambda x: int(x["generation"]) if x["generation"].isdecimal() else 0, reverse=True)
        logger.info(f"Found {len(versions)} state versions for '{product_id}' in "
                    f"gs://{bucket_name or self.state_bucket_name}")
        return versions

    def is_state_locked(self, product_id: str, bucket_name: Optional[str] = None) -> bool:
        """True when the backend lock object exists. Read-only; errors propagate (the caller fails closed)."""
        return self._bucket(bucket_name).get_blob(self.get_state_lock_path(product_id)) is not None

    def revert_state_to_generation(
        self, product_id: str, target_generation: str, live_generation: Optional[str] = None,
        bucket_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Copies state generation ``target_generation`` over the live state object.

        ``source_generation`` makes GCS copy that old generation (without it the copy would copy the live object onto
        itself). ``live_generation`` (when given) is a destination precondition: if the state was written after it was
        listed, GCS answers 412 and StateChangedDuringRollback is raised; nothing is overwritten.
        """
        blob_path = self.get_state_blob_path(validate_product_id(product_id))
        validate_generation(target_generation)
        bucket = self._bucket(bucket_name)
        # RT F1: without object versioning the copy would overwrite the only copy of the live state. Read the
        # bucket's real metadata and refuse unless versioning is exactly True.
        bucket.reload()
        if getattr(bucket, "versioning_enabled", None) is not True:
            raise RollbackUnavailable("state bucket is not versioned; a restore would be irreversible")
        source_blob = bucket.get_blob(blob_path, generation=int(target_generation))
        if not source_blob:
            raise InvalidRollbackRequest(f"State generation {target_generation} not found for {blob_path}")
        kwargs: Dict[str, Any] = {"source_generation": int(target_generation)}
        if live_generation is not None:
            kwargs["if_generation_match"] = int(validate_generation(live_generation))
        try:
            copied = bucket.copy_blob(source_blob, bucket, blob_path, **kwargs)
        except Exception as e:
            if _is_precondition_failed(e):
                raise StateChangedDuringRollback(f"live state of '{product_id}' changed during the rollback") from e
            raise
        result: Dict[str, Any] = {
            "status": REVERTED,
            "product_id": product_id,
            "blob_path": blob_path,
            "restored_generation": target_generation,
            "replaced_generation": live_generation,
            "restored_at": datetime.now(timezone.utc).isoformat(),
        }
        # FD-4AV-b: re-check right after the copy (read-only: two get_blob calls, no lock is created or deleted).
        copied_generation = getattr(copied, "generation", None)
        if not isinstance(copied_generation, int) or isinstance(copied_generation, bool) or copied_generation <= 0:
            raise RestoreUnverified(f"the copy for '{product_id}' returned no object generation; the restore could not "
                                    f"be re-checked", dict(result, restore_unverified=True))
        result["copied_generation"] = str(copied_generation)
        try:
            live_after = bucket.get_blob(blob_path)
            lock_after = bucket.get_blob(self.get_state_lock_path(product_id))
        except Exception as e:
            raise RestoreUnverified(f"the restore of '{product_id}' could not be re-checked: {type(e).__name__}: {e}",
                                    dict(result, restore_unverified=True)) from e
        live_after_generation = getattr(live_after, "generation", None) if live_after is not None else None
        result["live_generation_after"] = None if live_after_generation is None else str(live_after_generation)
        superseded: List[str] = []
        if result["live_generation_after"] != result["copied_generation"]:
            superseded.append(f"the live state is generation {result['live_generation_after']}, not the restored copy "
                              f"{result['copied_generation']}: a concurrent write replaced the restore")
        if lock_after is not None:
            superseded.append(f"the state lock {self.get_state_lock_path(product_id)} is held after the restore: a "
                              f"concurrent OpenTofu run may write over it")
        if superseded:
            result.update(status=SUPERSEDED, superseded_reasons=superseded, message="; ".join(superseded))
            logger.warning(f"Restore of '{product_id}' from generation {target_generation} was superseded: "
                           f"{result['message']}")
            return result
        logger.info(f"Restored state for '{product_id}' from generation {target_generation}")
        return result

    def execute_rollback(
        self,
        product_id: str,
        trace_id: str,
        target_generation: Optional[str] = None,
        reason: str = "Deployment failure detected",
    ) -> Dict[str, Any]:
        """
        Restores the previous state generation (or ``target_generation``) and records the real outcome.

        Raises InvalidRollbackRequest for malformed input (nothing is touched or recorded). Every other path returns a
        record whose ``status`` is one of ROLLBACK_OUTCOMES; the same record is written to Firestore.
        """
        validate_product_id(product_id)
        if not isinstance(trace_id, str) or not trace_id or "/" in trace_id:
            raise InvalidRollbackRequest(f"invalid trace_id {trace_id!r}")
        if target_generation is not None:
            validate_generation(target_generation)
        logger.warning(f"INITIATING INFRASTRUCTURE ROLLBACK for '{product_id}' (Trace: {trace_id}) - Reason: {reason}")

        history: List[Dict[str, Any]] = []
        bucket_name: Optional[str] = None
        selected: Optional[str] = None
        detail: Dict[str, Any] = {}
        try:
            bucket_name = self.resolve_state_bucket(product_id)
            history = self.get_state_history(product_id, bucket_name)
            live = history[0]["generation"] if history and history[0]["live"] else None
            if history and live is None:
                # RT L1: only noncurrent versions remain (the state object was deleted). Not a lock refusal.
                raise NoLiveState(f"no live state object for '{product_id}' ({len(history)} noncurrent version(s))")
            if target_generation is not None:
                known = {v["generation"] for v in history}
                if target_generation not in known:
                    raise InvalidRollbackRequest(f"generation {target_generation} is not a state generation of "
                                                 f"'{product_id}'")
                if target_generation == live:
                    raise InvalidRollbackRequest(f"generation {target_generation} is the live state of '{product_id}'")
                selected = target_generation
            elif len(history) >= 2:
                selected = history[1]["generation"]

            if selected is None:
                status = NO_PREVIOUS_VERSION
                detail["message"] = f"{len(history)} state generation(s); no previous version to restore."
            elif self.is_state_locked(product_id, bucket_name):
                status = REFUSED_STATE_LOCKED
                detail["message"] = f"state lock {self.get_state_lock_path(product_id)} is held; nothing copied."
            else:
                detail.update(self.revert_state_to_generation(product_id, selected, live_generation=live,
                                                              bucket_name=bucket_name))
                status = detail["status"]   # FD-4AV-b: REVERTED, or SUPERSEDED by the post-copy re-check
        except InvalidRollbackRequest:
            raise
        except RestoreUnverified as e:
            detail.update(e.detail)
            status, detail["message"] = ROLLBACK_FAILED, str(e)
        except RollbackUnavailable as e:
            status, detail["message"] = ROLLBACK_UNAVAILABLE, str(e)
        except StateChangedDuringRollback as e:
            status, detail["message"] = REFUSED_STATE_LOCKED, str(e)
        except NoLiveState as e:
            status, detail["message"] = ROLLBACK_FAILED, str(e)
        except Exception as e:
            logger.error(f"Rollback of '{product_id}' failed: {type(e).__name__}: {e}")
            status, detail["message"] = ROLLBACK_FAILED, f"{type(e).__name__}: {e}"

        record = {
            **{k: v for k, v in detail.items() if k != "status"},
            "product_id": product_id,
            "trace_id": trace_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "target_generation": selected,
            "state_history_count": len(history),
            "status": status,
            "state_bucket": bucket_name or self.state_bucket_name,
        }

        if status == REVERTED:
            record["rolled_back_at"] = record["recorded_at"]  # RT L2: stamped only when a revert really happened
        record["audit_recorded"] = False
        if self.db:
            try:
                self.db.collection("rollback_events").document(trace_id).set(record)
                record["audit_recorded"] = True
                logger.info(f"Recorded rollback event {status} in Firestore for {trace_id}")
            except Exception as e:
                logger.warning(f"Could not save rollback record to Firestore: {e}")
        return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="StackVend Infrastructure Rollback Engine CLI")
    parser.add_argument("--product_id", required=True, help="Target product identifier")
    parser.add_argument("--trace_id", required=True, help="Execution correlation trace ID")
    parser.add_argument("--generation", default=None, help="Specific GCS generation to restore")
    parser.add_argument("--reason", default="Automated deployment failure rollback", help="Rollback justification")

    args = parser.parse_args()
    try:
        res = InfraRollbackEngine().execute_rollback(
            product_id=args.product_id,
            trace_id=args.trace_id,
            target_generation=args.generation,
            reason=args.reason,
        )
    except InvalidRollbackRequest as e:
        print(json.dumps({"status": "INVALID_REQUEST", "error": str(e)}, indent=2))
        sys.exit(2)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["status"] == REVERTED else 1)

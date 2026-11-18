"""
FD-7L Phase 3 (vending side): status, backfill and state migration of the per-workload runner identity.
Plan: docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3 (owner 10-30) sections 2.7 (migration), 3
(backfill), 6 (tests). Precedent: managed_tag_backfill.py. Register rows FD-7L-a / FD-7L-b (Phase 3 parts).

Inert on a Shared install: while the operative mode is PLATFORM (`STACKVEND_TF_RUNNER_IDENTITY` unset or PLATFORM and
no Per-workload Settings record, FD-7L-F4), `status` answers the mode only (no workload reads) and `run` refuses with
RUNNER_IDENTITY_MODE_PLATFORM before any workload read or write.

Targets come only from the guard database's provenance records plus the lane 18 identity checks (ledger, provenance,
CRM number, direct managed tag, ancestry: `destructive_guard.verify_identity`). Never from a name or a pattern.

Steps (`run(steps=...)`; the default is the first eight, run in this order):
  ensure_provenance_check  provenance + identity checks (always run; listed for the dry-run report)
  ensure_apis / ensure_sa / ensure_owner / ensure_broker_grant / ensure_bucket
                           runner_broker.RunnerIdentityProvisioner's idempotent, add-only steps, after a
                           project testIamPermissions rights check (BACKFILL.NO_RIGHTS_ON_PROJECT before any write);
                           SAT-45: vending's bucket rights are checked on the state bucket itself once ensure_bucket
                           has found or created it (BACKFILL.NO_RIGHTS_ON_BUCKET before its IAM or any object)
  ensure_repository        SAT-41 (pre-switch RT HIGH-1): once the record is READY (after migrate_state when both
                           run), pin the workload's repository from its workload record (`github_repo`, `vcs_provider`,
                           `github_repository_identity`) with RunnerIdentityProvisioner.pin_repository, the pin
                           vend_all makes: an equal pin writes nothing, a different pin is refused
                           (BACKFILL.REPOSITORY_MISMATCH, never overwritten), a workload record without an owner/name
                           repository, a known provider, the name vending pins (Serverless Git: castor/<pid>, no
                           id) or (GitHub) a recorded repository id is refused (BACKFILL.REPOSITORY_UNKNOWN /
                           BACKFILL.REPOSITORY_NAME_DIFFERS / BACKFILL.REPOSITORY_ID_UNKNOWN: a full-build re-vend
                           pins it). Without the pin every deploy that reads the repository is refused
                           (RUNNER_REPOSITORY_NOT_PINNED) and the step-B readiness check reports
                           REPOSITORY_NOT_PINNED.
  migrate_state            byte-exact copy of the platform state into the workload's bucket (plan 2.7):
                           MIGRATING -> drain -> migration lock -> the last 20 noncurrent versions then the live one,
                           with chained generation preconditions and a resume cursor in the signed record -> crc32c,
                           serial and lineage checks -> race re-check -> tombstone lock -> READY
  restore_platform_state   owner-run (code rollback): copy the live state back and remove the tombstone
  purge_platform_copy      owner-run (Q7): 30 days after the migration, delete every generation of the old platform
                           copy, keeping the tombstone
A dry run reads (the same read-only inspection as `status`) and lists every call it would make; it writes nothing.
A run without product_ids lists closed workloads (ledger status exactly DECOMMISSIONED / ARCHIVED / DELETED) as
SKIPPED_CLOSED without any Google call (SAT-40 section 10: a purged project would stop the whole run).
Every per-workload failure is typed (BACKFILL.* / STATE_*); a configuration error (broker identity, store, signing,
certificates) stops the whole run with its 503. Each non-dry-run workload is audited before and after.
"""
import logging
import secrets
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

from shared import runner_identity as ri   # committed replica in this service's shared/ (byte-identical to root)
from shared.github_identity import (GITHUB_REPOSITORY_IDENTITY_FIELD, pinned_github_repository_id,
                                    resolve_repo_identity)

import destructive_guard as dg
import runner_broker as rb

logger = logging.getLogger("project-vending-runner-identity-backfill")

RunnerIdentityError = ri.RunnerIdentityError

ENSURE_STEPS = ("ensure_provenance_check", "ensure_apis", "ensure_sa", "ensure_owner", "ensure_broker_grant",
                "ensure_bucket")
MIGRATE_STEP = "migrate_state"
REPO_STEP = "ensure_repository"   # SAT-41 HIGH-1: runs last (it needs a READY record)
RESTORE_STEP = "restore_platform_state"
PURGE_STEP = "purge_platform_copy"
STEPS = ENSURE_STEPS + (REPO_STEP, MIGRATE_STEP, RESTORE_STEP, PURGE_STEP)
DEFAULT_STEPS = ENSURE_STEPS + (MIGRATE_STEP, REPO_STEP)
# vend_all's providers (vending._REPOSITORY_LABELS); the backfill reads the provider only from workloads/{pid}.vcs_provider
REPOSITORY_PROVIDERS = ("GITHUB", "SERVERLESS_GIT")
# shared/providers/serverless_git_provider.py vend_repository: full_name = f"castor/{product_id}" (the name vend_all
# pins and records for a Serverless Git repository; parity pinned by tests/test_sat41_backfill_repository_pin.py)
SERVERLESS_GIT_OWNER = "castor"
STEP_B_REPOSITORY_NOT_PINNED = "REPOSITORY_NOT_PINNED"   # = scripts/common/runner_identity_readiness.py's state
OWNER_STEPS = (RESTORE_STEP, PURGE_STEP)
DRY_RUN_STOP = "DRY_RUN_STOP"   # SAT-45: a dry run whose real run would refuse (error_class + detail say where)

DEFAULT_MAX = 25
MAX_LIMIT = 200
MAX_VERSIONS = 20                       # noncurrent versions copied before the live one (plan 2.7 step 4)
PURGE_AFTER = timedelta(days=30)        # Q7
# RT F2-2: the backfill runs inside one HTTP request (Control Center -> vending), so the drain is ONE probe: a
# workload with a run in flight fails fast with STATE_MIGRATION_BUSY and the operator retries. A long poll belongs
# to a job-mode run (fallback F-B, SAT-31), which may pass a larger `polls`.
DRAIN_POLLS = 1
DRAIN_POLL_S = 15.0
REAL_RUN_MAX = 3                        # RT F2-2: a real run names its workloads, at most 3 per request
STATUS_DEFAULT_LIMIT = 50               # RT F2-4: status inspects at most 50 records per call by default
# SAT-47 (display only): the workload ledger statuses (workloads/{pid}.status, exact values) of a closed workload. The
# Control Center card lists these rows apart, without a Run button (a backfill of a closed workload can only fail).
# managed_tag_backfill.CLOSED_STATUSES plus ARCHIVED (a decommissioned workload whose record the Control Center
# archived, routes/workloads.py).
CLOSED_WORKLOAD_STATUSES = frozenset({"DECOMMISSIONED", "ARCHIVED", "DELETED"})
WORKLOAD_STATUS_UNKNOWN = "unknown"     # the ledger record is unreadable, missing, or holds no string status
# SAT-40 section 10: a run that names no workloads (the card's "Dry run") lists a provenance record whose ledger status
# is exactly one of CLOSED_WORKLOAD_STATUSES with this outcome and makes no Resource Manager, IAM or Storage call for
# it. A purged project answers projects.get with 403 (CRM_UNAVAILABLE -> RUNNER_STORE_UNAVAILABLE, a configuration
# error), which would otherwise stop the whole run with 503 about 30 days after a decommission. Named workloads
# (product_ids) are processed as before; an unreadable or missing ledger status is "unknown", never assumed closed.
SKIPPED_CLOSED = "SKIPPED_CLOSED"
THROTTLE_S = 1.0                        # between workloads of a real run
REWRITE_ROUNDS = 20                     # rewriteToken continuations per object

# Project-level rights: cloudresourcemanager v3 projects.testIamPermissions on the child, as vending, before any
# backfill write (plan 3 "rights on legacy children"; a missing one is fallback F-B: vending is not an owner of the
# child). SAT-45: only permissions that roles/owner grants AT PROJECT LEVEL, one per step that needs it:
#   iam.serviceAccounts.create             ensure_sa (in roles/owner; held by vending on castor testplan01-e2, 11-02)
#   resourcemanager.projects.setIamPolicy  ensure_owner (in roles/owner, not roles/editor; held, same check)
#   iam.serviceAccounts.setIamPolicy       ensure_broker_grant (in roles/owner, not roles/editor; held, same check)
#   storage.buckets.create                 ensure_bucket (in roles/owner; held, same check)
# storage.buckets.setIamPolicy and storage.objects.create are NOT in roles/owner at project level (gcloud iam roles
# describe roles/owner): an owner gets them per bucket from Cloud Storage's default convenience bindings
# (projectOwner:<project> -> roles/storage.legacyBucketOwner / legacyObjectOwner), so a project-level test of them
# always failed (SAT-45 defect). They are checked on the state bucket itself (REQUIRED_BUCKET_PERMISSIONS).
REQUIRED_VENDING_PERMISSIONS = ("iam.serviceAccounts.create", "iam.serviceAccounts.setIamPolicy",
                                "resourcemanager.projects.setIamPolicy", "storage.buckets.create")
# Bucket-level rights: Cloud Storage buckets.testIamPermissions on the workload's state bucket, as vending, after
# ensure_bucket finds or creates it, before its IAM is changed or any object is written (BACKFILL.NO_RIGHTS_ON_BUCKET):
#   storage.buckets.getIamPolicy / setIamPolicy   ensure_bucket's add-only bucket IAM (GET + PUT b/{bucket}/iam)
#   storage.objects.list                          migrate_state lists the destination generations
#   storage.objects.get                           migrate_state reads the copy back (serial / lineage)
#   storage.objects.create                        migrate_state's rewrite into the bucket
#   storage.objects.delete                        overwriting the live copy (each later generation) and the removal
#                                                 of a bad copy (RT F2-3)
# legacyBucketOwner grants all but objects.get; legacyObjectOwner grants objects.get (both bound to projectOwner).
REQUIRED_BUCKET_PERMISSIONS = ("storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy",
                               "storage.objects.list", "storage.objects.get", "storage.objects.create",
                               "storage.objects.delete")

# runner_broker step classes -> plan section 3 backfill classes (exact keys).
STEP_CLASS_MAP = {
    "VENDING.RUNNER_IDENTITY_APIS_MISSING": "BACKFILL.APIS_MISSING",
    "VENDING.DEPLOYER_SA_FAILED": "BACKFILL.SA_CREATE_FAILED",
    "VENDING.DEPLOYER_OWNER_GRANT_FAILED": "BACKFILL.GRANT_FAILED",
    "VENDING.BROKER_GRANT_FAILED": "BACKFILL.GRANT_FAILED",
    "VENDING.DEPLOYER_UNEXPECTED_TOKEN_CREATOR": "BACKFILL.GRANT_FAILED",
    "VENDING.STATE_BUCKET_NAME_TAKEN": "BACKFILL.BUCKET_NAME_TAKEN",
    "VENDING.STATE_BUCKET_FAILED": "BACKFILL.BUCKET_FAILED",
}

# Errors that are about the install, not one workload: the whole run stops (HTTP 503).
CONFIG_ERRORS = frozenset({"RUNNER_BROKER_SHARED_IDENTITY", "VENDING.RUNNER_BROKER_SHARED_IDENTITY",
                           "RUNNER_STORE_UNAVAILABLE", "RUNNER_RECORD_UNVERIFIABLE", "RUNNER_RECORD_SIGN_FAILED",
                           "RUNNER_IDENTITY_MODE_INVALID", "RUNNER_IDENTITY_UNRESOLVED"})

_STORAGE = "https://storage.googleapis.com/storage/v1/"
_UPLOAD = "https://storage.googleapis.com/upload/storage/v1/"
_CRM_V3 = "https://cloudresourcemanager.googleapis.com/v3/"
_RUN = "https://run.googleapis.com/v2/"
_IAM = "https://iam.googleapis.com/v1/"

SOURCE_GENERATION_KEY = "stackvend-source-generation"
SOURCE_UPDATED_KEY = "stackvend-source-updated"
SOURCE_BUCKET_KEY = "stackvend-source-bucket"
BACKFILL_ACTOR = "runner-identity-backfill"


def _err(code: str, detail: str, status: int = 409) -> RunnerIdentityError:
    return RunnerIdentityError(code, detail, stage="runner-identity-backfill", http_status=status)


def _q(name: str) -> str:
    return quote(name, safe="")


def _pinned_repository(rec: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The record's pinned repository when it names a provider and a full name (the repository read's contract),
    else None."""
    repo = (rec or {}).get("repository")
    if isinstance(repo, dict) and isinstance(repo.get("provider"), str) and repo["provider"] \
            and isinstance(repo.get("full_name"), str) and repo["full_name"]:
        return repo
    return None


def _gen(value: Any) -> Optional[str]:
    s = str(value) if isinstance(value, (int, str)) and not isinstance(value, bool) else ""
    return s if s.isdigit() else None


class _Plan(list):
    """The call list of one workload (performed calls in a real run, intended calls in a dry run)."""

    def __init__(self):
        super().__init__()
        self.stopped: Optional[Tuple[str, str]] = None   # SAT-45: (class, detail) where a dry run says the run stops

    def add(self, method: str, target: str, why: str) -> None:
        self.append({"call": f"{method} {target}", "why": why})

    def stop(self, target: str, code: str, detail: str) -> None:
        """A dry run's STOP: the real run refuses here with `code`, before the calls that would follow."""
        self.add("STOP", target, f"{code}: {detail}")
        if self.stopped is None:
            self.stopped = (code, detail)


class RunnerIdentityBackfill:
    def __init__(self, deps: rb.RunnerDeps, *, platform_bucket: str,
                 region_for: Callable[[str], Optional[str]]):
        self.d = deps
        self.provisioner = rb.RunnerIdentityProvisioner(deps)
        self.broker_api = rb.RunnerBroker(deps)
        self.platform_bucket = platform_bucket
        self.region_for = region_for

    # ------------------------------------------------------------------------------------------ helpers
    def _now(self) -> str:
        return rb._now_iso(self.d.clock)

    def _rest(self, method: str, url: str, **kw) -> Tuple[int, Dict[str, Any]]:
        return self.d.rest.call(method, url, **kw)

    def _ctx(self):
        return self.d.guard_context()

    def _audit(self, pid: str, record: Dict[str, Any]) -> None:
        try:
            dg._audit(self._ctx(), pid, dict(record, actor=BACKFILL_ACTOR, at=self._now()))
        except Exception as e:  # noqa: BLE001 - surfaced as a per-workload failure by the caller
            raise _err("BACKFILL.AUDIT_UNAVAILABLE", f"{pid}: audit not written ({type(e).__name__})", 503) from None

    def _write(self, pid: str, base: Dict[str, Any], broker: str, **changes) -> Dict[str, Any]:
        record = {k: v for k, v in base.items() if k not in ("signed_by", "signed_at", "signature")}
        record.update(changes)
        record["updated_at"] = self._now()
        if record.get("status") not in ri.STATUSES:
            raise _err("RUNNER_IDENTITY_INVALID_STATUS", f"{pid}: {record.get('status')!r}", 500)
        signed = self.provisioner._sign_and_write(pid, record, broker)
        self._display(pid, signed["status"])
        return {k: v for k, v in signed.items() if k != "signature"}

    def _display(self, pid: str, status: str) -> None:
        """workloads/{pid}.runner_identity_status: display copy for the Control Center only (plan 2.1)."""
        db = self.d.store.db
        if db is None:
            return
        try:
            db.collection("workloads").document(pid).set({"runner_identity_status": status}, merge=True)
        except Exception as e:  # noqa: BLE001 - display only; the signed record is authoritative
            logger.warning(f"Could not write the runner identity display status of {pid}: {type(e).__name__}")

    # -- GCS objects ------------------------------------------------------------------------------------
    def _versions(self, bucket: str, name: str) -> List[Dict[str, Any]]:
        """Every generation of exactly `name`, oldest first. Raises STATE_MIGRATION_UNREADABLE on a read error."""
        out: List[Dict[str, Any]] = []
        token = None
        for _ in range(50):
            params = {"prefix": name, "versions": "true"}
            if token:
                params["pageToken"] = token
            status, body = self._rest("get", f"{_STORAGE}b/{bucket}/o", params=params)
            if status != 200:
                raise _err("STATE_MIGRATION_UNREADABLE", f"list gs://{bucket}/{name}: HTTP {status}", 502)
            for item in body.get("items") or []:
                if isinstance(item, dict) and item.get("name") == name and _gen(item.get("generation")):
                    out.append(item)
            token = body.get("nextPageToken")
            if not token:
                break
        out.sort(key=lambda o: int(o["generation"]))
        return out

    @staticmethod
    def _live(versions: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        live = [v for v in versions if not v.get("timeDeleted")]
        return live[-1] if live else None

    def _read_json(self, bucket: str, name: str, generation: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
        params = {"alt": "media"}
        if generation:
            params["generation"] = generation
        return self._rest("get", f"{_STORAGE}b/{bucket}/o/{_q(name)}", params=params)

    def _lock(self, bucket: str, pid: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """(generation, parsed LockInfo) of the platform lock object, (None, None) when there is none."""
        name = ri.lock_object_name(pid)
        status, meta = self._rest("get", f"{_STORAGE}b/{bucket}/o/{_q(name)}")
        if status == 404:
            return None, None
        if status != 200 or not _gen(meta.get("generation")):
            raise _err("STATE_MIGRATION_UNREADABLE", f"gs://{bucket}/{name}: HTTP {status}", 502)
        gen = _gen(meta.get("generation"))
        status, body = self._read_json(bucket, name, gen)
        if status != 200:
            raise _err("STATE_MIGRATION_UNREADABLE", f"gs://{bucket}/{name} content: HTTP {status}", 502)
        return gen, body

    def _upload_lock(self, bucket: str, pid: str, info: Dict[str, Any], if_generation: str) -> Optional[str]:
        """Writes a LockInfo object with a generation precondition. Returns the new generation, None on 412."""
        status, body = self._rest("post", f"{_UPLOAD}b/{bucket}/o", json=info, params={
            "uploadType": "media", "name": ri.lock_object_name(pid), "ifGenerationMatch": if_generation})
        if status == 412:
            return None
        if status != 200 or not _gen(body.get("generation")):
            raise _err("STATE_MIGRATION_LOCK_FAILED", f"gs://{bucket}/{ri.lock_object_name(pid)}: HTTP {status}", 502)
        return _gen(body.get("generation"))

    def _rewrite(self, src_bucket: str, src_name: str, src_gen: str, dst_bucket: str, dst_name: str,
                 if_generation: str, metadata: Dict[str, str], content_type: Optional[str]) -> Optional[Dict]:
        """Copies one source generation with a destination generation precondition (rewrite, token loop). Returns
        the destination object resource, None on a failed precondition (412)."""
        params: Dict[str, Any] = {"sourceGeneration": src_gen, "ifGenerationMatch": if_generation}
        body_obj: Dict[str, Any] = {"metadata": metadata}
        if content_type:
            body_obj["contentType"] = content_type
        url = f"{_STORAGE}b/{src_bucket}/o/{_q(src_name)}/rewriteTo/b/{dst_bucket}/o/{_q(dst_name)}"
        for _ in range(REWRITE_ROUNDS):
            status, body = self._rest("post", url, params=params, json=body_obj)
            if status == 412:
                return None
            if status != 200:
                raise _err("STATE_COPY_FAILED", f"gs://{src_bucket}/{src_name}#{src_gen} -> gs://{dst_bucket}/"
                           f"{dst_name}: HTTP {status}", 502)
            if body.get("done") is True and isinstance(body.get("resource"), dict):
                return body["resource"]
            token = body.get("rewriteToken")
            if not isinstance(token, str) or not token:
                raise _err("STATE_COPY_FAILED", f"rewrite of gs://{src_bucket}/{src_name} gave no token", 502)
            params = dict(params, rewriteToken=token)
        raise _err("STATE_COPY_FAILED", f"rewrite of gs://{src_bucket}/{src_name} did not finish", 502)

    def _delete_generation(self, bucket: str, name: str, generation: str) -> int:
        status, _ = self._rest("delete", f"{_STORAGE}b/{bucket}/o/{_q(name)}",
                               params={"generation": generation, "ifGenerationMatch": generation})
        return status

    # -- identity ---------------------------------------------------------------------------------------
    def _identity(self, pid: str):
        try:
            ident = dg.verify_identity(pid, ctx=self._ctx())
        except dg.DeletionRefused as e:
            if e.http_status == 503:
                raise _err("RUNNER_STORE_UNAVAILABLE", f"{pid}: {e.code}: {e.detail}", 503) from None
            raise _err("BACKFILL.IDENTITY_UNVERIFIED", f"{pid}: {e.code}: {e.detail}") from None
        prov = self.d.store.get_provenance(pid)
        if prov is None:
            raise _err("BACKFILL.NO_PROVENANCE", f"{pid}: no provenance record")
        self.broker_api.provenance_check(pid, prov)
        if prov.get("project_id") != ident.project_id or dg._num(prov.get("project_number")) != ident.project_number:
            raise _err("RUNNER_TARGET_MISMATCH", f"{pid}: provenance and the verified project differ")
        return ident, prov

    def _rights_missing(self, number: str) -> List[str]:
        status, body = self._rest("post", f"{_CRM_V3}projects/{number}:testIamPermissions",
                                  json={"permissions": list(REQUIRED_VENDING_PERMISSIONS)})
        if status != 200:
            return list(REQUIRED_VENDING_PERMISSIONS)
        held = set(body.get("permissions") or [])
        return [p for p in REQUIRED_VENDING_PERMISSIONS if p not in held]

    def _bucket_rights_missing(self, bucket: str) -> Tuple[List[str], int]:
        """(missing bucket permissions, HTTP status) of vending on gs://{bucket}. Fails closed: any answer but 200
        counts every permission as missing."""
        status, body = self._rest("get", f"{_STORAGE}b/{_q(bucket)}/iam/testPermissions",
                                  params={"permissions": list(REQUIRED_BUCKET_PERMISSIONS)})
        if status != 200:
            return list(REQUIRED_BUCKET_PERMISSIONS), status
        held = set(body.get("permissions") or [])
        return [p for p in REQUIRED_BUCKET_PERMISSIONS if p not in held], status

    def _require_bucket_rights(self, pid: str, bucket: str) -> None:
        """BACKFILL.NO_RIGHTS_ON_BUCKET before any bucket IAM change or object write (nothing is written)."""
        missing, status = self._bucket_rights_missing(bucket)
        if missing:
            answered = "" if status == 200 else f" (testPermissions answered HTTP {status})"
            raise _err("BACKFILL.NO_RIGHTS_ON_BUCKET", f"{pid}: vending lacks {', '.join(missing)} on gs://{bucket}"
                       f"{answered}; nothing was written to the bucket")

    # ------------------------------------------------------------------------------------------ inspection
    def inspect(self, pid: str, prov: Dict[str, Any], broker: str) -> Dict[str, Any]:
        """Read-only facts about one workload (status route and dry run). Never writes; never mints."""
        facts: Dict[str, Any] = {"product_id": pid, "project_id": prov.get("project_id"),
                                 "project_number": dg._num(prov.get("project_number")) or None,
                                 "provenance": prov.get("created_by"), "repository": None, "step_b": "NOT_READY"}
        try:
            rec = self.provisioner.verified_existing(pid, prov, broker)
        except RunnerIdentityError as e:
            if e.code in CONFIG_ERRORS:
                raise
            facts.update(record="UNSIGNED", error_class=e.code)
            return facts
        project_id, number = facts["project_id"], facts["project_number"]
        facts.update(record="PRESENT" if rec else "NONE", status=(rec or {}).get("status", ri.STATUS_NONE),
                     error_class=(rec or {}).get("error_class"), state_bucket=(rec or {}).get("state_bucket"),
                     migration_cursor=((rec or {}).get("migration") or {}).get("last_source_generation_copied"),
                     migrated_at=((rec or {}).get("migration") or {}).get("migrated_at"))
        # SAT-41 HIGH-1: the step-B view of this record, as scripts/common/runner_identity_readiness.py decides it
        # (READY, no error class, a pinned repository); a READY record without a pin is REPOSITORY_NOT_PINNED.
        pinned = _pinned_repository(rec)
        facts["repository"] = pinned["full_name"] if pinned else None
        if facts["status"] == ri.STATUS_READY and not facts["error_class"]:
            facts["step_b"] = ri.STATUS_READY if pinned else STEP_B_REPOSITORY_NOT_PINNED
        if not ri.is_project_id(project_id) or not number:
            facts["error_class"] = "BACKFILL.NO_PROVENANCE"
            return facts
        deployer = ri.deployer_email(project_id)
        facts["deployer_email"] = deployer
        facts["rights_missing"] = self._rights_missing(number)
        status, sa = self._rest("get", f"{_IAM}projects/{project_id}/serviceAccounts/{deployer}")
        facts["deployer"] = "PRESENT" if status == 200 else ("ABSENT" if status == 404 else f"HTTP {status}")
        try:
            policy = self.d.project_iam.get_iam_policy(project_id)
            facts["owner_grant"] = self.provisioner._has_member(policy, rb.OWNER_ROLE, f"serviceAccount:{deployer}")
        except dg.CRMUnavailable as e:
            facts["owner_grant"] = f"HTTP {e.status or 0}"
        if status == 200:
            s2, sp = self._rest("post", f"{_IAM}projects/{project_id}/serviceAccounts/{deployer}:getIamPolicy",
                                json={"options": {"requestedPolicyVersion": 3}})
            facts["broker_grant"] = (self.provisioner._has_member(sp, rb.TOKEN_CREATOR_ROLE, f"serviceAccount:{broker}")
                                     if s2 == 200 else f"HTTP {s2}")
        else:
            facts["broker_grant"] = False
        bucket = (rec or {}).get("state_bucket") or ri.state_bucket_name(project_id)
        s3, b = self._rest("get", f"{_STORAGE}b/{bucket}")
        facts["bucket"] = bucket
        facts["bucket_state"] = ("PRESENT" if s3 == 200 and str(b.get("projectNumber", "")) == number
                                 else "TAKEN" if s3 in (200, 403) else "ABSENT" if s3 == 404 else f"HTTP {s3}")
        # SAT-45: vending's bucket rights, read only on this project's existing bucket; for a bucket not created yet
        # the run checks them right after it creates the bucket (None here).
        facts["bucket_rights_missing"] = (self._bucket_rights_missing(bucket)[0]
                                          if facts["bucket_state"] == "PRESENT" else None)
        try:
            platform_versions = self._versions(self.platform_bucket, ri.state_object_name(pid))
            _gen_lock, lock = self._lock(self.platform_bucket, pid)
        except RunnerIdentityError as e:
            facts["state_location"] = f"UNKNOWN ({e.code})"
            return facts
        facts["platform_state_versions"] = len(platform_versions)
        facts["platform_lock"] = ("TOMBSTONE" if ri.is_tombstone(lock) else "MIGRATION_LOCK"
                                  if ri.is_migration_lock(lock) else "HELD" if lock else "NONE")
        ready = facts["status"] == ri.STATUS_READY
        facts["state_location"] = (f"gs://{bucket}/{ri.state_prefix(pid)}" if ready
                                   else f"gs://{self.platform_bucket}/{ri.state_prefix(pid)}")
        return facts

    def status(self, *, limit: int = STATUS_DEFAULT_LIMIT) -> Dict[str, Any]:
        try:
            mode = self.d.operative_mode()
        except RunnerIdentityError as e:   # FD-7L-F4: shown on the card (typed), never guessed
            return {"mode": None, "mode_label": None, "mode_source": ri.MODE_ENV,
                    "mode_error": f"{e.code}: {e.detail}", "per_workload": False, "workloads": [], "totals": {},
                    "truncated": False}
        base = {"mode": mode, "mode_label": ri.MODE_LABELS.get(mode, mode), "mode_source": ri.MODE_ENV}
        if mode != ri.MODE_PER_WORKLOAD:
            return dict(base, per_workload=False, workloads=[], totals={}, truncated=False)
        broker = self.provisioner.broker()
        records = self.d.store.list_provenance()
        rows = [self.inspect(pid, prov, broker) for pid, prov in records[:limit]]
        totals: Dict[str, int] = {}
        for r in rows:
            key = r.get("status") or r.get("record") or "UNKNOWN"
            totals[key] = totals.get(key, 0) + 1
        for r in rows:   # SAT-47: display only (the card's live / closed split)
            r["workload_status"] = self._workload_status(r["product_id"])
            r["closed"] = r["workload_status"] in CLOSED_WORKLOAD_STATUSES
        live = [r for r in rows if not r["closed"]]
        ready = sum(1 for r in live if r.get("step_b") == ri.STATUS_READY)
        summary = {"live": len(live), "ready": ready, "not_ready": len(live) - ready, "closed": len(rows) - len(live)}
        return dict(base, per_workload=True, broker=broker, workloads=rows, totals=totals, summary=summary,
                    truncated=len(records) > limit, max_records=limit, record_count=len(records))

    def _workload_status(self, pid: str) -> str:
        """workloads/{pid}.status exactly as stored (display only, SAT-47); WORKLOAD_STATUS_UNKNOWN when the record
        cannot be read, does not exist or holds no string status. Never guessed, never written."""
        try:
            data = self.d.store.get_workload(pid)
        except RunnerIdentityError:
            return WORKLOAD_STATUS_UNKNOWN
        status = data.get("status") if isinstance(data, dict) else None
        return status if isinstance(status, str) and status else WORKLOAD_STATUS_UNKNOWN

    # ------------------------------------------------------------------------------------------ run
    def run(self, caller: str, *, dry_run: bool = True, product_ids: Optional[List[str]] = None,
            max_items: int = DEFAULT_MAX, steps: Optional[List[str]] = None,
            operator_email: Optional[str] = None) -> Dict[str, Any]:
        self.broker_api.require_per_workload()
        chosen = tuple(steps) if steps else DEFAULT_STEPS
        if any(s not in STEPS for s in chosen) or len(set(chosen)) != len(chosen):
            raise _err("BACKFILL.STEPS_INVALID", f"steps must be distinct names from {', '.join(STEPS)}", 422)
        owner = [s for s in chosen if s in OWNER_STEPS]
        if owner and (len(chosen) != 1):
            raise _err("BACKFILL.STEPS_INVALID", f"{owner[0]} runs alone (owner action)", 422)
        if RESTORE_STEP in chosen and not product_ids:
            raise _err("BACKFILL.STEPS_INVALID", "restore_platform_state needs explicit product_ids", 422)
        if not isinstance(max_items, int) or isinstance(max_items, bool) or not 1 <= max_items <= MAX_LIMIT:
            raise _err("BACKFILL.STEPS_INVALID", f"max must be 1..{MAX_LIMIT}", 422)
        if not dry_run and (not product_ids or len(set(product_ids)) > REAL_RUN_MAX or max_items > REAL_RUN_MAX):
            # RT F2-2: one HTTP request must finish well inside the caller's 120 s wait and Cloud Run's timeout.
            raise _err("BACKFILL.REAL_RUN_TOO_LARGE", f"a real run names its workloads in product_ids, at most "
                       f"{REAL_RUN_MAX} per request, with max <= {REAL_RUN_MAX} (a dry run may cover more)", 422)
        broker = self.provisioner.broker()
        closed: List[Tuple[str, str]] = []
        if product_ids:
            targets = list(dict.fromkeys(p for p in product_ids if isinstance(p, str)))
        else:
            targets = []
            for pid, _ in self.d.store.list_provenance():
                ledger_status = self._workload_status(pid)
                if ledger_status in CLOSED_WORKLOAD_STATUSES:   # SAT-40 section 10: exact ledger values only
                    closed.append((pid, ledger_status))
                else:
                    targets.append(pid)
        truncated = len(targets) > max_items
        targets = targets[:max_items]
        results = []
        for i, pid in enumerate(targets):
            if i and not dry_run:
                self.d.sleep(THROTTLE_S)
            results.append(self._one(pid, chosen, dry_run, broker, caller, operator_email))
        for pid, ledger_status in closed:
            results.append({"product_id": pid, "outcome": SKIPPED_CLOSED, "error_class": None,
                            "workload_status": ledger_status, "calls": [],
                            "detail": f"workloads/{pid}.status is {ledger_status}: a closed workload is not "
                                      "backfilled (name it in product_ids to run it anyway)"})
        counts: Dict[str, int] = {}
        for r in results:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        logger.info(f"RUNNER_IDENTITY_BACKFILL by {caller} for {operator_email!r} dry_run={dry_run} "
                    f"steps={list(chosen)}: {counts}")
        return {"dry_run": dry_run, "steps": list(chosen), "results": results, "counts": counts,
                "truncated": truncated}

    def _one(self, pid: str, steps: Tuple[str, ...], dry_run: bool, broker: str, caller: str,
             operator_email: Optional[str]) -> Dict[str, Any]:
        calls = _Plan()
        out: Dict[str, Any] = {"product_id": pid, "outcome": "OK", "error_class": None, "calls": calls}
        audit_base = {"action": "RUNNER_IDENTITY_BACKFILL", "product_id": pid, "steps": list(steps),
                      "caller": caller, "operator": operator_email}
        try:
            ident, prov = self._identity(pid)
            out.update(project_id=ident.project_id, project_number=ident.project_number)
            if not dry_run:
                self._audit(pid, dict(audit_base, status="ATTEMPT"))
            if steps == (RESTORE_STEP,):
                out["outcome"] = self._restore(pid, prov, broker, dry_run, calls)
            elif steps == (PURGE_STEP,):
                out["outcome"] = self._purge(pid, prov, broker, dry_run, calls)
            else:
                out["outcome"] = self._ensure_and_migrate(pid, ident, prov, steps, broker, dry_run, calls)
            if calls.stopped is not None:
                # SAT-45: a dry run that finds a refusal says so in the outcome and the counts, not only in a line.
                out.update(outcome=DRY_RUN_STOP, error_class=calls.stopped[0], detail=calls.stopped[1])
        except RunnerIdentityError as e:
            if e.code in CONFIG_ERRORS:
                raise
            out.update(outcome="FAILED", error_class=e.code, detail=e.detail)
            logger.error(f"RUNNER_IDENTITY_BACKFILL {pid}: {e.code}: {e.detail}")
        if not dry_run and out.get("project_id"):
            try:
                self._audit(pid, dict(audit_base, status=out["outcome"], error_class=out["error_class"],
                                      calls=[c["call"] for c in calls]))
            except RunnerIdentityError as e:
                out.setdefault("warnings", []).append(f"{e.code}: {e.detail}")
        return out

    # -- ensure steps -----------------------------------------------------------------------------------
    def _ensure_and_migrate(self, pid, ident, prov, steps, broker, dry_run, calls) -> str:
        project_id, number = ident.project_id, ident.project_number
        deployer = ri.deployer_email(project_id)
        existing = self.provisioner.verified_existing(pid, prov, broker)
        if existing is not None and (existing.get("project_id") != project_id
                                     or existing.get("project_number") != number):
            raise _err("RUNNER_TARGET_MISMATCH", f"{pid}: the runner identity record names another project")
        writes = [s for s in steps if s in ENSURE_STEPS[1:]]
        if dry_run:
            facts = self.inspect(pid, prov, broker)
            self._plan_ensure(pid, facts, writes, broker, calls)
            if MIGRATE_STEP in steps and calls.stopped is None:
                self._plan_migrate(pid, facts, calls, check_bucket="ensure_bucket" not in writes)
            if REPO_STEP in steps and calls.stopped is None:
                self._plan_repository(pid, facts, calls)
            return "DRY_RUN"
        if writes:
            missing = self._rights_missing(number)
            if missing:
                raise _err("BACKFILL.NO_RIGHTS_ON_PROJECT", f"{pid}: vending lacks {', '.join(missing)} on "
                           f"{project_id} (fallback F-B: plan section 3)")
        record = existing
        recorded_bucket = (existing or {}).get("state_bucket")
        try:
            if "ensure_apis" in writes:
                self.provisioner.ensure_apis(number)
                calls.add("GET", f"serviceusage projects/{number}/services:batchGet", "required APIs enabled")
            if "ensure_sa" in writes:
                self.provisioner.ensure_sa(project_id, deployer, create=True)
                calls.add("POST", f"iam projects/{project_id}/serviceAccounts", "deployer (409 = adopt)")
            if "ensure_owner" in writes:
                self.provisioner.ensure_owner(project_id, deployer, add=True)
                calls.add("SET", f"projects/{project_id} IAM", "add-only roles/owner for the deployer")
            if "ensure_broker_grant" in writes:
                self.provisioner.ensure_broker_grant(project_id, deployer, broker, add=True)
                calls.add("SET", f"{deployer} IAM", "add-only token creator for the broker")
            if "ensure_bucket" in writes:
                region = self.region_for(pid) if recorded_bucket is None else None
                # SAT-45: vending's bucket rights on the found / created bucket, before its IAM or any object
                recorded_bucket = self.provisioner.ensure_bucket(
                    pid, project_id, number, region, recorded_bucket, deployer, broker, create=True,
                    before_iam=lambda bucket: self._require_bucket_rights(pid, bucket))
                calls.add("CREATE", f"gs://{recorded_bucket}", "versioned, uniform access, public access prevention")
        except rb._StepFailed as step:
            backfill_class = STEP_CLASS_MAP.get(step.error_class, step.error_class)
            if record is None or record.get("status") not in (ri.STATUS_READY, ri.STATUS_MIGRATING):
                base = record or ri.new_runner_identity_record(
                    product_id=pid, project_id=project_id, project_number=number, state_bucket=recorded_bucket,
                    status=ri.STATUS_FAILED, updated_at=self._now())
                self._write(pid, base, broker, status=ri.STATUS_FAILED, error_class=backfill_class,
                            state_bucket=recorded_bucket)
                calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", f"signed FAILED ({backfill_class})")
            raise _err(backfill_class, f"{pid}: {step.detail}") from None

        if writes and "ensure_bucket" in writes:
            platform = self._versions(self.platform_bucket, ri.state_object_name(pid))
            _lg, lock = self._lock(self.platform_bucket, pid)
            needs_migration = bool(platform) and not ri.is_tombstone(lock)
            if record is None or record.get("status") in (ri.STATUS_NONE, ri.STATUS_FAILED, ri.STATUS_SA_READY,
                                                          ri.STATUS_BUCKET_READY):
                new_status = ri.STATUS_BUCKET_READY if needs_migration else ri.STATUS_READY
                base = record or ri.new_runner_identity_record(
                    product_id=pid, project_id=project_id, project_number=number, state_bucket=recorded_bucket,
                    status=new_status, updated_at=self._now())
                record = self._write(pid, base, broker, status=new_status, error_class=None,
                                     state_bucket=recorded_bucket)
                calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", f"signed {new_status}")
        if MIGRATE_STEP not in steps:
            outcome = (record or {}).get("status") or "OK"
        else:
            if record is None:
                raise _err("BACKFILL.NOT_PROVISIONED", f"{pid}: no runner identity record (run the ensure steps first)")
            outcome = self._migrate(pid, record, broker, calls, check_bucket="ensure_bucket" not in writes)
        if REPO_STEP in steps:
            self._pin_repository(pid, broker, calls)
        return outcome

    # -- repository pin (SAT-41, pre-switch RT HIGH-1) ---------------------------------------------------
    def _workload_repository(self, pid: str) -> Dict[str, Any]:
        """The repository vend_all pins for this workload, from workloads/{pid} (read-only): exactly its
        {"provider", "full_name", "id"} form, so a later re-vend finds an equal pin. Typed refusal (nothing pinned)
        when the record has no owner/name repository, no known provider, or (GitHub) no recorded repository id."""
        db = self.d.store.db
        if db is None:
            raise _err("BACKFILL.WORKLOAD_UNREADABLE", f"{pid}: no default database client", 503)
        try:
            snap = db.collection("workloads").document(pid).get()
            data = snap.to_dict() if getattr(snap, "exists", False) is True else None
        except Exception as e:  # noqa: BLE001 - a record that cannot be read is never assumed
            raise _err("BACKFILL.WORKLOAD_UNREADABLE", f"workloads/{pid} unreadable ({type(e).__name__})", 503) from None
        if not isinstance(data, dict):
            raise _err("BACKFILL.REPOSITORY_UNKNOWN", f"{pid}: no workload record workloads/{pid}")
        full_name = data.get("github_repo")
        parts = full_name.split("/") if isinstance(full_name, str) else []
        if len(parts) != 2 or not all(parts) or any(p != p.strip() for p in parts):
            raise _err("BACKFILL.REPOSITORY_UNKNOWN", f"{pid}: workloads/{pid}.github_repo is {full_name!r}, not "
                       "owner/name; a full-build re-vend pins the repository")
        raw_provider = data.get("vcs_provider")
        provider = raw_provider.strip().upper() if isinstance(raw_provider, str) else ""
        if provider not in REPOSITORY_PROVIDERS:
            raise _err("BACKFILL.REPOSITORY_UNKNOWN", f"{pid}: workloads/{pid}.vcs_provider is {raw_provider!r} "
                       f"(expected one of {', '.join(REPOSITORY_PROVIDERS)}); a full-build re-vend pins the repository")
        # The deploy reads the repository it resolves from github_repo (resolve_repo_identity) and a re-vend pins the
        # name the provider returns; the pin must equal both, so a stored name in another form is refused, never
        # rewritten (a full-build re-vend records the canonical name and pins it).
        canonical = (f"{SERVERLESS_GIT_OWNER}/{pid}" if provider == "SERVERLESS_GIT"
                     else resolve_repo_identity(full_name, product_id=pid)[2])
        if canonical != full_name:
            raise _err("BACKFILL.REPOSITORY_NAME_DIFFERS", f"{pid}: workloads/{pid}.github_repo is {full_name!r}, "
                       f"not the name vending pins for this {provider} repository ({canonical!r}); a full-build "
                       "re-vend records that name and pins it")
        repo_id = None
        if provider == "GITHUB":
            repo_id = pinned_github_repository_id(data.get(GITHUB_REPOSITORY_IDENTITY_FIELD), full_name)
            if repo_id is None:
                # vend_all resolves and records the id at the next vend; a pin without it would then differ and that
                # vend would be refused (VENDING.RUNNER_REPOSITORY_MISMATCH).
                raise _err("BACKFILL.REPOSITORY_ID_UNKNOWN", f"{pid}: workloads/{pid}."
                           f"{GITHUB_REPOSITORY_IDENTITY_FIELD} holds no repository id for {full_name}; a full-build "
                           "re-vend records it and pins the repository")
        return {"provider": provider, "full_name": full_name, "id": repo_id}

    def _pin_repository(self, pid: str, broker: str, calls: _Plan) -> None:
        prov = self.d.store.get_provenance(pid) or {}
        rec = self.provisioner.verified_existing(pid, prov, broker)
        if rec is None:
            raise _err("BACKFILL.NOT_PROVISIONED", f"{pid}: no runner identity record (run the ensure steps first)")
        if rec.get("status") != ri.STATUS_READY:
            calls.add("SKIP", f"workload_provenance/{pid}.runner_identity", f"repository pin waits for READY "
                      f"(status {rec.get('status')}; run migrate_state)")
            return
        repository = self._workload_repository(pid)
        if rec.get("repository") == repository:
            calls.add("NONE", f"workload_provenance/{pid}.runner_identity",
                      f"repository {repository['full_name']} already pinned")
            return
        try:
            self.provisioner.pin_repository(pid, repository)
        except RunnerIdentityError as e:
            if e.code == "VENDING.RUNNER_REPOSITORY_MISMATCH":
                raise _err("BACKFILL.REPOSITORY_MISMATCH", e.detail) from None
            raise
        calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity",
                  f"signed: repository {repository['provider']} {repository['full_name']} pinned")

    def _plan_repository(self, pid: str, facts: Dict[str, Any], calls: _Plan) -> None:
        if facts.get("repository"):
            calls.add("NONE", f"workload_provenance/{pid}.runner_identity",
                      f"repository {facts['repository']} already pinned")
            return
        try:
            repository = self._workload_repository(pid)
        except RunnerIdentityError as e:
            calls.add("STOP", f"workloads/{pid}", f"{e.code}: {e.detail}")
            return
        calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity",
                  f"pin repository {repository['provider']} {repository['full_name']} (once the record is READY)")

    def _plan_ensure(self, pid, facts, writes, broker, calls) -> None:
        project_id, number = facts.get("project_id"), facts.get("project_number")
        deployer = facts.get("deployer_email")
        if facts.get("rights_missing") and writes:
            # SAT-45: the run refuses here before any write, so nothing after it is listed.
            calls.stop(f"projects/{project_id}", "BACKFILL.NO_RIGHTS_ON_PROJECT",
                       f"vending lacks {', '.join(facts['rights_missing'])} (fallback F-B: plan section 3)")
            return
        if "ensure_apis" in writes:
            calls.add("GET", f"serviceusage projects/{number}/services:batchGet", "check iam / iamcredentials / storage")
        if "ensure_sa" in writes and facts.get("deployer") != "PRESENT":
            calls.add("POST", f"iam projects/{project_id}/serviceAccounts", f"create {deployer}")
        if "ensure_owner" in writes and facts.get("owner_grant") is not True:
            calls.add("SET", f"projects/{project_id} IAM", f"add roles/owner serviceAccount:{deployer}")
        if "ensure_broker_grant" in writes and facts.get("broker_grant") is not True:
            calls.add("SET", f"{deployer} IAM", f"add {rb.TOKEN_CREATOR_ROLE} serviceAccount:{broker}")
        if "ensure_bucket" in writes:
            if facts.get("bucket_state") != "PRESENT":
                calls.add("POST", f"storage b?project={number}", f"create gs://{facts.get('bucket')} in "
                          f"{self.region_for(pid) or '<region unknown: BACKFILL.BUCKET_FAILED>'}")
                calls.add("GET", "storage b/<created bucket>/iam/testPermissions", "the bucket rights are checked "
                          "right after the bucket is created, before its IAM or any object "
                          "(BACKFILL.NO_RIGHTS_ON_BUCKET)")
            elif not self._plan_bucket_rights(facts, calls):
                return
            calls.add("PUT", f"storage b/{facts.get('bucket')}/iam", "add-only deployer objectAdmin, broker + Control "
                      "Center objectViewer")
            calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "signed BUCKET_READY or READY")

    def _plan_bucket_rights(self, facts, calls) -> bool:
        """Dry run, existing bucket: lists the rights check; a STOP (False) when vending lacks a bucket right."""
        bucket = facts.get("bucket")
        missing = facts.get("bucket_rights_missing")
        if missing:
            calls.stop(f"gs://{bucket}", "BACKFILL.NO_RIGHTS_ON_BUCKET", f"vending lacks {', '.join(missing)}")
            return False
        calls.add("GET", f"storage b/{bucket}/iam/testPermissions", "vending holds the bucket rights")
        return True

    def _plan_migrate(self, pid, facts, calls, *, check_bucket: bool = False) -> None:
        n = facts.get("platform_state_versions")
        if facts.get("platform_lock") == "TOMBSTONE" or facts.get("migrated_at"):
            calls.add("NONE", f"gs://{self.platform_bucket}/{ri.state_prefix(pid)}", "already migrated")
            return
        if not n:
            calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "no platform state: signed READY")
            return
        if check_bucket and facts.get("bucket_state") == "PRESENT" and not self._plan_bucket_rights(facts, calls):
            return
        copies = min(n - 1, MAX_VERSIONS) + 1 if isinstance(n, int) else "?"
        dst = f"gs://{facts.get('bucket')}/{ri.state_object_name(pid)}"
        calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "signed MIGRATING")
        calls.add("WAIT", "pipeline_executions + tf-applier executions", "drain (at most 10 min)")
        calls.add("POST", f"gs://{self.platform_bucket}/{ri.lock_object_name(pid)}", "migration lock "
                  "(ifGenerationMatch=0)")
        calls.add("REWRITE", f"gs://{self.platform_bucket}/{ri.state_object_name(pid)} -> {dst}",
                  f"{copies} generation(s), oldest first, chained preconditions, crc32c checked")
        calls.add("POST", f"gs://{self.platform_bucket}/{ri.lock_object_name(pid)}", "tombstone (generation "
                  "precondition)")
        calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "signed READY")

    # -- migration --------------------------------------------------------------------------------------
    def _in_flight(self, pid: str) -> Optional[str]:
        """A reason when a run of this workload may be in flight; None when drained. Fails closed (a read error is
        'busy')."""
        return runs_in_flight(self.d, pid)

    def _drain(self, pid: str, polls: int = DRAIN_POLLS) -> None:
        reason = None
        for attempt in range(polls):
            reason = self._in_flight(pid)
            if reason is None:
                return
            if attempt + 1 < polls:
                self.d.sleep(DRAIN_POLL_S)
        raise _err("STATE_MIGRATION_BUSY", f"{pid}: {reason}", 409)

    def _migrate(self, pid: str, record: Dict[str, Any], broker: str, calls: _Plan, *,
                 check_bucket: bool = True) -> str:
        mig = dict(record.get("migration") or {})
        status = record.get("status")
        dst_bucket = record.get("state_bucket")
        if not ri.is_state_bucket_name_for(record.get("project_id"), dst_bucket):
            raise _err("BACKFILL.NOT_PROVISIONED", f"{pid}: the record has no state bucket")
        src_bucket, obj = self.platform_bucket, ri.state_object_name(pid)
        if status == ri.STATUS_READY and mig.get("migrated_at"):
            return "ALREADY_MIGRATED"
        if status not in (ri.STATUS_BUCKET_READY, ri.STATUS_READY, ri.STATUS_MIGRATING):
            raise _err("BACKFILL.NOT_PROVISIONED", f"{pid}: runner identity status {status!r}")
        lock_gen, lock = self._lock(src_bucket, pid)
        source = self._versions(src_bucket, obj)
        if check_bucket and (status == ri.STATUS_MIGRATING or source):
            # SAT-45: a migration without ensure_bucket in this run checks vending's rights on the destination
            # before it writes anything (record, lock or object).
            self._require_bucket_rights(pid, dst_bucket)
        if status != ri.STATUS_MIGRATING:
            if ri.is_tombstone(lock):
                raise _err("STATE_MIGRATION_CONFLICT", f"{pid}: a tombstone exists but the record is not migrated")
            if not source:
                if status != ri.STATUS_READY:
                    self._write(pid, record, broker, status=ri.STATUS_READY, error_class=None)
                    calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "no platform state: READY")
                return "NOTHING_TO_MIGRATE"
            previous = status
            mig = {"source_bucket": src_bucket, "source_object": obj, "lock_id": "stackvend-migration-"
                   + secrets.token_hex(8), "lock_generation": None, "started_at": self._now(),
                   "max_versions": MAX_VERSIONS, "previous_status": previous, "planned": None, "copied": [],
                   "last_source_generation_copied": None, "migrated_from": None, "migrated_at": None,
                   "tombstone_generation": None, "restored_at": None, "purged_at": None}
            record = self._write(pid, record, broker, status=ri.STATUS_MIGRATING, error_class=None, migration=mig)
            calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "signed MIGRATING")

        # A resumed migration may already hold its own lock (crash after step 3): an abort must release it.
        lock_gen_mine: Optional[str] = lock_gen if ri.is_migration_lock(lock, mig.get("lock_id") or "-") else None

        def _abort(code: str, detail: str):
            """Nothing copied yet: release our migration lock and put the record back (the workload is not blocked).
            Something copied: keep MIGRATING, the lock and the cursor, with the error class (resume later)."""
            if not (mig.get("copied") or []):
                if lock_gen_mine is not None:
                    self._delete_generation(src_bucket, ri.lock_object_name(pid), lock_gen_mine)
                self._write(pid, record, broker, status=mig.get("previous_status") or ri.STATUS_BUCKET_READY,
                            error_class=code, migration=None)
            else:
                self._write(pid, record, broker, status=ri.STATUS_MIGRATING, error_class=code, migration=mig)
            raise _err(code, detail)

        # 2. drain
        try:
            self._drain(pid)
        except RunnerIdentityError as e:
            _abort(e.code, e.detail)
        # 3. migration lock (or resume under ours, or finish after our tombstone)
        lock_gen, lock = self._lock(src_bucket, pid)
        planned_done = bool(mig.get("planned")) and len(mig.get("copied") or []) == len(mig["planned"])
        if ri.is_tombstone(lock) and planned_done and lock.get("Info") == ri.tombstone_info(dst_bucket, pid):
            if not mig.get("migrated_from"):   # crashed between the tombstone and the record write
                mig.update(tombstone_generation=lock_gen, migrated_from={
                    "bucket": src_bucket, "generation": mig["planned"][-1], "crc32c": mig["copied"][-1]["crc32c"]})
            return self._finish(pid, record, broker, mig, calls)
        if lock is None:
            info = ri.lock_info(operation=ri.MIGRATION_LOCK_OPERATION, lock_id=mig["lock_id"],
                                info=f"StackVend state migration to gs://{dst_bucket}/{ri.state_prefix(pid)}",
                                path=ri.lock_object_name(pid), created=self._now())
            taken = self._upload_lock(src_bucket, pid, info, "0")
            if taken is None:
                _abort("STATE_LOCKED", f"{pid}: the platform state lock was taken concurrently")
            lock_gen_mine = taken
            calls.add("POST", f"gs://{src_bucket}/{ri.lock_object_name(pid)}", "migration lock")
        elif ri.is_migration_lock(lock, mig["lock_id"]):
            lock_gen_mine = lock_gen
        else:
            _abort("STATE_LOCKED", f"{pid}: the platform state is locked by another run")
        mig["lock_generation"] = lock_gen_mine
        # 4. copy, oldest first, chained preconditions, resumable
        source = self._versions(src_bucket, obj)
        live = self._live(source)
        if live is None:
            _abort("STATE_MIGRATION_CONFLICT", f"{pid}: the platform state has no live object")
        noncurrent = [v for v in source if v is not live and v.get("timeDeleted")]
        planned = [v["generation"] for v in noncurrent[-MAX_VERSIONS:]] + [live["generation"]]
        if mig.get("planned") is not None and mig["planned"] != planned:
            _abort("STATE_MIGRATION_RACE", f"{pid}: the platform state changed since the migration started")
        mig["planned"] = planned
        by_gen = {v["generation"]: v for v in source}
        copied: List[Dict[str, Any]] = list(mig.get("copied") or [])
        dest = self._versions(dst_bucket, obj)
        if len(dest) == len(copied) + 1 and len(copied) < len(planned):
            nxt = planned[len(copied)]
            extra = dest[-1]
            if (extra.get("metadata") or {}).get(SOURCE_GENERATION_KEY) == nxt \
                    and extra.get("crc32c") == by_gen[nxt].get("crc32c"):
                copied.append({"source_generation": nxt, "destination_generation": extra["generation"],
                               "crc32c": extra["crc32c"]})   # copied before a crash, cursor not yet written
        if [d["generation"] for d in dest] != [c["destination_generation"] for c in copied] \
                or [d.get("crc32c") for d in dest] != [c["crc32c"] for c in copied]:
            _abort("STATE_MIGRATION_CONFLICT", f"{pid}: gs://{dst_bucket}/{obj} holds generations this migration "
                   "did not write")
        mig["copied"] = copied
        # The chain continues from the destination's LIVE generation: our last recorded copy, or none at all when a bad
        # copy was removed (RT F2-3: the earlier copies are then noncurrent, and "0" asserts there is no live object).
        dest_live = self._live(dest)
        if dest_live is not None and (not copied or dest_live["generation"] != copied[-1]["destination_generation"]):
            _abort("STATE_MIGRATION_CONFLICT", f"{pid}: the live gs://{dst_bucket}/{obj} is not this migration's copy")
        precondition = dest_live["generation"] if dest_live is not None else "0"
        for src_gen in planned[len(copied):]:
            src = by_gen[src_gen]
            meta = {SOURCE_GENERATION_KEY: src_gen, SOURCE_UPDATED_KEY: str(src.get("updated") or ""),
                    SOURCE_BUCKET_KEY: src_bucket}
            res = self._rewrite(src_bucket, obj, src_gen, dst_bucket, obj, precondition, meta,
                                src.get("contentType"))
            if res is None:
                _abort("STATE_MIGRATION_CONFLICT", f"{pid}: destination precondition {precondition} failed")
            if res.get("crc32c") != src.get("crc32c") or not _gen(res.get("generation")):
                # RT F2-3: this run wrote that destination generation; remove exactly it (generation precondition)
                # so a later run does not find a foreign generation and refuse forever.
                removed = "not removed (no generation)"
                if _gen(res.get("generation")):
                    st = self._delete_generation(dst_bucket, obj, _gen(res["generation"]))
                    removed = "removed" if st in (200, 204) else f"NOT removed (HTTP {st}; delete it by hand)"
                    calls.add("DELETE", f"gs://{dst_bucket}/{obj}#{_gen(res['generation'])}",
                              f"bad copy of generation {src_gen} {removed}")
                _abort("STATE_MIGRATION_CONFLICT", f"{pid}: copy of generation {src_gen} has crc32c "
                       f"{res.get('crc32c')!r}, source {src.get('crc32c')!r}; the bad copy was {removed}")
            copied.append({"source_generation": src_gen, "destination_generation": _gen(res["generation"]),
                           "crc32c": res["crc32c"]})
            mig["copied"], mig["last_source_generation_copied"] = copied, src_gen
            record = self._write(pid, record, broker, status=ri.STATUS_MIGRATING, error_class=None, migration=mig)
            calls.add("REWRITE", f"gs://{src_bucket}/{obj}#{src_gen} -> gs://{dst_bucket}/{obj}",
                      f"ifGenerationMatch={precondition}")
            precondition = copied[-1]["destination_generation"]
        # serial / lineage of the live generation (bytes are never edited; crc32c already equal)
        s1, src_state = self._read_json(src_bucket, obj, live["generation"])
        s2, dst_state = self._read_json(dst_bucket, obj, copied[-1]["destination_generation"])
        if s1 != 200 or s2 != 200 or src_state.get("serial") != dst_state.get("serial") \
                or src_state.get("lineage") != dst_state.get("lineage") or "lineage" not in src_state:
            _abort("STATE_MIGRATION_CONFLICT", f"{pid}: serial / lineage of the copy differ from the source")
        # 5. race re-check
        after = self._live(self._versions(src_bucket, obj))
        if after is None or after["generation"] != live["generation"]:
            _abort("STATE_MIGRATION_RACE", f"{pid}: the platform state changed during the copy")
        # 6. tombstone
        tomb = ri.lock_info(operation=ri.TOMBSTONE_OPERATION, lock_id=f"stackvend-moved-{mig['lock_id'][-16:]}",
                            info=ri.tombstone_info(dst_bucket, pid), path=ri.lock_object_name(pid),
                            created=self._now())
        tomb_gen = self._upload_lock(src_bucket, pid, tomb, lock_gen_mine)
        if tomb_gen is None:
            _abort("STATE_MIGRATION_RACE", f"{pid}: the migration lock changed before the tombstone")
        calls.add("POST", f"gs://{src_bucket}/{ri.lock_object_name(pid)}", "tombstone")
        mig.update(tombstone_generation=tomb_gen, migrated_from={"bucket": src_bucket, "generation":
                   live["generation"], "crc32c": live.get("crc32c")})
        record = self._write(pid, record, broker, status=ri.STATUS_MIGRATING, error_class=None, migration=mig)
        return self._finish(pid, record, broker, mig, calls)

    def _finish(self, pid, record, broker, mig, calls) -> str:
        mig = dict(mig, migrated_at=self._now())
        mig.pop("previous_status", None)
        self._write(pid, record, broker, status=ri.STATUS_READY, error_class=None, migration=mig)
        calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "signed READY (migrated)")
        logger.info(f"State of {pid} migrated to gs://{record.get('state_bucket')}/{ri.state_prefix(pid)} "
                    f"({len(mig.get('copied') or [])} generation(s))")
        return "MIGRATED"

    # -- owner actions ----------------------------------------------------------------------------------
    def _migrated_record(self, pid, prov, broker) -> Dict[str, Any]:
        rec = self.provisioner.verified_existing(pid, prov, broker)
        mig = (rec or {}).get("migration") or {}
        if not rec or rec.get("status") != ri.STATUS_READY or not mig.get("migrated_at") or mig.get("restored_at"):
            raise _err("BACKFILL.NOT_MIGRATED", f"{pid}: no completed migration in the runner identity record")
        ri.check_runner_identity(rec, product_id=pid, project_id=prov.get("project_id"))
        return rec

    def _restore(self, pid, prov, broker, dry_run, calls) -> str:
        rec = self._migrated_record(pid, prov, broker)
        mig = dict(rec["migration"])
        obj, src_bucket = ri.state_object_name(pid), rec["state_bucket"]
        if dry_run:
            calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "signed MIGRATING")
            calls.add("REWRITE", f"gs://{src_bucket}/{obj} -> gs://{self.platform_bucket}/{obj}", "live state back")
            calls.add("DELETE", f"gs://{self.platform_bucket}/{ri.lock_object_name(pid)}", "tombstone")
            calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "signed BUCKET_READY (restored)")
            return "DRY_RUN"
        tomb_gen, tomb = self._lock(self.platform_bucket, pid)
        if not ri.is_tombstone(tomb):
            raise _err("STATE_MIGRATION_CONFLICT", f"{pid}: the platform lock is not the tombstone")
        rec = self._write(pid, rec, broker, status=ri.STATUS_MIGRATING, error_class=None, migration=mig)
        try:
            self._drain(pid)
        except RunnerIdentityError as e:
            self._write(pid, rec, broker, status=ri.STATUS_READY, error_class=e.code, migration=mig)
            raise
        live = self._live(self._versions(src_bucket, obj))
        platform_live = self._live(self._versions(self.platform_bucket, obj))
        if live is None:
            self._write(pid, rec, broker, status=ri.STATUS_READY, error_class="STATE_MIGRATION_CONFLICT",
                        migration=mig)
            raise _err("STATE_MIGRATION_CONFLICT", f"{pid}: gs://{src_bucket}/{obj} has no live state")
        res = self._rewrite(src_bucket, obj, live["generation"], self.platform_bucket, obj,
                            platform_live["generation"] if platform_live else "0",
                            {SOURCE_GENERATION_KEY: live["generation"], SOURCE_UPDATED_KEY: str(live.get("updated")
                                                                                              or ""),
                             SOURCE_BUCKET_KEY: src_bucket}, live.get("contentType"))
        if res is None or res.get("crc32c") != live.get("crc32c"):
            self._write(pid, rec, broker, status=ri.STATUS_READY, error_class="STATE_MIGRATION_RACE", migration=mig)
            raise _err("STATE_MIGRATION_RACE", f"{pid}: the platform copy changed during the restore")
        calls.add("REWRITE", f"gs://{src_bucket}/{obj}#{live['generation']} -> gs://{self.platform_bucket}/{obj}",
                  "restore")
        st = self._delete_generation(self.platform_bucket, ri.lock_object_name(pid), tomb_gen)
        if st not in (200, 204):
            self._write(pid, rec, broker, status=ri.STATUS_MIGRATING, error_class="STATE_RESTORE_INCOMPLETE",
                        migration=mig)
            raise _err("STATE_RESTORE_INCOMPLETE", f"{pid}: the state is back but the tombstone delete answered "
                       f"HTTP {st}")
        calls.add("DELETE", f"gs://{self.platform_bucket}/{ri.lock_object_name(pid)}#{tomb_gen}", "tombstone")
        mig.update(restored_at=self._now(), restored_generation=_gen(res.get("generation")))
        self._write(pid, rec, broker, status=ri.STATUS_BUCKET_READY, error_class=None, migration=mig)
        calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "signed BUCKET_READY (restored)")
        return "RESTORED"

    def _purge(self, pid, prov, broker, dry_run, calls) -> str:
        rec = self._migrated_record(pid, prov, broker)
        mig = dict(rec["migration"])
        if mig.get("purged_at"):
            return "ALREADY_PURGED"
        migrated = dg._parse_ts(mig.get("migrated_at"))
        if migrated is None or self.d.clock() - migrated < PURGE_AFTER:
            raise _err("BACKFILL.PURGE_TOO_EARLY", f"{pid}: migrated at {mig.get('migrated_at')}; the old copy is "
                       f"kept {PURGE_AFTER.days} days")
        obj = ri.state_object_name(pid)
        _tg, tomb = self._lock(self.platform_bucket, pid)
        if not ri.is_tombstone(tomb):
            raise _err("STATE_MIGRATION_CONFLICT", f"{pid}: the platform lock is not the tombstone; nothing purged")
        versions = self._versions(self.platform_bucket, obj)
        for v in versions:
            calls.add("DELETE", f"gs://{self.platform_bucket}/{obj}#{v['generation']}", "old platform copy")
        if dry_run:
            return "DRY_RUN"
        failed = []
        for v in versions:
            st = self._delete_generation(self.platform_bucket, obj, v["generation"])
            if st not in (200, 204, 404):
                failed.append(f"{v['generation']} (HTTP {st})")
        if failed:
            raise _err("STATE_PURGE_INCOMPLETE", f"{pid}: generations not deleted: {', '.join(failed)}", 502)
        mig.update(purged_at=self._now(), purged_generations=len(versions))
        self._write(pid, rec, broker, status=ri.STATUS_READY, error_class=None, migration=mig)
        calls.add("UPDATE", f"workload_provenance/{pid}.runner_identity", "purged_at recorded")
        return "PURGED"


# ------------------------------------------------------------------------------------------------ in-flight runs
# SAT-41 (pre-switch RT HIGH-2): a terraform stage IN_FLIGHT for longer than the workflow waits for its callback
# (workflows/main_orchestrator.yaml await_deploy_callback: 87 300 s = the tf-applier job timeout + 15 min) has no
# workflow waiting any more; the install-wide check of the mode switch does not wait for it (a crashed run would
# otherwise block every switch). A running tf-applier execution is always busy.
WORKFLOW_DEPLOY_WAIT = timedelta(seconds=87300)
TF_STAGE_STATUS_FIELD = "stages.terraform.status"   # the field the terraform server's IN_FLIGHT record writes


def runs_in_flight(deps: rb.RunnerDeps, product_id: Optional[str] = None, *,
                   stale_after: Optional[timedelta] = None) -> Optional[str]:
    """A reason when a Terraform run may be in flight, None when there is none. Fails closed (a read error is 'busy').
    `product_id` (the backfill's drain): that workload's pipeline_executions and tf-applier executions. None (SAT-41,
    the mode switch): every workload's IN_FLIGHT terraform stage (one query on `stages.terraform.status`) and every
    running tf-applier execution. `stale_after`: an IN_FLIGHT stage that started longer ago than this does not count
    (only with a readable `started_at`)."""
    db = deps.store.db
    try:
        coll = db.collection("pipeline_executions")
        query = (coll.where("product_id", "==", product_id) if product_id is not None
                 else coll.where(TF_STAGE_STATUS_FIELD, "==", "IN_FLIGHT"))
        for snap in query.stream():
            data = snap.to_dict() or {}
            tf = (data.get("stages") or {}).get("terraform") if isinstance(data.get("stages"), dict) else None
            if isinstance(tf, dict) and tf.get("status") == "IN_FLIGHT":
                started = dg._parse_ts(tf.get("started_at")) if stale_after is not None else None
                if started is not None and deps.clock() - started > stale_after:
                    continue
                return f"pipeline_executions/{snap.id} terraform IN_FLIGHT"
    except Exception as e:  # noqa: BLE001
        return f"pipeline_executions unreadable ({type(e).__name__})"
    region = deps.region()
    if not region:
        return "vending's region is unknown (tf-applier executions not checked)"
    bound = set()
    if product_id is not None:
        try:
            for snap in deps.store.guard_db.collection(ri.NONCE_COLLECTION).where("product_id", "==",
                                                                                   product_id).stream():
                ex = (snap.to_dict() or {}).get("execution")
                if isinstance(ex, str):
                    bound.add(ex)
        except Exception as e:  # noqa: BLE001
            return f"runner dispatch records unreadable ({type(e).__name__})"
    job = f"projects/{deps.config.host_project_id}/locations/{region}/jobs/{deps.config.job_name}"
    token = None
    for _ in range(20):
        params = {"pageSize": 100}
        if token:
            params["pageToken"] = token
        status, body = deps.rest.call("get", f"{_RUN}{job}/executions", params=params)
        if status != 200:
            return f"tf-applier executions unreadable (HTTP {status})"
        for ex in body.get("executions") or []:
            if not isinstance(ex, dict) or ex.get("completionTime"):
                continue
            if product_id is None:
                return f"tf-applier execution {ex.get('name')} is running"
            if ex.get("name") in bound:
                return f"{ex.get('name')} (dispatched for {product_id}) is running"
            for c in ((ex.get("template") or {}).get("containers") or []):
                for env in (c.get("env") or []) if isinstance(c, dict) else []:
                    if isinstance(env, dict) and env.get("name") == "PRODUCT_ID" and env.get("value") == product_id:
                        return f"{ex.get('name')} (PRODUCT_ID={product_id}) is running"
        token = body.get("nextPageToken")
        if not token:
            return None
    return "tf-applier executions: too many pages"


# ------------------------------------------------------------------------------------------------ decommission
class StateArchiveFailed(Exception):
    def __init__(self, detail: str):
        super().__init__(detail)
        self.code, self.detail = "DECOMMISSION_STATE_ARCHIVE_FAILED", detail


def runner_state_location(deps: rb.RunnerDeps, product_id: str, provenance: Optional[Dict[str, Any]],
                          platform_bucket: str) -> Dict[str, Any]:
    """Where vending's decommission finds the state (plan 2.8). Uses the verified record (expected signer = this
    vending's broker identity); raises RunnerIdentityError when the record exists but cannot be trusted."""
    broker = rb.RunnerIdentityProvisioner(deps).broker()
    loc = ri.state_location(product_id, provenance, legacy_bucket=platform_bucket, expected_signer=broker,
                            certs=deps.certs)
    raw = (provenance or {}).get(ri.RUNNER_IDENTITY_FIELD)
    loc["migration"] = (raw or {}).get("migration") if isinstance(raw, dict) else None
    return loc


def archive_child_state(deps: rb.RunnerDeps, product_id: str, child_bucket: str, platform_bucket: str,
                        archive_name: str) -> Optional[Dict[str, Any]]:
    """Copies the live child state to the platform archive path (ifGenerationMatch=0, crc32c checked) BEFORE the
    project delete. None when the workload has no state yet. Raises StateArchiveFailed."""
    helper = RunnerIdentityBackfill(deps, platform_bucket=platform_bucket, region_for=lambda _p: None)
    obj = ri.state_object_name(product_id)
    try:
        live = helper._live(helper._versions(child_bucket, obj))
    except RunnerIdentityError as e:
        raise StateArchiveFailed(f"{e.code}: {e.detail}") from None
    if live is None:
        return None
    try:
        res = helper._rewrite(child_bucket, obj, live["generation"], platform_bucket, archive_name, "0",
                              {SOURCE_GENERATION_KEY: live["generation"],
                               SOURCE_UPDATED_KEY: str(live.get("updated") or ""), SOURCE_BUCKET_KEY: child_bucket},
                              live.get("contentType"))
    except RunnerIdentityError as e:
        raise StateArchiveFailed(f"{e.code}: {e.detail}") from None
    if res is None or res.get("crc32c") != live.get("crc32c"):
        raise StateArchiveFailed(f"gs://{platform_bucket}/{archive_name}: copy not verified")
    return {"archive_path": archive_name, "source_generation": live["generation"], "crc32c": live.get("crc32c")}


def delete_stale_platform_copy(deps: rb.RunnerDeps, product_id: str, platform_bucket: str) -> List[str]:
    """After the delete of a migrated workload (plan 2.8, F11): every generation of the old platform
    default.tfstate and the tombstone. Returns warnings (the project is gone; nothing here undoes it)."""
    helper = RunnerIdentityBackfill(deps, platform_bucket=platform_bucket, region_for=lambda _p: None)
    warnings: List[str] = []
    for name in (ri.state_object_name(product_id), ri.lock_object_name(product_id)):
        try:
            versions = helper._versions(platform_bucket, name)
        except RunnerIdentityError as e:
            warnings.append(f"STALE_STATE_NOT_DELETED {name}: {e.code}")
            continue
        for v in versions:
            st = helper._delete_generation(platform_bucket, name, v["generation"])
            if st not in (200, 204, 404):
                warnings.append(f"STALE_STATE_NOT_DELETED {name}#{v['generation']}: HTTP {st}")
    return warnings


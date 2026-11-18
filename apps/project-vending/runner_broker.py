"""
FD-7L Phase 1 (vending side): the per-workload deployer, its state bucket, the signed provenance record, and the
token broker. Plan: docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3 (owner 10-30) sections 2.1-2.3,
2.12, 3 (backfill-result) and 4 (probe). Register rows "FD-7L plan", FD-7L-n.

Everything here is inert while the install's operative mode is PLATFORM ("Shared": `STACKVEND_TF_RUNNER_IDENTITY` unset
or PLATFORM and no Per-workload Settings record, FD-7L-F4; read live through `shared.runner_identity.runner_identity_mode`):
vending runs none of the ensure_* steps and every /runner/* route answers 409 RUNNER_IDENTITY_MODE_PLATFORM after its
caller check. Nothing here is a fallback for anything else: every failure is a typed RunnerIdentityError.

Provisioner (`RunnerIdentityProvisioner.ensure`), run by vending after billing, API enablement and the 3c grants, for
every provenanced project (new, re-vend and retry alike; each step is idempotent):
  0 ensure_apis          iam / iamcredentials / storage ENABLED on the child (read only)   VENDING.RUNNER_IDENTITY_APIS_MISSING
  1 ensure_sa            stackvend-deployer (409 = adopt after an exact email check)     VENDING.DEPLOYER_SA_FAILED
  2 ensure_owner         add-only roles/owner for the deployer on its own project        VENDING.DEPLOYER_OWNER_GRANT_FAILED
  3 ensure_broker_grant  add-only tokenCreator on the deployer for the broker only        VENDING.BROKER_GRANT_FAILED
                         (another member already holding it refuses)                       VENDING.DEPLOYER_UNEXPECTED_TOKEN_CREATOR
  4 ensure_bucket        <project>-tfstate[-<6 hex>] in the workload region; uniform        VENDING.STATE_BUCKET_FAILED /
                         access, public access prevention, versioning; add-only IAM        VENDING.STATE_BUCKET_NAME_TAKEN
  5 record               provenance.runner_identity = READY, signed by vending
Every IAM write is add-only (read-modify-write with the etag; other bindings and members are never removed).

Broker (`RunnerBroker`): /runner/dispatch (terraform-server identities), /runner/redeem, /runner/deployer-token,
/runner/repo-token, /runner/backfill-result (tf-applier identities), /runner-identity/probe (Control Center). A nonce
is single use, bound to one execution (from the RunJob operation) and one product, redeemable for about 10 minutes,
and redeemed for a session key that lives only in the execution's memory; neither is ever logged or stored in clear.

google-auth / requests are imported inside the functions that use them (root-suite tests stub `google.*`).
"""
import base64
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from shared import runner_identity as ri   # committed replica in this service's shared/ (byte-identical to root)

import destructive_guard as dg

logger = logging.getLogger("project-vending-runner-broker")

RunnerIdentityError = ri.RunnerIdentityError

# Fixed persona account ids (infra/platform: google_service_account.agents / stackvend_personas keys; pinned by
# tests/test_fd7l_vending_runner_identity.py::test_persona_account_ids_exist_in_platform_terraform).
DEVELOPER_ACCOUNT_ID = "sa-castor-developer"
PROVISIONER_ACCOUNT_ID = "sa-project-provisioner"
CONTROL_CENTER_ACCOUNT_ID = "sa-stackvend-control-center"
# The two runner SAs step A creates (infra/platform/tf_runner_identity.tf locals; pinned by a test). FD-7L-F4: vending
# accepts a Per-workload mode record only when its Terraform-owned step-A env names them.
RUNNER_JOB_ACCOUNT_ID = "sa-stackvend-tf-applier"
RUNNER_SERVER_ACCOUNT_ID = "sa-stackvend-tf-server"

REQUIRED_CHILD_APIS = ("iam.googleapis.com", "iamcredentials.googleapis.com", "storage.googleapis.com")
OWNER_ROLE = "roles/owner"
TOKEN_CREATOR_ROLE = "roles/iam.serviceAccountTokenCreator"
OBJECT_ADMIN_ROLE = "roles/storage.objectAdmin"
OBJECT_VIEWER_ROLE = "roles/storage.objectViewer"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

# Bounded retries. IAM and bucket writes that name a service account created a moment ago can answer 400 / 404
# (eventual consistency) and 409 / 412 (etag race); 429 / 5xx are transient. Status codes only, never message text.
IAM_RETRY_STATUSES = frozenset({400, 404, 409, 412, 429, 500, 502, 503, 504})
TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
MINT_RETRY_STATUSES = frozenset({403, 404}) | TRANSIENT_STATUSES   # 403 / 404 right after a new grant (propagation)
IAM_WRITE_ATTEMPTS = 5
API_CHECK_ATTEMPTS = 6
RETRY_DELAY_S = 3.0
# RT F3: the deployer-token mint waits for IAM propagation only while the record is young (its grant was made less
# than PROPAGATION_YOUNG_S ago), and then at most IMPERSONATION_PROPAGATION_S. Otherwise a 403 / 404 answers at once
# (a removed grant must not pin a vending worker); transient statuses get MINT_TRANSIENT_ATTEMPTS; the probe makes one
# call per record.
PROPAGATION_YOUNG_S = 120.0
IMPERSONATION_PROPAGATION_S = 60.0
MINT_TRANSIENT_ATTEMPTS = 3
# RT F1: Google rotates the broker's Google-managed signing keys; a READY record older than this is re-signed with the
# current key after a successful verification (and by the /runner-identity/resign sweep for idle workloads).
RESIGN_AFTER_SECONDS = 72 * 3600

TF_APPLIER_JOB_ENV = "TF_APPLIER_JOB_NAME"
TF_APPLIER_JOB_DEFAULT = "tf-applier"
STAGING_BUCKET_ENV = "STACKVEND_RUNNER_STAGING_BUCKET"
NONCE_ENV_NAME = "RUNNER_NONCE"
WORKFLOW_CALLBACK_HOST = "workflowexecutions.googleapis.com"

_IAM = "https://iam.googleapis.com/v1/"
_IAMCREDS = "https://iamcredentials.googleapis.com/v1/"
_STORAGE = "https://storage.googleapis.com/storage/v1/"
_SERVICEUSAGE = "https://serviceusage.googleapis.com/v1/"
_RUN = "https://run.googleapis.com/v2/"
RUN_V1_CREATOR_ANNOTATION = "run.googleapis.com/creator"   # RT F2: system-set on the v1 Execution
# SAT-52: a just-started execution can read runningCount 0 (the Admin API lags the container start). /runner/redeem
# then answers this retryable refusal instead of RUNNER_EXECUTION_NOT_RUNNING, but only when no structured field of the
# v2 Execution says it has ended (`_execution_ended`). 409 like RUNNER_DISPATCH_NOT_BOUND ("retry shortly"): the request
# conflicts with the execution's current state; 403 stays for permanent refusals and 503 for an unreadable execution.
RUNNER_EXECUTION_NOT_YET_RUNNING = "RUNNER_EXECUTION_NOT_YET_RUNNING"
NOT_YET_RUNNING_STATUS = 409
# Cloud Run v2 Condition: CONDITION_SUCCEEDED / CONDITION_FAILED are the documented terminal states; "Completed" is the
# execution's completion condition; these ExecutionReason values mean the execution is cancelled or deleted, or (RT
# LOW) NON_ZERO_EXIT_CODE: a task reached its retry limit (tf-applier: max_retries = 0) and its last attempt failed.
_RUN_COMPLETED_CONDITION = "Completed"
_RUN_TERMINAL_CONDITION_STATES = frozenset({"CONDITION_SUCCEEDED", "CONDITION_FAILED"})
_RUN_ENDED_EXECUTION_REASONS = frozenset({"CANCELLED", "CANCELLING", "DELETED", "NON_ZERO_EXIT_CODE"})
# SAT-52 RT LOW: the v2 Execution timestamps that are set only once the execution has ended or is being deleted.
_RUN_ENDED_TIMESTAMPS = ("completionTime", "deleteTime")
# `_execution_state` answers
EXECUTION_RUNNING = "RUNNING"
EXECUTION_NOT_YET_RUNNING = "NOT_YET_RUNNING"
EXECUTION_ENDED = "ENDED"
_CRM_V3 = "https://cloudresourcemanager.googleapis.com/v3/"
_METADATA = "http://metadata.google.internal/computeMetadata/v1/"


def _err(code: str, detail: str, status: int = 409, stage: str = "runner-identity") -> RunnerIdentityError:
    return RunnerIdentityError(code, detail, stage=stage, http_status=status)


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _execution_ended(exe: Mapping[str, Any]) -> bool:
    """SAT-52: True when a structured field of a Cloud Run v2 Execution shows it has ended or is ending: completionTime
    or deleteTime present; a "Completed" condition in a terminal state; an executionReason CANCELLED / CANCELLING /
    DELETED / NON_ZERO_EXIT_CODE; a failed or cancelled task; every task terminal (succeeded + failed + cancelled >=
    taskCount, absent = 1). A field that is present but malformed counts as ended (the permanent refusal). Never
    message text. RT LOW: a timestamp is judged by presence, not truthiness: proto3 JSON omits an unset Timestamp (or
    sends null), so any other value -- an empty string included -- is "set" (or malformed) and means ended."""
    if any(exe.get(key) is not None for key in _RUN_ENDED_TIMESTAMPS):
        return True
    conditions = exe.get("conditions", [])
    if not isinstance(conditions, list):
        return True
    for c in conditions:
        if not isinstance(c, dict):
            return True
        if c.get("type") == _RUN_COMPLETED_CONDITION and c.get("state") in _RUN_TERMINAL_CONDITION_STATES:
            return True
        if c.get("executionReason") in _RUN_ENDED_EXECUTION_REASONS:
            return True
    counts = {}
    for key in ("succeededCount", "failedCount", "cancelledCount"):
        value = exe.get(key, 0)                       # proto3 JSON omits zero counts
        if not _is_count(value):
            return True
        counts[key] = value
    tasks = exe.get("taskCount", 1)
    if not _is_count(tasks):
        return True
    return counts["failedCount"] > 0 or counts["cancelledCount"] > 0 or sum(counts.values()) >= max(tasks, 1)


def _execution_state(exe: Mapping[str, Any]) -> str:
    """SAT-52 RT LOW: the one reading of a v2 Execution's run state. Every ended signal (`_execution_ended`) wins over
    runningCount, so an execution that ended between two reads -- even while runningCount still lags at >= 1 or has
    dropped to 0 before completionTime is written -- is EXECUTION_ENDED, never "not yet running". Otherwise runningCount
    >= 1 is EXECUTION_RUNNING; absent (proto3 JSON omits a zero) or 0 is EXECUTION_NOT_YET_RUNNING; any other value is
    malformed and EXECUTION_ENDED (the permanent refusal)."""
    if _execution_ended(exe):
        return EXECUTION_ENDED
    if "runningCount" not in exe:
        return EXECUTION_NOT_YET_RUNNING
    running = exe.get("runningCount")
    if not _is_count(running):
        return EXECUTION_ENDED
    return EXECUTION_RUNNING if running >= 1 else EXECUTION_NOT_YET_RUNNING


def _now_iso(clock: Callable[[], datetime]) -> str:
    return clock().astimezone(timezone.utc).isoformat()


# ------------------------------------------------------------------------------------------------ configuration
@dataclass(frozen=True)
class BrokerConfig:
    host_project_id: str
    mode: str
    broker_env: Optional[str]
    runner_members: FrozenSet[str]
    server_members: FrozenSet[str]
    job_name: str
    staging_bucket: Optional[str]

    @staticmethod
    def members_from_env(name: str, environ: Optional[Mapping[str, str]] = None) -> FrozenSet[str]:
        """The caller allow-list `name` (RUNNER_MEMBERS_ENV / SERVER_MEMBERS_ENV). Reads only the environment: the
        route dependencies call it before the caller is authenticated (RT F6), so it builds no client and does not
        parse the mode."""
        env = os.environ if environ is None else environ
        raw = env.get(name)
        if raw is not None and raw.strip():
            return ri.csv_emails(raw)
        # plan 2.3: before step A, the existing child-owner list (= sa-castor-developer)
        return ri.service_account_members(env.get("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS"))

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "BrokerConfig":
        """Raises RunnerIdentityError(RUNNER_IDENTITY_MODE_INVALID) for an unknown mode value. `mode` is the install's
        DECLARATION only (FD-7L-F4): the operative mode is read live through RunnerDeps.mode."""
        env = os.environ if environ is None else environ
        mode = ri.declared_mode(env)
        broker = (env.get(ri.BROKER_SA_ENV) or "").strip().lower() or None
        return cls(host_project_id=(env.get("PROJECT_ID") or "").strip(), mode=mode, broker_env=broker,
                   runner_members=cls.members_from_env(ri.RUNNER_MEMBERS_ENV, env),
                   server_members=cls.members_from_env(ri.SERVER_MEMBERS_ENV, env),
                   job_name=(env.get(TF_APPLIER_JOB_ENV) or "").strip() or TF_APPLIER_JOB_DEFAULT,
                   staging_bucket=(env.get(STAGING_BUCKET_ENV) or "").strip() or None)

    def developer_email(self) -> str:
        return ri.service_account_email(DEVELOPER_ACCOUNT_ID, self.host_project_id).lower()

    def control_center_email(self) -> str:
        return ri.service_account_email(CONTROL_CENTER_ACCOUNT_ID, self.host_project_id).lower()

    def broker_email(self, runtime_email: Optional[str]) -> str:
        """The one identity that may hold tokenCreator on deployers and sign records (re-RT R9). It must be vending's
        own runtime SA, named by STACKVEND_BROKER_SA (Terraform-owned, step A) or, before that, the runtime SA when it
        is sa-project-provisioner of this host. Never sa-castor-developer, never a runner or server member."""
        runtime = (runtime_email or "").strip().lower()
        if not self.host_project_id:
            raise _err("RUNNER_BROKER_SHARED_IDENTITY", "PROJECT_ID is not configured", 503)
        if not runtime:
            raise _err("RUNNER_BROKER_SHARED_IDENTITY", "vending's runtime identity is unknown", 503)
        if self.broker_env:
            broker = self.broker_env
        elif runtime == ri.service_account_email(PROVISIONER_ACCOUNT_ID, self.host_project_id).lower():
            broker = runtime
        else:
            raise _err("RUNNER_BROKER_SHARED_IDENTITY",
                       f"vending runs as {runtime}, not as its own provisioner identity; set {ri.BROKER_SA_ENV}", 503)
        if broker != runtime:
            raise _err("RUNNER_BROKER_SHARED_IDENTITY", f"{ri.BROKER_SA_ENV} names {broker}, but vending runs as "
                       f"{runtime}", 503)
        if broker == self.developer_email() or broker in self.runner_members or broker in self.server_members:
            raise _err("RUNNER_BROKER_SHARED_IDENTITY", f"{broker} is shared with the runners", 503)
        return broker

    def step_a_missing(self) -> List[str]:
        """FD-7L-F4: what of the step-A runner setup this vending's Terraform-owned env does not show (empty = step A
        applied): the broker identity, both runner SAs in the caller lists (before step A the lists are derived and
        never name them) and the runner staging bucket. Exact values, set membership only."""
        missing = []
        if not self.host_project_id:
            return ["PROJECT_ID"]
        if not self.broker_env:
            missing.append(ri.BROKER_SA_ENV)
        if ri.service_account_email(RUNNER_JOB_ACCOUNT_ID, self.host_project_id).lower() not in self.runner_members:
            missing.append(f"{ri.RUNNER_MEMBERS_ENV} ({RUNNER_JOB_ACCOUNT_ID})")
        if ri.service_account_email(RUNNER_SERVER_ACCOUNT_ID, self.host_project_id).lower() not in self.server_members:
            missing.append(f"{ri.SERVER_MEMBERS_ENV} ({RUNNER_SERVER_ACCOUNT_ID})")
        if not self.staging_bucket:
            missing.append(STAGING_BUCKET_ENV)
        return missing


_runtime_email_lock = threading.Lock()
_runtime_email_cache: Dict[str, str] = {}


def metadata_runtime_email() -> Optional[str]:
    """This instance's service account email from the metadata server (cached). None off Cloud Run."""
    with _runtime_email_lock:
        if "email" in _runtime_email_cache:
            return _runtime_email_cache["email"]
    if not os.getenv("K_SERVICE"):
        return None
    try:
        import requests
        resp = requests.get(f"{_METADATA}instance/service-accounts/default/email",
                            headers={"Metadata-Flavor": "Google"}, timeout=2)
        email = resp.text.strip().lower() if resp.status_code == 200 else ""
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Could not read vending's runtime identity ({type(e).__name__})")
        return None
    if not email:
        return None
    with _runtime_email_lock:
        _runtime_email_cache["email"] = email
    return email


def metadata_region() -> Optional[str]:
    """This instance's region (the tf-applier job lives in the platform region). None off Cloud Run."""
    if not os.getenv("K_SERVICE"):
        return None
    try:
        import requests
        resp = requests.get(f"{_METADATA}instance/region", headers={"Metadata-Flavor": "Google"}, timeout=2)
        region = resp.text.strip().rsplit("/", 1)[-1] if resp.status_code == 200 else ""
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Could not read vending's region ({type(e).__name__})")
        return None
    return region or None


# ------------------------------------------------------------------------------------------------ REST adapter
class GoogleRest:
    """Google REST over an AuthorizedSession (vending's own identity), or with an explicit bearer token (probe).
    Returns (status, body dict); a transport failure is status 0. Never logs tokens or bodies."""

    def __init__(self, session: Any = None, http: Any = None):
        self._session = session
        self._http = http

    def _s(self):
        if self._session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            creds, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
            self._session = AuthorizedSession(creds)
        return self._session

    def call(self, method: str, url: str, *, json: Any = None, params: Any = None,
             bearer: Optional[str] = None, timeout: float = 15.0) -> Tuple[int, Dict[str, Any]]:
        try:
            if bearer is not None:
                http = self._http
                if http is None:
                    import requests as http
                resp = http.request(method.upper(), url, json=json, params=params, timeout=timeout,
                                    headers={"Authorization": f"Bearer {bearer}"})
            else:
                resp = self._s().request(method.upper(), url, json=json, params=params, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - transport error
            logger.warning(f"{method.upper()} {url.split('?', 1)[0]} transport error ({type(e).__name__})")
            return 0, {}
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            body = {}
        return int(getattr(resp, "status_code", 0) or 0), body if isinstance(body, dict) else {}


class IamSigner:
    """IAM Credentials signBlob as the broker itself (needs serviceAccountTokenCreator of the broker on itself: plan
    step A, the precedent of gateway_self_sign_blob)."""

    def __init__(self, rest: GoogleRest, email: str):
        self.rest, self.email = rest, email

    def __call__(self, payload: bytes) -> Tuple[str, str]:
        status, body = self.rest.call("post", f"{_IAMCREDS}projects/-/serviceAccounts/{self.email}:signBlob",
                                      json={"payload": base64.b64encode(payload).decode("ascii")})
        if status != 200 or not isinstance(body.get("keyId"), str) or not isinstance(body.get("signedBlob"), str):
            raise _err("RUNNER_RECORD_SIGN_FAILED", f"signBlob as {self.email} answered HTTP {status}", 503)
        return body["keyId"], body["signedBlob"]


# ------------------------------------------------------------------------------------------------ store
class RunnerStore:
    """Guard-DB records (provenance, runner nonces) + the default-DB ledger. StoreUnavailable -> 503."""

    def __init__(self, db: Any, guard_db: Any):
        self.db, self.guard_db = db, guard_db

    @staticmethod
    def _get(db, collection: str, doc_id: str) -> Optional[Dict[str, Any]]:
        if db is None:
            raise _err("RUNNER_STORE_UNAVAILABLE", "Firestore client unavailable", 503)
        try:
            snap = db.collection(collection).document(doc_id).get()
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"{collection} unreadable ({type(e).__name__})", 503) from None
        if getattr(snap, "exists", False) is not True:
            return None
        data = snap.to_dict()
        return data if isinstance(data, dict) else {}

    def get_provenance(self, product_id: str) -> Optional[Dict[str, Any]]:
        return self._get(self.guard_db, ri.PROVENANCE_COLLECTION, product_id)

    def get_workload(self, product_id: str) -> Optional[Dict[str, Any]]:
        """workloads/{product_id} from the default database (read-only; the backfill status card, SAT-47)."""
        return self._get(self.db, "workloads", product_id)

    def list_provenance(self) -> List[Tuple[str, Dict[str, Any]]]:
        try:
            return [(s.id, s.to_dict() or {}) for s in self.guard_db.collection(ri.PROVENANCE_COLLECTION).stream()]
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"provenance list failed ({type(e).__name__})", 503) from None

    def write_runner_identity(self, product_id: str, record: Dict[str, Any]) -> None:
        """update() replaces the whole field (a merge would keep stale nested keys and break the signature)."""
        try:
            self.guard_db.collection(ri.PROVENANCE_COLLECTION).document(product_id).update(
                {ri.RUNNER_IDENTITY_FIELD: record})
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"provenance write failed ({type(e).__name__})", 503) from None

    def get_nonce(self, doc_id: str) -> Optional[Dict[str, Any]]:
        return self._get(self.guard_db, ri.NONCE_COLLECTION, doc_id)

    def create_nonce(self, doc_id: str, record: Dict[str, Any]) -> None:
        try:
            self.guard_db.collection(ri.NONCE_COLLECTION).document(doc_id).create(record)
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"nonce record not written ({type(e).__name__})", 503) from None

    def _run_in_transaction(self, body: Callable[[Any], None]) -> None:
        from google.cloud import firestore as gcf
        txn = self.guard_db.transaction()
        gcf.transactional(body)(txn)

    def swap_nonce(self, doc_id: str, expected: Dict[str, Any], new: Dict[str, Any]) -> bool:
        """Compare-and-set in a transaction: writes `new` only when the stored record still equals `expected`.
        False on a lost race; RunnerIdentityError(503) when the store fails."""
        ref = self.guard_db.collection(ri.NONCE_COLLECTION).document(doc_id)
        outcome = {"ok": False}

        def _body(txn):
            snap = ref.get(transaction=txn)
            current = snap.to_dict() if getattr(snap, "exists", False) is True else None
            if current != expected:
                outcome["ok"] = False
                return
            txn.update(ref, new)
            outcome["ok"] = True

        try:
            self._run_in_transaction(_body)
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"nonce update failed ({type(e).__name__})", 503) from None
        return outcome["ok"]


# ------------------------------------------------------------------------------------------------ provisioner
class _StepFailed(Exception):
    def __init__(self, error_class: str, detail: str):
        super().__init__(f"{error_class}: {detail}")
        self.error_class, self.detail = error_class, detail


@dataclass
class RunnerDeps:
    """Everything the provisioner and broker touch (injected in tests)."""
    config: BrokerConfig
    rest: Any
    project_iam: Any                    # dg.RestCRM-compatible get_iam_policy / set_iam_policy (project IAM, v3)
    store: RunnerStore
    certs: Callable[..., Mapping[str, str]]
    runtime_email: Callable[[], Optional[str]]
    region: Callable[[], Optional[str]]
    guard_context: Callable[[], Any]
    signer_factory: Callable[[str], Callable[[bytes], Tuple[str, str]]]
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc))
    sleep: Callable[[float], None] = field(default=time.sleep)
    github_repo_token: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None
    # FD-7L-F4: the operative mode, read live (vending passes ri.runner_identity_mode with its guard database). None
    # (unit tests that build the deps by hand) = the declaration in `config.mode`.
    mode: Optional[Callable[[], str]] = None

    def operative_mode(self) -> str:
        return self.mode() if self.mode is not None else self.config.mode


class RunnerIdentityProvisioner:
    def __init__(self, deps: RunnerDeps):
        self.d = deps

    # -- records --------------------------------------------------------------------------------------------
    def broker(self) -> str:
        return self.d.config.broker_email(self.d.runtime_email())

    def _sign_and_write(self, product_id: str, record: Dict[str, Any], broker: str) -> Dict[str, Any]:
        signed = ri.sign_record(ri.provenance_doc_path(product_id), record, signer_email=broker,
                                signed_at=_now_iso(self.d.clock), sign_blob=self.d.signer_factory(broker))
        self.d.store.write_runner_identity(product_id, signed)
        return signed

    def verified_existing(self, product_id: str, prov: Dict[str, Any], broker: str) -> Optional[Dict[str, Any]]:
        """The provenance's runner_identity when present (verified), None when absent. An unverifiable record is
        refused, never silently replaced (it may name a suffixed bucket that holds state)."""
        raw = prov.get(ri.RUNNER_IDENTITY_FIELD)
        if raw is None:
            return None
        return ri.verify_record(ri.provenance_doc_path(product_id), raw, expected_signer=broker, certs=self.d.certs)

    def provenance_for(self, product_id: str, project_id: str, project_number: str) -> Dict[str, Any]:
        prov = self.d.store.get_provenance(product_id)
        if prov is None:
            raise _err("VENDING.RUNNER_IDENTITY_NO_PROVENANCE",
                       f"{ri.PROVENANCE_COLLECTION}/{product_id} does not exist (run the provenance backfill first)")
        if prov.get("created_by") not in dg.PROVENANCE_CREATORS or prov.get("project_id") != project_id \
                or dg._num(prov.get("project_number")) != str(project_number):
            raise _err("VENDING.RUNNER_IDENTITY_NO_PROVENANCE",
                       f"provenance of {product_id} does not name project {project_id} / {project_number}")
        return prov

    # -- the vend-order steps -------------------------------------------------------------------------------
    def ensure(self, *, product_id: str, project_id: str, project_number: str, region: Optional[str],
               verify_only: bool = False, claimed_bucket: Optional[str] = None) -> Dict[str, Any]:
        """Runs steps 0-5 and returns the signed READY record. Raises RunnerIdentityError with a VENDING.* class
        (after recording a signed FAILED record when possible). verify_only (backfill-result) creates nothing in
        the child and only checks what a backfill execution reports."""
        number = dg._num(project_number)
        if not number or not ri.is_project_id(project_id):
            raise _err("VENDING.DEPLOYER_SA_FAILED", f"project {project_id!r} / number {project_number!r} unresolved")
        try:
            broker = self.broker()
        except RunnerIdentityError as e:
            raise _err("VENDING.RUNNER_BROKER_SHARED_IDENTITY", e.detail, 503) from None
        prov = self.provenance_for(product_id, project_id, number)
        existing = self.verified_existing(product_id, prov, broker)
        if existing is not None:
            if existing.get("project_id") != project_id or existing.get("project_number") != number \
                    or existing.get("product_id") != product_id:
                raise _err("RUNNER_TARGET_MISMATCH", f"{product_id}: recorded runner identity names another project")
        if existing is not None and existing.get("status") == ri.STATUS_MIGRATING:
            # RT F5: a re-vend / retry / backfill result during a state migration must not re-sign the record as READY,
            # drop the migration cursor or lift the migration block.
            raise _err("RUNNER_IDENTITY_MIGRATING", f"{product_id}: its state is being migrated; retry when it is READY")
        recorded_bucket = existing.get("state_bucket") if existing else None
        repository = existing.get("repository") if existing else None
        migration = existing.get("migration") if existing else None
        if claimed_bucket is not None:
            if recorded_bucket and claimed_bucket != recorded_bucket:
                raise _err("VENDING.STATE_BUCKET_FAILED", f"{product_id}: reported bucket differs from the record")
            recorded_bucket = claimed_bucket
        if recorded_bucket is not None and not ri.is_state_bucket_name_for(project_id, recorded_bucket):
            raise _err("VENDING.STATE_BUCKET_FAILED", f"{product_id}: {recorded_bucket!r} is not this project's bucket")
        deployer = ri.deployer_email(project_id)
        try:
            self.ensure_apis(number)
            self.ensure_sa(project_id, deployer, create=not verify_only)
            self.ensure_owner(project_id, deployer, add=not verify_only)
            self.ensure_broker_grant(project_id, deployer, broker, add=not verify_only)
            bucket = self.ensure_bucket(product_id, project_id, number, region, recorded_bucket, deployer, broker,
                                        create=not verify_only,
                                        check_members=existing is None or not existing.get("state_bucket")
                                        or verify_only)
        except _StepFailed as step:
            logger.error(f"{step.error_class} for {product_id} ({project_id}): {step.detail}")
            if existing is not None and existing.get("status") == ri.STATUS_READY:
                # A failed re-check never downgrades a READY record (a transient API error on a re-vend must not take
                # a working workload offline); the broker re-checks the project and the grant at every mint.
                raise _err(step.error_class, step.detail, 502) from None
            failed = ri.new_runner_identity_record(
                product_id=product_id, project_id=project_id, project_number=number, state_bucket=recorded_bucket,
                status=ri.STATUS_FAILED, updated_at=_now_iso(self.d.clock), repository=repository,
                error_class=step.error_class)
            failed["migration"] = migration
            try:
                self._sign_and_write(product_id, failed, broker)
            except RunnerIdentityError as rec_err:
                logger.error(f"FAILED runner identity of {product_id} not recorded: {rec_err.code}")
            raise _err(step.error_class, step.detail, 502) from None
        record = ri.new_runner_identity_record(
            product_id=product_id, project_id=project_id, project_number=number, state_bucket=bucket,
            status=ri.STATUS_READY, updated_at=_now_iso(self.d.clock), repository=repository)
        record["migration"] = migration
        signed = self._sign_and_write(product_id, record, broker)
        logger.info(f"Runner identity READY for {product_id}: {deployer}, gs://{bucket}")
        return signed

    def ensure_apis(self, number: str) -> None:
        names = [f"projects/{number}/services/{a}" for a in REQUIRED_CHILD_APIS]
        missing: List[str] = list(REQUIRED_CHILD_APIS)
        status = 0
        for attempt in range(1, API_CHECK_ATTEMPTS + 1):
            status, body = self.d.rest.call("get", f"{_SERVICEUSAGE}projects/{number}/services:batchGet",
                                            params={"names": names})
            if status == 200:
                enabled = {str(s.get("name", "")).rsplit("/", 1)[-1] for s in (body.get("services") or [])
                           if isinstance(s, dict) and s.get("state") == "ENABLED"}
                missing = [a for a in REQUIRED_CHILD_APIS if a not in enabled]
                if not missing:
                    return
            if attempt < API_CHECK_ATTEMPTS:
                self.d.sleep(RETRY_DELAY_S)
        raise _StepFailed("VENDING.RUNNER_IDENTITY_APIS_MISSING",
                          f"projects/{number}: not enabled: {', '.join(missing)} (last HTTP {status})")

    def _sa_url(self, project_id: str, email: str) -> str:
        return f"{_IAM}projects/{project_id}/serviceAccounts/{email}"

    def _check_sa(self, body: Dict[str, Any], project_id: str, email: str) -> None:
        if str(body.get("email", "")).lower() != email or body.get("projectId") != project_id:
            raise _StepFailed("VENDING.DEPLOYER_SA_FAILED", f"{email}: the account found is not the deployer")
        if body.get("disabled") is True:
            raise _StepFailed("VENDING.DEPLOYER_SA_FAILED", f"{email} is disabled (enable it by hand, then re-vend)")

    def ensure_sa(self, project_id: str, email: str, *, create: bool = True) -> None:
        last = 0
        for attempt in range(1, IAM_WRITE_ATTEMPTS + 1):
            if create:
                status, body = self.d.rest.call("post", f"{_IAM}projects/{project_id}/serviceAccounts", json={
                    "accountId": ri.DEPLOYER_ACCOUNT_ID,
                    "serviceAccount": {"displayName": "StackVend deployer",
                                       "description": "StackVend runs this workload's OpenTofu as this account "
                                                      "(FD-7L). Managed by StackVend vending."}})
                if status == 200:
                    self._check_sa(body, project_id, email)
                    return
                if status != 409 and status not in TRANSIENT_STATUSES:
                    raise _StepFailed("VENDING.DEPLOYER_SA_FAILED", f"create {email}: HTTP {status}")
            status, body = self.d.rest.call("get", self._sa_url(project_id, email))
            if status == 200:
                self._check_sa(body, project_id, email)
                return
            last = status
            if not create and status == 404:
                raise _StepFailed("VENDING.DEPLOYER_SA_FAILED", f"{email} does not exist")
            if status not in IAM_RETRY_STATUSES or attempt == IAM_WRITE_ATTEMPTS:
                break
            self.d.sleep(RETRY_DELAY_S)
        raise _StepFailed("VENDING.DEPLOYER_SA_FAILED", f"{email}: HTTP {last}")

    @staticmethod
    def _add_member(policy: Dict[str, Any], role: str, member: str) -> Tuple[Dict[str, Any], bool]:
        """Add-only: a copy of `policy` with `member` in the UNCONDITIONAL `role` binding. Every other binding,
        member, condition, the version and the etag are kept as read. Returns (policy, changed)."""
        out = dict(policy)
        bindings = [dict(b) for b in (policy.get("bindings") or []) if isinstance(b, dict)]
        target = next((b for b in bindings if b.get("role") == role and not b.get("condition")), None)
        if target is None:
            target = {"role": role, "members": []}
            bindings.append(target)
        members = list(target.get("members") or [])
        if member in members:
            return policy, False
        target["members"] = members + [member]
        out["bindings"] = bindings
        return out, True

    @staticmethod
    def _has_member(policy: Any, role: str, member: str) -> bool:
        return isinstance(policy, dict) and any(
            isinstance(b, dict) and b.get("role") == role and not b.get("condition")
            and member in (b.get("members") or []) for b in (policy.get("bindings") or []))

    def _add_only(self, what: str, error_class: str, get: Callable[[], Tuple[int, Any]],
                  put: Callable[[Dict[str, Any]], Tuple[int, Any]], grants: List[Tuple[str, str]], add: bool,
                  check: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        last = 0
        for attempt in range(1, IAM_WRITE_ATTEMPTS + 1):
            status, policy = get()
            if status == 200 and isinstance(policy, dict):
                if check is not None:
                    check(policy)
                new, changed = policy, False
                for role, member in grants:
                    new, ch = self._add_member(new, role, member)
                    changed = changed or ch
                if not changed:
                    return
                if not add:
                    missing = [f"{r} {m}" for r, m in grants if not self._has_member(policy, r, m)]
                    raise _StepFailed(error_class, f"{what}: missing {', '.join(missing)}")
                status, result = put(new)
                if status == 200 and all(self._has_member(result, r, m) for r, m in grants):
                    return
                if status == 200:
                    raise _StepFailed(error_class, f"{what}: the returned policy lacks the grant")
            last = status
            if status not in IAM_RETRY_STATUSES or attempt == IAM_WRITE_ATTEMPTS:
                break
            self.d.sleep(RETRY_DELAY_S)
        raise _StepFailed(error_class, f"{what}: HTTP {last}")

    def ensure_owner(self, project_id: str, deployer: str, *, add: bool = True) -> None:
        iam = self.d.project_iam

        def _get():
            try:
                return 200, iam.get_iam_policy(project_id)
            except dg.CRMUnavailable as e:
                return e.status or 0, None

        def _put(policy):
            try:
                return 200, iam.set_iam_policy(project_id, policy)
            except dg.CRMUnavailable as e:
                return e.status or 0, None

        self._add_only(f"roles/owner on {project_id}", "VENDING.DEPLOYER_OWNER_GRANT_FAILED", _get, _put,
                       [(OWNER_ROLE, f"serviceAccount:{deployer}")], add)

    def ensure_broker_grant(self, project_id: str, deployer: str, broker: str, *, add: bool = True) -> None:
        url = self._sa_url(project_id, deployer)
        broker_member = f"serviceAccount:{broker}"

        def _check(policy):
            others = sorted({m for b in (policy.get("bindings") or []) if isinstance(b, dict)
                             and b.get("role") == TOKEN_CREATOR_ROLE for m in (b.get("members") or [])
                             if m != broker_member})
            if others:
                raise _StepFailed("VENDING.DEPLOYER_UNEXPECTED_TOKEN_CREATOR",
                                  f"{deployer}: token creator also granted to {', '.join(others)}; only the broker "
                                  "may mint its tokens (remove them by hand, then re-vend)")

        self._add_only(f"token creator on {deployer}", "VENDING.BROKER_GRANT_FAILED",
                       lambda: self.d.rest.call("post", f"{url}:getIamPolicy",
                                                json={"options": {"requestedPolicyVersion": 3}}),
                       lambda p: self.d.rest.call("post", f"{url}:setIamPolicy", json={"policy": p}),
                       [(TOKEN_CREATOR_ROLE, broker_member)], add, check=_check)

    def _bucket_ok(self, body: Dict[str, Any], number: str) -> bool:
        return str(body.get("projectNumber", "")) == number

    def _check_bucket_config(self, name: str, body: Dict[str, Any]) -> None:
        iam_cfg = body.get("iamConfiguration") if isinstance(body.get("iamConfiguration"), dict) else {}
        ubla = iam_cfg.get("uniformBucketLevelAccess") if isinstance(iam_cfg.get("uniformBucketLevelAccess"), dict) else {}
        versioning = body.get("versioning") if isinstance(body.get("versioning"), dict) else {}
        if ubla.get("enabled") is not True or iam_cfg.get("publicAccessPrevention") != "enforced" \
                or versioning.get("enabled") is not True:
            raise _StepFailed("VENDING.STATE_BUCKET_FAILED", f"gs://{name} exists without uniform access, public "
                              "access prevention or versioning (fix the bucket by hand, then re-vend)")

    def ensure_bucket(self, product_id: str, project_id: str, number: str, region: Optional[str],
                      recorded: Optional[str], deployer: str, broker: str, *, create: bool = True,
                      check_members: bool = True, before_iam: Optional[Callable[[str], None]] = None) -> str:
        """`before_iam` (SAT-45, the runner identity backfill only): called with the chosen bucket name after the bucket
        is found or created and before its IAM is read or changed; it refuses by raising (vend_all passes None)."""
        if recorded is None and (not isinstance(region, str) or not region or set(region) - set(
                "abcdefghijklmnopqrstuvwxyz0123456789-")):
            raise _StepFailed("VENDING.STATE_BUCKET_FAILED", f"{product_id}: the workload region is unknown")
        candidates = [recorded] if recorded else [ri.state_bucket_name(project_id),
                                                  ri.state_bucket_name(project_id, ri.random_bucket_suffix())]
        chosen = None
        for name in candidates:
            chosen = self._ensure_one_bucket(product_id, name, number, region, create=create)
            if chosen:
                break
        if not chosen:
            raise _StepFailed("VENDING.STATE_BUCKET_NAME_TAKEN",
                              f"{product_id}: {', '.join(candidates)} belong to other projects")
        if before_iam is not None:
            before_iam(chosen)
        readers = [f"serviceAccount:{broker}", f"serviceAccount:{self.d.config.control_center_email()}"]
        grants = [(OBJECT_ADMIN_ROLE, f"serviceAccount:{deployer}")] + [(OBJECT_VIEWER_ROLE, m) for m in readers]
        url = f"{_STORAGE}b/{chosen}/iam"
        expected = {m for _, m in grants} | {f"{kind}:{ident}" for kind in ("projectOwner", "projectEditor",
                                                                          "projectViewer")
                                             for ident in (project_id, number)}

        def _check_members(policy):
            # RT F4: a bucket that is new to the record (first adoption or a backfill result) must hold only the
            # expected members; a foreign reader or writer is refused, never removed (refuse, never change).
            found = sorted({m for b in (policy.get("bindings") or []) if isinstance(b, dict)
                            for m in (b.get("members") or []) if m not in expected})
            if found:
                raise _StepFailed("VENDING.STATE_BUCKET_UNEXPECTED_MEMBERS",
                                  f"gs://{chosen} also grants {', '.join(found)} (remove them by hand, then re-vend)")

        self._add_only(f"IAM of gs://{chosen}", "VENDING.STATE_BUCKET_FAILED",
                       lambda: self.d.rest.call("get", url, params={"optionsRequestedPolicyVersion": 3}),
                       lambda p: self.d.rest.call("put", url, json=p), grants, create,
                       check=_check_members if check_members else None)
        return chosen

    def _ensure_one_bucket(self, product_id: str, name: str, number: str, region: Optional[str], *,
                           create: bool) -> Optional[str]:
        """The bucket name when it is (now) this project's bucket; None when the global name is someone else's."""
        for attempt in range(1, IAM_WRITE_ATTEMPTS + 1):
            status, body = self.d.rest.call("get", f"{_STORAGE}b/{name}")
            if status == 200:
                if not self._bucket_ok(body, number):
                    return None
                self._check_bucket_config(name, body)
                return name
            if status == 403:
                return None   # the name exists in a project vending cannot read: someone else's
            if status == 404:
                if not create:
                    raise _StepFailed("VENDING.STATE_BUCKET_FAILED", f"gs://{name} does not exist")
                labels = {dg.LABEL_MANAGED: "true", "stackvend-purpose": "tfstate"}
                if set(product_id) <= set("abcdefghijklmnopqrstuvwxyz0123456789_-") and len(product_id) <= 63:
                    labels[dg.LABEL_PRODUCT] = product_id
                status, body = self.d.rest.call("post", f"{_STORAGE}b", params={"project": number}, json={
                    "name": name, "location": region, "storageClass": "STANDARD", "labels": labels,
                    "versioning": {"enabled": True},
                    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
                                         "publicAccessPrevention": "enforced"}})
                if status == 200:
                    if not self._bucket_ok(body, number):
                        raise _StepFailed("VENDING.STATE_BUCKET_FAILED", f"gs://{name} created in another project")
                    self._check_bucket_config(name, body)
                    return name
                if status == 409:
                    continue   # created concurrently (by us or by someone else): read it again
            if status not in TRANSIENT_STATUSES or attempt == IAM_WRITE_ATTEMPTS:
                raise _StepFailed("VENDING.STATE_BUCKET_FAILED", f"gs://{name}: HTTP {status}")
            self.d.sleep(RETRY_DELAY_S)
        raise _StepFailed("VENDING.STATE_BUCKET_FAILED", f"gs://{name}: no stable answer")

    # -- repository pin (vend_all) -------------------------------------------------------------------------
    def pin_repository(self, product_id: str, repository: Dict[str, Any]) -> Dict[str, Any]:
        broker = self.broker()
        prov = self.d.store.get_provenance(product_id) or {}
        existing = self.verified_existing(product_id, prov, broker)
        if existing is None:
            raise _err("VENDING.RUNNER_REPOSITORY_PIN_FAILED", f"{product_id}: no runner identity record")
        ri.check_runner_identity(existing, product_id=product_id, project_id=prov.get("project_id"))
        current = existing.get("repository")
        if current == repository:
            return existing
        if current is not None:
            raise _err("VENDING.RUNNER_REPOSITORY_MISMATCH",
                       f"{product_id}: runner identity pins {current.get('full_name')!r}; refusing to re-pin "
                       f"{repository.get('full_name')!r} (operator action)")
        record = {k: v for k, v in existing.items() if k not in ("signed_by", "signed_at")}
        record["repository"] = repository
        record["updated_at"] = _now_iso(self.d.clock)
        return self._sign_and_write(product_id, record, broker)


# ------------------------------------------------------------------------------------------------ broker
NONCE_PUBLIC_FIELDS = ("product_id", "project_id", "project_number", "deployer_email", "state_bucket", "state_prefix",
                       "repository", "trace_id", "branch", "mode", "callback_url", "payload_ref", "payload_sha256",
                       "saved_plan_sha256", "execution", "backfill_product_ids")


def _is_sha256(v: Any) -> bool:
    return isinstance(v, str) and len(v) == 64 and set(v) <= set("0123456789abcdef")


def _is_trace_id(v: Any) -> bool:
    return isinstance(v, str) and 0 < len(v) <= 128 and set(v) <= set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def _check_callback_url(url: Any) -> Optional[str]:
    """Only a Workflows callback endpoint: https, host exactly workflowexecutions.googleapis.com, no user info or
    port (the job posts its own OAuth token there). Structural parse, exact host equality."""
    if url is None:
        return None
    parts = urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme != "https" or parts.hostname != WORKFLOW_CALLBACK_HOST \
            or parts.username is not None or parts.password is not None or parts.port is not None \
            or parts.netloc != WORKFLOW_CALLBACK_HOST:
        raise _err("RUNNER_DISPATCH_INVALID", "callback_url is not a Workflows callback endpoint", 422)
    return url


class RunnerBroker:
    def __init__(self, deps: RunnerDeps):
        self.d = deps
        self.provisioner = RunnerIdentityProvisioner(deps)

    # -- shared checks ------------------------------------------------------------------------------------
    def require_per_workload(self) -> None:
        if self.d.operative_mode() != ri.MODE_PER_WORKLOAD:
            raise _err("RUNNER_IDENTITY_MODE_PLATFORM",
                       f"this install runs Terraform as the platform account (the runner identity mode is not "
                       f"{ri.MODE_PER_WORKLOAD}); the runner broker is off")

    def _broker(self) -> str:
        return self.d.config.broker_email(self.d.runtime_email())

    def verified_identity(self, product_id: str, broker: str) -> Dict[str, Any]:
        """The signed, READY runner identity of `product_id`, re-derived and checked against the ledger, CRM, the
        direct managed tag and the ancestry (lane 18 identity checks) before every mint."""
        if not isinstance(product_id, str) or not product_id:
            raise _err("RUNNER_DISPATCH_INVALID", "product_id is required", 422)
        prov = self.d.store.get_provenance(product_id)
        if prov is None or prov.get(ri.RUNNER_IDENTITY_FIELD) is None:
            raise _err("RUNNER_IDENTITY_NOT_READY", f"{product_id} has no runner identity record")
        rec = ri.verify_record(ri.provenance_doc_path(product_id), prov[ri.RUNNER_IDENTITY_FIELD],
                               expected_signer=broker, certs=self.d.certs)
        rec = ri.check_runner_identity(rec, product_id=product_id, project_id=prov.get("project_id"),
                                       project_number=dg._num(prov.get("project_number")) or None)
        try:
            ident = dg.verify_identity(product_id, ctx=self.d.guard_context())
        except dg.DeletionRefused as e:
            raise _err("RUNNER_TARGET_UNVERIFIED", f"{product_id}: {e.code}: {e.detail}",
                       503 if e.http_status == 503 else 409) from None
        if ident.project_id != rec["project_id"] or ident.project_number != rec["project_number"]:
            raise _err("RUNNER_TARGET_MISMATCH", f"{product_id}: the ledger / project does not match the record")
        return self.resign_if_stale(product_id, rec, broker)

    def resign_if_stale(self, product_id: str, rec: Dict[str, Any], broker: str) -> Dict[str, Any]:
        """RT F1: re-sign a VERIFIED record whose signature is older than RESIGN_AFTER_SECONDS with the broker's current
        key, before Google stops publishing the old one. The content is unchanged; a younger record is not written."""
        signed_at = dg._parse_ts(rec.get("signed_at"))
        if signed_at is not None and self.d.clock() - signed_at < timedelta(seconds=RESIGN_AFTER_SECONDS):
            return rec
        body = {k: v for k, v in rec.items() if k not in ("signed_by", "signed_at", "signature")}
        fresh = self.provisioner._sign_and_write(product_id, body, broker)
        logger.info(f"runner identity of {product_id} re-signed (previous signature from {rec.get('signed_at')})")
        return {k: v for k, v in fresh.items() if k != "signature"}

    def resign_sweep(self, caller: str, product_ids: Optional[List[str]], max_items: int) -> Dict[str, Any]:
        """POST /runner-identity/resign (Control Center): re-sign every verifiable runner identity record older than
        RESIGN_AFTER_SECONDS, so an idle workload is not refused after a key rotation. A record whose key is already
        retired (RUNNER_RECORD_KEY_RETIRED) or that does not verify is reported, never re-signed."""
        self.require_per_workload()
        broker = self._broker()
        wanted = set(product_ids) if product_ids else None
        rows = []
        for pid, prov in self.d.store.list_provenance():
            if (wanted is not None and pid not in wanted) or prov.get(ri.RUNNER_IDENTITY_FIELD) is None:
                continue
            if len(rows) >= max_items:
                break
            try:
                rec = ri.verify_record(ri.provenance_doc_path(pid), prov[ri.RUNNER_IDENTITY_FIELD],
                                       expected_signer=broker, certs=self.d.certs)
                if rec.get("product_id") != pid:
                    raise _err("RUNNER_TARGET_MISMATCH", f"{pid}: record names another product")
                after = self.resign_if_stale(pid, rec, broker)
                rows.append({"product_id": pid, "status": "RESIGNED" if after is not rec else "FRESH",
                             "error_class": None})
            except RunnerIdentityError as e:
                rows.append({"product_id": pid, "status": "FAILED", "error_class": e.code})
        logger.info(f"runner identity re-sign sweep by {caller}: {[(r['product_id'], r['status']) for r in rows]}")
        return {"results": rows, "ok": all(r["status"] != "FAILED" for r in rows)}

    def _region(self) -> str:
        region = self.d.region()
        if not region:
            raise _err("RUNNER_IDENTITY_UNRESOLVED", "vending's region is unknown", 503)
        return region

    def _execution_prefix(self) -> str:
        return f"projects/{self.d.config.host_project_id}/locations/{self._region()}/jobs/{self.d.config.job_name}/" \
               "executions/"

    def _check_execution_name(self, name: Any) -> str:
        prefix = self._execution_prefix()
        if not isinstance(name, str) or name[:len(prefix)] != prefix or not name[len(prefix):] \
                or "/" in name[len(prefix):]:
            raise _err("RUNNER_EXECUTION_MISMATCH", "not an execution of the tf-applier job", 403)
        return name

    def _running_execution(self, name: str, broker: str, code_ended: str, *, not_yet_retryable: bool = False) -> None:
        """The execution is ours (name, creator = broker) and running (`_execution_state`: runningCount >= 1 and no
        structured field shows it ended), else a typed refusal; nothing is issued or consumed before this passes.
        SAT-52: with `not_yet_retryable` (redeem only), EXECUTION_NOT_YET_RUNNING is RUNNER_EXECUTION_NOT_YET_RUNNING
        (409, retryable); every other not-running read is `code_ended` (403)."""
        status, exe = self.d.rest.call("get", f"{_RUN}{name}")
        if status != 200:
            raise _err("RUNNER_EXECUTION_UNVERIFIED", f"execution read answered HTTP {status}", 503)
        if exe.get("name") != name:
            raise _err("RUNNER_EXECUTION_MISMATCH", "execution name differs", 403)
        creator = exe.get("creator") if "creator" in exe else self._v1_creator(name)
        if str(creator or "").lower() != broker:
            raise _err("RUNNER_EXECUTION_NOT_BROKERED", "the execution was not started by the broker", 403)
        state = _execution_state(exe)
        if state == EXECUTION_RUNNING:
            return
        if state == EXECUTION_NOT_YET_RUNNING and not_yet_retryable:
            raise _err(RUNNER_EXECUTION_NOT_YET_RUNNING, "the execution has not started running yet; retry shortly",
                       NOT_YET_RUNNING_STATUS)
        raise _err(code_ended, "the execution is not running", 403)

    def _v1_creator(self, name: str) -> Optional[str]:
        """RT F2: when the v2 Execution carries no `creator`, the system-set v1 annotation run.googleapis.com/creator
        of the same execution (namespace = host project). Any failure -> RUNNER_EXECUTION_UNVERIFIED (fail closed)."""
        execution_id = name.rsplit("/", 1)[-1]
        url = (f"https://{self._region()}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/"
               f"{self.d.config.host_project_id}/executions/{execution_id}")
        status, body = self.d.rest.call("get", url)
        meta = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
        annotations = meta.get("annotations") if isinstance(meta.get("annotations"), dict) else {}
        if status != 200 or meta.get("name") != execution_id:
            raise _err("RUNNER_EXECUTION_UNVERIFIED", f"v1 execution read answered HTTP {status}", 503)
        return annotations.get(RUN_V1_CREATOR_ANNOTATION)

    def _nonce_record(self, doc_id: str, broker: str, missing_code: str, missing_status: int) -> Tuple[Dict, Dict]:
        doc = self.d.store.get_nonce(doc_id)
        if doc is None:
            raise _err(missing_code, "unknown", missing_status)
        rec = ri.verify_record(ri.nonce_doc_path(doc_id), doc, expected_signer=broker, certs=self.d.certs)
        if rec.get("schema") != ri.NONCE_SCHEMA:
            raise _err("RUNNER_RECORD_UNSIGNED", f"{ri.nonce_doc_path(doc_id)}: schema")
        return doc, rec

    def _sign_nonce(self, doc_id: str, record: Dict[str, Any], broker: str) -> Dict[str, Any]:
        body = {k: v for k, v in record.items() if k not in ("signed_by", "signed_at", "signature")}
        return ri.sign_record(ri.nonce_doc_path(doc_id), body, signer_email=broker, signed_at=_now_iso(self.d.clock),
                              sign_blob=self.d.signer_factory(broker))

    @staticmethod
    def _same_target(rec: Dict[str, Any], ident: Dict[str, Any]) -> None:
        for k in ("product_id", "project_id", "project_number", "deployer_email", "state_bucket"):
            if rec.get(k) != ident.get(k):
                raise _err("RUNNER_TARGET_MISMATCH", f"{rec.get('product_id')}: {k} changed since dispatch")

    # -- routes ---------------------------------------------------------------------------------------------
    def dispatch(self, caller: str, req: Dict[str, Any]) -> Dict[str, Any]:
        self.require_per_workload()
        broker = self._broker()
        product_id = req.get("product_id")
        mode = req.get("mode")
        if mode not in ri.DISPATCH_MODES:
            raise _err("RUNNER_DISPATCH_INVALID", f"mode must be one of {', '.join(ri.DISPATCH_MODES)}", 422)
        trace_id = req.get("trace_id")
        if not _is_trace_id(trace_id):
            raise _err("RUNNER_DISPATCH_INVALID", "trace_id is required ([A-Za-z0-9._-], at most 128)", 422)
        branch = req.get("branch")
        try:
            from shared.settings import is_branch_name
        except ImportError:  # pragma: no cover
            is_branch_name = None
        if branch is None or is_branch_name is None or not is_branch_name(branch):
            raise _err("RUNNER_DISPATCH_INVALID", "branch is not a plain branch name", 422)
        callback_url = _check_callback_url(req.get("callback_url"))
        payload_ref, payload_sha = req.get("payload_ref"), req.get("payload_sha256")
        if payload_ref is not None or payload_sha is not None:
            if not self.d.config.staging_bucket:
                raise _err("RUNNER_PAYLOAD_UNCONFIGURED", f"{STAGING_BUCKET_ENV} is not configured", 503)
            parts = urlsplit(payload_ref) if isinstance(payload_ref, str) else None
            if parts is None or parts.scheme != "gs" or parts.netloc != self.d.config.staging_bucket \
                    or not parts.path.strip("/") or parts.query or parts.fragment or not _is_sha256(payload_sha):
                raise _err("RUNNER_DISPATCH_INVALID", "payload_ref must be gs://<staging bucket>/<object> with a "
                           "sha256", 422)
        saved_plan = req.get("saved_plan_sha256")
        if saved_plan is not None and (mode != "apply" or not _is_sha256(saved_plan)):
            raise _err("RUNNER_DISPATCH_INVALID", "saved_plan_sha256 is a sha256 and only for mode apply", 422)

        ident = self.verified_identity(product_id, broker)
        region = self._region()
        job_url = f"{_RUN}projects/{self.d.config.host_project_id}/locations/{region}/jobs/{self.d.config.job_name}"
        status, job = self.d.rest.call("get", job_url)
        job_sa = (((job.get("template") or {}).get("template") or {}).get("serviceAccount") or "").lower() \
            if status == 200 else ""
        if not job_sa or job_sa not in self.d.config.runner_members:
            raise _err("RUNNER_IDENTITY_UNRESOLVED", f"the {self.d.config.job_name} job's identity is not a listed "
                       f"runner member (HTTP {status})", 503)

        nonce = ri.new_nonce()
        doc_id = ri.nonce_doc_id(nonce)
        record = {
            "schema": ri.NONCE_SCHEMA, "product_id": ident["product_id"], "project_id": ident["project_id"],
            "project_number": ident["project_number"], "deployer_email": ident["deployer_email"],
            "state_bucket": ident["state_bucket"], "state_prefix": ident["state_prefix"],
            "repository": ident.get("repository"), "trace_id": trace_id, "branch": branch, "mode": mode,
            "callback_url": callback_url, "payload_ref": payload_ref, "payload_sha256": payload_sha,
            "saved_plan_sha256": saved_plan, "backfill_product_ids": None, "dispatched_by": caller,
            "created_at": _now_iso(self.d.clock), "execution": None, "redeemed": False, "redeemed_at": None,
            "redeemed_by": None, "session_key_sha256": None,
        }
        signed = self._sign_nonce(doc_id, record, broker)
        self.d.store.create_nonce(doc_id, signed)
        status, op = self.d.rest.call("post", f"{job_url}:run", json={"overrides": {"containerOverrides": [
            {"env": [{"name": NONCE_ENV_NAME, "value": nonce}]}]}})
        execution = ((op.get("metadata") or {}).get("name")) if status == 200 else None
        try:
            execution = self._check_execution_name(execution)
        except RunnerIdentityError:
            logger.error(f"RUNNER_DISPATCH_FAILED for {product_id} (trace {trace_id}): RunJob answered HTTP {status} "
                         "without an execution name; the dispatch record stays unbound (never redeemable)")
            raise _err("RUNNER_DISPATCH_FAILED", f"RunJob answered HTTP {status} without an execution", 502) from None
        bound = self._sign_nonce(doc_id, dict(signed, execution=execution), broker)
        if not self.d.store.swap_nonce(doc_id, signed, bound):
            raise _err("RUNNER_DISPATCH_FAILED", "the dispatch record changed before the execution was bound", 502)
        logger.info(f"runner dispatch {doc_id[:12]} for {product_id} (trace {trace_id}, mode {mode}) -> {execution}")
        return {"status": "DISPATCHED", "dispatch_id": doc_id, "execution": execution, "product_id": product_id,
                "trace_id": trace_id, "mode": mode}

    def redeem(self, caller: str, nonce: Any, execution: Any) -> Dict[str, Any]:
        self.require_per_workload()
        broker = self._broker()
        doc_id = ri.nonce_doc_id(nonce if isinstance(nonce, str) else "")
        doc, rec = self._nonce_record(doc_id, broker, "RUNNER_NONCE_UNKNOWN", 404)
        if rec.get("redeemed") is not False:
            raise _err("RUNNER_NONCE_SPENT", "this nonce was already redeemed", 409)
        created = dg._parse_ts(rec.get("created_at"))
        if created is None or self.d.clock() - created > timedelta(seconds=ri.REDEEM_WINDOW_SECONDS):
            raise _err("RUNNER_NONCE_EXPIRED", "the redeem window has passed", 410)
        if rec.get("execution") is None:
            raise _err("RUNNER_DISPATCH_NOT_BOUND", "the execution is not bound yet; retry shortly", 409)
        if execution != rec.get("execution"):
            raise _err("RUNNER_EXECUTION_MISMATCH", "the nonce belongs to another execution", 403)
        self._check_execution_name(execution)
        self._running_execution(execution, broker, "RUNNER_EXECUTION_NOT_RUNNING", not_yet_retryable=True)
        if rec.get("mode") != ri.BACKFILL_MODE:
            self._same_target(rec, self.verified_identity(rec["product_id"], broker))
        session_key = ri.new_session_key(doc_id)
        new = self._sign_nonce(doc_id, dict(rec, redeemed=True, redeemed_at=_now_iso(self.d.clock),
                                            redeemed_by=caller, session_key_sha256=ri.secret_hash(session_key)),
                               broker)
        if not self.d.store.swap_nonce(doc_id, doc, new):
            raise _err("RUNNER_NONCE_SPENT", "this nonce was redeemed concurrently", 409)
        logger.info(f"runner redeem {doc_id[:12]} for {rec.get('product_id')} by {caller} ({execution})")
        return {"record": {k: rec.get(k) for k in NONCE_PUBLIC_FIELDS}, "session_key": session_key}

    def _session(self, session_key: Any, broker: str) -> Dict[str, Any]:
        return self._session_doc(session_key, broker)[2]

    def _session_doc(self, session_key: Any, broker: str) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """(record id, stored document, verified record) of a live session: redeemed, the key matches, the bound
        execution is still running."""
        doc_id = ri.session_doc_id(session_key)
        doc, rec = self._nonce_record(doc_id, broker, "RUNNER_SESSION_INVALID", 401)
        if rec.get("redeemed") is not True or not ri.secret_matches(session_key, rec.get("session_key_sha256")):
            raise _err("RUNNER_SESSION_INVALID", "unknown session", 401)
        # SAT-52: never the retryable NOT_YET_RUNNING here; a session exists only after the redeem saw it running
        self._running_execution(self._check_execution_name(rec.get("execution")), broker, "RUNNER_SESSION_ENDED")
        return doc_id, doc, rec

    def _mint(self, deployer: str, *, wait_for_propagation: bool = False, single: bool = False) -> Dict[str, Any]:
        """generateAccessToken for `deployer`. 403 / 404 are retried (for at most IMPERSONATION_PROPAGATION_S) only
        with wait_for_propagation (a grant made less than PROPAGATION_YOUNG_S ago); transient statuses get
        MINT_TRANSIENT_ATTEMPTS; `single` makes exactly one call (the probe). RT F3."""
        if single:
            attempts, retry = 1, frozenset()
        elif wait_for_propagation:
            attempts, retry = int(IMPERSONATION_PROPAGATION_S // RETRY_DELAY_S), MINT_RETRY_STATUSES
        else:
            attempts, retry = MINT_TRANSIENT_ATTEMPTS, TRANSIENT_STATUSES
        status = 0
        for attempt in range(1, attempts + 1):
            status, body = self.d.rest.call(
                "post", f"{_IAMCREDS}projects/-/serviceAccounts/{deployer}:generateAccessToken",
                json={"scope": [CLOUD_PLATFORM_SCOPE], "lifetime": f"{ri.DEPLOYER_TOKEN_LIFETIME_SECONDS}s"})
            if status == 200 and isinstance(body.get("accessToken"), str) and body["accessToken"]:
                return {"access_token": body["accessToken"], "expire_time": body.get("expireTime")}
            if status not in retry or attempt == attempts:
                break
            self.d.sleep(RETRY_DELAY_S)
        raise _err("RUNNER_IMPERSONATION_FAILED", f"generateAccessToken for {deployer} answered HTTP {status}", 503)

    def deployer_token(self, caller: str, session_key: Any) -> Dict[str, Any]:
        self.require_per_workload()
        broker = self._broker()
        rec = self._session(session_key, broker)
        if rec.get("mode") == ri.BACKFILL_MODE:
            raise _err("RUNNER_SESSION_MODE_MISMATCH", "a backfill session gets no deployer token", 403)
        ident = self.verified_identity(rec["product_id"], broker)
        self._same_target(rec, ident)
        updated = dg._parse_ts(ident.get("updated_at"))
        young = updated is not None and self.d.clock() - updated < timedelta(seconds=PROPAGATION_YOUNG_S)
        token = self._mint(ident["deployer_email"], wait_for_propagation=young)
        logger.info(f"deployer token minted for {ident['product_id']} ({rec.get('execution')}) by {caller}")
        return {"access_token": token["access_token"], "expire_time": token["expire_time"], "token_type": "Bearer",
                "deployer_email": ident["deployer_email"], "project_id": ident["project_id"],
                "quota_project_id": ident["project_id"]}

    def repo_token(self, caller: str, session_key: Any) -> Dict[str, Any]:
        self.require_per_workload()
        broker = self._broker()
        rec = self._session(session_key, broker)
        if rec.get("mode") == ri.BACKFILL_MODE:
            raise _err("RUNNER_SESSION_MODE_MISMATCH", "a backfill session gets no repository token", 403)
        ident = self.verified_identity(rec["product_id"], broker)
        self._same_target(rec, ident)
        repo = ident.get("repository")
        if not isinstance(repo, dict) or not repo.get("full_name"):
            raise _err("RUNNER_REPOSITORY_NOT_PINNED", f"{ident['product_id']}: no repository in the record")
        if repo.get("provider") != "GITHUB":
            raise _err("RUNNER_REPO_TOKEN_UNSUPPORTED", f"provider {repo.get('provider')!r} (FD-7L phase 4)")
        if self.d.github_repo_token is None:
            raise _err("RUNNER_REPO_TOKEN_UNAVAILABLE", "no GitHub App configured", 503)
        out = self.d.github_repo_token(repo["full_name"], repo.get("id"))
        logger.info(f"read-only repository token minted for {repo['full_name']} ({rec.get('execution')}) by {caller}")
        return {"token": out["token"], "expires_at": out.get("expires_at"), "repository": repo["full_name"],
                "permissions": {"contents": "read"}}

    def backfill_result(self, caller: str, session_key: Any, results: Any) -> Dict[str, Any]:
        self.require_per_workload()
        broker = self._broker()
        rec = self._session(session_key, broker)
        if rec.get("mode") != ri.BACKFILL_MODE:
            raise _err("RUNNER_SESSION_MODE_MISMATCH", "not a backfill session", 403)
        allowed = set(rec.get("backfill_product_ids") or [])
        out = []
        for item in results if isinstance(results, list) else []:
            pid = item.get("product_id") if isinstance(item, dict) else None
            if pid not in allowed:
                out.append({"product_id": pid, "status": "REFUSED", "error_class": "BACKFILL.NOT_IN_DISPATCH"})
                continue
            prov = self.d.store.get_provenance(pid) or {}
            try:
                self.provenance_check(pid, prov)
                self.provisioner.ensure(product_id=pid, project_id=prov["project_id"],
                                        project_number=dg._num(prov.get("project_number")), region=None,
                                        verify_only=True, claimed_bucket=item.get("state_bucket"))
                out.append({"product_id": pid, "status": ri.STATUS_READY, "error_class": None})
            except RunnerIdentityError as e:
                out.append({"product_id": pid, "status": ri.STATUS_FAILED, "error_class": e.code})
        logger.info(f"backfill results from {caller}: {[(r['product_id'], r['status']) for r in out]}")
        return {"results": out}

    def sign_result(self, caller: str, session_key: Any, result_sha256: Any) -> Dict[str, Any]:
        """POST /runner/result (FD-7L 5b, SAT-37): a synchronous run's execution reports the sha256 of its result
        document's `result_json`; vending signs it into the dispatch record (`result_sha256`), once. The terraform
        server accepts a result document only when its hash is this signed fingerprint, so a default-database writer
        cannot substitute the answer. Only a live session of a synchronous run (no callback URL, not a backfill); the
        same fingerprint again is answered unchanged (the job's bounded retry), a different one is refused."""
        self.require_per_workload()
        broker = self._broker()
        if not _is_sha256(result_sha256):
            raise _err("RUNNER_RESULT_INVALID", "result_sha256 is not a sha256", 422)
        doc_id, doc, rec = self._session_doc(session_key, broker)
        if rec.get("mode") not in ri.DISPATCH_MODES or rec.get("callback_url") is not None:
            raise _err("RUNNER_SESSION_MODE_MISMATCH", "only a synchronous run (no callback URL) reports a result "
                       "fingerprint", 403)
        signed = rec.get("result_sha256")
        if signed is not None:
            if signed != result_sha256:
                raise _err("RUNNER_RESULT_ALREADY_SIGNED", "a different result fingerprint is already signed", 409)
            return {"status": "SIGNED", "dispatch_id": doc_id, "result_sha256": signed}
        new = self._sign_nonce(doc_id, dict(rec, result_sha256=result_sha256,
                                            result_signed_at=_now_iso(self.d.clock)), broker)
        if not self.d.store.swap_nonce(doc_id, doc, new):
            # RT M1 (rt-sat-37): a concurrent call of the job's retry may have signed the SAME fingerprint first
            _doc2, rec2 = self._nonce_record(doc_id, broker, "RUNNER_SESSION_INVALID", 401)
            if rec2.get("result_sha256") == result_sha256:
                return {"status": "SIGNED", "dispatch_id": doc_id, "result_sha256": result_sha256}
            raise _err("RUNNER_RESULT_ALREADY_SIGNED", "the dispatch record changed while the fingerprint was signed",
                       409)
        logger.info(f"runner result {doc_id[:12]} for {rec.get('product_id')} ({rec.get('execution')}) signed by "
                    f"{caller}")
        return {"status": "SIGNED", "dispatch_id": doc_id, "result_sha256": result_sha256}

    def dispatch_status(self, caller: str, dispatch_id: Any) -> Dict[str, Any]:
        """POST /runner/dispatch-status (FD-7L 5b RT L2, SAT-37): for the terraform server that dispatched a
        synchronous run, whether its bound execution has ended and what the SIGNED record says (redeemed, result
        fingerprint signed). Read only; no token, nonce or session key in the answer. SAT-52 RT LOW: `ended` is the
        same reading as the credential routes (`_execution_ended`: every structured field, not completionTime alone),
        so a failed task is reported ended before Cloud Run writes completionTime; `completion_time` stays the raw
        field."""
        self.require_per_workload()
        broker = self._broker()
        if not _is_sha256(dispatch_id):
            raise _err("RUNNER_DISPATCH_INVALID", "dispatch_id is not a dispatch record id", 422)
        _doc, rec = self._nonce_record(dispatch_id, broker, "RUNNER_DISPATCH_UNKNOWN", 404)
        if rec.get("dispatched_by") != caller:
            raise _err("RUNNER_DISPATCH_UNKNOWN", "unknown", 404)
        out: Dict[str, Any] = {"dispatch_id": dispatch_id, "execution": rec.get("execution"),
                               "redeemed": rec.get("redeemed") is True,
                               "result_signed": rec.get("result_sha256") is not None, "ended": None,
                               "completion_time": None, "succeeded_count": None, "failed_count": None,
                               "cancelled_count": None}
        if rec.get("execution") is None:
            return out                              # never bound: no execution to report on
        name = self._check_execution_name(rec.get("execution"))
        status, exe = self.d.rest.call("get", f"{_RUN}{name}")
        if status != 200 or exe.get("name") != name:
            raise _err("RUNNER_EXECUTION_UNVERIFIED", f"execution read answered HTTP {status}", 503)
        out.update(ended=_execution_ended(exe), completion_time=exe.get("completionTime"),
                   succeeded_count=exe.get("succeededCount"), failed_count=exe.get("failedCount"),
                   cancelled_count=exe.get("cancelledCount"))
        return out

    @staticmethod
    def provenance_check(product_id: str, prov: Dict[str, Any]) -> None:
        if prov.get("created_by") not in dg.PROVENANCE_CREATORS or not ri.is_project_id(prov.get("project_id")) \
                or not dg._num(prov.get("project_number")):
            raise _err("BACKFILL.NO_PROVENANCE", f"{product_id}: no usable provenance")

    def probe(self, caller: str, product_ids: Optional[List[str]], max_items: int) -> Dict[str, Any]:
        """Plan section 4 probe: for each READY record, mint its deployer token INSIDE vending and ask the child (and
        the host) which permissions it holds. Tokens never leave vending; the answer is per workload."""
        self.require_per_workload()
        broker = self._broker()
        wanted = set(product_ids) if product_ids else None
        rows = []
        for pid, prov in self.d.store.list_provenance():
            if wanted is not None and pid not in wanted:
                continue
            if prov.get(ri.RUNNER_IDENTITY_FIELD) is None:
                continue
            if len(rows) >= max_items:
                break
            row: Dict[str, Any] = {"product_id": pid, "status": "FAILED", "error_class": None}
            try:
                ident = self.verified_identity(pid, broker)
                token = self._mint(ident["deployer_email"], single=True)["access_token"]
                perms = ["resourcemanager.projects.get", "iam.serviceAccounts.get", "storage.buckets.get"]
                s1, own = self.d.rest.call("post", f"{_CRM_V3}projects/{ident['project_number']}:testIamPermissions",
                                           json={"permissions": perms}, bearer=token)
                s2, host = self.d.rest.call(
                    "post", f"{_CRM_V3}projects/{self.d.config.host_project_id}:testIamPermissions",
                    json={"permissions": ["resourcemanager.projects.get"]}, bearer=token)
                row["own_project_ok"] = s1 == 200 and sorted(own.get("permissions") or []) == sorted(perms)
                row["host_project_denied"] = s2 == 403 or (s2 == 200 and not host.get("permissions"))
                row["status"] = "OK" if row["own_project_ok"] and row["host_project_denied"] else "FAILED"
                if row["status"] != "OK":
                    row["error_class"] = "RUNNER_PROBE_UNEXPECTED_PERMISSIONS"
            except RunnerIdentityError as e:
                row["error_class"] = e.code
            rows.append(row)
        logger.info(f"runner identity probe by {caller}: {[(r['product_id'], r['status']) for r in rows]}")
        return {"results": rows, "ok": all(r["status"] == "OK" for r in rows)}

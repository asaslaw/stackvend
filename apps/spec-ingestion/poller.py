"""
Project Castor: Specification Ingestion Poller
Scans Google Drive 01_Inbox_Requests, transitions docs to 02_In_Progress,
and publishes dispatch events to Cloud Pub/Sub.
Supports explicit folder IDs or zero-config auto-discovery of shared folders.
"""

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.cloud import firestore, pubsub_v1
from pydantic import TypeAdapter, ValidationError

try:
    import intake_outcomes as _io_mod
except ImportError:  # loaded by file path (tests, tools) without this directory on sys.path
    import importlib.util as _ilu
    import sys as _sys
    _io_spec = _ilu.spec_from_file_location(
        "intake_outcomes", os.path.join(os.path.dirname(os.path.abspath(__file__)), "intake_outcomes.py"))
    _io_mod = _ilu.module_from_spec(_io_spec)
    _io_spec.loader.exec_module(_io_mod)
    _io_mod = _sys.modules.setdefault("intake_outcomes", _io_mod)
INBOX_FOLDER_UNAUTHORIZED = _io_mod.INBOX_FOLDER_UNAUTHORIZED
SPEC_MOVE_FAILED = _io_mod.SPEC_MOVE_FAILED
SPEC_PRODUCT_ID_INVALID = _io_mod.SPEC_PRODUCT_ID_INVALID
SPEC_PUBLISH_FAILED = _io_mod.SPEC_PUBLISH_FAILED
SPEC_SUBMITTER_UNAUTHORIZED = _io_mod.SPEC_SUBMITTER_UNAUTHORIZED
SPEC_TARGET_PLATFORM_WORKLOAD = _io_mod.SPEC_TARGET_PLATFORM_WORKLOAD
SPEC_WORKLOAD_NOT_ASSIGNED = _io_mod.SPEC_WORKLOAD_NOT_ASSIGNED
SPEC_WORKLOAD_ALREADY_REQUESTED = _io_mod.SPEC_WORKLOAD_ALREADY_REQUESTED
TARGET_FOLDER_NOT_MANAGED = _io_mod.TARGET_FOLDER_NOT_MANAGED
IntakeList = _io_mod.IntakeList
IntakeRejected = _io_mod.IntakeRejected
IntakePublishError = _io_mod.IntakePublishError
IntakeUnavailableError = _io_mod.IntakeUnavailableError

# RT14-37: the same RFC 1123 product-id allow-list every other entry point uses (replicated file, byte-identical).
from shared.path_safety import UnsafePathError, validate_product_id  # noqa: E402

# RT14-02: the platform's own pseudo-workload ids (the Control Center's authz.PLATFORM_PSEUDO_WORKLOADS; every copy is
# pinned equal by tests/test_rt14_intake_trust.py). A Drive spec never targets the platform.
PLATFORM_PSEUDO_WORKLOADS = frozenset({"project-castor", "castor", "platform"})
ADMIN_ROLE = "ADMIN"

logger = logging.getLogger("spec-ingestion-service")
logging.basicConfig(level=logging.INFO)

SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/documents",
]

try:
    from shared.sandbox_detection import detect_sandbox_intent, compute_sandbox_expiry
except ImportError:
    try:
        from .shared.sandbox_detection import detect_sandbox_intent, compute_sandbox_expiry
    except ImportError:
        try:
            from apps.spec_ingestion.shared.sandbox_detection import detect_sandbox_intent, compute_sandbox_expiry
        except ImportError:
            try:
                from apps.control_center.shared.sandbox_detection import detect_sandbox_intent, compute_sandbox_expiry
            except ImportError:
                def detect_sandbox_intent(text: str):
                    return False, 30
                def compute_sandbox_expiry(ttl_days: int = 30):
                    return None


# FD-4AS (owner 10-20): Control Center roles that may submit a spec through Drive. The source of truth is the
# Control Center's own user registry, Firestore ``authorized_users/{email}`` (apps/control-center/auth.py
# get_user_access_record): an active record whose role can manage workloads. VIEWER is read-only in the Control
# Center, so it cannot start a build through Drive either. A missing role is the legacy APPROVER (exactly as the
# Control Center decodes it; it migrates APPROVER to WORKLOAD_MANAGER at startup); any other value is refused (the
# Control Center maps unknown strings to APPROVER; intake is stricter, fail closed).
SUBMITTER_ROLES = frozenset({"ADMIN", "WORKLOAD_MANAGER", "APPROVER"})
_BOOL = TypeAdapter(bool)


def normalize_folder_id(value: Any) -> Optional[str]:
    """'123' or 'folders/123' -> 'folders/123' (the form managed_folders.folder_id is stored in; same rule as
    apps/control-center/folders.py normalize_folder_name). Anything else -> None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v.startswith("folders/"):
        v = v[len("folders/"):]
    return f"folders/{v}" if v.isascii() and v.isdigit() else None


def _record_is_active(raw: Any) -> bool:
    """``is_active`` decoded exactly like the Control Center (Pydantic bool; the caller passes the default True for
    a missing field; null or invalid -> inactive)."""
    if raw is None:
        return False
    try:
        return _BOOL.validate_python(raw)
    except ValidationError:
        return False


# SAT-51 (owner 11-03 live, project-vending: two concurrent requests both died with "OSError: [Errno 9] Bad file
# descriptor"). The module-global poller (main.py) is shared by every request thread, and a discovery client built with
# credentials= holds ONE httplib2.Http, which is not thread-safe. Per the google-api-python-client thread-safety
# guidance the client stays shared but every request gets its own authorized httplib2 connection.
def _build_thread_safe(service: str, version: str, credentials):
    import google_auth_httplib2
    from googleapiclient.http import HttpRequest, build_http

    def request_builder(_http, *args, **kwargs):
        return HttpRequest(google_auth_httplib2.AuthorizedHttp(credentials, http=build_http()), *args, **kwargs)

    return build(service, version, http=google_auth_httplib2.AuthorizedHttp(credentials, http=build_http()),
                 requestBuilder=request_builder, cache_discovery=False)


class SpecIngestionPoller:
    def __init__(
        self,
        project_id: Optional[str] = None,
        drive_service: Optional[Any] = None,
        publisher_client: Optional[Any] = None,
        firestore_client: Optional[Any] = None,
        docs_service: Optional[Any] = None,
    ):
        self.project_id = project_id or os.getenv("PROJECT_ID", "")
        self.docs_service = docs_service

        # Google Drive Service
        if drive_service:
            self.drive_service = drive_service
        elif os.getenv("TEST_MODE"):
            self.drive_service = None
        else:
            try:
                credentials, _ = google.auth.default(scopes=SCOPES)
                self.drive_service = _build_thread_safe("drive", "v3", credentials)   # SAT-51
            except Exception as e:
                logger.warning(f"Failed to initialize Drive client: {e}")
                self.drive_service = None

        # Pub/Sub Publisher
        if publisher_client:
            self.publisher = publisher_client
        elif os.getenv("TEST_MODE"):
            self.publisher = None
        else:
            try:
                self.publisher = pubsub_v1.PublisherClient()
            except Exception as e:
                logger.warning(f"Failed to initialize Pub/Sub client: {e}")
                self.publisher = None

        # Firestore Database
        if firestore_client:
            self.db = firestore_client
        elif os.getenv("TEST_MODE"):
            self.db = None
        else:
            try:
                self.db = firestore.Client(project=self.project_id) if self.project_id else None
            except Exception as e:
                logger.warning(f"Failed to initialize Firestore client: {e}")
                self.db = None

        self.topic_path = (
            self.publisher.topic_path(self.project_id, "spec-intake-events")
            if self.publisher and self.project_id
            else None
        )

    def extract_product_id(self, doc_title: str) -> str:
        """Derives a normalized product identifier from a Google Doc title. RT14-37: "" when nothing is left (the
        "default-workload" fallback made unrelated specs collide); the caller validates the result
        (``validate_product_id``) before anything moves."""
        clean = re.sub(r"^(NEW_PRODUCT_SPEC|FEATURE_ENHANCEMENT|INCIDENT_FIX)[:\s\-_]*", "", doc_title, flags=re.IGNORECASE)
        clean = re.sub(r"[\(\)\[\]\{\}\.,!?:;]", "", clean)
        return re.sub(r"[\s_]+", "-", clean).strip("-").lower()

    def auto_discover_shared_folders(self) -> List[tuple[str, str]]:
        """
        Zero-Config Discovery (OSS-D18: called only when governance.drive_folder_auto_discovery is on; off by
        default). Searches Google Drive for all folders named '01_Inbox_Requests' and finds their sibling
        '02_In_Progress' folder. FD-4AS: a discovered inbox is used only when it is the configured INBOX_FOLDER_ID or
        its Drive owner (``owners`` of the same files.list call, ``drive_file_owner_email``) is an authorized
        submitter; every other inbox is skipped with INBOX_FOLDER_UNAUTHORIZED (returned on ``.skipped``). An
        unreadable authorization store raises IntakeUnavailableError (the caller skips the pass).
        """
        if not self.drive_service:
            return IntakeList()

        folder_pairs = IntakeList()
        configured_inbox = os.getenv("INBOX_FOLDER_ID", "").strip()
        try:
            # Find all folders named '01_Inbox_Requests'
            query = "name = '01_Inbox_Requests' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
            res = self.drive_service.files().list(
                q=query, fields="files(id, name, parents, owners(emailAddress, me))").execute()
            inbox_folders = res.get("files", [])

            for inbox in inbox_folders:
                inbox_id = inbox["id"]
                if not (configured_inbox and inbox_id == configured_inbox):
                    refusal = self.submitter_refusal(self.drive_file_owner_email(inbox))
                    if refusal:
                        logger.warning(f"{INBOX_FOLDER_UNAUTHORIZED}: discovered inbox {inbox_id} not polled ({refusal})")
                        folder_pairs.skipped.append({"inbox_folder_id": inbox_id, "code": INBOX_FOLDER_UNAUTHORIZED,
                                                     "reason": refusal})
                        continue
                parents = inbox.get("parents", [])
                if parents:
                    parent_id = parents[0]
                    # Find sibling '02_In_Progress'
                    sibling_query = f"'{parent_id}' in parents and name = '02_In_Progress' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
                    sibling_res = self.drive_service.files().list(q=sibling_query, fields="files(id, name)").execute()
                    progress_folders = sibling_res.get("files", [])
                    if progress_folders:
                        progress_id = progress_folders[0]["id"]
                        folder_pairs.append((inbox_id, progress_id))
                        logger.info(f"Auto-discovered intake pair under parent {parent_id}: Inbox ({inbox_id}) -> In_Progress ({progress_id})")

            return folder_pairs
        except IntakeUnavailableError:
            raise
        except Exception as e:
            logger.warning(f"Drive folder auto-discovery failed: {e}")
            return IntakeList(skipped=folder_pairs.skipped)

    def list_inbox_specs(self, inbox_folder_id: str) -> List[Dict[str, Any]]:
        """Queries Google Drive for specification documents in the Inbox folder."""
        if not self.drive_service:
            raise RuntimeError("Google Drive client is not initialized")

        query = f"'{inbox_folder_id}' in parents and trashed = false and mimeType = 'application/vnd.google-apps.document'"
        # OSS-D23-a (orchestrator decision 10-20): the same call also returns each file's ``owners`` (no extra API
        # call), used only as the Drive-verified submitter. Files in shared drives carry no ``owners`` (nobody listed).
        try:
            results = (
                self.drive_service.files()
                .list(
                    q=query,
                    fields="files(id, name, mimeType, modifiedTime, createdTime, webViewLink, owners(emailAddress, me))",
                    pageSize=50,
                )
                .execute()
            )
            return results.get("files", [])
        except HttpError as e:
            logger.error(f"Error querying inbox folder {inbox_folder_id}: {e}")
            raise

    def move_to_in_progress(self, file_id: str, inbox_folder_id: str, in_progress_folder_id: str) -> bool:
        """Transitions document from Inbox to In_Progress folder."""
        return self._move(file_id, inbox_folder_id, in_progress_folder_id, "In_Progress")

    def move_back_to_inbox(self, file_id: str, inbox_folder_id: str, in_progress_folder_id: str) -> bool:
        """RT14-26: undoes ``move_to_in_progress`` after a failed publish, so the next poll sees the document again."""
        return self._move(file_id, in_progress_folder_id, inbox_folder_id, "Inbox")

    def _move(self, file_id: str, from_folder_id: str, to_folder_id: str, label: str) -> bool:
        if not self.drive_service:
            raise RuntimeError("Google Drive client is not initialized")

        try:
            self.drive_service.files().update(
                fileId=file_id,
                addParents=to_folder_id,
                removeParents=from_folder_id,
                fields="id, parents",
            ).execute()
            logger.info(f"Successfully moved doc {file_id} to {label} folder {to_folder_id}")
            return True
        except HttpError as e:
            logger.error(f"Failed to move document {file_id}: {e}")
            return False

    def publish_intake_event(self, payload: Dict[str, Any]) -> str:
        """Publishes the intake event to the spec-intake-events Pub/Sub topic."""
        if not self.publisher or not self.topic_path:
            logger.warning("Pub/Sub publisher not configured. Skipping event publish.")
            return "mock-message-id"

        try:
            data = json.dumps(payload).encode("utf-8")
            future = self.publisher.publish(self.topic_path, data)
            message_id = future.result()
            logger.info(f"Published intake event for doc {payload.get('spec_doc_id')} (Msg ID: {message_id})")
            return message_id
        except Exception as e:
            logger.error(f"Failed to publish intake event to Pub/Sub: {e}")
            raise

    @staticmethod
    def drive_file_owner_email(doc: Dict[str, Any]) -> Optional[str]:
        """OSS-D23 (owner 10-20): the spec file's owner address from the Drive API metadata of the inbox listing
        (``owners`` of the same files.list call; no extra API call). The OWNER is listed, not whoever moved the file
        into the inbox (FD-4AS authorized submitters is the real fix); shared-drive files have no owners. Exactly one
        owner that is not this service account (``me``), else None (unknown). Never read from the title, body or description. The gateway validates
        the address again (``shared.access_policy.verified_submitter_member``) before listing it."""
        owners = doc.get("owners")
        if not isinstance(owners, list) or len(owners) != 1 or not isinstance(owners[0], dict):
            return None
        owner = owners[0]
        email = owner.get("emailAddress")
        if owner.get("me") is True or not isinstance(email, str) or not email:
            return None
        return email

    def submitter_refusal(self, owner_email: Optional[str]) -> Optional[str]:
        """FD-4AS: None when ``owner_email`` (the Drive-verified owner from ``drive_file_owner_email``, never text
        from the document) is an authorized submitter, else a short reason. Authorized = an ACTIVE Control Center user
        record ``authorized_users/{email}`` (exact document id: the address stripped and lower-cased, the same key the
        Control Center reads) whose role is in SUBMITTER_ROLES. No domain or pattern matching. Raises
        IntakeUnavailableError when the store cannot be read (fail closed: never "proceed")."""
        return self.submitter_decision(owner_email)[0]

    def submitter_decision(self, owner_email: Optional[str]) -> Tuple[Optional[str], Dict[str, Any]]:
        """``submitter_refusal`` plus the accepted submitter's user record (RT14-02: its role and
        ``assigned_workloads`` decide which existing workloads the spec may target). (refusal, {}) when refused."""
        if not owner_email:
            return "no single Drive owner other than the platform service account (shared-drive files have none)", {}
        if not self.db:
            raise IntakeUnavailableError("the authorized-user store (Firestore) is not configured")
        stripped = owner_email.strip()
        if not stripped.isascii():  # RT F5: non-ASCII could lower-case onto an ASCII key (e.g. KELVIN SIGN -> 'k')
            return "the owner address is not a valid Control Center user id", {}
        clean = stripped.lower()
        try:
            ref = self.db.collection("authorized_users").document(clean)
        except ValueError:  # not a valid document id (e.g. contains '/'): cannot be a Control Center user
            return "the owner address is not a valid Control Center user id", {}
        try:
            snap = ref.get()
            data = (snap.to_dict() or {}) if snap.exists else None
        except Exception as e:  # noqa: BLE001 - any read failure is SPEC_INTAKE_UNAVAILABLE, never "proceed"
            raise IntakeUnavailableError(f"authorized_users unreadable ({type(e).__name__})") from e
        if data is None:
            return "the owner is not a Control Center user", {}
        if not isinstance(data, dict):
            return "the owner's Control Center user record is unreadable", {}
        if not _record_is_active(data.get("is_active", True)):
            return "the owner's Control Center user record is inactive", {}
        role = data.get("role", "APPROVER")
        if not isinstance(role, str) or role not in SUBMITTER_ROLES:
            return f"the owner's Control Center role ({role!r}) cannot submit specs", {}
        return None, data

    def workload_target_refusal(self, product_id: str, submitter: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        """RT14-02: (code, reason) when an accepted submitter may not send a spec to ``product_id``, else None.
        Mirrors the Control Center (``auth.verify_workload_access``): the platform is never a target (a pseudo-id, a
        record with ``is_castor: true`` or a record whose ``project_id`` is the host project; every role); an EXISTING
        workload needs the ADMIN role or an exact assignment (``assigned_workloads`` entries compared stripped and
        lower-cased, as the Control Center does). A new workload (no record) keeps the FD-4AS rule. Raises
        IntakeUnavailableError when the workload record cannot be read (fail closed)."""
        if product_id in PLATFORM_PSEUDO_WORKLOADS:
            return SPEC_TARGET_PLATFORM_WORKLOAD, f"'{product_id}' is the platform itself, not a workload"
        if not self.db:
            raise IntakeUnavailableError("the workload ledger (Firestore) is not configured")
        try:
            snap = self.db.collection("workloads").document(product_id).get()
            record = (snap.to_dict() or {}) if snap.exists else None
        except Exception as e:  # noqa: BLE001 - unreadable -> SPEC_INTAKE_UNAVAILABLE, never "proceed"
            raise IntakeUnavailableError(f"workloads/{product_id} unreadable ({type(e).__name__})") from e
        if record is None:
            return None
        if not isinstance(record, dict):
            raise IntakeUnavailableError(f"workloads/{product_id} is not a document")
        host = (self.project_id or "").strip()
        if record.get("is_castor") is True or (host and record.get("project_id") == host):
            return SPEC_TARGET_PLATFORM_WORKLOAD, f"workloads/{product_id} is the platform workload"
        if submitter.get("role") == ADMIN_ROLE:
            return None
        assigned = submitter.get("assigned_workloads")
        clean_assigned = {p.strip().lower() for p in (assigned if isinstance(assigned, (list, tuple)) else [])
                          if isinstance(p, str) and p.strip()}
        if product_id not in clean_assigned:
            return SPEC_WORKLOAD_NOT_ASSIGNED, (f"the submitter is not assigned to the existing workload "
                                                f"'{product_id}' (an administrator assigns it in the Control Center)")
        return None

    def decide_document(self, doc: Dict[str, Any], parent_drive_folder_id: Optional[str]) -> Tuple[str, Optional[str]]:
        """The whole FD-4AS + RT14-02/37 decision for one document, with no side effect: (product_id, target folder).
        Raises IntakeRejected (typed skip) or IntakeUnavailableError (the store or Drive cannot answer)."""
        refusal, submitter = self.submitter_decision(self.drive_file_owner_email(doc))
        if refusal:
            raise IntakeRejected(SPEC_SUBMITTER_UNAUTHORIZED, refusal)
        # OSS-D23-a / RT F2: ``owners`` is fetched for the submitter only; folder routing gets the file WITHOUT it,
        # so the owner-email assignment tier stays inactive exactly as before.
        routing_doc = {k: v for k, v in doc.items() if k != "owners"}
        target_folder_id = self.resolve_target_folder(routing_doc, parent_drive_folder_id=parent_drive_folder_id)
        product_id = self.extract_product_id(str(doc.get("name") or ""))
        try:
            validate_product_id(product_id)
        except UnsafePathError:
            raise IntakeRejected(SPEC_PRODUCT_ID_INVALID,
                                 f"the title gives the product id {product_id!r}, which is not 1-63 lowercase letters, "
                                 "digits and hyphens (starting and ending with a letter or digit); rename the document "
                                 "(a folder tag in the title is part of the id: give a folder id in the description "
                                 "instead)") from None
        target = self.workload_target_refusal(product_id, submitter)
        if target:
            raise IntakeRejected(*target)
        return product_id, target_folder_id

    def drive_item_owner_email(self, file_id: str) -> Optional[str]:
        """The Drive owner of one file or folder by id, from Drive metadata only (``owners(emailAddress, me)``, the
        same field and the same ``drive_file_owner_email`` rule as the inbox listing). Used for ids that do not come
        from a listing: a request-supplied inbox folder and the single-document intake. Raises
        IntakeUnavailableError when Drive cannot answer."""
        if not self.drive_service:
            raise IntakeUnavailableError("Google Drive client is not initialized")
        try:
            meta = self.drive_service.files().get(fileId=file_id, fields="id, owners(emailAddress, me)").execute()
        except HttpError as e:
            # RT F6: the service account cannot see the item (exact statuses) -> no verified owner, a refusal.
            if getattr(getattr(e, "resp", None), "status", None) in (403, 404):
                return None
            raise IntakeUnavailableError(f"Drive metadata of {file_id} unreadable (HttpError)") from e
        except Exception as e:  # noqa: BLE001 - unknown owner is a refusal input, so an unreadable one is unavailable
            raise IntakeUnavailableError(f"Drive metadata of {file_id} unreadable ({type(e).__name__})") from e
        return self.drive_file_owner_email(meta if isinstance(meta, dict) else {})

    def inbox_folder_refusal(self, inbox_folder_id: str) -> Optional[str]:
        """FD-4AS: a request-supplied inbox folder is polled only when it is the configured INBOX_FOLDER_ID or its
        Drive owner is an authorized submitter (same rule as auto-discovery). None = may be polled."""
        return self._folder_refusal(inbox_folder_id, "INBOX_FOLDER_ID")

    def in_progress_folder_refusal(self, in_progress_folder_id: str) -> Optional[str]:
        """FD-4AS / RT F1: a request-supplied in-progress folder (documents are MOVED into it and inherit its sharing)
        is used only when it is the configured IN_PROGRESS_FOLDER_ID or its Drive owner is an authorized submitter."""
        return self._folder_refusal(in_progress_folder_id, "IN_PROGRESS_FOLDER_ID")

    def _folder_refusal(self, folder_id: str, env_name: str) -> Optional[str]:
        configured = os.getenv(env_name, "").strip()
        if configured and folder_id == configured:
            return None
        return self.submitter_refusal(self.drive_item_owner_email(folder_id))

    def record_skip(self, doc_id: str, code: str, reason: str, folders: Dict[str, str],
                    owner_email: Optional[str] = None) -> Dict[str, Any]:
        """FD-4AS: the typed skip of one document, logged (doc id only, never content) and merged into the existing
        audit record ``spec_ingestions/{doc_id}`` under ``last_skip`` (RT F4: ``merge=True``, so an earlier successful
        ingestion's fields are never overwritten; an identical skip is not rewritten on every poll). The document is
        NOT moved, so it stays in the inbox and is re-evaluated by the next poll."""
        logger.warning(f"{code}: doc {doc_id} skipped ({reason})")
        entry = {"spec_doc_id": doc_id, "status": "SKIPPED", "skip_code": code, "skip_reason": reason,
                 "checked_at": datetime.now(timezone.utc).isoformat(), "folders": dict(folders)}
        last_skip = {"skip_code": code, "skip_reason": reason, "folders": dict(folders),
                     "owner_email": owner_email or None}  # audit only (who to add as a user); not in poll results
        if not self.db:
            logger.warning("Firestore client not configured. Skipping audit write.")
            return entry
        try:
            ref = self.db.collection("spec_ingestions").document(doc_id)
            snap = ref.get()
            prior = ((snap.to_dict() or {}) if snap.exists else {}).get("last_skip")
            if isinstance(prior, dict) and {k: prior.get(k) for k in last_skip} == last_skip:
                return entry  # same refusal as already recorded: no rewrite every poll
            ref.set({"spec_doc_id": doc_id, "last_skip": dict(last_skip, checked_at=entry["checked_at"])},
                    merge=True)
        except Exception as e:  # noqa: BLE001 - the skip itself already happened (nothing moved); audit is best effort
            logger.error(f"Failed to write the skip audit for doc {doc_id} ({type(e).__name__})")
        return entry

    def _publish_failed(self, doc: Dict[str, Any], folders: Dict[str, str], err: Exception) -> Dict[str, Any]:
        """RT14-26: the typed SPEC_PUBLISH_FAILED skip of a moved document whose event was not published. The document
        is moved back to the inbox; when that move fails too the skip says so (an operator moves it back by hand)."""
        doc_id = doc["id"]
        returned = False
        try:
            returned = self.move_back_to_inbox(doc_id, folders["inbox"], folders["in_progress"])
        except Exception as move_err:  # noqa: BLE001 - reported on the skip below
            logger.error(f"Doc {doc_id}: move back to the inbox failed ({type(move_err).__name__})")
        reason = (f"the intake event was not published ({type(err).__name__}); "
                  + ("the document was moved back to the inbox and the next poll tries again" if returned else
                     "moving it back to the inbox failed too: it is in the in-progress folder with nothing started; "
                     "move it back to the inbox to retry"))
        entry = self.record_skip(doc_id, SPEC_PUBLISH_FAILED, reason, folders, self.drive_file_owner_email(doc))
        entry["returned_to_inbox"] = returned
        return entry

    def record_submitter(self, trace_id: str, product_id: str, doc_id: str, email: Optional[str]) -> None:
        """OSS-D23: ``intake_submitters/{trace_id}`` = the Drive-verified owner of the spec file, read by the gateway
        intake when it stores the private platform default for a new workload. Nothing known or no store -> no record
        (the default then lists nobody). A failed write is logged and the intake goes on (unknown submitter)."""
        if not email or not self.db:
            return
        try:
            self.db.collection("intake_submitters").document(trace_id).set({
                "product_id": product_id, "spec_doc_id": doc_id, "email": email,
                "verified_by": "drive_file_owner", "recorded_at": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:  # noqa: BLE001 - the submitter is optional: unknown, never a failed intake
            logger.warning(f"Could not record the Drive owner of doc {doc_id} ({type(e).__name__}); nobody is listed")

    def record_ingestion(self, doc_id: str, payload: Dict[str, Any]) -> None:
        """Records the ingestion transaction in Firestore for deduplication and audit."""
        if not self.db:
            logger.warning("Firestore client not configured. Skipping audit write.")
            return

        try:
            doc_ref = self.db.collection("spec_ingestions").document(doc_id)
            doc_ref.set(payload)
            logger.info(f"Recorded ingestion audit entry in Firestore for doc {doc_id}")
        except Exception as e:
            logger.error(f"Failed to write Firestore audit record: {e}")

    def managed_folders(self) -> List[Dict[str, Any]]:
        """FD-4AS: every ``managed_folders`` document, read once per decision. Raises IntakeUnavailableError when the
        store cannot be read (the pass is skipped; nothing falls through to a default)."""
        if not self.db:
            raise IntakeUnavailableError("the managed-folder store (Firestore) is not configured")
        try:
            snaps = list(self.db.collection("managed_folders").stream())
            return [d for d in ((s.to_dict() or {}) for s in snaps) if isinstance(d, dict)]
        except Exception as e:  # noqa: BLE001 - unreadable -> SPEC_INTAKE_UNAVAILABLE, never a silent default
            raise IntakeUnavailableError(f"managed_folders unreadable ({type(e).__name__})") from e

    @staticmethod
    def _active_managed(folders: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Managed folders usable as a target: a normalizable ``folder_id`` and status ACTIVE (a missing status is
        a legacy ACTIVE record; the Control Center's delete sets DISABLED)."""
        return [f for f in folders
                if normalize_folder_id(f.get("folder_id")) and f.get("status", "ACTIVE") == "ACTIVE"]

    @staticmethod
    def _by_id(active: List[Dict[str, Any]], folder_id: str) -> Optional[str]:
        """Exact ``folder_id`` equality (both sides normalized to ``folders/<digits>``)."""
        for f in active:
            if normalize_folder_id(f.get("folder_id")) == folder_id:
                return folder_id
        return None

    @staticmethod
    def _by_name(active: List[Dict[str, Any]], name: str) -> Optional[str]:
        """Display-name candidate: ``str.casefold()`` equality of the whole stripped name (case-insensitive as before
        FD-4AS; no substring, prefix or fuzzy matching). It must identify exactly ONE managed folder: two folders
        whose names differ only in case make the candidate ambiguous, so it is refused (None)."""
        key = name.strip().casefold()
        if not key:
            return None
        hits = {normalize_folder_id(f.get("folder_id")) for f in active
                if isinstance(f.get("display_name"), str) and f["display_name"].strip().casefold() == key}
        return hits.pop() if len(hits) == 1 else None

    def resolve_target_folder(
        self,
        doc: Dict[str, Any],
        parent_drive_folder_id: Optional[str] = None,
    ) -> Optional[str]:
        """
        Deterministic 4-Tier Target Folder Resolution (FD-4AS: every answer is an ACTIVE managed folder):
        1. Document Title / Tag / Description / Properties (e.g. "[Folder: Financial Services]", "[folder: 123]")
        2. Author / Owner Email Assignment (users/{email}.assigned_folder_id; inactive on the poll path, which routes a
           copy of the file without ``owners``)
        3. Drive Parent Folder Name match against managed_folders display_name
        4. Platform Default (managed_folders is_default=True, else MANAGED_WORKLOADS_FOLDER_ID)

        The tag regex only PARSES the tag syntax; the decision is an exact managed-folder lookup (``folder_id``
        equality for ids, whole-name casefold equality for names). A tag, property or owner assignment that is not a
        managed folder raises IntakeRejected(TARGET_FOLDER_NOT_MANAGED): the document is skipped and never re-routed
        to a later tier. A parent name that matches nothing is not a choice, so tier 4 applies. The
        MANAGED_WORKLOADS_FOLDER_ID fallback is used only when it is itself an active managed folder or no
        managed_folders documents exist at all (fresh install). Nothing configured -> None (unchanged: the platform
        applies its own root downstream). Store or Drive unreadable -> IntakeUnavailableError.
        """
        doc_title = doc.get("name", "")
        doc_desc = doc.get("description", "")
        doc_props = doc.get("properties", {}) or {}

        # 1. Check title/description/properties for explicit folder tag
        tag_match = re.search(r"\[(?:folder|target[_-]folder):\s*([^\]]+)\]", doc_title, re.IGNORECASE)
        if not tag_match and doc_desc:
            tag_match = re.search(r"(?:folder|target[_-]folder):\s*([^\n\r]+)", doc_desc, re.IGNORECASE)

        folder_candidate = None
        if tag_match:
            folder_candidate = tag_match.group(1).strip()
        elif doc_props.get("target_folder"):
            folder_candidate = str(doc_props["target_folder"]).strip()

        folders = self.managed_folders()
        active = self._active_managed(folders)

        if folder_candidate:
            as_id = normalize_folder_id(folder_candidate)
            hit = self._by_id(active, as_id) if as_id else self._by_name(active, folder_candidate)
            if hit:
                return hit
            raise IntakeRejected(TARGET_FOLDER_NOT_MANAGED,
                                 "the document's folder tag or target_folder property is not exactly one active "
                                 "managed folder")

        # 2. Check author assignment
        owners = doc.get("owners", [])
        if owners and isinstance(owners, list) and isinstance(owners[0], dict):
            owner_email = str(owners[0].get("emailAddress") or "").strip().lower()
            if owner_email:
                try:
                    user_doc = self.db.collection("users").document(owner_email).get()
                    u_data = (user_doc.to_dict() or {}) if user_doc.exists else {}
                except ValueError:
                    u_data = {}
                except Exception as e:  # noqa: BLE001
                    raise IntakeUnavailableError(f"users unreadable ({type(e).__name__})") from e
                assigned = u_data.get("assigned_folder_id") if isinstance(u_data, dict) else None
                if assigned:
                    as_id = normalize_folder_id(assigned)
                    hit = self._by_id(active, as_id) if as_id else None
                    if hit:
                        return hit
                    raise IntakeRejected(TARGET_FOLDER_NOT_MANAGED,
                                         "the owner's assigned folder is not an active managed folder")

        # 3. Check Drive Parent Folder Name
        if parent_drive_folder_id and self.drive_service:
            try:
                parent_meta = self.drive_service.files().get(fileId=parent_drive_folder_id, fields="name").execute()
            except Exception as e:  # noqa: BLE001
                raise IntakeUnavailableError(
                    f"Drive name of folder {parent_drive_folder_id} unreadable ({type(e).__name__})") from e
            parent_name = parent_meta.get("name") if isinstance(parent_meta, dict) else None
            if isinstance(parent_name, str) and parent_name.strip():
                hit = self._by_name(active, parent_name)
                if hit:
                    return hit

        # 4. Platform Default (RT F7: exactly one; two defaults are ambiguous and refused, never order-dependent)
        defaults = {normalize_folder_id(f.get("folder_id")) for f in active if f.get("is_default") is True}
        if len(defaults) > 1:
            raise IntakeRejected(TARGET_FOLDER_NOT_MANAGED, "more than one default managed folder")
        if defaults:
            return defaults.pop()

        env_root = os.getenv("MANAGED_WORKLOADS_FOLDER_ID") or None
        if env_root:
            as_id = normalize_folder_id(env_root)
            if not folders or (as_id and self._by_id(active, as_id)):
                return env_root
            raise IntakeRejected(TARGET_FOLDER_NOT_MANAGED,
                                 "MANAGED_WORKLOADS_FOLDER_ID is not an active managed folder and no managed folder "
                                 "is the default")
        return None

    def read_doc_text(self, doc_id: str) -> str:
        """Attempts to read text body from Google Doc via Docs API if available."""
        if not hasattr(self, "docs_service") or not self.docs_service:
            try:
                credentials, _ = google.auth.default(scopes=SCOPES)
                self.docs_service = _build_thread_safe("docs", "v1", credentials)   # SAT-51
            except Exception:
                self.docs_service = None

        if not self.docs_service:
            return ""

        try:
            doc = self.docs_service.documents().get(documentId=doc_id).execute()
            text_chunks = []
            for element in doc.get("body", {}).get("content", []):
                para = element.get("paragraph")
                if para:
                    for elem in para.get("elements", []):
                        text_run = elem.get("textRun")
                        if text_run and "content" in text_run:
                            text_chunks.append(text_run["content"])
            return "".join(text_chunks)
        except Exception as e:
            logger.warning(f"Could not read doc body for {doc_id}: {e}")
            return ""

    def intake_payload(self, doc: Dict[str, Any], product_id: str, target_folder_id: Optional[str], trace_id: str,
                       timestamp: str, status: str, folders: Dict[str, Any]) -> Dict[str, Any]:
        """The intake event of one accepted document (the poll path's payload, also used by the single-document
        intake, RT14-27). Sandbox intent is detected from the title, description and document body."""
        doc_id = doc["id"]
        doc_title = doc["name"]
        doc_body_text = self.read_doc_text(doc_id)
        full_text = f"{doc_title} {doc.get('description', '')} {doc_body_text}".strip()
        is_sandbox, sandbox_ttl = detect_sandbox_intent(full_text)
        sandbox_expires_at = compute_sandbox_expiry(sandbox_ttl) if is_sandbox else None
        return {
            "trace_id": trace_id,
            "spec_doc_id": doc_id,
            "doc_title": doc_title,
            "product_id": product_id,
            "folder_id": target_folder_id,
            "source_channel": "google_docs",
            "ingested_at": timestamp,
            "status": status,
            "web_view_link": doc.get("webViewLink", ""),
            "is_sandbox": is_sandbox,
            "sandbox_ttl_days": sandbox_ttl,
            "sandbox_expires_at": sandbox_expires_at,
            "folders": dict(folders),
        }

    def drive_document(self, file_id: str) -> Dict[str, Any]:
        """RT14-27: one document's Drive metadata by id (the fields the inbox listing returns, plus ``parents``,
        ``description`` and ``properties`` for folder routing). A 403 / 404 (the service account cannot see it) is a
        document with no verified owner, so it is refused as an unknown submitter; any other failure raises
        IntakeUnavailableError (exactly as ``drive_item_owner_email``)."""
        if not self.drive_service:
            raise IntakeUnavailableError("Google Drive client is not initialized")
        try:
            meta = self.drive_service.files().get(
                fileId=file_id, fields="id, name, mimeType, description, properties, parents, webViewLink, "
                                       "owners(emailAddress, me)").execute()
        except HttpError as e:
            if getattr(getattr(e, "resp", None), "status", None) in (403, 404):
                return {"id": file_id}
            raise IntakeUnavailableError(f"Drive metadata of {file_id} unreadable (HttpError)") from e
        except Exception as e:  # noqa: BLE001
            raise IntakeUnavailableError(f"Drive metadata of {file_id} unreadable ({type(e).__name__})") from e
        meta = dict(meta) if isinstance(meta, dict) else {}
        meta["id"] = file_id
        return meta

    def ingest_document(self, file_id: str) -> Dict[str, Any]:
        """RT14-27: the single-document intake runs the poll path's decision (submitter, folder, product id, workload
        authorization: ``decide_document``) on the document's own Drive metadata, mints a trace id per request (the
        constant ``manual-trace`` made every later intake a gateway DUPLICATE), and publishes the poll path's payload.
        The document is not moved (it is not in an inbox by contract). Raises IntakeRejected (typed refusal),
        IntakeUnavailableError, or IntakePublishError when the event was not published (RT14 RT F2: only the publish
        is reported as a publish failure; nothing is recorded as ingested)."""
        doc = self.drive_document(file_id)
        parents = doc.get("parents")
        parent = parents[0] if isinstance(parents, list) and parents and isinstance(parents[0], str) else None
        product_id, target_folder_id = self.decide_document(doc, parent)
        trace_id = str(uuid.uuid4())
        payload = self.intake_payload(dict(doc, name=str(doc.get("name") or "")), product_id, target_folder_id,
                                      trace_id, datetime.now(timezone.utc).isoformat(), "MANUAL_INGEST", {})
        self.record_submitter(trace_id, product_id, file_id, self.drive_file_owner_email(doc))
        try:
            payload["pubsub_message_id"] = self.publish_intake_event(payload)
        except Exception as e:  # noqa: BLE001 - typed: the caller answers SPEC_PUBLISH_FAILED
            raise IntakePublishError(type(e).__name__) from e
        self.record_ingestion(file_id, payload)
        return payload

    def poll_and_ingest(
        self, inbox_folder_id: str, in_progress_folder_id: str
    ) -> List[Dict[str, Any]]:
        """Executes a full polling pass: discovers, transitions, publishes, and audits new specs.

        FD-4AS: two phases. (1) Decide every listed document with no side effect: its Drive owner (the same
        ``drive_file_owner_email`` identity OSS-D23 records) must be an authorized submitter, the product id from its
        title must be valid and a workload the submitter may target (RT14-02/37: ``decide_document``), and its target
        folder must resolve to an active managed folder; a refused document gets a typed skip (``.skipped`` of the returned
        list + its ``spec_ingestions`` audit record) and is NOT moved or published. If any decision input is
        unreadable, IntakeUnavailableError propagates before anything is moved (SPEC_INTAKE_UNAVAILABLE: the whole
        pass is skipped). (2) Ingest the accepted documents exactly as before (same payload).

        RT14 RT F4: at most one document per workload id is accepted in a pass (the first listed); a later one gets the
        typed skip SPEC_WORKLOAD_ALREADY_REQUESTED, stays in the inbox and is decided again on the next poll, so two
        owners cannot both start (or one build on the other's) NEW workload in the same pass."""
        specs = self.list_inbox_specs(inbox_folder_id)
        logger.info(f"Found {len(specs)} specification documents in Inbox folder {inbox_folder_id}")
        folders = {"inbox": inbox_folder_id, "in_progress": in_progress_folder_id}

        # Phase 1: decisions only (raises IntakeUnavailableError before any move / publish / write).
        accepted, refused, requested = [], [], set()
        for doc in specs:
            doc_id = doc["id"]
            try:
                product_id, target_folder_id = self.decide_document(doc, inbox_folder_id)
                if product_id in requested:
                    raise IntakeRejected(SPEC_WORKLOAD_ALREADY_REQUESTED,
                                         f"another document of this poll already requested the workload "
                                         f"'{product_id}'; this one is checked again on the next poll")
            except IntakeRejected as rej:
                refused.append((doc_id, rej.code, rej.reason, self.drive_file_owner_email(doc)))
                continue
            requested.add(product_id)
            accepted.append((doc, product_id, target_folder_id))

        ingested_items = IntakeList()
        for doc_id, code, reason, owner_email in refused:
            ingested_items.skipped.append(self.record_skip(doc_id, code, reason, folders, owner_email))

        # Phase 2: ingest the accepted documents (unchanged flow and payload).
        for doc, product_id, target_folder_id in accepted:
            doc_id = doc["id"]
            trace_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()

            # 1. Move file to In_Progress
            moved = self.move_to_in_progress(doc_id, inbox_folder_id, in_progress_folder_id)
            if not moved:
                logger.error(f"Skipping doc {doc_id} due to folder move failure")
                ingested_items.skipped.append({"spec_doc_id": doc_id, "status": "SKIPPED", "skip_code": SPEC_MOVE_FAILED,
                                               "skip_reason": "the Drive move to the in-progress folder failed",
                                               "folders": dict(folders)})
                continue

            # 2. Build Event Payload
            payload = self.intake_payload(doc, product_id, target_folder_id, trace_id, timestamp, "IN_PROGRESS",
                                          {"inbox": inbox_folder_id, "in_progress": in_progress_folder_id})

            # OSS-D23: the Drive-verified file owner, for the gateway's private platform default (new workloads only).
            self.record_submitter(trace_id, product_id, doc_id, self.drive_file_owner_email(doc))

            # 3. Publish to Pub/Sub. RT14-26: a failure here used to propagate with the doc already moved (nothing
            # published, no record, never polled again). The doc goes back to the inbox (the next poll tries again)
            # and the skip is typed with the doc id; the other documents of this pass go on.
            try:
                msg_id = self.publish_intake_event(payload)
            except Exception as pub_err:  # noqa: BLE001 - typed below, never swallowed
                ingested_items.skipped.append(self._publish_failed(doc, folders, pub_err))
                continue
            payload["pubsub_message_id"] = msg_id

            # 4. Audit to Firestore
            self.record_ingestion(doc_id, payload)

            ingested_items.append(payload)

        return ingested_items

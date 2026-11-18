"""
StackVend Control Center: INTERIM destructive guard for the automatic sandbox TTL sweep (lane 18 U2 / OQ-1).

Owner decision 2026-10-12 (lane 18 OQ-1): lane 4 carries this guard because it merges well before lane 18. The sweep
stays automatic. Before ANY delete (project, liens, state, DNS, IPAM, status) `assert_sandbox_deletable` must pass;
the first failed check raises `SandboxDeletionRefused(code, detail)` and nothing is mutated.

Check semantics and refusal codes are lane 18's `assert_deletable(..., action_class=SANDBOX_TTL)`
(docs/planning/wave2-lane18-destructive-guards-plan.md @176a0a8, §2.3 checks 1-9b, §R F4/F6/F10, row 26), restricted
to what exists today, so lane 18's vending-side guard (S1/S2) can replace this module 1:1:

  1  GUARD_UNCONFIGURED      MANAGED_WORKLOADS_FOLDER_ID (numeric) and >= 1 host project id configured
  2  LEDGER_MISSING / LEDGER_UNAVAILABLE / PLATFORM_WORKLOAD
                             fresh read of workloads/{product_id}; is_castor is not True; not a pseudo-workload
  3  LEDGER_UNPROVENANCED / LEDGER_MISMATCH
                             ledger project_id (no `or product_id` fallback) and numeric project_number present;
                             reverse uniqueness: workloads where project_id == X is exactly this product;
                             workload_provenance/{pid}, IF it exists, must match project id and number
  4  HOST_PROJECT            project id is not a host id
  5  CRM_MISMATCH / NOT_ACTIVE / HOST_PROJECT / CRM_UNAVAILABLE
                             fresh CRM v3 GET projects/{project_number}: projectId == ledger project_id exactly,
                             state ACTIVE, number != any host project number
  6  NOT_STACKVEND_OWNED / SANDBOX_NOT_ELIGIBLE
                             labels: if the project carries any lane 14/18 key (stackvend-managed,
                             stackvend-product-id, stackvend-workload-type) the set must match exactly
                             (managed == "true", product-id == product_id, workload-type == "sandbox" when present).
                             Today's vending writes NO project labels (vending.py create body = projectId,
                             displayName, parent), so a project without any of those keys is "pre-vocabulary" and
                             passes this check; the IAM-gated tag (lane 18 F2) needs S0 and is not checked here.
  7  NOT_IN_MANAGED_FOLDER / ANCESTRY_UNAVAILABLE
                             CRM v1 projects/{projectId}:getAncestry (the id just pinned to the number by check 5;
                             v1 is documented on project ids): the managed root folder is a folder ancestor
                             (ancestor[i >= 1]; never the project itself)
  8  LIEN_PRESENT / CRM_UNAVAILABLE
                             CRM v3 liens.list: StackVend records no liens, so ANY lien refuses; the guard never
                             deletes a lien (the old sweep released every lien it found)
  9b SANDBOX_NOT_ELIGIBLE    vend-time fields if they exist (workload_provenance/{pid}: created_by ==
                             "stackvend-vending", is_sandbox, sandbox_auto_decommission, designation source,
                             sandbox_expires_at < now); otherwise the ledger: is_sandbox is True,
                             sandbox_auto_decommission is True, sandbox_designation_source in the EXPLICIT set
                             (keyword-derived or missing => refuse), sandbox_expires_at < now, status not in-flight

CRM errors of any kind, including 429 and 5xx, refuse (no retry loop). The project is later deleted by NUMBER only.
Trust (lane 18 §2.5): until S0/S0b every agent SA can write Firestore, so this guard is anti-accident (host project,
foreign folders, guessed/mis-typed targets, keyword-derived sandboxes), not anti-attacker.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("control-center-sandbox-guard")

ACTION_CLASS = "SANDBOX_TTL"
STACKVEND_LABEL_KEYS = ("stackvend-managed", "stackvend-product-id", "stackvend-workload-type")
# lane 18 §2.3 9b / lane 14 Q1 vocabulary. KEYWORD_DETECTED (spec-text detection) is deliberately absent.
EXPLICIT_DESIGNATION_SOURCES = frozenset({"OPERATOR_CHECKBOX", "API_FIELD", "OPERATOR_CONFIRMED"})
NOT_ELIGIBLE_STATUSES = frozenset({"DECOMMISSIONED", "DELETED", "PROVISIONING", "REDEPLOYING", "DEPLOYING"})
PROVENANCE_CREATORS_TTL = frozenset({"stackvend-vending"})
PLATFORM_PSEUDO_WORKLOADS = frozenset({"project-castor", "castor", "platform"})

_CRM_V3 = "https://cloudresourcemanager.googleapis.com/v3/"
_CRM_V1 = "https://cloudresourcemanager.googleapis.com/v1/"


class SandboxDeletionRefused(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


class CRMUnavailable(Exception):
    """Any non-success CRM answer (incl. 429/5xx) or transport error. Never retried here."""

    def __init__(self, what: str, status: Optional[int] = None):
        super().__init__(f"{what} -> {'HTTP ' + str(status) if status is not None else 'transport error'}")
        self.status = status


@dataclass(frozen=True)
class SandboxVerdict:
    product_id: str
    project_id: str
    project_number: str
    action_class: str
    checks: Tuple[str, ...]


class RestCRM:
    """Resource Manager over REST (AuthorizedSession), no retries. Each method raises CRMUnavailable on failure."""

    def __init__(self, session=None):
        self._session = session

    def _s(self):
        if self._session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            self._session = AuthorizedSession(creds)
        return self._session

    def _call(self, method: str, url: str, what: str, **kw) -> Dict[str, Any]:
        try:
            resp = getattr(self._s(), method)(url, timeout=10, **kw)
        except Exception as e:  # noqa: BLE001 - transport error => refuse
            raise CRMUnavailable(f"{what} ({type(e).__name__})") from None
        if resp.status_code != 200:
            raise CRMUnavailable(what, resp.status_code)
        try:
            return resp.json() or {}
        except Exception:  # noqa: BLE001
            raise CRMUnavailable(f"{what} (unparseable body)") from None

    def get_project(self, number_or_id: str) -> Dict[str, Any]:
        return self._call("get", f"{_CRM_V3}projects/{number_or_id}", f"projects.get {number_or_id}")

    def get_ancestry(self, project_id: str) -> List[Dict[str, Any]]:
        body = self._call("post", f"{_CRM_V1}projects/{project_id}:getAncestry", f"getAncestry {project_id}", json={})
        return body.get("ancestor") or []

    def list_liens(self, project_number: str) -> List[Dict[str, Any]]:
        body = self._call("get", f"{_CRM_V3}liens", f"liens.list {project_number}",
                          params={"parent": f"projects/{project_number}"})
        return body.get("liens") or []

    def delete_project(self, project_number: str) -> Dict[str, Any]:
        return self._call("delete", f"{_CRM_V3}projects/{project_number}", f"projects.delete {project_number}")


def _host_project_ids() -> frozenset:
    return frozenset(v.strip() for v in (os.getenv("PROJECT_ID", ""), os.getenv("GOOGLE_CLOUD_PROJECT", ""),
                                         os.getenv("PLATFORM_PROJECT_ID", "")) if v and v.strip())


def _managed_root_id() -> Optional[str]:
    v = (os.getenv("MANAGED_WORKLOADS_FOLDER_ID", "") or "").strip()
    if v.startswith("folders/"):
        v = v[len("folders/"):]
    return v if v.isdigit() else None


def _parse_ts(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _number_of(project: Dict[str, Any]) -> str:
    """v3 Project.name is exactly 'projects/<number>' (positional split, exact segment count)."""
    parts = str(project.get("name") or "").split("/")
    return parts[1] if len(parts) == 2 and parts[0] == "projects" and parts[1].isdigit() else ""


def _read(db, collection: str, doc_id: str) -> Optional[Dict[str, Any]]:
    try:
        snap = db.collection(collection).document(doc_id).get()
    except Exception as e:  # noqa: BLE001
        raise SandboxDeletionRefused("LEDGER_UNAVAILABLE", f"{collection}/{doc_id} unreadable: {type(e).__name__}") from None
    if not getattr(snap, "exists", False):
        return None
    data = snap.to_dict()
    return data if isinstance(data, dict) else {}


def assert_sandbox_deletable(product_id: str, *, db, crm, now: Optional[datetime] = None) -> SandboxVerdict:
    """Raises SandboxDeletionRefused unless every check passes. Read-only: never mutates anything."""
    now = now or datetime.now(timezone.utc)
    checks: List[str] = []

    # 1 config
    root = _managed_root_id()
    hosts = _host_project_ids()
    if not root or not hosts:
        raise SandboxDeletionRefused("GUARD_UNCONFIGURED", "MANAGED_WORKLOADS_FOLDER_ID and a host project id are required")
    checks.append("config")

    # 2 ledger (fresh read, never the sweep's stream snapshot)
    if not isinstance(product_id, str) or not product_id or product_id in PLATFORM_PSEUDO_WORKLOADS:
        raise SandboxDeletionRefused("PLATFORM_WORKLOAD", f"{product_id!r} is not a tenant workload")
    w = _read(db, "workloads", product_id)
    if w is None:
        raise SandboxDeletionRefused("LEDGER_MISSING", f"workloads/{product_id} does not exist")
    if w.get("is_castor") is True:
        raise SandboxDeletionRefused("PLATFORM_WORKLOAD", f"workloads/{product_id} is the platform workload")
    if "product_id" in w and w.get("product_id") != product_id:
        raise SandboxDeletionRefused("LEDGER_MISMATCH", "workload record product_id differs from its document id")
    checks.append("ledger")

    # 3 ledger project identity
    project_id, project_number = w.get("project_id"), w.get("project_number")
    if not isinstance(project_id, str) or not project_id:
        raise SandboxDeletionRefused("LEDGER_UNPROVENANCED", "workload record has no project_id (no fallback to the product id)")
    project_number = str(project_number) if isinstance(project_number, (str, int)) and not isinstance(project_number, bool) else ""
    if not project_number.isdigit():
        raise SandboxDeletionRefused("LEDGER_UNPROVENANCED", "workload record has no numeric project_number")
    try:
        owners = [d.id for d in db.collection("workloads").where("project_id", "==", project_id).stream()]
    except Exception as e:  # noqa: BLE001
        raise SandboxDeletionRefused("LEDGER_UNAVAILABLE", f"reverse lookup failed: {type(e).__name__}") from None
    if owners != [product_id]:
        raise SandboxDeletionRefused("LEDGER_MISMATCH", f"project {project_id} is claimed by {sorted(owners)}")
    prov = _read(db, "workload_provenance", product_id)
    if prov is not None and (prov.get("project_id") != project_id or str(prov.get("project_number") or "") != project_number):
        raise SandboxDeletionRefused("LEDGER_MISMATCH", "workload_provenance disagrees with the workload record")
    checks.append("ledger_identity")

    # 4 not host
    if project_id in hosts:
        raise SandboxDeletionRefused("HOST_PROJECT", f"{project_id} is the host project")
    checks.append("not_host")

    # 9b eligibility (pure Firestore; evaluated before any further CRM call)
    if prov is not None:
        src = prov
        if prov.get("created_by") not in PROVENANCE_CREATORS_TTL:
            raise SandboxDeletionRefused("SANDBOX_NOT_ELIGIBLE", "provenance was not written by vending at birth")
        checks.append("eligibility:provenance")
    else:
        src = w
        checks.append("eligibility:ledger_explicit_designation")
    if src.get("is_sandbox") is not True or src.get("sandbox_auto_decommission") is not True:
        raise SandboxDeletionRefused("SANDBOX_NOT_ELIGIBLE", "not an auto-decommission sandbox")
    if src.get("sandbox_designation_source") not in EXPLICIT_DESIGNATION_SOURCES:
        raise SandboxDeletionRefused("SANDBOX_NOT_ELIGIBLE",
                                     f"sandbox designation {src.get('sandbox_designation_source')!r} is not explicit")
    expires = _parse_ts(src.get("sandbox_expires_at"))
    if expires is None or not expires < now:
        raise SandboxDeletionRefused("SANDBOX_NOT_ELIGIBLE", "sandbox_expires_at is missing or in the future")
    if w.get("is_sandbox") is not True or w.get("status") in NOT_ELIGIBLE_STATUSES:
        raise SandboxDeletionRefused("SANDBOX_NOT_ELIGIBLE", f"workload status {w.get('status')!r} is not eligible")

    # 5 CRM identity (by number)
    try:
        host_numbers = {_number_of(crm.get_project(h)) for h in sorted(hosts)}
        project = crm.get_project(project_number)
    except CRMUnavailable as e:
        raise SandboxDeletionRefused("CRM_UNAVAILABLE", str(e)) from None
    if "" in host_numbers:
        raise SandboxDeletionRefused("CRM_UNAVAILABLE", "could not resolve the host project number")
    if _number_of(project) != project_number or project.get("projectId") != project_id:
        raise SandboxDeletionRefused("CRM_MISMATCH", f"projects/{project_number} is not {project_id}")
    if project_number in host_numbers:
        raise SandboxDeletionRefused("HOST_PROJECT", f"projects/{project_number} is the host project")
    if project.get("state") != "ACTIVE":
        raise SandboxDeletionRefused("NOT_ACTIVE", f"project state is {project.get('state')!r}")
    checks.append("crm_identity")

    # 6 labels
    labels = project.get("labels") or {}
    labels = labels if isinstance(labels, dict) else {}
    if any(k in labels for k in STACKVEND_LABEL_KEYS):
        if labels.get("stackvend-managed") != "true" or labels.get("stackvend-product-id") != product_id:
            raise SandboxDeletionRefused("NOT_STACKVEND_OWNED", "StackVend labels do not name this product")
        if "stackvend-workload-type" in labels and labels.get("stackvend-workload-type") != "sandbox":
            raise SandboxDeletionRefused("SANDBOX_NOT_ELIGIBLE", "project is labelled as a non-sandbox workload")
        checks.append("labels:stackvend")
    else:
        checks.append("labels:pre-vocabulary")

    # 7 ancestry
    try:
        ancestors = crm.get_ancestry(project_id)
    except CRMUnavailable as e:
        raise SandboxDeletionRefused("ANCESTRY_UNAVAILABLE", str(e)) from None
    first = ancestors[0].get("resourceId") if ancestors and isinstance(ancestors[0], dict) else None
    if not isinstance(first, dict) or first.get("type") != "project" or str(first.get("id")) not in (project_id, project_number):
        raise SandboxDeletionRefused("ANCESTRY_UNAVAILABLE", "ancestry does not start at the target project")
    if not any(isinstance(a, dict) and isinstance(a.get("resourceId"), dict)
               and a["resourceId"].get("type") == "folder" and str(a["resourceId"].get("id")) == root
               for a in ancestors[1:]):
        raise SandboxDeletionRefused("NOT_IN_MANAGED_FOLDER", f"projects/{project_number} is not under folders/{root}")
    checks.append("ancestry")

    # 8 liens
    try:
        liens = crm.list_liens(project_number)
    except CRMUnavailable as e:
        raise SandboxDeletionRefused("CRM_UNAVAILABLE", str(e)) from None
    if liens:
        raise SandboxDeletionRefused("LIEN_PRESENT", f"{len(liens)} lien(s) on the project; StackVend never removes a lien")
    checks.append("liens")

    return SandboxVerdict(product_id=product_id, project_id=project_id, project_number=project_number,
                          action_class=ACTION_CLASS, checks=tuple(checks))

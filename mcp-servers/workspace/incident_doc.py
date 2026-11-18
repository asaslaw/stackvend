"""
StackVend Workspace connector: incident document for POST /create-incident-spec (FD-4BM).

Three parts, all deterministic:
1. ``resolve_target`` decides where the document goes, from the existing Workspace connector configuration: the
   request's ``inbox_folder_id`` when the caller names a folder, else ``IN_PROGRESS_FOLDER_ID`` (the in-progress
   folder of the Docs intake, already set on every platform service from the install's Terraform variables). The
   document is created inside that folder, so it is shared exactly as the folder is (no permission is added). An
   optional ``INCIDENT_TEMPLATE_ID`` names a Google Doc template to copy instead of the built-in template.
   Nothing usable configured -> ``NotConfigured`` (the route answers 503 INCIDENT_TEMPLATE_NOT_CONFIGURED).
2. ``read_pipeline_records`` reads the incident's records READ-ONLY from Firestore (REST through the Google API
   discovery client the server already ships; no new dependency): ``incidents/{incident_id}``, its
   ``incident_clusters/{fingerprint_hash}``, the linked ``pipeline_executions/{trace}`` and
   ``workloads/{product_id}``. A record that cannot be read is named in the document's "Record sources" section;
   it never fails the document and is never invented.
3. ``build_context`` + ``render_html`` fill the built-in template (``incident_doc_template.html``). Every value is
   HTML-escaped; ``string.Template`` substitutes in one pass.
"""

import html
import logging
import os
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("mcp-workspace-connector")

TEMPLATE_PATH = Path(__file__).resolve().parent / "incident_doc_template.html"
BUILTIN_TEMPLATE_NAME = "builtin:incident_doc_template.html"

# Firestore document ids this module reads are letters, digits, '-' and '_' (incident ids "inc-<hex>", trace ids,
# product ids, sha256 fingerprints). Exact allow-list: anything else is not read (it could name another path).
RECORD_ID_CHARS = frozenset(string.ascii_letters + string.digits + "-_")
RECORD_ID_MAX_LEN = 256
# Drive folder / file ids (same rule as service.DRIVE_ID_CHARS; repeated here so this module stays standalone).
DRIVE_ID_CHARS = frozenset(string.ascii_letters + string.digits + "-_")
DRIVE_ID_MAX_LEN = 128

STACK_TRACE_LIMIT = 30000
FIELD_LIMIT = 4000
FIRESTORE_SCOPES = ["https://www.googleapis.com/auth/datastore"]
FIRESTORE_TIMEOUT_SECONDS = 15


class NotConfigured(Exception):
    """Workspace is not configured for incident documents. ``reason`` is a fixed code for the 503 body."""

    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def is_drive_id(value: Any) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= DRIVE_ID_MAX_LEN and set(value) <= DRIVE_ID_CHARS)


def is_record_id(value: Any) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= RECORD_ID_MAX_LEN and set(value) <= RECORD_ID_CHARS)


# ----------------------------------------------------------------------------------------------------------------
# 1. Target folder + template
# ----------------------------------------------------------------------------------------------------------------
class InvalidRequestFolder(ValueError):
    """The request named a folder that is not a Drive id (the route answers 422 INVALID_DRIVE_ID)."""


def resolve_target(requested_folder: Optional[str] = None,
                   env: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
    """``(folder_id, template_id)``; ``template_id`` "" = the built-in template.

    A folder named in the request wins (it must be a Drive id, else ``InvalidRequestFolder``). Otherwise
    ``IN_PROGRESS_FOLDER_ID``, documented as "a folder ID (or comma-separated IDs)": exactly one id is required
    here, because the document goes to one folder. Raises ``NotConfigured`` when nothing usable is configured."""
    env = os.environ if env is None else env
    template_id = (env.get("INCIDENT_TEMPLATE_ID") or "").strip()
    if template_id and not is_drive_id(template_id):
        raise NotConfigured("TEMPLATE_ID_INVALID",
                            "INCIDENT_TEMPLATE_ID is not a Drive document id (letters, digits, '-' and '_' only).")
    requested = (requested_folder or "").strip()
    if requested:
        if not is_drive_id(requested):
            raise InvalidRequestFolder("inbox_folder_id may contain only letters, digits, '-' and '_' "
                                       f"(at most {DRIVE_ID_MAX_LEN} characters)")
        return requested, template_id
    raw_folder = (env.get("IN_PROGRESS_FOLDER_ID") or "").strip()
    folders = [part.strip() for part in raw_folder.split(",") if part.strip()]
    if not folders:
        raise NotConfigured("FOLDER_NOT_CONFIGURED",
                            "No Drive folder for incident documents: IN_PROGRESS_FOLDER_ID is not set on "
                            "mcp-workspace-connector (install variable google_drive_in_progress_folder_ids).")
    if len(folders) > 1:
        raise NotConfigured("FOLDER_AMBIGUOUS",
                            f"IN_PROGRESS_FOLDER_ID lists {len(folders)} folders; incident documents need exactly one.")
    if not is_drive_id(folders[0]):
        raise NotConfigured("FOLDER_ID_INVALID",
                            "IN_PROGRESS_FOLDER_ID is not a Drive folder id (letters, digits, '-' and '_' only).")
    return folders[0], template_id


# ----------------------------------------------------------------------------------------------------------------
# 2. Pipeline records (read-only)
# ----------------------------------------------------------------------------------------------------------------
def decode_firestore_value(value: Dict[str, Any]) -> Any:
    """One Firestore REST ``Value`` -> Python (the documented union: exactly one key is set)."""
    if not isinstance(value, dict):
        return None
    if "stringValue" in value:
        return value["stringValue"]
    if "integerValue" in value:
        try:
            return int(value["integerValue"])
        except (TypeError, ValueError):
            return value["integerValue"]
    if "doubleValue" in value:
        return value["doubleValue"]
    if "booleanValue" in value:
        return bool(value["booleanValue"])
    if "nullValue" in value:
        return None
    if "timestampValue" in value:
        return value["timestampValue"]
    if "mapValue" in value:
        return decode_firestore_fields((value["mapValue"] or {}).get("fields") or {})
    if "arrayValue" in value:
        return [decode_firestore_value(v) for v in ((value["arrayValue"] or {}).get("values") or [])]
    if "referenceValue" in value:
        return value["referenceValue"]
    if "bytesValue" in value:
        return value["bytesValue"]
    if "geoPointValue" in value:
        return value["geoPointValue"]
    return None


def decode_firestore_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    return {k: decode_firestore_value(v) for k, v in (fields or {}).items()}


class FirestoreRestReader:
    """Read-only ``get`` of one document by collection + id over the Firestore REST API (discovery client
    ``firestore v1``, bundled with google-api-python-client). ``None`` when the document does not exist; any other
    failure raises. ``client`` is a seam for tests (a ``documents()`` resource)."""

    def __init__(self, project_id: str, database: str = "(default)", client: Any = None):
        self.project_id = project_id
        self.database = database
        self._client = client

    def _documents(self):
        if self._client is None:
            import google.auth
            import google_auth_httplib2
            import httplib2
            from googleapiclient.discovery import build

            credentials, _ = google.auth.default(scopes=FIRESTORE_SCOPES)
            http = google_auth_httplib2.AuthorizedHttp(credentials, http=httplib2.Http(timeout=FIRESTORE_TIMEOUT_SECONDS))
            self._client = build("firestore", "v1", http=http, cache_discovery=False).projects().databases().documents()
        return self._client

    def get(self, collection: str, doc_id: str) -> Optional[Dict[str, Any]]:
        if not is_record_id(collection) or not is_record_id(doc_id):
            raise ValueError("record path has characters outside letters, digits, '-' and '_'")
        name = f"projects/{self.project_id}/databases/{self.database}/documents/{collection}/{doc_id}"
        try:
            doc = self._documents().get(name=name).execute()
        except Exception as e:
            status = getattr(getattr(e, "resp", None), "status", None)
            if status == 404 or str(status) == "404":
                return None
            raise
        return decode_firestore_fields((doc or {}).get("fields") or {})


def _read(reader: Any, collection: str, doc_id: Any, notes: List[str]) -> Optional[Dict[str, Any]]:
    path = f"{collection}/{doc_id}"
    if not is_record_id(doc_id):
        notes.append(f"{collection}: not read (no valid record id)")
        return None
    try:
        data = reader.get(collection, doc_id)
    except Exception as e:
        logger.warning(f"Incident document: could not read {path}: {type(e).__name__}: {e}")
        notes.append(f"{path}: unavailable ({type(e).__name__})")
        return None
    if data is None:
        notes.append(f"{path}: not found")
        return None
    notes.append(f"{path}: read")
    return data


def read_pipeline_records(reader: Any, incident_id: str, product_id: str) -> Tuple[Dict[str, Any], List[str]]:
    """``({incident, cluster, pipeline, workload}, notes)``. ``reader`` None -> nothing read (noted)."""
    records: Dict[str, Any] = {"incident": None, "cluster": None, "pipeline": None, "workload": None}
    notes: List[str] = []
    if reader is None:
        notes.append("Firestore records: not read (PROJECT_ID is not set on mcp-workspace-connector)")
        return records, notes
    incident = _read(reader, "incidents", incident_id, notes)
    records["incident"] = incident
    incident = incident or {}
    fingerprint = incident.get("fingerprint_hash")
    if fingerprint:
        records["cluster"] = _read(reader, "incident_clusters", fingerprint, notes)
    linked = incident.get("linked_pipeline_trace_id")
    if linked:
        records["pipeline"] = _read(reader, "pipeline_executions", linked, notes)
    else:
        notes.append("pipeline_executions: no pipeline run is linked to this incident"
                     + (f" (link status {incident.get('link_status')})" if incident.get("link_status") else ""))
    pid = product_id or incident.get("product_id") or ""
    if pid:
        records["workload"] = _read(reader, "workloads", pid, notes)
    else:
        notes.append("workloads: not read (no workload is attributed to this incident)")
    return records, notes


# ----------------------------------------------------------------------------------------------------------------
# 3. Context + rendering
# ----------------------------------------------------------------------------------------------------------------
def _text(value: Any, limit: int = FIELD_LIMIT) -> str:
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    return s if len(s) <= limit else s[:limit] + f" [truncated, {len(s)} characters]"


def _or_none(value: str, missing: str = "not recorded") -> str:
    return value if value.strip() else missing


def _parse_ts(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _timeline(incident: Dict[str, Any], cluster: Dict[str, Any], pipeline: Dict[str, Any], pipeline_trace: str,
              now_iso: str) -> List[str]:
    events: List[Tuple[Optional[datetime], str, str]] = []

    def add(ts: Any, text: str) -> None:
        if isinstance(ts, str) and ts:
            events.append((_parse_ts(ts), ts, text))

    if pipeline:
        add(pipeline.get("started_at"), f"Pipeline run {pipeline_trace} started")
        if pipeline.get("completed_at"):
            ended = f"Pipeline run {pipeline_trace} ended {_text(pipeline.get('status')) or 'with no status'}"
            if pipeline.get("failed_stage"):
                ended += f" (failed stage: {_text(pipeline.get('failed_stage'), 200)})"
            add(pipeline.get("completed_at"), ended)
    if incident:
        add(incident.get("created_at"),
            f"Incident recorded by the SRE sentinel (status {_text(incident.get('status'), 100) or 'unknown'}, "
            f"auto-remediation {_text(incident.get('auto_remediation_status'), 200) or 'unknown'})")
    if cluster:
        if cluster.get("reopened_at"):
            prev = _text(cluster.get("previous_incident_id"), 100)
            add(cluster.get("reopened_at"), "Incident cluster reopened" + (f" (previous incident {prev})" if prev else ""))
        count = cluster.get("occurrence_count")
        add(cluster.get("last_seen_at"), "Last occurrence seen" + (f" ({count} occurrences)" if count else ""))
    add(now_iso, "Incident document created")
    known = sorted((e for e in events if e[0] is not None), key=lambda e: e[0])
    unknown = [e for e in events if e[0] is None]  # unparseable timestamps keep their order, after the rest
    return [f"{raw}: {text}" for _, raw, text in known + unknown]


def _pipeline_failure(pipeline: Dict[str, Any], pipeline_trace: str) -> str:
    if not pipeline:
        return "no pipeline record linked to this incident"
    parts = [f"run {pipeline_trace}", f"status {_text(pipeline.get('status'), 100) or 'unknown'}"]
    if pipeline.get("failed_stage"):
        parts.append(f"failed stage {_text(pipeline.get('failed_stage'), 200)}")
    if pipeline.get("current_stage") and not pipeline.get("failed_stage"):
        parts.append(f"current stage {_text(pipeline.get('current_stage'), 200)}")
    cause = _text(pipeline.get("failure_reason")) or _text(pipeline.get("error"))
    if pipeline.get("error_class"):
        cause = f"{_text(pipeline.get('error_class'), 200)}" + (f": {cause}" if cause else "")
    if cause:
        parts.append(cause)
    return "; ".join(parts)


def build_context(fields: Dict[str, Any], records: Dict[str, Any], notes: List[str],
                  now_iso: Optional[str] = None) -> Dict[str, Any]:
    """Plain-text values for the template. ``fields`` is the request body; a recorded value wins over a request
    value only where the request left it empty (the request is the triage of the same record)."""
    now_iso = now_iso or datetime.now(timezone.utc).isoformat()
    incident = records.get("incident") or {}
    cluster = records.get("cluster") or {}
    pipeline = records.get("pipeline") or {}
    workload = records.get("workload") or {}
    rca = incident.get("rca") if isinstance(incident.get("rca"), dict) else {}

    def pick(req_key: str, *recorded: Any) -> str:
        v = _text(fields.get(req_key))
        if v.strip():
            return v
        for r in recorded:
            if _text(r).strip():
                return _text(r)
        return ""

    incident_id = _text(fields.get("incident_id"), 200)
    service_name = pick("service_name", incident.get("service_name"))
    product_id = pick("product_id", incident.get("product_id"))
    trace_id = pick("trace_id", incident.get("trace_id"))
    pipeline_trace = _text(incident.get("linked_pipeline_trace_id"), 200)
    workload_text = product_id
    if product_id and workload.get("project_id"):
        workload_text = f"{product_id} (project {_text(workload.get('project_id'), 200)})"

    steps: List[str] = []
    recommended = _text(rca.get("recommended_action"))
    if recommended:
        steps.append(f"Recommended fix (deterministic analysis): {recommended}")
    if pipeline and pipeline.get("failed_stage"):
        steps.append(f"Check the failed stage {_text(pipeline.get('failed_stage'), 200)} of pipeline run "
                     f"{pipeline_trace} in Control Center.")
    steps.append("Review the remediation plan in Control Center > Approvals before approving it: the SRE "
                 "remediation request for this incident asks for plan approval.")
    if trace_id:
        steps.append(f"Follow the remediation run (trace {trace_id}) in Control Center.")

    title = f"INCIDENT-FIX: {_text(service_name, 100) or 'unknown component'} ({incident_id})"
    return {
        "TITLE": title,
        "INCIDENT_ID": incident_id,
        "SEVERITY": _or_none(pick("severity", rca.get("severity"))),
        "WORKLOAD": _or_none(workload_text, "not attributed to a workload"),
        "SERVICE_NAME": _or_none(service_name),
        "AFFECTED_REPO": _or_none(pick("affected_repository", rca.get("affected_repository"))),
        "TRACE_ID": _or_none(trace_id),
        "PIPELINE_TRACE_ID": _or_none(pipeline_trace, "none linked"),
        "ROOT_CAUSE": _or_none(pick("root_cause_summary", rca.get("root_cause_summary"))),
        "ERROR_MESSAGE": _or_none(_text(incident.get("error_message"))),
        "PIPELINE_FAILURE": _pipeline_failure(pipeline, pipeline_trace),
        "STACK_TRACE": _or_none(_text(fields.get("stack_trace") or incident.get("stack_trace"), STACK_TRACE_LIMIT)),
        "TIMELINE": _timeline(incident, cluster, pipeline, pipeline_trace, now_iso),
        "NEXT_STEPS": steps,
        "SOURCES": list(notes),
        # kept for Drive templates written against the earlier placeholder set
        "PRODUCT_ID": product_id,
    }


LIST_KEYS = {"TIMELINE_ITEMS": "TIMELINE", "NEXT_STEPS_ITEMS": "NEXT_STEPS", "SOURCES_ITEMS": "SOURCES"}
TEXT_KEYS = ("TITLE", "INCIDENT_ID", "SEVERITY", "WORKLOAD", "SERVICE_NAME", "AFFECTED_REPO", "TRACE_ID",
             "PIPELINE_TRACE_ID", "ROOT_CAUSE", "ERROR_MESSAGE", "PIPELINE_FAILURE", "STACK_TRACE")


def load_template(path: Path = TEMPLATE_PATH) -> string.Template:
    return string.Template(path.read_text(encoding="utf-8"))


def render_html(ctx: Dict[str, Any], template: Optional[string.Template] = None) -> str:
    """The built-in template filled with ``ctx`` (every value escaped). ``substitute`` raises KeyError when the
    template names a placeholder the context lacks, so a template / code mismatch fails loudly, never silently."""
    template = template or load_template()
    values = {k: html.escape(str(ctx.get(k, "")), quote=True) for k in TEXT_KEYS}
    for key, src in LIST_KEYS.items():
        values[key] = "\n".join(f"<li>{html.escape(str(item), quote=True)}</li>" for item in ctx.get(src) or [])
    return template.substitute(values)


def plain_replacements(ctx: Dict[str, Any]) -> Dict[str, str]:
    """``{{KEY}}`` replacements for an operator's Drive template (``INCIDENT_TEMPLATE_ID``): the earlier keys
    (INCIDENT_ID, SEVERITY, SERVICE_NAME, AFFECTED_REPO, ROOT_CAUSE, STACK_TRACE) plus the FD-4BM sections."""
    return {
        "INCIDENT_ID": ctx["INCIDENT_ID"],
        "SEVERITY": ctx["SEVERITY"],
        "SERVICE_NAME": ctx["SERVICE_NAME"],
        "AFFECTED_REPO": ctx["AFFECTED_REPO"],
        "ROOT_CAUSE": ctx["ROOT_CAUSE"],
        "STACK_TRACE": ctx["STACK_TRACE"],
        "PRODUCT_ID": ctx["PRODUCT_ID"],
        "WORKLOAD": ctx["WORKLOAD"],
        "TRACE_ID": ctx["TRACE_ID"],
        "PIPELINE_TRACE_ID": ctx["PIPELINE_TRACE_ID"],
        "ERROR_MESSAGE": ctx["ERROR_MESSAGE"],
        "FAILURE_SUMMARY": ctx["PIPELINE_FAILURE"],
        "TIMELINE": "\n".join(ctx["TIMELINE"]),
        "NEXT_STEPS": "\n".join(f"{i}. {s}" for i, s in enumerate(ctx["NEXT_STEPS"], 1)),
    }

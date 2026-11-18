"""
Pub/Sub intake policy for `/events/pubsub-intake` (lane 14 PR-4, plan §2.7 item 5, row L14-j; lane 17 R17-1).

Exact `source_channel` allow-set built from today's producers. A message whose channel is not in the set is refused
with 422 (Pub/Sub redelivers it until the dead-letter policy moves it to `castor-dlq`, where it is visible); it never
starts a pipeline. An absent channel is the Google Docs path (`main_orchestrator.yaml` defaults it the same way).

The two autonomous channels (`github_refactor_scanner`, `sre_sentinel`) carry no human request, so they are held to
more: `product_id` and their own id (`scan_id` / `incident_id`) are required, `execution_mode` must be exactly
`FULL_BUILD` (lane 17's `PLATFORM_REMEDIATION` does not exist yet), and plan approval is forced on. The ledger
re-check (toggle, code freeze, status) is done by the caller with Firestore (`autonomous_ledger_refusal`).

compliance-profile-explicit: an optional `compliance_profile` must be exactly one of the compliance profiles
(`compliance_agent/profiles.py`); anything else is 422 `SUPPRESSED:INVALID_COMPLIANCE_PROFILE` on every channel.

Lane 19 L19-11 (RT F9): intake events never carry the workload's access record. The CC stores it on
`workloads/{pid}.access` before publishing and the developer reads only that document, so an `access` field in an
event (any channel; `source_channel` is spoofable payload data) is 422 `SUPPRESSED:INVALID_ACCESS_POLICY`, never
silently ignored and never forwarded.

RESUME-DEVELOPER-TASK-DAG: `request_id` is optional run metadata, sent today by the CC create form and the CC promotion
(a CC relaunch records it on the run itself). `source_channel` is spoofable, and the id decides which feature request the
run's end updates, so an id on an event is checked on every channel before dispatch: it is one document id, and
`feature_requests/{id}` exists and belongs to the event's `product_id`. Anything else is 422
`SUPPRESSED:INVALID_REQUEST_ID`. The caller does the read (`check_request_id_format`, `check_request_id_owner`); an event
with no id is unchanged.

RT14-02 / RT14-37 (owner 11-14): `product_id` is required on every channel and must be an RFC 1123 label
(`shared.path_safety.validate_product_id`, the allow-list every other entry point uses), else 422
`SUPPRESSED:INVALID_PRODUCT_ID` (a `/` used to become a Firestore subcollection path, an empty id a run that fails
later). On every non-autonomous channel a platform pseudo-workload id is 422 `SUPPRESSED:PLATFORM_WORKLOAD`, and the
caller refuses an event whose workload record is the platform (`platform_workload_refusal`: `is_castor` or the host
project), because vending would otherwise reuse the host project (invariant 5). Autonomous channels keep their ledger
re-check (`autonomous_ledger_refusal`), unchanged.

Pure functions; no I/O. Exact comparisons only.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from compliance_agent.profiles import InvalidComplianceProfile, parse_profile
from shared.path_safety import UnsafePathError, validate_product_id

DEFAULT_SOURCE_CHANNEL = "google_docs"

# Producers on main (lane 14 rev 3 §2.7): spec-ingestion poller/main (google_docs), CC create (control_center_form),
# CC retrigger (control_center_retrigger), CC deploy-infra (control_center_deploy_infra), CC promote
# (deploy_to_folder), CC HITL approval (control_center_hitl_approval), refactor scanner, SRE remediation workflow.
SOURCE_CHANNELS = frozenset({
    "google_docs",
    "control_center_form",
    "control_center_retrigger",
    "control_center_deploy_infra",
    "deploy_to_folder",
    "control_center_hitl_approval",
    "github_refactor_scanner",
    "sre_sentinel",
})

CHANNEL_REFACTOR = "github_refactor_scanner"
CHANNEL_SRE = "sre_sentinel"
AUTONOMOUS_CHANNELS: Dict[str, Dict[str, str]] = {
    # RT F11: the refactor dedupe keys on findings_digest, so a digest-less event is incomplete (it skipped the
    # dedupe before).
    CHANNEL_REFACTOR: {"id_field": "scan_id", "invalid": "SUPPRESSED:INVALID_REFACTOR_EVENT",
                       "toggle": "refactor_scanner_enabled", "extra_field": "findings_digest"},
    CHANNEL_SRE: {"id_field": "incident_id", "invalid": "SUPPRESSED:INVALID_SRE_EVENT",
                  "toggle": "sre_auto_healing_enabled"},
}
AUTONOMOUS_EXECUTION_MODE = "FULL_BUILD"
ACTIVE_STATUS = "ACTIVE"
INVALID_REQUEST_ID = "SUPPRESSED:INVALID_REQUEST_ID"
INVALID_PRODUCT_ID = "SUPPRESSED:INVALID_PRODUCT_ID"
PLATFORM_WORKLOAD = "SUPPRESSED:PLATFORM_WORKLOAD"
# RT14-02: the platform's own pseudo-workload ids (the Control Center's authz.PLATFORM_PSEUDO_WORKLOADS; every copy is
# pinned equal by tests/test_rt14_intake_trust.py).
PLATFORM_PSEUDO_WORKLOADS = frozenset({"project-castor", "castor", "platform"})


class IntakeRejected(Exception):
    def __init__(self, status_code: int, status: str, detail: str):
        super().__init__(f"{status}: {detail}")
        self.status_code, self.status, self.detail = status_code, status, detail

    def body(self) -> Dict[str, Any]:
        return {"status": self.status, "detail": self.detail}


def _non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


SHA256_HEX_DIGITS = frozenset("0123456789abcdef")


def is_sha256_hex(value: Any) -> bool:
    """Exactly 64 lowercase hex characters (a sha256 hexdigest); exact length + character-set check."""
    return isinstance(value, str) and len(value) == 64 and all(ch in SHA256_HEX_DIGITS for ch in value)


def _check_access(payload: Mapping[str, Any]) -> None:
    """L19-11 (RT F9): no intake event carries an access record. `source_channel` is plain payload data that any
    publisher can set, and the only authoritative record is `workloads/{pid}.access` (written by the CC create form or
    the admin PATCH, read by the developer). An `access` field is refused on every channel, never ignored."""
    if "access" in payload:
        raise IntakeRejected(422, "SUPPRESSED:INVALID_ACCESS_POLICY",
                             "intake events never carry an access record; the developer reads only "
                             "workloads/{pid}.access (set it in the Control Center)")


def run_request_id(payload: Mapping[str, Any]) -> Optional[str]:
    """The feature request this event's run builds, None when the event names none (every channel but the CC create
    form and promotion)."""
    value = payload.get("request_id")
    return value if _non_empty_str(value) else None


def check_request_id_format(request_id: str) -> None:
    """A `/` would make the id a path into another collection, so it is refused before any read."""
    if "/" in request_id:
        raise IntakeRejected(422, INVALID_REQUEST_ID, f"request_id {request_id!r} is not a single document id")


def check_request_id_owner(payload: Mapping[str, Any], request_id: str, record: Optional[Mapping[str, Any]]) -> None:
    """`record` is `feature_requests/{request_id}`, None when it does not exist. The run's end writes to that document,
    so it must be a request of this event's workload."""
    if record is None:
        raise IntakeRejected(422, INVALID_REQUEST_ID, f"feature request {request_id!r} does not exist")
    owner = record.get("product_id")
    if not _non_empty_str(owner) or owner != payload.get("product_id"):
        raise IntakeRejected(422, INVALID_REQUEST_ID,
                             f"feature request {request_id!r} does not belong to product {payload.get('product_id')!r}")


def validate_intake(payload: Any) -> Dict[str, Any]:
    """Returns the payload to dispatch (autonomous channels: `require_plan_approval` forced True). Raises
    IntakeRejected(422, ...) for an unknown channel or an incomplete autonomous event. The input is not mutated."""
    if not isinstance(payload, dict):
        raise IntakeRejected(422, "SUPPRESSED:INVALID_EVENT", "intake message is not a JSON object")
    try:
        parse_profile(payload.get("compliance_profile"))
    except InvalidComplianceProfile as e:
        raise IntakeRejected(422, "SUPPRESSED:INVALID_COMPLIANCE_PROFILE", str(e)) from e
    _check_access(payload)
    channel = payload.get("source_channel")
    if channel is None:
        out = dict(payload)  # Google Docs path, unchanged
    elif not isinstance(channel, str) or channel not in SOURCE_CHANNELS:
        raise IntakeRejected(422, "SUPPRESSED:UNKNOWN_SOURCE_CHANNEL",
                             f"source_channel {channel!r} is not an accepted intake channel")
    elif channel not in AUTONOMOUS_CHANNELS:
        out = dict(payload)
    else:
        out = _validate_autonomous(channel, payload)
    _check_product_id(out, autonomous=channel in AUTONOMOUS_CHANNELS)
    return out


def _validate_autonomous(channel: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    rules = AUTONOMOUS_CHANNELS[channel]
    for field in ("product_id", rules["id_field"], "trace_id") + ((rules["extra_field"],) if "extra_field" in rules
                                                                  else ()):
        if not _non_empty_str(payload.get(field)):
            raise IntakeRejected(422, rules["invalid"], f"{channel} event needs {field}")
    if rules.get("extra_field") == "findings_digest" and not is_sha256_hex(payload.get("findings_digest")):
        # RT residual R1: the digest keys the dedupe claim document id; only the scanner's sha256 hex is accepted.
        raise IntakeRejected(422, rules["invalid"], f"{channel} event needs findings_digest as 64 lowercase hex")
    if payload.get("execution_mode") != AUTONOMOUS_EXECUTION_MODE:
        raise IntakeRejected(422, rules["invalid"],
                             f"{channel} event needs execution_mode {AUTONOMOUS_EXECUTION_MODE!r}, got "
                             f"{payload.get('execution_mode')!r}")
    out = dict(payload)
    out["require_plan_approval"] = True
    return out


def _check_product_id(payload: Mapping[str, Any], *, autonomous: bool) -> None:
    """RT14-37: every event names exactly one valid workload id. RT14-02: a non-autonomous event never names a platform
    pseudo-workload id (an autonomous event acts only on a ledger workload that is not the platform: the caller's
    ledger re-check, unchanged)."""
    product_id = payload.get("product_id")
    try:
        validate_product_id(product_id)
    except UnsafePathError:
        raise IntakeRejected(422, INVALID_PRODUCT_ID,
                             f"product_id {product_id!r} is not an RFC 1123 label (1-63 lowercase letters, digits and "
                             f"hyphens)") from None
    if not autonomous and product_id in PLATFORM_PSEUDO_WORKLOADS:
        raise IntakeRejected(422, PLATFORM_WORKLOAD, f"product_id {product_id!r} is the platform itself")


def platform_workload_refusal(product_id: str, workload: Optional[Mapping[str, Any]],
                              host_project_id: Optional[str]) -> Optional[IntakeRejected]:
    """RT14-02: the refusal for an event whose workload record is the platform (`is_castor: true`, or its `project_id`
    is the host project), else None. No record (a new workload) -> None."""
    if not isinstance(workload, Mapping):
        return None
    host = (host_project_id or "").strip()
    if workload.get("is_castor") is True or (host and workload.get("project_id") == host):
        return IntakeRejected(422, PLATFORM_WORKLOAD,
                              f"workloads/{product_id} is the platform workload; intake never builds the platform")
    return None


def autonomous_ledger_refusal(channel: Optional[str], workload: Optional[Mapping[str, Any]]) -> Optional[str]:
    """For an autonomous channel: a SUPPRESSED:<reason> when the workload must not get an automatic run, else None.
    The toggles use the Control Center's defaults: absent counts as enabled (what the CC shows); an explicit
    non-True value disables (same rule as the sentinel, row L14-k amendment 4)."""
    rules = AUTONOMOUS_CHANNELS.get(channel or "")
    if rules is None:
        return None
    if workload is None:
        return "SUPPRESSED:LEDGER_MISSING"
    if workload.get("is_castor") is True:
        return "SUPPRESSED:PLATFORM_WORKLOAD"
    if workload.get("status") != ACTIVE_STATUS:
        return "SUPPRESSED:NOT_ACTIVE"
    if workload.get("code_freeze") is True:
        return "SUPPRESSED:CODE_FREEZE"
    toggle = rules["toggle"]
    if toggle in workload and workload.get(toggle) is not True:
        return f"SUPPRESSED:{toggle.upper()}_OFF"
    return None

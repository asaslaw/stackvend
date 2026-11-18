"""
StackVend spec intake: typed outcomes for FD-4AS (authorized submitters, managed target folders).

Kept in its own module so the service entrypoint (main.py) and the poller share the exact codes and error types
without importing each other. Every rejected document or folder gets one of these codes in the poll result, the
`spec_ingestions/{doc_id}` audit record (documents) and a WARNING log line naming the id (never document content).
"""

from typing import List

# The document's Drive owner is not an active Control Center user allowed to submit specs.
SPEC_SUBMITTER_UNAUTHORIZED = "SPEC_SUBMITTER_UNAUTHORIZED"
# A target-folder candidate (title / description tag, `target_folder` property, owner assignment, the
# MANAGED_WORKLOADS_FOLDER_ID fallback) is not an active managed folder; the document is skipped, never re-routed.
TARGET_FOLDER_NOT_MANAGED = "TARGET_FOLDER_NOT_MANAGED"
# An auto-discovered or request-supplied inbox folder is not owned by an authorized submitter; it is not polled.
INBOX_FOLDER_UNAUTHORIZED = "INBOX_FOLDER_UNAUTHORIZED"
# A request-supplied in-progress folder (not the configured IN_PROGRESS_FOLDER_ID) is not owned by an authorized
# submitter: the pair is not polled, so no document is moved into it (Fable RT F1: a My Drive file inherits the
# sharing of the folder it is moved into).
IN_PROGRESS_FOLDER_UNAUTHORIZED = "IN_PROGRESS_FOLDER_UNAUTHORIZED"
# The authorization store (Firestore) or the Drive metadata needed for a decision could not be read: the whole
# pass is skipped (fail closed), nothing is moved or published, the documents stay in the inbox for the next poll.
SPEC_INTAKE_UNAVAILABLE = "SPEC_INTAKE_UNAVAILABLE"
# Pre-existing outcomes, now reported instead of swallowed.
SPEC_MOVE_FAILED = "SPEC_MOVE_FAILED"
INBOX_POLL_FAILED = "INBOX_POLL_FAILED"
# RT14-37: the product id derived from the document title is not an RFC 1123 label (shared/path_safety
# validate_product_id); the document stays in the inbox (rename it). There is no "default-workload" fallback.
SPEC_PRODUCT_ID_INVALID = "SPEC_PRODUCT_ID_INVALID"
# RT14-02: the title names the platform itself (a platform pseudo-workload id, a record with is_castor, or a record
# whose project is the host project). Refused for every role: a spec never builds the platform.
SPEC_TARGET_PLATFORM_WORKLOAD = "SPEC_TARGET_PLATFORM_WORKLOAD"
# RT14-02: the title names an EXISTING workload the submitter is neither ADMIN on nor assigned to (the Control
# Center's verify_workload_access rule).
SPEC_WORKLOAD_NOT_ASSIGNED = "SPEC_WORKLOAD_NOT_ASSIGNED"
# RT14-26: the intake event could not be published after the Drive move; the document is moved back to the inbox (the
# skip records whether that worked) so the next poll tries again.
SPEC_PUBLISH_FAILED = "SPEC_PUBLISH_FAILED"
# RT14 RT F4: another document of the same poll already requested this workload id; the later one stays in the inbox
# and is decided again on the next poll (by then a new workload exists, so the RT14-02 assignment check applies).
SPEC_WORKLOAD_ALREADY_REQUESTED = "SPEC_WORKLOAD_ALREADY_REQUESTED"


class IntakeUnavailableError(RuntimeError):
    """SPEC_INTAKE_UNAVAILABLE: a decision input could not be read. Callers must not move or publish anything."""

    code = SPEC_INTAKE_UNAVAILABLE


# RT14 RT F2: a single-document intake failed for a reason that is neither a refusal nor the publish (a bug or an
# unexpected client error before anything was published). Answered 500 with the error's class, never as a publish error.
SPEC_INGEST_FAILED = "SPEC_INGEST_FAILED"


class IntakePublishError(RuntimeError):
    """SPEC_PUBLISH_FAILED (RT14 RT F2): the intake event of an accepted document was not published. ``cause_class``
    is the publish error's class name (no message: it may carry request details)."""

    code = SPEC_PUBLISH_FAILED

    def __init__(self, cause_class: str):
        super().__init__(f"{SPEC_PUBLISH_FAILED}: the intake event was not published ({cause_class})")
        self.cause_class = cause_class


class IntakeRejected(Exception):
    """One document (or folder) is skipped with a typed code and a short reason (no document content)."""

    def __init__(self, code: str, reason: str):
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


class IntakeList(list):
    """A plain list of results (ingested payloads, or folder pairs) that also carries the typed skips of the same
    pass on `.skipped`, so existing callers that treat the result as a list keep working unchanged."""

    def __init__(self, items=(), skipped=None):
        super().__init__(items)
        self.skipped: List[dict] = list(skipped or [])

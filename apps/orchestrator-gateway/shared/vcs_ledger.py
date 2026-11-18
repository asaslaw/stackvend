"""
StackVend PR ledger (FD-4P / FD-4BB).

One Firestore document per branch / pull request StackVend created, written right after creation from the
provider's API response. Every later merge, close or branch delete is allowed only for a ledger entry, and only
while the live object still matches the entry exactly (the provider re-checks it: see
GitHubProvider._verify_identity). Nothing here guesses: identity is compared with `==` on structured fields; there
is no substring, prefix, label or body-text matching and no default PR number.

Collection `vcs_ledger`; document id = sha256("<provider>\\n<repo key>\\n<branch>"), so the release step and the
Control Center find the entry for (provider, repository, branch) with one read, no query.

Trust note (lane 16 plan RT H3): Firestore is the identity boundary, not the security boundary. Every agent SA can
write this collection today (FD-4T tracks per-service SAs). The provider-side live checks (same repo, no forks,
pinned head SHA) are what an outsider cannot satisfy.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .vcs_provider import PRIdentity

COLLECTION = "vcs_ledger"
SCHEMA_VERSION = 1

PROVIDER_GITHUB = "GITHUB"
PROVIDER_SERVERLESS_GIT = "SERVERLESS_GIT"
PROVIDERS = frozenset({PROVIDER_GITHUB, PROVIDER_SERVERLESS_GIT})

ORIGIN_DEVELOPER = "DEVELOPER"          # gateway developer stage (the only origin reconcile may supersede)
ORIGIN_IAC_UPGRADE = "IAC_UPGRADE"      # gateway IAC_UPGRADE change_type
ORIGIN_IAC_UPGRADE_CC = "IAC_UPGRADE_CC"  # Control Center "upgrade IaC modules" button
ORIGINS = frozenset({ORIGIN_DEVELOPER, ORIGIN_IAC_UPGRADE, ORIGIN_IAC_UPGRADE_CC})

STATE_OPEN = "OPEN"
STATE_MERGED = "MERGED"
STATE_MERGE_FAILED = "MERGE_FAILED"
STATE_SUPERSEDED = "SUPERSEDED"
STATE_DIVERGED = "DIVERGED"
STATES = frozenset({STATE_OPEN, STATE_MERGED, STATE_MERGE_FAILED, STATE_SUPERSEDED, STATE_DIVERGED})
MERGEABLE_STATES = frozenset({STATE_OPEN, STATE_MERGE_FAILED})

# GHA-PLATFORM-MERGE-SKIP-ACTIONS (owner 11-16): GitHub's documented "skip workflow runs" directive. A push whose
# head commit message contains it starts no `push` / `pull_request` workflow runs. Every platform-made merge of a
# ledger PR into a GitHub workload branch (gateway release auto-merge, Control Center approval merge) is followed by
# the platform's own build and apply, so it must not also start the repo's Actions Day-2 deploy (which raced the
# first apply's WIF pool -> invalid_target, and would race the apply on a re-run). StackVend writes this fixed text;
# GitHub interprets it; nothing in StackVend reads or parses commit messages.
PLATFORM_MERGE_SKIP_ACTIONS = "[skip actions]"


class LedgerError(RuntimeError):
    """Base class. `reason` is a stable machine-readable code."""

    reason = "LEDGER_ERROR"

    def __init__(self, message: str, *, reason: Optional[str] = None):
        super().__init__(message)
        if reason:
            self.reason = reason


class LedgerNotFound(LedgerError):
    reason = "NO_LEDGER_ENTRY"


class LedgerMismatch(LedgerError):
    """An entry exists but does not belong to this request (other product, trace, repository, provider or state)."""

    reason = "LEDGER_MISMATCH"


class LedgerUnavailable(LedgerError):
    reason = "LEDGER_UNAVAILABLE"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_int_id(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_clean_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def repo_key(repo_full_name: str) -> str:
    """Canonical repository key: GitHub owner/repo names are case-insensitive, so compare casefolded."""
    if not _is_clean_str(repo_full_name):
        raise LedgerMismatch(f"invalid repository name {repo_full_name!r}", reason="REPO_INVALID")
    return repo_full_name.casefold()


def ledger_id(provider: str, repo_full_name: str, branch: str) -> str:
    if provider not in PROVIDERS:
        raise LedgerMismatch(f"unknown provider {provider!r}", reason="VCS_PROVIDER_UNKNOWN")
    if not _is_clean_str(branch):
        raise LedgerMismatch(f"invalid branch {branch!r}", reason="BRANCH_INVALID")
    raw = f"{provider}\n{repo_key(repo_full_name)}\n{branch}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def creation_problems(
    provider: str,
    *,
    repo_full_name: Any,
    branch: str,
    base_branch: Any,
    commit_sha: Any,
    pull_request: Any,
) -> List[str]:
    """FD-4BB: reasons NOT to record what the provider just created. For GitHub, `pull_request` is the
    create_pull_request() response: its base repository must be the workload repository, its head repository the
    same repository (numeric id and name: no fork), its head ref the pushed branch, its base ref the intended base,
    and its head SHA the pushed commit. Empty list = record it."""
    if not _is_clean_str(commit_sha):
        return ["the commit returned no SHA"]
    if not _is_clean_str(base_branch):
        return [f"invalid base branch {base_branch!r}"]
    if provider != PROVIDER_GITHUB:
        return []
    pr = pull_request
    if not isinstance(pr, dict):
        return ["no pull request was created"]
    problems = []
    base_name, head_name = pr.get("base_repo_full_name"), pr.get("head_repo_full_name")
    if not (_is_clean_str(repo_full_name) and _is_clean_str(base_name) and base_name.casefold() == repo_full_name.casefold()):
        problems.append(f"PR base repository {base_name!r} is not {repo_full_name!r}")
    if not (_is_clean_str(head_name) and _is_clean_str(base_name) and head_name.casefold() == base_name.casefold()):
        problems.append(f"PR head repository {head_name!r} is not {base_name!r} (fork)")
    base_id, head_id = pr.get("base_repo_id"), pr.get("head_repo_id")
    if not (_is_int_id(base_id) and _is_int_id(head_id) and base_id == head_id):
        problems.append(f"PR head repository id {head_id!r} is not the base repository id {base_id!r} (fork)")
    if pr.get("head_ref") != branch:
        problems.append(f"PR head ref {pr.get('head_ref')!r} is not {branch!r}")
    if pr.get("base_ref") != base_branch:
        problems.append(f"PR base ref {pr.get('base_ref')!r} is not {base_branch!r}")
    if pr.get("head_sha") != commit_sha:
        problems.append(f"PR head {pr.get('head_sha')!r} is not the pushed commit {commit_sha!r}")
    if not _is_int_id(pr.get("pr_number")):
        problems.append(f"PR number {pr.get('pr_number')!r} is not a positive integer")
    return problems


def record_created(
    db: Any,
    *,
    provider: str,
    repo_full_name: str,
    repo_id: Optional[int],
    product_id: str,
    trace_id: Optional[str],
    origin: str,
    branch: str,
    base_branch: str,
    head_sha: str,
    pr_number: Optional[int],
    pr_url: Optional[str],
) -> str:
    """Writes the entry with DocumentReference.create() (fails if it already exists). Returns the ledger id.
    GitHub entries need an integer PR number and repository id; Serverless Git entries have neither."""
    if db is None:
        raise LedgerUnavailable("PR ledger store unavailable")
    if origin not in ORIGINS:
        raise LedgerMismatch(f"unknown origin {origin!r}", reason="ORIGIN_UNKNOWN")
    for name, value in (("product_id", product_id), ("base_branch", base_branch), ("head_sha", head_sha)):
        if not _is_clean_str(value):
            raise LedgerMismatch(f"invalid {name} {value!r}", reason=f"{name.upper()}_INVALID")
    if branch == base_branch:
        raise LedgerMismatch("branch equals its base branch", reason="BRANCH_IS_BASE")
    if provider == PROVIDER_GITHUB:
        if not _is_int_id(pr_number):
            raise LedgerMismatch(f"GitHub entry needs an integer PR number, got {pr_number!r}", reason="PR_NUMBER_INVALID")
        if not _is_int_id(repo_id):
            raise LedgerMismatch(f"GitHub entry needs an integer repository id, got {repo_id!r}", reason="REPO_ID_INVALID")
    elif pr_number is not None or repo_id is not None:
        raise LedgerMismatch("Serverless Git entries carry no PR number or repository id", reason="PR_NUMBER_INVALID")
    lid = ledger_id(provider, repo_full_name, branch)
    now = _now()
    data = {
        "schema_version": SCHEMA_VERSION,
        "ledger_id": lid,
        "provider": provider,
        "repo_full_name": repo_full_name,
        "repo_key": repo_key(repo_full_name),
        "repo_id": repo_id,
        "product_id": product_id,
        "trace_id": trace_id,
        "origin": origin,
        "branch": branch,
        "base_branch": base_branch,
        "head_sha": head_sha,
        "pr_number": pr_number,
        "pr_url": pr_url,
        "state": STATE_OPEN,
        "state_reason": None,
        "created_at": now,
        "updated_at": now,
    }
    try:
        db.collection(COLLECTION).document(lid).create(data)
    except Exception as e:  # noqa: BLE001 - AlreadyExists or an outage: either way nothing is recorded
        raise LedgerUnavailable(f"PR ledger write failed for {branch!r}: {type(e).__name__}: {e}") from e
    return lid


def get_entry(db: Any, lid: str) -> Dict[str, Any]:
    if db is None:
        raise LedgerUnavailable("PR ledger store unavailable")
    if not _is_clean_str(lid):
        raise LedgerNotFound(f"invalid ledger id {lid!r}")
    try:
        snap = db.collection(COLLECTION).document(lid).get()
        data = (snap.to_dict() or {}) if snap.exists else None
    except Exception as e:  # noqa: BLE001
        raise LedgerUnavailable(f"PR ledger unreadable: {type(e).__name__}: {e}") from e
    if not data:
        raise LedgerNotFound(f"no PR ledger entry {lid}")
    if data.get("ledger_id") != lid:
        raise LedgerMismatch(f"ledger entry {lid} is malformed", reason="LEDGER_MALFORMED")
    return data


def require_entry(
    db: Any,
    *,
    provider: str,
    repo_full_name: str,
    branch: str,
    product_id: str,
    trace_id: Optional[str] = None,
    mergeable: bool = True,
) -> Dict[str, Any]:
    """The entry StackVend created for exactly (provider, repository, branch), checked field by field against the
    caller's product (and trace, when given). `mergeable` additionally requires state OPEN or MERGE_FAILED."""
    entry = get_entry(db, ledger_id(provider, repo_full_name, branch))
    check_entry(entry, provider=provider, repo_full_name=repo_full_name, branch=branch, product_id=product_id,
                trace_id=trace_id, mergeable=mergeable)
    return entry


def check_entry(
    entry: Dict[str, Any],
    *,
    provider: str,
    repo_full_name: str,
    branch: str,
    product_id: str,
    trace_id: Optional[str] = None,
    mergeable: bool = True,
) -> None:
    if entry.get("provider") != provider:
        raise LedgerMismatch(f"ledger provider {entry.get('provider')!r} != {provider!r}", reason="VCS_PROVIDER_MISMATCH")
    if entry.get("repo_key") != repo_key(repo_full_name):
        raise LedgerMismatch(f"ledger repository {entry.get('repo_full_name')!r} != {repo_full_name!r}", reason="REPO_MISMATCH")
    if entry.get("branch") != branch:
        raise LedgerMismatch(f"ledger branch {entry.get('branch')!r} != {branch!r}", reason="BRANCH_MISMATCH")
    if entry.get("product_id") != product_id:
        raise LedgerMismatch(f"ledger product {entry.get('product_id')!r} != {product_id!r}", reason="PRODUCT_MISMATCH")
    if trace_id is not None and entry.get("trace_id") != trace_id:
        raise LedgerMismatch(f"ledger trace {entry.get('trace_id')!r} != {trace_id!r}", reason="TRACE_MISMATCH")
    if mergeable and entry.get("state") not in MERGEABLE_STATES:
        raise LedgerMismatch(f"ledger entry state {entry.get('state')!r} is not mergeable", reason="LEDGER_STATE")


def entries_for_product(db: Any, product_id: str) -> List[Dict[str, Any]]:
    """Every ledger entry of exactly this product (equality query + exact in-memory re-check)."""
    if db is None:
        raise LedgerUnavailable("PR ledger store unavailable")
    try:
        snaps = list(db.collection(COLLECTION).where("product_id", "==", product_id).stream())
    except Exception as e:  # noqa: BLE001
        raise LedgerUnavailable(f"PR ledger unreadable: {type(e).__name__}: {e}") from e
    out = []
    for snap in snaps:
        data = snap.to_dict() or {}
        if data.get("product_id") == product_id and _is_clean_str(data.get("ledger_id")):
            out.append(data)
    return out


def supersedable(
    entries: List[Dict[str, Any]],
    *,
    provider: str,
    repo_full_name: str,
    keep_branch: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Open DEVELOPER-origin entries in exactly this provider + repository, except `keep_branch`."""
    key = repo_key(repo_full_name)
    return [e for e in entries
            if e.get("origin") == ORIGIN_DEVELOPER and e.get("state") == STATE_OPEN and e.get("provider") == provider
            and e.get("repo_key") == key and e.get("branch") != keep_branch]


def identity(entry: Dict[str, Any]) -> PRIdentity:
    return PRIdentity(
        provider=entry.get("provider"),
        repo_full_name=entry.get("repo_full_name"),
        branch=entry.get("branch"),
        base_branch=entry.get("base_branch"),
        head_sha=entry.get("head_sha"),
        pr_number=entry.get("pr_number"),
        repo_id=entry.get("repo_id"),
    )


def github_platform_merge_message(commit_message: str) -> str:
    """GHA-PLATFORM-MERGE-SKIP-ACTIONS: the commit message for a platform-made GitHub merge of a ledger PR. The
    provider squash-merges with `commit_message` only, so GitHub writes the PR title "(#n)" as the commit title and
    this text as the commit body; the directive is therefore in the merge commit's message (the head commit of the
    push to the base branch). GitHub only: Serverless Git merges keep their message unchanged (no Actions there)."""
    if not isinstance(commit_message, str) or not commit_message:
        raise ValueError("a platform merge needs a non-empty commit message")
    return f"{commit_message}\n\n{PLATFORM_MERGE_SKIP_ACTIONS}"


def mark(db: Any, lid: str, state: str, *, reason: Optional[str] = None, **fields: Any) -> None:
    """Records a state the caller has already observed (e.g. GitHub reported the merge). Raises LedgerUnavailable."""
    if state not in STATES:
        raise LedgerMismatch(f"unknown ledger state {state!r}", reason="LEDGER_STATE")
    if db is None:
        raise LedgerUnavailable("PR ledger store unavailable")
    data = {"state": state, "state_reason": reason, "updated_at": _now(), **fields}
    try:
        db.collection(COLLECTION).document(lid).set(data, merge=True)
    except Exception as e:  # noqa: BLE001
        raise LedgerUnavailable(f"PR ledger update failed: {type(e).__name__}: {e}") from e

"""
Project Castor: Serverless Git Microservice (`apps/git-server`)
Stateless Cloud Run Gen2 microservice backed by Cloud Storage FUSE.
Provides Git Smart HTTP clone (`git-upload-pack`) and an internal REST API for autonomous agents.

FD-4K: every route except /health and /healthz requires a verified Google ID token from an allow-listed
service account (see git_server_auth.py). Repository ids are anchored RFC 1123 labels and branch names follow
git's ref-format rules. Smart-HTTP push is refused unless GIT_SERVER_ALLOW_SMART_HTTP_PUSH=true.
FD-4V: merges are fast-forward-only (409 when the target advanced) with compare-and-swap ref updates.
SERVERLESS-AUTOMERGE-SHA: a merge may name `expected_source_sha`; the source branch is then merged only when its
head is exactly that commit (409 SOURCE_MOVED otherwise, nothing written). GET /api/v1/capabilities advertises it.
Dulwich is the single implementation for the REST API; the git CLI is used only by `git http-backend`.
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import io
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Literal, Optional, Tuple

# FD-12: author e-mail of platform-made commits (same setting as shared/vcs_provider.py). The default is a
# non-routable RFC 2606 `.invalid` address, so no third party can own it.
AGENT_AUTHOR_EMAIL = os.getenv("STACKVEND_GIT_AUTHOR_EMAIL") or "stackvend-agent@noreply.invalid"

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.routing import Match

# FD-4G/FD-4K: no ImportError fallbacks -- a missing guard or engine must crash at boot, never fail open.
from shared.path_safety import (
    GIT_RESERVED,
    UnsafePathError,
    safe_join,
    validate_manifest_keys,
    validate_product_id,
)
from dulwich.graph import can_fast_forward
from dulwich.objects import Blob, Commit, Tree
from dulwich.refs import check_ref_format
from dulwich.repo import Repo

from git_server_auth import PUBLIC_PATHS, AuthError, GoogleIdTokenAuthenticator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("castor-git-server")

GIT_DATA_DIR = os.getenv("GIT_DATA_DIR", "/data/git")
PUBSUB_TOPIC = os.getenv("PUBSUB_TOPIC", "workload-git-events")
PLATFORM_PROJECT = os.getenv("PLATFORM_PROJECT", os.getenv("PROJECT_ID", ""))
GIT_BIN = shutil.which("git") or "/usr/bin/git"

# Replaced in tests with an authenticator whose network collaborators are injected.
authenticator = GoogleIdTokenAuthenticator()


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    try:
        await run_in_threadpool(authenticator.config)  # logs the effective allow-list and audiences once
    except AuthError as cfg_err:
        logger.error(f"FD-4K: auth configuration not available at startup ({cfg_err.detail}); requests get 503")
    yield


app = FastAPI(
    title="StackVend Serverless Git Microservice",
    description="Zero-database, Cloud Storage FUSE backed Git engine for StackVend",
    version="1.2.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=_lifespan,
)


def _is_read_route(scope) -> bool:
    """FD-7L Phase 4: True only when the request dispatches to an endpoint in READ_ONLY_ENDPOINTS. The route is
    resolved by Starlette's own matcher exactly as the router dispatches (the first FULL match = path AND method);
    no path text is inspected here."""
    for route in app.router.routes:
        match, _child = route.matches(scope)
        if match == Match.FULL:
            return getattr(route, "endpoint", None) in READ_ONLY_ENDPOINTS
    return False


@app.middleware("http")
async def _require_google_identity(request: Request, call_next):
    """FD-4K default-deny: every path except the exact public health paths needs a verified caller.
    FD-7L Phase 4: a GIT_SERVER_READONLY_INVOKERS caller is admitted on the read routes only (403 elsewhere)."""
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    try:
        if _is_read_route(request.scope):
            caller = await run_in_threadpool(authenticator.authenticate, request.headers.getlist("authorization"),
                                             read_route=True)
        else:
            caller = await run_in_threadpool(authenticator.authenticate, request.headers.getlist("authorization"))
    except AuthError as auth_err:
        headers = {"WWW-Authenticate": "Bearer"} if auth_err.status == 401 else None
        return JSONResponse(status_code=auth_err.status, content={"detail": auth_err.detail}, headers=headers)
    request.state.caller = caller
    return await call_next(request)


# Row GIT-404-TYPED (internal-ingress plan §6.3): every answer of this server carries this fixed header, its own 404s
# included, so a client can tell "the git server says not found" from a 404 that Cloud Run's front end gives a caller
# the ingress setting refuses. Exact protocol contract = shared/providers/serverless_git_provider.GIT_SERVER_HEADER.
# Registered after _require_google_identity, so it is the outer middleware and also marks the 401/403 answers.
GIT_SERVER_HEADER = "X-StackVend-Git-Server"
GIT_SERVER_HEADER_VALUE = "1"


@app.middleware("http")
async def _mark_git_server_answer(request: Request, call_next):
    response = await call_next(request)
    response.headers[GIT_SERVER_HEADER] = GIT_SERVER_HEADER_VALUE
    return response


@app.exception_handler(UnsafePathError)
async def _unsafe_path_handler(request: Request, exc: UnsafePathError):
    # FD-4G/FD-4K: a repo id, branch name or path failed structural validation.
    logger.warning(f"Rejected unsafe input on {request.url.path}: {exc.value!r} ({exc.reason})")
    return JSONResponse(status_code=400, content={"detail": f"unsafe path: {exc.reason}"})


# Auto-create data directory if not already present
try:
    os.makedirs(GIT_DATA_DIR, exist_ok=True)
except Exception:
    pass


# ==============================================================================
# Identifier validation (FD-4K)
# ==============================================================================

def validate_branch(name: Any) -> str:
    """Branch name per git check-ref-format (dulwich implementation), plus: ASCII printable, no leading '-',
    not 'HEAD' / '@'. Returns the name unchanged or raises UnsafePathError."""
    if not isinstance(name, str) or not name or not name.isascii() or not name.isprintable():
        raise UnsafePathError(name, "invalid branch name")
    if name.startswith("-") or name in ("HEAD", "@"):
        raise UnsafePathError(name, "invalid branch name")
    if not check_ref_format(b"refs/heads/" + name.encode("ascii")):
        raise UnsafePathError(name, "invalid branch name")
    return name


def get_repo_path(product_id: str) -> str:
    """Bare repository path on the FUSE volume for an anchored product id (RFC 1123 label).

    FD-4K: no '.git' stripping (FD26-21 collisions); every route validates the full id. Raises UnsafePathError.
    """
    validate_product_id(product_id)
    return safe_join(GIT_DATA_DIR, f"{product_id}.git")


def _require_repo(repo_path: str) -> None:
    if not os.path.isdir(repo_path) or not os.path.isfile(os.path.join(repo_path, "HEAD")):
        raise HTTPException(status_code=404, detail="Repository not found.")


# Concurrency locking per repo (per instance; ref updates for merges are also compare-and-swap).
_repo_locks: Dict[str, threading.Lock] = {}
_global_lock = threading.Lock()


def get_repo_lock(product_id: str) -> threading.Lock:
    """Lock keyed by the canonical, validated product id."""
    validate_product_id(product_id)
    with _global_lock:
        if product_id not in _repo_locks:
            _repo_locks[product_id] = threading.Lock()
        return _repo_locks[product_id]


# ==============================================================================
# Dulwich engine
# ==============================================================================

def init_bare_repo_dulwich(repo_path: str, product_id: str, description: str, initial_branch: str) -> str:
    repo = Repo.init_bare(repo_path)
    readme_text = f"# {product_id}\n\n{description or 'Vended workload managed by StackVend.'}\n"
    b_readme = Blob.from_string(readme_text.encode("utf-8"))
    repo.object_store.add_object(b_readme)

    b_gitignore = Blob.from_string(b"__pycache__/\n*.pyc\n.env\n.terraform/\n*.tfstate*\nnode_modules/\n")
    repo.object_store.add_object(b_gitignore)

    tree = Tree()
    tree.add(b"README.md", 0o100644, b_readme.id)
    tree.add(b".gitignore", 0o100644, b_gitignore.id)
    repo.object_store.add_object(tree)

    now = int(time.time())
    commit = Commit()
    commit.tree = tree.id
    commit.parents = []
    author = f"StackVend <{AGENT_AUTHOR_EMAIL}>".encode("utf-8")
    commit.author = author
    commit.committer = author
    commit.author_time = now
    commit.commit_time = now
    commit.author_timezone = 0
    commit.commit_timezone = 0
    commit.message = b"chore: initial repository structure\n"
    repo.object_store.add_object(commit)

    branch_ref = f"refs/heads/{initial_branch}".encode("utf-8")
    repo.refs[branch_ref] = commit.id
    repo.refs.set_symbolic_ref(b"HEAD", branch_ref)
    return commit.id.decode("ascii")


def get_metadata_dulwich(repo_path: str) -> tuple[str, List[str]]:
    repo = Repo(repo_path)
    default_branch = "main"
    try:
        head_target = repo.refs.read_ref(b"HEAD")
        if head_target and head_target.startswith(b"ref: refs/heads/"):
            default_branch = head_target.replace(b"ref: refs/heads/", b"").decode("utf-8")
    except Exception:
        pass
    branches = [
        ref.replace(b"refs/heads/", b"").decode("utf-8")
        for ref in repo.refs.keys()
        if ref.startswith(b"refs/heads/")
    ]
    return default_branch, (branches or [default_branch])


def create_branch_dulwich(repo_path: str, branch_name: str, source_branch: str) -> tuple[str, str]:
    repo = Repo(repo_path)
    target_ref = f"refs/heads/{branch_name}".encode("utf-8")
    if target_ref in repo.refs:
        existing_sha = repo.refs[target_ref].decode("ascii") if isinstance(repo.refs[target_ref], bytes) else str(repo.refs[target_ref])
        return "EXISTS", existing_sha

    src_ref = f"refs/heads/{source_branch}".encode("utf-8")
    if src_ref not in repo.refs:
        try:
            head_target = repo.refs.read_ref(b"HEAD")
            if head_target and head_target.startswith(b"ref: "):
                src_ref = head_target.replace(b"ref: ", b"").strip()
        except Exception:
            pass

    if src_ref not in repo.refs:
        raise ValueError(f"Source branch '{source_branch}' does not exist.")

    src_sha = repo.refs[src_ref]
    repo.refs[target_ref] = src_sha
    sha_str = src_sha.decode("ascii") if isinstance(src_sha, bytes) else str(src_sha)
    return "CREATED", sha_str


def _tree_priority_key(file_name: str) -> tuple:
    # Tier 0: Infrastructure, root configs, entrypoints, and contracts
    if (
        file_name.startswith("infra/")
        or file_name.endswith(".tf")
        or file_name in ("Procfile", "Dockerfile", "requirements.txt", "main.py", "app.py")
        or "/" not in file_name
    ):
        return (0, file_name)
    return (1, file_name)


def fetch_tree_dulwich(repo_path: str, branch: str, max_files: int = 2500) -> Optional[Dict[str, str]]:
    """Text files of exactly the commit refs/heads/{branch} points at; None when the branch is missing.

    Register row 40: no fallback to HEAD or another branch (a missing branch is a 404, never the default branch's
    code). The ref is resolved once (resolve_branch_head_dulwich), so the files all come from one commit.
    """
    result = fetch_tree_with_status_dulwich(repo_path, branch, max_files=max_files)
    return None if result is None else result[0]


def fetch_tree_with_status_dulwich(repo_path: str, branch: str,
                                   max_files: int = 2500) -> Optional[Tuple[Dict[str, str], bool]]:
    """(files, truncated) for exactly refs/heads/{branch}; None when the branch is missing.

    FD-4DC: `truncated` is True exactly when the branch has more text files than `max_files` (the same rule as
    GitHubProvider.fetch_file_tree), so a client can tell a tree of exactly `max_files` files from a cut one.
    The files are the same dict, in the same order, as before.
    """
    repo = Repo(repo_path)
    sha = resolve_branch_head_dulwich(repo, branch)
    if sha is None:
        return None

    commit = repo[sha]
    files: Dict[str, str] = {}
    binary_extensions = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".tar.gz", ".pyc"}

    raw_entries = []
    for entry in repo.object_store.iter_tree_contents(commit.tree):
        file_name = entry.path.decode("utf-8", errors="replace")
        _, ext = os.path.splitext(file_name)
        if ext.lower() in binary_extensions:
            continue
        raw_entries.append((file_name, entry.sha))

    raw_entries.sort(key=lambda item: _tree_priority_key(item[0]))

    for file_name, sha in raw_entries[:max_files]:
        obj = repo.get_object(sha)
        if isinstance(obj, Blob):
            try:
                files[file_name] = obj.data.decode("utf-8", errors="replace")
            except Exception:
                pass
    return files, len(raw_entries) > max_files


def read_blob_at_commit_dulwich(repo: Repo, commit_sha: bytes, file_path: str) -> Optional[str]:
    """UTF-8 text of `file_path` in the tree of `commit_sha` (already resolved from the exact branch), or None."""
    commit = repo[commit_sha]
    clean_target = file_path.lstrip("/").encode("utf-8")
    for entry in repo.object_store.iter_tree_contents(commit.tree):
        if entry.path == clean_target:
            obj = repo.get_object(entry.sha)
            if isinstance(obj, Blob):
                return obj.data.decode("utf-8", errors="replace")
    return None


def split_blob_ref_path_dulwich(repo: Repo, ref_path: str) -> Optional[Tuple[str, str, bytes]]:
    """Split `{branch}/{file_path}` from the blob route into (branch, file_path, branch head SHA).

    Branch names may contain '/' (pipeline branches are `castor/<id>-<suffix>`) and Starlette decodes `%2F` before
    routing, so the boundary cannot be read from the URL. It is decided by the repository's own refs: each leading
    run of path segments that is a valid branch name is resolved exactly (resolve_branch_head_dulwich, no HEAD
    fallback). git's ref namespace forbids a branch and a branch below it (`castor` and `castor/x`) from coexisting,
    so at most one prefix can exist; more than one (only possible with hand-edited packed-refs) fails closed.

    Returns None when no prefix is an existing branch. Raises UnsafePathError when no prefix is even a valid branch
    name (same 400 as before for `HEAD`, `-x`, ...).
    """
    parts = ref_path.split("/")
    valid = 0
    found: List[Tuple[str, str, bytes]] = []
    for i in range(1, len(parts)):
        branch = "/".join(parts[:i])
        try:
            validate_branch(branch)
        except UnsafePathError:
            continue
        valid += 1
        sha = resolve_branch_head_dulwich(repo, branch)
        if sha is not None:
            found.append((branch, "/".join(parts[i:]), sha))
    if not valid:
        raise UnsafePathError(parts[0], "invalid branch name")
    if len(found) > 1:
        raise RuntimeError(f"ambiguous branch prefix in blob path: {[f[0] for f in found]}")
    return found[0] if found else None


def commit_files_dulwich(
    repo_path: str,
    branch: str,
    files: Dict[str, str],
    message: str,
    author_name: str,
    author_email: str,
    files_to_delete: Optional[List[str]] = None,
    deleted_out: Optional[List[str]] = None,
) -> str:
    """One commit on `branch`: the parent tree, plus `files` written, minus `files_to_delete` (FD-4DC-e).

    A deletion removes exactly that file entry; a path the branch does not have is not an error (the end state is the
    same) and is not reported. `deleted_out`, when given, receives the paths that were removed."""
    repo = Repo(repo_path)
    branch_ref = f"refs/heads/{branch}".encode("utf-8")
    parent_sha = repo.refs[branch_ref] if branch_ref in repo.refs else None

    entries: Dict[bytes, tuple[int, bytes]] = {}
    if parent_sha:
        parent_commit = repo[parent_sha]
        for entry in repo.object_store.iter_tree_contents(parent_commit.tree):
            entries[entry.path] = (entry.mode, entry.sha)

    for dpath in files_to_delete or []:
        if entries.pop(dpath.lstrip("/").encode("utf-8"), None) is not None and deleted_out is not None:
            deleted_out.append(dpath)

    for fpath, content in files.items():
        clean_p = fpath.lstrip("/").encode("utf-8")
        c_bytes = content.encode("utf-8") if isinstance(content, str) else content
        blob = Blob.from_string(c_bytes)
        repo.object_store.add_object(blob)
        mode = 0o100755 if fpath.endswith((".sh", ".py")) else 0o100644
        entries[clean_p] = (mode, blob.id)

    def build_tree_dict(current_entries: Dict[bytes, tuple[int, bytes]]) -> bytes:
        t = Tree()
        subdirs: Dict[bytes, Dict[bytes, tuple[int, bytes]]] = {}
        for path_bytes, (mode, sha) in current_entries.items():
            parts = path_bytes.split(b"/", 1)
            if len(parts) == 1:
                t.add(parts[0], mode, sha)
            else:
                subdirs.setdefault(parts[0], {})[parts[1]] = (mode, sha)
        for dir_name, sub_paths in subdirs.items():
            sub_tree_sha = build_tree_dict(sub_paths)
            t.add(dir_name, 0o040000, sub_tree_sha)
        repo.object_store.add_object(t)
        return t.id

    root_tree_sha = build_tree_dict(entries)

    now = int(time.time())
    commit = Commit()
    commit.tree = root_tree_sha
    commit.parents = [parent_sha] if parent_sha else []
    author = f"{author_name} <{author_email}>".encode("utf-8")
    commit.author = author
    commit.committer = author
    commit.author_time = now
    commit.commit_time = now
    commit.author_timezone = 0
    commit.commit_timezone = 0
    commit.message = message.encode("utf-8")
    repo.object_store.add_object(commit)

    repo.refs[branch_ref] = commit.id
    return commit.id.decode("ascii")


class MergeConflict(Exception):
    """FD-4V: the merge would lose commits on the target (or the target moved during the merge)."""

    reason_code = "TARGET_ADVANCED"

    def __init__(self, reason: str, target_sha: str, source_sha: str):
        super().__init__(reason)
        self.reason, self.target_sha, self.source_sha = reason, target_sha, source_sha


class SourceMoved(Exception):
    """SERVERLESS-AUTOMERGE-SHA: the source branch head is not the commit the caller tested (expected_source_sha).
    Nothing was written: the target and the source branch are unchanged."""

    reason_code = "SOURCE_MOVED"

    def __init__(self, expected_sha: str, source_sha: str):
        super().__init__(f"source branch head {source_sha} is not the expected commit {expected_sha}")
        self.reason = str(self)
        self.expected_sha, self.source_sha = expected_sha, source_sha


# SERVERLESS-AUTOMERGE-SHA: what this server guarantees, read by clients BEFORE they rely on it (an older server
# has no such route and answers 404, so a client never mistakes it for one that checks the source commit).
GIT_SERVER_CAPABILITIES: Dict[str, bool] = {"merge_expected_source_sha": True}


def merge_branch_dulwich(
    repo_path: str,
    source_branch: str,
    target_branch: str,
    commit_message: str,
    merge_method: str = "squash",
    expected_source_sha: Optional[str] = None,
) -> Dict[str, str]:
    """Fast-forward-only merge (FD-4V).

    SERVERLESS-AUTOMERGE-SHA: with `expected_source_sha`, the source head is read once and must equal it, else
    SourceMoved before anything is written; the merge then uses exactly that commit (its tree, its ref value for
    the compare-and-swap delete), so a push after the check can never be merged in its place.
    The caller's per-repo lock is per instance: during a Cloud Run rollout an old and a new revision can run at once
    with separate locks. The merged content stays exact anyway, because the merge uses the one checked `src_sha`
    (tree and source delete via remove_if_equals) and moves the target with set_if_equals (a concurrent target
    write is a TARGET_ADVANCED conflict), not the lock.

    - source == target, or source is an ancestor of target: ALREADY_UP_TO_DATE, no new commit.
    - target is not an ancestor of source (target advanced since the branch point): MergeConflict, nothing written.
    - otherwise: 'squash' commits the source tree with parent = target (correct, because the source contains every
      target commit); 'fast-forward' moves the target to the source commit. The target ref is updated with a
      compare-and-swap; the source branch is removed only after the target is verified, and only if unchanged.
    """
    repo = Repo(repo_path)
    src_ref = f"refs/heads/{source_branch}".encode("utf-8")
    tgt_ref = f"refs/heads/{target_branch}".encode("utf-8")

    if src_ref not in repo.refs:
        raise ValueError(f"Source branch '{source_branch}' does not exist.")
    if tgt_ref not in repo.refs:
        raise ValueError(f"Target branch '{target_branch}' does not exist.")

    src_sha = repo.refs[src_ref]
    tgt_sha = repo.refs[tgt_ref]
    if expected_source_sha is not None and src_sha.decode("ascii") != expected_source_sha:
        raise SourceMoved(expected_source_sha, src_sha.decode("ascii"))

    if src_sha == tgt_sha or can_fast_forward(repo, src_sha, tgt_sha):
        repo.refs.remove_if_equals(src_ref, src_sha)
        return {"status": "ALREADY_UP_TO_DATE", "commit_sha": tgt_sha.decode("ascii"),
                "source_sha": src_sha.decode("ascii")}

    if not can_fast_forward(repo, tgt_sha, src_sha):
        raise MergeConflict("target advanced since the branch point; rebase or regenerate the source branch",
                            tgt_sha.decode("ascii"), src_sha.decode("ascii"))

    if merge_method == "fast-forward":
        new_sha = src_sha
    else:
        src_commit = repo[src_sha]
        now = int(time.time())
        commit = Commit()
        commit.tree = src_commit.tree
        commit.parents = [tgt_sha]
        author = f"StackVend Release Agent <{AGENT_AUTHOR_EMAIL}>".encode("utf-8")
        commit.author = author
        commit.committer = author
        commit.author_time = now
        commit.commit_time = now
        commit.author_timezone = 0
        commit.commit_timezone = 0
        commit.message = commit_message.encode("utf-8")
        repo.object_store.add_object(commit)
        new_sha = commit.id

    if not repo.refs.set_if_equals(tgt_ref, tgt_sha, new_sha):
        raise MergeConflict("target branch moved during the merge", tgt_sha.decode("ascii"), src_sha.decode("ascii"))
    if repo.refs[tgt_ref] != new_sha:
        raise RuntimeError("target branch does not point at the merge result after the update")
    repo.refs.remove_if_equals(src_ref, src_sha)
    return {"status": "MERGED", "commit_sha": new_sha.decode("ascii"), "source_sha": src_sha.decode("ascii")}


def resolve_branch_head_dulwich(repo: Repo, branch: str) -> Optional[bytes]:
    """Commit SHA (40 lowercase hex, bytes) that refs/heads/{branch} points at, or None when the branch is missing.

    19c: only the named branch is ever resolved; there is no fallback to HEAD or another branch. The ref is read once
    (no `in` check followed by a second read, so a concurrent delete is a clean None, not a KeyError).
    """
    try:
        sha = repo.refs[f"refs/heads/{branch}".encode("utf-8")]
    except KeyError:
        return None
    if not (isinstance(sha, bytes) and len(sha) == 40 and all(c in b"0123456789abcdef" for c in sha)):
        raise RuntimeError(f"refs/heads/{branch} does not hold a full commit SHA")
    if not isinstance(repo[sha], Commit):
        raise RuntimeError(f"refs/heads/{branch} does not point at a commit")
    return sha


def export_archive_dulwich(repo_path: str, branch: str) -> Optional[Tuple[str, bytes]]:
    """(commit SHA, .tar.gz bytes) of exactly the commit refs/heads/{branch} pointed at when it was resolved.

    19c (lane 13 contract): the branch ref is resolved once and the archive is built from that commit's tree, so a
    push that moves the branch while the archive is being built cannot mix trees; the caller receives the SHA of the
    archived commit (X-Commit-Sha). Missing branch -> None (404), never the HEAD tree.
    """
    import tarfile
    repo = Repo(repo_path)
    sha = resolve_branch_head_dulwich(repo, branch)
    if sha is None:
        return None

    commit = repo[sha]
    tar_stream = io.BytesIO()
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        for entry in repo.object_store.iter_tree_contents(commit.tree):
            obj = repo.get_object(entry.sha)
            if isinstance(obj, Blob):
                ti = tarfile.TarInfo(name=entry.path.decode("utf-8", errors="replace"))
                ti.size = len(obj.data)
                ti.mode = entry.mode
                tar.addfile(ti, io.BytesIO(obj.data))
    tar_stream.seek(0)
    return sha.decode("ascii"), tar_stream.getvalue()


def resolve_git_http_backend() -> List[str]:
    """Resolves path or invocation for git http-backend CGI handler across buildpack environments."""
    candidates = [
        shutil.which("git-http-backend"),
        "/usr/lib/git-core/git-http-backend",
        "/usr/libexec/git-core/git-http-backend",
        "/usr/local/libexec/git-core/git-http-backend",
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return [c]
    return [GIT_BIN, "http-backend"]


# ==============================================================================
# Request models
# ==============================================================================

class CreateRepoRequest(BaseModel):
    product_id: str
    description: Optional[str] = ""
    initial_branch: str = "main"

    @field_validator("initial_branch")
    @classmethod
    def _v_initial_branch(cls, v):
        return validate_branch(v)


class BranchRequest(BaseModel):
    branch_name: str
    source_branch: str = "main"

    @field_validator("branch_name", "source_branch")
    @classmethod
    def _v_branches(cls, v):
        return validate_branch(v)


class CommitRequest(BaseModel):
    # GIT-COMMITS-STRICT: an unknown key is a client bug and answers 422 before anything is written. Before this, a
    # client that sent `files_to_delete` to /commits (instead of /commits-with-deletions) got a commit that silently
    # kept the paths it asked to delete. Inherited by CommitChangesRequest, which declares `files_to_delete`.
    model_config = ConfigDict(extra="forbid")

    branch: str = "main"
    files: Dict[str, str] = Field(default_factory=dict)
    commit_message: str = "Automated commit by StackVend"
    author_name: str = "StackVend Developer Agent"
    author_email: str = AGENT_AUTHOR_EMAIL

    @field_validator("branch")
    @classmethod
    def _v_branch(cls, v):
        return validate_branch(v)

    @field_validator("files")
    @classmethod
    def _v_files(cls, v):
        # FD-4G (T10, H1): tree entries must be canonical relpaths with no .git component -- the same rule the
        # git CLI path's update-index (verify_path) enforces. Stops second-order traversal via fetch_tree.
        validate_manifest_keys(v, reserved=GIT_RESERVED)
        return v


class CommitChangesRequest(CommitRequest):
    """FD-4DC-e: a commit that also deletes files. A separate route, so a client never sends deletions to a server
    that would ignore them: an older git server answers this route with 404 and writes nothing."""
    files_to_delete: List[str] = Field(min_length=1)

    @field_validator("files_to_delete")
    @classmethod
    def _v_files_to_delete(cls, v):
        # the same canonical-relpath / no-.git rule as the written paths (FD-4G)
        validate_manifest_keys(dict.fromkeys(v, ""), reserved=GIT_RESERVED)
        return v

    @model_validator(mode="after")
    def _v_disjoint(self):
        both = sorted(set(self.files) & set(self.files_to_delete))
        if both:
            raise ValueError(f"paths both written and deleted: {both[:20]}")
        return self


class MergeRequest(BaseModel):
    source_branch: str
    target_branch: str = "main"
    commit_message: Optional[str] = None
    merge_method: Literal["squash", "fast-forward"] = "squash"
    # SERVERLESS-AUTOMERGE-SHA: the commit the caller tested; absent = the old behavior (no source check).
    expected_source_sha: Optional[str] = None

    @field_validator("source_branch", "target_branch")
    @classmethod
    def _v_branches(cls, v):
        return validate_branch(v)

    @field_validator("expected_source_sha")
    @classmethod
    def _v_expected_source_sha(cls, v):
        if v is None:
            return v
        if not (isinstance(v, str) and len(v) == 40 and all(c in "0123456789abcdef" for c in v)):
            raise ValueError("expected_source_sha must be a full commit SHA (40 lowercase hex characters)")
        return v


# ==============================================================================
# Health Check (public)
# ==============================================================================

@app.get("/health")
@app.get("/healthz")
def health_check():
    return {"status": "OK", "service": "castor-git-server"}


@app.get("/api/v1/capabilities")
def capabilities():
    """SERVERLESS-AUTOMERGE-SHA: authenticated (not a public path). `merge_expected_source_sha` = the merge route
    refuses a source branch whose head is not `expected_source_sha` (409 SOURCE_MOVED) and echoes the check."""
    # FD-7C P3a: this server's /health is public at the app level and stays minimal (FD-4K); its release is here.
    return {"service": "castor-git-server", "capabilities": dict(GIT_SERVER_CAPABILITIES),
            "release": release_info.current_release()}


# ==============================================================================
# Git Smart HTTP (clone/fetch; push only with explicit opt-in)
# ==============================================================================

SMART_HTTP_SERVICES = ("git-upload-pack", "git-receive-pack")


def _push_allowed() -> bool:
    return os.getenv("GIT_SERVER_ALLOW_SMART_HTTP_PUSH", "") == "true"


def _smart_http_product_id(repo_name: str) -> str:
    """Smart-HTTP repository segment must be exactly '<product_id>.git'."""
    if not repo_name.endswith(".git"):
        raise HTTPException(status_code=404, detail="Repository not found.")
    return validate_product_id(repo_name[: -len(".git")])


def _run_http_backend(product_id: str, rest: str, query: str, method: str, content_type: str,
                      content_encoding: str, body: bytes, caller: str, remote_addr: str) -> Response:
    repo_path = get_repo_path(product_id)
    _require_repo(repo_path)
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": tempfile.gettempdir(),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_PROJECT_ROOT": GIT_DATA_DIR,
        "GIT_HTTP_EXPORT_ALL": "1",
        "PATH_INFO": f"/{product_id}.git/{rest}",
        "QUERY_STRING": query,
        "REQUEST_METHOD": method,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(body)),
        "REMOTE_USER": caller,
        "REMOTE_ADDR": remote_addr,
        # Defence in depth: the backend itself refuses push unless explicitly enabled.
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "http.receivepack",
        "GIT_CONFIG_VALUE_0": "true" if _push_allowed() else "false",
        "GIT_CONFIG_KEY_1": "safe.directory",
        "GIT_CONFIG_VALUE_1": repo_path,
    }
    if content_encoding:
        env["HTTP_CONTENT_ENCODING"] = content_encoding

    lock = get_repo_lock(product_id) if rest == "git-receive-pack" else None
    if lock:
        lock.acquire()
    try:
        proc = subprocess.Popen(
            resolve_git_http_backend(),
            cwd=repo_path,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        stdout, stderr = proc.communicate(input=body)
    finally:
        if lock:
            lock.release()

    if proc.returncode != 0 and not stdout:
        logger.error(f"git http-backend error ({proc.returncode}): {stderr.decode('utf-8', errors='replace')[:2000]}")
        raise HTTPException(status_code=500, detail="Git backend error.")

    # Parse CGI response (Headers \r\n\r\n Body)
    header_end = stdout.find(b"\r\n\r\n")
    delimiter_len = 4
    if header_end == -1:
        header_end = stdout.find(b"\n\n")
        delimiter_len = 2
    if header_end != -1:
        raw_headers = stdout[:header_end].decode("iso-8859-1")
        resp_body = stdout[header_end + delimiter_len:]
    else:
        raw_headers = ""
        resp_body = stdout

    res_headers = {}
    status_code = 200
    for line in raw_headers.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "status":
                try:
                    status_code = int(v.split()[0])
                except Exception:
                    status_code = 200
            else:
                res_headers[k] = v

    content_type_out = res_headers.pop("content-type", "application/octet-stream")
    return Response(content=resp_body, status_code=status_code, headers=res_headers, media_type=content_type_out)


async def _proxy(product_id: str, rest: str, query: str, request: Request) -> Response:
    body = await request.body()
    return await run_in_threadpool(
        _run_http_backend,
        product_id,
        rest,
        query,
        request.method,
        request.headers.get("content-type", ""),
        request.headers.get("content-encoding", ""),
        body,
        request.state.caller,
        request.client.host if request.client else "127.0.0.1",
    )


@app.get("/git/{repo_name}/info/refs")
async def git_info_refs(repo_name: str, request: Request):
    product_id = _smart_http_product_id(repo_name)
    services = request.query_params.getlist("service")
    if len(services) != 1 or services[0] not in SMART_HTTP_SERVICES:
        raise HTTPException(status_code=403, detail="Only the smart HTTP protocol is supported.")
    if services[0] == "git-receive-pack" and not _push_allowed():
        raise HTTPException(status_code=403, detail="Push over Smart HTTP is disabled; use the REST commit API.")
    return await _proxy(product_id, "info/refs", f"service={services[0]}", request)


@app.post("/git/{repo_name}/git-upload-pack")
async def git_upload_pack(repo_name: str, request: Request):
    product_id = _smart_http_product_id(repo_name)
    return await _proxy(product_id, "git-upload-pack", "", request)


@app.post("/git/{repo_name}/git-receive-pack")
async def git_receive_pack(repo_name: str, request: Request):
    product_id = _smart_http_product_id(repo_name)
    if not _push_allowed():
        raise HTTPException(status_code=403, detail="Push over Smart HTTP is disabled; use the REST commit API.")
    return await _proxy(product_id, "git-receive-pack", "", request)


# ==============================================================================
# Agent REST API (/api/v1)
# ==============================================================================

@app.post("/api/v1/repos", status_code=status.HTTP_201_CREATED)
def vend_repository(req: CreateRepoRequest):
    """
    Initializes a new bare Git repository on Cloud Storage FUSE
    and seeds the initial commit with README.md and .gitignore.
    """
    repo_path = get_repo_path(req.product_id)  # FD-4G/4K: anchored id before any mkdir
    lock = get_repo_lock(req.product_id)

    with lock:
        head_file = os.path.join(repo_path, "HEAD")
        if os.path.isfile(head_file):
            return {
                "status": "EXISTS",
                "product_id": req.product_id,
                "clone_url": f"/git/{req.product_id}.git",
                "default_branch": req.initial_branch,
            }

        created_dir = not os.path.isdir(repo_path)
        os.makedirs(repo_path, exist_ok=True)
        try:
            commit_sha = init_bare_repo_dulwich(
                repo_path,
                req.product_id,
                req.description or "Vended workload managed by StackVend.",
                req.initial_branch,
            )
        except Exception as dul_err:
            logger.error(f"Repository init failed for '{req.product_id}': {dul_err}")
            if created_dir:
                shutil.rmtree(repo_path, ignore_errors=True)
            raise HTTPException(status_code=500, detail="Repository initialization failed.")
        logger.info(f"Initialized serverless repository '{req.product_id}' at {repo_path} (commit: {commit_sha})")
        return {
            "status": "CREATED",
            "product_id": req.product_id,
            "clone_url": f"/git/{req.product_id}.git",
            "default_branch": req.initial_branch,
            "initial_commit": commit_sha,
        }


@app.get("/api/v1/repos/{product_id}/metadata")
def get_metadata(product_id: str):
    """Returns repository branch information and status."""
    repo_path = get_repo_path(product_id)
    _require_repo(repo_path)
    default_branch, branches = get_metadata_dulwich(repo_path)
    return {
        "product_id": product_id,
        "default_branch": default_branch,
        "branches": branches,
        "clone_url": f"/git/{product_id}.git",
    }


@app.post("/api/v1/repos/{product_id}/branches")
def create_branch(product_id: str, req: BranchRequest):
    """Creates a new branch from a source branch."""
    repo_path = get_repo_path(product_id)
    lock = get_repo_lock(product_id)

    with lock:
        _require_repo(repo_path)
        try:
            status_code, commit_sha = create_branch_dulwich(repo_path, req.branch_name, req.source_branch)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        if status_code == "CREATED":
            logger.info(f"Created branch '{req.branch_name}' on '{product_id}' from '{req.source_branch}' ({commit_sha})")
        return {
            "status": status_code,
            "branch": req.branch_name,
            "commit_sha": commit_sha,
        }


@app.get("/api/v1/repos/{product_id}/tree/{branch:path}")
def fetch_tree(product_id: str, branch: str, max_files: int = 2500):
    """Fetches text file tree for a given branch directly from Git object database.

    Register row 40: only refs/heads/{branch} (404 when missing, no HEAD fallback). `branch` may contain '/'
    (raw or %2F); it is validated like every branch name.
    """
    validate_branch(branch)
    repo_path = get_repo_path(product_id)
    _require_repo(repo_path)
    result = fetch_tree_with_status_dulwich(repo_path, branch, max_files=max_files)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Branch '{branch}' not found.")
    files, truncated = result
    return {
        "product_id": product_id,
        "branch": branch,
        "files": files,
        "total_files": len(files),
        "truncated": truncated,   # FD-4DC: True only when the branch has more text files than max_files
    }


@app.get("/api/v1/repos/{product_id}/blob/{ref_path:path}")
def fetch_blob(product_id: str, ref_path: str):
    """Fetches single file content directly: `blob/{branch}/{file_path}`.

    Register row 40: the file is read from exactly refs/heads/{branch}; a missing branch is a 404 (never the HEAD
    tree). `branch` may contain '/' (raw or %2F): the branch/file boundary is resolved against the repo's refs
    (split_blob_ref_path_dulwich). A missing file on an existing branch keeps its previous 404 body.
    """
    repo_path = get_repo_path(product_id)
    _require_repo(repo_path)
    repo = Repo(repo_path)
    resolved = split_blob_ref_path_dulwich(repo, ref_path)
    if resolved is None:
        raise HTTPException(status_code=404, detail="Branch not found.", headers={"X-Git-Not-Found": "branch"})
    branch, file_path, sha = resolved
    content = read_blob_at_commit_dulwich(repo, sha, file_path)
    if content is None:
        raise HTTPException(status_code=404, detail=f"File '{file_path}' not found on branch '{branch}'.",
                            headers={"X-Git-Not-Found": "file"})
    return {
        "product_id": product_id,
        "branch": branch,
        "file_path": file_path,
        "content": content,
    }


@app.post("/api/v1/repos/{product_id}/commits")
def commit_files(product_id: str, req: CommitRequest):
    """Creates an atomic programmatic Git commit without working-tree checkout (Dulwich). Thread-safe per repo."""
    repo_path = get_repo_path(product_id)
    lock = get_repo_lock(product_id)

    with lock:
        head_file = os.path.join(repo_path, "HEAD")
        if not os.path.isfile(head_file):
            try:
                os.makedirs(repo_path, exist_ok=True)
                init_bare_repo_dulwich(repo_path, product_id, f"Repository for {product_id}", req.branch)
                logger.info(f"Auto-initialized missing bare repo for '{product_id}' before commit.")
            except Exception as auto_err:
                logger.warning(f"Auto-init failed for '{product_id}': {auto_err}")
            if not os.path.isfile(head_file):
                raise HTTPException(status_code=404, detail="Repository not found or uninitialized.")

        commit_sha = commit_files_dulwich(
            repo_path,
            req.branch,
            req.files,
            req.commit_message,
            req.author_name,
            req.author_email,
        )
        logger.info(f"Committed {len(req.files)} files to '{product_id}@{req.branch}' -> {commit_sha[:7]}")
        return {
            "status": "COMMITTED",
            "product_id": product_id,
            "branch": req.branch,
            "commit_sha": commit_sha,
            "files_committed": list(req.files.keys()),
        }


@app.post("/api/v1/repos/{product_id}/commits-with-deletions")
def commit_files_with_deletions(product_id: str, req: CommitChangesRequest):
    """FD-4DC-e: one commit that writes `files` and deletes `files_to_delete` (exact file paths). The repository must
    exist (no auto-init: a new repository has nothing to delete). The answer lists `files_deleted`."""
    repo_path = get_repo_path(product_id)
    lock = get_repo_lock(product_id)

    with lock:
        _require_repo(repo_path)
        deleted: List[str] = []
        commit_sha = commit_files_dulwich(
            repo_path,
            req.branch,
            req.files,
            req.commit_message,
            req.author_name,
            req.author_email,
            files_to_delete=req.files_to_delete,
            deleted_out=deleted,
        )
        logger.info(f"Committed {len(req.files)} files and deleted {len(deleted)} file(s) on "
                    f"'{product_id}@{req.branch}' -> {commit_sha[:7]}")
        return {
            "status": "COMMITTED",
            "product_id": product_id,
            "branch": req.branch,
            "commit_sha": commit_sha,
            "files_committed": list(req.files.keys()),
            "files_deleted": deleted,
        }


@app.post("/api/v1/repos/{product_id}/merge")
def merge_branch(product_id: str, req: MergeRequest):
    """
    FD-4V: fast-forward-only merge of source_branch into target_branch ('squash' = one commit with the source tree
    on top of the target, 'fast-forward' = move the target). 409 when the target advanced since the branch point;
    nothing is written and the source branch is kept. The source branch is deleted after a verified merge.
    SERVERLESS-AUTOMERGE-SHA: with `expected_source_sha`, a source head that is not that commit is a 409 with
    reason_code SOURCE_MOVED (nothing written); every answer says whether the check ran (`source_sha_checked`).
    Without the field the merge behaves as before (`source_sha_checked: false`).
    """
    repo_path = get_repo_path(product_id)
    lock = get_repo_lock(product_id)

    with lock:
        _require_repo(repo_path)
        try:
            result = merge_branch_dulwich(
                repo_path,
                req.source_branch,
                req.target_branch,
                req.commit_message or f"feat({product_id}): automated release merge of {req.source_branch} into {req.target_branch}",
                req.merge_method,
                expected_source_sha=req.expected_source_sha,
            )
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except SourceMoved as moved:
            logger.warning(f"Refused merge '{req.source_branch}' -> '{req.target_branch}' on '{product_id}': {moved.reason}")
            return JSONResponse(status_code=409, content={
                "status": "CONFLICT",
                "reason_code": moved.reason_code,
                "reason": moved.reason,
                "product_id": product_id,
                "target_branch": req.target_branch,
                "source_branch": req.source_branch,
                "expected_source_sha": moved.expected_sha,
                "source_sha": moved.source_sha,
                "source_sha_checked": True,
            })
        except MergeConflict as conflict:
            logger.warning(f"Refused merge '{req.source_branch}' -> '{req.target_branch}' on '{product_id}': {conflict.reason}")
            return JSONResponse(status_code=409, content={
                "status": "CONFLICT",
                "reason_code": conflict.reason_code,
                "reason": conflict.reason,
                "product_id": product_id,
                "target_branch": req.target_branch,
                "source_branch": req.source_branch,
                "target_sha": conflict.target_sha,
                "source_sha": conflict.source_sha,
                "source_sha_checked": req.expected_source_sha is not None,
            })
        logger.info(f"Merge '{req.source_branch}' -> '{req.target_branch}' on '{product_id}': {result['status']} {result['commit_sha'][:7]}")
        return {
            "status": result["status"],
            "product_id": product_id,
            "target_branch": req.target_branch,
            "merged_branch": req.source_branch,
            "commit_sha": result["commit_sha"],
            "source_sha": result["source_sha"],
            "source_sha_checked": req.expected_source_sha is not None,
        }


@app.get("/api/v1/repos/{product_id}/refs/heads/{branch:path}")
def get_branch_head(product_id: str, branch: str):
    """19c (optional lane 13 contract, RT C5): read-only head commit of refs/heads/{branch}; 404 when missing.

    `branch` may contain '/' (pipeline branches are `castor/<id>-<suffix>`); it is validated like every branch name.
    """
    validate_branch(branch)
    repo_path = get_repo_path(product_id)
    _require_repo(repo_path)
    sha = resolve_branch_head_dulwich(Repo(repo_path), branch)
    if sha is None:
        raise HTTPException(status_code=404, detail=f"Branch '{branch}' not found.")
    return {"product_id": product_id, "branch": branch, "commit_sha": sha.decode("ascii")}


@app.get("/api/v1/repos/{product_id}/archive/{branch:path}")
def export_archive(product_id: str, branch: str):
    """Returns a .tar.gz archive of the repository branch (Dulwich).

    19c: only refs/heads/{branch} (404 when missing, no HEAD fallback); the ref is resolved once and the archived
    commit is returned in `X-Commit-Sha` (40 lowercase hex). `branch` may contain '/' (pipeline branches).
    """
    validate_branch(branch)
    repo_path = get_repo_path(product_id)
    _require_repo(repo_path)
    result = export_archive_dulwich(repo_path, branch)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Branch '{branch}' not found.")
    commit_sha, archive_bytes = result
    safe_name = f"{product_id}-{branch.replace('/', '-')}".replace('"', "")
    return Response(
        content=archive_bytes,
        media_type="application/gzip",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}.tar.gz"',
            "X-Commit-Sha": commit_sha,
        },
    )


# FD-7L Phase 4 (plan 2.10): the routes a GIT_SERVER_READONLY_INVOKERS caller may call (all GET; they read and never
# write). Every other route (vend, branch, commits, merge, Smart HTTP incl. upload-pack) answers such a caller 403.
READ_ONLY_ENDPOINTS = frozenset({capabilities, get_metadata, fetch_tree, fetch_blob, get_branch_head, export_archive})

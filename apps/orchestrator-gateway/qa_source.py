"""
FD-4F (H7): complete, commit-SHA-bound source trees for the post-commit gates (gatekeeper, QA, release).

Why not `DeveloperAgent.fetch_branch_files`: it swallows every provider error, returns partial trees
(GitHubProvider.fetch_file_tree, FD-4D) and decodes with errors="ignore". A gate that cannot see the whole
committed tree must fail closed, so this module fetches ONE archive at ONE resolved commit SHA and raises
BranchFetchError on anything short of that. Lenient callers keep using fetch_branch_files.

No provider replica is edited: the GitHub path uses the REST API directly; the Serverless Git path uses the
existing provider's server URL + auth headers and REQUIRES the `X-Commit-Sha` archive header (Q-C / QS-1,
apps/git-server, lane 3). Until the git server sends it, SERVERLESS_GIT gates fail closed.
"""

import gzip
import hashlib
import io
import logging
import tarfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from shared.path_safety import GIT_RESERVED, UnsafePathError, validate_relpath

logger = logging.getLogger("castor-qa-source")

GITHUB_API = "https://api.github.com"
MAX_MEMBERS = 10_000
MAX_TOTAL_BYTES = 100 * 1024 * 1024
HTTP_TIMEOUT = 60
_HEX = frozenset("0123456789abcdef")


class BranchFetchError(RuntimeError):
    """The committed tree could not be obtained completely and unambiguously."""


class GitServerUnreachable(BranchFetchError):
    """GIT-404-TYPED-DIRECT-CALLERS: an HTTP 404 the git server itself did not send (no GIT_SERVER_HEADER), e.g. Cloud
    Run's front end refusing a caller the internal-only ingress does not admit, or a wrong URL. Never "branch / repo
    not found": a caller that treats a missing branch as normal (the QA diff base) must not treat this one so."""

    error_class = "GIT_SERVER_UNREACHABLE"
    stage = "vcs"


class BranchNotFoundError(BranchFetchError):
    """RT14-28: the provider answered that the branch does not exist (GitHub HTTP 404 on the branch of a repository
    the same credential can read; the git server's OWN 404, carrying GIT_SERVER_HEADER). The only fetch failure a
    caller may read as "no base branch yet": every other BranchFetchError is an outage or an integrity problem."""

    error_class = "BRANCH_NOT_FOUND"


class EmptyArchiveError(BranchFetchError):
    """RT14-28: the branch exists and its archive holds no file (an empty tree). A diff base may treat it as empty."""

    error_class = "ARCHIVE_EMPTY"


# GIT-404-TYPED (internal-ingress plan §6.3): apps/git-server sets this exact header on every answer, its own 404s
# included (= its GIT_SERVER_HEADER and shared/providers/serverless_git_provider.GIT_SERVER_HEADER; a test pins them
# equal). HTTP header names are case-insensitive (RFC 9110); the value is compared exactly.
GIT_SERVER_HEADER = "X-StackVend-Git-Server"
GIT_SERVER_HEADER_VALUE = "1"


def answered_by_git_server(headers: Any) -> bool:
    """True when `headers` (a response's header mapping) carries GIT_SERVER_HEADER == GIT_SERVER_HEADER_VALUE."""
    items = headers.items() if hasattr(headers, "items") else ()
    want = GIT_SERVER_HEADER.lower()
    return any(isinstance(k, str) and k.lower() == want and v == GIT_SERVER_HEADER_VALUE for k, v in items)


def is_commit_sha(value: Any) -> bool:
    """Exact format check: 40 lowercase hex characters (a full git SHA-1)."""
    return isinstance(value, str) and len(value) == 40 and all(c in _HEX for c in value)


@dataclass(frozen=True)
class SourceTree:
    commit_sha: str
    files_text: Dict[str, str]
    skipped_binary: List[str] = field(default_factory=list)
    tar_bytes: bytes = b""
    tar_sha256: str = ""


# ------------------------------------------------------------------------------
# Backends (injected HTTP session so tests never touch the network)
# ------------------------------------------------------------------------------
class GitHubSource:
    strip_top_dir = True
    provider = "GITHUB"            # shared.vcs_ledger.PROVIDER_GITHUB (QA-STAGE2-PLATFORM-FACTS; a test pins it)

    def __init__(self, full_repo_name: str, token: str, http: Any):
        if not full_repo_name or "/" not in full_repo_name:
            raise BranchFetchError(f"invalid GitHub repository name: {full_repo_name!r}")
        if not token:
            raise BranchFetchError("no GitHub credential available for the gate")
        self.full_repo_name = full_repo_name
        self.http = http
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def head_sha(self, branch: str) -> str:
        url = f"{GITHUB_API}/repos/{self.full_repo_name}/branches/{quote(branch, safe='')}"
        try:
            res = self.http.get(url, headers=self._headers, timeout=HTTP_TIMEOUT)
        except Exception as e:
            raise BranchFetchError(f"GitHub branch lookup failed: {type(e).__name__}: {e}") from e
        if res.status_code == 404:   # RT14-28: typed, so only "no such branch" can mean an empty diff base
            raise BranchNotFoundError(f"GitHub branch '{branch}' not found (HTTP 404)")
        if res.status_code != 200:
            raise BranchFetchError(f"GitHub branch lookup for '{branch}' returned HTTP {res.status_code}")
        try:
            sha = res.json()["commit"]["sha"]
        except Exception as e:
            raise BranchFetchError(f"GitHub branch response has no commit sha: {e}") from e
        if not is_commit_sha(sha):
            raise BranchFetchError(f"GitHub returned a malformed commit sha: {sha!r}")
        return sha

    def archive(self, branch: str, sha: str) -> Tuple[str, bytes]:
        url = f"{GITHUB_API}/repos/{self.full_repo_name}/tarball/{sha}"
        try:
            res = self.http.get(url, headers=self._headers, timeout=HTTP_TIMEOUT, allow_redirects=True)
        except Exception as e:
            raise BranchFetchError(f"GitHub tarball download failed: {type(e).__name__}: {e}") from e
        if res.status_code != 200 or not res.content:
            raise BranchFetchError(f"GitHub tarball for {sha} returned HTTP {res.status_code} ({len(res.content or b'')} bytes)")
        return sha, res.content


class ServerlessGitSource:
    strip_top_dir = False
    provider = "SERVERLESS_GIT"    # shared.vcs_ledger.PROVIDER_SERVERLESS_GIT (QA-STAGE2-PLATFORM-FACTS)

    def __init__(self, server_url: str, repo_id: str, headers: Dict[str, str], http: Any):
        if not server_url:
            raise BranchFetchError("no git server URL configured")
        self.server_url = server_url.rstrip("/")
        self.repo_id = repo_id
        self.headers = dict(headers)
        self.http = http

    def _get_archive(self, branch: str) -> Tuple[str, bytes]:
        url = f"{self.server_url}/api/v1/repos/{quote(self.repo_id, safe='')}/archive/{quote(branch, safe='')}"
        try:
            res = self.http.get(url, headers=self.headers, timeout=HTTP_TIMEOUT)
        except Exception as e:
            raise BranchFetchError(f"git server archive request failed: {type(e).__name__}: {e}") from e
        if res.status_code == 404 and not answered_by_git_server(getattr(res, "headers", None)):
            raise GitServerUnreachable(
                f"{GitServerUnreachable.error_class}: git server archive for '{branch}' returned HTTP 404 without the "
                f"{GIT_SERVER_HEADER} header: the git server did not answer (an ingress refusal or a wrong URL), so "
                "this is not 'branch not found'")
        if res.status_code == 404:   # the git server's own 404 (header checked above): no such branch / repository
            raise BranchNotFoundError(f"git server: branch '{branch}' not found (HTTP 404)")
        if res.status_code != 200 or not res.content:
            raise BranchFetchError(f"git server archive for '{branch}' returned HTTP {res.status_code}")
        sha = (res.headers or {}).get("X-Commit-Sha", "")
        if not is_commit_sha(sha):
            raise BranchFetchError(
                "git server archive lacks a valid X-Commit-Sha header (Q-C/QS-1 not deployed); "
                "SERVERLESS_GIT gates fail closed until it is"
            )
        return sha, res.content

    def head_sha(self, branch: str) -> str:
        return self._get_archive(branch)[0]

    def archive(self, branch: str, sha: str) -> Tuple[str, bytes]:
        got_sha, content = self._get_archive(branch)
        if got_sha != sha:
            raise BranchFetchError(f"git server archived {got_sha}, expected {sha}")
        return got_sha, content


def backend_for(developer_agent: Any, product_id: str, http: Any = None) -> Any:
    """Selects the source backend with the same provider resolution the developer agent uses."""
    if http is None:
        import requests

        http = requests.Session()
    try:
        from shared.vcs_provider import VCSProviderFactory
        from shared.providers.serverless_git_provider import ServerlessGitProvider
    except ImportError as e:  # the gateway image always ships these; absence is a broken build
        raise BranchFetchError(f"VCS provider modules unavailable: {e}") from e

    full_repo_name = developer_agent.get_full_repo_name(product_id)
    vcs_name = getattr(developer_agent, "vcs_provider", None)
    if not vcs_name and getattr(developer_agent, "db", None):
        try:
            w_doc = developer_agent.db.collection("workloads").document(product_id).get()
            if w_doc.exists:
                vcs_name = (w_doc.to_dict() or {}).get("vcs_provider")
        except Exception as e:
            raise BranchFetchError(f"could not read workload VCS provider: {e}") from e
    try:
        vcs = VCSProviderFactory.get_provider(
            provider_name=vcs_name,
            default_owner=getattr(developer_agent, "github_owner", ""),
            project_id=getattr(developer_agent, "project_id", ""),
            product_id=product_id,
            full_repo_name=full_repo_name,
        )
    except Exception as e:
        raise BranchFetchError(f"could not resolve VCS provider: {e}") from e

    if isinstance(vcs, ServerlessGitProvider):
        return ServerlessGitSource(vcs.server_url, vcs._clean_product_id(full_repo_name), vcs._get_headers(), http)
    return GitHubSource(full_repo_name, developer_agent.fetch_github_token(), http)


# ------------------------------------------------------------------------------
# Archive normalization
# ------------------------------------------------------------------------------
def normalize_archive(archive: bytes, *, strip_top_dir: bool) -> Dict[str, bytes]:
    """Returns {relpath: bytes}. Regular files only (directories skipped); any other member type raises."""
    # Decompress fully first so a truncated/corrupt gzip stream (CRC/length trailer) is an error, not a silently
    # shorter tree; bound the output against decompression bombs.
    raw_tar = archive
    if archive[:2] == b"\x1f\x8b":
        limit = MAX_TOTAL_BYTES + 64 * 1024 * 1024  # file data cap + generous tar header/padding headroom
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(archive)) as gz:
                raw_tar = gz.read(limit + 1)
                if len(raw_tar) > limit:
                    raise BranchFetchError("archive decompresses beyond the size cap")
                gz.read(1)  # forces trailer (CRC32 + ISIZE) verification when the stream ended exactly at limit
        except BranchFetchError:
            raise
        except Exception as e:
            raise BranchFetchError(f"corrupt or truncated gzip archive: {type(e).__name__}: {e}") from e
    try:
        tf = tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:")
        members = tf.getmembers()
    except Exception as e:
        raise BranchFetchError(f"unreadable archive: {type(e).__name__}: {e}") from e
    if len(members) > MAX_MEMBERS:
        raise BranchFetchError(f"archive has {len(members)} members (cap {MAX_MEMBERS})")

    prefix = None
    if strip_top_dir:
        tops = {m.name.split("/", 1)[0] for m in members}
        if len(tops) != 1:
            raise BranchFetchError(f"GitHub tarball must have exactly one top-level directory, found {len(tops)}")
        prefix = tops.pop() + "/"

    out: Dict[str, bytes] = {}
    total = 0
    for m in members:
        name = m.name
        if prefix is not None:
            if name + "/" == prefix:
                if not m.isdir():
                    raise BranchFetchError("GitHub tarball top-level entry is not a directory")
                continue
            if not name.startswith(prefix):
                raise BranchFetchError(f"member outside the top-level directory: {name!r}")
            name = name[len(prefix):]
        if m.isdir():
            continue
        if not m.isreg():
            raise BranchFetchError(f"non-regular archive member (symlink/link/device): {name!r}")
        try:
            validate_relpath(name, reserved=GIT_RESERVED)
        except UnsafePathError as e:
            raise BranchFetchError(f"unsafe archive member {name!r}: {e.reason}") from e
        if name in out:
            raise BranchFetchError(f"duplicate archive member {name!r}")
        total += m.size
        if total > MAX_TOTAL_BYTES:
            raise BranchFetchError(f"archive exceeds {MAX_TOTAL_BYTES} bytes uncompressed")
        try:
            fh = tf.extractfile(m)
            data = fh.read() if fh is not None else None
        except Exception as e:
            raise BranchFetchError(f"could not read member {name!r}: {e}") from e
        if data is None or len(data) != m.size:
            raise BranchFetchError(f"truncated archive member {name!r}")
        out[name] = data
    if not out:
        raise EmptyArchiveError("archive contains no files")
    return out


def deterministic_tar_gz(files: Dict[str, bytes]) -> bytes:
    """Sorted names, mode 0644, uid/gid 0, mtime 0, gzip mtime 0: same tree -> same bytes -> same sha256."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name in sorted(files):
            data = files[name]
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mode = 0o644
            ti.mtime = 0
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            tf.addfile(ti, io.BytesIO(data))
    gz = io.BytesIO()
    with gzip.GzipFile(fileobj=gz, mode="wb", mtime=0) as g:
        g.write(raw.getvalue())
    return gz.getvalue()


def fetch_tree_at_head(backend: Any, branch: str, expected_sha: Optional[str] = None) -> SourceTree:
    """Resolve the branch head, refuse if it moved from expected_sha, fetch the archive AT that sha."""
    sha = backend.head_sha(branch)
    if expected_sha is not None and sha != expected_sha:
        raise BranchMovedError(expected_sha, sha)
    got_sha, archive = backend.archive(branch, sha)
    raw = normalize_archive(archive, strip_top_dir=backend.strip_top_dir)
    files_text: Dict[str, str] = {}
    skipped: List[str] = []
    for name in sorted(raw):
        try:
            files_text[name] = raw[name].decode("utf-8")
        except UnicodeDecodeError:
            skipped.append(name)
    tar_bytes = deterministic_tar_gz(raw)
    return SourceTree(
        commit_sha=got_sha,
        files_text=files_text,
        skipped_binary=skipped,
        tar_bytes=tar_bytes,
        tar_sha256=hashlib.sha256(tar_bytes).hexdigest(),
    )


class BranchMovedError(BranchFetchError):
    """The branch head is not the commit an earlier gate verified (integrity event, F6)."""

    def __init__(self, expected_sha: str, actual_sha: str):
        super().__init__(f"branch moved: expected {expected_sha}, head is {actual_sha}")
        self.expected_sha = expected_sha
        self.actual_sha = actual_sha

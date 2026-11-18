"""FD-4F H7: complete, commit-bound source trees for the post-commit gates (no partial trees, no guessing)."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import io
import tarfile

import pytest

import fd4f_support  # noqa: F401
from fd4f_support import SHA_A, SHA_B, make_tar

from qa_source import (
    BranchFetchError,
    BranchMovedError,
    GitHubSource,
    ServerlessGitSource,
    deterministic_tar_gz,
    fetch_tree_at_head,
    is_commit_sha,
    normalize_archive,
)

# Attack keys are built without dict literals so tests/test_fd4g_do_no_harm.py's corpus scan stays meaningful.
PARENT_ESCAPE, ABSOLUTE, GIT_INTERNAL = "../escape.py", "/abs.py", ".git/config"
FILES = {"apps/a/main.py": b"print(1)\n", "apps/a/logo.png": bytes(range(256)), "README.md": "h\xe9\n".encode()}


class _Res:
    def __init__(self, status=200, content=b"", headers=None, payload=None):
        self.status_code, self.content, self.headers, self._payload = status, content, headers or {}, payload

    def json(self):
        return self._payload


class _Http:
    def __init__(self, responses):
        self.responses, self.calls = responses, []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        for key, res in self.responses.items():
            if key in url:
                if isinstance(res, Exception):
                    raise res
                return res
        return _Res(404)


def _gh(http):
    return GitHubSource("o/r", "tok", http)


def test_negative_github_tree_round_trips_bytes_exactly():
    tar = make_tar(FILES, prefix="o-r-" + SHA_A[:7] + "/")
    http = _Http({"/branches/": _Res(payload={"commit": {"sha": SHA_A}}), f"/tarball/{SHA_A}": _Res(content=tar)})
    tree = fetch_tree_at_head(_gh(http), "castor/x")
    assert tree.commit_sha == SHA_A
    assert tree.files_text == {"apps/a/main.py": "print(1)\n", "README.md": "h\xe9\n"}
    assert tree.skipped_binary == ["apps/a/logo.png"]
    with tarfile.open(fileobj=io.BytesIO(tree.tar_bytes)) as tf:
        assert {m.name: tf.extractfile(m).read() for m in tf.getmembers()} == FILES
    # branch names are URL-quoted, never spliced raw into the path
    assert "/branches/castor%2Fx" in http.calls[0][0]


def test_deterministic_tarball():
    assert deterministic_tar_gz(FILES) == deterministic_tar_gz(dict(reversed(list(FILES.items()))))


def test_branch_moved():
    http = _Http({"/branches/": _Res(payload={"commit": {"sha": SHA_B}})})
    with pytest.raises(BranchMovedError) as e:
        fetch_tree_at_head(_gh(http), "b", expected_sha=SHA_A)
    assert e.value.actual_sha == SHA_B


@pytest.mark.parametrize("responses", [
    {"/branches/": _Res(status=502)},
    {"/branches/": _Res(payload={"commit": {"sha": "short"}})},
    {"/branches/": ConnectionError("dns")},
    {"/branches/": _Res(payload={"commit": {"sha": SHA_A}}), "/tarball/": _Res(status=500)},
    {"/branches/": _Res(payload={"commit": {"sha": SHA_A}}), "/tarball/": _Res(content=b"")},
    {"/branches/": _Res(payload={"commit": {"sha": SHA_A}}), "/tarball/": _Res(content=make_tar(FILES, prefix="p/")[:-40])},
])
def test_github_failures_raise(responses):
    with pytest.raises(BranchFetchError):
        fetch_tree_at_head(_gh(_Http(responses)), "b")


def test_github_without_token_or_repo_raises():
    with pytest.raises(BranchFetchError):
        GitHubSource("o/r", "", _Http({}))
    with pytest.raises(BranchFetchError):
        GitHubSource("norepo", "t", _Http({}))


def _link(name, target, kind=tarfile.SYMTYPE):
    ti = tarfile.TarInfo(name)
    ti.type, ti.linkname = kind, target
    return ti


@pytest.mark.parametrize("archive", [
    make_tar({"a.py": b"x"}, extra=[_link("evil", "/etc/passwd")]),
    make_tar({"a.py": b"x"}, extra=[_link("rel", "a.py")]),
    make_tar({"a.py": b"x"}, extra=[_link("hard", "a.py", tarfile.LNKTYPE)]),
    make_tar(dict([(PARENT_ESCAPE, b"x")])),
    make_tar(dict([(ABSOLUTE, b"x")])),
    make_tar(dict([(GIT_INTERNAL, b"x")])),
    make_tar({}),
    b"not a tarball",
])
def test_unsafe_or_empty_archives_raise(archive):
    with pytest.raises(BranchFetchError):
        normalize_archive(archive, strip_top_dir=False)


def test_github_tarball_must_have_single_top_dir():
    with pytest.raises(BranchFetchError):
        normalize_archive(make_tar({"a/x.py": b"1", "b/y.py": b"2"}), strip_top_dir=True)


def test_serverless_requires_commit_sha_header():
    tar = make_tar({"a.py": b"x = 1\n"})
    no_header = ServerlessGitSource("https://git.example", "app", {}, _Http({"/archive/": _Res(content=tar)}))
    with pytest.raises(BranchFetchError, match="X-Commit-Sha"):
        fetch_tree_at_head(no_header, "main")
    ok = ServerlessGitSource("https://git.example", "app", {"Authorization": "Bearer t"},
                             _Http({"/archive/": _Res(content=tar, headers={"X-Commit-Sha": SHA_A})}))
    tree = fetch_tree_at_head(ok, "castor/x")
    assert tree.commit_sha == SHA_A and tree.files_text == {"a.py": "x = 1\n"}


def test_is_commit_sha():
    assert is_commit_sha(SHA_A)
    for bad in ("A" * 40, "a" * 39, "g" * 40, None, 1, "a" * 41):
        assert not is_commit_sha(bad)

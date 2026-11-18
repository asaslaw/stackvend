"""FD-12 / FD-4AY: owner-specific identifiers stay out of the shipped tree (everything tracked except docs/).

The identifiers themselves are never written down here: tests/owner_identifiers.py holds only their SHA-256 digests.
Every remaining occurrence is an explicit, reviewed exception below (file -> identifier keys allowed there). A new hit
fails with its file:line and key; replace it with configuration (env / tfvars) or a documentation placeholder.
"""
import hermetic_guard  # noqa: F401  (first import)

import os
import subprocess

import pytest

from owner_identifiers import IDENTIFIER_DIGESTS, find

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

ALLOWED = {
    # FD-4AY (owner 10-26): the six github_identity.py copies carry no exception any more (neutral
    # SERVERLESS_GIT_NAMESPACE), so an owner identifier reappearing there fails this test.
    # D-10 (owner 10-26): eval/run_examples.py carries no exception any more (neutral EVAL_GITHUB_ORG_DEFAULT), so
    # the owner's org reappearing there fails this test.
    # eval baseline artifacts: no exception any more (FD-4BI 1b/6, 11-16): the eval service account identity is
    # scrubbed to "<eval-service-account>" and product_root is the neutral "<product-root>", so an owner identifier
    # reappearing there fails this test.
    # Agent rule sheet names the two dev installs (deploy rules); needs a public variant before export (FD-4BI 1b).
    "AGENTS.md": {"host_project_a", "host_project_b"},
    # Maintainer handle (owner decision with the public repo slug; the slug itself is allowed everywhere).
    ".github/CODEOWNERS": {"owner_handle"},
    # owner 10-26 (release checklist D-2): conduct reports go to the maintainer's GitHub handle
    "CODE_OF_CONDUCT.md": {"owner_handle"},
}

# Exceptions for files that never reach the public repository: scripts/release/fresh_history.sh drops the eval baseline
# artifacts and replaces AGENTS.md with a public variant. They exist so the private tree can pass, so they lapse in the
# public tree (below): there, an identifier appearing in one of these paths fails the guard like anywhere else.
PRIVATE_TREE_ONLY = {"AGENTS.md"}
# The exporter is the boundary: tracked in the private repository only (the export excludes scripts/release/).
EXPORTER = "scripts/release/fresh_history.sh"


def _tracked_files():
    try:
        inside = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=REPO_ROOT,
                                capture_output=True, text=True)
    except OSError:
        inside = None
    if inside is None or inside.returncode != 0 or inside.stdout.strip() != "true":
        pytest.skip("not a git work tree (e.g. an exported tarball): the tracked-file list is unavailable")
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO_ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p and not p.startswith("docs/")]


def _exceptions_in_force(tracked):
    """Every reviewed exception in the private repository; only the shipped ones in an exported tree."""
    if EXPORTER in tracked:
        return ALLOWED
    return {rel: keys for rel, keys in ALLOWED.items() if rel not in PRIVATE_TREE_ONLY}


def _read_text(path):
    with open(path, "rb") as fh:
        data = fh.read()
    if b"\0" in data[:4096]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def test_no_owner_identifiers_outside_reviewed_exceptions():
    hits = []
    tracked = _tracked_files()
    exceptions = _exceptions_in_force(set(tracked))
    for rel in tracked:
        path = os.path.join(REPO_ROOT, rel)
        if os.path.islink(path) or not os.path.isfile(path):
            continue  # symlinks, and tracked files deleted in this working tree
        text = _read_text(path)
        if text is None:
            continue
        allowed = exceptions.get(rel, set())
        hits += [f"{rel}:{n}: {key}" for n, key in find(text) if key not in allowed]
    assert hits == []


def test_exceptions_are_still_needed():
    """A stale exception hides nothing today but would silently allow a regression later."""
    stale = []
    files = set(_tracked_files())
    for rel, keys in _exceptions_in_force(files).items():
        assert keys <= set(IDENTIFIER_DIGESTS), rel
        path = os.path.join(REPO_ROOT, rel)
        if rel not in files:
            stale.append(f"{rel}: not tracked")
            continue
        if not os.path.isfile(path):
            stale.append(f"{rel}: missing in this working tree")
            continue
        found = {key for _n, key in find(_read_text(path) or "")}
        stale += [f"{rel}: {k}" for k in sorted(keys - found)]
    assert stale == []


def test_private_only_exceptions_lapse_in_the_public_tree():
    """An export carries the exemption for none of the files it drops or replaces, and keeps every other one."""
    assert PRIVATE_TREE_ONLY <= set(ALLOWED)  # a typo here would quietly keep or lift the wrong exception
    assert _exceptions_in_force({EXPORTER, "README.md"}) == ALLOWED
    public = _exceptions_in_force({"README.md"})
    assert set(public) == set(ALLOWED) - PRIVATE_TREE_ONLY and public
    assert all(public[rel] == ALLOWED[rel] for rel in public)


def test_detector_on_synthetic_identifiers(monkeypatch):
    """The detector itself, with synthetic digests only (no real identifier appears in this file)."""
    import hashlib

    import owner_identifiers as oi

    assert find("folders/123456789012 example-org/castor-x stackvend-agent@noreply.invalid") == []

    def dg(s):
        return hashlib.sha256(s.encode()).hexdigest()

    table = {"owner_org": (dg("zzorgzz"), 7), "owner_handle": (dg("zzme"), 4), "domain_a": (dg("zz.example"), 10),
             "home_path": (dg("users/zzme"), 10), "billing": (dg("00aa11-22bb33-44cc55"), 20)}
    monkeypatch.setattr(oi, "_BY_DIGEST", {d: k for k, (d, _n) in table.items()})
    monkeypatch.setattr(oi, "_LENGTHS", {n for _d, n in table.values()} | {len("zzme/zzpublic")})
    monkeypatch.setattr(oi, "PUBLIC_SLUG", (dg("zzme/zzpublic"), len("zzme/zzpublic")))
    oi._digest.cache_clear()
    oi.token_hits.cache_clear()
    text = "\n".join([
        'GITHUB_ORG = "ZZorgZZ"',                          # case-folded
        "https://github.com/zzorgzz/castor-x",               # URL component
        "agent@zz.example host git.zz.example",              # e-mail domain and dot-suffix
        "/Users/zzme/repo",                                  # path pair
        "billing_account = 00AA11-22BB33-44CC55",
        "see https://github.com/zzme/zzpublic/issues",       # public slug: handle allowed
        "@zzme owns this; zzorgzzextra is not a hit",
    ])
    assert find(text) == [(1, "owner_org"), (2, "owner_org"), (3, "domain_a"), (3, "domain_a"),
                          (4, "home_path"), (4, "owner_handle"), (5, "billing"), (7, "owner_handle")]
    assert find(text, {"billing"}) == [(5, "billing")]
    oi._digest.cache_clear()
    oi.token_hits.cache_clear()


def test_detector_labels_and_hyphen_pieces(monkeypatch):
    """Release-preview sweep: a project id as an e-mail host label and a project number inside a Cloud Run URL."""
    import hashlib

    import owner_identifiers as oi

    def dg(s):
        return hashlib.sha256(s.encode()).hexdigest()

    table = {"proj": (dg("zzproj-123"), 10), "num": (dg("987650000001"), 12)}
    monkeypatch.setattr(oi, "_BY_DIGEST", {d: k for k, (d, _n) in table.items()})
    monkeypatch.setattr(oi, "_LENGTHS", {n for _d, n in table.values()} | {oi.PUBLIC_SLUG[1]})
    oi._digest.cache_clear()
    oi.token_hits.cache_clear()
    text = "\n".join([
        "sa-x@zzproj-123.iam.gserviceaccount.com",                # project id as the first host label
        "https://svc-987650000001.us-central1.run.app/x",         # project number as a hyphen piece
        "zzproj-1234 svc-9876500000012.run.app zzproj-12",       # near misses: longer/shorter values are not hits
    ])
    assert find(text) == [(1, "proj"), (2, "num")]
    oi._digest.cache_clear()
    oi.token_hits.cache_clear()

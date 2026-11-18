#!/usr/bin/env python3
"""
StackVend build-time vendoring tool (FD-61, Wave 2 lane 12).

Root ``shared/`` (and, for the Control Center, ``infra/modules/``) is the single source of truth.
Each Cloud Run build context is one service directory, so the paths listed for that service in
``deploy/vendor-manifest.json`` are copied into the context at build time.

Phase 0 status: this tool is NOT wired into the Cloud Build triggers or ``scripts/deploy-services.sh``
yet. Today it is used by ``tests/test_shared_packaging.py`` and to produce drift reports.

Subcommands (stdlib only, Python >= 3.9):
  stage --service DIR --out DIR      copy DIR plus its vendored paths into a fresh directory outside the repo
  stage --service DIR --in-place --ci
                                     same, into DIR itself (CI only: needs --ci, and refuses a vendored path in DIR
                                     that has uncommitted or untracked git changes)
  sync  [--check]                    report drift between root and every committed replica (never writes)
  sync  --write ROOT_FILE [...]      copy the named root files over every committed replica that tracks them
  report [--json] [--tree-hash]      full inventory: drift, closures, requirements, out-of-context imports, stubs
  build-info --service DIR [--out F] print or write the _build_info.json document for a service

Every failure exits non-zero. Nothing is silently skipped.

Safety rules (lane 12 Phase 0 code red-team F2/F4/F5):
- every manifest path (consumer keys, vendored paths, module copies) must be a plain relative posix path inside the
  repository: no absolute paths, drives, ``..``/``.`` parts, backslashes or redundant separators;
- ``stage`` checks containment on the resolved filesystem before any unlink/rmtree, refuses symlinks inside a
  vendored source tree, and validates everything before it writes anything.

``REPO_ROOT`` is derived from this script's own location, so ``python3 <checkout>/deploy/vendor_shared.py ...`` always
acts on that checkout, whatever the current working directory is.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Iterable, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "deploy" / "vendor-manifest.json"
BUILD_INFO_NAME = "_build_info.json"
BUILD_INFO_SCHEMA = 1

_IGNORE_DIRS = {"__pycache__", ".pytest_cache", ".venv", "venv", ".git", ".terraform", ".mypy_cache"}
_IGNORE_SUFFIXES = (".pyc", ".pyo")
_IGNORE_FILES = {".DS_Store"}  # Finder metadata: never part of a vendored tree or its hash (code RT F9)

# Explicit import-name -> distribution map for the per-service requirements check. Longest dotted prefix wins.
# An import that is missing from this map fails the packaging test on purpose (add it here; never guess).
DIST_FOR_IMPORT: Dict[str, str] = {
    "fastapi": "fastapi",
    "starlette": "fastapi",
    "uvicorn": "uvicorn",
    "pydantic": "pydantic",
    "httpx": "httpx",
    "requests": "requests",
    "tenacity": "tenacity",
    "yaml": "pyyaml",
    "jinja2": "jinja2",
    "github": "pygithub",
    "jwt": "pyjwt",
    "dulwich": "dulwich",
    "git": "gitpython",
    "google.auth": "google-auth",
    "google.oauth2": "google-auth",
    "google.api_core": "google-api-core",
    "google.cloud.firestore": "google-cloud-firestore",
    "google.cloud.firestore_v1": "google-cloud-firestore",
    "google.cloud.storage": "google-cloud-storage",
    "google.cloud.pubsub_v1": "google-cloud-pubsub",
    "google.cloud.secretmanager": "google-cloud-secret-manager",
    "google.cloud.logging": "google-cloud-logging",
    "google.cloud.billing": "google-cloud-billing",
    "google.cloud.run_v2": "google-cloud-run",
    "google.cloud.resourcemanager_v3": "google-cloud-resource-manager",
    "google.cloud.workflows": "google-cloud-workflows",
    "google.cloud.workflows_v1": "google-cloud-workflows",
    "google.cloud.aiplatform": "google-cloud-aiplatform",
    "google.genai": "google-genai",
    "googleapiclient": "google-api-python-client",
    "vertexai": "google-cloud-aiplatform",
    "sse_starlette": "sse-starlette",
    "itsdangerous": "itsdangerous",
    "multipart": "python-multipart",
    "authlib": "authlib",
    "cryptography": "cryptography",
    "markdown": "markdown",
    "bleach": "bleach",
    "kubernetes": "kubernetes",
    "dotenv": "python-dotenv",
    "urllib3": "urllib3",
    "packaging": "packaging",  # apps/qa-runner/sandbox_job.py (lane 3 PR-B RT F1: PEP 508 parsing)
    "hcl2": "python-hcl2",       # Step 1 (S1-A/S1-B): gateway assembly + validators
    "pyflakes": "pyflakes",      # Step 1 (S1-B): V3a undefined-name validator
}


class VendorError(Exception):
    """Raised for every vendoring failure; the CLI turns it into a non-zero exit."""


# ---------------------------------------------------------------------------------------------- basics
def check_repo_relpath(p: object, what: str) -> str:
    """Return ``p`` if it is a plain relative posix path that stays inside the repository; raise otherwise.

    Rejects: non-strings, empty, absolute (posix or Windows anchor/drive), backslashes, ``.``/``..`` parts, and any
    spelling that does not normalize to itself (``a//b``, ``a/``, ``./a``). An absolute path would make
    ``target / p`` *be* that path, so ``stage`` would rmtree it (code RT F2).
    """
    if not isinstance(p, str) or not p:
        raise VendorError(f"{what}: must be a non-empty string, got {p!r}")
    pure = PurePosixPath(p)
    if (pure.is_absolute() or PureWindowsPath(p).anchor or "\\" in p
            or any(part in ("..", ".") for part in p.split("/")) or pure.as_posix() != p):
        raise VendorError(f"{what}: {p!r} is not a plain relative path inside the repository")
    return p


def _require_inside(path: Path, base: Path, what: str) -> None:
    """``path`` (its parent resolved, its last component kept literally) must lie strictly inside ``base``.

    The last component is not resolved on purpose: a symlinked ``svc/shared -> ../shared`` is a link *inside* the
    target and is unlinked, never followed.
    """
    base_r = base.resolve()
    candidate = path.parent.resolve() / path.name
    if candidate == base_r or base_r not in candidate.parents:
        raise VendorError(f"{what}: {candidate} escapes {base_r}")


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("schema") != 1 or not isinstance(data.get("consumers"), dict):
        raise VendorError(f"{path}: unsupported manifest (need schema 1 with a 'consumers' map)")
    for consumer, paths in data["consumers"].items():
        check_repo_relpath(consumer, f"{path}: consumer key")
        if not isinstance(paths, list) or not paths:
            raise VendorError(f"{path}: consumer {consumer!r} must map to a non-empty list of repo paths")
        for p in paths:
            check_repo_relpath(p, f"{path}: vendored path of {consumer!r}")
    data.setdefault("module_copies", {})
    if not isinstance(data["module_copies"], dict):
        raise VendorError(f"{path}: 'module_copies' must be a map of copy -> root source")
    for copy, source in data["module_copies"].items():
        check_repo_relpath(copy, f"{path}: module copy")
        check_repo_relpath(source, f"{path}: module copy source of {copy!r}")
    return data


def _ignored(rel_parts: Tuple[str, ...]) -> bool:
    return (any(p in _IGNORE_DIRS for p in rel_parts[:-1]) or rel_parts[-1].endswith(_IGNORE_SUFFIXES)
            or rel_parts[-1] in _IGNORE_FILES)


def iter_tree_files(root: Path) -> List[str]:
    """Sorted posix relative paths of every regular file under ``root`` (filesystem, not git)."""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _IGNORE_DIRS)
        for name in filenames:
            rel = Path(dirpath, name).relative_to(root)
            if _ignored(rel.parts):
                continue
            out.append(rel.as_posix())
    return sorted(out)


def tree_hash(root: Path) -> str:
    """Content hash of a vendored tree: sha256 over sorted ``relpath NUL sha256(file)`` lines.

    ``_build_info.json`` at the top level is excluded, so a staged ``shared/`` hashes the same as root ``shared/``.
    """
    h = hashlib.sha256()
    for rel in iter_tree_files(root):
        if rel == BUILD_INFO_NAME:
            continue
        digest = hashlib.sha256((root / rel).read_bytes()).hexdigest()
        h.update(f"{rel}\0{digest}\n".encode("utf-8"))
    return h.hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_tracked(repo_root: Path, prefix: str) -> Optional[List[str]]:
    """Tracked files under ``prefix`` (repo-relative posix), or None when git is unavailable."""
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z", "--", prefix],
            capture_output=True, check=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return sorted(p for p in res.stdout.decode("utf-8").split("\0") if p)


def list_repo_files(repo_root: Path, prefix: str) -> List[str]:
    tracked = git_tracked(repo_root, prefix)
    if tracked is not None:
        return [p for p in tracked if (repo_root / p).is_file()]
    base = repo_root / prefix
    if base.is_file():
        return [prefix]
    if not base.is_dir():
        return []
    return [f"{prefix.rstrip('/')}/{rel}" for rel in iter_tree_files(base)]


def _resolve_git_sha(repo_root: Path, explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    for var in ("COMMIT_SHA", "GITHUB_SHA"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        res = subprocess.run(["git", "-C", str(repo_root), "rev-parse", "HEAD"],
                             capture_output=True, check=True, timeout=30)
        return res.stdout.decode().strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def build_info(service: str, repo_root: Path = REPO_ROOT, manifest_path: Path = MANIFEST_PATH,
               git_sha: Optional[str] = None) -> dict:
    """The ``shared/_build_info.json`` document (deterministic: no timestamps)."""
    manifest = load_manifest(manifest_path)
    return {
        "schema": BUILD_INFO_SCHEMA,
        "service": service,
        "vendored": list(manifest["consumers"].get(service, [])),
        "shared_tree_sha256": tree_hash(repo_root / "shared"),
        "manifest_sha256": file_sha256(manifest_path),
        "git_sha": _resolve_git_sha(repo_root, git_sha),
    }


# ---------------------------------------------------------------------------------------------- stage
def _copytree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*_IGNORE_DIRS, *_IGNORE_FILES, "*.pyc", "*.pyo"),
                    symlinks=False)


def _symlinks_in(root: Path) -> List[str]:
    """Symlinks (files or dirs) under ``root``; os.walk does not follow them, so each is reported once."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]
        for name in list(dirnames) + filenames:
            if Path(dirpath, name).is_symlink():
                found.append(Path(dirpath, name).relative_to(root).as_posix())
    return sorted(found)


def _git_toplevel(path: Path) -> Optional[Path]:
    try:
        res = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                             capture_output=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    out = res.stdout.decode().strip()
    return Path(out).resolve() if out else None


def _dirty_vendored_paths(repo_root: Path, service: str, vendored: List[str]) -> List[str]:
    """``git status --porcelain`` lines (modified, staged, deleted or untracked) inside the in-place targets.

    Only when ``repo_root`` is itself the top of a git work tree; a CI workspace without ``.git`` has no operator
    edits to lose (code RT F4).
    """
    if _git_toplevel(repo_root) != repo_root.resolve():
        return []
    paths = [f"{service}/{p}" for p in vendored]
    try:
        res = subprocess.run(["git", "-C", str(repo_root), "status", "--porcelain", "--untracked-files=all", "--",
                              *paths], capture_output=True, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise VendorError(f"cannot verify that {paths} are clean: {exc}") from exc
    return [ln for ln in res.stdout.decode("utf-8", "replace").splitlines() if ln.strip()]


def stage(service: str, out: Optional[Path] = None, in_place: bool = False, ci: bool = False,
          repo_root: Path = REPO_ROOT, manifest_path: Path = MANIFEST_PATH,
          git_sha: Optional[str] = None) -> Path:
    """Build the deployable context for ``service``. Always replaces vendored paths; never merges.

    Everything is validated before the first write: path shapes, containment, symlinks, the CI switch and (in place)
    a clean git state for the paths about to be replaced.
    """
    manifest = load_manifest(manifest_path)
    service = check_repo_relpath(service.rstrip("/"), "--service")
    src_dir = repo_root / service
    _require_inside(src_dir, repo_root, "--service")
    if not src_dir.is_dir():
        raise VendorError(f"service directory not found: {src_dir}")
    vendored = manifest["consumers"].get(service, [])
    for p in vendored:
        source = repo_root / p
        _require_inside(source, repo_root, f"manifest path {p!r}")
        if not source.is_dir() or source.is_symlink():
            raise VendorError(f"manifest path {p!r} for {service} does not exist under {repo_root} as a real directory")
        links = _symlinks_in(source)
        if links:
            raise VendorError(f"refusing to vendor {p!r}: it contains symlinks whose targets would ship in the image "
                              f"(code RT F5): {links[:10]}")

    if in_place == (out is not None):
        raise VendorError("pass exactly one of --out or --in-place")
    if in_place:
        if not ci:
            raise VendorError("--in-place rewrites the service directory; it runs only in CI and needs an explicit "
                              "--ci (no environment sniffing). Use --out <tempdir> locally.")
        target = src_dir
        dirty = _dirty_vendored_paths(repo_root, service, vendored)
        if dirty:
            raise VendorError(f"refusing --in-place: uncommitted or untracked changes in {service} vendored paths "
                              f"would be destroyed: {dirty[:10]}")
    else:
        target = Path(out).resolve()
        repo = repo_root.resolve()
        if target == repo or repo in target.parents:
            raise VendorError(f"--out must be outside the repository ({target}); stale copies there would "
                              "shadow root shared/ in local runs and tests")
        if target.exists() and any(target.iterdir()):
            raise VendorError(f"--out directory is not empty: {target}")
    for p in vendored:  # containment of every destination before anything is removed or written
        _require_inside(target / p, target, f"destination for {p!r}")

    if out is not None:
        if target.exists():
            target.rmdir()
        _copytree(src_dir, target)

    for p in vendored:
        dest = target / p
        _require_inside(dest, target, f"destination for {p!r}")
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        elif dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        _copytree(repo_root / p, dest)
    if "shared" in vendored:
        info = build_info(service, repo_root, manifest_path, git_sha)
        (target / "shared" / BUILD_INFO_NAME).write_text(json.dumps(info, indent=2, sort_keys=True) + "\n",
                                                        encoding="utf-8")
    return target


# ---------------------------------------------------------------------------------------------- drift
def replica_pairs(repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None) -> List[Tuple[str, str]]:
    """(replica, root source) pairs for every committed copy: per-consumer vendored dirs + module copies."""
    manifest = manifest or load_manifest()
    pairs: List[Tuple[str, str]] = []
    for consumer, paths in sorted(manifest["consumers"].items()):
        for p in paths:
            prefix = f"{consumer}/{p}"
            for rel in list_repo_files(repo_root, prefix):
                tail = rel[len(prefix) + 1:]
                if tail == BUILD_INFO_NAME:
                    continue
                pairs.append((rel, f"{p}/{tail}"))
    for copy, source in sorted(manifest["module_copies"].items()):
        if (repo_root / copy).exists():
            pairs.append((copy, source))
    return pairs


def drift(repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None) -> List[dict]:
    """Every replica that is not byte-identical to its root source (status ``differs`` or ``orphan``)."""
    out = []
    for replica, source in replica_pairs(repo_root, manifest):
        src = repo_root / source
        if not src.is_file():
            out.append({"replica": replica, "source": source, "status": "orphan"})
            continue
        a, b = (repo_root / replica).read_bytes(), src.read_bytes()
        if a != b:
            out.append({"replica": replica, "source": source, "status": "differs",
                        "replica_lines": a.count(b"\n"), "source_lines": b.count(b"\n")})
    return out


def _git_head_bytes(repo_root: Path, rel: str) -> Optional[bytes]:
    try:
        res = subprocess.run(["git", "-C", str(repo_root), "show", f"HEAD:{rel}"],
                             capture_output=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout


def sync_write(files: Iterable[str], repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None,
               allow_drifted: bool = False) -> List[str]:
    """Copy the named root files over every committed replica that already tracks them. Returns written paths.

    Do No Harm / owner behavior rule: a replica that matches neither the committed (HEAD) root version nor the
    current root has its own drift, i.e. a service ships different code today. Overwriting it would change that
    service, so it is refused unless ``allow_drifted`` (Phase 1 reconcile, after an approved register row).
    Without git, the HEAD comparison falls back to the current root bytes.
    """
    manifest = manifest or load_manifest()
    wanted = {check_repo_relpath(f.rstrip("/"), "sync --write") for f in files if f.rstrip("/")}
    if not wanted:
        raise VendorError("sync --write needs explicit root files (whole-tree regeneration is Phase 1)")
    for f in wanted:
        if not (repo_root / f).is_file():
            raise VendorError(f"not a root file: {f}")
    targets = [(r, s) for r, s in replica_pairs(repo_root, manifest) if s in wanted]
    if not targets:
        raise VendorError(f"no committed replica tracks {sorted(wanted)}")
    if not allow_drifted:
        drifted = []
        for replica, source in targets:
            current_root = (repo_root / source).read_bytes()
            baseline = _git_head_bytes(repo_root, source)
            current = (repo_root / replica).read_bytes()
            if current not in (current_root, baseline if baseline is not None else current_root):
                drifted.append(replica)
        if drifted:
            raise VendorError("refusing to overwrite replicas that already differ from root (a service ships "
                              f"different code today): {drifted}. Reconcile first (Phase 1) or pass "
                              "--allow-drifted with an approved behavior-change register row.")
    written = []
    for replica, source in targets:
        _require_inside(repo_root / replica, repo_root, f"replica {replica!r}")
        shutil.copyfile(repo_root / source, repo_root / replica)
        written.append(replica)
    return written


# ---------------------------------------------------------------------------------------------- AST analysis
def _is_test_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py" or "/tests/" in f"/{rel}"


def consumer_source_files(service: str, repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None) -> List[str]:
    """Non-test .py files the service owns (vendored destinations excluded)."""
    manifest = manifest or load_manifest()
    excluded = tuple(f"{service}/{p}/" for p in manifest["consumers"].get(service, []))
    return [f for f in list_repo_files(repo_root, service)
            if f.endswith(".py") and not f.startswith(excluded) and not _is_test_file(f[len(service) + 1:])]


def _parse(path: Path) -> Optional[ast.Module]:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError):
        return None


def shared_module_file(modname: str, repo_root: Path = REPO_ROOT) -> Optional[Path]:
    base = repo_root / "shared" / Path(*modname.split("."))
    if base.with_suffix(".py").is_file():
        return base.with_suffix(".py")
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    return None


def _shared_imports(tree: ast.Module, own_module: Optional[str]) -> Set[str]:
    """``shared`` submodules referenced by a file. ``own_module`` = dotted name inside shared (for relative imports)."""
    found: Set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            if n.level == 0 and n.module and n.module.split(".")[0] == "shared":
                rest = n.module.split(".")[1:]
                if rest:
                    found.add(".".join(rest))
                else:
                    found.update(a.name for a in n.names)
            elif n.level > 0 and own_module is not None:
                pkg = own_module.split(".")[:-1]
                pkg = pkg[: len(pkg) - (n.level - 1)] if n.level > 1 else pkg
                if n.module:
                    found.add(".".join(pkg + n.module.split(".")))
                else:
                    found.update(".".join(pkg + [a.name]) for a in n.names)
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name.startswith("shared."):
                    found.add(a.name[len("shared."):])
    return found


def shared_closure(service: str, repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None) -> Set[str]:
    """Dotted ``shared`` modules transitively imported by the service's own (non-test) code."""
    todo: List[str] = []
    for f in consumer_source_files(service, repo_root, manifest):
        tree = _parse(repo_root / f)
        if tree is not None:
            todo.extend(_shared_imports(tree, None))
    seen: Set[str] = set()
    while todo:
        mod = todo.pop()
        if mod in seen:
            continue
        seen.add(mod)
        path = shared_module_file(mod, repo_root)
        if path is None:
            continue
        own = mod + ".__init__" if path.name == "__init__.py" else mod
        tree = _parse(path)
        if tree is not None:
            todo.extend(_shared_imports(tree, own))
    return {m for m in seen if shared_module_file(m, repo_root) is not None}


def committed_shared_modules(service: str, repo_root: Path = REPO_ROOT) -> Set[str]:
    prefix = f"{service}/shared/"
    mods = set()
    for f in list_repo_files(repo_root, f"{service}/shared"):
        if f.endswith(".py"):
            mod = f[len(prefix):-3].replace("/", ".")
            mods.add(mod[: -len(".__init__")] if mod.endswith(".__init__") else mod)
    return mods - {"__init__"}


def out_of_context_path_inserts(service: str, repo_root: Path = REPO_ROOT,
                                manifest: Optional[dict] = None) -> List[dict]:
    """``sys.path.insert/append`` calls in service code whose target is outside the build directory."""
    manifest = manifest or load_manifest()
    svc_root = (repo_root / service).resolve()
    out = []
    for f in consumer_source_files(service, repo_root, manifest):
        path = repo_root / f
        tree = _parse(path)
        if tree is None:
            continue
        assigns: Dict[str, ast.AST] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                assigns.setdefault(n.targets[0].id, n.value)
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr in ("insert", "append")
                    and isinstance(n.func.value, ast.Attribute) and n.func.value.attr == "path"
                    and isinstance(n.func.value.value, ast.Name) and n.func.value.value.id == "sys"):
                continue
            arg = n.args[-1] if n.args else None
            if isinstance(arg, ast.Name) and arg.id in assigns:
                arg = assigns[arg.id]
            consts = [c for c in ast.walk(arg) if isinstance(c, ast.Constant) and isinstance(c.value, str)] \
                if arg is not None else []
            parts = [c.value for c in sorted(consts, key=lambda c: (c.lineno, c.col_offset))]  # source order
            uses_file = arg is not None and any(isinstance(c, ast.Name) and c.id == "__file__" for c in ast.walk(arg))
            if not uses_file:
                continue
            dirname_calls = sum(1 for c in ast.walk(arg) if isinstance(c, ast.Attribute) and c.attr == "dirname")
            parents_idx = [c.slice.value for c in ast.walk(arg)
                           if isinstance(c, ast.Subscript) and isinstance(c.value, ast.Attribute)
                           and c.value.attr == "parents" and isinstance(c.slice, ast.Constant)
                           and isinstance(c.slice.value, int)]
            if parents_idx:
                base = path.resolve().parents[parents_idx[0]]
            else:
                base = path.resolve()
                for _ in range(max(dirname_calls, 1)):
                    base = base.parent
            target = Path(os.path.normpath(os.path.join(str(base), *[p for p in parts if p not in ("", ".")])))
            if target == svc_root or svc_root in target.parents:
                continue
            try:
                rel_target = target.relative_to(repo_root.resolve()).as_posix() or "."
            except ValueError:
                rel_target = str(target)
            out.append({"file": f, "line": n.lineno, "target": rel_target})
    return out


def _bound_names(stmt: ast.stmt) -> Set[str]:
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {stmt.name}
    if isinstance(stmt, ast.Assign):
        return {t.id for t in stmt.targets if isinstance(t, ast.Name)}
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return {stmt.target.id}
    return set()


def stub_fallbacks(service: str, repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None) -> List[dict]:
    """Module-level ``try: from shared.X import ...`` ladders whose last resort binds local stand-ins.

    Such a service still boots when ``shared`` is missing from its image, so a vendoring miss is silent (RT F2).
    """
    out = []
    for f in consumer_source_files(service, repo_root, manifest):
        tree = _parse(repo_root / f)
        if tree is None:
            continue
        for node in tree.body:
            if not isinstance(node, ast.Try):
                continue
            names: Set[str] = set()
            mods: Set[str] = set()
            for s in node.body:
                if isinstance(s, ast.ImportFrom) and s.level == 0 and s.module and s.module.split(".")[0] == "shared":
                    names.update(a.asname or a.name for a in s.names)
                    mods.add(s.module)
            if not names:
                continue
            kinds: Set[str] = set()

            def walk(try_node: ast.Try) -> None:
                for h in try_node.handlers:
                    if any(isinstance(x, ast.Raise) for x in h.body):
                        continue
                    for s in h.body:
                        if isinstance(s, ast.Try):
                            walk(s)
                        elif _bound_names(s) & names:
                            is_none = isinstance(s, ast.Assign) and isinstance(s.value, ast.Constant) \
                                and s.value.value is None
                            kinds.add("none" if is_none else "stub")
                        elif isinstance(s, ast.Pass):
                            kinds.add("undefined")

            walk(node)
            if kinds:
                out.append({"file": f, "line": node.lineno, "modules": sorted(mods), "kinds": sorted(kinds)})
    return out


def loud_shared_imports(service: str, repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None) -> List[dict]:
    """Module-level ``shared`` imports that raise when ``shared`` is absent (no try, or a ladder with no stand-in)."""
    stubbed = {(s["file"], s["line"]) for s in stub_fallbacks(service, repo_root, manifest)}
    out = []
    for f in consumer_source_files(service, repo_root, manifest):
        tree = _parse(repo_root / f)
        if tree is None:
            continue
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module \
                    and node.module.split(".")[0] == "shared":
                out.append({"file": f, "line": node.lineno, "module": node.module, "kind": "unguarded"})
            elif isinstance(node, ast.Try) and (f, node.lineno) not in stubbed:
                mods = [s.module for s in node.body if isinstance(s, ast.ImportFrom) and s.level == 0
                        and s.module and s.module.split(".")[0] == "shared"]
                if mods and not any(isinstance(x, ast.Pass) for h in node.handlers for x in h.body):
                    out.append({"file": f, "line": node.lineno, "module": mods[0], "kind": "ladder-without-stub"})
    return out


def _normalize_dist(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def requirements_dists(service: str, repo_root: Path = REPO_ROOT) -> Set[str]:
    req = repo_root / service / "requirements.txt"
    dists: Set[str] = set()
    if not req.is_file():
        return dists
    for raw in req.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = line
        for sep in ("[", "=", "<", ">", "!", "~", ";", " ", "@"):
            name = name.split(sep, 1)[0]
        if name:
            dists.add(_normalize_dist(name))
    return dists


def dist_for_import(module: str) -> Optional[str]:
    parts = module.split(".")
    for i in range(len(parts), 0, -1):
        key = ".".join(parts[:i])
        if key in DIST_FOR_IMPORT:
            return DIST_FOR_IMPORT[key]
    return None


def third_party_imports(service: str, repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None,
                        guarded: bool = False) -> List[dict]:
    """Third-party imports in the service's code and its shared closure.

    ``guarded=False``: module-level statements only (they run at import time and are not in try/except).
    ``guarded=True``: every other import (inside try/except, functions, or conditionals).
    """
    manifest = manifest or load_manifest()
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    svc = repo_root / service
    local_top = {p.stem if p.suffix == ".py" else p.name for p in svc.iterdir()
                 if (p.suffix == ".py" or p.is_dir())} if svc.is_dir() else set()
    shared_top = {p.stem if p.suffix == ".py" else p.name for p in (repo_root / "shared").iterdir()}
    files: List[Tuple[str, str]] = [(f, "service") for f in consumer_source_files(service, repo_root, manifest)]
    for mod in sorted(shared_closure(service, repo_root, manifest)):
        path = shared_module_file(mod, repo_root)
        files.append((path.relative_to(repo_root).as_posix(), "shared"))
    out = []
    for rel, origin in files:
        tree = _parse(repo_root / rel)
        if tree is None:
            continue
        top_level = {id(s) for s in tree.body}
        for stmt in ast.walk(tree):
            if not isinstance(stmt, (ast.Import, ast.ImportFrom)) or (id(stmt) in top_level) == guarded:
                continue
            names: List[str] = []
            if isinstance(stmt, ast.Import):
                names = [a.name for a in stmt.names]
            elif stmt.level == 0 and stmt.module:
                names = [stmt.module] if stmt.module != "google.cloud" else [f"google.cloud.{a.name}" for a in stmt.names]
            for name in names:
                top = name.split(".")[0]
                local = local_top if origin == "service" else shared_top
                if top in stdlib or top == "shared" or top in local:
                    continue
                out.append({"file": rel, "line": stmt.lineno, "import": name, "dist": dist_for_import(name)})
    return out


def requirement_gaps(service: str, repo_root: Path = REPO_ROOT, manifest: Optional[dict] = None,
                     guarded: bool = False) -> List[dict]:
    """Third-party imports whose distribution is not in the service's requirements.txt.

    Unguarded: an unmapped import is a gap too (add it to DIST_FOR_IMPORT). Guarded: unmapped names are skipped,
    because guarded ladders also try repo-local fallback names (``from service import ...``, ``apps.x``).
    """
    have = requirements_dists(service, repo_root)
    gaps = []
    for item in third_party_imports(service, repo_root, manifest, guarded=guarded):
        if item["dist"] is None:
            if not guarded:
                gaps.append(item)
        elif _normalize_dist(item["dist"]) not in have:
            gaps.append(item)
    return gaps


def payload_vs_disk(repo_root: Path = REPO_ROOT) -> List[dict]:
    """Informational (owned by lane 8 / FD-4AM): embedded golden-module payload entries that differ from disk."""
    path = repo_root / "shared" / "builtin_modules_payload.py"
    tree = _parse(path)
    payload = None
    for node in tree.body if tree else []:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "BUILTIN_MODULE_FILES":
            payload = ast.literal_eval(node.value)
        elif isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "BUILTIN_MODULE_FILES" for t in node.targets):
            payload = ast.literal_eval(node.value)
    if payload is None:
        raise VendorError(f"{path}: BUILTIN_MODULE_FILES literal not found")
    out = []
    for mod, files in sorted(payload.items()):
        for fname, content in sorted(files.items()):
            disk = repo_root / "infra" / "modules" / mod / fname
            if not disk.is_file():
                out.append({"file": f"{mod}/{fname}", "status": "payload-only"})
            elif disk.read_text(encoding="utf-8") != content:
                out.append({"file": f"{mod}/{fname}", "status": "differs"})
    return out


# ---------------------------------------------------------------------------------------------- report / CLI
def report(repo_root: Path = REPO_ROOT, manifest_path: Path = MANIFEST_PATH) -> dict:
    manifest = load_manifest(manifest_path)
    consumers = {}
    for svc in sorted(manifest["consumers"]):
        closure = shared_closure(svc, repo_root, manifest)
        committed = committed_shared_modules(svc, repo_root)
        consumers[svc] = {
            "closure": sorted(closure),
            "committed_copy": sorted(committed),
            "closure_missing_from_copy": sorted(closure - committed) if committed else [],
            "copied_but_unused": sorted(committed - closure - {"providers"}),
            "requirement_gaps": requirement_gaps(svc, repo_root, manifest),
            "guarded_requirement_gaps": requirement_gaps(svc, repo_root, manifest, guarded=True),
            "out_of_context_path_inserts": out_of_context_path_inserts(svc, repo_root, manifest),
            "stub_fallbacks": stub_fallbacks(svc, repo_root, manifest),
        }
    return {
        "shared_tree_sha256": tree_hash(repo_root / "shared"),
        "manifest_sha256": file_sha256(manifest_path),
        "replica_files": len(replica_pairs(repo_root, manifest)),
        "drift": drift(repo_root, manifest),
        "consumers": consumers,
        "golden_payload_vs_disk": payload_vs_disk(repo_root),
    }


def _print_report(rep: dict) -> None:
    print(f"shared tree sha256 : {rep['shared_tree_sha256']}")
    print(f"manifest sha256    : {rep['manifest_sha256']}")
    print(f"replica files      : {rep['replica_files']}   drifted: {len(rep['drift'])}")
    for d in rep["drift"]:
        extra = f" ({d['replica_lines']} vs root {d['source_lines']} lines)" if d["status"] == "differs" else ""
        print(f"  DRIFT {d['status']:8s} {d['replica']}  <- {d['source']}{extra}")
    for svc, c in rep["consumers"].items():
        print(f"\n== {svc}: closure {len(c['closure'])}, committed copy {len(c['committed_copy'])}")
        if c["closure_missing_from_copy"]:
            print(f"  closure modules missing from committed copy: {c['closure_missing_from_copy']}")
        if c["copied_but_unused"]:
            print(f"  copied but unused: {c['copied_but_unused']}")
        for g in c["requirement_gaps"]:
            print(f"  requirement gap: {g['file']}:{g['line']} import {g['import']} -> {g['dist'] or 'UNMAPPED'}")
        for g in c["guarded_requirement_gaps"]:
            print(f"  guarded/lazy requirement gap: {g['file']}:{g['line']} import {g['import']} -> {g['dist']}")
        for o in c["out_of_context_path_inserts"]:
            print(f"  out-of-context sys.path: {o['file']}:{o['line']} -> {o['target']}")
        for s in c["stub_fallbacks"]:
            print(f"  stub fallback ({','.join(s['kinds'])}): {s['file']}:{s['line']} {s['modules']}")
    print(f"\ngolden payload vs infra/modules (lane 8 / FD-4AM, informational): {len(rep['golden_payload_vs_disk'])}")
    for g in rep["golden_payload_vs_disk"]:
        print(f"  {g['status']:12s} {g['file']}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("stage")
    st.add_argument("--service", required=True)
    st.add_argument("--out")
    st.add_argument("--in-place", action="store_true")
    st.add_argument("--ci", action="store_true")
    st.add_argument("--git-sha")
    sy = sub.add_parser("sync")
    sy.add_argument("--check", action="store_true", help="report drift without writing (the default)")
    sy.add_argument("--write", nargs="+", metavar="ROOT_FILE")
    sy.add_argument("--allow-drifted", action="store_true",
                    help="also overwrite replicas that already differ from root (needs an approved register row)")
    rp = sub.add_parser("report")
    rp.add_argument("--json", action="store_true")
    rp.add_argument("--tree-hash", action="store_true")
    bi = sub.add_parser("build-info")
    bi.add_argument("--service", required=True)
    bi.add_argument("--out")
    bi.add_argument("--git-sha")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "stage":
            target = stage(args.service, Path(args.out) if args.out else None, args.in_place, args.ci,
                           git_sha=args.git_sha)
            print(target)
        elif args.cmd == "sync":
            if args.write:
                if args.check:
                    raise VendorError("--check and --write are mutually exclusive")
                for path in sync_write(args.write, allow_drifted=args.allow_drifted):
                    print(f"wrote {path}")
                return 0
            found = drift()
            for d in found:
                print(f"DRIFT {d['status']}: {d['replica']} <- {d['source']}")
            print(f"{len(replica_pairs())} replica files checked, {len(found)} drifted")
            return 1 if found else 0
        elif args.cmd == "report":
            if args.tree_hash:
                print(tree_hash(REPO_ROOT / "shared"))
                return 0
            rep = report()
            if args.json:
                print(json.dumps(rep, indent=2, sort_keys=True))
            else:
                _print_report(rep)
        elif args.cmd == "build-info":
            info = json.dumps(build_info(args.service.strip("/"), git_sha=args.git_sha), indent=2, sort_keys=True)
            if args.out:
                Path(args.out).write_text(info + "\n", encoding="utf-8")
            else:
                print(info)
    except VendorError as exc:
        print(f"vendor_shared: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
FD-61 (Wave 2 lane 12) Phase 0 packaging test for the build-time vendoring of root ``shared/``.

It replaces, over Phases 1-2, the per-file parity tests (``test_hcl_utils_monorepo_parity``, the path_safety /
github_provider replica parity tests, ``test_h5_replica_byte_identical``, the payload compute-cloudrun parity).

Phase 0 rule: today's known defects are pinned as strict expected failures or no-growth allowlists, named by
file, so this suite passes now and tightens as Phase 1 lands:
- a KNOWN_* entry that gets fixed turns into an XPASS (strict) or a stale-entry failure, so the entry must be
  deleted in the same change;
- anything new (new drift, a new stub fallback, a new out-of-context import, a new requirements gap) fails.

Hermetic: no network, no GCP. The staged-context subprocesses run with ``-E -s`` (no PYTHON* env, no user site), an
explicit ``sys.path`` (stage first, then the interpreter's own stdlib/site-packages, nothing else), and the
orchestrator test guard loaded *by path* from the parent's PYTHONPATH (plan RT F7.4). They never strip entries by a
repo-path prefix: the AGENTS.md venv lives at ``<repo>/.venv``, so a prefix strip would drop site-packages when the
suite runs from the main checkout (code RT F1).

Requirements contract (code RT F10): the check is deliberately NON-transitive. A module-level (unguarded) import of a
third-party package needs that package's own distribution in the consumer's requirements.txt, even if another pinned
distribution happens to pull it in (``urllib3`` via ``requests``). Fix a gap by declaring the distribution, or by
dropping the direct import; never by mapping an import to some other distribution that depends on it.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import ast
import collections
import hashlib
import sysconfig
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("stackvend_vendor_shared", REPO / "deploy" / "vendor_shared.py")
vs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vs)

MANIFEST = vs.load_manifest()
CONSUMERS = sorted(MANIFEST["consumers"])

# --------------------------------------------------------------------------------------------- pinned state
# Drift between committed replicas and root (snapshot 2026-10-12, main 2f9ac21). Phase 1 reconcile + sync empties it.
KNOWN_DRIFT = {
    "apps/control-center/shared/__init__.py": "empty vs root docstring (cosmetic)",
    "apps/git-server/shared/__init__.py": "empty vs root docstring (cosmetic)",
    "mcp-servers/github/shared/__init__.py": "empty vs root docstring (cosmetic)",
    "apps/control-center/shared/iac_upgrade_engine.py": "shipping copy is AHEAD of root (+27 lines, 8f642b6); Phase 1 adopts it as root",
    "apps/orchestrator-gateway/shared/iac_upgrade_engine.py": "shipping copy is AHEAD of root (+27 lines); Phase 1 adopts it as root",
    "apps/orchestrator-gateway/developer_agent/firestore_scanner.py": "docstring only; Phase 1 deletes this copy",
}

# Closure modules a consumer imports (lazily) that its committed copy lacks.
KNOWN_CLOSURE_GAPS = {
    ("apps/qa-runner", "settings"): "vcs_provider.py:251 / serverless_git_provider.py:107 lazy-import shared.settings; "
                                    "swallowed, so qa-runner ignores Firestore platform settings (RT F11, lane 13)",
}

# Consumers whose every module-level `shared` import ends in a local stand-in: they boot healthy without `shared/`
# in the image, so a vendoring miss is silent (RT F2). Pre-Phase-2 work converts them to direct imports (lane 14
# owns mcp-servers/github).
KNOWN_SILENT_BOOT = {
    "mcp-servers/github": "service.py:13-33 -> get_github_token from env, retry decorator = identity",
}

# Module-level stub/None/pass fallbacks for `shared` imports, per file (no growth; Phase 3 removes them).
KNOWN_STUB_LADDERS = {
    "apps/control-center/assistant.py": 1,
    "apps/control-center/routes/approvals.py": 1,
    "apps/control-center/routes/settings.py": 7,
    "apps/control-center/routes/workloads.py": 4,
    "apps/control-center/schemas.py": 2,
    "apps/orchestrator-gateway/architect_agent/handler.py": 1,
    "apps/orchestrator-gateway/architect_agent/prompt.py": 1,
    "apps/orchestrator-gateway/architect_agent/red_team_critic.py": 1,
    "apps/orchestrator-gateway/compliance_agent/handler.py": 1,
    "apps/orchestrator-gateway/compliance_agent/prompt.py": 1,
    "apps/orchestrator-gateway/developer_agent/handler.py": 5,
    "apps/orchestrator-gateway/developer_agent/lead_orchestrator.py": 1,
    "apps/orchestrator-gateway/developer_agent/prompt.py": 1,
    "apps/orchestrator-gateway/developer_agent/swarm_dispatcher.py": 1,
    "apps/orchestrator-gateway/developer_agent/terraform_engine.py": 1,
    "apps/orchestrator-gateway/main.py": 1,
    "apps/orchestrator-gateway/qa_auditor/adherence_lens.py": 2,
    "apps/orchestrator-gateway/qa_auditor/coordinator.py": 1,
    "apps/orchestrator-gateway/qa_auditor/security_lens.py": 2,
    "apps/orchestrator-gateway/release_gatekeeper.py": 2,
    "apps/project-vending/vending.py": 3,
    "apps/spec-ingestion/poller.py": 1,
    "mcp-servers/github/service.py": 1,
    "mcp-servers/terraform/service.py": 5,
}

# sys.path inserts that leave the build context (the target is absent from the image). (file, repo-relative target)
KNOWN_OUT_OF_CONTEXT = {
    ("apps/control-center/routes/approvals.py", "apps/finops-enforcer"): "CC -> finops enforcer (lane 14 decision)",
    ("apps/orchestrator-gateway/compliance_agent/handler.py", "mcp-servers/compliance"): "gw -> compliance MCP (lane 17)",
    ("apps/orchestrator-gateway/main.py", "."): "repo-root fallback for local runs",
    ("apps/orchestrator-gateway/main.py", "apps/qa-runner"): "gw -> qa-runner runner: QA never runs in prod (FD20-04, lane 13)",
    ("apps/project-vending/main.py", "."): "repo-root fallback for local runs",
    ("mcp-servers/terraform/main.py", "."): "repo-root fallback for local runs",
    ("mcp-servers/terraform/service.py", "mcp-servers/kubernetes"): "tf -> k8s MCP `service` (name clash with tf service.py)",
}

# Guarded or lazy third-party imports whose distribution is missing from the consumer's requirements.txt.
# (consumer, file, distribution); no growth.
KNOWN_GUARDED_GAPS = {
    ("apps/control-center", "shared/module_inspector.py", "pyyaml"): "lazy",
    ("apps/orchestrator-gateway", "shared/module_inspector.py", "pyyaml"): "lazy",
    ("apps/project-vending", "apps/project-vending/vending.py", "google-cloud-storage"): "lazy",
    ("apps/qa-runner", "shared/github_resilience.py", "google-cloud-secret-manager"): "lazy",
    ("apps/qa-runner", "shared/github_resilience.py", "pygithub"): "lazy (RT E4)",
    ("apps/qa-runner", "shared/github_resilience.py", "pyjwt"): "lazy (RT E4)",
    ("apps/qa-runner", "shared/providers/github_provider.py", "dulwich"): "guarded (RT E4)",
    ("apps/qa-runner", "shared/providers/github_provider.py", "pygithub"): "guarded (RT E4)",
    ("mcp-servers/terraform", "mcp-servers/terraform/service.py", "kubernetes"): "actually the k8s MCP package (out of context)",
    ("mcp-servers/terraform", "shared/github_resilience.py", "pygithub"): "lazy (RT E4)",
    ("mcp-servers/terraform", "shared/module_inspector.py", "pyyaml"): "lazy",
    ("mcp-servers/terraform", "shared/providers/github_provider.py", "dulwich"): "guarded (RT E4)",
    ("mcp-servers/terraform", "shared/providers/github_provider.py", "pygithub"): "guarded (RT E4)",
}

# Phase 0: the 5 non-shared module copies still exist (Phase 1 de-dup deletes them).
SHADOW_COPIES_PRESENT = True


# --------------------------------------------------------------------------------------------- helpers
def _build_dirs_from_deploy_script():
    # deploy-services.sh sources its SERVICES / JOBS from scripts/common/components.sh (SELFUP P3b B2)
    text = (REPO / "scripts" / "common" / "components.sh").read_text(encoding="utf-8")
    dirs = set()
    for block in re.findall(r"^(?:SERVICES|JOBS)=\((.*?)^\)", text, flags=re.S | re.M):
        dirs.update(m.group(1) for m in re.finditer(r'"[^":]+:([^"]+)"', block))
    return dirs


ALL_BUILD_DIRS = sorted(_build_dirs_from_deploy_script())


def _guard_file():
    """The orchestrator test guard (a ``sitecustomize.py`` on the parent's PYTHONPATH), or None when absent."""
    for p in os.environ.get("PYTHONPATH", "").split(os.pathsep):
        if p and (Path(p) / "sitecustomize.py").is_file():
            return str((Path(p) / "sitecustomize.py").resolve())
    return None


def _guard_env(base):
    """Child env from ``base`` (``hermetic_guard.child_env()``): its Layer-0 keys plus a minimal set, ADC disabled and
    test mode. PYTHONPATH is irrelevant (children run with -E); the guard is loaded by path instead."""
    keep = {"PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR"} | set(hermetic_guard.FORCED_ENV)
    env = {k: v for k, v in base.items() if k in keep}
    env.update({
        "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc-disabled.json",
        "CLOUDSDK_CORE_PROJECT": "mock-stackvend-project",
        "PROJECT_ID": "mock-stackvend-project",
        "GCP_PROJECT": "mock-stackvend-project",
        "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project",
        "TEST_MODE": "true",
        "DEFAULT_REGION": "us-central1",
    })
    return env


# --------------------------------------------------------------------------------------------- manifest
def test_manifest_keys_are_build_dirs_and_sources_exist():
    for consumer, paths in MANIFEST["consumers"].items():
        assert consumer in ALL_BUILD_DIRS, f"{consumer} is not a Cloud Run build directory"
        for p in paths:
            assert (REPO / p).is_dir(), f"{consumer}: vendored path {p} missing"
    for copy, source in MANIFEST["module_copies"].items():
        assert (REPO / source).is_file(), f"module copy {copy} points at missing root file {source}"


@pytest.mark.parametrize("build_dir", ALL_BUILD_DIRS)
def test_manifest_covers_every_consumer(build_dir):
    closure = vs.shared_closure(build_dir)
    if closure:
        assert "shared" in MANIFEST["consumers"].get(build_dir, []), (
            f"{build_dir} imports shared ({sorted(closure)[:5]}...) but is not a manifest consumer")


def test_control_center_vendors_golden_modules():
    assert "infra/modules" in MANIFEST["consumers"]["apps/control-center"]


# --------------------------------------------------------------------------------------------- replica identity
_PAIRS = vs.replica_pairs()


def _identity_params():
    params = []
    for replica, source in _PAIRS:
        marks = []
        if replica in KNOWN_DRIFT:
            marks.append(pytest.mark.xfail(strict=True, reason=f"known drift: {KNOWN_DRIFT[replica]}"))
        params.append(pytest.param(replica, source, marks=marks, id=replica))
    return params


@pytest.mark.parametrize("replica,source", _identity_params())
def test_replica_identical_to_root(replica, source):
    assert (REPO / source).is_file(), f"{replica} has no root counterpart {source} (orphan replica)"
    assert (REPO / replica).read_bytes() == (REPO / source).read_bytes(), (
        f"{replica} drifted from {source}: edit root and run `python3 deploy/vendor_shared.py sync --write {source}`")


def test_known_drift_entries_are_live():
    """A KNOWN_DRIFT entry for a file that is gone must be deleted (keeps the list from rotting)."""
    replicas = {r for r, _ in _PAIRS}
    stale = sorted(set(KNOWN_DRIFT) - replicas)
    assert not stale, f"delete stale KNOWN_DRIFT entries: {stale}"


def test_sync_check_never_writes_and_reports_exit_code(capsys):
    before = {r: hashlib.sha256((REPO / r).read_bytes()).hexdigest() for r, _ in _PAIRS}
    rc = vs.main(["sync", "--check"])
    after = {r: hashlib.sha256((REPO / r).read_bytes()).hexdigest() for r, _ in _PAIRS}
    assert before == after
    assert rc == (1 if vs.drift() else 0)
    assert f"{len(_PAIRS)} replica files checked" in capsys.readouterr().out


# --------------------------------------------------------------------------------------------- filesystem check (RT F8)
def _expected_replica_dirs():
    out = set()
    for consumer, paths in MANIFEST["consumers"].items():
        for p in paths:
            if vs.git_tracked(REPO, f"{consumer}/{p}"):
                out.add(f"{consumer}/{p}")
    return out


def test_filesystem_has_no_untracked_or_unexpected_replicas():
    """Checks the filesystem, not only git: a stale staged copy would shadow root shared/ in local runs."""
    found = set()
    for build_dir in ALL_BUILD_DIRS:
        base = REPO / build_dir
        for dirpath, dirnames, _ in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in vs._IGNORE_DIRS]
            for d in dirnames:
                rel = Path(dirpath, d).relative_to(REPO).as_posix()
                if d == "shared" or rel == f"{build_dir}/infra/modules":
                    found.add(rel)
    expected = _expected_replica_dirs()
    assert found == expected, f"unexpected replica dirs on disk: {sorted(found - expected)}; missing: {sorted(expected - found)}"
    for rel in sorted(expected):
        on_disk = {f"{rel}/{p}" for p in vs.iter_tree_files(REPO / rel)}  # iter_tree_files skips .DS_Store
        tracked = set(vs.git_tracked(REPO, rel) or [])
        assert on_disk <= tracked, f"untracked files inside replica {rel}: {sorted(on_disk - tracked)[:10]}"
    assert not (REPO / "shared" / vs.BUILD_INFO_NAME).exists(), "root shared/ must never carry a build-info file"


# --------------------------------------------------------------------------------------------- closure / shadowing
def _closure_params():
    params = []
    for consumer in CONSUMERS:
        missing = sorted(vs.shared_closure(consumer) - vs.committed_shared_modules(consumer)) \
            if vs.committed_shared_modules(consumer) else []
        for mod in missing or [None]:
            key = (consumer, mod)
            marks = [pytest.mark.xfail(strict=True, reason=KNOWN_CLOSURE_GAPS[key])] if key in KNOWN_CLOSURE_GAPS else []
            params.append(pytest.param(consumer, mod, marks=marks, id=f"{consumer}:{mod or 'complete'}"))
    for consumer, mod in KNOWN_CLOSURE_GAPS:
        if (consumer, mod) not in {(p.values[0], p.values[1]) for p in params}:
            params.append(pytest.param(consumer, mod, marks=[pytest.mark.xfail(strict=True, reason="stale entry")],
                                       id=f"{consumer}:{mod}:stale"))
    return params


@pytest.mark.parametrize("consumer,module", _closure_params())
def test_committed_copy_contains_closure(consumer, module):
    if module is None:
        return
    assert module in vs.committed_shared_modules(consumer), f"{consumer} imports shared.{module} but its copy lacks it"


def _shadow_offenders():
    """Service files that are a byte-copy of a root shared module, or a top-level module named like one,
    plus every manifest ``module_copies`` entry still on disk."""
    root_hashes = {hashlib.sha256((REPO / f).read_bytes()).hexdigest(): f
                   for f in vs.list_repo_files(REPO, "shared") if f.endswith(".py") and not f.endswith("__init__.py")}
    shared_names = {Path(f).stem for f in root_hashes.values()}
    offenders = {c for c in MANIFEST["module_copies"] if (REPO / c).exists()}
    for build_dir in ALL_BUILD_DIRS:
        for f in vs.list_repo_files(REPO, build_dir):
            if not f.endswith(".py") or "/shared/" in f or f in offenders:
                continue
            if hashlib.sha256((REPO / f).read_bytes()).hexdigest() in root_hashes:
                offenders.add(f)
            elif f.count("/") == build_dir.count("/") + 1 and Path(f).stem in shared_names:
                offenders.add(f)
    return offenders


@pytest.mark.xfail(SHADOW_COPIES_PRESENT, strict=True, reason="5 non-shared module copies exist until Phase 1 de-dup")
def test_no_shadow_modules():
    """No service code may carry a byte-copy of a shared module, nor a top-level module named like one."""
    offenders = _shadow_offenders()
    assert not offenders, f"shadow copies of shared modules: {sorted(offenders)}"


def test_shadow_modules_are_only_the_manifest_module_copies():
    """While test_no_shadow_modules is xfail, a NEW shadow copy must still fail (no growth, plan RT F7.5)."""
    extra = sorted(_shadow_offenders() - set(MANIFEST["module_copies"]))
    assert not extra, f"new shadow copies of shared modules (edit root shared/ instead): {extra}"


# --------------------------------------------------------------------------------------------- requirements (RT F7.1)
@pytest.mark.parametrize("consumer", CONSUMERS)
def test_unguarded_third_party_imports_are_declared(consumer):
    gaps = vs.requirement_gaps(consumer)
    assert not gaps, (f"{consumer}: import-time third-party imports missing from requirements.txt "
                      f"(or unmapped in DIST_FOR_IMPORT): {[(g['file'], g['import'], g['dist']) for g in gaps]}")


@pytest.mark.parametrize("consumer", CONSUMERS)
def test_guarded_requirement_gaps_do_not_grow(consumer):
    found = {(consumer, g["file"], g["dist"]) for g in vs.requirement_gaps(consumer, guarded=True)}
    new = sorted(found - set(KNOWN_GUARDED_GAPS))
    assert not new, f"new guarded/lazy imports missing from {consumer}/requirements.txt: {new}"


# SAT-50 (live 11-02, dev install): the Per-workload repository read of mcp-terraform-server / tf-applier built the
# shared GitHubProvider, whose PyGithub import is guarded (KNOWN_GUARDED_GAPS) -> it imported, then failed at call time
# ("PyGithub is not installed", REPO_TREE_INCOMPLETE). A code path that must work in an image may therefore reach no
# module with a guarded/lazy requirements gap there. Entry: consumer -> (file, entry functions). The path is the entry
# functions plus the same-file functions they call by name (`self.x(...)` / `x(...)`); the modules it imports are its
# own (lazy) imports plus everything those execute at import time (parent packages, module-level imports, recursively).
# Scope (RT F3), deliberately narrow, so a pass is not a proof:
# - NOT followed: the entry file's own module-level imports (e.g. service.py's `runner_credentials`,
#   `shared.github_resilience`); they are covered only by test_unguarded_third_party_imports_are_declared /
#   test_guarded_requirement_gaps_do_not_grow, which do not tie a guarded gap to this path;
# - NOT followed: calls through another object or module (`runner.credentials.repository_token()`,
#   `runner_creds.check_branch_name(...)`, `reader.fetch_file_tree(...)`), and the lazy imports inside the functions
#   of a reached module. A gap in a reached file still counts (per-file), even when this path never runs that line.
# The runtime counterpart is tests/test_fd7l_4_repo_read.py, which runs the read with `github`/`dulwich` blocked.
IMAGE_PATHS = {
    "mcp-servers/terraform": ("mcp-servers/terraform/service.py", ("_fetch_repo_files_brokered",)),
}


def _path_functions(tree, entries):
    defs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    missing = sorted(set(entries) - set(defs))
    assert not missing, f"entry functions not found: {missing}"
    todo, seen = list(entries), set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for n in ast.walk(defs[name]):
            if isinstance(n, ast.Call):
                f = n.func
                callee = (f.attr if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == "self"
                          else f.id if isinstance(f, ast.Name) else None)
                if callee in defs:
                    todo.append(callee)
    return [defs[n] for n in sorted(seen)]


def _import_time_imports(node):
    """Import statements that run when `node` (a module) is imported: not inside a function or lambda body."""
    out = []
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            out.append(child)
        elif not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            out.extend(_import_time_imports(child))
    return out


def _with_parents(mod):
    parts = mod.split(".")
    return {".".join(parts[:i]) for i in range(1, len(parts) + 1)}


def _image_path_files(consumer):
    """(repo-relative files the path executes, third-party modules it imports itself)."""
    rel, entries = IMAGE_PATHS[consumer]
    fns = _path_functions(ast.parse((REPO / rel).read_text(encoding="utf-8")), entries)
    stmts = [s for fn in fns for s in ast.walk(fn) if isinstance(s, (ast.Import, ast.ImportFrom))]
    third = sorted({a.name for s in stmts if isinstance(s, ast.Import) for a in s.names}
                   | {s.module for s in stmts if isinstance(s, ast.ImportFrom) and s.level == 0 and s.module})
    todo = [m for m in vs._shared_imports(ast.Module(body=stmts, type_ignores=[]), None)]
    seen = set()
    while todo:
        for mod in _with_parents(todo.pop()):
            if mod in seen:
                continue
            seen.add(mod)
            path = vs.shared_module_file(mod)
            if path is None:
                continue
            own = mod + ".__init__" if path.name == "__init__.py" else mod
            todo.extend(vs._shared_imports(ast.Module(body=_import_time_imports(ast.parse(path.read_text())),
                                                      type_ignores=[]), own))
    files = {vs.shared_module_file(m).relative_to(REPO).as_posix() for m in seen if vs.shared_module_file(m)}
    return files, [m for m in third if m.split(".")[0] not in sys.stdlib_module_names and m.split(".")[0] != "shared"]


def test_image_path_detector_sees_the_providers_it_imports():
    """The detector follows a lazy `shared.providers.x` import into the provider, its package and its import-time
    `..vcs_provider` import (so the SAT-50 defect, a GitHubProvider import on the path, would have been caught)."""
    tree = ast.parse("class S:\n    def a(self):\n        self.b()\n    def b(self):\n"
                     "        from shared.providers.github_provider import GitHubProvider\n")
    stmts = [s for fn in _path_functions(tree, ("a",)) for s in ast.walk(fn) if isinstance(s, ast.ImportFrom)]
    assert [s.module for s in stmts] == ["shared.providers.github_provider"]
    gaps = {(g["file"], g["dist"]) for g in vs.requirement_gaps("mcp-servers/terraform", guarded=True)}
    assert ("shared/providers/github_provider.py", "pygithub") in gaps   # what the path must not reach


@pytest.mark.parametrize("consumer", sorted(IMAGE_PATHS))
def test_image_path_needs_only_declared_packages(consumer):
    files, third = _image_path_files(consumer)
    assert files, f"{consumer}: the image path reaches no shared module (detector broken?)"
    have = vs.requirements_dists(consumer)
    undeclared = sorted(m for m in third if vs.dist_for_import(m) is None
                        or vs._normalize_dist(vs.dist_for_import(m)) not in have)
    gapped = sorted({(g["file"], g["dist"]) for g in vs.requirement_gaps(consumer, guarded=True) if g["file"] in files})
    assert not undeclared and not gapped, (
        f"{consumer}: the {IMAGE_PATHS[consumer][1]} path needs packages its requirements.txt does not declare; "
        f"own imports {undeclared}, guarded/lazy gaps in modules it reaches {gapped}")


# --------------------------------------------------------------------------------------------- out-of-context imports (RT F7.2)
@pytest.mark.parametrize("consumer", CONSUMERS)
def test_out_of_context_path_inserts_do_not_grow(consumer):
    found = {(o["file"], o["target"]) for o in vs.out_of_context_path_inserts(consumer)}
    new = sorted(found - set(KNOWN_OUT_OF_CONTEXT))
    assert not new, f"{consumer}: new sys.path inserts outside the build context (absent from the image): {new}"


# --------------------------------------------------------------------------------------------- stub fallbacks (RT F2)
def _silent_boot_params():
    return [pytest.param(c, marks=[pytest.mark.xfail(strict=True, reason=KNOWN_SILENT_BOOT[c])] if c in KNOWN_SILENT_BOOT else [],
                         id=c) for c in CONSUMERS]


@pytest.mark.parametrize("consumer", _silent_boot_params())
def test_consumer_fails_loudly_without_shared(consumer):
    loud = vs.loud_shared_imports(consumer)
    assert loud, (f"{consumer}: every module-level shared import falls back to a stand-in, so an image without "
                  f"shared/ boots healthy: {vs.stub_fallbacks(consumer)}")


def test_stub_fallback_ladders_do_not_grow():
    counts = collections.Counter()
    for consumer in CONSUMERS:
        for s in vs.stub_fallbacks(consumer):
            counts[s["file"]] += 1
    grown = {f: (n, KNOWN_STUB_LADDERS.get(f, 0)) for f, n in counts.items() if n > KNOWN_STUB_LADDERS.get(f, 0)}
    assert not grown, f"new module-level stub fallbacks for shared imports (file: found, allowed): {grown}"


def test_stub_detector_sees_the_known_silent_boot_ladders():
    """Positive control: the detector flags spec-ingestion poller.py and mcp-github service.py."""
    flagged = {s["file"] for c in ("apps/spec-ingestion", "mcp-servers/github") for s in vs.stub_fallbacks(c)}
    assert {"apps/spec-ingestion/poller.py", "mcp-servers/github/service.py"} <= flagged


# --------------------------------------------------------------------------------------------- staged context smoke
# Child prologue shared by every staged-context subprocess (run as `python -E -s -c`). argv[1] = stage dir,
# argv[2] = guard file or "", argv[3] = JSON payload. It never filters sys.path by a repo-path prefix (code RT F1).
_CHILD_PROLOGUE = r"""
import importlib, importlib.util, json, sys
stage, guard, payload = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
if guard:
    _spec = importlib.util.spec_from_file_location("sitecustomize", guard)
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules["sitecustomize"] = _mod
    _spec.loader.exec_module(_mod)
sys.path[:] = [stage] + [p for p in sys.path if p not in ("", ".")]
"""

_CHILD_CLOSURE = _CHILD_PROLOGUE + r"""
out = {}
for m in payload:
    mod = importlib.import_module("shared." + m)
    out[m] = getattr(mod, "__file__", None)
print(json.dumps({"files": out, "sys_path": sys.path,
                  "guard": getattr(sys.modules.get("sitecustomize"), "__file__", None)}))
"""

_CHILD_IDENTITY = _CHILD_PROLOGUE + r"""
import traceback
out = {}
for modname, shared_mod, names in payload:
    try:
        mod = importlib.import_module(modname)
        ref = importlib.import_module(shared_mod)
    except BaseException:
        out[f"{modname}:__error__"] = traceback.format_exc()[-2000:]
        continue
    for name in names:
        obj = getattr(mod, name, None)
        out[f"{modname}:{name}"] = {
            "defined": hasattr(mod, name),
            "module": getattr(obj, "__module__", None),
            "is_shared": hasattr(ref, name) and obj is getattr(ref, name),
            "shared_file": getattr(ref, "__file__", None),
        }
print(json.dumps(out))
"""

_STAGES = {}


def _staged(consumer, tmp_path_factory):
    """Stage each consumer once per session (outside the repo); reused by the smoke and identity tests."""
    if consumer not in _STAGES:
        _STAGES[consumer] = vs.stage(consumer, out=tmp_path_factory.mktemp("stage") / "ctx", git_sha="0" * 40)
    return _STAGES[consumer]


def _run_child(code, stage_dir, payload):
    res = subprocess.run(
        [sys.executable, "-E", "-s", "-c", code, str(stage_dir), _guard_file() or "", json.dumps(payload)],
        cwd=stage_dir.parent, env=_guard_env(hermetic_guard.child_env()), capture_output=True, text=True, timeout=300,
    )
    assert res.returncode == 0, f"staged child failed in {stage_dir}:\n{res.stderr[-3000:]}"
    return json.loads(res.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("consumer", CONSUMERS)
def test_staged_context_imports_closure_from_stage(consumer, tmp_path_factory):
    stage_dir = _staged(consumer, tmp_path_factory)
    info = json.loads((stage_dir / "shared" / vs.BUILD_INFO_NAME).read_text())
    assert info["shared_tree_sha256"] == vs.tree_hash(REPO / "shared") == vs.tree_hash(stage_dir / "shared")
    assert info["service"] == consumer and info["git_sha"] == "0" * 40
    for p in MANIFEST["consumers"][consumer]:
        assert vs.tree_hash(stage_dir / p) == vs.tree_hash(REPO / p)
    result = _run_child(_CHILD_CLOSURE, stage_dir, sorted(vs.shared_closure(consumer)))
    wrong = {m: f for m, f in result["files"].items() if not str(f).startswith(str(stage_dir))}
    assert not wrong, f"{consumer}: modules resolved outside the staged context: {wrong}"


def test_staged_child_keeps_site_packages_guard_and_no_repo_dirs(tmp_path_factory):
    """Code RT F1 / plan RT F7.4: the child must keep the interpreter's site-packages even when the venv lives
    inside the repository (AGENTS.md setup), load the test guard, and see no repo source dir on sys.path."""
    stage_dir = _staged("apps/git-server", tmp_path_factory)
    result = _run_child(_CHILD_CLOSURE, stage_dir, [])
    child_path = result["sys_path"]
    assert child_path[0] == str(stage_dir)
    assert sysconfig.get_paths()["purelib"] in child_path, "site-packages was dropped from the child's sys.path"
    repo_sources = {str(REPO), str(REPO / "shared")} | {str(REPO / d) for d in ALL_BUILD_DIRS}
    assert not repo_sources & set(child_path), f"repo source dirs leaked into the child: {repo_sources & set(child_path)}"
    assert "" not in child_path and "." not in child_path
    if _guard_file():
        assert result["guard"] == _guard_file(), "the orchestrator test guard was not loaded in the child"


# --------------------------------------------------------------------------------------------- symbol identity (plan RT F7.3)
# Every module-level `from shared.<M> import ...` (including inside try/except ladders, excluding function bodies) in
# consumer code, where <M> is a shared module that still has a hand copy (manifest `module_copies`), is checked in the
# STAGED context. Rows are derived by parsing (ast), so a lane that adds or drops such an import needs no table edit.
# `__module__` proves each name came from the real module (or its byte-identical copy), not a stub/None/`pass`
# fallback. Identity with the shared object is the Phase 1 de-dup target: IDENTITY_PENDING_DEDUP rows resolve to the
# local copy today and are strict-xfail until the de-dup commit deletes the copy (the XPASS forces the entry's removal).
IDENTITY_PENDING_DEDUP = {
    # FD-4F A9 (FS-1/FS-2): handler.py no longer has a `from shared.firestore_scanner` / `shared.workflow_validator`
    # ladder (hard package imports), so its two rows are gone. FD-55 W1: preflight_validator.py no longer imports
    # hcl_utils at all (its only imports were the deleted dedupe / label-coercion bodies), so its row is gone too.
}
_COPIED_SHARED_MODULES = sorted({src[:-3].replace("/", ".") for src in MANIFEST["module_copies"].values()})


def _module_level_shared_imports(tree, wanted):
    """{shared module: [bound names]} for level-0 `from shared.X import ...` outside function/class bodies."""
    found = collections.defaultdict(list)
    todo = list(tree.body)
    while todo:
        node = todo.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in wanted:
            for a in node.names:
                if a.name != "*" and (a.asname or a.name) not in found[node.module]:
                    found[node.module].append(a.asname or a.name)
        todo.extend(ast.iter_child_nodes(node))
    return found


def _identity_targets():
    """(consumer, importable module, shared module, names), derived from the code."""
    rows = []
    for consumer in CONSUMERS:
        for f in vs.consumer_source_files(consumer):
            if f in MANIFEST["module_copies"]:
                continue
            tree = vs._parse(REPO / f)
            if tree is None:
                continue
            modname = f[len(consumer) + 1:-3].replace("/", ".")
            modname = modname[: -len(".__init__")] if modname.endswith(".__init__") else modname
            for shared_mod, names in sorted(_module_level_shared_imports(tree, _COPIED_SHARED_MODULES).items()):
                rows.append((consumer, modname, shared_mod, sorted(names)))
    return rows


_IDENTITY_TARGETS = _identity_targets()
_IDENTITY_RESULTS = {}


def _identity(consumer, tmp_path_factory):
    if consumer not in _IDENTITY_RESULTS:
        payload = [[m, s, n] for c, m, s, n in _IDENTITY_TARGETS if c == consumer]
        _IDENTITY_RESULTS[consumer] = _run_child(_CHILD_IDENTITY, _staged(consumer, tmp_path_factory), payload)
    return _IDENTITY_RESULTS[consumer]


def _identity_rows(pending_marks):
    rows = []
    for consumer, modname, shared_mod, names in _IDENTITY_TARGETS:
        key = (consumer, modname, shared_mod)
        marks = [pytest.mark.xfail(strict=True, reason=IDENTITY_PENDING_DEDUP[key])] \
            if pending_marks and key in IDENTITY_PENDING_DEDUP else []
        rows.append(pytest.param(consumer, modname, shared_mod, names, marks=marks,
                                 id=f"{consumer}:{modname}<-{shared_mod}"))
    return rows


def test_identity_targets_cover_the_known_copy_importers():
    """Positive control for the derivation, and stale-entry guard for IDENTITY_PENDING_DEDUP."""
    keys = {(c, m, s) for c, m, s, _ in _IDENTITY_TARGETS}
    assert not set(IDENTITY_PENDING_DEDUP) - keys, f"delete stale IDENTITY_PENDING_DEDUP entries: {set(IDENTITY_PENDING_DEDUP) - keys}"
    assert ("apps/orchestrator-gateway", "architect_agent.red_team_critic", "shared.critic_schemas") in keys
    assert ("apps/control-center", "schemas", "shared.critic_schemas") in keys


@pytest.mark.parametrize("consumer,modname,shared_mod,names", _identity_rows(pending_marks=False))
def test_reexported_shared_symbols_are_real(consumer, modname, shared_mod, names, tmp_path_factory):
    """Never a stub: each name is bound to an object defined in the shared module or its byte-identical copy."""
    res = _identity(consumer, tmp_path_factory)
    err = res.get(f"{modname}:__error__")
    assert not err, f"{consumer}: importing {modname} from the staged context failed: {err}"
    leaf = shared_mod.rsplit(".", 1)[-1]
    bad = {}
    for name in names:
        row = res[f"{modname}:{name}"]
        module = row["module"] or ""
        if not row["defined"] or module.rsplit(".", 1)[-1] != leaf or module == modname:
            bad[name] = row
    assert not bad, f"{consumer} {modname}: names bound to a fallback instead of {shared_mod}: {bad}"


@pytest.mark.parametrize("consumer,modname,shared_mod,names", _identity_rows(pending_marks=True))
def test_reexported_shared_symbols_are_the_shared_objects(consumer, modname, shared_mod, names, tmp_path_factory):
    res = _identity(consumer, tmp_path_factory)
    assert not res.get(f"{modname}:__error__"), res.get(f"{modname}:__error__")
    not_shared = [n for n in names if not res[f"{modname}:{n}"]["is_shared"]]
    assert not not_shared, f"{consumer} {modname}: not the {shared_mod} objects: {not_shared}"


# --------------------------------------------------------------------------------------------- stage semantics (synthetic repo)
def _mini_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "shared" / "providers").mkdir(parents=True)
    (repo / "shared" / "__init__.py").write_text('"""root"""\n')
    (repo / "shared" / "a.py").write_text("A = 1\n")
    (repo / "shared" / "providers" / "__init__.py").write_text("")
    (repo / "svc" / "shared").mkdir(parents=True)
    (repo / "svc" / "main.py").write_text("from shared.a import A\n")
    (repo / "svc" / "shared" / "a.py").write_text("A = 0  # old\n")
    (repo / "svc" / "shared" / "stale.py").write_text("STALE = True\n")
    (repo / "deploy").mkdir()
    manifest = repo / "deploy" / "vendor-manifest.json"
    manifest.write_text(json.dumps({"schema": 1, "consumers": {"svc": ["shared"]}, "module_copies": {}}))
    return repo, manifest


def test_stage_in_place_replaces_stale_copy_and_is_idempotent(tmp_path):
    repo, manifest = _mini_repo(tmp_path)
    vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest, git_sha="abc")
    staged = repo / "svc" / "shared"
    assert not (staged / "stale.py").exists(), "a module deleted from root must not survive in the staged copy"
    assert (staged / "a.py").read_text() == "A = 1\n"
    assert vs.tree_hash(staged) == vs.tree_hash(repo / "shared")
    snapshot = {p: (staged / p).read_bytes() for p in vs.iter_tree_files(staged)}
    # Negative test (Do No Harm): re-staging an already-correct context leaves it byte-identical.
    vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest, git_sha="abc")
    assert {p: (staged / p).read_bytes() for p in vs.iter_tree_files(staged)} == snapshot
    assert (repo / "svc" / "main.py").read_text() == "from shared.a import A\n"


def test_stage_in_place_needs_explicit_ci_flag(tmp_path, monkeypatch):
    """Code RT F4: only --ci enables --in-place; a generic $BUILD_ID (Jenkins etc. export it too) does not."""
    repo, manifest = _mini_repo(tmp_path)
    for build_id in (None, "cloud-build-123"):
        if build_id is None:
            monkeypatch.delenv("BUILD_ID", raising=False)
        else:
            monkeypatch.setenv("BUILD_ID", build_id)
        with pytest.raises(vs.VendorError, match="--ci"):
            vs.stage("svc", in_place=True, repo_root=repo, manifest_path=manifest)
        assert (repo / "svc" / "shared" / "stale.py").exists(), "refusal must not touch the tree"
    vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest, git_sha="abc")
    assert not (repo / "svc" / "shared" / "stale.py").exists()


def test_stage_out_refuses_inside_repo_or_non_empty(tmp_path):
    with pytest.raises(vs.VendorError, match="outside the repository"):
        vs.stage("apps/git-server", out=REPO / "apps" / "git-server" / "_stage_probe")
    assert not (REPO / "apps" / "git-server" / "_stage_probe").exists()
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "x").write_text("x")
    with pytest.raises(vs.VendorError, match="not empty"):
        vs.stage("apps/git-server", out=busy)


def test_stage_fails_loudly_on_missing_source(tmp_path):
    repo, manifest = _mini_repo(tmp_path)
    manifest.write_text(json.dumps({"schema": 1, "consumers": {"svc": ["shared", "infra/modules"]}}))
    with pytest.raises(vs.VendorError, match="infra/modules"):
        vs.stage("svc", out=tmp_path / "out", repo_root=repo, manifest_path=manifest)
    with pytest.raises(vs.VendorError, match="not found"):
        vs.stage("nope", out=tmp_path / "out2", repo_root=repo, manifest_path=manifest)


def test_build_info_is_deterministic_and_tracks_content(tmp_path):
    repo, manifest = _mini_repo(tmp_path)
    a = vs.build_info("svc", repo, manifest, git_sha="abc")
    assert a == vs.build_info("svc", repo, manifest, git_sha="abc")
    assert set(a) == {"schema", "service", "vendored", "shared_tree_sha256", "manifest_sha256", "git_sha"}
    (repo / "shared" / vs.BUILD_INFO_NAME).write_text("{}")  # excluded from the hash
    assert vs.build_info("svc", repo, manifest, git_sha="abc") == a
    (repo / "shared" / "a.py").write_text("A = 2\n")
    assert vs.build_info("svc", repo, manifest, git_sha="abc")["shared_tree_sha256"] != a["shared_tree_sha256"]


def test_sync_write_needs_explicit_root_files_and_only_touches_tracked_replicas(tmp_path):
    repo, manifest = _mini_repo(tmp_path)
    m = vs.load_manifest(manifest)
    with pytest.raises(vs.VendorError, match="explicit"):
        vs.sync_write([], repo, m)
    with pytest.raises(vs.VendorError, match="not a root file"):
        vs.sync_write(["shared/missing.py"], repo, m)
    # svc/shared/a.py has its own drift ("A = 0"): overwriting it would change what that service ships today.
    with pytest.raises(vs.VendorError, match="already differ"):
        vs.sync_write(["shared/a.py"], repo, m)
    assert (repo / "svc" / "shared" / "a.py").read_text() == "A = 0  # old\n", "refusal must not write"
    assert vs.sync_write(["shared/a.py"], repo, m, allow_drifted=True) == ["svc/shared/a.py"]
    assert (repo / "svc" / "shared" / "a.py").read_text() == "A = 1\n"
    assert not (repo / "svc" / "shared" / "__init__.py").exists(), "sync keeps each replica's file set (RT F4)"
    assert (repo / "svc" / "shared" / "stale.py").exists()
    orphan = {d["replica"] for d in vs.drift(repo, m) if d["status"] == "orphan"}
    assert orphan == {"svc/shared/stale.py"}


def test_sync_write_propagates_a_root_edit_when_replica_matched_head(tmp_path):
    """The Wave 2 workflow: edit root, then `sync --write`. A replica equal to the committed root is updated."""
    repo, manifest = _mini_repo(tmp_path)
    (repo / "svc" / "shared" / "a.py").write_text("A = 1\n")  # in sync with root at HEAD
    git_env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=git_env, capture_output=True)
    (repo / "shared" / "a.py").write_text("A = 2\n")
    m = vs.load_manifest(manifest)
    assert vs.sync_write(["shared/a.py"], repo, m) == ["svc/shared/a.py"]
    assert (repo / "svc" / "shared" / "a.py").read_text() == "A = 2\n"
    assert vs.drift(repo, m) == [{"replica": "svc/shared/stale.py", "source": "shared/stale.py", "status": "orphan"}]


def test_cli_report_tree_hash_matches_library(capsys):
    assert vs.main(["report", "--tree-hash"]) == 0
    assert capsys.readouterr().out.strip() == vs.tree_hash(REPO / "shared")


# --------------------------------------------------------------------------------------------- code RT fixes (synthetic repos)
def _snapshot(*roots):
    """Every file (path -> bytes) and directory under the given roots, symlinks not followed."""
    snap = {}
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            snap[dirpath] = None
            for name in filenames:
                f = Path(dirpath, name)
                snap[str(f)] = f.read_bytes() if not f.is_symlink() else ("link", os.readlink(f))
    return snap


def _victim(tmp_path):
    victim = tmp_path / "outside" / "victim"
    victim.mkdir(parents=True)
    (victim / "keep.txt").write_text("precious\n")
    return victim


@pytest.mark.parametrize("bad", ["/ABS", "../outside/victim", "shared/../../outside/victim", "./shared", "shared/",
                                 "shared//providers", "", "shared\\providers", "C:/x"])
def test_manifest_rejects_paths_that_escape_or_are_not_plain(tmp_path, bad):
    """Code RT F2: vendored paths, consumer keys and module copies must be plain relative paths in the repo."""
    repo, manifest = _mini_repo(tmp_path)
    victim = _victim(tmp_path)
    bad = str(victim) if bad == "/ABS" else bad
    variants = [
        {"schema": 1, "consumers": {"svc": ["shared", bad]}},
        {"schema": 1, "consumers": {bad or "": ["shared"]}},
        {"schema": 1, "consumers": {"svc": ["shared"]}, "module_copies": {bad: "shared/a.py"}},
        {"schema": 1, "consumers": {"svc": ["shared"]}, "module_copies": {"svc/a.py": bad}},
    ]
    original = manifest.read_bytes()
    before = _snapshot(repo, victim)
    for doc in variants:
        manifest.write_text(json.dumps(doc))
        with pytest.raises(vs.VendorError, match="plain relative path|non-empty"):
            vs.load_manifest(manifest)
        with pytest.raises(vs.VendorError):
            vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest)
        with pytest.raises(vs.VendorError):
            vs.stage("svc", out=tmp_path / f"out-{len(before)}", repo_root=repo, manifest_path=manifest)
    manifest.write_bytes(original)  # the test itself rewrote it; everything else must be untouched
    assert _snapshot(repo, victim) == before, "a rejected manifest must not change anything on disk"
    assert not list(tmp_path.glob("out-*"))


def test_stage_rejects_service_paths_that_escape(tmp_path):
    repo, manifest = _mini_repo(tmp_path)
    victim = _victim(tmp_path)
    before = _snapshot(repo, victim)
    for svc in (str(victim), "../outside/victim", "svc/../../outside/victim"):
        with pytest.raises(vs.VendorError, match="plain relative path"):
            vs.stage(svc, in_place=True, ci=True, repo_root=repo, manifest_path=manifest)
    assert _snapshot(repo, victim) == before


def test_stage_containment_follows_symlinked_parents(tmp_path):
    """A well-formed path can still escape through a symlinked parent dir: resolved containment refuses it."""
    repo, manifest = _mini_repo(tmp_path)
    victim = _victim(tmp_path)
    (victim / "modules").mkdir()
    (victim / "modules" / "keep.tf").write_text("# precious\n")
    (repo / "infra" / "modules").mkdir(parents=True)
    (repo / "infra" / "modules" / "m.tf").write_text("# root\n")
    (repo / "svc" / "infra").symlink_to(victim, target_is_directory=True)  # svc/infra -> outside
    manifest.write_text(json.dumps({"schema": 1, "consumers": {"svc": ["shared", "infra/modules"]}}))
    before = _snapshot(repo / "svc" / "shared", victim)
    with pytest.raises(vs.VendorError, match="escapes"):
        vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest)
    assert _snapshot(repo / "svc" / "shared", victim) == before, "nothing may be written before validation passes"
    # The vendored *source* escaping through a symlink is refused the same way.
    (repo / "svc" / "infra").unlink()
    manifest.write_text(json.dumps({"schema": 1, "consumers": {"svc": ["shared", "ext/modules"]}}))
    (repo / "ext").symlink_to(victim, target_is_directory=True)
    with pytest.raises(vs.VendorError, match="escapes"):
        vs.stage("svc", out=tmp_path / "out", repo_root=repo, manifest_path=manifest)
    assert not (tmp_path / "out").exists()


def test_stage_unlinks_symlinked_vendored_dir_without_following_it(tmp_path):
    """Negative (Do No Harm): a dev symlink svc/shared -> ../shared is replaced, root shared/ is left intact."""
    repo, manifest = _mini_repo(tmp_path)
    shutil.rmtree(repo / "svc" / "shared")
    (repo / "svc" / "shared").symlink_to(Path("..") / "shared", target_is_directory=True)
    before = _snapshot(repo / "shared")
    vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest, git_sha="abc")
    assert not (repo / "svc" / "shared").is_symlink()
    assert _snapshot(repo / "shared") == before


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_stage_refuses_symlinks_inside_vendored_sources(tmp_path, kind):
    """Code RT F5: a symlink in shared/ would ship its target's bytes; refuse before writing anything."""
    repo, manifest = _mini_repo(tmp_path)
    victim = _victim(tmp_path)
    link = repo / "shared" / "link"
    link.symlink_to(victim / "keep.txt" if kind == "file" else victim, target_is_directory=(kind == "dir"))
    before = _snapshot(repo / "svc")
    with pytest.raises(vs.VendorError, match="symlinks"):
        vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest)
    with pytest.raises(vs.VendorError, match="symlinks"):
        vs.stage("svc", out=tmp_path / "out", repo_root=repo, manifest_path=manifest)
    assert _snapshot(repo / "svc") == before and not (tmp_path / "out").exists()


def _git_init(repo):
    git_env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    for cmd in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True, env=git_env, capture_output=True)


@pytest.mark.parametrize("change", ["modified", "untracked", "deleted"])
def test_stage_in_place_refuses_uncommitted_replica_changes(tmp_path, change):
    """Code RT F4: --in-place must not destroy an operator's uncommitted edit inside a vendored path."""
    repo, manifest = _mini_repo(tmp_path)
    _git_init(repo)
    target = repo / "svc" / "shared"
    if change == "modified":
        (target / "a.py").write_text("A = 99  # local edit\n")
    elif change == "untracked":
        (target / "new_helper.py").write_text("X = 1\n")
    else:
        (target / "stale.py").unlink()
    before = _snapshot(target)
    with pytest.raises(vs.VendorError, match="uncommitted or untracked"):
        vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest, git_sha="abc")
    assert _snapshot(target) == before


def test_stage_in_place_proceeds_on_a_clean_git_tree(tmp_path):
    repo, manifest = _mini_repo(tmp_path)
    _git_init(repo)
    (repo / "svc" / "main.py").write_text("# unrelated local edit outside vendored paths\n")
    vs.stage("svc", in_place=True, ci=True, repo_root=repo, manifest_path=manifest, git_sha="abc")
    assert vs.tree_hash(repo / "svc" / "shared") == vs.tree_hash(repo / "shared")


def test_ds_store_is_never_vendored_or_hashed(tmp_path):
    """Code RT F9: Finder metadata must not change the tree hash or ship in a staged context."""
    repo, manifest = _mini_repo(tmp_path)
    clean = vs.tree_hash(repo / "shared")
    (repo / "shared" / ".DS_Store").write_bytes(b"\x00\x01finder")
    (repo / "shared" / "providers" / ".DS_Store").write_bytes(b"\x00\x02finder")
    assert vs.tree_hash(repo / "shared") == clean
    assert ".DS_Store" not in "".join(vs.iter_tree_files(repo / "shared"))
    out = vs.stage("svc", out=tmp_path / "out", repo_root=repo, manifest_path=manifest, git_sha="abc")
    assert not list(out.rglob(".DS_Store"))
    assert json.loads((out / "shared" / vs.BUILD_INFO_NAME).read_text())["shared_tree_sha256"] == clean


def test_urllib3_is_mapped_and_requirements_check_is_non_transitive(tmp_path):
    """Code RT F3/F10: a direct `import urllib3.util` needs urllib3 itself in requirements.txt."""
    assert vs.dist_for_import("urllib3.util") == "urllib3"
    repo, manifest = _mini_repo(tmp_path)
    (repo / "shared" / "cb.py").write_text("import urllib3.util\n")
    (repo / "svc" / "main.py").write_text("from shared.cb import *\n")
    (repo / "svc" / "requirements.txt").write_text("requests==2.32.3\n")
    m = vs.load_manifest(manifest)
    gaps = vs.requirement_gaps("svc", repo, m)
    assert [(g["file"], g["import"], g["dist"]) for g in gaps] == [("shared/cb.py", "urllib3.util", "urllib3")]
    (repo / "svc" / "requirements.txt").write_text("requests==2.32.3\nurllib3>=2\n")
    assert vs.requirement_gaps("svc", repo, m) == []


def test_cli_acts_on_its_own_checkout_regardless_of_cwd(tmp_path):
    """Code RT F6: REPO_ROOT comes from the script location, not the current directory."""
    assert vs.REPO_ROOT == REPO
    res = subprocess.run([sys.executable, "-E", "-s", str(REPO / "deploy" / "vendor_shared.py"), "report", "--tree-hash"],
                         cwd=tmp_path, env=_guard_env(hermetic_guard.child_env()), capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == vs.tree_hash(REPO / "shared")


def test_sync_write_rejects_escaping_paths(tmp_path):
    repo, manifest = _mini_repo(tmp_path)
    m = vs.load_manifest(manifest)
    for bad in ("/etc/hosts", "../outside/x.py", "shared/../shared/a.py"):
        with pytest.raises(vs.VendorError, match="plain relative path"):
            vs.sync_write([bad], repo, m)

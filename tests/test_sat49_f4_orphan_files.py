"""SAT-49 F4 (follow-up of QA-REPAIR-OWNERSHIP-PARITY): app-code provenance and the removal of unchanged orphan files.

A relaunch over an existing repository used to keep every file of the earlier build that the new build no longer
writes (the commit is additive). Such a file sits outside the validated tree, and a QA failure inside it (for
example a stale test importing a dead module) could never be repaired. Now the developer records, per committed
stack-validated build, the application files its LLM wrote (`workloads/{pid}.app_provenance`, exact path + sha256),
and the next build deletes, in its own commit, the recorded Python files that are unchanged, not written again and
not used by any file that stays (real `ast` imports, over-approximated). Covered: the decision table (pure), the
record, the store, the developer end to end (fake LLM / swarm / validate), Do No Harm without a store or a record,
and the gateway's commit call. Hermetic.
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import dataclasses
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

import test_qa_feedback as QF  # noqa: E402
from test_qa_feedback import APP, MAIN, SCHEMAS, TF_DRAFT, _develop  # noqa: E402
from developer_agent import app_provenance as AP  # noqa: E402
from fd4f_support import FakeDB  # noqa: E402

REPO = os.path.abspath(os.path.join(TESTS, ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
ROUTES = "apps/shop/routes.py"
STALE_ROUTES = "from schemas import EventInboundRequest\n\n\ndef route():\n    return EventInboundRequest\n"
STALE_TEST = "apps/shop/tests/test_routes.py"
STALE_TEST_TEXT = "from routes import route\n\n\ndef test_route():\n    assert route()\n"


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


def rec(files, trace="t-old"):
    """A record whose entries hold one version each (PROVENANCE-HISTORY canonical shape)."""
    return {p: {"sha256": AP.sha256(t), "trace_id": trace, "history": [AP.sha256(t)]} for p, t in files.items()}


TREE = {"apps/shop/main.py": "from fastapi import FastAPI\nfrom services import thing\n\napp = FastAPI()\n",
        "apps/shop/services/__init__.py": "thing = 1\n"}


def decide(old, tree=TREE, extra=None, record=None, complete=True):
    existing = dict(old, **(extra or {}))
    return AP.find_orphans(record if record is not None else rec(old), existing, tree, tree_complete=complete)


# ------------------------------------------------------------------------------------------------- decision table
def test_the_f4_shape_deletes_the_stale_test_and_the_dead_module_it_imports():
    """The review's F4 example: a stale test importing a dead `routes`; nothing that stays imports either."""
    d = decide({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT})
    assert d["status"] == AP.STATUS_CHECKED and d["deleted"] == [ROUTES, STALE_TEST] and d["kept"] == {}
    assert d["carry"] == {}


def test_a_file_a_person_changed_is_never_a_candidate():
    old = {ROUTES: STALE_ROUTES}
    d = decide(old, extra={ROUTES: STALE_ROUTES + "# edited by a person\n"})
    assert d["deleted"] == [] and d["kept"] == {} and d["carry"] == {}


def test_an_unrecorded_file_is_never_a_candidate():
    d = AP.find_orphans({}, {ROUTES: STALE_ROUTES}, TREE, tree_complete=True)
    assert d["deleted"] == [] and d["kept"] == {}


def test_a_file_the_new_build_writes_is_never_a_candidate():
    d = decide({MAIN: "old = 1\n"})
    assert d["deleted"] == [] and d["kept"] == {}


@pytest.mark.parametrize("importer", [
    "from routes import route\n",                 # absolute, the service directory as root
    "import routes\n",
    "from . import routes\n",                    # relative (package)
    "from .routes import route\n",
    "from apps.shop import routes\n",            # repository root as root, submodule named in the import
    "import apps.shop.routes as r\n",
])
def test_an_orphan_a_remaining_file_imports_is_kept(importer):
    tree = dict(TREE, **{"apps/shop/main.py": importer})
    d = decide({ROUTES: STALE_ROUTES}, tree=tree)
    assert d["deleted"] == [] and d["kept"] == {ROUTES: AP.KEPT_IMPORTED}
    assert d["carry"] == rec({ROUTES: STALE_ROUTES})   # still recorded: a later run can decide it again


def test_an_orphan_a_persons_file_imports_is_kept():
    d = decide({ROUTES: STALE_ROUTES}, extra={"apps/shop/mine.py": "import routes\n"})
    assert d["kept"] == {ROUTES: AP.KEPT_IMPORTED} and d["deleted"] == []


def test_keeping_one_orphan_keeps_what_it_imports_too():
    """Fixpoint: main -> stale_b (kept) -> routes (kept)."""
    old = {ROUTES: STALE_ROUTES, "apps/shop/stale_b.py": "import routes\n"}
    tree = dict(TREE, **{"apps/shop/main.py": "import stale_b\n"})
    d = decide(old, tree=tree)
    assert d["deleted"] == [] and set(d["kept"]) == {ROUTES, "apps/shop/stale_b.py"}


def test_non_python_files_and_conftest_are_kept():
    old = {"apps/shop/templates/index.html": "<p>old</p>\n", "apps/shop/tests/conftest.py": "import pytest\n"}
    d = decide(old)
    assert d["deleted"] == []
    assert d["kept"] == {"apps/shop/templates/index.html": AP.KEPT_NOT_PYTHON,
                         "apps/shop/tests/conftest.py": AP.KEPT_CONFTEST}


def test_a_package_init_is_kept_while_its_directory_has_other_files():
    old = {"apps/shop/legacy/__init__.py": "", "apps/shop/legacy/a.py": "x = 1\n"}
    d = decide(old, extra={"apps/shop/legacy/notes.md": "draft notes\n"})   # (every file is tokenised: no 'a')
    assert d["deleted"] == ["apps/shop/legacy/a.py"]
    assert d["kept"] == {"apps/shop/legacy/__init__.py": AP.KEPT_PACKAGE}
    d2 = decide(old)   # nothing else under it: the whole stale package goes
    assert d2["deleted"] == ["apps/shop/legacy/__init__.py", "apps/shop/legacy/a.py"]


@pytest.mark.parametrize("blocker,status", [
    ("def broken(:\n", AP.STATUS_SKIPPED_UNPARSEABLE),
    # PROVENANCE-CONSTANT-DYNAMIC-IMPORT: a constant name is an ordinary import (tests/test_provenance_cleanup_matrix);
    # a computed one with no constant head still removes nothing
    ("import importlib\nm = importlib.import_module(name)\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("m = __import__(name)\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("exec('import routes')\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("import runpy\nrunpy.run_module('routes')\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    # RT F3: the rest of Python's (and the common frameworks') module loaders
    ("import pkgutil\nmods = list(pkgutil.iter_modules(['plugins']))\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("import pkgutil\nmods = list(pkgutil.walk_packages())\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("import importlib.util\ns = importlib.util.find_spec('x')\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("import importlib.util\nm = importlib.util.module_from_spec(s)\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("from werkzeug.utils import import_string\nv = import_string('x:y')\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("m = loader.load_module('x')\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("import importlib.util\nn = importlib.util.resolve_name('.x', 'pkg')\n", AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
])
def test_an_unparseable_or_dynamic_remaining_file_removes_nothing(blocker, status):
    d = decide({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT}, extra={"apps/shop/plugin.py": blocker})
    assert d["status"] == status and d["deleted"] == [] and d["blocked_by"] == "apps/shop/plugin.py"
    assert set(d["kept"]) == {ROUTES, STALE_TEST}


def test_summary_is_bounded_and_has_every_key():
    d = AP.find_orphans(rec({f"apps/x/m{i}.py": "x = 1\n" for i in range(250)}),
                        {f"apps/x/m{i}.py": "x = 1\n" for i in range(250)}, {}, tree_complete=True)
    s = AP.summary(dict(d, error=None))
    assert set(s) == {"status", "deleted", "deleted_count", "kept", "kept_count", "blocked_by", "error"}
    assert len(s["deleted"]) == AP.SUMMARY_LIST_MAX and s["deleted_count"] == 250


# ------------------------------------------------------------------------------------------------- the record
def test_record_for_commit_holds_this_runs_app_files_only():
    files = {MAIN: "a\n", "apps/shop/x.py": "b\n", "infra/workload/custom.tf": "c\n", ".github/workflows/d.yml": "d\n",
             ".python-version": "3.13\n"}
    entries = AP.record_for_commit([MAIN, "apps/shop/x.py", "infra/workload/custom.tf", ".github/workflows/d.yml",
                                    "apps/shop/gone.py"], files, "t-new", {})
    assert entries == {MAIN: rec({MAIN: "a\n"}, "t-new")[MAIN], "apps/shop/x.py": rec({"x": "b\n"}, "t-new")["x"]}


def test_record_for_commit_keeps_every_stored_entry_and_appends_versions():
    """PROVENANCE-HISTORY (was: carries only unchanged entries): the stored record is append-only. An entry whose
    file a person edited, an entry of a file this commit deletes (maybe on a branch never merged) and an entry of a
    file not in this commit all stay; a rewritten file gains a version (newest last)."""
    stored = rec({"apps/shop/same.py": "s\n", "apps/shop/edited.py": "e\n", ROUTES: STALE_ROUTES})
    files = {"apps/shop/same.py": "s2\n", "apps/shop/edited.py": "e2\n"}
    entries = AP.record_for_commit(["apps/shop/same.py"], files, "t-new", stored)
    assert entries["apps/shop/edited.py"] == stored["apps/shop/edited.py"]
    assert entries[ROUTES] == stored[ROUTES]
    assert entries["apps/shop/same.py"] == {"sha256": AP.sha256("s2\n"), "trace_id": "t-new",
                                            "history": [AP.sha256("s\n"), AP.sha256("s2\n")]}


@pytest.mark.parametrize("raw", [None, [], "x", {"a.py": {"sha256": "short", "trace_id": "t"}},
                                 {"infra/workload/x.tf": {"sha256": "0" * 64, "trace_id": "t"}},
                                 {"a.py": {"sha256": "0" * 64}}, {"": {"sha256": "0" * 64, "trace_id": "t"}}])
def test_a_malformed_record_entry_is_ignored(raw):
    assert AP.parse_record(raw) == {}


def test_firestore_store_round_trip_and_typed_failures():
    db = FakeDB()
    store = AP.FirestoreAppProvenanceStore(db)
    assert store.load("shop") == {}
    entries = rec({MAIN: "a\n"})
    store.save("shop", entries)
    assert store.load("shop") == entries
    broken = AP.FirestoreAppProvenanceStore(SimpleNamespace(collection=MagicMock(side_effect=RuntimeError("down"))))
    with pytest.raises(AP.AppProvenanceUnavailable):
        broken.load("shop")
    with pytest.raises(AP.AppProvenanceUnavailable):
        broken.save("shop", entries)


# ------------------------------------------------------------------------------------------------- end to end
def _with_store(monkeypatch, store, tree_status=None):
    """The dispatch's runtime gets `store`; its (fake) repository read reports `tree_status` (default: complete)."""
    real, real_agent = QF._runtime, QF._agent

    def runtime(client, **settings):
        return dataclasses.replace(real(client, **settings), app_provenance_store=store)

    def agent(rt):
        a = real_agent(rt)
        a.last_tree_status = dict(tree_status or {"complete": True, "truncated": False, "error": None})
        return a
    monkeypatch.setattr(QF, "_runtime", runtime)
    monkeypatch.setattr(QF, "_agent", agent)


def _first():
    draft = dict(APP, **TF_DRAFT, **{SCHEMAS: "class Other:\n    pass\n"})
    att = {p: ("IAC_ENGINEER" if p.startswith("infra/workload/") else "BACKEND_ENGINEER") for p in draft}
    return draft, att


def test_a_relaunch_deletes_the_earlier_builds_unchanged_orphans(monkeypatch):
    store = AP.MemoryAppProvenanceStore()
    _with_store(monkeypatch, store)
    draft, att = _first()
    # an earlier build wrote the stale pair; this build's repository still holds them unchanged
    store.save("shop", rec({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT, MAIN: "old main\n"}))
    existing = {ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT, MAIN: "old main\n"}
    files, agent, _c, _seen = _develop("off", swarm_draft=draft, swarm_att=att, existing=existing)
    assert agent.last_validation_report.status == "PASS"
    run = agent.stack_run("t-qa")
    assert run["app_orphan_deletions"] == [ROUTES, STALE_TEST]
    assert run["app_orphans"]["status"] == AP.STATUS_CHECKED and run["app_orphans"]["deleted_count"] == 2
    assert ROUTES not in files and STALE_TEST not in files
    # the commit of that tree records this build's own app files; PROVENANCE-HISTORY: the deleted files' entries stay
    # (this commit may be on a branch that is never merged) and MAIN keeps its earlier version
    agent._write_app_provenance("shop", "t-qa", files)
    written = store.load("shop")
    assert set(written) == {p for p in run["llm_draft_paths"] if AP.is_app_path(p)} | {ROUTES, STALE_TEST}
    assert written[MAIN] == {"sha256": AP.sha256(files[MAIN]), "trace_id": "t-qa",
                             "history": [AP.sha256("old main\n"), AP.sha256(files[MAIN])],
                             "base": AP.sha256("old main\n")}   # RT R3: the default branch's version, never evicted
    assert written[ROUTES] == dict(rec({ROUTES: STALE_ROUTES})[ROUTES], base=AP.sha256(STALE_ROUTES))
    assert run_written(agent) == sorted(p for p in run["llm_draft_paths"] if AP.is_app_path(p))
    assert not any(p.startswith("infra/") for p in written)


def run_written(agent):
    return agent.stack_run("t-qa")["app_provenance_written"]


def test_no_record_deletes_nothing_and_builds_the_same_tree(monkeypatch):
    """Do No Harm: the first run after this change (no record) builds byte-identically and deletes nothing."""
    draft, att = _first()
    existing = {ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT}
    plain, plain_agent, _c, _s = _develop("off", swarm_draft=draft, swarm_att=att, existing=existing)
    store = AP.MemoryAppProvenanceStore()
    _with_store(monkeypatch, store)
    files, agent, _c2, _s2 = _develop("off", swarm_draft=draft, swarm_att=att, existing=existing)
    assert files == plain
    assert agent.stack_run("t-qa")["app_orphan_deletions"] == []
    assert agent.stack_run("t-qa")["app_orphans"]["status"] == AP.STATUS_NO_RECORD
    assert plain_agent.stack_run("t-qa")["app_orphan_deletions"] == []
    assert plain_agent.stack_run("t-qa")["app_orphans"]["status"] == AP.STATUS_OFF


def test_an_unreadable_record_deletes_nothing_and_says_so(monkeypatch):
    class Down:
        def load(self, _pid):
            raise AP.AppProvenanceUnavailable("app provenance read failed for shop: RuntimeError")

        def save(self, *_a):
            raise AssertionError("never written after a failed read")
    _with_store(monkeypatch, Down())
    draft, att = _first()
    files, agent, _c, _s = _develop("off", swarm_draft=draft, swarm_att=att,
                                    existing={ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT})
    run = agent.stack_run("t-qa")
    assert run["app_orphan_deletions"] == [] and run["app_orphans"]["status"] == AP.STATUS_UNAVAILABLE
    assert "read failed" in run["app_orphans"]["error"]


def test_a_commit_of_another_tree_records_nothing(monkeypatch):
    store = AP.MemoryAppProvenanceStore()
    _with_store(monkeypatch, store)
    draft, att = _first()
    files, agent, _c, _s = _develop("off", swarm_draft=draft, swarm_att=att)
    agent._write_app_provenance("shop", "t-qa", dict(files, **{"apps/shop/extra.py": "x = 1\n"}))
    assert store.load("shop") == {}


def test_a_failed_record_write_never_fails_the_commit(monkeypatch, caplog):
    class Refuses(AP.MemoryAppProvenanceStore):
        def save(self, *_a):
            raise AP.AppProvenanceUnavailable("app provenance write failed for shop: RuntimeError")
    _with_store(monkeypatch, Refuses())
    draft, att = _first()
    files, agent, _c, _s = _develop("off", swarm_draft=draft, swarm_att=att)
    agent._write_app_provenance("shop", "t-qa", files)   # no exception
    assert "APP_PROVENANCE_NOT_RECORDED" in caplog.text


@pytest.mark.parametrize("bound", ["APP_PROVENANCE_MAX", "APP_PROVENANCE_SHAS_MAX"])
def test_an_oversized_record_is_not_written_and_the_stored_one_stays(monkeypatch, caplog, bound):
    """PROVENANCE-HISTORY (was: cleared): every stored entry is still true, so it stays; this commit's versions are
    not recorded (fail-safe: those files are not platform-written later, i.e. kept)."""
    store = AP.MemoryAppProvenanceStore()
    store.save("shop", rec({ROUTES: STALE_ROUTES}))
    _with_store(monkeypatch, store)
    monkeypatch.setattr(AP, bound, 1)
    draft, att = _first()
    files, agent, _c, _s = _develop("off", swarm_draft=draft, swarm_att=att)
    agent._write_app_provenance("shop", "t-qa", files)
    assert store.load("shop") == rec({ROUTES: STALE_ROUTES}) and "APP_PROVENANCE_NOT_RECORDED" in caplog.text


# ------------------------------------------------------------------------------------------------- gateway
def _gateway_helper():
    src = open(os.path.join(GATEWAY, "main.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "_developer_app_orphan_deletions")
    from typing import Any, List, Optional
    ns = {"Any": Any, "Optional": Optional, "List": List}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), "main.py", "exec"), ns)  # noqa: S102 - repo code
    return tree, ns["_developer_app_orphan_deletions"]


def test_gateway_deletes_the_orphans_in_the_same_commit_only_when_there_are_any():
    tree, f = _gateway_helper()
    assert f(SimpleNamespace(stack_run=lambda t: {"app_orphan_deletions": [ROUTES]}), "t") == [ROUTES]
    assert f(SimpleNamespace(stack_run=lambda t: {"app_orphan_deletions": []}), "t") == []
    assert f(SimpleNamespace(stack_run=lambda t: {}), "t") == []
    assert f(MagicMock(), "t") == []
    assert f(SimpleNamespace(), "t") == []
    assert f(SimpleNamespace(stack_run=lambda t: {"app_orphan_deletions": [1]}), "t") == []
    assert f(SimpleNamespace(stack_run=lambda t: {"app_orphan_deletions": ROUTES}), "t") == []
    call = next(c for c in ast.walk(tree) if isinstance(c, ast.Call) and getattr(c.func, "attr", "") ==
                "commit_and_open_pr" and any(k.arg is None for k in c.keywords))
    starred = ast.unparse(next(k.value for k in call.keywords if k.arg is None))
    assert "files_to_delete" in starred and "orphan_deletions" in starred and "gha_deletions" in starred


def test_the_gateway_runtime_has_the_firestore_store():
    src = open(os.path.join(GATEWAY, "main.py"), encoding="utf-8").read()
    assert "app_provenance_store=FirestoreAppProvenanceStore(db) if db is not None else None" in src


@pytest.mark.parametrize("path,ok", [("apps/shop/x.py", True), ("tests/t.py", True), ("infra/workload/x.tf", False),
                                     (".github/workflows/d.yml", False), ("/" + "abs.py", False), ("", False),
                                     (None, False),
                                     # RT F5: never a segment the provider's path check would refuse
                                     ("../x.py", False), ("apps/../x.py", False), ("./x.py", False),
                                     ("a//b.py", False), ("a/b/", False), ("a\\b.py", False),
                                     ("infra", False), ("apps/infra/x.py", True), (".githubx/y.py", True)])
def test_is_app_path_is_exact(path, ok):
    assert AP.is_app_path(path) is ok


# ------------------------------------------------------------------------------------------------- RT fixes (11-07)
@pytest.mark.parametrize("orphan,importer_path,importer", [
    # RT F1 dry-run A: src layout (pytest `pythonpath = src` / an installed package)
    ("src/shop/routes.py", "tests/test_routes.py", "from shop.routes import r\n"),
    # RT F1 dry-run B: a root tests/ folder importing the service directory (pytest `pythonpath = apps/shop`)
    ("apps/shop/helpers.py", "tests/test_helpers.py", "from helpers import h\n"),
    ("apps/shop/helpers.py", "tests/test_helpers.py", "import helpers\n"),
    ("src/shop/__init__.py", "tests/test_pkg.py", "import shop\n"),
])
def test_imports_resolve_against_every_directory_of_the_repository(orphan, importer_path, importer):
    d = decide({orphan: "r = h = 1\n"}, tree=dict(TREE, **{importer_path: importer}))
    assert d["deleted"] == [] and d["kept"] == {orphan: AP.KEPT_IMPORTED}


def test_every_root_still_deletes_the_f4_pair():
    """F1 does not widen into keeping the dead pair: nothing that stays imports `routes` or the stale test."""
    tree = dict(TREE, **{"tests/test_main.py": "from main import app\n"})
    d = decide({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT}, tree=tree)
    assert d["deleted"] == [ROUTES, STALE_TEST]


WORKER = "apps/shop/worker.py"


@pytest.mark.parametrize("path,text", [
    # RT F2 dry-run C
    ("apps/shop/Procfile", "web: uvicorn main:app\nworker: python -m apps.shop.worker\n"),
    ("apps/shop/run.py", "import uvicorn\nuvicorn.run('worker:run')\n"),
    ("apps/shop/tests/conftest.py", "pytest_plugins = ['worker']\n"),
    ("apps/shop/celery_app.py", "from celery import Celery\napp = Celery('shop', include=['shop.worker'])\n"),
    ("pyproject.toml", "[project.scripts]\nshop-worker = \"apps.shop.worker:main\"\n"),
    ("apps/shop/start.sh", "#!/bin/sh\nexec python ./apps/shop/worker.py\n"),
    ("apps/shop/jobs.yaml", "jobs:\n  - module: shop.worker\n"),
    ("apps/shop/jobs.json", "{\"entry\": \"worker.py\"}\n"),
    ("setup.cfg", "[options.entry_points]\nconsole_scripts =\n    w = apps.shop.worker:main\n"),
    ("apps/shop/run.py", "label = 'the worker process'\n"),   # exact token 'worker': kept (conservative)
])
def test_a_module_named_in_a_string_or_config_token_is_kept(path, text):
    d = decide({WORKER: "def run():\n    pass\n"}, extra={path: text})
    assert d["deleted"] == [] and d["kept"] == {WORKER: AP.KEPT_NAMED_IN_STRING}


@pytest.mark.parametrize("path,text", [
    ("apps/shop/Procfile", "worker2: python -m apps.shop.worker_v2\n"),  # another module: exact equality only
    ("apps/shop/notes.md", "python -m apps.shop.worker_v2\n"),           # any file is scanned, exact names only
    ("apps/shop/run.py", "x = 'apps.shop'\n"),                           # a package prefix is not the module
    ("apps/shop/run.sh", "python3 /workspace/apps/shop/worker.pyc\n"),   # path suffix: component-exact
    ("apps/shop/run.sh", "python3 /workspace/apps/shop/myworker.py\n"),
    ("apps/shop/run.py", "x = 'workers'\n"),
])
def test_a_string_that_does_not_name_the_module_exactly_keeps_nothing(path, text):
    d = decide({WORKER: "def run():\n    pass\n"}, extra={path: text})
    assert d["deleted"] == [WORKER]


def test_a_kept_files_strings_keep_what_they_name_too():
    """Fixpoint: the Procfile names stale_b, stale_b's string names worker -> both kept."""
    old = {WORKER: "x = 1\n", "apps/shop/stale_b.py": "TARGET = 'apps.shop.worker:run'\n"}
    d = decide(old, extra={"apps/shop/Procfile": "web: python -m apps.shop.stale_b\n"})
    assert d["deleted"] == [] and set(d["kept"]) == {WORKER, "apps/shop/stale_b.py"}


def test_an_incomplete_repository_read_removes_nothing():
    """RT F4: a truncated / failed read cannot prove that nothing uses an orphan."""
    d = decide({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT}, complete=False)
    assert d["status"] == AP.STATUS_SKIPPED_TREE_INCOMPLETE and d["deleted"] == []
    assert d["kept"] == {ROUTES: AP.KEPT_RUN_SKIPPED, STALE_TEST: AP.KEPT_RUN_SKIPPED}
    assert set(d["carry"]) == {ROUTES, STALE_TEST}   # still recorded for a later complete read


@pytest.mark.parametrize("ini_path,ini,versions", [
    ("alembic.ini", "[alembic]\nscript_location = migrations\n", "migrations/versions/0002_add.py"),
    ("apps/shop/alembic.ini", "[alembic]\nscript_location = %(here)s/db/migrations\n",
     "apps/shop/db/migrations/versions/0002_add.py"),
    ("apps/shop/alembic.ini", "[alembic]\nscript_location = alembic\n", "apps/shop/alembic/env.py"),
])
def test_files_under_an_alembic_script_location_are_kept(ini_path, ini, versions):
    d = decide({versions: "revision = '0002'\n"}, extra={ini_path: ini})
    assert d["deleted"] == [] and d["kept"] == {versions: AP.KEPT_MIGRATION}


def test_a_folder_with_env_py_and_script_mako_is_a_migration_folder_without_alembic_ini():
    v = "apps/shop/migrations/versions/0001_init.py"
    d = decide({v: "revision = '0001'\n"}, extra={"apps/shop/migrations/env.py": "from alembic import context\n",
                                                 "apps/shop/migrations/script.py.mako": "${message}\n"})
    assert d["kept"] == {v: AP.KEPT_MIGRATION} and d["deleted"] == []


@pytest.mark.parametrize("extra", [
    {"apps/shop/migrations/env.py": "from alembic import context\n"},              # no script.py.mako
    {"alembic.ini": "[alembic]\nscript_location = other\n"},                       # another folder
    {"alembic.ini": "[alembic]\nscript_location = ../outside\n"},                  # outside the repository
    {"alembic.ini": "[alembic]\nscript_location = pkg:migrations\n"},              # package form: not resolved
    {"alembic.ini": "not an ini file ["},                                          # unreadable: no folder
])
def test_other_layouts_are_not_migration_folders(extra):
    v = "apps/shop/migrations/versions/0001_init.py"
    d = decide({v: "revision = '0001'\n"}, extra=extra)
    assert d["deleted"] == [v]


def test_e2e_an_incomplete_repository_read_records_it_and_deletes_nothing(monkeypatch):
    """RT F4 end to end. On the topology path the Lane 10 guard already stops a built product with an incomplete
    tree before any LLM call; the run record says the read was incomplete, so no orphan decision could delete."""
    from shared.diagnostics import StageError
    store = AP.MemoryAppProvenanceStore()
    store.save("shop", rec({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT}))
    _with_store(monkeypatch, store, tree_status={"complete": False, "truncated": True, "error": None})
    draft, att = _first()
    captured = {}
    from developer_agent import handler as h
    real_load = h.DeveloperAgent._load_app_provenance

    def load(self, product_id, trace_id, stack_on, tree_complete):
        captured["tree_complete"] = tree_complete
        return real_load(self, product_id, trace_id, stack_on, tree_complete)
    monkeypatch.setattr(h.DeveloperAgent, "_load_app_provenance", load)
    with pytest.raises(StageError):
        _develop("off", swarm_draft=draft, swarm_att=att,
                 existing={ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT})
    assert captured.get("tree_complete", False) is False   # never True for this read (or the guard stopped first)
    assert store.load("shop") == rec({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT})


def test_e2e_completeness_is_the_fetch_of_this_dispatch_not_a_later_read(monkeypatch):
    """RT F4: the status is captured right after this dispatch's fetch; a later change of the shared agent attribute
    (another dispatch on the instance) does not decide this one."""
    from developer_agent import handler as h
    store = AP.MemoryAppProvenanceStore()
    store.save("shop", rec({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT}))
    _with_store(monkeypatch, store)
    real_decide = h.DeveloperAgent._decide_app_orphans

    def decide_after_another_fetch(self, inputs, tree):
        self.last_tree_status = {"complete": False, "truncated": True, "error": None}
        return real_decide(self, inputs, tree)
    monkeypatch.setattr(h.DeveloperAgent, "_decide_app_orphans", decide_after_another_fetch)
    draft, att = _first()
    _files, agent, _c, _s = _develop("off", swarm_draft=draft, swarm_att=att,
                                     existing={ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT})
    assert agent.stack_run("t-qa")["app_orphan_deletions"] == [ROUTES, STALE_TEST]


@pytest.mark.parametrize("complete,status,deleted", [
    (False, AP.STATUS_SKIPPED_TREE_INCOMPLETE, []),
    (True, AP.STATUS_CHECKED, [ROUTES, STALE_TEST]),
])
def test_handler_decides_with_the_completeness_recorded_at_load(complete, status, deleted):
    """RT F4 at the handler seam (legacy path, where no topology guard runs first): the decision uses the
    completeness the dispatch recorded right after its fetch."""
    from test_qa_feedback import _agent as make_agent, _runtime as make_runtime
    store = AP.MemoryAppProvenanceStore()
    store.save("shop", rec({ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT}))
    agent = make_agent(dataclasses.replace(make_runtime(None), app_provenance_store=store))
    agent._load_app_provenance("shop", "t-legacy", True, complete)
    agent._record_stack("t-legacy", app_full_build=True)   # INCREMENTAL-CHANGE-NO-ORPHAN-DELETE: a full build
    agent.last_tree_status = {"complete": True, "truncated": False, "error": None}   # a later dispatch's read
    inputs = SimpleNamespace(trace_id="t-legacy", product_id="shop",
                             existing_files={ROUTES: STALE_ROUTES, STALE_TEST: STALE_TEST_TEXT})
    agent._decide_app_orphans(inputs, dict(TREE))
    run = agent.stack_run("t-legacy")
    assert run["app_orphans"]["status"] == status and run["app_orphan_deletions"] == deleted


# ------------------------------------------------------------------------------------------------- RT re-check (61d32127)
@pytest.mark.parametrize("case,path,text", [
    ("H1", "infra/workload/job.tf",
     'resource "google_cloud_run_v2_job" "w" {\n  template { template { containers {\n'
     '    args = ["python", "-m", "apps.shop.worker"]\n  } } }\n}\n'),
    ("H6", "infra/workload/gce.tf", 'metadata_startup_script = "cd /opt/app && python3 apps/shop/worker.py"\n'),
    ("H13", "infra/workload/terraform.tfvars", 'worker_module = "apps.shop.worker"\n'),
    ("H2", "Makefile", "run-worker:\n\tpython -m apps.shop.worker\n"),
    ("H3", ".env", "APP_MODULE=apps.shop.worker:run\n"),
    ("H4", "supervisord.conf", "[program:w]\ncommand=python -m apps.shop.worker\n"),
    ("dockerfile", "apps/shop/Dockerfile.local", 'CMD ["python", "-m", "apps.shop.worker"]\n'),
    ("extensionless", "apps/shop/run-worker", "#!/bin/sh\nexec python -m shop.worker\n"),
    ("notes", "apps/shop/notes.md", "python -m apps.shop.worker\n"),   # RT F7: inverted negative
    # RT F9: absolute paths match by component-exact suffix
    ("H7", "apps/shop/start.sh", "#!/bin/sh\npython3 /workspace/apps/shop/worker.py\n"),
    ("H20", "infra/workload/gce2.tf", 'metadata_startup_script = "python3 /opt/app/apps/shop/worker.py"\n'),
    ("H20-py", "apps/shop/launch.py", "import subprocess\nsubprocess.run(['python3', '/srv/shop/worker.py'])\n"),
])
def test_every_remaining_file_and_absolute_paths_keep_a_named_module(case, path, text):
    d = decide({WORKER: "def run():\n    pass\n"}, extra={path: text})
    assert d["deleted"] == [] and d["kept"] == {WORKER: AP.KEPT_NAMED_IN_STRING}, case


MAIN_PKG = "apps/shop/__main__.py"


@pytest.mark.parametrize("case,with_init,command", [
    ("H18", True, "web: python -m apps.shop\n"),
    ("H19", False, "web: python -m apps.shop\n"),
    ("H19-path", False, "web: python apps/shop\n"),
    ("short", False, "web: python -m shop\n"),
])
def test_python_dash_m_of_a_package_keeps_its_main(case, with_init, command):
    old = {MAIN_PKG: "print('run')\n"}
    if with_init:
        old["apps/shop/__init__.py"] = ""
    d = decide(old, extra={"apps/shop/Procfile": command}, tree={})
    assert MAIN_PKG not in d["deleted"] and d["kept"][MAIN_PKG] == AP.KEPT_NAMED_IN_STRING, case
    if with_init:
        assert "apps/shop/__init__.py" not in d["deleted"]


def test_a_package_main_nobody_names_is_still_deleted():
    d = decide({MAIN_PKG: "print('run')\n"}, extra={"apps/shop/Procfile": "web: python -m apps.other\n"}, tree={})
    assert d["deleted"] == [MAIN_PKG]


@pytest.mark.parametrize("path,names", [
    ("apps/shop/__main__.py", {"apps.shop.__main__", "shop.__main__", "__main__", "apps.shop", "shop"}),
    ("__main__.py", {"__main__"}),
    ("apps/shop/__init__.py", {"apps.shop", "shop"}),
    ("apps/shop/worker.py", {"apps.shop.worker", "shop.worker", "worker"}),
])
def test_module_names_table(path, names):
    assert AP.module_names(path) == names


def test_candidate_paths_of_a_package_main_include_its_folder():
    assert AP.candidate_paths("apps/shop/__main__.py") >= {"apps/shop", "shop", "apps/shop/__main__.py"}
    assert AP.candidate_paths("apps/shop/worker.py") == {"apps/shop/worker.py", "shop/worker.py", "worker.py"}


def test_an_f_string_module_name_is_not_seen():
    """RT F10 (documented limitation): a name built at run time is not a constant; a folded concatenation is."""
    only_fstring = decide({WORKER: "x = 1\n"}, extra={"apps/shop/run.py": "n = 'w'\nm = f'apps.shop.{n}orker'\n"})
    assert only_fstring["deleted"] == [WORKER]
    folded = decide({WORKER: "x = 1\n"}, extra={"apps/shop/run.py": "m = 'apps.shop.' 'worker'\n"})
    assert folded["kept"] == {WORKER: AP.KEPT_NAMED_IN_STRING}

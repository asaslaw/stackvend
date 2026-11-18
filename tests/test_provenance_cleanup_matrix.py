"""Provenance cleanup robustness (plan docs/planning/provenance-cleanup-robustness-plan.md; register rows
PROVENANCE-HISTORY, PROVENANCE-CONSTANT-DYNAMIC-IMPORT, QA-FINDING-ON-UNOWNED-FILE, PLATFORM-RENDERED-FINDING).

The owner's 11-13 ask: prove the mechanism across scenarios, not the one live case. `test_matrix` drives the REAL
provenance code (`find_orphans` -> commit -> `record_for_commit`, the developer's exact sequence) against a fake
repository with branches, one sequence of builds per scenario, and asserts what the last build deletes and keeps.
Negative tests: a valid / hand-edited file is never touched (invariant 1). Hermetic: no Firestore, no VCS.
"""
import hermetic_guard  # noqa: F401  (first import)

import dataclasses
import inspect
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

import test_qa_feedback  # noqa: E402,F401  (puts the gateway on sys.path, as the SAT-49 F4 tests do)
from developer_agent import app_provenance as AP  # noqa: E402

PID = "shop"


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


# ------------------------------------------------------------------------------------------------ fake repository
class Repo:
    """A workload repository (branches of {path: text}) plus its app provenance store. `build` runs the developer's
    provenance sequence for one stack-validated dispatch: read the record, decide the orphans on the start tree,
    commit (the start tree minus the deletions plus the build) to a branch, append the record, maybe merge."""

    def __init__(self, main=None):
        self.branches = {"main": dict(main or {})}
        self.store = AP.MemoryAppProvenanceStore()
        self.n = 0

    @property
    def main(self):
        return self.branches["main"]

    def build(self, files, *, base="main", merge=False, complete=True):
        self.n += 1
        start = self.branches[base]
        record = self.store.load(PID)
        decision = AP.find_orphans(record, start, files, tree_complete=complete) if record else {
            "status": AP.STATUS_NO_RECORD, "deleted": [], "kept": {}, "carry": {}, "blocked_by": None}
        branch = {p: c for p, c in start.items() if p not in decision["deleted"]}
        branch.update(files)
        name = f"castor/{PID}-{self.n}"
        self.branches[name] = branch
        pins = AP.start_tree_pins(record, start)
        self.store.save(PID, AP.record_for_commit(list(files), files, f"t{self.n}", self.store.load(PID), pins,
                                                  pins if base == "main" else {}))   # RT R3: the handler's rule
        if merge:
            self.branches["main"] = dict(branch)
        return dict(decision, branch=name)

    def edit_main(self, path, text):
        if text is None:
            self.main.pop(path, None)
        else:
            self.main[path] = text


MAIN_PY = "apps/shop/main.py"
CONFTEST = "tests/conftest.py"
OLD_TEST = "tests/test_iap_auth.py"
NEW_TEST = "tests/test_auth.py"
APP_V1 = "from fastapi import FastAPI\napp = FastAPI()\n"
APP_V2 = "from fastapi import FastAPI\napp = FastAPI(title='v2')\n"


def T(name, version=1):
    """A leaf test file (nothing imports a test module)."""
    return f"def test_{name}():\n    assert {version}\n"


# ------------------------------------------------------------------------------------------------ scenario matrix
def fresh_workload(r):
    d = r.build({MAIN_PY: APP_V1, NEW_TEST: T("a")}, merge=True)
    assert d["status"] == AP.STATUS_NO_RECORD and d["deleted"] == []
    assert AP.shas_of(r.store.load(PID)[NEW_TEST]) == {AP.sha256(T("a"))}
    return d, [], [NEW_TEST, MAIN_PY]


def relaunch_after_merge(r):
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old")}, merge=True)
    d = r.build({MAIN_PY: APP_V2, NEW_TEST: T("new")})
    return d, [OLD_TEST], [MAIN_PY]


def merged_then_unmerged_rewrite_ex01(r):
    """11-12/11-13 ex01: PR #2 merged test_iap_auth.py v1; PR #5 (unmerged) rewrote it; the 11-13 rebuild starts from
    main (v1). Before PROVENANCE-HISTORY the record held only PR #5's sha, so main's copy was 'a person's file'."""
    r.build({MAIN_PY: APP_V1, CONFTEST: "import pytest\n", OLD_TEST: T("iap", 1)}, merge=True)
    r.build({MAIN_PY: APP_V1, CONFTEST: "import pytest\n", OLD_TEST: T("iap", 2)})   # PR #5: never merged
    d = r.build({MAIN_PY: APP_V2, CONFTEST: "import pytest  # renamed fixtures\n", NEW_TEST: T("auth")})
    assert r.store.load(PID)[OLD_TEST]["history"] == [AP.sha256(T("iap", 1)), AP.sha256(T("iap", 2))]
    return d, [OLD_TEST], [CONFTEST]


def unmerged_branch_deleted_the_orphan(r):
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old")}, merge=True)
    first = r.build({MAIN_PY: APP_V2})                      # deletes OLD_TEST on its branch; never merged
    assert first["deleted"] == [OLD_TEST] and OLD_TEST in r.store.load(PID)   # the entry survives the deletion
    d = r.build({MAIN_PY: APP_V2})                          # main still has it: deleted again
    return d, [OLD_TEST], [MAIN_PY]


def failed_run_no_merge(r):
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("x", 1)}, merge=True)
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("x", 2)})         # QA failed, no merge
    d = r.build({MAIN_PY: APP_V2, NEW_TEST: T("y")})
    return d, [OLD_TEST], []


def hand_edited(r):
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old")}, merge=True)
    r.edit_main(OLD_TEST, T("old") + "# a person's change\n")
    d = r.build({MAIN_PY: APP_V2})
    assert OLD_TEST not in d["kept"]                        # not even a candidate: not platform-written
    return d, [], [OLD_TEST]


def reverted_to_platform_bytes(r):
    """By design (I-OWN): bytes identical to a platform version are platform-written again."""
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old")}, merge=True)
    r.edit_main(OLD_TEST, T("old") + "# edit\n")
    r.edit_main(OLD_TEST, T("old"))
    d = r.build({MAIN_PY: APP_V2})
    return d, [OLD_TEST], []


def renamed_by_new_build(r):
    r.build({MAIN_PY: APP_V1, "tests/test_a.py": T("a")}, merge=True)
    d = r.build({MAIN_PY: APP_V1, "tests/unit/test_a.py": T("a")})
    assert "tests/unit/test_a.py" in r.store.load(PID)
    return d, ["tests/test_a.py"], []


def multi_service_tests(r):
    r.build({"apps/a/main.py": APP_V1, "apps/a/tests/test_x.py": T("x"),
             "apps/b/main.py": APP_V1, "apps/b/tests/test_y.py": T("y")}, merge=True)
    d = r.build({"apps/a/main.py": APP_V2, "apps/a/tests/test_x2.py": T("x2"),
                 "apps/b/main.py": APP_V1, "apps/b/tests/test_y.py": T("y")})
    return d, ["apps/a/tests/test_x.py"], ["apps/b/tests/test_y.py"]


def deleted_by_person(r):
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old")}, merge=True)
    r.edit_main(OLD_TEST, None)
    d = r.build({MAIN_PY: APP_V2})
    assert OLD_TEST in r.store.load(PID)                    # harmless history
    return d, [], []


def fixture_rename_same_conftest(r):
    r.build({MAIN_PY: APP_V1, CONFTEST: "import pytest\n\n@pytest.fixture\ndef es256_keyring():\n    return 1\n",
             OLD_TEST: "def test_x(es256_keyring):\n    assert es256_keyring\n"}, merge=True)
    d = r.build({MAIN_PY: APP_V1, CONFTEST: "import pytest\n\n@pytest.fixture\ndef iap_keypair():\n    return 1\n",
                 NEW_TEST: "def test_y(iap_keypair):\n    assert iap_keypair\n"})
    return d, [OLD_TEST], [CONFTEST]


def conftest_moved(r):
    """Known limit (plan §2.1): a conftest.py is loaded by directory scan, so it is never removed."""
    r.build({MAIN_PY: APP_V1, CONFTEST: "import pytest\n"}, merge=True)
    d = r.build({MAIN_PY: APP_V1, "apps/shop/tests/conftest.py": "import pytest\n"})
    assert d["kept"] == {CONFTEST: AP.KEPT_CONFTEST}
    return d, [], [CONFTEST]


def pre_change_record(r):
    """Migration: a record written before PROVENANCE-HISTORY ({sha256, trace_id}) is a one-version history."""
    r.main.update({MAIN_PY: APP_V1, OLD_TEST: T("old")})
    r.store.data[PID] = {OLD_TEST: {"sha256": AP.sha256(T("old")), "trace_id": "t-old"}}
    d = r.build({MAIN_PY: APP_V2})
    assert r.store.load(PID)[OLD_TEST]["history"] == [AP.sha256(T("old"))]
    return d, [OLD_TEST], []


def qa_repair_dispatch(r):
    """A QA repair starts from the tested branch, not main: the cleanup runs on that tree; the repaired version is
    appended (both versions stay recorded)."""
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old")}, merge=True)
    first = r.build({MAIN_PY: APP_V2, NEW_TEST: T("new", 1)})
    d = r.build({MAIN_PY: APP_V2, NEW_TEST: T("new", 2)}, base=first["branch"])
    assert d["deleted"] == []                               # already deleted on that branch
    assert r.store.load(PID)[NEW_TEST]["history"] == [AP.sha256(T("new", 1)), AP.sha256(T("new", 2))]
    return d, [], []


def incomplete_read(r):
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old")}, merge=True)
    d = r.build({MAIN_PY: APP_V2}, complete=False)
    assert d["status"] == AP.STATUS_SKIPPED_TREE_INCOMPLETE
    return d, [], [OLD_TEST]


AUTH_TIME = "import os\ntime_module = __import__(\"time\")\n\n\ndef now():\n    return time_module.time()\n"


def constant_dynamic_import(r):
    """ex01 D2: the new build's `__import__("time")` no longer disables the cleanup; a module named by a constant
    `import_module("apps.shop.plugins.a")` is kept as imported."""
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old"), "apps/shop/plugins/a.py": "A = 1\n"}, merge=True)
    d = r.build({MAIN_PY: APP_V2, "apps/shop/auth.py": AUTH_TIME,
                 "apps/shop/loader.py": "import importlib\nm = importlib.import_module('apps.shop.plugins.a')\n"})
    assert d["status"] == AP.STATUS_CHECKED and d["kept"] == {"apps/shop/plugins/a.py": AP.KEPT_IMPORTED}
    return d, [OLD_TEST], ["apps/shop/plugins/a.py"]


def bounded_computed_import(r):
    """Review 11-13 item 3: `import_module(f"plugins.{name}")` keeps only what it could load; the run goes on."""
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old"), "apps/shop/plugins/a.py": "A = 1\n",
             "apps/shop/plugins/__init__.py": ""}, merge=True)
    d = r.build({MAIN_PY: APP_V2,
                 "apps/shop/loader.py": "import importlib\n\n\ndef load(n):\n"
                                        "    return importlib.import_module(f'plugins.{n}')\n"})
    assert d["status"] == AP.STATUS_CHECKED
    assert d["kept"] == {"apps/shop/plugins/a.py": AP.KEPT_IMPORTED, "apps/shop/plugins/__init__.py": AP.KEPT_IMPORTED}
    return d, [OLD_TEST], ["apps/shop/plugins/a.py"]


def computed_dynamic_import(r):
    """No constant head: removes nothing (unchanged SKIPPED_DYNAMIC_IMPORT; F3 makes the QA consequence loud)."""
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("old")}, merge=True)
    d = r.build({MAIN_PY: APP_V2, "apps/shop/loader.py": "import importlib\nm = importlib.import_module(NAME)\n"})
    assert d["status"] == AP.STATUS_SKIPPED_DYNAMIC_IMPORT and d["blocked_by"] == "apps/shop/loader.py"
    return d, [], [OLD_TEST]


SCENARIOS = [fresh_workload, relaunch_after_merge, merged_then_unmerged_rewrite_ex01,
             unmerged_branch_deleted_the_orphan, failed_run_no_merge, hand_edited, reverted_to_platform_bytes,
             renamed_by_new_build, multi_service_tests, deleted_by_person, fixture_rename_same_conftest,
             conftest_moved, pre_change_record, qa_repair_dispatch, incomplete_read, constant_dynamic_import,
             bounded_computed_import, computed_dynamic_import]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.__name__ for s in SCENARIOS])
def test_matrix(scenario):
    r = Repo()
    decision, deleted, survivors = scenario(r)
    assert decision["deleted"] == sorted(deleted)
    branch = r.branches[decision["branch"]]
    for p in survivors:
        assert p in branch, p
    for p in deleted:
        assert p not in branch, p


# ------------------------------------------------------------------------------------------------ record invariants
def test_a_record_never_drops_an_entry_across_any_build_sequence():
    """I-REC over a long mixed sequence: every (path, version) the platform committed stays recorded (bounds aside)."""
    r = Repo()
    committed = set()
    plan = [({MAIN_PY: APP_V1, "a.py": "a = 1\n"}, True), ({MAIN_PY: APP_V2, "b.py": "b = 1\n"}, False),
            ({MAIN_PY: APP_V1, "a.py": "a = 2\n"}, True), ({"c.py": "c = 1\n"}, False), ({MAIN_PY: APP_V2}, True)]
    for files, merge in plan:
        r.build(files, merge=merge)
        committed |= {(p, AP.sha256(c)) for p, c in files.items()}
        rec = r.store.load(PID)
        assert all(p in rec and s in AP.shas_of(rec[p]) for p, s in committed)


def test_history_bound_keeps_the_start_tree_version_and_the_newest(monkeypatch):
    monkeypatch.setattr(AP, "APP_PROVENANCE_HISTORY_MAX", 3)
    r = Repo()
    r.build({OLD_TEST: T("x", 0)}, merge=True)              # main holds version 0
    for v in range(1, 6):                                   # five unmerged rewrites
        r.build({OLD_TEST: T("x", v)})
    hist = r.store.load(PID)[OLD_TEST]["history"]
    assert len(hist) == 3 and hist[0] == AP.sha256(T("x", 0)) and hist[-1] == AP.sha256(T("x", 5))
    assert r.build({MAIN_PY: APP_V1})["deleted"] == [OLD_TEST]   # main's copy is still removable


def test_rt_r3_main_version_survives_more_than_16_unmerged_versions():
    """RT R3 reproduction: a regeneration from main, then 20 QA-repair commits from the tested branch (whose pin is
    the branch's version) rewriting one path. Before the fix main's version was evicted after 16; now it is the
    entry's `base` and stays, so the relaunch from main still removes the stale file."""
    r = Repo()
    r.build({MAIN_PY: APP_V1, OLD_TEST: T("x", 0)}, merge=True)              # main: version 0
    branch = r.build({MAIN_PY: APP_V2, OLD_TEST: T("x", 1)})["branch"]     # regeneration from main: base = v0
    for v in range(2, 22):                                                  # QA repairs on the tested branch
        branch = r.build({MAIN_PY: APP_V2, OLD_TEST: T("x", v)}, base=branch)["branch"]
    entry = r.store.load(PID)[OLD_TEST]
    main_sha = AP.sha256(T("x", 0))
    assert len(entry["history"]) == AP.APP_PROVENANCE_HISTORY_MAX and main_sha in entry["history"]
    assert entry["base"] == main_sha and entry["history"][-1] == AP.sha256(T("x", 21))
    assert r.build({MAIN_PY: APP_V2, NEW_TEST: T("new")})["deleted"] == [OLD_TEST]


def test_rt_r3_base_is_cleared_when_the_default_branch_holds_a_persons_version():
    rec = AP.record_for_commit([OLD_TEST], {OLD_TEST: T("x")}, "t1", {}, base_pins={})
    rec = AP.record_for_commit([], {}, "t2", rec, base_pins={OLD_TEST: AP.sha256(T("x"))})
    assert rec[OLD_TEST]["base"] == AP.sha256(T("x"))
    rec = AP.record_for_commit([], {}, "t3", rec, base_pins={OLD_TEST: AP.sha256("a person's\n")})
    assert "base" not in rec[OLD_TEST]
    assert AP.parse_record({OLD_TEST: dict(rec[OLD_TEST], base="short")}) == {}       # malformed: ignored (kept)


def test_an_evicted_version_is_kept_never_removed(monkeypatch):
    """Fail-safe: without the pin (a start tree that did not hold the file) the oldest version goes; a file with
    those bytes is then not platform-written and stays."""
    monkeypatch.setattr(AP, "APP_PROVENANCE_HISTORY_MAX", 2)
    rec = {}
    for v in range(3):
        rec = AP.record_for_commit([OLD_TEST], {OLD_TEST: T("x", v)}, f"t{v}", rec)
    assert AP.sha256(T("x", 0)) not in AP.shas_of(rec[OLD_TEST])
    d = AP.find_orphans(rec, {OLD_TEST: T("x", 0)}, {}, tree_complete=True)
    assert d["deleted"] == [] and d["kept"] == {}


@pytest.mark.parametrize("raw,want", [
    ({"a.py": {"sha256": "1" * 64, "trace_id": "t"}}, {"a.py": ["1" * 64]}),                       # migration
    ({"a.py": {"sha256": "1" * 64, "trace_id": "t", "history": ["2" * 64]}}, {"a.py": ["2" * 64, "1" * 64]}),
    ({"a.py": {"sha256": "1" * 64, "trace_id": "t", "history": ["1" * 64, "2" * 64]}},
     {"a.py": ["2" * 64, "1" * 64]}),                                                           # newest last
    ({"a.py": {"sha256": "1" * 64, "trace_id": "t", "history": "x"}}, {}),                        # ignored: kept
    ({"a.py": {"sha256": "1" * 64, "trace_id": "t", "history": ["short"]}}, {}),
])
def test_parse_record_migrates_and_ignores_malformed_history(raw, want):
    assert {p: e["history"] for p, e in AP.parse_record(raw).items()} == want


def test_hand_edited_negative_every_rule_keeps_a_persons_file():
    """Invariant 1: a recorded path whose bytes match no recorded version is never a candidate, whatever else holds."""
    rec = AP.record_for_commit([OLD_TEST, "apps/shop/dead.py"], {OLD_TEST: T("x"), "apps/shop/dead.py": "x = 1\n"},
                               "t1", {})
    edited = {OLD_TEST: T("x") + "\n", "apps/shop/dead.py": "x = 2\n"}
    d = AP.find_orphans(rec, edited, {}, tree_complete=True)
    assert d == {"status": AP.STATUS_CHECKED, "deleted": [], "kept": {}, "carry": {}, "blocked_by": None}


# ------------------------------------------------------------------------------------------------ F2 import shapes
def _refs(src):
    import ast
    return AP.references("apps/shop/x.py", ast.parse(src))


@pytest.mark.parametrize("src,names", [
    ("t = __import__('time')\n", {"time"}),
    ("m = __import__('os.path')\n", {"os", "os.path"}),
    ("import importlib\nm = importlib.import_module('apps.shop.worker')\n", {"apps", "apps.shop", "apps.shop.worker"}),
    ("from importlib import import_module\nm = import_module('worker')\n", {"importlib", "importlib.import_module",
                                                                         "worker"}),
])
def test_constant_import_is_an_ordinary_import(src, names):
    got = _refs(src)
    assert got[3] is False and names <= got[0] and got[4] == set()


@pytest.mark.parametrize("src", [
    "m = __import__(name)\n",                                    # a variable
    "m = __import__(f'{name}')\n",                               # no constant head
    "m = __import__(f'.{name}')\n",                              # relative head
    "m = __import__('.x')\n",                                    # relative constant
    "m = __import__('a b')\n",                                   # not a dotted name
    "m = __import__('x', globals(), locals(), ['y'])\n",         # fromlist / level
    "m = __import__(*args)\n",
    "import importlib\nm = importlib.import_module('.x', package='pkg')\n",
    "import importlib\nm = importlib.import_module(name='x')\n",
    "import importlib\nm = importlib.import_module(b'x')\n",     # bytes, not str
    "exec('import x')\n", "eval('x')\n",
    "import pkgutil\nmods = list(pkgutil.iter_modules(['plugins']))\n",
])
def test_non_constant_import_still_blocks_the_run(src):
    assert _refs(src)[3] is True


@pytest.mark.parametrize("src,prefix", [
    ("import importlib\nm = importlib.import_module(f'plugins.{n}')\n", "plugins."),
    ("import importlib\nm = importlib.import_module('plugins.' + n)\n", "plugins."),
    ("import importlib\nm = importlib.import_module('a.' + n + '.b')\n", "a."),
    ("m = __import__(f'plugin_{n}')\n", "plugin_"),
])
def test_a_computed_import_with_a_constant_head_is_bounded(src, prefix):
    got = _refs(src)
    assert got[3] is False and got[4] == {prefix}


@pytest.mark.parametrize("candidate,prefix,reachable", [
    ("apps/shop/plugins/a.py", "plugins.", True),
    ("apps/shop/plugins/__init__.py", "plugins.", True),         # the package the import passes through
    ("apps/shop/plugin_x.py", "plugin_", True),
    ("apps/shop/routes.py", "plugins.", False),
    ("apps/shop/plugins_old.py", "plugins.", False),             # `plugins_old` is not under `plugins.`
    ("apps/shop/a/b.py", "a.x", False),
    ("apps/shop/a/__init__.py", "a.x", True),
])
def test_reachable_by_prefix_table(candidate, prefix, reachable):
    assert AP.reachable_by_prefix(candidate, {prefix}) is reachable


def test_a_constant_import_of_a_stale_module_keeps_it_negative():
    """Invariant 1 for F2: a module a remaining file loads by a constant name is never deleted."""
    rec = AP.record_for_commit(["apps/shop/worker.py"], {"apps/shop/worker.py": "W = 1\n"}, "t1", {})
    d = AP.find_orphans(rec, {"apps/shop/worker.py": "W = 1\n"},
                        {"apps/shop/run.py": "w = __import__('worker')\n"}, tree_complete=True)
    assert d["deleted"] == [] and d["kept"] == {"apps/shop/worker.py": AP.KEPT_IMPORTED}


# ------------------------------------------------------------------------------------------------ handler seams
def _agent_with(store):
    from test_qa_feedback import _agent as make_agent, _runtime as make_runtime
    return make_agent(dataclasses.replace(make_runtime(None), app_provenance_store=store))


def _validated(agent, trace, files, llm_paths):
    from developer_agent.handler import artifact_hash
    agent._record_stack(trace, validated_hash=artifact_hash(files), llm_draft_paths=list(llm_paths))


def test_write_merges_with_the_stored_record():
    """Another dispatch's versions written after this dispatch started survive this dispatch's write."""
    store = AP.MemoryAppProvenanceStore()
    agent = _agent_with(store)
    agent._load_app_provenance(PID, "t-a", True, True)               # start: no record
    store.save(PID, AP.record_for_commit(["apps/shop/other.py"], {"apps/shop/other.py": "o = 1\n"}, "t-b", {}))
    files = {MAIN_PY: APP_V1}
    _validated(agent, "t-a", files, [MAIN_PY])
    agent._write_app_provenance(PID, "t-a", files)
    assert set(store.load(PID)) == {MAIN_PY, "apps/shop/other.py"}


def test_unreadable_record_at_write_time_is_not_overwritten(caplog):
    class Flaky(AP.MemoryAppProvenanceStore):
        broken = False

        def load(self, pid):
            if self.broken:
                raise AP.AppProvenanceUnavailable("app provenance read failed for shop: RuntimeError")
            return super().load(pid)

        def save(self, pid, entries):
            if self.broken:
                raise AssertionError("written without the stored record")
            super().save(pid, entries)
    store = Flaky()
    store.save(PID, AP.record_for_commit([OLD_TEST], {OLD_TEST: T("x")}, "t0", {}))
    agent = _agent_with(store)
    files = {MAIN_PY: APP_V1}
    _validated(agent, "t-a", files, [MAIN_PY])
    store.broken = True
    agent._write_app_provenance(PID, "t-a", files)                   # no exception, nothing written
    store.broken = False
    assert set(store.load(PID)) == {OLD_TEST} and "APP_PROVENANCE_NOT_RECORDED" in caplog.text


def test_both_vcs_providers_take_deletions_in_the_commit():
    """Row 22: GitHub and Serverless Git both delete through commit_files(files_to_delete=...)."""
    from shared.providers.github_provider import GitHubProvider
    from shared.providers.serverless_git_provider import ServerlessGitProvider
    for cls in (GitHubProvider, ServerlessGitProvider):
        assert "files_to_delete" in inspect.signature(cls.commit_files).parameters, cls.__name__


# ------------------------------------------------------------------------------------------------ IaC history
IAM = "infra/workload/iam.tf"


def test_iac_prior_llm_recognizes_mains_version_after_an_unmerged_rewrite():
    """PROVENANCE-HISTORY, IaC part: iac_provenance holds the unmerged branch's sha (last write); main's merged
    version is still the AI's through the history. Without the history: the single-sha check (user-owned)."""
    from shared.diagnostics import ProvenanceEntry
    store = AP.MemoryAppProvenanceStore()
    agent = _agent_with(store)
    v1, v2 = 'resource "x" "a" {}\n', 'resource "x" "a" { n = 2 }\n'
    agent.stack_runtime().provenance_store.save(PID, {IAM: ProvenanceEntry(persona="iac_worker", trace_id="t2",
                                                                           sha256=AP.sha256(v2))})
    assert agent._load_prior_llm(PID, {IAM: v1}) == {}                          # before: a person's file
    agent._write_iac_history(PID, {IAM: ProvenanceEntry(persona="iac_worker", trace_id="t1", sha256=AP.sha256(v1))})
    agent._write_iac_history(PID, {IAM: ProvenanceEntry(persona="iac_worker", trace_id="t2", sha256=AP.sha256(v2))})
    assert store.load_iac_history(PID) == {IAM: [AP.sha256(v1), AP.sha256(v2)]}
    assert agent._load_prior_llm(PID, {IAM: v1}) == {IAM: "iac_worker"}
    assert agent._load_prior_llm(PID, {IAM: v1 + "# edited\n"}) == {}           # a person's edit stays theirs


def test_iac_history_is_ignored_without_an_app_store_and_on_a_read_failure(caplog):
    from shared.diagnostics import ProvenanceEntry

    class Down(AP.MemoryAppProvenanceStore):
        def load_iac_history(self, pid):
            raise AP.AppProvenanceUnavailable("IaC provenance history read failed for shop: RuntimeError")
    for store in (None, Down()):
        agent = _agent_with(store)
        agent.stack_runtime().provenance_store.save(PID, {IAM: ProvenanceEntry(persona="p", trace_id="t",
                                                                               sha256=AP.sha256("a\n"))})
        assert agent._load_prior_llm(PID, {IAM: "a\n"}) == {IAM: "p"}
        assert agent._load_prior_llm(PID, {IAM: "b\n"}) == {}


@pytest.mark.parametrize("raw,want", [
    ({IAM: ["1" * 64]}, {IAM: ["1" * 64]}),
    ({"apps/x.py": ["1" * 64]}, {}), ({IAM: []}, {}), ({IAM: ["x"]}, {}), ({"infra/../x.tf": ["1" * 64]}, {}),
    ("x", {}),
])
def test_parse_iac_history_exact_shape(raw, want):
    assert AP.parse_iac_history(raw) == want


# ------------------------------------------------------------------------------------------------ C + F3: one predicate
from developer_agent import qa_repair as QR  # noqa: E402
from shared.artifact_ownership import Ownership, classify_repository_file  # noqa: E402
from test_qa_feedback import _feedback, _qa_diag  # noqa: E402

PYV = "apps/shop/.python-version"


def _jd(file, code="JUDGE.SECURITY"):
    return dict(_qa_diag(file=file, code=code), tool="judge", **{QR.JUDGE_FINDING_FIELD: True})


TESTED = {MAIN_PY: APP_V1, NEW_TEST: T("new"), OLD_TEST: T("old"), "infra/workload/services.tf": "# rendered\n",
          ".github/workflows/deploy-b.yml": "on: push\n", "cloudbuild.yaml": "steps: []\n",
          "infra/workload/custom.tf.json": "{}\n", "infra/workload/iac_intent.json": "{}\n",
          "infra/workload/human.tf": "# mine\n"}
DRAFT = [MAIN_PY, NEW_TEST, "infra/workload/iac_intent.json"]


@pytest.mark.parametrize("path,record,want", [
    ("infra/workload/human.tf", None, Ownership.USER_OWNED),
    ("infra/workload/custom.tf.json", None, Ownership.LLM_DOCUMENT),          # fixed through the AI's intent
    ("infra/workload/iac_intent.json", None, Ownership.LLM_DOCUMENT),
    ("infra/workload/services.tf", None, Ownership.PLATFORM_RENDERED),
    (".github/workflows/deploy-b.yml", None, Ownership.PLATFORM_RENDERED),     # GitHub CI
    ("cloudbuild.yaml", None, Ownership.PLATFORM_RENDERED),                    # Serverless Git CI
    (MAIN_PY, None, Ownership.LLM_AUTHORED),
    (OLD_TEST, None, Ownership.UNKNOWN),
    (OLD_TEST, {OLD_TEST: T("old")}, Ownership.PRIOR_BUILD),
    (OLD_TEST, {OLD_TEST: T("older")}, Ownership.USER_OWNED),                  # recorded, bytes changed by a person
])
def test_one_ownership_predicate_table(path, record, want):
    rec = AP.record_for_commit(list(record), record, "t0", {}) if record else None
    assert QR.finding_owner(path, TESTED, DRAFT, rec) is want


def test_the_pin_is_platform_rendered_only_with_the_platforms_content():
    from developer_agent.runtime_pin import PLATFORM_PYTHON_VERSION_CONTENT
    assert QR.finding_owner(PYV, {PYV: PLATFORM_PYTHON_VERSION_CONTENT}, [PYV]) is Ownership.PLATFORM_RENDERED
    assert QR.finding_owner(PYV, {PYV: "3.11\n"}, [PYV]) is Ownership.LLM_AUTHORED


def test_classify_repository_file_is_exact():
    assert classify_repository_file("x.py", None, draft=frozenset(), platform_rendered=False,
                                    recorded_versions=frozenset({"0" * 64})) is Ownership.USER_OWNED
    assert classify_repository_file("x.py", None, draft=frozenset(), platform_rendered=False,
                                    recorded_versions=None) is Ownership.UNKNOWN


def _plan(*diags, tree=TESTED, draft=DRAFT, **kw):
    return QR.plan_qa_repair(_feedback(tree, *diags, draft_paths=draft, **kw), stack_configured=True)


@pytest.mark.parametrize("finding", [
    _jd("infra/workload/services.tf"), _jd(".github/workflows/deploy-b.yml"), _jd("cloudbuild.yaml"),
    _qa_diag(file="infra/workload/services.tf"),
])
def test_c_a_finding_on_a_platform_rendered_file_is_a_typed_stop(finding):
    plan = _plan(finding)
    assert (plan.mode, plan.reason, plan.stop_files, plan.seeds) == (
        QR.STOP, QR.PLATFORM_RENDERED_REASON, (finding["file"],), ())
    err = QR.stop_error(plan, PID, _feedback(TESTED, finding, draft_paths=DRAFT))
    body = err.to_body()
    assert (body["error_class"], body["reason"], body["stage"]) == ("PLATFORM_DEFECT", QR.PLATFORM_RENDERED_REASON, "qa")
    assert body["details"]["files"] == [finding["file"]] and body["diagnostics"][0]["file"] == finding["file"]
    assert "message" not in body["diagnostics"][0]                    # QA's text never leaves the untrusted block


def test_c_rides_along_unchanged_when_another_finding_is_repaired():
    """A judge finding on a platform file beside sandbox findings on draft files stays text (unchanged rule)."""
    plan = _plan(_qa_diag(file=MAIN_PY), _jd("infra/workload/services.tf"))
    assert plan.mode == QR.QA_REPAIR and plan.repairable_paths == {MAIN_PY}


@pytest.mark.parametrize("access", ["PUBLIC_APP", "PRIVATE_IAP", "PRIVATE_IAM"])
def test_c_never_turns_a_platform_file_finding_into_a_pass_negative(access):
    """Review §4: an `allUsers` finding on services.tf must still block in a private mode. C has no access input and
    never yields a seedless repair or a pass: it stops."""
    plan = _plan(_jd("infra/workload/services.tf"))
    assert plan.mode == QR.STOP and not plan.seeds, access


def test_c_custom_tf_json_is_the_ais_document_not_a_stop():
    """QA-STOP-RENDER-SOURCES (owner 11-14): custom.tf.json's single source is the AI's intent, so its finding is a
    repair of the intent (before: today's regeneration). Without an intent in the tree: unchanged."""
    plan = _plan(_jd("infra/workload/custom.tf.json"))
    assert (plan.mode, [s.file for s in plan.seeds]) == (QR.QA_REPAIR, ["infra/workload/iac_intent.json"])
    tree = {k: v for k, v in TESTED.items() if k != "infra/workload/iac_intent.json"}
    plan = _plan(_jd("infra/workload/custom.tf.json"), tree=tree, draft=[MAIN_PY, NEW_TEST])
    assert (plan.mode, plan.reason, plan.off_draft_files) == (QR.REGENERATE, QR.NOT_ON_A_DRAFT_FILE, ())


def test_f3_router_lists_the_off_draft_files():
    plan = _plan(_qa_diag(file=OLD_TEST), _qa_diag(file=None))
    assert (plan.mode, plan.reason, plan.off_draft_files) == (QR.REGENERATE, QR.NOT_ON_A_DRAFT_FILE, (OLD_TEST,))


def test_f3_setup_error_group_is_unchanged():
    """Row 32: setup errors on a non-draft test file with test-setup targets stay a QA repair of the test setup."""
    tree = dict(TESTED, **{CONFTEST: "import pytest\n"})
    plan = _plan(_qa_diag(file=OLD_TEST, code="PY.TEST_SETUP_ERROR"), tree=tree, draft=DRAFT + [CONFTEST])
    assert plan.mode == QR.QA_REPAIR and CONFTEST in plan.repairable_paths


# ---- F3 outcome (pure), one row per scenario
def _rec(files):
    return AP.record_for_commit(list(files), files, "t0", {})


BASE = {MAIN_PY: APP_V1, OLD_TEST: T("old")}
HELP = "apps/shop/helpers.py"


@pytest.mark.parametrize("case,files,tree,record,verdict,cleanup", [
    ("ex01_live_record_lost", [OLD_TEST], BASE, {}, QR.REGENERATE, "NOT_PLATFORM_WRITTEN"),   # RT R1: first failure
    ("prior_build_removable", [OLD_TEST], BASE, _rec({OLD_TEST: T("old")}), QR.REGENERATE, AP.REMOVABLE),
    ("hand_edited", [OLD_TEST], BASE, _rec({OLD_TEST: T("platform")}), QR.REGENERATE, "CHANGED_BY_A_PERSON"),   # RT R1
    ("kept_by_a_persons_import", [HELP], {HELP: "H = 1\n", "apps/shop/mine.py": "import helpers\n"},
     _rec({HELP: "H = 1\n"}), QR.STOP, AP.KEPT_IMPORTED),
    ("kept_only_by_a_platform_file", [HELP], {HELP: "H = 1\n", MAIN_PY: "import helpers\n"},
     _rec({HELP: "H = 1\n", MAIN_PY: "import helpers\n"}), QR.REGENERATE, AP.REMOVABLE),
    ("conftest_moved", [CONFTEST], {CONFTEST: "import pytest\n"}, _rec({CONFTEST: "import pytest\n"}), QR.STOP,
     AP.KEPT_CONFTEST),
    ("computed_import_in_a_persons_file", [OLD_TEST], dict(BASE, **{"apps/shop/mine.py": "m = __import__(n)\n"}),
     _rec({OLD_TEST: T("old")}), QR.STOP, AP.STATUS_SKIPPED_DYNAMIC_IMPORT),
    ("outside_the_provenance", ["infra/workload/aux.tf"], {"infra/workload/aux.tf": "x\n"}, {}, QR.REGENERATE,
     "NOT_AN_APP_PATH"),
])
def test_f3_outcome_matrix(case, files, tree, record, verdict, cleanup):
    out = QR.unowned_finding_outcome(files, tree, tree, record, base_complete=True)
    assert out["verdict"] == verdict, case
    assert out["files"][0]["cleanup"] == cleanup, case


@pytest.mark.parametrize("tested,base", [
    (dict(BASE, **{OLD_TEST: T("changed on the tested branch")}), BASE),
    (BASE, {MAIN_PY: APP_V1}),                                       # not on the default branch
])
def test_f3_changed_or_absent_on_main_regenerates(tested, base):
    out = QR.unowned_finding_outcome([OLD_TEST], tested, base, {}, base_complete=True)
    assert out["verdict"] == QR.REGENERATE and out["files"][0]["unchanged_on_default_branch"] is False


def test_f3_incomplete_base_regenerates():
    out = QR.unowned_finding_outcome([OLD_TEST], BASE, BASE, {}, base_complete=False)
    assert (out["verdict"], out["reason"]) == (QR.REGENERATE, "BASE_TREE_INCOMPLETE")


def test_rt_r2_the_contract_written_requirements_file_is_derived_not_unowned():
    """RT R2 (S10): on a relaunch, the gatekeeper's contract-written apps/<svc>/requirements.txt (byte-exact proof,
    written_by_requirements_contract) has the same bytes on main and no record; a REQ.UNRESOLVABLE on it regenerates
    (the file is derived from the draft's imports). A person's requirements file with other bytes is not derived."""
    from test_qa_repair_missing_module import REQS, _ex08_tree
    tree, draft_paths = _ex08_tree()
    assert REQS not in draft_paths and QR.written_by_requirements_contract(tree, REQS)
    plan = QR.plan_qa_repair(_feedback(tree, _qa_diag(file=REQS, code="REQ.UNRESOLVABLE"), draft_paths=draft_paths),
                             stack_configured=True)
    assert (plan.mode, plan.off_draft_files) == (QR.REGENERATE, (REQS,))
    out = QR.unowned_finding_outcome(plan.off_draft_files, tree, tree, {}, base_complete=True)
    assert out["verdict"] == QR.REGENERATE and out["files"][0]["cleanup"] == QR.DERIVED_FROM_THE_DRAFT
    persons = dict(tree, **{REQS: tree[REQS] + "pinned-by-me==1.0\n"})
    out = QR.unowned_finding_outcome([REQS], persons, persons, {}, base_complete=True)
    assert out["files"][0]["cleanup"] != QR.DERIVED_FROM_THE_DRAFT


# ---- F3 / C at the developer stage seam (before any LLM call)
def _qa_agent(store, base, complete=True):
    agent = _agent_with(store)
    fetch = MagicMock(return_value=dict(base))

    def fetched(pid):
        agent.last_tree_status = {"complete": complete, "truncated": not complete, "error": None}
        return fetch(pid)
    agent.fetch_existing_repo_files = fetched
    return agent, fetch


def test_f3_removable_file_regenerates_and_records_why():
    store = AP.MemoryAppProvenanceStore()
    store.save(PID, _rec(BASE))
    agent, _fetch = _qa_agent(store, BASE)
    fb = _feedback(dict(BASE, **{NEW_TEST: T("new")}), _qa_diag(file=OLD_TEST), draft_paths=[MAIN_PY, NEW_TEST])
    assert agent._plan_qa_repair(PID, "t-qa", {"qa_feedback": fb}) is None      # today's regeneration
    check = agent.stack_run("t-qa")["qa_repair"]["unowned_check"]
    assert check["verdict"] == QR.REGENERATE and check["files"][0]["cleanup"] == AP.REMOVABLE


@pytest.mark.parametrize("store_kind", ["none", "unreadable", "incomplete"])
def test_f3_without_evidence_regenerates(store_kind):
    class Down(AP.MemoryAppProvenanceStore):
        def load(self, pid):
            raise AP.AppProvenanceUnavailable("app provenance read failed for shop: RuntimeError")
    store = {"none": None, "unreadable": Down(), "incomplete": AP.MemoryAppProvenanceStore()}[store_kind]
    agent, fetch = _qa_agent(store, BASE, complete=store_kind != "incomplete")
    fb = _feedback(BASE, _qa_diag(file=OLD_TEST), draft_paths=[MAIN_PY])
    assert agent._plan_qa_repair(PID, "t-qa", {"qa_feedback": fb}) is None
    check = agent.stack_run("t-qa")["qa_repair"]["unowned_check"]
    assert check["verdict"] == QR.REGENERATE and check["reason"] in (
        "NO_PROVENANCE_STORE", "EVIDENCE_UNAVAILABLE (AppProvenanceUnavailable)", "BASE_TREE_INCOMPLETE")
    if store_kind == "none":
        assert fetch.call_count == 0


def test_c_stops_at_the_developer_stage_seam_with_platform_defect():
    from gate_errors import PlatformDefectError
    agent, fetch = _qa_agent(AP.MemoryAppProvenanceStore(), TESTED)
    fb = _feedback(TESTED, _jd("infra/workload/services.tf"), draft_paths=DRAFT)
    with pytest.raises(PlatformDefectError) as ei:
        agent._plan_qa_repair(PID, "t-qa", {"qa_feedback": fb})
    assert ei.value.reason == QR.PLATFORM_RENDERED_REASON and fetch.call_count == 0
    assert agent.stack_run("t-qa")["qa_repair"]["stop_files"] == ["infra/workload/services.tf"]


# ---- RT R1: an unowned file stops at once only on proof, else after one regeneration
ORDERS = "apps/shop/orders.py"
ORDERS_TEST = "tests/test_orders.py"
RT_BASE = {ORDERS: "def total():\n    return 1\n", ORDERS_TEST: "from orders import total\n\n\ndef test_total():\n"
                                                             "    assert total() == 1\n"}
RT_TESTED = dict(RT_BASE, **{ORDERS: "def total():\n    return 2\n", "apps/shop/main.py": APP_V1,
                              "tests/test_main.py": T("main")})
RT_DRAFT = [ORDERS, "apps/shop/main.py", "tests/test_main.py"]


def _rt_record(kind):
    """S1 no record (first run on a person's repository / a workload from before SAT-49 F4), S2 a record of the
    platform's files only (feature request), S4 the platform wrote the test and a person edited it on purpose."""
    if kind == "none":
        return {}
    if kind == "platform_only":
        return _rec({ORDERS: RT_BASE[ORDERS]})
    return _rec({ORDERS: RT_BASE[ORDERS], ORDERS_TEST: "def test_total():\n    assert True\n"})


def _rt_feedback(attempt, *diags):
    return _feedback(RT_TESTED, *(diags or (_qa_diag(file=ORDERS_TEST),)), draft_paths=RT_DRAFT, attempt=attempt)


@pytest.mark.parametrize("kind", ["none", "platform_only", "hand_edited"])
@pytest.mark.parametrize("diags", [
    (_qa_diag(file=ORDERS_TEST),),                                                       # S1-S4
    (_qa_diag(file=ORDERS_TEST, code="PY.TEST_SETUP_ERROR"), _qa_diag(file=ORDERS_TEST)),
    (_qa_diag(file="tests/test_main.py"), _qa_diag(file=ORDERS_TEST)),                    # S9: draft + person
], ids=["test_failed", "setup_error_and_failed", "draft_and_person"])
def test_rt_r1_a_pytest_finding_on_a_persons_unchanged_test_regenerates_first(kind, diags):
    """RT R1 reproduction: the build edits orders.py (draft) and breaks the person's unchanged tests/test_orders.py.
    Before R1: OPERATOR_ACTION_REQUIRED at attempt 0. Now: one regeneration (the defect is in the draft); a
    recurrence at a later attempt, same file and bytes, stops."""
    from gate_errors import OperatorActionRequiredError
    store = AP.MemoryAppProvenanceStore()
    store.save(PID, _rt_record(kind))
    agent, _fetch = _qa_agent(store, RT_BASE)
    assert agent._plan_qa_repair(PID, "t-rt", {"qa_feedback": _rt_feedback(0, *diags)}) is None
    check = agent.stack_run("t-rt")["qa_repair"]["unowned_check"]
    assert (check["verdict"], check["reason"]) == (QR.REGENERATE, QR.FIRST_FAILURE_REASON)
    with pytest.raises(OperatorActionRequiredError) as ei:
        agent._plan_qa_repair(PID, "t-rt", {"qa_feedback": _rt_feedback(1, *diags)})
    body = ei.value.to_body()
    assert body["reason"] == QR.UNOWNED_FILE_REASON and body["details"]["files"][0]["stop"] == QR.STOP_RECURRED
    assert "delete" not in body["summary"].split("(")[0]          # the first remedy is to review, not to delete


def test_rt_r1_recurrence_needs_the_same_bytes_and_a_later_attempt():
    seen = QR.seen_entries({"files": [{"file": ORDERS_TEST, "sha256": AP.sha256(RT_BASE[ORDERS_TEST]),
                                     "first_failure": True}]}, 0)
    same = QR.unowned_finding_outcome([ORDERS_TEST], RT_TESTED, RT_BASE, {}, base_complete=True, seen=seen, attempt=1)
    assert same["verdict"] == QR.STOP
    for attempt in (0, None):                                     # not a later attempt: first failure again
        out = QR.unowned_finding_outcome([ORDERS_TEST], RT_TESTED, RT_BASE, {}, base_complete=True, seen=seen,
                                         attempt=attempt)
        assert out["verdict"] == QR.REGENERATE
    changed = dict(RT_BASE, **{ORDERS_TEST: RT_BASE[ORDERS_TEST] + "# edited\n"})
    out = QR.unowned_finding_outcome([ORDERS_TEST], changed, changed, {}, base_complete=True, seen=seen, attempt=1)
    assert out["verdict"] == QR.REGENERATE                         # other bytes: not the same failure


@pytest.mark.parametrize("code", ["JUDGE.SECURITY", "PY.BANDIT_HIGH", "REQ.UNRESOLVABLE"])
def test_rt_r1_an_intrinsic_finding_on_a_persons_file_stops_at_once(code):
    """S7: a finding about the file itself (not a test outcome) cannot be fixed by regenerating the draft."""
    out = QR.unowned_finding_outcome([ORDERS_TEST], RT_TESTED, RT_BASE, {}, base_complete=True,
                                     codes={ORDERS_TEST: (code,)}, attempt=0)
    assert out["verdict"] == QR.STOP and out["files"][0]["stop"] == QR.STOP_INTRINSIC
    mixed = QR.unowned_finding_outcome([ORDERS_TEST], RT_TESTED, RT_BASE, {}, base_complete=True,
                                       codes={ORDERS_TEST: (code, "PY.TEST_FAILED")}, attempt=0)
    assert mixed["verdict"] == QR.REGENERATE                       # any test outcome among them: first failure


def test_rt_r1_a_proven_stale_platform_file_still_stops_at_once():
    """Rows 16 / 30 / 44 keep their outcome for PRIOR_BUILD: the platform proved it wrote the file."""
    rec = _rec({HELP: "H = 1\n"})
    tree = {HELP: "H = 1\n", "apps/shop/mine.py": "import helpers\n"}
    out = QR.unowned_finding_outcome([HELP], tree, tree, rec, base_complete=True, codes={HELP: ("PY.TEST_FAILED",)},
                                     attempt=0)
    assert out["verdict"] == QR.STOP and out["files"][0]["stop"] == QR.STOP_PROVEN_STALE


def test_rt_r1_the_router_hands_the_codes_per_file():
    plan = _plan(_qa_diag(file=OLD_TEST), _qa_diag(file=OLD_TEST, code="JUDGE.SECURITY"))
    assert dict(plan.off_draft_codes) == {OLD_TEST: ("JUDGE.SECURITY", "PY.TEST_FAILED")}


def test_f3_ex01_live_record_regenerates_once_then_stops():
    """Row 16 (the live ex01 workload, no record entry for the stale test): attempt 0 regenerates once (the
    relaunch may still fix it), attempt 1 with the same file and bytes stops OPERATOR_ACTION_REQUIRED instead of a
    third futile round."""
    from gate_errors import OperatorActionRequiredError
    store = AP.MemoryAppProvenanceStore()
    store.save(PID, _rec({MAIN_PY: APP_V1}))
    tested = dict(BASE, **{NEW_TEST: T("new")})
    agent, fetch = _qa_agent(store, BASE)
    fb0 = _feedback(tested, _qa_diag(file=OLD_TEST), draft_paths=[MAIN_PY, NEW_TEST], attempt=0)
    assert agent._plan_qa_repair(PID, "t-qa", {"qa_feedback": fb0}) is None
    fb1 = _feedback(tested, _qa_diag(file=OLD_TEST), draft_paths=[MAIN_PY, NEW_TEST], attempt=1)
    with pytest.raises(OperatorActionRequiredError) as ei:
        agent._plan_qa_repair(PID, "t-qa", {"qa_feedback": fb1})
    body = ei.value.to_body()
    assert (body["reason"], body["stage"]) == (QR.UNOWNED_FILE_REASON, "qa")
    assert [f["file"] for f in body["details"]["files"]] == [OLD_TEST]
    assert body["details"]["files"][0]["cleanup"] == "NOT_PLATFORM_WRITTEN" and fetch.call_count == 2
    # corpus review 11-13: the persisted decision of the stopping dispatch is the stop, never a regeneration
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["reason"]) == (QR.STOP, QR.UNOWNED_FILE_REASON)


def test_rt_r1_the_first_failure_is_persisted_for_the_next_dispatch():
    """The evidence survives a new gateway instance: stages.developer.unowned_seen (merged) is read back."""
    from fd4f_support import FakeDB
    from gate_errors import OperatorActionRequiredError
    db = FakeDB()
    store = AP.MemoryAppProvenanceStore()
    first, _f = _qa_agent(store, RT_BASE)
    first.db = db
    assert first._plan_qa_repair(PID, "t-db", {"qa_feedback": _rt_feedback(0)}) is None
    # Firestore's merge is deep, FakeDB's is shallow: rebuild the document from the exact write the dispatch made
    (path, data, merge), = [w for w in db.writes if "unowned_seen" in str(w[1])]
    assert path == "pipeline_executions/t-db" and merge is True
    seen = data["stages"]["developer"]["unowned_seen"]
    assert [v["file"] for v in seen.values()] == [ORDERS_TEST]
    fresh = FakeDB()
    fresh.docs[path] = data
    second, _f2 = _qa_agent(store, RT_BASE)                       # another instance: no in-memory record
    second.db = fresh
    with pytest.raises(OperatorActionRequiredError):
        second._plan_qa_repair(PID, "t-db", {"qa_feedback": _rt_feedback(1)})


# ---- QA-REPAIR-KEEPS-ORPHAN-DELETIONS (PROVENANCE-HISTORY note; corpus scenario 01)
def _carry(base, record, tree, carried, complete=True):
    from types import SimpleNamespace
    agent, fetch = _qa_agent(None, base, complete=complete)
    inputs = SimpleNamespace(product_id=PID, trace_id="t-carry")
    decision = {"status": AP.STATUS_CHECKED, "deleted": [], "kept": {}, "carry": {}, "blocked_by": None}
    return agent._carry_orphan_deletions(inputs, tree, record, decision, carried), fetch


def test_a_qa_repair_repeats_the_builds_orphan_deletions_by_recorded_path_and_provenance():
    rec = _rec({OLD_TEST: T("old")})
    out, fetch = _carry(BASE, rec, {MAIN_PY: APP_V2}, [OLD_TEST])
    assert out["deleted"] == [OLD_TEST] and out["carried"] == [OLD_TEST] and fetch.call_count == 1


@pytest.mark.parametrize("case,base,record,tree,complete", [
    ("person_changed_it_on_main", dict(BASE, **{OLD_TEST: T("old") + "# mine\n"}), "rec", {}, True),
    ("no_record", BASE, "none", {}, True),
    ("gone_from_main", {MAIN_PY: APP_V1}, "rec", {}, True),
    ("the_repair_writes_it", BASE, "rec", {OLD_TEST: T("new")}, True),
    ("default_branch_incomplete", BASE, "rec", {}, False),
])
def test_a_carried_deletion_without_proof_is_dropped_negative(case, base, record, tree, complete):
    """Invariant 1: a carried path is deleted again only with the default branch's bytes still a recorded platform
    version; anything else is kept (never a wrong deletion)."""
    rec = _rec({OLD_TEST: T("old")}) if record == "rec" else {}
    out, _fetch = _carry(base, rec, tree, [OLD_TEST], complete=complete)
    assert out["deleted"] == [] and out["carried_dropped"] == [OLD_TEST], case


def test_the_gateway_records_and_forwards_the_commits_orphan_deletions():
    """main._committed_draft_extras / _matched_commit_extras (exec'd from the gateway source, as the SAT-49 F4
    gateway tests do): only paths the commit really deleted, both keys always written, forwarded only for exactly
    the tested commit."""
    import ast
    src = open(os.path.join(TESTS, "..", "apps", "orchestrator-gateway", "main.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef)
           and n.name in ("_committed_draft_extras", "_matched_commit_extras")]
    from typing import Any, Dict, Mapping
    from qa_source import is_commit_sha
    ns = {"Any": Any, "Dict": Dict, "Mapping": Mapping, "_DRAFT_PATHS_MAX": 3,
          "_QA_ORPHAN_DELETIONS_FIELD": QR.ORPHAN_DELETIONS_FIELD, "_QA_COMMITTED_PATHS_FIELD": QR.COMMITTED_PATHS_FIELD,
          "_QA_BASE_HEAD_SHA_FIELD": QR.BASE_HEAD_SHA_FIELD, "is_commit_sha": is_commit_sha}   # RT14-13
    exec(compile(ast.Module(body=fns, type_ignores=[]), "main.py", "exec"), ns)  # noqa: S102 - repo code
    extras = ns["_committed_draft_extras"]
    run = {"app_orphan_deletions": [OLD_TEST, "tests/other.py"]}
    result = {"files_deleted": [OLD_TEST, ".github/workflows/deploy-x.yml"], "files_committed": [MAIN_PY]}
    assert extras(run, result) == {"orphan_deletions": [OLD_TEST], "committed_paths": [MAIN_PY],
                                   "base_head_sha": None}
    assert extras(None, {}) == {"orphan_deletions": [], "committed_paths": None,     # every key, always
                                "base_head_sha": None}
    assert extras(run, dict(result, files_committed=["a", "b", "c", "d"]))["committed_paths"] is None
    record = {"commit_sha": "a" * 40, "llm_draft_paths": [MAIN_PY], "orphan_deletions": [OLD_TEST],
              "committed_paths": [MAIN_PY]}
    ns["_read_committed_draft"] = lambda gdb, trace: (record, "")
    assert ns["_matched_commit_extras"](None, "t", "a" * 40) == {"orphan_deletions": [OLD_TEST],
                                                                 "committed_paths": [MAIN_PY]}
    assert ns["_matched_commit_extras"](None, "t", "b" * 40) == {}                 # another commit: nothing
    assert QR.recorded_paths({"orphan_deletions": [OLD_TEST, "infra/x.tf", 5]}, QR.ORPHAN_DELETIONS_FIELD) == ()
    assert QR.recorded_paths({"orphan_deletions": [OLD_TEST, "infra/x.tf"]}, QR.ORPHAN_DELETIONS_FIELD) == (OLD_TEST,)


# ---- RT probe 6 / S1: one registry for QA routing and the judges' platform facts
def test_platform_rendered_paths_equals_what_qa_routing_classes_platform_rendered():
    from qa_auditor import judge_input as JI
    from developer_agent.runtime_pin import PLATFORM_PYTHON_VERSION_CONTENT
    tree = dict(TESTED, **{".python-version": PLATFORM_PYTHON_VERSION_CONTENT, PYV: PLATFORM_PYTHON_VERSION_CONTENT,
                         ".github/workflows/lint.yml": "on: push\n", "infra/workload/extra_override.tf": "x\n",
                         "apps/api/.python-version": "3.11\n"})
    via_qa = sorted(p for p in tree if QR.finding_owner(p, tree, ()) is Ownership.PLATFORM_RENDERED)
    assert sorted(JI.platform_rendered_paths(tree)) == via_qa
    assert ".python-version" in via_qa and PYV in via_qa                        # the two runtime pins
    assert ".github/workflows/deploy-b.yml" in via_qa and "cloudbuild.yaml" in via_qa
    assert ".github/workflows/lint.yml" not in via_qa                          # RT S1: a person's workflow
    assert "apps/api/.python-version" not in via_qa                            # not the platform's content


@pytest.mark.parametrize("path", [".github/workflows/deploy-b.yml", ".github/workflows/deploy-.yml",
                                  ".github/workflows/lint.yml", ".github/workflows/sub/deploy-b.yml",
                                  ".github/deploy-b.yml", "x/.github/workflows/deploy-b.yml"])
def test_the_deploy_workflow_rule_matches_the_developers_exact_rule(path):
    """Parity with developer_agent.handler.gha_workflow_paths (the paths generate_service_workflow writes)."""
    from developer_agent.handler import gha_workflow_paths
    from qa_auditor import judge_input as JI
    assert JI.is_platform_deploy_workflow(path) is (gha_workflow_paths({path: ""}) == [path])


def test_rt_s1_a_persons_workflow_finding_is_not_a_platform_defect():
    tree = dict(TESTED, **{".github/workflows/lint.yml": "on: push\n"})
    plan = _plan(_jd(".github/workflows/lint.yml"), tree=tree)
    assert (plan.mode, plan.reason) == (QR.REGENERATE, QR.NOT_ON_A_DRAFT_FILE)
    out = QR.unowned_finding_outcome(plan.off_draft_files, tree, tree, {}, base_complete=True)
    assert out["verdict"] == QR.REGENERATE and out["files"][0]["cleanup"] == "NOT_AN_APP_PATH"


def test_the_outlook_ignores_files_every_regeneration_rewrites():
    """Corpus scenario 01 found it: the platform's plan document on main lists the stale test, which kept it
    (NAMED_IN_A_STRING) in the most favourable regeneration. The tested commit's own paths (committed_paths) are
    written again by any regeneration, so their main copies never keep the file."""
    plan_doc = "docs/planning/0001-initial-workload-architecture.md"
    base = dict(BASE, **{plan_doc: "Files: tests/test_iap_auth.py\n"})
    rec = _rec({OLD_TEST: T("old")})
    kept = QR.unowned_finding_outcome([OLD_TEST], base, base, rec, base_complete=True)
    assert kept["verdict"] == QR.STOP and kept["files"][0]["cleanup"] == AP.KEPT_NAMED_IN_STRING
    out = QR.unowned_finding_outcome([OLD_TEST], base, base, rec, base_complete=True, replaced=(plan_doc, MAIN_PY))
    assert out["verdict"] == QR.REGENERATE and out["files"][0]["cleanup"] == AP.REMOVABLE
    neg = QR.unowned_finding_outcome([OLD_TEST], base, base, rec, base_complete=True, replaced=(OLD_TEST,))
    assert neg["files"][0]["cleanup"] == AP.KEPT_NAMED_IN_STRING              # the file itself is never replaced


# ---- RT probe 3 / S4: what tree a SOLO_FAST_PATH change commits
@pytest.mark.parametrize("mode,deleted", [("SOLO_FAST_PATH", []), ("STANDARD_SWARM", ["apps/uploads/tests/test_old_feature.py"])])
def test_a_solo_fast_path_change_never_deletes_an_omitted_earlier_test_a_full_build_does(mode, deleted):
    """INCREMENTAL-CHANGE-NO-ORPHAN-DELETE (owner 11-14; RT S4): a SOLO_FAST_PATH change commits its answer plus the
    platform's files and deletes nothing it did not write itself: the earlier platform test its answer omits survives
    (negative). A full build (here: one full single turn) still removes it (positive, the SAT-49 F4 rule)."""
    import json as _json
    from types import SimpleNamespace
    from developer_agent import handler as h
    from test_typed_iac_ti3_contract import APP, Client, UPLOADS, _agent, _runtime, record_of, topo
    from test_qa_feedback import SCHEMAS, TF_DRAFT
    answer = dict(APP, **TF_DRAFT, **{SCHEMAS: "class Other:\n    pass\n"})
    stale = "apps/uploads/tests/test_old_feature.py"
    store = AP.MemoryAppProvenanceStore()
    store.save("shop", AP.record_for_commit([stale], {stale: T("old")}, "t-old", {}))
    client = Client()
    agent = _agent(dataclasses.replace(_runtime(client, iac_intent_mode="off"), app_provenance_store=store))
    agent.last_tree_status = {"complete": True, "truncated": False, "error": None}

    class models:  # noqa: N801
        @staticmethod
        def generate_content(*a, **k):
            return SimpleNamespace(text=_json.dumps({"files": answer, "summary": "solo"}),
                                   candidates=[SimpleNamespace(finish_reason="STOP")], usage_metadata=None)
    agent.genai_client = SimpleNamespace(models=models)
    plan = MagicMock()
    plan.execution_mode = getattr(h.SwarmExecutionMode, mode)   # STANDARD_SWARM with no tasks: one full single turn
    plan.tasks = []
    with patch.object(h, "LeadDeveloperOrchestrator") as lead, \
            patch.object(h, "get_model_cascade_for_agent", return_value=["gemini-test"]), \
            patch.object(agent, "fetch_existing_repo_files", return_value={stale: T("old")}), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}):
        lead.return_value.decompose_specification.return_value = plan
        files = agent.generate_code_files(product_id="shop", spec_text="uploads service", task_dag=[],
                                          trace_id="t-solo", architect_compute_intent=record_of(topo([UPLOADS])),
                                          allow_unauthenticated=True, enable_direct_iap=False,
                                          domain_restricted_sharing=False)
    assert stale not in files and all(p in files for p in APP)
    run = agent.stack_run("t-solo")
    assert run["app_orphan_deletions"] == deleted
    assert run["app_orphans"]["status"] == (AP.STATUS_SKIPPED_INCREMENTAL if mode == "SOLO_FAST_PATH" else AP.STATUS_CHECKED)


# ---- INCREMENTAL-CHANGE-NO-ORPHAN-DELETE (owner 11-14)
def test_incremental_decision_keeps_every_derived_deletion():
    d = AP.find_orphans(_rec({OLD_TEST: T("old")}), BASE, {MAIN_PY: APP_V2}, tree_complete=True)
    assert d["deleted"] == [OLD_TEST]
    inc = AP.incremental_decision(d)
    assert (inc["status"], inc["deleted"], inc["kept"]) == (AP.STATUS_SKIPPED_INCREMENTAL, [],
                                                            {OLD_TEST: AP.KEPT_RUN_SKIPPED})


@pytest.mark.parametrize("kind,full,deleted", [("FULL", True, [OLD_TEST]), ("QA_REPAIR", False, []),
                                               ("SOLO_FAST_PATH", False, []), ("unset", None, [])])
def test_only_a_full_build_derives_orphan_deletions_at_the_handler(kind, full, deleted):
    """Typed: the run record's app_full_build (set from the repair plan and the lead's execution mode); a dispatch
    that never set it (unknown kind) derives nothing (fail-safe)."""
    from types import SimpleNamespace
    store = AP.MemoryAppProvenanceStore()
    store.save(PID, _rec({OLD_TEST: T("old")}))
    agent = _agent_with(store)
    agent._load_app_provenance(PID, "t-inc", True, True)
    if full is not None:
        agent._record_stack("t-inc", app_full_build=full, app_build_kind=kind)
    agent._decide_app_orphans(SimpleNamespace(trace_id="t-inc", product_id=PID, existing_files=dict(BASE)),
                              {MAIN_PY: APP_V2})
    assert agent.stack_run("t-inc")["app_orphan_deletions"] == deleted

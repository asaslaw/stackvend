"""
Repo-root pytest guards. Loaded for every pytest run under the repo (tests/, apps/*/test_*.py, mcp-servers/*),
whatever the arguments.

1. Hermetic guard (Wave 1 lane 2, tests/hermetic_guard.py): no credentials, no network, no cloud clients, no
   network-capable child processes. Installed FIRST, before anything else is imported. Recorded violations fail the
   test that caused them (setup/call/teardown or collection), even when the code under test swallowed the error,
   unless the exact nodeid is listed in tests/hermetic_known_leaks.py (then: warning only; the call is still
   blocked). ``@pytest.mark.live`` tests are skipped unless ``--run-live``; even then the guard stays on unless
   STACKVEND_ALLOW_NETWORK=1.

2. FD-08: no test may construct a real google.cloud.firestore Client.
   Incident FD-08: apps/control-center/test_portal.py resolved ADC and wrote to LIVE Firestore.
   - A meta-path hook patches google.cloud.firestore_v1.base_client.BaseClient.__init__ the moment the REAL module
     is imported (or immediately, if something already imported it). Sync and async clients both inherit it.
   - Everywhere: the patched __init__ records the attempt and raises RealFirestoreClientBlocked, so a real client
     never exists under pytest (app code that does `except Exception: db = None` degrades to its no-db path).
   - Strict (fail fast) for test files under apps/ (STRICT_DIRS, minus GRANDFATHERED).
   - tests/: existing suites import app modules (orchestrator-gateway main.py, control-center config.py) that try to
     build a client at import; there the attempt is blocked and counted against a per-file ratchet
     (FIRESTORE_ALLOWANCE in tests/hermetic_known_leaks.py): exceeding it fails the session.
   Tests that need Firestore must inject a fake (see tests/cc_identity_harness.py) or mock.patch the client class.
   The only escape hatch is the local emulator: FIRESTORE_EMULATOR_HOST pointing at localhost/127.0.0.1/[::1].
"""
import importlib.abc
import importlib.machinery
import importlib.util
import os
import sys
import traceback
from datetime import date

_ROOT = os.path.dirname(os.path.abspath(__file__))


def _load_by_path(name, rel):
    if name in sys.modules and getattr(sys.modules[name], "__file__", None):
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# Installed at import of this conftest: before pytest imports any test module or tests/conftest.py.
hermetic_guard = _load_by_path("hermetic_guard", os.path.join("tests", "hermetic_guard.py"))
hermetic_known_leaks = _load_by_path("hermetic_known_leaks", os.path.join("tests", "hermetic_known_leaks.py"))
# Guarded Python children (tests/hermetic_child/sitecustomize.py) forward their violations here; each report hook
# below ingests them into the test or module that was running.
hermetic_guard.start_child_log()

import pytest  # noqa: E402

_TARGET = "google.cloud.firestore_v1.base_client"
STRICT_DIRS = ("apps",)
# Existing apps/ test files whose code under test builds a real client (2026-10-12, FD-08). The client is
# still blocked for them; they are only exempt from the fail-fast report. Make each hermetic, then delete its line.
GRANDFATHERED = frozenset({
    "apps/finops-enforcer/test_enforcer.py",
    "apps/infra-rollback/test_rollback.py",
    "apps/log-sre-sentinel/test_sentinel.py",
    "apps/orchestrator-gateway/test_compliance_agent.py",
    "apps/orchestrator-gateway/test_main.py",
    "apps/project-vending/test_vending.py",
    "apps/refactor-scanner/test_scanner.py",
    "apps/sandbox-cleaner/test_cleaner.py",
    "apps/sre-digest/test_digest.py",
})
ATTEMPTS = []


def _rel(path):
    try:
        rel = os.path.relpath(str(path), _ROOT)
    except ValueError:
        return ""
    return rel.replace(os.sep, "/")


def _strict(path):
    rel = _rel(path)
    return rel.split("/", 1)[0] in STRICT_DIRS and rel not in GRANDFATHERED


class RealFirestoreClientBlocked(RuntimeError):
    pass


def _emulator_ok():
    host = (os.environ.get("FIRESTORE_EMULATOR_HOST") or "").strip()
    return host.rsplit(":", 1)[0].strip("[]") in ("localhost", "127.0.0.1", "::1")


def _patch(module):
    cls = getattr(module, "BaseClient", None)
    if cls is None or getattr(cls.__init__, "_fd08_guard", False):
        return
    real_init = cls.__init__

    def guarded_init(self, *args, **kwargs):
        if _emulator_ok():
            return real_init(self, *args, **kwargs)
        where = "".join(traceback.format_stack(limit=12)[:-1])
        ATTEMPTS.append(where)
        hermetic_guard.record("firestore", "google.cloud.firestore Client", stack=False)
        raise RealFirestoreClientBlocked(
            "FD-08 guard: blocked construction of a real google.cloud.firestore Client under pytest. Inject a fake db "
            "or mock.patch the client (see tests/cc_identity_harness.py).")

    guarded_init._fd08_guard = True
    cls.__init__ = guarded_init


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name != _TARGET:
            return None
        spec = importlib.machinery.PathFinder.find_spec(name, path, target)
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return spec
        real_loader = spec.loader

        class _Loader(importlib.abc.Loader):
            def create_module(self, s):
                return real_loader.create_module(s)

            def exec_module(self, module):
                real_loader.exec_module(module)
                _patch(module)

        spec.loader = _Loader()
        return spec


if _TARGET in sys.modules:
    _patch(sys.modules[_TARGET])
else:
    sys.meta_path.insert(0, _Finder())


def _report(since):
    return ("FD-08 guard: real google.cloud.firestore Client construction attempted "
            f"({len(ATTEMPTS) - since}x; the error may have been swallowed by the code under test). "
            "First attempt:\n" + ATTEMPTS[since])


# ------------------------------------------------------------------------------------------- hermetic reporting
_SEEN_LEAKS = set()  # KNOWN_LEAKS nodeids that leaked this session
_RAN = set()  # nodeids (tests and modules) run/collected this session
_SESSION_PROBLEMS = []
_HERMETIC_IDX = pytest.StashKey()


def _violation_text(recs):
    lines = [f"Hermetic guard: {len(recs)} blocked attempt(s) to reach the network / credentials / cloud clients "
             "(blocked; the code under test may have swallowed the error). Mock the dependency instead."]
    for r in recs[:5]:
        lines.append(f"- [{r['kind']}] {r['detail']}")
        if r["stack"]:
            lines.append("  " + r["stack"].rstrip().replace("\n", "\n  "))
    if len(recs) > 5:
        lines.append(f"... and {len(recs) - 5} more")
    return "\n".join(lines)


def _known(nodeid):
    return nodeid in hermetic_known_leaks.KNOWN_LEAKS


def pytest_addoption(parser):
    group = parser.getgroup("hermetic", "hermetic test guard")
    group.addoption("--run-live", action="store_true", default=False,
                    help="run @pytest.mark.live tests (the guard stays on unless STACKVEND_ALLOW_NETWORK=1)")
    group.addoption("--render-to", default=None,
                    help="tests/test_ci_render_golden.py: write the rendered golden workload to this directory")


def pytest_configure(config):
    config.addinivalue_line("markers", "live: needs real network/credentials; skipped unless --run-live")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-live"):
        return
    skip = pytest.mark.skip(reason="live test: needs --run-live (and STACKVEND_ALLOW_NETWORK=1 for network)")
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(skip)


@pytest.hookimpl(wrapper=True)
def pytest_make_collect_report(collector):
    st = hermetic_guard.state()
    is_module = isinstance(collector, pytest.Module)
    prev, start = st.current, len(st.records)
    if is_module:
        st.current = collector.nodeid
        _RAN.add(collector.nodeid)
    since = len(ATTEMPTS)
    try:
        rep = yield
    finally:
        if is_module:
            hermetic_guard.ingest_child_records()
            st.current = prev
    if len(ATTEMPTS) > since and rep.outcome != "failed" and _strict(getattr(collector, "path", "")):
        rep.outcome = "failed"
        rep.longrepr = _report(since)
    if is_module:
        recs = hermetic_guard.records_for(collector.nodeid, since=start)
        if recs and _known(collector.nodeid):
            _SEEN_LEAKS.add(collector.nodeid)
        elif recs and rep.outcome != "failed":
            rep.outcome = "failed"
            rep.longrepr = _violation_text(recs)
    return rep


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item, nextitem):
    st = hermetic_guard.state()
    prev_current, prev_enabled = st.current, st.enabled
    st.current = item.nodeid
    _RAN.add(item.nodeid)
    item.stash[_HERMETIC_IDX] = len(st.records)
    if (item.get_closest_marker("live") and item.config.getoption("--run-live")
            and os.environ.get("STACKVEND_ALLOW_NETWORK") == "1"):
        st.enabled = False
    try:
        return (yield)
    finally:
        st.current, st.enabled = prev_current, prev_enabled


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    rep = yield
    st = hermetic_guard.state()
    hermetic_guard.ingest_child_records()  # st.current is item.nodeid here (pytest_runtest_protocol)
    idx = item.stash.get(_HERMETIC_IDX, len(st.records))
    recs = hermetic_guard.records_for(item.nodeid, since=idx)
    item.stash[_HERMETIC_IDX] = len(st.records)
    if not recs:
        return rep
    if _known(item.nodeid):
        _SEEN_LEAKS.add(item.nodeid)
        return rep
    if rep.outcome != "failed":
        if hasattr(rep, "wasxfail"):
            del rep.wasxfail
        rep.outcome = "failed"
        rep.longrepr = _violation_text(recs)
    else:
        rep.sections.append(("hermetic guard", _violation_text(recs)))
    return rep


@pytest.fixture(autouse=True)
def _fd08_no_real_firestore(request):
    since = len(ATTEMPTS)
    yield
    if len(ATTEMPTS) > since and _strict(request.node.path):
        pytest.fail(_report(since), pytrace=False)


def _file_of(nodeid):
    return nodeid.split("::", 1)[0]


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    st = hermetic_guard.state()
    hermetic_guard.ingest_child_records()  # late reports from children that outlived their test -> "<session>"
    today = date.today().isoformat()
    # 1. violations outside any test or module collection (e.g. at conftest import)
    stray = [r for r in st.records if r["kind"] in hermetic_guard.FAIL_KINDS and r["nodeid"] == "<session>"]
    if stray:
        _SESSION_PROBLEMS.append(_violation_text(stray))
    # 2. KNOWN_LEAKS hygiene: expired entries; entries that ran this session but no longer leak (stale)
    for nodeid, meta in hermetic_known_leaks.KNOWN_LEAKS.items():
        if meta.get("expires", "0000") < today:
            _SESSION_PROBLEMS.append(f"KNOWN_LEAKS entry expired on {meta.get('expires')}: {nodeid} "
                                     f"({meta.get('fd')}, lane {meta.get('lane')})")
        elif nodeid in _RAN and nodeid not in _SEEN_LEAKS and session.testsfailed == 0:
            _SESSION_PROBLEMS.append(f"KNOWN_LEAKS entry is stale (ran without leaking): delete {nodeid} "
                                     "from tests/hermetic_known_leaks.py")
    # 3. Firestore ratchet (tests/ only; apps/ is strict per FD-08)
    counts = {}
    for r in st.records:
        if r["kind"] == "firestore":
            f = _file_of(r["nodeid"])
            if f.startswith("tests/"):
                counts[f] = counts.get(f, 0) + 1
    allowance = hermetic_known_leaks.FIRESTORE_ALLOWANCE
    for f, n in sorted(counts.items()):
        if n > allowance.get(f, 0):
            _SESSION_PROBLEMS.append(f"Firestore ratchet: {f} attempted {n} real Firestore client(s), allowance "
                                     f"{allowance.get(f, 0)} (tests/hermetic_known_leaks.py FIRESTORE_ALLOWANCE). "
                                     "Inject a fake db instead.")
    session.config.stash[_STATS_KEY] = {
        "firestore": sum(counts.values()), "firestore_by_file": counts,
        "known_leaks_seen": sorted(_SEEN_LEAKS),
        "adc_blocked": sum(1 for r in st.records if r["kind"] == "adc"),
    }
    if _SESSION_PROBLEMS and session.exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


_STATS_KEY = pytest.StashKey()


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    stats = config.stash.get(_STATS_KEY, None)
    if stats is None:
        return
    tr = terminalreporter
    if _SESSION_PROBLEMS or stats["known_leaks_seen"]:
        tr.section("hermetic guard")
        for p in _SESSION_PROBLEMS:
            tr.write_line("ERROR: " + p)
        for n in stats["known_leaks_seen"]:
            meta = hermetic_known_leaks.KNOWN_LEAKS[n]
            tr.write_line(f"known leak (blocked, not failed; {meta['fd']}, lane {meta['lane']}, "
                          f"expires {meta['expires']}): {n}")
    line = (f"hermetic guard: {len(stats['known_leaks_seen'])} known leak(s), {stats['firestore']} blocked "
            f"Firestore client(s), {stats['adc_blocked']} blocked ADC lookup(s), {len(_SESSION_PROBLEMS)} problem(s)")
    tr.write_line(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a") as fh:
                fh.write(f"- {line}\n")
        except OSError:
            pass

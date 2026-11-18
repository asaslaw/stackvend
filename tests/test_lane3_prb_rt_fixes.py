"""Lane 3 PR-B, security red-team fixes (docs/planning/lane3-prb-sandbox-job-code-red-team-fable.md, F1-F11).

Each adversarial case is the review's PoC, run only inside this hermetic harness against the loopback FakeCloud and
local index (qa_sandbox_support). Every PoC test failed on the branch before the fix (`2278ba5`) and passes after it;
each fix also has a negative (Do No Harm) test: valid workloads keep passing, unchanged.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
import qa_job_client as gw
from gate_errors import ErrorClass
from qa_source import deterministic_tar_gz

sj = sup.load_sandbox_job("sandbox_job_rt_fixes")

NONCE = "0123456789abcdef0123456789abcdef"

MAIN = "def health():\n    return {'status': 'healthy'}\n"
PASSING_TEST = "from main import health\n\ndef test_health():\n    assert health() == {'status': 'healthy'}\n"
FAILING_TEST = "def test_bad():\n    assert 1 + 1 == 3\n"
REWRITER = (
    "import pytest\n\n"
    "@pytest.hookimpl(hookwrapper=True)\n"
    "def pytest_runtest_makereport(item, call):\n"
    "    outcome = yield\n"
    "    rep = outcome.get_result()\n"
    "    rep.outcome = 'passed'\n"
)


def app(**extra):
    files = {"apps/svc/main.py": MAIN, "apps/svc/requirements.txt": "", "tests/test_main.py": PASSING_TEST}
    files.update(extra)
    return {k: v for k, v in files.items() if v is not None}


@pytest.fixture(scope="module")
def wheelhouse(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("wheelhouse-rt"))
    return d, sup.build_wheelhouse(d)


@pytest.fixture()
def cloud(wheelhouse):
    c = sup.FakeCloud(wheelhouse[0], dict(wheelhouse[1]))  # own copy: tests add plugin wheels to it
    yield c
    c.close()


@pytest.fixture()
def toolchain(cloud, tmp_path):
    return sup.make_toolchain(sj, cloud, str(tmp_path))


def run(cloud, toolchain, files, transport=None, **env_over):
    archive = deterministic_tar_gz({k: (v.encode() if isinstance(v, str) else v) for k, v in files.items()})
    cloud.source = archive
    env = {
        "QA_SOURCE_URL": cloud.url("source.tar.gz"), "QA_SOURCE_SHA256": hashlib.sha256(archive).hexdigest(),
        "QA_STATIC_PUT_URL": cloud.url("static.json"), "QA_REPORT_PUT_URL": cloud.url("report.json"),
        "QA_NONCE": NONCE, "QA_TRACE_ID": "trace-rt-1", "QA_COMMIT_SHA": "c" * 40, "QA_PRODUCT_ID": "demo-app",
        "QA_DEADLINE_SECONDS": "300",
    }
    env.update(env_over)
    return sj.run_job(env, toolchain=toolchain, transport=transport or sj.HttpTransport(sleep=lambda s: None))


def artifacts(cloud):
    s, r = cloud.objects.get("static.json"), cloud.objects.get("report.json")
    return (json.loads(s) if s else None), (json.loads(r) if r else None)


def verdict(cloud, code):
    if code == 0:
        execution, tasks = {"completionTime": "t", "succeededCount": 1}, [{"lastAttemptResult": {}}]
    else:
        execution, tasks = {"completionTime": "t", "failedCount": 1}, [{"lastAttemptResult": {"exitCode": code}}]
    return gw.classify(execution, tasks, cloud.objects.get("static.json"), cloud.objects.get("report.json"), NONCE)


def codes(diags):
    return [d["code"] for d in diags or []]


# ==================================================================================================================
# F1: requirements.txt lines are PEP 508 names (static phase), passed to pip as argv; no build backend runs
# ==================================================================================================================
def evil_backend_tree(marker, req_line, **extra):
    backend = (
        "import os\n"
        f"MARKER = {str(marker)!r}\n"
        "def _hit(*a, **k):\n"
        "    open(MARKER, 'w').write(os.environ.get('PATH', ''))\n"
        "    raise RuntimeError('build backend executed')\n"
        "get_requires_for_build_wheel = get_requires_for_build_editable = get_requires_for_build_sdist = _hit\n"
        "prepare_metadata_for_build_wheel = prepare_metadata_for_build_editable = _hit\n"
        "build_wheel = build_editable = build_sdist = _hit\n"
    )
    return app(**{
        "apps/svc/requirements.txt": req_line,
        "apps/svc/evil/pyproject.toml": "[build-system]\nrequires = []\nbuild-backend = 'evil_backend'\n"
                                        "backend-path = ['.']\n",
        "apps/svc/evil/evil_backend.py": backend,
        "apps/svc/other.txt": "./evil\n",
        **extra,
    })


@pytest.mark.parametrize("req_line", [
    "./evil\n",                                   # PoC 1a: path requirement
    "-e ./evil\n",                                # PoC 1b: editable
    "--no-binary :all:\n./evil\n",                # PoC 1c: pip option overriding --only-binary
    "-r other.txt\n",                             # nested requirements file
    "fastapi==0.110.0 --hash=sha256:abc\n",       # per-requirement pip option
    "evil @ http://127.0.0.1:9/evil-0.1.tar.gz\n",  # direct URL (loopback, refused, never fetched after the fix)
    "--index-url http://127.0.0.1:9/simple\nfastapi\n",  # foreign index
])
def test_f1_non_name_requirement_lines_fail_the_static_phase_and_run_nothing(cloud, toolchain, tmp_path, req_line):
    marker = tmp_path / "build_code_ran"
    code = run(cloud, toolchain, evil_backend_tree(marker, req_line))
    static, report = artifacts(cloud)
    assert code == 10, (static, report)
    assert static["passed"] is False and report is None  # static phase: no venv, no pip, nothing executed
    found = [d for d in static["diagnostics"] if d["code"] == "POLICY.REQUIREMENTS_LINE"]
    assert found and found[0]["file"] == "apps/svc/requirements.txt" and found[0]["line"] >= 1
    assert not marker.exists()
    assert not any(r.startswith("GET /simple/") and r != "GET /simple/pip/" for r in cloud.requests)
    assert verdict(cloud, code).error_class == ErrorClass.CODE_DEFECT  # POLICY.*, never the REQ.* index rule


def test_f1_bare_archive_name_never_resolves_to_a_file_in_the_tree(cloud, toolchain, tmp_path):
    """A valid PEP 508 name that looks like an archive (`evil.zip`) must not make pip install a local file: pip runs
    in an empty fresh directory, so the name is only ever looked up on the index (-> REQ.UNRESOLVABLE)."""
    marker = tmp_path / "build_code_ran"
    import io
    import zipfile

    buf = io.BytesIO()
    tree = evil_backend_tree(marker, "")
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("evil/pyproject.toml", tree["apps/svc/evil/pyproject.toml"])
        zf.writestr("evil/evil_backend.py", tree["apps/svc/evil/evil_backend.py"])
    files = app(**{"apps/svc/requirements.txt": "evil.zip\n", "apps/svc/evil.zip": buf.getvalue()})
    code = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert static["passed"] is True and code == 10, (static, report)
    assert codes(report["diagnostics"]) == ["REQ.UNRESOLVABLE"]
    assert not marker.exists()


def test_f1_negative_name_requirements_are_accepted_unchanged(tmp_path):
    text = (
        "﻿# platform deps\n"
        "fastapi>=0.110.0\n"
        "uvicorn[standard]>=0.28.0   # server\n"
        "\n"
        "pytest==7.0.0; python_version > \"3\"\n"
        "zope.interface\n"
    )
    (tmp_path / "apps" / "svc").mkdir(parents=True)
    (tmp_path / "apps" / "svc" / "requirements.txt").write_text(text, encoding="utf-8")
    svc = sj.Service("svc", "apps/svc", ["tests"])
    assert sj.check_requirements(str(tmp_path), [svc]) == []
    assert svc.requirements == ["fastapi>=0.110.0", "uvicorn[standard]>=0.28.0", 'pytest==7.0.0; python_version > "3"',
                                "zope.interface"]


def test_f1_valid_requirement_is_installed_from_argv(cloud, toolchain, wheelhouse):
    """End to end: a name requirement + inline comment installs (pip got it as argv) and the run passes."""
    fn = sup.build_plugin_wheel(wheelhouse[0], "tinylib", "1.0", "tinylib", "VALUE = 42\n")
    cloud.wheel_index["tinylib"] = [fn]
    files = app(**{"apps/svc/requirements.txt": "tinylib==1.0  # pinned\n",
                   "tests/test_main.py": "import tinylib\n\ndef test_v():\n    assert tinylib.VALUE == 42\n"})
    code = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 0, (static, report)
    assert "GET /simple/tinylib/" in cloud.requests


def test_f1_job_declares_packaging():
    with open(os.path.join(sup.QA_DIR, "requirements.txt")) as f:
        names = {ln.split(">=")[0].split("==")[0].strip().lower() for ln in f if ln.strip() and not ln.startswith("#")}
    assert {"packaging", "bandit"} <= names


# ==================================================================================================================
# F2: H4 lint resolves pytest_plugins tree-wide, follows star imports, flags pluginmanager; autoload off + allow-list
# ==================================================================================================================
def test_f2_pytest_plugins_in_a_nested_test_package_is_scanned(cloud, toolchain):  # PoC 2
    files = app(**{
        "tests/test_main.py": None,
        "tests/sub/__init__.py": "",
        "tests/sub/test_x.py": "pytest_plugins = ['plug']\n\n" + FAILING_TEST,
        "tests/plug.py": REWRITER,
    })
    code = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 10 and report is None, (static, report)
    assert [d["file"] for d in static["diagnostics"] if d["code"] == "PYTEST.OUTCOME_HOOK"] == ["tests/plug.py"]


@pytest.mark.parametrize("conftest", ["from helpers import *\n", "from .helpers import *\n"])
def test_f2_star_import_into_conftest_is_scanned(cloud, toolchain, conftest):  # PoC 3a
    files = app(**{"tests/__init__.py": "" if conftest.startswith("from .") else None,
                   "tests/conftest.py": conftest, "tests/helpers.py": REWRITER, "tests/test_main.py": FAILING_TEST})
    code = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 10 and report is None, (static, report)
    assert "tests/helpers.py" in [d["file"] for d in static["diagnostics"] if d["code"] == "PYTEST.OUTCOME_HOOK"]


def test_f2_pluginmanager_register_inside_an_allowed_hook_is_flagged(cloud, toolchain):  # PoC 3b
    helpers = (
        "import pytest\n\nclass Rewriter:\n    @pytest.hookimpl(hookwrapper=True)\n"
        "    def pytest_runtest_makereport(self, item, call):\n        outcome = yield\n"
        "        outcome.get_result().outcome = 'passed'\n"
    )
    files = app(**{
        "tests/conftest.py": "from helpers import Rewriter\n\ndef pytest_configure(config):\n"
                             "    config.pluginmanager.register(Rewriter())\n",
        "tests/helpers.py": helpers,
        "tests/test_main.py": FAILING_TEST,
    })
    code = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 10 and report is None, (static, report)
    hits = [d for d in static["diagnostics"] if d["code"] == "PYTEST.OUTCOME_HOOK"]
    assert ("tests/conftest.py", 4) in [(d["file"], d["line"]) for d in hits]


def _hooks(files):
    return sj.check_pytest_hooks({k: ast.parse(v) for k, v in files.items()}, [])


def test_f2_negative_ordinary_workload_code_is_not_flagged():
    files = {
        "tests/conftest.py": "import pytest\nfrom helpers import *\nfrom main import app\n\n"
                             "def pytest_configure(config):\n    config.addinivalue_line('markers', 'slow')\n",
        "tests/helpers.py": "import pytest\n\n@pytest.fixture\ndef client():\n    return 1\n",
        "apps/svc/main.py": "app = object()\n",
        "tests/test_x.py": "def test_opt(request):\n    assert request.config.getoption('-q') is not None\n",
        "tests/sub/test_y.py": "pytest_plugins = ['pytest_asyncio']\n",  # third party: not in the tree
    }
    assert _hooks(files) == []


@pytest.mark.parametrize("src", [
    "def test_x(request):\n    request.config.pluginmanager.import_plugin('evil')\n",
    "def test_x(pytestconfig):\n    pm = getattr(pytestconfig, 'pluginmanager')\n",
])
def test_f2_pluginmanager_anywhere_in_the_tree_is_flagged(src):
    assert codes(_hooks({"tests/test_x.py": src})) == ["PYTEST.OUTCOME_HOOK"]


def test_f2_untrusted_env_disables_plugin_autoload_and_caps_malloc_arenas(tmp_path):
    class W:
        home, tmp = str(tmp_path / "h"), str(tmp_path / "t")

    env = sj._untrusted_env(W, "/v/bin", "/s")
    assert env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert env["MALLOC_ARENA_MAX"] == "2"  # red-team F11
    assert env["PYTEST_ADDOPTS"] == "-p no:cacheprovider"


def test_f2_plugin_wheel_from_a_dependency_cannot_rewrite_outcomes(cloud, toolchain, wheelhouse):  # PoC 6
    fn = sup.build_plugin_wheel(wheelhouse[0], "evilplug", "0.1", "evilplug", REWRITER,
                                "[pytest11]\nevilplug = evilplug\n")
    cloud.wheel_index["evilplug"] = [fn]
    files = app(**{"apps/svc/requirements.txt": "evilplug==0.1\n", "tests/test_main.py": FAILING_TEST})
    code = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 10, (static, report)
    assert report["passed"] is False and report["tests_failed"] == 1
    assert verdict(cloud, code).error_class == ErrorClass.CODE_DEFECT


def test_f2_negative_allow_listed_plugin_is_loaded_explicitly(cloud, toolchain, wheelhouse):
    fn = sup.build_plugin_wheel(wheelhouse[0], "pytest-mock", "3.14.0", "pytest_mock",
                                "import pytest\n\n@pytest.fixture\ndef mocker():\n    return 'fake-mocker'\n",
                                "[pytest11]\npytest_mock = pytest_mock\n")
    cloud.wheel_index["pytest-mock"] = [fn]
    files = app(**{"apps/svc/requirements.txt": "pytest-mock==3.14.0\n",
                   "tests/test_main.py": "def test_m(mocker):\n    assert mocker == 'fake-mocker'\n"})
    code = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 0, (static, report)
    assert verdict(cloud, code).passed is True


def test_f2_missing_required_platform_plugin_is_runner_error(cloud, toolchain):
    toolchain.required_pytest_plugin_dists = ("pytest-timeout",)  # not installed: no wheel on the local index
    code = run(cloud, toolchain, app())
    static, report = artifacts(cloud)
    assert code == 11 and static["passed"] is True and report is None
    assert verdict(cloud, code).error_class == ErrorClass.GATE_UNAVAILABLE


def test_f2_default_toolchain_requires_pytest_timeout():
    tc = sj.Toolchain()
    assert tuple(tc.required_pytest_plugin_dists) == ("pytest-timeout",) and "--timeout=60" in tc.pytest_extra_args
    assert tc.harden_process is True and tc.sweep_uid_processes is True


# ==================================================================================================================
# F3: every other process of the job's uid is killed after an untrusted step (setsid daemons included)
# ==================================================================================================================
DAEMON = "import os, sys, time\nos.setsid()\nos.write(int(sys.argv[1]), b'r')\ntime.sleep(60)\n"
STEP = (
    "import os, subprocess, sys\n"
    "r, w = os.pipe()\n"
    "p = subprocess.Popen([sys.executable, sys.argv[1], str(w)], pass_fds=(w,))\n"
    "os.close(w)\n"
    "assert os.read(r, 1) == b'r'  # synchronised: the daemon has left the process group before the step exits\n"
    "open(sys.argv[2], 'w').write(str(p.pid))\n"
)


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _run_setsid_step(tmp_path, sweep):
    (tmp_path / "daemon.py").write_text(DAEMON)
    (tmp_path / "step.py").write_text(STEP)
    pidfile = tmp_path / "daemon.pid"
    runner = sj.Runner(deadline=time.monotonic() + 60, redact=sj.Redactor(), sweep=sweep)
    res = runner.run([sys.executable, str(tmp_path / "step.py"), str(tmp_path / "daemon.py"), str(pidfile)],
                     env=hermetic_guard.child_env(), cwd=str(tmp_path), untrusted=True, what="t",
                     log_path=str(tmp_path / "l.log"))
    assert res.returncode == 0, res.output
    return int(pidfile.read_text())


def test_f3_setsid_daemon_escapes_killpg_but_not_the_uid_sweep(tmp_path):
    # Before the fix (killpg only) the daemon is still running after the step: deterministic, it blocks for 60 s.
    pid = _run_setsid_step(tmp_path, sweep=None)
    try:
        assert _alive(pid)
    finally:
        os.kill(pid, signal.SIGKILL)

    # After: the sweep finds it by uid. The listing is scoped to this test's processes (the real /proc listing would
    # include every process of the developer's uid); the kill/loop/keep logic is the production code.
    me, uid, killed = os.getpid(), os.getuid(), []
    holder = {}

    def listing():
        out = [sj.ProcInfo(me, os.getppid(), uid, False), sj.ProcInfo(os.getppid(), 1, uid, False)]
        if "pid" in holder and _alive(holder["pid"]):
            out.append(sj.ProcInfo(holder["pid"], 1, uid, False))
        return out

    def kill(p, sig):
        killed.append(p)
        os.kill(p, sig)

    def sweep():
        holder["pid"] = int((tmp_path / "daemon.pid").read_text())
        sj.kill_stray_processes(list_processes=listing, kill=kill, rounds=2000)

    (tmp_path / "daemon.pid").unlink()
    pid = _run_setsid_step(tmp_path, sweep=sweep)
    assert not _alive(pid)
    assert set(killed) == {pid} and me not in killed and os.getppid() not in killed


def P(pid, ppid, uid=1000, zombie=False):
    return sj.ProcInfo(pid, ppid, uid, zombie)


def test_f3_sweep_keeps_self_ancestors_pid1_other_uids_and_zombies():
    rounds = [
        [P(1, 0), P(10, 1), P(50, 10), P(100, 50), P(200, 1), P(201, 1, uid=0), P(202, 1, zombie=True), P(203, 100)],
        [P(1, 0), P(10, 1), P(50, 10), P(100, 50), P(201, 1, uid=0), P(202, 1, zombie=True), P(203, 100)],
        [P(1, 0), P(10, 1), P(50, 10), P(100, 50), P(201, 1, uid=0), P(202, 1, zombie=True)],
    ]
    calls, killed = [], []

    def listing():
        calls.append(1)
        return rounds[min(len(calls) - 1, len(rounds) - 1)]

    got = sj.kill_stray_processes(list_processes=listing, kill=lambda p, s: killed.append((p, s)), me=100, uid=1000,
                                  sleep=lambda s: None)
    assert got == {200, 203}
    assert all(s == signal.SIGKILL for _, s in killed) and {p for p, _ in killed} == {200, 203}


def test_f3_sweep_fails_closed_when_a_process_survives():
    with pytest.raises(sj.RunnerError):
        sj.kill_stray_processes(list_processes=lambda: [P(100, 1), P(300, 1)], kill=lambda p, s: None, me=100,
                                uid=1000, sleep=lambda s: None, rounds=5)


def test_f3_list_proc_reads_the_documented_status_format(tmp_path):
    for pid, state, ppid, uid in ((7, "S (sleeping)", 1, 1000), (8, "Z (zombie)", 7, 1000)):
        (tmp_path / str(pid)).mkdir()
        (tmp_path / str(pid) / "status").write_text(
            f"Name:\tx\nState:\t{state}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{uid}\t1001\t1001\t1001\n")
    (tmp_path / "self").mkdir()
    (tmp_path / "9").mkdir()  # vanished while listing: skipped
    assert sorted(sj.list_proc(str(tmp_path)), key=lambda p: p.pid) == [P(7, 1), P(8, 7, zombie=True)]
    with pytest.raises(sj.RunnerError):
        sj.list_proc(str(tmp_path / "nope"))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc is Linux-only (production is Linux)")
def test_f3_list_proc_on_the_real_kernel_sees_this_process():
    me = [p for p in sj.list_proc() if p.pid == os.getpid()]
    assert me == [sj.ProcInfo(os.getpid(), os.getppid(), os.getuid(), False)]


def test_f3_runner_sweeps_after_untrusted_steps_only(tmp_path):
    calls = []
    runner = sj.Runner(deadline=time.monotonic() + 60, redact=sj.Redactor(), sweep=lambda: calls.append(1))
    kw = dict(cwd=str(tmp_path), what="t", log_path=str(tmp_path / "l.log"))
    runner.run([sys.executable, "-c", "pass"], env=hermetic_guard.child_env(), untrusted=False, **kw)
    assert calls == []
    runner.run([sys.executable, "-c", "pass"], env=hermetic_guard.child_env(), untrusted=True, **kw)
    assert calls == [1]
    runner = sj.Runner(deadline=time.monotonic() + 1.5, redact=sj.Redactor(), sweep=lambda: calls.append(2))
    with pytest.raises(sj.DeadlineExpired):
        runner.run([sys.executable, "-c", "import time; time.sleep(30)"], env=hermetic_guard.child_env(),
                   untrusted=True, **kw)
    assert calls == [1, 2]  # also on the untrusted deadline


def test_f3_run_job_sweeps_after_each_untrusted_step(cloud, toolchain, monkeypatch):
    calls = []
    monkeypatch.setattr(sj, "sweep_uid_processes", lambda: calls.append(1))  # never the real uid-wide sweep here
    toolchain.sweep_uid_processes = True
    assert run(cloud, toolchain, app()) == 0
    assert len(calls) == 2  # import smoke + pytest


def _unshare_works():
    exe = shutil.which("unshare")
    if not sys.platform.startswith("linux") or not exe:
        return None
    try:
        r = subprocess.run([exe, "-Urpf", "--mount-proc", "true"], capture_output=True, timeout=20,
                           env=hermetic_guard.child_env())
    except (OSError, subprocess.SubprocessError):
        return None
    return exe if r.returncode == 0 else None


@pytest.mark.skipif(_unshare_works() is None, reason="needs Linux with unprivileged user + PID namespaces")
def test_f3_real_uid_sweep_kills_a_setsid_daemon_inside_its_own_pid_namespace(tmp_path):
    """The production sweep end to end on the real kernel, confined to a fresh user+PID namespace (it would
    otherwise SIGKILL every process of this uid on the host)."""
    script = tmp_path / "ns.py"
    script.write_text(
        "import os, sys, time\n"
        f"sys.path[:0] = [{os.path.dirname(os.path.abspath(__file__))!r}, {sup.QA_DIR!r}]\n"
        "import qa_sandbox_support as sup\n"
        "sj = sup.load_sandbox_job('ns')\n"
        f"tmp = {str(tmp_path)!r}\n"
        f"open(os.path.join(tmp, 'daemon.py'), 'w').write({DAEMON!r})\n"
        f"open(os.path.join(tmp, 'step.py'), 'w').write({STEP!r})\n"
        "r = sj.Runner(time.monotonic() + 60, sj.Redactor(), sweep=sj.sweep_uid_processes)\n"
        "res = r.run([sys.executable, os.path.join(tmp, 'step.py'), os.path.join(tmp, 'daemon.py'),\n"
        "             os.path.join(tmp, 'pid')], env=dict(os.environ), cwd=tmp, untrusted=True, what='t',\n"
        "             log_path=os.path.join(tmp, 'l.log'))\n"
        "pid = int(open(os.path.join(tmp, 'pid')).read())\n"
        "alive = any(p.pid == pid and not p.zombie for p in sj.list_proc())\n"
        "print('RC', res.returncode, 'ALIVE', alive)\n"
    )
    r = subprocess.run([_unshare_works(), "-Urpf", "--mount-proc", sys.executable, str(script)], capture_output=True,
                       text=True, timeout=60, env=hermetic_guard.child_env())
    assert "RC 0 ALIVE False" in r.stdout, r.stdout + r.stderr


# ==================================================================================================================
# F4: the job process is non-dumpable from its first statement; uid recorded
# ==================================================================================================================
def test_f4_run_job_hardens_before_anything_and_fails_closed(cloud, toolchain, monkeypatch):
    seen = []
    monkeypatch.setattr(sj, "harden_process", lambda: seen.append(list(cloud.requests)))
    toolchain.harden_process = True
    assert run(cloud, toolchain, app()) == 0
    assert seen == [[]]  # once, before any request

    def refuse():
        raise sj.RunnerError("prctl refused")

    cloud.objects.clear()
    cloud.requests.clear()
    monkeypatch.setattr(sj, "harden_process", refuse)
    assert run(cloud, toolchain, app()) == 11
    assert cloud.requests == [] and cloud.objects == {}


def test_f4_uid_is_recorded_in_the_toolchain(cloud, toolchain):
    assert run(cloud, toolchain, app()) == 0
    static, _ = artifacts(cloud)
    assert static["toolchain"]["uid"] == str(os.getuid())


def test_f4_harden_process_is_a_no_op_off_linux_and_sets_non_dumpable_on_linux(tmp_path):
    code = (
        "import sys, ctypes\n"
        f"sys.path[:0] = [{os.path.dirname(os.path.abspath(__file__))!r}, {sup.QA_DIR!r}]\n"
        "import qa_sandbox_support as sup\n"
        "sj = sup.load_sandbox_job('h')\n"
        "sj.harden_process()\n"
        "if sys.platform.startswith('linux'):\n"
        "    print('DUMPABLE', ctypes.CDLL(None).prctl(sj.PR_GET_DUMPABLE, 0, 0, 0, 0))\n"
        "    print('STATUS', open('/proc/self/status').read().startswith('Name:'))\n"
        "else:\n"
        "    print('NOOP')\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60,
                       env=hermetic_guard.child_env(extra={"TMPDIR": str(tmp_path)}), cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr
    if sys.platform.startswith("linux"):
        assert "DUMPABLE 0" in r.stdout and "STATUS True" in r.stdout
    else:
        assert "NOOP" in r.stdout


# ==================================================================================================================
# F5: a service's files are re-verified before its dynamic phase
# ==================================================================================================================
def two_services(api_test):
    return {
        "apps/a/main.py": MAIN, "apps/a/requirements.txt": "", "apps/a/tests/test_a.py": api_test,
        "apps/b/main.py": MAIN, "apps/b/requirements.txt": "", "apps/b/tests/test_b.py": FAILING_TEST,
    }


def test_f5_earlier_service_rewriting_a_later_services_tests_is_a_defect(cloud, toolchain):  # PoC 7
    rewrite = (
        "import os\n\ndef test_a():\n"
        "    p = os.path.join(os.path.dirname(__file__), '..', '..', 'b', 'tests', 'test_b.py')\n"
        "    open(p, 'w').write('def test_b():\\n    assert True\\n')\n"
    )
    code = run(cloud, toolchain, two_services(rewrite))
    static, report = artifacts(cloud)
    assert code == 10, (static, report)
    hit = [d for d in report["diagnostics"] if d["code"] == "PY.TREE_MODIFIED"]
    assert [d["file"] for d in hit] == ["apps/b/tests/test_b.py"]


def test_f5_added_conftest_is_a_defect(cloud, toolchain):
    plant = (
        "import os\n\ndef test_a():\n"
        "    p = os.path.join(os.path.dirname(__file__), '..', '..', 'b', 'tests', 'conftest.py')\n"
        f"    open(p, 'w').write({REWRITER!r})\n"
    )
    code = run(cloud, toolchain, two_services(plant))
    _, report = artifacts(cloud)
    assert code == 10 and "apps/b/tests/conftest.py" in [d["file"] for d in report["diagnostics"]
                                                         if d["code"] == "PY.TREE_MODIFIED"]


def test_f5_negative_tests_writing_data_files_do_not_trip_the_check(cloud, toolchain):
    files = two_services("def test_a():\n    open('test.db', 'w').write('x')\n")
    files["apps/b/tests/test_b.py"] = PASSING_TEST
    code = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 0 and report["tests_total"] == 2, (static, report)


# ==================================================================================================================
# F7: the gateway never classifies a pass without at least one test and zero failures
# ==================================================================================================================
def _art(passed=True, **extra):
    return json.dumps({"schema_version": 1, "nonce": NONCE, "passed": passed, **extra}).encode()


@pytest.mark.parametrize("report,ok", [
    (_art(tests_total=0, tests_failed=0), False),
    (_art(), False),  # tests_total defaults to 0
    (_art(tests_total=2, tests_failed=1), False),
    (_art(tests_total=1, tests_failed=0), True),
], ids=["zero_tests", "no_counts", "a_failure", "one_passing_test"])
def test_f7_gateway_pass_needs_tests_and_no_failures(report, ok):
    out = gw.classify({"completionTime": "t", "succeededCount": 1}, [{"lastAttemptResult": {}}],
                      _art(index_reachable=True), report, NONCE)
    assert out.passed is ok
    if not ok:
        assert out.error_class == ErrorClass.GATE_UNAVAILABLE and out.reason == "VERDICT_MISMATCH"


def test_m9_job_never_passes_when_no_test_ran(cloud, toolchain, monkeypatch):
    monkeypatch.setattr(sj, "run_service", lambda *a, **k: None)  # every service ran nothing, reported nothing
    code = run(cloud, toolchain, app())
    _, report = artifacts(cloud)
    assert code == 10 and report["passed"] is False and "PY.NO_TESTS" in codes(report["diagnostics"])


# ==================================================================================================================
# F9: HTTP attempts are bounded by the task budget
# ==================================================================================================================
def test_f9_task_timeout_matches_the_gateway_and_leaves_room_after_the_deadline():
    assert sj.TASK_TIMEOUT_S == gw.JOB_TASK_TIMEOUT_S
    assert sj.MAX_DEADLINE_S + sj.TASK_BUDGET_MARGIN_S < sj.TASK_TIMEOUT_S


def test_f9_no_attempt_after_the_task_budget(cloud):
    t = {"now": 100.0}
    net = sj.HttpTransport(sleep=lambda s: None, clock=lambda: t["now"])
    with pytest.raises(sj.RunnerError):
        net.put_create_only(cloud.url("report.json"), b"{}", "report.json", deadline=99.0)
    assert cloud.requests == []


def test_f9_attempt_timeouts_and_backoff_are_bounded_by_what_is_left():
    t = {"now": 0.0}
    timeouts, sleeps = [], []

    class Flaky(sj.HttpTransport):
        def _attempt(self, req, timeout, max_bytes):
            timeouts.append(timeout)
            t["now"] += 1.0
            raise OSError("reset")

    net = Flaky(sleep=lambda s: (sleeps.append(s), t.__setitem__("now", t["now"] + s)), clock=lambda: t["now"])
    with pytest.raises(sj.RunnerError):
        net.request("PUT", "http://127.0.0.1:9/x", data=b"{}", deadline=5.0)
    assert timeouts[0] == 5.0 and all(x <= 5.0 for x in timeouts)
    assert sum(timeouts) / len(timeouts) < sj.HTTP_TIMEOUT_S and all(s <= 5.0 for s in sleeps)


def test_f9_run_job_bounds_every_put_by_the_task_timeout(cloud, toolchain):
    seen = []

    class Recording(sj.HttpTransport):
        def put_create_only(self, url, data, what, deadline=None):
            seen.append((what, deadline))
            return super().put_create_only(url, data, what, deadline=deadline)

    before = time.monotonic()
    assert run(cloud, toolchain, app(), transport=Recording(sleep=lambda s: None)) == 0
    assert [w for w, _ in seen] == ["static.json", "report.json"]
    assert all(d is not None and d <= time.monotonic() + sj.TASK_TIMEOUT_S and d >= before for _, d in seen)


# ==================================================================================================================
# M15 / M16: the report is redacted end to end; "exit 0 but junit lists failures" is reported
# ==================================================================================================================
def test_m15_signed_url_echoed_by_a_test_never_reaches_report_json(cloud, toolchain):
    url = cloud.url("report.json")
    files = app(**{"tests/test_main.py": f"def test_leak():\n    assert False, {url!r}\n"})
    code = run(cloud, toolchain, files)
    raw = cloud.objects["report.json"].decode()
    assert code == 10 and url not in raw and "[REDACTED]" in raw


def test_m16_pytest_exit_0_with_failures_in_junit_is_reported(cloud, toolchain):
    forge = (
        "import os\n\ndef test_forge(request):\n"
        "    open(request.config.option.xmlpath, 'w').write(\n"
        "        '<testsuites><testsuite><testcase classname=\"t\" name=\"x\">'\n"
        "        '<failure message=\"boom\">boom</failure></testcase></testsuite></testsuites>')\n"
        "    os._exit(0)\n"
    )
    code = run(cloud, toolchain, app(**{"tests/test_main.py": forge}))
    _, report = artifacts(cloud)
    assert code == 10 and "PYTEST.REPORT_INVALID" in codes(report["diagnostics"])

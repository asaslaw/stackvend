"""procfile-worker-build (RT F3 of FD-4AE-c): QA's import smoke covers a Procfile-only service.

`run_service` ran `import main` only when `apps/<svc>/main.py` existed, so a worker like Gate A 05-r2's
`apps/fleet-gke/` (`worker: python consumer.py`, no main.py) got no import check. Now such a service gets the same
blocking smoke on the module(s) its Procfile starts (`procfile_entry_modules`, exact parse; Procfile lines and
server option tables pinned to the pre-commit V3c contract below, launcher reading agrees with V3c `parse_command` on
the shapes both read). main.py services are unchanged."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

import pytest

import qa_sandbox_support as sup
from test_qa_sandbox_job import artifacts, cloud, codes, run, toolchain, wheelhouse  # noqa: F401  (fixtures)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY not in sys.path:
    sys.path.insert(0, GATEWAY)

from developer_agent.validators import container as v3c  # noqa: E402

sj = sup.load_sandbox_job("sandbox_job_procfile_worker")


# ------------------------------------------------------------------------------------------------ the parser
@pytest.mark.parametrize("command,module", [
    ("python consumer.py", "consumer"),
    ("python3 -u worker.py", "worker"),
    ("python -W ignore worker.py", "worker"),
    ("/usr/bin/python3 consumer.py --verbose", "consumer"),
    ("python -m worker", "worker"),
    ("python -m pkg.worker --once", "pkg.worker"),
    ("python -m uvicorn app:app --host 0.0.0.0 --port $PORT", "app"),
    ("uvicorn --host 0.0.0.0 --port ${PORT:-8080} api.main:app", "api.main"),
    ("gunicorn -b :$PORT -w 2 -k uvicorn.workers.UvicornWorker wsgi:application", "wsgi"),
    ("gunicorn 'factory:create_app()'", "factory"),
    ("hypercorn --bind 0.0.0.0:$PORT svc:app", "svc"),
])
def test_entry_module_of_known_launchers(command, module):
    assert sj.procfile_entry_module(command) == module


@pytest.mark.parametrize("command", [
    "python src/worker.py",              # a script in a subdirectory: its sys.path root differs, not judged
    "python -c 'import worker'",
    "python",
    "python -m",
    "alembic upgrade head",
    "bash start.sh",
    "celery -A tasks worker",
    "uvicorn --app-dir src main:app",
    "gunicorn --chdir src app:app",
    "gunicorn --pythonpath=src app:app",
    "uvicorn --port $PORT",
    "python my-worker.py",
    "python 'unbalanced",
    "",
])
def test_unreadable_commands_are_not_judged(command):
    assert sj.procfile_entry_module(command) is None


def test_entry_modules_dedupe_in_procfile_order(tmp_path):
    (tmp_path / "consumer.py").write_text("X = 1\n")
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "__init__.py").write_text("")
    (tmp_path / "Procfile").write_text("release: alembic upgrade head\nworker: python consumer.py\n"
                                       "beat: python -m consumer\nweb: uvicorn api:app --port $PORT\n")
    assert sj.procfile_entry_modules(str(tmp_path)) == ["consumer", "api"]


def test_only_modules_the_service_ships_are_smoked(tmp_path):
    """Gate B S3-r1/r3 shape: a gce-bastion dir with a stale `web: uvicorn main:app` Procfile and no main.py gets no
    smoke (today: none either). A Procfile naming a missing module is not caught here (follow-up PWB-3)."""
    (tmp_path / "export_maintenance.py").write_text("X = 1\n")
    (tmp_path / "Procfile").write_text("web: uvicorn main:app --host 0.0.0.0 --port $PORT\n")
    assert sj.procfile_entry_modules(str(tmp_path)) == []
    (tmp_path / "pkg" / "sub").mkdir(parents=True)
    (tmp_path / "pkg" / "sub" / "run.py").write_text("X = 1\n")
    (tmp_path / "Procfile").write_text("worker: python -m pkg.sub.run\nother: python -m pkg.sub\n")
    assert sj.procfile_entry_modules(str(tmp_path)) == ["pkg.sub.run"]


def test_entry_modules_without_a_readable_procfile(tmp_path):
    assert sj.procfile_entry_modules(str(tmp_path)) == []
    (tmp_path / "Procfile").write_bytes(b"\xff\xfe worker: python x.py\n")
    assert sj.procfile_entry_modules(str(tmp_path)) == []
    (tmp_path / "Procfile").write_text("worker: python x.py\n" + "#" * (sj.MAX_PROCFILE_BYTES + 1))
    assert sj.procfile_entry_modules(str(tmp_path)) == []
    (tmp_path / "Procfile").unlink()
    (tmp_path / "real").write_text("worker: python x.py\n")
    os.symlink(str(tmp_path / "real"), str(tmp_path / "Procfile"))
    assert sj.procfile_entry_modules(str(tmp_path)) == []


# ------------------------------------------------------------------------------------------------ parity with V3c
def test_server_value_options_match_v3c():
    assert sj.PROCFILE_SERVERS == v3c.VALUE_OPTIONS
    assert sj.PROCFILE_PYTHONS == v3c.PYTHONS


@pytest.mark.parametrize("text", ["", "web: uvicorn main:app --port $PORT\n", "# c\n\nweb: a\nworker: b\nweb: c\n",
                                  "bad line\nx: \n: y\nmy proc: z\nok: run it\n", "  worker :  python -m w  \n"])
def test_procfile_lines_match_v3c(text):
    assert sj.procfile_processes(text) == v3c.parse_procfile(text)[0]


@pytest.mark.parametrize("command", [
    "python consumer.py", "python3 -u worker.py", "uvicorn main:app --host 0.0.0.0 --port $PORT",
    "uvicorn --host 0.0.0.0 --port ${PORT:-8080} api.main:app", "gunicorn -b :$PORT -w 2 wsgi:application",
    "python -m uvicorn app:app --port $PORT", "hypercorn --bind 0.0.0.0:$PORT svc:app", "bash start.sh",
])
def test_entry_module_agrees_with_v3c_parse_command(command):
    """On these shapes both parsers read the same target (the job judges a superset/subset elsewhere: RT F3)."""
    import shlex
    launch = v3c.parse_command(shlex.split(command))
    if launch.kind == "server":
        expected = launch.target.partition(":")[0]
    elif launch.kind == "python_file":
        expected = launch.target[:-len(".py")]
    else:
        expected = None
    assert sj.procfile_entry_module(command) == expected


# ------------------------------------------------------------------------------------------------ end to end
CONSUMER_OK = ("import json\n\n\ndef handle(raw):\n    return json.loads(raw)\n\n\n"
               "if __name__ == '__main__':\n    raise SystemExit('the loop runs only as a script')\n")
CONSUMER_TEST = "from consumer import handle\n\n\ndef test_handle():\n    assert handle('{}') == {}\n"


def worker_service(**extra):
    files = {
        "apps/fleet-gke/consumer.py": CONSUMER_OK,
        "apps/fleet-gke/requirements.txt": "",
        "apps/fleet-gke/Procfile": "worker: python consumer.py\n",
        "apps/fleet-gke/.python-version": "3.13\n",
        "apps/fleet-gke/tests/test_consumer.py": CONSUMER_TEST,
    }
    files.update(extra)
    return {k: v for k, v in files.items() if v is not None}


def test_procfile_worker_gets_the_import_smoke_and_passes(cloud, toolchain):
    code, _ = run(cloud, toolchain, worker_service())
    static, report = artifacts(cloud)
    assert code == 0, (static, report)
    assert "== apps/fleet-gke: import consumer (exit 0)" in report["logs_tail"]
    assert report["tests_total"] == 1


def test_procfile_worker_import_failure_is_code_defect(cloud, toolchain):
    """The worker's tests never import consumer.py, so before this fix QA passed a worker that cannot start."""
    files = worker_service(**{
        "apps/fleet-gke/consumer.py": "import definitely_not_installed_module_xyz\n",
        "apps/fleet-gke/tests/test_consumer.py": "def test_nothing():\n    assert True\n",
    })
    code, _ = run(cloud, toolchain, files)
    _, report = artifacts(cloud)
    assert code == 10, report
    d = [d for d in report["diagnostics"] if d["code"] == "PY.IMPORT_FAILED"][0]
    assert d["file"] == "apps/fleet-gke/Procfile" and "definitely_not_installed_module_xyz" in d["detail"]
    assert d["message"] == "`import consumer` failed for apps/fleet-gke"


def test_procfile_command_the_job_cannot_read_gets_no_smoke(cloud, toolchain):
    """Negative: a launcher outside the exact set (here a shell script) is not judged, exactly as before."""
    files = worker_service(**{
        "apps/fleet-gke/consumer.py": "import definitely_not_installed_module_xyz\n",
        "apps/fleet-gke/Procfile": "worker: bash run.sh\n",
        "apps/fleet-gke/tests/test_consumer.py": "def test_nothing():\n    assert True\n",
    })
    code, _ = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 0, (static, report)
    assert "PY.IMPORT_FAILED" not in codes(report["diagnostics"])

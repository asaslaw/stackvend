"""QA-REPAIR-MISSING-MODULE (register row, awaiting owner): the QA runner reports the module an import could not find
as a typed field, and the QA repair may add exactly the one distribution the closed catalog maps it to.

Seen live 2026-11-09 (example 08): QA failed `import main` with `ModuleNotFoundError: No module named 'asyncpg'`.
SQLAlchemy loads the driver by name from a `postgresql+asyncpg://` URL, so no import line names asyncpg. The developer
wrote no requirements.txt; the gatekeeper's add-only contract created it with the proven needs, so it was not a draft
file and the repair could only edit main.py, made no progress, and the workload failed.

Covered here: the runner's import smoke writes the exception's own `name` (never the traceback text) and re-raises
unchanged; the job reads that fact as untrusted (regular file, size cap, exact module-name shape); the gateway's
artifact schema accepts it and leaves every other diagnostic exactly as before; the plan maps it only through the
catalog (unknown, local, stdlib, already declared and malformed names widen nothing); a requirements file the
gatekeeper wrote becomes repairable, add-only, for exactly that one distribution; and the ex08 shape end to end through
the real developer stage (fake LLM and /validate only).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import stat
import subprocess
import sys
import json

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401,E402  (puts the gateway on sys.path)
from test_qa_feedback import APP, MAIN, TF_DRAFT, _develop, _feedback, _qa_diag, _section  # noqa: E402
from test_qa_sandbox_job import artifacts, cloud, gateway_verdict, run, single_service, toolchain, wheelhouse  # noqa: F401,E402
import qa_job_client as qjc  # noqa: E402
from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent import qa_requirements_guard as G  # noqa: E402
from gatekeeper_agent.pypi_catalog import CANONICAL_PYPI_CATALOG  # noqa: E402
from gatekeeper_agent.requirements_contract import append_missing_requirements  # noqa: E402
from shared.diagnostics import RepairBudgetExhausted  # noqa: E402

sj = sup.load_sandbox_job("sandbox_job_qa_repair_missing_module")
REQS = "apps/shop/requirements.txt"
PROCFILE = "apps/shop/Procfile"
SCHEMAS = "apps/shop/schemas/__init__.py"
ASYNCPG = CANONICAL_PYPI_CATALOG["asyncpg"]                  # the catalog's own requirement string
EX08_MAIN = ("import os\n\nfrom fastapi import FastAPI\nfrom sqlalchemy.ext.asyncio import create_async_engine\n\n"
             "DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql+asyncpg://app@localhost/app')\n"
             "engine = create_async_engine(DATABASE_URL)\napp = FastAPI()\n\n\n@app.get('/health')\ndef health():\n"
             "    return {'ok': True}\n")
EX08_TEXT = "ModuleNotFoundError: No module named 'asyncpg'"


def _import_failed(missing="asyncpg", **kw):
    base = dict(file=MAIN, code="PY.IMPORT_FAILED", message="`import main` failed for apps/shop", detail=EX08_TEXT)
    base.update(kw)
    d = _qa_diag(**base)
    if missing is not None:
        d["missing_module"] = missing
    return d


def _ex08_tree():
    """The tested tree of example 08: the developer wrote main.py, the Procfile and a package, no requirements.txt;
    the gatekeeper's contract created the file (exactly append_missing_requirements, as reconcile_service_requirements
    runs it)."""
    draft = {MAIN: EX08_MAIN, PROCFILE: APP[PROCFILE], SCHEMAS: "class Other:\n    pass\n",
             "infra/workload/main.tf": "# platform\n"}
    tree, actions = append_missing_requirements(draft)
    assert actions == [f"created {REQS} with 3 proven requirement(s): "
                       f"['fastapi>=0.110.0', 'SQLAlchemy>=2.0.28', 'uvicorn[standard]>=0.28.0']"]
    return tree, sorted(p for p in draft if not p.startswith("infra/"))


# ------------------------------------------------------------------------------------------------ module-name parity
NAMES = ["asyncpg", "google.auth.transport.requests", "_private", "a" * QR.MAX_MODULE_NAME_CHARS, "x1.y_2"]
NOT_NAMES = ["", "a b", "a..b", ".a", "a.", "1abc", "a-b", "a/b", "café", "a" * (QR.MAX_MODULE_NAME_CHARS + 1),
             "asyncpg\n", None, 5, b"asyncpg", ["asyncpg"]]


@pytest.mark.parametrize("value", NAMES + NOT_NAMES)
def test_the_three_module_name_rules_agree(value):
    assert sj.is_module_name(value) == qjc.is_module_name(value) == QR.is_module_name(value) == (value in NAMES)


def test_the_three_caps_agree():
    assert sj.MAX_MODULE_NAME_CHARS == qjc.MAX_MODULE_NAME_CHARS == QR.MAX_MODULE_NAME_CHARS


def test_the_field_name_is_the_runners_and_the_gateways():
    assert QR.MISSING_MODULE_FIELD in qjc.DiagnosticIn.model_fields
    assert sj.diag("python", "PY.IMPORT_FAILED", "m", missing_module="asyncpg")[QR.MISSING_MODULE_FIELD] == "asyncpg"


# ------------------------------------------------------------------------------------------------ the import smoke
def _smoke(tmp_path, main_text, module="main"):
    (tmp_path / "svc").mkdir(exist_ok=True)
    (tmp_path / "svc" / f"{module}.py").write_text(main_text)
    fact = tmp_path / "fact"
    env = dict(hermetic_guard.child_env(), PYTHONPATH=str(tmp_path / "svc"))
    argv = sj.import_smoke_argv(sys.executable, module, str(fact), procfile=module != "main")
    r = subprocess.run(argv, cwd=str(tmp_path / "svc"), env=env, capture_output=True, text=True, timeout=60)
    return r, sj.missing_module_fact(str(fact))


# The two smokes before QA-REPAIR-MISSING-MODULE (main b8d5b0f4): `import main`, and IMPORT_BY_ARGV for a Procfile module
OLD_PROCFILE_SMOKE = "import importlib, sys; importlib.import_module(sys.argv[1])"


def _old_smoke(tmp_path, module="main"):
    env = dict(hermetic_guard.child_env(), PYTHONPATH=str(tmp_path / "svc"))
    argv = ([sys.executable, "-c", "import main"] if module == "main"
            else [sys.executable, "-c", OLD_PROCFILE_SMOKE, module])
    return subprocess.run(argv, cwd=str(tmp_path / "svc"), env=env, capture_output=True, text=True, timeout=60)


SMOKES = [
    ("a plain import", "import definitely_missing_xyz\n", "definitely_missing_xyz"),
    ("a submodule of a missing package", "import definitely_missing_xyz.sub\n", "definitely_missing_xyz"),
    ("loaded by name at run time (the SQLAlchemy driver shape)",
     "def _dbapi():\n    return __import__('asyncpg_missing_xyz')\n\nengine = _dbapi()\n", "asyncpg_missing_xyz"),
    ("an explicit cause (the google-auth requests transport shape)",
     "try:\n    import requests_missing_xyz\nexcept ImportError as caught:\n"
     "    raise ImportError('The requests library is not installed') from caught\n", "requests_missing_xyz"),
    ("an implicit context", "try:\n    import ctx_missing_xyz\nexcept ImportError:\n    raise RuntimeError('no')\n",
     "ctx_missing_xyz"),
]


@pytest.mark.parametrize("label,text,name", SMOKES, ids=[s[0] for s in SMOKES])
def test_the_smoke_writes_the_exceptions_own_name(tmp_path, label, text, name):
    r, fact = _smoke(tmp_path, text)
    assert r.returncode == 1 and fact == name
    assert "Traceback (most recent call last)" in r.stderr     # the failure is re-raised unchanged


NO_FACT = [
    ("a suppressed context", "try:\n    import gone_xyz\nexcept ImportError:\n    raise RuntimeError('no') from None\n"),
    ("a name that is not there", "from os import definitely_not_a_name\n"),
    ("another error", "raise RuntimeError('boom')\n"),
    ("a syntax error", "def (:\n"),
    ("SystemExit", "raise SystemExit(3)\n"),
]


@pytest.mark.parametrize("label,text", NO_FACT, ids=[s[0] for s in NO_FACT])
def test_without_a_missing_module_there_is_no_fact(tmp_path, label, text):
    r, fact = _smoke(tmp_path, text)
    assert r.returncode != 0 and fact is None


def test_the_smoke_keeps_the_exit_status_and_the_last_line_of_import_main(tmp_path):
    """Do No Harm: the same failure reads the same (exit status and the exception line) as `python -c "import main"`."""
    for text in ("import definitely_missing_xyz\n", "raise RuntimeError('boom')\n", "raise SystemExit(3)\n", "X = 1\n"):
        r, _fact = _smoke(tmp_path, text)
        env = dict(hermetic_guard.child_env(), PYTHONPATH=str(tmp_path / "svc"))
        old = subprocess.run([sys.executable, "-c", "import main"], cwd=str(tmp_path / "svc"), env=env,
                             capture_output=True, text=True, timeout=60)
        assert r.returncode == old.returncode
        assert r.stderr.strip().splitlines()[-1:] == old.stderr.strip().splitlines()[-1:]


def test_a_passing_import_writes_nothing(tmp_path):
    r, fact = _smoke(tmp_path, "X = 1\n")
    assert r.returncode == 0 and fact is None and not (tmp_path / "fact").exists()


def test_the_code_under_test_cannot_redirect_the_fact_through_argv(tmp_path):
    r, fact = _smoke(tmp_path, "import sys\nsys.argv[:] = ['-c', 'main', 'elsewhere']\nimport definitely_missing_xyz\n")
    assert fact == "definitely_missing_xyz" and not (tmp_path / "svc" / "elsewhere").exists()


ARGV_PROBE = "import sys\nprint('ARGV', repr(sys.argv))\n"
ARGPARSE_MAIN = ("import argparse\n\nparser = argparse.ArgumentParser()\nparser.add_argument('--batch', default='1')\n"
                 "ARGS = parser.parse_args()\n")


@pytest.mark.parametrize("module", ["main", "consumer"], ids=["main", "procfile_module"])
def test_rt_f1_the_imported_module_sees_exactly_the_old_smokes_argv(tmp_path, module):
    """RT F1 (Do No Harm): `python -c "import main"` gave ['-c'], the Procfile smoke ['-c', module]; so does this one."""
    r, fact = _smoke(tmp_path, ARGV_PROBE, module=module)
    old = _old_smoke(tmp_path, module)
    assert r.returncode == old.returncode == 0 and fact is None
    assert r.stdout == old.stdout == f"ARGV {['-c'] if module == 'main' else ['-c', module]!r}\n"


@pytest.mark.parametrize("module", ["main", "consumer"], ids=["main", "procfile_module"])
def test_rt_f1_a_module_level_argparse_behaves_exactly_as_before(tmp_path, module):
    """A batch-worker entry point that parses argv at import: `main` passes (as before); a Procfile module gets the
    same result as under the old smoke (which already passed it one argument)."""
    r, fact = _smoke(tmp_path, ARGPARSE_MAIN, module=module)
    old = _old_smoke(tmp_path, module)
    assert (r.returncode, r.stdout, r.stderr.splitlines()[-1:]) == (old.returncode, old.stdout,
                                                                   old.stderr.splitlines()[-1:])
    assert fact is None
    if module == "main":
        assert r.returncode == 0


def test_a_procfile_module_gets_the_same_smoke(tmp_path):
    r, fact = _smoke(tmp_path, "import definitely_missing_xyz\n", module="consumer")
    assert r.returncode == 1 and fact == "definitely_missing_xyz"


# ------------------------------------------------------------------------------------------------ reading the fact
def test_the_fact_is_read_as_untrusted(tmp_path):
    good = tmp_path / "good"
    good.write_text("asyncpg")
    assert sj.missing_module_fact(str(good)) == "asyncpg"
    assert sj.missing_module_fact(str(tmp_path / "absent")) is None
    link = tmp_path / "link"
    os.symlink(str(good), str(link))
    assert sj.missing_module_fact(str(link)) is None                       # never followed
    (tmp_path / "dir").mkdir()
    assert sj.missing_module_fact(str(tmp_path / "dir")) is None
    if hasattr(os, "mkfifo"):
        os.mkfifo(str(tmp_path / "fifo"))
        assert sj.missing_module_fact(str(tmp_path / "fifo")) is None      # never blocks
    for raw in [b"a" * (sj.MAX_MODULE_NAME_CHARS + 1), b"asyncpg\n", b"a b", b"\xff\xfe", b"", b"evil-package==1",
                "café".encode()]:
        bad = tmp_path / "bad"
        bad.write_bytes(raw)
        assert sj.missing_module_fact(str(bad)) is None, raw


def test_diag_keeps_its_seven_keys_without_a_valid_fact():
    base = sj.diag("python", "PY.IMPORT_FAILED", "m", file="apps/svc/main.py", detail="d")
    assert set(base) == {"tool", "code", "severity", "file", "line", "message", "detail"}
    for value in (None, "", "a b", "x" * 500, 3):
        assert sj.diag("python", "PY.IMPORT_FAILED", "m", file="apps/svc/main.py", detail="d",
                       missing_module=value) == base


# ------------------------------------------------------------------------------------------------ job + gateway, end to end
def test_the_job_reports_the_missing_module_and_the_gateway_keeps_it(cloud, toolchain):
    files = single_service(**{"apps/svc/main.py": "import definitely_not_installed_module_xyz\n"})
    code, _ = run(cloud, toolchain, files)
    _static, report = artifacts(cloud)
    assert code == 10, report
    (d,) = [d for d in report["diagnostics"] if d["code"] == "PY.IMPORT_FAILED"]
    assert d["missing_module"] == "definitely_not_installed_module_xyz" and d["file"] == "apps/svc/main.py"
    outcome = gateway_verdict(cloud, code)
    (g,) = [x for x in outcome.diagnostics if x["code"] == "PY.IMPORT_FAILED"]
    assert g["missing_module"] == "definitely_not_installed_module_xyz"


def test_another_import_failure_has_no_fact_and_the_gateway_dict_is_unchanged(cloud, toolchain):
    files = single_service(**{"apps/svc/main.py": "raise RuntimeError('boom')\n"})
    code, _ = run(cloud, toolchain, files)
    _static, report = artifacts(cloud)
    (d,) = [d for d in report["diagnostics"] if d["code"] == "PY.IMPORT_FAILED"]
    assert "missing_module" not in d
    (g,) = [x for x in gateway_verdict(cloud, code).diagnostics if x["code"] == "PY.IMPORT_FAILED"]
    assert set(g) == {"tool", "code", "severity", "file", "line", "message", "detail"}


def test_the_gateway_schema_accepts_the_old_shape_byte_identically_and_refuses_a_bad_fact():
    old = {"tool": "python", "code": "PY.IMPORT_FAILED", "severity": "error", "file": "apps/svc/main.py", "line": None,
           "message": "m", "detail": "d"}
    assert qjc.DiagnosticIn(**old).model_dump() == old                      # an older job: exactly as before
    assert json.loads(qjc.DiagnosticIn(**old).model_dump_json()) == old
    assert qjc.DiagnosticIn(**old, missing_module="asyncpg").model_dump() == dict(old, missing_module="asyncpg")
    for bad in ("a b", "", "x" * 300, "evil-package==1"):
        with pytest.raises(Exception):
            qjc.DiagnosticIn(**old, missing_module=bad)


# ------------------------------------------------------------------------------------------------ the plan: example 08
def test_ex08_the_gatekeeper_written_requirements_become_repairable_for_exactly_asyncpg():
    tree, draft_paths = _ex08_tree()
    assert REQS not in draft_paths and QR.written_by_requirements_contract(tree, REQS)
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(), draft_paths=draft_paths), stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.QA_REPAIR, "IMPORT_FAILURE_ON_SERVICE_DEPENDENCIES")
    assert plan.repairable_paths == {MAIN, REQS}
    assert dict(plan.requirements_guard) == {REQS: frozenset({"asyncpg"})}   # exactly one name, nothing imported
    assert plan.draft[REQS] == tree[REQS] and plan.seed_files[REQS] == tree[REQS]
    assert set(plan.draft) == set(draft_paths) | {REQS}                       # nothing else joined the draft
    for s in plan.seeds:
        assert s.hint == QR.MISSING_MODULE_SEED_HINT and s.symbol == "qa_import_finding_1"
        assert f"`{ASYNCPG}`" in s.message and EX08_TEXT not in s.model_dump_json()
    assert plan.summary()["missing_modules"] == [{"file": MAIN, "module": "asyncpg", "status": QR.MODULE_IN_CATALOG,
                                                  "requirement": ASYNCPG, "requirements": REQS}]


def test_ex08_without_the_fact_is_exactly_todays_plan():
    """Do No Harm: an older runner (no field) gives the plan this code gave before (the live failure's plan)."""
    tree, draft_paths = _ex08_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(missing=None), draft_paths=draft_paths),
                             stack_configured=True)
    assert (plan.mode, plan.reason) == (QR.QA_REPAIR, "CODE_DEFECT_ON_DRAFT_FILES")
    assert plan.repairable_paths == {MAIN} and not plan.requirements_guard and REQS not in plan.draft
    (seed,) = plan.seeds
    assert (seed.hint, seed.symbol) == (QR.SEED_HINT, None)
    assert plan.summary()["missing_modules"] == []


@pytest.mark.parametrize("missing,status", [
    ("acme_driver_xyz", QR.MODULE_NOT_IN_CATALOG),          # unknown: reported by name, never guessed
    ("schemas", "LOCAL_MODULE"),                             # a module of the service: a code fix
    ("tomllib", "STDLIB_MODULE"),
    ("a b", "MODULE_NAME_INVALID"),
    (7, "MODULE_NAME_INVALID"),
    ("sqlalchemy", "ALREADY_DECLARED"),                      # the file names it: nothing to add
], ids=["not_in_catalog", "local", "stdlib", "invalid", "not_a_string", "already_declared"])
def test_ex08_any_other_fact_widens_nothing_and_is_recorded(missing, status):
    tree, draft_paths = _ex08_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(missing=missing), draft_paths=draft_paths),
                             stack_configured=True)
    today = QR.plan_qa_repair(_feedback(tree, _import_failed(missing=None), draft_paths=draft_paths),
                              stack_configured=True)
    assert (plan.reason, plan.repairable_paths, plan.requirements_guard) == (
        today.reason, today.repairable_paths, today.requirements_guard)
    assert [s.model_dump() for s in plan.seeds] == [s.model_dump() for s in today.seeds]
    assert dict(plan.draft) == dict(today.draft)
    (fact,) = plan.summary()["missing_modules"]
    assert fact["status"] == status and fact["file"] == MAIN and fact["requirements"] is None
    assert fact["requirement"] == (CANONICAL_PYPI_CATALOG["sqlalchemy"] if status == "ALREADY_DECLARED" else None)


@pytest.mark.parametrize("edit", [
    lambda t: t + "pinned-thing==1.0\n",                     # a line the contract never writes
    lambda t: "".join(reversed(t.splitlines(keepends=True))),  # the contract's lines, another order
    lambda t: t.replace("fastapi>=0.110.0", "fastapi==0.115.0"),
    lambda t: t.rstrip("\n"),
], ids=["extra_line", "reordered", "repinned", "no_final_newline"])
def test_a_requirements_file_the_contract_did_not_write_stays_the_repositorys(edit):
    """Not a draft file and not byte for byte the gatekeeper's output (a person's file, an earlier build's edit):
    the ownership rule of SAT-49 holds, the fact allows nothing there."""
    tree, draft_paths = _ex08_tree()
    tree = dict(tree, **{REQS: edit(tree[REQS])})
    assert not QR.written_by_requirements_contract(tree, REQS)
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(), draft_paths=draft_paths), stack_configured=True)
    assert plan.reason == "CODE_DEFECT_ON_DRAFT_FILES" and plan.repairable_paths == {MAIN}
    assert not plan.requirements_guard and REQS not in plan.draft
    (fact,) = plan.summary()["missing_modules"]
    assert (fact["status"], fact["requirements"]) == (QR.MODULE_IN_CATALOG, None)   # known, but nothing was allowed


def test_written_by_the_contract_is_exact():
    tree, _paths = _ex08_tree()
    assert QR.written_by_requirements_contract(tree, REQS)
    assert not QR.written_by_requirements_contract({p: c for p, c in tree.items() if p != REQS}, REQS)
    assert not QR.written_by_requirements_contract(dict(tree, **{REQS: tree[REQS] + "\n"}), REQS)
    assert not QR.written_by_requirements_contract(None, REQS)
    assert not QR.written_by_requirements_contract({REQS: 5}, REQS)


def test_the_fact_is_read_only_on_a_sandbox_import_failure():
    tree, draft_paths = _ex08_tree()
    for d in (dict(_qa_diag(code="PY.TEST_FAILED"), missing_module="asyncpg"),
              dict(_import_failed(), stage2_judge=True)):
        plan = QR.plan_qa_repair(_feedback(tree, d, draft_paths=draft_paths), stack_configured=True)
        assert not plan.requirements_guard and REQS not in plan.draft and plan.summary()["missing_modules"] == []


def test_another_services_requirements_are_never_offered():
    tree, draft_paths = _ex08_tree()
    other_main, other_reqs = "apps/api/main.py", "apps/api/requirements.txt"
    tree, _ = append_missing_requirements(dict(tree, **{other_main: "import flask\n"}))
    assert QR.written_by_requirements_contract(tree, other_reqs)
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(), draft_paths=draft_paths + [other_main]),
                             stack_configured=True)
    assert set(plan.requirements_guard) == {REQS} and other_reqs not in plan.draft


# ------------------------------------------------------------------------------------------------ a draft requirements file
def test_a_draft_requirements_file_gains_the_catalog_distribution_beside_the_imported_names():
    tree, draft_paths = _ex08_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(), draft_paths=draft_paths + [REQS]), stack_configured=True)
    today = QR.plan_qa_repair(_feedback(tree, _import_failed(missing=None), draft_paths=draft_paths + [REQS]),
                              stack_configured=True)
    assert plan.requirements_guard[REQS] == today.requirements_guard[REQS] | {"asyncpg"}
    assert "asyncpg" not in today.requirements_guard[REQS]
    assert all(s.hint == QR.MISSING_MODULE_SEED_HINT for s in plan.seeds)
    assert all(s.hint == QR.IMPORT_SEED_HINT for s in today.seeds)            # without the fact: exactly as before


def test_the_requests_class_is_covered_when_no_import_names_it():
    """The earlier `requests` failures: a module loaded by name that the code never imports by that name."""
    tree = {MAIN: "import importlib\n\nhttp = importlib.import_module('requests')\n", PROCFILE: APP[PROCFILE]}
    tree, _ = append_missing_requirements(tree)
    assert "requests" not in tree[REQS]
    d = _import_failed(missing="requests", detail="ModuleNotFoundError: No module named 'requests'")
    plan = QR.plan_qa_repair(_feedback(tree, d, draft_paths=[MAIN, PROCFILE]), stack_configured=True)
    assert dict(plan.requirements_guard) == {REQS: frozenset({"requests"})}
    assert plan.summary()["missing_modules"][0]["requirement"] == CANONICAL_PYPI_CATALOG["requests"]


# ------------------------------------------------------------------------------------------------ the guard, with the fact
REFUSED = [
    ("an unrelated package", "evil-package==1.0\n", G.NOT_IMPORTED_BY_SERVICE),
    ("another catalog driver", "psycopg>=3.2.0\n", G.NOT_IMPORTED_BY_SERVICE),
    ("a typosquat", "asyncpgg\n", G.NOT_IMPORTED_BY_SERVICE),
    ("the name twice", f"{ASYNCPG}\nasyncpg\n", G.ALREADY_DECLARED),
    ("a URL for it", "asyncpg @ https://evil.example/a.whl\n", G.URL_REQUIREMENT),
    ("a pip option", "--index-url https://evil.example/simple\n", G.PIP_OPTION),
]


@pytest.mark.parametrize("label,added,reason", REFUSED, ids=[r[0] for r in REFUSED])
def test_the_guard_still_refuses_everything_else(label, added, reason):
    tree, draft_paths = _ex08_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(), draft_paths=draft_paths), stack_configured=True)
    refusals = G.refusals_of(plan.requirements_guard, plan.seed_files, {REQS: tree[REQS] + added})
    assert reason in [r.reason for r in refusals]


def test_the_guard_refuses_an_edit_of_a_gatekeeper_line_and_accepts_the_one_addition():
    tree, draft_paths = _ex08_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(), draft_paths=draft_paths), stack_configured=True)
    edited = tree[REQS].replace("SQLAlchemy>=2.0.28", "SQLAlchemy==1.4.0") + "asyncpg\n"
    assert [r.reason for r in G.refusals_of(plan.requirements_guard, plan.seed_files, {REQS: edited})] == [
        G.EXISTING_LINE_CHANGED]
    for added in (f"{ASYNCPG}\n", "asyncpg\n", "asyncpg>=0.30\n"):
        assert G.refusals_of(plan.requirements_guard, plan.seed_files, {REQS: tree[REQS] + added}) == []
    assert G.refusals_of(plan.requirements_guard, plan.seed_files, {REQS: tree[REQS]}) == []   # unchanged: no refusal


# ------------------------------------------------------------------------------------------------ developer stage, end to end
def _ex08_first_build():
    """Attempt 0 through the real assembly: the developer's draft has no requirements.txt."""
    draft = {MAIN: EX08_MAIN, PROCFILE: APP[PROCFILE], SCHEMAS: "class Other:\n    pass\n", **TF_DRAFT}
    att = {p: ("IAC_ENGINEER" if p.startswith("infra/") else "BACKEND_ENGINEER") for p in draft}
    files, agent, _c, _seen = _develop("off", swarm_draft=draft, swarm_att=att)
    assert agent.last_validation_report.status == "PASS"
    assert REQS in files and "asyncpg" not in files[REQS]           # the gatekeeper wrote it, without the driver
    assert QR.written_by_requirements_contract(files, REQS)
    return files, sorted(draft)


def test_ex08_end_to_end_the_driver_is_added_and_committed():
    tree, draft_paths = _ex08_first_build()
    fixed = tree[REQS] + f"{ASYNCPG}\n"
    files, agent, _client, seen = _develop("off", feedback=_feedback(tree, _import_failed(), draft_paths=draft_paths),
                                           repairs=[{REQS: fixed}])
    assert seen["swarm"] == 0 and not seen["lead_calls"]
    (task,) = seen["repair_tasks"]
    assert json.loads(_section(task["prompt"], "FILES TO FIX:", QR.QA_OUTPUT_HEADER)) == {MAIN: tree[MAIN],
                                                                                         REQS: tree[REQS]}
    diags = json.loads(_section(task["prompt"], "DIAGNOSTICS:", "FILES TO FIX:"))
    assert all(x["hint"] == QR.MISSING_MODULE_SEED_HINT and ASYNCPG in x["message"] for x in diags)
    assert agent.last_validation_report.status == "PASS" and files[REQS] == fixed and files[MAIN] == tree[MAIN]
    rec = agent.stack_run("t-qa")["qa_repair"]
    assert (rec["mode"], rec["reason"]) == (QR.QA_REPAIR, "IMPORT_FAILURE_ON_SERVICE_DEPENDENCIES")
    assert rec["missing_modules"][0]["status"] == QR.MODULE_IN_CATALOG


def test_ex08_end_to_end_an_unrelated_addition_is_refused_then_the_driver_is_accepted():
    tree, draft_paths = _ex08_first_build()
    bad = tree[REQS] + "evil-package==1.0\n"
    good = tree[REQS] + "asyncpg\n"
    files, agent, _client, seen = _develop("off", feedback=_feedback(tree, _import_failed(), draft_paths=draft_paths),
                                           repairs=[{REQS: bad}, {REQS: good}])
    assert "evil-package" not in files[REQS] and files[REQS] == good
    assert G.REQUIREMENTS_REFUSED in seen["repair_tasks"][1]["prompt"]


def test_ex08_end_to_end_without_the_fact_the_requirements_file_stays_out_of_reach():
    """Today's behaviour, kept for an older runner: the platform's file is not repairable, a candidate writing it is
    outside the group and the loop stays bounded (the live failure's shape)."""
    tree, draft_paths = _ex08_first_build()
    with pytest.raises(RepairBudgetExhausted):
        _develop("off", feedback=_feedback(tree, _import_failed(missing=None), draft_paths=draft_paths),
                 repairs=[{REQS: tree[REQS] + "asyncpg\n"}], repair_max_iterations_precommit=1)


def test_ex08_end_to_end_an_unknown_module_is_never_guessed():
    tree, draft_paths = _ex08_first_build()
    with pytest.raises(RepairBudgetExhausted):
        _develop("off", feedback=_feedback(tree, _import_failed(missing="acme_driver_xyz"), draft_paths=draft_paths),
                 repairs=[{REQS: tree[REQS] + "acme-driver-xyz\n"}], repair_max_iterations_precommit=1)


def test_the_seed_texts_of_the_existing_paths_are_unchanged():
    """Pinned before this change: the prompt cassettes key on these (repair_loop.render_repair_prompt)."""
    import hashlib
    assert hashlib.sha256(QR.IMPORT_SEED_HINT.encode()).hexdigest() == (
        "3eacf6fe24e35fad6d65c645311cffe757b49db7c08dcc749d78755c1a1697a6")


# ------------------------------------------------------------------------------------------------ RT F4: ownership after
def test_rt_f4_the_plan_names_the_lent_platform_file():
    tree, draft_paths = _ex08_tree()
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(), draft_paths=draft_paths), stack_configured=True)
    assert plan.platform_paths == {REQS}
    plan = QR.plan_qa_repair(_feedback(tree, _import_failed(), draft_paths=draft_paths + [REQS]), stack_configured=True)
    assert plan.platform_paths == frozenset()                      # the developer's own file is not lent


def test_rt_f4_a_changed_platform_file_becomes_a_draft_path_of_the_commit():
    tree, draft_paths = _ex08_first_build()
    _files, agent, _client, _seen = _develop("off", feedback=_feedback(tree, _import_failed(), draft_paths=draft_paths),
                                             repairs=[{REQS: tree[REQS] + "asyncpg\n"}])
    assert REQS in agent.stack_run("t-qa")["llm_draft_paths"]


def test_rt_f4_an_unchanged_platform_file_stays_the_platforms():
    tree, draft_paths = _ex08_first_build()
    fixed = tree[MAIN] + "\n# the driver is chosen by DATABASE_URL\n"
    files, agent, _client, _seen = _develop("off", feedback=_feedback(tree, _import_failed(), draft_paths=draft_paths),
                                            repairs=[{MAIN: fixed}])
    assert files[REQS] == tree[REQS] and files[MAIN] == fixed
    recorded = agent.stack_run("t-qa")["llm_draft_paths"]
    assert REQS not in recorded and MAIN in recorded

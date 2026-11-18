"""IMPORT-RESOLVE-GATE (register row, owner 10-28): V3e-local-imports, PY.LOCAL_IMPORT_UNRESOLVED (blocking).

Live 10-28 (testplan01-d): `handlers.py` imported `EventAuditRecord` from the local package `schemas`, whose
`__init__.py` neither defined nor re-exported it; pre-commit passed, QA's `import main` failed, the QA repair did not
fix it. The validator reads the source with `ast` only and reports; it never imports generated code or rewrites a file.

Every fixture below is also checked against CPython itself (test_cpython_agrees): the fixture (our own code) is written
to a temporary service directory and imported in a child interpreter with cwd = PYTHONPATH = the service dir, as QA's
sandbox does. A finding must mean an ImportError there; no finding on a fixture that imports cleanly.
Fakes stand in for the LLM; no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import os
import subprocess
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.repair_loop import Assembled, LoopContext, RepairLoop  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.local_imports import CODE, VALIDATOR_ID, LocalImportValidator  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import AssemblyRecord, MemoryLedgerStore, RepairBudgetExhausted  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

SVC = "apps/svc"
EVENTS = "class EventAuditRecord:\n    pass\n\n\nclass EventIn:\n    pass\n"
HANDLERS_BAD = "from schemas import (\n    EventIn,\n    EventAuditRecord,\n)\n\n\ndef handle():\n    return EventIn\n"
HANDLERS_OK = "from schemas import EventIn\nfrom schemas.events import EventAuditRecord\n\n\ndef handle():\n" \
              "    return EventIn, EventAuditRecord\n"
MAIN = "import handlers\n"


def svc(files, main=MAIN):
    out = {f"{SVC}/{k}": v for k, v in files.items()}
    if main is not None:
        out.setdefault(f"{SVC}/main.py", main)
    return out


def _ctx(files, llm=None):
    llm = set(files) if llm is None else set(llm)
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p in llm
                                   else Ownership.PLATFORM_RENDERED, draft={k: files[k] for k in llm if k in files})


def found(files, llm=None):
    return LocalImportValidator().validate(_ctx(files, llm))


def summary(files, llm=None):
    return sorted((d.file[len(SVC) + 1:], d.line, d.symbol) for d in found(files, llm))


# The live case, reconstructed: schemas/__init__.py re-exports EventIn only; EventAuditRecord lives in schemas/events.py
LIVE = svc({"handlers.py": HANDLERS_BAD, "schemas/__init__.py": "from .events import EventIn\n",
            "schemas/events.py": EVENTS})

# (name, files, the module to import in the CPython check, expected findings as (file, line, symbol))
POSITIVES = [
    ("live_package_lacks_name", LIVE, "main", [("handlers.py", 1, "EventAuditRecord")]),
    ("module_lacks_name", svc({"handlers.py": "from models import User, Order\n", "models.py": "class User: ...\n"}),
     "main", [("handlers.py", 1, "Order")]),
    ("shadowed_module", svc({"handlers.py": "from schemas import EventAuditRecord\n", "schemas.py": EVENTS,
                             "schemas/__init__.py": "from .contracts import *\n",
                             "schemas/contracts.py": "class Contract: ...\n"}),
     "main", [("handlers.py", 1, "EventAuditRecord")]),
    ("relative_name_missing", svc({"pkg/__init__.py": "", "pkg/a.py": "from .b import missing\n",
                                   "pkg/b.py": "present = 1\n"}, main="import pkg.a\n"),
     "main", [("pkg/a.py", 1, "missing")]),
    ("relative_submodule_missing", svc({"pkg/__init__.py": "", "pkg/a.py": "from .nothere import x\n"},
                                       main="import pkg.a\n"),
     "main", [("pkg/a.py", 1, ".nothere")]),
    ("dotted_import_missing_submodule", svc({"pkg/__init__.py": ""}, main="import pkg.nothere\n"),
     "main", [("main.py", 1, "pkg.nothere")]),
    ("from_dotted_missing_submodule", svc({"pkg/__init__.py": ""}, main="from pkg.nothere import x\n"),
     "main", [("main.py", 1, "pkg.nothere")]),
    ("module_has_no_submodules", svc({"util.py": "x = 1\n"}, main="import util.sub\n"),
     "main", [("main.py", 1, "util.sub")]),
    ("star_does_not_bind_it", svc({"handlers.py": "from schemas import Gone\n",
                                   "schemas/__init__.py": "from .events import *\n", "schemas/events.py": EVENTS}),
     "main", [("handlers.py", 1, "Gone")]),
    ("function_level_import", svc({"handlers.py": "def f():\n    from models import Nope\n    return Nope\n\n\nf()\n",
                                   "models.py": "Yes = 1\n"}),
     "main", [("handlers.py", 2, "Nope")]),
    ("class_attribute_is_not_module_level", svc({"handlers.py": "from models import inner\n",
                                                 "models.py": "class C:\n    inner = 1\n\n\ndef f():\n"
                                                              "    inner = 2\n    return inner\n"}),
     "main", [("handlers.py", 1, "inner")]),
    # review F2: an unguarded star import of a missing submodule is the importing module's own finding (no crash)
    ("unguarded_star_missing_submodule", svc({"handlers.py": "from pkg import x\n",
                                              "pkg/__init__.py": "from .missing import *\nx = 1\n"}),
     "main", [("pkg/__init__.py", 1, ".missing")]),
]

NEGATIVES = [
    ("live_fixed", svc({"handlers.py": HANDLERS_OK, "schemas/__init__.py": "from .events import EventIn\n",
                        "schemas/events.py": EVENTS}), "main"),
    ("reexport", svc({"handlers.py": HANDLERS_BAD,
                      "schemas/__init__.py": "from .events import EventAuditRecord, EventIn\n",
                      "schemas/events.py": EVENTS}), "main"),
    ("reexport_absolute_alias", svc({"handlers.py": HANDLERS_BAD,
                                     "schemas/__init__.py": "from schemas.events import EventIn\n"
                                                            "import schemas.events as _e\nEventAuditRecord = "
                                                            "_e.EventAuditRecord\n",
                                     "schemas/events.py": EVENTS}), "main"),
    ("star_reexport", svc({"handlers.py": HANDLERS_BAD, "schemas/__init__.py": "from .events import *\n",
                           "schemas/events.py": EVENTS}), "main"),
    ("star_chain", svc({"handlers.py": HANDLERS_BAD, "schemas/__init__.py": "from .mid import *\n",
                        "schemas/mid.py": "from .events import *\n", "schemas/events.py": EVENTS}), "main"),
    ("star_with_all", svc({"handlers.py": HANDLERS_BAD, "schemas/__init__.py": "from .events import *\n",
                           "schemas/events.py": EVENTS + "__all__ = ['EventAuditRecord', 'EventIn']\n"}), "main"),
    ("all_does_not_restrict", svc({"handlers.py": "from models import _private, hidden\n",
                                   "models.py": "__all__ = []\n_private = 1\nhidden = 2\n"}), "main"),
    ("submodule_import", svc({"handlers.py": "from schemas import events\nfrom schemas import sub\n",
                              "schemas/__init__.py": "", "schemas/events.py": EVENTS,
                              "schemas/sub/__init__.py": ""}), "main"),
    ("dotted_imports", svc({"handlers.py": "import schemas.events\nimport schemas.sub.leaf as leaf\n",
                            "schemas/__init__.py": "", "schemas/events.py": EVENTS, "schemas/sub/__init__.py": "",
                            "schemas/sub/leaf.py": ""}), "main"),
    ("relative_imports", svc({"pkg/__init__.py": "from . import a\nfrom .b import present as p\n",
                              "pkg/a.py": "from . import b\nfrom .b import present\nfrom ..helpers import h\n",
                              "pkg/b.py": "present = 1\n", "helpers.py": "h = 1\n"},
                             main="import pkg\n"), None),   # `..helpers` above pkg: V3c-imports' finding, not ours
    ("relative_ok", svc({"pkg/__init__.py": "from . import a\n", "pkg/a.py": "from . import b\nfrom .b import x\n",
                         "pkg/b.py": "x = 1\n"}, main="import pkg\n"), "main"),
    ("guarded_try", svc({"handlers.py": "try:\n    from models import Fast\nexcept ImportError:\n    Fast = None\n",
                         "models.py": "Slow = 1\n"}), "main"),
    ("guarded_type_checking", svc({"handlers.py": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
                                                  "    from models import OnlyTypes\n", "models.py": "x = 1\n"}),
     "main"),
    ("bound_in_branches", svc({"handlers.py": "from models import A, B, C, D, E, F, G, H, I, J, K\n",
                               "models.py": "import sys\nif sys.version_info >= (3, 0):\n    A = 1\nelse:\n    A = 2\n"
                                            "try:\n    import json as B\nexcept ImportError:\n    B = None\n"
                                            "for C in range(1):\n    pass\nwith open(__file__) as D:\n    pass\n"
                                            "E: int = 1\n(F := 2)\nG, (H, I) = 1, (2, 3)\n"
                                            "def _f():\n    global J\n    J = 1\n_f()\n"
                                            "class K:\n    pass\n"}), "main"),
    ("module_getattr", svc({"handlers.py": "from models import anything\n",
                            "models.py": "def __getattr__(name):\n    return name\n"}), "main"),
    ("globals_write", svc({"handlers.py": "from models import Made\n",
                           "models.py": "globals()['Made'] = 1\n"}), "main"),
    ("star_from_third_party", svc({"handlers.py": "from models import loads\n",
                                   "models.py": "from json import *\n"}), "main"),
    ("third_party_and_stdlib", svc({"handlers.py": "import os.path\nfrom json import loads\n"
                                                   "from email.mime.text import MIMEText\n"}), "main"),
    ("namespace_package", svc({"handlers.py": "from ns import mod\nfrom ns.mod import x\n", "ns/mod.py": "x = 1\n"}),
     "main"),
    ("attribute_injected", svc({"handlers.py": "import models\nmodels.Late = 1\n\n\ndef f():\n"
                                              "    from models import Late\n    return Late\n",
                                "models.py": "x = 1\n"}), "main"),
    ("sys_modules_rewired", svc({"handlers.py": "import sys\nimport types\nm = types.ModuleType('models')\n"
                                               "m.Fake = 1\nsys.modules['models'] = m\nfrom models import Fake\n",
                                 "models.py": "x = 1\n"}), "main"),
    ("ambiguous_top_level", svc({"tests/test_x.py": "from helpers import h\n", "tests/helpers.py": "h = 1\n",
                                 "helpers.py": "other = 1\n"}), None),   # pytest puts tests/ first: not judged
    ("syntax_error_target", svc({"handlers.py": "from models import x\n", "models.py": "def (:\n"}), None),
    ("star_cycle", svc({"handlers.py": "from a import z\n", "a.py": "from b import *\n", "b.py": "from a import *\n"}),
     None),
    # review F2: a guarded star import of a missing submodule makes the target unknown (was a KeyError)
    ("guarded_star_missing_submodule", svc({"handlers.py": "from pkg import x\n",
                                            "pkg/__init__.py": "try:\n    from .missing import *\nexcept ImportError:\n"
                                                               "    pass\nx = 1\n"}), "main"),
    # review F4a: attributes every module object has
    ("implicit_module_attributes", svc({"handlers.py": "from models import (__name__, __doc__, __file__, __spec__, "
                                                       "__loader__, __package__, __builtins__, __cached__, __dict__)\n"
                                                       "from pkg import __path__\n",
                                        "models.py": "x = 1\n", "pkg/__init__.py": ""}), "main"),
    # review F4b: contextlib.suppress(ImportError | base class) guards like try/except
    ("suppress_guard", svc({"handlers.py": "import contextlib\nfrom contextlib import suppress\n"
                                           "with contextlib.suppress(ImportError):\n    from models import Fast\n"
                                           "with suppress(ModuleNotFoundError, Exception):\n"
                                           "    from models import Faster\n", "models.py": "Slow = 1\n"}), "main"),
    # review F4c: a directory holding only data files is an importable namespace (sub)package
    ("data_only_namespace_dir", svc({"handlers.py": "from pkg import data\nimport pkg.data\n", "pkg/__init__.py": "",
                                     "pkg/data/config.json": "{}\n"}), "main"),
    # review F4d: walrus targets in defaults, annotations, class bases / keywords and lambda defaults
    ("walrus_in_definitions", svc({"handlers.py": "from models import W, A, R, B, M, L, K\n",
                                   "models.py": "def f(x=(W := 1)):\n    return x\n\n\n"
                                                "def g(y: (A := int) = 0) -> (R := int):\n    return y\n\n\n"
                                                "class C((B := object), metaclass=(M := type)):\n    pass\n\n\n"
                                                "h = lambda z=(L := 3): z\n\n\n"
                                                "def k(*, q=(K := 4)):\n    return q\n"}), "main"),
    ("enum_and_dataclass", svc({"handlers.py": "from models import Color, Point\n",
                                "models.py": "import enum\nimport dataclasses\n\n\nclass Color(enum.Enum):\n"
                                             "    RED = 1\n\n\n@dataclasses.dataclass\nclass Point:\n"
                                             "    x: int = 0\n"}), "main"),
]


@pytest.mark.parametrize("name,files,_mod,expected", POSITIVES, ids=[c[0] for c in POSITIVES])
def test_positive_findings(name, files, _mod, expected):
    assert summary(files) == sorted(expected)


@pytest.mark.parametrize("name,files,_mod", NEGATIVES, ids=[c[0] for c in NEGATIVES])
def test_do_no_harm_valid_trees_have_no_finding_and_are_not_written(name, files, _mod):
    before = dict(files)
    assert summary(files) == []
    assert files == before


def _import_in_cpython(tmp_path, files, module):
    root = tmp_path / "svc"
    for p, text in files.items():
        dest = root / p[len(SVC) + 1:]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    # `python -c` puts the cwd (the service dir) first on sys.path, the same root QA's cwd + PYTHONPATH give
    env = hermetic_guard.child_env(extra={"PYTHONDONTWRITEBYTECODE": "1"})
    r = subprocess.run([sys.executable, "-c", f"import {module}"], cwd=str(root), env=env, capture_output=True,
                       text=True, timeout=60)
    return r.returncode, r.stderr


@pytest.mark.parametrize("name,files,module,expect_error",
                         [(c[0], c[1], c[2], True) for c in POSITIVES] +
                         [(c[0], c[1], c[2], False) for c in NEGATIVES if c[2]],
                         ids=[c[0] for c in POSITIVES] + [c[0] for c in NEGATIVES if c[2]])
def test_cpython_agrees(tmp_path, name, files, module, expect_error):
    """The oracle: our fixture code imported by the real interpreter, from the service dir (QA's import root)."""
    code, err = _import_in_cpython(tmp_path, files, module)
    assert (code != 0) is expect_error, err
    if expect_error:
        assert "ImportError" in err or "ModuleNotFoundError" in err, err


def test_live_case_message_names_target_and_where_the_name_is_defined():
    (d,) = found(LIVE)
    assert (d.code, d.severity, d.tool, d.source) == (CODE, "error", "ast", "precommit")
    assert d.file == f"{SVC}/handlers.py" and d.line == 1 and d.symbol == "EventAuditRecord"
    assert f"{SVC}/schemas/__init__.py" in d.message and "ImportError" in d.message
    assert "schemas/events.py" in d.hint and "`from schemas.events import EventAuditRecord`" in d.hint
    assert "re-export it from schemas/__init__.py" in d.hint


def test_shadowed_module_hint_explains_the_package_wins_and_carries_the_definition():
    files = POSITIVES[2][1]
    (d,) = found(files)
    assert "schemas.py, which is never imported" in d.hint and "package schemas/__init__.py" in d.hint
    assert d.snippet is not None and d.snippet.startswith("class EventAuditRecord")


def test_name_defined_nowhere_lists_what_the_target_provides():
    (d,) = found(POSITIVES[1][1])
    assert "No module of apps/svc/ defines `Order`" in d.hint and "User" in d.hint


def test_scope_only_llm_owned_importers_and_unchanged_import_root():
    # a platform-rendered importer is out of scope
    assert summary(LIVE, llm={f"{SVC}/main.py", f"{SVC}/schemas/events.py"}) == []
    # a Procfile that changes the import root: the service is not judged (as V3c-imports)
    moved = dict(LIVE, **{f"{SVC}/Procfile": "web: uvicorn main:app --app-dir src --port $PORT\n"})
    assert summary(moved) == []
    # the plain Procfile keeps the service judged
    plain = dict(LIVE, **{f"{SVC}/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"})
    assert [s for _, _, s in summary(plain)] == ["EventAuditRecord"]


def test_sys_modules_with_literal_third_party_keys_keeps_the_service_judged():
    conftest = ("import sys\nfrom unittest import mock\nsys.modules['google.cloud.firestore'] = mock.MagicMock()\n"
                "mock.patch.dict(sys.modules, {'google.cloud.pubsub_v1': mock.MagicMock()})\n"
                "if 'redis' in sys.modules:\n    pass\n")
    files = dict(LIVE, **{f"{SVC}/tests/conftest.py": conftest})
    assert [s for _, _, s in summary(files)] == ["EventAuditRecord"]
    # a non-literal key, or a local module's key, makes the service not judged
    for line in ("sys.modules[name] = object()\n", "sys.modules['schemas'] = object()\n",
                 "sys.modules.update(other)\n"):
        files = dict(LIVE, **{f"{SVC}/tests/conftest.py": "import sys\nname = 'x'\nother = {}\n" + line})
        assert summary(files) == [], line


def test_f2_guarded_missing_star_target_keeps_the_stack_available_and_passing():
    st = ValidatorStack()
    st.register(LocalImportValidator(), "blocking")
    files = dict(next(c[1] for c in NEGATIVES if c[0] == "guarded_star_missing_submodule"))
    report = st.run(_ctx(files))
    assert report.status == "PASS" and report.tools_unavailable == []


def test_f2_a_non_string_file_value_is_unknown_not_a_crash():
    files = dict(LIVE, **{f"{SVC}/schemas/__init__.py": None})
    assert summary(files) == []


def test_f4b_runtime_imports_suppress_is_exact():
    import ast
    from developer_agent.validators.container import runtime_imports
    src = ("import contextlib\nwith contextlib.suppress(ImportError):\n    import a\n"
           "with contextlib.suppress(KeyError):\n    import b\nwith open('x') as f:\n    import c\n"
           "with suppress(Exception):\n    import d\n")
    names = [n.names[0].name for n in runtime_imports(ast.parse(src)) if isinstance(n, ast.Import)]
    assert names == ["contextlib", "b", "c"]


def test_f3_large_tree_is_fast():
    import time
    files = {f"{SVC}/main.py": MAIN, f"{SVC}/schemas/__init__.py": ""}
    for i in range(150):
        files[f"{SVC}/mod_{i}.py"] = f"from schemas import Missing{i}, Other{i}\n"
    for j in range(60):
        files[f"{SVC}/defs_{j}.py"] = "".join(f"class D{j}_{k}:\n    pass\n\n\n" for k in range(30))
    t0 = time.monotonic()
    out = found(files)
    assert len(out) == 300
    assert time.monotonic() - t0 < 5.0


def test_unjudged_imports_names_imports_whose_target_does_not_parse():
    from developer_agent.validators.local_imports import unjudged_imports
    broken = svc({"handlers.py": "from models import Missing\n", "models.py": "def (:\n"})
    assert (f"{SVC}/handlers.py", 1) in unjudged_imports(broken)
    fixed = dict(broken, **{f"{SVC}/models.py": "Present = 1\n"})
    assert (f"{SVC}/handlers.py", 1) not in unjudged_imports(fixed)
    assert unjudged_imports(LIVE) == set()   # every import of the live case is judged


# ------------------------------------------------------------------------------------------------ wiring
def test_registered_blocking_in_the_step1_stack():
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert VALIDATOR_ID in stack.ids and stack.mode_of(VALIDATOR_ID) == "blocking"


class Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        return {"files": self.responses.pop(0) if self.responses else {}, "envelope_ok": True, "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def _loop(persona, llm_paths):
    st = ValidatorStack()
    st.register(LocalImportValidator(), "blocking")

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st,
                       ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                       attribution={p: "backend_worker" for p in llm_paths}, llm_draft_paths=set(llm_paths),
                       preexisting=set(), repair_fn=persona, model="m", available_providers=["google"])


def test_repair_loop_turns_the_finding_into_a_precise_repair_before_commit():
    draft = dict(LIVE)
    persona = Persona({f"{SVC}/handlers.py": HANDLERS_OK})
    tree, report = RepairLoop(_loop(persona, set(draft))).run(draft)
    assert report.status == "PASS" and tree[f"{SVC}/handlers.py"] == HANDLERS_OK
    (t,) = persona.tasks
    assert t.persona == "backend_worker" and t.files_to_fix == {f"{SVC}/handlers.py": HANDLERS_BAD}
    (diag,) = t.diagnostics
    assert diag["code"] == CODE and diag["line"] == 1
    assert "from schemas.events import EventAuditRecord" in diag["hint"]
    assert "EventAuditRecord" in t.prompt() and "schemas/events.py" in t.prompt()
    assert {k: v for k, v in tree.items() if k != f"{SVC}/handlers.py"} == \
           {k: v for k, v in LIVE.items() if k != f"{SVC}/handlers.py"}   # nothing else touched


def test_clean_tree_passes_without_a_repair_and_is_unchanged():
    draft = svc({"handlers.py": HANDLERS_OK, "schemas/__init__.py": "from .events import EventIn\n",
                 "schemas/events.py": EVENTS})
    persona = Persona()
    tree, report = RepairLoop(_loop(persona, set(draft))).run(draft)
    assert report.status == "PASS" and persona.tasks == [] and tree == draft


def test_f1_a_target_syntax_fix_that_reveals_the_import_is_accepted_then_the_importer_is_repaired():
    from developer_agent.validators.step1 import PythonSyntaxValidator
    draft = svc({"handlers.py": "from models import Missing\n", "models.py": "def (:\n"})
    persona = Persona({f"{SVC}/models.py": "Present = 1\n"}, {f"{SVC}/handlers.py": "from models import Present\n"})
    ctx = _loop(persona, set(draft))
    ctx.stack.register(PythonSyntaxValidator(), "blocking")
    tree, report = RepairLoop(ctx).run(draft)
    assert report.status == "PASS" and len(persona.tasks) == 2
    assert list(persona.tasks[0].files_to_fix) == [f"{SVC}/models.py"]
    assert [x["code"] for x in persona.tasks[1].diagnostics] == [CODE]
    assert list(persona.tasks[1].files_to_fix) == [f"{SVC}/handlers.py"]
    assert tree[f"{SVC}/models.py"] == "Present = 1\n" and tree[f"{SVC}/handlers.py"] == "from models import Present\n"


def test_unfixed_import_blocks_the_commit():
    persona = Persona()   # the model returns nothing
    with pytest.raises(RepairBudgetExhausted) as e:
        RepairLoop(_loop(persona, set(LIVE))).run(dict(LIVE))
    assert [d.code for d in e.value.report.diagnostics] == [CODE]

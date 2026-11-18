"""FD-4AE-c: the container build and the deploy-workspace prep no longer change application code after QA.

Deleted from mcp-servers/terraform/service.py (FD-4AE RT residuals #11-#16):
  #11 AST/regex rewrite of `apps.<svc>.` / `from ..x` imports;
  #12 `alembic/` -> `migrations/` rename + alembic.ini / `.py` string rewrites (a duplicate of the pre-QA gate);
  #13 purge of `__init__.py` in "shielded" dirs (reserved names or any requirement stem);
  #14 purge of a flat `x.py` next to an `x/` dir;
  #15 "Dual Guard" requirements.txt pruning;
  #16 copy of apps/shared|common|contracts and of every root auxiliary dir into each service (build), and the
      same root-dir mirror in prepare_workspace (#16b);
  #17 generation of a missing `__init__.py` (Fable RT F1(a): an init can switch `import x` from the installed
      distribution or a flat module to a local dir; the pre-QA package gate owns init injection).
The real requirement behind #11 moves before QA as the report-only V3c-imports (CONTAINER.IMPORT_OUTSIDE_SERVICE).

Hermetic: no ADC, no network; the build stops at the (mocked) source staging step.
"""
import hermetic_guard  # noqa: F401  (first import)

import io
import os
import sys
import tarfile
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (REPO_ROOT,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fd4g_support import load_tf_service  # noqa: E402


# A valid service whose files hit every deleted trigger. QA runs it with apps/api/ as cwd and PYTHONPATH.
SERVICE = {
    "apps/api/__init__.py": "",
    "apps/api/main.py": (
        "from fastapi import FastAPI\n"
        "from app.routers.items import router\n"
        "from jobs import Item as JobItem  # noqa: F401\n\n"
        "app = FastAPI()\n"
        "app.include_router(router)\n\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return {'status': 'ok'}\n"
    ),
    "apps/api/app/__init__.py": "",
    "apps/api/app/models.py": "class Item:\n    pass\n",
    "apps/api/app/routers/__init__.py": "",
    # #11 rewrote `from ..models` (valid: app.routers.items -> app.models) into `from models` (ImportError)
    "apps/api/app/routers/items.py": (
        "from fastapi import APIRouter\n"
        "from ..models import Item\n\n"
        "router = APIRouter()\n\n"
        "@router.get('/items')\n"
        "def items():\n"
        "    return [Item.__name__]\n"
    ),
    # #11 also rewrote a guarded fallback import line
    "apps/api/jobs.py": (
        "try:\n"
        "    from apps.api.app.models import Item\n"
        "except ImportError:\n"
        "    from app.models import Item\n"
    ),
    # #12 renamed the standard Alembic layout and rewrote alembic.ini and this string
    "apps/api/alembic.ini": "[alembic]\nscript_location = alembic\n",
    "apps/api/alembic/env.py": "from alembic import context  # noqa: F401\n",
    "apps/api/alembic/versions/0001_init.py": "revision = '0001'\ndown_revision = None\n",
    "apps/api/settings.py": "ALEMBIC_TEMPLATE_NOTE = 'see alembic/alembic.ini in the upstream template'\n",
    # #13 purged a package init under any dir named `migrations` (a Django-style migrations package needs it)
    "apps/api/app/migrations/__init__.py": "",
    "apps/api/app/migrations/0001_initial.py": "operations = []\n",
    # #14 deleted `helpers.py` (the module `import helpers` loads: helpers/ has no __init__.py) and then
    # created helpers/__init__.py
    "apps/api/helpers.py": "def slug(s):\n    return s.lower()\n",
    "apps/api/helpers/extra.py": "VALUE = 1\n",
    "apps/api/Procfile": "web: alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}\n",
    "apps/api/.python-version": "3.12\n",
    "apps/api/static/.gitkeep": "",
}
# #16 copied these into apps/api/ (hierarchical and flat)
OUTSIDE = {
    "apps/shared/util.py": "def shared():\n    return 1\n",
    "scripts/seed.py": "print('seed')\n",
    "contracts/__init__.py": "from .schemas import *  # noqa: F401,F403\n",
    "contracts/schemas.py": "class Contract:\n    pass\n",
}


@pytest.fixture
def tf(monkeypatch):
    mod = load_tf_service(monkeypatch)
    import importlib
    settings = sys.modules.get("shared.settings") or importlib.import_module("shared.settings")
    monkeypatch.setattr(settings, "get_platform_settings", lambda *a, **k: None)   # no Firestore (BOM defaults)
    return mod


def _svc(tf, tmp_path):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    return svc


def _write(base, files):
    for rel, text in files.items():
        path = os.path.join(str(base), rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def _tree(base, prefix):
    out = {}
    for root, _, names in os.walk(os.path.join(str(base), prefix)):
        for n in names:
            full = os.path.join(root, n)
            with open(full, "r", encoding="utf-8") as fh:
                out[os.path.relpath(full, str(base)).replace(os.sep, "/")] = fh.read()
    return out


def _build_until_staging(tf, svc, ws):
    """Run _build_and_push_container through every pre-packaging step; return (ok, tarball member -> text)."""
    shipped = {}

    def stage(**kwargs):
        with tarfile.open(fileobj=io.BytesIO(kwargs["payload"]), mode="r:gz") as tar:
            for m in tar.getmembers():
                shipped[m.name] = tar.extractfile(m).read().decode("utf-8")
        raise RuntimeError("stop after packaging (test)")

    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("google.cloud.storage.Client"), \
         patch.object(tf.TerraformService, "_stage_build_source", side_effect=stage):
        ok = svc._build_and_push_container("fd4aec-app", "child", str(ws), "img:tag")
    return ok, shipped


def test_build_ships_the_service_exactly_as_qa_ran_it(tf, tmp_path):
    """Do No Harm (#11-#16): every file of the service is byte-identical after the build, nothing is deleted,
    renamed or vendored in, and the tarball carries exactly those files."""
    ws = tmp_path / "ws"
    _write(ws, {**SERVICE, **OUTSIDE})
    svc = _svc(tf, tmp_path / "base")
    ok, shipped = _build_until_staging(tf, svc, ws)
    assert ok is False and shipped, svc._last_build_error   # only the staging mock stops it
    assert _tree(ws, "apps/api") == SERVICE
    for rel, text in SERVICE.items():
        if rel.endswith(".py"):
            compile(text, rel, "exec")
    shipped_svc = {k: v for k, v in shipped.items() if k.startswith("apps/api/")}
    assert shipped_svc == {k: v for k, v in SERVICE.items() if not k.endswith(".gitkeep")}   # dotfile never-list
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "migrations"))
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "helpers", "__init__.py"))
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "alembic", "__init__.py"))


def test_build_adds_no_package_init(tf, tmp_path):
    """#17 deleted (Fable RT F1(a)): no `__init__.py` is generated anywhere in the service, neither in a plain dir
    (`lib/`) nor next to a flat module (`helpers.py` + `helpers/`)."""
    ws = tmp_path / "ws"
    files = {"apps/api/main.py": "app = None\n", "apps/api/Procfile": "web: uvicorn main:app\n",
             "apps/api/lib/x.py": "X = 1\n", "apps/api/helpers.py": "H = 1\n", "apps/api/helpers/y.py": "Y = 1\n"}
    _write(ws, files)
    _build_until_staging(tf, _svc(tf, tmp_path / "base"), ws)
    tree = {k: v for k, v in _tree(ws, "apps/api").items() if not k.endswith((".python-version", ".gitkeep"))}
    assert tree == files


def test_namespace_dir_named_like_a_transitive_distribution_stays_a_namespace(tf, tmp_path):
    """Fable RT F1 negative test: `yaml/` (no init) with `pyyaml` required. In QA `import yaml` loads PyYAML (a namespace
    dir loses to the installed regular package); an init added after QA would make the container load the empty local
    dir instead. The build adds nothing."""
    ws = tmp_path / "ws"
    files = {"apps/api/main.py": "import yaml\napp = yaml.safe_load('{}')\n",
             "apps/api/Procfile": "web: uvicorn main:app\n",
             "apps/api/yaml/loader.py": "LOCAL = True\n",
             "apps/api/requirements.txt": "pyyaml>=6.0\nfastapi\n"}
    _write(ws, files)
    ok, shipped = _build_until_staging(tf, _svc(tf, tmp_path / "base"), ws)
    assert shipped, "the build must reach packaging"
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "yaml", "__init__.py"))
    assert "apps/api/yaml/__init__.py" not in shipped
    for rel in ("apps/api/main.py", "apps/api/yaml/loader.py", "apps/api/Procfile"):
        assert shipped[rel] == files[rel]


def test_requirements_lines_qa_installed_survive_the_build(tf, tmp_path):
    """#15 dropped `docker` / `config` (fixed scaffold list, even pinned) and any bare name equal to a local stem.
    The BOM step (FD-4AE-b) may still rewrite pins; no requirement NAME may disappear."""
    ws = tmp_path / "ws"
    reqs = "docker==7.1.0\nconfig\nhelpers\nfastapi\n"
    _write(ws, {"apps/api/main.py": "app = None\n", "apps/api/Procfile": "web: uvicorn main:app\n",
                "apps/api/helpers.py": "H = 1\n", "apps/api/requirements.txt": reqs})
    _build_until_staging(tf, _svc(tf, tmp_path / "base"), ws)
    with open(os.path.join(str(ws), "apps", "api", "requirements.txt"), encoding="utf-8") as fh:
        names = {line.strip().split("=")[0].split(">")[0].split("<")[0].strip().lower()
                 for line in fh if line.strip() and not line.strip().startswith("#")}
    assert {"docker", "config", "helpers", "fastapi"} <= names


def test_prepare_workspace_does_not_mirror_root_dirs_into_services(tf, tmp_path):
    """#16b: the deploy-workspace prep no longer copies root dirs (scripts/, contracts/, ...) into apps/<svc>/."""
    svc = _svc(tf, tmp_path / "base")
    files = {"apps/api/main.py": "app = None\n", "apps/api/Procfile": "web: uvicorn main:app\n", **OUTSIDE}
    ws_dir = svc.prepare_workspace("fd4aec-app", "trace-fd4aec", dict(files))
    tree = _tree(ws_dir, "apps/api")
    assert tree["apps/api/main.py"] == "app = None\n"
    for leaked in ("apps/api/scripts/seed.py", "apps/api/seed.py", "apps/api/contracts/schemas.py",
                   "apps/api/schemas.py", "apps/api/contracts/__init__.py"):
        assert leaked not in tree, leaked


# ------------------------------------------------------------------ V3c-imports (pre-QA, report-only)
def _gateway(monkeypatch):
    monkeypatch.syspath_prepend(GATEWAY)
    pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
    from developer_agent.validators import ValidationContext
    from developer_agent.validators.container import ImportRootValidator
    from shared.artifact_ownership import Ownership
    return ValidationContext, ImportRootValidator, Ownership


def _findings(monkeypatch, files):
    ValidationContext, ImportRootValidator, Ownership = _gateway(monkeypatch)
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, draft=dict(files))
    return sorted((d.code, d.file, d.line, d.symbol, d.severity) for d in ImportRootValidator().validate(ctx))


BASE = {"apps/api/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
        "apps/api/requirements.txt": "fastapi\n"}


def test_v3c_imports_reports_imports_that_leave_the_service_root(monkeypatch):
    files = {**BASE,
             "apps/api/main.py": "from apps.api.models import Item\nfrom .config import settings\n",
             "apps/api/models.py": "class Item:\n    pass\n",
             "apps/api/config.py": "settings = None\n",
             "apps/api/routers/__init__.py": "",
             "apps/api/routers/items.py": "from ..models import Item\nimport apps.api.models\n"}
    got = _findings(monkeypatch, files)
    code = "CONTAINER.IMPORT_OUTSIDE_SERVICE"
    assert got == [
        (code, "apps/api/main.py", 1, "apps.api.models", "warning"),
        (code, "apps/api/main.py", 2, ".config", "warning"),
        (code, "apps/api/routers/items.py", 1, "..models", "warning"),
        (code, "apps/api/routers/items.py", 2, "apps.api.models", "warning"),
    ]


def test_v3c_imports_negatives_valid_code_is_not_reported(monkeypatch):
    """Do No Harm for the new check: resolvable relative imports, guarded fallbacks, TYPE_CHECKING imports, an
    `apps` package the service ships, and a Procfile that changes the import root give no finding."""
    files = {**BASE,
             "apps/api/main.py": (
                 "from typing import TYPE_CHECKING\n"
                 "try:\n    from apps.api.models import Item\nexcept ImportError:\n    from models import Item\n"
                 "if TYPE_CHECKING:\n    from apps.api.config import Settings\n"
                 "from app.routers.items import router\n"),
             "apps/api/models.py": "class Item:\n    pass\n",
             "apps/api/app/__init__.py": "",
             "apps/api/app/models.py": "X = 1\n",
             "apps/api/app/routers/__init__.py": "from . import items  # noqa: F401\n",
             "apps/api/app/routers/items.py": "from ..models import X\nrouter = X\n"}
    assert _findings(monkeypatch, files) == []
    shipped_apps = {**BASE, "apps/api/main.py": "from apps.core import run\n",
                    "apps/api/apps/__init__.py": "", "apps/api/apps/core.py": "def run():\n    pass\n"}
    assert _findings(monkeypatch, shipped_apps) == []
    app_dir = {"apps/api/Procfile": "web: uvicorn main:app --app-dir src --port $PORT\n",
               "apps/api/main.py": "from apps.api.models import Item\n"}
    assert _findings(monkeypatch, app_dir) == []


def test_v3c_imports_is_registered_report_only(monkeypatch):
    _gateway(monkeypatch)
    from developer_agent.validators.step1 import build_step1_stack
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V3c-imports") == "report_only"

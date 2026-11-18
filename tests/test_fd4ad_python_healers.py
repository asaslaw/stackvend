"""FD-4AD: the generation-time Python healers that mutated valid apps are deleted or add-only.

Do No Harm (Invariant 1): every valid input below goes through the whole generation-time Python tail
(enforce_container_contract -> verify_and_cure; FD-55 W5 deleted the preflight copies of the add-only requirements /
package passes that ran after them, G26 / G28)
with every input file byte-identical; the only additions are missing `__init__.py` files, a requirements.txt for a Python
service that had none, appended AST-proven requirement lines, and the platform `.python-version` pin. The genuine hazards
the old healers guessed at are the report-only V3d diagnostics. Hermetic: no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent.handler import enforce_container_contract  # noqa: E402
from developer_agent.validators.base import ValidationContext  # noqa: E402
from developer_agent.validators.python_layout import PythonLayoutValidator  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from gatekeeper_agent import requirements_contract as rc  # noqa: E402
from gatekeeper_agent.pypi_catalog import resolve_import_to_pypi  # noqa: E402
from gatekeeper_agent.verifier import SynthesisVerifierAgent  # noqa: E402


def tail(files, pid="prod"):
    f = dict(files)
    enforce_container_contract(f, pid, "cloudrun")
    f, _, _ = SynthesisVerifierAgent(pid).verify_and_cure(f, product_id=pid)
    return f


def v3d(files):
    return sorted((d.code, d.file) for d in PythonLayoutValidator().validate(
        ValidationContext.build(files, ownership=lambda p: None)))


FUTURE_MAIN = (
    "from __future__ import annotations\n"
    "import os\n"
    "from fastapi import FastAPI, Form\n"
    "from pydantic import BaseModel, EmailStr\n"
    "app = FastAPI()\n"
    "@app.get('/health')\n"
    "def health():\n"
    "    return {'ok': True, 'url': 'apps.api.models'}\n"   # a literal that looks like a monorepo path
    "@app.post('/login')\n"
    "def login(user: str = Form(...)):\n"
    "    return {'user': user}\n"
)
VALID_TREES = {
    # the FD22 probe shapes: `__future__` first, exact user pins, a worker Procfile, GCE URI literals, relative imports
    "future_and_pins": {
        "apps/api/main.py": FUTURE_MAIN,
        "apps/api/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
        "apps/api/requirements.txt": ("fastapi==0.115.6\nuvicorn[standard]==0.34.0\npydantic==2.10.4\n"
                                      "python-multipart==0.0.20\nemail-validator==2.2.0\n"),
    },
    "worker": {
        "apps/worker/main.py": "from google.cloud import pubsub_v1\nprint(pubsub_v1)\n",
        "apps/worker/Procfile": "worker: python main.py\n",
        "apps/worker/requirements.txt": "google-cloud-pubsub==2.27.1\n",
    },
    "gce_uris": {
        "apps/vm/ops.py": ("from google.cloud import compute_v1\n"
                           "def iface(net):\n"
                           "    n = compute_v1.NetworkInterface()\n"
                           "    n.network = net if '/' in net else f'global/networks/{net}'\n"
                           "    return n, 'regions/us-central1/subnetworks/default'\n"),
        "apps/vm/requirements.txt": "google-cloud-compute>=1.18.0\n",
    },
    "relative_imports_and_stdlib_named_nested_module": {
        "apps/shop/api/v1/items.py": "from ..models import Item\nfrom . import helpers\n",
        "apps/shop/api/v1/helpers.py": "X = 1\n",
        "apps/shop/api/models.py": "Item = object\n",
        "apps/shop/utils/logging.py": "LEVEL = 'INFO'\n",
        "apps/shop/main.py": "from api.v1 import items\nimport logging\n",
        "apps/shop/requirements.txt": "",
    },
    "alembic_and_local_stems": {
        "apps/billing/alembic.ini": "[alembic]\nscript_location = alembic\n",
        "apps/billing/alembic/env.py": "from alembic import context\n",
        "apps/billing/celery_app.py": "from celery import Celery\napp = Celery()\n",
        "apps/billing/celery.py": "BROKER = 'redis://'\n",     # a local stem equal to a requirement name
        "apps/billing/requirements.txt": "alembic==1.14.0\ncelery==5.4.0\n",
    },
    "node_service": {
        "apps/web/package.json": '{"name": "web"}\n',
        "apps/web/server.js": "console.log(1)\n",
    },
    # ---- the probe inputs (docs/planning/review/probes/fd22-gatekeeper-preflight-qa_{gatekeeper,preflight}.py,
    #      fd21-developer-agent_container_contract.py): each was valid and each used to come out broken
    "probe_fd22_1_stdlib_named_submodule": {
        "apps/api/main.py": "from fastapi import FastAPI\nfrom utils.logging import setup\napp = FastAPI()\nsetup()\n",
        "apps/api/utils/__init__.py": "",
        "apps/api/utils/logging.py": "def setup():\n    return 'configured'\n",
        "apps/api/utils/helpers.py": "from logging import getLogger\nlog = getLogger(__name__)\n",
        "apps/api/requirements.txt": "fastapi\n",
    },
    "probe_fd22_2_celery_and_user_pins": {
        "apps/worker/main.py": "from celery_app import app\n",
        "apps/worker/celery.py": "# conventional celery module name\nfrom celery import Celery\napp = Celery('w')\n",
        "apps/worker/requirements.txt": "celery==5.3.6\npydantic==1.10.13\ngoogle-cloud-storage==2.14.0\n",
    },
    "probe_fd22_3_future_import": {
        "apps/api/main.py": '"""API."""\nfrom __future__ import annotations\nfrom fastapi import FastAPI\napp = FastAPI()\n',
        "apps/api/requirements.txt": "fastapi\n",
    },
    "probe_fd22_3_app_factory": {
        "apps/api/main.py": ("import os\nfrom fastapi import FastAPI\n\n"
                             "def create_app():\n    app = FastAPI(title='x')\n    return app\n\napp = create_app()\n"),
        "apps/api/requirements.txt": "fastapi\n",
    },
    "probe_fd22_4_worker_procfile": {
        "apps/ingest/main.py": ("import time\n\ndef run():\n    while True:\n        time.sleep(1)\n\n"
                                "if __name__ == '__main__':\n    run()\n"),
        "apps/ingest/Procfile": "worker: python main.py\n",
        "apps/ingest/requirements.txt": "google-cloud-pubsub\n",
    },
    "probe_fd22_8_string_literals": {
        "apps/api/main.py": ('API = "https://apps.api.example.com/v1"\n'
                             'CFG = """\nroutes:\n  fallback:\n    target: /home\n"""\n'
                             "DOC = '''\nGET /health -> ok\n'''\n"),
        "apps/api/requirements.txt": "",
    },
    "probe_fd22_pf2_types_submodule": {
        "apps/api/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "apps/api/core/types.py": "Id = int\n",
        "apps/api/core/models.py": "from types import SimpleNamespace\nX = SimpleNamespace(a=1)\n",
        "apps/api/requirements.txt": "fastapi\n",
    },
    "probe_fd22_pf3_root_assets": {
        "apps/api/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "apps/api/requirements.txt": "fastapi\n",
        "frontend/package.json": '{"name": "fe"}\n',
        "tools/config.py": "X = 1\n",
    },
    "probe_fd21_12_pins_and_node": {
        "apps/todo/main.py": ('import os\nfrom fastapi import FastAPI\n\napp = FastAPI(title=os.getenv("TITLE", "Todo"), '
                              'version="1.0")\n\n@app.get("/")\ndef root():\n    return {"ok": True}\n'),
        "apps/todo/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
        "apps/todo/requirements.txt": "pydantic==1.10.13\nfastapi==0.99.1\nuvicorn[standard]==0.23.0\n",
        "apps/web/server.js": "require('http').createServer((q,s)=>s.end('ok')).listen(process.env.PORT)",
        "apps/web/Procfile": "web: node server.js\n",
    },
}


@pytest.mark.parametrize("name", sorted(VALID_TREES))
def test_valid_trees_are_byte_identical_through_the_python_tail(name):
    files = VALID_TREES[name]
    out = tail(files)
    for path, text in files.items():
        assert out.get(path) == text, path
    for path in sorted(set(out) - set(files)):
        assert path.endswith(("/__init__.py", ".python-version")) or path == "apps/__init__.py", path
    assert not any(p.endswith("/requirements.txt") and p not in files for p in out if p.startswith("apps/web/"))
    # nothing is vendored or created outside the package / platform-pin rows (HB-32 flat copies, Node requirements)
    assert not any(p.endswith(("package.json", "config.py")) and p not in files for p in out)


@pytest.mark.parametrize("name", sorted(VALID_TREES))
def test_the_tail_is_idempotent(name):
    """GK-5 (CURE_WOULD_CHANGE_TREE): re-running verify_and_cure on the tail's output is a no-op."""
    out = tail(VALID_TREES[name])
    again, _, _ = SynthesisVerifierAgent("prod").verify_and_cure(dict(out), product_id="prod")
    assert again == out


def test_alembic_package_is_never_given_an_init():
    out = tail(VALID_TREES["alembic_and_local_stems"])
    assert "apps/billing/alembic/__init__.py" not in out
    assert "apps/billing/migrations/env.py" not in out


# ------------------------------------------------------------------------------------- add-only requirements contract
def test_contract_appends_only_proven_missing_needs_and_keeps_bytes():
    files = {
        "apps/api/main.py": ("import yaml\nfrom fastapi import FastAPI, UploadFile\nfrom fastapi.templating import "
                             "Jinja2Templates\nfrom pydantic import EmailStr\nimport json, os\n"),
        "apps/api/tests/test_main.py": "import pytest\nfrom fastapi.testclient import TestClient\n",
        "apps/api/Procfile": "web: alembic upgrade head && gunicorn -k uvicorn.workers.UvicornWorker main:app\n",
        "apps/api/requirements.txt": "FastAPI==0.115.6  # pinned\nPyYAML",          # no trailing newline
    }
    out, actions = rc.append_missing_requirements(files)
    assert out["apps/api/requirements.txt"] == (
        "FastAPI==0.115.6  # pinned\nPyYAML\n"
        "email-validator>=2.0.0\ngunicorn>=22.0.0\nhttpx>=0.27.0\njinja2>=3.1.5\npydantic>=2.6.0\npytest>=8.0.0\n"
        "python-multipart>=0.0.20\nuvicorn[standard]>=0.28.0\n")
    assert len(actions) == 1
    assert {k: v for k, v in out.items() if k != "apps/api/requirements.txt"} == \
        {k: v for k, v in files.items() if k != "apps/api/requirements.txt"}


def test_contract_matches_canonical_names_and_never_duplicates():
    files = {"apps/a/main.py": "import yaml\nfrom google.cloud import storage\n",
             "apps/a/requirements.txt": "pyyaml>=6\nGoogle_Cloud.Storage==2.19.0\n"}
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_contract_skips_local_modules_stdlib_relative_and_unparseable_files():
    files = {
        "apps/a/main.py": "import redis\nimport json\nfrom . import x\nfrom .cache import get\n",
        "apps/a/redis.py": "X = 1\n",          # a local module named like a catalog import: local wins
        "apps/a/broken.py": "import pandas\ndef f(:\n",   # PY.SYNTAX: its imports are read after the repair
        "apps/a/requirements.txt": "",
    }
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_contract_creates_requirements_for_python_service_only():
    files = {"apps/py/main.py": "import requests\n", "apps/node/index.js": "1\n", "apps/shared/util.py": "import yaml\n"}
    out, _ = rc.append_missing_requirements(files)
    assert out["apps/py/requirements.txt"] == "requests>=2.31.0\n"
    assert "apps/node/requirements.txt" not in out and "apps/shared/requirements.txt" not in out


@pytest.mark.parametrize("procfile, expected", [
    ("web: uvicorn main:app --port $PORT\n", {"uvicorn[standard]>=0.28.0"}),
    ("web: python -u -m hypercorn main:app\n", {"hypercorn>=0.16.0"}),
    ("web: /usr/bin/gunicorn --worker-class=uvicorn.workers.UvicornWorker main:app\n",
     {"gunicorn>=22.0.0", "uvicorn[standard]>=0.28.0"}),
    ("worker: python main.py\n# web: uvicorn x:app\n", set()),
    ("web: uvicorn 'unterminated\n", set()),
    ("not a process line\n", set()),
    # FDAD-5 (RT F4): exact wrapper tokens in front of the launcher
    ("web: exec uvicorn main:app --port $PORT\n", {"uvicorn[standard]>=0.28.0"}),
    ("web: env PORT=8080 LOG=info uvicorn main:app\n", {"uvicorn[standard]>=0.28.0"}),
    ("web: PYTHONUNBUFFERED=1 exec hypercorn main:app\n", {"hypercorn>=0.16.0"}),
    ('web: sh -c "uvicorn main:app --port $PORT"\n', {"uvicorn[standard]>=0.28.0"}),
    ("web: bash -e -c 'alembic upgrade head && exec gunicorn main:app'\n", {"gunicorn>=22.0.0"}),
    ("web: bash start.sh\n", set()),                 # a script: not read
    ("web: env\n", set()),
    ("web: sh -c 'uvicorn main:app\n", set()),       # the -c argument does not split
    ("web: echo uvicorn\n", set()),                  # a token that merely names a launcher is not a launch
])
def test_procfile_launcher_needs(procfile, expected):
    assert rc.procfile_needs(procfile) == expected


def test_declared_names_follow_the_pip_comment_rule():
    text = "# comment\nfoo==1 # trailing\nbar#not-a-comment\n-r other.txt\n--index-url https://x\nbad line ===\n"
    assert rc.declared_names(text) == {"foo"}


# ------------------------------------------------------------------------------------------------ V3d (report-only)
def test_v3d_codes_on_the_hazards_the_old_healers_rewrote():
    files = {
        "apps/s/secrets.py": "TOKEN = 1\n",               # stdlib shadow at the service root
        "apps/s/email/__init__.py": "",                   # stdlib-named regular package at the root
        "apps/s/utils/logging.py": "X = 1\n",             # nested: not a shadow
        "apps/s/schemas.py": "A = 1\n",                   # module beside a package of the same name
        "apps/s/schemas/__init__.py": "",
        "apps/s/schemas/event.py": "B = 1\n",
        # import-root facts are V3c-imports' CONTAINER.IMPORT_OUTSIDE_SERVICE (FD-4AE-c RT F2), not V3d
        "apps/s/main.py": "from apps.s.models import M\nimport apps.s.config\nfrom .x import y\n",
        "apps/s/requirements.txt": "schemas\nfastapi\n",
    }
    assert v3d(files) == [
        ("PY.MODULE_PACKAGE_CONFLICT", "apps/s/schemas.py"),
        ("PY.STDLIB_SHADOWED", "apps/s/email/__init__.py"),
        ("PY.STDLIB_SHADOWED", "apps/s/secrets.py"),
        ("REQ.LOCAL_MODULE_NAME", "apps/s/requirements.txt"),
    ]


def test_v3d_is_silent_on_a_valid_service():
    assert v3d(VALID_TREES["relative_imports_and_stdlib_named_nested_module"]) == []
    assert v3d({"apps/s/apps/__init__.py": "", "apps/s/main.py": "from apps import x\n"}) == []   # own `apps` package


def test_v3d_is_registered_report_only():
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V3d") == "report_only"


# ------------------------------------------------------------------------------------- FDAD-5 (RT F4)
def test_one_procfile_parser_for_v3c_and_the_contract():
    """Gate 5: V3c and the requirements contract use the same parse_command / parse_procfile objects."""
    from developer_agent.validators import container
    from gatekeeper_agent import procfile
    assert container.parse_command is procfile.parse_command is rc.parse_command
    assert container.parse_procfile is procfile.parse_procfile is rc.parse_procfile


def test_v3c_now_judges_a_wrapped_launcher():
    """`web: exec uvicorn ...` used to be `unknown` (not judged) in V3c too; now the wrapped uvicorn is parsed."""
    from developer_agent.validators.container import parse_command
    launch = parse_command(["exec", "uvicorn", "main:app", "--port", "8000"])
    assert (launch.kind, launch.server, launch.target, launch.port_ok) == ("server", "uvicorn", "main:app", False)
    assert parse_command(["sh", "-c", "uvicorn main:app --port $PORT"]).port_ok is True
    assert parse_command(["bash", "start.sh"]).kind == "unknown"
    assert parse_command(["alembic", "upgrade", "head", "&&", "uvicorn", "main:app"]).kind == "unknown"   # unchanged


@pytest.mark.parametrize("src, spec", [
    ("from google.oauth2 import id_token\n", "google-auth>=2.28.0"),
    ("import google.api_core.exceptions\n", "google-api-core>=2.17.0"),
    ("from google.cloud.sql.connector import Connector\n", "cloud-sql-python-connector>=1.9.0"),
    ("from googleapiclient.discovery import build\n", "google-api-python-client>=2.100.0"),
])
def test_catalog_rows_the_base_pins_used_to_hide(src, spec):
    out, _ = rc.append_missing_requirements({"apps/a/main.py": src, "apps/a/requirements.txt": ""})
    assert out["apps/a/requirements.txt"] == spec + "\n"
    # Do No Harm: already declared (any pin, any spelling) -> byte-identical
    name = spec.split(">=")[0]
    declared = {"apps/a/main.py": src, "apps/a/requirements.txt": f"{name.upper()}==1.0.0\n"}
    again, actions = rc.append_missing_requirements(declared)
    assert again == declared and actions == []


def test_wrapped_launcher_already_declared_is_byte_identical():
    files = {"apps/a/main.py": "app = None\n", "apps/a/Procfile": 'web: sh -c "exec uvicorn main:app"\n',
             "apps/a/requirements.txt": "uvicorn==0.34.0\n"}
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


# REQUIREMENTS-GOOGLE-AUTH-REQUESTS: google-auth declares `requests` only as an extra, so these imports fail at
# `import main` unless the service's requirements.txt names it.
_GOOGLE_AUTH_REQUESTS_IMPORTS = [
    "from google.auth.transport import requests\n",
    "from google.auth.transport import requests as google_requests\n",
    "from google.auth.transport.requests import Request\n",
    "from google.auth.transport.requests import AuthorizedSession\n",
    "from google.auth.transport.requests import Request, AuthorizedSession\n",
    "import google.auth.transport.requests\n",
    "import google.auth.transport.requests as tr\n",
    "def f():\n    from google.auth.transport.requests import Request\n    return Request()\n",
    "from google.auth import compute_engine\n",
    "from google.auth.compute_engine import IDTokenCredentials\n",
    "from google.auth.compute_engine import _metadata\n",
    "from google.auth.compute_engine.credentials import Credentials\n",
    "from google.auth.compute_engine._metadata import get_project_id\n",
    "import google.auth.compute_engine\n",
    "import google.auth.compute_engine.credentials\n",
]


@pytest.mark.parametrize("src", _GOOGLE_AUTH_REQUESTS_IMPORTS)
def test_google_auth_requests_imports_append_the_pin(src):
    files = {"apps/a/main.py": src, "apps/a/requirements.txt": "google-auth>=2.28.0\n"}
    out, actions = rc.append_missing_requirements(files)
    assert out["apps/a/requirements.txt"] == "google-auth>=2.28.0\nrequests>=2.31.0\n"
    assert len(actions) == 1


def test_google_auth_requests_pin_is_the_catalog_row():
    assert set(rc.IMPLIED_BY_IMPORTED_MODULE.values()) == {resolve_import_to_pypi("requests")}


@pytest.mark.parametrize("src", _GOOGLE_AUTH_REQUESTS_IMPORTS)
@pytest.mark.parametrize("requirements", [
    "google-auth\nrequests\n",
    "google-auth\nrequests==2.32.3\n",
    "google-auth\nRequests>=2.0  # pinned\n",
    "google-auth\nrequests[socks]>=2.31.0\n",
    'google-auth\nrequests>=2.31.0; python_version >= "3.8"\n',
    "google-auth\nrequests @ https://example.invalid/requests-2.32.3-py3-none-any.whl\n",
    "google-auth\nrequests",                    # no trailing newline: the bytes stay as they are
    "google-auth[requests]>=2.28.0\n",
    "google_auth[Requests]==2.61.0\n",
    "Google.Auth[aiohttp,requests]\n",
    "google-auth[aiohttp]>=2.28.0",
])
def test_negative_requests_already_declared_is_byte_identical(src, requirements):
    files = {"apps/a/main.py": src, "apps/a/requirements.txt": requirements}
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


@pytest.mark.parametrize("extra, covers", [("requests", True), ("aiohttp", True), ("reauth", False), ("grpc", False)])
def test_installed_by_extra_matches_only_extras_that_install_requests(extra, covers):
    assert rc.installed_by_declared_extras(f"google-auth[{extra}]>=2.28.0\n") == ({"requests"} if covers else set())


def test_an_extra_of_another_distribution_does_not_declare_requests():
    text = "uvicorn[requests]\nnot a requirement [requests]\n# google-auth[requests]\n"
    assert rc.installed_by_declared_extras(text) == set()


def test_declared_names_do_not_count_an_extra_as_a_declared_distribution():
    # the verifier's `installed` set keeps reading only the names the lines hold
    assert rc.declared_names("google-auth[requests]>=2.28.0\n") == {"google-auth"}


def test_installed_by_extra_rows_match_the_installed_package_metadata():
    from importlib.metadata import requires

    from packaging.requirements import Requirement
    reqs = [Requirement(r) for r in requires("google-auth")]
    for (dist, extra), installed in rc.INSTALLED_BY_EXTRA.items():
        assert dist == "google-auth"
        assert any(rc.canonical_name(r.name) == installed and r.marker is not None
                   and r.marker.evaluate({"extra": extra}) for r in reqs), extra
    # the premise of the fix: google-auth alone does not install requests
    assert not any(rc.canonical_name(r.name) == "requests" and (r.marker is None or r.marker.evaluate({"extra": ""}))
                   for r in reqs)


@pytest.mark.parametrize("src", [
    "import google.auth\n",
    "from google.auth import default\n",
    "from google.auth import transport\n",
    "from google.auth.transport import grpc\n",
    "from google.auth.transport import urllib3\n",
    "import google.auth.transport\n",
    "from google.auth.transport._http_client import Request\n",
    "from google.auth.exceptions import DefaultCredentialsError\n",
    "from google.oauth2 import id_token, service_account\n",
    "import google.oauth2.credentials\n",
])
def test_negative_unrelated_google_auth_imports_add_no_requests(src):
    files = {"apps/a/main.py": src, "apps/a/requirements.txt": "google-auth>=2.28.0\n"}
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_a_local_google_package_is_not_google_auth():
    src = "from google.auth.transport import requests\nimport google.auth.transport.requests\n"
    files = {"apps/a/main.py": src, "apps/a/google/__init__.py": "", "apps/a/requirements.txt": ""}
    out, actions = rc.append_missing_requirements(files)
    assert out == files and actions == []


def test_google_auth_requests_reads_the_root_tests_of_a_single_service():
    files = {"apps/a/main.py": "app = None\n", "tests/test_a.py": "from google.auth.transport.requests import Request\n",
             "apps/a/requirements.txt": "google-auth>=2.28.0\n"}
    out, _ = rc.append_missing_requirements(files)
    assert out["apps/a/requirements.txt"] == "google-auth>=2.28.0\nrequests>=2.31.0\n"

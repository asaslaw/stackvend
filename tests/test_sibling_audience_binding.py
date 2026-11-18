"""SIBLING-AUDIENCE-BINDING (option A, docs/implemented/sibling-audience-binding-plan.md).

For an `http` edge the caller's `<BASE>_AUDIENCE` holds the one fixed ID-token audience the callee's own non-test code
verifies (ast facts: the verifying API resolved through imports, the audience resolved to one str constant). Every
other case renders byte-identical to today's `vt.edge_env` binding (Invariant 1): each negative case below compares
the new render with the render that has the audience step switched off. Hermetic, no I/O."""
import hermetic_guard  # noqa: F401  (first import)

import logging
import os
import sys
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt", pytrace=False)

from developer_agent import audience_facts as af  # noqa: E402
from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF  # noqa: E402
from developer_agent.topology_wiring import topology_contract_rule, topology_env_vars  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

AUD = "https://service-b.orders.example"
KEY = "CORE_PROCESSOR_AUDIENCE"
URI = "module.compute_core_processor.service_uri"
CALLEE = "apps/core-processor/"

# Minimal reproduction of example 02's shape (ex02-1109b, step 0): the caller reads the key through a pydantic-settings
# field whose default is the fixed audience; the callee verifies a module-level annotated constant.
EX02_CALLER_CONFIG = '''from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    core_processor_url: str = Field(default="http://localhost:8081", alias="CORE_PROCESSOR_URL")
    core_processor_audience: str = Field(default="https://service-b.orders.example", alias="CORE_PROCESSOR_AUDIENCE")
'''
EX02_CALLEE_AUTH = '''from google.auth.transport import requests
from google.oauth2 import id_token

AUDIENCE: str = "https://service-b.orders.example"
_request_adapter = requests.Request()


def verify(token: str) -> dict:
    payload = id_token.verify_oauth2_token(token, _request_adapter, audience=AUDIENCE)
    return payload
'''
CALLEE_MAIN = "from fastapi import FastAPI\n\napp = FastAPI()\n"


def _vt(edges=(("api-gateway", "core-processor", "http"),), services=None, primary="api-gateway"):
    services = services or [("api-gateway", "cloudrun"), ("core-processor", "cloudrun")]
    raw = {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
           "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges], "resources": []}
    vt, diags = validate_service_topology(raw, product_id="orders")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def _tree(callee_files, caller_config=EX02_CALLER_CONFIG):
    files = {CUSTOM_TF: "", "apps/api-gateway/config.py": caller_config,
             "apps/api-gateway/main.py": "from config import Settings\nsettings = Settings()\n",
             CALLEE + "main.py": CALLEE_MAIN}
    files.update({CALLEE + rel: text for rel, text in callee_files.items()})
    return files


def _render(vt, files, service="api-gateway", allow_unauthenticated=True):
    """ex02 is PUBLIC_APP (`allow_unauthenticated=True`); the private and unknown modes are tested below."""
    return topology_env_vars(vt, service, files[CUSTOM_TF], files, caller_service=None,
                             allow_unauthenticated=allow_unauthenticated)


def _render_today(vt, files, service="api-gateway", allow_unauthenticated=True):
    """The render with the audience step switched off: today's output on the same tree."""
    with patch.object(af, "edge_audience_decisions", return_value=[]):
        return _render(vt, files, service, allow_unauthenticated)


def _auth(audience_expr="AUDIENCE", header="", extra=""):
    return (f"from google.auth.transport import requests\nfrom google.oauth2 import id_token\n{header}\n"
            f"def verify(token):\n    return id_token.verify_oauth2_token(token, requests.Request(), "
            f"audience={audience_expr})\n{extra}")


# ------------------------------------------------------------------------------------------------- positive
def test_ex02_shape_binds_the_fixed_literal():
    vt = _vt()
    files = _tree({"auth.py": EX02_CALLEE_AUTH})
    env, today = _render(vt, files), _render_today(vt, files)
    assert today[KEY] == URI == vt.edge_env("api-gateway")[KEY]
    assert env[KEY] == f'"{AUD}"'
    assert env["CORE_PROCESSOR_URL"] == URI
    assert {k: v for k, v in env.items() if k != KEY} == {k: v for k, v in today.items() if k != KEY}
    rendered = te.format_hcl_env_vars(env)
    assert f'"{KEY}" = "{AUD}"' in rendered
    body = hcl2.loads(f"x = {rendered}\n")["x"]
    assert AUD in str(body)


def test_ex02_shape_through_the_primary_and_secondary_render_sites():
    from developer_agent.handler import DeveloperAgent
    vt = _vt()
    files = _tree({"auth.py": EX02_CALLEE_AUTH})
    env, _ = DeveloperAgent._topology_primary_overrides(vt, "", files, True)
    assert env[KEY] == f'"{AUD}"'
    for private in (False, None):   # PRIVATE_IAM / PRIVATE_IAP, or the mode not passed
        assert DeveloperAgent._topology_primary_overrides(vt, "", files, private)[0][KEY] == URI
    # secondary caller -> secondary callee (terraform_engine render site)
    vt3 = _vt(edges=(("web", "api-gateway", "http"), ("api-gateway", "core-processor", "http")),
              services=[("web", "cloudrun"), ("api-gateway", "cloudrun"), ("core-processor", "cloudrun")],
              primary="web")
    files3 = _tree({"auth.py": EX02_CALLEE_AUTH})
    files3["apps/web/main.py"] = "x = 1\n"
    te.reconcile_multi_service_declarations(
        files=files3, product_id="orders", spec_text="", archetype=vt3.archetype, allow_unauthenticated=True,
        assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF], target_services=list(vt3.names), topology=vt3)
    mods = {}
    for m in hcl2.loads(files3[te.SERVICES_TF]).get("module", []):
        mods.update(m)
    gateway_env = str(mods["compute_api_gateway"]["env_vars"])
    assert AUD in gateway_env and "module.compute_core_processor.service_uri" in gateway_env   # URL stays
    assert AUD not in str(mods["compute_core_processor"].get("env_vars", ""))


def test_caller_reading_the_key_without_a_default_gets_the_literal_too():
    vt = _vt()
    files = _tree({"auth.py": EX02_CALLEE_AUTH},
                  caller_config='import os\nAUDIENCE = os.environ["CORE_PROCESSOR_AUDIENCE"]\n')
    assert _render(vt, files)[KEY] == f'"{AUD}"'


@pytest.mark.parametrize("callee_files", [
    {"auth.py": _auth(f'"{AUD}"')},                                                      # literal argument
    {"auth.py": _auth("AUDIENCE", header=f'AUDIENCE = "{AUD}"\n')},                      # Assign
    {"auth.py": _auth("AUDIENCE", header=f'_A = "{AUD}"\nAUDIENCE: str = _A\n')},        # name chain
    {"auth.py": _auth("AUDIENCE", header="from config import AUDIENCE\n"),
     "config.py": f'AUDIENCE = "{AUD}"\n'},                                              # same-service import
    {"app/__init__.py": "", "app/auth.py": _auth("AUD", header="from .settings import AUDIENCE as AUD\n"),
     "app/settings.py": f'AUDIENCE: str = "{AUD}"\n'},                                    # relative import
    {"auth.py": ("from google.oauth2.id_token import verify_token as vt\nfrom google.auth.transport import requests\n"
                 f'AUDIENCE = "{AUD}"\n\ndef verify(t):\n    return vt(t, requests.Request(), AUDIENCE)\n')},
    {"auth.py": ("import google.oauth2.id_token\nimport google.auth.transport.requests\n"
                 f'AUD = "{AUD}"\n\ndef verify(t):\n    return google.oauth2.id_token.verify_oauth2_token('
                 "t, google.auth.transport.requests.Request(), audience=AUD)\n")},
    {"auth.py": ("from google.auth import jwt\n"
                 f'AUD = "{AUD}"\n\ndef verify(t, certs):\n    return jwt.decode(t, certs=certs, audience=AUD)\n')},
    {"auth.py": EX02_CALLEE_AUTH, "tests/test_auth.py": _auth('"https://other.example"'),
     "test_more.py": _auth('"https://third.example"')},                                  # tests never count
    {"auth.py": EX02_CALLEE_AUTH, "other.py": "from os.path import *\n\nx = join('a', 'b')\n"},   # unrelated star
    {"auth.py": EX02_CALLEE_AUTH, "schemas/__init__.py": "from .models import *\n",              # recorded 02 shape
     "schemas/models.py": "from pydantic import BaseModel\n\n\nclass Order(BaseModel):\n    id: str\n",
     "routes.py": "from schemas import Order\nfrom auth import verify\n\n\ndef h(t):\n    verify(t)\n    "
                  "return Order(id='1')\n"},
    {"auth.py": _auth(f'"{AUD}"'), "admin.py": ("from utils import id_token\nfrom google.auth.transport import "
                                                f'requests\n\n\ndef v(t):\n    return id_token.verify_token(t, '
                                                f'requests.Request(), audience="{AUD}")\n'),
     "utils.py": "from google.oauth2 import id_token\n"},                                # re-export, same literal
    {"auth.py": EX02_CALLEE_AUTH, "vendor/README.md": "x\n",                             # a module it does not ship
     "admin.py": "import vendor\nfrom .missing import Base\n\n\nclass A(Base):\n    pass\n\n\n"
                 "def v(t):\n    return vendor.check(t)\n"},
])
def test_supported_callee_forms_bind_the_literal(callee_files):
    vt = _vt()
    fact = af.callee_audience_fact(_tree(callee_files), "core-processor")
    assert (fact.outcome, fact.literal) == (af.LITERAL, AUD), fact
    assert af.callee_literal_audience(_tree(callee_files), "core-processor") == AUD
    assert _render(vt, _tree(callee_files))[KEY] == f'"{AUD}"'


def test_the_binding_is_logged_as_a_typed_decision(caplog):
    vt = _vt()
    files = _tree({"auth.py": EX02_CALLEE_AUTH})
    env = topology_env_vars(vt, "api-gateway", "", files, caller_service=None, allow_unauthenticated=True)
    (d,) = af.edge_audience_decisions(vt, "api-gateway", {**env, KEY: URI}, files, allow_unauthenticated=True)
    assert (d.caller, d.callee, d.env_key, d.value, d.fact.outcome) == (
        "api-gateway", "core-processor", KEY, f'"{AUD}"', af.LITERAL)
    with caplog.at_level(logging.INFO, logger="castor-audience-facts"):
        _render(vt, files)
    assert any("SIBLING_AUDIENCE_BINDING" in r.getMessage() for r in caplog.records)


# ------------------------------------------------------------------------------------------------- negative
RUNTIME_URL = '''import os
import requests as http
from google.auth.transport import requests
from google.oauth2 import id_token


def _own_url():
    region = http.get("http://metadata.google.internal/computeMetadata/v1/instance/region",
                      headers={"Metadata-Flavor": "Google"}).text
    return f"https://{os.environ['K_SERVICE']}-{region}.run.app"


def verify(token):
    return id_token.verify_oauth2_token(token, requests.Request(), audience=_own_url())
'''

NEGATIVE = {
    "no verify call": ({"auth.py": "def verify(token):\n    return {}\n"}, af.NO_VERIFY_CALL),
    "non-python files only besides main.py": ({"index.js": "module.exports = {}\n"}, af.NO_VERIFY_CALL),
    "runtime-computed audience (old 02)": ({"auth.py": RUNTIME_URL}, af.UNRESOLVED),
    "audience list": ({"auth.py": _auth(f'["{AUD}", "https://b.example"]')}, af.UNRESOLVED),
    "one-element audience list": ({"auth.py": _auth(f'["{AUD}"]')}, af.UNRESOLVED),
    "two different literals": ({"auth.py": _auth(f'"{AUD}"'), "admin.py": _auth('"https://admin.example"')},
                               af.CONFLICTING),
    "literal only in tests": ({"auth.py": RUNTIME_URL, "tests/test_auth.py": _auth(f'"{AUD}"'),
                               "auth_test.py": _auth(f'"{AUD}"'), "conftest.py": _auth(f'"{AUD}"')}, af.UNRESOLVED),
    "literal only in tests, no verify in code": ({"tests/test_auth.py": _auth(f'"{AUD}"')}, af.NO_VERIFY_CALL),
    "parse error": ({"auth.py": EX02_CALLEE_AUTH, "broken.py": "def x(:\n"}, af.PARSE_ERROR),
    "no audience argument": ({"auth.py": _auth("None")}, af.UNRESOLVED),
    "audience omitted": ({"auth.py": ("from google.auth.transport import requests\nfrom google.oauth2 import id_token"
                                      "\n\ndef verify(t):\n    return id_token.verify_oauth2_token(t, requests.Request())"
                                      "\n")}, af.UNRESOLVED),
    "name assigned twice": ({"auth.py": _auth("AUDIENCE", header=f'AUDIENCE = "{AUD}"\nAUDIENCE = "https://x.example"\n')},
                            af.UNRESOLVED),
    # SIBLING-AUDIENCE-GETENV-DEFAULT: a name from env WITH a default now binds unless the platform sets the name
    # (tests/test_sibling_audience_getenv_default.py); without a default it stays unresolved:
    "name from env without a default": ({"auth.py": _auth("AUDIENCE", header='import os\nAUDIENCE = os.getenv("AUD")\n')},
                                        af.UNRESOLVED),
    "function-local name": ({"auth.py": ("from google.auth.transport import requests\nfrom google.oauth2 import id_token"
                                         f'\n\ndef verify(t):\n    aud = "{AUD}"\n    return id_token.verify_oauth2_token('
                                         "t, requests.Request(), audience=aud)\n")}, af.UNRESOLVED),
    "global rebinding": ({"auth.py": _auth("AUDIENCE", header=f'AUDIENCE = "{AUD}"\n',
                                           extra="\ndef reset(v):\n    global AUDIENCE\n    AUDIENCE = v\n")},
                         af.UNRESOLVED),
    "import from a module the callee does not ship": ({"auth.py": _auth("AUDIENCE", header="from settings import AUDIENCE\n")},
                                                      af.UNRESOLVED),
    "attribute of an imported module": ({"auth.py": _auth("config.AUDIENCE", header="import config\n"),
                                         "config.py": f'AUDIENCE = "{AUD}"\n'}, af.UNRESOLVED),
    "IAP verify_token with certs_url": ({"auth.py": (
        "from google.auth.transport import requests\nfrom google.oauth2 import id_token\n"
        'IAP_AUD = "/projects/123/global/backendServices/456"\n\n\ndef v(t):\n    return id_token.verify_token('
        't, requests.Request(), audience=IAP_AUD, certs_url="https://www.gstatic.com/iap/verify/public_key")\n')},
        af.UNRESOLVED),
    "IAP verify_token with a positional certs_url": ({"auth.py": (
        "from google.auth.transport import requests\nfrom google.oauth2 import id_token\n\n\ndef v(t):\n    return "
        'id_token.verify_token(t, requests.Request(), "/projects/1/global/backendServices/2", '
        '"https://www.gstatic.com/iap/verify/public_key")\n')}, af.UNRESOLVED),
    "verifying module aliased by value": ({"b.py": EX02_CALLEE_AUTH, "auth.py": (
        "from google.auth.transport import requests\nfrom google.oauth2 import id_token\nverifier = id_token\n\n\n"
        "def v(t, compute):\n    return verifier.verify_oauth2_token(t, requests.Request(), audience=compute())\n")},
        af.UNRESOLVED),
    "verifier reached by getattr": ({"b.py": EX02_CALLEE_AUTH, "auth.py": (
        "from google.auth.transport import requests\nfrom google.oauth2 import id_token\n\n\ndef v(t):\n    return "
        'getattr(id_token, "verify_oauth2_token")(t, requests.Request(), audience="https://other.example")\n')},
        af.UNRESOLVED),
    "verifying package aliased by value": ({"b.py": EX02_CALLEE_AUTH, "auth.py": (
        "import google.oauth2.id_token\nG = google.oauth2\n")}, af.UNRESOLVED),
    "verifier aliased": ({"auth.py": ("from google.oauth2 import id_token\n_v = id_token.verify_oauth2_token\n"
                                      f'\n\ndef verify(t, r):\n    return _v(t, r, audience="{AUD}")\n')}, af.UNRESOLVED),
    "star arguments": ({"auth.py": _auth("AUDIENCE", header=f'AUDIENCE = "{AUD}"\nKW = {{}}\n').replace(
        "audience=AUDIENCE)", "audience=AUDIENCE, **KW)")}, af.UNRESOLVED),
    "optional import (try/except None)": ({"auth.py": EX02_CALLEE_AUTH.replace(
        "from google.oauth2 import id_token\n",
        "try:\n    from google.oauth2 import id_token\nexcept ImportError:\n    id_token = None\n")}, af.UNRESOLVED),
    "re-exported verifier with another literal": ({"auth.py": EX02_CALLEE_AUTH, "utils.py": "from google.oauth2 import "
                                                   "id_token\n", "admin.py": _auth('"https://admin.example"').replace(
                                                       "from google.oauth2 import id_token", "from utils import id_token")},
                                                  af.CONFLICTING),
    "star-imported verifier with another literal": ({"auth.py": EX02_CALLEE_AUTH, "admin.py": (
        "from google.oauth2.id_token import *\n\n\ndef v(t, r):\n    return verify_oauth2_token(t, r, "
        "audience='https://admin.example')\n")}, af.CONFLICTING),
    "verifier re-exported by an in-tree star import": ({"auth.py": EX02_CALLEE_AUTH,
                                                        "pkg/__init__.py": "from .impl import *\n",
                                                        "pkg/impl.py": "from google.oauth2 import id_token\n",
                                                        "admin.py": ("from pkg import id_token\n\n\ndef v(t, r):\n    "
                                                                     "return id_token.verify_oauth2_token(t, r, "
                                                                     "audience='https://admin.example')\n")},
                                                       af.CONFLICTING),
    "verifier imported through a global": ({"auth.py": EX02_CALLEE_AUTH, "admin.py": (
        "def setup():\n    global id_token\n    from google.oauth2 import id_token\n\n\ndef v(t, r):\n    return "
        "id_token.verify_oauth2_token(t, r, audience='https://admin.example')\n")}, af.CONFLICTING),
    "verifier re-exported by a test module": ({"auth.py": EX02_CALLEE_AUTH,
                                               "tests/helpers.py": "from google.oauth2 import id_token\n",
                                               "admin.py": ("from tests.helpers import id_token\n\n\ndef v(t, r):\n    "
                                                            "return id_token.verify_oauth2_token(t, r, audience="
                                                            "'https://admin.example')\n")}, af.UNRESOLVED),
    "audience name rebindable by a star import": ({"auth.py": _auth("AUDIENCE", header=f'AUDIENCE = "{AUD}"\n'
                                                                     "from os.path import *\n")}, af.UNRESOLVED),
    "jwt.decode with a computed verify flag": ({"auth.py": ("from google.auth import jwt\nimport os\n"
                                                            f'\n\ndef v(t, c):\n    return jwt.decode(t, c, os.environ'
                                                            f'.get("V") == "1", "{AUD}")\n')}, af.UNRESOLVED),
    "jwt.decode verify=False checks nothing": ({"auth.py": ("from google.auth import jwt\n\n\ndef v(t):\n    return "
                                                            f'jwt.decode(t, verify=False, audience="{AUD}")\n')},
                                               af.NO_VERIFY_CALL),
    "PyJWT is not a Google ID-token verifier": ({"auth.py": ("import jwt\n\n\ndef v(t, k):\n    return jwt.decode("
                                                             f't, k, algorithms=["RS256"], audience="{AUD}")\n')},
                                                af.NO_VERIFY_CALL),
    "callee ships its own google package": ({"auth.py": EX02_CALLEE_AUTH, "google/__init__.py": "",
                                             "google/oauth2/__init__.py": "", "google/oauth2/id_token.py": ""},
                                            af.NO_VERIFY_CALL),
    "literal with a double quote": ({"auth.py": _auth("'https://a.example\"x'")}, af.UNSAFE_LITERAL),
    "literal with an interpolation": ({"auth.py": _auth('"https://a.example/${var.x}"')}, af.UNSAFE_LITERAL),
    "literal with a template directive": ({"auth.py": _auth('"https://a.example/%{if true}x%{endif}"')},
                                          af.UNSAFE_LITERAL),
    "literal with a newline": ({"auth.py": _auth('"https://a.example\\nx"')}, af.UNSAFE_LITERAL),
    "literal with a backslash": ({"auth.py": _auth('"https://a.example\\\\x"')}, af.UNSAFE_LITERAL),
    "empty literal": ({"auth.py": _auth('""')}, af.UNSAFE_LITERAL),
    "literal over 256 characters": ({"auth.py": _auth('"https://' + "a" * 260 + '.example"')}, af.UNSAFE_LITERAL),
}


@pytest.mark.parametrize("case", sorted(NEGATIVE))
def test_every_other_case_renders_byte_identical_to_today(case):
    callee_files, outcome = NEGATIVE[case]
    vt = _vt()
    files = _tree(callee_files)
    assert af.callee_audience_fact(files, "core-processor").outcome == outcome
    assert af.callee_literal_audience(files, "core-processor") is None
    env, today = _render(vt, files), _render_today(vt, files)
    assert env == today
    assert env[KEY] == URI == vt.edge_env("api-gateway")[KEY]
    assert te.format_hcl_env_vars(env) == te.format_hcl_env_vars(today)


def test_no_callee_code_at_all_and_no_app_files():
    vt = _vt()
    assert af.callee_audience_fact({}, "core-processor").outcome == af.NO_CODE
    assert af.callee_audience_fact(None, "core-processor").outcome == af.NO_CODE
    env = topology_env_vars(vt, "api-gateway", "", None, caller_service=None)
    assert env[KEY] == URI


def test_unresolved_and_refused_cases_are_reported(caplog):
    vt = _vt()
    for case in ("literal with an interpolation", "two different literals", "runtime-computed audience (old 02)"):
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="castor-audience-facts"):
            assert _render(vt, _tree(NEGATIVE[case][0]))[KEY] == URI
        assert any("SIBLING_AUDIENCE_UNRESOLVED" in r.getMessage() for r in caplog.records), case


def test_non_http_edges_and_callers_without_edges_are_untouched():
    vt = _vt(edges=(("api-gateway", "core-processor", "http"), ("core-processor", "worker", "pubsub")),
             services=[("api-gateway", "cloudrun"), ("core-processor", "cloudrun"), ("worker", "event-worker")])
    files = _tree({"auth.py": EX02_CALLEE_AUTH})
    files["apps/worker/main.py"] = _auth(f'"{AUD}"')
    for svc in ("core-processor", "worker"):
        assert _render(vt, files, svc) == _render_today(vt, files, svc)
    assert af.edge_audience_decisions(vt, "core-processor", _render(vt, files, "core-processor"), files,
                                      allow_unauthenticated=True) == []


def test_an_audience_key_already_bound_otherwise_is_left_alone():
    """Only the exact edge binding (`module.<callee>.service_uri`) is ever replaced."""
    vt = _vt()
    files = _tree({"auth.py": EX02_CALLEE_AUTH})
    assert af.edge_audience_decisions(vt, "api-gateway", {KEY: '"https://manual.example"'}, files,
                                      allow_unauthenticated=True) == []


def test_contract_text_is_unchanged():
    """The developer contract (and so every replay cassette key) still lists the same env keys."""
    vt = _vt()
    rule = topology_contract_rule(vt)
    assert "CORE_PROCESSOR_AUDIENCE, CORE_PROCESSOR_URL" in rule
    assert AUD not in rule


# ------------------------------------------------------------------------------- access mode (review finding 1)
SIGN_IN_CALLEE = {"auth.py": ("from google.auth.transport import requests\nfrom google.oauth2 import id_token\n"
                              'CLIENT_ID = "1234-abc.apps.googleusercontent.com"\n\n\ndef login(t):\n    return '
                              "id_token.verify_oauth2_token(t, requests.Request(), CLIENT_ID)\n")}


@pytest.mark.parametrize("access, outcome", [(False, af.IAM_ENFORCED), (None, af.ACCESS_UNKNOWN)])
@pytest.mark.parametrize("callee_files", [{"auth.py": EX02_CALLEE_AUTH}, SIGN_IN_CALLEE],
                         ids=["ex02-shape", "google-sign-in-client-id"])
def test_a_private_or_unknown_access_mode_keeps_todays_binding(callee_files, access, outcome, caplog):
    """Cloud Run invoker IAM (PRIVATE_IAM / PRIVATE_IAP) accepts only the service URL as the audience: a literal would
    be rejected at the front door (and an end-user sign-in client id is never a caller audience)."""
    vt = _vt()
    files = _tree(callee_files)
    assert af.callee_audience_fact(files, "core-processor").outcome == af.LITERAL   # the code fact alone binds
    with caplog.at_level(logging.WARNING, logger="castor-audience-facts"):
        env, today = _render(vt, files, allow_unauthenticated=access), _render_today(vt, files, allow_unauthenticated=access)
    assert env == today and env[KEY] == URI
    assert te.format_hcl_env_vars(env) == te.format_hcl_env_vars(today)
    (d,) = af.edge_audience_decisions(vt, "api-gateway", today, files, allow_unauthenticated=access)
    assert (d.fact.outcome, d.fact.literal, d.value) == (outcome, None, URI)
    assert any("SIBLING_AUDIENCE_UNRESOLVED" in r.getMessage() and outcome in r.getMessage() for r in caplog.records)


def test_the_secondary_render_site_keeps_todays_binding_on_a_private_workload():
    vt3 = _vt(edges=(("web", "api-gateway", "http"), ("api-gateway", "core-processor", "http")),
              services=[("web", "cloudrun"), ("api-gateway", "cloudrun"), ("core-processor", "cloudrun")],
              primary="web")
    files3 = _tree({"auth.py": EX02_CALLEE_AUTH})
    files3["apps/web/main.py"] = "x = 1\n"
    te.reconcile_multi_service_declarations(
        files=files3, product_id="orders", spec_text="", archetype=vt3.archetype, allow_unauthenticated=False,
        assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF], target_services=list(vt3.names), topology=vt3)
    mods = {}
    for m in hcl2.loads(files3[te.SERVICES_TF]).get("module", []):
        mods.update(m)
    assert AUD not in str(mods["compute_api_gateway"]["env_vars"])


def test_the_public_ex02_shape_still_binds():
    vt = _vt()
    files = _tree({"auth.py": EX02_CALLEE_AUTH})
    assert _render(vt, files, allow_unauthenticated=True)[KEY] == f'"{AUD}"'


# ------------------------------------------------------------------------------------ memoization (finding 5)
def test_facts_are_memoized_by_callee_tree_content():
    files = _tree({"auth.py": EX02_CALLEE_AUTH, "tests/test_auth.py": "x = 1\n"})
    first = af.callee_audience_fact(files, "core-processor")
    assert af.callee_audience_fact(dict(files), "core-processor") is first
    files[CALLEE + "tests/test_auth.py"] = "y = 2\n"                     # test text is never read: same key
    assert af.callee_audience_fact(files, "core-processor") is first
    files["apps/api-gateway/other.py"] = "z = 3\n"                       # another service: same key
    assert af.callee_audience_fact(files, "core-processor") is first
    changed = dict(files, **{CALLEE + "auth.py": _auth('"https://other.example"')})
    assert af.callee_audience_fact(changed, "core-processor").literal == "https://other.example"
    shadow = dict(files, **{CALLEE + "google/README.md": "x\n"})       # a path alone changes in_tree
    assert af.callee_audience_fact(shadow, "core-processor").outcome == af.NO_VERIFY_CALL
    assert af.callee_audience_fact(files, "core-processor") is first
    for i in range(af._FACT_CACHE_SIZE + 5):
        af.callee_audience_fact({f"apps/svc-{i}/main.py": "x = 1\n"}, f"svc-{i}")
    assert len(af._FACTS) <= af._FACT_CACHE_SIZE


def test_tree_key_is_injective_across_field_boundaries():
    # Re-review finding 5: a NUL inside a file must not imitate a path/text boundary and reuse another tree's fact.
    two_files = {CALLEE + "x.py": "a = 1\n", CALLEE + "y.py": "b = 2\n"}
    one_file = {CALLEE + "x.py": "a = 1\n\0y.py\0b = 2\n"}
    assert af._tree_key(two_files, "core-processor") != af._tree_key(one_file, "core-processor")
    assert af.callee_audience_fact(one_file, "core-processor").outcome == af.PARSE_ERROR

"""QA-AUTH-STATIC-CHECK: the QA job's static phase refuses three authentication shapes, each proven by structure and
import resolution (never by what an identifier or a string is called, invariant 2).

R1 SEC.UNVERIFIED_TOKEN_DECODE: a token library call, resolved through imports, that skips the signature check.
R2 SEC.AUTH_OFF_BY_DEFAULT: a function whose every HTTP 401/403 is unreachable while a module-level flag read from the
   environment sits at its literal truthy default.
R3 SEC.LITERAL_BEARER_TOKEN: a function of the same file returning a string literal whose result is sent as
   `Authorization: f"Bearer {x}"`.

There is no override, so a false positive would block a valid build: the negative tables below matter as much as the
positives. Covered as well: the repository's test-path rule and platform prefixes (parity with the code the job cannot
import), the typed diagnostic's route into a QA repair, and the job end to end.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import pathlib
import re

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
from gate_errors import ErrorClass
from qa_job_client import DiagnosticIn
from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent.deploy_repair import PLATFORM_TREE_PREFIXES  # noqa: E402
from test_qa_feedback import _feedback, _qa_diag  # noqa: E402
from test_qa_sandbox_job import (artifacts, cloud, codes, gateway_verdict, run, single_service,  # noqa: E402,F401
                                 toolchain, wheelhouse)

sj = sup.load_sandbox_job("sandbox_job_auth_static")
R1, R2, R3 = sj.SEC_UNVERIFIED_DECODE, sj.SEC_AUTH_OFF_BY_DEFAULT, sj.SEC_LITERAL_BEARER
REL = "apps/svc/auth.py"

_spec = importlib.util.spec_from_file_location(
    "vendor_shared_auth_static", pathlib.Path(sup.REPO_ROOT) / "deploy" / "vendor_shared.py")
vendor_shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vendor_shared)


def scan(src, rel=REL, **extra):
    files = {rel: src, **{k.replace("__", "/") + ".py": v for k, v in extra.items()}}
    return sj.check_auth_structure({k: ast.parse(v) for k, v in files.items()})


def found(src, **kw):
    return [(d["code"], d["line"]) for d in scan(src, **kw)]


def found_codes(src, **kw):
    return [d["code"] for d in scan(src, **kw)]


# ------------------------------------------------------------------------------------------------------------------
# R1: unverified token decode, resolved through imports
# ------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("src", [
    "import google.auth.jwt\nx = google.auth.jwt.decode(t, verify=False)\n",
    "from google.auth import jwt as gj\nx = gj.decode(t, verify=False)\n",
    "from google.auth.jwt import decode\nx = decode(t, None, False)\n",
    "from google.auth.jwt import decode as d\nx = d(t, verify=False)\n",
    "import google.auth.jwt as a\nx = a.decode(t, certs_url='u', verify=False)\n",
    "import jwt\nx = jwt.decode(t, options={'verify_signature': False})\n",
    "import jwt as pyjwt\nx = pyjwt.decode(t, options={'verify_signature': False})\n",
    "from jwt import decode as d\nx = d(t, options={'verify_signature': False, 'verify_exp': False})\n",
    "import jwt\nx = jwt.decode(t, '', ['RS256'], {'verify_signature': False})\n",
    "import jwt\nopts = {'verify_signature': False}\nx = jwt.decode(t, options=opts)\n",
    "import jwt\nx = jwt.decode(t, 'k', verify=False)\n",
    "from jose import jwt\nx = jwt.get_unverified_claims(t)\n",
    "from jose.jwt import get_unverified_claims as g\nx = g(t)\n",
    "import jose.jwt\nx = jose.jwt.get_unverified_claims(t)\n",
    "from jose import jws\nx = jws.get_unverified_claims(t)\n",
    "from jose import jwt as j\nx = j.decode(t, 'k', options={'verify_signature': False})\n",
])
def test_r1_true_positives_including_aliases(src):
    assert found_codes(src) == [R1]


def test_r1_function_local_import_and_exact_line():
    src = ("def f(t):\n"
           "    try:\n"
           "        from google.auth.jwt import decode\n"
           "        return decode(t, verify=False)\n"
           "    except Exception:\n"
           "        return None\n")
    assert found(src) == [(R1, 4)]


@pytest.mark.parametrize("src", [
    "from google.auth.jwt import decode\nx = decode(t, certs, verify=True)\n",
    "from google.auth.jwt import decode\nx = decode(t, certs)\n",
    "from google.oauth2 import id_token\nx = id_token.verify_oauth2_token(t, r, a)\n",
    "import jwt\nx = jwt.decode(t, k, algorithms=['RS256'], audience='a')\n",
    "import jwt\nx = jwt.decode(t, k, algorithms=['RS256'], options={'verify_exp': False})\n",
    "import jwt\nx = jwt.decode(t, k, algorithms=['RS256'], options={'verify_signature': True})\n",
    "import jwt\nx = jwt.get_unverified_header(t)\n",  # reading the key id is the documented first step
    "from jose import jwt\nx = jwt.get_unverified_header(t)\n",
])
def test_r1_negative_verified_calls(src):
    assert found(src) == []


@pytest.mark.parametrize("src", [
    # the name is not the library: a local object, function, parameter or relative module
    "class C:\n    def decode(self, t, verify):\n        return t\njwt = C()\nx = jwt.decode(t, verify=False)\n",
    "def decode(t, verify):\n    return t\nx = decode(t, verify=False)\n",
    "def get_unverified_claims(t):\n    return {}\nx = get_unverified_claims(t)\n",
    "import jwt\ndef f(jwt):\n    return jwt.decode(t, options={'verify_signature': False})\n",
    "from . import jwt\nx = jwt.decode(t, options={'verify_signature': False})\n",
    # a parameter or anything not a literal false proves nothing
    "import jwt\ndef f(t, o):\n    return jwt.decode(t, options=o)\n",
    "from google.auth.jwt import decode\ndef f(t, v):\n    return decode(t, verify=v)\n",
])
def test_r1_negative_not_proven(src):
    assert found(src) == []


def test_r1_negative_module_shipped_by_the_workload():
    src = "import jwt\nx = jwt.decode(t, options={'verify_signature': False})\n"
    assert found(src, apps__svc__jwt="def decode(t, options):\n    return t\n") == []


# Known residual documented in known-limitations.md: a peek is allowed only when structure proves real verification.
PEEK_OK = [
    ("import jwt\n"
     "def f(token, keys):\n"
     "    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    key = keys[peek['iss']]\n"
     "    return jwt.decode(token, key, algorithms=['RS256'], audience='a')\n"),
    ("import jwt\n"
     "def f(token, keys):\n"
     "    iss = jwt.decode(token, options={'verify_signature': False})['iss']\n"
     "    claims = jwt.decode(token, keys[iss], algorithms=['RS256'])\n"
     "    return claims\n"),
    ("import jwt\n"
     "def f(token, keys):\n"
     "    iss = jwt.decode(token, options={'verify_signature': False}).get('iss')\n"
     "    return jwt.decode(token, keys[iss], algorithms=['RS256'])\n"),
    ("from jose import jwt\n"
     "from fastapi import HTTPException\n"
     "def f(token, keys):\n"
     "    peek = jwt.get_unverified_claims(token)\n"
     "    try:\n"
     "        return jwt.decode(token, keys[peek['iss']], algorithms=['RS256'])\n"
     "    except Exception as exc:\n"
     "        raise HTTPException(401) from exc\n"),
    ("import jwt\n"
     "from google.oauth2 import id_token\n"
     "def f(token, req):\n"
     "    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    aud = peek['aud']\n"
     "    return id_token.verify_oauth2_token(token, req, aud)\n"),
]


@pytest.mark.parametrize("src", PEEK_OK)
def test_r1_negative_peek_followed_by_proven_verification(src):
    assert found(src) == []


@pytest.mark.parametrize("src", [
    # no verification at all
    "import jwt\ndef f(token):\n    peek = jwt.decode(token, options={'verify_signature': False})\n    return peek['iss']\n",
    # verifies a different token
    ("import jwt\ndef f(token, other, k):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    return jwt.decode(other, k, algorithms=['RS256'])\n"),
    # an early return can hand out the unverified claims
    ("import jwt\ndef f(token, k):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    if peek['iss'] == 'a':\n        return peek\n    return jwt.decode(token, k, algorithms=['RS256'])\n"),
    # the verified result is dropped, the unverified one is used
    ("import jwt\ndef f(token, k):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    jwt.decode(token, k, algorithms=['RS256'])\n    return peek\n"),
    # "verification" with no key
    ("import jwt\ndef f(token):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    return jwt.decode(token, '', algorithms=['RS256'])\n"),
    # the second decode is unverified too
    ("import jwt\ndef f(token):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    return jwt.decode(token, options={'verify_signature': False})\n"),
    # verification only on one branch
    ("import jwt\ndef f(token, k, c):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    if c:\n        jwt.decode(token, k, algorithms=['RS256'])\n    return token\n"),
    # a handler swallows the verification failure
    ("import jwt\ndef f(token, k):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    try:\n        jwt.decode(token, k, algorithms=['RS256'])\n    except Exception:\n        pass\n    return token\n"),
    # the token is replaced between the peek and the verification
    ("import jwt\ndef f(token, k, g):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    token = g()\n    return jwt.decode(token, k, algorithms=['RS256'])\n"),
    # options the structure cannot read
    ("import jwt\ndef f(token, k, o):\n    peek = jwt.decode(token, options={'verify_signature': False})\n"
     "    return jwt.decode(token, k, algorithms=['RS256'], options=o)\n"),
])
def test_r1_true_positives_when_verification_is_not_proven(src):
    assert R1 in found_codes(src) and set(found_codes(src)) == {R1}


# ------------------------------------------------------------------------------------------------------------------
# R2: an HTTP 401/403 that is only reachable when a flag is away from its literal truthy default
# ------------------------------------------------------------------------------------------------------------------
HX = "import os\nfrom fastapi import HTTPException, status\n"
CHECK = "def f(token):\n    if not token:\n        if F:\n            return 'x'\n        else:\n            raise HTTPException(401)\n"


@pytest.mark.parametrize("flag", [
    'F = os.getenv("A", "true")\n',
    'F = os.getenv("A", "1")\n',
    'F = os.getenv("A", "YES")\n',
    'F = os.environ.get("A", "on")\n',
    'F = os.getenv("A", default="true")\n',
    'F = os.getenv("A", "true").lower() in ("1", "true", "yes")\n',
    'F = os.getenv("A", "True").strip().lower() == "true"\n',
    'F = os.getenv("A", "true") != "false"\n',
    'F: bool = bool(os.getenv("A", "1"))\n',
    'RAW = os.getenv("A", "true")\nF = RAW.lower() == "true"\n',
])
def test_r2_flag_definitions_proven_on_by_default(flag):
    assert found_codes(HX + flag + CHECK) == [R2]


@pytest.mark.parametrize("imports,flag", [
    ("import os as o\nfrom fastapi import HTTPException\n", 'F = o.getenv("A", "true")\n'),
    ("from os import getenv as g\nfrom fastapi import HTTPException\n", 'F = g("A", "true")\n'),
    ("from os import environ as e\nfrom fastapi import HTTPException\n", 'F = e.get("A", "true")\n'),
])
def test_r2_environment_read_resolved_through_aliases(imports, flag):
    assert found_codes(imports + flag + CHECK) == [R2]


@pytest.mark.parametrize("body", [
    # the shape seen live: a fallback identity in the default branch, the refusal in the other one
    "def f(t):\n    if not t:\n        if F:\n            t = 'u'\n        else:\n            raise HTTPException(status_code=401)\n    return t\n",
    "def f(t):\n    if not t:\n        if not F:\n            raise HTTPException(status_code=403)\n    return t\n",
    "def f(t):\n    if not t and not F:\n        raise HTTPException(status.HTTP_401_UNAUTHORIZED)\n    return t\n",
    "def f(t):\n    if F or t:\n        return t\n    else:\n        raise HTTPException(status.HTTP_403_FORBIDDEN)\n",
    # the flag returns first, every check below it is off
    "def f(t):\n    if F:\n        return 'u'\n    if not t:\n        raise HTTPException(401)\n    return t\n",
    "async def f(t):\n    if F:\n        return 'u'\n    try:\n        return check(t)\n    except ValueError:\n        raise HTTPException(401)\n",
    "class C:\n    def f(self, t):\n        if F:\n            return 'u'\n        if not t:\n            raise HTTPException(401)\n",
    # a comparison at the use site
    "def f(t):\n    if not t:\n        if F == 'true':\n            return 'u'\n        raise HTTPException(401)\n",
])
def test_r2_true_positives(body):
    assert found_codes(HX + 'F = os.getenv("A", "true")\n' + body) == [R2]


@pytest.mark.parametrize("imports,refusal", [
    ("from starlette.exceptions import HTTPException\n", "raise HTTPException(401)"),
    ("from fastapi.exceptions import HTTPException as H\n", "raise H(status_code=403)"),
    ("import fastapi\n", "raise fastapi.HTTPException(401)"),
    ("from fastapi import HTTPException\nfrom starlette import status as s\n", "raise HTTPException(s.HTTP_403_FORBIDDEN)"),
    ("from fastapi import HTTPException\nfrom http import HTTPStatus\n", "raise HTTPException(HTTPStatus.UNAUTHORIZED)"),
    ("from werkzeug.exceptions import Unauthorized\n", "raise Unauthorized()"),
    ("from werkzeug.exceptions import Forbidden\n", "raise Forbidden"),
    ("from flask import abort\n", "abort(401)"),
])
def test_r2_refusal_resolved_through_imports(imports, refusal):
    src = (f"import os\n{imports}F = os.getenv('A', 'true')\n"
           f"def f(t):\n    if not t:\n        if F:\n            return 1\n        {refusal}\n")
    assert found_codes(src) == [R2]


def test_r2_reports_the_if_that_turns_the_check_off():
    src = HX + 'F = os.getenv("A", "true")\ndef f(t):\n    if not t:\n        if F:\n            return "u"\n        raise HTTPException(401)\n'
    assert found(src) == [(R2, 6)]


@pytest.mark.parametrize("src", [
    # a local-development flag that defaults OFF: the check is on unless someone opts out
    HX + 'F = os.getenv("A", "false").lower() in ("1", "true")\n' + CHECK,
    HX + 'F = os.getenv("A", "0") == "1"\n' + CHECK,
    HX + 'F = os.getenv("A", "")\n' + CHECK,
    HX + 'F = os.getenv("A")\n' + CHECK,
    HX + 'F = os.environ.get("A", "no")\n' + CHECK,
    HX + 'F = os.getenv("A", "true") == "false"\n' + CHECK,
    # the default is not a boolean-looking literal, or is not a literal at all
    HX + 'F = os.getenv("A", "production")\n' + CHECK,
    HX + 'D = "true"\nF = os.getenv("A", D)\n' + CHECK,
    # no environment involved
    HX + "F = True\n" + CHECK,
    # enforcement ON by default: the refusal is reached when the flag is on
    HX + 'F = os.getenv("A", "true") == "true"\ndef f(t):\n    if F and not t:\n        raise HTTPException(401)\n',
    HX + 'F = os.getenv("A", "true")\ndef f(t):\n    if F:\n        if not t:\n            raise HTTPException(403)\n',
    # another 401 stays live with the flag at its default, so the function can still refuse
    HX + 'F = os.getenv("A", "true")\ndef f(t, u):\n    if not u:\n        raise HTTPException(401)\n    if not t and not F:\n        raise HTTPException(403)\n',
    # a kill switch: with the flag off everybody is refused, it does not bypass a credential check
    HX + 'F = os.getenv("A", "true")\ndef f():\n    if not F:\n        raise HTTPException(403)\n    return 1\n',
    HX + 'F = os.getenv("A", "true")\ndef f():\n    if F:\n        return 1\n    raise HTTPException(403)\n',
    # the default path still refuses, just with another status
    HX + 'F = os.getenv("A", "true")\ndef f(t):\n    if not t:\n        if F:\n            raise HTTPException(400)\n        else:\n            raise HTTPException(403)\n',
    # the flag alone does not decide: a localhost-only bypass
    HX + 'F = os.getenv("A", "true")\ndef f(t, h):\n    if F and h == "127.0.0.1":\n        return 1\n    if not t:\n        raise HTTPException(401)\n',
    # other statuses are not the check
    HX + 'F = os.getenv("A", "true")\ndef f(t):\n    if not t:\n        if F:\n            return 1\n        raise HTTPException(404)\n',
    # a status that is not a literal 401/403
    HX + 'F = os.getenv("A", "true")\ndef f(t, c):\n    if not t:\n        if F:\n            return 1\n        raise HTTPException(c)\n',
    # not the framework: a local class of the same name
    'import os\nclass HTTPException(Exception):\n    pass\nF = os.getenv("A", "true")\n' + CHECK,
    # shadowed, reassigned or conditional flags are not proven
    HX + 'F = os.getenv("A", "true")\ndef f(t, F):\n    if not t:\n        if F:\n            return 1\n        raise HTTPException(401)\n',
    HX + 'F = os.getenv("A", "true")\nF = compute()\n' + CHECK,
    HX + 'F = os.getenv("A", "true")\ndef g():\n    global F\n    F = False\n' + CHECK,
    HX + 'if c:\n    F = os.getenv("A", "true")\n' + CHECK,
    # read inside the function: not a module-level flag
    HX + 'def f(t):\n    if not t:\n        if os.getenv("A", "true"):\n            return 1\n        raise HTTPException(401)\n',
    # a refusal in another function is not gated by this flag
    HX + 'F = os.getenv("A", "true")\ndef g(t):\n    if F:\n        return 1\n    return t\ndef h(t):\n    if not t:\n        raise HTTPException(401)\n',
])
def test_r2_negatives(src):
    assert found(src) == []


@pytest.mark.parametrize("src", [
    # a public health route next to protected ones
    (HX + 'F = os.getenv("A", "false") == "true"\n'
     "def verify(t):\n    if not t:\n        raise HTTPException(401)\n"
     "def health():\n    return {'status': 'healthy'}\n"),
    "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health():\n    return {'status': 'ok'}\n",
])
def test_r2_negative_public_health_route(src):
    assert found(src) == []


def test_r2_identifiers_are_never_read():
    """Invariant 2: the same structure is judged the same under any name, meaningful or not."""
    template = HX + '{n} = os.getenv("A", "{d}") == "{e}"\ndef f(t):\n    if not t:\n        if {n}:\n            return 1\n        raise HTTPException(401)\n'
    for name in ("q7", "ALLOW_DEV_AUTH_BYPASS", "ENFORCE_SECURITY", "MOCK"):
        assert found_codes(template.format(n=name, d="true", e="true")) == [R2]
        assert found_codes(template.format(n=name, d="false", e="true")) == []


# ------------------------------------------------------------------------------------------------------------------
# R3: a literal returned by a function of the file and sent as a Bearer token
# ------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("src,line", [
    ("def t():\n    return 'abc'\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n", 2),
    ("def t():\n    return 'abc'\nhead = {'authorization': f'Bearer {t()}'}\n", 2),
    ("def t():\n    return 'abc'\ndef h(d):\n    d['Authorization'] = f'Bearer {t()}'\n", 2),
    ("async def t():\n    return 'abc'\nasync def h():\n    x = await t()\n    return {'Authorization': f'Bearer {x}'}\n", 2),
    ("def t(c):\n    if c:\n        return real()\n    return 'abc'\ndef h():\n    x = t(1)\n    return {'Authorization': f'Bearer {x}'}\n", 4),
    ("K = 'abc'\ndef t():\n    return K\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n", 3),
    ("class C:\n    def t(self):\n        return 'abc'\n    def h(self):\n        x = self.t()\n        return {'Authorization': f'Bearer {x}'}\n", 3),
    ("class C:\n    def t(me):\n        return 'abc'\n    def h(me):\n        return {'Authorization': f'Bearer {me.t()}'}\n", 3),
])
def test_r3_true_positives_and_the_line_is_the_literal(src, line):
    assert found(src) == [(R3, line)]


def test_r3_the_fallback_shape_seen_live():
    src = ("import os, urllib.request\n"
           "class Client:\n"
           "    def token(self):\n"
           "        env = os.getenv('T', '')\n"
           "        if env:\n"
           "            return env\n"
           "        try:\n"
           "            return urllib.request.urlopen('u').read().decode()\n"
           "        except Exception:\n"
           "            return 'abc'\n"
           "    def headers(self):\n"
           "        token = self.token()\n"
           "        return {'Authorization': f'Bearer {token}'}\n")
    assert found(src) == [(R3, 10)]


@pytest.mark.parametrize("src", [
    # an env-supplied or fetched token
    "import os\ndef t():\n    return os.environ['T']\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n",
    "import os\ndef t():\n    return os.getenv('T')\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n",
    ("from google.oauth2 import id_token\ndef t(r, a):\n    return id_token.fetch_id_token(r, a)\n"
     "def h(r, a):\n    x = t(r, a)\n    return {'Authorization': f'Bearer {x}'}\n"),
    # "no token" is not a credential
    "def t():\n    return ''\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n",
    "def t():\n    return '   '\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n",
    "def t():\n    return None\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n",
    # the literal never reaches the header
    "def t():\n    return 'abc'\ndef h(x):\n    t()\n    return {'Authorization': f'Bearer {x}'}\n",
    "def t():\n    return 'abc'\ndef h():\n    x = t()\n    return {'X-Trace': f'Bearer {x}'}\n",
    "def t():\n    return 'abc'\ndef h():\n    x = t()\n    return {'Authorization': f'Basic {x}'}\n",
    "def t():\n    return 'abc'\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}-{x}'}\n",
    # x has more than one source
    "def t():\n    return 'abc'\ndef h(c):\n    x = t()\n    if c:\n        x = c\n    return {'Authorization': f'Bearer {x}'}\n",
    # another object's method, a method defined twice, an imported function, a nested function's return
    "class C:\n    def t(self):\n        return 'abc'\n    def h(self, o):\n        x = o.t()\n        return {'Authorization': f'Bearer {x}'}\n",
    "class C:\n    def t(self):\n        return 'abc'\n    def t(self):\n        return real()\n    def h(self):\n        x = self.t()\n        return {'Authorization': f'Bearer {x}'}\n",
    "from auth import t\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n",
    "def t():\n    def inner():\n        return 'abc'\n    return real(inner)\ndef h():\n    x = t()\n    return {'Authorization': f'Bearer {x}'}\n",
])
def test_r3_negatives(src):
    assert found(src) == []


# ------------------------------------------------------------------------------------------------------------------
# Scope of the scan: tests, platform-provided code, parse failures
# ------------------------------------------------------------------------------------------------------------------
ALL_THREE = ("import os\nimport jwt\nfrom fastapi import HTTPException\n"
             "x = jwt.decode(t, options={'verify_signature': False})\n"
             "F = os.getenv('A', 'true')\n"
             "def f(t):\n    if not t:\n        if F:\n            return 1\n        raise HTTPException(401)\n"
             "def g():\n    return 'abc'\ndef h():\n    y = g()\n    return {'Authorization': f'Bearer {y}'}\n")


def test_all_three_rules_on_a_non_test_file():
    assert sorted(found_codes(ALL_THREE)) == sorted([R1, R2, R3])


@pytest.mark.parametrize("rel", [
    "tests/conftest.py", "tests/test_main.py", "tests/helpers.py", "apps/svc/tests/fakes.py", "apps/svc/test_auth.py",
    "apps/svc/auth_test.py", "apps/svc/conftest.py", "a/b/tests/c/d.py",
])
def test_tests_are_excluded(rel):
    assert found(ALL_THREE, rel=rel) == []


@pytest.mark.parametrize("rel", [
    "apps/svc/testing.py", "apps/svc/contest.py", "apps/svc/mytests/auth.py", "apps/svc/test/auth.py",
    "apps/svc/latest_auth.py", "scripts/auth.py", "contracts/auth.py", "apps/svc/shared/auth.py",
])
def test_paths_that_are_not_tests_stay_in_scope(rel):
    assert len(found(ALL_THREE, rel=rel)) == 3


@pytest.mark.parametrize("rel", [
    "tests/conftest.py", "tests/test_main.py", "tests/helpers.py", "apps/svc/tests/fakes.py", "apps/svc/test_auth.py",
    "apps/svc/auth_test.py", "apps/svc/conftest.py", "a/b/tests/c/d.py", "apps/svc/testing.py", "apps/svc/contest.py",
    "apps/svc/mytests/auth.py", "apps/svc/test/auth.py", "apps/svc/latest_auth.py", "scripts/auth.py", "main.py",
    "tests.py", "conftest.py", "test_x.py", "x_test.py", "tests/x.py",
])
def test_test_path_rule_parity_with_the_repository_rule(rel):
    assert sj.is_workload_test_file(rel) == vendor_shared._is_test_file(rel)


@pytest.mark.parametrize("rel", ["infra/workload/fn/main.py", "infra/modules/m/src/auth.py", ".github/scripts/auth.py"])
def test_platform_provided_code_paths_are_excluded(rel):
    assert found(ALL_THREE, rel=rel) == []


def test_platform_prefixes_parity_with_the_repair_planner():
    assert sj.PLATFORM_TREE_PREFIXES == PLATFORM_TREE_PREFIXES == QR.PLATFORM_TREE_PREFIXES


def test_an_unparseable_file_only_has_its_syntax_finding(tmp_path):
    (tmp_path / "bad.py").write_text("def f(:\n")
    (tmp_path / "good.py").write_text(ALL_THREE)
    trees, syntax = sj.check_syntax(str(tmp_path), ["bad.py", "good.py"])
    assert [d["code"] for d in syntax] == ["PY.SYNTAX"] and set(trees) == {"good.py"}
    assert len(sj.check_auth_structure(trees)) == 3


@pytest.mark.parametrize("src", [
    "",
    "x = " + " + ".join(["'a'"] * 3000) + "\n",
    "x = " + ".".join(["a"] * 3000) + "\n",
    "x = (" + "not " * 500 + "y)\n",
    "import os\nF = os.getenv('A', 'true')\ndef f():\n    if " + "not " * 500 + "F:\n        pass\n",
])
def test_a_deep_or_empty_file_never_raises(src):
    assert found(src) == []


# ------------------------------------------------------------------------------------------------------------------
# The route: typed diagnostic -> static phase -> gateway verdict -> QA repair
# ------------------------------------------------------------------------------------------------------------------
GRAMMAR = re.compile(r"^[A-Z][A-Z0-9]*(\.[A-Z0-9_]+)+$")   # shared.diagnostics.DiagnosticCode


def test_findings_are_typed_errors_with_file_and_line():
    findings = scan(ALL_THREE)
    assert sorted(d["code"] for d in findings) == sorted([R1, R2, R3])
    for d in findings:
        assert d["severity"] == "error" and d["file"] == REL and isinstance(d["line"], int) and d["line"] > 0
        assert GRAMMAR.match(d["code"])
        DiagnosticIn(**d)   # the gateway's contract for the job's diagnostics


def test_the_literal_is_never_copied_into_the_finding():
    src = "def g():\n    return 'do-not-echo-me'\ndef h():\n    y = g()\n    return {'Authorization': f'Bearer {y}'}\n"
    assert all("do-not-echo-me" not in (d["message"] + str(d["detail"])) for d in scan(src))


@pytest.mark.parametrize("code", [R1, R2, R3])
def test_each_code_is_a_qa_repair_of_the_named_file(code):
    tree = {"apps/shop/main.py": "x = 1\n", "apps/shop/auth.py": "y = 1\n", "infra/workload/main.tf": "# platform\n"}
    plan = QR.plan_qa_repair(_feedback(tree, _qa_diag(file="apps/shop/auth.py", code=code, line=7)), stack_configured=True)
    assert plan.mode == QR.QA_REPAIR and plan.reason == "CODE_DEFECT_ON_DRAFT_FILES"
    assert [(s.code, s.file, s.line) for s in plan.seeds] == [(code, "apps/shop/auth.py", 7)]


def test_a_finding_on_a_file_the_build_did_not_write_takes_the_existing_route():
    """Same as any other QA finding on a repository file (SAT-49): the repair must not edit it, so the run regenerates."""
    tree = {"apps/shop/main.py": "x = 1\n", "apps/shop/auth.py": "y = 1\n"}
    fb = _feedback(tree, _qa_diag(file="apps/shop/auth.py", code=R1, line=7), draft_paths=["apps/shop/main.py"])
    plan = QR.plan_qa_repair(fb, stack_configured=True)
    assert plan.mode == QR.REGENERATE and plan.reason == "FINDING_NOT_ON_A_DRAFT_FILE"


def test_job_end_to_end_static_phase_is_a_code_defect(cloud, toolchain):
    files = single_service(**{"apps/svc/auth.py": ALL_THREE})
    code, _ = run(cloud, toolchain, files)
    static, report = artifacts(cloud)
    assert code == 10 and static["passed"] is False and report is None   # no untrusted code ran
    assert {R1, R2, R3} <= set(codes(static["diagnostics"]))
    assert gateway_verdict(cloud, code).error_class == ErrorClass.CODE_DEFECT


def test_job_end_to_end_valid_workload_is_unchanged(cloud, toolchain):
    code, _ = run(cloud, toolchain, single_service())
    static, _report = artifacts(cloud)
    assert code == 0 and static["passed"] is True
    assert not [c for c in codes(static["diagnostics"]) if c.startswith("SEC.")]

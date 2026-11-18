"""SIBLING-AUDIENCE-GETENV-DEFAULT (extends SIBLING-AUDIENCE-BINDING option A; docs/implemented/sibling-audience-binding-plan.md
§8). A callee that verifies `os.getenv(NAME, L)` / `os.environ.get(NAME, L)` (example 02, the 11-10 run) gets its
caller's `<BASE>_AUDIENCE` bound to L only on a public workload, only when the platform's IaC sets no NAME on the
callee (topology_wiring.callee_env_names) and only when the callee's own code cannot set NAME. Every other case keeps
today's `module.<callee>.service_uri` byte-identical (Invariant 1). Hermetic, no I/O."""
import hermetic_guard  # noqa: F401  (first import)

import ast
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
from developer_agent import topology_wiring as tw  # noqa: E402
from developer_agent.assembly import CUSTOM_TF, bespoke_root_text  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402
from shared.service_topology import RESERVED_ENV_KEYS, validate_service_topology  # noqa: E402

AUD = "https://service-b.orders.example"
NAME = "OIDC_AUDIENCE"
CALLEE = "core-service"
ROOT = f"apps/{CALLEE}/"
KEY = "CORE_SERVICE_AUDIENCE"
URI = "module.compute_core_service.service_uri"

# The exact shape of the example 02 callee of the 11-10 run (apps/core-service/security.py): a module-level annotated
# env read with the fixed audience as its default, verified inside a function.
EX02_1110_SECURITY = f'''import os
from typing import Any, Dict

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

EXPECTED_AUDIENCE: str = os.getenv("{NAME}", "{AUD}")
request_adapter = google_requests.Request()


def verify_caller(token_str: str) -> Dict[str, Any]:
    claims = id_token.verify_oauth2_token(token_str, request_adapter, audience=EXPECTED_AUDIENCE)
    return claims
'''
# That callee's own resource bindings (its deployed env named these two besides the platform's).
EX02_RESOURCES = [
    {"type": "google_secret_manager_secret", "logical_name": "order_signing",
     "consumers": [{"service": CALLEE, "env_key": "ORDER_SIGNING_SECRET_ID"}]},
    {"type": "google_storage_bucket", "logical_name": "orders_archive",
     "consumers": [{"service": CALLEE, "env_key": "FIRESTORE_DATABASE_ID"}]},
]


def _vt(resources=(), edges=(("api-gateway", CALLEE, "http"),), services=None, primary="api-gateway"):
    services = services or [("api-gateway", "cloudrun"), (CALLEE, "cloudrun")]
    raw = {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
           "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges], "resources": list(resources)}
    vt, diags = validate_service_topology(raw, product_id="orders")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def _tree(callee_files, extra=None):
    files = {CUSTOM_TF: "", "apps/api-gateway/main.py": f'import os\nAUD = os.environ["{KEY}"]\n',
             ROOT + "main.py": "from fastapi import FastAPI\n\napp = FastAPI()\n"}
    files.update({ROOT + rel: text for rel, text in callee_files.items()})
    files.update(extra or {})
    return files


def _render(vt, files, allow_unauthenticated=True):
    return tw.topology_env_vars(vt, "api-gateway", files[CUSTOM_TF], files, caller_service=None,
                                allow_unauthenticated=allow_unauthenticated)


def _render_today(vt, files, allow_unauthenticated=True):
    with patch.object(af, "edge_audience_decisions", return_value=[]):
        return _render(vt, files, allow_unauthenticated)


def _auth(audience_expr, header="import os\n", extra=""):
    return (f"from google.auth.transport import requests\nfrom google.oauth2 import id_token\n{header}\n"
            f"def verify(token):\n    return id_token.verify_oauth2_token(token, requests.Request(), "
            f"audience={audience_expr})\n{extra}")


def _modules(text):
    mods = {}
    for m in hcl2.loads(text).get("module", []):
        mods.update(m)
    return mods


# ------------------------------------------------------------------------------------------------- positive
def test_the_exact_ex02_1110_shape_binds_the_default():
    vt = _vt(EX02_RESOURCES)
    files = _tree({"security.py": EX02_1110_SECURITY})
    fact = af.callee_audience_fact(files, CALLEE)
    assert (fact.outcome, fact.literal, fact.env_names) == (af.LITERAL_ENV_DEFAULT, AUD, (NAME,))
    assert af.callee_literal_audience(files, CALLEE) is None   # not a code-only fact
    names, why = tw.callee_env_names(vt, CALLEE, files)
    assert why == "" and NAME not in names
    assert {"ORDER_SIGNING_SECRET_ID", "FIRESTORE_DATABASE_ID", "PROJECT_ID", "CASTOR_DEPLOY_NONCE"} <= names
    env, today = _render(vt, files), _render_today(vt, files)
    assert today[KEY] == URI and env[KEY] == f'"{AUD}"' and env["CORE_SERVICE_URL"] == URI
    assert {k: v for k, v in env.items() if k != KEY} == {k: v for k, v in today.items() if k != KEY}


def test_the_ex02_1110_shape_through_both_render_sites():
    from developer_agent.handler import DeveloperAgent
    vt = _vt(EX02_RESOURCES)
    files = _tree({"security.py": EX02_1110_SECURITY})
    assert DeveloperAgent._topology_primary_overrides(vt, "", files, True)[0][KEY] == f'"{AUD}"'
    for private in (False, None):
        assert DeveloperAgent._topology_primary_overrides(vt, "", files, private)[0][KEY] == URI
    # a secondary caller of the PRIMARY callee (terraform_engine render site; the callee renders into main.tf)
    vt2 = _vt([], edges=(("api-gateway", CALLEE, "http"),), primary=CALLEE)
    files2 = _tree({"security.py": EX02_1110_SECURITY})
    te.reconcile_multi_service_declarations(
        files=files2, product_id="orders", spec_text="", archetype=vt2.archetype, allow_unauthenticated=True,
        assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF], target_services=list(vt2.names), topology=vt2)
    gateway_env = str(_modules(files2[te.SERVICES_TF])["compute_api_gateway"]["env_vars"])
    assert AUD in gateway_env and "module.compute.service_uri" in gateway_env


ENV_DEFAULT_FORMS = {
    "function-level getenv": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")')},
    "function-level environ.get": {"auth.py": _auth(f'os.environ.get("{NAME}", "{AUD}")')},
    "default keyword": {"auth.py": _auth(f'os.getenv("{NAME}", default="{AUD}")')},
    "from os import getenv": {"auth.py": _auth("A", header=f'from os import getenv\nA = getenv("{NAME}", "{AUD}")\n')},
    "import os as _os": {"auth.py": _auth("A", header=f'import os as _os\nA = _os.getenv("{NAME}", "{AUD}")\n')},
    "from os import environ": {"auth.py": _auth("A", header=f'from os import environ\nA = environ.get("{NAME}", "{AUD}")\n')},
    "constant name and default": {"auth.py": _auth("A", header=f'import os\n_N = "{NAME}"\n_D: str = "{AUD}"\n'
                                                                "A = os.getenv(_N, _D)\n")},
    "same-service import": {"auth.py": _auth("AUDIENCE", header="from config import AUDIENCE\n"),
                            "config.py": f'import os\nAUDIENCE = os.getenv("{NAME}", "{AUD}")\n'},
    "with a same-literal constant elsewhere": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")'),
                                               "admin.py": _auth(f'"{AUD}"')},
    "other env keys written by constant": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")', extra=(
        '\nos.environ.setdefault("OTHER", "1")\nos.environ["GRPC_X"] = "y"\ndel os.environ["Z"]\n'
        'os.putenv("W", "1")\nCOPY = os.environ.copy()\nHAS = "Q" in os.environ\nP = os.path.join("a", "b")\n'))},
}


@pytest.mark.parametrize("case", sorted(ENV_DEFAULT_FORMS))
def test_supported_env_default_forms_bind_the_default(case):
    vt = _vt()
    files = _tree(ENV_DEFAULT_FORMS[case])
    fact = af.callee_audience_fact(files, CALLEE)
    assert (fact.outcome, fact.literal, fact.env_names) == (af.LITERAL_ENV_DEFAULT, AUD, (NAME,)), fact
    assert _render(vt, files)[KEY] == f'"{AUD}"'


def test_the_binding_names_the_shape_in_the_log(caplog):
    vt = _vt()
    with caplog.at_level(logging.INFO, logger="castor-audience-facts"):
        _render(vt, _tree({"security.py": EX02_1110_SECURITY}))
    assert any("SIBLING_AUDIENCE_BINDING" in r.getMessage() and af.LITERAL_ENV_DEFAULT in r.getMessage()
               and NAME in r.getMessage() for r in caplog.records)


# ------------------------------------------------------------------------------------------------- negative
def _assert_today(vt, files, outcome=None, allow_unauthenticated=True):
    env, today = _render(vt, files, allow_unauthenticated), _render_today(vt, files, allow_unauthenticated)
    assert env == today and env[KEY] == URI
    assert te.format_hcl_env_vars(env) == te.format_hcl_env_vars(today)
    if outcome is not None:
        decisions = af.edge_audience_decisions(vt, "api-gateway", today, files,
                                               allow_unauthenticated=allow_unauthenticated,
                                               callee_env_names=lambda c: tw.callee_env_names(vt, c, files))
        assert [(d.fact.outcome, d.value) for d in decisions] == [(outcome, URI)]


@pytest.mark.parametrize("env_key", [NAME, "K_SERVICE", "PROJECT_ID"])
def test_a_name_the_platform_sets_keeps_the_url(env_key):
    """The platform's own value (a topology consumer binding, Cloud Run / the module's literal env) wins at run time."""
    resources = ([{"type": "google_storage_bucket", "logical_name": "files",
                   "consumers": [{"service": CALLEE, "env_key": env_key}]}] if env_key == NAME else [])
    vt = _vt(resources)
    files = _tree({"security.py": EX02_1110_SECURITY.replace(NAME, env_key)})
    assert af.callee_audience_fact(files, CALLEE).outcome == af.LITERAL_ENV_DEFAULT
    _assert_today(vt, files, af.ENV_SET_BY_PLATFORM)


def test_the_deploy_nonce_an_edge_key_and_an_hb05_key_keep_the_url():
    # the rollout nonce
    vt = _vt()
    _assert_today(vt, _tree({"security.py": EX02_1110_SECURITY.replace(NAME, tw.DEPLOY_NONCE_ENV)}),
                  af.ENV_SET_BY_PLATFORM)
    # the callee's own outgoing edge key
    vt3 = _vt(edges=(("api-gateway", CALLEE, "http"), (CALLEE, "ledger", "http")),
              services=[("api-gateway", "cloudrun"), (CALLEE, "cloudrun"), ("ledger", "cloudrun")])
    files3 = _tree({"security.py": EX02_1110_SECURITY.replace(NAME, "LEDGER_URL")}, {"apps/ledger/main.py": "x = 1\n"})
    _assert_today(vt3, files3, af.ENV_SET_BY_PLATFORM)
    # a key HB-05 binds from bespoke IaC (custom.tf bucket -> GCS_BUCKET_NAME)
    files4 = _tree({"security.py": EX02_1110_SECURITY.replace(NAME, "GCS_BUCKET_NAME")},
                   {CUSTOM_TF: 'resource "google_storage_bucket" "b" {\n  name     = "b"\n  location = "US"\n}\n'})
    _assert_today(vt, files4, af.ENV_SET_BY_PLATFORM)


UNKNOWN_ENV = {
    "tfvars sets env_vars": {"infra/workload/terraform.tfvars": f'env_vars = {{ {NAME} = "x" }}\n'},
    "auto tfvars sets env_vars": {"infra/workload/team.auto.tfvars": 'env_vars = {}\n'},
    "json tfvars sets env_vars": {"infra/workload/terraform.tfvars.json": '{"env_vars": {}}'},
    "unparseable auto tfvars": {"infra/workload/x.auto.tfvars": "env_vars = {\n"},
    "repo-root tfvars sets env_vars": {"terraform.tfvars": 'env_vars = {}\n'},
    "override file declares the callee's module": {
        "infra/workload/human_override.tf": f'module "compute_core_service" {{\n  env_vars = {{ "{NAME}" = "x" }}\n}}\n'},
    "repository file declares the callee's module": {
        "infra/workload/legacy.tf": 'module "compute_core_service" {\n  source = "../modules/compute-cloudrun"\n}\n'},
    "json root file declares the callee's module": {
        "infra/workload/extra.tf.json": '{"module": {"compute_core_service": {"source": "../modules/compute-cloudrun"}}}'},
    "root file redeclares var.env_vars": {"infra/workload/human.tf": 'variable "env_vars" {\n  default = {}\n}\n'},
    "unparseable root file": {"infra/workload/broken.tf": 'resource "x" "y" {\n'},
}


@pytest.mark.parametrize("case", sorted(UNKNOWN_ENV))
def test_an_unknown_callee_env_set_keeps_the_url(case):
    vt = _vt()
    files = _tree({"security.py": EX02_1110_SECURITY}, UNKNOWN_ENV[case])
    names, why = tw.callee_env_names(vt, CALLEE, files)
    assert names is None and why
    _assert_today(vt, files, af.CALLEE_ENV_UNKNOWN)


def test_platform_tfvars_without_env_vars_are_known():
    vt = _vt()
    files = _tree({"security.py": EX02_1110_SECURITY},
                  {"infra/workload/terraform.tfvars": 'allow_unauthenticated = true\nmemory_limit = "1Gi"\n'})
    assert _render(vt, files)[KEY] == f'"{AUD}"'


def test_no_env_facts_passed_keeps_the_url():
    vt = _vt()
    files = _tree({"security.py": EX02_1110_SECURITY})
    (d,) = af.edge_audience_decisions(vt, "api-gateway", {KEY: URI}, files, allow_unauthenticated=True)
    assert (d.fact.outcome, d.value) == (af.CALLEE_ENV_UNKNOWN, URI)


NOT_RESOLVED = {
    "getenv without a default": {"auth.py": _auth(f'os.getenv("{NAME}")')},
    "environ.get without a default": {"auth.py": _auth(f'os.environ.get("{NAME}")')},
    "environ subscript": {"auth.py": _auth(f'os.environ["{NAME}"]')},
    "f-string default": {"auth.py": _auth(f'os.getenv("{NAME}", f"https://{{x}}.example")', header="import os\nx = 'a'\n")},
    "concatenated default": {"auth.py": _auth(f'os.getenv("{NAME}", "https://" + "b.example")')},
    "nested getenv default": {"auth.py": _auth(f'os.getenv("{NAME}", os.getenv("B", "{AUD}"))')},
    "computed name": {"auth.py": _auth(f'os.getenv(name(), "{AUD}")', extra="\ndef name():\n    return 'X'\n")},
    "name assigned twice": {"auth.py": _auth(f'os.getenv(N, "{AUD}")', header='import os\nN = "A"\nN = "B"\n')},
    "function-local name": {"auth.py": ("import os\nfrom google.auth.transport import requests\nfrom google.oauth2 "
                                        f'import id_token\n\n\ndef verify(t):\n    a = os.getenv("{NAME}", "{AUD}")\n'
                                        "    return id_token.verify_oauth2_token(t, requests.Request(), audience=a)\n")},
    "extra positional argument": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}", 1)')},
    "unknown keyword": {"auth.py": _auth(f'os.getenv(key="{NAME}", default="{AUD}")')},
    "star arguments": {"auth.py": _auth(f'os.getenv(*ARGS)', header=f'import os\nARGS = ("{NAME}", "{AUD}")\n')},
    "getenv shadowed by a def": {"auth.py": _auth("A", header=(f'from os import getenv\n\n\ndef getenv(n, d):\n    '
                                                               f'return d\n\n\nA = getenv("{NAME}", "{AUD}")\n'))},
    "getenv rebound to a lambda": {"auth.py": _auth("A", header=f'getenv = lambda n, d: d\nA = getenv("{NAME}", "{AUD}")\n')},
    "getenv aliased by value": {"auth.py": _auth("A", header=f'import os\nget = os.getenv\nA = get("{NAME}", "{AUD}")\n')},
    "os is a parameter": {"auth.py": ("from google.auth.transport import requests\nfrom google.oauth2 import id_token\n"
                                      f'\n\ndef verify(t, os):\n    return id_token.verify_oauth2_token(t, requests.Request(), '
                                      f'audience=os.getenv("{NAME}", "{AUD}"))\n')},
    "os is another module": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")', header="import settings_lib as os\n")},
    "callee ships its own os module": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")'),
                                       "os.py": "def getenv(n, d):\n    return 'x'\n"},
    "optional os import": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")', header=(
        "try:\n    import os\nexcept ImportError:\n    os = None\n"))},
    # the callee's own code may set NAME
    "code writes NAME": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")', extra=f'\nos.environ["{NAME}"] = "x"\n')},
    "code setdefaults NAME": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")',
                                               extra=f'\nos.environ.setdefault("{NAME}", "x")\n')},
    "code writes a computed key": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")',
                                                    extra="\ndef put(k, v):\n    os.environ[k] = v\n")},
    "code updates os.environ": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")', extra="\nos.environ.update({})\n")},
    "code putenvs NAME": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")', extra=f'\nos.putenv("{NAME}", "x")\n')},
    "code rebinds os.environ": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")', extra="\nos.environ = {}\n")},
    "code aliases os.environ": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")',
                                                 extra="\nENV = os.environ\nENV['X'] = '1'\n")},
    "os.environ written through an in-tree re-export": {
        "auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")'), "envs.py": "from os import environ\n",
        "boot.py": f'from envs import environ\nenviron["{NAME}"] = "x"\n'},
    "code uses the os module as a value": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")',
                                                            extra="\nsetattr(os, 'getenv', None)\n")},
    "dotenv imported": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")'),
                        "boot.py": "from dotenv import load_dotenv\nload_dotenv()\n"},
    "env file shipped": {"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")'), ".env": f"{NAME}=https://x.example\n"},
}


@pytest.mark.parametrize("case", sorted(NOT_RESOLVED))
def test_unsupported_env_shapes_keep_the_url(case):
    vt = _vt()
    files = _tree(NOT_RESOLVED[case])
    fact = af.callee_audience_fact(files, CALLEE)
    assert fact.outcome == af.UNRESOLVED, fact
    _assert_today(vt, files, af.UNRESOLVED)


def test_conflicting_and_unsafe_env_defaults_keep_the_url():
    vt = _vt()
    two = _tree({"auth.py": _auth(f'os.getenv("{NAME}", "{AUD}")'), "admin.py": _auth('"https://admin.example"')})
    assert af.callee_audience_fact(two, CALLEE).outcome == af.CONFLICTING
    _assert_today(vt, two, af.CONFLICTING)
    unsafe = _tree({"auth.py": _auth(f'os.getenv("{NAME}", "https://a.example/${{x}}")')})
    assert af.callee_audience_fact(unsafe, CALLEE).outcome == af.UNSAFE_LITERAL
    _assert_today(vt, unsafe, af.UNSAFE_LITERAL)


@pytest.mark.parametrize("access, outcome", [(False, af.IAM_ENFORCED), (None, af.ACCESS_UNKNOWN)])
def test_a_private_or_unknown_access_mode_keeps_the_url(access, outcome):
    vt = _vt()
    files = _tree({"security.py": EX02_1110_SECURITY})
    with patch.object(tw, "callee_env_names", side_effect=AssertionError("not consulted off a public workload")):
        _assert_today(vt, files, allow_unauthenticated=access)
    (d,) = af.edge_audience_decisions(vt, "api-gateway", {KEY: URI}, files, allow_unauthenticated=access)
    assert (d.fact.outcome, d.value) == (outcome, URI)


def test_the_secondary_render_site_keeps_the_url_when_the_platform_sets_the_name():
    vt = _vt([{"type": "google_storage_bucket", "logical_name": "files",
               "consumers": [{"service": CALLEE, "env_key": NAME}]}], primary="web",
             edges=(("web", "api-gateway", "http"), ("api-gateway", CALLEE, "http")),
             services=[("web", "cloudrun"), ("api-gateway", "cloudrun"), (CALLEE, "cloudrun")])
    files = _tree({"security.py": EX02_1110_SECURITY}, {"apps/web/main.py": "x = 1\n"})
    te.reconcile_multi_service_declarations(
        files=files, product_id="orders", spec_text="", archetype=vt.archetype, allow_unauthenticated=True,
        assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF], target_services=list(vt.names), topology=vt)
    mods = _modules(files[te.SERVICES_TF])
    assert AUD not in str(mods["compute_api_gateway"]["env_vars"])
    assert NAME in str(mods["compute_core_service"]["env_vars"])


# ------------------------------------------------------------------------- the cache is the tree's only (stale hits)
def test_the_env_decision_is_never_served_from_the_tree_cache():
    files = _tree({"security.py": EX02_1110_SECURITY})
    first = af.callee_audience_fact(files, CALLEE)
    unbound, bound = _vt(), _vt([{"type": "google_storage_bucket", "logical_name": "files",
                                  "consumers": [{"service": CALLEE, "env_key": NAME}]}])
    assert _render(unbound, files)[KEY] == f'"{AUD}"'
    assert _render(bound, files)[KEY] == URI                     # same callee tree, other env set
    assert _render(unbound, files)[KEY] == f'"{AUD}"'
    with_tfvars = dict(files, **{"infra/workload/x.auto.tfvars": "env_vars = {}\n"})   # outside apps/<callee>/
    assert af._tree_key(with_tfvars, CALLEE) == af._tree_key(files, CALLEE)
    assert _render(unbound, with_tfvars)[KEY] == URI
    assert af.callee_audience_fact(files, CALLEE) is first     # the tree fact itself is cached
    calls = []
    real = tw.callee_env_names
    with patch.object(tw, "callee_env_names", side_effect=lambda *a, **kw: calls.append(a) or real(*a, **kw)):
        _render(unbound, files)
        _render(unbound, files)
    assert len(calls) == 2                                       # asked per decision


# ----------------------------------------------------------------- the env set is complete (parity with the renders)
def test_callee_env_names_cover_every_key_both_render_sites_write():
    """Parity: every key the platform writes into the callee's `env_vars` (secondary: services.tf; primary: main.tf
    through the handler's override) is in callee_env_names, on a tree with topology and HB-05 bindings."""
    from developer_agent.handler import DeveloperAgent
    resources = EX02_RESOURCES + [{"type": "google_pubsub_topic", "logical_name": "events",
                                   "consumers": [{"service": CALLEE, "env_key": "EVENTS_TOPIC"}]}]
    bespoke = ('resource "google_storage_bucket" "audit_logs" {\n  name     = "a"\n  location = "US"\n}\n'
               'resource "google_secret_manager_secret" "api-key" {\n  secret_id = "k"\n  replication {\n'
               '    auto {}\n  }\n}\n')
    for primary in ("api-gateway", CALLEE):
        vt = _vt(resources, primary=primary, edges=(("api-gateway", CALLEE, "http"), (CALLEE, "ledger", "http")),
                 services=[("api-gateway", "cloudrun"), (CALLEE, "cloudrun"), ("ledger", "cloudrun")])
        files = _tree({"security.py": EX02_1110_SECURITY,
                       "storage.py": 'import os\nB = os.environ["BUCKET_NAME"]\nT = os.getenv("TOPIC_NAME")\n'},
                      {CUSTOM_TF: bespoke, "apps/ledger/main.py": "x = 1\n"})
        names, why = tw.callee_env_names(vt, CALLEE, files)
        assert why == "", why
        if primary == CALLEE:
            env, _ = DeveloperAgent._topology_primary_overrides(vt, bespoke_root_text(files) or None, files, True)
        else:
            te.reconcile_multi_service_declarations(
                files=files, product_id="orders", spec_text="", archetype=vt.archetype, allow_unauthenticated=True,
                assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF], target_services=list(vt.names),
                topology=vt)
            env = tw.topology_env_vars(vt, CALLEE, bespoke_root_text(
                {p: t for p, t in files.items() if p != te.SERVICES_TF}), files, caller_service=CALLEE,
                allow_unauthenticated=True)
            rendered = _modules(files[te.SERVICES_TF])["compute_core_service"]["env_vars"]
            for k in env:
                assert k in str(rendered)
        assert env and set(env) <= names, sorted(set(env) - names)
        assert {"GCS_BUCKET_NAME", "SECRET_API_KEY", "EVENTS_TOPIC", "LEDGER_URL", "LEDGER_AUDIENCE"} <= set(env)


def test_static_platform_env_names_are_covered():
    """compute-cloudrun's literal `env` names, the Cloud Run deploy workflow's `--update-env-vars` names and the
    rollout nonce are all in the set (the module's names are also pinned to RESERVED_ENV_KEYS elsewhere)."""
    from developer_agent.handler import generate_service_workflow
    vt = _vt()
    names, _ = tw.callee_env_names(vt, CALLEE, _tree({}))
    with open(os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun", "main.tf")) as fh:
        body = hcl2.loads(fh.read())
    module_env = set()
    for res in body["resource"]:
        for svc in res.get("google_cloud_run_v2_service", {}).values():
            for tmpl in svc["template"]:
                for c in tmpl["containers"]:
                    module_env |= {e["name"] for e in c.get("env", []) if "${" not in e["name"]}
                    # CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV: one-name `dynamic "env"` blocks (literal content name)
                    for dyn in c.get("dynamic", []):
                        module_env |= {e["name"] for e in dyn.get("env", {}).get("content", [])
                                       if "${" not in e["name"]}
    assert "GOOGLE_CLOUD_PROJECT" in module_env
    assert module_env and module_env <= names
    workflow = generate_service_workflow(CALLEE, "orders", "example-project", "123", archetype="cloudrun")
    (flag,) = [line.strip() for line in workflow.splitlines() if "--update-env-vars=" in line]
    deploy_env = {pair.split("=", 1)[0] for pair in flag.split("--update-env-vars=", 1)[1].split(",")}
    assert deploy_env and deploy_env <= RESERVED_ENV_KEYS <= names
    with open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py")) as fh:
        tree = ast.parse(fh.read())
    assert any(isinstance(n, ast.Constant) and n.value == tw.DEPLOY_NONCE_ENV for n in ast.walk(tree))
    assert tw.DEPLOY_NONCE_ENV in names


def test_a_non_cloudrun_callee_or_no_tree_is_unknown():
    vt = _vt()
    assert tw.callee_env_names(vt, CALLEE, None)[0] is None
    vt2 = _vt(edges=(("api-gateway", "worker", "pubsub"),), services=[("api-gateway", "cloudrun"),
                                                                       ("worker", "event-worker")])
    assert tw.callee_env_names(vt2, "worker", {})[0] is None


# ------------------------------------------------------------- RT F1: the tree the build deploys, not the render map
def _render_deployed(vt, files, existing, allow_unauthenticated=True):
    return tw.topology_env_vars(vt, "api-gateway", files[CUSTOM_TF], files, caller_service=None,
                                allow_unauthenticated=allow_unauthenticated,
                                deployed_files=tw.deployed_view(files, existing))


REPO_ONLY = {
    "repository-only auto tfvars": {"infra/workload/team.auto.tfvars": f'env_vars = {{ {NAME} = "https://x.run.app" }}\n'},
    "repository-only json tfvars": {"infra/workload/terraform.tfvars.json": '{"env_vars": {}}'},
    "repository-only json root file": {
        "infra/workload/extra.tf.json": '{"module": {"compute_core_service": {"env_vars": {}}}}'},
    "repository-only root tfvars": {"terraform.tfvars": "env_vars = {}\n"},
    "kept callee file writes NAME": {ROOT + "boot.py": f'import os\nos.environ["{NAME}"] = "x"\n'},
    "kept callee .env": {ROOT + ".env": f"{NAME}=x\n"},
    "kept callee Procfile sets NAME": {ROOT + "Procfile": f"web: {NAME}=x gunicorn main:app\n"},
}


@pytest.mark.parametrize("case", sorted(REPO_ONLY))
def test_repository_files_the_build_does_not_rewrite_are_seen(case):
    vt = _vt()
    files = _tree({"security.py": EX02_1110_SECURITY})
    existing = dict(REPO_ONLY[case], **{ROOT + "security.py": "old text, rewritten by this build\n"})
    assert _render(vt, files)[KEY] == f'"{AUD}"'                       # the render map alone binds (unchanged)
    env = _render_deployed(vt, files, existing)
    assert env == _render_today(vt, files) and env[KEY] == URI
    view = tw.deployed_view(files, existing)
    assert view[ROOT + "security.py"] == EX02_1110_SECURITY            # this render wins over the repository
    decisions = af.edge_audience_decisions(vt, "api-gateway", {KEY: URI}, view, allow_unauthenticated=True,
                                           callee_env_names=lambda c: tw.callee_env_names(vt, c, files, view))
    assert [d.fact.outcome for d in decisions] in ([af.CALLEE_ENV_UNKNOWN], [af.UNRESOLVED])


def test_repository_only_tfvars_reach_both_render_sites():
    from developer_agent.handler import DeveloperAgent
    existing = {"infra/workload/team.auto.tfvars": "env_vars = {}\n"}
    vt = _vt(EX02_RESOURCES)
    files = _tree({"security.py": EX02_1110_SECURITY})
    view = tw.deployed_view(files, existing)
    assert DeveloperAgent._topology_primary_overrides(vt, "", files, True)[0][KEY] == f'"{AUD}"'
    assert DeveloperAgent._topology_primary_overrides(vt, "", files, True, deployed_files=view)[0][KEY] == URI
    vt3 = _vt(edges=(("web", "api-gateway", "http"), ("api-gateway", CALLEE, "http")),
              services=[("web", "cloudrun"), ("api-gateway", "cloudrun"), (CALLEE, "cloudrun")], primary="web")
    for deployed, bound in ((None, True), (existing, False)):
        files3 = _tree({"security.py": EX02_1110_SECURITY}, {"apps/web/main.py": "x = 1\n"})
        te.reconcile_multi_service_declarations(
            files=files3, product_id="orders", spec_text="", archetype=vt3.archetype, allow_unauthenticated=True,
            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF], target_services=list(vt3.names),
            topology=vt3, deployed_files=None if deployed is None else tw.deployed_view(files3, deployed))
        assert (AUD in str(_modules(files3[te.SERVICES_TF])["compute_api_gateway"]["env_vars"])) is bound


def test_the_deployed_view_changes_nothing_else():
    """Do No Harm: unrelated repository files leave every binding as the render map has it, HB-05 keys included."""
    vt = _vt(EX02_RESOURCES)
    bespoke = 'resource "google_storage_bucket" "b" {\n  name     = "b"\n  location = "US"\n}\n'
    existing = {"README.md": "x\n", "apps/other/main.py": "import os\nB = os.environ['BUCKET_NAME']\n",
                "infra/workload/terraform.tfvars": "allow_unauthenticated = true\n"}
    for callee_files in ({"security.py": EX02_1110_SECURITY}, {"auth.py": _auth(f'"{AUD}"')},
                         {"auth.py": _auth("compute()", extra="\ndef compute():\n    return 'x'\n")}):
        files = _tree(callee_files, {CUSTOM_TF: bespoke})
        assert _render_deployed(vt, files, existing) == _render(vt, files)
        assert tw.topology_env_vars(vt, CALLEE, bespoke, files, caller_service=CALLEE,
                                    deployed_files=tw.deployed_view(files, existing)) == \
            tw.topology_env_vars(vt, CALLEE, bespoke, files, caller_service=CALLEE)


# ------------------------------------------------------------------------- RT F2: the start command and its config
PROCFILE_SETS_ENV = {
    "inline assignment": {"Procfile": f"web: {NAME}=x gunicorn main:app\n"},
    "env wrapper": {"Procfile": f"web: env {NAME}=x uvicorn main:app --port $PORT\n"},
    "gunicorn -e": {"Procfile": f"web: gunicorn -e {NAME}=x main:app\n"},
    "gunicorn --env=": {"Procfile": f"web: gunicorn --env={NAME}=x main:app\n"},
    "gunicorn config file": {"Procfile": "web: gunicorn -c conf.py main:app\n"},
    "uvicorn env file": {"Procfile": "web: uvicorn main:app --port $PORT --env-file prod.env\n"},
    "start script": {"Procfile": "web: ./start.sh\n", "start.sh": f"export {NAME}=x\nexec gunicorn main:app\n"},
    "bash script": {"Procfile": "web: bash start.sh\n"},
    "export in sh -c": {"Procfile": f'web: sh -c "export {NAME}=x && gunicorn main:app"\n'},
    "source before the server": {"Procfile": "web: . ./vars.sh && gunicorn main:app\n"},
    "unknown launcher": {"Procfile": "web: fastapi run main.py\n"},
    "unparseable line": {"Procfile": "web gunicorn main:app\n"},
    "unsplittable command": {"Procfile": "web: gunicorn 'main:app\n"},
    "gunicorn.conf.py raw_env": {"gunicorn.conf.py": f'raw_env = ["{NAME}=x"]\n'},
    "project.toml": {"project.toml": "[[build.env]]\nname = \"GOOGLE_ENTRYPOINT\"\nvalue = \"x\"\n"},
    ".flaskenv": {".flaskenv": f"{NAME}=x\n"},
}


@pytest.mark.parametrize("case", sorted(PROCFILE_SETS_ENV))
def test_a_start_command_that_may_set_env_keeps_the_url(case):
    vt = _vt()
    files = _tree(dict(PROCFILE_SETS_ENV[case], **{"security.py": EX02_1110_SECURITY}))
    fact = af.callee_audience_fact(files, CALLEE)
    assert fact.outcome == af.UNRESOLVED, fact
    _assert_today(vt, files, af.UNRESOLVED)


@pytest.mark.parametrize("procfile", [
    "web: gunicorn -b :$PORT main:app\n",
    "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
    "web: exec gunicorn --bind=0.0.0.0:$PORT -w 2 main:app\n",
    "web: alembic upgrade head && exec uvicorn main:app --port $PORT\n",
    'web: sh -c "uvicorn main:app --port $PORT"\n',
    "web: python main.py\n",
    "web: python -m uvicorn main:app --port ${PORT:-8080}\n",
])
def test_a_plain_start_command_still_binds(procfile):
    vt = _vt()
    files = _tree({"security.py": EX02_1110_SECURITY, "Procfile": procfile})
    assert af.callee_audience_fact(files, CALLEE).outcome == af.LITERAL_ENV_DEFAULT
    assert _render(vt, files)[KEY] == f'"{AUD}"'


def test_the_procfile_is_part_of_the_tree_key():
    plain = _tree({"security.py": EX02_1110_SECURITY, "Procfile": "web: gunicorn main:app\n"})
    first = af.callee_audience_fact(plain, CALLEE)
    assert first.outcome == af.LITERAL_ENV_DEFAULT
    changed = dict(plain, **{ROOT + "Procfile": f"web: {NAME}=x gunicorn main:app\n"})
    assert af._tree_key(changed, CALLEE) != af._tree_key(plain, CALLEE)
    assert af.callee_audience_fact(changed, CALLEE).outcome == af.UNRESOLVED
    assert af.callee_audience_fact(plain, CALLEE) is first


def test_a_procfile_never_changes_a_constant_literal():
    """Do No Harm: the start-command checks run only for an env-default audience."""
    files = _tree({"auth.py": _auth(f'"{AUD}"'), "Procfile": f"web: {NAME}=x ./start.sh\n",
                   "gunicorn.conf.py": 'raw_env = ["A=b"]\n', "boot.py": "import ab_test\n",
                   "ab_test.py": "x = 1\n"})
    assert af.callee_audience_fact(files, CALLEE).outcome == af.LITERAL


# ----------------------------------------------------------------------- RT F3: a module named like a test is imported
@pytest.mark.parametrize("callee_files", [
    {"boot.py": "import ab_test\n", "ab_test.py": f'import os\nos.environ["{NAME}"] = "x"\n'},
    {"boot.py": "from tests import helpers\n", "tests/__init__.py": "",
     "tests/helpers.py": f'import os\nos.environ["{NAME}"] = "x"\n'},
    {"pkg/__init__.py": "", "pkg/boot.py": "def f():\n    from . import conftest\n", "pkg/conftest.py": ""},
], ids=["bare-import", "from-tests-package", "relative-import-in-a-function"])
def test_an_imported_test_named_module_keeps_the_url(callee_files):
    vt = _vt()
    files = _tree(dict(callee_files, **{"security.py": EX02_1110_SECURITY}))
    fact = af.callee_audience_fact(files, CALLEE)
    assert fact.outcome == af.UNRESOLVED and "named like a test" in fact.detail, fact
    _assert_today(vt, files, af.UNRESOLVED)


def test_a_test_module_nothing_imports_is_not_a_write():
    files = _tree({"security.py": EX02_1110_SECURITY, "tests/test_x.py": f'import os\nos.environ["{NAME}"] = "x"\n'})
    assert af.callee_audience_fact(files, CALLEE).outcome == af.LITERAL_ENV_DEFAULT


# --------------------------------------------------------------------- RT F4: the env facts raise -> URL, logged
def test_a_raising_env_fact_keeps_the_url_and_is_logged(caplog):
    vt = _vt()
    files = _tree({"security.py": EX02_1110_SECURITY})

    def boom(_callee):
        raise RuntimeError("surprise")

    with caplog.at_level(logging.WARNING, logger="castor-audience-facts"):
        (d,) = af.edge_audience_decisions(vt, "api-gateway", {KEY: URI}, files, allow_unauthenticated=True,
                                          callee_env_names=boom)
    assert (d.fact.outcome, d.value) == (af.CALLEE_ENV_UNKNOWN, URI) and "RuntimeError" in d.fact.detail
    assert any("SIBLING_AUDIENCE_ENV_FACTS_FAILED" in r.getMessage() and "RuntimeError" in r.getMessage()
               for r in caplog.records)
    with patch.object(tw, "callee_env_names", side_effect=KeyError("x")):
        assert _render(vt, files)[KEY] == URI


# ------------------------------------------------------------------------------------- RT F7: the empty default
def test_an_empty_default_is_reported_as_an_empty_literal():
    fact = af.callee_audience_fact(_tree({"auth.py": _auth(f'os.getenv("{NAME}", "")')}), CALLEE)
    assert (fact.outcome, fact.detail) == (af.UNSAFE_LITERAL, "empty literal")

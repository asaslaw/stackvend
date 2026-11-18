"""RUNTIME-ENV-CONTRACT-CHECK (owner 11-10, warning-only for launch; docs/implemented/runtime-env-contract-check-plan.md).

V-ENV reports, report-only, every environment variable a topology service's non-test code reads (ast facts only)
that the platform's typed env set for that service (topology_wiring.callee_env_names) does not hold. Live cases: the
11-10 run read GOOGLE_CLOUD_PROJECT / GCP_PROJECT with a default while the platform set only PROJECT_ID (since
CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV the golden module sets GOOGLE_CLOUD_PROJECT, so the fixtures use names it still does
not set); the 11-09 example 02 callee read OIDC_AUDIENCE, which the platform never set. Never blocks, never changes a tree, a prompt or a
rendered value (Invariant 1). Hermetic, no I/O."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import inspect
import logging
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import runtime_env_facts as R  # noqa: E402
from developer_agent import topology_wiring as tw  # noqa: E402
from developer_agent.assembly import CUSTOM_TF  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators import runtime_env as V  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.service_topology import RESERVED_ENV_KEYS, validate_service_topology  # noqa: E402

SVC = "dispatcher"
ROOT = f"apps/{SVC}/"

# The 11-10 shape: the project read from env names with a literal fallback, nested. The platform sets PROJECT_ID,
# GCP_PROJECT_ID and (CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV) GOOGLE_CLOUD_PROJECT, but neither name here.
TONIGHT = '''import os

PROJECT = os.getenv("GCP_PROJECT", os.getenv("GCLOUD_PROJECT", "local-project"))
'''
# The recorded example 03 run 2 shape (apps/dispatcher/config.py:56): the outer name is now set by the platform, so
# the inner read's value is never used (EnvRead.shadowed_by).
EX03_R2 = '''import os

PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT", os.getenv("GCP_PROJECT", ""))
'''
# The 11-09 example 02 callee shape (apps/core-service/security.py).
EX02_SECURITY = '''import os
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

EXPECTED_AUDIENCE: str = os.getenv("OIDC_AUDIENCE", "https://service-b.orders.example")


def verify_caller(token_str):
    return id_token.verify_oauth2_token(token_str, google_requests.Request(), audience=EXPECTED_AUDIENCE)
'''


def _vt(services=((SVC, "cloudrun"),), primary=SVC, edges=(), resources=()):
    raw = {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
           "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges], "resources": list(resources)}
    vt, diags = validate_service_topology(raw, product_id="orders")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def _tree(service_files, root=ROOT, extra=None):
    files = {CUSTOM_TF: ""}
    files.update({root + rel: text for rel, text in service_files.items()})
    files.update(extra or {})
    return files


def _not_provided(vt, files):
    return [f for f in R.runtime_env_findings(vt, files) if f.code == R.READ_NOT_PROVIDED]


# ------------------------------------------------------------------------------------------------ live shapes
def test_tonights_shape_gives_advisories_with_the_default_as_written():
    found = _not_provided(_vt(), _tree({"config.py": TONIGHT}))
    by_name = {f.name: f for f in found}
    assert sorted(by_name) == ["GCLOUD_PROJECT", "GCP_PROJECT"]
    outer, inner = by_name["GCP_PROJECT"], by_name["GCLOUD_PROJECT"]
    assert (outer.service, outer.file, outer.line, outer.form) == (SVC, ROOT + "config.py", 3, R.FORM_GETENV)
    assert outer.has_default is True and outer.default_is_literal is False
    assert outer.default == "os.getenv('GCLOUD_PROJECT', 'local-project')"
    assert (inner.has_default, inner.default, inner.default_is_literal) == (True, "local-project", True)
    assert "local-project" in inner.message and "GCLOUD_PROJECT" in inner.message


def test_tonights_shape_with_one_read_gives_exactly_one_advisory():
    code = 'import os\nPROJECT = os.getenv("GCP_PROJECT", "local-project")\n'
    (f,) = _not_provided(_vt(), _tree({"config.py": code}))
    assert (f.name, f.has_default, f.default) == ("GCP_PROJECT", True, "local-project")


def test_the_same_code_once_the_platform_provides_the_name_gives_none(monkeypatch):
    code = 'import os\nPROJECT = os.getenv("GCP_PROJECT", "local-project")\n'
    assert len(_not_provided(_vt(), _tree({"config.py": code}))) == 1
    # a module change that adds the name to the module's static env, i.e. RESERVED_ENV_KEYS
    import shared.service_topology as st
    monkeypatch.setattr(st, "RESERVED_ENV_KEYS", frozenset(RESERVED_ENV_KEYS | {"GCP_PROJECT"}))
    assert _not_provided(_vt(), _tree({"config.py": code})) == []


def test_google_cloud_project_is_provided_since_the_module_sets_it():
    # CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV (main 0ec5ac35): the 11-10 single-read shape no longer warns
    assert "GOOGLE_CLOUD_PROJECT" in RESERVED_ENV_KEYS
    code = 'import os\nPROJECT = os.getenv("GOOGLE_CLOUD_PROJECT", "local-project")\n'
    assert _not_provided(_vt(), _tree({"config.py": code})) == []


def test_a_name_provided_by_a_topology_binding_gives_none():
    code = 'import os\nPROJECT = os.getenv("GCP_PROJECT", "local-project")\n'
    res = [{"type": "google_storage_bucket", "logical_name": "media",
            "consumers": [{"service": SVC, "env_key": "GCP_PROJECT"}]}]
    assert _not_provided(_vt(resources=res), _tree({"config.py": code})) == []


def test_the_ex02_oidc_audience_shape_gives_one_advisory():
    vt = _vt(services=(("api-gateway", "cloudrun"), ("core-service", "cloudrun")), primary="api-gateway",
             edges=(("api-gateway", "core-service", "http"),))
    files = _tree({"security.py": EX02_SECURITY, "main.py": "from fastapi import FastAPI\napp = FastAPI()\n"},
                  root="apps/core-service/",
                  extra={"apps/api-gateway/main.py": 'import os\nAUD = os.environ["CORE_SERVICE_AUDIENCE"]\n'})
    (f,) = _not_provided(vt, files)
    assert (f.service, f.name, f.file, f.line) == ("core-service", "OIDC_AUDIENCE", "apps/core-service/security.py", 5)
    assert (f.has_default, f.default) == (True, "https://service-b.orders.example")


def test_platform_names_never_warn():
    names = sorted(RESERVED_ENV_KEYS | {tw.DEPLOY_NONCE_ENV})
    reads = "\n".join(f'v{i} = os.environ["{n}"]' for i, n in enumerate(names))
    assert _not_provided(_vt(), _tree({"main.py": "import os\n" + reads + "\n"})) == []


# ------------------------------------------------------------------------------------------------ read forms
@pytest.mark.parametrize("code,form", [
    ('import os\nX = os.getenv("APP_MODE")\n', R.FORM_GETENV),
    ('import os\nX = os.environ.get("APP_MODE", "a")\n', R.FORM_ENVIRON_GET),
    ('import os\nX = os.environ["APP_MODE"]\n', R.FORM_ENVIRON_SUBSCRIPT),
    ('import os as o\nX = o.getenv("APP_MODE")\n', R.FORM_GETENV),
    ('from os import getenv\nX = getenv("APP_MODE")\n', R.FORM_GETENV),
    ('from os import getenv as g\nX = g("APP_MODE")\n', R.FORM_GETENV),
    ('from os import environ\nX = environ["APP_MODE"]\n', R.FORM_ENVIRON_SUBSCRIPT),
    ('from os import environ as e\nX = e.get("APP_MODE")\n', R.FORM_ENVIRON_GET),
    ('import os.path\nX = os.getenv(key="APP_MODE", default="a")\n', R.FORM_GETENV),
    ('import os\nKEY = "APP_MODE"\nX = os.getenv(KEY)\n', R.FORM_GETENV),               # module-constant NAME
    ('import os\nKEY: str = "APP_MODE"\n\ndef f():\n    return os.environ[KEY]\n', R.FORM_ENVIRON_SUBSCRIPT),
])
def test_read_forms_are_resolved(code, form):
    (f,) = _not_provided(_vt(), _tree({"main.py": code}))
    assert (f.name, f.form) == ("APP_MODE", form)


def test_a_name_imported_from_the_services_own_module_and_a_helper_module_getter():
    files = _tree({"names.py": 'KEY = "APP_MODE"\n', "env.py": "from os import getenv\n",
                   "main.py": "from names import KEY\nfrom env import getenv\nX = getenv(KEY)\n"})
    (f,) = _not_provided(_vt(), files)
    assert (f.name, f.file, f.line) == ("APP_MODE", ROOT + "main.py", 3)


def test_has_default_and_no_default():
    code = ('import os\nA = os.getenv("NO_DEFAULT")\nB = os.environ["SUBSCRIPT"]\nC = os.getenv("NONE_DEFAULT", None)\n'
            'D = os.getenv("INT_DEFAULT", 5)\n')
    got = {f.name: (f.has_default, f.default, f.default_is_literal) for f in _not_provided(_vt(), _tree({"m.py": code}))}
    assert got == {"NO_DEFAULT": (False, None, None), "SUBSCRIPT": (False, None, None),
                   "NONE_DEFAULT": (True, "None", True), "INT_DEFAULT": (True, "5", True)}


def test_a_long_default_is_trimmed():
    code = f'import os\nA = os.getenv("LONG", "{"x" * 300}")\n'
    (f,) = _not_provided(_vt(), _tree({"m.py": code}))
    assert len(f.default) == R.DEFAULT_TEXT_MAX and f.default.endswith("...")


@pytest.mark.parametrize("code", [
    'import os\n\ndef f(name):\n    return os.getenv(name)\n',
    'import os\nX = os.environ[f"{1}_KEY"]\n',
    'import os\nPREFIX = "APP"\nX = os.getenv(PREFIX + "_MODE")\n',
    'import os\nKEY = "A"\nKEY = "B"\nX = os.getenv(KEY)\n',         # rebound: not one constant
    'import os\nargs = ["APP_MODE"]\nX = os.getenv(*args)\n',
])
def test_dynamic_names_are_unresolved_and_never_reported(code):
    files = _tree({"m.py": code})
    assert _not_provided(_vt(), files) == []
    facts = R.service_env_reads(files, SVC)
    assert facts.reads == () and len(facts.unresolved) == 1


@pytest.mark.parametrize("code", [
    'config = {}\nX = config.get("APP_MODE")\n',
    'import os\nenviron = {}\nX = environ["APP_MODE"]\n',                        # a local dict named environ
    'def getenv(k):\n    return k\nX = getenv("APP_MODE")\n',                     # a local function named getenv
    'import os\nX = "APP_MODE" in os.environ\n',                                  # a presence test is not a read
    'import os\nos.environ["APP_MODE"] = "x"\n',                                   # a write is not a read
])
def test_things_that_are_not_env_reads(code):
    files = _tree({"m.py": code})
    assert _not_provided(_vt(), files) == [] and R.service_env_reads(files, SVC).reads == ()


@pytest.mark.parametrize("write", [
    'os.environ["APP_MODE"] = "a"',
    'os.environ.setdefault("APP_MODE", "a")',
    'os.putenv("APP_MODE", "a")',
])
def test_a_name_the_service_itself_writes_is_not_reported(write):
    code = f'import os\n{write}\nX = os.environ["APP_MODE"]\n'
    assert _not_provided(_vt(), _tree({"m.py": code})) == []


# ------------------------------------------------------------------------------------------------ scope
@pytest.mark.parametrize("rel", ["test_config.py", "config_test.py", "conftest.py", "tests/helpers.py"])
def test_test_files_are_ignored(rel):
    files = _tree({rel: 'import os\nX = os.getenv("TEST_ONLY_NAME")\n', "main.py": "X = 1\n"})
    assert _not_provided(_vt(), files) == []


def test_code_outside_the_services_directory_is_not_read():
    files = _tree({"main.py": "X = 1\n"}, extra={"tests/test_main.py": 'import os\nos.getenv("A_NAME")\n',
                                                  "contracts/schemas.py": 'import os\nos.getenv("B_NAME")\n'})
    assert R.runtime_env_findings(_vt(), files) == []


def test_unknown_provided_set_gives_no_read_advisory_and_one_unknown_note():
    files = _tree({"config.py": TONIGHT}, extra={"infra/workload/terraform.tfvars": 'env_vars = { A = "b" }\n'})
    (f,) = R.runtime_env_findings(_vt(), files)
    assert f.code == R.PROVIDED_SET_UNKNOWN and f.service == SVC and "env_vars" in f.reason


def test_unknown_note_only_when_the_service_reads_a_constant_name():
    files = _tree({"main.py": "X = 1\n"}, extra={"infra/workload/terraform.tfvars": 'env_vars = { A = "b" }\n'})
    assert R.runtime_env_findings(_vt(), files) == []


def test_no_topology_or_no_tree_gives_nothing():
    assert R.runtime_env_findings(None, _tree({"config.py": TONIGHT})) == []
    assert R.runtime_env_findings(_vt(), {}) == []


def test_multi_service_sets_are_per_service():
    # the edge gives the caller CORE_URL; the callee does not get it, and a non-Cloud-Run service is unknown
    vt = _vt(services=(("api", "cloudrun"), ("core", "cloudrun"), ("proc", "gce-worker")), primary="api",
             edges=(("api", "core", "http"), ("api", "proc", "launch")))
    read = 'import os\nX = os.environ["CORE_URL"]\n'
    files = {CUSTOM_TF: "", "apps/api/main.py": read, "apps/core/main.py": read, "apps/proc/main.py": read}
    found = R.runtime_env_findings(vt, files)
    assert [(f.code, f.service, f.name) for f in found] == [
        (R.READ_NOT_PROVIDED, "core", "CORE_URL"), (R.PROVIDED_SET_UNKNOWN, "proc", None)]
    assert "proc" in found[1].reason and "not a Cloud Run service" in found[1].reason


def test_findings_are_deterministic_and_records_are_plain_json():
    files = _tree({"b.py": 'import os\nB = os.getenv("B_NAME")\n', "a.py": 'import os\nA = os.getenv("A_NAME", "x")\n'})
    one, two = R.runtime_env_findings(_vt(), files), R.runtime_env_findings(_vt(), dict(reversed(list(files.items()))))
    assert one == two and [f.name for f in one] == ["A_NAME", "B_NAME"]
    rec = one[0].record()
    assert rec == {"code": R.READ_NOT_PROVIDED, "service": SVC, "message": one[0].message, "file": ROOT + "a.py",
                   "line": 2, "name": "A_NAME", "form": R.FORM_GETENV, "has_default": True, "default": "x",
                   "default_is_literal": True}


def test_a_file_that_does_not_parse_is_skipped_not_fatal():
    files = _tree({"bad.py": "def (:\n", "ok.py": 'import os\nX = os.getenv("APP_MODE")\n'})
    assert [f.name for f in _not_provided(_vt(), files)] == ["APP_MODE"]


def test_the_module_reads_code_with_ast_only():
    # Invariant 2: no regex / substring heuristics on source text in the new module
    src = inspect.getsource(R)
    names = {n.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Name)}
    assert "re" not in names
    assert not any(isinstance(n, ast.Import) and any(a.name == "re" for a in n.names) for n in ast.walk(ast.parse(src)))


# ------------------------------------------------------------------------------------------------ policy / wiring
def test_registered_report_only_in_the_step1_stack():
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert V.VALIDATOR_ID in stack.ids and stack.mode_of(V.VALIDATOR_ID) == "report_only"
    assert V.RUNTIME_ENV_MODE == "report_only"
    assert stack.ids.index(V.VALIDATOR_ID) == stack.ids.index("V-K8S-WI") + 1


def _ctx(files):
    return ValidationContext.build(files, ownership=lambda p: None)


def test_findings_land_in_report_only_and_never_change_pass_or_fail():
    stack = ValidatorStack()
    V.register(stack, _vt())
    rep = stack.run(_ctx(_tree({"config.py": TONIGHT})))
    assert rep.status == "PASS" and rep.diagnostics == [] and V.VALIDATOR_ID in rep.tools_ran
    assert sorted(d.code for d in rep.report_only) == [R.READ_NOT_PROVIDED] * 2
    d = rep.report_only[0]
    assert (d.severity, d.tool, d.source, d.file, d.symbol) == ("warning", "ast", "precommit", ROOT + "config.py",
                                                                 "GCLOUD_PROJECT")


def test_a_raising_check_is_unavailable_but_never_blocks(monkeypatch):
    stack = ValidatorStack()
    V.register(stack, _vt())
    monkeypatch.setattr(V, "runtime_env_findings", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    rep = stack.run(_ctx(_tree({"config.py": TONIGHT})))
    assert rep.status == "PASS" and rep.tools_unavailable == [V.VALIDATOR_ID] and rep.report_only == []


def test_blocking_mode_is_the_single_switch_and_an_unknown_set_never_blocks(monkeypatch):
    monkeypatch.setattr(V, "RUNTIME_ENV_MODE", "blocking")
    stack = ValidatorStack()
    V.register(stack, _vt())
    assert stack.mode_of(V.VALIDATOR_ID) == "blocking"
    rep = stack.run(_ctx(_tree({"config.py": TONIGHT})))
    assert rep.status == "FAIL" and rep.report_only == []
    assert [(d.code, d.severity) for d in rep.diagnostics] == [(R.READ_NOT_PROVIDED, "error")] * 2
    unknown = _tree({"config.py": TONIGHT}, extra={"infra/workload/terraform.tfvars": 'env_vars = { A = "b" }\n'})
    rep = stack.run(_ctx(unknown))
    assert rep.status == "PASS" and [(d.code, d.severity) for d in rep.diagnostics] == [
        (R.PROVIDED_SET_UNKNOWN, "warning")]


def test_no_topology_registers_and_reports_nothing():
    stack = ValidatorStack()
    V.register(stack, None)
    rep = stack.run(_ctx(_tree({"config.py": TONIGHT})))
    assert rep.status == "PASS" and rep.report_only == []


# ------------------------------------------------------------------------------------------------ workload record
def _agent(db):
    from developer_agent import handler as h
    agent = h.DeveloperAgent.__new__(h.DeveloperAgent)
    agent.db = db
    return h, agent


def test_the_developer_stage_stores_the_advisories_on_the_workload_record(caplog):
    db = MagicMock()
    h, agent = _agent(db)
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    inputs = SimpleNamespace(product_id="orders", trace_id="t1", compute_intent=SimpleNamespace(topology=_vt()),
                             existing_files={})
    tree = _tree({"config.py": TONIGHT})
    with caplog.at_level(logging.WARNING):
        h.DeveloperAgent._runtime_env_outcome(agent, inputs, tree, stack)
    db.collection.assert_called_with("workloads")
    db.collection.return_value.document.assert_called_with("orders")
    (payload,), kw = db.collection.return_value.document.return_value.set.call_args
    assert kw == {"merge": True} and payload["runtime_env_advisories_trace_id"] == "t1"
    assert [a["name"] for a in payload["runtime_env_advisories"]] == ["GCLOUD_PROJECT", "GCP_PROJECT"]
    assert payload["runtime_env_advisories_total"] == 2
    assert agent.stack_run("t1")["runtime_env_advisories"] == payload["runtime_env_advisories"]
    assert sum("RUNTIME_ENV_ADVISORY ENV.READ_NOT_PROVIDED" in r.getMessage() for r in caplog.records) == 2
    # a clean build clears the record
    h.DeveloperAgent._runtime_env_outcome(agent, inputs, _tree({"config.py": "X = 1\n"}), stack)
    assert db.collection.return_value.document.return_value.set.call_args.args[0]["runtime_env_advisories"] == []


def test_mode_off_writes_nothing_and_a_failure_is_logged_not_raised(caplog, monkeypatch):
    db = MagicMock()
    h, agent = _agent(db)
    inputs = SimpleNamespace(product_id="orders", trace_id="t2", compute_intent=SimpleNamespace(topology=_vt()),
                             existing_files={})
    off = build_step1_stack(validate_client=None, verifier_factory=None, modes={V.VALIDATOR_ID: "off"})
    h.DeveloperAgent._runtime_env_outcome(agent, inputs, _tree({"config.py": TONIGHT}), off)
    assert not db.collection.called
    # no topology (legacy path): the check does not apply, the workload record is not touched
    legacy = SimpleNamespace(product_id="orders", trace_id="t3", compute_intent=SimpleNamespace(topology=None),
                             existing_files={})
    h.DeveloperAgent._runtime_env_outcome(agent, legacy, _tree({"config.py": TONIGHT}),
                                          build_step1_stack(validate_client=None, verifier_factory=None))
    assert not db.collection.called and "runtime_env_advisories" not in agent.stack_run("t3")
    on = build_step1_stack(validate_client=None, verifier_factory=None)
    monkeypatch.setattr(R, "runtime_env_result", lambda *a, **k: (_ for _ in ()).throw(KeyError("x")))
    with caplog.at_level(logging.WARNING):
        h.DeveloperAgent._runtime_env_outcome(agent, inputs, _tree({"config.py": TONIGHT}), on)
    assert not db.collection.called
    assert any("RUNTIME_ENV_CHECK_FAILED" in r.getMessage() for r in caplog.records)


def test_the_stage_outcome_hook_runs_after_the_report_is_persisted():
    from developer_agent import handler as h
    src = inspect.getsource(h.DeveloperAgent._run_hallucination_stack)
    assert src.index("self._persist_stack_outcome(inputs.trace_id, report, events)\n") < src.index(
        "self._runtime_env_outcome(inputs, tree, stack)") < src.index("return tree")


def test_the_workload_page_renders_the_advisories():
    with open(os.path.join(REPO_ROOT, "apps/control-center/templates/dashboard.html"), encoding="utf-8") as fh:
        html = fh.read()
    assert 'data-testid="runtime-env-advisories"' in html
    assert 'x-for="(a, i) in workloadDetails.runtime_env_advisories"' in html and 'x-text="a.message"' in html
    from importlib import util
    spec = util.spec_from_file_location("cc_schemas_env", os.path.join(REPO_ROOT, "apps/control-center/schemas.py"))
    mod = util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert {"runtime_env_advisories", "runtime_env_advisories_total"} <= set(mod.WorkloadDetailsResponse.model_fields)


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_the_check_never_mutates_the_tree():
    files = _tree({"config.py": TONIGHT})
    before = dict(files)
    R.runtime_env_findings(_vt(), files)
    stack = ValidatorStack()
    V.register(stack, _vt())
    stack.run(_ctx(files))
    assert files == before


# ------------------------------------------------------------------------------------------------ shadowed reads
def test_a_read_inside_the_default_of_a_provided_read_is_not_reported():
    # the recorded 03-r2 / 05-r2 shape: GOOGLE_CLOUD_PROJECT is set, so GCP_PROJECT's value is never used
    files = _tree({"config.py": EX03_R2})
    assert R.runtime_env_findings(_vt(), files) == []
    (inner,) = [r for r in R.service_env_reads(files, SVC).reads if r.name == "GCP_PROJECT"]
    assert inner.shadowed_by == ("GOOGLE_CLOUD_PROJECT",)
    assert R.summary(_vt(), files)["services"][SVC]["shadowed"] == ["GCP_PROJECT<GOOGLE_CLOUD_PROJECT"]


@pytest.mark.parametrize("code,expected", [
    # provided outer (PROJECT_ID): every read anywhere inside its default is unused
    ('import os\nX = os.getenv("PROJECT_ID", os.getenv("A_NAME", os.environ["B_NAME"]))\n', []),
    ('import os\nX = os.environ.get("PROJECT_ID", default=str(os.getenv("A_NAME")))\n', []),
    # outer not provided: the outer is reported and the inner value can be used
    ('import os\nX = os.getenv("A_NAME", os.getenv("B_NAME", "x"))\n', ["A_NAME", "B_NAME"]),
    # middle provided: the outer is reported, only what is inside the provided read's default is unused
    ('import os\nX = os.getenv("A_NAME", os.getenv("PROJECT_ID", os.getenv("B_NAME")))\n', ["A_NAME"]),
    # a walrus inside the default binds a name the code may use later: nothing is shadowed
    ('import os\nX = os.getenv("PROJECT_ID", (y := os.getenv("B_NAME")))\nZ = y\n', ["B_NAME"]),
    # `or` is not a default argument: no typed rule, both reads stand
    ('import os\nX = os.getenv("PROJECT_ID") or os.getenv("B_NAME")\n', ["B_NAME"]),
    # a read next to (not inside) a provided read's default is not shadowed
    ('import os\nX = (os.getenv("PROJECT_ID", "p"), os.getenv("B_NAME"))\n', ["B_NAME"]),
])
def test_shadowing_is_exactly_the_default_subtree_of_a_provided_read(code, expected):
    assert sorted(f.name for f in _not_provided(_vt(), _tree({"m.py": code}))) == expected


def test_a_name_the_code_writes_shadows_the_reads_in_its_default():
    code = 'import os\nos.environ["A_NAME"] = "a"\nX = os.getenv("A_NAME", os.getenv("B_NAME"))\n'
    assert _not_provided(_vt(), _tree({"m.py": code})) == []


# ------------------------------------------------------------------------------------------------ deployed view
TFVARS_ENV = {"infra/workload/terraform.tfvars": 'env_vars = { GCP_PROJECT = "p" }\n'}
OVERRIDE_MODULE = {"infra/workload/zz_override.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n'}


@pytest.mark.parametrize("repo", [TFVARS_ENV, OVERRIDE_MODULE])
def test_repository_files_the_build_does_not_rewrite_make_the_set_unknown_in_the_validator(repo):
    files = _tree({"config.py": TONIGHT})
    stack = ValidatorStack()
    V.register(stack, _vt())
    assert {d.code for d in stack.run(_ctx(files)).report_only} == {R.READ_NOT_PROVIDED}
    ctx = ValidationContext.build(files, ownership=lambda p: None, extras={"preexisting_files": dict(repo)})
    assert [d.code for d in stack.run(ctx).report_only] == [R.PROVIDED_SET_UNKNOWN]


def test_repository_files_make_the_set_unknown_on_the_workload_record():
    db = MagicMock()
    h, agent = _agent(db)
    inputs = SimpleNamespace(product_id="orders", trace_id="t4", compute_intent=SimpleNamespace(topology=_vt()),
                             existing_files=dict(TFVARS_ENV))
    h.DeveloperAgent._runtime_env_outcome(agent, inputs, _tree({"config.py": TONIGHT}),
                                          build_step1_stack(validate_client=None, verifier_factory=None))
    (payload,), _ = db.collection.return_value.document.return_value.set.call_args
    assert [a["code"] for a in payload["runtime_env_advisories"]] == [R.PROVIDED_SET_UNKNOWN]


# ------------------------------------------------------------------------------------------------ bounds
def _many(n, prefix="N"):
    return "import os\n" + "".join(f'v{i} = os.getenv("{prefix}_{i:04d}")\n' for i in range(n))


def test_findings_are_capped_per_service_and_per_workload_with_a_total():
    import time
    t0 = time.monotonic()
    res = R.runtime_env_result(_vt(), _tree({"m.py": _many(300)}))
    assert time.monotonic() - t0 < 10.0
    assert (len(res.findings), res.total) == (R.MAX_FINDINGS_PER_SERVICE, 300)
    names = [f"s{i}" for i in range(4)]
    vt = _vt(services=tuple((n, "cloudrun") for n in names), primary="s0")
    files = {CUSTOM_TF: "", **{f"apps/{n}/m.py": _many(30, n.upper()) for n in names}}
    res = R.runtime_env_result(vt, files)
    assert res.total == 120 and len(res.findings) == R.MAX_FINDINGS
    assert {f.service for f in res.findings} == {"s0", "s1", "s2"}   # 20 + 20 + 10


def test_warning_lines_are_capped_with_one_summary_line(caplog):
    db = MagicMock()
    h, agent = _agent(db)
    names = [f"s{i}" for i in range(5)]
    vt = _vt(services=tuple((n, "cloudrun") for n in names), primary="s0")
    tree = {CUSTOM_TF: "", **{f"apps/{n}/m.py": _many(30, n.upper()) for n in names}}
    inputs = SimpleNamespace(product_id="orders", trace_id="t5", compute_intent=SimpleNamespace(topology=vt),
                             existing_files={})
    with caplog.at_level(logging.WARNING):
        h.DeveloperAgent._runtime_env_outcome(agent, inputs, tree,
                                              build_step1_stack(validate_client=None, verifier_factory=None))
    lines = [r.getMessage() for r in caplog.records]
    assert sum(m.startswith("RUNTIME_ENV_ADVISORY ") for m in lines) == h.DeveloperAgent.RUNTIME_ENV_LOG_MAX
    (summary,) = [m for m in lines if m.startswith("RUNTIME_ENV_ADVISORY_SUMMARY")]
    assert "150 findings" in summary
    (payload,), _ = db.collection.return_value.document.return_value.set.call_args
    assert (len(payload["runtime_env_advisories"]), payload["runtime_env_advisories_total"]) == (R.MAX_FINDINGS, 150)


# ------------------------------------------------------------------------------------------------ record failure
def test_a_failed_record_write_is_logged_typed_and_never_raises(caplog):
    db = MagicMock()
    db.collection.return_value.document.return_value.set.side_effect = RuntimeError("firestore down")
    h, agent = _agent(db)
    inputs = SimpleNamespace(product_id="orders", trace_id="t6", compute_intent=SimpleNamespace(topology=_vt()),
                             existing_files={})
    with caplog.at_level(logging.WARNING):
        h.DeveloperAgent._runtime_env_outcome(agent, inputs, _tree({"config.py": TONIGHT}),
                                              build_step1_stack(validate_client=None, verifier_factory=None))
    (line,) = [r.getMessage() for r in caplog.records if "RUNTIME_ENV_RECORD_FAILED" in r.getMessage()]
    assert "'orders'" in line and "RuntimeError" in line
    assert len(agent.stack_run("t6")["runtime_env_advisories"]) == 2   # the run record still has them

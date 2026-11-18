"""Row L3-PRB-t (owner decision 2026-10-13; docs/handoff/lane3-prb-report.md §12.2): per-service test layout.

More than one service in the typed compute intent (`ComputeIntent.service_names`) -> tests live in
`apps/<svc>/tests/` (platform contract test, developer prompt, lead orchestrator); one service (or none) -> root
`tests/`, byte-identical to before. The QA sandbox job's layout check (`discover_layout`) runs the new layout and
still answers PY.TEST_LAYOUT for root `tests/` next to more than one service.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import json
import os
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
from test_lane3_prb_qa_contract import cloud, gateway_run, wheelhouse  # noqa: F401  (fixtures)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "apps", "orchestrator-gateway"))

from developer_agent import app_auth_contract as AAC  # noqa: E402
from developer_agent import prompt as P  # noqa: E402
from developer_agent import workload_test_layout as TL  # noqa: E402
from developer_agent.lead_orchestrator import LeadDeveloperOrchestrator  # noqa: E402
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)

sj = sup.load_sandbox_job("sandbox_job_test_layout")
TWO = ("public-gateway", "internal-core")

# sha256 of render_contract_test("svc-a", policy) before row L3-PRB-t (2cb18a9), policy public_api_routes
# ["GET /api/config"]: the single-service contract test must stay byte-identical.
PRE_RULE_SHA256 = {
    "PUBLIC_APP": "9c0e18da884210e6630d57bd34c292b9ba8a33a18a4c470152fc539d7dca3fc1",
    "PRIVATE_IAP": "139f447971e6f1b95914d6dd031f7fa690c68d0dee74c26c99f2ecc62b8b7e1d",
    "PRIVATE_IAM": "b253ae9f447a921a741bab81467ebbebd53412703e9f940756f62de87319620e",
}


def _policy(mode="PUBLIC_APP"):
    return SimpleNamespace(mode=mode, public_api_routes=["GET /api/config"])


# ------------------------------------------------------------------------------------------- the layout helpers
def test_multi_service_is_more_than_one_distinct_typed_name():
    assert not TL.is_multi_service(None) and not TL.is_multi_service(()) and not TL.is_multi_service(["a"])
    assert not TL.is_multi_service(["a", "a", ""])  # duplicates / empty entries are one service
    assert TL.is_multi_service(["a", "b"]) and TL.services(["b", "a", "b"]) == ("b", "a")
    assert TL.developer_prompt_rule(["a"]) == "" and TL.lead_prompt_rule(None) == ""


# ------------------------------------------------------------------------------------- platform contract test
@pytest.mark.parametrize("mode", sorted(PRE_RULE_SHA256))
def test_single_service_contract_test_is_byte_identical(mode):
    """Negative: one service -> root tests/ path and the exact pre-rule bytes."""
    text = AAC.render_contract_test("svc-a", _policy(mode), service_names=("svc-a",))
    assert hashlib.sha256(text.encode()).hexdigest() == PRE_RULE_SHA256[mode]
    assert AAC.contract_test_path("svc-a", service_names=["svc-a"]) == "tests/test_stackvend_auth_contract_svc_a.py"


def test_multi_service_contract_tests_live_in_each_service():
    files = {}
    for svc in TWO:
        files.update(AAC.render_service_files(svc, _policy(), service_names=TWO))
    assert sorted(files) == [
        "apps/internal-core/stackvend_auth.py",
        "apps/internal-core/tests/test_stackvend_auth_contract_internal_core.py",
        "apps/public-gateway/stackvend_auth.py",
        "apps/public-gateway/tests/test_stackvend_auth_contract_public_gateway.py",
    ]
    assert not any(p.startswith("tests/") for p in files)
    src = files["apps/public-gateway/tests/test_stackvend_auth_contract_public_gateway.py"]
    assert 'SERVICE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))\n' in src
    # Only the service-dir line differs from the single-service rendering of the same service.
    single = AAC.render_contract_test("public-gateway", _policy(), service_names=("public-gateway",))
    diff = [(a, b) for a, b in zip(single.splitlines(), src.splitlines()) if a != b]
    assert len(single.splitlines()) == len(src.splitlines()) and len(diff) == 1 and diff[0][0].startswith(
        "SERVICE_DIR = ")


def test_service_must_be_one_of_the_typed_services():
    with pytest.raises(ValueError):
        AAC.contract_test_path("other", service_names=TWO)
    with pytest.raises(ValueError):
        AAC.render_service_files("svc-a", _policy(), service_names=())
    with pytest.raises(TypeError):  # the layout is never defaulted: callers state the service list
        AAC.contract_test_path("svc-a")


_PROTECTED_MAIN = '''from fastapi import Depends, FastAPI
from stackvend_auth import require_user

app = FastAPI()


@app.get("/api/items")
def items(user=Depends(require_user)):
    return []


@app.get("/health")
def health():
    return {"status": "ok"}
'''


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def _run_service_tests(root, svc):
    """How the QA job runs one service: runner-owned ini, rootdir = repo, cwd = the service directory."""
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-c", os.path.join(REPO, "apps", "qa-runner", "qa_pytest.ini"),
         "--rootdir", str(root), "--confcutdir", str(root), "-p", "no:cacheprovider", "-q",
         str(root / "apps" / svc / "tests")],
        cwd=str(root / "apps" / svc), capture_output=True, text=True, timeout=120, env=hermetic_guard.child_env())


def test_multi_service_contract_tests_run_from_each_service(tmp_path):
    """The rendered per-service contract test finds its own service (SERVICE_DIR = ..) for both services; the
    unprotected route of one service fails only that service's run."""
    leaky = _PROTECTED_MAIN + '\n\n@app.get("/api/leak")\ndef leak():\n    return {"secret": 1}\n'
    files = {}
    for svc, main in zip(TWO, (_PROTECTED_MAIN, leaky)):
        files.update(AAC.render_service_files(svc, _policy(), service_names=TWO))
        files[f"apps/{svc}/main.py"] = main
    _write(tmp_path, files)
    ok, bad = (_run_service_tests(tmp_path, svc) for svc in TWO)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert bad.returncode != 0 and "APP.ROUTE_UNAUTHENTICATED" in bad.stdout and "GET /api/leak" in bad.stdout


# ------------------------------------------------------------------------------------------ QA layout check (H8)
def _tree(services, test_paths):
    files = []
    for svc in services:
        files += [f"apps/{svc}/requirements.txt", f"apps/{svc}/main.py"]
    return files + list(test_paths)


def test_qa_layout_accepts_the_multi_service_layout():
    contract = [AAC.contract_test_path(s, service_names=TWO) for s in TWO]
    llm = [f"{TL.service_tests_dir(s)}/test_main.py" for s in TWO]
    lay = sj.discover_layout(_tree(TWO, contract + llm))
    assert lay.diagnostics == []
    assert [(s.rel, s.test_roots) for s in lay.services] == [
        ("apps/internal-core", ["apps/internal-core/tests"]), ("apps/public-gateway", ["apps/public-gateway/tests"])]
    for svc, path in zip(TWO, contract):  # each contract test is under its own service's test root
        assert path.startswith(TL.service_tests_dir(svc) + "/")


def test_qa_layout_still_flags_root_tests_with_more_than_one_service():
    """The pre-rule platform path (root tests/) next to two services is exactly the first-contact PY.TEST_LAYOUT."""
    old = [f"tests/test_stackvend_auth_contract_{s.replace('-', '_')}.py" for s in TWO]
    lay = sj.discover_layout(_tree(TWO, old + [f"{TL.service_tests_dir(s)}/test_main.py" for s in TWO]))
    assert [d["code"] for d in lay.diagnostics] == ["PY.TEST_LAYOUT"] and lay.diagnostics[0]["file"] == "tests"


def test_qa_layout_single_service_root_tests_unchanged():
    path = AAC.contract_test_path("svc-a", service_names=("svc-a",))
    lay = sj.discover_layout(_tree(("svc-a",), [path, "tests/test_main.py"]))
    assert lay.diagnostics == [] and [(s.rel, s.test_roots) for s in lay.services] == [("apps/svc-a", ["tests"])]


def test_qa_job_runs_per_service_tests_end_to_end(cloud, tmp_path):  # noqa: F811 (fixture)
    """Gateway QAJobClient.run -> real job: two services (hyphenated names, the package inits the preflight
    injects) with per-service tests that import their own `main` -> exit 0, both services' tests ran."""
    files = {}
    for i, svc in enumerate(TWO):
        files[f"apps/{svc}/main.py"] = f"def health():\n    return {{'status': 'healthy', 'svc': {i}}}\n"
        files[f"apps/{svc}/requirements.txt"] = ""
        files[f"apps/{svc}/__init__.py"] = ""
        files[f"apps/{svc}/tests/__init__.py"] = ""
        files[f"apps/{svc}/tests/test_main.py"] = (
            f"from main import health\n\n\ndef test_health():\n    assert health() == "
            f"{{'status': 'healthy', 'svc': {i}}}\n")
    files["apps/__init__.py"] = ""
    outcome, run_api, _ = gateway_run(cloud, tmp_path, files)
    assert run_api.exit_code == 0, outcome
    assert outcome.passed is True and outcome.report["tests_total"] == 2 and outcome.report["tests_failed"] == 0


# ---------------------------------------------------------------------------------------------- developer prompt
@pytest.fixture()
def base_prompt():
    """The resolver's Firestore read is replaced by the code constant, the custom-module contracts and skills lookups
    by fixed blocks (no Firestore client is ever constructed)."""
    with patch("shared.prompt_resolver.get_agent_system_prompt",
               side_effect=lambda agent_role, fallback_constant=None, **k: fallback_constant), \
            patch.object(P, "get_all_active_module_contracts", return_value="CONTRACTS BLOCK"), \
            patch.object(P, "resolve_active_skills", return_value=["skill"]), \
            patch.object(P, "format_skills_for_prompt", return_value="SKILLS BLOCK"):
        yield


def test_single_service_developer_prompt_is_byte_identical(base_prompt):
    """Negative: None / () / one service / a duplicated single name -> the pre-rule prompt, byte for byte."""
    ref = P.build_developer_system_prompt()
    assert ref.startswith(P.DEVELOPER_SYSTEM_PROMPT) and ref.endswith("\n\nSKILLS BLOCK\n")
    for names in (None, (), ("svc-a",), ["svc-a", "svc-a"]):
        assert P.build_developer_system_prompt(service_names=names) == ref


def test_multi_service_developer_prompt_adds_only_the_rule(base_prompt):
    ref = P.build_developer_system_prompt()
    multi = P.build_developer_system_prompt(service_names=TWO)
    rule = TL.developer_prompt_rule(TWO)
    assert multi == P.DEVELOPER_SYSTEM_PROMPT + "\n\n" + rule + "\n" + ref[len(P.DEVELOPER_SYSTEM_PROMPT):]
    assert '"apps/public-gateway/tests/test_main.py"' in rule and '"apps/internal-core/tests/test_main.py"' in rule
    assert "NEVER create files under the repository-root `tests/`" in rule


# ---------------------------------------------------------------------------------------------- lead orchestrator
def _lead_prompt(service_names):
    seen = []

    def gen(model, contents, config):
        seen.append(contents)
        raise ValueError("stop after the request is captured")

    client = MagicMock()
    client.models.generate_content.side_effect = gen
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=["m"]):
        lead = LeadDeveloperOrchestrator(genai_client=client, model_name="m")
        plan = lead.decompose_specification(product_id="shop", spec_text="Spec", task_dag=[{"task_id": "s"}],
                                            service_names=service_names)
    assert len(seen) == 1
    return seen[0], plan


def test_single_service_lead_prompt_and_fallback_are_unchanged():
    ref, ref_plan = _lead_prompt(None)
    for names in ((), ("shop",)):
        text, plan = _lead_prompt(names)
        assert text == ref and plan.model_dump() == ref_plan.model_dump()
    qa = [t for t in ref_plan.tasks if t.task_id.endswith("-w3-qa")][0]
    assert qa.assigned_files == ["tests/test_shop.py", "tests/conftest.py"]


def test_multi_service_lead_prompt_and_fallback_use_per_service_tests():
    ref, _ = _lead_prompt(None)
    text, plan = _lead_prompt(TWO)
    assert text == ref + "\n\n" + TL.lead_prompt_rule(TWO)
    assert "`apps/public-gateway/tests/test_api.py`" in text and "NEVER assign a file under the repository-root" in text
    files = [f for t in plan.tasks for f in t.assigned_files]
    assert not any(f.startswith("tests/") for f in files)
    qa = [t for t in plan.tasks if t.task_id.endswith("-w3-qa")][0]
    assert qa.assigned_files == ["apps/shop/tests/test_shop.py", "apps/shop/tests/conftest.py"]


# ------------------------------------------------------------------------------------------------ handler wiring
@pytest.mark.parametrize("names", [["shop"], ["shop", "worker"]])
def test_handler_passes_the_typed_services_to_lead_and_developer_prompt(names):
    """generate_code_files hands ComputeIntent.service_names to the lead and to the solo developer prompt."""
    from developer_agent import handler as h
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        agent = h.DeveloperAgent(project_id="")
    seen = {}

    class Client:
        class models:  # noqa: N801
            @staticmethod
            def generate_content(model, contents, config):
                seen["system_instruction"] = config.system_instruction
                raise ValueError("stop after the request is captured")

    agent.genai_client = Client()
    rule = TL.developer_prompt_rule(names)
    with patch.object(h, "LeadDeveloperOrchestrator") as lead, \
            patch.object(h, "get_model_cascade_for_agent", return_value=["m"]), \
            patch.object(agent, "fetch_existing_repo_files", return_value={}), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        lead.return_value.decompose_specification.side_effect = RuntimeError("lead unavailable")
        with pytest.raises(Exception):
            agent.generate_code_files(product_id="shop", spec_text="spec", task_dag=[], trace_id="trace-tl",
                                      architect_compute_intent={"target_compute_services": names}, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    assert tuple(lead.return_value.decompose_specification.call_args.kwargs["service_names"]) == tuple(names)
    assert rule == "" or rule in seen["system_instruction"]
    assert ("MULTI-SERVICE TEST LAYOUT" in seen["system_instruction"]) is (len(names) > 1)
    json.dumps(seen["system_instruction"])  # a plain string

"""ARCHITECT-PYTHON-PIN (owner 10-31): the architect is told, as one typed platform fact line, that the platform pins the
workload's Python runtime, so a plan never chooses a Python version the build cannot meet.

Live case (testplan01-e2, 10-30): the architect planned "Python 3.11"; `handler.enforce_container_contract` writes
`.python-version` "3.13\\n" in the repository root and every deployed service (the Buildpacks runtime pin, FD-55 W5),
so the directive could never be met and QA reported it as missed.

- single source: the fact is `developer_agent.runtime_pin.ARCHITECT_PYTHON_RUNTIME_FACT`, rendered from
  `PLATFORM_PYTHON_VERSION`, and that version is what the real container contract writes;
- exactly once: the rendered architect prompt (and the system instruction the model receives) holds it once, on its
  own line, after the service_topology contract, whatever base prompt resolved;
- Do No Harm: removing that one line gives back main 7b07e597's prompt byte for byte (every other section unchanged).

Prompt-only: no plan text is read or matched. Hermetic: stub prompt sections, fake genai client, no Firestore.
"""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import re
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from architect_agent import prompt as ap  # noqa: E402
from developer_agent import runtime_pin as RP  # noqa: E402

FACT = RP.ARCHITECT_PYTHON_RUNTIME_FACT
# ARCHITECT-REFUSED-ROLES-FACT (ex02-g13) re-pin: the IAM roles fact line follows this one
# (tests/test_architect_refused_roles_fact.py); removing both lines gives back main's prompt byte for byte
ROLES = ap.ARCHITECT_REFUSED_ROLES_FACT


def _fallback_base(monkeypatch, base=None):
    """The prompt registry returns `base`, or the code fallback constant (the built-in prompt) when None."""
    import shared.prompt_resolver as resolver
    monkeypatch.setattr(resolver, "get_agent_system_prompt",
                        lambda **kw: kw.get("fallback_constant") if base is None else base)
    monkeypatch.delenv("PROJECT_ID", raising=False)


# ============================================================================ single source
def test_the_fact_is_the_runtime_pin_module_constant():
    assert ap.ARCHITECT_PYTHON_RUNTIME_FACT is RP.ARCHITECT_PYTHON_RUNTIME_FACT


def test_the_fact_names_exactly_the_version_the_container_contract_writes():
    from developer_agent.handler import enforce_container_contract
    files = {"apps/svc/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
             "apps/svc/requirements.txt": "fastapi\n", "apps/svc/.python-version": "3.11\n"}
    enforce_container_contract(files, "svc")
    written = {files[".python-version"], files["apps/svc/.python-version"]}
    assert written == {RP.PLATFORM_PYTHON_VERSION_CONTENT}
    version = RP.PLATFORM_PYTHON_VERSION_CONTENT.strip()
    assert f"Python {version} " in FACT
    # the only version the fact names is the pinned one (a duplicated or stale literal would show here)
    assert re.findall(r"\d+\.\d+", FACT) == [version]


def test_the_fact_is_one_line_saying_the_plan_chooses_no_python_version():
    assert "\n" not in FACT and FACT.startswith("### PLATFORM FACT (Python runtime):")
    assert f"`{RP.PYTHON_VERSION_FILE}`" in FACT and "must not choose a Python version" in FACT


# ============================================================================ exactly once
def test_the_rendered_prompt_holds_the_fact_exactly_once_on_its_own_line(monkeypatch):
    _fallback_base(monkeypatch)
    # real built-in base, real topology contract, real built-in skills (this context activates one)
    out = ap.build_architect_system_prompt(task_context="Review enterprise network design with org policy constraints",
                                           quota_snapshot={"status": "OK", "regions": {"us-central1": {
                                               "external_ips_available": 4, "cpus_available": 24}}})
    assert out.count(FACT) == 1
    assert out.split("\n").count(FACT) == 1
    assert "DYNAMIC AGENTIC SKILLS" in out and "REGIONAL CAPACITY" in out   # the other sections are still there
    from shared.service_topology import render_topology_contract
    assert out.startswith(ap.ARCHITECT_SYSTEM_PROMPT + "\n\n" + render_topology_contract() + "\n" + FACT + "\n"
                          + ROLES + "\n")


@pytest.mark.parametrize("base", [None, "OPERATOR OVERRIDE PROMPT"])
def test_any_base_prompt_gets_the_fact_once(monkeypatch, base):
    _fallback_base(monkeypatch, base)
    monkeypatch.setattr(ap, "resolve_active_skills", lambda **kw: [])
    assert ap.build_architect_system_prompt(task_context="spec").count(FACT) == 1


# ============================================================================ Do No Harm
def _stub_sections(monkeypatch, directives):
    """Every section of the architect prompt replaced by a fixed stub, so the expected text is exact."""
    _fallback_base(monkeypatch, "BASE")
    monkeypatch.setattr(ap, "render_topology_contract", lambda: "TOPOLOGY\n")
    monkeypatch.setattr(ap, "resolve_active_skills", lambda **kw: [{"skill_id": "s"}])
    monkeypatch.setattr(ap, "format_skills_for_prompt", lambda skills: "SKILLS" if skills else "")
    import shared.quota_inspector as qi
    monkeypatch.setattr(qi, "sanitize_quota_for_prompt", lambda snap: "QUOTA")
    doc = SimpleNamespace(exists=True, to_dict=lambda: {"models": {"custom_directives": {"ARCHITECT_AGENT": directives}}})
    return SimpleNamespace(collection=lambda c: SimpleNamespace(
        document=lambda d: SimpleNamespace(get=lambda: doc), stream=lambda: iter(())))


# build_architect_system_prompt of main 7b07e597 on _stub_sections(["d1"]) with a quota snapshot (checked on an export
# of that commit before this row)
MAIN_STUB_PROMPT = ("BASE\n\nTOPOLOGY\n\n\nSKILLS\n\n\n### ACTIVE OPERATIONAL DIRECTIVES (MANAGED VIA GLASS PANE):\n"
                    "- [DIRECTIVE]: d1\n\n\n### REGIONAL CAPACITY & QUOTA CONSTRAINTS:\nQUOTA\n")
MAIN_STUB_PROMPT_BARE = "BASE\n\nTOPOLOGY\n"   # same, no skills / directives / quota


def test_every_other_section_is_byte_identical_to_main(monkeypatch):
    db = _stub_sections(monkeypatch, ["d1"])
    out = ap.build_architect_system_prompt(task_context="spec", db_client=db, quota_snapshot={"status": "OK"})
    assert out == "BASE\n\nTOPOLOGY\n\n" + FACT + "\n" + ROLES + MAIN_STUB_PROMPT[len("BASE\n\nTOPOLOGY\n"):]
    assert out.replace("\n" + FACT, "", 1).replace("\n" + ROLES, "", 1) == MAIN_STUB_PROMPT


def test_bare_prompt_is_main_plus_the_one_line(monkeypatch):
    _stub_sections(monkeypatch, [])
    monkeypatch.setattr(ap, "resolve_active_skills", lambda **kw: [])
    out = ap.build_architect_system_prompt(task_context="spec")
    assert out == MAIN_STUB_PROMPT_BARE + "\n" + FACT + "\n" + ROLES
    assert out.replace("\n" + FACT, "", 1).replace("\n" + ROLES, "", 1) == MAIN_STUB_PROMPT_BARE


def test_the_base_prompt_constant_is_unchanged():
    # the fact is appended at render time; the built-in base prompt (and its registry copies) carries no version
    assert FACT not in ap.ARCHITECT_SYSTEM_PROMPT
    assert not re.search(r"Python \d", ap.ARCHITECT_SYSTEM_PROMPT)


# ============================================================================ the model receives it
class _Client:
    def __init__(self, plan):
        self.plan = plan
        self.configs = []
        self.models = SimpleNamespace(generate_content=self._gen)

    def _gen(self, model, contents, config):
        self.configs.append(config)
        return SimpleNamespace(text=json.dumps(self.plan), candidates=[], usage_metadata=None)


def test_the_architect_model_call_carries_the_fact_once(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "PROJECT_ID", "K_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "false")
    fake_fs = SimpleNamespace(Client=lambda *a, **kw: MagicMock(), Increment=lambda n: ("INC", n))
    import google.cloud  # noqa: F401
    monkeypatch.setattr(sys.modules["google.cloud"], "firestore", fake_fs, raising=False)
    monkeypatch.setitem(sys.modules, "google.cloud.firestore", fake_fs)
    monkeypatch.setitem(sys.modules, "vertexai", None)
    _fallback_base(monkeypatch)
    from architect_agent import handler as h
    monkeypatch.setattr(h.ArchitectAgent, "persist_build_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h.ArchitectAgent, "persist_implementation_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h, "get_model_cascade_for_agent", lambda *a, **kw: ["model-a"])
    agent = h.ArchitectAgent(project_id="")
    agent.project_id, agent.model_name, agent.model, agent.spec_decomposer = "", "model-a", None, None
    agent.genai_client = _Client({
        "product_id": "shop", "summary": "s", "architecture_overview": "o", "infra_tasks": [], "code_tasks": [],
        "target_compute_services": ["shop"], "compute_archetype": "cloudrun", "iac_engine": "tofu",
        "service_topology": {"services": [{"name": "shop", "kind": "cloudrun"}], "primary_service": "shop",
                             "edges": [], "resources": []}})
    agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="t-pin")
    (config,) = agent.genai_client.configs
    system = config.system_instruction
    system = system if isinstance(system, str) else "".join(getattr(p, "text", "") or "" for p in
                                                            getattr(system, "parts", []) or [])
    assert system.count(FACT) == 1
    assert agent.last_architect_rendered_prompt.count(FACT) == 1

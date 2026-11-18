"""ARCHITECT-REFUSED-ROLES-FACT (ex02-g13, docs/handoff/ex02-g13-repair-exhaustion-diagnosis.md §4 S3).

Live run ex02-g13 (stackvend13, 11-16): the architect planned "roles/iam.serviceAccountTokenCreator for Cloud Scheduler
OIDC token generation", a role StackVend's IAM policy refuses in every workload's IaC; the build could never meet it.
The architect is now told, as one platform fact line, which roles the policy refuses (rendered from
`policy_tables.PRIVILEGED_ROLES`, the one table), that identity tokens need none of them, and that a plan which
genuinely needs one says so in its `risk_assessment` instead of planning the grant.

- single source: the fact lists exactly the table, rendered from it (a changed table changes the line);
- exactly once, on its own line, right after the Python runtime fact, whatever base prompt resolved;
- Do No Harm: removing that one line gives back the prompt without it byte for byte (test_architect_python_pin pins
  main's sections); the built-in base prompt constant is unchanged.
Prompt-only: no plan text is read or matched. Hermetic.
"""
import hermetic_guard  # noqa: F401  (first import)

import os
import re
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from architect_agent import prompt as ap  # noqa: E402
from developer_agent.runtime_pin import ARCHITECT_PYTHON_RUNTIME_FACT  # noqa: E402
from developer_agent.validators.policy_tables import PRIVILEGED_ROLES  # noqa: E402

FACT = ap.ARCHITECT_REFUSED_ROLES_FACT


def _base(monkeypatch, base=None):
    import shared.prompt_resolver as resolver
    monkeypatch.setattr(resolver, "get_agent_system_prompt",
                        lambda **kw: kw.get("fallback_constant") if base is None else base)
    monkeypatch.setattr(ap, "resolve_active_skills", lambda **kw: [])
    monkeypatch.delenv("PROJECT_ID", raising=False)


def test_the_fact_lists_exactly_the_policy_table():
    assert set(re.findall(r"`(roles/[A-Za-z.]+)`", FACT)) == set(PRIVILEGED_ROLES)
    assert "roles/iam.serviceAccountTokenCreator" in FACT


def test_the_fact_is_rendered_from_the_table_not_copied():
    assert ap.render_refused_roles_fact() == FACT
    other = ap.render_refused_roles_fact(frozenset({"roles/owner"}))
    assert "`roles/owner`" in other and "`roles/editor`" not in other


def test_the_fact_is_one_line_with_the_planning_rule():
    assert "\n" not in FACT and FACT.startswith("### PLATFORM FACT (IAM roles):")
    assert "Never plan a grant" in FACT and "`risk_assessment`" in FACT
    assert "metadata server" in FACT and "Cloud Scheduler" in FACT


@pytest.mark.parametrize("base", [None, "OPERATOR OVERRIDE PROMPT"])
def test_the_rendered_prompt_holds_it_once_after_the_python_fact(monkeypatch, base):
    _base(monkeypatch, base)
    out = ap.build_architect_system_prompt(task_context="spec")
    assert out.count(FACT) == 1 and out.split("\n").count(FACT) == 1
    assert ARCHITECT_PYTHON_RUNTIME_FACT + "\n" + FACT in out


def test_do_no_harm_removing_the_line_gives_the_prompt_without_it(monkeypatch):
    _base(monkeypatch, "BASE")
    out = ap.build_architect_system_prompt(task_context="spec")
    monkeypatch.setattr(ap, "ARCHITECT_REFUSED_ROLES_FACT", "")
    without = ap.build_architect_system_prompt(task_context="spec")
    assert out.replace("\n" + FACT, "", 1) == without[:-1]   # without = ... + "\n" + "" (the empty line removed)
    assert FACT not in ap.ARCHITECT_SYSTEM_PROMPT

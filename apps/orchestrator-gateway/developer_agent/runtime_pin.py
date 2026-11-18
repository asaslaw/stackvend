"""QA-JUDGE-FILE-MAPPING: the platform's Python runtime pin, as QA repair and the QA judge read it.

- `handler.enforce_container_contract` writes `.python-version` with this exact content in the repository root and in
  every deployed service directory `apps/<service>/` (the Buildpacks runtime pin, FD-55 W5; its literal stays in that
  function, and tests/test_qa_judge_file_mapping.py pins the two equal on the real function's output). It replaces any
  other value, so a developer edit of such a file never reaches a commit.
- `qa_repair.plan_qa_repair` never seeds a QA finding on such a file: a repair of it is overwritten by the next
  assembly, so the finding cannot be repaired by the developer (it would only consume repair iterations).
- The QA adherence judge is told the pin as a trusted platform fact (`judge_input.platform_facts_text`) when the
  committed tree holds a pinned file, so it does not report the platform's own value as a missed directive.
- ARCHITECT-PYTHON-PIN: the architect is told the pin as one platform fact line (`ARCHITECT_PYTHON_RUNTIME_FACT`,
  appended by `architect_agent.prompt.build_architect_system_prompt` after the topology contract), so a plan never
  chooses a Python version the build cannot meet.

"Pinned" is decided by exact path structure AND exact content (the rule `_platform_golden_copies` uses for golden
module copies): a `.python-version` the platform did not write (another value, another directory depth) is an
ordinary file of the draft.
"""
from __future__ import annotations

from typing import Any, List, Mapping

PYTHON_VERSION_FILE = ".python-version"
PLATFORM_PYTHON_VERSION = "3.13"
PLATFORM_PYTHON_VERSION_CONTENT = PLATFORM_PYTHON_VERSION + "\n"
ARCHITECT_PYTHON_RUNTIME_FACT = (
    f"### PLATFORM FACT (Python runtime): the platform pins the Python runtime of the repository and of every deployed "
    f"service to Python {PLATFORM_PYTHON_VERSION} (it writes `{PYTHON_VERSION_FILE}` itself and replaces any other "
    f"value); the plan must not choose a Python version: name no Python version in any task, target file or "
    f"acceptance criterion.")
APPS_DIR = "apps"


def is_runtime_pin_path(path: Any) -> bool:
    """The exact paths the platform pins: the root `.python-version` and `apps/<dir>/.python-version`."""
    if not isinstance(path, str):
        return False
    parts = path.split("/")
    return parts == [PYTHON_VERSION_FILE] or (
        len(parts) == 3 and parts[0] == APPS_DIR and bool(parts[1]) and parts[2] == PYTHON_VERSION_FILE)


def is_platform_runtime_pin(path: Any, content: Any) -> bool:
    """True only for a pin path whose content is exactly the platform's pin."""
    return is_runtime_pin_path(path) and content == PLATFORM_PYTHON_VERSION_CONTENT


def platform_runtime_pins(tree: Mapping[str, Any]) -> List[str]:
    """The tree's platform-pinned files (sorted)."""
    return sorted(p for p, c in (tree or {}).items() if is_platform_runtime_pin(p, c))


__all__ = ["PYTHON_VERSION_FILE", "PLATFORM_PYTHON_VERSION", "PLATFORM_PYTHON_VERSION_CONTENT",
           "ARCHITECT_PYTHON_RUNTIME_FACT", "is_runtime_pin_path", "is_platform_runtime_pin", "platform_runtime_pins"]

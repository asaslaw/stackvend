"""
Where a generated workload's tests live (owner decision 2026-10-13, row L3-PRB-t; report
docs/handoff/lane3-prb-report.md §12.2).

* One service (or none: foundation-only): the root ``tests/`` directory. Unchanged layout; the QA sandbox job runs it
  with the single service's venv. Prompts for these workloads are byte-identical to before the rule.
* More than one service: each service's tests live in ``apps/<service>/tests/`` and nothing goes in root ``tests/``.
  The QA sandbox job (``apps/qa-runner/sandbox_job.discover_layout``) runs ``apps/<svc>/tests/`` with that service's
  venv and answers ``PY.TEST_LAYOUT`` for a root ``tests/`` next to more than one Python service.

The service count is a typed fact: ``ComputeIntent.service_names`` (the architect's ``target_compute_services``
after exact normalization and repository pinning, ``compute_intent.py``). Never inferred from file names or spec
prose.
"""

from __future__ import annotations

from typing import Any, Iterable, List, Optional, Sequence, Tuple

__all__ = ["LEAD_TEST_LAYOUT_REASK", "ROOT_TESTS_DIR", "developer_prompt_rule", "is_multi_service",
           "is_root_test_path", "lead_prompt_rule", "plan_test_target_changes", "plan_test_targets",
           "root_test_assignments", "service_tests_dir", "services"]

ROOT_TESTS_DIR = "tests"


def services(service_names: Optional[Iterable[str]]) -> Tuple[str, ...]:
    """The typed service list, order kept, empty and duplicate entries dropped (exact string equality)."""
    out = []
    for name in service_names or ():
        if isinstance(name, str) and name and name not in out:
            out.append(name)
    return tuple(out)


def is_multi_service(service_names: Optional[Iterable[str]]) -> bool:
    return len(services(service_names)) > 1


def service_tests_dir(service: str) -> str:
    return f"apps/{service}/tests"


def _listing(names: Tuple[str, ...]) -> str:
    return ", ".join(f"`{n}`" for n in names)


def developer_prompt_rule(service_names: Optional[Iterable[str]]) -> str:
    """Developer system-prompt section for a multi-service workload; "" otherwise (single-service prompt unchanged)."""
    names = services(service_names)
    if len(names) < 2:
        return ""
    examples = ", ".join(f'"{service_tests_dir(n)}/test_main.py"' for n in names)
    return (
        f"MULTI-SERVICE TEST LAYOUT (this workload has {len(names)} services: {_listing(names)}). This rule overrides "
        f"item 10, the `tests/test_main.py` key of the Response Format example and any root `tests/` path in the "
        f"Architecture Task DAG:\n"
        f"- Put each service's pytest tests (and its conftest.py, if any) in `apps/<service-name>/tests/`: {examples}.\n"
        f"- NEVER create files under the repository-root `tests/` directory: QA rejects a multi-service repository "
        f"with a root `tests/` (PY.TEST_LAYOUT).\n"
        f"- Each service's tests run with that service's own `requirements.txt`, from inside `apps/<service-name>/`: "
        f"import the service's own modules directly (e.g. `from main import app`), never another service's code."
    )


def lead_prompt_rule(service_names: Optional[Iterable[str]]) -> str:
    """Lead-orchestrator decomposition-prompt section for a multi-service workload; "" otherwise."""
    names = services(service_names)
    if len(names) < 2:
        return ""
    first = service_tests_dir(names[0])
    return (
        f"Test layout (multi-service workload, services: {_listing(names)}): assign each service's pytest files to "
        f"`apps/<service>/tests/` (e.g. `{first}/test_api.py`, `{first}/conftest.py`); NEVER assign a file under the "
        f"repository-root `tests/` directory. The `tests/...` paths in the schema example apply to single-service "
        f"workloads only."
    )


def _components(path: Any) -> Optional[List[str]]:
    """Exact path components of a repository path; None for a non-string or a path with an empty, `.` or `..`
    component."""
    if not isinstance(path, str):
        return None
    parts = path.split("/")
    return parts if all(p not in ("", ".", "..") for p in parts) else None


def is_root_test_path(path: Any) -> bool:
    """A file under the repository-root ``tests/`` directory (first path component exactly ``tests``)."""
    parts = _components(path)
    return parts is not None and len(parts) > 1 and parts[0] == ROOT_TESTS_DIR


LEAD_TEST_LAYOUT_REASK = ("\n\nERROR PY.TEST_LAYOUT: the previous plan assigned files under the repository-root "
                          "`tests/` directory: {paths}. This workload has more than one service: assign each "
                          "service's pytest files to `apps/<service>/tests/` and return the whole plan again without "
                          "any root `tests/` path, keeping every other assignment.")


def root_test_assignments(tasks: Iterable[Any], service_names: Optional[Iterable[str]]) -> List[Tuple[str, str]]:
    """TEST-LAYOUT-PLATFORM-FACT: (task_id, path) of every root ``tests/`` file a lead plan assigns to a junior when
    the workload has more than one service (the plan-time form of QA's PY.TEST_LAYOUT); [] for one service or none."""
    if not is_multi_service(service_names):
        return []
    out: List[Tuple[str, str]] = []
    for t in tasks:
        for f in getattr(t, "assigned_files", None) or ():
            if is_root_test_path(f):
                out.append((str(getattr(t, "task_id", "")), f))
    return out


def plan_test_targets(target_files: Sequence[Any], service_names: Optional[Iterable[str]]
                      ) -> Tuple[List[Any], Tuple[str, ...]]:
    """TEST-LAYOUT-PLATFORM-FACT (owner 11-13): one plan task's `target_files` under this layout rule.

    Returns (the targets, the root ``tests/`` targets that were relocated or removed). One service or none: the
    targets unchanged (a copy) and nothing relocated. More than one service: each root ``tests/<rest>`` target becomes
    ``apps/<svc>/tests/<rest>`` when the task's other targets name exactly one of the services by an exact
    ``apps/<svc>/...`` path component; otherwise it is removed (which service a test file name means is not a typed
    fact; the developer's layout rule places each service's tests and QA's platform facts state it). Order kept, no
    duplicates added; every other entry is kept as it is."""
    out, relocated, removed = plan_test_target_changes(target_files, service_names)
    moved = set(removed) | {old for old, _new in relocated}
    return out, tuple(t for t in target_files or [] if t in moved)


def plan_test_target_changes(target_files: Sequence[Any], service_names: Optional[Iterable[str]]
                             ) -> Tuple[List[Any], Tuple[Tuple[str, str], ...], Tuple[str, ...]]:
    """`plan_test_targets` with the record of what changed (red-team F3: the architect stage trace and the plan show
    it): (the targets, the relocated (root path, new path) pairs, the removed root paths)."""
    targets = list(target_files or [])
    names = services(service_names)
    if len(names) < 2:
        return targets, (), ()
    named = set()
    for t in targets:
        parts = _components(t)
        if parts is not None and len(parts) > 2 and parts[0] == "apps" and parts[1] in names:
            named.add(parts[1])
    owner = next(iter(named)) if len(named) == 1 else None
    out: List[Any] = []
    relocated: List[Tuple[str, str]] = []
    removed: List[str] = []
    for t in targets:
        if not is_root_test_path(t):
            out.append(t)
            continue
        if owner is None:
            removed.append(t)
            continue
        new = f"{service_tests_dir(owner)}/{t[len(ROOT_TESTS_DIR) + 1:]}"
        relocated.append((t, new))
        if new not in out and new not in targets:
            out.append(new)
    return out, tuple(relocated), tuple(removed)

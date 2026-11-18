"""PLAN-TARGET-FILES + MANIFEST-PATH-DEFERS-TO-DAG (live ex09-1115 / ex04-1114 on stackvend12, 11-15; diagnosis
docs/handoff/ex09-1115-dag-target-file-diagnosis.md). Pure functions over the architect's task DAG: no I/O, no LLM.

Before: the architect's task DAG names exact `target_files` per task, the Stage 2 adherence judge checks them
(qa_auditor.judge_input PLAN TARGET FILES: "not in this commit at this exact path"), but nothing before QA did. The
lead developer may place a file elsewhere (ex09-1115: the DAG's `apps/<svc>/models.py` went to
`apps/<svc>/schemas/portal.py`), and the platform's own k8s hint named `k8s/<service>.yaml` where the DAG said
`k8s/deployment.yaml` (ex04-1114). The judge's file-less finding can only send the whole build back
(qa_repair REGENERATE / FINDING_NOT_ON_A_DRAFT_FILE): ex09-1115 threw away two passing builds that way.

Now:
- `required_plan_targets`: the DAG target files the developer itself must write, exact paths in DAG order. A task the
  platform answers by its exact category (the judge's CI/CD and infrastructure categories, judge_input
  CI_TASK_CATEGORIES / IAC_TASK_CATEGORIES) contributes nothing. Of the other tasks a target counts only inside the
  platform's own layout (an allow-list, RT F3): a file of a typed service `apps/<service>/...` (`service_names`,
  exact), a root `tests/...` file of a single-service workload, the root `README.md`, or an applied manifest
  `k8s/<name>.yaml|yml`; with a text file name (TEXT_SUFFIXES, or the exact basename `Procfile`), never a dotfile
  or a lock file. Within the layout it is still not counted when (each an exact rule, never text matching of the
  task's prose): it is not a safe relative path or holds a glob character; it is a platform render
  (`judge_input.is_platform_rendered`, the CI files included) or a runtime pin path; a Buildpacks-forbidden container
  file (handler.is_prohibited_container_file); a file name reserved for the human architect; a Wave 0 contract
  registry path or the module it shadows (contract_registry.reserved_paths). Every other DAG path stays the judge's,
  exactly as before.
  The pre-commit validator V-PLAN-TARGETS (validators/plan_targets.py) reports each one missing from the assembled
  tree as PLAN.TARGET_FILE_MISSING, a file to create (repair_loop.CREATE_FILE_CODES): the developer's own repair loop
  writes it before commit, so the judge never sees a missing DAG file and no passing build is regenerated for one.
- `dag_manifest_paths`: per gke-autopilot service, the applied manifest paths (`k8s/<name>.yaml|yml`, exactly the
  platform's apply rule validators/container.applied_k8s_manifest_paths) the DAG names for it, in DAG order. With one
  gke service every applied manifest target of the DAG is its; with several, a task's manifests belong to the one
  service whose `apps/<service>/` the same task targets (exact path components); a manifest claimed by two services
  is nobody's. The platform's manifest-name hint (topology_wiring.gke_manifest_clause) and the missing-workload finding
  (validators/container.K8sWorkloadValidator) use these paths instead of `k8s/<service>.yaml`; with none, both are
  byte-identical to before.
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from shared.artifact_ownership import USER_OWNED_BASENAMES, _is_override_file
    from shared.path_safety import GIT_RESERVED, UnsafePathError, validate_relpath
except ImportError:  # pragma: no cover
    from ..shared.artifact_ownership import USER_OWNED_BASENAMES, _is_override_file  # type: ignore
    from ..shared.path_safety import GIT_RESERVED, UnsafePathError, validate_relpath  # type: ignore

from qa_auditor.judge_input import (CI_TASK_CATEGORIES, DIFF_EXCLUDED_FILES, IAC_TASK_CATEGORIES, is_asset,
                                    is_platform_rendered, is_printable_task_id)

from .contract_registry import reserved_paths
from .deploy_repair import PLATFORM_TREE_PREFIXES
from .runtime_pin import is_runtime_pin_path
from .validators.container import applied_k8s_manifest_paths
from .workload_test_layout import is_multi_service, is_root_test_path

# fnmatch's own magic characters: a target holding one names a pattern, not a file
GLOB_CHARACTERS = frozenset("*?[")
# RT F3: the file name suffixes of a source / text file a repair can write (exact, lower case); `Procfile` by name
TEXT_SUFFIXES = frozenset({".py", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".html", ".htm",
                           ".css", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".sh", ".sql", ".jinja", ".j2", ".csv"})
TEXT_BASENAMES = frozenset({"Procfile"})
ROOT_DOCUMENTS = frozenset({"README.md"})
PLATFORM_ANSWERED_CATEGORIES = CI_TASK_CATEGORIES | IAC_TASK_CATEGORIES


@dataclass(frozen=True)
class PlanTarget:
    path: str
    task_id: Optional[str]          # the DAG task naming it first (printable ids only; None otherwise)
    siblings: Tuple[str, ...]       # that task's other target paths, exact, DAG order


def dag_tasks(task_dag: Any) -> List[Mapping[str, Any]]:
    """The DAG's task mappings in order ([] for anything that is not a list)."""
    return [t for t in task_dag if isinstance(t, Mapping)] if isinstance(task_dag, list) else []


def task_targets(task: Mapping[str, Any]) -> List[str]:
    targets = task.get("target_files")
    return [t for t in targets if isinstance(t, str) and t] if isinstance(targets, list) else []


def is_file_path(path: Any) -> bool:
    """A safe relative file path (shared.path_safety, `.git` reserved) without a glob character."""
    if not isinstance(path, str) or GLOB_CHARACTERS & set(path):
        return False
    try:
        validate_relpath(path, reserved=GIT_RESERVED)
    except UnsafePathError:
        return False
    return True


def in_platform_layout(path: str, service_names: Optional[Iterable[str]] = None) -> bool:
    """RT F3: the allow-list (module docstring): a typed service's file, a single-service root test file, the root
    README.md or an applied k8s manifest; with a text file name, not a dotfile, not a lock file / asset."""
    parts = path.split("/")
    base = parts[-1]
    suffix = posixpath.splitext(base)[1].lower()
    if base.startswith(".") or base in DIFF_EXCLUDED_FILES or is_asset(path):
        return False
    if suffix not in TEXT_SUFFIXES and base not in TEXT_BASENAMES:
        return False
    names = tuple(n for n in (service_names or ()) if isinstance(n, str) and n)
    if len(parts) > 2 and parts[0] == "apps" and parts[1] in names:
        return True
    if is_root_test_path(path):
        return not is_multi_service(names)
    return path in ROOT_DOCUMENTS or applied_k8s_manifest_paths([path]) == [path]


def developer_writes(path: str, service_names: Optional[Iterable[str]] = None) -> bool:
    """True when `path` (already a file path) is a file the developer may write (module docstring, exact rules)."""
    from .handler import is_prohibited_container_file   # the one Dockerfile rule (handler imports this module)
    if not in_platform_layout(path, service_names):
        return False
    if path.startswith(PLATFORM_TREE_PREFIXES) or is_platform_rendered(path, None) or is_runtime_pin_path(path):
        return False
    if is_prohibited_container_file(path):
        return False
    if posixpath.basename(path) in USER_OWNED_BASENAMES or _is_override_file(path):
        return False
    parts = path.split("/")
    services = [parts[1]] if len(parts) > 2 and parts[0] == "apps" else []
    if path in reserved_paths(services):
        return False
    if is_multi_service(service_names) and is_root_test_path(path):
        return False
    return True


def required_plan_targets(task_dag: Any, *, service_names: Optional[Iterable[str]] = None
                          ) -> Tuple[PlanTarget, ...]:
    """The DAG target files the developer must write (module docstring), first-seen order, one entry per path."""
    names = tuple(service_names or ())
    out: List[PlanTarget] = []
    seen = set()
    for task in dag_tasks(task_dag):
        if task.get("category") in PLATFORM_ANSWERED_CATEGORIES:
            continue   # the platform answers this task (CI/CD or infrastructure): the judge is told so too
        # RT F4: a CI or platform path in a code task is dropped by itself (developer_writes), not the whole task
        targets = task_targets(task)
        tid = task.get("task_id")
        for t in targets:
            if t in seen or not is_file_path(t) or not developer_writes(t, names):
                continue
            seen.add(t)
            out.append(PlanTarget(t, tid if is_printable_task_id(tid) else None,
                                  tuple(s for s in dict.fromkeys(targets) if s != t)))
    return tuple(out)


def missing_plan_targets(targets: Sequence[PlanTarget], tree: Mapping[str, Any],
                         draft: Optional[Mapping[str, Any]] = None,
                         repository: Optional[Mapping[str, Any]] = None) -> List[PlanTarget]:
    """The targets whose exact path is not in the tree (path -> content) and could be: not a directory of the tree
    (a path some tree file lies under) and not under a tree file (git holds one or the other, never both). A target
    the draft holds that the tree lacks was removed by the platform's own assembly (e.g. a foundation-only workload has
    no `apps/`): the platform decided, so it is not reported (a repair could never make it stay). RT F1: a target the
    repository already holds (`repository`, the files the dispatch started from; the assembled tree does not carry the
    repository's app files, the commit keeps them) is present, as the judge sees it ("present, unchanged")."""
    paths = [p for p in tree if isinstance(p, str)] + [p for p in (repository or {}) if isinstance(p, str)]
    out: List[PlanTarget] = []
    for t in targets:
        if t.path in tree or (draft is not None and t.path in draft) or t.path in (repository or {}):
            continue
        parts = t.path.split("/")
        if any(p.startswith(t.path + "/") for p in paths):
            continue
        if any("/".join(parts[:i]) in tree or "/".join(parts[:i]) in (repository or {})
               for i in range(1, len(parts))):
            continue
        out.append(t)
    return out


def is_applied_manifest_path(path: Any) -> bool:
    return is_file_path(path) and applied_k8s_manifest_paths([path]) == [path]


def _apps_services(targets: Iterable[str], gke: FrozenSet[str]) -> FrozenSet[str]:
    out = set()
    for t in targets:
        parts = t.split("/")
        if len(parts) > 2 and parts[0] == "apps" and parts[1] in gke:
            out.add(parts[1])
    return frozenset(out)


def dag_manifest_paths(task_dag: Any, gke_services: Iterable[str]) -> Dict[str, Tuple[str, ...]]:
    """MANIFEST-PATH-DEFERS-TO-DAG: gke service -> the applied manifest paths the DAG names for it (module docstring).
    Services without one are absent ({} for no DAG, no gke service, or no applied manifest target)."""
    gke = tuple(dict.fromkeys(s for s in gke_services if isinstance(s, str) and s))
    if not gke:
        return {}
    claims: Dict[str, List[str]] = {}   # manifest path -> claiming services, DAG order
    order: List[str] = []
    for task in dag_tasks(task_dag):
        targets = task_targets(task)
        manifests = [t for t in targets if is_applied_manifest_path(t)]
        if not manifests:
            continue
        owners = (frozenset(gke) if len(gke) == 1 else _apps_services(targets, frozenset(gke)))
        if len(owners) != 1:
            continue   # no service, or several: the task's manifests are not one service's
        (svc,) = tuple(owners)
        for m in manifests:
            if m not in claims:
                claims[m] = []
                order.append(m)
            if svc not in claims[m]:
                claims[m].append(svc)
    out: Dict[str, List[str]] = {}
    for m in order:
        if len(claims[m]) == 1:
            out.setdefault(claims[m][0], []).append(m)
    return {s: tuple(paths) for s, paths in out.items()}


__all__ = ["PlanTarget", "GLOB_CHARACTERS", "TEXT_SUFFIXES", "dag_tasks", "task_targets", "is_file_path",
           "in_platform_layout", "developer_writes",
           "required_plan_targets", "missing_plan_targets", "is_applied_manifest_path", "dag_manifest_paths"]

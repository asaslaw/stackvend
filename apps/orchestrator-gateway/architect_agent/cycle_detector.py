"""
Project Castor: DAG Cycle & Topological Invariant Detector
Deterministic topological validation using Kahn's Algorithm across both
macro sequenced build plan steps and micro infra/code task items.
"""

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple


class DAGValidationResult:
    def __init__(
        self,
        is_valid: bool,
        cycle_detected: bool = False,
        orphan_dependencies: Optional[List[str]] = None,
        ordering_violations: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
    ):
        self.is_valid = is_valid
        self.cycle_detected = cycle_detected
        self.orphan_dependencies = orphan_dependencies or []
        self.ordering_violations = ordering_violations or []
        self.errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "cycle_detected": self.cycle_detected,
            "orphan_dependencies": self.orphan_dependencies,
            "ordering_violations": self.ordering_violations,
            "errors": self.errors,
        }


def _run_kahns_algorithm(
    node_ids: List[str],
    dependencies: Dict[str, List[str]],
) -> Tuple[bool, List[str]]:
    """
    Executes Kahn's algorithm for topological sorting.
    Returns (has_cycle, cycle_or_unresolved_nodes).
    """
    in_degree: Dict[str, int] = {nid: 0 for nid in node_ids}
    adj_list: Dict[str, List[str]] = {nid: [] for nid in node_ids}

    for nid in node_ids:
        deps = dependencies.get(nid, [])
        for dep in deps:
            if dep in adj_list:
                adj_list[dep].append(nid)
                in_degree[nid] += 1

    queue: deque = deque([nid for nid in node_ids if in_degree[nid] == 0])
    visited_count = 0

    while queue:
        curr = queue.popleft()
        visited_count += 1
        for neighbor in adj_list[curr]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    if visited_count < len(node_ids):
        unresolved = [nid for nid in node_ids if in_degree[nid] > 0]
        return True, unresolved
    return False, []


def validate_build_plan_steps(steps: List[Any]) -> DAGValidationResult:
    """
    Validates macro build plan steps (e.g. STEP-01-APIS, STEP-02-STORAGE, etc.)
    using Kahn's algorithm and canonical stage ordering invariants.
    """
    if not steps:
        return DAGValidationResult(is_valid=True)

    errors: List[str] = []
    orphans: List[str] = []
    ordering_violations: List[str] = []

    step_ids: List[str] = []
    dependencies: Dict[str, List[str]] = {}
    categories_by_id: Dict[str, str] = {}
    seen_ids: Set[str] = set()

    for s in steps:
        sid = getattr(s, "step_id", None) or (s.get("step_id") if isinstance(s, dict) else "")
        if not sid:
            continue
        if sid in seen_ids:
            errors.append(f"Duplicate step_id detected: '{sid}'")
        seen_ids.add(sid)
        step_ids.append(sid)

        deps = getattr(s, "depends_on", None) or (s.get("depends_on") if isinstance(s, dict) else [])
        dependencies[sid] = list(deps) if deps else []

        cat = getattr(s, "category", None) or (s.get("category") if isinstance(s, dict) else "")
        cat_str = cat.value if hasattr(cat, "value") else str(cat)
        categories_by_id[sid] = cat_str.split(".")[-1].upper()

    # 1. Orphan check: Verify all dependencies point to existing step_ids
    for sid, deps in dependencies.items():
        for dep in deps:
            if dep not in seen_ids:
                orphans.append(f"Step '{sid}' references non-existent prerequisite '{dep}'")

    # 2. Cycle check via Kahn's algorithm
    has_cycle, cycle_nodes = _run_kahns_algorithm(step_ids, dependencies)
    if has_cycle:
        errors.append(f"Topological cycle detected in build steps among nodes: {cycle_nodes}")

    # 3. Canonical Stage Ordering Invariants
    # e.g., IAM should not depend on COMPUTE; FOUNDATION_API should not depend on APP_CODE
    stage_priority = {
        "FOUNDATION_API": 1,
        "STORAGE_AND_DATA": 2,
        "DATABASE": 2,
        "REGISTRY": 2,
        "IAM": 3,
        "APP_CODE": 4,
        "CICD": 5,
        "COMPUTE": 6,
        "TEST": 7,
        "DOCS": 8,
    }

    for sid, deps in dependencies.items():
        curr_cat = categories_by_id.get(sid, "")
        curr_prio = stage_priority.get(curr_cat)
        if curr_prio is not None:
            for dep in deps:
                dep_cat = categories_by_id.get(dep, "")
                dep_prio = stage_priority.get(dep_cat)
                if dep_prio is not None and dep_prio > curr_prio:
                    ordering_violations.append(
                        f"Stage ordering inverted: Step '{sid}' ({curr_cat}, prio {curr_prio}) "
                        f"depends on later-stage step '{dep}' ({dep_cat}, prio {dep_prio})"
                    )

    is_valid = not (has_cycle or orphans or errors or ordering_violations)
    all_errors = errors + orphans + ordering_violations
    return DAGValidationResult(
        is_valid=is_valid,
        cycle_detected=has_cycle,
        orphan_dependencies=orphans,
        ordering_violations=ordering_violations,
        errors=all_errors,
    )


def validate_task_dag_items(tasks: List[Any]) -> DAGValidationResult:
    """
    Validates micro tasks (infra_tasks and code_tasks) using Kahn's algorithm.
    """
    if not tasks:
        return DAGValidationResult(is_valid=True)

    errors: List[str] = []
    orphans: List[str] = []

    task_ids: List[str] = []
    dependencies: Dict[str, List[str]] = {}
    seen_ids: Set[str] = set()

    for t in tasks:
        tid = getattr(t, "task_id", None) or (t.get("task_id") if isinstance(t, dict) else "")
        if not tid:
            continue
        if tid in seen_ids:
            errors.append(f"Duplicate task_id detected: '{tid}'")
        seen_ids.add(tid)
        task_ids.append(tid)

        deps = getattr(t, "depends_on", None) or (t.get("depends_on") if isinstance(t, dict) else [])
        dependencies[tid] = list(deps) if deps else []

    # 1. Orphan check
    for tid, deps in dependencies.items():
        for dep in deps:
            if dep not in seen_ids:
                orphans.append(f"Task '{tid}' references non-existent prerequisite task '{dep}'")

    # 2. Cycle check
    has_cycle, cycle_nodes = _run_kahns_algorithm(task_ids, dependencies)
    if has_cycle:
        errors.append(f"Topological cycle detected in task DAG among tasks: {cycle_nodes}")

    is_valid = not (has_cycle or orphans or errors)
    all_errors = errors + orphans
    return DAGValidationResult(
        is_valid=is_valid,
        cycle_detected=has_cycle,
        orphan_dependencies=orphans,
        errors=all_errors,
    )


def validate_dual_layer_dag(
    steps: Optional[List[Any]] = None,
    infra_tasks: Optional[List[Any]] = None,
    code_tasks: Optional[List[Any]] = None,
) -> DAGValidationResult:
    """
    Validates both macro build steps and combined micro infra/code tasks.
    """
    step_res = validate_build_plan_steps(steps or [])
    all_tasks = (infra_tasks or []) + (code_tasks or [])
    task_res = validate_task_dag_items(all_tasks)

    combined_valid = step_res.is_valid and task_res.is_valid
    combined_cycle = step_res.cycle_detected or task_res.cycle_detected
    combined_orphans = step_res.orphan_dependencies + task_res.orphan_dependencies
    combined_order = step_res.ordering_violations
    combined_errors = step_res.errors + task_res.errors

    return DAGValidationResult(
        is_valid=combined_valid,
        cycle_detected=combined_cycle,
        orphan_dependencies=combined_orphans,
        ordering_violations=combined_order,
        errors=combined_errors,
    )

"""
FD-4F: the former Stage 2 keyword heuristics, kept ONLY as unreferenced library code.

They are NOT a verdict source any more: no gateway code path calls them (the lenses raise LensUnavailableError
when the judge is unavailable, the coordinator never substitutes them). They remain importable solely because
`tests/test_qa_gatekeeper.py` (lane 2-owned) imports them at module level; this file is deleted together with
that test change (sequenced, see docs/implemented/wave2-lane13-fd4f-hardened-plan.md §11 Stage 2 notes).
Do not add callers.
"""

import os
import re
from typing import Any, Dict, List

from shared.qa_audit_schemas import AdherenceLensResult, SecurityLensResult


def _deterministic_security_heuristic(
    git_diff: str,
    allow_unauth: bool,
    requires_vpc: bool,
) -> SecurityLensResult:
    """Heuristic scanner for secret leaks, primitive IAM roles, and forbidden ingress."""
    criticals = []
    moderates = []
    flags = []

    diff_lower = git_diff.lower()

    # 1. Private keys and tokens
    if "begin private key" in diff_lower or "begin rsa private key" in diff_lower:
        criticals.append("Detected hardcoded private key in source code or manifests.")
    if re.search(r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', git_diff):
        criticals.append("Detected potential hardcoded API secret or credential token.")

    # 2. Primitive IAM roles
    if "roles/owner" in git_diff:
        criticals.append("Detected forbidden primitive IAM role 'roles/owner'. Use least-privilege roles.")
    if "roles/editor" in git_diff:
        criticals.append("Detected forbidden primitive IAM role 'roles/editor'. Use least-privilege roles.")

    # 3. Public database ingress
    if "0.0.0.0/0" in git_diff:
        # Check if inside database or storage context
        if any(db_kw in diff_lower for db_kw in ["sql", "database", "authorized_networks", "redis"]):
            criticals.append("Detected public database ingress (0.0.0.0/0) on private datastore.")
        elif not allow_unauth:
            criticals.append("Detected 0.0.0.0/0 public ingress on a private workload.")
        else:
            moderates.append("Detected 0.0.0.0/0 ingress; verified allowed for public web app.")

    # 4. allUsers checks
    if "allusers" in diff_lower:
        # GCS public bucket check
        if "google_storage_bucket_iam" in diff_lower or "storage.admin" in diff_lower:
            criticals.append("Detected public 'allUsers' access on Cloud Storage bucket.")
        # Cloud Run check
        elif not allow_unauth:
            criticals.append("Detected 'allUsers' invoker on Cloud Run when allow_unauthenticated is false.")
        else:
            flags.append("Public web app configured with roles/run.invoker for allUsers (policy permitted).")

    passed = len(criticals) == 0
    summary = (
        "Security audit passed via deterministic heuristic scan (zero critical defects)."
        if passed
        else f"Security audit failed: {len(criticals)} critical vulnerabilities detected."
    )

    return SecurityLensResult(
        lens_name="SECURITY_AND_INGRESS",
        passed=passed,
        critical_vulnerabilities=criticals,
        moderate_vulnerabilities=moderates,
        compliance_flags=flags,
        summary=summary,
        eval_judge_model="deterministic-heuristic-fallback",
    )


def _deterministic_adherence_heuristic(
    git_diff: str,
    tasks: List[Dict[str, Any]],
) -> AdherenceLensResult:
    """Heuristic scanner matching target files and acceptance criteria against git diff."""
    missed = []
    adherence = 1.0
    grounding = 1.0

    if not tasks:
        return AdherenceLensResult(
            lens_name="TASK_DAG_ADHERENCE",
            instruction_adherence_score=1.0,
            grounding_score=1.0,
            passed=True,
            missed_directives=[],
            hallucinated_features=[],
            summary="Zero task definitions in Task DAG; heuristic pass granted.",
            eval_judge_model="deterministic-heuristic-fallback",
        )

    # Check each task's target files and keywords
    for t in tasks:
        t_id = t.get("task_id") or t.get("id") or "unnamed-task"
        t_title = t.get("title", "")
        target_files = t.get("target_files") or []
        criteria = t.get("acceptance_criteria") or []

        # If task specifies target files, verify at least one appears in git diff
        if target_files:
            file_found = any(os.path.basename(f) in git_diff for f in target_files)
            if not file_found:
                missed.append(f"Task '{t_id}' ({t_title}): None of the target files ({', '.join(target_files)}) found in diff.")
                adherence -= 0.15

        # Check key acceptance criteria terms
        if isinstance(criteria, list):
            for c in criteria:
                c_str = str(c).lower()
                # Check for critical keywords in acceptance criteria (e.g., specific endpoints or resources)
                key_match = re.search(r'["\'](/[\w/\-]+)["\']', c_str)
                if key_match:
                    endpoint = key_match.group(1)
                    if endpoint not in git_diff:
                        missed.append(f"Task '{t_id}': Acceptance criteria endpoint '{endpoint}' not found in implemented code.")
                        adherence -= 0.1

    adherence = max(0.0, min(1.0, round(adherence, 2)))
    passed = adherence >= 0.95 and len(missed) == 0

    summary = (
        "Task DAG adherence verified via deterministic heuristic scan."
        if passed
        else f"Task DAG adherence below threshold ({adherence:.2f}): {len(missed)} missed directives."
    )

    return AdherenceLensResult(
        lens_name="TASK_DAG_ADHERENCE",
        instruction_adherence_score=adherence,
        grounding_score=grounding,
        passed=passed,
        missed_directives=missed,
        hallucinated_features=[],
        summary=summary,
        eval_judge_model="deterministic-heuristic-fallback",
    )

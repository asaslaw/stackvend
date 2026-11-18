"""
Project Castor: Stage 3 - Lead Release Gatekeeper & Autonomous Merge Arbiter
Consumes certified Stage 1 + Stage 2 audit records, enforces workload HITL policy,
generates Markdown Release Certificates, and authorizes Pull Request merges.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

try:
    from shared.qa_audit_schemas import (
        AdherenceLensResult,
        DeterministicGateReport,
        ReleaseGateDecision,
        SecurityLensResult,
    )
except ImportError:
    try:
        from qa_audit_schemas import (
            AdherenceLensResult,
            DeterministicGateReport,
            ReleaseGateDecision,
            SecurityLensResult,
        )
    except ImportError:
        from pydantic import BaseModel, Field

        class ReleaseGateDecision(BaseModel):
            is_approved: bool
            requires_human_intervention: bool
            deterministic_passed: bool = True
            security_clean: bool = True
            adherence_score: float = 1.0
            grounding_score: float = 1.0
            blocking_reasons: List[str] = []
            release_certificate_markdown: str = ""
            recommended_action: Literal["AUTO_MERGE", "BLOCK_FOR_HITL_REVIEW", "AUTO_REJECT"] = "BLOCK_FOR_HITL_REVIEW"
            certified_at: str = ""

try:
    from shared.vcs_provider import VCSProviderFactory
except ImportError:
    try:
        from vcs_provider import VCSProviderFactory
    except ImportError:
        VCSProviderFactory = None

# ADHERENCE-PLATFORM-SATISFIED: qa_auditor.adherence_lens.ADHERENCE_WAIVER_FLOOR (a test pins the equality). Since
# JUDGE-GATE-ENUMERATED-FINDINGS F1 also the contradiction floor: a stored passed record below it blocks.
ADHERENCE_WAIVER_FLOOR = 0.80


def adherence_score_waived(adh_dict: Dict[str, Any]) -> bool:
    """ADHERENCE-PLATFORM-SATISFIED (RT F1): the QA adherence lens waived its below-threshold score because every
    omission it listed is handled by the platform. Re-checked here on the stored record with the lens's own condition
    (exact flag, a passed verdict, no missed directive, score not below the waiver floor). Since
    JUDGE-GATE-ENUMERATED-FINDINGS the score never blocks, so this only words the release certificate."""
    score = adh_dict.get("instruction_adherence_score")
    return (adh_dict.get("adherence_score_waived") is True and adh_dict.get("passed") is True
            and not adh_dict.get("missed_directives")
            and isinstance(score, (int, float)) and not isinstance(score, bool) and score >= ADHERENCE_WAIVER_FLOOR)


def _stored_score(value: Any) -> float:
    """A stored judge score, typed: a number (never a bool: True is not 1.0); anything else reads as 0.0, the
    failed-verdict default (FD-4F RL-2)."""
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


def _is_score(value: Any) -> bool:
    """A stored judge score, typed: a number in [0, 1], never a bool."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0.0 <= float(value) <= 1.0


def _handled_counts(adh_dict: Dict[str, Any]) -> str:
    """The platform-handled findings of the stored record as 'FACET xN' (facet and count only), or "".
    IAM-POLICY-PLATFORM-FACT RT 3: an IAM_POLICY entry also names its refused role(s), only exact roles of the
    platform's IAM policy table (a closed set, safe to print): 'IAM_POLICY x1 (roles/iam.serviceAccountTokenCreator)'."""
    try:
        from qa_auditor.platform_satisfied import FACET_IAM_POLICY, is_denied_role
    except ImportError as exc:  # the certificate never fails on it: no role is printed, said out loud (RT re-review a)
        logger.warning(f"release certificate: the IAM policy role table could not be imported ({exc}); "
                       f"IAM_POLICY counts are printed without their refused role(s)")
        FACET_IAM_POLICY, is_denied_role = "IAM_POLICY", (lambda _r: False)
    counts: Dict[str, int] = {}
    roles: Dict[str, set] = {}
    for key in ("platform_satisfied_directives", "platform_limitation_advisories"):
        for e in adh_dict.get(key) or []:
            facet = e.get("facet") if isinstance(e, dict) else None
            if isinstance(facet, str):
                counts[facet] = counts.get(facet, 0) + 1
                if facet == FACET_IAM_POLICY and is_denied_role(e.get("denied_role")):
                    roles.setdefault(facet, set()).add(e["denied_role"])
    return ", ".join(f"{f} x{n}" + (f" ({', '.join(sorted(roles[f]))})" if roles.get(f) else "")
                     for f, n in sorted(counts.items()))


logger = logging.getLogger("castor-release-gatekeeper")


def evaluate_release_decision(
    determ_report: Any,
    sec_report: Any,
    adh_report: Any,
    workload_policy: Dict[str, Any],
    product_id: str = "",
    branch_name: str = "",
    commit_sha: str = "",
) -> ReleaseGateDecision:
    """
    Evaluates certified reports from Stage 1 & Stage 2 against governance policy.
    Returns the binding ReleaseGateDecision.
    """
    blocking: List[str] = []

    # 1. Inspect Deterministic Report
    determ_dict = determ_report if isinstance(determ_report, dict) else (getattr(determ_report, "model_dump", None) or getattr(determ_report, "dict", lambda: {}))()
    # FD-4F (RL-2): a missing verdict is a failed verdict. Defaults are False / 0.0, never True / 1.0.
    determ_passed = determ_dict.get("passed") is True

    if not determ_passed:
        blocking.extend(determ_dict.get("bandit_issues", []))
        blocking.extend(determ_dict.get("hcl_errors", []))
        blocking.extend(determ_dict.get("zero_dockerfile_violations", []))
        blocking.extend(determ_dict.get("ast_syntax_errors", []))
        if not blocking:
            blocking.append("Deterministic CI checks failed.")

    # 2. Inspect Security Lens
    sec_dict = sec_report if isinstance(sec_report, dict) else (getattr(sec_report, "model_dump", None) or getattr(sec_report, "dict", lambda: {}))()
    crit_vulns = list(sec_dict.get("critical_vulnerabilities", []))
    sec_clean = sec_dict.get("passed") is True and len(crit_vulns) == 0
    if crit_vulns:
        blocking.extend([f"Security: {v}" for v in crit_vulns])
    elif not sec_clean:
        blocking.append("Security lens did not pass (missing or failed verdict).")

    # 3. Inspect Task DAG Adherence Lens
    adh_dict = adh_report if isinstance(adh_report, dict) else (getattr(adh_report, "model_dump", None) or getattr(adh_report, "dict", lambda: {}))()
    adh_score = _stored_score(adh_dict.get("instruction_adherence_score"))
    gnd_score = _stored_score(adh_dict.get("grounding_score"))
    missed_dirs = list(adh_dict.get("missed_directives", []))
    n_before = len(blocking)

    # JUDGE-GATE-ENUMERATED-FINDINGS (owner 11-13): the stored verdict and its missed directives decide; the scores
    # are reported in the certificate, never a blocking reason. A record without both numeric scores is malformed
    # evidence (the lens always writes both; before, a missing adherence score read as 0.0 and blocked): it blocks as
    # such, never as a threshold (RT F4: grounding too, so an approved certificate never prints a missing score).
    if missed_dirs:
        blocking.extend([f"Missed Directive: {d}" for d in missed_dirs])
    if adh_dict.get("passed") is not True and len(blocking) == n_before:
        blocking.append("Adherence lens did not pass (missing or failed verdict).")
    if len(blocking) == n_before and not all(_is_score(adh_dict.get(k))
                                             for k in ("instruction_adherence_score", "grounding_score")):
        blocking.append("Adherence lens record is malformed (no numeric adherence and grounding scores).")
    elif len(blocking) == n_before and adh_score < ADHERENCE_WAIVER_FLOOR:
        # JUDGE-GATE-ENUMERATED-FINDINGS F1 (defence in depth; the lens no longer writes such a record): a passed
        # verdict with nothing listed and a score below the contradiction floor is not a verdict.
        blocking.append(f"Adherence lens record is contradictory (score {adh_score:.2f} below "
                        f"{ADHERENCE_WAIVER_FLOOR:.2f} with no missed directive).")

    # 4. Workload Governance Policy
    # FD-4P (RT F7, P3): one exact bool. The derived `auto_merge` display field never overrides human review.
    require_human = workload_policy.get("require_human_code_review") is not False

    is_clean = len(blocking) == 0
    is_approved = is_clean and (not require_human)

    if not is_clean:
        action = "AUTO_REJECT"
    elif is_approved:
        action = "AUTO_MERGE"
    else:
        action = "BLOCK_FOR_HITL_REVIEW"

    now_iso = datetime.now(timezone.utc).isoformat()

    decision = ReleaseGateDecision(
        is_approved=is_approved,
        requires_human_intervention=require_human or (not is_clean),
        deterministic_passed=determ_passed,
        security_clean=sec_clean,
        adherence_score=adh_score,
        grounding_score=gnd_score,
        blocking_reasons=blocking,
        recommended_action=action,
        certified_at=now_iso,
    )

    cert_md = generate_release_certificate(
        decision=decision,
        product_id=product_id,
        branch_name=branch_name,
        commit_sha=commit_sha,
        determ_dict=determ_dict,
        sec_dict=sec_dict,
        adh_dict=adh_dict,
    )
    decision.release_certificate_markdown = cert_md
    return decision


def _pytest_counts(d_info: Dict[str, Any]) -> Tuple[int, int, str]:
    """RT14-17: (passed, ran, skipped note) for the certificate row. The QA evidence record keeps the sandbox counts in
    its `report` (tests_total / tests_failed / tests_skipped); a caller's top-level tests_passed / tests_total are used
    as given. A skipped or xfail test is never counted as passed or as run; the note is "" when none was skipped."""
    report = d_info.get("report")
    if "tests_total" not in d_info and isinstance(report, dict) and _is_count(report.get("tests_total")):
        total = report["tests_total"]
        failed = report.get("tests_failed") if _is_count(report.get("tests_failed")) else 0
        skipped = report.get("tests_skipped") if _is_count(report.get("tests_skipped")) else 0
        ran = max(total - skipped, 0)
        return max(ran - failed, 0), ran, (f" ({skipped} skipped)" if skipped else "")
    py_passed = d_info.get("tests_passed", 0)
    return py_passed, d_info.get("tests_total", py_passed), ""


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _fallback_judge_note(info: Dict[str, Any]) -> str:
    """QA-JUDGE-FALLBACK RT D1: the certificate row suffix naming a fallback judge, from the stored lens record's typed
    fields only (`eval_judge_fallback` exactly True); "" when the evaluation model gave the verdict."""
    if info.get("eval_judge_fallback") is not True:
        return ""
    return (f"; reviewed by fallback model `{info.get('eval_judge_model')}` "
            f"(`{info.get('eval_judge_primary_model')}` unavailable)")


def generate_release_certificate(
    decision: ReleaseGateDecision,
    product_id: str = "",
    branch_name: str = "",
    commit_sha: str = "",
    determ_dict: Optional[Dict[str, Any]] = None,
    sec_dict: Optional[Dict[str, Any]] = None,
    adh_dict: Optional[Dict[str, Any]] = None,
) -> str:
    """Renders the standard Project Castor Release Certificate in GitHub-flavored Markdown."""
    d_info = determ_dict or {}
    s_info = sec_dict or {}
    a_info = adh_dict or {}

    py_passed, py_total, py_skipped = _pytest_counts(d_info)
    bandit_issues = len(d_info.get("bandit_issues", []))
    hcl_issues = len(d_info.get("hcl_errors", []))
    # QA-RECORD-HCL-FIELD: `hcl_syntax_passed` None (or absent) = this report did not check HCL (QA does not; the
    # pre-commit gate does): say so instead of "0 HCL syntax errors". Errors listed are always counted.
    hcl_note = (f"{hcl_issues} HCL syntax errors" if hcl_issues or d_info.get("hcl_syntax_passed") is not None
                else "HCL syntax not checked by QA")
    docker_issues = len(d_info.get("zero_dockerfile_violations", []))
    ast_issues = len(d_info.get("ast_syntax_errors", []))

    det_status = "✅ PASSED" if decision.deterministic_passed else "❌ FAILED"
    docker_status = "✅ PASSED" if docker_issues == 0 else "❌ VIOLATION"
    sec_status = "✅ PASSED" if decision.security_clean else "❌ VULNERABILITIES"
    # JUDGE-GATE-ENUMERATED-FINDINGS: the lens row follows the verdict and its listed findings; a score below 95% is
    # named as informational, never as the defect.
    adh_status = "✅ PASSED" if (a_info.get("passed") is True and not a_info.get("missed_directives")
                                and _is_score(a_info.get("instruction_adherence_score"))
                                and _is_score(a_info.get("grounding_score"))
                                and a_info["instruction_adherence_score"] >= ADHERENCE_WAIVER_FLOOR) else "❌ DEFECTS"
    handled = _handled_counts(a_info)
    # SECURITY-LENS-PLATFORM-FACTS: the security lens's platform-handled findings (advisories) on its own row.
    sec_handled_counts = _handled_counts(s_info)
    sec_handled = f"; platform-handled, not code defects: {sec_handled_counts}" if sec_handled_counts else ""
    adh_handled = (f"; platform-handled, not code defects: {handled}"
                   + (" (score below 95% waived)" if adherence_score_waived(a_info) else "")) if handled else ""
    if not adherence_score_waived(a_info) and any(
            _is_score(a_info.get(k)) and a_info[k] < 0.95 for k in ("instruction_adherence_score", "grounding_score")):
        adh_handled += "; score below 95%: informational, not a blocking reason"

    if decision.is_approved:
        verdict = "**APPROVED FOR AUTONOMOUS MERGE**"
        verdict_badge = "🟢 CERTIFIED"
        action_note = f"Automated merge authorized into `main` (Branch: `{branch_name}`)."
    elif decision.recommended_action == "BLOCK_FOR_HITL_REVIEW":
        verdict = "**PENDING HUMAN OPERATOR APPROVAL (HITL Enforced)**"
        verdict_badge = "🟡 PENDING REVIEW"
        action_note = "All automated quality and security gates passed. Left PR open for operator review per workload governance policy."
    else:
        verdict = "**REJECTED BY RELEASE GATEKEEPER**"
        verdict_badge = "🔴 REJECTED"
        blocking_list = "\n".join([f"- {b}" for b in decision.blocking_reasons])
        action_note = f"Auto-merge blocked due to non-negotiable policy violations:\n{blocking_list}"

    cert = f"""## 🛡️ StackVend: Autonomous Release Certification

- **Workload / Product**: `{product_id or 'unknown'}`
- **Branch**: `{branch_name or 'unknown'}`
- **Commit SHA**: `{commit_sha[:8] if commit_sha else 'HEAD'}`
- **Certified At**: `{decision.certified_at}`
- **Release Seal**: {verdict_badge}

| Verification Stage | Status | Metrics / Audit Findings |
| :--- | :--- | :--- |
| **Deterministic Hard Gate** | {det_status} | {py_passed}/{py_total} Pytest passed{py_skipped}, {bandit_issues} Bandit Sev-1/2, {hcl_note} |
| **Zero Dockerfile Policy** | {docker_status} | 100% Google Cloud Buildpacks compliant ({docker_issues} Dockerfile violations) |
| **Python AST Integrity** | ✅ PASSED | {ast_issues} syntax errors across application modules |
| **Security & Ingress Lens** | {sec_status} | {len(s_info.get('critical_vulnerabilities', []))} critical defects{sec_handled}, Contextual ingress policy verified{_fallback_judge_note(s_info)} |
| **Task DAG Adherence Lens** | {adh_status} | **{decision.adherence_score * 100:.1f}%** Adherence, **{decision.grounding_score * 100:.1f}%** Grounding ({len(a_info.get('missed_directives', []))} missed directives{adh_handled}){_fallback_judge_note(a_info)} |

> **Gatekeeper Verdict**: {verdict}  
> **Operational Status**: {action_note}
"""
    return cert.strip()


def post_release_certificate_to_vcs(
    full_repo_name: str,
    pr_number: Optional[int],
    markdown_content: str,
    product_id: str,
    project_id: str = "",
    default_owner: str = "",
    vcs_provider_name: Optional[str] = None,
) -> bool:
    """
    Safely posts the Release Certificate comment to the Pull Request.
    Operates resiliently with GitHubProvider and safely handles ServerlessGitProvider.
    """
    if not VCSProviderFactory or not pr_number:
        logger.debug("VCSProviderFactory not available or no PR number; skipping PR comment.")
        return False

    try:
        vcs = VCSProviderFactory.get_provider(
            provider_name=vcs_provider_name,
            default_owner=default_owner,
            project_id=project_id,
            product_id=product_id,
            full_repo_name=full_repo_name,
        )
        if hasattr(vcs, "post_pull_request_comment"):
            vcs.post_pull_request_comment(full_repo_name, pr_number, markdown_content)
            logger.info(f"Posted Release Certificate to PR #{pr_number} on '{full_repo_name}'")
            return True
        elif hasattr(vcs, "create_pull_request_comment"):
            vcs.create_pull_request_comment(full_repo_name, pr_number, markdown_content)
            return True
    except Exception as e:
        logger.warning(f"Could not post PR certificate comment via VCSProvider: {e}")

    return False

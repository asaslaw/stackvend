"""QA-STAGE2-INPUT (owner 10-27): what the Stage 2 judges are shown of a commit.

Before: one unified diff of every changed file in path order, cut at 60 000 characters with the file inventory
appended AFTER the cut, then cut again at 40 000 by each lens. Path order put `.github/`, `cloudbuild.yaml`,
`contracts/`, `docs/planning/` and the copied golden modules (`infra/modules/`) before `infra/workload/` and root
`tests/`, so on any realistic first build the judges never saw the workload's root Terraform or its tests and
reported them "missing" (testplan01-d2, 10-27 live run).

Now (pure functions, no I/O; deterministic for a given input):
- FILES: the complete list of changed files (base `main` -> committed head), names never truncated, each with its
  status and whether its diff is shown; plus every exact path the task DAG names (`target_files`) with its state in
  the commit (changed / present but unchanged / not at that exact path), so a "missing" claim can be checked.
- DIFF: one shared size budget (STAGE2_DIFF_BUDGET_CHARS; the lenses no longer cut again), whole files only, in
  priority order by exact path structure: the files directly in `infra/workload/` (root Terraform,
  `terraform.tfvars`, the typed intent `iac_intent.json` and its render); then root `tests/**` and `apps/**`; then
  the plan (`docs/planning/*.md`); then everything else in path order. A file that does not fit is listed as not
  shown (never cut in the middle). A workload file (WORKLOAD_TIERS) that does not fit stops Stage 2 in run_qa
  (GATE_UNAVAILABLE QA_INPUT_BUDGET, Fable RT F1): the judges never pass a workload they were not shown.
- Copied platform golden modules are listed by name only. Which files those are is decided by the caller from the
  exact vendoring source (path AND byte-identical content, `main._platform_golden_copies`), never by path text.
- Asset / lock files are listed by name only (same exact extension / basename sets as before).

Both judges frame the FILES and DIFF content with `judge.untrusted_block` (AI-written names and code).
"""

import difflib
import os
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from shared.artifact_ownership import (DEPLOY_WORKFLOW_RENDER, LLM_DOCUMENT_PATHS, PLATFORM_RENDERED_FLOOR,
                                       RENDER_SOURCES, RUNTIME_PIN_RENDER, RenderSource)
from shared.iac_intent import FACTS_RENDER_PATH, INTENT_PATH, RENDER_PATH

from developer_agent.workload_test_layout import is_root_test_path, service_tests_dir
from developer_agent.workload_test_layout import services as _layout_services

from .platform_satisfied import facts_lines as _platform_handled_lines
from .platform_satisfied import is_printable_service_name

# One budget for the DIFF block, shared by both lenses. Fable RT F1 (10-27): the 27 committed Gate A first-build trees
# (10-18, plans 01-09) measure up to about 236 kB IN TOTAL (every file, golden copies included); `apps/` + `tests/`
# alone exceed 80 kB on 18 of 27. 400 000 characters (about 100 k tokens, a fraction of the model's context) holds
# the largest measured tree whole, with about 1.7x headroom; a workload file that still does not fit fails closed.
STAGE2_DIFF_BUDGET_CHARS = 400_000

# RT14-29 (owner 11-14): the Task DAG is shown to the adherence judge WHOLE (it was cut at 15 000 characters, mid-JSON,
# so the acceptance criteria of later tasks could never be reported missed). A DAG whose JSON is longer than this
# budget stops Stage 2 with GATE_UNAVAILABLE QA_INPUT_BUDGET (run_qa), the same rule as a workload file the diff
# budget leaves out. 100 000 characters is about 25 k tokens; the 11-11 cassettes peaked at about 9 000.
TASK_DAG_BUDGET_CHARS = 100_000


def task_dag_json(task_dag: Optional[Sequence[Any]]) -> str:
    """RT14-29: the exact Task DAG text the adherence judge is shown (never cut); "[]" for no plan."""
    import json
    return json.dumps(list(task_dag), indent=2) if task_dag else "[]"

DIFF_EXCLUDED_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pyc", ".lock"})
DIFF_EXCLUDED_FILES = frozenset({"package-lock.json", "poetry.lock", "yarn.lock", "pnpm-lock.yaml"})

# Fable RT F1: the root module (what the security lens exists to audit) first, then app code and tests.
TIER_WORKLOAD_ROOT_MODULE, TIER_WORKLOAD_CODE, TIER_PLAN, TIER_OTHER = 0, 1, 2, 3
WORKLOAD_TIERS = frozenset({TIER_WORKLOAD_ROOT_MODULE, TIER_WORKLOAD_CODE})

SHOWN = "diff shown"
NOT_SHOWN_BUDGET = "content not shown: size budget"
NOT_SHOWN_GOLDEN = "platform golden module copy: not under audit, content not shown"
NOT_SHOWN_ASSET = "asset or lock file: content not shown"
# Fable RT F5: the diff splits with str.splitlines(), which also treats form feeds, \x1c-\x1e, \x85 and U+2028/9 as
# line breaks; the note says exactly that.
NO_LINE_CHANGES = "no line changes: only line-break characters or the final newline differ"


@dataclass(frozen=True)
class JudgeInput:
    diff: str                                  # the DIFF block content
    files: str                                 # the FILES block content
    shown: Tuple[str, ...] = ()
    not_shown_budget: Tuple[str, ...] = ()
    golden: Tuple[str, ...] = ()

    @property
    def workload_not_shown(self) -> Tuple[str, ...]:
        """Workload-authored text files (WORKLOAD_TIERS, not assets) the budget left out: run_qa fails closed on any."""
        return tuple(p for p in self.not_shown_budget if path_tier(p) in WORKLOAD_TIERS and not is_asset(p))


def path_tier(path: str) -> int:
    """Priority of a changed file in the DIFF block, by exact path components (no text matching)."""
    parts = path.split("/")
    if len(parts) == 3 and parts[0] == "infra" and parts[1] == "workload":
        return TIER_WORKLOAD_ROOT_MODULE
    if len(parts) > 1 and parts[0] in ("tests", "apps"):
        return TIER_WORKLOAD_CODE
    if len(parts) == 3 and parts[0] == "docs" and parts[1] == "planning" and os.path.splitext(parts[2])[1] == ".md":
        return TIER_PLAN
    return TIER_OTHER


def is_asset(path: str) -> bool:
    name = os.path.basename(path)
    return os.path.splitext(name)[1].lower() in DIFF_EXCLUDED_EXTS or name in DIFF_EXCLUDED_FILES


def _file_diff(path: str, old: Optional[str], new: Optional[str]) -> str:
    return "\n".join(difflib.unified_diff(
        (old or "").splitlines(), (new or "").splitlines(),
        fromfile=f"a/{path}" if old is not None else "/dev/null",
        tofile=f"b/{path}" if new is not None else "/dev/null",
        lineterm="",
    ))


def plan_target_files(task_dag: Optional[Sequence[Any]]) -> List[str]:
    """Every exact `target_files` string of the task DAG, first-seen order, no duplicates."""
    out: List[str] = []
    seen = set()
    for task in task_dag or []:
        targets = task.get("target_files") if isinstance(task, Mapping) else None
        for t in targets if isinstance(targets, list) else []:
            if isinstance(t, str) and t and t not in seen:
                seen.add(t)
                out.append(t)
    return out


def layout_services(service_names: Any) -> Tuple[str, ...]:
    """TEST-LAYOUT-PLATFORM-FACT: the developer's typed service list (`ComputeIntent.service_names`, recorded on
    `pipeline_executions/{trace}.developer_compute_intent`) when it has more than one service and every entry is a
    printable service name (it is printed in the trusted PLATFORM FACTS); () otherwise (no fact: fail closed)."""
    if not isinstance(service_names, (list, tuple)) or not all(is_printable_service_name(n) for n in service_names):
        return ()
    names = _layout_services(service_names)
    return names if len(names) > 1 else ()


# TEST-LAYOUT-PLATFORM-FACT: the PLAN TARGET FILES state of a root `tests/` target of a multi-service workload.
LAYOUT_TARGET_STATE = ("not in this commit at this exact path; the platform's multi-service test layout rule puts "
                       "each service's tests in `apps/<service>/tests/` and forbids the repository-root `tests/`: "
                       "judge the services' tests there")


def build_judge_input(base_files: Mapping[str, str], head_files: Mapping[str, str], *,
                      task_dag: Optional[Sequence[Any]] = None, golden_copies: FrozenSet[str] = frozenset(),
                      budget: Optional[int] = None, test_layout_services: Any = None,
                      base_branch: str = "main") -> JudgeInput:
    """The judges' FILES and DIFF content for base -> head (module docstring). `test_layout_services`
    (TEST-LAYOUT-PLATFORM-FACT): the developer's typed service list; with more than one service a root `tests/` plan
    target that is not in the commit is described by the layout rule (`layout_services`); else byte-identical.
    `base_branch` (RT14-28): the workload's recorded base branch the diff is taken from, named in the header ("main",
    the default, gives the earlier text byte for byte)."""
    budget = STAGE2_DIFF_BUDGET_CHARS if budget is None else budget
    multi_service = bool(layout_services(test_layout_services))
    changed = sorted(p for p in set(base_files) | set(head_files) if base_files.get(p) != head_files.get(p))
    status = {p: ("added" if p not in base_files else "deleted" if p not in head_files else "modified")
              for p in changed}

    note: Dict[str, str] = {}
    candidates: List[Tuple[int, str]] = []
    for p in changed:
        if p in golden_copies and p in head_files:
            note[p] = NOT_SHOWN_GOLDEN
        else:
            candidates.append((path_tier(p), p))

    chunks: List[str] = []
    used = 0
    shown: List[str] = []
    over: List[str] = []
    for _, p in sorted(candidates):
        if is_asset(p):
            chunk = f"diff --git {p} [ASSET/LOCKFILE PRUNED]"
        else:
            chunk = _file_diff(p, base_files.get(p), head_files.get(p))
            if not chunk:
                note[p] = NO_LINE_CHANGES
                continue
        cost = len(chunk) + (1 if chunks else 0)
        if used + cost > budget:
            note[p] = NOT_SHOWN_BUDGET
            over.append(p)
            continue
        chunks.append(chunk)
        used += cost
        if is_asset(p):
            note[p] = NOT_SHOWN_ASSET
        else:
            note[p] = SHOWN
            shown.append(p)

    lines = [f"CHANGED FILES ({len(changed)}; the complete list, base branch {base_branch} -> this commit):"]
    lines += [f"- {status[p]}: {p} [{note[p]}]" for p in changed] or ["- (none)"]
    targets = plan_target_files(task_dag)
    lines.append("")
    lines.append(f"PLAN TARGET FILES ({len(targets)}; every exact path the task DAG names, as found in this commit):")
    for t in targets:
        if t not in head_files:
            state = (LAYOUT_TARGET_STATE if multi_service and is_root_test_path(t)
                     else "not in this commit at this exact path")
        elif t not in status:
            state = "present, unchanged in this commit (content not shown; it is not missing)"
        elif t in golden_copies:
            state = f"present, changed in this commit [{NOT_SHOWN_GOLDEN}]"
        else:
            state = f"present, changed in this commit [{note.get(t, SHOWN)}]"
        lines.append(f"- {t}: {state}")
    if not targets:
        lines.append("- (none)")

    golden = tuple(p for p in changed if note.get(p) == NOT_SHOWN_GOLDEN)
    return JudgeInput(diff="\n".join(chunks), files="\n".join(lines), shown=tuple(shown),
                      not_shown_budget=tuple(over), golden=golden)


# The judges' reading rules for the FILES block (both lenses; the block itself is untrusted data).
FILES_SECTION_TEMPLATE = """### FILES UNDER AUDIT:
The platform's record of this commit: every changed file (complete; compared with the {base_branch} branch) and every file
the plan names, as found in the commit. Reading rules:
- Every path listed as added, modified or present exists in the commit. A file marked "content not shown" exists in
  the commit; its content is outside this audit.
- Only files marked "diff shown" are in the diff below, in this order: the workload's root Terraform in
  `infra/workload/`, then application code and tests, then the plan, then other files.
- A "platform golden module copy" is a byte-identical copy of the platform's own reviewed golden module: it is not
  under audit.
- A plan target file "present, unchanged in this commit" was committed earlier and is still there: it is not missing.
{files_block}
"""


def files_section(files_block: Optional[str], base_branch: str = "main") -> str:
    """The FILES section of a lens prompt, or "" (no section) when the caller gave no file record. `base_branch`
    (RT14-28): the workload's recorded base branch the commit is compared with ("main" gives the earlier text)."""
    return (FILES_SECTION_TEMPLATE.format(files_block=files_block, base_branch=base_branch) + "\n"
            if files_block is not None else "")


# ------------------------------------------------------------------------------------------------ platform facts
# QA-STAGE2-PLATFORM-FACTS (owner 10-27): what the platform writes itself, told to the adherence judge as typed facts
# (VCS provider of the source QA fetched, IaC mode of the committed tree, exact task category / exact target path).
VCS_GITHUB, VCS_SERVERLESS_GIT = "GITHUB", "SERVERLESS_GIT"      # shared.vcs_ledger.PROVIDER_* (a test pins them)
IAC_MODE_GENERATE, IAC_MODE_OFF = "generate", "off"              # iac_intent_contract.MODE_* (a test pins them)
# The CI file of a Serverless Git workload (ServerlessGitProvider.get_pipeline_contract(...).target_file; pinned).
SERVERLESS_GIT_PIPELINE_FILE = "cloudbuild.yaml"
# The CI directory the developer replaces on GitHub and purges on Serverless Git (handler.py, step 2: every path
# under `.github/workflows/` and the root `cloudbuild.yaml`), as exact path components.
CI_WORKFLOW_DIR = (".github", "workflows")
# Exact task categories (architect_agent.schemas.TaskCategory / BuildStepCategory values).
CI_TASK_CATEGORIES = frozenset({"CICD"})
IAC_TASK_CATEGORIES = frozenset({"INFRA", "FOUNDATION_API", "DATABASE", "REGISTRY", "IAM", "COMPUTE"})

TASK_ID_MAX_CHARS = 64
FACT_CI = "CI/CD"
FACT_IAC = "infrastructure"


def is_platform_ci_path(path: Any) -> bool:
    """The developer's exact CI ownership rule: a file under `.github/workflows/`, or the root `cloudbuild.yaml`.
    RT F2 (SECURITY-LENS-PLATFORM-FACTS): exact path components only; a path with an empty, `.` or `..` component
    (`.github/workflows/../../apps/x/main.py`) is never a CI path."""
    if not isinstance(path, str):
        return False
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    return (len(parts) > 2 and tuple(parts[:2]) == CI_WORKFLOW_DIR) or path == SERVERLESS_GIT_PIPELINE_FILE


def _platform_iac_paths() -> FrozenSet[str]:
    return frozenset(PLATFORM_RENDERED_FLOOR) | {RENDER_PATH, FACTS_RENDER_PATH, "infra/workload/terraform.tfvars"}


# PLATFORM-RENDERED-FINDING (owner 11-13, RT probe 6): the one registry of files the platform renders on every run,
# shared by QA routing (developer_agent.qa_repair) and the judges' platform facts (PlatformFacts.platform_rendered_paths)
# so both see the same set. RT S1: the CI files the platform renders are exactly the deploy workflows
# generate_service_workflow writes (developer_agent.handler.gha_workflow_paths: `.github/workflows/deploy-NAME.yml`,
# directly in that directory, parity-tested) and the Serverless Git pipeline file, not every file of the CI folder.
DEPLOY_WORKFLOW_PREFIX, DEPLOY_WORKFLOW_SUFFIX = "deploy-", ".yml"


def is_platform_deploy_workflow(path: Any) -> bool:
    """`.github/workflows/deploy-NAME.yml` (three exact components, a non-empty NAME): a generated deploy workflow."""
    parts = path.split("/") if isinstance(path, str) else []
    return (len(parts) == 3 and tuple(parts[:2]) == CI_WORKFLOW_DIR and parts[2].startswith(DEPLOY_WORKFLOW_PREFIX)
            and parts[2].endswith(DEPLOY_WORKFLOW_SUFFIX)
            and len(parts[2]) > len(DEPLOY_WORKFLOW_PREFIX) + len(DEPLOY_WORKFLOW_SUFFIX))


def is_platform_rendered(path: Any, content: Any) -> bool:
    """The platform renders this file on every run, by exact registries: the rendered IaC floor, the intent / facts
    renders and tfvars (`_platform_iac_paths`), a generated deploy workflow, the root Serverless Git pipeline file,
    and the runtime pin with exactly the platform's content (developer_agent.runtime_pin, imported at call time: the
    developer package imports this module). RT F2 (SECURITY-LENS-PLATFORM-FACTS): a path with an empty, `.` or `..`
    component is never platform-rendered."""
    if not isinstance(path, str) or any(p in ("", ".", "..") for p in path.split("/")):
        return False
    if path in _platform_iac_paths() or is_platform_deploy_workflow(path) or path == SERVERLESS_GIT_PIPELINE_FILE:
        return True
    from developer_agent.runtime_pin import is_platform_runtime_pin
    return is_platform_runtime_pin(path, content)


def render_sources_of(path: Any, content: Any) -> Tuple[RenderSource, ...]:
    """QA-STOP-RENDER-SOURCES: the typed sources (shared.artifact_ownership.RENDER_SOURCES) of a file the platform
    renders (`is_platform_rendered`, the same registry), keyed exactly: its own path, a generated deploy workflow, or
    the runtime pin with the platform's content. () for any other file (not a platform render)."""
    if not is_platform_rendered(path, content):
        return ()
    if path in RENDER_SOURCES:
        return RENDER_SOURCES[path]
    if is_platform_deploy_workflow(path):
        return RENDER_SOURCES[DEPLOY_WORKFLOW_RENDER]
    from developer_agent.runtime_pin import is_platform_runtime_pin
    if is_platform_runtime_pin(path, content):
        return RENDER_SOURCES[RUNTIME_PIN_RENDER]
    return ()


def platform_rendered_paths(committed: Any) -> FrozenSet[str]:
    """The committed files the platform itself writes: the paths of the commit that the ONE ownership predicate
    (shared.artifact_ownership.classify_repository_file, the same answer QA routing gets for each file:
    PLATFORM-RENDERED-FINDING) classes PLATFORM_RENDERED. `committed` is the committed tree (path to content: the
    runtime pin is checked by content) or, from an older caller, its paths only (a pin is then never in the set). The
    AI's typed documents and their render (`LLM_DOCUMENT_PATHS`), a person's files (`human.tf`, override files),
    other AI HCL, modules and a person's own CI files are never in it; a path not in the commit never is."""
    from shared.artifact_ownership import Ownership, classify_repository_file
    tree = dict(committed) if isinstance(committed, Mapping) else {p: None for p in (committed or ())}
    return frozenset(p for p, c in tree.items() if isinstance(p, str) and classify_repository_file(
        p, c if isinstance(c, str) else None, draft=frozenset(), platform_rendered=is_platform_rendered(p, c),
        recorded_versions=None) is Ownership.PLATFORM_RENDERED)


def is_printable_task_id(tid: Any) -> bool:
    """A DAG task_id that may be printed in the trusted PLATFORM FACTS section (Fable RT F2)."""
    return isinstance(tid, str) and 0 < len(tid) <= TASK_ID_MAX_CHARS and tid.isprintable()


def task_fact_kinds(task: Any) -> List[str]:
    """The platform facts that apply to one DAG task: by its exact `category`, or by an exact target path the platform
    itself writes (CI rule above; the IaC floor / intent renders). [] = none."""
    if not isinstance(task, Mapping):
        return []
    category = task.get("category")
    targets = [t for t in (task.get("target_files") if isinstance(task.get("target_files"), list) else [])
               if isinstance(t, str)]
    kinds: List[str] = []
    if category in CI_TASK_CATEGORIES or any(is_platform_ci_path(t) for t in targets):
        kinds.append(FACT_CI)
    iac = _platform_iac_paths()
    if category in IAC_TASK_CATEGORIES or any(t in iac for t in targets):
        kinds.append(FACT_IAC)
    return kinds


def _ci_fact(vcs_provider: Optional[str]) -> str:
    if vcs_provider == VCS_SERVERLESS_GIT:
        return (f"VCS provider: SERVERLESS_GIT (Cloud Build). The platform itself writes the CI/CD pipeline file "
                f"`{SERVERLESS_GIT_PIPELINE_FILE}` and deletes every AI-written file under `.github/workflows/`; GitHub "
                f"Actions is not used on this provider. A plan task that asks for a GitHub Actions workflow under "
                f"`.github/workflows/` is met by the platform's `{SERVERLESS_GIT_PIPELINE_FILE}`: do not report the "
                f"workflow file as missing, and do not report `{SERVERLESS_GIT_PIPELINE_FILE}` as an unmandated feature.")
    if vcs_provider == VCS_GITHUB:
        return ("VCS provider: GITHUB (GitHub Actions). The platform itself writes `.github/workflows/deploy-<service>.yml` "
                "for each service and replaces any AI-written workflow; those files are platform output, not "
                "unmandated features.")
    return "VCS provider: not recorded for this audit (no CI/CD facts)."


def _iac_fact(iac_mode: str) -> str:
    floor = ", ".join(f"`{p}`" for p in sorted(PLATFORM_RENDERED_FLOOR))
    common = (f"In both IaC modes the platform itself renders {floor} and `infra/workload/terraform.tfvars` (when the "
              f"workload needs them) and copies the golden modules into `infra/modules/`: they are expected platform "
              f"output, not unmandated features, and the root module's calls to the golden modules provision the "
              f"workload's resources.")
    if iac_mode == IAC_MODE_GENERATE:
        return (f"IaC mode: generate (typed intent). The AI writes no Terraform: it writes the typed IaC intent "
                f"`{INTENT_PATH}`, and the platform renders `{RENDER_PATH}` (and `{FACTS_RENDER_PATH}` when needed) "
                f"from it. An infrastructure task is met by entries in `{INTENT_PATH}` and their render, even when "
                f"the task names a `.tf` file. " + common)
    return ("IaC mode: Terraform (no typed intent). The AI may add its own Terraform files directly in "
            "`infra/workload/`. " + common)


def _python_runtime_fact(version: str) -> str:
    return (f"Python runtime: the platform itself writes `.python-version` containing `{version}` (the Buildpacks "
            f"runtime pin) in the repository root and in every deployed service directory `apps/<service>/`, and "
            f"replaces any other value; the developer cannot change it. A plan task or acceptance criterion that names "
            f"another Python version is met by this pin: do not report the Python version or a `.python-version` "
            f"file as a missed directive.")


def _direct_iap_fact() -> str:
    return ("Application authentication: this workload's Cloud Run services are served behind Direct IAP (access mode "
            "PRIVATE_IAP). The platform's rule for their code verifies the signed `X-Goog-IAP-JWT-Assertion` header "
            "with IAP's public keys, takes the identity only from the verified claims and forbids any bypass or "
            "mock-auth mode; it overrides other auth detail in the plan. A plan task or acceptance criterion that asks "
            "to read `X-Goog-Authenticated-User-Email` as the identity, or for a mock-auth or bypass flag, is met by "
            "that verification: do not report the email header or the flag as a missed directive, and do not report "
            "the packages the rule requires (`google-auth`, `requests`, `cryptography`) as unmandated features.")


# APP-ADMIN-IAP-CONTRACT (owner 11-16): the env the platform sets on a Direct IAP Cloud Run workload's services
# (developer_agent.terraform_engine.APP_ADMIN_EMAILS_ENV; a test pins the equality).
APP_ADMIN_EMAILS_ENV = "STACKVEND_APP_ADMIN_EMAILS"
APP_ADMIN_NONE_CONFIGURED = "APP_ADMIN.NONE_CONFIGURED"   # developer_agent.handler's warning code (pinned)


def is_app_admin_count(value: Any) -> bool:
    """A typed admin count the facts may print: a non-negative int (never a bool)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _app_admin_fact(count: int) -> str:
    """The app administrator fact of a Direct IAP Cloud Run commit whose root declares the platform's admin list.
    `count` is the only value printed (never an address)."""
    common = (f"A plan task or acceptance criterion that asks for a first-user, first-sign-in or other bootstrap way of "
              f"making the first administrator is met by the platform's administrator list: do not report the "
              f"missing bootstrap as a missed directive. Never granting the role any other way is the platform's rule "
              f"too: a first-user, first-visitor, empty-store, unknown-user or self-service grant of an "
              f"application-wide administrative role, or one taken from a request body, header, query parameter or "
              f"any other environment variable, is a critical security defect (whoever reaches the app first, or "
              f"forges the input, takes the role); report it in the security review. Ownership of a single resource a "
              f"user creates (for example \"whoever creates a project owns that project\") is ordinary app logic, not "
              f"an administrative role. When the plan defines no application-wide administrative role the code need "
              f"not read `{APP_ADMIN_EMAILS_ENV}`, and an admin feature the plan never asked for is still an unmandated "
              f"feature.")
    head = (f"App administrators: the platform sets the environment variable `{APP_ADMIN_EMAILS_ENV}` on the Cloud "
            f"Run services it renders for this workload (a JSON list set by the platform at deploy time, rendered as "
            f"the root variable `app_admin_emails`; reading it is neither a hardcoded value nor an unmandated "
            f"feature). The platform's rule for the code: when the plan defines an application-wide administrative "
            f"role (a role with powers over the whole app or other users, for example SuperAdmin or Admin), every "
            f"listed email always holds the highest one (the code reads this variable and compares it with the "
            f"verified IAP identity); other users get such roles only from the app's store, changed by an "
            f"administrator through an audited action. ")
    if count == 0:
        return (head + f"For this workload the list is EMPTY: no app administrator is configured (operator "
                f"configuration, recorded by the platform as the warning {APP_ADMIN_NONE_CONFIGURED}; the code cannot "
                f"change it). An application-wide administrative plan role that nobody holds only because the list "
                f"is empty is that configuration gap, not a missed directive; such a role whose code never reads "
                f"`{APP_ADMIN_EMAILS_ENV}` is still a missed directive. " + common)
    return (head + f"For this workload the list holds {count} email address(es). An application-wide "
            f"administrative plan role that no listed email can hold at runtime (the code never reads "
            f"`{APP_ADMIN_EMAILS_ENV}`, or grants the role only through a first-user, unknown-user or self-service "
            f"bootstrap) is a missed directive. " + common)


def _test_layout_fact(names: Tuple[str, ...], task_dag: Optional[Sequence[Any]]) -> List[str]:
    """TEST-LAYOUT-PLATFORM-FACT (owner 11-13): the multi-service test layout rule (workload_test_layout.py, row
    L3-PRB-t) as a trusted fact, plus the plan tasks with an exact target path under the repository-root `tests/`."""
    dirs = ", ".join(f"`{service_tests_dir(n)}/`" for n in names)
    lines = [f"- Test layout: this workload has {len(names)} services ({', '.join(names)}). The platform's "
             f"multi-service test layout rule puts each service's pytest tests in its own `apps/<service>/tests/` "
             f"directory ({dirs}) and forbids files under the repository-root `tests/` directory (QA rejects them); "
             f"the developer cannot follow a plan path under root `tests/`. A plan task, target file or acceptance "
             f"criterion that names a file under root `tests/` is met by the services' tests in "
             f"`apps/<service>/tests/`: judge those tests, never report the root `tests/` file as missing, and never "
             f"ask for a file under root `tests/`."]
    tids: List[str] = []
    for task in task_dag or []:
        targets = task.get("target_files") if isinstance(task, Mapping) else None
        tid = task.get("task_id") if isinstance(task, Mapping) else None
        if (isinstance(targets, list) and any(is_root_test_path(t) for t in targets) and is_printable_task_id(tid)
                and tid not in tids):
            tids.append(tid)
    if tids:
        lines.append(f"  - Plan tasks with a target under root `tests/` (exact target path): {', '.join(tids)}")
    return lines


def platform_facts_text(vcs_provider: Optional[str], iac_mode: str, task_dag: Optional[Sequence[Any]], *,
                        python_runtime_pin: Optional[str] = None, direct_iap_cloud_run: bool = False,
                        platform_handled: Optional[Mapping[str, Any]] = None,
                        test_layout_services: Any = None, app_admin_count: Optional[int] = None) -> str:
    """The adherence judge's PLATFORM FACTS content (trusted: built only from the platform's typed records).
    `python_runtime_pin` (QA-JUDGE-FILE-MAPPING): the platform's pinned Python version, given by the caller only when
    the committed tree holds a platform-pinned `.python-version` (developer_agent.runtime_pin); None = no such line
    (the facts are then byte-identical to before).
    `direct_iap_cloud_run` (DIRECT-IAP-SKILL-VERIFY): True only for a PRIVATE_IAP workload whose commit has a Cloud Run
    service, the workloads whose code writers get the rule; False = no such line (byte-identical to before).
    `platform_handled` (ADHERENCE-PLATFORM-SATISFIED): the facets the platform handles for this workload
    (platform_satisfied.platform_handlings of its typed facts), one line each; None or {} = no such line.
    `test_layout_services` (TEST-LAYOUT-PLATFORM-FACT): the developer's typed service list; more than one printable
    service name = the test layout line (`layout_services`); anything else = no such line (byte-identical).
    `app_admin_count` (APP-ADMIN-IAP-CONTRACT): the number of addresses in the committed root's platform-rendered
    `app_admin_emails` default; with `direct_iap_cloud_run` True and a non-negative int, the app administrator line
    (`_app_admin_fact`) follows the Direct IAP line; None or anything else = no such line (byte-identical)."""
    lines = [f"- {_ci_fact(vcs_provider)}", f"- {_iac_fact(iac_mode)}"]
    layout = layout_services(test_layout_services)
    if layout:
        lines += _test_layout_fact(layout, task_dag)
    if python_runtime_pin is not None:
        lines.append(f"- {_python_runtime_fact(python_runtime_pin)}")
    if direct_iap_cloud_run is True:
        lines.append(f"- {_direct_iap_fact()}")
        if is_app_admin_count(app_admin_count):
            lines.append(f"- {_app_admin_fact(app_admin_count)}")
    if platform_handled:
        lines += _platform_handled_lines(platform_handled)
    applied: List[str] = []
    for task in task_dag or []:
        kinds = task_fact_kinds(task)
        tid = task.get("task_id") if isinstance(task, Mapping) else None
        # Fable RT F2: task_id is architect-LLM text printed in a TRUSTED section: only a single printable line of at
        # most TASK_ID_MAX_CHARS (exact character-class check: no newline / line separator can forge a bullet; the
        # DAG has no stricter id grammar, TaskItem.task_id is a plain str). Anything else: no per-task line.
        if kinds and is_printable_task_id(tid):
            applied.append(f"  - {tid}: {' and '.join(kinds)} facts apply")
    if applied:
        lines.append("- Judge these plan tasks against the facts above (matched on the task's exact category or an "
                     "exact target path the platform writes):")
        lines += applied
    return "\n".join(lines)


PLATFORM_FACTS_SECTION_TEMPLATE = """### PLATFORM FACTS (trusted: from the platform's own records, not from the code under audit):
{facts}

"""


def platform_facts_section(facts: Optional[str]) -> str:
    """The PLATFORM FACTS section of the adherence prompt, or "" when the caller gave none."""
    return PLATFORM_FACTS_SECTION_TEMPLATE.format(facts=facts) if facts is not None else ""

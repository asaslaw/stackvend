#!/usr/bin/env python3
"""C4 apply-preparation checkpoint ($0, offline): what does the apply side's `prepare_workspace` do to a tree?

    python eval/tools/c4_apply_prep.py <results_dir> [--tofu-bin BIN] [--tofu-mirror DIR] [--provider-set production]
                                       [--product-root <worktree>] [--vcs-fetch verbatim|github] [--keep-workspaces]

Step 2 plan (docs/planning/wave2-step2-plan.md rev 2) §1.3 P-6, §2.1 S2-0, §3.6, §4 G0 "C4 (prepare_workspace -> V1b)";
FD-55 W0 (docs/planning/fd-55-healer-deletion-plan.md §4): the apply input is built with the PRODUCTION functions.

For every run under <results_dir>/runs/<key>/:
  1. Tree: checkpoints.C3_committed.tree when present (label `committed`), else the last tree_dumps.assemble[-1]
     .assembled tree (label `assembled_iter0`: a PROXY, because nothing was committed in that run).
  2. Apply input, built the way TerraformService._deploy_workload_impl builds it, calling the product's own
     module-level functions from <product_root>/mcp-servers/terraform/service.py (imported as the hermetic tests do):
     the TI-5a intent refusal (`iac_intent_state`, `manifest_has_service_topology`), the FD-4D root-config check
     (exact keys before the copy), the FD-4D-b infra/workload/ copy (every `infra/workload/<p>` also at
     `workload_relpath(<p>)`, subdirectories kept; a nested copy never replaces a path the manifest already has;
     `.tf` files through `rewrite_flattened_module_sources`, the FD-4BW parser-based module-source re-anchoring, with
     `nested_repo_path` for a nested file) and the FD-4BV root `terraform.tfvars` (`merge_tfvars_texts` over the
     workload's tfvars with the
     platform keys, MOCK values only; the two secrets go by TF_VAR_* in production and are absent here).
  3. `TerraformService(db=MagicMock(), state_bucket="").prepare_workspace(product_id, trace_id, files,
     iac_engine=None, region=<mock region>)` in a private workspace root under TMPDIR (no backend.tf, no
     _ensure_binary, no Firestore, no GCS, no GitHub). The workspace is read back and diffed against the apply input.
  4. V1b: `tofu init -backend=false` + `tofu validate -json` (eval TofuRunner: offline mirror, sandbox-exec, env
     allowlist) at the ROOT of (a) the apply input as given and (b) the prepared workspace, so a verdict change is
     attributable to prepare_workspace alone.

Product steps are cited by a code landmark (a comment or statement that occurs verbatim in the named product method),
not by line number: line numbers moved with every service.py change and went stale. tests/test_eval_c4_apply_prep.py
checks that every landmark still occurs in its method.

Writes <results_dir>/c4_apply_prep.json and .md and prints the markdown. Workspaces are removed afterwards.
Reads the results directory only; never edits a product file.
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import importlib.util
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Tuple

EVAL_DIR = Path(__file__).resolve().parent.parent
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from stackvend_eval.blobs import BlobStore  # noqa: E402

SCHEMA = 2   # 2 (FD-55 W0): production flatten + tfvars merge; uncovered-trigger keys without line numbers
WORKLOAD = "infra/workload/"
MOCK_PROJECT = "c4-mock-project"
MOCK_PROJECT_NUMBER = "000000000000"
MOCK_REPO_OWNER = "c4-mock-owner"
MOCK_REGION = "us-central1"
GITHUB_FETCH_SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".ico", ".tar.gz", ".zip", ".pyc")
SERVICE_LOGGER = "mcp-terraform-server"
STALE_MODULE_MARKER = "PLATFORM.VENDORED_MODULE_STALE"   # the report-only finding (FD55-W3 intent / W6d every workspace)
MAX_LOG_LINES = 120

DEPLOY = "_deploy_workload_impl"
PREPARE = "prepare_workspace"
# (product method, verbatim landmark in it, what C4 does with that step)
COVERED_STEPS: List[Tuple[str, str, str]] = [
    (DEPLOY, "# Fetch latest files from GitHub repository",
     "repo files = the tree (C3 committed, or the iter-0 assembled proxy); `--vcs-fetch github` also applies "
     "GitHubProvider.fetch_file_tree's filter (drops paths starting with `.git`, binary suffixes); default `verbatim`"),
    (DEPLOY, "intent_state = iac_intent_state(files)",
     "TI-5a intent refusal (unreadable intent / intent without topology.json), production `iac_intent_state` and "
     "`manifest_has_service_topology`"),
    (DEPLOY, "# FD-4D RT F1: the root config is one of these exact keys BEFORE the copy to the workspace root",
     "FD-4D no-root-config refusal (`main.tf`, `infra/workload/main.tf`, `infra/workloads/main.tf` before the copy)"),
    (DEPLOY, "rel = workload_relpath(path)",
     "FD-4D-b: infra/workload/<p> also copied to the production `workload_relpath(<p>)` (subdirectories kept, never "
     "the basename; a nested copy never replaces a path the manifest already has); `.tf` files through the production "
     "`rewrite_flattened_module_sources` (FD-4BW: parsed module blocks, any formatting; `nested_repo_path` for a "
     "nested file); modules stay at their paths"),
    (DEPLOY, "merged_root_tfvars = merge_tfvars_texts([files[k] for k in tfvars_keys], platform_tfvars)",
     "FD-4BV root terraform.tfvars: production `merge_tfvars_texts` over infra/workload/terraform.tfvars + "
     "terraform.tfvars with the platform keys (MOCK project / repo / image, empty OAuth client id as when Secret "
     "Manager is unreachable); FD-4BD secrets are TF_VAR_* in production, absent here"),
    (DEPLOY, "workspace_dir = self.prepare_workspace(",
     "prepare_workspace called with iac_engine=None (no _ensure_binary; the HCL-parser-gated healers see `--tofu-bin` "
     "on PATH, as production has the engine installed by then) and the mock region; MagicMock Firestore doc (mock "
     "project_id / number); state_bucket empty -> no backend.tf"),
    (PREPARE, "validate_manifest_keys(hcl_files, reserved=TF_WORKSPACE_RESERVED)", "prepare_workspace in full: "
     "manifest-key validation"),
    (PREPARE, "# FD55-W6b / W6d (register FD55-W6b+W6d): no committed .tf file is rewritten in this method",
     "no .tf rewriter left on any workspace (typed intent or legacy) and nothing recorded for a commit back "
     "(FD55-W6b / W6d; before: the TI-5a/b skips)"),
    (PREPARE, "continue  # Strictly suppress any Dockerfile", "Dockerfile drop"),
    (PREPARE, "validate_github_workflow_yaml(content, filename=filename)   # the committed text, judged as-is",
     "workflow validate on the committed text (FD55-W6a: no sanitize; FD55-W6c: deploy / plan turn a failure into "
     "the typed APPLY.WORKFLOW_INVALID, C4 reports the exception)"),
    (PREPARE, "self._add_static_mount_placeholders(workspace_dir)", "static mount placeholder `<dir>/.gitkeep` (AST "
     "literal `StaticFiles(directory=...)`, the gateway W5 rule; FD55-A8-CONVERT, before: substring `StaticFiles`)"),
    (PREPARE, "# 3. Ensure modules are resolvable from both workspace root and subdirectories", "modules symlinks"),
    (PREPARE, "# 4. FD55-W6d (HS-42): vendored golden modules are applied exactly as committed.",
     "stale vendored golden module: report only (`PLATFORM.VENDORED_MODULE_STALE` log lines counted as "
     "`stale_module_reports`; nothing written)"),
]
# Deleted from prepare_workspace since C4 was written (tombstones in the product; C4 has nothing to run):
DELETED_SINCE: List[Tuple[str, str, str]] = [
    (DEPLOY, "# 2a-1.5. RT14-01 (FD-4Q / lane 18 S3): the Pass 0.5 stub purge is DELETED",
     "Pass 0.5 stub purge and the subnet orphan purge (case B) (RT14-01: no REST delete outside the plan)"),
    (PREPARE, "FD-4AD: `.py` files are written as committed", "HB-42 python path sanitize"),
    (PREPARE, "FD-4AE-c (#16, deploy-workspace copy): DELETED", "root-asset vendoring into apps/<svc>/"),
    (PREPARE, "the semantic deduplication sweep is deleted", "HA-14 semantic dedup (FD-4AA)"),
    (PREPARE, "S2-F HB-13 (deleted)", "HB-13 foundation reference remap"),
    (PREPARE, "the `_ensure_default` healer that injected a guessed default", "HB-08 guessed variable defaults"),
    (PREPARE, "steps 6 'contract schema healing' and 3e 'SQLAlchemy synonym curing' were DELETED",
     "contract-schema and SQLAlchemy heals (FD-4AE)"),
    (PREPARE, "FD55-W6a DELETED (A3) the drop of root main.py / Procfile / requirements.txt",
     "legacy root-file drops, default interpolation strip, Cloud Run deletion_protection, google provider >= 6, "
     "workflow sanitize (FD55-W6a A3-A7)"),
    (PREPARE, "FD55-W6a DELETED the root-module rewriters",
     "root-module rewriters: undeclared-variable declaration, GCP naming invariants, output dedup, compute-collision "
     "reconcile (FD55-W6a A9-A12)"),
    (PREPARE, "FD55-W6a DELETED (A13, HB-16)", "compute-cloudrun module / root variables.tf text heals (FD55-W6a A13)"),
    (PREPARE, "# 4. FD55-W6a: the workspace-wide per-file .tf sanitize chain is DELETED",
     "workspace-wide per-file sanitize chain (HB-10 strip incl. custom.tf outputs and the newline trim, service_url, "
     "locals, firestore / data / source rewrites, provider / lifecycle / timeouts / WI injections, google-beta root "
     "heal; FD55-W6a A14-A26)"),
    (DEPLOY, "# FD55-W6a (A41 DELETED): the second naming-invariant pass over every root .tf is gone",
     "pre-apply GCP naming-invariant pass (FD55-W6a A41)"),
    (DEPLOY, "# FD-55-IMG (A38/A39 DELETED): no container_image / image literal is rewritten here",
     "main.tf / root .tf container_image rewrite by app-name substring (FD-55-IMG A38/A39)"),
    (DEPLOY, "# AQ-1 (register AQ-1): the install's Google sign-in client id and secret",
     "Secret Manager read of the install's OAuth client id/secret (AQ-1: never read)"),
    (DEPLOY, "# FD55-W3 (A54 DELETED): main.tf is never read or written here.",
     "OAuth / Firebase main.tf text injection (FD55-W3 A54)"),
    (PREPARE, "# FD55-W6b (register FD55-W6b+W6d) DELETED the apply-time \"Autonomous IaC Curing\"",
     "apply-time IaC curing: delimiter balancing, locals normalization / synthesis, parser-gated orphaned depends_on "
     "repair (FD55-W6b A27-A29)"),
    (PREPARE, "the A31 write-back dict `_last_healed_files` is deleted",
     "the write-back record (`healed_writeback` stays in the report: 0 on this product, the base product's count "
     "on an older root)"),
    (PREPARE, "The deleted A30 (HA-31 \"Canonical", "golden module payload refresh (FD55-W6d A30: report only)"),
    (DEPLOY, "# FD55-W6b (register FD55-W6b+W6d, A31 DELETED): the deploy never commits to the workload repository.",
     "GitOps write-back commit of healed files to the deploy branch (FD55-W6b A31)"),
    (DEPLOY, "# FD55-W6c (A42 DELETED, register FD55-W6c): the Layer 3 pre-apply variable reconciler is gone.",
     "Layer 3 pre-apply tfvars reconciler: name-guessed values for variables without a default (FD55-W6c A42)"),
    (DEPLOY, "# FD55-W6c (A44 / A45 / A46 DELETED, register FD55-W6c)",
     "legacy validate-error heals: locals curing, undeclared Cloud Run reference rewrite, custom.tf output purge "
     "(FD55-W6c A44-A46)"),
    (DEPLOY, "# FD55-W6c (A47 / A48 DELETED, register FD55-W6c)",
     "apply-error self-reference rewrite and locals curing (FD55-W6c A47 / A48)"),
    (DEPLOY, "# FD55-W6c (A49 DELETED, register FD55-W6c)",
     "regex bypass of the Identity Platform IdP block in main.tf after CONFIGURATION_NOT_FOUND (FD55-W6c A49)"),
    (DEPLOY, "# FD55-W6e (A33, HB-15 DELETED, register FD55-W6e)",
     "plural infra/workloads/ block merge into custom.tf / variables.tf by text pattern (FD55-W6e A33)"),
    (DEPLOY, "# FD55-W6e (A34 DELETED, register FD55-W6e)",
     "PORT env-block regex strip on every .tf (FD55-W6e A34; now a plan check in the gated apply)"),
    (DEPLOY, "# FD55-W6e (A35 DELETED, \"Guardrail 4\")",
     "GKE healers: module output, kubernetes provider wiring, subnet lifecycle, k8s timeouts, repository_id, "
     "workload identity (FD55-W6e A35)"),
    (DEPLOY, "# FD55-W6e (A43, Layer 3b DELETED, register FD55-W6e)",
     "Layer 3b multi-tier compute auto-wiring (FD55-W6e A43)"),
]
NOT_COVERED_STEPS: List[Tuple[str, str, str]] = [
    (DEPLOY, "# Guardrail 1: One-way state gate preventing tofu -> terraform downgrade",
     "Firestore metadata, engine resolution / downgrade gate, region resolution"),
    (DEPLOY, "# 0. FD-4H: read-only pre-flight state-lock check", "state-lock check"),
    (DEPLOY, "# Inspect plural infra/workloads/ directory or legacy infra/ paths",
     "plural infra/workloads/ copy when it is the only root config, else the typed APPLY.PLURAL_WORKLOADS_NOT_APPLIED "
     "stop (FD55-W6e: no merge; trigger reported)"),
    (DEPLOY, "# Resolve canonical Artifact Registry repository ID", "Artifact Registry repository id from the HCL"),
    (DEPLOY, "firebase_api_key, target_p_num = self._resolve_workload_web_key(target_project_id, clean_pid)",
     "Public-workload web key resolution by exact key id (network; mocked as empty strings)"),
    (DEPLOY, "self._register_workspace_tf_vars(workspace_dir, secret_tf_vars)", "secrets as TF_VAR_* of the workspace"),
    (DEPLOY, "self._report_iac_outdated(product_id, trace_id, stale_vendored_module_files(workspace_dir))",
     "IaC outdated flag on the workload record (Firestore; C4 counts the prepare_workspace findings instead)"),
    (DEPLOY, "# 1. Build and Push Container Image via Google Cloud Buildpacks", "Buildpacks container build"),
    (DEPLOY, "# Non-destructive terraform.tfvars merge preserving",
     "runtime terraform.tfvars merge (deployed container_image)"),
    (DEPLOY, "# Ensure variables.tf declares firebase_api_key and firebase_auth_domain", "firebase variables.tf additions"),
    (DEPLOY, "# Ensure Identity Platform is initialized for target child project",
     "Identity Platform init, API auto-enablement (network)"),
    (DEPLOY, "# 2. Terraform Init with exponential backoff",
     "`init -upgrade` with the real GCS backend (C4 uses init -backend=false)"),
    (DEPLOY, "# 2a. Shift-Left IaC Validation Pre-Check",
     "shift-left validate: the intent typed report and the legacy untyped VALIDATION_FAILED (no validate-error heal "
     "since FD55-W6c; C4 reports the first validate only)"),
    (DEPLOY, "# 2b. Terraform Apply",
     "plan / apply, Pass 0 adoption of existing planned creates, and the cloud-side apply-error reactions (409 "
     "adoption at the plan's address since FD-4CY W7, Cloud Run creation "
     "timeout retry, startup-probe revision re-check, initializeAuth + one "
     "retry; no file rewrite since FD55-W6c; no REST delete since RT14-01: a CIDR conflict is SUBNET_CIDR_CONFLICT)"),
]


def _step_text(steps: List[Tuple[str, str, str]]) -> List[str]:
    return [f"{text} [{meth}: `{mark}`]" for meth, mark, text in steps]


COVERED = _step_text(COVERED_STEPS) + [
    "V1b: tofu init -backend=false + validate -json at the workspace root, before vs after prepare_workspace"]
NOT_COVERED = _step_text(NOT_COVERED_STEPS) + [
    f"(deleted from the product, nothing to run) {t} [{m}: `{k}`]" for m, k, t in DELETED_SINCE]


# ------------------------------------------------------------------------------------------------ run input
def _norm(p: str) -> str:
    return str(PurePosixPath(p.replace(os.sep, "/")))


def load_run_tree(run_dir: Path) -> Dict[str, Any]:
    """{'label': committed|assembled_iter0|no_tree, 'tree_hash', 'tree', 'product_id', 'pipeline_outcome'}."""
    run_dir = Path(run_dir)
    res = json.loads((run_dir / "result.json").read_text())
    out: Dict[str, Any] = {"label": "no_tree", "tree_hash": None, "tree": None, "product_id": res.get("product_id"),
                           "pipeline_outcome": res.get("pipeline_outcome")}
    store = BlobStore(run_dir)
    c3 = (res.get("checkpoints") or {}).get("C3_committed") or {}
    th = c3.get("tree") if isinstance(c3, dict) else None
    if th:
        out.update(label="committed", tree_hash=th, tree=store.get_tree(th))
        return out
    dumps = ((res.get("tree_dumps") or {}).get("assemble") or [])
    for d in reversed(dumps):
        th = d.get("assembled") if isinstance(d, dict) else None
        if th:
            out.update(label="assembled_iter0", tree_hash=th, tree=store.get_tree(th),
                       iteration=(d.get("assembly_record") or {}).get("iteration"))
            return out
    return out


def github_fetch_filter(tree: Dict[str, str]) -> Dict[str, str]:
    """GitHubProvider.fetch_file_tree: blobs whose path does not start with `.git` and does not end with a binary
    suffix."""
    return {p: t for p, t in tree.items()
            if not p.startswith(".git") and not p.endswith(GITHUB_FETCH_SKIP_SUFFIXES)}


def mock_platform_tfvars(product_id: str) -> Dict[str, str]:
    """deploy_workload's FD-4BV `platform_tfvars` keys ({name: HCL value text}) with MOCK values only (never a real
    project, repo, OAuth client or API key). The FD-4BD secrets are not tfvars keys in production."""
    clean_pid = product_id.lower().replace("_", "-")
    return {"project_id": f'"{MOCK_PROJECT}"', "region": f'"{MOCK_REGION}"', "product_id": f'"{clean_pid}"',
            "github_repo_full_name": f'"{MOCK_REPO_OWNER}/{clean_pid}"',
            "container_image": f'"{MOCK_REGION}-docker.pkg.dev/{MOCK_PROJECT}/{clean_pid}/app:latest"',
            "oauth_client_id": '""', "firebase_auth_domain": f'"{MOCK_PROJECT}.firebaseapp.com"'}


def build_apply_input(tree: Dict[str, str], product_id: str, svc_mod, vcs_fetch: str = "verbatim") -> Dict[str, Any]:
    """The `files` dict deploy_workload hands to prepare_workspace, restricted to the covered steps, built with the
    product's own functions from `svc_mod` (load_service): iac_intent_state / manifest_has_service_topology,
    workload_relpath, rewrite_flattened_module_sources and merge_tfvars_texts. The loop order and overwrite
    semantics are _deploy_workload_impl's (FD-4D-b: a direct child replaces a same-named root file, a nested copy
    never replaces an existing path).

    Returns {'files', 'root_copies': [workspace paths written from infra/workload/], 'nested_not_copied': [repo paths
    whose nested copy production skips], 'refused': reason|None, 'fetch_dropped': [paths], 'intent_ws': bool}."""
    repo = github_fetch_filter(tree) if vcs_fetch == "github" else dict(tree)
    dropped = sorted(set(tree) - set(repo))
    files = dict(repo)
    refused = None
    intent_state = svc_mod.iac_intent_state(files)                       # TI-5a
    intent_ws = intent_state == "intent"
    if intent_state == "unreadable" or (intent_ws and not svc_mod.manifest_has_service_topology(files)):
        refused = (svc_mod.APPLY_INTENT_UNREADABLE if intent_state == "unreadable"
                   else svc_mod.APPLY_INTENT_WITHOUT_TOPOLOGY)
    root_main_present = any(k in files for k in ("main.tf", "infra/workload/main.tf", "infra/workloads/main.tf"))
    root_copies: List[str] = []
    not_copied: List[str] = []
    for path, content in list(files.items()):                            # the FD-4D-b infra/workload/ copy
        rel = svc_mod.workload_relpath(path)
        if rel is None:
            continue
        nested = "/" in rel
        if path.endswith(".tf"):
            content = svc_mod.rewrite_flattened_module_sources(content, filename=path,
                                                               nested_repo_path=path if nested else "")
        if nested and rel in files:
            not_copied.append(path)
            continue
        files[rel] = content
        root_copies.append(rel)
    if refused is None and not root_main_present:                        # FD-4D
        refused = "no root config (main.tf / infra/workload/main.tf / infra/workloads/main.tf): deploy refuses"
    platform = mock_platform_tfvars(product_id)                          # FD-4BV
    layers = [files[k] for k in ("infra/workload/terraform.tfvars", "terraform.tfvars") if k in files]
    merged = svc_mod.merge_tfvars_texts(layers, platform)
    if merged is None:
        merged = "".join(f"{k} = {v}\n" for k, v in platform.items())
    files["terraform.tfvars"] = merged
    return {"files": files, "root_copies": sorted(set(root_copies)), "nested_not_copied": sorted(not_copied),
            "refused": refused, "fetch_dropped": dropped, "intent_ws": intent_ws}


def uncovered_triggers(files: Dict[str, str], svc_mod=None, intent_ws: bool = False) -> Dict[str, Any]:
    """Whether the deploy_workload step C4 does NOT run (the plural infra/workloads/ copy or stop) would act on this
    input: the step's own guard (exact path prefix; an intent workspace never reads the directory), used only to label
    the gap. FD55-W6e deleted the PORT strip and GKE Guardrail 4 this used to label too. `svc_mod` is accepted for
    older callers and not read."""
    plural = sorted(p for p in files if p.startswith("infra/workloads/") and p.endswith(".tf") and not intent_ws)
    return {"plural_workloads": plural}


# ------------------------------------------------------------------------------------------------ workspace
def read_workspace(ws: Path) -> Dict[str, Any]:
    """{'files': {relpath: text}, 'symlinks': {relpath: target}, 'binary': [relpath]} (symlinks are not followed)."""
    ws = Path(ws)
    files: Dict[str, str] = {}
    links: Dict[str, str] = {}
    binary: List[str] = []
    for root, dirs, fnames in os.walk(ws):
        for d in list(dirs):
            full = Path(root) / d
            if full.is_symlink():
                links[_norm(os.path.relpath(full, ws))] = os.readlink(full)
                dirs.remove(d)
        for f in fnames:
            full = Path(root) / f
            rel = _norm(os.path.relpath(full, ws))
            if full.is_symlink():
                links[rel] = os.readlink(full)
                continue
            try:
                files[rel] = full.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                binary.append(rel)
    return {"files": files, "symlinks": links, "binary": sorted(binary)}


def diff_trees(before: Dict[str, str], after: Dict[str, str]) -> Dict[str, List[str]]:
    b = {_norm(k): v for k, v in before.items()}
    a = {_norm(k): v for k, v in after.items()}
    return {"added": sorted(set(a) - set(b)), "removed": sorted(set(b) - set(a)),
            "changed": sorted(k for k in set(a) & set(b) if a[k] != b[k])}


def whitespace_only(before: Dict[str, str], after: Dict[str, str], paths: List[str]) -> List[str]:
    """Changed paths whose before/after differ only in whitespace (e.g. a dropped trailing newline)."""
    return sorted(p for p in paths if p in before and p in after
                  and "".join(before[p].split()) == "".join(after[p].split()))


def module_paths(paths: List[str], is_golden: Optional[Callable[[str], bool]] = None) -> Dict[str, List[str]]:
    """Split changed paths into golden-module files (the product's exact is_golden_module_file) and any file under
    infra/modules/ or modules/."""
    golden = sorted(p for p in paths if is_golden and is_golden(p))
    anymod = sorted(p for p in paths if p.startswith(("infra/modules/", "modules/")))
    return {"golden": golden, "infra_modules": anymod}


# ------------------------------------------------------------------------------------------------ product
def load_service(product_root: Path):
    """Import <product_root>/mcp-servers/terraform/service.py (as the hermetic tests do) with its own shared/ first."""
    tf_dir = str(Path(product_root).resolve() / "mcp-servers" / "terraform")
    if tf_dir not in sys.path:
        sys.path.insert(0, tf_dir)
    spec = importlib.util.spec_from_file_location("stackvend_tf_service_c4", os.path.join(tf_dir, "service.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    require_product_api(mod, product_root)
    return mod


# The production functions build_apply_input / run_prepare call (FD-55 W0). Their introducing rows, for the error.
REQUIRED_PRODUCT_API = {
    "iac_intent_state": "TI-5a", "manifest_has_service_topology": "TI-5a", "APPLY_INTENT_UNREADABLE": "TI-5a",
    "APPLY_INTENT_WITHOUT_TOPOLOGY": "TI-5a", "workload_relpath": "FD-4D-b",
    "rewrite_flattened_module_sources": "FD-4BW (nested_repo_path: FD-4D-b)", "merge_tfvars_texts": "FD-4BV",
}


class ProductApiError(SystemExit):
    """--product-root predates a production function C4 imports (C4 never falls back to a copy of it)."""


def require_product_api(mod, product_root: Path) -> None:
    import inspect
    missing = [f"{n} ({row})" for n, row in REQUIRED_PRODUCT_API.items() if not hasattr(mod, n)]
    fn = getattr(mod, "rewrite_flattened_module_sources", None)
    if fn is not None and "nested_repo_path" not in inspect.signature(fn).parameters:
        missing.append("rewrite_flattened_module_sources(nested_repo_path=...) (FD-4D-b)")
    if missing:
        raise ProductApiError(f"--product-root {product_root} predates the production deploy functions C4 calls: "
                              f"missing {', '.join(missing)}. Use a product root at or after FD-4D-b, or the C4 tool "
                              "from that product's own commit.")


def mock_db():
    from unittest.mock import MagicMock
    db = MagicMock()
    doc = db.collection.return_value.document.return_value.get.return_value
    doc.exists = True
    doc.to_dict.return_value = {"project_id": MOCK_PROJECT, "project_number": MOCK_PROJECT_NUMBER}
    return db


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.INFO)
        self.lines: List[str] = []
        self.stale_module_reports = 0   # counted beyond the MAX_LOG_LINES cap

    def emit(self, record):
        try:
            if STALE_MODULE_MARKER in record.getMessage():
                self.stale_module_reports += 1
        except Exception:  # noqa: BLE001
            pass
        if len(self.lines) < MAX_LOG_LINES:
            try:
                self.lines.append(f"{record.levelname}: {record.getMessage()}"[:300])
            except Exception:  # noqa: BLE001
                pass


@contextlib.contextmanager
def _quiet_capture():
    """Capture the service's log lines (which heal acted) without printing them."""
    root = logging.getLogger()
    cap = _Capture()
    saved = [(h, h.level) for h in root.handlers]
    old_level = root.level
    for h, _ in saved:
        h.setLevel(logging.CRITICAL + 1)
    root.addHandler(cap)
    root.setLevel(logging.INFO)
    try:
        yield cap
    finally:
        root.removeHandler(cap)
        root.setLevel(old_level)
        for h, lvl in saved:
            h.setLevel(lvl)


@contextlib.contextmanager
def _path_with(bin_dir: Optional[str]):
    old = os.environ.get("PATH", "")
    if bin_dir:
        os.environ["PATH"] = bin_dir + os.pathsep + old
    try:
        yield
    finally:
        os.environ["PATH"] = old


def run_prepare(svc_mod, work_base: Path, product_id: str, trace_id: str, files: Dict[str, str],
                parser_dir: Optional[str] = None, region: str = MOCK_REGION) -> Dict[str, Any]:
    """Hermetic prepare_workspace call + read-back. Returns {'status', 'workspace', 'readback', 'healed_writeback',
    'log', 'error', 'backend_tf'}."""
    os.environ.pop("TFSTATE_BUCKET", None)
    svc = svc_mod.TerraformService(project_id="mock-stackvend-project", state_bucket="", db=mock_db(),
                                   workspace_base_dir=str(work_base))
    svc.state_bucket = ""   # never a GCS backend
    out: Dict[str, Any] = {"status": None, "workspace": None, "error": None}
    with _quiet_capture() as cap, _path_with(parser_dir):
        hcl_parser = None
        try:
            # the product's hcl_utils module, by its parser helper (any import path; FD-55 W6b deleted the healer
            # this used to be found through)
            hu = next((m for n, m in list(sys.modules.items())
                       if n.split(".")[-1] == "hcl_utils" and hasattr(m, "find_hcl_parser_binary")), None)
            hcl_parser = hu.find_hcl_parser_binary() if hu else None
        except Exception:  # noqa: BLE001
            pass
        try:
            ws = svc.prepare_workspace(product_id, trace_id, dict(files), iac_engine=None, region=region)
            out.update(status="prepared", workspace=ws)
        except Exception as e:  # noqa: BLE001 - a raise here is what the apply step would hit
            out.update(status="prepare_failed", error=f"{type(e).__name__}: {str(e)[:500]}")
    out["log"] = cap.lines
    out["hcl_parser"] = hcl_parser
    # FD-55 W6b deleted the write-back record: 0 on this product; an older product root still reports its paths
    out["healed_writeback"] = sorted((getattr(svc, "_last_healed_files", {}) or {}).get(product_id, {}) or {})
    out["stale_module_reports"] = cap.stale_module_reports
    if out["workspace"]:
        out["readback"] = read_workspace(Path(out["workspace"]))
        out["backend_tf"] = "backend.tf" in out["readback"]["files"] and "backend.tf" not in files
    return out


# ------------------------------------------------------------------------------------------------ tofu (V1b)
class V1b:
    """init -backend=false + validate -json at a directory root, via the eval TofuRunner (offline, sandboxed)."""

    def __init__(self, work_root: Path, tofu_bin: Optional[str], mirror: Optional[Path]):
        from stackvend_eval.tofu_runner import TofuRunner
        self.runner = TofuRunner(Path(work_root), Path(mirror) if mirror else None, tofu_bin=tofu_bin)

    @property
    def available(self) -> bool:
        return self.runner.available

    def version(self) -> Optional[str]:
        try:
            r = self.runner._run(["version", "-json"])
            return json.loads(r.stdout or "{}").get("terraform_version")
        except Exception:  # noqa: BLE001
            return None

    def validate_dir(self, wd: Path, tree: Dict[str, str]) -> Dict[str, Any]:
        from stackvend_eval import hclparse
        from stackvend_eval.tofu_runner import normalize_diag
        if not self.available:
            return {"status": "tofu_unavailable"}
        root_tf = [p for p in tree if p.endswith(".tf") and "/" not in p]
        if not root_tf:
            return {"status": "no_root_tf"}
        try:
            parsed, bad = hclparse.parse_tree(tree)
        except hclparse.HclUnavailable:
            return {"status": "skipped_no_hcl_parser"}
        remote = [(p, m, s) for p, m, s in hclparse.module_sources(parsed) if not hclparse.is_local_source(s)]
        if remote:   # H6: never let init fetch a remote module
            return {"status": "remote_module_source",
                    "remote_sources": [{"file": p, "module": m, "source": s} for p, m, s in remote]}
        out: Dict[str, Any] = {"structure_unavailable_files": sorted(bad)}
        r = self.runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
        out["init_ok"] = r.returncode == 0
        if r.returncode != 0:
            out["status"] = "init_failed" if self.runner.mirror_ready else "init_failed_offline_mirror"
            out["init_error"] = (r.stderr or r.stdout or "")[-1200:]
            return out
        r = self.runner._run(["validate", "-json", "-no-color"], cwd=wd)
        try:
            vj = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            vj = {"valid": False, "diagnostics": [{"severity": "error", "summary": "unparseable validate output",
                                                   "detail": ((r.stdout or "") + (r.stderr or ""))[-500:]}]}
        out["status"] = "validated"
        out["valid"] = bool(vj.get("valid"))
        out["diagnostics"] = [normalize_diag(d) for d in vj.get("diagnostics", [])][:200]
        return out


def write_before(files: Dict[str, str], base: Path, trace_id: str, product_id: str, layout: bool) -> Path:
    """The apply input written at <base>/<trace_id>/<product_id> (the workspace's own depth). layout=True also
    creates the two module links prepare_workspace makes (step 3: <ws>/modules -> infra/modules and
    <trace>/modules -> <ws>/infra/modules), which is directory layout, not file content: comparing after with this
    variant isolates prepare_workspace's content edits from its symlinks."""
    from stackvend_eval.tofu_runner import TofuRunner
    trace_dir = Path(base) / trace_id
    if trace_dir.exists():
        shutil.rmtree(trace_dir)
    wd = trace_dir / product_id
    wd.mkdir(parents=True)
    TofuRunner.write_tree(files, wd)
    infra_modules = wd / "infra" / "modules"
    if layout and infra_modules.is_dir():
        if not os.path.lexists(wd / "modules"):
            os.symlink("infra/modules", wd / "modules")
        if not os.path.lexists(trace_dir / "modules"):
            os.symlink(str(infra_modules), trace_dir / "modules")
    return wd


def verdict(v: Optional[Dict[str, Any]]) -> str:
    if not v:
        return "-"
    if v.get("status") == "validated":
        n = sum(1 for d in v.get("diagnostics", []) if d.get("severity") == "error")
        return "pass" if v.get("valid") else f"FAIL({n})"
    return v.get("status") or "-"


def _summary_key(summary: Any) -> str:
    """tofu prints a dependency cycle's members in a nondeterministic order: compare them as a sorted set."""
    s = str(summary)
    if s.startswith("Cycle: "):
        return "Cycle: " + ", ".join(sorted(x.strip() for x in s[len("Cycle: "):].split(", ")))
    return s


def _dkey(d: Dict[str, Any]) -> Tuple[str, str, str]:
    return (str(d.get("severity")), _summary_key(d.get("summary")), str(d.get("file")))


def compare_diags(before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Multiset difference of (severity, summary, file) between the two validate results."""
    bc = collections.Counter(_dkey(d) for d in (before or {}).get("diagnostics", []) or [])
    ac = collections.Counter(_dkey(d) for d in (after or {}).get("diagnostics", []) or [])
    new = [{"severity": k[0], "summary": k[1], "file": k[2], "count": n} for k, n in sorted((ac - bc).items())]
    gone = [{"severity": k[0], "summary": k[1], "file": k[2], "count": n} for k, n in sorted((bc - ac).items())]
    return {"new": new, "resolved": gone}


# ------------------------------------------------------------------------------------------------ one run
def _trace_id(key: str) -> str:
    import re
    t = re.sub(r"[^A-Za-z0-9._-]", "-", f"c4-{key}")
    return t if t[0].isalnum() else "c" + t


def analyze_run(run_dir: Path, svc_mod, work_base: Path, v1b: Optional[V1b], vcs_fetch: str = "verbatim",
                parser_dir: Optional[str] = None) -> Dict[str, Any]:
    run_dir = Path(run_dir)
    key = run_dir.name
    src = load_run_tree(run_dir)
    row: Dict[str, Any] = {"run": key, "label": src["label"], "tree_hash": src["tree_hash"],
                           "product_id": src["product_id"], "pipeline_outcome": src["pipeline_outcome"]}
    if src["tree"] is None:
        row["status"] = "no_tree"
        return row
    product_id = src["product_id"] or "workload"
    ai = build_apply_input(src["tree"], product_id, svc_mod, vcs_fetch)
    files = ai["files"]
    row.update(tree_files=len(src["tree"]), input_files=len(files), root_copies=ai["root_copies"],
               nested_not_copied=ai["nested_not_copied"],
               fetch_dropped=ai["fetch_dropped"], deploy_refused=ai["refused"], intent_ws=ai["intent_ws"],
               uncovered_triggers=uncovered_triggers(files, svc_mod, ai["intent_ws"]))
    trace_id = _trace_id(key)
    prep = run_prepare(svc_mod, work_base, product_id, trace_id, files, parser_dir=parser_dir)
    row.update(prepare_status=prep["status"], prepare_error=prep["error"], hcl_parser=prep.get("hcl_parser"),
               healed_writeback=prep["healed_writeback"], stale_module_reports=prep.get("stale_module_reports", 0),
               log=prep["log"])
    is_golden = getattr(svc_mod, "is_golden_module_file", None)
    try:
        if v1b is not None:
            for name, layout in (("validate_before", False), ("validate_before_layout", True)):
                wd = write_before(files, work_base / "_before" / name, trace_id, product_id, layout)
                if layout and not (wd / "modules").is_symlink():
                    row[name] = dict(row["validate_before"], same_as="validate_before")  # no infra/modules: no links
                    continue
                row[name] = v1b.validate_dir(wd, files)
        if prep["status"] == "prepared":
            rb = prep["readback"]
            d = diff_trees(files, rb["files"])
            parent_link = Path(prep["workspace"]).parent / "modules"
            if parent_link.is_symlink():
                rb["symlinks"]["../modules"] = os.readlink(parent_link).replace(str(Path(prep["workspace"])), "<ws>")
            row.update(added=d["added"], removed=d["removed"], changed=d["changed"], symlinks=rb["symlinks"],
                       binary=rb["binary"], backend_tf_written=bool(prep.get("backend_tf")))
            touched = d["added"] + d["removed"] + d["changed"]
            mp = module_paths(touched, is_golden)
            ws_only = whitespace_only(files, rb["files"], d["changed"])
            row.update(golden_changed=mp["golden"], infra_modules_changed=mp["infra_modules"],
                       changed_whitespace_only=ws_only,
                       module_changes_whitespace_only=[p for p in ws_only if p in mp["infra_modules"]])
            if v1b is not None:
                row["validate_after"] = v1b.validate_dir(Path(prep["workspace"]), rb["files"])
                row["diag_delta"] = compare_diags(row.get("validate_before_layout"), row["validate_after"])
        row["status"] = "ok" if prep["status"] == "prepared" else prep["status"]
    finally:
        trace_dir = work_base / trace_id
        if trace_dir.exists():
            shutil.rmtree(trace_dir, ignore_errors=True)
        for name in ("validate_before", "validate_before_layout"):
            before_root = work_base / "_before" / name / trace_id
            if before_root.exists():
                shutil.rmtree(before_root, ignore_errors=True)
    return row


# ------------------------------------------------------------------------------------------------ report
def build_report(rows: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    agg = collections.Counter()
    for r in rows:
        agg["runs"] += 1
        agg[f"label_{r.get('label')}"] += 1
        if r.get("status") != "ok":
            agg[f"status_{r.get('status')}"] += 1
            continue
        if r.get("added") or r.get("removed") or r.get("changed"):
            agg["prepare_changed_files"] += 1
            if not (r.get("added") or r.get("removed")) and \
                    set(r.get("changed") or []) <= set(r.get("changed_whitespace_only") or []):
                agg["prepare_changed_whitespace_only"] += 1
        if r.get("golden_changed"):
            agg["golden_mutated"] += 1
            if set(r["golden_changed"]) <= set(r.get("module_changes_whitespace_only") or []):
                agg["golden_mutated_whitespace_only"] += 1
        if r.get("infra_modules_changed"):
            agg["infra_modules_touched"] += 1
        if r.get("healed_writeback"):
            agg["write_back_runs"] += 1
            agg["write_back_files"] += len(r["healed_writeback"])
        if r.get("stale_module_reports"):
            agg["stale_module_report_runs"] += 1
            agg["stale_module_reports"] += r["stale_module_reports"]
        vb, vl, va = (verdict(r.get(k)).split("(")[0]
                      for k in ("validate_before", "validate_before_layout", "validate_after"))
        agg[f"v1b_raw_{vb}->{va}"] += 1
        agg[f"v1b_links_{vl}->{va}"] += 1
        if (r.get("diag_delta") or {}).get("new"):
            agg["new_diagnostics"] += 1
    return {"schema": SCHEMA, "checkpoint": "C4", "meta": meta, "covered": COVERED, "not_covered": NOT_COVERED,
            "aggregate": dict(sorted(agg.items())), "runs": rows}


def _short(paths: List[str], n: int = 6) -> str:
    if not paths:
        return ""
    s = ", ".join(f"`{p}`" for p in paths[:n])
    return s + (f" (+{len(paths) - n})" if len(paths) > n else "")


def render_markdown(rep: Dict[str, Any]) -> str:
    m = rep.get("meta", {})
    L = ["# C4 apply-preparation checkpoint (prepare_workspace -> V1b)", "",
         f"Results: `{m.get('results_dir')}` | product root: `{m.get('product_root')}` | tofu "
         f"{m.get('tofu_version')} (`{m.get('tofu_bin')}`) | provider set `{m.get('provider_set')}` "
         f"(mirror {m.get('mirror_status')}) | VCS fetch model `{m.get('vcs_fetch')}` | $0, offline.", "",
         "Tree per run: `committed` = checkpoints.C3_committed; `assembled_iter0` = the last assembled tree the "
         "validators saw, a **proxy** used because that run committed nothing. V1b = `tofu init -backend=false` + "
         "`validate -json` at the root of the apply input as built (before), of the same input plus only the two "
         "`modules` symlinks prepare_workspace creates (before+links: layout only, no content edit), and of the "
         "prepared workspace (after). before -> after is attributable to prepare_workspace; before+links -> after "
         "to its file-content edits alone.", "",
         "## Apply-side steps C4 covers", ""]
    L += [f"- {c}" for c in rep.get("covered", [])]
    L += ["", "## Apply-side steps C4 does NOT cover", ""]
    L += [f"- {c}" for c in rep.get("not_covered", [])]
    L += ["", "## Aggregate", "", "| metric | n |", "| :--- | ---: |"]
    L += [f"| {k} | {v} |" for k, v in rep.get("aggregate", {}).items()]
    L += ["", "## Per run", "",
          "| run | label | prepare | files +added/-removed/~changed | golden mutated | writeback | V1b before / "
          "before+links -> after | new diagnostics (vs before+links) | resolved diagnostics | uncovered steps that would act |",
          "| :--- | :--- | :--- | :--- | ---: | ---: | :--- | :--- | :--- | :--- |"]
    for r in rep.get("runs", []):
        if r.get("status") in ("no_tree", "tool_error"):
            L.append(f"| {r['run']} | {r.get('label') or r.get('status')} | {r.get('error') or '-'} | - | - | - | - "
                     "| - | - | - |")
            continue
        d = r.get("diag_delta") or {}
        new = "; ".join(f"{x['severity']}: {x['summary']} ({x['file']})" + (f" x{x['count']}" if x["count"] > 1 else "")
                        for x in (d.get("new") or [])[:4])
        if len(d.get("new") or []) > 4:
            new += f" (+{len(d['new']) - 4})"
        rc = collections.Counter()
        for x in d.get("resolved") or []:
            rc[f"{x['summary'][:60]} ({x['file']})"] += x["count"]
        resolved = "; ".join(f"{k} x{n}" for k, n in sorted(rc.items()))
        ut = r.get("uncovered_triggers") or {}
        trig = "plural" if ut.get("plural_workloads") else ""
        prep = r.get("prepare_status") or "-"
        if r.get("deploy_refused"):
            prep += " (deploy refuses)"
        L.append(f"| {r['run']} | {r['label']} | {prep} | +{len(r.get('added') or [])}/-{len(r.get('removed') or [])}"
                 f"/~{len(r.get('changed') or [])} (ws-only {len(r.get('changed_whitespace_only') or [])}) | "
                 f"{len(r.get('golden_changed') or [])} | "
                 f"{len(r.get('healed_writeback') or [])} | {verdict(r.get('validate_before'))} / "
                 f"{verdict(r.get('validate_before_layout'))} -> {verdict(r.get('validate_after'))} | {new} | {resolved} | {trig} |")
    L += ["", "## Paths changed by prepare_workspace", ""]
    for r in rep.get("runs", []):
        if r.get("status") in ("no_tree", "tool_error"):
            continue
        parts = []
        wso = set(r.get("changed_whitespace_only") or [])
        for k, sign in (("added", "+"), ("removed", "-")):
            if r.get(k):
                parts.append(f"{sign} {_short(r[k])}")
        content = [p for p in (r.get("changed") or []) if p not in wso]
        if content:
            parts.append(f"~ {_short(content, 10)}")
        if wso:
            parts.append(f"~ws-only {_short(sorted(wso), 4)}")
        if r.get("symlinks"):
            parts.append("symlinks " + ", ".join(f"`{k}`->`{v}`" for k, v in sorted(r["symlinks"].items())))
        if r.get("golden_changed"):
            wso = set(r.get("module_changes_whitespace_only") or [])
            parts.append("**golden mutated** " + ", ".join(
                f"`{g}`" + (" (whitespace only)" if g in wso else "") for g in r["golden_changed"]))
        if r.get("prepare_error"):
            parts.append(f"error `{r['prepare_error'][:200]}`")
        L.append(f"- **{r['run']}**: " + ("; ".join(parts) if parts else "no changes"))
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------------------------------------ main
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("results_dir")
    ap.add_argument("--tofu-bin", default=None)
    ap.add_argument("--tofu-mirror", default=None)
    ap.add_argument("--provider-set", default="production")
    ap.add_argument("--product-root", default=str(EVAL_DIR.parent))
    ap.add_argument("--vcs-fetch", choices=("verbatim", "github"), default="verbatim")
    ap.add_argument("--runs", nargs="*", default=None, help="only these run keys")
    ap.add_argument("--no-validate", action="store_true", help="skip V1b (no tofu)")
    ap.add_argument("--keep-workspaces", action="store_true")
    a = ap.parse_args(argv)

    results = Path(a.results_dir).resolve()
    run_dirs = sorted(p for p in (results / "runs").iterdir() if (p / "result.json").is_file())
    if a.runs:
        run_dirs = [p for p in run_dirs if p.name in set(a.runs)]
    meta: Dict[str, Any] = {"results_dir": str(results), "product_root": str(Path(a.product_root).resolve()),
                            "provider_set": a.provider_set, "tofu_bin": a.tofu_bin, "tofu_mirror": a.tofu_mirror,
                            "vcs_fetch": a.vcs_fetch}
    work_base = Path(tempfile.mkdtemp(prefix="c4-apply-prep-"))
    try:
        v1b = None
        if not a.no_validate:
            if not a.tofu_mirror:
                raise SystemExit("--tofu-mirror is required for V1b (or pass --no-validate)")
            from stackvend_eval.provider_sets import ProviderSetError, check_mirror_matches_set, get_set
            try:
                meta["providers"] = check_mirror_matches_set(Path(a.tofu_mirror), a.provider_set)
            except ProviderSetError as e:
                raise SystemExit(f"--provider-set {a.provider_set}: {e}")
            v1b = V1b(work_base / "_tofu", a.tofu_bin, Path(a.tofu_mirror))
            if not v1b.available:
                raise SystemExit("no usable tofu binary (--tofu-bin)")
            meta["tofu_version"] = v1b.version()
            meta["mirror_status"] = v1b.runner.mirror_manifest.get("status")
            want = get_set(a.provider_set).get("engine_version")
            if meta["tofu_version"] != want:
                raise SystemExit(f"tofu {meta['tofu_version']} != provider set {a.provider_set!r} engine {want}")
            if meta["mirror_status"] != "verified":
                raise SystemExit(f"mirror manifest {meta['mirror_status']}: refusing (fail closed)")
        svc_mod = load_service(Path(a.product_root))
        meta["service_py"] = getattr(svc_mod, "__file__", None)
        meta["shared_pkg"] = getattr(sys.modules.get("shared"), "__file__", None)
        parser_dir = str(Path(a.tofu_bin).resolve().parent) if a.tofu_bin else None
        rows = []
        for rd in run_dirs:
            try:
                rows.append(analyze_run(rd, svc_mod, work_base, v1b, a.vcs_fetch, parser_dir))
            except Exception as e:  # noqa: BLE001 - one bad run never hides the others
                rows.append({"run": rd.name, "status": "tool_error", "error": f"{type(e).__name__}: {str(e)[:400]}"})
        meta["hcl_parser_seen_by_prepare"] = sorted({r.get("hcl_parser") or "none" for r in rows if "hcl_parser" in r})
        rep = build_report(rows, meta)
        (results / "c4_apply_prep.json").write_text(json.dumps(rep, indent=1, sort_keys=True))
        md = render_markdown(rep)
        (results / "c4_apply_prep.md").write_text(md)
        sys.stdout.write(md)
        return 0
    finally:
        if not a.keep_workspaces:
            shutil.rmtree(work_base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

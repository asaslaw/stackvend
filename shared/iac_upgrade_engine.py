"""
Project Castor: Workload IaC Module & Bundle Upgrade Engine
Pure deterministic, Zero-LLM re-vendoring of Golden Modules and Composite Bundles.
Bypasses Architect and Developer LLMs completely. 100% deterministic file transforms.
"""

import copy
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

try:
    from shared.iac_upgrade_schema import (
        IaCAssetType,
        IaCModuleStatus,
        IaCDriftStatusResponse,
        IaCUpgradeRecord,
        IaCUpgradeHistoryResponse,
        TriggerIaCUpgradeRequest,
    )
except ImportError:
    from iac_upgrade_schema import (  # type: ignore
        IaCAssetType,
        IaCModuleStatus,
        IaCDriftStatusResponse,
        IaCUpgradeRecord,
        IaCUpgradeHistoryResponse,
        TriggerIaCUpgradeRequest,
    )

try:
    from shared.vcs_provider import IncompleteRepoTreeError
except ImportError:  # loaded without the shared package: no VCS provider exists, so nothing can raise it
    class IncompleteRepoTreeError(RuntimeError):  # type: ignore[no-redef]
        """Stand-in used only when shared.vcs_provider cannot be imported."""

logger = logging.getLogger("castor-iac-upgrade-engine")

MANIFEST_FILENAME = ".castor-module.json"
BUNDLE_MANIFEST_FILENAME = ".castor-bundle.json"


def calculate_module_content_hash(files_dict: Dict[str, str]) -> str:

    """
    Computes a deterministic SHA-256 hash over the module's .tf files.
    Files are sorted alphabetically by relative filename to guarantee determinism.
    Ignores .castor-module.json metadata to avoid hash recursion.
    Normalizes line endings and trailing whitespace.
    """
    h = hashlib.sha256()
    for fname in sorted(files_dict.keys()):
        if fname.endswith(".tf"):
            content = files_dict[fname] or ""
            # Strip trailing whitespace and normalize CRLF to LF
            lines = [line.rstrip() for line in content.replace("\r\n", "\n").splitlines()]
            normalized = "\n".join(lines).strip()
            h.update(f"{fname}\n{normalized}\n".encode("utf-8"))
    return h.hexdigest()


def get_platform_modules_path() -> Optional[str]:
    """Resolves the canonical infra/modules directory path across environments."""
    candidates = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../infra/modules")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infra/modules")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../infra/modules")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "infra/modules")),
        os.path.abspath("infra/modules"),
        os.path.abspath("apps/control-center/infra/modules"),
    ]
    for p in candidates:
        if os.path.isdir(p):
            return p
    return None


def _get_foundation_embedded_modules() -> Dict[str, str]:
    """The canonical workload-foundation/base files for the container fallback (FD-4AT RT F6).

    Returns the built-in payload entry (the same files as infra/modules/workload-foundation/base, pinned by the
    payload parity tests). It used to be a stale literal copy (a WIF provider with no attribute_condition, another
    Artifact Registry repository id, old outputs); a missing payload now fails loudly instead of re-vendoring that.
    """
    try:
        try:
            from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
        except ImportError:
            from builtin_modules_payload import BUILTIN_MODULE_FILES  # type: ignore
        entry = BUILTIN_MODULE_FILES["workload-foundation/base"]
    except (ImportError, KeyError) as exc:
        raise RuntimeError(
            "workload-foundation/base is unavailable: builtin_modules_payload is missing or lacks the entry"
        ) from exc
    return {f"infra/modules/workload-foundation/base/{fname}": text for fname, text in entry.items()}


def get_canonical_module_files() -> Dict[str, str]:
    """
    Loads all canonical module files from disk if available, or returns embedded
    definitions from payload / fallbacks.
    Returns dictionary of { "infra/modules/<module_name>/<filename>": "content" }.
    """
    modules: Dict[str, str] = {}
    mod_path = get_platform_modules_path()

    if mod_path and os.path.isdir(mod_path):
        for root, dirs, files_in_dir in os.walk(mod_path):
            tf_files = [f for f in files_in_dir if f.endswith(".tf")]
            if tf_files:
                rel_dir = os.path.relpath(root, mod_path)
                for fname in tf_files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            modules[f"infra/modules/{rel_dir}/{fname}"] = f.read()
                    except Exception as e:
                        logger.warning(f"Failed to read module file {fpath}: {e}")

    # Fallback to embedded payload if available
    if not modules:
        try:
            from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
            for mod_id, fdict in BUILTIN_MODULE_FILES.items():
                for fname, fcontent in fdict.items():
                    modules[f"infra/modules/{mod_id}/{fname}"] = fcontent
        except Exception:
            pass

    # Always ensure workload-foundation/base is populated
    embedded_foundations = _get_foundation_embedded_modules()
    for fpath, fcontent in embedded_foundations.items():
        if fpath not in modules:
            modules[fpath] = fcontent

    return modules


def extract_module_name_and_prefix(file_path: str) -> Optional[Tuple[str, str]]:
    """
    Extracts module identifier and directory prefix from an infra/modules path.
    Example:
      'infra/modules/workload-foundation/base/apis.tf' -> ('workload-foundation/base', 'infra/modules/workload-foundation/base/')
      'infra/modules/compute-cloudrun/main.tf' -> ('compute-cloudrun', 'infra/modules/compute-cloudrun/')
    """
    if not file_path.startswith("infra/modules/"):
        return None
    rel = file_path[len("infra/modules/"):]
    parts = rel.split("/")
    if len(parts) < 2:
        return None
    if parts[0] == "workload-foundation" and len(parts) >= 3 and parts[1] == "base":
        return "workload-foundation/base", "infra/modules/workload-foundation/base/"
    return parts[0], f"infra/modules/{parts[0]}/"


def extract_vendored_modules_from_files(files: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """
    Groups vendored files in child repository by module identifier.
    Returns: { module_name: { relative_filename: content } }
    """
    vendored: Dict[str, Dict[str, str]] = {}
    for path, content in files.items():
        res = extract_module_name_and_prefix(path)
        if res:
            mod_name, prefix = res
            rel_fname = path[len(prefix):]
            if mod_name not in vendored:
                vendored[mod_name] = {}
            vendored[mod_name][rel_fname] = content
    return vendored


def extract_vendored_bundles_from_files(files: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    """
    Extracts all bundle files under infra/bundles/<bundle_id>/ or bundles/<bundle_id>/.
    Returns: { bundle_id: { relative_filename: content } }
    """
    vendored: Dict[str, Dict[str, str]] = {}
    for path, content in files.items():
        clean_path = path.strip("/")
        bundle_id = None
        rel_fname = None
        if clean_path.startswith("infra/bundles/"):
            rest = clean_path[len("infra/bundles/"):]
            parts = rest.split("/", 1)
            if len(parts) == 2:
                bundle_id, rel_fname = parts[0], parts[1]
        elif clean_path.startswith("bundles/"):
            rest = clean_path[len("bundles/"):]
            parts = rest.split("/", 1)
            if len(parts) == 2:
                bundle_id, rel_fname = parts[0], parts[1]

        if bundle_id and rel_fname:
            if bundle_id not in vendored:
                vendored[bundle_id] = {}
            vendored[bundle_id][rel_fname] = content
    return vendored



def _get_firestore_client(client: Optional[Any] = None) -> Optional[Any]:
    if client is not None:
        return client
    try:
        from google.cloud import firestore
        proj = os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT")
        return firestore.Client(project=proj) if proj else firestore.Client()
    except Exception:
        return None


def get_upstream_module_files(
    mod_name: str,
    canonical_files: Dict[str, str],
    manifest: Optional[Dict[str, Any]] = None,
    firestore_client: Optional[Any] = None,
) -> Tuple[Dict[str, str], str, str, str]:
    """
    Resolves the canonical upstream files and metadata for a module.
    Returns: (upstream_files_dict, asset_type, latest_version, source_url)
    """
    manifest = manifest or {}
    asset_type = manifest.get("type", IaCAssetType.BUILTIN_MODULE.value)
    source_url = manifest.get("source", f"infra/modules/{mod_name}")
    latest_version = manifest.get("latest_version") or "v1.0.0"

    # 1. Check if canonical module exists in built-in platform files
    upstream_files: Dict[str, str] = {}
    for cpath, ccontent in canonical_files.items():
        res = extract_module_name_and_prefix(cpath)
        if res and res[0] == mod_name:
            _, prefix = res
            rel_name = cpath[len(prefix):]
            upstream_files[rel_name] = ccontent

    if upstream_files:
        return upstream_files, IaCAssetType.BUILTIN_MODULE.value, "v1.0.0", f"infra/modules/{mod_name}"

    # 2. Check custom_modules collection in Firestore
    fs = _get_firestore_client(firestore_client)
    if fs:
        try:
            doc = fs.collection("custom_modules").document(mod_name).get()
            if doc.exists:
                c_data = doc.to_dict() or {}
                s_type = c_data.get("source_type", "DIRECT_CODE")
                latest_ver = c_data.get("version_tag", "v1.0.0")
                src = c_data.get("source_url", f"custom_modules/{mod_name}")

                if s_type == "DIRECT_CODE":
                    hcl_files = c_data.get("hcl_files", {})
                    return hcl_files, IaCAssetType.CUSTOM_MODULE.value, latest_ver, src
                elif s_type == "REMOTE_GIT":
                    # For remote git, check if files can be fetched or if recorded in doc
                    hcl_files = c_data.get("hcl_files") or {}
                    if not hcl_files and c_data.get("source_url"):
                        try:
                            from shared.module_inspector import parse_github_repo_identifier
                            from shared.vcs_provider import VCSProviderFactory
                            provider = VCSProviderFactory.get_provider("GITHUB")
                            repo_id = parse_github_repo_identifier(c_data["source_url"])
                            repo_path = c_data.get("repo_path", "").strip().strip("/")
                            # FD-4DC: a partial upstream tree is never vendored as the module (typed refusal).
                            tree = provider.fetch_file_tree(repo_id, branch=latest_ver, require_complete=True)
                            for tpath, tcontent in tree.items():
                                if repo_path:
                                    if tpath.startswith(repo_path + "/"):
                                        hcl_files[tpath[len(repo_path) + 1:]] = tcontent
                                elif tpath.endswith(".tf"):
                                    hcl_files[tpath] = tcontent
                        except IncompleteRepoTreeError:
                            raise
                        except Exception as ge:
                            logger.debug(f"Could not fetch remote git tree for {mod_name}: {ge}")

                    return hcl_files, IaCAssetType.CUSTOM_MODULE.value, latest_ver, src
        except IncompleteRepoTreeError:
            raise
        except Exception as e:
            logger.debug(f"Could not inspect custom_modules for {mod_name}: {e}")

    return upstream_files, asset_type, latest_version, source_url


def _inspect_bundles_drift_hook(
    files: Dict[str, str],
    firestore_client: Optional[Any] = None,
) -> List[IaCModuleStatus]:
    """
    Inspects drift for all composite bundles present in infra/bundles/.
    Checks against built-in bundles or Firestore custom_bundles collection.
    """
    bundle_statuses: List[IaCModuleStatus] = []
    vendored_bundles = extract_vendored_bundles_from_files(files)
    if not vendored_bundles:
        return bundle_statuses

    try:
        from shared.builtin_bundles_payload import get_builtin_bundle
    except ImportError:
        try:
            from builtin_bundles_payload import get_builtin_bundle
        except ImportError:
            get_builtin_bundle = lambda b: None

    fs = _get_firestore_client(firestore_client)

    for bundle_id, bundle_files in sorted(vendored_bundles.items()):
        manifest: Dict[str, Any] = {}
        if BUNDLE_MANIFEST_FILENAME in bundle_files:
            try:
                manifest = json.loads(bundle_files[BUNDLE_MANIFEST_FILENAME])
            except Exception:
                pass

        current_sha256 = calculate_module_content_hash(bundle_files)
        current_version = manifest.get("version") or manifest.get("version_tag")

        upstream_files: Dict[str, str] = {}
        latest_version = current_version or "1.0.0"
        asset_type = IaCAssetType.CUSTOM_BUNDLE.value
        source_url = f"infra/bundles/{bundle_id}"

        # 1. Check built-in bundles
        built = get_builtin_bundle(bundle_id)
        if built:
            upstream_files = dict(built.hcl_files)
            latest_version = built.version_tag or "1.0.0"
            asset_type = IaCAssetType.BUILTIN_BUNDLE.value
            source_url = f"builtin://castor/bundles/{bundle_id}"
        elif fs:
            # 2. Check Firestore custom_bundles
            try:
                doc = fs.collection("custom_bundles").document(bundle_id).get()
                if doc.exists:
                    doc_data = doc.to_dict() or {}
                    upstream_files = dict(doc_data.get("hcl_files", {}))
                    latest_version = doc_data.get("version_tag", "1.0.0")
                    asset_type = IaCAssetType.CUSTOM_BUNDLE.value
                    source_url = doc_data.get("source_url") or f"infra/bundles/{bundle_id}"
            except Exception as e:
                logger.debug(f"Could not inspect custom_bundles for {bundle_id}: {e}")

        latest_sha256 = calculate_module_content_hash(upstream_files) if upstream_files else current_sha256

        changed_files: List[str] = []
        if upstream_files:
            all_file_keys = set(bundle_files.keys()).union(set(upstream_files.keys()))
            for f in all_file_keys:
                if f.endswith(".tf"):
                    if bundle_files.get(f) != upstream_files.get(f):
                        changed_files.append(f)

        drift_detected = False
        if upstream_files:
            if current_sha256 != latest_sha256:
                drift_detected = True
            elif current_version and latest_version and current_version != latest_version:
                drift_detected = True

        status = IaCModuleStatus(
            name=f"bundle:{bundle_id}",
            type=asset_type,
            current_version=current_version,
            latest_version=latest_version,
            current_sha256=current_sha256,
            latest_sha256=latest_sha256,
            drift_detected=drift_detected,
            source=source_url,
            changed_files=sorted(changed_files),
        )
        bundle_statuses.append(status)

    return bundle_statuses


def _re_vendor_bundles_hook(
    files: Dict[str, str],
    modules_to_upgrade: Optional[List[str]] = None,
    firestore_client: Optional[Any] = None,
    author: str = "StackVend IaC Upgrader",
) -> List[Dict[str, Any]]:
    """
    Pluggable composite bundle re-vendoring hook (Guardrail 4: Atomic cascade re-vendoring).
    Upgrades targeted bundles in infra/bundles/<bundle-id>/ AND automatically cascades to
    all underlying modules in infra/modules/ referenced in modules_included.
    """
    upgrade_details: List[Dict[str, Any]] = []
    vendored_bundles = extract_vendored_bundles_from_files(files)
    if not vendored_bundles:
        return upgrade_details

    try:
        from shared.builtin_bundles_payload import get_builtin_bundle
    except ImportError:
        try:
            from builtin_bundles_payload import get_builtin_bundle
        except ImportError:
            get_builtin_bundle = lambda b: None

    fs = _get_firestore_client(firestore_client)
    canonical_modules = get_canonical_module_files()

    for bundle_id, bundle_files in vendored_bundles.items():
        bundle_target_keys = {f"bundle:{bundle_id}", bundle_id}
        if modules_to_upgrade is not None and not any(k in modules_to_upgrade for k in bundle_target_keys):
            continue

        built = get_builtin_bundle(bundle_id)
        upstream_files: Dict[str, str] = {}
        latest_ver = "1.0.0"
        modules_included: List[str] = []
        commit_sha: Optional[str] = None
        asset_type = IaCAssetType.CUSTOM_BUNDLE.value

        if built:
            upstream_files = dict(built.hcl_files)
            latest_ver = built.version_tag or "1.0.0"
            modules_included = list(built.modules_included)
            asset_type = IaCAssetType.BUILTIN_BUNDLE.value
        elif fs:
            try:
                doc = fs.collection("custom_bundles").document(bundle_id).get()
                if doc.exists:
                    doc_data = doc.to_dict() or {}
                    upstream_files = dict(doc_data.get("hcl_files", {}))
                    latest_ver = doc_data.get("version_tag", "1.0.0")
                    modules_included = list(doc_data.get("modules_included", []))
                    commit_sha = doc_data.get("commit_sha")
                    asset_type = IaCAssetType.CUSTOM_BUNDLE.value
            except Exception as e:
                logger.warning(f"Error resolving bundle {bundle_id} during upgrade: {e}")

        if not upstream_files:
            continue

        prefix = f"infra/bundles/{bundle_id}/"
        for rel_fname, hcl_code in upstream_files.items():
            files[f"{prefix}{rel_fname}"] = hcl_code

        content_hash = calculate_module_content_hash(upstream_files)
        bundle_manifest = {
            "bundle_id": bundle_id,
            "version": latest_ver,
            "type": asset_type,
            "commit_sha": commit_sha,
            "content_sha256": content_hash,
            "modules_included": modules_included,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "vendored_by": author,
        }
        files[f"{prefix}{BUNDLE_MANIFEST_FILENAME}"] = json.dumps(bundle_manifest, indent=2)

        bundle_upgrade_entry: Dict[str, Any] = {
            "bundle": bundle_id,
            "type": asset_type,
            "version": latest_ver,
            "content_sha256": content_hash,
            "files_updated": list(upstream_files.keys()),
            "cascaded_modules": [],
        }

        # Guardrail 4: Atomic cascade re-vendoring of underlying Golden Modules
        for mod_name in modules_included:
            mod_upstream, mod_type, mod_latest_ver, _ = get_upstream_module_files(
                mod_name, canonical_modules, None, fs
            )
            if mod_upstream:
                mod_prefix = f"infra/modules/{mod_name}/"
                for rel_mfile, mcontent in mod_upstream.items():
                    files[f"{mod_prefix}{rel_mfile}"] = mcontent
                mod_hash = calculate_module_content_hash(mod_upstream)
                mod_manifest = {
                    "module": mod_name,
                    "version": mod_latest_ver,
                    "type": mod_type,
                    "content_sha256": mod_hash,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "vendored_by": f"{author} (via bundle:{bundle_id} cascade)",
                }
                files[f"{mod_prefix}{MANIFEST_FILENAME}"] = json.dumps(mod_manifest, indent=2)
                bundle_upgrade_entry["cascaded_modules"].append(mod_name)

        upgrade_details.append(bundle_upgrade_entry)

    return upgrade_details



def inspect_workload_iac_drift(
    files: Dict[str, str],
    workload_id: str = "",
    firestore_client: Optional[Any] = None,
) -> IaCDriftStatusResponse:
    """
    Performs dual-check drift detection:
    1. Cryptographic SHA-256 content hashing across all vendored .tf files.
    2. Version tag / manifest comparison.
    Zero LLM calls. Returns complete drift status response.
    """
    vendored_modules = extract_vendored_modules_from_files(files)
    canonical_files = get_canonical_module_files()

    module_statuses: List[IaCModuleStatus] = []

    for mod_name, mod_files in sorted(vendored_modules.items()):
        # Parse manifest if present
        manifest: Dict[str, Any] = {}
        if MANIFEST_FILENAME in mod_files:
            try:
                manifest = json.loads(mod_files[MANIFEST_FILENAME])
            except Exception:
                pass

        current_sha256 = calculate_module_content_hash(mod_files)
        current_version = manifest.get("version")

        upstream_files, asset_type, latest_version, source_url = get_upstream_module_files(
            mod_name, canonical_files, manifest, firestore_client
        )

        latest_sha256 = calculate_module_content_hash(upstream_files) if upstream_files else current_sha256

        # Changed files calculation
        changed_files: List[str] = []
        if upstream_files:
            all_file_keys = set(mod_files.keys()).union(set(upstream_files.keys()))
            for f in all_file_keys:
                if f.endswith(".tf"):
                    if mod_files.get(f) != upstream_files.get(f):
                        changed_files.append(f)

        drift_detected = False
        if upstream_files:
            # Hash difference is authoritative for content drift
            if current_sha256 != latest_sha256:
                drift_detected = True
            # Version tag difference if both present
            elif current_version and latest_version and current_version != latest_version:
                drift_detected = True

        status = IaCModuleStatus(
            name=mod_name,
            type=asset_type,
            current_version=current_version,
            latest_version=latest_version,
            current_sha256=current_sha256,
            latest_sha256=latest_sha256,
            drift_detected=drift_detected,
            source=source_url,
            changed_files=sorted(changed_files),
        )
        module_statuses.append(status)

    # Run pluggable composite bundle hook
    bundle_statuses = _inspect_bundles_drift_hook(files, firestore_client)
    module_statuses.extend(bundle_statuses)

    total_modules = len(module_statuses)
    outdated_modules = sum(1 for m in module_statuses if m.drift_detected)
    drift_detected = outdated_modules > 0

    return IaCDriftStatusResponse(
        workload_id=workload_id,
        drift_detected=drift_detected,
        modules=module_statuses,
        total_modules=total_modules,
        outdated_modules=outdated_modules,
    )


def upgrade_workload_iac_vendoring(
    files: Dict[str, str],
    modules_to_upgrade: Optional[List[str]] = None,
    author: str = "Operator",
    firestore_client: Optional[Any] = None,
) -> Tuple[Dict[str, str], List[str], List[Dict[str, Any]]]:
    """
    Deterministically re-vendors canonical Golden Modules and Composite Bundles.
    1. Overwrites files under infra/modules/<mod_name>/* with latest upstream canonical definitions.
    2. Writes .castor-module.json manifest recording version, SHA-256 hash, and author.
    3. STRICTLY PRESERVES: infra/human.tf, infra/human_override.tf, infra/main.tf, and apps/*.
    4. Executes zero LLM agent calls.
    Returns: (updated_files_dict, list_of_upgraded_module_names, upgrade_details)
    """
    updated_files = dict(files)
    canonical_files = get_canonical_module_files()
    now_iso = datetime.now(timezone.utc).isoformat()

    # If modules_to_upgrade not specified, inspect drift and upgrade all drifted
    if not modules_to_upgrade:
        drift_resp = inspect_workload_iac_drift(files, firestore_client=firestore_client)
        target_modules = [m.name for m in drift_resp.modules if m.drift_detected]
    else:
        target_modules = list(modules_to_upgrade)

    if not target_modules:
        return updated_files, [], []

    upgraded_modules: List[str] = []
    upgrade_details: List[Dict[str, Any]] = []

    vendored_modules = extract_vendored_modules_from_files(files)

    for mod_name in target_modules:
        current_mod_files = vendored_modules.get(mod_name, {})
        manifest = {}
        if MANIFEST_FILENAME in current_mod_files:
            try:
                manifest = json.loads(current_mod_files[MANIFEST_FILENAME])
            except Exception:
                pass

        upstream_files, asset_type, latest_ver, source_url = get_upstream_module_files(
            mod_name, canonical_files, manifest, firestore_client
        )

        if not upstream_files:
            logger.warning(f"No upstream files found for module '{mod_name}'; skipping upgrade.")
            continue

        # Prefix for target directory
        if mod_name == "workload-foundation/base":
            prefix = "infra/modules/workload-foundation/base/"
        else:
            prefix = f"infra/modules/{mod_name}/"

        # 1. Remove old .tf files from module if no longer in upstream
        for old_fname in list(current_mod_files.keys()):
            if old_fname.endswith(".tf") and old_fname not in upstream_files:
                old_path = f"{prefix}{old_fname}"
                if old_path in updated_files:
                    del updated_files[old_path]

        # 2. Overwrite / write upstream .tf files
        for fname, fcontent in upstream_files.items():
            if fname.endswith(".tf"):
                updated_files[f"{prefix}{fname}"] = fcontent

        # 3. Generate and write updated .castor-module.json manifest
        content_hash = calculate_module_content_hash(upstream_files)
        new_manifest = {
            "module_name": mod_name,
            "type": asset_type,
            "version": latest_ver,
            "content_sha256": content_hash,
            "source": source_url,
            "vendored_at": now_iso,
            "vendored_by": author,
        }
        updated_files[f"{prefix}{MANIFEST_FILENAME}"] = json.dumps(new_manifest, indent=2)

        upgraded_modules.append(mod_name)
        upgrade_details.append({
            "module": mod_name,
            "type": asset_type,
            "version": latest_ver,
            "content_sha256": content_hash,
            "files_updated": list(upstream_files.keys()),
        })

    # Pluggable composite bundle hook (Guardrail 4: Atomic cascade re-vendoring)
    bundle_details = _re_vendor_bundles_hook(updated_files, target_modules, firestore_client, author=author)
    upgrade_details.extend(bundle_details)
    for bd in bundle_details:
        b_name = f"bundle:{bd['bundle']}"
        if b_name not in upgraded_modules:
            upgraded_modules.append(b_name)

    return updated_files, upgraded_modules, upgrade_details



class ModuleDeletionScopeError(RuntimeError):
    """FD-4DC-e: the upgrade dropped a path that is not a `.tf` file of a module it upgraded. The engine never removes
    anything else, so this is a platform defect: the caller deletes nothing and commits nothing."""

    error_class = "IAC_UPGRADE_DELETION_SCOPE"


def module_files_removed_by_upgrade(
    existing_files: Dict[str, str],
    updated_files: Dict[str, str],
    upgraded_modules: List[str],
) -> List[str]:
    """
    FD-4DC-e: the repository paths an upgrade removes (sorted), i.e. the vendored `.tf` files the new module version no
    longer has. `existing_files` is the tree the upgrade read; `updated_files` / `upgraded_modules` are what
    upgrade_workload_iac_vendoring returned for it.

    A removed path is returned only when it is a `.tf` file owned (extract_module_name_and_prefix, the engine's own
    grouping) by a module in `upgraded_modules`; a module that was not upgraded, a bundle, app code, root IaC and
    human overrides can never be listed. Any other removed path raises ModuleDeletionScopeError (never filtered out).
    """
    upgraded = {m for m in upgraded_modules if isinstance(m, str) and not m.startswith("bundle:")}
    removed = sorted(p for p in existing_files if p not in updated_files)
    outside = []
    for path in removed:
        owner = extract_module_name_and_prefix(path)
        if not (path.endswith(".tf") and owner is not None and owner[0] in upgraded):
            outside.append(path)
    if outside:
        raise ModuleDeletionScopeError(
            f"the upgrade of {sorted(upgraded)} removed {len(outside)} path(s) outside the upgraded modules' .tf "
            f"files: {outside[:20]}")
    return removed


# ------------------------------------------------------------------------------
# Firestore Audit Subcollection & Parent Document Helpers
# ------------------------------------------------------------------------------

def record_iac_upgrade_start(
    workload_id: str,
    author: str,
    modules: List[str],
    firestore_client: Optional[Any] = None,
) -> str:
    """
    Creates an immutable audit record in workloads/{product_id}/iac_upgrades/{upgrade_id}
    with status IN_PROGRESS.
    """
    upgrade_id = f"upgrade-{uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    record = IaCUpgradeRecord(
        upgrade_id=upgrade_id,
        workload_id=workload_id,
        triggered_at=now_iso,
        triggered_by=author or "Operator",
        status="IN_PROGRESS",
        updated_modules=modules,
    )

    fs = _get_firestore_client(firestore_client)
    if fs:
        try:
            doc_data = record.model_dump() if hasattr(record, "model_dump") else record.dict()
            fs.collection("workloads").document(workload_id).collection("iac_upgrades").document(upgrade_id).set(doc_data)
        except Exception as e:
            logger.warning(f"Could not record iac upgrade start in Firestore: {e}")

    return upgrade_id


def record_iac_upgrade_complete(
    workload_id: str,
    upgrade_id: str,
    status: str,
    commit_sha: Optional[str] = None,
    pr_number: Optional[int] = None,
    pr_url: Optional[str] = None,
    validation_error: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    drift_detected: bool = False,
    drift_count: int = 0,
    author: str = "Operator",
    firestore_client: Optional[Any] = None,
) -> None:
    """
    Updates the audit record and updates high-performance summary fields
    on the parent workload document for instant $O(1)$ catalog loading.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    fs = _get_firestore_client(firestore_client)
    if not fs:
        return

    try:
        upgrade_ref = fs.collection("workloads").document(workload_id).collection("iac_upgrades").document(upgrade_id)
        update_data = {
            "status": status,
            "completed_at": now_iso,
            "commit_sha": commit_sha,
            "pr_number": pr_number,
            "pr_url": pr_url,
            "validation_error": validation_error,
            "details": details or {},
        }
        upgrade_ref.update(update_data)
    except Exception as e:
        logger.warning(f"Could not update iac_upgrades subcollection: {e}")

    # Update parent doc
    try:
        parent_ref = fs.collection("workloads").document(workload_id)
        parent_update = {
            "last_iac_upgrade_at": now_iso,
            "last_iac_upgrade_by": author,
            "last_iac_upgrade_status": status,
            "iac_drift_detected": drift_detected,
            "iac_drift_count": drift_count,
        }
        parent_ref.update(parent_update)
        logger.info(f"Updated parent workload '{workload_id}' with IaC upgrade status '{status}'.")
    except Exception as e:
        logger.warning(f"Could not update parent workload doc '{workload_id}': {e}")


def get_iac_upgrade_history(
    workload_id: str,
    limit: int = 50,
    firestore_client: Optional[Any] = None,
) -> List[IaCUpgradeRecord]:
    """
    Retrieves the chronological audit history of IaC upgrades for a workload.
    """
    records: List[IaCUpgradeRecord] = []
    fs = _get_firestore_client(firestore_client)
    if not fs:
        return records

    try:
        from google.cloud.firestore import Query
        docs = (
            fs.collection("workloads")
            .document(workload_id)
            .collection("iac_upgrades")
            .order_by("triggered_at", direction=Query.DESCENDING)
            .limit(limit)
            .stream()
        )
        for doc in docs:
            data = doc.to_dict() or {}
            records.append(IaCUpgradeRecord(**data))
    except Exception as e:
        logger.warning(f"Could not read iac_upgrades history for '{workload_id}': {e}")

    return records

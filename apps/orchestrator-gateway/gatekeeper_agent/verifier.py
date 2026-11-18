"""
Project Castor: Anti-Hallucination Gatekeeper Agent (SynthesisVerifierAgent)
Hermetic in-memory compilation, add-only package/requirements scaffolding (FD-4AD),
and container contract verification before git commits and release promotion.
"""

import ast
import logging
import os
import py_compile
import re
import shutil
import tempfile
from collections.abc import Mapping
from typing import Any, Dict, List, Optional, Set, Tuple

# FD-4G: no ImportError fallback -- a missing path guard must crash at boot, never fail open.
from shared.path_safety import GIT_RESERVED, UnsafePathError, safe_join, validate_manifest_keys
from shared.service_topology import topology_owned_tree as _topology_owned_tree  # lane 10 (FD-51) seam

try:
    from .distribution_imports import NAMESPACE_TOP_LEVELS, requirement_import_roots
    from .pypi_catalog import STDLIB_MODULES
    from .requirements_contract import append_missing_requirements, canonical_name, declared_names
except ImportError:
    from distribution_imports import NAMESPACE_TOP_LEVELS, requirement_import_roots
    from pypi_catalog import STDLIB_MODULES
    from requirements_contract import append_missing_requirements, canonical_name, declared_names

logger = logging.getLogger("castor-gatekeeper-agent")
logging.basicConfig(level=logging.INFO)

CRITICAL_STDLIB_MODULES = {
    "secrets", "queue", "email", "http", "random", "logging", "asyncio",
    "json", "token", "typing", "sys", "os", "re", "io", "time", "ast",
    "copy", "types", "socket", "ssl", "platform", "signal",
}


# HB-29 helper `_find_fastapi_instantiation_end` (located `app = FastAPI(` by regex for the /health injection) DELETED
# with that injection in Step 2 S2-A (register HS-09).


def _module_ast(text: Any) -> Optional[ast.Module]:
    if not isinstance(text, str):
        return None
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def imports_sibling_conftest_top_level(d: str, files: Mapping) -> bool:
    """CONFTEST-TOP-LEVEL-IMPORT (register row; live ex09-1115, 11-15): True when the add-only package scaffolding must
    NOT add `d/__init__.py`, because that file would turn valid test code into a collection error. Exact AST facts
    only (Invariant 2), all of them required:
    * `d/conftest.py` is in the tree;
    * a `.py` file directly in `d` imports the top-level module `conftest` (`import conftest[.x]` or
      `from conftest import ...`, absolute: level 0), which resolves to `d/conftest.py` only while `d` is not a
      package (pytest's default `prepend` import mode then puts `d` itself on sys.path; with `d/__init__.py` it puts
      the first ancestor without one there and registers the file as `<package>.conftest`);
    * no `.py` file in `d` or below it uses a relative import (those, `from ..x` in a sub-package included, need the
      package), every file directly in `d` parses, and no `.py` file of the tree imports a dotted module name that has
      `d`'s own name as a component (a `from tests.x import ...` needs the package too);
    * RT F2: no other `conftest.py` sits where a top-level `conftest` import could find it instead: the repository root,
      a service directory `apps/<service>/` (the QA runner's cwd and PYTHONPATH) or any ancestor directory of `d`
      (with that file the import resolved before, while `d` was a package).
    Anything else (the default): False, and the directory gets its `__init__.py` exactly as before."""
    prefix = f"{d}/"
    if not isinstance(files.get(f"{prefix}conftest.py"), str):
        return False
    d_parts = d.split("/")
    ancestors = {"/".join(d_parts[:i]) for i in range(len(d_parts))}   # "" = the repository root
    for path in files:
        if not isinstance(path, str) or path.split("/")[-1] != "conftest.py" or path == f"{prefix}conftest.py":
            continue
        folder = path.rsplit("/", 1)[0] if "/" in path else ""
        parts = folder.split("/") if folder else []
        if folder in ancestors or (len(parts) == 2 and parts[0] == "apps"):
            return False
    name = d_parts[-1]
    imports_conftest = False
    for path in sorted(p for p in files if isinstance(p, str) and p.endswith(".py")):
        own = path.startswith(prefix) and "/" not in path[len(prefix):]
        below = path.startswith(prefix)
        tree = _module_ast(files[path])
        if tree is None:
            if own:
                return False
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                dotted = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    if below:
                        return False
                    continue
                dotted = [node.module or ""]
            else:
                continue
            for mod in dotted:
                parts = mod.split(".")
                if name in parts:
                    return False   # the tree imports this directory as a package
                if own and parts[0] == "conftest":
                    imports_conftest = True
    return imports_conftest


class SynthesisVerifierAgent:
    """
    Dedicated Zero-Hallucination Gatekeeper.
    Performs compiler-in-the-loop verification across all microservices:
    1. Adds missing package `__init__.py` files (add-only; the import rewrites were deleted, FD-4AD).
    2. Appends requirements an exact fact proves missing (add-only, FD-4AD).
    3. Runs in-memory Python syntax compilation (py_compile).
    4. (The Buildpack container contract, Dockerfile purge and runtime pin, is the developer stage's
       handler.enforce_container_contract (FD-55 W5); the Procfile and the health route are the AI's, judged by V3c.)
    """

    def __init__(self, product_id: Optional[str] = None):
        self.product_id = product_id or "workload"

    def detect_services(self, files: Dict[str, str]) -> List[str]:
        """Discovers all service directory names under apps/<service>/."""
        services = set()
        excluded_dirs = {"shared", "common", "contracts", "schemas", "__pycache__"}
        for path in files.keys():
            if path.startswith("apps/"):
                parts = path.split("/")
                # Must have at least 3 parts (apps/<service>/...), not be an excluded library dir, and not be a flat file
                if len(parts) >= 3 and parts[1] and parts[1] not in excluded_dirs and "." not in parts[1]:
                    services.add(parts[1])
        return sorted(list(services)) if services else [self.product_id]

    def purge_shadowed_package_files(
        self,
        files: Dict[str, str],
        existing_paths: Optional[List[str]] = None,
        existing_contents: Optional[Dict[str, str]] = None,
        castor_authored_paths: Optional[Set[str]] = None,
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Add-only package scaffolding (FD-4AD; the name is kept for its callers): every directory that holds a `.py`
        file gets an `__init__.py` when it has none, except hidden directories and "shielded" ones (a path part equal
        to a reserved non-package dir, to a requirement name or (FD-4A) to a top-level import name that requirement's
        distribution installs, so a local dir never becomes a package that shadows an installed distribution). No existing file is changed, moved, renamed or removed: an existing file is returned
        byte-identical (Invariant 1). The `existing_*` / `castor_authored_paths` arguments are accepted and unused.

        DELETED here (FD-4AD, HEALERS HB-26 / HB-27), each mutated valid trees:
        * the Alembic move `alembic/` -> `migrations/` + `alembic.ini` regex + `alembic/alembic.ini` replace in `.py`;
        * the purge of a flat `x.py` beside an `x/` directory (Gate A 01-r3: the AI's `schemas.py` was deleted);
        * the purge of existing `__init__.py` files in shielded dirs;
        * the stdlib-shadow rename `<stem>.py` -> `<stem>_service.py` at any depth plus a regex rewrite of every
          `from <stem>` (Gate B S3-r2: `secrets.py` renamed and `main.py` rewritten).
        Their genuine requirements are typed diagnostics: GATE.ENTRYPOINT_SHADOWED (verify, blocking) and the
        report-only V3d codes PY.STDLIB_SHADOWED / PY.MODULE_PACKAGE_CONFLICT (developer_agent/validators/
        python_layout.py).
        Returns (files, []): nothing is ever scheduled for deletion.
        """
        updated = dict(files)
        GLOBAL_RESERVED_NON_PACKAGE_DIRS = {
            "alembic", "migrations", "static", "templates", "docs", "infra", "k8s", "versions"
        }
        installed_packages: Set[str] = set()
        for path, content in updated.items():
            if path.endswith("requirements.txt") and isinstance(content, str):
                installed_packages |= {n.replace("-", "_") for n in declared_names(content)}
                # FD-4A: also the top-level import names the distribution installs (PyYAML -> yaml,
                # google-cloud-storage -> google), so the scaffolding never turns a dir into a package shadowing it.
                installed_packages |= {m.lower() for m in requirement_import_roots([content])[0]}
        shadowing_hazard_dirs = GLOBAL_RESERVED_NON_PACKAGE_DIRS | installed_packages

        py_dirs = set()
        for path in updated.keys():
            if path.endswith(".py") and not path.endswith("__init__.py"):
                parts = path.split("/")
                for i in range(1, len(parts)):
                    py_dirs.add("/".join(parts[:i]))

        def is_shielded_non_package_dir(d: str) -> bool:
            return any(part.lower() in shadowing_hazard_dirs for part in d.split("/"))

        for d in sorted(py_dirs):
            if not d or d.startswith(".") or "/." in d or is_shielded_non_package_dir(d):
                continue
            if imports_sibling_conftest_top_level(d, updated):
                # CONFTEST-TOP-LEVEL-IMPORT (ex09-1115, 11-15): an `__init__.py` here would make pytest import the
                # directory's conftest.py as `<package>.conftest`, so the author's `from conftest import ...` would
                # fail collection (ModuleNotFoundError: No module named 'conftest'). The directory is left as written.
                continue
            init_file = f"{d}/__init__.py"
            if init_file not in updated:
                updated[init_file] = "# Auto-generated package init by StackVend\n"
                logger.info(f"🛡️ Gatekeeper ensured package init '{init_file}'")

        return updated, []

    # HB-31 rest / HE-02 `cure_imports` (ContainerImportTransformer + pre_ast_normalize over every `.py`) DELETED
    # (FD-4AD): its regexes rewrote `apps.<svc>.` inside string literals (Gate A 08-r2 `migrations/env.py`), flattened
    # valid relative imports and rewrote files outside any service (FDCSQL 08-r1 root `tests/test_main.py`). An import
    # that cannot resolve from the service root is the report-only CONTAINER.IMPORT_OUTSIDE_SERVICE (V3c-imports); a hyphenated
    # `apps.<svc-name>` import is PY.SYNTAX (V3a), repaired by the AI.

    # HE-03 twin `extract_ast_dependencies` DELETED (FD-4AD RT minor): no caller was left after the add-only contract
    # (gatekeeper_agent/requirements_contract.py) replaced HB-28; the catalog `resolve_import_to_pypi` stays.

    def reconcile_service_requirements(self, files: Dict[str, str]) -> Dict[str, str]:
        """
        Add-only (FD-4AD, replaces HB-28): appends to `apps/<svc>/requirements.txt` only a distribution an exact fact
        proves the service needs and no line names (gatekeeper_agent/requirements_contract.py: AST imports through the
        closed-world catalog HE-03, exact imported-name table, Procfile launcher). Never deletes, reorders, re-pins or
        rewrites a line; never touches the root requirements.txt; never gives a non-Python service a requirements.txt.

        DELETED (HB-28): the 9 prepended base pins (incl. `pytest`, `pydantic>=2.6.0` beside a user `==1.10`), the
        prune of every line whose name matched any local `.py` stem anywhere in the tree, the `==` -> `>=` softening of
        Google SDK pins (Gate A 04-r1 / 05-r3: `google-cloud-pubsub==2.27.1` rewritten), the root <-> service mirroring.
        """
        updated, actions = append_missing_requirements(files)
        for action in actions:
            logger.info(f"Gatekeeper requirements contract: {action}")
        return updated

    def compile_in_memory(self, files: Dict[str, str]) -> Tuple[bool, List[str]]:
        """
        Runs py_compile across all Python files using in-memory virtual temporary buffers.
        Returns (success: bool, errors: List[str]).
        """
        errors = []
        with tempfile.TemporaryDirectory() as tmpdir:
            for path, content in files.items():
                if path.endswith(".py"):
                    # FD-4G: a key that is not a contained, canonical relpath is a compile ERROR (ok=False),
                    # never written and never silently dropped.
                    try:
                        full_p = safe_join(tmpdir, path)
                    except UnsafePathError as e:
                        clean_msg = f"Unsafe path key {path!r}: {e.reason}"
                        errors.append(clean_msg)
                        logger.error(clean_msg)
                        continue
                    if os.path.isdir(full_p):
                        shutil.rmtree(full_p)
                    os.makedirs(os.path.dirname(full_p), exist_ok=True)
                    with open(full_p, "w", encoding="utf-8") as f:
                        f.write(content)

                    try:
                        py_compile.compile(full_p, doraise=True)
                    except py_compile.PyCompileError as e:
                        clean_msg = f"Syntax/Compilation Error in '{path}': {e.msg}"
                        errors.append(clean_msg)
                        logger.error(clean_msg)
                    except Exception as exc:
                        clean_msg = f"Compiler error in '{path}': {exc}"
                        errors.append(clean_msg)
                        logger.error(clean_msg)

        return (len(errors) == 0, errors)

    # HB-29 twin `enforce_container_contracts` DELETED (FD-55 W5, plan G23, register FD55-W5): its Dockerfile purge
    # (`basename.startswith("dockerfile")`, broader than the platform rule: it also deleted e.g. `dockerfile-notes.md`)
    # and its `.python-version` = 3.13 pins duplicated the developer stage's one container-contract rule,
    # developer_agent/handler.enforce_container_contract (exact basenames `Dockerfile`, `Dockerfile.<x>`,
    # `.dockerignore`; the runtime pin of every deployed service and the root), which runs on every assembled tree.

    def reconcile_iac_environment_contracts(self, files: Dict[str, str]) -> Dict[str, str]:
        """
        HB-05: binds the env vars the workload's custom resources (and, without a topology, the sibling service URLs
        the service's own code reads, S2-D) imply into main.tf's `module "compute"` and into the secondary
        compute-cloudrun modules of custom.tf. The bound keys and values are unchanged (extract_custom_resource_env_vars).

        FD-55 W5 (register FD55-W5; plan G17 CONVERT): the edit is an exact parser edit
        (developer_agent/sibling_wiring.bind_module_env, python-hcl2 parse-tree offsets): a key counts as bound only
        when it is a key of that module's `env_vars` object; the new keys are appended to the object of
        `merge(var.env_vars, {...})`, or `var.env_vars` becomes `merge(var.env_vars, {...})`; every other byte of the
        file is kept, and an edit python-hcl2 does not confirm exactly is not written. DELETED: the `merge(var.env_vars,
        {` ... `})` body regex, the `env_vars = var.env_vars` regex (which normalized the attribute's alignment), the
        whole-file `"KEY" =` presence regex and the `str.replace` of a module's text.
        Idempotent: a second pass finds every key bound and writes nothing.
        """
        updated = dict(files)
        custom_tf = updated.get("infra/workload/custom.tf")
        main_tf = updated.get("infra/workload/main.tf")

        if not custom_tf or not main_tf:
            return updated

        try:
            try:
                from developer_agent.terraform_engine import extract_custom_resource_env_vars
                from developer_agent.sibling_wiring import (bind_module_env, compute_cloudrun_modules,
                                                            module_env_keys, plan_sibling_wiring,
                                                            primary_caller_service)
            except ImportError:
                from ..developer_agent.terraform_engine import extract_custom_resource_env_vars
                from ..developer_agent.sibling_wiring import (bind_module_env, compute_cloudrun_modules,
                                                              module_env_keys, plan_sibling_wiring,
                                                              primary_caller_service)
        except Exception:
            return updated

        # LANE 10 SEAM (FD-51): a tree that carries a valid platform-rendered infra/workload/topology.json is wired
        # from the topology's edges only, so the sibling section never re-adds another service's URL here (FD-40
        # cycle, FD-41/45 misrouting). A mode switch that can only make this cure do less; no HCL comes from it.
        include_siblings = not _topology_owned_tree(files, getattr(self, "product_id", "") or "")
        # S2-D (HS-65): the caller is main.tf's primary compute module (its literal service_name; exact parse).
        expected_env = extract_custom_resource_env_vars(custom_tf, files, caller_service=primary_caller_service(main_tf),
                                                        caller_module="compute", main_tf=main_tf,
                                                        include_siblings=include_siblings)
        if not expected_env:
            return updated

        # Keys main.tf's module "compute" does not bind yet (exact env_vars object keys)
        bound = module_env_keys(main_tf, "compute")
        missing_bindings = {k: v for k, v in expected_env.items() if k not in bound}
        if not missing_bindings:
            return updated

        new_main, written = bind_module_env(main_tf, "compute", missing_bindings)
        if written:
            updated["infra/workload/main.tf"] = new_main
            logger.info(f"Gatekeeper HB-05: bound {written} into main.tf module 'compute' (exact parser edit)")
        else:
            logger.warning(f"Gatekeeper HB-05: {sorted(missing_bindings)} not bound into main.tf module 'compute' "
                           "(no exact `env_vars = var.env_vars` / `merge(var.env_vars, {...})` to edit)")

        # Secondary compute-cloudrun modules declared in custom.tf (S2-D: by the exact module `source`)
        try:
            current_custom = updated.get("infra/workload/custom.tf", "")
            cured_custom = current_custom
            for sec in compute_cloudrun_modules(current_custom):
                m_lbl, sec_svc_name = sec.label, sec.service
                sec_expected = extract_custom_resource_env_vars(current_custom, files, caller_service=sec_svc_name,
                                                                caller_module=m_lbl,
                                                                main_tf=updated.get("infra/workload/main.tf"),
                                                                include_siblings=include_siblings)
                sec_bound = module_env_keys(current_custom, m_lbl)
                sec_missing = {k: v for k, v in sec_expected.items() if k not in sec_bound}
                if not sec_missing:
                    continue
                # A module whose env_vars is exactly `var.env_vars` is only given a merge when the plan binds a sibling
                # URL its code reads exactly (S2-D code RT F2; lane 10 seam F4 rule 2: never on a topology tree).
                reads_sibling = False
                if include_siblings:
                    plan = plan_sibling_wiring(current_custom, files, sec_svc_name, caller_module=m_lbl,
                                               main_tf=updated.get("infra/workload/main.tf"))
                    reads_sibling = any(plan.bindings.get(k) == v for k, v in sec_missing.items())
                cured_custom, sec_written = bind_module_env(cured_custom, m_lbl, sec_missing,
                                                            allow_plain=include_siblings and reads_sibling)
                if sec_written:
                    logger.info(f"Gatekeeper HB-05: bound {sec_written} into custom.tf module '{m_lbl}' "
                                "(exact parser edit)")
                elif reads_sibling:
                    # never silent: V2f reports IAC.SIBLING_URI_UNBOUND reason=not_written
                    logger.warning(f"Gatekeeper HB-05: not wiring {sorted(sec_missing)} into custom.tf module "
                                   f"'{m_lbl}': no exact edit (V2f reports not_written)")
            updated["infra/workload/custom.tf"] = cured_custom
        except Exception as exc:  # noqa: BLE001 - custom.tf is then kept byte-identical (cured_custom not stored)
            logger.warning(f"Gatekeeper HB-05: custom.tf secondary env binding skipped ({type(exc).__name__}: {exc})")

        return updated

    def reconcile_iac_module_vendoring(self, files: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
        """
        Finds the local modules the tree's Terraform calls (a module call's exact local `source` naming
        `modules/<name>`) and, if any of them lacks files in infra/modules/<name>/, adds that module's files from the
        platform catalog (vendor_terraform_modules, the developer stage's one vendoring rule, run on a copy).
        FD-55 W5 (register FD55-W5; plan G20 HD-39 CONVERT): the references come from the parser
        (terraform_engine.referenced_local_dirs: python-hcl2 for `.tf`, json for `.tf.json`), not from a
        `source = "../modules/<x>"` regex over the text, so a commented-out `source` line vendors nothing.
        FD-55 W8 (register FD55-W8; FD-4AD residual FD22-09): add-only and archetype-free. Only files under
        `infra/modules/<name>/` of a missing referenced module that are not in the tree are added; no existing file
        is changed. The `archetype` argument is gone: it made the vendoring call (re)write the whole foundation module
        and the archetype's compute module on every cure that found a missing module, and three of the four callers
        ran with its "cloudrun" default whatever the workload (the pre-commit cure, the gatekeeper stage, whose
        workflow call sends no archetype, and the eval harness), so a GKE / Cloud Run Job / bastion tree was given an
        unused compute-cloudrun module.
        """
        updated = dict(files)
        errors = []

        try:
            from developer_agent.terraform_engine import referenced_local_dirs
        except ImportError:  # pragma: no cover - loaded as a sub-package of the gateway root
            from ..developer_agent.terraform_engine import referenced_local_dirs  # type: ignore
        referenced_modules = referenced_local_dirs(updated, "modules", skip_prefixes=("infra/modules/",))

        missing_modules = set()
        for mod_name in referenced_modules:
            has_files = any(p.startswith(f"infra/modules/{mod_name}/") or p.startswith(f"modules/{mod_name}/") for p in updated.keys())
            if not has_files:
                missing_modules.add(mod_name)

        if missing_modules:
            logger.info(f"🛡️ Gatekeeper: Detected unvendored referenced modules: {sorted(missing_modules)}. Triggering auto-cure...")
            try:
                try:
                    from developer_agent.terraform_engine import vendor_terraform_modules
                except ImportError:  # pragma: no cover - loaded as a sub-package of the gateway root
                    from ..developer_agent.terraform_engine import vendor_terraform_modules  # type: ignore
                catalog = dict(updated)
                vendor_terraform_modules(catalog)
                prefixes = tuple(f"infra/modules/{m}/" for m in sorted(missing_modules))
                for path in sorted(catalog):
                    if path.startswith(prefixes) and path not in updated:
                        updated[path] = catalog[path]
            except Exception as e:
                logger.warning(f"🛡️ Gatekeeper: Failed to run vendor_terraform_modules during curing: {e}")

            # Re-check
            for mod_name in sorted(missing_modules):
                has_files = any(p.startswith(f"infra/modules/{mod_name}/") or p.startswith(f"modules/{mod_name}/") for p in updated.keys())
                if has_files:
                    logger.info(f"✅ Gatekeeper auto-cured missing module vendoring for '{mod_name}'")
                else:
                    errors.append(f"Unvendored module dependency: module '{mod_name}' is referenced in Terraform configuration but could not be resolved or vendored.")

        return updated, errors

    # HB-30 `cure_gce_resource_uris` DELETED (FD-4AD): it rewrote `global/networks/...` literals in any file mentioning
    # compute_v1 into an f-string with an undefined `{project_id}` (NameError at run time). A malformed GCE URI is the
    # Compute API's 400, which the AI's code must handle; nothing rewrites it.

    # HB-23 `cure_service_account_ids` DELETED (FD-55 W4, register FD55-W4): it truncated any account_id over 30
    # characters and rewrote `-prefix` / `-dispatcher` / `-cr-dispatcher` / `-ephemeral-worker` in templated ids at
    # any length (a renamed service account is a replaced one, with its IAM grants). A bad literal id is the
    # provider's ValidateFunc at V1b `tofu validate`; a templated one resolved from platform values is V2k
    # IAC.NAME_INVALID (developer_agent/validators/names.py); the AI fixes it.

    def verify_container_entrypoint_imports(self, files: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
        """
        Shift-Left Container Entrypoint Smoke Test:
        Validates that top-level module imports in main.py for EXTERNAL dependencies
        (standard library modules or PyPI packages declared in requirements.txt)
        are not shadowed by local package subdirectories containing __init__.py.

        FD-4A: a requirement names a distribution, not an import. A requirement counts through the top-level import
        names it installs (gatekeeper_agent/distribution_imports.py: installed metadata, else an explicit table), so
        `PyYAML` covers `import yaml` and `google-cloud-storage` covers `from google.cloud import storage`; requirement
        lines are read by `packaging` (extras, specifiers, markers, comments, pip options). A requirement whose import
        names are unknown is never guessed: a local package whose name equals the requirement's (PEP 503) is blocked
        as before, because the platform cannot rule out that it hides the library.

        FD-4A-b: `import X.sub` / `from X.sub import ...` / `from X import sub` in main.py, where X is an external
        import name (not a namespace package, distribution_imports.NAMESPACE_TOP_LEVELS) and the service has an
        init-less local `X/` holding `sub.py` or `sub/`, is blocked: the installed regular package X wins, so the local
        file cannot be imported (the service fails at boot, or silently gets X's own `sub`).
        """
        errors = []
        services = self.detect_services(files)
        for svc in services:
            main_path = f"apps/{svc}/main.py"
            if main_path not in files:
                continue

            # Top-level import names of the distributions this service declares (service + root requirements.txt)
            texts = [files[r] for r in (f"apps/{svc}/requirements.txt", "requirements.txt")
                     if isinstance(files.get(r), str)]
            external_imports, unknown_dists = requirement_import_roots(texts)

            try:
                tree = ast.parse(files[main_path], filename=main_path)
            except Exception:
                continue

            top_level_imports = set()
            sub_imports = {}   # FD-4A-b: (X, sub) -> the import as written (`X.sub...` or `from X import sub`)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_level_imports.add(alias.name.split(".")[0])
                        if "." in alias.name:
                            parts = alias.name.split(".")
                            sub_imports.setdefault((parts[0], parts[1]), alias.name)
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    top_level_imports.add(node.module.split(".")[0])
                    if "." in node.module:
                        parts = node.module.split(".")
                        sub_imports.setdefault((parts[0], parts[1]), node.module)
                    else:
                        for alias in node.names:
                            if alias.name != "*":
                                sub_imports.setdefault((node.module, alias.name),
                                                       f"from {node.module} import {alias.name}")

            for mod in sorted(top_level_imports):
                shadow_init = f"apps/{svc}/{mod}/__init__.py"
                if shadow_init not in files:
                    continue
                mod_lower = mod.lower()
                # Shadowing only occurs if mod is an external package or a standard library module!
                is_external = (
                    mod in external_imports or
                    mod_lower in CRITICAL_STDLIB_MODULES or
                    mod_lower in STDLIB_MODULES
                )
                if is_external:
                    errors.append(
                        f"Container entrypoint conflict: '{main_path}' imports external module '{mod}', "
                        f"which is shadowed by local package directory 'apps/{svc}/{mod}/'."
                    )
                elif canonical_name(mod) in unknown_dists:
                    errors.append(
                        f"Container entrypoint conflict: '{main_path}' imports '{mod}' from local package directory "
                        f"'apps/{svc}/{mod}/', a requirement of the same name is declared and the platform cannot "
                        f"confirm its import names: rename the local package or remove the requirement."
                    )
                # else: legitimate local subpackage (e.g. routers, schemas, services, models)

            # FD-4A-b: an init-less local `X/` loses to the installed regular package X; its submodules are unreachable
            for (mod, sub), written in sorted(sub_imports.items()):
                if mod not in external_imports or mod in NAMESPACE_TOP_LEVELS:
                    continue
                if f"apps/{svc}/{mod}/__init__.py" in files:
                    continue   # a regular local package: the shadow finding above covers it
                local_sub = f"apps/{svc}/{mod}/{sub}.py"
                sub_dir = f"apps/{svc}/{mod}/{sub}/"
                if local_sub in files or any(p.startswith(sub_dir) for p in files):
                    errors.append(
                        f"Container entrypoint conflict: '{main_path}' imports '{written}' and the service has a "
                        f"local '{mod}.{sub}' under 'apps/{svc}/{mod}/' (no __init__.py), but '{mod}' is an installed "
                        f"external package: the local file cannot be imported: the installed package (or its own "
                        f"module of that name) is imported instead."
                    )
        return files, errors

    # HC-15 `cure_syntax_errors` DELETED (FD-55 W1, register FD55-W1): uncalled since Step 2 S2-A (HS-13); a file that
    # does not parse is PY.SYNTAX and the AI repairs it.

    def verify(self, files: Dict[str, str], *, source: str = "precommit", iteration: int = 0) -> List[Any]:
        """Check-only gatekeeper (Step 1 S1-B V8, register HS-04): the judging half of verify_and_cure with no cures.
        Returns typed Diagnostics (shared.diagnostics.Diagnostic); never mutates `files`. Same rejection reasons as
        today's pre-commit gate: unsafe keys, Python that does not compile, referenced modules not vendored,
        external imports shadowed by local package dirs."""
        from shared.diagnostics import Diagnostic

        def diag(code: str, path: str, message: str, line: Optional[int] = None) -> Diagnostic:
            return Diagnostic(tool="gatekeeper", code=code, severity="error", file=path, line=line,
                              message=message[:2048], source=source, iteration=iteration)

        out: List[Any] = []
        # Every unsafe key is reported by name and the other checks still run (Step 1 code RT F12): the repair loop
        # sends an LLM-written key back to its persona for a rename, and an early return here would hide the other
        # findings until after that rename (they would then look new). The other checks see only the safe keys.
        safe: Dict[str, str] = {}
        for key in sorted(files, key=str):
            try:
                validate_manifest_keys({key: None}, reserved=GIT_RESERVED)
            except UnsafePathError as e:
                out.append(diag("GATE.UNSAFE_PATH_KEY", key if isinstance(key, str) and key else "<unsafe>",
                                f"unsafe path key: {e.value!r} ({e.reason})"))
            else:
                safe[key] = files[key]
        files = safe
        for path in sorted(p for p in files if p.endswith(".py")):
            try:
                compile(files[path], path, "exec", dont_inherit=True)
            except (SyntaxError, ValueError) as e:
                out.append(diag("GATE.PY_COMPILE_ERROR", path, f"Syntax/Compilation Error in '{path}': {e}",
                                getattr(e, "lineno", None)))
        try:
            from developer_agent.assembly import index_blocks
        except ImportError:  # pragma: no cover
            from ..developer_agent.assembly import index_blocks  # type: ignore
        referenced = set()
        for fpath in sorted(files):
            if not fpath.endswith(".tf") or fpath.startswith(("infra/modules/", "modules/")):
                continue
            for b in index_blocks(files[fpath]) or []:  # unparseable file: V1b reports it
                src = (b.body or {}).get("source") if b.kind == "module" else None
                if isinstance(src, str):
                    parts = src.split("/")
                    if len(parts) >= 3 and parts[0] in (".", "..") and parts[1] == "modules":
                        referenced.add((parts[2], fpath))
        for mod_name, fpath in sorted(referenced):
            if not any(p.startswith(f"infra/modules/{mod_name}/") or p.startswith(f"modules/{mod_name}/") for p in files):
                out.append(diag("GATE.UNVENDORED_MODULE", fpath,
                                f"module '{mod_name}' is referenced but not vendored under infra/modules/{mod_name}/"))
        for svc in self.detect_services(dict(files)):
            subset = {k: v for k, v in files.items() if k.startswith(f"apps/{svc}/") or k == "requirements.txt"}
            _, smoke_errors = self.verify_container_entrypoint_imports(subset)
            for msg in smoke_errors:
                out.append(diag("GATE.ENTRYPOINT_SHADOWED", f"apps/{svc}/main.py", msg))
        return out

    def verify_and_cure(
        self,
        files: Dict[str, str],
        product_id: Optional[str] = None,
        *,
        typed_iac: bool = False,
    ) -> Tuple[Dict[str, str], bool, List[str]]:
        """
        Master Gatekeeper Pipeline:
        0. Adds missing package `__init__.py` files (add-only, FD-4AD).
        2. Appends requirements an exact fact proves missing (add-only, FD-4AD).
        3. (FD-55 W5: the container contract twin is deleted; handler.enforce_container_contract is the one rule.)
        4. Reconciles IaC environment contracts between custom.tf and main.tf.
        4b. Adds the files of a referenced module that has none (add-only; FD-55 W8: no `archetype` argument, so
            every caller runs the same cure).
        4c. Shift-Left Container Entrypoint Smoke Test (validates zero module shadowing).
        5. Runs in-memory py_compile validation.
        `typed_iac` (FD55-W2, register TI-4a): a typed-intent run (TI-3) has no AI-authored HCL, so the IaC text cure
        4 does not run (1c, HB-23, is deleted: FD-55 W4).
        Returns: (cured_files, passed: bool, errors: List[str])
        """
        # FD-4G (H5): reject unsafe manifest keys by RETURNING passed=False -- never raise. The pre-commit
        # caller only turns passed=False into a hard RuntimeError; other exceptions are swallowed there.
        try:
            validate_manifest_keys(files, reserved=GIT_RESERVED)
        except UnsafePathError as e:
            msg = f"unsafe path key: {e.value!r} ({e.reason})"
            logger.error(
                f"🛡️ Anti-Hallucination Gatekeeper rejected manifest for "
                f"'{product_id or getattr(self, 'product_id', '')}': {msg}"
            )
            return (dict(files) if isinstance(files, Mapping) else {}), False, [msg]

        if product_id:
            self.product_id = product_id

        logger.info(f"🛡️ Anti-Hallucination Gatekeeper: verifying & curing {len(files)} files for '{self.product_id}'...")

        # Step 0: add-only package scaffolding (FD-4AD: nothing is purged, moved or renamed any more)
        cured, purged_shadows = self.purge_shadowed_package_files(files)

        # Step 0.5 (HC-15 cure_syntax_errors) is no longer called, Step 2 S2-A (register HS-13): a file that does
        # not parse is PY.SYNTAX (V3a) / GATE.PY_COMPILE_ERROR and the AI repairs it. The method stays for the FD-55
        # phase 4 audit only.

        # Step 1 (HB-31/HE-02 cure_imports) and Step 1b (HB-30 cure_gce_resource_uris) DELETED (FD-4AD).

        # Step 1c (HB-23 cure_service_account_ids) DELETED (FD-55 W4; tombstone above verify_container_entrypoint_imports).

        # Step 2: add-only requirements contract (FD-4AD; the HB-28 delete / re-pin / prepend is removed)
        cured = self.reconcile_service_requirements(cured)

        # Step 3 (HB-29 twin enforce_container_contracts) DELETED (FD-55 W5): handler.enforce_container_contract is the
        # one Dockerfile / runtime-pin rule and runs on every assembled tree before this pass.

        # Step 4: IaC Custom Resource Environment Auto-Curing (FD55-W2: not on a typed-intent run)
        if not typed_iac:
            cured = self.reconcile_iac_environment_contracts(cured)

        # Step 4b: IaC Module Auto-Vendoring and Verification
        cured, mod_errors = self.reconcile_iac_module_vendoring(cured)

        # Step 4c: Shift-Left Container Entrypoint Smoke Test
        cured, smoke_errors = self.verify_container_entrypoint_imports(cured)

        # Step 4d (HC-15 final cure_syntax_errors) no longer called, Step 2 S2-A (HS-13); see Step 0.5.

        # Step 5: In-Memory Syntax Compilation Check
        passed, errors = self.compile_in_memory(cured)
        if mod_errors:
            errors.extend(mod_errors)
            passed = False
        if smoke_errors:
            errors.extend(smoke_errors)
            passed = False

        if passed:
            logger.info(f"✅ Gatekeeper: All files compiled and passed container contract verification with zero hallucinations!")
        else:
            logger.warning(f"⚠️ Gatekeeper: Detected {len(errors)} compilation/validation errors: {errors}")

        return cured, passed, errors


# bcd RT F1 `_case_b_edit_is_exact` (python-hcl2 check of the secondary Case B line edit) DELETED with that edit
# (FD-55 W5): developer_agent/sibling_wiring._env_edit_is_exact checks every HB-05 parser edit the same way.

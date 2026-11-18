"""
Project Castor: Enterprise Module Inspector & In-Memory HCL AST Parser
Extracts input and output contracts from variables.tf and outputs.tf.
Supports both Direct HCL string parsing (Zero-Git) and Remote GitHub REST API inspection.
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

logger = logging.getLogger("castor-module-inspector")


def _strip_hcl_comments(hcl_text: str) -> str:
    """Removes single-line (#, //) and multi-line (/* ... */) comments from HCL text."""
    if not hcl_text:
        return ""
    # Remove multi-line comments
    text = re.sub(r'/\*[\s\S]*?\*/', '', hcl_text)
    # Remove single-line comments
    lines = []
    for line in text.splitlines():
        # Strip # and // unless inside quotes
        # Simple heuristic: strip # or // if preceded by whitespace or at start
        cleaned = re.sub(r'(?<!["\'])(?:#|//).*$', '', line)
        lines.append(cleaned)
    return "\n".join(lines)


class HclUnavailable(RuntimeError):
    """python-hcl2 is not importable: module contracts cannot be read (a deployment defect, not a user error)."""


class ModuleContractUnparseable(ValueError):
    """The HCL text cannot be read as a module contract: python-hcl2 rejects it, or a variable/output block has a
    label count Terraform rejects. Never answered with a partial or empty contract (callers must not register one)."""


def _hcl_tree(hcl_text: str):
    """python-hcl2 7.3.1 parse tree (lark, exact character positions) of one file; the same parser and the same
    trailing-newline input as hcl2.loads, so it accepts exactly what the platform's other HCL readers accept."""
    try:
        from hcl2.parser import parser  # python-hcl2==7.3.1 (requirements.txt of every service that ships this file)
    except ImportError as e:  # pragma: no cover - environment
        raise HclUnavailable("python-hcl2 is not installed") from e
    try:
        return parser().parse(hcl_text + "\n")
    except Exception as e:  # noqa: BLE001 - lark raises several exception types for syntax errors
        first_line = (str(e).strip().splitlines() or [""])[0]  # lark appends a long "Expected one of" list
        raise ModuleContractUnparseable(f"HCL could not be parsed: {type(e).__name__}: {first_line}") from e


def _extract_blocks(hcl_text: str, block_type: str) -> List[Tuple[str, str]]:
    """
    (block_name, block_body) for every top-level `block_type` block (e.g. 'variable' or 'output'), in file order.

    Block boundaries come from python-hcl2's parse tree: the body is the exact text between the block's own `{` and
    its closing `}`, comment-stripped and trimmed (the same body text the old regex + brace counter returned for valid
    HCL). Blocks inside strings, heredocs or nested bodies are never returned.

    Empty or whitespace-only text -> []. Text python-hcl2 cannot parse, or a `block_type` block whose label count is
    not exactly one (Terraform rejects it), -> ModuleContractUnparseable for the whole text: never a partial list.
    python-hcl2 missing -> HclUnavailable. CRLF line endings and a leading UTF-8 byte-order mark are normalized
    first (python-hcl2 rejects both; HCL allows them).
    """
    if not hcl_text or not hcl_text.strip():
        return []
    text = hcl_text[1:] if hcl_text.startswith("\ufeff") else hcl_text
    text = text.replace("\r\n", "\n")
    tree = _hcl_tree(text)

    results: List[Tuple[str, str]] = []
    top_body = next((c for c in tree.children if getattr(c, "data", None) == "body"), None)
    for block in (top_body.children if top_body is not None else []):
        if getattr(block, "data", None) != "block":
            continue
        ident, header = block.children[0], block.children[1:-1]
        if text[ident.meta.start_pos:ident.meta.end_pos] != block_type:
            continue
        labels = [c for c in header if getattr(c, "data", None) in ("string", "identifier")]
        if len(labels) != 1:
            raise ModuleContractUnparseable(
                f"{block_type} block at line {block.meta.line} has {len(labels)} labels (Terraform requires 1)")
        label = labels[0]
        raw_label = text[label.meta.start_pos:label.meta.end_pos]
        name = raw_label[1:-1] if label.data == "string" else raw_label
        header_end = (header[-1] if header else ident).meta.end_pos
        # The grammar puts only ignored blanks between the last header child and the block's "{" (an anonymous
        # token lark drops from the tree), and the block's span ends at its "}": both are verified, never guessed.
        open_brace = text.find("{", header_end)
        close_brace = block.meta.end_pos - 1
        if open_brace < 0 or text[header_end:open_brace].strip(" \t") or text[close_brace] != "}":
            raise ModuleContractUnparseable(f"{block_type} block at line {block.meta.line}: no exact body range")
        results.append((name, _strip_hcl_comments(text[open_brace + 1:close_brace]).strip()))
    return results


def _extract_field_value(body: str, field_name: str) -> Optional[str]:
    """Extracts attribute value handling multiline brackets, parens, and braces."""
    m = re.search(rf'\b{field_name}\s*=\s*', body)
    if not m:
        return None
    start = m.end()
    parens = 0
    braces = 0
    brackets = 0
    in_str = False
    escape = False
    i = start
    while i < len(body):
        c = body[i]
        if in_str:
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == '(':
                parens += 1
            elif c == ')':
                parens -= 1
            elif c == '{':
                braces += 1
            elif c == '}':
                braces -= 1
            elif c == '[':
                brackets += 1
            elif c == ']':
                brackets -= 1
            elif c == '\n' and parens == 0 and braces == 0 and brackets == 0:
                break
        i += 1
    val = body[start:i].strip()
    return val if val else None


def parse_hcl_variables_and_outputs(
    variables_hcl: Any,
    outputs_hcl: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parses raw HCL strings (or a dictionary of filename -> content) for variables and outputs into structured dictionaries.
    Zero disk writes, zero subprocess calls, executed in < 50ms.
    """
    if isinstance(variables_hcl, dict):
        hcl_dict = variables_hcl
        var_content = hcl_dict.get("variables.tf", "") or hcl_dict.get("main.tf", "")
        out_content = hcl_dict.get("outputs.tf", "") or hcl_dict.get("main.tf", "")
        variables_hcl = var_content
        outputs_hcl = out_content

    inputs: List[Dict[str, Any]] = []
    outputs: List[Dict[str, Any]] = []

    # 1. Parse variables.tf (block ranges from python-hcl2 on the raw text; each body is comment-stripped)
    var_blocks = _extract_blocks(variables_hcl or "", "variable")

    for var_name, body in var_blocks:
        # Description
        desc_match = re.search(r'description\s*=\s*"([^"]*)"', body)
        description = desc_match.group(1) if desc_match else ""

        # Type with balanced parsing
        raw_type = _extract_field_value(body, "type")
        var_type = "string"
        if raw_type:
            # Flatten formatting
            cleaned_type = re.sub(r'\s+', ' ', raw_type).strip()
            var_type = cleaned_type if cleaned_type else "string"

        # Default value & required check
        has_default = bool(re.search(r'\bdefault\s*=', body))
        default_val = None
        if has_default:
            raw_default = _extract_field_value(body, "default")
            if raw_default is not None:
                if raw_default.lower() in ("true", "false"):
                    default_val = raw_default.lower() == "true"
                elif raw_default.isdigit():
                    default_val = int(raw_default)
                elif raw_default.startswith('"') and raw_default.endswith('"'):
                    default_val = raw_default[1:-1]
                else:
                    default_val = re.sub(r'\s+', ' ', raw_default).strip()

        inputs.append({
            "name": var_name,
            "type": var_type,
            "description": description,
            "required": not has_default,
            "default": default_val,
        })

    # 2. Parse outputs.tf
    out_blocks = _extract_blocks(outputs_hcl or "", "output")

    for out_name, body in out_blocks:
        desc_match = re.search(r'description\s*=\s*"([^"]*)"', body)
        description = desc_match.group(1) if desc_match else ""
        outputs.append({
            "name": out_name,
            "description": description,
        })

    return inputs, outputs


def parse_github_repo_identifier(source_url: str) -> str:
    """
    Normalizes URLs like:
      - https://github.com/acme/tf-modules.git
      - https://github.com/acme/tf-modules
      - git@github.com:acme/tf-modules.git
      - acme/tf-modules
    into 'acme/tf-modules'.
    """
    cleaned = (source_url or "").strip()
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]

    # Handle git@github.com:owner/repo
    if ":" in cleaned and "@" in cleaned:
        cleaned = cleaned.split(":")[-1]

    # Handle https://github.com/owner/repo
    match = re.search(r'github\.com/([^/]+/[^/]+)', cleaned)
    if match:
        return match.group(1)

    # If it's already 'owner/repo'
    parts = cleaned.strip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"

    return cleaned


def fetch_and_inspect_github_module(
    source_url: str,
    repo_path: str = "",
    version_tag: str = "main",
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Fetches variables.tf and outputs.tf from a GitHub repository via the GitHub REST Contents API
    and parses their contracts in-memory. Zero git clone overhead.
    """
    repo_id = parse_github_repo_identifier(source_url)
    clean_path = (repo_path or "").strip().strip("/")

    vars_path = f"{clean_path}/variables.tf" if clean_path else "variables.tf"
    outs_path = f"{clean_path}/outputs.tf" if clean_path else "outputs.tf"

    from shared.vcs_provider import VCSProviderFactory

    try:
        provider = VCSProviderFactory.get_provider("GITHUB")
    except Exception as e:
        logger.warning(f"Could not load GitHub VCS provider: {e}")
        raise ValueError(f"GitHub VCS provider unavailable: {e}")

    # Fetch variables.tf
    vars_content = ""
    try:
        vars_content = provider.fetch_file_content(repo_id, vars_path, branch=version_tag) or ""
    except Exception as e:
        logger.warning(f"Could not fetch {vars_path} from {repo_id}@{version_tag}: {e}")
        raise ValueError(f"Could not fetch '{vars_path}' from repository '{repo_id}' at ref '{version_tag}': {e}")

    # Fetch outputs.tf (optional, does not fail if missing)
    outs_content = ""
    try:
        outs_content = provider.fetch_file_content(repo_id, outs_path, branch=version_tag) or ""
    except Exception as e:
        logger.info(f"Optional {outs_path} not found in {repo_id}@{version_tag}: {e}")

    return parse_hcl_variables_and_outputs(vars_content, outs_content)


BUNDLE_SOURCE_HOST = "github.com"  # bundles are read with the GitHub provider only


def _split_bundle_scheme_url(raw: str) -> Tuple[str, str, Optional[str]]:
    """Scheme URL (``https://github.com/org/repo(.git)[//subdir][?ref=x]``, optional ``git::`` prefix).

    Parsed with ``urllib.parse``; the host must be exactly ``github.com`` and the path before ``//``
    exactly ``<owner>/<repo>``, otherwise ``ValueError`` (the bundle would be read from a different
    repository than the one typed). Returns ``(owner/repo, subdir, ref or None)``.
    """
    url = raw[len("git::"):] if raw.lower().startswith("git::") else raw
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme.lower() not in ("https", "http", "ssh", "git") or host != BUNDLE_SOURCE_HOST:
        raise ValueError(
            f"Only GitHub bundle sources are supported: '{raw}' has host '{host or '?'}' "
            f"(scheme '{parts.scheme}'); expected https://{BUNDLE_SOURCE_HOST}/<owner>/<repo>."
        )
    path = parts.path
    sep = path.find("//")
    repo_path, subpath = (path[:sep], path[sep + 2:].strip("/")) if sep != -1 else (path, "")
    segs = [x for x in repo_path.strip("/").split("/") if x]
    if len(segs) != 2:
        raise ValueError(
            f"Bundle source '{raw}' must name exactly one repository: "
            f"https://{BUNDLE_SOURCE_HOST}/<owner>/<repo>[.git][//subdir][?ref=x]."
        )
    owner, repo = segs
    if repo.endswith(".git"):
        repo = repo[:-4]
    query = parse_qs(parts.query)
    refs = query.get("ref") or query.get("version") or []
    return f"{owner}/{repo}", subpath, (refs[0].strip() or None) if refs else None


def _split_bundle_source(source_url: str) -> Tuple[str, str, Optional[str]]:
    """Like ``parse_bundle_source_url`` but the ref is ``None`` when the URL names none."""
    raw = (source_url or "").strip()
    if "://" in raw:
        return _split_bundle_scheme_url(raw)

    ref = None

    # Extract ?ref= or ?version=
    if "?ref=" in raw:
        raw, ref = raw.split("?ref=", 1)
    elif "?version=" in raw:
        raw, ref = raw.split("?version=", 1)

    subpath = ""
    # Extract //subdirectory
    if "//" in raw:
        repo_part, subpath = raw.split("//", 1)
        subpath = subpath.strip("/")
    else:
        repo_part = raw

    repo_id = parse_github_repo_identifier(repo_part)
    return repo_id, subpath, ref


def parse_bundle_source_url(source_url: str) -> Tuple[str, str, str]:
    """
    Parses universal Terraform Git source notation or standard URLs:
      - github.com/org/repo//bundles/secure-three-tier-web?ref=v1.2.0
      - https://github.com/org/repo.git//bundles/my-bundle
      - org/repo
    Returns: (repo_identifier, bundle_subpath, ref) -- ref is 'main' when the URL names none.
    A URL with a scheme must be on github.com (``ValueError`` otherwise).
    """
    repo_id, subpath, ref = _split_bundle_source(source_url)
    return repo_id, subpath, ref if ref is not None else "main"


def _resolve_bundle_ref(source_url: str, url_ref: Optional[str], version_tag: Optional[str]) -> str:
    """The Git ref to read: the explicit ``version_tag``, else the URL's ``?ref=``, else 'main'.

    Both given and different -> ``ValueError`` (never silently read a different ref than the URL names).
    """
    explicit = (version_tag or "").strip() or None
    if explicit and url_ref and explicit != url_ref:
        raise ValueError(
            f"Git ref conflict: source URL '{source_url}' names ref '{url_ref}' but version_tag is "
            f"'{explicit}'. Set only one of them, or make them equal."
        )
    return explicit or url_ref or "main"


def fetch_and_inspect_git_bundle(
    source_url: str,
    repo_path: str = "",
    version_tag: Optional[str] = None,
    known_golden_modules: Optional[List[str]] = None,
    project_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Git-native bundle inspector:
    1. Fetches main.tf, variables.tf, outputs.tf, and optional bundle.yaml.
    2. Validates HCL syntax and extracts variables & outputs.
    3. Guardrail 6: Cross-checks all module 'source' references against known Golden Modules.
    4. Auto-discovers metadata and resource footprint if bundle.yaml is missing.

    ``repo_path`` is the bundle's subdirectory inside the repository (overrides a ``//subdir`` in
    ``source_url``). ``project_id`` is the host project whose Secret Manager holds the GitHub
    token; when empty the provider resolves it itself (platform settings, then ``PROJECT_ID``).
    ``version_tag``: explicit ref; ``None`` = the URL's ``?ref=``, else 'main' (conflict -> ValueError).
    The returned ``version_tag`` is the ref actually read.
    """
    parsed_repo, parsed_path, parsed_ref = _split_bundle_source(source_url)
    repo_id = parsed_repo or source_url
    clean_path = (repo_path or parsed_path or "").strip().strip("/")
    ref = _resolve_bundle_ref(source_url, parsed_ref, version_tag)

    from shared.vcs_provider import VCSProviderFactory

    try:
        provider = VCSProviderFactory.get_provider("GITHUB", **({"project_id": project_id} if project_id else {}))
    except Exception as e:
        logger.warning(f"Could not load VCS provider: {e}")
        raise ValueError(f"Git VCS provider unavailable: {e}")

    main_path = f"{clean_path}/main.tf" if clean_path else "main.tf"
    vars_path = f"{clean_path}/variables.tf" if clean_path else "variables.tf"
    outs_path = f"{clean_path}/outputs.tf" if clean_path else "outputs.tf"
    yaml_path = f"{clean_path}/bundle.yaml" if clean_path else "bundle.yaml"

    # 1. Fetch main.tf (Mandatory)
    try:
        main_content = provider.fetch_file_content(repo_id, main_path, branch=ref) or ""
    except Exception as e:
        raise ValueError(f"Could not fetch mandatory '{main_path}' from '{repo_id}@{ref}': {e}")

    if not main_content:
        raise ValueError(f"Bundle directory '{clean_path}' does not contain 'main.tf'.")

    # 2. Fetch variables.tf (Mandatory)
    try:
        vars_content = provider.fetch_file_content(repo_id, vars_path, branch=ref) or ""
    except Exception as e:
        raise ValueError(f"Could not fetch mandatory '{vars_path}' from '{repo_id}@{ref}': {e}")

    # 3. Fetch outputs.tf (Optional)
    outs_content = ""
    try:
        outs_content = provider.fetch_file_content(repo_id, outs_path, branch=ref) or ""
    except Exception:
        pass

    # 4. Fetch bundle.yaml (Optional)
    yaml_content = ""
    try:
        yaml_content = provider.fetch_file_content(repo_id, yaml_path, branch=ref) or ""
    except Exception:
        pass

    # Extract inputs and outputs
    inputs, outputs = parse_hcl_variables_and_outputs(vars_content, outs_content)

    # Detect modules invoked in main.tf
    module_invocations = re.findall(r'module\s+"([^"]+)"\s*\{[^}]*source\s*=\s*"([^"]+)"', main_content, re.DOTALL)
    modules_included: List[str] = []
    
    # Guardrail 6: Missing Dependency Fast-Fail Validation Gate
    golden_set = set(known_golden_modules or [])
    for mod_label, mod_source in module_invocations:
        clean_src = mod_source.strip()
        # Relative module references
        if clean_src.startswith("./") or clean_src.startswith("../"):
            mod_name = os.path.basename(clean_src.rstrip("/"))
            modules_included.append(mod_name)
            if golden_set and mod_name not in golden_set:
                # Check if it's an in-tree submodule under bundle path
                if not (clean_src.startswith("./submodules/") or clean_src.startswith("./")):
                    raise ValueError(
                        f"Validation Error: Bundle references module '{mod_name}' (source = '{mod_source}') "
                        f"which does not exist in StackVend's Golden Modules catalog or bundle submodules."
                    )
        elif not clean_src.startswith("git::") and not clean_src.startswith("http"):
            # Registry module
            modules_included.append(os.path.basename(clean_src.rstrip("/")))

    # Auto-infer bundle ID from folder or repo
    inferred_id = os.path.basename(clean_path) if clean_path else os.path.basename(repo_id)
    inferred_id = re.sub(r'[^a-zA-Z0-9_-]', '-', inferred_id).strip("-").lower()

    # Parse bundle.yaml metadata if present
    parsed_metadata: Dict[str, Any] = {}
    if yaml_content:
        try:
            import yaml
            parsed_metadata = yaml.safe_load(yaml_content) or {}
        except Exception as ye:
            logger.debug(f"Could not parse bundle.yaml: {ye}")

    bundle_id = parsed_metadata.get("bundle_id") or inferred_id
    name = parsed_metadata.get("name") or bundle_id.replace("-", " ").title()
    description = parsed_metadata.get("description") or f"Custom Git Solution Bundle from {repo_id}"
    supported_engines = parsed_metadata.get("supported_engines") or ["tofu", "terraform"]
    default_engine = parsed_metadata.get("default_engine") or "tofu"
    category = parsed_metadata.get("category") or "COMPUTE_DATA"
    resource_footprint = parsed_metadata.get("resource_footprint") or {
        "cpus": 2,
        "memory_gb": 4,
        "subnets": 1 if any("vpc" in m for m in modules_included) else 0,
        "static_ips": 1 if any("cloudrun" in m or "gke" in m for m in modules_included) else 0,
    }
    default_parameters = parsed_metadata.get("default_parameters") or {}

    hcl_files = {
        "main.tf": main_content,
        "variables.tf": vars_content,
    }
    if outs_content:
        hcl_files["outputs.tf"] = outs_content

    return {
        "bundle_id": bundle_id,
        "name": name,
        "category": category,
        "description": description,
        "source_url": repo_id,
        "repo_path": clean_path,
        "version_tag": ref,
        "supported_engines": supported_engines,
        "default_engine": default_engine,
        "modules_included": list(dict.fromkeys(modules_included)),
        "resource_footprint": resource_footprint,
        "default_parameters": default_parameters,
        "variables": inputs,
        "outputs": outputs,
        "hcl_files": hcl_files,
        "has_manifest": bool(yaml_content),
    }


def scan_repository_git_bundles(
    source_url: str,
    parent_path: str = "bundles",
    version_tag: Optional[str] = None,
    project_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Guardrail 3: Uses a single recursive Git Trees API call to scan an entire monorepo
    folder and detect all subdirectories containing both main.tf and variables.tf.
    Eliminates sequential HTTP request rate-limiting.
    ``project_id``: as in ``fetch_and_inspect_git_bundle`` (GitHub token project; empty = provider default).
    ``version_tag``: as in ``fetch_and_inspect_git_bundle`` (explicit ref; ``None`` = URL ref, else 'main').
    """
    parsed_repo, parsed_path, parsed_ref = _split_bundle_source(source_url)
    repo_id = parsed_repo or source_url
    search_dir = (parent_path or parsed_path or "bundles").strip().strip("/")
    ref = _resolve_bundle_ref(source_url, parsed_ref, version_tag)

    from shared.vcs_provider import VCSProviderFactory

    try:
        provider = VCSProviderFactory.get_provider("GITHUB", **({"project_id": project_id} if project_id else {}))
    except Exception as e:
        logger.warning(f"Could not load VCS provider: {e}")
        raise ValueError(f"Git VCS provider unavailable: {e}")

    # Fetch all file paths in branch via existing single-call provider
    all_files = provider.fetch_existing_repo_files(repo_id, branch=ref, max_files=2000)
    file_paths = set(all_files.keys())

    # Find directories under search_dir that have both main.tf and variables.tf
    candidate_dirs = set()
    for fp in file_paths:
        if fp.endswith("/main.tf") or fp.endswith("/variables.tf"):
            dir_name = os.path.dirname(fp)
            if not search_dir or dir_name.startswith(search_dir):
                candidate_dirs.add(dir_name)

    discovered: List[Dict[str, Any]] = []
    for d in sorted(candidate_dirs):
        has_main = f"{d}/main.tf" in file_paths
        has_vars = f"{d}/variables.tf" in file_paths
        has_yaml = f"{d}/bundle.yaml" in file_paths or f"{d}/castor-bundle.yaml" in file_paths

        if has_main and has_vars:
            main_code = all_files.get(f"{d}/main.tf", "")
            mods = re.findall(r'module\s+"([^"]+)"', main_code)
            bid = os.path.basename(d).lower().replace("_", "-")
            discovered.append({
                "bundle_id": bid,
                "name": bid.replace("-", " ").title(),
                "repo_path": d,
                "has_manifest": has_yaml,
                "modules_detected": list(dict.fromkeys(mods)),
                "supported_engines": ["tofu", "terraform"],
                "description": f"Detected composite bundle at '{d}' with {len(mods)} submodules.",
            })

    return discovered


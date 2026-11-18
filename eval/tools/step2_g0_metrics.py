#!/usr/bin/env python3
"""S2-0 / G0 metrics over a `--dump-trees` results directory (Step 2 plan §2.1 S2-0, §3.3, §3.4 gate, §4 G0).

    python eval/tools/step2_g0_metrics.py <results_dir> [--product-root <checkout>]

Reads `<results_dir>/runs/<key>/result.json` and the run's content-addressed trees (`tree_dumps`), writes
`<results_dir>/step2_g0_metrics.json` + `.md` and prints the markdown. Read-only on the product: no product module is
imported. Where product logic is needed it is either loaded from the product source by AST extraction (the exact
function/table text, exec'd in an isolated namespace with no imports of product modules) or replicated verbatim:

  * `extract_apis_from_hcl` + `GCP_RESOURCE_TO_API_MAP` + `GCP_MODULE_TO_API_MAP` (mcp-servers/terraform/service.py)
    -> AST-extracted (today's apply-side `batchEnable` set). Its input is replicated from the consumer
    (service.py ~:6091-6114): every .tf/.tf.json and .yaml/.yml file of the assembled tree, skipping the consumer's
    IGNORED_SCAN_DIRS. Assumption: the apply workspace holds the assembled tree's files (C4 = prepare_workspace on the
    committed tree); files prepare_workspace itself adds (backend.tf, tfvars) carry no resource types.
  * the vending base API list (apps/project-vending/vending.py `foundation_apis = [...]`) -> AST-extracted literal.
  * foundation `base_apis` default -> parsed with python-hcl2 from the tree's vendored
    infra/modules/workload-foundation/base/variables.tf (product checkout copy if the tree has none).
  * HB-05 `extract_custom_resource_env_vars` + `extract_hcl_blocks` (developer_agent/terraform_engine.py) ->
    AST-extracted and called on the final custom.tf with `caller_service` = the module's service_name (the verifier
    twin's call, verifier.py:659) to confirm which sibling keys the product binds. On an S2-D product the sibling
    section is `developer_agent/sibling_wiring.py`: it and its pure dependencies (env_reads, assembly,
    workload_inventory) are exec'd whole in isolated namespaces (`_exec_module_isolated`), never imported.
  * HB-05's "keys the code reads" collector (terraform_engine.py :1284-1316: caller file selection by
    `f"apps/{svc}/" in path.replace("_","-").lower()`, the all-files fallback, `.get`/`.getenv` with a string first
    argument on ANY object, and EVERY string-constant subscript) is inline in that function, so it is REPLICATED
    verbatim in `old_collector()`; each counted key is tagged with the form it was seen in.
  * HB-05's sibling binding rules (:1269-1277 discovery, :1379-1396 unconditional <TOKEN>_URL/_AUDIENCE, shared
    noun, generic aliases) are replicated in `binding_rules()` for attribution only.

HCL structure comes from python-hcl2's lark parse tree (`hcl2.parses`): traversals, object keys and literals are
read from grammar nodes, so comments and string literals never count as references (no substring search).
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

EVAL_DIR = Path(__file__).resolve().parents[1]
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from stackvend_eval.assembly_metrics import golden_module_mutations  # noqa: E402
from stackvend_eval.blobs import BlobStore  # noqa: E402
from stackvend_eval.metrics import fallback_sites  # noqa: E402
from stackvend_eval.env_reads import (FORM_ENVIRON_GET, FORM_ENVIRON_SUBSCRIPT,  # noqa: E402
                                      FORM_IMPORTED_ENVIRON_GET, FORM_IMPORTED_ENVIRON_SUBSCRIPT, FORM_OS_GETENV,
                                      EnvReads, _environ_kind, _os_names, exact_env_reads_files)
from stackvend_eval.paths import CONFIG_DIR, REPO_ROOT, add_deps_to_path  # noqa: E402

WORKLOAD = "infra/workload/"
SINGLE_TURN_SITE_SUFFIX = "DeveloperAgent.generate_code_files"
CLOUD_RUN_MODULE_DIR = "compute-cloudrun"
URI_SUFFIXES = ("_URL", "_URI", "_ENDPOINT", "_AUDIENCE")
IGNORED_SCAN_DIRS = {".git", ".terraform", ".venv", "__pycache__", "node_modules", "dist", "build"}
GENERIC_ALIASES = ("DOWNSTREAM_URL", "TARGET_SERVICE_URL", "DOWNSTREAM_SERVICE_URL", "BACKEND_URL", "CORE_SERVICE_URL")
NOUN_STOP = ("SERVICE", "APP", "CR", "CLOUDRUN")

OLD_FORM_GET_OTHER = ".get on another object"
OLD_FORM_GETENV_OTHER = ".getenv on another object"
OLD_FORM_SUBSCRIPT_OTHER = "non-environ subscript"
OLD_FORM_ENVIRON_WRITE = "environ subscript write"


# ==== HCL (python-hcl2 lark tree) ==============================================================================

def hcl_parse(text: str) -> Any:
    add_deps_to_path()
    import hcl2
    return hcl2.parses(text)


def _data(n: Any) -> Optional[str]:
    return getattr(n, "data", None)


def _trees(n: Any) -> List[Any]:
    return [c for c in getattr(n, "children", []) if _data(c) is not None]


def _ident(n: Any) -> Optional[str]:
    if _data(n) == "identifier" and n.children:
        return str(n.children[0])
    return None


def _unwrap(expr: Any) -> Any:
    """expr_term with exactly one sub-tree (and only punctuation tokens otherwise) -> that sub-tree."""
    while _data(expr) == "expr_term":
        kids = _trees(expr)
        if len(kids) != 1:
            return expr
        tokens = [c for c in expr.children if _data(c) is None]
        if tokens:   # parenthesised expression: keep unwrapping, parentheses do not change the value
            pass
        expr = kids[0]
    return expr


def literal_string(expr: Any) -> Optional[str]:
    """The text of a string literal without interpolation, else None."""
    n = _unwrap(expr)
    if _data(n) != "string":
        return None
    out = []
    for part in n.children:
        if _data(part) != "string_part":
            if _data(part) is None:
                continue
            return None
        for c in part.children:
            if _data(c) is not None:      # interpolation / directive
                return None
            out.append(str(c))
    return "".join(out)


def literal_bool(expr: Any) -> Optional[bool]:
    n = _unwrap(expr)
    name = _ident(n)
    if name in ("true", "false"):
        return name == "true"
    if _data(n) is None and str(n) in ("true", "false"):
        return str(n) == "true"
    for c in getattr(n, "children", []):
        if _data(c) is None and str(c) in ("true", "false") and len(n.children) == 1:
            return str(c) == "true"
    return None


def iter_blocks(body: Any) -> Iterator[Tuple[str, List[str], Any]]:
    """(block type, labels, body) of the direct child blocks of a body (or of the start node)."""
    if _data(body) == "start":
        body = next((c for c in _trees(body) if _data(c) == "body"), None)
    for b in _trees(body) if body is not None else []:
        if _data(b) != "block":
            continue
        kids = _trees(b)
        if not kids:
            continue
        btype = _ident(kids[0])
        labels: List[str] = []
        inner = None
        for k in kids[1:]:
            if _data(k) == "body":
                inner = k
                break
            lab = _ident(k) if _data(k) == "identifier" else literal_string(k)
            labels.append(lab if lab is not None else "")
        yield btype or "", labels, inner


def attributes(body: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for a in _trees(body) if body is not None else []:
        if _data(a) == "attribute":
            kids = _trees(a)
            if len(kids) >= 2 and _ident(kids[0]) is not None:
                out[_ident(kids[0])] = kids[-1]
    return out


def walk(n: Any, attr_stack: Tuple[str, ...] = ()) -> Iterator[Tuple[Any, Tuple[str, ...]]]:
    """Every tree node with the names of the enclosing attributes (outermost first)."""
    if _data(n) is None:
        return
    yield n, attr_stack
    if _data(n) == "attribute":
        kids = _trees(n)
        name = _ident(kids[0]) if kids else None
        for k in kids[1:]:
            yield from walk(k, attr_stack + ((name or ""),))
        return
    for c in n.children:
        yield from walk(c, attr_stack)


def root_refs(n: Any, root: str) -> List[Tuple[str, Tuple[str, ...], Any]]:
    """Every `<root>.<name>` traversal under n (exact grammar nodes): [(name, enclosing attributes, node)]."""
    out = []
    for node, stack in walk(n):
        if _data(node) != "get_attr_expr_term":
            continue
        kids = _trees(node)
        if len(kids) < 2 or _data(kids[0]) != "expr_term" or _data(kids[1]) != "get_attr":
            continue
        base = _trees(kids[0])
        if len(base) == 1 and _ident(base[0]) == root and len(kids[0].children) == 1:
            name = next((_ident(c) for c in _trees(kids[1]) if _ident(c) is not None), None)
            if name is not None:
                out.append((name, stack, node))
    return out


def traversal(expr: Any) -> Optional[List[str]]:
    """`a.b.c` -> ['a', 'b', 'c']; anything else (index, splat, call, literal) -> None."""
    n = _unwrap(expr)
    if _ident(n) is not None:
        return [_ident(n)]
    if _data(n) == "get_attr_expr_term":
        kids = _trees(n)
        if len(kids) == 2 and _data(kids[1]) == "get_attr":
            base = traversal(kids[0])
            name = next((_ident(c) for c in _trees(kids[1]) if _ident(c) is not None), None)
            if base is not None and name is not None:
                return base + [name]
    return None


def object_elems(n: Any) -> Iterator[Tuple[Optional[str], Any]]:
    """(literal key, value expr) of every object element under n."""
    for node, _ in walk(n):
        if _data(node) != "object_elem":
            continue
        kids = _trees(node)
        if len(kids) < 2:
            continue
        key_node = kids[0]
        key = None
        if _data(key_node) == "object_elem_key":
            kk = _trees(key_node)
            if len(kk) == 1:
                key = _ident(kk[0]) if _data(kk[0]) == "identifier" else literal_string(kk[0])
        yield key, kids[-1]


def is_local_source(src: Optional[str]) -> bool:
    return isinstance(src, str) and src.startswith(("./", "../")) and "${" not in src


def module_dir(src: Optional[str]) -> Optional[str]:
    if not is_local_source(src):
        return None
    parts = [p for p in src.split("/") if p not in ("", ".")]
    return parts[-1] if parts else None


def root_tf(tree: Dict[str, str]) -> Dict[str, str]:
    return {p: t for p, t in tree.items() if p.startswith(WORKLOAD) and "/" not in p[len(WORKLOAD):]
            and (p.endswith(".tf") or p.endswith(".tf.json"))}


def parse_all(files: Dict[str, str]) -> Tuple[Dict[str, Any], Dict[str, str]]:
    ok, bad = {}, {}
    for p, t in sorted(files.items()):
        if not p.endswith(".tf"):
            continue
        try:
            ok[p] = hcl_parse(t)
        except Exception as e:  # noqa: BLE001 - python-hcl2 rejects some valid HCL: structure unavailable
            bad[p] = f"{type(e).__name__}: {str(e).splitlines()[0][:160] if str(e) else ''}"
    return ok, bad


# ==== product source loaders (AST extraction, no product import) ==============================================

def _extract_defs(src_path: Path, names: Set[str], extra_ns: Dict[str, Any]) -> Dict[str, Any]:
    tree = ast.parse(src_path.read_text())
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names:
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in node.targets):
            nodes.append(node)
    found = {getattr(n, "name", None) or n.targets[0].id for n in nodes}
    missing = names - found
    if missing:
        raise RuntimeError(f"{src_path}: definitions not found: {sorted(missing)}")
    mod = ast.Module(body=nodes, type_ignores=[])
    import re
    import typing
    ns: Dict[str, Any] = {"re": re, "ast": ast, "Dict": typing.Dict, "List": typing.List,
                          "Optional": typing.Optional, "Any": typing.Any, "Tuple": typing.Tuple, "Set": typing.Set}
    ns.update(extra_ns)
    exec(compile(mod, str(src_path), "exec"), ns)  # noqa: S102 - exact product text, isolated namespace
    _assert_globals_resolved(src_path, [ns[n] for n in sorted(names) if callable(ns[n])], ns)
    return ns


def _global_names(code: Any) -> Set[str]:
    """Global names a code object (and every nested code object) loads or stores (LOAD_GLOBAL / LOAD_NAME /
    STORE_GLOBAL / DELETE_GLOBAL), read from the bytecode. `co_names` alone also holds attribute names."""
    import dis
    out: Set[str] = set()
    for ins in dis.get_instructions(code):
        if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME", "STORE_GLOBAL", "DELETE_GLOBAL"):
            out.add(str(ins.argval).replace(" + NULL", "").replace("NULL + ", ""))
    for const in code.co_consts:
        if hasattr(const, "co_code"):
            out |= _global_names(const)
    return out


def _assert_globals_resolved(src_path: Path, objs: List[Any], ns: Dict[str, Any]) -> None:
    """Code RT F8: every global an extracted product function uses must exist in the isolated namespace, so a new
    module-level dependency fails loudly here instead of raising NameError inside a broad `except` of the product
    function (e.g. extract_custom_resource_env_vars) and under-counting silently."""
    import builtins
    known = set(ns) | set(dir(builtins))
    for obj in objs:
        code = getattr(obj, "__code__", None)
        if code is None:
            continue
        free = _global_names(code) - known
        if free:
            raise RuntimeError(f"{src_path}: {obj.__name__} uses names outside the extracted namespace: {sorted(free)}")


def load_required_apis(product_root: Path) -> Optional[Callable[..., Any]]:
    """S2-C: the terraform server's copy of shared/api_requirements.py (a stdlib-only module that imports python-hcl2
    and PyYAML lazily), loaded by file path; None for a product root from before S2-C."""
    path = product_root / "mcp-servers" / "terraform" / "shared" / "api_requirements.py"
    if not path.is_file():
        return None
    import importlib.util
    add_deps_to_path()
    name = f"g0_api_requirements_{abs(hash(str(path)))}"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod          # dataclasses resolve their module through sys.modules
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return sys.modules[name].required_apis


def load_extract_apis(product_root: Path) -> Callable[..., List[str]]:
    src = product_root / "mcp-servers" / "terraform" / "service.py"
    required = load_required_apis(product_root)
    if required is not None and "_legacy_extract_apis_from_text" in src.read_text():
        # S2-C C1b product: extract_apis_from_hcl = required_apis + the per-file legacy remainder; same exact text,
        # with the shared table function and a quiet logger in the isolated namespace.
        import logging
        quiet = logging.getLogger("stackvend-eval-g0-quiet")
        quiet.addHandler(logging.NullHandler())
        quiet.propagate = False
        ns = _extract_defs(src, {"GCP_RESOURCE_TO_API_MAP", "GCP_MODULE_TO_API_MAP", "_LEGACY_K8S_SIGNATURES",
                                 "_legacy_extract_apis_from_text", "extract_apis_from_hcl"},
                           {"required_apis": required, "logger": quiet})
        return ns["extract_apis_from_hcl"]
    ns = _extract_defs(src, {"GCP_RESOURCE_TO_API_MAP", "GCP_MODULE_TO_API_MAP", "extract_apis_from_hcl"}, {})
    return ns["extract_apis_from_hcl"]


def _import_ladder_names(node: ast.AST) -> Optional[Set[str]]:
    """Names bound by a top-level `try: from .x import a / except ImportError: from x import a ...` ladder (every
    statement an import), else None."""
    if not isinstance(node, ast.Try):
        return None
    stmts = list(node.body) + [s for h in node.handlers for s in h.body]
    names: Set[str] = set()
    for s in stmts:
        if isinstance(s, (ast.Import, ast.ImportFrom)):
            names |= {a.asname or a.name.split(".")[0] for a in s.names}
        elif isinstance(s, ast.Try):
            inner = _import_ladder_names(s)
            if inner is None:
                return None
            names |= inner
        else:
            return None
    return names


def _exec_module_isolated(src_path: Path, provided: Dict[str, Any]) -> Dict[str, Any]:
    """Exec a whole product module in an isolated namespace: its top-level product-import ladders (S2-D style
    `try: from .x import ...`) are replaced by `provided` (every imported name must be provided, else RuntimeError);
    stdlib imports stay. Used for small pure product modules (sibling_wiring, env_reads, assembly, inventory)."""
    import types
    tree = ast.parse(src_path.read_text())
    body = []
    for node in tree.body:
        names = _import_ladder_names(node)
        if names is None:
            if isinstance(node, ast.ImportFrom) and node.level:
                names = {a.asname or a.name for a in node.names}
            else:
                body.append(node)
                continue
        missing = names - set(provided)
        if missing:
            raise RuntimeError(f"{src_path}: product imports not provided to the isolated namespace: {sorted(missing)}")
    name = f"_stackvend_eval_isolated_{src_path.stem}"
    mod = types.ModuleType(name)
    mod.__dict__.update(provided)
    sys.modules[name] = mod          # dataclasses resolve string annotations through sys.modules[cls.__module__]
    try:
        exec(compile(ast.Module(body=body, type_ignores=[]), str(src_path), "exec"), mod.__dict__)  # noqa: S102
    finally:
        sys.modules.pop(name, None)
    return mod.__dict__


def load_hb05(product_root: Path) -> Callable[..., Dict[str, str]]:
    dev = product_root / "apps" / "orchestrator-gateway" / "developer_agent"
    extra: Dict[str, Any] = {}
    if (dev / "sibling_wiring.py").is_file():
        # S2-D product: HB-05's sibling section is sibling_wiring.plan_sibling_wiring (exact env reads, exact source).
        er = _exec_module_isolated(dev / "env_reads.py", {})
        asm = _exec_module_isolated(dev / "assembly.py", {})
        inv = _exec_module_isolated(dev / "workload_inventory.py", {})
        sw = _exec_module_isolated(dev / "sibling_wiring.py", {
            "index_blocks": asm["index_blocks"], "HclUnavailable": asm["HclUnavailable"], "env_reads": er["env_reads"],
            "detect_workload_services": inv["detect_workload_services"]})
        extra = {"plan_sibling_wiring": sw["plan_sibling_wiring"],
                 # FD-4Y HB-02 product: extract_hcl_blocks is built on assembly.index_blocks / block_text.
                 "index_blocks": asm["index_blocks"], "block_text": asm["block_text"],
                 # FD-4Y RT F6 product: extract_hcl_blocks reads the skip count (absent on older product roots).
                 "index_blocks_with_skipped": asm.get("index_blocks_with_skipped")}
    names = {"extract_hcl_blocks", "extract_custom_resource_env_vars"}
    te_src = dev / "terraform_engine.py"
    if any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_EXTRACTED_BLOCK_KINDS"
                                             for t in n.targets) for n in ast.parse(te_src.read_text()).body):
        names.add("_EXTRACTED_BLOCK_KINDS")  # HB-02 product (older product roots predate it)
    ns = _extract_defs(te_src, names, extra)
    return ns["extract_custom_resource_env_vars"]


def load_vending_apis(product_root: Path) -> List[str]:
    """The APIs vending enables. Older product roots: the literal `foundation_apis = [...]`. VEND-API-TABLE (10-27):
    the literal tuple `VENDING_BASELINE_APIS = (...)` plus base_apis + foundation_base_apis of the service's copy of
    the API table (apps/project-vending/shared/api_requirements.json), in vending's request order."""
    vdir = product_root / "apps" / "project-vending"
    tree = ast.parse((vdir / "vending.py").read_text())
    for name, kind in (("foundation_apis", ast.List), ("VENDING_BASELINE_APIS", ast.Tuple)):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name
                                                    for t in node.targets) and isinstance(node.value, kind):
                vals = [e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if len(vals) != len(node.value.elts):
                    continue
                if name == "VENDING_BASELINE_APIS":
                    table = json.loads((vdir / "shared" / "api_requirements.json").read_text())
                    vals += [a for a in sorted(set(table["base_apis"]) | set(table["foundation_base_apis"]))
                             if a not in vals]
                return vals
    raise RuntimeError("vending.py: literal `foundation_apis = [...]` / `VENDING_BASELINE_APIS = (...)` not found")


def base_apis_from_text(text: str) -> Optional[List[str]]:
    add_deps_to_path()
    import hcl2
    doc = hcl2.loads(text)
    for entry in doc.get("variable", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("base_apis"), dict):
            d = entry["base_apis"].get("default")
            if isinstance(d, list):
                return [str(x) for x in d]
    return None


def tfvars_additional_apis(text: Optional[str]) -> Tuple[List[str], Optional[str]]:
    if not text:
        return [], None
    add_deps_to_path()
    import hcl2
    try:
        doc = hcl2.loads(text)
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}"
    v = doc.get("additional_apis")
    return ([str(x) for x in v] if isinstance(v, list) else []), None


# ==== metric 1: single-turn calls ==============================================================================

def single_turn_calls(result: Dict[str, Any]) -> int:
    return sum(1 for c in ((result.get("llm") or {}).get("per_call") or [])
               if str(c.get("site") or "").endswith(SINGLE_TURN_SITE_SUFFIX))


# ==== metric 2/3: env reads, sibling edges, cycle attribution ==================================================

def old_collector(app_files: Dict[str, str], caller_service: Optional[str]) -> Dict[str, Any]:
    """Verbatim replica of HB-05's caller-file selection + "keys the code reads" collector
    (terraform_engine.py :1287-1316), with each key tagged by the form it was seen in."""
    relevant: List[Tuple[str, str]] = []
    selection = "all_files_no_caller"
    if caller_service:
        clean_cs = caller_service.replace("_", "-").lower()
        relevant = [(p, c) for p, c in app_files.items()
                    if p.endswith(".py") and f"apps/{clean_cs}/" in p.replace("_", "-").lower()]
        selection = "caller_files"
    if not relevant:
        relevant = [(p, c) for p, c in app_files.items() if p.endswith(".py")]
        if caller_service:
            selection = "all_files_fallback"
    keys: Set[str] = set()
    forms: Dict[str, Set[str]] = {}
    for path, code in relevant:
        try:
            tree = ast.parse(code)
        except Exception:  # noqa: BLE001 - the product swallows it the same way
            continue
        names = _os_names(tree)
        for node in ast.walk(tree):
            key = form = None
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute) and node.func.attr in ("getenv", "get") and node.args
                        and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                    key = node.args[0].value
                    if node.func.attr == "get":
                        kind = _environ_kind(node.func.value, names)
                        form = {"os": FORM_ENVIRON_GET, "imported": FORM_IMPORTED_ENVIRON_GET}.get(
                            kind or "", OLD_FORM_GET_OTHER)
                    else:
                        form = FORM_OS_GETENV if (isinstance(node.func.value, ast.Name)
                                                  and node.func.value.id in names.os_mods) else OLD_FORM_GETENV_OTHER
            elif isinstance(node, ast.Subscript):
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    key = node.slice.value
                    kind = _environ_kind(node.value, names)
                    if kind and not isinstance(node.ctx, ast.Load):
                        form = OLD_FORM_ENVIRON_WRITE
                    elif kind:
                        form = FORM_ENVIRON_SUBSCRIPT if kind == "os" else FORM_IMPORTED_ENVIRON_SUBSCRIPT
                    else:
                        form = OLD_FORM_SUBSCRIPT_OTHER
            if key is None:
                continue
            keys.add(key)
            if selection == "all_files_fallback" or (selection == "all_files_no_caller"):
                form = f"{form} [{selection}: {path}]"
            forms.setdefault(key, set()).add(form)
    return {"keys": keys, "forms": forms, "selection": selection, "files": sorted(p for p, _ in relevant)}


def service_py_files(tree: Dict[str, str], svc: str) -> Dict[str, str]:
    pre = f"apps/{svc}/"
    return {p: t for p, t in tree.items() if p.startswith(pre) and p.endswith(".py")}


def app_services(tree: Dict[str, str]) -> List[str]:
    out = set()
    for p in tree:
        if p.startswith("apps/") and p.endswith(".py"):
            parts = p.split("/")
            if len(parts) >= 3:
                out.add(parts[1])
    return sorted(out)


def module_calls(parsed_root: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for path, doc in parsed_root.items():
        for btype, labels, body in iter_blocks(doc):
            if btype != "module" or not labels:
                continue
            attrs = attributes(body)
            out[labels[0]] = {"path": path, "source": literal_string(attrs["source"]) if "source" in attrs else None,
                              "service_name": literal_string(attrs["service_name"]) if "service_name" in attrs
                              else None, "body": body, "attrs": attrs}
    return out


def module_service(label: str, info: Dict[str, Any]) -> str:
    """HB-05's caller/target name: literal service_name, else the label without "compute_" (verifier.py:654-657)."""
    sn = info.get("service_name") or label
    return sn[len("compute_"):] if sn.startswith("compute_") else sn


def token_of(label: str, info: Dict[str, Any]) -> str:
    return module_service(label, info).upper().replace("-", "_")


def sibling_edges(mods: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every `env_vars` object element of a module call whose value is exactly module.<other>.<attr>."""
    edges = []
    for label, info in sorted(mods.items()):
        ev = info["attrs"].get("env_vars")
        if ev is None:
            continue
        for key, val in object_elems(ev):
            tr = traversal(val)
            if tr and len(tr) >= 3 and tr[0] == "module" and tr[1] != label and key is not None:
                edges.append({"caller_module": label, "caller_service": module_service(label, info), "key": key,
                              "target_module": tr[1], "target_attr": ".".join(tr[2:]), "path": info["path"]})
    return edges


def parse_cycle_nodes(message: str) -> List[str]:
    """tofu's "Cycle: a, b (expand, reference), c" -> ['a', 'b', 'c'] (commas inside parentheses kept)."""
    text = message.split("Cycle:", 1)[1] if "Cycle:" in message else message
    nodes, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            nodes.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    nodes.append("".join(cur))
    out = []
    for n in nodes:
        n = n.strip()
        if " (" in n:
            n = n.split(" (", 1)[0]
        if n:
            out.append(n)
    return out


def cycle_modules(nodes: List[str]) -> List[str]:
    out: List[str] = []
    for n in nodes:
        parts = n.split(".")
        if len(parts) >= 2 and parts[0] == "module" and parts[1] not in out:
            out.append(parts[1])
    return out


def binding_rules(key: str, target_token: str, old_keys: Set[str]) -> List[str]:
    """Which HB-05 rule (terraform_engine.py :1379-1396) emits `key` for a sibling with this token."""
    rules = []
    if key in (f"{target_token}_URL", f"{target_token}_AUDIENCE"):
        rules.append("unconditional <TOKEN>_URL/_AUDIENCE")
    token_parts = [p for p in target_token.split("_") if p not in NOUN_STOP]
    if key in old_keys and key.endswith(URI_SUFFIXES):
        k_parts = [p for p in key.rsplit("_", 1)[0].split("_") if p not in NOUN_STOP]
        if token_parts and k_parts and any(tp in k_parts for tp in token_parts):
            rules.append("shared noun")
    if key in GENERIC_ALIASES and key in old_keys and any(tp in key for tp in token_parts):
        rules.append("generic alias")
    return rules


def _has_cycle(nodes: List[str], arcs: Set[Tuple[str, str]]) -> bool:
    adj: Dict[str, List[str]] = {n: [] for n in nodes}
    for a, b in arcs:
        adj.setdefault(a, []).append(b)
    state: Dict[str, int] = {}

    def dfs(u: str) -> bool:
        state[u] = 1
        for v in adj.get(u, []):
            if state.get(v) == 1 or (state.get(v) is None and dfs(v)):
                return True
        state[u] = 2
        return False
    return any(state.get(n) is None and dfs(n) for n in list(adj))


def attribute_edges(edges: List[Dict[str, Any]], mods: Dict[str, Dict[str, Any]], tree: Dict[str, str],
                    hb05: Optional[Callable[..., Dict[str, str]]]) -> List[Dict[str, Any]]:
    custom = tree.get(WORKLOAD + "custom.tf")
    product_cache: Dict[str, Dict[str, str]] = {}
    out = []
    for e in edges:
        svc = e["caller_service"]
        tgt = mods.get(e["target_module"], {})
        tgt_token = token_of(e["target_module"], tgt) if tgt else e["target_module"].upper()
        own = service_py_files(tree, svc)
        exact = exact_env_reads_files(own)
        old = old_collector(tree, svc)
        rules = binding_rules(e["key"], tgt_token, old["keys"])
        product_binds = None
        if hb05 is not None and custom is not None:
            if svc not in product_cache:
                try:
                    product_cache[svc] = hb05(custom, tree, caller_service=svc)
                except Exception as ex:  # noqa: BLE001
                    product_cache[svc] = {"__error__": f"{type(ex).__name__}: {ex}"[:200]}
            product_binds = product_cache[svc].get(e["key"]) == f"module.{e['target_module']}.service_uri"
        read_exact = e["key"] in exact.keys
        if read_exact:
            klass = "read exactly"
        elif e["key"] in old["keys"] or any(r != "unconditional <TOKEN>_URL/_AUDIENCE" for r in rules):
            klass = "guessed (old inexact form only)"
        else:
            klass = "unread"
        s2d_keys = {f"{tgt_token}{s}" for s in URI_SUFFIXES}
        target_is_cr = module_dir(tgt.get("source")) == CLOUD_RUN_MODULE_DIR if tgt else False
        out.append({**e, "target_token": tgt_token, "caller_files": sorted(own), "binding_rules": rules,
                    "product_binds_on_final_custom_tf": product_binds,
                    "exact_forms": sorted(exact.forms.get(e["key"], set())),
                    "old_forms": sorted(old["forms"].get(e["key"], set())), "old_selection": old["selection"],
                    "class": klass,
                    "survives_s2d": bool(read_exact and e["key"] in s2d_keys and target_is_cr and own)})
    return out


def cycle_attribution(result: Dict[str, Any], tree: Dict[str, str], mods: Dict[str, Dict[str, Any]],
                      hb05: Optional[Callable[..., Dict[str, str]]]) -> List[Dict[str, Any]]:
    diags = ((result.get("hallucination_stack") or {}).get("developer_failed_typed") or {}).get("diagnostics") or []
    out = []
    edges = sibling_edges(mods)
    for d in diags:
        if d.get("code") != "TF.CYCLE":
            continue
        text = " ".join(str(x) for x in (d.get("message"), d.get("detail")) if x)
        nodes = parse_cycle_nodes(text)
        cmods = cycle_modules(nodes)
        cyc_edges = [e for e in edges if e["caller_module"] in cmods and e["target_module"] in cmods]
        att = attribute_edges(cyc_edges, mods, tree, hb05)
        # module-level references between cycle modules outside env_vars (visibility)
        other_refs = []
        for m in cmods:
            info = mods.get(m)
            if not info:
                continue
            for name, stack, _ in root_refs(info["body"], "module"):
                if name in cmods and name != m and (not stack or stack[0] != "env_vars"):
                    other_refs.append({"caller_module": m, "target_module": name, "attribute": ".".join(stack)})
        exact_read = [a for a in att if a["class"] == "read exactly"]
        arcs_after = {(a["caller_module"], a["target_module"]) for a in att if a["survives_s2d"]}
        arcs_after |= {(r["caller_module"], r["target_module"]) for r in other_refs}
        remains = _has_cycle(cmods, arcs_after)
        if not att:
            verdict = "no env_vars sibling edge found between the cycle's modules"
        elif exact_read:
            verdict = ("edge " + ", ".join(sorted({f"{a['caller_module']}.{a['key']}" for a in exact_read}))
                       + " is read exactly (S2-D does not clear it)")
        else:
            verdict = "every edge is an unread or guessed key (S2-D clears it)"
        out.append({"cycle_nodes": nodes, "cycle_modules": cmods, "edges": att, "other_refs": other_refs,
                    "verdict": verdict, "cycle_remains_after_s2d": remains if att else None})
    return out


def module_callers(tree: Dict[str, str], mods: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per compute-cloudrun module call: its service, whether apps/<service>/ has .py code (S2-D caller files),
    and which file set HB-05's old selection uses for it."""
    out = []
    for label, info in sorted(mods.items()):
        if module_dir(info.get("source")) != CLOUD_RUN_MODULE_DIR:
            continue
        svc = module_service(label, info)
        old = old_collector(tree, None if label in ("compute", "app") else svc)
        out.append({"module": label, "service": svc, "own_py_files": len(service_py_files(tree, svc)),
                    "old_selection": old["selection"], "old_files": len(old["files"])})
    return out


def env_read_sets(tree: Dict[str, str], mods: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    callers: Dict[str, List[str]] = {}
    for label, info in mods.items():
        callers.setdefault(module_service(label, info), []).append(label)
    services = []
    for svc in app_services(tree):
        own = service_py_files(tree, svc)
        ex = exact_env_reads_files(own)
        old = old_collector(tree, svc)
        services.append({"service": svc, "modules": sorted(callers.get(svc, [])), "py_files": len(own),
                         "old_selection": old["selection"], "old_keys": sorted(old["keys"]),
                         "exact_keys": sorted(ex.keys), "exact_forms": {k: sorted(v) for k, v in ex.forms.items()},
                         "old_only": sorted(old["keys"] - ex.keys), "exact_only": sorted(ex.keys - old["keys"]),
                         "basesettings_classes": ex.basesettings_classes, "unresolved": ex.unresolved,
                         "uncounted": len(ex.uncounted)})
    no_caller = old_collector(tree, None)
    return {"services": services, "old_keys_no_caller_all_files": len(no_caller["keys"])}


# ==== metric 4: google_project_service references in the drafts ==============================================

def gps_metrics(draft: Dict[str, str]) -> Dict[str, Any]:
    parsed, bad = parse_all({p: t for p, t in draft.items() if p.endswith(".tf")})
    declared: Dict[str, Dict[str, Any]] = {}
    for path, doc in parsed.items():
        for btype, labels, body in iter_blocks(doc):
            if btype == "resource" and len(labels) >= 2 and labels[0] == "google_project_service":
                attrs = attributes(body)
                nested = [b for b in iter_blocks(body)]
                lit_service = literal_string(attrs["service"]) if "service" in attrs else None
                others = set(attrs) - {"service", "disable_on_destroy"}
                dod_ok = "disable_on_destroy" not in attrs or literal_bool(attrs["disable_on_destroy"]) is False
                declared[labels[1]] = {"path": path, "attributes": sorted(attrs),
                                       "nested_blocks": sorted({b[0] for b in nested}),
                                       "literal_only": bool(lit_service is not None and not others and dod_ok
                                                            and not nested),
                                       "service": lit_service}
    refs = []
    undeclared = []
    for path, doc in parsed.items():
        for name, stack, _ in root_refs(doc, "google_project_service"):
            kind = "depends_on" if "depends_on" in stack else "expression"
            (refs if name in declared else undeclared).append({"path": path, "name": name, "kind": kind,
                                                               "attribute": ".".join(stack)})
    return {"blocks": len(declared), "literal_only": sum(1 for d in declared.values() if d["literal_only"]),
            "declared": declared, "references": len(refs),
            "depends_on_refs": sum(1 for r in refs if r["kind"] == "depends_on"),
            "expression_refs": sum(1 for r in refs if r["kind"] == "expression"),
            "referenced_blocks": len({r["name"] for r in refs}), "reference_list": refs,
            "undeclared_refs": undeclared, "unparsed": bad}


# ==== metric 5: API coverage =================================================================================

def required_apis(tree: Dict[str, str], ref: Dict[str, Any]) -> Dict[str, Any]:
    rfiles = root_tf(tree)
    parsed, bad = parse_all(rfiles)
    need: Dict[str, Set[str]] = {}
    unknown: List[str] = []
    unknown_modules: List[str] = []

    def add(kind_key: str, row: Optional[List[str]]) -> None:
        if row is None:
            unknown.append(kind_key)
            return
        for api in row:
            need.setdefault(api, set()).add(kind_key)

    for path, doc in parsed.items():
        for btype, labels, body in iter_blocks(doc):
            if btype == "resource" and labels:
                add(labels[0], ref["resource_types"].get(labels[0]))
            elif btype == "data" and labels:
                add(f"data.{labels[0]}", ref["data_types"].get(labels[0]))
            elif btype == "module" and labels:
                src = literal_string(attributes(body).get("source")) if attributes(body).get("source") else None
                d = module_dir(src)
                if d is None:
                    unknown_modules.append(f"module.{labels[0]} ({src})")
                else:
                    add(f"module:{d}", ref["modules"].get(d))
    for path, text in rfiles.items():
        if path.endswith(".tf.json"):
            try:
                doc = json.loads(text)
            except Exception:  # noqa: BLE001
                bad[path] = "json"
                continue
            for kind, table in (("resource", "resource_types"), ("data", "data_types")):
                for typ in (doc.get(kind) or {}):
                    add(typ if kind == "resource" else f"data.{typ}", ref[table].get(typ))
    return {"apis": need, "unknown_types": sorted(set(unknown)), "unknown_module_sources": unknown_modules,
            "unparsed_root_files": bad}


def apply_scan_input(tree: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    tf, yml = {}, {}
    for p, t in tree.items():
        if any(part in IGNORED_SCAN_DIRS for part in p.split("/")[:-1]):
            continue
        low = p.split("/")[-1].lower()
        if low.endswith((".tf", ".tf.json")):
            tf[p] = t
        elif low.endswith((".yaml", ".yml")):
            yml[p] = t
    return tf, yml


def api_coverage(tree: Dict[str, str], ref: Dict[str, Any], vending: List[str], product_root: Path,
                 extract_apis: Callable[..., List[str]]) -> Dict[str, Any]:
    req = required_apis(tree, ref)
    base_txt = tree.get("infra/modules/workload-foundation/base/variables.tf")
    if base_txt is None:
        p = product_root / "infra/modules/workload-foundation/base/variables.tf"
        base_txt = p.read_text() if p.is_file() else ""
    base = base_apis_from_text(base_txt) or []
    additional, tfvars_err = tfvars_additional_apis(tree.get(WORKLOAD + "terraform.tfvars"))
    tf, yml = apply_scan_input(tree)
    apply_set = set(extract_apis(tf, yml))
    gateway = set(vending) | set(base) | set(additional)
    covered = gateway | apply_set
    required = set(req["apis"])
    gaps = {api: sorted(req["apis"][api]) for api in sorted(required - covered)}
    gw_gaps = {api: sorted(req["apis"][api]) for api in sorted(required - gateway)}
    return {"required": sorted(required), "additional_apis": additional, "tfvars_error": tfvars_err,
            "apply_batch_enable": sorted(apply_set), "gaps": gaps, "gateway_only_gaps": gw_gaps,
            "unknown_types": req["unknown_types"], "unknown_module_sources": req["unknown_module_sources"],
            "unparsed_root_files": req["unparsed_root_files"]}


def module_row_check(product_root: Path, ref: Dict[str, Any]) -> Dict[str, Any]:
    """Every golden module row covers its internal resource/data types; every internal type has a row."""
    per: Dict[str, Set[str]] = {}
    unknown: Set[str] = set()
    for p in sorted((product_root / "infra" / "modules").rglob("*.tf")):
        try:
            doc = hcl_parse(p.read_text())
        except Exception:  # noqa: BLE001
            continue
        d = p.parent.name
        for btype, labels, _ in iter_blocks(doc):
            if btype in ("resource", "data") and labels:
                table = ref["resource_types"] if btype == "resource" else ref["data_types"]
                row = table.get(labels[0])
                if row is None:
                    unknown.add(("data." if btype == "data" else "") + labels[0])
                    continue
                per.setdefault(d, set()).update(row)
    incomplete = {d: sorted(apis - set(ref["modules"].get(d, []))) for d, apis in per.items()
                  if d not in ref["modules"] or apis - set(ref["modules"].get(d, []))}
    missing_rows = sorted(d for d in per if d not in ref["modules"])
    return {"module_dirs": sorted(per), "rows_incomplete": incomplete, "missing_module_rows": missing_rows,
            "unknown_golden_types": sorted(unknown)}


# ==== driver ==================================================================================================

def analyse_run(key: str, run_dir: Path, ref: Dict[str, Any], vending: List[str], product_root: Path,
                extract_apis: Callable[..., List[str]], hb05: Optional[Callable[..., Dict[str, str]]]
                ) -> Dict[str, Any]:
    result = json.loads((run_dir / "result.json").read_text())
    out: Dict[str, Any] = {"run": key, "single_turn_calls": single_turn_calls(result),
                           "not_exact_sites": fallback_sites(result),
                           "error_class": ((result.get("hallucination_stack") or {}).get("developer_failed_typed")
                                           or {}).get("error_class")}
    asm = ((result.get("tree_dumps") or {}).get("assemble") or [])
    asm = [a for a in asm if a.get("assembled")]
    if not asm:
        out["error"] = "no tree_dumps.assemble entry"
        return out
    bs = BlobStore(run_dir)
    last = bs.get_tree(asm[-1]["assembled"])
    draft = bs.get_tree(asm[0]["draft"])
    out["assemble_calls"] = len(asm)
    parsed_root, bad_root = parse_all(root_tf(last))
    mods = module_calls(parsed_root)
    out["root_unparsed"] = bad_root
    out["sibling_edges"] = attribute_edges(sibling_edges(mods), mods, last, hb05)
    out["module_callers"] = module_callers(last, mods)
    out["cycles"] = cycle_attribution(result, last, mods, hb05)
    out["env_reads"] = env_read_sets(last, mods)
    out["google_project_service"] = gps_metrics(draft)
    out["api_coverage"] = api_coverage(last, ref, vending, product_root, extract_apis)
    gm = golden_module_mutations(last, product_root)
    out["golden_module_mutations"] = gm
    return out


def _fmt_set(xs: Any, limit: int = 8) -> str:
    xs = list(xs)
    if not xs:
        return "-"
    s = ", ".join(str(x) for x in xs[:limit])
    return s + (f" (+{len(xs) - limit})" if len(xs) > limit else "")


def render_md(rep: Dict[str, Any]) -> str:
    runs = [r for r in rep["runs"] if "error" not in r]
    T = rep["totals"]
    L: List[str] = [f"# S2-0 / G0 metrics — `{rep['results_dir']}`", "",
                    f"{len(rep['runs'])} runs; product root `{rep['product_root']}`. "
                    "Tool: `eval/tools/step2_g0_metrics.py` (see its docstring for every replicated/extracted "
                    "product rule).", ""]
    pe = rep.get("paired_exclusions") or []
    L += ["## 0. Paired exclusions (code RT F7)", "",
          "Runs whose LLM calls were not all served by exact replay (site/ordinal fallback or miss). Their outcome is "
          "not faithful to the recording at those sites; a paired comparison drops a run when its not-exact sites "
          "differ between the two sides (`eval/compare.py`, `stackvend_eval.metrics.excluded_from_pairing`).", ""]
    L += [f"- {e['run']}: {e['reason']} {e['sites']}" for e in pe] or ["- none"]
    L += [""]
    L += ["## 1. Single-turn calls", "",
          f"LLM calls whose site ends with `{SINGLE_TURN_SITE_SUFFIX}`: **{T['single_turn_calls']}** in total "
          f"(runs with ≥1: {_fmt_set(T['single_turn_runs'])}).", ""]
    L += ["## 2. Cycle attribution (`TF.CYCLE`)", "",
          f"Runs with `TF.CYCLE`: {_fmt_set(T['cycle_runs'])}.", "",
          "| run | edge (caller module → key → target) | caller files | HB-05 rule | product binds | exact read forms "
          "| old-collector forms | class | survives S2-D |", "|---|---|---|---|---|---|---|---|---|"]
    for r in runs:
        for c in r["cycles"]:
            for e in c["edges"]:
                L.append(f"| {r['run']} | `{e['caller_module']}` → `{e['key']}` → `{e['target_module']}` | "
                         f"{len(e['caller_files'])} | {_fmt_set(e['binding_rules'])} | "
                         f"{e['product_binds_on_final_custom_tf']} | {_fmt_set(e['exact_forms'])} | "
                         f"{_fmt_set(e['old_forms'], 3)} | {e['class']} | {e['survives_s2d']} |")
    L += ["", "| run | cycle modules | verdict | cycle remains after S2-D (arc analysis) |", "|---|---|---|---|"]
    for r in runs:
        for c in r["cycles"]:
            L.append(f"| {r['run']} | {_fmt_set(c['cycle_modules'])} | {c['verdict']} | "
                     f"{c['cycle_remains_after_s2d']} |")
    L += ["", "### 2b. All sibling `service_uri` env edges (every run; G-D baseline)", "",
          f"Edges {T['sibling_edges']} in {len(T['sibling_edge_runs'])} runs; read exactly by the caller's own code "
          f"{T['sibling_edges_read_exactly']}; would survive S2-D {T['sibling_edges_survive_s2d']}; Cloud Run module "
          f"callers without `apps/<service>/` code {T['callers_without_code']}; callers whose old HB-05 selection is "
          f"all files {T['callers_old_all_files']}.", "",
          "| run | edges | read exactly | survive S2-D | edge classes | callers (module: own .py files / old selection) |",
          "|---|---|---|---|---|---|"]
    for r in runs:
        es = r["sibling_edges"]
        if not es and not r["module_callers"]:
            continue
        classes: Dict[str, int] = {}
        for e in es:
            classes[e["class"]] = classes.get(e["class"], 0) + 1
        L.append(f"| {r['run']} | {len(es)} | {sum(1 for e in es if e['class'] == 'read exactly')} | "
                 f"{sum(1 for e in es if e['survives_s2d'])} | "
                 f"{_fmt_set([f'{k}×{v}' for k, v in sorted(classes.items())])} | "
                 f"{_fmt_set([f'{c['module']}: {c['own_py_files']}/{c['old_selection']}' for c in r['module_callers']], 4)} |")
    L += ["", "## 3. Env-read key sets per service (old HB-05 collector vs exact)", "",
          f"Services: {T['services']}; old keys {T['old_keys']}, exact keys {T['exact_keys']}, old-only "
          f"{T['old_only']}, exact-only {T['exact_only']}; `BaseSettings` classes **{T['basesettings_classes']}**; "
          f"unresolved {T['unresolved']}; old selection fell back to all files for {T['old_fallback_services']} "
          "services.", "",
          "| run | service | modules | py | old sel. | old | exact | old-only (sample) | exact-only | BaseSettings "
          "| unresolved |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in runs:
        for s in r["env_reads"]["services"]:
            L.append(f"| {r['run']} | {s['service']} | {_fmt_set(s['modules'], 3)} | {s['py_files']} | "
                     f"{s['old_selection']} | {len(s['old_keys'])} | {len(s['exact_keys'])} | "
                     f"{_fmt_set(s['old_only'], 5)} | {_fmt_set(s['exact_only'], 4)} | "
                     f"{s['basesettings_classes']} | {len(s['unresolved'])} |")
    L += ["", "## 4. `google_project_service` in the LLM drafts (`tree_dumps.assemble[0].draft`)", "",
          f"Blocks **{T['gps_blocks']}** in {T['gps_runs_with_blocks']} runs; literal-only **{T['gps_literal_only']}**; "
          f"references **{T['gps_references']}** (depends_on {T['gps_depends_on']}, expression {T['gps_expression']}); "
          f"runs with ≥1 reference **{len(T['gps_runs_referencing'])}** vs 0: "
          f"{T['gps_runs_with_blocks'] - len(T['gps_runs_referencing'])} (of the runs with blocks); undeclared-name "
          f"traversals (not counted) {T['gps_undeclared']}.", "",
          "| run | blocks | literal-only | refs | depends_on | expr | referenced blocks | attribute shapes | unparsed |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in runs:
        g = r["google_project_service"]
        shapes: Dict[str, int] = {}
        for d in g["declared"].values():
            k = "+".join(d["attributes"] + [f"<{b}>" for b in d["nested_blocks"]]) or "(none)"
            shapes[k] = shapes.get(k, 0) + 1
        L.append(f"| {r['run']} | {g['blocks']} | {g['literal_only']} | {g['references']} | {g['depends_on_refs']} | "
                 f"{g['expression_refs']} | {g['referenced_blocks']} | "
                 f"{_fmt_set([f'{k}×{v}' for k, v in sorted(shapes.items())], 4)} | {_fmt_set(g['unparsed'])} |")
    L += ["", "## 5. `api_coverage_gaps` (required − (vending ∪ base_apis ∪ tfvars additional_apis ∪ apply "
          "batchEnable))", "",
          f"Runs with ≥1 gap: **{len(T['api_gap_runs'])}** ({_fmt_set(T['api_gap_runs'], 30)}); gateway-only gap "
          f"runs: {len(T['api_gateway_gap_runs'])}. Unknown types (no reference row): "
          f"{_fmt_set(T['unknown_types'], 30)}. Module-row check: incomplete {rep['module_row_check']['rows_incomplete'] or '-'}"
          f", unknown golden types {_fmt_set(rep['module_row_check']['unknown_golden_types'])}.", "",
          "| run | gaps (API ← types) | gateway-only gaps | unknown types | unparsed root files |", "|---|---|---|---|---|"]
    for r in runs:
        a = r["api_coverage"]
        gaps = [f"{api} ← {_fmt_set(t, 3)}" for api, t in a["gaps"].items()]
        gw = [f"{api}" for api in a["gateway_only_gaps"]]
        L.append(f"| {r['run']} | {_fmt_set(gaps, 6)} | {_fmt_set(gw, 8)} | {_fmt_set(a['unknown_types'])} | "
                 f"{_fmt_set(a['unparsed_root_files'])} |")
    L += ["", "## 6. Golden-module mutations on the final assembled tree", "",
          f"Runs with ≥1 mutated `infra/modules/**` file: **{len(T['golden_mutation_runs'])}** "
          f"({_fmt_set(T['golden_mutation_runs'])}).", ""]
    errs = [r for r in rep["runs"] if "error" in r]
    if errs:
        L += ["## Runs not analysed", ""] + [f"- {r['run']}: {r['error']}" for r in errs] + [""]
    return "\n".join(L)


def totals(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    ok = [r for r in runs if "error" not in r]
    svcs = [s for r in ok for s in r["env_reads"]["services"]]
    unknown = sorted({t for r in ok for t in r["api_coverage"]["unknown_types"]})
    return {
        "single_turn_calls": sum(r.get("single_turn_calls", 0) for r in runs),
        "single_turn_runs": [r["run"] for r in runs if r.get("single_turn_calls")],
        "cycle_runs": [r["run"] for r in ok if r["cycles"]],
        "cycle_verdicts": {r["run"]: [c["verdict"] for c in r["cycles"]] for r in ok if r["cycles"]},
        "sibling_edges": sum(len(r["sibling_edges"]) for r in ok),
        "sibling_edge_runs": [r["run"] for r in ok if r["sibling_edges"]],
        "sibling_edges_read_exactly": sum(1 for r in ok for e in r["sibling_edges"] if e["class"] == "read exactly"),
        "sibling_edges_survive_s2d": sum(1 for r in ok for e in r["sibling_edges"] if e["survives_s2d"]),
        "callers_without_code": sum(1 for r in ok for c in r["module_callers"] if not c["own_py_files"]),
        "callers_old_all_files": sum(1 for r in ok for c in r["module_callers"]
                                     if c["old_selection"] != "caller_files"),
        "services": len(svcs), "old_keys": sum(len(s["old_keys"]) for s in svcs),
        "exact_keys": sum(len(s["exact_keys"]) for s in svcs), "old_only": sum(len(s["old_only"]) for s in svcs),
        "exact_only": sum(len(s["exact_only"]) for s in svcs),
        "basesettings_classes": sum(s["basesettings_classes"] for s in svcs),
        "unresolved": sum(len(s["unresolved"]) for s in svcs),
        "old_fallback_services": sum(1 for s in svcs if s["old_selection"] == "all_files_fallback"),
        "gps_blocks": sum(r["google_project_service"]["blocks"] for r in ok),
        "gps_runs_with_blocks": sum(1 for r in ok if r["google_project_service"]["blocks"]),
        "gps_literal_only": sum(r["google_project_service"]["literal_only"] for r in ok),
        "gps_references": sum(r["google_project_service"]["references"] for r in ok),
        "gps_depends_on": sum(r["google_project_service"]["depends_on_refs"] for r in ok),
        "gps_expression": sum(r["google_project_service"]["expression_refs"] for r in ok),
        "gps_runs_referencing": [r["run"] for r in ok if r["google_project_service"]["references"]],
        "gps_undeclared": sum(len(r["google_project_service"]["undeclared_refs"]) for r in ok),
        "api_gap_runs": [r["run"] for r in ok if r["api_coverage"]["gaps"]],
        "api_gateway_gap_runs": [r["run"] for r in ok if r["api_coverage"]["gateway_only_gaps"]],
        "api_gaps_by_api": _count({api for api in r["api_coverage"]["gaps"]} for r in ok),
        "unknown_types": unknown,
        "golden_mutation_runs": [r["run"] for r in ok if r.get("golden_module_mutations")],
    }


def _count(sets: Any) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for s in sets:
        for x in s:
            out[x] = out.get(x, 0) + 1
    return dict(sorted(out.items()))


def _jsonable(o: Any) -> Any:
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items() if k not in ("body", "attrs")}
    if isinstance(o, (list, tuple)):
        return [_jsonable(x) for x in o]
    if isinstance(o, set):
        return sorted(_jsonable(x) for x in o)
    if isinstance(o, EnvReads):
        return o.to_json()
    return o


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("results_dir", type=Path)
    ap.add_argument("--product-root", type=Path, default=REPO_ROOT)
    ap.add_argument("--ref", type=Path, default=CONFIG_DIR / "api_requirements_ref.json")
    args = ap.parse_args(argv)
    product_root = args.product_root.resolve()
    ref = json.loads(args.ref.read_text())
    extract_apis = load_extract_apis(product_root)
    vending = load_vending_apis(product_root)
    try:
        hb05 = load_hb05(product_root)
    except Exception as e:  # noqa: BLE001 - attribution cross-check only
        print(f"warning: HB-05 not loadable ({e}); product_binds column is None", file=sys.stderr)
        hb05 = None
    runs = []
    for rd in sorted((args.results_dir / "runs").iterdir()):
        if (rd / "result.json").is_file():
            runs.append(analyse_run(rd.name, rd, ref, vending, product_root, extract_apis, hb05))
    rep = {"results_dir": str(args.results_dir), "product_root": str(product_root), "vending_apis": vending,
           "module_row_check": module_row_check(product_root, ref), "runs": runs, "totals": totals(runs),
           "paired_exclusions": [{"run": r["run"], "reason": "replay_not_exact", "sites": r["not_exact_sites"]}
                                 for r in runs if r.get("not_exact_sites")]}
    rep = _jsonable(rep)
    (args.results_dir / "step2_g0_metrics.json").write_text(json.dumps(rep, indent=1, sort_keys=True))
    md = render_md(rep)
    (args.results_dir / "step2_g0_metrics.md").write_text(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())

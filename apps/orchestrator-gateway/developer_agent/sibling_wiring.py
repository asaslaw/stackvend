"""HB-05's sibling Cloud Run URL wiring, narrowed to exact reads (Step 2 plan rev 2 §3.4 D1, S2-D; register HS-65).

A service receives another (sibling) Cloud Run service's `service_uri` only under an environment key that its OWN
Python code reads exactly. Every decision is a parser result or an exact string equality; nothing is guessed:

  sibling   a `module` block (python-hcl2) whose literal `source` is the golden compute-cloudrun module directory
            (exact last path component) and whose label is not the primary's ("compute"/"app"). Its service is the
            literal `service_name` attribute, else the label; a leading "compute_" is dropped; TOKEN is that name
            upper-cased with "-" -> "_" (the platform's own naming, unchanged from HB-05).
  caller    the service whose module is being wired. Its files are the `.py` files under `apps/<dir>/` where <dir>
            equals the service name after the platform's "_" -> "-" normalisation (exact equality, no substring).
            With no service name, the caller is the one service of `detect_workload_services` that is not a sibling,
            and only if exactly one remains. There is no "every file in the repo" fallback.
  reads     `env_reads(caller files)`: os.environ[...] / os.environ.get / os.getenv / environ / getenv imported from
            os / pydantic BaseSettings fields (developer_agent/env_reads.py). Nothing else counts.
  binding   `<TOKEN>_URL`, `<TOKEN>_URI`, `<TOKEN>_ENDPOINT`, `<TOKEN>_AUDIENCE` of a sibling, each only if that exact key
            is in the caller's reads. The former unconditional <TOKEN>_URL/_AUDIENCE, shared-noun and generic-alias
            bindings are gone.
  unbound   a sibling whose four keys the caller does not read (or an unresolved caller) is returned in `unbound`
            (report-only diagnostic IAC.SIBLING_URI_UNBOUND): never silent. A key the code reads with a URI suffix that
            names no sibling is reported with it (`unmatched_uri_reads`), not bound (code RT ruling Q1, 02-r3).
  cycles    AGENTS invariant 6 (multi-service IaC stays acyclic). The read graph between the sibling services (and the
            caller when it is itself a sibling) is built from each service's own exact reads. An edge inside a
            strongly connected component (A reads B's key and B reads A's, directly or around a ring) is NOT bound and
            is returned in `withheld` (blocking diagnostic IAC.SIBLING_URI_CYCLE, routed to the Python file that reads
            the key), so the AI repairs the mutual read instead of the platform dropping an edge silently.

Pure functions: no I/O, no LLM, no mutation of their inputs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

try:
    from .assembly import HclUnavailable, index_blocks
    from .env_reads import env_reads
    from .workload_inventory import detect_workload_services
except ImportError:
    try:
        from assembly import HclUnavailable, index_blocks  # type: ignore
        from env_reads import env_reads  # type: ignore
        from workload_inventory import detect_workload_services  # type: ignore
    except ImportError:
        from developer_agent.assembly import HclUnavailable, index_blocks  # type: ignore
        from developer_agent.env_reads import env_reads  # type: ignore
        from developer_agent.workload_inventory import detect_workload_services  # type: ignore

CLOUD_RUN_MODULE_DIR = "compute-cloudrun"   # the only golden module that deploys a Cloud Run service
URI_SUFFIXES = ("_URL", "_URI", "_ENDPOINT", "_AUDIENCE")
PRIMARY_MODULE_LABELS = ("compute", "app")  # main.tf's own compute module: a caller, never a sibling target

REASON_CALLER_UNRESOLVED = "caller_unresolved"
REASON_NO_TOKEN_MATCH = "no_token_match"     # the caller reads URI-suffixed keys, none of them this sibling's
REASON_NOT_READ = "not_read"
REASON_NOT_ADDRESSABLE = "not_addressable"  # the sibling module has for_each/count (code RT F6)
REASON_NOT_WRITTEN = "not_written"          # bound by the plan, absent from the caller's env_vars (code RT F2)


def _is_cloud_run_module_source(source: Any) -> bool:
    """True when a module's literal `source` is a local path whose last directory is the golden compute-cloudrun module
    (e.g. "../modules/compute-cloudrun", "./modules/compute-cloudrun/"). Exact path component, no substring."""
    if not isinstance(source, str) or not source.startswith(("./", "../")) or "${" in source:
        return False
    parts = [p for p in source.split("/") if p not in ("", ".")]
    return bool(parts) and parts[-1] == CLOUD_RUN_MODULE_DIR


def literal_string(value: Any) -> Optional[str]:
    """A python-hcl2 attribute value that is a string literal (expressions render as "${...}")."""
    if isinstance(value, str) and "${" not in value:
        return value
    return None


def service_token(service: str) -> str:
    return service.upper().replace("-", "_")


def _norm(service: str) -> str:
    return service.replace("_", "-").lower()


def uri_keys(token: str) -> Tuple[str, ...]:
    return tuple(f"{token}{s}" for s in URI_SUFFIXES)


@dataclass(frozen=True)
class SiblingModule:
    label: str        # module label
    service: str      # literal service_name, else the label (leading "compute_" dropped)
    token: str
    start: int = 0    # 1-based line range of the block in the text it was found in
    end: int = 0
    addressable: bool = True   # False with `for_each`/`count`: module.<label>.service_uri is not a valid reference

    @property
    def address(self) -> str:
        return f"module.{self.label}"

    @property
    def uri_ref(self) -> str:
        return f"module.{self.label}.service_uri"


def module_service(label: str, body: Mapping[str, Any]) -> str:
    sn = literal_string(body.get("service_name")) or label
    return sn[len("compute_"):] if sn.startswith("compute_") else sn


def compute_cloudrun_modules(hcl_text: Optional[str]) -> List[SiblingModule]:
    """Every compute-cloudrun module call in `hcl_text` except the primary's ("compute"/"app"), in file order, by exact
    python-hcl2 structure. A text python-hcl2 cannot parse yields none (V1a-llm reports an unparseable LLM file;
    nothing is guessed)."""
    out: List[SiblingModule] = []
    for b in index_blocks(hcl_text or "") or []:
        if b.kind != "module" or not b.labels or b.labels[0] in PRIMARY_MODULE_LABELS:
            continue
        body = b.body or {}
        if not _is_cloud_run_module_source(body.get("source")):
            continue
        svc = module_service(b.labels[0], body)
        out.append(SiblingModule(b.labels[0], svc, service_token(svc), b.start, b.end,
                                 addressable=not ("for_each" in body or "count" in body)))
    return out


def sibling_compute_modules(hcl_text: Optional[str]) -> List[SiblingModule]:
    """The sibling targets: the addressable `compute_cloudrun_modules`, one per TOKEN (the later module wins, HB-05's
    dict semantics, unchanged). A `for_each`/`count` module is not a target (its outputs need an index; code RT F6)."""
    by_token: Dict[str, SiblingModule] = {}
    for m in compute_cloudrun_modules(hcl_text):
        if not m.addressable:
            continue
        by_token.pop(m.token, None)
        by_token[m.token] = m
    return list(by_token.values())


def primary_caller_service(main_tf: Optional[str]) -> Optional[str]:
    """The literal `service_name` of main.tf's `module "compute"` when it is a compute-cloudrun module, else None."""
    for b in index_blocks(main_tf or "") or []:
        if b.kind == "module" and b.labels and b.labels[0] == "compute":
            body = b.body or {}
            if _is_cloud_run_module_source(body.get("source")):
                return literal_string(body.get("service_name"))
    return None


# ---- exact env_vars references (python-hcl2 lark grammar nodes; code RT F1/F2) --------------------------------
def _data(n: Any) -> Optional[str]:
    return getattr(n, "data", None)


def _kids(n: Any) -> List[Any]:
    return [c for c in getattr(n, "children", []) if _data(c) is not None]


def _ident(n: Any) -> Optional[str]:
    return str(n.children[0]) if _data(n) == "identifier" and n.children else None


def _unwrap(n: Any) -> Any:
    while _data(n) == "expr_term" and len(_kids(n)) == 1:
        n = _kids(n)[0]
    return n


def _string_literal(n: Any) -> Optional[str]:
    n = _unwrap(n)
    if _data(n) != "string":
        return None
    out: List[str] = []
    for part in n.children:
        if _data(part) is None:
            continue
        if _data(part) != "string_part":
            return None
        for c in part.children:
            if _data(c) is not None:        # interpolation / directive
                return None
            out.append(str(c))
    return "".join(out)


def _traversal(n: Any) -> Optional[Tuple[str, ...]]:
    """`a.b.c` -> ("a", "b", "c"); an index, splat, call or literal -> None."""
    n = _unwrap(n)
    if _ident(n) is not None:
        return (_ident(n),)
    if _data(n) == "get_attr_expr_term":
        kids = _kids(n)
        if len(kids) == 2 and _data(kids[1]) == "get_attr":
            base = _traversal(kids[0])
            name = next((_ident(c) for c in _kids(kids[1]) if _ident(c) is not None), None)
            if base is not None and name is not None:
                return base + (name,)
    return None


@lru_cache(maxsize=256)
def _module_env_refs(hcl_text: str) -> Tuple[Tuple[str, Tuple[Tuple[str, Optional[Tuple[str, ...]]], ...]], ...]:
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError as e:  # pragma: no cover - environment
        raise HclUnavailable("python-hcl2 is not installed") from e
    try:
        tree = hcl2.parses(hcl_text)
    except Exception:  # noqa: BLE001 - unparseable: no structure known (V1a-llm reports LLM files)
        return ()
    body = next((c for c in _kids(tree) if _data(c) == "body"), None)
    out = []
    for blk in _kids(body) if body is not None else []:
        kids = _kids(blk)
        if _data(blk) != "block" or len(kids) < 3 or _ident(kids[0]) != "module":
            continue
        label = _string_literal(kids[1])
        inner = next((k for k in kids if _data(k) == "body"), None)
        if label is None or inner is None:
            continue
        elems: List[Tuple[str, Optional[Tuple[str, ...]]]] = []
        for attr in _kids(inner):
            akids = _kids(attr)
            if _data(attr) != "attribute" or len(akids) < 2 or _ident(akids[0]) != "env_vars":
                continue
            stack = [akids[-1]]
            while stack:
                node = stack.pop()
                if _data(node) == "object_elem":
                    ek = _kids(node)
                    if len(ek) >= 2 and _data(ek[0]) == "object_elem_key" and len(_kids(ek[0])) == 1:
                        kn = _kids(ek[0])[0]
                        key = _ident(kn) if _data(kn) == "identifier" else _string_literal(kn)
                        if key is not None:
                            elems.append((key, _traversal(ek[-1])))
                    continue
                stack.extend(_kids(node))
        out.append((label, tuple(elems)))
    return tuple(out)


def module_env_refs(hcl_text: Optional[str]) -> Dict[str, Dict[str, Optional[Tuple[str, ...]]]]:
    """label -> {env key: exact traversal of its value, or None} for the `env_vars` object elements of every top-level
    module block (an object literal, or the object inside `merge(var.env_vars, {...})`). From python-hcl2's grammar
    nodes, never from text; {} for text python-hcl2 cannot parse."""
    return {label: dict(elems) for label, elems in _module_env_refs(hcl_text or "")}


# ---- FD-55 W5 (register FD55-W5): HB-05's env binding as an exact parser edit ----------------------------------
ENV_BIND_PLAIN = "plain"       # env_vars = var.env_vars
ENV_BIND_MERGE = "merge"       # env_vars = merge(var.env_vars, { ... })


def _env_attribute(hcl_text: str, label: str) -> Optional[Tuple[str, Any, Any]]:
    """(form, attribute node, object node or the plain expression node) of the `env_vars` attribute of the ONE
    top-level `module "<label>"` block, from python-hcl2's parse tree (exact offsets in `.meta`). None when the text
    does not parse, the label is not exactly one module block, the block has not exactly one `env_vars`, or its value
    is neither exactly `var.env_vars` nor exactly `merge(var.env_vars, {<object>})`."""
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError as e:  # pragma: no cover - environment
        raise HclUnavailable("python-hcl2 is not installed") from e
    try:
        tree = hcl2.parses(hcl_text)
    except Exception:  # noqa: BLE001 - unparseable: no structure, nothing is edited
        return None
    body = next((c for c in _kids(tree) if _data(c) == "body"), None)
    hits = []
    for blk in _kids(body) if body is not None else []:
        kids = _kids(blk)
        if _data(blk) == "block" and len(kids) == 3 and _ident(kids[0]) == "module" \
                and _string_literal(kids[1]) == label and _data(kids[2]) == "body":
            hits.append(kids[2])
    if len(hits) != 1:
        return None
    attrs = [a for a in _kids(hits[0]) if _data(a) == "attribute" and len(_kids(a)) == 2
             and _ident(_kids(a)[0]) == "env_vars"]
    if len(attrs) != 1:
        return None
    attr = attrs[0]
    expr = _unwrap(_kids(attr)[1])
    if _traversal(expr) == ("var", "env_vars"):
        return ENV_BIND_PLAIN, attr, _kids(attr)[1]
    if _data(expr) == "function_call":
        fk = _kids(expr)
        if len(fk) == 2 and _ident(fk[0]) == "merge" and _data(fk[1]) == "arguments":
            args = _kids(fk[1])
            if len(args) == 2 and _traversal(args[0]) == ("var", "env_vars") and _data(_unwrap(args[1])) == "object":
                return ENV_BIND_MERGE, attr, _unwrap(args[1])
    return None


def _object_keys(obj: Any) -> Set[str]:
    """The literal keys (identifier or plain string) of an HCL object node's elements."""
    out: Set[str] = set()
    for el in _kids(obj):
        ek = _kids(el)
        if _data(el) == "object_elem" and ek and _data(ek[0]) == "object_elem_key" and len(_kids(ek[0])) == 1:
            kn = _kids(ek[0])[0]
            key = _ident(kn) if _data(kn) == "identifier" else _string_literal(kn)
            if key is not None:
                out.add(key)
    return out


def module_env_keys(hcl_text: Optional[str], label: str) -> Set[str]:
    """The env keys `module "<label>"` already binds in `env_vars` (exact object keys of `merge(var.env_vars, {...})`;
    none for `var.env_vars`, an unparseable text or any other shape)."""
    got = _env_attribute(hcl_text or "", label)
    return _object_keys(got[2]) if got is not None and got[0] == ENV_BIND_MERGE else set()


def _object_elements(obj: Any, text: str) -> Optional[List[Tuple[str, str]]]:
    """[(literal key, exact value text)] of an HCL object node's elements, in order (the value text sliced from `text`
    by the node's parse-tree offsets); None when an element has no literal key or no position."""
    out: List[Tuple[str, str]] = []
    for el in _kids(obj):
        if _data(el) != "object_elem":
            continue
        ek = _kids(el)
        if len(ek) < 2 or _data(ek[0]) != "object_elem_key" or len(_kids(ek[0])) != 1:
            return None
        kn = _kids(ek[0])[0]
        key = _ident(kn) if _data(kn) == "identifier" else _string_literal(kn)
        meta = getattr(ek[-1], "meta", None)
        if key is None or meta is None or getattr(meta, "empty", True):
            return None
        out.append((key, text[meta.start_pos:meta.end_pos]))
    return out


def _env_edit_is_exact(old_text: str, new_text: str, label: str, written: Mapping[str, str]) -> bool:
    """Do No Harm check of one bind_module_env edit, by the parser on both texts: the new text parses into the same
    top-level block keys; every block except `module "<label>"` is byte-identical; in that module every attribute
    except `env_vars` is equal (python-hcl2), and its `env_vars` is `merge(var.env_vars, {...})` whose elements are
    exactly the elements it had before (same keys, same value text, same order) followed by one element per written
    key whose value text is exactly the written reference."""
    try:
        from .assembly import block_text
    except ImportError:  # pragma: no cover
        from developer_agent.assembly import block_text  # type: ignore
    old_idx, new_idx = index_blocks(old_text), index_blocks(new_text)
    if old_idx is None or new_idx is None or [b.keys for b in old_idx] != [b.keys for b in new_idx]:
        return False
    target = f"module.{label}"
    old_mod = new_mod = None
    for ob, nb in zip(old_idx, new_idx):
        if ob.key == target:
            old_mod, new_mod = ob.body or {}, nb.body or {}
        elif block_text(old_text, ob) != block_text(new_text, nb):
            return False
    if old_mod is None:
        return False

    def _attrs(b: Mapping[str, Any]) -> Dict[str, Any]:   # python-hcl2 line metadata (__start_line__ ...) is position
        return {k: v for k, v in b.items() if k != "env_vars" and not (k.startswith("__") and k.endswith("__"))}
    if _attrs(old_mod) != _attrs(new_mod):
        return False
    old_env, new_env = _env_attribute(old_text, label), _env_attribute(new_text, label)
    if old_env is None or new_env is None or new_env[0] != ENV_BIND_MERGE:
        return False
    before = _object_elements(old_env[2], old_text) if old_env[0] == ENV_BIND_MERGE else []
    after = _object_elements(new_env[2], new_text)
    if before is None or after is None:
        return False
    return after == before + [(k, v) for k, v in written.items()]


def bind_module_env(hcl_text: str, label: str, bindings: Mapping[str, str], *,
                    allow_plain: bool = True) -> Tuple[str, List[str]]:
    """FD-55 W5 (register FD55-W5; plan G17 CONVERT): write the `bindings` (env key -> HCL reference) that
    `module "<label>"` does not bind yet into its `env_vars`, by an exact parser edit. Returns (text, written keys);
    the text is returned byte-identical when nothing is written.

    Replaces HB-05's text edits (the `merge(var.env_vars, {` ... `})` body regex over the whole file, the
    `env_vars = var.env_vars` regex, the whole-file `"KEY" =` presence regex and `str.replace` of a block's text).
    Every position comes from python-hcl2's parse tree of `hcl_text`:
      merge  `env_vars = merge(var.env_vars, {<object>})`: the missing keys (exact object keys) are appended after the
             object's last element, one `"KEY" = <ref>` line each, sorted; nothing else in the file changes.
      plain  `env_vars = var.env_vars` (only with `allow_plain`): the value becomes `merge(var.env_vars, {...})`
             holding every binding; the attribute name and its alignment are kept.
    Anything else (no such module, two blocks with the label, no or two `env_vars`, another value shape, a text
    python-hcl2 cannot parse) writes nothing. The edited text is accepted only when _env_edit_is_exact holds
    (Do No Harm): otherwise nothing is written."""
    if not hcl_text or not bindings:
        return hcl_text, []
    got = _env_attribute(hcl_text, label)
    if got is None:
        return hcl_text, []
    form, attr, node = got
    present = _object_keys(node) if form == ENV_BIND_MERGE else set()
    missing = {k: v for k, v in sorted(bindings.items()) if k not in present}
    if not missing or (form == ENV_BIND_PLAIN and not allow_plain):
        return hcl_text, []
    line_start = hcl_text.rfind("\n", 0, attr.meta.start_pos) + 1
    indent = hcl_text[line_start:attr.meta.start_pos]
    if indent.strip():   # the attribute does not start its own line: no layout to follow, nothing is written
        return hcl_text, []
    lines = "\n".join(f'{indent}  "{k}" = {v}' for k, v in missing.items())
    s, e = node.meta.start_pos, node.meta.end_pos
    if form == ENV_BIND_MERGE:
        if hcl_text[s:s + 1] != "{" or hcl_text[e - 1:e] != "}":
            return hcl_text, []
        inner = hcl_text[s + 1:e - 1]
        new_text = hcl_text[:s + 1] + inner.rstrip() + "\n" + lines + "\n" + indent + hcl_text[e - 1:]
    else:
        if hcl_text[s:e].strip() != "var.env_vars":
            return hcl_text, []
        new_text = hcl_text[:s] + "merge(var.env_vars, {\n" + lines + "\n" + indent + "})" + hcl_text[e:]
    if not _env_edit_is_exact(hcl_text, new_text, label, missing):
        return hcl_text, []
    return new_text, list(missing)


def structural_arcs(hcl_texts: List[Optional[str]], label_tokens: Mapping[str, str]
                    ) -> Set[Tuple[str, str, str, str, str]]:
    """(reader token, target token, reader module label, env key, target label) for every env_vars element written in
    HCL whose value is exactly `module.<label>.service_uri` between two known compute modules: edges of the real
    Terraform graph that HB-05 did not decide (AI-written or hand-wired; code RT F1)."""
    out: Set[Tuple[str, str, str, str, str]] = set()
    for text in hcl_texts:
        for label, elems in module_env_refs(text).items():
            a = label_tokens.get(label)
            if a is None:
                continue
            for key, tr in elems.items():
                if tr and len(tr) == 3 and tr[0] == "module" and tr[2] == "service_uri" and tr[1] in label_tokens \
                        and label_tokens[tr[1]] != a:
                    out.add((a, label_tokens[tr[1]], label, key, tr[1]))
    return out


def service_py_files(app_files: Optional[Mapping[str, str]], service: Optional[str]) -> Dict[str, str]:
    """The `.py` files of one service: `apps/<dir>/...` with _norm(<dir>) == _norm(service) (exact equality)."""
    if not app_files or not service:
        return {}
    want = _norm(service)
    out: Dict[str, str] = {}
    for p, t in app_files.items():
        if not (isinstance(p, str) and isinstance(t, str) and p.endswith(".py") and p.startswith("apps/")):
            continue
        parts = p.split("/")
        if len(parts) >= 3 and parts[1] and _norm(parts[1]) == want:
            out[p] = t
    return out


def resolve_caller(app_files: Optional[Mapping[str, str]], siblings: List[SiblingModule]) -> Optional[str]:
    """No caller name: the single service of the platform inventory that is not a sibling, else None."""
    if not app_files:
        return None
    sib = {_norm(s.service) for s in siblings}
    rest = [s for s in detect_workload_services(dict(app_files), "") if s and _norm(s) not in sib]
    return rest[0] if len(rest) == 1 else None


def _cyclic_components(nodes: List[str], arcs: Set[Tuple[str, str]]) -> Dict[str, int]:
    """node -> component id for every node in a strongly connected component of size > 1: a and b share a component
    iff each reaches the other (the graphs are a handful of services, so plain reachability is enough)."""
    adj: Dict[str, Set[str]] = {n: {b for a, b in arcs if a == n} for n in nodes}
    reach: Dict[str, Set[str]] = {}
    for n in nodes:
        seen: Set[str] = set()
        todo = list(adj.get(n, ()))
        while todo:
            v = todo.pop()
            if v not in seen:
                seen.add(v)
                todo.extend(adj.get(v, ()))
        reach[n] = seen
    out: Dict[str, int] = {}
    for cid, n in enumerate(nodes):
        if n in out:
            continue
        ring = [m for m in nodes if m != n and m in reach[n] and n in reach[m]]
        if ring:
            for m in [n] + ring:
                out[m] = cid
    return out


@dataclass
class SiblingWiring:
    caller: Optional[str]                                        # resolved caller service (None = unresolved)
    caller_files: List[str] = field(default_factory=list)
    targets: List[SiblingModule] = field(default_factory=list)   # siblings other than the caller
    bindings: Dict[str, str] = field(default_factory=dict)       # env key -> module.<label>.service_uri
    unbound: List[Dict[str, Any]] = field(default_factory=list)
    withheld: List[Dict[str, Any]] = field(default_factory=list)


def plan_sibling_wiring(hcl_text: Optional[str], app_files: Optional[Mapping[str, str]],
                        caller_service: Optional[str] = None, *, caller_module: Optional[str] = None,
                        main_tf: Optional[str] = None) -> SiblingWiring:
    """The sibling `service_uri` env bindings of one caller (see the module docstring). `caller_module` is the
    caller's module label when known: a primary label ("compute"/"app") is never a binding target of the other
    services; any other caller is a potential target (a secondary being synthesized may not be in `hcl_text` yet).
    `main_tf` (when known) names the primary's service, so env_vars references written in HCL that point at
    `module.compute` join the cycle graph (code RT F1)."""
    siblings = sibling_compute_modules(hcl_text)
    caller = caller_service or resolve_caller(app_files, siblings)
    caller_tok = service_token(caller) if caller else None
    targets = [s for s in siblings if s.token != caller_tok]
    files = service_py_files(app_files, caller)
    reads = env_reads(files) if files else set()
    plan = SiblingWiring(caller=caller, caller_files=sorted(files), targets=targets)

    # Invariant 6 graph. Nodes: the siblings, a non-primary caller (it may not be declared yet) and the primary when
    # its service is known. Read arcs: a node reads one of a SIBLING's four keys exactly (the primary is never a
    # binding target). Structural arcs (code RT F1): env_vars elements already written in HCL whose value is exactly
    # module.<label>.service_uri, including references to module.compute.
    is_primary_caller = caller_module in PRIMARY_MODULE_LABELS
    primary = caller if is_primary_caller else primary_caller_service(main_tf)
    node_svc: Dict[str, str] = {s.token: s.service for s in siblings}
    if caller_tok and caller_tok not in node_svc:
        node_svc[caller_tok] = caller  # type: ignore[assignment]
    if primary and service_token(primary) not in node_svc:
        node_svc[service_token(primary)] = primary
    node_reads = {t: (reads if t == caller_tok else env_reads(service_py_files(app_files, svc)))
                  for t, svc in node_svc.items()}
    sib_tokens = {s.token for s in siblings}
    if caller_tok and not is_primary_caller:
        sib_tokens.add(caller_tok)
    arcs = {(a, b) for a in node_svc for b in sib_tokens
            if a != b and any(k in node_reads[a] for k in uri_keys(b))}
    label_tokens = {m.label: m.token for m in compute_cloudrun_modules(hcl_text)}
    if primary:   # bcd RT F9: every primary label ("compute", "app") is the primary's node for structural arcs
        for lab in PRIMARY_MODULE_LABELS:
            label_tokens.setdefault(lab, service_token(primary))
    if caller_tok and caller_module and caller_module not in label_tokens:
        label_tokens[caller_module] = caller_tok
    structural = structural_arcs([hcl_text, main_tf], label_tokens)
    arcs |= {(a, b) for a, b, _l, _k, _t in structural}
    cyclic = _cyclic_components(sorted(node_svc), arcs)

    target_keys = {k for t in targets for k in uri_keys(t.token)}
    unmatched = sorted(k for k in reads if k.endswith(URI_SUFFIXES) and k not in target_keys)
    for t in targets:
        read = [k for k in uri_keys(t.token) if k in reads]
        if read and caller_tok in cyclic and cyclic.get(t.token) == cyclic[caller_tok]:
            ring = sorted(n for n, c in cyclic.items() if c == cyclic[caller_tok])
            in_ring = set(ring)
            hcl_refs = sorted(f"module.{lab}: {key} = module.{tgt}.service_uri"
                              for a, b, lab, key, tgt in structural if a in in_ring and b in in_ring)
            for k in read:
                plan.withheld.append({"caller": caller, "sibling": t.service, "sibling_module": t.address,
                                      "key": k, "cycle": [node_svc[n] for n in ring], "hcl_refs": hcl_refs,
                                      "files": sorted(p for p, txt in files.items() if k in env_reads({p: txt}))})
            continue
        if read:
            for k in read:
                plan.bindings[k] = t.uri_ref
            continue
        if not files:
            reason = REASON_CALLER_UNRESOLVED
        elif unmatched:
            reason = REASON_NO_TOKEN_MATCH
        else:
            reason = REASON_NOT_READ
        plan.unbound.append({"caller": caller, "sibling": t.service, "sibling_module": t.address, "reason": reason,
                             "candidate_keys": list(uri_keys(t.token)), "unmatched_uri_reads": unmatched})
    for m in compute_cloudrun_modules(hcl_text):
        if not m.addressable and m.token != caller_tok:
            plan.unbound.append({"caller": caller, "sibling": m.service, "sibling_module": m.address,
                                 "reason": REASON_NOT_ADDRESSABLE, "candidate_keys": list(uri_keys(m.token)),
                                 "unmatched_uri_reads": unmatched})
    return plan

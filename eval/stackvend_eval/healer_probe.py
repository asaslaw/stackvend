"""Healer instrumentation without editing healers (plan §4; red-team H1, H2, H9).

function targets  every binding whose value IS the target function object (module globals incl. `from x import f`
                  re-bindings, class __dict__ entries, staticmethod/classmethod descriptors) is replaced by one
                  wrapper. The wrapper calls the healer with the ORIGINAL arguments (in-place mutation semantics are
                  preserved); a deep copy is taken only as the before-snapshot.
inline targets    line ranges inside large functions (e.g. HA-10 inside generate_code_files) are counted with
                  sys.monitoring LINE events restricted to the enclosing code objects -> `reached` counts.
                  Fires for inline rows are attributed from checkpoint diffs, not per row.
audit             after patching, gc.get_referrers lists references to an original that were NOT rebound
                  (lists, dicts, partials, closures) so coverage gaps are visible.

Classification of fired events (syntax-valid / validate-valid / unknown) happens post hoc in the scoring child
from the stored snapshots (H1); the generation child cannot run tofu.

Healers-off mode (checkpoint C1): a non-tier-D target listed in IDENTITY_CONTRACTS is replaced by an identity stub
that returns exactly what the real healer returns when it changes nothing (see the table). The contract is checked
against the live callable at install time (named parameter present, declared return type of the stated shape); a
target without a contract, or whose contract no longer matches, keeps running and is reported, never guessed.
"""
from __future__ import annotations

import copy
import functools
import gc
import importlib
import inspect
import sys
import threading
import types
from typing import Any, Dict, List, Optional, Tuple

from .blobs import BlobStore, sha
from .state import RunState

MONITOR_TOOL_ID = 3

# Healers-off identity contracts (checkpoint C1), keyed by __qualname__. Each row was read from the healer's code
# (product 44a2747; the gateway is unchanged at 429bb6f) and states what it returns on its no-change path:
#   ("arg", p)        p itself                 str rewriters: `if not <p>: return <p>` / unchanged `return <p>`
#   ("copy", p)       dict(p)                  verifier cures: `updated = dict(files) ... return updated`
#   ("copy_list", p)  (dict(p), [])            `healed_files = dict(files); actions = [] ... return (healed_files, actions)`
#   ("str_list", p)   (p, [])                  `return (content, [])` / `return (hcl_text, actions)` with no actions
#   ("str_false", p)  (p, False)               `return (hcl_text, False)`
#   ("none", p)       None, p left untouched   in-place mutators of the files dict
#   ("empty_dict", p) {}                       extract_custom_resource_env_vars: `env_vars = {} ... return env_vars`
#                                              (an extractor, not a rewriter of p: "off" = nothing auto-wired)
#   ("opt_arg", p)    p, or None when p is ""  Optional[str] extractors whose no-change result is their input:
#                                              extract_bespoke_custom_resources (HB-03) `if not raw_hcl: return None`,
#                                              otherwise every block kept = the input text (S1-0, Step 1 RT F1)
# Rows whose healer no longer exists in the product checkout under test (deleted upstream, e.g. by lane 8 Part A)
# stay in the table so replays against older product roots (44a2747) keep their contracts; the contract test
# only requires that every row is either used or names a function absent from that checkout.
# The previous rule (return the first str/dict argument, whatever the declared type) handed
# extract_custom_resource_env_vars(custom_tf_content: str, ...) -> Dict its str argument, so
# terraform_engine.format_hcl_env_vars crashed with "'str' object has no attribute 'items'" on every run.
IDENTITY_CONTRACTS: Dict[str, Tuple[str, str]] = {
    # str -> str
    "strip_hcl_resource_block": ("arg", "hcl_text"),              # hcl_utils.py:573 (x2 replicas)
    "sanitize_hcl_wif": ("arg", "hcl_text"),                      # hcl_utils.py:158
    "inject_gke_workload_identity_bindings": ("arg", "content"),  # preflight_validator.py:1390
    "sanitize_hcl_triggers": ("arg", "hcl_text"),                 # handler.py:1010
    "sanitize_gcp_naming_invariants": ("arg", "content"),         # preflight_validator.py:1207
    "sanitize_self_referential_hcl_blocks": ("arg", "content"),   # preflight_validator.py:1311
    "inject_cloud_run_timeouts": ("arg", "content"),              # preflight_validator.py:2418
    "standardize_requirements": ("arg", "req_content"),           # handler.py:692
    "ensure_health_check_endpoint": ("arg", "py_content"),        # handler.py:664
    "sanitize_python_paths": ("arg", "py_content"),               # handler.py:565
    "pre_ast_normalize": ("arg", "code"),                         # ast_transformer.py:76
    "heal_try_fallback_labels": ("arg", "code"),                  # ast_transformer.py:57
    "heal_multiline_with_statements": ("arg", "code"),            # ast_transformer.py:17
    "_strip_hcl_comments": ("arg", "hcl_text"),                   # module_inspector.py:15
    # Dict -> Dict (fresh copy)
    "SynthesisVerifierAgent.reconcile_iac_environment_contracts": ("copy", "files"),  # verifier.py:573
    "SynthesisVerifierAgent.cure_service_account_ids": ("copy", "files"),             # verifier.py:774
    "SynthesisVerifierAgent.reconcile_service_requirements": ("copy", "files"),       # verifier.py:328
    "SynthesisVerifierAgent.cure_gce_resource_uris": ("copy", "files"),               # verifier.py:721
    "SynthesisVerifierAgent.cure_syntax_errors": ("copy", "files"),                   # verifier.py:890
    # Dict -> (Dict, List)
    "sanitize_duplicate_gke_clusters": ("copy_list", "files"),          # preflight_validator.py:2469
    "sanitize_multiservice_compute_coverage": ("copy_list", "files"),   # preflight_validator.py:2579
    "hydrate_kubernetes_manifests": ("copy_list", "files"),             # preflight_validator.py:2713
    "auto_wire_network_graph_dependencies": ("copy_list", "files"),     # hcl_utils.py:1165
    "deduplicate_semantic_hcl_resources": ("copy_list", "files"),       # hcl_utils.py:606
    "deduplicate_semantic_hcl_blocks": ("copy_list", "files"),          # hcl_utils.py:1030
    # str -> (str, List) / (str, bool)
    "self_correct_hcl_syntax": ("str_list", "content"),                 # hcl_utils.py:469
    "sanitize_hcl_locals_invariants": ("str_list", "content"),          # hcl_utils.py:773
    "coerce_hcl_metadata_maps": ("str_list", "hcl_text"),               # hcl_utils.py:991
    "heal_orphaned_resource_syntax": ("str_false", "hcl_text"),         # hcl_utils.py:108
    "_ensure_resource_depends_on": ("str_false", "block_text"),         # hcl_utils.py:1125
    # in-place mutators -> None
    "reconcile_multi_service_declarations": ("none", "files"),          # terraform_engine.py:428
    "enforce_container_contract": ("none", "files"),                    # handler.py:730
    # extractor -> Dict
    "extract_custom_resource_env_vars": ("empty_dict", "custom_tf_content"),  # terraform_engine.py:1194
    # extractor -> Optional[str] (S1-0: HB-03 identity contract, Step 1 RT F1)
    "extract_bespoke_custom_resources": ("opt_arg", "raw_hcl"),            # terraform_engine.py:1948
}

# kind -> (declared return shape it requires, required type of the named argument or None)
_KIND_RULES: Dict[str, Tuple[str, Optional[type]]] = {
    "arg": ("str", str), "copy": ("dict", dict), "copy_list": ("tuple[dict,list]", dict),
    "str_list": ("tuple[str,list]", str), "str_false": ("tuple[str,bool]", str), "none": ("none", dict),
    "empty_dict": ("dict", None), "opt_arg": ("optional", str),
}
_NO_STUB = object()


def _split_top(text: str) -> List[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        depth += ch in "[("
        depth -= ch in "])"
        cur += ch
    out.append(cur)
    return out


def _norm_type(text: str) -> str:
    """'Tuple[Dict[str, str], List[str]]' -> 'tuple[dict,list]' (outer shape only; type text, not product data)."""
    text = text.replace("typing.", "").replace(" ", "").lower()
    if text in ("none", "nonetype", "<class'nonetype'>"):
        return "none"
    if text.startswith("<class'") and text.endswith("'>"):
        text = text[7:-2]
    head, _, rest = text.partition("[")
    if head == "tuple" and rest:
        return "tuple[" + ",".join(part.partition("[")[0] for part in _split_top(rest[:-1])) + "]"
    return head


def contract_shape(fn: Any) -> Optional[str]:
    """Normalized outer shape of fn's declared return type ('str', 'dict', 'tuple[dict,list]', 'none', ...)."""
    try:
        ann = inspect.signature(fn).return_annotation
    except (TypeError, ValueError):
        return None
    if ann is inspect.Signature.empty:
        return None
    if ann is None:
        return "none"
    if isinstance(ann, str):
        return _norm_type(ann)
    if getattr(ann, "__origin__", None) is not None:
        return _norm_type(repr(ann))
    return _norm_type(getattr(ann, "__name__", None) or repr(ann))


def check_identity_contract(fn: Any, spec: Tuple[str, str]) -> Optional[str]:
    """None if fn's signature honours spec, else the reason it does not (the stub is then not installed)."""
    kind, param = spec
    rule = _KIND_RULES.get(kind)
    if rule is None:
        return f"unknown identity kind {kind!r}"
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return "no signature"
    if param not in params:
        return f"parameter {param!r} not in signature"
    shape = contract_shape(fn)
    if shape != rule[0]:
        return f"declared return {shape!r} != {rule[0]!r} required by {kind!r}"
    return None


def identity_result(sig: inspect.Signature, spec: Tuple[str, str], args: Tuple[Any, ...],
                    kwargs: Dict[str, Any]) -> Any:
    """What the healer returns when it changes nothing, for this call; _NO_STUB if the call's argument is not of
    the contract's type (the real healer then runs: a stub never fabricates a value of the wrong type)."""
    kind, param = spec
    try:
        bound = sig.bind(*args, **kwargs)
    except TypeError:
        return _NO_STUB
    bound.apply_defaults()
    val = bound.arguments.get(param)
    need = _KIND_RULES[kind][1]
    if need is not None and not isinstance(val, need):
        return _NO_STUB
    if kind == "arg":
        return val
    if kind == "copy":
        return dict(val)
    if kind == "copy_list":
        return dict(val), []
    if kind == "str_list":
        return val, []
    if kind == "str_false":
        return val, False
    if kind == "none":
        return None
    if kind == "empty_dict":
        return {}
    if kind == "opt_arg":
        return val if val else None
    return _NO_STUB


def _ret_shape(fn: Any) -> Optional[str]:
    try:
        ann = inspect.signature(fn).return_annotation
    except (TypeError, ValueError):
        return None
    if ann is inspect.Signature.empty:
        return None
    if isinstance(ann, str):
        text = ann
    elif getattr(ann, "__origin__", None) is not None:  # typing generic: Tuple[...], Dict[...], Optional[...]
        text = repr(ann)
    else:
        text = getattr(ann, "__name__", None) or repr(ann)
    text = str(text).replace("typing.", "").replace(" ", "")
    if ann is None or text in ("None", "NoneType"):
        return "none"  # in-place healer: mutates its dict argument
    if text in ("str",):
        return "str"
    if text.startswith(("Dict[", "dict[")) or text in ("dict", "Dict"):
        return "dict"
    if text.startswith(("Tuple[Dict", "tuple[dict", "Tuple[dict", "tuple[Dict")):
        inner = text.split("[", 1)[1]
        parts = inner.rstrip("]").split("],")
        if len(parts) == 2 and parts[1].startswith(("List", "list")):
            return "dict_list"
    return None


class HealerProbe:
    def __init__(self, state: RunState, targets: List[Dict[str, Any]], gateway_dir: str, blobs: BlobStore,
                 healers_off: bool = False, identity: Optional[Dict[str, Tuple[str, str]]] = None,
                 bypass_ids: Optional[List[str]] = None):
        """healers_off=True stubs every healer with a contract (checkpoint C1). bypass_ids (S1-0, `--bypass-healers`)
        stubs only targets whose exact healer id is listed (e.g. ["HB-03", "HB-04"]); every other healer runs."""
        self.state = state
        self.bypass_ids = frozenset(bypass_ids or ())
        self.identity = IDENTITY_CONTRACTS if identity is None else identity
        self.targets = targets
        self.gateway_dir = gateway_dir.rstrip("/") + "/"
        self.blobs = blobs
        self.healers_off = healers_off or bool(self.bypass_ids)
        self._lock = threading.Lock()
        self._tls = threading.local()
        self._eid = 0
        self.stats: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        self.inline_hits: Dict[str, Dict[str, int]] = {}
        self._inline_map: Dict[Any, List[Tuple[str, int, int, int]]] = {}
        self._originals: Dict[str, Any] = {}
        self._wrappers: Dict[int, Any] = {}
        self.audit: Dict[str, Any] = {}

    # ------------------------------------------------------------------------------------------ install
    def install(self) -> None:
        by_obj: Dict[int, Tuple[Any, List[Dict[str, Any]]]] = {}
        for t in self.targets:
            key = t["key"]
            st = self.stats.setdefault(key, {"key": key, "id": t["healer_id"], "tier": t["tier"], "kind": t["kind"],
                                             "file": t.get("file"), "qualname": t.get("qualname") or t.get("enclosing"),
                                             "status": t.get("status"), "calls": 0, "fires": 0, "bindings": 0,
                                             "reached": 0, "lines_hit": 0, "healers_off": None})
            if t.get("deleted_by"):   # FD-55 W0: retired on purpose (eval/config/healer_deletions.json, code gone)
                st["deleted_by"] = t["deleted_by"]
            if t["kind"] not in ("function", "inline") or t.get("status") not in ("present", "anchored"):
                continue
            mod = self._import(t.get("module"))
            if mod is None:
                st["status"] = "absent_module"
                continue
            if t["kind"] == "function":
                fn = self._resolve(mod, t["qualname"])
                if fn is None:
                    st["status"] = "absent"
                    continue
                # Wrap the object exactly as bound (a product decorator's wrapper is what callers reach).
                by_obj.setdefault(id(fn), (fn, []))[1].append(t)
            else:
                enc = self._resolve(mod, t["enclosing"])
                if enc is None:
                    st["status"] = "absent"
                    continue
                self._register_inline(t, enc)
        work = list(by_obj.values())
        by_obj.clear()
        while work:
            raw_fn, tlist = work.pop()
            self._wrap_function(raw_fn, tlist)
        raw_fn = tlist = None  # drop loop references before the referrer audit
        if self._inline_map:
            self._start_monitoring()
        self._audit_referrers()

    def _import(self, modname: Optional[str]) -> Optional[types.ModuleType]:
        if not modname:
            return None
        if modname in sys.modules:
            return sys.modules[modname]
        try:
            return importlib.import_module(modname)
        except Exception as e:  # noqa: BLE001
            self.state.record("probe_import_failed", {"module": modname, "error": repr(e)[:200]})
            return None

    @staticmethod
    def _resolve(mod: Any, qualname: Optional[str]) -> Any:
        if not qualname:
            return None
        obj = mod
        parts = qualname.split(".")
        for i, p in enumerate(parts):
            if isinstance(obj, type) and i == len(parts) - 1:
                return obj.__dict__.get(p, getattr(obj, p, None))
            obj = getattr(obj, p, None)
            if obj is None:
                return None
        return obj

    # ---------------------------------------------------------------------------------------- wrapping
    def _wrap_function(self, raw: Any, ts: List[Dict[str, Any]]) -> None:
        descriptor = None
        if isinstance(raw, (staticmethod, classmethod)):
            descriptor = type(raw)
            raw = raw.__func__
        keys = [t["key"] for t in ts]
        shape = _ret_shape(raw)
        try:
            annotated = inspect.signature(raw).return_annotation is not inspect.Signature.empty
        except (TypeError, ValueError):
            annotated = False
        # Tier D rows are guessers/classifiers by inventory definition; a callable whose declared return type is
        # not str / Dict / Tuple[Dict, List] (e.g. Optional[str] lookups, (owner, repo) tuples) cannot be a
        # code/tree rewriter, so it is observed (calls) but never counted as firing.
        role = "classifier" if (all(t["tier"] == "D" for t in ts) or (annotated and shape is None)) else "rewriter"
        params = list(inspect.signature(raw).parameters)
        is_method = bool(params) and params[0] in ("self", "cls") and descriptor is not staticmethod
        probe = self
        spec = None
        off_status = None
        if self.healers_off:
            spec = self.identity.get(getattr(raw, "__qualname__", ""))
            if self.bypass_ids and not any(t["healer_id"] in self.bypass_ids for t in ts):
                spec, off_status = None, "running: not in --bypass-healers"
            elif all(t["tier"] == "D" for t in ts):
                spec, off_status = None, "unsupported: tier D (classifier, always runs)"
            elif spec is None:
                off_status = "unsupported: no identity contract"
            else:
                why = check_identity_contract(raw, spec)
                if why is not None:
                    self.state.record("healers_off_contract_mismatch", {"keys": keys, "spec": list(spec), "why": why})
                    spec, off_status = None, f"unsupported: contract mismatch ({why})"
                else:
                    off_status = "bypassed"
        sig = inspect.signature(raw) if spec is not None else None
        for k in keys:
            self.stats[k]["healers_off"] = off_status
            self.stats[k]["identity"] = list(spec) if spec is not None else None
            self.stats[k]["bypass_fallbacks"] = 0
            self.stats[k]["role"] = role
            self.stats[k]["ret_shape"] = shape

        @functools.wraps(raw)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return probe._invoke(raw, keys, role, shape, is_method, spec, sig, args, kwargs)

        wrapper.__stackvend_probe__ = True  # type: ignore[attr-defined]
        replacement = descriptor(wrapper) if descriptor else wrapper
        self._originals[keys[0]] = raw
        self._wrappers[id(wrapper)] = wrapper
        n = self._rebind(raw, replacement, wrapper, descriptor)
        for k in keys:
            self.stats[k]["bindings"] = n

    def _rebind(self, raw: Any, replacement: Any, wrapper: Any, descriptor: Any) -> int:
        n = 0
        for mod in list(sys.modules.values()):
            d = getattr(mod, "__dict__", None)
            if not isinstance(d, dict):
                continue
            for name, val in list(d.items()):
                if val is raw:
                    setattr(mod, name, wrapper)
                    n += 1
                elif isinstance(val, type) and getattr(val, "__module__", None) == mod.__name__:
                    for cname, cval in list(val.__dict__.items()):
                        if cval is raw:
                            setattr(val, cname, wrapper)
                            n += 1
                        elif isinstance(cval, (staticmethod, classmethod)) and cval.__func__ is raw:
                            setattr(val, cname, type(cval)(wrapper))
                            n += 1
        return n

    def _payload(self, args: Tuple[Any, ...], kwargs: Dict[str, Any], is_method: bool) -> Any:
        pos = list(args[1:] if is_method else args)
        for v in pos + list(kwargs.values()):
            if isinstance(v, (str, dict)):
                return v
        return None

    def _caller_tree(self, payload: str) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
        """For str healers called per file (`files[p] = healer(files[p])`): find the caller's dict that holds
        this exact string object (identity, not content search) to recover the path and the full tree."""
        f = sys._getframe(4)  # 0 this, 1 _record_fire, 2 _invoke, 3 wrapper, 4 the healer's caller
        depth = 0
        while f is not None and depth < 4:
            for v in list(f.f_locals.values()):
                if isinstance(v, dict) and 0 < len(v) < 5000:
                    for k, s in v.items():
                        if s is payload and isinstance(k, str):
                            return k, {kk: vv for kk, vv in v.items() if isinstance(kk, str) and isinstance(vv, str)}
            f = f.f_back
            depth += 1
        return None, None

    def _invoke(self, raw: Any, keys: List[str], role: str, shape: Optional[str], is_method: bool,
                spec: Optional[Tuple[str, str]], sig: Optional[inspect.Signature],
                args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Any:
        stack = getattr(self._tls, "stack", None)
        if stack is None:
            stack = self._tls.stack = []
        payload = self._payload(args, kwargs, is_method)
        before = copy.deepcopy(payload) if isinstance(payload, (str, dict)) else None
        with self._lock:
            self._eid += 1
            eid = self._eid
            for k in keys:
                self.stats[k]["calls"] += 1
        parent = stack[-1] if stack else None
        stack.append(eid)
        try:
            result = identity_result(sig, spec, args, kwargs) if spec is not None else _NO_STUB
            if result is _NO_STUB:
                if spec is not None:
                    with self._lock:
                        for k in keys:
                            self.stats[k]["bypass_fallbacks"] += 1
                result = raw(*args, **kwargs)
        finally:
            stack.pop()
        if role == "classifier" or before is None:
            return result
        after: Any = None
        actions: Any = None
        if isinstance(result, type(before)):
            after = result
        elif isinstance(before, dict) and isinstance(result, tuple) and result and isinstance(result[0], dict):
            after = result[0]
            actions = result[1] if len(result) > 1 else None
        elif result is None or isinstance(result, (bool, list)):
            after = payload  # in-place healer
            if isinstance(result, list):
                actions = result
        if after is None:
            return result
        if isinstance(before, dict) and after is not payload and before and not (set(before) & set(after)):
            return result  # a different mapping (e.g. extracted env vars), not a rewritten file tree
        fired = after != before or (isinstance(actions, list) and len(actions) > 0)
        if fired:
            self._record_fire(keys, eid, parent, before, after, actions, payload)
        return result

    def _record_fire(self, keys: List[str], eid: int, parent: Optional[int], before: Any, after: Any,
                     actions: Any, payload: Any = None) -> None:
        evt: Dict[str, Any] = {"eid": eid, "parent": parent, "keys": keys, "thread": threading.current_thread().name}
        if isinstance(before, str):
            path, tree = self._caller_tree(payload if isinstance(payload, str) else before)
            evt["payload"] = "text"
            evt["path"] = path
            evt["before_blob"] = self.blobs.put(before)
            evt["after_blob"] = self.blobs.put(after) if isinstance(after, str) else None
            if tree is not None and path is not None:
                bt = dict(tree)
                bt[path] = before
                evt["before_tree"] = self.blobs.put_tree(bt)
        else:
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
            evt["payload"] = "files"
            evt["changed_paths"] = changed[:200]
            evt["before_tree"] = self.blobs.put_tree({k: v for k, v in before.items() if isinstance(v, str)})
            evt["after_changed"] = {k: (self.blobs.put(after[k]) if isinstance(after.get(k), str) else None)
                                    for k in changed[:200]}
        if isinstance(actions, list):
            evt["actions"] = [str(a)[:200] for a in actions[:20]]
        with self._lock:
            self.events.append(evt)
            for k in keys:
                self.stats[k]["fires"] += 1

    # ------------------------------------------------------------------------------------------- inline
    def _register_inline(self, t: Dict[str, Any], enc: Any) -> None:
        fn = enc.__func__ if isinstance(enc, (staticmethod, classmethod)) else enc
        fn = inspect.unwrap(fn)
        code = getattr(fn, "__code__", None)
        if code is None:
            self.stats[t["key"]]["status"] = "absent"
            return
        for a, b in t.get("lines_pinned") or []:
            for c in self._walk_codes(code):
                lines = sorted({ln for (_, _, ln) in c.co_lines() if ln is not None and a <= ln <= b})
                if lines:
                    self._inline_map.setdefault(c, []).append((t["key"], a, b, lines[0]))

    @staticmethod
    def _walk_codes(code: types.CodeType):
        yield code
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                yield from HealerProbe._walk_codes(const)

    def _start_monitoring(self) -> None:
        mon = sys.monitoring
        try:
            mon.use_tool_id(MONITOR_TOOL_ID, "stackvend-eval-probe")
        except ValueError:
            self.state.record("probe_monitoring_unavailable", "tool id in use")
            return
        probe = self

        def on_line(code: types.CodeType, line: int) -> Any:
            entries = probe._inline_map.get(code)
            if not entries:
                return mon.DISABLE
            hit = False
            for key, a, b, first in entries:
                if a <= line <= b:
                    hit = True
                    st = probe.stats[key]
                    st["lines_hit"] += 1
                    if line == first:
                        st["reached"] += 1
            return None if hit else mon.DISABLE

        mon.register_callback(MONITOR_TOOL_ID, mon.events.LINE, on_line)
        for code in self._inline_map:
            mon.set_local_events(MONITOR_TOOL_ID, code, mon.events.LINE)

    def stop(self) -> None:
        try:
            mon = sys.monitoring
            if mon.get_tool(MONITOR_TOOL_ID) == "stackvend-eval-probe":
                for code in self._inline_map:
                    mon.set_local_events(MONITOR_TOOL_ID, code, 0)
                mon.register_callback(MONITOR_TOOL_ID, mon.events.LINE, None)
                mon.free_tool_id(MONITOR_TOOL_ID)
        except Exception:
            pass

    # -------------------------------------------------------------------------------------------- audit
    def _audit_referrers(self) -> None:
        ignore = {id(self._originals), id(self.__dict__)}
        for w in self._wrappers.values():
            ignore.add(id(w.__dict__))
        unpatched: Dict[str, List[str]] = {}
        frame = sys._getframe()
        for key, raw in self._originals.items():
            kinds = []
            for r in gc.get_referrers(raw):
                if id(r) in ignore or r is frame or isinstance(r, (types.FrameType, types.CellType)):
                    continue
                if isinstance(r, dict) and r.get("__wrapped__") is raw:
                    continue
                if isinstance(r, (staticmethod, classmethod)):
                    continue
                if isinstance(r, types.MethodType):
                    kinds.append("bound_method")
                elif isinstance(r, functools.partial):
                    kinds.append("partial")
                elif isinstance(r, dict):
                    kinds.append("dict:" + ("module" if "__name__" in r and "__builtins__" in r else "other"))
                elif isinstance(r, tuple):
                    if len(r) == 2 and isinstance(r[0], str) and r[1] is raw:
                        continue  # a (key, value) item pair left by a dict-items iteration; any live dict is reported itself
                    kinds.append("tuple:" + ",".join(type(x).__name__ for x in r[:4]))
                else:
                    kinds.append(type(r).__name__)
            if kinds:
                unpatched[key] = kinds
        self.audit = {"unpatched_referrers": unpatched, "count": sum(len(v) for v in unpatched.values())}

    # ------------------------------------------------------------------------------------------ report
    def report(self) -> Dict[str, Any]:
        with self._lock:
            return {"targets": list(self.stats.values()), "events": list(self.events), "audit": self.audit}

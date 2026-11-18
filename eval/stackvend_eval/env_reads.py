"""Exact environment-variable read set of one Python module (Step 2 plan §3.4 D1(3); S2-0 gate before building D1).

Two byte-identical copies (the harness never imports product code): apps/orchestrator-gateway/developer_agent/
env_reads.py (product: HB-05's sibling wiring, S2-D) and eval/stackvend_eval/env_reads.py (harness: S2-0 metrics).
tests/test_s2d_sibling_wiring.py pins the parity. Edit both or neither.

`env_reads(service_files)` is the exact key set of one service's Python files (the S2-D binding input).
`exact_env_reads(py_text)` walks the module's `ast` only (no regex, no substring test on code text) and returns the
keys the code reads from the process environment in one of these exact forms:

  os.environ["K"]                 FORM_ENVIRON_SUBSCRIPT        (Load context only: a write is not a read)
  os.environ.get("K"[, d])        FORM_ENVIRON_GET
  os.getenv("K"[, d])             FORM_OS_GETENV
  environ["K"]                    FORM_IMPORTED_ENVIRON_SUBSCRIPT   only when `environ` is imported from os
  environ.get("K"[, d])           FORM_IMPORTED_ENVIRON_GET         (same)
  getenv("K"[, d])                FORM_IMPORTED_GETENV              only when `getenv` is imported from os
  BaseSettings annotated field    FORM_BASESETTINGS_FIELD

Name resolution uses the module's own import statements, anywhere in the module: `import os` / `import os as m` /
`import os.path` (binds `os`) make `os` / `m` the os module; `from os import environ [as e], getenv [as g]` bind the
imported names. A name that is not bound by such an import (e.g. a local variable called `environ`) is never the
environment. There is no scope analysis: an import anywhere in the module counts for the whole module.

BaseSettings: a class whose bases include `BaseSettings` (a Name, or an Attribute whose attr is `BaseSettings`), or
a module-local subclass (transitively) of such a class, is a settings class. Its keys are its annotated fields
(own and inherited from module-local settings parents; `ClassVar[...]`, `model_config` and `_private` names are not
fields):
  - `Field(alias="K")` / `Field(validation_alias="K")` / `Field(env="K")` with a string literal -> key "K" exactly
    (pydantic-settings does not apply env_prefix to an alias);
  - otherwise (prefix + field name).upper() (pydantic-settings matches case-insensitively by default; with a literal
    `case_sensitive=True` the key is prefix + name as written),
where prefix is a literal `env_prefix` from `model_config = SettingsConfigDict(...)` (or `ConfigDict(...)` / a dict
literal) or from `class Config: env_prefix = "..."`, inherited from a module-local parent when the class sets none.
A non-literal env_prefix, a non-literal alias (incl. AliasChoices/AliasPath/lists) or a non-literal model_config
makes that class's keys unresolved: the class is listed in `unresolved` and none of its keys are added (never
guessed).

Nothing else counts: `config.get("K")`, `request.headers.get("K")`, `row["K"]`, `payload["K"]`, a non-literal key
(`os.getenv(name)`), or an alias of os.environ (`env = os.environ; env["K"]`). Uses of os.environ / imported
environ / getenv that are not one of the counted forms are listed in `uncounted` for visibility (never counted).

Dependency-free (stdlib `ast` only), so the product copy is this file unchanged.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Set

FORM_ENVIRON_SUBSCRIPT = "os.environ[]"
FORM_ENVIRON_GET = "os.environ.get"
FORM_OS_GETENV = "os.getenv"
FORM_IMPORTED_ENVIRON_SUBSCRIPT = "environ[] (from os)"
FORM_IMPORTED_ENVIRON_GET = "environ.get (from os)"
FORM_IMPORTED_GETENV = "getenv (from os)"
FORM_BASESETTINGS_FIELD = "BaseSettings field"

EXACT_FORMS = (FORM_ENVIRON_SUBSCRIPT, FORM_ENVIRON_GET, FORM_OS_GETENV, FORM_IMPORTED_ENVIRON_SUBSCRIPT,
               FORM_IMPORTED_ENVIRON_GET, FORM_IMPORTED_GETENV, FORM_BASESETTINGS_FIELD)

_ALIAS_KWARGS = ("alias", "validation_alias", "env")


@dataclass
class EnvReads:
    keys: Set[str] = field(default_factory=set)
    forms: Dict[str, Set[str]] = field(default_factory=dict)
    basesettings_classes: int = 0
    unresolved: List[Dict[str, object]] = field(default_factory=list)
    uncounted: List[Dict[str, object]] = field(default_factory=list)
    parse_error: Optional[str] = None

    def add(self, key: str, form: str) -> None:
        self.keys.add(key)
        self.forms.setdefault(key, set()).add(form)

    def merge(self, other: "EnvReads") -> "EnvReads":
        for k, fs in other.forms.items():
            for f in fs:
                self.add(k, f)
        self.basesettings_classes += other.basesettings_classes
        self.unresolved.extend(other.unresolved)
        self.uncounted.extend(other.uncounted)
        return self

    def to_json(self) -> Dict[str, object]:
        return {"keys": sorted(self.keys), "forms": {k: sorted(v) for k, v in sorted(self.forms.items())},
                "basesettings_classes": self.basesettings_classes, "unresolved": list(self.unresolved),
                "uncounted": list(self.uncounted), "parse_error": self.parse_error}


@dataclass
class _OsNames:
    os_mods: Set[str]
    environ: Set[str]
    getenv: Set[str]


def _os_names(tree: ast.AST) -> _OsNames:
    names = _OsNames(set(), set(), set())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "os":
                    names.os_mods.add(a.asname or "os")
                elif a.name.startswith("os.") and a.asname is None:
                    names.os_mods.add("os")   # `import os.path` binds the name `os` to the os package
        elif isinstance(node, ast.ImportFrom) and node.module == "os" and not node.level:
            for a in node.names:
                if a.name == "environ":
                    names.environ.add(a.asname or "environ")
                elif a.name == "getenv":
                    names.getenv.add(a.asname or "getenv")
    return names


def _str_const(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _environ_kind(node: ast.AST, names: _OsNames) -> Optional[str]:
    """'os' when node is <os-module>.environ, 'imported' when node is a Name imported as os.environ, else None."""
    if isinstance(node, ast.Attribute) and node.attr == "environ" and isinstance(node.value, ast.Name) \
            and node.value.id in names.os_mods:
        return "os"
    if isinstance(node, ast.Name) and node.id in names.environ:
        return "imported"
    return None


def _call_key(node: ast.Call) -> Optional[str]:
    if node.args:
        return _str_const(node.args[0])
    for kw in node.keywords:
        if kw.arg == "key":
            return _str_const(kw.value)
    return None


def _collect_environ_reads(tree: ast.AST, names: _OsNames, out: EnvReads) -> None:
    counted_nodes: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            kind = _environ_kind(node.value, names)
            if kind is None:
                continue
            counted_nodes.add(id(node.value))
            key = _str_const(node.slice)
            if not isinstance(node.ctx, ast.Load):
                out.uncounted.append({"line": node.lineno, "kind": "environ_subscript_write", "key": key})
            elif key is None:
                out.uncounted.append({"line": node.lineno, "kind": "non_literal_key"})
            else:
                out.add(key, FORM_ENVIRON_SUBSCRIPT if kind == "os" else FORM_IMPORTED_ENVIRON_SUBSCRIPT)
        elif isinstance(node, ast.Call):
            func = node.func
            form = None
            if isinstance(func, ast.Attribute) and func.attr == "get":
                kind = _environ_kind(func.value, names)
                if kind is not None:
                    counted_nodes.add(id(func.value))
                    form = FORM_ENVIRON_GET if kind == "os" else FORM_IMPORTED_ENVIRON_GET
            elif isinstance(func, ast.Attribute) and func.attr == "getenv" and isinstance(func.value, ast.Name) \
                    and func.value.id in names.os_mods:
                counted_nodes.add(id(func))
                form = FORM_OS_GETENV
            elif isinstance(func, ast.Name) and func.id in names.getenv:
                counted_nodes.add(id(func))
                form = FORM_IMPORTED_GETENV
            if form is None:
                continue
            key = _call_key(node)
            if key is None:
                out.uncounted.append({"line": node.lineno, "kind": "non_literal_key", "form": form})
            else:
                out.add(key, form)
    # Visibility only: references to the environment that are not one of the counted forms.
    for node in ast.walk(tree):
        if id(node) in counted_nodes:
            continue
        if _environ_kind(node, names) is not None:
            if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
                continue
            out.uncounted.append({"line": getattr(node, "lineno", None), "kind": "environ_other_use"})
        elif isinstance(node, ast.Attribute) and node.attr == "getenv" and isinstance(node.value, ast.Name) \
                and node.value.id in names.os_mods:
            out.uncounted.append({"line": node.lineno, "kind": "getenv_other_use"})


# ---- BaseSettings ---------------------------------------------------------------------------------------------

def _base_name(b: ast.AST) -> Optional[str]:
    if isinstance(b, ast.Name):
        return b.id
    if isinstance(b, ast.Attribute):
        return b.attr
    if isinstance(b, ast.Subscript):          # Generic[...]-style base: use the subscripted name
        return _base_name(b.value)
    return None


def _is_classvar(ann: ast.AST) -> bool:
    n = ann.value if isinstance(ann, ast.Subscript) else ann
    return (isinstance(n, ast.Name) and n.id == "ClassVar") or (isinstance(n, ast.Attribute) and n.attr == "ClassVar")


def _is_field_call(v: Optional[ast.AST]) -> bool:
    return isinstance(v, ast.Call) and ((isinstance(v.func, ast.Name) and v.func.id == "Field")
                                        or (isinstance(v.func, ast.Attribute) and v.func.attr == "Field"))


_UNSET = object()


def _config_from_mapping(node: ast.AST) -> Dict[str, object]:
    """{'env_prefix': str | None(non-literal), 'case_sensitive': bool | None} from SettingsConfigDict(...) / dict."""
    out: Dict[str, object] = {}
    pairs = []
    if isinstance(node, ast.Call):
        if any(kw.arg is None for kw in node.keywords):
            out["opaque"] = True
        pairs = [(kw.arg, kw.value) for kw in node.keywords if kw.arg is not None]
    elif isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            ks = _str_const(k) if k is not None else None
            if ks is None:
                out["opaque"] = True
                continue
            pairs.append((ks, v))
    else:
        out["opaque"] = True
        return out
    for k, v in pairs:
        if k == "env_prefix":
            out["env_prefix"] = _str_const(v)          # None = non-literal
        elif k == "case_sensitive":
            out["case_sensitive"] = v.value if isinstance(v, ast.Constant) and isinstance(v.value, bool) else None
    return out


def _class_config(cls: ast.ClassDef) -> Dict[str, object]:
    cfg: Dict[str, object] = {}
    for stmt in cls.body:
        target = value = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            target, value = stmt.targets[0].id, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            target, value = stmt.target.id, stmt.value
        if target == "model_config":
            cfg.update(_config_from_mapping(value))
        elif isinstance(stmt, ast.ClassDef) and stmt.name == "Config":
            for s in stmt.body:
                if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                    if s.targets[0].id == "env_prefix":
                        cfg["env_prefix"] = _str_const(s.value)
                    elif s.targets[0].id == "case_sensitive":
                        cfg["case_sensitive"] = s.value.value if isinstance(s.value, ast.Constant) \
                            and isinstance(s.value.value, bool) else None
    return cfg


def _class_fields(cls: ast.ClassDef) -> List[Dict[str, object]]:
    """[{name, alias (str) | alias_nonliteral True}] for the class's own annotated fields."""
    out = []
    for stmt in cls.body:
        if not (isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)):
            continue
        name = stmt.target.id
        if name == "model_config" or name.startswith("_") or _is_classvar(stmt.annotation):
            continue
        rec: Dict[str, object] = {"name": name, "line": stmt.lineno}
        if _is_field_call(stmt.value):
            for kw in stmt.value.keywords:
                if kw.arg in _ALIAS_KWARGS:
                    lit = _str_const(kw.value)
                    if lit is None:
                        rec["alias_nonliteral"] = kw.arg
                    else:
                        rec.setdefault("alias", lit)
                elif kw.arg is None:
                    rec["alias_nonliteral"] = "**kwargs"
        out.append(rec)
    return out


def _collect_basesettings(tree: ast.AST, out: EnvReads) -> None:
    classes = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    by_name: Dict[str, ast.ClassDef] = {}
    for c in classes:
        by_name.setdefault(c.name, c)
    settings: Set[str] = set()
    parents: Dict[str, List[str]] = {}
    changed = True
    while changed:
        changed = False
        for c in classes:
            if c.name in settings:
                continue
            bnames = [_base_name(b) for b in c.bases]
            local_parents = [b for b in bnames if b in settings]
            if "BaseSettings" in bnames or local_parents:
                settings.add(c.name)
                parents[c.name] = local_parents
                changed = True
    seen: Set[str] = set()
    for c in classes:
        if c.name not in settings or c.name in seen:
            continue
        seen.add(c.name)
        out.basesettings_classes += 1
        # effective config and fields, own first, then module-local settings parents (depth-first, MRO-ish)
        chain: List[ast.ClassDef] = []
        stack = [c.name]
        visited: Set[str] = set()
        while stack:
            n = stack.pop(0)
            if n in visited or n not in by_name:
                continue
            visited.add(n)
            chain.append(by_name[n])
            stack.extend(parents.get(n, []))
        cfg: Dict[str, object] = {}
        for k in reversed(chain):                 # parents first, the class itself last (overrides)
            cfg.update(_class_config(k))
        fields: Dict[str, Dict[str, object]] = {}
        for k in reversed(chain):
            for f in _class_fields(k):
                fields[f["name"]] = f
        reasons = []
        if cfg.get("opaque"):
            reasons.append("non_literal_model_config")
        if "env_prefix" in cfg and cfg["env_prefix"] is None:
            reasons.append("non_literal_env_prefix")
        for f in fields.values():
            if f.get("alias_nonliteral"):
                reasons.append(f"non_literal_alias:{f['name']}")
        if reasons:
            out.unresolved.append({"class": c.name, "line": c.lineno, "reasons": reasons,
                                   "fields": sorted(fields)})
            continue
        prefix = cfg.get("env_prefix") or ""
        case_sensitive = cfg.get("case_sensitive") is True
        for f in fields.values():
            if "alias" in f:
                key = str(f["alias"])
            else:
                key = f"{prefix}{f['name']}"
                if not case_sensitive:
                    key = key.upper()
            out.add(key, FORM_BASESETTINGS_FIELD)


def exact_env_reads(py_text: str) -> EnvReads:
    out = EnvReads()
    try:
        tree = ast.parse(py_text)
    except (SyntaxError, ValueError) as e:
        out.parse_error = f"{type(e).__name__}: {e}"[:200]
        return out
    _collect_environ_reads(tree, _os_names(tree), out)
    _collect_basesettings(tree, out)
    return out


def exact_env_reads_files(files: Dict[str, str]) -> EnvReads:
    """Union over several modules (each resolved through its own imports)."""
    total = EnvReads()
    for path in sorted(files):
        r = exact_env_reads(files[path])
        if r.parse_error:
            total.uncounted.append({"file": path, "kind": "parse_error", "error": r.parse_error})
        for item in r.unresolved:
            item.setdefault("file", path)
        total.merge(r)
    return total


def env_reads(service_files: Mapping[str, str]) -> Set[str]:
    """The exact env-read key set of one service: the union of `exact_env_reads` over its `.py` files (other paths and
    non-text values are ignored). Pure; a file that does not parse contributes no keys."""
    py = {p: t for p, t in service_files.items() if p.endswith(".py") and isinstance(t, str)}
    return set(exact_env_reads_files(py).keys)

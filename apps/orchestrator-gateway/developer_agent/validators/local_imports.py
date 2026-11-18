"""V3e-local-imports (register row IMPORT-RESOLVE-GATE, owner 10-28): a local import that names nothing in its target.

Live 10-28 (testplan01-d): swarm juniors write the files of one service independently, against the Wave 0 contract
registry. `handlers.py` did `from schemas import (..., EventAuditRecord, ...)` while the local package
`schemas/__init__.py` neither defined nor re-exported `EventAuditRecord`. Every pre-commit check passed; QA's
`import main` smoke failed, the QA repair round did not find the file, and the run failed. This validator finds that
class before commit, from the source alone, so the repair loop sends the writer an exact instruction.

Read-only and exact (Invariant 2): CPython's `ast` only; generated code is never imported or executed; nothing is
rewritten (Do No Harm). Scope and rules:

* service      = `apps/<svc>/` holding a `.py` file (gatekeeper_agent.requirements_contract.python_services). The
                 import root is `apps/<svc>/`: QA runs `import main` / pytest with cwd and PYTHONPATH = the service dir
                 (apps/qa-runner/sandbox_job.py run_service / _untrusted_env) and Buildpacks run the Procfile from it.
                 A service whose Procfile changes the import root (container._import_root_changed) is not judged.
* importer     = an LLM-owned `.py` file of the service; its imports that run unguarded (container.runtime_imports:
                 not inside `try` with an ImportError handler, not under `if TYPE_CHECKING:`, not in a
                 `with suppress(ImportError):` body), also inside functions.
* local target = `from X import a` / `import X.Y` whose X resolves inside the service with the import system's own
                 order per directory (regular package `X/__init__.py`, then module `X.py`, then namespace dir).
                 Absolute X: its first component must resolve at the service root, must not be a stdlib name
                 (PY.STDLIB_SHADOWED owns those) and must exist at no other directory of the service (a script or a
                 pytest rootdir insertion could put that directory first on sys.path: ambiguous -> not judged).
                 Relative X: resolved from the importer's package; an import that climbs above the service root is
                 V3c-imports' finding (CONTAINER.IMPORT_OUTSIDE_SERVICE), not this one. A namespace package anywhere
                 on the path is not judged (another sys.path entry may contribute to it; a directory of data files
                 counts as one). Third-party / stdlib imports
                 are out of scope (the requirements contract owns them).
* bound names  = what the target binds at module level: def / class / any assignment target (incl. augmented,
                 annotated, walrus, for / with / except / match targets, `type X = ...`), import / `from ... import`
                 (re-exports), names declared `global` in a function, walrus targets in decorators / defaults /
                 annotations / class bases, the attributes every module has (`__name__`, `__file__`, `__dict__`, ...;
                 IMPLICIT_MODULE_ATTRIBUTES), in every branch of if / try / with / loops. `from
                 Y import *` adds Y's bound names, its literal `__all__` and, for a package, its submodules, when Y is a
                 local module that is itself known; otherwise the target is UNKNOWN. A package also provides each of its
                 submodules (`from pkg import submodule`). `__all__` does not restrict `from X import a`.
* unknown      = never reported: the target does not parse (V3a-syntax reports it); it defines or assigns a module-level
                 `__getattr__` or assigns `__path__`; it calls `globals()` anywhere, or `vars()` / `locals()` / `exec` /
                 `eval` at module level; a star import it holds is not judged. A name some service file assigns as an
                 attribute (`mod.Name = ...`) or with `setattr(..., "Name", ...)` is not reported. A service that uses
                 `sys.modules` other than with literal keys outside the service's own top-level names is not judged.

Finding: PY.LOCAL_IMPORT_UNRESOLVED (error) on the importing file and line, `symbol` = the missing name (or dotted
module). The message names the target file; the hint says where the name IS defined in the same service, when it is
(e.g. "defined in schemas/events.py: import it with `from schemas.events import EventAuditRecord`"), else lists the
names the target provides. Every blocking error is routed by repair_loop.Router to the persona that wrote the file.
A finding a repair reveals (the import was not judgeable before, e.g. its target did not parse, and the importing file
is unchanged) is accepted as progress by repair_loop.accept (`unjudged_imports`).
"""
from __future__ import annotations

import ast
import posixpath
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

try:
    from shared.artifact_ownership import Ownership
    from shared.diagnostics import Diagnostic
except ImportError:  # pragma: no cover
    from ...shared.artifact_ownership import Ownership  # type: ignore
    from ...shared.diagnostics import Diagnostic  # type: ignore

try:
    from gatekeeper_agent.pypi_catalog import STDLIB_MODULES
    from gatekeeper_agent.requirements_contract import python_services
except ImportError:  # pragma: no cover - loaded as a sub-package of the gateway root
    from ...gatekeeper_agent.pypi_catalog import STDLIB_MODULES  # type: ignore
    from ...gatekeeper_agent.requirements_contract import python_services  # type: ignore

from .container import _import_root_changed, runtime_imports

CODE = "PY.LOCAL_IMPORT_UNRESOLVED"
VALIDATOR_ID = "V3e-local-imports"
LLM_OWNED = (Ownership.LLM_AUTHORED, Ownership.LLM_DOCUMENT)
MAX_LISTED_NAMES = 40
MAX_DEFINED_IN = 3
# exact builtin calls that read or write the module namespace dynamically
_DYNAMIC_ANYWHERE = frozenset({"globals"})
_DYNAMIC_MODULE_SCOPE = frozenset({"vars", "locals", "exec", "eval"})
_DYNAMIC_NAMES = frozenset({"__getattr__", "__path__"})
# attributes every module object has without binding them (`__path__` on packages; a superset is safe: never reported)
IMPLICIT_MODULE_ATTRIBUTES = frozenset({"__name__", "__doc__", "__file__", "__spec__", "__loader__", "__package__",
                                        "__builtins__", "__cached__", "__dict__", "__path__"})
# sys.modules methods that only read it (any other use of sys.modules makes the service not judged)
_SYS_MODULES_READS = frozenset({"get", "keys", "items", "values", "copy", "__contains__"})
_SYS_MODULES_KEYED = frozenset({"get", "pop", "setdefault", "__contains__", "__getitem__", "__setitem__",
                                "__delitem__"})

PACKAGE, MODULE, NAMESPACE = "package", "module", "namespace"


class _Unknown(Exception):
    """The target's names cannot be known exactly: never reported."""


def _d(**kw: Any) -> Diagnostic:
    kw.setdefault("source", "precommit")
    kw.setdefault("severity", "error")
    kw.setdefault("tool", "ast")
    kw.setdefault("code", CODE)
    return Diagnostic(**kw)


# ------------------------------------------------------------------------------------------------ the module index
class ServiceIndex:
    """The `.py` files of one service and their directories, with parsed trees (cached)."""

    def __init__(self, files: Any, svc: str):
        self.files = files
        self.root = f"apps/{svc}"
        self.py = sorted(p for p in files if p.startswith(self.root + "/") and p.endswith(".py")
                         and isinstance(files.get(p), str))
        dirs: Set[str] = set()
        for p in files:   # every file, not only .py: a directory of data files is still an importable namespace dir
            if not p.startswith(self.root + "/"):
                continue
            d = posixpath.dirname(p)
            while d != self.root and d.startswith(self.root + "/"):
                dirs.add(d)
                d = posixpath.dirname(d)
        self.dirs = frozenset(dirs)            # directories below the root that hold any file at some depth
        self._trees: Dict[str, Optional[ast.Module]] = {}
        self._names: Dict[str, Optional[FrozenSet[str]]] = {}
        self._defined: Dict[str, FrozenSet[str]] = {}

    def tree(self, path: str) -> Optional[ast.Module]:
        if path not in self._trees:
            text = self.files.get(path)
            try:
                self._trees[path] = ast.parse(text) if isinstance(text, str) else None
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                self._trees[path] = None
        return self._trees[path]

    def find(self, directory: str, name: str) -> Optional[Tuple[str, str]]:
        """(kind, path) of `name` in `directory`, in the import system's order: regular package (its `__init__.py`),
        module (`name.py`), namespace directory (the directory)."""
        stem = posixpath.join(directory, name)
        if f"{stem}/__init__.py" in self.files:
            return PACKAGE, f"{stem}/__init__.py"
        if f"{stem}.py" in self.files:
            return MODULE, f"{stem}.py"
        if stem in self.dirs:
            return NAMESPACE, stem
        return None

    def submodules(self, init_path: str) -> Set[str]:
        """Names importable as submodules of the package whose `__init__.py` is `init_path`."""
        pkg = posixpath.dirname(init_path)
        out: Set[str] = set()
        for p in self.py:
            if posixpath.dirname(p) == pkg and p != init_path:
                out.add(posixpath.basename(p)[:-3])
        for d in self.dirs:
            if posixpath.dirname(d) == pkg:
                out.add(posixpath.basename(d))
        return out

    def top_level_elsewhere(self, name: str) -> bool:
        """`name` is also importable from a directory below the root (ambiguous first sys.path entry)."""
        return any(d != self.root and self.find(d, name) is not None for d in self.dirs)

    def module_name(self, path: str) -> str:
        rel = path[len(self.root) + 1:-3].split("/")
        if rel[-1] == "__init__":
            rel = rel[:-1]
        return ".".join(rel)

    def importable(self, path: str) -> bool:
        """`path` is what its dotted name imports from the service root (not shadowed by a same-named package)."""
        name = self.module_name(path)
        if not name or not all(part.isidentifier() for part in name.split(".")):
            return False
        try:
            got = self.resolve_chain(self.root, name)
        except _Unknown:
            return True   # through a namespace package: not judged, keep the plain suggestion
        return got is not None and got[1] == path

    def defined_names(self, path: str) -> FrozenSet[str]:
        """Names `path` DEFINES at module level (bound, not only imported); cached per file."""
        if path not in self._defined:
            tree = self.tree(path)
            if tree is None:
                self._defined[path] = frozenset()
            else:
                bound, _ = module_scope_bindings(tree)
                imported = {a.asname or a.name.split(".")[0] for n in tree.body
                            if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
                self._defined[path] = frozenset(bound - imported)
        return self._defined[path]

    def definition_source(self, path: str, name: str) -> Optional[str]:
        """The source of the top-level def/class/assignment that defines `name` in `path` (for the repair snippet)."""
        tree = self.tree(path)
        for node in (tree.body if tree is not None else []):
            hit = (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name) or \
                  (isinstance(node, (ast.Assign, ast.AnnAssign)) and any(
                      isinstance(t, ast.Name) and t.id == name
                      for t in (node.targets if isinstance(node, ast.Assign) else [node.target])))
            if hit:
                return ast.get_source_segment(self.files[path], node)
        return None

    # -------------------------------------------------------------------------------------------- names
    def names(self, path: str, _stack: Tuple[str, ...] = ()) -> FrozenSet[str]:
        """Names bound at module level in `path` (see the module docstring). Raises _Unknown."""
        if path in self._names:
            got = self._names[path]
            if got is None:
                raise _Unknown(path)
            return got
        if path in _stack:
            raise _Unknown(path)   # a star-import cycle: not judged
        try:
            got = frozenset(self._compute_names(path, _stack + (path,)))
        except _Unknown:
            self._names[path] = None
            raise
        except (RecursionError, MemoryError):
            self._names[path] = None
            raise _Unknown(path)
        self._names[path] = got
        return got

    def _compute_names(self, path: str, stack: Tuple[str, ...]) -> Set[str]:
        tree = self.tree(path)
        if tree is None:
            raise _Unknown(path)
        names, stars = module_scope_bindings(tree)
        if names & _DYNAMIC_NAMES or dynamic_namespace(tree):
            raise _Unknown(path)
        names |= IMPLICIT_MODULE_ATTRIBUTES   # after the dynamic check: `__path__` is only dynamic when assigned
        for node in stars:
            target = self.resolve_from(path, node.module or "", node.level)
            if target is None or target[0] in (NAMESPACE, "missing"):
                raise _Unknown(path)   # a missing star target is the importing module's own finding
            kind, tpath = target
            names |= self.names(tpath, stack)
            names |= literal_all(self.tree(tpath))
            if kind == PACKAGE:
                names |= self.submodules(tpath)
        return names

    # -------------------------------------------------------------------------------------------- resolution
    def resolve_chain(self, base: str, dotted: str) -> Optional[Tuple[str, str]]:
        """Resolve the dotted module `dotted` from directory `base`. None when its FIRST component is not in `base`
        (not local); raises _Unknown through a namespace package; returns ("missing", <dotted prefix>) when a later
        component is not a submodule of the package before it."""
        parts = dotted.split(".") if dotted else []
        directory = base
        found: Optional[Tuple[str, str]] = None
        for i, part in enumerate(parts):
            found = self.find(directory, part)
            if found is None:
                return None if i == 0 else ("missing", ".".join(parts[:i + 1]))
            kind, p = found
            if kind == NAMESPACE:
                raise _Unknown(p)
            if kind == MODULE and i + 1 < len(parts):
                return "missing", ".".join(parts[:i + 2])   # a plain module has no submodules
            directory = posixpath.dirname(p)
        return found

    def resolve_from(self, importer: str, module: str, level: int) -> Optional[Tuple[str, str]]:
        """The local target of `from <level dots><module> import ...` in `importer`, or None (not local / not judged).
        Raises _Unknown for a namespace package; ("missing", dotted) for a missing submodule."""
        if level:
            depth = len(importer[len(self.root) + 1:].split("/")) - 1
            if level > depth:
                return None   # no parent package at that level inside the service: V3c-imports' finding
            base = posixpath.dirname(importer)
            for _ in range(level - 1):
                base = posixpath.dirname(base)
            init = f"{base}/__init__.py"
            if init not in self.files:
                raise _Unknown(base)   # a namespace package: another sys.path entry may contribute to it
            if not module:
                return PACKAGE, init
            got = self.resolve_chain(base, module)
            # inside a regular package, a first component that is not there is a missing submodule
            return ("missing", module.split(".")[0]) if got is None else got
        top = module.split(".")[0]
        if not top or top in STDLIB_MODULES or self.top_level_elsewhere(top):
            return None
        return self.resolve_chain(self.root, module)


# ------------------------------------------------------------------------------------------------ AST helpers
def evaluated_in_enclosing_scope(node: ast.AST) -> List[ast.AST]:
    """The parts of a def / class / lambda that run in the scope that defines it: decorators, argument defaults and
    annotations, return annotation, class bases and keyword values (a walrus there binds a module name)."""
    out: List[ast.AST] = list(getattr(node, "decorator_list", []))
    args = getattr(node, "args", None)
    if isinstance(args, ast.arguments):
        out += list(args.defaults) + [d for d in args.kw_defaults if d is not None]
        for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs) + [args.vararg, args.kwarg]:
            if a is not None and a.annotation is not None:
                out.append(a.annotation)
    if getattr(node, "returns", None) is not None:
        out.append(node.returns)
    if isinstance(node, ast.ClassDef):
        out += list(node.bases) + [k.value for k in node.keywords]
    return out


def module_scope_bindings(tree: ast.Module) -> Tuple[Set[str], List[ast.ImportFrom]]:
    """(names bound at module scope, the module-level `from ... import *` nodes)."""
    names: Set[str] = set()
    stars: List[ast.ImportFrom] = []

    def scoped(node: ast.AST) -> None:   # a def/class/lambda: only its `global` declarations bind module names
        for n in ast.walk(node):
            if isinstance(n, ast.Global):
                names.update(n.names)

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if not isinstance(node, ast.Lambda):
                names.add(node.name)
            for c in evaluated_in_enclosing_scope(node):
                visit(c)
            scoped(node)
            return
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add(a.asname or a.name.split(".")[0])
            return
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "*":
                    stars.append(node)
                else:
                    names.add(a.asname or a.name)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif type(node).__name__ in ("MatchAs", "MatchStar") and getattr(node, "name", None):
            names.add(node.name)
        elif type(node).__name__ == "MatchMapping" and getattr(node, "rest", None):
            names.add(node.rest)
        for c in ast.iter_child_nodes(node):
            visit(c)

    for stmt in tree.body:
        visit(stmt)
    return names, stars


def _call_name(node: ast.AST) -> Optional[str]:
    return node.func.id if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) else None


def dynamic_namespace(tree: ast.Module) -> bool:
    """A builtin that reads or writes the module namespace dynamically (see _DYNAMIC_*)."""
    if any(_call_name(n) in _DYNAMIC_ANYWHERE for n in ast.walk(tree)):
        return True

    def module_scope(node: ast.AST) -> bool:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return any(module_scope(c) for c in evaluated_in_enclosing_scope(node))
        if _call_name(node) in _DYNAMIC_MODULE_SCOPE:
            return True
        return any(module_scope(c) for c in ast.iter_child_nodes(node))

    return any(module_scope(s) for s in tree.body)


def literal_all(tree: Optional[ast.Module]) -> Set[str]:
    out: Set[str] = set()
    for node in (tree.body if tree is not None else []):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets) and \
                    isinstance(node.value, (ast.List, ast.Tuple)):
                out.update(e.value for e in node.value.elts
                           if isinstance(e, ast.Constant) and isinstance(e.value, str))
    return out


def injected_attributes(trees: Iterable[ast.Module]) -> Set[str]:
    """Attribute names any service file assigns (`x.Name = ...`, `setattr(x, "Name", ...)`)."""
    out: Set[str] = set()
    for tree in trees:
        for n in ast.walk(tree):
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Store):
                out.add(n.attr)
            elif _call_name(n) == "setattr" and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) \
                    and isinstance(n.args[1].value, str):
                out.add(n.args[1].value)
    return out


def _sys_aliases(tree: ast.Module) -> Set[str]:
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "sys":
                    out.add(a.asname or "sys")
    return out


def sys_modules_keys(tree: ast.Module) -> Optional[Set[str]]:
    """The literal top-level module names this file reads or writes in `sys.modules`; None when it uses
    `sys.modules` in any other way (or imports `modules` from sys)."""
    aliases = _sys_aliases(tree)
    parents: Dict[int, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parents[id(c)] = p
        if isinstance(p, ast.ImportFrom) and p.module == "sys" and any(a.name in ("modules", "*") for a in p.names):
            return None
    keys: Set[str] = set()

    def literal(node: Any) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            keys.add(node.value.split(".")[0])
            return True
        return False

    def literal_dict(node: Any) -> bool:
        return isinstance(node, ast.Dict) and all(k is not None and literal(k) for k in node.keys)

    def call_with_literal_keys(call: ast.Call, n: ast.AST) -> bool:
        """`f(sys.modules, {"k": v})` / `f(sys.modules, "k", v)` (patch.dict, monkeypatch.setitem): the keys are
        literals. A call whose other arguments hold no literal key at all is not readable."""
        others = [a for a in call.args if a is not n] + [k.value for k in call.keywords]
        keyed = False
        for a in others:
            if isinstance(a, ast.Dict):
                if not literal_dict(a):
                    return False
                keyed = True
            elif literal(a):
                keyed = True
        return keyed

    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and n.value == "sys.modules":   # mock.patch.dict("sys.modules", {...})
            parent = parents.get(id(n))
            if not (isinstance(parent, ast.Call) and n in parent.args and call_with_literal_keys(parent, n)):
                return None
            continue
        if not (isinstance(n, ast.Attribute) and n.attr == "modules" and isinstance(n.value, ast.Name)
                and n.value.id in aliases):
            continue
        parent = parents.get(id(n))
        if isinstance(parent, ast.Subscript) and parent.value is n:
            if not literal(parent.slice):
                return None
        elif isinstance(parent, ast.Attribute) and parent.value is n:
            call = parents.get(id(parent))
            if parent.attr in _SYS_MODULES_READS and parent.attr not in _SYS_MODULES_KEYED:
                continue
            if isinstance(call, ast.Call) and call.func is parent and parent.attr in _SYS_MODULES_KEYED \
                    and call.args and literal(call.args[0]):
                continue
            if isinstance(call, ast.Call) and call.func is parent and parent.attr == "update" and call.args and \
                    all(literal_dict(a) for a in call.args) and not call.keywords:
                continue
            return None
        elif isinstance(parent, ast.Compare) and n in parent.comparators:
            continue   # `"x" in sys.modules`: a read
        elif isinstance(parent, ast.Call) and n in parent.args:
            if not call_with_literal_keys(parent, n):
                return None
        else:
            return None
    return keys


# ------------------------------------------------------------------------------------------------ the validator
def service_not_judged(files: Any, svc: str, idx: ServiceIndex) -> bool:
    """The service's import root is changed by its Procfile, or a file uses `sys.modules` for a service module (or
    in a way that cannot be read): none of its imports is judged."""
    if _import_root_changed(files, svc):
        return True
    local_tops = {posixpath.basename(p)[:-3] for p in idx.py if posixpath.dirname(p) == idx.root} | \
                 {posixpath.basename(d) for d in idx.dirs if posixpath.dirname(d) == idx.root}
    for t in (idx.tree(p) for p in idx.py):
        if t is None:
            continue
        keys = sys_modules_keys(t)
        if keys is None or keys & local_tops:
            return True
    return False


def _judgeable(idx: ServiceIndex, path: str, node: ast.AST) -> bool:
    """False when this import's target is unknown (namespace, unparseable, dynamic, unknown star import)."""
    try:
        if isinstance(node, ast.Import):
            for a in node.names:
                idx.resolve_from(path, a.name, 0)
            return True
        if isinstance(node, ast.ImportFrom):
            target = idx.resolve_from(path, node.module or "", node.level)
            if target is not None and target[0] != "missing":
                idx.names(target[1])
    except _Unknown:
        return False
    return True


def unjudged_imports(files: Any) -> Set[Tuple[str, Optional[int]]]:
    """(file, line) of every unguarded import this validator could not judge on `files`: its target was unknown or
    did not parse, or its service was not judged. Pure (no I/O). repair_loop.accept uses it to tell a finding a repair
    REVEALED (e.g. a syntax fix in the target module) from one it caused."""
    out: Set[Tuple[str, Optional[int]]] = set()
    for svc in python_services(files):
        idx = ServiceIndex(files, svc)
        parsed = [(p, t) for p, t in ((p, idx.tree(p)) for p in idx.py) if t is not None]
        try:
            skipped = service_not_judged(files, svc, idx)
            for p, t in parsed:
                for node in runtime_imports(t):
                    if skipped or not _judgeable(idx, p, node):
                        out.add((p, getattr(node, "lineno", None)))
        except (RecursionError, MemoryError):
            for p, t in parsed:
                out.update((p, getattr(n, "lineno", None)) for n in ast.walk(t)
                           if isinstance(n, (ast.Import, ast.ImportFrom)))
    return out


class LocalImportValidator:
    id, tool = VALIDATOR_ID, "ast"

    def validate(self, ctx: Any) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        for svc in python_services(ctx.files):
            try:
                out.extend(self._service(ctx, svc))
            except (RecursionError, MemoryError):
                continue   # a pathological tree is not judged (never a guessed finding)
        return out

    def _service(self, ctx: Any, svc: str) -> List[Diagnostic]:
        idx = ServiceIndex(ctx.files, svc)
        importers = [p for p in idx.py if ctx.ownership(p) in LLM_OWNED]
        if not importers or service_not_judged(ctx.files, svc, idx):
            return []
        trees = [t for t in (idx.tree(p) for p in idx.py) if t is not None]
        injected = injected_attributes(trees)
        out: List[Diagnostic] = []
        for path in importers:
            tree = idx.tree(path)
            if tree is None:
                continue   # V3a-syntax reports it
            for node in runtime_imports(tree):
                out.extend(self._check(ctx, idx, path, node, injected))
        return out

    def _check(self, ctx: Any, idx: ServiceIndex, path: str, node: ast.AST, injected: Set[str]) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        line = getattr(node, "lineno", None)
        if isinstance(node, ast.Import):
            for a in node.names:
                if "." not in a.name:
                    continue
                try:
                    got = idx.resolve_from(path, a.name, 0)
                except _Unknown:
                    continue
                if got is not None and got[0] == "missing":
                    out.append(self._missing_module(ctx, idx, path, line, got[1]))
            return out
        if not isinstance(node, ast.ImportFrom):
            return out
        try:
            target = idx.resolve_from(path, node.module or "", node.level)
        except _Unknown:
            return out
        if target is None:
            return out
        if target[0] == "missing":
            return [self._missing_module(ctx, idx, path, line, target[1], node)]
        kind, tpath = target
        try:
            bound = idx.names(tpath)
        except _Unknown:
            return out
        subs = idx.submodules(tpath) if kind == PACKAGE else set()
        for a in node.names:
            if a.name == "*" or a.name in bound or a.name in subs or a.name in injected:
                continue
            out.append(self._missing_name(ctx, idx, path, line, a.name, tpath, sorted(bound | subs)))
        return out

    # -------------------------------------------------------------------------------------------- findings
    def _defined_in(self, idx: ServiceIndex, name: str, exclude: Set[str]) -> List[str]:
        """Service modules that DEFINE `name` (not only import it), test files last."""
        found = [p for p in idx.py if p not in exclude and name in idx.defined_names(p)]
        rel = lambda p: p[len(idx.root) + 1:]   # noqa: E731
        is_test = lambda p: "tests" in rel(p).split("/")[:-1] or posixpath.basename(p).startswith("test_") \
            or posixpath.basename(p) == "conftest.py"   # noqa: E731
        return sorted(found, key=lambda p: (is_test(p), p))[:MAX_DEFINED_IN]

    def _missing_name(self, ctx: Any, idx: ServiceIndex, path: str, line: Optional[int], name: str, tpath: str,
                      provided: List[str]) -> Diagnostic:
        rel_t = tpath[len(idx.root) + 1:]
        tmod = idx.module_name(tpath)
        defined = self._defined_in(idx, name, {tpath, path})
        reachable = [p for p in defined if idx.importable(p)]
        snippet = None
        if reachable:
            where = ", ".join(p[len(idx.root) + 1:] for p in reachable)
            hint = (f"`{name}` is defined in {where}: import it from there (`from {idx.module_name(reachable[0])} "
                    f"import {name}`), or re-export it from {rel_t}. Do not import a name its module does not define.")
        elif defined:
            # e.g. the AI's schemas.py beside the package schemas/ (PY.MODULE_PACKAGE_CONFLICT): the package wins, so
            # the module that defines the name is never imported
            src = defined[0]
            rel_s = src[len(idx.root) + 1:]
            hint = (f"`{name}` is defined only in {rel_s}, which is never imported: `{idx.module_name(src)}` is the "
                    f"package {rel_t} (a package wins over a module of the same name), and it does not provide "
                    f"`{name}`. Import from `{tmod}` only names it provides, and define `{name}` (its definition is "
                    f"in the snippet) in this file, or import it from a module with a unique name.")
            snippet = idx.definition_source(src, name)
        else:
            shown = ", ".join(provided[:MAX_LISTED_NAMES]) + (" ..." if len(provided) > MAX_LISTED_NAMES else "")
            hint = (f"No module of apps/{idx.root[5:]}/ defines `{name}`. Import a name {rel_t} provides "
                    f"({shown or 'none'}), define `{name}` in the code that needs it, or remove the import.")
        return _d(file=path, line=line, symbol=name, iteration=ctx.iteration, hint=hint, snippet=snippet,
                  message=f"`{name}` is imported from `{tmod}` ({tpath}), but {rel_t} does not define, import or "
                          f"re-export `{name}`: the import raises ImportError when the module loads (QA's `import "
                          f"main` smoke and the container fail the same way)")

    def _missing_module(self, ctx: Any, idx: ServiceIndex, path: str, line: Optional[int], dotted: str,
                        node: Optional[ast.ImportFrom] = None) -> Diagnostic:
        parent, _, last = dotted.rpartition(".")
        dots = "." * node.level if node is not None and node.level else ""
        shown = dots + dotted
        where = f"`{dots}{parent}`" if parent else f"the package `{dots}` ({posixpath.dirname(path)}/)"
        defined = self._defined_in(idx, last, {path})
        extra = (f" `{last}` is defined in {defined[0][len(idx.root) + 1:]}." if defined else "")
        return _d(file=path, line=line, symbol=shown, iteration=ctx.iteration,
                  hint=f"Import an existing module of the service (relative to apps/{idx.root[5:]}/), or ship "
                       f"the module it names.{extra}",
                  message=f"`{shown}` is not a module of the service: {where} is local to {idx.root}/ and has no "
                          f"submodule `{last}`, so the import raises ModuleNotFoundError when the module loads")


__all__ = ["CODE", "VALIDATOR_ID", "IMPLICIT_MODULE_ATTRIBUTES", "LocalImportValidator", "ServiceIndex",
           "module_scope_bindings", "unjudged_imports", "service_not_judged", "evaluated_in_enclosing_scope",
           "dynamic_namespace", "sys_modules_keys", "literal_all", "injected_attributes"]

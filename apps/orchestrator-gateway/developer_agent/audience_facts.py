"""SIBLING-AUDIENCE-BINDING (option A, docs/implemented/sibling-audience-binding-plan.md): the one fixed ID-token audience
a called Cloud Run service verifies, read from its parsed code.

For an `http` edge the topology binds `<BASE>_AUDIENCE = module.<callee>.service_uri` on the caller (Google's default
service-to-service pattern: the callee verifies its own URL). When the callee's own non-test code verifies Google ID
tokens against exactly one fixed audience L, that binding overrode the caller's correct value (example 02, 401). This
module answers one question from `ast` facts only (Invariant 2): which single str constant does every verifying call
in `apps/<callee>/` pass as its audience? Any doubt (no verifying call, a runtime-computed or missing audience, a list,
two different literals, an unparseable file, a call or API reference it cannot follow, a literal outside the closed
HCL-safe grammar) is not a literal, and the caller keeps today's binding byte-identical (Invariant 1).

Verifying APIs are recognised by the absolute name a call resolves to through imports (closed list; the resolution of
apps/qa-runner/sandbox_job.py `_AuthFile.dotted`, extended to follow the callee's own modules, star imports and
`global` names), never by a name's text. Every name a call may resolve to is considered: a call that may be a
verifying API but cannot be followed, a verifying API used other than as a direct call (an alias, `partial`), and a
module that holds one used as a value (`v = id_token`, `getattr(id_token, ...)`) make the callee unresolved.
`google.oauth2.id_token.verify_token` with `certs_url` (or more than three positional arguments) verifies an IAP
assertion, not a caller's token: unresolved. The audience resolves through a str constant, a module-level name with
exactly one assignment (`Assign` / `AnnAssign`), or a `from x import NAME` of a module the callee itself ships (same
rules in that file). A pydantic-settings field default or a parameter default is unresolved on purpose (the typed
contract for that is FD-7V).

SIBLING-AUDIENCE-GETENV-DEFAULT: an audience that resolves (same rules) to `os.getenv(NAME, L)` or
`os.environ.get(NAME, L)` (the getter resolved through imports like the verifying APIs; NAME and L str constants by
the same rules, no f-string, concatenation or nested call) is the fact LITERAL_ENV_DEFAULT: L holds only while NAME is
unset in the callee's process. That needs two more facts. From the callee's code (part of this cached fact, a pure
function of the tree): no non-test file writes NAME (`os.environ[NAME] = ...`, `setdefault` / `pop` / `putenv` /
`unsetenv` of NAME or of a key that is not a str constant, `update` / `clear` / any other `os.environ` method, the
`os` module or `os.environ` used as a value or rebound), imports `dotenv` or a module named like a test (its code is
not read), binds a module-level `raw_env` (a gunicorn setting), or ships a `.env` / `.flaskenv` / `project.toml` file;
and its Procfile, when it has one, may not set the environment: every line parses, no command assigns a variable
(`NAME=value`, `env NAME=value`, `export` / `source` / `.` / `set` / `eval` ...), the last command of each process
is a launcher the shared Procfile parser knows (gatekeeper_agent/procfile.py `parse_command`: uvicorn / gunicorn /
hypercorn / `python[3] <file>.py` / `python -m <server>`, behind `exec` / `sh -c`), and that launcher gets no
`-e` / `--env` / `--env-file` / `-c` / `--config`. Else unresolved.
From the platform's IaC for the callee (not a tree fact, so never cached here): the edge decision asks
`callee_env_names` (topology_wiring) for every env name the platform sets on the callee and binds L only when NAME is
not one of them; an unknown set or a set that holds NAME keeps today's binding. `os.environ[NAME]` and
`os.getenv(NAME)` (no default) stay unresolved.

Limits, accepted: `importlib.import_module`, `__import__`, `exec` / `eval` and attribute writes on modules are out of
reach of a static reading. Test files are skipped by the repository's workload test-path rule (`test_*.py`,
`*_test.py`, `conftest.py`, anything under `tests/`), so a real module named like a test (`ab_test.py`) is not read;
a non-test file that uses a name such a module may hold as a verifying API is unresolved (for an env default, any
import of one is), so only code nothing imports is missed. For an env default, a library that writes the process
environment by itself (e.g. `environs.read_env`) and `__import__("os")` are out of reach too.

The edge decision (`edge_audience_decisions`) binds the literal only on a public workload (`allow_unauthenticated is
True`): with Cloud Run invoker IAM enforced (`False`) Cloud Run accepts only the service URL as the audience (the
golden `compute-cloudrun` module sets no `custom_audiences`), and an unknown access mode (`None`) fails safe. Facts
are memoized per callee tree content; the env-name check of a LITERAL_ENV_DEFAULT fact runs per decision, uncached.
Pure functions; no I/O, no LLM.
"""
from __future__ import annotations

import ast
import hashlib
import logging
import posixpath
import re
import shlex
import sys
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger("castor-audience-facts")

# Closed API list: absolute name -> positional index of `audience` (google-auth signatures).
VERIFY_APIS: Dict[str, int] = {
    "google.oauth2.id_token.verify_oauth2_token": 2,   # (id_token, request, audience=None, ...)
    "google.oauth2.id_token.verify_token": 2,          # (id_token, request, audience=None, certs_url=..., ...)
    "google.auth.jwt.decode": 3,                       # (token, certs=None, verify=True, audience=None, ...)
}
_JWT_DECODE = "google.auth.jwt.decode"
_JWT_VERIFY_INDEX = 2
_VERIFY_TOKEN = "google.oauth2.id_token.verify_token"
_VERIFY_TOKEN_MAX_ARGS = 3   # (id_token, request, audience): a 4th positional is certs_url (IAP)
# The modules on the way to a verifying API (`google`, `google.oauth2`, `google.oauth2.id_token`, ...): such a module
# object used as a value can reach the API by a route this module does not follow.
_API_MODULES = frozenset(".".join(api.split(".")[:i]) for api in VERIFY_APIS for i in range(1, api.count(".") + 1))
# SIBLING-AUDIENCE-GETENV-DEFAULT: the process-environment names of the standard library (absolute names).
_ENV_GETTERS = ("os.getenv", "os.environ.get")          # (key, default): the env-default audience shape
_ENV_MAPPINGS = ("os.environ", "os.environb")            # read by subscript / get / copy / keys / items / values / `in`
_ENV_SETTERS = ("os.putenv", "os.unsetenv")              # (key, ...): a write of `key`
_ENV_READ_METHODS = frozenset({"get", "copy", "keys", "items", "values"})
_ENV_KEY_WRITE_METHODS = frozenset({"setdefault", "pop"})   # (key, ...): a write of `key` only
_DOTENV = "dotenv"
_ENV_FILES = frozenset({".env", ".flaskenv", "project.toml"})   # exact basenames: env / buildpack start config
_PROCFILE = "Procfile"
_GUNICORN_RAW_ENV = "raw_env"   # a gunicorn setting (gunicorn.conf.py) that sets the server's environment
# Launcher options that pass environment variables or a config file that can (RT F2).
_ENV_OPTIONS = frozenset({"-e", "--env", "--env-file", "-c", "--config"})
# Shell builtins that change the environment of the commands after them in the same shell.
_ENV_BUILTINS = frozenset({"export", "source", ".", "set", "eval", "declare", "typeset", "readonly", "unset",
                           "alias"})
_CMD_SEPARATORS = frozenset({"&&", "||", ";", "|", "&"})
_FACT_CACHE_SIZE = 64
# Closed grammar of an audience the platform writes as an HCL string literal: no `"`, `\`, `$`, `{`, whitespace or
# newline can occur, so `"L"` never interpolates (`${`, `%{`) or escapes. Anything else falls back (UNSAFE_LITERAL).
_HCL_SAFE_LITERAL = re.compile(r"[A-Za-z0-9:/._~%-]{1,256}")
_MAX_NAME_HOPS = 8

LITERAL = "literal"                    # bound: the caller's `<BASE>_AUDIENCE` = "L"
NO_CODE = "no_code"                    # no non-test .py file under apps/<callee>/
NO_VERIFY_CALL = "no_verify_call"      # the callee verifies no Google ID token in code (Cloud Run IAM or own URL)
UNRESOLVED = "unresolved"              # a verifying call whose audience is not one str constant, or a doubt
CONFLICTING = "conflicting_literals"   # two or more different literals
UNSAFE_LITERAL = "unsafe_literal"      # one literal outside the closed HCL-safe grammar
PARSE_ERROR = "parse_error"            # a non-test .py file of the callee does not parse
IAM_ENFORCED = "iam_enforced"          # private workload: Cloud Run accepts only the service URL (edge decision)
ACCESS_UNKNOWN = "access_unknown"      # the workload's access mode was not passed: fail safe (edge decision)
# SIBLING-AUDIENCE-GETENV-DEFAULT
LITERAL_ENV_DEFAULT = "literal_env_default"   # `os.getenv(NAME, L)`: bound when the platform sets no NAME on the callee
ENV_SET_BY_PLATFORM = "env_set_by_platform"   # the platform's IaC sets NAME on the callee (edge decision): URL kept
CALLEE_ENV_UNKNOWN = "callee_env_unknown"     # the callee's full env set is not known (edge decision): URL kept

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


@dataclass(frozen=True)
class AudienceFact:
    """What the callee's code says about the audience it verifies. `literal` is set only for LITERAL and
    LITERAL_ENV_DEFAULT; `env_names` (LITERAL_ENV_DEFAULT only) are the env names that must be unset on the callee for
    `literal` to hold."""
    callee: str
    outcome: str
    literal: Optional[str] = None
    detail: str = ""
    env_names: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AudienceDecision:
    """One `http` edge's `<BASE>_AUDIENCE` decision on the caller: `value` is the HCL expression rendered."""
    caller: str
    callee: str
    env_key: str
    fact: AudienceFact
    value: str


def is_test_path(rel: str) -> bool:
    """The repository's workload test-path rule (apps/qa-runner/sandbox_job.py `is_workload_test_file`)."""
    name = rel.rsplit("/", 1)[-1]
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py" or "/tests/" in f"/{rel}"


class _Unknown:
    """A name that may refer to a verifying API but cannot be followed: the whole callee is unresolved."""


@dataclass(frozen=True)
class _ApiModule:
    """A module object on the way to a verifying API (one of _API_MODULES)."""
    path: str


@dataclass(frozen=True)
class _Targets:
    """The absolute names a resolution looks for (`apis`) and the module objects on the way to them (`modules`)."""
    apis: FrozenSet[str]
    modules: FrozenSet[str]


_VERIFY_TARGETS = _Targets(frozenset(VERIFY_APIS), _API_MODULES)
_ENV_TARGETS = _Targets(frozenset(_ENV_GETTERS + _ENV_MAPPINGS + _ENV_SETTERS), frozenset({"os"}))
_UNKNOWN = _Unknown()
# What an expression names: a VERIFY_APIS key, an _ApiModule, None (provably neither) or _UNKNOWN.
_Api = Any


@dataclass(eq=False)
class _Scope:
    node: ast.AST
    parent: Optional["_Scope"]
    bindings: Dict[str, List[Tuple[str, Any]]] = field(default_factory=dict)


def _scope_nodes(scope_node: ast.AST) -> Iterable[ast.AST]:
    """Every node of one scope without entering a nested def, lambda or class (iterative: no RecursionError)."""
    stack = list(ast.iter_child_nodes(scope_node))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPE_NODES):
            stack.extend(ast.iter_child_nodes(node))


class _File:
    """One parsed callee file: lexical scopes and bindings."""

    def __init__(self, rel: str, tree: ast.Module):
        self.rel = rel
        self.tree = tree
        self._parents: Optional[Dict[int, ast.AST]] = None
        self.poisoned: Set[str] = set()   # `global` / `nonlocal`: rebindable from any scope
        self.star_sources: List[Tuple[int, str]] = []   # (level, module) of each `from module import *`
        self.module = _Scope(tree, None)
        self.scopes = [self.module]
        todo = [self.module]
        while todo:
            scope = todo.pop()
            for child in self._bind(scope):
                inner = _Scope(child, scope)
                self.scopes.append(inner)
                todo.append(inner)

    def _bind(self, scope: _Scope) -> List[ast.AST]:
        def add(name: str, kind: str, payload: Any = None) -> None:
            scope.bindings.setdefault(name, []).append((kind, payload))

        children: List[ast.AST] = []
        simple: Set[int] = set()
        for node in _scope_nodes(scope.node):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        add(a.asname, "import", a.name)
                    else:
                        add(a.name.split(".")[0], "import", a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name == "*":
                        self.star_sources.append((node.level, node.module or ""))
                    elif node.level == 0 and node.module:
                        add(a.asname or a.name, "import", f"{node.module}.{a.name}")
                    else:
                        add(a.asname or a.name, "relimport", (node.level, node.module or "", a.name))
            elif isinstance(node, _SCOPE_NODES):
                if not isinstance(node, ast.Lambda):
                    add(node.name, "other")
                children.append(node)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                self.poisoned.update(node.names)
            elif isinstance(node, ast.arg):
                add(node.arg, "other")
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                add(node.targets[0].id, "value", node.value)
                simple.add(id(node.targets[0]))
            elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
                add(node.target.id, "value", node.value)
                simple.add(id(node.target))
            elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load) and id(node) not in simple:
                add(node.id, "other")   # any other store or `del`: the name is not a single assignment
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
                add(node.name, "other")
            elif isinstance(node, ast.MatchMapping) and node.rest:
                add(node.rest, "other")
        return children

    def owner(self, name: str, scope: _Scope) -> Optional[_Scope]:
        """The scope a Name read in `scope` resolves to (class bodies are invisible from their methods); None for a
        `global` / `nonlocal` name and for a name bound nowhere on the way up."""
        if name in self.poisoned:
            return None
        current: Optional[_Scope] = scope
        while current is not None:
            if name in current.bindings and (current is scope or not isinstance(current.node, ast.ClassDef)):
                return current
            current = current.parent
        return None

    def candidates(self, name: str, scope: _Scope) -> List[Tuple[str, Any]]:
        """Every binding a read of `name` in `scope` may see: the owning scope's bindings; for a module-level or
        unbound name also one candidate per star import (`from m import *` may bind `m.name`); for a `global` /
        `nonlocal` name every binding of it anywhere in the file."""
        if name in self.poisoned:
            found = [b for s in self.scopes for b in s.bindings.get(name, [])]
        else:
            owner = self.owner(name, scope)
            found = list(owner.bindings[name]) if owner is not None else []
            if owner is not None and owner is not self.module:
                return found
        for level, module in self.star_sources:
            found.append(("import", f"{module}.{name}") if level == 0 else ("relimport", (level, module, name)))
        return found

    def parent(self, node: ast.AST) -> Optional[ast.AST]:
        """The syntactic parent of `node` (computed once per file, on first use)."""
        if self._parents is None:
            self._parents = {id(c): p for p in ast.walk(self.tree) for c in ast.iter_child_nodes(p)}
        return self._parents.get(id(node))

    def single(self, name: str, scope: _Scope) -> Optional[Tuple[_Scope, str, Any]]:
        """(owner scope, kind, payload) when `name` has exactly one binding there and no star import of the file can
        rebind it, else None."""
        found = self.owner(name, scope)
        if found is None or len(found.bindings[name]) != 1 or (found is self.module and self.star_sources):
            return None
        kind, payload = found.bindings[name][0]
        return found, kind, payload


def _keyword(call: ast.Call, name: str) -> Optional[ast.AST]:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _argument(call: ast.Call, index: int, name: str) -> Optional[ast.AST]:
    return call.args[index] if len(call.args) > index else _keyword(call, name)


class _Callee:
    """The non-test Python files of one callee (`apps/<callee>/`, the service root on its import path)."""

    def __init__(self, callee: str, app_files: Mapping[str, str]):
        self.root = f"apps/{callee}/"
        self.files: Dict[str, _File] = {}
        self.parse_error: Optional[str] = None
        self.in_tree: Set[str] = set()   # top-level module names the callee ships (never a pip API)
        self.test_modules: Set[str] = set()
        self.paths: Set[str] = set()   # every path of the callee, relative to its root
        self.procfile: Optional[str] = None   # the callee's Procfile text (RT F2; part of the tree key)
        self._followed: Dict[Tuple[_Targets, Tuple[str, ...]], _Api] = {}
        for path in sorted(app_files):
            if not isinstance(path, str) or not path.startswith(self.root):
                continue
            rel = path[len(self.root):]
            self.paths.add(rel)
            if rel == _PROCFILE:
                self.procfile = app_files[path] if isinstance(app_files[path], str) else ""
            top = rel.split("/", 1)[0]
            self.in_tree.add(top[:-3] if "/" not in rel and top.endswith(".py") else top)
            if rel.endswith(".py") and is_test_path(rel):
                self.test_modules.add(rel)   # importable at run time, but its code is never read
            if not rel.endswith(".py") or is_test_path(rel):
                continue
            text = app_files[path]
            try:
                tree = ast.parse(text if isinstance(text, str) else "")
            except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
                self.parse_error = f"{path}: {type(exc).__name__}"
                continue
            self.files[rel] = _File(rel, tree)

    def module_file(self, dotted_module: str) -> Optional[_File]:
        """The callee file an absolute dotted module names (from the service root): `<m>.py` or `<m>/__init__.py`,
        exactly one of them and not a test file."""
        base = posixpath.join(*dotted_module.split("."))
        found = [self.files[c] for c in (f"{base}.py", posixpath.join(base, "__init__.py")) if c in self.files]
        return found[0] if len(found) == 1 else None

    @staticmethod
    def absolute(f: _File, level: int, module: str) -> Optional[str]:
        """The absolute dotted module of `from <level dots><module> import ...` in `f` ("" = the service root), or
        None above the service root."""
        package = posixpath.dirname(f.rel)
        for _ in range(level - 1):
            if not package:
                return None
            package = posixpath.dirname(package)
        return ".".join([p for p in package.split("/") if p] + [p for p in module.split(".") if p])

    # -- which verifying API (if any) an expression names
    def api_of(self, f: _File, expr: ast.AST, scope: _Scope, targets: _Targets = _VERIFY_TARGETS) -> _Api:
        attrs: List[str] = []
        while isinstance(expr, ast.Attribute):
            attrs.append(expr.attr)
            expr = expr.value
        if not isinstance(expr, ast.Name):
            return None   # a call result, subscript, literal: an API object reaches it only through a name (checked)
        return self._combine(f, f.candidates(expr.id, scope), tuple(attrs[::-1]), 0, targets)

    def _combine(self, f: _File, bindings: List[Tuple[str, Any]], attrs: Tuple[str, ...], hops: int,
                 targets: _Targets = _VERIFY_TARGETS) -> _Api:
        results: List[_Api] = []
        for kind, payload in bindings:
            if kind == "import":
                results.append(self._follow(tuple(payload.split(".")) + attrs, hops + 1, targets))
            elif kind == "relimport":
                level, module, name = payload
                base = self.absolute(f, level, module)
                results.append(None if base is None else   # above the service root: the import fails
                               self._follow(tuple(p for p in base.split(".") if p) + (name,) + attrs, hops + 1,
                                            targets))
            else:
                results.append(None)   # a local def, value or argument: not an imported API (aliases are checked)
        if all(r is None for r in results):
            return None
        first = results[0]
        if isinstance(first, (str, _ApiModule)) and all(r == first for r in results):
            return first
        return _UNKNOWN   # e.g. `try: from google.oauth2 import id_token` / `except: id_token = None`

    def _follow(self, parts: Tuple[str, ...], hops: int, targets: _Targets = _VERIFY_TARGETS) -> _Api:
        """The API an absolute dotted path names: a pip path is itself; a path into the callee's own modules is
        followed to the binding there."""
        if hops > _MAX_NAME_HOPS or not parts:
            return _UNKNOWN
        if parts[0] not in self.in_tree:
            path = ".".join(parts)
            return path if path in targets.apis else _ApiModule(path) if path in targets.modules else None
        key = (targets, parts)
        if key in self._followed:
            return self._followed[key]
        self._followed[key] = _UNKNOWN   # a cycle stays unknown
        result: _Api = None   # no module file the callee ships: the import fails at run time, it names no API
        for i in range(len(parts), 0, -1):   # the longest prefix that is a callee module
            target = self.module_file(".".join(parts[:i]))
            if target is None:
                base = posixpath.join(*parts[:i])
                if {f"{base}.py", posixpath.join(base, "__init__.py")} & self.test_modules:
                    result = _UNKNOWN   # a test module: it exists at run time, its code is not read
                    break
                continue
            result = (None if i == len(parts) else   # the module object itself
                      self._combine(target, target.candidates(parts[i], target.module), parts[i + 1:], hops,
                                    targets))
            break
        self._followed[key] = result
        return result

    # -- which str constant an audience expression is
    def resolve(self, f: _File, expr: Optional[ast.AST], scope: _Scope, hops: int = 0,
                env_ok: bool = True) -> Optional[Tuple[str, Optional[str]]]:
        """(L, None) when `expr` is the str constant L; (L, NAME) when it is `os.getenv(NAME, L)` /
        `os.environ.get(NAME, L)` (only with `env_ok`: NAME and L themselves must be plain constants); else None."""
        if hops > _MAX_NAME_HOPS or expr is None:
            return None
        if isinstance(expr, ast.Constant):
            return (expr.value, None) if isinstance(expr.value, str) else None
        if isinstance(expr, ast.Call):
            return self._env_default(f, expr, scope, hops) if env_ok else None
        if not isinstance(expr, ast.Name):
            return None
        bound = f.single(expr.id, scope)
        if bound is None or bound[0] is not f.module:   # module-level names only
            return None
        _, kind, payload = bound
        if kind == "value":
            return self.resolve(f, payload, f.module, hops + 1, env_ok)
        if kind == "import":   # `from x.y import NAME`: x must be a module this callee ships
            module, _, name = payload.rpartition(".")
            if not module or module.split(".")[0] not in self.in_tree:
                return None
        elif kind == "relimport":
            level, rel_module, name = payload
            module = self.absolute(f, level, rel_module) or ""
        else:
            return None
        target = self.module_file(module) if module else None
        if target is None:
            return None
        return self.resolve(target, ast.Name(id=name, ctx=ast.Load()), target.module, hops + 1, env_ok)

    def _env_default(self, f: _File, call: ast.Call, scope: _Scope, hops: int) -> Optional[Tuple[str, str]]:
        """(L, NAME) for `os.getenv(NAME, L)` / `os.environ.get(NAME, L)` (L positional or `default=`), the getter
        resolved through imports; NAME and L str constants (or module-level constant names). Else None."""
        if self.api_of(f, call.func, scope, _ENV_TARGETS) not in _ENV_GETTERS:
            return None
        if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg != "default" for k in call.keywords):
            return None
        args = list(call.args) + [k.value for k in call.keywords]
        if not call.args or len(args) != 2:
            return None
        name = self.resolve(f, args[0], scope, hops + 1, env_ok=False)
        default = self.resolve(f, args[1], scope, hops + 1, env_ok=False)
        if name is None or default is None or not name[0]:
            return None
        return default[0], name[0]

    # -- whether the callee's own code may set an env name
    def env_write(self, names: FrozenSet[str]) -> Optional[str]:
        """Where the callee may set one of `names` in its own process environment (see the module docstring), or
        None. Any use of the `os` environment API this reading cannot follow counts as a write."""
        shipped = sorted(rel for rel in self.paths if posixpath.basename(rel) in _ENV_FILES)
        if shipped:
            return f"the callee ships {shipped[0]}"
        if self.procfile is not None:
            why = _procfile_env(self.procfile)
            if why is not None:
                return f"{_PROCFILE}: {why}"
        for rel, f in sorted(self.files.items()):
            imports = [p for s in f.scopes for b in s.bindings.values() for k, p in b if k == "import"]
            imports += [m for level, m in f.star_sources if level == 0]
            if _DOTENV not in self.in_tree and any(p.split(".")[0] == _DOTENV for p in imports):
                return f"{_DOTENV} imported ({rel})"
            test_import = self._imported_test_module(f)
            if test_import is not None:
                return f"a module named like a test is imported, its code is not read ({rel}:{test_import})"
            if f.module.bindings.get(_GUNICORN_RAW_ENV):
                return f"module-level {_GUNICORN_RAW_ENV} (a gunicorn setting) ({rel})"
            for scope in f.scopes:
                nodes = list(_scope_nodes(scope.node))
                chained = {id(n.value) for n in nodes if isinstance(n, ast.Attribute)}
                for node in nodes:
                    if not isinstance(node, (ast.Name, ast.Attribute)):
                        continue
                    target = self.api_of(f, node, scope, _ENV_TARGETS)
                    if target is None or target in _ENV_GETTERS:
                        continue
                    if isinstance(target, _ApiModule) and id(node) in chained and isinstance(node.ctx, ast.Load):
                        continue   # `os.<attr>`: judged by its chain
                    if (target is _UNKNOWN or not isinstance(node.ctx, ast.Load)
                            or not self._env_use_ok(f, node, target, scope, names)):
                        what = target if isinstance(target, str) else "the os module"
                        return f"{what} may set {', '.join(sorted(names))} ({rel}:{getattr(node, 'lineno', 0)})"
        return None

    def _imported_test_module(self, f: _File) -> Optional[int]:
        """The line of the first import in `f` (any scope) of a callee module named like a test, else None (RT F3: its
        code is not read, so a write there would be missed)."""
        for node in ast.walk(f.tree):
            dotted: List[str] = []
            if isinstance(node, ast.Import):
                dotted = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = (node.module or "") if node.level == 0 else self.absolute(f, node.level, node.module or "")
                if base is None:
                    continue
                dotted = [".".join(p for p in (base, a.name) if p) for a in node.names if a.name != "*"] + [base]
            for name in dotted:
                parts = [p for p in name.split(".") if p]
                for i in range(1, len(parts) + 1):
                    base_path = posixpath.join(*parts[:i])
                    if {f"{base_path}.py", posixpath.join(base_path, "__init__.py")} & self.test_modules:
                        return getattr(node, "lineno", 0)
        return None

    def _env_use_ok(self, f: _File, node: ast.AST, target: _Api, scope: _Scope, names: FrozenSet[str]) -> bool:
        """A read of the environment, or a write of a str-constant key that is none of `names`."""
        parent = f.parent(node)

        def other_key(expr: Optional[ast.AST]) -> bool:
            key = self.resolve(f, expr, scope, env_ok=False)
            return key is not None and key[0] not in names

        def called(p: Optional[ast.AST], func: ast.AST) -> Optional[ast.Call]:
            return p if isinstance(p, ast.Call) and p.func is func else None

        if target in _ENV_SETTERS:
            call = called(parent, node)
            return call is not None and bool(call.args) and other_key(call.args[0])
        if target not in _ENV_MAPPINGS:
            return False   # the `os` module itself used as a value
        if isinstance(parent, ast.Attribute) and parent.value is node:
            if parent.attr in _ENV_READ_METHODS:
                return True
            call = called(f.parent(parent), parent)
            return (parent.attr in _ENV_KEY_WRITE_METHODS and call is not None and bool(call.args)
                    and other_key(call.args[0]))
        if isinstance(parent, ast.Subscript) and parent.value is node:
            return isinstance(parent.ctx, ast.Load) or other_key(parent.slice)
        if isinstance(parent, ast.Compare) and node in parent.comparators:
            return all(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops)
        return False


def _procfile_env(text: str) -> Optional[str]:
    """Why the Procfile may set the server's environment, or None (see the module docstring; RT F2). Parsed with the
    shared Procfile parser and `shlex`, token by token; anything it cannot judge counts."""
    try:
        try:
            from gatekeeper_agent.procfile import SHELLS, parse_command, parse_procfile
        except ImportError:  # pragma: no cover - imported as a package-relative module
            from ..gatekeeper_agent.procfile import SHELLS, parse_command, parse_procfile  # type: ignore
    except ImportError as exc:  # pragma: no cover - the gateway image always carries gatekeeper_agent/
        return f"the Procfile parser is not importable ({type(exc).__name__})"
    procs, bad = parse_procfile(text)
    if bad:
        return "a line is not `<process>: <command>`"
    for process, cmd in sorted(procs.items()):
        try:
            why = _command_env(shlex.split(cmd), SHELLS, parse_command, 0)
        except ValueError:
            why = "the command cannot be split"
        if why is not None:
            return f"process '{process}': {why}"
    return None


def _command_env(argv: List[str], shells: Any, parse_command: Any, depth: int, server: bool = True) -> Optional[str]:
    """Why one Procfile command may set the server's environment, or None. `server`: its last simple command is the
    process that keeps running (judged as a launcher); an earlier one runs in its own process."""
    if depth > 4:
        return "nested shell commands"
    segments: List[List[str]] = [[]]
    for tok in argv:
        if tok in _CMD_SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(tok)
    if server and not segments[-1]:
        return "the last command is empty"
    for i, seg in enumerate(segments):
        rest = list(seg)
        while rest:   # exact wrappers in front of a command
            head = posixpath.basename(rest[0])
            name, eq, _ = rest[0].partition("=")
            if eq and name.isidentifier():
                return f"assigns {name}"
            if head == "env":
                return "runs `env`"
            if head in _ENV_BUILTINS:
                return f"runs the shell builtin `{head}`"
            if head == "exec":
                rest = rest[1:]
                continue
            if head in shells:
                opts = rest[1:]
                while opts and opts[0].startswith("-") and opts[0] != "-c":
                    opts = opts[1:]
                if len(opts) >= 2 and opts[0] == "-c":
                    why = _command_env(shlex.split(opts[1]), shells, parse_command, depth + 1,
                                       server and i == len(segments) - 1)
                    if why is not None:
                        return why
                    rest = []
                    break
                return f"runs a {head} script"
            break
        if not rest or not server or i != len(segments) - 1:
            continue   # an earlier command runs in its own process: it cannot set the server's environment
        if parse_command(rest).kind not in ("server", "python_file"):
            return f"starts `{posixpath.basename(rest[0])}`, a launcher this check does not know"
        options = [t.partition("=")[0] for t in rest[1:] if t.startswith("-")]
        passed = sorted(set(options) & _ENV_OPTIONS)
        if passed:
            return f"passes {passed[0]} to the server"
    return None


def _call_audience(cal: _Callee, f: _File, call: ast.Call, api: str, scope: _Scope) -> Tuple[str, Any]:
    """("skip", None) for a call that verifies nothing, ("literal", (L, NAME or None)) or ("unresolved", reason)."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return "unresolved", f"star arguments ({f.rel}:{call.lineno})"
    if api == _VERIFY_TOKEN and (_keyword(call, "certs_url") is not None or len(call.args) > _VERIFY_TOKEN_MAX_ARGS):
        return "unresolved", f"verify_token with certs_url verifies an IAP assertion ({f.rel}:{call.lineno})"
    if api == _JWT_DECODE:
        verify = _argument(call, _JWT_VERIFY_INDEX, "verify")
        if isinstance(verify, ast.Constant) and verify.value is False:
            return "skip", None   # decodes without verifying: checks no audience
        if verify is not None and not (isinstance(verify, ast.Constant) and verify.value is True):
            return "unresolved", f"verify flag not a literal ({f.rel}:{call.lineno})"
    resolved = cal.resolve(f, _argument(call, VERIFY_APIS[api], "audience"), scope)
    if resolved is None:
        return "unresolved", f"{api} audience is not one str constant ({f.rel}:{call.lineno})"
    return "literal", resolved


_FACTS: "OrderedDict[Tuple[str, str], AudienceFact]" = OrderedDict()
_FACTS_LOCK = threading.Lock()   # the gateway assembles on Starlette's threadpool


def _tree_key(app_files: Mapping[str, str], callee: str) -> str:
    """sha256 over every path of `apps/<callee>/` (the paths decide in_tree and the test modules) and the text of
    each non-test .py file and of the Procfile (the only text the analysis reads). Each field is length-prefixed, so the encoding is
    injective (a NUL inside a file cannot imitate a field boundary)."""
    root = f"apps/{callee}/"
    digest = hashlib.sha256()
    for path in sorted(p for p in app_files if isinstance(p, str) and p.startswith(root)):
        rel = path[len(root):]
        text = app_files[path] if (rel.endswith(".py") and not is_test_path(rel)) or rel == _PROCFILE else ""
        for value in (rel, text if isinstance(text, str) else repr(type(text))):
            data = value.encode("utf-8", "surrogatepass")
            digest.update(len(data).to_bytes(8, "big") + data)
    return digest.hexdigest()


def callee_audience_fact(app_files: Optional[Mapping[str, str]], callee: str) -> AudienceFact:
    """The audience `callee`'s non-test code verifies (see module docstring). Pure function of the files, memoized
    per (callee, tree content) in a bounded, locked LRU."""
    files = app_files or {}
    key = (callee, _tree_key(files, callee))
    with _FACTS_LOCK:
        cached = _FACTS.get(key)
        if cached is not None:
            _FACTS.move_to_end(key)
            return cached
    fact = _analyse(files, callee)
    with _FACTS_LOCK:
        _FACTS[key] = fact
        _FACTS.move_to_end(key)
        while len(_FACTS) > _FACT_CACHE_SIZE:
            _FACTS.popitem(last=False)
    return fact


def _analyse(app_files: Mapping[str, str], callee: str) -> AudienceFact:
    cal = _Callee(callee, app_files)
    if cal.parse_error:
        return AudienceFact(callee, PARSE_ERROR, detail=cal.parse_error)
    if not cal.files:
        return AudienceFact(callee, NO_CODE)
    literals: Set[str] = set()
    env_names: Set[str] = set()   # SIBLING-AUDIENCE-GETENV-DEFAULT: the env names whose default is the literal
    for rel, f in sorted(cal.files.items()):
        for scope in f.scopes:
            followed: Set[int] = set()
            nodes = list(_scope_nodes(scope.node))
            chained = {id(n.value) for n in nodes if isinstance(n, ast.Attribute)}   # inner links of a dotted chain
            for node in nodes:
                if not isinstance(node, ast.Call):
                    continue
                api = cal.api_of(f, node.func, scope)
                if api is _UNKNOWN:
                    return AudienceFact(callee, UNRESOLVED, detail=f"call not followable ({rel}:{node.lineno})")
                if not isinstance(api, str):
                    continue   # None, or calling a module object (a TypeError at run time)
                followed.add(id(node.func))
                outcome, value = _call_audience(cal, f, node, api, scope)
                if outcome == "unresolved":
                    return AudienceFact(callee, UNRESOLVED, detail=value or "")
                if outcome == "literal" and value is not None:
                    literals.add(value[0])
                    if value[1] is not None:
                        env_names.add(value[1])
            for node in nodes:
                # a verifying API used other than as a direct call (alias, partial), or a module that holds one used
                # as a value (alias, getattr): not followed. An inner link of a dotted chain is judged by its chain.
                if (not isinstance(node, (ast.Name, ast.Attribute)) or id(node) in followed
                        or not isinstance(getattr(node, "ctx", None), ast.Load)):
                    continue
                api = cal.api_of(f, node, scope)
                if api is None or (isinstance(api, _ApiModule) and id(node) in chained):
                    continue
                return AudienceFact(callee, UNRESOLVED,
                                    detail=f"verifying API or its module used as a value ({rel}:{node.lineno})")
    if not literals:
        return AudienceFact(callee, NO_VERIFY_CALL)
    if len(literals) > 1:
        return AudienceFact(callee, CONFLICTING, detail=", ".join(sorted(literals)))
    (literal,) = literals
    if not _HCL_SAFE_LITERAL.fullmatch(literal):
        return AudienceFact(callee, UNSAFE_LITERAL, detail="empty literal" if not literal else
                            f"{len(literal)} characters outside the closed grammar")
    if env_names:
        written = cal.env_write(frozenset(env_names))
        if written is not None:
            return AudienceFact(callee, UNRESOLVED, detail=f"env-default audience, but {written}")
        names = tuple(sorted(env_names))
        return AudienceFact(callee, LITERAL_ENV_DEFAULT, literal=literal, env_names=names,
                            detail=f"default of {', '.join(names)}")
    return AudienceFact(callee, LITERAL, literal=literal)


def callee_literal_audience(app_files: Optional[Mapping[str, str]], callee: str) -> Optional[str]:
    """The plan's step-1 function: the one HCL-safe literal audience `callee` verifies, or None. An env-default
    literal (LITERAL_ENV_DEFAULT) is not returned: it holds only with the callee's env facts (edge_audience_decisions)."""
    fact = callee_audience_fact(app_files, callee)
    return fact.literal if fact.outcome == LITERAL else None


# (env names the platform sets on the callee, or None when not known; why it is not known)
CalleeEnvNames = Callable[[str], Tuple[Optional[FrozenSet[str]], str]]
_BOUND = (LITERAL, LITERAL_ENV_DEFAULT)


def edge_audience_decisions(vt: Any, service: str, env: Mapping[str, str], app_files: Optional[Mapping[str, str]],
                            *, allow_unauthenticated: Optional[bool] = None,
                            callee_env_names: Optional[CalleeEnvNames] = None) -> List[AudienceDecision]:
    """One decision per `http` edge of `service` whose `<BASE>_AUDIENCE` is bound, in `env`, to exactly the edge's
    `module.<callee label>.service_uri`. `value` is `"L"` for a LITERAL fact on a public workload
    (`allow_unauthenticated is True`), else that binding unchanged: a literal on a private workload becomes
    IAM_ENFORCED (`False`: Cloud Run's invoker check accepts only the service URL) or ACCESS_UNKNOWN (`None`).
    SIBLING-AUDIENCE-GETENV-DEFAULT: a LITERAL_ENV_DEFAULT fact binds `"L"` on the same terms and only when
    `callee_env_names(callee)` (topology_wiring.callee_env_names: every env name the platform's IaC sets on the
    callee) is known and holds none of the fact's env names; else ENV_SET_BY_PLATFORM or CALLEE_ENV_UNKNOWN, binding
    unchanged. Evaluated per decision, never cached (the cached fact is a function of the callee's tree only). Each
    decision other than "the callee verifies nothing in code" is logged."""
    env_base = getattr(sys.modules.get(type(vt).__module__), "env_base", None)   # vt's own service_topology copy
    if env_base is None:  # pragma: no cover - vt is always a shared.service_topology.ValidatedTopology
        return []
    out: List[AudienceDecision] = []
    for e in vt.intent.edges:
        if e.caller != service or e.protocol != "http":
            continue
        key = f"{e.env_key_base or env_base(e.callee)}_AUDIENCE"
        today = f"module.{vt.label(e.callee)}.service_uri"
        if env.get(key) != today:
            continue
        fact = callee_audience_fact(app_files, e.callee)
        if fact.outcome in _BOUND and allow_unauthenticated is not True:
            fact = AudienceFact(e.callee, IAM_ENFORCED if allow_unauthenticated is False else ACCESS_UNKNOWN,
                                detail=("Cloud Run invoker IAM accepts only the service URL" if allow_unauthenticated
                                        is False else "access mode not passed") + f"; the code verifies {fact.literal}")
        elif fact.outcome == LITERAL_ENV_DEFAULT:
            fact = _env_default_decision(fact, callee_env_names)
        value = f'"{fact.literal}"' if fact.outcome in _BOUND and fact.literal is not None else today
        out.append(AudienceDecision(service, e.callee, key, fact, value))
        if fact.outcome == LITERAL:
            logger.info("SIBLING_AUDIENCE_BINDING %s -> %s: %s = %s (the callee verifies this fixed audience)",
                        service, e.callee, key, value)
        elif fact.outcome == LITERAL_ENV_DEFAULT:
            logger.info("SIBLING_AUDIENCE_BINDING %s -> %s: %s = %s (%s: the callee verifies the default of %s, "
                        "which the platform does not set on it)", service, e.callee, key, value, fact.outcome,
                        ", ".join(fact.env_names))
        elif fact.outcome not in (NO_VERIFY_CALL, NO_CODE):
            logger.warning("SIBLING_AUDIENCE_UNRESOLVED %s -> %s: %s kept = %s (%s: %s)",
                           service, e.callee, key, today, fact.outcome, fact.detail)
    return out


def _env_default_decision(fact: AudienceFact, callee_env_names: Optional[CalleeEnvNames]) -> AudienceFact:
    """A LITERAL_ENV_DEFAULT fact against the platform's env names for the callee (see edge_audience_decisions):
    unchanged when none of its names is set there, else unresolved with the reason."""
    try:
        names, why = (callee_env_names(fact.callee) if callee_env_names is not None
                      else (None, "no env facts passed"))
    except Exception as exc:  # noqa: BLE001 - RT F4: fail-loudly policy §2: the URL is kept, the cause is logged
        logger.warning("SIBLING_AUDIENCE_ENV_FACTS_FAILED %s: callee_env_names raised %s; the URL is kept",
                       fact.callee, type(exc).__name__)
        names, why = None, f"callee_env_names failed ({type(exc).__name__})"
    if names is None:
        return AudienceFact(fact.callee, CALLEE_ENV_UNKNOWN,
                            detail=f"the code verifies the default of {', '.join(fact.env_names)}; the callee's env "
                                   f"set is not known ({why})")
    taken = sorted(set(fact.env_names) & set(names))
    if taken:
        return AudienceFact(fact.callee, ENV_SET_BY_PLATFORM,
                            detail=f"the platform sets {', '.join(taken)} on the callee, so the code's default is not "
                                   "the audience it verifies")
    return fact

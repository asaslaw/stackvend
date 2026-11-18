"""V3c: the Buildpacks container contract of every AI-written Python service (Step 2 plan §3.1 A6, register HS-09).

Replaces HB-29 (the gateway's `enforce_container_contract` Procfile overwrite + `/health` injection and the verifier
twin's Procfile overwrite / `import os` prepend / `/health` injection). Nothing here writes: an AI-written Procfile is
parsed, never overwritten, and a missing piece is reported to the persona that wrote the service.

Exact rules only (no regex, no substring tests on code):
* service      = `apps/<svc>/` holding at least one LLM-owned `.py` file (platform-synthesized stubs and Node services are
                 out of scope; the platform renders its own stubs' Procfiles). On the topology path a service whose
                 typed kind is gce-bastion or gce-worker (NON_CONTAINER_KINDS) is out of scope too: it runs on a VM,
                 never in a Buildpacks container (S3-bastion, 10-19).
* Procfile     = `<process>: <command>` lines (`#` comment lines skipped); the command is split with `shlex`.
                 Buildpacks run it from `apps/<svc>/` (the deploy workflow builds `--source apps/<svc>`).
* launchers    = `uvicorn` / `gunicorn` / `hypercorn` (app target `module[:attr]`, port option), `python[3] <file>` and
                 `python[3] -m <launcher> ...`, also behind the exact wrappers `exec`, `env [NAME=value ...]`,
                 `NAME=value` and `sh|bash -c "<command>"` (gatekeeper_agent/procfile.py, one parser with the gatekeeper's
                 requirements contract, FD-4AD FDAD-5). Any other launcher is not judged (no diagnostic).
* chain        = (HS-40 RT A1) a command whose argv holds the exact token `&&` or `;` is judged by the segment after
                 the LAST such token, the server that keeps running (e.g. `alembic upgrade head && uvicorn ...`); that
                 segment holding `||`, or being empty, is not judged. An argv without `&&` / `;` is judged exactly as
                 before. Separators glued to a word by shlex (`head&&uvicorn`) are not tokens: not judged, as before.
                 Converges with FD-4AD's shared `gatekeeper_agent/procfile.py` `command_segments` when that lands.
* PORT         = the port value is exactly `$PORT`, `${PORT}` or `${PORT:-<digits>}` (`--port V`, `--port=V`,
                 `-b/--bind host:V`); `gunicorn` without a bind honours `$PORT` itself; `python <file>` must read PORT
                 in some `.py` file of the service (code RT F2b) through `os.environ[...]` / `os.environ.get` /
                 `os.getenv` (imports resolved exactly) or a pydantic `BaseSettings` field that maps to PORT (field
                 `port` with no literal env_prefix, or `Field(alias|validation_alias|env="PORT")`); a settings class
                 whose keys are not literal makes the service not judged for PORT.
* health       = required only by the probe that calls it (code RT F2c): the `httpGet` probe paths of a Kubernetes
                 workload that names the service; otherwise the literal `health_check_path` (default `/health`) of
                 every root-module `compute-cloudrun` module block whose literal `service_name` is the service. A
                 service with neither, or a non-literal `health_check_path`, is not judged. (A Cloud Run module the
                 platform synthesized for a GKE service is HB-04's defect, not a requirement on the AI's code.) A route is a decorator
                 `<x>.get|api_route|route|head("<path>")` or a call `<x>.add_api_route|add_url_rule|add_route("<path>",
                 ...)` / `Route("<path>", ...)` in any `.py` file of the service; `APIRouter(prefix=<literal>)` and one
                 level of `<app>.include_router(<router>, prefix=<literal>)` (router resolved through the service's own
                 imports) are applied; an include that cannot be resolved exactly makes the service not judged.
                 HR-1: routes are read only for a service with a framework app (a `FastAPI(` / `Flask(` /
                 `Starlette(` call, exact AST call name, in any `.py` file of the service). A service without one
                 (e.g. stdlib `http.server`) gets the report-only CONTAINER.HEALTH_ROUTE_UNVERIFIED (`V3c-health-
                 unverified`) instead of the blocking HEALTH_ROUTE_MISSING: its routes cannot be read, so a missing
                 route is never asserted (05-r1: a `BaseHTTPRequestHandler` pod that served `/healthz` was rewritten).

* planned push = (FD55-W5c-PLAN-FACTS) only for a service the repair loop's whole-service CREATE round wrote
                 (`planned_push_route_findings`; V3c itself never judges it): CONTAINER.PUSH_ROUTE_MISSING when a Pub/Sub
                 push path of the typed plan is not served as POST (`post_route_state`, `ast` only; what it cannot
                 decide never blocks). What it cannot decide is recorded as the report-only
                 CONTAINER.PUSH_ROUTE_UNVERIFIED (`planned_push_route_unverified`): measured in `report.report_only`,
                 never in a blocking report and never in a repair prompt.

Codes: CONTAINER.ENTRYPOINT_MISSING (no Procfile, no process line, unparseable command, entry module/file or app attribute
not found in the service), CONTAINER.PORT_NOT_BOUND, CONTAINER.HEALTH_ROUTE_MISSING (web process only) and, in the
blocking `V3c-migration` (register row HS-40, owner 10-19), CONTAINER.MIGRATION_NOT_INVOKED (`apps/<svc>/alembic.ini`
present, and the `web` process does not run `alembic upgrade`: exact token `alembic`, then only exact alembic global
options (`-c/--config/-n/--name/-x` with a value, `--raiseerr`, `-q/--quiet`), then exact `upgrade`. Only `web`
counts (HS-40 RT A2): Cloud Run starts the Buildpacks `web` process only, so a `release:` line never runs). The finding names
`apps/<svc>/Procfile`, the file the repair edits; with no Procfile it is a create (repair_loop.CREATE_FILE_CODES), so
the persona that writes the missing Procfile is told both requirements in one round.

in the report-only `V3c-imports` (FD-4AE-c),
CONTAINER.IMPORT_OUTSIDE_SERVICE (an unguarded `apps.<...>` import the service does not ship, or a relative import that
climbs above apps/<svc>/; it replaces the terraform MCP's post-QA rewrite of such imports).

PWB-3 (10-19): on the topology path every container-kind topology service (any kind except NON_CONTAINER_KINDS) with
an LLM-owned `.py` file is judged, also a Procfile-only worker next to a `main.py` sibling. PWB-4 (10-19): V3c-k8s
(K8sWorkloadValidator) reports CONTAINER.K8S_WORKLOAD_MISSING for a gke-autopilot topology service that no applied
Kubernetes manifest (`k8s/*.yaml` at the repository root) runs, and CONTAINER.K8S_MANIFEST_UNPARSEABLE for an applied
manifest that is not valid YAML.
"""
from __future__ import annotations

import ast
import posixpath
import shlex
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

try:
    from shared.artifact_ownership import Ownership
    from shared.diagnostics import Diagnostic
except ImportError:  # pragma: no cover
    from ...shared.artifact_ownership import Ownership  # type: ignore
    from ...shared.diagnostics import Diagnostic  # type: ignore

LLM_OWNED = (Ownership.LLM_AUTHORED, Ownership.LLM_DOCUMENT)
HEALTH_PATH = "/health"
ROUTE_DECORATORS = frozenset({"get", "api_route", "route", "head"})
ROUTE_CALLS = frozenset({"add_api_route", "add_url_rule", "add_route"})
ROUTE_CLASSES = frozenset({"Route"})
# Procfile parsing lives in gatekeeper_agent/procfile.py (one parser for V3c and the gatekeeper's requirements contract,
# FD-4AD RT F4); the names stay importable from here.
try:
    from gatekeeper_agent.procfile import (ASGI_SERVERS, GUNICORN_DEFAULT_BINDS_PORT, PORT_OPTIONS, PYTHONS,  # noqa: F401
                                 VALUE_OPTIONS, Launch, _bind_port_ref, is_port_ref, parse_command, parse_procfile,
                                 unwrap)
except ImportError:  # pragma: no cover
    from ...gatekeeper_agent.procfile import (ASGI_SERVERS, GUNICORN_DEFAULT_BINDS_PORT, PORT_OPTIONS,  # type: ignore  # noqa: F401
                                    PYTHONS, VALUE_OPTIONS, Launch, _bind_port_ref, is_port_ref, parse_command,
                                    parse_procfile, unwrap)

ENTRYPOINT_CODE = "CONTAINER.ENTRYPOINT_MISSING"
# Checks `_service` evaluates only after a process's entrypoint resolves: every ENTRYPOINT_MISSING path returns or
# `continue`s before the PORT and health checks of that process. So a repair that fixes a service's Procfile can
# reveal these findings in that service without having caused them (repair_loop.accept, entrypoint-repair-hint).
# Masking is per process and the masked checks run for the `web` process only: a per-process ENTRYPOINT_MISSING
# carries `symbol=<process>`; the file-level ones (no Procfile, no process line) carry no symbol and mask every process.
WEB_PROCESS = "web"
# FD55-W5c-PLAN-FACTS: a whole-service CREATE round's service does not serve the POST path its planned Pub/Sub push
# delivers to (planned_push_route_findings). Evaluated, like the other two, only once the `web` entrypoint resolves.
PUSH_ROUTE_CODE = "CONTAINER.PUSH_ROUTE_MISSING"
ENTRYPOINT_MASKED_CODES = frozenset({"CONTAINER.PORT_NOT_BOUND", "CONTAINER.HEALTH_ROUTE_MISSING", PUSH_ROUTE_CODE})
# HR-1: report-only (V3c-health-unverified), never in a blocking report, so never masked, revealed or repaired.
HEALTH_UNVERIFIED_CODE = "CONTAINER.HEALTH_ROUTE_UNVERIFIED"
# Report-only, like HR-1's: a planned push whose POST route cannot be read statically (planned_push_route_unverified).
PUSH_UNVERIFIED_CODE = "CONTAINER.PUSH_ROUTE_UNVERIFIED"
FRAMEWORK_APPS = frozenset({"FastAPI", "Flask", "Starlette"})
# S3-bastion (10-19): topology kinds (shared/service_topology.COMPUTE_KINDS members, data) whose `apps/<svc>/` code is
# never built into a Buildpacks container, so no Procfile / PORT / health contract applies to it. A gce-bastion's CI
# workflow is `terraform apply` only (handler.generate_service_workflow) and compute-gce-bastion takes no image; a
# gce-worker gets no workflow (topology_wiring.workflow_services) and runs apps/<worker>/startup.sh (V-T6). Every
# other kind, and every service the topology does not name, is judged as before.
NON_CONTAINER_KINDS = frozenset({"gce-bastion", "gce-worker"})
MIGRATION_CODE = "CONTAINER.MIGRATION_NOT_INVOKED"
HINT_MIGRATION = ("Run the migrations in the web process before the server starts, e.g. `web: alembic upgrade head && "
                  "uvicorn main:app --host 0.0.0.0 --port $PORT` (Buildpacks run the Procfile from apps/{svc}/, where "
                  "alembic.ini is). Do not hide a failed migration with `|| true`.")
HINT_PROCFILE = ("Write apps/{svc}/Procfile with one line, e.g. `web: uvicorn main:app --host 0.0.0.0 --port $PORT` "
                 "(Buildpacks run it from apps/{svc}/, so the module path is relative to that directory).")


CHAIN_SEPARATORS = frozenset({"&&", ";"})   # HS-40 RT A1: exact shlex tokens
ALTERNATIVE_SEPARATOR = "||"
ALEMBIC_VALUE_OPTIONS = frozenset({"-c", "--config", "-n", "--name", "-x"})   # alembic global options with a value
ALEMBIC_LONG_VALUE_OPTIONS = frozenset({"--config", "--name"})                # also as `--opt=value`
ALEMBIC_FLAG_OPTIONS = frozenset({"--raiseerr", "-q", "--quiet"})


def server_segment(argv: List[str]) -> Optional[List[str]]:
    """HS-40 RT A1: the argv V3c judges. No exact `&&` / `;` token -> `argv` itself (unchanged behaviour); else the
    tokens after the last one, or None (not judged) when that segment is empty or holds an exact `||`."""
    cut = -1
    for i, tok in enumerate(argv):
        if tok in CHAIN_SEPARATORS:
            cut = i
    if cut < 0:
        return argv
    seg = argv[cut + 1:]
    if not seg or ALTERNATIVE_SEPARATOR in seg:
        return None
    return seg


def runs_alembic_upgrade(argv: List[str]) -> bool:
    """Exact token `alembic`, then only exact alembic global options, then exact `upgrade` (HS-40 RT A3:
    `alembic -c alembic.ini upgrade head` runs the migrations)."""
    for i, tok in enumerate(argv):
        if tok != "alembic":
            continue
        j = i + 1
        while j < len(argv):
            a = argv[j]
            if a in ALEMBIC_VALUE_OPTIONS:
                j += 2
            elif a in ALEMBIC_FLAG_OPTIONS or ("=" in a and a.partition("=")[0] in ALEMBIC_LONG_VALUE_OPTIONS):
                j += 1
            else:
                break
        if j < len(argv) and argv[j] == "upgrade":
            return True
    return False


def _d(**kw: Any) -> Diagnostic:
    kw.setdefault("source", "precommit")
    kw.setdefault("severity", "error")
    kw.setdefault("tool", "container")
    return Diagnostic(**kw)


# ------------------------------------------------------------------------------------------------ AST helpers
def _parse(text: str) -> Optional[ast.Module]:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def _str_arg(call: ast.Call, kw_name: str = "path") -> Optional[str]:
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    for kw in call.keywords:
        if kw.arg == kw_name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _router_prefixes(tree: ast.Module) -> Dict[str, str]:
    """Module-level `name = APIRouter(prefix="<literal>")` bindings (exact)."""
    out: Dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            fname = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if fname != "APIRouter":
                continue
            prefix = next((kw.value.value for kw in node.value.keywords if kw.arg == "prefix"
                           and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)), "")
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = prefix
    return out


def has_route(tree: ast.Module, path: str = HEALTH_PATH) -> bool:
    prefixes = _router_prefixes(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) \
                        and dec.func.attr in ROUTE_DECORATORS:
                    owner = dec.func.value.id if isinstance(dec.func.value, ast.Name) else None
                    route = _str_arg(dec)
                    if route is not None and prefixes.get(owner, "") + route == path:
                        return True
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in ROUTE_CALLS and _str_arg(node) == path:
                return True
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name in ROUTE_CLASSES and _str_arg(node) == path:
                return True
    return False


def builds_framework_app(tree: ast.Module) -> bool:
    """True when the module calls a FRAMEWORK_APPS constructor (`FastAPI(...)` or `<mod>.FastAPI(...)`; exact AST
    call name, HR-1)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name in FRAMEWORK_APPS:
                return True
    return False


def service_builds_framework_app(files: Any, svc: str) -> bool:
    for p in sorted(files):
        if p.startswith(f"apps/{svc}/") and p.endswith(".py"):
            tree = _parse(files[p])
            if tree is not None and builds_framework_app(tree):
                return True
    return False


def _decorator_routes(tree: ast.Module) -> List[Tuple[Optional[str], str]]:
    """(owner name, literal path) of every route decorator and `<owner>.add_api_route|add_url_rule|add_route(path)`."""
    out: List[Tuple[Optional[str], str]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) \
                        and dec.func.attr in ROUTE_DECORATORS:
                    route = _str_arg(dec)
                    if route is not None:
                        out.append((dec.func.value.id if isinstance(dec.func.value, ast.Name) else None, route))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ROUTE_CALLS:
            route = _str_arg(node)
            if route is not None:
                out.append((node.func.value.id if isinstance(node.func.value, ast.Name) else None, route))
    return out


def _resolve_module(files: Any, svc: str, from_file: str, module: str, level: int) -> Optional[str]:
    """The service file of `module` imported from `from_file`: absolute imports resolve from `apps/<svc>/` (the
    Buildpacks working directory), relative ones from the importing file's package; never outside the service."""
    root = f"apps/{svc}"
    if level:
        base = posixpath.dirname(from_file)
        for _ in range(level - 1):
            base = posixpath.dirname(base)
        if base != root and not base.startswith(root + "/"):
            return None
    else:
        base = root
    stem = posixpath.join(base, *module.split(".")) if module else base
    for cand in (f"{stem}.py", f"{stem}/__init__.py"):
        if cand in files:
            return cand
    return None


def _import_bindings(files: Any, svc: str, path: str, tree: ast.Module) -> Dict[str, Tuple[str, str, Optional[str]]]:
    """name -> ("module", file, None) | ("attr", file, attribute) for imports that resolve to a service file."""
    out: Dict[str, Tuple[str, str, Optional[str]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "*":
                    continue
                full = f"{node.module}.{a.name}" if node.module else a.name
                sub = _resolve_module(files, svc, path, full, node.level)
                mod = _resolve_module(files, svc, path, node.module or "", node.level)
                if sub:
                    out[a.asname or a.name] = ("module", sub, None)
                elif mod:
                    out[a.asname or a.name] = ("attr", mod, a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    f = _resolve_module(files, svc, path, a.name, 0)
                    if f:
                        out[a.asname] = ("module", f, None)
    return out


def included_route_paths(files: Any, svc: str) -> Optional[Set[str]]:
    """Paths served through one level of `<owner>.include_router(<router>, prefix=<literal>)` in the service's files:
    include prefix + the router's own `APIRouter(prefix=...)` + each route of that router. None (not judged) when an
    include cannot be resolved exactly: a router argument that is not a module-level `APIRouter` of a service file
    reached through the file's own imports, a non-literal prefix, or an include onto a router (nested prefixes)."""
    out: Set[str] = set()
    for path in sorted(files):
        if not (path.startswith(f"apps/{svc}/") and path.endswith(".py")):
            continue
        tree = _parse(files[path])
        if tree is None:
            continue
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and n.func.attr == "include_router"]
        if not calls:
            continue
        local = _router_prefixes(tree)
        imports = _import_bindings(files, svc, path, tree)
        for call in calls:
            owner = call.func.value.id if isinstance(call.func.value, ast.Name) else None
            if owner in local or not call.args:
                return None
            arg = call.args[0]
            target: Optional[Tuple[str, str]] = None
            if isinstance(arg, ast.Name):
                if arg.id in local:
                    target = (path, arg.id)
                elif arg.id in imports and imports[arg.id][0] == "attr":
                    target = (imports[arg.id][1], imports[arg.id][2] or "")
            elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id in imports \
                    and imports[arg.value.id][0] == "module":
                target = (imports[arg.value.id][1], arg.attr)
            if target is None:
                return None
            prefix = ""
            for kw in call.keywords:
                if kw.arg == "prefix":
                    if not (isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)):
                        return None
                    prefix = kw.value.value
            ttree = tree if target[0] == path else _parse(files[target[0]])
            routers = _router_prefixes(ttree) if ttree is not None else {}
            if target[1] not in routers:
                return None
            for r_owner, route in _decorator_routes(ttree):
                if r_owner == target[1]:
                    out.add(prefix + routers[target[1]] + route)
    return out


# FD55-W5c-PLAN-FACTS: method-aware route reading for the planned-push check (`post_route_state`).
HTTP_METHOD_DECORATORS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
                          "head": "HEAD", "options": "OPTIONS"}
METHODS_KW_DECORATORS = frozenset({"api_route", "route"})   # FastAPI api_route / Flask route: GET unless `methods=` says
POST_CAPABLE_ROUTE_NAMES = frozenset({"post"}) | METHODS_KW_DECORATORS
ROUTER_CONSTRUCTORS = frozenset({"APIRouter", "Router"})
UNRESOLVED_ROUTING_CALLS = frozenset({"register_blueprint", "add_resource"})   # whatever the receiver: None
UNRESOLVED_ROUTING_CLASSES = frozenset({"Host", "Blueprint", "APIRoute"})
ROUTE_TEMPLATE_CHARS = frozenset("{<")   # FastAPI/Starlette `{param}`, Flask `<param>`: the path is not a literal
APP_BINDING, ROUTER_BINDING, OTHER_BINDING = "app", "router", "other"


def _literal_methods(call: ast.Call, default: Optional[FrozenSet[str]]) -> Optional[FrozenSet[str]]:
    """The literal `methods=[...]` of a route registration (upper-cased, as both frameworks do); `default` when the
    call has none; None (unknown) for a non-literal value or a `**kwargs` that may carry one."""
    for kw in call.keywords:
        if kw.arg is None:
            return None
        if kw.arg == "methods":
            v = kw.value
            if isinstance(v, (ast.List, ast.Tuple, ast.Set)) and all(
                    isinstance(e, ast.Constant) and isinstance(e.value, str) for e in v.elts):
                return frozenset(e.value.upper() for e in v.elts)
            return None
    return default


def _route_path(call: ast.Call) -> Optional[str]:
    path = _str_arg(call, "path")
    return path if path is not None else _str_arg(call, "rule")


def _is_template_segment(seg: str) -> bool:
    return bool(set(seg) & ROUTE_TEMPLATE_CHARS)


def _is_catch_all_segment(seg: str) -> bool:
    """`{name:path}` (FastAPI/Starlette) or `<path:name>` (Flask): the framework's whole-remainder converter."""
    if len(seg) < 2:
        return False
    inner = seg[1:-1]
    return (seg[0] == "{" and seg[-1] == "}" and inner.partition(":")[2] == "path") or (
        seg[0] == "<" and seg[-1] == ">" and inner.partition(":")[0] == "path")


def _route_matches(route: str, path: str) -> Optional[bool]:
    """Does the route template `route` match the URL path `path`, segment by segment? True: the literal path itself.
    False: it cannot (a literal segment differs, or the segment count does, so `/x/` is not `/x`). None: a parameter
    may match it (the framework decides at run time)."""
    if route == path:
        return True
    route_segs, path_segs = route.split("/"), path.split("/")
    template = False
    for i, seg in enumerate(route_segs):
        if _is_catch_all_segment(seg):
            return None if i <= len(path_segs) else False
        if i >= len(path_segs):
            return False
        if _is_template_segment(seg):
            template = True
        elif seg != path_segs[i]:
            return False
    return None if template and len(route_segs) == len(path_segs) else False


def _mount_covers(prefix: Optional[str], path: str) -> bool:
    """False only when the literal mount `prefix` provably does not lead to `path` (`https://`, `/static`)."""
    if prefix is None:
        return True
    path_segs = path.split("/")
    segs = prefix.rstrip("/").split("/")
    for i, seg in enumerate(segs):
        if _is_template_segment(seg):
            continue
        if i >= len(path_segs) or seg != path_segs[i]:
            return False
    return True


def _external_import_names(files: Any, svc: str, path: str, tree: ast.Module) -> Set[str]:
    """Names bound by an absolute import that does not resolve to a file of the service."""
    out: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if _resolve_module(files, svc, path, a.name, 0) is None:
                    out.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module \
                and _resolve_module(files, svc, path, node.module, 0) is None:
            for a in node.names:
                if a.name != "*" and _resolve_module(files, svc, path, f"{node.module}.{a.name}", 0) is None:
                    out.add(a.asname or a.name)
    return out


def _value_kind(value: ast.AST, external: Set[str], kinds: Dict[str, str]) -> Optional[str]:
    """What an expression holds: APP_BINDING / ROUTER_BINDING (a framework constructor's result, or a name or attribute
    of one), OTHER_BINDING (the result of calling something imported from outside the service), None (unknown)."""
    if isinstance(value, ast.Name):
        return kinds.get(value.id)
    if isinstance(value, ast.Attribute):
        return _value_kind(value.value, external, kinds)
    if isinstance(value, ast.Call):
        f = value.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
        if name in FRAMEWORK_APPS:
            return APP_BINDING
        if name in ROUTER_CONSTRUCTORS:
            return ROUTER_BINDING
        root = f
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in external:
            return OTHER_BINDING
    return None


def _binding_kinds(tree: ast.Module, external: Set[str]) -> Dict[str, str]:
    """name -> kind for the file's assignments; a name assigned two different kinds is unknown (left out)."""
    pairs: List[Tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            pairs += [(t.id, node.value) for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name) and node.value:
            pairs.append((node.target.id, node.value))
    kinds: Dict[str, str] = {}
    for _pass in range(2):   # the second pass resolves aliases (`a = app`) of names the first one found
        seen: Dict[str, Set[Optional[str]]] = {}
        for name, value in pairs:
            seen.setdefault(name, set()).add(_value_kind(value, external, kinds))
        kinds = {n: next(iter(k)) for n, k in seen.items() if len(k) == 1 and None not in k}
    return kinds


def _dynamic_router_prefixes(tree: ast.Module) -> Set[str]:
    """Module-level `name = APIRouter(...)` whose `prefix` is not a literal (or may be in `**kwargs`)."""
    out: Set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            if (f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)) != "APIRouter":
                continue
            if any(kw.arg is None or (kw.arg == "prefix" and not (isinstance(kw.value, ast.Constant)
                                                                  and isinstance(kw.value.value, str)))
                   for kw in node.value.keywords):
                out.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return out


def _file_post_state(files: Any, svc: str, file: str, tree: ast.Module, path: str) -> Optional[Tuple[bool, bool]]:
    """(a registration serves POST `path`, a registration may serve it) for one file; None when the file holds routing
    this reader cannot resolve at all. See post_route_state."""
    external = _external_import_names(files, svc, file, tree)
    kinds = _binding_kinds(tree, external)
    routers = _router_prefixes(tree)
    dynamic = _dynamic_router_prefixes(tree)
    includes: Dict[str, List[str]] = {}
    on_router: List[Tuple[str, Optional[str], Optional[FrozenSet[str]]]] = []
    served, maybe = False, False

    def judge(route: Optional[str], methods: Optional[FrozenSet[str]]) -> None:
        nonlocal served, maybe
        if methods is not None and "POST" not in methods:
            return   # whatever its path, it cannot serve a POST
        match = _route_matches(route, path) if route is not None else None
        if match is False:
            return
        if match is True and methods is not None:
            served = True
        else:
            maybe = True

    def register(owner: Optional[str], route: Optional[str], methods: Optional[FrozenSet[str]]) -> None:
        if owner in routers:
            on_router.append((owner, route, methods))   # served only through an include (below)
        else:
            judge(route, methods)

    decorator_funcs = {id(dec.func) for node in ast.walk(tree)
                       if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                       for dec in node.decorator_list if isinstance(dec, ast.Call)}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                   and dec.func.attr in POST_CAPABLE_ROUTE_NAMES for dec in node.decorator_list):
                return None   # a class view (e.g. a Flask-RESTX namespace): its methods are not readable here
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                    continue
                attr = dec.func.attr
                if attr not in HTTP_METHOD_DECORATORS and attr not in METHODS_KW_DECORATORS:
                    continue
                owner = dec.func.value.id if isinstance(dec.func.value, ast.Name) else None
                register(owner, _route_path(dec), (frozenset({HTTP_METHOD_DECORATORS[attr]})
                                                   if attr in HTTP_METHOD_DECORATORS
                                                   else _literal_methods(dec, frozenset({"GET"}))))
        elif isinstance(node, ast.Attribute):
            # `app.post(path)(h)`, `post = app.post`: a route method of a framework object used as a plain value
            if node.attr in POST_CAPABLE_ROUTE_NAMES and id(node) not in decorator_funcs \
                    and isinstance(node.value, ast.Name) and kinds.get(node.value.id) in (APP_BINDING, ROUTER_BINDING):
                return None
        elif isinstance(node, ast.Call):
            f = node.func
            attr = f.attr if isinstance(f, ast.Attribute) else None
            name = f.id if isinstance(f, ast.Name) else attr
            if name in UNRESOLVED_ROUTING_CLASSES or attr in UNRESOLVED_ROUTING_CALLS:
                return None
            if name == "Mount" or attr == "mount":
                if attr == "mount" and _value_kind(f.value, external, kinds) == OTHER_BINDING:
                    continue   # e.g. requests.Session().mount(...): not a framework object
                if _mount_covers(_str_arg(node), path):
                    return None
            elif attr == "include_router":
                arg = node.args[0] if node.args else None
                prefix_kw = [kw for kw in node.keywords if kw.arg == "prefix"]
                literal = not prefix_kw or (isinstance(prefix_kw[0].value, ast.Constant)
                                            and isinstance(prefix_kw[0].value.value, str))
                if (_value_kind(f.value, external, kinds) != APP_BINDING or not isinstance(arg, ast.Name)
                        or arg.id not in routers or arg.id in dynamic or not literal
                        or any(kw.arg is None for kw in node.keywords)):
                    return None   # not onto a known app, an imported or dynamic router, a non-literal prefix
                includes.setdefault(arg.id, []).append(prefix_kw[0].value.value if prefix_kw else "")
            elif attr in ROUTE_CALLS or name in ROUTE_CLASSES:
                # add_route(path, endpoint, methods) can carry `methods` positionally
                owner = f.value.id if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) else None
                register(owner, _route_path(node), None if len(node.args) > 2 else _literal_methods(node, None))
    for owner, route, methods in on_router:
        for prefix in includes.get(owner, ()):
            judge(None if route is None else prefix + routers[owner] + route, methods)
    return served, maybe


def post_route_state(files: Any, svc: str, path: str) -> Optional[bool]:
    """Does the service's framework app serve POST `path`? Read with `ast` from all its `.py` files. True: a route does.
    False: no registration can. None (not judged, never a finding): that cannot be decided statically.

    A route whose literal methods exclude POST, or whose literal path or template cannot match `path`, says nothing, and
    neither does a `mount` whose literal prefix cannot lead to `path`. A few forms make it None even when they cannot
    serve `path`, because they are not resolved: an unused `Blueprint`, an `APIRoute`, any `Host`, `app.post("/other")(h)`,
    a class under a route decorator. A route on a module-level `APIRouter` counts only through an `include_router` of
    that router in the same file (no include: not served, a real POST is 404); a router created inside a function is not
    tracked. A route on any other owner counts as served, also on a second app or a plain object. `/x/` is not `/x`
    (Pub/Sub push counts only 102/200/201/202/204 as delivered, so a framework's 307 is a failed delivery).

    None for: a file that does not parse, no FastAPI/Flask/Starlette app (HR-1), a POST-capable registration with a
    non-literal path, a template that may match, unknown `methods` on the path itself (non-literal, `**kwargs`, a
    call-form `add_api_route` / `add_url_rule` / `add_route` / `Route(...)` without literal `methods=`, whose default
    depends on the endpoint), a route method used as a plain value (`app.post(p)(h)`, `post = app.post`), a route-style
    decorator on a class, `register_blueprint` / `add_resource` / `Host` / `Blueprint` / `APIRoute`, an `include_router`
    that is not a local router included onto a known framework app, and a `mount` / `Mount` whose prefix may lead to
    `path`. A `.mount` on an object made by calling something imported from outside the service
    (`requests.Session().mount(...)`) is ignored."""
    if not service_builds_framework_app(files, svc):
        return None
    served, maybe = False, False
    for p in sorted(files):
        if not (p.startswith(f"apps/{svc}/") and p.endswith(".py")):
            continue
        tree = _parse(files[p])
        if tree is None:
            return None
        state = _file_post_state(files, svc, p, tree, path)
        if state is None:
            return None
        served, maybe = served or state[0], maybe or state[1]
    return True if served else (None if maybe else False)


def top_level_names(tree: ast.Module) -> Tuple[Set[str], bool]:
    """Names bound at module level, and whether a star import makes the set open."""
    names: Set[str] = set()
    star = False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        names.add(n.id)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.name == "*":
                    star = True
                else:
                    names.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, (ast.If, ast.Try, ast.With)):
            sub = ast.Module(body=[n for n in ast.iter_child_nodes(node) if isinstance(n, ast.stmt)], type_ignores=[])
            n2, s2 = top_level_names(sub)
            names |= n2
            star = star or s2
    return names, star


def reads_port(tree: ast.Module) -> bool:
    """`os.environ["PORT"]`, `os.environ.get("PORT", ...)`, `os.getenv("PORT", ...)`, with `import os [as m]` /
    `from os import environ [as e], getenv [as g]` resolved exactly."""
    os_names: Set[str] = set()
    environ_names: Set[str] = set()
    getenv_names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "os":
                    os_names.add(a.asname or "os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os" and node.level == 0:
            for a in node.names:
                if a.name == "environ":
                    environ_names.add(a.asname or "environ")
                elif a.name == "getenv":
                    getenv_names.add(a.asname or "getenv")

    def is_environ(e: ast.AST) -> bool:
        return (isinstance(e, ast.Attribute) and e.attr == "environ" and isinstance(e.value, ast.Name)
                and e.value.id in os_names) or (isinstance(e, ast.Name) and e.id in environ_names)

    def is_lit(e: ast.AST) -> bool:
        return isinstance(e, ast.Constant) and e.value == "PORT"

    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and is_environ(node.value) and is_lit(node.slice):
            return True
        if isinstance(node, ast.Call) and node.args and is_lit(node.args[0]):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "get" and is_environ(f.value):
                return True
            if isinstance(f, ast.Attribute) and f.attr == "getenv" and isinstance(f.value, ast.Name) \
                    and f.value.id in os_names:
                return True
            if isinstance(f, ast.Name) and f.id in getenv_names:
                return True
    return False


_SETTINGS_ALIAS_KWARGS = ("alias", "validation_alias", "env")


def _base_name(b: ast.AST) -> Optional[str]:
    if isinstance(b, ast.Name):
        return b.id
    if isinstance(b, ast.Attribute):
        return b.attr
    if isinstance(b, ast.Subscript):
        return _base_name(b.value)
    return None


_UNRESOLVED = object()


def _settings_config(cls: ast.ClassDef) -> Any:
    """(env_prefix, case_sensitive) set literally by the class (`model_config = SettingsConfigDict|ConfigDict(...)` /
    dict literal, or `class Config:`), None when it sets neither, _UNRESOLVED when a value is not a literal."""
    prefix: Any = None
    case: Any = None

    def take(key: Optional[str], value: ast.AST) -> bool:
        nonlocal prefix, case
        if key not in ("env_prefix", "case_sensitive"):
            return True
        if not isinstance(value, ast.Constant):
            return False
        if key == "env_prefix":
            prefix = value.value
        else:
            case = value.value
        return True

    for node in cls.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not any(isinstance(t, ast.Name) and t.id == "model_config" for t in targets):
                continue
            v = node.value
            if isinstance(v, ast.Call):
                for kw in v.keywords:
                    if kw.arg is None or not take(kw.arg, kw.value):
                        return _UNRESOLVED
            elif isinstance(v, ast.Dict):
                for k, val in zip(v.keys, v.values):
                    if not (isinstance(k, ast.Constant) and isinstance(k.value, str)) or not take(k.value, val):
                        return _UNRESOLVED
            elif v is not None:
                return _UNRESOLVED
        elif isinstance(node, ast.ClassDef) and node.name == "Config":
            for sub in node.body:
                if isinstance(sub, ast.Assign):
                    for t in sub.targets:
                        if isinstance(t, ast.Name) and not take(t.id, sub.value):
                            return _UNRESOLVED
    return None if prefix is None and case is None else (prefix or "", bool(case))


def settings_reads_port(tree: ast.Module) -> Optional[bool]:
    """True when a pydantic `BaseSettings` class of the module (a base named `BaseSettings`, or a module-local subclass
    of one, transitively) has a field that pydantic-settings fills from the PORT environment variable; None when a
    settings class's keys are not literal (not judged); else False."""
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
    settings: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, c in classes.items():
            if name not in settings and any(_base_name(b) == "BaseSettings" or _base_name(b) in settings
                                            for b in c.bases):
                settings.add(name)
                changed = True
    unresolved = False
    for name in sorted(settings):
        cls = classes[name]
        cfg = _settings_config(cls)
        chain = [cls]
        while cfg is None:   # inherited from a module-local settings parent
            parents = [classes[_base_name(b)] for b in chain[-1].bases if _base_name(b) in settings]
            if not parents:
                break
            chain.append(parents[0])
            cfg = _settings_config(parents[0])
        if cfg is _UNRESOLVED:
            unresolved = True
            continue
        prefix, case = cfg if cfg is not None else ("", False)
        for node in cls.body:
            if not (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)):
                continue
            field_name = node.target.id
            if field_name.startswith("_") or field_name == "model_config":
                continue
            key: Optional[str] = None
            literal = True
            v = node.value
            if isinstance(v, ast.Call) and _base_name(v.func) == "Field":
                for kw in v.keywords:
                    if kw.arg in _SETTINGS_ALIAS_KWARGS:
                        literal = isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str)
                        key = kw.value.value if literal else None
                        if not literal:
                            break
            if not literal:
                unresolved = True
                continue
            if key is None:
                key = (prefix + field_name) if case else (prefix + field_name).upper()
            if key == "PORT":
                return True
    return None if unresolved else False


def service_reads_port(files: Any, svc: str) -> Optional[bool]:
    """PORT read anywhere in the service's `.py` files (exact os.environ/getenv forms or a BaseSettings field)."""
    unresolved = False
    for path in sorted(files):
        if path.startswith(f"apps/{svc}/") and path.endswith(".py"):
            tree = _parse(files[path])
            if tree is None:
                continue
            if reads_port(tree):
                return True
            got = settings_reads_port(tree)
            if got:
                return True
            unresolved = unresolved or got is None
    return None if unresolved else False


def cloudrun_health_paths(files: Any, svc: str) -> Tuple[Optional[Set[str]], bool]:
    """(health paths, unresolved) of the root-module `compute-cloudrun` module blocks whose literal `service_name` is
    `svc` (python-hcl2 body; exact `source` rule of HB-04/S2-D): the literal `health_check_path`, else the module
    default HEALTH_PATH. (None, False) when no such block exists; unresolved when a matching block's
    `health_check_path` is not a literal."""
    try:
        from ..assembly import WORKLOAD, index_blocks
        from ..terraform_engine import _is_cloud_run_module_source
    except ImportError:  # pragma: no cover
        from developer_agent.assembly import WORKLOAD, index_blocks  # type: ignore
        from developer_agent.terraform_engine import _is_cloud_run_module_source  # type: ignore
    found: Optional[Set[str]] = None
    for p in sorted(files):
        if not (p.startswith(WORKLOAD) and p.endswith(".tf") and "/" not in p[len(WORKLOAD):]):
            continue
        for b in index_blocks(files[p]) or []:
            body = b.body if isinstance(b.body, dict) else {}
            if b.kind != "module" or not _is_cloud_run_module_source(body.get("source")):
                continue
            if body.get("service_name") != svc:
                continue
            hp = body.get("health_check_path", HEALTH_PATH)
            if not isinstance(hp, str) or "${" in hp:
                return None, True
            found = (found or set()) | {hp}
    return found, False


# ------------------------------------------------------------------------------------------------ the validator
def llm_services(ctx: Any, topology: Any = None) -> List[str]:
    """The services the platform builds and deploys (`detect_workload_services`, the same inventory that drives the
    container contract and the deploy workflows; on the topology path also every container-kind topology service,
    PWB-3 `is_topology_container_service`) that hold at least one LLM-owned `.py` file.

    S3-bastion (10-19): on the topology path (`topology` = shared.service_topology.ValidatedTopology) a service whose
    typed kind is in NON_CONTAINER_KINDS is left out: its code is never built into a Buildpacks container, so it has
    no container contract. The lookup is the exact topology name, normalized as the CI workflow's kind lookup is
    (handler._service_kind: `_` -> `-`); a directory that is not a topology service keeps today's rule. No topology
    (legacy path): unchanged."""
    try:
        from ..workload_inventory import detect_workload_services
    except ImportError:  # pragma: no cover
        from developer_agent.workload_inventory import detect_workload_services  # type: ignore
    deployed = set(detect_workload_services(dict(ctx.files), ""))
    out: Set[str] = set()
    for p in ctx.files:
        parts = p.split("/")
        if len(parts) >= 3 and parts[0] == "apps" and p.endswith(".py") \
                and (parts[1] in deployed or is_topology_container_service(topology, parts[1])) \
                and ctx.ownership(p) in LLM_OWNED:
            out.add(parts[1])
    if topology is not None:
        out = {s for s in out if topology.kind(s.replace("_", "-")) not in NON_CONTAINER_KINDS}
    return sorted(out)


def is_topology_container_service(topology: Any, directory: str) -> bool:
    """PWB-3 (10-19): on the topology path `apps/<directory>/` is a container service when the topology names it
    (exact lookup, S3B-1 normalization `_` -> `-`) with any kind except NON_CONTAINER_KINDS -- the same typed rule the
    container build uses (mcp-servers/terraform/service.py `entryless_service_is_buildable`). Such a service is judged
    by V3c even when it has no `main.py` while a sibling has one (`detect_workload_services`' "authentic entrypoint"
    skeleton rule left a Procfile-only worker unjudged, so a Procfile naming a missing module was built and crashed at
    runtime). No topology (legacy path) -> False: the inventory alone decides, as before."""
    if topology is None:
        return False
    kind = topology.kind(directory.replace("_", "-"))
    return kind is not None and kind not in NON_CONTAINER_KINDS


K8S_WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet"})
PROBES = ("startupProbe", "livenessProbe", "readinessProbe")


def k8s_probe_paths(files: Any, svc: str) -> Optional[Set[str]]:
    """HTTP probe paths of the Kubernetes workload(s) named `svc` (metadata.name or a container name, exact) in any
    YAML file of the tree (yaml.safe_load_all). None when no such workload exists (a name miss is never read as a
    Cloud Run service: the health requirement then comes only from a compute-cloudrun module, code RT F2c)."""
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML ships with the gateway (uvicorn[standard])
        return None
    found = False
    paths: Set[str] = set()
    for p in sorted(files):
        if not p.endswith((".yaml", ".yml")):
            continue
        try:
            docs = list(yaml.safe_load_all(files[p]))
        except Exception:  # noqa: BLE001 - an unparseable manifest is V5's/apply's finding, not a probe source
            continue
        for doc in docs:
            if not isinstance(doc, dict) or doc.get("kind") not in K8S_WORKLOAD_KINDS:
                continue
            name = (doc.get("metadata") or {}).get("name") if isinstance(doc.get("metadata"), dict) else None
            tmpl = ((doc.get("spec") or {}).get("template") or {}) if isinstance(doc.get("spec"), dict) else {}
            containers = ((tmpl.get("spec") or {}).get("containers") or []) if isinstance(tmpl, dict) else []
            for c in containers if isinstance(containers, list) else []:
                if not isinstance(c, dict) or svc not in (name, c.get("name")):
                    continue
                found = True
                for probe in PROBES:
                    get = (c.get(probe) or {}).get("httpGet") if isinstance(c.get(probe), dict) else None
                    if isinstance(get, dict) and isinstance(get.get("path"), str):
                        paths.add(get["path"])
    return paths if found else None


def _module_file(files: Any, svc: str, app_dir: str, module: str) -> Optional[str]:
    base = posixpath.normpath(posixpath.join("apps", svc, app_dir)) if app_dir else f"apps/{svc}"
    rel = module.replace(".", "/")
    for cand in (f"{base}/{rel}.py", f"{base}/{rel}/__init__.py"):
        if cand in files:
            return cand
    return None


class ContainerContractValidator:
    """V3c (blocking once HB-29 is deleted; see build_step1_stack)."""

    id, tool = "V3c", "container"

    def __init__(self, topology: Any = None, push_scope: Optional[FrozenSet[str]] = None):
        self.topology = topology   # lane 10 ValidatedTopology or None (see llm_services, NON_CONTAINER_KINDS)
        # FD55-W5c-PLAN-FACTS: the service directories whose planned push paths are judged
        # (planned_push_route_findings); None (V3c itself): never judged here
        self.push_scope = push_scope

    def validate(self, ctx: Any) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        for svc in llm_services(ctx, self.topology):
            out.extend(d for d in self._service(ctx, svc) if d.code != HEALTH_UNVERIFIED_CODE)
        return out

    def _service(self, ctx: Any, svc: str) -> List[Diagnostic]:
        files = ctx.files
        pf = f"apps/{svc}/Procfile"
        hint = HINT_PROCFILE.format(svc=svc)
        it = ctx.iteration
        if pf not in files:
            return [_d(code="CONTAINER.ENTRYPOINT_MISSING", file=pf, iteration=it, hint=hint,
                       message=f"service '{svc}' has no Procfile: Cloud Buildpacks need an explicit entrypoint")]
        procs, _bad = parse_procfile(files[pf])
        if not procs:
            return [_d(code="CONTAINER.ENTRYPOINT_MISSING", file=pf, iteration=it, hint=hint,
                       message="the Procfile declares no `<process>: <command>` line")]
        out: List[Diagnostic] = []
        for name in sorted(procs):
            cmd = procs[name]
            try:
                argv = shlex.split(cmd)
            except ValueError as e:
                out.append(_d(code="CONTAINER.ENTRYPOINT_MISSING", file=pf, iteration=it, hint=hint, symbol=name,
                              message=f"process '{name}': the command cannot be split ({e}): {cmd!r}"))
                continue
            segment = server_segment(argv)   # HS-40 RT A1: the server of a chained command
            if segment is None:
                continue   # a chain whose last segment is not one simple command is not judged
            launch = parse_command(segment)
            if launch.kind == "unknown":
                continue   # a launcher this validator does not know is not judged
            entry: Optional[str] = None
            if launch.kind == "python_file":
                entry = posixpath.normpath(posixpath.join("apps", svc, launch.target or ""))
                if entry not in files:
                    out.append(_d(code="CONTAINER.ENTRYPOINT_MISSING", file=pf, iteration=it, hint=hint, symbol=name,
                                  message=f"process '{name}' runs {launch.target!r}, which is not a file of "
                                          f"apps/{svc}/ (the Procfile runs from the service directory)"))
                    continue
                if name == "web":
                    tree = _parse(files[entry])
                    if tree is not None and not reads_port(tree) and service_reads_port(files, svc) is False:
                        out.append(_d(code="CONTAINER.PORT_NOT_BOUND", file=entry, iteration=it,
                                      message=f"the web process runs {launch.target!r}, which never reads the PORT "
                                              "environment variable (Cloud Run sends traffic to $PORT)",
                                      hint="Read the port with os.environ.get(\"PORT\", \"8080\") and listen on "
                                           "0.0.0.0, or start an ASGI server: `web: uvicorn main:app --host 0.0.0.0 "
                                           "--port $PORT`."))
            else:
                target = launch.target or ""
                module, _, attr = target.partition(":")
                entry = _module_file(files, svc, launch.app_dir, module) if module else None
                if entry is None:
                    out.append(_d(code="CONTAINER.ENTRYPOINT_MISSING", file=pf, iteration=it, hint=hint, symbol=name,
                                  message=f"process '{name}': {launch.server} app {target!r} names module "
                                          f"{module!r}, which is not in apps/{svc}/ (the Procfile runs from the "
                                          "service directory)"))
                    continue
                attr_name = attr or ("app" if launch.server in ("uvicorn", "hypercorn") else "application")
                tree = _parse(files[entry])
                if tree is not None and attr_name.isidentifier():
                    names, star = top_level_names(tree)
                    if not star and attr_name not in names:
                        out.append(_d(code="CONTAINER.ENTRYPOINT_MISSING", file=pf, iteration=it, hint=hint,
                                      symbol=name,
                                      message=f"process '{name}': module {module!r} ({entry}) defines no "
                                              f"{attr_name!r}"))
                        continue
                if name == "web" and launch.port_ok is False:
                    out.append(_d(code="CONTAINER.PORT_NOT_BOUND", file=pf, iteration=it,
                                  message=f"the web process does not listen on $PORT: {cmd!r}",
                                  hint="Use `--port $PORT` (uvicorn) or `--bind 0.0.0.0:$PORT` (gunicorn, "
                                       "hypercorn); Cloud Run sends traffic to $PORT."))
            if name == "web" and entry is not None:
                out.extend(self._health(ctx, svc, entry))
                if self.push_scope is not None and svc in self.push_scope:
                    out.extend(self._push(ctx, svc, entry))
        return out

    def _push(self, ctx: Any, svc: str, entry: str) -> List[Diagnostic]:
        """FD55-W5c-PLAN-FACTS: every Pub/Sub push the typed plan delivers to this service (exact topology name, S3B-1
        normalization `_` -> `-`) must be served as POST at exactly its path. When that cannot be decided
        (`post_route_state` is None) the only output is the warning PUSH_UNVERIFIED_CODE, which the callers keep apart
        from the blocking code."""
        edges = [e for e in (getattr(self.topology, "pushes", ()) or ()) if e.service == svc.replace("_", "-")]
        out: List[Diagnostic] = []
        for e in sorted(edges, key=lambda x: x.path):
            state = post_route_state(ctx.files, svc, e.path)
            if state is True:
                continue
            if state is None:
                out.append(_d(code=PUSH_UNVERIFIED_CODE, file=entry, iteration=ctx.iteration, severity="warning",
                              symbol=f"POST {e.path}",
                              message=f"the plan's Pub/Sub push subscription for topic '{e.topic}' delivers to POST "
                                      f"{e.path} on service '{svc}'; its routes cannot be read statically, so serving "
                                      f"that path is unverified"))
                continue
            out.append(_d(code=PUSH_ROUTE_CODE, file=entry, iteration=ctx.iteration, symbol=f"POST {e.path}",
                          message=f"the plan's Pub/Sub push subscription for topic '{e.topic}' delivers to POST "
                                  f"{e.path} on service '{svc}', but no route of the service serves POST {e.path}, "
                                  f"so its messages would never be received",
                          hint=f"Serve exactly `POST {e.path}` in this file, e.g. `@app.post(\"{e.path}\")`, reading "
                               f"the Pub/Sub push envelope (JSON body, base64 `message.data`) and answering 2xx. The "
                               f"plan fixes this path: do not choose another one. Keep the file's other top-level "
                               f"names (a repair that drops one is rejected)."))
        return out

    def _health(self, ctx: Any, svc: str, entry: str) -> List[Diagnostic]:
        """The health route(s) required by the probes that call this service (code RT F2c); nothing when no probe is
        known exactly."""
        files = ctx.files
        k8s = k8s_probe_paths(files, svc)
        if k8s is not None:   # a Kubernetes workload that names the service: its own probes (as before F2c)
            required, source = k8s, "its Kubernetes probes call it"
        else:
            cloudrun, unresolved = cloudrun_health_paths(files, svc)
            if unresolved or cloudrun is None:
                return []     # no probe known exactly -> not judged (never the Cloud Run default by guess)
            required, source = cloudrun, "its compute-cloudrun module's startup probe (health_check_path) calls it"
        included = included_route_paths(files, svc)
        if included is None:
            return []
        out: List[Diagnostic] = []
        framework = None
        for path in sorted(required):
            if path in included or self._serves(files, svc, path):
                continue
            if framework is None:
                framework = service_builds_framework_app(files, svc)
            if not framework:   # HR-1: routes not readable -> report-only, never a blocking MISSING
                out.append(_d(code=HEALTH_UNVERIFIED_CODE, file=entry, iteration=ctx.iteration, severity="warning",
                              message=f"service '{svc}' builds no FastAPI/Flask/Starlette app, so its routes cannot "
                                      f"be read; serving GET {path} is unverified ({source})"))
                continue
            out.append(_d(code="CONTAINER.HEALTH_ROUTE_MISSING", file=entry, iteration=ctx.iteration,
                          message=f"no route of service '{svc}' serves GET {path}; {source}",
                          hint=f"Add e.g. `@app.get(\"{path}\")` returning 200 to the web app."))
        return out

    @staticmethod
    def _serves(files: Any, svc: str, path: str) -> bool:
        for p in sorted(files):
            if p.startswith(f"apps/{svc}/") and p.endswith(".py"):
                tree = _parse(files[p])
                if tree is not None and has_route(tree, path):
                    return True
        return False


# FD-55 W5 (register FD55-W5): the files that make `apps/<svc>/` a service with code (the deleted HB-04 placeholder's
# entry-module list, plus the Procfile and a Node package.json, which the build starts from).
PLANNED_ENTRY_FILES = ("Procfile", "main.py", "app.py", "server.js", "main.go", "index.js", "main.ts", "app.ts",
                       "package.json")
# FD-55 W5 RT F3: marks a V3c-planned finding, so the repair loop's stop names it (PLANNED_SERVICE_STOP_REASON)
PLANNED_SERVICE_DETAIL = "planned_service_without_code"
# FD55-W5c (register FD55-W5c, owner 10-25): the files of the one whole-service CREATE round the repair loop offers for
# a V3c-planned finding (HINT_PLANNED's entry module, requirements and Procfile), under the finding's apps/<svc>/.
PLANNED_SERVICE_CREATE_FILES = ("main.py", "requirements.txt", "Procfile")
# RT F7: the plan records no language or runtime per service, so the round offers this Python set; its hint says these
# are the only paths accepted (another file is an out-of-scope write and the round is rejected).
HINT_PLANNED_CREATE = ("The plan names the service '{svc}' but the repository has no code for it. Write the whole "
                       "service now, as a Python service: return exactly these files, complete: {files}. They are the "
                       "only paths accepted in this answer (any other file is rejected). The Procfile starts the web "
                       "process, e.g. `web: uvicorn main:app --host 0.0.0.0 --port $PORT`. This is the only request "
                       "for this service: if it is still missing afterwards, the run stops.")
HINT_PLANNED = ("The plan names the service '{svc}' but the repository has no code for it. Write the service under "
                "apps/{svc}/: its entry module (e.g. main.py), requirements.txt and a Procfile, e.g. `web: uvicorn "
                "main:app --host 0.0.0.0 --port $PORT`. The platform does not generate service code.")


# FD55-W5c-PLAN-FACTS (D1 of the W5c paired check): the facts the platform holds for the service, in the round's hint.
HINT_PLANNED_FACTS = (" PLAN FACTS for this service (the platform's typed plan, binding, not an example): {facts}. Serve "
                      "every entry of `must_serve` at exactly that method and path; a Pub/Sub push subscription "
                      "delivers to each path of `pubsub_pushes`. Read each value this service needs from exactly the "
                      "`env_keys` names (do not invent other names for them). `purpose` is what the service does: "
                      "write that service, not a generic example.")


def planned_service_facts(topology: Any, svc: str, files: Any, typed_intent: bool = False) -> Dict[str, Any]:
    """The plan's facts for the planned service `svc`, from typed data only: kind, role and purpose (ServiceSpec),
    `must_serve` (its probe's health path(s) as `GET <path>`, then one `POST <path>` per push), its push subscriptions
    (PushEdge) and the env keys the platform binds on it (`env_for`, the keys topology_wiring.topology_contract_rule
    lists; `typed_intent`: also the keys only the typed path binds). The health path comes from the service's
    compute-cloudrun module in `files` (V3c's own source); when no module names the service, from the Cloud Run default
    for a topology `cloudrun` service; a non-literal one is left out. {} without a typed plan (the request is then as
    before), and for a service the topology does not name when no module names it either."""
    if topology is None:
        return {}
    facts: Dict[str, Any] = {}
    name = svc.replace("_", "-")
    spec = topology.spec(name)
    if spec is not None:
        facts.update(service=name, kind=spec.kind,
                     role="primary" if name == topology.intent.primary_service else "secondary")
        if spec.purpose:
            facts["purpose"] = spec.purpose
    health, unresolved = cloudrun_health_paths(files, svc)
    if health is None and not unresolved and spec is not None and spec.kind == "cloudrun":
        health = {HEALTH_PATH}
    must_serve = [f"GET {p}" for p in sorted(health or ())]
    if spec is not None:
        pushes = sorted((e for e in topology.pushes if e.service == name), key=lambda e: e.path)
        must_serve += [f"POST {e.path}" for e in pushes]
        if pushes:
            facts["pubsub_pushes"] = [{"topic": e.topic, "method": "POST", "path": e.path} for e in pushes]
        env = set(topology.env_for(name))
        if typed_intent:
            env |= set(topology.typed_only_env_keys(name))
        if env:
            facts["env_keys"] = sorted(env)
    if must_serve:
        facts["must_serve"] = must_serve
    return facts


def planned_push_route_findings(ctx: Any, topology: Any, services: Iterable[str]) -> List[Diagnostic]:
    """FD55-W5c-PLAN-FACTS (D1): CONTAINER.PUSH_ROUTE_MISSING for each service in `services` (directory names: the
    services the repair loop's whole-service CREATE round wrote) that V3c judges, whose `web` entrypoint resolves, and
    that does not serve a Pub/Sub push path of the typed plan as POST. Empty without a topology, for a service with no
    planned push, and whenever that cannot be decided statically (`post_route_state`)."""
    return _planned_push_diagnostics(ctx, topology, services, PUSH_ROUTE_CODE)


def planned_push_route_unverified(ctx: Any, topology: Any, services: Iterable[str]) -> List[Diagnostic]:
    """The same scope as `planned_push_route_findings`, for the planned pushes `post_route_state` cannot decide:
    report-only warnings. The caller puts them in `report.report_only`; they never block and are never repaired."""
    return _planned_push_diagnostics(ctx, topology, services, PUSH_UNVERIFIED_CODE)


def _planned_push_diagnostics(ctx: Any, topology: Any, services: Iterable[str], code: str) -> List[Diagnostic]:
    scope = frozenset(services)
    if topology is None or not scope:
        return []
    v = ContainerContractValidator(topology, push_scope=scope)
    out: List[Diagnostic] = []
    for svc in llm_services(ctx, topology):
        if svc in scope:
            out.extend(d for d in v._service(ctx, svc) if d.code == code)
    return out


def _service_dir_candidates(name: str) -> Tuple[str, ...]:
    """The directory spellings of one planned service: as written, `-` -> `_`, `_` -> `-` (the deleted placeholder's
    exact candidate list)."""
    return tuple(dict.fromkeys((name, name.replace("-", "_"), name.replace("_", "-"))))


class PlannedServiceCodeValidator:
    """V3c-planned (blocking; FD-55 W5, register FD55-W5, replaces the HB-04 placeholder app G15): every planned
    Cloud Run service (terraform_engine.planned_cloud_run_services: the typed multi-service plan) must have code.
    A planned service none of whose directory spellings (`_service_dir_candidates`) holds an entry file
    (PLANNED_ENTRY_FILES, exact path) is CONTAINER.ENTRYPOINT_MISSING on `apps/<svc>/Procfile`; nothing is written.
    A service V3c judges (it holds an LLM-owned `.py`, `llm_services`) is left to V3c's own entrypoint findings, so
    one gap is never reported twice. Exact path equality only."""

    id, tool = "V3c-planned", "container"

    def __init__(self, planned: Any = (), topology: Any = None):
        # A list is kept by reference (FD-55 W5 RT F2: the handler refreshes it with the services each assembly
        # renders); any other iterable is frozen.
        self.planned = planned if isinstance(planned, list) else tuple(planned or ())
        self.topology = topology

    def validate(self, ctx: Any) -> List[Diagnostic]:
        if not self.planned:
            return []
        judged = set(llm_services(ctx, self.topology))
        out: List[Diagnostic] = []
        for svc in tuple(dict.fromkeys(self.planned)):
            dirs = _service_dir_candidates(svc)
            if judged.intersection(dirs):
                continue
            if any(f"apps/{d}/{f}" in ctx.files for d in dirs for f in PLANNED_ENTRY_FILES):
                continue
            out.append(_d(code=ENTRYPOINT_CODE, file=f"apps/{svc}/Procfile", iteration=ctx.iteration,
                          hint=HINT_PLANNED.format(svc=svc), detail=PLANNED_SERVICE_DETAIL,
                          message=f"the plan names the Cloud Run service '{svc}' but apps/{svc}/ has no code "
                                  f"(no Procfile and no entry module)"))
        return out


class HealthRouteUnverifiedValidator:
    """V3c-health-unverified (report_only, HR-1): the health findings V3c withholds for a service without a framework
    app (same Procfile/probe rules; only HEALTH_UNVERIFIED_CODE is kept)."""

    id, tool = "V3c-health-unverified", "container"

    def __init__(self, topology: Any = None):
        self.topology = topology

    def validate(self, ctx: Any) -> List[Diagnostic]:
        v = ContainerContractValidator(self.topology)
        out: List[Diagnostic] = []
        for svc in llm_services(ctx, self.topology):
            out.extend(d for d in v._service(ctx, svc) if d.code == HEALTH_UNVERIFIED_CODE)
        return out


class MigrationInvocationValidator:
    """V3c-migration (blocking, register row HS-40): a service shipping apps/<svc>/alembic.ini must run `alembic
    upgrade` from its `web` Procfile process (RT A2: the only process Cloud Run starts; RT A3: alembic global options
    may stand between `alembic` and `upgrade`). The finding is an error on apps/<svc>/Procfile (the file the repair
    edits) with a hint."""

    id, tool = "V3c-migration", "container"

    def __init__(self, topology: Any = None):
        self.topology = topology

    def validate(self, ctx: Any) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        for svc in llm_services(ctx, self.topology):
            if f"apps/{svc}/alembic.ini" not in ctx.files:
                continue
            procs, _ = parse_procfile(ctx.files.get(f"apps/{svc}/Procfile", ""))
            web = procs.get(WEB_PROCESS)
            try:
                invoked = web is not None and runs_alembic_upgrade(shlex.split(web))
            except ValueError:
                invoked = False   # an unsplittable web command is V3c's ENTRYPOINT_MISSING; it runs nothing here
            if not invoked:
                out.append(_d(code=MIGRATION_CODE, file=f"apps/{svc}/Procfile", iteration=ctx.iteration,
                              hint=HINT_MIGRATION.format(svc=svc),
                              message=f"service '{svc}' ships Alembic migrations (apps/{svc}/alembic.ini) but its "
                                      "`web` Procfile process does not run `alembic upgrade` (Cloud Run starts only "
                                      "the web process), so the database schema is never migrated"))
        return out


# ------------------------------------------------------------------------------------------------ PWB-4 (10-19)
# A gke-autopilot topology service runs only if a Kubernetes workload runs its image: compute-gke-autopilot renders the
# cluster and nothing else, and the platform applies exactly the top-level `k8s/*.yaml|yml` files of the repository
# (the service's CI workflow `kubectl apply -f k8s/`, handler.generate_service_workflow; the terraform MCP's post-apply
# step lists `<workspace>/k8s/` -- both non-recursive). Gate A 05-r2 x3: the image was built, nothing ran it.
K8S_WORKLOAD_MISSING_CODE = "CONTAINER.K8S_WORKLOAD_MISSING"
# RT F1: an applied manifest that is not YAML is its own blocking finding (nothing downstream parses it: hydration is
# string replacement and both apply paths log a failure as non-fatal), never a reason to skip the check.
K8S_MANIFEST_UNPARSEABLE_CODE = "CONTAINER.K8S_MANIFEST_UNPARSEABLE"
K8S_APPLY_DIR = "k8s"
# Kinds that run the service's pods, with the exact path of their pod spec (RT F2: Job / CronJob too). A `kind: List`
# document is unwrapped through `items` (kubectl apply accepts it).
K8S_POD_SPEC_PATHS: Dict[str, Tuple[str, ...]] = {
    "Deployment": ("spec", "template", "spec"), "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"), "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}
K8S_LIST_KIND = "List"
# Terraform kubernetes-provider resources that run pods (the platform configures the provider for gke-autopilot,
# terraform_engine). Their names are usually expressions (`${local.app_name}`, Gate A 04-r1), so a root module that
# declares one makes the check not judged (never a name guess; tofu validate is blocking on that file).
TF_K8S_WORKLOAD_TYPES = frozenset({"kubernetes_deployment", "kubernetes_deployment_v1", "kubernetes_stateful_set",
                                   "kubernetes_stateful_set_v1", "kubernetes_daemonset", "kubernetes_daemon_set_v1",
                                   "kubernetes_job", "kubernetes_job_v1", "kubernetes_cron_job",
                                   "kubernetes_cron_job_v1", "kubernetes_manifest"})
K8S_WORKLOAD_WORDING = "a Deployment (or StatefulSet / DaemonSet / Job / CronJob)"


def applied_k8s_manifest_paths(files: Any) -> List[str]:
    """The manifests the platform applies: `k8s/<file>.yaml|yml`, exactly one path segment below the repository root
    (`apps/<svc>/k8s/deployment.yaml` is never applied)."""
    return sorted(p for p in files if p.endswith((".yaml", ".yml")) and len(p.split("/")) == 2
                  and p.split("/")[0] == K8S_APPLY_DIR)


def _dig(doc: Any, path: Tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(key)
    return doc


def _workload_docs(docs: List[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        if doc.get("kind") == K8S_LIST_KIND and isinstance(doc.get("items"), list):
            out.extend(d for d in doc["items"] if isinstance(d, dict) and d.get("kind") in K8S_POD_SPEC_PATHS)
        elif doc.get("kind") in K8S_POD_SPEC_PATHS:
            out.append(doc)
    return out


def k8s_workload_names(text: str) -> Tuple[Optional[Set[str]], Optional[str]]:
    """(names, None): `metadata.name` and every container `name` of each workload document (K8S_POD_SPEC_PATHS kinds,
    also inside a `kind: List`; yaml.safe_load_all, exact strings). (None, <PyYAML error>) when the text is not YAML.
    (None, None) when PyYAML is missing (the caller then does not judge)."""
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML ships with the gateway (uvicorn[standard])
        return None, None
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as e:
        return None, " ".join(str(e).split())[:500] or type(e).__name__
    names: Set[str] = set()
    for doc in _workload_docs(docs):
        meta = doc.get("metadata")
        if isinstance(meta, dict) and isinstance(meta.get("name"), str):
            names.add(meta["name"])
        containers = _dig(doc, K8S_POD_SPEC_PATHS[doc["kind"]] + ("containers",))
        if isinstance(containers, list):
            names |= {c["name"] for c in containers if isinstance(c, dict) and isinstance(c.get("name"), str)}
    return names, None


def declares_tf_k8s_workload(files: Any) -> Optional[bool]:
    """Whether a root-module `.tf` file of infra/workload/ declares a TF_K8S_WORKLOAD_TYPES resource (python-hcl2,
    exact resource type). None when a root-module file cannot be indexed (not judged; tofu validate reports it)."""
    try:
        from ..assembly import WORKLOAD, index_blocks
    except ImportError:  # pragma: no cover
        from developer_agent.assembly import WORKLOAD, index_blocks  # type: ignore
    for p in sorted(files):
        if not (p.startswith(WORKLOAD) and p.endswith(".tf") and "/" not in p[len(WORKLOAD):]):
            continue
        text = files[p]
        blocks = index_blocks(text) if isinstance(text, str) else None
        if blocks is None:
            return None
        if any(b.kind == "resource" and b.labels and b.labels[0] in TF_K8S_WORKLOAD_TYPES for b in blocks):
            return True
    return False


def k8s_workload_hint(svc: str, path: Optional[str] = None) -> str:
    """MANIFEST-PATH-DEFERS-TO-DAG: `path` = the manifest the architect's plan names for the service (None: the
    platform's own `k8s/<svc>.yaml`, the text byte-identical to before)."""
    target = path if path is not None else f"k8s/{svc}.yaml"
    plan = " (the manifest the architect's plan names for this service)" if path is not None else ""
    return (f"Write {target}{plan} (repository root: the platform applies exactly k8s/*.yaml) with "
            f"{K8S_WORKLOAD_WORDING} named `{svc}` whose container `{svc}` uses "
            f"`image: ${{ARTIFACT_REGISTRY}}/{svc}:latest` (the image the platform builds from apps/{svc}/) and runs "
            f"the service's Procfile command.")


class K8sWorkloadValidator:
    """V3c-k8s (PWB-4, blocking; registered only for a topology with a gke-autopilot service): every gke-autopilot
    topology service must be named (metadata.name or a container name, exact) by a workload document
    (K8S_POD_SPEC_PATHS kinds, also inside a `kind: List`) in a manifest the platform applies
    (`applied_k8s_manifest_paths`). An applied manifest that is not YAML is CONTAINER.K8S_MANIFEST_UNPARSEABLE (file =
    that manifest; repaired by its own author on the normal route), and the services are still judged against the
    manifests that parsed (RT F1). Not judged when the root module declares a Terraform Kubernetes workload
    (TF_K8S_WORKLOAD_TYPES) or a root-module `.tf` file cannot be indexed. The missing-workload finding's file is
    `k8s/<svc>.yaml`: a file to create when it does not exist (repair_loop.CREATE_FILE_CODES, routed to the persona
    that writes the manifests), otherwise that file's own author repairs it. Never writes."""

    id, tool = "V3c-k8s", "container"

    def __init__(self, topology: Any = None, manifest_paths: Optional[Dict[str, Tuple[str, ...]]] = None):
        self.services: Tuple[str, ...] = tuple(n for n in topology.names if topology.kind(n) == "gke-autopilot") \
            if topology is not None else ()
        # MANIFEST-PATH-DEFERS-TO-DAG: service -> the applied manifest paths the architect's DAG names for it
        # (developer_agent.plan_targets.dag_manifest_paths); None / {} / a service without one: `k8s/<svc>.yaml`
        self.manifest_paths: Dict[str, Tuple[str, ...]] = dict(manifest_paths or {})

    def missing_workload_path(self, svc: str, files: Any) -> Tuple[str, Optional[str]]:
        """(the finding's file, the plan path or None): the first DAG manifest path of the service that is not in the
        tree (a file to create), else its first DAG manifest path (repaired by that file's author); without a DAG
        path the platform's `k8s/<svc>.yaml`, exactly as before."""
        planned = [p for p in self.manifest_paths.get(svc, ()) if isinstance(p, str)]
        if not planned:
            return f"{K8S_APPLY_DIR}/{svc}.yaml", None
        path = next((p for p in planned if p not in files), planned[0])
        return path, path

    def validate(self, ctx: Any) -> List[Diagnostic]:
        if not self.services:
            return []
        files = ctx.files
        if declares_tf_k8s_workload(files) is not False:
            return []
        out: List[Diagnostic] = []
        named: Set[str] = set()
        for p in applied_k8s_manifest_paths(files):
            if not isinstance(files[p], str):
                continue
            names, err = k8s_workload_names(files[p])
            if names is None and err is None:
                return []      # no YAML parser in this process: not judged (never a guess)
            if names is None:
                out.append(_d(code=K8S_MANIFEST_UNPARSEABLE_CODE, file=p, iteration=ctx.iteration,
                              message=f"Kubernetes manifest {p} is not valid YAML ({err}); the platform applies it "
                                      f"as written, so nothing in it can run",
                              hint="Rewrite the file as valid YAML (one Kubernetes object per `---` document; quote "
                                   "values that contain `: ` or start with a special character)."))
                continue
            named |= names
        for svc in self.services:
            if svc in named:
                continue
            path, planned = self.missing_workload_path(svc, files)
            out.append(_d(code=K8S_WORKLOAD_MISSING_CODE, file=path, iteration=ctx.iteration,
                          hint=k8s_workload_hint(svc, planned),
                          message=f"GKE service '{svc}' has no Kubernetes workload: no {K8S_WORKLOAD_WORDING} in "
                                  f"k8s/*.yaml names it, so its image is built but never runs"))
        return out


IMPORT_ROOT_CODE = "CONTAINER.IMPORT_OUTSIDE_SERVICE"
# The monorepo directory that holds the services. `pack --path=apps/<svc>` (and QA) put apps/<svc>/ on sys.path, never
# the repo root, so `apps.<...>` only resolves if the service itself ships an `apps/` package.
REPO_SERVICES_DIR = "apps"
IMPORT_ERROR_GUARDS = frozenset({"ImportError", "ModuleNotFoundError", "Exception", "BaseException"})
# Launcher options / Procfile forms that change the import root: such a service is not judged (no diagnostic).
IMPORT_ROOT_OPTIONS = frozenset({"--app-dir", "--chdir", "--pythonpath"})


def _catches_import_error(node: ast.AST) -> bool:
    for h in getattr(node, "handlers", []):
        types = h.type.elts if isinstance(h.type, ast.Tuple) else [h.type]
        for t in types:
            if t is None:
                return True   # bare `except:`
            name = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else None)
            if name in IMPORT_ERROR_GUARDS:
                return True
    return False


def _is_type_checking(test: ast.AST) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or \
           (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _suppresses_import_error(node: ast.AST) -> bool:
    """`with suppress(ImportError):` / `with contextlib.suppress(...):` (exact call name `suppress`, a Name or an
    Attribute) whose arguments name ImportError or a base class (IMPORT_ERROR_GUARDS)."""
    for item in node.items:
        call = item.context_expr
        if not isinstance(call, ast.Call):
            continue
        fn = call.func
        name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else None)
        if name != "suppress":
            continue
        for a in call.args:
            arg = a.id if isinstance(a, ast.Name) else (a.attr if isinstance(a, ast.Attribute) else None)
            if arg in IMPORT_ERROR_GUARDS:
                return True
    return False


def runtime_imports(tree: ast.Module) -> List[ast.AST]:
    """Import / ImportFrom nodes that run unguarded: not in the body of a `try` whose handlers catch ImportError
    (or a base class), not under `if TYPE_CHECKING:`, not in a `with suppress(ImportError | base class):` body."""
    out: List[ast.AST] = []

    def visit(node: ast.AST, guarded: bool) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if not guarded:
                out.append(node)
            return
        if isinstance(node, ast.Try) or type(node).__name__ == "TryStar":
            body_guarded = guarded or _catches_import_error(node)
            for c in node.body:
                visit(c, body_guarded)
            for c in list(node.handlers) + list(node.orelse) + list(node.finalbody):
                visit(c, guarded)
            return
        if isinstance(node, ast.If) and _is_type_checking(node.test):
            for c in node.body:
                visit(c, True)
            for c in node.orelse:
                visit(c, guarded)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)) and _suppresses_import_error(node):
            for item in node.items:
                visit(item.context_expr, guarded)
            for c in node.body:
                visit(c, True)
            return
        for c in ast.iter_child_nodes(node):
            visit(c, guarded)

    visit(tree, False)
    return out


def _import_root_changed(files: Any, svc: str) -> bool:
    """True when a Procfile process changes the import root (a `cd`, a `PYTHONPATH=` assignment, `--app-dir` /
    `--chdir` / `--pythonpath`), or a process line cannot be split: the service is then not judged."""
    procs, _ = parse_procfile(files.get(f"apps/{svc}/Procfile", ""))
    for cmd in procs.values():
        try:
            argv = shlex.split(cmd)
        except ValueError:
            return True
        for tok in argv:
            key = tok.split("=", 1)[0]
            if tok == "cd" or key == "PYTHONPATH" or key in IMPORT_ROOT_OPTIONS:
                return True
    return False


class ImportRootValidator:
    """V3c-imports (report_only; FD-4AE-c): an import in an AI-written service file that cannot resolve under the
    container's import root. Buildpacks build `--path=apps/<svc>` and QA runs the service with apps/<svc>/ as cwd and
    PYTHONPATH, so (a) an absolute `apps.<...>` import resolves only to a module the service itself ships, and (b) a
    relative import of level L in a file D directories below apps/<svc>/ needs L <= D (a module at the service root has
    no parent package). Exact: ast only; the import must run unguarded (no ImportError fallback, not TYPE_CHECKING),
    and a service whose Procfile changes the import root is not judged. This replaces the post-QA build rewrite of
    such imports (#11 in the FD-4AE inventory, deleted): the writer fixes the import before QA."""

    id, tool = "V3c-imports", "container"

    def __init__(self, topology: Any = None):
        self.topology = topology

    def validate(self, ctx: Any) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        for svc in llm_services(ctx, self.topology):
            if _import_root_changed(ctx.files, svc):
                continue
            root = f"apps/{svc}/"
            for path in sorted(p for p in ctx.files if p.startswith(root) and p.endswith(".py")):
                if ctx.ownership(path) not in LLM_OWNED:
                    continue
                tree = _parse(ctx.files[path])
                if tree is None:
                    continue   # V3a-syntax reports it
                depth = len(path[len(root):].split("/")) - 1
                for node in runtime_imports(tree):
                    out.extend(self._check(ctx, svc, path, depth, node))
        return out

    def _check(self, ctx: Any, svc: str, path: str, depth: int, node: ast.AST) -> List[Diagnostic]:
        if isinstance(node, ast.ImportFrom) and node.level:
            if node.level <= depth:
                return []
            what = "." * node.level + (node.module or "")
            why = ("a module at the service root has no parent package" if depth == 0 else
                   f"it climbs {node.level - 1} package level(s) from a file {depth} level(s) below apps/{svc}/")
        else:
            mods = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
            bad = [m for m in mods if m.split(".")[0] == REPO_SERVICES_DIR
                   and _resolve_module(ctx.files, svc, path, m, 0) is None]
            if not bad:
                return []
            what = bad[0]
            why = f"apps/{svc}/ is the import root, so `{REPO_SERVICES_DIR}` is not importable"
        return [_d(code=IMPORT_ROOT_CODE, file=path, line=getattr(node, "lineno", None), iteration=ctx.iteration,
                   severity="warning", symbol=what,
                   message=f"import of `{what}` cannot resolve in the container ({why}; QA runs the same root)",
                   hint=f"Import service modules relative to apps/{svc}/ (e.g. `from models import X`) or ship the "
                        f"module inside apps/{svc}/.")]


__all__ = ["ContainerContractValidator", "HealthRouteUnverifiedValidator", "MigrationInvocationValidator", "MIGRATION_CODE",
           "ImportRootValidator", "runtime_imports", "parse_procfile", "parse_command",
           "is_port_ref", "has_route", "reads_port", "llm_services", "included_route_paths", "service_reads_port",
           "settings_reads_port", "cloudrun_health_paths", "NON_CONTAINER_KINDS", "server_segment",
           "runs_alembic_upgrade", "is_topology_container_service", "K8sWorkloadValidator",
           "K8S_WORKLOAD_MISSING_CODE", "K8S_MANIFEST_UNPARSEABLE_CODE", "applied_k8s_manifest_paths",
           "k8s_workload_names", "declares_tf_k8s_workload", "k8s_workload_hint"]

"""RUNTIME-ENV-CONTRACT-CHECK (owner 11-10, warning-only for launch): environment variables a service's code reads
that the platform does not set on that service.

Live defects of the same class (11-09 / 11-10): the generated code read `OIDC_AUDIENCE` and, later,
`GOOGLE_CLOUD_PROJECT` / `GCP_PROJECT` with a literal default, while the platform set neither on the Cloud Run
service; QA mocks the cloud, so only a live run showed it. This module compares two typed facts per topology service:

- **What the platform sets**: `topology_wiring.callee_env_names` (Cloud Run's own and the golden module's names
  `RESERVED_ENV_KEYS`, the deploy nonce, the topology's `env_for` bindings and HB-05's non-sibling keys), or "unknown"
  with its reason (a variables file may set `var.env_vars`, an override file declares the module, the service is not
  a Cloud Run service ...). Nothing is added here by guessing.
- **What the code reads**: the non-test Python files of `apps/<service>/` (the repository's workload test-path rule,
  `audience_facts.is_test_path`), parsed with `ast` only, through `audience_facts`' import and constant resolution
  (Invariant 2: no regex or substring test on source). Counted forms: `os.getenv(NAME[, default])`,
  `os.environ.get(NAME[, default])` and `os.environ[NAME]` (Load), with `os` / `environ` / `getenv` resolved through
  imports and aliases (`from os import getenv as g`, the service's own modules, star imports); NAME a str constant or
  a module-level name bound once to one (also through `from <own module> import NAME`). A read whose NAME is anything
  else (a parameter, an f-string, a call) is counted as unresolved, never reported. A name the service's own code
  writes (`os.environ[NAME] = ...`, `os.environ.setdefault(NAME, ...)`, `os.putenv(NAME, ...)`) is not reported.
  Nor is a read inside the default expression of a read whose NAME the platform sets (or the code writes):
  `os.getenv("GCP_PROJECT_ID", os.getenv("GOOGLE_CLOUD_PROJECT", "x"))` with GCP_PROJECT_ID set evaluates the inner
  read but discards its value (EnvRead.shadowed_by; a default holding a walrus `:=` shadows nothing). Not reported
  rather than labelled: the finding means "the code uses this read's fallback", which cannot happen there, and a
  warning nobody can act on is noise on the operator's page; the facts keep it for measurement (`summary`).
  Not read (documented limits): pydantic-settings fields, `os.environ` passed around as a value, `importlib` /
  `exec`, a Procfile or `.env` that sets the variable.

A read whose NAME the known set does not hold is one ENV.READ_NOT_PROVIDED finding (service, file:line, NAME, the
form, whether a default is given and the default as written, trimmed). The default's text is reported, never judged.
A service whose set is unknown and whose code reads at least one resolved NAME contributes to one
ENV.PROVIDED_SET_UNKNOWN finding per workload. No topology = no finding (the legacy path has no typed env set).
At most MAX_FINDINGS_PER_SERVICE findings per service and MAX_FINDINGS per workload are kept (RuntimeEnvResult.total
counts all of them).

Pure functions; no I/O, no LLM, no change to any tree, prompt or rendered IaC. The policy (report only) lives in
validators/runtime_env.py.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, replace
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Set, Tuple

try:
    from . import audience_facts as _af
    from .topology_wiring import callee_env_names
except ImportError:  # pragma: no cover - imported as a top-level module
    from developer_agent import audience_facts as _af  # type: ignore[no-redef]
    from developer_agent.topology_wiring import callee_env_names  # type: ignore[no-redef]

READ_NOT_PROVIDED = "ENV.READ_NOT_PROVIDED"
PROVIDED_SET_UNKNOWN = "ENV.PROVIDED_SET_UNKNOWN"

FORM_GETENV = "os.getenv"
FORM_ENVIRON_GET = "os.environ.get"
FORM_ENVIRON_SUBSCRIPT = "os.environ[]"
_FORM_OF_GETTER = {"os.getenv": FORM_GETENV, "os.environ.get": FORM_ENVIRON_GET}
_PUTENV = "os.putenv"
_SETDEFAULT = "setdefault"
DEFAULT_TEXT_MAX = 80   # characters of a default kept in a finding
# Bounds on what one check keeps (the work itself is one ast walk per non-test file, with audience_facts' memoised,
# 8-hop name resolution): at most MAX_FINDINGS_PER_SERVICE ENV.READ_NOT_PROVIDED findings per service and
# MAX_FINDINGS per workload are kept; RuntimeEnvResult.total counts them all.
MAX_FINDINGS_PER_SERVICE = 20
MAX_FINDINGS = 50


@dataclass(frozen=True)
class EnvRead:
    """One counted read of the process environment in a service's code."""
    file: str            # repository path
    line: int
    name: str
    form: str            # FORM_GETENV / FORM_ENVIRON_GET / FORM_ENVIRON_SUBSCRIPT
    has_default: bool
    default: Optional[str] = None       # the default as written (trimmed), when there is one
    default_is_literal: bool = False    # the default is a constant (or a module-level name bound to one)
    # The NAMEs of the reads whose default expression contains this read (`os.getenv("A", os.getenv("B", "x"))`:
    # the read of B has ("A",)). Python evaluates that default either way, but its value is discarded whenever A is
    # set, so when the platform sets (or the code writes) any of these names this read's value is never used.
    shadowed_by: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ServiceEnvReads:
    service: str
    reads: Tuple[EnvRead, ...]
    unresolved: Tuple[Tuple[str, int, str], ...]   # (file, line, why): a read whose NAME is not a constant
    written: FrozenSet[str]                        # names the service's own code sets
    parse_error: Optional[str] = None              # a non-test file that does not parse (its reads are not counted)


@dataclass(frozen=True)
class Finding:
    code: str
    service: str
    message: str
    file: str
    line: Optional[int] = None
    name: Optional[str] = None
    form: Optional[str] = None
    has_default: Optional[bool] = None
    default: Optional[str] = None
    default_is_literal: Optional[bool] = None
    reason: Optional[str] = None   # PROVIDED_SET_UNKNOWN: why each service's set is not known

    def record(self) -> Dict[str, Any]:
        """The workload record entry (`workloads/{product_id}.runtime_env_advisories`): plain JSON fields."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


def _trim(text: str) -> str:
    return text if len(text) <= DEFAULT_TEXT_MAX else text[:DEFAULT_TEXT_MAX - 3] + "..."


def _arg(call: ast.Call, index: int, keyword: str) -> Optional[ast.AST]:
    if len(call.args) > index:
        return call.args[index]
    return next((k.value for k in call.keywords if k.arg == keyword), None)


def service_env_reads(files: Mapping[str, str], service: str) -> ServiceEnvReads:
    """Every counted environment read of `apps/<service>/`'s non-test Python code (see the module docstring)."""
    cal = _af._Callee(service, files)
    found: List[Tuple[int, EnvRead]] = []   # (id of the read's node, read)
    shadow: Dict[int, Set[str]] = {}         # id of a node inside a resolved read's default -> that read's NAME
    unresolved: List[Tuple[str, int, str]] = []
    written: Set[str] = set()

    for rel, f in sorted(cal.files.items()):
        path = cal.root + rel

        def const_name(expr: Optional[ast.AST], scope: Any) -> Optional[str]:
            got = cal.resolve(f, expr, scope, env_ok=False)
            return got[0] if got is not None and got[0] else None

        def read(node: ast.AST, form: str, key: Optional[ast.AST], default: Optional[ast.AST], scope: Any) -> None:
            line = getattr(node, "lineno", 0)
            name = const_name(key, scope)
            if name is None:
                unresolved.append((path, line, f"{form} with a name that is not a constant"))
                return
            text, literal = None, False
            if default is not None:
                got = cal.resolve(f, default, scope, env_ok=False)
                if got is not None:
                    text, literal = got[0], True
                elif isinstance(default, ast.Constant):
                    text, literal = repr(default.value), True
                else:
                    text = ast.unparse(default)
                text = _trim(text)
                # the default's value is discarded when NAME is set; a walrus inside it binds a name the code may read
                # later, so such a default shadows nothing
                inner = list(ast.walk(default))
                if not any(isinstance(n, ast.NamedExpr) for n in inner):
                    for n in inner:
                        shadow.setdefault(id(n), set()).add(name)
            found.append((id(node), EnvRead(path, line, name, form, default is not None, text, literal)))

        for scope in f.scopes:
            for node in _af._scope_nodes(scope.node):
                if isinstance(node, ast.Call):
                    api = cal.api_of(f, node.func, scope, _af._ENV_TARGETS)
                    starred = (any(isinstance(a, ast.Starred) for a in node.args)
                               or any(k.arg is None for k in node.keywords))
                    if isinstance(api, str) and api in _FORM_OF_GETTER:
                        if starred:
                            unresolved.append((path, node.lineno, f"{api} with star arguments"))
                        else:
                            read(node, _FORM_OF_GETTER[api], _arg(node, 0, "key"), _arg(node, 1, "default"), scope)
                    elif api == _PUTENV and not starred:
                        name = const_name(_arg(node, 0, "key"), scope)
                        if name:
                            written.add(name)
                    elif (isinstance(node.func, ast.Attribute) and node.func.attr == _SETDEFAULT and not starred
                          and cal.api_of(f, node.func.value, scope, _af._ENV_TARGETS) in _af._ENV_MAPPINGS):
                        name = const_name(_arg(node, 0, "key"), scope)
                        if name:
                            written.add(name)
                elif (isinstance(node, ast.Subscript)
                      and cal.api_of(f, node.value, scope, _af._ENV_TARGETS) in _af._ENV_MAPPINGS):
                    if isinstance(node.ctx, ast.Load):
                        read(node, FORM_ENVIRON_SUBSCRIPT, node.slice, None, scope)
                    elif isinstance(node.ctx, ast.Store):
                        name = const_name(node.slice, scope)
                        if name:
                            written.add(name)
    reads = [replace(r, shadowed_by=tuple(sorted(shadow.get(nid, ())))) for nid, r in found]
    reads.sort(key=lambda r: (r.file, r.line, r.name))
    unresolved.sort()
    return ServiceEnvReads(service, tuple(reads), tuple(unresolved), frozenset(written), cal.parse_error)


def _read_message(service: str, r: EnvRead) -> str:
    where = f"{r.file}:{r.line}"
    if not r.has_default:
        tail = "and the code gives no default"
    elif r.default_is_literal:
        tail = f"so the code's default applies: {r.default!r}"
    else:
        tail = f"so the code's default expression applies: {r.default}"
    return (f"Service '{service}' reads the environment variable {r.name} ({r.form}, {where}), which the platform "
            f"does not set on this Cloud Run service, {tail}.")


# APP-ADMIN-IAP-CONTRACT: the platform's own root renders (rewritten on every run): main.tf holds module "compute",
# services.tf the topology's secondaries. A module only another file declares (a repository file the platform skips,
# services_tf_skip_addresses, or a kept repository service, RT14-12) is not the platform's render.
_PLATFORM_MODULE_FILES = ("infra/workload/main.tf", "infra/workload/services.tf")


def _blocks(files: Mapping[str, str], path: str, index_blocks: Any) -> List[Any]:
    text = files.get(path)
    if not isinstance(text, str):
        return []
    try:
        return list(index_blocks(text) or [])
    except Exception:  # noqa: BLE001 - unparsable: nothing in it is known
        return []


def platform_admin_env(files: Mapping[str, str], module_label: str) -> FrozenSet[str]:
    """APP-ADMIN-IAP-CONTRACT: {STACKVEND_APP_ADMIN_EMAILS} for the service whose compute module is `module_label`
    when (exact block parse, no expression text read) the platform-rendered infra/workload/variables.tf declares
    `variable "app_admin_emails"` AND the platform's own main.tf / services.tf declares exactly one compute-cloudrun
    `module "<module_label>"`: the platform renders that env on every compute-cloudrun module call it writes while
    the variable is declared (one gate input). Else (a service the platform skipped or kept, not Cloud Run, or a file
    that does not parse) the empty set."""
    try:
        from .assembly import index_blocks
        from .sibling_wiring import _is_cloud_run_module_source
        from .terraform_engine import APP_ADMIN_EMAILS_ENV, APP_ADMIN_EMAILS_VARIABLE
    except ImportError:  # pragma: no cover - imported as a top-level module
        from developer_agent.assembly import index_blocks  # type: ignore[no-redef]
        from developer_agent.sibling_wiring import _is_cloud_run_module_source  # type: ignore[no-redef]
        from developer_agent.terraform_engine import APP_ADMIN_EMAILS_ENV, APP_ADMIN_EMAILS_VARIABLE  # type: ignore
    declared = any(b.kind == "variable" and tuple(b.labels) == (APP_ADMIN_EMAILS_VARIABLE,)
                   for b in _blocks(files, "infra/workload/variables.tf", index_blocks))
    if not declared:
        return frozenset()
    modules = [b for path in _PLATFORM_MODULE_FILES for b in _blocks(files, path, index_blocks)
               if b.kind == "module" and tuple(b.labels) == (module_label,)]
    if len(modules) != 1 or not _is_cloud_run_module_source((modules[0].body or {}).get("source")):
        return frozenset()
    return frozenset({APP_ADMIN_EMAILS_ENV})


@dataclass(frozen=True)
class RuntimeEnvResult:
    """The kept findings (bounded, see MAX_FINDINGS*) and how many there were in all."""
    findings: Tuple[Finding, ...]
    total: int


def runtime_env_result(topology: Any, files: Optional[Mapping[str, str]],
                       deployed_files: Optional[Mapping[str, str]] = None) -> RuntimeEnvResult:
    """The findings for every service of `topology` (see the module docstring); none without a topology or a tree.
    The service code is read from `files`; the platform's env set (callee_env_names) from `files` and, for its
    variables-file and override checks, `deployed_files` (topology_wiring.deployed_view: the repository files the build
    does not rewrite included; None = `files`). A read whose value is unused because an enclosing read's NAME is set
    (EnvRead.shadowed_by) is not reported."""
    if topology is None or not files:
        return RuntimeEnvResult((), 0)
    out: List[Finding] = []
    total = 0
    unknown: List[Tuple[str, str]] = []
    for service in topology.names:
        facts = service_env_reads(files, service)
        if not facts.reads:
            continue
        names, why = callee_env_names(topology, service, files, deployed_files=deployed_files)
        if names is None:
            unknown.append((service, why))
            continue
        # APP-ADMIN-IAP-CONTRACT: the admin env, only on a Cloud Run module the platform itself rendered
        provided = set(names) | set(facts.written) | set(platform_admin_env(files, topology.label(service)))
        kept = 0
        for r in facts.reads:
            if r.name in provided or provided.intersection(r.shadowed_by):
                continue
            total += 1
            if kept >= MAX_FINDINGS_PER_SERVICE or len(out) >= MAX_FINDINGS:
                continue
            kept += 1
            out.append(Finding(READ_NOT_PROVIDED, service, _read_message(service, r), r.file, r.line, r.name, r.form,
                               r.has_default, r.default, r.default_is_literal if r.has_default else None))
    if unknown:
        total += 1
        listed = "; ".join(f"{s} ({why})" for s, why in unknown)
        first = unknown[0][0]
        note = Finding(PROVIDED_SET_UNKNOWN, first,
                       f"The environment variables the platform sets are not known for: {listed}. The code's "
                       "environment reads of these services were not checked.",
                       f"apps/{first}/", reason=listed)
        out = (out[:MAX_FINDINGS - 1] if len(out) >= MAX_FINDINGS else out) + [note]
    return RuntimeEnvResult(tuple(out), total)


def runtime_env_findings(topology: Any, files: Optional[Mapping[str, str]],
                         deployed_files: Optional[Mapping[str, str]] = None) -> List[Finding]:
    """runtime_env_result(...).findings as a list."""
    return list(runtime_env_result(topology, files, deployed_files).findings)


def summary(topology: Any, files: Optional[Mapping[str, str]]) -> Dict[str, Any]:
    """Measurement helper (plan §6, eval trees): per service, the counted reads, unresolved reads, the provided set
    (or why unknown) and the findings."""
    out: Dict[str, Any] = {"services": {}, "findings": []}
    if topology is None or not files:
        return out
    for service in topology.names:
        facts = service_env_reads(files, service)
        names, why = callee_env_names(topology, service, files)
        out["services"][service] = {
            "kind": topology.kind(service), "reads": len(facts.reads), "unresolved": len(facts.unresolved),
            "read_names": sorted({r.name for r in facts.reads}),
            "shadowed": sorted(f"{r.name}<{','.join(r.shadowed_by)}" for r in facts.reads
                               if names is not None and set(r.shadowed_by) & (set(names) | set(facts.written))),
            "provided": sorted(names) if names is not None else None, "unknown_reason": why or None}
    out["findings"] = [f.record() for f in runtime_env_findings(topology, files)]
    return out

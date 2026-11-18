"""Typed compute intent: the workload's compute archetype and Cloud Run service set (HD-01 / HD-02 replacement).

Replaces `terraform_engine.detect_compute_archetype` (HD-01, FD-4X: archetype from spec keywords) and
`detect_requested_service_count` / `detect_requested_service_names` (HD-02, FD-4AC, FD21-08: service names and counts
from spec-prose regexes, padded with `service-N`). Those guessers turned example 01/03's Cloud Run service into a
Cloud Run Job and deployed phantom services (`service-with`, `service-must`, `service-account`, ...).

The intent is resolved ONLY from typed facts (AGENTS.md invariant 2: no substring/regex guessing), in this order:

1. **Existing repository** (`existing_files`, the workload repo's main branch): the platform's own compute modules,
   found by an exact python-hcl2 parse of `infra/workload/*.tf`. The primary is `module "compute"` in `main.tf`; its
   kind is the golden module directory its literal `source` resolves to (`../modules/<dir>`, exact path component).
   Secondaries are `module "compute_<x>"` blocks whose source is the golden `compute-cloudrun` module. Existing
   compute is pinned: it is never dropped and its kind never changes on regeneration (lane 10 §8: removal or a kind
   change needs decommission, FD-4Q). A conflicting architect archetype is recorded, not applied.
2. **Architect plan** (`ArchitecturePlanDAG`, recorded in the architect's typed output):
   - `compute_archetype` (exact enum in the architect's LLM response schema, `ArchitecturePlanDAG.compute_archetype`;
     docs/handoff/architect-compute-archetype-report.md). A value outside `ARCHETYPES` raises
     `InvalidComputeIntentError` (never a default); absent / null (records written before the field) falls through;
   - else `bundle_id` (typed literal) through the data table `BUNDLE_PRIMARY_ARCHETYPE`;
   - else `cloudrun`: the architect's contract defines `target_compute_services` as Cloud Run services.
   Services: `target_compute_services` in the architect's order (normalized exactly: trim, lower case, `_` -> `-`).
   An empty list means the architect's documented single-service default `[product_id]`.
3. **Platform default** (no architect record and no existing compute): `cloudrun` with `[product_id]`, recorded as
   `source="platform-default"` and logged as a warning.

Service-list contract (all archetypes): `service_names[0]` is the workload deployed on `module "compute"` (for a
non-Cloud-Run primary: the cluster / VM / job workload); `service_names[1:]` are Cloud Run secondary services.
`foundation-only` (no compute) is reachable only from the typed fact `compute_archetype == "foundation-only"`. An existing
foundation-only workload (platform `main.tf` without `module "compute"`) pins nothing, so compute can be added later.

Lane 10 (FD-51): a v2 architect record carries the validated per-service `service_topology`
(shared/service_topology.py). Then `resolve_topology_intent` decides alone: the record is re-validated (sha drift ->
PLATFORM_DEFECT) against every golden compute module already in the repository (`existing_compute_entries`: any
label, `.tf` and `.tf.json`, nested local composites; RT F1). A removal, kind change, primary change or rename of
existing compute, or compute the topology cannot pin (bundle / Express labels), raises `TopologyGuardError`
(BROWNFIELD_CONFLICT) before any LLM call; nothing is pinned or merged silently. Records without a topology keep the
path above unchanged.

Every function here is pure (no I/O, no LLM).
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # lane 10 (FD-51): typed per-service topology (root shared/ is the source; vendored into the gateway)
    from shared.diagnostics import Diagnostic, ErrorClass
    from shared.service_topology import (
        KIND_FOR_MODULE_DIR,
        ExistingComputeEntry,
        ValidatedTopology,
        topology_from_record,
    )
except ImportError:  # pragma: no cover - package-relative fallback
    from ..shared.diagnostics import Diagnostic, ErrorClass  # type: ignore
    from ..shared.service_topology import (  # type: ignore
        KIND_FOR_MODULE_DIR,
        ExistingComputeEntry,
        ValidatedTopology,
        topology_from_record,
    )

ARCHETYPES: Tuple[str, ...] = ("cloudrun", "event-worker", "gke-autopilot", "gce-bastion", "foundation-only")

# Golden compute module directory -> archetype (data; exact directory names under infra/modules/).
MODULE_DIR_ARCHETYPE: Dict[str, str] = {
    "compute-cloudrun": "cloudrun",
    "compute-event-worker": "event-worker",
    "compute-gke-autopilot": "gke-autopilot",
    "compute-gce-bastion": "gce-bastion",
}

# Architect `bundle_id` literal (architect_agent/schemas.py ArchitecturePlanDAG.bundle_id) -> primary archetype.
# Data, from each bundle's definition in architect_agent/prompt.py §6: only private-gke-microservices has a non-Cloud-Run
# primary; the others name a Cloud Run API / consumer (serverless-analytics-lakehouse names no compute, so the
# architect's service list decides whether a Cloud Run service exists; it defaults to [product_id]).
BUNDLE_PRIMARY_ARCHETYPE: Dict[str, str] = {
    "secure-three-tier-web": "cloudrun",
    "event-driven-microservice": "cloudrun",
    "vertex-ai-rag-stack": "cloudrun",
    "private-gke-microservices": "gke-autopilot",
    "serverless-analytics-lakehouse": "cloudrun",
}

# The architect plan fields the developer reads: architect_agent/schemas.py `compute_intent_record` writes exactly
# these (request body `architect_compute_intent`, Firestore pipeline_executions/{trace}.architect_compute_intent).
ARCHITECT_INTENT_FIELDS: Tuple[str, ...] = ("target_compute_services", "bundle_id", "compute_archetype")
# A v2 record (lane 10) additionally carries `service_topology`; resolve_compute_intent then takes the topology path.

# Cloud Run service name grammar (RFC 1123 label, <= 63 chars, starts with a letter). A grammar check, not a guess.
_SERVICE_NAME = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_WORKLOAD_ROOT = "infra/workload/"
_MAIN_TF = "infra/workload/main.tf"


class InvalidComputeIntentError(ValueError):
    """The architect record carries a `compute_archetype` outside `ARCHETYPES` (version skew or a corrupted record).
    The developer stage fails instead of guessing an archetype."""


class TopologyGuardError(ValueError):
    """Lane 10: the recorded service topology fails re-validation against the repository (brownfield guard:
    BROWNFIELD_CONFLICT), or the record itself is inconsistent (PLATFORM_DEFECT). Raised before any LLM call;
    carries typed diagnostics. Never repaired by an LLM."""

    def __init__(self, message: str, diagnostics: List[Diagnostic]):
        super().__init__(message)
        self.diagnostics = list(diagnostics)


@dataclass(frozen=True)
class ComputeIntent:
    archetype: str
    service_names: Tuple[str, ...]
    source: str                                    # existing-repo | architect | platform-default
    archetype_source: str                          # which typed fact decided the archetype
    rejected_names: Tuple[str, ...] = ()           # architect names that fail the service-name grammar
    conflicts: Tuple[str, ...] = ()                # architect facts overridden by pinned existing compute
    existing_services: Tuple[str, ...] = ()        # pinned from the repository
    # lane 10 (FD-51): the validated per-service topology when the architect record carries one (v2 records).
    # Then the archetype, the service set, every service's kind and all service-to-service wiring come from it.
    topology: Optional[ValidatedTopology] = None
    topology_warnings: Tuple[str, ...] = ()

    @property
    def primary(self) -> Optional[str]:
        return self.service_names[0] if self.service_names and self.archetype != "foundation-only" else None

    @property
    def secondary_services(self) -> Tuple[str, ...]:
        return self.service_names[1:] if self.archetype != "foundation-only" else ()

    def kind_of(self, service: str) -> Optional[str]:
        """A service's own compute kind (topology path only; None for the legacy single-archetype path)."""
        return self.topology.kind(service) if self.topology is not None else None

    def as_record(self) -> Dict[str, Any]:
        rec = {"archetype": self.archetype, "service_names": list(self.service_names), "source": self.source,
               "archetype_source": self.archetype_source, "rejected_names": list(self.rejected_names),
               "conflicts": list(self.conflicts), "existing_services": list(self.existing_services)}
        if self.topology is not None:
            rec["topology_sha256"] = self.topology.sha256
            rec["service_kinds"] = {n: self.topology.kind(n) for n in self.topology.names}
            rec["http_entrypoint"] = self.topology.http_entrypoint
            rec["topology_warnings"] = list(self.topology_warnings)
        return rec


def normalize_service_name(name: Any) -> str:
    """Exact normalization of a typed service identifier (trim, lower case, `_` -> `-`); no inference."""
    return str(name).strip().lower().replace("_", "-") if name is not None else ""


def _golden_module_dir(source: Any, declaring_path: str) -> Optional[str]:
    """Basename of the golden module a literal local `source` resolves to (`infra/modules/<dir>`), else None."""
    if not isinstance(source, str) or "${" in source or not source.startswith(("./", "../")):
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(declaring_path), source))
    parent, base = posixpath.split(resolved)
    return base if parent == "infra/modules" else None


def _index_blocks():
    """The developer package's python-hcl2 block index (same import ladder as terraform_engine)."""
    try:
        from .assembly import index_blocks
    except ImportError:
        try:
            from assembly import index_blocks
        except ImportError:
            from developer_agent.assembly import index_blocks
    return index_blocks


def _literal(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and "${" not in value else None


def _root_tf_paths(files: Mapping[str, str]) -> List[str]:
    return sorted(p for p, v in files.items() if isinstance(v, str) and p.startswith(_WORKLOAD_ROOT)
                  and p.endswith(".tf") and "/" not in p[len(_WORKLOAD_ROOT):])


@dataclass
class ExistingCompute:
    primary_kind: Optional[str] = None             # archetype of main.tf module "compute" (None: no platform compute)
    primary_name: Optional[str] = None             # literal service_name of module "compute" (Cloud Run only)
    secondaries: List[str] = field(default_factory=list)
    unparsed: List[str] = field(default_factory=list)


def existing_compute_from_repo(existing_files: Optional[Mapping[str, str]], product_id: str) -> ExistingCompute:
    """The platform compute modules already in the workload repository (exact python-hcl2 parse, no substring).
    A platform main.tf without `module "compute"` (a foundation-only workload) pins nothing: adding compute later
    removes nothing and changes no kind."""
    out = ExistingCompute()
    if not existing_files:
        return out
    index_blocks = _index_blocks()
    clean_pid = normalize_service_name(product_id)
    for path in _root_tf_paths(existing_files):
        blocks = index_blocks(existing_files[path])
        if blocks is None:
            out.unparsed.append(path)
            continue
        for b in blocks:
            if b.kind != "module" or not b.labels:
                continue
            label = b.labels[0]
            body = b.body or {}
            kind = MODULE_DIR_ARCHETYPE.get(_golden_module_dir(body.get("source"), path) or "")
            if kind is None:
                continue
            if path == _MAIN_TF and label == "compute":
                out.primary_kind = kind
                name = _literal(body.get("service_name"))
                out.primary_name = normalize_service_name(name) if name else None
            elif kind == "cloudrun" and label.startswith("compute_"):
                name = _literal(body.get("service_name"))
                svc = normalize_service_name(name) if name else normalize_service_name(label[len("compute_"):])
                if svc and svc != clean_pid and svc not in out.secondaries:
                    out.secondaries.append(svc)
    return out


_MAX_NESTING = 3
_PRODUCT_ID_REF = "${var.product_id}"
SERVICES_TF = "infra/workload/services.tf"   # TI-1: the platform's secondary-compute render (topology path only)


def _module_blocks_of(path: str, text: str, index_blocks: Any) -> Optional[List[Tuple[str, Mapping[str, Any]]]]:
    """(label, body) of every top-level `module` block of one Terraform file: python-hcl2 for `.tf`, `json.loads`
    for `.tf.json` (same dict shape). None when the file does not parse."""
    if path.endswith(".tf.json"):
        try:
            doc = json.loads(text)
        except ValueError:
            return None
        mods = doc.get("module") if isinstance(doc, dict) else None
        out: List[Tuple[str, Mapping[str, Any]]] = []
        for entry in (mods if isinstance(mods, list) else [mods] if isinstance(mods, dict) else []):
            if isinstance(entry, dict):
                for label, body in entry.items():
                    for b in (body if isinstance(body, list) else [body]):
                        if isinstance(b, dict):
                            out.append((str(label), b))
        return out
    blocks = index_blocks(text)
    if blocks is None:
        return None
    return [(b.labels[0], b.body or {}) for b in blocks if b.kind == "module" and b.labels]


def _resolve_local_source(source: Any, declaring_path: str) -> Optional[str]:
    """Repo-relative directory a literal local module `source` resolves to (posix normpath), else None. Never
    escapes the repository (a leading '..' after normalization is refused)."""
    if not isinstance(source, str) or "${" in source or not source.startswith(("./", "../")):
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(declaring_path), source))
    return None if resolved.startswith("..") or resolved.startswith("/") else resolved


def existing_compute_entries(existing_files: Optional[Mapping[str, str]]
                             ) -> Tuple[List[ExistingComputeEntry], List[str]]:
    """Lane 10 / RT F1: every golden compute module call already in the workload repository, for ANY label, in
    every root file of `infra/workload/` (`*.tf` and `*.tf.json`), following local composite modules that are in the
    tree (e.g. `infra/bundles/<id>/`, vendored by terraform_engine.vendor_composite_bundle) up to 3 levels deep.
    A module is compute when its literal `source` resolves exactly to `infra/modules/<golden compute dir>` (set
    membership of the directory, parent equality; no substring). Returns (entries, unparsed workload files)."""
    files = dict(existing_files or {})
    if not files:
        return [], []
    index_blocks = _index_blocks()
    entries: List[ExistingComputeEntry] = []
    unparsed: List[str] = []

    def dir_files(directory: str) -> List[str]:
        prefix = directory.rstrip("/") + "/"
        return sorted(p for p, v in files.items() if isinstance(v, str) and p.startswith(prefix)
                      and "/" not in p[len(prefix):] and (p.endswith(".tf") or p.endswith(".tf.json")))

    def walk(directory: str, address_prefix: str, depth: int, visited: Tuple[str, ...]) -> None:
        for path in dir_files(directory):
            mods = _module_blocks_of(path, files[path], index_blocks)
            if mods is None:
                unparsed.append(path)
                continue
            for label, body in mods:
                address = f"{address_prefix}module.{label}"
                target = _resolve_local_source(body.get("source"), path)
                if target is None:
                    continue
                parent, base = posixpath.split(target)
                if parent == "infra/modules" and base in KIND_FOR_MODULE_DIR:
                    kind = KIND_FOR_MODULE_DIR[base]
                    sn = body.get("service_name")
                    name: Optional[str] = None
                    expr: Optional[str] = None
                    if sn is None and kind == "cloudrun":
                        expr = "<absent: module default>"
                    elif isinstance(sn, str) and sn == _PRODUCT_ID_REF:
                        name = "${product_id}"
                    elif isinstance(sn, str) and "${" not in sn:
                        name = sn
                    elif sn is not None:
                        expr = repr(sn)[:200]
                    entries.append(ExistingComputeEntry(address=address, label=label, kind=kind, file=path,
                                                        root=depth == 0, service_name=name, service_name_expr=expr,
                                                        # RT F5: exact key membership on the parsed body
                                                        indexed="count" in body or "for_each" in body))
                elif depth < _MAX_NESTING and target not in visited and dir_files(target):
                    walk(target, f"{address}.", depth + 1, visited + (target,))

    walk("infra/workload", "", 0, ("infra/workload",))
    return entries, sorted(set(unparsed))


def _bind_product_id(entries: List[ExistingComputeEntry], product_id: str) -> List[ExistingComputeEntry]:
    """`service_name = var.product_id` deploys the product id itself (exact substitution of the one reference)."""
    out = []
    for e in entries:
        if e.service_name == "${product_id}":
            e = ExistingComputeEntry(address=e.address, label=e.label, kind=e.kind, file=e.file, root=e.root,
                                     service_name=normalize_service_name(product_id),
                                     service_name_expr=e.service_name_expr, indexed=e.indexed)
        out.append(e)
    return out


def resolve_topology_intent(product_id: str, record: Mapping[str, Any],
                            existing_files: Optional[Mapping[str, str]],
                            target_compute_services: Optional[List[str]] = None) -> ComputeIntent:
    """Lane 10 topology path: re-validate the architect's recorded topology (sha drift check) against the
    repository's existing compute (brownfield guard of record), before any LLM call. Errors raise
    TopologyGuardError; nothing is pinned, merged or defaulted silently."""
    entries, unparsed = existing_compute_entries(existing_files)
    if unparsed:
        diags = [Diagnostic(tool="topology", code="TOPOLOGY.EXISTING_UNPARSEABLE", severity="error",
                            error_class=ErrorClass.BROWNFIELD_CONFLICT, file=p, source="precommit",
                            message=f"{p} does not parse, so the existing compute in it cannot be guarded")
                 for p in unparsed]
        raise TopologyGuardError(f"existing workload files do not parse: {unparsed}", diags)
    vt, diags = topology_from_record(record.get("service_topology"), product_id=product_id,
                                     file="infra/workload/topology.json", source="precommit",
                                     existing=_bind_product_id(entries, product_id))
    explicit = [normalize_service_name(s) for s in (target_compute_services or []) if normalize_service_name(s)]
    if vt is not None and explicit and list(explicit) != list(vt.names):
        diags = diags + [Diagnostic(tool="topology", code="TOPOLOGY.REQUEST_LIST_CONFLICT", severity="error",
                                    error_class=ErrorClass.PLATFORM_DEFECT, file="<request>", source="precommit",
                                    message=f"the request's target_compute_services {explicit} differ from the "
                                            f"recorded topology's services {list(vt.names)}")]
        vt = None
    if vt is None:
        errs = [d for d in diags if d.severity == "error"]
        raise TopologyGuardError("service topology refused: " + "; ".join(f"{d.code} {d.message}" for d in errs[:8]),
                                 diags)
    existing_names = tuple(sorted({e.address for e in entries}))
    return ComputeIntent(archetype=vt.archetype, service_names=vt.names, source="architect.service_topology",
                         archetype_source="architect.service_topology", existing_services=existing_names,
                         topology=vt, topology_warnings=tuple(f"{d.code}: {d.message}" for d in diags
                                                              if d.severity == "warning"))


def resolve_compute_intent(
    product_id: str,
    architect_intent: Optional[Mapping[str, Any]] = None,
    existing_files: Optional[Mapping[str, str]] = None,
    target_compute_services: Optional[List[str]] = None,
) -> ComputeIntent:
    """Resolve the workload's archetype and service set from typed facts only (module docstring)."""
    clean_pid = normalize_service_name(product_id)
    rec = dict(architect_intent or {})
    if rec.get("service_topology") is not None:
        # lane 10 (FD-51): a v2 record carries the typed per-service topology; it alone decides (re-validated here
        # against the repository). Records without it (written before lane 10) keep the path below unchanged.
        return resolve_topology_intent(product_id, rec, existing_files, target_compute_services)
    if isinstance((existing_files or {}).get(SERVICES_TF), str):
        # TI-1 code RT F2: a repository holding the platform's services.tf was generated with a service topology. The
        # legacy branch would append the secondaries to custom.tf beside that render (duplicate module declarations),
        # so the run is held for the operator before any LLM call, never merged silently.
        msg = (f"{SERVICES_TF} exists: this workload was generated with a service topology and cannot be "
               f"regenerated by a request without one")
        raise TopologyGuardError(msg, [Diagnostic(
            tool="topology", code="TOPOLOGY.SERVICES_TF_WITHOUT_TOPOLOGY", severity="error",
            error_class=ErrorClass.BROWNFIELD_CONFLICT, file=SERVICES_TF, source="precommit", message=msg,
            hint="Re-plan through the architect (service topology) or remove the platform's services.tf after "
                 "decommissioning its services (FD-4Q).")])
    explicit = [s for s in (target_compute_services or []) if normalize_service_name(s)]
    if explicit:  # an explicit typed list on the request (DeveloperExecuteRequest.target_compute_services) wins
        rec["target_compute_services"] = explicit
    have_architect = bool(rec) and any(k in rec for k in ARCHITECT_INTENT_FIELDS)

    # Services named by the architect (grammar-checked, order kept, duplicates dropped).
    names: List[str] = []
    rejected: List[str] = []
    for raw in rec.get("target_compute_services") or []:
        n = normalize_service_name(raw)
        if not _SERVICE_NAME.match(n):
            rejected.append(str(raw))
        elif n not in names:
            names.append(n)

    # Archetype from the architect's typed fields.
    ca = rec.get("compute_archetype")
    bundle = rec.get("bundle_id")
    if ca is not None and not (isinstance(ca, str) and ca in ARCHETYPES):
        raise InvalidComputeIntentError(
            f"architect compute_archetype {ca!r} is not one of {list(ARCHETYPES)} (product '{product_id}')")
    if ca is not None:
        archetype, arch_src = ca, "architect.compute_archetype"
    elif isinstance(bundle, str) and bundle in BUNDLE_PRIMARY_ARCHETYPE:
        archetype, arch_src = BUNDLE_PRIMARY_ARCHETYPE[bundle], f"architect.bundle_id:{bundle}"
    elif have_architect:
        archetype, arch_src = "cloudrun", "architect.target_compute_services"
    else:
        archetype, arch_src = "cloudrun", "platform-default"
    source = "architect" if have_architect else "platform-default"

    # Existing compute is pinned (never dropped, kind never changed by regeneration).
    existing = existing_compute_from_repo(existing_files, product_id)
    conflicts: List[str] = []
    pinned: List[str] = []
    if existing.primary_kind is not None:
        if have_architect and existing.primary_kind != archetype:
            conflicts.append(f"archetype:{arch_src}={archetype}->existing={existing.primary_kind}")
        archetype, arch_src = existing.primary_kind, "existing-repo:module.compute"
        source = "existing-repo"
        primary = existing.primary_name or clean_pid
        pinned.append(primary)
        if names and names[0] != primary:
            conflicts.append(f"primary:architect={names[0]}->existing={primary}")
        names = [primary] + [n for n in names if n != primary]
    for s in existing.secondaries:
        pinned.append(s)
        if s not in names:
            names.append(s)

    if archetype == "foundation-only":
        names = []
    elif not names:
        names = [clean_pid]  # the architect's documented single-service default
    return ComputeIntent(archetype=archetype, service_names=tuple(names), source=source, archetype_source=arch_src,
                         rejected_names=tuple(rejected), conflicts=tuple(conflicts), existing_services=tuple(pinned))

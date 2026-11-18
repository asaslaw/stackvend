"""V2m (FD-4DK, report only): a private database that no compute service of the workload can reach.

| id  | code                         | default mode | when |
| V2m | IAC.PRIVATE_DB_UNREACHABLE   | report_only  | the root module declares a database with only a private IP (Cloud SQL / AlloyDB) and at least one serverless compute service (Cloud Run, Cloud Run job, Cloud Functions, event-worker), but no compute service has a route into a VPC (Serverless VPC Access connector or Direct VPC egress) and no VPC-native compute (GKE, Compute Engine) exists |

What counts, by exact type / attribute path / golden module directory (never by name or substring):
- private database: `google_sql_database_instance` with `settings.ip_configuration.private_network` set and
  `ipv4_enabled = false`; `google_alloydb_instance` whose `network_config.enable_public_ip` is absent or `false`; a
  golden `database-cloudsql` module with `private_network_id` set and `enable_public_ip` absent or `false`; a golden
  `database-alloydb` module.
- route: a golden `compute-cloudrun` module with a non-empty `vpc_access_connector`; `google_cloud_run_v2_service`
  (`template.vpc_access`) / `google_cloud_run_v2_job` (`template.template.vpc_access`) with a connector or
  `network_interfaces`; a v1 `google_cloud_run_service` with the exact template annotation
  `run.googleapis.com/vpc-access-connector`; a Cloud Functions `vpc_connector`; any VPC-native compute (golden `compute-gke-autopilot` /
  `compute-gce-bastion` / `compute-gce-worker`, `google_container_cluster`, `google_compute_instance`, instance
  templates).

Every root-module `.tf` file is read (platform renders included: main.tf carries the platform's connector line), with
python-hcl2. JSON files (`*.tf.json`) and unparseable files contribute nothing, so they can only suppress a finding.
Report only: measured in `report.report_only`, never blocks and never reaches a repair prompt. Whether the route is on
the database's own network is not judged here (topology_wiring renders the connector only when it is).
"""
from __future__ import annotations

import posixpath
from typing import Any, Iterable, List, Optional, Tuple

try:
    from shared.diagnostics import Diagnostic, ErrorClass
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore

from ..assembly import Block, index_blocks
from ..topology_wiring import _nested
from .base import ValidationContext
from .step1 import _is_root_tf

CODE = "IAC.PRIVATE_DB_UNREACHABLE"

CLOUDRUN_DIR = "compute-cloudrun"
SERVERLESS_NO_ROUTE_DIRS = frozenset({"compute-event-worker"})          # the golden module has no VPC input
VPC_NATIVE_DIRS = frozenset({"compute-gke-autopilot", "compute-gce-bastion", "compute-gce-worker"})
VPC_NATIVE_TYPES = frozenset({"google_container_cluster", "google_compute_instance",
                              "google_compute_instance_template", "google_compute_region_instance_template"})
V1_CONNECTOR_ANNOTATION = "run.googleapis.com/vpc-access-connector"   # exact key of the v1 Cloud Run template

HINT = ("Nothing in this workload can reach {address}: it has only a private IP, and no compute service has a route "
        "into its VPC. Give the Cloud Run services a Serverless VPC Access connector on the database's network "
        "(google_vpc_access_connector, ip_cidr_range = var.connector_cidr), or let the architect's plan state which "
        "service reads the database so the platform wires it.")


def _module_dir(source: Any, declaring_path: str) -> Optional[str]:
    """The golden module directory a local `source` resolves to (`infra/modules/<dir>`), else None."""
    if not isinstance(source, str) or "${" in source or not source.startswith(("./", "../")):
        return None
    parent, base = posixpath.split(posixpath.normpath(posixpath.join(posixpath.dirname(declaring_path), source)))
    return base if parent == "infra/modules" else None


def _set(value: Any) -> bool:
    """An attribute that is present with a value other than null / the empty string."""
    return value is not None and value != ""


def _off(switch: Any) -> bool:
    """A public-IP switch that is absent or the literal `false` (an expression such as var.x may be true: no
    finding; FD-4DK RT F3)."""
    return switch is None or switch is False


def _root_blocks(ctx: ValidationContext) -> Iterable[Tuple[str, Block]]:
    for path in sorted(ctx.files):
        if _is_root_tf(path) and isinstance(ctx.files[path], str):
            for b in index_blocks(ctx.files[path]) or []:
                yield path, b


def _private_database(path: str, b: Block) -> Optional[str]:
    """The block's address when it is a database with only a private IP (module docstring), else None."""
    body = b.body or {}
    if b.kind == "resource" and len(b.labels) == 2:
        typ, name = b.labels
        if typ == "google_sql_database_instance":
            ipc = _nested(body, ("settings", "ip_configuration"))
            ipc = ipc[0] if isinstance(ipc, list) and len(ipc) == 1 else ipc
            if isinstance(ipc, dict) and _set(ipc.get("private_network")) and ipc.get("ipv4_enabled") is False:
                return f"{typ}.{name}"
        elif typ == "google_alloydb_instance":
            if _off(_nested(body, ("network_config", "enable_public_ip"))):
                return f"{typ}.{name}"
    elif b.kind == "module" and b.labels:
        d = _module_dir(body.get("source"), path)
        if d == "database-cloudsql" and _set(body.get("private_network_id")) and _off(body.get("enable_public_ip")):
            return f"module.{b.labels[0]}"
        if d == "database-alloydb":
            return f"module.{b.labels[0]}"
    return None


def _vpc_access_route(vpc_access: Any) -> bool:
    va = vpc_access[0] if isinstance(vpc_access, list) and len(vpc_access) == 1 else vpc_access
    return isinstance(va, dict) and (_set(va.get("connector")) or _set(va.get("network_interfaces")))


def _compute(path: str, b: Block) -> Tuple[bool, bool]:
    """(is compute, has a route into a VPC) of one block."""
    body = b.body or {}
    if b.kind == "module":
        d = _module_dir(body.get("source"), path)
        if d == CLOUDRUN_DIR:
            return True, _set(body.get("vpc_access_connector"))
        if d in SERVERLESS_NO_ROUTE_DIRS:
            return True, False
        if d in VPC_NATIVE_DIRS:
            return True, True
        return False, False
    if b.kind != "resource" or len(b.labels) != 2:
        return False, False
    typ = b.labels[0]
    if typ in VPC_NATIVE_TYPES:
        return True, True
    if typ == "google_cloud_run_v2_service":
        return True, _vpc_access_route(_nested(body, ("template", "vpc_access")))
    if typ == "google_cloud_run_service":   # v1 API: the connector is a template annotation (FD-4DK RT F6)
        annotations = _nested(body, ("template", "metadata", "annotations"))
        return True, isinstance(annotations, dict) and _set(annotations.get(V1_CONNECTOR_ANNOTATION))
    if typ == "google_cloud_run_v2_job":
        return True, _vpc_access_route(_nested(body, ("template", "template", "vpc_access")))
    if typ == "google_cloudfunctions2_function":
        return True, _set(_nested(body, ("service_config", "vpc_connector")))
    if typ == "google_cloudfunctions_function":
        return True, _set(body.get("vpc_connector"))
    return False, False


class PrivateDatabaseReachValidator:
    id, tool = "V2m", "platform"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        databases: List[Tuple[str, Block, str]] = []
        compute = route = False
        for path, b in _root_blocks(ctx):
            address = _private_database(path, b)
            if address is not None:
                databases.append((path, b, address))
            is_compute, has_route = _compute(path, b)
            compute = compute or is_compute
            route = route or has_route
        if not databases or not compute or route:
            return []
        return [Diagnostic(tool="platform", code=CODE, severity="warning", error_class=ErrorClass.CODE_DEFECT,
                           source="precommit", file=path, line=b.start, end_line=b.end, block_address=address,
                           iteration=ctx.iteration,
                           message=f"{address} has only a private IP, but no compute service of this workload has a "
                                   f"VPC connector or Direct VPC egress to reach it",
                           hint=HINT.format(address=address))
                for path, b, address in databases]


def register(stack: Any) -> None:
    stack.register(PrivateDatabaseReachValidator(), "report_only")

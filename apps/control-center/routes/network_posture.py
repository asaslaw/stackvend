"""
StackVend Control Center: Settings ▸ install status "Platform network" card (row CC-NETWORK-POSTURE; internal-ingress
plan §6.2 / §7.2 b). Read-only.

GET /api/settings/network-posture   (ADMIN) for every component in shared/release_manifest.COMPONENTS, from the Cloud
                                    Run Admin API v2 (typed fields only): the service's `ingress`, and the
                                    `vpcAccess` of its template (service: template.vpcAccess; job:
                                    template.template.vpcAccess), then a verdict:
  OK                       nothing to flag;
  INGRESS_PUBLIC           a host service other than the Control Center still accepts internet traffic
                           (ingress INGRESS_TRAFFIC_ALL; the target is internal-only, owner rule 11-07). Informational
                           while the install has no platform network yet (see below), a warning once it has;
  INGRESS_CALLER_OFF_VPC   a host service or job (every component except the QA sandbox job) is not on the host
                           network `stackvend-host` while at least one host service is already internal-only: its
                           requests to that service are refused (Cloud Run answers 404). Before any service is
                           internal-only an off-network caller is not refused, so it is not flagged then;
  QA_JOB_ON_HOST_VPC       the QA sandbox job (untrusted generated code) is on the host network, where it would be an
                           internal source for every internal-only host service;
  NOT_CHECKED              the Admin API read failed, the component is not deployed, or the answer has no known
                           `ingress` value (INGRESS_TRAFFIC_ALL or INTERNAL_INGRESS); never shown as OK.
A component can carry more than one finding (`findings`); `verdict` is the first of them, or OK.

"The install has the platform network" (`platform_network_present`) is read from the same typed fields: a component
is attached to `stackvend-host`, or a host service is internal-only. Until then (the network arrives with a platform
release) INGRESS_PUBLIC is expected and shown as information, not as a warning (review F5).

The Control Center reads Cloud Run with its own identity (the reads behind Settings ▸ Upgrades); it changes nothing.
The card is cached for CACHE_SECONDS (about 21 Admin API reads per refresh).
"""
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import APIRouter
from authz import ADMIN, require

from config import PROJECT_ID
from shared import release_manifest as rm

logger = logging.getLogger("control-center-network-posture")

router = APIRouter()

# = infra/platform host network `google_compute_network.host` (internal-ingress plan §3.1).
HOST_NETWORK = "stackvend-host"
QA_JOB = "qa-sandbox-test-runner"
# The Run Admin API v2 `ingress` enum: the public value and the values an outside caller cannot reach. Anything else
# is an answer we cannot read (NOT_CHECKED), never guessed as public or internal.
INGRESS_ALL = "INGRESS_TRAFFIC_ALL"
INTERNAL_INGRESS = frozenset({"INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
                              "INGRESS_TRAFFIC_NONE"})

OK = "OK"
INGRESS_PUBLIC = "INGRESS_PUBLIC"
INGRESS_CALLER_OFF_VPC = "INGRESS_CALLER_OFF_VPC"
QA_JOB_ON_HOST_VPC = "QA_JOB_ON_HOST_VPC"
NOT_CHECKED = "NOT_CHECKED"
VERDICTS = (OK, INGRESS_PUBLIC, INGRESS_CALLER_OFF_VPC, QA_JOB_ON_HOST_VPC, NOT_CHECKED)
SEVERITY_OK, SEVERITY_INFO, SEVERITY_WARNING = "ok", "info", "warning"
CARD_OK, CARD_INFO, CARD_ATTENTION = "OK", "INFO", "ATTENTION"
CACHE_SECONDS = 60

MESSAGES = {
    INGRESS_PUBLIC: "accepts internet traffic (ingress INGRESS_TRAFFIC_ALL); only the Control Center should",
    INGRESS_CALLER_OFF_VPC: (f"is not on the host network {HOST_NETWORK} while a host service is internal-only: "
                             "its requests to that service are refused"),
    QA_JOB_ON_HOST_VPC: (f"the QA sandbox job is on the host network {HOST_NETWORK}: untrusted generated code would "
                         "reach internal-only host services"),
}
NOT_YET_NOTE = (f"This install has no platform network ({HOST_NETWORK}) yet; it arrives with a platform release. "
                "Until then every service accepts internet traffic from callers with a valid Google identity token "
                "and the invoker right (documentation/known-limitations.md). Expected; nothing to do now.")

# Test seams (None = the real implementation; each returns (status, body) and never makes up a value).
cloud_run_get_json: Optional[Callable[[str], Tuple[int, Any]]] = None
region_provider: Optional[Callable[[], str]] = None
clock: Callable[[], float] = time.monotonic

_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _project() -> str:
    return (PROJECT_ID or os.getenv("PROJECT_ID", "") or os.getenv("GOOGLE_CLOUD_PROJECT", "")).strip()


def _region() -> str:
    if region_provider is not None:
        return region_provider()
    from routes import platform_release   # the Settings ▸ Upgrades region reader (REGION env, then metadata)
    return platform_release._region()


def _get_json() -> Callable[[str], Tuple[int, Any]]:
    if cloud_run_get_json is not None:
        return cloud_run_get_json
    from routes import platform_release   # the Settings ▸ Upgrades Cloud Run reader (the CC's own credentials)
    return platform_release._run_get_json()


def network_name(value: Any) -> Optional[str]:
    """The network's name from a Run API `networkInterfaces[].network` value: the bare name, or the relative resource
    name `projects/<project>/global/networks/<name>`. Anything else -> None (not a network name)."""
    if not isinstance(value, str) or not value:
        return None
    parts = value.split("/")
    if len(parts) == 1:
        return value
    if len(parts) == 5 and parts[0] == "projects" and parts[2:4] == ["global", "networks"] and parts[1] and parts[4]:
        return parts[4]
    return None


def _vpc_view(vpc: Any) -> Dict[str, Any]:
    vpc = vpc if isinstance(vpc, dict) else {}
    nics = vpc.get("networkInterfaces") if isinstance(vpc.get("networkInterfaces"), list) else []
    networks = [n.get("network") for n in nics if isinstance(n, dict) and isinstance(n.get("network"), str)]
    subnets = [n.get("subnetwork") for n in nics if isinstance(n, dict) and isinstance(n.get("subnetwork"), str)]
    return {
        "networks": networks,
        "subnetworks": subnets,
        "egress": vpc.get("egress") if isinstance(vpc.get("egress"), str) else None,
        "connector": vpc.get("connector") if isinstance(vpc.get("connector"), str) and vpc.get("connector") else None,
        "on_host_network": any(network_name(n) == HOST_NETWORK for n in networks),
    }


def read_component(get: Callable[[str], Tuple[int, Any]], project: str, region: str, name: str,
                   kind: str) -> Dict[str, Any]:
    """{"ingress", "vpc"} from the Run Admin API v2, or {"error", "detail"} (typed; never a guessed value)."""
    collection = "services" if kind == "service" else "jobs"
    url = f"https://run.googleapis.com/v2/projects/{project}/locations/{region}/{collection}/{name}"
    try:
        status, body = get(url)
    except Exception as e:  # noqa: BLE001
        return {"error": "READ_FAILED", "detail": f"{type(e).__name__}"}
    if status == 404:
        return {"error": "NOT_DEPLOYED", "detail": f"{kind} {name} does not exist"}
    if status != 200 or not isinstance(body, dict):
        return {"error": "READ_FAILED", "detail": f"HTTP {status}"}
    if kind == "service":
        ingress = body.get("ingress")
        if not isinstance(ingress, str) or not ingress:
            return {"error": "BAD_RESPONSE", "detail": f"service {name} has no typed ingress"}
        if ingress != INGRESS_ALL and ingress not in INTERNAL_INGRESS:
            return {"error": "BAD_RESPONSE", "detail": f"service {name} has an unknown ingress {ingress!r}"}
        tmpl = body.get("template") if isinstance(body.get("template"), dict) else {}
        return {"ingress": ingress, "vpc": _vpc_view(tmpl.get("vpcAccess"))}
    outer = body.get("template") if isinstance(body.get("template"), dict) else {}
    task = outer.get("template") if isinstance(outer.get("template"), dict) else None
    if task is None:
        return {"error": "BAD_RESPONSE", "detail": f"job {name} has no task template"}
    return {"ingress": None, "vpc": _vpc_view(task.get("vpcAccess"))}


def assess(reads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """The card from the per-component reads (pure; ordered as rm.COMPONENTS)."""
    readable = {n: r for n, r in reads.items() if "error" not in r}
    internal_active = any(
        r.get("ingress") in INTERNAL_INGRESS
        for n, r in readable.items() if rm.COMPONENT_KINDS.get(n) == "service" and n != rm.CONTROL_CENTER_SERVICE)
    network_present = internal_active or any((r.get("vpc") or {}).get("on_host_network") for r in readable.values())
    rows: List[Dict[str, Any]] = []
    for name, kind, _ in rm.COMPONENTS:
        r = reads.get(name) or {"error": "READ_FAILED", "detail": "not read"}
        row: Dict[str, Any] = {"component": name, "kind": kind, "ingress": r.get("ingress"),
                               "vpc": r.get("vpc"), "findings": [], "error": None}
        warn = False
        if "error" in r:
            row.update(findings=[NOT_CHECKED], error=f"{r['error']}: {r.get('detail', '')}")
            warn = True
        else:
            on_host = bool((r.get("vpc") or {}).get("on_host_network"))
            if name == QA_JOB:
                if on_host:
                    row["findings"].append(QA_JOB_ON_HOST_VPC)
                    warn = True
            else:
                if kind == "service" and name != rm.CONTROL_CENTER_SERVICE and r.get("ingress") == INGRESS_ALL:
                    row["findings"].append(INGRESS_PUBLIC)
                    warn = warn or network_present   # expected (information) until the install has the network
                if internal_active and not on_host:
                    row["findings"].append(INGRESS_CALLER_OFF_VPC)
                    warn = True
        row["verdict"] = row["findings"][0] if row["findings"] else OK
        row["severity"] = SEVERITY_WARNING if warn else (SEVERITY_INFO if row["findings"] else SEVERITY_OK)
        row["messages"] = [f"{name} {MESSAGES[f]}" for f in row["findings"] if f in MESSAGES]
        rows.append(row)
    counts = {v: sum(1 for row in rows if v in row["findings"] or (v == OK and not row["findings"]))
              for v in VERDICTS}
    severities = {row["severity"] for row in rows}
    verdict = (CARD_ATTENTION if SEVERITY_WARNING in severities
               else CARD_INFO if SEVERITY_INFO in severities else CARD_OK)
    return {"host_network": HOST_NETWORK, "internal_ingress_active": internal_active,
            "platform_network_present": network_present, "note": "" if network_present else NOT_YET_NOTE,
            "components": rows, "counts": counts, "verdict": verdict}


def _read_card() -> Dict[str, Any]:
    project, region = _project(), _region()
    if not project or not region:
        reads = {n: {"error": "READ_FAILED", "detail": "project or region unknown"} for n, _, _ in rm.COMPONENTS}
        return assess(reads)
    try:
        get = _get_json()
    except Exception as e:  # noqa: BLE001
        reads = {n: {"error": "READ_FAILED", "detail": f"no credentials: {type(e).__name__}"}
                 for n, _, _ in rm.COMPONENTS}
        return assess(reads)

    def one(item):
        name, kind, _ = item
        return name, read_component(get, project, region, name, kind)
    with ThreadPoolExecutor(max_workers=8) as pool:
        reads = dict(pool.map(one, rm.COMPONENTS))
    card = assess(reads)
    card.update(project=project, region=region)
    return card


@router.get("/api/settings/network-posture", dependencies=[require(ADMIN)])
def get_network_posture_api():
    now = clock()
    with _cache_lock:
        hit = _cache.get("card")
        if hit is not None and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    card = _read_card()
    with _cache_lock:
        _cache["card"] = (now, card)
    return card

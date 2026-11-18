"""AGENTS.md invariant checks on a scored tree (measurement only; nothing here edits code).

I3  hardcoded literals in generated workload IaC: a GCP region (static list, config/gcp_regions.txt), a CIDR
    (ipaddress.ip_network), or a forbidden project id (passed in by the parent; never hardcoded here). Literals in
    resource/module/provider arguments are violations; variable defaults are reported separately.
I4  IaC outside infra/workload/ (vendored infra/modules/ is expected) and any Dockerfile/.dockerignore.
I6  module -> module `service_uri` references must be acyclic (graphlib). HCL expressions arrive from python-hcl2
    as "${...}" strings; extracting `module.<name>.service_uri` traversals from them is expression parsing for a
    metric, not a product heuristic.
"""
from __future__ import annotations

import graphlib
import ipaddress
import json
import posixpath
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from . import hclparse
from .paths import CONFIG_DIR

WORKLOAD = "infra/workload/"
MODULES = "infra/modules/"
_MOD_REF = re.compile(r"\bmodule\.([A-Za-z_][A-Za-z0-9_-]*)\.service_uri\b")


def load_regions(path: Optional[Path] = None) -> Set[str]:
    p = path or (CONFIG_DIR / "gcp_regions.txt")
    return {ln.strip() for ln in p.read_text().splitlines() if ln.strip() and not ln.startswith("#")}


def _strings(v: Any) -> Iterable[str]:
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


def _is_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def literal_findings(value: str, regions: Set[str], forbidden_projects: Set[str]) -> List[str]:
    s = hclparse.unquote(value).strip()
    if "${" in s:
        return []  # an expression (var./local./module. reference), not a literal
    out = []
    if s in regions:
        out.append("region")
    if _is_cidr(s):
        out.append("cidr")
    if s and s in forbidden_projects:
        out.append("project")
    return out


def check(tree: Dict[str, str], *, regions: Set[str], forbidden_projects: Iterable[str] = ()) -> Dict[str, Any]:
    forbidden = {p for p in forbidden_projects if p}
    res: Dict[str, Any] = {}
    # I4 (no parser needed)
    res["I4_iac_outside_infra_workload"] = sorted(p for p in tree if p.endswith((".tf", ".tf.json"))
                                                  and not p.startswith((WORKLOAD, MODULES)))
    res["I4_dockerfiles"] = sorted(p for p in tree if posixpath.basename(p).lower().startswith("dockerfile")
                                   or posixpath.basename(p).lower() == ".dockerignore")
    try:
        parsed, bad = hclparse.parse_tree(tree, WORKLOAD)
    except hclparse.HclUnavailable as e:
        res["structure"] = f"unavailable: {e}"
        return res
    res["structure_unavailable_files"] = bad
    # I3
    viol, var_defaults = [], []
    for path, doc in parsed.items():
        for kind in ("resource", "data", "module", "provider", "locals"):
            for labels, body in hclparse.blocks(doc, kind):
                for s in _strings(body):
                    for f in literal_findings(s, regions, forbidden):
                        viol.append({"file": path, "block": f"{kind}.{'.'.join(labels)}", "kind": f,
                                     "value": hclparse.unquote(s)[:80]})
        for labels, body in hclparse.blocks(doc, "variable"):
            d = body.get("default")
            for s in _strings(d):
                for f in literal_findings(s, regions, forbidden):
                    var_defaults.append({"file": path, "variable": labels[0], "kind": f})
    res["I3_literals"] = viol
    res["I3_variable_default_literals"] = var_defaults
    # I6
    graph: Dict[str, Set[str]] = {}
    for path, doc in parsed.items():
        for labels, body in hclparse.blocks(doc, "module"):
            refs = set()
            for s in _strings(body):
                refs.update(_MOD_REF.findall(s))
            graph.setdefault(labels[0], set()).update(r for r in refs if r != labels[0])
            if labels[0] in refs:
                graph[labels[0]].add(labels[0])
    cycles = []
    g = {k: set(v) for k, v in graph.items()}
    for k, v in g.items():
        if k in v:
            cycles.append([k, k])
            v.discard(k)
    try:
        list(graphlib.TopologicalSorter(g).static_order())
    except graphlib.CycleError as e:
        cycles.append(list(e.args[1]))
    res["I6_service_uri_cycles"] = cycles
    res["I6_service_uri_edges"] = sum(len(v) for v in graph.values())
    # misc
    ser = json.dumps(parsed)
    res["backend_block_present"] = any(
        "backend" in body for doc in parsed.values() for _, body in hclparse.blocks(doc, "terraform"))
    res["var_project_id_used"] = "var.project_id" in ser
    types_ = sorted({labels[0] for doc in parsed.values() for labels, _ in hclparse.blocks(doc, "resource")})
    res["workload_resource_types"] = types_
    res["workload_module_count"] = sum(1 for doc in parsed.values() for _ in hclparse.blocks(doc, "module"))
    res["violations"] = len(viol) + len(cycles) + len(res["I4_iac_outside_infra_workload"]) + len(res["I4_dockerfiles"])
    return res

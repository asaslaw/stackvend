#!/usr/bin/env python3
"""Build shared/iac_intent/module_catalog.json from the golden modules (typed IaC intent TI-2, plan §2.3, RT F4/F8).

Offline, python-hcl2 7.3.1 (NOT shared/module_inspector.py, which is regex). For every AI-instantiable module it reads
infra/modules/<m>/*.tf and emits:
  variables {name: {hcl_type, default, has_default, sensitive, description, class (+ fact / policy / refs),
                    count_driver}}, outputs {name: {description, sensitive}}, declares_types, count_drivers.
Every variable must have a class in shared.iac_intent.MODULE_ARG_CLASS, or the build fails.

Static count rule (RT F4; `validate` cannot see "Invalid count argument", only `plan` can): a `count` / `for_each`
meta-argument of a resource / data / module block in a catalog module (dynamic blocks excluded: an unknown for_each
there is legal) may reference, directly or through locals, only
  - FACT variables whose platform value is known at plan time (shared.iac_intent.PLAN_KNOWN_FACTS),
  - SECRET variables with render policy "omit" (the platform never sets them: the module default is a literal),
  - AI variables, which the gate then accepts only as literals (count_driver -> IAC.LITERAL_REQUIRED).
A REF_ONLY variable, a SECRET variable the platform would render, or a FACT that may be unknown fails the build.

Usage: python3 scripts/build_iac_catalog.py [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Set, Tuple

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from shared.iac_intent import (MODULE_ARG_CLASS, MODULE_ARG_CLASS_BY_MODULE, PLAN_KNOWN_FACTS,  # noqa: E402
                               parse_type_constraint)
from shared.host_platform_modules import HOST_PLATFORM_ONLY_MODULE_REASONS  # noqa: E402

MODULES_DIR = REPO / "infra" / "modules"
OUT = REPO / "shared" / "iac_intent" / "module_catalog.json"
MANIFEST = REPO / "shared" / "iac_intent" / "MANIFEST"
# RT TI-2 F5: the gateway image is built from its committed shared/ copy (no build step runs deploy/vendor_shared.py
# yet), so the artifacts are committed there too, byte-identical (tests/test_typed_iac_ti2_artifacts.py).
REPLICA_DIRS = (REPO / "apps" / "orchestrator-gateway" / "shared" / "iac_intent",)
CATALOG_SCHEMA = "iac_intent_module_catalog/v1"
DESC_MAX = 160

AI_INSTANTIABLE = (
    "ai-vertex-endpoint", "analytics-bigquery", "cache-redis", "database-alloydb", "database-bigtable",
    "database-cloudsql", "database-spanner", "dns-record", "event-trigger", "messaging-pubsub",
    "observability-alerts", "orchestration-composer", "scheduling-cron", "security-kms", "security-secret",
    "storage-bucket", "tasks-queue", "workflows-dag",
)
# The host-platform-only module (`workflows`) and its reason come from the one shared source
# (shared/host_platform_modules.py, FD-4CB-b); the critic and the developer stage read the same file.
PLATFORM_ONLY = {
    "compute-cloudrun": "topology (compute)", "compute-event-worker": "topology (compute)",
    "compute-gce-bastion": "topology (compute)", "compute-gce-worker": "topology (compute)",
    "compute-gke-autopilot": "topology (compute)", "workload-foundation": "platform foundation",
    "workload_auth": "platform foundation", "networking-vpc": "lane 11 (network)",
    "networking-vpc-connector": "lane 11 (network)",   # FD-4BH: rendered by the platform (shared/iac_intent.py)
    **HOST_PLATFORM_ONLY_MODULE_REASONS,
}


def _desc(text: Any) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= DESC_MAX else text[: DESC_MAX - 1] + "…"


def _unwrap(expr: Any) -> str:
    s = str(expr)
    return s[2:-1] if s.startswith("${") and s.endswith("}") else s


def _type_text(s: str) -> str:
    """PUSH-SUB-RENDER (the first object-typed catalog variable): python-hcl2 7.3.1 writes `object({k = T, ...})` as
    `object({"k": "T", ...})`, a JSON object inside object(...); give it back in HCL form (JSON-decoded, exact) so
    shared.iac_intent.parse_type_constraint reads it. Any other text is returned unchanged."""
    if not (s.startswith("object({") and s.endswith("})")):
        return s
    try:
        fields = json.loads(s[len("object("):-1])
    except ValueError:
        return s
    if not (isinstance(fields, dict) and all(isinstance(v, str) for v in fields.values())):
        return s
    return "object({" + ", ".join(f"{k} = {_type_text(v)}" for k, v in fields.items()) + "})"


# ------------------------------------------------------------------------------------------------ lark walking
def _children(node: Any) -> List[Any]:
    return list(getattr(node, "children", []) or [])


def _ident(node: Any) -> str:
    """Text of an `identifier` / `string` node (lark)."""
    if getattr(node, "data", None) == "identifier":
        return str(_children(node)[0])
    if getattr(node, "data", None) == "string":
        return "".join(str(c.children[0]) if hasattr(c, "children") else str(c) for c in _children(node))
    return str(node)


def refs(node: Any) -> Set[Tuple[str, str]]:
    """Every `var.X` / `local.X` traversal in an expression subtree (exact parse-tree walk)."""
    out: Set[Tuple[str, str]] = set()

    def walk(n: Any) -> None:
        if getattr(n, "data", None) == "get_attr_expr_term":
            head, attr = _children(n)[0], _children(n)[1]
            if getattr(head, "data", None) == "expr_term":
                hc = _children(head)
                if len(hc) == 1 and getattr(hc[0], "data", None) == "identifier" and _ident(hc[0]) in ("var", "local"):
                    out.add((_ident(hc[0]), _ident(_children(attr)[0])))
        for c in _children(n):
            walk(c)
    walk(node)
    return out


def _blocks(tree: Any) -> Iterable[Tuple[str, List[str], Any]]:
    body = _children(tree)[0]
    for b in _children(body):
        if getattr(b, "data", None) != "block":
            continue
        kids = _children(b)
        kind = _ident(kids[0])
        labels = [_ident(k) for k in kids[1:] if getattr(k, "data", None) in ("identifier", "string")]
        inner = next(k for k in kids if getattr(k, "data", None) == "body")
        yield kind, labels, inner


def _attributes(body: Any) -> Iterable[Tuple[str, Any]]:
    for a in _children(body):
        if getattr(a, "data", None) == "attribute":
            kids = _children(a)
            yield _ident(kids[0]), kids[-1]


def module_facts(mdir: Path) -> Dict[str, Any]:
    import hcl2  # python-hcl2==7.3.1
    variables: Dict[str, Any] = {}
    outputs: Dict[str, Any] = {}
    declares: Set[str] = set()
    locals_refs: Dict[str, Set[Tuple[str, str]]] = {}
    meta: List[Tuple[str, str, Set[Tuple[str, str]]]] = []   # (address, meta-arg, refs)
    for tf in sorted(mdir.glob("*.tf")):
        text = tf.read_text()
        doc = hcl2.loads(text)
        for v in doc.get("variable") or []:
            for name, body in v.items():
                variables[name] = {
                    "hcl_type": _type_text(_unwrap(body.get("type", "any"))),
                    "has_default": "default" in body,
                    "default": body.get("default"),
                    "sensitive": bool(body.get("sensitive", False)),
                    "description": _desc(body.get("description")),
                }
        for o in doc.get("output") or []:
            for name, body in o.items():
                outputs[name] = {"description": _desc(body.get("description")),
                                 "sensitive": bool(body.get("sensitive", False))}
        for r in doc.get("resource") or []:
            declares.update(r.keys())
        tree = hcl2.parses(text)
        for kind, labels, body in _blocks(tree):
            if kind == "locals":
                for name, expr in _attributes(body):
                    locals_refs[name] = refs(expr)
            elif kind in ("resource", "data", "module"):
                addr = ".".join(([kind] if kind != "resource" else []) + labels)
                for name, expr in _attributes(body):
                    if name in ("count", "for_each"):
                        meta.append((addr, name, refs(expr)))

    def close(rs: Set[Tuple[str, str]], seen: Set[str]) -> Set[str]:
        out: Set[str] = set()
        for kind, name in rs:
            if kind == "var":
                out.add(name)
            elif name not in seen:
                out |= close(locals_refs.get(name, set()), seen | {name})
        return out

    drivers: Dict[str, List[str]] = {}
    for addr, arg, rs in meta:
        for var in sorted(close(rs, set())):
            drivers.setdefault(var, []).append(f"{addr}.{arg}")
    return {"variables": variables, "outputs": outputs, "declares_types": sorted(declares),
            "count_drivers": {k: sorted(v) for k, v in sorted(drivers.items())}}


def classify(module_id: str, variables: Mapping[str, Any], drivers: Mapping[str, List[str]]) -> List[str]:
    """Attach the class to every variable; return the problems (unclassified names, static count-rule breaks)."""
    problems: List[str] = []
    for name, v in sorted(variables.items()):
        cls = MODULE_ARG_CLASS_BY_MODULE.get((module_id, name)) or MODULE_ARG_CLASS.get(name)   # TI-5c override first
        if cls is None:
            problems.append(f"{module_id}.{name}: no class in shared.iac_intent.MODULE_ARG_CLASS")
            continue
        v.update({k: (list(x) if isinstance(x, tuple) else x) for k, x in cls.items()})
        v["count_driver"] = name in drivers
        try:
            parse_type_constraint(v["hcl_type"])
        except ValueError as exc:
            problems.append(f"{module_id}.{name}: {exc}")
        if name in drivers:
            where = ", ".join(drivers[name])
            c = cls["class"]
            if c == "FACT" and cls["fact"] not in PLAN_KNOWN_FACTS:
                problems.append(f"{module_id}: {where} references FACT {name} (fact {cls['fact']}), "
                                "which may be unknown at plan time")
            elif c == "SECRET" and cls.get("policy") != "omit":
                problems.append(f"{module_id}: {where} references SECRET {name}, which the platform renders")
            elif c == "REF_ONLY":
                problems.append(f"{module_id}: {where} references REF_ONLY {name} (a reference may be unknown)")
    for name in sorted(drivers):
        if name not in variables:
            problems.append(f"{module_id}: count/for_each references undeclared var.{name}")
    return problems


def build(modules_dir: Path = MODULES_DIR) -> Tuple[Dict[str, Any], List[str]]:
    on_disk = sorted(p.name for p in modules_dir.iterdir() if p.is_dir())
    problems: List[str] = []
    extra = sorted(set(on_disk) - set(AI_INSTANTIABLE) - set(PLATFORM_ONLY))
    gone = sorted((set(AI_INSTANTIABLE) | set(PLATFORM_ONLY)) - set(on_disk))
    if extra or gone:
        problems.append(f"module set drift: unlisted {extra}, missing {gone}")
    host_only = sorted(set(AI_INSTANTIABLE) & set(HOST_PLATFORM_ONLY_MODULE_REASONS))
    if host_only:
        problems.append(f"host-platform-only modules listed as AI-instantiable: {host_only}")
    modules: Dict[str, Any] = {}
    for m in AI_INSTANTIABLE:
        mdir = modules_dir / m
        if not mdir.is_dir():
            continue
        facts = module_facts(mdir)
        problems += classify(m, facts["variables"], facts["count_drivers"])
        modules[m] = {"source": f"../modules/{m}", **facts}
    catalog = {"schema": CATALOG_SCHEMA, "built_by": "scripts/build_iac_catalog.py (python-hcl2)",
               "ai_instantiable": list(AI_INSTANTIABLE),
               "platform_only": dict(sorted(PLATFORM_ONLY.items())), "modules": modules}
    return catalog, problems


def modules_tree_sha256(modules_dir: Path = MODULES_DIR) -> str:
    h = hashlib.sha256()
    for m in AI_INSTANTIABLE:
        for tf in sorted((modules_dir / m).glob("*.tf")):
            h.update(f"{m}/{tf.name}\0".encode())
            h.update(tf.read_bytes())
            h.update(b"\0")
    return h.hexdigest()


def render(catalog: Mapping[str, Any]) -> str:
    return json.dumps(catalog, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true", help="exit 1 on drift (never writes)")
    a = ap.parse_args(argv)
    catalog, problems = build()
    if problems:
        print("catalog build FAILED:\n  " + "\n  ".join(problems))
        return 2
    text = render(catalog)
    entry = {"sha256": hashlib.sha256(text.encode()).hexdigest(), "modules_tree_sha256": modules_tree_sha256(),
             "built_by": "scripts/build_iac_catalog.py"}
    if a.check:
        # The MANIFEST entry is checked too: a comment-only module edit leaves the catalog text unchanged but moves
        # modules_tree_sha256 (visible-rename-3 found --check passing on a stale tree hash).
        same = (OUT.exists() and OUT.read_text() == text and MANIFEST.exists()
                and json.loads(MANIFEST.read_text()).get("module_catalog") == entry
                and all((d / src.name).exists() and (d / src.name).read_bytes() == src.read_bytes()
                        for d in REPLICA_DIRS for src in (OUT, MANIFEST)))
        print("module catalog:", "up to date" if same else "DRIFT")
        return 0 if same else 1
    OUT.write_text(text)
    man = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    man["module_catalog"] = entry
    MANIFEST.write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")
    for d in REPLICA_DIRS:
        d.mkdir(parents=True, exist_ok=True)
        for src in (OUT, MANIFEST):
            (d / src.name).write_bytes(src.read_bytes())
    print(f"wrote {OUT.relative_to(REPO)} ({len(catalog['modules'])} modules) + replicas")
    return 0


if __name__ == "__main__":
    sys.exit(main())

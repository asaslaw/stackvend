#!/usr/bin/env python3
"""Build shared/iac_intent/provider_schema_slice.json + MANIFEST offline (typed IaC intent TI-2, plan §2.5, RT F8).

Operator tool. No network: a throw-away root pins the production provider set (eval/config/provider_sets.json
"production"), `tofu init -backend=false` runs under a CLI config whose provider_installation holds ONLY a
filesystem_mirror (the validate_service.py mechanism; no `direct {}`), with a scrubbed environment (allow-list),
then `tofu providers schema -json`. Only the allow-listed types (shared/iac_intent/allowed_types.json `types`) are
kept: attributes {type, required, optional, computed, sensitive}, nested blocks {nesting_mode, min_items,
max_items, block}, descriptions cut to 160 characters.

MANIFEST records the provider versions and the tofu version (the parity keys, RT F8: never the mirror sha, which
differs per os_arch), plus the sha256 of the full schema dump and of the slice (drift detection only).

Usage:
  python3 scripts/build_provider_schema_slice.py --tofu <tofu-1.9.0> --mirror <.tofu-mirror-prod> [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "shared" / "iac_intent"
SLICE = DATA / "provider_schema_slice.json"
MANIFEST = DATA / "MANIFEST"
REPLICA_DIRS = (REPO / "apps" / "orchestrator-gateway" / "shared" / "iac_intent",)   # RT TI-2 F5 (committed copy)
PROVIDER_SETS = REPO / "eval" / "config" / "provider_sets.json"
REGISTRIES = ("registry.opentofu.org", "registry.terraform.io")
DESC_MAX = 160
SLICE_SCHEMA = "iac_intent_provider_schema_slice/v1"


def production_set() -> Dict[str, Any]:
    return json.loads(PROVIDER_SETS.read_text())["sets"]["production"]


def _desc(text: Any) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= DESC_MAX else text[: DESC_MAX - 1] + "…"


def _block(block: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"attributes": {}, "block_types": {}}
    for name, a in sorted((block.get("attributes") or {}).items()):
        out["attributes"][name] = {
            "type": a.get("type", "dynamic") if "type" in a else ["nested_type", a.get("nested_type")],
            "required": bool(a.get("required")), "optional": bool(a.get("optional")),
            "computed": bool(a.get("computed")), "sensitive": bool(a.get("sensitive")),
            # write-only (ephemeral-input) attribute: tofu 1.9.0's schema JSON does not report the flag, so every
            # entry is False at the production engine; the exact refused_attributes table covers the twins (TI-2c)
            "write_only": bool(a.get("write_only")),
            "description": _desc(a.get("description")),
        }
    for name, b in sorted((block.get("block_types") or {}).items()):
        out["block_types"][name] = {
            "nesting_mode": b.get("nesting_mode"), "min_items": int(b.get("min_items") or 0),
            "max_items": int(b.get("max_items") or 0), "block": _block(b.get("block") or {}),
        }
    return out


def slice_schema(dump: Dict[str, Any], types: Dict[str, Any]) -> Dict[str, Any]:
    by_type: Dict[str, Any] = {}
    for paddr, pschema in sorted((dump.get("provider_schemas") or {}).items()):
        for rtype, rs in sorted((pschema.get("resource_schemas") or {}).items()):
            if rtype in types and paddr.endswith("/hashicorp/" + types[rtype]["provider"]):
                by_type[rtype] = {"provider": paddr.split("/", 1)[1], "version": rs.get("version", 0),
                                  "block": _block(rs.get("block") or {})}
    missing = sorted(set(types) - set(by_type))
    if missing:
        raise SystemExit(f"allow-listed types absent from the provider schema dump: {missing}")
    return by_type


def build(tofu: str, mirror: str) -> Dict[str, Any]:
    prod = production_set()
    allowed = json.loads((DATA / "allowed_types.json").read_text())["types"]
    with tempfile.TemporaryDirectory(prefix="iac-slice-") as tmp:
        root = Path(tmp) / "root"
        root.mkdir()
        req = "\n".join(f'    {p.split("/")[1]} = {{\n      source  = "{p}"\n      version = "{v}"\n    }}'
                         for p, v in sorted(prod["providers"].items()))
        (root / "main.tf").write_text("terraform {\n  required_providers {\n" + req + "\n  }\n}\n")
        include = [f"{reg}/{p}" for reg in REGISTRIES for p in sorted(prod["providers"])]
        rc = Path(tmp) / "cli.tfrc"
        rc.write_text("provider_installation {\n  filesystem_mirror {\n    path    = " + json.dumps(str(Path(mirror).resolve()))
                      + "\n    include = " + json.dumps(include) + "\n  }\n}\n")   # no direct {}: no egress
        home = Path(tmp) / "home"
        home.mkdir()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TF_CLI_CONFIG_FILE": str(rc), "TF_IN_AUTOMATION": "1",
               "CHECKPOINT_DISABLE": "1", "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
               "NO_PROXY": ""}
        ver = subprocess.run([tofu, "version", "-json"], cwd=root, env=env, capture_output=True, text=True, check=True)
        tofu_version = json.loads(ver.stdout)["terraform_version"]
        if tofu_version != prod["engine_version"]:
            raise SystemExit(f"tofu {tofu_version} != production engine {prod['engine_version']}")
        init = subprocess.run([tofu, "init", "-backend=false", "-input=false", "-no-color"], cwd=root, env=env,
                              capture_output=True, text=True)
        if init.returncode != 0:
            raise SystemExit(f"tofu init failed (offline mirror only):\n{init.stdout[-2000:]}\n{init.stderr[-2000:]}")
        dump_proc = subprocess.run([tofu, "providers", "schema", "-json"], cwd=root, env=env, capture_output=True,
                                   check=True)
        dump_bytes = dump_proc.stdout
        lock = (root / ".terraform.lock.hcl").read_text()
    dump = json.loads(dump_bytes)
    for p, v in prod["providers"].items():
        if f'"{REGISTRIES[0]}/{p}"' not in lock or f'version     = "{v}"' not in lock:
            raise SystemExit(f"lock file does not pin {p} {v}")
    sliced = {"schema": SLICE_SCHEMA, "providers": dict(sorted(prod["providers"].items())),
              "engine": {"name": prod["engine"], "version": tofu_version},
              "resource_schemas": slice_schema(dump, allowed)}
    slice_text = json.dumps(sliced, indent=1, sort_keys=True) + "\n"
    manifest = {"schema": "iac_intent_manifest/v1", "engine": {"name": prod["engine"], "version": tofu_version},
                "providers": dict(sorted(prod["providers"].items())),
                "full_schema_dump_sha256": hashlib.sha256(dump_bytes).hexdigest(),
                "provider_schema_slice_sha256": hashlib.sha256(slice_text.encode()).hexdigest(),
                "slice_types": sorted(sliced["resource_schemas"]),
                "built_by": "scripts/build_provider_schema_slice.py (offline, filesystem_mirror only)"}
    return {"slice": slice_text, "manifest": manifest}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--tofu", required=True)
    ap.add_argument("--mirror", required=True)
    ap.add_argument("--check", action="store_true", help="exit 1 when the committed slice differs (never writes)")
    a = ap.parse_args(argv)
    out = build(a.tofu, a.mirror)
    if a.check:
        same = SLICE.exists() and SLICE.read_text() == out["slice"] and all(   # RT TI-2b R6: replicas too
            (d / SLICE.name).exists() and (d / SLICE.name).read_bytes() == SLICE.read_bytes() for d in REPLICA_DIRS)
        print("provider schema slice:", "up to date" if same else "DRIFT")
        return 0 if same else 1
    SLICE.write_text(out["slice"])
    man = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    man.update({"provider_schema": out["manifest"]})
    MANIFEST.write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")
    for d in REPLICA_DIRS:
        d.mkdir(parents=True, exist_ok=True)
        for src in (SLICE, MANIFEST):
            (d / src.name).write_bytes(src.read_bytes())
    print(f"wrote {SLICE.relative_to(REPO)} ({len(out['slice'])} bytes, {len(out['manifest']['slice_types'])} types)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Exact resource-type / golden-module-source -> Google Cloud API table (Wave 2 Step 2 S2-C, register HS-63/HS-30).

One function for both sides of API enablement:
  * the gateway (developer_agent.terraform_engine.infer_additional_apis_from_custom_tf -> terraform.tfvars
    additional_apis -> the workload foundation's google_project_service.apis), and
  * the terraform server's REST services:batchEnable before apply (mcp-servers/terraform/service.py
    extract_apis_from_hcl).

Rules (no prefix, no substring, no text search):
  * the base trio (serviceusage, iam, cloudresourcemanager) is always required;
  * every resource / data block -> the row of its EXACT type (python-hcl2 for .tf, json for .tf.json);
  * every module call whose literal LOCAL source ("./" or "../") ends in a golden-module directory -> that
    directory's row (last path component, after normalisation; the `_is_cloud_run_module_source` rule generalised);
  * every YAML document (yaml.safe_load_all) that is a mapping whose `apiVersion` is exactly one of the table's
    Kubernetes apiVersions or whose `kind` is exactly one of its kinds -> the Kubernetes row (container + compute).
A type, module directory or remote module source with no row is reported (`unknown`, IAC.API_UNKNOWN_FOR_TYPE), never
guessed; a file the parsers reject is reported (`unparseable_files`, IAC.API_SCAN_UNPARSEABLE). The table is data
(api_requirements.json next to this file), drift-tested against the golden modules, the foundation, the recorded eval
drafts and lane 15's allow-list (tests/test_step2c_api_requirements.py).

This file and api_requirements.json are replicated: root shared/ is the source; apps/orchestrator-gateway/shared/ and
mcp-servers/terraform/shared/ carry byte-identical copies (deploy/vendor_shared.py sync --check; parity test).
"""
from __future__ import annotations

import json
import os
import posixpath
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

__all__ = ["RequiredApis", "TABLE_PATH", "additional_apis", "load_table", "module_dir", "required_apis"]

TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_requirements.json")
_TABLE_CACHE: Dict[str, Dict[str, Any]] = {}


@dataclass(frozen=True)
class RequiredApis:
    apis: Tuple[str, ...]                          # sorted, unique service ids
    sources: Mapping[str, Tuple[str, ...]]         # api -> sorted reasons ("base", "resource:<type>", ...)
    unknown: Tuple[Tuple[str, str], ...]           # (file, "resource:<type>" | "data:<type>" | "module:<source>")
    unparseable_files: Tuple[str, ...]             # files python-hcl2 / json / PyYAML rejected

    @property
    def unknown_types(self) -> Tuple[str, ...]:
        return tuple(sorted({k for _f, k in self.unknown}))


def load_table(path: str = TABLE_PATH) -> Dict[str, Any]:
    """The table (cached per path). Raises on a missing or malformed file: API enablement never runs on a guess."""
    if path not in _TABLE_CACHE:
        with open(path, encoding="utf-8") as fh:
            table = json.load(fh)
        for key in ("base_apis", "foundation_base_apis", "resource_types", "data_types", "modules", "kubernetes"):
            if key not in table:
                raise ValueError(f"{path}: missing {key!r}")
        _TABLE_CACHE[path] = table
    return _TABLE_CACHE[path]


def module_dir(source: Any) -> Optional[str]:
    """Last path component of a literal LOCAL module source ("./x", "../modules/x", "../modules/x/"); None for a
    remote/registry source, an expression, or anything that is not a string."""
    if not isinstance(source, str) or "${" in source or not source.startswith(("./", "../")):
        return None
    norm = posixpath.normpath(source)
    name = posixpath.basename(norm)
    return name if name not in ("", ".", "..") else None


def _hcl_blocks(text: str) -> Iterable[Tuple[str, str, Any]]:
    """(kind, type-or-name, body) of the top-level resource/data/module blocks of one .tf file (python-hcl2)."""
    import hcl2  # python-hcl2==7.3.1 (both services' requirements.txt)
    doc = hcl2.loads(text)
    for kind in ("resource", "data"):
        for entry in doc.get(kind) or []:
            if isinstance(entry, dict):
                for typ, named in entry.items():
                    if isinstance(named, dict):
                        for body in named.values():
                            yield kind, typ, body
    for entry in doc.get("module") or []:
        if isinstance(entry, dict):
            for name, body in entry.items():
                yield "module", name, body


def _json_blocks(text: str) -> Iterable[Tuple[str, str, Any]]:
    doc = json.loads(text)
    if not isinstance(doc, dict):
        return
    for kind in ("resource", "data"):
        section = doc.get(kind) or {}
        for typ, named in (section.items() if isinstance(section, dict) else []):
            for body in (named.values() if isinstance(named, dict) else []):
                yield kind, typ, body
    mods = doc.get("module") or {}
    for name, body in (mods.items() if isinstance(mods, dict) else []):
        yield "module", name, body


def required_apis(tf_files: Mapping[str, str], yaml_files: Optional[Mapping[str, str]] = None, *,
                  table: Optional[Dict[str, Any]] = None) -> RequiredApis:
    """APIs the given Terraform (.tf / .tf.json) and Kubernetes YAML files need, by the exact table."""
    t = table if table is not None else load_table()
    need: Dict[str, Set[str]] = {}
    unknown: Set[Tuple[str, str]] = set()
    bad: Set[str] = set()

    def add(apis: Iterable[str], why: str) -> None:
        for api in apis:
            need.setdefault(api, set()).add(why)

    add(t["base_apis"], "base")
    for path in sorted(tf_files):
        text = tf_files[path]
        if not isinstance(text, str):
            continue
        try:
            if path.endswith(".tf.json"):
                blocks = list(_json_blocks(text))
            elif path.endswith(".tf"):
                blocks = list(_hcl_blocks(text)) if text.strip() else []
            else:
                continue
        except ImportError:
            raise
        except Exception:  # noqa: BLE001 - the parser's rejection is the finding (IAC.API_SCAN_UNPARSEABLE)
            bad.add(path)
            continue
        for kind, name, body in blocks:
            if kind == "resource":
                row = t["resource_types"].get(name)
                key = f"resource:{name}"
            elif kind == "data":
                row = t["data_types"].get(name)
                key = f"data:{name}"
            else:
                src = body.get("source") if isinstance(body, dict) else None
                d = module_dir(src)
                row = t["modules"].get(d) if d else None
                key = f"module:{d}" if d else f"module:{src}"
            if row is None:
                unknown.add((path, key))
            else:
                add(row, key)
    k8s = t["kubernetes"]
    api_versions, kinds = set(k8s["api_versions"]), set(k8s["kinds"])
    for path in sorted(yaml_files or {}):
        text = (yaml_files or {})[path]
        if not isinstance(text, str):
            continue
        try:
            import yaml  # PyYAML (both services' requirements.txt)
            docs = list(yaml.safe_load_all(text))
        except ImportError:
            raise
        except Exception:  # noqa: BLE001
            bad.add(path)
            continue
        for doc in docs:
            if isinstance(doc, dict) and (doc.get("apiVersion") in api_versions or doc.get("kind") in kinds):
                add(k8s["apis"], f"kubernetes:{path}")
                break
    return RequiredApis(apis=tuple(sorted(need)), sources={a: tuple(sorted(w)) for a, w in sorted(need.items())},
                        unknown=tuple(sorted(unknown)), unparseable_files=tuple(sorted(bad)))


def additional_apis(required: RequiredApis, table: Optional[Dict[str, Any]] = None) -> List[str]:
    """The gateway's terraform.tfvars `additional_apis`: required minus what the foundation already enables
    (its base_apis default) and minus the base trio (enabled by project vending)."""
    t = table if table is not None else load_table()
    have = set(t["base_apis"]) | set(t["foundation_base_apis"])
    return sorted(a for a in required.apis if a not in have)

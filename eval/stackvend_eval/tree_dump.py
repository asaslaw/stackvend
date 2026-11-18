"""S2-0 `--dump-trees`: hermetic export of the trees the developer stage builds (Step 2 plan §2.1, RT F6).

Most Step 1 runs stop with a typed developer failure, so no C2/C3 checkpoint exists and the trees the validators saw
were lost. This observer records, per call and without changing any argument or return value:

  assemble        every `DeveloperAgent._assemble_tree(draft, inputs)` call (one per repair iteration): the draft,
                  the assembled tree it returned, the root module V2c used (`assembled_root`), the platform-vendored
                  file list, and the AssemblyRecord.
  self_correct    every `preflight_validator.self_correct_hcl(files, errors, product_id, platform_files)` call made
                  through the gateway's bindings: its input tree, the HD-15 error strings, the platform-file keys and
                  the returned tree (the S2-B B0 equality corpus).

Trees go to the run's BlobStore; result.json carries `tree_dumps` (lists of blob ids). The wrappers call the original
with the original arguments (no copy is passed in); a snapshot is taken only for the record.
"""
from __future__ import annotations

import functools
import threading
from typing import Any, Dict, List, Optional

from .blobs import BlobStore


def _str_tree(d: Any) -> Dict[str, str]:
    return {k: v for k, v in (d or {}).items() if isinstance(k, str) and isinstance(v, str)}


def _dump_model(v: Any) -> Any:
    if v is None:
        return None
    if hasattr(v, "model_dump"):
        try:
            return v.model_dump(mode="json")
        except Exception:  # noqa: BLE001
            return str(v)[:2000]
    return v


class TreeDump:
    def __init__(self, blobs: BlobStore):
        self.blobs = blobs
        self._lock = threading.Lock()
        self.assemble: List[Dict[str, Any]] = []
        self.self_correct: List[Dict[str, Any]] = []
        self.installed: Dict[str, Any] = {}

    def install(self, mods: Dict[str, Any], rebind: Any) -> Dict[str, Any]:
        dev_mod = mods.get("developer_agent.handler")
        DA = getattr(dev_mod, "DeveloperAgent", None)
        orig_assemble = getattr(DA, "_assemble_tree", None) if DA is not None else None
        if orig_assemble is not None:
            dump = self

            @functools.wraps(orig_assemble)
            def _assemble_tree(self_: Any, draft: Dict[str, str], inputs: Any) -> Any:
                draft_snapshot = _str_tree(draft)
                out = orig_assemble(self_, draft, inputs)
                try:
                    tree, meta = out
                    rec = {"call": None, "draft": dump.blobs.put_tree(draft_snapshot),
                           "assembled": dump.blobs.put_tree(_str_tree(tree)),
                           "assembled_root": dump.blobs.put_tree(_str_tree(meta.get("assembled_root")))
                           if isinstance(meta.get("assembled_root"), dict) else None,
                           "platform_files": sorted((meta.get("platform_files") or {}).keys()),
                           "archetype": meta.get("archetype"),
                           "assembly_record": _dump_model(meta.get("assembly_record"))}
                except Exception as e:  # noqa: BLE001 - the record never changes the product's result
                    rec = {"call": None, "error": f"{type(e).__name__}: {e}"[:300]}
                with dump._lock:
                    rec["call"] = len(dump.assemble)
                    dump.assemble.append(rec)
                return out
            DA._assemble_tree = _assemble_tree
            self.installed["assemble"] = True
        pv = mods.get("developer_agent.preflight_validator")
        orig_scf = getattr(pv, "self_correct_hcl", None) if pv is not None else None
        if orig_scf is not None:
            dump = self

            @functools.wraps(orig_scf)
            def self_correct_hcl(files: Dict[str, str], errors: List[str], product_id: str = "workload",
                                 platform_files: Optional[Dict[str, str]] = None, **kwargs: Any) -> Dict[str, str]:
                # any further keyword (main 10-13: `primary_workload`, lane 11) is forwarded unchanged
                before = _str_tree(files)
                out = orig_scf(files, errors, product_id, platform_files=platform_files, **kwargs)
                try:
                    rec = {"call": None, "files": dump.blobs.put_tree(before), "errors": [str(e) for e in errors or []],
                           "product_id": product_id, "kwargs": {k: repr(v)[:200] for k, v in sorted(kwargs.items())},
                           "platform_files": sorted((platform_files or {}).keys()) if platform_files is not None else None,
                           "result": dump.blobs.put_tree(_str_tree(out))}
                except Exception as e:  # noqa: BLE001
                    rec = {"call": None, "error": f"{type(e).__name__}: {e}"[:300]}
                with dump._lock:
                    rec["call"] = len(dump.self_correct)
                    dump.self_correct.append(rec)
                return out
            self.installed["self_correct_bindings"] = rebind(orig_scf, self_correct_hcl)
        return dict(self.installed)

    def report(self) -> Dict[str, Any]:
        with self._lock:
            return {"installed": dict(self.installed), "assemble": list(self.assemble),
                    "self_correct": list(self.self_correct)}

"""LLM cassettes: record/replay of generate_content calls (plan §7, red-team H5).

Key: (request_hash, occurrence_index). request_hash is computed over the normalized request BEFORE the harness
injects a seed, with harness-controlled values (product_id, trace_id, frozen date) already fixed per run, so a
replay of the same run reproduces the same keys. occurrence_index disambiguates identical retried requests
(junior outer/inner retries resend the same request).

Fallback key (site, ordinal-within-site) exists only to keep a diverged replay going; any call served by it is
tagged `replay_diverged` and the run is excluded from deterministic comparisons.

F9: recorded call entries also carry the normalized `request` they were hashed from, and the meta line carries the
spec (`spec_text`, `spec_sha256`, `spec_mode`), so a divergence can be diffed and a replay never depends on the
checkout's docs (older cassettes: eval/config/cassette_spec_pins.json).

Cassettes contain full internal prompts and model output: they are gitignored (eval/.gitignore) and never
committed (Q7).
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11): the product's default fallback list changed (gemini-3.7-flash ->
# gemini-4-argon). `--fallback-models default` means THIS list, pinned in the harness, never the product's code
# default: it is the fallback every existing cassette was recorded with (their fallback calls name it), so a replay
# that reaches a fallback call still finds its recording. Change it only together with a re-recording.
HARNESS_DEFAULT_FALLBACK_MODELS: Tuple[str, ...] = ("gemini-3.7-flash",)


def _jsonable(v: Any) -> Any:
    try:
        from pydantic import BaseModel
    except Exception:  # pragma: no cover
        BaseModel = None  # type: ignore
    if BaseModel is not None and isinstance(v, type) and issubclass(v, BaseModel):
        return {"$pydantic_class": v.__name__, "json_schema": v.model_json_schema()}
    if BaseModel is not None and isinstance(v, BaseModel):
        out = {}
        for k in sorted(type(v).model_fields):
            val = getattr(v, k, None)
            if val is not None:
                out[k] = _jsonable(val)
        return out
    if isinstance(v, dict):
        return {str(k): _jsonable(val) for k, val in sorted(v.items(), key=lambda kv: str(kv[0])) if val is not None}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if hasattr(v, "value") and isinstance(getattr(v, "value"), (str, int)):  # enums
        return v.value
    return repr(v)


def normalize_request(model: str, contents: Any, config: Any) -> Dict[str, Any]:
    """SLOW-CALL-FALLBACK (owner 11-13): `http_options` (the per-call timeout the developer transport sets, capped by
    the stage time left) is transport, not request content: it is left out of the key, so existing cassettes match."""
    norm_config = _jsonable(config) if config is not None else {}
    if isinstance(norm_config, dict):
        norm_config.pop("http_options", None)
    return {"model": model, "contents": _jsonable(contents), "config": norm_config}


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def request_hash(normalized: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(normalized)).hexdigest()


class Cassette:
    def __init__(self, path: Optional[Path]):
        self.path = Path(path) if path else None
        self.meta: Dict[str, Any] = {}
        self.by_key: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.by_site: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._fh = None

    # ----------------------------------------------------------------------------------------------- read
    @classmethod
    def load(cls, path: Path) -> "Cassette":
        c = cls(path)
        with Path(path).open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("type") == "meta":
                    c.meta = rec
                elif rec.get("type") == "call":
                    c.by_key[(rec["request_hash"], int(rec["occurrence"]))] = rec
                    c.by_site[(rec["site"], int(rec["site_ordinal"]))] = rec
        return c

    def lookup(self, rhash: str, occurrence: int) -> Optional[Dict[str, Any]]:
        return self.by_key.get((rhash, occurrence))

    def lookup_fallback(self, site: str, ordinal: int) -> Optional[Dict[str, Any]]:
        return self.by_site.get((site, ordinal))

    # ---------------------------------------------------------------------------------------------- write
    def open_for_record(self, meta: Dict[str, Any]) -> None:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("w")
        self.meta = {"type": "meta", **meta}
        self._fh.write(json.dumps(self.meta, sort_keys=True) + "\n")
        self._fh.flush()

    def append(self, rec: Dict[str, Any]) -> None:
        rec = {"type": "call", **rec}
        with self._lock:
            self.by_key[(rec["request_hash"], int(rec["occurrence"]))] = rec
            self.by_site[(rec["site"], int(rec["site_ordinal"]))] = rec
            if self._fh is not None:
                self._fh.write(json.dumps(rec, sort_keys=True) + "\n")
                self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def calls(self) -> List[Dict[str, Any]]:
        return list(self.by_key.values())

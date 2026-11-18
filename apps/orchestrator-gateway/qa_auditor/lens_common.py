"""FD-4F: strict parsing of LLM judge replies. Anything short of the documented schema is UNAVAILABLE, never a pass."""

import json
import math
from typing import Any, Dict, List


class LensUnavailableError(RuntimeError):
    """A Stage 2 lens could not produce a verdict (judge unavailable, timeout, unparseable or incomplete reply)."""


def parse_judge_json(raw: str, lens: str) -> Dict[str, Any]:
    clean = (raw or "").strip()
    # A single surrounding ``` / ```json fence is a known transport wrapper, not content: strip exactly that.
    if clean.startswith("```json"):
        clean = clean[len("```json"):]
    elif clean.startswith("```"):
        clean = clean[3:]
    if clean.endswith("```"):
        clean = clean[:-3]
    try:
        data = json.loads(clean.strip())
    except ValueError as e:
        raise LensUnavailableError(f"{lens}: judge reply is not JSON ({e})") from e
    if not isinstance(data, dict):
        raise LensUnavailableError(f"{lens}: judge reply is not a JSON object")
    return data


def require_str_list(data: Dict[str, Any], key: str, lens: str, *, required: bool = True) -> List[str]:
    if key not in data:
        if required:
            raise LensUnavailableError(f"{lens}: judge reply is missing '{key}'")
        return []
    value = data[key]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise LensUnavailableError(f"{lens}: '{key}' must be a list of strings")
    return list(value)


def require_score(data: Dict[str, Any], key: str, lens: str) -> float:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LensUnavailableError(f"{lens}: judge reply has no numeric '{key}'")
    score = float(value)
    if math.isnan(score) or not 0.0 <= score <= 1.0:
        raise LensUnavailableError(f"{lens}: '{key}'={value!r} is outside [0, 1]")
    return score

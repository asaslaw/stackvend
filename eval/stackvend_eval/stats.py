"""Small, dependency-free statistics (red-team L2).

- Wilson score interval: descriptive per-example rates (N=3 is descriptive only).
- Exact McNemar (two-sided binomial on discordant pairs): pooled paired live comparisons.
- Paired deltas: replay comparisons over the same cassettes (the main decision lever).
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple


def wilson(k: int, n: int, z: float = 1.959963984540054) -> Tuple[Optional[float], Optional[float]]:
    if n <= 0:
        return None, None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def mcnemar_exact(b: int, c: int) -> float:
    """b = pass->fail, c = fail->pass discordant pairs. Two-sided exact p-value."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def paired(base: Dict[str, bool], cand: Dict[str, bool]) -> Dict[str, object]:
    keys = sorted(set(base) & set(cand))
    b = sum(1 for k in keys if base[k] and not cand[k])
    c = sum(1 for k in keys if not base[k] and cand[k])
    return {"pairs": len(keys), "pass_to_fail": b, "fail_to_pass": c,
            "regressed": [k for k in keys if base[k] and not cand[k]],
            "improved": [k for k in keys if not base[k] and cand[k]],
            "mcnemar_p": round(mcnemar_exact(b, c), 6)}


def rate(k: int, n: int) -> Dict[str, Optional[float]]:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "ci95": [lo, hi] if n else None}

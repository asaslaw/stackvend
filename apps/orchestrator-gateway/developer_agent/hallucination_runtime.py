"""Process-wide runtime of the hallucination stack (Step 1): the stores, the V1b client and the settings the developer
stage uses. Configured exactly once at startup -- gateway startup (main.py) in production, the eval harness child
in measurement -- and never by a TEST_MODE branch (FD-4F D1, Step 1 RT F6).

Unconfigured (unit tests, old entry points): no ledger/provenance store and no validate client; each consumer states
what it does without one.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

try:
    from shared.diagnostics import MemoryLedgerStore, MemoryProvenanceStore
    from shared.hallucination_stack import HallucinationStackSettings
except ImportError:  # pragma: no cover - gateway-local copy on the import path
    from ..shared.diagnostics import MemoryLedgerStore, MemoryProvenanceStore  # type: ignore
    from ..shared.hallucination_stack import HallucinationStackSettings  # type: ignore


@dataclass(frozen=True)
class HallucinationRuntime:
    ledger_store: Any = None            # shared.diagnostics.LedgerStore
    provenance_store: Any = None        # shared.diagnostics.ProvenanceStore
    validate_client: Any = None         # V1b client: ready() / validate(files, iac_engine=, trace_id=)
    settings: HallucinationStackSettings = field(default_factory=HallucinationStackSettings)
    source: str = "unconfigured"
    # lane 11: IPAM network facts (developer_agent.platform_facts): resolve(product_id, purposes, project_id=)
    facts_provider: Any = None
    # TI-3h (owner 10-21): the install's platform setting governance.iac_intent_generate, read per developer run:
    # (project_id=) -> bool, True only when the setting is exactly True. Gateway startup (main.py) attaches it; the
    # eval harness and unit tests have none, so their HallucinationStackSettings.iac_intent_mode decides alone.
    intent_generate_setting: Any = None
    # SAT-49 F4: workloads/{product_id}.app_provenance (developer_agent.app_provenance); None = no record, no orphan
    # removal (unit tests, eval harness)
    app_provenance_store: Any = None


_LOCK = threading.Lock()
_RUNTIME = HallucinationRuntime()

logger = logging.getLogger("castor-hallucination-stack")

# Bounded readiness wait (owner 10-13, Step 1 follow-up): exponential backoff between /validate/ready probes,
# 2 s doubling to a 30 s cap (probes at ~0, 2, 6, 14, 30, 60, 90, 120, 150, 180 s within the default 180 s).
READY_POLL_INITIAL_S = 2.0
READY_POLL_MAX_S = 30.0
_sleep = time.sleep        # module-level so tests can patch the wait without touching the time module
_clock = time.monotonic


def get_runtime() -> HallucinationRuntime:
    return _RUNTIME


def configure(*, ledger_store: Any = None, provenance_store: Any = None, validate_client: Any = None,
              settings: Optional[HallucinationStackSettings] = None, source: str = "gateway",
              facts_provider: Any = None) -> HallucinationRuntime:
    """Install the runtime (gateway startup). Replaces any previous configuration as a whole."""
    global _RUNTIME
    with _LOCK:
        _RUNTIME = HallucinationRuntime(ledger_store=ledger_store, provenance_store=provenance_store,
                                        validate_client=validate_client,
                                        settings=settings or HallucinationStackSettings(), source=source,
                                        facts_provider=facts_provider)
        return _RUNTIME


def configure_for_harness(*, validate_client: Any = None,
                          settings_overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Eval harness child: in-memory ledger/provenance stores (no Firestore), the harness V1b client, an in-memory
    IPAM facts provider (deterministic, same allocation order as the IPAM engine; lane 11) and per-run setting
    overrides (e.g. repair_max_iterations_precommit=0). Returns a JSON-able description."""
    from .platform_facts import MemoryFactsProvider
    settings = HallucinationStackSettings(**dict(settings_overrides or {}))
    rt = configure(ledger_store=MemoryLedgerStore(), provenance_store=MemoryProvenanceStore(),
                   validate_client=validate_client, settings=settings, source="harness",
                   facts_provider=MemoryFactsProvider())
    return {"source": rt.source, "settings": rt.settings.model_dump(),
            "validate_client": type(validate_client).__name__ if validate_client is not None else None,
            "facts_provider": rt.facts_provider.name}


def reset_for_tests() -> None:
    configure(source="unconfigured")


def with_settings(**overrides: Any) -> HallucinationRuntime:
    """Return (not install) a copy of the runtime with some settings replaced."""
    rt = get_runtime()
    return replace(rt, settings=rt.settings.model_copy(update=overrides))


def wait_for_validate_ready(client: Any, iac_engine: str, max_wait_s: float, *,
                            sleep: Optional[Callable[[float], None]] = None,
                            clock: Optional[Callable[[], float]] = None,
                            accept: Optional[Callable[[Dict[str, Any]], bool]] = None,
                            ) -> Tuple[Dict[str, Any], int, float]:
    """Poll the V1b client's ready() with backoff until it answers ready or `max_wait_s` has elapsed (owner 10-13:
    a cold terraform server is still fetching the engine and provider mirror in its warm-up). Returns (last answer,
    probes, seconds waited). Fail closed: an exception, a non-dict answer or anything but `"ready": True` is NOT
    ready, and the caller raises GATE_UNAVAILABLE on a not-ready answer. No probe starts after the deadline;
    `max_wait_s` <= 0 is a single probe. Nothing here calls an LLM.

    `accept` (validate-ready-wait, 10-27): an extra condition on a ready answer -- e.g. the typed-intent schema-slice
    provider versions are all in `provider_versions` (the server answers ready as soon as `hashicorp/google` is
    mirrored, while its warm-up is still fetching google-beta / kubernetes / random). Polling stops only when the
    answer is ready AND accepted; an `accept` that raises counts as not accepted. The caller re-checks the last
    answer (a timed-out wait returns the last answer, accepted or not)."""
    sleep = sleep or _sleep
    clock = clock or _clock
    start = clock()
    if client is None:
        return {"ready": False, "reason": "no validate client"}, 0, 0.0
    deadline = start + max(0.0, float(max_wait_s))
    delay = READY_POLL_INITIAL_S
    probes = 0
    while True:
        probes += 1
        try:
            answer = client.ready(iac_engine)
            if not isinstance(answer, dict):
                answer = {"ready": False, "reason": f"invalid ready answer ({type(answer).__name__})"}
        except Exception as e:  # noqa: BLE001 - a broken probe is a not-ready gate, never a pass
            answer = {"ready": False, "reason": f"{type(e).__name__}: {e}"}
        if answer.get("ready") is True and _accepted(accept, answer):
            if probes > 1:
                logger.info(f"/validate/ready turned true after {probes} probes ({clock() - start:.0f}s)")
            return answer, probes, clock() - start
        remaining = deadline - clock()
        if remaining <= 0:
            return answer, probes, clock() - start
        pause = min(delay, remaining)
        why = (answer.get("reason") if answer.get("ready") is not True
               else "ready, but the caller's condition is not met yet")
        logger.info(f"/validate/ready not ready (probe {probes}: {why}); next probe in "
                    f"{pause:.0f}s, {remaining:.0f}s left")
        sleep(pause)
        delay = min(delay * 2, READY_POLL_MAX_S)


def _accepted(accept: Optional[Callable[[Dict[str, Any]], bool]], answer: Dict[str, Any]) -> bool:
    if accept is None:
        return True
    try:
        return accept(answer) is True
    except Exception as e:  # noqa: BLE001 - a broken condition is a not-accepted answer, never a pass
        logger.info(f"/validate/ready answer not accepted ({type(e).__name__}: {e})")
        return False

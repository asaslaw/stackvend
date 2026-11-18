"""Fail-closed tripwires on the deterministic stub/fallback paths (plan §2.2; FD-4C is still open).

Each tripwire records `fallback_tripwire` in RunState (sticky, fatal at the next stage boundary) and raises
EvalInvalidRun. Product code may swallow the exception; the sticky state is authoritative.

Observers (not invalidating) record exceptions the product swallows: the swarm (handler.py `except Exception as
swarm_err`) and the in-loop gatekeeper (`except Exception as gk_err`).
"""
from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable, Dict, List, Tuple

from .errors import EvalInvalidRun
from .state import RunState

# (module, class, method) -> human label
TRIPWIRE_SITES: List[Tuple[str, str, str]] = [
    ("architect_agent.handler", "ArchitectAgent", "_fallback_plan"),
    ("architect_agent.red_team_critic", "RedTeamCritic", "_deterministic_fallback_critique"),
    ("developer_agent.lead_orchestrator", "LeadDeveloperOrchestrator", "_build_deterministic_fallback_plan"),
]
# Lane 19 (owner register row 27a) deleted SwarmDispatcher._generate_deterministic_junior_files and
# DeveloperAgent._generate_template_scaffold: with no LLM the developer now raises DeveloperStageError
# (LLM_UNAVAILABLE), so those two stub paths cannot run any more and need no tripwire.
LOG_MARKERS = ("ARCHITECT_FALLBACK_TRIGGERED",)


class _LogTripwire(logging.Handler):
    def __init__(self, state: RunState):
        super().__init__(level=logging.WARNING)
        self.state = state

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:
            return
        for m in LOG_MARKERS:
            if m in msg:
                self.state.record("tripwire", {"site": f"log:{m}"}, invalid="fallback_tripwire")


def install_tripwires(state: RunState, modules: Dict[str, Any]) -> Dict[str, Callable]:
    """Returns the ORIGINAL functions keyed 'module.Class.method' (the synthetic backend reuses them)."""
    originals: Dict[str, Callable] = {}
    for modname, clsname, meth in TRIPWIRE_SITES:
        cls = getattr(modules[modname], clsname)
        orig = cls.__dict__[meth]
        originals[f"{modname}.{clsname}.{meth}"] = orig
        label = f"{clsname}.{meth}"

        def make(orig_fn: Callable, lbl: str) -> Callable:
            @functools.wraps(orig_fn)
            def tripped(*args: Any, **kwargs: Any) -> Any:
                state.record("tripwire", {"site": lbl}, stack=True, invalid="fallback_tripwire")
                raise EvalInvalidRun(f"deterministic fallback '{lbl}' ran: the run would measure a stub")
            return tripped
        setattr(cls, meth, make(orig, label))
    logging.getLogger().addHandler(_LogTripwire(state))
    return originals


def install_observers(state: RunState, modules: Dict[str, Any], checkpoints: Dict[str, Any]) -> None:
    sd = modules["developer_agent.swarm_dispatcher"].SwarmDispatcher
    orig_swarm = sd.__dict__["execute_phased_junior_swarm"]
    assert inspect.iscoroutinefunction(orig_swarm)

    @functools.wraps(orig_swarm)
    async def swarm(*args: Any, **kwargs: Any) -> Any:
        try:
            out = await orig_swarm(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001
            state.record("swallowed_exception", {"site": "SwarmDispatcher.execute_phased_junior_swarm",
                                                 "error": repr(e)[:500]})
            raise
        if isinstance(out, dict):
            checkpoints["C0_raw_swarm"] = dict(out)
        return out
    sd.execute_phased_junior_swarm = swarm

    va = modules["gatekeeper_agent.verifier"].SynthesisVerifierAgent
    orig_vc = va.__dict__["verify_and_cure"]

    @functools.wraps(orig_vc)
    def verify_and_cure(*args: Any, **kwargs: Any) -> Any:
        try:
            return orig_vc(*args, **kwargs)
        except BaseException as e:  # noqa: BLE001
            state.record("swallowed_exception", {"site": "SynthesisVerifierAgent.verify_and_cure",
                                                 "error": repr(e)[:500]})
            raise
    va.verify_and_cure = verify_and_cure

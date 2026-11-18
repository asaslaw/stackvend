"""Harness exception hierarchy.

Guard exceptions subclass OSError/PermissionError so that product code which already tolerates "no network /
no credentials" (as on a machine without ADC) degrades along its existing path. Because product code swallows
them (`except Exception`), every guard/tripwire/budget event ALSO sets sticky per-run state (state.RunState);
the harness never relies on these exceptions propagating (red-team B5/H7).
"""


class EvalGuardBlocked(PermissionError):
    """An isolation guard refused an operation (egress, process creation, client construction)."""


class EvalEgressBlocked(EvalGuardBlocked):
    pass


class EvalProcessBlocked(EvalGuardBlocked):
    pass


class EvalClientBlocked(EvalGuardBlocked):
    pass


class EvalBudgetExceeded(RuntimeError):
    pass


class EvalUnpricedModel(EvalBudgetExceeded):
    pass


class EvalInvalidRun(RuntimeError):
    """A fallback/stub tripwire fired: the run measured a stub, not the model."""


class EvalReplayMiss(RuntimeError):
    pass


class EvalAbort(RuntimeError):
    """Raised at a stage boundary when sticky run state says the run must stop."""


class EvalHarnessError(RuntimeError):
    pass

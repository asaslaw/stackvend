"""BUILD-ADMISSION-QUEUE test support: for tests whose Firestore fake cannot hold the build-slot document (a MagicMock,
or a store without create() / precondition writes), admit every build as the real admission does when a slot is free.
The admission itself is pinned by tests/test_build_admission_queue.py; these tests pin other behaviour of the same
routes."""

import contextlib
from unittest.mock import patch


class _Admitted:
    state = "ADMITTED"
    pump_needed = False
    position = None
    limit = 1
    running = 1

    def __init__(self, trace_id):
        self.trace_id = trace_id

    def view(self):
        return {"state": self.state, "trace_id": self.trace_id, "limit": self.limit, "running": self.running}


def _admit(db, *, trace_id, **_kw):
    return _Admitted(trace_id)


def admit_every_build(monkeypatch, workloads_module):
    """Every CC admission answers ADMITTED and every slot release is a no-op (the pre-queue behaviour)."""
    bq = workloads_module.build_queue
    monkeypatch.setattr(bq, "admit_run", _admit)
    monkeypatch.setattr(bq, "reconcile_and_pump", lambda db: [])
    monkeypatch.setattr(workloads_module, "_release_unpublished_build", lambda trace_id: None)


@contextlib.contextmanager
def every_build_admitted(workloads_module):
    """The same, as a context manager (harnesses that run without pytest's monkeypatch)."""
    bq = workloads_module.build_queue
    with patch.object(bq, "admit_run", _admit), patch.object(bq, "reconcile_and_pump", lambda db: []), \
            patch.object(workloads_module, "_release_unpublished_build", lambda trace_id: None):
        yield

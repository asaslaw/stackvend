"""FD-4CI-b-R3 / 3a test support: Firestore behaviour of the Control Center's preconditioned settings write.

`routes/settings.store_settings_document` reads the stored document through the settings DocumentReference
(`doc_ref.get()`), then writes with `doc_ref.create(doc)` (no document) or
`doc_ref.update(doc, option=db.write_option(last_update_time=<that read's update_time>))`.

`wire_settings_writes(cc_store, doc_ref, source)` makes the MagicMock `doc_ref` the tests already use behave like
Firestore for that:

* `doc_ref.get()` returns a snapshot of `source()` -> (exists, document): the same stored document the strict settings
  reader sees, with the fake's current update_time;
* `create` fails with AlreadyExists when a document exists; `update` fails with NotFound when none exists and with
  FailedPrecondition when the update_time precondition does not match (someone wrote after our read);
* every successful write is recorded as the exact store it is equivalent to, `doc_ref.set(document, merge=False)`
  (top-level DELETE_FIELD entries removed), so the existing assertions on `doc_ref.set` keep meaning "what was stored".

`state.concurrent = fn` runs `fn(state)` once, right after the next read: another writer landing in the window.
`state.bump(data)` is such a write (the stored document changes and update_time moves)."""
import copy
from types import SimpleNamespace

from google.api_core import exceptions as gexc


def strict_reader_source():
    """(exists, document) as the patched `google.cloud.firestore.Client` the strict reader uses would return it."""
    from google.cloud import firestore

    snap = firestore.Client().collection("system_config").document("platform_settings").get()
    exists = getattr(snap, "exists", None) is True
    return exists, (snap.to_dict() if exists else None)


class _State:
    def __init__(self, source):
        self.source, self.update_time, self.concurrent, self.override = source, 1, None, None

    def current(self):
        return self.override if self.override is not None else self.source()

    def bump(self, data):
        """Another writer stored `data` (a dict) after our read."""
        self.override = (True, copy.deepcopy(data))
        self.update_time += 1


def wire_settings_writes(cc_store, doc_ref, source=strict_reader_source):
    state = _State(source)
    cc_store.write_option = lambda **kw: dict(kw)

    def get(*_a, **_k):
        exists, data = state.current()
        snap = SimpleNamespace(exists=bool(exists), update_time=state.update_time,
                               to_dict=lambda d=copy.deepcopy(data): copy.deepcopy(d))
        if state.concurrent is not None:
            hook, state.concurrent = state.concurrent, None
            hook(state)
        return snap

    def create(doc, *_a, **_k):
        if state.current()[0]:
            raise gexc.AlreadyExists("document already exists")
        state.update_time += 1
        doc_ref.set(doc, merge=False)

    def update(upd, option=None, *_a, **_k):
        from google.cloud.firestore_v1 import DELETE_FIELD
        if not state.current()[0]:
            raise gexc.NotFound("no document to update")
        if (option or {}).get("last_update_time") != state.update_time:
            raise gexc.FailedPrecondition("the stored document changed after it was read")
        state.update_time += 1
        doc_ref.set({k: v for k, v in upd.items() if v is not DELETE_FIELD}, merge=False)

    doc_ref.get.side_effect = get
    doc_ref.create.side_effect = create
    doc_ref.update.side_effect = update
    return state

"""In-memory Firestore stand-in with transactions, for the IPAM engine tests (row IPAM-1).

It follows the google-cloud-firestore contract the engine uses: `client.transaction(max_attempts=N)`,
`collection.stream(transaction=txn)` (a transactional read), `txn.set` / `txn.create` (buffered writes) and a
`transactional(fn)(txn)` runner that commits and re-runs `fn` on Aborted, raising ValueError (chained to the last
Aborted) when every attempt aborts. Concurrency control is optimistic: a commit aborts when a collection it read has
changed since the read. `create()` fails AlreadyExists when the document exists. Both errors carry `.code = 409`, like
google.api_core's Conflict family.
"""

import threading


class FakeAborted(Exception):
    code = 409


class FakeAlreadyExists(Exception):
    code = 409


class FakeSnapshot:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data

    def to_dict(self):
        return dict(self._data) if self._data is not None else None

    @property
    def exists(self):
        return self._data is not None


class FakeDocRef:
    def __init__(self, db, coll, doc_id):
        self._db, self._coll, self.id = db, coll, doc_id

    def get(self):
        with self._db.lock:
            return FakeSnapshot(self.id, self._db.store.get(self._coll, {}).get(self.id))

    def set(self, data, merge=False):
        with self._db.lock:
            self._db._apply(self._coll, self.id, dict(data), merge)

    def create(self, data):
        with self._db.lock:
            if self.id in self._db.store.get(self._coll, {}):
                raise FakeAlreadyExists(f"Document already exists: {self._coll}/{self.id}")
            self._db._apply(self._coll, self.id, dict(data), False)

    def update(self, data):
        with self._db.lock:
            self._db._apply(self._coll, self.id, dict(data), True)

    def delete(self):
        with self._db.lock:
            self._db.store.get(self._coll, {}).pop(self.id, None)
            self._db.versions[self._coll] = self._db.versions.get(self._coll, 0) + 1


class FakeCollection:
    def __init__(self, db, name):
        self._db, self._name = db, name

    def document(self, doc_id):
        return FakeDocRef(self._db, self._name, doc_id)

    def stream(self, transaction=None):
        if self._db.read_error is not None:
            raise self._db.read_error
        with self._db.lock:
            snaps = [FakeSnapshot(k, dict(v)) for k, v in sorted(self._db.store.get(self._name, {}).items())]
            if transaction is not None:
                transaction.read_versions.setdefault(self._name, self._db.versions.get(self._name, 0))
        if self._db.after_read is not None:
            self._db.after_read(self._name, transaction)
        return iter(snaps)

    def where(self, field, op, value):
        db, name = self._db, self._name

        class _Filtered:
            def stream(self_inner, transaction=None):
                return iter([s for s in FakeCollection(db, name).stream(transaction) if (s.to_dict() or {}).get(field) == value])

        return _Filtered()


class FakeTransaction:
    def __init__(self, db, max_attempts=5):
        self._db = db
        self._max_attempts = max_attempts
        self.read_versions = {}
        self.writes = []
        self.commits = 0
        self.aborts = 0

    def set(self, ref, data, merge=False):
        self.writes.append(("set", ref, dict(data), merge))

    def create(self, ref, data):
        self.writes.append(("create", ref, dict(data), False))

    def _reset(self):
        self.read_versions = {}
        self.writes = []

    def _commit(self):
        db = self._db
        with db.lock:
            if db.abort_commits > 0:
                db.abort_commits -= 1
                self.aborts += 1
                raise FakeAborted("simulated contention")
            for coll, seen in self.read_versions.items():
                if db.versions.get(coll, 0) != seen:
                    self.aborts += 1
                    raise FakeAborted(f"{coll} changed since it was read")
            for kind, ref, data, _merge in self.writes:
                if kind == "create" and ref.id in db.store.get(ref._coll, {}):
                    raise FakeAlreadyExists(f"Document already exists: {ref._coll}/{ref.id}")
            for kind, ref, data, merge in self.writes:
                db._apply(ref._coll, ref.id, data, merge)
            self.commits += 1
            db.commits += 1


def fake_transactional(fn):
    """Same contract as google.cloud.firestore_v1.transaction.transactional."""

    def run(transaction, *args, **kwargs):
        last = None
        for _attempt in range(transaction._max_attempts):
            transaction._reset()
            result = fn(transaction, *args, **kwargs)
            try:
                transaction._commit()
                return result
            except FakeAborted as e:
                last = e
        raise ValueError(f"Failed to commit transaction in {transaction._max_attempts} attempts.") from last

    return run


class FakeFirestore:
    def __init__(self):
        self.store = {}
        self.versions = {}
        self.lock = threading.RLock()
        self.read_error = None     # an exception to raise on every collection read
        self.after_read = None     # hook(collection_name, transaction) run after each read (outside the lock)
        self.abort_commits = 0     # abort this many commits unconditionally
        self.commits = 0
        self.transactions = []

    def collection(self, name):
        return FakeCollection(self, name)

    def transaction(self, max_attempts=5):
        txn = FakeTransaction(self, max_attempts)
        self.transactions.append(txn)
        return txn

    def _apply(self, coll, doc_id, data, merge):
        bucket = self.store.setdefault(coll, {})
        if merge and doc_id in bucket:
            bucket[doc_id].update(data)
        else:
            bucket[doc_id] = dict(data)
        self.versions[coll] = self.versions.get(coll, 0) + 1

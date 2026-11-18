"""C10 test fakes: an in-memory Firestore (the subset the C10 jobs and shared modules use) and Pub/Sub / Run REST
sessions. No google client is constructed (the root conftest forbids real Firestore clients)."""
import base64
import itertools
import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional


class AlreadyExists(Exception):
    code = 409


class FailedPrecondition(Exception):
    code = 412


_ids = itertools.count(1)


class _Snap:
    def __init__(self, doc_id, data, update_time):
        self.id, self._data, self.update_time = doc_id, data, update_time
        self.exists = data is not None
        self.reference = None

    def to_dict(self):
        return dict(self._data) if self._data is not None else None


class DocRef:
    def __init__(self, db, path):
        self.db, self.path = db, path
        self.id = path[-1]

    def _key(self):
        return tuple(self.path)

    def get(self):
        if ("get", self._key()) in self.db.fail:
            raise RuntimeError("get failed")
        data = self.db.docs.get(self._key())
        snap = _Snap(self.id, data, self.db.times.get(self._key()))
        snap.reference = self
        return snap

    def create(self, data):
        self.db.ops.append(("create", self._key()))
        if ("create", self.path[0]) in self.db.fail:
            raise RuntimeError("create failed")
        if self._key() in self.db.docs:
            raise AlreadyExists(self._key())
        self._write(dict(data))

    def set(self, data, merge=False):
        self.db.ops.append(("set", self._key()))
        if ("set", self.path[0]) in self.db.fail:
            raise RuntimeError("set failed")
        cur = self.db.docs.get(self._key()) if merge else None
        self._write({**(cur or {}), **dict(data)})

    def update(self, data, option=None):
        self.db.ops.append(("update", self._key()))
        if option is not None and option != self.db.times.get(self._key()):
            raise FailedPrecondition(self._key())
        self._write({**(self.db.docs.get(self._key()) or {}), **dict(data)})

    def delete(self):
        self.db.ops.append(("delete", self._key()))
        self.db.docs.pop(self._key(), None)

    def _write(self, data):
        self.db.docs[self._key()] = data
        self.db.times[self._key()] = next(_ids)

    def collection(self, name):
        return Collection(self.db, self.path + [name])


class Query:
    def __init__(self, coll, filters, lim=None):
        self.coll, self.filters, self.lim = coll, filters, lim

    def where(self, field, op, value):
        return Query(self.coll, self.filters + [(field, op, value)], self.lim)

    def limit(self, n):
        return Query(self.coll, self.filters, n)

    def stream(self):
        if ("stream", self.coll.path[-1]) in self.coll.db.fail:
            raise RuntimeError("query failed")
        out = []
        for key, data in sorted(self.coll.db.docs.items()):
            if list(key[:-1]) != self.coll.path:
                continue
            ok = True
            for field, op, value in self.filters:
                v = data.get(field)
                if op == "==" and v != value:
                    ok = False
                if op == "in" and v not in value:
                    ok = False
            if ok:
                snap = DocRef(self.coll.db, list(key)).get()
                out.append(snap)
        return iter(out[: self.lim] if self.lim else out)


class Collection(Query):
    def __init__(self, db, path):
        self.db, self.path = db, path
        super().__init__(self, [])

    def document(self, doc_id=None):
        return DocRef(self.db, self.path + [doc_id or f"auto{next(_ids)}"])

    def add(self, data):
        ref = self.document()
        ref.set(data)
        return None, ref


class _Batch:
    def __init__(self, db):
        self.db, self.writes = db, []

    def set(self, ref, data, merge=False):
        self.writes.append(("set", ref, data, merge))

    def delete(self, ref):
        self.writes.append(("delete", ref, None, False))

    def commit(self):
        self.db.ops.append(("commit", tuple(w[1]._key() for w in self.writes)))
        if ("commit", None) in self.db.fail:
            raise RuntimeError("batch commit failed")
        for op, ref, data, merge in self.writes:
            if op == "set":
                cur = self.db.docs.get(ref._key()) if merge else None
                ref._write({**(cur or {}), **dict(data)})
            else:
                self.db.docs.pop(ref._key(), None)


class FakeDB:
    def __init__(self):
        self.docs: Dict[tuple, Dict[str, Any]] = {}
        self.times: Dict[tuple, int] = {}
        self.ops: List[tuple] = []
        self.fail = set()

    def collection(self, name):
        return Collection(self, [name])

    def write_option(self, last_update_time=None):
        return last_update_time

    def batch(self):
        """RT14-05 / RT14-20: an atomic batch; ("commit", None) in `fail` makes commit() raise with nothing written."""
        return _Batch(self)

    def put(self, *path_and_data):
        *path, data = path_and_data
        DocRef(self, list(path))._write(dict(data))

    def doc(self, *path):
        return self.docs.get(tuple(path))

    def coll(self, *path):
        return {k[-1]: v for k, v in self.docs.items() if list(k[:-1]) == list(path)}


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.text = status, body, json.dumps(body) if body is not None else ""

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


def b64(obj) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


class FakeRest:
    """Pub/Sub pull/ack/modack + Run jobs:run / executions.get, recorded in `calls`."""

    def __init__(self, messages=(), run_status=200, execution="", on_run=None, exec_complete=True):
        self.queue = list(messages)
        self.calls: List[tuple] = []
        self.run_status, self.execution, self.on_run, self.exec_complete = run_status, execution, on_run, exec_complete
        self.pull_script: List[Any] = []
        self.expired_ack_ids = set()

    def post(self, url, json=None, timeout=None):
        verb = url.rsplit(":", 1)[-1]
        self.calls.append((verb, json))
        if verb == "pull":
            if self.pull_script:   # scripted answers, one per pull (each a list of received messages)
                answer = self.pull_script.pop(0)
                return Resp(200, {"receivedMessages": answer} if answer else {})
            n = int((json or {}).get("maxMessages") or 1)
            batch, self.queue = self.queue[:n], self.queue[n:]
            return Resp(200, {"receivedMessages": batch} if batch else {})
        if verb in ("acknowledge", "modifyAckDeadline") and self.expired_ack_ids & set((json or {}).get("ackIds") or []):
            return Resp(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT", "details": [
                {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "EXACTLY_ONCE_ACKID_FAILURE",
                 "metadata": {a: "PERMANENT_FAILURE_INVALID_ACK_ID" for a in json["ackIds"]}}]}})
        if verb in ("acknowledge", "modifyAckDeadline"):
            return Resp(200, {})
        if verb == "run":
            if self.on_run:
                self.on_run(json)
            if self.run_status != 200:
                return Resp(self.run_status, {"error": {}})
            return Resp(200, {"metadata": {"name": self.execution}})
        raise AssertionError(url)

    def get(self, url, timeout=None):
        self.calls.append(("get", url))
        return Resp(200, {"completionTime": "2026-11-07T00:00:00Z"} if self.exec_complete else {})

    def verbs(self):
        return [c[0] for c in self.calls]


def message(mid, data, attributes=None, ack_id=None, attempt=1):
    return {"ackId": ack_id or f"ack-{mid}", "deliveryAttempt": attempt,
            "message": {"messageId": mid, "data": data, "attributes": attributes or {}}}


ns = SimpleNamespace

"""Test-only: a fake of the Google APIs the upgrader's stage scripts call, for tests/test_selfup_b2_stages.py.

Loaded in the stage scripts' Python children through PYTHONPATH (tests/hermetic_child/sitecustomize.py installs the
hermetic guard first and then chains to this file). It replaces urllib.request.urlopen, so no socket is ever opened.
State: the JSON file $STUB_API_STATE (services, revisions, jobs, act-as grants, Artifact Registry, Firestore
documents, /validate/ready). Every call is appended to $STUB_API_LOG as "METHOD URL".
"""
import fcntl
import hashlib
import io
import json
import os
import urllib.error
import urllib.parse
import urllib.request


class _Resp:
    def __init__(self, status, body=b"", headers=None):
        self.status, self._body, self.headers = status, body, _Headers(headers or {})

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Headers(dict):
    def items(self):
        return list(dict.items(self))


def _digest_of(ref):
    return "sha256:" + hashlib.sha256(ref.encode()).hexdigest()


def _service_doc(state, name):
    s = state["services"][name]
    return {"metadata": {"name": name, "annotations": s.get("annotations", {})},
            "spec": {"template": s.get("template") or {"spec": {"serviceAccountName": s["sa"]}}},
            "status": {"latestReadyRevisionName": s["revision"], "latestCreatedRevisionName": s.get("created", s["revision"]),
                       "conditions": [{"type": "Ready", "status": "True" if s.get("ready", True) else "False"}],
                       "url": f"https://{name}.example.run.app"}}


def _job_doc(state, name):
    j = state["jobs"][name]
    return {"metadata": {"name": name, "labels": j.get("labels", {})},
            "spec": {"template": {"spec": {"template": {"spec": {"serviceAccountName": j["sa"],
                                                                 "containers": [{"image": j["image"]}]}}}}}}


def _fake(method, url, body, state):
    if url.startswith("http://metadata.google.internal/"):
        if "/identity?" in url:
            return 200, b"h.p.s", {}
        return 200, json.dumps({"access_token": "stub-token"}).encode(), {}
    u = urllib.parse.urlsplit(url)
    path = u.path
    if u.netloc == "artifactregistry.googleapis.com":
        return (200, b"{}", {}) if state.get("ar", True) else (404, b"", {})
    if u.netloc == "run.googleapis.com" and path.startswith("/v2/") and "/services/" in path:
        name = path.rsplit("/", 1)[1]
        if name not in state["services"]:
            return 404, b"", {}
        doc = {"name": path[len("/v2/"):]}
        ingress = state["services"][name].get("ingress", "INGRESS_TRAFFIC_ALL")
        if ingress is not None:   # None: a v2 answer without the typed field
            doc["ingress"] = ingress
        return 200, json.dumps(doc).encode(), {}
    if u.netloc.endswith("-run.googleapis.com"):
        name = path.rsplit("/", 1)[1]
        if "/services/" in path:
            return (200, json.dumps(_service_doc(state, name)).encode(), {}) if name in state["services"] else (404, b"", {})
        if "/revisions/" in path:
            rev = state["revisions"].get(name)
            if rev is None:
                return 404, b"", {}
            return 200, json.dumps({"metadata": {"labels": {"serving.knative.dev/service": rev["service"]}},
                                    "status": {"imageDigest": rev["image"]}}).encode(), {}
        if "/jobs/" in path:
            return (200, json.dumps(_job_doc(state, name)).encode(), {}) if name in state["jobs"] else (404, b"", {})
    if u.netloc == "iam.googleapis.com":
        sa = path.split("/serviceAccounts/", 1)[1].split(":", 1)[0]
        perms = ["iam.serviceAccounts.actAs"] if sa in state.get("actas", []) else []
        return 200, json.dumps({"permissions": perms} if perms else {}).encode(), {}
    if u.netloc.endswith("-docker.pkg.dev") and "/manifests/" in path:
        repo_path, ref = path[len("/v2/"):].split("/manifests/")
        image = f"{u.netloc}/{repo_path}"
        if ref.startswith("sha256:"):
            ok = f"{image}@{ref}" in state.get("registry", [])
            return (200, b"", {"Docker-Content-Digest": ref}) if ok else (404, b"", {})
        pushed = os.path.join(os.environ["STUB_API_DIR"], "pushed", hashlib.sha256(f"{image}:{ref}".encode()).hexdigest())
        if os.path.exists(pushed) or f"{image}:{ref}" in state.get("registry_tags", {}):
            digest = state.get("registry_tags", {}).get(f"{image}:{ref}") or _digest_of(f"{image}:{ref}")
            return 200, b"", {"Docker-Content-Digest": digest}
        return 404, b"", {}
    if u.netloc == "firestore.googleapis.com":
        key = path.split("/documents/", 1)[1]
        docs = state.setdefault("firestore", {})
        if method == "GET":
            return (200, json.dumps(docs[key]).encode(), {}) if key in docs else (404, b"", {})
        if method == "PATCH":
            q = urllib.parse.parse_qs(u.query)
            if q.get("currentDocument.exists") == ["false"] and key in docs:
                return 409, b"", {}
            if q.get("currentDocument.exists") == ["true"] and key not in docs:
                return 404, b"", {}
            new = json.loads(body)
            fields = dict((docs.get(key) or {}).get("fields") or {})
            mask = q.get("updateMask.fieldPaths")
            for k, v in (new.get("fields") or {}).items():
                if mask is None or k in mask:
                    fields[k] = v
            docs[key] = {"fields": fields, "updateTime": "2026-11-02T00:00:00Z"}
            return 200, b"{}", {}
    if u.netloc.endswith(".example.run.app") and path == "/validate/ready":
        st = state.get("ready_status", 403)
        return st, json.dumps({"ready": state.get("ready", True)}).encode() if st == 200 else b"", {}
    return 599, b"", {}


def _urlopen(req, data=None, timeout=None, **kw):
    if isinstance(req, str):
        req = urllib.request.Request(req, data=data)
    method, url = req.get_method(), req.full_url
    with open(os.environ["STUB_API_STATE"] + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        with open(os.environ["STUB_API_STATE"]) as fh:
            state = json.load(fh)
        with open(os.environ["STUB_API_LOG"], "a") as log:
            log.write(f"{method} {url}\n")
        status, body, headers = _fake(method, url, req.data, state)
        with open(os.environ["STUB_API_STATE"], "w") as fh:
            json.dump(state, fh)
    if status >= 400:
        raise urllib.error.HTTPError(url, status, "fake", headers, io.BytesIO(body))
    return _Resp(status, body, headers)


if os.environ.get("STUB_API_STATE"):
    urllib.request.urlopen = _urlopen

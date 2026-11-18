"""
FD-7L Phase 3 test fakes: an in-memory Cloud Storage object world (versioned objects, generation preconditions,
rewrite, media upload, delete by generation) and tf-applier execution listing, layered on fd7l_fakes.FakeGoogle.
No network, no GCP.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
import json
import zlib
from urllib.parse import unquote

import fd7l_fakes as k

_STORAGE = "https://storage.googleapis.com/storage/v1/b/"
_UPLOAD = "https://storage.googleapis.com/upload/storage/v1/b/"
EXECUTIONS = f"projects/{k.HOST}/locations/{k.REGION}/jobs/{k.JOB}/executions"


def crc(data) -> str:
    return str(zlib.crc32(json.dumps(data, sort_keys=True).encode("utf-8")))


class GCSGoogle(k.FakeGoogle):
    """FakeGoogle plus versioned GCS objects: objects[bucket][name] = [version, ...] oldest first, each
    {generation, data, crc32c, metadata, updated, timeDeleted, contentType}."""

    def __init__(self, log=None):
        super().__init__(log)
        self.objects = {}
        self.gen = 1000
        self.running = []              # tf-applier executions listed by the Run API (dicts)
        self.rewrite_hook = None       # called (src_bucket, src_name, src_gen) before each rewrite
        self.rewrite_fail = {}         # n-th rewrite (1-based) -> status
        self.rewrite_corrupt = set()   # n-th rewrites (1-based) that store different bytes (crc32c mismatch)
        self.rewrites = 0
        self.perms = None              # testIamPermissions answer for vending on children (None = all)

    # -- helpers for tests ---------------------------------------------------------------------------------
    def put(self, bucket, name, data, *, metadata=None, updated="2026-10-01T00:00:00Z"):
        self.gen += 1
        versions = self.objects.setdefault(bucket, {}).setdefault(name, [])
        for v in versions:
            if v["timeDeleted"] is None:
                v["timeDeleted"] = "2026-10-30T00:00:00Z"
        versions.append({"generation": self.gen, "data": copy.deepcopy(data), "crc32c": crc(data),
                         "metadata": dict(metadata or {}), "updated": updated, "timeDeleted": None,
                         "contentType": "application/json"})
        return str(self.gen)

    def versions(self, bucket, name):
        return list(self.objects.get(bucket, {}).get(name, []))

    def live(self, bucket, name):
        lv = [v for v in self.versions(bucket, name) if v["timeDeleted"] is None]
        return lv[-1] if lv else None

    def _item(self, bucket, name, v):
        out = {"name": name, "bucket": bucket, "generation": str(v["generation"]), "crc32c": v["crc32c"],
               "updated": v["updated"], "contentType": v["contentType"], "metadata": dict(v["metadata"])}
        if v["timeDeleted"]:
            out["timeDeleted"] = v["timeDeleted"]
        return out

    # -- routing -------------------------------------------------------------------------------------------
    def _route(self, m, url, json_body, params, bearer):
        params = params or {}
        if url.startswith(_UPLOAD) and m == "POST":
            bucket = url[len(_UPLOAD):].split("/")[0]
            name = params["name"]
            live = self.live(bucket, name)
            want = str(params.get("ifGenerationMatch"))
            if (want == "0" and live is not None) or (want != "0" and (live is None or
                                                                      str(live["generation"]) != want)):
                return 412, {}
            gen = self.put(bucket, name, json_body)
            return 200, {"name": name, "generation": gen}
        if url.startswith(_STORAGE):
            rest = url[len(_STORAGE):]
            bucket, _, tail = rest.partition("/")
            if tail == "o" and m == "GET":
                prefix = params.get("prefix", "")
                items = []
                for name, versions in sorted(self.objects.get(bucket, {}).items()):
                    if not name.startswith(prefix):
                        continue
                    for v in versions:
                        if v["timeDeleted"] is None or params.get("versions") == "true":
                            items.append(self._item(bucket, name, v))
                return 200, {"items": items}
            if tail.startswith("o/"):
                obj_part = tail[2:]
                if "/rewriteTo/b/" in obj_part:
                    if m != "POST":
                        return 405, {}
                    self.rewrites += 1
                    st = self.rewrite_fail.get(self.rewrites)
                    if st:
                        return st, {}
                    src_name = unquote(obj_part.split("/rewriteTo/b/")[0])
                    dst_bucket, _, dst_rest = obj_part.split("/rewriteTo/b/")[1].partition("/o/")
                    dst_name = unquote(dst_rest)
                    src_gen = str(params["sourceGeneration"])
                    if self.rewrite_hook:
                        self.rewrite_hook(bucket, src_name, src_gen)
                    src = next((v for v in self.versions(bucket, src_name) if str(v["generation"]) == src_gen), None)
                    if src is None:
                        return 404, {}
                    live = self.live(dst_bucket, dst_name)
                    want = str(params.get("ifGenerationMatch"))
                    if (want == "0" and live is not None) or (want != "0" and (live is None or
                                                                              str(live["generation"]) != want)):
                        return 412, {}
                    data = dict(src["data"], corrupted=True) if self.rewrites in self.rewrite_corrupt else src["data"]
                    gen = self.put(dst_bucket, dst_name, data, metadata=(json_body or {}).get("metadata"))
                    v = self.live(dst_bucket, dst_name)
                    return 200, {"done": True, "resource": self._item(dst_bucket, dst_name, v) | {"generation": gen}}
                name = unquote(obj_part)
                versions = self.versions(bucket, name)
                if m == "DELETE":
                    g = str(params.get("generation"))
                    keep = [v for v in versions if str(v["generation"]) != g]
                    if len(keep) == len(versions):
                        return 404, {}
                    self.objects[bucket][name] = keep
                    return 204, {}
                if m == "GET":
                    g = params.get("generation")
                    v = (next((x for x in versions if str(x["generation"]) == str(g)), None) if g
                         else self.live(bucket, name))
                    if v is None:
                        return 404, {}
                    if params.get("alt") == "media":
                        return 200, copy.deepcopy(v["data"])
                    return 200, self._item(bucket, name, v)
        if url == f"https://run.googleapis.com/v2/{EXECUTIONS}" and m == "GET":
            return 200, {"executions": copy.deepcopy(self.running)}
        if url.startswith("https://cloudresourcemanager.googleapis.com/v3/projects/") \
                and url.endswith(":testIamPermissions") and bearer is None and self.perms is not None:
            return 200, {"permissions": [p for p in json_body["permissions"] if p in self.perms]}
        return super()._route(m, url, json_body, params, bearer)

    def gcs_mutations(self):
        return [(m, url.split("?")[0]) for m, url, *_ in self.calls
                if (m in ("POST", "DELETE", "PUT") and ("storage.googleapis.com" in url) and "/o" in url)]

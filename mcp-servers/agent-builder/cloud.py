"""
REST calls the agent-builder server makes in a managed CHILD project (lane 14 PR-9). AuthorizedSession only: no
Vertex AI / ADK SDK is imported here (the SDK's `agent_engines.create` pickles a live agent object; that happens only
inside the child's Cloud Build). The session is injectable for hermetic tests.

Every call returns parsed JSON or raises CloudError(stage, http_status, detail); nothing is ever defaulted.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional
from urllib.parse import quote

SERVICE_USAGE = "https://serviceusage.googleapis.com/v1"
CLOUD_BUILD = "https://cloudbuild.googleapis.com/v1"
STORAGE = "https://storage.googleapis.com/storage/v1"
STORAGE_UPLOAD = "https://storage.googleapis.com/upload/storage/v1"
RESOURCE_MANAGER = "https://cloudresourcemanager.googleapis.com/v3"
TIMEOUT_S = 30.0

DISCOVERY_LOCATIONS = frozenset({"global", "us", "eu"})


class CloudError(Exception):
    def __init__(self, stage: str, http_status: Optional[int], detail: str = ""):
        super().__init__(f"{stage}: HTTP {http_status}: {detail}")
        self.stage, self.http_status, self.detail = stage, http_status, detail


def safe_segment(value: str) -> bool:
    """Project ids, regions, bucket names, build ids: [a-z0-9._-] only, so they can never alter a URL."""
    return isinstance(value, str) and bool(value) and len(value) <= 222 and all(
        ch.islower() or ch.isdigit() or ch in "-._" for ch in value)


def aiplatform_base(region: str) -> str:
    return f"https://{region}-aiplatform.googleapis.com/v1"


def discovery_base(location: str) -> str:
    return "https://discoveryengine.googleapis.com/v1" if location == "global" else (
        f"https://{location}-discoveryengine.googleapis.com/v1")


def _default_session():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return AuthorizedSession(creds)


class ChildProjectClient:
    def __init__(self, session_factory: Optional[Callable[[], Any]] = None):
        self._factory = session_factory or _default_session
        self._session = None

    @property
    def session(self):
        if self._session is None:
            self._session = self._factory()
        return self._session

    def _json(self, stage: str, res: Any, ok=(200,)) -> Dict[str, Any]:
        status = getattr(res, "status_code", None)
        if status not in ok:
            text = ""
            try:
                text = (res.text or "")[:300]
            except Exception:
                pass
            raise CloudError(stage, status, text)
        try:
            body = res.json()
        except Exception as e:
            raise CloudError(stage, status, f"invalid JSON: {type(e).__name__}") from e
        if not isinstance(body, dict):
            raise CloudError(stage, status, "response is not an object")
        return body

    def _call(self, stage: str, method: str, url: str, **kw: Any):
        try:
            return getattr(self.session, method)(url, timeout=TIMEOUT_S, **kw)
        except CloudError:
            raise
        except Exception as e:
            raise CloudError(stage, None, f"{type(e).__name__}: {e}") from e

    # -- prerequisites
    def service_enabled(self, project: str, api: str) -> bool:
        body = self._json("SERVICE_USAGE", self._call(
            "SERVICE_USAGE", "get", f"{SERVICE_USAGE}/projects/{project}/services/{api}",
            headers={"X-Goog-User-Project": project}))
        return body.get("state") == "ENABLED"

    def get_project_number(self, project: str) -> str:
        """Resource Manager v3 `projects.get`: the child's own project number (RT F3). Raises CloudError."""
        body = self._json("PROJECT_GET", self._call("PROJECT_GET", "get", f"{RESOURCE_MANAGER}/projects/{project}"))
        prefix, _, number = (body.get("name") or "").partition("/")
        if prefix != "projects" or not number.isascii() or not number.isdigit():
            raise CloudError("PROJECT_GET", 200, "projects.get returned no project number")
        return number

    # -- Cloud Storage
    def upload_object(self, bucket: str, name: str, data: bytes, content_type: str) -> Dict[str, Any]:
        return self._json("UPLOAD", self._call(
            "UPLOAD", "post", f"{STORAGE_UPLOAD}/b/{bucket}/o?uploadType=media&name={quote(name, safe='')}",
            data=data, headers={"Content-Type": content_type}))

    def read_object(self, bucket: str, name: str) -> Optional[bytes]:
        res = self._call("RESULT_READ", "get", f"{STORAGE}/b/{bucket}/o/{quote(name, safe='')}?alt=media")
        status = getattr(res, "status_code", None)
        if status == 404:
            return None
        if status != 200:
            raise CloudError("RESULT_READ", status, "")
        return res.content

    # -- Cloud Build (in the child project, as the child's build SA)
    def create_build(self, project: str, region: str, build: Dict[str, Any]) -> Dict[str, Any]:
        return self._json("BUILD_CREATE", self._call(
            "BUILD_CREATE", "post", f"{CLOUD_BUILD}/projects/{project}/locations/{region}/builds", json=build))

    def get_build(self, project: str, region: str, build_id: str) -> Dict[str, Any]:
        return self._json("BUILD_STATUS", self._call(
            "BUILD_STATUS", "get", f"{CLOUD_BUILD}/projects/{project}/locations/{region}/builds/{build_id}"))

    # -- Vertex AI Agent Engine
    def get_reasoning_engine(self, region: str, name: str) -> Dict[str, Any]:
        return self._json("ENGINE_GET", self._call("ENGINE_GET", "get", f"{aiplatform_base(region)}/{name}"))

    def stream_query(self, region: str, name: str, user_id: str, message: str) -> str:
        """AdkApp `stream_query`; returns the concatenated text parts of the streamed events."""
        res = self._call("ENGINE_QUERY", "post", f"{aiplatform_base(region)}/{name}:streamQuery",
                         json={"class_method": "stream_query", "input": {"user_id": user_id, "message": message}})
        status = getattr(res, "status_code", None)
        if status != 200:
            raise CloudError("ENGINE_QUERY", status, "")
        texts = []
        for line in (res.text or "").splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError as e:
                raise CloudError("ENGINE_QUERY", status, "stream line is not JSON") from e
            for part in ((event.get("content") or {}).get("parts") or []) if isinstance(event, dict) else []:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    texts.append(part["text"])
        return "".join(texts)

    def evaluate_instance(self, project: str, region: str, input_key: str, result_key: str,
                          instance: Dict[str, Any]) -> Dict[str, Any]:
        body = self._json("EVALUATE", self._call(
            "EVALUATE", "post", f"{aiplatform_base(region)}/projects/{project}/locations/{region}:evaluateInstances",
            json={input_key: {"metricSpec": {}, "instance": instance}}))
        result = body.get(result_key)
        if not isinstance(result, dict) or not isinstance(result.get("score"), (int, float)):
            raise CloudError("EVALUATE", 200, f"{result_key}.score missing")
        return result

    # -- Discovery Engine
    def create_datastore(self, project: str, location: str, datastore_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._json("DATASTORE_CREATE", self._call(
            "DATASTORE_CREATE", "post",
            f"{discovery_base(location)}/projects/{project}/locations/{location}/collections/default_collection/"
            f"dataStores?dataStoreId={quote(datastore_id, safe='')}",
            json=body, headers={"X-Goog-User-Project": project}))

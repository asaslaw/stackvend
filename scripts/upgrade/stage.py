#!/usr/bin/env python3
"""
StackVend upgrader, stages after step 0 (SELFUP P3b; plan docs/planning/self-upgrade-plan.md §3.4.2, §3.5-§3.8;
plan RT 11-02 M-3, I-1). Runs from the VERIFIED target tree (scripts/upgrade/run.sh and the stage scripts), so it
can change with any release (no Terraform apply). Typed Cloud Run / IAM / Artifact Registry REST reads with the build
identity's metadata-server token; nothing is guessed from text. Standard library only.

Commands (a stage failure: one line `stackvend-upgrade: FAILED <CODE> [<component>]: <message>` on stderr and the
exit status of FAIL_CODES[<CODE>]; every command that writes a result writes JSON):
  fields      --verified FILE                print "<project> <region> <kind> <request_id> <release> <commit12>"
  preflight   --project P --region R --out FILE NAME:KIND...
              every component exists (skip: castor-git-server when it is not deployed) and the build identity may act
              as its runtime service account (iam testIamPermissions); the git server is on its FUSE volume; the
              Artifact Registry repository exists                          -> PLATFORM_NOT_READY <component>
  docker-config --region R --out DIR         DIR/config.json with a fresh token for <region>-docker.pkg.dev
  tag-absent  --image REF                    the build's target tag does not exist yet (registry HEAD 404), else
                                             IMAGE_TAG_EXISTS (FD-148)
  report-digest --report FILE --image REF    the digest pack exported for REF (report.toml [image] digest) as a
                                             digest reference; the tag is never re-read (FD-148)
  snapshot    --project P --region R --out FILE NAME:KIND...
              what runs now, before anything is deployed: service -> its ready revision (+ digest); job -> its image
              as a digest reference (a tag is resolved through Artifact Registry, M-3) or `unavailable`
  check       --project P --region R --deployed FILE --out FILE
              every deployed service runs a Ready revision with the deployed digest; every job carries the deployed
              image (+ the QA contract label); tf-applier == mcp-terraform-server, stage-runner == the
              orchestrator gateway                                                     -> CHECK_FAILED <component>
  ready       --project P --region R          mcp-terraform-server GET /validate/ready with an ID token: READY, or
              NOT_CHECKED when the build identity may not call it (it has no run.invoker by design), else CHECK_FAILED.
              The server's ingress is read first (Run Admin API v2, typed `ingress`): an internal-only value is
              NOT_CHECKED INGRESS_INTERNAL with no HTTP probe (Cloud Build is never an internal source); an unknown
              value is API_FAILED. After a NOT_CHECKED, the Control Center checks /validate/ready with its own
              identity when Settings ▸ Upgrades shows the finished upgrade
  rollback-plan --project P --region R --previous FILE --out FILE
              the targets to roll back to, re-validated against Cloud Run / Artifact Registry (never trusted from the
              progress record alone): service -> the recorded revision must belong to that service and its digest
              comes from Cloud Run; job -> a digest reference in the platform repository castor-docker-repo that exists.
              Others: ROLLBACK_UNAVAILABLE <component>.
  previous    --project P --request-id ID --out FILE    the `previous` snapshot from platform_upgrades_progress/{id}
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

FAIL_CODES: Dict[str, int] = {
    "USAGE": 2,
    "PLATFORM_NOT_READY": 80,
    "BUILDER_PIN_MISSING": 81,
    "BUILD_FAILED": 82,
    "DIGEST_UNKNOWN": 83,
    "DEPLOY_FAILED": 84,
    "CHECK_FAILED": 85,
    "ROLLBACK_UNAVAILABLE": 86,
    "TOKEN_UNAVAILABLE": 87,
    "API_FAILED": 88,
    "INTERNAL": 89,
    "IMAGE_TAG_EXISTS": 90,
}

AR_REPOSITORY = "castor-docker-repo"
GIT_SERVER = "castor-git-server"
TERRAFORM_SERVER = "mcp-terraform-server"
TF_APPLIER = "tf-applier"
GATEWAY = "orchestrator-gateway-service"
STAGE_RUNNER = "stage-runner"   # STAGE-JOB-RUNNER: runs the gateway's image
QA_JOB = "qa-sandbox-test-runner"
QA_LABEL_KEY, QA_LABEL_VALUE = "stackvend-qa-job-contract", "1"   # parity: scripts/common/components.sh
HTTP_TIMEOUT = 30
METADATA = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default"
_HEX = frozenset("0123456789abcdef")


class StageError(Exception):
    def __init__(self, code: str, message: str, component: str = ""):
        if code not in FAIL_CODES:
            code, message = "INTERNAL", f"unknown code {code!r}: {message}"
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.component = code, message, component


# ------------------------------------------------------------------------------------------------ HTTP
Http = Callable[..., Tuple[int, Any, Dict[str, str]]]


def _metadata(path: str) -> str:
    req = urllib.request.Request(f"{METADATA}/{path}", headers={"Metadata-Flavor": "Google"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.read().decode("utf-8")
    except (urllib.error.URLError, OSError) as e:
        raise StageError("TOKEN_UNAVAILABLE", f"metadata server: {type(e).__name__}") from None


def access_token() -> str:
    try:
        token = json.loads(_metadata("token")).get("access_token")
    except ValueError:
        token = None
    if not isinstance(token, str) or not token:
        raise StageError("TOKEN_UNAVAILABLE", "the metadata server returned no access token")
    return token


def id_token(audience: str) -> str:
    token = _metadata("identity?audience=" + urllib.parse.quote(audience, safe="") + "&format=full").strip()
    if not token or token.count(".") != 2:
        raise StageError("TOKEN_UNAVAILABLE", "the metadata server returned no ID token")
    return token


def make_http(token: str, project: str = "") -> Http:
    def call(method: str, url: str, body: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None
             ) -> Tuple[int, Any, Dict[str, str]]:
        h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        if project:
            h["X-Goog-User-Project"] = project
        h.update(headers or {})
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                raw, status, rh = resp.read(), resp.status, dict(resp.headers.items())
        except urllib.error.HTTPError as e:
            raw, status, rh = e.read(), e.code, dict(e.headers.items()) if e.headers else {}
        except (urllib.error.URLError, OSError) as e:
            raise StageError("API_FAILED", f"{method} {url.split('?')[0]}: {type(e).__name__}") from None
        try:
            data = json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            data = None
        return status, data, {k.lower(): v for k, v in rh.items()}
    return call


def _run_v1(region: str, path: str) -> str:
    return f"https://{region}-run.googleapis.com/apis/{path}"


def _get(http: Http, url: str, what: str, component: str = "") -> Optional[Dict[str, Any]]:
    status, body, _ = http("GET", url)
    if status == 404:
        return None
    if status != 200 or not isinstance(body, dict):
        raise StageError("API_FAILED", f"could not read {what} (HTTP {status})", component)
    return body


def get_service(http: Http, project: str, region: str, name: str) -> Optional[Dict[str, Any]]:
    return _get(http, _run_v1(region, f"serving.knative.dev/v1/namespaces/{project}/services/{name}"),
                f"service {name}", name)


def get_revision(http: Http, project: str, region: str, name: str) -> Optional[Dict[str, Any]]:
    return _get(http, _run_v1(region, f"serving.knative.dev/v1/namespaces/{project}/revisions/{name}"),
                f"revision {name}")


def get_service_v2(http: Http, project: str, region: str, name: str) -> Optional[Dict[str, Any]]:
    """The Run Admin API v2 service (typed fields such as `ingress`; the v1 form keeps it in an annotation)."""
    return _get(http, f"https://run.googleapis.com/v2/projects/{project}/locations/{region}/services/{name}",
                f"service {name} (v2)", name)


def service_ingress(svc_v2: Any, name: str) -> str:
    """The typed v2 `ingress` enum: INGRESS_TRAFFIC_ALL or one of INTERNAL_INGRESS. Absent, not a string or any other
    value: an answer we cannot read -> API_FAILED (never guessed as public or internal)."""
    ingress = svc_v2.get("ingress") if isinstance(svc_v2, dict) else None
    if not isinstance(ingress, str) or not ingress:
        raise StageError("API_FAILED", f"service {name} has no typed ingress field in the Run Admin API", name)
    if ingress != INGRESS_ALL and ingress not in INTERNAL_INGRESS:
        raise StageError("API_FAILED", f"service {name} has an unknown ingress {ingress!r}", name)
    return ingress


def get_job(http: Http, project: str, region: str, name: str) -> Optional[Dict[str, Any]]:
    return _get(http, _run_v1(region, f"run.googleapis.com/v1/namespaces/{project}/jobs/{name}"), f"job {name}", name)


def _dig(doc: Any, *path: Any) -> Any:
    for p in path:
        if isinstance(p, int):
            if not isinstance(doc, list) or len(doc) <= p:
                return None
        elif not isinstance(doc, dict):
            return None
        doc = doc[p] if isinstance(p, int) else doc.get(p)
    return doc


def service_runtime_sa(svc: Dict[str, Any]) -> Optional[str]:
    return _dig(svc, "spec", "template", "spec", "serviceAccountName")


def job_runtime_sa(job: Dict[str, Any]) -> Optional[str]:
    return _dig(job, "spec", "template", "spec", "template", "spec", "serviceAccountName")


def job_image(job: Dict[str, Any]) -> Optional[str]:
    return _dig(job, "spec", "template", "spec", "template", "spec", "containers", 0, "image")


def job_labels(job: Dict[str, Any]) -> Dict[str, str]:
    labels = _dig(job, "metadata", "labels")
    return labels if isinstance(labels, dict) else {}


def is_digest_ref(image: Any) -> bool:
    if not isinstance(image, str):
        return False
    repository, sep, digest = image.rpartition("@sha256:")
    return bool(repository) and sep == "@sha256:" and len(digest) == 64 and set(digest) <= _HEX


def registry_host(region: str) -> str:
    return f"{region}-docker.pkg.dev"


def in_project_registry(image: str, project: str, region: str) -> bool:
    """`<region>-docker.pkg.dev/<project>/castor-docker-repo/<name>@sha256:<digest>`: the platform repository only
    (exact path structure; plan RT 11-02 code review M-D), never another repository of the project."""
    repository, _, _ = image.rpartition("@sha256:")
    parts = repository.split("/")
    return len(parts) >= 4 and parts[0] == registry_host(region) and parts[1] == project \
        and parts[2] == AR_REPOSITORY and all(parts[3:])


_MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json"])


def resolve_digest(http: Http, image: str) -> str:
    """Tag or digest reference -> `<repository>@sha256:<digest>` through the registry API (HEAD manifests; the
    Docker-Content-Digest header). Raises DIGEST_UNKNOWN."""
    if "@" in image:
        repository, reference = image.split("@", 1)
    else:
        slash = image.rfind("/")
        colon = image.rfind(":")
        repository, reference = (image[:colon], image[colon + 1:]) if colon > slash else (image, "latest")
    host, _, path = repository.partition("/")
    if not host or not path:
        raise StageError("DIGEST_UNKNOWN", f"{image} is not a registry image reference")
    status, _, headers = http("HEAD", f"https://{host}/v2/{path}/manifests/{reference}", None,
                              {"Accept": _MANIFEST_ACCEPT})
    digest = headers.get("docker-content-digest", "")
    if status != 200 or not digest.startswith("sha256:") or not is_digest_ref(f"{repository}@{digest}"):
        raise StageError("DIGEST_UNKNOWN", f"no digest for {image} (HTTP {status})")
    return f"{repository}@{digest}"


def _tag_ref(image: str) -> Tuple[str, str, str, str]:
    """`<host>/<path>:<tag>` -> (repository, host, path, tag); anything else (no tag, a digest) -> USAGE."""
    slash, colon = image.rfind("/"), image.rfind(":")
    if "@" in image or colon <= slash or any(c.isspace() for c in image):
        raise StageError("USAGE", f"{image} is not a tagged image reference")
    repository, tag = image[:colon], image[colon + 1:]
    host, _, path = repository.partition("/")
    if not host or not path or not tag:
        raise StageError("USAGE", f"{image} is not a registry image reference")
    return repository, host, path, tag


def require_tag_absent(http: Http, image: str) -> None:
    """FD-148 (attacker F2): the build's target tag must not exist yet (registry HEAD answers 404), so an image
    planted under that tag can never be taken for this build's. 200 -> IMAGE_TAG_EXISTS; anything else -> API_FAILED."""
    _repository, host, path, tag = _tag_ref(image)
    status, _, _headers = http("HEAD", f"https://{host}/v2/{path}/manifests/{tag}", None, {"Accept": _MANIFEST_ACCEPT})
    if status == 404:
        return
    if status == 200:
        raise StageError("IMAGE_TAG_EXISTS", f"{image} already exists in the registry before this build; nothing "
                         "was built (an image under this request's tag was not made by it)")
    raise StageError("API_FAILED", f"could not check that {image} does not exist yet (HTTP {status})")


def report_digest(report_path: str, image: str) -> str:
    """FD-148 (attacker F2): the digest pack itself exported (`--report-output-dir` -> report.toml, [image] digest),
    as `<repository>@sha256:<digest>`, only from a report whose [image] tags name exactly this image; the tag is never
    re-read from the registry. Raises DIGEST_UNKNOWN."""
    repository = _tag_ref(image)[0]
    try:
        import tomllib
    except ImportError:
        raise StageError("INTERNAL", "python3 3.11 or later (tomllib) is needed to read pack's report.toml") from None
    try:
        with open(report_path, "rb") as fh:
            doc = tomllib.load(fh)
    except (OSError, ValueError) as e:   # tomllib.TOMLDecodeError is a ValueError
        raise StageError("DIGEST_UNKNOWN", f"no readable pack report for {image} ({type(e).__name__})") from None
    section = doc.get("image") if isinstance(doc, dict) else None
    tags = section.get("tags") if isinstance(section, dict) else None
    if not isinstance(tags, list) or image not in tags:
        raise StageError("DIGEST_UNKNOWN", f"pack's report is not for {image} (its [image] tags do not name it)")
    digest = section.get("digest")
    ref = f"{repository}@{digest}" if isinstance(digest, str) else ""
    if not isinstance(digest, str) or not digest.startswith("sha256:") or not is_digest_ref(ref):
        raise StageError("DIGEST_UNKNOWN", f"pack's report for {image} has no sha256 image digest")
    return ref


# ------------------------------------------------------------------------------------------------ builder pins
def _semver3(value: Any) -> bool:
    parts = value.split(".") if isinstance(value, str) else []
    return len(parts) == 3 and all(p.isdigit() for p in parts)


def read_pins(doc: Any) -> Tuple[str, str, str, str, str, str]:
    """scripts/upgrade/builder-pins.json -> (pack version, pack linux tarball sha256, default builder, QA builder,
    default run image, lifecycle image). Every image must be a digest reference (never a floating tag); an empty,
    missing or tag-only pin -> BUILDER_PIN_MISSING (nothing is built, nothing is deployed). FD-148 builder parity: the
    run image (every build) is the one `gcloud run deploy --source` builds use (the builder's own default run image
    is a different one); the lifecycle image is what pack runs for an untrusted builder (otherwise pulled by tag)."""
    pack = doc.get("pack") if isinstance(doc, dict) else None
    builders = doc.get("builders") if isinstance(doc, dict) else None
    run_images = doc.get("run_images") if isinstance(doc, dict) else None
    lifecycle = doc.get("lifecycle") if isinstance(doc, dict) else None
    if not all(isinstance(s, dict) for s in (pack, builders, run_images, lifecycle)):
        raise StageError("BUILDER_PIN_MISSING",
                         "builder-pins.json has no pack / builders / run_images / lifecycle section")
    version, sha = pack.get("version"), pack.get("linux_amd64_sha256")
    if not _semver3(version):
        raise StageError("BUILDER_PIN_MISSING", "builder-pins.json pack.version must be MAJOR.MINOR.PATCH")
    if not (isinstance(sha, str) and len(sha) == 64 and set(sha) <= _HEX):
        raise StageError("BUILDER_PIN_MISSING", "builder-pins.json pack.linux_amd64_sha256 must be 64 hex")
    if not _semver3(lifecycle.get("version")):
        raise StageError("BUILDER_PIN_MISSING", "builder-pins.json lifecycle.version must be MAJOR.MINOR.PATCH")
    default, qa = builders.get("default"), builders.get(QA_JOB)
    run_default, lifecycle_image = run_images.get("default"), lifecycle.get("image")
    for key, ref in (("builders.default", default), (f"builders.{QA_JOB}", qa), ("run_images.default", run_default),
                     ("lifecycle.image", lifecycle_image)):
        # no whitespace: build.sh reads the six values as one space-separated line
        if not is_digest_ref(ref) or any(c.isspace() for c in ref):
            raise StageError("BUILDER_PIN_MISSING", f"builder-pins.json {key} must be an image@sha256 digest")
    return version, sha, default, qa, run_default, lifecycle_image


# ------------------------------------------------------------------------------------------------ components
def parse_components(items: List[str]) -> List[Tuple[str, str]]:
    out = []
    for item in items:
        name, _, kind = item.partition(":")
        kind = kind.split(":")[0]
        if not name or kind not in ("service", "job"):
            raise StageError("USAGE", f"component {item!r} is not NAME:service|job")
        out.append((name, kind))
    return out


def preflight(http: Http, project: str, region: str, components: List[Tuple[str, str]]) -> Dict[str, Any]:
    """plan §3.4.2 readiness preflight: typed API reads, nothing guessed."""
    if _get(http, f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{region}/repositories/"
                  f"{AR_REPOSITORY}", f"Artifact Registry repository {AR_REPOSITORY}") is None:
        raise StageError("PLATFORM_NOT_READY", f"Artifact Registry repository {AR_REPOSITORY} does not exist",
                         "artifact-registry")
    ready, skipped = [], []
    for name, kind in components:
        doc = get_service(http, project, region, name) if kind == "service" else get_job(http, project, region, name)
        if doc is None:
            if name == GIT_SERVER:
                skipped.append(name)   # the Serverless Git server is optional (deploy-services.sh skips it too)
                continue
            raise StageError("PLATFORM_NOT_READY", f"{kind} {name} does not exist; this release needs "
                             "`apply.sh apply` first", name)
        sa = service_runtime_sa(doc) if kind == "service" else job_runtime_sa(doc)
        if not isinstance(sa, str) or "@" not in sa:
            raise StageError("PLATFORM_NOT_READY", f"{name} has no runtime service account set by Terraform", name)
        status, body, _ = http("POST", f"https://iam.googleapis.com/v1/projects/-/serviceAccounts/{sa}:testIamPermissions",
                               json.dumps({"permissions": ["iam.serviceAccounts.actAs"]}).encode("utf-8"))
        if status != 200 or not isinstance(body, dict):
            raise StageError("PLATFORM_NOT_READY", f"cannot check the act-as right on {sa} (HTTP {status})", name)
        if "iam.serviceAccounts.actAs" not in (body.get("permissions") or []):
            raise StageError("PLATFORM_NOT_READY", f"the upgrader may not act as {sa}; this release needs "
                             "`apply.sh apply` first", name)
        if name == GIT_SERVER:
            _git_server_volume(doc, project)
        ready.append(name)
    return {"ready": ready, "skipped": skipped}


def _git_server_volume(svc: Dict[str, Any], project: str) -> None:
    """The deploy-services.sh git server preflight, as typed fields: gen2, the git-storage GCS FUSE volume on
    castor-git-repos-<project>, mounted at /data/git."""
    tmpl = _dig(svc, "spec", "template") or {}
    ann = _dig(tmpl, "metadata", "annotations") or {}
    vols = [v for v in (_dig(tmpl, "spec", "volumes") or []) if isinstance(v, dict) and v.get("name") == "git-storage"]
    csi = (vols[0].get("csi") or {}) if vols else {}
    mounts = [m for c in (_dig(tmpl, "spec", "containers") or []) if isinstance(c, dict)
              for m in (c.get("volumeMounts") or []) if isinstance(m, dict)
              and m.get("name") == "git-storage" and m.get("mountPath") == "/data/git"]
    if ann.get("run.googleapis.com/execution-environment") != "gen2" or csi.get("driver") != "gcsfuse.run.googleapis.com" \
            or (csi.get("volumeAttributes") or {}).get("bucketName") != f"castor-git-repos-{project}" or not mounts:
        raise StageError("PLATFORM_NOT_READY", "castor-git-server is not on its GCS FUSE volume; run `apply.sh apply` "
                         "first", GIT_SERVER)


def snapshot(http: Http, project: str, region: str, components: List[Tuple[str, str]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for name, kind in components:
        if kind == "service":
            svc = get_service(http, project, region, name)
            revision = _dig(svc, "status", "latestReadyRevisionName") if svc else None
            if not isinstance(revision, str) or not revision:
                out[name] = {"kind": kind, "available": False, "reason": "no ready revision"}
                continue
            rev = get_revision(http, project, region, revision)
            digest = _dig(rev, "status", "imageDigest")
            out[name] = {"kind": kind, "revision": revision, "image": digest if is_digest_ref(digest) else None,
                         "available": True}
            continue
        job = get_job(http, project, region, name)
        image = job_image(job) if job else None
        if is_digest_ref(image):
            out[name] = {"kind": kind, "image": image, "available": True}
            continue
        if isinstance(image, str) and image:
            try:   # M-3: a job deployed by tag (trigger installs) -> resolve the tag to a digest now, before the deploy
                out[name] = {"kind": kind, "image": resolve_digest(http, image), "available": True, "was_tag": image}
            except StageError as e:
                out[name] = {"kind": kind, "available": False, "reason": e.message}
            continue
        out[name] = {"kind": kind, "available": False, "reason": "no container image"}
    return out


def _ready(svc: Dict[str, Any]) -> bool:
    for c in _dig(svc, "status", "conditions") or []:
        if isinstance(c, dict) and c.get("type") == "Ready":
            return c.get("status") == "True"
    return False


def check(http: Http, project: str, region: str, deployed: Dict[str, Any]) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for name, d in sorted(deployed.items()):
        want = d.get("image")
        if d.get("kind") == "service":
            svc = get_service(http, project, region, name) or {}
            latest = _dig(svc, "status", "latestReadyRevisionName")
            created = _dig(svc, "status", "latestCreatedRevisionName")
            rev = get_revision(http, project, region, latest) if isinstance(latest, str) and latest else None
            digest = _dig(rev, "status", "imageDigest")
            ok = _ready(svc) and latest == created and isinstance(digest, str) and _same_digest(digest, want)
            results[name] = {"ok": ok, "revision": latest, "image": digest,
                             "reason": "" if ok else "the newest revision is not Ready with the deployed image"}
        else:
            job = get_job(http, project, region, name) or {}
            image = job_image(job)
            ok = isinstance(image, str) and _same_digest(image, want)
            reason = "" if ok else "the job does not carry the deployed image"
            if ok and name == QA_JOB and job_labels(job).get(QA_LABEL_KEY) != QA_LABEL_VALUE:
                ok, reason = False, f"the QA job has no {QA_LABEL_KEY}={QA_LABEL_VALUE} label"
            results[name] = {"ok": ok, "image": image, "reason": reason}
    for job, service in ((TF_APPLIER, TERRAFORM_SERVER), (STAGE_RUNNER, GATEWAY)):
        if job in deployed and service in deployed:
            if not _same_digest(deployed[job].get("image"), deployed[service].get("image")):
                results[job] = {"ok": False, "image": deployed[job].get("image"),
                                "reason": f"{job} does not run the {service} image"}
    return results


def _same_digest(a: Any, b: Any) -> bool:
    return is_digest_ref(a) and is_digest_ref(b) and a.rpartition("@sha256:")[2] == b.rpartition("@sha256:")[2]


# The Cloud Run Admin API v2 `ingress` enum: the one public value and the values an outside caller cannot reach.
# Anything else (UNSPECIFIED, a future value) is an answer we cannot read -> API_FAILED, never guessed.
INGRESS_ALL = "INGRESS_TRAFFIC_ALL"
INTERNAL_INGRESS = frozenset({"INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
                              "INGRESS_TRAFFIC_NONE"})
# What happens instead (apps/control-center/routes/platform_upgrade.py cc_terraform_ready_for): when Settings ▸
# Upgrades shows a finished upgrade whose check is NOT_CHECKED, the Control Center asks /validate/ready itself.
CC_CHECK = ("the Control Center checks /validate/ready with its own identity when Settings ▸ Upgrades shows this "
            "finished upgrade")


def terraform_ready(http_id: Callable[[str], Tuple[int, Any]], service_url: str, attempts: int = 20,
                    wait_s: int = 30, *, ingress: str) -> Dict[str, Any]:
    """GET /validate/ready (the canary rule: a healthy terraform server is not a working one).

    `ingress` is the server's typed Run Admin API v2 ingress. INTERNAL_INGRESS: the upgrader (Cloud Build, never an
    internal source) cannot reach it -> NOT_CHECKED INGRESS_INTERNAL, no probe, never a pass. Not INGRESS_TRAFFIC_ALL
    either -> API_FAILED."""
    if ingress in INTERNAL_INGRESS:
        return {"state": "NOT_CHECKED", "reason": f"INGRESS_INTERNAL: the terraform server's ingress is {ingress}, "
                f"which the upgrader cannot reach; {CC_CHECK}"}
    if ingress != INGRESS_ALL:
        raise StageError("API_FAILED", f"the terraform server has an unknown ingress {ingress!r}", TERRAFORM_SERVER)
    last = ""
    for i in range(attempts):
        status, body = http_id(service_url.rstrip("/") + "/validate/ready")
        if status in (401, 403):
            return {"state": "NOT_CHECKED", "reason": f"HTTP {status}: the upgrader has no invoker right on the "
                    f"terraform server (by design); {CC_CHECK}"}
        if status == 200 and isinstance(body, dict) and body.get("ready") is True:
            return {"state": "READY"}
        last = f"HTTP {status}, ready={body.get('ready') if isinstance(body, dict) else None}"
        if i + 1 < attempts:
            time.sleep(wait_s)
    return {"state": "CHECK_FAILED", "reason": f"/validate/ready never answered ready ({last})"}


def rollback_plan(http: Http, project: str, region: str, previous: Dict[str, Any]) -> Dict[str, Any]:
    """Re-validate every rollback target against Cloud Run / Artifact Registry. The snapshot lives in the default
    Firestore database (writable by every agent identity), so it only NAMES a target; the image comes from Cloud Run
    (services) or must be an existing digest in this project's registry (jobs)."""
    targets, unavailable = {}, {}
    for name, p in sorted(previous.items()):
        if not isinstance(p, dict) or not p.get("available"):
            unavailable[name] = (p or {}).get("reason") or "no rollback target was recorded"
            continue
        if p.get("kind") == "service":
            revision = p.get("revision")
            rev = get_revision(http, project, region, revision) if isinstance(revision, str) and revision else None
            owner = _dig(rev, "metadata", "labels", "serving.knative.dev/service")
            digest = _dig(rev, "status", "imageDigest")
            if rev is None or owner != name or not is_digest_ref(digest):
                unavailable[name] = f"revision {revision!r} of {name} no longer exists or names no image"
                continue
            targets[name] = {"kind": "service", "image": digest, "revision": revision}
        elif p.get("kind") == "job":
            image = p.get("image")
            if not is_digest_ref(image) or not in_project_registry(image, project, region):
                unavailable[name] = f"the recorded image is not a digest in {AR_REPOSITORY} of this project"
                continue
            try:
                if resolve_digest(http, image) != image:
                    raise StageError("DIGEST_UNKNOWN", "digest mismatch")
            except StageError:
                unavailable[name] = f"{image} no longer exists in Artifact Registry"
                continue
            targets[name] = {"kind": "job", "image": image}
        else:
            unavailable[name] = "unknown component kind"
    return {"targets": targets, "unavailable": unavailable}


# ------------------------------------------------------------------------------------------------ CLI
def _write(path: str, doc: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, sort_keys=True, indent=1)
        fh.write("\n")


def _fail(e: StageError) -> int:
    comp = f" {e.component}" if e.component else ""
    print(f"stackvend-upgrade: FAILED {e.code}{comp}: {e.message}", file=sys.stderr)
    return FAIL_CODES[e.code]


def _id_http(audience_url: str) -> Callable[[str], Tuple[int, Any]]:
    token = id_token(audience_url)
    raw = make_http(token)

    def call(url: str) -> Tuple[int, Any]:
        status, body, _ = raw("GET", url)
        return status, body
    return call


def _no_probe(url: str) -> Tuple[int, Any]:
    raise StageError("INTERNAL", "an internal-only terraform server must not be probed", TERRAFORM_SERVER)


def main(argv: Optional[List[str]] = None, http_factory: Optional[Callable[[str], Http]] = None,
         id_http_factory: Optional[Callable[[str], Callable[[str], Tuple[int, Any]]]] = None) -> int:
    # SAT-48 review H-1: the upgrader identity's metadata token, without a quota-project header (a service account
    # bills its own project; the header would need serviceusage.services.use, which it lacks)
    http_factory = http_factory or (lambda project: make_http(access_token()))
    id_http_factory = id_http_factory or _id_http
    p = argparse.ArgumentParser(prog="stage.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("fields")
    s.add_argument("--verified", required=True)
    for name in ("preflight", "snapshot"):
        s = sub.add_parser(name)
        s.add_argument("--project", required=True)
        s.add_argument("--region", required=True)
        s.add_argument("--out", required=True)
        s.add_argument("components", nargs="+")
    s = sub.add_parser("docker-config")
    s.add_argument("--region", required=True)
    s.add_argument("--out", required=True)
    s = sub.add_parser("tag-absent")
    s.add_argument("--image", required=True)
    s = sub.add_parser("report-digest")
    s.add_argument("--report", required=True)
    s.add_argument("--image", required=True)
    s = sub.add_parser("check")
    for f in ("--project", "--region", "--deployed", "--out"):
        s.add_argument(f, required=True)
    s = sub.add_parser("ready")
    s.add_argument("--project", required=True)
    s.add_argument("--region", required=True)
    s.add_argument("--attempts", type=int, default=20)
    s = sub.add_parser("rollback-plan")
    for f in ("--project", "--region", "--previous", "--out"):
        s.add_argument(f, required=True)
    s = sub.add_parser("previous")
    for f in ("--project", "--request-id", "--out"):
        s.add_argument(f, required=True)
    s = sub.add_parser("pins")
    s.add_argument("--file", required=True)
    try:
        a = p.parse_args(argv)
    except SystemExit:
        return FAIL_CODES["USAGE"]
    try:
        if a.cmd == "fields":
            with open(a.verified, encoding="utf-8") as fh:
                v = json.load(fh)
            print(v["project"], v["region"], v["kind"], v["request_id"], v["release"], v["commit"][:12])
            return 0
        if a.cmd == "pins":
            with open(a.file, encoding="utf-8") as fh:
                print(" ".join(read_pins(json.load(fh))))
            return 0
        if a.cmd == "preflight":
            _write(a.out, preflight(http_factory(a.project), a.project, a.region, parse_components(a.components)))
            return 0
        if a.cmd == "snapshot":
            _write(a.out, snapshot(http_factory(a.project), a.project, a.region, parse_components(a.components)))
            return 0
        if a.cmd == "docker-config":
            auth = base64.b64encode(f"oauth2accesstoken:{access_token()}".encode()).decode()
            os.makedirs(a.out, exist_ok=True)
            path = os.path.join(a.out, "config.json")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump({"auths": {registry_host(a.region): {"auth": auth}}}, fh)
            return 0
        if a.cmd == "tag-absent":
            require_tag_absent(http_factory(""), a.image)
            return 0
        if a.cmd == "report-digest":
            print(report_digest(a.report, a.image))
            return 0
        if a.cmd == "check":
            with open(a.deployed, encoding="utf-8") as fh:
                deployed = json.load(fh)
            results = check(http_factory(a.project), a.project, a.region, deployed)
            _write(a.out, results)
            bad = sorted(n for n, r in results.items() if not r["ok"])
            if bad:
                raise StageError("CHECK_FAILED", "; ".join(f"{n}: {results[n]['reason']}" for n in bad), ",".join(bad))
            return 0
        if a.cmd == "ready":
            svc = get_service(http_factory(a.project), a.project, a.region, TERRAFORM_SERVER) or {}
            url = _dig(svc, "status", "url")
            if not isinstance(url, str) or not url.startswith("https://"):
                raise StageError("CHECK_FAILED", "mcp-terraform-server has no URL", TERRAFORM_SERVER)
            svc2 = get_service_v2(http_factory(a.project), a.project, a.region, TERRAFORM_SERVER)
            if svc2 is None:
                raise StageError("CHECK_FAILED", "mcp-terraform-server is not in the Run Admin API v2", TERRAFORM_SERVER)
            ingress = service_ingress(svc2, TERRAFORM_SERVER)
            # internal-only: no ID token is minted and no HTTP probe is sent (terraform_ready returns before calling)
            http_id = id_http_factory(url) if ingress == INGRESS_ALL else _no_probe
            res = terraform_ready(http_id, url, attempts=max(1, a.attempts), ingress=ingress)
            print(res["state"] + (f": {res['reason']}" if res.get("reason") else ""))
            if res["state"] == "CHECK_FAILED":
                raise StageError("CHECK_FAILED", res["reason"], TERRAFORM_SERVER)
            return 0
        if a.cmd == "rollback-plan":
            with open(a.previous, encoding="utf-8") as fh:
                previous = json.load(fh)
            if not isinstance(previous, dict):
                raise StageError("ROLLBACK_UNAVAILABLE", "the previous snapshot is not an object")
            _write(a.out, rollback_plan(http_factory(a.project), a.project, a.region, previous))
            return 0
        if a.cmd == "previous":
            if not (len(a.request_id) == 32 and set(a.request_id) <= _HEX):
                raise StageError("USAGE", "the request id is not 32 hex characters")
            http = http_factory(a.project)
            url = (f"https://firestore.googleapis.com/v1/projects/{a.project}/databases/(default)/documents/"
                   f"platform_upgrades_progress/{a.request_id}")
            doc = _get(http, url, f"the progress record of {a.request_id}")
            prev = _firestore_field(doc, "previous") if doc else None
            if not isinstance(prev, dict) or not prev:
                raise StageError("ROLLBACK_UNAVAILABLE", f"upgrade {a.request_id} recorded no previous state")
            _write(a.out, prev)
            return 0
    except StageError as e:
        return _fail(e)
    except (OSError, ValueError, KeyError, TypeError) as e:
        return _fail(StageError("INTERNAL", f"{a.cmd}: {type(e).__name__}: {e}"))
    return FAIL_CODES["USAGE"]


def _from_value(v: Dict[str, Any]) -> Any:
    if "nullValue" in v:
        return None
    for k, conv in (("booleanValue", bool), ("integerValue", int), ("doubleValue", float), ("stringValue", str),
                    ("timestampValue", str)):
        if k in v:
            return conv(v[k])
    if "mapValue" in v:
        return {k: _from_value(x) for k, x in (v["mapValue"].get("fields") or {}).items()}
    if "arrayValue" in v:
        return [_from_value(x) for x in (v["arrayValue"].get("values") or [])]
    raise ValueError("unsupported Firestore value")


def _firestore_field(doc: Dict[str, Any], name: str) -> Any:
    field = (doc.get("fields") or {}).get(name)
    return _from_value(field) if isinstance(field, dict) else None


if __name__ == "__main__":
    sys.exit(main())

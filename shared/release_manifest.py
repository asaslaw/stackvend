"""
StackVend releases: component list, SemVer, `release-manifest.json`, the `apply.sh` guard and the Cloud Run reads
behind the deployed version record (FD-7C P3a; plan docs/planning/self-upgrade-plan.md §3.2, §3.4, §3.11).

Used by `scripts/common/release_record.py` (writes `system_config/platform_release` after a deploy),
`scripts/release/check_manifest.py` (release-time rules) and the Control Center's Settings ▸ Upgrades
(`apps/control-center/routes/platform_release.py`, through the vendored copy in `apps/control-center/shared/`).

Rules:
- Exact parsing only: SemVer 2.0 by its grammar, the manifest by an exact key set and exact JSON types, typed Cloud Run
  API fields. No prose is parsed and nothing is guessed.
- Platform stamp (FD-4DA-STAMP, live since 11-01; supersedes SELFUP-A-STAMP): every install's `apply.sh` /
  bootstrap writes it (from `STAMP_FIRST_RELEASE`, the first release), so a missing stamp is always "platform release
  unknown" (PLATFORM_STAMP_UNKNOWN, fail closed; SELFUP-STAMP-RETIRE). Nothing here writes a stamp.
Standard library only.
"""

from __future__ import annotations

import json
import string
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

# The official StackVend repository (the FD-4BF public slug); the default release source.
OFFICIAL_RELEASE_REPOSITORY = "asaslaw/stackvend"
# The first release whose `apply.sh` writes the stamp (FD-4DA-STAMP shipped in 0.9.0-preview: review BL-1). Every
# release is stamped, so there is no "assumed" platform release (code review L-1 removed it).
STAMP_FIRST_RELEASE = "0.9.0-preview"
# plan §3.4.3: service-level annotations on the Control Center's Cloud Run service, owned by core Terraform.
STAMP_RELEASE_ANNOTATION = "stackvend/platform-release"
STAMP_COMMIT_ANNOTATION = "stackvend/platform-commit"
CONTROL_CENTER_SERVICE = "product-control-center-ui"

# (Cloud Run name, kind, source directory): the components scripts/deploy-services.sh deploys (same order as its
# SERVICES / JOBS arrays; parity test), plus tf-applier, which runs the mcp-terraform-server image, and stage-runner
# (STAGE-JOB-RUNNER), which runs the orchestrator-gateway image. The git server is first: it deploys before its clients
# (row GIT-404-TYPED).
COMPONENTS: Tuple[Tuple[str, str, str], ...] = (
    ("castor-git-server", "service", "apps/git-server"),
    ("product-control-center-ui", "service", "apps/control-center"),
    ("orchestrator-gateway-service", "service", "apps/orchestrator-gateway"),
    ("project-repo-vending-service", "service", "apps/project-vending"),
    ("log-sre-sentinel-service", "service", "apps/log-sre-sentinel"),
    ("spec-ingestion-service", "service", "apps/spec-ingestion"),
    ("mcp-terraform-server", "service", "mcp-servers/terraform"),
    ("mcp-gcloud-server", "service", "mcp-servers/gcloud"),
    ("mcp-github-toolserver", "service", "mcp-servers/github"),
    ("mcp-workspace-connector", "service", "mcp-servers/workspace"),
    ("mcp-infracost-server", "service", "mcp-servers/infracost"),
    ("mcp-compliance-server", "service", "mcp-servers/compliance"),
    ("mcp-kubernetes-server", "service", "mcp-servers/kubernetes"),
    ("mcp-agent-builder-server", "service", "mcp-servers/agent-builder"),
    ("github-refactor-scanner-job", "job", "apps/refactor-scanner"),
    ("qa-sandbox-test-runner", "job", "apps/qa-runner"),
    ("finops-budget-enforcer-job", "job", "apps/finops-enforcer"),
    ("infra-rollback-job", "job", "apps/infra-rollback"),
    ("sandbox-garbage-collector-job", "job", "apps/sandbox-cleaner"),
    ("sre-telemetry-digest-job", "job", "apps/sre-digest"),
    ("finops-spend-sync-job", "job", "apps/finops-spend-sync"),
    ("sandbox-workload-sweeper-job", "job", "apps/sandbox-sweeper"),
    ("billing-alert-drain-job", "job", "apps/billing-alert-drain"),
    ("tf-applier", "job", "mcp-servers/terraform"),
    ("stage-runner", "job", "apps/orchestrator-gateway"),
)
COMPONENT_KINDS = {name: kind for name, kind, _ in COMPONENTS}

HISTORY_LIMIT = 20  # OQ-12c Q13 (plan recommendation, listed in the SAT-11 brief): last 20 deploys
RECORD_COLLECTION = "system_config"
RECORD_DOCUMENT = "platform_release"


# ------------------------------------------------------------------------------------------------ SemVer 2.0
_ALNUM_HYPHEN = frozenset(string.ascii_letters + string.digits + "-")


@dataclass(frozen=True)
class SemVer:
    major: int
    minor: int
    patch: int
    prerelease: Tuple[str, ...] = ()

    def __str__(self) -> str:
        core = f"{self.major}.{self.minor}.{self.patch}"
        return core + ("-" + ".".join(self.prerelease) if self.prerelease else "")

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def key(self) -> Tuple:
        """Sort key with SemVer 2.0 §11 precedence (a pre-release sorts before its release)."""
        # numeric identifiers sort before alphanumeric ones; a shorter identifier list sorts first (tuple order)
        pre = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.prerelease)
        return (self.major, self.minor, self.patch, 0 if self.prerelease else 1, pre)


def _numeric(part: str) -> bool:
    return bool(part) and part.isascii() and part.isdigit() and not (len(part) > 1 and part[0] == "0")


def parse_semver(text: Any) -> Optional[SemVer]:
    """`MAJOR.MINOR.PATCH[-PRE]` by the SemVer 2.0 grammar (build metadata refused: releases never carry it)."""
    if not isinstance(text, str) or not text or len(text) > 64 or text != text.strip():
        return None
    core, sep, pre = text.partition("-")
    parts = core.split(".")
    if len(parts) != 3 or not all(_numeric(p) for p in parts):
        return None
    ids: Tuple[str, ...] = ()
    if sep:
        ids = tuple(pre.split("."))
        for ident in ids:
            if not ident or not set(ident) <= _ALNUM_HYPHEN or not ident.isascii():
                return None
            if ident.isdigit() and not _numeric(ident):
                return None
    return SemVer(int(parts[0]), int(parts[1]), int(parts[2]), ids)


def parse_release_tag(tag: Any) -> Optional[SemVer]:
    """A release tag is exactly `v` + SemVer (`v0.9.3`, `v0.9.3-preview`, `v1.0.0-rc.1`)."""
    if not isinstance(tag, str) or not tag.startswith("v"):
        return None
    return parse_semver(tag[1:])


def compare(a: SemVer, b: SemVer) -> int:
    ka, kb = a.key(), b.key()
    return (ka > kb) - (ka < kb)


# ------------------------------------------------------------------------------------------------ repository names
_OWNER_CHARS = frozenset(string.ascii_letters + string.digits + "-")
_REPO_CHARS = frozenset(string.ascii_letters + string.digits + "._-")


def is_valid_repository(slug: Any) -> bool:
    """GitHub `owner/repo`: owner 1-39 of [A-Za-z0-9-] (no leading/trailing hyphen), repo 1-100 of [A-Za-z0-9._-],
    not `.` / `..`."""
    if not isinstance(slug, str) or slug.count("/") != 1:
        return False
    owner, repo = slug.split("/")
    if not (1 <= len(owner) <= 39) or not set(owner) <= _OWNER_CHARS or owner[0] == "-" or owner[-1] == "-":
        return False
    if not (1 <= len(repo) <= 100) or not set(repo) <= _REPO_CHARS or repo in (".", ".."):
        return False
    return owner.isascii() and repo.isascii()


def repository_from_remote_url(url: Any) -> Optional[str]:
    """`owner/repo` only for the two exact github.com URL forms (`https://github.com/<o>/<r>[.git]`,
    `git@github.com:<o>/<r>[.git]`); anything else is None."""
    if not isinstance(url, str):
        return None
    for prefix in ("https://github.com/", "git@github.com:"):
        if url.startswith(prefix):
            rest = url[len(prefix):]
            if rest.endswith(".git"):
                rest = rest[:-4]
            return rest if is_valid_repository(rest) else None
    return None


# ------------------------------------------------------------------------------------------------ release manifest
MANIFEST_FILE = "release-manifest.json"
MANIFEST_SCHEMA_VERSIONS = frozenset({1})
MANIFEST_MAX_BYTES = 4096
_MANIFEST_FIELDS = {"schema_version": int, "release": str, "requires_apply_sh": bool, "min_platform_release": str}


@dataclass(frozen=True)
class Manifest:
    release: SemVer
    requires_apply_sh: bool
    min_platform_release: SemVer


class ManifestError(ValueError):
    """code: MANIFEST_INVALID | MANIFEST_UNSUPPORTED."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def parse_manifest(raw: Any) -> Manifest:
    """Strict parser (plan §3.4.1): bytes / str / an already-decoded object; exact key set, exact JSON types."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > MANIFEST_MAX_BYTES:
            raise ManifestError("MANIFEST_INVALID", "larger than 4096 bytes")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ManifestError("MANIFEST_INVALID", "not UTF-8") from None
    if isinstance(raw, str):
        if len(raw) > MANIFEST_MAX_BYTES:
            raise ManifestError("MANIFEST_INVALID", "larger than 4096 bytes")
        try:
            raw = json.loads(raw)
        except ValueError:
            raise ManifestError("MANIFEST_INVALID", "not JSON") from None
    if not isinstance(raw, dict):
        raise ManifestError("MANIFEST_INVALID", "not a JSON object")
    schema = raw.get("schema_version")
    if type(schema) is int and schema not in MANIFEST_SCHEMA_VERSIONS:
        raise ManifestError("MANIFEST_UNSUPPORTED", f"schema_version {schema} (supported: 1)")
    if set(raw) != set(_MANIFEST_FIELDS):
        extra, missing = sorted(set(raw) - set(_MANIFEST_FIELDS)), sorted(set(_MANIFEST_FIELDS) - set(raw))
        raise ManifestError("MANIFEST_INVALID", f"keys: unknown {extra}, missing {missing}")
    for key, typ in _MANIFEST_FIELDS.items():
        if type(raw[key]) is not typ:
            raise ManifestError("MANIFEST_INVALID", f"{key} must be a JSON {typ.__name__}")
    release, minimum = parse_semver(raw["release"]), parse_semver(raw["min_platform_release"])
    if release is None:
        raise ManifestError("MANIFEST_INVALID", "release is not a SemVer version")
    if minimum is None:
        raise ManifestError("MANIFEST_INVALID", "min_platform_release is not a SemVer version")
    return Manifest(release, raw["requires_apply_sh"], minimum)


def manifest_rule_errors(m: Manifest) -> List[str]:
    """The release rules of plan §3.4.1 that need only the manifest."""
    errors = []
    if compare(m.min_platform_release, m.release) > 0:
        errors.append("min_platform_release is newer than release")
    same = compare(m.min_platform_release, m.release) == 0
    if m.requires_apply_sh != same:
        errors.append("requires_apply_sh must be true exactly when min_platform_release == release")
    return errors


# ------------------------------------------------------------------------------------------------ apply.sh guard
ALLOW = "ALLOW"
NEEDS_APPLY_SH = "NEEDS_APPLY_SH"
PLATFORM_STAMP_UNKNOWN = "PLATFORM_STAMP_UNKNOWN"


@dataclass(frozen=True)
class PlatformStamp:
    """What the Control Center service's annotations say (both None: no stamp)."""
    release: Optional[str] = None
    commit: Optional[str] = None

    @property
    def present(self) -> bool:
        return self.release is not None or self.commit is not None

    @property
    def dirty(self) -> bool:
        return isinstance(self.commit, str) and self.commit.endswith("+dirty")


@dataclass(frozen=True)
class GuardDecision:
    decision: str
    platform_release: Optional[str]
    assumed: bool  # always False since SELFUP-STAMP-RETIRE (kept so callers' field reads stay valid)
    warnings: Tuple[str, ...] = ()


def platform_release_for(stamp: PlatformStamp, installed_services: Optional[SemVer] = None) -> Tuple[Optional[SemVer], bool, Optional[str]]:
    """(platform release, assumed, error) per plan §3.4.2. A missing or unparseable stamp is unknown (fail closed;
    SELFUP-STAMP-RETIRE): every release writes one. `assumed` is always False and `installed_services` is unused; both
    stay so the signature other callers use does not change."""
    if stamp.present:
        parsed = parse_semver(stamp.release)
        return (parsed, False, None) if parsed else (None, False, "platform stamp release is not a SemVer version")
    return None, False, (f"no platform stamp (every install from release {STAMP_FIRST_RELEASE} on has one: "
                         "run scripts/apply.sh apply)")


def guard_decision(stamp: PlatformStamp, target: Manifest, installed_services: Optional[SemVer] = None) -> GuardDecision:
    """Can the services of `target` run on this platform without `apply.sh`? (display in P3a; the build decides in P3b)"""
    platform, _assumed, error = platform_release_for(stamp, installed_services)
    if platform is None:
        return GuardDecision(PLATFORM_STAMP_UNKNOWN, None, False, (error or "platform release unknown",))
    warnings = ("platform stamp is +dirty: apply.sh ran from a modified checkout",) if stamp.dirty else ()
    decision = ALLOW if compare(platform, target.min_platform_release) >= 0 else NEEDS_APPLY_SH
    return GuardDecision(decision, str(platform), False, warnings)


# ------------------------------------------------------------------------------------------------ Cloud Run reads
class ComponentReadError(Exception):
    """code: NOT_DEPLOYED | READ_FAILED | BAD_RESPONSE."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


GetJson = Callable[[str], Tuple[int, Any]]


def _run_v1(region: str, path: str) -> str:
    return f"https://{region}-run.googleapis.com/apis/{path}"


_DIGEST_SEPARATOR = "@sha256:"
_HEX = frozenset("0123456789abcdef")


def is_digest_reference(image: str) -> bool:
    """`<repository>@sha256:<64 lowercase hex>`: an image reference that names exactly one image. A tag reference
    (`...:latest`, `...:v1`) is mutable: a later deploy that reuses the tag changes what it means."""
    repository, sep, digest = image.rpartition(_DIGEST_SEPARATOR)
    return bool(repository) and sep == _DIGEST_SEPARATOR and len(digest) == 64 and set(digest) <= _HEX


IMAGE_DIGEST, IMAGE_TAG = "DIGEST", "TAG"


def classify_image(image: Any) -> Optional[str]:
    """Image reference grammar `name[:tag][@digest]`: IMAGE_DIGEST for a valid `@sha256:` digest reference, IMAGE_TAG
    for a reference without a digest part (`name` or `name:tag`; mutable, so it cannot be verified), None when the
    field is missing, empty, holds whitespace, or has a digest part that is not a valid sha256 digest (malformed)."""
    if not isinstance(image, str) or not image or any(c.isspace() for c in image):
        return None
    if is_digest_reference(image):
        return IMAGE_DIGEST
    return None if "@" in image else IMAGE_TAG


def _get(get_json: GetJson, url: str, what: str) -> Mapping[str, Any]:
    try:
        status, body = get_json(url)
    except Exception as e:  # noqa: BLE001 - typed below, never a made-up value
        raise ComponentReadError("READ_FAILED", f"{what}: {type(e).__name__}: {e}") from None
    if status == 404:
        raise ComponentReadError("NOT_DEPLOYED", f"{what} does not exist")
    if status != 200:
        raise ComponentReadError("READ_FAILED", f"{what}: HTTP {status}")
    if not isinstance(body, dict):
        raise ComponentReadError("BAD_RESPONSE", f"{what}: not a JSON object")
    return body


def read_component(get_json: GetJson, project: str, region: str, name: str, kind: str) -> Dict[str, Any]:
    """The image a component runs, from the Cloud Run Admin API (v1 resource shapes, typed fields only):
    service -> status.latestReadyRevisionName -> that revision's status.imageDigest (the resolved digest);
    job -> spec.template.spec.template.spec.containers[0].image; a tag image (no digest part) is returned as
    `image_tag` with `image_digest` None (it cannot be verified). Also the service-level annotations (platform stamp).
    The deploy script and the Control Center both read through this function, so the two always compare like for like."""
    if kind == "service":
        svc = _get(get_json, _run_v1(region, f"serving.knative.dev/v1/namespaces/{project}/services/{name}"),
                   f"service {name}")
        status = svc.get("status") if isinstance(svc.get("status"), dict) else {}
        revision = status.get("latestReadyRevisionName")
        if not isinstance(revision, str) or not revision:
            raise ComponentReadError("BAD_RESPONSE", f"service {name}: no ready revision")
        rev = _get(get_json, _run_v1(region, f"serving.knative.dev/v1/namespaces/{project}/revisions/{revision}"),
                   f"revision {revision}")
        digest = (rev.get("status") or {}).get("imageDigest") if isinstance(rev.get("status"), dict) else None
        if not isinstance(digest, str) or "@sha256:" not in digest:
            raise ComponentReadError("BAD_RESPONSE", f"revision {revision}: no resolved image digest")
        meta = svc.get("metadata") if isinstance(svc.get("metadata"), dict) else {}
        annotations = meta.get("annotations") if isinstance(meta.get("annotations"), dict) else {}
        return {"image_digest": digest, "revision": revision,
                "annotations": {k: v for k, v in annotations.items() if isinstance(k, str) and isinstance(v, str)}}
    if kind == "job":
        job = _get(get_json, _run_v1(region, f"run.googleapis.com/v1/namespaces/{project}/jobs/{name}"), f"job {name}")
        try:
            image = job["spec"]["template"]["spec"]["template"]["spec"]["containers"][0]["image"]
        except (KeyError, IndexError, TypeError):
            image = None
        if not isinstance(image, str) or not image:
            raise ComponentReadError("BAD_RESPONSE", f"job {name}: no container image")
        form = classify_image(image)
        if form is None:
            raise ComponentReadError("BAD_RESPONSE", f"job {name}: malformed container image {image!r}")
        if form == IMAGE_TAG:
            # A job carries no resolved digest of its own (unlike a service revision's status.imageDigest). A tag is
            # mutable: it is reported as such and never compared with
            # a recorded digest, so it can never show a recorded release (review M4).
            return {"image_digest": None, "image_tag": image, "revision": "", "annotations": {}}
        return {"image_digest": image, "revision": "", "annotations": {}}
    raise ComponentReadError("BAD_RESPONSE", f"unknown component kind {kind!r}")


def stamp_from_annotations(annotations: Mapping[str, str]) -> PlatformStamp:
    return PlatformStamp(annotations.get(STAMP_RELEASE_ANNOTATION), annotations.get(STAMP_COMMIT_ANNOTATION))

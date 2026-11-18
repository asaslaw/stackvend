#!/usr/bin/env python3
"""
StackVend upgrader, step 0 helper: request, release source, platform stamp, signatures and the manifest guard
(SELFUP P3b; plan docs/planning/self-upgrade-plan.md §3.3-§3.4, §3.10.5; plan RT 11-02 H-4, M-6).

FROZEN CONTENT. Together with `verify.sh` (same directory) this file is embedded by core Terraform into the
"Update StackVend" Cloud Build trigger as its step 0 (infra/platform/platform_upgrader.tf; a parity test keeps the
embedded copy equal to this file). A change here takes an `apply.sh apply` to reach an install. It runs BEFORE any
code of the release being installed, so it must not import anything from a checkout: standard library only, one
file. The same file in the target tree is also used by the later stages (`report`), so the progress document has one
writer.

Commands (every refusal: one line `stackvend-upgrade: REFUSED <CODE>: <message>` on stderr, `<out-dir>/refusal.json`
when an out dir is known, and the exit status of CODES[<CODE>]):
  inputs   --request-id ID --project P --region R --guard-database DB --official-signers FILE --out-dir DIR
           Network (metadata-server token; Firestore and Cloud Run REST): read and validate the request, the lease,
           the release source (UPDATE_CHECK_OFF, SOURCE_SETTING_CHANGED), the platform stamp and the version floor;
           claim the request (create-only progress document). Writes DIR/inputs.json, DIR/allowed_signers,
           DIR/signers.json.
  fields   --inputs FILE                         print "<repository> <target_tag> <expected_commit> <kind>"
  classify --tag-object FILE --signers FILE      after a FAILED `git verify-tag`: SIGNATURE_INVALID or UNKNOWN_SIGNER
  signer   --tag-object FILE --signers FILE      after a GOOD `git verify-tag`: print the trusted key's fingerprint
  decide   --inputs FILE --commit SHA --manifest FILE --signer FPR --out FILE
           Pure: manifest (strict), release == tag, previews, PLATFORM_STAMP_UNKNOWN, DOWNGRADE_REFUSED,
           NEEDS_APPLY_SH. Writes the hand-over document (verified.json).
  refuse   --code CODE --message TEXT [--out-dir DIR]   a refusal decided by verify.sh (same output and exit status)
  report   --request-id ID --project P --status S [--stage S] [--code C] [--message M] [--steps-file F]
           Update the progress document platform_upgrades_progress/{id} (default database; it must exist).

Exact parsing only (AGENTS.md invariant 2): SemVer 2.0 by its grammar, the manifest by an exact key set and exact
JSON types, SSH keys and SSH signatures decoded field by field, typed REST fields. Nothing is guessed from text.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import string
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# ------------------------------------------------------------------------------------------------ refusal codes
# Exit status per code (0 = OK). Stable: the Control Center and the build log show the code; tests pin the table.
CODES: Dict[str, int] = {
    "USAGE": 2,
    "BAD_REQUEST_ID": 10,
    "REQUEST_NOT_FOUND": 11,
    "REQUEST_INVALID": 12,
    "REQUEST_NOT_PENDING": 13,
    "LEASE_NOT_HELD": 14,
    "REQUEST_ALREADY_RUN": 15,
    "RELEASE_SOURCE_INVALID": 20,
    "UPDATE_CHECK_OFF": 21,
    "SOURCE_SETTING_CHANGED": 22,
    "BRANCH_NOT_SUPPORTED": 23,
    "OFFICIAL_SIGNERS_INVALID": 24,
    "NO_TRUSTED_SIGNERS": 25,
    "FETCH_FAILED": 30,
    "SIGNATURE_INVALID": 31,
    "UNKNOWN_SIGNER": 32,
    "SOURCE_CHANGED": 33,
    "MANIFEST_INVALID": 40,
    "MANIFEST_UNSUPPORTED": 41,
    "MANIFEST_MISMATCH": 42,
    "PREVIEW_NOT_ALLOWED": 43,
    "DOWNGRADE_REFUSED": 44,
    "NEEDS_APPLY_SH": 45,
    "PLATFORM_STAMP_UNKNOWN": 46,
    "TOKEN_UNAVAILABLE": 50,
    "API_READ_FAILED": 51,
    "PROGRESS_WRITE_FAILED": 52,
    "TARGET_NOT_UPGRADABLE": 60,
    "INTERNAL": 70,
}


class Refusal(Exception):
    def __init__(self, code: str, message: str, steps: Optional[List[str]] = None):
        if code not in CODES:
            code, message = "INTERNAL", f"unknown refusal code {code!r}: {message}"
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.steps = code, message, list(steps or [])


def _emit_refusal(r: Refusal, out_dir: Optional[str]) -> int:
    print(f"stackvend-upgrade: REFUSED {r.code}: {r.message}", file=sys.stderr)
    for step in r.steps:
        print(f"stackvend-upgrade:   {step}", file=sys.stderr)
    if out_dir:
        try:
            with open(os.path.join(out_dir, "refusal.json"), "w", encoding="utf-8") as fh:
                json.dump({"code": r.code, "message": r.message, "steps": r.steps}, fh, sort_keys=True)
        except OSError:
            pass
    return CODES[r.code]


# ------------------------------------------------------------------------------------------------ constants
OFFICIAL_RELEASE_REPOSITORY = "asaslaw/stackvend"
CONTROL_CENTER_SERVICE = "product-control-center-ui"
STAMP_RELEASE_ANNOTATION = "stackvend/platform-release"
STAMP_COMMIT_ANNOTATION = "stackvend/platform-commit"
REQUESTS = "platform_upgrades"
LEASE_DOC = "_lease"
PROGRESS = "platform_upgrades_progress"
SOURCE_COLLECTION, SOURCE_DOC = "platform_release_source", "current"
RECORD_COLLECTION, RECORD_DOC = "system_config", "platform_release"
KIND_UPGRADE, KIND_ROLLBACK = "UPGRADE", "ROLLBACK"
REQUEST_SCHEMA = 1

# Parity (tests): == COMPONENTS in shared/release_manifest.py == scripts/common/components.sh (+ tf-applier).
COMPONENT_KINDS: Dict[str, str] = {
    "product-control-center-ui": "service", "orchestrator-gateway-service": "service",
    "project-repo-vending-service": "service", "log-sre-sentinel-service": "service",
    "spec-ingestion-service": "service", "mcp-terraform-server": "service", "mcp-gcloud-server": "service",
    "mcp-github-toolserver": "service", "mcp-workspace-connector": "service", "mcp-infracost-server": "service",
    "mcp-compliance-server": "service", "mcp-kubernetes-server": "service", "mcp-agent-builder-server": "service",
    "castor-git-server": "service", "github-refactor-scanner-job": "job", "qa-sandbox-test-runner": "job",
    "finops-budget-enforcer-job": "job", "infra-rollback-job": "job", "sandbox-garbage-collector-job": "job",
    "sre-telemetry-digest-job": "job", "finops-spend-sync-job": "job", "sandbox-workload-sweeper-job": "job",
    "billing-alert-drain-job": "job", "tf-applier": "job",
}

_HEX = frozenset("0123456789abcdef")


def _is_hex(text: Any, n: int) -> bool:
    return isinstance(text, str) and len(text) == n and set(text) <= _HEX


# ------------------------------------------------------------------------------------------------ SemVer 2.0
_ALNUM_HYPHEN = frozenset(string.ascii_letters + string.digits + "-")


def _numeric(part: str) -> bool:
    return bool(part) and part.isascii() and part.isdigit() and not (len(part) > 1 and part[0] == "0")


def parse_semver(text: Any) -> Optional[Tuple[int, int, int, Tuple[str, ...]]]:
    """`MAJOR.MINOR.PATCH[-PRE]` (no build metadata); same grammar as shared/release_manifest.parse_semver."""
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
    return int(parts[0]), int(parts[1]), int(parts[2]), ids


def parse_release_tag(tag: Any) -> Optional[Tuple[int, int, int, Tuple[str, ...]]]:
    if not isinstance(tag, str) or not tag.startswith("v"):
        return None
    return parse_semver(tag[1:])


def _key(v: Tuple[int, int, int, Tuple[str, ...]]) -> Tuple:
    pre = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in v[3])
    return (v[0], v[1], v[2], 0 if v[3] else 1, pre)


def compare(a: Tuple, b: Tuple) -> int:
    ka, kb = _key(a), _key(b)
    return (ka > kb) - (ka < kb)


def semver_str(v: Tuple) -> str:
    return f"{v[0]}.{v[1]}.{v[2]}" + ("-" + ".".join(v[3]) if v[3] else "")


# ------------------------------------------------------------------------------------------------ manifest
MANIFEST_MAX_BYTES = 4096
_MANIFEST_FIELDS = {"schema_version": int, "release": str, "requires_apply_sh": bool, "min_platform_release": str}


def parse_manifest(raw: bytes) -> Dict[str, Any]:
    """Strict parser, same rules as shared/release_manifest.parse_manifest + manifest_rule_errors."""
    if len(raw) > MANIFEST_MAX_BYTES:
        raise Refusal("MANIFEST_INVALID", "release-manifest.json is larger than 4096 bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refusal("MANIFEST_INVALID", "release-manifest.json is not UTF-8 JSON") from None
    if not isinstance(doc, dict):
        raise Refusal("MANIFEST_INVALID", "release-manifest.json is not a JSON object")
    schema = doc.get("schema_version")
    if type(schema) is int and schema != 1:
        raise Refusal("MANIFEST_UNSUPPORTED", f"release-manifest.json schema_version {schema} (supported: 1); "
                      "install this release with the terminal path once")
    if set(doc) != set(_MANIFEST_FIELDS):
        raise Refusal("MANIFEST_INVALID", f"release-manifest.json keys: unknown {sorted(set(doc) - set(_MANIFEST_FIELDS))}, "
                      f"missing {sorted(set(_MANIFEST_FIELDS) - set(doc))}")
    for key, typ in _MANIFEST_FIELDS.items():
        if type(doc[key]) is not typ:
            raise Refusal("MANIFEST_INVALID", f"release-manifest.json {key} must be a JSON {typ.__name__}")
    release, minimum = parse_semver(doc["release"]), parse_semver(doc["min_platform_release"])
    if release is None or minimum is None:
        raise Refusal("MANIFEST_INVALID", "release-manifest.json release / min_platform_release is not a SemVer version")
    if compare(minimum, release) > 0:
        raise Refusal("MANIFEST_INVALID", "min_platform_release is newer than release")
    if doc["requires_apply_sh"] != (compare(minimum, release) == 0):
        raise Refusal("MANIFEST_INVALID", "requires_apply_sh must be true exactly when min_platform_release == release")
    return {"release": release, "requires_apply_sh": doc["requires_apply_sh"], "min_platform_release": minimum}


# ------------------------------------------------------------------------------------------------ SSH keys
ALLOWED_KEY_TYPES = ("ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256",
                     "sk-ecdsa-sha2-nistp256@openssh.com")


def _read_string(blob: bytes, pos: int) -> Tuple[bytes, int]:
    if pos + 4 > len(blob):
        raise ValueError("ends early")
    (length,) = struct.unpack(">I", blob[pos:pos + 4])
    pos += 4
    if length > len(blob) - pos:
        raise ValueError("ends early")
    return blob[pos:pos + length], pos + length


def fingerprint_of_blob(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def parse_key_blob(declared: str, blob: bytes) -> None:
    """Field-by-field check of an SSH public key blob (same rules as the Control Center's release_source.py)."""
    if declared not in ALLOWED_KEY_TYPES:
        raise ValueError(f"key type {declared!r} is not accepted")
    inner, pos = _read_string(blob, 0)
    if inner != declared.encode("ascii"):
        raise ValueError("the key data is of another type")
    if declared in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        pk, pos = _read_string(blob, pos)
        if len(pk) != 32:
            raise ValueError("an ed25519 public key is 32 bytes")
    else:
        curve, pos = _read_string(blob, pos)
        if curve != b"nistp256":
            raise ValueError("the ecdsa key is not on curve nistp256")
        q, pos = _read_string(blob, pos)
        if len(q) != 65 or q[0] != 4:
            raise ValueError("the ecdsa public point is not an uncompressed P-256 point")
    if declared.startswith("sk-"):
        application, pos = _read_string(blob, pos)
        if not application:
            raise ValueError("a security-key public key names its application")
    if pos != len(blob):
        raise ValueError("unexpected data after the key")


def parse_public_key(declared: str, b64: str) -> Tuple[str, str]:
    """(`<type> <base64>`, fingerprint) or ValueError."""
    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("the key is not valid base64") from None
    parse_key_blob(declared, blob)
    return f"{declared} {b64}", fingerprint_of_blob(blob)


def parse_official_signers(text: str) -> List[Tuple[str, str]]:
    """The installed release's scripts/release/allowed_signers: per non-comment line exactly
    `<principal> <type> <base64> [comment]` or `<principal> namespaces="git" <type> <base64> [comment]`.
    Returns [(public key, fingerprint)]. Anything else -> OFFICIAL_SIGNERS_INVALID (fail closed)."""
    keys: List[Tuple[str, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if len(tokens) >= 4 and tokens[1] == 'namespaces="git"':
            tokens = [tokens[0]] + tokens[2:]
        if len(tokens) < 3:
            raise Refusal("OFFICIAL_SIGNERS_INVALID", f"official allowed_signers line {n} is not `<principal> <type> <key>`")
        try:
            keys.append(parse_public_key(tokens[1], tokens[2]))
        except ValueError as e:
            raise Refusal("OFFICIAL_SIGNERS_INVALID", f"official allowed_signers line {n}: {e}") from None
    return keys


# ------------------------------------------------------------------------------------------------ release source
FOLLOW_TAGS, FOLLOW_BRANCH = "TAGS", "BRANCH"
SIGNER_OFFICIAL, SIGNER_SSH_KEY = "OFFICIAL", "SSH_KEY"
MAX_SIGNERS = 8
_SOURCE_V1 = {"repository", "follow", "branch", "allow_unsigned", "signers", "include_previews", "fingerprint",
              "version", "updated_by", "updated_at"}
_SOURCE_V2 = _SOURCE_V1 | {"update_check"}   # SELFUP-OFF (plan RT H-3): a v1 document reads as update check ON
_OWNER_CHARS = frozenset(string.ascii_letters + string.digits + "-")
_REPO_CHARS = frozenset(string.ascii_letters + string.digits + "._-")


def is_valid_repository(slug: Any) -> bool:
    if not isinstance(slug, str) or slug.count("/") != 1:
        return False
    owner, repo = slug.split("/")
    if not (1 <= len(owner) <= 39) or not set(owner) <= _OWNER_CHARS or owner[0] == "-" or owner[-1] == "-":
        return False
    if not (1 <= len(repo) <= 100) or not set(repo) <= _REPO_CHARS or repo in (".", ".."):
        return False
    return owner.isascii() and repo.isascii()


def source_fingerprint(repository: str, follow: str, branch: str, allow_unsigned: bool,
                       signers: List[Dict[str, str]]) -> str:
    """apps/control-center/release_source.ReleaseSource.fingerprint (parity test): sha256 over the canonical JSON of
    the five decision fields."""
    decision = {"repository": repository, "follow": follow, "branch": branch, "allow_unsigned": allow_unsigned,
                "signers": [{"kind": s["kind"], "fingerprint_sha256": s.get("fingerprint_sha256", "")} for s in signers]}
    canonical = json.dumps(decision, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def default_source() -> Dict[str, Any]:
    signers = [{"kind": SIGNER_OFFICIAL}]
    return {"repository": OFFICIAL_RELEASE_REPOSITORY, "follow": FOLLOW_TAGS, "branch": "", "allow_unsigned": False,
            "signers": signers, "include_previews": True, "update_check": True, "stored": False,
            "fingerprint": source_fingerprint(OFFICIAL_RELEASE_REPOSITORY, FOLLOW_TAGS, "", False, signers)}


def read_source(doc: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate-on-read of platform_release_source/current (None: never saved -> the default source). Raises
    RELEASE_SOURCE_INVALID; never falls back to the default for a document that exists."""
    if doc is None:
        return default_source()

    def bad(why: str) -> Refusal:
        return Refusal("RELEASE_SOURCE_INVALID", f"the stored release source is invalid ({why}); an administrator "
                       "saves a valid one in Settings > Upgrades")

    if not isinstance(doc, dict) or set(doc) not in (_SOURCE_V1, _SOURCE_V2):
        raise bad("unexpected fields")
    update_check = doc.get("update_check", True)
    if type(update_check) is not bool:
        raise bad("update_check is not true or false")
    if type(doc.get("version")) is not int or doc["version"] < 1:
        raise bad("no valid version")
    repository, follow, branch = doc.get("repository"), doc.get("follow"), doc.get("branch")
    allow_unsigned, include_previews = doc.get("allow_unsigned"), doc.get("include_previews")
    if not is_valid_repository(repository):
        raise bad("repository")
    if follow not in (FOLLOW_TAGS, FOLLOW_BRANCH) or not isinstance(branch, str):
        raise bad("follow / branch")
    if follow == FOLLOW_TAGS and branch:
        raise bad("branch is set while following tags")
    if type(allow_unsigned) is not bool or type(include_previews) is not bool:
        raise bad("allow_unsigned / include_previews")
    if allow_unsigned and follow != FOLLOW_BRANCH:
        raise bad("unsigned is only allowed for a branch")
    raw_signers = doc.get("signers")
    if not isinstance(raw_signers, list) or len(raw_signers) > MAX_SIGNERS:
        raise bad("signers")
    signers: List[Dict[str, str]] = []
    seen = set()
    for entry in raw_signers:
        if not isinstance(entry, dict):
            raise bad("signers")
        kind = entry.get("kind")
        if kind == SIGNER_OFFICIAL:
            if set(entry) != {"kind"}:
                raise bad("the official signer entry has other fields")
            key, item = SIGNER_OFFICIAL, {"kind": SIGNER_OFFICIAL}
        elif kind == SIGNER_SSH_KEY:
            parts = entry.get("public_key").split() if isinstance(entry.get("public_key"), str) else []
            if len(parts) != 2:
                raise bad("a signer key is not `<type> <base64>`")
            try:
                public_key, fp = parse_public_key(parts[0], parts[1])
            except ValueError as e:
                raise bad(f"signer key: {e}") from None
            if entry.get("fingerprint_sha256") != fp or entry.get("key_type") != parts[0]:
                raise bad("a stored signer fingerprint does not match its key")
            key, item = fp, {"kind": SIGNER_SSH_KEY, "public_key": public_key, "fingerprint_sha256": fp,
                             "principal": str(entry.get("principal") or "")}
        else:
            raise bad("signer kind")
        if key in seen:
            raise bad("a signer is listed twice")
        seen.add(key)
        signers.append(item)
    if not signers and not allow_unsigned:
        raise bad("no trusted signer")
    fingerprint = source_fingerprint(repository, follow, branch, allow_unsigned, signers)
    if doc.get("fingerprint") != fingerprint:
        raise bad("the stored fingerprint does not match the stored fields")
    return {"repository": repository, "follow": follow, "branch": branch, "allow_unsigned": allow_unsigned,
            "signers": signers, "include_previews": include_previews, "update_check": update_check,
            "stored": True, "fingerprint": fingerprint}


def trusted_signers(source: Dict[str, Any], official_text: str) -> List[Dict[str, str]]:
    """The keys a tag may be signed with: the installed release's official keys when the source trusts the official
    signer, plus the custom keys stored in the source. Each gets a fixed principal `signer-<n>`."""
    keys: List[Tuple[str, str, str]] = []
    for s in source["signers"]:
        if s["kind"] == SIGNER_OFFICIAL:
            for public_key, fp in parse_official_signers(official_text):
                keys.append((public_key, fp, "official"))
        else:
            keys.append((s["public_key"], s["fingerprint_sha256"], "custom"))
    out, seen = [], set()
    for public_key, fp, origin in keys:
        if fp in seen:
            continue
        seen.add(fp)
        out.append({"principal": f"signer-{len(out) + 1}", "public_key": public_key, "fingerprint": fp,
                    "origin": origin})
    if not out:
        raise Refusal("NO_TRUSTED_SIGNERS", "the release source trusts no signing key (the official key list of this "
                      "install is empty and no custom key is set)")
    return out


def allowed_signers_text(signers: List[Dict[str, str]]) -> str:
    return "".join(f'{s["principal"]} namespaces="git" {s["public_key"]}\n' for s in signers)


# ------------------------------------------------------------------------------------------------ request
def _timestamp(v: Any) -> Optional[datetime]:
    if not isinstance(v, str) or not v.endswith("Z") or "T" not in v:
        return None
    main, _, frac = v[:-1].partition(".")
    try:
        ts = datetime.strptime(main, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    if frac and not frac.isdigit():
        return None
    return ts


def validate_request(request_id: str, doc: Any) -> Dict[str, Any]:
    """platform_upgrades/{id} in the guard database (written by the Control Center). The fields below are required
    with exactly these types; other fields are ignored (never read)."""
    def bad(why: str) -> Refusal:
        return Refusal("REQUEST_INVALID", f"request {request_id}: {why}")

    if not isinstance(doc, dict):
        raise bad("not a document")
    if doc.get("schema_version") != REQUEST_SCHEMA or type(doc.get("schema_version")) is not int:
        raise bad("schema_version must be 1")
    kind = doc.get("kind")
    if kind not in (KIND_UPGRADE, KIND_ROLLBACK):
        raise bad("kind must be UPGRADE or ROLLBACK")
    if doc.get("status") != "REQUESTED":
        raise Refusal("REQUEST_NOT_PENDING", f"request {request_id} has status {doc.get('status')!r}, not REQUESTED")
    tag = doc.get("target_tag")
    if parse_release_tag(tag) is None:
        raise bad("target_tag is not a release tag vMAJOR.MINOR.PATCH[-PRE]")
    if not _is_hex(doc.get("expected_commit"), 40):
        raise bad("expected_commit is not a 40-hex commit")
    fp = doc.get("source_fingerprint")
    if not (isinstance(fp, str) and fp.startswith("sha256:") and _is_hex(fp[7:], 64)):
        raise bad("source_fingerprint is not sha256:<64 hex>")
    by = doc.get("requested_by")
    if not isinstance(by, str) or not by or len(by) > 254 or not by.isprintable():
        raise bad("requested_by is missing")
    rollback_of = doc.get("rollback_of", "")
    if kind == KIND_ROLLBACK and not _is_hex(rollback_of, 32):
        raise bad("a ROLLBACK names the upgrade it rolls back (rollback_of, 32 hex)")
    if kind == KIND_UPGRADE and rollback_of not in ("", None):
        raise bad("rollback_of is only set on a ROLLBACK")
    return {"request_id": request_id, "kind": kind, "target_tag": tag, "expected_commit": doc["expected_commit"],
            "source_fingerprint": fp, "requested_by": by, "rollback_of": rollback_of or ""}


# The trigger's build timeout (infra/platform/platform_upgrader.tf `timeout = "7200s"`). At claim time the lease must
# still cover a whole build, so it can never expire while this build runs (plan RT 11-02 code review M-A).
BUILD_TIMEOUT_S = 7200


def check_lease(request_id: str, lease: Any, now: datetime) -> None:
    if not isinstance(lease, dict) or lease.get("request_id") != request_id:
        raise Refusal("LEASE_NOT_HELD", f"request {request_id} does not hold the upgrade lease")
    expires = _timestamp(lease.get("expires_at"))
    if expires is None or expires <= now:
        raise Refusal("LEASE_NOT_HELD", f"the upgrade lease of request {request_id} has expired")
    if expires < now + timedelta(seconds=BUILD_TIMEOUT_S):
        raise Refusal("LEASE_NOT_HELD", f"the upgrade lease of request {request_id} expires before a build of up to "
                      f"{BUILD_TIMEOUT_S} s could finish; request the upgrade again")


# ------------------------------------------------------------------------------------------------ REST
Http = Callable[[str, str, Optional[bytes]], Tuple[int, Any]]
HTTP_TIMEOUT = 20
METADATA_TOKEN = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
FIRESTORE = "https://firestore.googleapis.com/v1"


def metadata_token() -> str:
    req = urllib.request.Request(METADATA_TOKEN, headers={"Metadata-Flavor": "Google"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise Refusal("TOKEN_UNAVAILABLE", f"no access token from the metadata server ({type(e).__name__})") from None
    token = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        raise Refusal("TOKEN_UNAVAILABLE", "the metadata server returned no access token")
    return token


def make_http(token: str, quota_project: str = "") -> Http:
    """Step 0 calls with the upgrader identity's metadata token and no quota project (SAT-48 review H-1): a service
    account bills its own project, and `X-Goog-User-Project` would need serviceusage.services.use, which it lacks."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if quota_project:
        headers["X-Goog-User-Project"] = quota_project

    def call(method: str, url: str, body: Optional[bytes] = None) -> Tuple[int, Any]:
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        except (urllib.error.URLError, OSError) as e:
            raise Refusal("API_READ_FAILED", f"{method} {url.split('?')[0]}: {type(e).__name__}") from None
        try:
            return status, (json.loads(raw.decode("utf-8")) if raw else None)
        except ValueError:
            return status, None
    return call


def from_value(v: Dict[str, Any]) -> Any:
    if "nullValue" in v:
        return None
    for k, conv in (("booleanValue", bool), ("integerValue", int), ("doubleValue", float), ("stringValue", str),
                    ("timestampValue", str), ("referenceValue", str), ("bytesValue", str)):
        if k in v:
            return conv(v[k])
    if "mapValue" in v:
        return {k: from_value(x) for k, x in (v["mapValue"].get("fields") or {}).items()}
    if "arrayValue" in v:
        return [from_value(x) for x in (v["arrayValue"].get("values") or [])]
    raise ValueError(f"unsupported Firestore value {sorted(v)}")


def to_value(v: Any) -> Dict[str, Any]:
    if v is None:
        return {"nullValue": None}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, str):
        return {"stringValue": v}
    if isinstance(v, dict):
        return {"mapValue": {"fields": {str(k): to_value(x) for k, x in v.items()}}}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [to_value(x) for x in v]}}
    raise ValueError(f"cannot store a {type(v).__name__}")


def _doc_url(project: str, database: str, path: str) -> str:
    return f"{FIRESTORE}/projects/{project}/databases/{database}/documents/{path}"


def get_doc(http: Http, project: str, database: str, path: str) -> Optional[Dict[str, Any]]:
    status, body = http("GET", _doc_url(project, database, path), None)
    if status == 404:
        return None
    if status != 200 or not isinstance(body, dict):
        raise Refusal("API_READ_FAILED", f"could not read {database}/{path} (HTTP {status})")
    try:
        return from_value({"mapValue": {"fields": body.get("fields") or {}}})
    except (ValueError, TypeError):
        raise Refusal("API_READ_FAILED", f"{database}/{path}: unreadable document") from None


def _run_v1(region: str, path: str) -> str:
    return f"https://{region}-run.googleapis.com/apis/{path}"


def _get_run(http: Http, url: str, what: str) -> Optional[Dict[str, Any]]:
    status, body = http("GET", url, None)
    if status == 404:
        return None
    if status != 200 or not isinstance(body, dict):
        raise Refusal("API_READ_FAILED", f"could not read {what} (HTTP {status})")
    return body


def read_stamp(http: Http, project: str, region: str) -> Dict[str, Optional[str]]:
    """The platform stamp: two service-level annotations on the Control Center's Cloud Run service (FD-4DA-STAMP)."""
    svc = _get_run(http, _run_v1(region, f"serving.knative.dev/v1/namespaces/{project}/services/{CONTROL_CENTER_SERVICE}"),
                   f"service {CONTROL_CENTER_SERVICE}")
    if svc is None:
        return {"release": None, "commit": None}
    meta = svc.get("metadata") if isinstance(svc.get("metadata"), dict) else {}
    ann = meta.get("annotations") if isinstance(meta.get("annotations"), dict) else {}
    rel, com = ann.get(STAMP_RELEASE_ANNOTATION), ann.get(STAMP_COMMIT_ANNOTATION)
    return {"release": rel if isinstance(rel, str) else None, "commit": com if isinstance(com, str) else None}


def live_digest(http: Http, project: str, region: str, name: str, kind: str) -> Optional[str]:
    """The digest a component runs (typed Cloud Run fields; a job deployed by tag has none -> None)."""
    if kind == "service":
        svc = _get_run(http, _run_v1(region, f"serving.knative.dev/v1/namespaces/{project}/services/{name}"),
                       f"service {name}")
        status = (svc or {}).get("status") if isinstance((svc or {}).get("status"), dict) else {}
        revision = status.get("latestReadyRevisionName")
        if not isinstance(revision, str) or not revision:
            return None
        rev = _get_run(http, _run_v1(region, f"serving.knative.dev/v1/namespaces/{project}/revisions/{revision}"),
                       f"revision {revision}")
        st = (rev or {}).get("status") if isinstance((rev or {}).get("status"), dict) else {}
        digest = st.get("imageDigest")
        return digest if isinstance(digest, str) and _is_digest_ref(digest) else None
    job = _get_run(http, _run_v1(region, f"run.googleapis.com/v1/namespaces/{project}/jobs/{name}"), f"job {name}")
    try:
        image = job["spec"]["template"]["spec"]["template"]["spec"]["containers"][0]["image"]  # type: ignore[index]
    except (KeyError, IndexError, TypeError):
        return None
    return image if isinstance(image, str) and _is_digest_ref(image) else None


def _is_digest_ref(image: str) -> bool:
    repository, sep, digest = image.rpartition("@sha256:")
    return bool(repository) and sep == "@sha256:" and _is_hex(digest, 64)


def version_floor(http: Http, project: str, region: str, record: Any, stamp_release: Optional[Tuple]
                  ) -> Tuple[Optional[Tuple], List[str]]:
    """Plan RT H-4: floor = max(release of the record's components whose recorded digest is the digest running now,
    platform stamp release). The record (default database) is forgeable: it can only raise the floor (refuse), never
    push it below the stamp."""
    floor = stamp_release
    matched: List[str] = []
    components = record.get("components") if isinstance(record, dict) else None
    if not isinstance(components, dict):
        return floor, matched
    for name in sorted(components):
        entry = components[name]
        kind = COMPONENT_KINDS.get(name)
        if kind is None or not isinstance(entry, dict):
            continue
        recorded, release = entry.get("image_digest"), parse_semver(entry.get("release"))
        if not isinstance(recorded, str) or release is None:
            continue
        if live_digest(http, project, region, name, kind) != recorded:
            continue
        matched.append(f"{name}={semver_str(release)}")
        if floor is None or compare(release, floor) > 0:
            floor = release
    return floor, matched


def _create_progress(http: Http, project: str, request_id: str, fields: Dict[str, Any]) -> int:
    """Create platform_upgrades_progress/{id} (default database) only if it does not exist. HTTP status."""
    url = _doc_url(project, "(default)", f"{PROGRESS}/{request_id}") + "?currentDocument.exists=false"
    status, _ = http("PATCH", url, json.dumps({"fields": to_value(fields)["mapValue"]["fields"]}).encode("utf-8"))
    return status


def claim(http: Http, project: str, request: Dict[str, Any], now_iso: str) -> None:
    """Each request runs once: the progress record is created here, and only if it does not exist yet."""
    fields = {"schema_version": 1, "request_id": request["request_id"], "kind": request["kind"],
              "target_tag": request["target_tag"], "expected_commit": request["expected_commit"],
              "requested_by": request["requested_by"], "status": "RUNNING", "stage": "VERIFYING", "code": "",
              "message": "", "steps": [], "build_id": os.environ.get("BUILD_ID", ""), "started_at": now_iso,
              "updated_at": now_iso}
    status = _create_progress(http, project, request["request_id"], fields)
    if status in (400, 409, 412):
        raise Refusal("REQUEST_ALREADY_RUN", f"request {request['request_id']} already has a progress record; a "
                      "request runs once")
    if status != 200:
        raise Refusal("PROGRESS_WRITE_FAILED", f"could not create the progress record (HTTP {status})")


def record_unclaimed_refusal(http: Http, project: str, request_id: str, r: Refusal, now_iso: str) -> None:
    """A request that cannot be claimed (invalid, or not holding the lease) still gets a visible refusal, but only
    when it has no progress record yet (create-only: an earlier run's record is never overwritten)."""
    fields = {"schema_version": 1, "request_id": request_id, "status": f"REFUSED_{r.code}", "stage": "VERIFYING",
              "code": r.code, "message": r.message, "steps": [], "build_id": os.environ.get("BUILD_ID", ""),
              "started_at": now_iso, "updated_at": now_iso}
    try:
        _create_progress(http, project, request_id, fields)
    except Refusal:
        pass


def update_progress(http: Http, project: str, request_id: str, fields: Dict[str, Any]) -> None:
    mask = "&".join("updateMask.fieldPaths=" + urllib.parse.quote(k, safe="") for k in sorted(fields))
    url = _doc_url(project, "(default)", f"{PROGRESS}/{request_id}") + f"?currentDocument.exists=true&{mask}"
    status, _ = http("PATCH", url, json.dumps({"fields": to_value(fields)["mapValue"]["fields"]}).encode("utf-8"))
    if status != 200:
        raise Refusal("PROGRESS_WRITE_FAILED", f"could not update the progress record (HTTP {status})")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def gather_inputs(http: Http, request_id: str, project: str, region: str, guard_db: str, official_text: str,
                  now: Optional[datetime] = None) -> Dict[str, Any]:
    """Everything step 0 reads before it fetches anything (plan §3.3 step 1, §3.10.5, H-4, M-6)."""
    now = now or _now()
    doc = get_doc(http, project, guard_db, f"{REQUESTS}/{request_id}")
    if doc is None:
        raise Refusal("REQUEST_NOT_FOUND", f"no request {request_id} in the guard database")
    try:
        request = validate_request(request_id, doc)
        check_lease(request_id, get_doc(http, project, guard_db, f"{REQUESTS}/{LEASE_DOC}"), now)
    except Refusal as r:
        if r.code in ("REQUEST_INVALID", "LEASE_NOT_HELD"):
            record_unclaimed_refusal(http, project, request_id, r, _iso(now))
        raise
    claim(http, project, request, _iso(now))
    claimed = {"request": request}
    try:
        source = read_source(get_doc(http, project, guard_db, f"{SOURCE_COLLECTION}/{SOURCE_DOC}"))
        if not source["update_check"]:
            raise Refusal("UPDATE_CHECK_OFF", "the update check is off on this install (Settings > Upgrades); updates "
                          "are manual: scripts/upgrade.sh / scripts/deploy-services.sh")
        if source["fingerprint"] != request["source_fingerprint"]:
            raise Refusal("SOURCE_SETTING_CHANGED", "the release source changed after the upgrade was requested; "
                          "review Settings > Upgrades and request the upgrade again")
        if source["follow"] != FOLLOW_TAGS:
            raise Refusal("BRANCH_NOT_SUPPORTED", "the release source follows a branch; the Update button installs "
                          "signed release tags only")
        signers = trusted_signers(source, official_text)
        stamp = read_stamp(http, project, region)
        stamp_release = parse_semver(stamp["release"]) if stamp["release"] is not None else None
        floor, matched = version_floor(http, project, region,
                                       get_doc(http, project, "(default)", f"{RECORD_COLLECTION}/{RECORD_DOC}"),
                                       stamp_release)
    except Refusal as r:
        raise _Claimed(r, claimed) from None
    return {"schema_version": 1, "project": project, "region": region, "request": request,
            "source": {"repository": source["repository"], "fingerprint": source["fingerprint"],
                       "include_previews": source["include_previews"], "stored": source["stored"]},
            "signers": signers, "stamp": stamp,
            "floor": semver_str(floor) if floor is not None else None, "floor_from": matched}


class _Claimed(Exception):
    """A refusal after the request was claimed: it is also written to the progress record."""

    def __init__(self, refusal: Refusal, ctx: Dict[str, Any]):
        super().__init__(str(refusal))
        self.refusal, self.ctx = refusal, ctx


# ------------------------------------------------------------------------------------------------ signatures
_SIG_HEADERS = (b"-----BEGIN PGP SIGNATURE-----", b"-----BEGIN PGP MESSAGE-----", b"-----BEGIN SIGNED MESSAGE-----",
                b"-----BEGIN SSH SIGNATURE-----")
_SSH_BEGIN, _SSH_END = b"-----BEGIN SSH SIGNATURE-----", b"-----END SSH SIGNATURE-----"


def split_signed_tag(raw: bytes) -> Tuple[bytes, Optional[bytes]]:
    """git's own rule (gpg-interface.c parse_signed_buffer): the signature starts at the LAST line that begins with a
    known signature header. Returns (payload, SSH signature armor) or (raw, None) when there is no SSH signature."""
    pos, match = 0, -1
    while pos < len(raw):
        if any(raw.startswith(h, pos) for h in _SIG_HEADERS):
            match = pos
        eol = raw.find(b"\n", pos)
        pos = len(raw) if eol < 0 else eol + 1
    if match < 0 or not raw.startswith(_SSH_BEGIN, match):
        return raw, None
    return raw[:match], raw[match:]


def sshsig_public_key(armor: bytes) -> Tuple[str, str]:
    """(fingerprint, namespace) of the key inside an SSHSIG armor (PROTOCOL.sshsig: "SSHSIG", uint32 version,
    string publickey, string namespace, string reserved, string hash_algorithm, string signature)."""
    lines = armor.strip().split(b"\n")
    if len(lines) < 3 or lines[0].strip() != _SSH_BEGIN or lines[-1].strip() != _SSH_END:
        raise ValueError("not an SSH signature armor")
    try:
        blob = base64.b64decode(b"".join(x.strip() for x in lines[1:-1]), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("the SSH signature is not base64") from None
    if not blob.startswith(b"SSHSIG") or len(blob) < 10:
        raise ValueError("not an SSHSIG blob")
    (version,) = struct.unpack(">I", blob[6:10])
    if version != 1:
        raise ValueError(f"SSHSIG version {version}")
    public_key, pos = _read_string(blob, 10)
    namespace, pos = _read_string(blob, pos)
    return fingerprint_of_blob(public_key), namespace.decode("utf-8", "replace")


def _load_signers(path: str) -> List[Dict[str, str]]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def classify_failure(tag_object: bytes, signers: List[Dict[str, str]]) -> Refusal:
    """`git verify-tag` failed: was the tag unsigned / badly signed (SIGNATURE_INVALID) or signed correctly by a key
    this install does not trust (UNKNOWN_SIGNER)? Decided by ssh-keygen's exit status and the key inside the
    signature, never by git's message text."""
    payload, armor = split_signed_tag(tag_object)
    if armor is None:
        return Refusal("SIGNATURE_INVALID", "the release tag carries no SSH signature (unsigned tag)")
    try:
        fp, namespace = sshsig_public_key(armor)
    except ValueError as e:
        return Refusal("SIGNATURE_INVALID", f"the release tag's signature is malformed ({e})")
    with tempfile.TemporaryDirectory() as d:
        sig = os.path.join(d, "tag.sig")
        with open(sig, "wb") as fh:
            fh.write(armor)
        try:
            rc = subprocess.run(["ssh-keygen", "-Y", "check-novalidate", "-n", "git", "-s", sig], input=payload,
                                capture_output=True, timeout=60).returncode
        except (OSError, subprocess.SubprocessError) as e:
            return Refusal("SIGNATURE_INVALID", f"ssh-keygen could not check the signature ({type(e).__name__})")
    if rc != 0 or namespace != "git":
        return Refusal("SIGNATURE_INVALID", "the release tag's signature does not verify")
    if fp in {s["fingerprint"] for s in signers}:
        return Refusal("SIGNATURE_INVALID", f"the tag is signed by trusted key {fp} but git did not accept the signature")
    return Refusal("UNKNOWN_SIGNER", f"the release tag is signed by {fp}, which this install does not trust "
                   "(Settings > Upgrades > trusted signers)")


def trusted_signer(tag_object: bytes, signers: List[Dict[str, str]]) -> str:
    """`git verify-tag` succeeded: the fingerprint of the trusted key that signed it (cross-checked)."""
    _, armor = split_signed_tag(tag_object)
    if armor is None:
        raise Refusal("SIGNATURE_INVALID", "git accepted the tag but it carries no SSH signature")
    try:
        fp, namespace = sshsig_public_key(armor)
    except ValueError as e:
        raise Refusal("SIGNATURE_INVALID", f"the release tag's signature is malformed ({e})") from None
    if namespace != "git" or fp not in {s["fingerprint"] for s in signers}:
        raise Refusal("SIGNATURE_INVALID", "the signing key is not one of the trusted signers")
    return fp


# ------------------------------------------------------------------------------------------------ decision
def manual_steps(project: str, tag: str) -> List[str]:
    """Typed terminal steps (no text from the release): plan RT H-5."""
    return [f"PROJECT_ID={project} bash scripts/upgrade.sh {tag}"]


def decide(inputs: Dict[str, Any], commit: str, manifest_raw: bytes, signer: str) -> Dict[str, Any]:
    request = inputs["request"]
    tag = request["target_tag"]
    target = parse_release_tag(tag)
    if target is None or not _is_hex(commit, 40) or commit != request["expected_commit"]:
        raise Refusal("SOURCE_CHANGED", f"{tag} does not point at the commit the administrator confirmed")
    manifest = parse_manifest(manifest_raw)
    if compare(manifest["release"], target) != 0:
        raise Refusal("MANIFEST_MISMATCH", f"release-manifest.json says {semver_str(manifest['release'])}, the tag is {tag}")
    stamp = inputs.get("stamp") or {}
    platform = parse_semver(stamp.get("release")) if stamp.get("release") is not None else None
    warnings: List[str] = []
    if isinstance(stamp.get("commit"), str) and stamp["commit"].endswith("+dirty"):
        warnings.append("platform stamp is +dirty: apply.sh ran from a modified checkout")
    steps = manual_steps(inputs["project"], tag)
    if request["kind"] == KIND_UPGRADE:
        if target[3] and not inputs["source"]["include_previews"]:
            raise Refusal("PREVIEW_NOT_ALLOWED", f"{tag} is a preview release and this install follows stable releases only")
        if platform is None:
            raise Refusal("PLATFORM_STAMP_UNKNOWN", "the platform release of this install is unknown (no valid platform "
                          "stamp on the Control Center service); use the terminal path", steps)
        floor = parse_semver(inputs.get("floor")) if inputs.get("floor") else None
        if floor is not None and compare(target, floor) < 0:
            raise Refusal("DOWNGRADE_REFUSED", f"{tag} is older than this install ({semver_str(floor)})")
        if compare(platform, manifest["min_platform_release"]) < 0:
            raise Refusal("NEEDS_APPLY_SH", f"{tag} needs platform Terraform {semver_str(manifest['min_platform_release'])}; "
                          f"this install's platform is {semver_str(platform)}. An administrator applies it from a "
                          "terminal first, then presses Update again", steps)
    return {"schema_version": 1, "request_id": request["request_id"], "kind": request["kind"],
            "rollback_of": request["rollback_of"], "requested_by": request["requested_by"],
            "project": inputs["project"], "region": inputs["region"],
            "repository": inputs["source"]["repository"], "source_fingerprint": inputs["source"]["fingerprint"],
            "target_tag": tag, "commit": commit, "release": semver_str(manifest["release"]),
            "requires_apply_sh": manifest["requires_apply_sh"],
            "min_platform_release": semver_str(manifest["min_platform_release"]),
            "platform_release": semver_str(platform) if platform else None, "floor": inputs.get("floor"),
            "signer_fingerprint": signer, "warnings": warnings}


# ------------------------------------------------------------------------------------------------ CLI
def _http_for(project: str) -> Http:
    # `project` names the install; the metadata token needs no quota-project header (SAT-48 review H-1)
    return make_http(metadata_token())


def _report_refusal(http: Http, project: str, request_id: str, r: Refusal, stage: str = "VERIFYING") -> None:
    try:
        update_progress(http, project, request_id, {"status": f"REFUSED_{r.code}", "stage": stage, "code": r.code,
                                                    "message": r.message, "steps": r.steps,
                                                    "updated_at": _iso(_now())})
    except Refusal as e:
        print(f"stackvend-upgrade: could not record the refusal in the progress record ({e})", file=sys.stderr)


def _write_json(path: str, doc: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, sort_keys=True, indent=1)
        fh.write("\n")


def main(argv: Optional[List[str]] = None, http_factory: Callable[[str], Http] = _http_for) -> int:
    p = argparse.ArgumentParser(prog="guard.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("inputs")
    for f in ("--request-id", "--project", "--region", "--guard-database", "--official-signers", "--out-dir"):
        a.add_argument(f, required=True)
    f_ = sub.add_parser("fields")
    f_.add_argument("--inputs", required=True)
    for name in ("classify", "signer"):
        c = sub.add_parser(name)
        c.add_argument("--tag-object", required=True)
        c.add_argument("--signers", required=True)
        c.add_argument("--out-dir", default="")
    d = sub.add_parser("decide")
    for f in ("--inputs", "--commit", "--manifest", "--signer", "--out"):
        d.add_argument(f, required=True)
    r = sub.add_parser("refuse")
    r.add_argument("--code", required=True)
    r.add_argument("--message", required=True)
    r.add_argument("--out-dir", default="")
    rep = sub.add_parser("report")
    rep.add_argument("--request-id", required=True)
    rep.add_argument("--project", required=True)
    rep.add_argument("--status", default="")
    rep.add_argument("--stage", default="")
    rep.add_argument("--code", default="")
    rep.add_argument("--message", default="")
    rep.add_argument("--steps-file", default="")
    rep.add_argument("--extra-file", default="", help="JSON object of further progress fields (later stages)")
    rep.add_argument("--refusal-file", default="", help="a refusal.json: status REFUSED_<code> + code/message/steps")
    rep.add_argument("--verified-file", default="", help="a verified.json: what step 0 verified")
    try:
        args = p.parse_args(argv)
    except SystemExit:
        return CODES["USAGE"]
    out_dir = getattr(args, "out_dir", "") or ""
    if args.cmd == "decide":
        out_dir = os.path.dirname(os.path.abspath(args.out))
    try:
        if args.cmd == "inputs":
            if not _is_hex(args.request_id, 32):
                raise Refusal("BAD_REQUEST_ID", "the request id is not 32 lowercase hex characters")
            try:
                with open(args.official_signers, encoding="utf-8") as fh:
                    official = fh.read()
            except OSError:
                raise Refusal("OFFICIAL_SIGNERS_INVALID", "the installed official allowed_signers is missing") from None
            http = http_factory(args.project)
            try:
                inputs = gather_inputs(http, args.request_id, args.project, args.region, args.guard_database, official)
            except _Claimed as c:
                _report_refusal(http, args.project, args.request_id, c.refusal)
                raise c.refusal from None
            _write_json(os.path.join(out_dir, "inputs.json"), inputs)
            _write_json(os.path.join(out_dir, "signers.json"), inputs["signers"])
            with open(os.path.join(out_dir, "allowed_signers"), "w", encoding="utf-8") as fh:
                fh.write(allowed_signers_text(inputs["signers"]))
            return 0
        if args.cmd == "fields":
            with open(args.inputs, encoding="utf-8") as fh:
                inp = json.load(fh)
            req = inp["request"]
            print(inp["source"]["repository"], req["target_tag"], req["expected_commit"], req["kind"])
            return 0
        if args.cmd in ("classify", "signer"):
            with open(args.tag_object, "rb") as fh:
                obj = fh.read()
            signers = _load_signers(args.signers)
            if args.cmd == "classify":
                raise classify_failure(obj, signers)
            print(trusted_signer(obj, signers))
            return 0
        if args.cmd == "decide":
            with open(args.inputs, encoding="utf-8") as fh:
                inp = json.load(fh)
            with open(args.manifest, "rb") as fh:
                raw = fh.read(MANIFEST_MAX_BYTES + 1)
            _write_json(args.out, decide(inp, args.commit, raw, args.signer))
            return 0
        if args.cmd == "refuse":
            raise Refusal(args.code, args.message)
        if args.cmd == "report":
            if not _is_hex(args.request_id, 32):
                raise Refusal("BAD_REQUEST_ID", "the request id is not 32 lowercase hex characters")
            fields: Dict[str, Any] = {"updated_at": _iso(_now())}
            for k in ("status", "stage", "code", "message"):
                if getattr(args, k):
                    fields[k] = getattr(args, k)
            if args.refusal_file:
                with open(args.refusal_file, encoding="utf-8") as fh:
                    ref = json.load(fh)
                code = ref.get("code") if ref.get("code") in CODES else "INTERNAL"
                fields.update({"status": f"REFUSED_{code}", "code": code, "message": str(ref.get("message", "")),
                               "steps": [str(x) for x in ref.get("steps") or []]})
            if args.verified_file:
                with open(args.verified_file, encoding="utf-8") as fh:
                    ver = json.load(fh)
                fields["verified"] = {k: ver.get(k) for k in ("target_tag", "commit", "release", "repository",
                                                              "signer_fingerprint", "platform_release", "floor",
                                                              "min_platform_release", "warnings")}
            if "status" not in fields:
                raise Refusal("USAGE", "report needs --status or --refusal-file")
            if args.steps_file:
                with open(args.steps_file, encoding="utf-8") as fh:
                    fields["steps"] = [str(s) for s in json.load(fh)]
            if args.extra_file:
                with open(args.extra_file, encoding="utf-8") as fh:
                    extra = json.load(fh)
                if not isinstance(extra, dict):
                    raise Refusal("USAGE", "--extra-file must hold a JSON object")
                fields.update({str(k): v for k, v in extra.items() if k not in ("request_id", "schema_version")})
            update_progress(http_factory(args.project), args.project, args.request_id, fields)
            return 0
    except Refusal as e:
        return _emit_refusal(e, out_dir)
    except (OSError, ValueError, KeyError, TypeError) as e:
        return _emit_refusal(Refusal("INTERNAL", f"{args.cmd}: {type(e).__name__}: {e}"), out_dir)
    return CODES["USAGE"]


if __name__ == "__main__":
    sys.exit(main())

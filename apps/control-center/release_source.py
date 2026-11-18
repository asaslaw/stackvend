"""
StackVend Control Center: the release source setting (FD-7C P3a, SELFUP-SOURCE setting + display part; plan
docs/planning/self-upgrade-plan.md §3.10).

Where upgrades come from: a GitHub repository (default the official StackVend repository), what to follow (signed
release tags only) and which signing keys are trusted (the official release key by
default). In P3a it changes only what Settings displays (which releases are listed, the commands printed); nothing
is installed from it. P3b's upgrade build will verify against it.

Stored in the guard Firestore database (`STACKVEND_GUARD_FIRESTORE_DATABASE`, which workload Terraform cannot write;
OQ-12c Q14 recommendation): `platform_release_source/current`, with a never-trimmed change record under
`platform_release_source/current/changes/{id}`. Validate on write AND on read: an invalid stored document is shown
as "release source invalid" and never silently replaced by a default.

Exact parsing only (no pattern guessing): GitHub name rules, the `git check-ref-format --branch` rules implemented
as checks, SSH public keys decoded and parsed (the key type inside the blob must equal the declared one).

"Check for updates" switch (P3a-OFF, owner 11-02; plan §3.12): `update_check` (JSON bool) is one more field of the
same document. Off = the Control Center makes no GitHub call for releases, branch heads or the upstream-sync variables.
It is not a trust decision, so it is not in the fingerprint (like `include_previews`). Stored key set v2 = v1 +
`update_check`; a v1 document (no key) reads as on and valid; any present value that is not a JSON bool makes the
stored document invalid (fail closed: no check).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from shared import release_manifest as rm

COLLECTION = "platform_release_source"
DOCUMENT = "current"
CHANGES = "changes"

FOLLOW_TAGS = "TAGS"
FOLLOW_BRANCH = "BRANCH"
SIGNER_OFFICIAL = "OFFICIAL"
SIGNER_SSH_KEY = "SSH_KEY"
MAX_SIGNERS = 8
MAX_PRINCIPAL = 100
ALLOWED_KEY_TYPES = ("ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256",
                     "sk-ecdsa-sha2-nistp256@openssh.com")
DEFAULT_INCLUDE_PREVIEWS = True  # OQ-12c Q3 (listed in the SAT-11 brief): previews included during the preview
DEFAULT_UPDATE_CHECK = True      # P3a-OFF: on unless an administrator turns it off

_DECISION_FIELDS = ("repository", "follow", "branch", "allow_unsigned", "signers")
_STORED_FIELDS_V1 = set(_DECISION_FIELDS) | {"include_previews", "fingerprint", "version", "updated_by", "updated_at"}
_STORED_FIELDS = _STORED_FIELDS_V1 | {"update_check"}  # v2 (P3a-OFF): what every save writes


class SourceError(ValueError):
    def __init__(self, code: str, message: str, field: str = ""):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.field = code, message, field

    def detail(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "field": self.field}


# ------------------------------------------------------------------------------------------------ SSH public keys
def _read_string(blob: bytes, pos: int) -> Tuple[bytes, int]:
    if pos + 4 > len(blob):
        raise SourceError("INVALID_KEY", "the key data ends early", "signers")
    (length,) = struct.unpack(">I", blob[pos:pos + 4])
    pos += 4
    if length > len(blob) - pos:
        raise SourceError("INVALID_KEY", "the key data ends early", "signers")
    return blob[pos:pos + length], pos + length


def parse_ssh_public_key(text: Any) -> Dict[str, str]:
    """`<type> <base64> [comment]` -> {key_type, public_key (type + base64), fingerprint_sha256}. The blob is decoded
    and parsed field by field (RFC 4253 / 5656 / OpenSSH PROTOCOL.u2f): the type inside it must equal the declared
    type, the field sizes must be exact and nothing may follow. RSA and every other type are refused."""
    if not isinstance(text, str) or not text.strip() or len(text) > 2000 or "\n" in text.strip():
        raise SourceError("INVALID_KEY", "paste one SSH public key line", "signers")
    parts = text.strip().split()
    declared, b64 = parts[0], parts[1] if len(parts) > 1 else ""
    if declared == "ssh-rsa":
        raise SourceError("RSA_REFUSED", "RSA keys are not accepted; use an ed25519 or ecdsa-sha2-nistp256 key",
                          "signers")
    if declared not in ALLOWED_KEY_TYPES:
        raise SourceError("INVALID_KEY", f"key type {declared!r} is not accepted (accepted: {', '.join(ALLOWED_KEY_TYPES)})",
                          "signers")
    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise SourceError("INVALID_KEY", "the key is not valid base64", "signers") from None
    inner, pos = _read_string(blob, 0)
    if inner != declared.encode("ascii"):
        raise SourceError("KEY_TYPE_MISMATCH", f"the key data is a {inner.decode('ascii', 'replace')!r} key, not "
                          f"{declared!r}", "signers")
    if declared in ("ssh-ed25519", "sk-ssh-ed25519@openssh.com"):
        pk, pos = _read_string(blob, pos)
        if len(pk) != 32:
            raise SourceError("INVALID_KEY", "an ed25519 public key is 32 bytes", "signers")
    else:
        curve, pos = _read_string(blob, pos)
        if curve != b"nistp256":
            raise SourceError("INVALID_KEY", "the ecdsa key is not on curve nistp256", "signers")
        q, pos = _read_string(blob, pos)
        if len(q) != 65 or q[0] != 4:
            raise SourceError("INVALID_KEY", "the ecdsa public point is not an uncompressed P-256 point", "signers")
    if declared.startswith("sk-"):
        application, pos = _read_string(blob, pos)
        if not application:
            raise SourceError("INVALID_KEY", "a security-key public key names its application", "signers")
    if pos != len(blob):
        raise SourceError("INVALID_KEY", "unexpected data after the key", "signers")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return {"key_type": declared, "public_key": f"{declared} {b64}", "fingerprint_sha256": fingerprint}


# ------------------------------------------------------------------------------------------------ the setting
@dataclass(frozen=True)
class ReleaseSource:
    repository: str
    follow: str
    branch: str
    allow_unsigned: bool
    signers: Tuple[Dict[str, str], ...]
    include_previews: bool
    update_check: bool = DEFAULT_UPDATE_CHECK  # not a trust decision: never in decision() / the fingerprint

    def decision(self) -> Dict[str, Any]:
        """The fields that decide what may be installed (the fingerprint covers exactly these)."""
        return {"repository": self.repository, "follow": self.follow, "branch": self.branch,
                "allow_unsigned": self.allow_unsigned,
                "signers": [{"kind": s["kind"], "fingerprint_sha256": s.get("fingerprint_sha256", "")}
                            for s in self.signers]}

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(self.decision(), sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def is_default(self) -> bool:
        return self.fingerprint == default_source().fingerprint

    @property
    def level(self) -> str:
        """Banner: OFFICIAL (none), NOT_OFFICIAL (amber)."""
        return "OFFICIAL" if self.is_default else "NOT_OFFICIAL"

    def describe(self) -> str:
        what = "signed release tags"
        keys = ", ".join("Official StackVend release key" if s["kind"] == SIGNER_OFFICIAL
                         else f"{s.get('principal') or 'key'} ({s.get('fingerprint_sha256')})" for s in self.signers)
        return f"Upgrades come from: {self.repository} · {what}" + (f" · {keys}" if keys else " · no signing key")

    def describe_update_check(self) -> str:
        """The switch's own line (the "Upgrades come from" line is unchanged: off is not a trust change)."""
        return "Update check: on" if self.update_check else \
            "Update check: off (no GitHub call is made; updates are manual with scripts/upgrade.sh)"


def default_source() -> ReleaseSource:
    return ReleaseSource(rm.OFFICIAL_RELEASE_REPOSITORY, FOLLOW_TAGS, "", False, ({"kind": SIGNER_OFFICIAL},),
                         DEFAULT_INCLUDE_PREVIEWS, DEFAULT_UPDATE_CHECK)


def validate_source(raw: Any, existing_keys: Optional[Dict[str, Dict[str, str]]] = None
                    ) -> ReleaseSource:
    """Validate a requested (or stored) setting. Raises SourceError with a code and the field. `existing_keys`
    (fingerprint -> stored entry) keeps `added_by` / `added_at` of keys that were already trusted."""
    if not isinstance(raw, dict):
        raise SourceError("INVALID_SOURCE", "the release source must be an object")
    repository = raw.get("repository")
    if not rm.is_valid_repository(repository):
        raise SourceError("INVALID_REPOSITORY", "repository must be a GitHub owner/repo name", "repository")
    follow = raw.get("follow")
    if follow not in (FOLLOW_TAGS, FOLLOW_BRANCH):
        raise SourceError("INVALID_FOLLOW", "follow must be TAGS", "follow")
    branch = raw.get("branch") or ""
    allow_unsigned = raw.get("allow_unsigned", False)
    include_previews = raw.get("include_previews", DEFAULT_INCLUDE_PREVIEWS)
    if type(allow_unsigned) is not bool or type(include_previews) is not bool:
        raise SourceError("INVALID_SOURCE", "allow_unsigned and include_previews must be true or false")
    update_check = raw.get("update_check", DEFAULT_UPDATE_CHECK)  # absent (a v1 document or request) = on
    if type(update_check) is not bool:
        raise SourceError("INVALID_UPDATE_CHECK", "update_check must be true or false", "update_check")
    if follow == FOLLOW_BRANCH:  # a stored or requested branch source fails typed; it is never silently switched to tags
        raise SourceError("BRANCH_REQUIRES_DEVELOPER_MODE", "following a branch is not available; use signed release tags",
                          "follow")
    if branch:
        raise SourceError("INVALID_BRANCH", "branch is set only when follow is BRANCH", "branch")
    if allow_unsigned:
        raise SourceError("UNSIGNED_REQUIRES_BRANCH", "unsigned sources are not available; use signed release tags",
                          "allow_unsigned")
    raw_signers = raw.get("signers")
    if not isinstance(raw_signers, list):
        raise SourceError("INVALID_SIGNERS", "signers must be a list", "signers")
    if len(raw_signers) > MAX_SIGNERS:
        raise SourceError("TOO_MANY_SIGNERS", f"at most {MAX_SIGNERS} trusted signers", "signers")
    signers: List[Dict[str, str]] = []
    seen = set()
    for entry in raw_signers:
        if not isinstance(entry, dict):
            raise SourceError("INVALID_SIGNERS", "each signer is an object", "signers")
        kind = entry.get("kind")
        if kind == SIGNER_OFFICIAL:
            if set(entry) != {"kind"}:
                raise SourceError("INVALID_SIGNERS", "the official entry has no other fields", "signers")
            key, item = SIGNER_OFFICIAL, {"kind": SIGNER_OFFICIAL}
        elif kind == SIGNER_SSH_KEY:
            parsed = parse_ssh_public_key(entry.get("public_key"))
            principal = entry.get("principal") or ""
            if not isinstance(principal, str) or len(principal) > MAX_PRINCIPAL or not principal.isprintable():
                raise SourceError("INVALID_SIGNERS", f"principal is a label of at most {MAX_PRINCIPAL} characters",
                                  "signers")
            if entry.get("fingerprint_sha256") not in (None, "", parsed["fingerprint_sha256"]):
                raise SourceError("INVALID_SIGNERS", "stored fingerprint does not match the key", "signers")
            key = parsed["fingerprint_sha256"]
            prior = (existing_keys or {}).get(key) or {}
            item = {"kind": SIGNER_SSH_KEY, "principal": principal, **parsed,
                    "added_by": str(entry.get("added_by") or prior.get("added_by") or ""),
                    "added_at": str(entry.get("added_at") or prior.get("added_at") or "")}
        else:
            raise SourceError("INVALID_SIGNERS", "signer kind must be OFFICIAL or SSH_KEY", "signers")
        if key in seen:
            raise SourceError("DUPLICATE_SIGNER", "a signer is listed twice", "signers")
        seen.add(key)
        signers.append(item)
    if not signers:
        raise SourceError("NO_SIGNERS", "at least one trusted signer is needed", "signers")
    return ReleaseSource(repository, follow, branch, allow_unsigned, tuple(signers), include_previews, update_check)


def stored_document(src: ReleaseSource, version: int, updated_by: str, updated_at: str) -> Dict[str, Any]:
    return {"repository": src.repository, "follow": src.follow, "branch": src.branch,
            "allow_unsigned": src.allow_unsigned, "signers": [dict(s) for s in src.signers],
            "include_previews": src.include_previews, "update_check": src.update_check,
            "fingerprint": src.fingerprint, "version": version, "updated_by": updated_by, "updated_at": updated_at}


def read_stored(doc: Any) -> ReleaseSource:
    """Validate-on-read: exact stored key set (v1, written before P3a-OFF, or v2 = v1 + `update_check`), every field
    re-validated, the stored fingerprint must match. Raises SourceError("RELEASE_SOURCE_INVALID", ...) on anything
    else (never a silent fallback to the default). A v1 document reads with the update check on (review H-3)."""
    if not isinstance(doc, dict) or set(doc) not in (_STORED_FIELDS_V1, _STORED_FIELDS):
        raise SourceError("RELEASE_SOURCE_INVALID", "the stored release source has unexpected fields")
    if type(doc.get("version")) is not int or doc["version"] < 1:
        raise SourceError("RELEASE_SOURCE_INVALID", "the stored release source has no valid version")
    try:
        src = validate_source(doc)
    except SourceError as e:
        raise SourceError("RELEASE_SOURCE_INVALID", f"the stored release source is invalid ({e.code}: {e.message})",
                          e.field) from None
    if doc.get("fingerprint") != src.fingerprint:
        raise SourceError("RELEASE_SOURCE_INVALID", "the stored fingerprint does not match the stored fields")
    return src


def new_key_fingerprints(old: Optional[ReleaseSource], new: ReleaseSource) -> List[str]:
    before = {s.get("fingerprint_sha256") for s in (old.signers if old else ()) if s["kind"] == SIGNER_SSH_KEY}
    return [s["fingerprint_sha256"] for s in new.signers if s["kind"] == SIGNER_SSH_KEY
            and s["fingerprint_sha256"] not in before]


CONFIRM_SUFFIX_LEN = 6


def check_confirmation(new: ReleaseSource, old: Optional[ReleaseSource], confirm_repository: Any,
                       confirm_key_suffixes: Any) -> None:
    """Typed confirmation: the new repository name exactly, and for every newly trusted key the last 6 characters of
    its SHA256 fingerprint."""
    if confirm_repository != new.repository:
        raise SourceError("CONFIRMATION_REQUIRED", f"type the repository name ({new.repository}) to confirm",
                          "confirm_repository")
    typed = confirm_key_suffixes if isinstance(confirm_key_suffixes, list) else []
    for fp in new_key_fingerprints(old, new):
        if fp[-CONFIRM_SUFFIX_LEN:] not in typed:
            raise SourceError("CONFIRMATION_REQUIRED", f"type the last {CONFIRM_SUFFIX_LEN} characters of the new "
                              f"key's fingerprint ({fp[:-CONFIRM_SUFFIX_LEN]}......) to confirm", "confirm_key_suffixes")


# ------------------------------------------------------------------------------------------------ one change, two writers
VIA_CONTROL_CENTER = "control-center"
VIA_CLI = "cli"
REQUEST_FIELDS = ("repository", "follow", "branch", "allow_unsigned", "include_previews", "signers", "update_check")


def update_check_request(src: ReleaseSource, enabled: bool) -> Dict[str, Any]:
    """The request that keeps every field of `src` and sets only the update check (the switch's route and the
    `update-check` CLI command; stored signer entries validate as they are, `added_by` / `added_at` kept)."""
    return {"repository": src.repository, "follow": src.follow, "branch": src.branch,
            "allow_unsigned": src.allow_unsigned, "include_previews": src.include_previews,
            "signers": [dict(s) for s in src.signers], "update_check": enabled}


@dataclass(frozen=True)
class PlannedChange:
    new: ReleaseSource
    stored: Dict[str, Any]   # the full `current` document (replaces whatever is stored)
    change: Dict[str, Any]   # the never-trimmed `changes/{id}` record
    version: int


def plan_change(requested: Dict[str, Any], current: Optional[ReleaseSource], stored_error: Optional[SourceError],
                stored_version: int, changed_by: str, now_iso: str, confirm_repository: Any,
                confirm_key_suffixes: Any, via: str) -> Optional[PlannedChange]:
    """The one place both writers (the Control Center route and scripts/release-source.py) turn a request into the
    stored document and its change record: validation, typed confirmation, `added_by` / `added_at` for newly trusted
    keys. None when nothing changes. Raises SourceError (validation or confirmation).

    `update_check` absent from the request keeps the value in force (the release-source form does not carry it). A
    change of ONLY the update check (every other field equal to what is in force) needs no typed confirmation: the
    switch neither trusts a new repository or key nor installs anything (plan §3.12, review M-7)."""
    existing_keys = {s["fingerprint_sha256"]: s for s in (current.signers if current else ())
                     if s["kind"] == SIGNER_SSH_KEY}
    before = current if current is not None else (None if stored_error is not None else default_source())
    fields = {k: requested[k] for k in REQUEST_FIELDS if k in requested}
    if "update_check" not in fields:
        fields["update_check"] = before.update_check if before is not None else DEFAULT_UPDATE_CHECK
    new = validate_source(fields, existing_keys)
    switch_only = before is not None and new.fingerprint == before.fingerprint \
        and new.include_previews == before.include_previews and new.update_check != before.update_check
    if not switch_only:
        check_confirmation(new, current, confirm_repository, confirm_key_suffixes)
    signers = []
    for s in new.signers:  # a key trusted by this change records who added it and when
        if s["kind"] == SIGNER_SSH_KEY and s["fingerprint_sha256"] not in existing_keys:
            s = {**s, "added_by": changed_by, "added_at": now_iso}
        signers.append(s)
    new = ReleaseSource(new.repository, new.follow, new.branch, new.allow_unsigned, tuple(signers),
                        new.include_previews, new.update_check)
    if current is not None and current.fingerprint == new.fingerprint \
            and current.include_previews == new.include_previews and current.update_check == new.update_check:
        return None
    version = stored_version + 1
    change = {
        "changed_at": now_iso, "changed_by": changed_by, "via": via, "from_version": stored_version,
        "to_version": version,
        "from": ({**before.decision(), "fingerprint": before.fingerprint, "include_previews": before.include_previews,
                  "update_check": before.update_check}
                 if before is not None else {"invalid_stored_document": True}),
        "to": {**new.decision(), "fingerprint": new.fingerprint, "include_previews": new.include_previews,
               "update_check": new.update_check},
        "from_default": current is None and stored_error is None,
    }
    return PlannedChange(new, stored_document(new, version, changed_by, now_iso), change, version)

"""
FD-4CX: public-exposure check of a registered (non-golden) Terraform module.

Who may use a workload is decided by the workload's access record (``workloads/{pid}.access``, lane 19 / FD-4CS), and
the platform applies it only through the golden compute modules (``compute-cloudrun`` reads ``allow_unauthenticated``,
``enable_direct_iap`` and ``authorized_invoker_members``). A module an administrator registers in Settings > Modules is
vendored into the workload as written, so a module that grants public access by itself would make a Private workload
public. This module finds those grants.

``inspect_module_files(files)`` returns one ``ExposureFinding`` per public-exposure setting in the module's own files:

* ``PUBLIC_MEMBER``: an exact ``allUsers`` / ``allAuthenticatedUsers`` value in an attribute named ``member`` or
  ``members`` of any resource or data block (every ``google_*_iam_member`` / ``_iam_binding`` type: Cloud Run, Cloud
  Functions, Storage, Pub/Sub, ...), in ``binding.members`` of ``data "google_iam_policy"``, or the ``entity`` of a
  ``google_storage_*_access_control`` resource.
* ``PUBLIC_ACL``: a ``role_entity`` entry of a ``google_storage_*_acl`` resource whose entity (after the first ``:``)
  is public, or a ``predefined_acl`` in {publicRead, publicReadWrite, authenticatedRead}.
* ``INVOKER_IAM_DISABLED``: ``invoker_iam_disabled = true`` on ``google_cloud_run_v2_service``, or the Cloud Run v1
  annotation ``run.googleapis.com/invoker-iam-disabled = "true"`` on ``google_cloud_run_service`` (Cloud Run then
  skips the invoker check, so anyone can call the service).
* ``PUBLIC_MODULE_INPUT``: a ``module`` call inside the registered module that passes ``allow_unauthenticated =
  true`` (the golden compute modules' public switch, which only the access record may set).
* ``UNCHECKABLE``: a Terraform / OpenTofu file the parser cannot read (it cannot be shown to be private).

Files: ``.tf`` / ``.tofu`` (python-hcl2) and ``.tf.json`` / ``.tofu.json`` (json); OpenTofu loads all four. A bool
setting is true when it is ``true`` or the string ``"true"`` (OpenTofu converts that string; nothing else).

Values are read from the parsed file (python-hcl2 7.3.1 for ``.tf``, ``json`` for ``.tf.json``), never by searching
the text (AGENTS.md invariant 2). A value that is exactly one bare ``var.NAME`` reference is resolved through that
variable's ``default`` in the same directory, as ``access_policy_validator`` does. Any other expression (a template,
``each.value``, ``jsonencode(...)``) is not a literal and is not judged. Ingress (``INGRESS_TRAFFIC_ALL``) and
``iap_enabled = false`` are not findings: the golden module's private services use the same ingress, and Cloud Run
still requires an authorized caller unless one of the settings above opens it.

The tables are the same as ``apps/orchestrator-gateway/developer_agent/access_policy_validator.py`` (pinned by
``tests/test_fd4cx_registered_module_exposure.py``). Inputs are never mutated.

Replicas (byte-identical, ``tests/test_fd4cx_registered_module_exposure.py``): ``shared/``,
``apps/control-center/shared/``, ``apps/orchestrator-gateway/shared/``.
"""

from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

__all__ = [
    "ExposureFinding",
    "ModuleExposureUnavailable",
    "RegisteredModulePublicExposureError",
    "REGISTERED_MODULE_PUBLIC_EXPOSURE",
    "PUBLIC_MEMBERS",
    "PUBLIC_PREDEFINED_ACLS",
    "STORAGE_ACL_TYPES",
    "STORAGE_ACCESS_CONTROL_TYPES",
    "INVOKER_IAM_DISABLED_TYPES",
    "inspect_module_files",
    "check_registered_module",
    "fetch_remote_module_files",
    "RemoteModuleReadError",
    "modules_under",
]

REGISTERED_MODULE_PUBLIC_EXPOSURE = "REGISTERED_MODULE_PUBLIC_EXPOSURE"

PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
PUBLIC_PREDEFINED_ACLS = frozenset({"publicRead", "publicReadWrite", "authenticatedRead"})
STORAGE_ACL_TYPES = frozenset({
    "google_storage_bucket_acl", "google_storage_default_object_acl", "google_storage_object_acl",
})
STORAGE_ACCESS_CONTROL_TYPES = frozenset({
    "google_storage_bucket_access_control", "google_storage_default_object_access_control",
    "google_storage_object_access_control",
})
INVOKER_IAM_DISABLED_TYPES = frozenset({"google_cloud_run_v2_service"})

# OpenTofu 1.8+ also loads `.tofu` / `.tofu.json` (and prefers them over a `.tf` of the same name): RT F2b
_IAC_SUFFIXES = (".tf", ".tf.json", ".tofu", ".tofu.json")
_JSON_SUFFIXES = (".tf.json", ".tofu.json")
# Cloud Run v1 (`google_cloud_run_service`): the service annotation that turns the invoker check off (RT F2c)
CLOUD_RUN_V1_INVOKER_IAM_DISABLED_ANNOTATION = "run.googleapis.com/invoker-iam-disabled"


class ModuleExposureUnavailable(RuntimeError):
    """python-hcl2 is not importable, so ``.tf`` files cannot be checked (a deployment defect, never a skip)."""


@dataclass(frozen=True)
class ExposureFinding:
    kind: str          # PUBLIC_MEMBER | PUBLIC_ACL | INVOKER_IAM_DISABLED | PUBLIC_MODULE_INPUT | UNCHECKABLE
    file: str          # the file's key as given to inspect_module_files
    address: str       # resource / data address ("" for UNCHECKABLE)
    attribute: str     # attribute path ("" for UNCHECKABLE)
    value: str         # the public value (or the parser error class for UNCHECKABLE)

    def describe(self) -> str:
        if self.kind == "UNCHECKABLE":
            return f"{self.file}: cannot be parsed ({self.value}), so it cannot be checked for public access"
        return f"{self.file}: {self.address} {self.attribute} = {self.value}"


class RegisteredModulePublicExposureError(ValueError):
    """A registered module grants public access by itself (or cannot be checked). ``reason`` is the stable code."""

    reason = REGISTERED_MODULE_PUBLIC_EXPOSURE

    def __init__(self, module_id: str, findings: Iterable[ExposureFinding]):
        self.module_id = module_id
        self.findings = list(findings)
        # `detail`: the message without the code (for callers that add the code themselves)
        self.detail = (
            f"registered module '{module_id}' grants public access by itself: "
            + "; ".join(f.describe() for f in self.findings)
            + ". A registered module may not grant access to allUsers / allAuthenticatedUsers, set a public storage "
              "ACL, turn off the Cloud Run invoker check or pass allow_unauthenticated = true to a module it calls: "
              "who may use a workload is set only by the workload's access record, through the golden compute "
              "modules. Remove these settings from the module."
        )
        super().__init__(f"{REGISTERED_MODULE_PUBLIC_EXPOSURE}: {self.detail}")


# ------------------------------------------------------------------------------------------------ parsing
def _parse(path: str, text: str) -> Mapping[str, Any]:
    if path.endswith(_JSON_SUFFIXES):
        doc = json.loads(text)
        if not isinstance(doc, dict):
            raise ValueError("top-level JSON value is not an object")
        return doc
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt of every service that ships this file)
    except ImportError as e:  # pragma: no cover - environment
        raise ModuleExposureUnavailable("python-hcl2 is not installed; .tf files cannot be checked") from e
    # python-hcl2 rejects a byte-order mark and CRLF line endings, which HCL allows (same as module_inspector)
    return hcl2.loads(text.lstrip("﻿").replace("\r\n", "\n") + "\n") or {}


def _unquote(label: Any) -> Any:
    if isinstance(label, str) and len(label) >= 2 and label[0] == '"' and label[-1] == '"':
        return label[1:-1]
    return label


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _labelled_blocks(doc: Mapping[str, Any], kind: str, depth: int) -> Iterable[Tuple[Tuple[str, ...], Mapping]]:
    """(labels, body) of every top-level ``kind`` block (python-hcl2 lists of dicts and the ``.tf.json`` shape)."""
    def walk(node: Any, labels: Tuple[str, ...]):
        if len(labels) == depth:
            for body in _as_list(node):
                if isinstance(body, Mapping):
                    yield labels, body
            return
        for item in _as_list(node):
            if isinstance(item, Mapping):
                for k, v in item.items():
                    yield from walk(v, labels + (str(_unquote(k)),))

    yield from walk(doc.get(kind), ())


def _literal(v: Any) -> Optional[str]:
    """A literal string (python-hcl2 renders every expression as "${...}"; .tf.json uses the same syntax)."""
    if isinstance(v, str) and "${" not in v:
        return _unquote(v)
    return None


def _true(v: Any) -> bool:
    """A bool setting that is true: the literal ``true``, or the string ``"true"``, which OpenTofu converts to true
    (exact: ``"True"``, ``"1"`` and ``"false"`` are not true; RT F2a)."""
    return v is True or v == "true"


def _single_var_ref(v: Any) -> Optional[str]:
    """NAME when ``v`` is exactly the expression ``${var.NAME}``, else None."""
    if not isinstance(v, str) or not (v.startswith("${var.") and v.endswith("}")):
        return None
    name = v[len("${var."):-1]
    if name and all(c.isalnum() or c in "_-" for c in name):
        return name
    return None


# ------------------------------------------------------------------------------------------------ inspection
def inspect_module_files(files: Mapping[str, str]) -> List[ExposureFinding]:
    """Every public-exposure setting in ``files`` (path -> text of one module's ``.tf`` / ``.tf.json`` files; other
    files are ignored). Empty list = the module grants no public access by itself. Never mutates ``files``.
    Raises ``ModuleExposureUnavailable`` when python-hcl2 is missing."""
    findings: List[ExposureFinding] = []
    parsed: Dict[str, Mapping[str, Any]] = {}
    for path in sorted(files):
        text = files[path]
        if not path.endswith(_IAC_SUFFIXES) or not isinstance(text, str):
            continue
        try:
            parsed[path] = _parse(path, text)
        except ModuleExposureUnavailable:
            raise
        except Exception as e:  # noqa: BLE001 - the parser's error class is the finding
            findings.append(ExposureFinding("UNCHECKABLE", path, "", "", type(e).__name__))

    defaults: Dict[str, Dict[str, Any]] = {}
    for path, doc in parsed.items():
        d = defaults.setdefault(posixpath.dirname(path), {})
        for (name,), body in _labelled_blocks(doc, "variable", 1):
            if "default" in body:
                d[name] = body["default"]

    def resolve(path: str, v: Any) -> Any:
        name = _single_var_ref(v)
        if name is None:
            return v
        return defaults.get(posixpath.dirname(path), {}).get(name, v)

    def literals(path: str, v: Any) -> List[str]:
        out: List[str] = []
        for item in _as_list(resolve(path, v)):
            lit = _literal(resolve(path, item))
            if lit is not None:
                out.append(lit)
        return out

    def add(kind: str, path: str, address: str, attribute: str, value: str) -> None:
        findings.append(ExposureFinding(kind, path, address, attribute, json.dumps(value)))

    for path, doc in parsed.items():
        for kind in ("resource", "data"):
            for (rtype, rname), body in _labelled_blocks(doc, kind, 2):
                address = f"{rtype}.{rname}" if kind == "resource" else f"data.{rtype}.{rname}"
                for attr in ("member", "members"):
                    if attr in body:
                        for m in literals(path, body[attr]):
                            if m in PUBLIC_MEMBERS:
                                add("PUBLIC_MEMBER", path, address, attr, m)
                if kind == "data" and rtype == "google_iam_policy":
                    for binding in _as_list(body.get("binding")):
                        if isinstance(binding, Mapping):
                            for m in literals(path, binding.get("members")):
                                if m in PUBLIC_MEMBERS:
                                    add("PUBLIC_MEMBER", path, address, "binding.members", m)
                if kind != "resource":
                    continue
                if rtype in STORAGE_ACCESS_CONTROL_TYPES and "entity" in body:
                    for entity in literals(path, body["entity"]):
                        if entity in PUBLIC_MEMBERS:
                            add("PUBLIC_MEMBER", path, address, "entity", entity)
                if rtype in STORAGE_ACL_TYPES:
                    for entry in literals(path, body.get("role_entity")):
                        _role, sep, entity = entry.partition(":")
                        if sep and entity in PUBLIC_MEMBERS:
                            add("PUBLIC_ACL", path, address, "role_entity", entry)
                if "predefined_acl" in body:
                    acl = _literal(resolve(path, body["predefined_acl"]))
                    if acl in PUBLIC_PREDEFINED_ACLS:
                        add("PUBLIC_ACL", path, address, "predefined_acl", acl)
                if rtype in INVOKER_IAM_DISABLED_TYPES and "invoker_iam_disabled" in body:
                    if _true(resolve(path, body["invoker_iam_disabled"])):
                        findings.append(ExposureFinding("INVOKER_IAM_DISABLED", path, address,
                                                        "invoker_iam_disabled", "true"))
                if rtype == "google_cloud_run_service":
                    key = CLOUD_RUN_V1_INVOKER_IAM_DISABLED_ANNOTATION
                    for meta in _as_list(body.get("metadata")):
                        ann = meta.get("annotations") if isinstance(meta, Mapping) else None
                        if isinstance(ann, Mapping) and key in ann and _true(resolve(path, ann[key])):
                            findings.append(ExposureFinding("INVOKER_IAM_DISABLED", path, address,
                                                            f'metadata.annotations["{key}"]', "true"))
        # a module call inside the registered module that opens a golden compute module to the public
        for (mname,), body in _labelled_blocks(doc, "module", 1):
            if "allow_unauthenticated" in body and _true(resolve(path, body["allow_unauthenticated"])):
                findings.append(ExposureFinding("PUBLIC_MODULE_INPUT", path, f"module.{mname}",
                                                "allow_unauthenticated", "true"))
    return findings


def check_registered_module(module_id: str, files: Mapping[str, str]) -> None:
    """Raise ``RegisteredModulePublicExposureError`` when ``inspect_module_files(files)`` finds anything."""
    findings = inspect_module_files(files)
    if findings:
        raise RegisteredModulePublicExposureError(module_id, findings)


class RemoteModuleReadError(RuntimeError):
    """A REMOTE_GIT module's repository tree could not be read completely, so the module cannot be checked (RT F4).
    ``transient`` is True when the read itself failed (rate limit, timeout, API error: retry later) and False when the
    repository has more files than the platform reads (it cannot be registered from that repository)."""

    def __init__(self, message: str, transient: bool):
        self.transient = transient
        super().__init__(message)


def fetch_remote_module_files(source_url: str, repo_path: str = "", version_tag: str = "main") -> Dict[str, str]:
    """Every Terraform / OpenTofu file (``_IAC_SUFFIXES``) under a REMOTE_GIT module's directory (``repo_path``, its
    subdirectories included: a module may call ``./sub``; RT F5) at ``version_tag``, keyed by the path relative to the
    module directory (so per-directory variable defaults resolve as in a DIRECT_CODE module). Read with the
    platform's GitHub access (the same provider as the contract read). The tree must be read completely
    (``require_complete``): an incomplete read raises ``RemoteModuleReadError`` (typed by cause) instead of answering
    with part of the module; no files -> ``ValueError``."""
    from shared.module_inspector import parse_github_repo_identifier
    from shared.vcs_provider import IncompleteRepoTreeError, VCSProviderFactory

    repo_id = parse_github_repo_identifier(source_url)
    clean = (repo_path or "").strip().strip("/")
    provider = VCSProviderFactory.get_provider("GITHUB")
    try:
        tree = provider.fetch_file_tree(repo_id, branch=version_tag, require_complete=True)
    except IncompleteRepoTreeError as e:
        if e.tree_status.get("truncated"):
            raise RemoteModuleReadError(
                f"repository '{repo_id}' ({version_tag}) has more files than the platform reads (2,500), so module "
                f"'{clean or '/'}' cannot be read whole and checked for public access; register it from a smaller "
                f"repository", transient=False) from e
        raise RemoteModuleReadError(f"repository '{repo_id}' ({version_tag}) could not be read: "
                                    f"{e.tree_status.get('error') or 'not complete'}; try again later",
                                    transient=True) from e
    base = f"{clean}/" if clean else ""
    own = {p[len(base):]: t for p, t in tree.items() if p.startswith(base) and p.endswith(_IAC_SUFFIXES)}
    if not own:
        raise ValueError(f"no Terraform files in '{clean or '/'}' of '{repo_id}' at '{version_tag}'")
    return own


def modules_under(files: Mapping[str, str], module_ids: Iterable[str],
                  prefix: str = "infra/modules/") -> Dict[str, Dict[str, str]]:
    """{module_id: {path relative to the module directory: text}} for each id in ``module_ids`` that has files under
    ``<prefix><module_id>/`` in ``files`` (exact path prefix of the module directory)."""
    out: Dict[str, Dict[str, str]] = {}
    for mod in sorted(set(module_ids)):
        base = f"{prefix}{mod}/"
        own = {p[len(base):]: t for p, t in files.items() if p.startswith(base)}
        if own:
            out[mod] = own
    return out

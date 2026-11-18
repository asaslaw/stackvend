"""
Workload IaC access-policy validator (Wave 2 lane 19, L19-4; FD-4I; plan §2.3). REPORT ONLY: it never rewrites.

``validate(files, access, platform_owned_paths=...) -> list[dict]`` returns Diagnostic-shaped dicts (lane 8 Part B /
Step 1 ``Diagnostic`` field names; ``disposition`` is lane 19's ask (a) to lane 8). Codes:

* ``POLICY.PUBLIC_PRINCIPAL_FORBIDDEN`` (REPAIR, iac): an exact ``allUsers`` / ``allAuthenticatedUsers`` value in an
  attribute named ``member`` / ``members`` of any resource or data block, in ``binding.members`` of
  ``data "google_iam_policy"``, as the entity of a ``role_entity`` entry of a ``google_storage_*_acl`` resource
  (split on the first ':'), or ``predefined_acl`` in {publicRead, publicReadWrite, authenticatedRead}. A value that is
  exactly one ``var.NAME`` reference is resolved through ``terraform.tfvars`` (root only) and the variable default.
* ``POLICY.ACCESS_POLICY_MISMATCH`` (PLATFORM_DEFECT): a platform-owned key in ``infra/workload/terraform.tfvars``
  (``allow_unauthenticated``, ``enable_direct_iap``, ``authorized_invoker_members``) differs from the AccessPolicy.
* ``POLICY.IDP_CONFIG_IN_IAC`` (REPAIR, iac): an Identity Platform IdP/config resource type in LLM IaC; and, for
  PRIVATE_* workloads (register rows 42/46), any module call whose ``source`` names the golden ``workload_auth`` module.
* ``POLICY.IDP_SECRET_READER_FORBIDDEN`` (REPAIR, iac): in shared-client mode (owner 27b), an IAM ``role`` that carries
  ``firebaseauth.configs.get`` (exact role table, provisional until RT-1), or a custom role listing that permission.
* ``POLICY.PUBLIC_PRINCIPAL_IN_MODULE_CALL`` (REPAIR, iac; FD-4CX-b): PRIVATE_* workloads only. A ``module`` call (any
  source: golden, registered or workload-local) passes an exact ``allUsers`` / ``allAuthenticatedUsers`` value in an
  argument: the argument's literal string, or a string anywhere inside its literal list / set / tuple / object value,
  object keys included (a node that is exactly one ``var.NAME`` is resolved as above; the caller may pass the merged
  root variable files as ``tfvars``). ``attribute_path`` names the exact place (``members[0]``,
  ``bindings["viewer"][1]``, ``member_roles["allUsers"]``). Expressions (``toset([...])``, templates, function calls) are not judged,
  as everywhere in this validator.

Rules (AGENTS.md invariants 1 and 2): exact values on parsed attributes, never substring or regex matching on text;
platform-owned files are excluded by provenance (the caller passes the exact paths); input dicts/strings are never
mutated. ``.tf.json`` files are parsed with ``json``; ``.tf`` files with python-hcl2 (``HclUnavailable`` if the
package is missing: fail loudly, never skip). An unparseable file is reported as ``POLICY.UNCHECKABLE_FILE``.

Integration: Step 1's V2a (``POLICY.PUBLIC_MEMBER`` on ``*_iam_*`` types) overlaps the literal-member part of the
first code; lane 8 V2 / lane 15 own the merge of the two tables (same codes kept by whoever takes them over).
"""

from __future__ import annotations

import json
import posixpath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

# ``access`` is a ``shared.access_policy.AccessPolicy``. It is deliberately NOT imported here: the gateway's committed
# shared/ copy gains access_policy only through lane 12's build-time vendoring (replica rule), and this module reads
# the policy only through its public attributes (mode, sign_in.google, invoker_members(), allow_unauthenticated,
# enable_direct_iap).
AccessPolicy = Any

__all__ = [
    "HclUnavailable",
    "IDP_RESOURCE_TYPES",
    "IDP_SECRET_PERMISSION",
    "IDP_SECRET_READER_ROLES",
    "MODULE_PUBLIC_PRINCIPAL_CODE",
    "PRIVATE_MODES",
    "PUBLIC_MEMBERS",
    "PUBLIC_PREDEFINED_ACLS",
    "validate",
]

PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})   # == shared.module_exposure.PUBLIC_MEMBERS (pinned)
PRIVATE_MODES = ("PRIVATE_IAP", "PRIVATE_IAM")
MODULE_PUBLIC_PRINCIPAL_CODE = "POLICY.PUBLIC_PRINCIPAL_IN_MODULE_CALL"   # FD-4CX-b
PUBLIC_PREDEFINED_ACLS = frozenset({"publicRead", "publicReadWrite", "authenticatedRead"})
STORAGE_ACL_TYPES = frozenset({
    "google_storage_bucket_acl", "google_storage_default_object_acl", "google_storage_object_acl",
})
IDP_RESOURCE_TYPES = frozenset({
    "google_identity_platform_default_supported_idp_config",
    "google_identity_platform_oauth_idp_config",
    "google_identity_platform_config",
})
WORKLOAD_AUTH_MODULE = "workload_auth"
IDP_SECRET_PERMISSION = "firebaseauth.configs.get"
# Roles whose permissions include firebaseauth.configs.get (reads the IdP clientSecret, plan §2.6.1 / RT-1).
# PROVISIONAL until RT-1 lists them from `gcloud iam roles describe`; exact strings only.
IDP_SECRET_READER_ROLES = frozenset({
    "roles/owner", "roles/editor", "roles/viewer",
    "roles/firebase.admin", "roles/firebase.viewer", "roles/firebase.developAdmin", "roles/firebase.developViewer",
    "roles/firebaseauth.admin", "roles/firebaseauth.viewer",
    "roles/identityplatform.admin", "roles/identityplatform.viewer",
})
CUSTOM_ROLE_TYPES = frozenset({"google_project_iam_custom_role", "google_organization_iam_custom_role"})
PLATFORM_TFVARS_KEYS = ("allow_unauthenticated", "enable_direct_iap", "authorized_invoker_members")
ROOT_DIR = "infra/workload"
ROOT_TFVARS = "infra/workload/terraform.tfvars"


class HclUnavailable(RuntimeError):
    """python-hcl2 is not importable, so ``.tf`` files cannot be checked (a deployment defect, never a skip)."""


# ------------------------------------------------------------------------------------------------ parsing
def _parse(path: str, text: str) -> Dict[str, Any]:
    if path.endswith(".tf.json") or path.endswith(".tfvars.json"):
        doc = json.loads(text)
        if not isinstance(doc, dict):
            raise ValueError("top-level JSON value is not an object")
        return doc
    try:
        import hcl2  # python-hcl2 (Step 1 adds python-hcl2==7.3.1 to the gateway requirements)
    except ImportError as e:
        raise HclUnavailable("python-hcl2 is not installed; .tf files cannot be policy-checked") from e
    return hcl2.loads(text)


def _unquote(label: Any) -> Any:
    """Block labels: python-hcl2 versions differ in whether they keep the surrounding quotes (exact syntax only)."""
    if isinstance(label, str) and len(label) >= 2 and label[0] == '"' and label[-1] == '"':
        return label[1:-1]
    return label


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _labelled_blocks(doc: Mapping[str, Any], kind: str, depth: int) -> Iterable[Tuple[Tuple[str, ...], Mapping]]:
    """Yield (labels, body) for top-level ``kind`` blocks; ``depth`` labels (resource/data: 2, module/variable: 1).

    Handles both the python-hcl2 shape (lists of single-key dicts) and the ``.tf.json`` shape (nested objects, a
    body may itself be a list of objects)."""
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
    """A literal string value (python-hcl2 renders expressions as "${...}"; .tf.json uses the same syntax)."""
    if isinstance(v, str) and "${" not in v:
        return _unquote(v)
    return None


def _single_var_ref(v: Any) -> Optional[str]:
    """NAME when ``v`` is exactly the expression ``${var.NAME}`` (a bare variable reference), else None."""
    if not isinstance(v, str) or not (v.startswith("${var.") and v.endswith("}")):
        return None
    name = v[len("${var."):-1]
    if name and all(c.isalnum() or c in "_-" for c in name):
        return name
    return None


def attribute_location(loc: Iterable[Any]) -> str:
    """HCL index syntax from (argument, index | key, ...): ``members[0]``, ``bindings["viewer"][1]``,
    ``member_roles["allUsers"]`` (object keys are always quoted, so a key and an index never look alike)."""
    parts: List[str] = []
    for i, seg in enumerate(loc):
        if i == 0:
            parts.append(str(seg))
        elif isinstance(seg, int):
            parts.append(f"[{seg}]")
        else:
            parts.append(f"[{json.dumps(seg)}]")
    return "".join(parts)


# ------------------------------------------------------------------------------------------------ diagnostics
def _diag(code: str, path: str, address: str, message: str, disposition: str, *, persona: Optional[str] = "iac",
          attribute_path: Optional[str] = None) -> Dict[str, Any]:
    return {
        "tool": "policy",
        "source": "access_policy_validator",
        "code": code,
        "severity": "error",
        "disposition": disposition,
        "persona": persona if disposition == "REPAIR" else None,
        "file": path,
        "block_address": address,
        "attribute_path": attribute_path,
        "message": message,
    }


def _mode_value(access: Any) -> str:
    mode = getattr(access, "mode", None)
    return getattr(mode, "value", mode)


def _google_mode_value(access: Any) -> str:
    g = getattr(getattr(access, "sign_in", None), "google", None)
    return getattr(g, "value", g)


# ------------------------------------------------------------------------------------------------ validate
def validate(files: Mapping[str, str], access: "AccessPolicy", platform_owned_paths: Iterable[str] = (),
             tfvars: Optional[Mapping[str, Any]] = None) -> List[Dict[str, Any]]:
    """Report-only access-policy check of the workload IaC in ``files`` (path -> text). Never mutates its inputs.

    ``tfvars``: the root tfvars as a dict when the caller already has it (tf-applier renders it); otherwise
    ``infra/workload/terraform.tfvars`` in ``files`` is parsed."""
    owned = frozenset(platform_owned_paths)
    mode = _mode_value(access)
    shared_client = _google_mode_value(access) == "SHARED_PLATFORM_CLIENT"
    out: List[Dict[str, Any]] = []

    parsed: Dict[str, Dict[str, Any]] = {}
    for path in sorted(files):
        if not (path.endswith(".tf") or path.endswith(".tf.json")) or path in owned:
            continue
        try:
            parsed[path] = _parse(path, files[path])
        except HclUnavailable:
            raise
        except Exception as e:  # noqa: BLE001 - the parser's message is the finding
            out.append(_diag("POLICY.UNCHECKABLE_FILE", path, "", f"cannot parse for policy checks: "
                             f"{type(e).__name__}", "REPAIR"))

    tfvars = dict(tfvars) if tfvars is not None else {}
    if not tfvars and ROOT_TFVARS in files:
        try:
            import hcl2  # noqa: F401
        except ImportError as e:
            raise HclUnavailable("python-hcl2 is not installed; terraform.tfvars cannot be policy-checked") from e
        try:
            tfvars = hcl2.loads(files[ROOT_TFVARS]) or {}
        except Exception as e:  # noqa: BLE001
            out.append(_diag("POLICY.UNCHECKABLE_FILE", ROOT_TFVARS, "", f"cannot parse for policy checks: "
                             f"{type(e).__name__}", "PLATFORM_DEFECT"))

    # Variable defaults per module directory (resolution of bare var.NAME references).
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
        directory = posixpath.dirname(path)
        if directory == ROOT_DIR and name in tfvars:
            return tfvars[name]
        return defaults.get(directory, {}).get(name, v)

    def literal_members(path: str, v: Any) -> List[str]:
        vals: List[str] = []
        for item in _as_list(resolve(path, v)):
            lit = _literal(resolve(path, item))
            if lit is not None:
                vals.append(lit)
        return vals

    def public_literals(path: str, v: Any, where: Tuple[Any, ...], seen: frozenset = frozenset()
                        ) -> Iterable[Tuple[Tuple[Any, ...], str]]:
        """(location, value) of every exact public principal in the literal value ``v``; the location is the argument
        name followed by list indexes (int) and object keys (str). A node that is exactly one ``var.NAME`` is
        resolved (each variable at most once along a path, so a default that names a variable cannot loop); any
        other expression string is not a literal and is not judged."""
        name = _single_var_ref(v)
        if name is not None:
            if name in seen:
                return
            v, seen = resolve(path, v), seen | {name}
        if isinstance(v, list):
            for i, item in enumerate(v):
                yield from public_literals(path, item, where + (i,), seen)
        elif isinstance(v, Mapping):
            for k, item in v.items():
                key = str(_unquote(k))
                if _literal(key) in PUBLIC_MEMBERS:   # FD-4CX-b RT F1: a module keyed by member (each.key)
                    yield where + (key,), key
                yield from public_literals(path, item, where + (key,), seen)
        else:
            lit = _literal(v)
            if lit in PUBLIC_MEMBERS:
                yield where, lit

    for path, doc in parsed.items():
        for kind in ("resource", "data"):
            for (rtype, rname), body in _labelled_blocks(doc, kind, 2):
                address = f"{rtype}.{rname}" if kind == "resource" else f"data.{rtype}.{rname}"
                # -- public principals
                for attr in ("member", "members"):
                    if attr in body and any(m in PUBLIC_MEMBERS for m in literal_members(path, body[attr])):
                        out.append(_diag("POLICY.PUBLIC_PRINCIPAL_FORBIDDEN", path, address,
                                         f"{address} grants {attr} to allUsers/allAuthenticatedUsers; public access "
                                         f"is configured only by the platform compute module", "REPAIR",
                                         attribute_path=attr))
                if kind == "data" and rtype == "google_iam_policy":
                    for binding in _as_list(body.get("binding")):
                        if isinstance(binding, Mapping) and any(
                                m in PUBLIC_MEMBERS for m in literal_members(path, binding.get("members"))):
                            out.append(_diag("POLICY.PUBLIC_PRINCIPAL_FORBIDDEN", path, address,
                                             f"{address} binding grants allUsers/allAuthenticatedUsers", "REPAIR",
                                             attribute_path="binding.members"))
                if kind == "resource" and rtype in STORAGE_ACL_TYPES:
                    for entry in literal_members(path, body.get("role_entity")):
                        _role, sep, entity = entry.partition(":")
                        if sep and entity in PUBLIC_MEMBERS:
                            out.append(_diag("POLICY.PUBLIC_PRINCIPAL_FORBIDDEN", path, address,
                                             f"{address} role_entity {entry!r} is public", "REPAIR",
                                             attribute_path="role_entity"))
                if kind == "resource" and "predefined_acl" in body:
                    acl = _literal(resolve(path, body["predefined_acl"]))
                    if acl in PUBLIC_PREDEFINED_ACLS:
                        out.append(_diag("POLICY.PUBLIC_PRINCIPAL_FORBIDDEN", path, address,
                                         f"{address} predefined_acl {acl!r} is public", "REPAIR",
                                         attribute_path="predefined_acl"))
                # -- Identity Platform config in LLM IaC (owner 27b: tf-applier configures the IdP by REST)
                if kind == "resource" and rtype in IDP_RESOURCE_TYPES:
                    out.append(_diag("POLICY.IDP_CONFIG_IN_IAC", path, address,
                                     f"{rtype} is configured by the platform, never by workload IaC", "REPAIR"))
                # -- IdP secret readers (shared-client mode only)
                if shared_client and kind == "resource":
                    role = _literal(resolve(path, body.get("role")))
                    if role in IDP_SECRET_READER_ROLES:
                        out.append(_diag("POLICY.IDP_SECRET_READER_FORBIDDEN", path, address,
                                         f"{address} grants {role}, which can read the shared sign-in client secret",
                                         "REPAIR", attribute_path="role"))
                    if rtype in CUSTOM_ROLE_TYPES and IDP_SECRET_PERMISSION in literal_members(
                            path, body.get("permissions")):
                        out.append(_diag("POLICY.IDP_SECRET_READER_FORBIDDEN", path, address,
                                         f"{address} includes {IDP_SECRET_PERMISSION}", "REPAIR",
                                         attribute_path="permissions"))
        # -- workload_auth module in a private workload (rows 42/46)
        if mode in PRIVATE_MODES:
            for (mname,), body in _labelled_blocks(doc, "module", 1):
                src = _literal(body.get("source"))
                if src is not None and posixpath.basename(posixpath.normpath(src)) == WORKLOAD_AUTH_MODULE:
                    out.append(_diag("POLICY.IDP_CONFIG_IN_IAC", path, f"module.{mname}",
                                     f"{mode} workloads get no sign-in module (register rows 42/46)", "REPAIR",
                                     attribute_path="source"))
                # -- a public principal passed to a module call (FD-4CX-b): golden and registered modules alike
                for arg, value in body.items():
                    for loc, lit in public_literals(path, value, (str(_unquote(arg)),)):
                        where = attribute_location(loc)
                        d = _diag(MODULE_PUBLIC_PRINCIPAL_CODE, path, f"module.{mname}",
                                  f"module.{mname} passes {lit} in argument {where}; this {mode} workload may be "
                                  f"reached only by the principals in its access settings, which the platform grants",
                                  "REPAIR", attribute_path=where)
                        d["location"] = list(loc)
                        out.append(d)

    # -- platform-owned tfvars keys vs the authoritative AccessPolicy
    expected = {
        "allow_unauthenticated": bool(getattr(access, "allow_unauthenticated")),
        "enable_direct_iap": bool(getattr(access, "enable_direct_iap")),
        "authorized_invoker_members": sorted(access.invoker_members()),
    }
    for key in PLATFORM_TFVARS_KEYS:
        if key not in tfvars:
            continue
        got = tfvars[key]
        if key == "authorized_invoker_members":
            got = sorted(_literal(m) or repr(m) for m in _as_list(got))
        if got != expected[key] or type(got) is not type(expected[key]):
            out.append(_diag("POLICY.ACCESS_POLICY_MISMATCH", ROOT_TFVARS, key,
                             f"terraform.tfvars {key} does not match the workload AccessPolicy ({mode})",
                             "PLATFORM_DEFECT", persona=None, attribute_path=key))
    return out

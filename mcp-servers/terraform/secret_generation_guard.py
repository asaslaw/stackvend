"""SECRET-INITIAL-VERSION F2 (red-team 11-10): never add the platform's random first version over a secret value that
already exists.

The golden `security-secret` module creates `google_secret_manager_secret_version.generated` (count = its input
`generate_initial_version`, which typed infrastructure renders only for a secret that is new to the repository). A new
version becomes the secret's `latest`, which is what the app reads. When the secret itself already exists in Google
Cloud (adopted by Pass 0 or by the Universal 409 engine, or the version was removed outside OpenTofu), an operator's
value may be there, and the new random version would replace it silently.

Typed rule, read from the exact saved plan the gated apply is about to apply (never from text):
- a resource change of type GENERATED_VERSION_TYPE named GENERATED_VERSION_NAME, index 0, with actions exactly
  ["create"], inside a module (`module_address`), i.e. the module's input is true in this plan;
- and the sibling GENERATED_SECRET_TYPE / GENERATED_SECRET_NAME of the same `module_address` is NOT being created
  (it is in the state: adopted or created earlier).
For each such pair the caller lists the secret's ENABLED versions through the Secret Manager REST API
(`versions_url`). Any enabled version refuses the apply (APPLY.SECRET_GENERATION_WOULD_SHADOW_EXISTING, operator
required); a list that cannot be read refuses it too (APPLY.SECRET_VERSIONS_UNREADABLE): "could not check" is never a
pass. A plan without such a pair (no generated version, or a secret created by the same apply, which has no version)
needs no call: Do No Harm. Pure functions; the REST call is the caller's (service.py, AuthorizedSession).
"""
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import quote

__all__ = ["GENERATED_VERSION_TYPE", "GENERATED_VERSION_NAME", "GENERATED_SECRET_TYPE", "GENERATED_SECRET_NAME",
           "APPLY_SECRET_GENERATION_WOULD_SHADOW_EXISTING", "APPLY_SECRET_VERSIONS_UNREADABLE",
           "ERROR_SECRET_GENERATION_WOULD_SHADOW_EXISTING", "ERROR_SECRET_VERSIONS_UNREADABLE",
           "generated_versions_over_existing_secrets", "versions_url", "enabled_versions", "refusal_result"]

GENERATED_VERSION_TYPE = "google_secret_manager_secret_version"
GENERATED_VERSION_NAME = "generated"
GENERATED_SECRET_TYPE = "google_secret_manager_secret"
GENERATED_SECRET_NAME = "secret"
APPLY_SECRET_GENERATION_WOULD_SHADOW_EXISTING = "APPLY.SECRET_GENERATION_WOULD_SHADOW_EXISTING"
APPLY_SECRET_VERSIONS_UNREADABLE = "APPLY.SECRET_VERSIONS_UNREADABLE"
ERROR_SECRET_GENERATION_WOULD_SHADOW_EXISTING = "SECRET_GENERATION_WOULD_SHADOW_EXISTING"
ERROR_SECRET_VERSIONS_UNREADABLE = "SECRET_VERSIONS_UNREADABLE"


def _values(change: Mapping[str, Any]) -> Mapping[str, Any]:
    after = change.get("after") if isinstance(change.get("after"), dict) else None
    before = change.get("before") if isinstance(change.get("before"), dict) else None
    return after or before or {}


def generated_versions_over_existing_secrets(plan_json: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """One entry {module_address, version_address, secret_address, project, secret_id} per planned create of the
    golden module's generated version whose secret is not created by the same plan, in plan order. `project` /
    `secret_id` are None when the plan does not hold them (the caller refuses: unreadable)."""
    if not isinstance(plan_json, Mapping):
        return []
    changes = [rc for rc in (plan_json.get("resource_changes") or []) if isinstance(rc, dict)]
    secrets: Dict[str, Dict[str, Any]] = {}
    for rc in changes:
        if rc.get("type") == GENERATED_SECRET_TYPE and rc.get("name") == GENERATED_SECRET_NAME \
                and rc.get("mode", "managed") == "managed" and isinstance(rc.get("module_address"), str):
            secrets[rc["module_address"]] = rc
    out: List[Dict[str, Any]] = []
    for rc in changes:
        change = rc.get("change") if isinstance(rc.get("change"), dict) else {}
        module = rc.get("module_address")
        if not (rc.get("type") == GENERATED_VERSION_TYPE and rc.get("name") == GENERATED_VERSION_NAME
                and rc.get("index") == 0 and isinstance(module, str) and change.get("actions") == ["create"]):
            continue
        secret = secrets.get(module)
        if secret is None:   # the module always declares its secret; no sibling in the plan = nothing to compare
            continue
        secret_change = secret.get("change") if isinstance(secret.get("change"), dict) else {}
        if "create" in (secret_change.get("actions") or []):
            continue   # created by this apply: a new secret has no version to shadow
        values = _values(secret_change)
        project, secret_id = values.get("project"), values.get("secret_id")
        out.append({"module_address": module, "version_address": rc.get("address"),
                    "secret_address": secret.get("address"),
                    "project": project if isinstance(project, str) and project else None,
                    "secret_id": secret_id if isinstance(secret_id, str) and secret_id else None})
    return out


def versions_url(project: str, secret_id: str) -> str:
    """The secret's ENABLED versions, one is enough (Secret Manager v1 `projects.secrets.versions.list`)."""
    return (f"https://secretmanager.googleapis.com/v1/projects/{quote(project, safe='')}/secrets/"
            f"{quote(secret_id, safe='')}/versions?filter={quote('state:ENABLED', safe='')}&pageSize=1")


def enabled_versions(status_code: Any, body: Any) -> Optional[int]:
    """The number of enabled versions the list answer shows (0 or more), or None when the answer is not a readable
    200 list (the caller refuses)."""
    if status_code != 200 or not isinstance(body, dict):
        return None
    versions = body.get("versions", [])
    if not isinstance(versions, list):
        return None
    return len(versions)


def refusal_result(product_id: str, trace_id: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The typed apply refusal (status FAILED, operator required; nothing applied). Each finding carries `code`
    (one of the two APPLY_* codes), the secret's address / project / id and a reason."""
    shadow = [f for f in findings if f.get("code") == APPLY_SECRET_GENERATION_WOULD_SHADOW_EXISTING]
    code = APPLY_SECRET_GENERATION_WOULD_SHADOW_EXISTING if shadow else APPLY_SECRET_VERSIONS_UNREADABLE
    error_class = ERROR_SECRET_GENERATION_WOULD_SHADOW_EXISTING if shadow else ERROR_SECRET_VERSIONS_UNREADABLE
    named = "; ".join(f"{f.get('secret_id') or f.get('secret_address')} ({f.get('reason')})" for f in findings[:20])
    if shadow:
        error = (f"{code}: in the plan of '{product_id}', the platform would add its random first version to a "
                 f"secret that already has a value: {named}. A new version would replace that value as the one the "
                 "app reads, so nothing was applied. Keep the existing value: remove the secret's initial_value "
                 "\"random\" from the plan (or the generated version from the workload), or delete the existing "
                 "versions if the value is not needed.")
    else:
        error = (f"{code}: in the plan of '{product_id}', the platform could not check whether these existing secrets "
                 f"already have a value before adding its random first version: {named}. Nothing was applied; run the "
                 "deploy again when Secret Manager can be read.")
    return {"status": "FAILED", "error_class": error_class, "code": code, "error": error, "operator_required": True,
            "secret_generation_findings": findings[:50], "product_id": product_id, "trace_id": trace_id}

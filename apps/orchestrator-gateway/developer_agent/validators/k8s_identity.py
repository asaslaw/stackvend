"""V-K8S-WI (W6e review F5, report only): a Kubernetes service account that names a Google service account for
Workload Identity, but no `roles/iam.workloadIdentityUser` grant lets it act as that account.

| id       | code                            | default mode | when |
| V-K8S-WI | K8S.WORKLOAD_IDENTITY_UNBOUND   | report_only  | a `ServiceAccount` in a manifest the platform applies (`k8s/*.yaml`, also inside a `kind: List`) or a root-module `kubernetes_service_account(_v1)` carries the annotation `iam.gke.io/gcp-service-account`, and no root-module grant of `roles/iam.workloadIdentityUser` names that Kubernetes service account as its member |

Why: the deploy no longer adds such grants (FD-55 W6e deleted the apply-time `inject_gke_workload_identity_bindings`,
which also guessed a Firestore role), and the platform never added them for manifests. Without the grant the pods
start and every Google API call fails at runtime, so the gap would otherwise only show in production.

What counts, by exact type / attribute / annotation key and the documented member grammar (never by name or substring):
- annotated KSA: YAML (`yaml.safe_load_all`) document `kind: ServiceAccount` with `metadata.annotations
  ["iam.gke.io/gcp-service-account"]` set; namespace `metadata.namespace` (absent = `default`). Terraform: a root-module
  `kubernetes_service_account` / `kubernetes_service_account_v1` with the same key in `metadata.annotations`.
  A name or namespace that is not a plain string (an expression) is not judged.
- grant: a root-module `google_service_account_iam_member` (`member`) / `google_service_account_iam_binding`
  (`members`), or a project-level `google_project_iam_member` / `google_project_iam_binding`, with `role` exactly
  `roles/iam.workloadIdentityUser`, whose member is `serviceAccount:<pool>.svc.id.goog[<namespace>/<ksa>]`
  (GKE's documented principal format; `<pool>` is not compared). Which Google account the grant is on is not judged.
- not judged at all (no finding, never a guess): a root-module `.tf` / `.tf.json` file that does not parse, an applied
  manifest that is not YAML (V3c-k8s reports it), a workload-identity grant whose member namespace / name is an
  expression (`${var.ns}` ...), a `google_service_account_iam_policy` / `google_project_iam_policy` (a whole policy
  document), or no YAML parser in the process.
Report only: measured in `report.report_only`, never blocks and never reaches a repair prompt (fail-loudly policy §2,
validator roll-out); the owner decides on `blocking` after measurement (register row K8S-WI-UNBOUND).
"""
from __future__ import annotations

import json
from typing import Any, Iterable, List, Mapping, Optional, Set, Tuple

try:
    from shared.diagnostics import Diagnostic, ErrorClass
    from shared.iac_intent import gke_wi_hint
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore
    from ...shared.iac_intent import gke_wi_hint  # type: ignore

from ..assembly import WORKLOAD, index_blocks
from ..iac_intent_contract import INTENT_PATH, is_intent_tree
from .base import ValidationContext
from .container import K8S_LIST_KIND, applied_k8s_manifest_paths

CODE = "K8S.WORKLOAD_IDENTITY_UNBOUND"
WI_ANNOTATION = "iam.gke.io/gcp-service-account"
WI_ROLE = "roles/iam.workloadIdentityUser"
KSA_KIND = "ServiceAccount"
TF_KSA_TYPES = frozenset({"kubernetes_service_account", "kubernetes_service_account_v1"})
# grant resource type -> its member attribute ("member": one string, "members": a list of strings)
GRANT_TYPES: Mapping[str, str] = {
    "google_service_account_iam_member": "member", "google_service_account_iam_binding": "members",
    "google_project_iam_member": "member", "google_project_iam_binding": "members",
}
POLICY_TYPES = frozenset({"google_service_account_iam_policy", "google_project_iam_policy"})
MEMBER_PREFIX = "serviceAccount:"
POOL_SUFFIX = ".svc.id.goog["
DEFAULT_NAMESPACE = "default"
GRANT_FILE = WORKLOAD + "custom.tf"


class _NotJudged(Exception):
    pass


def _plain(value: Any) -> Optional[str]:
    """A non-empty string without a Terraform interpolation, else None."""
    return value if isinstance(value, str) and value and "${" not in value else None


def parse_wi_member(member: Any) -> Optional[Tuple[str, str]]:
    """(namespace, ksa) of `serviceAccount:<pool>.svc.id.goog[<namespace>/<ksa>]`; None for any other principal.
    Raises _NotJudged when it is a workload-identity member whose namespace / name is an expression."""
    if not isinstance(member, str) or not member.startswith(MEMBER_PREFIX) or not member.endswith("]"):
        return None
    head, sep, inner = member[len(MEMBER_PREFIX):-1].rpartition(POOL_SUFFIX)
    if not sep or not head:
        return None
    ns, slash, ksa = inner.partition("/")
    if not slash or "/" in ksa:
        return None
    if _plain(ns) is None or _plain(ksa) is None:
        raise _NotJudged()
    return ns, ksa


def _root_tf_paths(files: Mapping[str, Any]) -> List[str]:
    return sorted(p for p in files if p.startswith(WORKLOAD) and p.endswith((".tf", ".tf.json"))
                  and "/" not in p[len(WORKLOAD):] and isinstance(files[p], str))


def _resources(path: str, text: str) -> Iterable[Tuple[str, str, Mapping[str, Any], Optional[int]]]:
    """(type, name, body, line) of every resource block of one root-module file (python-hcl2 / json)."""
    if path.endswith(".tf.json"):
        try:
            doc = json.loads(text) if text.strip() else {}
        except ValueError:
            raise _NotJudged() from None
        res = doc.get("resource") if isinstance(doc, dict) else None
        for typ, named in (res.items() if isinstance(res, dict) else ()):
            for name, body in (named.items() if isinstance(named, dict) else ()):
                yield typ, name, body if isinstance(body, dict) else {}, None
        return
    blocks = index_blocks(text)
    if blocks is None:
        raise _NotJudged()
    for b in blocks:
        if b.kind == "resource" and len(b.labels) == 2:
            yield b.labels[0], b.labels[1], b.body or {}, b.start


def _single(value: Any) -> Any:
    """A nested block as python-hcl2 / tf.json render it: a one-element list of an object, or the object."""
    if isinstance(value, list):
        return value[0] if len(value) == 1 else None
    return value


def _ksa_from_metadata(meta: Any) -> Optional[Tuple[str, str]]:
    """(namespace, name) of an annotated KSA's metadata; None when not annotated. _NotJudged for expressions."""
    if not isinstance(meta, dict):
        return None
    annotations = meta.get("annotations")
    if not isinstance(annotations, dict) or annotations.get(WI_ANNOTATION) in (None, ""):
        return None
    name = _plain(meta.get("name"))
    namespace = meta.get("namespace", DEFAULT_NAMESPACE)
    if name is None or _plain(namespace) is None:
        raise _NotJudged()
    return namespace, name


def _manifest_ksas(files: Mapping[str, Any]) -> List[Tuple[str, str, str]]:
    """(file, namespace, name) of every annotated ServiceAccount in the applied manifests."""
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML ships with the gateway
        raise _NotJudged() from None
    out: List[Tuple[str, str, str]] = []
    for p in applied_k8s_manifest_paths(files):
        if not isinstance(files[p], str):
            continue
        try:
            docs = list(yaml.safe_load_all(files[p]))
        except yaml.YAMLError:
            continue   # V3c-k8s reports the manifest; nothing in it can run, so nothing here is judged
        flat: List[Any] = []
        for doc in docs:
            if isinstance(doc, dict) and doc.get("kind") == K8S_LIST_KIND and isinstance(doc.get("items"), list):
                flat.extend(doc["items"])
            else:
                flat.append(doc)
        for doc in flat:
            if isinstance(doc, dict) and doc.get("kind") == KSA_KIND:
                got = _ksa_from_metadata(doc.get("metadata"))
                if got is not None:
                    out.append((p, got[0], got[1]))
    return out


def unbound_service_accounts(files: Mapping[str, Any]) -> Optional[List[Tuple[str, str, str]]]:
    """(file, namespace, name) of every annotated KSA no workload-identity grant names; None when not judged."""
    try:
        ksas = _manifest_ksas(files)
        bound: Set[Tuple[str, str]] = set()
        for path in _root_tf_paths(files):
            for typ, _name, body, _line in _resources(path, files[path]):
                if typ in POLICY_TYPES:
                    raise _NotJudged()
                if typ in TF_KSA_TYPES:
                    got = _ksa_from_metadata(_single(body.get("metadata")))
                    if got is not None:
                        ksas.append((path, got[0], got[1]))
                    continue
                attr = GRANT_TYPES.get(typ)
                if attr is None or body.get("role") != WI_ROLE:
                    continue
                members = body.get(attr)
                for member in members if isinstance(members, list) else [members]:
                    got = parse_wi_member(member)
                    if got is not None:
                        bound.add(got)
    except _NotJudged:
        return None
    return [(f, ns, n) for f, ns, n in ksas if (ns, n) not in bound]


class WorkloadIdentityBindingValidator:
    id, tool = "V-K8S-WI", "yaml"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        unbound = unbound_service_accounts(ctx.files)
        out: List[Diagnostic] = []
        # GKE-WI-INTENT (ex04-1115b): on a typed-intent tree the AI writes no Terraform, so the grant goes in the
        # intent (exact sticky rule iac_intent_contract.is_intent_tree); the legacy tree keeps its custom.tf hint
        intent_tree = is_intent_tree(ctx.files)
        for file, ns, name in unbound or []:
            hint = (f'Add to {INTENT_PATH}, under "resources": ' + gke_wi_hint(ns, name) if intent_tree else
                (f'Add to {GRANT_FILE}: resource "google_service_account_iam_member" with service_account_id = '
                 f'the annotated Google service account\'s `.name`, role = "{WI_ROLE}" and member = '
                 f'"serviceAccount:${{var.project_id}}.svc.id.goog[{ns}/{name}]".'))
            out.append(Diagnostic(
                tool="yaml", code=CODE, severity="warning", error_class=ErrorClass.CODE_DEFECT, source="precommit",
                file=INTENT_PATH if intent_tree else GRANT_FILE, symbol=f"{ns}/{name}", iteration=ctx.iteration,
                message=(f"Kubernetes service account {ns}/{name} ({file}) names a Google service account for Workload "
                         f"Identity, but no {WI_ROLE} grant lets it act as that account; its pods would fail every "
                         "Google API call"),
                hint=hint))
        return out


def register(stack: Any) -> None:
    stack.register(WorkloadIdentityBindingValidator(), "report_only")

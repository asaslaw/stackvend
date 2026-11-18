"""The providers OpenTofu may install for a workload (FD-4AQ W1b, finding AQ-X1a; proposed owner row AQ-6).

This module is the terraform server's single allow-list source. Everything below derives from
PLATFORM_PROVIDER_SOURCES x PROVIDER_REGISTRIES:
  * service.py `_ensure_provider_mirror`: the CLI config (`cli_config`) and the verified mirror's pre-cache
    (MIRROR_PROVIDER_VERSIONS);
  * service.py FD-4AW-b apply content policy (APPLY_PLATFORM_PROVIDER_SOURCES / APPLY_PROVIDER_REGISTRIES /
    APPLY_ALLOWED_PROVIDERS are these objects);
  * validate_service.py (VALIDATE_PROVIDERS / REGISTRIES and its mirror-only CLI config, `cli_config(registry=False)`).
The gateway (a separate deployable) keeps an exact copy in developer_agent/validators/policy_tables.py; tests pin it
equal to this module.

Install rule (`cli_config`): both installation methods carry the same exact `include` list, so OpenTofu (and
Terraform) can install exactly these 8 provider addresses and nothing else. Any other provider, from any registry or
namespace, matches no installation method and `tofu init` fails ("not found in any of the search locations"); the
plugin cache does not bypass this (OpenTofu queries the installation methods even for a locked, cached provider;
checked with tofu 1.9.0). OpenTofu's built-in `terraform` provider is never installed.
  * filesystem_mirror: the platform's verified copies (FD-4BQ: only checksum-verified zips are unpacked there).
  * direct, limited to the same 8 addresses: the official registries (OpenTofu checks each package against the
    registry's published checksums). It stays because `tofu init -upgrade` merges the versions of every matching
    method and selects the newest allowed one; without it every workload would silently move to the mirror's pinned
    versions (google 6.35.0, kubernetes 2.36.0, random 3.7.1) from the newer versions the registry serves (the eval
    oracle mirror, resolved from the registry, holds google 6.50.0, kubernetes 3.3.0, random 3.9.1; see the FD-4AQ W1b
    report). Dropping it is an owner decision.

Typed failure (`disallowed_providers`): when `init` fails, the configuration's provider requirements are read with
python-hcl2 (a real parser) and Terraform's own rules, and every required provider address outside the allow-list is
named (error class PROVIDER_NOT_ALLOWED). The rules: each `required_providers` entry is required (its `source`, else
the implied `hashicorp/<local name>`); each provider local name used by a `provider` block, a resource / data block
(the `provider` meta-argument, else the type label's prefix before the first `_`), a `check` block's nested data
block, an `import` block's `provider`, or a module call's `providers` map maps to that module's `required_providers`
entry, else to `hashicorp/<local name>`. Modules: the root, every local module call (`./` / `../` sources, followed
recursively) and every directory in OpenTofu's own module manifest (`.terraform/modules/modules.json`, written by
`init` before it installs providers, so remote modules count too). Files: `*.tf`, `*.tf.json`, `*.tofu`, `*.tofu.json`.
State (`state_disallowed_providers`): a provider needed only by resources recorded in state is read from
`tofu state pull` JSON (`resources[].provider`), so a state-only provider is typed too (an operator `state rm`s it).
The classification runs only after `init` has already failed, so it never blocks a configuration OpenTofu accepts.
"""
from __future__ import annotations

import json
import logging
import os
import posixpath
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

logger = logging.getLogger("mcp-terraform-provider-allowlist")

# Exact {local name: source}; the validate service's pinned set (Q-S5 utility set, owner) and FD-4AW-a's table.
PLATFORM_PROVIDER_SOURCES = {
    "google": "hashicorp/google",
    "google-beta": "hashicorp/google-beta",
    "kubernetes": "hashicorp/kubernetes",
    "random": "hashicorp/random",
}
# The two registry hosts a short `hashicorp/<type>` source resolves to (OpenTofu / Terraform 1.5.7).
PROVIDER_REGISTRIES = ("registry.opentofu.org", "registry.terraform.io")
BUILTIN_PROVIDER = "terraform.io/builtin/terraform"   # terraform_data / terraform_remote_state; never installed
INSTALLABLE_PROVIDERS = tuple(f"{reg}/{src}" for reg in PROVIDER_REGISTRIES
                              for src in PLATFORM_PROVIDER_SOURCES.values())
# Versions the server pre-caches into its verified mirror (FD-4BQ), per provider type.
MIRROR_PROVIDER_VERSIONS = {
    "google": ("6.35.0", "5.44.0"),
    "google-beta": ("6.35.0", "5.44.0"),
    "kubernetes": ("2.36.0", "2.35.0"),
    "random": ("3.7.1", "3.6.3"),
}
ERROR_PROVIDER_NOT_ALLOWED = "PROVIDER_NOT_ALLOWED"


def cli_config(mirror_dir: str, registry: bool = True) -> str:
    """The exact CLI config of the terraform server's tofu/terraform runs (see the module docstring). `registry=False`
    is the validate service's mirror-only form (no provider egress at all; same include list)."""
    include = "    include = [\n" + ",\n".join(f"      {json.dumps(a)}" for a in INSTALLABLE_PROVIDERS) + "\n    ]\n"
    text = "provider_installation {\n  filesystem_mirror {\n    path = " + json.dumps(mirror_dir) + "\n" + include + "  }\n"
    if registry:
        text += "  direct {\n" + include + "  }\n"
    return text + "}\n"


# ----------------------------------------------------------------------------------------------- classification
_HCL2_KEYWORD_RENDERING = {"None": "null", "True": "true", "False": "false"}   # python-hcl2 renders these keywords
_LOCAL_SOURCE_PREFIXES = ("./", "../")   # Terraform's local-path module source rule (exact prefixes)
_MODULE_MANIFEST = (".terraform", "modules", "modules.json")
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
# OpenTofu loads `*.tf` / `*.tf.json` and (1.8+) `*.tofu` / `*.tofu.json`; a `.tofu` file shadows the same-named `.tf`
# file. Reading both is a superset, which is right for naming providers after init already failed.
_HCL_SUFFIXES = (".tf", ".tofu")
_JSON_SUFFIXES = (".tf.json", ".tofu.json")


def _entries(value: Any) -> List[Dict[str, Any]]:
    """python-hcl2 renders a block kind as a list of dicts; Terraform JSON as one dict (or a list of them)."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _local_name(value: Any) -> Optional[str]:
    """The provider local name of a reference (`google`, `google.west`, `${google.west}`), or None when the value is
    not a plain reference."""
    if not isinstance(value, str):
        return None
    ref = value[2:-1] if value.startswith("${") and value.endswith("}") else value
    name = ref.split(".", 1)[0]
    name = _HCL2_KEYWORD_RENDERING.get(name, name)
    if not name or not name[0].isalpha() or not set(name) <= _NAME_CHARS:
        return None
    return name


def normalize_source(source: Any, default_registry: str) -> Optional[str]:
    """Fully qualified, lower-case provider address of a `source` string (provider addresses are case-insensitive;
    a two-part source gets the engine's default registry host). None for a value that is not a provider address."""
    if not isinstance(source, str):
        return None
    parts = source.strip().lower().split("/")
    if len(parts) == 2:
        parts = [default_registry] + parts
    if len(parts) != 3 or not all(parts):
        return None
    return "/".join(parts)


def is_allowed(address: str) -> bool:
    if address == BUILTIN_PROVIDER:
        return True
    host, _, rest = address.partition("/")
    return host in PROVIDER_REGISTRIES and rest in PLATFORM_PROVIDER_SOURCES.values()


def _load_module_files(module_dir: str) -> List[Dict[str, Any]]:
    """Parsed `*.tf` / `*.tf.json` / `*.tofu` / `*.tofu.json` files of one module directory (not recursive, like
    OpenTofu). A file the parser cannot read is skipped: OpenTofu reports it itself."""
    docs: List[Dict[str, Any]] = []
    try:
        names = sorted(os.listdir(module_dir))
    except OSError:
        return docs
    for name in names:
        path = os.path.join(module_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            if name.endswith(_JSON_SUFFIXES):
                with open(path, "r", encoding="utf-8") as fh:
                    doc = json.load(fh)
            elif name.endswith(_HCL_SUFFIXES):
                import hcl2  # python-hcl2==7.3.1 (requirements.txt)
                with open(path, "r", encoding="utf-8") as fh:
                    doc = hcl2.load(fh)
            else:
                continue
        except Exception as e:  # noqa: BLE001 - unparseable: OpenTofu names it in its own error
            logger.debug(f"provider allow-list: {path} not parsed ({type(e).__name__})")
            continue
        if isinstance(doc, dict):
            docs.append(doc)
    return docs


def _typed_blocks(value: Any) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """(type label, body) of every `resource` / `data` block in a parsed block-kind value."""
    for entry in _entries(value):
        for rtype, by_name in entry.items():
            if rtype.startswith("__"):
                continue
            for named in _entries(by_name):
                for name, body in named.items():
                    if name.startswith("__"):
                        continue
                    yield from ((rtype, b) for b in _entries(body))


def _module_requirements(docs: List[Dict[str, Any]], default_registry: str) -> Tuple[Set[str], List[str]]:
    """(required provider addresses, local module sources) of one module (Terraform's rules, module docstring)."""
    declared: Dict[str, Optional[str]] = {}
    used: Set[str] = set()
    sources: List[str] = []
    for doc in docs:
        for tf in _entries(doc.get("terraform")):
            for rp in _entries(tf.get("required_providers")):
                for local, spec in rp.items():
                    if local.startswith("__"):
                        continue
                    src = spec.get("source") if isinstance(spec, dict) else None
                    declared[local] = normalize_source(src, default_registry) if src is not None else None
        for prov in _entries(doc.get("provider")):
            used.update(k for k in prov if not k.startswith("__"))
        blocks = [*_typed_blocks(doc.get("resource")), *_typed_blocks(doc.get("data"))]
        for check in _entries(doc.get("check")):
            for name, body in check.items():
                if not name.startswith("__"):
                    for inner in _entries(body):
                        blocks.extend(_typed_blocks(inner.get("data")))
        for rtype, body in blocks:
            used.add(_local_name(body.get("provider")) or rtype.split("_", 1)[0])
        for imp in _entries(doc.get("import")):
            name = _local_name(imp.get("provider"))
            if name:
                used.add(name)
        for entry in _entries(doc.get("module")):
            for call_name, call in entry.items():
                if call_name.startswith("__"):
                    continue
                for body in _entries(call):
                    passed = body.get("providers")
                    for target in (passed.values() if isinstance(passed, dict) else ()):
                        name = _local_name(target)
                        if name:
                            used.add(name)
                    src = body.get("source")
                    if isinstance(src, str) and src.startswith(_LOCAL_SOURCE_PREFIXES):
                        sources.append(src)
    addresses: Set[str] = set()
    for local in set(declared) | used:
        address = declared.get(local)
        if address is None:
            address = BUILTIN_PROVIDER if local == "terraform" else f"{default_registry}/hashicorp/{local}"
        addresses.add(address)
    return addresses, sources


def _manifest_dirs(root_dir: str) -> Iterator[str]:
    path = os.path.join(root_dir, *_MODULE_MANIFEST)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError):
        return
    for mod in _entries((manifest or {}).get("Modules") if isinstance(manifest, dict) else None):
        rel = mod.get("Dir")
        if isinstance(rel, str) and rel:
            yield os.path.normpath(os.path.join(root_dir, rel))


def required_providers(root_dir: str, default_registry: str = PROVIDER_REGISTRIES[0]) -> Set[str]:
    """Every provider address the configuration rooted at `root_dir` requires (module docstring)."""
    pending: List[str] = [os.path.normpath(root_dir), *_manifest_dirs(root_dir)]
    seen: Set[str] = set()
    out: Set[str] = set()
    while pending:
        module_dir = pending.pop()
        real = os.path.realpath(module_dir)
        if real in seen or not os.path.isdir(module_dir):
            continue
        seen.add(real)
        addresses, sources = _module_requirements(_load_module_files(module_dir), default_registry)
        out |= addresses
        pending.extend(os.path.normpath(os.path.join(module_dir, *posixpath.normpath(s).split("/"))) for s in sources)
    return out


def disallowed_providers(root_dir: str, default_registry: str = PROVIDER_REGISTRIES[0]) -> List[str]:
    """Sorted provider addresses the configuration requires that OpenTofu may not install ([] when none)."""
    return sorted(a for a in required_providers(root_dir, default_registry) if not is_allowed(a))


def state_disallowed_providers(state_json: str) -> List[str]:
    """Sorted provider addresses outside the allow-list recorded in a `tofu state pull` document (JSON keys only:
    `resources[].provider`, an absolute provider configuration address `[module.<name>.]provider["<address>"][.<alias>]`
    whose bracketed part is a JSON string). Unreadable JSON or an unexpected shape -> [] (the untyped failure stands)."""
    try:
        doc = json.loads(state_json)
    except ValueError:
        return []
    bad: Set[str] = set()
    for res in _entries(doc.get("resources") if isinstance(doc, dict) else None):
        config = res.get("provider")
        if not isinstance(config, str):
            continue
        _, marker, rest = config.partition("provider[")
        quoted, close, _alias = rest.partition("]")
        if not marker or not close:
            continue
        try:
            address = json.loads(quoted)
        except ValueError:
            continue
        norm = normalize_source(address, PROVIDER_REGISTRIES[0]) if isinstance(address, str) else None
        if norm and not is_allowed(norm):
            bad.add(norm)
    return sorted(bad)


def not_allowed_message(addresses: Iterable[str], state_addresses: Iterable[str] = ()) -> str:
    """The typed sentence. `addresses`: required by the configuration; `state_addresses`: recorded only in state."""
    config, state = list(addresses), list(state_addresses)
    parts = [f"{ERROR_PROVIDER_NOT_ALLOWED}:"]
    if config:
        parts.append(f"this workload's Terraform requires {', '.join(config)}, which the platform does not install.")
    if state:
        parts.append(f"This workload's Terraform state records resources of {', '.join(state)}, which the platform "
                     "does not install (recorded in state; an operator removes those resources with `state rm`).")
    parts.append(f"OpenTofu may install only these providers: {', '.join(sorted(PLATFORM_PROVIDER_SOURCES.values()))} "
                 "(from the platform's verified copies or the official registry).")
    if config:
        parts.append("Remove the resources, data sources and provider blocks of that provider.")
    return " ".join(parts)


# ----------------------------------------------------------------------------------------------- pre-init policy
# FD-7L Phase 2b (plan docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, section 2.5; owner OQ-32):
# before the first `tofu init` of every plan / apply / drift / unlock run, the workload Terraform may not configure a
# way to reach a platform token or another state. Exact names only, read with python-hcl2 / json (never a pattern):
#  * POLICY.PROVIDER_ATTRIBUTE_FORBIDDEN: a `provider` block whose local name resolves (through that module's own
#    `required_providers`, else Terraform's implied `hashicorp/<local name>`) to a provider with an attribute table
#    below may set only those attributes and nested blocks (`dynamic "<name>"` counts as block `<name>`). A local name
#    that resolves to a provider without a table (anything outside PLATFORM_PROVIDER_SOURCES) is refused (fail
#    closed). `credentials`, `access_token`, `impersonate_service_account*`, every `*_custom_endpoint`,
#    `universe_domain`, `scopes`, kubernetes `exec` / `config_*` / `client_*` and the like are refused because they
#    are not listed, not because they are named here.
#  * POLICY.REMOTE_STATE_FORBIDDEN: `data "terraform_remote_state"` unless `backend = "gcs"` and `config` is exactly
#    {bucket = <this run's state bucket>, prefix = "workloads/<product_id>"} as literals (FD-4AW-b's rule, pre-init).
#  * POLICY.BACKEND_NOT_PLATFORM: a `backend` block in any file but the root `backend.tf` (which the platform writes;
#    override files included), `terraform { cloud {} }`, and a file named exactly `backend.tofu` / `backend.tofu.json`
#    (OpenTofu loads `<name>.tofu` instead of `<name>.tf`, so it would shadow the platform's `backend.tf`).
#  * POLICY.STATE_ENCRYPTION_FORBIDDEN: `terraform { encryption {} }` (OpenTofu state encryption; a key provider can
#    run a program, and the platform must be able to read the state it migrates and archives).
#  * POLICY.MODULE_SOURCE_NOT_LOCAL: a module call whose source is not a literal `./` / `../` path that the caller's
#    `module_target_allowed` accepts, or that sets `version`.
#  * APPLY.SOURCE_UNPARSEABLE: a configuration file that neither python-hcl2 / json nor OpenTofu's own parser
#    (`tofu fmt`, hcl_utils.hcl_parse_errors) can read. APPLY.SOURCE_NOT_CHECKABLE (review F4): an HCL file python-hcl2
#    cannot read although OpenTofu's parser accepts it (or no OpenTofu binary could decide). Its content cannot be
#    checked, so it is still refused (fail closed), under its own code so the measurement tells "unreadable to the
#    platform" from "forbidden"; the detail names the line python-hcl2 stopped at.
# Files: every `*.tf`, `*.tf.json`, `*.tofu`, `*.tofu.json` OpenTofu loads from the root module and from every local
# module it calls (followed recursively), override files included; names OpenTofu itself ignores (a leading `.`, a
# trailing `~`, `#...#`) are skipped exactly as OpenTofu skips them. The check reports; it never rewrites.
PREINIT_POLICY_STAGE = "preinit_policy"
POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN = "POLICY.PROVIDER_ATTRIBUTE_FORBIDDEN"
POLICY_REMOTE_STATE_FORBIDDEN = "POLICY.REMOTE_STATE_FORBIDDEN"
POLICY_BACKEND_NOT_PLATFORM = "POLICY.BACKEND_NOT_PLATFORM"
POLICY_STATE_ENCRYPTION_FORBIDDEN = "POLICY.STATE_ENCRYPTION_FORBIDDEN"
POLICY_MODULE_SOURCE_NOT_LOCAL = "POLICY.MODULE_SOURCE_NOT_LOCAL"
POLICY_SOURCE_UNPARSEABLE = "APPLY.SOURCE_UNPARSEABLE"   # = service.APPLY_SOURCE_UNPARSEABLE (parity test)
POLICY_SOURCE_NOT_CHECKABLE = "APPLY.SOURCE_NOT_CHECKABLE"
PREINIT_POLICY_CODES = (POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, POLICY_REMOTE_STATE_FORBIDDEN, POLICY_BACKEND_NOT_PLATFORM,
                        POLICY_STATE_ENCRYPTION_FORBIDDEN, POLICY_MODULE_SOURCE_NOT_LOCAL, POLICY_SOURCE_UNPARSEABLE,
                        POLICY_SOURCE_NOT_CHECKABLE)

# `version` (owner F10, 11-01): the deprecated in-block version constraint OpenTofu still accepts; a constraint, never
# a credential or an endpoint, so it is allowed on every provider (with `alias`, a meta-argument of every block).
_PROVIDER_META_ARGUMENTS = frozenset({"alias", "version"})
_GOOGLE_PROVIDER_ATTRIBUTES = frozenset({
    "project", "region", "zone", "user_project_override", "billing_project", "default_labels",
    "add_terraform_attribution_label", "request_timeout", "request_reason", "batching",
}) | _PROVIDER_META_ARGUMENTS
# Exact attribute / nested-block names each installable provider may be configured with (plan 2.5). Keyed by the
# provider source without the registry host; every PLATFORM_PROVIDER_SOURCES value has a table (pinned by a test, R8).
PROVIDER_ATTRIBUTE_ALLOWLIST = {
    "hashicorp/google": _GOOGLE_PROVIDER_ATTRIBUTES,
    "hashicorp/google-beta": _GOOGLE_PROVIDER_ATTRIBUTES,
    "hashicorp/kubernetes": frozenset({"host", "token", "cluster_ca_certificate", "ignore_annotations",
                                       "ignore_labels"}) | _PROVIDER_META_ARGUMENTS,
    "hashicorp/random": _PROVIDER_META_ARGUMENTS,
}
PLATFORM_BACKEND_FILE = "backend.tf"   # the root file the platform writes (service.py prepare_workspace)
BACKEND_SHADOW_FILES = frozenset({"backend.tofu", "backend.tofu.json"})
OVERRIDE_FILE_NAMES = frozenset({"override.tf", "override.tf.json", "override.tofu", "override.tofu.json"})
OVERRIDE_FILE_SUFFIXES = ("_override.tf", "_override.tf.json", "_override.tofu", "_override.tofu.json")
_JSON_COMMENT_KEY = "//"   # Terraform JSON syntax: a "//" property is a comment and ignored
_DYNAMIC_BLOCK = "dynamic"


def is_override_file(name: str) -> bool:
    """OpenTofu's override-file names (an exact name, or one of the exact `_override` suffix forms)."""
    return name in OVERRIDE_FILE_NAMES or name.endswith(OVERRIDE_FILE_SUFFIXES)


def opentofu_ignores(name: str) -> bool:
    """OpenTofu's IsIgnoredFile: a name starting with '.', ending with '~', or starting and ending with '#'."""
    return name.startswith(".") or name.endswith("~") or (name.startswith("#") and name.endswith("#"))


def configuration_files(module_dir: str) -> List[Tuple[str, str]]:
    """(name, path) of every configuration file OpenTofu loads from one module directory (override files included),
    sorted by name. Not recursive, like OpenTofu."""
    try:
        names = sorted(os.listdir(module_dir))
    except OSError:
        return []
    out: List[Tuple[str, str]] = []
    for name in names:
        path = os.path.join(module_dir, name)
        if opentofu_ignores(name) or not os.path.isfile(path):
            continue
        if name.endswith(_JSON_SUFFIXES) or name.endswith(_HCL_SUFFIXES):
            out.append((name, path))
    return out


def provider_table_key(source: Optional[str]) -> Optional[str]:
    """`hashicorp/google` for a fully qualified address on one of PROVIDER_REGISTRIES, else None."""
    if not isinstance(source, str):
        return None
    host, _, rest = source.partition("/")
    return rest if host in PROVIDER_REGISTRIES else None


def _body_keys(body: Dict[str, Any], is_json: bool) -> Set[str]:
    """Attribute and nested-block names of one block body; `dynamic "<name>"` counts as block `<name>`."""
    keys: Set[str] = set()
    for key, value in body.items():
        if is_json and key == _JSON_COMMENT_KEY:
            continue
        if key == _DYNAMIC_BLOCK:
            for dyn in _entries(value):
                keys.update(k for k in dyn if not (is_json and k == _JSON_COMMENT_KEY))
            continue
        keys.add(key)
    return keys


def _local_provider_sources(docs: List[Tuple[str, Dict[str, Any], bool]]) -> Dict[str, Optional[str]]:
    """{local name: fully qualified source, or None for a source that is not a provider address} from one module's
    `required_providers` (an entry without `source` is Terraform's implied `hashicorp/<local name>`)."""
    declared: Dict[str, Optional[str]] = {}
    for _name, doc, is_json in docs:
        for tf in _entries(doc.get("terraform")):
            for rp in _entries(tf.get("required_providers")):
                for local, spec in rp.items():
                    if is_json and local == _JSON_COMMENT_KEY:
                        continue
                    src = spec.get("source") if isinstance(spec, dict) else None
                    declared[local] = (f"{PROVIDER_REGISTRIES[0]}/hashicorp/{local}" if src is None
                                       else normalize_source(src, PROVIDER_REGISTRIES[0]))
    return declared


def _finding(code: str, rel_file: str, detail: str) -> Dict[str, str]:
    return {"code": code, "file": rel_file, "detail": detail}


def _parse_configuration_file(path: str, is_json: bool) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        if is_json:
            return json.load(fh)
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
        return hcl2.load(fh)


def _opentofu_parse_errors(path: str, name: str, parser_bin: Optional[str]) -> Optional[List[str]]:
    """OpenTofu's own parser on one file (hcl_utils.hcl_parse_errors: [] parses, [msg] rejects, None undecided)."""
    try:
        from shared.hcl_utils import hcl_parse_errors
    except ImportError:  # pragma: no cover - loaded without the shared package on sys.path
        from hcl_utils import hcl_parse_errors
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError):
        return None
    return hcl_parse_errors(text, filename=name, parser_bin=parser_bin)


def _unreadable_finding(path: str, name: str, rel_file: str, is_json: bool, err: BaseException,
                        parser_bin: Optional[str]) -> Dict[str, str]:
    """APPLY.SOURCE_UNPARSEABLE when OpenTofu's parser rejects the file too (or it is JSON), else
    APPLY.SOURCE_NOT_CHECKABLE (valid OpenTofu the platform's reader cannot check). Both refuse in PER_WORKLOAD."""
    line = getattr(err, "line", None)
    where = f" at line {line}" if isinstance(line, int) else ""
    if is_json:
        return _finding(POLICY_SOURCE_UNPARSEABLE, rel_file, f"not valid JSON ({type(err).__name__}{where})")
    verdict = _opentofu_parse_errors(path, name, parser_bin)
    if verdict:   # OpenTofu rejects it as well
        return _finding(POLICY_SOURCE_UNPARSEABLE, rel_file,
                        f"neither the platform's parser nor OpenTofu's can read it ({type(err).__name__}{where})")
    return _finding(POLICY_SOURCE_NOT_CHECKABLE, rel_file,
                    f"valid OpenTofu that the platform's reader cannot check ({type(err).__name__}{where}); rewrite "
                    "that construct in plain HCL (for example a conditional on one line, a heredoc assigned to a "
                    "local first)" if verdict == [] else
                    f"the platform's reader cannot check it ({type(err).__name__}{where}) and OpenTofu's parser could "
                    "not decide")


def preinit_policy_findings(root_dir: str, *, product_id: str, state_bucket: str,
                            module_target_allowed: Callable[[str], bool],
                            parser_bin: Optional[str] = None) -> List[Dict[str, str]]:
    """Every pre-init policy finding of the configuration rooted at `root_dir` ([] = allowed); see the section
    comment. Each finding is {"code", "file" (path relative to `root_dir`), "detail"}. `state_bucket`: the bucket this
    run's backend uses (the only one a remote-state data source may read). `module_target_allowed(target)`: the
    workspace rule for a local module directory (`target` is the normalized path relative to the root, for example
    `infra/modules/x` or `../modules/x`)."""
    findings: List[Dict[str, str]] = []
    pending: List[Tuple[str, str]] = [(os.path.normpath(root_dir), ".")]
    seen: Set[str] = set()
    own_config = {"bucket": state_bucket, "prefix": f"workloads/{product_id}"}
    while pending:
        module_dir, rel_dir = pending.pop(0)
        real = os.path.realpath(module_dir)
        if real in seen or not os.path.isdir(module_dir):
            continue
        seen.add(real)
        is_root = rel_dir == "."
        docs: List[Tuple[str, Dict[str, Any], bool]] = []
        for name, path in configuration_files(module_dir):
            rel_file = name if is_root else posixpath.join(rel_dir, name)
            if name in BACKEND_SHADOW_FILES:
                findings.append(_finding(POLICY_BACKEND_NOT_PLATFORM, rel_file,
                                         f"{name} would replace the platform's {PLATFORM_BACKEND_FILE}"))
            is_json = name.endswith(_JSON_SUFFIXES)
            try:
                doc = _parse_configuration_file(path, is_json)
            except Exception as e:  # noqa: BLE001 - content the platform cannot read cannot be checked: fail closed
                findings.append(_unreadable_finding(path, name, rel_file, is_json, e, parser_bin))
                continue
            if not isinstance(doc, dict):
                findings.append(_finding(POLICY_SOURCE_UNPARSEABLE, rel_file, "not a configuration object"))
                continue
            docs.append((name, doc, is_json))
        declared = _local_provider_sources(docs)
        for name, doc, is_json in docs:
            rel_file = name if is_root else posixpath.join(rel_dir, name)
            for tf in _entries(doc.get("terraform")):
                if "backend" in tf and not (is_root and name == PLATFORM_BACKEND_FILE):
                    findings.append(_finding(POLICY_BACKEND_NOT_PLATFORM, rel_file, "backend block"))
                if "cloud" in tf:
                    findings.append(_finding(POLICY_BACKEND_NOT_PLATFORM, rel_file, "terraform { cloud {} }"))
                if "encryption" in tf:
                    findings.append(_finding(POLICY_STATE_ENCRYPTION_FORBIDDEN, rel_file,
                                             "terraform { encryption {} }"))
            for prov in _entries(doc.get("provider")):
                for local, bodies in prov.items():
                    if is_json and local == _JSON_COMMENT_KEY:
                        continue
                    source = declared[local] if local in declared else f"{PROVIDER_REGISTRIES[0]}/hashicorp/{local}"
                    allowed = PROVIDER_ATTRIBUTE_ALLOWLIST.get(provider_table_key(source))
                    if allowed is None:
                        findings.append(_finding(POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, rel_file,
                                                 f'provider "{local}" resolves to '
                                                 f'{source or "a source that is not a provider address"}, which has '
                                                 "no attribute allow-list"))
                        continue
                    for body in _entries(bodies):
                        extra = sorted(_body_keys(body, is_json) - allowed)
                        if extra:
                            findings.append(_finding(POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, rel_file,
                                                     f'provider "{local}" sets {", ".join(extra)}'))
            for rtype, body in _typed_blocks(doc.get("data")):
                if rtype == "terraform_remote_state" and not (
                        state_bucket and body.get("backend") == "gcs" and body.get("config") == own_config):
                    findings.append(_finding(POLICY_REMOTE_STATE_FORBIDDEN, rel_file,
                                             "data terraform_remote_state reads a state other than this workload's "
                                             "own"))
            for entry in _entries(doc.get("module")):
                for call_name, calls in entry.items():
                    if is_json and call_name == _JSON_COMMENT_KEY:
                        continue
                    for body in _entries(calls):
                        src = body.get("source")
                        target = None
                        if isinstance(src, str) and src.startswith(_LOCAL_SOURCE_PREFIXES):
                            target = posixpath.normpath(posixpath.join(rel_dir, src))
                        if "version" in body or target is None or not module_target_allowed(target):
                            findings.append(_finding(POLICY_MODULE_SOURCE_NOT_LOCAL, rel_file,
                                                     f'module "{call_name}" source {src!r} is not a local module '
                                                     "inside the workspace"
                                                     + (" (it sets version)" if "version" in body else "")))
                            continue
                        pending.append((os.path.normpath(os.path.join(module_dir, *src.split("/"))), target))
    return findings


def module_resource_bodies(module_dir: str) -> Optional[Dict[Tuple[str, str], Dict[str, Any]]]:
    """{(resource type, name): body} of one module directory as python-hcl2 / json read it (FD-7L 2b review F1: the
    content policy checks that an unknown identity attribute is a bare reference in the workload's own HCL). None
    when any configuration file cannot be read; a resource that an override file also declares maps to None (its
    effective expression is a merge the platform does not reconstruct), so the caller refuses it."""
    bodies: Dict[Tuple[str, str], Any] = {}
    for name, path in configuration_files(module_dir):
        is_json = name.endswith(_JSON_SUFFIXES)
        try:
            doc = _parse_configuration_file(path, is_json)
        except Exception:  # noqa: BLE001 - unreadable: nothing in this module can be shown to be a bare reference
            return None
        if not isinstance(doc, dict):
            return None
        for entry in _entries(doc.get("resource")):
            for rtype, by_name in entry.items():
                for named in _entries(by_name):
                    for rname, body in named.items():
                        key = (rtype, rname)
                        if is_override_file(name) or key in bodies:
                            bodies[key] = None
                        else:
                            bodies[key] = body if isinstance(body, dict) else None
    return bodies


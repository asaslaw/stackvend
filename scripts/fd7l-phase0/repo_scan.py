#!/usr/bin/env python3
"""
FD-7L Phase 0 (read-only): scan workload repository checkouts for Terraform the planned pre-init allow-list (plan
docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, section 2.5) would refuse, BEFORE that rule exists.

Usage:  python3 scripts/fd7l-phase0/repo_scan.py [--root=infra/workload] [--json] <checkout> [<checkout> ...]

Each <checkout> is a local clone of one workload repository (the orchestrator clones them read-only; this script
never touches the network or the files). Parsing is python-hcl2 (the gateway's pinned parser); `.tf.json` /
`.tofu.json` are JSON. Exact names only (no pattern guessing).

Prints one line per finding: `<repo> <file> <RULE> <detail>`, then `SUMMARY repos=<n> files=<n> findings=<n>
unparseable=<n>`. Rules (the class the pre-init policy would raise):
  BACKEND_NOT_PLATFORM          a backend / cloud block outside <root>/backend.tf (override files included)
  BACKEND_TOFU                  a committed backend.tofu / backend.tofu.json (shadows the platform backend.tf)
  STATE_ENCRYPTION_FORBIDDEN    terraform { encryption {} }
  PROVIDER_ATTRIBUTE_FORBIDDEN  a provider attribute or block outside its allow-list, or an unknown local name
  MODULE_SOURCE_NOT_LOCAL       a module source that is not ./ or ../
  REMOTE_STATE                  data "terraform_remote_state" (allowed later only with the workload's own constants)
  OVERRIDE_FILE                 an override file exists (informational: its contents are checked like any file)
  UNPARSEABLE                   the file does not parse (the pre-init policy refuses it: fail closed)
Exit: 0 no findings, 1 findings, 2 usage error.
"""
import json
import os
import sys

TF_SUFFIXES = (".tf", ".tf.json", ".tofu", ".tofu.json")
SKIP_DIRS = {".git", ".terraform", "node_modules", ".venv"}
OVERRIDE_EXACT = {"override.tf", "override.tf.json", "override.tofu", "override.tofu.json"}
OVERRIDE_SUFFIXES = ("_override.tf", "_override.tf.json", "_override.tofu", "_override.tofu.json")

ALLOWED = {
    "hashicorp/google": {"project", "region", "zone", "alias", "user_project_override", "billing_project",
                         "default_labels", "add_terraform_attribution_label", "request_timeout", "request_reason",
                         "batching"},
    "hashicorp/kubernetes": {"host", "token", "cluster_ca_certificate", "alias", "ignore_annotations",
                             "ignore_labels"},
    "hashicorp/random": {"alias"},
}
ALLOWED["hashicorp/google-beta"] = ALLOWED["hashicorp/google"]
DEFAULT_SOURCES = {"google": "hashicorp/google", "google-beta": "hashicorp/google-beta",
                   "kubernetes": "hashicorp/kubernetes", "random": "hashicorp/random"}


def _norm_source(src):
    if not isinstance(src, str):
        return None
    parts = src.strip().lower().split("/")
    if len(parts) == 3 and parts[0] == "registry.terraform.io":
        parts = parts[1:]
    if len(parts) == 3 and parts[0] == "registry.opentofu.org":
        parts = parts[1:]
    return "/".join(parts) if len(parts) == 2 else None


def _blocks(doc, key):
    """python-hcl2 shape: {"provider": [{"name": {...}}, ...]}; JSON shape: {"provider": {"name": {...} or [...]}}."""
    raw = doc.get(key) if isinstance(doc, dict) else None
    out = []
    for item in raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else []):
        if isinstance(item, dict):
            for name, body in item.items():
                for b in body if isinstance(body, list) else [body]:
                    out.append((name, b if isinstance(b, dict) else {}))
    return out


def _bodies(doc, key):
    """Unlabelled blocks (terraform): python-hcl2 {"terraform": [{...}]}; JSON {"terraform": {...} or [{...}]}."""
    raw = doc.get(key) if isinstance(doc, dict) else None
    return [b for b in (raw if isinstance(raw, list) else [raw]) if isinstance(b, dict)]


def _items(value):
    """A nested block's entries as dicts: hcl2 gives a list of dicts, JSON a dict (or list)."""
    return [v for v in (value if isinstance(value, list) else [value]) if isinstance(v, dict)]


def _load(path):
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    import hcl2
    with open(path, encoding="utf-8") as fh:
        return hcl2.load(fh)


def _is_override(name):
    return name in OVERRIDE_EXACT or name.endswith(OVERRIDE_SUFFIXES)


def _block_keys(body):
    keys = set()
    for k, v in body.items():
        if k == "dynamic":
            for item in v if isinstance(v, list) else [v]:
                if isinstance(item, dict):
                    keys.update(item.keys())     # dynamic "exec" counts as block exec
        else:
            keys.add(k)
    return keys


def scan_repo(repo, root_rel):
    findings, files, unparseable = [], 0, 0
    modules = {}   # dir -> list of (relpath, doc)
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if not fn.endswith(TF_SUFFIXES):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, repo)
            files += 1
            if fn in ("backend.tofu", "backend.tofu.json"):
                findings.append((rel, "BACKEND_TOFU", "shadows the platform backend.tf"))
            if _is_override(fn):
                findings.append((rel, "OVERRIDE_FILE", "override file present"))
            try:
                doc = _load(path)
            except Exception as e:  # noqa: BLE001
                unparseable += 1
                findings.append((rel, "UNPARSEABLE", type(e).__name__))
                continue
            modules.setdefault(os.path.relpath(dirpath, repo), []).append((rel, fn, doc))
    for mdir, docs in modules.items():
        local_names = dict(DEFAULT_SOURCES)
        for _rel, _fn, doc in docs:
            for tf in _bodies(doc, "terraform"):
                for rp in _items(tf.get("required_providers")):
                    for local, spec in rp.items():
                        src = spec.get("source") if isinstance(spec, dict) else None
                        local_names[local] = _norm_source(src) or f"<unresolved {src!r}>"
        for rel, fn, doc in docs:
            for tf in _bodies(doc, "terraform"):
                platform_backend = fn == "backend.tf" and os.path.normpath(mdir) == os.path.normpath(root_rel)
                if "backend" in tf and not platform_backend:
                    findings.append((rel, "BACKEND_NOT_PLATFORM", "backend block"))
                if "cloud" in tf:
                    findings.append((rel, "BACKEND_NOT_PLATFORM", "terraform { cloud {} }"))
                if "encryption" in tf:
                    findings.append((rel, "STATE_ENCRYPTION_FORBIDDEN", "terraform { encryption {} }"))
            for local, body in _blocks(doc, "provider"):
                source = local_names.get(local)
                allowed = ALLOWED.get(source)
                if allowed is None:
                    findings.append((rel, "PROVIDER_ATTRIBUTE_FORBIDDEN", f"provider {local!r} -> {source} has no table"))
                    continue
                extra = sorted(_block_keys(body) - allowed)
                if extra:
                    findings.append((rel, "PROVIDER_ATTRIBUTE_FORBIDDEN", f"provider {local!r}: {', '.join(extra)}"))
            for mname, body in _blocks(doc, "module"):
                src = body.get("source")
                if not (isinstance(src, str) and (src.startswith("./") or src.startswith("../"))):
                    findings.append((rel, "MODULE_SOURCE_NOT_LOCAL", f"module {mname!r} source {src!r}"))
            for dtype, body in _blocks(doc, "data"):
                if dtype == "terraform_remote_state":
                    names = sorted(body.keys())
                    findings.append((rel, "REMOTE_STATE", f"data terraform_remote_state {', '.join(names)}"))
    return findings, files, unparseable


def main(argv):
    root_rel, as_json, repos = "infra/workload", False, []
    for a in argv:
        if a.startswith("--root="):
            root_rel = a.split("=", 1)[1]
        elif a == "--json":
            as_json = True
        elif a.startswith("-"):
            print(__doc__, file=sys.stderr)
            return 2
        else:
            repos.append(a)
    if not repos or not all(os.path.isdir(r) for r in repos):
        print(__doc__, file=sys.stderr)
        return 2
    total, total_files, total_bad, rows = 0, 0, 0, []
    for repo in repos:
        findings, files, bad = scan_repo(repo, root_rel)
        total_files += files
        total_bad += bad
        for rel, rule, detail in findings:
            rows.append({"repo": os.path.basename(os.path.normpath(repo)), "file": rel, "rule": rule,
                         "detail": detail})
            if rule != "OVERRIDE_FILE":
                total += 1
    if as_json:
        print(json.dumps({"findings": rows, "repos": len(repos), "files": total_files}, indent=1))
    else:
        for r in rows:
            print(r["repo"], r["file"], r["rule"], r["detail"])
        print(f"SUMMARY repos={len(repos)} files={total_files} findings={total} unparseable={total_bad}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

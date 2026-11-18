#!/usr/bin/env python3
"""
FD-7L Phase 0 (read-only, offline): list resource / data-source attributes of the installable providers that a human
must review for "can this reach a platform token" (plan section 2.5, re-RT R8), from `tofu providers schema -json`.

Usage:
  python3 scripts/fd7l-phase0/provider_schema_review.py <schema.json> [--json]

Produce <schema.json> once on an operator machine: in an empty directory with a main.tf that requires the four
platform providers (hashicorp/google, google-beta, kubernetes, random at the platform's pinned versions), run
`tofu init -backend=false` and `tofu providers schema -json > schema.json`. This script only reads that file.

An attribute is LISTED FOR REVIEW when its exact name is in REVIEW_NAMES or ends with one of REVIEW_SUFFIXES. This
is a review aid for a person, not a product rule: the product refuses exact attribute names only (section 2.5), and
each listed attribute that can reach a platform token becomes such an exact-name refusal.

Prints `<provider> <resource|data> <type> <attribute>` per listed attribute and `SUMMARY providers=<n> listed=<n>`.
Exit 0 (always, when the file parses), 2 usage error.
"""
import json
import sys

REVIEW_NAMES = {"credentials", "access_token", "token", "kubeconfig", "config_path", "config_paths", "exec",
                "client_certificate", "client_key", "service_account_key", "impersonate_service_account",
                "universe_domain", "private_key", "password"}
REVIEW_SUFFIXES = ("_endpoint", "_credentials", "_token", "_kubeconfig")


def _walk_block(block, path=()):
    for name in (block.get("attributes") or {}):
        yield path + (name,)
    for name, nested in (block.get("block_types") or {}).items():
        yield path + (name,)
        yield from _walk_block(nested.get("block") or {}, path + (name,))


def main(argv):
    files = [a for a in argv if not a.startswith("--")]
    if len(files) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    with open(files[0], encoding="utf-8") as fh:
        schema = json.load(fh)
    rows = []
    providers = schema.get("provider_schemas") or {}
    for provider, ps in sorted(providers.items()):
        for kind, key in (("resource", "resource_schemas"), ("data", "data_source_schemas")):
            for rtype, rs in sorted((ps.get(key) or {}).items()):
                for path in _walk_block(rs.get("block") or {}):
                    leaf = path[-1]
                    if leaf in REVIEW_NAMES or leaf.endswith(REVIEW_SUFFIXES):
                        rows.append((provider, kind, rtype, ".".join(path)))
    if "--json" in argv:
        print(json.dumps([dict(zip(("provider", "kind", "type", "attribute"), r)) for r in rows], indent=1))
    else:
        for r in rows:
            print(*r)
        print(f"SUMMARY providers={len(providers)} listed={len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

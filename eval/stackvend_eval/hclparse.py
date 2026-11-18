"""Structural HCL access via python-hcl2 (eval-only dependency, eval/requirements.txt).

Used for module sources (H6 remote-module refusal), provider names (mock generation), variables, and the invariant
checks. Never used to decide validity: python-hcl2 rejects some valid HCL, so a parse failure here yields
`structure_unavailable`, not "invalid".
"""
from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple

from .paths import add_deps_to_path


class HclUnavailable(RuntimeError):
    pass


def loads(text: str) -> Dict[str, Any]:
    add_deps_to_path()
    try:
        import hcl2
    except Exception as e:  # pragma: no cover - environment dependent
        raise HclUnavailable("python-hcl2 is not installed (pip install -r apps/orchestrator-gateway/requirements.txt, "
                             "or pip install --target eval/.deps -r eval/requirements.txt)") from e
    return hcl2.loads(text)


def parse_tree(tree: Dict[str, str], prefix: str = "") -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """-> ({path: parsed}, {path: error}) for every .tf under prefix."""
    ok, bad = {}, {}
    for path, text in sorted(tree.items()):
        if not path.endswith(".tf") or not path.startswith(prefix):
            continue
        try:
            ok[path] = loads(text)
        except HclUnavailable:
            raise
        except Exception as e:  # noqa: BLE001
            bad[path] = f"{type(e).__name__}: {str(e)[:200]}"
    return ok, bad


def blocks(doc: Dict[str, Any], kind: str) -> Iterator[Tuple[List[str], Dict[str, Any]]]:
    """Yield (labels, body) for `kind` blocks. hcl2 shapes: resource -> [{type: {name: body}}],
    module/variable/output/provider -> [{name: body}], terraform -> [body]."""
    for entry in doc.get(kind, []) or []:
        if not isinstance(entry, dict):
            continue
        if kind == "resource" or kind == "data":
            for typ, named in entry.items():
                if isinstance(named, dict):
                    for name, body in named.items():
                        yield [typ, name], body if isinstance(body, dict) else {}
        elif kind == "terraform":
            yield [], entry
        else:
            for name, body in entry.items():
                yield [name], body if isinstance(body, dict) else {}


def unquote(v: Any) -> Any:
    if isinstance(v, str) and len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def module_sources(parsed: Dict[str, Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    out = []
    for path, doc in parsed.items():
        for labels, body in blocks(doc, "module"):
            src = unquote(body.get("source"))
            out.append((path, labels[0], str(src)))
    return out


def is_local_source(src: str) -> bool:
    return src.startswith("./") or src.startswith("../")


def required_providers(parsed: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    """local name -> source address, from terraform { required_providers { ... } } blocks."""
    out: Dict[str, str] = {}
    for doc in parsed.values():
        for _, body in blocks(doc, "terraform"):
            for rp in body.get("required_providers", []) or []:
                if not isinstance(rp, dict):
                    continue
                for local, spec in rp.items():
                    if isinstance(spec, dict) and spec.get("source"):
                        out[local] = str(unquote(spec["source"]))
                    elif isinstance(spec, str):
                        out.setdefault(local, f"hashicorp/{local}")
    return out


def provider_aliases(parsed: Dict[str, Dict[str, Any]]) -> List[Tuple[str, Optional[str]]]:
    out = []
    for doc in parsed.values():
        for labels, body in blocks(doc, "provider"):
            alias = unquote(body.get("alias")) if body.get("alias") is not None else None
            out.append((labels[0], alias))
    return out


def variables(parsed: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out = {}
    for doc in parsed.values():
        for labels, body in blocks(doc, "variable"):
            out[labels[0]] = body
    return out


def lockfile_providers(text: str) -> List[str]:
    """Provider source addresses from .terraform.lock.hcl (e.g. registry.opentofu.org/hashicorp/google)."""
    doc = loads(text)
    out = []
    for entry in doc.get("provider", []) or []:
        if isinstance(entry, dict):
            out.extend(str(k) for k in entry.keys())
    return out

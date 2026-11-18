#!/usr/bin/env python3
"""Convert AI-written workload HCL (custom.tf / main.tf / ...) into a typed IaC intent (TI-2 measurement; TI-6 reuse).

python-hcl2 7.3.1 parse tree in, `shared.iac_intent.IacIntent` document out. Every block that cannot be expressed gets
a typed CONVERT.* reason; nothing is guessed:
- resource types: allow-listed -> ExtraResource; not-expressible owners (platform / forbidden / topology / lane 11,
  shared/iac_intent/allowed_types.json) -> `excluded` (counted separately); anything else -> CONVERT.TYPE_NOT_ALLOWED.
- module blocks with a local golden source of an AI-instantiable module -> ModuleInstance (FACT / SECRET args dropped:
  the platform renders them).
- expressions are converted from the parse tree: literals, tuples, objects, allow-listed function calls (Call),
  templates (-> Call format), and traversals that resolve EXACTLY (fact table below, declared draft resources,
  draft modules, literal-default variables, locals). Conditionals, operators, for/splat expressions, other functions,
  template directives, interpolated heredocs, data sources, `dynamic` blocks, provisioners -> typed reasons.
- `count = <int literal>` and `for_each = <literal set/list/map>` (incl. toset([...])) are expanded into one entry per
  instance (RT E6: "per-member fan-out that the intent must express as N entries"); indexed references to them resolve
  by literal key; anything else -> CONVERT.META_COUNT / CONVERT.META_FOR_EACH.
- IAM `member`: exact template shapes only -> Member (service account ref or service-agent fact).
- an entry that references an entry that did not convert is itself not converted (CONVERT.DEPENDS_ON_UNCONVERTED).

Library use: `convert_tree(files, artifacts)` -> ConvertResult. CLI (owner-run, TI-6):
  python3 scripts/convert_custom_tf.py <workload-dir> [--json]
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from shared.iac_intent import (MODULE_ARG_CLASS, Artifacts, load_artifacts)  # noqa: E402

IDENT_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
FACT_VARS = {"project_id": "project_id", "region": "region", "product_id": "product_id",
             "container_image": "container_image", "workload_sa_email": "workload_sa_email"}
_PREC = {"||": 1, "&&": 2, "==": 3, "!=": 3, "<": 4, ">": 4, "<=": 4, ">=": 4, "+": 5, "-": 5, "*": 6, "/": 6,
         "%": 6}
_UNDECIDED = object()
CR_OUTPUTS = {"uri": "service_uri", "name": "service_name", "id": "service_id"}
# Raw types the plan makes module-REQUIRED (Q-TI-2: Cloud SQL / Redis / AlloyDB / Spanner / Bigtable): exact typed map
# of the arguments that have a module variable, and of the attributes that have a module output. Everything else in
# the raw block is dropped (noted CONVERT.MAPPED_TO_MODULE, lossy); a reference to an unmapped attribute fails.
MODULE_MAPPINGS = {
    "google_sql_database_instance": {
        "module": "database-cloudsql",
        "args": {("database_version",): "database_version", ("settings", "tier"): "tier",
                 ("deletion_protection",): "deletion_protection"},
        "outputs": {"name": "instance_name", "connection_name": "instance_connection_name"},
    },
}
FOUNDATION_OUTPUT_FACTS = {"workload_sa_email": "workload_sa_email", "docker_repo_id": "docker_repo_id",
                           "database_name": "database_name"}
# (data source type, attribute) -> fact (RT F5: drafts reach these through data sources)
DATA_FACTS = {("google_project", "number"): "project_number", ("google_project", "project_id"): "project_id",
              ("google_storage_project_service_account", "email_address"): "gcs_service_agent",
              ("google_client_config", "project"): "project_id", ("google_client_config", "region"): "region"}
# (platform-owned / lane-11 type, attribute) -> fact. Exact: the foundation output reads exactly this attribute.
OWNED_ATTR_FACTS = {("google_firestore_database", "name"): "database_name",
                    ("google_artifact_registry_repository", "repository_id"): "docker_repo_id",
                    ("google_compute_network", "id"): "network", ("google_compute_network", "self_link"): "network",
                    ("google_compute_network", "name"): "network",
                    ("google_compute_subnetwork", "id"): "subnetwork",
                    ("google_compute_subnetwork", "self_link"): "subnetwork",
                    ("google_compute_subnetwork", "name"): "subnetwork",
                    ("google_vpc_access_connector", "id"): "connector_id"}
PUBSUB_AGENT_SUFFIX = "@gcp-sa-pubsub.iam.gserviceaccount.com"
SA_MEMBER_PREFIX = "serviceAccount:"


class Unconvertible(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason, self.detail = reason, detail


# ------------------------------------------------------------------------------------------------ lark helpers
def _kids(n: Any) -> List[Any]:
    return [c for c in (getattr(n, "children", []) or []) if not (getattr(n, "data", None) and
                                                                   getattr(c, "data", None) == "new_line_or_comment")]


def _data(n: Any) -> Optional[str]:
    return getattr(n, "data", None)


def _ident(n: Any) -> str:
    if _data(n) == "identifier":
        return str(n.children[0])
    if _data(n) == "string":
        return "".join(str(p.children[0]) for p in n.children if _data(p) == "string_part"
                       and not hasattr(p.children[0], "data"))
    return str(n)


_ESC = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


def _unescape(raw: str) -> str:
    """HCL quoted-string escapes (\\n \\r \\t \\" \\\\ \\uNNNN \\UNNNNNNNN) and %%{ -> %{. A lone %{ is a directive."""
    out, i = [], 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nx = raw[i + 1]
            if nx in _ESC:
                out.append(_ESC[nx])
                i += 2
                continue
            if nx == "u" and i + 6 <= len(raw):
                out.append(chr(int(raw[i + 2:i + 6], 16)))
                i += 6
                continue
            if nx == "U" and i + 10 <= len(raw):
                out.append(chr(int(raw[i + 2:i + 10], 16)))
                i += 10
                continue
            raise Unconvertible("CONVERT.STRING_ESCAPE", raw[i:i + 2])
        if raw.startswith("%%{", i):
            out.append("%{")
            i += 3
            continue
        if raw.startswith("%{", i):
            raise Unconvertible("CONVERT.TEMPLATE_DIRECTIVE", raw[i:i + 20])
        out.append(ch)
        i += 1
    return "".join(out)


def _traversal(n: Any) -> Optional[Tuple[str, List[Tuple[str, Any]]]]:
    """Flatten get_attr / index chains: (root identifier, [("attr", name) | ("index", expr-node)])."""
    segs: List[Tuple[str, Any]] = []
    cur = n
    while True:
        d = _data(cur)
        if d == "expr_term" and len(_kids(cur)) == 1:
            cur = _kids(cur)[0]
            continue
        if d == "get_attr_expr_term":
            head, ga = _kids(cur)
            segs.append(("attr", _ident(_kids(ga)[0])))
            cur = head
            continue
        if d == "index_expr_term":
            head, idx = _kids(cur)
            ik = _kids(idx)
            segs.append(("index", ik[0] if ik and hasattr(ik[0], "data") else ("int", str(ik[0]) if ik else "")))
            cur = head
            continue
        if d == "identifier":
            return _ident(cur), list(reversed(segs))
        return None


# ------------------------------------------------------------------------------------------------ result
@dataclass
class EntryReport:
    address: str
    type: str
    file: str
    status: str                 # converted | excluded | failed
    category: str               # allowed | module | platform_owned | forbidden | topology_owned | lane11_owned | ...
    reasons: List[str] = field(default_factory=list)
    instances: int = 1
    details: List[str] = field(default_factory=list)


@dataclass
class ConvertResult:
    intent: Dict[str, Any]
    entries: List[EntryReport]
    notes: collections.Counter
    functions: collections.Counter
    lifecycle: collections.Counter
    data_sources: collections.Counter
    meta: collections.Counter
    parse_errors: List[str]

    @property
    def counted(self) -> List[EntryReport]:
        return [e for e in self.entries if e.status != "excluded"]

    @property
    def expressibility(self) -> Optional[float]:
        c = self.counted
        return (sum(1 for e in c if e.status == "converted") / len(c)) if c else None


# ------------------------------------------------------------------------------------------------ converter
class _Conv:
    def __init__(self, art: Artifacts, services: Mapping[str, Tuple[str, str]]):
        self.art = art
        self.allowed = art.allowed_types
        self.services = services            # module label -> (service name, module id)
        self.resources: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.modules: Dict[str, Dict[str, Any]] = {}
        self.data: Set[Tuple[str, str]] = set()
        self.variables: Dict[str, Any] = {}
        self.locals: Dict[str, Any] = {}
        self.outputs: List[Tuple[str, Any, str]] = []
        self.notes: collections.Counter = collections.Counter()
        self.functions: collections.Counter = collections.Counter()
        self.lifecycle: collections.Counter = collections.Counter()
        self.data_sources: collections.Counter = collections.Counter()
        self.meta: collections.Counter = collections.Counter()
        self.parse_errors: List[str] = []
        self._local_stack: List[str] = []
        self._decide = 0      # > 0 while evaluating a condition / operator operand / for_each collection
        self.deps: Set[Tuple[str, str]] = set()
        self.expanded: Dict[Tuple[str, str], Optional[Dict[Any, str]]] = {}
        self.platform_outputs: Set[str] = set()

    # ---------------------------------------------------------------------------- collection
    def collect(self, files: Mapping[str, str]) -> None:
        import hcl2  # python-hcl2==7.3.1
        for path in sorted(files):
            if not path.endswith(".tf"):
                continue
            try:
                tree = hcl2.parses(files[path])
            except Exception as exc:  # noqa: BLE001 - parser errors are typed below
                self.parse_errors.append(f"{path}: {type(exc).__name__}")
                continue
            body = _kids(tree)[0]
            for b in _kids(body):
                if _data(b) != "block":
                    continue
                kids = _kids(b)
                kind = _ident(kids[0])
                labels = [_ident(k) for k in kids[1:] if _data(k) in ("identifier", "string")]
                inner = next(k for k in kids if _data(k) == "body")
                if kind == "resource" and len(labels) == 2:
                    self.resources[(labels[0], labels[1])] = {"body": inner, "file": path}
                elif kind == "module" and len(labels) == 1:
                    self.modules[labels[0]] = {"body": inner, "file": path}
                elif kind == "data" and len(labels) == 2:
                    self.data.add((labels[0], labels[1]))
                    self.data_sources[labels[0]] += 1
                elif kind == "variable" and len(labels) == 1:
                    attrs = dict(self.attrs(inner))
                    self.variables[labels[0]] = attrs.get("default")
                elif kind == "locals":
                    for name, expr in self.attrs(inner):
                        self.locals[name] = expr
                elif kind == "output" and len(labels) == 1:
                    attrs = dict(self.attrs(inner))
                    if "value" in attrs:
                        self.outputs.append((labels[0], attrs["value"], path))
                else:
                    self.notes[f"block:{kind}"] += 1

    @staticmethod
    def attrs(body: Any) -> List[Tuple[str, Any]]:
        out = []
        for a in _kids(body):
            if _data(a) == "attribute":
                k = _kids(a)
                out.append((_ident(k[0]), k[-1]))
        return out

    @staticmethod
    def blocks(body: Any) -> List[Tuple[str, List[str], Any]]:
        out = []
        for b in _kids(body):
            if _data(b) == "block":
                k = _kids(b)
                labels = [_ident(x) for x in k[1:] if _data(x) in ("identifier", "string")]
                out.append((_ident(k[0]), labels, next(x for x in k if _data(x) == "body")))
        return out

    # ---------------------------------------------------------------------------- expressions
    def expr(self, n: Any, scope: Mapping[str, Any]) -> Any:
        d = _data(n)
        if d == "expr_term":
            kids = _kids(n)
            if len(kids) == 3 and str(kids[0]) == "(":
                return self.expr(kids[1], scope)
            if len(kids) == 1:
                return self.expr(kids[0], scope)
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "expr_term")
        if d == "int_lit":
            return int("".join(str(c) for c in n.children))
        if d == "float_lit":
            return float("".join(str(c) for c in n.children))
        if d == "string":
            return self.template(n, scope)
        if d in ("heredoc_template", "heredoc_template_trim"):
            return self.heredoc(str(n.children[0]), trim=d.endswith("trim"))
        if d == "identifier":
            name = _ident(n)
            if name in ("true", "false"):
                return name == "true"
            if name == "null":
                return None
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", f"bare identifier {name}")
        if d == "tuple":
            return [self.expr(c, scope) for c in _kids(n)]
        if d == "object":
            out: Dict[str, Any] = {}
            for el in _kids(n):
                if _data(el) != "object_elem":
                    continue
                ek = _kids(el)
                keynode = _kids(ek[0])[0]
                if _data(keynode) == "identifier":
                    key = _ident(keynode)
                elif _data(keynode) == "string":
                    key = self.template(keynode, scope)
                    if not isinstance(key, str):
                        raise Unconvertible("CONVERT.TEMPLATED_KEY")
                elif _data(keynode) in ("int_lit", "float_lit"):
                    key = "".join(str(c) for c in keynode.children)
                else:
                    raise Unconvertible("CONVERT.TEMPLATED_KEY")
                if key.startswith("$") or "${" in key or "%{" in key or key == "//":
                    raise Unconvertible("CONVERT.RESERVED_KEY", key)
                out[key] = self.expr(ek[-1], scope)
            return out
        if d == "function_call":
            kids = _kids(n)
            fname = _ident(kids[0])
            self.functions[fname] += 1
            args = []
            if len(kids) > 1 and _data(kids[1]) == "arguments":
                ak = [c for c in _kids(kids[1]) if hasattr(c, "data")]
                if any(str(c) == "..." for c in kids[1].children if not hasattr(c, "data")):
                    raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "argument expansion ...")
                args = [self.expr(a, scope) for a in ak]
            if fname == "toset" and self._decide:   # only a collection whose value decides (for_each)
                if len(args) == 1 and isinstance(args[0], list) and not _has_expr(args[0]):
                    return [json.loads(x) for x in dict.fromkeys(json.dumps(x, sort_keys=True) for x in args[0])]
                raise Unconvertible("CONVERT.META_FOR_EACH", "toset of a non-literal collection")
            if fname not in self.art.functions:
                raise Unconvertible("CONVERT.FUNCTION_NOT_ALLOWED", fname)
            return {"$fn": fname, "$args": args}
        if d == "provider_function_call":
            raise Unconvertible("CONVERT.FUNCTION_NOT_ALLOWED", "provider::")
        if d in ("get_attr_expr_term", "index_expr_term"):
            tr = _traversal(n)
            if tr is None:
                raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "traversal on an expression")
            return self.traverse(tr[0], tr[1], scope)
        if d in ("attr_splat_expr_term", "full_splat_expr_term"):
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "splat")
        if d in ("for_tuple_expr", "for_object_expr"):
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "for expression")
        if d == "conditional":
            c, t, f = [k for k in _kids(n) if hasattr(k, "data")]
            return self.expr(t if self.truth(self.decided(c, scope)) else f, scope)
        if d == "binary_op":
            return self.binary(n, scope)
        if d == "unary_op":
            op, operand = str(n.children[0]), [k for k in n.children if hasattr(k, "data")][0]
            v = self.literal_of(self.expr(operand, scope))
            if op == "!" and isinstance(v, bool):
                return not v
            if op == "-" and isinstance(v, (int, float)) and not isinstance(v, bool):
                return -v
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "undecidable operator")
        raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", str(d))

    # ---------------------------------------------------------------------------- partial evaluation
    # python-hcl2 7.3.1 parses `a != "" ? 1 : 0` as binary_op(a, !=, conditional("", 1, 0)) and every operator chain
    # right-associatively without precedence. `flatten` re-reads the chain (operands / operators / a trailing
    # unparenthesized conditional) and `binary` re-applies HCL precedence. Values are decided only from literals,
    # literal variable defaults and platform facts (a fact is a known, non-empty, non-null string).
    def flatten(self, n: Any) -> Tuple[List[Any], List[str], Optional[Tuple[Any, Any]]]:
        kids = [k for k in _kids(n) if hasattr(k, "data")]
        left, bt = kids[0], kids[1]
        btk = [k for k in _kids(bt) if hasattr(k, "data")]
        op = str(btk[0].children[0])
        right = btk[-1]
        if _data(right) == "binary_op":
            o2, ops2, tail = self.flatten(right)
            return [left] + o2, [op] + ops2, tail
        if _data(right) == "conditional":
            c, t, f = [k for k in _kids(right) if hasattr(k, "data")]
            if _data(c) == "binary_op":
                o2, ops2, tail2 = self.flatten(c)
                if tail2 is not None:
                    raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "nested conditional")
                return [left] + o2, [op] + ops2, (t, f)
            return [left, c], [op], (t, f)
        return [left, right], [op], None

    def literal_of(self, v: Any) -> Any:
        if isinstance(v, dict) and "$ref" in v and v["$ref"].get("kind") == "fact":
            return _FactValue(v["$ref"]["fact"])
        if isinstance(v, dict) and v.get("$fn") == "length" and len(v.get("$args") or []) == 1:
            a = self.literal_of(v["$args"][0])
            if isinstance(a, (str, list, dict)) and not _has_expr(a):
                return len(a)
        if _has_expr(v):
            return _UNDECIDED
        return v

    def apply(self, op: str, a: Any, b: Any) -> Any:
        if a is _UNDECIDED or b is _UNDECIDED:
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "undecidable operator")
        if op in ("==", "!="):
            if isinstance(a, _FactValue) or isinstance(b, _FactValue):
                other = b if isinstance(a, _FactValue) else a
                if other == "" or other is None:
                    return op == "!="
                raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "undecidable comparison with a fact")
            same = (type(a) is type(b) or (isinstance(a, (int, float)) and isinstance(b, (int, float))
                                            and not isinstance(a, bool) and not isinstance(b, bool))) and a == b
            return same if op == "==" else not same
        if op in ("&&", "||"):
            if isinstance(a, bool) and isinstance(b, bool):
                return (a and b) if op == "&&" else (a or b)
        elif all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (a, b)):
            if op == "<":
                return a < b
            if op == ">":
                return a > b
            if op == "<=":
                return a <= b
            if op == ">=":
                return a >= b
            if op == "+":
                return a + b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "/" and b != 0:
                return a / b
            if op == "%" and b != 0:
                return a % b
        raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", f"operator {op} on these operands")

    def binary(self, n: Any, scope: Mapping[str, Any]) -> Any:
        operands, ops, tail = self.flatten(n)
        vals = [self.literal_of(self.decided(o, scope)) for o in operands]
        out_vals, out_ops = [vals[0]], []
        for op, v in zip(ops, vals[1:]):         # precedence climbing over the flat chain
            while out_ops and _PREC[out_ops[-1]] >= _PREC[op]:
                b, a = out_vals.pop(), out_vals.pop()
                out_vals.append(self.apply(out_ops.pop(), a, b))
            out_ops.append(op)
            out_vals.append(v)
        while out_ops:
            b, a = out_vals.pop(), out_vals.pop()
            out_vals.append(self.apply(out_ops.pop(), a, b))
        result = out_vals[0]
        self.notes["operator_evaluated"] += 1
        if tail is not None:
            return self.expr(tail[0] if self.truth(result) else tail[1], scope)
        if isinstance(result, _FactValue):
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "operator result")
        return result

    def decided(self, n: Any, scope: Mapping[str, Any]) -> Any:
        """Convert `n` where only its VALUE matters to a decision (condition, operand, for_each collection)."""
        self._decide += 1
        try:
            return self.expr(n, scope)
        finally:
            self._decide -= 1

    def truth(self, v: Any) -> bool:
        v = self.literal_of(v) if not isinstance(v, (bool, _FactValue)) else v
        if isinstance(v, bool):
            self.notes["condition_decided"] += 1
            return v
        raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "undecidable condition")

    def template_parts(self, n: Any, scope: Mapping[str, Any]) -> List[Any]:
        parts: List[Any] = []
        for p in n.children:
            if _data(p) != "string_part":
                continue
            c = p.children[0]
            if hasattr(c, "data") and c.data == "interpolation":
                parts.append(("expr", self.expr(_kids(c)[0], scope)))
            elif getattr(c, "type", "") == "ESCAPED_INTERPOLATION":
                parts.append(_unescape(str(c)[1:]))          # $${x} -> ${x}
            else:
                parts.append(_unescape(str(c)))
        merged: List[Any] = []
        for p in parts:
            if isinstance(p, str) and merged and isinstance(merged[-1], str):
                merged[-1] += p
            else:
                merged.append(p)
        return merged

    def template(self, n: Any, scope: Mapping[str, Any]) -> Any:
        parts = self.template_parts(n, scope)
        if not parts:
            return ""
        if len(parts) == 1:
            return parts[0][1] if isinstance(parts[0], tuple) else parts[0]
        if all(isinstance(p, str) for p in parts):
            return "".join(parts)
        fmt, args = "", []
        for p in parts:
            if isinstance(p, tuple):
                fmt += "%s"
                args.append(p[1])
            else:
                fmt += p.replace("%", "%%")
        self.notes["template->format"] += 1
        if "format" not in self.art.functions:
            raise Unconvertible("CONVERT.FUNCTION_NOT_ALLOWED", "format")
        return {"$fn": "format", "$args": [fmt] + args}

    def heredoc(self, raw: str, *, trim: bool) -> str:
        lines = raw.split("\n")
        body = lines[1:-2] if lines[-1] == "" else lines[1:-1]
        if trim:
            ind = min((len(ln) - len(ln.lstrip(" \t")) for ln in body if ln.strip()), default=0)
            body = [ln[ind:] for ln in body]
        text = "\n".join(body) + "\n"
        scan = text.replace("$${", "").replace("%%{", "")
        if "${" in scan or "%{" in scan:
            raise Unconvertible("CONVERT.HEREDOC_TEMPLATE")
        return text.replace("$${", "${").replace("%%{", "%{")

    @staticmethod
    def ref(**kw: Any) -> Dict[str, Any]:
        return {"$ref": dict(kw)}

    def index_key(self, seg: Any, scope: Mapping[str, Any]) -> Any:
        if isinstance(seg, tuple):
            return int(seg[1])
        v = self.expr(seg, scope)
        if isinstance(v, (int, str)) and not isinstance(v, bool):
            return v
        raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "computed index")

    def traverse(self, root: str, segs: List[Tuple[str, Any]], scope: Mapping[str, Any]) -> Any:
        attrs = [s[1] for s in segs if s[0] == "attr"]
        if attrs and len(segs) == 1 and f"{root}.{attrs[0]}" in scope:      # each.* / count.index / dynamic iterator
            return scope[f"{root}.{attrs[0]}"]
        if root in ("each", "count"):
            key = f"{root}.{attrs[0]}" if attrs else root
            if key in scope and len(segs) == 1:
                return scope[key]
            raise Unconvertible("CONVERT.META_REFERENCE", key)
        if root == "var":
            if not segs or segs[0][0] != "attr":
                raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "var")
            name = segs[0][1]
            if len(segs) > 1:
                raise Unconvertible("CONVERT.UNRESOLVED_VARIABLE", f"var.{name} with traversal")
            if name in FACT_VARS:
                return self.ref(kind="fact", fact=FACT_VARS[name])
            default = self.variables.get(name)
            if default is not None:
                v = self.expr(default, scope)
                if v in ("", None) and not self._decide:
                    # an AI input nobody sets (the platform never writes tfvars for AI variables): as a value it is
                    # a missing input, not the literal "" (in a condition its default decides the branch)
                    raise Unconvertible("CONVERT.UNSET_VARIABLE", f"var.{name}")
                self.notes["variable_default_inlined"] += 1
                return v
            raise Unconvertible("CONVERT.UNRESOLVED_VARIABLE", f"var.{name}")
        if root == "local":
            name = segs[0][1] if segs and segs[0][0] == "attr" else ""
            if name not in self.locals or len(segs) > 1 or name in self._local_stack:
                raise Unconvertible("CONVERT.UNRESOLVED_LOCAL", f"local.{name}")
            self._local_stack.append(name)
            try:
                self.notes["local_inlined"] += 1
                return self.expr(self.locals[name], scope)
            finally:
                self._local_stack.pop()
        if root == "module":
            if len(segs) < 2 or segs[0][0] != "attr" or segs[1][0] != "attr" or len(segs) > 2:
                raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "module traversal")
            label, out = segs[0][1], segs[1][1]
            if label == "foundation":
                if out in FOUNDATION_OUTPUT_FACTS:
                    return self.ref(kind="fact", fact=FOUNDATION_OUTPUT_FACTS[out])
                raise Unconvertible("CONVERT.PLATFORM_OUTPUT", f"module.foundation.{out}")
            if label in self.services:
                return self.ref(kind="service", service=self.services[label][0], output=out)
            if label in self.modules:
                self.deps.add(("module", label))
                return self.ref(kind="module_output", module=label, output=out)
            raise Unconvertible("CONVERT.UNDECLARED_REFERENCE", f"module.{label}")
        if root == "data":
            if len(attrs) < 3:
                raise Unconvertible("CONVERT.DATA_SOURCE", "data")
            key = (attrs[0], attrs[2])
            if key in DATA_FACTS and (attrs[0], attrs[1]) in self.data and len(segs) == 3:
                self.notes["data_source->fact"] += 1
                return self.ref(kind="fact", fact=DATA_FACTS[key])
            raise Unconvertible("CONVERT.DATA_SOURCE", f"data.{attrs[0]}")
        if root in ("path", "terraform", "self"):
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", root)
        # <type>.<name>[...].<attr>...
        if not segs or segs[0][0] != "attr":
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", root)
        rtype, name = root, segs[0][1]
        rest = segs[1:]
        inst_key = None
        if rest and rest[0][0] == "index" and self.expanded.get((rtype, name)) is not None:
            inst_key = self.index_key(rest[0][1], scope)
            rest = rest[1:]
        if (rtype, name) not in self.resources:
            raise Unconvertible("CONVERT.UNDECLARED_REFERENCE", f"{rtype}.{name}")
        if (rtype, name) in self.mapped:
            outs = MODULE_MAPPINGS[rtype]["outputs"]
            if len(rest) == 1 and rest[0][0] == "attr" and rest[0][1] in outs:
                self.deps.add(("module", name))
                return self.ref(kind="module_output", module=name, output=outs[rest[0][1]])
            raise Unconvertible("CONVERT.UNMAPPED_MODULE_ATTRIBUTE",
                                f"{rtype}.{name}.{'.'.join(str(x[1]) for x in rest)}")
        owner = self.art.not_expressible_owner(rtype)
        if owner is not None or rtype not in self.allowed:
            if len(rest) == 1 and rest[0][0] == "attr" and (rtype, rest[0][1]) in OWNED_ATTR_FACTS:
                self.notes["owned_reference->fact"] += 1
                return self.ref(kind="fact", fact=OWNED_ATTR_FACTS[(rtype, rest[0][1])])
            if owner == "topology_owned" and rtype == "google_cloud_run_v2_service" and len(rest) == 1:
                crs = [k for k in self.resources if k[0] == "google_cloud_run_v2_service"]
                if len(crs) == 1 and len(self.services) == 1 and rest[0][1] in CR_OUTPUTS:
                    # exactly one AI-declared Cloud Run service and exactly one topology service: the same service
                    self.notes["topology_reference->service_ref"] += 1
                    return self.ref(kind="service", service=next(iter(self.services.values()))[0],
                                    output=CR_OUTPUTS[rest[0][1]])
                raise Unconvertible("CONVERT.TOPOLOGY_REFERENCE", f"{rtype}.{name}.{rest[0][1]}")
            raise Unconvertible("CONVERT.UNCONVERTED_REFERENCE", f"{rtype}.{name} ({owner or 'not allowed'})")
        block_key = (rtype, name)
        exp = self.expanded.get((rtype, name))
        if exp is not None:
            if inst_key is None or inst_key not in exp:
                raise Unconvertible("CONVERT.INDEXED_REFERENCE", f"{rtype}.{name}")
            name = exp[inst_key]
        path = ""
        for kind, v in rest:
            if kind == "attr":
                path += ("." if path else "") + v
            else:
                k = self.index_key(v, scope)
                if not isinstance(k, int):
                    raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "map index on a resource attribute")
                path += f"[{k}]"
        if not path:
            raise Unconvertible("CONVERT.UNSUPPORTED_EXPRESSION", "whole-resource reference")
        self.deps.add(block_key)
        return self.ref(kind="resource_attr", type=rtype, name=name, attr=path)

    # ---------------------------------------------------------------------------- members
    def member(self, n: Any, scope: Mapping[str, Any]) -> Dict[str, Any]:
        d = n
        while _data(d) == "expr_term" and len(_kids(d)) == 1:
            d = _kids(d)[0]
        if _data(d) == "string":
            parts = self.template_parts(d, scope)
            if len(parts) == 2 and parts[0] == SA_MEMBER_PREFIX and isinstance(parts[1], tuple):
                v = parts[1][1]
                if isinstance(v, dict) and "$ref" in v:
                    r = v["$ref"]
                    if r.get("kind") == "fact" and r.get("fact") in ("gcs_service_agent", "pubsub_service_agent"):
                        return {"$member": {"service_agent": r["fact"]}}
                    return {"$member": {"service_account": v}}
            if (len(parts) == 3 and parts[0] == SA_MEMBER_PREFIX + "service-" and isinstance(parts[1], tuple)
                    and parts[2] == PUBSUB_AGENT_SUFFIX and parts[1][1] == self.ref(kind="fact", fact="project_number")):
                return {"$member": {"service_agent": "pubsub_service_agent"}}
            raise Unconvertible("CONVERT.MEMBER_NOT_TYPED", "literal or untyped member")
        tr = _traversal(d)
        if tr and tr[0] not in ("var", "local", "module", "data", "each", "count") and len(tr[1]) == 2 \
                and tr[1][1] == ("attr", "member") and tr[0] == "google_service_account":
            v = self.traverse(tr[0], [tr[1][0], ("attr", "email")], scope)
            return {"$member": {"service_account": v}}
        raise Unconvertible("CONVERT.MEMBER_NOT_TYPED", "member expression")

    # ---------------------------------------------------------------------------- bodies
    def body(self, body: Any, scope: Mapping[str, Any], rtype: str, *, top: bool,
             path: str = "") -> Tuple[Dict[str, Any], Dict]:
        out: Dict[str, Any] = {}
        extra: Dict[str, Any] = {}
        spec = self.allowed.get(rtype) or {}
        targets = spec.get("target_ref_only") or {}
        for name, expr in self.attrs(body):
            if top and name in ("count", "for_each"):
                continue
            if top and name == "depends_on":
                extra["depends_on"] = expr
                continue
            if top and name == "provider":
                self.meta["provider"] += 1
                continue
            rp = f"{path}.{name}" if path else name
            try:
                out[name] = (self.member(expr, scope) if top and name == "member" and spec.get("iam")
                             else self.expr(expr, scope))
                if rp in targets and isinstance(out[name], str):
                    out[name] = self.target_literal(out[name], targets[rp], rp)
            except Unconvertible as exc:
                raise Unconvertible(exc.reason, f"{name}: {exc.detail}") from None
        for kind, labels, inner in self.blocks(body):
            if kind == "dynamic":
                self.meta["dynamic"] += 1
                for bname, val in self.dynamic(labels, inner, scope, rtype, path):
                    if bname in out:
                        out[bname] = (out[bname] if isinstance(out[bname], list) else [out[bname]]) + [val]
                    else:
                        out[bname] = val
                continue
            if top and kind in ("provisioner", "connection"):
                raise Unconvertible("CONVERT.PROVISIONER", kind)
            if top and kind == "lifecycle":
                extra["lifecycle"] = self.lifecycle_block(inner)
                continue
            val, _ = self.body(inner, scope, rtype, top=False, path=f"{path}.{kind}" if path else kind)
            if kind in out:
                out[kind] = (out[kind] if isinstance(out[kind], list) else [out[kind]]) + [val]
            else:
                out[kind] = val
        return out, extra

    def target_literal(self, lit: str, shapes: Sequence[Sequence[str]], rp: str) -> Dict[str, Any]:
        """RT TI-2 F1/F2: an IAM target / data destination written as a literal converts only when it EQUALS the
        literal attribute of exactly one declared resource of a listed shape (same object); else CONVERT.TARGET_LITERAL."""
        hits = []
        for shape in shapes:
            if shape[0] != "resource_attr":
                continue
            for (t, n), info in self.resources.items():
                if t != shape[1] or self.expanded.get((t, n)) is not None or (t, n) not in self.expanded:
                    continue
                node = dict(self.attrs(info["body"])).get(shape[2])
                if node is None:
                    continue
                try:
                    if self.expr(node, {}) == lit:
                        hits.append((t, n, shape[2]))
                except Unconvertible:
                    continue
        if len({(t, n) for t, n, _a in hits}) == 1:
            t, n, a = hits[0]
            self.deps.add((t, n))
            self.notes["target_literal->ref"] += 1
            return self.ref(kind="resource_attr", type=t, name=n, attr=a)
        raise Unconvertible("CONVERT.TARGET_LITERAL", rp)

    def dynamic(self, labels: List[str], inner: Any, scope: Mapping[str, Any], rtype: str,
                path: str = "") -> List[Tuple[str, Any]]:
        """Expand a `dynamic` block whose for_each decides to a literal collection (partial evaluation)."""
        if len(labels) != 1:
            raise Unconvertible("CONVERT.DYNAMIC_BLOCK", "labels")
        label = labels[0]
        a = dict(self.attrs(inner))
        if "iterator" in a or "labels" in a or "for_each" not in a:
            raise Unconvertible("CONVERT.DYNAMIC_BLOCK", label)
        coll = self.decided(a["for_each"], scope)
        if _has_expr(coll):
            raise Unconvertible("CONVERT.DYNAMIC_BLOCK", f"{label}: for_each is not decidable")
        items = list(coll.items()) if isinstance(coll, dict) else list(enumerate(coll or []))
        content = [b for k, _l, b in self.blocks(inner) if k == "content"]
        if len(content) != 1:
            raise Unconvertible("CONVERT.DYNAMIC_BLOCK", f"{label}: content")
        out = []
        for k, v in items:
            sc = dict(scope)
            sc.update({f"{label}.key": k, f"{label}.value": v})
            val, _ = self.body(content[0], sc, rtype, top=False, path=f"{path}.{label}" if path else label)
            out.append((label, val))
        self.notes["dynamic_block_expanded"] += 1
        return out

    def path_value(self, body: Any, path: Tuple[str, ...]) -> Any:
        node = body
        for part in path[:-1]:
            blks = [b for k, _l, b in self.blocks(node) if k == part]
            if len(blks) != 1:
                return None
            node = blks[0]
        return dict(self.attrs(node)).get(path[-1])

    def lifecycle_block(self, inner: Any) -> Dict[str, Any]:
        lc: Dict[str, Any] = {}
        for name, expr in self.attrs(inner):
            self.lifecycle[name] += 1
            if name == "prevent_destroy":
                v = self.expr(expr, {})
                if not isinstance(v, bool):
                    raise Unconvertible("CONVERT.LIFECYCLE_UNSUPPORTED", "prevent_destroy not a literal")
                lc["prevent_destroy"] = v
            elif name == "ignore_changes":
                d = expr
                while _data(d) == "expr_term" and len(_kids(d)) == 1:
                    d = _kids(d)[0]
                if _data(d) != "tuple":
                    raise Unconvertible("CONVERT.LIFECYCLE_UNSUPPORTED", "ignore_changes = all")
                paths = []
                for el in _kids(d):
                    tr = _traversal(el)
                    if tr is None:
                        raise Unconvertible("CONVERT.LIFECYCLE_UNSUPPORTED", "ignore_changes element")
                    paths.append(".".join([tr[0]] + [s[1] for s in tr[1] if s[0] == "attr"]))
                lc["ignore_changes"] = paths
            else:
                raise Unconvertible("CONVERT.LIFECYCLE_UNSUPPORTED", name)
        for blk, _l, _i in self.blocks(inner):
            self.lifecycle[blk] += 1
            raise Unconvertible("CONVERT.LIFECYCLE_UNSUPPORTED", blk)
        return lc

    def depends(self, expr: Any) -> List[Dict[str, Any]]:
        d = expr
        while _data(d) == "expr_term" and len(_kids(d)) == 1:
            d = _kids(d)[0]
        out = []
        for el in _kids(d) if _data(d) == "tuple" else []:
            tr = _traversal(el)
            if tr is None:
                self.notes["depends_on_dropped"] += 1
                continue
            root, segs = tr
            if root == "module" and segs and segs[0][0] == "attr":
                label = segs[0][1]
                if label in self.modules:
                    out.append({"module": label})
                else:
                    self.notes["depends_on_platform_dropped"] += 1
            elif segs and segs[0][0] == "attr" and (root, segs[0][1]) in self.resources and root in self.allowed:
                exp = self.expanded.get((root, segs[0][1]))
                names = list(exp.values()) if exp else [segs[0][1]]
                for nm in names:
                    out.append({"resource": {"type": root, "name": nm}})
                self.deps.add((root, segs[0][1]))
            else:
                self.notes["depends_on_platform_dropped"] += 1
        return out

    def binding_owner(self, rtype: str, body: Any) -> Optional[str]:
        """(IAM type, literal role) pairs the platform / topology owns (allowed_types.json not_expressible)."""
        ne = self.art.allowed.get("not_expressible") or {}
        role_node = dict(self.attrs(body)).get("role")
        if role_node is None:
            return None
        try:
            role = self.expr(role_node, {})
        except Unconvertible:
            return None
        for owner in ("platform_owned_bindings", "topology_owned_bindings"):
            if [rtype, role] in (ne.get(owner) or []):
                return owner.replace("_bindings", "")
        return None

    # ---------------------------------------------------------------------------- expansion
    def instances(self, rtype: str, name: str, body: Any) -> Optional[List[Tuple[str, Dict[str, Any]]]]:
        a = dict(self.attrs(body))
        if "count" in a:
            self.meta["count"] += 1
            v = self.decided(a["count"], {})
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 50:
                raise Unconvertible("CONVERT.META_COUNT", "count is not a literal integer")
            return [(f"{name}_{i}", {"count.index": i, "_key": i}) for i in range(v)]
        if "for_each" in a:
            self.meta["for_each"] += 1
            node = a["for_each"]
            d = node
            while _data(d) == "expr_term" and len(_kids(d)) == 1:
                d = _kids(d)[0]
            coll = self._literal(node)
            if isinstance(coll, dict):
                items = list(coll.items())
            elif isinstance(coll, list) and _is_set_call(d, self):
                items = [(x, x) for x in coll]
            else:
                raise Unconvertible("CONVERT.META_FOR_EACH", "for_each is not a literal set or map")
            out = []
            for k, v in items:
                if not isinstance(k, str):
                    raise Unconvertible("CONVERT.META_FOR_EACH", "non-string key")
                inst = f"{name}_{_slug(k)}"
                if not IDENT_RE.match(inst):
                    raise Unconvertible("CONVERT.META_FOR_EACH", f"key {k!r} gives no identifier")
                out.append((inst, {"each.key": k, "each.value": v, "_key": k}))
            return out
        return None

    def _literal(self, node: Any) -> Any:
        """A for_each collection: must convert to a literal (no Ref / Call anywhere)."""
        v = self.decided(node, {})
        if _has_expr(v):
            raise Unconvertible("CONVERT.META_FOR_EACH", "for_each is not a literal")
        return v

    # ---------------------------------------------------------------------------- driver
    def run(self, files: Mapping[str, str]) -> ConvertResult:
        self.collect(files)
        reports: Dict[Tuple[str, str], EntryReport] = {}
        self.mapped = {k for k in self.resources if k[0] in MODULE_MAPPINGS and k[1] not in self.modules
                       and k[1] not in ("foundation", "compute") and not k[1].startswith("compute_")}
        inst_plan: Dict[Tuple[str, str], List[Tuple[str, Dict[str, Any]]]] = {}
        for (rtype, name), info in sorted(self.resources.items()):
            owner = self.art.not_expressible_owner(rtype)
            cat = owner or ("allowed" if rtype in self.allowed else "not_allowed")
            rep = EntryReport(f"{rtype}.{name}", rtype, info["file"], "pending", cat)
            reports[(rtype, name)] = rep
            if owner is not None:
                rep.status = "excluded"
                continue
            if (rtype, name) in self.mapped:
                rep.category = "module_mapped"
                continue
            if rtype not in self.allowed:
                rep.status, rep.reasons = "failed", ["CONVERT.TYPE_NOT_ALLOWED"]
                continue
            bowner = self.binding_owner(rtype, info["body"])
            if bowner is not None:
                rep.status, rep.category = "excluded", bowner
                continue
            try:
                plan = self.instances(rtype, name, info["body"])
            except Unconvertible as exc:
                rep.status, rep.reasons, rep.details = "failed", [exc.reason], [exc.detail]
                continue
            if plan is None:
                inst_plan[(rtype, name)] = [(name, {})]
                self.expanded[(rtype, name)] = None
            else:
                inst_plan[(rtype, name)] = plan
                self.expanded[(rtype, name)] = {sc["_key"]: inst for inst, sc in plan}
                rep.instances = len(plan)
        converted: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        deps_of: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        for key, plan in sorted(inst_plan.items()):
            rtype, name = key
            rep = reports[key]
            out_entries = []
            self.deps = set()
            try:
                for inst, scope in plan:
                    args, extra = self.body(self.resources[key]["body"], scope, rtype, top=True)
                    entry: Dict[str, Any] = {"type": rtype, "name": inst, "arguments": args}
                    if extra.get("lifecycle"):
                        entry["lifecycle"] = extra["lifecycle"]
                    if "depends_on" in extra:
                        dep = self.depends(extra["depends_on"])
                        if dep:
                            entry["depends_on"] = dep
                    out_entries.append(entry)
            except Unconvertible as exc:
                rep.status, rep.reasons, rep.details = "failed", [exc.reason], [exc.detail]
                continue
            converted[key] = out_entries
            deps_of[key] = {d for d in self.deps}
        # modules
        mod_entries: Dict[str, Dict[str, Any]] = {}
        for label, info in sorted(self.modules.items()):
            a = dict(self.attrs(info["body"]))
            src = self.expr(a["source"], {}) if "source" in a else None
            mid = os.path.basename(os.path.normpath(src)) if isinstance(src, str) and src.startswith(("./", "../")) \
                else None
            rep = EntryReport(f"module.{label}", f"module:{mid or src}", info["file"], "pending", "module")
            reports[("module", label)] = rep
            if mid in self.art.catalog.get("platform_only", {}):
                rep.status, rep.category = "excluded", "platform_module"
                continue
            if mid not in self.art.ai_modules:
                rep.status, rep.reasons = "failed", ["CONVERT.MODULE_NOT_IN_CATALOG"]
                continue
            cvars = self.art.module(mid).get("variables") or {}
            args: Dict[str, Any] = {}
            self.deps = set()
            try:
                for k, e in a.items():
                    if k == "source":
                        continue
                    if k in ("count", "for_each", "providers", "version"):
                        raise Unconvertible("CONVERT.META_MODULE", k)
                    if k == "depends_on":
                        continue
                    cls = (cvars.get(k) or MODULE_ARG_CLASS.get(k) or {}).get("class")
                    if cls in ("FACT", "SECRET"):
                        self.notes[f"module_{cls.lower()}_arg_dropped"] += 1
                        continue
                    args[k] = self.expr(e, {})
            except Unconvertible as exc:
                rep.status, rep.reasons, rep.details = "failed", [exc.reason], [exc.detail]
                continue
            mod_entries[label] = {"module": mid, "name": label, "args": args}
            deps_of[("module", label)] = set(self.deps)
        for rtype, label in sorted(self.mapped):      # Q-TI-2 module-required raw types
            mp = MODULE_MAPPINGS[rtype]
            rep = reports[(rtype, label)]
            body = self.resources[(rtype, label)]["body"]
            args = {}
            self.deps = set()
            try:
                if any(k in dict(self.attrs(body)) for k in ("count", "for_each")):
                    raise Unconvertible("CONVERT.META_COUNT", "module-mapped block with count/for_each")
                for path, var in sorted(mp["args"].items()):
                    node = self.path_value(body, path)
                    if node is not None:
                        args[var] = self.expr(node, {})
            except Unconvertible as exc:
                rep.status, rep.reasons, rep.details = "failed", [exc.reason], [exc.detail]
                continue
            rep.reasons, rep.details = ["CONVERT.MAPPED_TO_MODULE"], [mp["module"]]
            mod_entries[label] = {"module": mp["module"], "name": label, "args": args}
            deps_of[("module", label)] = set(self.deps)
            reports[("module", label)] = rep
        # cascade: a converted entry that references a non-converted resource is not converted
        changed = True
        while changed:
            changed = False
            for key in list(converted) + [("module", m) for m in list(mod_entries)]:
                dead = [d for d in deps_of.get(key, ()) if d not in converted
                        and not (d[0] == "module" and d[1] in mod_entries)]
                if dead:
                    rep = reports[key]
                    rep.status, rep.reasons = "failed", ["CONVERT.DEPENDS_ON_UNCONVERTED"]
                    converted.pop(key, None)
                    if key[0] == "module":
                        mod_entries.pop(key[1], None)
                    changed = True
        for key in converted:
            reports[key].status = "converted"
        for label in mod_entries:
            reports[("module", label)].status = "converted"
        resources = [e for key in sorted(converted) for e in converted[key]]
        names = {(e["type"], e["name"]) for e in resources}
        for e in resources:   # depends_on on dropped instances
            if "depends_on" in e:
                e["depends_on"] = [d for d in e["depends_on"] if "module" in d and d["module"] in mod_entries
                                   or "resource" in d and (d["resource"]["type"], d["resource"]["name"]) in names]
                if not e["depends_on"]:
                    e.pop("depends_on")
        outputs = []
        for oname, expr, _f in self.outputs:
            self.deps = set()
            try:
                v = self.expr(expr, {})
            except Unconvertible as exc:
                self.notes[f"output_dropped:{exc.reason}"] += 1
                continue
            if not (isinstance(v, dict) and "$ref" in v) or v["$ref"].get("kind") == "fact" \
                    or any(d not in converted for d in self.deps) or not IDENT_RE.match(oname):
                self.notes["output_dropped:CONVERT.OUTPUT_NOT_REF"] += 1
                continue
            if oname in self.platform_outputs:
                self.notes["output_dropped:platform_output_name"] += 1
                continue
            outputs.append({"name": oname, "value": v})
        intent = {"schema": "iac_intent/v1", "modules": [mod_entries[k] for k in sorted(mod_entries)],
                  "resources": resources, "outputs": outputs}
        entries = sorted(reports.values(), key=lambda r: r.address)
        if self.parse_errors:
            for pe in self.parse_errors:
                entries.append(EntryReport(f"file:{pe.split(':', 1)[0]}", "file", pe.split(":", 1)[0], "failed",
                                           "parse_error", ["CONVERT.HCL_PARSE_ERROR"]))
        return ConvertResult(intent, entries, self.notes, self.functions, self.lifecycle, self.data_sources,
                             self.meta, self.parse_errors)


def _is_set_call(node: Any, conv: "_Conv") -> bool:
    """for_each takes a set or a map: the collection expression must be toset(...) itself or a local whose value is."""
    d = node
    while _data(d) == "expr_term" and len(_kids(d)) == 1:
        d = _kids(d)[0]
    if _data(d) == "function_call":
        return _ident(_kids(d)[0]) == "toset"
    tr = _traversal(d)
    if tr and tr[0] == "local" and len(tr[1]) == 1 and tr[1][0][1] in conv.locals:
        return _is_set_call(conv.locals[tr[1][0][1]], conv)
    return False


class _FactValue:
    """A platform fact during partial evaluation: a known, non-empty, non-null string."""
    def __init__(self, fact: str):
        self.fact = fact


def _has_expr(v: Any) -> bool:
    if isinstance(v, dict):
        return "$ref" in v or "$fn" in v or "$member" in v or any(_has_expr(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_expr(x) for x in v)
    return False


def _slug(k: str) -> str:
    out = "".join(c.lower() if c.isalnum() else "_" for c in k)
    while "__" in out:
        out = out.replace("__", "_")
    return out.strip("_")


def convert_tree(files: Mapping[str, str], art: Optional[Artifacts] = None, *,
                 services: Optional[Mapping[str, Tuple[str, str]]] = None,
                 platform_output_names: Sequence[str] = ()) -> ConvertResult:
    """Convert the workload `.tf` files of one draft. `services`: compute module label -> (service, module id);
    `platform_output_names`: outputs the platform's outputs.tf already declares (an AI copy is dropped, noted)."""
    conv = _Conv(art or load_artifacts(), services or {})
    conv.platform_outputs = set(platform_output_names)
    return conv.run(files)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("workload_dir")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    files = {str(p.relative_to(a.workload_dir)): p.read_text() for p in Path(a.workload_dir).glob("*.tf")}
    res = convert_tree(files)
    if a.json:
        print(json.dumps({"intent": res.intent, "entries": [e.__dict__ for e in res.entries]}, indent=1))
    else:
        for e in res.entries:
            print(f"{e.status:9} {e.address:60} {e.category:15} {' '.join(e.reasons)}")
        print(f"expressibility: {res.expressibility}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

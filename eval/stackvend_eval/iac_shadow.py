"""Typed-IaC intent shadow scoring (TI-2, plan §4 TI-2 $0 gate; inert: nothing here runs in the product).

For every recorded run: take the IaC persona's FIRST-DRAFT answers from the cassette (the swarm call whose system
instruction is the Junior IaC / Cloud Engineer prompt; every such swarm answer of the run, in order, later paths
override earlier ones - the dispatcher's merge), convert the workload `.tf` files to an `iac_intent/v1` document
(scripts/convert_custom_tf.py), run the intent gate (shared/iac_intent.py), render the gate-clean subset with the
platform root and run production `tofu validate` (filesystem_mirror only, sandbox-exec with outbound networking denied
on macOS, scrubbed env, plugin cache in the work dir).

Gate metrics (plan §4 TI-2):
  (a) expressibility per run = converted / (converted + failed) AI blocks; blocks of not-expressible owners
      (platform / forbidden / topology / lane 11) are counted separately (`excluded`).
  (b) render of the gate-clean subset + platform root under production `tofu validate`: PASS rate.
  (c) compiler agreement: TF.* diagnostics on gate-clean renders (target 0).
  (d) gate precision: entries the gate rejected ONLY with compiler-mirroring codes, rendered one at a time with the
      clean subset ("leave-one-in"); a render that validates is a gate false positive (target 0).

Imports (documented exception to the harness's "no product import" rule, because the gate IS the code under test):
shared.iac_intent and scripts/convert_custom_tf.py from the product root, and the three pure golden generators of
developer_agent.terraform_engine for the platform root (main.tf / variables.tf / outputs.tf, archetype cloudrun).
"""
from __future__ import annotations

import collections
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# VISIBLE-RENAME (10-26): the persona now says StackVend; cassettes recorded before it carry the old wording.
IAC_PERSONA_PREFIX = ("You are StackVend's Junior IaC / Cloud Engineer.", "You are Project Castor's Junior IaC / Cloud Engineer.")
SWARM_SITE_SUFFIX = "SwarmDispatcher._call_gemini_with_backoff"
WORKLOAD = "infra/workload"
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
SANDBOX_PROFILE = "(version 1)(allow default)(deny network-outbound (remote ip))"
COMPILER_MIRRORING = frozenset({
    "IAC.UNKNOWN_ARGUMENT", "IAC.MISSING_REQUIRED_ARGUMENT", "IAC.UNKNOWN_ATTRIBUTE", "IAC.MISSING_REQUIRED_BLOCK",
    "IAC.TYPE_MISMATCH", "IAC.COMPUTED_ONLY_ATTRIBUTE", "IAC.MAX_ITEMS_EXCEEDED", "IAC.NOT_INDEXABLE",
    "IAC.INDEX_REQUIRED", "IAC.UNKNOWN_REFERENCE", "IAC.UNKNOWN_OUTPUT", "IAC.REFERENCE_CYCLE",
})
PROVIDERS = ("google", "google-beta", "kubernetes", "random")
REGISTRIES = ("registry.opentofu.org", "registry.terraform.io")


# ------------------------------------------------------------------------------------------------ cassettes
def iac_first_drafts(cassette: Path) -> Dict[str, Any]:
    """{"files": {path: text}, "answers": n, "errors": n, "header": {...}} for one cassette (read-only)."""
    files: Dict[str, str] = {}
    answers = errors = 0
    header: Dict[str, Any] = {}
    with Path(cassette).open() as fh:
        for i, line in enumerate(fh):
            rec = json.loads(line)
            if i == 0:
                header = {k: rec.get(k) for k in ("example", "run", "model", "spec_sha256")}
                continue
            if not str(rec.get("site", "")).endswith(SWARM_SITE_SUFFIX):
                continue
            si = ((rec.get("request") or {}).get("config") or {}).get("system_instruction") or ""
            if not si.startswith(IAC_PERSONA_PREFIX):
                continue
            try:
                text = rec["response"]["candidates"][0]["content"]["parts"][0]["text"]
                got = json.loads(text)["files"]
            except (KeyError, IndexError, TypeError, ValueError):
                errors += 1
                continue
            answers += 1
            for p, t in got.items():
                if isinstance(p, str) and isinstance(t, str):
                    files[p] = t
    return {"files": files, "answers": answers, "errors": errors, "header": header}


def workload_tf(files: Mapping[str, str]) -> Dict[str, str]:
    return {p: t for p, t in files.items() if p.startswith("infra/") and p.endswith(".tf")
            and not p.startswith("infra/modules/")}


# ------------------------------------------------------------------------------------------------ product loading
def load_product(product_root: Path) -> Dict[str, Any]:
    root = Path(product_root).resolve()
    for p in (str(root / "apps" / "orchestrator-gateway"), str(root)):   # root shared/ wins
        if p not in sys.path:
            sys.path.insert(0, p)
    import shared.iac_intent as ii  # noqa: WPS433 - the code under test
    spec = importlib.util.spec_from_file_location("ti2_convert_custom_tf", root / "scripts" / "convert_custom_tf.py")
    conv = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = conv
    spec.loader.exec_module(conv)
    from developer_agent import terraform_engine as te  # pure string generators only
    from developer_agent.validators.tofu_diagnostics import tf_code
    return {"ii": ii, "conv": conv, "te": te, "tf_code": tf_code, "root": root}


def platform_root(prod: Mapping[str, Any], product_id: str) -> Dict[str, str]:
    te = prod["te"]
    files = {
        f"{WORKLOAD}/main.tf": te.generate_golden_main_tf(product_id, "cloudrun", env_vars_override={}),
        f"{WORKLOAD}/variables.tf": te.generate_golden_variables_tf(product_id,
                                                                     default_repo=f"stackvend-eval/{product_id}"),
        f"{WORKLOAD}/outputs.tf": te.generate_golden_outputs_tf(product_id, "cloudrun"),
    }
    mods = Path(prod["root"]) / "infra" / "modules"
    for p in sorted(mods.rglob("*.tf")):
        files[f"infra/modules/{p.relative_to(mods).as_posix()}"] = p.read_text()
    return files


def output_names(text: str) -> List[str]:
    import hcl2
    return sorted(k for o in (hcl2.loads(text).get("output") or []) for k in o)


# ------------------------------------------------------------------------------------------------ tofu
class ShadowValidator:
    """`tofu init -backend=false` + `validate -json` only; mirror-only CLI config; no network."""

    def __init__(self, tofu: str, mirror: str, work: Path):
        self.tofu, self.mirror = tofu, str(Path(mirror).resolve())
        self.work = Path(work)
        self.work.mkdir(parents=True, exist_ok=True)
        self.home = self.work / "home"
        self.home.mkdir(exist_ok=True)
        self.cache = self.work / "plugin-cache"
        self.cache.mkdir(exist_ok=True)
        self.rc = self.work / "cli.tfrc"
        inc = [f"{r}/hashicorp/{p}" for r in REGISTRIES for p in PROVIDERS]
        self.rc.write_text("provider_installation {\n  filesystem_mirror {\n    path    = " + json.dumps(self.mirror)
                           + "\n    include = " + json.dumps(inc) + "\n  }\n}\n")
        self.n = 0

    def env(self) -> Dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "HOME": str(self.home), "TF_CLI_CONFIG_FILE": str(self.rc),
                "TF_PLUGIN_CACHE_DIR": str(self.cache), "CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "1",
                "TF_INPUT": "0", "LANG": "C.UTF-8", "TZ": "UTC"}

    def _run(self, args: Sequence[str], cwd: Path) -> subprocess.CompletedProcess:
        cmd = [self.tofu, *args]
        if sys.platform == "darwin" and os.path.exists(SANDBOX_EXEC):
            cmd = [SANDBOX_EXEC, "-p", SANDBOX_PROFILE, *cmd]
        return subprocess.run(cmd, cwd=str(cwd), env=self.env(), capture_output=True, text=True, timeout=600)

    def validate(self, tree: Mapping[str, str], tf_code) -> Dict[str, Any]:
        self.n += 1
        root = Path(tempfile.mkdtemp(prefix=f"t{self.n:04d}-", dir=self.work))
        try:
            for rel, text in tree.items():
                p = (root / rel).resolve()
                if not str(p).startswith(str(root.resolve()) + os.sep):
                    continue
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            wd = root / WORKLOAD
            r = self._run(["init", "-backend=false", "-input=false", "-no-color"], wd)
            if r.returncode != 0:
                return {"status": "init_failed", "ok": False, "error": (r.stdout + r.stderr)[-1500:],
                        "diagnostics": []}
            r = self._run(["validate", "-json", "-no-color"], wd)
            try:
                vj = json.loads(r.stdout or "{}")
            except ValueError:
                return {"status": "unparseable", "ok": False, "error": (r.stdout + r.stderr)[-800:],
                        "diagnostics": []}
            diags = []
            for d in vj.get("diagnostics") or []:
                rng = d.get("range") or {}
                diags.append({"severity": d.get("severity"), "summary": d.get("summary"),
                              "detail": (d.get("detail") or "")[:300], "file": rng.get("filename"),
                              "line": (rng.get("start") or {}).get("line"), "code": tf_code(d.get("summary") or "")})
            errs = [d for d in diags if d["severity"] == "error"]
            return {"status": "validated", "ok": bool(vj.get("valid")) and not errs, "diagnostics": diags}
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ one run
def _entry_of(path: str) -> Optional[Tuple[str, int]]:
    parts = (path or "/").split("/")
    if len(parts) >= 3 and parts[1] in ("modules", "resources", "outputs") and parts[2].isdigit():
        return parts[1], int(parts[2])
    return None


def _subset(doc: Mapping[str, Any], keep: Mapping[str, Iterable[int]]) -> Dict[str, Any]:
    out = {"schema": doc.get("schema", "iac_intent/v1")}
    for sec in ("modules", "resources", "outputs"):
        ks = set(keep.get(sec, ()))
        out[sec] = [e for i, e in enumerate(doc.get(sec) or []) if i in ks]
    return out


def clean_subset(ii, doc: Mapping[str, Any], art, ctx) -> Tuple[Dict[str, Any], List[Any], List[Any]]:
    """Drop every entry with a diagnostic (and, by re-gating, every entry that referenced it) until the gate is clean.
    Returns (clean_doc, first_gate_diagnostics, dropped [(section, entry, codes)])."""
    cur = json.loads(json.dumps(doc))
    first = None
    dropped: List[Any] = []
    for _ in range(50):
        g = ii.validate_intent(cur, art, ctx)
        if first is None:
            first = list(g.diagnostics)
        if g.ok:
            return cur, first, dropped
        bad: Dict[str, Dict[int, List[str]]] = collections.defaultdict(lambda: collections.defaultdict(list))
        whole = False
        for d in g.diagnostics:
            e = _entry_of(d.attribute_path or "/")
            if e is None:
                whole = True
            else:
                bad[e[0]][e[1]].append(d.code)
        if whole and not bad:
            for sec in ("modules", "resources", "outputs"):
                for i, e in enumerate(cur.get(sec) or []):
                    dropped.append((sec, e, ["(whole-intent diagnostic)"]))
            return {"schema": "iac_intent/v1", "modules": [], "resources": [], "outputs": []}, first, dropped
        keep = {}
        for sec in ("modules", "resources", "outputs"):
            keep[sec] = [i for i in range(len(cur.get(sec) or [])) if i not in bad.get(sec, {})]
            for i, codes in sorted(bad.get(sec, {}).items()):
                dropped.append((sec, cur[sec][i], sorted(set(codes))))
        cur = _subset(cur, keep)
    raise RuntimeError("clean_subset did not converge")  # pragma: no cover


def shadow_run(prod: Mapping[str, Any], art, validator: ShadowValidator, key: str, cassette: Path,
               product_id: str, *, precision: bool = True, mutations: bool = False) -> Dict[str, Any]:
    ii, conv = prod["ii"], prod["conv"]
    drafts = iac_first_drafts(cassette)
    rec: Dict[str, Any] = {"key": key, "product_id": product_id, "answers": drafts["answers"],
                           "answer_errors": drafts["errors"]}
    tf = workload_tf(drafts["files"])
    rec["ai_iac_paths"] = sorted(tf)
    if not tf:
        rec["status"] = "no_iac_draft"
        return rec
    root = platform_root(prod, product_id)
    plat_outputs = output_names(root[f"{WORKLOAD}/outputs.tf"])
    svc = product_id[:40].rstrip("-")
    services_conv = {"compute": (svc, "compute-cloudrun")}
    ctx = ii.IntentContext(services={svc: ("module.compute", "compute-cloudrun")},
                           platform_output_names=frozenset(plat_outputs))
    res = conv.convert_tree(tf, art, services=services_conv, platform_output_names=plat_outputs)
    entries = [e.__dict__ for e in res.entries]
    rec.update({
        "entries": entries,
        "converted": sum(1 for e in res.entries if e.status == "converted"),
        "failed": sum(1 for e in res.entries if e.status == "failed"),
        "excluded": sum(1 for e in res.entries if e.status == "excluded"),
        "expressibility": res.expressibility,
        "expressibility_excl_draft_defects": _expr_excl(res.entries),
        "convert_reasons": dict(collections.Counter(r for e in res.entries for r in e.reasons)),
        "excluded_by_owner": dict(collections.Counter(e.category for e in res.entries if e.status == "excluded")),
        "functions_seen": dict(res.functions), "lifecycle_seen": dict(res.lifecycle),
        "data_sources_seen": dict(res.data_sources), "meta_seen": dict(res.meta), "notes": dict(res.notes),
        "intent": res.intent,
    })
    clean, first, dropped = clean_subset(ii, res.intent, art, ctx)
    rec["gate_codes"] = dict(collections.Counter(d.code for d in first))
    rec["gate_clean_entries"] = sum(len(clean.get(s) or []) for s in ("modules", "resources"))
    rec["gate_dropped"] = [{"section": s, "address": _addr(s, e), "codes": c} for s, e, c in dropped]
    g = ii.validate_intent(clean, art, ctx)
    assert g.ok, g.diagnostics
    rendered = ii.render_intent(g.validated)
    rec["functions_rendered"] = list(rendered.functions_used)
    rec["facts_rendered"] = list(rendered.facts_used)
    rec["lifecycle_rendered"] = sorted({k for e in clean.get("resources") or [] for k, v in
                                        (e.get("lifecycle") or {}).items() if v not in (None, [])})
    # determinism: render twice, byte-identical
    again = ii.render_intent(ii.validate_intent(clean, art, ctx).validated)
    rec["render_deterministic"] = dict(again.files) == dict(rendered.files)
    tree = dict(root)
    tree.update(rendered.files)
    v = validator.validate(tree, prod["tf_code"])
    rec["validate"] = {"status": v["status"], "ok": v["ok"], "error": v.get("error"),
                       "diagnostics": [d for d in v["diagnostics"] if d["severity"] == "error"]}
    rec["tf_codes_on_clean"] = sorted({d["code"] for d in rec["validate"]["diagnostics"]})
    # (d) precision: leave-one-in for entries rejected ONLY by compiler-mirroring codes
    prec = []
    if precision and v["ok"]:
        for s, e, codes in dropped:
            if s == "outputs" or not set(codes) <= COMPILER_MIRRORING:
                continue
            trial = json.loads(json.dumps(clean))
            trial[s] = list(trial.get(s) or []) + [e]
            try:
                parsed = ii.IacIntent.model_validate(trial)
                rr = ii.render_parsed_for_shadow(parsed, art, ctx)
            except Exception as exc:  # noqa: BLE001 - unrenderable entry: the gate was right to refuse it
                prec.append({"address": _addr(s, e), "codes": codes, "render": f"refused: {type(exc).__name__}",
                             "tofu_agrees": True})
                continue
            t2 = dict(root)
            t2.update(rr.files)
            v2 = validator.validate(t2, prod["tf_code"])
            prec.append({"address": _addr(s, e), "codes": codes, "render": "ok", "tofu_ok": v2["ok"],
                         "tofu_agrees": not v2["ok"],
                         "tf_codes": sorted({d["code"] for d in v2["diagnostics"] if d["severity"] == "error"})})
    rec["precision_checks"] = prec
    rec["mutation_checks"] = mutation_checks(prod, art, validator, clean, root, ctx) if (mutations and v["ok"]) else []
    rec["status"] = "scored"
    return rec


# ------------------------------------------------------------------------------------------------ mutations
def _mutants(art, clean: Mapping[str, Any]) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Deterministic schema-derived mutants of a gate-clean intent: (kind, expected gate code, mutant doc)."""
    out: List[Tuple[str, str, Dict[str, Any]]] = []
    res = clean.get("resources") or []
    for i, e in enumerate(res):
        block = art.resource_schema(e["type"]) or {}
        attrs = block.get("attributes") or {}
        args = e.get("arguments") or {}

        def mut(fn) -> Dict[str, Any]:
            doc = json.loads(json.dumps(clean))
            fn(doc["resources"][i]["arguments"])
            return doc
        if not any(k == "unknown_argument" for k, _c, _d in out):
            out.append(("unknown_argument", "IAC.UNKNOWN_ARGUMENT",
                        mut(lambda a: a.__setitem__("stackvend_no_such_argument", "x"))))
        req = sorted(k for k, a in attrs.items() if a.get("required") and k in args)
        if req and not any(k == "missing_required" for k, _c, _d in out):
            out.append(("missing_required", "IAC.MISSING_REQUIRED_ARGUMENT", mut(lambda a, k=req[0]: a.pop(k))))
        bools = sorted(k for k, a in attrs.items() if a.get("type") == "bool" and a.get("optional")
                       and not a.get("computed") and k not in ("uniform_bucket_level_access",))
        if bools and not any(k == "type_mismatch" for k, _c, _d in out):
            out.append(("type_mismatch", "IAC.TYPE_MISMATCH",
                        mut(lambda a, k=bools[0]: a.__setitem__(k, "not-a-bool"))))
        comp = sorted(k for k, a in attrs.items() if a.get("computed") and not a.get("optional")
                      and not a.get("required"))
        if comp and not any(k == "computed_only" for k, _c, _d in out):
            out.append(("computed_only", "IAC.COMPUTED_ONLY_ATTRIBUTE",
                        mut(lambda a, k=comp[0]: a.__setitem__(k, "x"))))
        if not any(k == "unknown_attribute" for k, _c, _d in out):
            doc = json.loads(json.dumps(clean))
            doc.setdefault("outputs", []).append({"name": "stackvend_mutant_out", "value": {"$ref": {
                "kind": "resource_attr", "type": e["type"], "name": e["name"], "attr": "stackvend_no_such_attr"}}})
            out.append(("unknown_attribute", "IAC.UNKNOWN_ATTRIBUTE", doc))
    return out


def mutation_checks(prod: Mapping[str, Any], art, validator: "ShadowValidator", clean: Mapping[str, Any],
                    root: Mapping[str, str], ctx) -> List[Dict[str, Any]]:
    """Gate vs compiler on schema-derived mutants: the gate must flag each (recall) and OpenTofu must reject each
    (the gate code is not a false positive)."""
    ii = prod["ii"]
    out = []
    for kind, code, doc in _mutants(art, clean):
        g = ii.validate_intent(doc, art, ctx)
        flagged = code in {d.code for d in g.diagnostics}
        try:
            rr = ii.render_parsed_for_shadow(ii.IacIntent.model_validate(doc), art, ctx)
        except Exception as exc:  # noqa: BLE001
            out.append({"kind": kind, "gate_flagged": flagged, "render": f"refused: {type(exc).__name__}"})
            continue
        tree = dict(root)
        tree.update(rr.files)
        v = validator.validate(tree, prod["tf_code"])
        out.append({"kind": kind, "expected": code, "gate_flagged": flagged, "tofu_rejected": not v["ok"],
                    "tf_codes": sorted({d["code"] for d in v["diagnostics"] if d["severity"] == "error"})})
    return out


def _addr(section: str, e: Mapping[str, Any]) -> str:
    if section == "modules":
        return "module." + str(e.get("name"))
    if section == "resources":
        return f"{e.get('type')}.{e.get('name')}"
    return "output." + str(e.get("name"))


# ------------------------------------------------------------------------------------------------ escaping (FD-4AW)
ESCAPE_LITERALS = ('${file("/etc/hostname")}', "%{ if true }x%{ endif }",
                   'a"}%{ if file("/etc/hosts") != "" }LEAK%{ endif }', "$${already}", "%%{already}", "${", "%{",
                   "$", "100%", "plain", "$$$${x}", "a$", "%%%{", "\\n back\\slash", "tab\tnl\n")


def escape_roundtrip(prod: Mapping[str, Any], validator: "ShadowValidator") -> Dict[str, Any]:
    """OpenTofu itself evaluates every escaped literal (JSON-syntax template) and every Call string literal
    (native syntax inside ${...}) back to exactly the original text (`tofu console`, no providers, no network)."""
    ii = prod["ii"]
    loc = {f"j{i}": ii.escape_template(s) for i, s in enumerate(ESCAPE_LITERALS)}
    loc.update({f"n{i}": "${upper(" + ii.hcl_string_literal(s) + ")}" for i, s in enumerate(ESCAPE_LITERALS)})
    root = Path(tempfile.mkdtemp(prefix="esc-", dir=validator.work))
    try:
        (root / "main.tf.json").write_text(json.dumps({"locals": loc}))
        q = "".join(f"jsonencode(local.j{i})\njsonencode(local.n{i})\n" for i in range(len(ESCAPE_LITERALS)))
        cmd = [validator.tofu, "console"]
        if sys.platform == "darwin" and os.path.exists(SANDBOX_EXEC):
            cmd = [SANDBOX_EXEC, "-p", SANDBOX_PROFILE, *cmd]
        p = subprocess.run(cmd, cwd=str(root), env=validator.env(), input=q, capture_output=True, text=True,
                           timeout=120)
        outs = [ln for ln in p.stdout.splitlines() if ln.strip()]
        bad = []
        for i, s in enumerate(ESCAPE_LITERALS):
            try:
                j, n = json.loads(json.loads(outs[2 * i])), json.loads(json.loads(outs[2 * i + 1]))
            except (IndexError, ValueError):
                bad.append({"literal": s, "error": "no console output"})
                continue
            if j != s or n != s.upper():
                bad.append({"literal": s, "template": j, "native": n})
        return {"checked": len(ESCAPE_LITERALS), "mismatches": bad, "stderr": p.stderr[-300:]}
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ catalog smoke
def _sample(ty: Any) -> Any:
    if ty == "string" or ty == "dynamic":
        return "stackvend-smoke"
    if ty == "number":
        return 1
    if ty == "bool":
        return True
    if isinstance(ty, list) and ty[0] in ("list", "set"):
        return [_sample(ty[1])]
    if isinstance(ty, list) and ty[0] == "map":
        return {"k": _sample(ty[1])}
    return "stackvend-smoke"


def module_smoke(prod: Mapping[str, Any], art, validator: "ShadowValidator", product_id: str) -> Dict[str, Any]:
    """Every AI-instantiable catalog module, instantiated alone with its required arguments only (literals of the
    variable type; REF_ONLY -> the allowed reference), through the gate, the renderer and production validate."""
    ii = prod["ii"]
    root = platform_root(prod, product_id)
    svc = product_id[:40].rstrip("-")
    ctx = ii.IntentContext(services={svc: ("module.compute", "compute-cloudrun")},
                           platform_output_names=frozenset(output_names(root[f"{WORKLOAD}/outputs.tf"])))
    out: Dict[str, Any] = {}
    for mid in art.ai_modules:
        cvars = art.module(mid)["variables"]
        mods = []
        args: Dict[str, Any] = {}
        for name, v in sorted(cvars.items()):
            if v.get("has_default") or v["class"] in ("FACT", "SECRET"):
                continue
            if v["class"] == "REF_ONLY":
                kind, _, detail = v["refs"][0].partition(":")
                if kind == "service":
                    args[name] = {"$ref": {"kind": "service", "service": svc, "output": detail}}
                elif kind == "fact":
                    args[name] = {"$ref": {"kind": "fact", "fact": detail}}
                elif kind == "module_output":
                    dep, _, o = detail.partition(".")
                    mods.append({"module": dep, "name": "smoke_dep", "args": {}})
                    args[name] = {"$ref": {"kind": "module_output", "module": "smoke_dep", "output": o}}
            else:
                args[name] = _sample(ii.parse_type_constraint(v["hcl_type"]))
        doc = {"schema": "iac_intent/v1", "modules": mods + [{"module": mid, "name": "smoke", "args": args}]}
        g = ii.validate_intent(doc, art, ctx)
        if not g.ok:
            out[mid] = {"gate": [d.code for d in g.diagnostics], "validate_ok": None}
            continue
        tree = dict(root)
        tree.update(ii.render_intent(g.validated).files)
        v = validator.validate(tree, prod["tf_code"])
        out[mid] = {"gate": [], "validate_ok": v["ok"],
                    "errors": [f"{d['code']} {d['file']}:{d['line']} {d['detail'][:120]}"
                               for d in v["diagnostics"] if d["severity"] == "error"][:5]}
    return out


# ------------------------------------------------------------------------------------------------ summary
def summarize(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    scored = [r for r in records if r.get("status") == "scored"]
    per_set: Dict[str, List[Mapping[str, Any]]] = collections.defaultdict(list)
    for r in scored:
        per_set[r["key"].split("/", 1)[0]].append(r)
    expr = [r["expressibility"] for r in scored if r.get("expressibility") is not None]
    out: Dict[str, Any] = {
        "runs_total": len(records), "runs_scored": len(scored),
        "runs_without_iac_draft": [r["key"] for r in records if r.get("status") == "no_iac_draft"],
        "a_expressibility": {
            "min_per_run": min(expr) if expr else None,
            "mean_per_run": (sum(expr) / len(expr)) if expr else None,
            "runs_below_90": sorted(r["key"] for r in scored if _below(r.get("expressibility"), 0.9)),
            "runs_below_80": sorted(r["key"] for r in scored if _below(r.get("expressibility"), 0.8)),
            "excl_draft_defects": {
                "min_per_run": min((r["expressibility_excl_draft_defects"] for r in scored
                                    if r.get("expressibility_excl_draft_defects") is not None), default=None),
                "runs_below_90": sorted(r["key"] for r in scored
                                        if _below(r.get("expressibility_excl_draft_defects"), 0.9)),
                "runs_below_80": sorted(r["key"] for r in scored
                                        if _below(r.get("expressibility_excl_draft_defects"), 0.8))},
            "runs_with_no_counted_block": sorted(r["key"] for r in scored if r.get("expressibility") is None),
            "blocks": {k: sum(r[k] for r in scored) for k in ("converted", "failed", "excluded")},
            "convert_reasons": _sum(r["convert_reasons"] for r in scored),
            "failed_types": _sum({e["type"]: 1 for e in r["entries"] if e["status"] == "failed"} for r in scored),
            "excluded_by_owner": _sum(r["excluded_by_owner"] for r in scored),
            "per_set": {s: {"runs": len(rs), "min": min((x["expressibility"] for x in rs
                                                          if x["expressibility"] is not None), default=None),
                            "below_90": sum(1 for x in rs if _below(x["expressibility"], 0.9)),
                            "below_80": sum(1 for x in rs if _below(x["expressibility"], 0.8))}
                        for s, rs in sorted(per_set.items())},
        },
        "b_render_validate": {"pass": sum(1 for r in scored if r["validate"]["ok"]), "runs": len(scored),
                              "failing": sorted(r["key"] for r in scored if not r["validate"]["ok"])},
        "c_tf_codes_on_gate_clean": _sum({c: 1 for c in r["tf_codes_on_clean"]} for r in scored),
        "mutations": {
            "checked": sum(len(r.get("mutation_checks") or []) for r in scored),
            "gate_missed": [dict(m, key=r["key"]) for r in scored for m in r.get("mutation_checks") or []
                            if not m.get("gate_flagged")],
            "tofu_accepted_gate_flagged": [dict(m, key=r["key"]) for r in scored for m in r.get("mutation_checks") or []
                                           if m.get("gate_flagged") and m.get("tofu_rejected") is False],
            "by_kind": _sum({m["kind"]: 1 for m in r.get("mutation_checks") or []} for r in scored),
        },
        "d_gate_precision": {
            "checked": sum(len(r["precision_checks"]) for r in scored),
            "false_positives": [dict(p, key=r["key"]) for r in scored for p in r["precision_checks"]
                                if not p.get("tofu_agrees")],
        },
        "gate_codes": _sum(r["gate_codes"] for r in scored),
        "gate_clean_entries": sum(r["gate_clean_entries"] for r in scored),
        "render_deterministic": all(r["render_deterministic"] for r in scored),
        "functions_seen": _sum(r["functions_seen"] for r in scored),
        "functions_rendered": _sum({f: 1 for f in r["functions_rendered"]} for r in scored),
        "lifecycle_seen": _sum(r["lifecycle_seen"] for r in scored),
        "lifecycle_rendered": _sum({k: 1 for k in r["lifecycle_rendered"]} for r in scored),
        "data_sources_seen": _sum(r["data_sources_seen"] for r in scored),
        "meta_seen": _sum(r["meta_seen"] for r in scored),
        "facts_rendered": _sum({f: 1 for f in r["facts_rendered"]} for r in scored),
    }
    return out


# Reasons that are defects of the recorded draft itself (it would fail OpenTofu as written, or needs an input nobody
# sets), not gaps of the intent design. Reported separately; the raw metric (a) counts them as failures.
DRAFT_DEFECT_REASONS = frozenset({"CONVERT.UNRESOLVED_VARIABLE", "CONVERT.UNSET_VARIABLE",
                                  "CONVERT.UNDECLARED_REFERENCE", "CONVERT.HCL_PARSE_ERROR"})


def _expr_excl(entries: Sequence[Any]) -> Optional[float]:
    counted = [e for e in entries if e.status != "excluded" and not set(e.reasons) & DRAFT_DEFECT_REASONS]
    return (sum(1 for e in counted if e.status == "converted") / len(counted)) if counted else None


def _below(v: Optional[float], bar: float) -> bool:
    return v is not None and v < bar


def _sum(dicts: Iterable[Mapping[str, int]]) -> Dict[str, int]:
    c: collections.Counter = collections.Counter()
    for d in dicts:
        c.update(d)
    return dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))

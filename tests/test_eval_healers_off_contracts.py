"""FD-30 checkpoint C1 (--healers-off): for every healer the harness disables, the identity stub returns the same
type/shape as the REAL product function on a no-op input. Runs the product import in a guarded child process
(same guards and import path as eval/run_child.py), so nothing product-side touches the pytest process."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"
sys.path.insert(0, str(EVAL))

CHILD = r'''
import inspect, json, sys, typing
cfg = json.loads(open(sys.argv[1]).read())
sys.path.insert(0, cfg["eval"])
sys.path.insert(0, cfg["gateway"])
from stackvend_eval.state import get_state
from stackvend_eval.guard import Guard
state = get_state()
g = Guard(state)
g.install_all()
g.seal_genai()
from stackvend_eval import stages as st
from stackvend_eval.blobs import BlobStore
from stackvend_eval.healer_probe import HealerProbe, contract_shape
st.import_product()
probe = HealerProbe(state, cfg["targets"], cfg["gateway"], BlobStore(cfg["blobs"]), healers_off=True)
probe.install()

def ann_text(ann):
    if isinstance(ann, str):
        return ann
    if getattr(ann, "__origin__", None) is not None:
        return repr(ann)
    return getattr(ann, "__name__", repr(ann))

def noop_value(text):
    t = text.replace("typing.", "").replace(" ", "").lower()
    if t.startswith(("optional[", "union[")):
        return None
    return {"dict": {}, "list": [], "set": set(), "bool": False, "int": 0, "str": ""}.get(t.split("[", 1)[0])

def shape(v):
    if isinstance(v, tuple):
        return ["tuple", [type(x).__name__ for x in v]]
    return type(v).__name__

out = {"checked": [], "unsupported": [], "problems": [], "contracts_used": [], "present_qualnames": []}
done = set()
for t in cfg["targets"]:
    if t["kind"] != "function" or t.get("status") not in ("present", "anchored"):
        continue
    s = probe.stats[t["key"]]
    mod = sys.modules.get(t.get("module") or "")
    if mod is None:
        continue
    bound = HealerProbe._resolve(mod, t["qualname"])
    if bound is None:
        continue
    out["present_qualnames"].append(t["qualname"])
    fn = bound.__func__ if isinstance(bound, (staticmethod, classmethod)) else bound
    if s["healers_off"] != "bypassed":
        if t["tier"] != "D":
            real = inspect.unwrap(fn)
            out["unsupported"].append({"key": t["key"], "status": s["healers_off"], "shape": contract_shape(real)})
        continue
    if (t.get("module"), t["qualname"]) in done:
        continue
    done.add((t.get("module"), t["qualname"]))
    if not getattr(fn, "__stackvend_probe__", False):
        out["problems"].append(f"{t['key']}: bypassed but not wrapped")
        continue
    real = fn.__wrapped__
    kind, pname = s["identity"]
    sig = inspect.signature(real)
    try:
        hints = typing.get_type_hints(real)
    except Exception:
        hints = {}
    args = {}
    for i, (name, p) in enumerate(sig.parameters.items()):
        if i == 0 and name in ("self", "cls"):
            owner = HealerProbe._resolve(mod, t["qualname"].rsplit(".", 1)[0])
            try:  # SynthesisVerifierAgent(product_id=None), GitHubProvider(project_id=None, github_token=None, ...)
                args[name] = owner()
            except Exception as e:
                out["problems"].append(f"{t['key']}: cannot construct {owner.__name__}(): {type(e).__name__}: {e}")
                break
            continue
        if p.default is not inspect.Parameter.empty and name != pname:
            continue
        args[name] = noop_value(ann_text(hints.get(name, p.annotation)))
    if any(msg.startswith(t["key"] + ":") for msg in out["problems"]):
        continue
    if kind in ("arg", "str_list", "str_false", "opt_arg") and not isinstance(args.get(pname), str):
        args[pname] = ""
    if kind in ("copy", "copy_list", "none") and not isinstance(args.get(pname), dict):
        args[pname] = {}
    real_in = {k: (dict(v) if isinstance(v, dict) else v) for k, v in args.items()}
    stub_in = {k: (dict(v) if isinstance(v, dict) else v) for k, v in args.items()}
    try:
        real_out = real(**real_in)
    except Exception as e:
        out["problems"].append(f"{t['key']}: real healer raised on no-op input: {type(e).__name__}: {e}")
        continue
    before = probe.stats[t["key"]]["bypass_fallbacks"]
    stub_out = fn(**stub_in)
    rec = {"key": t["key"], "kind": kind, "real": shape(real_out), "stub": shape(stub_out),
           "fallback": probe.stats[t["key"]]["bypass_fallbacks"] != before}
    p_in = stub_in[pname]
    if kind == "arg":
        rec["identity_ok"] = stub_out is p_in
    elif kind == "copy":
        rec["identity_ok"] = stub_out == p_in and stub_out is not p_in
    elif kind == "copy_list":
        rec["identity_ok"] = stub_out == (p_in, []) and stub_out[0] is not p_in
    elif kind == "str_list":
        rec["identity_ok"] = stub_out == (p_in, [])
    elif kind == "str_false":
        rec["identity_ok"] = stub_out == (p_in, False)
    elif kind == "none":
        rec["identity_ok"] = stub_out is None and stub_in[pname] == {}
    elif kind == "empty_dict":
        rec["identity_ok"] = stub_out == {}
    elif kind == "opt_arg":
        rec["identity_ok"] = stub_out is None and p_in == ""
    out["checked"].append(rec)
    out["contracts_used"].append(real.__qualname__)
probe.stop()
print("@@RESULT@@" + json.dumps(out, default=str))
'''

from stackvend_eval.healer_probe import _KIND_RULES  # noqa: E402

# "opt_arg" (Optional[str]) is an extractor shape shared by lookups/classifiers (e.g. HA-14's target-id helper), so
# it is a contract kind for named rows only and never marks an un-contracted callable as a rewriter.
REWRITER_SHAPES = {rule[0] for kind, rule in _KIND_RULES.items() if kind != "opt_arg"}


def _exact_child_env(env):
    """``hermetic_guard.child_env()`` kwargs that give the child exactly ``env`` plus the guard's Layer 0 and inherit
    nothing else from the pytest process (this child must see a minimal, credential-less env)."""
    want = hermetic_guard.hermetic_env(env)
    guarded = set(hermetic_guard.FORCED_ENV) | set(hermetic_guard.SECRET_ENV) | {"PYTHONPATH"}
    return {"drop": tuple(k for k in os.environ if k not in want or k == "PYTHONPATH"),
            "extra": {k: v for k, v in want.items() if k not in guarded}}


def test_every_disabled_healer_stub_matches_the_real_return_shape(tmp_path):
    import run_examples
    from stackvend_eval.healer_probe import IDENTITY_CONTRACTS
    targets = run_examples.anchored_targets(ROOT)
    gateway = str(ROOT / "apps" / "orchestrator-gateway")
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"eval": str(EVAL), "gateway": gateway, "targets": targets,
                               "blobs": str(tmp_path / "blobs")}))
    script = tmp_path / "child.py"
    script.write_text(CHILD)
    env = run_examples.child_env(tmp_path / "env", "gemini-3.8-flash",
                                 json.loads((EVAL / "config" / "prod_env.json").read_text())["env"])
    r = subprocess.run([sys.executable, "-I", "-B", str(script), str(cfg)], capture_output=True, text=True,
                       env=hermetic_guard.child_env(**_exact_child_env(env)),
                       cwd=str(tmp_path), timeout=600)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    res = json.loads(r.stdout.split("@@RESULT@@", 1)[1])
    assert res["problems"] == []
    assert res["checked"], "no healer was bypassed"
    for rec in res["checked"]:
        assert rec["stub"] == rec["real"], rec
        assert rec["identity_ok"] and not rec["fallback"], rec
    # Every contract row names an inventoried healer (no typo rows) and matches every healer still present in this
    # tree (no stale rows); every healer bypassed is in the table. Rows whose healer a later lane deleted from this
    # tree (target status "absent", e.g. lane 8's sanitize_hcl_wif / sanitize_hcl_triggers) stay in the table: the
    # pinned pre-lane-8 baseline product root (--product-root at 44a2747) still has them.
    inventoried = {t["qualname"] for t in targets if t["kind"] == "function"}
    assert set(IDENTITY_CONTRACTS) <= inventoried, set(IDENTITY_CONTRACTS) - inventoried
    present = {t["qualname"] for t in targets if t["kind"] == "function" and t.get("status") in ("present", "anchored")}
    expected = set(IDENTITY_CONTRACTS) & present
    used = set(res["contracts_used"])
    assert used == expected, (expected - used, used - expected)
    # A non-tier-D callable the harness leaves running must not have a rewriter shape (otherwise it needs a row).
    for u in res["unsupported"]:
        assert u["status"] == "unsupported: no identity contract", u
        assert u["shape"] not in REWRITER_SHAPES, u

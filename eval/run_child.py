#!/usr/bin/env python3
"""Generation child: ONE (example, run) in a guarded process. Started by run_examples.py as

    python -I eval/run_child.py --config <run_dir>/child_config.json   (access token, if any, on stdin)

Order (red-team H7): guards (process, grpc, sockets, clients, auth) -> harness LLM backend -> seal genai ->
canary -> freeze date -> product import -> tripwires/observers/probe -> pipeline -> result.json.
Exit codes: 0 finished (see result.json for validity), 3 isolation guard ineffective, 4 harness error (incl.
a product dependency the product's requirements.txt lists but this interpreter cannot import).

    python -I -B eval/run_child.py --check-deps <product_root> [--dep-dir <dir> ...]

prints the same dependency report as JSON (no guards, no product import) and exits 0, or 5 if one is missing.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent


def read_spec(path: str) -> str:
    """The run's spec.md exactly as the parent wrote it: UTF-8, no newline translation (FD-4BN RT fix 7: the spec
    bytes sent are the bytes the manifest hashes, CRLF included)."""
    return Path(path).read_bytes().decode("utf-8")


# --------------------------------------------------------------------------------- TI-0 observers (eval only, $0)
# Each one wraps a product callable to RECORD what happened; it never changes an argument, a return value or an LLM
# request, so a replay-strict run stays byte-identical (proved by served replay == calls, replay_miss == 0).
CONSENSUS_ENV = "ENABLE_DUAL_ARCHITECT_CONSENSUS"


def _sha(obj) -> str:
    import hashlib
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def topology_digest(plan) -> "dict | None":
    """Separate sha256s of each form of the plan's topology (RT F7: pre and post are compared like with like):
    `raw` = the model's `_raw_service_topology` (set by _attach_raw_topology), `typed` = the parsed service_topology,
    `fields` = compute_archetype + target_compute_services + bundle_id. A form that is absent is None."""
    if plan is None:
        return None
    raw = getattr(plan, "_raw_service_topology", None)
    typed = getattr(plan, "service_topology", None)
    typed = typed.model_dump(mode="json") if hasattr(typed, "model_dump") else typed
    return {"raw": None if raw is None else _sha(raw), "typed": None if typed is None else _sha(typed),
            "fields": _sha({"compute_archetype": getattr(plan, "compute_archetype", None),
                            "target_compute_services": list(getattr(plan, "target_compute_services", None) or []),
                            "bundle_id": getattr(plan, "bundle_id", None)})}


def topology_changed(pre, post) -> "tuple":
    """(changed, compared form): True when the fields differ or a form present on BOTH sides differs (typed first,
    then raw: the canonical typed form wins when both sides parsed, so a re-serialized raw answer with the same
    topology is not a change). A plan with no topology on either side (products before lane 10) is compared on the
    fields alone. None when the sides carry different forms only and the fields are equal: not comparable."""
    if pre is None or post is None:
        return None, None
    if pre["fields"] != post["fields"]:
        return True, "fields"
    for form in ("typed", "raw"):
        if pre[form] is not None and post[form] is not None:
            return pre[form] != post[form], form
    if all(d[f] is None for d in (pre, post) for f in ("raw", "typed")):
        return False, "fields"
    return None, None


def topology_sha256(plan) -> "str | None":
    """One sha over every form (display only; `changed` uses topology_changed)."""
    d = topology_digest(plan)
    return None if d is None else _sha(d)


def install_consensus_observer(handler_mod, sink: list) -> dict:
    """consensus_changed_topology: the plan's topology sha before and after DualArchitectConsensusEngine
    .evaluate_and_reconcile (the class the architect handler actually uses). Not called when consensus is off."""
    cls = getattr(handler_mod, "DualArchitectConsensusEngine", None)
    real = getattr(cls, "evaluate_and_reconcile", None)
    if real is None:
        return {"installed": False, "reason": "product has no DualArchitectConsensusEngine.evaluate_and_reconcile"}

    def observed(self, *args, **kwargs):
        plan = kwargs.get("plan", args[0] if args else None)
        pre = topology_digest(plan)
        rec = {"pre_topology_sha256": topology_sha256(plan), "pre": pre}
        try:
            out = real(self, *args, **kwargs)
        except BaseException as e:  # noqa: BLE001 - recorded, then re-raised unchanged
            rec["error"] = type(e).__name__
            sink.append(rec)
            raise
        post = out[0] if isinstance(out, tuple) and out else None
        tel = out[1] if isinstance(out, tuple) and len(out) > 1 else None
        rec["post_topology_sha256"] = topology_sha256(post)
        rec["post"] = topology_digest(post)
        rec["changed"], rec["compared"] = topology_changed(pre, rec["post"])
        rec["consensus_status"] = getattr(tel, "consensus_status", None)
        sink.append(rec)
        return out
    cls.evaluate_and_reconcile = observed
    return {"installed": True}


def install_repair_call_observer(dispatcher_mod, sink: dict) -> dict:
    """repair_calls_by_persona: every SwarmDispatcher.invoke_repair (the one repair call site), by its persona
    argument, with the transport attempts it made (= LLM calls)."""
    import threading
    cls = getattr(dispatcher_mod, "SwarmDispatcher", None)
    real = getattr(cls, "invoke_repair", None)
    if real is None:
        return {"installed": False, "reason": "product has no SwarmDispatcher.invoke_repair"}
    lock = threading.Lock()

    def observed(self, *args, **kwargs):
        persona = kwargs.get("persona", args[0] if args else None)
        out = real(self, *args, **kwargs)
        attempts = out.get("transport_attempts") if isinstance(out, dict) else None
        with lock:
            row = sink.setdefault(str(persona), {"calls": 0, "llm_calls": 0, "envelope_ok": 0})
            row["calls"] += 1
            row["llm_calls"] += int(attempts) if isinstance(attempts, int) and attempts > 0 else 1
            row["envelope_ok"] += 1 if isinstance(out, dict) and out.get("envelope_ok") else 0
        return out
    cls.invoke_repair = observed
    return {"installed": True}


def install_junior_draft_observer(dispatcher_mod, sink: dict) -> dict:
    """first_draft_types / data_sources_used / functions_used need the IaC persona's OWN first draft (C0_raw_swarm is
    every persona merged): record each SwarmDispatcher.invoke_junior_worker result's files under its persona."""
    import threading
    cls = getattr(dispatcher_mod, "SwarmDispatcher", None)
    real = getattr(cls, "invoke_junior_worker", None)
    if real is None:
        return {"installed": False, "reason": "product has no SwarmDispatcher.invoke_junior_worker"}
    lock = threading.Lock()

    async def observed(self, *args, **kwargs):
        res = await real(self, *args, **kwargs)
        persona = getattr(getattr(res, "persona", None), "value", getattr(res, "persona", None))
        files = getattr(res, "files", None)
        if isinstance(files, dict):
            with lock:
                sink.setdefault(str(persona), {}).update({k: v for k, v in files.items() if isinstance(v, str)})
        return res
    cls.invoke_junior_worker = observed
    return {"installed": True}


def install_hb04_append_observer(engine_mod, sink: list) -> dict:
    """platform_blocks_in_ai_files, HB-04 half: the synthesized secondary compute modules HB-04 APPENDS into the AI's
    custom.tf (`append_text(files, custom_key, mod_block)`; the AssemblyRecord records only the in-place
    PLATFORM_RESYNTHESIZED ones). append_text has exactly one caller in terraform_engine (that HB-04 loop); the
    appended text is parsed with the product's own `index_blocks` (python-hcl2), so the address never depends on a
    product variable name (RT F6). A text index_blocks cannot parse is counted under `unparsed`, never dropped."""
    real = getattr(engine_mod, "append_text", None)
    index = getattr(engine_mod, "index_blocks", None)
    if real is None or index is None:
        return {"installed": False, "reason": "product terraform_engine has no append_text / index_blocks"}

    def observed(files, path, text, *args, **kwargs):
        out = real(files, path, text, *args, **kwargs)
        try:
            blocks = index(text)
        except Exception:  # noqa: BLE001 - observation only
            blocks = None
        if blocks is None:
            sink.append({"path": path, "address": None, "unparsed": True})
        for b in blocks or []:
            labels = list(getattr(b, "labels", None) or [])
            if getattr(b, "kind", None) == "module" and labels:
                sink.append({"path": path, "address": f"module.{labels[0]}"})
        return out
    engine_mod.append_text = observed
    return {"installed": True}


def install_architect_failure_observer(pipe, result: dict) -> None:
    """A typed architect-stage failure (a GateError such as TopologyInvalidError -> ARCHITECT_DEFECT) carries its
    ErrorClass on the exception, not a ValidationReport, so stages.Pipeline records it only as an error string.
    Record the class exactly (S2 expects ARCHITECT_DEFECT or an acyclic topology)."""
    real = pipe._architect

    def observed():
        try:
            return real()
        except BaseException as e:  # noqa: BLE001 - recorded, then re-raised unchanged
            ec = getattr(e, "error_class", None)
            if ec is not None:
                diags = list(getattr(e, "diagnostics", None) or [])
                result["architect_failed_typed"] = {
                    "exception": type(e).__name__, "error_class": getattr(ec, "value", ec),
                    "reason": getattr(e, "reason", None),
                    "codes": sorted({str(d.get("code")) for d in diags if isinstance(d, dict) and d.get("code")})}
            raise
    pipe._architect = observed


def install_existing_repo(mods: dict, existing: dict) -> dict:
    """S7 brownfield rerun: the repository read returns the base run's committed tree (production reads the repo's
    main branch here) instead of the greenfield {}."""
    DA = mods["developer_agent.handler"].DeveloperAgent
    tree = {k: v for k, v in (existing.get("tree") or {}).items() if isinstance(v, str)}

    def fetch_existing_repo_files(self_, *args, **kwargs):
        return dict(tree)
    DA.fetch_existing_repo_files = fetch_existing_repo_files
    return {"files": len(tree), "tree_sha": existing.get("tree_sha"), "base": existing.get("base")}


def _provenance_store():
    import importlib
    try:
        return importlib.import_module("developer_agent.hallucination_runtime").get_runtime().provenance_store
    except Exception:  # noqa: BLE001 - pre-Step-1 product: no store
        return None


def seed_provenance(product_id: str, entries: dict) -> int:
    """S7: the IaC provenance the base run's commit wrote (production keeps it in Firestore between runs)."""
    store = _provenance_store()
    if store is None or not entries:
        return 0
    from shared.diagnostics import ProvenanceEntry  # the gateway-local copy the runtime uses
    store.save(product_id, {p: ProvenanceEntry(**e) for p, e in entries.items()})
    return len(entries)


def dump_provenance(product_id: str):
    store = _provenance_store()
    if store is None:
        return None
    try:
        return {p: e.model_dump(mode="json") for p, e in (store.load(product_id) or {}).items()}
    except Exception as e:  # noqa: BLE001 - observation only
        return {"_error": type(e).__name__}


def _read_token() -> str:
    line = sys.stdin.readline()
    if not line.strip():
        return ""
    data = json.loads(line)
    return str(data.get("access_token") or "")


def main() -> int:  # noqa: C901
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--canary-only", action="store_true")
    ap.add_argument("--check-deps", metavar="PRODUCT_ROOT")
    ap.add_argument("--dep-dir", action="append", default=[], help="with --check-deps: a parent-resolved dep dir")
    args = ap.parse_args()
    if args.check_deps:
        sys.path.insert(0, str(EVAL_DIR))
        from stackvend_eval.paths import product_deps_report
        report = product_deps_report(args.check_deps, args.dep_dir)
        print(json.dumps(report, sort_keys=True))
        return 5 if report["missing"] else 0
    if not args.config:
        ap.error("--config is required")
    cfg = json.loads(Path(args.config).read_text())
    run_dir = Path(cfg["run_dir"])
    run_dir.mkdir(parents=True, exist_ok=True)
    gateway = str(Path(cfg["product_root"]).resolve() / "apps" / "orchestrator-gateway")
    sys.path.insert(0, str(EVAL_DIR))
    sys.path.insert(0, gateway)  # production parity: `import shared` resolves to the gateway-local copy

    from stackvend_eval.state import get_state
    from stackvend_eval.guard import Guard
    from stackvend_eval.llm_proxy import LIVE_MODES, LLMProxy, make_live_backend, vertex_hosts

    state = get_state()
    mode = cfg["llm_mode"]
    token = _read_token() if mode in LIVE_MODES else ""
    allow = vertex_hosts(cfg["vertex_location"]) if mode in LIVE_MODES else []
    guard = Guard(state, allow_hosts=allow)
    result: dict = {"schema_version": 1, "example": cfg["example"], "run": cfg["run"], "llm_mode": mode,
                    "model": cfg["model"], "fallback_models": cfg.get("fallback_models"),
                    "product_id": cfg["product_id"], "spec_provenance": cfg.get("spec_provenance"),
                    "started": time.time()}

    def finish(code: int) -> int:
        result["finished"] = time.time()
        result["state"] = state.to_json()
        result["valid_run"] = state.valid and result.get("pipeline_outcome") not in (None, "invalid")
        result["invalid_reasons"] = list(state.invalid_reasons)
        (run_dir / "result.json").write_text(json.dumps(result, indent=1, sort_keys=True, default=str))
        return code

    try:
        state.stage = "guard"
        guard.install_all()
        backend = None
        if mode in LIVE_MODES:
            if not token:
                state.invalidate("harness_error", "live mode without an access token on stdin")
                return finish(4)
            backend = make_live_backend(cfg["vertex_project"], cfg["vertex_location"], token)
            token = ""  # the client holds it; drop our copy
        guard.seal_genai()
        state.stage = "canary"
        from stackvend_eval.canary import run_canary
        canary = run_canary(guard)
        result["canary"] = canary
        if not canary["ok"]:
            state.invalidate("isolation_guard_ineffective", [p for p in canary["probes"] if p["outcome"] != "blocked"])
            return finish(3)
        if args.canary_only:
            result["pipeline_outcome"] = "canary_only"
            return finish(0)

        state.stage = "setup"
        from stackvend_eval.freeze import freeze
        result["frozen_now"] = freeze(cfg["frozen_now"]).isoformat()
        from stackvend_eval import stages as st
        from stackvend_eval.blobs import BlobStore
        from stackvend_eval.budget import Budget, PriceTable
        from stackvend_eval.cassettes import Cassette
        from stackvend_eval.healer_probe import HealerProbe
        from stackvend_eval.tripwires import install_observers, install_tripwires

        os.environ["GEMINI_MODEL"] = cfg["model"]  # B7: explicit, recorded; no implicit default
        # Production parity (Step 1): python-hcl2/lark/pyflakes are gateway requirements now; the child is `python -I`
        # (no site PYTHONPATH), so the pinned eval copies in eval/.deps stand in for the image's site-packages.
        # Without an eval/.deps override they come from this interpreter's own site-packages (kept by -I) or from the
        # directories the parent resolved them in (product_dep_dirs: e.g. its PYTHONPATH, which -I drops). A missing
        # one fails the run here with one named reason, not later as an opaque generation_error.
        from stackvend_eval.paths import missing_deps_message, product_deps_report
        deps = product_deps_report(cfg["product_root"], cfg.get("product_dep_dirs") or [])
        result["product_deps_on_path"] = deps["deps_dir_on_path"]
        result["product_deps"] = deps
        if deps["missing"]:
            state.invalidate("product_dependency_missing", missing_deps_message(deps, cfg["product_root"]))
            return finish(4)
        mods = st.import_product()
        result["pinned_settings"] = st.pin_settings(mods, cfg["model"], cfg.get("fallback_models"))
        st.install_site_shim()
        import asyncio
        asyncio.to_thread.gateway_dir = gateway.rstrip("/") + "/"  # type: ignore[attr-defined]
        originals = install_tripwires(state, mods)

        prices = PriceTable.load(Path(cfg["pricing_path"]))
        budget = Budget(cfg["budget_usd"], cfg["token_cap"], prices, max_calls=cfg["max_calls"], state=state)
        cassette = None
        if mode.startswith("replay"):
            cassette = Cassette.load(Path(cfg["cassette_in"]))
            if mode == "replay-then-live" and cfg.get("cassette_out"):
                cassette.path = Path(cfg["cassette_out"])
                cassette.open_for_record({"example": cfg["example"], "run": cfg["run"], "model": cfg["model"],
                                          "frozen_now": cfg["frozen_now"], "derived_from": cfg["cassette_in"],
                                          **(cfg.get("cassette_meta_extra") or {})})
        elif mode == "record" or (mode == "synthetic" and cfg.get("cassette_out")):
            cassette = Cassette(Path(cfg["cassette_out"]))
            cassette.open_for_record({"example": cfg["example"], "run": cfg["run"], "model": cfg["model"],
                                      "frozen_now": cfg["frozen_now"], **(cfg.get("cassette_meta_extra") or {})})
        if mode == "synthetic":
            from stackvend_eval.synthetic import SyntheticBackend
            backend = SyntheticBackend({
                "architect_fallback": originals["architect_agent.handler.ArchitectAgent._fallback_plan"],
                "lead_fallback": originals["developer_agent.lead_orchestrator.LeadDeveloperOrchestrator."
                                           "_build_deterministic_fallback_plan"],
            })
        proxy = None
        if cfg.get("no_llm_client"):
            result["note"] = "no_llm_client: agents keep genai_client=None (tripwire self-test)"
        else:
            proxy = LLMProxy(mode=mode, budget=budget, state=state, gateway_dir=gateway, example=cfg["example"],
                             run=cfg["run"], backend=backend, cassette=cassette,
                             inject_seed=cfg.get("inject_seed", True),
                             temperature_override=cfg.get("temperature_override"),
                             request_log=(run_dir / "llm_requests.jsonl") if cfg.get("dump_llm_requests") else None)

        blobs = BlobStore(run_dir)
        pipe = st.Pipeline(state=state, mods=mods, proxy=proxy, product_id=cfg["product_id"],
                           # lower(): unchanged for 01-09 ("eval-01-r1"); TI-0 S ids give "eval-s1-r1" (names derived
                           # from a trace id stay lowercase)
                           spec_text=read_spec(cfg["spec_path"]),
                           trace_id=f"eval-{cfg['example'][:2].lower()}-r{cfg['run']}",
                           stop_after=cfg.get("stop_after"), topology_fixture=cfg.get("topology_fixtures"),
                           example=str(cfg.get("example", "")))
        install_observers(state, mods, pipe.checkpoints)
        pipe.install_patches()
        probe = HealerProbe(state, cfg.get("healer_targets", []), gateway, blobs, healers_off=cfg.get("healers_off", False),
                            bypass_ids=cfg.get("bypass_healers") or None)
        probe.install()
        # S2-0: per-branch probe of the HD-15 -> self_correct_hcl chain (observes locals only) and, with
        # --dump-trees, the hermetic export of every assembled tree / self_correct_hcl input (Step 2 plan §2.1).
        from stackvend_eval.branch_probe import BranchProbe
        branch_probe = BranchProbe()
        branch_probe.install()
        tree_dump = None
        if cfg.get("dump_trees"):
            from stackvend_eval.tree_dump import TreeDump
            tree_dump = TreeDump(blobs)
            tree_dump.install(mods, st.rebind)
        # S1-0: hallucination-stack runtime (product >= Step 1 S1-B): memory ledger/provenance stores (F6), the harness
        # V1b client over file IPC, and per-run repair settings. Older product roots have no hook: nothing installed.
        result["hallucination_runtime"] = st.install_hallucination_runtime(
            mods, run_dir=run_dir, validate_client=cfg.get("validate_client") or "none",
            repair_iterations=cfg.get("repair_iterations"), repair_model=cfg.get("repair_model"),
            **({"iac_intent_mode": cfg["iac_intent_mode"]} if cfg.get("iac_intent_mode") is not None
               else {}))   # TI-3 (TI-3h: an explicit "off" is passed too)
        accept_trace: list = []
        if cfg.get("accept_trace") or cfg.get("shadow_accept") is not None:
            shadow = cfg.get("shadow_accept")
            shadow = {int(k): (bool(v[0]), v[1]) for k, v in shadow.items()} if shadow is not None else None
            result["accept_observer"] = st.install_accept_observer(accept_trace, shadow)
        # TI-0 observers (record only) and the S7 brownfield repository
        consensus_calls: list = []
        repair_calls: dict = {}
        result["architect_consensus"] = {
            "requested": cfg.get("architect_consensus", "on"), "env": os.environ.get(CONSENSUS_ENV),
            "observer": install_consensus_observer(mods["architect_agent.handler"], consensus_calls)}
        result["repair_calls"] = {"observer": install_repair_call_observer(
            mods["developer_agent.swarm_dispatcher"], repair_calls)}
        junior_drafts: dict = {}
        hb04_appends: list = []
        result["junior_drafts"] = {"observer": install_junior_draft_observer(
            mods["developer_agent.swarm_dispatcher"], junior_drafts)}
        result["hb04_appends"] = {"observer": install_hb04_append_observer(
            mods["developer_agent.terraform_engine"], hb04_appends)}
        install_architect_failure_observer(pipe, result)
        if cfg.get("existing_repo_path"):
            existing = json.loads(Path(cfg["existing_repo_path"]).read_text())
            result["brownfield"] = install_existing_repo(mods, existing)
            result["brownfield"]["base_compute"] = existing.get("base_compute")
            result["brownfield"]["provenance_seeded"] = seed_provenance(cfg["product_id"],
                                                                        existing.get("provenance") or {})

        state.stage = "pipeline"
        pipe.run()
        result["architect_consensus"]["invocations"] = consensus_calls
        result["repair_calls"]["by_persona"] = dict(sorted(repair_calls.items()))
        result["provenance_after_commit"] = dump_provenance(cfg["product_id"])
        result["junior_drafts"]["trees"] = {p: blobs.put_tree(t) for p, t in sorted(junior_drafts.items())}
        result["hb04_appends"]["appends"] = (hb04_appends if result["hb04_appends"]["observer"].get("installed")
                                             else None)   # RT F6: not observed = unknown, never 0
        probe.stop()
        branch_probe.stop()
        result["self_correct_branches"] = branch_probe.report()
        if tree_dump is not None:
            result["tree_dumps"] = tree_dump.report()
        if cassette is not None:
            cassette.close()

        result["pipeline_outcome"] = pipe.outcome
        result["stages"] = pipe.stages
        result["hallucination_stack"] = pipe.hallucination_stack
        if "accept_observer" in result:
            result["accept_trace"] = accept_trace
        ck = {}
        for name, tree in pipe.checkpoints.items():
            if isinstance(tree, dict):
                ck[name] = {"tree": blobs.put_tree(tree), "files": len(tree)}
            else:
                ck[name] = tree
        if cfg.get("healers_off") and "C2_generated" in ck:
            ck["C1_healers_off"] = ck.pop("C2_generated")
        result["checkpoints"] = ck
        result["healers"] = probe.report()
        result["healers_off"] = bool(cfg.get("healers_off"))
        result["llm"] = proxy.summary() if proxy is not None else {"mode": "none", "calls": 0}
        result["budget"] = budget.snapshot()
        if mode == "synthetic":
            result["synthetic_unknown_sites"] = backend.unknown_sites
        return finish(0)
    except BaseException as e:  # noqa: BLE001
        state.invalidate("harness_error", f"{type(e).__name__}: {e}")
        result["harness_traceback"] = traceback.format_exc()[-6000:]
        return finish(4)


if __name__ == "__main__":
    sys.exit(main())

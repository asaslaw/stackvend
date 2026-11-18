"""SCENARIO-REPLAY-CORPUS child: the terraform server's failed-deploy routing, run in its own process.

The terraform server ships its own `shared/` package (a drifted copy of the gateway's), so its `service.py` cannot be
imported into the gateway's test process. tests/scenario_replay.py runs this script with the scenario's recorded deploy
failure on stdin and gets back the result the server would send to the workflow, plus the route record it would write
on the run (`pipeline_executions/{trace}.stages.terraform.failure_route`).

Real code: `service.TerraformService._route_failed_deploy` and `_record_failure_route`, and for a failed gated plan
the legacy branch of `_classify_plan_failure` (deploy_failure_router.route_from_legacy_diagnostics with the server's
own `is_golden_module_file` / `apply_user_owned`). Faked: the read-only re-plan subprocess (its `plan -json` stdout is
the scenario's recorded engine stream) and the workspace (an empty temporary directory).

A server without the router (DEPLOY-FAILURE-OWNER-ROUTER not merged) returns the recorded result unchanged and no
route: exactly what that server sends. stdin: {"result", "engine_plan_stream", "manifest", "trace_id"}; stdout: one
JSON object {"router": bool, "result", "route_record"}.
"""
import json
import os
import sys
import tempfile

TF_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mcp-servers", "terraform")


def main() -> None:
    req = json.load(sys.stdin)
    sys.path.insert(0, TF_DIR)
    import importlib.util
    spec = importlib.util.spec_from_file_location("service", os.path.join(TF_DIR, "service.py"))
    service = importlib.util.module_from_spec(spec)
    sys.modules["service"] = service
    spec.loader.exec_module(service)
    result = dict(req["result"])
    dfr = getattr(service, "dfr", None)
    if dfr is None:   # a server without the owner router: the recorded result is what it sends
        print(json.dumps({"router": False, "result": result, "route_record": None}))
        return
    stream = req.get("engine_plan_stream")
    with tempfile.TemporaryDirectory() as ws:
        if stream is not None and result.get("compliance_gate_phase", "plan") == "plan":
            diags = dfr.error_diagnostics_from_stream(stream)
            result[dfr.FAILURE_ROUTE_FIELD] = dfr.route_from_legacy_diagnostics(
                diags, phase=dfr.PHASE_PLAN, workspace_dir=ws, manifest=req.get("manifest") or [],
                is_golden=service.is_golden_module_file, user_owned=service.apply_user_owned)
        recorded = {}

        class _Doc:
            def update(self, data):
                recorded.update(data)

        class _Db:
            def collection(self, name):
                return self

            def document(self, doc_id):
                return _Doc()

        class _Server:
            db = _Db()
            _record_failure_route = service.TerraformService._record_failure_route

        out = service.TerraformService._route_failed_deploy(_Server(), result, req.get("trace_id") or "trace")
    record = recorded.get(dfr.STAGE_ROUTE_FIELD_PATH)
    if isinstance(record, dict):
        record.pop("recorded_at", None)   # wall clock: not part of the replay
    print(json.dumps({"router": True, "result": out, "route_record": record}, default=str))


if __name__ == "__main__":
    main()

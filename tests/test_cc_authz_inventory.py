"""FD-4N: Control Center route inventory (deny-by-default authorization).

Every effective FastAPI route must declare exactly ONE authorization policy on its decorator. This test pins:
- the exact route count and the exact (method, path) -> policy table (any new route or policy change is a diff);
- that routes inside included routers are enumerated (FastAPI 0.13x wraps include_router in _IncludedRouter, so a
  naive `app.routes` + isinstance(APIRoute) walk is empty and passes vacuously; red-team B3);
- the exact non-API route set (Mounts and Starlette Routes skip app-level dependencies);
- structural rules for object-keyed path parameters (child objects must be bound to their workload; red-team B1);
- deny-by-default at runtime (an untagged route answers 403) and at boot (assert_all_routes_have_policy raises);
- that authorization code never reads TEST_MODE / MOCK_MODE (AST walk, explicit allow-list; red-team H10);
- FD-4AY: no owner-specific defaults in Control Center code.

The app is imported in a clean subprocess (hermetic_guard.child_env) on the FD-4E hermetic prefix (sockets/DNS refused, ADC
disabled, in-memory Firestore). Run directly with `python tests/test_cc_authz_inventory.py --harness`.
"""
import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

import ast
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
CC = os.path.join(REPO, "apps", "control-center")

EXPECTED_ROUTE_COUNT = 139  # RT14-31 / D4: + POST /api/settings/cc-log-reader/backfill (ADMIN); DELETION-TAG-BANNER: + GET /api/deletion-safety/status (AUTHENTICATED, read-only); CC-NETWORK-POSTURE: + GET /api/settings/network-posture (ADMIN, read-only); SELFUP-B (P3b, CC side): + 6 /api/settings/platform-upgrade routes (ADMIN; writes human); SELFUP-OFF (P3a-OFF): + PUT /api/settings/update-check (ADMIN); FD-7L-F4: + POST /api/settings/runner-identity/mode (ADMIN); SAT-11 (FD-7C P3a + FD-4DA (3)): + 6 Settings > Upgrades routes (ADMIN); GHA-DEPLOY-SWITCH: + PATCH /api/workloads/{product_id}/github-actions-deploy (ADMIN); FD-7L Phase 3: + GET /api/settings/runner-identity, POST .../backfill (ADMIN); FD-4DT: + GET /api/workloads/{product_id}/access (ADMIN); FD-4CI-b-3c: + GET /api/users/access-audit (ADMIN); FD-4CI-b: + PUT /api/settings/vcs-provider (ADMIN); FD-4CV: + GET /api/guide (AUTHENTICATED); lane 18 S2: + POST /api/workloads/{product_id}/sandbox/confirm; lane 18 v3: + 2 Settings routes; +1 L19-11: PATCH /api/workloads/{product_id}/access (ADMIN)
EXPECTED_NON_API = {
    ("Route", "/openapi.json"),
    ("Route", "/docs"),
    ("Route", "/docs/oauth2-redirect"),
    ("Route", "/redoc"),
    ("Mount", "/static/vendor"),  # FD-4AR: vendored SRI-pinned scripts; public by exact prefix /static/vendor/
}

GOLDEN = {
    ("GET", "/"): "AUTHENTICATED",
    ("POST", "/api/alerts/billing"): "PUBSUB_PUSH path=/api/alerts/billing",
    ("GET", "/api/approvals"): "SCOPED",
    ("POST", "/api/approvals/{approval_id}/decision"): "APPROVAL param=approval_id manager",
    ("POST", "/api/assistant/chat"): "SCOPED",
    ("GET", "/api/build-plans/{trace_id}"): "TRACE param=trace_id collection=build_plans",
    ("GET", "/api/deletion-safety/status"): "AUTHENTICATED",  # DELETION-TAG-BANNER: global banner state, every user
    ("GET", "/api/diagram/{product_id}"): "WORKLOAD param=product_id",
    ("POST", "/api/finops/sync-spend"): "ADMIN",  # C10: human manual trigger (was ADMIN_OR_JOB)
    ("GET", "/api/guide"): "AUTHENTICATED",  # FD-4CV Guide tab (read-only; admin-only sections are display-only)
    # FD-7C P3a + FD-4DA (3), routes/platform_release.py: Settings > Upgrades (writes also need a human principal)
    ("GET", "/api/settings/platform-version"): "ADMIN",
    ("GET", "/api/settings/platform-updates"): "ADMIN",
    ("GET", "/api/settings/release-source"): "ADMIN",
    ("PUT", "/api/settings/release-source"): "ADMIN",
    ("PUT", "/api/settings/update-check"): "ADMIN",  # SELFUP-OFF: the "Check for updates" switch (human ADMIN)
    # SELFUP-B (P3b, routes/platform_upgrade.py): the "Update StackVend" button (writes: human ADMIN + typed project id)
    ("GET", "/api/settings/platform-upgrade"): "ADMIN",
    ("POST", "/api/settings/platform-upgrade"): "ADMIN",
    ("POST", "/api/settings/platform-upgrade/{request_id}/retry"): "ADMIN",
    ("POST", "/api/settings/platform-upgrade/{request_id}/rollback"): "ADMIN",
    ("POST", "/api/settings/platform-upgrade/lease/clear"): "ADMIN",
    ("POST", "/api/settings/platform-upgrade/{request_id}/maintenance/restore"): "ADMIN",
    ("GET", "/api/settings/upstream-sync"): "ADMIN",
    ("PUT", "/api/settings/upstream-sync"): "ADMIN",
    ("GET", "/api/ipam/allocations"): "ADMIN",
    ("GET", "/api/pipeline/agents"): "ADMIN",
    ("GET", "/api/pipeline/executions/active"): "SCOPED",
    ("GET", "/api/pipeline/executions/{trace_id}"): "TRACE param=trace_id",
    ("GET", "/api/pipeline/executions/{trace_id}/aar"): "TRACE param=trace_id",
    ("POST", "/api/pipeline/executions/{trace_id}/aar"): "TRACE param=trace_id manager",
    ("POST", "/api/pipeline/executions/{trace_id}/abort"): "TRACE param=trace_id manager",
    ("GET", "/api/pipeline/executions/{trace_id}/logs"): "TRACE param=trace_id",
    ("GET", "/api/pipeline/executions/{trace_id}/stages/{stage_name}/eval"): "TRACE param=trace_id",
    ("POST", "/api/pipeline/executions/{trace_id}/stages/{stage_name}/evaluate"): "TRACE param=trace_id manager",
    ("POST", "/api/pipeline/executions/{trace_id}/stages/{stage_name}/feedback"): "TRACE param=trace_id manager",
    ("POST", "/api/pipeline/executions/{trace_id}/stages/{stage_name}/promote-example"): "ADMIN",
    ("GET", "/api/pipeline/executions/{trace_id}/telemetry"): "TRACE param=trace_id",
    ("GET", "/api/pipeline/overview"): "ADMIN",
    ("GET", "/api/platform/agent-health-glass-pane"): "ADMIN",
    ("GET", "/api/platform/agents/{agent_id}/audit-exceptions"): "ADMIN",
    ("GET", "/api/platform/agents/{agent_id}/details"): "ADMIN",
    ("DELETE", "/api/platform/agents/{agent_role}/directives"): "ADMIN",
    ("POST", "/api/platform/agents/{agent_role}/directives"): "ADMIN",
    ("POST", "/api/platform/agents/{agent_role}/streamline-prompt"): "ADMIN",
    ("GET", "/api/platform/emergency-stop"): "AUTHENTICATED",
    ("POST", "/api/platform/emergency-stop"): "ADMIN",
    ("GET", "/api/prompts"): "ADMIN",
    ("GET", "/api/prompts/{agent_role}"): "ADMIN",
    ("PUT", "/api/prompts/{agent_role}"): "ADMIN",
    ("GET", "/api/prompts/{agent_role}/diff"): "ADMIN",
    ("POST", "/api/prompts/{agent_role}/reset-default"): "ADMIN",
    ("POST", "/api/prompts/{agent_role}/rollback"): "ADMIN",
    ("GET", "/api/prompts/{agent_role}/versions/{version}"): "ADMIN",
    ("GET", "/api/quotas/regional/{project_id}"): "WORKLOAD_BY_PROJECT param=project_id",
    ("GET", "/api/settings"): "AUTHENTICATED",
    ("PUT", "/api/settings"): "ADMIN",
    ("GET", "/api/settings/billing-status"): "ADMIN",
    ("GET", "/api/settings/install-warnings"): "ADMIN",  # lane 18 v3
    ("POST", "/api/settings/managed-tag/backfill"): "ADMIN",  # lane 18 v3
    ("POST", "/api/settings/cc-log-reader/backfill"): "ADMIN",  # RT14-31 / owner decision D4 11-14
    ("GET", "/api/settings/runner-identity"): "ADMIN",  # FD-7L Phase 3
    ("POST", "/api/settings/runner-identity/backfill"): "ADMIN",  # FD-7L Phase 3
    ("POST", "/api/settings/runner-identity/mode"): "ADMIN",  # FD-7L-F4 (+ human, recent sign-in, typed confirm)
    ("GET", "/api/settings/network-posture"): "ADMIN",  # CC-NETWORK-POSTURE (read-only)
    ("GET", "/api/settings/custom-bundles"): "ADMIN",
    ("POST", "/api/settings/custom-bundles"): "ADMIN",
    ("POST", "/api/settings/custom-bundles/scan-repository"): "ADMIN",
    ("DELETE", "/api/settings/custom-bundles/{bundle_id}"): "ADMIN",
    ("GET", "/api/settings/custom-bundles/{bundle_id}"): "ADMIN",
    ("PATCH", "/api/settings/custom-bundles/{bundle_id}"): "ADMIN",
    ("POST", "/api/settings/custom-bundles/{bundle_id}/sync"): "ADMIN",
    ("PATCH", "/api/settings/custom-bundles/{bundle_id}/toggle-active"): "ADMIN",
    ("GET", "/api/settings/folders"): "ADMIN",
    ("POST", "/api/settings/folders"): "ADMIN",
    ("DELETE", "/api/settings/folders/{folder_id:path}"): "ADMIN",
    ("POST", "/api/settings/folders/{folder_id:path}/set-default"): "ADMIN",
    ("GET", "/api/settings/modules"): "ADMIN",
    ("POST", "/api/settings/modules"): "ADMIN",
    ("POST", "/api/settings/modules/register"): "ADMIN",
    ("DELETE", "/api/settings/modules/{module_id}"): "ADMIN",
    ("PATCH", "/api/settings/modules/{module_id}"): "ADMIN",
    ("POST", "/api/settings/modules/{module_id}/sync"): "ADMIN",
    ("POST", "/api/settings/reset-defaults"): "ADMIN",
    ("GET", "/api/settings/skills"): "ADMIN",
    ("POST", "/api/settings/skills"): "ADMIN",
    ("DELETE", "/api/settings/skills/{skill_id}"): "ADMIN",
    ("GET", "/api/settings/skills/{skill_id}"): "ADMIN",
    ("PATCH", "/api/settings/skills/{skill_id}"): "ADMIN",
    ("PUT", "/api/settings/vcs-provider"): "ADMIN",  # FD-4CI-b (9-10)
    ("GET", "/api/settings/vcs-status"): "ADMIN",
    ("GET", "/api/users"): "ADMIN",
    ("POST", "/api/users"): "ADMIN",
    ("GET", "/api/users/access-audit"): "ADMIN",  # FD-4CI-b-3c
    ("DELETE", "/api/users/{email}"): "ADMIN",
    ("PUT", "/api/users/{email}/workloads"): "ADMIN",
    ("GET", "/api/workloads"): "SCOPED",
    ("POST", "/api/workloads"): "ADMIN",
    ("POST", "/api/workloads/bootstrap-castor"): "ADMIN",
    ("POST", "/api/workloads/extract-document-text"): "ADMIN",
    ("POST", "/api/workloads/sweep-expired-sandboxes"): "ADMIN",  # C10 (was ADMIN_OR_JOB)
    ("GET", "/api/workloads/{product_id}/access"): "ADMIN",  # FD-4DT access-editing screen (read only)
    ("PATCH", "/api/workloads/{product_id}/access"): "ADMIN",  # L19-11
    ("PATCH", "/api/workloads/{product_id}/github-actions-deploy"): "ADMIN",  # GHA-DEPLOY-SWITCH
    ("POST", "/api/workloads/{product_id}/archive"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/budget"): "ADMIN",
    ("GET", "/api/workloads/{product_id}/build-plans"): "WORKLOAD param=product_id",
    ("POST", "/api/workloads/{product_id}/decommission"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/deploy-infra"): "WORKLOAD param=product_id manager",
    ("POST", "/api/workloads/{product_id}/deploy-to-folder"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/deployment-lock/unlock"): "WORKLOAD param=product_id manager",
    ("GET", "/api/workloads/{product_id}/details"): "WORKLOAD param=product_id",
    ("GET", "/api/workloads/{product_id}/executions"): "WORKLOAD param=product_id",
    ("POST", "/api/workloads/{product_id}/executions/{trace_id}/resume-cooldown"): "WORKLOAD_CHILD param=product_id child=pipeline_executions/{trace_id} manager",
    ("GET", "/api/workloads/{product_id}/feature-requests"): "WORKLOAD param=product_id",
    ("POST", "/api/workloads/{product_id}/feature-requests"): "WORKLOAD param=product_id manager",
    ("GET", "/api/workloads/{product_id}/feature-requests/{request_id}"): "WORKLOAD_CHILD param=product_id child=feature_requests/{request_id}",
    ("POST", "/api/workloads/{product_id}/feature-requests/{request_id}/retrigger"): "WORKLOAD_CHILD param=product_id child=feature_requests/{request_id} manager",
    ("GET", "/api/workloads/{product_id}/iac-drift-status"): "WORKLOAD param=product_id",
    ("GET", "/api/workloads/{product_id}/iac-upgrades"): "WORKLOAD param=product_id",
    ("GET", "/api/workloads/{product_id}/latest-aar"): "WORKLOAD param=product_id",
    ("POST", "/api/workloads/{product_id}/latest-aar"): "WORKLOAD param=product_id manager",
    ("GET", "/api/workloads/{product_id}/logs"): "WORKLOAD param=product_id",
    ("GET", "/api/workloads/{product_id}/plans"): "WORKLOAD param=product_id",
    ("GET", "/api/workloads/{product_id}/plans/{filename}"): "WORKLOAD param=product_id",
    ("GET", "/api/workloads/{product_id}/plans/{filename}/raw"): "WORKLOAD param=product_id",
    ("GET", "/api/workloads/{product_id}/policies"): "WORKLOAD param=product_id",
    ("PATCH", "/api/workloads/{product_id}/policies"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/redeploy"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/retrigger"): "WORKLOAD param=product_id manager",
    ("POST", "/api/workloads/{product_id}/sandbox/extend"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/sandbox/promote"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/sandbox/confirm"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/sync-spend"): "WORKLOAD param=product_id manager",
    ("POST", "/api/workloads/{product_id}/unarchive"): "ADMIN",
    ("POST", "/api/workloads/{product_id}/upgrade-iac"): "WORKLOAD param=product_id manager",
    ("POST", "/auth/config-client-id"): "PUBLIC",
    ("POST", "/auth/google-login"): "PUBLIC",
    ("GET", "/auth/logout"): "PUBLIC",
    ("POST", "/auth/logout"): "PUBLIC",
    ("GET", "/health"): "PUBLIC",
}

# Path parameters that only select a sub-key INSIDE an object already bound by the route's policy.
SUBKEY_PARAMS = {"stage_name", "filename"}
# Platform-level identifiers (not tenant documents); routes using them must be ADMIN.
ADMIN_ONLY_PARAMS = {"email", "agent_role", "agent_id", "version", "module_id", "skill_id", "bundle_id", "folder_id"}

# TEST_MODE / MOCK_MODE: forbidden everywhere in the Control Center app code except this explicit allow-list.
TESTMODE_ALLOWED = {
    "main.py": 2,                   # the startup refusal guard (K_SERVICE + TEST_MODE/MOCK_MODE)
    "services/finops_sync.py": 3,   # deterministic mock spend in tests (not authorization)
}


# ---------------------------------------------------------------------------------------------- harness (subprocess)
def _harness():
    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "cc_authz_inventory_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    main, auth = ns["main"], ns["auth"]
    import authz
    from fastapi.routing import APIRoute

    out = {"routes": [], "non_api": [], "multi_policy": []}
    for route, path, methods in authz.iter_effective_routes(main.app.routes):
        if isinstance(route, APIRoute):
            pols = authz.policies_of(route)
            if len(pols) != 1:
                out["multi_policy"].append([sorted(methods), path, len(pols)])
            for m in sorted(methods):
                out["routes"].append([m, path, pols[0].describe() if len(pols) == 1 else None,
                                      [p.name for p in route.dependant.path_params],
                                      (pols[0].param, pols[0].child_param) if len(pols) == 1 else None])
        else:
            out["non_api"].append([type(route).__name__, getattr(route, "path", None)])
    out["missing"] = authz.routes_missing_policy(main.app)
    out["public_paths_const"] = sorted(authz.PUBLIC_PATHS)
    out["public_paths_routes"] = sorted(authz.public_paths(main.app))
    out["public_static_prefix"] = authz.PUBLIC_STATIC_PREFIX
    out["naive_api_routes"] = sum(1 for r in main.app.routes if isinstance(r, APIRoute))

    # Deny by default at runtime: a route added without a policy is answered 403 even for the administrator.
    main.app.router.add_api_route("/api/fd4n-untagged-probe", lambda: {"leak": True}, methods=["GET"])
    client = ns["TestClient"](main.app, raise_server_exceptions=False)
    r = client.get("/api/fd4n-untagged-probe", cookies=ns["OWNER_COOKIE"])
    out["untagged_status"] = r.status_code
    out["untagged_leak"] = "leak" in r.text
    try:
        authz.assert_all_routes_have_policy(main.app)
        out["boot_check_raises"] = False
    except RuntimeError as e:
        out["boot_check_raises"] = "fd4n-untagged-probe" in str(e)
    # Code RT F10: a FastAPI that changes route enumeration must make the boot self-check refuse, not pass vacuously.
    real_iter = authz.iter_effective_routes
    authz.iter_effective_routes = lambda routes: ((r, getattr(r, "path", ""), frozenset()) for r in routes
                                                  if type(r).__name__ != "APIRoute")  # pre-0.13x naive walk
    try:
        authz.assert_all_routes_have_policy(main.app)
        out["boot_check_vacuous_raises"] = False
    except RuntimeError as e:
        out["boot_check_vacuous_raises"] = "no API routes" in str(e)
    finally:
        authz.iter_effective_routes = real_iter
    out["network_attempts"] = ns["NETWORK_ATTEMPTS"]
    print(json.dumps(out))


# ---------------------------------------------------------------------------------------------- pytest side
@pytest.fixture(scope="module")
def inv():
    # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy, guard shim)
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL"),
                                   extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_hermetic(inv):
    assert inv["network_attempts"] == []


def test_enumeration_is_not_vacuous(inv):
    # app.routes holds _IncludedRouter wrappers on FastAPI 0.13x: a naive walk finds no APIRoute at all.
    assert len(inv["routes"]) == EXPECTED_ROUTE_COUNT
    assert inv["naive_api_routes"] <= len(inv["routes"])


def test_boot_self_check_refuses_vacuous_enumeration(inv):
    assert inv["boot_check_vacuous_raises"] is True


def test_fastapi_requirement_is_a_floor_never_a_downgrade():
    """Code RT F10: main declared fastapi>=0.110.0 (each castor build resolved the newest release), so an exact pin
    could downgrade the live image. The CC declares the verified version as a FLOOR; the venv must satisfy it."""
    import fastapi
    import starlette
    reqs = {}
    with open(os.path.join(CC, "requirements.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            for name in ("fastapi", "starlette"):
                if line.startswith(name) and line[len(name):len(name) + 1] in ("=", ">", "<", "~", "!"):
                    reqs[name] = line[len(name):]
    assert reqs == {"fastapi": ">=0.143.0", "starlette": ">=1.7.0"}, reqs

    def ver(v):
        return tuple(int(x) for x in v.split(".")[:3])
    assert ver(fastapi.__version__) >= (0, 143, 0)
    assert ver(starlette.__version__) >= (1, 7, 0)


def test_every_route_has_exactly_one_policy(inv):
    assert inv["missing"] == []
    assert inv["multi_policy"] == []
    assert all(r[2] for r in inv["routes"])


def test_golden_policy_table(inv):
    actual = {(m, p): d for m, p, d, _, _ in inv["routes"]}
    assert actual == GOLDEN


def test_exact_non_api_routes(inv):
    # Mounts / Starlette Routes bypass app-level dependencies: only FastAPI's own docs routes (authenticated by the
    # middleware, FD-4M) and the public vendored-scripts mount (FD-4AR) may exist.
    assert {tuple(x) for x in inv["non_api"]} == EXPECTED_NON_API


def test_public_set_equals_middleware_exemptions(inv):
    assert inv["public_paths_routes"] == inv["public_paths_const"]
    assert set(inv["public_paths_const"]) == {"/health", "/auth/google-login", "/auth/config-client-id", "/auth/logout"}
    assert inv["public_static_prefix"] == "/static/vendor/"


def test_object_keyed_path_params_are_bound(inv):
    problems = []
    for m, path, desc, params, binding in inv["routes"]:
        kind = desc.split()[0]
        bound = {b for b in (binding or ()) if b}
        for p in params:
            if kind == "ADMIN":
                continue
            if p in bound or p in SUBKEY_PARAMS and bound:
                continue
            if p in ADMIN_ONLY_PARAMS:
                problems.append(f"{m} {path}: '{p}' is a platform identifier but the route is {kind}")
            else:
                problems.append(f"{m} {path}: path parameter '{p}' is not bound by policy {desc!r}")
        if "{product_id}" in path and kind not in ("ADMIN", "WORKLOAD", "WORKLOAD_CHILD"):
            problems.append(f"{m} {path}: product_id route has policy {kind}")
        if "{trace_id}" in path and kind not in ("ADMIN", "TRACE", "WORKLOAD_CHILD"):
            problems.append(f"{m} {path}: trace_id route has policy {kind}")
        if "{approval_id}" in path and kind != "APPROVAL":
            problems.append(f"{m} {path}: approval route has policy {kind}")
    assert problems == []


def test_untagged_route_is_denied_at_runtime_and_boot(inv):
    assert inv["untagged_status"] == 403
    assert inv["untagged_leak"] is False
    assert inv["boot_check_raises"] is True


def _env_reads(tree):
    """Count reads of TEST_MODE / MOCK_MODE through os.getenv / os.environ.get / os.environ[...]."""
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant) \
                and node.args[0].value in ("TEST_MODE", "MOCK_MODE"):
            n += 1
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) \
                and node.slice.value in ("TEST_MODE", "MOCK_MODE"):
            n += 1
    return n


def _cc_app_files():
    for root, dirs, files in os.walk(CC):
        rel_root = os.path.relpath(root, CC)
        if rel_root.split(os.sep)[0] in ("shared", "infra", ".venv", "venv", "__pycache__"):
            continue
        for f in files:
            if f.endswith(".py") and not f.startswith("test_"):
                yield os.path.normpath(os.path.join(rel_root, f))


def test_authorization_never_reads_test_mode():
    found = {}
    for rel in _cc_app_files():
        with open(os.path.join(CC, rel), encoding="utf-8") as fh:
            n = _env_reads(ast.parse(fh.read()))
        if n:
            found[rel] = n
    assert found == TESTMODE_ALLOWED


def test_no_owner_specific_defaults():
    """FD-4AY: the owner's folder id and GitHub account must not appear as defaults in Control Center code."""
    offenders = []
    for rel in list(_cc_app_files()) + ["templates/dashboard.html", "templates/forbidden.html"]:
        with open(os.path.join(CC, rel), encoding="utf-8") as fh:
            text = fh.read()
        from owner_identifiers import find  # FD-12: identifiers held as SHA-256 digests only
        offenders += [f"{rel}:{n}: {key}" for n, key in find(text, {"owner_handle", "private_repo", "folder_1"})]
    assert offenders == []


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()

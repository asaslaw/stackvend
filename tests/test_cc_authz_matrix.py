"""FD-4N / FD-4O: Control Center authorization matrix + regression cases (red-team B1, B2, B9, B12, B13, H1-H12).

Runs the real Control Center app in a clean subprocess (hermetic_guard.child_env) on the FD-4E hermetic prefix (sockets and DNS
refused and recorded, ADC disabled, in-memory Firestore, really-signed session cookies and Google ID tokens).
TEST_MODE is unset before any request.

What it proves:
- every route x every low-privilege principal (anonymous, unapproved, VIEWER with [], VIEWER/MANAGER of tenant-b,
  the platform service account) is refused on tenant-a objects, with ZERO Firestore writes and zero side-effect
  calls (publisher, LLM evaluator, enforcer, VCS, vending, git);
- canary sweep: no tenant-a canary string appears in any 2xx body, captured LLM prompt or deterministic fallback
  served to a tenant-b / unassigned principal;
- policy-level Do-No-Harm: ADMIN passes every route's policy; tenant-b principals pass their OWN objects;
- the red-team repros (cross-tenant feature-request read, resume-cooldown write, DEPLOY_ONLY retrigger into a
  foreign project), the platform-SA session/login refusal, pseudo-workload isolation, and the billing push contract.
Run directly: `python tests/test_cc_authz_matrix.py --harness`.
"""
import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

CANARY = "CANARY-TENANT-A-7F3E"


# ================================================================================================ harness
def _harness():  # noqa: C901 - one linear scenario script
    import base64
    import copy
    import types
    from unittest.mock import MagicMock, patch

    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "cc_authz_matrix_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    main, auth, fake, identity = ns["main"], ns["auth"], ns["fake"], ns["identity"]
    TestClient, google_token, CC_URLS, FINOPS, LEGIT = (ns["TestClient"], ns["google_token"], ns["CC_URLS"],
                                                         ns["FINOPS"], ns["LEGIT_CLIENT"])
    ns["mode"]("")  # public mode: sessions + Google Sign-In + platform bearer for this service's URLs
    os.environ.pop("TEST_MODE", None)
    os.environ["MANAGED_WORKLOADS_FOLDER_ID"] = "111111111111"

    import authz
    from fastapi.routing import APIRoute
    from starlette.requests import Request
    import routes.agent_evals as r_evals
    import routes.approvals as r_appr
    import routes.settings as r_settings
    import routes.workloads as r_work

    R = {}

    def record(name, problems):
        R[name] = "pass" if not problems else "FAIL: " + json.dumps(problems[:25], default=str)[:3500]

    # ------------------------------------------------------------------ seed (every tenant-a doc carries the canary)
    def col(name):
        return fake.collection(name)

    users = col("authorized_users")
    users.document("owner@example.com").set({"role": "ADMIN", "assigned_workloads": [], "is_active": True})
    users.document("viewer-none@example.com").set({"role": "VIEWER", "assigned_workloads": [], "is_active": True})
    users.document("viewer-b@example.com").set({"role": "VIEWER", "assigned_workloads": ["tenant-b"], "is_active": True})
    users.document("mgr-b@example.com").set({"role": "WORKLOAD_MANAGER", "assigned_workloads": ["tenant-b"], "is_active": True})
    users.document("mgr-castor@example.com").set(
        {"role": "WORKLOAD_MANAGER", "assigned_workloads": ["project-castor"], "is_active": True})
    # Code RT F8: an assignment typed with capitals (main compared lower-cased on both sides) must keep working.
    users.document("mgr-mixedcase@example.com").set(
        {"role": "WORKLOAD_MANAGER", "assigned_workloads": [" Tenant-B "], "is_active": True})
    for t in ("a", "b"):
        tag = CANARY if t == "a" else "tenant-b-visible"
        col("workloads").document(f"tenant-{t}").set({
            "product_id": f"tenant-{t}", "project_id": f"proj-tenant-{t}", "github_repo": f"org/tenant-{t}",
            "default_branch": "main", "status": "ACTIVE", "description": tag, "budget_ceiling_monthly_usd": 100.0})
        col("pipeline_executions").document(f"trace-{t}").set({
            "trace_id": f"trace-{t}", "product_id": f"tenant-{t}", "status": "PAUSED_RATE_LIMIT_COOLDOWN",
            "feature_title": tag, "started_at": "2026-10-01T00:00:00+00:00",
            "after_action_report": {"summary": tag}})
        col("pipeline_executions").document(f"trace-{t}").collection("stage_traces").document("developer").set(
            {"rendered_prompt": tag, "agent_output": tag, "stage_name": "developer"})
        col("approval_requests").document(f"appr-{t}").set({
            "approval_id": f"appr-{t}", "product_id": f"tenant-{t}", "status": "PENDING", "plan_markdown": tag,
            "approval_type": "PULL_REQUEST", "branch_name": "feature-x", "pr_number": 3, "trace_id": f"trace-{t}",
            "summary": tag, "callback_url": "https://workflowexecutions.googleapis.com/v1/projects/p/callbacks/c"})
        col("build_plans").document(f"trace-{t}").set({"product_id": f"tenant-{t}", "trace_id": f"trace-{t}",
                                                       "plan_markdown": tag})
        col("implementation_plans").document(f"plan-{t}").set({"product_id": f"tenant-{t}", "content": tag})
    # tenant-a feature request; tenant-b's carries FORGED tenant-a targets (must be ignored by retrigger, H1)
    # Realistic shape (code RT F2): status + created_at so it enters every feature-request stream/overview query.
    col("feature_requests").document("fr-a").set({"product_id": "tenant-a", "request_id": "fr-a", "title": CANARY,
                                                  "description": CANARY, "project_id": "proj-tenant-a",
                                                  "github_repo": "org/tenant-a", "status": "PENDING_TRIAGE",
                                                  "priority": "MEDIUM", "created_at": "2026-10-02T00:00:00+00:00"})
    col("feature_requests").document("fr-b").set({"product_id": "tenant-b", "request_id": "fr-b", "title": "fr-b",
                                                  "description": "fr-b", "project_id": "proj-tenant-a",
                                                  "github_repo": "org/tenant-a"})
    col("pipeline_executions").document("trace-orphan").set({"trace_id": "trace-orphan", "status": "FAILED",
                                                             "feature_title": CANARY})
    col("approval_requests").document("appr-orphan").set({"approval_id": "appr-orphan", "status": "PENDING",
                                                          "plan_markdown": CANARY})
    col("ipam_allocations").document("a").set({"product_id": "tenant-a", "cidr_block": CANARY})
    col("managed_folders").document("folders_222").set({"folder_id": "folders/222", "display_name": CANARY})

    # ------------------------------------------------------------------ side-effect spies
    future = MagicMock()
    future.result.return_value = "msg-1"
    publisher = MagicMock(name="publisher")
    publisher.publish.return_value = future
    spies = {
        "publisher": publisher,
        "evaluator": MagicMock(name="evaluate_agent_execution", return_value={"overall_score": 1.0}),
        "enforcer": MagicMock(name="get_finops_enforcer", return_value=None),
        "vcs": MagicMock(name="VCSProviderFactory"),
        "vending": MagicMock(name="make_vending_request", return_value=None),
        "branch": MagicMock(name="create_or_verify_branch"),
    }
    patches = [
        patch.object(main, "get_pubsub_publisher", lambda: publisher, create=True),
        patch.object(r_work, "get_pubsub_publisher", lambda: publisher),
        patch.object(r_evals, "evaluate_agent_execution", spies["evaluator"]),
        patch.object(r_appr, "get_finops_enforcer", spies["enforcer"]),
        patch.object(r_appr, "VCSProviderFactory", spies["vcs"]),
        patch.object(main, "make_vending_request", spies["vending"], create=True),
        patch.object(r_settings, "make_vending_request", spies["vending"]),
        patch.object(main, "create_or_verify_branch", spies["branch"], create=True),
        patch.object(r_work, "create_or_verify_branch", spies["branch"]),
    ]
    for p in patches:
        p.start()

    # LLM boundary: a fake google-genai client that records the prompt (no network, no credentials)
    prompts, llm_reply = [], ["model says hello"]

    class _Cfg:
        def __init__(self, **kw):
            self.kw = kw

    class _Models:
        def generate_content(self, model, contents, config):
            prompts.append(f"{contents}\n{config.kw.get('system_instruction', '')}")
            return types.SimpleNamespace(text=llm_reply[0])

    class _Client:
        def __init__(self, **kw):
            self.models = _Models()

    g_genai = types.ModuleType("google.genai")
    g_types = types.ModuleType("google.genai.types")
    g_types.GenerateContentConfig = _Cfg
    g_genai.Client, g_genai.types = _Client, g_types
    sys.modules["google.genai"], sys.modules["google.genai.types"] = g_genai, g_types
    import google
    google.genai = g_genai
    sys.modules["vertexai"] = types.ModuleType("vertexai")  # legacy fallback: unusable, no network

    def spy_calls():
        return {k: (v.publish.call_count if k == "publisher" else v.call_count) for k, v in spies.items()}

    client = TestClient(main.app, raise_server_exceptions=False)

    def cookie(email):
        return {"stackvend_session": auth.create_session_token(email)}

    def bearer(tok):
        return {"Authorization": f"Bearer {tok}"}

    principals = {
        "anon": ({}, {}),
        "intruder": (cookie("intruder@external.org"), {}),
        "viewer_none": (cookie("viewer-none@example.com"), {}),
        "viewer_b": (cookie("viewer-b@example.com"), {}),
        "mgr_b": (cookie("mgr-b@example.com"), {}),
        "platform_sa": ({}, bearer(google_token(FINOPS, CC_URLS[1]))),
    }
    fill = {"product_id": "tenant-a", "trace_id": "trace-a", "request_id": "fr-a", "approval_id": "appr-a",
            "project_id": "proj-tenant-a", "email": "viewer-none@example.com", "agent_role": "architect",
            "agent_id": "architect", "stage_name": "developer", "filename": "plan.md", "folder_id": "folders/222",
            "module_id": "x", "skill_id": "x", "bundle_id": "x", "version": "1"}

    def concrete(path):
        out = path.replace("{folder_id:path}", fill["folder_id"])
        for k, v in fill.items():
            out = out.replace("{" + k + "}", v)
        return out

    routes = []
    for route, path, methods in authz.iter_effective_routes(main.app.routes):
        if isinstance(route, APIRoute):
            for m in sorted(methods):
                routes.append((m, path, authz.policy_of(route)))

    def send(method, url, ck, hd, body=None):
        return client.request(method, url, cookies=ck, headers=hd,
                              json=({} if body is None else body) if method in ("POST", "PUT", "PATCH") else None)

    # ------------------------------------------------------------------ 1. full matrix (denials have no effects)
    problems = {"anon": [], "intruder": [], "platform_sa": [], "lowpriv": [], "effects": [], "canary": []}
    for pname, (ck, hd) in principals.items():
        for method, path, pol in routes:
            if pol.kind == "PUBLIC":
                continue
            if pname == "platform_sa" and pol.kind == "ADMIN_OR_JOB":
                continue  # allowed by design (Scheduler jobs); covered at policy level below + FD-4E harness
            open_route = pol.kind in ("AUTHENTICATED", "SCOPED") and pname not in ("anon", "intruder", "platform_sa")
            before, calls_before = copy.deepcopy(fake.store), spy_calls()
            r = send(method, concrete(path), ck, hd)
            if open_route:
                if r.status_code < 300 and CANARY in r.text:
                    problems["canary"].append(f"{pname} {method} {path}")
                continue
            expected = 401 if pname == "anon" else 403
            key = pname if pname in ("anon", "intruder", "platform_sa") else "lowpriv"
            if r.status_code != expected:
                problems[key].append(f"{pname} {method} {path} -> {r.status_code} {r.text[:120]}")
            if fake.store != before or spy_calls() != calls_before:
                problems["effects"].append(f"{pname} {method} {path} changed state/spies")
            if CANARY in r.text:
                problems["canary"].append(f"{pname} {method} {path} (denied body)")
    record("matrix_anonymous_401_everywhere", problems["anon"])
    record("matrix_unapproved_403_everywhere", problems["intruder"])
    record("matrix_platform_sa_confined_to_job_routes", problems["platform_sa"])
    record("matrix_lowpriv_refused_on_tenant_a", problems["lowpriv"])
    record("matrix_denials_have_zero_side_effects", problems["effects"])
    # H12 / code RT F2: the canary sweep is a recorded case (it was computed but never asserted before).
    open_routes = sorted({f"{m} {p}" for m, p, pol in routes if pol.kind in ("AUTHENTICATED", "SCOPED")})
    if not open_routes:
        problems["canary"].append("sweep is vacuous: no AUTHENTICATED/SCOPED route enumerated")
    record("matrix_canary_never_served_to_other_tenants", problems["canary"])

    # ------------------------------------------------------------------ 2. policy-level Do-No-Harm (no handlers run)
    def mk_request(path_params, email, role, assigned, method="session", aud=""):
        req = Request({"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b"",
                       "path_params": path_params, "state": {}})
        req.state.user_email, req.state.user_role = email, role
        req.state.assigned_workloads, req.state.auth_method, req.state.token_audience = assigned, method, aud
        return req

    from schemas import UserRole
    own = {"product_id": "tenant-b", "trace_id": "trace-b", "request_id": "fr-b", "approval_id": "appr-b",
           "project_id": "proj-tenant-b"}
    dnh = []
    for method, path, pol in routes:
        params = {k: (own.get(k) or fill[k]) for k in fill if "{" + k in path}
        if pol.kind != "PUBSUB_PUSH":
            try:
                authz._check(pol, mk_request(params, "owner@example.com", UserRole.ADMIN, []))
            except Exception as e:  # noqa: BLE001
                dnh.append(f"ADMIN refused by {pol.describe()} on {method} {path}: {e}")
        if pol.kind in ("WORKLOAD", "WORKLOAD_CHILD", "TRACE", "APPROVAL", "WORKLOAD_BY_PROJECT", "SCOPED", "AUTHENTICATED"):
            try:
                authz._check(pol, mk_request(params, "mgr-b@example.com", UserRole.WORKLOAD_MANAGER, ["tenant-b"]))
            except Exception as e:  # noqa: BLE001
                dnh.append(f"tenant-b manager refused on OWN object by {pol.describe()} on {method} {path}: {e}")
        if pol.kind == "ADMIN_OR_JOB":
            try:
                authz._check(pol, mk_request(params, FINOPS, UserRole.ADMIN, [], method="bearer", aud=CC_URLS[1]))
            except Exception as e:  # noqa: BLE001
                dnh.append(f"platform job bearer refused on {method} {path}: {e}")
    record("policy_do_no_harm_admin_and_own_tenant", dnh)

    ck_b = cookie("mgr-b@example.com")
    ck_admin = cookie("owner@example.com")

    # ------------------------------------------------------------------ code RT F8: workload id case handling
    # Workload ids are lower-case by construction (every writer lower-cases: CC create/express/bootstrap, vending,
    # spec-ingestion extract_product_id). Assignments are matched case-insensitively (as on main, so no existing
    # assignee is locked out); a non-lower-case PATH id is refused (exact, documented in authz._check_workload).
    ck_mixed = cookie("mgr-mixedcase@example.com")
    f8 = []
    r = client.get("/api/workloads/tenant-b/policies", cookies=ck_mixed)
    if r.status_code != 200:
        f8.append(["mixed-case assignment locked out of its lower-case workload", r.status_code, r.text[:200]])
    for path in ("/api/workloads/Tenant-B/policies", "/api/workloads/TENANT-B/policies", "/api/workloads/tenant-a/policies"):
        r = client.get(path, cookies=ck_mixed)
        if r.status_code != 403:
            f8.append([path, r.status_code, r.text[:200]])
    record("f8_workload_id_case_exact_and_no_assignee_lockout", f8)

    # ------------------------------------------------------------------ 3. red-team B1 repros (now refused)
    r = client.get("/api/workloads/tenant-b/feature-requests/fr-a", cookies=ck_b)
    record("b1_cross_tenant_feature_request_read", [] if r.status_code == 403 and CANARY not in r.text
           else [r.status_code, r.text[:200]])
    before = copy.deepcopy(fake.store)
    r = client.post("/api/workloads/tenant-b/executions/trace-a/resume-cooldown", cookies=ck_b)
    record("b1_cross_tenant_resume_cooldown_write", [] if r.status_code == 403 and fake.store == before
           else [r.status_code, r.text[:200]])
    pubs = publisher.publish.call_count
    r = client.post("/api/workloads/tenant-b/feature-requests/fr-a/retrigger", cookies=ck_b,
                    json={"execution_mode": "DEPLOY_ONLY", "target_branch": "attacker-branch"})
    record("b1_cross_tenant_deploy_only_retrigger", [] if r.status_code == 403 and publisher.publish.call_count == pubs
           else [r.status_code, r.text[:200]])
    r = client.get("/api/workloads/tenant-b/feature-requests/fr-a", cookies=ck_admin)
    record("b1_admin_child_bound_to_path_workload", [] if r.status_code == 404 else [r.status_code])

    # H1: own retrigger takes targets ONLY from workloads/tenant-b (fr-b carries forged tenant-a targets)
    r = client.post("/api/workloads/tenant-b/feature-requests/fr-b/retrigger", cookies=ck_b,
                    json={"execution_mode": "DEPLOY_ONLY", "target_branch": "attacker-branch"})
    p1 = [] if r.status_code == 400 and publisher.publish.call_count == pubs else [r.status_code, r.text[:200]]
    r = client.post("/api/workloads/tenant-b/feature-requests/fr-b/retrigger", cookies=ck_b,
                    json={"execution_mode": "DEPLOY_ONLY"})
    if r.status_code == 200 and publisher.publish.call_count == pubs + 1:
        payload = json.loads(publisher.publish.call_args.args[1])
        got = {k: payload.get(k) for k in ("product_id", "target_project_id", "github_repo", "target_branch")}
        want = {"product_id": "tenant-b", "target_project_id": "proj-tenant-b", "github_repo": "org/tenant-b",
                "target_branch": "main"}
        if got != want:
            p1.append({"payload": got})
    else:
        p1.append([r.status_code, r.text[:200]])
    pubs = publisher.publish.call_count
    r = client.post("/api/workloads/tenant-b/deploy-infra", cookies=ck_b, json={"branch": "attacker-branch"})
    if not (r.status_code == 400 and publisher.publish.call_count == pubs):
        p1.append(["deploy-infra branch override", r.status_code, r.text[:200]])
    record("h1_retrigger_and_deploy_targets_from_workload_doc_only", p1)

    # ------------------------------------------------------------------ 4. B2/H2 platform SA never gets a session
    probs = []
    r = TestClient(main.app, raise_server_exceptions=False).post(
        "/auth/google-login", json={"credential": google_token(FINOPS, LEGIT)})
    if r.status_code != 403 or r.cookies.get("stackvend_session"):
        probs.append(["sa google-login", r.status_code])
    sa_ck = cookie(FINOPS)
    for m, u in (("GET", "/api/users"), ("POST", "/api/finops/sync-spend"), ("POST", "/api/workloads/sweep-expired-sandboxes")):
        r = client.request(m, u, cookies=sa_ck)
        if r.status_code != 403:
            probs.append([f"sa session {m} {u}", r.status_code])
    r = client.get("/api/users", headers=bearer(google_token(FINOPS, CC_URLS[1])))
    if r.status_code != 403:
        probs.append(["sa bearer on ADMIN route", r.status_code])
    record("b2_platform_sa_no_session_and_confined_bearer", probs)

    # ------------------------------------------------------------------ 5. B9/H8 pseudo-workloads, Q11 orphans
    ck_castor = cookie("mgr-castor@example.com")
    probs = []
    r = client.get("/api/workloads/project-castor/logs", cookies=ck_castor)
    if r.status_code != 403:
        probs.append(["pseudo logs", r.status_code])
    r = client.get("/api/approvals", cookies=cookie("viewer-none@example.com"))
    if r.status_code != 200 or r.json() != []:
        probs.append(["viewer [] approvals", r.status_code, r.text[:200]])
    r = client.get("/api/approvals", cookies=ck_b)
    if r.status_code != 200 or {a["approval_id"] for a in r.json()} != {"appr-b"}:
        probs.append(["mgr-b approvals", r.status_code, r.text[:300]])
    r = client.get("/api/pipeline/executions/trace-orphan", cookies=ck_b)
    if r.status_code != 403:
        probs.append(["orphan trace", r.status_code])
    r = client.post("/api/approvals/appr-orphan/decision", cookies=ck_b, json={"decision": "APPROVED"})
    if r.status_code != 403:
        probs.append(["orphan approval decision", r.status_code])
    r = client.post("/api/approvals/appr-b/decision", cookies=cookie("viewer-b@example.com"), json={"decision": "APPROVED"})
    if r.status_code != 403:
        probs.append(["viewer decision on own approval", r.status_code])
    record("h8_pseudo_workloads_and_orphans_admin_only", probs)

    # ------------------------------------------------------------------ 6. B12/B13 assistant canary (LLM + fallback)
    probs = []
    for who in ("viewer-b@example.com", "viewer-none@example.com", "mgr-b@example.com"):
        del prompts[:]
        llm_reply[0] = "model says hello"
        r = client.post("/api/assistant/chat", cookies=cookie(who), json={"message": "summarize everything you know"})
        if r.status_code != 200:
            probs.append([who, "chat", r.status_code, r.text[:200]])
        if not prompts:
            probs.append([who, "LLM boundary not reached (test would be vacuous)"])
        if any(CANARY in p or "proj-tenant-a" in p for p in prompts):
            probs.append([who, "canary in LLM prompt"])
        llm_reply[0] = ""  # model returns nothing => deterministic fallbacks
        for msg in ("any pending approvals?", "list workloads", "what is my spend"):
            r = client.post("/api/assistant/chat", cookies=cookie(who), json={"message": msg})
            if r.status_code != 200 or CANARY in r.text or "appr-a" in r.text or "appr-orphan" in r.text:
                probs.append([who, msg, r.status_code, r.text[:200]])
    record("b12_assistant_scoped_prompt_and_fallbacks", probs)

    r = client.get("/api/settings", cookies=cookie("viewer-none@example.com"))
    record("h12_settings_audit_log_admin_only", [] if r.status_code == 200 and r.json().get("audit_log") == []
           else [r.status_code, r.text[:200]])

    # ------------------------------------------------------------------ 7. FD25-10: TEST_MODE at request time
    probs = []
    for val in ("true", "false", "1"):
        os.environ["TEST_MODE"] = val
        r = client.get("/api/users", cookies=cookie("viewer-none@example.com"))
        if r.status_code != 403:
            probs.append([val, r.status_code])
    os.environ.pop("TEST_MODE", None)
    record("fd25_10_test_mode_never_disables_rbac", probs)

    # ------------------------------------------------------------------ 8. FD-4O billing push contract
    def push(data, attributes=None, aud=CC_URLS[1] + "/api/alerts/billing", ck=None, email=FINOPS, hdr=True):
        body = {"message": {"data": base64.b64encode(json.dumps(data).encode()).decode(), "messageId": "1",
                            **({"attributes": attributes} if attributes else {})}}
        headers = bearer(google_token(email, aud)) if hdr else {}
        return client.post("/api/alerts/billing", json=body, headers=headers, cookies=ck or {})

    probs = []
    alert = {"budgetDisplayName": "budget-tenant-a", "costAmount": 5.0, "budgetAmount": 1.0}
    if push(alert, hdr=False).status_code != 401:
        probs.append("anonymous push not 401")
    if push(alert, hdr=False, ck=ck_admin).status_code != 403:
        probs.append("admin session push not 403")
    if push(alert, aud=CC_URLS[1]).status_code != 403:
        probs.append("push token with service-URL audience (not the exact path) not 403")
    if push(alert, email="pwn@attacker-proj.iam.gserviceaccount.com").status_code != 401:
        probs.append("foreign SA push not 401")
    # C10 (owner 11-07): the platform-caller allow-list is empty, so the route refuses even the former push identity
    # with the exact per-path audience, for every payload, with zero writes and no enforcer call. The mapping and
    # threshold contract moved with the handler to shared/billing_alerts.py (tests/test_c10_billing_drain.py).
    for name, data, attrs in (
        ("unknown display name", {"budgetDisplayName": "budget-platform-monthly", "costAmount": 999.0}, None),
        ("legit-looking push", {"budgetDisplayName": "budget-tenant-b", "costAmount": 10.0, "budgetAmount": 1.0}, None),
        ("over threshold", {"budgetDisplayName": "budget-tenant-b", "costAmount": 500.0, "budgetAmount": 1.0}, None),
    ):
        before, enf = copy.deepcopy(fake.store), spies["enforcer"].call_count
        r = push(data, attrs)
        if r.status_code != 403 or fake.store != before or spies["enforcer"].call_count != enf:
            probs.append([name, r.status_code, r.text[:200]])
    record("fd4o_billing_push_contract", probs)

    # ------------------------------------------------------------------ register row 41: Direct-IAP => IAP-only humans
    import config as cc_config
    iap_token, IAP_AUD, mode_fn = ns["iap_token"], ns["IAP_AUD"], ns["mode"]
    r41_iap, r41_pub = [], []
    own_ck = cookie("owner@example.com")
    finops_bearer = {"Authorization": "Bearer " + google_token(FINOPS, CC_URLS[1])}
    mode_fn(IAP_AUD)
    try:
        r = client.post("/auth/google-login", json={"credential": "anything"})
        if r.status_code != 404 or "set-cookie" in r.headers:
            r41_iap.append(["google-login behind IAP", r.status_code, r.headers.get("set-cookie")])
        # "absent" = configured nowhere, so no Terraform env pin either (lane 19 L19-0c: a pinned client -> 409).
        # FD-103 (§8 Q3): an anonymous caller is refused (401) before the state read; an IAP administrator reaches the
        # absent state and gets the unchanged row-41 refusal (403). Neither ever gets a cookie.
        with patch.object(cc_config, "oauth_client_id_state", return_value="absent"), \
                patch.object(cc_config, "GOOGLE_OAUTH_CLIENT_ID_ENV_PINNED", False):
            r = client.post("/auth/config-client-id", json={"client_id": "x.apps.googleusercontent.com", "credential": "tok"})
            r_iap_admin = client.post(
                "/auth/config-client-id", json={"client_id": "x.apps.googleusercontent.com", "credential": "tok"},
                headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD)})
        if r.status_code != 401 or "set-cookie" in r.headers:
            r41_iap.append(["first-run anonymous behind IAP", r.status_code, r.headers.get("set-cookie")])
        if r_iap_admin.status_code != 403 or "set-cookie" in r_iap_admin.headers:
            r41_iap.append(["first-run GIS session behind IAP", r_iap_admin.status_code, r_iap_admin.headers.get("set-cookie")])
        r = client.get("/api/workloads", cookies=own_ck)
        if r.status_code != 401:
            r41_iap.append(["admin session cookie honoured behind IAP", r.status_code])
        r = client.get("/api/workloads", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD)})
        if r.status_code != 200:
            r41_iap.append(["valid IAP assertion", r.status_code, r.text[:200]])
        r = client.get("/api/workloads", headers={"x-goog-iap-jwt-assertion": iap_token("owner@example.com", IAP_AUD)},
                       cookies=cookie("viewer-none@example.com"))
        if r.status_code != 200:
            r41_iap.append(["IAP identity wins over a cookie", r.status_code])
        r = client.post("/api/finops/sync-spend", headers=finops_bearer)
        if r.status_code != 403:   # C10: no platform caller any more (the route is ADMIN, humans only)
            r41_iap.append(["former platform bearer on the job route behind IAP", r.status_code, r.text[:200]])
    finally:
        mode_fn("")
    r = client.get("/api/workloads", cookies=own_ck)
    if r.status_code != 200:
        r41_pub.append(["public-mode session cookie", r.status_code])
    r = client.post("/auth/google-login", json={"credential": "not-a-jwt"})
    if r.status_code != 401:
        r41_pub.append(["public-mode google-login still verifies (401 on a bad token)", r.status_code])
    r = client.post("/api/finops/sync-spend", headers=finops_bearer)
    if r.status_code != 403:   # C10: refused in public mode too
        r41_pub.append(["public-mode former platform bearer", r.status_code])
    record("row41_iap_mode_accepts_only_iap_for_humans", r41_iap)
    record("row41_public_mode_unchanged", r41_pub)

    for p in patches:
        p.stop()
    print(json.dumps({"results": R, "network_attempts": ns["NETWORK_ATTEMPTS"], "route_count": len(routes)}))


# ================================================================================================ pytest side
CASES = [
    "matrix_anonymous_401_everywhere",
    "matrix_unapproved_403_everywhere",
    "matrix_platform_sa_confined_to_job_routes",
    "matrix_lowpriv_refused_on_tenant_a",
    "matrix_denials_have_zero_side_effects",
    "matrix_canary_never_served_to_other_tenants",
    "policy_do_no_harm_admin_and_own_tenant",
    "f8_workload_id_case_exact_and_no_assignee_lockout",
    "b1_cross_tenant_feature_request_read",
    "b1_cross_tenant_resume_cooldown_write",
    "b1_cross_tenant_deploy_only_retrigger",
    "b1_admin_child_bound_to_path_workload",
    "h1_retrigger_and_deploy_targets_from_workload_doc_only",
    "b2_platform_sa_no_session_and_confined_bearer",
    "h8_pseudo_workloads_and_orphans_admin_only",
    "b12_assistant_scoped_prompt_and_fallbacks",
    "h12_settings_audit_log_admin_only",
    "fd25_10_test_mode_never_disables_rbac",
    "fd4o_billing_push_contract",
    "row41_iap_mode_accepts_only_iap_for_humans",
    "row41_public_mode_unchanged",
]


@pytest.fixture(scope="module")
def harness():
    # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy, guard shim)
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL", "VENDING_SERVICE_URL"),
                                   extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=600, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_harness_is_hermetic_and_complete(harness):
    assert harness["network_attempts"] == []
    # lane 18 S2: + POST /api/workloads/{product_id}/sandbox/confirm (ADMIN); lane 18 v3: + GET
    # /api/settings/install-warnings, POST /api/settings/managed-tag/backfill (both ADMIN);
    # +1 L19-11 PATCH /api/workloads/{product_id}/access; +1 FD-4CV GET /api/guide (AUTHENTICATED)
    # +1 FD-4DT GET /api/workloads/{product_id}/access (ADMIN); +2 FD-7L Phase 3 GET /api/settings/runner-identity,
    # POST /api/settings/runner-identity/backfill (both ADMIN); +6 SAT-11 Settings > Upgrades routes (all ADMIN);
    # +1 FD-7L-F4 POST /api/settings/runner-identity/mode (ADMIN); +1 SELFUP-OFF PUT /api/settings/update-check (ADMIN)
    # +6 SELFUP-B /api/settings/platform-upgrade routes (all ADMIN; writes need a human principal)
    # +1 CC-NETWORK-POSTURE GET /api/settings/network-posture (ADMIN, read-only)
    # +1 DELETION-TAG-BANNER GET /api/deletion-safety/status (AUTHENTICATED, read-only)
    assert harness["route_count"] == 139  # RT14-31 / D4: + POST /api/settings/cc-log-reader/backfill (ADMIN); DELETION-TAG-BANNER: + GET /api/deletion-safety/status; CC-NETWORK-POSTURE: + GET /api/settings/network-posture; SELFUP-B: + 6 platform-upgrade routes; SELFUP-OFF: + PUT /api/settings/update-check; FD-7L-F4: + POST .../runner-identity/mode; SAT-11: + 6 Settings > Upgrades routes; GHA-DEPLOY-SWITCH: + PATCH .../github-actions-deploy; FD-4CI-b: + PUT /api/settings/vcs-provider; FD-4CI-b-3c: + GET /api/users/access-audit
    assert sorted(harness["results"]) == sorted(CASES)


@pytest.mark.parametrize("case", CASES)
def test_authz_case(harness, case):
    assert harness["results"][case] == "pass", harness["results"][case]


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()

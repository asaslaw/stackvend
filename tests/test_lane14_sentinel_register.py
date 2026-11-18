"""
Wave 2 lane 14 PR-3: the sentinel's ``register_incident`` hook (plan section 2.5 item 6, section 2.4 item 4), used by
sre-telemetry-digest-job. A registered finding goes through the SAME de-duplication, record and dispatch rules as a
log entry; refusals are typed and record nothing.

Hermetic: reuses the in-memory Firestore fake and harness of tests/test_lane14_sentinel.py.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json

import pytest

import test_lane14_sentinel as base

sentinel_mod, main_mod, clf = base.sentinel_mod, base.main_mod, base.clf

SOURCE = "sre-telemetry-digest-job"
EVIDENCE = {"finding_type": "LatencyRegression", "service_name": "api", "severity": "WARNING",
            "summary": "p95 latency of api rose +100.0% week over week (200.0 ms -> 400.0 ms)",
            "recommendation": "Profile request handling of api.", "ratio": 2.0}


DIGEST_SA = "sa-castor-developer@mock-stackvend-project.iam.gserviceaccount.com"
OWN_URL = "https://log-sre-sentinel-service-h4sh.a.run.app"  # base.Harness's resolver answer for this service
BODY = {"product_id": "shop-app", "fingerprint": "latency_regression/api", "source": SOURCE, "evidence": EVIDENCE}


def claims(email=DIGEST_SA, aud=OWN_URL, iss="https://accounts.google.com", verified=True):
    return {"iss": iss, "aud": aud, "email": email, "email_verified": verified}


class FakeVerifier:
    """Stands in for google.oauth2.id_token.verify_oauth2_token: token -> claims (or an exception)."""

    def __init__(self, tokens=None):
        self.tokens = {"good": claims()} if tokens is None else tokens
        self.calls = []

    def __call__(self, token, audiences):
        self.calls.append((token, list(audiences)))
        out = self.tokens.get(token)
        if isinstance(out, Exception) or out is None:
            raise out or ValueError("Token used too late")
        return out


def route_harness(env=None, verifier=None, url_resolver=None):
    resolver_calls = []

    def resolver(project, region, name):
        resolver_calls.append(name)
        return (url_resolver or (lambda p, r, n: f"https://{n}-h4sh.a.run.app"))(project, region, name)

    h = base.Harness(env={"SRE_REGISTRATION_CALLERS": DIGEST_SA, **(env or {})}, url_resolver=resolver)
    h.sentinel._id_token_verifier = verifier if verifier is not None else FakeVerifier()
    return h, resolver_calls


def post(h, headers=None, body=None):
    from fastapi.testclient import TestClient

    main_mod._sentinel = h.sentinel
    try:
        return TestClient(main_mod.app).post("/incidents/register", json=body or BODY,
                                             headers={"Authorization": "Bearer good"} if headers is None else headers)
    finally:
        main_mod._sentinel = None


def register(h, product_id="shop-app", fingerprint="latency_regression/api", evidence=None, source=SOURCE):
    return h.sentinel.register_incident(product_id, fingerprint, EVIDENCE if evidence is None else evidence, source)


def test_registered_finding_is_recorded_as_a_workload_incident_and_not_dispatched_by_default():
    h = base.Harness()
    result = register(h)
    assert result["status"] == "INCIDENT_RECORDED"
    rec = h.incident(result)
    assert rec["classification"]["incident_class"] == clf.WORKLOAD_INCIDENT
    assert rec["classification"]["resource_type"] == sentinel_mod.REGISTERED_RESOURCE_TYPE
    assert rec["classification"]["entry_project"] == "child-shop-1"
    assert rec["product_id"] == "shop-app" and rec["source"] == SOURCE and rec["service_name"] == "api"
    assert rec["auto_remediation_status"] == "SUPPRESSED:INTAKE_CONTRACT_PENDING"
    assert rec["rca"]["root_cause_summary"] == EVIDENCE["summary"]
    assert rec["rca"]["affected_repository"] == "acme/shop-app"
    assert rec["rca"]["exception_type"] == "LatencyRegression"
    assert rec["log_name"] is None and rec["log_severity"] == "WARNING"
    assert rec["evidence"]["ratio"] == 2.0
    assert h.starts == []


def test_registered_finding_dispatches_only_through_the_normal_gates():
    h = base.Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    result = register(h)
    assert result["auto_remediation_status"] == "DISPATCHED" and len(h.starts) == 1
    assert h.starts[0][1]["execution_mode"] == "FULL_BUILD"
    frozen = base.Harness(env={"SRE_INTAKE_ACCEPTED_MODES": json.dumps(["FULL_BUILD"])})
    frozen.db.data["workloads"]["shop-app"]["code_freeze"] = True
    assert register(frozen)["auto_remediation_status"] == "SUPPRESSED:CODE_FREEZE" and frozen.starts == []


def test_repeat_registration_within_the_cooldown_clusters_onto_the_open_incident():
    h = base.Harness()
    first = register(h)
    second = register(h)
    assert second["status"] == "DUPLICATE_CLUSTERED" and second["incident_id"] == first["incident_id"]
    other = register(h, fingerprint="latency_regression/web")
    assert other["status"] == "INCIDENT_RECORDED" and other["incident_id"] != first["incident_id"]


@pytest.mark.parametrize("kwargs,code", [
    ({"source": "someone-else"}, "UNKNOWN_SOURCE"),
    ({"source": None}, "UNKNOWN_SOURCE"),
    ({"product_id": "ghost-app"}, "PRODUCT_NOT_IN_LEDGER"),
    ({"product_id": "project-castor"}, "PLATFORM_WORKLOAD"),
    ({"product_id": ""}, "INVALID_REQUEST"),
    ({"fingerprint": "x" * 300}, "INVALID_REQUEST"),
    ({"evidence": ["not", "an", "object"]}, "INVALID_REQUEST"),
    ({"evidence": {"blob": "x" * 20000}}, "INVALID_REQUEST"),
])
def test_refused_registrations_record_nothing(kwargs, code):
    h = base.Harness()
    with pytest.raises(sentinel_mod.RegistrationRejected) as exc:
        register(h, **kwargs)
    assert exc.value.code == code
    assert "incidents" not in h.db.data and "incident_clusters" not in h.db.data


def test_project_shared_by_two_ledger_docs_is_refused():
    h = base.Harness()
    h.db.data["workloads"]["twin-app"] = {"project_id": "child-shop-1", "status": "ACTIVE"}
    with pytest.raises(sentinel_mod.RegistrationRejected) as exc:
        register(h)
    assert exc.value.code == "PRODUCT_AMBIGUOUS" and "incidents" not in h.db.data


def test_ledger_doc_pointing_at_the_host_project_is_refused():
    h = base.Harness()
    h.db.data["workloads"]["evil-app"] = {"project_id": base.HOST, "status": "ACTIVE"}
    with pytest.raises(sentinel_mod.RegistrationRejected) as exc:
        register(h, product_id="evil-app")
    assert exc.value.code == "HOST_PROJECT"


def test_firestore_unavailable_raises_for_a_retry():
    h = base.Harness()
    h.db.failing.add("workloads")
    with pytest.raises(sentinel_mod.FirestoreUnavailable):
        register(h)


def test_register_route_answers_typed_422_and_503():
    h, _ = route_harness()
    ok = post(h)
    refused = post(h, body={"product_id": "ghost-app", "fingerprint": "f", "source": SOURCE, "evidence": {}})
    h.db.failing.add("workloads")
    down = post(h, body={"product_id": "shop-app", "fingerprint": "f", "source": SOURCE, "evidence": {}})
    assert ok.status_code == 200 and ok.json()["status"] == "INCIDENT_RECORDED"
    assert refused.status_code == 422 and refused.json() == {"status": "NOT_RECORDED",
                                                             "error_class": "PRODUCT_NOT_IN_LEDGER",
                                                             "detail": "ghost-app"}
    assert down.status_code == 503 and down.json()["error_class"] == "FIRESTORE_UNAVAILABLE"


# ---------------------------------------------------------------------------------------------------------------
# RT F3-1: caller identity on POST /incidents/register (fail closed; lane 18 authenticate_caller pattern)
# ---------------------------------------------------------------------------------------------------------------
def test_allow_listed_caller_with_a_token_for_this_service_is_recorded_with_its_identity():
    h, _ = route_harness()
    resp = post(h)
    assert resp.status_code == 200 and resp.json()["status"] == "INCIDENT_RECORDED"
    assert h.incident(resp.json())["registered_by"] == DIGEST_SA
    assert h.sentinel._id_token_verifier.calls == [("good", [OWN_URL])]  # aud = this service's own URL


def test_unset_allow_list_is_503_callers_unconfigured_and_records_nothing():
    verifier = FakeVerifier()
    h, resolver_calls = route_harness(env={"SRE_REGISTRATION_CALLERS": ""}, verifier=verifier)
    resp = post(h)
    assert resp.status_code == 503
    assert resp.json() == {"status": "NOT_RECORDED", "error_class": "CALLERS_UNCONFIGURED",
                           "detail": "SRE_REGISTRATION_CALLERS is not configured"}
    assert verifier.calls == [] and resolver_calls == []
    assert "incidents" not in h.db.data and "incident_clusters" not in h.db.data


def test_unresolved_own_url_is_503_audience_unconfigured_and_records_nothing():
    verifier = FakeVerifier()
    h, _ = route_harness(verifier=verifier, url_resolver=lambda p, r, n: None)
    resp = post(h)
    assert resp.status_code == 503 and resp.json()["error_class"] == "AUDIENCE_UNCONFIGURED"
    assert verifier.calls == [] and "incidents" not in h.db.data


@pytest.mark.parametrize("headers,tokens,status,code", [
    ({}, None, 401, "UNAUTHENTICATED"),                                                    # missing header
    ({"Authorization": "Basic good"}, None, 401, "UNAUTHENTICATED"),
    ({"Authorization": "Bearer"}, None, 401, "UNAUTHENTICATED"),
    ({"Authorization": "Bearer bad"}, None, 401, "UNAUTHENTICATED"),                       # signature/expiry
    ({"Authorization": "Bearer good"}, {"good": claims(aud="https://other-service.a.run.app")}, 401, "UNAUTHENTICATED"),
    ({"Authorization": "Bearer good"}, {"good": claims(iss="https://evil.example")}, 401, "UNAUTHENTICATED"),
    ({"Authorization": "Bearer good"}, {"good": claims(email="sa-intruder@x.iam.gserviceaccount.com")}, 403,
     "CALLER_NOT_ALLOWED"),
    ({"Authorization": "Bearer good"}, {"good": claims(verified=False)}, 403, "CALLER_NOT_ALLOWED"),
    ({"Authorization": "Bearer good"}, {"good": claims(email=None)}, 403, "CALLER_NOT_ALLOWED"),
])
def test_unauthenticated_or_unlisted_callers_are_refused_and_record_nothing(headers, tokens, status, code):
    h, _ = route_harness(verifier=FakeVerifier(tokens))
    resp = post(h, headers=headers)
    assert resp.status_code == status and resp.json()["error_class"] == code
    assert resp.json()["status"] == "NOT_RECORDED"
    assert "incidents" not in h.db.data and "incident_clusters" not in h.db.data


def test_allow_list_is_exact_and_case_insensitive():
    h, _ = route_harness(env={"SRE_REGISTRATION_CALLERS": f" {DIGEST_SA.upper()} , other@x.iam.gserviceaccount.com"})
    assert post(h).status_code == 200
    near = route_harness(verifier=FakeVerifier({"good": claims(email=DIGEST_SA + ".evil")}))[0]
    assert post(near).status_code == 403


def test_configured_own_url_is_an_accepted_audience():
    configured = "https://log-sre-sentinel-service-123456789.us-central1.run.app"
    verifier = FakeVerifier({"good": claims(aud=configured)})
    h, _ = route_harness(env={"SRE_SENTINEL_URL": configured + "/"}, verifier=verifier)
    assert post(h).status_code == 200
    assert verifier.calls == [("good", [configured, OWN_URL])]


def test_log_sink_entries_are_unchanged_by_the_shared_record_path():
    """Do-No-Harm negative test: a log entry records with the same fields as before PR-3 (no registration fields)."""
    h = base.Harness()
    rec = h.incident(h.process(base.run_service_entry("my-gateway-app", project="child-shop-1")))
    assert rec["classification"]["incident_class"] == clf.WORKLOAD_INCIDENT
    assert rec["classification"]["resource_type"] == "cloud_run_revision"
    assert "source" not in rec and "evidence" not in rec and "registered_fingerprint" not in rec
    assert rec["rca"]["exception_type"] == "KeyError"  # stack-trace RCA, not the registration override

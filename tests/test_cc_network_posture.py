"""Row CC-NETWORK-POSTURE (internal-ingress plan §6.2 / §7.2 b): Settings ▸ install status "Platform network" card.

GET /api/settings/network-posture (ADMIN, read-only) reads, for every component of shared/release_manifest.COMPONENTS,
the Run Admin API v2 `ingress` (services) and `template.vpcAccess` (services) / `template.template.vpcAccess` (jobs),
and gives one verdict per component: OK, INGRESS_PUBLIC, INGRESS_CALLER_OFF_VPC, QA_JOB_ON_HOST_VPC (or NOT_CHECKED
when a read fails; never OK). One test per verdict; the Admin API is a fake (no network, no credentials), and the
card writes nothing (GET only).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import re
import sys

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(BASE_DIR, "apps", "control-center")
for _p in (BASE_DIR, CC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_saved_client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "cc-network-posture-test.apps.googleusercontent.com"
try:
    from routes import network_posture as np  # noqa: E402
    from shared import release_manifest as rm  # noqa: E402
finally:
    if _saved_client_id is None:
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
    else:
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = _saved_client_id

PROJ, REGION = "mock-stackvend-project", "us-central1"
CC = "product-control-center-ui"
QA = "qa-sandbox-test-runner"
HOST_NET = f"projects/{PROJ}/global/networks/stackvend-host"
HOST_SUB = f"projects/{PROJ}/regions/{REGION}/subnetworks/stackvend-host-{REGION}"
QA_NET = f"projects/{PROJ}/global/networks/castor-qa-sandbox"
HOST_VPC = {"networkInterfaces": [{"network": HOST_NET, "subnetwork": HOST_SUB}], "egress": "PRIVATE_RANGES_ONLY"}
QA_VPC = {"networkInterfaces": [{"network": QA_NET}], "egress": "ALL_TRAFFIC"}


def _world(ingress="INGRESS_TRAFFIC_INTERNAL_ONLY", vpc=HOST_VPC, qa_vpc=QA_VPC):
    """Target posture by default: every non-CC service internal-only, everything but the QA job on the host network."""
    w = {}
    for name, kind, _ in rm.COMPONENTS:
        v = copy.deepcopy(qa_vpc if name == QA else vpc)
        if kind == "service":
            w[name] = {"ingress": "INGRESS_TRAFFIC_ALL" if name == CC else ingress, "template": {}}
            if v is not None:
                w[name]["template"]["vpcAccess"] = v
        else:
            w[name] = {"template": {"template": {} if v is None else {"vpcAccess": v}}}
    return w


class FakeRunApi:
    URL = re.compile(r"https://run\.googleapis\.com/v2/projects/([^/]+)/locations/([^/]+)/(services|jobs)/([^/]+)")

    def __init__(self, world, status=None):
        self.world, self.status, self.urls = world, status or {}, []

    def __call__(self, url):
        self.urls.append(url)
        m = self.URL.fullmatch(url)
        assert m and m.group(1) == PROJ and m.group(2) == REGION, url
        name = m.group(4)
        assert (m.group(3) == "services") == (rm.COMPONENT_KINDS[name] == "service"), url
        if name in self.status:
            return self.status[name], None
        if name not in self.world:
            return 404, {"error": {"code": 404}}
        return 200, copy.deepcopy(self.world[name])


@pytest.fixture
def make_client(monkeypatch):
    monkeypatch.setattr(np, "PROJECT_ID", PROJ)
    monkeypatch.setattr(np, "region_provider", lambda: REGION)
    monkeypatch.setattr(np, "_cache", {})   # F7: every test reads afresh

    def _make(api, role="ADMIN"):
        monkeypatch.setattr(np, "cloud_run_get_json", api)
        app = FastAPI()

        @app.middleware("http")
        async def _auth(request: Request, call_next):
            request.state.user_email, request.state.user_role, request.state.auth_method = "owner@example.com", role, "iap"
            return await call_next(request)

        app.include_router(np.router)
        return TestClient(app)
    return _make


def _card(make_client, world, **kw):
    api = FakeRunApi(world, **kw)
    r = make_client(api).get("/api/settings/network-posture")
    assert r.status_code == 200, r.text
    return r.json(), api


def _rows(card):
    return {row["component"]: row for row in card["components"]}


def test_every_component_is_read_once_from_the_v2_api(make_client):
    card, api = _card(make_client, _world())
    assert [row["component"] for row in card["components"]] == [n for n, _, _ in rm.COMPONENTS]
    assert len(api.urls) == len(rm.COMPONENTS) == len(set(api.urls))


def test_ok_target_posture(make_client):
    card, _ = _card(make_client, _world())
    assert card["verdict"] == "OK" and card["internal_ingress_active"] is True
    assert card["host_network"] == "stackvend-host"
    rows = _rows(card)
    assert {r["verdict"] for r in rows.values()} == {"OK"}
    assert rows[CC]["ingress"] == "INGRESS_TRAFFIC_ALL"   # the Control Center stays public: never flagged
    assert rows["mcp-terraform-server"]["vpc"]["networks"] == [HOST_NET]
    assert rows["mcp-terraform-server"]["vpc"]["egress"] == "PRIVATE_RANGES_ONLY"
    assert rows["tf-applier"]["ingress"] is None and rows["tf-applier"]["vpc"]["on_host_network"] is True
    assert rows[QA]["vpc"]["on_host_network"] is False
    assert card["counts"]["OK"] == len(rm.COMPONENTS)


def test_ingress_public(make_client):
    w = _world()
    w["mcp-gcloud-server"]["ingress"] = "INGRESS_TRAFFIC_ALL"
    card, _ = _card(make_client, w)
    rows = _rows(card)
    assert rows["mcp-gcloud-server"]["verdict"] == "INGRESS_PUBLIC"
    assert rows["mcp-gcloud-server"]["messages"][0].startswith("mcp-gcloud-server accepts internet traffic")
    assert card["verdict"] == "ATTENTION" and card["counts"]["INGRESS_PUBLIC"] == 1
    assert {n for n, r in rows.items() if r["verdict"] != "OK"} == {"mcp-gcloud-server"}


def test_todays_posture_is_public_and_callers_off_the_network_are_not_flagged(make_client):
    """Before the flip (every service ALL, no network): 13 INGRESS_PUBLIC, and no INGRESS_CALLER_OFF_VPC, because no
    request is refused yet."""
    card, _ = _card(make_client, _world(ingress="INGRESS_TRAFFIC_ALL", vpc=None, qa_vpc=None))
    rows = _rows(card)
    assert card["internal_ingress_active"] is False
    public = {n for n, r in rows.items() if r["verdict"] == "INGRESS_PUBLIC"}
    assert public == {n for n, k, _ in rm.COMPONENTS if k == "service" and n != CC}
    assert card["counts"]["INGRESS_CALLER_OFF_VPC"] == 0
    assert rows[CC]["verdict"] == "OK" and rows[QA]["verdict"] == "OK"
    # F5: expected until the install has the platform network -> information, not a warning (not amber)
    assert card["platform_network_present"] is False and card["verdict"] == "INFO"
    assert {rows[n]["severity"] for n in public} == {"info"}
    assert card["note"].startswith("This install has no platform network (stackvend-host) yet")


def test_ingress_public_is_a_warning_once_the_install_has_the_network(make_client):
    """F5: Phase 2 applied (everything on stackvend-host, ingress still ALL) -> INGRESS_PUBLIC is a warning."""
    card, _ = _card(make_client, _world(ingress="INGRESS_TRAFFIC_ALL"))
    rows = _rows(card)
    assert card["platform_network_present"] is True and card["internal_ingress_active"] is False
    assert card["verdict"] == "ATTENTION" and card["note"] == ""
    assert rows["mcp-terraform-server"]["verdict"] == "INGRESS_PUBLIC"
    assert rows["mcp-terraform-server"]["severity"] == "warning"
    assert rows[CC]["severity"] == "ok"


def test_one_component_on_the_network_counts_as_present(make_client):
    w = _world(ingress="INGRESS_TRAFFIC_ALL", vpc=None, qa_vpc=None)
    w["tf-applier"]["template"]["template"]["vpcAccess"] = copy.deepcopy(HOST_VPC)
    card, _ = _card(make_client, w)
    assert card["platform_network_present"] is True and card["verdict"] == "ATTENTION"


def test_the_qa_job_on_another_network_does_not_count_as_present(make_client):
    card, _ = _card(make_client, _world(ingress="INGRESS_TRAFFIC_ALL", vpc=None))   # QA job on the sandbox network
    assert card["platform_network_present"] is False and card["verdict"] == "INFO"


@pytest.mark.parametrize("value", ["INGRESS_TRAFFIC_UNSPECIFIED", "INGRESS_TRAFFIC_SOMETHING_NEW"])
def test_an_unknown_ingress_is_not_checked_and_never_internal(make_client, value):
    """F3: only INGRESS_TRAFFIC_ALL and the three internal values are read; anything else is NOT_CHECKED."""
    w = _world(ingress="INGRESS_TRAFFIC_ALL", vpc=None, qa_vpc=None)
    w["mcp-gcloud-server"]["ingress"] = value
    card, _ = _card(make_client, w)
    row = _rows(card)["mcp-gcloud-server"]
    assert row["verdict"] == "NOT_CHECKED" and row["error"].startswith("BAD_RESPONSE") and value in row["error"]
    assert card["internal_ingress_active"] is False and card["counts"]["INGRESS_CALLER_OFF_VPC"] == 0


@pytest.mark.parametrize("value", ["INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
                                   "INGRESS_TRAFFIC_NONE"])
def test_each_internal_value_counts_as_internal(make_client, value):
    w = _world(ingress="INGRESS_TRAFFIC_ALL")
    w["mcp-gcloud-server"]["ingress"] = value
    assert _card(make_client, w)[0]["internal_ingress_active"] is True


def test_the_card_is_cached_for_a_minute(make_client, monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr(np, "clock", lambda: t["now"])
    api = FakeRunApi(_world())
    c = make_client(api)
    c.get("/api/settings/network-posture")
    c.get("/api/settings/network-posture")
    assert len(api.urls) == len(rm.COMPONENTS)
    t["now"] += np.CACHE_SECONDS + 1
    c.get("/api/settings/network-posture")
    assert len(api.urls) == 2 * len(rm.COMPONENTS)


def test_known_limitations_names_the_public_services():
    text = open(os.path.join(BASE_DIR, "documentation", "known-limitations.md"), encoding="utf-8").read()
    assert "Platform network" in text and "stackvend-host" in text


@pytest.mark.parametrize("off", ["tf-applier", CC, "orchestrator-gateway-service", "sandbox-garbage-collector-job"])
def test_ingress_caller_off_vpc(make_client, off):
    w = _world()
    tmpl = w[off]["template"]["template"] if rm.COMPONENT_KINDS[off] == "job" else w[off]["template"]
    tmpl.pop("vpcAccess")
    card, _ = _card(make_client, w)
    rows = _rows(card)
    assert rows[off]["verdict"] == "INGRESS_CALLER_OFF_VPC"
    assert rows[off]["vpc"]["networks"] == []
    assert {n for n, r in rows.items() if r["verdict"] != "OK"} == {off}


def test_a_caller_on_another_network_or_a_connector_is_off_the_host_network(make_client):
    w = _world()
    w["mcp-github-toolserver"]["template"]["vpcAccess"] = {"connector": f"projects/{PROJ}/locations/{REGION}/connectors/c"}
    w["github-refactor-scanner-job"]["template"]["template"]["vpcAccess"] = copy.deepcopy(QA_VPC)
    rows = _rows(_card(make_client, w)[0])
    assert rows["mcp-github-toolserver"]["verdict"] == "INGRESS_CALLER_OFF_VPC"
    assert rows["mcp-github-toolserver"]["vpc"]["connector"]
    assert rows["github-refactor-scanner-job"]["verdict"] == "INGRESS_CALLER_OFF_VPC"


def test_a_public_service_off_the_network_carries_both_findings(make_client):
    w = _world()
    w["mcp-infracost-server"]["ingress"] = "INGRESS_TRAFFIC_ALL"
    w["mcp-infracost-server"]["template"].pop("vpcAccess")
    row = _rows(_card(make_client, w)[0])["mcp-infracost-server"]
    assert row["findings"] == ["INGRESS_PUBLIC", "INGRESS_CALLER_OFF_VPC"] and row["verdict"] == "INGRESS_PUBLIC"


@pytest.mark.parametrize("network", [HOST_NET, "stackvend-host", "projects/123456789012/global/networks/stackvend-host"])
def test_qa_job_on_host_vpc(make_client, network):
    w = _world()
    w[QA]["template"]["template"]["vpcAccess"] = {"networkInterfaces": [{"network": network}], "egress": "ALL_TRAFFIC"}
    card, _ = _card(make_client, w)
    rows = _rows(card)
    assert rows[QA]["verdict"] == "QA_JOB_ON_HOST_VPC"
    assert "untrusted generated code" in rows[QA]["messages"][0]
    assert {n for n, r in rows.items() if r["verdict"] != "OK"} == {QA}


def test_qa_job_off_every_network_is_ok(make_client):
    w = _world()
    w[QA]["template"]["template"].pop("vpcAccess")
    assert _rows(_card(make_client, w)[0])[QA]["verdict"] == "OK"


@pytest.mark.parametrize("status", [403, 500])
def test_a_failed_read_is_not_checked_never_ok(make_client, status):
    card, _ = _card(make_client, _world(), status={"mcp-compliance-server": status})
    row = _rows(card)["mcp-compliance-server"]
    assert row["verdict"] == "NOT_CHECKED" and row["error"] == f"READ_FAILED: HTTP {status}"
    assert card["verdict"] == "ATTENTION"


def test_a_missing_component_is_not_deployed(make_client):
    w = _world()
    del w["castor-git-server"]
    row = _rows(_card(make_client, w)[0])["castor-git-server"]
    assert row["verdict"] == "NOT_CHECKED" and row["error"].startswith("NOT_DEPLOYED")


def test_a_service_without_a_typed_ingress_is_not_checked(make_client):
    w = _world()
    del w["mcp-workspace-connector"]["ingress"]
    row = _rows(_card(make_client, w)[0])["mcp-workspace-connector"]
    assert row["verdict"] == "NOT_CHECKED" and row["error"].startswith("BAD_RESPONSE")


def test_an_unreadable_service_does_not_count_as_internal(make_client):
    w = _world(ingress="INGRESS_TRAFFIC_ALL", vpc=None, qa_vpc=None)
    card, _ = _card(make_client, w, status={"mcp-terraform-server": 500})
    assert card["internal_ingress_active"] is False
    assert card["counts"]["INGRESS_CALLER_OFF_VPC"] == 0


def test_no_credentials_marks_every_component_not_checked(make_client, monkeypatch):
    def broken():
        raise RuntimeError("no ADC")
    client = make_client(None)
    monkeypatch.setattr(np, "cloud_run_get_json", None)
    monkeypatch.setattr(np, "_get_json", broken)
    card = client.get("/api/settings/network-posture").json()
    assert {r["verdict"] for r in card["components"]} == {"NOT_CHECKED"}


def test_non_admin_is_refused(make_client):
    r = make_client(FakeRunApi(_world()), role="VIEWER").get("/api/settings/network-posture")
    assert r.status_code == 403


def test_the_card_is_read_only():
    routes = [(sorted(r.methods), r.path) for r in np.router.routes]
    assert routes == [(["GET"], "/api/settings/network-posture")]


def test_host_network_name_matches_the_gateway_qa_check():
    sys.path.insert(0, os.path.join(BASE_DIR, "apps", "orchestrator-gateway"))
    try:
        import qa_job_client as qjc
    finally:
        sys.path.remove(os.path.join(BASE_DIR, "apps", "orchestrator-gateway"))
    assert np.HOST_NETWORK == qjc.HOST_PLATFORM_NETWORK == "stackvend-host"


def test_dashboard_has_the_card_in_the_install_status_style():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert 'data-settings-card="network-posture"' in html
    assert "fetch('/api/settings/network-posture')" in html
    assert "await this.fetchNetworkPosture();" in html
    card = html[html.index('data-settings-card="network-posture"'):]
    card = card[:card.index("<!-- 4 Category Grid -->")]
    assert 'class="sv-ri-table' in card   # the runner identity card's table style
    assert "<button" not in card and "@click" not in card   # read-only

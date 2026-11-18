"""COMPLIANCE-BASELINE-LABEL (owner 10-27): honest compliance labels in the Control Center.

* The create form's dropdown is "Security controls baseline" with a warning that FedRAMP / HIPAA / CJIS compliance
  requires an Assured Workloads folder of that regime.
* Records and dashboards show "Compliance: <regime> (Assured Workloads)" only when the recorded `profile_source` is
  ASSURED_WORKLOADS_FOLDER, otherwise "Controls: <regime> baseline (not a compliance environment)"; STANDARD is
  "Standard". Old records without a source get the "Controls" form.
* Display only: profile resolution (tests/test_compliance_profile_explicit.py) is unchanged.

Hermetic: pure functions, the template file, and the CC routes on an in-memory Firestore fake.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import os
import re
import sys
from html.parser import HTMLParser
from unittest.mock import MagicMock, patch

import pytest

from fd4f_support import FakeDB

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
DASHBOARD = os.path.join(CC_DIR, "templates", "dashboard.html")
COMPLIANCE_DIR = os.path.join(REPO_ROOT, "mcp-servers", "compliance")

WARNING = ("FedRAMP, HIPAA and CJIS compliance require an Assured Workloads folder of that regime. Choosing a "
           "baseline here in an ordinary folder applies that baseline's technical controls (customer-managed "
           "encryption keys, audit logging, allowed regions) but does not make the workload compliant.")


@pytest.fixture
def cl(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    import compliance_label
    return compliance_label


def _decision(profile, source, requested=None):
    return {"profile": profile, "profile_source": source, "requested_profile": requested}


# ------------------------------------------------------------------ label per profile_source
@pytest.mark.parametrize("workload, label, kind", [
    # FOLDER -> Compliance (the profile is the folder's Assured Workloads regime)
    ({"compliance_decision": _decision("HIPAA", "ASSURED_WORKLOADS_FOLDER")},
     "Compliance: HIPAA (Assured Workloads)", "COMPLIANCE_ENVIRONMENT"),
    ({"requested_compliance_profile": "HIPAA",
      "compliance_decision": _decision("FEDRAMP_HIGH", "ASSURED_WORKLOADS_FOLDER", "HIPAA")},  # folder was stricter
     "Compliance: FedRAMP High (Assured Workloads)", "COMPLIANCE_ENVIRONMENT"),
    # EXPLICIT in an ordinary folder -> Controls baseline
    ({"requested_compliance_profile": "HIPAA", "compliance_decision": _decision("HIPAA", "EXPLICIT_REQUEST", "HIPAA")},
     "Controls: HIPAA baseline (not a compliance environment)", "CONTROLS_BASELINE"),
    ({"requested_compliance_profile": "FEDRAMP_MODERATE",
      "compliance_decision": _decision("FEDRAMP_MODERATE", "WORKLOAD_SELECTION", "FEDRAMP_MODERATE")},
     "Controls: FedRAMP Moderate baseline (not a compliance environment)", "CONTROLS_BASELINE"),
    # request stricter than the folder's regime: not the folder's regime -> Controls (row text)
    ({"requested_compliance_profile": "FEDRAMP_HIGH",
      "compliance_decision": _decision("FEDRAMP_HIGH", "EXPLICIT_REQUEST", "FEDRAMP_HIGH")},
     "Controls: FedRAMP High baseline (not a compliance environment)", "CONTROLS_BASELINE"),
    # DEFAULT -> Standard
    ({"compliance_decision": _decision("STANDARD", "DEFAULT_STANDARD")}, "Standard", "STANDARD"),
    ({}, "Standard", "STANDARD"),
    ({"requested_compliance_profile": "STANDARD",
      "compliance_decision": _decision("STANDARD", "EXPLICIT_REQUEST", "STANDARD")}, "Standard", "STANDARD"),
    # old records without a source -> Controls baseline
    ({"requested_compliance_profile": "PCI_DSS"},
     "Controls: PCI DSS baseline (not a compliance environment)", "CONTROLS_BASELINE"),
    ({"compliance_profile": "CJIS"}, "Controls: CJIS baseline (not a compliance environment)", "CONTROLS_BASELINE"),
    ({"requested_compliance_profile": "HIPAA", "compliance_decision": {"profile": "HIPAA"}},
     "Controls: HIPAA baseline (not a compliance environment)", "CONTROLS_BASELINE"),
    ({"compliance_profile": "EU_REGIONS_AND_SUPPORT", "compliance_decision": {"profile": "EU_REGIONS_AND_SUPPORT"}},
     "Standard", "STANDARD"),  # legacy decision, no selection: the apply-time gate enforces STANDARD (load_decision)
    # a decision made for another selection (stale): the selection, never the old folder claim
    ({"requested_compliance_profile": "FEDRAMP_HIGH",
      "compliance_decision": _decision("HIPAA", "ASSURED_WORKLOADS_FOLDER", None)},
     "Controls: FedRAMP High baseline (not a compliance environment)", "CONTROLS_BASELINE"),
])
def test_label_per_profile_source(cl, workload, label, kind):
    assert cl.compliance_label(workload) == {"compliance_label": label, "compliance_label_kind": kind}


def test_only_the_folder_source_is_ever_called_compliance(cl):
    sources = ["EXPLICIT_REQUEST", "WORKLOAD_SELECTION", "DEFAULT_STANDARD", None, "", "assured_workloads_folder",
               "ASSURED_WORKLOADS_FOLDER "]
    for profile in cl.PROFILE_DISPLAY_NAMES:
        for source in sources:
            out = cl.compliance_label({"compliance_decision": _decision(profile, source)})
            assert not out["compliance_label"].startswith("Compliance:"), (profile, source)
            assert "Assured Workloads" not in out["compliance_label"]


def test_effective_profile_follows_the_apply_gate_precedence(cl, monkeypatch):
    """Same profile as mcp-servers/terraform/compliance_gate.py::load_decision for every record shape."""
    tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
    if tf_dir not in sys.path:
        monkeypatch.syspath_prepend(tf_dir)
    import compliance_gate

    cases = [
        {}, {"compliance_profile": "CJIS"}, {"requested_compliance_profile": "HIPAA"},
        {"requested_compliance_profile": "HIPAA", "compliance_decision": {"profile": "PCI_DSS"}},
        {"compliance_decision": {"profile": "PCI_DSS"}},
        {"requested_compliance_profile": "HIPAA", "compliance_decision": _decision("HIPAA", "EXPLICIT_REQUEST", "HIPAA")},
        {"compliance_decision": _decision("HIPAA", "ASSURED_WORKLOADS_FOLDER")},
        {"compliance_decision": _decision("STANDARD", "DEFAULT_STANDARD")},
    ]
    for data in cases:
        db = FakeDB()
        db.docs["workloads/app"] = dict(data)
        decision, _ = compliance_gate.load_decision(db, "app")
        assert cl.effective_profile(data)[0] == decision["profile"], data


# ------------------------------------------------------------------ create form
class _Select(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_select = False
        self.options = []
        self._opt = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "select" and a.get("x-model") == "newWorkloadForm.compliance_profile":
            self.in_select = True
        elif tag == "option" and self.in_select:
            self._opt = [a.get("value"), ""]

    def handle_data(self, data):
        if self._opt is not None:
            self._opt[1] += data

    def handle_endtag(self, tag):
        if tag == "option" and self._opt is not None:
            self.options.append((self._opt[0], self._opt[1].strip()))
            self._opt = None
        elif tag == "select":
            self.in_select = False


def _html():
    with open(DASHBOARD, encoding="utf-8") as f:
        return f.read()


def test_create_form_label_and_warning():
    html = _html()
    assert html.count('x-model="newWorkloadForm.compliance_profile"') == 1  # the only create surface offering it
    i = html.index('x-model="newWorkloadForm.compliance_profile"')
    block = html[html.rindex("<div>", 0, i):html.index("</div>", i)]
    assert ">Security controls baseline</label>" in block
    assert ">Compliance Profile</label>" not in html
    assert WARNING in " ".join(block.split())
    assert 'data-testid="compliance-baseline-warning"' in block


def test_form_option_names_match_the_display_names(cl):
    p = _Select()
    p.feed(_html())
    names = dict(p.options)
    assert names.pop("") == "Standard (default)"
    assert names == {k: v for k, v in cl.PROFILE_DISPLAY_NAMES.items() if k != "STANDARD"}


def test_dashboard_shows_the_label_on_details_and_catalog():
    html = _html()
    assert 'data-testid="workload-compliance-label"' in html and 'x-text="workloadDetails.compliance_label"' in html
    assert 'data-testid="catalog-compliance-label"' in html and 'x-text="w.compliance_label"' in html
    # no template builds its own "Compliance:" claim from raw fields
    assert not re.search(r"'Compliance: '", html)


# ------------------------------------------------------------------ routes carry the label
def _routes(monkeypatch, store):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl_routes

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(wl_routes, "db", store)
    return wl_routes


def _admin():
    request = MagicMock()
    request.state.user_email = "admin@example.com"
    request.state.user_role = "ADMIN"
    request.state.assigned_workloads = []
    return request


def test_list_and_details_routes_carry_the_label(monkeypatch):
    store = FakeDB()
    store.docs["workloads/aw-app"] = {"product_id": "aw-app", "project_id": "aw-app", "status": "ACTIVE",
                                      "compliance_decision": _decision("HIPAA", "ASSURED_WORKLOADS_FOLDER")}
    store.docs["workloads/plain-app"] = {"product_id": "plain-app", "project_id": "plain-app", "status": "ACTIVE",
                                         "requested_compliance_profile": "HIPAA",
                                         "compliance_decision": _decision("HIPAA", "EXPLICIT_REQUEST", "HIPAA")}
    store.docs["workloads/std-app"] = {"product_id": "std-app", "project_id": "std-app", "status": "ACTIVE"}
    wl = _routes(monkeypatch, store)
    from authz import UserRole

    request = _admin()
    request.state.user_role = UserRole.ADMIN
    listed = {w.product_id: (w.compliance_label, w.compliance_label_kind) for w in wl.list_workloads(request)}
    assert listed == {
        "aw-app": ("Compliance: HIPAA (Assured Workloads)", "COMPLIANCE_ENVIRONMENT"),
        "plain-app": ("Controls: HIPAA baseline (not a compliance environment)", "CONTROLS_BASELINE"),
        "std-app": ("Standard", "STANDARD"),
    }
    with patch.object(wl, "verify_workload_access", lambda *a, **k: None), \
         patch.object(wl, "fetch_workload_state_from_gcs", return_value=None):
        for pid, (label, kind) in listed.items():
            details = wl.get_workload_details(pid, _admin())
            assert (details.compliance_label, details.compliance_label_kind) == (label, kind)


# ------------------------------------------------------------------ resolution unchanged
def test_resolution_is_unchanged_by_the_label(monkeypatch):
    """The compliance server's decision table (rows CP-8 / CP-10) is exactly as before: the label is display only."""
    if COMPLIANCE_DIR not in sys.path:
        monkeypatch.syspath_prepend(COMPLIANCE_DIR)
    import importlib.util
    spec = importlib.util.spec_from_file_location("cbl_compliance_service", os.path.join(COMPLIANCE_DIR, "service.py"))
    svc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(svc)
    resolve = svc.ComplianceService(project_id="mock-stackvend-project").resolve_profile
    plain = {"is_assured_workload": False}
    aw = lambda regime: {"is_assured_workload": True, "compliance_regime": regime}  # noqa: E731
    assert resolve(None, plain)["profile_source"] == "DEFAULT_STANDARD"
    assert resolve("HIPAA", plain)["profile_source"] == "EXPLICIT_REQUEST"
    assert resolve(None, aw("HIPAA"))["profile_source"] == "ASSURED_WORKLOADS_FOLDER"
    assert resolve("HIPAA", aw("HIPAA"))["profile_source"] == "ASSURED_WORKLOADS_FOLDER"
    assert (resolve("FEDRAMP_HIGH", aw("HIPAA"))["profile"], resolve("FEDRAMP_HIGH", aw("HIPAA"))["profile_source"]) \
        == ("FEDRAMP_HIGH", "EXPLICIT_REQUEST")
    # ASSURED_WORKLOADS_FOLDER is answered only when the profile IS the folder's regime (what the label relies on)
    for regime in svc.FOLDER_REGIME_PROFILES:
        for requested in [None, "STANDARD", "PCI_DSS", "HIPAA", "FEDRAMP_MODERATE", "CJIS", "FEDRAMP_HIGH",
                          "EU_REGIONS_AND_SUPPORT"]:
            try:
                d = resolve(requested, aw(regime))
            except svc.ProfileRefused:
                continue  # incomparable pair: refused (CP-8), nothing to label
            assert (d["profile_source"] == "ASSURED_WORKLOADS_FOLDER") == (d["profile"] == regime == d["folder_regime"])

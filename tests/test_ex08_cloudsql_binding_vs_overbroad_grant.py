"""ex08 integration (owner 11-14): CLOUDSQL-PASSWORD-BINDING x OVERBROAD-SECRET-GRANT. Hermetic.

CLOUDSQL-PASSWORD-BINDING renders `grant_workload_secret_access = true` on the realizing database-cloudsql module (and
binds the password secret id on its consumers); OVERBROAD-SECRET-GRANT blocks project-wide Secret Manager grants in
developer-owned IaC. Together: the module's own grant is on the one secret (google_secret_manager_secret_iam_member,
platform-rendered) and is never refused by either gate (typed IAC.PROJECT_WIDE_GRANT, render-check gate gap, classic
POLICY.PROJECT_WIDE_GRANT), the ex08-1114 shape passes generate mode end to end, and an AI-written project-wide
accessor next to the binding is still refused (the binding never masks it). Pure, no network."""
import hermetic_guard  # noqa: F401  (first import)
import json
import os
import sys

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_cloudsql_password_binding import BARE_MODULE, EX08_DB, KEY, SECRET_REF, _render  # noqa: E402
from test_overbroad_secret_grant import ACCESSOR, _gaps, _policy, project_grant  # noqa: E402
from test_typed_iac_ti3_contract import APP, REPO_ROOT, W, C, intent, topo, vt_of  # noqa: E402
from test_typed_iac_ti5c_network_facts import _assemble_net, _generate_net, _module_body  # noqa: E402
from test_ti5_r2_typed_topology_psa import PSA_FACTS  # noqa: E402
from developer_agent import platform_facts as PF  # noqa: E402
from shared import iac_intent as ii  # noqa: E402

BLOCKING = {ii.PROJECT_WIDE_GRANT_CODE, "POLICY.PROJECT_WIDE_GRANT", "PLATFORM.INTENT_GATE_GAP"}


def test_platform_forced_module_grant_passes_the_gate_and_the_render_check():
    _, files, doc = _render(vt_of(topo([EX08_DB])), [BARE_MODULE])   # _render asserts no gate diagnostics
    assert doc["module"]["postgres"]["grant_workload_secret_access"] is True
    assert "google_project_iam_member" not in (doc.get("resource") or {})
    assert _gaps(files[C.RENDER_PATH]) == []


def test_the_golden_module_grant_is_secret_scoped_and_classic_v2a_does_not_refuse_it():
    with open(os.path.join(REPO_ROOT, "infra", "modules", "database-cloudsql", "main.tf"), encoding="utf-8") as fh:
        text = fh.read()
    assert 'resource "google_secret_manager_secret_iam_member" "workload_accessor"' in text
    import hcl2
    project_roles = {body.get("role") for blk in hcl2.loads(text).get("resource", [])
                     for rtype, by_name in blk.items() if rtype in ii.PROJECT_WIDE_GRANT_TYPES
                     for body in by_name.values()}
    assert project_roles and not project_roles & ii.PROJECT_WIDE_DENIED_ROLES   # e.g. roles/cloudsql.client only
    # even read as if AI-written (it is vendored and never is), the module's grant gets no project-wide finding
    assert not {d.code for d in _policy(text)} & BLOCKING


def test_ex08_shape_generate_mode_passes_with_both_fixes():
    agent, files = _generate_net(dict(APP, **{C.INTENT_PATH: intent([BARE_MODULE])}), topo([EX08_DB]),
                                 PF.MemoryFactsProvider())
    report = agent.last_validation_report
    assert report.status == "PASS", report
    assert not {d.code for d in list(report.diagnostics) + list(report.report_only)} & BLOCKING
    env = str(_module_body(files[W + "main.tf"], "compute")["env_vars"])
    assert KEY in env and SECRET_REF in env
    assert json.loads(files[C.RENDER_PATH])["module"]["postgres"]["grant_workload_secret_access"] is True


def test_an_ai_written_project_wide_accessor_beside_the_binding_is_still_refused():
    vt = vt_of(topo([EX08_DB]))
    asm, _, _ = _assemble_net(vt, {C.INTENT_PATH: intent([BARE_MODULE], resources=[project_grant(ACCESSOR)])},
                              PSA_FACTS)
    assert [d.code for d in asm.diagnostics] == [ii.PROJECT_WIDE_GRANT_CODE]

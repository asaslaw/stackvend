"""GCE-WORKER-MAX-RUN-DURATION: a Spot gce-worker VM has a bounded lifetime.

Before: the compute-gce-worker instance template had no `scheduling.max_run_duration`, so a Spot batch VM whose startup
script never powered it off (example 03: an application bug) ran and billed forever. Now the template carries
`max_run_duration { seconds = var.max_run_duration_seconds }` (default 86400 = 24 h) for Spot workers; the existing
`instance_termination_action = "DELETE"` makes Compute Engine delete the VM when the time is up. VMs that
`instances.insert` creates with `sourceInstanceTemplate` inherit the template's scheduling.
Do No Harm: a standard worker (`spot = false`) renders exactly as before (no max_run_duration, no termination action);
`max_run_duration_seconds = null` turns the bound off; the platform-rendered module block is unchanged (the module
default applies) and no prompt / topology schema text changes. Hermetic (python-hcl2 reads the module; no tofu)."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: put eval/.deps on PYTHONPATH; this file must not skip", pytrace=False)

from developer_agent.topology_wiring import render_gce_worker_block  # noqa: E402
from shared import service_topology as st  # noqa: E402

MODULE_DIRS = ("infra/modules/compute-gce-worker", "apps/control-center/infra/modules/compute-gce-worker")
DEFAULT_SECONDS = 86400
MIN_SECONDS, MAX_SECONDS = 30, 10368000   # Compute Engine's run-duration range: 30 s to 120 days


def _hcl(rel):
    with open(os.path.join(REPO_ROOT, rel)) as f:
        return hcl2.loads(f.read())


def _variable(module_dir, name):
    return next(v[name] for v in _hcl(f"{module_dir}/variables.tf")["variable"] if name in v)


def _scheduling(module_dir):
    main = _hcl(f"{module_dir}/main.tf")
    tmpl = next(r["google_compute_instance_template"]["worker"] for r in main["resource"]
                if "google_compute_instance_template" in r)
    (sched,) = tmpl["scheduling"]
    return sched


@pytest.mark.parametrize("module_dir", MODULE_DIRS)
def test_variable_has_a_documented_24h_default_null_opt_out_and_the_gce_range(module_dir):
    var = _variable(module_dir, "max_run_duration_seconds")
    assert var["type"] == "number"
    assert var["default"] == DEFAULT_SECONDS and var["nullable"] is True
    assert "86400" in var["description"] and "null" in var["description"] and "Spot" in var["description"]
    (rule,) = var["validation"]
    cond = rule["condition"]
    assert "var.max_run_duration_seconds == null" in cond
    assert f">= {MIN_SECONDS}" in cond and f"<= {MAX_SECONDS}" in cond
    assert "floor(var.max_run_duration_seconds) == var.max_run_duration_seconds" in cond


@pytest.mark.parametrize("module_dir", MODULE_DIRS)
def test_spot_template_gets_max_run_duration_and_delete(module_dir):
    sched = _scheduling(module_dir)
    (dyn,) = sched["dynamic"]
    block = dyn["max_run_duration"]
    # Gated on Spot AND a non-null value: one block for a Spot worker, none otherwise.
    assert block["for_each"] == ("${var.spot && var.max_run_duration_seconds != null ? "
                                 "['${var.max_run_duration_seconds}'] : []}")
    assert block["content"] == [{"seconds": "${max_run_duration.value}"}]
    assert sched["instance_termination_action"] == '${var.spot ? "DELETE" : null}'


@pytest.mark.parametrize("module_dir", MODULE_DIRS)
def test_standard_worker_scheduling_is_unchanged(module_dir):
    """Negative: every scheduling setting a standard (spot = false) worker had stays as it was; the only new block is
    the Spot-gated dynamic one, so a standard worker renders no max_run_duration and no termination action."""
    sched = _scheduling(module_dir)
    assert {k: v for k, v in sched.items() if k != "dynamic"} == {
        "provisioning_model": '${var.spot ? "SPOT" : "STANDARD"}',
        "preemptible": "${var.spot}",
        "automatic_restart": False,
        "on_host_maintenance": "TERMINATE",
        "instance_termination_action": '${var.spot ? "DELETE" : null}',
    }
    assert [list(d) for d in sched["dynamic"]] == [["max_run_duration"]]
    assert sched["dynamic"][0]["max_run_duration"]["for_each"].startswith("${var.spot && ")


def test_spot_stays_the_default_so_default_workers_are_bounded():
    for module_dir in MODULE_DIRS:
        assert _variable(module_dir, "spot")["default"] is True


def test_module_copies_and_payloads_carry_the_change():
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    for f in ("main.tf", "variables.tf"):
        with open(os.path.join(REPO_ROOT, MODULE_DIRS[0], f)) as h:
            disk = h.read()
        assert "max_run_duration" in disk
        assert BUILTIN_MODULE_FILES["compute-gce-worker"][f] == disk
        with open(os.path.join(REPO_ROOT, MODULE_DIRS[1], f)) as h:
            assert h.read() == disk


# Example 03 shape (spot) and a standard worker: the platform block never sets the new input, so the module default
# (Spot: 24 h; standard: no bound) decides; the rendered block is byte-identical to before this change.
def _vt(spot):
    raw = {"services": [{"name": "dispatcher", "kind": "cloudrun"},
                        {"name": "batch-worker", "kind": "gce-worker",
                         "vm": {"machine_type": "e2-micro", "spot": spot}}],
           "primary_service": "dispatcher",
           "edges": [{"caller": "dispatcher", "callee": "batch-worker", "protocol": "launch"}],
           "resources": []}
    vt, diags = st.validate_service_topology(raw, product_id="batch")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


@pytest.mark.parametrize("spot", [True, False])
def test_platform_rendered_block_does_not_set_the_bound(spot):
    block = render_gce_worker_block(_vt(spot), "batch-worker", {})
    assert "max_run_duration" not in block
    body = hcl2.loads(block)["module"][0]["compute_batch_worker"]
    assert body["spot"] is spot

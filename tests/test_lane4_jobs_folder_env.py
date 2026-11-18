import hermetic_guard  # noqa: F401  (lane 2 standing rule: first import)

from pathlib import Path

MAIN_TF = Path(__file__).resolve().parents[1] / "infra" / "platform" / "main.tf"


def _resource_text(tf: str, header: str) -> str:
    start = tf.index(header)
    nxt = tf.find('\nresource "', start + len(header))
    return tf[start:nxt if nxt != -1 else len(tf)]


def test_cloud_run_jobs_get_managed_workloads_folder_id():
    """FD-4O: finops-budget-enforcer-job's target guard refuses every quarantine without this env."""
    jobs = _resource_text(MAIN_TF.read_text(), 'resource "google_cloud_run_v2_job" "jobs"')
    assert 'name  = "MANAGED_WORKLOADS_FOLDER_ID"' in jobs
    assert "value = var.castor_managed_workloads_folder_id" in jobs

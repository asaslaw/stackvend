"""RT14-F1 (docs/planning/rt14-iac-render-golden-rt.md): the exact two additions a gce-bastion root render gained (the
root google_compute_zones read and the module's `zone` input). Older byte-identity pins remove exactly this first,
so a further change to the render still fails them. tests/test_rt14_golden_location.py pins the additions."""

ROOT_ZONES_BLOCK = """
# RT14-F1: read at plan time (no depends_on), so the bastion VM's zone is a known value in every plan.
data "google_compute_zones" "stackvend_bastion_zones" {
  project = var.project_id
  region  = var.region
}
"""
ZONE_INPUT_LINE = "  zone       = element(sort(data.google_compute_zones.stackvend_bastion_zones.names), 0)\n"


def without_rt14_bastion_zone(render: str) -> str:
    """A generator render without the bastion zone additions (both present once, or neither: other renders pass)."""
    if ROOT_ZONES_BLOCK not in render and ZONE_INPUT_LINE not in render:
        return render
    assert render.count(ROOT_ZONES_BLOCK) == 1 and render.count(ZONE_INPUT_LINE) == 1
    return render.replace(ROOT_ZONES_BLOCK, "").replace(ZONE_INPUT_LINE, "")

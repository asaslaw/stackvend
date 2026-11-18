"""SELFUP-STATE (owner row, 10-27): the Terraform state bucket's bucket-wide writers write only workload state.

The state bucket (`castor-tfstate-<project_id>`) holds the platform's own state (`platform/state/default.tfstate`,
backend prefix in infra/platform/providers.tf) next to every workload's state (backend prefix
`workloads/<product_id>`). DevOps, developer, provisioner and the Control Center hold `roles/storage.objectAdmin` on
the bucket; each grant now carries one IAM condition:

    resource.type == "storage.googleapis.com/Bucket"
      || resource.name.startsWith("projects/_/buckets/<bucket>/objects/workloads/")

GCS evaluates object operations (get / create / overwrite / delete / copy destination) on
`projects/_/buckets/<bucket>/objects/<object>` and bucket-level checks (storage.objects.list) on the bucket, so
workload deploys (state + `<prefix>/default.tflock`), vending's archive and the rollback service keep working and
nothing under `platform/` can be written. Reads stay unconditional (agent_state_viewers + the new cc_state_viewer).

Static (python-hcl2) + path contract: every producer of a state-bucket object path writes under `workloads/`, the
platform backend does not. The rendered expression is pinned by the mocked `tofu test` contract
(tests/fixtures/lane18_s0/lane18_s0.tftest.hcl, run by tests/test_lane18_s0_platform_iam.py).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os

import hcl2
import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
BUCKET_REF = "${data.google_storage_bucket.workload_tfstate_bucket.name}"
PREFIX_TEMPLATE = "projects/_/buckets/" + BUCKET_REF + "/objects/workloads/"
CONDITION_TEMPLATE = ('resource.type == "storage.googleapis.com/Bucket" || '
                      'resource.name.startsWith("${local.state_bucket_workload_objects_prefix}")')
WRITER_ROLES = {"roles/storage.objectAdmin", "roles/storage.objectCreator", "roles/storage.objectUser",
                "roles/storage.admin", "roles/storage.legacyBucketWriter", "roles/storage.legacyBucketOwner",
                "roles/storage.legacyObjectOwner"}


def _load(name):
    with open(os.path.join(PLATFORM, name), encoding="utf-8") as fh:
        return hcl2.load(fh)


# The only platform files that reference the state bucket (test_only_these_files_reference_the_state_bucket).
STATE_BUCKET_FILES = ("main.tf", "destructive_guard.tf")


def _platform_docs():
    return {n: _load(n) for n in STATE_BUCKET_FILES}


def test_only_these_files_reference_the_state_bucket():
    # outputs.tf names the bucket in an output; every IAM grant on it lives in STATE_BUCKET_FILES.
    refs = []
    for n in sorted(os.listdir(PLATFORM)):
        if n.endswith(".tf"):
            with open(os.path.join(PLATFORM, n), encoding="utf-8") as fh:
                if "data.google_storage_bucket.workload_tfstate_bucket" in fh.read():
                    refs.append(n)
    # stage_runner.tf (STAGE-JOB-RUNNER): the TFSTATE_BUCKET env value the services and the stage-runner job share; no IAM
    assert refs == ["destructive_guard.tf", "main.tf", "outputs.tf", "stage_runner.tf"]
    runner = open(os.path.join(PLATFORM, "stage_runner.tf"), encoding="utf-8").read()
    assert runner.count("data.google_storage_bucket.workload_tfstate_bucket") == 1 and "_iam_" not in runner.split(
        "data.google_storage_bucket.workload_tfstate_bucket")[0].rsplit("\n", 1)[-1]


def _locals():
    out = {}
    for doc in _platform_docs().values():
        for block in doc.get("locals", []):
            out.update(block)
    return out


def _state_bucket_members():
    """Every google_storage_bucket_iam_member / _binding / _policy on the state bucket: (file, name, body)."""
    found = []
    for fname, doc in _platform_docs().items():
        for res in doc.get("resource", []):
            for rtype in ("google_storage_bucket_iam_member", "google_storage_bucket_iam_binding",
                          "google_storage_bucket_iam_policy"):
                for name, body in (res.get(rtype) or {}).items():
                    if body.get("bucket") == BUCKET_REF:
                        found.append((fname, rtype, name, body))
    return found


def _condition(body):
    cond = body.get("condition") or []
    return cond[0] if cond else None


# ================================================================================ the grants
def test_condition_locals_are_exact():
    loc = _locals()
    assert loc["state_bucket_workload_objects_prefix"] == PREFIX_TEMPLATE
    assert loc["state_bucket_workload_write_condition"] == CONDITION_TEMPLATE


def test_the_four_writers_carry_the_workload_only_condition():
    members = {name: (fname, rtype, body) for fname, rtype, name, body in _state_bucket_members()}
    admins = members["state_bucket_admins"]
    assert admins[0] == "main.tf" and admins[1] == "google_storage_bucket_iam_member"
    # (python-hcl2 drops the quotes inside a function call; the mocked tofu test pins the exact keys)
    assert admins[2]["for_each"] == "${toset([sa-castor-gcp-devops, sa-castor-developer, sa-project-provisioner])}"
    cc = members["cc_state_admin"]
    assert cc[0] == "destructive_guard.tf"
    for body in (admins[2], cc[2]):
        assert body["role"] == "roles/storage.objectAdmin"
        cond = _condition(body)
        assert cond is not None
        assert cond["expression"] == "${local.state_bucket_workload_write_condition}"
        assert cond["title"] == "stackvend-workload-state-only"


def test_no_unconditioned_writer_on_the_state_bucket():
    # Only additive members (never a binding / policy that would drop the operator's or the readers' access), and every
    # role that can write objects is conditioned.
    writers = []
    for fname, rtype, name, body in _state_bucket_members():
        assert rtype == "google_storage_bucket_iam_member", (fname, rtype, name)
        if body["role"] in WRITER_ROLES:
            writers.append(name)
            cond = _condition(body)
            assert cond is not None and cond["expression"] == "${local.state_bucket_workload_write_condition}", name
    assert sorted(writers) == ["cc_state_admin", "state_bucket_admins"]


def test_reads_stay_unconditional_and_the_cc_keeps_platform_read():
    members = {name: body for _f, _t, name, body in _state_bucket_members()}
    cc_view = members["cc_state_viewer"]
    assert cc_view["role"] == "roles/storage.objectViewer" and _condition(cc_view) is None
    assert cc_view["member"] == "serviceAccount:${local.cc_sa_email}"
    agents = members["agent_state_viewers"]
    assert agents["role"] == "roles/storage.objectViewer" and _condition(agents) is None
    assert agents["for_each"] == "${local.agent_roles}"
    loc_agents = _locals()["agent_roles"]
    for sa in ("sa-castor-gcp-devops", "sa-castor-developer", "sa-project-provisioner"):
        assert sa in loc_agents   # the three writers still read platform/ through agent_state_viewers


def test_cc_service_waits_for_its_state_read_grant():
    with open(os.path.join(PLATFORM, "main.tf"), encoding="utf-8") as fh:
        text = fh.read()
    start = text.index('resource "google_cloud_run_v2_service" "services"')
    deps = text[text.index("depends_on = [", start):text.index("]", text.index("depends_on = [", start))]
    assert "google_storage_bucket_iam_member.cc_state_viewer" in deps
    assert "google_storage_bucket_iam_member.cc_state_admin" in deps


# ================================================================================ the paths the condition must allow
def _allowed(object_name, bucket="castor-tfstate-p1"):
    """The pinned condition, applied to one object: resource.type is an Object, so only startsWith decides."""
    prefix = PREFIX_TEMPLATE.replace(BUCKET_REF, bucket)
    return f"projects/_/buckets/{bucket}/objects/{object_name}".startswith(prefix)


def _platform_backend_prefix():
    tf = _load("providers.tf")["terraform"][0]
    return tf["backend"][0]["gcs"]["prefix"]


def test_platform_state_and_lock_are_outside_the_writable_prefix():
    prefix = _platform_backend_prefix()
    assert prefix == "platform/state"
    for obj in (f"{prefix}/default.tfstate", f"{prefix}/default.tflock", "platform/x", "default.tfstate",
                "terraform.tfstate", "sources/app/run-1/source.tar.gz", "workloads", "workloadsX/app/default.tfstate"):
        assert not _allowed(obj), obj


@pytest.mark.parametrize("obj", [
    "workloads/app/default.tfstate",                                   # OpenTofu GCS backend state, workspace default
    "workloads/app/default.tflock",                                    # its lock (<prefix>/<workspace>.tflock)
    "workloads/app/state_history/decommission_1700000000.tfstate",     # vending's decommission archive
])
def test_workload_paths_are_writable(obj):
    assert _allowed(obj)


def test_negative_another_bucket_name_never_matches():
    prefix = PREFIX_TEMPLATE.replace(BUCKET_REF, "castor-tfstate-p1")
    assert not "projects/_/buckets/castor-tfstate-p10/objects/workloads/app/default.tfstate".startswith(prefix)


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
        return fh.read()


def test_every_workload_state_producer_uses_the_workloads_prefix():
    # The terraform server's backend (both renders), the Express synthesizer's backend, the rollback service's state
    # and lock objects and vending's archive all live under workloads/<product_id>/ .
    service = _read("mcp-servers/terraform/service.py")
    assert service.count('prefix = "workloads/{product_id}"') == 2
    assert service.count('backend "gcs" {{') == 2   # no third backend render with another prefix
    assert 'prefix = "workloads/{product_id}"' in _read("shared/express_synthesizer.py")
    rollback = _read("apps/infra-rollback/rollback.py")
    assert 'return f"workloads/{product_id}/default.tfstate"' in rollback
    assert 'return f"workloads/{product_id}/default.tflock"' in rollback
    vending = _read("apps/project-vending/vending.py")
    assert 'bucket.blob(f"workloads/{pid}/default.tfstate")' in vending
    assert 'archive_path = f"workloads/{pid}/state_history/decommission_{int(time.time())}.tfstate"' in vending

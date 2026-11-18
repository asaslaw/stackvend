"""FD-4AT: the workload CI deployer (sa-gh-deployer) gets least-privilege roles; WIF accepts only main of the repo.

Pins, with real HCL parsing (python-hcl2), on infra/modules/workload-foundation/base:
- no roles/editor, run.admin, artifactregistry.admin, storage.admin (or any other admin/owner role) for the deployer;
- the deployer's role set is exactly the inventoried one (docs/handoff/fd-4at-report.md);
- iam.serviceAccountUser for the deployer only on the runtime SA and the Cloud Build (Compute default) SA
  (google_service_account_iam_member), never project-wide;
- the WIF condition is exactly `assertion.repository == '<repo>'[ && assertion.repository_id == '<id>'] &&
  assertion.ref == 'refs/heads/<branch>' && assertion.event_name in ['push','workflow_dispatch']`, and repository_id /
  ref are mapped; the repository-id clause (FD-4AT-c) is present only when the platform supplies the id; <branch> is
  github_default_branch (FD-4CI-b-R1-WIF, default "main" = the FD-4AT ref byte for byte);
- Do No Harm: the WIF binding member is byte-identical to the pre-FD-4AT string (no destroy/create of
  `github_wif_binding` for existing tenants), the runtime SA grants are untouched, nothing else changed vs the
  pre-FD-4AT files (real-parser diff); the only module inputs added since are FD-4AT-c's optional
  github_repository_id (default empty = the FD-4AT condition, byte for byte) and FD-4CI-b-R1-WIF's
  github_default_branch (default "main" = the FD-4AT ref, byte for byte);
- disk == Control Center copy == all 4 payload entries for this module.
The semantic plan contract (condition / member values, actAs on the runtime SA) runs through `tofu test` with mock
providers when OpenTofu + STACKVEND_TOFU_PROVIDER_MIRROR are available (nothing downloaded).
"""
import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)
import os
import shutil
import subprocess
import tempfile

import pytest

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
MOD_ID = "workload-foundation/base"
DISK = os.path.join(REPO, "infra", "modules", "workload-foundation", "base")
CC = os.path.join(REPO, "apps", "control-center", "infra", "modules", "workload-foundation", "base")
PAYLOADS = [
    "shared/builtin_modules_payload.py",
    "apps/control-center/shared/builtin_modules_payload.py",
    "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
    "mcp-servers/terraform/shared/builtin_modules_payload.py",
]
FIXTURES = os.path.join(HERE, "fixtures", "fd4at")
TFTEST = os.path.join(FIXTURES, "fd4at.tftest.hcl")
TOFU = shutil.which("tofu")
MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")

DEPLOYER = "serviceAccount:${google_service_account.github_deployer.email}"
# FD-4AT RT F2: minimal set. run.sourceDeveloper covers run.developer, cloudbuild.builds.editor,
# serviceusage.serviceUsageConsumer and the source repository/bucket; CI never pushes images (the build SA does).
EXPECTED_DEPLOYER_PROJECT_ROLES = {
    "deployer_run_source_developer": "roles/run.sourceDeveloper",
    "deployer_logging_viewer": "roles/logging.viewer",
    "deployer_container_developer": "roles/container.developer",
}
# RT R1: the project number comes from the pool's resource name (state-known), not a data source (a deferred read on a
# Day-2 change would make this ForceNew id unknown and replace the grant).
BUILD_SA_ID = ('projects/${var.project_id}/serviceAccounts/'
               '${split("/", google_iam_workload_identity_pool.github_pool.name)[1]}-compute@developer.gserviceaccount.com')
# FD-4AT-c: ${local.wif_repository_id_clause} is "" without the vend-time id (pinned below and by the tofu test).
EXPECTED_WIF_CONDITION = ("assertion.repository == '${var.github_repo_full_name}'${local.wif_repository_id_clause}"
                          " && assertion.ref == 'refs/heads/${var.github_default_branch}'"
                          " && assertion.event_name in ['push','workflow_dispatch']")
EXPECTED_REPOSITORY_ID_CLAUSE = ('${var.github_repository_id == "" ? "" : '
                                 '" && assertion.repository_id == \'${var.github_repository_id}\'"}')
FORBIDDEN_ROLES = {"roles/editor", "roles/owner", "roles/run.admin", "roles/artifactregistry.admin",
                   "roles/storage.admin", "roles/iam.serviceAccountUser"}
# The pre-FD-4AT member string: existing tenants' binding must not change while github_repository_id is null.
LEGACY_MEMBER = ("principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}"
                 "/attribute.repository/${var.github_repo_full_name}")


def _module_docs(root=DISK):
    """The module's parsed files with the GHA-DEPLOY-SWITCH edits undone (tests/gha_switch_render.py: `count`,
    `[0]`, moved blocks, one input, three outputs; tests/test_gha_deploy_switch.py pins that undoing them gives the
    base files byte for byte), so the FD-4AT contract below is still checked on everything else."""
    from gha_switch_render import without_gha_switch
    docs = {}
    for name in sorted(os.listdir(root)):
        if name.endswith(".tf"):
            with open(os.path.join(root, name), encoding="utf-8") as f:
                docs[name] = hcl2.loads(without_gha_switch(name, f.read()))
    return docs


def _resources(rtype):
    out = {}
    for doc in _module_docs().values():
        for block in doc.get("resource", []):
            for t, named in block.items():
                if t == rtype:
                    out.update(named)
    return out


def _payload_entry(rel):
    ns = {}
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        exec(compile(f.read(), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
    return ns["BUILTIN_MODULE_FILES"][MOD_ID]


def _disk_files(root):
    out = {}
    for name in sorted(os.listdir(root)):
        if name.endswith(".tf"):
            with open(os.path.join(root, name), encoding="utf-8") as f:
                out[name] = f.read()
    return out


# ------------------------------------------------------------------------------------------------ roles
def test_deployer_project_roles_are_exactly_the_inventoried_set():
    deployer = {name: body["role"] for name, body in _resources("google_project_iam_member").items()
                if body.get("member") == DEPLOYER}
    assert deployer == EXPECTED_DEPLOYER_PROJECT_ROLES


def test_no_admin_or_editor_grant_to_the_deployer_anywhere():
    for rtype in ("google_project_iam_member", "google_project_iam_binding", "google_service_account_iam_member",
                  "google_storage_bucket_iam_member", "google_artifact_registry_repository_iam_member"):
        for name, body in _resources(rtype).items():
            members = [body.get("member")] + list(body.get("members") or [])
            if DEPLOYER not in members:
                continue
            role = body["role"]
            if rtype == "google_service_account_iam_member" and role == "roles/iam.serviceAccountUser":
                continue  # pinned separately: only on the runtime SA and the build SA
            assert role not in FORBIDDEN_ROLES, f"{rtype}.{name}: {role}"
            assert not role.endswith(".admin") and role != "roles/owner", f"{rtype}.{name}: {role}"


def test_service_account_user_only_on_the_runtime_and_build_sas():
    grants = {name: body for name, body in _resources("google_service_account_iam_member").items()
              if body.get("member") == DEPLOYER}
    assert grants == {
        "deployer_runtime_sa_user": {
            "service_account_id": "${google_service_account.workload_sa.name}",
            "role": "roles/iam.serviceAccountUser",
            "member": DEPLOYER,
        },
        # FD-4AT RT F1: `--source` builds run as the Compute Engine default SA (resource-scoped actAs).
        "deployer_build_sa_user": {
            "service_account_id": BUILD_SA_ID,
            "role": "roles/iam.serviceAccountUser",
            "member": DEPLOYER,
        },
    }
    # RT R1: no data source in the module (nothing deferred to apply on a Day-2 plan).
    assert not [blk for doc in _module_docs().values() for blk in doc.get("data", [])]
    removed = {"deployer_editor", "deployer_run_admin", "deployer_artifact_admin", "deployer_storage_admin",
               "deployer_sa_user", "deployer_run_developer", "deployer_build_editor", "deployer_artifact_writer",
               "deployer_service_usage_consumer"}
    assert not removed & set(_resources("google_project_iam_member"))


def test_runtime_sa_grants_unchanged():
    """Do No Harm: the runtime SA's own project roles are untouched by FD-4AT."""
    runtime = {name: body["role"] for name, body in _resources("google_project_iam_member").items()
               if body.get("member") == "serviceAccount:${google_service_account.workload_sa.email}"}
    assert runtime == {
        "workload_datastore_user": "roles/datastore.user",
        "workload_log_writer": "roles/logging.logWriter",
        "workload_pubsub_publisher": "roles/pubsub.publisher",
        "workload_storage_user": "roles/storage.objectUser",
    }


# ------------------------------------------------------------------------------------------------ WIF
def test_wif_condition_requires_main_branch_of_the_named_repo():
    provider = _resources("google_iam_workload_identity_pool_provider")["github_provider"]
    # exact equality clauses only (no startsWith / contains / regex matching of the ref or repository)
    assert provider["attribute_condition"] == EXPECTED_WIF_CONDITION
    assert provider["attribute_mapping"] == {
        "google.subject": "assertion.sub",
        "attribute.actor": "assertion.actor",
        "attribute.repository": "assertion.repository",
        "attribute.repository_owner": "assertion.repository_owner",
        "attribute.repository_id": "assertion.repository_id",
        "attribute.ref": "assertion.ref",
    }


def test_wif_binding_member_is_the_legacy_string():
    """Do No Harm: the binding member is unchanged, so `github_wif_binding` is not replaced on live tenants."""
    member = _resources("google_service_account_iam_member")["github_wif_binding"]["member"]
    assert member == LEGACY_MEMBER


def test_repository_id_input_is_optional_and_platform_only():
    """FD-4AT-c (was FD-4AT follow-up F1): the only new input is github_repository_id, default "" (unpinned = the
    FD-4AT condition), digits-only validation; the clause is exact equality; the developer prompt does not advertise
    the input (contract_inspector._PLATFORM_ONLY_INPUTS), so the prompt the eval cassettes replay is unchanged."""
    variables = {n: body for block in _module_docs()["variables.tf"]["variable"] for n, body in block.items()}
    assert set(variables) == {"project_id", "region", "product_id", "github_repo_full_name", "github_repository_id",
                              "base_apis", "additional_apis", "firestore_delete_protection",
                              "github_default_branch"}   # FD-4CI-b-R1-WIF (tests/test_r1_wif_default_branch.py)
    rid = variables["github_repository_id"]
    assert rid["default"] == "" and rid["type"] == "string"
    assert rid["validation"][0]["condition"] == \
        '${var.github_repository_id == "" || can(regex("^[1-9][0-9]*$", var.github_repository_id))}'
    wif_locals = {k: v for block in _module_docs()["wif.tf"].get("locals", []) for k, v in block.items()}
    assert wif_locals == {"wif_repository_id_clause": EXPECTED_REPOSITORY_ID_CLAUSE}
    import sys
    gw = os.path.join(REPO, "apps", "orchestrator-gateway")
    if gw not in sys.path:
        sys.path.insert(0, gw)
    from developer_agent import contract_inspector as ci
    contract = ci.get_golden_module_contract(MOD_ID, force_refresh=True)
    ci._CONTRACT_CACHE.pop(MOD_ID, None)
    assert "github_repository_id" not in contract and "github_repo_full_name" in contract


def _parsed_resources(path, normalize=lambda text: text):
    with open(path, encoding="utf-8") as f:
        doc = hcl2.loads(normalize(f.read()))
    return {(t, n): body for block in doc.get("resource", []) for t, named in block.items() for n, body in named.items()}


def test_only_deployer_iam_and_wif_provider_changed_vs_pre_fd4at():
    """Real-parser diff against the pre-FD-4AT files (tests/fixtures/fd4at/pre_fd4at_*.tf.txt, = main 44643a2e):
    every resource except the deployer grants and the WIF provider is identical; the provider differs only in
    attribute_condition and two added attribute_mapping keys."""
    for name in ("iam.tf", "wif.tf"):
        pre = _parsed_resources(os.path.join(FIXTURES, f"pre_fd4at_{name}.txt"))
        # visible-rename-3b (owner 10-26): the pool's display_name changed only in the product name; revert exactly
        # that edit (tests/visible_rename_render.py) so every other attribute is still compared with the fixture.
        from visible_rename_render import pre_visible_rename
        from gha_switch_render import without_gha_switch   # GHA-DEPLOY-SWITCH: its own edits, undone exactly
        now = _parsed_resources(os.path.join(DISK, name), lambda t: pre_visible_rename(without_gha_switch(name, t)))
        is_deployer_grant = lambda k, b: b.get("member") == DEPLOYER  # noqa: E731
        changed = {k for k in set(pre) | set(now) if pre.get(k) != now.get(k)}
        for k in changed:
            body = now.get(k) or pre.get(k)
            if k == ("google_iam_workload_identity_pool_provider", "github_provider"):
                p, n = dict(pre[k]), dict(now[k])
                assert p.pop("attribute_condition") != n.pop("attribute_condition")
                pm, nm = p.pop("attribute_mapping"), n.pop("attribute_mapping")
                assert {kk: nm[kk] for kk in pm} == pm and set(nm) - set(pm) == {"attribute.repository_id",
                                                                                   "attribute.ref"}
                assert p == n
            else:
                assert is_deployer_grant(k, body), f"{name}: unexpected change to {k}"


# ------------------------------------------------------------------------------------------------ parity
def test_disk_cc_and_payload_entries_identical():
    disk = _disk_files(DISK)
    assert _disk_files(CC) == disk
    for rel in PAYLOADS:
        assert _payload_entry(rel) == disk, rel


# ------------------------------------------------------------------------------------------------ tofu (optional)
@pytest.mark.skipif(not (TOFU and MIRROR and os.path.isdir(os.path.join(MIRROR, "registry.opentofu.org", "hashicorp",
                                                                          "google"))),
                    reason="needs OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
def test_tofu_plan_contract_with_mock_provider():
    tmp = tempfile.mkdtemp(prefix="fd4at-")
    sock_dir = None
    try:
        mod = os.path.join(tmp, "base")
        shutil.copytree(DISK, mod, ignore=shutil.ignore_patterns(".terraform*", "*.tfstate*"))
        os.makedirs(os.path.join(mod, "tests"))
        shutil.copy(TFTEST, os.path.join(mod, "tests"))
        rc_file = os.path.join(tmp, "cli.tfrc")
        with open(rc_file, "w", encoding="utf-8") as f:
            f.write('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                    '    include = ["registry.opentofu.org/*/*"]\n  }\n}\n' % MIRROR)
        extra = {"TF_CLI_CONFIG_FILE": rc_file, "TF_DATA_DIR": os.path.join(tmp, "tfdata"), "TF_IN_AUTOMATION": "1"}
        if len(tempfile.gettempdir()) > 60:  # macOS caps provider unix-socket paths at 104 bytes
            sock_dir = tempfile.mkdtemp(prefix="fd4at-", dir="/private/tmp" if os.path.isdir("/private/tmp") else "/tmp")
            extra["TMPDIR"] = sock_dir
        env = hermetic_guard.child_env(extra=extra)
        init = subprocess.run([TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=mod, env=env,
                              capture_output=True, text=True, timeout=300)
        assert init.returncode == 0, init.stdout + init.stderr
        res = subprocess.run([TOFU, "test", "-no-color"], cwd=mod, env=env, capture_output=True, text=True, timeout=600)
        assert res.returncode == 0, res.stdout + res.stderr
        assert "18 passed, 0 failed" in res.stdout  # + 2 FD-4AT-c runs + 12 FD-4CI-b-R1-WIF runs + 2 GHA-DEPLOY-SWITCH runs
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if sock_dir:
            shutil.rmtree(sock_dir, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ FD-4AT-b / RT F6
UPGRADE_ENGINES = [
    "shared/iac_upgrade_engine.py",
    "apps/control-center/shared/iac_upgrade_engine.py",
    "apps/orchestrator-gateway/shared/iac_upgrade_engine.py",
    "mcp-servers/terraform/shared/iac_upgrade_engine.py",
]


def _load_engine(rel):
    import importlib.util

    name = "fd4at_engine_" + rel.replace("/", "_").replace("-", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fallback_source(rel):
    import ast

    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        src = f.read()
    fn = next(n for n in ast.parse(src, rel).body
              if isinstance(n, ast.FunctionDef) and n.name == "_get_foundation_embedded_modules")
    return ast.get_source_segment(src, fn)


def test_upgrade_engine_fallback_is_the_same_function_in_every_copy():
    assert len({_fallback_source(rel) for rel in UPGRADE_ENGINES}) == 1


@pytest.mark.parametrize("rel", UPGRADE_ENGINES)
def test_upgrade_engine_fallback_equals_the_module_for_every_file(rel):
    """RT F6: the container fallback is the payload entry (== disk module, every file), never a stale literal that
    could re-vendor a WIF provider without a condition or the removed deployer roles."""
    files = _load_engine(rel)._get_foundation_embedded_modules()
    disk = {f"infra/modules/workload-foundation/base/{n}": t for n, t in _disk_files(DISK).items()}
    assert files == disk


@pytest.mark.parametrize("rel", UPGRADE_ENGINES)
def test_upgrade_engine_fallback_raises_without_the_payload(rel):
    import sys
    from unittest import mock

    mod = _load_engine(rel)
    with mock.patch.dict(sys.modules, {"shared.builtin_modules_payload": None, "builtin_modules_payload": None}):
        with pytest.raises(RuntimeError, match="workload-foundation/base is unavailable"):
            mod._get_foundation_embedded_modules()


def _workflow(archetype):
    import sys

    gw = os.path.join(REPO, "apps", "orchestrator-gateway")
    if gw not in sys.path:
        sys.path.insert(0, gw)
    from developer_agent.handler import generate_service_workflow

    return generate_service_workflow("ops-bastion", "fd4at", "fd4at-proj", "123", archetype=archetype)


def _parsed_workflow(archetype):
    import yaml

    return yaml.safe_load(_workflow(archetype))


def test_bastion_ci_step_is_a_logged_no_op():
    """FD-4AT-b (owner 10-20): the gce-bastion CI never runs Terraform; the step and job stay, the command is a
    logged exit 0 (tf-applier applies and owns the state)."""
    steps = _parsed_workflow("gce-bastion")["jobs"]["deploy"]["steps"]
    step = next(s for s in steps if s.get("name") == "Deploy Infrastructure via Terraform")
    assert step == {
        "name": "Deploy Infrastructure via Terraform",
        "if": "steps.auth.outcome == 'success'",
        "run": "echo \"Infrastructure is applied by the platform's tf-applier, which owns the Terraform state. "
               "Nothing to apply from CI.\"\nexit 0\n",
    }
    for s in steps:
        if s is not step:
            assert "terraform" not in (s.get("run") or "").lower()


@pytest.mark.parametrize("archetype", ["cloudrun", "event-worker", "gke-autopilot"])
def test_other_archetype_steps_identical_to_pre_fd4at(archetype):
    """Do No Harm: only the bastion step changed (YAML-parsed steps == main 44643a2e output). The fixture is kept as
    recorded; the one later deliberate change, GHA-FIREBASE-ENV-NO-BLANK (the FIREBASE_* pair left the Cloud Run
    deploy flag), is applied to it here, exactly once."""
    import json

    with open(os.path.join(FIXTURES, "pre_fd4at_deploy_steps.json"), encoding="utf-8") as f:
        pre = json.load(f)[archetype]
    firebase_pair = (",FIREBASE_API_KEY=${{ secrets.FIREBASE_API_KEY }},"
                     "FIREBASE_AUTH_DOMAIN=${{ secrets.FIREBASE_AUTH_DOMAIN }}")
    for step in pre:
        if archetype == "cloudrun" and step.get("name") == "Build and Deploy to Cloud Run":
            assert step["run"].count(firebase_pair) == 1
            step["run"] = step["run"].replace(firebase_pair, "")
    assert _parsed_workflow(archetype)["jobs"]["deploy"]["steps"] == pre


@pytest.mark.parametrize("archetype", ["cloudrun", "event-worker", "gke-autopilot", "gce-bastion"])
def test_workflow_triggers_match_the_wif_condition(archetype):
    """RT F8: the WIF condition admits only push to main and workflow_dispatch; the generated workflow triggers on
    exactly those, so a trigger change surfaces here instead of as a CI auth failure."""
    wf = _parsed_workflow(archetype)
    triggers = wf.get("on", wf.get(True))  # YAML 1.1 reads the bare `on` key as boolean True
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["main"]
    assert set(triggers["push"]) == {"branches", "paths"}

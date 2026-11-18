"""SELFUP P3b (B2): one component list for `scripts/deploy-services.sh` and the upgrader (`scripts/upgrade/`).

- `scripts/common/components.sh` holds SERVICES / JOBS and the per-component recipes that existed in
  deploy-services.sh (CC module sync, pinned Helm staging, the QA job contract label, the git server's private
  flag, tf-applier following mcp-terraform-server). deploy-services.sh sources it.
- Command-diff: deploy-services.sh issues byte-identical commands before and after the refactor. The "before" side
  is `tests/fixtures/selfup_b2/deploy_services_commands.json`, captured from deploy-services.sh at main `70b848f6`
  (the last commit with the arrays inline) under the lane 5 logging stubs; every scenario is replayed against the
  current script and must produce the same command lines (exact order for single-component runs; the same multiset
  for the parallel bulk runs, whose start order depends on the scheduler). STAGE-JOB-RUNNER (11-13) re-captured the four
  bulk scenarios that deploy the gateway: additions only (the stage-runner job list, gateway image read and job update).
- Parity: components.sh == `COMPONENTS` in shared/release_manifest.py (+ tf-applier) == the upgrader's guard list.
Hermetic: lane 5 harness (logging stubs, no network, no credentials).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
GOLDEN = os.path.join(HERE, "fixtures", "selfup_b2", "deploy_services_commands.json")


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


lane5 = _load("selfup_b2_lane5", "tests/test_platform_safe_apply_lane5.py")
rm = _load("selfup_b2_release_manifest", "shared/release_manifest.py")

BAD_HELM_PIN = '{"version": "v3.15.0", "linux_amd64_sha256": "' + "0" * 64 + '"}\n'

# (name, args, extra env, files to write, ordered?)  `ordered` = single-component runs (sequential, exact order).
SCENARIOS = (
    ("single_control_center", ["control-center"], {}, {}, True),
    ("single_cc_by_name", ["product-control-center-ui"], {}, {}, True),
    ("single_terraform_server", ["mcp-terraform-server"],
     {"STUB_TF_IMAGE": "us-central1-docker.pkg.dev/p/r/mcp-terraform-server@sha256:feed"}, {}, True),
    ("single_tf_applier_alias", ["tf-applier"], {}, {}, True),
    ("single_git_server_ok", ["git-server"], {"STUB_GIT_JSON": "@GIT_JSON@"}, {}, True),
    ("single_git_server_absent", ["git-server"], {}, {}, True),
    ("single_qa_job", ["qa-sandbox-test-runner"], {}, {}, True),
    ("single_qa_job_by_dir", ["qa-runner"], {}, {}, True),
    ("single_sre_digest_job", ["sre-digest"], {}, {}, True),
    ("single_kubernetes_no_pin", ["mcp-kubernetes-server"], {}, {}, True),
    ("single_kubernetes_bad_pin", ["mcp-kubernetes-server"], {},
     {"mcp-servers/kubernetes/helm-pin.json": BAD_HELM_PIN}, True),
    ("single_deploy_fails", ["mcp-gcloud-server"], {"STUB_DEPLOY_RC": "1"}, {}, True),
    ("single_region_flag", ["--region=europe-west1", "spec-ingestion"], {}, {}, True),
    ("unknown_target", ["no-such-thing"], {}, {}, True),
    ("bulk_services", [], {"PARALLEL_LIMIT": "4"}, {}, False),
    ("bulk_all_jobs_git", ["--all-jobs"], {"STUB_GIT_JSON": "@GIT_JSON@"}, {}, False),
    ("bulk_retry_tf_server", [], {"STUB_DEPLOY_FAIL_ONCE": "mcp-terraform-server"}, {}, False),
    ("bulk_all_fail", ["--all-jobs"], {"STUB_DEPLOY_RC": "1"}, {}, False),
    ("bulk_with_version", ["--all-jobs"], {"STUB_GIT_JSON": "@GIT_JSON@"}, {"VERSION": "0.9.2\n"}, False),
)


class _Runner(lane5._Harness):
    """The lane 5 deploy-services harness, one scenario per setUp (the copy of scripts/ is fresh every time)."""

    def runTest(self):  # pragma: no cover - only used as a harness object
        pass

    def prepare(self, files):
        for d in lane5.TestDeployServices.DIRS:
            os.makedirs(os.path.join(self.repo, d), exist_ok=True)
        os.makedirs(os.path.join(self.repo, "apps/control-center/shared"), exist_ok=True)
        self.write("infra/modules/m/main.tf", "# module\n")
        self.write("shared/builtin_modules_payload.py", "PAYLOAD = {}\n")
        self.git_json = os.path.join(self.tmp, "git.json")
        with open(self.git_json, "w") as fh:
            json.dump(lane5.GOOD_GIT_JSON, fh)
        for rel, text in files.items():
            self.write(rel, text)

    def commands(self, args, env):
        env = {k: (self.git_json if v == "@GIT_JSON@" else v) for k, v in env.items()}
        rc, out, err = self.run_script("deploy-services.sh", args, PROJECT_ID=lane5.PROJ, **env)
        # mktemp directories differ per run (test-side normalisation of the log only)
        lines = [re.sub(r"\S*/tmp\.[A-Za-z0-9]+/", "<MKTEMP>/", x.replace(self.tmp, "<TMP>"))
                 for x in self.calls() if not x.startswith("sleep ")]
        return rc, lines


def run_scenario(name, args, env, files, ordered):
    r = _Runner()
    r.setUp()
    try:
        r.prepare(files)
        rc, lines = r.commands(args, env)
    finally:
        r.tearDown()
    return {"rc": rc, "commands": lines if ordered else sorted(lines)}


def capture_all():
    """Used once to write the golden file from the pre-refactor script (kept for re-capture by hand)."""
    return {s[0]: run_scenario(*s) for s in SCENARIOS}


class TestDeployServicesCommandDiff(unittest.TestCase):
    def setUp(self):
        with open(GOLDEN, encoding="utf-8") as fh:
            self.golden = json.load(fh)

    def test_every_scenario_has_a_golden(self):
        self.assertEqual(sorted(self.golden), sorted(s[0] for s in SCENARIOS))

    def test_commands_byte_identical_to_pre_refactor(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario[0]):
                self.assertEqual(run_scenario(*scenario), self.golden[scenario[0]])

    def test_golden_is_not_trivial(self):
        bulk = self.golden["bulk_all_jobs_git"]["commands"]
        self.assertEqual(len([c for c in bulk if c.startswith(("gcloud run deploy ", "gcloud run jobs deploy "))]), 23)  # C10: + 3 jobs
        self.assertIn("gcloud run jobs update qa-sandbox-test-runner --region us-central1 --project "
                      f"{lane5.PROJ} --update-labels=stackvend-qa-job-contract=1 --quiet", bulk)


# ------------------------------------------------------------------------------------------------ parity
def _sourced_lists():
    """SERVICES / JOBS exactly as bash sees them after sourcing components.sh."""
    script = ('set -eu; . "$1"; for e in "${SERVICES[@]}"; do echo "service ${e}"; done; '
              'for e in "${JOBS[@]}"; do echo "job ${e}"; done; echo "follow ${SV_TF_APPLIER_FOLLOWS}"; echo "followgw ${SV_STAGE_RUNNER_FOLLOWS} ${SV_STAGE_RUNNER_JOB}"; '
              'echo "label ${QA_JOB_CONTRACT_LABEL}"')
    out = subprocess.run(["/bin/bash", "-c", script, "x", os.path.join(REPO, "scripts", "common", "components.sh")],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    comps, extra = [], {}
    for line in out:
        kind, _, rest = line.partition(" ")
        if kind in ("service", "job"):
            name, _, d = rest.partition(":")
            comps.append((name, kind, d))
        else:
            extra[kind] = rest
    return comps, extra


def test_components_sh_matches_release_manifest():
    comps, extra = _sourced_lists()
    assert tuple(comps) + (("tf-applier", "job", "mcp-servers/terraform"),
                           ("stage-runner", "job", "apps/orchestrator-gateway")) == rm.COMPONENTS
    assert extra["follow"] == "mcp-terraform-server"
    assert extra["followgw"] == "orchestrator-gateway-service stage-runner"


def test_qa_label_matches_qa_runner_contract():
    _, extra = _sourced_lists()
    src = open(os.path.join(REPO, "apps", "qa-runner", "sandbox_job.py"), encoding="utf-8").read()
    version = extra["label"].split("=", 1)[1]
    assert f"JOB_CONTRACT_VERSION = {version}" in src or f'JOB_CONTRACT_VERSION = "{version}"' in src


def test_deploy_services_has_no_inline_component_list():
    text = open(os.path.join(REPO, "scripts", "deploy-services.sh"), encoding="utf-8").read()
    assert "SERVICES=(" not in text and "JOBS=(" not in text
    assert '. "${SCRIPT_DIR}/common/components.sh"' in text


def test_components_sh_is_bash32_syntax_and_side_effect_free():
    path = os.path.join(REPO, "scripts", "common", "components.sh")
    r = subprocess.run(["/bin/bash", "-n", path], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    # sourcing it runs nothing (definitions only): no output, no command executed
    r = subprocess.run(["/bin/bash", "-c", '. "$1"', "x", path], capture_output=True, text=True,
                       env={"PATH": "/nonexistent"})
    assert r.returncode == 0 and r.stdout == "" and r.stderr == ""


if __name__ == "__main__":
    unittest.main()

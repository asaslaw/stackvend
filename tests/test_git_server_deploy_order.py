"""Row GIT-404-TYPED, deploy order (review F1): the Serverless Git server deploys before every client.

Clients read a 404 without the git server's X-StackVend-Git-Server header as GitServerUnreachable, so they must
never run against an older git server. Enforced, not incidental:
- scripts/common/components.sh lists it first in SERVICES, and shared/release_manifest.COMPONENTS (both copies) first;
- scripts/deploy-services.sh (bulk) deploys it alone and synchronously before any other build is submitted, retries
  it once, and deploys nothing else when it still fails;
- the upgrader's deploy.sh puts it first explicitly (tests/test_selfup_b2_stages.py covers that path).
Hermetic: the lane 5 deploy-services harness (stub gcloud, temp repo copy).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


lane5 = _load("git_order_lane5", "tests/test_platform_safe_apply_lane5.py")
rm = _load("git_order_release_manifest", "shared/release_manifest.py")
rm_cc = _load("git_order_release_manifest_cc", "apps/control-center/shared/release_manifest.py")
GIT = "castor-git-server"


def test_git_server_is_first_in_every_component_list():
    assert rm.COMPONENTS[0] == (GIT, "service", "apps/git-server")
    assert rm_cc.COMPONENTS == rm.COMPONENTS
    text = open(os.path.join(REPO, "scripts", "common", "components.sh"), encoding="utf-8").read()
    body = text[text.index("SERVICES=("):]
    first = [ln.strip().strip('"') for ln in body.splitlines()[1:] if ln.strip().startswith('"')][0]
    assert first == f"{GIT}:apps/git-server"


class TestBulkDeployOrder(lane5._Harness):
    def setUp(self):
        super().setUp()
        for d in lane5.TestDeployServices.DIRS:
            os.makedirs(os.path.join(self.repo, d), exist_ok=True)
        os.makedirs(os.path.join(self.repo, "apps/control-center/shared"), exist_ok=True)
        self.write("infra/modules/m/main.tf", "# module\n")
        self.write("shared/builtin_modules_payload.py", "PAYLOAD = {}\n")
        self.git_json = os.path.join(self.tmp, "git.json")
        import json
        with open(self.git_json, "w") as f:
            json.dump(lane5.GOOD_GIT_JSON, f)

    def _deploys(self):
        return [x for x in self.calls() if x.startswith("gcloud run deploy") or x.startswith("gcloud run jobs deploy")]

    def test_git_server_deploys_first_and_alone(self):
        rc, out, err = self.run_script("deploy-services.sh", ["--all-jobs"], PROJECT_ID=lane5.PROJ,
                                       STUB_GIT_JSON=self.git_json, PARALLEL_LIMIT="8")
        self.assertEqual(rc, 0, out + err)
        deploys = self._deploys()
        # every service and job once; tf-applier (the terraform server image) and stage-runner (the gateway image,
        # STAGE-JOB-RUNNER) are never deployed on their own
        self.assertEqual(len(deploys), len([c for c in rm.COMPONENTS if c[0] not in ("tf-applier", "stage-runner")]))
        self.assertEqual(deploys[0], f"gcloud run deploy {GIT} --source apps/git-server --region us-central1 "
                                     f"--project {lane5.PROJ} --no-allow-unauthenticated --quiet")
        self.assertIn(f"Deploying {GIT}", out.replace("\x1b[1m", "").replace("\x1b[0m", ""))

    def test_a_git_server_failure_is_retried_once_before_any_client(self):
        rc, out, err = self.run_script("deploy-services.sh", [], PROJECT_ID=lane5.PROJ, STUB_GIT_JSON=self.git_json,
                                       STUB_DEPLOY_FAIL_ONCE=GIT)
        self.assertEqual(rc, 0, out + err)
        names = [x.split()[3] for x in self._deploys()]
        self.assertEqual(names[:2], [GIT, GIT])
        self.assertNotIn(GIT, names[2:])
        self.assertEqual(len(names), 15)

    def test_a_git_server_that_keeps_failing_deploys_nothing_else(self):
        rc, out, err = self.run_script("deploy-services.sh", ["--all-jobs"], PROJECT_ID=lane5.PROJ,
                                       STUB_GIT_JSON=self.git_json, STUB_DEPLOY_RC=1)
        self.assertNotEqual(rc, 0)
        names = [x.split()[3] for x in self._deploys()]
        self.assertEqual(set(names), {GIT}, names)
        self.assertIn("Nothing else was deployed", err)

    def test_negative_an_install_without_the_git_server_is_unchanged(self):
        rc, out, err = self.run_script("deploy-services.sh", [], PROJECT_ID=lane5.PROJ)
        self.assertEqual(rc, 0, out + err)
        names = [x.split()[3] for x in self._deploys()]
        self.assertEqual(len(names), 13)
        self.assertNotIn(GIT, names)
        self.assertIn("Skipping", out)

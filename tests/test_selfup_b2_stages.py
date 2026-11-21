"""SELFUP P3b (B2): the upgrader's stages after step 0 (scripts/upgrade/run.sh, preflight.sh, build.sh, deploy.sh,
check.sh, rollback.sh, stage.py) and `release_record.py --token-from-metadata` (plan §3.4.2, §3.5-§3.8; plan RT M-3,
M-8, I-1).

Hermetic. The stages run from a fixture checkout (a git repository made here from the real scripts) under /bin/bash
with stub `gcloud`, `curl` and a stub `pack` (shipped in a fixture tarball whose SHA-256 is pinned in the fixture's
builder-pins.json). Their Python children talk to a fake of the Google APIs (tests/fixtures/selfup_b2/fakeapi:
urllib.request.urlopen replaced, no socket opened) whose state is a JSON file the gcloud stub also updates.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
UPGRADE = os.path.join(REPO, "scripts", "upgrade")
FAKEAPI = os.path.join(HERE, "fixtures", "selfup_b2", "fakeapi")
G = "gi" + "t"


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


stage = _load("selfup_b2_stage", "scripts/upgrade/stage.py")
rm = _load("selfup_b2_stages_rm", "shared/release_manifest.py")
rr = _load("selfup_b2_release_record", "scripts/common/release_record.py")

PROJ, REGION = "proj-aaaa1", "us-central1"
RUN_PIN = "r/run-universal@sha256:" + "c" * 64
LIFECYCLE_PIN = "docker.io/buildpacksio/lifecycle@sha256:" + "d" * 64
AR = f"{REGION}-docker.pkg.dev/{PROJ}/castor-docker-repo"
RID = "1" * 32
RID2 = "2" * 32
TAG_JOB = "infra-rollback-job"   # deployed by tag before the upgrade (a trigger install), tag NOT resolvable


def _h(s):
    return hashlib.sha256(s.encode()).hexdigest()


GCLOUD_STUB = r'''#!/usr/bin/env python3
import fcntl, json, os, sys
a = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write("gcloud " + " ".join(a) + "\n")
if a[:3] in (["run", "services", "update"], ["run", "jobs", "update"]):
    name = a[3]
    if name in os.environ.get("STUB_FAIL_UPDATE", "").split(","):
        sys.exit(1)
    image = a[a.index("--image") + 1]
    with open(os.environ["STUB_API_STATE"] + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        st = json.load(open(os.environ["STUB_API_STATE"]))
        if a[1] == "services":
            s = st["services"][name]
            n = len([r for r in st["revisions"] if r.startswith(name + "-")]) + 1
            rev = f"{name}-r{n}"
            st["revisions"][rev] = {"service": name, "image": image}
            s["revision"] = s["created"] = rev
        else:
            j = st["jobs"][name]
            j["image"] = image
            for x in a:
                if x.startswith("--update-labels="):
                    k, v = x.split("=", 1)[1].split("=", 1)
                    j.setdefault("labels", {})[k] = v
        json.dump(st, open(os.environ["STUB_API_STATE"], "w"))
sys.exit(0)
'''

CURL_STUB = r'''#!/bin/bash
echo "curl $*" >> "$STUB_LOG"
out=""; prev=""
for x in "$@"; do [ "$prev" = "-o" ] && out="$x"; prev="$x"; done
cp "$STUB_PACK_TGZ" "$out"
'''

PACK_STUB = r'''#!/bin/bash
echo "pack $*" >> "$STUB_LOG"
img="$2"; path=""; report=""; prev=""
for x in "$@"; do [ "$prev" = "--path" ] && path="$x"; [ "$prev" = "--report-output-dir" ] && report="$x"; prev="$x"; done
[ -f "$path/release.json" ] || { echo "no release.json in $path" >&2; exit 1; }
[ -f "$DOCKER_CONFIG/config.json" ] || { echo "no docker config" >&2; exit 1; }
case ",${STUB_FAIL_BUILD:-}," in *",$(basename "${img%%:*}"),"*) exit 1 ;; esac
mkdir -p "$STUB_API_DIR/pushed"
sha="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$img")"
touch "$STUB_API_DIR/pushed/${sha}"
# pack's report.toml (lifecycle export report): the digest the registry holds for the pushed tag
if [ -n "$report" ]; then
    case ",${STUB_BAD_REPORT:-}," in
        *",$(basename "${img%%:*}"),"*) printf '[image]\ntags = ["%s"]\n' "$img" > "$report/report.toml" ;;
        *) printf '[image]\ntags = ["%s"]\ndigest = "sha256:%s"\n' "$img" "$sha" > "$report/report.toml" ;;
    esac
fi
'''


def _git(cwd, *args):
    env = {"PATH": os.environ.get("PATH", ""), "HOME": cwd, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "r", "GIT_AUTHOR_EMAIL": "r@example.invalid", "GIT_COMMITTER_NAME": "r",
           "GIT_COMMITTER_EMAIL": "r@example.invalid"}
    return subprocess.run([G, "-C", cwd, "-c", "commit.gpgsign=false", *args], capture_output=True, text=True,
                          check=True, env=env)


def _sa(name):
    return f"sa-{name[:20]}@{PROJ}.iam.gserviceaccount.com"


def initial_state():
    services, revisions, jobs, registry = {}, {}, {}, []
    for name, kind, _ in rm.COMPONENTS:
        old = f"{AR}/{name}@sha256:{_h('old-' + name)}"
        if kind == "service":
            services[name] = {"sa": _sa(name), "revision": f"{name}-r0", "created": f"{name}-r0"}
            revisions[f"{name}-r0"] = {"service": name, "image": old}
        else:
            jobs[name] = {"sa": _sa(name), "image": f"{AR}/{name}:abc123" if name == TAG_JOB else old}
            registry.append(old)
    # tf-applier runs the mcp-terraform-server image (FD28-02); stage-runner the gateway's (STAGE-JOB-RUNNER)
    jobs["tf-applier"]["image"] = revisions["mcp-terraform-server-r0"]["image"]
    registry.append(jobs["tf-applier"]["image"])
    jobs["stage-runner"]["image"] = revisions["orchestrator-gateway-service-r0"]["image"]
    registry.append(jobs["stage-runner"]["image"])
    services["castor-git-server"]["template"] = {
        "metadata": {"annotations": {"run.googleapis.com/execution-environment": "gen2"}},
        "spec": {"serviceAccountName": _sa("castor-git-server"),
                 "volumes": [{"name": "git-storage", "csi": {"driver": "gcsfuse.run.googleapis.com",
                                                             "volumeAttributes": {"bucketName": f"castor-git-repos-{PROJ}"}}}],
                 "containers": [{"image": "x", "volumeMounts": [{"name": "git-storage", "mountPath": "/data/git"}]}]}}
    jobs["qa-sandbox-test-runner"]["labels"] = {"stackvend-qa-job-contract": "1"}
    return {"services": services, "revisions": revisions, "jobs": jobs, "registry": registry,
            "actas": sorted({_sa(n) for n, _, _ in rm.COMPONENTS}), "ar": True, "ready_status": 403,
            "firestore": {f"platform_upgrades_progress/{RID}": {"fields": {"status": {"stringValue": "RUNNING"}}}}}


class Env:
    def __init__(self, tmp):
        self.tmp = tmp
        self.src = os.path.join(tmp, "work", "src")
        self.work = os.path.join(tmp, "work")
        self.api_dir = os.path.join(tmp, "api")
        self.state = os.path.join(self.api_dir, "state.json")
        self.api_log = os.path.join(self.api_dir, "calls.log")
        self.log = os.path.join(tmp, "calls.log")
        self.stub = os.path.join(tmp, "stub")
        for d in (self.src, self.api_dir, self.stub):
            os.makedirs(d, exist_ok=True)
        self._tree()
        self._stubs()
        self.write_state(initial_state())
        open(self.api_log, "w").close()
        open(self.log, "w").close()

    def _tree(self):
        for rel in ("scripts/common/components.sh", "scripts/common/release_record.py", "shared/release_manifest.py",
                    "mcp-servers/kubernetes/helm-pin.json"):
            os.makedirs(os.path.dirname(os.path.join(self.src, rel)), exist_ok=True)
            shutil.copy(os.path.join(REPO, rel), os.path.join(self.src, rel))
        shutil.copytree(UPGRADE, os.path.join(self.src, "scripts", "upgrade"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        for _, _, d in rm.COMPONENTS:
            os.makedirs(os.path.join(self.src, d), exist_ok=True)
            with open(os.path.join(self.src, d, "main.py"), "w") as fh:
                fh.write("# component\n")
        for rel, text in (("VERSION", "0.9.2\n"), ("infra/modules/m/main.tf", "# m\n"),
                          ("shared/builtin_modules_payload.py", "PAYLOAD = {}\n"),
                          ("apps/control-center/shared/.keep", "")):
            os.makedirs(os.path.dirname(os.path.join(self.src, rel)), exist_ok=True)
            with open(os.path.join(self.src, rel), "w") as fh:
                fh.write(text)
        # the pinned pack: a fixture tarball holding the stub, pinned by its real SHA-256
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = PACK_STUB.encode()
            info = tarfile.TarInfo("pack")
            info.size, info.mode = len(data), 0o755
            tf.addfile(info, io.BytesIO(data))
        self.pack_tgz = os.path.join(self.tmp, "pack.tgz")
        with open(self.pack_tgz, "wb") as fh:
            fh.write(buf.getvalue())
        self.pack_sha = hashlib.sha256(buf.getvalue()).hexdigest()
        self.set_pins(self.pack_sha)
        _git(self.src, "init", "-q")
        _git(self.src, "add", "-A")
        _git(self.src, "commit", "-q", "-m", "release 0.9.2")
        self.commit = _git(self.src, "rev-parse", "HEAD").stdout.strip()

    def set_pins(self, sha, builders=True, **overrides):
        pins = {"pack": {"version": "0.36.0", "linux_amd64_sha256": sha},
                "builders": {"default": "r/builder-default@sha256:" + "a" * 64 if builders else "",
                             "qa-sandbox-test-runner": "r/universal@sha256:" + "b" * 64 if builders else ""},
                "run_images": {"default": RUN_PIN if builders else ""},
                "lifecycle": {"version": "0.21.25", "image": LIFECYCLE_PIN if builders else ""}}
        pins.update(overrides)
        with open(os.path.join(self.src, "scripts", "upgrade", "builder-pins.json"), "w") as fh:
            json.dump(pins, fh)

    def _stubs(self):
        for name, body in (("gcloud", GCLOUD_STUB), ("curl", CURL_STUB)):
            p = os.path.join(self.stub, name)
            with open(p, "w") as fh:
                fh.write(body)
            os.chmod(p, 0o755)
        os.symlink(sys.executable, os.path.join(self.stub, "python3"))
        p = os.path.join(self.stub, "sha256sum")  # coreutils' output format, on every OS
        with open(p, "w") as fh:
            fh.write("#!/usr/bin/env python3\nimport hashlib, sys\n"
                     "for f in sys.argv[1:]:\n"
                     "    print(hashlib.sha256(open(f, 'rb').read()).hexdigest() + '  ' + f)\n")
        os.chmod(p, 0o755)

    def write_state(self, st):
        with open(self.state, "w") as fh:
            json.dump(st, fh)

    def read_state(self):
        return json.load(open(self.state))

    def verified(self, kind="UPGRADE", request_id=RID, rollback_of=""):
        v = {"schema_version": 1, "request_id": request_id, "kind": kind, "rollback_of": rollback_of,
             "requested_by": "admin@example.com", "project": PROJ, "region": REGION, "repository": "asaslaw/stackvend",
             "source_fingerprint": "sha256:" + "0" * 64, "target_tag": "v0.9.2", "commit": self.commit,
             "release": "0.9.2", "requires_apply_sh": False, "min_platform_release": "0.9.0-preview",
             "platform_release": "0.9.0-preview", "floor": "0.9.1", "signer_fingerprint": "SHA256:x", "warnings": []}
        path = os.path.join(self.work, "verified.json")
        with open(path, "w") as fh:
            json.dump(v, fh)
        return path

    def run(self, kind="UPGRADE", request_id=RID, rollback_of="", **env):
        path = self.verified(kind, request_id, rollback_of)
        e = {"PATH": os.pathsep.join([self.stub, os.path.dirname(shutil.which(G)), "/usr/bin", "/bin"]),
             "HOME": self.tmp, "LANG": "C", "STUB_LOG": self.log, "STUB_API_STATE": self.state,
             "STUB_API_LOG": self.api_log, "STUB_API_DIR": self.api_dir, "STUB_PACK_TGZ": self.pack_tgz,
             "PYTHONPATH": FAKEAPI, "PARALLEL_LIMIT": "32"}
        e.update(env)
        r = subprocess.run(["/bin/bash", os.path.join(self.src, "scripts", "upgrade", "run.sh"), path],
                           capture_output=True, text=True, env=hermetic_guard.hermetic_env(e), timeout=300)
        return r.returncode, r.stdout + r.stderr

    def calls(self, prefix=""):
        return [x for x in open(self.log).read().splitlines() if x.startswith(prefix)]

    def progress(self, rid=RID):
        doc = self.read_state()["firestore"].get(f"platform_upgrades_progress/{rid}")
        return rr.from_value({"mapValue": {"fields": doc["fields"]}}) if doc else None


@pytest.fixture
def env():
    tmp = tempfile.mkdtemp(prefix="selfup-b2-st-")
    try:
        yield Env(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _updates(env):
    return [c for c in env.calls("gcloud ") if " update " in c]


# ================================================================================================ end to end
def test_upgrade_builds_everything_then_deploys_image_only_cc_last(env):
    rc, out = env.run()
    assert rc == 0, out
    p = env.progress()
    assert p["status"] == "SUCCEEDED" and p["stage"] == "DONE", p
    builds = env.calls("pack build")
    assert len(builds) == 23  # 14 services + 9 jobs (C10: +3); tf-applier and stage-runner are never built
    assert all(f":0.9.2-{env.commit[:12]}-{RID[:12]} " in b and " --publish " in b for b in builds)
    qa = [b for b in builds if "qa-sandbox-test-runner:" in b][0]
    assert "--builder r/universal@sha256:" in qa
    # FD-148 builder parity: every component (the QA job too) builds on the pinned --source run image with the pinned
    # lifecycle, the runtime source --source uses (the install's region, never a hardcoded one), and none trusts the
    # builder
    for b in builds:
        assert f" --run-image {RUN_PIN} --lifecycle-image {LIFECYCLE_PIN} " in b, b
        assert (f" --env GOOGLE_RUNTIME_IMAGE_REGION={REGION} --env GOOGLE_USE_SERVERLESS_RUNTIMES_TARBALLS=true "
                in b), b
        assert "--trust-builder" not in b and "--network" not in b, b
        assert " --report-output-dir " in b, b
        if b is not qa:
            assert "--builder r/builder-default@sha256:" in b, b
    ups = _updates(env)
    assert len(ups) == 25   # C10: + 3 jobs; STAGE-JOB-RUNNER: + stage-runner
    assert ups[-1].startswith("gcloud run services update product-control-center-ui --image ")
    for u in ups:
        assert re.fullmatch(r"gcloud run (services|jobs) update \S+ --image \S+@sha256:[0-9a-f]{64}"
                            r"( --update-labels=stackvend-qa-job-contract=1)? --region us-central1 --project "
                            + PROJ + " --quiet", u), u
    st = env.read_state()
    assert st["jobs"]["tf-applier"]["image"] == st["revisions"][st["services"]["mcp-terraform-server"]["revision"]]["image"]
    gw_image = st["revisions"][st["services"]["orchestrator-gateway-service"]["revision"]]["image"]
    assert st["jobs"]["stage-runner"]["image"] == gw_image
    assert ups.index(next(u for u in ups if " stage-runner " in u)) == ups.index(
        next(u for u in ups if " orchestrator-gateway-service " in u)) + 1   # right after the gateway
    assert st["jobs"]["qa-sandbox-test-runner"]["labels"] == {"stackvend-qa-job-contract": "1"}
    # previous revisions recorded BEFORE the first update (the rollback targets)
    assert p["previous"]["mcp-gcloud-server"] == {"kind": "service", "revision": "mcp-gcloud-server-r0",
                                                  "image": f"{AR}/mcp-gcloud-server@sha256:{_h('old-mcp-gcloud-server')}",
                                                  "available": True}
    assert p["previous"][TAG_JOB]["available"] is False   # deployed by tag, tag unresolvable (M-3)
    api = open(env.api_log).read()
    assert api.index("/platform_upgrades_progress/") < api.index("testIamPermissions")
    # the version record, written with the build identity's token (M-8), deployer upgrader, full run
    rec = rr.from_value({"mapValue": {"fields": st["firestore"]["system_config/platform_release"]["fields"]}})
    assert rec["deployer"] == "upgrader" and rec["release"] == "0.9.2" and rec["commit"] == env.commit
    assert rec["source_repo"] == "asaslaw/stackvend" and rec["deployed_by"] == "admin@example.com"
    assert len(rec["components"]) == 25 and rec["history"][0]["full_run"] is True   # STAGE-JOB-RUNNER: + stage-runner
    # /validate/ready: the upgrader has no invoker right -> NOT_CHECKED, reported, never a pass
    assert p["terraform_ready"].startswith("NOT_CHECKED")
    # no release.json left in a place the next build would not expect, and the tree's commit was not changed
    assert _git(env.src, "rev-parse", "HEAD").stdout.strip() == env.commit


def test_terraform_server_not_ready_fails_the_check(env):
    st = env.read_state()
    st.update(ready_status=200, ready=False)
    env.write_state(st)
    rc, out = env.run(UP_READY_ATTEMPTS="1")
    assert rc != 0
    assert env.progress()["status"] in ("FAILED_CHECKING",)


def test_internal_only_terraform_server_is_not_checked_without_a_probe(env):
    """UPGRADER-READY-INGRESS: an internal-only terraform server (typed v2 ingress) -> NOT_CHECKED INGRESS_INTERNAL,
    no /validate/ready request at all, the upgrade succeeds (never a pass: the state is NOT_CHECKED)."""
    st = env.read_state()
    st["services"]["mcp-terraform-server"]["ingress"] = "INGRESS_TRAFFIC_INTERNAL_ONLY"
    st.update(ready_status=200, ready=False)   # a probe would fail the upgrade: proves none is sent
    env.write_state(st)
    rc, out = env.run(UP_READY_ATTEMPTS="1")
    assert rc == 0, out
    p = env.progress()
    assert p["status"] == "SUCCEEDED", p
    assert p["terraform_ready"].startswith("NOT_CHECKED: INGRESS_INTERNAL"), p["terraform_ready"]
    api = open(env.api_log).read()
    assert "/validate/ready" not in api
    assert "https://run.googleapis.com/v2/projects/proj-aaaa1/locations/us-central1/services/mcp-terraform-server" in api


def test_public_terraform_server_is_still_probed_and_fails_when_not_ready(env):
    """Negative (Do No Harm): INGRESS_TRAFFIC_ALL keeps today's probe and CHECK_FAILED after the retries."""
    st = env.read_state()
    st["services"]["mcp-terraform-server"]["ingress"] = "INGRESS_TRAFFIC_ALL"
    st.update(ready_status=200, ready=False)
    env.write_state(st)
    rc, out = env.run(UP_READY_ATTEMPTS="2")
    assert rc != 0
    assert env.progress()["status"] == "FAILED_CHECKING"
    assert open(env.api_log).read().count("/validate/ready") == 2


def test_terraform_server_without_a_typed_ingress_fails_loudly(env):
    st = env.read_state()
    st["services"]["mcp-terraform-server"]["ingress"] = None
    env.write_state(st)
    rc, out = env.run()
    assert rc != 0
    assert "API_FAILED mcp-terraform-server" in out
    assert "/validate/ready" not in open(env.api_log).read()


def test_missing_component_is_platform_not_ready_before_any_build(env):
    st = env.read_state()
    del st["jobs"]["sre-telemetry-digest-job"]
    env.write_state(st)
    rc, out = env.run()
    assert rc == stage.FAIL_CODES["PLATFORM_NOT_READY"], out
    assert "FAILED PLATFORM_NOT_READY sre-telemetry-digest-job" in out
    assert env.progress()["status"] == "REFUSED_PLATFORM_NOT_READY"
    assert env.calls("pack ") == [] and _updates(env) == []


def test_missing_act_as_right_is_platform_not_ready(env):
    st = env.read_state()
    st["actas"].remove(_sa("mcp-gcloud-server"))
    env.write_state(st)
    rc, out = env.run()
    assert rc == stage.FAIL_CODES["PLATFORM_NOT_READY"] and "mcp-gcloud-server" in out
    assert env.calls("pack ") == [] and _updates(env) == []


def test_absent_git_server_is_skipped(env):
    st = env.read_state()
    del st["services"]["castor-git-server"]
    env.write_state(st)
    rc, out = env.run()
    assert rc == 0, out
    assert not [b for b in env.calls("pack build") if "castor-git-server" in b]
    assert not [u for u in _updates(env) if "castor-git-server" in u]


def test_git_server_without_its_volume_is_not_ready(env):
    st = env.read_state()
    st["services"]["castor-git-server"]["template"]["spec"]["volumes"] = []
    env.write_state(st)
    rc, out = env.run()
    assert rc == stage.FAIL_CODES["PLATFORM_NOT_READY"] and "castor-git-server" in out


def test_empty_builder_pins_build_and_deploy_nothing(env):
    env.set_pins("", builders=False)
    rc, out = env.run()
    assert rc == stage.FAIL_CODES["BUILDER_PIN_MISSING"], out
    assert env.progress()["status"] == "FAILED_BUILDING"
    assert env.calls("pack ") == [] and _updates(env) == []


def test_committed_builder_pins_are_filled_and_valid():
    """11-03: the pins were filled from the real releases (pack v0.40.10's GitHub-published asset sha256; builder digests
    resolved read-only from the registries). They must parse as exact version / 64-hex / digest references."""
    pins = stage.read_pins(json.load(open(os.path.join(UPGRADE, "builder-pins.json"))))
    assert pins is not None


def test_fd148_committed_pins_match_the_source_deploy_builder():
    """FD-148 builder parity (read-only from 2026-11-20 `gcloud run deploy --source` Cloud Build records and the
    live image's labels): the platform builder and its run image are the serverless-runtimes ones,
    never the old gcr.io/buildpacks/builder (Ubuntu 18.04, Python <= 3.11); the lifecycle is pinned too."""
    _pack, _sha, default, qa, run_image, lifecycle = stage.read_pins(
        json.load(open(os.path.join(UPGRADE, "builder-pins.json"))))
    assert default == ("us-central1-docker.pkg.dev/serverless-runtimes/google-24-full/builder/universal"
                       "@sha256:eed34031fd9ba4ecce8d844f7ef0b97ab06811649b64f4312853de8c82f3b981")
    assert run_image == ("us-central1-docker.pkg.dev/serverless-runtimes/google-24/run/universal"
                         "@sha256:4a040650646e5d6d193156dcba8a4452502df9b88fbb409577654569fb57216f")
    assert lifecycle == ("mirror.gcr.io/buildpacksio/lifecycle"
                         "@sha256:319ef7d97a2e9e1fc82cd83fcb632a223647dbfb23b0fe8bb27846bc98247d1d")
    assert qa == default  # the QA job's --source build used the same builder
    assert "gcr.io/buildpacks/builder" not in json.dumps(json.load(open(os.path.join(UPGRADE, "builder-pins.json")))
                                                         ["builders"])


def _code_lines(path):
    """The shell lines that run (comment lines and trailing comments removed)."""
    out = []
    for line in open(path, encoding="utf-8").read().splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        out.append(line.split(" # ", 1)[0])
    return "\n".join(out)


def test_fd148_build_sh_never_trusts_the_builder_and_pins_lifecycle_and_run_image():
    """Attacker review: pack is never given --trust-builder (the builder's own lifecycle would get the registry
    credentials) nor --network (build containers must not reach the metadata server); the comment says why."""
    path = os.path.join(UPGRADE, "build.sh")
    code = _code_lines(path)
    for flag in ("--trust-builder", "--network", "trust-builder"):
        assert flag not in code, flag
    src = open(path, encoding="utf-8").read()
    assert "NEVER add pack's trust-builder flag" in src and "or its\n    # network flag" in src
    assert '--run-image "${RUN_IMAGE}" --lifecycle-image "${LIFECYCLE_IMAGE}"' in code
    assert '--env "GOOGLE_RUNTIME_IMAGE_REGION=${UP_REGION}"' in code  # the install's region, never a literal one
    assert '--report-output-dir "${W}/report/${name}"' in code and "report-digest --report" in code
    assert "stage_py digest" not in code  # the tag is never re-read for the digest


def test_fd148_negative_code_line_filter_keeps_flags():
    """The filter above only drops comments: a flag on a code line is still seen."""
    import tempfile as _t
    with _t.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write('# --network host\n"${PACK}" build x --trust-builder  # comment\npack --network host\n')
    try:
        code = _code_lines(fh.name)
    finally:
        os.unlink(fh.name)
    assert "--trust-builder" in code and "--network host" in code and code.count("--network") == 1


def test_fd148_report_digest_reads_packs_report(tmp_path):
    image = f"{AR}/svc:0.9.2-abc-123"
    good = tmp_path / "report.toml"
    good.write_text('[image]\ntags = ["%s"]\ndigest = "sha256:%s"\n' % (image, "e" * 64))
    assert stage.report_digest(str(good), image) == f"{AR}/svc@sha256:" + "e" * 64
    tags = 'tags = ["%s"]\n' % image
    bad_cases = {
        "missing.toml": None,
        "nodigest.toml": '[image]\n' + tags,
        "short.toml": '[image]\n' + tags + 'digest = "sha256:%s"\n' % ("e" * 63),
        "notsha.toml": '[image]\n' + tags + 'digest = "md5:%s"\n' % ("e" * 64),
        "broken.toml": '[image\n',
        "noimage.toml": tags + 'digest = "sha256:%s"\n' % ("e" * 64),
        # the report must be for this image: its [image] tags name it exactly
        "notags.toml": '[image]\ndigest = "sha256:%s"\n' % ("e" * 64),
        "othertag.toml": '[image]\ntags = ["%s"]\ndigest = "sha256:%s"\n' % (image + "0", "e" * 64),
        "tagsstring.toml": '[image]\ntags = "%s"\ndigest = "sha256:%s"\n' % (image, "e" * 64),
        "othersvc.toml": '[image]\ntags = ["%s"]\ndigest = "sha256:%s"\n' % (f"{AR}/other:0.9.2-abc-123", "e" * 64),
    }
    for name, text in bad_cases.items():
        if text is not None:
            (tmp_path / name).write_text(text)
        with pytest.raises(stage.StageError) as e:
            stage.report_digest(str(tmp_path / name), image)
        assert e.value.code == "DIGEST_UNKNOWN", name


def test_fd148_build_one_checks_the_tag_right_before_its_build():
    """The up-front pass refuses before anything is built; build_one checks its own tag again immediately before
    `pack build` (narrows the window for an image planted meanwhile)."""
    code = _code_lines(os.path.join(UPGRADE, "build.sh"))
    upfront = code.index('up_stage_py tag-absent --image "$(image_of "${name}")" || exit $?')
    body = code[code.index("build_one() {"):code.index("PARALLEL_LIMIT=")]
    assert upfront < code.index("build_one() {")
    check = body.index('up_stage_py tag-absent --image "${image}" || return 1')
    assert check < body.index('"${PACK}" build') < body.index("report-digest --report")
    assert body.count("tag-absent") == 1


def test_fd148_require_tag_absent():
    image = f"{AR}/svc:0.9.2-abc-123"
    stage.require_tag_absent(Api({}), image)  # 404: absent
    for status, code in ((200, "IMAGE_TAG_EXISTS"), (500, "API_FAILED"), (403, "API_FAILED")):
        api = Api({("HEAD", "/manifests/0.9.2-abc-123"): (status, None, {})})
        with pytest.raises(stage.StageError) as e:
            stage.require_tag_absent(api, image)
        assert e.value.code == code
        assert api.calls == [("HEAD", f"https://{REGION}-docker.pkg.dev/v2/{PROJ}/castor-docker-repo/svc/manifests/"
                                      "0.9.2-abc-123")]
    for bad in (f"{AR}/svc", f"{AR}/svc@sha256:" + "a" * 64, "svc:tag"):
        with pytest.raises(stage.StageError) as e:
            stage.require_tag_absent(Api({}), bad)
        assert e.value.code == "USAGE"


def test_fd148_preexisting_tag_builds_and_deploys_nothing(env):
    """A pre-planted image under this request's tag is refused before any build (typed IMAGE_TAG_EXISTS)."""
    st = env.read_state()
    st.setdefault("registry_tags", {})[f"{AR}/product-control-center-ui:0.9.2-{env.commit[:12]}-{RID[:12]}"] = \
        "sha256:" + "f" * 64
    env.write_state(st)
    rc, out = env.run()
    assert rc == stage.FAIL_CODES["IMAGE_TAG_EXISTS"], out
    assert "IMAGE_TAG_EXISTS" in out and env.progress()["status"] == "FAILED_BUILDING"
    assert env.calls("pack ") == [] and _updates(env) == []


def test_fd148_a_report_without_digest_deploys_nothing(env):
    rc, out = env.run(STUB_BAD_REPORT="orchestrator-gateway-service")
    assert rc == stage.FAIL_CODES["BUILD_FAILED"], out
    assert env.progress()["status"] == "FAILED_BUILDING" and _updates(env) == []


def test_fd148_deployed_digest_is_packs_reported_digest(env):
    """The deployed image is exactly the digest pack reported for this request's tag."""
    import hashlib as _h
    rc, out = env.run()
    assert rc == 0, out
    image = f"{AR}/product-control-center-ui:0.9.2-{env.commit[:12]}-{RID[:12]}"
    expected = f"{AR}/product-control-center-ui@sha256:" + _h.sha256(image.encode()).hexdigest()
    cc = [u for u in _updates(env) if u.startswith("gcloud run services update product-control-center-ui ")]
    assert cc and f" --image {expected} " in cc[0], cc


def test_empty_builder_pins_are_refused():
    """An empty pin file (a fork that has not filled it) is refused: digests are never guessed."""
    empty = {"pack": {"version": "", "linux_amd64_sha256": ""}, "builders": {"default": "", "qa-sandbox-test-runner": ""}}
    with pytest.raises(stage.StageError) as e:
        stage.read_pins(empty)
    assert e.value.code == "BUILDER_PIN_MISSING"


def _good_pins():
    return {"pack": {"version": "0.40.10", "linux_amd64_sha256": "a" * 64},
            "builders": {"default": "r/b@sha256:" + "a" * 64, "qa-sandbox-test-runner": "r/q@sha256:" + "b" * 64},
            "run_images": {"default": RUN_PIN}, "lifecycle": {"version": "0.21.25", "image": LIFECYCLE_PIN}}


def test_fd148_negative_good_pins_are_read_unchanged():
    """Do No Harm: a complete pin file reads back exactly, in build.sh's order."""
    assert stage.read_pins(_good_pins()) == ("0.40.10", "a" * 64, "r/b@sha256:" + "a" * 64, "r/q@sha256:" + "b" * 64,
                                             RUN_PIN, LIFECYCLE_PIN)


@pytest.mark.parametrize("section,key,value", [
    ("run_images", None, None),                                                   # no run_images section
    ("run_images", "default", None),                                              # missing
    ("run_images", "default", ""),                                                # empty
    ("run_images", "default", "us-central1-docker.pkg.dev/serverless-runtimes/google-24/run/universal:public-image-next"),
    ("run_images", "default", "r/run@sha256:" + "c" * 63),                        # short digest
    ("run_images", "default", "r/run x@sha256:" + "c" * 64),                      # whitespace splits build.sh's read
    ("lifecycle", None, None),                                                    # no lifecycle section
    ("lifecycle", "image", None),
    ("lifecycle", "image", ""),
    ("lifecycle", "image", "docker.io/buildpacksio/lifecycle:0.21.25"),           # tag only
    ("lifecycle", "image", "buildpacksio/lifecycle@sha256:" + "d" * 63 + "z"),     # not hex
    ("lifecycle", "version", ""),
    ("lifecycle", "version", "0.21"),
    ("builders", "default", "gcr.io/buildpacks/builder:v1"),                      # tag only (unchanged rule)
])
def test_fd148_missing_or_tag_only_run_image_or_lifecycle_is_refused(section, key, value):
    pins = _good_pins()
    if key is None:
        pins.pop(section)
    elif value is None:
        pins[section].pop(key)
    else:
        pins[section][key] = value
    with pytest.raises(stage.StageError) as e:
        stage.read_pins(pins)
    assert e.value.code == "BUILDER_PIN_MISSING"


@pytest.mark.parametrize("override", [{"run_images": {"default": ""}},
                                      {"lifecycle": {"version": "0.21.25", "image": "buildpacksio/lifecycle:0.21.25"}}])
def test_fd148_missing_run_image_or_lifecycle_builds_and_deploys_nothing(env, override):
    env.set_pins(env.pack_sha, **override)
    rc, out = env.run()
    assert rc == stage.FAIL_CODES["BUILDER_PIN_MISSING"], out
    assert env.progress()["status"] == "FAILED_BUILDING"
    assert env.calls("pack ") == [] and _updates(env) == []


def test_pack_tarball_with_the_wrong_hash_is_refused(env):
    env.set_pins("0" * 64)
    rc, out = env.run()
    assert rc == stage.FAIL_CODES["BUILD_FAILED"] and "does not match the pin" in out
    assert env.calls("pack ") == [] and _updates(env) == []


def test_one_failed_build_deploys_nothing(env):
    rc, out = env.run(STUB_FAIL_BUILD="mcp-compliance-server")
    assert rc == stage.FAIL_CODES["BUILD_FAILED"], out
    assert env.progress()["status"] == "FAILED_BUILDING" and _updates(env) == []


def test_failed_deploy_is_partial_and_tf_applier_follows_its_server(env):
    rc, out = env.run(STUB_FAIL_UPDATE="mcp-terraform-server")
    assert rc != 0
    assert env.progress()["status"] == "PARTIAL"
    assert "FAILED DEPLOY_FAILED mcp-terraform-server" in out and "FAILED DEPLOY_FAILED tf-applier" in out
    assert not [u for u in _updates(env) if " tf-applier " in u]
    rec = rr.from_value({"mapValue": {"fields": env.read_state()["firestore"]["system_config/platform_release"]["fields"]}})
    assert "mcp-terraform-server" not in rec["components"] and rec["history"][0]["full_run"] is False


def test_git_server_is_updated_first_and_explicitly(env):
    """GIT-404-TYPED: the git server's image update precedes every client's (deploy.sh sets it, not built.json's
    sorted keys)."""
    rc, out = env.run()
    assert rc == 0, out
    ups = _updates(env)
    assert ups[0].startswith("gcloud run services update castor-git-server --image ")
    assert ups[-1].startswith("gcloud run services update product-control-center-ui --image ")
    text = open(os.path.join(UPGRADE, "deploy.sh"), encoding="utf-8").read()
    assert 'order=("${git_server}"' in text


def test_a_failed_git_server_update_updates_nothing_else(env):
    rc, out = env.run(STUB_FAIL_UPDATE="castor-git-server")
    assert rc != 0
    assert "FAILED DEPLOY_FAILED castor-git-server: nothing else was updated" in out
    ups = _updates(env)
    assert len(ups) == 1 and " castor-git-server " in ups[0], ups


def test_rollback_restores_previous_revisions_and_reports_unavailable_components(env):
    rc, out = env.run()
    assert rc == 0, out
    before = env.read_state()
    open(env.log, "w").close()
    st = env.read_state()
    st["firestore"][f"platform_upgrades_progress/{RID2}"] = {"fields": {"status": {"stringValue": "RUNNING"}}}
    env.write_state(st)
    rc, out = env.run(kind="ROLLBACK", request_id=RID2, rollback_of=RID)
    assert rc != 0  # one component cannot be rolled back
    assert f"FAILED ROLLBACK_UNAVAILABLE {TAG_JOB}" in out
    assert env.progress(RID2)["status"] == "PARTIAL"
    after = env.read_state()
    svc = after["services"]["mcp-gcloud-server"]["revision"]
    assert after["revisions"][svc]["image"] == f"{AR}/mcp-gcloud-server@sha256:{_h('old-mcp-gcloud-server')}"
    assert after["jobs"]["sre-telemetry-digest-job"]["image"] == f"{AR}/sre-telemetry-digest-job@sha256:{_h('old-sre-telemetry-digest-job')}"
    assert after["jobs"][TAG_JOB]["image"] == before["jobs"][TAG_JOB]["image"]  # untouched, never guessed
    ups = _updates(env)
    assert ups[-1].startswith("gcloud run services update product-control-center-ui ") and len(ups) == 24   # C10: + 3 jobs; + stage-runner
    assert env.calls("pack ") == []   # no rebuild


def test_rollback_of_a_tag_deployed_job_resolves_its_digest_before_the_deploy(env):
    """M-3: when the tag still resolves at deploy time, the snapshot keeps its digest and the rollback can use it."""
    st = env.read_state()
    digest = f"{AR}/{TAG_JOB}@sha256:{_h('tagged')}"
    st["registry_tags"] = {f"{AR}/{TAG_JOB}:abc123": "sha256:" + _h("tagged")}
    st["registry"].append(digest)
    env.write_state(st)
    assert env.run()[0] == 0
    prev = env.progress()["previous"][TAG_JOB]
    assert prev == {"kind": "job", "image": digest, "available": True, "was_tag": f"{AR}/{TAG_JOB}:abc123"}
    st = env.read_state()
    st["firestore"][f"platform_upgrades_progress/{RID2}"] = {"fields": {"status": {"stringValue": "RUNNING"}}}
    env.write_state(st)
    rc, out = env.run(kind="ROLLBACK", request_id=RID2, rollback_of=RID)
    assert rc == 0, out
    assert env.progress(RID2)["status"] == "ROLLED_BACK"
    assert env.read_state()["jobs"][TAG_JOB]["image"] == digest


# ================================================================================================ stage.py units
class Api:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, body=None, headers=None):
        self.calls.append((method, url))
        for (m, part), resp in self.routes.items():
            if m == method and part in url:
                return resp if len(resp) == 3 else (resp[0], resp[1], {})
        return 404, None, {}


def test_rollback_plan_never_trusts_the_recorded_snapshot():
    d = f"{AR}/a@sha256:" + "1" * 64
    other = f"{AR}/b@sha256:" + "2" * 64
    api = Api({("GET", "/revisions/a-r0"): (200, {"metadata": {"labels": {"serving.knative.dev/service": "a"}},
                                                  "status": {"imageDigest": d}}),
               ("GET", "/revisions/b-r9"): (200, {"metadata": {"labels": {"serving.knative.dev/service": "b"}},
                                                  "status": {"imageDigest": other}}),
               ("HEAD", "/manifests/sha256:" + "3" * 64): (200, None, {"docker-content-digest": "sha256:" + "3" * 64})})
    plan = stage.rollback_plan(api, PROJ, REGION, {
        "a": {"kind": "service", "revision": "a-r0", "available": True, "image": "attacker@sha256:" + "9" * 64},
        "c": {"kind": "service", "revision": "b-r9", "available": True},          # another service's revision
        "j1": {"kind": "job", "image": f"{AR}/j1@sha256:" + "3" * 64, "available": True},
        "j2": {"kind": "job", "image": "docker.io/evil/x@sha256:" + "4" * 64, "available": True},  # other registry
        "j3": {"kind": "job", "image": f"{AR}/j3@sha256:" + "5" * 64, "available": True},        # not in AR
        "j4": {"kind": "job", "image": f"{AR}/j4:latest", "available": True},                     # a tag
        # code review M-D: another repository of the same project is not the platform repository
        "j6": {"kind": "job", "image": f"{REGION}-docker.pkg.dev/{PROJ}/cloud-run-source-deploy/j6@sha256:" + "3" * 64,
               "available": True},
        "j5": {"kind": "job", "available": False, "reason": "deployed by tag"},
    })
    assert plan["targets"] == {"a": {"kind": "service", "image": d, "revision": "a-r0"},
                               "j1": {"kind": "job", "image": f"{AR}/j1@sha256:" + "3" * 64}}
    assert sorted(plan["unavailable"]) == ["c", "j2", "j3", "j4", "j5", "j6"]
    assert "castor-docker-repo" in plan["unavailable"]["j6"]


def test_terraform_ready_states():
    ALL = "INGRESS_TRAFFIC_ALL"
    assert stage.terraform_ready(lambda url: (403, None), "https://x", ingress=ALL)["state"] == "NOT_CHECKED"
    assert stage.terraform_ready(lambda url: (200, {"ready": True}), "https://x", ingress=ALL)["state"] == "READY"
    res = stage.terraform_ready(lambda url: (200, {"ready": False}), "https://x", attempts=2, wait_s=0, ingress=ALL)
    assert res["state"] == "CHECK_FAILED"
    assert stage.terraform_ready(lambda url: (500, None), "https://x", attempts=1, wait_s=0,
                                 ingress=ALL)["state"] == "CHECK_FAILED"


@pytest.mark.parametrize("ingress", ["INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
                                     "INGRESS_TRAFFIC_NONE"])
def test_terraform_ready_internal_ingress_is_not_checked_and_never_probes(ingress):
    def probe(url):
        raise AssertionError("an internal-only server must not be probed")
    res = stage.terraform_ready(probe, "https://x", ingress=ingress)
    assert res["state"] == "NOT_CHECKED" and res["reason"].startswith("INGRESS_INTERNAL")


def test_terraform_ready_needs_the_ingress():
    with pytest.raises(TypeError):
        stage.terraform_ready(lambda url: (200, {"ready": True}), "https://x")   # pylint: disable=missing-kwoa


def test_terraform_ready_unknown_ingress_is_api_failed_and_never_probes():
    def probe(url):
        raise AssertionError("an unknown ingress must not be probed")
    for value in ("INGRESS_TRAFFIC_UNSPECIFIED", "INGRESS_TRAFFIC_SOMETHING_NEW", "all"):
        with pytest.raises(stage.StageError) as e:
            stage.terraform_ready(probe, "https://x", ingress=value)
        assert e.value.code == "API_FAILED"


def test_internal_ingress_set_is_explicit():
    assert stage.INTERNAL_INGRESS == {"INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
                                      "INGRESS_TRAFFIC_NONE"}
    assert stage.INGRESS_ALL not in stage.INTERNAL_INGRESS


def test_not_checked_reasons_name_the_control_center_check():
    res = stage.terraform_ready(lambda url: (403, None), "https://x", ingress="INGRESS_TRAFFIC_ALL")
    assert "the Control Center checks /validate/ready with its own identity" in res["reason"]
    res = stage.terraform_ready(None, "https://x", ingress="INGRESS_TRAFFIC_INTERNAL_ONLY")
    assert "the Control Center checks /validate/ready with its own identity" in res["reason"]


def test_terraform_server_with_an_unknown_ingress_fails_the_check(env):
    st = env.read_state()
    st["services"]["mcp-terraform-server"]["ingress"] = "INGRESS_TRAFFIC_UNSPECIFIED"
    env.write_state(st)
    rc, out = env.run()
    assert rc != 0
    assert "API_FAILED mcp-terraform-server" in out and "unknown ingress" in out
    assert "/validate/ready" not in open(env.api_log).read()


def test_service_ingress_is_the_typed_field():
    assert stage.service_ingress({"ingress": "INGRESS_TRAFFIC_ALL"}, "s") == "INGRESS_TRAFFIC_ALL"
    assert stage.service_ingress({"ingress": "INGRESS_TRAFFIC_NONE"}, "s") == "INGRESS_TRAFFIC_NONE"
    for bad in ({}, {"ingress": ""}, {"ingress": 1}, None, {"ingress": "INGRESS_TRAFFIC_UNSPECIFIED"}):
        with pytest.raises(stage.StageError) as e:
            stage.service_ingress(bad, "s")
        assert e.value.code == "API_FAILED"


def test_resolve_digest_reads_the_registry_header_only():
    api = Api({("HEAD", "/v2/p/r/n/manifests/t1"): (200, None, {"docker-content-digest": "sha256:" + "a" * 64})})
    assert stage.resolve_digest(api, "us-central1-docker.pkg.dev/p/r/n:t1") == \
        "us-central1-docker.pkg.dev/p/r/n@sha256:" + "a" * 64
    for bad in ("us-central1-docker.pkg.dev/p/r/n:t2", "n:t1"):
        with pytest.raises(stage.StageError) as e:
            stage.resolve_digest(api, bad)
        assert e.value.code == "DIGEST_UNKNOWN"


@pytest.mark.parametrize("pins", [
    {}, {"pack": {"version": "0.36", "linux_amd64_sha256": "a" * 64}, "builders": {}},
    {"pack": {"version": "0.36.0", "linux_amd64_sha256": "a" * 63}, "builders": {}},
    {"pack": {"version": "0.36.0", "linux_amd64_sha256": "a" * 64},
     "builders": {"default": "gcr.io/buildpacks/builder:v1", "qa-sandbox-test-runner": "x@sha256:" + "b" * 64}},
])
def test_builder_pins_must_be_exact(pins):
    with pytest.raises(stage.StageError) as e:
        stage.read_pins(pins)
    assert e.value.code == "BUILDER_PIN_MISSING"


def test_check_flags_label_image_and_applier_drift():
    d1, d2 = "r/x@sha256:" + "1" * 64, "r/y@sha256:" + "2" * 64
    api = Api({("GET", "/jobs/qa-sandbox-test-runner"): (200, {"metadata": {"labels": {}}, "spec": {"template": {
        "spec": {"template": {"spec": {"containers": [{"image": d1}]}}}}}})})
    res = stage.check(api, PROJ, REGION, {"qa-sandbox-test-runner": {"kind": "job", "image": d1},
                                          "tf-applier": {"kind": "job", "image": d1},
                                          "mcp-terraform-server": {"kind": "service", "image": d2}})
    assert res["qa-sandbox-test-runner"]["ok"] is False and "label" in res["qa-sandbox-test-runner"]["reason"]
    assert res["tf-applier"]["ok"] is False and res["mcp-terraform-server"]["ok"] is False


# ================================================================================================ static rules (I-1)
STAGE_SCRIPTS = ("run.sh", "preflight.sh", "build.sh", "deploy.sh", "check.sh", "rollback.sh", "lib.sh")


def test_stage_scripts_are_bash_syntax():
    for f in STAGE_SCRIPTS:
        r = subprocess.run(["/bin/bash", "-n", os.path.join(UPGRADE, f)], capture_output=True, text=True)
        assert r.returncode == 0, f + r.stderr


def test_the_upgrader_sends_image_only_updates_and_nothing_else():
    """Plan RT I-1 + Q3: the only gcloud calls are the two image-only updates in lib.sh; no Terraform, no IAM."""
    gcloud_lines = []
    for f in STAGE_SCRIPTS + ("verify.sh",):
        for ln in open(os.path.join(UPGRADE, f), encoding="utf-8").read().splitlines():
            code = ln.split("#", 1)[0]
            for bad in ("tofu", "terraform ", "apply.sh", "--source", "--service-account", "env-vars", "--set-",
                        "--clear-", "--remove-", "allow-unauthenticated", "update-traffic", "iam ", "add-iam",
                        "set-iam", "services delete", "jobs delete", "services create", "jobs create", "repositories create",
                        "buckets create", "services enable", "run deploy", "jobs deploy", "jobs execute", "builds submit"):
                assert bad not in code, (f, ln)
            if re.search(r"\bgcloud\b", code):
                gcloud_lines.append((f, code.strip()))
    assert gcloud_lines == [
        ("lib.sh", 'gcloud run services update "$1" --image "$2" --region "${UP_REGION}" --project "${UP_PROJECT}" --quiet'),
        ("lib.sh", 'gcloud run jobs update "$1" --image "$2" --update-labels="${labels}" --region "${UP_REGION}" \\'),
        ("lib.sh", 'gcloud run jobs update "$1" --image "$2" --region "${UP_REGION}" --project "${UP_PROJECT}" --quiet'),
    ], gcloud_lines


def test_stage_codes_do_not_collide_with_step_0():
    guard = _load("selfup_b2_stage_guard", "scripts/upgrade/guard.py")
    assert not set(stage.FAIL_CODES.values()) - {2} & set(guard.CODES.values())
    assert len(set(stage.FAIL_CODES.values())) == len(stage.FAIL_CODES)


def test_stage_py_is_standard_library_only():
    import ast
    tree = ast.parse(open(os.path.join(UPGRADE, "stage.py"), encoding="utf-8").read())
    mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    mods |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert mods <= set(sys.stdlib_module_names)


def test_qa_label_parity_with_components_sh():
    out = subprocess.run(["/bin/bash", "-c", '. "$1"; echo "$QA_JOB_CONTRACT_LABEL"', "x",
                          os.path.join(REPO, "scripts", "common", "components.sh")],
                         capture_output=True, text=True, check=True).stdout.strip()
    assert out == f"{stage.QA_LABEL_KEY}={stage.QA_LABEL_VALUE}"


# ================================================================================================ release_record.py (M-8)
def test_record_token_source_is_exactly_one(monkeypatch, tmp_path):
    rel = tmp_path / "release.json"
    rel.write_text(json.dumps({"schema_version": 1, "release": "0.9.2", "commit": "a" * 40, "dirty": False,
                               "built_at": "2026-11-02T00:00:00Z", "source_repo": "asaslaw/stackvend",
                               "builder": "upgrader"}))
    base = ["record", "--project", PROJ, "--region", REGION, "--release-file", str(rel), "mcp-gcloud-server"]
    for extra in ([], ["--token-stdin", "--token-from-metadata"]):
        with pytest.raises(SystemExit):
            rr.main(base[:-1] + extra + base[-1:])
    seen = {}
    monkeypatch.setattr(rr, "metadata_token", lambda: "meta-token")
    monkeypatch.setattr(rr, "make_http", lambda token, project: seen.setdefault("token", token) and (lambda *a: (404, None)))
    monkeypatch.setattr(rr, "write_record", lambda *a, **k: [])
    assert rr.main(base[:-1] + ["--token-from-metadata"] + base[-1:]) == 0
    assert seen["token"] == "meta-token"
    # code review L-C: an empty token names its real source
    monkeypatch.setattr(rr, "metadata_token", lambda: "")
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    assert rr.main(base[:-1] + ["--token-from-metadata"] + base[-1:]) == 1
    assert "no access token (metadata server)" in err.getvalue() and "stdin" not in err.getvalue()


def test_metadata_token_is_typed():
    class R(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    assert rr.metadata_token(lambda req, timeout: R(b'{"access_token": "t"}')) == "t"
    for body in (b"{}", b"nope"):
        with pytest.raises(rr.RecordError):
            rr.metadata_token(lambda req, timeout, b=body: R(b))
    assert rr.BUILDERS[1] == "upgrader"

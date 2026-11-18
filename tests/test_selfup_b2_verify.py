"""SELFUP P3b (B2): the upgrader's step 0 (`scripts/upgrade/verify.sh` + `scripts/upgrade/guard.py`), frozen into the
"Update StackVend" Cloud Build trigger by core Terraform (plan §3.3; plan RT 11-02 H-4, M-6, §6).

Hermetic. The release repositories are fixture git repositories created here; the release keys are ed25519 keys made
with ssh-keygen here. verify.sh fetches `https://github.com/<owner>/<repo>.git`; the test maps that prefix to the
fixture directory with git's own `url.<base>.insteadOf` (GIT_CONFIG_* environment), so nothing leaves the machine.
The network half of step 0 (`guard.py inputs`: request, lease, release source, stamp, version floor, claim) runs
against an in-memory Firestore / Cloud Run double through guard.main's http seam.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
VERIFY = os.path.join(REPO, "scripts", "upgrade", "verify.sh")
GUARD = os.path.join(REPO, "scripts", "upgrade", "guard.py")
G = "gi" + "t"

pytestmark = pytest.mark.skipif(not (shutil.which("ssh-keygen") and shutil.which(G)), reason="needs git + ssh-keygen")


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, rel))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


guard = _load("selfup_b2_guard", "scripts/upgrade/guard.py")
rm = _load("selfup_b2_rm", "shared/release_manifest.py")
_cli = _load("selfup_b2_release_source_cli", "scripts/release-source.py")
rsrc = _cli._load_release_source()

PROJ, REGION, GUARD_DB = "proj-aaaa1", "us-central1", "stackvend-guard"
OFFICIAL = "asaslaw/stackvend"
FORK = "acme/stackvend"
RID = "0123456789abcdef0123456789abcdef"


def _git_env(home):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home, "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "Release", "GIT_AUTHOR_EMAIL": "release@example.invalid",
           "GIT_COMMITTER_NAME": "Release", "GIT_COMMITTER_EMAIL": "release@example.invalid", "LANG": "C"}
    return env


def _manifest(release, requires=False, minimum="0.9.0-preview"):
    return json.dumps({"schema_version": 1, "release": release, "requires_apply_sh": requires,
                       "min_platform_release": minimum}) + "\n"


class Fixture:
    """Release keys and fixture repositories under <tmp>/gh/<owner>/<repo>.git (the stand-in for github.com)."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.home = os.path.join(tmp, "home")
        os.makedirs(self.home)
        self.env = _git_env(self.home)
        self.keys = {}
        for k in ("official", "fork", "stranger"):
            path = os.path.join(tmp, "keys", k)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", k, "-f", path], check=True,
                           env=self.env)
            pub = open(path + ".pub").read().split()
            self.keys[k] = {"file": path, "type": pub[0], "b64": pub[1], "public_key": f"{pub[0]} {pub[1]}",
                            "fingerprint": guard.parse_public_key(pub[0], pub[1])[1]}
        self.official_text = f"stackvend-release {self.keys['official']['public_key']}\n"

    def path(self, slug):
        return os.path.join(self.tmp, "gh", slug + ".git")

    def git(self, slug, *args, check=True):
        return subprocess.run([G, "-C", self.path(slug), "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                              capture_output=True, text=True, env=self.env, check=check)

    def commit(self, slug, files, msg="release"):
        p = self.path(slug)
        if not os.path.isdir(p):
            os.makedirs(p)
            subprocess.run([G, "init", "-q", p], check=True, env=self.env)
        for rel, text in files.items():
            full = os.path.join(p, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            if text is None:
                os.remove(full)
            else:
                with open(full, "w") as fh:
                    fh.write(text)
        self.git(slug, "add", "-A")
        self.git(slug, "commit", "-q", "--allow-empty", "-m", msg)
        return self.git(slug, "rev-parse", "HEAD").stdout.strip()

    def release_commit(self, slug, release, requires=False, minimum="0.9.0-preview", run_sh=True, manifest=None):
        files = {"VERSION": release + "\n",
                 "release-manifest.json": manifest if manifest is not None else _manifest(release, requires, minimum)}
        files["scripts/upgrade/run.sh"] = "#!/bin/bash\necho run\n" if run_sh else None
        if not run_sh and not os.path.exists(os.path.join(self.path(slug), "scripts/upgrade/run.sh")):
            files.pop("scripts/upgrade/run.sh")
        return self.commit(slug, files, f"release {release}")

    def tag(self, slug, tag, commit, key="official", kind="signed", force=False):
        f = ["-f"] if force else []
        if kind == "signed":
            self.git(slug, "-c", "gpg.format=ssh", "-c", f"user.signingkey={self.keys[key]['file']}",
                     "tag", *f, "-s", tag, "-m", tag, commit)
        elif kind == "annotated":
            self.git(slug, "tag", *f, "-a", tag, "-m", tag, commit)
        else:
            self.git(slug, "tag", *f, tag, commit)


@pytest.fixture
def fx():
    tmp = tempfile.mkdtemp(prefix="selfup-b2-")
    try:
        yield Fixture(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def make_inputs(fx, tag, commit, kind="UPGRADE", repository=OFFICIAL, signers=None, stamp=("0.9.0-preview", "c" * 40),
                floor=None, include_previews=True, rollback_of=""):
    signers = signers if signers is not None else [{"kind": "OFFICIAL"}]
    src = {"signers": [s if s["kind"] == "OFFICIAL" else
                       {"kind": "SSH_KEY", "public_key": fx.keys[s["key"]]["public_key"],
                        "fingerprint_sha256": fx.keys[s["key"]]["fingerprint"]} for s in signers]}
    trusted = guard.trusted_signers(src, fx.official_text)
    return {"schema_version": 1, "project": PROJ, "region": REGION,
            "request": {"request_id": RID, "kind": kind, "target_tag": tag, "expected_commit": commit,
                        "source_fingerprint": "sha256:" + "0" * 64, "requested_by": "admin@example.com",
                        "rollback_of": rollback_of},
            "source": {"repository": repository, "fingerprint": "sha256:" + "0" * 64,
                       "include_previews": include_previews, "stored": False},
            "signers": trusted, "stamp": {"release": stamp[0], "commit": stamp[1]} if stamp else
            {"release": None, "commit": None}, "floor": floor, "floor_from": []}


def run_verify(fx, inputs):
    work = tempfile.mkdtemp(prefix="work-", dir=fx.tmp)
    with open(os.path.join(work, "inputs.json"), "w") as fh:
        json.dump(inputs, fh)
    with open(os.path.join(work, "signers.json"), "w") as fh:
        json.dump(inputs["signers"], fh)
    with open(os.path.join(work, "allowed_signers"), "w") as fh:
        fh.write(guard.allowed_signers_text(inputs["signers"]))
    env = {"PATH": os.pathsep.join([os.path.dirname(sys.executable), os.path.dirname(shutil.which(G)),
                                    os.path.dirname(shutil.which("ssh-keygen")), "/usr/bin", "/bin"]),
           "HOME": fx.home, "LANG": "C",
           # github.com -> the fixture directory, through git's own URL rewriting (no network)
           "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"url.file://{fx.tmp}/gh/.insteadOf",
           "GIT_CONFIG_VALUE_0": "https://github.com/"}
    r = subprocess.run(["/bin/bash", VERIFY, "verify", "--workdir", work], capture_output=True, text=True,
                       env=hermetic_guard.hermetic_env(env), timeout=120)
    refusal = None
    if os.path.exists(os.path.join(work, "refusal.json")):
        refusal = json.load(open(os.path.join(work, "refusal.json")))
    verified = None
    if os.path.exists(os.path.join(work, "verified.json")):
        verified = json.load(open(os.path.join(work, "verified.json")))
    return r.returncode, r.stdout + r.stderr, refusal, verified, work


def assert_refused(result, code):
    rc, out, refusal, _, _ = result
    assert rc == guard.CODES[code], out
    assert refusal and refusal["code"] == code, out
    assert f"REFUSED {code}:" in out


# ================================================================================================ verify.sh, git side
def test_signed_tag_by_official_key_is_verified_and_checked_out(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    fx.tag(OFFICIAL, "v0.9.1", c)
    rc, out, refusal, verified, work = run_verify(fx, make_inputs(fx, "v0.9.1", c))
    assert rc == 0 and refusal is None, out
    assert verified["commit"] == c and verified["release"] == "0.9.1" and verified["target_tag"] == "v0.9.1"
    assert verified["signer_fingerprint"] == fx.keys["official"]["fingerprint"]
    assert verified["platform_release"] == "0.9.0-preview" and verified["requires_apply_sh"] is False
    assert os.path.isfile(os.path.join(work, "src", "scripts", "upgrade", "run.sh"))
    assert f"VERIFIED v0.9.1 ({c})" in out


def test_unsigned_annotated_tag_is_refused(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    fx.tag(OFFICIAL, "v0.9.1", c, kind="annotated")
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c)), "SIGNATURE_INVALID")


def test_lightweight_tag_is_refused(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    fx.tag(OFFICIAL, "v0.9.1", c, kind="lightweight")
    res = run_verify(fx, make_inputs(fx, "v0.9.1", c))
    assert_refused(res, "SIGNATURE_INVALID")
    assert not os.path.exists(os.path.join(res[4], "src", "VERSION")), "nothing checked out"


def test_tag_signed_by_an_untrusted_key_is_unknown_signer(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    fx.tag(OFFICIAL, "v0.9.1", c, key="stranger")
    res = run_verify(fx, make_inputs(fx, "v0.9.1", c))
    assert_refused(res, "UNKNOWN_SIGNER")
    assert fx.keys["stranger"]["fingerprint"] in res[2]["message"]


def test_moved_tag_is_refused(fx):
    """The admin confirmed commit A; the tag (still validly signed) now points at B."""
    a = fx.release_commit(OFFICIAL, "0.9.1")
    b = fx.commit(OFFICIAL, {"apps/x.py": "evil = True\n"}, "later")
    fx.tag(OFFICIAL, "v0.9.1", b)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", a)), "SOURCE_CHANGED")


def test_manifest_edited_in_an_unsigned_commit_is_refused(fx):
    """Someone with push rights but not the key edits the manifest and moves the tag to an unsigned tag object."""
    a = fx.release_commit(OFFICIAL, "0.9.3", requires=True, minimum="0.9.3")
    fx.tag(OFFICIAL, "v0.9.3", a)
    b = fx.commit(OFFICIAL, {"release-manifest.json": _manifest("0.9.3", False, "0.9.0-preview")}, "lie")
    fx.tag(OFFICIAL, "v0.9.3", b, kind="annotated", force=True)
    # what the Control Center saw (the moved tag) and what the admin was shown before the move: both refused
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.3", b)), "SIGNATURE_INVALID")
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.3", a)), "SIGNATURE_INVALID")


def test_unsigned_manifest_commit_cannot_ride_on_the_signed_tag(fx):
    """The signed tag stays on A; a request that names the unsigned commit B (manifest edited) is refused."""
    a = fx.release_commit(OFFICIAL, "0.9.3", requires=True, minimum="0.9.3")
    fx.tag(OFFICIAL, "v0.9.3", a)
    b = fx.commit(OFFICIAL, {"release-manifest.json": _manifest("0.9.3", False, "0.9.0-preview")}, "lie")
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.3", b)), "SOURCE_CHANGED")


def test_signed_tag_object_republished_under_another_name_is_refused(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    fx.tag(OFFICIAL, "v0.9.1", c)
    obj = fx.git(OFFICIAL, "rev-parse", "refs/tags/v0.9.1").stdout.strip()
    fx.git(OFFICIAL, "update-ref", "refs/tags/v0.9.5", obj)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.5", c)), "SIGNATURE_INVALID")


def test_downgrade_is_refused_and_same_release_is_allowed(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    fx.tag(OFFICIAL, "v0.9.1", c)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c, floor="0.9.2")), "DOWNGRADE_REFUSED")
    # equal to the floor: the U3 flow (apply.sh applied 0.9.1, then the button deploys 0.9.1's services) and retries
    rc, out, _, verified, _ = run_verify(fx, make_inputs(fx, "v0.9.1", c, floor="0.9.1"))
    assert rc == 0, out
    # a pre-release sorts below its release (SemVer 2.0 §11)
    c2 = fx.release_commit(OFFICIAL, "0.9.2-preview")
    fx.tag(OFFICIAL, "v0.9.2-preview", c2)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.2-preview", c2, floor="0.9.2")), "DOWNGRADE_REFUSED")


def test_min_platform_release_above_the_stamp_needs_apply_sh(fx):
    c = fx.release_commit(OFFICIAL, "0.9.3", requires=True, minimum="0.9.3")
    fx.tag(OFFICIAL, "v0.9.3", c)
    res = run_verify(fx, make_inputs(fx, "v0.9.3", c, stamp=("0.9.2", "d" * 40)))
    assert_refused(res, "NEEDS_APPLY_SH")
    assert res[2]["steps"] == [f"PROJECT_ID={PROJ} bash scripts/upgrade.sh v0.9.3"]
    assert not os.path.exists(os.path.join(res[4], "src", "VERSION")), "refused before checkout"
    # the platform at the target's minimum: allowed (infra first, then services)
    rc, out, _, _, _ = run_verify(fx, make_inputs(fx, "v0.9.3", c, stamp=("0.9.3", "d" * 40)))
    assert rc == 0, out


def test_skipped_release_still_needs_apply_sh(fx):
    """U4: v0.9.4 says requires_apply_sh: no but carries min_platform_release 0.9.3 forward."""
    c = fx.release_commit(OFFICIAL, "0.9.4", requires=False, minimum="0.9.3")
    fx.tag(OFFICIAL, "v0.9.4", c)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.4", c, stamp=("0.9.1", "d" * 40))), "NEEDS_APPLY_SH")


def test_missing_or_unparseable_stamp_is_platform_stamp_unknown(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    fx.tag(OFFICIAL, "v0.9.1", c)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c, stamp=None)), "PLATFORM_STAMP_UNKNOWN")
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c, stamp=("latest", "d" * 40))), "PLATFORM_STAMP_UNKNOWN")


def test_dirty_stamp_is_a_warning(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    fx.tag(OFFICIAL, "v0.9.1", c)
    rc, out, _, verified, _ = run_verify(fx, make_inputs(fx, "v0.9.1", c, stamp=("0.9.1", "d" * 40 + "+dirty")))
    assert rc == 0, out
    assert verified["warnings"] == ["platform stamp is +dirty: apply.sh ran from a modified checkout"]


def test_custom_key_fork_is_accepted(fx):
    c = fx.release_commit(FORK, "0.9.1")
    fx.tag(FORK, "v0.9.1", c, key="fork")
    rc, out, _, verified, _ = run_verify(fx, make_inputs(fx, "v0.9.1", c, repository=FORK,
                                                         signers=[{"kind": "SSH_KEY", "key": "fork"}]))
    assert rc == 0, out
    assert verified["repository"] == FORK and verified["signer_fingerprint"] == fx.keys["fork"]["fingerprint"]


def test_official_key_is_refused_once_the_fork_removed_it(fx):
    c = fx.release_commit(FORK, "0.9.1")
    fx.tag(FORK, "v0.9.1", c, key="official")
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c, repository=FORK,
                                              signers=[{"kind": "SSH_KEY", "key": "fork"}])), "UNKNOWN_SIGNER")
    # kept both: accepted
    rc, out, _, _, _ = run_verify(fx, make_inputs(fx, "v0.9.1", c, repository=FORK,
                                                  signers=[{"kind": "OFFICIAL"}, {"kind": "SSH_KEY", "key": "fork"}]))
    assert rc == 0, out


def test_fetch_failure_is_typed(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1")
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c)), "FETCH_FAILED")  # tag never published
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c, repository="nobody/nothing")), "FETCH_FAILED")


@pytest.mark.parametrize("manifest,code", [
    (_manifest("0.9.2"), "MANIFEST_MISMATCH"),
    (json.dumps({"schema_version": 2, "release": "0.9.1"}), "MANIFEST_UNSUPPORTED"),
    (json.dumps({"schema_version": 1, "release": "0.9.1", "requires_apply_sh": False,
                 "min_platform_release": "0.9.0-preview", "notes": "x"}), "MANIFEST_INVALID"),
    (_manifest("0.9.1", True, "0.9.0-preview"), "MANIFEST_INVALID"),
    ("{" + " " * 5000 + "}", "MANIFEST_INVALID"),
    ("not json", "MANIFEST_INVALID"),
])
def test_manifest_is_parsed_strictly(fx, manifest, code):
    c = fx.release_commit(OFFICIAL, "0.9.1", manifest=manifest)
    fx.tag(OFFICIAL, "v0.9.1", c)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c)), code)


def test_missing_manifest_is_invalid(fx):
    c = fx.commit(OFFICIAL, {"VERSION": "0.9.1\n", "scripts/upgrade/run.sh": "#!/bin/bash\n"})
    fx.tag(OFFICIAL, "v0.9.1", c)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c)), "MANIFEST_INVALID")


def test_preview_refused_when_the_source_follows_stable_only(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1-preview")
    fx.tag(OFFICIAL, "v0.9.1-preview", c)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1-preview", c, include_previews=False)), "PREVIEW_NOT_ALLOWED")
    rc, out, _, _, _ = run_verify(fx, make_inputs(fx, "v0.9.1-preview", c, include_previews=True))
    assert rc == 0, out


def test_release_without_the_upgrader_stages_is_not_upgradable(fx):
    c = fx.release_commit(OFFICIAL, "0.9.1", run_sh=False)
    fx.tag(OFFICIAL, "v0.9.1", c)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.1", c)), "TARGET_NOT_UPGRADABLE")


def test_rollback_reverifies_the_signature_but_skips_floor_and_platform(fx):
    c = fx.release_commit(OFFICIAL, "0.9.3", requires=True, minimum="0.9.3")
    fx.tag(OFFICIAL, "v0.9.3", c)
    rc, out, _, verified, _ = run_verify(fx, make_inputs(fx, "v0.9.3", c, kind="ROLLBACK", floor="0.9.9",
                                                         stamp=("0.9.0-preview", "d" * 40), rollback_of="f" * 32))
    assert rc == 0, out
    assert verified["kind"] == "ROLLBACK" and verified["rollback_of"] == "f" * 32
    fx.tag(OFFICIAL, "v0.9.3", c, key="stranger", force=True)
    assert_refused(run_verify(fx, make_inputs(fx, "v0.9.3", c, kind="ROLLBACK", rollback_of="f" * 32)),
                   "UNKNOWN_SIGNER")


def test_no_hook_of_the_fetched_repository_runs(fx):
    """Hooks are off and nothing is executed from the target before the hand-over."""
    marker = os.path.join(fx.tmp, "hook-ran")
    c = fx.commit(OFFICIAL, {"VERSION": "0.9.1\n", "release-manifest.json": _manifest("0.9.1"),
                             "scripts/upgrade/run.sh": f"#!/bin/bash\ntouch {marker}\n",
                             ".githooks/post-checkout": f"#!/bin/bash\ntouch {marker}\n"})
    fx.tag(OFFICIAL, "v0.9.1", c)
    rc, out, _, _, _ = run_verify(fx, make_inputs(fx, "v0.9.1", c))
    assert rc == 0, out
    assert not os.path.exists(marker)


# ================================================================================================ guard.py inputs (network half)
class FakeApi:
    """Firestore REST + Cloud Run v1 double. docs: {(database, path): dict}; services/revisions/jobs: Cloud Run bodies."""

    def __init__(self):
        self.docs, self.run, self.calls = {}, {}, []

    def http(self, method, url, body=None):
        self.calls.append((method, url))
        if url.startswith(guard.FIRESTORE):
            rest = url[len(guard.FIRESTORE):].split("?")[0]
            parts = rest.split("/documents/")
            database = parts[0].rsplit("/", 1)[1]
            key = (database, parts[1])
            if method == "GET":
                if key not in self.docs:
                    return 404, None
                return 200, {"fields": guard.to_value(self.docs[key])["mapValue"]["fields"], "updateTime": "t"}
            if method == "PATCH":
                q = url.split("?", 1)[1] if "?" in url else ""
                fields = guard.from_value({"mapValue": json.loads(body)})
                if "currentDocument.exists=false" in q:
                    if key in self.docs:
                        return 409, None
                    self.docs[key] = fields
                    return 200, {}
                if "currentDocument.exists=true" in q and key not in self.docs:
                    return 404, None
                self.docs[key] = {**self.docs.get(key, {}), **fields}
                return 200, {}
        name = url.rsplit("/", 1)[1]
        if name in self.run:
            return 200, self.run[name]
        return 404, None

    def factory(self, project):
        return self.http


def _now_plus(minutes):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.123456Z")


def _request(**over):
    req = {"schema_version": 1, "kind": "UPGRADE", "status": "REQUESTED", "target_tag": "v0.9.1",
           "expected_commit": "a" * 40, "source_fingerprint": rsrc.default_source().fingerprint,
           "requested_by": "admin@example.com", "requested_at": "2026-11-02T10:00:00Z", "rollback_of": ""}
    req.update(over)
    return req


def _api(stamp="0.9.0-preview", record=None, source=None, request=None, lease=True):
    api = FakeApi()
    api.docs[(GUARD_DB, f"platform_upgrades/{RID}")] = request if request is not None else _request()
    if lease:
        api.docs[(GUARD_DB, "platform_upgrades/_lease")] = {"request_id": RID, "expires_at": _now_plus(150)}
    if source is not None:
        api.docs[(GUARD_DB, "platform_release_source/current")] = source
    if record is not None:
        api.docs[("(default)", "system_config/platform_release")] = record
    ann = {} if stamp is None else {"stackvend/platform-release": stamp, "stackvend/platform-commit": "c" * 40}
    api.run["product-control-center-ui"] = {"metadata": {"annotations": ann},
                                            "status": {"latestReadyRevisionName": "cc-1"}}
    api.run["cc-1"] = {"status": {"imageDigest": "r/cc@sha256:" + "1" * 64}}
    return api


def run_inputs(api, tmp, official_text=None):
    out = tempfile.mkdtemp(dir=tmp)
    off = os.path.join(out, "official")
    with open(off, "w") as fh:
        fh.write(official_text if official_text is not None else "")
    rc = guard.main(["inputs", "--request-id", RID, "--project", PROJ, "--region", REGION, "--guard-database",
                     GUARD_DB, "--official-signers", off, "--out-dir", out], http_factory=api.factory)
    inputs = json.load(open(os.path.join(out, "inputs.json"))) if os.path.exists(os.path.join(out, "inputs.json")) else None
    refusal = json.load(open(os.path.join(out, "refusal.json"))) if os.path.exists(os.path.join(out, "refusal.json")) else None
    return rc, inputs, refusal, out


def _progress(api):
    return api.docs.get(("(default)", f"platform_upgrades_progress/{RID}"))


def test_inputs_default_source_official_key_and_claim(fx):
    api = _api()
    rc, inputs, refusal, out = run_inputs(api, fx.tmp, fx.official_text)
    assert rc == 0 and refusal is None
    assert inputs["source"]["repository"] == OFFICIAL and inputs["stamp"]["release"] == "0.9.0-preview"
    assert [s["fingerprint"] for s in inputs["signers"]] == [fx.keys["official"]["fingerprint"]]
    assert open(os.path.join(out, "allowed_signers")).read() == \
        f'signer-1 namespaces="git" {fx.keys["official"]["public_key"]}\n'
    assert inputs["floor"] == "0.9.0-preview"
    assert _progress(api)["status"] == "RUNNING" and _progress(api)["stage"] == "VERIFYING"
    # nothing was written to the guard database (the upgrader only reads it)
    assert not [c for c in api.calls if c[0] != "GET" and GUARD_DB in c[1]]


def test_inputs_request_runs_once(fx):
    api = _api()
    assert run_inputs(api, fx.tmp, fx.official_text)[0] == 0
    rc, _, refusal, _ = run_inputs(api, fx.tmp, fx.official_text)
    assert rc == guard.CODES["REQUEST_ALREADY_RUN"] and refusal["code"] == "REQUEST_ALREADY_RUN"
    assert _progress(api)["status"] == "RUNNING"  # the first run's record is untouched


@pytest.mark.parametrize("request_doc,lease,code", [
    (None, True, "REQUEST_NOT_FOUND"),
    (_request(status="RUNNING"), True, "REQUEST_NOT_PENDING"),
    (_request(target_tag="latest"), True, "REQUEST_INVALID"),
    (_request(expected_commit="abc"), True, "REQUEST_INVALID"),
    (_request(source_fingerprint="x"), True, "REQUEST_INVALID"),
    (_request(kind="ROLLBACK"), True, "REQUEST_INVALID"),
    (_request(schema_version=2), True, "REQUEST_INVALID"),
    (_request(), False, "LEASE_NOT_HELD"),
])
def test_inputs_request_and_lease_are_checked(fx, request_doc, lease, code):
    api = _api(request=request_doc if request_doc is not None else {}, lease=lease)
    if request_doc is None:
        del api.docs[(GUARD_DB, f"platform_upgrades/{RID}")]
    rc, _, refusal, _ = run_inputs(api, fx.tmp, fx.official_text)
    assert rc == guard.CODES[code] and refusal["code"] == code
    if code in ("REQUEST_INVALID", "LEASE_NOT_HELD"):
        assert _progress(api)["status"] == f"REFUSED_{code}"  # visible, create-only
    else:
        assert _progress(api) is None


def test_inputs_expired_lease(fx):
    api = _api()
    api.docs[(GUARD_DB, "platform_upgrades/_lease")] = {"request_id": RID, "expires_at": _now_plus(-1)}
    rc, _, refusal, _ = run_inputs(api, fx.tmp, fx.official_text)
    assert refusal["code"] == "LEASE_NOT_HELD"


def test_lease_shorter_than_the_build_timeout_is_refused(fx):
    """Code review M-A: a lease valid now but ending before a full build (7200 s) could expire mid-build."""
    api = _api()
    api.docs[(GUARD_DB, "platform_upgrades/_lease")] = {"request_id": RID, "expires_at": _now_plus(119)}
    rc, inputs, refusal, _ = run_inputs(api, fx.tmp, fx.official_text)
    assert rc == guard.CODES["LEASE_NOT_HELD"] and refusal["code"] == "LEASE_NOT_HELD" and inputs is None
    assert "7200" in refusal["message"]
    assert guard.BUILD_TIMEOUT_S == 7200
    api = _api()
    api.docs[(GUARD_DB, "platform_upgrades/_lease")] = {"request_id": RID, "expires_at": _now_plus(121)}
    assert run_inputs(api, fx.tmp, fx.official_text)[0] == 0


def test_bad_request_id_reads_nothing(fx):
    api = _api()
    out = tempfile.mkdtemp(dir=fx.tmp)
    rc = guard.main(["inputs", "--request-id", "../x", "--project", PROJ, "--region", REGION, "--guard-database",
                     GUARD_DB, "--official-signers", "/nonexistent", "--out-dir", out], http_factory=api.factory)
    assert rc == guard.CODES["BAD_REQUEST_ID"] and api.calls == []


def _stored(src, version=1, **extra):
    doc = rsrc.stored_document(src, version, "admin@example.com", "2026-11-02T10:00:00Z")
    doc.update(extra)
    return doc


def test_update_check_off_is_refused_before_any_fetch(fx):
    api = _api(source=_stored(rsrc.default_source(), update_check=False))
    rc, inputs, refusal, _ = run_inputs(api, fx.tmp, fx.official_text)
    assert refusal["code"] == "UPDATE_CHECK_OFF" and inputs is None
    assert _progress(api)["status"] == "REFUSED_UPDATE_CHECK_OFF"
    # v1 document (no update_check): ON; v2 with true: ON
    v1 = _stored(rsrc.default_source())
    v1.pop("update_check", None)
    for doc in (v1, _stored(rsrc.default_source(), update_check=True)):
        assert run_inputs(_api(source=doc), fx.tmp, fx.official_text)[0] == 0


@pytest.mark.parametrize("value", ["off", 0, None, "false"])
def test_update_check_that_is_not_a_bool_is_invalid(fx, value):
    rc, _, refusal, _ = run_inputs(_api(source=_stored(rsrc.default_source(), update_check=value)), fx.tmp,
                                   fx.official_text)
    assert refusal["code"] == "RELEASE_SOURCE_INVALID"


def test_source_setting_changed_after_the_request(fx):
    fork = rsrc.validate_source({"repository": FORK, "follow": "TAGS", "signers": [
        {"kind": "SSH_KEY", "public_key": fx.keys["fork"]["public_key"], "principal": "acme"}]})
    # request carries the default fingerprint (what the admin saw); the stored source is now the fork
    rc, _, refusal, _ = run_inputs(_api(source=_stored(fork)), fx.tmp, fx.official_text)
    assert refusal["code"] == "SOURCE_SETTING_CHANGED"
    # the request made after the change carries the fork's fingerprint: accepted, fork key trusted, official not
    api = _api(source=_stored(fork), request=_request(source_fingerprint=fork.fingerprint))
    rc, inputs, refusal, _ = run_inputs(api, fx.tmp, fx.official_text)
    assert rc == 0, refusal
    assert inputs["source"]["repository"] == FORK
    assert [s["fingerprint"] for s in inputs["signers"]] == [fx.keys["fork"]["fingerprint"]]


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(extra=1),
    lambda d: d.update(fingerprint="sha256:" + "0" * 64),
    lambda d: d.update(repository="not a repo"),
    lambda d: d.update(version=0),
    lambda d: d["signers"].append({"kind": "OFFICIAL"}),
    lambda d: d.update(signers=[{"kind": "SSH_KEY", "public_key": "ssh-rsa AAAA", "fingerprint_sha256": "x",
                                 "key_type": "ssh-rsa"}]),
])
def test_invalid_stored_source_never_falls_back(fx, mutate):
    doc = _stored(rsrc.default_source())
    mutate(doc)
    rc, _, refusal, _ = run_inputs(_api(source=doc), fx.tmp, fx.official_text)
    assert refusal["code"] == "RELEASE_SOURCE_INVALID"


def test_branch_source_is_not_supported(fx):
    # The Control Center no longer accepts this source; the upgrader's step 0 still refuses a stored one by itself.
    src = rsrc.ReleaseSource(FORK, "BRANCH", "main", True, (), True)
    api = _api(source=_stored(src), request=_request(source_fingerprint=src.fingerprint))
    assert run_inputs(api, fx.tmp, fx.official_text)[2]["code"] == "BRANCH_NOT_SUPPORTED"


def test_no_trusted_signers_when_the_official_list_is_empty(fx):
    rc, _, refusal, _ = run_inputs(_api(), fx.tmp, official_text="# no key yet\n")
    assert refusal["code"] == "NO_TRUSTED_SIGNERS"


def test_malformed_official_signers_fail_closed(fx):
    rc, _, refusal, _ = run_inputs(_api(), fx.tmp, official_text="stackvend-release ssh-rsa AAAAB3Nza\n")
    assert refusal["code"] == "OFFICIAL_SIGNERS_INVALID"
    ok = f'stackvend-release namespaces="git" {fx.keys["official"]["public_key"]} release key\n'
    assert run_inputs(_api(), fx.tmp, official_text=ok)[0] == 0


def _record(components):
    return {"schema_version": 1, "components": components, "history": []}


def test_floor_uses_only_digest_matched_components_and_never_drops_below_the_stamp(fx):
    d_gw = "r/gw@sha256:" + "2" * 64
    api = _api(stamp="0.9.1", record=_record({
        "orchestrator-gateway-service": {"image_digest": d_gw, "release": "0.9.2"},        # matches -> 0.9.2
        "mcp-gcloud-server": {"image_digest": "r/g@sha256:" + "3" * 64, "release": "0.9.9"},  # not running -> ignored
        "made-up-component": {"image_digest": d_gw, "release": "9.9.9"},                    # unknown name -> ignored
    }))
    api.run["orchestrator-gateway-service"] = {"status": {"latestReadyRevisionName": "gw-1"}}
    api.run["gw-1"] = {"status": {"imageDigest": d_gw}}
    api.run["mcp-gcloud-server"] = {"status": {"latestReadyRevisionName": "g-1"}}
    api.run["g-1"] = {"status": {"imageDigest": "r/g@sha256:" + "4" * 64}}
    rc, inputs, _, _ = run_inputs(api, fx.tmp, fx.official_text)
    assert rc == 0 and inputs["floor"] == "0.9.2" and inputs["floor_from"] == ["orchestrator-gateway-service=0.9.2"]
    # a forged record claiming an older release cannot push the floor below the platform stamp
    api = _api(stamp="0.9.1", record=_record({"orchestrator-gateway-service": {"image_digest": d_gw, "release": "0.1.0"}}))
    api.run["orchestrator-gateway-service"] = {"status": {"latestReadyRevisionName": "gw-1"}}
    api.run["gw-1"] = {"status": {"imageDigest": d_gw}}
    assert run_inputs(api, fx.tmp, fx.official_text)[1]["floor"] == "0.9.1"


def test_missing_stamp_is_carried_to_the_decision(fx):
    rc, inputs, _, _ = run_inputs(_api(stamp=None), fx.tmp, fx.official_text)
    assert rc == 0 and inputs["stamp"] == {"release": None, "commit": None} and inputs["floor"] is None


def test_api_failure_is_typed_and_reported(fx):
    api = _api()
    real = api.http

    def failing(method, url, body=None):
        if "run.googleapis.com" in url:
            return 503, None
        return real(method, url, body)
    api.http = failing
    rc, _, refusal, _ = run_inputs(api, fx.tmp, fx.official_text)
    assert refusal["code"] == "API_READ_FAILED"
    assert _progress(api)["status"] == "REFUSED_API_READ_FAILED"


def test_report_writes_the_refusal_and_the_verification(fx):
    api = _api()
    assert run_inputs(api, fx.tmp, fx.official_text)[0] == 0
    ref = os.path.join(fx.tmp, "refusal.json")
    json.dump({"code": "NEEDS_APPLY_SH", "message": "m", "steps": ["PROJECT_ID=p bash scripts/upgrade.sh v1.0.0"]},
              open(ref, "w"))
    assert guard.main(["report", "--request-id", RID, "--project", PROJ, "--refusal-file", ref,
                       "--stage", "VERIFYING"], http_factory=api.factory) == 0
    p = _progress(api)
    assert (p["status"], p["code"], p["steps"]) == ("REFUSED_NEEDS_APPLY_SH", "NEEDS_APPLY_SH",
                                                    ["PROJECT_ID=p bash scripts/upgrade.sh v1.0.0"])
    # report never creates a record for a request that was not claimed
    api2 = FakeApi()
    assert guard.main(["report", "--request-id", RID, "--project", PROJ, "--status", "RUNNING"],
                      http_factory=api2.factory) == guard.CODES["PROGRESS_WRITE_FAILED"]


# ================================================================================================ parity + frozen-content rules
def test_codes_table_is_stable_and_unique():
    assert len(set(guard.CODES.values())) == len(guard.CODES)
    for code in ("FETCH_FAILED", "SIGNATURE_INVALID", "UNKNOWN_SIGNER", "DOWNGRADE_REFUSED", "NEEDS_APPLY_SH",
                 "PLATFORM_STAMP_UNKNOWN", "UPDATE_CHECK_OFF", "SOURCE_SETTING_CHANGED", "SOURCE_CHANGED"):
        assert code in guard.CODES
    assert all(0 < v < 126 for v in guard.CODES.values())


def test_component_list_parity():
    """Step 0 (guard.py) is frozen in Terraform (platform_upgrader.tf hashes it), so it lists the components of the
    release that installed the trigger. STAGE-JOB-RUNNER added `stage-runner` after that: step 0 does not know it,
    which only means version_floor ignores its record entry (it runs the gateway's image, whose entry floors the
    release). It joins the frozen list with the next scheduled platform release (POST-RC-NO-CORE-TF)."""
    added_after_step0 = {"stage-runner": "job"}
    assert {**guard.COMPONENT_KINDS, **added_after_step0} == rm.COMPONENT_KINDS
    assert not set(added_after_step0) & set(guard.COMPONENT_KINDS)


def test_constants_parity():
    assert guard.OFFICIAL_RELEASE_REPOSITORY == rm.OFFICIAL_RELEASE_REPOSITORY
    assert guard.CONTROL_CENTER_SERVICE == rm.CONTROL_CENTER_SERVICE
    assert (guard.STAMP_RELEASE_ANNOTATION, guard.STAMP_COMMIT_ANNOTATION) == \
        (rm.STAMP_RELEASE_ANNOTATION, rm.STAMP_COMMIT_ANNOTATION)
    assert (guard.RECORD_COLLECTION, guard.RECORD_DOC) == (rm.RECORD_COLLECTION, rm.RECORD_DOCUMENT)
    assert (guard.SOURCE_COLLECTION, guard.SOURCE_DOC) == (rsrc.COLLECTION, rsrc.DOCUMENT)
    assert guard.ALLOWED_KEY_TYPES == rsrc.ALLOWED_KEY_TYPES and guard.MAX_SIGNERS == rsrc.MAX_SIGNERS
    # what the Control Center writes is a key set step 0 accepts (v1 before SELFUP-OFF, v2 after; plan RT H-3)
    stored = set(rsrc.stored_document(rsrc.default_source(), 1, "a@example.com", "2026-11-02T00:00:00Z"))
    assert stored in (guard._SOURCE_V1, guard._SOURCE_V2)


SEMVERS = ["0.9.0-preview", "0.9.0", "0.9.1-preview", "0.9.1", "0.9.10", "1.0.0-alpha", "1.0.0-alpha.1",
           "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "01.0.0", "1.0", "1.0.0-",
           "1.0.0+b", "v1.0.0", " 1.0.0", "1.0.0-01", ""]


def test_semver_parity_with_release_manifest():
    for a in SEMVERS:
        assert (guard.parse_semver(a) is None) == (rm.parse_semver(a) is None), a
        for b in SEMVERS:
            ga, gb, ra, rb = guard.parse_semver(a), guard.parse_semver(b), rm.parse_semver(a), rm.parse_semver(b)
            if ga and gb:
                assert guard.compare(ga, gb) == rm.compare(ra, rb), (a, b)


MANIFESTS = [
    {"schema_version": 1, "release": "0.9.1", "requires_apply_sh": False, "min_platform_release": "0.9.0"},
    {"schema_version": 1, "release": "0.9.3", "requires_apply_sh": True, "min_platform_release": "0.9.3"},
    {"schema_version": 1, "release": "0.9.3", "requires_apply_sh": False, "min_platform_release": "0.9.3"},
    {"schema_version": 1, "release": "0.9.3", "requires_apply_sh": True, "min_platform_release": "0.9.1"},
    {"schema_version": 1, "release": "0.9.1", "requires_apply_sh": False, "min_platform_release": "0.9.2"},
    {"schema_version": 2, "release": "0.9.1"},
    {"schema_version": 1, "release": "0.9.1", "requires_apply_sh": "no", "min_platform_release": "0.9.0"},
    {"schema_version": 1, "release": "0.9.1", "requires_apply_sh": False},
    {"schema_version": True, "release": "0.9.1", "requires_apply_sh": False, "min_platform_release": "0.9.0"},
]


def _rm_verdict(doc):
    try:
        m = rm.parse_manifest(json.dumps(doc).encode())
    except rm.ManifestError as e:
        return e.code
    return "MANIFEST_INVALID" if rm.manifest_rule_errors(m) else "OK"


def _guard_verdict(doc):
    try:
        guard.parse_manifest(json.dumps(doc).encode())
    except guard.Refusal as r:
        return r.code
    return "OK"


@pytest.mark.parametrize("doc", MANIFESTS)
def test_manifest_parity_with_release_manifest(doc):
    assert _guard_verdict(doc) == _rm_verdict(doc)


@pytest.mark.parametrize("platform,minimum", [("0.9.0-preview", "0.9.0-preview"), ("0.9.1", "0.9.3"),
                                              ("0.9.3", "0.9.3"), ("1.0.0", "0.9.3"), ("0.9.3-rc.1", "0.9.3")])
def test_guard_decision_parity_with_release_manifest_when_stamped(platform, minimum):
    target = "0.9.3" if minimum != "0.9.0-preview" else "0.9.1"
    raw = json.dumps({"schema_version": 1, "release": target, "requires_apply_sh": target == minimum,
                      "min_platform_release": minimum}).encode()
    rm_decision = rm.guard_decision(rm.PlatformStamp(platform, "c" * 40), rm.parse_manifest(raw)).decision
    inputs = {"project": PROJ, "region": REGION, "floor": None, "stamp": {"release": platform, "commit": "c" * 40},
              "source": {"repository": OFFICIAL, "fingerprint": "", "include_previews": True},
              "request": {"request_id": RID, "kind": "UPGRADE", "target_tag": "v" + target, "expected_commit": "a" * 40,
                          "requested_by": "x", "rollback_of": ""}}
    try:
        guard.decide(inputs, "a" * 40, raw, "SHA256:x")
        verdict = "ALLOW"
    except guard.Refusal as r:
        verdict = r.code
    assert verdict == rm_decision


def test_unstamped_platform_fails_closed_unlike_the_display_fallback():
    """Plan RT BL-1: every install is stamped; step 0 never assumes the RC release."""
    inputs = {"project": PROJ, "region": REGION, "floor": None, "stamp": {"release": None, "commit": None},
              "source": {"repository": OFFICIAL, "fingerprint": "", "include_previews": True},
              "request": {"request_id": RID, "kind": "UPGRADE", "target_tag": "v0.9.1", "expected_commit": "a" * 40,
                          "requested_by": "x", "rollback_of": ""}}
    with pytest.raises(guard.Refusal) as e:
        guard.decide(inputs, "a" * 40, json.dumps({"schema_version": 1, "release": "0.9.1", "requires_apply_sh": False,
                                                   "min_platform_release": "0.9.0-preview"}).encode(), "SHA256:x")
    assert e.value.code == "PLATFORM_STAMP_UNKNOWN"


def test_source_fingerprint_and_key_parity_with_the_control_center(fx):
    default = rsrc.default_source()
    assert guard.default_source()["fingerprint"] == default.fingerprint
    fork = rsrc.validate_source({"repository": FORK, "follow": "TAGS", "signers": [
        {"kind": "OFFICIAL"}, {"kind": "SSH_KEY", "public_key": fx.keys["fork"]["public_key"], "principal": "acme"}]})
    assert guard.read_source(_stored(fork))["fingerprint"] == fork.fingerprint
    assert guard.read_source(_stored(default))["fingerprint"] == default.fingerprint
    for k in fx.keys.values():
        assert rsrc.parse_ssh_public_key(k["public_key"])["fingerprint_sha256"] == k["fingerprint"]
        out = subprocess.run(["ssh-keygen", "-l", "-E", "sha256", "-f", k["file"] + ".pub"], capture_output=True,
                             text=True, check=True).stdout.split()
        assert out[1] == k["fingerprint"]


def test_guard_is_standard_library_only_and_one_file():
    tree = ast.parse(open(GUARD, encoding="utf-8").read())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "no relative imports"
            mods.add(node.module.split(".")[0])
    assert mods <= set(sys.stdlib_module_names), mods - set(sys.stdlib_module_names)
    assert "importlib" not in mods and "runpy" not in mods


def test_verify_sh_is_self_contained_and_runs_nothing_from_the_target_before_hand_over():
    text = open(VERIFY, encoding="utf-8").read()
    r = subprocess.run(["/bin/bash", "-n", VERIFY], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    code = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    body = "\n".join(code)
    assert "source " not in body and "\n. " not in body, "verify.sh sources nothing"
    # the only path into the target tree that runs code is the final exec of scripts/upgrade/run.sh, after verification
    runs = [ln for ln in code if "/src/" in ln and ("bash " in ln or "exec " in ln or "python3 " in ln)]
    assert runs == ['            exec bash "${SV_WORK}/src/scripts/upgrade/run.sh" "${SV_WORK}/verified.json"'], runs
    for forbidden in ("tofu", "terraform ", "gcloud", "curl ", "eval "):
        assert forbidden not in body, forbidden
    # order in `run`: inputs -> verify -> report -> exec
    run = body[body.index("        run)"):]
    assert run.index("sv_guard inputs") < run.index("sv_verify_target") < run.index("--stage VERIFIED") < run.index("exec bash")
    # hooks / fsmonitor off on every git call that touches the fetched repository
    assert "-c core.hooksPath=/dev/null -c core.fsmonitor=false" in body
    assert body.count("git -C") == 1, "every git call on the fetched repository goes through sv_git"
    # code review L-A: no global (or system) git config can reach the fetched repository
    for ln in code:
        if "git -C" in ln or "git init" in ln:
            assert "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null" in ln, ln

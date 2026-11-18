"""FD-4BR C1 (row L3-PRB-g, QA egress Phase 2): the sandbox job takes its package index from argv only.

`python3 -m sandbox_job --index-url <Artifact Registry PyPI remote .../simple/>` (the job template's args, set by
infra/platform/qa_sandbox.tf once the egress Terraform is applied). With it, the job fetches the sandbox SA's token from
the metadata server, probes `<index>/pip/` with Artifact Registry's Basic auth and gives pip the credential through a
0600 netrc file (`NETRC=` in the trusted pip's env, in the service's fresh trusted directory, never the untrusted
$HOME) that exists only while the trusted pip steps run. Without it the job behaves exactly as before (negative
tests): pypi.org default, no metadata request, no netrc, no NETRC, no Authorization header.

Hermetic: loopback FakeCloud (signed URLs + PEP 503 index + metadata endpoint), offline wheelhouse, stub bandit.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64
import hashlib
import json
import os
import stat

import pytest

import qa_sandbox_support as sup
import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
from qa_source import deterministic_tar_gz

sj = sup.load_sandbox_job("sandbox_job_fd4br_argv")

AR_INDEX = "https://us-central1-python.pkg.dev/mock-stackvend-project/castor-pypi-remote/simple/"
NONCE = "0123456789abcdef0123456789abcdef"

MAIN = "def health():\n    return {'status': 'healthy'}\n"
TEST_MAIN = "from main import health\n\ndef test_health():\n    assert health() == {'status': 'healthy'}\n"
# Untrusted code: proves no credential file is left anywhere in the job's work tree (HOME is <workdir>/home).
TEST_NO_NETRC = ("import os\n\ndef test_index_credential_is_gone():\n"
                 "    root = os.path.dirname(os.environ['HOME'])\n"
                 "    found = [f for _, _, fs in os.walk(root) for f in fs if f.endswith('netrc')]\n"
                 "    assert found == []\n")


def tree(**extra):
    files = {"apps/svc/main.py": MAIN, "apps/svc/requirements.txt": "", "apps/svc/tests/test_main.py": TEST_MAIN}
    files.update(extra)
    return deterministic_tar_gz({k: v.encode() for k, v in files.items()})


@pytest.fixture(scope="module")
def wheelhouse(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("wheelhouse"))
    return d, sup.build_wheelhouse(d)


@pytest.fixture()
def cloud(wheelhouse):
    c = sup.FakeCloud(*wheelhouse)
    yield c
    c.close()


def toolchain(cloud, tmp_path, **over):
    kw = dict(bandit_argv=sup.write_fake_bandit(str(tmp_path / "bandit")), test_packages=("pytest",),
              pytest_extra_args=(), index_url=cloud.index_url, apply_rlimits=False, **sup.HERMETIC_TOOLCHAIN)
    kw.update(over)
    return sj.Toolchain(**kw)


def run(cloud, tc, archive=None):
    archive = tree() if archive is None else archive
    cloud.source = archive
    env = {
        "QA_SOURCE_URL": cloud.url("source.tar.gz"), "QA_SOURCE_SHA256": hashlib.sha256(archive).hexdigest(),
        "QA_STATIC_PUT_URL": cloud.url("static.json"), "QA_REPORT_PUT_URL": cloud.url("report.json"),
        "QA_NONCE": NONCE, "QA_TRACE_ID": "trace-fd4br-1", "QA_COMMIT_SHA": "c" * 40, "QA_PRODUCT_ID": "demo",
        "QA_DEADLINE_SECONDS": "300",
    }
    return sj.run_job(env, toolchain=tc, transport=sj.HttpTransport(sleep=lambda s: None))


def static_json(cloud):
    raw = cloud.objects.get("static.json")
    return json.loads(raw) if raw else None


def basic(token):
    return "Basic " + base64.b64encode(f"oauth2accesstoken:{token}".encode()).decode()


# ------------------------------------------------------------------------------
# argv parsing (argv only; never env, never the tree)
# ------------------------------------------------------------------------------
def test_no_argument_keeps_the_default_toolchain_unchanged():
    assert sj.toolchain_from_argv([]) is None
    tc = sj.Toolchain()
    assert tc.index_url == sj.DEFAULT_INDEX_URL == "https://pypi.org/simple"
    assert tc.index_auth_metadata is False
    assert tc.index_probe_url() == "https://pypi.org/simple/pip/"


def test_index_url_argument_selects_the_artifact_registry_index_and_metadata_auth():
    tc = sj.toolchain_from_argv(["--index-url", AR_INDEX])
    assert tc.index_url == AR_INDEX and tc.index_auth_metadata is True
    assert tc.metadata_token_url == sj.METADATA_TOKEN_URL
    assert tc.index_probe_url() == AR_INDEX + "pip/"  # AR simple/pip/ (PEP 503 project page)
    # Everything else is the production default.
    default = sj.Toolchain()
    for name in ("python", "bandit_argv", "test_packages", "pytest_extra_args", "required_pytest_plugin_dists",
                 "harden_process", "sweep_uid_processes", "apply_rlimits", "constraints"):
        assert getattr(tc, name) == getattr(default, name), name


@pytest.mark.parametrize("argv", [
    ["--index-url"],
    [f"--index-url={AR_INDEX}"],
    ["--extra-index-url", AR_INDEX],
    ["--index-url", AR_INDEX, "--index-url", AR_INDEX],
    ["--index-url", AR_INDEX, "extra"],
    [AR_INDEX],
    ["--index-url", "http://us-central1-python.pkg.dev/p/castor-pypi-remote/simple/"],
    ["--index-url", "https://user:secret@us-central1-python.pkg.dev/p/castor-pypi-remote/simple/"],
    ["--index-url", "https://us-central1-python.pkg.dev/p/castor-pypi-remote/simple/?x=1"],
    ["--index-url", "https://us-central1-python.pkg.dev/p/castor-pypi-remote/simple/#f"],
    ["--index-url", "file:///tmp/simple/"],
    ["--index-url", "https:///simple/"],
])
def test_any_other_argv_is_a_runner_error_before_anything_runs(argv, monkeypatch):
    with pytest.raises(sj.RunnerError) as e:
        sj.toolchain_from_argv(argv)
    assert "secret" not in str(e.value)
    calls = []
    monkeypatch.setattr(sj, "run_job", lambda *a, **k: calls.append((a, k)) or 0)
    assert sj.main(argv) == 11
    assert calls == []


def test_main_without_arguments_calls_run_job_exactly_as_before(monkeypatch):
    calls = []
    monkeypatch.setattr(sj, "run_job", lambda *a, **k: calls.append((a, k)) or 0)
    # An index named in the environment is ignored: the job template has no env (verify_job_identity) and the job
    # never reads one for the index.
    for name in ("PIP_INDEX_URL", "QA_INDEX_URL", "INDEX_URL"):
        monkeypatch.setenv(name, "https://evil.example/simple/")
    assert sj.main([]) == 0
    assert calls == [((), {})]


def test_main_passes_the_argv_toolchain_to_run_job(monkeypatch):
    calls = []
    monkeypatch.setattr(sj, "run_job", lambda *a, **k: calls.append((a, k)) or 0)
    assert sj.main(["--index-url", AR_INDEX]) == 0
    (args, kwargs), = calls
    assert args == () and set(kwargs) == {"toolchain"}
    assert kwargs["toolchain"].index_url == AR_INDEX and kwargs["toolchain"].index_auth_metadata is True


def test_main_reads_sys_argv_by_default(monkeypatch):
    calls = []
    monkeypatch.setattr(sj, "run_job", lambda *a, **k: calls.append((a, k)) or 0)
    monkeypatch.setattr(sj.sys, "argv", ["sandbox_job.py", "--index-url", AR_INDEX])
    assert sj.main() == 0
    assert calls[0][1]["toolchain"].index_url == AR_INDEX
    monkeypatch.setattr(sj.sys, "argv", ["sandbox_job.py"])
    assert sj.main() == 0
    assert calls[1] == ((), {})


# ------------------------------------------------------------------------------
# .netrc (trusted pip only)
# ------------------------------------------------------------------------------
def test_netrc_is_0600_names_the_index_host_and_is_removed(tmp_path):
    path = sj.write_index_netrc(str(tmp_path), AR_INDEX, "ya29.tok")
    assert path == str(tmp_path / "pip-index.netrc")
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600
    assert open(path).read() == "machine us-central1-python.pkg.dev login oauth2accesstoken password ya29.tok\n"
    sj.remove_index_netrc(path)
    assert not os.path.lexists(path)
    sj.remove_index_netrc(path)  # idempotent


def test_netrc_never_follows_a_planted_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("untouched\n")
    d = tmp_path / "svc"
    d.mkdir()
    os.symlink(str(target), str(d / "pip-index.netrc"))
    path = sj.write_index_netrc(str(d), AR_INDEX, "ya29.tok")
    assert not os.path.islink(path) and stat.S_IMODE(os.lstat(path).st_mode) == 0o600
    assert target.read_text() == "untouched\n"


# ------------------------------------------------------------------------------
# End to end against an index that needs the token (hermetic)
# ------------------------------------------------------------------------------
def test_argv_index_end_to_end_token_reaches_probe_and_pip_and_leaves_no_credential(cloud, tmp_path, monkeypatch):
    cloud.index_auth = basic(cloud.metadata_token)
    written, real_write = [], sj.write_index_netrc

    def recording_write(directory, index_url, token):
        written.append(directory)
        return real_write(directory, index_url, token)

    monkeypatch.setattr(sj, "write_index_netrc", recording_write)
    tc = toolchain(cloud, tmp_path, index_auth_metadata=True, metadata_token_url=cloud.metadata_url)
    code = run(cloud, tc, tree(**{"apps/svc/tests/test_no_netrc.py": TEST_NO_NETRC}))
    # One netrc per service, in the service's fresh trusted directory (never the untrusted steps' HOME).
    assert len(written) == 1 and os.path.basename(written[0]).startswith("svc-")
    assert code == 0, (static_json(cloud), cloud.objects.get("report.json"))
    assert static_json(cloud)["index_reachable"] is True
    report = json.loads(cloud.objects["report.json"])
    assert report["passed"] is True and report["tests_total"] == 2 and report["tests_failed"] == 0
    # One token for the probe + one per service, fetched right before that service's netrc (RT F3).
    assert cloud.requests.count(f"GET {sup.METADATA_TOKEN_PATH}") == 2
    assert cloud.index_auth_seen and set(cloud.index_auth_seen) == {cloud.index_auth}  # probe + every pip request
    for raw in cloud.objects.values():
        assert cloud.metadata_token.encode() not in raw


def test_auth_index_without_the_token_is_unreachable_exit_11(cloud, tmp_path):
    cloud.index_auth = basic(cloud.metadata_token)
    code = run(cloud, toolchain(cloud, tmp_path))  # the pre-Phase-2 toolchain cannot use Artifact Registry
    assert code == 11
    assert static_json(cloud)["index_reachable"] is False and "report.json" not in cloud.objects


@pytest.mark.parametrize("status,body", [
    (500, None),
    (200, b"not json"),
    (200, b"{}"),
    (200, json.dumps({"access_token": ""}).encode()),
    (200, json.dumps({"access_token": "tok\nmachine evil login x password y"}).encode()),
    (200, json.dumps({"access_token": 7}).encode()),
])
def test_no_usable_metadata_token_fails_closed_before_untrusted_code(cloud, tmp_path, status, body):
    cloud.index_auth = basic(cloud.metadata_token)
    cloud.metadata_status, cloud.metadata_body = status, body
    tc = toolchain(cloud, tmp_path, index_auth_metadata=True, metadata_token_url=cloud.metadata_url)
    assert run(cloud, tc) == 11
    assert static_json(cloud)["index_reachable"] is False
    assert "report.json" not in cloud.objects
    assert not [r for r in cloud.requests if r.startswith("GET /simple/") or r.startswith("GET /wheels/")]


def test_metadata_request_carries_the_metadata_flavor_header(cloud):
    net = sj.HttpTransport(sleep=lambda s: None)
    assert sj.fetch_index_token(net, cloud.metadata_url, None) == cloud.metadata_token
    # Without the header the (fake, like the real) metadata server refuses: the header is what made the call work.
    assert net.request("GET", cloud.metadata_url)[0] == 403


# ------------------------------------------------------------------------------
# Do No Harm: no --index-url -> byte-identical behaviour
# ------------------------------------------------------------------------------
def test_default_toolchain_never_asks_for_a_token_or_writes_a_netrc(cloud, tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("credential path used without --index-url")

    monkeypatch.setattr(sj, "fetch_index_token", forbidden)
    monkeypatch.setattr(sj, "write_index_netrc", forbidden)
    monkeypatch.setattr(sj, "remove_index_netrc", forbidden)
    code = run(cloud, toolchain(cloud, tmp_path), tree(**{"apps/svc/tests/test_no_netrc.py": TEST_NO_NETRC}))
    assert code == 0
    assert static_json(cloud)["index_reachable"] is True
    assert f"GET {sup.METADATA_TOKEN_PATH}" not in cloud.requests
    assert cloud.index_auth_seen and set(cloud.index_auth_seen) == {None}  # no Authorization header anywhere


def test_default_probe_call_is_unchanged(cloud, tmp_path):
    """The probe is called exactly as before (no headers kwarg), so a transport without the new parameter works."""
    seen = []

    class OldTransport(sj.HttpTransport):
        def probe(self, url, deadline=None):  # the pre-Phase-2 signature
            seen.append(url)
            return super().probe(url, deadline=deadline)

    cloud.source = tree()
    archive = cloud.source
    env = {
        "QA_SOURCE_URL": cloud.url("source.tar.gz"), "QA_SOURCE_SHA256": hashlib.sha256(archive).hexdigest(),
        "QA_STATIC_PUT_URL": cloud.url("static.json"), "QA_REPORT_PUT_URL": cloud.url("report.json"),
        "QA_NONCE": NONCE, "QA_TRACE_ID": "trace-fd4br-2", "QA_COMMIT_SHA": "c" * 40, "QA_PRODUCT_ID": "demo",
        "QA_DEADLINE_SECONDS": "300",
    }
    assert sj.run_job(env, toolchain=toolchain(cloud, tmp_path), transport=OldTransport(sleep=lambda s: None)) == 0
    assert seen == [cloud.index_url + "/pip/"]


# ------------------------------------------------------------------------------
# RT F3 / F9: a fresh token per service; the Basic header value is redacted too
# ------------------------------------------------------------------------------
def two_services():
    files = {}
    for svc in ("a", "b"):
        files[f"apps/{svc}/main.py"] = MAIN
        files[f"apps/{svc}/requirements.txt"] = ""
        files[f"apps/{svc}/tests/test_main.py"] = TEST_MAIN
    return deterministic_tar_gz({k: v.encode() for k, v in files.items()})


def test_f3_each_service_gets_a_fresh_token_right_before_its_pip(cloud, tmp_path):
    # Only the newest token is valid: a token fetched once at the probe would 401 on the services' pip.
    cloud.metadata_rotate = True
    tc = toolchain(cloud, tmp_path, index_auth_metadata=True, metadata_token_url=cloud.metadata_url)
    code = run(cloud, tc, two_services())
    assert code == 0, (static_json(cloud), cloud.objects.get("report.json"))
    served = cloud.metadata_served
    assert len(served) == 3 and len(set(served)) == 3  # probe, service a, service b
    pip_auth = [a for a, r in zip(cloud.index_auth_seen, [r for r in cloud.requests
                                                           if r.startswith(("GET /simple/", "GET /wheels/"))])
                if not r.endswith("/simple/pip/")]
    assert {basic(served[1]), basic(served[2])} <= set(pip_auth)
    assert json.loads(cloud.objects["report.json"])["tests_total"] == 2


def test_f3_no_token_for_a_later_service_is_exit_11_never_a_code_defect(cloud, tmp_path):
    cloud.metadata_fail_after = 2  # probe + service a get a token; service b's request answers 500
    tc = toolchain(cloud, tmp_path, index_auth_metadata=True, metadata_token_url=cloud.metadata_url)
    assert run(cloud, tc, two_services()) == 11
    assert static_json(cloud)["index_reachable"] is True
    assert "report.json" not in cloud.objects  # nothing charged to the workload (no REQ.UNRESOLVABLE)


def test_f9_basic_auth_header_value_is_redacted():
    redact = sj.Redactor()
    sj._register_index_token(redact, "ya29.tok")
    header = sj.index_auth_headers("ya29.tok")["Authorization"]
    out = redact(f"token ya29.tok header {header} b64 {header.split(' ', 1)[1]}")
    assert "ya29.tok" not in out and header not in out and header.split(" ", 1)[1] not in out

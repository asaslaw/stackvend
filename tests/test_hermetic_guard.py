"""
Proof tests for the hermetic test guard (tests/hermetic_guard.py + repo-root conftest.py; Wave 1 lane 2).

Probe scenarios run in a SEPARATE pytest process inside tmp_path, with verbatim copies of the root conftest and the
guard files, WITHOUT any PYTHONPATH sitecustomize (so the orchestrator's interim guard is not active there): they prove
the repo guard alone is enough, including inside ``patch.dict(os.environ, {}, clear=True)`` (red-team F1).

Safety net: every probe module first installs an audit hook that refuses to open the real gcloud ADC file / any
real credential store. The guard's own hook is installed earlier (root conftest), so the net only fires if the guard
is broken, and then the probe fails loudly instead of reading a secret.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import xml.etree.ElementTree as ET
from datetime import date

import pytest

import hermetic_known_leaks

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TESTS = os.path.join(REPO, "tests")

SAFETY_NET = '''
import os as _os, sys as _sys
_REAL_HOMES = set()
try:
    import pwd as _pwd
    _REAL_HOMES.add(_pwd.getpwuid(_os.getuid()).pw_dir)
except Exception:
    pass
_NET_HITS = []
def _safety_net(event, args):
    if event == "open" and isinstance(args[0], str) and any(
            args[0].startswith(_os.path.join(h, ".config", "gcloud")) for h in _REAL_HOMES):
        _NET_HITS.append(args[0])
        raise PermissionError("PROBE SAFETY NET: the hermetic guard let a real credential store be opened")
_sys.addaudithook(_safety_net)
'''

PROBES = {
    # ---------------------------------------------------------------- Layer 1: sockets
    "test_socket_egress.py": """
        import socket
        def test_connect_swallowed():
            s = socket.socket()
            try:
                s.connect(("192.0.2.1", 443))  # TEST-NET-1
            except OSError:
                pass
            finally:
                s.close()
    """,
    "test_dns.py": """
        import socket
        def test_dns_swallowed():
            try:
                socket.getaddrinfo("example.invalid", 443)
            except OSError:
                pass
    """,
    "test_http_via_proxy.py": """
        import urllib.request
        def test_urlopen_swallowed():
            try:
                urllib.request.urlopen("http://example.com/", timeout=5)
            except Exception:
                pass
    """,
    # code-RT: every resolver entry point and sendmsg (NI_NUMERICHOST: no lookup would happen even unguarded)
    "test_resolvers.py": """
        import socket
        def test_gethostbyname_swallowed():
            try:
                socket.gethostbyname("example.invalid")
            except OSError:
                pass
        def test_gethostbyname_ex_swallowed():
            try:
                socket.gethostbyname_ex("example.invalid")
            except OSError:
                pass
        def test_getnameinfo_swallowed():
            try:
                socket.getnameinfo(("192.0.2.1", 443), socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)
            except OSError:
                pass
        def test_sendmsg_swallowed():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.sendmsg([b"x"], [], 0, ("192.0.2.1", 9))
            except OSError:
                pass
            finally:
                s.close()
    """,
    # code-RT finding 2 (P7): libuv does DNS/connect below the audit hook. Under the guard uvloop hands out the
    # asyncio loop, so a lookup through "uvloop" is audited and blocked (example.invalid: no real name either way).
    "test_uvloop.py": """
        import asyncio
        def test_uvloop_run_dns_swallowed():
            import uvloop
            async def main():
                try:
                    await asyncio.get_running_loop().getaddrinfo("example.invalid", 443)
                except OSError:
                    pass
            uvloop.run(main())
        def test_uvloop_direct_loop_swallowed():
            import uvloop
            try:
                uvloop.Loop().close()
            except Exception:
                pass
        def test_uvloop_loopback_server_ok():
            import uvloop
            async def main():
                server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                _, w = await asyncio.open_connection("127.0.0.1", port)
                w.close()
                server.close()
                return type(asyncio.get_running_loop()).__module__
            assert uvloop.run(main()).startswith("asyncio")
    """,
    "test_loopback_ok.py": """
        import http.server, socket, threading, urllib.request
        def test_loopback_http_and_unix_sockets():
            srv = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                port = srv.server_address[1]
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
                    assert r.status == 200
                with urllib.request.urlopen(f"http://localhost:{port}/", timeout=5) as r:
                    assert r.status == 200
            finally:
                srv.shutdown()
            a, b = socket.socketpair()
            a.sendall(b"x"); assert b.recv(1) == b"x"
            a.close(); b.close()
            assert socket.getaddrinfo("localhost", 80)
    """,
    # ---------------------------------------------------------------- Layer 3: credentials (F1)
    "test_adc_cleared_env.py": """
        import os
        from unittest import mock
        import hermetic_guard
        def test_adc_blocked_with_cleared_environment():
            import google.auth
            import google.auth._default
            from google.auth import _cloud_sdk
            from google.auth.exceptions import DefaultCredentialsError
            from google.auth import default as bound_default  # a binding taken after the guard (case 4c)
            with mock.patch.dict(os.environ, {}, clear=True):
                assert "GOOGLE_APPLICATION_CREDENTIALS" not in os.environ
                for fn in (google.auth.default, google.auth._default.default, bound_default):
                    try:
                        fn()
                    except DefaultCredentialsError as e:
                        assert isinstance(e, hermetic_guard.HermeticGuardError), type(e)
                    else:
                        raise AssertionError("google.auth.default() returned credentials")
                assert _cloud_sdk.get_application_default_credentials_path() == hermetic_guard.ADC_DISABLED_PATH
                from google.auth.compute_engine import _metadata
                assert _metadata.is_on_gce(None) is False
            assert _NET_HITS == []
    """,
    "test_cred_file_open.py": """
        import os, pwd
        def test_open_real_credential_store_swallowed():
            home = pwd.getpwuid(os.getuid()).pw_dir
            try:
                open(os.path.join(home, ".config", "gcloud", "hermetic-probe-nonexistent.json"))
            except OSError:
                pass
    """,
    # ---------------------------------------------------------------- Layer 3: clients
    "test_grpc_remote.py": """
        def test_gapic_channel_swallowed():
            from google.api_core import grpc_helpers
            from google.auth.credentials import AnonymousCredentials
            try:
                grpc_helpers.create_channel("pubsub.googleapis.com:443", credentials=AnonymousCredentials())
            except Exception:
                pass
    """,
    "test_grpc_loopback_ok.py": """
        def test_loopback_channels_allowed():
            import grpc
            from google.api_core import grpc_helpers
            from google.auth.credentials import AnonymousCredentials
            grpc.insecure_channel("localhost:8085").close()
            grpc_helpers.create_channel("localhost:8085", credentials=AnonymousCredentials()).close()
    """,
    "test_gcs_client.py": """
        def test_storage_client_swallowed():
            from google.cloud import storage
            from google.auth.credentials import AnonymousCredentials
            try:
                storage.Client(project="p", credentials=AnonymousCredentials())
            except Exception:
                pass
    """,
    "test_gcs_emulator_ok.py": """
        def test_storage_client_on_local_emulator(monkeypatch):
            monkeypatch.setenv("STORAGE_EMULATOR_HOST", "localhost:9023")
            from google.cloud import storage
            from google.auth.credentials import AnonymousCredentials
            storage.Client(project="p", credentials=AnonymousCredentials())
    """,
    "test_genai_client.py": """
        def test_genai_client_swallowed():
            from google import genai
            try:
                genai.Client(api_key="x")
            except Exception:
                pass
    """,
    "test_genai_doubles_ok.py": """
        from unittest import mock
        import pytest
        import hermetic_guard
        def test_unavailable_double():
            from google import genai
            with hermetic_guard.unavailable("google.genai.Client", "Gemini"):
                with pytest.raises(hermetic_guard.UnavailableInTests):
                    genai.Client(api_key="x")
        def test_mock_patch_unaffected():
            with mock.patch("google.genai.Client") as fake:
                from google import genai
                genai.Client(api_key="x")
                fake.assert_called_once()
    """,
    "test_pygithub.py": """
        def test_pygithub_swallowed():
            import github
            try:
                github.Github("fake-token")
            except Exception:
                pass
    """,
    # ---------------------------------------------------------------- Layer 2: processes
    "test_proc_git_remote.py": """
        import subprocess
        def test_git_network_swallowed():
            try:
                subprocess.run(["git", "ls-remote", "https://github.com/a/b.git"], capture_output=True)
            except OSError:
                pass
    """,
    "test_proc_gcloud.py": """
        import subprocess
        def test_gcloud_swallowed():
            try:
                subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True)
            except OSError:
                pass
    """,
    "test_proc_unittest.py": """
        import subprocess, sys
        def test_python_m_unittest_swallowed():
            try:
                subprocess.run([sys.executable, "-m", "unittest", "discover"], capture_output=True)
            except OSError:
                pass
    """,
    # network-capable binaries under a CLEARED environment, directly and through a shell
    "test_proc_cleared_env.py": """
        import os, subprocess
        from unittest import mock
        def _spawn(argv):
            with mock.patch.dict(os.environ, {}, clear=True):
                try:
                    subprocess.run(argv, capture_output=True, timeout=30)
                except OSError:
                    pass
        def test_cleared_env_gcloud():
            _spawn(["gcloud", "auth", "print-access-token"])
        def test_cleared_env_gsutil():
            _spawn(["gsutil", "ls", "gs://b"])
        def test_cleared_env_kubectl():
            _spawn(["/usr/local/bin/kubectl", "get", "pods"])
        def test_cleared_env_bq():
            _spawn(["bq", "ls"])
        def test_cleared_env_curl_via_shell():
            _spawn(["sh", "-c", "curl -s https://example.com"])
    """,
    # Python children are guarded too (tests/hermetic_child/sitecustomize.py) and report back to the parent test
    "test_child_python.py": """
        import os, subprocess, sys
        from unittest import mock
        CHILD = "import socket\\ntry:\\n    socket.getaddrinfo('example.invalid', 443)\\nexcept OSError:\\n    pass\\n"
        def test_child_python_violation_swallowed():
            subprocess.run([sys.executable, "-c", CHILD], check=True, capture_output=True, timeout=120)
        def test_child_python_violation_swallowed_cleared_env():
            with mock.patch.dict(os.environ, {"PATH": os.environ["PATH"]}, clear=True):
                subprocess.run([sys.executable, "-c", CHILD], check=True, capture_output=True, timeout=120)
        def test_child_python_clean_ok():
            out = subprocess.run([sys.executable, "-c", "import sys; print('hermetic_guard' in sys.modules)"],
                                 check=True, capture_output=True, text=True, timeout=120)
            assert out.stdout.strip() == "True", out.stdout + out.stderr
    """,
    "test_proc_local_ok.py": """
        import os, subprocess, sys
        from unittest import mock
        import hermetic_guard
        def test_local_git_and_children(tmp_path):
            subprocess.run(["git", "--version"], check=True, capture_output=True)
            subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(tmp_path), "diff"], check=True, capture_output=True)
            show = "import os; print(os.environ.get('HTTPS_PROXY'), os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))"
            # env built from scratch: the guard injects Layer 0
            out = subprocess.run([sys.executable, "-c", show], env={"PATH": os.environ["PATH"]},
                                 capture_output=True, text=True, check=True).stdout.split()
            assert out == [hermetic_guard.PROXY_SENTINEL, hermetic_guard.ADC_DISABLED_PATH], out
            # inherited env from a cleared os.environ: injected too
            with mock.patch.dict(os.environ, {"PATH": os.environ["PATH"]}, clear=True):
                out = subprocess.run([sys.executable, "-c", show], capture_output=True, text=True,
                                     check=True).stdout.split()
            assert out == [hermetic_guard.PROXY_SENTINEL, hermetic_guard.ADC_DISABLED_PATH], out
            assert "GOOGLE_APPLICATION_CREDENTIALS" not in os.environ or os.environ["GOOGLE_APPLICATION_CREDENTIALS"] == hermetic_guard.ADC_DISABLED_PATH
    """,
    # ---------------------------------------------------------------- markers / collection
    "test_live_marker.py": """
        import pytest, socket
        @pytest.mark.live
        def test_live_needs_network():
            socket.create_connection(("192.0.2.1", 443), timeout=1)
    """,
    "test_import_time_leak.py": """
        import socket
        try:
            socket.getaddrinfo("example.invalid", 443)
        except OSError:
            pass
        def test_never_reported_as_pass():
            pass
    """,
}

# Expected outcome per probe test (junit classname::name suffix) -> "violation" (fails with the guard message),
# "passed", "skipped" or "collect-error".
EXPECT = {
    "::test_connect_swallowed": ("violation", "[socket]"),
    "::test_dns_swallowed": ("violation", "[dns]"),
    "::test_gethostbyname_swallowed": ("violation", "[dns]"),
    "::test_gethostbyname_ex_swallowed": ("violation", "[dns]"),
    "::test_getnameinfo_swallowed": ("violation", "[dns] getnameinfo"),
    "::test_sendmsg_swallowed": ("violation", "[socket]"),
    "::test_uvloop_run_dns_swallowed": ("violation", "[dns]"),
    "::test_uvloop_direct_loop_swallowed": ("violation", "uvloop.Loop()"),
    "::test_uvloop_loopback_server_ok": ("passed", None),
    "::test_cleared_env_gcloud": ("violation", "[subprocess] gcloud"),
    "::test_cleared_env_gsutil": ("violation", "[subprocess] gsutil"),
    "::test_cleared_env_kubectl": ("violation", "[subprocess] /usr/local/bin/kubectl"),
    "::test_cleared_env_bq": ("violation", "[subprocess] bq"),
    "::test_cleared_env_curl_via_shell": ("violation", "[subprocess] sh -c curl"),
    "::test_child_python_violation_swallowed": ("violation", "[child pid"),
    "::test_child_python_violation_swallowed_cleared_env": ("violation", "[child pid"),
    "::test_child_python_clean_ok": ("passed", None),
    "::test_urlopen_swallowed": ("violation", "proxy sentinel"),
    "::test_loopback_http_and_unix_sockets": ("passed", None),
    "::test_adc_blocked_with_cleared_environment": ("passed", None),
    "::test_open_real_credential_store_swallowed": ("violation", "[credential-file]"),
    "::test_gapic_channel_swallowed": ("violation", "[client]"),
    "::test_loopback_channels_allowed": ("passed", None),
    "::test_storage_client_swallowed": ("violation", "[client]"),
    "::test_storage_client_on_local_emulator": ("passed", None),
    "::test_genai_client_swallowed": ("violation", "google.genai.Client"),
    "::test_unavailable_double": ("passed", None),
    "::test_mock_patch_unaffected": ("passed", None),
    "::test_pygithub_swallowed": ("violation", "PyGithub"),
    "::test_git_network_swallowed": ("violation", "[subprocess]"),
    "::test_gcloud_swallowed": ("violation", "[subprocess]"),
    "::test_python_m_unittest_swallowed": ("violation", "[subprocess]"),
    "::test_local_git_and_children": ("passed", None),
    "::test_live_needs_network": ("skipped", None),
}


def _make_project(d, probes, known_leaks_src=None):
    shutil.copy(os.path.join(REPO, "conftest.py"), d / "conftest.py")
    (d / "tests").mkdir(exist_ok=True)
    shutil.copy(os.path.join(TESTS, "hermetic_guard.py"), d / "tests" / "hermetic_guard.py")
    shutil.copytree(os.path.join(TESTS, "hermetic_child"), d / "tests" / "hermetic_child",
                    ignore=shutil.ignore_patterns("__pycache__"))
    if known_leaks_src is None:
        shutil.copy(os.path.join(TESTS, "hermetic_known_leaks.py"), d / "tests" / "hermetic_known_leaks.py")
    else:
        (d / "tests" / "hermetic_known_leaks.py").write_text(textwrap.dedent(known_leaks_src))
    (d / "pytest.ini").write_text("[pytest]\n")
    for name, src in probes.items():
        (d / "tests" / name).write_text(SAFETY_NET + textwrap.dedent(src))


def _run_child(d):
    # ``python -I``: no PYTHONPATH at all (neither the orchestrator's interim guard nor this repo's child shim), so the
    # probes prove the root conftest alone installs the guard. The child does not report to this process
    # (CHILD_LOG_ENV dropped): its violations are the expected outcomes, read from its junit report.
    env = hermetic_guard.child_env(drop=("PYTHONPATH", "PYTEST_ADDOPTS", "FIRESTORE_EMULATOR_HOST",
                                         "STORAGE_EMULATOR_HOST", hermetic_guard.CHILD_LOG_ENV),
                                   extra={"HOME": str(d)})
    out = subprocess.run(
        [sys.executable, "-I", "-m", "pytest", "-p", "no:cacheprovider", "--continue-on-collection-errors",
         "--import-mode=importlib", f"--junitxml={d / 'r.xml'}", str(d / "tests")],
        cwd=d, capture_output=True, text=True, timeout=600, env=env)
    res = {}
    xml = d / "r.xml"
    if xml.exists():
        for case in ET.parse(xml).getroot().iter("testcase"):
            key = f"{case.get('classname')}::{case.get('name')}"
            kinds = [c.tag for c in case if c.tag in ("failure", "error", "skipped")]
            msg = " ".join((c.get("message") or "") + (c.text or "") for c in case)
            res[key] = (kinds[0] if kinds else "passed", msg)
    return res, out


@pytest.fixture(scope="module")
def probe_run(tmp_path_factory):
    d = tmp_path_factory.mktemp("hermetic_guard")
    _make_project(d, PROBES)
    return _run_child(d)


def _find(res, suffix):
    hits = [v for k, v in res.items() if k.endswith(suffix)]
    assert len(hits) == 1, f"{suffix}: {sorted(res)}"
    return hits[0]


@pytest.mark.parametrize("suffix", sorted(EXPECT))
def test_probe_outcome(probe_run, suffix):
    res, out = probe_run
    kind, msg = _find(res, suffix)
    want, needle = EXPECT[suffix]
    log = (out.stdout + out.stderr)[-4000:]
    assert "PROBE SAFETY NET" not in msg, msg
    if want == "violation":
        assert kind in ("failure", "error"), (kind, msg[:2000], log)
        assert "Hermetic guard" in msg and needle in msg, msg[:3000]
    else:
        assert kind == want, (kind, msg[:3000], log)


def test_probe_import_time_attempt_fails_collection(probe_run):
    res, out = probe_run
    collect = [v for k, v in res.items() if "test_import_time_leak" in k]
    assert collect and all(kind == "error" for kind, _ in collect), (collect, out.stdout[-3000:])
    assert any("Hermetic guard" in m and "[dns]" in m for _, m in collect)


def test_probe_session_exit_code_and_no_safety_net(probe_run):
    _, out = probe_run
    assert out.returncode != 0
    assert "PROBE SAFETY NET" not in out.stdout + out.stderr


def test_early_bound_default_and_clear_env_in_plain_python(tmp_path):
    """Case 4c: google.auth.default bound BEFORE the guard is installed, then called with a cleared os.environ,
    in a plain interpreter (the ``python -m unittest`` / direct-run path: no conftest at all)."""
    script = SAFETY_NET + textwrap.dedent(f"""
        import os, sys
        import google.auth
        early = google.auth.default          # taken before the guard exists
        sys.path.insert(0, {TESTS!r})
        import hermetic_guard                # what every tests/test_*.py does first
        from unittest import mock
        with mock.patch.dict(os.environ, {{}}, clear=True):
            try:
                early()
                print("RESULT returned-credentials")
            except Exception as e:
                print("RESULT", type(e).__name__)
        print("NET", _NET_HITS)
    """)
    # -I: no PYTHONPATH, so the child shim does not pre-install the guard (the binding really is taken first).
    env = hermetic_guard.child_env(drop=("PYTHONPATH", hermetic_guard.CHILD_LOG_ENV), extra={"HOME": str(tmp_path)})
    out = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, timeout=120, env=env,
                         cwd=tmp_path)
    assert out.returncode == 0, out.stderr[-3000:]
    assert "RESULT DefaultCredentialsError" in out.stdout, out.stdout + out.stderr[-2000:]
    assert "NET []" in out.stdout, out.stdout


def _isolated_script(tmp_path, body, guard_dir=TESTS):
    """Run ``body`` in ``python -I`` (no PYTHONPATH, no conftest) after importing the guard from ``guard_dir``.
    ``guard_dir`` lets a reviewer replay the same script against an older guard copy (fails-before check)."""
    script = SAFETY_NET + f"import sys\nsys.path.insert(0, {guard_dir!r})\nimport hermetic_guard\n" + textwrap.dedent(body)
    env = hermetic_guard.child_env(drop=(hermetic_guard.CHILD_LOG_ENV,), extra={"HOME": str(tmp_path)})
    out = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, text=True, timeout=120, env=env,
                         cwd=tmp_path)
    assert out.returncode == 0, out.stdout[-2000:] + out.stderr[-3000:]
    return out.stdout


ADC_RELOAD_BODY = """
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError as first
    try:
        google.auth.default()
    except first:
        pass
    # What the FD-05A sandbox (tests/conftest.py::_rollback) does between test modules: drop pure-Python
    # google.auth* and re-import it, which creates a NEW DefaultCredentialsError class object.
    for name in [n for n in sys.modules if n == "google.auth" or n.startswith("google.auth.")]:
        del sys.modules[name]
    import google.auth as again
    from google.auth.exceptions import DefaultCredentialsError as second
    assert second is not first
    try:
        again.default()
        print("RESULT returned-credentials")
    except second as e:
        assert isinstance(e, hermetic_guard.HermeticGuardError)
        print("RESULT caught-by-live-class")
    except Exception as e:
        print("RESULT escaped", type(e).__mro__)
    print("SUBCLASS", issubclass(hermetic_guard.state().adc_error_cls, second))
"""


def test_adc_error_class_tracks_reimported_google_auth(tmp_path):
    """Code-RT finding 1: after google.auth is dropped and re-imported, the guard's error must still be caught by the
    LIVE ``except DefaultCredentialsError`` (it was cached once and went stale; outcome depended on file order)."""
    out = _isolated_script(tmp_path, ADC_RELOAD_BODY)
    assert "RESULT caught-by-live-class" in out and "SUBCLASS True" in out, out


UVLOOP_BODY = """
    import asyncio
    import uvloop
    outcomes = {}
    async def main():
        return 1
    def kind(loop):
        try:
            return "uvloop" if type(loop).__module__.startswith("uvloop") else "asyncio"
        finally:
            loop.close()
    def via_policy(policy):
        return kind(policy.new_event_loop())
    def via_install():
        uvloop.install()
        try:
            return kind(asyncio.get_event_loop_policy().new_event_loop())
        finally:
            asyncio.set_event_loop_policy(None)
    async def running():
        return type(asyncio.get_running_loop()).__module__.split(".")[0]
    for name, call in (("run", lambda: uvloop.run(running())), ("new_event_loop", lambda: kind(uvloop.new_event_loop())),
                       ("EventLoopPolicy", lambda: via_policy(uvloop.EventLoopPolicy())), ("install", via_install),
                       ("Loop", lambda: kind(uvloop.Loop()))):
        try:
            outcomes[name] = call()
        except hermetic_guard.HermeticClientBlocked:
            outcomes[name] = "blocked"
        except Exception as e:
            outcomes[name] = type(e).__name__
    print("OUTCOMES", sorted(outcomes.items()))
    print("RECORDED", sum(1 for r in hermetic_guard.state().records if r["kind"] == "client"))
"""


def test_uvloop_cannot_build_a_loop(tmp_path):
    """Code-RT finding 2 (P7): no libuv loop is ever built. The package entry points hand out the (audited) asyncio
    loop; constructing uvloop.Loop directly is blocked and recorded."""
    pytest.importorskip("uvloop")
    out = _isolated_script(tmp_path, UVLOOP_BODY)
    want = sorted({"run": "asyncio", "new_event_loop": "asyncio", "EventLoopPolicy": "asyncio", "install": "asyncio",
                   "Loop": "blocked"}.items())
    assert f"OUTCOMES {want}" in out and "RECORDED 1" in out, out


def test_python_child_is_guarded_without_conftest(tmp_path):
    """A plain ``python -c`` child of a test (no conftest, no ``import hermetic_guard``) runs with the guard installed
    by tests/hermetic_child/sitecustomize.py: DNS, credential-store reads and gcloud are blocked IN the child."""
    child = textwrap.dedent("""
        import os, pwd, socket, subprocess, sys
        print("GUARD", "hermetic_guard" in sys.modules)
        for name, fn in (
                ("dns", lambda: socket.getaddrinfo("example.invalid", 443)),
                ("adc", lambda: open(os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".config", "gcloud",
                                                  "application_default_credentials.json"))),
                ("gcloud", lambda: subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True))):
            try:
                fn()
                print(name, "ALLOWED")
            except Exception as e:
                # (with the orchestrator's interim guard chained after the shim, its Popen wrapper may refuse
                # gcloud first: also a guard refusal)
                guarded = type(e).__module__ == "hermetic_guard" or "testguard" in str(e)
                print(name, "blocked" if guarded else f"other:{type(e).__name__}: {e}")
    """)
    # This test checks blocking, not reporting: the child must not report into this test (it would fail it).
    env = hermetic_guard.child_env(drop=(hermetic_guard.CHILD_LOG_ENV,), extra={"HOME": str(tmp_path)})
    out = subprocess.run([sys.executable, "-c", child], capture_output=True, text=True, timeout=120, env=env,
                         cwd=tmp_path)
    assert out.returncode == 0, out.stderr[-3000:]
    lines = out.stdout.split("\n")
    assert "GUARD True" in lines and "dns blocked" in lines and "adc blocked" in lines and "gcloud blocked" in lines, \
        out.stdout + out.stderr[-2000:]


def test_child_shim_chains_to_the_next_sitecustomize(tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "sitecustomize.py").write_text("import builtins\nbuiltins.CHAINED_SITECUSTOMIZE = True\n")
    env = hermetic_guard.child_env(drop=(hermetic_guard.CHILD_LOG_ENV,))
    env["PYTHONPATH"] = os.pathsep.join([hermetic_guard.CHILD_SHIM_DIR, str(other)])
    out = subprocess.run([sys.executable, "-c", "import builtins, sys; print('hermetic_guard' in sys.modules, "
                          "getattr(builtins, 'CHAINED_SITECUSTOMIZE', False))"],
                         capture_output=True, text=True, timeout=120, env=env, cwd=tmp_path)
    assert out.stdout.split() == ["True", "True"], out.stdout + out.stderr[-2000:]


def test_child_env_never_drops_the_child_guard():
    env = hermetic_guard.child_env(drop=("PYTHONPATH",))
    assert env["PYTHONPATH"].split(os.pathsep)[0] == hermetic_guard.CHILD_SHIM_DIR
    with pytest.raises(ValueError):
        hermetic_guard.child_env(extra={"PYTHONPATH": "/elsewhere"})


def test_gcloud_config_dir_reused_by_children_and_removed_at_exit(tmp_path):
    """Code-RT finding 9: one empty gcloud config dir per pytest process tree, deleted when its creator exits."""
    env = hermetic_guard.child_env(drop=(hermetic_guard.CHILD_LOG_ENV,))
    out = subprocess.run([sys.executable, "-c", "import hermetic_guard; print(hermetic_guard.state().gcloud_config_dir)"],
                         capture_output=True, text=True, timeout=120, env=env, cwd=tmp_path)
    assert out.stdout.strip() == hermetic_guard.state().gcloud_config_dir, out.stdout + out.stderr[-2000:]
    created = _isolated_script(tmp_path, 'print("DIR", hermetic_guard.state().gcloud_config_dir)\n')
    d = created.split("DIR ", 1)[1].split()[0]
    assert d == hermetic_guard.state().gcloud_config_dir  # -I child inherits CLOUDSDK_CONFIG too: reused
    fresh = subprocess.run(
        [sys.executable, "-I", "-c", f"import os, sys; os.environ.pop('CLOUDSDK_CONFIG', None); "
                                     f"sys.path.insert(0, {TESTS!r}); import hermetic_guard; "
                                     "print(hermetic_guard.state().gcloud_config_dir)"],
        capture_output=True, text=True, timeout=120, env=env, cwd=tmp_path)
    made = fresh.stdout.strip()
    assert made and made != hermetic_guard.state().gcloud_config_dir, fresh.stdout + fresh.stderr[-2000:]
    assert not os.path.exists(made), f"{made} left behind"


def test_known_leaks_downgrade_and_stale_detection(tmp_path):
    """An exact KNOWN_LEAKS nodeid that leaks -> warning, still blocked; one that no longer leaks -> session fails."""
    probes = {
        "test_leaky.py": """
            import socket
            def test_listed_and_leaking():
                try:
                    socket.getaddrinfo("example.invalid", 443)
                except OSError as e:
                    assert "hermetic guard" in str(e)
                else:
                    raise AssertionError("not blocked")
            def test_listed_but_clean():
                pass
        """,
    }
    known = """
        KNOWN_LEAKS = {
            "tests/test_leaky.py::test_listed_and_leaking": {"fd": "FD-00", "lane": 2, "expires": "2999-01-01", "why": "probe"},
            "tests/test_leaky.py::test_listed_but_clean": {"fd": "FD-00", "lane": 2, "expires": "2999-01-01", "why": "probe"},
        }
        FIRESTORE_ALLOWANCE = {}
        PREAMBLE_EXEMPT = frozenset()
    """
    _make_project(tmp_path, probes, known_leaks_src=known)
    res, out = _run_child(tmp_path)
    assert _find(res, "::test_listed_and_leaking")[0] == "passed", out.stdout[-3000:]
    assert _find(res, "::test_listed_but_clean")[0] == "passed"
    text = out.stdout + out.stderr
    assert "known leak (blocked, not failed" in text
    assert "KNOWN_LEAKS entry is stale" in text and "test_listed_but_clean" in text
    assert out.returncode != 0


# ---------------------------------------------------------------------------------------------- meta-tests (AST)
def _test_files():
    return sorted(os.path.relpath(p, REPO).replace(os.sep, "/") for p in glob.glob(os.path.join(TESTS, "test_*.py")))


def _first_import(path):
    tree = ast.parse(open(os.path.join(REPO, path), encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant):
            continue
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        return node
    return None


def _pending_exempt(path, check, pending=None, today=None):
    """True while a PENDING_LANE_FILES entry (another lane's not-yet-merged file) exempts ``path`` from ``check``."""
    pending = hermetic_known_leaks.PENDING_LANE_FILES if pending is None else pending
    meta = pending.get(path)
    return bool(meta) and check in meta["checks"] and meta["expires"] >= (today or date.today().isoformat())


def _has_preamble(path):
    node = _first_import(path)
    return isinstance(node, ast.Import) and [a.name for a in node.names] == ["hermetic_guard"]


def _bad_spawns(path):
    tree = ast.parse(open(os.path.join(REPO, path), encoding="utf-8").read())
    return [f"{path}:{line} ({fn})" for fn, line, ok in _calls_with_sys_executable(tree)
            if not ok and not (path == "tests/test_hermetic_guard.py" and fn == "_run_child")]


def test_every_test_module_imports_the_guard_first():
    """``python -m unittest`` and ``python tests/test_x.py`` never load conftest.py: the first import installs it."""
    missing = []
    for path in _test_files():
        if path in hermetic_known_leaks.PREAMBLE_EXEMPT or _pending_exempt(path, "preamble"):
            continue
        if not _has_preamble(path):
            missing.append(path)
    assert not missing, ("Start these files with `import hermetic_guard` (first import, after the docstring): "
                         f"{missing}. Do not add them to PREAMBLE_EXEMPT / PENDING_LANE_FILES (CI refuses new "
                         "entries; tests/hermetic_known_leaks.py).")


def test_preamble_exemptions_only_shrink():
    stale = [p for p in hermetic_known_leaks.PREAMBLE_EXEMPT
             if not os.path.exists(os.path.join(REPO, p)) or _has_preamble(p)]
    assert not stale, f"delete from PREAMBLE_EXEMPT (file gone or already guarded): {stale}"


def _calls_with_sys_executable(tree):
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        uses_child_env = any(isinstance(n, ast.Attribute) and n.attr in ("child_env", "run_python_child")
                             and isinstance(n.value, ast.Name) and n.value.id == "hermetic_guard"
                             for n in ast.walk(fn))
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call) or not call.args:
                continue
            first = call.args[0]
            if isinstance(first, (ast.List, ast.Tuple)) and any(
                    isinstance(e, ast.Attribute) and e.attr == "executable" and isinstance(e.value, ast.Name)
                    and e.value.id == "sys" for e in first.elts):
                has_env = any(k.arg == "env" for k in call.keywords)
                yield fn.name, call.lineno, has_env and uses_child_env


def test_python_children_use_child_env():
    """Every ``subprocess.*([sys.executable, ...])`` in tests/ passes env built by hermetic_guard.child_env()
    (red-team F7c): children do not load conftest.py, so they must at least inherit the Layer-0 env."""
    bad = []
    for path in _test_files():
        if path in hermetic_known_leaks.PREAMBLE_EXEMPT or _pending_exempt(path, "child_env"):
            continue
        bad.extend(_bad_spawns(path))
    assert not bad, f"spawn Python children with env=hermetic_guard.child_env(...): {bad}"


def _pending_problems(pending, today, exists, compliant):
    """Hygiene of PENDING_LANE_FILES. ``exists(path)`` / ``compliant(path, check)`` are injectable for the unit test."""
    problems = []
    for path, meta in pending.items():
        if set(meta) != {"lane", "checks", "expires"}:
            problems.append(f"{path}: keys must be lane/checks/expires, got {sorted(meta)}")
            continue
        if not (path.startswith("tests/test_") and path.endswith(".py") and "/" not in path[len("tests/"):]):
            problems.append(f"{path}: only top-level tests/test_*.py files (exact paths, no globs)")
        if not (isinstance(meta["lane"], int) and meta["lane"] != 2):
            problems.append(f"{path}: lane must be the owning lane's number (not lane 2)")
        checks = tuple(meta["checks"])
        if not checks or len(set(checks)) != len(checks) or not set(checks) <= {"preamble", "child_env"}:
            problems.append(f"{path}: checks must be a non-empty subset of ('preamble', 'child_env')")
            continue
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(meta["expires"])):
            problems.append(f"{path}: expires must be YYYY-MM-DD")
        if path in hermetic_known_leaks.PREAMBLE_EXEMPT:
            problems.append(f"{path}: listed in both PREAMBLE_EXEMPT and PENDING_LANE_FILES")
        if exists(path) and all(compliant(path, c) for c in checks):
            problems.append(f"stale: {path} now passes {list(checks)}; delete its PENDING_LANE_FILES entry "
                            f"(lane {meta['lane']})")
    return problems


def test_pending_lane_files_are_exact_owned_dated_and_not_stale():
    def compliant(path, check):
        return _has_preamble(path) if check == "preamble" else not _bad_spawns(path)

    problems = _pending_problems(hermetic_known_leaks.PENDING_LANE_FILES, date.today().isoformat(),
                                 lambda p: os.path.exists(os.path.join(REPO, p)), compliant)
    assert not problems, problems


def test_pending_lane_files_mechanism():
    """Unit test of the registration rules (finding 3): absent file = waiting for its lane (ok); existing and
    non-compliant = exempt until expiry, then not; existing and compliant = stale; malformed = refused."""
    today = "2026-10-12"
    pending = {
        "tests/test_waiting.py": {"lane": 4, "checks": ("preamble",), "expires": "2026-11-15"},
        "tests/test_merged_noncompliant.py": {"lane": 4, "checks": ("preamble", "child_env"), "expires": "2026-11-15"},
        "tests/test_merged_fixed.py": {"lane": 3, "checks": ("preamble",), "expires": "2026-11-15"},
        "tests/test_expired.py": {"lane": 8, "checks": ("preamble",), "expires": "2026-10-01"},
        "tests/sub/test_glob*.py": {"lane": 2, "checks": ("everything",), "expires": "2026-11-15"},
    }
    exists = {"tests/test_merged_noncompliant.py", "tests/test_merged_fixed.py", "tests/test_expired.py"}.__contains__
    compliant = lambda p, c: p == "tests/test_merged_fixed.py"  # noqa: E731
    problems = _pending_problems(pending, today, exists, compliant)
    assert any(p.startswith("stale: tests/test_merged_fixed.py") for p in problems), problems
    assert any("tests/sub/test_glob*.py: only top-level" in p for p in problems), problems
    assert any("tests/sub/test_glob*.py: lane must be" in p for p in problems), problems
    assert any("tests/sub/test_glob*.py: checks must be" in p for p in problems), problems
    assert not any("test_waiting" in p or "test_merged_noncompliant" in p or "test_expired" in p for p in problems)
    # exemption is per path, per check, and ends at expiry; an unlisted file is never exempt
    assert _pending_exempt("tests/test_merged_noncompliant.py", "child_env", pending, today)
    assert not _pending_exempt("tests/test_waiting.py", "child_env", pending, today)
    assert not _pending_exempt("tests/test_expired.py", "preamble", pending, today)
    assert not _pending_exempt("tests/test_brand_new_file.py", "preamble", pending, today)


def test_known_leaks_are_exact_owned_and_dated():
    today = date.today().isoformat()
    for nodeid, meta in hermetic_known_leaks.KNOWN_LEAKS.items():
        assert "::" in nodeid and not re.search(r"[*?\[]", nodeid.split("::", 1)[0]), nodeid
        assert os.path.exists(os.path.join(REPO, nodeid.split("::", 1)[0])), nodeid
        assert set(meta) >= {"fd", "lane", "expires", "why"}, nodeid
        assert re.fullmatch(r"FD-\w+", meta["fd"]) and isinstance(meta["lane"], int), nodeid
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", meta["expires"]) and meta["expires"] >= today, nodeid


def test_firestore_allowance_well_formed():
    for path, n in hermetic_known_leaks.FIRESTORE_ALLOWANCE.items():
        assert path.startswith("tests/test_") and os.path.exists(os.path.join(REPO, path)), path
        assert isinstance(n, int) and n > 0, (path, n)


def _load_allowlist_guard():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "allowlist_guard_under_test", os.path.join(REPO, ".github", "scripts", "allowlist_guard.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_allowlist_guard_pending_lane_files_only_shrink():
    """CI half of finding 3: PENDING_LANE_FILES is registered once (by lane 2) and can only lose entries."""
    guard = _load_allowlist_guard()
    base = textwrap.dedent('''
        KNOWN_LEAKS = {}
        FIRESTORE_ALLOWANCE = {}
        PENDING_LANE_FILES = {
            "tests/test_a.py": {"lane": 4, "checks": ("preamble",), "expires": "2026-11-15"},
            "tests/test_b.py": {"lane": 3, "checks": ("preamble",), "expires": "2026-11-15"},
        }
        PREAMBLE_EXEMPT = frozenset({"tests/test_old.py"})
    ''')
    shrunk = base.replace('    "tests/test_b.py": {"lane": 3, "checks": ("preamble",), "expires": "2026-11-15"},\n', "")
    assert guard.leaks_problems(base, base) == []
    assert guard.leaks_problems(base, shrunk) == []
    assert guard.leaks_problems(None, base) == []  # lane 2's own PR: the file is new on main
    grown = base.replace('PENDING_LANE_FILES = {\n', 'PENDING_LANE_FILES = {\n    "tests/test_new.py": '
                                                     '{"lane": 5, "checks": ("preamble",), "expires": "2026-11-15"},\n')
    widened = base.replace('"tests/test_a.py": {"lane": 4, "checks": ("preamble",)',
                           '"tests/test_a.py": {"lane": 4, "checks": ("preamble", "child_env")')
    extended = base.replace('"tests/test_a.py": {"lane": 4, "checks": ("preamble",), "expires": "2026-11-15"}',
                            '"tests/test_a.py": {"lane": 4, "checks": ("preamble",), "expires": "2027-01-01"}')
    assert grown != base and widened != base and extended != base
    assert any("new PENDING_LANE_FILES entry tests/test_new.py" in p for p in guard.leaks_problems(base, grown))
    assert any("exempts more checks" in p for p in guard.leaks_problems(base, widened))
    assert any("expiry extended for tests/test_a.py" in p for p in guard.leaks_problems(base, extended))
    exempt = base.replace('frozenset({"tests/test_old.py"})', 'frozenset({"tests/test_old.py", "tests/test_x.py"})')
    assert any("new PREAMBLE_EXEMPT entry tests/test_x.py" in p for p in guard.leaks_problems(base, exempt))


def test_layer0_injection_keeps_the_childs_own_choices(tmp_path):
    """Do no harm to an env a test built for its child (cross-lane merge simulation: lane 5's apply.sh tests and
    lane 7's eval canary build envs without project ids): only the security settings are injected, never mock project
    ids; a test's own gcloud config dir is kept, the developer's real one never."""
    import pwd

    show = ("import json, os; print(json.dumps({k: os.environ.get(k) for k in ('PROJECT_ID', 'GOOGLE_CLOUD_PROJECT', "
            "'CLOUDSDK_CORE_PROJECT', 'CLOUDSDK_CONFIG', 'HTTPS_PROXY', 'GOOGLE_APPLICATION_CREDENTIALS')}))")
    real_gcloud = os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".config", "gcloud")
    own = str(tmp_path / "stub-gcloud-config")
    outs = {}
    for label, cfg in (("own", own), ("real", real_gcloud)):
        scratch = {"PATH": os.environ["PATH"], "CLOUDSDK_CONFIG": cfg}
        r = subprocess.run([sys.executable, "-I", "-c", show], env=scratch, capture_output=True, text=True,
                           timeout=60, cwd=tmp_path)
        assert r.returncode == 0, r.stderr[-2000:]
        import json as _json
        outs[label] = _json.loads(r.stdout.strip().splitlines()[-1])
    for label in ("own", "real"):
        assert outs[label]["PROJECT_ID"] is None and outs[label]["GOOGLE_CLOUD_PROJECT"] is None, outs
        assert outs[label]["CLOUDSDK_CORE_PROJECT"] is None, outs
        assert outs[label]["HTTPS_PROXY"] == hermetic_guard.PROXY_SENTINEL, outs
        assert outs[label]["GOOGLE_APPLICATION_CREDENTIALS"] == hermetic_guard.ADC_DISABLED_PATH, outs
    assert outs["own"]["CLOUDSDK_CONFIG"] == own, outs
    assert outs["real"]["CLOUDSDK_CONFIG"] == hermetic_guard.state().gcloud_config_dir, outs
    # child_env() (the inherited test-process env) still carries the mock ids
    assert hermetic_guard.child_env()["PROJECT_ID"]
    # GOOGLE_APPLICATION_CREDENTIALS: a non-existent path (negative probe, lane 7's eval canary) or a fake key under
    # the temp dir is kept; an existing file elsewhere (could be a real key) or no value at all is replaced.
    fake_key = tmp_path / "fake-key.json"
    fake_key.write_text("{}")
    # "existing" must be an existing file OUTSIDE the temp dir (the guard keeps any file under it as a test's fake
    # key). The checkout's pytest.ini is, except when the checkout itself lives under $TMPDIR (the release export
    # dry run builds it there); then fall back to the stdlib's os.py, which is never under the temp dir.
    tmp_root = os.path.realpath(tempfile.gettempdir()) + os.sep
    outside = [f for f in (os.path.join(REPO, "pytest.ini"), os.path.realpath(os.__file__))
               if os.path.isfile(f) and not os.path.realpath(f).startswith(tmp_root)]
    assert outside, "no existing file outside the temp dir to probe the guard with"
    cases = {"missing": os.path.expanduser("~/hermetic-probe-missing.json"), "tmp": str(fake_key),
             "existing": outside[0], "unset": None}
    for label, gac in cases.items():
        scratch = {"PATH": os.environ["PATH"]}
        if gac:
            scratch["GOOGLE_APPLICATION_CREDENTIALS"] = gac
        r = subprocess.run([sys.executable, "-I", "-c", show], env=scratch, capture_output=True, text=True,
                           timeout=60, cwd=tmp_path)
        got = _json.loads(r.stdout.strip().splitlines()[-1])["GOOGLE_APPLICATION_CREDENTIALS"]
        want = gac if label in ("missing", "tmp") else hermetic_guard.ADC_DISABLED_PATH
        assert got == want, (label, got)
    # a test's own GIT_CONFIG_* entries survive; credential helpers are disabled AFTER them (lane 3's loopback
    # smart-HTTP test passes http.extraHeader this way)
    git_env = {"PATH": os.environ["PATH"], "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
               "GIT_CONFIG_VALUE_0": "Authorization: Bearer test"}
    r = subprocess.run(["git", "config", "--get-all", "http.extraHeader"], env=git_env, capture_output=True,
                       text=True, timeout=60, cwd=tmp_path)
    assert r.stdout.strip() == "Authorization: Bearer test", r.stdout + r.stderr
    r = subprocess.run(["git", "config", "--get-all", "credential.helper"], env=git_env, capture_output=True,
                       text=True, timeout=60, cwd=tmp_path)
    assert r.stdout.split("\n")[-2:] == ["", ""] or r.stdout.strip() == "", repr(r.stdout)
    # git to a server on loopback may spawn; to any other host it may not
    subprocess.run(["git", "ls-remote", "http://127.0.0.1:9/none.git"], env=hermetic_guard.child_env(),
                   capture_output=True, timeout=60, cwd=tmp_path)
    with pytest.raises(hermetic_guard.HermeticSubprocessBlocked):
        subprocess.run(["git", "ls-remote", "https://example.com/none.git"], capture_output=True, timeout=60)
    hermetic_guard.state().records.pop()  # the refusal above is this test's expected outcome, not a leak

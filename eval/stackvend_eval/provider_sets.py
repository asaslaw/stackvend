"""Exact engine/provider sets for the scoring columns (S1-0, Step 1 RT F5, owner decision D11).

A provider set (eval/config/provider_sets.json) pins one OpenTofu version and one version per provider. A mirror
directory is accepted for a set only when its MANIFEST.sha256 (written by the owner-approved warm-up, re-verified by
every TofuRunner) lists exactly those provider versions for this os/arch. The check reads the mirror's own manifest
paths, whose layout is fixed by `tofu providers mirror` (<registry>/<namespace>/<type>/terraform-provider-<type>_
<version>_<os>_<arch>.zip); nothing is guessed.

The binary helpers verify a downloaded release zip against the upstream SHA256SUMS file the owner fetched (D12)
before anything is unpacked. The download itself is an owner-approved network step and never runs in tests.
"""
from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

from .paths import CONFIG_DIR

PROVIDER_SETS_PATH = CONFIG_DIR / "provider_sets.json"
MIRROR_MANIFEST = "MANIFEST.sha256"


class ProviderSetError(Exception):
    """A mirror, binary or set definition does not match the requested pins (fail closed, with the reason)."""


def load_sets(path: Path = PROVIDER_SETS_PATH) -> Dict[str, Dict]:
    data = json.loads(Path(path).read_text())
    if data.get("schema") != 1:
        raise ProviderSetError(f"{path}: unsupported schema {data.get('schema')!r}")
    return data["sets"]


def get_set(name: str, path: Path = PROVIDER_SETS_PATH) -> Dict:
    sets = load_sets(path)
    if name not in sets:
        raise ProviderSetError(f"unknown provider set {name!r}; known: {sorted(sets)}")
    return sets[name]


def host_os_arch() -> str:
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    return f"{platform.system().lower()}_{arch}"


def mirror_provider_versions(mirror: Path, os_arch: Optional[str] = None) -> Dict[str, List[str]]:
    """{"hashicorp/google": ["6.50.0"], ...} for every provider package listed in the mirror manifest for os_arch."""
    os_arch = os_arch or host_os_arch()
    mf = Path(mirror) / MIRROR_MANIFEST
    if not mf.is_file():
        raise ProviderSetError(f"{mf} not found (mirror not warmed, or warmed without a manifest)")
    out: Dict[str, List[str]] = {}
    for line in mf.read_text().splitlines():
        if not line.strip():
            continue
        _, _, rel = line.partition("  ")
        parts = PurePosixPath(rel).parts
        if len(parts) != 4 or not parts[3].endswith(".zip"):
            continue  # index.json / <version>.json metadata files
        _registry, namespace, ptype, fname = parts
        prefix = f"terraform-provider-{ptype}_"
        suffix = f"_{os_arch}.zip"
        if not (fname.startswith(prefix) and fname.endswith(suffix)):
            continue  # another os/arch
        version = fname[len(prefix):-len(suffix)]
        out.setdefault(f"{namespace}/{ptype}", []).append(version)
    return {k: sorted(set(v)) for k, v in sorted(out.items())}


def check_mirror_matches_set(mirror: Path, set_name: str, os_arch: Optional[str] = None,
                             path: Path = PROVIDER_SETS_PATH) -> Dict[str, str]:
    """Return the set's provider pins if the mirror holds exactly them; raise ProviderSetError with every
    difference otherwise (missing provider, other version, extra provider)."""
    pins: Dict[str, str] = dict(get_set(set_name, path)["providers"])
    have = mirror_provider_versions(mirror, os_arch)
    problems: List[str] = []
    for prov, ver in sorted(pins.items()):
        got = have.get(prov)
        if not got:
            problems.append(f"missing {prov} {ver}")
        elif got != [ver]:
            problems.append(f"{prov}: mirror has {got}, set {set_name!r} pins {ver}")
    for prov in sorted(set(have) - set(pins)):
        problems.append(f"extra provider {prov} {have[prov]} not in set {set_name!r}")
    if problems:
        raise ProviderSetError(f"mirror {mirror} does not match provider set {set_name!r}: " + "; ".join(problems))
    return pins


def required_providers_block(set_name: str, path: Path = PROVIDER_SETS_PATH) -> str:
    """versions.tf text pinning every provider of the set exactly (used by the owner-approved mirror warm-up)."""
    pins = get_set(set_name, path)["providers"]
    lines = ["terraform {", "  required_providers {"]
    for prov, ver in sorted(pins.items()):
        local = prov.split("/", 1)[1]
        lines.append(f'    {local} = {{ source = "{prov}", version = "= {ver}" }}')
    lines += ["  }", "}", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------ binaries (D12)
def release_zip_name(version: str, os_arch: Optional[str] = None) -> str:
    return f"tofu_{version}_{os_arch or host_os_arch()}.zip"


def sha256sums_entry(sums_text: str, filename: str) -> str:
    """The digest the upstream SHA256SUMS file lists for exactly `filename` (`<hex>  <name>` lines)."""
    hits = []
    for line in sums_text.splitlines():
        digest, _, name = line.strip().partition("  ")
        if name.strip().lstrip("*") == filename:
            hits.append(digest.strip().lower())
    if len(hits) != 1:
        raise ProviderSetError(f"SHA256SUMS lists {filename!r} {len(hits)} times (need exactly once)")
    if len(hits[0]) != 64 or any(c not in "0123456789abcdef" for c in hits[0]):
        raise ProviderSetError(f"SHA256SUMS entry for {filename!r} is not a sha256 hex digest")
    return hits[0]


def verify_release_zip(zip_path: Path, sums_path: Path, filename: str) -> str:
    """Verify zip_path against the owner-fetched SHA256SUMS before unpacking; return the digest."""
    want = sha256sums_entry(Path(sums_path).read_text(), filename)
    h = hashlib.sha256()
    with Path(zip_path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    got = h.hexdigest()
    if got != want:
        raise ProviderSetError(f"{zip_path}: sha256 {got} != SHA256SUMS {want} for {filename}")
    return got


def unpack_verified_tofu(zip_path: Path, sums_path: Path, version: str, into: Path,
                         os_arch: Optional[str] = None) -> Tuple[Path, str]:
    """Verify, then extract only the `tofu` member into `into` (0755). Returns (binary path, sha256 of the zip)."""
    import zipfile
    digest = verify_release_zip(zip_path, sums_path, release_zip_name(version, os_arch))
    into = Path(into)
    into.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        if "tofu" not in zf.namelist():
            raise ProviderSetError(f"{zip_path}: no 'tofu' member")
        data = zf.read("tofu")
    out = into / "tofu"
    out.write_bytes(data)
    out.chmod(0o755)
    (into / "SOURCE.json").write_text(json.dumps({"zip": Path(zip_path).name, "sha256": digest,
                                                  "sha256sums": str(sums_path), "version": version}, indent=1))
    return out, digest

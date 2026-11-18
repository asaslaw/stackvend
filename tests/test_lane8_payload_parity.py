"""Wave 1 lane 8 (FD-4AX, red-team F3/H3): built-in module payload == infra/modules on disk.

Lane 8 regenerated ONLY `database-cloudsql` in the 4 payload copies. No file drifts today: KNOWN_DRIFT is empty and
every payload file below is a plain (non-xfail) pin. Fixed drifts (FD-4AM):
- networking-vpc/main.tf (disk <- payload, FD-4AM-c): the payload was newer (`lifecycle { ignore_changes =
  [secondary_ip_range] }` on both subnetworks, the a84ce58 GKE fix); infra/modules and the Control Center copy
  apps/control-center/infra/modules/ now carry it byte-for-byte.
- compute-gke-autopilot/outputs.tf (disk <- payload, FD-4AM-c): one trailing blank line, same two disk copies.
Whole-payload regeneration would have reverted the networking-vpc GKE fix on every live workload through
service.py "Canonical Golden Module Alignment" (deleted by FD-55 W6d: a stale vendored module is now only reported,
and updated through an Upgrade IaC pull request). (workload-foundation/base IS in the payload and in parity.)
A strict xfail turns green-by-accident into a failure, so a fixed drift must be removed from KNOWN_DRIFT.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import functools
import hashlib
import os

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PAYLOAD_COPIES = [
    "shared/builtin_modules_payload.py",
    "apps/control-center/shared/builtin_modules_payload.py",
    "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
    "mcp-servers/terraform/shared/builtin_modules_payload.py",
]
KNOWN_DRIFT: set = set()  # "<module>/<file>" -> strict xfail; add an entry only together with its fix ticket


@functools.lru_cache(maxsize=None)
def _payload(rel):
    ns = {}
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        exec(compile(f.read(), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
    return ns["BUILTIN_MODULE_FILES"]


def _entries():
    payload = _payload(PAYLOAD_COPIES[0])
    params = []
    for mod_id, fdict in sorted(payload.items()):
        for fname in sorted(fdict):
            key = f"{mod_id}/{fname}"
            marks = [pytest.mark.xfail(strict=True, reason="FD-4AM known drift; fix in its own change")] if key in KNOWN_DRIFT else []
            params.append(pytest.param(mod_id, fname, id=key, marks=marks))
    return params


def test_payload_copies_byte_identical():
    digests = set()
    for rel in PAYLOAD_COPIES:
        with open(os.path.join(REPO_ROOT, rel), "rb") as f:
            digests.add(hashlib.sha256(f.read()).hexdigest())
    assert len(digests) == 1


def test_payload_covers_every_disk_module_and_nothing_else():
    payload = _payload(PAYLOAD_COPIES[0])
    disk = set()
    base = os.path.join(REPO_ROOT, "infra", "modules")
    for root, _, names in os.walk(base):
        for n in names:
            if n.endswith(".tf"):
                disk.add(os.path.relpath(os.path.join(root, n), base))
    pay = {f"{m}/{f}" for m, fd in payload.items() for f in fd}
    assert pay == disk


@pytest.mark.parametrize("mod_id,fname", _entries())
def test_payload_file_equals_disk(mod_id, fname):
    with open(os.path.join(REPO_ROOT, "infra", "modules", mod_id, fname), encoding="utf-8") as f:
        disk = f.read()
    assert _payload(PAYLOAD_COPIES[0])[mod_id][fname] == disk


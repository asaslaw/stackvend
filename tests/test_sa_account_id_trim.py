"""SA-ACCOUNT-ID-TRIM: a golden-module service account id never ends in '-'.

Live defect (2026-11-12): product id `finalrun-testplan01-a` -> workload-foundation's
`"sa-${substr(replace(var.product_id, "_", "-"), 0, 20)}"` = `sa-finalrun-testplan01-`, which fails the provider's
account_id check (`^[a-z]([-a-z0-9]*[a-z0-9])?$`) at `tofu plan`; the developer agent cannot change a golden module,
so the run was doomed. compute-gce-bastion had the same expression (18-character cut). Both now drop the trailing
dashes of the cut with the house pattern `replace(substr(...), "/-+$/", "")` (compute-gce-bastion `net_base`,
compute-gce-worker `local.short`). The developer's generated CI default for the workload SA email mirrors the module
through `developer_agent.handler.workload_sa_account_id`.

Do No Harm: for every product id whose cut does NOT end in '-', the account id is byte-identical to before (no
existing workload's service account is renamed or replaced). Only ids that failed plan before change.

Hermetic: the expressions are checked as literal HCL text plus a Python reference implementation over a table of
ids; the optional test evaluates the exact module expressions with `tofu console` (no providers, no config, nothing
downloaded) and is skipped without OpenTofu.
"""
import hermetic_guard  # noqa: F401  (first import)

import os
import re
import shutil
import subprocess
import sys
import tempfile

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

MODULE_ROOTS = ("infra/modules", "apps/control-center/infra/modules")
PAYLOAD_COPIES = (
    "shared/builtin_modules_payload.py",
    "apps/control-center/shared/builtin_modules_payload.py",
    "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
    "mcp-servers/terraform/shared/builtin_modules_payload.py",
)
# (module file, prefix, cut length, expression before the fix, expression now)
SITES = {
    "workload_sa": ("workload-foundation/base/iam.tf", "sa-", 20,
                    'sa-${substr(replace(var.product_id, "_", "-"), 0, 20)}',
                    'sa-${replace(substr(replace(var.product_id, "_", "-"), 0, 20), "/-+$/", "")}'),
    "bastion_sa": ("compute-gce-bastion/main.tf", "sa-bastion-", 18,
                   'sa-bastion-${substr(replace(var.product_id, "_", "-"), 0, 18)}',
                   'sa-bastion-${replace(substr(replace(var.product_id, "_", "-"), 0, 18), "/-+$/", "")}'),
}
# google provider: google_service_account.account_id, 6-30 characters
ACCOUNT_ID_RE = re.compile(r"^[a-z]([-a-z0-9]*[a-z0-9])$")
ACCOUNT_ID_MIN, ACCOUNT_ID_MAX = 6, 30
LIVE_DEFECT_ID = "finalrun-testplan01-a"
ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"


def _base(n):
    return "".join(ALNUM[i % len(ALNUM)] for i in range(n))


def _ids():
    """Lengths 1..40; a dash at every position; an underscore at every position; dash runs across the cut; the
    live defect id."""
    out = {LIVE_DEFECT_ID, "finalrun_testplan01_a", "a" + "-" * 30, "ab--" + "c" * 30}
    for n in range(1, 41):
        b = _base(n)
        out.add(b)
        for i in range(n):
            out.add(b[:i] + "-" + b[i + 1:])
            out.add(b[:i] + "_" + b[i + 1:])
        for cut in (18, 20):
            for run in (1, 2, 3):
                if cut - run >= 1 and n > cut:
                    out.add(b[:cut - run] + "-" * run + b[cut:])
    return sorted(out)


IDS = _ids()


def _old(prefix, n, pid):
    """Python reference of the expression before the fix: prefix + substr(replace(pid, "_", "-"), 0, n)."""
    return prefix + pid.replace("_", "-")[:n]


def _new(prefix, n, pid):
    """Python reference of the fixed expression: the HCL regex replace `/-+$/` -> "" on the cut."""
    return prefix + re.sub(r"-+$", "", pid.replace("_", "-")[:n])


def _valid(account_id):
    return bool(ACCOUNT_ID_RE.match(account_id)) and ACCOUNT_ID_MIN <= len(account_id) <= ACCOUNT_ID_MAX


def _read(rel):
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------------------------------------ literal HCL text
@pytest.mark.parametrize("root", MODULE_ROOTS)
@pytest.mark.parametrize("site", sorted(SITES))
def test_module_carries_the_trimmed_expression(root, site):
    rel, _prefix, _n, old, new = SITES[site]
    text = _read(f"{root}/{rel}")
    assert text.count(f'  account_id   = "{new}"\n') == 1
    assert old not in text


@pytest.mark.parametrize("site", sorted(SITES))
def test_payload_copies_carry_the_module_file(site):
    rel = SITES[site][0]
    mod_id, fname = rel.rsplit("/", 1)
    disk = _read(f"infra/modules/{rel}")
    for copy in PAYLOAD_COPIES:
        ns = {}
        exec(compile(_read(copy), copy, "exec"), ns)  # noqa: S102 - repo-owned data module
        assert ns["BUILTIN_MODULE_FILES"][mod_id][fname] == disk, copy


def test_no_golden_module_cuts_a_service_account_id_without_the_trim():
    """Sweep: every `substr(` in a golden module is followed by the trailing-dash trim (the 4 known sites)."""
    found = []
    for root in MODULE_ROOTS:
        base = os.path.join(REPO_ROOT, root)
        for dirpath, _dirs, names in os.walk(base):
            for name in names:
                if name.endswith(".tf"):
                    for line in _read(os.path.join(dirpath, name)).splitlines():
                        if "substr(" in line:
                            found.append(line.strip())
    assert found and all(re.search(r'replace\(substr\(.*\), "/-\+\$/", ""\)', line) for line in found), found


# ------------------------------------------------------------------------------------------------ reference table
def test_live_defect_id():
    assert _old("sa-", 20, LIVE_DEFECT_ID) == "sa-finalrun-testplan01-" and not _valid("sa-finalrun-testplan01-")
    assert _new("sa-", 20, LIVE_DEFECT_ID) == "sa-finalrun-testplan01"
    assert _valid("sa-finalrun-testplan01")


@pytest.mark.parametrize("site", sorted(SITES))
def test_do_no_harm_cut_without_trailing_dash_is_byte_identical(site):
    _rel, prefix, n, _old_expr, _new_expr = SITES[site]
    unchanged = [pid for pid in IDS if not _old(prefix, n, pid).endswith("-")]
    assert len(unchanged) > 1000
    for pid in unchanged:
        assert _new(prefix, n, pid) == _old(prefix, n, pid), pid


@pytest.mark.parametrize("site", sorted(SITES))
def test_only_ids_that_failed_plan_change(site):
    _rel, prefix, n, _old_expr, _new_expr = SITES[site]
    changed = [pid for pid in IDS if _new(prefix, n, pid) != _old(prefix, n, pid)]
    assert changed
    if site == "workload_sa":
        assert LIVE_DEFECT_ID in changed
    for pid in changed:
        assert not _valid(_old(prefix, n, pid)), pid


@pytest.mark.parametrize("site", sorted(SITES))
def test_trimmed_id_is_a_valid_account_id(site):
    """Valid whenever the trimmed stem keeps enough characters for the 6-character minimum (a product id of one or
    two characters is still too short for `sa-<id>`, as before this fix). Never a regression: an id that was valid
    stays valid, and every id still invalid was invalid before."""
    _rel, prefix, n, _old_expr, _new_expr = SITES[site]
    for pid in IDS:
        new = _new(prefix, n, pid)
        assert len(new) <= ACCOUNT_ID_MAX, pid
        if len(new) >= ACCOUNT_ID_MIN and new != prefix:   # new == prefix: an all-dash cut (not a product id)
            assert _valid(new), pid
        else:
            assert not _valid(_old(prefix, n, pid)), pid
        if _valid(_old(prefix, n, pid)):
            assert _valid(new), pid


# ------------------------------------------------------------------------------------------------ developer mirror
def test_developer_workload_sa_account_id_mirrors_the_module():
    from developer_agent.handler import workload_sa_account_id
    _rel, prefix, n, _old_expr, _new_expr = SITES["workload_sa"]
    for pid in IDS:
        assert workload_sa_account_id(pid) == _new(prefix, n, pid), pid
        if not _old(prefix, n, pid).endswith("-"):
            assert workload_sa_account_id(pid) == f"sa-{pid.replace('_', '-')[:20]}", pid


def test_generated_workflow_workload_sa_default():
    from developer_agent.handler import generate_service_workflow
    wf = generate_service_workflow("api", LIVE_DEFECT_ID, project_id="p-123456", region="us-central1")
    assert "'sa-finalrun-testplan01@p-123456.iam.gserviceaccount.com'" in wf
    assert "sa-finalrun-testplan01-@" not in wf
    # Do No Harm: a cut without a trailing dash renders exactly the previous default
    wf = generate_service_workflow("api", "orders-service-platform-x", project_id="p-123456", region="us-central1")
    assert "'sa-orders-service-platf@p-123456.iam.gserviceaccount.com'" in wf


# ------------------------------------------------------------------------------------------------ tofu (optional)
TOFU = shutil.which("tofu")


@pytest.mark.skipif(not TOFU, reason="needs OpenTofu (tofu console; no providers, nothing downloaded)")
@pytest.mark.parametrize("site", sorted(SITES))
def test_tofu_console_evaluates_the_module_expression_like_the_reference(site):
    _rel, prefix, n, old_expr, new_expr = SITES[site]
    pids = [pid for pid in IDS if 15 <= len(pid) <= 25] + [LIVE_DEFECT_ID]
    lines = []
    for pid in pids:
        for expr in (old_expr, new_expr):
            lines.append('"' + expr.replace("var.product_id", f'"{pid}"') + '"')
    tmp = tempfile.mkdtemp(prefix="sa-trim-")
    try:
        res = subprocess.run([TOFU, "console", "-no-color"], cwd=tmp, input="\n".join(lines) + "\n",
                             capture_output=True, text=True, timeout=300,
                             env=hermetic_guard.child_env(extra={"TF_IN_AUTOMATION": "1"}))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    assert res.returncode == 0, res.stderr
    got = [line.strip().strip('"') for line in res.stdout.splitlines() if line.strip()]
    assert len(got) == len(lines), res.stdout[-2000:]
    for i, pid in enumerate(pids):
        assert got[2 * i] == _old(prefix, n, pid), pid
        assert got[2 * i + 1] == _new(prefix, n, pid), pid

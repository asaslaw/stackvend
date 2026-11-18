import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

"""GHA-FIREBASE-ENV-NO-BLANK (owner 11-13; diagnosis ex02-1113 finding 3): the generated Cloud Run deploy workflow no
longer sets FIREBASE_API_KEY / FIREBASE_AUTH_DOMAIN from GitHub secrets that nothing creates.

Before, `--update-env-vars=...,FIREBASE_API_KEY=${{ secrets.FIREBASE_API_KEY }},FIREBASE_AUTH_DOMAIN=${{
secrets.FIREBASE_AUTH_DOMAIN }}` expanded to "" (vending writes only the three deploy secrets), so every CI deploy
blanked the values Terraform set (compute-cloudrun env, fed by the terraform server). Now the two names are left to
Terraform: `--update-env-vars` merges, so its values stay.

- Do No Harm: every render equals the pre-change render with exactly the removed text put back (sha256 of the
  pre-change renders pinned from main 43552421); non-Cloud-Run renders do not change at all.
- No generated workflow sets a service env var from a secret the platform does not create (checked through the
  workflow's own `env:` block, against the names vending writes, read from vending.py by AST).
"""
import ast
import hashlib
import os
import re
import sys

import pytest
import yaml

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from shared import github_identity as gi  # noqa: E402

ARCHETYPES = ("cloudrun", "event-worker", "gce-bastion", "gke-autopilot")
BRANCHES = ("main", "develop", "release/v1.2-rc")
NEW_FLAG = "--update-env-vars=PROJECT_ID=${PROJECT_ID},GCP_PROJECT_ID=${PROJECT_ID}"
REMOVED = ",FIREBASE_API_KEY=${{ secrets.FIREBASE_API_KEY }},FIREBASE_AUTH_DOMAIN=${{ secrets.FIREBASE_AUTH_DOMAIN }}"
# sha256 of the pre-change renders (main 43552421): tests/test_r1_wif_shared.py's former BASE_WORKFLOW_SHA256 cloudrun
# entries (r1wif-app renders) and tests/test_r1_wif_default_branch.py's former workflow:cloudrun pin (service "api").
PRE_CHANGE_SHA256 = {
    "cloudrun:develop": "b6aeb6624caf40723d8ed0c155ba55ce75af6b9323bae2e6b00cf2ce75ace704",
    "cloudrun:main": "2af2833e6e6398bea52469c2ebeb80965d0ac8c9557ea862e0a4cf31534cedde",
    "cloudrun:release/v1.2-rc": "d867c3b568df6fc2e3778c78ef126d73c6294c9cf52960479257b529c6246e01",
    "event-worker:develop": "8bdc78fbcfb166776a9ea143d2db3f03e13369c8e192c4b90d6bb36e3f7f1380",
    "event-worker:main": "13280b5fb4f857e962df3de0aaeda4faf3b89d9e8a154a3e170746525d0bef33",
    "event-worker:release/v1.2-rc": "8e1118cca445ac5fa7c8acfdb6a748c57f7b4dfe86bf40ae7319cc4c1c6d38ec",
    "gce-bastion:develop": "7ef7cec842f2972dc25a42f090a38a6e6c0110c0ca36ce3de6d12cd42d3e6349",
    "gce-bastion:main": "782d4869f4f560bb4a36b0f84662aafd2910fb94fec8daff8bc8a81ed84a61de",
    "gce-bastion:release/v1.2-rc": "1267f47cb7487619671493697a8c0c2445534f1a40bc1fe1294b74a90c58482f",
    "gke-autopilot:develop": "2005a06d534a57368ddd32e6a6d93b66aeb2c40ec5c7bf60dc4dacbd9547dfc0",
    "gke-autopilot:main": "745b6e3d5a308b6d02b342fddd9b796b93cc3e285c69a8fafbb8114b1f3ba79f",
    "gke-autopilot:release/v1.2-rc": "2b835e6bd892c70ea3791c51d8b18986ea59a066192f34a4e4c154fcf44cdf21",
}
PRE_CHANGE_API_CLOUDRUN_SHA256 = "4b2d59676b1315a86896ab8907b2689eaceeb3c373f2eb7d2790b1f4e2b87245"


def gsw(*a, **kw):
    from developer_agent.handler import generate_service_workflow
    return generate_service_workflow(*a, **kw)


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _render(arch, branch="main", **kw):
    return gsw("r1wif-app", "r1wif-app", "r1wif-app-1234", "123456789012", archetype=arch, region="us-central1",
               branch=branch, **kw)


def _with_removal_undone(text):
    """The pre-change text: the removed tail put back after the Cloud Run deploy flag (exactly once)."""
    assert text.count(NEW_FLAG + "\n") <= 1
    return text.replace(NEW_FLAG + "\n", NEW_FLAG + REMOVED + "\n")


# ------------------------------------------------------------------------------------------------ Do No Harm
@pytest.mark.parametrize("arch", ARCHETYPES)
@pytest.mark.parametrize("branch", BRANCHES)
def test_every_render_is_the_pre_change_render_minus_exactly_the_firebase_pair(arch, branch):
    now = _render(arch, branch)
    assert REMOVED not in now
    if arch == "cloudrun":
        assert now.count(NEW_FLAG + "\n") == 1
        assert _sha(_with_removal_undone(now)) == PRE_CHANGE_SHA256[f"{arch}:{branch}"]
    else:
        assert _sha(now) == PRE_CHANGE_SHA256[f"{arch}:{branch}"]   # untouched archetypes: byte-identical


def test_the_default_branch_pin_render_differs_only_by_the_removal():
    now = gsw("api", "r1wif-app", "r1wif-proj", "123", archetype="cloudrun", region="us-central1")
    assert _sha(_with_removal_undone(now)) == PRE_CHANGE_API_CLOUDRUN_SHA256


@pytest.mark.parametrize("kw", [{}, {"allow_unauthenticated": False}, {"memory_limit": "1Gi", "cpu_limit": "2",
                                                                        "min_instances": 1, "max_instances": 4},
                                {"branch": "prod", "branch_secrets": True}])
def test_only_the_deploy_command_line_changes(kw):
    """Structural Do No Harm for other options: the parsed workflow equals the pre-change text's parse except the one
    deploy step's `run`, and that differs by exactly the removed tail."""
    now = _render("cloudrun", **kw)
    pre = _with_removal_undone(now)
    a, b = yaml.safe_load(now), yaml.safe_load(pre)
    steps_a, steps_b = a["jobs"]["deploy"].pop("steps"), b["jobs"]["deploy"].pop("steps")
    assert a == b
    diff = [(x, y) for x, y in zip(steps_a, steps_b) if x != y]
    assert len(steps_a) == len(steps_b) and len(diff) == 1
    x, y = diff[0]
    assert x["name"] == "Build and Deploy to Cloud Run"
    assert y["run"].replace(REMOVED, "", 1) == x["run"]


# ------------------------------------------------------------------------------------------------ secrets contract
def _platform_written_secret_names():
    """The GitHub repository secrets the platform creates: vending's two `secrets_dict` literals (plain names, and
    f-string names whose constant prefix is a base name followed by the branch suffix), read from source by AST."""
    with open(os.path.join(REPO, "apps", "project-vending", "vending.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    plain, prefixed = set(), set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "secrets_dict"
                                                 for t in node.targets) and isinstance(node.value, ast.Dict)):
            for k in node.value.keys:
                if isinstance(k, ast.Constant):
                    plain.add(k.value)
                else:
                    assert isinstance(k, ast.JoinedStr) and isinstance(k.values[0], ast.Constant)
                    prefixed.add(k.values[0].value)
    return plain, prefixed


def test_vending_writes_exactly_the_shared_deploy_secret_names():
    plain, prefixed = _platform_written_secret_names()
    assert plain == set(gi.DEPLOY_SECRET_BASE_NAMES)
    assert prefixed == {f"{n}_" for n in gi.DEPLOY_SECRET_BASE_NAMES}


def _allowed(branch):
    plain, prefixed = _platform_written_secret_names()
    return plain | {p + gi.branch_secret_suffix(branch) for p in prefixed}


_EXPR = re.compile(r"\$\{\{(.*?)\}\}")
_SECRET = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")
_SHELL_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def service_env_secret_reads(workflow_text):
    """{service env key: secret names its value reads}, for every --update-env-vars / --set-env-vars pair in a run
    step; a `${NAME}` shell reference is followed into the workflow's top-level `env:` block."""
    wf = yaml.safe_load(workflow_text)
    wf_env = {k: str(v) for k, v in (wf.get("env") or {}).items()}
    out = {}
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            run = (step.get("run") or "").replace("\\\n", " ")
            for line in run.splitlines():
                for flag in ("--update-env-vars=", "--set-env-vars="):
                    if flag not in line:
                        continue
                    for pair in line.split(flag, 1)[1].strip().split(","):
                        key, _, value = pair.partition("=")
                        texts = [e for e in _EXPR.findall(value)]
                        texts += [wf_env.get(n, "") for n in _SHELL_REF.findall(_EXPR.sub("", value))]
                        out[key] = {s for t in texts for s in _SECRET.findall(t)}
    return out


@pytest.mark.parametrize("arch", ARCHETYPES)
@pytest.mark.parametrize("branch,branch_secrets", [("main", False), ("develop", False), ("prod", True),
                                                   ("release/v1.2-rc", True)])
def test_no_service_env_var_is_set_from_a_secret_the_platform_does_not_create(arch, branch, branch_secrets):
    reads = service_env_secret_reads(_render(arch, branch, branch_secrets=branch_secrets))
    if arch in ("cloudrun", "event-worker"):
        assert set(reads) == {"PROJECT_ID", "GCP_PROJECT_ID"}
        assert all(names for names in reads.values())   # the project id is read through the workflow env
    bad = {k: sorted(v - _allowed(branch)) for k, v in reads.items() if v - _allowed(branch)}
    assert bad == {}


def test_the_check_catches_the_former_firebase_pair():
    """The checker is not vacuous: on the pre-change text it reports exactly the two FIREBASE keys."""
    pre = _with_removal_undone(_render("cloudrun"))
    reads = service_env_secret_reads(pre)
    bad = {k for k, v in reads.items() if v - _allowed("main")}
    assert bad == {"FIREBASE_API_KEY", "FIREBASE_AUTH_DOMAIN"}


@pytest.mark.parametrize("arch", ARCHETYPES)
def test_no_workflow_names_a_firebase_variable(arch):
    assert "FIREBASE" not in _render(arch)

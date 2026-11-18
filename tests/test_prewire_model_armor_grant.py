"""PREWIRE-MODEL-ARMOR-GRANT (register row of the same name, FD-77): the host identities behind the three intake
surfaces (gateway, spec ingestion, Control Center) hold roles/modelarmor.user on the host project, and nobody else does.

Text checks on the platform Terraform (python-hcl2 cannot parse every platform file); nothing is applied.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import glob
import os
import re

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_DIR = os.path.join(REPO_ROOT, "infra", "platform")
GUARD_TF = os.path.join(PLATFORM_DIR, "destructive_guard.tf")
RUNNER_TF = os.path.join(PLATFORM_DIR, "tf_runner_identity.tf")
ROLE = "roles/modelarmor.user"
HEADER = 'resource "google_project_iam_member" "model_armor_users" {'


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0].rstrip() for line in text.splitlines())


def _block():
    text = _strip_comments(_read(GUARD_TF))
    start = text.index(HEADER)
    return text[start:text.index("\n}\n", start) + 2]


def _runtime_map(text, name):
    """The body of a `name = {` / `name = merge({` assignment, up to its closing brace at the same indent."""
    match = re.search(r"^( *)%s\s*=\s*(?:merge\()?\{\n" % re.escape(name), text, re.M)
    assert match, name
    end = text.index("\n" + match.group(1) + "}", match.end())
    return text[match.end():end]


def test_the_grant_is_project_level_and_only_creates_members():
    block = _block()
    assert "project = var.project_id" in block
    assert f'role    = "{ROLE}"' in block
    assert 'member  = "serviceAccount:${each.value}"' in block
    assert "condition" not in block


def test_exactly_the_developer_and_control_center_identities_are_granted():
    entries = dict(re.findall(r'"([a-z-]+)"\s*=\s*(local\.[a-z_]+)', _block()))
    assert entries == {"gateway-and-spec-ingestion": "local.developer_sa_email",
                       "control-center": "local.cc_sa_email"}


def test_the_granted_identities_are_the_ones_the_services_run_as():
    """Fails if the gateway or spec ingestion ever moves off sa-castor-developer: the grant must then follow it."""
    guard = _strip_comments(_read(GUARD_TF))
    runtime = _runtime_map(guard, "service_runtime_sa")
    assert '"product-control-center-ui"    = local.cc_sa_email' in runtime
    [runner] = [line for line in _strip_comments(_read(RUNNER_TF)).splitlines()
                if line.strip().startswith("tf_runner_service_runtime_sa")]
    for service in ("orchestrator-gateway-service", "spec-ingestion-service"):
        assert f'"{service}"' not in runtime
        assert f'"{service}"' not in runner


def test_the_role_is_granted_nowhere_else_and_no_broader_model_armor_role_is_granted():
    seen = []
    for path in glob.glob(os.path.join(PLATFORM_DIR, "*.tf")):
        for role in re.findall(r"roles/modelarmor\.[A-Za-z]+", _strip_comments(_read(path))):
            seen.append((os.path.basename(path), role))
    assert seen == [("destructive_guard.tf", ROLE)]

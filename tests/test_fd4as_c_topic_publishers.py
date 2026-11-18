import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""FD-4AS-c (register row FD-4AS-c, owner 10-20): only the spec-ingestion and Control Center SAs (plus, under row
FD-4AS-c-a (owner 10-24), the SRE remediation workflow SA) may publish to spec-intake-events; every Pub/Sub publisher grant in
core Terraform is topic-level.

1. Static (python-hcl2, no provider, no network): the exact publisher set per topic across infra/platform/*.tf and
   the platform-only workflows module, no project-level publish-capable role, the old project-level resources gone
   from disk, the Control Center copy and every embedded payload copy.
2. Code cross-check: each topic in the table is the one the publishing code names.
3. Plan-level (tofu test, MOCK providers; skipped without OpenTofu + STACKVEND_TOFU_PROVIDER_MIRROR): a fresh-install
   apply creates every grant and each grant names the identity that runs the publishing code.
"""
import ast
import json
import os
import shutil
import subprocess
import tempfile

import pytest

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
WORKFLOWS_MODULE = os.path.join(REPO, "infra", "modules", "workflows")
CC_WORKFLOWS_MODULE = os.path.join(REPO, "apps", "control-center", "infra", "modules", "workflows")
PAYLOADS = [os.path.join(REPO, p, "builtin_modules_payload.py") for p in
            ("shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "mcp-servers/terraform/shared")]
TFTEST = os.path.join(HERE, "fixtures", "fd4as_c", "fd4as_c.tftest.hcl")
TOFU = shutil.which("tofu")
MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")
# The fixture's keyed `override_resource` targets and infra/platform's `removed { lifecycle }` block need OpenTofu
# 1.10+ (1.9.0 rejects both at init / test load).
MIN_TOFU = (1, 10, 0)


def _tofu_version():
    """(major, minor, patch) of the `tofu` on PATH, or None (no tofu / unreadable). Local, no network."""
    if not TOFU:
        return None
    try:
        out = subprocess.run([TOFU, "version", "-json"], capture_output=True, text=True, timeout=30,
                             env=hermetic_guard.child_env())   # the guard's child env disables checkpoint calls
        parts = json.loads(out.stdout)["terraform_version"].split("-", 1)[0].split(".")
        return tuple(int(p) for p in parts[:3])
    except Exception:
        return None

PUBLISH_CAPABLE_ROLES = {"roles/pubsub.publisher", "roles/pubsub.editor", "roles/pubsub.admin", "roles/editor",
                         "roles/owner"}
PROJECT_IAM_TYPES = {"google_project_iam_member", "google_project_iam_binding", "google_project_iam_policy"}
TOPIC_IAM_TYPES = {"google_pubsub_topic_iam_member", "google_pubsub_topic_iam_binding", "google_pubsub_topic_iam_policy"}

# topic reference -> exact set of member expressions (as written in HCL) holding roles/pubsub.publisher on it.
EXPECTED_PUBLISHERS = {
    "${google_pubsub_topic.spec_intake_events.name}": {
        "serviceAccount:${local.spec_ingestion_sa_email}",        # apps/spec-ingestion/poller.py
        "serviceAccount:${local.cc_sa_email}",                    # apps/control-center/routes/workloads.py
        'serviceAccount:${google_service_account.agents["sa-castor-sre"].email}',  # row FD-4AS-c-a
    },
    "${google_pubsub_topic.autonomous_refactor_events.name}": {
        "serviceAccount:${local.refactor_scanner_sa_email}",      # apps/refactor-scanner/scanner.py
    },
    "${google_pubsub_topic.castor_dlq.name}": {
        'serviceAccount:${google_service_account.agents["sa-castor-architect"].email}',  # main_orchestrator.yaml
        "serviceAccount:service-${data.google_project.platform_project.number}@gcp-sa-pubsub.iam.gserviceaccount.com",
    },
    "${google_pubsub_topic.runtime_incident_events.name}": {
        "${google_logging_project_sink.sre_error_sink.writer_identity}",
    },
    # SELFUP-B (platform_upgrader.tf, count = enable_platform_upgrader): the Update StackVend button's request topic.
    "${google_pubsub_topic.platform_upgrade[0].name}": {
        "serviceAccount:${local.cc_sa_email}",                    # the Control Center's start route
    },
}
# Publisher grants that are a single member behind an on/off `count` switch (still exactly one member).
COUNT_GATED_PUBLISHERS = {"cc_platform_upgrade_publisher": "${var.enable_platform_upgrader ? 1 : 0}"}


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _tf_files():
    files = [os.path.join(PLATFORM, n) for n in sorted(os.listdir(PLATFORM)) if n.endswith(".tf")]
    files += [os.path.join(WORKFLOWS_MODULE, n) for n in sorted(os.listdir(WORKFLOWS_MODULE)) if n.endswith(".tf")]
    return files


# python-hcl2 7.3.1 cannot parse a multi-line conditional that starts a line with `?` (billing_iam.tf). Such a file is
# checked as text instead: it must not mention any Pub/Sub role, a publish-capable basic role or a project IAM resource.
PARSER_GAP_FILES = {"billing_iam.tf"}


def _parsed(path):
    try:
        return hcl2.loads(_read(path))
    except Exception:
        assert os.path.basename(path) in PARSER_GAP_FILES, f"{path}: python-hcl2 cannot parse it"
        text = _read(path)
        for needle in ("roles/pubsub", "roles/editor", "roles/owner", "google_project_iam_", "google_pubsub_"):
            assert needle not in text, f"{path}: unparsed file mentions {needle}"
        return {}


def _resources():
    """(type, name, body, file) for every resource block of the platform root and the workflows module."""
    out = []
    for path in _tf_files():
        for block in _parsed(path).get("resource", []):
            for rtype, named in block.items():
                for name, body in named.items():
                    out.append((rtype, name, body, os.path.relpath(path, REPO)))
    return out


def _locals():
    merged = {}
    for path in _tf_files():
        for block in _parsed(path).get("locals", []):
            merged.update(block)
    return merged


def _module(name):
    for block in hcl2.loads(_read(os.path.join(PLATFORM, "main.tf"))).get("module", []):
        if name in block:
            return block[name]
    raise AssertionError(f"module {name} not found")


# ---------------------------------------------------------------------------------------------------- static
def test_exact_publisher_set_per_topic():
    found = {}
    for rtype, name, body, path in _resources():
        if rtype in TOPIC_IAM_TYPES and body.get("role") == "roles/pubsub.publisher":
            assert rtype == "google_pubsub_topic_iam_member", f"{path}: {rtype}.{name} (authoritative publisher IAM)"
            assert "for_each" not in body, f"{path}: {name} must name one member"
            assert body.get("count") == COUNT_GATED_PUBLISHERS.get(name), f"{path}: {name} must name one member"
            found.setdefault(body["topic"], set()).add(body["member"])
    assert found == EXPECTED_PUBLISHERS


def test_spec_intake_publishers_are_spec_ingestion_cc_and_sre_only():
    spec = EXPECTED_PUBLISHERS["${google_pubsub_topic.spec_intake_events.name}"]
    assert len(spec) == 3
    # No other agent persona appears on the intake topic.
    for persona in ("sa-castor-architect", "sa-castor-developer", "sa-castor-gcp-devops", "sa-castor-qa",
                    "sa-castor-release", "sa-castor-finops", "sa-project-provisioner"):
        assert not any(persona in m for m in spec), persona


def test_no_project_level_publish_capable_grant():
    for rtype, name, body, path in _resources():
        if rtype in PROJECT_IAM_TYPES:
            role = body.get("role")
            roles = {role} if isinstance(role, str) else set()
            assert not (roles & PUBLISH_CAPABLE_ROLES), f"{path}: {rtype}.{name} grants {role} on the host project"


def test_publisher_identities_follow_the_runtime_maps():
    loc = _locals()
    assert loc["spec_ingestion_sa_email"] == \
        '${lookup(local.service_runtime_sa, "spec-ingestion-service", local.developer_sa_email)}'
    assert loc["refactor_scanner_sa_email"] == \
        '${lookup(local.job_runtime_sa, "github-refactor-scanner-job", local.developer_sa_email)}'
    # The services / jobs resolve their runtime SA from the same maps with the same default.
    main = _read(os.path.join(PLATFORM, "main.tf"))
    assert ('service_account = lookup(local.service_runtime_sa, each.key, '
            'google_service_account.agents["sa-castor-developer"].email)') in main
    assert ('service_account = lookup(local.job_runtime_sa, each.key, '
            'google_service_account.agents["sa-castor-developer"].email)') in main
    assert loc["developer_sa_email"] == '${google_service_account.agents["sa-castor-developer"].email}'
    # The workflow identities the DLQ / SRE grants name are the ones the workflows module runs as.
    wf = _module("workflows")
    assert wf["orchestrator_service_account_email"] == '${google_service_account.agents["sa-castor-architect"].email}'
    assert wf["sre_service_account_email"] == '${google_service_account.agents["sa-castor-sre"].email}'


def test_old_project_level_grants_gone_everywhere():
    for path in _tf_files():
        body = _read(path)
        assert 'resource "google_project_iam_member" "agent_pubsub_publishers"' not in body, path
        assert 'resource "google_project_iam_member" "orchestrator_pubsub_publisher"' not in body, path
    assert _read(os.path.join(CC_WORKFLOWS_MODULE, "main.tf")) == _read(os.path.join(WORKFLOWS_MODULE, "main.tf"))
    disk = _read(os.path.join(WORKFLOWS_MODULE, "main.tf"))
    for p in PAYLOADS:
        tree = ast.parse(_read(p))
        payload = next(ast.literal_eval(n.value) for n in tree.body
                       if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", "") == "BUILTIN_MODULE_FILES")
        assert payload["workflows"]["main.tf"] == disk, p


# ------------------------------------------------------------------------------------------- code cross-check
def test_topics_match_the_publishing_code():
    assert 'self.publisher.topic_path(self.project_id, "spec-intake-events")' in \
        _read(os.path.join(REPO, "apps", "spec-ingestion", "poller.py"))
    assert 'TOPIC = "autonomous-refactor-events"' in _read(os.path.join(REPO, "apps", "refactor-scanner", "scanner.py"))
    assert 'SPEC_INTAKE_TOPIC_NAME = "spec-intake-events"' in \
        _read(os.path.join(REPO, "apps", "log-sre-sentinel", "sentinel.py"))
    assert "call: googleapis.pubsub.v1.projects.topics.publish" in _read(os.path.join(REPO, "workflows",
                                                                                     "sre_remediation.yaml"))
    assert 'payload["dlq_topic"] = f"projects/{project_id}/topics/castor-dlq"' in \
        _read(os.path.join(REPO, "apps", "orchestrator-gateway", "main.py"))
    cc = _read(os.path.join(REPO, "apps", "control-center", "routes", "workloads.py"))
    assert cc.count("/topics/spec-intake-events\"") >= 4
    main = _read(os.path.join(PLATFORM, "main.tf"))
    for topic in ("spec-intake-events", "autonomous-refactor-events", "castor-dlq"):
        assert f'name       = "{topic}"' in main, topic


# ---------------------------------------------------------------------------------------------- tofu (optional)
@pytest.mark.skipif(not (TOFU and MIRROR and os.path.isdir(os.path.join(MIRROR, "registry.opentofu.org", "hashicorp",
                                                                          "google"))),
                    reason="needs OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
def test_tofu_fresh_install_contract_with_mock_providers():
    version = _tofu_version()
    if version is None or version < MIN_TOFU:
        pytest.skip(f"needs OpenTofu >= {'.'.join(map(str, MIN_TOFU))} (found {version}): keyed override_resource / "
                    f"removed {{ lifecycle }}")
    tmp = tempfile.mkdtemp(prefix="fd4asc-")
    sock_dir = None
    try:
        shutil.copytree(os.path.join(REPO, "infra"), os.path.join(tmp, "infra"),
                        ignore=shutil.ignore_patterns(".terraform*", "*.tfvars", "*.tfstate*"))
        shutil.copytree(os.path.join(REPO, "workflows"), os.path.join(tmp, "workflows"))
        os.makedirs(os.path.join(tmp, "mcp-servers", "kubernetes"))
        shutil.copy(os.path.join(REPO, "mcp-servers", "kubernetes", "helm-pin.json"),
                    os.path.join(tmp, "mcp-servers", "kubernetes"))
        plat = os.path.join(tmp, "infra", "platform")
        for n in os.listdir(plat):  # tofu test tears its in-memory state down; prevent_destroy would block that
            if n.endswith(".tf"):
                p = os.path.join(plat, n)
                text = _read(p)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(text.replace("prevent_destroy = true", "prevent_destroy = false"))
        os.makedirs(os.path.join(plat, "tests"))
        shutil.copy(TFTEST, os.path.join(plat, "tests"))
        rc_file = os.path.join(tmp, "cli.tfrc")
        with open(rc_file, "w", encoding="utf-8") as f:
            f.write('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                    '    include = ["registry.opentofu.org/*/*"]\n  }\n}\n' % MIRROR)
        extra = {"TF_CLI_CONFIG_FILE": rc_file, "TF_DATA_DIR": os.path.join(tmp, "tfdata"), "TF_IN_AUTOMATION": "1"}
        if len(tempfile.gettempdir()) > 60:  # macOS caps provider unix-socket paths at 104 bytes
            sock_dir = tempfile.mkdtemp(prefix="fd4asc-", dir="/private/tmp" if os.path.isdir("/private/tmp") else "/tmp")
            extra["TMPDIR"] = sock_dir
        env = hermetic_guard.child_env(extra=extra)
        init = subprocess.run([TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=plat, env=env,
                              capture_output=True, text=True, timeout=300)
        assert init.returncode == 0, init.stdout + init.stderr
        res = subprocess.run([TOFU, "test", "-no-color"], cwd=plat, env=env, capture_output=True, text=True,
                             timeout=600)
        assert res.returncode == 0, res.stdout + res.stderr
        assert "1 passed, 0 failed" in res.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if sock_dir:
            shutil.rmtree(sock_dir, ignore_errors=True)

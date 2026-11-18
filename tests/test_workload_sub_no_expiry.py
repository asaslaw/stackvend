"""WORKLOAD-SUB-NO-EXPIRY (register row, owner 10-28): the golden messaging-pubsub module's subscription never expires
from inactivity (`expiration_policy { ttl = "" }`), like SUB-NO-EXPIRY (tests/test_sub_no_expiry.py) for the
platform's own subscriptions. Pub/Sub's default deletes a subscription after 31 days without activity.

- every google_pubsub_subscription in the module (the on-disk module, the Control Center copy and all four embedded
  payloads) sets expiration_policy.ttl = "". The module's dead-letter path is a topic only (no dead-letter
  subscription), so the one subscription is the whole set.
- Do No Harm: removing exactly the addition gives the previous module bytes (PUSH-SUB-RENDER's main.tf).
- module internals only: the typed-intent catalog (what the renderer reads) is byte-identical and rendered intents carry
  no expiration policy.
- real engine (production tofu + mirror, when present): `tofu validate` and a mock-provider `tofu test` plan show
  ttl = "" for pull, push and dead-letter variants.

Hermetic: python-hcl2 parsing; the real tofu run only when the untracked production column is present.
"""
import hermetic_guard  # noqa: F401  (first import)

import functools
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

MODULE = os.path.join(REPO_ROOT, "infra", "modules", "messaging-pubsub")
CC_MODULE = os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", "messaging-pubsub")
PAYLOADS = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "mcp-servers/terraform/shared"]
# sha256 of messaging-pubsub/main.tf before this row (PUSH-SUB-RENDER, a03e40a3)
PRE_MAIN_SHA256 = "51d51c1b07764d30a8ed8ac63f728ade73ec4924591a39e5af6e0324b9451f13"
# module_catalog.json sha256 before this row (shared/iac_intent/MANIFEST at a03e40a3): the renderer's only module input
PRE_CATALOG_SHA256 = "45c6807fb811147690036ca46510495eba8ddde7237252a1a955d3513b96cc2f"


def _main_texts():
    yield "infra/modules/messaging-pubsub", Path(MODULE, "main.tf").read_text(encoding="utf-8")
    yield "apps/control-center/infra/modules/messaging-pubsub", Path(CC_MODULE, "main.tf").read_text(encoding="utf-8")
    for rel in PAYLOADS:
        ns = {}
        path = os.path.join(REPO_ROOT, rel, "builtin_modules_payload.py")
        with open(path, encoding="utf-8") as f:
            exec(compile(f.read(), path, "exec"), ns)  # noqa: S102 - repo-owned data module
        yield rel, ns["BUILTIN_MODULE_FILES"]["messaging-pubsub"]["main.tf"]


def _subscriptions(text):
    for res in hcl2.loads(text).get("resource", []):
        for name, body in (res.get("google_pubsub_subscription") or {}).items():
            yield name, body


def test_every_module_subscription_never_expires_in_every_copy():
    for where, text in _main_texts():
        subs = dict(_subscriptions(text))
        assert set(subs) == {"subscription"}, where   # the dead-letter path is a topic, not a subscription
        for name, body in subs.items():
            pol = body.get("expiration_policy")
            assert pol, f"{where} {name}: no expiration_policy (Pub/Sub would delete it after 31 idle days)"
            assert not isinstance(pol, list) or len(pol) == 1, (where, name)
            pol = pol[0] if isinstance(pol, list) else pol
            assert pol == {"ttl": ""}, f"{where} {name}: ttl must be \"\" (never expire), got {pol!r}"


def test_dead_letter_topic_has_no_subscription_of_its_own():
    text = Path(MODULE, "main.tf").read_text(encoding="utf-8")
    topics = {n for res in hcl2.loads(text).get("resource", []) for n in (res.get("google_pubsub_topic") or {})}
    assert topics == {"topic", "dead_letter"}
    for _name, body in _subscriptions(text):
        assert body["topic"] == "${google_pubsub_topic.topic.name}"


def test_negative_module_without_the_addition_is_the_previous_module():
    """Do No Harm: removing exactly the addition gives the pre-row bytes; nothing else in the module changed."""
    from sub_no_expiry_module_delta import pre_sub_no_expiry
    text = Path(MODULE, "main.tf").read_text(encoding="utf-8")
    before = pre_sub_no_expiry("infra/modules/messaging-pubsub/main.tf", text)
    assert "expiration_policy" not in before
    assert hashlib.sha256(before.encode("utf-8")).hexdigest() == PRE_MAIN_SHA256
    # other files are returned unchanged
    other = Path(MODULE, "variables.tf").read_text(encoding="utf-8")
    assert pre_sub_no_expiry("infra/modules/messaging-pubsub/variables.tf", other) == other


def test_module_internals_only_catalog_and_render_are_unchanged():
    from shared import iac_intent as ii
    for rel in ("shared", "apps/orchestrator-gateway/shared"):
        cat = Path(REPO_ROOT, rel, "iac_intent", "module_catalog.json").read_bytes()
        man = json.loads(Path(REPO_ROOT, rel, "iac_intent", "MANIFEST").read_text(encoding="utf-8"))
        assert man["module_catalog"]["sha256"] == hashlib.sha256(cat).hexdigest(), rel
        # FD-4BH (golden VPC connector) later added exactly one platform_only entry; without it the catalog is the
        # pre-row bytes (scripts/build_iac_catalog.py serialization), so this row changed no catalog entry
        doc = json.loads(cat)
        assert doc["platform_only"].pop("networking-vpc-connector") == "lane 11 (network)", rel
        # REMOVE-DEVELOPER-MODE later removed the `cloud_build` entry (the module is gone); restored for this comparison
        assert "cloud_build" not in doc["platform_only"], rel
        doc["platform_only"]["cloud_build"] = "CI is platform"
        # SECRET-INITIAL-VERSION (owner 11-10) later added exactly security-secret's generate_initial_version (its
        # variable and count drivers) and the module's random_password type; without them the catalog is the same
        sec = doc["modules"]["security-secret"]
        assert sec["variables"].pop("generate_initial_version")["class"] == "TOPOLOGY", rel
        assert sec["count_drivers"].pop("generate_initial_version") == [
            "google_secret_manager_secret_version.generated.count", "random_password.initial.count"], rel
        sec["declares_types"].remove("random_password")
        # SCHEDULING-CRON-AUDIENCE (owner 11-14) later added exactly scheduling-cron's optional `audience` variable
        assert doc["modules"]["scheduling-cron"]["variables"].pop("audience")["class"] == "AI", rel
        # RT14-36 (owner 11-14) later changed exactly database-spanner: `config` became HELD (module-derived
        # regional-<region>, default "") and a FACT `region` input was added; restored for this comparison
        sp = doc["modules"]["database-spanner"]["variables"]
        assert sp.pop("region")["fact"] == "region", rel
        assert sp["config"]["class"] == "HELD" and sp["config"]["row"] == "RT14-36", rel
        sp["config"] = {"class": "AI", "count_driver": False, "default": "regional-us-central1",
                        "description": "The name of the Spanner instance configuration defining regional or "
                                       "multi-region topology.",
                        "has_default": True, "hcl_type": "string", "sensitive": False}
        pre = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"
        assert hashlib.sha256(pre.encode("utf-8")).hexdigest() == PRE_CATALOG_SHA256, rel
    art = ii.load_artifacts()
    assert "expiration_policy" not in json.dumps(art.module("messaging-pubsub"))
    import push_sub_render_cases as cases
    for name, d, ctxargs in cases.NO_PUSH_CASES:
        g = ii.validate_intent(d, art, cases.ctx_of(ii, ctxargs))
        if g.ok:
            assert "expiration_policy" not in json.dumps(ii.render_intent(g.validated).files), name


# ------------------------------------------------------------------------------------------------ real engine
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")


@functools.lru_cache(maxsize=1)
def _skip_reason():
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        return "production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present"
    return None


@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if _skip_reason():
        pytest.skip(_skip_reason())
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("sub-no-expiry-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


SA = "wsa@expiry-test.iam.gserviceaccount.com"
URI = "https://expiry-abc-uc.a.run.app"
NEVER = 'length(google_pubsub_subscription.subscription[0].expiration_policy) == 1 && ' \
        'google_pubsub_subscription.subscription[0].expiration_policy[0].ttl == ""'
MODULE_TEST = f'''mock_provider "google" {{}}

variables {{
  project_id        = "expiry-test"
  workload_sa_email = "{SA}"
}}

run "pull_never_expires" {{
  command = plan
  assert {{
    condition     = {NEVER}
    error_message = "the pull subscription must never expire"
  }}
}}

run "push_never_expires" {{
  command = plan
  variables {{
    push = {{
      endpoint              = "{URI}/x"
      service_account_email = "{SA}"
      audience              = "{URI}"
    }}
  }}
  assert {{
    condition     = {NEVER} && length(google_pubsub_subscription.subscription[0].push_config) == 1
    error_message = "the push subscription must never expire"
  }}
}}

run "dead_letter_never_expires" {{
  command = plan
  variables {{
    enable_dead_letter = true
  }}
  assert {{
    condition     = {NEVER} && length(google_pubsub_subscription.subscription[0].dead_letter_policy) == 1
    error_message = "the dead-letter variant must never expire"
  }}
}}
'''


def test_module_plans_never_expire_with_the_production_engine(runner, tmp_path):
    wd = tmp_path / "messaging-pubsub"
    wd.mkdir()
    for name in ("main.tf", "variables.tf", "outputs.tf"):
        (wd / name).write_text(Path(MODULE, name).read_text(encoding="utf-8"), encoding="utf-8")
    (wd / "tests").mkdir()
    (wd / "tests" / "expiry.tftest.hcl").write_text(MODULE_TEST, encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["test", "-test-directory=tests", "-filter=tests/expiry.tftest.hcl", "-no-color"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "3 passed, 0 failed" in out, out[-4000:]

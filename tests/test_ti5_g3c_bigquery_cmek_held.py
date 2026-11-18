"""TI-5-G3d (owner 10-25; Opus re-check 10-24): until TI-5-G3c lets security-kms grant BigQuery's
encryption account, the typed intent refuses `kms_key_name` on `analytics-bigquery` (exact MODULE_ARG_CLASS_BY_MODULE
entry, class HELD, typed code IAC.ARGUMENT_HELD), so a CMEK BigQuery dataset is never planned without its key grant.
The prompt does not offer the argument (HELD is not listed). Pure."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import iac_intent as ii  # noqa: E402

ART = ii.load_artifacts()
KMS = {"module": "security-kms", "name": "k", "args": {"service_agent_services": ["storage.googleapis.com"]}}
REF = {"$ref": {"kind": "module_output", "module": "k", "output": "crypto_key_name"}}


def gate(args):
    doc = {"schema": "iac_intent/v1", "resources": [], "outputs": [],
           "modules": [KMS, {"module": "analytics-bigquery", "name": "analytics", "args": args}]}
    return ii.validate_intent(doc, ART, ii.IntentContext())


def test_cmek_bigquery_dataset_is_a_typed_held_refusal():
    res = gate({"dataset_id": "events", "kms_key_name": REF})
    assert not res.ok
    held = [d for d in res.diagnostics if d.code == "IAC.ARGUMENT_HELD"]
    assert len(held) == 1 and "TI-5-G3c" in held[0].message and "analytics-bigquery.kms_key_name" in held[0].message
    assert held[0].file == "infra/workload/iac_intent.json" or held[0].file   # anchored to the intent entry


def test_bigquery_dataset_without_cmek_is_unchanged():
    assert gate({"dataset_id": "events"}).ok


def test_held_is_exact_to_the_module_and_the_catalog_and_prompt_follow():
    assert ii.MODULE_ARG_CLASS_BY_MODULE[("analytics-bigquery", "kms_key_name")]["class"] == "HELD"
    assert ART.module("analytics-bigquery")["variables"]["kms_key_name"]["class"] == "HELD"
    # every other CMEK module keeps the TI-5-G3 crypto_key_name reference
    for mid in ART.ai_modules:
        v = (ART.module(mid) or {}).get("variables", {}).get("kms_key_name")
        if v and mid != "analytics-bigquery":
            assert v["class"] == "REF_ONLY" and v["refs"] == ["module_output:security-kms.crypto_key_name"], mid
    from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt
    line = next(x for x in build_iac_intent_worker_prompt(ART).splitlines() if x.startswith("- analytics-bigquery:"))
    assert "kms_key_name" not in line and "dataset_id" in line

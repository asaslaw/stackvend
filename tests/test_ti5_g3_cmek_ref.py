"""TI-5-G3 (register, owner 10-24): a CMEK input in the typed intent references the security-kms module's
`crypto_key_name` output, which waits for the key's grants (infra/modules/security-kms/outputs.tf depends_on), never
`crypto_key_id` (which waits for the key only). So an encrypted bucket / topic / secret is never created before the
key's in-module grants. Pure (artifacts + render + python-hcl2), no network."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys

import hcl2

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import iac_intent as ii  # noqa: E402

ART = ii.load_artifacts()
CTX = ii.IntentContext()
KMS = {"module": "security-kms", "name": "k", "args": {"key_name": "docs-cmek", "keyring_name": "docs",
                                                        "service_agent_services": ["run.googleapis.com"]}}


def OUT(output):
    return {"$ref": {"kind": "module_output", "module": "k", "output": output}}


def doc(modules=(), resources=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources), "outputs": []}


def bucket_module(output):
    return {"module": "storage-bucket", "name": "docs", "args": {"bucket_name_suffix": "docs",
                                                                 "kms_key_name": OUT(output)}}


def test_every_cmek_reference_in_the_artifacts_is_crypto_key_name():
    module_refs = {(mid, name): tuple(v.get("refs") or ())
                   for mid in ART.ai_modules for name, v in ((ART.module(mid) or {}).get("variables") or {}).items()
                   if name == "kms_key_name" and v.get("class") != "HELD"}   # TI-5-G3d: BigQuery CMEK held
    assert module_refs and set(module_refs.values()) == {("module_output:security-kms.crypto_key_name",)}
    resource_refs = [shape for spec in ART.allowed_types.values()
                     for shapes in (spec.get("target_ref_only") or {}).values() for shape in shapes
                     if list(shape[:2]) == ["module_output", "security-kms"]]
    assert resource_refs and {tuple(s) for s in resource_refs} == {("module_output", "security-kms", "crypto_key_name")}


def test_gate_accepts_crypto_key_name_and_refuses_crypto_key_id():
    ok = ii.validate_intent(doc([KMS, bucket_module("crypto_key_name")]), ART, CTX)
    assert ok.ok, [(d.code, d.message) for d in ok.diagnostics]
    bad = ii.validate_intent(doc([KMS, bucket_module("crypto_key_id")]), ART, CTX)
    assert not bad.ok and "IAC.REF_KIND_NOT_ALLOWED" in {d.code for d in bad.diagnostics}
    for output, accepted in (("crypto_key_name", True), ("crypto_key_id", False)):   # a raw bucket resource too
        res = {"type": "google_storage_bucket", "name": "raw",
               "arguments": {"name": "raw-docs", "location": {"$ref": {"kind": "fact", "fact": "region"}},
                             "encryption": {"default_kms_key_name": OUT(output)}}}
        got = ii.validate_intent(doc([KMS], [res]), ART, CTX)
        assert got.ok is accepted, output
        if not accepted:   # a resource's target_ref_only path refuses with its own code (Opus review 10-24, Low)
            assert "IAC.TARGET_REF_REQUIRED" in {d.code for d in got.diagnostics}


def test_rendered_bucket_reads_crypto_key_name_which_depends_on_the_key_grants():
    gate = ii.validate_intent(doc([KMS, bucket_module("crypto_key_name")]), ART, CTX)
    body = json.loads(ii.render_intent(gate.validated).files[ii.RENDER_PATH])["module"]["docs"]
    assert body["kms_key_name"] == "${module.k.crypto_key_name}"
    # Terraform orders a consumer of a module output after that output's depends_on: the grants of the key.
    with open(os.path.join(REPO_ROOT, "infra", "modules", "security-kms", "outputs.tf"), encoding="utf-8") as fh:
        outputs = {n: b for blk in hcl2.load(fh)["output"] for n, b in blk.items()}
    deps = " ".join(str(d) for d in outputs["crypto_key_name"]["depends_on"])
    assert "google_kms_crypto_key_iam_member.service_agents" in deps
    assert "google_kms_crypto_key_iam_member.encrypter_decrypter" in deps
    assert "depends_on" not in outputs["crypto_key_id"]   # why crypto_key_id is no longer accepted


def test_iac_prompt_names_crypto_key_name_never_crypto_key_id():
    from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt
    prompt = build_iac_intent_worker_prompt(ART)
    assert "kms_key_name (Ref: module_output:security-kms.crypto_key_name" in prompt
    assert "security-kms.crypto_key_id" not in prompt and "security-kms.crypto_key_name" in prompt

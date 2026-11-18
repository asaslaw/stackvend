"""SUB-NO-EXPIRY (owner 10-27): every platform Pub/Sub subscription sets expiration_policy { ttl = "" }.
Pub/Sub's default deletes a subscription after 31 days without activity; the quiet billing-alerts subscription
expired on a dev install and budget alerts stopped reaching the Control Center."""
import hermetic_guard  # noqa: F401
import os

import hcl2

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _subscriptions():
    with open(os.path.join(REPO, "infra", "platform", "main.tf"), encoding="utf-8") as fh:
        doc = hcl2.load(fh)
    for res in doc.get("resource", []):
        for name, body in (res.get("google_pubsub_subscription") or {}).items():
            yield name, body


def test_every_platform_subscription_never_expires():
    subs = dict(_subscriptions())
    assert {"castor_dlq_sub", "spec_intake_push", "sre_incident_push", "billing_alerts_push"} <= set(subs)
    for name, body in subs.items():
        pol = body.get("expiration_policy")
        assert pol, f"{name}: no expiration_policy (Pub/Sub would delete it after 31 idle days)"
        pol = pol[0] if isinstance(pol, list) else pol
        assert pol.get("ttl") == "", f"{name}: ttl must be \"\" (never expire), got {pol.get('ttl')!r}"

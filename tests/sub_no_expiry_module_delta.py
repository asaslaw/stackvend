"""WORKLOAD-SUB-NO-EXPIRY (owner 10-28): the exact text the golden messaging-pubsub module gained (one block inserted in
its google_pubsub_subscription, right after message_retention_duration). Tests that pin older bytes of main.tf remove
exactly this (once) first; it was added after PUSH-SUB-RENDER, so strip it before push_sub_module_delta.pre_push_sub."""

ADDED_MAIN = (
    "\n"
    "  # StackVend WORKLOAD-SUB-NO-EXPIRY (owner 10-28): never expire from inactivity. Pub/Sub's default deletes a\n"
    "  # subscription after 31 days without activity (as SUB-NO-EXPIRY fixed for the platform's own subscriptions).\n"
    "  expiration_policy {\n"
    '    ttl = ""\n'
    "  }\n"
)
ANCHOR = "  message_retention_duration = var.message_retention_duration\n"


def pre_sub_no_expiry(rel: str, text: str) -> str:
    """`text` without the WORKLOAD-SUB-NO-EXPIRY addition when `rel` is messaging-pubsub/main.tf (asserted present
    exactly once, right after the subscription's message_retention_duration); any other file is unchanged."""
    if not rel.endswith("messaging-pubsub/main.tf"):
        return text
    assert text.count(ADDED_MAIN) == 1 and text.count(ANCHOR + ADDED_MAIN) == 1, rel
    return text.replace(ANCHOR + ADDED_MAIN, ANCHOR, 1)

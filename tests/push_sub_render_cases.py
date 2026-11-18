"""PUSH-SUB-RENDER (owner 10-28): typed intents WITHOUT the new messaging-pubsub `push` argument, with the sha256 of
their gate-clean render (custom.tf.json + intent_facts.tf.json) as computed by the code before PUSH-SUB-RENDER, or the
sorted gate codes when the gate refuses them. tests/test_push_sub_render.py checks today's code gives exactly these
(render byte-identity / unchanged findings for intents without push). Data only: no import of the code under test."""


def _ref(**kw):
    return {"$ref": dict(kw)}


FACT_WSA = _ref(kind="fact", fact="workload_sa_email")
SVC_URI = _ref(kind="service", service="shop", output="service_uri")
EVENTS_MODULE = {"module": "messaging-pubsub", "name": "events", "realizes": "events",
                 "args": {"topic_name_suffix": "events", "ack_deadline_seconds": 30, "enable_dead_letter": True}}
RAW_PUSH_SUB = {"type": "google_pubsub_subscription", "name": "events_push",
                "arguments": {"name": "events-push",
                              "topic": _ref(kind="module_output", module="events", output="topic_id"),
                              "push_config": {"push_endpoint": {"$fn": "format", "$args": ["%s/api/v1/tasks/process",
                                                                                           SVC_URI]},
                                              "oidc_token": {"service_account_email": FACT_WSA}}}}
PUSHER = {"type": "google_service_account", "name": "pusher", "arguments": {"account_id": "pusher"}}


def doc(modules=(), resources=(), outputs=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources),
            "outputs": list(outputs)}


# (name, intent document, context args)
CTX_SHOP = {"services": {"shop": ("module.compute", "compute-cloudrun")},
            "topology_resources": {"events": "google_pubsub_topic"},
            "service_reads": (("shop", "events"),)}
NO_PUSH_CASES = [
    ("module_only", doc([EVENTS_MODULE]), CTX_SHOP),
    ("module_and_raw_push_subscription", doc([EVENTS_MODULE], [RAW_PUSH_SUB]), CTX_SHOP),
    ("subscription_output_and_depends_on",
     doc([EVENTS_MODULE], [dict(PUSHER, depends_on=[{"module": "events"}])],
         [{"name": "events_sub", "value": _ref(kind="module_output", module="events", output="subscription_name")}]),
     CTX_SHOP),
    ("raw_push_with_own_identity",
     doc([EVENTS_MODULE], [PUSHER, dict(RAW_PUSH_SUB, arguments=dict(RAW_PUSH_SUB["arguments"], push_config={
         "push_endpoint": SVC_URI, "oidc_token": {"service_account_email": _ref(
             kind="resource_attr", type="google_service_account", name="pusher", attr="email")}}))]),
     CTX_SHOP),
    ("refused_unknown_module_argument",
     doc([dict(EVENTS_MODULE, args=dict(EVENTS_MODULE["args"], push_endpoint="https://example.com/x"))]), CTX_SHOP),
]


# computed with the code of main 94c13a4b (before PUSH-SUB-RENDER): sha256 of json.dumps(render.files, sort_keys=True)
# for a gate-clean case, the sorted gate codes otherwise
PRE_CHANGE = {
    "module_only": "09796f72b2b8e6689eb36f052288fcdbc05945e7c81c6ba4cf59ad77f67b7db0",
    "module_and_raw_push_subscription": "b749d6580a298c6cc72a97ffe93f63909472de7c8cccf8a43589da65e6f36604",
    "subscription_output_and_depends_on": "092a7627f7dad4ac577ddbb88aa2e4e40ff77985d2a8b47fd902044ab1aad056",
    "raw_push_with_own_identity": "f81528a3955a3eecea9258759842c1d931664c42e6d8a63a19261dd9a01550cf",
    "refused_unknown_module_argument": ["IAC.UNKNOWN_ARGUMENT"],
}


def ctx_of(ii, args):
    """The IntentContext of a case (`ii` is the shared.iac_intent module under test)."""
    return ii.IntentContext(**args)

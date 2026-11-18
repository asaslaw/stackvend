"""PUSH-SUB-RENDER (owner 10-28): the exact text the golden messaging-pubsub module gained (one block inserted at the end
of its google_pubsub_subscription, one variable appended to variables.tf). Tests that pin older bytes of those files
remove exactly this (each once) first."""

ADDED_MAIN = (
    "\n"
    "  # StackVend PUSH-SUB-RENDER (owner 10-28): with `push` set (platform-rendered from the typed intent, never an AI\n"
    "  # string) the subscription pushes to the workload's own Cloud Run service with an OIDC token; null = pull, "
    "unchanged.\n"
    '  dynamic "push_config" {\n'
    "    for_each = var.push == null ? [] : [var.push]\n"
    "    content {\n"
    "      push_endpoint = push_config.value.endpoint\n"
    "      oidc_token {\n"
    "        service_account_email = push_config.value.service_account_email\n"
    "        audience              = push_config.value.audience\n"
    "      }\n"
    "    }\n"
    "  }\n"
)
ADDED_VARIABLES = (
    "\n"
    'variable "push" {\n'
    '  description = "PUSH-SUB-RENDER: push delivery for the subscription, rendered by the platform from the typed '
    "intent: the endpoint (the workload's own Cloud Run service URL plus a path), the service account that signs the "
    'OIDC token and the token audience (the service URL). null = pull subscription."\n'
    "  type = object({\n"
    "    endpoint              = string\n"
    "    service_account_email = string\n"
    "    audience              = string\n"
    "  })\n"
    "  default = null\n"
    "\n"
    "  validation {\n"
    '    condition     = var.push == null ? true : (startswith(var.push.endpoint, "https:") && '
    'var.push.service_account_email != "" && !startswith(var.push.service_account_email, "serviceAccount:"))\n'
    '    error_message = "push.endpoint must be an https URL and push.service_account_email a bare service account '
    'email."\n'
    "  }\n"
    "}\n"
)
# sha256 of the files before PUSH-SUB-RENDER (main 94c13a4b)
PRE_SHA256 = {"main.tf": "3bd4d7ae3d7ba8fa03a96f711f8781317d5782d01b831063d909ed6704ea5de9",
              "variables.tf": "98c4f7f8da3a2e85dabe72c0c2aad95ab55229f113ff5bef0d606b527a5dac1d"}


def pre_push_sub(rel: str, text: str) -> str:
    """`text` without the PUSH-SUB-RENDER addition when `rel` is messaging-pubsub/main.tf (inserted once, right before
    the subscription's closing brace) or variables.tf (appended once at the end); any other file is unchanged."""
    if rel.endswith("messaging-pubsub/main.tf"):
        assert text.count(ADDED_MAIN) == 1, rel
        return text.replace(ADDED_MAIN, "", 1)
    if rel.endswith("messaging-pubsub/variables.tf"):
        assert text.count(ADDED_VARIABLES) == 1 and text.endswith(ADDED_VARIABLES), rel
        return text[:-len(ADDED_VARIABLES)]
    return text

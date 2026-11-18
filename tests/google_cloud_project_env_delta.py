"""CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV (owner 11-10): the exact text the golden compute-cloudrun and compute-event-worker
modules gained (a GOOGLE_CLOUD_PROJECT env entry right after PROJECT_ID). Tests that pin older bytes of those files
remove exactly this (each once) first."""

ADDED_CLOUDRUN = (
    '      # StackVend CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV (owner 11-10): Cloud Run sets no project variable, and Google client\n'
    '      # libraries and most generated code read GOOGLE_CLOUD_PROJECT. Emitted only when var.env_vars has no such key, so\n'
    '      # a caller\'s own value is the single entry (Cloud Run env names must be unique).\n'
    '      dynamic "env" {\n'
    '        for_each = contains(keys(var.env_vars), "GOOGLE_CLOUD_PROJECT") ? [] : [var.project_id]\n'
    '        content {\n'
    '          name  = "GOOGLE_CLOUD_PROJECT"\n'
    '          value = env.value\n'
    '        }\n'
    '      }\n'
)
ADDED_EVENT_WORKER = (
    '        # StackVend CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV (owner 11-10): the project variable Google client libraries and\n'
    '        # most generated code read (Cloud Run sets none). This module takes no caller env, so the name is never doubled.\n'
    '        env {\n'
    '          name  = "GOOGLE_CLOUD_PROJECT"\n'
    '          value = var.project_id\n'
    '        }\n'
)


def pre_google_cloud_project_env(rel: str, text: str) -> str:
    """`text` without the CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV addition when `rel` is compute-cloudrun/main.tf or
    compute-event-worker/main.tf (asserted present exactly once); any other file is returned unchanged."""
    if rel.endswith("compute-cloudrun/main.tf"):
        added = ADDED_CLOUDRUN
    elif rel.endswith("compute-event-worker/main.tf"):
        added = ADDED_EVENT_WORKER
    else:
        return text
    assert text.count(added) == 1, rel
    return text.replace(added, "")

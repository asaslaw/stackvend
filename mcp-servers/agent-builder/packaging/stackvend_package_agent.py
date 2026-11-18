"""
StackVend agent packaging script, version 1 (lane 14 PR-9, owner Q11).

Fixed platform code, shipped from the platform repo; never generated. The agent-builder server copies this file
next to the validated scaffold into the source tarball of a Cloud Build that runs INSIDE THE WORKLOAD'S OWN PROJECT,
as the workload's build service account. Only here is the generated agent imported (and pickled by the Vertex AI SDK);
never in the platform.

Inputs (environment, set by the server as literal Cloud Build step env values):
  SV_PROJECT, SV_LOCATION, SV_STAGING_BUCKET (gs://...), SV_RESULT_URI (gs://.../result.json),
  SV_DISPLAY_NAME, SV_REQUIREMENTS_JSON (JSON list, already allow-listed by the server).
Output: SV_RESULT_URI = {"resource_name": "...", "packager_version": "1"}; any failure exits non-zero (the build fails,
the server reports DEPLOY_FAILED:BUILD).
"""

import json
import os
import sys

PACKAGER_VERSION = "1"
LOCAL_PACKAGES = ["agent.py", "app.py", "tools"]


def main() -> int:
    project = os.environ["SV_PROJECT"]
    location = os.environ["SV_LOCATION"]
    staging_bucket = os.environ["SV_STAGING_BUCKET"]
    result_uri = os.environ["SV_RESULT_URI"]
    display_name = os.environ["SV_DISPLAY_NAME"]
    requirements = json.loads(os.environ["SV_REQUIREMENTS_JSON"])
    if not isinstance(requirements, list) or not all(isinstance(r, str) for r in requirements):
        print("SV_REQUIREMENTS_JSON must be a JSON list of strings", file=sys.stderr)
        return 2
    if not result_uri.startswith("gs://"):
        print("SV_RESULT_URI must be a gs:// URI", file=sys.stderr)
        return 2

    sys.path.insert(0, os.getcwd())
    import vertexai
    from vertexai import agent_engines

    import agent as scaffold_agent

    vertexai.init(project=project, location=location, staging_bucket=staging_bucket)
    app = agent_engines.AdkApp(agent=scaffold_agent.build_root_agent())
    remote = agent_engines.create(
        agent_engine=app,
        requirements=requirements,
        extra_packages=LOCAL_PACKAGES,
        display_name=display_name,
    )

    from google.cloud import storage

    bucket_name, _, object_name = result_uri[len("gs://"):].partition("/")
    storage.Client(project=project).bucket(bucket_name).blob(object_name).upload_from_string(
        json.dumps({"resource_name": remote.resource_name, "packager_version": PACKAGER_VERSION}),
        content_type="application/json",
    )
    print(f"StackVend packager v{PACKAGER_VERSION}: created {remote.resource_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

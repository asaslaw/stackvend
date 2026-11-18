"""
Agent Engine Deployment Automation Script
"""

import os
import sys

def deploy_agent(project_id: str, location: str, agent_name: str, staging_bucket: str):
    """
    Automates deployment to Agent Engine using the Google Cloud SDK.
    """
    try:
        import vertexai
        from vertexai.agent_engines import create
        from app import ADKApplication

        vertexai.init(project=project_id, location=location, staging_bucket=staging_bucket)
        app = ADKApplication(agent_name=agent_name)

        agent_engine = create(
            app,
            requirements=[
                "google-adk>=0.1.0",
                "google-cloud-firestore>=2.15.0",
                "pydantic>=2.0.0",
            ],
            display_name=agent_name,
        )
        return {
            "status": "DEPLOYED",
            "resource_name": getattr(agent_engine, "resource_name", f"projects/{project_id}/locations/{location}/reasoningEngines/{agent_name}"),
        }
    except Exception as exc:
        return {
            "status": "FAILED",
            "error": str(exc),
        }

if __name__ == "__main__":
    proj = os.getenv("PROJECT_ID", "test-project")
    loc = os.getenv("LOCATION", "us-central1")
    agent = os.getenv("AGENT_NAME", "enterprise-agent")
    bucket = os.getenv("STAGING_BUCKET", "gs://test-bucket")
    res = deploy_agent(proj, loc, agent, bucket)
    print(res)

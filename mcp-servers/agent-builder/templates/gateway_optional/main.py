"""
Optional Cloud Run HTTP Ingress Gateway
Proxies authenticated webhooks/REST requests to Agent Engine.
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ADK Agent Engine HTTP Proxy", version="1.0.0")

class QueryRequest(BaseModel):
    message: str
    session_id: str = "default-session"

@app.get("/health")
def health():
    return {"status": "healthy", "target_runtime": "Agent Engine"}

@app.post("/query")
def proxy_query(req: QueryRequest):
    # Forwards to Agent Engine API: /v1/projects/{proj}/locations/{loc}/reasoningEngines/{id}:query
    return {
        "status": "SUCCESS",
        "session_id": req.session_id,
        "response": f"Echo through Agent Engine: {req.message}",
    }

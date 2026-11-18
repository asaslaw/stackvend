"""The platform's service inventory of a generated workload (`apps/<service>/` directories that the deploy workflows
build). Moved verbatim from handler.py (Step 2a code RT F10) so validators can share it without importing the handler;
lane 10's typed topology replaces it."""
from __future__ import annotations

from typing import Dict, List


def detect_workload_services(files: Dict[str, str], default_product_id: str) -> List[str]:
    """
    Inspects workload files to identify all microservices under `apps/<service>/`.
    Filters out flat files (like __init__.py) and shared non-service modules (like common/schemas).
    Prioritizes directories with authentic runnable code entrypoints over skeleton directories.
    """
    authentic_entrypoint_suffixes = ("/main.py", "/app.py", "/server.js", "/main.go", "/index.js", "/main.ts", "/app.ts")
    authentic_services = set()
    for path in files.keys():
        if path.startswith("apps/"):
            parts = path.split("/")
            if len(parts) >= 3 and parts[1]:
                cand = parts[1]
                if cand.endswith(".py") or cand.endswith(".txt") or cand.endswith(".md"):
                    continue
                if any(path.startswith(f"apps/{cand}/") and path.endswith(suffix) for suffix in authentic_entrypoint_suffixes):
                    authentic_services.add(cand)

    if authentic_services:
        return sorted(list(authentic_services))

    services = set()
    runnable_suffixes = ("/main.py", "/app.py", "/Procfile", "/server.js", "/main.go", "/package.json")
    for path in files.keys():
        if path.startswith("apps/"):
            parts = path.split("/")
            if len(parts) >= 3 and parts[1]:
                cand = parts[1]
                if cand.endswith(".py") or cand.endswith(".txt") or cand.endswith(".md"):
                    continue
                if any(path.startswith(f"apps/{cand}/") and path.endswith(suffix) for suffix in runnable_suffixes):
                    services.add(cand)
    if not services:
        for path in files.keys():
            if path.startswith("apps/"):
                parts = path.split("/")
                if len(parts) >= 3 and parts[1]:
                    cand = parts[1]
                    if not (cand.endswith(".py") or cand in ("common", "contracts", "schemas", "shared")):
                        services.add(cand)
    return sorted(list(services)) if services else [default_product_id]

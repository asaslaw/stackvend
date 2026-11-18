"""
finops-spend-sync-job: Firestore clients. The default database (workloads, run records) and, read-only, the guard
database named by STACKVEND_GUARD_FIRESTORE_DATABASE, with the Control Center's exact `get_guard_db` contract
(services/runner_state.py, a byte copy of the Control Center's, imports it from here): unset -> the default database;
configured but cannot be opened -> None (the caller fails closed, never the default database).
"""
import logging
import os
from typing import Any, Optional

logger = logging.getLogger("finops-spend-sync-db")

GUARD_DB_ENV = "STACKVEND_GUARD_FIRESTORE_DATABASE"
_db_client: Any = None
_guard_db_client: Any = None
_guard_db_name: Optional[str] = None


def get_db():
    """The default database client, or None when it cannot be opened (the job then exits RUN_RECORD_UNAVAILABLE)."""
    global _db_client
    if _db_client is None:
        project = (os.getenv("PROJECT_ID") or "").strip()
        if not project:
            return None
        try:
            from google.cloud import firestore
            _db_client = firestore.Client(project=project)
        except Exception as e:  # noqa: BLE001 - typed by the caller
            logger.error(f"Could not open the Firestore database: {type(e).__name__}: {e}")
            return None
    return _db_client


def get_guard_db():
    global _guard_db_client, _guard_db_name
    name = (os.getenv(GUARD_DB_ENV) or "").strip()
    if not name:
        return get_db()
    if _guard_db_client is None or _guard_db_name != name:
        project = (os.getenv("PROJECT_ID") or "").strip()
        try:
            from google.cloud import firestore
            _guard_db_client = firestore.Client(project=project, database=name)
            _guard_db_name = name
        except Exception as e:  # noqa: BLE001
            logger.error(f"Could not open guard Firestore database '{name}': {e}")
            return None
    return _guard_db_client

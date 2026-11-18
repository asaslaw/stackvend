"""
Project Castor: Control Center Database & Storage Singletons
Provides lazily initialized Firestore, Storage, and Pub/Sub clients with mock-friendly proxying for unit tests.
"""

import logging
import os
import sys
from typing import Any, Optional

from config import PROJECT_ID

logger = logging.getLogger("control-center-db")

try:
    from google.cloud import firestore
except ImportError:
    firestore = None

try:
    from google.cloud import storage
except ImportError:
    storage = None

try:
    from google.cloud import pubsub_v1
except ImportError:
    pubsub_v1 = None

try:
    from google.cloud import logging_v2 as cloud_logging
except ImportError:
    try:
        from google.cloud import logging as cloud_logging
    except ImportError:
        cloud_logging = None

_db_client = None
_storage_client = None
_pubsub_client = None


def get_firestore_db():
    """Lazily initializes Firestore client on first API request to guarantee instant startup."""
    global _db_client
    if _db_client is None:
        if firestore and PROJECT_ID:
            try:
                _db_client = firestore.Client(project=PROJECT_ID)
                logger.info(f"Connected to Firestore client in project {PROJECT_ID}")
            except Exception as e:
                logger.warning(f"Could not initialize Firestore client: {e}")
                _db_client = False
        else:
            _db_client = False
    return _db_client if _db_client else None


def get_storage():
    """Lazily initializes Google Cloud Storage client."""
    global _storage_client
    if _storage_client is None:
        if storage and PROJECT_ID:
            try:
                _storage_client = storage.Client(project=PROJECT_ID)
            except Exception as e:
                logger.warning(f"Could not initialize Cloud Storage client: {e}")
                _storage_client = False
        else:
            _storage_client = False
    return _storage_client if _storage_client else None


def get_pubsub_publisher():
    """Lazily initializes Pub/Sub PublisherClient."""
    global _pubsub_client
    if _pubsub_client is None:
        if pubsub_v1 and PROJECT_ID:
            try:
                _pubsub_client = pubsub_v1.PublisherClient()
                logger.info(f"Connected to Pub/Sub publisher client in project {PROJECT_ID}")
            except Exception as e:
                logger.warning(f"Could not initialize Pub/Sub client: {e}")
                _pubsub_client = False
        else:
            _pubsub_client = False
    return _pubsub_client if _pubsub_client else None


def get_cloud_logging():
    """Returns cloud_logging client if available."""
    if cloud_logging and PROJECT_ID:
        try:
            return cloud_logging.Client(project=PROJECT_ID)
        except Exception:
            return None
    return None


class LazyDbProxy:
    """Transparent proxy object so existing db.collection(...) calls work seamlessly."""

    def _resolve_target(self):
        from config import get_caller_main_module
        caller_mod = get_caller_main_module()
        if caller_mod and hasattr(caller_mod, "db") and not isinstance(caller_mod.db, LazyDbProxy):
            return caller_mod.db

        for mod_name in ("cc_main", "main"):
            mod = sys.modules.get(mod_name)
            if mod and hasattr(mod, "db") and not isinstance(mod.db, LazyDbProxy):
                return mod.db
        import gc, types
        for obj in reversed(gc.get_objects()):
            if (
                isinstance(obj, types.ModuleType)
                and "control-center" in (getattr(obj, "__file__", "") or "")
                and (getattr(obj, "__file__", "") or "").endswith("main.py")
            ):
                if hasattr(obj, "db") and not isinstance(obj.db, LazyDbProxy):
                    return obj.db
        return get_firestore_db()

    def collection(self, *args, **kwargs):
        target = self._resolve_target()
        if not target:
            raise RuntimeError("Firestore database client is unavailable.")
        return target.collection(*args, **kwargs)

    def document(self, *args, **kwargs):
        target = self._resolve_target()
        if not target:
            raise RuntimeError("Firestore database client is unavailable.")
        return target.document(*args, **kwargs)

    def __bool__(self):
        target = self._resolve_target()
        return target is not None and bool(target)

    def __getattr__(self, name):
        target = self._resolve_target()
        if target is not None:
            return getattr(target, name)
        raise AttributeError(f"'LazyDbProxy' object has no attribute '{name}' (Firestore client unavailable)")


db = LazyDbProxy()


def get_db():
    """Returns active Firestore client or mock if patched."""
    target = db._resolve_target()
    return target if target else None


# Lane 18 S0b: destructive-action approvals (and vending's provenance) live in a named Firestore database that only the
# Control Center and project-vending can write. Unset -> the default database (anti-accident only, plan §2.5).
GUARD_DB_ENV = "STACKVEND_GUARD_FIRESTORE_DATABASE"
_guard_db_client = None
_guard_db_name = None


def get_guard_db():
    """The guard database client, or None when it is configured but cannot be opened (callers fail closed; a
    configured guard database NEVER falls back to the default one)."""
    global _guard_db_client, _guard_db_name
    name = (os.getenv(GUARD_DB_ENV) or "").strip()
    if not name:
        return get_db()
    if _guard_db_client is None or _guard_db_name != name:
        if not firestore or not PROJECT_ID:
            logger.error(f"Guard Firestore database '{name}' is configured but no Firestore client is available.")
            return None
        try:
            _guard_db_client = firestore.Client(project=PROJECT_ID, database=name)
            _guard_db_name = name
        except Exception as e:  # noqa: BLE001
            logger.error(f"Could not open guard Firestore database '{name}': {e}")
            return None
    return _guard_db_client

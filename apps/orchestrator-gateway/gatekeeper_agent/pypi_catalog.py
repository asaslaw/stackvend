"""
Project Castor: Canonical PyPI Import Catalog & Dependency Resolver
Maps Python import root names to vetted PyPI distribution packages,
and filters against Python standard library to guarantee clean requirements.txt.
"""

import sys
from typing import Dict, Optional, Set

# Standard library module names in Python 3.10-3.13
STDLIB_MODULES: Set[str] = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else {
    "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii", "bisect", "builtins",
    "bz2", "calendar", "cmath", "cmd", "code", "codecs", "collections", "colorsys", "compileall",
    "concurrent", "configparser", "contextlib", "contextvars", "copy", "copyreg", "crypt", "csv",
    "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal", "difflib", "dis", "distutils",
    "doctest", "email", "encodings", "ensurepip", "enum", "errno", "faulthandler", "fcntl", "filecmp",
    "fileinput", "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt", "getpass", "gettext",
    "glob", "graphlib", "grp", "gzip", "hashlib", "heapq", "hmac", "html", "http", "idlelib", "imaplib",
    "imghdr", "imp", "importlib", "inspect", "io", "ipaddress", "itertools", "json", "keyword", "lib2to3",
    "linecache", "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes",
    "mmap", "modulefinder", "msilib", "msvcrt", "multiprocessing", "netrc", "nis", "nntplib", "numbers",
    "operator", "optparse", "os", "ossaudiodev", "pathlib", "pdb", "pickle", "pickletools", "pipes",
    "pkgutil", "platform", "plistlib", "poplib", "posix", "posixpath", "pprint", "profile", "pstats",
    "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random", "re", "readline",
    "reprlib", "resource", "rlcompleter", "runpy", "sched", "secrets", "select", "selectors", "shelve",
    "shlex", "shutil", "signal", "site", "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "spwd",
    "sqlite3", "ssl", "stat", "statistics", "string", "stringprep", "struct", "subprocess", "sunau",
    "symbol", "symtable", "sys", "sysconfig", "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile",
    "termios", "test", "textwrap", "threading", "time", "timeit", "tkinter", "token", "tokenize",
    "tomllib", "trace", "traceback", "tracemalloc", "tty", "turtle", "turtledemo", "types", "typing",
    "unicodedata", "unittest", "urllib", "uu", "uuid", "venv", "warnings", "wave", "weakref",
    "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile",
    "zipimport", "zlib", "zoneinfo"
}

# Mapping: import_root -> (canonical_pypi_package, pinned_version_constraint)
CANONICAL_PYPI_CATALOG: Dict[str, str] = {
    # FastAPI & Web Ecosystem
    "fastapi": "fastapi>=0.110.0",
    "uvicorn": "uvicorn[standard]>=0.28.0",
    "starlette": "starlette>=0.36.0",
    "pydantic": "pydantic>=2.6.0",
    "pydantic_settings": "pydantic-settings>=2.2.0",
    "email_validator": "email-validator>=2.0.0",
    "jinja2": "jinja2>=3.1.5",
    "httpx": "httpx>=0.27.0",
    "requests": "requests>=2.31.0",
    "aiohttp": "aiohttp>=3.9.0",

    # Google Cloud SDKs
    "google.cloud.storage": "google-cloud-storage>=2.14.0",
    "google.cloud.pubsub": "google-cloud-pubsub>=2.19.0",
    "google.cloud.pubsub_v1": "google-cloud-pubsub>=2.19.0",
    "google.cloud.firestore": "google-cloud-firestore>=2.15.0",
    "google.cloud.firestore_v1": "google-cloud-firestore>=2.15.0",
    "google.cloud.secretmanager": "google-cloud-secret-manager>=2.18.0",
    "google.cloud.secretmanager_v1": "google-cloud-secret-manager>=2.18.0",
    "google.cloud.bigquery": "google-cloud-bigquery>=3.17.0",
    "google.cloud.logging": "google-cloud-logging>=3.9.0",
    "google.cloud.tasks": "google-cloud-tasks>=2.16.0",
    "google.cloud.tasks_v2": "google-cloud-tasks>=2.16.0",
    "google.cloud.workflows": "google-cloud-workflows>=1.13.0",
    "google.cloud.workflows_v1": "google-cloud-workflows>=1.13.0",
    "google.cloud.compute": "google-cloud-compute>=1.18.0",
    "google.cloud.compute_v1": "google-cloud-compute>=1.18.0",
    "google.cloud.run": "google-cloud-run>=0.10.0",
    "google.cloud.run_v2": "google-cloud-run>=0.10.0",
    "google.cloud.scheduler": "google-cloud-scheduler>=2.13.0",
    "google.cloud.scheduler_v1": "google-cloud-scheduler>=2.13.0",
    "google.cloud.aiplatform": "google-cloud-aiplatform>=1.42.0",
    "google.cloud.aiplatform_v1": "google-cloud-aiplatform>=1.42.0",
    "google.cloud.discoveryengine": "google-cloud-discoveryengine>=0.11.0",
    "google.cloud.discoveryengine_v1": "google-cloud-discoveryengine>=0.11.0",
    "google.cloud.monitoring": "google-cloud-monitoring>=2.18.0",
    "google.cloud.monitoring_v3": "google-cloud-monitoring>=2.18.0",
    "google.cloud.artifactregistry": "google-cloud-artifact-registry>=1.11.0",
    "google.cloud.artifactregistry_v1": "google-cloud-artifact-registry>=1.11.0",
    "google.cloud.cloudbuild": "google-cloud-build>=3.23.0",
    "google.cloud.cloudbuild_v1": "google-cloud-build>=3.23.0",
    "google.auth": "google-auth>=2.28.0",
    # FD-4AD RT F4 (FDAD-5): rows the deleted base pins used to cover by accident
    "google.oauth2": "google-auth>=2.28.0",
    "google.api_core": "google-api-core>=2.17.0",
    "google.cloud.sql.connector": "cloud-sql-python-connector>=1.9.0",
    "googleapiclient": "google-api-python-client>=2.100.0",
    "google.genai": "google-genai>=0.1.1",
    "kubernetes": "kubernetes>=29.0.0",

    # Database & Cache
    "sqlalchemy": "SQLAlchemy>=2.0.28",
    "alembic": "alembic>=1.13.0",
    "psycopg2": "psycopg2-binary>=2.9.10,<3.0.0",
    "psycopg": "psycopg>=3.2.0,<4.0.0",
    "asyncpg": "asyncpg>=0.30.0,<1.0.0",
    # AIOSQLITE-CATALOG (owner 11-11): the async SQLite driver test fixtures load by URL (sqlite+aiosqlite://)
    "aiosqlite": "aiosqlite>=0.20.0,<1.0.0",
    "redis": "redis>=5.0.3",
    "pymongo": "pymongo>=4.6.0",

    # Data & Serialization
    "yaml": "PyYAML>=6.0.1",
    "PIL": "Pillow>=10.2.0",
    "jwt": "PyJWT>=2.8.0",
    "jose": "python-jose[cryptography]>=3.3.0",
    "cryptography": "cryptography>=43.0.0,<45.0.0",
    "cv2": "opencv-python-headless>=4.9.0",
    "dateutil": "python-dateutil>=2.9.0",
    "pandas": "pandas>=2.2.0",
    "numpy": "numpy>=1.26.0",
    "pytest": "pytest>=8.0.0",
    "multipart": "python-multipart>=0.0.9",
    "dotenv": "python-dotenv>=1.0.0",
    "prometheus_client": "prometheus-client>=0.20.0",
    "opentelemetry": "opentelemetry-api>=1.24.0",
    "protobuf": "protobuf>=4.25.0",
    "google.protobuf": "protobuf>=4.25.0",
    "grpc": "grpcio>=1.62.0",
}


def resolve_import_to_pypi(import_module: str) -> Optional[str]:
    """
    Given an imported module name (e.g. 'google.cloud.storage' or 'yaml'),
    returns the pinned canonical PyPI package name, or None if it's in the stdlib
    or not in the vetted canonical catalog (closed-world dependency governance).
    """
    if not import_module:
        return None

    # Check stdlib first
    root = import_module.split(".")[0]
    if root in STDLIB_MODULES:
        return None

    # Exact match in catalog
    if import_module in CANONICAL_PYPI_CATALOG:
        return CANONICAL_PYPI_CATALOG[import_module]

    # Two-part match (e.g. google.cloud.pubsub)
    parts = import_module.split(".")
    if len(parts) >= 2:
        if len(parts) >= 3:
            three_part = f"{parts[0]}.{parts[1]}.{parts[2]}"
            if three_part in CANONICAL_PYPI_CATALOG:
                return CANONICAL_PYPI_CATALOG[three_part]
        two_part = f"{parts[0]}.{parts[1]}"
        if two_part in CANONICAL_PYPI_CATALOG:
            return CANONICAL_PYPI_CATALOG[two_part]

    # Root match
    if root in CANONICAL_PYPI_CATALOG:
        return CANONICAL_PYPI_CATALOG[root]

    # Reject known namespace packages, local module names, and unvetted imports
    # (Level 3 Closed-World Governance: prevents hallucinated package injection and typosquatting)
    return None

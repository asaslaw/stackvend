"""FD-4A: a requirement names a DISTRIBUTION; code imports its TOP-LEVEL MODULES. The two often differ.

    beautifulsoup4 -> bs4        PyYAML -> yaml, _yaml      python-dateutil -> dateutil
    Pillow -> PIL                scikit-learn -> sklearn    google-cloud-storage -> google (namespace package)

The entrypoint shadow check (verifier.verify_container_entrypoint_imports, GATE.ENTRYPOINT_SHADOWED) and the
`__init__.py` scaffolding shield (verifier.purge_shadowed_package_files + its preflight twin) used to compare the
requirement name itself (lower case, `-` -> `_`) with import / directory names, so `PyYAML` never matched `import yaml`
(a local `yaml/` package shadowing PyYAML was missed) while a local package that merely shares the distribution's name
was blocked. This module answers "which top-level import names does distribution X install?" from facts only:

1. the metadata of the distributions installed in the running interpreter
   (`importlib.metadata.packages_distributions()`: each distribution's `top_level.txt`, else its RECORD file list) --
   the real answer for every distribution the gateway image installs;
2. KNOWN_TOP_LEVEL_IMPORTS, an explicit table for distributions the gateway image does not install. Every row whose
   distribution IS installed in the test interpreter is checked against (1) by
   tests/test_fd4a_requirement_import_names.py, so the two sources never disagree there.

A distribution in neither source is UNKNOWN and callers never guess its import name (no `-` -> `_` folding, no prefix
rules such as "google-cloud-* -> google"; Invariant 2). Distribution names are matched by their PEP 503 canonical form
(`packaging.utils.canonicalize_name`), requirement lines are read by `packaging` (`declared_names`: extras, version
specifiers, environment markers, comments and pip option lines handled).
"""
from __future__ import annotations

import functools
import logging
from typing import Dict, FrozenSet, Iterable, Optional, Set, Tuple

try:
    from .requirements_contract import canonical_name, declared_names
except ImportError:  # pragma: no cover - module loaded outside its package
    from requirements_contract import canonical_name, declared_names  # type: ignore

logger = logging.getLogger("castor-gatekeeper-agent")

_GOOGLE = ("google",)

# Canonical distribution name -> top-level import names it installs (its `top_level.txt`). Exact rows only; add a row
# rather than a rule. Rows for distributions installed in the test interpreter are verified against their metadata.
KNOWN_TOP_LEVEL_IMPORTS: Dict[str, Tuple[str, ...]] = {
    # --- name differs from the import name ---
    "beautifulsoup4": ("bs4",),
    "pyyaml": ("_yaml", "yaml"),
    "python-dateutil": ("dateutil",),
    "pillow": ("PIL",),
    "scikit-learn": ("sklearn",),
    "scikit-image": ("skimage",),
    "pyjwt": ("jwt",),
    "python-jose": ("jose",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "opencv-contrib-python": ("cv2",),
    "python-multipart": ("multipart", "python_multipart"),
    "python-dotenv": ("dotenv",),
    "prometheus-client": ("prometheus_client",),
    "opentelemetry-api": ("opentelemetry",),
    "opentelemetry-sdk": ("opentelemetry",),
    "opentelemetry-semantic-conventions": ("opentelemetry",),
    "psycopg2-binary": ("psycopg2",),
    "psycopg2": ("psycopg2",),
    "psycopg-binary": ("psycopg_binary",),
    "psycopg-pool": ("psycopg_pool",),
    "pymongo": ("bson", "gridfs", "pymongo"),
    "email-validator": ("email_validator",),
    "pydantic-settings": ("pydantic_settings",),
    "pydantic-core": ("pydantic_core",),
    "typing-extensions": ("typing_extensions",),
    "charset-normalizer": ("charset_normalizer",),
    "attrs": ("attr", "attrs"),
    "pyopenssl": ("OpenSSL",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "mysqlclient": ("MySQLdb",),
    "python-magic": ("magic",),
    "pyzmq": ("zmq",),
    "dnspython": ("dns",),
    "websocket-client": ("websocket",),
    "pygithub": ("github",),
    "python-slugify": ("slugify",),
    "python-docx": ("docx",),
    "python-pptx": ("pptx",),
    "pypdf2": ("PyPDF2",),
    "fpdf2": ("fpdf",),
    "pyserial": ("serial",),
    "markdown-it-py": ("markdown_it",),
    "python-json-logger": ("pythonjsonlogger",),
    "argon2-cffi": ("argon2",),
    "python-socketio": ("socketio",),
    "python-engineio": ("engineio",),
    "firebase-admin": ("firebase_admin",),
    "huggingface-hub": ("huggingface_hub",),
    "sentence-transformers": ("sentence_transformers",),
    "faiss-cpu": ("faiss",),
    "factory-boy": ("factory",),
    "djangorestframework": ("rest_framework",),
    "flask-cors": ("flask_cors",),
    "flask-sqlalchemy": ("flask_sqlalchemy",),
    "sse-starlette": ("sse_starlette",),
    "pytest-asyncio": ("pytest_asyncio",),
    "pytest": ("_pytest", "py", "pytest"),
    "setuptools": ("_distutils_hack", "pkg_resources", "setuptools"),
    "python-hcl2": ("hcl2",),
    "pyasn1-modules": ("pyasn1_modules",),
    "requests-oauthlib": ("requests_oauthlib",),
    "google-auth-oauthlib": ("google_auth_oauthlib",),
    "google-auth-httplib2": ("google_auth_httplib2",),
    "google-api-python-client": ("apiclient", "googleapiclient"),
    "google-crc32c": ("google_crc32c",),
    "grpcio": ("grpc",),
    "grpcio-status": ("grpc_status",),
    "proto-plus": ("proto",),
    "cffi": ("_cffi_backend", "cffi"),
    "pynacl": ("_sodium", "nacl"),
    "langchain-core": ("langchain_core",),
    "langchain-google-vertexai": ("langchain_google_vertexai",),
    "tiktoken": ("tiktoken", "tiktoken_ext"),
    "matplotlib": ("matplotlib", "mpl_toolkits", "pylab"),
    "azure-storage-blob": ("azure",),
    "azure-identity": ("azure",),
    "sentry-sdk": ("sentry_sdk",),
    "slack-sdk": ("slack", "slack_sdk"),          # slack_sdk 3.x still ships the deprecated `slack` package
    "mysql-connector-python": ("mysql",),        # `mysqlx` moved to mysqlx-connector-python in 8.3.0
    "flask-login": ("flask_login",),
    "flask-migrate": ("flask_migrate",),
    "torch": ("functorch", "torch", "torchgen"),
    "confluent-kafka": ("confluent_kafka",),
    "kafka-python": ("kafka",),
    # --- Google namespace packages: every one installs the top-level `google` ---
    "google-cloud-storage": _GOOGLE,
    "google-cloud-pubsub": _GOOGLE,
    "google-cloud-firestore": _GOOGLE,
    "google-cloud-secret-manager": _GOOGLE,
    "google-cloud-bigquery": _GOOGLE,
    "google-cloud-logging": _GOOGLE,
    "google-cloud-tasks": _GOOGLE,
    "google-cloud-workflows": _GOOGLE,
    "google-cloud-compute": _GOOGLE,
    "google-cloud-run": _GOOGLE,
    "google-cloud-scheduler": _GOOGLE,
    "google-cloud-discoveryengine": _GOOGLE,
    "google-cloud-monitoring": _GOOGLE,
    "google-cloud-artifact-registry": _GOOGLE,
    "google-cloud-build": _GOOGLE,
    "google-cloud-core": _GOOGLE,
    "google-cloud-container": _GOOGLE,
    "google-cloud-resource-manager": _GOOGLE,
    "google-cloud-appengine-logging": _GOOGLE,
    "google-cloud-audit-log": _GOOGLE,
    "google-cloud-spanner": _GOOGLE,
    "google-cloud-bigtable": _GOOGLE,
    "google-cloud-datastore": _GOOGLE,
    "google-cloud-kms": _GOOGLE,
    "google-cloud-speech": _GOOGLE,
    "google-cloud-texttospeech": _GOOGLE,
    "google-cloud-translate": _GOOGLE,
    "google-cloud-vision": _GOOGLE,
    "google-cloud-language": _GOOGLE,
    "google-cloud-documentai": _GOOGLE,
    "google-cloud-dlp": _GOOGLE,
    "google-cloud-redis": _GOOGLE,
    "google-cloud-error-reporting": _GOOGLE,
    "google-cloud-trace": _GOOGLE,
    "google-cloud-functions": _GOOGLE,
    "google-cloud-dataproc": _GOOGLE,
    "google-cloud-videointelligence": _GOOGLE,
    "google-cloud-ndb": _GOOGLE,
    "google-cloud-aiplatform": ("agentplatform", "google", "vertex_ray", "vertexai"),
    "google-auth": _GOOGLE,
    "google-api-core": _GOOGLE,
    "google-genai": _GOOGLE,
    "google-generativeai": _GOOGLE,
    "google-resumable-media": _GOOGLE,
    "googleapis-common-protos": _GOOGLE,
    "grpc-google-iam-v1": _GOOGLE,
    "protobuf": _GOOGLE,
    "cloud-sql-python-connector": _GOOGLE,
    # --- name equals the import name (listed so the answer does not depend on what the gateway image installs) ---
    **{name: (name,) for name in (
        "fastapi", "uvicorn", "starlette", "pydantic", "jinja2", "httpx", "requests", "aiohttp", "kubernetes",
        "sqlalchemy", "alembic", "psycopg", "asyncpg", "redis", "cryptography", "pandas", "numpy", "scipy",
        "gunicorn", "hypercorn", "flask", "werkzeug", "itsdangerous", "markupsafe", "click", "blinker", "django",
        "boto3", "botocore", "stripe", "openai", "anthropic", "langchain", "celery", "kombu", "apscheduler",
        "tenacity", "structlog", "loguru", "bcrypt", "passlib", "authlib", "sqlmodel", "motor", "aiosqlite",
        "elasticsearch", "jsonschema", "marshmallow", "lxml", "html5lib", "nltk", "spacy", "pytz", "tzdata",
        "babel", "arrow", "pendulum", "qrcode", "reportlab", "openpyxl", "xlsxwriter", "six", "certifi", "idna",
        "urllib3", "httpcore", "h11", "anyio", "sniffio", "websockets", "uvloop", "httptools", "watchfiles",
        "pyparsing", "packaging", "rich", "typer", "toml", "tomli", "msgpack", "orjson", "ujson", "aiofiles",
        "faker", "slowapi", "pypdf", "markdown", "httplib2", "oauthlib", "pyasn1", "rsa", "cachetools",
        "dulwich", "lark", "regex", "pyflakes", "pygments", "uritemplate", "distro", "pluggy", "iniconfig",
        "multidict", "yarl", "frozenlist", "aiosignal", "propcache", "aiohappyeyeballs", "pycparser",
        "durationpy", "pyarrow", "polars", "tensorflow", "transformers", "pika", "gevent", "twilio", "sendgrid",
        "pyotp", "jwcrypto",
    )},
    "docstring-parser": ("docstring_parser",),
    "typing-inspection": ("typing_inspection",),
    "annotated-types": ("annotated_types",),
    "annotated-doc": ("annotated_doc",),
    "aiohttp-retry": ("aiohttp_retry",),
}

# Top-level import names that are native PEP 420 namespace packages (no `__init__.py` in any installed portion): a
# local init-less `<name>/` directory is one more portion of the same namespace, so its submodules stay reachable.
# (A pkgutil `extend_path` package does NOT merge init-less dirs and is not listed.) `tiktoken_ext` is tiktoken's
# plugin namespace. Exact list; installed names are checked against `importlib.util.find_spec` by the FD-4A tests.
# `mysql` is listed conservatively (not confirmed to be a regular package across mysql-connector-python versions):
# listing a name here can only suppress an FD-4A-b finding, never create one.
NAMESPACE_TOP_LEVELS: FrozenSet[str] = frozenset(
    {"google", "azure", "opentelemetry", "mpl_toolkits", "tiktoken_ext", "mysql"})


def _importable(name: str) -> bool:
    """Exact rule for a top-level import name: a Python identifier (drops RECORD artefacts such as `a/b` paths or
    `x.pth`) other than the bytecode cache directory."""
    return name.isidentifier() and name != "__pycache__"


@functools.lru_cache(maxsize=1)
def _installed_top_levels() -> Dict[str, FrozenSet[str]]:
    """{canonical distribution name: top-level import names} for every distribution installed in this interpreter.
    Unreadable metadata yields {} (the explicit table still answers; nothing is guessed)."""
    try:
        from importlib.metadata import packages_distributions
        by_import = packages_distributions()
    except Exception as exc:  # pragma: no cover - broken site-packages metadata
        logger.warning(f"FD-4A: installed distribution metadata unreadable ({exc}); using the explicit table only")
        return {}
    out: Dict[str, Set[str]] = {}
    for module, dists in by_import.items():
        if not _importable(module):
            continue
        for dist in dists:
            out.setdefault(canonical_name(dist), set()).add(module)
    return {k: frozenset(v) for k, v in out.items()}


def top_level_imports(distribution: str) -> Optional[FrozenSet[str]]:
    """Top-level import names the distribution installs, or None when no fact is known (never a guess)."""
    name = canonical_name(distribution)
    installed = _installed_top_levels().get(name)
    if installed:
        return installed
    known = KNOWN_TOP_LEVEL_IMPORTS.get(name)
    return frozenset(known) if known else None


def requirement_import_roots(texts: Iterable[str]) -> Tuple[Set[str], Set[str]]:
    """For requirements.txt texts: (top-level import names of every declared distribution with a known answer,
    canonical names of the declared distributions whose import names are unknown)."""
    imports: Set[str] = set()
    unknown: Set[str] = set()
    for text in texts:
        for dist in declared_names(text):
            roots = top_level_imports(dist)
            if roots is None:
                unknown.add(dist)
            else:
                imports |= roots
    return imports, unknown


__all__ = ["KNOWN_TOP_LEVEL_IMPORTS", "NAMESPACE_TOP_LEVELS", "requirement_import_roots", "top_level_imports"]

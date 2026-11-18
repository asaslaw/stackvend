"""
Project Castor: Gatekeeper Agent Package
Exports SynthesisVerifierAgent and resolve_import_to_pypi (ContainerImportTransformer was deleted, FD-4AD).
"""

from .pypi_catalog import CANONICAL_PYPI_CATALOG, STDLIB_MODULES, resolve_import_to_pypi
from .verifier import SynthesisVerifierAgent

__all__ = [
    "SynthesisVerifierAgent",
    "resolve_import_to_pypi",
    "CANONICAL_PYPI_CATALOG",
    "STDLIB_MODULES",
]

"""
Project Castor: QA Auditor & Dual-Lens Audit Package
"""

from .security_lens import evaluate_security_lens
from .adherence_lens import evaluate_adherence_lens
from .coordinator import DualLensAuditorCoordinator
from .lens_common import LensUnavailableError
from .platform_facts import PlatformFacts, build_platform_facts

__all__ = [
    "evaluate_security_lens",
    "evaluate_adherence_lens",
    "DualLensAuditorCoordinator",
    "LensUnavailableError",
    "PlatformFacts",
    "build_platform_facts",
]

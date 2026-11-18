"""
Developer Agent Package
"""
# FD-4F A9 (RT F1): hard import. A missing gate module must crash `import developer_agent` with the real ImportError,
# never bind `DeveloperAgent = None` (which only failed later as a TypeError, or silently for other importers).
from .handler import DeveloperAgent

from .terraform_engine import (
    detect_cloudrun_scaling_parameters,
    extract_scaling_from_spec,
    vendor_terraform_modules,
    generate_golden_main_tf,
    generate_golden_variables_tf,
    generate_golden_outputs_tf,
    generate_golden_moved_tf,
)
# FD-55 W5: `reconcile_iac_reference_graph` (HB-01) is deleted, so it is no longer exported.
# FD-55 W1: `extract_bespoke_custom_resources` (X2, never called) is deleted, so it is no longer exported.

__all__ = [
    "DeveloperAgent",
    "detect_cloudrun_scaling_parameters",
    "extract_scaling_from_spec",
    "vendor_terraform_modules",
    "generate_golden_main_tf",
    "generate_golden_variables_tf",
    "generate_golden_outputs_tf",
    "generate_golden_moved_tf",
]

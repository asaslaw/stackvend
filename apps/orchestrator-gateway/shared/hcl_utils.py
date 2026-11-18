"""
StackVend: shared HCL helpers (the Developer Agent and the Terraform MCP server ship byte-identical copies;
tests/test_hcl_utils.py::test_hcl_utils_monorepo_parity).

Wave 1 lane 8 (FD-44, FD-4U, FD-4AY) deleted the regex rewriters is_valid_ipv4_cidr,
sanitize_cidr_declarations, strip_balanced_block and sanitize_hcl_wif: they mutated valid HCL.
Invalid CIDRs and LLM-declared WIF now fail loudly at `tofu init/plan/apply` (FD-53 moves these
checks to pre-commit validators). Do not re-add them; tests/test_lane8_deletions.py is the tombstone.
FD-4AA (HA-13 / HC-19) deleted the graph phases of auto_wire_network_graph_dependencies (VPC convergence, subnet
dedup, network rewiring, PSA depends_on, password synthesis); tests/test_fd4aa_apply_healers.py is the tombstone.
FD-55 W1 (register FD55-W1) deleted the bodies that no production code called any more: the semantic duplicate-resource
/ data / provider clean-up (deduplicate_semantic_hcl_resources / _blocks, strip_hcl_resource_block / _data_block /
_provider_block and their block-body helpers), the label coercion coerce_hcl_metadata_maps and the depends_on insertion
_ensure_resource_depends_on. Do not re-add them; tests/test_fd55_w1_dead_code.py is the tombstone.
FD-55 W6b (register FD55-W6b+W6d) deleted the apply-time "Autonomous IaC Curing" bodies with their last caller
(the Terraform MCP prepare_workspace): the delimiter checker validate_hcl_syntax_tree (HE-01) and its "balancer"
self_correct_hcl_syntax (HC-14), and the orphaned depends_on repair heal_orphaned_resource_syntax /
heal_orphaned_root_resource_syntax / auto_wire_network_graph_dependencies (HB-24 / HA-13 Phase 0, register row 7:
kept until the FD-53 repair loop, which is live). A file that does not parse fails `tofu validate` / apply and is
reported back. Do not re-add them; tests/test_fd55_w6bd_no_writeback.py is the tombstone.

FD-55 W6b + W6c (register FD55-W6b+W6d / FD55-W6c) deleted the locals pair extract_declared_locals /
sanitize_hcl_locals_invariants (HA-17: `locals.` -> `local.` and invented undeclared locals) with its last callers
(the prepare_workspace call, W6b; the validate-error and apply-error heals A44 / A48, W6c). An undeclared local is
an OpenTofu validate error reported back. Do not re-add them; tests/test_fd55_w6bd_no_writeback.py is the tombstone.

What remains: only the read-only parser helpers find_hcl_parser_binary / hcl_parse_errors (OpenTofu / Terraform
`fmt`; no production caller after W6b, kept as the read-only checker for FD-61's consolidation). Nothing here
writes or rewrites HCL.
"""

import os
import shutil
import subprocess
import tempfile
from typing import List, Optional


# Install locations searched (after PATH) for the OpenTofu/Terraform binary used as the HCL parser:
# the usual host install directories (the gateway's former preflight_validate_terraform searched the same ones;
# FD-55 W4 deleted it), plus the Terraform server's tooling cache (TerraformService.tooling_dir/bin, binaries named
# <engine>_<version>).
_HCL_PARSER_ENGINES = ("tofu", "terraform")
_HCL_PARSER_DIRS = (
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/tmp/castor_tf_workspaces/bin",
    "/tmp/castor_tf_workspaces/.castor-tooling/bin",
)


def _is_executable_file(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def find_hcl_parser_binary() -> Optional[str]:
    """Returns an installed OpenTofu (preferred) or Terraform binary, or None. Never downloads."""
    for engine in _HCL_PARSER_ENGINES:
        found = shutil.which(engine)
        if found:
            return found
    for engine in _HCL_PARSER_ENGINES:
        for directory in _HCL_PARSER_DIRS:
            candidate = os.path.join(directory, engine)
            if _is_executable_file(candidate):
                return candidate
            try:
                cached = sorted(os.listdir(directory), reverse=True)
            except OSError:
                continue
            for entry in cached:
                if entry.startswith(f"{engine}_") and not entry.endswith(".zip"):
                    candidate = os.path.join(directory, entry)
                    if _is_executable_file(candidate):
                        return candidate
    return None


# Exit status of `<bin> fmt` when the input has invalid syntax (diagnostics on stderr), in both
# OpenTofu and Terraform. Every other non-zero status is a non-parse failure and proves nothing.
_HCL_FMT_SYNTAX_ERROR_EXIT = 2


def hcl_parse_errors(content: str, filename: str = "custom.tf", parser_bin: Optional[str] = None) -> Optional[List[str]]:
    """
    Parses HCL with OpenTofu/Terraform's own parser: `<bin> fmt -no-color -` on stdin. Syntax only:
    no init, no providers, no state, no network, no files written ($HOME is a throwaway temp dir, so
    fmt's $HOME/.terraform.d is not created in the real home).

    Decided by fmt's exit-code contract only (Invariant 1, lane 8 RT-2 F1):
      exit 0 -> [] (parses); exit 2 -> a one-item list with the parser's diagnostics (rejects);
      anything else (no binary, could not run, timeout, killed by a signal, any other exit status)
      -> None: the content is NOT proven broken and callers must never mutate it.
    """
    bin_path = parser_bin or find_hcl_parser_binary()
    if not bin_path:
        return None
    env = dict(os.environ)
    env["CHECKPOINT_DISABLE"] = "1"  # Terraform's version check is a network call; fmt needs none.
    try:
        with tempfile.TemporaryDirectory(prefix="stackvend-hcl-fmt-") as scratch_home:
            env["HOME"] = scratch_home
            res = subprocess.run(
                [bin_path, "fmt", "-no-color", "-"],
                input=content,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                env=env,
            )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode == 0:
        return []
    if res.returncode == _HCL_FMT_SYNTAX_ERROR_EXIT:
        detail = (res.stderr or res.stdout or "").strip() or f"exit status {res.returncode}"
        return [f"HCL parse error in {filename}: {detail}"]
    return None

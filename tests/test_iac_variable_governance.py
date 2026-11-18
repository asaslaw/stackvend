"""
Tombstones for the terraform MCP's IaC variable guessers (all deleted).

1. FD-55 W4 (register FD55-W4): the gateway copies (developer_agent.preflight_validator) of HD-14 / HB-17 and the HD-15
   pre-flight + self_correct_hcl are deleted.
2. FD-55 W6a (register FD55-W6a): the apply-time GCP naming sanitizer (sanitize_gcp_naming_invariants, A10 / A41)
   and the auto-declaration of undeclared variables are deleted (prepare_workspace writes the committed files,
   tests/test_fd55_w6a_apply_text_heals.py).
3. FD-55 W6c (register FD55-W6c): the pre-apply tfvars reconciler (A42) is deleted with its two helpers, the HD-14
   name-based value guesser (generate_rfc1123_variable_default, with the lane 19 `_ACCESS_KEY_DEFAULTS` table) and
   the regex variables.tf schema reader (parse_variables_tf_schema). No variable value is guessed at deploy; the
   deploy-level behaviour is pinned in tests/test_fd55_w6c_apply_error_heals.py.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest

GATEWAY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "orchestrator-gateway"))
TERRAFORM_MCP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform"))
for p in [GATEWAY_DIR, TERRAFORM_MCP_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

import service as tf_service


class TestIaCVariableGovernance(unittest.TestCase):
    """The apply-time variable / name guessers stay deleted (a mutant re-adding one fails here)."""

    def test_apply_time_name_rewriters_are_gone(self):
        # FD-55 W6a (A10 / A41)
        self.assertFalse(hasattr(tf_service, "sanitize_gcp_naming_invariants"))
        self.assertFalse(hasattr(tf_service, "sanitize_secret_manager_references"))

    def test_apply_time_variable_value_guessers_are_gone(self):
        # FD-55 W6c (A42)
        for name in ("generate_rfc1123_variable_default", "parse_variables_tf_schema", "_ACCESS_KEY_DEFAULTS"):
            self.assertFalse(hasattr(tf_service, name), name)


if __name__ == "__main__":
    unittest.main()

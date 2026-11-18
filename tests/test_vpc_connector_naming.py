import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import re
import unittest
import importlib.util
import os
import sys

GATEWAY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "orchestrator-gateway"))
TERRAFORM_MCP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform"))
for p in [GATEWAY_DIR, TERRAFORM_MCP_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

# FD-55 W4 (register FD55-W4): the gateway copies of the naming / default healers (sanitize_gcp_naming_invariants,
# generate_rfc1123_variable_default) and self_correct_hcl are deleted; their gateway cases are removed here. FD-55 W6a
# (register FD55-W6a) deletes the terraform MCP's apply-time sanitize_gcp_naming_invariants (connector-name clamps 3b /
# 3c) with its two cases: a too-long literal connector name is now applied as committed and rejected by the provider
# (tests/test_fd55_w6a_apply_text_heals.py pins the byte identity). FD-55 W6c (register FD55-W6c) deletes the
# terraform MCP's generate_rfc1123_variable_default with the pre-apply tfvars reconciler (A42), so its two
# connector-default cases are gone too: a connector name variable without a value fails at plan. A templated connector name
# is now V2k IAC.NAME_INVALID (tests/test_fd55_w4_name_check.py). FD-55 W1 (FD55-W1): the gateway's unused
# deduplicate_semantic_hcl_resources copy and its two connector cases are deleted too.
import service as mcp_tf

VPC_CONNECTOR_REGEX = re.compile(r"^[a-z][-a-z0-9]{0,23}[a-z0-9]$")


class TestVPCConnectorNaming(unittest.TestCase):
    def test_apply_time_connector_default_guess_is_deleted(self):
        """FD-55 W6c (A42): no connector name (or any other value) is guessed at deploy; a mutant re-adding the
        generator fails here."""
        self.assertFalse(hasattr(mcp_tf, "generate_rfc1123_variable_default"))

    def test_apply_time_connector_name_clamp_is_deleted(self):
        """FD-55 W6a (A10 / A41): a mutant re-adding the apply-time name rewrite fails here."""
        self.assertFalse(hasattr(mcp_tf, "sanitize_gcp_naming_invariants"))


if __name__ == "__main__":
    unittest.main()

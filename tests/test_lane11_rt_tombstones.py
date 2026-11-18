"""Lane 11 code RT F2 tombstones: no platform healer invents an IP range (AGENTS.md invariant 3).

Both copies of `generate_rfc1123_variable_default` (gateway `preflight_validator.py`, terraform server `service.py`;
AGENTS.md "Replicated files") lost their CIDR branch, which returned "10.10.0.0/24" / "10.8.0.0/28" for any variable
name containing `cidr` / `ip_range` / `mask`; `prepare_workspace`'s `_ensure_default` (which injected those values into
variable blocks) is deleted. A CIDR variable without a value now fails at plan instead of silently getting a range
outside IPAM.
FD-55 W4 (register FD55-W4): the gateway copy is deleted altogether (no generation-time default is guessed); FD-55
W6c (register FD55-W6c) deletes the terraform MCP copy with the pre-apply tfvars reconciler, so no copy is left to
return any value, IP range or not.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import inspect
import os
import sys

GATEWAY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "orchestrator-gateway"))
TERRAFORM_MCP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform"))
for p in [GATEWAY_DIR, TERRAFORM_MCP_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent import preflight_validator as gateway_pv  # noqa: E402
import service as mcp_tf  # noqa: E402

LEGACY_LITERALS = ("10.10.0.0/24", "10.8.0.0/28")


def test_no_copy_of_generate_rfc1123_variable_default_is_left():
    assert not hasattr(mcp_tf, "generate_rfc1123_variable_default")
    assert not hasattr(gateway_pv, "generate_rfc1123_variable_default")


def test_no_legacy_ip_literal_left_in_the_terraform_server():
    tree = ast.parse(inspect.getsource(mcp_tf))
    consts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert not [c for c in consts if any(lit in c for lit in LEGACY_LITERALS)]


def test_prepare_workspace_has_no_default_injecting_healer():
    module = ast.parse(inspect.getsource(mcp_tf))
    [cls] = [n for n in module.body if isinstance(n, ast.ClassDef) and n.name == "TerraformService"]
    [prep] = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "prepare_workspace"]
    assert "_ensure_default" not in {n.name for n in ast.walk(prep) if isinstance(n, ast.FunctionDef)}


def test_gateway_copy_is_deleted():
    assert not hasattr(gateway_pv, "generate_rfc1123_variable_default")

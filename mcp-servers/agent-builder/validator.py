"""
Project Castor: Agent Builder Security Validator
Enforces supply-chain dependency whitelisting, grounding delimiter boundaries,
and tool safety levels before staging and deploying Google ADK agents.
"""

import ast
import keyword
import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("mcp-agent-builder-validator")

# Lane 14 RT F2: the caller's `requirements` are installed into the Agent Engine runtime in the child project, so the
# allow-list is an EXACT set of canonical names (packaging.utils.canonicalize_name), never a prefix: the ADK §5.4 list
# plus explicitly named google-cloud-* client libraries. Adding a package is an owner decision (row L14-h).
APPROVED_PACKAGES = frozenset({
    "google-adk",
    "google-cloud-aiplatform",
    "google-genai",
    "google-auth",
    "pydantic",
    "httpx",
    "fastapi",
    "requests",
    # explicitly named google-cloud-* client libraries
    "google-cloud-bigquery",
    "google-cloud-discoveryengine",
    "google-cloud-firestore",
    "google-cloud-logging",
    "google-cloud-secret-manager",
    "google-cloud-storage",
})

MAX_TOOL_NAME_LENGTH = 64

REQUIRED_GROUNDING_DELIMITERS = [
    "<retrieved_context>",
    "</retrieved_context>",
]


class RequirementRefused(ValueError):
    pass


def parse_requirement(req_line: Any):
    """One requirement line -> packaging.requirements.Requirement, or RequirementRefused. A real PEP 508 parser (RT
    F2): no direct URL (`name @ url`), no environment marker, a canonical name in APPROVED_PACKAGES, and exactly one
    `==` specifier with a concrete version (a wildcard is not a Version)."""
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import InvalidVersion, Version

    if not isinstance(req_line, str):
        raise RequirementRefused(f"Requirement {req_line!r} must be a string.")
    try:
        req = Requirement(req_line)
    except InvalidRequirement as e:
        raise RequirementRefused(f"Requirement {req_line!r} is not a valid PEP 508 requirement: {e}") from e
    name = canonicalize_name(req.name)
    if req.url:
        raise RequirementRefused(f"Requirement {req_line!r} uses a direct URL; only index packages are allowed.")
    if req.marker is not None:
        raise RequirementRefused(f"Requirement {req_line!r} has an environment marker; markers are not allowed.")
    if name not in APPROVED_PACKAGES:
        raise RequirementRefused(
            f"Package '{name}' is not in the approved dependency list: {', '.join(sorted(APPROVED_PACKAGES))}")
    specs = list(req.specifier)
    if len(specs) != 1 or specs[0].operator != "==":
        raise RequirementRefused(f"Requirement {req_line!r} must pin exactly one version with '=='.")
    try:
        Version(specs[0].version)
    except InvalidVersion as e:
        raise RequirementRefused(f"Requirement {req_line!r} must pin a concrete version (no wildcard).") from e
    return req


def requirement_name(req_line: Any) -> str:
    """Canonical package name of a requirement line (parsed, never split by characters); '' if it does not parse."""
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name

    try:
        return canonicalize_name(Requirement(req_line).name)
    except (InvalidRequirement, TypeError):
        return ""


def validate_dependencies(requirements: List[str]) -> Tuple[bool, List[str]]:
    """
    Validates pip requirements against the exact approved package set (RT F2: parsed with packaging.requirements;
    URLs and markers refused; `==` pins required). Blank lines and whole-line comments are skipped.
    Returns (is_valid, list_of_violations).
    """
    violations = []
    for req in requirements or []:
        if isinstance(req, str) and (not req.strip() or req.strip().startswith("#")):
            continue
        try:
            parse_requirement(req)
        except RequirementRefused as e:
            violations.append(str(e))
    return len(violations) == 0, violations


def validate_grounding_prompt(system_instruction: str, requires_grounding: bool = False) -> Tuple[bool, List[str]]:
    """
    Verifies that system instructions enforce strict XML delimiter boundaries
    when knowledge grounding is configured.
    """
    violations = []
    if not requires_grounding:
        return True, []

    for delim in REQUIRED_GROUNDING_DELIMITERS:
        if delim not in system_instruction:
            violations.append(f"System instruction missing required grounding delimiter boundary: '{delim}'")

    untrusted_advisory = any(
        phrase in system_instruction.lower()
        for phrase in ["untrusted", "do not execute", "never interpret as instructions", "treat as reference"]
    )
    if not untrusted_advisory:
        violations.append(
            "System instruction must explicitly declare that text inside <retrieved_context> is untrusted reference data."
        )

    return len(violations) == 0, violations


def validate_tool_matrix(tools: List[Dict[str, Any]]) -> Tuple[bool, List[str]]:
    """
    Validates tool definitions for safety classification and parameter integrity.
    """
    violations = []
    if not tools:
        return True, []

    seen_names = set()
    for idx, tool in enumerate(tools):
        if not isinstance(tool, dict):
            violations.append(f"Tool #{idx} must be an object.")
            continue
        name = tool.get("name", f"tool_{idx}")
        # Lane 14 PR-1 (FD27-12): a tool name becomes a Python function name in generated code. It must be a plain
        # identifier (str.isidentifier, not a keyword), bounded and unique, so it can never carry code.
        if not isinstance(name, str) or not name.isidentifier() or keyword.iskeyword(name) or not name.isascii():
            violations.append(f"Tool name {name!r} must be a Python identifier (letters, digits, underscore).")
        elif len(name) > MAX_TOOL_NAME_LENGTH:
            violations.append(f"Tool name {name!r} is longer than {MAX_TOOL_NAME_LENGTH} characters.")
        elif name in seen_names:
            violations.append(f"Tool name {name!r} is defined twice.")
        else:
            seen_names.add(name)
        safety = tool.get("safety_level")
        if safety not in ["READ_ONLY", "STATE_MUTATING"]:
            violations.append(
                f"Tool '{name}' must specify safety_level as either 'READ_ONLY' or 'STATE_MUTATING'. Got: {safety}"
            )

        if not tool.get("description"):
            violations.append(f"Tool '{name}' must have a descriptive docstring.")

        if "parameters_schema" not in tool or not isinstance(tool["parameters_schema"], dict):
            violations.append(f"Tool '{name}' must provide a valid JSON Schema in 'parameters_schema'.")

    return len(violations) == 0, violations


# Lane 14 PR-1 (FD27-12): the static check is an `ast` walk (it used to be five regexes that a line break or an alias
# defeated). It reduces risk; it is NOT the isolation boundary: the MCP server never imports, executes or unpickles
# generated code (packaging runs inside the child project's Cloud Build, PR-9).
FORBIDDEN_CALL_NAMES = frozenset({"eval", "exec", "compile", "__import__", "breakpoint", "globals", "locals", "vars"})
FORBIDDEN_MODULES = frozenset({
    "importlib", "subprocess", "pickle", "cloudpickle", "dill", "marshal", "shelve", "ctypes", "socket", "pty",
    "multiprocessing", "builtins", "code", "codeop", "runpy",
})
FORBIDDEN_ATTRIBUTES = frozenset({("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
                                  ("os", "execl"), ("os", "spawnv"), ("os", "fork"), ("os", "kill")})
# Top-level modules generated code may import: the ADK plan §5.4 allow-list (google-adk, google-cloud-*, google-genai,
# pydantic, httpx, fastapi) as module names, a small safe stdlib subset, and the scaffold's own modules.
ALLOWED_IMPORT_ROOTS = frozenset({
    "google", "vertexai", "pydantic", "httpx", "fastapi",
    "typing", "json", "datetime", "dataclasses", "enum", "functools", "logging", "unittest", "uuid",
    "app", "agent", "tools",
})
ALLOWED_GOOGLE_SUBPACKAGES = frozenset({"adk", "genai", "cloud", "auth"})


def _attribute_chain(node: Any) -> List[str]:
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return []


def _import_allowed(module: str) -> bool:
    parts = module.split(".")
    if parts[0] not in ALLOWED_IMPORT_ROOTS or parts[0] in FORBIDDEN_MODULES:
        return False
    if parts[0] == "google":
        return len(parts) >= 2 and parts[1] in ALLOWED_GOOGLE_SUBPACKAGES
    return True


def run_static_security_check(source_code: str) -> Tuple[bool, List[str]]:
    """AST check of generated Python: no eval/exec/compile/__import__, no non-literal getattr/setattr, no importlib /
    subprocess / pickle / os.system / os.popen, imports only from the allow-list. Unparsable source is a violation."""
    try:
        tree = ast.parse(source_code or "")
    except SyntaxError as e:
        return False, [f"Generated source does not parse: {e.msg} (line {e.lineno})."]
    violations: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if not _import_allowed(alias.name):
                    violations.append(f"Import of '{alias.name}' is outside the allow-list.")
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and not _import_allowed(node.module or ""):
                violations.append(f"Import from '{node.module}' is outside the allow-list.")
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_CALL_NAMES:
                violations.append(f"Call to {func.id}() is not allowed in generated code.")
            if isinstance(func, ast.Name) and func.id in ("getattr", "setattr", "delattr"):
                if len(node.args) < 2 or not (isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
                    violations.append(f"{func.id}() with a non-literal attribute name is not allowed.")
        elif isinstance(node, ast.Attribute):
            chain = _attribute_chain(node)
            if chain and chain[0] in FORBIDDEN_MODULES:
                violations.append(f"Use of '{'.'.join(chain)}' is not allowed in generated code.")
            if len(chain) >= 2 and (chain[0], chain[1]) in FORBIDDEN_ATTRIBUTES:
                violations.append(f"Use of '{chain[0]}.{chain[1]}' is not allowed in generated code.")
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_MODULES and isinstance(node.ctx, ast.Load):
            violations.append(f"Reference to '{node.id}' is not allowed in generated code.")
    # Deduplicate, keep order.
    seen: List[str] = []
    for v in violations:
        if v not in seen:
            seen.append(v)
    return len(seen) == 0, seen

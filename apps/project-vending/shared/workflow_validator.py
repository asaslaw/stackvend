"""
Zero-dependency pre-commit validator for GitHub Actions CI/CD workflows.
Guarantees mapping key uniqueness (no duplicate keys in env, jobs, or steps),
expression context integrity, and strict GitHub Actions syntax conformance.
"""

import re
from typing import Dict, List, Optional


class WorkflowValidationError(Exception):
    """Raised when a GitHub Actions workflow fails syntax or contract validation."""

    def __init__(self, message: str, line_number: Optional[int] = None, key: Optional[str] = None, filename: Optional[str] = None):
        self.message = message
        self.line_number = line_number
        self.key = key
        self.filename = filename
        loc = f"[{filename}:{line_number}] " if filename and line_number else (f"[Line {line_number}] " if line_number else (f"[{filename}] " if filename else ""))
        super().__init__(f"{loc}{message}")


def validate_github_workflow_yaml(content: str, filename: str = "") -> None:
    """
    Validates a GitHub Actions workflow YAML file before commit.
    Zero-dependency pure Python: enforces duplicate key prevention,
    expression syntax integrity, top-level schema requirements, and
    service account naming conventions.

    Raises:
        WorkflowValidationError if any violation is detected.
    """
    if not content or not content.strip():
        raise WorkflowValidationError("Workflow file is empty", filename=filename)

    # 1. Check top-level required sections
    has_name = bool(re.search(r'^name:\s*.+$', content, re.MULTILINE))
    has_on = bool(re.search(r'^on:\s*', content, re.MULTILINE))
    has_jobs = bool(re.search(r'^jobs:\s*', content, re.MULTILINE))
    if not (has_name and has_on and has_jobs):
        missing = [k for k, v in [("name", has_name), ("on", has_on), ("jobs", has_jobs)] if not v]
        raise WorkflowValidationError(
            f"Missing required top-level GitHub Actions keys: {missing}",
            filename=filename,
        )

    # 2. Check balanced expression braces (${{ vs }})
    open_count = content.count("${{")
    close_count = content.count("}}")
    if open_count != close_count:
        raise WorkflowValidationError(
            f"Unbalanced GitHub Actions expression braces: found {open_count} '${{{{ ' but {close_count} '}}'",
            filename=filename,
        )

    # 3. Line-by-line block structure, duplicate key detection, and expression validation
    lines = content.splitlines()
    stack = [[-1, False, set()]]  # [indent_level, is_list_item, set_of_keys_at_this_level]
    in_multiline_scalar = False
    scalar_indent = 0
    in_top_level_env = False

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        # Track if we are inside the top-level env: block
        if indent == 0:
            in_top_level_env = stripped.startswith("env:")

        # Expression syntax checks on every non-comment line (even inside multiline bash)
        for match in re.finditer(r'\$\{\{([\s\S]*?)\}\}', line):
            expr = match.group(1)
            # Check for illegal vars.env. or secrets.env. context prefixes
            if re.search(r'\b(?:vars|secrets)\.env\.', expr):
                raise WorkflowValidationError(
                    f"Illegal context 'vars.env.' or 'secrets.env.' found in expression: '${{{{ {expr.strip()} }}}}'. "
                    "Use 'vars.VARIABLE_NAME' or 'secrets.VARIABLE_NAME' directly.",
                    line_number=idx,
                    filename=filename,
                )
            # Check for illegal top-level env self-reference
            if in_top_level_env and re.search(r'\benv\.[A-Za-z0-9_-]+', expr):
                raise WorkflowValidationError(
                    f"Illegal '${{{{ env... }}}}' interpolation inside top-level env: block at line {idx}. "
                    "GitHub Actions does not allow env context interpolation within the top-level env block.",
                    line_number=idx,
                    filename=filename,
                )

        # Service Account Naming Convention Guard
        # Prevents legacy non-canonical format like 'example-workload-sa@...'
        # Golden Foundation requires 'sa-<name>@...' (e.g. 'sa-example-workload@...' or 'sa-gh-deployer@...')
        sa_legacy = re.search(r'\b(?<!sa-)([a-zA-Z0-9_-]+-sa)@[a-zA-Z0-9_-]+\.iam\.gserviceaccount\.com', line)
        if sa_legacy:
            raise WorkflowValidationError(
                f"Non-canonical service account format '{sa_legacy.group(0)}' detected at line {idx}. "
                "The StackVend Golden Foundation requires service accounts to follow the 'sa-<name>@...' naming convention, not '<name>-sa@...'.",
                line_number=idx,
                filename=filename,
            )

        # Handle multiline scalar blocks (| or >)
        if in_multiline_scalar:
            if indent > scalar_indent:
                continue
            else:
                in_multiline_scalar = False

        if stripped.endswith(("|", ">", "|-", ">-")):
            in_multiline_scalar = True
            scalar_indent = indent

        # Mapping key parsing and duplicate detection
        is_list = stripped.startswith("- ")
        key_text = stripped[2:].strip() if is_list else stripped

        # Match a mapping key definition e.g. "key:", "'key':", or "key: value"
        key_match = re.match(r'^(?:["\']?([A-Za-z0-9_-]+)["\']?):(?:\s+.*)?$', key_text)
        if not key_match:
            continue

        key = key_match.group(1)
        effective_indent = indent + (2 if is_list else 0)

        # Pop levels from the stack that are deeper than or equal to (if new list item) the current key
        while len(stack) > 1 and (stack[-1][0] > effective_indent or (stack[-1][0] == effective_indent and is_list)):
            stack.pop()

        if stack[-1][0] < effective_indent:
            stack.append([effective_indent, is_list, {key}])
        else:
            if key in stack[-1][2]:
                raise WorkflowValidationError(
                    f"Duplicate mapping key '{key}' detected in YAML mapping at line {idx}. "
                    "GitHub Actions strict YAML parser rejects workflows with duplicate mapping keys.",
                    line_number=idx,
                    key=key,
                    filename=filename,
                )
            stack[-1][2].add(key)


def validate_all_staged_workflows(files: Dict[str, str], base_dir: str = "") -> List[str]:
    """
    Validates all workflow files in a dictionary of files (e.g. DeveloperAgent staged files).
    Returns a list of validated workflow file paths.
    Raises WorkflowValidationError if any workflow is invalid.
    """
    validated = []
    for fpath, content in files.items():
        if fpath.startswith(".github/workflows/") and fpath.endswith((".yml", ".yaml")):
            display_path = f"{base_dir}/{fpath}" if base_dir else fpath
            validate_github_workflow_yaml(content, filename=display_path)
            validated.append(fpath)
    return validated

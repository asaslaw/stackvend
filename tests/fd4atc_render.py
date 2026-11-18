"""FD-4AT-c test support: the two exact additions FD-4AT-c makes to the generated workload root.

Older byte-identity pins (sha256 / golden files of `generate_golden_main_tf` / `generate_golden_variables_tf` renders)
compare `without_fd4atc(render)` with their unchanged pre-FD-4AT-c values, so they keep proving "nothing else
changed". tests/test_fd4at_c_repository_id.py pins that each addition appears exactly once where expected.
"""

# generate_golden_main_tf: one argument in the module "foundation" block, right after github_repo_full_name.
FOUNDATION_ARG_LINE = "  github_repository_id  = var.github_repository_id\n"

# generate_golden_variables_tf: one variable block right after github_repo_full_name's.
VARIABLE_BLOCK = (
    '\nvariable "github_repository_id" {\n'
    '  description = "GitHub numeric repository id for the WIF condition (FD-4AT-c). Supplied by the platform at '
    'apply time; empty = not pinned."\n'
    "  type        = string\n"
    '  default     = ""\n'
    "}\n"
)


# infra/modules/workload-foundation/base/variables.tf: the module input (with the blank line that follows it).
MODULE_VARIABLE_BLOCK = (
    'variable "github_repository_id" {\n'
    '  description = "FD-4AT-c: GitHub\'s immutable numeric id of github_repo_full_name, resolved by vending and '
    "supplied by the platform at apply time (never by generated code). Empty = not pinned; the repository name + "
    'main-branch condition still applies."\n'
    "  type        = string\n"
    '  default     = ""\n'
    "\n"
    "  validation {\n"
    '    condition     = var.github_repository_id == "" || can(regex("^[1-9][0-9]*$", var.github_repository_id))\n'
    '    error_message = "github_repository_id must be empty or GitHub\'s numeric repository id (digits only)."\n'
    "  }\n"
    "}\n"
    "\n"
)


def without_fd4atc(text: str) -> str:
    """`text` with each FD-4AT-c addition removed once (no-op for text without them)."""
    return text.replace(FOUNDATION_ARG_LINE, "", 1).replace(VARIABLE_BLOCK, "", 1)

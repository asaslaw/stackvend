"""FD-4CI-b-R1-WIF test support: the exact module input FD-4CI-b-R1-WIF adds to
infra/modules/workload-foundation/base/variables.tf (with the blank line that follows it).

Older byte-identity pins of the vendored foundation variables.tf remove it once (`without_r1_wif`) before comparing
with their unchanged values, so they keep proving "nothing else changed"; tests/test_r1_wif_default_branch.py pins
that it appears exactly once.
"""

MODULE_VARIABLE_BLOCK = (
    'variable "github_default_branch" {\n'
    '  description = "FD-4CI-b-R1-WIF: the workload\'s recorded default branch, the only branch whose GitHub Actions '
    'runs the WIF condition accepts (exact refs/heads/<branch>). Supplied by the platform from the workload record; '
    '\\"main\\" = the condition before this input existed."\n'
    '  type        = string\n'
    '  default     = "main"\n'
    '  nullable    = false\n'
    '\n'
    "  # The platform's branch-name grammar (shared/settings.py is_branch_name): 1..100 of letters, digits, '.', '_', "
    "'-',\n"
    '  # \'/\'; not "HEAD"; no leading \'-\', \'/\' or \'.\'; no trailing \'/\' or \'.\'; no \'..\'; no empty path '
    'component; no\n'
    "  # component starting with '.' or ending in '.lock'. Nothing else reaches the condition (no quote, no wildcard).\n"
    '  validation {\n'
    '    condition     = can(regex("^[A-Za-z0-9._/-]{1,100}$", var.github_default_branch)) && '
    'var.github_default_branch != "HEAD"\n'
    '    error_message = "github_default_branch must be 1 to 100 letters, digits, \'.\', \'_\', \'-\' or \'/\' and not '
    'HEAD."\n'
    '  }\n'
    '\n'
    '  validation {\n'
    '    condition     = !can(regex("^[-/.]", var.github_default_branch)) && !can(regex("[/.]$", '
    'var.github_default_branch)) && !can(regex("\\\\.\\\\.", var.github_default_branch))\n'
    '    error_message = "github_default_branch must not start with \'-\', \'/\' or \'.\', end with \'/\' or \'.\', or '
    'contain \'..\'."\n'
    '  }\n'
    '\n'
    '  validation {\n'
    '    condition     = !can(regex("//", var.github_default_branch)) && !can(regex("/\\\\.", '
    'var.github_default_branch)) && !can(regex("\\\\.lock(/|$)", var.github_default_branch))\n'
    '    error_message = "github_default_branch must not have an empty path component, or one that starts with \'.\' '
    'or ends in \'.lock\'."\n'
    '  }\n'
    '}\n'
    '\n'
)


def without_r1_wif(text: str) -> str:
    """`text` with the FD-4CI-b-R1-WIF module input removed once (no-op for text without it)."""
    return text.replace(MODULE_VARIABLE_BLOCK, "", 1)

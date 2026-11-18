"""Lane 14 PR-0b: the exact text PR-0b inserted into golden-module files that the pre-FD-4G goldens hash
(tests/fixtures/fd4g_gatekeeper_golden.json, fd4g_workspace_golden.json). The golden tests remove these insertions and
check the result still hashes to the golden (pins that PR-0b's insertions are the ONLY change to those files), then
expect the current file. `NEW_FILES` are module files PR-0b added (vendored with the module)."""
import hashlib

PR0B_INSERTIONS = {
    "infra/modules/compute-cloudrun/main.tf": (
        "    encryption_key  = var.encryption_key # lane 14 PR-0b: CMEK for regulated profiles (null = Google-managed)\n",
    ),
    "infra/modules/compute-cloudrun/variables.tf": (
        '\nvariable "encryption_key" {\n'
        '  description = "Cloud KMS CryptoKey resource name for the service\'s customer-managed encryption (CMEK), in the '
        'service\'s region. null = Google-managed encryption."\n'
        "  type        = string\n  default     = null\n}\n",
    ),
    "infra/modules/workload-foundation/base/database.tf": (
        "\n  # Lane 14 PR-0b: CMEK for regulated profiles (no block = Google-managed encryption). Set at creation only.\n"
        '  dynamic "cmek_config" {\n    for_each = var.kms_key_name != null ? [1] : []\n    content {\n'
        "      kms_key_name = var.kms_key_name\n    }\n  }\n",
    ),
    "infra/modules/workload-foundation/base/registry.tf": (
        "  kms_key_name  = var.kms_key_name # lane 14 PR-0b: CMEK for regulated profiles (null = Google-managed)\n",
    ),
}
NEW_FILES = ("infra/modules/workload-foundation/base/compliance.tf",)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def pre_pr0b(path: str, text: str) -> str:
    """`text` with PR-0b's insertions removed (each must occur exactly once)."""
    for snippet in PR0B_INSERTIONS.get(path, ()):
        assert text.count(snippet) == 1, (path, snippet[:60])
        text = text.replace(snippet, "", 1)
    return text

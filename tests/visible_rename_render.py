"""VISIBLE-RENAME test support (owner 10-26): the exact text edits that made generated text and agent personas say
StackVend instead of (Project) Castor.

Older byte-identity pins (sha256 of golden renders, persona prompts, verifier output) compare
`pre_visible_rename(text)` with their unchanged pre-rename values, so they keep proving "nothing else changed".
tests/test_visible_rename.py pins that the new wording is in place and the old wording is gone.
"""

# (old, new) pairs, exactly as the rename commit changed them. Only pairs whose new text is unique to the rename
# (never written by anything else) are listed, so the reverse mapping cannot touch unrelated text.
PAIRS = (
    # developer_agent/terraform_engine.py golden root files
    ("# PROJECT CASTOR: WORKLOAD INFRASTRUCTURE (DETERMINISTIC GOLDEN FOUNDATION)",
     "# STACKVEND: WORKLOAD INFRASTRUCTURE (DETERMINISTIC GOLDEN FOUNDATION)"),
    ("# PROJECT CASTOR: WORKLOAD OUTPUTS", "# STACKVEND: WORKLOAD OUTPUTS"),
    ("# PROJECT CASTOR: DECLARATIVE STATE MIGRATION GUARDS", "# STACKVEND: DECLARATIVE STATE MIGRATION GUARDS"),
    ("# PROJECT CASTOR: GOOGLE CLOUD FIRESTORE COMPOSITE INDEXES", "# STACKVEND: GOOGLE CLOUD FIRESTORE COMPOSITE INDEXES"),
    # gatekeeper_agent/verifier.py package init
    ("# Auto-generated package init by Castor Platform\n", "# Auto-generated package init by StackVend\n"),
    # persona prompts (developer_agent/juniors/*, lead_orchestrator.py)
    *((f"You are Project Castor's {p}", f"You are StackVend's {p}") for p in (
        "Junior Backend Engineer.", "Junior Frontend Engineer.", "Junior QA & Test Engineer.",
        "Junior DevOps Engineer.", "Junior IaC / Cloud Engineer.", "Staff Lead Developer Agent.")),
    ("adhering strictly to Project Castor's Enterprise Golden Modules",
     "adhering strictly to StackVend's Enterprise Golden Modules"),
    ("   - Project Castor workloads strictly rely on", "   - StackVend workloads strictly rely on"),
    # visible-rename-3: golden-module header comments (infra/modules/**, payload copies) and composite-bundle headers.
    # Anchored at the start of a line; "# STACKVEND: <section>" is written by nothing else.
    *((f"\n# PROJECT CASTOR: {s}", f"\n# STACKVEND: {s}") for s in (
        "COMPUTE ARCHETYPE - ", "NETWORKING ARCHETYPE - ", "PARAMETERIZED MODULE - ", "WORKLOAD FOUNDATION - ",
        "GOOGLE CLOUD WORKFLOWS ORCHESTRATION MODULE\n", "WORKLOAD AUTHENTICATION MODULE (")),
    ("\n# Declarative enablement of core GCP APIs required by all Castor workloads.\n",
     "\n# Declarative enablement of core GCP APIs required by all StackVend workloads.\n"),
    ("\n# Castor Composite Bundle: ", "\n# StackVend Composite Bundle: "),
    # visible-rename-3b (owner 10-26): golden-module attribute display text, whole lines (attribute name included)
    *((f"  {a} = \"{o}\"\n", f"  {a} = \"{n}\"\n") for a, o, n in (
        ("description            ", "Enterprise Google Cloud VPC Network managed by Project Castor",
         "Enterprise Google Cloud VPC Network managed by StackVend"),
        ("display_name             ", "Castor GitHub Pool", "StackVend GitHub Pool"),
        ("description               ", "Serverless BigQuery dataset managed by Castor",
         "Serverless BigQuery dataset managed by StackVend"),
        ("description", "Scheduled cron job managed by Castor", "Scheduled cron job managed by StackVend"),
        ("description    ", "Workload orchestration workflow state machine managed by Castor",
         "Workload orchestration workflow state machine managed by StackVend"),
        ("default    ", "Managed Vertex AI Endpoint provisioned by Project Castor",
         "Managed Vertex AI Endpoint provisioned by StackVend"),
        ("description", "Project Castor product/workload identifier for labeling and naming defaults.",
         "StackVend product/workload identifier for labeling and naming defaults."),
        ("description", "Foundational GCP APIs required by all Castor workloads",
         "Foundational GCP APIs required by all StackVend workloads"))),
)


def pre_visible_rename(text: str) -> str:
    """`text` with each VISIBLE-RENAME edit reverted (no-op for text without them)."""
    for old, new in PAIRS:
        text = text.replace(new, old)
    return text

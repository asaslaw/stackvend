"""
Project Castor: Dynamic Container Resource Sizing & Out-Of-Memory (OOM) Guardrails
Analyzes Python requirements.txt and user spec intent to determine optimal Cloud Run
memory and CPU allocations, startup probe grace periods, and CI/CD parameters.
"""

from dataclasses import dataclass
import re
from typing import Dict, List, Optional, Set, Tuple


@dataclass(frozen=True)
class ContainerSizingProfile:
    tier: int
    memory_limit: str       # e.g. "512Mi", "1Gi", "2Gi"
    cpu_limit: str          # Terraform millicores: "1000m", "2000m"
    gcloud_cpu: str         # gcloud CLI integer: "1", "2"
    initial_delay_secs: int # Startup probe delay: 2, 4, 6
    failure_threshold: int  # Startup probe retries: 20, 25, 30
    matched_packages: List[str]
    matched_intents: List[str]


# Package Classification Tiers
TIER_2_DATA_PACKAGES: Set[str] = {
    "pandas", "numpy", "pillow", "pil", "openpyxl", "reportlab",
    "weasyprint", "xlsxwriter", "matplotlib", "seaborn", "duckdb",
    "polars", "pyarrow", "scikit-image", "xlrd", "pdfplumber", "pypdf",
    "pdfminer", "pypdf2", "fitz", "pymupdf", "tabula-py", "imageio"
}

TIER_3_COMPUTE_PACKAGES: Set[str] = {
    "torch", "torchvision", "torchaudio", "tensorflow", "transformers",
    "scipy", "scikit-learn", "sklearn", "playwright", "selenium",
    "spacy", "nltk", "cv2", "opencv-python", "opencv-python-headless",
    "fastai", "xgboost", "lightgbm", "catboost", "onnx", "onnxruntime",
    "sentence-transformers", "diffusers", "accelerate"
}

# Spec Intent Keyword Triggers (Fallback / Pre-code Analysis)
TIER_2_SPEC_KEYWORDS: Set[str] = {
    "pandas", "excel", "spreadsheet", "data analysis", "csv processing",
    "image generation", "image resize", "pdf generation", "pdf report",
    "matplotlib", "chart generation", "large dataset", "data frame", "dataframe"
}

TIER_3_SPEC_KEYWORDS: Set[str] = {
    "machine learning", "deep learning", "neural network", "pytorch",
    "tensorflow", "transformers", "huggingface", "playwright", "web scraping",
    "browser automation", "headless browser", "model training", "inference",
    "computer vision", "nlp"
}


def extract_package_names(requirements_text: str) -> Set[str]:
    """Extracts normalized lowercase package names from requirements.txt text."""
    packages = set()
    for line in requirements_text.splitlines():
        line = line.strip().split("#")[0].strip()
        if not line:
            continue
        # Remove version constraints (==, >=, <=, ~=, !=, <, >, ;)
        pkg_name = re.split(r"[<>=!~;\[]", line)[0].strip().lower()
        if pkg_name:
            packages.add(pkg_name)
    return packages


def calculate_container_sizing(
    requirements_text: str = "",
    spec_text: str = "",
) -> ContainerSizingProfile:
    """
    Analyzes requirements.txt and spec_text to determine the optimal Cloud Run sizing profile.
    """
    packages = extract_package_names(requirements_text)
    spec_lower = spec_text.lower()

    matched_tier3_pkgs = sorted(list(packages.intersection(TIER_3_COMPUTE_PACKAGES)))
    matched_tier3_intents = [kw for kw in sorted(list(TIER_3_SPEC_KEYWORDS)) if kw in spec_lower]

    if matched_tier3_pkgs or matched_tier3_intents:
        return ContainerSizingProfile(
            tier=3,
            memory_limit="2Gi",
            cpu_limit="2000m",
            gcloud_cpu="2",
            initial_delay_secs=6,
            failure_threshold=30,
            matched_packages=matched_tier3_pkgs,
            matched_intents=matched_tier3_intents,
        )

    matched_tier2_pkgs = sorted(list(packages.intersection(TIER_2_DATA_PACKAGES)))
    matched_tier2_intents = [kw for kw in sorted(list(TIER_2_SPEC_KEYWORDS)) if kw in spec_lower]

    if matched_tier2_pkgs or matched_tier2_intents:
        return ContainerSizingProfile(
            tier=2,
            memory_limit="1Gi",
            cpu_limit="1000m",
            gcloud_cpu="1",
            initial_delay_secs=4,
            failure_threshold=25,
            matched_packages=matched_tier2_pkgs,
            matched_intents=matched_tier2_intents,
        )

    return ContainerSizingProfile(
        tier=1,
        memory_limit="512Mi",
        cpu_limit="1000m",
        gcloud_cpu="1",
        initial_delay_secs=2,
        failure_threshold=20,
        matched_packages=[],
        matched_intents=[],
    )


def resolve_workload_sizing(
    files: Optional[Dict[str, str]] = None,
    requirements_text: str = "",
    spec_text: str = "",
) -> ContainerSizingProfile:
    """
    Scans all apps/*/requirements.txt in files, root requirements.txt,
    and user spec_text, returning the maximum resource sizing profile required.
    """
    combined_reqs = [requirements_text] if requirements_text else []

    if files:
        for path, content in files.items():
            norm_path = path.replace("\\", "/").lower()
            if norm_path == "requirements.txt" or (norm_path.startswith("apps/") and norm_path.endswith("/requirements.txt")):
                combined_reqs.append(content)

    full_reqs = "\n".join(combined_reqs)
    return calculate_container_sizing(requirements_text=full_reqs, spec_text=spec_text)

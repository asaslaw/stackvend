"""FD-4A: requirement (distribution) name != import name in the gatekeeper's shadow checks.

GATE.ENTRYPOINT_SHADOWED (verifier.verify_container_entrypoint_imports, blocking) and the add-only `__init__.py`
scaffolding shield (verifier.purge_shadowed_package_files + preflight_validator.validate_and_heal_python_packages) read
a requirement through the top-level import names its distribution installs (gatekeeper_agent/distribution_imports.py),
never by folding its name. Both directions for the six classic mismatches, namespace packages, requirement-line syntax,
unknown distributions (no guess, no block), the metadata source and Do No Harm. Hermetic: no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from importlib.metadata import PackageNotFoundError, distribution

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent.validators.python_layout import PythonLayoutValidator  # noqa: E402
from developer_agent.validators.base import ValidationContext  # noqa: E402
from gatekeeper_agent import distribution_imports as di  # noqa: E402
from gatekeeper_agent.requirements_contract import canonical_name  # noqa: E402
from gatekeeper_agent.verifier import SynthesisVerifierAgent  # noqa: E402

# (requirement as an AI writes it, the import name it really provides, the "import name" the old folding guessed)
SIX = [
    ("beautifulsoup4", "bs4", "beautifulsoup4"),
    ("google-cloud-storage", "google", "google_cloud_storage"),
    ("PyYAML", "yaml", "pyyaml"),
    ("python-dateutil", "dateutil", "python_dateutil"),
    ("Pillow", "PIL", "pillow"),
    ("scikit-learn", "sklearn", "scikit_learn"),
]
IMPORT_LINE = {
    "bs4": "from bs4 import BeautifulSoup\n",
    "google": "from google.cloud import storage\n",
    "yaml": "import yaml\n",
    "dateutil": "from dateutil import parser\n",
    "PIL": "from PIL import Image\n",
    "sklearn": "import sklearn.linear_model\n",
}


@pytest.fixture
def table_only(monkeypatch):
    """Answer from the explicit table only (the test interpreter's installed metadata ignored)."""
    monkeypatch.setattr(di, "_installed_top_levels", lambda: {})


def shadow_errors(files):
    _, errors = SynthesisVerifierAgent("p").verify_container_entrypoint_imports(dict(files))
    return errors


def gate_codes(files):
    return [(d.code, d.file) for d in SynthesisVerifierAgent("p").verify(dict(files))]


# ---------------------------------------------------------------------------------------------- the name -> import map
@pytest.mark.parametrize("dist,module,_folded", SIX)
def test_six_mismatches_resolve_to_their_import_names(table_only, dist, module, _folded):
    assert module in di.top_level_imports(dist)


@pytest.mark.parametrize("spelling", ["PyYAML", "pyyaml", "PYYAML", "python_dateutil", "Python.Dateutil",
                                      "python--dateutil", "Scikit_Learn"])
def test_pep503_spellings_of_a_name_resolve_alike(table_only, spelling):
    assert di.top_level_imports(spelling) == di.top_level_imports(canonical_name(spelling)) is not None


def test_unknown_distribution_has_no_answer(table_only):
    assert di.top_level_imports("acme-widgets-sdk") is None   # never a guess like `acme_widgets_sdk`


def test_requirement_lines_extras_markers_specifiers_comments_and_options(table_only):
    text = ("uvicorn[standard]>=0.28.0 ; python_version >= '3.10'  # server\n"
            "PyYAML==6.0.3\n"
            "requests ~= 2.31\n"
            "google-cloud-pubsub>=2.19,<3\n"
            "-r base.txt\n"
            "--index-url https://example.invalid/simple\n"
            "# a comment line\n"
            "\n"
            "acme-widgets-sdk==1.0\n")
    imports, unknown = di.requirement_import_roots([text])
    assert imports == {"uvicorn", "yaml", "_yaml", "requests", "google"}
    assert unknown == {"acme-widgets-sdk"}


def test_metadata_source_is_used_and_artefact_names_dropped(monkeypatch):
    import importlib.metadata as md
    fake = {"acmew": ["Acme_Widgets"], "acme/sub": ["Acme_Widgets"], "__pycache__": ["Acme_Widgets"],
            "x.pth": ["Acme_Widgets"], "yaml": ["PyYAML"]}
    monkeypatch.setattr(md, "packages_distributions", lambda: fake)
    di._installed_top_levels.cache_clear()
    try:
        assert di.top_level_imports("acme-widgets") == frozenset({"acmew"})
        assert di.top_level_imports("pyyaml") == frozenset({"yaml"})     # installed metadata wins over the table
        assert di.top_level_imports("scikit-learn") == frozenset({"sklearn"})   # not installed: the table answers
    finally:
        di._installed_top_levels.cache_clear()


def test_table_agrees_with_installed_metadata():
    """Every table row whose distribution is installed in this interpreter equals its real top-level names."""
    di._installed_top_levels.cache_clear()
    installed = di._installed_top_levels()
    checked = 0
    for name, roots in di.KNOWN_TOP_LEVEL_IMPORTS.items():
        assert name == canonical_name(name), name
        try:
            distribution(name)
        except PackageNotFoundError:
            continue
        if name in installed:
            assert frozenset(roots) == installed[name], f"update KNOWN_TOP_LEVEL_IMPORTS[{name!r}] to {sorted(installed[name])}"
            checked += 1
    assert checked >= 20   # the gateway's own dependencies are installed in the test interpreter


def test_catalog_distributions_all_have_a_row():
    """Every distribution the closed-world catalog appends (pypi_catalog, HE-03) has a table row, and its catalog
    import key's root is one of that row's import names (except the catalog's `protobuf` key, whose real import is
    `google.protobuf`)."""
    from gatekeeper_agent.pypi_catalog import CANONICAL_PYPI_CATALOG
    from gatekeeper_agent.requirements_contract import requirement_name
    for imp, spec in CANONICAL_PYPI_CATALOG.items():
        name = requirement_name(spec)
        assert name in di.KNOWN_TOP_LEVEL_IMPORTS, name
        if imp != "protobuf":
            assert imp.split(".")[0] in di.KNOWN_TOP_LEVEL_IMPORTS[name], (imp, name)


# ------------------------------------------------------------------------ GATE.ENTRYPOINT_SHADOWED, both directions
@pytest.mark.parametrize("dist,module,_folded", SIX)
def test_shadow_of_the_real_import_name_is_blocked(table_only, dist, module, _folded):
    """False negative removed: the old check compared `import yaml` with `pyyaml` and let the shadow through."""
    files = {
        "apps/svc/requirements.txt": f"fastapi>=0.110.0\n{dist}>=1.0\n",
        "apps/svc/main.py": IMPORT_LINE[module],
        f"apps/svc/{module}/__init__.py": "",
    }
    errors = shadow_errors(files)
    assert len(errors) == 1
    assert f"imports external module '{module}'" in errors[0]
    assert ("GATE.ENTRYPOINT_SHADOWED", "apps/svc/main.py") in gate_codes(files)


@pytest.mark.parametrize("dist,module,folded", SIX)
def test_local_package_named_like_the_distribution_is_not_blocked(table_only, dist, module, folded):
    """False positive removed: a local package that only shares the distribution's (folded) name shadows nothing."""
    files = {
        "apps/svc/requirements.txt": f"{dist}\n",
        "apps/svc/main.py": f"import {folded}\n{IMPORT_LINE[module]}",
        f"apps/svc/{folded}/__init__.py": "",
    }
    assert shadow_errors(files) == []
    assert gate_codes(files) == []


def test_namespace_package_google_shadowed_by_a_local_google_package(table_only):
    files = {
        "apps/svc/requirements.txt": "google-cloud-storage>=2.14.0\ngoogle-cloud-pubsub==2.27.1\n",
        "apps/svc/main.py": "from google.cloud import storage, pubsub_v1\nimport google.auth\n",
        "apps/svc/google/__init__.py": "",
        "apps/svc/google/helpers.py": "X = 1\n",
    }
    errors = shadow_errors(files)
    assert len(errors) == 1 and "'google'" in errors[0]


def test_extras_and_markers_no_longer_hide_a_shadow(table_only):
    """The old `re.split('[=<>!~]')` kept `uvicorn[standard]` / `requests ; python_version...` as names."""
    files = {
        "apps/svc/requirements.txt": "uvicorn[standard]>=0.28.0\nrequests ; python_version >= '3.10'\n",
        "apps/svc/main.py": "import uvicorn\nimport requests\n",
        "apps/svc/uvicorn/__init__.py": "",
        "apps/svc/requests/__init__.py": "",
    }
    errors = shadow_errors(files)
    assert [e.split("'")[3] for e in errors] == ["requests", "uvicorn"]


def test_root_requirements_still_count(table_only):
    files = {
        "requirements.txt": "PyYAML\n",
        "apps/svc/main.py": "import yaml\n",
        "apps/svc/yaml/__init__.py": "",
    }
    assert len(shadow_errors(files)) == 1


def test_stdlib_shadow_unchanged(table_only):
    files = {"apps/svc/main.py": "import json\n", "apps/svc/json/__init__.py": ""}
    assert len(shadow_errors(files)) == 1


def test_unknown_distribution_with_same_named_local_package_is_blocked(table_only):
    """Option B (Fable RT, owner pending): the import names of `acme-widgets-sdk` are unknown, so the platform cannot
    rule out that a local `acme_widgets_sdk` package hides it: blocked as before (distinct message), and the
    report-only V3d REQ.LOCAL_MODULE_NAME still reports the line."""
    files = {
        "apps/svc/requirements.txt": "acme-widgets-sdk==1.0\n",
        "apps/svc/main.py": "import acme_widgets_sdk\n",
        "apps/svc/acme_widgets_sdk/__init__.py": "",
    }
    errors = shadow_errors(files)
    assert len(errors) == 1
    assert "cannot confirm its import names: rename the local package or remove the requirement" in errors[0]
    assert gate_codes(files) == [("GATE.ENTRYPOINT_SHADOWED", "apps/svc/main.py")]
    report = PythonLayoutValidator().validate(ValidationContext.build(files, ownership=lambda p: None))
    assert ("REQ.LOCAL_MODULE_NAME", "apps/svc/requirements.txt") in [(d.code, d.file) for d in report]


def test_unknown_distribution_unrelated_local_package_not_blocked(table_only):
    files = {
        "apps/svc/requirements.txt": "acme-widgets-sdk==1.0\n",
        "apps/svc/main.py": "import acme_widgets_sdk\nfrom routers import items\n",
        "apps/svc/routers/__init__.py": "",
        "apps/svc/routers/items.py": "X = 1\n",
    }
    assert shadow_errors(files) == []


# ------------------------------------------------- FD-4A-b: init-less local `X/` behind an installed regular package X
@pytest.mark.parametrize("main_py", ["import yaml.helpers\n", "from yaml.helpers import load_all\n",
                                     "import yaml.helpers.deep as d\n", "from yaml import helpers\n",
                                     "from yaml import helpers as h, safe_load\n"])
@pytest.mark.parametrize("local", ["apps/svc/yaml/helpers.py", "apps/svc/yaml/helpers/__init__.py",
                                   "apps/svc/yaml/helpers/deep.py"])
def test_unreachable_local_submodule_behind_external_package_is_blocked(table_only, main_py, local):
    files = {"apps/svc/requirements.txt": "PyYAML==6.0.3\n", "apps/svc/main.py": main_py, local: "X = 1\n"}
    errors = shadow_errors(files)
    assert len(errors) == 1
    assert ("the local file cannot be imported: the installed package (or its own module of that name) is imported "
            "instead") in errors[0]
    assert "'yaml.helpers'" in errors[0]
    assert gate_codes(files) == [("GATE.ENTRYPOINT_SHADOWED", "apps/svc/main.py")]


def test_unreachable_submodule_negative_renamed_local_dir(table_only):
    """Negative: the same tree with the local dir renamed (`yaml_tools/`) and imported by that name -> no finding."""
    files = {"apps/svc/requirements.txt": "PyYAML==6.0.3\n",
             "apps/svc/main.py": "import yaml\nimport yaml_tools.helpers\n",
             "apps/svc/yaml_tools/helpers.py": "X = 1\n"}
    assert shadow_errors(files) == []
    assert gate_codes(files) == []


@pytest.mark.parametrize("files", [
    # a real PyYAML submodule, no local yaml/ dir
    {"apps/svc/requirements.txt": "PyYAML\n", "apps/svc/main.py": "import yaml.constructor\n"},
    # local yaml/ dir exists but holds a different submodule
    {"apps/svc/requirements.txt": "PyYAML\n", "apps/svc/main.py": "import yaml.constructor\n",
     "apps/svc/yaml/helpers.py": "X = 1\n"},
    # namespace package: a local init-less google/ merges with the installed google namespace
    {"apps/svc/requirements.txt": "google-cloud-storage\n", "apps/svc/main.py": "import google.mylocal\n",
     "apps/svc/google/mylocal.py": "X = 1\n"},
    # requirement not declared: not an external package of this service
    {"apps/svc/requirements.txt": "fastapi\n", "apps/svc/main.py": "import yaml.helpers\n",
     "apps/svc/yaml/helpers.py": "X = 1\n"},
    # unknown distribution: no fact about its import names
    {"apps/svc/requirements.txt": "acme-widgets-sdk\n", "apps/svc/main.py": "import acme_widgets_sdk.helpers\n",
     "apps/svc/acme_widgets_sdk/helpers.py": "X = 1\n"},
    # `from X import name` where the local dir holds a different file: no finding
    {"apps/svc/requirements.txt": "PyYAML\n", "apps/svc/main.py": "from yaml import safe_load\n",
     "apps/svc/yaml/other.py": "X = 1\n"},
    # star import names no submodule
    {"apps/svc/requirements.txt": "PyYAML\n", "apps/svc/main.py": "from yaml import *\n",
     "apps/svc/yaml/other.py": "X = 1\n"},
    # tiktoken's native PEP 420 plugin namespace: a local init-less tiktoken_ext/ is one more portion
    {"apps/svc/requirements.txt": "tiktoken\n", "apps/svc/main.py": "import tiktoken_ext.my_enc\n",
     "apps/svc/tiktoken_ext/my_enc.py": "ENCODING_CONSTRUCTORS = {}\n"},
    {"apps/svc/requirements.txt": "tiktoken\n", "apps/svc/main.py": "from tiktoken_ext import my_enc\n",
     "apps/svc/tiktoken_ext/my_enc.py": "ENCODING_CONSTRUCTORS = {}\n"},
])
def test_unreachable_submodule_no_false_positive(table_only, files):
    assert shadow_errors(files) == []


def test_regular_local_package_reports_the_shadow_once(table_only):
    files = {"apps/svc/requirements.txt": "PyYAML\n", "apps/svc/main.py": "import yaml.helpers\n",
             "apps/svc/yaml/__init__.py": "", "apps/svc/yaml/helpers.py": "X = 1\n"}
    errors = shadow_errors(files)
    assert len(errors) == 1 and "shadowed by local package directory" in errors[0]


def test_namespace_list_matches_the_installed_specs():
    """NAMESPACE_TOP_LEVELS is exact for every table import name findable in this interpreter: listed iff its spec
    is a namespace package (`mysql` is the documented conservative entry, not installed here)."""
    import importlib.util
    names = {m for roots in di.KNOWN_TOP_LEVEL_IMPORTS.values() for m in roots}
    checked = 0
    for name in sorted(names):
        try:
            spec = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            continue
        if spec is None:
            continue
        is_namespace = spec.origin is None and spec.submodule_search_locations is not None
        assert (name in di.NAMESPACE_TOP_LEVELS) == is_namespace, name
        checked += 1
    assert checked >= 20
    assert {"google", "opentelemetry", "tiktoken_ext"} <= di.NAMESPACE_TOP_LEVELS


def test_valid_app_with_correct_requirements_has_no_finding_and_is_unchanged(table_only):
    """Negative test (Do No Harm): a valid app whose imports all differ from their requirement names."""
    files = {
        "apps/svc/requirements.txt": ("fastapi>=0.110.0\nuvicorn[standard]>=0.28.0\nPyYAML==6.0.3\n"
                                      "beautifulsoup4>=4.12\npython-dateutil>=2.9.0\nPillow>=10.2.0\n"
                                      "scikit-learn>=1.4\ngoogle-cloud-storage>=2.14.0\n"),
        "apps/svc/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
        "apps/svc/main.py": ("import os\nimport yaml\nfrom bs4 import BeautifulSoup\nfrom dateutil import parser\n"
                             "from PIL import Image\nimport sklearn\nfrom google.cloud import storage\n"
                             "from fastapi import FastAPI\nfrom routers import items\n\napp = FastAPI()\n"
                             "app.include_router(items.router)\n\n\n@app.get('/health')\ndef health():\n"
                             "    return {'ok': True}\n"),
        "apps/svc/routers/__init__.py": "",
        "apps/svc/routers/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
    }
    snapshot = dict(files)
    assert shadow_errors(files) == []
    assert gate_codes(files) == []
    cured, passed, errors = SynthesisVerifierAgent("p").verify_and_cure(dict(files), product_id="p")
    assert passed is True, errors
    for path, text in snapshot.items():
        assert cured[path] == text, path
    assert files == snapshot


# ------------------------------------------------------------- __init__.py scaffolding shield (verifier + preflight)
def _scaffold_both(files):
    # FD-55 W5 (G26): the preflight copy is deleted; the verifier's pass is the one scaffolding rule
    out_v, _ = SynthesisVerifierAgent("p").purge_shadowed_package_files(dict(files))
    return (out_v,)


@pytest.mark.parametrize("req,dirname", [("PyYAML\n", "yaml"), ("google-cloud-storage\n", "google"),
                                         ("Pillow\n", "PIL"), ("beautifulsoup4\n", "bs4")])
def test_scaffolding_never_turns_a_dir_into_a_package_shadowing_an_import_name(table_only, req, dirname):
    files = {
        "apps/svc/requirements.txt": req,
        "apps/svc/main.py": "import os\n",
        f"apps/svc/{dirname}/helpers.py": "X = 1\n",
        "apps/svc/routers/items.py": "Y = 2\n",
    }
    for out in _scaffold_both(files):
        assert f"apps/svc/{dirname}/__init__.py" not in out
        assert "apps/svc/routers/__init__.py" in out           # a legitimate package still gets its init
        for path, text in files.items():
            assert out[path] == text, path                     # add-only


def test_scaffolding_shield_by_requirement_name_kept(table_only):
    """The old shield (requirement name, `-` -> `_`) is kept: only more dirs are shielded, never fewer."""
    files = {
        "apps/svc/requirements.txt": "acme-widgets-sdk\nPillow\n",
        "apps/svc/acme_widgets_sdk/x.py": "X = 1\n",
        "apps/svc/pillow/x.py": "X = 1\n",
    }
    for out in _scaffold_both(files):
        assert "apps/svc/acme_widgets_sdk/__init__.py" not in out
        assert "apps/svc/pillow/__init__.py" not in out


def test_scaffolding_valid_tree_unchanged(table_only):
    """Negative test: a tree that already has every init and no shielded dir comes back byte-identical."""
    files = {
        "apps/__init__.py": "",
        "apps/svc/__init__.py": "",
        "apps/svc/requirements.txt": "PyYAML\ngoogle-cloud-storage\n",
        "apps/svc/main.py": "import yaml\n",
        "apps/svc/routers/__init__.py": "",
        "apps/svc/routers/items.py": "Y = 2\n",
    }
    for out in _scaffold_both(files):
        assert out == files

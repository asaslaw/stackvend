"""Step 2 S2-A A3/A4/A5 (register HS-13, HS-14, HS-15): the Python R-class cures that edited the AI's code between
repair iterations are gone; typed V3a diagnostics replace them. Hermetic: no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)


def _calls_in(path, func_name):
    src = open(os.path.join(REPO_ROOT, path)).read()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", None)
                    for n in ast.walk(node) if isinstance(n, ast.Call)}
    raise AssertionError(f"{func_name} not found in {path}")


# ------------------------------------------------------------------------------------------------ A3 HC-15 / HB-31
def test_hc15_is_never_called_by_verify_and_cure_and_is_deleted():
    calls = _calls_in("apps/orchestrator-gateway/gatekeeper_agent/verifier.py", "verify_and_cure")
    assert "cure_syntax_errors" not in calls
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    assert not hasattr(SynthesisVerifierAgent, "cure_syntax_errors")  # FD-55 W1 (FD55-W1): the uncalled body is gone


def test_hb31_syntax_steps_are_gone():
    # FD-4AD deleted the rest of HB-31 (pre_ast_normalize, ContainerImportTransformer); FD-55 W1 (X9) deleted the
    # tombstone module itself
    import importlib.util
    assert importlib.util.find_spec("gatekeeper_agent.ast_transformer") is None
    assert not os.path.exists(os.path.join(GATEWAY, "gatekeeper_agent", "ast_transformer.py"))


def test_syntax_broken_test_shapes_are_reported_not_edited():
    """The three R2c shapes (01-r3, 02-r2, 03-r3: broken test files) reach V3a as PY.SYNTAX at iteration 0 and are
    byte-identical through verify_and_cure."""
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    shapes = {
        "tests/test_a.py": "def test_x():\n    with patch('a') as a,\n         patch('b') as b:\n        pass\n",
        "tests/test_b.py": "try:\n    import x\ntry_fallback:\n    pass\nexcept ImportError:\n    pass\n",
        "tests/test_c.py": "@app.get('/x')\nflag = False\n@app.get('/y')\ndef y():\n    return 1\n",
    }
    cured, passed, errors = SynthesisVerifierAgent("svc").verify_and_cure(dict(shapes), product_id="svc")
    assert passed is False
    for k, v in shapes.items():
        assert cured[k] == v
    pytest.importorskip("hcl2")
    from developer_agent.validators import ValidationContext
    from developer_agent.validators.step1 import PythonSyntaxValidator
    from shared.artifact_ownership import Ownership
    ctx = ValidationContext.build(shapes, ownership=lambda p: Ownership.LLM_AUTHORED)
    assert sorted(d.file for d in PythonSyntaxValidator().validate(ctx)) == sorted(shapes)


# ------------------------------------------------------------------------------------------------ A4 HC-16 / A5 flip
def _vctx(files, llm=None):
    from developer_agent.validators import ValidationContext
    from shared.artifact_ownership import Ownership
    llm = set(files) if llm is None else set(llm)
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p in llm
                                   else Ownership.PLATFORM_RENDERED)


GOOD_RETRY = ("from google.api_core.retry import Retry, if_transient_error\n"
              "from google.api_core import exceptions\n\nR = Retry(predicate=if_transient_error)\n"
              "E = exceptions.ServiceUnavailable\n")
BAD_RETRY = ("from google.api_core import exceptions as gexc\n\n"
             "def pred(e):\n    return gexc.is_transient_error(e)\n")


def test_hc16_rename_is_gone_and_valid_sdk_use_is_unchanged():
    pytest.importorskip("hcl2")
    pytest.importorskip("google.api_core")
    from developer_agent.validators.step1 import SdkAttributeValidator
    from gatekeeper_agent.verifier import SynthesisVerifierAgent

    def validate_and_heal_python_packages(files):   # FD-55 W5 (G26): the gatekeeper's pass is the one rule
        return SynthesisVerifierAgent(product_id="svc").purge_shadowed_package_files(dict(files))
    files = {"apps/svc/main.py": BAD_RETRY, "apps/svc/ok.py": GOOD_RETRY}
    healed, _ = validate_and_heal_python_packages(dict(files))
    assert healed["apps/svc/main.py"] == BAD_RETRY            # tombstone: no rename, no import prepended
    assert healed["apps/svc/ok.py"] == GOOD_RETRY             # Do No Harm
    got = SdkAttributeValidator().validate(_vctx(files))
    assert [(d.code, d.file, d.symbol) for d in got] == [
        ("PY.ATTRIBUTE", "apps/svc/main.py", "google.api_core.exceptions.is_transient_error")]


def test_sdk_attribute_check_is_exact_to_the_imported_module():
    pytest.importorskip("hcl2")
    pytest.importorskip("google.api_core")
    from developer_agent.validators.step1 import SdkAttributeValidator
    # a local object named `exceptions` (not from google.api_core) is never judged
    local = "import myexc as exceptions\nx = exceptions.is_transient_error\n"
    assert SdkAttributeValidator().validate(_vctx({"a.py": local})) == []
    comment = "# exceptions.is_transient_error\ns = 'gexc.is_transient_error'\n"
    assert SdkAttributeValidator().validate(_vctx({"a.py": comment})) == []


def test_undefined_name_blocks_on_llm_files_only():
    pytest.importorskip("hcl2")
    pytest.importorskip("pyflakes")
    from developer_agent.validators.step1 import UndefinedNameValidator, build_step1_stack
    files = {"apps/a/x.py": "class J(str, Enum):\n    A = 'a'\n", "apps/a/copy.py": "y = Literal\n",
             "apps/a/ok.py": "from enum import Enum\n\nclass J(str, Enum):\n    A = 'a'\n",
             "apps/a/star.py": "from enum import *\n\nclass J(str, Enum):\n    A = 'a'\n"}
    got = UndefinedNameValidator().validate(_vctx(files, llm={"apps/a/x.py", "apps/a/ok.py", "apps/a/star.py"}))
    assert [(d.code, d.file, d.symbol) for d in got] == [("PY.UNDEFINED_NAME", "apps/a/x.py", "Enum")]
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V3a-undefined") == "blocking" and stack.mode_of("V3a-pyflakes") == "report_only"
    assert stack.mode_of("V3a-sdk-attr") == "blocking"


# ------------------------------------------------------------------------------------------------ code RT F1 (binding)
SDK_REBOUND_SHAPES = {
    # the five shapes of the 2a code RT (adv.py): every one is valid code and must not be judged
    "parameter": "from google.api_core import exceptions\ndef f(exceptions):\n    exceptions.append(1)\n"
                 "    return exceptions\n",
    "rebound_to_instance": "from google.api_core import retry\nretry = retry.Retry(predicate=retry.if_transient_error)\n"
                           "retry.deadline\n",
    "later_import": "from google.api_core import exceptions\nfrom google.cloud import exceptions\n"
                    "raise exceptions.GoogleCloudError('x')\n",
    "fallback_import": "try:\n    from google.api_core import exceptions\nexcept ImportError:\n"
                       "    import exceptions_fallback as exceptions\nexceptions.MyErr\n",
    "comprehension": "from google.api_core import retry\nxs = [retry.upper() for retry in ['a']]\n",
    "global_in_function": "from google.api_core import exceptions\ndef init():\n    global exceptions\n"
                          "    exceptions = object()\nexceptions.nope\n",
    "star_import": "from google.api_core import exceptions\nfrom helpers import *\nexceptions.nope\n",
    "function_level_import": "def f():\n    from google.api_core import exceptions\n    return exceptions.nope\n",
}


@pytest.mark.parametrize("shape", sorted(SDK_REBOUND_SHAPES))
def test_sdk_attribute_judges_only_an_alias_bound_once_by_a_module_level_import(shape):
    pytest.importorskip("google.api_core")
    from developer_agent.validators.step1 import SdkAttributeValidator
    assert SdkAttributeValidator().validate(_vctx({"apps/api/x.py": SDK_REBOUND_SHAPES[shape]})) == []


def test_sdk_attribute_true_positive_kept_and_vendored_copy_not_emitted():
    pytest.importorskip("google.api_core")
    import google.api_core
    from developer_agent.validators.step1 import SdkAttributeValidator
    bad = "from google.api_core import exceptions\nexceptions.is_transient_error\n"
    guarded = "try:\n    from google.api_core import exceptions as gexc\nexcept ImportError:\n    raise\ngexc.nope\n"
    files = {"apps/api/x.py": bad, "apps/api/g.py": guarded, "contracts/x.py": bad}
    got = SdkAttributeValidator().validate(_vctx(files, llm={"apps/api/x.py", "apps/api/g.py"}))
    assert [(d.code, d.file, d.symbol) for d in got] == [
        ("PY.ATTRIBUTE", "apps/api/g.py", "google.api_core.exceptions.nope"),
        ("PY.ATTRIBUTE", "apps/api/x.py", "google.api_core.exceptions.is_transient_error")]
    assert all(google.api_core.__version__ in d.detail for d in got)
    # a write to the module attribute is not a read of a hallucinated attribute
    assert SdkAttributeValidator().validate(_vctx({"a.py": "from google.api_core import retry\nretry.X = 1\n"})) == []


# ------------------------------------------------------------------------------------------------ code RT F6
def test_undefined_name_is_emitted_once_per_report_and_pyflakes_runs_once():
    pytest.importorskip("pyflakes")
    from pyflakes import checker
    from developer_agent.validators.step1 import build_step1_stack
    files = {"apps/a/x.py": "print(nope)\n", "contracts/x.py": "print(nope)\n", "apps/a/ok.py": "import os\n"}
    ctx = _vctx(files, llm={"apps/a/x.py", "apps/a/ok.py"})
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    pf = next(r.validator for r in stack._regs if r.validator.id == "V3a-pyflakes")
    und = next(r.validator for r in stack._regs if r.validator.id == "V3a-undefined")
    calls = []

    class counting(checker.Checker):
        def __init__(self, *a, **kw):
            calls.append(kw.get("filename"))
            super().__init__(*a, **kw)
    from unittest.mock import patch
    with patch.object(checker, "Checker", counting):
        report_only = pf.validate(ctx)
        blocking = und.validate(ctx)
    assert sorted(calls) == sorted(files)                               # one pyflakes pass over the tree
    assert [(d.code, d.file) for d in blocking] == [("PY.UNDEFINED_NAME", "apps/a/x.py")]
    undefined_ro = [(d.code, d.file) for d in report_only if d.code == "PY.UNDEFINED_NAME"]
    assert undefined_ro == [("PY.UNDEFINED_NAME", "contracts/x.py")]   # the platform copy only
    assert ("PY.UNUSED_IMPORT", "apps/a/ok.py") in [(d.code, d.file) for d in report_only]

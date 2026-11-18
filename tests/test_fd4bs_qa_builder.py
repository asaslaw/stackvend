"""FD-4BS: the QA sandbox job builds on the generated-workload builder (Python 3.13); nothing else changes.

- the script-deployed install (scripts/deploy-services.sh, no triggers): unchanged from main. `gcloud run jobs deploy --source` already
  builds with the google-24-full universal builder (live 10-13), so every job keeps `--source`; the QA contract label
  follows via `gcloud run jobs update --update-labels` (`jobs deploy` has no such flag).
- apps/qa-runner/.python-version is 3.13 (review H9: same minor as generated services), and every apps/qa-runner
  Python file is valid on BOTH 3.11 and 3.13 (rollback safety: reverting the builder pin must not break the job).

Hermetic: HCL parsed with python-hcl2, service.py read with `ast`, deploy-services.sh run against the lane 5 stub
gcloud harness. No network, no credentials.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import io
import os
import re
import tokenize
from pathlib import Path

import hcl2
import pytest

import test_platform_safe_apply_lane5 as l5

REPO = Path(__file__).resolve().parent.parent
QA_DIR = REPO / "apps" / "qa-runner"
QA_JOB = "qa-sandbox-test-runner"


def _workload_builder():
    """The one builder every generated-workload pack step in mcp-servers/terraform/service.py uses."""
    src = (REPO / "mcp-servers" / "terraform" / "service.py").read_text(encoding="utf-8")
    builders = {n.value[len("--builder="):] for n in ast.walk(ast.parse(src))
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("--builder=")}
    assert len(builders) == 1, builders
    return builders.pop()


WORKLOAD_BUILDER = _workload_builder()


def _hcl(rel):
    with open(REPO / rel, encoding="utf-8") as f:
        return hcl2.load(f)


def test_workload_builder_is_the_universal_python313_builder():
    assert WORKLOAD_BUILDER == "us-central1-docker.pkg.dev/serverless-runtimes/google-24-full/builder/universal:latest"


# --- apps/qa-runner runtime ---------------------------------------------------------------------------------------
def test_qa_runner_pins_python_313():
    assert (QA_DIR / ".python-version").read_text() == "3.13\n"


def _pep701_only_fstrings(src):
    """f-strings 3.12 accepts but 3.11 rejects (PEP 701), found with the real 3.12+ tokenizer: in a replacement field,
    a backslash, a '#', a newline, or the enclosing quote. `ast.parse(feature_version=(3, 11))` does not check these
    (the class of crash fixed in ecb6e9d / 1046ab8)."""
    if not hasattr(tokenize, "FSTRING_START"):  # pragma: no cover - the suite runs on 3.12+
        pytest.skip("needs the PEP 701 tokenizer")
    problems = []
    # One frame per open f-string: (quote, line, expression text). Every token between a frame's START and END is part
    # of its expression EXCEPT its own literal FSTRING_MIDDLE text; a nested f-string is wholly expression of every
    # enclosing frame (3.11 tokenized the outer f-string as one STRING, so its rules cover the nested text too).
    stack = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        text = "\n" if tok.type in (tokenize.NL, tokenize.NEWLINE) else tok.string
        if tok.type == tokenize.FSTRING_START:
            for frame in stack:
                frame[2].append(text)
            stack.append((tok.string.lstrip("rRbBfFuU"), tok.start[0], []))
        elif not stack:
            continue
        elif tok.type == tokenize.FSTRING_END:
            quote, line, expr = stack.pop()
            joined = "".join(expr)
            bad = [why for why, hit in (("backslash", "\\" in joined), ("'#'", "#" in joined),
                                        ("enclosing quote", quote in joined),
                                        ("newline", len(quote) == 1 and "\n" in joined)) if hit]
            if bad:
                problems.append(f"line {line}: {', '.join(bad)} in an f-string expression")
            for frame in stack:
                frame[2].append(text)
        elif tok.type == tokenize.FSTRING_MIDDLE:
            for frame in stack[:-1]:  # the innermost frame's own literal text is not expression
                frame[2].append(text)
        else:
            for frame in stack:
                frame[2].append(text)
    return problems


@pytest.mark.parametrize("src,flagged", [
    ('x = f"{chr(10).join([\'\\n\'])}"\n', True),       # backslash in the expression (ecb6e9d)
    ('x = f"{"a"}"\n', True),                          # enclosing quote reused
    ('x = f"{a  # c\n}"\n', True),                     # comment in the expression
    ('x = f"{\'a\'}" + f\'{"b"}\' + rf"\\d{x!r:>4}"\n', False),  # all valid on 3.11
    ('x = f"""{"a"}"""\n', False),                     # single quote char inside a triple-quoted f-string is fine
    ('x = f"{{literal}} {y}"\n', False),
])
def test_pep701_checker_negative_and_positive(src, flagged):
    assert bool(_pep701_only_fstrings(src)) is flagged, _pep701_only_fstrings(src)


QA_PY = sorted(p.relative_to(REPO).as_posix() for p in QA_DIR.rglob("*.py"))


def test_qa_runner_python_files_found():
    assert "apps/qa-runner/sandbox_job.py" in QA_PY and len(QA_PY) > 5, QA_PY


@pytest.mark.parametrize("rel", QA_PY)
def test_qa_runner_valid_on_311_and_313(rel):
    src = (REPO / rel).read_text(encoding="utf-8")
    for fv in ((3, 11), (3, 13)):
        ast.parse(src, filename=rel, feature_version=fv)
    assert _pep701_only_fstrings(src) == [], rel


# --- script-deployed install: scripts/deploy-services.sh ------------------------------------------------------------
# Live 10-13: `gcloud run jobs deploy --source` builds with the serverless-runtimes google-24-full universal builder
# (it resolved Python against [3.15.0 3.14.x ... 3.13.x] and rejected 3.11), i.e. already the workload builder. So the
# sv9 path needs NO builder override: every job keeps `jobs deploy --source`, and the QA contract label follows via
# `jobs update --update-labels` (main @ 50cbd18; `jobs deploy` has no --update-labels flag).
QA_LABEL_UPDATE = (f"gcloud run jobs update {QA_JOB} --region us-central1 --project {l5.PROJ} "
                   f"--update-labels=stackvend-qa-job-contract=1 --quiet")


def test_deploy_services_has_no_qa_builder_override():
    src = (REPO / "scripts" / "deploy-services.sh").read_text(encoding="utf-8")
    for needle in ("QA_JOB_BUILDER", "deploy_job()", "--pack", "--builder", "gcloud builds submit"):
        assert needle not in src, needle


class TestDeployServicesQAJobSourceDeploy(l5._Harness):
    def setUp(self):
        super().setUp()
        for d in l5.TestDeployServices.DIRS:
            os.makedirs(os.path.join(self.repo, d), exist_ok=True)
        os.makedirs(os.path.join(self.repo, "apps/control-center/shared"), exist_ok=True)
        self.write("infra/modules/m/main.tf", "# module\n")
        self.write("shared/builtin_modules_payload.py", "PAYLOAD = {}\n")

    def _assert_qa_source_deploy_then_label(self, calls):
        qa_deploys = [x for x in calls if x.startswith(f"gcloud run jobs deploy {QA_JOB} ")]
        self.assertEqual(qa_deploys, [f"gcloud run jobs deploy {QA_JOB} --source apps/qa-runner --region us-central1 "
                                      f"--project {l5.PROJ} --quiet"])
        self.assertEqual([x for x in calls if "--update-labels" in x], [QA_LABEL_UPDATE])
        self.assertLess(calls.index(qa_deploys[0]), calls.index(QA_LABEL_UPDATE))
        self.assertFalse([x for x in calls if x.startswith("gcloud builds submit")], calls)

    def test_single_qa_job_source_deploy_then_label(self):
        rc, out, err = self.run_script("deploy-services.sh", [QA_JOB], PROJECT_ID=l5.PROJ)
        self.assertEqual(rc, 0, out + err)
        self._assert_qa_source_deploy_then_label(self.calls())

    def test_bulk_all_jobs_source_deploy_only_qa_labelled(self):
        rc, out, err = self.run_script("deploy-services.sh", ["--all-jobs"], PROJECT_ID=l5.PROJ)
        self.assertEqual(rc, 0, out + err)
        calls = self.calls()
        self._assert_qa_source_deploy_then_label(calls)
        others = sorted(x for x in calls if x.startswith("gcloud run jobs deploy") and f" {QA_JOB} " not in x)
        self.assertEqual(others, sorted(
            f"gcloud run jobs deploy {job} --source {d} --region us-central1 --project {l5.PROJ} --quiet"
            for job, d in (("github-refactor-scanner-job", "apps/refactor-scanner"),
                           ("finops-budget-enforcer-job", "apps/finops-enforcer"),
                           ("infra-rollback-job", "apps/infra-rollback"),
                           ("sandbox-garbage-collector-job", "apps/sandbox-cleaner"),
                           ("sre-telemetry-digest-job", "apps/sre-digest"),
                           ("finops-spend-sync-job", "apps/finops-spend-sync"),            # C10
                           ("sandbox-workload-sweeper-job", "apps/sandbox-sweeper"),       # C10
                           ("billing-alert-drain-job", "apps/billing-alert-drain"))))      # C10

    def test_negative_deploy_failure_sets_no_label_and_fails(self):
        rc, out, err = self.run_script("deploy-services.sh", [QA_JOB], PROJECT_ID=l5.PROJ, STUB_DEPLOY_RC=1)
        self.assertNotEqual(rc, 0, out + err)
        self.assertEqual([x for x in self.calls() if x.startswith("gcloud run jobs update")], [])

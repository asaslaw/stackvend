"""C0a contracts (integration plan §1.1/§1.2/§1.6/§1.7, §S.6 step 3): typed diagnostics, ownership, Step 1 settings,
validator skeleton. Inert: nothing here is called by product code yet."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest
from pydantic import ValidationError

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared.artifact_ownership import (LLM_DOCUMENT_PATHS, PLATFORM_RENDERED_FLOOR, Ownership,  # noqa: E402
                                       UnattributablePath, classify_address, classify_path, classify_report)
from shared.diagnostics import (DIAGNOSTIC_CLASSES, HTTP_STATUS, PRECEDENCE, ROUTE, AssemblyRecord,  # noqa: E402
                                Diagnostic, ErrorClass, MemoryLedgerStore, MemoryProvenanceStore, ProvenanceEntry,
                                RepairBudgetExhausted, RepairEvent, RepairLedger, Route, Segment, StageError,
                                ValidationReport, artifact_hash, derive_error_class, fingerprint)
from shared.hallucination_stack import (HallucinationStackSettings, effective_dispatch_token_budget,
                                        effective_repair_token_budget,  # noqa: E402
                                        repair_call_max_output_tokens, resolve_repair_model)
from shared.path_safety import UnsafePathError  # noqa: E402


def _d(code="TF.REFERENCE_TO_UNDECLARED_RESOURCE", file="infra/workload/custom.tf", line=3, cls=ErrorClass.CODE_DEFECT, message="Reference to undeclared resource",
       severity="error", **kw):
    return Diagnostic(tool="tofu", code=code, severity=severity, error_class=cls, file=file, line=line,
                      message=message, source="precommit", **kw)


# ---------------------------------------------------------------------------------------------------- diagnostics
def test_diagnostic_round_trip_and_frozen():
    d = _d(block_address="google_pubsub_topic.t", snippet="\n".join(str(i) for i in range(30)), hint="h" * 9000)
    again = Diagnostic.model_validate_json(d.model_dump_json())
    assert again == d
    assert len(d.snippet.split("\n")) == 11 and len(d.hint.encode()) == 4096
    with pytest.raises(ValidationError):
        d.code = "X.Y"  # frozen


@pytest.mark.parametrize("code", ["TF", "tf.lower", "TF.", "TF.has space", "1TF.X"])
def test_diagnostic_code_pattern(code):
    with pytest.raises(ValidationError):
        _d(code=code)


def test_diagnostic_rejects_report_classes_and_unknown_fields():
    with pytest.raises(ValidationError):
        _d(cls=ErrorClass.GATE_UNAVAILABLE)
    with pytest.raises(ValidationError):
        Diagnostic(tool="tofu", code="TF.X", severity="error", file="a", message="m", source="precommit", extra=1)


def test_fingerprint_ignores_line_numbers_but_not_location_keys():
    a, b = _d(line=3), _d(line=99, column=7, message="other text")
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) != fingerprint(_d(block_address="google_pubsub_topic.t"))
    assert fingerprint(a) != fingerprint(_d(file="infra/workload/iam.tf"))


def test_artifact_hash_is_order_independent_and_content_sensitive():
    a = {"b.py": "x", "a.tf": "y"}
    assert artifact_hash(a) == artifact_hash(dict(reversed(list(a.items()))))
    assert artifact_hash(a) != artifact_hash({"b.py": "x", "a.tf": "y "})
    assert artifact_hash(a) != artifact_hash({"b.py": "x", "a.tf2": "y"})


def test_error_class_derivation_table():
    code, plat, brown = _d(), _d(cls=ErrorClass.PLATFORM_DEFECT), _d(cls=ErrorClass.BROWNFIELD_CONFLICT)
    warn_plat = _d(cls=ErrorClass.PLATFORM_DEFECT, severity="warning")
    assert derive_error_class("UNAVAILABLE", [code]) is ErrorClass.GATE_UNAVAILABLE
    assert derive_error_class("PASS", []) is None
    assert derive_error_class("FAIL", [code]) is ErrorClass.CODE_DEFECT
    assert derive_error_class("FAIL", [code, plat]) is ErrorClass.PLATFORM_DEFECT   # mixed -> platform wins
    assert derive_error_class("FAIL", [brown, code]) is ErrorClass.BROWNFIELD_CONFLICT
    assert derive_error_class("FAIL", [code, warn_plat]) is ErrorClass.CODE_DEFECT  # warnings never route
    assert PRECEDENCE[0] is ErrorClass.GATE_UNAVAILABLE and PRECEDENCE[-1] is ErrorClass.CODE_DEFECT


def test_routes_and_http_status():
    assert ROUTE[ErrorClass.CODE_DEFECT] is Route.DEVELOPER_REPAIR
    assert ROUTE[ErrorClass.BROWNFIELD_CONFLICT] is Route.OPERATOR and ROUTE[ErrorClass.STATE_LOCKED] is Route.OPERATOR
    assert ROUTE[ErrorClass.PLATFORM_DEFECT] is Route.DLQ and ROUTE[ErrorClass.GATE_UNAVAILABLE] is Route.DLQ
    assert {HTTP_STATUS[c] for c in DIAGNOSTIC_CLASSES} <= {409, 422, 503}
    assert not any(c.value in ("IAC_DEFECT", "TOPOLOGY_CONFLICT") for c in ErrorClass)


def test_validation_report_derives_and_checks_consistency():
    r = ValidationReport(status="FAIL", source="precommit", artifact_hash="h", diagnostics=[_d()])
    assert r.error_class is ErrorClass.CODE_DEFECT and r.error_fingerprints() == [fingerprint(_d())]
    assert ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="h").error_class is \
        ErrorClass.GATE_UNAVAILABLE
    with pytest.raises(ValidationError):
        ValidationReport(status="PASS", source="precommit", artifact_hash="h", diagnostics=[_d()])
    with pytest.raises(ValidationError):
        ValidationReport(status="FAIL", source="precommit", artifact_hash="h", diagnostics=[])
    with pytest.raises(ValidationError):
        ValidationReport(status="FAIL", source="precommit", artifact_hash="h", diagnostics=[_d()],
                         error_class=ErrorClass.PLATFORM_DEFECT)
    assert ValidationReport.model_validate_json(r.model_dump_json()) == r


def test_stage_errors_carry_the_report():
    r = ValidationReport(status="FAIL", source="precommit", artifact_hash="h", diagnostics=[_d()])
    e = RepairBudgetExhausted(r, "NO_PROGRESS")
    assert isinstance(e, StageError) and e.report is r and e.error_class is ErrorClass.CODE_DEFECT
    assert e.exhausted_reason == "NO_PROGRESS" and "NO_PROGRESS" in str(e)


def test_repair_event_and_ledger_round_trip():
    ev = RepairEvent(trace_id="t", product_id="p", iteration=1, source="precommit", persona="iac_worker",
                     files=["infra/workload/main.tf"], codes=["TF.X"], fingerprints_before=["a"],
                     fingerprints_after=[], accepted=True, removed_addresses=["google_x.y"], model="m",
                     tokens_in=10, tokens_out=20, tokens_thoughts=5, duration_ms=3)
    assert RepairEvent.model_validate_json(ev.model_dump_json()) == ev
    with pytest.raises(ValidationError):
        RepairEvent(**dict(ev.model_dump(), reject_reason="NOT_DECREASING"))  # rev 3: count rule retired
    led = RepairLedger(trace_id="t", iteration=2, tokens_in=5, tokens_out=7, reserved_tokens=3)
    assert led.tokens_spent == 12 and RepairLedger.model_validate_json(led.model_dump_json()) == led


def test_memory_stores_round_trip_copies():
    ls = MemoryLedgerStore()
    assert ls.load("t") is None
    led = RepairLedger(trace_id="t")
    ls.save(led)
    led.iteration = 9                       # the caller's later mutation never leaks into the store
    got = ls.load("t")
    assert got.iteration == 0 and got is not ls.load("t")
    ps = MemoryProvenanceStore()
    assert ps.load("p") == {}
    ps.save("p", {"infra/workload/iam.tf": ProvenanceEntry(persona="iac_worker", trace_id="t", sha256="0" * 64)})
    assert ps.load("p")["infra/workload/iam.tf"].persona == "iac_worker"


def test_assembly_record_round_trip_and_back_mapping():
    rec = AssemblyRecord(trace_id="t", relocated={"infra/workload/main.tf": "infra/workload/custom.tf"},
                         segments=[Segment(assembled_path="infra/workload/custom.tf", start_line=10, end_line=20,
                                           draft_path="infra/workload/main.tf", draft_start_line=1)])
    rec.record("google_cloud_run_v2_service.api", "module.compute", "CLOUD_RUN_REPLACED_BY_MODULE",
               "infra/workload/main.tf")
    assert AssemblyRecord.model_validate_json(rec.model_dump_json()) == rec
    assert rec.draft_location("infra/workload/custom.tf", 12) == ("infra/workload/main.tf", 3)
    assert rec.draft_location("infra/workload/custom.tf", 9) is None
    with pytest.raises(ValidationError):
        AssemblyRecord(replaced_reason={"x": "SOMETHING_ELSE"})


# ---------------------------------------------------------------------------------------------------- ownership
SETS = dict(vendored={"infra/modules/compute-cloudrun/main.tf"},
            rendered={"infra/workload/main.tf", "infra/workload/variables.tf"},
            authored={"infra/workload/iam.tf", "apps/api/main.py", "infra/workload/custom.tf"},
            preexisting={"infra/workload/monitoring.tf", "infra/workload/network.tf", "infra/workload/human.tf"})


@pytest.mark.parametrize("path,want", [
    ("infra/modules/compute-cloudrun/main.tf", Ownership.PLATFORM_VENDORED),
    ("infra/workload/main.tf", Ownership.PLATFORM_RENDERED),
    ("infra/workload/custom.tf.json", Ownership.LLM_DOCUMENT),
    ("infra/workload/human.tf", Ownership.USER_OWNED),
    ("infra/workload/human_override.tf", Ownership.USER_OWNED),
    ("infra/workload/extra_override.tf", Ownership.USER_OWNED),
    ("infra/workload/iam.tf", Ownership.LLM_AUTHORED),
    ("apps/api/main.py", Ownership.LLM_AUTHORED),
    # F4: pre-existing infra files with no provenance record are the user's (never repaired, never purged)
    ("infra/workload/monitoring.tf", Ownership.USER_OWNED),
    ("infra/workload/network.tf", Ownership.USER_OWNED),
])
def test_classify_path_table(path, want):
    assert classify_path(path, **SETS) is want


def test_network_tf_is_platform_only_when_rendered_this_run():
    assert "infra/workload/network.tf" not in PLATFORM_RENDERED_FLOOR
    assert "infra/workload/terraform.tfvars" not in PLATFORM_RENDERED_FLOOR
    sets = dict(SETS, rendered=SETS["rendered"] | {"infra/workload/network.tf"})
    assert classify_path("infra/workload/network.tf", **sets) is Ownership.PLATFORM_RENDERED
    # TI-3: the typed IaC intent is the AI's document too (custom.tf.json rendered from it is in `rendered`, first)
    assert LLM_DOCUMENT_PATHS == {"infra/workload/custom.tf.json", "infra/workload/iac_intent.json"}
    assert classify_path("infra/workload/iac_intent.json", **SETS) is Ownership.LLM_DOCUMENT
    sets = dict(SETS, rendered=SETS["rendered"] | {"infra/workload/custom.tf.json"})
    assert classify_path("infra/workload/custom.tf.json", **sets) is Ownership.PLATFORM_RENDERED


def test_prior_llm_provenance_keeps_ai_files_repairable():
    # I-20: the caller verifies sha256 and passes only matching paths as prior_llm
    assert classify_path("infra/workload/monitoring.tf", prior_llm={"infra/workload/monitoring.tf": "iac_worker"},
                         **SETS) is Ownership.LLM_AUTHORED
    assert classify_path("infra/workload/monitoring.tf", prior_llm={}, **SETS) is Ownership.USER_OWNED


def test_legacy_custom_tf_is_user_owned_only_from_15b():
    assert classify_path("infra/workload/custom.tf", **SETS) is Ownership.LLM_AUTHORED
    assert classify_path("infra/workload/custom.tf", legacy_custom_tf=True, **SETS) is Ownership.USER_OWNED


@pytest.mark.parametrize("bad", ["../etc/passwd", "/abs/x.tf", "infra/../../x", "", "a\\b"])
def test_classify_path_rejects_unsafe_keys(bad):
    with pytest.raises(UnsafePathError):
        classify_path(bad, **SETS)


def test_unattributable_path_raises():
    with pytest.raises(UnattributablePath):
        classify_path("apps/ghost/main.py", **SETS)


def test_classify_address_and_report_precedence():
    platform = {("infra/workload/custom.tf", "module.compute_worker")}
    assert classify_address("infra/workload/custom.tf", "module.compute_worker",
                            platform_addresses=platform) is Ownership.PLATFORM_RENDERED
    assert classify_address("infra/workload/custom.tf", "google_x.y", platform_addresses=platform) is None
    own = {"infra/workload/custom.tf": Ownership.LLM_AUTHORED, "infra/workload/main.tf": Ownership.PLATFORM_RENDERED,
           "infra/workload/human.tf": Ownership.USER_OWNED}
    mixed = ValidationReport(status="FAIL", source="precommit", artifact_hash="h",
                             diagnostics=[_d(), _d(file="infra/workload/main.tf")])
    assert classify_report(mixed, own.get) is ErrorClass.PLATFORM_DEFECT
    user = ValidationReport(status="FAIL", source="precommit", artifact_hash="h",
                            diagnostics=[_d(), _d(file="infra/workload/human.tf")])
    assert classify_report(user, own.get) is ErrorClass.BROWNFIELD_CONFLICT
    ghost = ValidationReport(status="FAIL", source="precommit", artifact_hash="h", diagnostics=[_d(file="x/y.tf")])
    assert classify_report(ghost, own.get) is ErrorClass.PLATFORM_DEFECT
    code = ValidationReport(status="FAIL", source="precommit", artifact_hash="h", diagnostics=[_d()])
    assert classify_report(code, own.get) is ErrorClass.CODE_DEFECT


# ---------------------------------------------------------------------------------------------------- settings
def test_step1_settings_defaults():
    s = HallucinationStackSettings()
    # QA-REPAIR-BUDGET (owner 10-29): per trace sized for 3 QA rounds (was 5 / 250_000 / 0.7); per dispatch = the old
    # per-trace values, so one dispatch on a fresh trace stops where it did before
    assert (s.repair_max_iterations_precommit, s.repair_max_iterations_total) == (3, 10)
    assert s.repair_token_budget == 500_000 and s.repair_budget_envelope_fraction == 1.4
    assert effective_repair_token_budget(s) == 490_000 == effective_repair_token_budget(s, 350_000)
    assert effective_repair_token_budget(s, 1_000_000) == 500_000
    assert (s.repair_dispatch_token_budget, s.repair_dispatch_envelope_fraction) == (250_000, 0.7)
    assert effective_dispatch_token_budget(s) == 245_000 == effective_dispatch_token_budget(s, 350_000)
    assert effective_dispatch_token_budget(s, 1_000_000) == 250_000
    for env in (100_000, 350_000, 1_000_000):   # the trace budget is exactly 2x the old one for every envelope
        assert effective_repair_token_budget(s, env) == 2 * effective_dispatch_token_budget(s, env)
    # bound = answer room (1.5 x files + 2048) + repair_thinking_budget (2048), capped (R3 10-13 token-bound fix)
    assert repair_call_max_output_tokens(s, 1000) == 3548 + 2048 and repair_call_max_output_tokens(s, 100_000) == 16_384
    assert resolve_repair_model(s, "gemini-3.8-flash") == "gemini-3.8-flash"
    assert resolve_repair_model(s.model_copy(update={"repair_model": "pro"}), "flash") == "pro"
    assert (s.repair_wall_clock_s, s.remote_validate_timeout_s) == (900, 60)   # REPAIR-WALL-CLOCK-900 (owner 11-15)
    with pytest.raises(ValidationError):
        HallucinationStackSettings(unknown_field=1)


# ---------------------------------------------------------------------------------------------------- skeleton
def test_validator_stack_modes_report_only_and_unavailable():
    from developer_agent.validators import ValidationContext, ValidatorStack, ValidatorUnavailable

    class V:
        def __init__(self, vid, out=None, boom=False):
            self.id, self.tool, self.out, self.boom = vid, "policy", out or [], boom

        def validate(self, ctx):
            if self.boom:
                raise ValidatorUnavailable("down")
            return list(self.out)

    files = {"infra/workload/custom.tf": "x"}
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED)
    stack = ValidatorStack()
    stack.register(V("a", [_d()]), "blocking")
    stack.register(V("b", [_d(code="PY.UNDEFINED_NAME")]), "report_only")
    stack.register(V("c", [_d(code="TF.OFF")]), "off")
    r = stack.run(ctx)
    assert r.status == "FAIL" and [d.code for d in r.diagnostics] == ["TF.REFERENCE_TO_UNDECLARED_RESOURCE"]
    assert [d.code for d in r.report_only] == ["PY.UNDEFINED_NAME"] and r.tools_ran == ["a", "b"]
    assert r.artifact_hash == artifact_hash(files)
    s2 = ValidatorStack({"a": "report_only"})
    s2.register(V("a", [_d()]), "blocking")
    assert s2.mode_of("a") == "report_only"
    assert s2.run(ctx).status == "PASS"                      # override: measured, never blocks
    s3 = ValidatorStack()
    s3.register(V("a", [_d()]), "blocking")
    s3.register(V("down", boom=True), "blocking")
    r3 = s3.run(ctx)
    assert r3.status == "UNAVAILABLE" and r3.error_class is ErrorClass.GATE_UNAVAILABLE and r3.tools_unavailable == ["down"]
    s4 = ValidatorStack()
    s4.register(V("down", boom=True), "report_only")
    assert s4.run(ctx).status == "PASS"                      # a report-only validator never blocks

    with pytest.raises(ValueError):
        s4.register(V("down"), "blocking")                   # ids are unique
    with pytest.raises(ValueError):
        ValidatorStack({"x": "sometimes"})


def test_validation_context_is_read_only():
    from developer_agent.validators import ValidationContext
    files = {"a.tf": "x"}
    ctx = ValidationContext.build(files, ownership=lambda p: None)
    with pytest.raises(TypeError):
        ctx.files["a.tf"] = "y"
    files["a.tf"] = "z"
    assert ctx.files["a.tf"] == "x"


def test_gateway_copies_are_identical_to_root():
    for name in ("diagnostics.py", "artifact_ownership.py", "hallucination_stack.py"):
        root = open(os.path.join(REPO_ROOT, "shared", name), "rb").read()
        copy = open(os.path.join(GATEWAY, "shared", name), "rb").read()
        assert root == copy, name


def test_a_crashing_blocking_validator_is_unavailable_never_a_pass():
    from developer_agent.validators import ValidationContext, ValidatorStack

    class Crash:
        id, tool = "crash", "policy"

        def validate(self, ctx):
            raise KeyError("validator bug")

    ctx = ValidationContext.build({"infra/workload/custom.tf": "x"}, ownership=lambda p: Ownership.LLM_AUTHORED)
    s = ValidatorStack()
    s.register(Crash(), "blocking")
    r = s.run(ctx)
    assert r.status == "UNAVAILABLE" and r.tools_unavailable == ["crash"] and r.diagnostics == []
    s2 = ValidatorStack()
    s2.register(Crash(), "report_only")
    assert s2.run(ctx).status == "PASS"

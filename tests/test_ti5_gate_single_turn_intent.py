"""TI-5 paid gate diagnosis (docs/handoff/ti5-gate-diagnosis.md, issue 2): 08-r2 / 08-r3 ended `generation_error`
with an untyped `TypeError: 'str' object cannot be interpreted as an integer` (shared/diagnostics.artifact_hash).
The swarm hit a file collision and fell back to the single-turn developer call; on the intent path that answer
carried infra/workload/iac_intent.json as a JSON object (not a JSON string), and the single-turn path, unlike the
junior and repair envelopes (TI-3), never normalized it. The fix: the same normalization on the parsed files map.
TI-5-G2 (owner 10-24): any other non-text file content in that answer is re-asked with a typed note, never a crash.
Hermetic: a fake LLM answer, a fake /validate; no network, no Firestore."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import (APP, BUCKET_MODULE, PID, UPLOADS, C, II, Client, _agent,  # noqa: E402
                                         _runtime, intent, record_of, topo, vt_of)


def test_normalize_intent_files_redumps_only_an_object_intent_and_is_identity_otherwise():
    doc = {"schema": "iac_intent/v1", "modules": []}
    files = {C.INTENT_PATH: doc, "apps/x.py": "x = 1\n"}
    out = C.normalize_intent_files(files)
    assert out[C.INTENT_PATH] == json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    assert out["apps/x.py"] == "x = 1\n" and list(out) == list(files)
    assert files[C.INTENT_PATH] is doc                       # the caller's map is not mutated
    assert C.normalize_intent_files({C.INTENT_PATH: [1]})[C.INTENT_PATH] == "[\n  1\n]\n"
    # Do No Harm: a string intent (valid or not) and a map without the intent are returned as the same object
    for unchanged in ({C.INTENT_PATH: '{"schema": "iac_intent/v1"}'}, {C.INTENT_PATH: "not json"},
                      {"apps/x.py": "x = 1\n"}, {}):
        assert C.normalize_intent_files(unchanged) is unchanged
    # the envelope form (juniors / repair) is byte-identical to before the refactor
    env = json.dumps({"files": {C.INTENT_PATH: doc, "apps/x.py": "x = 1\n"}, "summary": "s"})
    assert json.loads(C.normalize_intent_envelope(env)) == {"files": out, "summary": "s"}


class _Genai:
    """Single-turn developer answers, one per call (the swarm failed before them); records each call's model and
    prompt."""

    def __init__(self, *texts):
        self.seen = []
        answers = list(texts)
        outer = self

        class models:  # noqa: N801
            @staticmethod
            def generate_content(*a, **k):
                outer.seen.append((k.get("model"), k.get("contents")))
                return SimpleNamespace(text=answers.pop(0), candidates=[SimpleNamespace(finish_reason="STOP")],
                                       usage_metadata=None)
        self.models = models

    @property
    def calls(self):
        return len(self.seen)


def _answer(files):
    return json.dumps({"files": files, "summary": "single turn"})


def _single_turn(mode, answer_files, *more_answers, cascade=("gemini-test",), calls=1):
    from developer_agent import handler as h
    client = Client()
    agent = _agent(_runtime(client, iac_intent_mode=mode))
    agent.model_name = cascade[0]
    agent.genai_client = _Genai(_answer(answer_files), *(_answer(f) for f in more_answers))
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]

    class CollidingDispatcher:   # 08-r2/r3: "File collision detected ... falling back to standard pipeline path"
        def __init__(self, *a, **k):
            self.iac_intent = None

        async def execute_phased_junior_swarm(self, *a, **k):
            raise ValueError("File collision detected on 'apps/shop/schemas/__init__.py'.")

    try:
        with patch.object(h, "LeadDeveloperOrchestrator") as lead, \
                patch.object(h, "SwarmDispatcher", CollidingDispatcher), \
                patch.object(h, "get_model_cascade_for_agent", return_value=list(cascade)), \
                patch.object(agent, "fetch_existing_repo_files", return_value={}), \
                patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
                patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
            lead.return_value.decompose_specification.return_value = plan
            files = agent.generate_code_files(product_id=PID, spec_text="uploads service", task_dag=[],
                                              trace_id="t-ti5-gate",
                                              architect_compute_intent=record_of(topo([UPLOADS])),
                                              allow_unauthenticated=True, enable_direct_iap=False,
                                              domain_restricted_sharing=False)
    finally:
        assert agent.genai_client.calls == calls
    return files, agent, client


def test_single_turn_intent_given_as_an_object_is_normalized_gated_and_rendered():
    doc = json.loads(intent([BUCKET_MODULE]))
    files, agent, client = _single_turn("generate", dict(APP, **{C.INTENT_PATH: doc}))
    assert agent.last_validation_report.status == "PASS"
    assert isinstance(files[C.INTENT_PATH], str)
    assert json.loads(files[C.INTENT_PATH]) == doc
    res = II.validate_intent(files[C.INTENT_PATH], C.II.load_artifacts(), C.intent_context(vt_of(topo([UPLOADS]))))
    assert res.ok and files[C.RENDER_PATH] == II.render_intent(res.validated).files[C.RENDER_PATH]
    assert client.validated and all(isinstance(v, str) for v in client.validated[-1].values())


def test_single_turn_string_intent_is_passed_through_byte_identical():
    text = intent([BUCKET_MODULE])
    files, agent, _client = _single_turn("generate", dict(APP, **{C.INTENT_PATH: text}))
    assert agent.last_validation_report.status == "PASS"
    assert files[C.INTENT_PATH] == text


# ------------------------------------------------------------------------------------------------ TI-5-G2
# Register TI-5-G2 (owner 10-24): a single-turn answer with a file whose content is not text is re-asked with a typed
# "invalid files" note (the next model of the cascade, like the JSON re-ask HS-12), never a crash.
def _with_intent(files):
    return dict(files, **{C.INTENT_PATH: intent([BUCKET_MODULE])})


def test_g2_non_text_file_content_is_reasked_with_a_typed_note():
    bad = _with_intent(dict(APP, **{"apps/shop/requirements.txt": ["fastapi>=0.110.0", "uvicorn>=0.28.0"]}))
    files, agent, _client = _single_turn("generate", bad, _with_intent(APP), cascade=("m1", "m2"), calls=2)
    (m_first, p_first), (m_second, p_second) = agent.genai_client.seen
    assert (m_first, m_second) == ("m1", "m2")
    assert "JSON.OUTPUT_INVALID" not in p_first
    assert p_second.startswith(p_first) and "JSON.OUTPUT_INVALID" in p_second
    note = p_second[len(p_first):]
    assert '"apps/shop/requirements.txt"' in note and "apps/shop/main.py" not in note
    assert agent.last_validation_report.status == "PASS"
    assert files["apps/shop/requirements.txt"] == APP["apps/shop/requirements.txt"]


def test_g2_every_model_answering_non_text_is_a_typed_llm_output_invalid():
    from developer_agent.errors import LLM_OUTPUT_INVALID, DeveloperStageError
    bad = _with_intent(dict(APP, **{"apps/shop/Procfile": {"web": "uvicorn main:app"}}))
    with pytest.raises(DeveloperStageError) as ei:
        _single_turn("generate", bad, bad, cascade=("m1", "m2"), calls=2)
    assert ei.value.error_class == LLM_OUTPUT_INVALID
    assert "file content not text: apps/shop/Procfile" in str(ei.value)   # Opus review 10-24 (optional item)


def test_g2_valid_answer_is_unchanged_and_never_reasked():
    """Do No Harm: an all-text answer is used as given after one call (no re-ask, no note), byte-identical."""
    good = _with_intent(APP)
    files, agent, _client = _single_turn("generate", good, cascade=("m1", "m2"), calls=1)
    assert "JSON.OUTPUT_INVALID" not in agent.genai_client.seen[0][1]
    assert all(files[p] == t for p, t in good.items())

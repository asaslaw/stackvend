"""PUSH-PLAN-CHECK (register row PUSH-PLAN-CHECK, owner 10-28): the typed intent declares every Pub/Sub push the plan
requires.

The architect's typed topology may declare push edges (`shared.service_topology.PushEdge`: topic resource T pushes to
the cloudrun service S at the path P). PUSH-SUB-RENDER renders a push only when the AI's intent declares it, so a
draft that leaves it out (seen 10-28, example 01) deploys a topic nobody delivers. This validator (V-IAC-PUSH, code
IAC.PUSH_PLAN_MISSING, blocking) compares the typed intent with each edge and, when no entry satisfies it, emits one
finding on infra/workload/iac_intent.json with the exact entry and field to set. The repair loop routes it to the
intent's author (the IaC persona). Nothing here rewrites anything.

An edge is satisfied by either (typed objects of the parsed intent only; no string inspection):
- module form: a messaging-pubsub instance with `realizes` = T whose `push` is {"service": ServiceRef(S,
  service_uri), "path": P, ...} (the identity is the gate's to judge: _Gate.push_arg);
- raw form: a google_pubsub_subscription resource whose `topic` is a Ref to T's realizing entry (module output
  topic_name / topic_id of a messaging-pubsub instance realizing T, or name / id of a google_pubsub_topic resource
  realizing T) and whose single push_config block has push_endpoint = format("%s<P>", ServiceRef(S, service_uri))
  (or the bare ServiceRef when P is "/").

Not judged (no finding): the tree has no intent, or it is not a typed-parseable `iac_intent/v1` document (V-IAC
reports JSON.OUTPUT_INVALID / IAC.INTENT_MISSING). A finding that appears only once a repair makes the intent parse is
revealed, not caused (repair_loop.accept, `unmasked_push_plan`; the IMPORT-RESOLVE-GATE precedent).

Registered by build_step1_stack only on the intent path with a topology that declares at least one push edge; any
other run registers nothing new.
"""
from __future__ import annotations

import json
from typing import Any, List, Mapping, Optional, Set

try:
    from shared import iac_intent as II
    from shared.diagnostics import Diagnostic, ErrorClass
except ImportError:  # pragma: no cover
    from ...shared import iac_intent as II  # type: ignore
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore

from ..iac_intent_contract import INTENT_PATH, PUSH_PLAN_IDENTITY, push_plan_form

VALIDATOR_ID = "V-IAC-PUSH"
CODE = "IAC.PUSH_PLAN_MISSING"
SYMBOL_PREFIX = "push:"           # symbol = "push:<topic logical name>" (one push per topic, validated)
TOPIC_TYPE = "google_pubsub_topic"
TOPIC_MODULE_OUTPUTS = frozenset({"topic_name", "topic_id"})
TOPIC_RESOURCE_ATTRS = frozenset({"name", "id"})

__all__ = ["VALIDATOR_ID", "CODE", "PushPlanValidator", "parsed_intent", "push_plan_judged", "register"]


def parsed_intent(files: Mapping[str, Any]) -> Optional[Any]:
    """The tree's intent as `shared.iac_intent.IacIntent` (the gate's own first step: json.loads + model_validate),
    else None (absent, not JSON, not the closed schema)."""
    text = files.get(INTENT_PATH) if hasattr(files, "get") else None
    if not isinstance(text, (str, bytes)):
        return None
    try:
        return II.IacIntent.model_validate(json.loads(text))
    except Exception:  # noqa: BLE001 - ValueError / pydantic ValidationError / wrong JSON type: not judged
        return None


def push_plan_judged(files: Mapping[str, Any]) -> bool:
    """True when V-IAC-PUSH judges this tree (its intent parses); repair_loop.accept reads it for the previous tree."""
    return parsed_intent(files) is not None


def _service_uri_ref(v: Any, service: str) -> bool:
    return (isinstance(v, II.Ref) and isinstance(v.ref, II.ServiceRef) and v.ref.service == service
            and v.ref.output == "service_uri")


def _single_block(v: Any) -> Optional[Mapping[str, Any]]:
    if isinstance(v, list) and len(v) == 1:
        v = v[0]
    return v if isinstance(v, dict) else None


def _endpoint_path(v: Any, service: str) -> Optional[str]:
    """The path a typed push endpoint appends to `service`'s URL ("" for the bare ServiceRef), else None."""
    if _service_uri_ref(v, service):
        return ""
    if (isinstance(v, II.Call) and v.fn == "format" and len(v.args) == 2 and isinstance(v.args[0], str)
            and v.args[0].startswith("%s") and v.args[0].count("%") == 1 and _service_uri_ref(v.args[1], service)):
        return v.args[0][2:]
    return None


class PushPlanValidator:
    id, tool = VALIDATOR_ID, "schema"

    def __init__(self, topology: Any):
        self.topology = topology

    def validate(self, ctx: Any) -> List[Diagnostic]:
        edges = tuple(getattr(self.topology, "pushes", ()) or ())
        intent = parsed_intent(ctx.files) if edges else None
        if intent is None:
            return []
        out: List[Diagnostic] = []
        for e in edges:
            if not self.satisfied(intent, e.topic, e.service, e.path):
                out.append(self.finding(intent, e.topic, e.service, e.path, ctx))
        return out

    # ------------------------------------------------------------------------------------------- typed comparison
    @staticmethod
    def realizers(intent: Any, topic: str) -> tuple:
        mods = [m for m in intent.modules if m.module == II.PUSH_MODULE and m.realizes == topic]
        res = [r for r in intent.resources if r.type == TOPIC_TYPE and r.realizes == topic]
        return mods, res

    def satisfied(self, intent: Any, topic: str, service: str, path: str) -> bool:
        mods, res = self.realizers(intent, topic)
        for m in mods:
            push = m.args.get(II.PUSH_ARG)
            if isinstance(push, dict) and _service_uri_ref(push.get("service"), service) and \
                    isinstance(push.get("path"), str) and push.get("path") == path:
                return True
        mod_names: Set[str] = {m.name for m in mods}
        res_names: Set[str] = {r.name for r in res}
        for r in intent.resources:
            if r.type != II.PUSH_SUBSCRIPTION_TYPE or not self._topic_of(r.arguments.get("topic"), mod_names,
                                                                          res_names):
                continue
            block = _single_block(r.arguments.get("push_config"))
            got = _endpoint_path(block.get("push_endpoint"), service) if block is not None else None
            if got is not None and (got == path or (got == "" and path == "/")):
                return True
        return False

    @staticmethod
    def _topic_of(v: Any, mod_names: Set[str], res_names: Set[str]) -> bool:
        if not isinstance(v, II.Ref):
            return False
        t = v.ref
        if isinstance(t, II.ModuleOutputRef):
            return t.module in mod_names and t.output in TOPIC_MODULE_OUTPUTS
        if isinstance(t, II.ResourceAttrRef):
            return t.type == TOPIC_TYPE and t.name in res_names and t.attr in TOPIC_RESOURCE_ATTRS
        return False

    # ------------------------------------------------------------------------------------------- the finding
    def finding(self, intent: Any, topic: str, service: str, path: str, ctx: Any) -> Diagnostic:
        mods, res = self.realizers(intent, topic)
        form = json.dumps(push_plan_form(service, path), sort_keys=True)
        endpoint = json.dumps({"$fn": "format", "$args": ["%s" + path, push_plan_form(service, path)["service"]]},
                              sort_keys=True)
        names = ({m.name for m in mods}, {r.name for r in res})
        raw_push = [r for r in intent.resources if r.type == II.PUSH_SUBSCRIPTION_TYPE
                    and self._topic_of(r.arguments.get("topic"), *names)
                    and _single_block(r.arguments.get("push_config")) is not None]
        pushing = [m for m in mods if II.PUSH_ARG in m.args]
        if pushing:
            m = pushing[0]
            hint = (f"Module {m.name} (messaging-pubsub, realizes {topic!r}) pushes elsewhere: set its \"push\" "
                    f"\"service\" to {json.dumps(push_plan_form(service, path)['service'], sort_keys=True)} and "
                    f"its \"path\" to {json.dumps(path)} (keep its service_account_email).")
        elif raw_push:
            r = raw_push[0]
            hint = (f"{II.PUSH_SUBSCRIPTION_TYPE}.{r.name} (on the topic {topic!r}) pushes elsewhere: set its "
                    f"push_config.push_endpoint to {endpoint} (keep its oidc_token).")
        elif mods:
            m = mods[0]
            hint = (f"Set \"push\" in the args of module {m.name} (the messaging-pubsub instance with \"realizes\": "
                    f"{json.dumps(topic)}) to {form}. The platform renders the push subscription, its endpoint, "
                    "OIDC token and audience from it; do not also write a google_pubsub_subscription for it.")
        elif res:
            r = res[0]
            args = {"topic": {"$ref": {"kind": "resource_attr", "type": TOPIC_TYPE, "name": r.name, "attr": "id"}},
                    "push_config": {"push_endpoint": {"$fn": "format", "$args": [
                        "%s" + path, push_plan_form(service, path)["service"]]},
                        "oidc_token": {"service_account_email": PUSH_PLAN_IDENTITY}}}
            hint = (f"The topic {topic!r} is realized by the resource {TOPIC_TYPE}.{r.name}: add a "
                    f"{II.PUSH_SUBSCRIPTION_TYPE} resource to \"resources\" whose \"arguments\" hold its name and "
                    f"{json.dumps(args, sort_keys=True)}.")
        else:
            hint = (f"Realize the topic {topic!r} with a messaging-pubsub module instance (\"realizes\": "
                    f"{json.dumps(topic)}) and set its \"push\" to {form}.")
        return Diagnostic(
            tool="schema", code=CODE, severity="error", error_class=ErrorClass.CODE_DEFECT, file=INTENT_PATH,
            source="precommit", iteration=ctx.iteration, symbol=SYMBOL_PREFIX + topic,
            message=(f"the plan's topic {topic!r} pushes to the service {service!r} at {path!r}, and the intent "
                     "declares no such push subscription"),
            hint=hint)


def register(stack: Any, topology: Any, iac_intent: Any) -> None:
    """V-IAC-PUSH, blocking: only on the intent path (`iac_intent` set) with a topology that declares a push edge."""
    if iac_intent is None or topology is None or not tuple(getattr(topology, "pushes", ()) or ()):
        return
    stack.register(PushPlanValidator(topology), "blocking")

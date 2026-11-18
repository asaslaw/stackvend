"""SECRET-INITIAL-VERSION F1 (red-team 11-10): a saved plan's JSON with every value the engine marks sensitive masked.

`tofu show -json <plan>` writes sensitive values in clear text (a re-plan's `prior_state`, the `before` / `after` of
no-op changes, sensitive outputs and root variables) and marks them with typed structures beside them. The terraform
server returns that JSON from `generate_plan` (`raw_plan_json`), which the `tf-applier` plan mode stores in Firestore
(`runner_results`). `redact_plan_json` replaces exactly the values those marks name, using only the engine's own
typed marks (never attribute names, never value patterns; AGENTS.md invariant 2):

- `resource_changes[]` / `resource_drift[]`: `change.before` by `change.before_sensitive`, `change.after` by
  `change.after_sensitive`;
- `output_changes{}`: `before` / `after` by `before_sensitive` / `after_sensitive`;
- `prior_state.values` / `planned_values` (every module, recursively): each resource's `values` by its
  `sensitive_values`, each output's `value` when its `sensitive` is true;
- `variables{}`: a root variable's `value` when `configuration.root_module.variables.<name>.sensitive` is true;
- `configuration` (every module, recursively): a `variables.<name>.default` whose variable is sensitive, and a module
  call's `expressions.<name>.constant_value` whose called module declares `<name>` sensitive.

A mark is `true` (the whole value), an object / list of marks (walk in step) or anything else (not sensitive). A value
the engine does not mark is returned unchanged (Do No Harm), as is everything that is not a plan value (addresses,
actions, `after_unknown`, references). `None` stays `None` (nothing to hide). Pure: the input is never changed.
"""
import copy
from typing import Any, Dict, Mapping

__all__ = ["SENSITIVE_PLACEHOLDER", "redact_plan_json", "mask_marked"]

SENSITIVE_PLACEHOLDER = "(sensitive value)"


def mask_marked(value: Any, mark: Any) -> Any:
    """`value` with every part `mark` marks sensitive replaced by SENSITIVE_PLACEHOLDER (same structure)."""
    if value is None:
        return None
    if mark is True:
        return SENSITIVE_PLACEHOLDER
    if isinstance(mark, dict) and isinstance(value, dict):
        return {k: mask_marked(v, mark.get(k)) for k, v in value.items()}
    if isinstance(mark, list) and isinstance(value, list):
        return [mask_marked(v, mark[i] if i < len(mark) else None) for i, v in enumerate(value)]
    return value


def _mask_change(change: Any) -> None:
    if not isinstance(change, dict):
        return
    for side in ("before", "after"):
        if side in change:
            change[side] = mask_marked(change[side], change.get(f"{side}_sensitive"))


def _mask_values_module(module: Any) -> None:
    """prior_state.values.root_module / planned_values.root_module and their child_modules."""
    if not isinstance(module, dict):
        return
    for res in module.get("resources") or []:
        if isinstance(res, dict) and "values" in res:
            res["values"] = mask_marked(res["values"], res.get("sensitive_values"))
    for child in module.get("child_modules") or []:
        _mask_values_module(child)


def _mask_values(values: Any) -> None:
    """A `values` representation: {outputs: {name: {sensitive, value}}, root_module: {...}}."""
    if not isinstance(values, dict):
        return
    for out in (values.get("outputs") or {}).values() if isinstance(values.get("outputs"), dict) else ():
        if isinstance(out, dict) and out.get("sensitive") is True and "value" in out:
            out["value"] = mask_marked(out["value"], True)
    _mask_values_module(values.get("root_module"))


def _sensitive_variables(module: Any) -> Dict[str, bool]:
    variables = module.get("variables") if isinstance(module, dict) else None
    if not isinstance(variables, dict):
        return {}
    return {name: True for name, v in variables.items() if isinstance(v, dict) and v.get("sensitive") is True}


def _mask_config_module(module: Any) -> None:
    """configuration.root_module and every called module: sensitive variable defaults and the constant arguments a
    module call passes to a sensitive variable of the called module."""
    if not isinstance(module, dict):
        return
    for name in _sensitive_variables(module):
        var = module["variables"][name]
        if "default" in var:
            var["default"] = mask_marked(var["default"], True)
    calls = module.get("module_calls")
    for call in calls.values() if isinstance(calls, dict) else ():
        if not isinstance(call, dict):
            continue
        child = call.get("module")
        child_sensitive = _sensitive_variables(child)
        expressions = call.get("expressions")
        for name, expr in expressions.items() if isinstance(expressions, dict) else ():
            if child_sensitive.get(name) and isinstance(expr, dict) and "constant_value" in expr:
                expr["constant_value"] = mask_marked(expr["constant_value"], True)
        _mask_config_module(child)


def redact_plan_json(plan_json: Mapping[str, Any]) -> Dict[str, Any]:
    """A deep copy of `plan_json` (a `tofu show -json` plan) with every engine-marked sensitive value masked."""
    out: Dict[str, Any] = copy.deepcopy(dict(plan_json))
    for key in ("resource_changes", "resource_drift"):
        for rc in out.get(key) or []:
            if isinstance(rc, dict):
                _mask_change(rc.get("change"))
    changes = out.get("output_changes")
    for change in changes.values() if isinstance(changes, dict) else ():
        _mask_change(change)
    prior = out.get("prior_state")
    if isinstance(prior, dict):
        _mask_values(prior.get("values"))
    _mask_values(out.get("planned_values"))
    config = out.get("configuration") if isinstance(out.get("configuration"), dict) else {}
    root_sensitive = _sensitive_variables(config.get("root_module"))
    variables = out.get("variables")
    for name, var in variables.items() if isinstance(variables, dict) else ():
        if root_sensitive.get(name) and isinstance(var, dict) and "value" in var:
            var["value"] = mask_marked(var["value"], True)
    _mask_config_module(config.get("root_module"))
    return out

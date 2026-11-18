"""Static, escaped HTML report for a harness invocation (FD-4BN Phase 0, plan §12.3). Pure: no I/O.

`render(summary, records) -> str` is deterministic for a fixed input. The page renders LLM output (stage errors,
diagnostics, file names), so the operator's own browser is the attack surface (red team F11):

- every interpolated value goes through `_e` (html.escape, quote=True, truncated at TRUNCATE chars with a marker);
  markup is built with `+` only, and every operand of a chain that emits markup is a constant, an `_e(...)` call, a
  builder call or STYLE (pinned by an AST test over the `+` chains; the module has no f-strings);
- no JavaScript, no external resources, no inline event handlers, no links built from data; the head carries a CSP
  that forbids everything except inline styles;
- generated file contents are never embedded: file names and sizes only (the tree stays in the run's blob store).
"""
from __future__ import annotations

import html
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import metrics
from .llm_proxy import LIVE_MODES
from .verdict import INCONCLUSIVE, WOULD_FAIL_AT, WOULD_SUCCEED, tally, verdict

TRUNCATE = 2000
TRUNC_MARKER = " [truncated]"
MAX_DIAGNOSTICS = 20
MAX_LIST = 50
CSP = "default-src 'none'; style-src 'unsafe-inline'"
BILLED_MODES = LIVE_MODES

# Shown verbatim on every report (plan §5.3, Phase 0 wording of §5.4).
NOT_CHECKED = (
    "Plan-time API errors: APIs not enabled, invalid machine types or regions for the org, name collisions, "
    "provider read-time lookups (data sources).",
    "Quotas and capacity (CPU, IPs, GKE), billing account state.",
    "Org policies (domain restricted sharing, allowed regions, CMEK required, external IP). The policy harvest step "
    "is skipped; compliance uses only spec intent.",
    "IAM propagation, Workload Identity Federation, Cloud Build buildpack success, container boot, health checks, "
    "runtime behaviour, QA tests, IAP/OAuth configuration.",
    "LLM non-determinism: one dry run is a sample, not a guarantee. A real run makes new LLM calls; N repeats show "
    "the spread. Synthetic mode uses the product's deterministic fallbacks for the architect, red team and lead plan, "
    "and minimal eval-only junior files, not a model.",
)
DIFFERS_COMMON = (
    "No FinOps cost check: the workflow's FinOps stage is not run.",
    "Compliance runs in-process (the deployed compliance server's engine, called locally), not on the compliance "
    "MCP server.",
    "Platform settings are pinned to the code defaults (the model under test replaces every agent model); an "
    "install's Firestore settings, junior prompts and directives are not read.",
    "No vended project, no repository, no authorized users: project id, branch and IAM members use the fallbacks; no "
    "custom modules or bundles; IPAM is not claimed.",
)
_NOTHING_CREATED = ("Nothing is created: no project, repository, commit, pull request, Firestore document or cloud "
                    "resource. ")
# RT fix 5: the credentials clause depends on the mode (BILLED_MODES == LIVE_MODES: the parent mints a token)
DIFFERS_FREE_LAST = (_NOTHING_CREATED + "In this mode (synthetic, replay-strict) the generation child has no "
                     "credentials and no token, and a guard refuses every network, process and cloud-client call.")
DIFFERS_BILLED_LAST = (_NOTHING_CREATED + "In this mode (record, live, replay-then-live) the generation child receives "
                       "one short-lived access token on stdin, used only by the harness's metered Vertex AI client: your "
                       "Application Default Credentials unless the run used --impersonate-service-account (recommended, "
                       "with a service account that can only call Vertex AI). A guard refuses every other network, "
                       "process and cloud-client call.")


def differs(llm_mode: Optional[str]) -> tuple:
    """The "How this differs from a real run" box for this mode."""
    return DIFFERS_COMMON + ((DIFFERS_BILLED_LAST,) if llm_mode in BILLED_MODES else (DIFFERS_FREE_LAST,))


WORDING = "A verdict of WOULD_SUCCEED means the pipeline would succeed through validation. It never means \"will deploy\"."

STYLE = """
body{font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:16px;background:#fafafa;color:#1b1b1b}
main{max-width:1100px;margin:0 auto}
h1{font-size:20px;margin:0 0 8px}h2{font-size:17px;margin:24px 0 8px}h3{font-size:15px;margin:12px 0 6px}
table{border-collapse:collapse;width:100%;margin:6px 0 12px;background:#fff}
th,td{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f0f0f0;font-weight:600}
.card{background:#fff;border:1px solid #ddd;border-radius:6px;padding:8px 12px;margin:8px 0}
.run{border-left:4px solid #888;padding-left:12px;margin:16px 0}
.chip{display:inline-block;padding:2px 8px;border-radius:10px;font-weight:600;font-size:13px}
.ok{background:#dff3e3;color:#11602a}.fail{background:#fde2e1;color:#8a1c14}.inc{background:#fff1cc;color:#6b4e00}
.box{background:#fff;border:1px solid #c9c9c9;border-radius:6px;padding:8px 14px;margin:12px 0}
.muted{color:#666}code{font:12px ui-monospace,Menlo,monospace}
@media (prefers-color-scheme: dark){body{background:#161616;color:#e6e6e6}table,.card,.box{background:#1f1f1f}
th{background:#2a2a2a}th,td,.card,.box{border-color:#3a3a3a}.muted{color:#a0a0a0}
.ok{background:#16351f;color:#9be0ad}.fail{background:#3d1a18;color:#f3a69f}.inc{background:#3a3214;color:#f0d68a}}
"""


def _e(value: Any) -> str:
    """The only way data enters the page: str(), truncate, html.escape(quote=True)."""
    s = "" if value is None else str(value)
    if len(s) > TRUNCATE:
        s = s[:TRUNCATE] + TRUNC_MARKER
    return html.escape(s, quote=True)


def _row(cells: Iterable[Any], header: bool = False) -> str:
    tag = "th" if header else "td"
    return "<tr>" + "".join("<" + tag + ">" + _e(c) + "</" + tag + ">" for c in cells) + "</tr>"


def _table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    body = "".join(_row(r) for r in rows)
    return "<table>" + _row(headers, header=True) + body + "</table>"


def _kv(pairs: Iterable[Sequence[Any]]) -> str:
    return "<table>" + "".join(_row(p) for p in pairs) + "</table>"


def _ul(items: Iterable[Any]) -> str:
    items = list(items)
    if not items:
        return "<p class=\"muted\">none</p>"
    return "<ul>" + "".join("<li>" + _e(i) + "</li>" for i in items) + "</ul>"


def _chip_class(v: str) -> str:
    if v == WOULD_SUCCEED:
        return "ok"
    if v.startswith(WOULD_FAIL_AT):
        return "fail"
    return "inc"


def _chip(v: str) -> str:
    return "<span class=\"chip " + _chip_class(v) + "\">" + _e(v) + "</span>"


def _card(title: str, inner: str) -> str:
    return "<div class=\"card\"><h3>" + _e(title) + "</h3>" + inner + "</div>"


def _stage_pairs(stage: Dict[str, Any], fields: Sequence[str]) -> List[List[Any]]:
    pairs: List[List[Any]] = [["ok", stage.get("ok")]]
    pairs += [[f, stage.get(f)] for f in fields if f in stage]
    if stage.get("error"):
        pairs.append(["error", stage["error"]])
    if stage.get("wall_s") is not None:
        pairs.append(["wall_s", stage["wall_s"]])
    return pairs


STAGE_FIELDS = {
    "architect": ("tasks", "consensus_status", "remediation_performed", "requires_human_approval",
                  "target_compute_services", "plan_file_path"),
    "compliance": ("profile", "injected_tasks", "allow_unauthenticated", "enable_direct_iap",
                   "domain_restricted_sharing"),
    "developer": ("path", "files"),
    "precommit": ("status", "rejected", "capture_point", "note"),
    "gatekeeper_4_5": ("passed", "idempotent"),
}


def _c3_tofu(score: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return ((((score or {}).get("checkpoints") or {}).get("C3_committed") or {}).get("tofu")) or {}


def _isolation_rows(result: Dict[str, Any]) -> List[List[Any]]:
    rows = []
    for ev in ((result.get("state") or {}).get("events") or []):
        if ev.get("stage") in ("canary", "guard") or not str(ev.get("kind", "")).endswith("_blocked"):
            continue
        d = ev.get("detail") or {}
        target = (d.get("call") or d.get("host") or d.get("address") or d.get("target")) if isinstance(d, dict) else d
        rows.append([ev.get("stage"), ev.get("kind"), target])
    return rows[:MAX_LIST]


def _step1_diag_rows(diags: Iterable[Any]) -> List[List[Any]]:
    rows = []
    for d in list(diags or [])[:MAX_LIST]:
        if not isinstance(d, dict):
            rows.append(["", "", "", "", "", "", str(d)])
            continue
        # snippet is generated file content: never embedded
        rows.append([d.get("tool"), d.get("code"), d.get("severity"), d.get("error_class"), d.get("file"),
                     d.get("line"), d.get("message")])
    return rows


def _joined(values: Any) -> str:
    """A list / dict as one line of text (escaped later by _e like every other value)."""
    if isinstance(values, dict):
        return ", ".join(str(k) + "=" + str(values[k]) for k in sorted(values)) or "none"
    if isinstance(values, (list, tuple)):
        return ", ".join(str(x) for x in values) or "none"
    return "n/a" if values is None else str(values)


def _ti0_pairs(row: Dict[str, Any]) -> List[List[Any]]:
    fdc = row.get("first_draft_codes") or {}
    exp = row.get("synthetic_expectation")
    pairs: List[List[Any]] = [
        ["first-draft codes (IaC author)", _joined(fdc.get("iac"))],
        ["first-draft codes (app author)", _joined(fdc.get("app"))],
        ["first-draft codes (single-turn, both)", _joined(fdc.get("mixed"))],
        ["repair calls by persona", _joined(row.get("repair_calls_by_persona"))],
        ["platform blocks in AI files", _joined(row.get("platform_blocks_in_ai_files"))],
        ["AI IaC paths (first draft)", _joined(row.get("ai_iac_paths"))],
        ["first-draft resource types (IaC persona)", _joined(row.get("first_draft_types"))],
        ["data sources used", _joined(row.get("data_sources_used"))],
        ["functions used", _joined(row.get("functions_used"))],
        ["first-draft source", row.get("first_draft_source")],
        ["healer fires on validate-valid input by kind", _joined(row.get("healer_fvv_split"))],
        ["consensus status", row.get("consensus_status")],
        ["consensus changed topology", row.get("consensus_changed_topology")],
        ["architect typed failure", row.get("architect_failed_typed")],
        ["committed public members (root module)", _joined(row.get("c3_public_members"))],
        ["committed owner grants (root module)", _joined(row.get("c3_owner_grants"))],
    ]
    if row.get("compute_dropped_on_rerun") is not None:
        pairs.append(["compute dropped on rerun", _joined(row.get("compute_dropped_on_rerun"))])
    if exp is not None:
        pairs.append(["synthetic expectation", "met" if exp.get("met") else "NOT met"])
        pairs.append(["expected (any of)", _joined(exp.get("accept"))])
        pairs.append(["got", exp.get("got")])
    return pairs


def _run_section(rec: Dict[str, Any], row: Dict[str, Any], v: Dict[str, Any]) -> str:
    result = rec.get("result") or {}
    stages = result.get("stages") or {}
    parts: List[str] = ["<section class=\"run\"><h2>Run " + _e(row.get("key")) + " " + _chip(v["verdict"]) + "</h2>"]
    parts.append(_kv([["verdict", v["verdict"]], ["stage", v.get("stage")], ["reason", v.get("reason")],
                      ["gate false-pass", v.get("gate_false_pass")], ["pipeline outcome", row.get("outcome")],
                      ["valid run", row.get("valid")], ["invalid reasons", ", ".join(row.get("invalid_reasons") or [])
                                                        or "none"]]))
    parts.append("<h3>Warnings</h3>" + _ul(v.get("warnings") or []))
    for name in ("architect", "compliance", "developer", "precommit", "gatekeeper_4_5"):
        st = stages.get(name)
        if st is None:
            parts.append(_card(name, "<p class=\"muted\">not reached</p>"))
            continue
        inner = _kv(_stage_pairs(st, STAGE_FIELDS[name]))
        if name == "gatekeeper_4_5" and st.get("errors"):
            inner += "<h3>gatekeeper errors</h3>" + _ul(list(st["errors"])[:MAX_DIAGNOSTICS])
        if name == "developer":
            files = rec.get("c3_files")
            if files is not None:
                inner += ("<h3>committed files (names and sizes only; contents are not embedded)</h3>"
                          + _table(["file", "bytes"], [[f.get("name"), f.get("bytes")] for f in files[:200]]))
        parts.append(_card(name, inner))
    t3 = _c3_tofu(rec.get("score"))
    diags = list(t3.get("diagnostics") or [])
    tofu_inner = _kv([["status", t3.get("status") or "not scored"], ["validate_ok", t3.get("validate_ok")],
                      ["diagnostics", len(diags)], ["plan_ok", (t3.get("plan") or {}).get("plan_ok")]])
    if diags:
        tofu_inner += _table(["severity", "summary", "file", "line", "detail"],
                             [[d.get("severity"), d.get("summary"), d.get("file"), d.get("line"), d.get("detail")]
                              for d in diags[:MAX_DIAGNOSTICS]])
    parts.append(_card("C3 tofu validate (committed tree)", tofu_inner))
    parts.append(_card("invariants", _kv([["violations", row.get("invariant_violations")],
                                          ["I6 service_uri cycles", row.get("I6_cycles")],
                                          ["I3 hardcoded literals", row.get("I3_literals")],
                                          ["golden module mutations", row.get("golden_module_mutations")]])))
    iso = _isolation_rows(result)
    parts.append(_card("isolation attempts (blocked; nothing reached the network or a cloud API)",
                       _kv([["blocked attempts", row.get("isolation_attempts")]])
                       + (_table(["stage", "kind", "target"], iso) if iso else "")))
    served = row.get("served") or {}
    parts.append(_card("LLM", _kv([["calls", row.get("llm_calls")], ["usd", row.get("usd")],
                                   ["served", ", ".join(k + "=" + str(served[k]) for k in sorted(served))],
                                   ["wall_s", row.get("wall_s")]])))
    hs = result.get("hallucination_stack") or {}
    if hs:
        vr = hs.get("validation_report") or {}
        typed = hs.get("developer_failed_typed") or {}
        inner = _kv([["validation status", vr.get("status")], ["typed failure", typed.get("error_class")],
                     ["repair events", len(hs.get("repair_events") or [])],
                     ["report-only codes", ", ".join(row.get("report_only_codes") or []) or "none"]])
        drows = _step1_diag_rows(vr.get("diagnostics") or typed.get("diagnostics") or [])
        if drows:
            inner += _table(["tool", "code", "severity", "class", "file", "line", "message"], drows)
        parts.append(_card("Step 1 typed diagnostics", inner))
    parts.append(_card("typed-IaC measurement (TI-0)", _kv(_ti0_pairs(row))))
    parts.append("</section>")
    return "".join(parts)


def render(summary: Dict[str, Any], records: List[Dict[str, Any]]) -> str:
    m = summary.get("manifest") or {}
    o = summary.get("overall") or {}
    rows = [metrics.run_row(r) for r in records]
    verdicts = [verdict(row, rec.get("result") or {}) for row, rec in zip(rows, records)]
    t = tally(verdicts)
    head = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"" + _e(CSP) + "\">"
            "<meta name=\"referrer\" content=\"no-referrer\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>StackVend dry run report</title><style>" + STYLE + "</style></head><body><main>")
    parts = [head, "<h1>StackVend dry run: " + _e(t["would_succeed"]) + "/" + _e(t["runs"]) + " would succeed "
             "through validation</h1>", "<p class=\"muted\">" + _e(WORDING) + "</p>"]
    parts.append(_kv([
        ["invocation id", m.get("id")], ["LLM mode", m.get("llm_mode")], ["model", m.get("model")],
        ["product SHA", m.get("product_sha")], ["product dirty", m.get("product_dirty")],
        ["harness SHA", m.get("harness_sha")], ["spec source", m.get("spec_source")],
        ["spec sha256", m.get("spec_sha256")], ["product id", m.get("product_id")],
        ["runs", len(records)], ["metered spend (USD)", o.get("usd")],
        ["billed", "yes: live Vertex calls (see metered spend)" if m.get("llm_mode") in BILLED_MODES
         else "no: this mode makes no paid calls (synthetic spend is notional)"],
        ["LLM calls", o.get("llm_calls")],
        ["wall time per run, mean (s)", o.get("wall_s_mean")], ["tofu", m.get("tofu")],
        ["provider set", m.get("provider_set") or "default"]]))
    parts.append("<h2>Runs</h2>")
    parts.append(_table(["run", "verdict", "stage", "outcome", "valid", "C3 validate", "committed files", "usd"],
                        [[row.get("key"), v["verdict"], v.get("stage"), row.get("outcome"), row.get("valid"),
                          row.get("c3_validate_ok"), len(rec.get("c3_files") or []) if rec.get("c3_files") is not None
                          else "", row.get("usd")] for row, v, rec in zip(rows, verdicts, records)]))
    parts.append(_kv([[k, n] for k, n in t["counts"].items()] + [["would succeed", str(t["would_succeed"]) + "/"
                                                                   + str(t["runs"])]]))
    parts.append("<h2>Typed-IaC measurement (TI-0)</h2>")
    parts.append(_kv([
        ["architect consensus arm", m.get("architect_consensus") or "on"],
        ["first-draft code runs", _joined(o.get("first_draft_code_runs"))],
        ["typed failure code runs", _joined(o.get("typed_failure_code_runs"))],
        ["repair calls (IaC / total)", str(o.get("repair_calls_iac")) + " / " + str(o.get("repair_calls_total"))],
        ["repair calls by persona", _joined(o.get("repair_calls_by_persona"))],
        ["platform blocks in AI files (blocks; runs)", str(o.get("platform_blocks_in_ai_files")) + "; "
         + str(o.get("platform_blocks_in_ai_files_runs"))],
        ["AI IaC path runs", _joined(o.get("ai_iac_path_runs"))],
        ["first-draft resource type runs", _joined(o.get("first_draft_type_runs"))],
        ["data source runs", _joined(o.get("data_source_runs"))],
        ["function runs", _joined(o.get("function_runs"))],
        ["healer fires on validate-valid input by kind", _joined(o.get("healer_fvv_split"))],
        ["consensus changed topology (runs)", o.get("consensus_changed_topology")],
        ["synthetic expectations met (all runs)", o.get("synthetic_expected_met")],
        ["synthetic expectations met (valid runs)", o.get("synthetic_expected_met_valid")]]))
    for row, v, rec in zip(rows, verdicts, records):
        parts.append(_run_section(rec, row, v))
    parts.append("<div class=\"box\"><h2>What this does not check</h2>" + _ul(NOT_CHECKED) + "</div>")
    parts.append("<div class=\"box\"><h2>How this differs from a real run</h2>" + _ul(differs(m.get("llm_mode")))
                 + "</div>")
    parts.append("<p class=\"muted\">Verdicts: " + _e(WOULD_SUCCEED) + " (through validation), "
                 + _e(WOULD_FAIL_AT) + "&lt;stage&gt;, " + _e(INCONCLUSIVE) + "&lt;reason&gt;.</p>")
    parts.append("</main></body></html>\n")
    return "".join(parts)

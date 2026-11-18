"""
StackVend project vending: owner-run provenance backfill for workloads vended before lane 18 S1 (plan F7, 2.4).

Usage (owner only, after S0 + S0b; never automatic):
    python backfill_provenance.py --project <product_id> [--project <product_id> ...]            # dry run (default)
    python backfill_provenance.py --project <product_id> [--project ...] --apply                 # write

Rules:
  * explicit product ids only; there is no "all" mode, and no --project means nothing runs (exit 2);
  * dry run prints, per product: ledger trace_id, project id + number, CRM createTime, planned labels and tag;
  * skipped (never written): missing ledger, platform workload, no project id, no vend trace (trace_id), brownfield /
    adopted projects (is_brownfield, track BYO_IAC), provenance already present, CRM identity mismatch, project not
    ACTIVE or outside the managed root folder;
  * --apply writes labels (stackvend-managed / stackvend-product-id / stackvend-workload-type = "standard"), the
    stackvend-managed tag binding, and workload_provenance/{pid} with created_by = "owner-backfill" and NO sandbox
    expiry: a backfilled project is eligible for an approved (HITL) decommission only, never SANDBOX_TTL.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import destructive_guard as dg


def plan_backfill(product_id: str, *, store, crm, managed_root_folder_id: Optional[str],
                  tag_value: Optional[str], host_project_ids) -> Dict[str, Any]:
    """Read-only. Returns {"product_id", "decision": "PLANNED" | "SKIPPED:<reason>", ...facts}."""
    out: Dict[str, Any] = {"product_id": product_id}

    def skip(reason: str, detail: str = "") -> Dict[str, Any]:
        out.update(decision=f"SKIPPED:{reason}", detail=detail)
        return out

    try:
        w = store.get_workload(product_id)
        prov = store.get_provenance(product_id)
    except dg.StoreUnavailable as e:
        return skip("LEDGER_UNAVAILABLE", str(e))
    if w is None:
        return skip("LEDGER_MISSING")
    if w.get("is_castor") is True or product_id in dg.PLATFORM_PSEUDO_WORKLOADS:
        return skip("PLATFORM_WORKLOAD")
    project_id = w.get("project_id")
    if not isinstance(project_id, str) or not project_id or project_id in host_project_ids:
        return skip("NO_PROJECT")
    trace_id = w.get("trace_id")
    out.update(project_id=project_id, trace_id=trace_id)
    if not isinstance(trace_id, str) or not trace_id:
        return skip("NO_VEND_TRACE")
    if w.get("is_brownfield") is True or w.get("track") == "BYO_IAC":
        return skip("BROWNFIELD")
    if prov is not None:
        return skip("ALREADY_PROVENANCED", str(prov.get("created_by")))
    try:
        claimants = store.workloads_claiming(project_id)
    except dg.StoreUnavailable as e:
        return skip("LEDGER_UNAVAILABLE", str(e))
    if claimants != [product_id]:
        return skip("LEDGER_MISMATCH", f"claimed by {sorted(claimants)}")
    try:
        project = crm.get_project(project_id)
        number = dg._number_of(project) if isinstance(project, dict) else ""
        ancestors = crm.get_ancestry(project_id) if number else []
    except dg.CRMUnavailable as e:
        return skip("CRM_UNAVAILABLE", str(e))
    if not number or project.get("projectId") != project_id:
        return skip("CRM_MISMATCH")
    ledger_number = w.get("project_number")
    if ledger_number not in (None, "") and dg._num(ledger_number) != number:
        return skip("LEDGER_MISMATCH", "ledger project_number differs from Resource Manager")
    if project.get("state") != "ACTIVE":
        return skip("NOT_ACTIVE", str(project.get("state")))
    if not managed_root_folder_id or not any(
            isinstance(a, dict) and isinstance(a.get("resourceId"), dict)
            and a["resourceId"].get("type") == "folder" and str(a["resourceId"].get("id")) == managed_root_folder_id
            for a in (ancestors or [])[1:]):
        return skip("NOT_IN_MANAGED_FOLDER")
    labels = dict(project.get("labels") or {})
    labels.update({dg.LABEL_MANAGED: "true", dg.LABEL_PRODUCT: product_id, dg.LABEL_TYPE: "standard"})
    out.update(decision="PLANNED", project_number=number, crm_create_time=project.get("createTime"),
               planned_labels=labels, planned_tag_value=tag_value)
    return out


def apply_backfill(plan: Dict[str, Any], *, store, crm, now: datetime) -> Dict[str, Any]:
    if plan.get("decision") != "PLANNED":
        return plan
    pid, number = plan["product_id"], plan["project_number"]
    result = dict(plan)
    try:
        crm.patch_labels(number, plan["planned_labels"])
        tag_bound = False
        if plan.get("planned_tag_value"):
            crm.create_tag_binding(number, plan["planned_tag_value"])
            tag_bound = True
        store.create_provenance(pid, {
            "created_by": dg.CREATED_BY_BACKFILL,
            "product_id": pid,
            "project_id": plan["project_id"],
            "project_number": number,
            "created_at": plan.get("crm_create_time"),
            "backfilled_at": now.isoformat(),
            "trace_id": plan.get("trace_id"),
            "labels_written": True,
            "tag_bound": tag_bound,
            "is_sandbox": False,
            "sandbox_auto_decommission": False,
            "sandbox_designation_source": None,
            "sandbox_ttl_days": None,
            "sandbox_expires_at": None,
            "extensions": 0,
            "liens": [],
            "dns_records": [],
        })
        result["decision"] = "APPLIED" if tag_bound else "APPLIED_UNTAGGED"
    except Exception as e:  # noqa: BLE001 - reported per project; the owner re-runs
        result["decision"] = "FAILED"
        result["detail"] = f"{type(e).__name__}: {e}"
    return result


def run(argv: List[str], *, store, crm, env=None, now: Optional[datetime] = None, out=sys.stdout) -> int:
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--project", action="append", default=[], help="product id (repeatable); required")
    parser.add_argument("--apply", action="store_true", help="write (default: dry run)")
    args = parser.parse_args(argv)
    if not args.project:
        print("refused: pass explicit --project ids (there is no 'all' mode)", file=out)
        return 2
    root = dg._env_root_folder(env.get("MANAGED_WORKLOADS_FOLDER_ID"))
    tag = dg._env_tag_value(env.get("STACKVEND_MANAGED_TAG_VALUE"))
    hosts = frozenset(v for v in (env.get("PROJECT_ID"), env.get("GOOGLE_CLOUD_PROJECT"),
                                  env.get("PLATFORM_PROJECT_ID")) if v)
    if args.apply and not tag:
        print("refused: --apply needs STACKVEND_MANAGED_TAG_VALUE (S0)", file=out)
        return 2
    now = now or datetime.now(timezone.utc)
    worst = 0
    for pid in dict.fromkeys(args.project):
        plan = plan_backfill(pid, store=store, crm=crm, managed_root_folder_id=root, tag_value=tag,
                             host_project_ids=hosts)
        result = apply_backfill(plan, store=store, crm=crm, now=now) if args.apply else plan
        print(json.dumps(result, sort_keys=True, default=str), file=out)
        if result.get("decision") == "FAILED":
            worst = 1
    return worst


def main() -> int:  # pragma: no cover - owner-run entry point
    from google.cloud import firestore
    project = os.environ["PROJECT_ID"]
    db = firestore.Client(project=project)
    guard_name = (os.getenv("STACKVEND_GUARD_FIRESTORE_DATABASE") or "").strip()
    guard_db = firestore.Client(project=project, database=guard_name) if guard_name else db
    return run(sys.argv[1:], store=dg.FirestoreGuardStore(db, guard_db), crm=dg.RestCRM())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

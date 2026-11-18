"""
tf-applier: Cloud Run Job batch execution entrypoint for heavy/long-running Terraform applies.
Runs with up to 24-hour execution timeout, fully isolated container per deployment,
streams live Terraform logs, and guarantees callback notification to Cloud Workflows.
The callback body is the deploy result (TerraformService.deploy_workload) with `status` / `error` set here; every
other result key passes through, including `error_class` and WF-OPERATOR-FLAG's `operator_required` (boolean).

FD-7L Phase 2a (plan rev 3 section 2.4, re-RT R3): on a Per-workload install (`STACKVEND_TF_RUNNER_IDENTITY` =
PER_WORKLOAD) the job reads ONLY `RUNNER_NONCE` from its environment, redeems it once with vending for the dispatch
record and an in-memory session key, verifies the run's target against vending's SIGNED provenance record, the
workload record and the state bucket's owner, and deploys with the workload deployer's brokered credentials through a
local metadata endpoint. Product, trace, branch, project and callback URL come from the verified records only; the
old variables (PRODUCT_ID, TARGET_PROJECT_ID, ...) are ignored and named in one RUNNER_ENV_IGNORED line. A Shared
install (unset / PLATFORM) runs exactly the path below as before.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
from service import TOFU_TIME_LIMITS_JOB, TerraformService, deploy_url_summary, is_cloud_capacity_stockout
from service import install_runner_identity_mode, ri, runner_creds   # FD-7L: install mode + brokered credentials
from service import TOFU_TIME_LIMITS_SERVICE, DestroyPolicy            # FD-7L 5b: sync runs (server limits, EXP-7)
from service import IaCEngineDowngradeBlockedError                     # FD-7L 5b part 2 (SAT-37): the plan run
import runner_runs as rr                                               # FD-7L 5b: staged payload + result channel
from shared.callbacks import guaranteed_callback_scope
from shared.logging_utils import AgentLifecycle
from shared.path_safety import (
    TF_WORKSPACE_RESERVED,
    UnsafePathError,
    validate_manifest_keys,
    validate_path_component,
    validate_trace_id,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("tf-applier")


def _per_workload_install() -> bool:
    """FD-7L-n: True only for an exact PER_WORKLOAD. A mode that cannot be read is False here; run_job decides on the
    error first (SAT-41 LOW-1: an execution with a nonce or a callback URL never runs the Shared path on it)."""
    return _install_mode()[0]


def _install_mode():
    """(per_workload, the typed mode-read error or None), through the one mode reader (FD-7L 2b F5)."""
    try:
        return install_runner_identity_mode() == ri.MODE_PER_WORKLOAD, None
    except ri.RunnerIdentityError as e:
        return False, e


# SAT-41 (FD-7L pre-switch RT HIGH-2 (b)): an execution started with the Shared inputs (CALLBACK_URL, no RUNNER_NONCE)
# on an install that is now Per workload (a deploy started just before a mode switch), and the symmetric case.
RUNNER_EXECUTION_NOT_DISPATCHED = "RUNNER_EXECUTION_NOT_DISPATCHED"
RUNNER_NONCE_ON_SHARED_INSTALL = "RUNNER_NONCE_ON_SHARED_INSTALL"


def _report_unrunnable(callback_url: str, code: str, detail: str) -> None:
    """SAT-41 (HIGH-2 (b), LOW-1): the typed FAILED callback of an execution this job will not run, through the
    guaranteed callback mechanism (which sends a token only to this platform's Workflows callback endpoint). Nothing
    is deployed. Product and trace are the execution's own inputs, used only to label the failure."""
    product_id = os.getenv("PRODUCT_ID") or ""
    trace_id = os.getenv("TRACE_ID") or ""
    try:
        if trace_id:
            validate_trace_id(trace_id)
    except UnsafePathError:
        trace_id = ""
    db = None
    try:
        db = TerraformService().db
    except Exception as e:  # noqa: BLE001 - the callback is still sent; only the pipeline record is not updated
        logger.warning(f"no Firestore client for the pipeline record ({type(e).__name__})")
    logger.error(f"{code}: {detail}")
    with guaranteed_callback_scope(callback_url=callback_url, trace_id=trace_id or None, stage_name="terraform",
                                   product_id=product_id or None, firestore_db=db) as outcome:
        outcome.update(_failed(code, detail, product_id, trace_id))


def run_job():
    release_info.log_release("tf-applier")  # FD-7C P3a: one stackvend.release line per run (mcp-terraform-server image)
    per_workload, mode_error = _install_mode()
    has_nonce = bool(os.getenv(runner_creds.NONCE_ENV))
    env_callback = os.getenv("CALLBACK_URL") or None
    if mode_error is not None and (has_nonce or env_callback):
        # SAT-41 LOW-1: never the Shared path on a mode that cannot be read (a nonce-only execution's failure is
        # reported by the terraform server's dispatch watcher)
        detail = (f"the runner identity mode could not be read ({mode_error.code}: {mode_error.detail}); nothing "
                  "was deployed")
        if env_callback:
            _report_unrunnable(env_callback, mode_error.code, detail)
        else:
            logger.error(f"{mode_error.code} ({mode_error.stage}): {detail}")
        sys.exit(1)
    if per_workload:
        if not has_nonce and env_callback:
            _report_unrunnable(env_callback, RUNNER_EXECUTION_NOT_DISPATCHED, (
                f"this tf-applier execution was started with the Shared inputs (CALLBACK_URL, no "
                f"{runner_creds.NONCE_ENV}) but the install's runner identity mode is Per workload (for example a "
                "deploy started just before a mode switch); a Per-workload execution is started only by vending's "
                "dispatch. Nothing was deployed; run the deploy again"))
            sys.exit(1)
        sys.exit(0 if run_brokered_job() else 1)
    if has_nonce and not os.getenv("PRODUCT_ID"):
        logger.error(f"{RUNNER_NONCE_ON_SHARED_INSTALL}: this tf-applier execution was dispatched by vending for a "
                     "Per-workload run, but the install's runner identity mode is Shared (for example a dispatch just "
                     "before a switch back); nothing runs. The terraform server's dispatch watcher reports the typed "
                     "failure to the workflow.")
        sys.exit(1)
    product_id = os.getenv("PRODUCT_ID") or (sys.argv[1] if len(sys.argv) > 1 else "")
    trace_id = os.getenv("TRACE_ID") or (sys.argv[2] if len(sys.argv) > 2 else "")
    target_project_id = os.getenv("TARGET_PROJECT_ID") or None
    callback_url = os.getenv("CALLBACK_URL") or None
    branch = os.getenv("BRANCH") or "main"
    hcl_json = os.getenv("HCL_FILES_JSON")

    if not product_id:
        logger.error("PRODUCT_ID is required for tf-applier.")
        sys.exit(1)

    if not trace_id:
        trace_id = f"tf-applier-{product_id}"

    service = TerraformService()
    # FD-4AQ W3 (AQ-5): the job's limits (apply/destroy 3 h, other commands 30 min, 15 min grace after SIGINT),
    # not the server's 20 min cap.
    service.tofu_time_limits = TOFU_TIME_LIMITS_JOB

    success = False
    try:
        success = _run_deploy(service, product_id, trace_id, target_project_id, callback_url, branch, hcl_json)
    finally:
        _remove_trace_workspace(service, trace_id)

    sys.exit(0 if success else 1)


# ------------------------------------------------------------------------------------------------ FD-7L Phase 2a
class BrokeredRun:
    """One redeemed Per-workload run: the verified dispatch record, the session key (memory only) and, after
    `prepare`, the deployer's credentials, the local metadata endpoint and their registration on the service."""

    def __init__(self, record: Dict[str, Any], session_key: str, broker: Any, *,
                 guard_db_factory: Optional[Callable[[], Any]] = None,
                 certs: Optional[Callable[..., Any]] = None, environ: Optional[Mapping[str, str]] = None,
                 tick_s: float = runner_creds.TICK_S):
        self.record = record
        self.__session_key = session_key
        self.broker = broker
        self._guard_db_factory = guard_db_factory
        self._certs = certs
        self._environ = os.environ if environ is None else environ
        self._tick_s = tick_s
        self.credentials = None
        self.endpoint = None
        self.key_id: Optional[str] = None
        self._registration = None
        self._service = None
        self.dispatch_id: Optional[str] = None   # FD-7L 5b: sha256 of the nonce (the result document's id)

    def __repr__(self) -> str:
        return f"BrokeredRun(product={self.record.get('product_id')!r}, project={self.record.get('project_id')!r})"

    @property
    def project_id(self) -> str:
        return self.record["project_id"]

    def _guard_db(self):
        if self._guard_db_factory is not None:
            return self._guard_db_factory()
        name = (self._environ.get(runner_creds.GUARD_DB_ENV) or "").strip()
        if not name:
            raise ri.RunnerIdentityError(runner_creds.RUNNER_IDENTITY_NOT_READY,
                                         f"{runner_creds.GUARD_DB_ENV} is not set on this job (plan step A)",
                                         stage="runner-config", http_status=503)
        from google.cloud import firestore
        return firestore.Client(project=self._environ.get("PROJECT_ID"), database=name)

    def _workload_record(self, service) -> Optional[Dict[str, Any]]:
        if not service.db:
            return None
        snap = service.db.collection("workloads").document(self.record["product_id"]).get()
        return (snap.to_dict() or {}) if getattr(snap, "exists", False) is True else None

    def prepare(self, service) -> Optional[Dict[str, Any]]:
        """None when the run may deploy (credentials minted, endpoint started, registered for the trace folder), else
        the typed FAILED result for the callback. Order: dispatch mode -> signed provenance + workload record ->
        first mint -> state bucket owner -> endpoint -> registration."""
        product_id, trace_id = self.record.get("product_id"), self.record.get("trace_id")
        try:
            if not self.supported_dispatch():
                raise ri.RunnerIdentityError(
                    runner_creds.RUNNER_MODE_UNSUPPORTED,
                    f"dispatch mode {self.record.get('mode')!r} (with a staged payload or a saved plan) is not run by "
                    "this job: it runs the workflow's `deploy` (callback, no payload) and the synchronous `deploy` / "
                    "`force_unlock` / `plan` (staged payload, result document; FD-7L Phase 5b)",
                    stage="runner-dispatch")
            try:
                snap = self._guard_db().collection(ri.PROVENANCE_COLLECTION).document(product_id).get()
                provenance = snap.to_dict() if getattr(snap, "exists", False) is True else None
                workload = self._workload_record(service)
            except ri.RunnerIdentityError:
                raise
            except Exception as e:  # noqa: BLE001 - a record that cannot be read is never assumed
                raise ri.RunnerIdentityError(runner_creds.RUNNER_IDENTITY_NOT_READY,
                                             f"{product_id}: records unreadable ({type(e).__name__})",
                                             stage="runner-target", http_status=503) from None
            verified, self.key_id = runner_creds.verify_run_target(
                self.record, provenance=provenance, workload=workload,
                expected_signer=ri.expected_broker_email(self._environ),
                certs=self._certs or ri.X509CertFetcher())
            self.credentials = runner_creds.BrokeredCredentials(
                self.broker, self.__session_key, project_id=verified["project_id"],
                deployer_email=verified["deployer_email"])
            self.credentials.current_token()                       # the first mint
            runner_creds.check_state_bucket_owner(self.credentials.session(), verified["state_bucket"],
                                                  verified["project_number"])
            self.endpoint = runner_creds.LocalMetadataEndpoint(self.credentials, tick_s=self._tick_s).start()
            self._service = service
            self._registration = service._register_workspace_runner(
                service.workspace_trace_dir(trace_id),
                runner_creds.WorkspaceRunner(self.credentials, self.endpoint, self.key_id,
                                             product_id=verified["product_id"],          # FD-7L Phase 4: the run
                                             repository=verified.get("repository")))    # reads only this repository
        except ri.RunnerIdentityError as e:
            self.close()
            logger.error(f"{e.code} ({e.stage}): {e.detail}")
            return {"status": "FAILED", "error_class": e.code, "error": f"{e.code}: {e.detail}",
                    "product_id": product_id, "trace_id": trace_id, "operator_required": True}
        logger.info(f"Per-workload run of '{product_id}' as {self.credentials.deployer_email} "
                    f"(provenance key {self.key_id})")
        return None

    @property
    def synchronous(self) -> bool:
        """FD-7L 5b: a dispatch without a callback URL answers through the result document."""
        return self.record.get("callback_url") is None

    def supported_dispatch(self) -> bool:
        """The workflow's deploy (callback URL, no payload), or a synchronous run (no callback URL) of a sync mode with
        a staged payload. Never a saved plan (plan / apply are not executions yet)."""
        rec = self.record
        if rec.get("saved_plan_sha256") is not None:
            return False
        if not self.synchronous:
            return rec.get("mode") == "deploy" and rec.get("payload_ref") is None
        return rec.get("mode") in rr.SYNC_MODES and rec.get("payload_ref") is not None

    def sign_result(self, result_sha256: str) -> None:
        """FD-7L 5b (SAT-37): vending signs this synchronous run's result fingerprint into its dispatch record (the
        session key stays in memory). Raises RunnerIdentityError (typed)."""
        self.broker.sign_result(self.__session_key, result_sha256)

    def typed_result(self, res: Dict[str, Any]) -> Dict[str, Any]:
        """A deploy that the broker failure interrupted carries RUNNER_BROKER_UNAVAILABLE (operator_required)."""
        failure = self.endpoint.failure if self.endpoint is not None else None
        if failure is None or not isinstance(res, dict) or res.get("status") == "SUCCESS":
            return res
        return dict(res, error_class=failure.code, operator_required=True,
                    error=f"{failure.code}: {failure.detail}")

    def close(self) -> None:
        if self._registration is not None and self._service is not None:
            self._service._forget_workspace_runner(*self._registration)
            self._registration = None
        if self.endpoint is not None:
            self.endpoint.stop()


def redeem_run(environ: Mapping[str, str], *, broker: Any = None,
               region_lookup: Optional[Callable[[], Optional[str]]] = None, **run_kwargs) -> BrokeredRun:
    """Reads RUNNER_NONCE (and nothing else of the old inputs), names every ignored input once (RUNNER_ENV_IGNORED),
    and redeems the nonce for this execution. Raises RunnerIdentityError (typed)."""
    ignored = [name for name in runner_creds.LEGACY_JOB_ENV if environ.get(name)]
    if len(sys.argv) > 1:
        ignored.append("argv")
    if ignored:
        logger.warning(f"{runner_creds.RUNNER_ENV_IGNORED}: {', '.join(ignored)} (a Per-workload run takes its inputs "
                       "only from the signed dispatch record)")
    nonce = environ.get(runner_creds.NONCE_ENV) or ""
    if not nonce:
        raise ri.RunnerIdentityError(runner_creds.RUNNER_IDENTITY_NOT_READY, f"{runner_creds.NONCE_ENV} is not set "
                                     "(a Per-workload execution is started only by vending's dispatch)",
                                     stage="runner-config", http_status=503)
    if broker is None:
        url = (environ.get(runner_creds.VENDING_URL_ENV) or "").strip()
        if not url:
            raise ri.RunnerIdentityError(runner_creds.RUNNER_IDENTITY_NOT_READY,
                                         f"{runner_creds.VENDING_URL_ENV} is not set on this job (plan step A)",
                                         stage="runner-config", http_status=503)
        broker = runner_creds.BrokerClient(url)
    try:
        region = (region_lookup or runner_creds.metadata_region)()
    except Exception as e:  # noqa: BLE001
        raise ri.RunnerIdentityError(runner_creds.RUNNER_IDENTITY_NOT_READY,
                                     f"the execution's region is unknown ({type(e).__name__})",
                                     stage="runner-config", http_status=503) from None
    execution = runner_creds.execution_name(environ, region)
    record, session_key = broker.redeem(nonce, execution)
    run = BrokeredRun(record, session_key, broker, environ=environ, **run_kwargs)
    run.dispatch_id = ri.nonce_doc_id(nonce)
    return run


def run_brokered_job(environ: Optional[Mapping[str, str]] = None, *, payload_session: Any = None,
                     result_store: Any = None, clock: Callable[[], float] = time.time, **redeem_kwargs) -> bool:
    """FD-7L 2a entry point of a Per-workload execution. Before the redeem no callback URL is known (it is in the
    signed dispatch record), so a failure there is logged (typed) and the execution fails; vending and the workflow
    see the failed execution."""
    environ = os.environ if environ is None else environ
    try:
        run = redeem_run(environ, **redeem_kwargs)
    except ri.RunnerIdentityError as e:
        logger.error(f"{e.code} ({e.stage}): {e.detail}; no callback URL is known before the redeem")
        return False
    record = run.record
    product_id, trace_id = record.get("product_id") or "", record.get("trace_id") or ""
    service = TerraformService()
    service.tofu_time_limits = TOFU_TIME_LIMITS_JOB
    try:
        if run.synchronous:   # FD-7L 5b: sync /deploy or force-unlock; the answer is the result document
            return _run_sync_job(service, run, environ, payload_session=payload_session,
                                 result_store=result_store, clock=clock)
        return _run_deploy(service, product_id, trace_id, record.get("project_id"), record.get("callback_url"),
                           record.get("branch") or "main", None, runner=run)
    finally:
        run.close()
        _remove_trace_workspace(service, trace_id)


def _failed(code: str, detail: str, product_id: Any, trace_id: Any, **extra) -> Dict[str, Any]:
    return dict({"status": "FAILED", "error_class": code, "error": f"{code}: {detail}", "product_id": product_id,
                 "trace_id": trace_id, "operator_required": True}, **extra)


def _sync_result(service, run: "BrokeredRun", environ: Mapping[str, str], *, payload_session: Any,
                 clock: Callable[[], float]) -> Dict[str, Any]:
    """The synchronous run's result: the staged payload is read and checked against the signed record BEFORE any
    credential is minted; then the deploy (with the request's remaining DEPLOY-SYNC-BUDGET and the server's
    per-command limits, as the in-process sync /deploy) or the force-unlock (service.force_unlock's own lock checks)."""
    record = run.record
    product_id, trace_id, mode = record.get("product_id"), record.get("trace_id"), record.get("mode")
    try:
        validate_path_component(product_id)
        validate_trace_id(trace_id)
        if not run.supported_dispatch():
            raise ri.RunnerIdentityError(runner_creds.RUNNER_MODE_UNSUPPORTED, f"dispatch mode {mode!r} is not run "
                                         "by this job", stage="runner-dispatch")
        options = rr.read_payload(record, environ, session=payload_session)
        if mode in ("deploy", "plan"):
            hcl_files = options.get("hcl_files")
            if mode == "plan" and not isinstance(hcl_files, dict):
                raise ri.RunnerIdentityError(rr.RUNNER_PAYLOAD_MISMATCH, "the plan payload names no file map",
                                             stage=rr.PAYLOAD_STAGE)
            if hcl_files is not None:
                if not isinstance(hcl_files, dict):
                    raise ri.RunnerIdentityError(rr.RUNNER_PAYLOAD_MISMATCH, "hcl_files is not a file map",
                                                 stage=rr.PAYLOAD_STAGE)
                validate_manifest_keys(hcl_files, reserved=TF_WORKSPACE_RESERVED)
            deadline = options.get("deadline_epoch")
            if not isinstance(deadline, (int, float)) or isinstance(deadline, bool) or deadline <= clock():
                what = "planned" if mode == "plan" else "deployed"
                raise ri.RunnerIdentityError(rr.RUNNER_SYNC_DEADLINE_PASSED, f"the request's {mode} budget had run out "
                                             f"before this execution started; nothing was {what}",
                                             stage="runner-dispatch", http_status=504)
        elif not isinstance(options.get("lock_id"), str) or not options.get("lock_id"):
            raise ri.RunnerIdentityError(rr.RUNNER_PAYLOAD_MISMATCH, "the unlock payload names no lock ID",
                                         stage=rr.PAYLOAD_STAGE)
    except ri.RunnerIdentityError as e:
        logger.error(f"{e.code} ({e.stage}): {e.detail}")
        return _failed(e.code, e.detail, product_id, trace_id)
    except UnsafePathError as e:
        logger.error(f"unsafe input in the synchronous run: {e.reason}")
        return _failed(rr.RUNNER_PAYLOAD_MISMATCH, f"unsafe path input ({e.reason})", product_id, trace_id)
    refusal = run.prepare(service)
    if refusal is not None:
        return refusal
    service.tofu_time_limits = TOFU_TIME_LIMITS_SERVICE   # the in-process sync /deploy's limits (its budget math)
    if mode == "deploy":
        budget = float(options["deadline_epoch"]) - clock()
        if budget <= 0:
            return _failed(rr.RUNNER_SYNC_DEADLINE_PASSED, "the request's deploy budget ran out before the deploy "
                           "started; nothing was deployed", product_id, trace_id)
        policy = DestroyPolicy(frozenset(options.get("approved_removals") or ())) \
            if options.get("refuse_destroy") is True else None
        res = service.deploy_workload(product_id=product_id, trace_id=trace_id, hcl_files=options.get("hcl_files"),
                                      target_project_id=run.project_id, branch=record.get("branch") or "main",
                                      iac_engine=options.get("iac_engine"), destroy_policy=policy,
                                      time_budget_s=budget)
        return run.typed_result(res)
    if mode == "plan":   # SAT-37: generate_plan unchanged; its saved plan goes with this container (not kept)
        try:
            res = service.generate_plan(product_id, trace_id, options["hcl_files"],
                                        iac_engine=options.get("iac_engine"))
        except IaCEngineDowngradeBlockedError as e:
            return {"status": "FAILED", "error_class": rr.IAC_ENGINE_DOWNGRADE_BLOCKED, "error": str(e),
                    "product_id": product_id, "trace_id": trace_id}
        return res if isinstance(res, dict) and res.get("status") == "PLAN_READY" else run.typed_result(res)
    res = service.force_unlock(product_id=product_id, lock_id=options["lock_id"], trace_id=trace_id,
                               iac_engine=options.get("iac_engine"))
    return run.typed_result(res) if isinstance(res, dict) and res.get("status") != "UNLOCKED" else res


def _run_sync_job(service, run: "BrokeredRun", environ: Mapping[str, str], *, payload_session: Any = None,
                  result_store: Any = None, clock: Callable[[], float] = time.time) -> bool:
    """FD-7L 5b: one synchronous run; its result goes to `runner_results/<dispatch_id>` (created once), which the
    server that dispatched it polls. No callback (the record has no callback URL). True only for a success result
    that was recorded."""
    record = run.record
    product_id, trace_id, mode = record.get("product_id"), record.get("trace_id"), record.get("mode")
    with AgentLifecycle("Terraform-Applier-Job", product_id or "", trace_id or "", mode="CLOUD RUN JOB SYNC") as agent:
        try:
            res = _sync_result(service, run, environ, payload_session=payload_session, clock=clock)
        except Exception as e:  # noqa: BLE001 - every outcome reaches the result document (fail loudly, typed)
            logger.error(f"synchronous {mode} run of '{product_id}' raised {type(e).__name__}: {e}")
            res = {"status": "FAILED", "error": f"{type(e).__name__}: {e}", "product_id": product_id,
                   "trace_id": trace_id}
        if not isinstance(res, dict):
            res = {"status": "FAILED", "error": f"the {mode} run returned no result", "product_id": product_id,
                   "trace_id": trace_id}
        ok = res.get("status") in ("SUCCESS", "UNLOCKED", "PLAN_READY")
        agent.set_summary(f"Synchronous {mode}: {res.get('status')} {res.get('error_class') or ''}".strip(),
                          status="SUCCESS" if ok else "FAILED")
        # SAT-37: vending signs the result's fingerprint BEFORE the document is written; the server accepts only a
        # document whose sha256 is that signed fingerprint. No signature -> no document (fail loudly).
        result_json, truncated = rr.result_text(res)
        try:
            run.sign_result(rr.result_fingerprint(result_json))
        except ri.RunnerIdentityError as e:
            logger.error(f"{rr.RUNNER_RESULT_NOT_RECORDED}: vending did not sign the {mode} result of '{product_id}' "
                         f"(trace {trace_id}, status {res.get('status')}, error class {res.get('error_class')}): "
                         f"{e.code} ({e.detail}); no result document is written, the caller's request ends in "
                         f"{rr.TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT} or {rr.RUNNER_RESULT_TIMEOUT}")
            return False
        try:
            store = result_store if result_store is not None else rr.ResultStore(service.db)
            if isinstance(store, rr.ResultStore) and store.db is None:
                raise RuntimeError("no Firestore client")
            store.write(run.dispatch_id, execution=record.get("execution"), product_id=product_id, trace_id=trace_id,
                        mode=mode, result_json=result_json, result_truncated=truncated,
                        finished_at=datetime.now(timezone.utc).isoformat())
        except Exception as e:  # noqa: BLE001 - the server's wait then ends typed (no accepted result)
            logger.error(f"{rr.RUNNER_RESULT_NOT_RECORDED}: the {mode} result of '{product_id}' (trace {trace_id}, "
                         f"status {res.get('status')}) could not be written ({type(e).__name__}); the caller's request "
                         f"ends in {rr.RUNNER_RESULT_MISMATCH} (another document holds the id), "
                         f"{rr.TF_APPLIER_EXECUTION_ENDED_WITHOUT_RESULT} or {rr.RUNNER_RESULT_TIMEOUT}")
            return False
    logger.info(f"synchronous {mode} of '{product_id}' [Trace: {trace_id}]: {res.get('status')} (result recorded)")
    return ok


def _remove_trace_workspace(service: TerraformService, trace_id: str) -> None:
    """FD-4AQ W3 (AQ-5): each job run is a fresh container, so this is only hygiene: the trace folder (app source,
    .terraform, plan files) is deleted when the run ends. Never fails the run."""
    import shutil
    try:
        path = service.workspace_trace_dir(trace_id)
    except Exception as e:  # noqa: BLE001 - an invalid trace ID was already reported FAILED in the callback scope
        logger.warning(f"WORKSPACE_CLEANUP_SKIPPED: {type(e).__name__}")
        return
    if os.path.isdir(path) and not os.path.islink(path):
        try:
            shutil.rmtree(path)
            logger.info(f"WORKSPACE_DELETED: {path} (job run ended)")
        except OSError as e:
            logger.warning(f"WORKSPACE_CLEANUP_FAILED: could not delete {path}: {type(e).__name__}")


def _run_deploy(service, product_id, trace_id, target_project_id, callback_url, branch, hcl_json,
                runner: "Optional[BrokeredRun]" = None) -> bool:
    """`runner` (FD-7L 2a): a redeemed Per-workload run; None (Shared installs) changes nothing below."""
    success = False
    with AgentLifecycle("Terraform-Applier-Job", product_id, trace_id, mode="CLOUD RUN JOB") as agent:
        with guaranteed_callback_scope(
            callback_url=callback_url,
            trace_id=trace_id,
            stage_name="terraform",
            product_id=product_id,
            firestore_db=service.db,
        ) as outcome:
            # FD-4G: env parsing + path validation run INSIDE the callback scope, so a bad ID or manifest key
            # reports FAILED to the workflow instead of leaving it waiting for a timeout.
            validate_path_component(product_id)
            validate_trace_id(trace_id)
            hcl_files = None
            if hcl_json:
                try:
                    hcl_files = json.loads(hcl_json)
                except Exception as e:
                    logger.warning(f"Failed to parse HCL_FILES_JSON: {e}")
            if hcl_files is not None:
                validate_manifest_keys(hcl_files, reserved=TF_WORKSPACE_RESERVED)

            if runner is not None:
                # FD-7L 2a: the target comes only from the verified records; nothing below reconciles it.
                refusal = runner.prepare(service)
                if refusal is not None:
                    outcome.update(refusal)
                    outcome["status"] = "FAILED"
                    agent.set_summary(f"Refused: {refusal['error_class']}", status="FAILED")
                    return False
                target_project_id = runner.project_id
            active_target_pid = target_project_id or product_id
            if runner is None and service.db and product_id:
                try:
                    w_doc = service.db.collection("workloads").document(product_id).get()
                    if w_doc.exists:
                        vended_pid = (w_doc.to_dict() or {}).get("project_id")
                        if vended_pid and vended_pid != active_target_pid:
                            logger.info(f"🛡️ Reconciled target project from Firestore workloads collection: '{active_target_pid}' -> '{vended_pid}'")
                            active_target_pid = vended_pid
                            target_project_id = vended_pid
                except Exception as fs_err:
                    logger.debug(f"Firestore project reconciliation notice: {fs_err}")

            if active_target_pid and runner is None:
                # FD4BD-Q3: the quota project is registered for this run's workspace (every tofu process of the run
                # bills the child in its own env) instead of being written into the process env, which every Google
                # client of this process (Firestore, the workflow callback) then inherited.
                service._register_workspace_billing(service.workspace_trace_dir(trace_id), active_target_pid)
                logger.info(f"Configured the quota project of this run's OpenTofu processes: {active_target_pid}")

            logger.info(f"🚀 tf-applier starting deployment for '{product_id}' [Trace: {trace_id}]")

            res = service.deploy_workload(
                product_id=product_id,
                trace_id=trace_id,
                hcl_files=hcl_files,
                target_project_id=target_project_id,
                branch=branch,
            )
            if runner is not None:
                res = runner.typed_result(res)   # FD-7L 2a: a broker failure during the run keeps its class
            res_status = res.get("status")
            if res_status != "SUCCESS":
                err_msg = res.get("error") or res.get("stderr") or res.get("stdout") or f"Deployment failed with status {res_status}"
                stubs = None
                if is_cloud_capacity_stockout(err_msg):
                    # RT14-01 (FD-4Q / lane 18 S3): READ-ONLY. The old branch REST-deleted every ERROR cluster of the
                    # project (any region) and ran a hardcoded `state rm`; now the dead stubs are only listed for an
                    # operator (docs/runbooks/stub-cleanup.md). Nothing is deleted. The child project is the run's own
                    # (never the product id as a guess).
                    logger.warning(f"Detected cloud capacity stockout on '{product_id}'. Listing errored stubs (read-only)...")
                    if target_project_id:
                        # FD-7M-a (SAT-22): the deploy's own region (the result's `region`; None = the platform region)
                        stubs = service.detect_errored_child_stubs(target_project_id, region=res.get("region"))
                    else:
                        stubs = {"connectors": [], "clusters": [], "errors": [
                            "STUB_DETECTION_REFUSED: the run has no target project"]}
                    n_stubs = len(stubs["connectors"]) + len(stubs["clusters"])
                    agent.set_summary(f"Paused: Cloud capacity deficit (GCE_STOCKOUT). {n_stubs} errored stub(s) "
                                      "listed for an operator; nothing was deleted.", status="FAILED")
                    delivered_error = f"Cloud capacity deficit (GCE_STOCKOUT): {err_msg[:200]}"
                else:
                    agent.set_summary(f"Deployment failed: {err_msg[:120]}", status="FAILED")
                    delivered_error = err_msg
                outcome["outputs"] = res
                outcome.update(res)
                # FD-4D-c-e: the error is set AFTER outcome.update(res), so the result's own "error" (even None) never
                # overwrites it (e.g. the GCE_STOCKOUT prefix). err_msg is the result's error when it has one.
                outcome["error"] = delivered_error
                outcome["status"] = "FAILED"
                if stubs is not None:   # RT14-01: the read-only listing reaches the operator with the failure
                    outcome["errored_stubs"] = stubs
                if isinstance(res.get("validation_report"), dict):
                    # TI-5a (S2-F F1 subset): the typed apply report of an intent workspace reaches the workflow
                    # callback as its own key (the error string stays as before for today's consumers)
                    outcome["validation_report"] = res["validation_report"]
                logger.error(f"❌ tf-applier failed: {err_msg}")
            else:
                agent.set_summary(
                    f"Deployed successfully. URL: {deploy_url_summary(res)}",
                    status="SUCCESS",
                )
                outcome["error"] = None
                outcome["outputs"] = res
                outcome.update(res)
                outcome["status"] = "SUCCESS"   # FD-4AI-c F1: after update(res), so the result's word never overrides it
                logger.info(f"✅ tf-applier completed successfully. URL: {res.get('service_url')}")
                success = True
    return success


if __name__ == "__main__":
    run_job()

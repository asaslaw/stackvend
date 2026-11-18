"""
FD-7L-F4 (vending side): the operative Terraform runner identity mode record. Register rows FD-7L-F4 and FD-7L-n
implementation (owner 11-01); design: SAT-33 red team F4 / Answer 3, plan rev 3 section 2.11 and OQ-35; hardened per
the F4 red-team review (11-01: H1, M1, L1; round 2: N1).

The install DECLARES its mode in Terraform (`tf_runner_identity` -> `STACKVEND_TF_RUNNER_IDENTITY`). On an install that
declares Shared (PLATFORM or unset), the OPERATIVE mode is `install_settings/runner_identity` in the guard database:
written and signed only here, as vending itself (the provenance signer, IAM signBlob: no new IAM), on the Control
Center's Settings request for a human ADMIN. Every reader resolves it through `shared.runner_identity.
runner_identity_mode()`: no record and no change entry = PLATFORM (never switched); after the first switch a record
must exist, verify and be the newest logged change. Switching (and the rollback drill) therefore needs no `apply.sh`;
only step A and step B stay platform applies.

Rules (`RunnerIdentityModeSetting.set`):
* the declaration is `PER_WORKLOAD` -> RUNNER_IDENTITY_MODE_RETIRED (409): the mode is final, the setting read-only;
* `PER_WORKLOAD` is refused until vending's Terraform-owned env shows step A (BrokerConfig.step_a_missing) ->
  RUNNER_IDENTITY_STEP_A_MISSING (409); step B's apply.sh gate is unchanged;
* `expected_version` must equal the stored record's version, 0 when there is none (RUNNER_MODE_CHANGED, 409); the
  mode already in force writes nothing;
* SAT-41 (pre-switch RT HIGH-2): a change is refused while any Terraform run may be in flight
  (RUNNER_MODE_SWITCH_BUSY, 409): an IN_FLIGHT terraform stage in `pipeline_executions` (one younger than the
  workflow's 87 300 s callback wait) or a running tf-applier execution, read as the backfill's drain reads them
  (runner_identity_backfill.runs_in_flight); a read error is busy;
* both modes are a SIGNED record (RT H1: Shared is never "no record" once switched, so deleting the record is a typed
  refusal, RUNNER_MODE_RECORD_MISSING, not a silent downgrade). One signed change entry `install_settings/
  runner_identity/changes/{change_id}` is created in the same transaction, which re-checks the record read before
  signing. Versions grow monotonically (above every logged one). Nothing here deletes anything;
* a stored record that is missing, stale (not the newest logged change, RT M1), tampered or unverifiable can be
  replaced by a new switch (that is how an operator repairs it); the change entry records the class it replaced;
* `changed_by` is the identity vending verified (the caller's Google ID token: the Control Center's service account);
  `operator_attested` is the administrator the Control Center says made the change (RT L1: CC-attested, the CC's
  `stackvend.runner_identity_mode_requested` log line is the second witness).

Re-signing (SAT-19 RT F1: Google rotates vending's Google-managed signing keys): `resign_if_stale` re-signs a verified,
current record (either mode) older than runner_broker.RESIGN_AFTER_SECONDS with the current key, content unchanged. It
runs on every Settings view, in the `/runner-identity/resign` sweep, and (at most hourly, best effort) on vending's own
mode reads.
"""
import json
import logging
import math
import os
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional

from shared import runner_identity as ri   # committed replica in this service's shared/ (byte-identical to root)

import destructive_guard as dg
import runner_broker as rb
import runner_identity_backfill as rib   # SAT-41: the in-flight check of the backfill's drain

logger = logging.getLogger("project-vending-runner-identity-mode")

RunnerIdentityError = ri.RunnerIdentityError

CHANGES_SHOWN = 10
CHANGE_KEYS = ("schema", "change_id", "from_mode", "from_version", "from_error", "to_mode", "to_version",
               "changed_by", "operator_attested", "changed_at")
# Record states that are a security event, not just "unusable" (shown as a Settings warning).
TAMPER_CLASSES = frozenset({"RUNNER_MODE_RECORD_MISSING", "RUNNER_MODE_RECORD_STALE", "RUNNER_MODE_TAMPERED",
                            "RUNNER_RECORD_UNSIGNED", "RUNNER_MODE_RECORD_INVALID", "RUNNER_MODE_LOG_CORRUPT"})
INT64_MAX = 2 ** 63 - 1   # the largest version a Firestore integer field holds


def _rank(value: Any) -> Optional[float]:
    """RT round 2, N1: a change entry's `to_version` as the readers' Firestore query ranks it (numeric, >= 1, int and
    double together; booleans, strings, maps, null, NaN never rank). None = not ranked."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if value >= 1 else None   # NaN >= 1 is False


def _err(code: str, detail: str, status: int = 409) -> RunnerIdentityError:
    return RunnerIdentityError(code, detail, stage="runner-identity-mode", http_status=status)


def _stored_version(doc: Any) -> int:
    v = doc.get("version") if isinstance(doc, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


class RunnerIdentityModeSetting:
    def __init__(self, deps: "rb.RunnerDeps", *, guard_db: Any, environ: Optional[Dict[str, str]] = None):
        """`guard_db`: the NAMED guard database client (None when STACKVEND_GUARD_FIRESTORE_DATABASE is unset: nothing
        is ever written to the default database)."""
        self.d = deps
        self.guard_db = guard_db
        self.environ = environ

    # ------------------------------------------------------------------------------------------ reads
    def _env(self):
        return os.environ if self.environ is None else self.environ

    def _ref(self):
        if self.guard_db is None:
            raise _err("RUNNER_STORE_UNAVAILABLE", f"{ri.GUARD_DB_ENV} is not set: the mode record has no store", 503)
        try:
            return self.guard_db.collection(ri.INSTALL_SETTINGS_COLLECTION).document(ri.MODE_RECORD_ID)
        except Exception as e:  # noqa: BLE001 - a configured guard database that cannot be opened
            raise _err("RUNNER_STORE_UNAVAILABLE", f"guard database unavailable ({type(e).__name__})", 503) from None

    def _raw(self) -> Optional[Dict[str, Any]]:
        ref = self._ref()
        try:
            snap = ref.get()
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"{ri.mode_record_doc_path()} unreadable ({type(e).__name__})",
                       503) from None
        if getattr(snap, "exists", False) is not True:
            return None
        data = snap.to_dict()
        return data if isinstance(data, dict) else {}

    def _all_changes(self) -> List[Dict[str, Any]]:
        """Every RANKED change entry (raw, numeric `to_version` >= 1, as the readers rank them), newest first, each
        with its document path under `_path`. Unranked entries (a forged non-numeric `to_version`) are kept in
        `self.unranked` (their paths): readers ignore them too. The log is small (one entry per administrator switch)."""
        ref = self._ref()
        try:
            snaps = list(ref.collection(ri.MODE_CHANGES_COLLECTION).stream())
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"mode change log unreadable ({type(e).__name__})", 503) from None
        rows, self.unranked = [], []
        for snap in snaps:
            data = snap.to_dict()
            path = ri.mode_change_doc_path(str(getattr(snap, "id", "")))
            if not isinstance(data, dict) or _rank(data.get("to_version")) is None:
                self.unranked.append(path)
                continue
            rows.append(dict(data, _path=path))
        rows.sort(key=lambda r: (_rank(r.get("to_version")), str(r.get("changed_at") or "")), reverse=True)
        return rows

    @staticmethod
    def _next_version(stored: int, changes: List[Dict[str, Any]]) -> Optional[int]:
        """The version that outranks the record and every ranked entry; None when no Firestore integer can (a forged
        `to_version` of 1e300 or infinity): RUNNER_MODE_LOG_CORRUPT."""
        top = _rank(changes[0].get("to_version")) if changes else None
        if top is not None and not math.isfinite(top):
            return None
        nxt = max(stored, int(math.floor(top)) if top is not None else 0) + 1
        return nxt if nxt <= INT64_MAX else None

    def _verified(self, raw: Optional[Dict[str, Any]], changes: List[Dict[str, Any]], broker: str) -> Dict[str, Any]:
        """{"record": the verified CURRENT record or None, "error": typed class or None}.
        * no record: no error while the log is empty; else RUNNER_MODE_RECORD_MISSING (RT H1);
        * the newest change entry must carry vending's signature (else RUNNER_MODE_TAMPERED) and name this record's
          version and change id (else RUNNER_MODE_RECORD_STALE, RT M1);
        * certificates unavailable -> raised (503): nothing can be decided."""
        newest = changes[0] if changes else None
        if self._next_version(_stored_version(raw), changes) is None:
            path = newest.get("_path") if newest else ri.mode_record_doc_path()
            return {"record": None, "error": "RUNNER_MODE_LOG_CORRUPT",
                    "detail": f"{path} has a version no switch can outrank; a project owner removes that document "
                              "in the console"}
        newest = {k: v for k, v in newest.items() if k != "_path"} if newest is not None else None
        try:
            if newest is not None:
                try:
                    ri.verify_record(ri.mode_change_doc_path(str(newest.get("change_id"))), newest,
                                     expected_signer=broker, certs=self.d.certs)
                except RunnerIdentityError as e:
                    if e.code == "RUNNER_RECORD_UNVERIFIABLE":
                        raise
                    raise _err("RUNNER_MODE_TAMPERED", f"the newest mode change entry does not verify ({e.code})",
                               503) from None
            if raw is None:
                if newest is not None:
                    raise _err("RUNNER_MODE_RECORD_MISSING", f"{ri.mode_record_doc_path()} is missing after a switch",
                               503)
                return {"record": None, "error": None}
            rec = ri.verify_record(ri.mode_record_doc_path(), raw, expected_signer=broker, certs=self.d.certs)
            rec = ri.check_mode_record(rec)
            ri.check_mode_record_current(rec, {k: v for k, v in (newest or {}).items() if k != "signature"}
                                         if newest is not None else None)
            return {"record": rec, "error": None}
        except RunnerIdentityError as e:
            if e.code == "RUNNER_RECORD_UNVERIFIABLE":
                raise _err(e.code, e.detail, 503) from None   # certificates unavailable: nothing can be decided
            return {"record": None, "error": e.code}

    @staticmethod
    def _public_change(row: Dict[str, Any]) -> Dict[str, Any]:
        return {k: row.get(k) for k in CHANGE_KEYS}

    def view(self) -> Dict[str, Any]:
        """The Settings card's mode block. Never raises for a bad record: it is shown (typed) so it can be repaired;
        a tamper class is also listed in `warnings`."""
        env = self._env()
        out: Dict[str, Any] = {"declared_mode": None, "mode": None, "mode_source": None, "mode_error": None,
                               "editable": False, "record": None, "record_error": None, "record_version": 0,
                               "record_resign": None, "last_mode_change": None, "mode_changes": [],
                               "step_a_missing": None, "warnings": [], "record_error_detail": None,
                               "unranked_change_entries": []}
        try:
            declared = ri.declared_mode(env)
        except RunnerIdentityError as e:
            out["mode_error"] = f"{e.code}: {e.detail}"
            return out
        out["declared_mode"] = declared
        out["step_a_missing"] = self.d.config.step_a_missing()
        if declared == ri.MODE_PER_WORKLOAD:
            out.update(mode=declared, mode_source=f"install declaration {ri.MODE_ENV} (final; not editable)")
            return out
        try:
            out["mode"] = ri.runner_identity_mode(env, guard_db=self.guard_db, certs=self.d.certs)
        except RunnerIdentityError as e:
            out["mode_error"] = f"{e.code}: {e.detail}"
        if self.guard_db is None:
            out["mode_source"] = f"default (no guard database: {ri.GUARD_DB_ENV} is not set)"
            return out
        out["editable"] = True
        try:
            out["record_resign"] = self.resign_if_stale()
        except RunnerIdentityError as e:
            out["record_resign"] = f"FAILED ({e.code})"
        try:
            raw = self._raw()
            changes = self._all_changes()
            ver = self._verified(raw, changes, self.d.config.broker_email(self.d.runtime_email()))
            out["record_version"] = _stored_version(raw)
            out["record"], out["record_error"] = ver["record"], ver["error"]
            out["record_error_detail"] = ver.get("detail")
            out["unranked_change_entries"] = list(self.unranked)
            out["mode_changes"] = [self._public_change(c) for c in changes[:CHANGES_SHOWN]]
        except RunnerIdentityError as e:
            out["record_error"] = e.code
        rec = out["record"]
        out["mode_source"] = ("Control Center Settings (signed by vending)" if rec is not None
                              else "default (never switched)" if out["record_error"] is None
                              else "Settings record unusable")
        if out["mode_changes"]:
            last = out["mode_changes"][0]
            out["last_mode_change"] = {"by": last.get("operator_attested"), "verified_caller": last.get("changed_by"),
                                       "at": last.get("changed_at"), "mode": last.get("to_mode"),
                                       "version": last.get("to_version")}
        if out["record_error"] == "RUNNER_MODE_LOG_CORRUPT":
            out["warnings"].append({"code": "RUNNER_MODE_LOG_CORRUPT", "severity": "error",
                                    "message": f"The runner identity mode change log was changed outside Settings: "
                                               f"{out.get('record_error_detail')}. Every service refuses to run; "
                                               "Settings cannot repair this."})
        elif out["record_error"] in TAMPER_CLASSES:
            out["warnings"].append({"code": out["record_error"], "severity": "error",
                                    "message": "The runner identity mode record in the guard database was changed "
                                               f"outside Settings ({out['record_error']}); every service refuses to "
                                               "run until an administrator switches the mode again here."})
        if out.get("unranked_change_entries") and out["record_error"] != "RUNNER_MODE_LOG_CORRUPT":
            out["warnings"].append({"code": "RUNNER_MODE_LOG_CORRUPT", "severity": "warning",
                                    "message": "Change entries with a non-numeric version were written outside "
                                               "Settings (the services ignore them; a project owner removes them in "
                                               f"the console): {', '.join(out['unranked_change_entries'])}"})
            logger.warning(json.dumps({"event": "stackvend.runner_identity_mode_tampered",
                                       "class": out["record_error"]}, sort_keys=True))
        return out

    # ------------------------------------------------------------------------------------------ re-sign
    def resign_if_stale(self) -> Optional[str]:
        """None (no record), "FRESH" or "RESIGNED". A verified, current record (either mode) whose signature is older
        than rb.RESIGN_AFTER_SECONDS is re-signed with the broker's current key (content unchanged, compare-and-set);
        a record that is missing after a switch, stale, tampered or unverifiable is never re-signed (its class is
        raised: the operator switches the mode again)."""
        if self.guard_db is None:
            return None
        ref = self._ref()
        broker = self.d.config.broker_email(self.d.runtime_email())
        raw = self._raw()
        ver = self._verified(raw, self._all_changes(), broker)
        if ver["error"] is not None:
            raise _err(ver["error"], ver.get("detail") or f"{ri.mode_record_doc_path()} is not usable; it is not "
                       "re-signed", 409)
        if raw is None:
            return None
        signed_at = dg._parse_ts(raw.get("signed_at"))
        if signed_at is not None and self.d.clock() - signed_at < timedelta(seconds=rb.RESIGN_AFTER_SECONDS):
            return "FRESH"
        body = {k: v for k, v in ver["record"].items() if k not in ("signed_by", "signed_at")}
        fresh = ri.sign_record(ri.mode_record_doc_path(), body, signer_email=broker,
                               signed_at=rb._now_iso(self.d.clock), sign_blob=self.d.signer_factory(broker))
        outcome = {"ok": False}

        def _body(txn):
            snap = ref.get(transaction=txn)
            current = snap.to_dict() if getattr(snap, "exists", False) is True else None
            if current != raw:
                return
            txn.set(ref, fresh)
            outcome["ok"] = True

        try:
            self._run_in_transaction(_body)
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"mode record not re-signed ({type(e).__name__})", 503) from None
        if not outcome["ok"]:
            return "FRESH"   # changed meanwhile: the writer signed it just now
        logger.info(f"runner identity mode record re-signed (previous signature from {raw.get('signed_at')})")
        return "RESIGNED"

    # ------------------------------------------------------------------------------------------ write
    def set(self, caller: str, *, mode: Any, expected_version: Any, operator_email: Any) -> Dict[str, Any]:
        env = self._env()
        if mode not in ri.MODES:
            raise _err("RUNNER_IDENTITY_MODE_INVALID", f"mode {mode!r}; expected one of {', '.join(ri.MODES)}", 422)
        if not isinstance(expected_version, int) or isinstance(expected_version, bool) or expected_version < 0:
            raise _err("RUNNER_MODE_CHANGE_INVALID", "expected_version must be the stored version (an integer)", 422)
        operator = operator_email.strip().lower() if isinstance(operator_email, str) else ""
        if not operator:
            raise _err("RUNNER_MODE_CHANGE_INVALID", "operator_email (the administrator the Control Center verified) "
                       "is required", 422)
        verified_caller = (caller or "").strip().lower()
        if not verified_caller:
            raise _err("RUNNER_MODE_CHANGE_INVALID", "no verified caller identity", 401)
        declared = ri.declared_mode(env)
        if declared == ri.MODE_PER_WORKLOAD:
            raise _err("RUNNER_IDENTITY_MODE_RETIRED", f"the install declares {ri.MODE_PER_WORKLOAD} "
                       f"({ri.MODE_ENV}); the runner identity mode is final and cannot be changed in Settings")
        if mode == ri.MODE_PER_WORKLOAD:
            missing = self.d.config.step_a_missing()
            if missing:
                raise _err("RUNNER_IDENTITY_STEP_A_MISSING", "Per workload needs the platform's step A (the runner "
                           f"service accounts and vending's runner settings); missing: {', '.join(missing)}")
        ref = self._ref()
        broker = self.d.config.broker_email(self.d.runtime_email())
        raw = self._raw()
        changes = self._all_changes()
        before = self._verified(raw, changes, broker)
        if before["error"] == "RUNNER_MODE_LOG_CORRUPT":
            raise _err("RUNNER_MODE_LOG_CORRUPT", before["detail"])
        stored = _stored_version(raw)
        if expected_version != stored:
            raise _err("RUNNER_MODE_CHANGED", f"the stored version is {stored}, not {expected_version}; reload and "
                       "retry (nothing was changed)")
        never_switched = raw is None and before["error"] is None
        if before["record"] is not None:
            effective_before = before["record"]["mode"]
        else:
            effective_before = ri.MODE_PLATFORM if never_switched else None
        if effective_before == mode and before["error"] is None:
            return {"changed": False, "mode": mode, "version": stored}   # in force (never switched = PLATFORM)
        # SAT-41 (pre-switch RT HIGH-2): a run started under one mode and continued under the other either hangs the
        # workflow or fails half-way, so the switch waits until no Terraform run is in flight anywhere (the backfill's
        # drain check, install-wide). Nothing is written.
        busy = rib.runs_in_flight(self.d, stale_after=rib.WORKFLOW_DEPLOY_WAIT)
        if busy is not None:
            raise _err("RUNNER_MODE_SWITCH_BUSY", f"a Terraform run may be in flight ({busy}). Wait until no pipeline "
                       "is deploying and no tf-applier execution is running, then switch again (nothing was "
                       "changed)")
        version = self._next_version(stored, changes)   # not None: LOG_CORRUPT refused above
        now = rb._now_iso(self.d.clock)
        change_id = uuid.uuid4().hex
        sign = self.d.signer_factory(broker)
        record = ri.new_mode_record(mode=mode, version=version, previous_mode=effective_before,
                                    set_by=verified_caller, set_at=now, change_id=change_id)
        signed = ri.sign_record(ri.mode_record_doc_path(), record, signer_email=broker, signed_at=now, sign_blob=sign)
        change = {"schema": ri.MODE_CHANGE_SCHEMA, "change_id": change_id, "from_mode": effective_before,
                  "from_version": stored, "from_error": before["error"], "to_mode": mode, "to_version": version,
                  "changed_by": verified_caller, "operator_attested": operator, "changed_at": now}
        signed_change = ri.sign_record(ri.mode_change_doc_path(change_id), change, signer_email=broker,
                                       signed_at=now, sign_blob=sign)
        change_ref = ref.collection(ri.MODE_CHANGES_COLLECTION).document(change_id)
        outcome = {"ok": False}

        def _body(txn):
            snap = ref.get(transaction=txn)
            current = snap.to_dict() if getattr(snap, "exists", False) is True else None
            if current != raw:
                return
            txn.set(ref, signed)
            txn.create(change_ref, signed_change)
            outcome["ok"] = True

        try:
            self._run_in_transaction(_body)
        except Exception as e:  # noqa: BLE001
            raise _err("RUNNER_STORE_UNAVAILABLE", f"mode record not written ({type(e).__name__})", 503) from None
        if not outcome["ok"]:
            raise _err("RUNNER_MODE_CHANGED", "the mode record changed while this change was prepared; reload and "
                       "retry (nothing was changed)")
        ri.clear_mode_cache()
        logger.warning(json.dumps({"event": "stackvend.runner_identity_mode_changed", "from": effective_before,
                                   "from_error": before["error"], "to": mode, "version": version,
                                   "changed_by": verified_caller, "operator_attested": operator,
                                   "change_id": change_id}, sort_keys=True))
        return {"changed": True, "mode": mode, "version": version, "record_version": version,
                "change_id": change_id, "changed_by": verified_caller, "operator_attested": operator,
                "set_at": now, "previous_mode": effective_before}

    def _run_in_transaction(self, body) -> None:
        from google.cloud import firestore as gcf
        txn = self.guard_db.transaction()
        gcf.transactional(body)(txn)

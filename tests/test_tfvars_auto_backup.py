"""TFVARS-AUTO-BACKUP (owner 11-16): infra/platform/<project_id>.tfvars is backed up next to the platform state and
restored from there (scripts/common/tfvars_backup.sh).

  * scripts/bootstrap.sh copies it to gs://castor-tfstate-<id>/platform/<id>.tfvars once, at the end of a successful
    install; a failure is the typed warning BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN (exit 0) plus a Next Steps item.
  * scripts/apply.sh refreshes that copy after every successful `apply` (never for plan, never after a failed or
    refused apply); a copy that differs is kept as <id>.tfvars.prev-<UTC> first; an unreadable copy is never
    overwritten; a failure is APPLY_TFVARS_BACKUP_NOT_WRITTEN (exit 0).
  * scripts/apply.sh with PROJECT_ID set and the local file missing offers the restore on a terminal ([y/N]), restores
    with mode 600 and stops for review (APPLY_TFVARS_RESTORED); N / no terminal -> APPLY_TFVARS_MISSING; no backup ->
    APPLY_TFVARS_MISSING_NO_BACKUP; an existing local file is never overwritten.

Runs the real scripts under lane 5's hermetic harness (stubbed gcloud / curl / tofu; only `tofu console` is the real
engine). A fake object store in a temp dir stands in for the bucket: the gcloud stub's `storage cp` and the curl stub's
JSON API metadata GET read and write it (generation counter + base64 MD5, as the JSON API reports them). Nothing here
can reach GCP.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import base64
import hashlib
import json
import os
import re
import stat
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)
import test_installer_messages as IM  # noqa: E402  (module import only)

PROJ = L5.PROJ
OBJ = f"castor-tfstate-{PROJ}/platform/{PROJ}.tfvars"
URI = f"gs://{OBJ}"
REL = f"infra/platform/{PROJ}.tfvars"

# gcloud wrapper: `storage cp` against the fake object store ($STUB_GCS/<bucket>/<object>, generation in <object>.gen);
# every other call goes to the wrapped stub. STUB_CP_FAIL=<substring>: a cp whose argv contains it fails.
# STUB_CP_CREATE_DEST=<path>: the download also creates that local file (a file that appears meanwhile).
GCLOUD_GCS_WRAPPER = r'''#!/bin/bash
if [ "$1" = "storage" ] && [ "$2" = "cp" ]; then
  echo "gcloud $*" >> "$STUB_LOG"
  if [ -n "${STUB_CP_FAIL:-}" ] && [[ "$*" == *"${STUB_CP_FAIL}"* ]]; then
    echo "Copying..." >&2; echo "ERROR: (gcloud.storage.cp) stub refused this copy" >&2; exit 1
  fi
  src="$3"; dst="$4"; gen=""; sgen=""
  for a in "$@"; do case "$a" in --if-generation-match=*) gen="${a#--if-generation-match=}" ;; esac; done
  case "$src" in gs://*"#"*) sgen="${src##*#}"; src="${src%#*}" ;; esac
  case "$src" in gs://*) s="$STUB_GCS/${src#gs://}" ;; *) s="$src" ;; esac
  case "$dst" in gs://*) d="$STUB_GCS/${dst#gs://}" ;; *) d="$dst" ;; esac
  [ -f "$s" ] || { echo "ERROR: (gcloud.storage.cp) not found: $src" >&2; exit 1; }
  if [ -n "$sgen" ]; then
    cur=1; [ -f "$s.gen" ] && cur="$(cat "$s.gen")"
    [ "$sgen" = "$cur" ] || { echo "ERROR: (gcloud.storage.cp) The following URLs matched no objects: $src#$sgen" >&2; exit 1; }
  fi
  if [ -n "${STUB_CP_HANG:-}" ]; then
    : > "$STUB_CP_HANG"; exec python3 -c 'import time; time.sleep(60)'
  fi
  if [ -n "$gen" ]; then
    cur=0; [ -f "$d.gen" ] && cur="$(cat "$d.gen")"
    [ -e "$d" ] || cur=0
    [ "$gen" = "$cur" ] || { echo "ERROR: (gcloud.storage.cp) HTTPError 412: precondition failed" >&2; exit 1; }
  fi
  mkdir -p "$(dirname "$d")"
  if [ -n "${STUB_CP_CORRUPT:-}" ]; then printf 'corrupted\n' > "$d"; else cp "$s" "$d"; fi
  case "$dst" in gs://*)
    n=0; [ -f "$d.gen" ] && n="$(cat "$d.gen")"; echo $((n + 1)) > "$d.gen" ;;
  esac
  if [ -n "${STUB_CP_CREATE_DEST:-}" ]; then printf 'appeared meanwhile\n' > "$STUB_CP_CREATE_DEST"; fi
  if [ -n "${STUB_CP_CREATE_DIR:-}" ]; then mkdir -p "$STUB_CP_CREATE_DIR"; fi
  exit 0
fi
exec "$(dirname "$0")/gcloud.next" "$@"
'''

# curl wrapper: answers the JSON API metadata GET of a platform/*.tfvars object from the fake store; every other call
# goes to the wrapped stub. STUB_META_CODE forces an HTTP status (e.g. 403); STUB_META_MODE=fail -> curl rc 7.
CURL_META_WRAPPER = r'''#!/bin/bash
case "$*" in *storage/v1/b/*/o/platform%2F*.tfvars*)
  m_out=""; m_prev=""; m_url=""
  for m_a in "$@"; do [ "$m_prev" = "-o" ] && m_out="$m_a"; m_prev="$m_a"; case "$m_a" in https://*) m_url="$m_a" ;; esac; done
  m_stdin="$(cat)"
  echo "curl $*" >> "$STUB_LOG.meta"
  case "$m_stdin" in *'header = "Authorization: Bearer '*) echo "auth-on-stdin" >> "$STUB_LOG.meta" ;; esac
  [ "${STUB_META_MODE:-answer}" = "fail" ] && exit 7
  if [ -n "${STUB_META_CODE:-}" ]; then
    echo '{"error": {"code": '"$STUB_META_CODE"', "message": "stub says no"}}' > "$m_out"; printf '%s' "$STUB_META_CODE"; exit 0
  fi
  exec python3 "$(dirname "$0")/meta.py" "$m_url" "$m_out"
esac
exec "$(dirname "$0")/curl.next" "$@"
'''

META_PY = r'''import base64, hashlib, json, os, sys, urllib.parse
url, out = sys.argv[1], sys.argv[2]
path = urllib.parse.urlparse(url).path            # /storage/v1/b/<bucket>/o/<encoded object>
bucket, obj = path.split("/b/", 1)[1].split("/o/", 1)
f = os.path.join(os.environ["STUB_GCS"], bucket, urllib.parse.unquote(obj))
if not os.path.isfile(f):
    with open(out, "w") as o:
        json.dump({"error": {"code": 404, "message": "No such object"}}, o)
    sys.stdout.write("404")
    sys.exit(0)
data = open(f, "rb").read()
gen = open(f + ".gen").read().strip() if os.path.exists(f + ".gen") else "1"
with open(out, "w") as o:
    meta = {"generation": gen, "md5Hash": base64.b64encode(hashlib.md5(data).digest()).decode(),
            "size": str(len(data)), "updated": "2026-11-16T10:00:00.000Z"}
    if os.environ.get("STUB_META_NO_MD5"):
        del meta["md5Hash"]   # a composite object has no md5Hash
    if os.environ.get("STUB_META_SIZE"):
        meta["size"] = os.environ["STUB_META_SIZE"]
    json.dump(meta, o)
sys.stdout.write("200")
'''

TOFU_APPLY_WRAPPER = r'''#!/bin/bash
if [ "$1" = "apply" ] && [ -n "${STUB_TOFU_APPLY_RC:-}" ]; then echo "tofu $*" >> "$STUB_LOG"; exit "$STUB_TOFU_APPLY_RC"; fi
exec "$(dirname "$0")/tofu.next" "$@"
'''

# Do-No-Harm baseline: the same scripts with the two entry points as no-ops (what apply.sh did before the change).
NOOP_BACKUP_LIB = '''# shellcheck shell=bash
sv_tfvars_backup_uri() { printf 'gs://%s/platform/%s.tfvars' "$1" "${PROJECT_ID}"; }
sv_tfvars_backup_write() { return 0; }
sv_tfvars_restore_offer() { return 0; }
'''


def _md5(data):
    return base64.b64encode(hashlib.md5(data).digest()).decode()


class _GcsMixin:
    """Installs the fake object store wrappers on top of whatever gcloud/curl/tofu stubs the harness has."""

    def _wrap(self, name, body):
        p = os.path.join(self.stub, name)
        os.rename(p, p + ".next")
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)

    def install_gcs(self):
        self.gcs = os.path.join(self.tmp, "gcs")
        os.makedirs(os.path.join(self.gcs, f"castor-tfstate-{PROJ}", "platform"))
        self._wrap("gcloud", GCLOUD_GCS_WRAPPER)
        self._wrap("curl", CURL_META_WRAPPER)
        self._wrap("tofu", TOFU_APPLY_WRAPPER)
        with open(os.path.join(self.stub, "meta.py"), "w") as f:
            f.write(META_PY)

    def remote(self, rel=OBJ):
        return os.path.join(self.gcs, rel)

    def put_remote(self, data, gen=7, rel=OBJ):
        p = self.remote(rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        with open(p + ".gen", "w") as f:
            f.write(str(gen))

    def remote_bytes(self, rel=OBJ):
        with open(self.remote(rel), "rb") as f:
            return f.read()

    def prev_objects(self):
        d = os.path.dirname(self.remote())
        return sorted(n for n in os.listdir(d) if n.startswith(f"{PROJ}.tfvars.prev-") and not n.endswith(".gen"))

    def cp_calls(self):
        return [c for c in self.calls() if c.startswith("gcloud storage cp")]

    def meta_calls(self):
        p = self.log + ".meta"
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return f.read().splitlines()

    def download_dirs(self):
        """The temp dirs the restore downloaded into (the local destination of each gs:// -> local copy). mktemp -d
        does not honour the harness TMPDIR on every macOS, so the dirs are taken from the calls themselves."""
        dirs = []
        for c in self.cp_calls():
            args = c.split(" ")
            if len(args) > 4 and args[3].startswith("gs://") and not args[4].startswith("gs://"):
                dirs.append(os.path.dirname(args[4]))
        return dirs

    def gcs_env(self, **env):
        env.setdefault("STUB_GCS", self.gcs)
        return env


# ------------------------------------------------------------------------------------------------------------------
# bootstrap.sh
# ------------------------------------------------------------------------------------------------------------------
@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestBootstrapBackup(_GcsMixin, IM._Boot):
    def setUp(self):
        super().setUp()
        self.install_gcs()
        self.local = os.path.join(self.platform, f"{PROJ}.tfvars")

    def _boot(self, **env):
        return self.boot("n", **self.gcs_env(**env))

    def test_fresh_install_backs_up_once_at_the_end(self):
        rc, text = self._boot()
        self.assertEqual(rc, 0, text)
        with open(self.local, "rb") as f:
            local = f.read()
        self.assertEqual(self.remote_bytes(), local)
        cps = self.cp_calls()
        self.assertEqual(cps, [f"gcloud storage cp {self.local} {URI} --if-generation-match=0"])
        # Two GETs (the start-of-install note check and the backup), each with its token on stdin.
        self.assertEqual(len([c for c in self.meta_calls() if c.startswith("curl ")]), 2, self.meta_calls())
        self.assertEqual(self.meta_calls().count("auth-on-stdin"), 2, self.meta_calls())
        self.assertNotIn("A backup of this install's vars file exists", text)   # 404 at the start: no note
        # After the platform apply, before Next Steps.
        calls = self.calls()
        self.assertLess([i for i, c in enumerate(calls) if c.startswith("tofu apply")][-1],
                        calls.index(cps[0]))
        self.assertIn(f"[OK]\x1b[0m Backed up {self.local} to {URI}.", text)
        # The step line (stdout) comes before Next Steps; the helper's own lines go to stderr (text = out + err).
        self.assertLess(text.index(f"Backing up {self.local} to"), text.index("Next Steps:"))
        tail = text[text.index("Next Steps:"):]
        self.assertNotIn("Back up infra/platform", tail)
        self.assertNotIn("gcloud storage cp", tail)
        self.assertNotIn("NOT_WRITTEN", text)
        self.assertEqual(self.prev_objects(), [])

    def test_backup_failure_is_a_typed_warning_and_exit_0(self):
        rc, text = self._boot(STUB_CP_FAIL=URI)
        self.assertEqual(rc, 0, text)
        self.assertIn("BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN: the upload to " + URI + " failed (gcloud rc=1: ERROR: "
                      "(gcloud.storage.cp) stub refused this copy)", text)
        self.assertIn("The install itself succeeded", text)
        self.assertNotIn("Backed up", text)
        self.assertFalse(os.path.exists(self.remote()))
        tail = text[text.index("Next Steps:"):]
        self.assertIn(f"Back up infra/platform/{PROJ}.tfvars (the automatic backup failed: "
                      "BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN above):", tail)
        self.assertIn(f"   PROJECT_ID={PROJ} bash scripts/apply.sh apply (a run with no changes only refreshes the backup)",
                      tail)

    def test_unreadable_copy_is_never_overwritten(self):
        self.put_remote(b"hand edited elsewhere\n")
        rc, text = self._boot(STUB_META_CODE=403)
        self.assertEqual(rc, 0, text)
        self.assertIn(f"BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN: could not read the existing copy {URI} (HTTP 403: stub says "
                      "no), so it was not overwritten", text)
        self.assertEqual(self.cp_calls(), [])
        self.assertEqual(self.remote_bytes(), b"hand edited elsewhere\n")

    def test_curl_failure_is_a_typed_warning(self):
        rc, text = self._boot(STUB_META_MODE="fail")
        self.assertEqual(rc, 0, text)
        self.assertIn("BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN: could not read the existing copy", text)
        self.assertIn("(HTTP none (curl rc=7))", text)
        self.assertEqual(self.cp_calls(), [])

    def test_differing_copy_is_kept_as_prev_before_overwrite(self):
        self.put_remote(b"older copy with hand edits\n", gen=7)
        rc, text = self._boot()
        self.assertEqual(rc, 0, text)
        prevs = self.prev_objects()
        self.assertEqual(len(prevs), 1, prevs)
        self.assertRegex(prevs[0], r"^" + re.escape(PROJ) + r"\.tfvars\.prev-\d{8}T\d{6}Z$")
        self.assertEqual(self.remote_bytes(f"castor-tfstate-{PROJ}/platform/{prevs[0]}"), b"older copy with hand edits\n")
        with open(self.local, "rb") as f:
            self.assertEqual(self.remote_bytes(), f.read())
        cps = self.cp_calls()
        self.assertEqual(len(cps), 2, cps)
        self.assertEqual(cps[0], f"gcloud storage cp {URI}#7 {URI}.{prevs[0].split('.tfvars.', 1)[1]} --if-generation-match=0")
        self.assertTrue(cps[1].endswith(f" {URI} --if-generation-match=7"), cps[1])
        self.assertIn(f"The earlier copy {URI} differed from {self.local}; it is kept as {URI}.prev-", text)
        self.assertIn("Backed up", text)
        # Red-team fix 5: the start of the run noted the backup (a note only: the install went on).
        self.assertIn(f"A backup of this install's vars file exists: {URI} (27 bytes, updated 2026-11-16T10:00:00.000Z),",
                      text)
        self.assertIn(f"restore it instead: PROJECT_ID={PROJ} bash scripts/apply.sh plan", text)

    def test_failed_install_writes_no_backup(self):
        # Wrong typed project id: the gated apply refuses, bootstrap stops before the end.
        answers = [PROJ, "", "", "", "", "", "y", "", "", "octo-org", "", "", "", "", "", L5.OTHER, "n"]
        rc, out, err = self.run_script("bootstrap.sh", [], tty_input="\n".join(answers),
                                       **self.gcs_env(STUB_PLAN_JSON=self.plan_json))
        self.assertNotEqual(rc, 0, out + err)
        self.assertEqual(self.cp_calls(), [])
        self.assertEqual(len([c for c in self.meta_calls() if c.startswith("curl ")]), 1)   # the note check only
        self.assertFalse(os.path.exists(self.remote()))

    def test_failed_platform_apply_writes_no_backup(self):
        self.put_remote(b"kept as it is\n")
        rc, text = self._boot(STUB_TOFU_APPLY_RC=1)
        self.assertNotEqual(rc, 0, text)
        self.assertEqual(self.cp_calls(), [])
        self.assertEqual(len([c for c in self.meta_calls() if c.startswith("curl ")]), 1)   # the note check only
        self.assertEqual(self.remote_bytes(), b"kept as it is\n")

    def test_note_never_asks_and_needs_no_terminal_answer(self):
        """The note is output only: the same answers as a fresh install complete it, nothing extra is read."""
        self.put_remote(b"x\n", gen=3)
        rc, text = self._boot(STUB_META_CODE=403)
        self.assertEqual(rc, 0, text)
        self.assertNotIn("A backup of this install's vars file exists", text)   # unreadable: no note
        self.assertEqual(self.cp_calls(), [])


# ------------------------------------------------------------------------------------------------------------------
# apply.sh: refresh after apply
# ------------------------------------------------------------------------------------------------------------------
@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestApplyRefresh(_GcsMixin, L5._Harness):
    def setUp(self):
        super().setUp()
        self.install_gcs()
        self.tfvars = self.write(f"infra/platform/{PROJ}.tfvars", L5._tfvars())
        with open(self.tfvars, "rb") as f:
            self.local = f.read()
        self.plan_json = os.path.join(self.tmp, "plan.json")
        self._plan(["create"])

    def _plan(self, *actions):
        with open(self.plan_json, "w") as f:
            f.write(L5._plan_json(list(actions)))

    def _apply(self, args=("apply",), tty=PROJ, **env):
        return self.run_script("apply.sh", list(args), tty_input=tty,
                               **self.gcs_env(PROJECT_ID=PROJ, STUB_PLAN_JSON=self.plan_json, **env))

    def test_apply_writes_missing_backup(self):
        rc, out, err = self._apply()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.remote_bytes(), self.local)
        cps = self.cp_calls()
        self.assertEqual(len(cps), 1, cps)
        self.assertTrue(cps[0].startswith("gcloud storage cp ") and cps[0].endswith(f" {URI} --if-generation-match=0"))
        self.assertIn(f"Backed up {os.path.realpath(self.tfvars)} to {URI}.", err)
        # Only after the apply.
        calls = self.calls()
        self.assertLess(max(i for i, c in enumerate(calls) if c.startswith("tofu apply")), calls.index(cps[0]))
        self.assertIn("auth-on-stdin", self.meta_calls())
        self.assertFalse([c for c in self.meta_calls() if "stub-token" in c], "the token must never be on argv")

    def test_apply_with_current_copy_writes_nothing(self):
        self.put_remote(self.local)
        rc, out, err = self._apply()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cp_calls(), [])
        self.assertIn(f"Backed up {os.path.realpath(self.tfvars)}: {URI} is up to date.", err)

    def test_apply_keeps_differing_copy_as_prev(self):
        self.put_remote(b"written by another machine\n", gen=12)
        rc, out, err = self._apply()
        self.assertEqual(rc, 0, err)
        prevs = self.prev_objects()
        self.assertEqual(len(prevs), 1, prevs)
        self.assertEqual(self.remote_bytes(f"castor-tfstate-{PROJ}/platform/{prevs[0]}"), b"written by another machine\n")
        self.assertEqual(self.remote_bytes(), self.local)
        self.assertEqual(self.cp_calls()[0].split(" --")[0].split(" ")[3], f"{URI}#12")
        self.assertTrue(self.cp_calls()[1].endswith(f" {URI} --if-generation-match=12"))
        self.assertIn("[NOTE]", err)


    def test_prev_copy_failure_never_overwrites(self):
        self.put_remote(b"written by another machine\n", gen=12)
        rc, out, err = self._apply(STUB_CP_FAIL=".prev-")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.remote_bytes(), b"written by another machine\n")
        self.assertIn("APPLY_TFVARS_BACKUP_NOT_WRITTEN: could not keep the earlier copy as " + URI + ".prev-", err)
        self.assertIn(f"so {URI} was not overwritten", err)
        self.assertEqual(len(self.cp_calls()), 1)

    def test_copy_changed_meanwhile_is_not_clobbered(self):
        # The generation read (12) is gone by the upload: the precondition refuses it.
        self.put_remote(b"written by another machine\n", gen=12)
        with open(self.remote() + ".gen", "w") as f:
            f.write("12")
        os.rename(os.path.join(self.stub, "meta.py"), os.path.join(self.stub, "meta_real.py"))
        with open(os.path.join(self.stub, "meta.py"), "w") as f:
            f.write("import os, runpy, sys\nrunpy.run_path(os.path.join(os.path.dirname(sys.argv[0]), 'meta_real.py'), "
                    "run_name='__main__')\nopen(os.path.join(os.environ['STUB_GCS'], %r) + '.gen', 'w').write('13')\n"
                    % OBJ)
        rc, out, err = self._apply()
        self.assertEqual(rc, 0, err)
        # The .prev- copy is pinned to generation 12, which is gone: nothing is kept and nothing is overwritten.
        self.assertIn("APPLY_TFVARS_BACKUP_NOT_WRITTEN: could not keep the earlier copy as " + URI + ".prev-", err)
        self.assertIn("The following URLs matched no objects: " + URI + "#12", err)
        self.assertEqual(self.remote_bytes(), b"written by another machine\n")
        self.assertEqual(self.prev_objects(), [])

    def test_upload_precondition_protects_a_copy_written_meanwhile(self):
        # The copy appears between the metadata read (404) and the upload (--if-generation-match=0): 412, not clobbered.
        os.rename(os.path.join(self.stub, "meta.py"), os.path.join(self.stub, "meta_real.py"))
        with open(os.path.join(self.stub, "meta.py"), "w") as f:
            # The 404 path of meta_real.py ends in sys.exit(0): write the copy in a finally.
            f.write("import os, runpy, sys\ntry:\n    runpy.run_path(os.path.join(os.path.dirname(sys.argv[0]), "
                    "'meta_real.py'), run_name='__main__')\nfinally:\n    p = os.path.join(os.environ['STUB_GCS'], %r)\n"
                    "    open(p, 'w').write('other\\n')\n    open(p + '.gen', 'w').write('5')\n" % OBJ)
        rc, out, err = self._apply()
        self.assertEqual(rc, 0, err)
        self.assertIn("APPLY_TFVARS_BACKUP_NOT_WRITTEN: the upload to " + URI + " failed (gcloud rc=1: ERROR: "
                      "(gcloud.storage.cp) HTTPError 412: precondition failed)", err)
        self.assertEqual(self.remote_bytes(), b"other\n")

    def test_backup_failure_is_a_typed_warning_and_exit_0(self):
        rc, out, err = self._apply(STUB_CP_FAIL=URI)
        self.assertEqual(rc, 0, err)
        self.assertIn("APPLY_TFVARS_BACKUP_NOT_WRITTEN: the upload to " + URI + " failed", err)
        self.assertIn("The apply itself succeeded", err)
        self.assertIn(f"Retry: PROJECT_ID={PROJ} bash scripts/apply.sh apply (a run with no changes only refreshes the "
                      "backup)", err)

    def test_retry_names_tfvars_file_when_given(self):
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ,
                                       **self.gcs_env(TFVARS_FILE=self.tfvars, STUB_PLAN_JSON=self.plan_json,
                                                      STUB_CP_FAIL=URI))
        self.assertEqual(rc, 0, err)
        self.assertIn(f"Retry: TFVARS_FILE={os.path.realpath(self.tfvars)} bash scripts/apply.sh apply", err)

    def test_retry_quotes_a_tfvars_file_path(self):
        spaced = self.write(f"my vars/{PROJ}.tfvars", L5._tfvars())
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ,
                                       **self.gcs_env(TFVARS_FILE=spaced, STUB_PLAN_JSON=self.plan_json,
                                                      STUB_CP_FAIL=URI))
        self.assertEqual(rc, 0, err)
        quoted = os.path.realpath(spaced).replace(" ", "\\ ")
        self.assertIn(f"Retry: TFVARS_FILE={quoted} bash scripts/apply.sh apply", err)

    def test_signal_traps_are_put_back(self):
        """Do No Harm for the shell: after the helper, INT/TERM/HUP traps are what they were and no temp dir is left."""
        import subprocess
        lib = os.path.join(self.repo, "scripts", "common", "tfvars_backup.sh")
        script = ('sv_die() { exit 1; }\n. "$1"\ntrap "echo orig" INT\nSTATE_BUCKET=castor-tfstate-' + PROJ +
                  '\nPROJECT_ID=' + PROJ + '\nsv_tfvars_backup_write APPLY "$2" retry || true\n'
                  'trap -p INT; trap -p TERM; trap -p HUP; echo "left=[$SV_TFB_TMPS]"\n')
        for sh in ("bash", L5.BASH):
            r = subprocess.run([sh, "-c", script, "x", lib, self.tfvars], env=self.env(**self.gcs_env()),
                               capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            self.assertIn("trap -- 'echo orig' SIGINT", r.stdout, (sh, r.stdout, r.stderr))
            self.assertNotIn("TERM", r.stdout, sh)
            self.assertNotIn("HUP", r.stdout, sh)
            self.assertIn("left=[]", r.stdout, sh)


    def test_no_changes_apply_refreshes(self):
        self._plan(["no-op"])
        rc, out, err = self._apply(tty=None)
        self.assertEqual(rc, 0, err)
        self.assertIn("No changes. Nothing to apply.", err)
        self.assertEqual(self.remote_bytes(), self.local)

    def test_plan_never_writes(self):
        rc, out, err = self.run_script("apply.sh", ["plan"], **self.gcs_env(PROJECT_ID=PROJ))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cp_calls(), [])
        self.assertEqual(self.meta_calls(), [])
        self.assertNotIn("Backed up", err)

    def test_other_subcommands_never_write(self):
        for args in (["output"], ["validate"], ["state", "list"]):
            rc, out, err = self.run_script("apply.sh", args, **self.gcs_env(PROJECT_ID=PROJ))
            self.assertEqual(rc, 0, (args, err))
        self.assertEqual(self.cp_calls(), [])
        self.assertEqual(self.meta_calls(), [])

    def test_failed_apply_never_writes(self):
        rc, out, err = self._apply(STUB_TOFU_APPLY_RC=1)
        self.assertNotEqual(rc, 0, err)
        self.assertEqual(self.cp_calls(), [])
        self.assertEqual(self.meta_calls(), [])

    def test_refused_or_failed_plan_never_writes(self):
        for env, tty in (({"STUB_PLAN_RC": 1}, PROJ), ({}, L5.OTHER), ({}, None)):
            rc, out, err = self._apply(tty=tty, **env)
            self.assertNotEqual(rc, 0, (env, tty, err))
        self._plan(["delete"])
        rc, out, err = self._apply()
        self.assertNotEqual(rc, 0, err)
        self.assertEqual(self.cp_calls(), [])
        self.assertEqual(self.meta_calls(), [])

    def test_do_no_harm_other_calls_and_output_unchanged(self):
        """With the local file present and the backup succeeding, the only differences from a run without the
        feature (both entry points as no-ops) are the backup's own calls and lines."""
        def norm(text):
            # The plan temp dir name differs per run.
            return re.sub(r"tmp\.[A-Za-z0-9]+", "tmp.X", text)

        rc, out, err = self._apply()
        self.assertEqual(rc, 0, err)
        real_calls = [norm(c) for c in self.calls() if not c.startswith("gcloud storage cp")]
        real_out, real_err = out, err
        # Baseline: same harness, same scripts, the backup library replaced by no-ops.
        open(self.log, "w").close()
        lib = os.path.join(self.repo, "scripts", "common", "tfvars_backup.sh")
        with open(lib, "w") as f:
            f.write(NOOP_BACKUP_LIB)
        os.remove(self.remote())
        rc, out, err = self._apply()
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cp_calls(), [])
        base_calls = [norm(c) for c in self.calls()]

        # The real run adds exactly one access-token read (the metadata GET's), nothing else.
        extra = list(real_calls)
        for c in base_calls:
            extra.remove(c) if c in extra else self.fail(f"baseline call missing from the real run: {c}")
        self.assertEqual(extra, ["gcloud auth print-access-token"])
        self.assertEqual(norm(real_out), norm(out))
        # The only extra output: the one "[OK] Backed up ..." line (it follows the typed-id prompt on the same line).
        backup_line = re.compile("\x1b\\[0;32m\\[OK\\]\x1b\\[0m Backed up [^\n]*\n")
        self.assertEqual(len(backup_line.findall(real_err)), 1, real_err)
        self.assertEqual(backup_line.sub("", norm(real_err)), norm(err))


# ------------------------------------------------------------------------------------------------------------------
# apply.sh: restore offer
# ------------------------------------------------------------------------------------------------------------------
@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestApplyRestoreOffer(_GcsMixin, L5._Harness):
    def setUp(self):
        super().setUp()
        self.install_gcs()
        self.backup = L5._tfvars(extra='authorized_invoker_members = ["user:a@example.com", "user:b@example.com"]\n'
                                 ).encode()
        self.dest = os.path.join(self.platform, f"{PROJ}.tfvars")

    def _run(self, args=("plan",), tty=None, **env):
        return self.run_script("apply.sh", list(args), tty_input=tty, **self.gcs_env(PROJECT_ID=PROJ, **env))

    def _no_temp_left(self):
        for d in self.download_dirs():
            self.assertFalse(os.path.exists(d), d)
        self.assertFalse([n for n in os.listdir(self.platform) if n.startswith(".tfvars-restore")])

    def _no_engine_calls(self):
        self.assertEqual(self.tofu_ops(), [])
        self.assertFalse([c for c in self.calls() if "objects describe" in c or "services enable" in c])

    def test_yes_restores_mode_600_and_stops_for_review(self):
        self.put_remote(self.backup)
        rc, out, err = self._run(("apply",), tty="y")
        self.assertEqual(rc, 1, err)
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), self.backup)
        self.assertEqual(stat.S_IMODE(os.stat(self.dest).st_mode), 0o600)
        self.assertIn(f"{REL} does not exist. A backup exists: {URI} ({len(self.backup)} bytes, updated "
                      "2026-11-16T10:00:00.000Z).", err)
        self.assertIn(f"Restore {REL} from {URI}? [y/N]: ", err)
        self.assertIn(f"Restored {REL} from {URI} (mode 600).", err)
        self.assertIn(f"APPLY_TFVARS_RESTORED: nothing was planned or applied. Review {REL} before the next run", err)
        self.assertIn(f"then re-run: PROJECT_ID={PROJ} bash scripts/apply.sh apply", err)
        self.assertIn("before the next run", err)
        self._no_engine_calls()
        self.assertEqual(len(self.cp_calls()), 1, self.cp_calls())
        self.assertTrue(self.cp_calls()[0].startswith(f"gcloud storage cp {URI}#7 "), self.cp_calls())
        self.assertNotIn(self.platform, self.cp_calls()[0])   # downloaded under $TMPDIR, not into the repo
        self._no_temp_left()
        # The re-run then uses the restored file (G1 guard etc. unchanged): plan works and offers nothing.
        open(self.log + ".meta", "w").close()
        rc, out, err = self._run(("plan",))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.meta_calls(), [])

    def test_no_declines_with_typed_stop(self):
        self.put_remote(self.backup)
        rc, out, err = self._run(tty="n")
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_MISSING: {REL} does not exist and you chose not to restore it from {URI}. Nothing "
                      "was changed.", err)
        self.assertIn("bash scripts/bootstrap.sh", err)
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self.cp_calls(), [])
        self._no_engine_calls()

    def test_enter_is_no(self):
        self.put_remote(self.backup)
        rc, out, err = self._run(tty="")
        self.assertNotEqual(rc, 0)
        self.assertIn("APPLY_TFVARS_MISSING:", err)
        self.assertFalse(os.path.exists(self.dest))

    def test_no_terminal_never_asks(self):
        self.put_remote(self.backup)
        rc, out, err = self._run()
        self.assertNotEqual(rc, 0)
        self.assertNotIn("[y/N]", err)
        self.assertIn(f"APPLY_TFVARS_MISSING: {REL} does not exist. A backup exists at {URI} ({len(self.backup)} bytes, "
                      "updated 2026-11-16T10:00:00.000Z); this is not a terminal, so it was not offered.", err)
        self.assertIn(f"run in a terminal and answer y: PROJECT_ID={PROJ} bash scripts/apply.sh plan", err)
        self.assertIn(f"(or: gcloud storage cp {URI} {REL} && chmod 600 {REL})", err)
        self.assertIn("Or write it again with the installer: bash scripts/bootstrap.sh", err)
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self.cp_calls(), [])
        self._no_engine_calls()

    def test_no_backup(self):
        rc, out, err = self._run(tty="y")
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_MISSING_NO_BACKUP: {REL} does not exist, and there is no backup at {URI}. Nothing "
                      "was changed. Write it again with the installer: bash scripts/bootstrap.sh", err)
        self.assertIn("authorized_invoker_members, must be made again", err)
        self.assertNotIn("[y/N]", err)
        self.assertFalse(os.path.exists(self.dest))
        self._no_engine_calls()

    def test_unchecked_backup(self):
        rc, out, err = self._run(tty="y", STUB_META_CODE=403)
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_BACKUP_UNCHECKED: {REL} does not exist, and its backup {URI} could not be checked "
                      "(HTTP 403: stub says no).", err)
        self.assertNotIn("[y/N]", err)
        self.assertFalse(os.path.exists(self.dest))

    def test_existing_local_file_is_never_touched(self):
        self.put_remote(self.backup)
        local = L5._tfvars().encode()
        with open(self.dest, "wb") as f:
            f.write(local)
        rc, out, err = self._run(tty="y")
        self.assertEqual(rc, 0, err)
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), local)
        self.assertEqual(self.meta_calls(), [])
        self.assertNotIn("[y/N]", err)

    def test_dangling_link_counts_as_existing(self):
        self.put_remote(self.backup)
        os.symlink(os.path.join(self.tmp, "nowhere.tfvars"), self.dest)
        rc, out, err = self._run(tty="y")
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.meta_calls(), [])
        self.assertTrue(os.path.islink(self.dest))
        self.assertEqual(self.cp_calls(), [])

    def test_file_that_appears_meanwhile_is_not_overwritten(self):
        self.put_remote(self.backup)
        rc, out, err = self._run(tty="y", STUB_CP_CREATE_DEST=self.dest)
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_RESTORE_FAILED: {REL} appeared while the backup was downloaded (File exists); it "
                      "was not overwritten.", err)
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), b"appeared meanwhile\n")
        self._no_temp_left()

    def test_directory_that_appears_is_not_a_false_success(self):
        self.put_remote(self.backup)
        rc, out, err = self._run(tty="y", STUB_CP_CREATE_DIR=self.dest)
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_RESTORE_FAILED: {REL} appeared while the backup was downloaded (File exists)", err)
        self.assertNotIn("Restored", err)
        self.assertTrue(os.path.isdir(self.dest))
        self.assertEqual(os.listdir(self.dest), [])
        self._no_temp_left()

    def test_wrong_project_in_backup_is_refused(self):
        self.put_remote(L5._tfvars(project=L5.OTHER).encode())
        rc, out, err = self._run(tty="y")
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_BACKUP_PROJECT_MISMATCH: {URI} holds project_id = \"{L5.OTHER}\", not \"{PROJ}\". "
                      "Nothing was written", err)
        self.assertFalse(os.path.exists(self.dest))
        self._no_temp_left()

    def test_unparseable_backup_is_refused(self):
        self.put_remote(b"this is { not hcl\n")
        rc, out, err = self._run(tty="y")
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_BACKUP_PROJECT_MISMATCH: {URI} has no readable project_id", err)
        self.assertFalse(os.path.exists(self.dest))

    def test_no_md5_compares_size(self):
        self.put_remote(self.backup)
        rc, out, err = self._run(tty="y", STUB_META_NO_MD5=1)
        self.assertEqual(rc, 1, err)
        self.assertIn("APPLY_TFVARS_RESTORED", err)
        with open(self.dest, "rb") as f:
            self.assertEqual(f.read(), self.backup)
        os.remove(self.dest)
        rc, out, err = self._run(tty="y", STUB_META_NO_MD5=1, STUB_META_SIZE=len(self.backup) + 1)
        self.assertNotEqual(rc, 0)
        self.assertIn(f"is {len(self.backup)} bytes, the object {len(self.backup) + 1} (it has no MD5 to compare)", err)
        self.assertFalse(os.path.exists(self.dest))

    def test_download_is_pinned_to_the_generation_read(self):
        self.put_remote(self.backup, gen=7)
        # The object changes between the metadata read and the download: the pinned download fails, nothing written.
        os.rename(os.path.join(self.stub, "meta.py"), os.path.join(self.stub, "meta_real.py"))
        with open(os.path.join(self.stub, "meta.py"), "w") as f:
            f.write("import os, runpy, sys\nrunpy.run_path(os.path.join(os.path.dirname(sys.argv[0]), 'meta_real.py'), "
                    "run_name='__main__')\nopen(os.path.join(os.environ['STUB_GCS'], %r) + '.gen', 'w').write('8')\n"
                    % OBJ)
        rc, out, err = self._run(tty="y")
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_RESTORE_FAILED: the download of {URI}#7 failed (gcloud rc=1: ERROR: "
                      "(gcloud.storage.cp) The following URLs matched no objects", err)
        self.assertFalse(os.path.exists(self.dest))
        self._no_temp_left()

    def test_signal_during_download_removes_the_temp_dir(self):
        # SIGTERM: a signal ignored when the shell starts cannot be trapped (bash rule), and this harness may start
        # with SIGINT ignored; the INT/TERM/HUP traps share one handler.
        import pty
        import signal
        import subprocess
        import time
        self.put_remote(self.backup)
        marker = os.path.join(self.tmp, "cp-started")
        import termios
        import threading
        master, slave = pty.openpty()
        # As lane 5's harness: no echo, and drain the master, or the exiting shell blocks in tty close.
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        def _drain():
            try:
                while os.read(master, 1024):
                    pass
            except OSError:
                pass

        threading.Thread(target=_drain, daemon=True).start()
        p = subprocess.Popen([L5.BASH, os.path.join(self.repo, "scripts", "apply.sh"), "plan"], cwd=self.repo,
                             env=self.env(**self.gcs_env(PROJECT_ID=PROJ, STUB_CP_HANG=marker)), stdin=slave,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        os.close(slave)
        try:
            os.write(master, b"y\n")
            deadline = time.time() + 60
            while not os.path.exists(marker) and time.time() < deadline and p.poll() is None:
                time.sleep(0.1)
            self.assertTrue(os.path.exists(marker), "the download never started")
            dirs = self.download_dirs()
            self.assertEqual(len(dirs), 1, self.cp_calls())
            self.assertTrue(os.path.isdir(dirs[0]), "the restore temp dir should exist during the download")
            os.killpg(p.pid, signal.SIGTERM)
            out, err = p.communicate(timeout=60)
        finally:
            if p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    p.kill()
                p.wait()
            os.close(master)
        self.assertEqual(p.returncode, 143, err)
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse(os.path.exists(dirs[0]), "the INT/TERM/HUP trap must remove the temp dir")
        self.assertNotIn("Restored", err.decode(errors="replace"))

    def test_failed_download_writes_nothing(self):
        self.put_remote(self.backup)
        rc, out, err = self._run(tty="y", STUB_CP_FAIL=URI)
        self.assertNotEqual(rc, 0)
        self.assertIn(f"APPLY_TFVARS_RESTORE_FAILED: the download of {URI}#7 failed (gcloud rc=1: ERROR: "
                      "(gcloud.storage.cp) stub refused this copy). Nothing was written", err)
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse([n for n in os.listdir(self.platform) if n.startswith(".tfvars-restore.")])

    def test_corrupt_download_writes_nothing(self):
        self.put_remote(self.backup)
        rc, out, err = self._run(tty="y", STUB_CP_CORRUPT=1)
        self.assertNotEqual(rc, 0)
        self.assertIn("does not match the object's MD5", err)
        self.assertFalse(os.path.exists(self.dest))

    def test_explicit_tfvars_file_or_gcloud_default_is_not_offered(self):
        self.put_remote(self.backup)
        rc, out, err = self.run_script("apply.sh", ["plan"], tty_input="y",
                                       **self.gcs_env(TFVARS_FILE=self.dest))
        self.assertNotEqual(rc, 0)
        self.assertIn("does not exist", err)
        rc, out, err = self.run_script("apply.sh", ["plan"], tty_input="y",
                                       **self.gcs_env(STUB_GCLOUD_CONFIG_PROJECT=PROJ))
        self.assertNotEqual(rc, 0)
        self.assertIn(f"No vars file for '{PROJ}'", err)
        # Red-team fix 7: the shared stop names the backup and the restore command (upgrade.sh sees it too).
        self.assertIn(f"If the install backed it up to {URI}, PROJECT_ID={PROJ} bash scripts/apply.sh plan offers to "
                      "restore it.", err)
        self.assertEqual(self.meta_calls(), [])
        self.assertFalse(os.path.exists(self.dest))


class TestStatic(unittest.TestCase):
    def _src(self, rel):
        return L5._read(os.path.join(L5.SCRIPTS, rel))

    def test_both_scripts_source_the_library(self):
        for s in ("apply.sh", "bootstrap.sh"):
            self.assertIn('. "${SCRIPT_DIR}/common/tfvars_backup.sh"', self._src(s), s)

    def test_manual_backup_step_is_gone(self):
        self.assertNotIn("gcloud storage cp infra/platform/", self._src("bootstrap.sh"))
        for doc in ("README.md", os.path.join("documentation", "quickstart.md")):
            text = L5._read(os.path.join(L5.REPO, doc))
            self.assertNotIn("gcloud storage cp infra/platform/", text, doc)
            self.assertNotIn("prints the command to back it up", text, doc)

    def test_every_read_is_behind_the_terminal_guard(self):
        lib = self._src(os.path.join("common", "tfvars_backup.sh"))
        # Reads of stdin only (the temp-dir list and the metadata fields are read from here-strings).
        reads = [ln for ln in lib.splitlines() if re.search(r"\bread -r\b", ln) and "<<<" not in ln
                 and not ln.strip().startswith("while IFS= read -r p; do")]
        self.assertEqual(len(reads), 1, reads)
        self.assertIn('if [ -t 0 ]; then\n        printf \'Restore %s from %s? [y/N]: \'', lib)

    def test_token_only_on_stdin(self):
        lib = self._src(os.path.join("common", "tfvars_backup.sh"))
        self.assertIn("curl -sS --max-time 30 --config -", lib)
        self.assertNotIn("Authorization: Bearer ${", lib)

    def test_bash_syntax_both_shells(self):
        import subprocess
        for s in ("apply.sh", "bootstrap.sh", os.path.join("common", "tfvars_backup.sh")):
            for sh in ("bash", L5.BASH):
                r = subprocess.run([sh, "-n", os.path.join(L5.SCRIPTS, s)], capture_output=True, text=True,
                                   timeout=60)
                self.assertEqual(r.returncode, 0, (sh, s, r.stderr))


if __name__ == "__main__":
    unittest.main()

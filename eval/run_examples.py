#!/usr/bin/env python3
"""FD-30 examples eval harness: parent CLI.

Runs the real generation pipeline on documentation/examples/<NN> in guarded child processes, scores the output in a
credential-less scoring child, and writes results/<id>/{summary.json,SCOREBOARD.md,manifest.json}.
See eval/README.md. Run from the repo root as `python -m eval.run_examples ...` or `python eval/run_examples.py ...`.

Spend safety: live/record/replay-then-live need --model, --budget-usd (<= $25 unless --budget-override) and
STACKVEND_EVAL_VERTEX_PROJECT; the parent mints one short-lived access token per child and hands it over stdin.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

EVAL_DIR = Path(__file__).resolve().parent
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from stackvend_eval import gitutil, metrics, scoreboard  # noqa: E402
from stackvend_eval.budget import Budget, InvocationLedger, PriceTable  # noqa: E402
from stackvend_eval.cassettes import HARNESS_DEFAULT_FALLBACK_MODELS  # noqa: E402
from stackvend_eval.freeze import now_iso_utc_seconds  # noqa: E402
from stackvend_eval.guard import DISABLED_ADC  # noqa: E402
from stackvend_eval.llm_proxy import LIVE_MODES, MODES  # noqa: E402
from stackvend_eval.paths import (BASELINE_DIR, CASSETTES_DIR, CONFIG_DIR, EXAMPLES_DIR, REPO_ROOT,  # noqa: E402
                                  RESULTS_DIR, deps_dir, resolve_product_dep_dirs)
from stackvend_eval.targets import (INVENTORY_SHA, anchor_to, Fragment, inventory_reader,  # noqa: E402
                                    load_inventory_digests, load_retired_healers, require_inventory_coverage)

HARD_CEILING_USD = 25.0
# --stop-after: stages after which a run may end early (architect-only record / measurement; nothing is scored).
STOP_AFTER_STAGES = ("architect",)
# terraform/tofu are deliberately NOT shimmed: production's gateway image has neither binary, so `shutil.which` must
# find nothing (preflight then stays AST-only). Any exec attempt is still refused by the in-process guard.
SHIMS = ("git", "gh", "gcloud", "gsutil", "bq", "kubectl", "curl", "wget", "ssh", "nc")
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
# --impersonate-service-account (RT finding 1c): lifetime of the impersonated child token. The child wall clock
# (--timeout-min) must fit inside it. AC-5: 3600 s, the IAM default maximum (a 25-min wall clock counted Vertex
# latency as a product failure, 10-14 09-r3).
IMPERSONATED_TOKEN_LIFETIME_S = 3600
# Stale per-run outputs removed before a child is launched (RT finding 4): a child that dies before finish() must
# never be credited with a previous invocation's result.json / score.json.
STALE_RUN_FILES = ("result.json", "score.json", "child.log", "llm_requests.jsonl")


# --------------------------------------------------------------------------------------------- helpers
_ID_RE = re.compile(r"([A-Z]*)([0-9]+)")


def _split_id(i: str) -> Optional[tuple]:
    """'07' -> ('', 7); 'S3' -> ('S', 3); anything else -> None (exact grammar: optional capital prefix + digits)."""
    m = _ID_RE.fullmatch(i)
    return (m.group(1), int(m.group(2))) if m else None


def parse_examples(spec: str, catalog: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Catalog ids: '01'..'09' (examples) and 'S1'..'S7' (TI-0 synthetic specs). A range 'a-b' selects the ids with
    the same prefix as both ends whose number lies in [a, b] ('01-09' never selects an S id; 'S1-S7' never an example)."""
    ids = [e["id"] for e in catalog]
    wanted: List[str] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = (_split_id(x.strip().upper()) for x in part.split("-", 1))
            if a is None or b is None or a[0] != b[0]:
                raise SystemExit(f"bad example range {part!r} (e.g. 01-09 or S1-S7)")
            wanted += [i for i in ids if (_split_id(i) or ("?", -1))[0] == a[0]
                       and a[1] <= (_split_id(i) or ("?", -1))[1] <= b[1]]
        elif part:
            wanted.append(part.upper() if _split_id(part.upper()) and part[:1].isalpha() else part.zfill(2))
    unknown = [w for w in wanted if w not in ids]
    if unknown:
        raise SystemExit(f"unknown example ids: {unknown}")
    return [e for e in catalog if e["id"] in wanted]


def catalog_spec_path(example: Dict[str, Any]) -> Path:
    """Where a catalog entry's spec lives: documentation/examples/<file>, or <repo>/<spec_dir>/<file> (TI-0 synthetic
    specs keep theirs under eval/specs/synthetic so the public examples directory is unchanged)."""
    if example.get("spec_dir"):
        return REPO_ROOT / example["spec_dir"] / example["file"]
    return EXAMPLES_DIR / example["file"]


DEFAULT_EXAMPLES = "01-09"
SPEC_ENTRY_ID = "spec"
SPEC_FILE_MAX_BYTES = 200 * 1024  # same limit as the product's dry-run submit (plan DR-1)
# GCP project-id shape (generated IaC may embed the product id): 6-30 chars, lowercase letter first, no trailing '-'.
PRODUCT_ID_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")


def resolve_selection(a: argparse.Namespace) -> argparse.Namespace:
    """FD-4BN Phase 0: --spec-file and --examples are exclusive; with neither, --examples resolves to 01-09 here
    (after parsing), so every pre-existing invocation selects exactly the jobs it always did. Idempotent."""
    spec_file = getattr(a, "spec_file", None)
    if spec_file and a.examples is not None:
        raise SystemExit("--spec-file and --examples are exclusive")
    if getattr(a, "product_id", None) is not None and not spec_file:
        raise SystemExit("--product-id only applies with --spec-file")
    if not spec_file and a.examples is None:
        a.examples = DEFAULT_EXAMPLES
    return a


def load_spec_file(path: str) -> Dict[str, Any]:
    """Checks a --spec-file before any spend: a regular file, <= 200 KB, UTF-8, non-empty after strip(). The file is
    read once; `text` is the exact decoded bytes (no newline translation), so the bytes hashed are the bytes sent."""
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise SystemExit(f"--spec-file {path}: not a regular file")
    size = p.stat().st_size
    if size > SPEC_FILE_MAX_BYTES:
        raise SystemExit(f"--spec-file {path}: {size} bytes exceeds the {SPEC_FILE_MAX_BYTES // 1024} KB limit")
    raw = p.read_bytes()
    if len(raw) > SPEC_FILE_MAX_BYTES:  # grew between stat and read
        raise SystemExit(f"--spec-file {path}: exceeds the {SPEC_FILE_MAX_BYTES // 1024} KB limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise SystemExit(f"--spec-file {path}: not valid UTF-8 ({e.reason} at byte {e.start})")
    if not text.strip():
        raise SystemExit(f"--spec-file {path}: empty")
    import hashlib
    return {"path": str(p), "sha256": hashlib.sha256(raw).hexdigest(), "text": text}


def spec_catalog_entry(spec_file: str, product_id: Optional[str]) -> Dict[str, Any]:
    """The one synthetic catalog entry a --spec-file run uses: everything keyed on ex["id"] (run key spec-r<n>,
    run dir, trace id eval-sp-r<n>, seeds, aggregation, cassette spec-r<n>.jsonl) then works unchanged."""
    info = load_spec_file(spec_file)
    pid = product_id if product_id is not None else ("dryrun-" + info["sha256"][:8])
    if not PRODUCT_ID_RE.fullmatch(pid):
        raise SystemExit(f"--product-id {pid!r}: must match ^[a-z][a-z0-9-]{{4,28}}[a-z0-9]$ (GCP project-id shape)")
    return {"id": SPEC_ENTRY_ID, "file": None, "spec_path": info["path"], "spec_sha256": info["sha256"],
            "product_id": pid}


def spec_text(example: Dict[str, Any], mode: str, examples_sha: Optional[str] = None) -> str:
    """The example spec. With examples_sha (S1-0) the text is read from git at that commit, so replays of cassettes
    recorded on 44a2747 keep byte-identical architect requests after later docs edits (lane 9 rewrote 04-09).
    A --spec-file entry (FD-4BN) re-reads the operator's file as bytes (no newline translation) and refuses it if it
    changed since start (RT fix 7: the hash in the manifest is the hash of the bytes sent)."""
    if example.get("spec_path"):
        import hashlib
        raw = Path(example["spec_path"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != example.get("spec_sha256"):
            raise SystemExit("--spec-file changed since start (sha256 differs from the one checked at start)")
        text = raw.decode("utf-8")
    elif examples_sha:
        rel = catalog_spec_path(example).relative_to(REPO_ROOT).as_posix()
        text = gitutil.show(str(REPO_ROOT), examples_sha, rel)
        if text is None:
            if not gitutil.has_commit(REPO_ROOT, examples_sha):
                # OSS blocker 1a: only pre-F9 cassettes (private, never exported) need a commit pin; recordings since
                # F9 carry spec_text in their cassette meta and replay without any git history.
                raise SystemExit(f"--examples-sha / legacy spec pin {examples_sha}: commit {gitutil.NOT_IN_CLONE}. "
                                 "Replay that cassette from a full clone of the private repository, or use a "
                                 "recording whose cassette meta carries spec_text.")
            raise SystemExit(f"--examples-sha {examples_sha}: cannot read {rel} from git")
    else:
        text = catalog_spec_path(example).read_text()
    if mode == "full":
        return text
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if ln.lstrip().startswith("#") and "Form Submission Prompt" in ln:
            body = []
            for nxt in lines[i + 1:]:
                if nxt.lstrip().startswith("#"):
                    break
                body.append(nxt)
            return "\n".join(body).strip() + "\n"
    raise SystemExit(f"{example.get('file') or '--spec-file'}: no 'Form Submission Prompt' section for "
                     "--spec-mode form-prompt")


SPEC_PINS_PATH = CONFIG_DIR / "cassette_spec_pins.json"


def sha256_text(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def legacy_spec_pin(meta: Dict[str, Any], pins_path: Path = SPEC_PINS_PATH) -> Optional[Dict[str, Any]]:
    """Exact (frozen_now, model) match of a cassette meta against eval/config/cassette_spec_pins.json."""
    try:
        pins = json.loads(Path(pins_path).read_text()).get("pins") or []
    except FileNotFoundError:
        return None
    for p in pins:
        if p.get("frozen_now") == meta.get("frozen_now") and p.get("model") == meta.get("model"):
            return p
    return None


def resolve_spec(example: Dict[str, Any], mode: str, examples_sha: Optional[str], llm_mode: str,
                 meta: Optional[Dict[str, Any]] = None, pins_path: Path = SPEC_PINS_PATH) -> Dict[str, Any]:
    """F9: the spec a run sends, and where it came from. Replays must send the RECORDED spec: the architect, red-team
    and lead requests embed it, so reading the current checkout's documentation/examples made their request hashes
    depend on which checkout ran the harness. Precedence for replays: --examples-sha (explicit) > the cassette meta's
    spec_text (recordings since F9) > a legacy pin (exact meta match) > the working tree (`worktree_unpinned`). The
    expected hash (meta spec_sha256 or pin) is compared; `match` False means the replay cannot be exact."""
    meta = meta or {}
    expected: Optional[str] = meta.get("spec_sha256")
    pin = None
    if expected is None and llm_mode.startswith("replay"):
        pin = legacy_spec_pin(meta, pins_path)
        if pin is not None:
            expected = (pin.get("spec_sha256") or {}).get(example["id"]) if pin.get("spec_mode") == mode else None
    recorded_mode = meta.get("spec_mode")
    if example.get("spec_path"):
        # FD-4BN: a --spec-file run always sends the operator's file. A replay compares it with the recorded hash
        # (meta spec_sha256, recordings since F9), so a changed file fails closed as replay_spec_mismatch instead of
        # silently replaying the recorded text.
        # RT fix 1: a replay whose recording has no spec hash cannot prove it recorded this file -> mismatch
        # (match False, recorded_spec_sha256 None), so the run is refused before launch in every replay mode.
        text, source = spec_text(example, mode, None), "spec_file"
        expected = meta.get("spec_sha256") if llm_mode.startswith("replay") else None
        got = sha256_text(text)
        match = (got == expected) if expected else (False if llm_mode.startswith("replay") else None)
        return {"text": text, "source": source, "spec_mode": mode, "spec_sha256": got,
                "recorded_spec_sha256": expected or None, "match": match}
    elif examples_sha:
        text, source = spec_text(example, mode, examples_sha), f"examples_sha:{examples_sha}"
    elif llm_mode.startswith("replay") and meta.get("spec_text") is not None and recorded_mode in (None, mode):
        text, source = meta["spec_text"], "cassette_meta"
    elif pin is not None and expected is not None:
        text, source = spec_text(example, mode, pin["examples_sha"]), f"legacy_pin:{pin['examples_sha'][:12]}"
    else:
        text = spec_text(example, mode, None)
        source = "worktree_unpinned" if llm_mode.startswith("replay") else "worktree"
    got = sha256_text(text)
    return {"text": text, "source": source, "spec_mode": mode, "spec_sha256": got, "recorded_spec_sha256": expected,
            "match": (got == expected) if expected is not None else None}


def write_shims(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    log = d / "blocked_exec.log"
    for name in SHIMS:
        p = d / name
        p.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\nexit 126\n')
        p.chmod(0o755)


ARCHITECT_CONSENSUS_CHOICES = ("on", "off")
CONSENSUS_ENV = "ENABLE_DUAL_ARCHITECT_CONSENSUS"   # read at architect_agent/handler.py (default "true")
# A recording made before TI-0 has no `architect_consensus` in its cassette meta: the child env never set the flag
# (prod_env.json leaves it unset), so the product default ran, i.e. consensus on.
LEGACY_RECORDED_CONSENSUS = "on"
# D-10 (owner 10-26): the child's GITHUB_ORG when STACKVEND_EVAL_GITHUB_ORG is unset. The product has no built-in GitHub
# owner (FD-4AY) and the harness needs one with VCS_PROVIDER=GITHUB. Like the product's SERVERLESS_GIT_NAMESPACE this
# is deliberately NOT a valid GitHub account name (the underscore is outside GitHub's [A-Za-z0-9-] alphabet), so no one
# can register it. It only reaches the platform-rendered workload files (the WIF repository name), never a VCS and
# never an LLM request (the recorded cassettes hold no owner), so replay of existing cassettes is unaffected.
EVAL_GITHUB_ORG_DEFAULT = "stackvend_eval-org"


def child_env(tmp: Path, model: str, prod_env: Dict[str, str], architect_consensus: str = "on") -> Dict[str, str]:
    """Allowlist env for the generation child (B1/B2): no credentials, no project, no emulator variables.
    TI-0 `--architect-consensus off` sets ENABLE_DUAL_ARCHITECT_CONSENSUS=false; `on` leaves it unset (the product
    default, exactly as in production), so an `on` child env is byte-identical to the pre-TI-0 one."""
    if architect_consensus not in ARCHITECT_CONSENSUS_CHOICES:
        raise SystemExit(f"--architect-consensus must be one of {ARCHITECT_CONSENSUS_CHOICES}")
    home, sdk, t = tmp / "home", tmp / "cloudsdk", tmp / "tmp"
    for p in (home, sdk, t):
        p.mkdir(parents=True, exist_ok=True)
    write_shims(tmp / "shims")
    env = {"PATH": f"{tmp / 'shims'}:/usr/bin:/bin", "HOME": str(home), "CLOUDSDK_CONFIG": str(sdk),
           "TMPDIR": str(t), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC", "PYTHONHASHSEED": "0",
           "PYTHONDONTWRITEBYTECODE": "1",  # RT finding 5: never write __pycache__ into the product worktree
           "GOOGLE_APPLICATION_CREDENTIALS": DISABLED_ADC, "NO_GCE_CHECK": "True", "PROJECT_ID": "",
           "ADMIN_USER_EMAIL": "eval@example.invalid", "COMPLIANCE_SERVER_URL": "http://127.0.0.1:1",
           "GEMINI_MODEL": model,
           # FD-4AY / D-10: the product has no built-in GitHub owner; the child gets STACKVEND_EVAL_GITHUB_ORG, else
           # the neutral EVAL_GITHUB_ORG_DEFAULT.
           "GITHUB_ORG": os.environ.get("STACKVEND_EVAL_GITHUB_ORG") or EVAL_GITHUB_ORG_DEFAULT}
    env.update(prod_env)
    if architect_consensus == "off":
        env[CONSENSUS_ENV] = "false"
    return env


def scoring_env(tmp: Path) -> Dict[str, str]:
    home = tmp / "score-home"
    home.mkdir(parents=True, exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
           "CLOUDSDK_CONFIG": str(tmp / "score-cloudsdk"), "GOOGLE_APPLICATION_CREDENTIALS": DISABLED_ADC}
    if deps_dir().is_dir():
        env["STACKVEND_EVAL_DEPS"] = str(deps_dir())
    return env


def mint_access_token(impersonate_service_account: Optional[str] = None, *, _default: Any = None,
                      _impersonated: Any = None, _request: Any = None) -> str:
    """One short-lived access token for one child (live modes only; runs in the parent, never in the child).

    Default: the owner's ADC token (cloud-platform scope). With --impersonate-service-account (RT finding 1c, opt-in)
    the owner's ADC is only the *source* credential: the child gets a token for the target service account, minted
    via the IAM Credentials API with lifetime <= IMPERSONATED_TOKEN_LIFETIME_S, so the child's blast radius is that
    account's roles (intended: roles/aiplatform.user on the dev Vertex project), not the owner's.
    The underscore parameters are test seams (fakes only); production passes none of them."""
    if _default is None or _request is None or (impersonate_service_account and _impersonated is None):
        import google.auth  # pragma: no cover - live only
        import google.auth.impersonated_credentials
        import google.auth.transport.requests
        _default = _default or google.auth.default
        _request = _request or google.auth.transport.requests.Request
        _impersonated = _impersonated or google.auth.impersonated_credentials.Credentials
    source, _ = _default(scopes=SCOPES)
    creds = source
    if impersonate_service_account:
        creds = _impersonated(source_credentials=source, target_principal=impersonate_service_account,
                              target_scopes=list(SCOPES), lifetime=IMPERSONATED_TOKEN_LIFETIME_S)
    creds.refresh(_request())
    if not creds.token:
        raise SystemExit("could not mint an access token" + (
            f" for {impersonate_service_account}" if impersonate_service_account else " from ADC"))
    return creds.token


INVENTORY_DIGESTS_PATH = CONFIG_DIR / "inventory_line_digests.json"


def anchored_targets(product_root: Path) -> List[Dict[str, Any]]:
    data = json.loads((CONFIG_DIR / "healer_targets.json").read_text())
    frags = []
    for f in data["fragments"]:
        f = dict(f)
        f.pop("key", None)
        frags.append(Fragment(**{k: v for k, v in f.items() if k in Fragment.__dataclass_fields__}))
        frags[-1].lines = [tuple(x) for x in frags[-1].lines]

    def read_new(path: str) -> Optional[str]:
        p = product_root / path
        return p.read_text() if p.is_file() else None
    # FD-55 W0 / FD-4CR: the reviewed retired-healer list (fail closed on a malformed entry)
    deleted = load_retired_healers(CONFIG_DIR / "healer_deletions.json")
    # OSS blocker 1a: the inventory side comes from the vendored line digests, not `git show INVENTORY_SHA:<path>`,
    # so a fresh single-commit history or a shallow clone anchors exactly like the full private history.
    # RT F1: fail closed. A missing digests file raises FileNotFoundError; an uncovered inline file raises
    # InventoryDigestsError. Never a silent anchor_lost.
    files = load_inventory_digests(INVENTORY_DIGESTS_PATH)
    require_inventory_coverage(frags, files, INVENTORY_DIGESTS_PATH)
    return anchor_to(frags, inventory_reader(INVENTORY_DIGESTS_PATH, files), read_new, deleted)


def tofu_version(tofu_bin: Optional[str] = None) -> Optional[str]:
    from stackvend_eval.tofu_runner import find_tofu
    t = tofu_bin or find_tofu()
    if not t:
        return None
    try:
        r = subprocess.run([t, "version", "-json"], capture_output=True, text=True, timeout=30,
                           env={"PATH": "/usr/bin:/bin", "HOME": tempfile.gettempdir(), "CHECKPOINT_DISABLE": "1"})
        return json.loads(r.stdout).get("terraform_version")
    except Exception:
        return None


# ------------------------------------------------------------------------------------------------- runs
class Invocation:
    def __init__(self, a: argparse.Namespace):
        self.a = resolve_selection(a)
        self.catalog = json.loads((CONFIG_DIR / "examples.json").read_text())["examples"]
        self.spec_entry: Optional[Dict[str, Any]] = None
        if getattr(a, "spec_file", None):
            self.spec_entry = spec_catalog_entry(a.spec_file, getattr(a, "product_id", None))
            self.examples = [self.spec_entry]
        else:
            self.examples = parse_examples(a.examples, self.catalog)
        self.prod_env = json.loads((CONFIG_DIR / "prod_env.json").read_text())["env"]
        self.prices = PriceTable.load(Path(a.pricing))
        self.product_root = Path(a.product_root).resolve()
        self.live = a.llm in LIVE_MODES
        sha = (gitutil.head_sha(self.product_root) or "nosha")[:7]
        self.id = a.out_id or f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{sha}-{a.llm}" + (
            "-healers-off" if a.healers_off else "") + (
            ("-bypass-" + "-".join(h.strip() for h in a.bypass_healers.split(",") if h.strip()))
            if a.bypass_healers else "") + ("-consensus-off" if getattr(a, "architect_consensus", "on") == "off" else "")
        self.out = Path(a.out).resolve() / self.id
        self.frozen_now = a.frozen_now or now_iso_utc_seconds()
        self.ledger = InvocationLedger(a.budget_usd or 0.0, self.out / "spend-ledger.jsonl")
        self._lock = threading.Lock()
        self._launched: set = set()   # run keys whose child was started (ledger close semantics, RT F1)
        # None ("default") = the harness's pinned HARNESS_DEFAULT_FALLBACK_MODELS (stages.pin_settings), never the
        # product's code default (DEFAULT-MODEL-GEMINI-4-CARBON); the manifest records the list
        self.fallback_models = (None if a.fallback_models in (None, "default")
                                else [m for m in a.fallback_models.split(",") if m] if a.fallback_models != "none" else [])
        self.bypass_ids = [h.strip() for h in (a.bypass_healers or "").split(",") if h.strip()]
        from stackvend_eval.validate_client import ValidateColumn
        self.validate_column = ValidateColumn(tofu_bin=a.tofu_bin, mirror_dir=Path(a.tofu_mirror),
                                              provider_set=a.provider_set)

    def preflight(self) -> None:
        a = self.a
        if self.spec_entry is not None:  # FD-4BN: before every other check, so the reason shown is the spec-file one
            if a.baseline:
                raise SystemExit("--spec-file refuses --baseline (a baseline is the bundled 9-example corpus)")
            if a.examples_sha:
                raise SystemExit("--spec-file refuses --examples-sha (it pins the git-tracked examples only)")
        models = [a.model] + list(self.fallback_models or [])
        for m in models:
            self.prices.get(m)  # unknown model -> EvalUnpricedModel (fail closed before any spend)
        if self.live:
            if not a.budget_usd:
                raise SystemExit("--budget-usd is required for live/record/replay-then-live (no implicit default)")
            if a.budget_usd > HARD_CEILING_USD and not a.budget_override:
                raise SystemExit(f"--budget-usd {a.budget_usd} exceeds the ${HARD_CEILING_USD} ceiling; "
                                 "pass --budget-override only with explicit owner approval")
            if not a.vertex_project:
                raise SystemExit("set STACKVEND_EVAL_VERTEX_PROJECT (or --vertex-project); it is never defaulted")
            unverified = [m for m in models if not self.prices.get(m).verified]
            if unverified and not a.accept_unverified_prices:
                raise SystemExit(f"price rows not owner-verified for {unverified} (eval/config/pricing.json); "
                                 "verify them, or pass --accept-unverified-prices with owner approval")
        if a.impersonate_service_account:
            sa = a.impersonate_service_account
            if not self.live:
                raise SystemExit("--impersonate-service-account only applies to live/record/replay-then-live")
            if "@" not in sa or not sa.endswith(".gserviceaccount.com"):
                raise SystemExit(f"--impersonate-service-account must be a service account email, got {sa!r}")
            if a.timeout_min * 60 > IMPERSONATED_TOKEN_LIFETIME_S:
                raise SystemExit(f"--timeout-min {a.timeout_min} exceeds the impersonated token lifetime "
                                 f"({IMPERSONATED_TOKEN_LIFETIME_S // 60} min)")
        if a.healers_off and not a.llm.startswith("replay"):
            raise SystemExit("--healers-off (checkpoint C1) is defined on replayed LLM output only")
        if self.bypass_ids and not a.llm.startswith("replay"):
            raise SystemExit("--bypass-healers is defined on replayed LLM output only")
        if self.bypass_ids and a.healers_off:
            raise SystemExit("--bypass-healers and --healers-off are exclusive")
        if a.baseline and self.bypass_ids:
            raise SystemExit("--baseline refuses --bypass-healers runs")
        if a.shadow_accept_from and not a.llm.startswith("replay"):
            raise SystemExit("--shadow-accept-from is defined on replayed LLM output only")
        if a.shadow_accept_from and not (Path(a.shadow_accept_from) / "runs").is_dir():
            raise SystemExit(f"--shadow-accept-from {a.shadow_accept_from}: no runs/ directory")
        if a.repair_iterations is not None and a.repair_iterations < 0:
            raise SystemExit("--repair-iterations must be >= 0")
        if a.repair_iterations and a.llm == "replay-strict":
            raise SystemExit("--repair-iterations > 0 makes repair calls that have no cassette: use "
                             "replay-then-live (owner-approved spend) or --repair-iterations 0")
        if a.validate_client == "harness" and not self.validate_column.available:
            raise SystemExit(f"--validate-client harness needs a usable tofu binary ({self.validate_column.reason})")
        if a.provider_set:
            from stackvend_eval.provider_sets import ProviderSetError, check_mirror_matches_set
            try:
                check_mirror_matches_set(Path(a.tofu_mirror), a.provider_set)
            except ProviderSetError as e:
                raise SystemExit(f"--provider-set {a.provider_set}: {e}")
        if a.oracle_provider_set and a.oracle_tofu_mirror:
            from stackvend_eval.provider_sets import ProviderSetError, check_mirror_matches_set
            try:
                check_mirror_matches_set(Path(a.oracle_tofu_mirror), a.oracle_provider_set)
            except ProviderSetError as e:
                raise SystemExit(f"--oracle-provider-set {a.oracle_provider_set}: {e}")
        if a.baseline and (a.llm == "synthetic" or a.healers_off or a.temperature_override is not None
                           or a.no_llm_client):
            raise SystemExit("--baseline refuses synthetic, healers-off, temperature-override and no-llm-client runs")
        if a.stop_after and a.baseline:
            raise SystemExit("--baseline refuses --stop-after runs (nothing is generated or scored)")
        if a.topology_fixtures and (a.baseline or not a.llm.startswith("replay")):
            raise SystemExit("--topology-fixtures is a replay-only lane 10 checkpoint (never a baseline)")
        if a.llm.startswith("replay") and not a.cassettes:
            raise SystemExit("replay modes need --cassettes <dir>")
        if getattr(a, "architect_consensus", "on") not in ARCHITECT_CONSENSUS_CHOICES:
            raise SystemExit(f"--architect-consensus must be one of {ARCHITECT_CONSENSUS_CHOICES}")
        # TI-0 S7: a brownfield rerun needs its base run in the same invocation (its committed tree is the repo)
        selected = {e["id"] for e in self.examples}
        for e in self.examples:
            base = e.get("brownfield_of")
            if base and base not in selected:
                raise SystemExit(f"{e['id']} is a brownfield rerun of {base}: select {base} in the same invocation "
                                 f"(e.g. --examples {base},{e['id']})")
            if base and a.stop_after:
                raise SystemExit(f"{e['id']} (brownfield rerun) needs its base's committed tree: refuses --stop-after")

    def min_child_alloc(self) -> float:
        b = Budget(1e9, 10 ** 12, self.prices)
        return b.worst_case(self.a.model, 200_000, 65536)[3]

    def run_one(self, ex: Dict[str, Any], n: int, targets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """TI-0 RT F1: an allocation admitted for a run must never stay outstanding. A run refused before its child
        was launched (replay/spec/consensus/brownfield refusals, harness errors) is closed at $0; a launched child
        whose close was skipped by an exception is charged its full allocation (the never-under-report rule)."""
        key = f"{ex['id']}-r{n}"
        try:
            return self._run_one(ex, n, targets)
        finally:
            if self.live and key in self.ledger.outstanding:
                self.ledger.close(key, None if key in self._launched else 0.0)

    def _run_one(self, ex: Dict[str, Any], n: int, targets: List[Dict[str, Any]]) -> Dict[str, Any]:
        a = self.a
        key = f"{ex['id']}-r{n}"
        run_dir = self.out / "runs" / key
        run_dir.mkdir(parents=True, exist_ok=True)
        stale = [f for f in STALE_RUN_FILES if (run_dir / f).exists()]
        for f in stale:  # RT finding 4: before any early return too (score() picks up any dir with a result.json)
            (run_dir / f).unlink()
        if stale:
            print(f"[eval] {key}: removed stale {stale} from a reused run dir", flush=True)
        alloc = a.run_cap
        if self.live:
            alloc = self.ledger.admit(key, a.run_cap, self.min_child_alloc())
            if alloc is None:
                return {"key": key, "result": {"example": ex["id"], "run": n, "valid_run": False,
                                               "pipeline_outcome": None, "invalid_reasons": ["not_run_budget"]},
                        "run_dir": str(run_dir)}
        frozen = self.frozen_now
        cassette_in = cassette_out = None
        meta: Dict[str, Any] = {}
        if a.llm.startswith("replay"):
            cassette_in = str(Path(a.cassettes) / f"{key}.jsonl")
            if not Path(cassette_in).exists():
                return {"key": key, "result": {"example": ex["id"], "run": n, "valid_run": False,
                                               "invalid_reasons": ["replay_miss"], "pipeline_outcome": None},
                        "run_dir": str(run_dir)}
            meta = json.loads(Path(cassette_in).read_text().splitlines()[0])
            frozen = meta.get("frozen_now") or frozen
            if a.llm == "replay-then-live":
                cassette_out = str(run_dir / "cassette.jsonl")
        if a.llm == "record" or (a.llm == "synthetic" and a.cassettes):
            cassette_out = str(Path(a.cassettes or (CASSETTES_DIR / self.id)) / f"{key}.jsonl")
        spec = resolve_spec(ex, a.spec_mode, a.examples_sha, a.llm, meta)
        provenance = {k: v for k, v in spec.items() if k != "text"}
        if spec["match"] is False and (a.llm == "replay-strict"
                                       or (ex.get("spec_path") and a.llm.startswith("replay"))):
            # F9: the recorded architect/red-team/lead requests embed a different spec: an exact replay is impossible,
            # so fail closed before launching instead of serving those calls by site/ordinal fallback. RT fix 2: a
            # --spec-file run refuses in every replay mode (replay-then-live too), before any token is minted.
            recorded = spec["recorded_spec_sha256"]
            print(f"[eval] {key}: spec {spec['source']} sha256 {spec['spec_sha256'][:12]} != recorded "
                  f"{recorded[:12] if recorded else 'none (no spec hash in the recording)'}", flush=True)
            return {"key": key, "result": {"example": ex["id"], "run": n, "valid_run": False,
                                           "invalid_reasons": ["replay_spec_mismatch"], "pipeline_outcome": None,
                                           "spec_provenance": provenance}, "run_dir": str(run_dir)}
        # TI-0: the architect-consensus arm is part of what was recorded (it changes the architect calls made), so a
        # replay of the other arm is refused before launch instead of being served by site/ordinal fallback.
        consensus = getattr(a, "architect_consensus", "on")
        if a.llm.startswith("replay"):
            recorded_c = meta.get("architect_consensus") or LEGACY_RECORDED_CONSENSUS
            if recorded_c != consensus:
                print(f"[eval] {key}: --architect-consensus {consensus} != recorded {recorded_c}", flush=True)
                return {"key": key, "result": {"example": ex["id"], "run": n, "valid_run": False,
                                               "invalid_reasons": ["replay_consensus_mismatch"],
                                               "pipeline_outcome": None,
                                               "architect_consensus": {"requested": consensus,
                                                                       "recorded": recorded_c}},
                        "run_dir": str(run_dir)}
        existing_repo = None
        if ex.get("brownfield_of"):
            # TI-0 S7: rerun on the base run's committed tree (the repository production would hold after it)
            base_key = f"{ex['brownfield_of']}-r{n}"
            existing_repo = brownfield_base(self.out / "runs" / base_key)
            reason = None
            if existing_repo is None:
                reason = "brownfield_base_not_committed"
            elif a.llm.startswith("replay") and meta.get("existing_repo_tree") != existing_repo["tree_sha"]:
                reason = "replay_existing_repo_mismatch"
            if reason:
                print(f"[eval] {key}: {reason} (base {base_key})", flush=True)
                return {"key": key, "result": {"example": ex["id"], "run": n, "valid_run": False,
                                               "invalid_reasons": [reason], "pipeline_outcome": None,
                                               "brownfield": {"base": base_key}}, "run_dir": str(run_dir)}
            existing_repo["base"] = base_key
            (run_dir / "existing_repo.json").write_text(json.dumps(existing_repo, sort_keys=True))
        spec_path = run_dir / "spec.md"
        spec_path.write_bytes(spec["text"].encode("utf-8"))  # RT fix 7: exact bytes (the child reads them back as is)
        cfg = {"example": ex["id"], "run": n, "product_id": ex["product_id"], "run_dir": str(run_dir),
               "product_root": str(self.product_root), "llm_mode": a.llm, "model": a.model,
               "product_dep_dirs": resolve_product_dep_dirs(self.product_root),
               "fallback_models": self.fallback_models, "vertex_project": a.vertex_project or "",
               "vertex_location": a.vertex_location, "budget_usd": alloc, "token_cap": a.run_token_cap,
               "max_calls": a.max_calls, "pricing_path": str(Path(a.pricing).resolve()), "frozen_now": frozen,
               "spec_path": str(spec_path), "cassette_in": cassette_in, "cassette_out": cassette_out,
               "healers_off": a.healers_off, "inject_seed": not a.no_seed,
               "temperature_override": a.temperature_override, "healer_targets": targets,
               "no_llm_client": a.no_llm_client, "bypass_healers": self.bypass_ids,
               "validate_client": a.validate_client, "repair_iterations": a.repair_iterations,
               "repair_model": a.repair_model, "dump_llm_requests": a.dump_llm_requests, "stop_after": a.stop_after,
               "topology_fixtures": a.topology_fixtures,
               "dump_trees": a.dump_trees,
               "spec_provenance": provenance, "accept_trace": bool(a.accept_trace),
               "shadow_accept": _shadow_verdicts(a.shadow_accept_from, key) if a.shadow_accept_from else None,
               # F9: recordings carry their spec, so a later replay never depends on the checkout's docs
               "cassette_meta_extra": {"spec_text": spec["text"], "spec_sha256": spec["spec_sha256"],
                                       "spec_mode": a.spec_mode, "examples_sha": a.examples_sha}}
        # TI-0: the arm is recorded in every new cassette's meta line (a replay compares it, above)
        cfg["architect_consensus"] = consensus
        cfg["cassette_meta_extra"]["architect_consensus"] = consensus
        # TI-3h: the harness always passes the mode it runs (an explicit "off" keeps replays of mode-off cassettes on
        # the legacy contract whatever the product default is); only a generate run tags new cassettes' meta
        cfg["iac_intent_mode"] = getattr(a, "iac_intent_mode", "off")
        if cfg["iac_intent_mode"] != "off":
            cfg["cassette_meta_extra"]["iac_intent_mode"] = a.iac_intent_mode
        if existing_repo is not None:
            cfg["existing_repo_path"] = str(run_dir / "existing_repo.json")
            cfg["cassette_meta_extra"]["existing_repo_tree"] = existing_repo["tree_sha"]
        cfg_path = run_dir / "child_config.json"
        cfg_path.write_text(json.dumps(cfg, indent=1))
        tmp = Path(tempfile.mkdtemp(prefix=f"eval-{key}-"))
        env = child_env(tmp, a.model, self.prod_env, consensus)
        token_line = ""
        if self.live:
            token_line = json.dumps({"access_token": mint_access_token(a.impersonate_service_account)}) + "\n"
        cmd = [sys.executable, "-I", "-B", str(EVAL_DIR / "run_child.py"), "--config", str(cfg_path)]
        if a.canary_only:
            cmd.append("--canary-only")
        timed_out = False
        server = None
        if a.validate_client == "harness":
            # S1-0: the child cannot spawn tofu or open sockets; it hands trees to this parent over files in
            # run_dir/ipc and the parent validates them with the allow-listed TofuRunner (production column).
            from stackvend_eval.validate_client import ParentValidateServer
            server = ParentValidateServer(run_dir / "ipc", self.validate_column, work_root=tmp / "validate")
            server.start()
        with (run_dir / "child.log").open("w") as log:
            self._launched.add(key)
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT, env=env,
                                    cwd=str(tmp), text=True)
            try:
                proc.stdin.write(token_line)
                proc.stdin.close()
            except BrokenPipeError:
                pass
            token_line = ""
            try:
                proc.wait(timeout=a.timeout_min * 60)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                proc.wait()
        if server is not None:
            server.stop()
        shutil.rmtree(tmp, ignore_errors=True)
        rp = run_dir / "result.json"
        result = json.loads(rp.read_text()) if rp.exists() else {
            "example": ex["id"], "run": n, "valid_run": False, "pipeline_outcome": None,
            "invalid_reasons": ["harness_error"], "note": f"child exited {proc.returncode} without result.json"}
        if timed_out:
            result["valid_run"] = False
            result.setdefault("invalid_reasons", []).append("timeout")
            rp.write_text(json.dumps(result, indent=1, sort_keys=True, default=str))
        if self.live:
            b = result.get("budget") or {}
            reported = None if (timed_out or "settled_usd" not in b) else b["settled_usd"] + b.get("outstanding_usd", 0)
            result["charged_usd"] = self.ledger.close(key, reported)
        return {"key": key, "result": result, "run_dir": str(run_dir), "exit_code": proc.returncode}

    def score(self, records: List[Dict[str, Any]]) -> None:
        dirs = [r["run_dir"] for r in records if (Path(r["run_dir"]) / "result.json").exists()]
        if not dirs or self.a.skip_score or self.a.stop_after:
            return
        for d in dirs:  # RT finding 4: a scoring child that dies must not leave an older score.json to be read
            (Path(d) / "score.json").unlink(missing_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix="eval-score-"))
        forbidden = [p for p in [self.a.vertex_project] + os.environ.get(
            "STACKVEND_EVAL_FORBIDDEN_PROJECTS", "").split(",") if p]
        cfg = {"run_dirs": dirs, "work_root": str(tmp / "work"), "mirror_dir": str(Path(self.a.tofu_mirror).resolve()),
               "forbidden_projects": forbidden, "plan": not self.a.no_plan, "tofu_bin": self.a.tofu_bin,
               "column_label": self.a.provider_set or "default",
               "oracle_tofu_bin": self.a.oracle_tofu_bin,
               "oracle_mirror_dir": str(Path(self.a.oracle_tofu_mirror).resolve()) if self.a.oracle_tofu_mirror else None,
               "oracle_label": self.a.oracle_provider_set or "oracle", "product_root": str(self.product_root),
               "dep_dirs": resolve_product_dep_dirs(None)}
        cp = self.out / "scoring_config.json"
        cp.write_text(json.dumps(cfg, indent=1))
        with (self.out / "scoring.log").open("w") as log:
            subprocess.run([sys.executable, "-I", "-B", str(EVAL_DIR / "score_child.py"), "--config", str(cp)],
                           stdout=log, stderr=subprocess.STDOUT, env=scoring_env(tmp), cwd=str(tmp),
                           timeout=self.a.score_timeout_min * 60)
        shutil.rmtree(tmp, ignore_errors=True)
        for r in records:
            sp = Path(r["run_dir"]) / "score.json"
            if sp.exists():
                r["score"] = json.loads(sp.read_text())

    def manifest(self, records: List[Dict[str, Any]]) -> Dict[str, Any]:
        a = self.a
        models = [a.model] + list(self.fallback_models or [])
        return {
            "id": self.id, "llm_mode": a.llm, "model": a.model,
            "fallback_models": (self.fallback_models if self.fallback_models is not None
                                else list(HARNESS_DEFAULT_FALLBACK_MODELS)),
            "vertex_location": a.vertex_location, "vertex_project_set": bool(a.vertex_project),
            "child_token_identity": (("impersonated:" + a.impersonate_service_account)
                                     if a.impersonate_service_account else "owner_adc") if self.live else "none",
            "examples": [e["id"] for e in self.examples], "runs_per_example": a.runs, "spec_mode": a.spec_mode,
            "product_root": str(self.product_root), "product_sha": gitutil.head_sha(self.product_root),
            "product_dirty": gitutil.is_dirty(self.product_root), "harness_sha": gitutil.head_sha(REPO_ROOT),
            "harness_dirty": gitutil.is_dirty(REPO_ROOT), "inventory_sha": INVENTORY_SHA,
            "python": platform.python_version(), "tofu": tofu_version(a.tofu_bin), "frozen_now": self.frozen_now,
            "tofu_mirror_manifest": _mirror_manifest_digest(Path(a.tofu_mirror)),
            "provider_set": a.provider_set, "tofu_bin": a.tofu_bin,
            "oracle_tofu": tofu_version(a.oracle_tofu_bin) if a.oracle_tofu_bin else None,
            "oracle_tofu_mirror_manifest": (_mirror_manifest_digest(Path(a.oracle_tofu_mirror))
                                            if a.oracle_tofu_mirror else None),
            "oracle_provider_set": a.oracle_provider_set, "examples_sha": a.examples_sha,
            "bypass_healers": self.bypass_ids, "validate_client": a.validate_client,
            "repair_iterations": a.repair_iterations, "repair_model": a.repair_model,
            "accept_trace": bool(a.accept_trace), "shadow_accept_from": a.shadow_accept_from, "stop_after": a.stop_after,
            "topology_fixtures": a.topology_fixtures,
            "healers_off": a.healers_off, "inject_seed": not a.no_seed, "seed_scheme": "sha256(example|run|request_hash|occurrence)[:8] mod 2^31",
            "temperature_override": a.temperature_override, "budget_usd": a.budget_usd, "run_cap": a.run_cap,
            "run_token_cap": a.run_token_cap, "max_calls": a.max_calls,
            "prices": {m: {"in_ceiling": self.prices.get(m).in_per_m, "out_ceiling": self.prices.get(m).out_per_m,
                           "verified": self.prices.get(m).verified} for m in models},
            "prod_env": self.prod_env, "ledger": self.ledger.snapshot() if self.live else "n/a (no live spend)",
            "settings_pinned_hash": _hash_first(records, "pinned_settings"),
            # FD-4BN: where the spec came from; never the spec path or text
            "spec_source": "file" if self.spec_entry is not None else "catalog",
            "spec_sha256": self.spec_entry["spec_sha256"] if self.spec_entry is not None else None,
            "product_id": self.spec_entry["product_id"] if self.spec_entry is not None else None,
            # TI-0: which architect-consensus arm ran (child env ENABLE_DUAL_ARCHITECT_CONSENSUS; "on" = unset)
            "architect_consensus": getattr(a, "architect_consensus", "on"),
            # TI-3: the product's typed IaC intent mode for this run (HallucinationStackSettings.iac_intent_mode)
            "iac_intent_mode": getattr(a, "iac_intent_mode", "off"),
        }


def brownfield_base(base_dir: Path) -> Optional[Dict[str, Any]]:
    """TI-0 S7: the base run's committed (C3) tree and the IaC provenance its commit wrote, or None when the base did
    not commit (then the rerun is not run: `brownfield_base_not_committed`, a harness outcome, never a product one)."""
    rp = Path(base_dir) / "result.json"
    if not rp.is_file():
        return None
    r = json.loads(rp.read_text())
    th = ((r.get("checkpoints") or {}).get("C3_committed") or {}).get("tree")
    if not r.get("valid_run") or not isinstance(th, str) or not SHA256_HEX_RE.fullmatch(th):
        return None
    from stackvend_eval.blobs import BlobStore
    try:
        tree = BlobStore(Path(base_dir)).get_tree(th)
    except FileNotFoundError:
        return None
    from stackvend_eval.metrics import compute_service_names
    return {"tree_sha": th, "tree": tree, "provenance": r.get("provenance_after_commit") or {},
            "base_compute": compute_service_names(r)}


def job_phases(jobs: List[Any]) -> List[List[Any]]:
    """Brownfield reruns (catalog `brownfield_of`) run after every other job, so their base has finished."""
    first = [j for j in jobs if not j[0].get("brownfield_of")]
    second = [j for j in jobs if j[0].get("brownfield_of")]
    return [p for p in (first, second) if p]


def _shadow_verdicts(results_dir: str, key: str) -> Dict[str, List[Any]]:
    """{repair iteration: [accepted, reject_reason]} from a recorded run's RepairEvents (all personas of one iteration
    share the verdict). A run without a result or events gets {} (every product verdict passes through)."""
    p = Path(results_dir) / "runs" / key / "result.json"
    if not p.is_file():
        return {}
    events = (json.loads(p.read_text()).get("hallucination_stack") or {}).get("repair_events") or []
    return {str(e["iteration"]): [bool(e["accepted"]), e.get("reject_reason")] for e in events}


def _mirror_manifest_digest(mirror: Path) -> Optional[str]:
    from stackvend_eval.tofu_runner import MIRROR_MANIFEST, _sha256_file
    mf = Path(mirror) / MIRROR_MANIFEST
    return _sha256_file(mf) if mf.is_file() else None


def _hash_first(records: List[Dict[str, Any]], field: str) -> Optional[str]:
    import hashlib
    for r in records:
        v = r["result"].get(field)
        if v is not None:
            return hashlib.sha256(json.dumps(v, sort_keys=True).encode()).hexdigest()[:16]
    return None


def warm_tofu_mirror(mirror: Path, extra: Optional[List[str]] = None) -> int:  # pragma: no cover - network, owner step
    """--warm-tofu-mirror DIR [--provider-set NAME] [--tofu-bin PATH]: with a provider set (S1-0) every provider is
    pinned exactly (`= x.y.z`) from eval/config/provider_sets.json; without one, the lane 7 ranges are kept."""
    from stackvend_eval.tofu_runner import find_tofu
    ap = argparse.ArgumentParser(prog="run_examples.py --warm-tofu-mirror DIR")
    ap.add_argument("--provider-set", default=None)
    ap.add_argument("--tofu-bin", default=None)
    xa = ap.parse_args(extra or [])
    t = xa.tofu_bin or find_tofu()
    if not t:
        print("tofu not found")
        return 1
    d = Path(tempfile.mkdtemp(prefix="mirror-cfg-"))
    if xa.provider_set:
        from stackvend_eval.provider_sets import required_providers_block
        (d / "versions.tf").write_text(required_providers_block(xa.provider_set))
    else:
        (d / "versions.tf").write_text(
            'terraform {\n  required_providers {\n'
            '    google = { source = "hashicorp/google", version = ">= 6.0.0, < 7.0.0" }\n'
            '    google-beta = { source = "hashicorp/google-beta", version = ">= 6.0.0, < 7.0.0" }\n'
            '    kubernetes = { source = "hashicorp/kubernetes", version = ">= 2.20" }\n'
            '    random = { source = "hashicorp/random" }\n    null = { source = "hashicorp/null" }\n'
            '    time = { source = "hashicorp/time" }\n    archive = { source = "hashicorp/archive" }\n  }\n}\n')
    mirror.mkdir(parents=True, exist_ok=True)
    print(f"Downloading providers from registry.opentofu.org into {mirror} (network) ...")
    r = subprocess.run([t, "providers", "mirror", str(mirror)], cwd=str(d),
                       env={"PATH": "/usr/bin:/bin", "HOME": str(d), "CHECKPOINT_DISABLE": "1"})
    if r.returncode == 0:
        from stackvend_eval.tofu_runner import write_mirror_manifest
        mf = write_mirror_manifest(mirror)  # RT finding 7: every scoring run re-verifies these checksums
        print(f"Wrote {mf} ({len(mf.read_text().splitlines())} files); scoring refuses a mirror that no longer matches")
    return r.returncode


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--examples", default=None, help=f"catalog ids, e.g. 01,03-05 (default {DEFAULT_EXAMPLES}; "
                    "exclusive with --spec-file)")
    ap.add_argument("--spec-file", default=None, metavar="PATH",
                    help="FD-4BN dry run: run this spec (UTF-8, non-empty, <= 200 KB) instead of the catalog")
    ap.add_argument("--product-id", default=None, metavar="ID",
                    help="with --spec-file: product id (default dryrun-<first 8 hex of sha256(spec)>; GCP project-id "
                         "shape)")
    ap.add_argument("--report", choices=("none", "html"), default="none",
                    help="html: also write results/<id>/report.html (static, escaped, no scripts)")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--llm", choices=MODES, required=True)
    ap.add_argument("--model", required=True, help="REQUIRED (B7): e.g. gemini-3.8-flash or gemini-3.7-flash")
    ap.add_argument("--fallback-models", default="default",
                    help="comma list, 'none', or 'default' (= the harness's pinned fallback list, "
                         "HARNESS_DEFAULT_FALLBACK_MODELS: the one the cassettes were recorded with; recorded)")
    ap.add_argument("--vertex-project", default=os.environ.get("STACKVEND_EVAL_VERTEX_PROJECT"))
    ap.add_argument("--vertex-location", default=os.environ.get("STACKVEND_EVAL_VERTEX_LOCATION", "global"))
    ap.add_argument("--budget-usd", type=float, default=None, help="invocation cap (required for live modes)")
    ap.add_argument("--budget-override", action="store_true", help=f"allow --budget-usd above ${HARD_CEILING_USD}")
    ap.add_argument("--run-cap", type=float, default=3.0, help="per-run USD cap (reservation semantics)")
    ap.add_argument("--run-token-cap", type=int, default=1_500_000)
    ap.add_argument("--max-calls", type=int, default=60)
    ap.add_argument("--accept-unverified-prices", action="store_true")
    ap.add_argument("--impersonate-service-account", default=None, metavar="EMAIL",
                    help="live modes, opt-in (default OFF): mint each child's token by impersonating this service "
                         "account (lifetime <= 60 min) instead of handing the child the owner's ADC token")
    ap.add_argument("--pricing", default=str(CONFIG_DIR / "pricing.json"))
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--timeout-min", type=float, default=45.0)  # AC-5; must fit IMPERSONATED_TOKEN_LIFETIME_S
    ap.add_argument("--score-timeout-min", type=float, default=120.0)
    ap.add_argument("--product-root", default=str(REPO_ROOT))
    ap.add_argument("--out", default=str(RESULTS_DIR))
    ap.add_argument("--out-id", default=None)
    ap.add_argument("--cassettes", default=None, help="record: output dir; replay: input dir (<NN>-r<n>.jsonl)")
    ap.add_argument("--frozen-now", default=None, help="ISO-8601 with offset; default now (record) / cassette meta (replay)")
    ap.add_argument("--spec-mode", choices=("full", "form-prompt"), default="full")
    ap.add_argument("--healers-off", action="store_true", help="checkpoint C1 (replay only)")
    ap.add_argument("--no-seed", action="store_true")
    ap.add_argument("--dump-llm-requests", action="store_true",
                    help="write every normalized (hashed) LLM request to runs/<key>/llm_requests.jsonl (full prompts; "
                         "diagnostic, for diffing replay divergence across environments)")
    ap.add_argument("--dump-trees", action="store_true",
                    help="S2-0: store every assembled tree (draft, assembled, root module, platform files, assembly "
                         "record) and every self_correct_hcl input/output in the run's blob store (tree_dumps)")
    ap.add_argument("--temperature-override", type=float, default=None, help="diagnostic only; never a baseline")
    ap.add_argument("--no-llm-client", action="store_true", help="tripwire self-test: agents get no client")
    ap.add_argument("--canary-only", action="store_true")
    ap.add_argument("--skip-score", action="store_true")
    ap.add_argument("--no-plan", action="store_true")
    ap.add_argument("--tofu-mirror", default=str(EVAL_DIR / ".tofu-mirror"))
    # ---- S1-0 (Step 1): production engine/provider column, oracle column, validate client, repair, bypass
    ap.add_argument("--tofu-bin", default=None, help="tofu binary for the scorer and --validate-client harness "
                    "(production column; default: host tofu)")
    ap.add_argument("--provider-set", default=None, help="exact pins the --tofu-mirror must hold "
                    "(eval/config/provider_sets.json, e.g. production); refused on any mismatch")
    ap.add_argument("--oracle-tofu-bin", default=None, help="second scoring column: tofu binary (e.g. 1.13.1)")
    ap.add_argument("--oracle-tofu-mirror", default=None, help="second scoring column: provider mirror")
    ap.add_argument("--oracle-provider-set", default=None, help="exact pins for --oracle-tofu-mirror")
    ap.add_argument("--validate-client", choices=("none", "harness"), default="none",
                    help="harness: install HarnessValidateClient in the product (V1b over child->parent file IPC)")
    ap.add_argument("--repair-iterations", type=int, default=None,
                    help="product repair_max_iterations_precommit for this run (0 = validators only, no repair calls)")
    ap.add_argument("--repair-model", default=None, help="product repair_model for this run (needs a pricing row)")
    ap.add_argument("--accept-trace", action="store_true",
                    help="record every repair-acceptance verdict with the diagnostics it fixed/introduced "
                         "(result.json accept_trace; observation only)")
    ap.add_argument("--shadow-accept-from", default=None, metavar="RESULTS_DIR",
                    help="replay only ($0 re-scoring): hand the repair loop the verdicts recorded in "
                         "RESULTS_DIR/runs/<key>/result.json so the replay keeps matching the recorded repair "
                         "cassette; the product's own verdicts are recorded in accept_trace")
    ap.add_argument("--bypass-healers", default=None, metavar="IDS",
                    help="replay only: stub just these HEALERS.md ids with their identity contracts (e.g. HB-03,HB-04)")
    ap.add_argument("--examples-sha", default=None,
                    help="read documentation/examples from git at this commit (replay of cassettes recorded there)")
    ap.add_argument("--baseline", action="store_true", help="also write eval/baseline/{summary.json,SCOREBOARD.md,manifest.json}")
    ap.add_argument("--topology-fixtures", choices=("legacy-equivalent",), default=None,
                    help="replay only (lane 10 checkpoint A): give the recorded architect answers (which predate "
                         "service_topology) the topology that reproduces the recorded service set, plus typed edges")
    ap.add_argument("--architect-consensus", choices=ARCHITECT_CONSENSUS_CHOICES, default="on",
                    help="TI-0: on = product default (ENABLE_DUAL_ARCHITECT_CONSENSUS unset, as in production); off = "
                         "the child runs with ENABLE_DUAL_ARCHITECT_CONSENSUS=false. Recorded in the manifest and in "
                         "each cassette; a replay of the other arm is refused (replay_consensus_mismatch)")
    ap.add_argument("--iac-intent-mode", choices=("off", "generate"), default="off",
                    help="TI-3: the product's HallucinationStackSettings.iac_intent_mode for every run, always passed "
                         "explicitly (off = the legacy HCL contract, the harness default; an install's default is "
                         "generate since GEN-DEFAULT, but the harness never reads the install's Control Center "
                         "setting). Recorded in the manifest and in new cassettes' meta")
    ap.add_argument("--stop-after", choices=STOP_AFTER_STAGES, default=None,
                    help="end each run after this stage (outcome stopped_after_<stage>; no scoring): an architect-only "
                         "record makes only the architect + red-team calls")
    return ap


PATH_ARGS = ("cassettes", "product_root", "out", "pricing", "tofu_mirror", "tofu_bin", "oracle_tofu_bin",
             "oracle_tofu_mirror")
OPTIONAL_PATH_ARGS = ("spec_file",)  # FD-4BN: absolutized the same way, but only when given


def c3_file_listing(run_dir: Path, result: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Names and sizes of the committed (C3) tree for the HTML report; contents never leave the blob store."""
    tree = ((result.get("checkpoints") or {}).get("C3_committed") or {}).get("tree")
    if not isinstance(tree, str) or not SHA256_HEX_RE.fullmatch(tree):
        return None
    mp = Path(run_dir) / "trees" / f"{tree}.json"
    if not mp.is_file():
        return None
    out = []
    for name, h in sorted(json.loads(mp.read_text()).items()):
        p = Path(run_dir) / "blobs" / h[:2] / h if SHA256_HEX_RE.fullmatch(str(h)) else None
        out.append({"name": name, "bytes": p.stat().st_size if p is not None and p.is_file() else None})
    return out


def write_report(out_dir: Path, summary: Dict[str, Any], records: List[Dict[str, Any]]) -> Path:
    """--report html: results/<id>/report.html, written to a temp file then os.replace'd. RT fix 9: a lone surrogate in
    model output is written as "?" (errors="replace"; the page stays escaped), and the temp file never outlives a
    failed write or replace."""
    from stackvend_eval import report
    for r in records:
        r["c3_files"] = c3_file_listing(Path(r["run_dir"]), r.get("result") or {})
    page = report.render(summary, records)
    dest = Path(out_dir) / "report.html"
    fd, tmp = tempfile.mkstemp(prefix=".report-", suffix=".html", dir=str(out_dir))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(page)
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return dest


def absolutize_paths(a: argparse.Namespace) -> argparse.Namespace:
    """Children run with cwd=<tmpdir>, so every path argument is resolved against the caller's cwd up front
    (a relative --cassettes used to be looked up inside the child's tmpdir)."""
    for attr in PATH_ARGS + OPTIONAL_PATH_ARGS:
        if getattr(a, attr, None):
            setattr(a, attr, str(Path(getattr(a, attr)).expanduser().resolve()))
    return a


def warm_tofu_binary(argv: List[str]) -> int:  # pragma: no cover - network, owner-approved step only (D12)
    """--warm-tofu-binary VERSION --into DIR --sha256sums FILE: download the release zip, verify it against the
    owner-fetched upstream SHA256SUMS BEFORE unpacking, then unpack only `tofu`. Never uses a PATH binary."""
    import urllib.request
    from stackvend_eval.provider_sets import release_zip_name, unpack_verified_tofu
    ap = argparse.ArgumentParser(prog="run_examples.py --warm-tofu-binary")
    ap.add_argument("version")
    ap.add_argument("--into", required=True)
    ap.add_argument("--sha256sums", required=True)
    a = ap.parse_args(argv)
    name = release_zip_name(a.version)
    url = f"https://github.com/opentofu/opentofu/releases/download/v{a.version}/{name}"
    d = Path(tempfile.mkdtemp(prefix="tofu-zip-"))
    zp = d / name
    print(f"Downloading {url} (network, owner-approved) ...")
    urllib.request.urlretrieve(url, zp)
    binary, digest = unpack_verified_tofu(zp, Path(a.sha256sums), a.version, Path(a.into))
    shutil.rmtree(d, ignore_errors=True)
    print(f"verified sha256 {digest}; installed {binary}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None and len(sys.argv) > 1 and sys.argv[1] == "--warm-tofu-binary":
        return warm_tofu_binary(sys.argv[2:])
    if argv is None and len(sys.argv) > 1 and sys.argv[1] == "--warm-tofu-mirror":
        return warm_tofu_mirror(Path(sys.argv[2]) if len(sys.argv) > 2 else EVAL_DIR / ".tofu-mirror",
                                sys.argv[3:])
    a = absolutize_paths(build_parser().parse_args(argv))
    inv = Invocation(a)
    inv.preflight()
    inv.out.mkdir(parents=True, exist_ok=True)
    targets = anchored_targets(inv.product_root)
    jobs = [(ex, n) for ex in inv.examples for n in range(1, a.runs + 1)]
    print(f"[eval] {inv.id}: {len(jobs)} runs, mode={a.llm}, model={a.model}, out={inv.out}", flush=True)
    records = []
    for phase in job_phases(jobs):
        with ThreadPoolExecutor(max_workers=max(1, a.parallel)) as pool:
            records += list(pool.map(lambda j: inv.run_one(j[0], j[1], targets), phase))
    expected = {e["id"]: e.get("expected_outcome") for e in inv.examples}
    for r in records:  # TI-0: the synthetic specs' expected typed outcomes (metrics.synthetic_expectation)
        if expected.get(r["result"].get("example")):
            r["expected_outcome"] = expected[r["result"]["example"]]
    for r in records:
        print(f"[eval] {r['key']}: outcome={r['result'].get('pipeline_outcome')} valid={r['result'].get('valid_run')} "
              f"reasons={r['result'].get('invalid_reasons')} served={metrics.served_counts(r['result'])} "
              f"spec={(r['result'].get('spec_provenance') or {}).get('source')}", flush=True)
    inv.score(records)
    summary = metrics.aggregate(records)
    summary["manifest"] = inv.manifest(records)
    summary["manifest"]["paired_exclusions"] = summary["paired_exclusions"]   # code RT F7
    (inv.out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True, default=str))
    (inv.out / "manifest.json").write_text(json.dumps(summary["manifest"], indent=1, sort_keys=True, default=str))
    (inv.out / "SCOREBOARD.md").write_text(scoreboard.render(summary))
    if a.report == "html":
        print(f"[eval] wrote {write_report(inv.out, summary, records)}", flush=True)
    if a.baseline:
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        slim = {k: v for k, v in summary.items() if k != "runs"}
        slim["runs"] = [{k: v for k, v in r.items() if k not in ("resource_types",)} for r in summary["runs"]]
        (BASELINE_DIR / "summary.json").write_text(json.dumps(slim, indent=1, sort_keys=True, default=str))
        (BASELINE_DIR / "manifest.json").write_text(json.dumps(summary["manifest"], indent=1, sort_keys=True, default=str))
        (BASELINE_DIR / "SCOREBOARD.md").write_text(scoreboard.render(summary))
    print(f"[eval] wrote {inv.out / 'SCOREBOARD.md'}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

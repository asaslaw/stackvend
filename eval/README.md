# Examples eval harness (FD-30)

Runs StackVend's **real generation pipeline in-process** (architect + consensus, compliance, developer swarm,
preflight, pre-commit gate, gatekeeper) on `documentation/examples/01-09`, and scores what production would commit:
`tofu validate`, a hermetic mock-provider plan, HCL/Python parse rates, undefined Python names, AGENTS.md
invariants (acyclic `service_uri`, no hardcoded region/CIDR/project, IaC layout, no Dockerfiles) and, per healer in
the healer inventory (`eval/config/healer_targets.json`; ids such as `HB-03`), how often it fires and whether its
input was already valid.

It is the measuring stick for replacing regex healers with validators + repair loops (FD-53) and deleting them
(FD-55): record LLM output once, then replay the same cassettes through two product checkouts and compare.

## Isolation model (why it is safe to point at a real Vertex project)

| Layer | What it does |
| :-- | :-- |
| 0. Credentials | The parent mints one short-lived **access token** per run and passes it on stdin. The generation child runs with `GOOGLE_APPLICATION_CREDENTIALS=/nonexistent/adc-disabled.json`, an empty `HOME`/`CLOUDSDK_CONFIG`, `PROJECT_ID=""`, no `*_EMULATOR_HOST`. Only the harness's own `genai.Client` holds the token; every other Google client fails closed on credentials alone. |
| 1. Process/env | One `python -I` child per (example, run), allowlist env, `PATH` shims for `git`/`gcloud`/`kubectl`/... |
| 2. In-process guard | Denies ALL process creation (`fork_exec`, `posix_spawn`, `system`, `fork`, `exec*`, `spawn*`, `pty`), every gRPC channel (sync + `grpc.aio`), every socket except the Vertex hostname(s), Firestore/Storage/Pub/Sub/Secret Manager/legacy `vertexai` constructors, `google.auth.default()`, and any second `genai.Client`. |
| Canary | Before importing product code, 23 probes (anonymous-credential clients, gRPC, `grpc.aio`, sockets incl. a localhost listener, `httpx`/`requests`, `os.system`, `posix_spawn`, `subprocess`, asyncio and multiprocessing spawn) must each be blocked **by the guard**, or the run aborts before spending. |
| 3. Scoring child | No credentials at all, socket/gRPC guard with an empty allowlist; `tofu` only via an allowlisted runner (`fmt`/`init -backend=false`/`validate`/filtered `test`), offline filesystem mirror, `sandbox-exec` network deny on macOS, remote module sources refused, every provider mocked. |

Nothing is ever written to Firestore, GCS, GitHub, Pub/Sub or Cloud Run; no `plan`/`apply`.

## Budget

Every LLM call reserves its worst case (`input bytes + 64` tokens at the ceiling input price, plus
`max_output_tokens` at the ceiling output price, thinking included) **before** it is sent, and settles to the actual
`usage_metadata` after. A failed call is charged its full reservation. Exceeding a cap is sticky and invalidates the
run. Caps: per run (`--run-cap`, USD), per run tokens (`--run-token-cap`), calls per run (`--max-calls`), and per
invocation (`--budget-usd`, required for live modes, max $25 without `--budget-override`); the parent counts money
allocated to running children and charges a child that dies its whole allocation. Prices live in
`config/pricing.json` (ceiling = 2x list); a model with no row is refused; unverified rows need
`--accept-unverified-prices`.

Wall clock and budget stalls (AC-5): each child gets `--timeout-min` (default 45) and, with
`--impersonate-service-account`, a token valid for 60 min (`IMPERSONATED_TOKEN_LIFETIME_S` = 3600, the IAM default
maximum; the wall clock must fit inside it). A call that has to wait for in-flight reservations to settle records the
time in `result.json` → `budget.wait_s` / `budget.waits`, so a budget stall is not mistaken for model latency.
`wait_s` is summed over calls, and junior calls run in parallel threads, so it can exceed the run's wall time. A child
killed at the wall clock writes no `result.json`, so its stall is not recorded (the run shows `timeout`).
For `record` runs use `--run-cap 3`: reservations are worst case (a heavy multi-service run settles ≈ $1.2 but reserves
far more), so a smaller per-run cap stalls or refuses calls; the invocation cap (`--budget-usd`) still bounds the spend.

## Modes

| `--llm` | Use |
| :-- | :-- |
| `synthetic` | Offline, $0: schema-valid responses built from the product's own fallbacks. Harness self-test only; never a baseline. With `--cassettes DIR` it also records. |
| `record` | Live Vertex, budgeted, records cassettes to `eval/cassettes/<id>/` (gitignored). |
| `live` | Live Vertex, budgeted, nothing recorded. |
| `replay-strict` | Cassettes only, $0, deterministic. A miss invalidates the run. |
| `replay-then-live` | Cassettes, falling back to live (budgeted) on a miss; needed once FD-53 adds repair calls. |

`--model` is **required** (no implicit default): production and the code/TF defaults currently disagree on the model
(FD-07 D1). Seeds are injected best-effort (`sha256(example|run|request_hash|occurrence)`), production temperatures
are kept, and the date is frozen per run (recorded in the cassette) so committed trees are comparable across days.

## Checkpoints and metrics

`C0` raw LLM files (parse rates) | `C1` healers off (`--healers-off`, replay only) | `C2` `generate_code_files`
return | `C3` committed tree, captured at the token fetch inside the real `commit_and_open_pr`.
`pipeline_outcome` is one of `committed_passed`, `precommit_rejected`, `gatekeeper_rejected`, `generation_error`,
`invalid`. The validate rate is reported unconditionally (rejected = fail) and conditionally. The Do-No-Harm gate is
**fires on validate-valid input = 0** (a healer changed input that already passed `tofu validate` /
`ast`+pyflakes), shown next to the probe coverage %.

Probe coverage % is measured over **live** healers only (FD-55 W0): the healer inventory
(`config/healer_targets.json`) minus the reviewed retired list `config/healer_deletions.json`, where every healer
deleted on purpose is listed with the commit that deleted it. A listed healer leaves the denominator only when its
code is really gone from the product root being measured. A change that deletes a healer adds its row to that list
in the same commit; an unlisted deletion stays in the denominator as unmeasured and fails the exact pin in
`tests/test_eval_e2e.py`.

In `--healers-off` each non-tier-D healer listed in `IDENTITY_CONTRACTS` (`stackvend_eval/healer_probe.py`) returns
what the real function returns when it changes nothing (its str argument, `dict(files)`, `(dict(files), [])`,
`(text, [])`, `(text, False)`, `None`, or `{}` for the env-var extractor). Each contract is checked against the live
signature at install; a healer without one (or with a stale one) keeps running and is reported per target
(`healers_off`), and `tests/test_eval_healers_off_contracts.py` compares every stub with the real function. With
healers off later prompts can differ from the recording: those calls are served by the (site, ordinal) fallback and
the run is counted as `replay-diverged`; a call with no fallback invalidates the run (`replay_miss`).

Replay provenance (F9): the architect, red-team and lead requests embed the example spec, so a replay must send the
recorded spec, not the checkout's `documentation/examples`. Recordings store `spec_text`/`spec_sha256` in the cassette
meta (and each call's hashed `request`); cassettes recorded before that are matched exactly by `(frozen_now, model)`
in `config/cassette_spec_pins.json` and their spec is read from git at the pinned commit (a clone without that
commit, e.g. a shallow checkout, refuses such a replay with a reason; recordings with `spec_text` need no history).
`--examples-sha` overrides both. In `replay-strict` a spec whose sha256 differs from the recording fails the run before launch
(`replay_spec_mismatch`). Every run row in `summary.json` and the SCOREBOARD "Replay provenance" table shows
`served` (exact replay / site-ordinal fallback / miss / backend), the not-exact sites and the spec source.
`--dump-llm-requests` writes each normalized request to `runs/<key>/llm_requests.jsonl` for diffing.

## Commands

```bash
pip install --target eval/.deps -r eval/requirements.txt          # only if the venv lacks the AGENTS.md Setup requirements (python-hcl2, pyflakes)
python -m eval.run_examples --warm-tofu-mirror                       # once, owner-approved: downloads providers, writes MANIFEST.sha256
python -m eval.run_examples --llm synthetic --model gemini-3.8-flash --examples 01-09 --runs 1   # offline self-test
python -m eval.run_examples --llm replay-strict --model <m> --cassettes eval/cassettes/<id> --product-root <checkout>
python -m eval.compare eval/results/<baseline-id> eval/results/<candidate-id>
python -m eval.tools.build_targets --check                           # maintainers: HEALERS.md -> config/healer_targets.json + inventory_line_digests.json
```

### Dry run of any spec (`--spec-file`, `--report html`; FD-4BN Phase 0)

```bash
python -m eval.run_examples --llm synthetic --model gemini-3.8-flash --spec-file my-spec.md --runs 1 --report html
```

`--spec-file PATH` runs one spec instead of the catalog (exclusive with `--examples`; with neither, `--examples`
resolves to `01-09` after parsing, so existing invocations are unchanged). The file must be a regular file, UTF-8,
non-empty and at most 200 KB; `--product-id` (default `dryrun-<sha256[:8]>`) must have the GCP project-id shape. The
run uses one catalog entry `id: "spec"`: run key `spec-r<n>`, cassette `spec-r<n>.jsonl`, trace id `eval-sp-r<n>`.
Refused with `--baseline` and `--examples-sha`. The manifest records `spec_source`, `spec_sha256` and `product_id`,
never the path or text. A replay (`replay-strict` or `replay-then-live`) always sends the file; a recording of
different text, or one with no recorded `spec_sha256`, fails as `replay_spec_mismatch` before launch and before any
token is minted (record it with `--spec-file`; `synthetic --cassettes DIR` does that at $0 for mechanics). The file is
read as bytes once (CRLF kept; the hash is of the bytes sent) and a file changed during the invocation is refused. A
run with any call served by site/ordinal fallback, or with `spec_match` False, gets `INCONCLUSIVE:replay_diverged`.
`--report html` (default `none`) writes `results/<id>/report.html`: the per-run verdict
(`stackvend_eval/verdict.py`, rules in its docstring) and stage cards, static and escaped (no scripts, CSP, file names and
sizes only). Operator how-to and the honest OSS story: [`documentation/test-a-spec-locally.md`](../documentation/test-a-spec-locally.md).

### Live runs (spend money; owner approval required)

```bash
export STACKVEND_EVAL_VERTEX_PROJECT=<your dev project>              # never committed
python -m eval.run_examples --llm record --model <model> --examples 01 --runs 1 \
    --budget-usd 2 --run-cap 2 --parallel 1 --accept-unverified-prices          # calibration
python -m eval.run_examples --llm record --model <model> --examples 01-09 --runs 3 \
    --budget-usd 25 --run-cap 3 --parallel 3 --accept-unverified-prices \
    --product-root <checkout pinned to the baseline SHA> --baseline             # baseline
```

Run live commands from a normal shell: the parent needs ADC to mint the access token.
Optional least privilege (default OFF): add `--impersonate-service-account <sa-email>` to either command and the
parent mints each child's token for that service account (60-min lifetime, cloud-platform scope via
`google.auth.impersonated_credentials`) instead of handing the child the owner's ADC token. Intended SA: only
`roles/aiplatform.user` on the Vertex project; the owner needs `roles/iam.serviceAccountTokenCreator` on it.

## Real-provider plan tests (`tests/test_iap_gate_known_member.py`)

Three tests make a real `tofu plan` of the platform's root with the production provider set, against a local fake
Resource Manager and behind a dead proxy (no credentials, no GCP call). They skip unless they find an OpenTofu binary
and a filesystem mirror of that set: `STACKVEND_WORKLOAD_TOFU` (OpenTofu 1.9.0, the workload engine; default `tofu` on
`PATH`) and `STACKVEND_WORKLOAD_TOFU_MIRROR` (default `eval/.tofu-mirror-prod`). The mirror holds google and
google-beta 6.35.0, kubernetes 2.36.0 and random 3.7.1 (`mcp-servers/terraform/provider_allowlist.py`), laid out like
`eval/.tofu-mirror` with its own `MANIFEST.sha256`. It is not `eval/.tofu-mirror`, which holds the oracle set (google
6.50.0). The replay's `--tofu-mirror ... --provider-set production` uses the same mirror. Filling one downloads
providers, so it needs the owner's approval, like `--warm-tofu-mirror`.

## Never commit

`eval/results/`, `eval/cassettes/`, `eval/.deps/`, `eval/.tofu-mirror/`, `eval/.tofu-mirror-prod/` (all gitignored). Only `eval/baseline/*`
(aggregates, no generated code or prompts) is committed.

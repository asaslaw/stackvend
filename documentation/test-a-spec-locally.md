# Test a spec locally (dry run)

Before you submit a workload, you can run your spec through StackVend's real generation pipeline on your own machine
and get a verdict: would the pipeline produce infrastructure code and application code that pass its own gates and
`tofu validate`? This is an operator command-line tool built on the examples eval harness (`eval/`). It **creates
nothing**: no Google Cloud project, no repository, no commit or pull request, no Firestore document, no cloud
resource.

> **What a verdict means.** `WOULD_SUCCEED` means the pipeline would succeed **through validation**. It never means
> "will deploy". See [What this does not check](#what-this-does-not-check).

## How it stays side-effect free

Each run happens in a separate, guarded Python child process:

- Credentials depend on the mode. In `synthetic` and `replay-strict` the child has **no credentials and no token**:
  `GOOGLE_APPLICATION_CREDENTIALS` points at a file that does not exist, `HOME` and the gcloud config directory are
  empty, and `PROJECT_ID` is empty. In `record`, `live` and `replay-then-live` the child has the same empty
  environment but receives **one short-lived access token** on stdin, used only by the harness's metered Vertex AI
  client. By default that token comes from your Application Default Credentials (your own identity, with whatever
  your account can do); pass `--impersonate-service-account <sa>` with a service account that can only call Vertex AI
  to limit it.
- An in-process guard refuses **every** process creation, every gRPC channel, every socket (except the Vertex AI
  host in the live modes), the Firestore, Cloud Storage, Pub/Sub and Secret Manager client constructors, and
  `google.auth.default()`.
- Before any product code is imported, a canary of more than 20 probes must each be blocked by the guard, or the run
  stops before it spends anything.
- The commit is captured inside the product's own `commit_and_open_pr` before it would contact a Git server, so
  nothing is pushed.

Details: [`eval/README.md`](../eval/README.md), section "Isolation model".

## Prerequisites

- A Python 3.12 virtual environment with the gateway's requirements, as in the [developer guide](developer-guide.md).
- The harness's own parsers, installed next to the harness (not into the venv):
  `pip install --target eval/.deps -r eval/requirements.txt`.
- For a `tofu validate` verdict: the `tofu` binary and an offline provider mirror. Build the mirror once with
  `python -m eval.run_examples --warm-tofu-mirror` (this downloads the providers). Without `tofu` or the mirror, a run
  that commits gets `INCONCLUSIVE:validator_unavailable` instead of a verdict.
- Run every command from the repository root.

## Three ways to run it

### 1. Synthetic: no Google Cloud project, no cost

```bash
python -m eval.run_examples --llm synthetic --model gemini-3.8-flash \
    --spec-file my-spec.md --runs 1 --report html
```

This is what you get without a Vertex AI project. Be clear about what it tests: the synthetic backend answers every
model call with schema-valid responses built from the product's deterministic fallbacks for the architect, red team
and lead plan, and minimal eval-only junior files. It exercises the
pipeline's mechanics (every stage, every gate, the validators and the scorer) on your spec text, but it is **not**
real model output, so the generated workload says little about how a model would implement your spec. Synthetic
spend in the report is notional; nothing is billed.

There is no "replay for free" option for a new spec out of the box: replay needs a recording of that spec, and
StackVend never ships recordings (see [Recordings](#recordings-cassettes-never-commit-or-share)).

### 2. Your own Vertex AI project: record once, then replay at $0

```bash
export STACKVEND_EVAL_VERTEX_PROJECT=<your dev project>      # never committed
python -m eval.run_examples --llm record --model <model> --spec-file my-spec.md --runs 1 \
    --budget-usd 3 --run-cap 3 --parallel 1 --cassettes eval/cassettes/my-spec --report html
python -m eval.run_examples --llm replay-strict --model <model> --spec-file my-spec.md --runs 1 \
    --cassettes eval/cassettes/my-spec --report html                # $0, deterministic
```

`record` makes real, budgeted model calls in your project (the parent mints a short-lived access token from your
Application Default Credentials, or from `--impersonate-service-account <sa>`, which we recommend, and hands it only
to the harness's metered client). After that, `replay-strict` replays the recording for $0, which is useful for
re-checking the same spec against a newer StackVend checkout (`--product-root <checkout>`). A replay
(`replay-strict` or `replay-then-live`) always sends the spec file you pass; if it differs from the recorded one, or
the recording has no recorded spec hash, the run stops before launch, and before any token is minted, with
`INCONCLUSIVE:replay_spec_mismatch`. If any model call of a replay is answered by a fallback match instead of an
exact one, the verdict is `INCONCLUSIVE:replay_diverged`: that answer was recorded for a different request.

### 3. Live with caps

```bash
python -m eval.run_examples --llm live --model <model> --spec-file my-spec.md --runs 3 \
    --budget-usd 9 --run-cap 3 --report html
```

Live mode samples the model every time and records nothing. `--budget-usd` is required (at most $25 unless
`--budget-override`), `--run-cap` caps each run, and every call reserves its worst-case price before it is sent. Use
`--runs N` to see the spread: one run is a sample, not a guarantee.

`record` and `live` refuse to start while the model's row in `eval/config/pricing.json` is not marked verified: check
the prices against the current Vertex AI price list and set `verified`, or pass `--accept-unverified-prices` knowingly
(the rows hold ceiling prices, twice the list price).

## Options for a spec run

| Option | Meaning |
| :-- | :-- |
| `--spec-file PATH` | The spec to run (UTF-8, not empty, at most 200 KB). Exclusive with `--examples`. |
| `--product-id ID` | Product id used inside the generated code. Default `dryrun-` plus the first 8 hex digits of the spec's sha256. Must look like a Google Cloud project id: 6 to 30 characters, lowercase letters, digits and hyphens, starting with a letter and not ending with a hyphen. |
| `--report html` | Also write `report.html` next to `SCOREBOARD.md`. |
| `--spec-mode form-prompt` | Send only the spec's "Form Submission Prompt" section, if it has one. |

A spec run refuses `--baseline` (a baseline is the bundled 9-example corpus) and `--examples-sha` (it pins the
bundled examples in git). Results are written to `eval/results/<id>/` (gitignored): `summary.json`,
`manifest.json`, `SCOREBOARD.md` and, with `--report html`, `report.html`. The manifest records the spec's sha256 and
product id, never the spec's path or text.

Where the spec text goes: it is copied to `eval/results/<id>/runs/spec-r<n>/spec.md` and
`eval/results/<id>/runs/spec-r<n>/child_config.json`, and into any recording (`--cassettes`); in `record`, `live` and
`replay-then-live` it is sent to Vertex AI. The file is read with your own permissions and symbolic links are
followed (the tool does not refuse them), so pass only the spec. It is read once as bytes (line endings are kept,
and the sha256 is of exactly the bytes sent); if the file changes while the command runs, the run stops with
`--spec-file changed since start`.

## The report

`report.html` is a static page: no JavaScript, no external resources, a Content Security Policy that blocks
everything except its own inline styles, and every value escaped (model output can contain anything). It shows:

- the verdict for each run, with the reason and any warnings;
- one card per stage: architect, compliance, developer (with the committed file **names and sizes**; file contents
  are never embedded), pre-commit gate, gatekeeper, `tofu validate` with the first 20 diagnostics, invariants, and
  the isolation attempts the guard blocked;
- the typed validation diagnostics when the product reports them;
- a matrix of all runs and "k/N would succeed";
- the two boxes below, verbatim.

## Verdicts

| Verdict | Meaning |
| :-- | :-- |
| `WOULD_SUCCEED` | The pipeline committed a tree that passed every gate and `tofu validate`. Through validation only. |
| `WOULD_FAIL_AT:architect` / `:compliance` / `:developer` | That stage raised an error. |
| `WOULD_FAIL_AT:developer` (typed) | The developer stage stopped with typed validation diagnostics (error class and codes shown). |
| `WOULD_FAIL_AT:precommit` | The pre-commit gate rejected the generated tree. |
| `WOULD_FAIL_AT:gatekeeper` | The gatekeeper (synthesis verifier) rejected the tree. |
| `WOULD_FAIL_AT:deploy` | The gates passed a tree that fails `tofu validate` (a gate false-pass): a real run would fail at deploy time. |
| `INCONCLUSIVE:validator_unavailable` | The tree was committed but `tofu validate` did not run (no `tofu`, no mirror, or `--skip-score`). |
| `INCONCLUSIVE:isolation` | The isolation canary failed; the run stopped before spending. |
| `INCONCLUSIVE:llm_fallback` | A deterministic fallback ran instead of a model call; the run does not show model behaviour. |
| `INCONCLUSIVE:replay_miss` / `:replay_spec_mismatch` | The recording does not cover this run, or the spec changed since it was recorded (or the recording has no recorded spec hash). |
| `INCONCLUSIVE:replay_diverged` | A replay answered at least one model call by a fallback match (a response recorded for a different request), or the spec differs from the recorded one. The run measured someone else's model output. |
| `INCONCLUSIVE:budget_exceeded` / `:not_run_budget` / `:timeout` / `:harness_error` / `:unmetered_llm_client` | The run was stopped by a cap, the clock, a harness fault, or a product attempt to build its own model client. |
| `INCONCLUSIVE:canary_only` | `--canary-only`: the pipeline was not run. |

Warnings (invariant violations, blocked isolation attempts) never change a verdict. Replay divergence is listed as a
warning too, but it does change the verdict, to `INCONCLUSIVE:replay_diverged`.

## What this does not check

- Plan-time API errors: APIs not enabled, invalid machine types or regions for the org, name collisions, provider
  read-time lookups (data sources).
- Quotas and capacity (CPU, IPs, GKE), billing account state.
- Org policies (domain restricted sharing, allowed regions, CMEK required, external IP). The policy harvest step is
  skipped; compliance uses only the spec's ingress intent, and the compliance profile is `STANDARD` (the harness
  passes no explicit `compliance_profile`; spec words never choose one).
- IAM propagation, Workload Identity Federation, Cloud Build buildpack success, container boot, health checks,
  runtime behaviour, QA tests, IAP/OAuth configuration.
- LLM non-determinism: one dry run is a sample, not a guarantee. A real run makes new LLM calls; N repeats show the
  spread. Synthetic mode uses the product's deterministic fallbacks for the architect, red team and lead plan, and
  minimal eval-only junior files, not a model.

## How this differs from a real run

- No FinOps cost check: the workflow's FinOps stage is not run.
- Compliance runs in-process (the deployed compliance server's engine, called locally), not on the compliance MCP
  server.
- Platform settings are pinned to the code defaults (the model under test replaces every agent model); an install's
  Firestore settings, junior prompts and directives are not read.
- No vended project, no repository, no authorized users: project id, branch and IAM members use the fallbacks; no
  custom modules or bundles; IPAM is not claimed.
- Nothing is created: no project, repository, commit, pull request, Firestore document or cloud resource. In
  `synthetic` and `replay-strict` the generation child has no credentials and no token. In `record`, `live` and
  `replay-then-live` it receives one short-lived access token on stdin, used only by the harness's metered Vertex AI
  client: your Application Default Credentials unless you pass `--impersonate-service-account` (recommended, with a
  service account that can only call Vertex AI). In every mode a guard refuses every other network, process and
  cloud-client call. (The report prints the line for the mode it ran in.)

## Recordings (cassettes): never commit or share

A recording holds the **full prompts** sent to the model, including your spec and StackVend's internal prompts.
Keep recordings in a gitignored directory (`eval/cassettes/` is ignored), never commit them, and never share them.
The same applies to `eval/results/` and to `--dump-llm-requests` output.

## Checklist: is my dry run done?

- [ ] The command finished and printed `wrote .../report.html`.
- [ ] `report.html` shows a verdict for every run (`k/N would succeed` at the top).
- [ ] For a `tofu validate` verdict, `tofu` and the provider mirror were available (otherwise the verdict is
      `INCONCLUSIVE:validator_unavailable`).
- [ ] Every run's canary passed (no `INCONCLUSIVE:isolation`).
- [ ] For model behaviour, the mode was `record`, `replay-strict` of your own recording, or `live` (synthetic shows
      pipeline mechanics only).
- [ ] You read both boxes: a `WOULD_SUCCEED` is "through validation", not "will deploy".
- [ ] No recording or result directory was committed or shared.

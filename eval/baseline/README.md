# FD-30 committed baseline

Empty until the owner approves the first live baseline (see `eval/README.md`, "Live runs").

A baseline invocation with `--baseline` writes three small files here:

- `summary.json`: aggregates, per-run rows (no generated code, no prompts), healer IDs and counts
- `SCOREBOARD.md`: the human-readable scoreboard
- `manifest.json`: product/harness SHAs, model, fallbacks, prices, caps, frozen date, settings hash

Never commit `eval/results/` or `eval/cassettes/`: they hold generated code and full internal prompts.

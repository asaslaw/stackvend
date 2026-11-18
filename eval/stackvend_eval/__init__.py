"""StackVend examples eval harness (FD-30).

Runs the real generation pipeline in-process on documentation/examples/01-09 and scores the output.
See eval/README.md and docs/implemented/wave1-lane7-eval-harness-plan.md (+ wave1-lane7-plan-red-team.md).

The package name avoids shadowing the `eval` builtin. Modules in this package never import product code at
module import time; product modules are only imported inside the guarded generation child (run_child.py).
"""

SCHEMA_VERSION = 1

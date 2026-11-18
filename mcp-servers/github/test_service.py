"""
mcp-github-toolserver tests live in the hermetic root suite: tests/test_fd4l_mcp_github.py (FD-4L / FD27-17).

The tests that were here drove the old any-repository API (`repo_name` only, retried non-idempotent writes, head
branch always deleted on merge). Every call now takes `product_id` and acts only on the workload's own repository.
"""

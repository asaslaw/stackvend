"""
mcp-gcloud-server tests live in the hermetic root suite: tests/test_fd4l_mcp_gcloud.py (FD-4L / FD27-05).

The tests that were here exercised the removed free-form CLI executor (substring denylist, `--project` default to
the host project, MOCK_SUCCESS on a missing binary). The server is now typed REST tools only; see executor.py.
"""

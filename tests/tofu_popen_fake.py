"""FD-4AQ W3: `TerraformService._run_subprocess` starts OpenTofu with `subprocess.Popen` (time limit, SIGINT, then
SIGKILL). Tests that fake the engine with a `subprocess.run`-shaped function adapt it with `popen_from_run`."""
import subprocess


class _FakeProc:
    pid = None   # never a real process group (the service never signals a pid it does not own)

    def __init__(self, completed: subprocess.CompletedProcess):
        self.returncode = completed.returncode
        self._out = completed.stdout
        self._err = completed.stderr

    def communicate(self, timeout=None):
        return self._out, self._err


def popen_from_run(run):
    """A `subprocess.Popen` stand-in that calls `run(cmd, cwd=..., env=..., **other Popen kwargs)` once and serves
    its CompletedProcess."""
    def _popen(cmd, **kw):
        return _FakeProc(run(cmd, **kw))
    return _popen

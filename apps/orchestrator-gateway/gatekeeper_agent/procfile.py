"""Procfile parsing (FD-4AD RT F4) shared by the developer stage's V3c container contract (developer_agent/validators/container.py)
and the gatekeeper's add-only requirements contract (gatekeeper_agent/requirements_contract.py). One parser, so the
two can never disagree on what a Procfile launches (FD-4AD RT F4, Gate 5 single source of truth).

Exact rules only (no regex, no substring tests):
* Procfile line  = `<process>: <command>` (blank and `#` lines skipped; a space in the process name is not a process).
* command        = `shlex.split`; `unwrap` then removes exact wrapper tokens before the launcher: a leading `exec`,
                   `env` (and `env`'s `NAME=value` operands), shell assignment prefixes `NAME=value` (NAME an
                   identifier), and `sh|bash [-e|-x|...] -c "<command>"` (the `-c` argument is split again). Anything
                   else is left as written (a launcher this module does not know is `unknown`, i.e. not judged).
* launchers      = `uvicorn` / `gunicorn` / `hypercorn` by executable basename, `python[3] [-flags] -m <server>` and
                   `python[3] <file>.py`.
"""
from __future__ import annotations

import posixpath
import shlex
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

ASGI_SERVERS = frozenset({"uvicorn", "gunicorn", "hypercorn"})
PYTHONS = frozenset({"python", "python3"})
# options of each server that take a separate value token (so the value is never mistaken for the app target)
VALUE_OPTIONS: Dict[str, frozenset] = {
    "uvicorn": frozenset({"--host", "--port", "--uds", "--fd", "--workers", "--loop", "--http", "--ws", "--lifespan",
                          "--interface", "--env-file", "--log-config", "--log-level", "--root-path",
                          "--limit-concurrency", "--backlog", "--limit-max-requests", "--timeout-keep-alive",
                          "--timeout-graceful-shutdown", "--ssl-keyfile", "--ssl-certfile", "--ssl-keyfile-password",
                          "--ssl-version", "--ssl-cert-reqs", "--ssl-ca-certs", "--ssl-ciphers", "--app-dir",
                          "--reload-dir", "--reload-include", "--reload-exclude", "--reload-delay",
                          "--forwarded-allow-ips", "--header", "--h11-max-incomplete-event-size",
                          "--ws-max-size", "--ws-max-queue", "--ws-ping-interval", "--ws-ping-timeout"}),
    "gunicorn": frozenset({"-b", "--bind", "-w", "--workers", "-k", "--worker-class", "-t", "--timeout", "-c",
                           "--config", "--threads", "--chdir", "--log-level", "--access-logfile", "--error-logfile",
                           "--graceful-timeout", "--keep-alive", "--max-requests", "--max-requests-jitter", "-n",
                           "--name", "--pythonpath", "-e", "--env", "--worker-connections", "--backlog", "-u", "-g",
                           "--user", "--group", "--forwarded-allow-ips", "--limit-request-line"}),
    "hypercorn": frozenset({"-b", "--bind", "-w", "--workers", "-k", "--worker-class", "-c", "--config",
                            "--root-path", "--log-level", "--access-logfile", "--error-logfile", "--keep-alive",
                            "--graceful-timeout", "--backlog", "--certfile", "--keyfile"}),
}
PORT_OPTIONS: Dict[str, frozenset] = {"uvicorn": frozenset({"--port"}), "gunicorn": frozenset({"-b", "--bind"}),
                                      "hypercorn": frozenset({"-b", "--bind"})}
GUNICORN_DEFAULT_BINDS_PORT = frozenset({"gunicorn"})   # gunicorn binds 0.0.0.0:$PORT when PORT is set and no -b
SHELLS = frozenset({"sh", "bash", "dash"})
SHELL_SEPARATORS = frozenset({"&&", "||", ";"})


def is_port_ref(token: str) -> bool:
    """Exactly `$PORT`, `${PORT}` or `${PORT:-<digits>}`."""
    if token in ("$PORT", "${PORT}"):
        return True
    head, tail = "${PORT:-", "}"
    return token.startswith(head) and token.endswith(tail) and token[len(head):-len(tail)].isdigit()


def _bind_port_ref(value: str) -> bool:
    """`host:PORTREF` (the host part may be empty)."""
    for form in ("$PORT", "${PORT}"):
        if value.endswith(":" + form):
            return True
    i = value.find(":${PORT:-")
    return i >= 0 and is_port_ref(value[i + 1:])


def parse_procfile(text: str) -> Tuple[Dict[str, str], int]:
    """{process: command}, number of non-blank lines that are not `name: command`."""
    procs: Dict[str, str] = {}
    bad = 0
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, cmd = line.partition(":")
        if not sep or not name.strip() or not cmd.strip() or " " in name.strip():
            bad += 1
            continue
        procs.setdefault(name.strip(), cmd.strip())
    return procs, bad


@dataclass
class Launch:
    kind: str                       # "server" | "python_file" | "unknown"
    server: Optional[str] = None    # uvicorn / gunicorn / hypercorn
    target: Optional[str] = None    # "module[:attr]" or a file path
    port_ok: Optional[bool] = None  # None = not judged
    app_dir: str = ""


def _is_assignment(token: str) -> bool:
    name, eq, _ = token.partition("=")
    return bool(eq) and name.isidentifier()


def unwrap(argv: List[str]) -> List[str]:
    """Strip the exact wrapper tokens in front of the real command (see the module docstring). Returns the argv the
    launcher starts at; an unsplittable `sh -c` argument leaves the argv as written."""
    out = list(argv)
    for _ in range(8):   # bounded: each pass removes at least one wrapper
        if not out:
            return out
        head = posixpath.basename(out[0])
        if head == "exec":
            out = out[1:]
        elif head == "env":
            rest = out[1:]
            while rest and _is_assignment(rest[0]):
                rest = rest[1:]
            out = rest
        elif _is_assignment(out[0]):
            out = out[1:]
        elif head in SHELLS:
            rest = out[1:]
            while rest and rest[0].startswith("-") and rest[0] != "-c":
                rest = rest[1:]
            if len(rest) >= 2 and rest[0] == "-c":
                try:
                    out = shlex.split(rest[1])
                except ValueError:
                    return out
            else:
                return out
        else:
            return out
    return out


def command_segments(argv: List[str]) -> List[List[str]]:
    """The unwrapped simple commands of one Procfile command, split at the exact shell tokens `&&`, `||`, `;`."""
    segments: List[List[str]] = [[]]
    for tok in unwrap(argv):
        if tok in SHELL_SEPARATORS:
            segments.append([])
        else:
            segments[-1].append(tok)
    return [unwrap(seg) for seg in segments if seg]


def parse_command(argv: List[str]) -> Launch:
    argv = unwrap(argv)
    if not argv:
        return Launch("unknown")
    head = posixpath.basename(argv[0])
    if head in PYTHONS:
        rest = argv[1:]
        while rest and rest[0].startswith("-") and rest[0] != "-m":
            rest = rest[1:]   # interpreter flags (-u, -O, ...)
        if len(rest) >= 2 and rest[0] == "-m":
            if rest[1] in ASGI_SERVERS:
                return parse_command(rest[1:])
            return Launch("unknown")
        if rest and rest[0].endswith(".py"):
            return Launch("python_file", target=rest[0])
        return Launch("unknown")
    if head not in ASGI_SERVERS:
        return Launch("unknown")
    value_opts, port_opts = VALUE_OPTIONS[head], PORT_OPTIONS[head]
    target: Optional[str] = None
    port_values: List[str] = []
    app_dir = ""
    toks = argv[1:]
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.startswith("-"):
            opt, eq, val = t.partition("=")
            if not eq and opt in value_opts:
                val = toks[i + 1] if i + 1 < len(toks) else ""
                i += 1
            if opt in port_opts:
                port_values.append(val)
            if opt == "--app-dir":
                app_dir = val
        elif target is None:
            target = t
        i += 1
    if head == "uvicorn":
        port_ok = bool(port_values) and all(is_port_ref(v) for v in port_values)
    elif head in GUNICORN_DEFAULT_BINDS_PORT and not port_values:
        port_ok = True
    else:
        port_ok = bool(port_values) and any(_bind_port_ref(v) for v in port_values)
    return Launch("server", server=head, target=target, port_ok=port_ok, app_dir=app_dir)

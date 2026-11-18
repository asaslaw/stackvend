"""QA-REPAIR-MISSING-MODULE-SETUP: the QA sandbox job's own pytest plugin (platform-owned; never part of a workload).

The job (`sandbox_job.run_service`) copies this file into the service's fresh QA venv (trusted, after pip) and loads it
for the pytest step only, through `PYTEST_PLUGINS` (pytest reads it once, autoload off or not; row L3-PRB-f). Nothing
is added to pytest's argv. At import the plugin removes that variable again, so the code under test sees exactly the
environment it saw before, and a pytest it starts itself does not load this plugin.

What it does: when collecting a node or setting a test up raises (pytest calls `pytest_exception_interact` for every
such error it reports, not only with --pdb), it takes the first ModuleNotFoundError on the exception's chain (explicit
cause, else implicit context, at most 32 links: the import smoke's own walk, `sandbox_job.IMPORT_SMOKE_BY_ARGV`) and
writes its `name` attribute, the module Python could not find, to `<junit path>.missing-module` (create-only: the
first one wins). The exception's own attribute, never the traceback text. It returns nothing and changes no report,
outcome or output; without a ModuleNotFoundError it writes nothing at all.

The code under test runs in the same process and could write that file itself, so the job reads it as untrusted
(`sandbox_job.missing_module_fact`) and the gateway maps it only through its closed catalog.
"""
import os

PLUGINS_ENV = "PYTEST_PLUGINS"
FACT_SUFFIX = ".missing-module"   # parity: sandbox_job.MISSING_MODULE_FACT_SUFFIX
MAX_CHAIN_LINKS = 32
FACT_PHASES = ("collect", "setup")

# Do No Harm: the variable that loaded this plugin is the job's, not the workload's (exact value only).
if os.environ.get(PLUGINS_ENV) == __name__:
    del os.environ[PLUGINS_ENV]


def missing_module_name(exc):
    """The `name` of the first ModuleNotFoundError on `exc`'s chain, or None."""
    e, n = exc, 0
    while e is not None and n < MAX_CHAIN_LINKS:
        if isinstance(e, ModuleNotFoundError) and isinstance(e.name, str):
            return e.name
        e, n = (e.__cause__ if e.__cause__ is not None else None if e.__suppress_context__ else e.__context__), n + 1
    return None


def pytest_exception_interact(node, call, report):
    if getattr(call, "when", None) not in FACT_PHASES or getattr(call, "excinfo", None) is None:
        return None
    try:
        name = missing_module_name(call.excinfo.value)
        xmlpath = node.config.getoption("xmlpath", None)
        if name is None or not xmlpath:
            return None
        with open(os.fspath(xmlpath) + FACT_SUFFIX, "x", encoding="utf-8") as f:
            f.write(name)
    except Exception:  # noqa: BLE001 - a fact that cannot be written is simply absent (today's report)
        pass
    return None

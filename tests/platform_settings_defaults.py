"""Row SWARM-TOK-1: an autouse fixture that serves the compile-time PlatformSettings defaults from the settings cache.

Since the lead orchestrator and the swarm dispatcher really read the platform settings (before, the read was a
swallowed TypeError), unit tests that drive them would otherwise try a real Firestore client (blocked by the FD-08
guard, counted by the Firestore ratchet) and then fall back to the same defaults. Import it into a test module to
activate it there:

    from platform_settings_defaults import default_platform_settings  # noqa: F401  (autouse fixture)

A test that needs other values patches `shared.settings.get_platform_settings` as before; a test that reads with
`force_refresh=True` bypasses the cache as before. The cache is restored after every test."""
import importlib

import pytest


@pytest.fixture(autouse=True)
def default_platform_settings(monkeypatch):
    settings = importlib.import_module("shared.settings")  # the module the product's `from shared.settings` gets
    monkeypatch.setattr(settings, "_SETTINGS_CACHE", settings.PlatformSettings())
    monkeypatch.setattr(settings, "_LAST_FETCH_TIME", float("inf"))
    yield

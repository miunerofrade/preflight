"""Prevent an accidentally unmocked SDK client from spending credits in pytest."""
import pytest
from clocked_sdk import Clocked


@pytest.fixture(autouse=True)
def forbid_live_clocked(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Live Clocked calls are disabled in tests; use a fake or ReplayClient.")

    monkeypatch.setattr(Clocked, "_send", blocked)

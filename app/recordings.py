"""Explicit synthetic-case recording and strict, network-free SDK replay."""
from __future__ import annotations

import copy
import time
from typing import Any


class RecordingClient:
    """Only record method bodies and selected billing metadata, never auth headers."""

    def __init__(self, client: Any, *, max_calls: int = 64, max_credits: int = 1500):
        self.client = client
        self.calls: list[dict] = []
        self.credits = 0
        self.max_calls = max_calls
        self.max_credits = max_credits

    def __getattr__(self, method: str):
        if method not in {"injection", "pii", "script", "decide"}:
            raise AttributeError(method)

        def call(**request):
            if len(self.calls) >= self.max_calls or self.credits >= self.max_credits:
                raise RuntimeError("Recording budget reached; no further requests were sent.")
            started = time.perf_counter()
            response = getattr(self.client, method)(**request)
            metadata = {key: getattr(response, key, None) for key in
                        ("status", "model_ms", "credits", "cost_usd", "attempts")}
            metadata["wall_ms"] = round((time.perf_counter() - started) * 1000)
            self.credits += metadata["credits"] or 0
            self.calls.append({"method": method, "request": copy.deepcopy(request),
                               "response": copy.deepcopy(dict(response)), "metadata": metadata})
            return response

        return call


class ReplayClient:
    """Fail on changed requests, missing calls or unexpected calls; no live fallback."""

    def __init__(self, calls: list[dict]):
        self.calls = calls
        self.index = 0

    def __getattr__(self, method: str):
        def call(**request):
            if self.index >= len(self.calls):
                raise AssertionError(f"Unrecorded call: {method}")
            recorded = self.calls[self.index]
            assert recorded["method"] == method, f"Call {self.index}: expected {recorded['method']}, got {method}"
            assert recorded["request"] == request, f"Call {self.index} ({method}): request changed"
            self.index += 1
            return copy.deepcopy(recorded["response"])

        return call

    def assert_complete(self) -> None:
        assert self.index == len(self.calls), f"{len(self.calls) - self.index} recorded calls were not used"

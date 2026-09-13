"""Tests for FallbackProvider failover.

When the primary provider fails, the next
provider in the chain serves the call, and the failover is recorded as a
STRUCTURED field (ProviderResult.used_fallback / TraceEvent.used_fallback),
never inferred from a substring of the model name.
"""
import pytest

from pramagent import Pramagent
from pramagent.providers import (BaseProvider, FallbackProvider, MockProvider,
                                 ProviderResult)


class FailingProvider(BaseProvider):
    name = "failing"

    def __init__(self, exc: Exception | None = None):
        self.exc = exc or RuntimeError("upstream 500")
        self.calls = 0

    async def complete(self, prompt: str, **kwargs) -> ProviderResult:
        self.calls += 1
        raise self.exc


@pytest.mark.asyncio
async def test_primary_success_is_not_marked_fallback():
    fb = FallbackProvider([MockProvider(model="primary"), MockProvider(model="backup")])
    res = await fb.complete("hello")
    assert res.model == "primary"
    assert res.used_fallback is False


@pytest.mark.asyncio
async def test_primary_failure_fires_fallback_with_structured_field():
    primary = FailingProvider()
    fb = FallbackProvider([primary, MockProvider(model="backup")])
    res = await fb.complete("hello")
    assert primary.calls == 1
    assert res.used_fallback is True          # structured, not substring
    assert res.text


@pytest.mark.asyncio
async def test_second_fallback_fires_when_first_two_fail():
    fb = FallbackProvider([
        FailingProvider(), FailingProvider(), MockProvider(model="last-resort"),
    ])
    res = await fb.complete("hello")
    assert res.used_fallback is True
    assert "last-resort" in res.model


@pytest.mark.asyncio
async def test_exhaustion_raises_with_last_error():
    fb = FallbackProvider([
        FailingProvider(RuntimeError("first down")),
        FailingProvider(RuntimeError("second down")),
    ])
    with pytest.raises(RuntimeError, match="second down"):
        await fb.complete("hello")


def test_empty_provider_list_rejected():
    with pytest.raises(ValueError):
        FallbackProvider([])


@pytest.mark.asyncio
async def test_trace_used_fallback_comes_from_structured_field():
    """The trace flag must follow ProviderResult.used_fallback even when the
    model name happens to contain the word 'fallback' (or not contain it)."""

    class TrickyNameProvider(BaseProvider):
        # model name contains 'fallback' but this IS the primary — the old
        # substring check would have mislabeled this call
        name = "tricky"

        async def complete(self, prompt: str, **kwargs) -> ProviderResult:
            return ProviderResult(text="ok", model="fallback-tuned-v2")

    armor = Pramagent(provider=TrickyNameProvider())
    r = await armor.run("hi", tenant_id="t", session_id="s")
    assert r.trace.used_fallback is False


@pytest.mark.asyncio
async def test_pipeline_records_fallback_in_trace():
    armor = Pramagent(provider=FallbackProvider([
        FailingProvider(), MockProvider(model="backup"),
    ]))
    r = await armor.run("hi", tenant_id="t", session_id="s")
    assert r.blocked is False
    assert r.trace.used_fallback is True

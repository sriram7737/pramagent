"""
SEC-2026-06-15: configurable escalate_policy.

Verdict.ESCALATE used to be recorded in the trace and otherwise ignored. It is
now routed by escalate_policy, per stage ("pre" = input, "post" = output), with
one of "log" | "hitl" | "block". Default is "log" (record and continue) so
adding an ESCALATE rule never silently starts gating traffic.
"""
import asyncio

import pytest

from pramagent import EscalatePolicy, Pramagent, Verdict
from pramagent.layers import HITLLayer, Rule, SafetyLayer
from pramagent.providers import MockProvider


def run(coro):
    return asyncio.run(coro)


class CountingProvider(MockProvider):
    """MockProvider that records whether/how often it was called, so a test can
    prove a pre escalation short-circuited *before* the model ran."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = 0

    async def complete(self, prompt, **kwargs):
        self.calls += 1
        return await super().complete(prompt, **kwargs)


# Input rule fires on the prompt; output rule fires on the model's reply.
ESC_PRE = [Rule("esc_in", Verdict.ESCALATE, pattern=r"transfer \$\d+")]
ESC_POST = [Rule("esc_out", Verdict.ESCALATE, pattern=r"escalate-me")]


async def _silent(action, ctx):
    return None


async def _approve(action, ctx):
    return True


async def _deny(action, ctx):
    return False


# ── normalization / validation ─────────────────────────────────────────────

def test_from_config_normalizes_all_forms():
    assert EscalatePolicy.from_config(None) == EscalatePolicy()
    assert EscalatePolicy.from_config("hitl") == EscalatePolicy(pre="hitl", post="hitl")
    assert EscalatePolicy.from_config({"pre": "block"}) == EscalatePolicy(pre="block", post="log")
    existing = EscalatePolicy(pre="hitl")
    assert EscalatePolicy.from_config(existing) is existing


def test_invalid_value_raises_at_construction_not_runtime():
    with pytest.raises(ValueError):
        Pramagent(provider=MockProvider(), escalate_policy="nope")
    with pytest.raises(ValueError):
        Pramagent(provider=MockProvider(), escalate_policy={"pre": "bogus"})
    with pytest.raises(ValueError):
        EscalatePolicy(post="x")


def test_invalid_type_raises():
    with pytest.raises(TypeError):
        Pramagent(provider=MockProvider(), escalate_policy=123)


def test_unknown_dict_key_raises():
    with pytest.raises(ValueError):
        Pramagent(provider=MockProvider(), escalate_policy={"during": "hitl"})


# ── "log" (default): record + continue ─────────────────────────────────────

def test_log_default_records_escalate_and_continues():
    p = CountingProvider()
    armor = Pramagent(provider=p, safety=SafetyLayer(rules=ESC_PRE))  # default policy
    r = run(armor.run("please transfer $500"))
    assert r.trace.pre_verdict == "escalate"          # recorded
    assert p.calls == 1                                # continued to the model
    assert r.blocked is False
    assert "action not executed" not in r.output
    # the firing rule is in the auditable record
    fired = [x for x in r.trace.rules_evaluated
             if x.fired and x.action == Verdict.ESCALATE]
    assert fired and fired[0].rule_id == "esc_in"


# ── "block" ─────────────────────────────────────────────────────────────────

def test_block_pre_blocks_before_model_call():
    p = CountingProvider()
    armor = Pramagent(provider=p, safety=SafetyLayer(rules=ESC_PRE),
                      escalate_policy={"pre": "block"})
    r = run(armor.run("please transfer $500"))
    assert r.blocked is True
    assert "blocked by policy (pre)" in r.block_reason
    assert p.calls == 0          # short-circuited before the provider
    assert r.output == ""


def test_block_post_withholds_after_model_call():
    p = CountingProvider(scripted={"trigger": "please escalate-me now"})
    armor = Pramagent(provider=p,
                      safety=SafetyLayer(rules=[], post_rules=ESC_POST),
                      escalate_policy={"post": "block"})
    r = run(armor.run("trigger"))
    assert p.calls == 1          # the model ran (cost incurred)
    assert r.blocked is True
    assert "blocked by policy (post)" in r.block_reason
    assert r.output == ""


# ── "hitl" ──────────────────────────────────────────────────────────────────

def test_hitl_pre_idle_gates_before_model():
    p = CountingProvider()
    armor = Pramagent(provider=p, safety=SafetyLayer(rules=ESC_PRE),
                      hitl=HITLLayer(timeout_s=0.5, approver=_silent),
                      escalate_policy="hitl")
    r = run(armor.run("please transfer $500"))
    assert r.trace.hitl_status == "idle"
    assert p.calls == 0          # no model call when input is held for review
    assert r.output == "[action not executed - awaiting/declined human approval]"


def test_hitl_pre_denied_does_not_proceed():
    p = CountingProvider()
    armor = Pramagent(provider=p, safety=SafetyLayer(rules=ESC_PRE),
                      hitl=HITLLayer(timeout_s=0.5, approver=_deny),
                      escalate_policy="hitl")
    r = run(armor.run("please transfer $500"))
    assert r.trace.hitl_status == "denied"
    assert p.calls == 0
    assert r.output == "[action not executed - awaiting/declined human approval]"


def test_hitl_pre_approved_proceeds():
    p = CountingProvider()
    armor = Pramagent(provider=p, safety=SafetyLayer(rules=ESC_PRE),
                      hitl=HITLLayer(timeout_s=0.5, approver=_approve),
                      escalate_policy="hitl")
    r = run(armor.run("please transfer $500"))
    assert p.calls == 1          # approval lets the call proceed
    assert "action not executed" not in r.output
    assert any(e.layer == "HITLLayer" and e.decision == "approved"
               for e in r.trace.layer_events)


def test_hitl_post_idle_gates_after_model():
    p = CountingProvider(scripted={"trigger": "please escalate-me now"})
    armor = Pramagent(provider=p,
                      safety=SafetyLayer(rules=[], post_rules=ESC_POST),
                      hitl=HITLLayer(timeout_s=0.5, approver=_silent),
                      escalate_policy={"post": "hitl"})
    r = run(armor.run("trigger"))
    assert p.calls == 1          # model ran, then output held for review
    assert r.trace.hitl_status == "idle"
    assert r.output == "[action not executed - awaiting/declined human approval]"


# ── per-stage dict form ─────────────────────────────────────────────────────

def test_dict_form_pre_hitl_post_log():
    """{"pre": "hitl", "post": "log"} — input escalations gate, output
    escalations are merely recorded."""
    # pre escalation gates
    p1 = CountingProvider()
    armor1 = Pramagent(provider=p1, safety=SafetyLayer(rules=ESC_PRE),
                       hitl=HITLLayer(timeout_s=0.5, approver=_silent),
                       escalate_policy={"pre": "hitl", "post": "log"})
    r1 = run(armor1.run("please transfer $500"))
    assert r1.trace.hitl_status == "idle"
    assert p1.calls == 0

    # post escalation is logged, not gated
    p2 = CountingProvider(scripted={"trigger": "please escalate-me now"})
    armor2 = Pramagent(provider=p2,
                       safety=SafetyLayer(rules=[], post_rules=ESC_POST),
                       hitl=HITLLayer(timeout_s=0.5, approver=_silent),
                       escalate_policy={"pre": "hitl", "post": "log"})
    r2 = run(armor2.run("trigger"))
    assert r2.trace.post_verdict == "escalate"
    assert p2.calls == 1
    assert "action not executed" not in r2.output
    assert r2.blocked is False

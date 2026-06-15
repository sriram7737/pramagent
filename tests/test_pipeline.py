"""Minimal but real test suite. Run with: pytest -q"""
import asyncio
import json

from pramagent import Pramagent, Verdict
from pramagent.layers import ComplianceLayer, HITLLayer, Rule, SafetyLayer
from pramagent.providers import MockProvider
from pramagent.rca import RCAEngine


def run(coro):
    return asyncio.run(coro)


def test_normal_call_produces_chained_trace():
    armor = Pramagent(provider=MockProvider())
    r = run(armor.run("hi", tenant_id="t", session_id="s"))
    assert r.output
    assert r.trace.this_hash and r.trace.prev_hash == "0" * 64
    assert armor.audit.verify_chain()


def test_pii_is_scrubbed():
    armor = Pramagent(provider=MockProvider(), compliance=ComplianceLayer())
    r = run(armor.run("email me at a@b.com"))
    assert "email" in r.trace.pii_redactions
    assert "a@b.com" not in r.output


def test_raw_pii_never_persisted_in_trace_or_audit_chain():
    """Finding #3: the scrub must protect the durable record, not just the
    model copy — raw PII may not appear in input_text/output_text or in any
    audit-chain payload."""
    armor = Pramagent(provider=MockProvider(), compliance=ComplianceLayer())
    r = run(armor.run("my email is bob@x.com and my SSN is 123-45-6789",
                      tenant_id="t", session_id="s"))
    stored = armor.store.get(r.trace.call_id)
    for leaked in ("bob@x.com", "123-45-6789"):
        assert leaked not in stored.input_text
        assert leaked not in stored.output_text
        assert leaked not in r.trace.input_text
    assert "[REDACTED:EMAIL]" in stored.input_text
    chain = json.dumps([rec["payload"] for rec in armor.audit.records()])
    assert "bob@x.com" not in chain
    assert "123-45-6789" not in chain


def test_gdpr_erase_redacts_memory_chain_and_reanchors():
    """Finding #4: after erasure the audit chain must hold no original PII
    and must still verify (re-anchored)."""
    # compliance disabled simulates PII that reached the record despite the
    # scrub (misconfiguration, custom pattern gap) — erasure must still work
    armor = Pramagent(provider=MockProvider(), compliance=ComplianceLayer(enabled=False))
    run(armor.run("subject SSN 123-45-6789", tenant_id="erase-me"))
    run(armor.run("unrelated tenant data", tenant_id="keeper"))
    assert "123-45-6789" in json.dumps([r["payload"] for r in armor.audit.records()])

    armor.store.delete_for_tenant("erase-me")
    redacted = armor.audit.redact_for_tenant("erase-me")

    assert redacted == 1
    chain = json.dumps([r["payload"] for r in armor.audit.records()])
    assert "123-45-6789" not in chain
    assert "unrelated tenant data" in chain          # other tenant untouched
    assert armor.audit.verify_chain()                # chain re-anchored, still valid
    assert armor.audit.head == armor.audit.records()[-1]["this_hash"]


def test_block_rule_stops_call():
    armor = Pramagent(
        provider=MockProvider(),
        safety=SafetyLayer(rules=[Rule("blk", Verdict.BLOCK, pattern=r"forbidden")]),
    )
    r = run(armor.run("this is forbidden"))
    assert r.blocked and r.trace.pre_verdict == "block"


def test_hitl_idle_on_silence():
    async def no_answer(a, c): return None
    armor = Pramagent(
        provider=MockProvider(),
        hitl=HITLLayer(require_approval_for=["pay"], timeout_s=1.0, approver=no_answer),
    )
    r = run(armor.run("pay now", action="pay"))
    assert r.hitl == "idle"


def test_allow_verdict_auto_under_default_policy():
    """Regression guard: a normal ALLOW call must auto-pass. escalate_policy
    handling (default "log") must not gate ordinary responses. The ESCALATE
    policy matrix is covered in test_escalate_policy.py."""
    armor = Pramagent(provider=MockProvider())
    r = run(armor.run("hello there", action="respond"))
    assert r.trace.pre_verdict == "allow"
    assert r.hitl == "auto"
    assert r.output and "action not executed" not in r.output


def test_tamper_breaks_chain():
    armor = Pramagent(provider=MockProvider())
    run(armor.run("a")); run(armor.run("b"))
    assert armor.audit.verify_chain()
    armor.audit.records()[0]["payload"]["output_text"] = "x"
    assert not armor.audit.verify_chain()


def test_rca_replay_reproducible():
    armor = Pramagent(
        provider=MockProvider(),
        safety=SafetyLayer(rules=[Rule("blk", Verdict.BLOCK, pattern=r"nope")]),
    )
    r = run(armor.run("nope"))
    rca = RCAEngine(armor.store.list_all())
    rep = rca.replay(r.trace.call_id)
    assert rep["derived_from_rules"] == "block"
    assert rep["reproducible"] is True

    # tamper with the stored verdict: the fired BLOCK rule no longer matches
    # the stored "allow", so replay must flag the trace as NOT reproducible
    traces = armor.store.list_all()
    tampered = next(t for t in traces if t.call_id == r.trace.call_id)
    tampered.pre_verdict = "allow"
    rep2 = RCAEngine(traces).replay(r.trace.call_id)
    assert rep2["reproducible"] is False
    assert rep2["derived_pre_verdict"] == "block"
    assert rep2["stored_pre_verdict"] == "allow"


def test_rca_replay_separates_pre_and_post_phases():
    """A post-only REDACT must not contaminate the pre-verdict derivation."""
    armor = Pramagent(
        provider=MockProvider(),
        safety=SafetyLayer(
            rules=[],
            post_rules=[Rule("redact_out", Verdict.REDACT, pattern=r".")],
        ),
    )
    r = run(armor.run("anything"))
    assert r.trace.pre_verdict == "allow"
    assert r.trace.post_verdict == "redact"
    rep = RCAEngine(armor.store.list_all()).replay(r.trace.call_id)
    assert rep["derived_pre_verdict"] == "allow"      # post rule not mixed in
    assert rep["derived_post_verdict"] == "redact"
    assert rep["reproducible"] is True

    # tampering with the post verdict alone is also caught
    trace = armor.store.list_all()[0]
    trace.post_verdict = "allow"
    rep2 = RCAEngine([trace]).replay(trace.call_id)
    assert rep2["reproducible"] is False


def test_narrow_post_safety_does_not_silently_withhold_benign_output():
    provider = MockProvider(scripted={
        "safe chemistry": (
            "This chemistry answer says not to make explosives and explains "
            "that exothermic reactions release heat."
        )
    })
    armor = Pramagent(
        provider=provider,
        safety=SafetyLayer(
            rules=[Rule("block_make_explosives", Verdict.BLOCK, pattern=r"make explosives")],
            post_rules=[],
            post_classifier=lambda _: Verdict.ALLOW,
        ),
    )

    r = run(armor.run("safe chemistry", tenant_id="t", session_id="s"))
    assert r.blocked is False
    assert r.trace.post_verdict == "allow"
    assert r.output != "[output withheld by safety rule]"
    assert "exothermic reactions" in r.output


def test_consent_gate_blocks_without_consent_and_allows_with_it():
    """When a ConsentRegistry is configured, core.run() refuses to process
    without consent on file for the tenant/subject/purpose (GDPR Art. 5/7)."""
    from pramagent.compliance import ConsentRegistry, Purpose

    registry = ConsentRegistry()
    armor = Pramagent(provider=MockProvider(), consent=registry,
                      consent_purpose=Purpose.SERVICE.value)

    r = run(armor.run("hello", tenant_id="acme", session_id="subj1"))
    assert r.blocked is True
    assert "consent" in r.block_reason
    assert r.output == ""
    # the refusal itself is traced
    assert any(e.layer == "ConsentGate" and e.decision == "blocked"
               for e in r.trace.layer_events)

    registry.grant("acme", "subj1", [Purpose.SERVICE])
    r2 = run(armor.run("hello", tenant_id="acme", session_id="subj1"))
    assert r2.blocked is False
    assert any(e.layer == "ConsentGate" and e.decision == "ok"
               for e in r2.trace.layer_events)

    # revocation is honored immediately
    registry.revoke("acme", "subj1")
    r3 = run(armor.run("hello", tenant_id="acme", session_id="subj1"))
    assert r3.blocked is True


def test_no_consent_registry_means_no_enforcement():
    armor = Pramagent(provider=MockProvider())
    r = run(armor.run("hello", tenant_id="acme"))
    assert r.blocked is False
    assert not any(e.layer == "ConsentGate" for e in r.trace.layer_events)


def test_provider_error_does_not_leak_exception_text():
    """block_reason must be generic — provider internals stay in logs/trace."""

    class ExplodingProvider(MockProvider):
        async def complete(self, prompt, **kwargs):
            raise RuntimeError("secret-internal-detail http://10.0.0.1/creds")

    armor = Pramagent(provider=ExplodingProvider())
    r = run(armor.run("hello"))
    assert r.blocked is True
    assert r.block_reason == "provider error"
    assert "secret-internal-detail" not in r.block_reason

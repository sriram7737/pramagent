import asyncio
import json

import pytest

from pramagent import Pramagent, Verdict
from pramagent.adapters import guarded_tool
from pramagent.layers import ToolGuardLayer, ToolPolicy
from pramagent.policies import backtest_policy_file, load_tool_guard
from pramagent.providers import MockProvider


def run(coro):
    return asyncio.run(coro)


def _args_policy(name: str, action: Verdict = Verdict.ALLOW) -> ToolPolicy:
    return ToolPolicy(
        name=name,
        schema={
            "type": "object",
            "properties": {
                "args": {"type": "array"},
                "kwargs": {"type": "object"},
            },
            "required": ["args", "kwargs"],
            "additionalProperties": False,
        },
        action=action,
    )


def test_observe_mode_records_tool_block_without_stopping_provider():
    guard = ToolGuardLayer(policies=[
        ToolPolicy(
            name="delete_customer_db",
            schema={"type": "object"},
            action=Verdict.BLOCK,
            detail="destructive admin action",
        )
    ])
    armor = Pramagent(
        provider=MockProvider(scripted={"please do it": "provider still ran"}),
        tool_guard=guard,
        enforcement_mode="observe",
    )

    resp = run(armor.run(
        "please do it",
        tool_name="delete_customer_db",
        tool_arguments={},
    ))

    assert resp.blocked is False
    assert resp.output == "provider still ran"
    assert resp.trace.enforcement_mode == "observe"
    assert resp.trace.would_block is True
    assert "tool blocked by policy" in resp.trace.would_block_reason
    assert any(
        event.layer == "ToolGuardLayer.observe"
        and event.decision == "would_block"
        for event in resp.trace.layer_events
    )


def test_enforce_mode_still_blocks_tool_policy():
    guard = ToolGuardLayer(policies=[
        ToolPolicy(
            name="delete_customer_db",
            schema={"type": "object"},
            action=Verdict.BLOCK,
        )
    ])
    armor = Pramagent(provider=MockProvider(), tool_guard=guard)

    resp = run(armor.run(
        "please do it",
        tool_name="delete_customer_db",
        tool_arguments={},
    ))

    assert resp.blocked is True
    assert resp.trace.enforcement_mode == "enforce"
    assert resp.trace.would_block is False
    assert "tool blocked by policy" in resp.block_reason


def test_classifier_metadata_is_visible_on_isolation_trace_event():
    class ClassifierVerdict:
        flagged = False
        score = 0.41
        threshold = 0.75
        layer = "keyword"
        matched_exemplar = None
        matched_pattern = "near_override"

    def classifier(_text):
        return ClassifierVerdict()

    from pramagent.layers import IsolationLayer

    armor = Pramagent(
        provider=MockProvider(),
        isolation=IsolationLayer(classifier=classifier, block_on_injection=False),
    )

    resp = run(armor.run("ordinary request"))
    isolation_event = next(
        event for event in resp.trace.layer_events
        if event.layer == "IsolationLayer"
    )

    assert isolation_event.data["classifier_flagged"] is False
    assert isolation_event.data["classifier_meta"]["score"] == 0.41
    assert isolation_event.data["classifier_meta"]["threshold"] == 0.75
    assert isolation_event.data["classifier_meta"]["matched_pattern"] == "near_override"


def test_policy_as_code_loader_and_backtest(tmp_path):
    policy_file = tmp_path / "policies.json"
    policy_file.write_text(json.dumps({
        "policies": [
            {
                "name": "send_payment",
                "side_effect": "payment",
                "action": "escalate",
                "schema": {
                    "type": "object",
                    "properties": {"amount_usd": {"type": "number"}},
                    "required": ["amount_usd"],
                    "additionalProperties": False,
                },
            }
        ]
    }), encoding="utf-8")
    cases_file = tmp_path / "cases.jsonl"
    cases_file.write_text(
        json.dumps({
            "case_id": "pay-001",
            "tool_name": "send_payment",
            "arguments": {"amount_usd": 1000},
            "expected": "escalate",
        }) + "\n",
        encoding="utf-8",
    )

    guard = load_tool_guard(policy_file)
    decision = guard.evaluate("send_payment", {"amount_usd": 1000})
    assert decision.verdict == Verdict.ESCALATE

    result = backtest_policy_file(policy_file, cases_file)
    assert result.total == 1
    assert result.escalated == 1
    assert result.mismatches == []


def test_guarded_tool_stops_escalate_before_side_effect():
    guard = ToolGuardLayer(policies=[_args_policy("wire_payment", Verdict.ESCALATE)])
    armor = Pramagent(tool_guard=guard)
    executed = {"value": False}

    @guarded_tool(armor, policy="wire_payment")
    def wire_payment(amount):
        executed["value"] = True
        return amount

    with pytest.raises(PermissionError, match="requires human approval"):
        wire_payment(100)
    assert executed["value"] is False

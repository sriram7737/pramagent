"""Conformance helpers for agent-security framework mappings.

The helpers in this module do not replace the trust stack. They label the
decisions the stack already makes using the vocabulary common to current
agent-security roadmaps: AWS autonomy scopes, DeepMind-style detection and
response tiers, ATT&CK-style threat tags, and live operational metrics.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from .types import AgentScope, TraceEvent


READ_ONLY_SIDE_EFFECTS = {"read", "compute"}


ATTACK_TECHNIQUE_MAP: dict[str, list[str]] = {
    "injection": [
        "ATT&CK:T1059 Command and Scripting Interpreter",
        "ATLAS:AML.T0051 Prompt Injection",
    ],
    "data_exfiltration": [
        "ATT&CK:TA0010 Exfiltration",
        "ATT&CK:T1041 Exfiltration Over C2 Channel",
    ],
    "credential_access": [
        "ATT&CK:TA0006 Credential Access",
        "ATT&CK:T1552 Unsecured Credentials",
    ],
    "destructive": [
        "ATT&CK:TA0040 Impact",
        "ATT&CK:T1485 Data Destruction",
    ],
    "payment": [
        "ATT&CK:TA0040 Impact",
        "FIN:unauthorized_funds_movement",
    ],
    "external_message": [
        "ATT&CK:TA0010 Exfiltration",
        "ATT&CK:T1041 Exfiltration Over C2 Channel",
    ],
    "config_change": [
        "ATT&CK:TA0003 Persistence",
        "ATT&CK:T1548 Abuse Elevation Control Mechanism",
    ],
    "write": [
        "ATT&CK:TA0040 Impact",
        "ATT&CK:T1565 Data Manipulation",
    ],
}


def is_read_only_side_effect(side_effect: str) -> bool:
    return (side_effect or "").lower() in READ_ONLY_SIDE_EFFECTS


def attack_techniques_for_side_effect(side_effect: str) -> list[str]:
    return list(ATTACK_TECHNIQUE_MAP.get((side_effect or "").lower(), []))


def attack_techniques_for_text(*parts: str) -> list[str]:
    text = " ".join(p for p in parts if p).lower()
    out: list[str] = []
    if any(token in text for token in (
        "injection", "override", "system prompt", "developer message",
        "ignore previous", "jailbreak",
    )):
        out.extend(ATTACK_TECHNIQUE_MAP["injection"])
    if any(token in text for token in (
        "exfil", "dump", "export", "secret", "credential", "api key",
        "environment variable", "account",
    )):
        out.extend(ATTACK_TECHNIQUE_MAP["data_exfiltration"])
    if any(token in text for token in (
        "credential", "secret", "api key", "password", "token",
    )):
        out.extend(ATTACK_TECHNIQUE_MAP["credential_access"])
    if any(token in text for token in (
        "delete", "drop", "wipe", "truncate", "destroy", "erase",
    )):
        out.extend(ATTACK_TECHNIQUE_MAP["destructive"])
    if any(token in text for token in (
        "transfer", "wire", "payment", "funds", "routing number",
    )):
        out.extend(ATTACK_TECHNIQUE_MAP["payment"])
    return _dedupe(out)


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _decision_is_terminal(decision: str) -> bool:
    d = (decision or "").lower()
    return any(token in d for token in (
        "block", "blocked", "withheld", "denied", "idle", "degraded",
        "truncated",
    ))


def _decision_is_escalation(decision: str) -> bool:
    d = (decision or "").lower()
    return "escalate" in d or d in {"approved", "auto", "not_required"}


def _highest_detection_tier(trace: TraceEvent) -> str:
    layers = {event.layer for event in trace.layer_events}
    decisions = {event.decision for event in trace.layer_events}
    if any(_decision_is_terminal(d) for d in decisions):
        return "D4_runtime_containment"
    if "OutputJudgeLayer" in layers:
        return "D3_semantic_supervision"
    if any(layer.startswith(("SafetyLayer", "IsolationLayer", "ToolGuardLayer"))
           for layer in layers):
        return "D2_rule_detection"
    return "D1_observed"


def _response_tier(trace: TraceEvent, *, blocked: bool) -> str:
    if blocked or any(_decision_is_terminal(e.decision) for e in trace.layer_events):
        return "R3_block_or_safe_default"
    if (
        trace.hitl_status not in {"", "not_required", "auto"}
        or trace.pre_verdict == "escalate"
        or trace.post_verdict == "escalate"
        or any("escalate" in (e.decision or "").lower()
               for e in trace.layer_events)
    ):
        return "R2_human_approval"
    return "R1_log_and_monitor"


def _time_to_response_ms(trace: TraceEvent) -> float:
    elapsed = 0.0
    for event in trace.layer_events:
        elapsed += max(float(event.latency_ms or 0.0), 0.0)
        if _decision_is_terminal(event.decision) or "escalate" in (event.decision or "").lower():
            return round(elapsed, 3)
    return round(float(trace.total_latency_ms or elapsed), 3)


def _coverage(trace: TraceEvent) -> dict[str, Any]:
    required = ["ComplianceLayer", "IsolationLayer", "SafetyLayer.pre"]
    observed = {event.layer for event in trace.layer_events}
    covered = [layer for layer in required if layer in observed]
    return {
        "trace_layer_coverage": round(len(covered) / len(required), 3),
        "coverage_scope": "single_trace_required_layer_presence",
        "trace_required_layers": required,
        "trace_observed_layers": sorted(observed),
        "monitored": len(covered) == len(required),
    }


def trace_attack_techniques(trace: TraceEvent, *, block_reason: str = "") -> list[str]:
    tags: list[str] = []
    tags.extend(attack_techniques_for_text(
        block_reason,
        trace.input_text,
        trace.output_text,
        trace.pre_verdict or "",
        trace.post_verdict or "",
    ))
    for event in trace.layer_events:
        tags.extend(attack_techniques_for_text(event.layer, event.decision, event.detail))
        side_effect = ""
        if isinstance(event.data, dict):
            side_effect = str(event.data.get("side_effect") or "")
        tags.extend(attack_techniques_for_side_effect(side_effect))
    return _dedupe(tags)


def finalize_trace_conformance(
    trace: TraceEvent,
    *,
    blocked: bool = False,
    block_reason: str = "",
) -> None:
    """Populate conformance labels and metrics on a trace in-place."""
    trace.detection_tier = _highest_detection_tier(trace)
    trace.response_tier = _response_tier(trace, blocked=blocked)
    trace.attack_techniques = trace_attack_techniques(trace, block_reason=block_reason)
    coverage = _coverage(trace)
    trace.conformance_metrics = {
        **coverage,
        "time_to_response_ms": _time_to_response_ms(trace),
        "seeded_recall": None,
        "seeded_recall_source": (
            "not available on runtime traces; use run_injection_benchmark() "
            "for first-party seeded recall"
        ),
    }


def normalize_agent_scope(value: Optional[str | AgentScope]) -> AgentScope:
    return AgentScope.from_config(value)

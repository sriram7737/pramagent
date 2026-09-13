"""
pramagent.rca
=============
The RCA engine turns an immutable trace into a forensic instrument. Three
capabilities, all operating on stored TraceEvents:

    replay()         - deterministically re-derive the verdict from a trace
    causality()      - build the decision graph (what caused what)
    counterfactual() - re-evaluate "what if rule X had not fired?" offline

Because MockProvider and the rule engine are deterministic, replay reproduces
the exact outcome -- which is what makes the audit trustworthy.
"""
from __future__ import annotations

from dataclasses import dataclass

from .types import TraceEvent, Verdict


@dataclass
class CausalNode:
    node_id: str
    kind: str          # "input" | "rule" | "classifier" | "provider" | "output"
    summary: str
    caused_by: list[str]


class RCAEngine:
    def __init__(self, store: list[TraceEvent]):
        # index by call_id for O(1) lookup
        self._by_id = {t.call_id: t for t in store}

    def get(self, call_id: str) -> TraceEvent:
        return self._by_id[call_id]

    @staticmethod
    def _derive_verdict(rules, phase: str) -> Verdict:
        """Max-precedence verdict over the fired rules of one screening phase."""
        precedence = {Verdict.BLOCK: 3, Verdict.ESCALATE: 2,
                      Verdict.REDACT: 1, Verdict.ALLOW: 0}
        fired = [r.action for r in rules
                 if r.fired and getattr(r, "phase", "pre") == phase]
        return (max((Verdict(a) for a in fired), key=lambda v: precedence[v])
                if fired else Verdict.ALLOW)

    # decision replay
    def replay(self, call_id: str) -> dict:
        """
        Re-derive the pre and post verdicts from the recorded rule results,
        independently of what was stored, then compare each to its stored
        counterpart. Pre- and post-rules are derived separately (both phases
        live in rules_evaluated, tagged by `phase`). A disagreement means the
        trace was tampered with or the engine changed since the call ran.
        """
        t = self.get(call_id)
        derived_pre = self._derive_verdict(t.rules_evaluated, "pre")
        derived_post = self._derive_verdict(t.rules_evaluated, "post")
        # A None stored verdict means that phase never ran (e.g. a pre-BLOCK
        # short-circuits before post) — nothing to compare for that phase.
        pre_matches = t.pre_verdict is None or derived_pre.value == t.pre_verdict
        post_matches = t.post_verdict is None or derived_post.value == t.post_verdict
        return {
            "call_id": call_id,
            "stored_pre_verdict": t.pre_verdict,
            "stored_post_verdict": t.post_verdict,
            "derived_pre_verdict": derived_pre.value if t.pre_verdict is not None else None,
            "derived_post_verdict": derived_post.value if t.post_verdict is not None else None,
            # kept for backwards compatibility: the pre-phase derivation
            "derived_from_rules": derived_pre.value,
            "rules_fired": [r.rule_id for r in t.rules_evaluated if r.fired],
            "reproducible": pre_matches and post_matches,
        }

    # causality graph
    def causality(self, call_id: str) -> list[CausalNode]:
        t = self.get(call_id)
        nodes: list[CausalNode] = [CausalNode("input", "input", t.input_text[:80], [])]
        last = "input"
        for ev in t.layer_events:
            nid = f"{ev.layer}"
            nodes.append(CausalNode(nid, "layer", f"{ev.layer}: {ev.decision} ({ev.detail})", [last]))
            last = nid
        nodes.append(CausalNode("output", "output", t.output_text[:80], [last]))
        return nodes

    # counterfactual
    def counterfactual(self, call_id: str, disable_rule: str) -> dict:
        """Recompute the verdict as if `disable_rule` had not fired. No production calls.

        Compares against the stored pre_verdict, so the derivation is scoped
        to pre-phase rules only."""
        t = self.get(call_id)
        precedence = {Verdict.BLOCK: 3, Verdict.ESCALATE: 2, Verdict.REDACT: 1, Verdict.ALLOW: 0}
        fired = [r.action for r in t.rules_evaluated
                 if r.fired and r.rule_id != disable_rule
                 and getattr(r, "phase", "pre") == "pre"]
        verdict = max((Verdict(a) for a in fired), key=lambda v: precedence[v]) if fired else Verdict.ALLOW
        return {
            "call_id": call_id,
            "disabled_rule": disable_rule,
            "original_verdict": t.pre_verdict,
            "counterfactual_verdict": verdict.value,
            "changed": verdict.value != t.pre_verdict,
        }

    # tool-call graph (complex agents)
    def tool_call_graph(self, call_id: str) -> dict:
        """Build a directed graph of tool calls recorded in the trace.

        Supports complex agents: every ToolGuardLayer decision in the trace
        becomes a node; edges follow execution order within the call, and
        branch points (an ESCALATE/BLOCK that diverts the plan) are flagged.

        Returns {"nodes": [...], "edges": [...], "branches": [...]}.
        """
        t = self.get(call_id)
        nodes, edges, branches = [], [], []
        prev = None
        for i, ev in enumerate(t.layer_events):
            if not ev.layer.startswith("ToolGuard"):
                continue
            data = ev.data or {}
            nid = f"tool#{i}"
            node = {
                "id": nid,
                "tool": data.get("tool") or data.get("decision_id") or ev.detail,
                "verdict": ev.decision,
                "side_effect": data.get("side_effect", "unknown"),
                "detail": ev.detail,
            }
            nodes.append(node)
            if prev is not None:
                edges.append({"from": prev, "to": nid})
            # a non-ALLOW verdict is a branch point in the plan
            if ev.decision in ("block", "escalate"):
                branches.append({"node": nid, "verdict": ev.decision,
                                 "reason": ev.detail})
            prev = nid
        return {"call_id": call_id, "nodes": nodes, "edges": edges,
                "branches": branches, "is_linear": len(branches) == 0}

    def multi_rule_counterfactual(self, call_id: str,
                                  disable_rules: list[str]) -> dict:
        """Recompute the verdict as if MULTIPLE rules had not fired.

        Generalises counterfactual() to complex agents where several rules
        interact. No production calls — pure re-derivation from the trace.
        """
        t = self.get(call_id)
        precedence = {Verdict.BLOCK: 3, Verdict.ESCALATE: 2,
                      Verdict.REDACT: 1, Verdict.ALLOW: 0}
        disabled = set(disable_rules)
        fired = [r.action for r in t.rules_evaluated
                 if r.fired and r.rule_id not in disabled
                 and getattr(r, "phase", "pre") == "pre"]
        verdict = (max((Verdict(a) for a in fired), key=lambda v: precedence[v])
                   if fired else Verdict.ALLOW)
        return {
            "call_id": call_id,
            "disabled_rules": sorted(disabled),
            "original_verdict": t.pre_verdict,
            "counterfactual_verdict": verdict.value,
            "changed": verdict.value != t.pre_verdict,
            "remaining_fired": [r.rule_id for r in t.rules_evaluated
                                if r.fired and r.rule_id not in disabled],
        }

    def critical_path(self, call_id: str) -> list[str]:
        """Return the ordered layers that determined the outcome (the decisive
        path): every layer whose decision was block/escalate/denied, in order."""
        t = self.get(call_id)
        decisive = {"block", "blocked", "escalate", "denied", "idle"}
        return [ev.layer for ev in t.layer_events
                if str(ev.decision).lower() in decisive]

    # incident report
    def incident_report(self, call_id: str) -> str:
        t = self.get(call_id)
        lines = [
            f"INCIDENT REPORT  ·  call_id={call_id}",
            f"tenant={t.tenant_id}  session={t.session_id}",
            f"created_at={t.created_at}",
            f"input_hash={t.input_hash[:16]}…",
            f"provider={t.provider} ({t.provider_model})  latency={t.provider_latency_ms:.1f}ms"
            f"  cost=${t.provider_cost_usd:.6f}  fallback={t.used_fallback}",
            f"pre_verdict={t.pre_verdict}  post_verdict={t.post_verdict}  hitl={t.hitl_status}",
            f"pii_redactions={t.pii_redactions}",
            "rules_fired=" + (", ".join(r.rule_id for r in t.rules_evaluated if r.fired) or "(none)"),
            f"chain: prev={t.prev_hash[:12]}… -> this={t.this_hash[:12]}…  anchor={t.anchor_tx_id}",
            "decision path: " + " -> ".join(e.layer for e in t.layer_events),
        ]
        return "\n".join(lines)

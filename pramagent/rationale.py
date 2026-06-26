"""
pramagent.rationale
====================
Structured decision rationale for trace events.

The hazard this module guards against is logging raw chain-of-thought: free,
unbounded model reasoning that can carry secrets, PII, or unsafe intermediate
content straight into durable traces. The defence is the *shape* of the data,
not a discipline you have to remember -- DecisionRationale has slots only for
safe, structured fields:

    intent          one-line declared goal of this step
    policy_reason   which policy/rule fired, by id
    tool_rationale  why THIS tool / these args, structured

There is deliberately NO ``raw_reasoning`` slot, and there never will be. A
caller that wants to attach reasoning has nowhere to put the raw stream, so
leaking it becomes a type error rather than a code-review catch.

This is INTENT capture, not THOUGHT capture. Even the free-text slots (intent,
tool_rationale) are run through the same PII scrubber (pramagent.layers.
ComplianceLayer) used before model egress, so any sensitive token that slips
into a summary is redacted before it touches the store. Use DecisionRationale.
capture(...) to get that scrubbing automatically.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DecisionRationale:
    """Structured, scrubbed rationale for one agent decision. Attach to a trace
    event. Construct via :meth:`capture` to scrub the free-text slots; the bare
    constructor stores fields verbatim (use only with already-safe content)."""

    intent: str
    policy_reason: str
    tool_rationale: str
    # Labels of PII patterns redacted from the free-text slots during capture()
    # -- pattern names only (e.g. "email"), never the redacted values.
    redactions: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def capture(cls, *, intent: str, policy_reason: str, tool_rationale: str,
                scrubber=None) -> "DecisionRationale":
        """Build a DecisionRationale, scrubbing the free-text slots.

        ``intent`` and ``tool_rationale`` are free text, so they pass through
        the PII scrubber. ``policy_reason`` is a structured rule id and is left
        as-is. ``scrubber`` is any object exposing ``scrub(text) -> (text,
        labels)`` (duck-typed); it defaults to a fresh ComplianceLayer.
        """
        if scrubber is None:
            from .layers import ComplianceLayer
            scrubber = ComplianceLayer()
        labels: list[str] = []
        clean_intent, l1 = cls._safe_scrub(scrubber, intent)
        clean_tool, l2 = cls._safe_scrub(scrubber, tool_rationale)
        labels.extend(l1)
        labels.extend(l2)
        return cls(
            intent=clean_intent,
            policy_reason=policy_reason,
            tool_rationale=clean_tool,
            redactions=tuple(labels),
        )

    @staticmethod
    def _safe_scrub(scrubber, text: str) -> tuple[str, list[str]]:
        """Run the scrubber, failing CLOSED. If it raises, returns a non-str
        cleaned value, or anything other than a (text, labels) pair, we drop the
        field to a redaction marker and flag it -- we NEVER fall back to storing
        the unredacted text because the scrubber misbehaved."""
        try:
            result = scrubber.scrub(text)
            if not isinstance(result, tuple) or len(result) != 2:
                raise TypeError("scrubber must return a (text, labels) pair")
            clean, found = result
            if not isinstance(clean, str):
                raise TypeError("scrubber returned a non-str cleaned value")
            if isinstance(found, (str, bytes)) or not isinstance(found, Iterable):
                raise TypeError("scrubber labels must be an iterable of strings")
            labels = list(found)
            if not all(isinstance(label, str) for label in labels):
                raise TypeError("scrubber labels must be strings")
            return clean, labels
        except Exception:
            return "[REDACTED:SCRUB_ERROR]", ["scrub_error"]

    def to_dict(self) -> dict:
        """JSON-safe form for embedding in a trace payload."""
        return {
            "intent": self.intent,
            "policy_reason": self.policy_reason,
            "tool_rationale": self.tool_rationale,
            "redactions": list(self.redactions),
        }

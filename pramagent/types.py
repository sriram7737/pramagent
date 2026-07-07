"""
pramagent.types
===============
Core data structures shared across all layers. Everything that flows through
the pipeline is one of these typed objects. Keeping them in one place makes the
contract between layers explicit and auditable.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    """Outcome of a safety evaluation."""
    ALLOW = "allow"          # proceed normally
    BLOCK = "block"          # stop unconditionally
    ESCALATE = "escalate"    # route to human / higher authority
    REDACT = "redact"        # proceed but with content removed


class EnforcementMode(str, Enum):
    """Whether policy gates stop execution or only record what they would do.

    ENFORCE is the production default. OBSERVE is a shadow/dry-run mode for
    policy rollout: deterministic policy blocks are recorded on the trace but
    the request continues so teams can tune policies before switching traffic
    to enforcement.
    """
    ENFORCE = "enforce"
    OBSERVE = "observe"

    @classmethod
    def from_config(cls, value) -> "EnforcementMode":
        if value is None or value == "":
            return cls.ENFORCE
        if isinstance(value, cls):
            return value
        key = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "enforce": cls.ENFORCE,
            "enforced": cls.ENFORCE,
            "block": cls.ENFORCE,
            "blocking": cls.ENFORCE,
            "observe": cls.OBSERVE,
            "shadow": cls.OBSERVE,
            "shadow_mode": cls.OBSERVE,
            "dry_run": cls.OBSERVE,
            "dryrun": cls.OBSERVE,
        }
        try:
            return aliases[key]
        except KeyError as exc:
            raise ValueError(f"unknown enforcement mode: {value!r}") from exc


class Provenance(str, Enum):
    """Source provenance for input content.

    The strongest defense against indirect prompt injection is structural: tag
    every piece of content by source and hold untrusted sources to stricter
    classifier thresholds.

    SYSTEM    — system prompt / developer instructions. Fully trusted; not
                scanned for injection (the developer wrote it).
    USER      — direct user input. Semi-trusted; scanned at normal threshold.
    TOOL_OUTPUT — tool / API return. Untrusted; scanned at lower threshold.
    RETRIEVED — RAG / search result. Untrusted; scanned at lower threshold.
    """
    SYSTEM = "system"
    USER = "user"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED = "retrieved"


class AgentScope(str, Enum):
    """AWS-style autonomy scope declaration for a Pramagent deployment.

    UNDECLARED keeps backwards-compatible library behavior.
    SCOPE_1_READ_ONLY allows human-initiated read/compute work only.
    SCOPE_2_HUMAN_APPROVED requires human approval for non-read side effects.
    SCOPE_3_BOUNDED_AUTONOMY allows bounded autonomous execution under the
    configured ToolGuard/HITL/rate-limit policies.
    """
    UNDECLARED = "undeclared"
    SCOPE_1_READ_ONLY = "scope_1_read_only"
    SCOPE_2_HUMAN_APPROVED = "scope_2_human_approved"
    SCOPE_3_BOUNDED_AUTONOMY = "scope_3_bounded_autonomy"

    @classmethod
    def from_config(cls, value) -> "AgentScope":
        if value is None or value == "":
            return cls.UNDECLARED
        if isinstance(value, cls):
            return value
        key = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "1": cls.SCOPE_1_READ_ONLY,
            "scope1": cls.SCOPE_1_READ_ONLY,
            "scope_1": cls.SCOPE_1_READ_ONLY,
            "read_only": cls.SCOPE_1_READ_ONLY,
            "scope_1_read_only": cls.SCOPE_1_READ_ONLY,
            "2": cls.SCOPE_2_HUMAN_APPROVED,
            "scope2": cls.SCOPE_2_HUMAN_APPROVED,
            "scope_2": cls.SCOPE_2_HUMAN_APPROVED,
            "human_approved": cls.SCOPE_2_HUMAN_APPROVED,
            "scope_2_human_approved": cls.SCOPE_2_HUMAN_APPROVED,
            "3": cls.SCOPE_3_BOUNDED_AUTONOMY,
            "scope3": cls.SCOPE_3_BOUNDED_AUTONOMY,
            "scope_3": cls.SCOPE_3_BOUNDED_AUTONOMY,
            "bounded_autonomy": cls.SCOPE_3_BOUNDED_AUTONOMY,
            "scope_3_bounded_autonomy": cls.SCOPE_3_BOUNDED_AUTONOMY,
            "undeclared": cls.UNDECLARED,
        }
        try:
            return aliases[key]
        except KeyError as exc:
            raise ValueError(f"unknown agent scope: {value!r}") from exc


class HITLStatus(str, Enum):
    """Status of a human-in-the-loop decision."""
    NOT_REQUIRED = "not_required"   # action was low-risk; no approval needed
    AUTO = "auto"                   # auto-approved by policy
    APPROVED = "approved"           # a human approved
    DENIED = "denied"               # a human denied
    IDLE = "idle"                   # timed out with no response -> did nothing


@dataclass(frozen=True)
class EscalatePolicy:
    """What the pipeline does when a SafetyLayer pass returns Verdict.ESCALATE.

    ESCALATE sits between ALLOW and BLOCK: "suspicious, but not certain enough
    to block." Deployments differ on how to treat that, and input screening vs
    output screening often warrant different responses, so the policy is set
    per stage:

        pre  -- verdict from safety.pre  (suspicious INPUT, before the model)
        post -- verdict from safety.post (suspicious OUTPUT, after the model)

    Each stage takes one of:

        "log"   -- record the verdict in the trace and continue (default). The
                   audit chain keeps the evidence; the caller is not gated.
        "hitl"  -- route to the human-in-the-loop gate. Propose-and-wait; on
                   silence (IDLE) or DENIED the call does not proceed.
        "block" -- hard block. Stop immediately: no model call for a pre
                   escalation, no output for a post escalation.

    Default is ("log", "log") so adding an ESCALATE rule never silently starts
    gating traffic. Production deployments handling consequential actions
    should set at minimum {"pre": "hitl"}.

    Build from a string (applies to both stages), a dict, or directly::

        EscalatePolicy.from_config("hitl")
        EscalatePolicy.from_config({"pre": "hitl", "post": "log"})
        EscalatePolicy(pre="hitl", post="block")
    """
    pre: str = "log"
    post: str = "log"

    VALID = ("log", "hitl", "block")

    def __post_init__(self):
        for field_name, value in (("pre", self.pre), ("post", self.post)):
            if value not in self.VALID:
                raise ValueError(
                    f"escalate_policy.{field_name} must be one of "
                    f"{self.VALID}, got {value!r}")

    @classmethod
    def from_config(cls, value) -> "EscalatePolicy":
        if value is None:
            return cls()
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            return cls(pre=value, post=value)
        if isinstance(value, dict):
            unknown = set(value) - {"pre", "post"}
            if unknown:
                raise ValueError(
                    "escalate_policy dict keys must be 'pre'/'post', got "
                    f"unexpected {sorted(unknown)}")
            return cls(pre=value.get("pre", "log"),
                       post=value.get("post", "log"))
        raise TypeError(
            "escalate_policy must be str, dict, or EscalatePolicy, got "
            f"{type(value).__name__}")


@dataclass
class RuleResult:
    """Record of a single rule evaluation by the SafetyLayer rule engine.

    `phase` records which screening pass produced the result ("pre" = input,
    "post" = output) so RCA replay can re-derive each verdict separately
    instead of mixing both passes into one. Records persisted before this
    field existed default to "pre"."""
    rule_id: str
    fired: bool
    action: Verdict
    detail: str = ""
    phase: str = "pre"


@dataclass
class LayerEvent:
    """
    A single decision made by a single layer. The ordered list of LayerEvents
    is the spine of the trace and the input to the RCA engine.
    """
    layer: str
    decision: str
    detail: str = ""
    latency_ms: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceEvent:
    """
    The complete, immutable record of one agent call. This is returned as a
    first-class field on every response (never a side channel) and is the unit
    that gets hash-chained and anchored.
    """
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    session_id: str = "default"
    created_at: float = field(default_factory=time.time)

    input_text: str = ""
    input_hash: str = ""
    output_text: str = ""

    pii_redactions: list[str] = field(default_factory=list)
    pre_verdict: Optional[str] = None
    post_verdict: Optional[str] = None
    rules_evaluated: list[RuleResult] = field(default_factory=list)

    provider: str = ""
    provider_model: str = ""
    provider_cost_usd: float = 0.0
    provider_latency_ms: float = 0.0
    provider_prompt_tokens: int = 0
    provider_completion_tokens: int = 0
    used_fallback: bool = False

    hitl_status: str = HITLStatus.NOT_REQUIRED.value
    layer_events: list[LayerEvent] = field(default_factory=list)
    total_latency_ms: float = 0.0

    # Shadow rollout metadata. In observe mode, policy gates can record that
    # they would have blocked without stopping execution. Isolation and consent
    # gates still fail closed because allowing those through can leak data or
    # send known injection to the provider.
    enforcement_mode: str = EnforcementMode.ENFORCE.value
    would_block: bool = False
    would_block_reason: str = ""

    # Framework-conformance labels. Populated by the orchestrator at finalize
    # time so every persisted trace can be read through DeepMind/AWS vocabulary
    # without changing the core policy engine.
    aws_scope: str = AgentScope.UNDECLARED.value
    detection_tier: str = ""
    response_tier: str = ""
    attack_techniques: list[str] = field(default_factory=list)
    conformance_metrics: dict[str, Any] = field(default_factory=dict)

    # hash-chain fields
    prev_hash: str = ""
    this_hash: str = ""
    anchor_tx_id: str = ""
    anchor_block_number: int = 0
    anchor_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "TraceEvent":
        """Reconstruct a TraceEvent from a dict (e.g. loaded from SQLite JSON)."""
        d = dict(d)  # shallow copy to avoid mutating caller's data
        d["rules_evaluated"] = [
            RuleResult(**{**r, "action": Verdict(r["action"])})
            for r in d.get("rules_evaluated", [])
        ]
        d["layer_events"] = [LayerEvent(**le) for le in d.get("layer_events", [])]
        return cls(**d)


@dataclass
class AgentResponse:
    """What the caller receives. `.output` is the safe text; `.trace` is always present."""
    output: str
    trace: TraceEvent
    blocked: bool = False
    block_reason: str = ""

    @property
    def hitl(self) -> str:
        return self.trace.hitl_status
